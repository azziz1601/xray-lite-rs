use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::address::{is_private_ip, TargetAddr};
use crate::stats::UserTraffic;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Applies `TCP_NODELAY` and kernel TCP keepalive (60s idle / 15s interval) so dead mobile
/// connections are automatically reaped instead of lingering for hours as zombie sockets.
pub fn configure_tcp_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    let _ = SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Connects directly to `target` (Freedom outbound) with optional private-IP SSRF protection.
pub async fn dial_tcp(target: &TargetAddr, block_private: bool) -> io::Result<TcpStream> {
    let addr = timeout(DIAL_TIMEOUT, target.resolve())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolve timeout"))??;

    if block_private && is_private_ip(addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked connection to private IP {addr}"),
        ));
    }

    let stream = timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;

    configure_tcp_socket(&stream);
    Ok(stream)
}

/// Resolves a UDP target address with optional private-IP protection.
pub async fn resolve_udp_target(target: &TargetAddr, block_private: bool) -> io::Result<SocketAddr> {
    let addr = timeout(DIAL_TIMEOUT, target.resolve())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolve timeout"))??;

    if block_private && is_private_ip(addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked UDP packet to private IP {addr}"),
        ));
    }
    Ok(addr)
}

/// Binds an ephemeral local UDP socket matching the IP family of `remote`.
pub async fn bind_udp_for(remote: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match remote {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    UdpSocket::bind(bind_addr).await
}

/// Relays TCP streams bidirectionally without traffic accounting (used for fallbacks).
pub async fn relay_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    target: &mut TcpStream,
) -> io::Result<()> {
    let _ = tokio::io::copy_bidirectional(client, target).await;
    Ok(())
}

/// Relays TCP streams bidirectionally while updating real-time per-user uplink/downlink
/// atomic byte counters on every chunk.
pub async fn relay_tcp_with_stats<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    target: &mut TcpStream,
    stats: Option<Arc<UserTraffic>>,
) -> io::Result<()> {
    match stats {
        Some(counters) => {
            let mut counted_target = CountingOutbound {
                inner: target,
                counters,
            };
            let _ = tokio::io::copy_bidirectional(client, &mut counted_target).await;
        }
        None => {
            let _ = tokio::io::copy_bidirectional(client, target).await;
        }
    }
    Ok(())
}

struct CountingOutbound<'a> {
    inner: &'a mut TcpStream,
    counters: Arc<UserTraffic>,
}

impl AsyncRead for CountingOutbound<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = buf.filled().len().saturating_sub(before);
            self.counters.add_downlink(delta as u64);
        }
        res
    }
}

impl AsyncWrite for CountingOutbound<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.counters.add_uplink(*n as u64);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
