use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::server;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::log_debug;

const MAX_GRPC_API_REQ_BYTES: usize = 64 * 1024;

/// Lock-free per-user traffic byte counters.
#[derive(Default)]
pub struct UserTraffic {
    pub uplink: AtomicU64,
    pub downlink: AtomicU64,
}

impl UserTraffic {
    #[inline]
    pub fn add_uplink(&self, n: u64) {
        if n > 0 {
            self.uplink.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_downlink(&self, n: u64) {
        if n > 0 {
            self.downlink.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Shared registry of per-user uplink/downlink byte counters, exposed via Xray-compatible
/// gRPC `StatsService` (`QueryStats` / `GetStats`).
#[derive(Clone, Default)]
pub struct StatsRegistry {
    users: Arc<RwLock<HashMap<String, Arc<UserTraffic>>>>,
}

impl StatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns (or lazily creates) the atomic traffic counters for `email`.
    /// Returns `None` if `email` is empty.
    pub fn counters_for(&self, email: &str) -> Option<Arc<UserTraffic>> {
        if email.is_empty() {
            return None;
        }
        {
            let map = self.users.read().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = map.get(email) {
                return Some(Arc::clone(c));
            }
        }
        let mut map = self.users.write().unwrap_or_else(|e| e.into_inner());
        Some(Arc::clone(
            map.entry(email.to_string())
                .or_insert_with(|| Arc::new(UserTraffic::default())),
        ))
    }

    /// Queries all stats whose name contains `pattern` (empty pattern matches all).
    /// When `reset` is true, atomically resets returned counters to 0.
    pub fn query_stats(&self, pattern: &str, reset: bool) -> Vec<(String, i64)> {
        let map = self.users.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (email, counters) in map.iter() {
            let up_name = format!("user>>>{email}>>>traffic>>>uplink");
            if pattern.is_empty() || up_name.contains(pattern) {
                let val = if reset {
                    counters.uplink.swap(0, Ordering::Relaxed)
                } else {
                    counters.uplink.load(Ordering::Relaxed)
                };
                if val > 0 {
                    out.push((up_name, val.min(i64::MAX as u64) as i64));
                }
            }

            let down_name = format!("user>>>{email}>>>traffic>>>downlink");
            if pattern.is_empty() || down_name.contains(pattern) {
                let val = if reset {
                    counters.downlink.swap(0, Ordering::Relaxed)
                } else {
                    counters.downlink.load(Ordering::Relaxed)
                };
                if val > 0 {
                    out.push((down_name, val.min(i64::MAX as u64) as i64));
                }
            }
        }
        out
    }

    /// Fetches a single stat by exact Xray stat name (`user>>><email>>>>traffic>>>{uplink|downlink}`).
    pub fn get_stat(&self, name: &str, reset: bool) -> Option<(String, i64)> {
        let mut parts = name.split(">>>");
        let scope = parts.next()?;
        let email = parts.next()?;
        let metric = parts.next()?;
        let dir = parts.next()?;
        if scope != "user" || metric != "traffic" || email.is_empty() {
            return None;
        }
        let map = self.users.read().unwrap_or_else(|e| e.into_inner());
        let counters = map.get(email)?;
        let val = match dir {
            "uplink" => {
                if reset {
                    counters.uplink.swap(0, Ordering::Relaxed)
                } else {
                    counters.uplink.load(Ordering::Relaxed)
                }
            }
            "downlink" => {
                if reset {
                    counters.downlink.swap(0, Ordering::Relaxed)
                } else {
                    counters.downlink.load(Ordering::Relaxed)
                }
            }
            _ => return None,
        };
        Some((name.to_string(), val.min(i64::MAX as u64) as i64))
    }
}

/// Xray-compatible access logger writing to `log.access` (e.g. `/var/log/xray/access.log`)
/// using `O_APPEND` so external log truncation (`echo -n > /var/log/xray/access.log`) stays safe.
#[derive(Clone, Default)]
pub struct AccessLogger {
    file: Option<Arc<Mutex<File>>>,
}

impl AccessLogger {
    pub fn disabled() -> Self {
        Self { file: None }
    }

    pub fn open(path: &str) -> Result<Self, String> {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
            return Ok(Self::disabled());
        }
        let p = Path::new(trimmed);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map_err(|e| format!("failed to open access log '{trimmed}': {e}"))?;
        Ok(Self {
            file: Some(Arc::new(Mutex::new(f))),
        })
    }

    /// Formats a line compatible with Xray-core & VPS scripts (`cekws`, `cekvless`, `cektr`, `limit-ip`):
    /// `YYYY/MM/DD HH:MM:SS tcp:<ip>:<port> accepted <net>:<target> [<tag>] email: <email>`
    pub fn log_accepted(
        &self,
        peer_desc: &str,
        net: &str,
        target: &str,
        tag: &str,
        email: &str,
    ) {
        let Some(file_lock) = &self.file else {
            return;
        };
        let line = format_access_line(peer_desc, net, target, tag, email);
        if let Ok(mut f) = file_lock.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

pub fn format_access_line(
    peer_desc: &str,
    net: &str,
    target: &str,
    tag: &str,
    email: &str,
) -> String {
    let ts = format_utc_timestamp();
    let peer_field = normalize_peer_field(peer_desc);
    if email.is_empty() {
        format!("{ts} {peer_field} accepted {net}:{target} [{tag}]\n")
    } else {
        format!("{ts} {peer_field} accepted {net}:{target} [{tag}] email: {email}\n")
    }
}

fn normalize_peer_field(peer_desc: &str) -> String {
    let trimmed = peer_desc.trim();
    let stripped = trimmed
        .strip_prefix("tcp:")
        .or_else(|| trimmed.strip_prefix("udp:"))
        .unwrap_or(trimmed);
    if stripped.is_empty() || stripped == "unix" {
        return "tcp:127.0.0.1:0".to_string();
    }
    // If IPv4 without port, append `:0` so `cut -d ":" -f 1` extracts the clean IP.
    if !stripped.contains(':') {
        format!("tcp:{stripped}:0")
    } else {
        format!("tcp:{stripped}")
    }
}

fn format_utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

/// Serves an HTTP/2 gRPC connection for Xray's `StatsService` (`QueryStats` & `GetStats`).
pub async fn serve_stats_api_connection<S>(stream: S, stats: StatsRegistry) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut h2_conn = server::handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stats h2 handshake: {e}")))?;

    while let Some(next) = h2_conn.accept().await {
        let (req, mut respond) = match next {
            Ok(pair) => pair,
            Err(e) => {
                log_debug!("stats API h2 accept error: {}", e);
                break;
            }
        };

        let path = req.uri().path().to_string();
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut body = req.into_body();
            let mut raw = BytesMut::new();
            while let Some(chunk_res) = body.data().await {
                match chunk_res {
                    Ok(chunk) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        if raw.len() + chunk.len() > MAX_GRPC_API_REQ_BYTES {
                            send_grpc_error(&mut respond, "8", "request too large");
                            return;
                        }
                        raw.extend_from_slice(&chunk);
                    }
                    Err(_) => return,
                }
            }

            if raw.len() < 5 {
                send_grpc_error(&mut respond, "3", "truncated gRPC frame");
                return;
            }
            let _compressed = raw[0];
            let msg_len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
            if raw.len() < 5 + msg_len {
                send_grpc_error(&mut respond, "3", "incomplete gRPC payload");
                return;
            }
            let payload = &raw[5..5 + msg_len];

            let resp_proto = match path.as_str() {
                "/xray.app.stats.command.StatsService/QueryStats" => {
                    let (pattern, reset) = decode_stats_request(payload);
                    let items = stats.query_stats(&pattern, reset);
                    encode_query_stats_response(&items)
                }
                "/xray.app.stats.command.StatsService/GetStats" => {
                    let (name, reset) = decode_stats_request(payload);
                    let item = stats.get_stat(&name, reset);
                    encode_get_stats_response(item.as_ref())
                }
                _ => {
                    send_grpc_error(&mut respond, "12", "unimplemented RPC");
                    return;
                }
            };

            let mut frame = BytesMut::with_capacity(5 + resp_proto.len());
            frame.put_u8(0);
            frame.put_u32(resp_proto.len() as u32);
            frame.put_slice(&resp_proto);

            let resp = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();

            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send_all_bytes(&mut send, frame.freeze()).await;
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                let _ = send.send_trailers(trailers);
            }
        });
    }

    Ok(())
}

fn send_grpc_error(respond: &mut server::SendResponse<Bytes>, code: &'static str, msg: &'static str) {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", code)
        .header("grpc-message", msg)
        .body(())
        .unwrap();
    let _ = respond.send_response(resp, true);
}

async fn send_all_bytes(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 capacity: {e}")))?;
        let chunk = data.split_to(cap.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 send: {e}")))?;
    }
    Ok(())
}

/// Decodes protobuf `QueryStatsRequest { string pattern = 1; bool reset = 2; }`
/// (identical wire layout to `GetStatsRequest { string name = 1; bool reset = 2; }`).
pub fn decode_stats_request(mut data: &[u8]) -> (String, bool) {
    let mut text = String::new();
    let mut reset = false;

    while !data.is_empty() {
        let Some(tag) = read_varint(&mut data) else {
            break;
        };
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => {
                let Some(len) = read_varint(&mut data) else {
                    break;
                };
                let len = len as usize;
                if data.len() < len {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&data[..len]) {
                    text = s.to_string();
                }
                data.advance(len);
            }
            (2, 0) => {
                if let Some(v) = read_varint(&mut data) {
                    reset = v != 0;
                } else {
                    break;
                }
            }
            (_, 0) => {
                if read_varint(&mut data).is_none() {
                    break;
                }
            }
            (_, 1) => {
                if data.len() < 8 {
                    break;
                }
                data.advance(8);
            }
            (_, 2) => {
                let Some(len) = read_varint(&mut data) else {
                    break;
                };
                let len = len as usize;
                if data.len() < len {
                    break;
                }
                data.advance(len);
            }
            (_, 5) => {
                if data.len() < 4 {
                    break;
                }
                data.advance(4);
            }
            _ => break,
        }
    }

    (text, reset)
}

/// Encodes `QueryStatsResponse { repeated Stat stat = 1; }`.
pub fn encode_query_stats_response(items: &[(String, i64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in items {
        let stat_bytes = encode_stat(name, *value);
        out.push(0x0A); // field 1, wire type 2
        write_varint(&mut out, stat_bytes.len() as u64);
        out.extend_from_slice(&stat_bytes);
    }
    out
}

/// Encodes `GetStatsResponse { Stat stat = 1; }`.
pub fn encode_get_stats_response(item: Option<&(String, i64)>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some((name, value)) = item {
        let stat_bytes = encode_stat(name, *value);
        out.push(0x0A); // field 1, wire type 2
        write_varint(&mut out, stat_bytes.len() as u64);
        out.extend_from_slice(&stat_bytes);
    }
    out
}

fn encode_stat(name: &str, value: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 16);
    if !name.is_empty() {
        out.push(0x0A); // field 1 (string name), wire type 2
        write_varint(&mut out, name.len() as u64);
        out.extend_from_slice(name.as_bytes());
    }
    if value != 0 {
        out.push(0x10); // field 2 (int64 value), wire type 0
        write_varint(&mut out, value as u64);
    }
    out
}

fn read_varint(data: &mut &[u8]) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while !data.is_empty() && shift < 64 {
        let b = data[0];
        data.advance(1);
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_query_and_reset_roundtrip() {
        let reg = StatsRegistry::new();
        let c = reg.counters_for("alice").unwrap();
        c.add_uplink(1200);
        c.add_downlink(3400);

        let all = reg.query_stats("user>>>", false);
        assert_eq!(all.len(), 2);

        let dl = reg.query_stats(">>>traffic>>>downlink", true);
        assert_eq!(dl, vec![("user>>>alice>>>traffic>>>downlink".to_string(), 3400)]);

        // Downlink was reset to 0, uplink still 1200.
        let dl_after = reg.query_stats(">>>traffic>>>downlink", false);
        assert!(dl_after.is_empty());
        let ul_after = reg.query_stats("user>>>", false);
        assert_eq!(ul_after, vec![("user>>>alice>>>traffic>>>uplink".to_string(), 1200)]);
    }

    #[test]
    fn protobuf_stats_codec_matches_xray() {
        // QueryStatsRequest { pattern: "user>>>", reset: true }
        let mut req = Vec::new();
        req.push(0x0A);
        req.push(7);
        req.extend_from_slice(b"user>>>");
        req.push(0x10);
        req.push(1);

        let (pat, reset) = decode_stats_request(&req);
        assert_eq!(pat, "user>>>");
        assert!(reset);

        let resp = encode_query_stats_response(&[
            ("user>>>bob>>>traffic>>>downlink".to_string(), 4096),
        ]);
        assert!(!resp.is_empty());
        assert_eq!(resp[0], 0x0A);
    }

    #[test]
    fn access_log_line_matches_vps_script_awk_cut_fields() {
        let line = format_access_line("114.122.10.5", "tcp", "example.com:443", "vless-ws", "alice");
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Field 2 (0-indexed 1): HH:MM:SS
        assert_eq!(fields[1].len(), 8);
        assert_eq!(&fields[1][2..3], ":");
        // Field 3 (0-indexed 2): tcp:<ip>:<port>
        assert_eq!(fields[2], "tcp:114.122.10.5:0");
        let ip = fields[2].replace("tcp:", "");
        assert_eq!(ip.split(':').next().unwrap(), "114.122.10.5");
        assert!(line.contains("email: alice"));
    }
}
