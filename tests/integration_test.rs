use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use xray_lite_rs::config::{
    parse_uuid, ClientConfig, HttpUpgradeSettings, InboundConfig, InboundSettings, PortSpec,
    StreamSettings, WsSettings, XrayConfig,
};
use xray_lite_rs::protocol::trojan_password_hash;
use xray_lite_rs::{run_server, HotReloadRegistry};

async fn spawn_tcp_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn free_local_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn build_vless_tcp_request(uuid: &[u8; 16], target: std::net::SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00); // version
    out.extend_from_slice(uuid);
    out.push(0x00); // addons len
    out.push(0x00); // CMD_TCP
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        std::net::SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
        }
        std::net::SocketAddr::V6(v6) => {
            out.push(0x03);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out
}

#[tokio::test]
async fn vless_over_httpupgrade_and_hot_reload() {
    let echo_addr = spawn_tcp_echo_server().await;
    let listen_port = free_local_port();
    let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let uuid2_str = "11111111-2222-3333-4444-555555555555";

    let mut cfg = XrayConfig {
        log: None,
        inbounds: vec![InboundConfig {
            tag: "vless-hu".to_string(),
            listen: "127.0.0.1".to_string(),
            port: PortSpec::Num(listen_port),
            protocol: "vless".to_string(),
            settings: InboundSettings {
                clients: vec![ClientConfig {
                    id: uuid_str.to_string(),
                    password: String::new(),
                    email: "u1".to_string(),
                    flow: String::new(),
                    level: 0,
                }],
                decryption: Some("none".to_string()),
                fallbacks: vec![],
            },
            stream_settings: Some(StreamSettings {
                network: "httpupgrade".to_string(),
                security: "none".to_string(),
                httpupgrade_settings: Some(HttpUpgradeSettings {
                    accept_proxy_protocol: false,
                    path: "/hu".to_string(),
                    host: String::new(),
                    headers: Default::default(),
                }),
                ..Default::default()
            }),
        }],
        outbounds: vec![],
        // Allow localhost in test by providing empty routing rules (disables private-IP block).
        routing: Some(Default::default()),
    };

    let registry = HotReloadRegistry::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_reg = registry.clone();
    let srv_cfg = cfg.clone();
    let srv = tokio::spawn(async move {
        let _ = run_server(srv_cfg, srv_reg, shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Connect with user 1 via HTTPUpgrade
    let mut s = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    let req = "GET /hu HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    s.write_all(req.as_bytes()).await.unwrap();

    let mut resp_buf = [0u8; 256];
    let n = s.read(&mut resp_buf).await.unwrap();
    assert!(std::str::from_utf8(&resp_buf[..n]).unwrap().contains("101 Switching Protocols"));

    let mut vless_req = build_vless_tcp_request(&parse_uuid(uuid_str).unwrap(), echo_addr);
    vless_req.extend_from_slice(b"hello-httpupgrade");
    s.write_all(&vless_req).await.unwrap();

    let mut vless_resp = [0u8; 2];
    s.read_exact(&mut vless_resp).await.unwrap();
    assert_eq!(vless_resp, [0x00, 0x00]);

    let mut echo = [0u8; 17];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello-httpupgrade");

    // Hot-reload: add user 2 without closing connection `s`
    cfg.inbounds[0].settings.clients.push(ClientConfig {
        id: uuid2_str.to_string(),
        password: String::new(),
        email: "u2".to_string(),
        flow: String::new(),
        level: 0,
    });
    assert_eq!(registry.apply_config(&cfg), 2);

    // Existing connection `s` still works after hot-reload!
    s.write_all(b"still-alive").await.unwrap();
    let mut echo2 = [0u8; 11];
    s.read_exact(&mut echo2).await.unwrap();
    assert_eq!(&echo2, b"still-alive");

    // New user 2 can now connect!
    let mut s2 = TcpStream::connect(("127.0.0.1", listen_port)).await.unwrap();
    s2.write_all(req.as_bytes()).await.unwrap();
    let _ = s2.read(&mut resp_buf).await.unwrap();
    let mut vless_req2 = build_vless_tcp_request(&parse_uuid(uuid2_str).unwrap(), echo_addr);
    vless_req2.extend_from_slice(b"user2-ok");
    s2.write_all(&vless_req2).await.unwrap();
    s2.read_exact(&mut vless_resp).await.unwrap();
    let mut echo3 = [0u8; 8];
    s2.read_exact(&mut echo3).await.unwrap();
    assert_eq!(&echo3, b"user2-ok");

    let _ = shutdown_tx.send(true);
    drop(s);
    drop(s2);
    srv.await.unwrap();
}

#[tokio::test]
async fn trojan_tcp_and_ws_handshake() {
    let echo_addr = spawn_tcp_echo_server().await;
    let trojan_port = free_local_port();
    let ws_port = free_local_port();
    let pass = "super-secret-trojan";
    let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    let cfg = XrayConfig {
        log: None,
        inbounds: vec![
            InboundConfig {
                tag: "trojan-tcp".to_string(),
                listen: "127.0.0.1".to_string(),
                port: PortSpec::Num(trojan_port),
                protocol: "trojan".to_string(),
                settings: InboundSettings {
                    clients: vec![ClientConfig {
                        id: String::new(),
                        password: pass.to_string(),
                        email: "t1".to_string(),
                        flow: String::new(),
                        level: 0,
                    }],
                    decryption: None,
                    fallbacks: vec![],
                },
                stream_settings: None,
            },
            InboundConfig {
                tag: "vless-ws".to_string(),
                listen: "127.0.0.1".to_string(),
                port: PortSpec::Num(ws_port),
                protocol: "vless".to_string(),
                settings: InboundSettings {
                    clients: vec![ClientConfig {
                        id: uuid_str.to_string(),
                        password: String::new(),
                        email: "w1".to_string(),
                        flow: String::new(),
                        level: 0,
                    }],
                    decryption: None,
                    fallbacks: vec![],
                },
                stream_settings: Some(StreamSettings {
                    network: "ws".to_string(),
                    security: "none".to_string(),
                    ws_settings: Some(WsSettings {
                        accept_proxy_protocol: false,
                        path: "/ws".to_string(),
                        host: String::new(),
                        headers: Default::default(),
                    }),
                    ..Default::default()
                }),
            },
        ],
        outbounds: vec![],
        routing: Some(Default::default()),
    };

    let registry = HotReloadRegistry::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv = tokio::spawn(async move {
        let _ = run_server(cfg, registry, shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // 1. Test Trojan TCP end-to-end
    let mut ts = TcpStream::connect(("127.0.0.1", trojan_port)).await.unwrap();
    let mut tr_req = Vec::new();
    tr_req.extend_from_slice(&trojan_password_hash(pass));
    tr_req.extend_from_slice(b"\r\n");
    tr_req.push(0x01); // CMD_TCP
    tr_req.push(0x01); // IPv4
    if let std::net::SocketAddr::V4(v4) = echo_addr {
        tr_req.extend_from_slice(&v4.ip().octets());
        tr_req.extend_from_slice(&v4.port().to_be_bytes());
    }
    tr_req.extend_from_slice(b"\r\n");
    tr_req.extend_from_slice(b"hello-trojan");
    ts.write_all(&tr_req).await.unwrap();

    let mut tr_echo = [0u8; 12];
    ts.read_exact(&mut tr_echo).await.unwrap();
    assert_eq!(&tr_echo, b"hello-trojan");

    // 2. Test WebSocket upgrade handshake
    let mut ws = TcpStream::connect(("127.0.0.1", ws_port)).await.unwrap();
    let ws_req = "GET /ws?ed=2048 HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    ws.write_all(ws_req.as_bytes()).await.unwrap();
    let mut resp = [0u8; 256];
    let n = ws.read(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp[..n]).unwrap();
    assert!(resp_str.contains("101 Switching Protocols"));
    assert!(resp_str.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

    let _ = Arc::new(shutdown_tx).send(true);
    drop(ts);
    drop(ws);
    srv.await.unwrap();
}
