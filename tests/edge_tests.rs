//! End-to-end tests for the edge: who the client is (trusted proxies,
//! PROXY protocol), request IDs, and the access log. Each test starts a real
//! proxy on a free port in front of a raw-TCP backend that reports the request
//! heads it receives, and talks to the proxy with raw bytes.

use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::config::LoggingConfig;
use soli_proxy::{
    build_rate_limiter, new_challenge_store, new_metrics, ConfigManager, LuaEngine, ProxyServer,
    ShutdownCoordinator,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

type Seen = mpsc::UnboundedReceiver<String>;

/// Backend answering every request `200 ok`, reporting each request head.
async fn spawn_backend() -> (u16, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let _ = tx.send(head.clone());
                if head.to_ascii_lowercase().contains("upgrade: websocket") {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                              Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n",
                        )
                        .await;
                    // Echo until the client goes away.
                    while let Ok(n) = sock.read(&mut tmp).await {
                        if n == 0 || sock.write_all(&tmp[..n]).await.is_err() {
                            return;
                        }
                    }
                    return;
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (port, rx)
}

/// Value of the first `name` header in a raw head (case-insensitive name).
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn header_count(head: &str, name: &str) -> usize {
    head.lines()
        .filter(|l| {
            l.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        })
        .count()
}

struct Proxy {
    port: u16,
    shutdown: ShutdownCoordinator,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.initiate();
    }
}

/// Start a proxy with `conf` as its route file and `server_extra` appended to
/// config.toml right after `[server]` (so bare keys land in `[server]`; later
/// sections may follow). `scripts` are route scripts.
async fn start_proxy(conf: &str, server_extra: &str, scripts: &[(&str, &str)]) -> Proxy {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let scripts_dir = dir.path().join("lua");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    for (name, src) in scripts {
        std::fs::write(scripts_dir.join(name), src).unwrap();
    }
    let port = portpicker::pick_unused_port().unwrap();
    let conf_path = dir.path().join("proxy.conf");
    std::fs::write(&conf_path, conf).unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "[server]\nbind = \"127.0.0.1:{}\"\nhttps_port = 443\n{}\n",
            port, server_extra
        ),
    )
    .unwrap();

    let manager = Arc::new(ConfigManager::new(conf_path.to_str().unwrap()).unwrap());
    let engine = if scripts.is_empty() {
        None
    } else {
        let names: Vec<String> = scripts.iter().map(|(n, _)| n.to_string()).collect();
        Some(
            LuaEngine::with_route_scripts(
                &scripts_dir,
                1,
                Duration::from_millis(100),
                &[],
                &names,
                &[],
            )
            .unwrap(),
        )
    };
    let cb_config = manager
        .get_config()
        .circuit_breaker
        .as_ref()
        .map(|t| CircuitBreakerConfig::from_toml(Some(t)))
        .unwrap_or_default();
    let rate_limiter = build_rate_limiter(&manager);
    let shutdown = ShutdownCoordinator::new();
    let server = ProxyServer::new(
        manager,
        shutdown.clone(),
        new_metrics(),
        new_challenge_store(),
        engine,
        Arc::new(CircuitBreaker::new(cb_config)),
        None,
        rate_limiter,
    )
    .unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Proxy {
                port,
                shutdown,
                _dir: dir,
            };
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not start on port {}", port);
}

/// Send `raw` verbatim and return the response (head plus `Content-Length`
/// bytes of body). Empty when the proxy closed the connection unanswered.
async fn raw_bytes(port: u16, raw: &[u8]) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _ = sock.write_all(raw).await;
    read_response(&mut sock).await
}

async fn raw(port: u16, raw: &str) -> String {
    raw_bytes(port, raw.as_bytes()).await
}

async fn read_response(sock: &mut TcpStream) -> String {
    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    let read_all = async {
        loop {
            if let Some(end) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&resp[..end]).to_string();
                if let Some(len) =
                    header(&head, "content-length").and_then(|v| v.parse::<usize>().ok())
                {
                    if resp.len() >= end + 4 + len {
                        return;
                    }
                }
            }
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => resp.extend_from_slice(&tmp[..n]),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read_all).await;
    String::from_utf8_lossy(&resp).to_string()
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {resp:?}"))
}

async fn next_head(seen: &mut Seen) -> String {
    tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("the backend saw no request")
        .unwrap()
}

/// Without `trusted_proxies` nothing changes: the peer is the client, every
/// forwarding claim and request ID it sends is replaced.
#[tokio::test]
async fn an_untrusted_peer_is_the_client_and_gets_a_fresh_request_id() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "real_ip_header = \"CF-Connecting-IP\"",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: https\r\n\
         CF-Connecting-IP: 6.6.6.6\r\nX-Request-Id: forged\r\n\
         traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(header(&head, "x-real-ip"), Some("127.0.0.1"));
    assert_eq!(header(&head, "x-forwarded-proto"), Some("http"));
    assert!(header(&head, "cf-connecting-ip").is_none(), "{head}");
    // A fresh ID, sent upstream and back to the client.
    let id = header(&head, "x-request-id").unwrap();
    assert_ne!(id, "forged");
    assert_eq!(id.len(), 32);
    assert_eq!(header_count(&head, "x-request-id"), 1);
    assert_eq!(header(&resp, "x-request-id"), Some(id));
    // W3C trace context passes through untouched.
    assert_eq!(
        header(&head, "traceparent"),
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    );
}

/// From a trusted proxy: the client is found in its chain, the chain is
/// appended to, its scheme and request ID are kept.
#[tokio::test]
async fn a_trusted_proxys_chain_names_the_client() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 6.6.6.6, 203.0.113.9, 10.1.1.1\r\n\
         X-Forwarded-Proto: https\r\nX-Request-Id: lb-abc-123\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(
        header(&head, "x-forwarded-for"),
        Some("6.6.6.6, 203.0.113.9, 10.1.1.1, 127.0.0.1")
    );
    assert_eq!(header(&head, "x-real-ip"), Some("203.0.113.9"));
    assert_eq!(header(&head, "x-forwarded-proto"), Some("https"));
    assert_eq!(header(&head, "x-request-id"), Some("lb-abc-123"));
    assert_eq!(header(&resp, "x-request-id"), Some("lb-abc-123"));

    // An invalid ID from a trusted peer is still replaced.
    raw(
        proxy.port,
        "GET / HTTP/1.1\r\nHost: h\r\nX-Request-Id: has space\r\n\r\n",
    )
    .await;
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-request-id").unwrap().len(), 32);
}

/// The rate limiter's budget belongs to the client behind the trusted proxy,
/// not to the proxy: one client running out does not throttle another.
#[tokio::test]
async fn rate_limits_are_per_real_client() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = \"loopback\"\n\n[rate_limiting]\nenabled = true\n\
         requests_per_second = 1\nburst_size = 1",
        &[],
    )
    .await;
    let from = |ip: &str| format!("GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: {ip}\r\n\r\n");
    assert_eq!(status(&raw(proxy.port, &from("198.51.100.1")).await), 200);
    assert_eq!(status(&raw(proxy.port, &from("198.51.100.1")).await), 429);
    assert_eq!(status(&raw(proxy.port, &from("198.51.100.2")).await), 200);
}

/// Request ID off: no header added, none returned.
#[tokio::test]
async fn request_ids_can_be_turned_off() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "request_id_header = \"\"",
        &[],
    )
    .await;
    let resp = raw(proxy.port, "GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
    assert_eq!(status(&resp), 200);
    assert!(header(&resp, "x-request-id").is_none());
    assert!(header(&next_head(&mut seen).await, "x-request-id").is_none());
}

/// Lua sees the decided client and the request ID.
#[tokio::test]
async fn lua_sees_client_ip_and_request_id() {
    let (backend, mut seen) = spawn_backend().await;
    let script = r#"
        function on_request(req)
            req:set_header("x-seen-ip", req.client_ip or "nil")
            req:set_header("x-seen-rid", req.request_id or "nil")
        end
    "#;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{} @script:edge.lua\n", backend),
        "trusted_proxies = [\"127.0.0.1\"]",
        &[("edge.lua", script)],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 192.0.2.44\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-seen-ip"), Some("192.0.2.44"));
    assert_eq!(header(&head, "x-seen-rid"), header(&resp, "x-request-id"));
}

fn pp_v2_ipv4(src: [u8; 4], sport: u16) -> Vec<u8> {
    let mut out = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00,
        0x0C,
    ];
    out.extend_from_slice(&src);
    out.extend_from_slice(&[127, 0, 0, 1]);
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&80u16.to_be_bytes());
    out
}

/// PROXY protocol: the carried address is the client, for the forwarding
/// headers and for the per-IP connection cap; a connection without a header
/// is closed.
#[tokio::test]
async fn proxy_protocol_names_the_client_and_is_capped_per_carried_address() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"127.0.0.1\"]\nproxy_protocol = \"any\"\n\n[limits]\n\
         max_connections_per_ip = 1",
        &[],
    )
    .await;

    // v1
    let resp = raw(
        proxy.port,
        "PROXY TCP4 198.51.100.7 127.0.0.1 40000 80\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-forwarded-for"), Some("198.51.100.7"));

    // v2
    let mut req = pp_v2_ipv4([203, 0, 113, 50], 40001);
    req.extend_from_slice(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    let resp = raw_bytes(proxy.port, &req).await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-real-ip"), Some("203.0.113.50"));

    // No header: closed without an answer.
    let resp = raw(proxy.port, "GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
    assert_eq!(resp, "");

    // One connection per carried address: a second from 198.51.100.9 is
    // closed while the first is open, one from another address is served.
    let mut held = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    held.write_all(b"PROXY TCP4 198.51.100.9 127.0.0.1 1 80\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = raw(
        proxy.port,
        "PROXY TCP4 198.51.100.9 127.0.0.1 2 80\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",
    )
    .await;
    assert_eq!(resp, "", "over the per-IP cap");
    let resp = raw(
        proxy.port,
        "PROXY TCP4 198.51.100.10 127.0.0.1 3 80\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    drop(held);
}

/// PROXY protocol is refused from a peer that is not a trusted proxy.
#[tokio::test]
async fn proxy_protocol_from_an_untrusted_peer_is_refused() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"10.0.0.0/8\"]\nproxy_protocol = \"v1\"",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "PROXY TCP4 198.51.100.7 127.0.0.1 40000 80\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",
    )
    .await;
    assert_eq!(resp, "");
}

/// The access log writes one line per request, when the body is done, with
/// the real client, the bytes sent, the upstream and the request ID.
#[tokio::test]
async fn the_access_log_has_one_line_per_request() {
    let (backend, _seen) = spawn_backend().await;
    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("access.log");
    soli_proxy::access_log::init(
        &LoggingConfig {
            access_log: Some(log_path.to_str().unwrap().to_string()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"127.0.0.1\"]",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET /logged?x=1 HTTP/1.1\r\nHost: logged.example\r\nUser-Agent: edge-test/1\r\n\
         Referer: https://ref.example/\r\nX-Forwarded-For: 192.0.2.77\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let id = header(&resp, "x-request-id").unwrap().to_string();

    let mut line = None;
    for _ in 0..100 {
        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        line = content
            .lines()
            .find(|l| l.contains(&id))
            .map(str::to_string);
        if line.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let line = line.expect("no access-log line for the request");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["client_ip"], "192.0.2.77");
    assert_eq!(v["method"], "GET");
    assert_eq!(v["host"], "logged.example");
    assert_eq!(v["path"], "/logged?x=1");
    assert_eq!(v["protocol"], "HTTP/1.1");
    assert_eq!(v["status"], 200);
    assert_eq!(v["bytes_out"], 2);
    assert_eq!(v["request_id"], id.as_str());
    assert_eq!(v["user_agent"], "edge-test/1");
    assert_eq!(v["referer"], "https://ref.example/");
    assert_eq!(v["tls"], false);
    assert_eq!(v["complete"], true);
    let upstream = v["upstream"].as_str().unwrap();
    assert!(
        upstream.starts_with(&format!("http://127.0.0.1:{}/", backend)),
        "{upstream}"
    );
    assert!(v["duration_ms"].as_f64().unwrap() >= 0.0);

    // A WebSocket upgrade is logged with its 101, and the tunnel still works
    // through the access log's body wrapper.
    let mut sock = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    sock.write_all(
        b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "closed before the 101");
        got.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&got).to_string();
    assert_eq!(status(&head), 101, "{head}");
    let ws_id = header(&head, "x-request-id").unwrap().to_string();
    sock.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"ping");
    let mut found = false;
    for _ in 0..100 {
        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        if let Some(l) = content.lines().find(|l| l.contains(&ws_id)) {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["status"], 101);
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(found, "no access-log line for the upgrade");
}

/// `$client_ip` in a `headers { }` block is the client a trusted proxy names,
/// not the proxy: it was read after the request's extensions were cleared,
/// so it always fell back to the TCP peer.
#[tokio::test]
async fn headers_block_client_ip_is_the_forwarded_client() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!(
            "default -> http://127.0.0.1:{}\nheaders {{\n    X-Client: $client_ip\n}}\n",
            backend
        ),
        "trusted_proxies = [\"127.0.0.1\"]",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-client"), Some("203.0.113.9"), "{head}");
}

/// `/metrics` is for this host only, judged on the connection — never on a
/// forwarded claim. A tenant container on a trusted Docker range (here the
/// PROXY header's source, 172.18.0.5) saying `X-Forwarded-For: 127.0.0.1`
/// used to read it; a request relayed for a remote client by a front proxy
/// on this host is not local either.
#[tokio::test]
async fn metrics_are_not_opened_by_a_forwarded_loopback_claim() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"127.0.0.1\", \"172.16.0.0/12\"]\nproxy_protocol = \"any\"",
        &[],
    )
    .await;
    let get = |pp: &str, xff: &str| {
        format!(
            "PROXY TCP4 {pp} 127.0.0.1 40000 80\r\nGET /metrics HTTP/1.1\r\nHost: h\r\n\
             {xff}Connection: close\r\n\r\n"
        )
    };
    // From a tenant's range, forging this host.
    let resp = raw(
        proxy.port,
        &get("172.18.0.5", "X-Forwarded-For: 127.0.0.1\r\n"),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    // From this host, relaying a remote client.
    let resp = raw(
        proxy.port,
        &get("127.0.0.1", "X-Forwarded-For: 203.0.113.9\r\n"),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    // From this host, for itself.
    let resp = raw(proxy.port, &get("127.0.0.1", "")).await;
    assert_eq!(status(&resp), 200, "{resp}");
}

/// A PROXY header that names no client (v1 `UNKNOWN`, v2 `LOCAL`) is served —
/// the balancer's health check — but what the connection says about its
/// client is not believed: the balancer did not write it.
#[tokio::test]
async fn an_addressless_proxy_header_does_not_vouch_for_forwarding_headers() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "trusted_proxies = [\"127.0.0.1\"]\nproxy_protocol = \"any\"",
        &[],
    )
    .await;
    let forged = "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 6.6.6.6\r\n\
                  X-Forwarded-Proto: https\r\nX-Request-Id: forged\r\n\r\n";
    // v2 LOCAL: signature, version 2 / command LOCAL, AF_UNSPEC, no address.
    let mut local = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00, 0x00,
        0x00,
    ];
    local.extend_from_slice(forged.as_bytes());
    let mut unknown = b"PROXY UNKNOWN\r\n".to_vec();
    unknown.extend_from_slice(forged.as_bytes());
    for req in [unknown, local] {
        let resp = raw_bytes(proxy.port, &req).await;
        assert_eq!(status(&resp), 200, "{resp}");
        let head = next_head(&mut seen).await;
        assert_eq!(
            header(&head, "x-forwarded-for"),
            Some("127.0.0.1"),
            "{head}"
        );
        assert_eq!(header(&head, "x-forwarded-proto"), Some("http"), "{head}");
        assert_ne!(header(&head, "x-request-id"), Some("forged"), "{head}");
    }
}

/// Send a WebSocket upgrade with `extra` header lines; the response head.
async fn upgrade(port: u16, extra: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(
        format!(
            "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             {extra}\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&buf).to_string()
}

/// A WebSocket upgrade picks its target like a request does: past a target
/// whose breaker is open. It used to go to the rule's first target always.
#[tokio::test]
async fn websocket_upgrades_skip_a_broken_target() {
    let (backend, _seen) = spawn_backend().await;
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let proxy = start_proxy(
        &format!(
            "default -> http://127.0.0.1:{closed}, http://127.0.0.1:{backend} @lb:round-robin\n"
        ),
        "\n[circuit_breaker]\nfailure_threshold = 1\nrecovery_timeout_secs = 300",
        &[],
    )
    .await;
    // The first two upgrades meet both targets; the dead one's breaker opens.
    for _ in 0..2 {
        upgrade(proxy.port, "").await;
    }
    for _ in 0..3 {
        let resp = upgrade(proxy.port, "").await;
        assert_eq!(status(&resp), 101, "{resp}");
    }
}

/// A rule's `headers { }` block applies to its WebSocket upgrades too.
#[tokio::test]
async fn headers_block_applies_to_websocket_upgrades() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!(
            "default -> http://127.0.0.1:{backend}\nheaders {{\n    X-Ws-Client: $client_ip\n    \
             X-Forwarded-Proto: https\n    -X-Drop\n}}\n"
        ),
        "",
        &[],
    )
    .await;
    let resp = upgrade(proxy.port, "X-Drop: secret\r\nX-Keep: yes\r\n").await;
    assert_eq!(status(&resp), 101, "{resp}");
    let head = next_head(&mut seen).await;
    assert_eq!(header(&head, "x-ws-client"), Some("127.0.0.1"), "{head}");
    assert_eq!(header(&head, "x-forwarded-proto"), Some("https"), "{head}");
    assert_eq!(header_count(&head, "x-forwarded-proto"), 1, "{head}");
    assert!(header(&head, "x-drop").is_none(), "{head}");
    assert_eq!(header(&head, "x-keep"), Some("yes"), "{head}");
    assert_eq!(header_count(&head, "host"), 1, "{head}");
}
