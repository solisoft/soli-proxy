//! End-to-end tests for the request-path hardening: what a client can and
//! cannot make the proxy do with the request it sends. Each test starts a real
//! proxy on a free port in front of a minimal raw-TCP backend, and talks to it
//! with raw bytes where an HTTP client would normalise the attack away.

use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::{
    new_challenge_store, new_metrics, ConfigManager, LuaEngine, ProxyServer, ShutdownCoordinator,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// What a backend saw: the raw request head of every request.
type Seen = mpsc::UnboundedReceiver<String>;

/// Backend answering every request `200 ok`, reporting each request head.
/// When the request is a WebSocket upgrade it answers 101 instead and keeps
/// the socket open until the peer closes it.
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
                    // Hold the tunnel open until the client goes away.
                    while matches!(sock.read(&mut tmp).await, Ok(n) if n > 0) {}
                    return;
                }
                // Wait for a declared body in full before answering, so an
                // upload the client abandons fails on the proxy's side.
                let declared = header(&head, "content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let head_len = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let mut have = buf.len() - head_len;
                while have < declared {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => have += n,
                    }
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

/// Start a proxy with `conf` as its route file, `toml_extra` appended to its
/// config.toml, and `scripts` as (file name, source) route scripts.
async fn start_proxy(conf: &str, toml_extra: &str, scripts: &[(&str, &str)]) -> Proxy {
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
            "[server]\nbind = \"127.0.0.1:{}\"\nhttps_port = 443\n\n{}",
            port, toml_extra
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
    let shutdown = ShutdownCoordinator::new();
    let server = ProxyServer::new(
        manager,
        shutdown.clone(),
        new_metrics(),
        new_challenge_store(),
        engine,
        Arc::new(CircuitBreaker::new(cb_config)),
        None,
        None,
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

/// Send `raw` verbatim and return the response: its head plus as much body as
/// `Content-Length` announces (or everything up to EOF without one). Empty
/// when the proxy closed the connection without answering.
async fn raw(port: u16, raw: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(raw.as_bytes()).await.unwrap();
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

const WS_UPGRADE: &str = "Upgrade: websocket\r\nConnection: Upgrade\r\n\
                          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                          Sec-WebSocket-Version: 13\r\n";

/// A route guarded by a Lua script must stay guarded for a WebSocket upgrade:
/// the script's deny applies, and its header rewrite replaces the client's.
#[tokio::test]
async fn websocket_upgrade_runs_the_route_scripts() {
    let (backend, mut seen) = spawn_backend().await;
    let script = r#"
        function on_request(req)
            if req.headers["authorization"] ~= "Bearer good" then
                return req:deny(403, "denied by script")
            end
            req:set_header("x-user", "from-script")
        end
    "#;
    let proxy = start_proxy(
        &format!(
            "/ws/* -> http://127.0.0.1:{}/ws/ @script:auth.lua\n",
            backend
        ),
        "",
        &[("auth.lua", script)],
    )
    .await;

    // No credentials: the script's deny, not a tunnel.
    let resp = raw(
        proxy.port,
        &format!("GET /ws/chat HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}X-User: admin\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&resp), 403, "{resp}");
    assert!(seen.try_recv().is_err(), "the backend must not be reached");

    // With credentials: tunnelled, and the backend sees the script's x-user,
    // never the forged one.
    let mut sock = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    sock.write_all(
        format!(
            "GET /ws/chat HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}Authorization: Bearer good\r\n\
             X-User: admin\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status(&String::from_utf8_lossy(&buf[..n])), 101);
    let head = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header(&head, "x-user"), Some("from-script"), "{head}");
    assert_eq!(header_count(&head, "x-user"), 1, "{head}");
}

/// A route on_route hook that raises denies the upgrade too (fail closed).
#[tokio::test]
async fn websocket_upgrade_runs_route_on_route() {
    let (backend, mut seen) = spawn_backend().await;
    let script = r#"
        function on_route(req, target)
            error("boom")
        end
    "#;
    let proxy = start_proxy(
        &format!(
            "/ws/* -> http://127.0.0.1:{}/ws/ @script:route.lua\n",
            backend
        ),
        "",
        &[("route.lua", script)],
    )
    .await;
    let resp = raw(
        proxy.port,
        &format!("GET /ws/x HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}\r\n"),
    )
    .await;
    assert_eq!(status(&resp), 500, "{resp}");
    assert!(seen.try_recv().is_err());
}

/// `//admin/x` and `/%61dmin/x` are `/admin/x` to the backend, so they must
/// meet the `/admin/*` rule's password, not fall through to the open rule.
#[tokio::test]
async fn encoded_and_doubled_slash_paths_cannot_skip_auth() {
    let (backend, _seen) = spawn_backend().await;
    let hash = soli_proxy::auth::generate_hash("s3cret");
    let proxy = start_proxy(
        &format!(
            "/admin/* -> http://127.0.0.1:{b}/ @auth:admin:{hash}\n\
             /* -> http://127.0.0.1:{b}/\n",
            b = backend
        ),
        "",
        &[],
    )
    .await;
    for path in ["/admin/x", "//admin/x", "/%61dmin/x", "/%61%64min//x"] {
        let resp = raw(
            proxy.port,
            &format!("GET {path} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status(&resp), 401, "{path} served without credentials");
    }
    let resp = raw(
        proxy.port,
        "GET /public HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200);
}

/// The backend sees the proxy's view of the client, never the client's own
/// forwarding headers — on a plain path rule as on a domain rule.
#[tokio::test]
async fn client_forwarding_headers_never_reach_the_backend() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(&format!("/* -> http://127.0.0.1:{}/\n", backend), "", &[]).await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: real.example\r\nConnection: close\r\n\
         Forwarded: for=1.2.3.4;proto=https\r\nX-Forwarded-For: 1.2.3.4\r\n\
         X-Real-IP: 10.0.0.1\r\nX-Forwarded-Host: evil.example\r\n\
         X-Forwarded-Port: 443\r\nX-Forwarded-Prefix: /admin\r\nX-Forwarded-Ssl: on\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200);
    let head = seen.recv().await.unwrap();
    assert!(header(&head, "forwarded").is_none(), "{head}");
    assert!(header(&head, "x-forwarded-port").is_none(), "{head}");
    assert!(header(&head, "x-forwarded-prefix").is_none(), "{head}");
    assert!(header(&head, "x-forwarded-ssl").is_none(), "{head}");
    assert_eq!(
        header(&head, "x-forwarded-for"),
        Some("127.0.0.1"),
        "{head}"
    );
    assert_eq!(header(&head, "x-real-ip"), Some("127.0.0.1"), "{head}");
    assert_eq!(header(&head, "x-forwarded-proto"), Some("http"), "{head}");
    assert_eq!(
        header(&head, "x-forwarded-host"),
        Some("real.example"),
        "{head}"
    );
    assert_eq!(header_count(&head, "x-forwarded-for"), 1, "{head}");
}

/// A client's `Connection: x-user` must not delete the x-user a script set.
#[tokio::test]
async fn connection_listed_header_cannot_remove_a_script_header() {
    let (backend, mut seen) = spawn_backend().await;
    let script = r#"
        function on_request(req)
            req:set_header("x-user", "from-script")
        end
    "#;
    let proxy = start_proxy(
        &format!("/* -> http://127.0.0.1:{}/ @script:user.lua\n", backend),
        "",
        &[("user.lua", script)],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close, x-user\r\nX-User: admin\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200);
    let head = seen.recv().await.unwrap();
    assert_eq!(header(&head, "x-user"), Some("from-script"), "{head}");
}

/// A deny with a status no HTTP response can carry is answered 500, rather
/// than panicking the connection (which dropped it without a response).
#[tokio::test]
async fn lua_deny_with_an_impossible_status_answers_500() {
    let (backend, _seen) = spawn_backend().await;
    let script = r#"
        function on_request(req)
            return { status = 1000, body = "nope" }
        end
    "#;
    let proxy = start_proxy(
        &format!("/* -> http://127.0.0.1:{}/ @script:deny.lua\n", backend),
        "",
        &[("deny.lua", script)],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 500, "{resp}");
}

/// CONNECT, authority-form and asterisk-form targets, and duplicate Host
/// headers are refused up front instead of panicking or being routed.
#[tokio::test]
async fn malformed_request_targets_are_refused() {
    let (backend, mut seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("default -> http://127.0.0.1:{}\n", backend),
        "",
        &[],
    )
    .await;
    let cases = [
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            405,
        ),
        (
            "OPTIONS * HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            200,
        ),
        (
            "GET /x HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nConnection: close\r\n\r\n",
            400,
        ),
    ];
    for (req, want) in cases {
        let resp = raw(proxy.port, req).await;
        assert_eq!(status(&resp), want, "{req:?} -> {resp}");
    }
    // The proxy is still alive and routing.
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200);
    let mut reached = 0;
    while seen.try_recv().is_ok() {
        reached += 1;
    }
    assert_eq!(
        reached, 1,
        "only the well-formed request reaches the backend"
    );
}

/// The force_https redirect is built from a validated host, so a Host with
/// userinfo cannot point the Location at another site.
#[tokio::test]
async fn force_https_redirect_cannot_be_pointed_elsewhere() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("example.com -> http://127.0.0.1:{}\n", backend),
        "[tls]\nmode = \"disabled\"\ncache_dir = \"./certs\"\nforce_https = true\n",
        &[],
    )
    .await;
    let resp = raw(
        proxy.port,
        "GET /p?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 308, "{resp}");
    assert_eq!(header(&resp, "location"), Some("https://example.com/p?q=1"));
    for evil in [
        "example.com:@evil.com",
        "example.com:80@evil.com",
        "example.com/x",
    ] {
        let resp = raw(
            proxy.port,
            &format!("GET / HTTP/1.1\r\nHost: {evil}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status(&resp), 400, "{evil}: {resp}");
        assert!(!resp.to_ascii_lowercase().contains("evil.com"), "{resp}");
    }
}

/// A client that abandons its upload has not shown the backend to be broken:
/// with a breaker that opens on the first failure, the next request must
/// still be served.
#[tokio::test]
async fn aborted_upload_does_not_trip_the_circuit_breaker() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("/* -> http://127.0.0.1:{}/\n", backend),
        "[circuit_breaker]\nfailure_threshold = 1\nrecovery_timeout_secs = 300\n",
        &[],
    )
    .await;
    for _ in 0..3 {
        let mut sock = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        sock.write_all(
            b"POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 100000\r\n\r\npartial",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(sock); // abandon the upload mid-body
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&resp),
        200,
        "breaker tripped by a client abort: {resp}"
    );
}

/// One address cannot hold more than `max_connections_per_ip` connections.
#[tokio::test]
async fn per_ip_connection_cap_refuses_the_excess() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("/* -> http://127.0.0.1:{}/\n", backend),
        "[limits]\nmax_connections_per_ip = 2\n",
        &[],
    )
    .await;
    // Give the readiness probe's connection time to be released.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _a = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let _b = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.is_empty(), "third connection was served: {resp}");
    drop(_a);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "a freed slot is reusable");
}

/// An open WebSocket tunnel keeps holding its connection's slots after hyper
/// has handed the socket over. Observed through the per-IP cap: with one
/// connection allowed, the tunnel must keep the next one out until it closes.
/// (The same lease carries the `max_connections` permit; that cap is not
/// exercised directly here because its permit-before-accept loops — one per
/// core — cannot be driven deterministically with a cap of one.)
#[tokio::test]
async fn websocket_tunnel_keeps_its_connection_slot() {
    let (backend, _seen) = spawn_backend().await;
    let proxy = start_proxy(
        &format!("/* -> http://127.0.0.1:{}/\n", backend),
        "[limits]\nmax_connections_per_ip = 1\n",
        &[],
    )
    .await;
    // Let the readiness probe's connection be released.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut ws = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    ws.write_all(format!("GET /ws HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), ws.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status(&String::from_utf8_lossy(&buf[..n])), 101);
    // hyper has finished with the upgraded connection by now.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.is_empty(),
        "served while the tunnel held the slot: {resp}"
    );

    // Closing the tunnel frees it.
    drop(ws);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = raw(
        proxy.port,
        "GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "slot released when the tunnel closed");
}
