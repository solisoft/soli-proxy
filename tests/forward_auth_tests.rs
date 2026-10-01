//! End-to-end tests for forward authentication (`@forward_auth`): a real
//! proxy in front of a raw-TCP backend, gated by a fake auth service that
//! decides on the `Cookie` it is shown — the way oauth2-proxy, Authelia or
//! Authentik do.

use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::{
    new_challenge_store, new_metrics, ConfigManager, ProxyServer, ShutdownCoordinator,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// What a server saw: the raw request head of every request.
type Seen = mpsc::UnboundedReceiver<String>;

/// Read one request head from `sock`.
async fn read_head(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buf).to_string());
        }
    }
}

/// Backend answering `200 ok` (or `101` to a WebSocket upgrade, held open),
/// reporting each request head.
async fn spawn_backend() -> (u16, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Some(head) = read_head(&mut sock).await else {
                    return;
                };
                let _ = tx.send(head.clone());
                if head.to_ascii_lowercase().contains("upgrade: websocket") {
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                              Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n",
                        )
                        .await;
                    let mut tmp = [0u8; 1024];
                    while matches!(sock.read(&mut tmp).await, Ok(n) if n > 0) {}
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

/// The fake auth service. It decides on the `session` cookie:
/// - `good`: 200, with `X-Auth-User: alice` and `X-Auth-Email`;
/// - `redirect`: 302 to a login page, setting a CSRF cookie;
/// - `slow`: never answers;
/// - anything else, or none: 401 with a body.
async fn spawn_auth() -> (u16, Seen) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Some(head) = read_head(&mut sock).await else {
                    return;
                };
                let _ = tx.send(head.clone());
                let cookie = header(&head, "cookie").unwrap_or_default().to_string();
                let response: &[u8] = if cookie.contains("session=good") {
                    b"HTTP/1.1 200 OK\r\nX-Auth-User: alice\r\n\
                      X-Auth-Email: alice@example.com\r\nX-Internal: no\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n"
                } else if cookie.contains("session=redirect") {
                    b"HTTP/1.1 302 Found\r\n\
                      Location: https://login.example.com/?rd=https%3A%2F%2Fh%2Fapp%2Fpage\r\n\
                      Set-Cookie: csrf=abc; HttpOnly\r\nContent-Length: 11\r\n\
                      Connection: close\r\n\r\nredirecting"
                } else if cookie.contains("session=slow") {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                } else {
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\
                      Content-Length: 13\r\nConnection: close\r\n\r\nplease log in"
                };
                let _ = sock.write_all(response).await;
            });
        }
    });
    (port, rx)
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
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

/// Start a proxy with `conf` as its route file and `toml_extra` appended to
/// its config.toml.
async fn start_proxy(conf: &str, toml_extra: &str) -> Proxy {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
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
        None,
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
/// `Content-Length` announces (or everything up to EOF without one).
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
    let _ = tokio::time::timeout(Duration::from_secs(10), read_all).await;
    String::from_utf8_lossy(&resp).to_string()
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {resp:?}"))
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

async fn next(seen: &mut Seen) -> String {
    tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("nothing seen in time")
        .unwrap()
}

/// One proxy, one route gated by the fake auth service with two copied
/// headers and a `@noauth` carve-out.
async fn gated() -> (Proxy, Seen, Seen) {
    let (backend, seen_backend) = spawn_backend().await;
    let (auth, seen_auth) = spawn_auth().await;
    let proxy = start_proxy(
        &format!(
            "/app/* -> http://127.0.0.1:{backend}/ \
             @forward_auth:http://127.0.0.1:{auth}/verify?app=demo \
             @forward_auth_headers:X-Auth-User,X-Auth-Email @noauth:/app/public/*\n"
        ),
        "[forward_auth]\ntimeout_secs = 1\n",
    )
    .await;
    (proxy, seen_backend, seen_auth)
}

/// 2xx: the request goes through with the auth service's headers — and only
/// those: the client's forged copies are gone, and a header the route does
/// not name is not copied.
#[tokio::test]
async fn allowed_request_carries_the_auth_headers_and_never_the_forged_ones() {
    let (proxy, mut backend, mut auth) = gated().await;
    let resp = raw(
        proxy.port,
        "GET /app/page?q=1 HTTP/1.1\r\nHost: h\r\nCookie: session=good\r\n\
         X-Auth-User: mallory\r\nX-Auth-User: root\r\nX-Auth-Email: m@evil\r\n\
         X-Secret: s\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");

    let asked = next(&mut auth).await;
    assert!(
        asked.starts_with("GET /verify?app=demo HTTP/1.1\r\n"),
        "{asked}"
    );
    assert_eq!(header(&asked, "cookie"), Some("session=good"), "{asked}");
    assert_eq!(header(&asked, "x-forwarded-method"), Some("GET"), "{asked}");
    assert_eq!(
        header(&asked, "x-forwarded-uri"),
        Some("/app/page?q=1"),
        "{asked}"
    );
    assert_eq!(header(&asked, "x-forwarded-host"), Some("h"), "{asked}");
    assert_eq!(header(&asked, "x-forwarded-proto"), Some("http"), "{asked}");
    assert_eq!(
        header(&asked, "x-forwarded-for"),
        Some("127.0.0.1"),
        "{asked}"
    );
    // The auth service is addressed as itself, and not shown the rest.
    assert!(
        header(&asked, "host").is_some_and(|h| h.starts_with("127.0.0.1:")),
        "{asked}"
    );
    assert!(header(&asked, "x-secret").is_none(), "{asked}");
    assert!(header(&asked, "x-auth-user").is_none(), "{asked}");

    let head = next(&mut backend).await;
    assert_eq!(header(&head, "x-auth-user"), Some("alice"), "{head}");
    assert_eq!(header_count(&head, "x-auth-user"), 1, "{head}");
    assert_eq!(
        header(&head, "x-auth-email"),
        Some("alice@example.com"),
        "{head}"
    );
    assert_eq!(header_count(&head, "x-auth-email"), 1, "{head}");
    assert!(header(&head, "x-internal").is_none(), "{head}");
    assert_eq!(header(&head, "x-secret"), Some("s"), "{head}");
}

/// 401: the auth service's answer is the client's, and the upstream is
/// never contacted.
#[tokio::test]
async fn denied_request_gets_the_auth_services_401() {
    let (proxy, mut backend, mut auth) = gated().await;
    let resp = raw(
        proxy.port,
        "GET /app/page HTTP/1.1\r\nHost: h\r\nCookie: session=bad\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 401, "{resp}");
    assert_eq!(body(&resp), "please log in", "{resp}");
    assert_eq!(header(&resp, "content-type"), Some("text/plain"), "{resp}");
    next(&mut auth).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        backend.try_recv().is_err(),
        "the backend must not be reached"
    );
}

/// 3xx: the redirect to the login page reaches the browser intact —
/// `Location`, `Set-Cookie` and body.
#[tokio::test]
async fn redirect_to_the_login_page_is_relayed() {
    let (proxy, mut backend, _auth) = gated().await;
    let resp = raw(
        proxy.port,
        "GET /app/page HTTP/1.1\r\nHost: h\r\nCookie: session=redirect\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 302, "{resp}");
    assert_eq!(
        header(&resp, "location"),
        Some("https://login.example.com/?rd=https%3A%2F%2Fh%2Fapp%2Fpage"),
        "{resp}"
    );
    assert_eq!(
        header(&resp, "set-cookie"),
        Some("csrf=abc; HttpOnly"),
        "{resp}"
    );
    assert_eq!(body(&resp), "redirecting", "{resp}");
    assert!(
        backend.try_recv().is_err(),
        "the backend must not be reached"
    );
}

/// No answer — refused or too slow — is a 503, never a pass.
#[tokio::test]
async fn unreachable_or_slow_auth_service_fails_closed() {
    let (backend, mut seen_backend) = spawn_backend().await;
    let down = closed_port().await;
    let (auth, _seen_auth) = spawn_auth().await;
    let proxy = start_proxy(
        &format!(
            "/down/* -> http://127.0.0.1:{backend}/ @forward_auth:http://127.0.0.1:{down}/verify\n\
             /slow/* -> http://127.0.0.1:{backend}/ @forward_auth:http://127.0.0.1:{auth}/verify\n"
        ),
        "[forward_auth]\ntimeout_secs = 1\n",
    )
    .await;

    let resp = raw(
        proxy.port,
        "GET /down/x HTTP/1.1\r\nHost: h\r\nCookie: session=good\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 503, "{resp}");

    let started = Instant::now();
    let resp = raw(
        proxy.port,
        "GET /slow/x HTTP/1.1\r\nHost: h\r\nCookie: session=slow\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 503, "{resp}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the timeout was not applied: {:?}",
        started.elapsed()
    );
    assert!(
        seen_backend.try_recv().is_err(),
        "the backend must not be reached"
    );
}

/// A `@noauth` carve-out skips the auth service — but still never forwards a
/// client's copy of a header the auth service is trusted to set.
#[tokio::test]
async fn noauth_paths_skip_the_check_but_not_the_strip() {
    let (proxy, mut backend, mut auth) = gated().await;
    let resp = raw(
        proxy.port,
        "GET /app/public/logo.png HTTP/1.1\r\nHost: h\r\nX-Auth-User: admin\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let head = next(&mut backend).await;
    assert!(header(&head, "x-auth-user").is_none(), "{head}");
    assert!(
        auth.try_recv().is_err(),
        "the auth service must not be asked"
    );
}

/// A WebSocket upgrade is gated like any request: refused without a session,
/// tunnelled with one — carrying the auth service's identity, not the
/// client's.
#[tokio::test]
async fn websocket_upgrade_is_gated_by_forward_auth() {
    const WS_UPGRADE: &str = "Upgrade: websocket\r\nConnection: Upgrade\r\n\
                              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                              Sec-WebSocket-Version: 13\r\n";
    let (proxy, mut backend, _auth) = gated().await;

    let resp = raw(
        proxy.port,
        &format!("GET /app/ws HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}X-Auth-User: admin\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&resp), 401, "{resp}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        backend.try_recv().is_err(),
        "the backend must not be reached"
    );

    let mut sock = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    sock.write_all(
        format!(
            "GET /app/ws HTTP/1.1\r\nHost: h\r\n{WS_UPGRADE}Cookie: session=good\r\n\
             X-Auth-User: admin\r\n\r\n"
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
    let head = next(&mut backend).await;
    assert_eq!(header(&head, "x-auth-user"), Some("alice"), "{head}");
    assert_eq!(header_count(&head, "x-auth-user"), 1, "{head}");
}

/// `@auth` and `@forward_auth` on one route: Basic first, both must pass, and
/// the Basic password is never shown to the auth service.
#[tokio::test]
async fn basic_auth_runs_first_and_its_password_stays_here() {
    let (backend, mut seen_backend) = spawn_backend().await;
    let (auth, mut seen_auth) = spawn_auth().await;
    let hash = soli_proxy::auth::hash_password("s3cret", 4);
    let proxy = start_proxy(
        &format!(
            "/both/* -> http://127.0.0.1:{backend}/ @auth:admin:{hash} \
             @forward_auth:http://127.0.0.1:{auth}/verify\n"
        ),
        "",
    )
    .await;

    // No Basic credential: Basic's 401, the auth service is not asked.
    let resp = raw(
        proxy.port,
        "GET /both/x HTTP/1.1\r\nHost: h\r\nCookie: session=good\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&resp), 401, "{resp}");
    assert!(header(&resp, "www-authenticate").is_some(), "{resp}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(seen_auth.try_recv().is_err(), "asked before Basic passed");

    // Basic passes but the session does not: the auth service's 401.
    let basic = "YWRtaW46czNjcmV0"; // admin:s3cret
    let resp = raw(
        proxy.port,
        &format!(
            "GET /both/x HTTP/1.1\r\nHost: h\r\nAuthorization: Basic {basic}\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status(&resp), 401, "{resp}");
    assert_eq!(body(&resp), "please log in", "{resp}");
    let asked = next(&mut seen_auth).await;
    assert!(header(&asked, "authorization").is_none(), "{asked}");

    // Both pass.
    let resp = raw(
        proxy.port,
        &format!(
            "GET /both/x HTTP/1.1\r\nHost: h\r\nAuthorization: Basic {basic}\r\n\
             Cookie: session=good\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status(&resp), 200, "{resp}");
    let asked = next(&mut seen_auth).await;
    assert!(header(&asked, "authorization").is_none(), "{asked}");
    let head = next(&mut seen_backend).await;
    assert_eq!(
        header(&head, "x-auth-user"),
        None,
        "nothing to copy: {head}"
    );
}
