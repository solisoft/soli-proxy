//! End-to-end tests for what the proxy does to responses on the way out:
//! compression, custom error pages and maintenance mode. Each test starts a
//! real proxy (and, where needed, its admin API) in front of a small raw-TCP
//! backend.

use soli_proxy::admin::{run_admin_server, AdminState};
use soli_proxy::app::{AppManager, PortManager};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::{
    new_challenge_store, new_metrics, ConfigManager, ProxyServer, ShutdownCoordinator,
};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A page big enough to be compressed, with root-relative links for the
/// prefix-mount rewrite to change.
fn page() -> String {
    let mut html = String::from("<!doctype html><html><body>\n");
    for i in 0..400 {
        html.push_str(&format!(
            "<p><a href=\"/item/{i}\">Item {i}</a> — some text that repeats.</p>\n"
        ));
    }
    html.push_str("</body></html>\n");
    html
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Backend answering by path:
/// - `/big`: the page, `text/html`, with a strong ETag;
/// - `/sse`: the page as `text/event-stream`;
/// - `/small`: four bytes of text;
/// - `/gz`: the page, gzip-encoded by the backend itself;
/// - `/missing`: the backend's own 404 page;
/// - anything else: `ok`.
async fn spawn_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, extra, body): (&str, &str, Vec<u8>) = match path.as_str() {
                    "/big" => (
                        "200 OK",
                        "Content-Type: text/html; charset=utf-8\r\nETag: \"v1\"\r\n",
                        page().into_bytes(),
                    ),
                    "/sse" => (
                        "200 OK",
                        "Content-Type: text/event-stream\r\n",
                        page().into_bytes(),
                    ),
                    "/small" => ("200 OK", "Content-Type: text/plain\r\n", b"tiny".to_vec()),
                    "/gz" => (
                        "200 OK",
                        "Content-Type: text/html\r\nContent-Encoding: gzip\r\n",
                        gzip(page().as_bytes()),
                    ),
                    "/missing" => (
                        "404 Not Found",
                        "Content-Type: text/html\r\n",
                        b"<h1>the backend's own 404</h1>".to_vec(),
                    ),
                    _ => ("200 OK", "Content-Type: text/plain\r\n", b"ok".to_vec()),
                };
                let head_only = head.starts_with("HEAD ");
                let mut out = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                if !head_only {
                    out.extend_from_slice(&body);
                }
                let _ = sock.write_all(&out).await;
            });
        }
    });
    port
}

struct Proxy {
    port: u16,
    admin_port: u16,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.initiate();
    }
}

async fn wait_for(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing listening on {port}");
}

/// Start a proxy (and its admin API) with `conf` as proxy.conf and
/// `toml_extra` appended to config.toml. `sites` is a sites directory for an
/// app manager, discovered without starting anything.
async fn start_proxy(conf: &str, toml_extra: &str, sites: Option<&std::path::Path>) -> Proxy {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let port = portpicker::pick_unused_port().unwrap();
    let admin_port = portpicker::pick_unused_port().unwrap();
    let conf_path = dir.path().join("proxy.conf");
    std::fs::write(&conf_path, conf).unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "[server]\nbind = \"127.0.0.1:{port}\"\nhttps_port = 443\n\n\
             [admin]\nenabled = true\nbind = \"127.0.0.1:{admin_port}\"\n\n{toml_extra}"
        ),
    )
    .unwrap();
    let manager = Arc::new(ConfigManager::new(conf_path.to_str().unwrap()).unwrap());
    let app_manager = match sites {
        Some(sites) => {
            let ports =
                Arc::new(PortManager::new(dir.path().join("run").to_str().unwrap()).unwrap());
            let apps =
                AppManager::new(sites.to_str().unwrap(), ports, manager.clone(), false).unwrap();
            apps.discover_apps_readonly().await.unwrap();
            Some(Arc::new(apps))
        }
        None => None,
    };
    let breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default()));
    let shutdown = ShutdownCoordinator::new();
    let server = ProxyServer::new(
        manager.clone(),
        shutdown.clone(),
        new_metrics(),
        new_challenge_store(),
        None,
        breaker.clone(),
        app_manager.clone(),
        None,
    )
    .unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    let state = Arc::new(AdminState {
        config_manager: manager.clone(),
        metrics: new_metrics(),
        start_time: Instant::now(),
        circuit_breaker: breaker,
        app_manager,
        rate_limiter: None,
        tls_manager: None,
        challenge_store: None,
    });
    tokio::spawn(async move {
        let _ = run_admin_server(state).await;
    });
    wait_for(port).await;
    wait_for(admin_port).await;
    Proxy {
        port,
        admin_port,
        config: manager,
        shutdown,
        _dir: dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn get(proxy: &Proxy, host: &str, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut req = client()
        .get(format!("http://127.0.0.1:{}{}", proxy.port, path))
        .header("Host", host);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

fn header<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn decode(coding: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match coding {
        "gzip" => {
            flate2::read::GzDecoder::new(data)
                .read_to_end(&mut out)
                .unwrap();
        }
        "br" => {
            brotli::Decompressor::new(data, 4096)
                .read_to_end(&mut out)
                .unwrap();
        }
        "zstd" => out = zstd::stream::decode_all(data).unwrap(),
        other => panic!("unexpected coding {other}"),
    }
    out
}

const ENABLED: &str = "[compression]\nenabled = true\n";

#[tokio::test]
async fn each_coding_decodes_back_to_the_backends_body() {
    let backend = spawn_backend().await;
    let proxy = start_proxy(
        &format!("site.test -> http://127.0.0.1:{backend}\n"),
        ENABLED,
        None,
    )
    .await;
    for coding in ["gzip", "br", "zstd"] {
        let resp = get(&proxy, "site.test", "/big", &[("Accept-Encoding", coding)]).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(header(&resp, "content-encoding"), Some(coding));
        assert_eq!(header(&resp, "vary"), Some("Accept-Encoding"));
        assert_eq!(header(&resp, "etag"), Some("W/\"v1\""));
        assert!(header(&resp, "content-length").is_none());
        let body = resp.bytes().await.unwrap();
        assert!(body.len() < page().len() / 3, "{coding} barely shrank");
        assert_eq!(decode(coding, &body), page().into_bytes(), "{coding}");
    }
    // A browser's usual list picks brotli.
    let resp = get(
        &proxy,
        "site.test",
        "/big",
        &[("Accept-Encoding", "gzip, deflate, br, zstd")],
    )
    .await;
    assert_eq!(header(&resp, "content-encoding"), Some("br"));
}

#[tokio::test]
async fn what_must_not_be_compressed_is_not() {
    let backend = spawn_backend().await;
    let proxy = start_proxy(
        &format!(
            "site.test -> http://127.0.0.1:{backend}\n\
             off.test -> http://127.0.0.1:{backend}  @compress:off\n"
        ),
        ENABLED,
        None,
    )
    .await;
    let gzip_ok = [("Accept-Encoding", "gzip")];

    // No Accept-Encoding: identity, but the response says it varies.
    let resp = get(&proxy, "site.test", "/big", &[]).await;
    assert!(header(&resp, "content-encoding").is_none());
    assert_eq!(header(&resp, "vary"), Some("Accept-Encoding"));
    assert_eq!(resp.bytes().await.unwrap(), page().as_bytes());

    // Too small, event streams, a route that opted out.
    for (host, path) in [
        ("site.test", "/small"),
        ("site.test", "/sse"),
        ("off.test", "/big"),
    ] {
        let resp = get(&proxy, host, path, &gzip_ok).await;
        assert!(header(&resp, "content-encoding").is_none(), "{host}{path}");
    }

    // Already gzip-encoded by the backend: passed through byte for byte.
    let resp = get(
        &proxy,
        "site.test",
        "/gz",
        &[("Accept-Encoding", "br, gzip")],
    )
    .await;
    assert_eq!(header(&resp, "content-encoding"), Some("gzip"));
    assert_eq!(
        resp.bytes().await.unwrap().to_vec(),
        gzip(page().as_bytes())
    );

    // HEAD: nothing to compress, still varies.
    let resp = client()
        .head(format!("http://127.0.0.1:{}/big", proxy.port))
        .header("Host", "site.test")
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert!(header(&resp, "content-encoding").is_none());
    assert_eq!(header(&resp, "vary"), Some("Accept-Encoding"));
}

/// A prefix mount rewrites root-relative links in HTML — decoding the
/// backend's gzip to do it — and the rewritten page is then compressed for
/// the client: the two compose, rewrite first.
#[tokio::test]
async fn a_rewritten_page_is_compressed_after_the_rewrite() {
    let backend = spawn_backend().await;
    let proxy = start_proxy(
        &format!("/mount/* -> http://127.0.0.1:{backend}/\n"),
        ENABLED,
        None,
    )
    .await;
    for path in ["/mount/big", "/mount/gz"] {
        let resp = get(&proxy, "any.test", path, &[("Accept-Encoding", "br")]).await;
        assert_eq!(header(&resp, "content-encoding"), Some("br"), "{path}");
        let html = String::from_utf8(decode("br", &resp.bytes().await.unwrap())).unwrap();
        assert!(
            html.contains("href=\"/mount/item/7\""),
            "{path}: not rewritten"
        );
        assert!(!html.contains("href=\"/item/7\""), "{path}");
    }
}

#[tokio::test]
async fn compression_is_off_unless_enabled_or_asked_for_by_a_route() {
    let backend = spawn_backend().await;
    let proxy = start_proxy(
        &format!(
            "site.test -> http://127.0.0.1:{backend}\n\
             on.test -> http://127.0.0.1:{backend}  @compress:on\n"
        ),
        "",
        None,
    )
    .await;
    let resp = get(&proxy, "site.test", "/big", &[("Accept-Encoding", "gzip")]).await;
    assert!(header(&resp, "content-encoding").is_none());
    assert!(header(&resp, "vary").is_none());
    let resp = get(&proxy, "on.test", "/big", &[("Accept-Encoding", "gzip")]).await;
    assert_eq!(header(&resp, "content-encoding"), Some("gzip"));
}

fn error_pages_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("502.html"),
        "<h1>{{status}} {{reason}}</h1><p>{{host}}</p>",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("4xx.html"),
        "<h1>client error {{status}}</h1>",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("maintenance.html"),
        "<h1>closed: {{message}}</h1>",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn proxy_errors_get_the_custom_page_backend_errors_keep_theirs() {
    let backend = spawn_backend().await;
    let dead = portpicker::pick_unused_port().unwrap();
    let pages = error_pages_dir();
    let proxy = start_proxy(
        &format!(
            "site.test -> http://127.0.0.1:{backend}\n\
             dead.test -> http://127.0.0.1:{dead}\n"
        ),
        &format!("[error_pages]\ndir = \"{}\"\n", pages.path().display()),
        None,
    )
    .await;
    let browser = [("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")];

    // The proxy's 502 for an unreachable backend: the page, filled in.
    let resp = get(&proxy, "dead.test", "/", &browser).await;
    assert_eq!(resp.status(), 502);
    assert_eq!(
        header(&resp, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        resp.text().await.unwrap(),
        "<h1>502 Bad Gateway</h1><p>dead.test</p>"
    );

    // Same error for an API client: the plain text it always got.
    let resp = get(&proxy, "dead.test", "/", &[("Accept", "application/json")]).await;
    assert_eq!(resp.status(), 502);
    assert_eq!(resp.text().await.unwrap(), "Bad Gateway");

    // An unknown host's 421 falls back to the 4xx page.
    let resp = get(&proxy, "nowhere.test", "/", &browser).await;
    assert_eq!(resp.status(), 421);
    assert_eq!(resp.text().await.unwrap(), "<h1>client error 421</h1>");

    // The backend's own 404 is the backend's.
    let resp = get(&proxy, "site.test", "/missing", &browser).await;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text().await.unwrap(), "<h1>the backend's own 404</h1>");
}

async fn admin_put(proxy: &Proxy, path: &str, body: &str) -> reqwest::Response {
    client()
        .put(format!("http://127.0.0.1:{}{}", proxy.admin_port, path))
        .header("X-Requested-With", "test")
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn global_maintenance_through_the_admin_api() {
    let backend = spawn_backend().await;
    let pages = error_pages_dir();
    let proxy = start_proxy(
        &format!("site.test -> http://127.0.0.1:{backend}\n"),
        &format!(
            "[error_pages]\ndir = \"{}\"\n\n\
             [maintenance]\nretry_after = 90\nallow_paths = [\"/up\"]\nallow_ips = [\"10.0.0.0/8\"]\n",
            pages.path().display()
        ),
        None,
    )
    .await;
    let browser = [("Accept", "text/html")];

    let resp = admin_put(
        &proxy,
        "/api/v1/maintenance",
        r#"{"enabled": true, "message": "back at <5>"}"#,
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let resp = get(&proxy, "site.test", "/", &browser).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header(&resp, "retry-after"), Some("90"));
    assert_eq!(
        resp.text().await.unwrap(),
        "<h1>closed: back at &lt;5&gt;</h1>"
    );

    let resp = get(&proxy, "site.test", "/", &[("Accept", "*/*")]).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(
        resp.text().await.unwrap(),
        "Service Unavailable: back at <5>\n"
    );

    // An allowlisted path reaches the backend.
    let resp = get(&proxy, "site.test", "/up", &browser).await;
    assert_eq!(resp.status(), 200);

    // The state is visible, and switching it off reopens the site.
    let state: serde_json::Value = client()
        .get(format!(
            "http://127.0.0.1:{}/api/v1/maintenance",
            proxy.admin_port
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["data"]["global"]["message"], "back at <5>");

    let resp = admin_put(&proxy, "/api/v1/maintenance", r#"{"enabled": false}"#).await;
    assert_eq!(resp.status(), 200);
    let resp = get(&proxy, "site.test", "/", &browser).await;
    assert_eq!(resp.status(), 200);

    // A malformed toggle is refused.
    let resp = admin_put(&proxy, "/api/v1/maintenance", r#"{"on": true}"#).await;
    assert_eq!(resp.status(), 400);
    assert!(proxy.config.maintenance.snapshot().global.is_none());
}

/// An app's own `error_pages/` and `maintenance.flag`, and per-app maintenance
/// through the admin API.
#[tokio::test]
async fn per_app_pages_and_maintenance() {
    let sites = tempfile::tempdir().unwrap();
    let site = sites.path().join("shop.test");
    std::fs::create_dir_all(site.join("error_pages")).unwrap();
    std::fs::write(
        site.join("app.infos"),
        "name = \"shop.test\"\ndomain = \"shop.test\"\n",
    )
    .unwrap();
    std::fs::write(
        site.join("error_pages/4xx.html"),
        "<h1>shop says {{status}}</h1>",
    )
    .unwrap();
    std::fs::write(
        site.join("error_pages/maintenance.html"),
        "<h1>shop closed {{message}}</h1>",
    )
    .unwrap();
    let other = sites.path().join("other.test");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("app.infos"),
        "name = \"other.test\"\ndomain = \"other.test\"\n",
    )
    .unwrap();
    std::fs::write(other.join("maintenance.flag"), "").unwrap();

    let proxy = start_proxy("", "", Some(sites.path())).await;
    let browser = [("Accept", "text/html")];

    // shop.test is not running: the proxy's 421 wears the shop's page.
    let resp = get(&proxy, "shop.test", "/", &browser).await;
    assert_eq!(resp.status(), 421);
    assert_eq!(resp.text().await.unwrap(), "<h1>shop says 421</h1>");

    // other.test has a maintenance.flag: 503 with the built-in page.
    let resp = get(&proxy, "other.test", "/", &browser).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header(&resp, "retry-after"), Some("300"));
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("other.test is being worked on"));

    // The shop, switched off through the API, uses its own page.
    let resp = admin_put(
        &proxy,
        "/api/v1/apps/shop.test/maintenance",
        r#"{"enabled": true, "retry_after": 30, "message": "till noon"}"#,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = get(&proxy, "shop.test", "/", &browser).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header(&resp, "retry-after"), Some("30"));
    assert_eq!(resp.text().await.unwrap(), "<h1>shop closed till noon</h1>");

    // An app that does not exist cannot be put in maintenance.
    let resp = admin_put(
        &proxy,
        "/api/v1/apps/nope.test/maintenance",
        r#"{"enabled": true}"#,
    )
    .await;
    assert_eq!(resp.status(), 404);

    // GET /apps reports both.
    let apps: serde_json::Value = client()
        .get(format!("http://127.0.0.1:{}/api/v1/apps", proxy.admin_port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let in_maintenance: Vec<&str> = apps["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["maintenance"] == true)
        .map(|a| a["config"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(in_maintenance, vec!["other.test", "shop.test"]);
}

/// Multi-tenant: a tenant's `www.victim.com/` derives a claim on the apex,
/// which the operator's rule serves. The tenant's `error_pages/` (its HTML,
/// scripts included) and its `maintenance.flag` must not apply there — they
/// did, by hostname, while routing correctly served the operator's rule.
#[tokio::test]
async fn a_tenants_derived_apex_lends_no_pages_or_flag_to_the_operators_rule() {
    let sites = tempfile::tempdir().unwrap();
    let site = sites.path().join("www.victim.test");
    std::fs::create_dir_all(site.join("error_pages")).unwrap();
    std::fs::write(
        site.join("app.infos"),
        "name = \"www.victim.test\"\ndomain = \"www.victim.test\"\n",
    )
    .unwrap();
    std::fs::write(
        site.join("error_pages/5xx.html"),
        "<script>steal()</script>",
    )
    .unwrap();
    std::fs::write(site.join("maintenance.flag"), "").unwrap();
    // Nothing listens there: the operator's rule answers a proxy 502.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let proxy = start_proxy(
        &format!("victim.test -> http://127.0.0.1:{dead}/\n"),
        "[apps]\nmulti_tenant = true\n",
        Some(sites.path()),
    )
    .await;
    let browser = [("Accept", "text/html")];

    let resp = get(&proxy, "victim.test", "/", &browser).await;
    assert_eq!(resp.status(), 502, "not closed by the tenant's flag");
    assert!(!resp.text().await.unwrap().contains("steal"));

    // The tenant's own host keeps both.
    let resp = get(&proxy, "www.victim.test", "/", &browser).await;
    assert_eq!(resp.status(), 503);
}

/// When an app takes a whole-domain rule over, a WebSocket upgrade is gated
/// by the app alone, as a request is: the rule's `@forward_auth` used to be
/// asked first as well.
#[tokio::test]
async fn an_app_taking_over_a_rule_drops_its_gates_for_websockets_too() {
    let sites = tempfile::tempdir().unwrap();
    let site = sites.path().join("app.test");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::write(
        site.join("app.infos"),
        "name = \"app.test\"\ndomain = \"app.test\"\n",
    )
    .unwrap();
    // An auth service that counts the requests it is asked, and says no.
    let auth = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_port = auth.local_addr().unwrap().port();
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = auth.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut tmp = [0u8; 4096];
            let _ = sock.read(&mut tmp).await;
            let _ = sock
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let backend = spawn_backend().await;
    let proxy = start_proxy(
        &format!(
            "app.test -> http://127.0.0.1:{backend}/ \
             @forward_auth:http://127.0.0.1:{auth_port}/verify\n"
        ),
        "",
        Some(sites.path()),
    )
    .await;
    let mut sock = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    sock.write_all(
        b"GET /ws HTTP/1.1\r\nHost: app.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    // The app is not running: 421 — and the rule's auth service was never
    // asked, nor its backend reached.
    assert!(resp.starts_with("HTTP/1.1 421"), "{resp}");
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0);
}
