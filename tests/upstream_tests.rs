//! End-to-end tests for how the proxy talks to its upstreams: retrying a
//! failed attempt on another target, active health checks, HTTP/2 (h2c) with
//! trailers, Unix sockets, upstream TLS options and per-route timeouts. Each
//! test starts a real proxy on a free port in front of real hyper backends.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderMap;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, Health};
use soli_proxy::{
    new_challenge_store, new_metrics, ConfigManager, ProxyServer, ShutdownCoordinator,
};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// What a backend saw of one request.
#[derive(Debug)]
struct Seen {
    method: String,
    path: String,
    version: hyper::Version,
    headers: HeaderMap,
    body: Bytes,
}

/// How a backend answers.
#[derive(Clone)]
enum Answer {
    /// This status, body `<name>`, after this delay.
    Status(u16, Duration),
    /// Read the request head, then close the connection without a word.
    Hangup,
    /// 200 while the flag is set, 500 otherwise (a health endpoint).
    Flag(Arc<AtomicBool>),
}

type SeenRx = mpsc::UnboundedReceiver<Seen>;

async fn record(req: Request<Incoming>, tx: &mpsc::UnboundedSender<Seen>) {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let _ = tx.send(Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        version: parts.version,
        headers: parts.headers,
        body,
    });
}

/// An HTTP/1.1 backend named `name` (its body says who answered).
async fn backend(name: &'static str, answer: Answer) -> (u16, SeenRx) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let tx = tx.clone();
            let answer = answer.clone();
            if let Answer::Hangup = answer {
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut sock = sock;
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = tx.send(Seen {
                        method: "?".into(),
                        path: "?".into(),
                        version: hyper::Version::HTTP_11,
                        headers: HeaderMap::new(),
                        body: Bytes::new(),
                    });
                    // Dropped: the connection closes with no response.
                });
                continue;
            }
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    let answer = answer.clone();
                    async move {
                        record(req, &tx).await;
                        let status = match answer {
                            Answer::Status(status, delay) => {
                                tokio::time::sleep(delay).await;
                                status
                            }
                            Answer::Flag(up) => {
                                if up.load(Ordering::SeqCst) {
                                    200
                                } else {
                                    500
                                }
                            }
                            Answer::Hangup => unreachable!(),
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(name)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(sock), svc)
                    .await;
            });
        }
    });
    (port, rx)
}

/// A port nothing listens on.
async fn dead_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

struct Proxy {
    port: u16,
    breaker: Arc<CircuitBreaker>,
    manager: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.initiate();
    }
}

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
    let breaker = Arc::new(CircuitBreaker::new(cb_config));
    let shutdown = ShutdownCoordinator::new();
    let server = ProxyServer::new(
        manager.clone(),
        shutdown.clone(),
        new_metrics(),
        new_challenge_store(),
        None,
        breaker.clone(),
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
                breaker,
                manager,
                shutdown,
                dir,
            };
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not start on port {}", port);
}

/// What the client got back.
struct Got {
    status: u16,
    body: Bytes,
    trailers: Option<HeaderMap>,
}

/// One request over a fresh HTTP/1.1 connection to the proxy.
async fn send(
    port: u16,
    method: &str,
    host: &str,
    path: &str,
    body: &'static str,
    headers: &[(&str, &str)],
) -> Got {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .expect("the proxy answers")
        .unwrap();
    let status = resp.status().as_u16();
    let collected = resp.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned();
    Got {
        status,
        body: collected.to_bytes(),
        trailers,
    }
}

async fn get(port: u16, path: &str) -> Got {
    send(port, "GET", "localhost", path, "", &[]).await
}

/// Poll `cond` for up to five seconds.
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {}", what);
}

// ---------------------------------------------------------------- retries

#[tokio::test]
async fn a_refused_connection_is_retried_on_the_next_target() {
    let dead = dead_port().await;
    let (live, mut seen) = backend("live", Answer::Status(200, Duration::ZERO)).await;
    let proxy = start_proxy(
        &format!("/api/* -> http://127.0.0.1:{dead}, http://127.0.0.1:{live} @lb:failover\n"),
        "",
    )
    .await;

    let got = get(proxy.port, "/api/x").await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body, "live");
    assert_eq!(seen.recv().await.unwrap().path, "/x");

    // Nothing was sent, so a POST is replayed too — body intact.
    let got = send(proxy.port, "POST", "localhost", "/api/form", "a=1&b=2", &[]).await;
    assert_eq!(got.status, 200);
    let req = seen.recv().await.unwrap();
    assert_eq!(
        (req.method.as_str(), &req.body[..]),
        ("POST", &b"a=1&b=2"[..])
    );

    // Each failed attempt still counts against the dead target.
    let states = proxy.breaker.get_states();
    let dead_state = &states[&format!("http://127.0.0.1:{dead}/")];
    assert_eq!(dead_state.consecutive_failures, 2);
}

#[tokio::test]
async fn retries_can_be_turned_off_per_route() {
    let dead = dead_port().await;
    let (live, _seen) = backend("live", Answer::Status(200, Duration::ZERO)).await;
    let proxy = start_proxy(
        &format!(
            "/api/* -> http://127.0.0.1:{dead}, http://127.0.0.1:{live} @lb:failover @retries:0\n"
        ),
        "",
    )
    .await;
    assert_eq!(get(proxy.port, "/api/x").await.status, 502);
}

#[tokio::test]
async fn a_lost_exchange_is_replayed_only_when_safe() {
    let (hangup, mut hung) = backend("hangup", Answer::Hangup).await;
    let (live, mut seen) = backend("live", Answer::Status(200, Duration::ZERO)).await;
    let proxy = start_proxy(
        &format!("/api/* -> http://127.0.0.1:{hangup}, http://127.0.0.1:{live} @lb:failover\n"),
        "",
    )
    .await;

    // A GET without a body may be sent again.
    let got = get(proxy.port, "/api/x").await;
    assert_eq!((got.status, &got.body[..]), (200, &b"live"[..]));
    hung.recv().await.unwrap();
    seen.recv().await.unwrap();

    // A POST reached the first backend, which may have acted on it: no retry.
    let got = send(
        proxy.port,
        "POST",
        "localhost",
        "/api/pay",
        "amount=10",
        &[],
    )
    .await;
    assert_eq!(got.status, 502);
    hung.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(seen.try_recv().is_err(), "the POST must not be replayed");
}

#[tokio::test]
async fn a_status_in_retry_on_is_retried_for_safe_requests() {
    let (busy, _b) = backend("busy", Answer::Status(503, Duration::ZERO)).await;
    let (live, _l) = backend("live", Answer::Status(200, Duration::ZERO)).await;
    let conf = format!("/api/* -> http://127.0.0.1:{busy}, http://127.0.0.1:{live} @lb:failover\n");

    // Not by default: a 503 is an answer.
    let proxy = start_proxy(&conf, "").await;
    assert_eq!(get(proxy.port, "/api/x").await.status, 503);
    drop(proxy);

    let proxy = start_proxy(
        &conf,
        "[upstream]\nretry_on = [\"connect\", \"error\", \"503\"]\n",
    )
    .await;
    let got = get(proxy.port, "/api/x").await;
    assert_eq!((got.status, &got.body[..]), (200, &b"live"[..]));
    let got = send(proxy.port, "POST", "localhost", "/api/x", "x", &[]).await;
    assert_eq!(got.status, 503, "a POST is never replayed for a status");
}

// ---------------------------------------------------------- health checks

#[tokio::test]
async fn health_checks_take_a_target_out_and_put_it_back() {
    let up = Arc::new(AtomicBool::new(false));
    let (a, mut a_seen) = backend("a", Answer::Flag(up.clone())).await;
    let (b, _b_seen) = backend("b", Answer::Status(200, Duration::ZERO)).await;
    let a_url = format!("http://127.0.0.1:{a}/");
    let conf = format!(
        "/api/* -> http://127.0.0.1:{a}, http://127.0.0.1:{b} @lb:failover \
         @health:/healthz @health_interval:100ms\n"
    );
    let proxy = start_proxy(
        &conf,
        "[health_checks]\nunhealthy_threshold = 2\nhealthy_threshold = 2\ntimeout = \"500ms\"\n",
    )
    .await;

    let breaker = proxy.breaker.clone();
    eventually("a marked down", || breaker.health(&a_url) == Health::Down).await;
    let probe = a_seen.recv().await.unwrap();
    assert_eq!(probe.path, "/healthz");
    assert_eq!(
        probe.headers["user-agent"], "soli-proxy-health-check",
        "probes say who they are"
    );
    // Failover would send everything to `a`; it is down, so `b` answers.
    let got = get(proxy.port, "/api/x").await;
    assert_eq!(got.body, "b");
    assert_eq!(
        proxy.breaker.get_states()[&a_url].health.as_deref(),
        Some("down")
    );

    up.store(true, Ordering::SeqCst);
    eventually("a back up", || breaker.health(&a_url) == Health::Up).await;
    assert_eq!(get(proxy.port, "/api/x").await.body, "a");

    // A reload that drops the check stops the probes and forgets the verdict.
    up.store(false, Ordering::SeqCst);
    eventually("a down again", || breaker.health(&a_url) == Health::Down).await;
    std::fs::write(
        proxy.dir.path().join("proxy.conf"),
        format!("/api/* -> http://127.0.0.1:{a}, http://127.0.0.1:{b} @lb:failover\n"),
    )
    .unwrap();
    proxy.manager.reload().await.unwrap();
    eventually("verdict cleared", || {
        breaker.health(&a_url) == Health::Unknown
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    while a_seen.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        a_seen.try_recv().is_err(),
        "no probe task outlives its check"
    );
}

// ------------------------------------------------------ h2c and trailers

/// An h2c (prior knowledge) backend answering gRPC-style: a body, then
/// trailers. Reports each request.
async fn h2c_backend() -> (u16, SeenRx) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        record(req, &tx).await;
                        let mut trailers = HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        trailers.insert("grpc-message", "fine".parse().unwrap());
                        let frames: Vec<Result<Frame<Bytes>, Infallible>> = vec![
                            Ok(Frame::data(Bytes::from_static(b"\0\0\0\0\x02hi"))),
                            Ok(Frame::trailers(trailers)),
                        ];
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/grpc")
                                .header("trailer", "grpc-status, grpc-message")
                                .body(StreamBody::new(futures::stream::iter(frames)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(sock), svc)
                    .await;
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn h2c_upstreams_get_http2_te_trailers_and_return_trailers() {
    let (grpc, mut seen) = h2c_backend().await;
    let proxy = start_proxy(&format!("grpc.test -> h2c://127.0.0.1:{grpc}\n"), "").await;

    let got = send(
        proxy.port,
        "POST",
        "grpc.test",
        "/pkg.Greeter/SayHello",
        "\0\0\0\0\0",
        &[
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("connection", "te"),
        ],
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(&got.body[..], b"\0\0\0\0\x02hi");
    let trailers = got.trailers.expect("trailers reach the client");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(trailers["grpc-message"], "fine");

    let req = seen.recv().await.unwrap();
    assert_eq!(req.version, hyper::Version::HTTP_2);
    assert_eq!(req.path, "/pkg.Greeter/SayHello");
    assert_eq!(req.headers["te"], "trailers");
    assert_eq!(&req.body[..], b"\0\0\0\0\0");
    // The client's host travels as X-Forwarded-Host; Host may not contradict
    // :authority on HTTP/2.
    assert_eq!(req.headers["x-forwarded-host"], "grpc.test");
    assert!(req
        .headers
        .get("host")
        .is_none_or(|h| h == &format!("127.0.0.1:{grpc}")));
}

#[tokio::test]
async fn http1_upstreams_do_not_get_te() {
    let (plain, mut seen) = backend("plain", Answer::Status(200, Duration::ZERO)).await;
    let proxy = start_proxy(&format!("default -> http://127.0.0.1:{plain}\n"), "").await;
    let got = send(
        proxy.port,
        "GET",
        "localhost",
        "/",
        "",
        &[("te", "trailers"), ("connection", "te")],
    )
    .await;
    assert_eq!(got.status, 200);
    let req = seen.recv().await.unwrap();
    assert_eq!(req.version, hyper::Version::HTTP_11);
    assert!(req.headers.get("te").is_none());
}

// ------------------------------------------------------------ unix sockets

#[tokio::test]
async fn unix_socket_upstreams_keep_the_client_host() {
    let sock_dir = tempfile::tempdir().unwrap();
    let path = sock_dir.path().join("app.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (tx, mut seen) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        record(req, &tx).await;
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("socket"))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(sock), svc)
                    .await;
            });
        }
    });
    let proxy = start_proxy(
        &format!(
            "sock.test -> unix:{}\n/mounted/* -> unix:{}\n",
            path.display(),
            path.display()
        ),
        "",
    )
    .await;

    let got = send(proxy.port, "GET", "sock.test", "/a/b?c=1", "", &[]).await;
    assert_eq!((got.status, &got.body[..]), (200, &b"socket"[..]));
    let req = seen.recv().await.unwrap();
    assert_eq!(req.path, "/a/b");
    assert_eq!(req.headers["host"], "sock.test");

    let got = send(proxy.port, "GET", "other.test", "/mounted/x", "", &[]).await;
    assert_eq!(got.status, 200);
    assert_eq!(seen.recv().await.unwrap().path, "/x");
}

// -------------------------------------------------------- upstream TLS

struct Pki {
    ca_pem: String,
    server_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: Vec<u8>,
    client_pem: String,
    client_key_pem: String,
}

fn pki() -> Pki {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "soli test CA");
    let ca = rcgen::Certificate::from_params(ca_params).unwrap();
    let server = rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![
        "upstream.test".to_string(),
    ]))
    .unwrap();
    let client = rcgen::Certificate::from_params(rcgen::CertificateParams::new(vec![
        "client.test".to_string(),
    ]))
    .unwrap();
    Pki {
        ca_pem: ca.serialize_pem().unwrap(),
        server_chain: vec![server.serialize_der_with_signer(&ca).unwrap().into()],
        server_key: server.serialize_private_key_der(),
        client_pem: client.serialize_pem_with_signer(&ca).unwrap(),
        client_key_pem: client.serialize_private_key_pem(),
    }
}

/// An HTTPS backend with the PKI's server certificate; with `require_client`
/// it also demands a client certificate from the PKI's CA.
async fn tls_backend(pki: &Pki, require_client: bool) -> (u16, SeenRx) {
    use rustls::pki_types::pem::PemObject;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let builder = rustls::ServerConfig::builder();
    let builder = if require_client {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pki.ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
    } else {
        builder.with_no_client_auth()
    };
    let config = builder
        .with_single_cert(
            pki.server_chain.clone(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(pki.server_key.clone()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let tx = tx.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let sni = tls.get_ref().1.server_name().map(str::to_string);
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    let sni = sni.clone();
                    async move {
                        record(req, &tx).await;
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                            sni.unwrap_or_default(),
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn upstream_tls_options() {
    let pki = pki();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    let cert = dir.path().join("client.pem");
    let key = dir.path().join("client.key");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    std::fs::write(&cert, &pki.client_pem).unwrap();
    std::fs::write(&key, &pki.client_key_pem).unwrap();
    let (tls, _seen) = tls_backend(&pki, false).await;
    let (mtls, mut mtls_seen) = tls_backend(&pki, true).await;
    let ca = ca.display();
    let conf = format!(
        "/public/* -> https://127.0.0.1:{tls}\n\
         /private/* -> https://127.0.0.1:{tls} @tls_ca:{ca} @tls_sni:upstream.test\n\
         /wrongname/* -> https://127.0.0.1:{tls} @tls_ca:{ca} @tls_sni:other.test\n\
         /insecure/* -> https://127.0.0.1:{tls} @tls_insecure\n\
         /nocert/* -> https://127.0.0.1:{mtls} @tls_ca:{ca} @tls_sni:upstream.test\n\
         /mtls/* -> https://127.0.0.1:{mtls} @tls_ca:{ca} @tls_sni:upstream.test \
         @tls_client_cert:{},{}\n",
        cert.display(),
        key.display()
    );
    let proxy = start_proxy(&conf, "").await;

    // The public roots do not know this CA.
    assert_eq!(get(proxy.port, "/public/x").await.status, 502);
    // Trusting it (and verifying the name it was issued for) works, and the
    // SNI sent is the one asked for.
    let got = get(proxy.port, "/private/x").await;
    assert_eq!((got.status, &got.body[..]), (200, &b"upstream.test"[..]));
    // The CA alone is not enough: the name must match too.
    assert_eq!(get(proxy.port, "/wrongname/x").await.status, 502);
    // No verification at all.
    assert_eq!(get(proxy.port, "/insecure/x").await.status, 200);
    // mTLS: refused without a client certificate, served with one.
    assert_eq!(get(proxy.port, "/nocert/x").await.status, 502);
    let got = get(proxy.port, "/mtls/x").await;
    assert_eq!(got.status, 200);
    assert_eq!(mtls_seen.recv().await.unwrap().path, "/x");
}

#[tokio::test]
async fn a_missing_ca_file_refuses_the_configuration() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("proxy.conf");
    std::fs::write(
        &conf,
        "/x/* -> https://example.com @tls_ca:/nonexistent/soli-ca.pem\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        "[server]\nbind = \"127.0.0.1:1\"\nhttps_port = 443\n",
    )
    .unwrap();
    let err = ConfigManager::new(conf.to_str().unwrap()).err().unwrap();
    assert!(
        format!("{:#}", err).contains("/nonexistent/soli-ca.pem"),
        "{err:#}"
    );
}

// ------------------------------------------------------------- timeouts

#[tokio::test]
async fn a_route_timeout_overrides_the_request_timeout() {
    let (slow, _s) = backend("slow", Answer::Status(200, Duration::from_millis(1500))).await;
    let conf = format!(
        "/default/* -> http://127.0.0.1:{slow}\n\
         /patient/* -> http://127.0.0.1:{slow} @timeout:5s\n\
         /hasty/* -> http://127.0.0.1:{slow} @timeout:300ms\n"
    );
    let proxy = start_proxy(&conf, "[limits]\nrequest_timeout = 1\n").await;
    assert_eq!(get(proxy.port, "/default/x").await.status, 504);
    assert_eq!(get(proxy.port, "/patient/x").await.status, 200);
    let started = std::time::Instant::now();
    assert_eq!(get(proxy.port, "/hasty/x").await.status, 504);
    assert!(started.elapsed() < Duration::from_millis(1000));
}

#[tokio::test]
async fn websocket_upgrades_reach_a_unix_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sock_dir = tempfile::tempdir().unwrap();
    let path = sock_dir.path().join("ws.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (tx, mut heads) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n",
                    )
                    .await;
                while matches!(sock.read(&mut tmp).await, Ok(n) if n > 0) {}
            });
        }
    });
    let proxy = start_proxy(&format!("ws.test -> unix:{}\n", path.display()), "").await;

    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    client
        .write_all(
            b"GET /cable HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
    let mut resp = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&resp[..n]).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&resp[..n])
    );
    let head = heads.recv().await.unwrap();
    assert!(head.starts_with("GET /cable HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("Host: ws.test\r\n"), "{head}");
}
