use crate::acme::ChallengeStore;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::shutdown::ShutdownCoordinator;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

type ClientType = Client<HttpConnector, Incoming>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

pub struct ProxyServer {
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    tls_acceptor: Option<TlsAcceptor>,
    https_addr: Option<SocketAddr>,
    metrics: SharedMetrics,
    connection_pool: Arc<Mutex<HashMap<String, ClientType>>>,
    challenge_store: ChallengeStore,
}

impl ProxyServer {
    pub fn new(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
    ) -> Result<Self> {
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: None,
            https_addr: None,
            metrics,
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            challenge_store,
        })
    }

    pub fn with_https(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        tls_acceptor: TlsAcceptor,
        https_addr: SocketAddr,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
    ) -> Result<Self> {
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: Some(tls_acceptor),
            https_addr: Some(https_addr),
            metrics,
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            challenge_store,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let cfg = self.config.get_config();
        let http_addr: SocketAddr = cfg.server.bind.parse()?;
        let https_addr = self.https_addr;

        let http_addr_clone = http_addr;
        let has_https = https_addr.is_some();

        let config_clone = self.config.clone();
        let shutdown_clone = self.shutdown.clone();
        let metrics_clone = self.metrics.clone();
        let pool_clone = self.connection_pool.clone();
        let challenge_store_clone = self.challenge_store.clone();

        tokio::spawn(async move {
            if let Err(e) = run_http_server(
                http_addr_clone,
                config_clone,
                shutdown_clone,
                metrics_clone,
                pool_clone,
                challenge_store_clone,
            )
            .await
            {
                tracing::error!("HTTP/1.1 server error: {}", e);
            }
        });

        if let Some(https_addr) = https_addr {
            let config_clone = self.config.clone();
            let shutdown_clone = self.shutdown.clone();
            let acceptor = self.tls_acceptor.as_ref().unwrap().clone();
            let metrics_clone = self.metrics.clone();
            let pool_clone = self.connection_pool.clone();
            let challenge_store_clone = self.challenge_store.clone();

            tokio::spawn(async move {
                if let Err(e) = run_https_server(
                    https_addr,
                    config_clone,
                    shutdown_clone,
                    acceptor,
                    metrics_clone,
                    pool_clone,
                    challenge_store_clone,
                )
                .await
                {
                    tracing::error!("HTTPS/2 server error: {}", e);
                }
            });
        }

        tracing::info!("HTTP/1.1 server listening on {}", http_addr);
        if has_https {
            tracing::info!("HTTPS/2 server listening on {}", https_addr.unwrap());
        }

        loop {
            if self.shutdown.is_shutting_down() {
                tracing::info!("Shutting down servers...");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }
}

async fn run_http_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    metrics: SharedMetrics,
    _pool: Arc<Mutex<HashMap<String, ClientType>>>,
    challenge_store: ChallengeStore,
) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let exec = TokioExecutor::new();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(30)));
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    let client = Client::builder(exec.clone()).build(connector);

    loop {
        if shutdown.is_shutting_down() {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                let client = client.clone();
                let config = config.get_config();
                let metrics = metrics.clone();
                let cs = challenge_store.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_http11_connection(stream, client, config, metrics, cs).await
                    {
                        tracing::debug!("HTTP/1.1 connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("HTTP/1.1 accept error: {}", e);
            }
        }
    }

    Ok(())
}

async fn run_https_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    acceptor: TlsAcceptor,
    metrics: SharedMetrics,
    _pool: Arc<Mutex<HashMap<String, ClientType>>>,
    challenge_store: ChallengeStore,
) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let exec = TokioExecutor::new();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(30)));
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    let client = Client::builder(exec.clone()).build(connector);

    loop {
        if shutdown.is_shutting_down() {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                let client = client.clone();
                let config = config.get_config();
                let acceptor = acceptor.clone();
                let metrics = metrics.clone();
                let cs = challenge_store.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            metrics.inc_tls_connections();
                            if let Err(e) =
                                handle_https2_connection(tls_stream, client, config, metrics, cs)
                                    .await
                            {
                                tracing::debug!("HTTPS/2 connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("TLS accept error: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                tracing::error!("HTTPS/2 accept error: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_http11_connection(
    stream: tokio::net::TcpStream,
    client: ClientType,
    config: Arc<crate::config::Config>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        handle_request(
            req,
            client.clone(),
            config.clone(),
            metrics.clone(),
            challenge_store.clone(),
        )
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, svc);

    if let Err(e) = conn.await {
        tracing::debug!("HTTP/1.1 connection error: {}", e);
    }

    Ok(())
}

async fn handle_https2_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client: ClientType,
    config: Arc<crate::config::Config>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
) -> Result<()> {
    let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");

    let io = TokioIo::new(stream);

    if is_h2 {
        let exec = TokioExecutor::new();
        let svc = service_fn(move |req| {
            handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
            )
        });
        let conn = hyper::server::conn::http2::Builder::new(exec).serve_connection(io, svc);
        if let Err(e) = conn.await {
            tracing::debug!("HTTPS/2 connection error: {}", e);
        }
    } else {
        let svc = service_fn(move |req| {
            handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
            )
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .serve_connection(io, svc);
        if let Err(e) = conn.await {
            tracing::debug!("HTTPS/1.1 connection error: {}", e);
        }
    }

    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    client: ClientType,
    config: Arc<crate::config::Config>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start_time = std::time::Instant::now();
    metrics.inc_in_flight();

    // ACME challenge check — must come before all other routing
    if let Some(response) = handle_acme_challenge(&req, &challenge_store) {
        metrics.dec_in_flight();
        return Ok(response);
    }

    if is_metrics_request(&req) {
        let duration = start_time.elapsed();
        metrics.dec_in_flight();
        let metrics_output = metrics.format_metrics();
        metrics.record_request(0, metrics_output.len() as u64, 200, duration);
        let body = http_body_util::Full::new(Bytes::from(metrics_output)).boxed();
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    let is_websocket = is_websocket_request(&req);

    if is_websocket {
        return handle_websocket_request(req, client, &config, &metrics, start_time).await;
    }

    let result = handle_regular_request(req, client, &config).await;
    let duration = start_time.elapsed();

    metrics.dec_in_flight();

    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            metrics.record_request(0, 0, status, duration);
            let (parts, body) = response.into_parts();
            let boxed = body.map_err(|_| unreachable!()).boxed();
            Ok(Response::from_parts(parts, boxed))
        }
        Err(e) => {
            metrics.inc_errors();
            Err(e)
        }
    }
}

fn is_websocket_request(req: &Request<Incoming>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade") {
        if upgrade == "websocket" {
            return true;
        }
    }
    false
}

fn is_metrics_request(req: &Request<Incoming>) -> bool {
    req.uri().path() == "/metrics"
}

fn handle_acme_challenge(
    req: &Request<Incoming>,
    challenge_store: &ChallengeStore,
) -> Option<Response<BoxBody>> {
    let path = req.uri().path();
    let prefix = "/.well-known/acme-challenge/";

    if !path.starts_with(prefix) {
        return None;
    }

    let token = &path[prefix.len()..];

    if let Ok(store) = challenge_store.read() {
        if let Some(key_auth) = store.get(token) {
            let body = http_body_util::Full::new(Bytes::from(key_auth.clone())).boxed();
            return Some(
                Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(body)
                    .unwrap(),
            );
        }
    }

    let body = http_body_util::Full::new(Bytes::from("Challenge not found")).boxed();
    Some(Response::builder().status(404).body(body).unwrap())
}

async fn handle_websocket_request(
    req: Request<Incoming>,
    _client: ClientType,
    config: &crate::config::Config,
    metrics: &SharedMetrics,
    _start_time: std::time::Instant,
) -> Result<Response<BoxBody>, hyper::Error> {
    let target_result = find_target(&req, &config.rules);

    if target_result.is_none() {
        metrics.inc_errors();
        let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
        return Ok(Response::builder().status(421).body(body).unwrap());
    }

    let (target_url, _, _) = target_result.unwrap();
    let path = req.uri().path();

    let ws_url = format!("ws://{}{}", target_url, path);

    tracing::info!("WebSocket upgrade request to {}", ws_url);

    metrics.inc_errors();
    let body = http_body_util::Full::new(Bytes::from(
        "WebSocket proxy requires separate connection handling",
    ))
    .boxed();
    Ok(Response::builder().status(101).body(body).unwrap())
}

async fn handle_regular_request(
    req: Request<Incoming>,
    client: ClientType,
    config: &crate::config::Config,
) -> Result<Response<BoxBody>, hyper::Error> {
    let host_header = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|s| s.to_string());

    let target_result = find_target(&req, &config.rules);

    match target_result {
        Some((target_url, from_domain_rule, matched_prefix)) => {
            let (parts, body) = req.into_parts();

            let mut request = Request::builder()
                .method(parts.method.clone())
                .uri(&target_url)
                .body(body)
                .expect("Failed to build request");

            for (key, value) in parts.headers.iter() {
                request.headers_mut().insert(key, value.clone());
            }

            request
                .headers_mut()
                .insert("X-Forwarded-For", "127.0.0.1".parse().unwrap());

            if from_domain_rule {
                if let Some(host) = host_header {
                    request
                        .headers_mut()
                        .insert("X-Forwarded-Host", host.parse().unwrap());
                }
            }

            match client.request(request).await {
                Ok(response) => {
                    let is_html = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.starts_with("text/html"))
                        .unwrap_or(false);

                    if is_html {
                        if let Some(prefix) = matched_prefix {
                            let (parts, body) = response.into_parts();
                            let body_bytes = body
                                .collect()
                                .await
                                .map(|collected| collected.to_bytes())
                                .unwrap_or_default();
                            let html = String::from_utf8_lossy(&body_bytes);
                            let rewritten = html
                                .replace("href=\"/", &format!("href=\"{}/", prefix))
                                .replace("src=\"/", &format!("src=\"{}/", prefix))
                                .replace("action=\"/", &format!("action=\"{}/", prefix));
                            let rewritten_bytes = Bytes::from(rewritten);
                            let mut parts = parts;
                            parts.headers.remove("content-length");
                            parts.headers.insert(
                                "content-length",
                                rewritten_bytes.len().to_string().parse().unwrap(),
                            );
                            let boxed = http_body_util::Full::new(rewritten_bytes).boxed();
                            return Ok(Response::from_parts(parts, boxed));
                        }
                    }

                    let (parts, body) = response.into_parts();
                    let boxed = body.map_err(|_| unreachable!()).boxed();
                    Ok(Response::from_parts(parts, boxed))
                }
                Err(e) => {
                    tracing::error!("Backend request failed: {} (target: {})", e, target_url);
                    let body = http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                    Ok(Response::builder()
                        .status(502)
                        .body(body)
                        .expect("Failed to build response"))
                }
            }
        }
        None => {
            let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
            Ok(Response::builder()
                .status(421)
                .body(body)
                .expect("Failed to build response"))
        }
    }
}

fn find_target(
    req: &Request<Incoming>,
    rules: &[crate::config::ProxyRule],
) -> Option<(String, bool, Option<String>)> {
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|h| h.split(':').next().unwrap_or(h))
        .map(|s| s.to_string())?;

    let path = req.uri().path();
    let mut matched_domain = false;

    for rule in rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Domain(domain) => {
                if domain == &host {
                    matched_domain = true;
                    if let Some(target) = rule.targets.first() {
                        let target_str = target.url.as_str();
                        let final_url = if target_str.ends_with('/') {
                            format!("{}{}", target_str, &path[1..])
                        } else {
                            format!("{}{}", target_str, path)
                        };
                        return Some((final_url, true, None));
                    }
                }
            }
            crate::config::RuleMatcher::DomainPath(domain, path_prefix) => {
                if domain == &host && path.starts_with(path_prefix) {
                    if let Some(target) = rule.targets.first() {
                        let target_str = target.url.as_str();
                        let suffix = &path[path_prefix.len()..];
                        let final_url = format!("{}{}", target_str, suffix);
                        let prefix = path_prefix.trim_end_matches('/').to_string();
                        return Some((final_url, true, Some(prefix)));
                    }
                }
            }
            _ => {}
        }
    }

    if matched_domain {
        return None;
    }

    // Check specific rules (Exact, Prefix, Regex) before Default
    for rule in rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Exact(exact) => {
                if path == exact {
                    if let Some(target) = rule.targets.first() {
                        return Some((target.url.as_str().to_owned(), false, None));
                    }
                }
            }
            crate::config::RuleMatcher::Prefix(prefix) => {
                if path.starts_with(prefix) {
                    if let Some(target) = rule.targets.first() {
                        let target_str = target.url.as_str();
                        let suffix = &path[prefix.len()..];
                        let final_url = format!("{}{}", target_str, suffix);
                        let matched_prefix = prefix.trim_end_matches('/').to_string();
                        return Some((final_url, false, Some(matched_prefix)));
                    }
                }
            }
            crate::config::RuleMatcher::Regex(regex) => {
                if regex.is_match(path) {
                    if let Some(target) = rule.targets.first() {
                        return Some((target.url.as_str().to_owned(), false, None));
                    }
                }
            }
            _ => {}
        }
    }

    // Fall back to Default rule
    for rule in rules {
        if let crate::config::RuleMatcher::Default = &rule.matcher {
            if let Some(target) = rule.targets.first() {
                let target_str = target.url.as_str();
                let final_url = if target_str.ends_with('/') {
                    format!("{}{}", target_str, &path[1..])
                } else {
                    format!("{}{}", target_str, path)
                };
                return Some((final_url, false, None));
            }
        }
    }

    None
}
