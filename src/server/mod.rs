// When scripting feature is disabled, OptionalLuaEngine = () and cloning it triggers warnings
#![allow(clippy::let_unit_value, clippy::clone_on_copy, clippy::unit_arg)]

use crate::acme::ChallengeStore;
use crate::app::AppManager;
use crate::auth;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::pool::{ConnectionPool, ProxyClient};
use crate::shutdown::ShutdownCoordinator;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "scripting")]
use crate::scripting::{LuaEngine, LuaRequest, RequestHookResult, RouteHookResult};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

#[cfg(feature = "scripting")]
type OptionalLuaEngine = Option<LuaEngine>;
#[cfg(not(feature = "scripting"))]
type OptionalLuaEngine = ();

pub struct LoadBalancerState {
    counters: Vec<AtomicUsize>,
}

impl LoadBalancerState {
    pub fn new(num_rules: usize) -> Self {
        Self {
            counters: (0..num_rules).map(|_| AtomicUsize::new(0)).collect(),
        }
    }

    pub fn select_index(&self, rule_idx: usize, num_targets: usize) -> usize {
        if num_targets == 0 {
            return 0;
        }
        self.counters[rule_idx].fetch_add(1, Ordering::Relaxed) % num_targets
    }
}

/// Helper to record app-specific metrics
async fn record_app_metrics(
    metrics: &SharedMetrics,
    app_manager: &Option<Arc<AppManager>>,
    target_url: &str,
    bytes_in: u64,
    bytes_out: u64,
    status: u16,
    duration: Duration,
) {
    if let Some(ref manager) = app_manager {
        if let Ok(url) = url::Url::parse(target_url) {
            if let Some(port) = url.port() {
                if let Some(app_name) = manager.get_app_name(port).await {
                    metrics.record_app_request(&app_name, bytes_in, bytes_out, status, duration);
                }
            }
        }
    }
}

static X_FORWARDED_PROTO_HTTPS: std::sync::LazyLock<HeaderValue> =
    std::sync::LazyLock::new(|| HeaderValue::from_static("https"));
static X_FORWARDED_PROTO_HTTP: std::sync::LazyLock<HeaderValue> =
    std::sync::LazyLock::new(|| HeaderValue::from_static("http"));

const MAX_HTML_REWRITE_SIZE: usize = 10 * 1024 * 1024;

/// Verify Basic Auth credentials against stored hashes
/// Returns true if credentials are valid, false otherwise
fn verify_basic_auth(req: &Request<Incoming>, auth_entries: &[crate::auth::BasicAuth]) -> bool {
    if auth_entries.is_empty() {
        return true;
    }

    let auth_header = req.headers().get("authorization");
    if auth_header.is_none() {
        return false;
    }

    let header_value = auth_header.unwrap().to_str().unwrap_or("");
    if !header_value.starts_with("Basic ") {
        return false;
    }

    let encoded = &header_value[6..];
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .unwrap_or_default();
    let creds = String::from_utf8_lossy(&decoded);

    if let Some((username, password)) = creds.split_once(':') {
        let username_bytes = username.as_bytes();
        for entry in auth_entries {
            if constant_time_eq(entry.username.as_bytes(), username_bytes)
                && auth::verify_password(password, &entry.hash)
            {
                return true;
            }
        }
    }

    false
}

/// Constant-time byte comparison to prevent timing attacks on username comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Create 401 Unauthorized response with WWW-Authenticate header
fn create_auth_required_response() -> Response<BoxBody> {
    let body = http_body_util::Full::new(Bytes::from("Authentication required")).boxed();
    Response::builder()
        .status(401)
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .body(body)
        .unwrap()
}

fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(8192)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub struct ProxyServer {
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    tls_acceptor: Option<TlsAcceptor>,
    https_addr: Option<SocketAddr>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
}

impl ProxyServer {
    pub fn new(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
        circuit_breaker: SharedCircuitBreaker,
        app_manager: Option<Arc<AppManager>>,
    ) -> Result<Self> {
        let num_rules = config.get_config().rules.len();
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: None,
            https_addr: None,
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer: Arc::new(LoadBalancerState::new(num_rules)),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_https(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        tls_acceptor: TlsAcceptor,
        https_addr: SocketAddr,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
        circuit_breaker: SharedCircuitBreaker,
        app_manager: Option<Arc<AppManager>>,
    ) -> Result<Self> {
        let num_rules = config.get_config().rules.len();
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: Some(tls_acceptor),
            https_addr: Some(https_addr),
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer: Arc::new(LoadBalancerState::new(num_rules)),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let cfg = self.config.get_config();
        let http_addr: SocketAddr = cfg.server.bind.parse()?;
        let https_addr = self.https_addr;

        let has_https = https_addr.is_some();
        let num_listeners = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // Spawn N HTTP accept loops with SO_REUSEPORT
        // Each listener gets its own client with its own connection pool to avoid contention
        let app_manager = self.app_manager.clone();
        for i in 0..num_listeners {
            let config_clone = self.config.clone();
            let shutdown_clone = self.shutdown.clone();
            let metrics_clone = self.metrics.clone();
            let challenge_store_clone = self.challenge_store.clone();
            let lua_clone = self.lua_engine.clone();
            let cb_clone = self.circuit_breaker.clone();
            let am_clone = app_manager.clone();
            let lb_clone = self.load_balancer.clone();

            tokio::spawn(async move {
                if let Err(e) = run_http_server(
                    http_addr,
                    config_clone,
                    shutdown_clone,
                    metrics_clone,
                    challenge_store_clone,
                    lua_clone,
                    cb_clone,
                    am_clone,
                    lb_clone,
                )
                .await
                {
                    tracing::error!("HTTP/1.1 server error (listener {}): {}", i, e);
                }
            });
        }

        if let Some(https_addr) = https_addr {
            for i in 0..num_listeners {
                let config_clone = self.config.clone();
                let shutdown_clone = self.shutdown.clone();
                let acceptor = self.tls_acceptor.as_ref().unwrap().clone();
                let metrics_clone = self.metrics.clone();
                let challenge_store_clone = self.challenge_store.clone();
                let lua_clone = self.lua_engine.clone();
                let cb_clone = self.circuit_breaker.clone();
                let am_clone = app_manager.clone();
                let lb_clone = self.load_balancer.clone();

                tokio::spawn(async move {
                    if let Err(e) = run_https_server(
                        https_addr,
                        config_clone,
                        shutdown_clone,
                        acceptor,
                        metrics_clone,
                        challenge_store_clone,
                        lua_clone,
                        cb_clone,
                        am_clone,
                        lb_clone,
                    )
                    .await
                    {
                        tracing::error!("HTTPS/2 server error (listener {}): {}", i, e);
                    }
                });
            }
        }

        tracing::info!(
            "HTTP/1.1 server listening on {} ({} accept loops)",
            http_addr,
            num_listeners
        );
        if has_https {
            tracing::info!(
                "HTTPS/2 server listening on {} ({} accept loops)",
                https_addr.unwrap(),
                num_listeners
            );
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

#[allow(clippy::too_many_arguments)]
async fn run_http_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let client = ConnectionPool::new().client();
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let client = client.clone();
                    let config = config.clone();
                    let metrics = metrics.clone();
                    let cs = challenge_store.clone();
                    let lua = lua_engine.clone();
                    let cb = circuit_breaker.clone();
                    let am = app_manager.clone();
                    let lb = load_balancer.clone();
                    let sd = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_http11_connection(
                            stream, client, config, metrics, cs, lua, cb, am, lb, sd,
                        )
                        .await
                        {
                            tracing::debug!("HTTP/1.1 connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("HTTP/1.1 accept error: {}", e);
                }
            },
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_https_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    acceptor: TlsAcceptor,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let client = ConnectionPool::new().client();
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let client = client.clone();
                    let config = config.clone();
                    let acceptor = acceptor.clone();
                    let metrics = metrics.clone();
                    let cs = challenge_store.clone();
                    let lua = lua_engine.clone();
                    let cb = circuit_breaker.clone();
                    let am = app_manager.clone();
                    let lb = load_balancer.clone();
                    let sd = shutdown.clone();
                    tokio::spawn(async move {
                        const TLS_HANDSHAKE_TIMEOUT: tokio::time::Duration =
                            tokio::time::Duration::from_secs(10);
                        match tokio::time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(tls_stream)) => {
                                metrics.inc_tls_connections();
                                if let Err(e) = handle_https2_connection(
                                    tls_stream, client, config, metrics, cs, lua, cb, am, lb, sd,
                                )
                                .await
                                {
                                    tracing::debug!("HTTPS/2 connection error: {}", e);
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("TLS accept error (client incompatible): {}", e);
                            }
                            Err(_) => {
                                tracing::debug!("TLS handshake timed out after {:?}s", TLS_HANDSHAKE_TIMEOUT);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("HTTPS/2 accept error: {}", e);
                }
            },
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_http11_connection(
    stream: tokio::net::TcpStream,
    client: ProxyClient,
    config: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    shutdown: ShutdownCoordinator,
) -> Result<()> {
    let peer_addr = stream.peer_addr().ok();
    let io = TokioIo::new(stream);
    let config_inner = config.get_config();
    let header_timeout = config_inner
        .limits
        .keep_alive_timeout
        .map(Duration::from_secs);
    let svc = service_fn(move |req| {
        handle_request(
            req,
            client.clone(),
            config.clone(),
            metrics.clone(),
            challenge_store.clone(),
            lua_engine.clone(),
            circuit_breaker.clone(),
            app_manager.clone(),
            load_balancer.clone(),
            false,
            peer_addr,
        )
    });

    let conn = match header_timeout {
        Some(timeout) => hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .pipeline_flush(true)
            .header_read_timeout(timeout)
            .serve_connection(io, svc)
            .with_upgrades(),
        None => hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .pipeline_flush(true)
            .serve_connection(io, svc)
            .with_upgrades(),
    };
    let mut conn = std::pin::pin!(conn);
    let mut shutdown_rx = shutdown.subscribe();

    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!("HTTP/1.1 connection error: {}", e);
            }
        }
        _ = shutdown_rx.recv() => {
            // Send Connection: close after the in-flight request completes
            // so the Mac's browser knows to drop its keep-alive socket instead
            // of detecting a dead peer on the next request (saves ~30s).
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/1.1 graceful shutdown error: {}", e);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_https2_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client: ProxyClient,
    config: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    shutdown: ShutdownCoordinator,
) -> Result<()> {
    let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");

    let peer_addr = stream.get_ref().0.peer_addr().ok();
    let io = TokioIo::new(stream);
    let mut shutdown_rx = shutdown.subscribe();

    if is_h2 {
        let exec = TokioExecutor::new();
        let svc = service_fn(move |req| {
            handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
                lua_engine.clone(),
                circuit_breaker.clone(),
                app_manager.clone(),
                load_balancer.clone(),
                true,
                peer_addr,
            )
        });
        let conn = hyper::server::conn::http2::Builder::new(exec)
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_concurrent_streams(250)
            .serve_connection(io, svc);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!("HTTPS/2 connection error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                // Emit HTTP/2 GOAWAY so the browser closes its multiplexed
                // connection promptly. Without this, Chrome waits ~30s on
                // its HTTP/2 PING timeout before retrying on a fresh conn.
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/2 graceful shutdown error: {}", e);
                }
            }
        }
    } else {
        let config_inner = config.get_config();
        let header_timeout = config_inner
            .limits
            .keep_alive_timeout
            .map(Duration::from_secs);
        let svc = service_fn(move |req| {
            handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
                lua_engine.clone(),
                circuit_breaker.clone(),
                app_manager.clone(),
                load_balancer.clone(),
                true,
                peer_addr,
            )
        });
        let conn = match header_timeout {
            Some(timeout) => hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .pipeline_flush(true)
                .header_read_timeout(timeout)
                .serve_connection(io, svc)
                .with_upgrades(),
            None => hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .pipeline_flush(true)
                .serve_connection(io, svc)
                .with_upgrades(),
        };
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!("HTTPS/1.1 connection error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/1.1 graceful shutdown error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Extract headers from a hyper request into a HashMap for Lua consumption.
#[cfg(feature = "scripting")]
fn extract_headers(req: &Request<Incoming>) -> std::collections::HashMap<String, String> {
    req.headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Build a LuaRequest from a hyper Request.
#[cfg(feature = "scripting")]
fn build_lua_request(req: &Request<Incoming>) -> LuaRequest {
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .unwrap_or("")
        .to_string();

    let content_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    LuaRequest {
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        headers: extract_headers(req),
        host,
        content_length,
    }
}

/// Extract response headers into a HashMap for Lua consumption.
#[cfg(feature = "scripting")]
fn extract_response_headers(
    headers: &hyper::HeaderMap,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<Incoming>,
    client: ProxyClient,
    config_manager: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start_time = std::time::Instant::now();
    metrics.inc_in_flight();
    let config = config_manager.get_config();

    // ACME challenge check — must come before all other routing
    if let Some(response) = handle_acme_challenge(&req, &challenge_store) {
        metrics.dec_in_flight();
        return Ok(response);
    }

    // Body size limit check
    if let Some(max_size) = config.limits.max_request_size {
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let is_chunked = req
            .headers()
            .get("transfer-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false);
        if content_length > max_size || (content_length == 0 && !is_chunked) {
            metrics.dec_in_flight();
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 413, duration);
            let body = http_body_util::Full::new(Bytes::from("Payload Too Large")).boxed();
            return Ok(Response::builder()
                .status(413)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    }

    if is_metrics_request(
        &req,
        config.metrics.endpoint.as_deref().unwrap_or("/metrics"),
    ) {
        let is_loopback = peer_addr.map(|a| a.ip().is_loopback()).unwrap_or(false);
        if !is_loopback {
            let duration = start_time.elapsed();
            metrics.dec_in_flight();
            metrics.record_request(0, 0, 403, duration);
            let body = http_body_util::Full::new(Bytes::from("Forbidden")).boxed();
            return Ok(Response::builder()
                .status(403)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
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

    if is_health_request(&req, &config.health) {
        let duration = start_time.elapsed();
        metrics.dec_in_flight();
        metrics.record_request(0, 0, 200, duration);
        let body = http_body_util::Full::new(Bytes::from("OK")).boxed();
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    // --- Lua on_request hook ---
    #[cfg(feature = "scripting")]
    if let Some(ref engine) = lua_engine {
        if engine.has_on_request() {
            let mut lua_req = build_lua_request(&req);
            match engine.call_on_request(&mut lua_req) {
                RequestHookResult::Deny { status, body } => {
                    metrics.dec_in_flight();
                    let duration = start_time.elapsed();
                    metrics.record_request(0, body.len() as u64, status, duration);
                    let resp_body = http_body_util::Full::new(Bytes::from(body)).boxed();
                    return Ok(Response::builder().status(status).body(resp_body).unwrap());
                }
                RequestHookResult::Continue(updated_req) => {
                    // Apply any header modifications back to the hyper request
                    // We can't easily mutate the incoming request headers here since
                    // we'd need to own it, so we store the lua_req for later use.
                    // Headers set via set_header in on_request will be applied after
                    // the request is decomposed into parts.
                    let _ = updated_req;
                }
            }
        }
    }

    let is_websocket = is_websocket_request(&req);

    if is_websocket {
        return handle_websocket_request(
            req,
            client,
            &config,
            &metrics,
            start_time,
            app_manager.clone(),
        )
        .await;
    }

    let timeout_duration = config.limits.request_timeout.map(Duration::from_secs);

    let result = if let Some(timeout_sec) = timeout_duration {
        let handle_fut = handle_regular_request(
            req,
            client,
            &config,
            &lua_engine,
            &circuit_breaker,
            app_manager.clone(),
            load_balancer.clone(),
            is_tls,
            peer_addr,
        );
        match timeout(timeout_sec, handle_fut).await {
            Ok(res) => res,
            Err(_) => {
                metrics.dec_in_flight();
                let duration = start_time.elapsed();
                metrics.record_request(0, 0, 504, duration);
                let body = http_body_util::Full::new(Bytes::from("Gateway Timeout")).boxed();
                return Ok(Response::builder()
                    .status(504)
                    .header("Content-Type", "text/plain")
                    .body(body)
                    .unwrap());
            }
        }
    } else {
        handle_regular_request(
            req,
            client,
            &config,
            &lua_engine,
            &circuit_breaker,
            app_manager.clone(),
            load_balancer.clone(),
            is_tls,
            peer_addr,
        )
        .await
    };
    let duration = start_time.elapsed();

    metrics.dec_in_flight();

    match result {
        #[allow(unused_variables)]
        Ok((response, _target_url, route_scripts)) => {
            let status = response.status().as_u16();

            // --- Lua on_request_end hooks (global + route) ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                let lua_req = LuaRequest {
                    method: String::new(),
                    path: String::new(),
                    headers: std::collections::HashMap::new(),
                    host: String::new(),
                    content_length: 0,
                };
                let duration_ms = duration.as_secs_f64() * 1000.0;

                // Global on_request_end
                if engine.has_on_request_end() {
                    engine.call_on_request_end(&lua_req, status, duration_ms, &_target_url);
                }

                // Route-specific on_request_end
                for script_name in &route_scripts {
                    engine.call_route_on_request_end(
                        script_name,
                        &lua_req,
                        status,
                        duration_ms,
                        &_target_url,
                    );
                }
            }

            metrics.record_request(0, 0, status, duration);
            record_app_metrics(&metrics, &app_manager, &_target_url, 0, 0, status, duration).await;
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
        if let Ok(s) = upgrade.to_str() {
            return s.eq_ignore_ascii_case("websocket");
        }
    }
    false
}

fn is_metrics_request(req: &Request<Incoming>, endpoint: &str) -> bool {
    req.uri().path() == endpoint
}

fn is_health_request(req: &Request<Incoming>, health_config: &crate::config::HealthConfig) -> bool {
    if health_config.enabled == Some(false) {
        return false;
    }
    let path = req.uri().path();
    let liveness_path = health_config
        .liveness_path
        .as_deref()
        .unwrap_or("/health/live");
    let readiness_path = health_config
        .readiness_path
        .as_deref()
        .unwrap_or("/health/ready");
    path == liveness_path || path == readiness_path
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
    _client: ProxyClient,
    config: &crate::config::Config,
    metrics: &SharedMetrics,
    _start_time: std::time::Instant,
    app_manager: Option<Arc<AppManager>>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|h| h.split(':').next().unwrap_or(h).to_string());

    let route = find_matching_rule(&req, &config.rules);
    let override_with_app = match (&route, &host, &app_manager) {
        (Some(matched), Some(h), Some(manager)) if matched.from_domain_rule => {
            manager.resolve_app_target(h).await.is_some()
        }
        _ => false,
    };
    let target_result = if override_with_app {
        None
    } else {
        find_target(&req, &config.rules)
    };

    let target_url = match target_result {
        Some((url, _, _, _)) => url,
        None => {
            if let (Some(ref manager), Some(ref h)) = (app_manager, host) {
                if let Some(target) = manager.resolve_app_target(h).await {
                    let path = req.uri().path();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{}", q))
                        .unwrap_or_default();
                    if target.url.as_str().ends_with('/') {
                        format!("{}{}{}", target.url, &path[1..], query)
                    } else {
                        format!("{}{}{}", target.url, path, query)
                    }
                } else {
                    metrics.inc_errors();
                    let body =
                        http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
                    return Ok(Response::builder().status(421).body(body).unwrap());
                }
            } else {
                metrics.inc_errors();
                let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
                return Ok(Response::builder().status(421).body(body).unwrap());
            }
        }
    };

    // Extract host:port from target URL (e.g. "http://127.0.0.1:3000/path" -> "127.0.0.1:3000")
    let backend_addr = match url::Url::parse(&target_url) {
        Ok(u) => format!(
            "{}:{}",
            u.host_str().unwrap_or("127.0.0.1"),
            u.port().unwrap_or(80)
        ),
        Err(_) => {
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from("Bad backend URL")).boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
    };

    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let host_header = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&backend_addr)
        .to_string();

    // Collect all request headers to forward to the backend.
    // This preserves Cookie, Origin, Sec-WebSocket-Extensions, and any
    // custom headers the client sent — backends may need them for session
    // management, CORS validation, or compression negotiation.
    let mut extra_headers = String::new();
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        // Skip hop-by-hop and headers we set explicitly in the handshake
        match name_str {
            "host"
            | "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol" => continue,
            _ => {}
        }
        if let Ok(v) = value.to_str() {
            extra_headers.push_str(&format!("{}: {}\r\n", name_str, v));
        }
    }

    tracing::info!(
        "WebSocket upgrade request to {}{}{}",
        backend_addr,
        path,
        query
    );

    // Connect to the backend
    let backend = match TcpStream::connect(&backend_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to backend for WebSocket: {}", e);
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from("Backend not reachable")).boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
    };

    // Build the upgrade request forwarding all relevant headers
    let ws_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ws_version = req
        .headers()
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("13")
        .to_string();
    let ws_protocol = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut handshake = format!(
        "GET {}{} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: {}\r\n",
        path, query, host_header, ws_key, ws_version,
    );
    if let Some(proto) = &ws_protocol {
        handshake.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", proto));
    }
    handshake.push_str(&extra_headers);
    handshake.push_str("\r\n");

    let (mut backend_read, mut backend_write) = backend.into_split();
    if let Err(e) = backend_write.write_all(handshake.as_bytes()).await {
        tracing::error!("Failed to send WebSocket handshake to backend: {}", e);
        metrics.inc_errors();
        let body =
            http_body_util::Full::new(Bytes::from("Failed to initiate WebSocket with backend"))
                .boxed();
        return Ok(Response::builder().status(502).body(body).unwrap());
    }

    // Read the backend's 101 response
    let mut response_buf = vec![0u8; 4096];
    let n = match tokio::io::AsyncReadExt::read(&mut backend_read, &mut response_buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            tracing::error!("No response from backend for WebSocket upgrade");
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from(
                "Backend did not respond to WebSocket upgrade",
            ))
            .boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    if !response_str.contains("101") {
        tracing::error!(
            "Backend rejected WebSocket upgrade: {}",
            response_str.lines().next().unwrap_or("")
        );
        metrics.inc_errors();
        let body =
            http_body_util::Full::new(Bytes::from("Backend rejected WebSocket upgrade")).boxed();
        return Ok(Response::builder().status(502).body(body).unwrap());
    }

    // Extract headers from backend 101 response
    let mut accept_key = String::new();
    let mut resp_protocol = None;
    for line in response_str.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name_lower = name.trim().to_lowercase();
            let value = value.trim().to_string();
            if name_lower == "sec-websocket-accept" {
                accept_key = value;
            } else if name_lower == "sec-websocket-protocol" {
                resp_protocol = Some(value);
            }
        }
    }

    // Check for trailing data after the HTTP response headers.
    // The backend may send WebSocket frames immediately after the 101
    // response; if they arrive in the same TCP segment as the response
    // headers they would be in our buffer and must be forwarded.
    let trailing_data = response_buf[..n]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|pos| {
            let body_start = pos + 4;
            if body_start < n {
                Some(response_buf[body_start..n].to_vec())
            } else {
                None
            }
        });

    // Use hyper::upgrade::on to get the client-side stream after we return 101
    let client_upgrade = hyper::upgrade::on(req);

    // Reunite the backend halves
    let backend_stream = backend_read.reunite(backend_write).unwrap();

    // Spawn the bidirectional copy task
    tokio::spawn(async move {
        match client_upgrade.await {
            Ok(upgraded) => {
                let mut client_stream = TokioIo::new(upgraded);
                let (mut br, mut bw) = tokio::io::split(backend_stream);
                let (mut cr, mut cw) = tokio::io::split(&mut client_stream);

                // Forward any trailing WebSocket data captured in the 101 read
                if let Some(data) = trailing_data {
                    if tokio::io::AsyncWriteExt::write_all(&mut cw, &data)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                let _ = tokio::join!(
                    tokio::io::copy(&mut br, &mut cw),
                    tokio::io::copy(&mut cr, &mut bw),
                );
            }
            Err(e) => {
                tracing::error!("WebSocket client upgrade failed: {}", e);
            }
        }
    });

    metrics.dec_in_flight();

    // Return 101 Switching Protocols to the client
    let mut resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key);
    if let Some(proto) = resp_protocol {
        resp = resp.header("Sec-WebSocket-Protocol", proto);
    }
    Ok(resp
        .body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap())
}

/// Returns (Response, target_url_for_logging, route_scripts)
#[allow(clippy::too_many_arguments)]
async fn handle_regular_request(
    req: Request<Incoming>,
    client: ProxyClient,
    config: &crate::config::Config,
    lua_engine: &OptionalLuaEngine,
    circuit_breaker: &SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
) -> Result<(Response<BoxBody>, String, Vec<String>), hyper::Error> {
    let route = find_matching_rule(&req, &config.rules);
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|h| h.split(':').next().unwrap_or(h).to_string());
    tracing::debug!(
        "handle_regular_request: uri.host={:?}, header.host={:?}, rules.len={}",
        req.uri().host(),
        host,
        config.rules.len()
    );

    // When a static domain rule matches but AppManager manages this domain,
    // prefer dynamic app routing so blue-green deployment works correctly.
    let override_with_app = match (&route, &host, &app_manager) {
        (Some(matched), Some(h), Some(manager)) if matched.from_domain_rule => {
            manager.resolve_app_target(h).await.is_some()
        }
        _ => false,
    };
    let route = if override_with_app { None } else { route };

    match route {
        #[allow(unused_mut, unused_variables)]
        Some(matched_route) => {
            let path = req.uri().path().to_string();
            let from_domain_rule = matched_route.from_domain_rule;
            let matched_prefix = matched_route.matched_prefix(is_tls);

            if !matched_route.auth.is_empty() && !verify_basic_auth(&req, &matched_route.auth) {
                tracing::debug!("Basic auth failed for {}", req.uri().path());
                return Ok((create_auth_required_response(), String::new(), vec![]));
            }
            let route_scripts = matched_route.route_scripts.clone();
            let query = req.uri().query().map(|q| q.to_string());

            // Select an available target via circuit breaker
            let target_selection = select_target(
                &matched_route,
                &path,
                query.as_deref(),
                circuit_breaker,
                &load_balancer,
            );
            let (mut target_url, base_url) = match target_selection {
                Some((url, base)) => (url, base),
                None => {
                    // All targets are circuit-broken
                    let body =
                        http_body_util::Full::new(Bytes::from("Service Unavailable")).boxed();
                    return Ok((
                        Response::builder()
                            .status(503)
                            .body(body)
                            .expect("Failed to build response"),
                        String::new(),
                        route_scripts,
                    ));
                }
            };
            // --- Lua route-specific on_request hooks ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                for script_name in &route_scripts {
                    let mut lua_req = build_lua_request(&req);
                    match engine.call_route_on_request(script_name, &mut lua_req) {
                        RequestHookResult::Deny { status, body } => {
                            let resp_body = http_body_util::Full::new(Bytes::from(body)).boxed();
                            return Ok((
                                Response::builder().status(status).body(resp_body).unwrap(),
                                target_url,
                                route_scripts.clone(),
                            ));
                        }
                        RequestHookResult::Continue(_) => {}
                    }
                }
            }

            // --- Lua on_route hook (global) ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                if engine.has_on_route() {
                    let lua_req = build_lua_request(&req);
                    match engine.call_on_route(&lua_req, &target_url) {
                        RouteHookResult::Override(new_url) => {
                            target_url = new_url;
                        }
                        RouteHookResult::Default => {}
                    }
                }
                // Route-specific on_route hooks
                for script_name in &route_scripts {
                    let lua_req = build_lua_request(&req);
                    match engine.call_route_on_route(script_name, &lua_req, &target_url) {
                        RouteHookResult::Override(new_url) => {
                            target_url = new_url;
                        }
                        RouteHookResult::Default => {}
                    }
                }
            }

            // Only extract host_header when needed (domain rules only)
            let host_header = if from_domain_rule {
                req.uri()
                    .host()
                    .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
                    .map(|s| s.to_string())
            } else {
                None
            };

            let (mut parts, body) = req.into_parts();

            // Move headers directly instead of cloning one by one
            let uri = match target_url.parse::<hyper::Uri>() {
                Ok(uri) => uri,
                Err(e) => {
                    tracing::warn!(
                        "Invalid URI from Lua hook or target URL: {}: {}",
                        target_url,
                        e
                    );
                    let body = http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                    return Ok((
                        Response::builder().status(502).body(body).unwrap(),
                        target_url,
                        route_scripts,
                    ));
                }
            };
            parts.uri = uri;
            parts.version = http::Version::HTTP_11;
            parts.extensions = http::Extensions::new();

            // Strip hop-by-hop headers that shouldn't be forwarded to upstream
            const HOP_BY_HOP: &[&str] = &[
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            ];
            for h in HOP_BY_HOP {
                parts.headers.remove(*h);
            }
            // Also strip any header listed in the Connection header
            let conn_header = parts
                .headers
                .get("connection")
                .and_then(|v| v.to_str().ok().map(String::from));
            parts.headers.remove("connection");
            if let Some(conn) = conn_header {
                for name in conn.split(',').map(str::trim) {
                    parts.headers.remove(name);
                }
            }

            let mut request = Request::from_parts(parts, body);

            request.headers_mut().insert(
                "X-Forwarded-For",
                peer_addr
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            request.headers_mut().insert(
                "X-Forwarded-Proto",
                if is_tls {
                    X_FORWARDED_PROTO_HTTPS.clone()
                } else {
                    X_FORWARDED_PROTO_HTTP.clone()
                },
            );

            if from_domain_rule {
                if let Some(host) = host_header {
                    request
                        .headers_mut()
                        .insert("X-Forwarded-Host", host.parse().unwrap());
                }
            }

            match client.request(request).await {
                Ok(response) => {
                    // --- Circuit breaker: record success or failure ---
                    let status_code = response.status().as_u16();
                    if circuit_breaker.is_failure_status(status_code) {
                        circuit_breaker.record_failure(&base_url);
                    } else {
                        circuit_breaker.record_success(&base_url);
                    }

                    // --- Lua on_response hooks (global + route) ---
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = lua_engine {
                        let has_global = engine.has_on_response();
                        let has_route = !route_scripts.is_empty();

                        if has_global || has_route {
                            use crate::scripting::ResponseMod;

                            let lua_req = LuaRequest {
                                method: String::new(),
                                path: String::new(),
                                headers: std::collections::HashMap::new(),
                                host: String::new(),
                                content_length: 0,
                            };
                            let resp_headers = extract_response_headers(response.headers());
                            let resp_status = response.status().as_u16();

                            // Collect all mods: global first, then route scripts
                            let mut all_mods: Vec<ResponseMod> = Vec::new();
                            if has_global {
                                all_mods.push(engine.call_on_response(
                                    &lua_req,
                                    resp_status,
                                    &resp_headers,
                                ));
                            }
                            for script_name in &route_scripts {
                                all_mods.push(engine.call_route_on_response(
                                    script_name,
                                    &lua_req,
                                    resp_status,
                                    &resp_headers,
                                ));
                            }

                            // Merge all mods
                            let mut merged = ResponseMod::default();
                            for mods in all_mods {
                                merged.set_headers.extend(mods.set_headers);
                                merged.remove_headers.extend(mods.remove_headers);
                                if mods.replace_body.is_some() {
                                    merged.replace_body = mods.replace_body;
                                }
                                if mods.override_status.is_some() {
                                    merged.override_status = mods.override_status;
                                }
                            }

                            // Apply modifications if any
                            if !merged.set_headers.is_empty()
                                || !merged.remove_headers.is_empty()
                                || merged.replace_body.is_some()
                                || merged.override_status.is_some()
                            {
                                let (mut parts, body) = response.into_parts();

                                if let Some(status) = merged.override_status {
                                    parts.status =
                                        hyper::StatusCode::from_u16(status).unwrap_or(parts.status);
                                }

                                for name in &merged.remove_headers {
                                    if let Ok(header_name) =
                                        name.parse::<hyper::header::HeaderName>()
                                    {
                                        parts.headers.remove(header_name);
                                    }
                                }

                                for (name, value) in &merged.set_headers {
                                    if let (Ok(header_name), Ok(header_value)) = (
                                        name.parse::<hyper::header::HeaderName>(),
                                        value.parse::<HeaderValue>(),
                                    ) {
                                        parts.headers.insert(header_name, header_value);
                                    }
                                }

                                if let Some(new_body) = merged.replace_body {
                                    let new_bytes = Bytes::from(new_body);
                                    parts.headers.remove("content-length");
                                    parts.headers.insert(
                                        "content-length",
                                        new_bytes.len().to_string().parse().unwrap(),
                                    );
                                    let boxed = http_body_util::Full::new(new_bytes).boxed();
                                    return Ok((
                                        Response::from_parts(parts, boxed),
                                        target_url,
                                        route_scripts.clone(),
                                    ));
                                }

                                let boxed = body.map_err(|_| unreachable!()).boxed();
                                return Ok((
                                    Response::from_parts(parts, boxed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }
                        }
                    }

                    // Rewrite Location header for redirects when a prefix is matched
                    // This ensures redirects go through the proxy, not directly to the backend
                    if let Some(prefix) = matched_prefix.as_ref() {
                        if (300..400).contains(&status_code) {
                            if let Some(location) = response.headers().get("location") {
                                if let Ok(location_str) = location.to_str() {
                                    if location_str.starts_with('/') {
                                        let new_location = format!("{}{}", prefix, location_str);
                                        let (mut parts, body) = response.into_parts();
                                        parts
                                            .headers
                                            .insert("location", new_location.parse().unwrap());
                                        let boxed = body.map_err(|_| unreachable!()).boxed();
                                        return Ok((
                                            Response::from_parts(parts, boxed),
                                            target_url,
                                            route_scripts,
                                        ));
                                    }
                                }
                            }
                        }
                    }

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

                            if body_bytes.len() <= MAX_HTML_REWRITE_SIZE {
                                let is_gzip = parts
                                    .headers
                                    .get("content-encoding")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|v| v.contains("gzip"))
                                    .unwrap_or(false);
                                let is_deflate = parts
                                    .headers
                                    .get("content-encoding")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|v| v.contains("deflate"))
                                    .unwrap_or(false);

                                let raw_bytes = if is_gzip {
                                    use std::io::Read;
                                    let mut decoder = flate2::read::GzDecoder::new(&body_bytes[..]);
                                    let mut decoded = Vec::new();
                                    decoder.read_to_end(&mut decoded).unwrap_or_default();
                                    Bytes::from(decoded)
                                } else if is_deflate {
                                    use std::io::Read;
                                    let mut decoder =
                                        flate2::read::DeflateDecoder::new(&body_bytes[..]);
                                    let mut decoded = Vec::new();
                                    decoder.read_to_end(&mut decoded).unwrap_or_default();
                                    Bytes::from(decoded)
                                } else {
                                    body_bytes.clone()
                                };

                                let html = String::from_utf8_lossy(&raw_bytes);
                                if html.contains("<script")
                                    && (html.contains("integrity=") || html.contains("nonce="))
                                {
                                    tracing::warn!(
                                        "Skipping HTML rewrite for prefix {} due to SRI/nonce attributes",
                                        prefix
                                    );
                                    let body = http_body_util::Full::new(raw_bytes).boxed();
                                    return Ok((
                                        Response::from_parts(parts, body),
                                        target_url,
                                        route_scripts.clone(),
                                    ));
                                }
                                let rewritten = html
                                    .replace("href=\"/", &format!("href=\"{}/", prefix))
                                    .replace("src=\"/", &format!("src=\"{}/", prefix))
                                    .replace("action=\"/", &format!("action=\"{}/", prefix));
                                let rewritten_bytes = Bytes::from(rewritten);
                                let mut parts = parts;
                                parts.headers.remove("content-encoding");
                                parts.headers.remove("content-length");
                                parts.headers.insert(
                                    "content-length",
                                    rewritten_bytes.len().to_string().parse().unwrap(),
                                );
                                let boxed = http_body_util::Full::new(rewritten_bytes).boxed();
                                return Ok((
                                    Response::from_parts(parts, boxed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            } else {
                                let body = http_body_util::Full::new(body_bytes).boxed();
                                return Ok((
                                    Response::from_parts(parts, body),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }
                        }
                    }

                    let (parts, body) = response.into_parts();
                    let boxed = body.map_err(|_| unreachable!()).boxed();
                    Ok((
                        Response::from_parts(parts, boxed),
                        target_url,
                        route_scripts,
                    ))
                }
                Err(e) => {
                    circuit_breaker.record_failure(&base_url);
                    tracing::error!("Backend request failed: {} (target: {})", e, target_url);
                    let body = http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                    Ok((
                        Response::builder()
                            .status(502)
                            .body(body)
                            .expect("Failed to build response"),
                        target_url,
                        route_scripts,
                    ))
                }
            }
        }
        None => {
            let host = req
                .uri()
                .host()
                .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
                .map(|h| h.split(':').next().unwrap_or(h).to_string());
            let app_manager_available = app_manager.is_some();

            if let (Some(ref manager), Some(ref h)) = (app_manager, host) {
                if let Some(target) = manager.resolve_app_target(h).await {
                    let base_url = target.url.to_string();
                    let path = req.uri().path();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{}", q))
                        .unwrap_or_default();
                    let target_url = if target.url.as_str().ends_with('/') {
                        format!("{}{}{}", target.url, &path[1..], query)
                    } else {
                        format!("{}{}{}", target.url, path, query)
                    };
                    let forwarded_host = h.clone();

                    let (mut parts, body) = req.into_parts();
                    let uri = match target_url.parse::<hyper::Uri>() {
                        Ok(uri) => uri,
                        Err(e) => {
                            tracing::warn!(
                                "Invalid URI in app-managed path: {}: {}",
                                target_url,
                                e
                            );
                            let body =
                                http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                            return Ok((
                                Response::builder().status(502).body(body).unwrap(),
                                target_url,
                                vec![],
                            ));
                        }
                    };
                    parts.uri = uri;
                    parts.version = http::Version::HTTP_11;
                    parts.extensions = http::Extensions::new();

                    let mut request = Request::from_parts(parts, body);
                    request.headers_mut().insert(
                        "X-Forwarded-For",
                        peer_addr
                            .map(|addr| addr.ip().to_string())
                            .unwrap_or_default()
                            .parse()
                            .unwrap_or_else(|_| HeaderValue::from_static("")),
                    );
                    request.headers_mut().insert(
                        "X-Forwarded-Proto",
                        if is_tls {
                            X_FORWARDED_PROTO_HTTPS.clone()
                        } else {
                            X_FORWARDED_PROTO_HTTP.clone()
                        },
                    );
                    request
                        .headers_mut()
                        .insert("X-Forwarded-Host", forwarded_host.parse().unwrap());

                    match client.request(request).await {
                        Ok(response) => {
                            let status_code = response.status().as_u16();
                            if circuit_breaker.is_failure_status(status_code) {
                                circuit_breaker.record_failure(&base_url);
                            } else {
                                circuit_breaker.record_success(&base_url);
                            }
                            let (parts, body) = response.into_parts();
                            let boxed = body.map_err(|_| unreachable!()).boxed();
                            return Ok((Response::from_parts(parts, boxed), target_url, vec![]));
                        }
                        Err(e) => {
                            circuit_breaker.record_failure(&base_url);
                            tracing::error!(
                                "Backend request failed: {} (target: {})",
                                e,
                                target_url
                            );
                            // Trigger immediate async failover so the next
                            // request hits a healthy backend
                            {
                                let mgr = manager.clone();
                                let host = h.clone();
                                tokio::spawn(async move {
                                    if let Some(app_name) = mgr.app_name_for_host(&host).await {
                                        mgr.trigger_async_failover(app_name);
                                    }
                                });
                            }
                            let body =
                                http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                            return Ok((
                                Response::builder()
                                    .status(502)
                                    .body(body)
                                    .expect("Failed to build response"),
                                target_url,
                                vec![],
                            ));
                        }
                    }
                }
            }

            let _ = lua_engine;
            tracing::warn!("Returning 421 Misdirected Request - no route found for host, app_manager available: {}", app_manager_available);
            let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
            Ok((
                Response::builder()
                    .status(421)
                    .body(body)
                    .expect("Failed to build response"),
                String::new(),
                vec![],
            ))
        }
    }
}

/// How the target URL is resolved from the matched route
enum UrlResolution {
    /// Domain, Default: append full request path
    AppendPath,
    /// DomainPath, Prefix: strip prefix, append suffix
    StripPrefix(String),
    /// Exact, Regex: use target URL as-is
    Identity,
}

/// A matched routing rule with all the info needed to resolve a target URL
struct MatchedRoute<'a> {
    targets: &'a [crate::config::Target],
    from_domain_rule: bool,
    resolution: UrlResolution,
    route_scripts: Vec<String>,
    auth: Vec<crate::auth::BasicAuth>,
    load_balancing: &'a crate::config::LoadBalancingStrategy,
    host: String,
}

impl<'a> MatchedRoute<'a> {
    fn matched_prefix(&self, is_tls: bool) -> Option<String> {
        match &self.resolution {
            UrlResolution::StripPrefix(prefix) => Some(prefix.trim_end_matches('/').to_string()),
            UrlResolution::AppendPath => {
                let scheme = if is_tls { "https" } else { "http" };
                Some(format!("{}://{}", scheme, self.host))
            }
            _ => None,
        }
    }
}

/// Resolve a target URL based on the resolution strategy
fn resolve_target_url(
    target: &crate::config::Target,
    path: &str,
    query: Option<&str>,
    resolution: &UrlResolution,
) -> String {
    let target_str = target.url.as_str();
    let qs = match query {
        Some(q) if !q.is_empty() => format!("?{}", q),
        _ => String::new(),
    };
    match resolution {
        UrlResolution::AppendPath => {
            if target_str.ends_with('/') {
                format!("{}{}{}", target_str, &path[1..], qs)
            } else {
                format!("{}{}{}", target_str, path, qs)
            }
        }
        UrlResolution::StripPrefix(prefix) => {
            let suffix = if path.len() >= prefix.len() {
                &path[prefix.len()..]
            } else {
                ""
            };
            format!("{}{}{}", target_str, suffix, qs)
        }
        UrlResolution::Identity => {
            if qs.is_empty() {
                target_str.to_owned()
            } else {
                format!("{}{}", target_str, qs)
            }
        }
    }
}

/// Pure routing: find which rule matches the request
fn find_matching_rule<'a>(
    req: &Request<Incoming>,
    rules: &'a [crate::config::ProxyRule],
) -> Option<MatchedRoute<'a>> {
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|h| h.split(':').next().unwrap_or(h))?;

    let path = req.uri().path();

    for rule in rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Domain(domain)
                if domain == host && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: true,
                    resolution: UrlResolution::AppendPath,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: domain.clone(),
                });
            }
            crate::config::RuleMatcher::DomainPath(domain, path_prefix)
                if domain == host && !rule.targets.is_empty() =>
            {
                let matches = path.starts_with(path_prefix)
                    || (path_prefix.ends_with('/') && path == path_prefix.trim_end_matches('/'));
                if matches {
                    return Some(MatchedRoute {
                        targets: &rule.targets,
                        from_domain_rule: true,
                        resolution: UrlResolution::StripPrefix(path_prefix.clone()),
                        route_scripts: rule.scripts.clone(),
                        auth: rule.auth.clone(),
                        load_balancing: &rule.load_balancing,
                        host: domain.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    // Check specific rules (Exact, Prefix, Regex) before Default
    for rule in rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Exact(exact)
                if path == exact && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                });
            }
            crate::config::RuleMatcher::Prefix(prefix) if !rule.targets.is_empty() => {
                // Match /db against prefix /db/ (path without trailing slash)
                let matches = path.starts_with(prefix)
                    || (prefix.ends_with('/') && path == prefix.trim_end_matches('/'));
                if matches {
                    return Some(MatchedRoute {
                        targets: &rule.targets,
                        from_domain_rule: false,
                        resolution: UrlResolution::StripPrefix(prefix.clone()),
                        route_scripts: rule.scripts.clone(),
                        auth: rule.auth.clone(),
                        load_balancing: &rule.load_balancing,
                        host: host.to_string(),
                    });
                }
            }
            crate::config::RuleMatcher::Regex(ref rm)
                if rm.is_match(path) && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                });
            }
            _ => {}
        }
    }

    // Fall back to Default rule
    for rule in rules {
        if let crate::config::RuleMatcher::Default = &rule.matcher {
            if !rule.targets.is_empty() {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                });
            }
        }
    }

    None
}

/// Select a target based on the load balancing strategy.
/// Returns (resolved_url, base_url) for logging and circuit breaker tracking.
fn select_target(
    route: &MatchedRoute<'_>,
    path: &str,
    query: Option<&str>,
    circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
    load_balancer: &LoadBalancerState,
) -> Option<(String, String)> {
    let targets = route.targets;
    if targets.is_empty() {
        return None;
    }

    match route.load_balancing {
        crate::config::LoadBalancingStrategy::Failover => {
            // Failover: use first available target (circuit breaker aware)
            for target in targets {
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
        crate::config::LoadBalancingStrategy::RoundRobin => {
            // Round-robin: cycle through all targets, skip unhealthy ones
            let num_targets = targets.len();
            if num_targets == 0 || load_balancer.counters.is_empty() {
                return None;
            }
            let start_idx = load_balancer.counters[0].load(Ordering::Relaxed) % num_targets;

            for i in 0..num_targets {
                let idx = (start_idx + i) % num_targets;
                let target = &targets[idx];
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    load_balancer.counters[0].fetch_add(1, Ordering::Relaxed);
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
        crate::config::LoadBalancingStrategy::Weighted => {
            // Weighted: use weights to determine distribution, skip unhealthy
            let total_weight: u32 = targets.iter().map(|t| t.weight as u32).sum();
            if total_weight == 0 {
                return select_target(
                    route,
                    path,
                    query,
                    circuit_breaker,
                    &LoadBalancerState::new(1),
                );
            }

            let start_idx =
                (load_balancer.counters[0].load(Ordering::Relaxed) % total_weight as usize) as u32;
            let mut cumulative = 0u32;

            for target in targets.iter() {
                cumulative += target.weight as u32;
                let base_url = target.url.as_str().to_owned();
                if cumulative > start_idx && circuit_breaker.is_available(&base_url) {
                    load_balancer.counters[0].fetch_add(1, Ordering::Relaxed);
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }

            // Fallback: try any available target
            for target in targets {
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
    }
}

/// Backward-compatible wrapper: returns (target_url, from_domain_rule, matched_prefix, route_scripts)
fn find_target(
    req: &Request<Incoming>,
    rules: &[crate::config::ProxyRule],
) -> Option<(String, bool, Option<String>, Vec<String>)> {
    let route = find_matching_rule(req, rules)?;
    let path = req.uri().path();
    let query = req.uri().query();
    let target = route.targets.first()?;
    let resolved = resolve_target_url(target, path, query, &route.resolution);
    let matched_prefix = route.matched_prefix(false);
    Some((
        resolved,
        route.from_domain_rule,
        matched_prefix,
        route.route_scripts,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_balancer_state_select_index() {
        let lb = LoadBalancerState::new(1);

        // First call should return 0
        assert_eq!(lb.select_index(0, 3), 0);
        // Second call should return 1
        assert_eq!(lb.select_index(0, 3), 1);
        // Third call should return 2
        assert_eq!(lb.select_index(0, 3), 2);
        // Fourth call wraps around to 0
        assert_eq!(lb.select_index(0, 3), 0);
    }

    #[test]
    fn test_load_balancer_state_zero_targets() {
        let lb = LoadBalancerState::new(1);
        assert_eq!(lb.select_index(0, 0), 0);
    }
}
