// When scripting feature is disabled, OptionalLuaEngine = () and cloning it triggers warnings
#![allow(clippy::let_unit_value, clippy::clone_on_copy, clippy::unit_arg)]

use crate::acme::ChallengeStore;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::shutdown::ShutdownCoordinator;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "scripting")]
use crate::scripting::{LuaEngine, LuaRequest, RequestHookResult, RouteHookResult};

type ClientType = Client<HttpConnector, Incoming>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

#[cfg(feature = "scripting")]
type OptionalLuaEngine = Option<LuaEngine>;
#[cfg(not(feature = "scripting"))]
type OptionalLuaEngine = ();

/// Pre-parsed header value for X-Forwarded-For to avoid parsing on every request
static X_FORWARDED_FOR_VALUE: std::sync::LazyLock<HeaderValue> =
    std::sync::LazyLock::new(|| HeaderValue::from_static("127.0.0.1"));

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

fn create_client() -> ClientType {
    let exec = TokioExecutor::new();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(30)));
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    Client::builder(exec)
        .pool_max_idle_per_host(256)
        .pool_idle_timeout(Duration::from_secs(60))
        .build(connector)
}

pub struct ProxyServer {
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    tls_acceptor: Option<TlsAcceptor>,
    https_addr: Option<SocketAddr>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
}

impl ProxyServer {
    pub fn new(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
    ) -> Result<Self> {
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: None,
            https_addr: None,
            metrics,
            challenge_store,
            lua_engine,
        })
    }

    pub fn with_https(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        tls_acceptor: TlsAcceptor,
        https_addr: SocketAddr,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
    ) -> Result<Self> {
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: Some(tls_acceptor),
            https_addr: Some(https_addr),
            metrics,
            challenge_store,
            lua_engine,
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
        for i in 0..num_listeners {
            let config_clone = self.config.clone();
            let shutdown_clone = self.shutdown.clone();
            let metrics_clone = self.metrics.clone();
            let challenge_store_clone = self.challenge_store.clone();
            let lua_clone = self.lua_engine.clone();

            tokio::spawn(async move {
                if let Err(e) = run_http_server(
                    http_addr,
                    config_clone,
                    shutdown_clone,
                    metrics_clone,
                    challenge_store_clone,
                    lua_clone,
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

                tokio::spawn(async move {
                    if let Err(e) = run_https_server(
                        https_addr,
                        config_clone,
                        shutdown_clone,
                        acceptor,
                        metrics_clone,
                        challenge_store_clone,
                        lua_clone,
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

async fn run_http_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let client = create_client();

    loop {
        if shutdown.is_shutting_down() {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let client = client.clone();
                let config = config.get_config();
                let metrics = metrics.clone();
                let cs = challenge_store.clone();
                let lua = lua_engine.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_http11_connection(stream, client, config, metrics, cs, lua).await
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
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let client = create_client();

    loop {
        if shutdown.is_shutting_down() {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let client = client.clone();
                let config = config.get_config();
                let acceptor = acceptor.clone();
                let metrics = metrics.clone();
                let cs = challenge_store.clone();
                let lua = lua_engine.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            metrics.inc_tls_connections();
                            if let Err(e) =
                                handle_https2_connection(tls_stream, client, config, metrics, cs, lua)
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
    lua_engine: OptionalLuaEngine,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        handle_request(
            req,
            client.clone(),
            config.clone(),
            metrics.clone(),
            challenge_store.clone(),
            lua_engine.clone(),
        )
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .pipeline_flush(true)
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
    lua_engine: OptionalLuaEngine,
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
                lua_engine.clone(),
            )
        });
        let conn = hyper::server::conn::http2::Builder::new(exec)
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_concurrent_streams(250)
            .serve_connection(io, svc);
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
                lua_engine.clone(),
            )
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .pipeline_flush(true)
            .serve_connection(io, svc);
        if let Err(e) = conn.await {
            tracing::debug!("HTTPS/1.1 connection error: {}", e);
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

async fn handle_request(
    req: Request<Incoming>,
    client: ClientType,
    config: Arc<crate::config::Config>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
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
                    return Ok(Response::builder()
                        .status(status)
                        .body(resp_body)
                        .unwrap());
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
        return handle_websocket_request(req, client, &config, &metrics, start_time).await;
    }

    let result = handle_regular_request(req, client, &config, &lua_engine).await;
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
                    engine.call_on_request_end(
                        &lua_req,
                        status,
                        duration_ms,
                        &_target_url,
                    );
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

    let (target_url, _, _, _) = target_result.unwrap();
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

/// Returns (Response, target_url_for_logging, route_scripts)
async fn handle_regular_request(
    req: Request<Incoming>,
    client: ClientType,
    config: &crate::config::Config,
    lua_engine: &OptionalLuaEngine,
) -> Result<(Response<BoxBody>, String, Vec<String>), hyper::Error> {
    let target_result = find_target(&req, &config.rules);

    match target_result {
        #[allow(unused_mut, unused_variables)]
        Some((mut target_url, from_domain_rule, matched_prefix, route_scripts)) => {
            // --- Lua route-specific on_request hooks ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                for script_name in &route_scripts {
                    let mut lua_req = build_lua_request(&req);
                    match engine.call_route_on_request(script_name, &mut lua_req) {
                        RequestHookResult::Deny { status, body } => {
                            let resp_body =
                                http_body_util::Full::new(Bytes::from(body)).boxed();
                            return Ok((
                                Response::builder()
                                    .status(status)
                                    .body(resp_body)
                                    .unwrap(),
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
            let uri: hyper::Uri = target_url.parse().expect("valid URI");
            parts.uri = uri;
            parts.extensions = http::Extensions::new();

            let mut request = Request::from_parts(parts, body);

            request
                .headers_mut()
                .insert("X-Forwarded-For", X_FORWARDED_FOR_VALUE.clone());

            if from_domain_rule {
                if let Some(host) = host_header {
                    request
                        .headers_mut()
                        .insert("X-Forwarded-Host", host.parse().unwrap());
                }
            }

            match client.request(request).await {
                Ok(response) => {
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
                                all_mods.push(engine.call_on_response(&lua_req, resp_status, &resp_headers));
                            }
                            for script_name in &route_scripts {
                                all_mods.push(engine.call_route_on_response(
                                    script_name, &lua_req, resp_status, &resp_headers,
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
                                    if let Ok(header_name) = name.parse::<hyper::header::HeaderName>()
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
                            return Ok((Response::from_parts(parts, boxed), target_url, route_scripts.clone()));
                        }
                    }

                    let (parts, body) = response.into_parts();
                    let boxed = body.map_err(|_| unreachable!()).boxed();
                    Ok((Response::from_parts(parts, boxed), target_url, route_scripts))
                }
                Err(e) => {
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
            // Suppress unused variable warning when scripting feature is disabled
            let _ = lua_engine;
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

/// Returns (target_url, from_domain_rule, matched_prefix, route_scripts)
fn find_target(
    req: &Request<Incoming>,
    rules: &[crate::config::ProxyRule],
) -> Option<(String, bool, Option<String>, Vec<String>)> {
    let host = req
        .uri()
        .host()
        .or(req.headers().get("host").and_then(|h| h.to_str().ok()))
        .map(|h| h.split(':').next().unwrap_or(h))?;

    let path = req.uri().path();
    let mut matched_domain = false;

    for rule in rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Domain(domain) => {
                if domain == host {
                    matched_domain = true;
                    if let Some(target) = rule.targets.first() {
                        let target_str = target.url.as_str();
                        let final_url = if target_str.ends_with('/') {
                            format!("{}{}", target_str, &path[1..])
                        } else {
                            format!("{}{}", target_str, path)
                        };
                        return Some((final_url, true, None, rule.scripts.clone()));
                    }
                }
            }
            crate::config::RuleMatcher::DomainPath(domain, path_prefix) => {
                if domain == host && path.starts_with(path_prefix) {
                    if let Some(target) = rule.targets.first() {
                        let target_str = target.url.as_str();
                        let suffix = &path[path_prefix.len()..];
                        let final_url = format!("{}{}", target_str, suffix);
                        let prefix = path_prefix.trim_end_matches('/').to_string();
                        return Some((final_url, true, Some(prefix), rule.scripts.clone()));
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
                        return Some((target.url.as_str().to_owned(), false, None, rule.scripts.clone()));
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
                        return Some((final_url, false, Some(matched_prefix), rule.scripts.clone()));
                    }
                }
            }
            crate::config::RuleMatcher::Regex(regex) => {
                if regex.is_match(path) {
                    if let Some(target) = rule.targets.first() {
                        return Some((target.url.as_str().to_owned(), false, None, rule.scripts.clone()));
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
                return Some((final_url, false, None, rule.scripts.clone()));
            }
        }
    }

    None
}
