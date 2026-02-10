pub mod handlers;

use crate::app::AppManager;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

pub struct AdminState {
    pub config_manager: Arc<ConfigManager>,
    pub metrics: SharedMetrics,
    pub start_time: Instant,
    pub circuit_breaker: SharedCircuitBreaker,
    pub app_manager: Option<Arc<AppManager>>,
}

pub(crate) fn cors_headers(
    builder: hyper::http::response::Builder,
) -> hyper::http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .header("Access-Control-Allow-Headers", "Content-Type, X-Api-Key")
}

fn json_response(status: u16, body: serde_json::Value) -> Response<BoxBody> {
    let bytes = Bytes::from(serde_json::to_string(&body).unwrap());
    cors_headers(Response::builder())
        .status(status)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(bytes).boxed())
        .unwrap()
}

fn ok_response(data: serde_json::Value) -> Response<BoxBody> {
    json_response(200, serde_json::json!({ "ok": true, "data": data }))
}

fn created_response(data: serde_json::Value) -> Response<BoxBody> {
    json_response(201, serde_json::json!({ "ok": true, "data": data }))
}

fn no_content_response() -> Response<BoxBody> {
    cors_headers(Response::builder())
        .status(204)
        .body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap()
}

fn preflight_response() -> Response<BoxBody> {
    cors_headers(Response::builder())
        .status(204)
        .header("Access-Control-Max-Age", "86400")
        .body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap()
}

fn error_response(status: u16, message: &str) -> Response<BoxBody> {
    json_response(status, serde_json::json!({ "ok": false, "error": message }))
}

fn check_auth(req: &Request<Incoming>, api_key: &Option<String>) -> bool {
    match api_key {
        None => true, // No auth configured = dev mode
        Some(key) if key.is_empty() => true,
        Some(key) => req
            .headers()
            .get("X-Api-Key")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == key),
    }
}

/// Extract route index from path like /api/v1/routes/3
fn extract_route_index(path: &str) -> Option<usize> {
    path.strip_prefix("/api/v1/routes/")
        .and_then(|s| s.parse::<usize>().ok())
}

async fn handle_admin_request(
    req: Request<Incoming>,
    state: Arc<AdminState>,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    let api_key = state.config_manager.get_config().admin.api_key.clone();
    if !check_auth(&req, &api_key) {
        return Ok(error_response(401, "Unauthorized"));
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Handle CORS preflight
    if method == Method::OPTIONS {
        return Ok(preflight_response());
    }

    let response = match (method.clone(), path.as_str()) {
        // Phase 1: Read-only endpoints
        (Method::GET, "/api/v1/status") => handlers::get_status(&state),
        (Method::GET, "/api/v1/config") => handlers::get_config(&state),
        (Method::GET, "/api/v1/routes") => handlers::get_routes(&state),
        (Method::GET, "/api/v1/metrics") => handlers::get_metrics(&state),
        (Method::POST, "/api/v1/reload") => handlers::post_reload(&state).await,

        // App management endpoints
        (Method::GET, "/api/v1/apps") => handlers::get_apps(&state).await,
        (_, p) if p.starts_with("/api/v1/apps/") => {
            let app_name = p.strip_prefix("/api/v1/apps/").unwrap_or("");
            if method == Method::GET && !app_name.is_empty() && !app_name.contains('/') {
                handlers::get_app(&state, app_name).await
            } else if app_name.ends_with("/deploy") {
                let name = app_name.strip_suffix("/deploy").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_deploy(&state, name).await
                }
            } else if app_name.ends_with("/restart") {
                let name = app_name.strip_suffix("/restart").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_restart(&state, name).await
                }
            } else if app_name.ends_with("/rollback") {
                let name = app_name.strip_suffix("/rollback").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_rollback(&state, name).await
                }
            } else if app_name.ends_with("/stop") {
                let name = app_name.strip_suffix("/stop").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_stop(&state, name).await
                }
            } else if app_name.ends_with("/logs") {
                let name = app_name.strip_suffix("/logs").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::get_app_logs(&state, name).await
                }
            } else {
                error_response(404, "Not found")
            }
        }

        // Phase 2: Mutation endpoints
        (Method::POST, "/api/v1/routes") => {
            let body = read_body(req).await;
            handlers::post_route(&state, &body)
        }
        (Method::PUT, "/api/v1/config") => {
            let body = read_body(req).await;
            handlers::put_config(&state, &body)
        }

        // Routes with index parameter
        (Method::GET, p) if p.starts_with("/api/v1/routes/") => match extract_route_index(p) {
            Some(idx) => handlers::get_route(&state, idx),
            None => error_response(400, "Invalid route index"),
        },
        (Method::PUT, p) if p.starts_with("/api/v1/routes/") => match extract_route_index(p) {
            Some(idx) => {
                let body = read_body(req).await;
                handlers::put_route(&state, idx, &body)
            }
            None => error_response(400, "Invalid route index"),
        },
        (Method::DELETE, p) if p.starts_with("/api/v1/routes/") => match extract_route_index(p) {
            Some(idx) => handlers::delete_route(&state, idx),
            None => error_response(400, "Invalid route index"),
        },

        // Circuit breaker endpoints
        (Method::GET, "/api/v1/circuit-breaker") => handlers::get_circuit_breaker(&state),
        (Method::POST, "/api/v1/circuit-breaker/reset") => handlers::reset_circuit_breaker(&state),

        // Everything else → proxy to _admin app (UI, static assets, etc.)
        _ if state.app_manager.is_some() => {
            let is_ws = req
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
            if is_ws {
                proxy_websocket_to_admin_app(req, &state).await
            } else {
                proxy_to_admin_app(req, &state).await
            }
        }
        _ => error_response(404, "Not found"),
    };

    Ok(response)
}

async fn proxy_to_admin_app(req: Request<Incoming>, state: &Arc<AdminState>) -> Response<BoxBody> {
    let port = match resolve_admin_port(state).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_uri = format!("http://localhost:{}{}{}", port, path, query);

    let (mut parts, body) = req.into_parts();
    parts.uri = match target_uri.parse() {
        Ok(uri) => uri,
        Err(_) => return error_response(500, "Failed to build proxy URI"),
    };

    let proxy_req = Request::from_parts(parts, body);

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(std::time::Duration::from_secs(3)));

    let client: Client<HttpConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build(connector);

    match client.request(proxy_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let mapped = body.map_err(|_| -> std::convert::Infallible { unreachable!() });
            Response::from_parts(parts, mapped.boxed())
        }
        Err(e) => {
            tracing::error!("Failed to proxy to _admin app: {}", e);
            error_response(502, &format!("Admin app not reachable on port {} — deploy it first: POST /api/v1/apps/_admin/deploy", port))
        }
    }
}

/// Resolve the _admin app's backend port, or return an error response.
async fn resolve_admin_port(state: &Arc<AdminState>) -> Result<u16, Response<BoxBody>> {
    let app_manager = match &state.app_manager {
        Some(m) => m,
        None => return Err(error_response(501, "App management not configured")),
    };

    let app = match app_manager.get_app("_admin").await {
        Some(a) => a,
        None => return Err(error_response(502, "_admin app not found")),
    };

    let port = if app.current_slot == "blue" {
        app.blue.port
    } else {
        app.green.port
    };

    if port == 0 {
        return Err(error_response(502, "_admin app not deployed"));
    }

    Ok(port)
}

async fn proxy_websocket_to_admin_app(
    req: Request<Incoming>,
    state: &Arc<AdminState>,
) -> Response<BoxBody> {
    let port = match resolve_admin_port(state).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Build the raw HTTP upgrade request to send to the backend
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

    // Connect to the backend
    let backend = match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to _admin backend for WebSocket: {}", e);
            return error_response(502, "Admin app not reachable");
        }
    };

    // Send the upgrade request to the backend
    let mut handshake = format!(
        "GET {}{} HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: {}\r\n",
        path, query, port, ws_key, ws_version,
    );
    if let Some(proto) = &ws_protocol {
        handshake.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", proto));
    }
    handshake.push_str("\r\n");

    let (mut backend_read, mut backend_write) = backend.into_split();
    if let Err(e) = backend_write.write_all(handshake.as_bytes()).await {
        tracing::error!("Failed to send WebSocket handshake to backend: {}", e);
        return error_response(502, "Failed to initiate WebSocket with backend");
    }

    // Read the backend's 101 response
    let mut response_buf = vec![0u8; 4096];
    let n = match backend_read.read(&mut response_buf).await {
        Ok(n) if n > 0 => n,
        _ => {
            tracing::error!("No response from backend for WebSocket upgrade");
            return error_response(502, "Backend did not respond to WebSocket upgrade");
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    if !response_str.contains("101") {
        tracing::error!(
            "Backend rejected WebSocket upgrade: {}",
            response_str.lines().next().unwrap_or("")
        );
        return error_response(502, "Backend rejected WebSocket upgrade");
    }

    // Extract headers from backend 101 response to forward to client
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

    // Return 101 Switching Protocols to the client
    let mut resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key);
    if let Some(proto) = resp_protocol {
        resp = resp.header("Sec-WebSocket-Protocol", proto);
    }
    resp.body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap()
}

async fn read_body(req: Request<Incoming>) -> String {
    match req.into_body().collect().await {
        Ok(collected) => String::from_utf8_lossy(&collected.to_bytes()).to_string(),
        Err(_) => String::new(),
    }
}

pub async fn run_admin_server(state: Arc<AdminState>) -> Result<()> {
    let bind = state.config_manager.get_config().admin.bind.clone();
    let addr: std::net::SocketAddr = bind.parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("Admin API listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        async move { handle_admin_request(req, state).await }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!("Admin connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Admin accept error: {}", e);
            }
        }
    }
}
