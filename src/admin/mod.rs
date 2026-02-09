pub mod handlers;

use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

pub struct AdminState {
    pub config_manager: Arc<ConfigManager>,
    pub metrics: SharedMetrics,
    pub start_time: Instant,
}

fn json_response(status: u16, body: serde_json::Value) -> Response<BoxBody> {
    let bytes = Bytes::from(serde_json::to_string(&body).unwrap());
    Response::builder()
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
    Response::builder()
        .status(204)
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

    let response = match (method, path.as_str()) {
        // Phase 1: Read-only endpoints
        (Method::GET, "/api/v1/status") => handlers::get_status(&state),
        (Method::GET, "/api/v1/config") => handlers::get_config(&state),
        (Method::GET, "/api/v1/routes") => handlers::get_routes(&state),
        (Method::GET, "/api/v1/metrics") => handlers::get_metrics(&state),
        (Method::POST, "/api/v1/reload") => handlers::post_reload(&state).await,

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

        _ => error_response(404, "Not found"),
    };

    Ok(response)
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
