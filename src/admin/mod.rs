pub mod handlers;

use crate::app::AppManager;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::proxy_headers::strip_hop_by_hop;
use crate::server::IpRateLimiter;
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
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
    /// Shared per-IP rate limiter (same `Arc` as the proxy's, so the
    /// configured budget is global across both surfaces). `None` when
    /// `[rate_limiting].enabled` is unset/false.
    pub rate_limiter: Option<Arc<IpRateLimiter>>,
    /// TLS manager for rescanning `certs/` at runtime.
    ///
    /// Certificate files were only ever read once, during startup, so dropping
    /// a new or renewed certificate into `certs/` required a full restart —
    /// every connection dropped to install a cert. `TlsManager` is `Clone` and
    /// its resolver is an `Arc` shared with the running acceptor, so a reload
    /// through this clone is visible to live TLS handshakes immediately.
    pub tls_manager: Option<crate::TlsManager>,
    /// HTTP-01 tokens this proxy will answer for.
    ///
    /// The same `Arc` the request path reads, so a token pushed here is
    /// answerable on the next request with no reload.
    ///
    /// **This is what makes a second proxy possible.** Let's Encrypt validates
    /// by fetching `http://<domain>/.well-known/acme-challenge/<token>` and
    /// gets whichever node the VIP routes it to — not the node that placed the
    /// order. With the token only in the ordering node's memory, a two-node
    /// cluster answers correctly about half the time, and every miss also
    /// spends one of the five failed-validation slots for that hostname.
    ///
    /// The cluster's elected orderer pushes its live tokens here before it
    /// tells Let's Encrypt to validate. Nothing pushes today, and an empty map
    /// changes no behaviour at all — locally-ordered certificates still write
    /// their own tokens into the same store.
    pub challenge_store: Option<crate::ChallengeStore>,
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

fn unauthorized_response(use_basic_auth: bool) -> Response<BoxBody> {
    let body = http_body_util::Full::new(Bytes::from("Unauthorized")).boxed();
    let mut builder = Response::builder()
        .status(401)
        .header("Content-Type", "application/json");
    if use_basic_auth {
        builder = builder.header("WWW-Authenticate", "Basic realm=\"Admin\"");
    }
    builder.body(body).unwrap()
}

/// Byte-equal in time independent of where (or whether) the inputs differ.
/// `==` short-circuits on the first mismatching byte, which leaks key
/// prefix information through response timing on a network-reachable port.
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

fn check_auth(
    req: &Request<Incoming>,
    api_key: &Option<String>,
    username: &Option<String>,
    password_hash: &Option<String>,
) -> bool {
    if username.is_none() && password_hash.is_none() && api_key.is_none() {
        return true;
    }

    if let Some(key) = api_key {
        if !key.is_empty()
            && req
                .headers()
                .get("X-Api-Key")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| constant_time_eq(v.as_bytes(), key.as_bytes()))
        {
            return true;
        }
    }

    if let (Some(user), Some(hash)) = (username, password_hash) {
        if let Some(auth_header) = req.headers().get("authorization") {
            if let Ok(header_value) = auth_header.to_str() {
                if let Some(encoded) = header_value.strip_prefix("Basic ") {
                    if let Ok(decoded) =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                    {
                        let creds = String::from_utf8_lossy(&decoded);
                        if let Some((u, p)) = creds.split_once(':') {
                            let user_ok = constant_time_eq(u.as_bytes(), user.as_bytes());
                            // Always run exactly one bcrypt verify — against the
                            // real hash when the username matches, otherwise a
                            // dummy — so response timing doesn't reveal whether
                            // the admin username is correct (user enumeration).
                            let verify_hash = if user_ok {
                                hash.as_str()
                            } else {
                                crate::auth::dummy_hash()
                            };
                            let pass_ok = crate::auth::verify_password(p, verify_hash);
                            if user_ok && pass_ok {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

/// Extract route index from path like /api/v1/routes/3
fn extract_route_index(path: &str) -> Option<usize> {
    path.strip_prefix("/api/v1/routes/")
        .and_then(|s| s.parse::<usize>().ok())
}

/// Inject `X-Forwarded-{For,Proto,Host}` so the bundled `_admin` Rails app
/// sees the real client IP and can render correct URLs. Always sets
/// `X-Forwarded-Proto: http` because the admin server itself is plaintext;
/// operators who terminate TLS in front of it can rewrite at the terminator.
fn inject_forwarding_headers(headers: &mut hyper::HeaderMap, peer: Option<SocketAddr>) {
    use hyper::header::HeaderValue;
    let xff = peer.map(|a| a.ip().to_string()).unwrap_or_default();
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("X-Forwarded-For", v);
    }
    headers.insert("X-Forwarded-Proto", HeaderValue::from_static("http"));
    if let Some(host) = headers.get("host").cloned() {
        headers.insert("X-Forwarded-Host", host);
    }
}

/// Reject oversized or chunked-encoded requests before we forward them to
/// the bundled `_admin` Rails backend. `_admin` is internal but not
/// hardened against memory blow-ups, so we cap the same way the public
/// proxy does — gated on `[limits].max_request_size` being configured.
/// Returns `Some(response)` to short-circuit, `None` to continue.
fn enforce_admin_body_size_limit(
    req: &Request<Incoming>,
    max_size: Option<usize>,
) -> Option<Response<BoxBody>> {
    // Fast-path only: Content-Length already over the cap. Streaming bodies
    // without CL are enforced by `http_body_util::Limited` in the passthrough
    // / API body readers (chunked is no longer blanket-rejected).
    let max = max_size?;
    let content_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > max {
        let body = http_body_util::Full::new(Bytes::from("Payload Too Large")).boxed();
        return Some(
            Response::builder()
                .status(413)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap(),
        );
    }
    None
}

async fn handle_admin_request(
    req: Request<Incoming>,
    state: Arc<AdminState>,
    peer_addr: Option<SocketAddr>,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    // Per-IP rate limit applied BEFORE auth so a rejected client can't
    // burn bcrypt rounds by replaying a wrong password under the limit.
    if let (Some(limiter), Some(peer)) = (state.rate_limiter.as_ref(), peer_addr) {
        if limiter.check_key(&peer.ip()).is_err() {
            let body =
                http_body_util::Full::new(Bytes::from_static(b"Rate limit exceeded")).boxed();
            return Ok(Response::builder()
                .status(429)
                .header("Retry-After", "1")
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    }

    let admin_config = &state.config_manager.get_config().admin;
    let api_key = admin_config.api_key.clone();
    let username = admin_config.username.clone();
    let password_hash = admin_config.password_hash.clone();
    let use_basic_auth = username.is_some() && password_hash.is_some();
    if !check_auth(&req, &api_key, &username, &password_hash) {
        return Ok(unauthorized_response(use_basic_auth));
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = match (method.clone(), path.as_str()) {
        // CORS is intentionally not enabled on the admin API. Browsers send
        // OPTIONS as a preflight; without `Access-Control-Allow-Origin` they
        // will fail the cross-origin request. Returning 405 directly avoids
        // proxying the preflight to the bundled _admin app.
        (Method::OPTIONS, _) => error_response(405, "Method not allowed"),

        // Phase 1: Read-only endpoints
        (Method::GET, "/api/v1/status") => handlers::get_status(&state).await,
        (Method::GET, "/api/v1/config") => handlers::get_config(&state),
        (Method::GET, "/api/v1/routes") => handlers::get_routes(&state),
        (Method::GET, "/api/v1/metrics") => handlers::get_metrics(&state),
        (Method::GET, "/api/v1/app-metrics") => handlers::get_all_app_metrics(&state).await,
        (Method::GET, "/api/v1/app-metrics/system") => {
            handlers::get_app_system_metrics(&state).await
        }
        (Method::GET, "/api/v1/events/apps") => handlers::sse_app_events(state.clone()).await,
        (Method::POST, "/api/v1/reload") => handlers::post_reload(&state).await,
        (Method::POST, "/api/v1/certs/reload") => handlers::post_certs_reload(&state),
        (Method::GET, "/api/v1/settings") => handlers::get_settings(&state),

        // App management endpoints
        (Method::GET, "/api/v1/apps") => handlers::get_apps(&state).await,
        (Method::GET, "/api/v1/apps/by-domain") => handlers::get_apps_by_domain(&state).await,
        (Method::GET, "/api/v1/aliases") => handlers::get_aliases(&state).await,
        (Method::GET, "/api/v1/routing-table") => handlers::get_routing_table(&state).await,
        (Method::PUT, "/api/v1/routing-table") => match read_body(req).await {
            Ok(body) => handlers::put_routing_table(&state, &body).await,
            Err(e) => error_response(400, e),
        },
        (Method::GET, "/api/v1/acme-challenges") => handlers::get_acme_challenges(&state).await,
        (Method::PUT, "/api/v1/acme-challenges") => match read_body(req).await {
            Ok(body) => handlers::put_acme_challenges(&state, &body).await,
            Err(e) => error_response(400, e),
        },
        (_, p) if p.starts_with("/api/v1/apps/") => {
            let app_name = p.strip_prefix("/api/v1/apps/").unwrap_or("");
            // Aliases are matched before the generic app routes so
            // `<name>/aliases` is not mistaken for an app called
            // `<name>/aliases`.
            if method == Method::POST && app_name.ends_with("/aliases") {
                let name = app_name.strip_suffix("/aliases").unwrap_or("").to_string();
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    let body = match read_body(req).await {
                        Ok(b) => b,
                        Err(e) => return Ok(error_response(413, e)),
                    };
                    handlers::post_app_alias(&state, &name, &body).await
                }
            } else if method == Method::DELETE && app_name.contains("/aliases/") {
                let (name, domain) = app_name.split_once("/aliases/").unwrap_or(("", ""));
                if name.is_empty() || domain.is_empty() {
                    error_response(400, "Invalid app name or alias domain")
                } else {
                    handlers::delete_app_alias(&state, name, domain).await
                }
            } else if method == Method::GET && !app_name.is_empty() && !app_name.contains('/') {
                handlers::get_app(&state, app_name).await
            } else if method == Method::GET && app_name.ends_with("/metrics") {
                let name = app_name.strip_suffix("/metrics").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::get_app_metrics(&state, name).await
                }
            } else if method == Method::POST && app_name.ends_with("/deploy") {
                let name = app_name.strip_suffix("/deploy").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_deploy(&state, name).await
                }
            } else if method == Method::POST && app_name.ends_with("/restart") {
                let name = app_name.strip_suffix("/restart").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_restart(&state, name).await
                }
            } else if method == Method::POST && app_name.ends_with("/rollback") {
                let name = app_name.strip_suffix("/rollback").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_rollback(&state, name).await
                }
            } else if method == Method::POST && app_name.ends_with("/stop") {
                let name = app_name.strip_suffix("/stop").unwrap_or("");
                if name.is_empty() {
                    error_response(400, "Invalid app name")
                } else {
                    handlers::post_app_stop(&state, name).await
                }
            } else if method == Method::GET && app_name.ends_with("/logs") {
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
            let body = match read_body(req).await {
                Ok(b) => b,
                Err(e) => return Ok(error_response(413, e)),
            };
            handlers::post_route(&state, &body)
        }
        (Method::PUT, "/api/v1/config") => {
            let body = match read_body(req).await {
                Ok(b) => b,
                Err(e) => return Ok(error_response(413, e)),
            };
            handlers::put_config(&state, &body)
        }
        (Method::PUT, "/api/v1/settings") => {
            let body = match read_body(req).await {
                Ok(b) => b,
                Err(e) => return Ok(error_response(413, e)),
            };
            handlers::put_settings(&state, &body)
        }

        // Routes with index parameter
        (Method::GET, p) if p.starts_with("/api/v1/routes/") => match extract_route_index(p) {
            Some(idx) => handlers::get_route(&state, idx),
            None => error_response(400, "Invalid route index"),
        },
        (Method::PUT, p) if p.starts_with("/api/v1/routes/") => match extract_route_index(p) {
            Some(idx) => {
                let body = match read_body(req).await {
                    Ok(b) => b,
                    Err(e) => return Ok(error_response(413, e)),
                };
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

        // Utility endpoints
        (Method::POST, "/api/v1/hash-password") => {
            let body = match read_body(req).await {
                Ok(b) => b,
                Err(e) => return Ok(error_response(413, e)),
            };
            handlers::post_hash_password(&state, &body)
        }

        // Everything else → proxy to _admin app (UI, static assets, etc.)
        _ if state.app_manager.is_some() => {
            let is_ws = req
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
            if is_ws {
                proxy_websocket_to_admin_app(req, &state, peer_addr).await
            } else {
                proxy_to_admin_app(req, &state, peer_addr).await
            }
        }
        _ => error_response(404, "Not found"),
    };

    Ok(response)
}

async fn proxy_to_admin_app(
    req: Request<Incoming>,
    state: &Arc<AdminState>,
    peer_addr: Option<SocketAddr>,
) -> Response<BoxBody> {
    let max_request_size = state.config_manager.get_config().limits.max_request_size;
    if let Some(resp) = enforce_admin_body_size_limit(&req, max_request_size) {
        return resp;
    }

    let port = match resolve_admin_port(state).await {
        Ok(p) => p,
        Err(resp) => return *resp,
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

    // Strip auth credentials before forwarding to admin app — they were already
    // validated by check_auth and do not need to propagate to the backend.
    parts.headers.remove("authorization");
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("x-api-key");

    // Strip hop-by-hop framing headers and inject forwarding identity, the
    // same shape the public proxy applies on outbound requests.
    strip_hop_by_hop(&mut parts.headers);
    crate::proxy_headers::coalesce_cookies(&mut parts.headers);
    inject_forwarding_headers(&mut parts.headers, peer_addr);

    // Buffer with a hard cap so chunked / missing-CL bodies cannot blow memory.
    let max = max_request_size.unwrap_or(MAX_ADMIN_REQUEST_BODY_SIZE);
    let limited = http_body_util::Limited::new(body, max);
    let body_bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(413)
                .header("Content-Type", "text/plain")
                .body(http_body_util::Full::new(Bytes::from("Payload Too Large")).boxed())
                .unwrap();
        }
    };
    let proxy_req = Request::from_parts(parts, http_body_util::Full::new(body_bytes));

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(std::time::Duration::from_secs(3)));

    let client: Client<HttpConnector, http_body_util::Full<Bytes>> =
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
///
/// The error is boxed because `Response<BoxBody>` dwarfs the `u16` success
/// value, and every caller immediately returns it as its own response.
async fn resolve_admin_port(state: &Arc<AdminState>) -> Result<u16, Box<Response<BoxBody>>> {
    let app_manager = match &state.app_manager {
        Some(m) => m,
        None => {
            return Err(Box::new(error_response(
                501,
                "App management not configured",
            )))
        }
    };

    let app = match app_manager.get_app("_admin").await {
        Some(a) => a,
        None => return Err(Box::new(error_response(502, "_admin app not found"))),
    };

    let port = if app.current_slot == "blue" {
        app.blue.port
    } else {
        app.green.port
    };

    if port == 0 {
        return Err(Box::new(error_response(502, "_admin app not deployed")));
    }

    Ok(port)
}

async fn proxy_websocket_to_admin_app(
    req: Request<Incoming>,
    state: &Arc<AdminState>,
    peer_addr: Option<SocketAddr>,
) -> Response<BoxBody> {
    let port = match resolve_admin_port(state).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Capture Connection-listed headers BEFORE iterating so the skip-set is
    // built before we look at the headers themselves.
    let connection_listed: Vec<String> = req
        .headers()
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Collect extra headers to forward to the backend, skipping hop-by-hop
    // and credential headers. The hop-by-hop set mirrors RFC 7230 §6.1.
    let mut extra_headers = String::new();
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        match name_str {
            "host"
            | "upgrade"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "authorization"
            | "x-api-key"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host" => continue,
            _ => {}
        }
        if connection_listed.iter().any(|n| n == name_str) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            extra_headers.push_str(&format!("{}: {}\r\n", name_str, v));
        }
    }

    // Inject forwarding identity for the bundled _admin Rails app.
    if let Some(peer) = peer_addr {
        extra_headers.push_str(&format!("X-Forwarded-For: {}\r\n", peer.ip()));
    }
    extra_headers.push_str("X-Forwarded-Proto: http\r\n");
    if let Some(host) = req.headers().get("host").and_then(|v| v.to_str().ok()) {
        extra_headers.push_str(&format!("X-Forwarded-Host: {}\r\n", host));
    }

    // Connect to the backend
    let backend = match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to _admin backend for WebSocket: {}", e);
            return error_response(502, "Admin app not reachable");
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
    handshake.push_str(&extra_headers);
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

    // Check for trailing WebSocket data after the HTTP response headers
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

    // Snapshot WS limits from the shared config — same defaults as the proxy
    // path so a single [limits] section governs both.
    let limits = &state.config_manager.get_config().limits;
    let ws_idle = std::time::Duration::from_secs(limits.websocket_idle_timeout_secs.unwrap_or(300));
    let ws_lifetime =
        std::time::Duration::from_secs(limits.websocket_max_lifetime_secs.unwrap_or(3600));
    let ws_max_bytes = limits
        .websocket_max_bytes_per_direction
        .unwrap_or(1_073_741_824);
    let ws_deadline = std::time::Instant::now() + ws_lifetime;

    // Spawn the bidirectional copy task
    tokio::spawn(async move {
        match client_upgrade.await {
            Ok(upgraded) => {
                let mut client_stream = TokioIo::new(upgraded);
                let (br, bw) = tokio::io::split(backend_stream);
                let (cr, mut cw) = tokio::io::split(&mut client_stream);

                // Forward any trailing WebSocket data captured in the 101 read
                if let Some(data) = trailing_data {
                    if tokio::io::AsyncWriteExt::write_all(&mut cw, &data)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                // Admin traffic is not counted toward proxy byte metrics.
                tokio::select! {
                    _ = crate::server::forward_ws_half(br, cw, ws_idle, ws_deadline, ws_max_bytes, None) => {},
                    _ = crate::server::forward_ws_half(cr, bw, ws_idle, ws_deadline, ws_max_bytes, None) => {},
                }
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

const MAX_ADMIN_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1MB

async fn read_body(req: Request<Incoming>) -> Result<String, &'static str> {
    let body = req.into_body();
    let limited = http_body_util::Limited::new(body, MAX_ADMIN_REQUEST_BODY_SIZE);
    match limited.collect().await {
        Ok(collected) => Ok(String::from_utf8_lossy(&collected.to_bytes()).to_string()),
        Err(e) if e.to_string().contains("body size limit") => Err("413 Payload Too Large"),
        Err(_) => Ok(String::new()),
    }
}

/// True when at least one credential is configured (non-empty key or
/// both username + password_hash). Empty strings count as unset.
fn admin_auth_configured(
    api_key: &Option<String>,
    username: &Option<String>,
    password_hash: &Option<String>,
) -> bool {
    if api_key.as_deref().is_some_and(|k| !k.is_empty()) {
        return true;
    }
    matches!(
        (username.as_deref(), password_hash.as_deref()),
        (Some(u), Some(h)) if !u.is_empty() && !h.is_empty()
    )
}

pub async fn run_admin_server(state: Arc<AdminState>) -> Result<()> {
    let admin_cfg = state.config_manager.get_config().admin.clone();
    let bind = admin_cfg.bind.clone();
    let addr: std::net::SocketAddr = bind.parse()?;

    // Warn when admin API is exposed on non-loopback without TLS.
    // Credentials (Basic-auth password or API key) transit in cleartext over HTTP.
    if !addr.ip().is_loopback() {
        tracing::warn!(
            "Admin API is listening on a non-loopback address {} — \
             HTTP Basic-auth passwords and API keys transit unencrypted. \
             Bind to 127.0.0.1 or use a TLS-terminating proxy (e.g. ssh -L, nginx, haproxy).",
            addr
        );
    }

    // Fail closed: refuse to expose the admin API on a non-loopback address
    // unless an api_key or username+password_hash is configured. Without auth,
    // any host that can reach the bind address gets full read/write access to
    // routes, config, and app deploys.
    if !addr.ip().is_loopback()
        && !admin_auth_configured(
            &admin_cfg.api_key,
            &admin_cfg.username,
            &admin_cfg.password_hash,
        )
    {
        anyhow::bail!(
            "refusing to start admin API on non-loopback address {} without authentication; \
             set [admin].api_key or [admin].username + password_hash, or bind to 127.0.0.1",
            addr
        );
    }

    // Loopback without auth is allowed for local dev, but any other process on
    // the host can call deploy/stop/config — warn so operators enable auth.
    if addr.ip().is_loopback()
        && !admin_auth_configured(
            &admin_cfg.api_key,
            &admin_cfg.username,
            &admin_cfg.password_hash,
        )
    {
        tracing::warn!(
            "Admin API on {} has no authentication configured — any local process can deploy, \
             stop apps, and edit routes. Set ADMIN_USER/ADMIN_PASSWORD (bcrypt hash) or [admin].api_key.",
            addr
        );
    }

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind admin API to {addr}"))?;

    tracing::info!("Admin API listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                let peer_addr = stream.peer_addr().ok();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        async move { handle_admin_request(req, state, peer_addr).await }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_inputs() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_rejects_different_inputs() {
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"Abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"zbcdef"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn auth_configured_recognizes_api_key() {
        assert!(admin_auth_configured(&Some("secret".into()), &None, &None,));
    }

    #[test]
    fn auth_configured_treats_empty_api_key_as_unset() {
        assert!(!admin_auth_configured(&Some("".into()), &None, &None));
    }

    #[test]
    fn auth_configured_requires_both_user_and_hash() {
        assert!(!admin_auth_configured(&None, &Some("admin".into()), &None));
        assert!(!admin_auth_configured(
            &None,
            &None,
            &Some("$2b$12$abc".into()),
        ));
        assert!(admin_auth_configured(
            &None,
            &Some("admin".into()),
            &Some("$2b$12$abc".into()),
        ));
    }

    #[test]
    fn auth_configured_returns_false_when_all_unset() {
        assert!(!admin_auth_configured(&None, &None, &None));
    }
}
