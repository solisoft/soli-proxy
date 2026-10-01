pub mod handlers;

use crate::app::AppManager;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::proxy_headers::strip_hop_by_hop;
use crate::server::{client_key, IpRateLimiter};
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

use crate::pool::BoxError;
use crate::server::{empty, full, BoxBody};

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
        .body(full(bytes))
        .unwrap()
}

fn ok_response(data: serde_json::Value) -> Response<BoxBody> {
    json_response(200, serde_json::json!({ "ok": true, "data": data }))
}

fn created_response(data: serde_json::Value) -> Response<BoxBody> {
    json_response(201, serde_json::json!({ "ok": true, "data": data }))
}

fn no_content_response() -> Response<BoxBody> {
    Response::builder().status(204).body(empty()).unwrap()
}

fn error_response(status: u16, message: &str) -> Response<BoxBody> {
    json_response(status, serde_json::json!({ "ok": false, "error": message }))
}

fn unauthorized_response(use_basic_auth: bool) -> Response<BoxBody> {
    let body = full(Bytes::from("Unauthorized"));
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

/// How a request got past `check_auth`. The dispatcher branches on this:
/// Basic credentials are cached and replayed by the browser on any request
/// to the origin, so only that path needs the cross-site checks below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthMethod {
    /// No credential is configured at all.
    Open,
    ApiKey,
    Basic,
}

/// What `check_auth` concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthOutcome {
    Allowed(AuthMethod),
    /// No credential, or a wrong one.
    Denied,
    /// The bcrypt pool stayed saturated: the credential was not checked.
    Busy,
    /// The client is over its failed-attempt budget and the credential could
    /// not be accepted without running bcrypt (see `AuthFailures`).
    Throttled,
}

/// Authenticate an admin request.
///
/// Not an `async fn`: everything it needs is copied out of the request first,
/// so the returned future borrows nothing — the request's body type need not be
/// `Sync` for the handler's future to stay `Send`. The API key is compared
/// right here (it is a plain constant-time compare); only the Basic path
/// awaits, because it runs bcrypt on the bounded blocking pool and remembers
/// successes, exactly like route auth (`auth::verify_basic`). It used to run
/// bcrypt inline on a tokio worker on every request — a polling TUI paid
/// ~250 ms per refresh, and a password-guessing loop could stall the runtime
/// the whole proxy shares.
///
/// `throttled` is set for a client over its failure budget: bcrypt is then not
/// run at all, but a matching API key or a Basic credential still in the
/// success cache is let through — an operator who is already logged in keeps
/// working while someone else hammers the same address (every client looks
/// like `127.0.0.1` when the admin API is published through a local route).
fn check_auth<B>(
    req: &Request<B>,
    api_key: &Option<String>,
    username: &Option<String>,
    password_hash: &Option<String>,
    throttled: bool,
) -> impl std::future::Future<Output = AuthOutcome> + Send + 'static {
    // The same notion of "configured" as the bind-time guard: config loading
    // drops empty credentials, and this keeps the two in step regardless.
    let configured = admin_auth_configured(api_key, username, password_hash);

    let key_ok = api_key.as_deref().is_some_and(|key| {
        !key.is_empty()
            && req
                .headers()
                .get("X-Api-Key")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| constant_time_eq(v.as_bytes(), key.as_bytes()))
    });

    let account = match (username, password_hash) {
        (Some(user), Some(hash)) if !user.is_empty() && !hash.is_empty() => {
            Some(crate::auth::BasicAuth {
                username: user.clone(),
                hash: hash.clone(),
            })
        }
        _ => None,
    };
    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    async move {
        if !configured {
            return AuthOutcome::Allowed(AuthMethod::Open);
        }
        if key_ok {
            return AuthOutcome::Allowed(AuthMethod::ApiKey);
        }
        let Some(account) = account else {
            return if throttled {
                AuthOutcome::Throttled
            } else {
                AuthOutcome::Denied
            };
        };
        if throttled {
            let remembered = authorization.as_deref().is_some_and(|header| {
                crate::auth::is_remembered(std::slice::from_ref(&account), header)
            });
            return if remembered {
                AuthOutcome::Allowed(AuthMethod::Basic)
            } else {
                AuthOutcome::Throttled
            };
        }
        match crate::auth::verify_basic(std::slice::from_ref(&account), authorization.as_deref())
            .await
        {
            crate::auth::Verdict::Granted => AuthOutcome::Allowed(AuthMethod::Basic),
            crate::auth::Verdict::Denied => AuthOutcome::Denied,
            crate::auth::Verdict::Busy => AuthOutcome::Busy,
        }
    }
}

/// Whether the request carried a credential at all. Only those count as
/// failed attempts: a browser's first, credential-less hit (the one that gets
/// the 401 and opens the password prompt) is not a guess.
fn presents_credential<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(hyper::header::AUTHORIZATION)
        || req.headers().contains_key("X-Api-Key")
}

/// Failed admin authentications allowed per client IP within one window.
const MAX_AUTH_FAILURES: u32 = 10;
/// The window `MAX_AUTH_FAILURES` is counted over, and how long an IP that
/// exhausted it waits.
const AUTH_FAILURE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Tracked IPs above which expired entries are swept (and, if that is not
/// enough, everything is forgotten — the cheapest sane answer to a flood from
/// spoofed-looking address space).
const AUTH_FAILURE_CAPACITY: usize = 10_000;

/// Per-IP budget of **failed** admin authentications.
///
/// The general `[rate_limiting]` limiter is shared with the proxy, sized for
/// traffic (1000 rps by default) and off unless configured, so it never stood
/// between a password guesser and the admin credential. This one is always on
/// and counts only failures: a correct credential never consumes it, so the
/// TUI and CLI can poll as fast as they like, while a guessing loop gets
/// `MAX_AUTH_FAILURES` tries a minute — and is answered 429 *before* bcrypt
/// runs, so the guesses stop costing CPU too.
struct AuthFailures {
    by_ip: parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>,
}

impl AuthFailures {
    fn global() -> &'static AuthFailures {
        static FAILURES: std::sync::LazyLock<AuthFailures> =
            std::sync::LazyLock::new(|| AuthFailures {
                by_ip: parking_lot::Mutex::new(std::collections::HashMap::new()),
            });
        &FAILURES
    }

    /// Seconds until `ip` may try again, or `None` when it may now.
    fn blocked_for(&self, ip: std::net::IpAddr, now: Instant) -> Option<u64> {
        let by_ip = self.by_ip.lock();
        let (count, since) = by_ip.get(&ip)?;
        let elapsed = now.saturating_duration_since(*since);
        if *count >= MAX_AUTH_FAILURES && elapsed < AUTH_FAILURE_WINDOW {
            Some((AUTH_FAILURE_WINDOW - elapsed).as_secs().max(1))
        } else {
            None
        }
    }

    fn record(&self, ip: std::net::IpAddr, now: Instant) {
        let mut by_ip = self.by_ip.lock();
        if by_ip.len() >= AUTH_FAILURE_CAPACITY {
            by_ip.retain(|_, (_, since)| {
                now.saturating_duration_since(*since) < AUTH_FAILURE_WINDOW
            });
            if by_ip.len() >= AUTH_FAILURE_CAPACITY {
                by_ip.clear();
            }
        }
        let entry = by_ip.entry(ip).or_insert((0, now));
        if now.saturating_duration_since(entry.1) >= AUTH_FAILURE_WINDOW {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
    }
}

/// Whether `host` (a `Host` header value) names this loopback listener.
///
/// **DNS rebinding.** With no credential configured, the admin API trusts
/// whatever reaches `127.0.0.1:9090` — and a web page can reach it: its
/// attacker-controlled hostname first resolves to the attacker's server, then,
/// once the page is loaded, to `127.0.0.1`. The browser treats both as the
/// same origin, so the page can read and write the admin API with no
/// credential to steal. What it cannot change is the `Host` header, which
/// still carries the attacker's name. So the open admin API answers only
/// requests addressed to a loopback name: `localhost`, a loopback IP literal
/// (`127.0.0.1`, `[::1]`), or the bound address, each with an optional port.
/// A request with no `Host` at all (HTTP/1.0 tooling; never a browser) passes.
fn is_loopback_host(host: &str, bound: SocketAddr) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        // `[v6]` or `[v6]:port`
        match rest.split_once(']') {
            Some((ip, port)) if port.is_empty() || is_port_suffix(port) => ip,
            _ => return false,
        }
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) if is_port_suffix(&format!(":{port}")) => name,
            Some(_) => return false,
            None => host,
        }
    };
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match name.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip == bound.ip(),
        Err(_) => false,
    }
}

/// `:` followed by one to five digits.
fn is_port_suffix(s: &str) -> bool {
    s.strip_prefix(':')
        .is_some_and(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Cross-site request check for Basic-authenticated mutations.
///
/// The browser attaches cached Basic credentials to any request it makes to
/// this origin, including one a hostile page triggers with a `text/plain`
/// form post — which needs no preflight and carries a body serde_json will
/// happily parse. Two things a form cannot do: set a custom header, and lie
/// about `Sec-Fetch-Site`. So a mutation must carry `X-Requested-With`
/// (any value — a cross-origin `fetch` that sets it triggers a preflight,
/// and OPTIONS answers 405), and if the browser sent `Sec-Fetch-Site` it
/// must say the request is same-origin or user-initiated.
///
/// Applies to every credential a browser can supply on its own: cached
/// Basic auth, and the no-auth loopback default (where a page can form-post
/// to `127.0.0.1:9090` with nothing at all). An `X-Api-Key` caller is exempt:
/// a browser never attaches that header by itself. The TUI and CLI send
/// `X-Requested-With` unconditionally so they work in every mode.
fn is_cross_site_mutation<B>(req: &Request<B>, method: AuthMethod) -> bool {
    if method == AuthMethod::ApiKey {
        return false;
    }
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    if req.headers().get("x-requested-with").is_none() {
        return true;
    }
    match req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        None => false,
        Some(site) => {
            !(site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none"))
        }
    }
}

/// Extract route index from path like /api/v1/routes/3
fn extract_route_index(path: &str) -> Option<usize> {
    path.strip_prefix("/api/v1/routes/")
        .and_then(|s| s.parse::<usize>().ok())
}

/// Give the bundled `_admin` app the proxy's view of the client, through the
/// same `set_forwarding_headers` the public proxy uses: every client-supplied
/// `Forwarded` / `X-Forwarded-*` / `X-Real-IP` is dropped (this function used
/// to overwrite three of them and relay `X-Real-IP` and the rest verbatim),
/// then `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto` and
/// `X-Forwarded-Host` are set. The proto is `http` because the admin server
/// itself is plaintext — unless the request came through a proxy listed in
/// `[server] trusted_proxies` (the public proxy itself, typically, when the
/// admin API is published through a route), whose chain and scheme are kept
/// (see `set_forwarding_headers_for`).
fn inject_forwarding_headers(
    headers: &mut hyper::HeaderMap,
    client: Option<&crate::edge::ClientInfo>,
) {
    let host = headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    crate::proxy_headers::set_forwarding_headers_for(headers, client, false, host.as_deref());
}

/// Who the client is (see `crate::edge::ClientInfo`), as `handle_admin_request`
/// decided, or the peer.
fn admin_client(
    ext: &http::Extensions,
    peer_addr: Option<SocketAddr>,
) -> Option<crate::edge::ClientInfo> {
    crate::edge::client_info(ext)
        .copied()
        .or_else(|| peer_addr.map(|a| crate::edge::ClientInfo::direct(a.ip())))
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
        let body = full(Bytes::from("Payload Too Large"));
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
    mut req: Request<Incoming>,
    state: Arc<AdminState>,
    peer_addr: Option<SocketAddr>,
    bound_addr: SocketAddr,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    // The client is the peer, or — when the admin API is reached through a
    // proxy listed in `[server] trusted_proxies` — the client that proxy
    // names. Budgets below are charged to it.
    if let Some(peer) = peer_addr {
        let config = state.config_manager.get_config();
        let who = crate::edge::ClientInfo::resolve(peer.ip(), req.headers(), &config.server.edge);
        req.extensions_mut().insert(who);
    }
    let client_info = admin_client(req.extensions(), peer_addr);

    // Per-IP rate limit applied BEFORE auth so a rejected client can't
    // burn bcrypt rounds by replaying a wrong password under the limit.
    if let (Some(limiter), Some(who)) = (state.rate_limiter.as_ref(), client_info) {
        if limiter.check_key(&client_key(who.ip)).is_err() {
            let body = full(Bytes::from_static(b"Rate limit exceeded"));
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

    // `run_admin_server` refuses to start on a non-loopback address without
    // a credential, but the config is hot-reloaded and the listener is not:
    // if a reload ever produced an auth-less config while we are bound to a
    // reachable address, deny everything rather than open up.
    if !bound_addr.ip().is_loopback() && !admin_auth_configured(&api_key, &username, &password_hash)
    {
        tracing::error!(
            "Admin API on {} has no credential configured; refusing request",
            bound_addr
        );
        return Ok(error_response(503, "admin auth not configured"));
    }

    // DNS rebinding: see `is_loopback_host`. Only the open (credential-less)
    // API needs it — with a credential configured, a rebinding page has none
    // to send, since the browser keys cached Basic credentials by origin and
    // never invents an `X-Api-Key`. Applying it there too would break an
    // operator who publishes a protected admin API through a named route.
    if bound_addr.ip().is_loopback() && !admin_auth_configured(&api_key, &username, &password_hash)
    {
        let host_ok = match req.headers().get(hyper::header::HOST) {
            None => true,
            Some(host) => host
                .to_str()
                .is_ok_and(|host| is_loopback_host(host, bound_addr)),
        };
        if !host_ok {
            return Ok(error_response(
                403,
                "the unauthenticated admin API only answers requests addressed to localhost",
            ));
        }
    }

    // Failed-credential budget, checked before bcrypt runs (see `AuthFailures`).
    // Keyed like every other per-client budget: an IPv6 client per /64, or a
    // guesser would get a fresh budget from each of its 2^64 addresses.
    let client = client_info.map(|who| client_key(who.ip));
    let blocked_for = client.and_then(|ip| AuthFailures::global().blocked_for(ip, Instant::now()));

    let auth_method = match check_auth(
        &req,
        &api_key,
        &username,
        &password_hash,
        blocked_for.is_some(),
    )
    .await
    {
        AuthOutcome::Allowed(method) => method,
        AuthOutcome::Denied => {
            if let Some(ip) = client {
                if presents_credential(&req) {
                    AuthFailures::global().record(ip, Instant::now());
                }
            }
            return Ok(unauthorized_response(use_basic_auth));
        }
        AuthOutcome::Throttled => {
            let body = full(Bytes::from_static(
                b"Too many failed authentication attempts",
            ));
            return Ok(Response::builder()
                .status(429)
                .header("Retry-After", blocked_for.unwrap_or(1).to_string())
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
        AuthOutcome::Busy => {
            let body = full(Bytes::from_static(
                b"Authentication temporarily unavailable",
            ));
            return Ok(Response::builder()
                .status(503)
                .header("Retry-After", "1")
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    };

    if is_cross_site_mutation(&req, auth_method) {
        return Ok(error_response(403, "cross-site request rejected"));
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
            handlers::post_hash_password(&state, &body).await
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
    let client_info = admin_client(&parts.extensions, peer_addr);
    inject_forwarding_headers(&mut parts.headers, client_info.as_ref());

    // Buffer with a hard cap so chunked / missing-CL bodies cannot blow memory.
    let max = max_request_size.unwrap_or(MAX_ADMIN_REQUEST_BODY_SIZE);
    let limited = http_body_util::Limited::new(body, max);
    let body_bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(413)
                .header("Content-Type", "text/plain")
                .body(full(Bytes::from("Payload Too Large")))
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
            let mapped = body.map_err(BoxError::from);
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
            | "x-api-key" => continue,
            _ => {}
        }
        if crate::proxy_headers::is_forwarding_header(name_str)
            || connection_listed.iter().any(|n| n == name_str)
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            extra_headers.push_str(&format!("{}: {}\r\n", name_str, v));
        }
    }

    // Inject forwarding identity for the bundled _admin Rails app — the same
    // set as a plain request (see `inject_forwarding_headers`).
    let mut forwarding = hyper::HeaderMap::new();
    if let Some(host) = req.headers().get(hyper::header::HOST) {
        forwarding.insert(hyper::header::HOST, host.clone());
    }
    let client_info = admin_client(req.extensions(), peer_addr);
    if client_info.is_some_and(|who| who.trusted_peer) {
        // A trusted proxy's chain and scheme are kept (and appended to).
        for name in ["x-forwarded-for", "x-forwarded-proto"] {
            for v in req.headers().get_all(name) {
                forwarding.append(name, v.clone());
            }
        }
    }
    inject_forwarding_headers(&mut forwarding, client_info.as_ref());
    for (name, value) in &forwarding {
        if name == hyper::header::HOST {
            continue;
        }
        if let Ok(v) = value.to_str() {
            extra_headers.push_str(&format!("{}: {}\r\n", name, v));
        }
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
    let Some((accept_key, resp_protocol)) =
        crate::server::ws_upgrade_response_headers(&response_str)
    else {
        tracing::error!("_admin sent WebSocket upgrade headers that are not valid header values");
        return error_response(502, "Backend rejected WebSocket upgrade");
    };

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
    resp.body(empty()).unwrap()
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
             set [admin].api_key in config.toml or the ADMIN_USER + ADMIN_PASSWORD_HASH \
             environment variables, or bind to 127.0.0.1",
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

    // A hash bcrypt should not run (malformed, or a cost outside 4..=13) is
    // never verified, so Basic login would fail with no explanation. Say why.
    if let Some(hash) = admin_cfg.password_hash.as_deref().filter(|h| !h.is_empty()) {
        if let Err(e) = crate::auth::validate_hash(hash) {
            tracing::error!(
                "ADMIN_PASSWORD_HASH is unusable ({}); Basic login to the admin API will be \
                 refused. Regenerate it with `hash-password`.",
                e
            );
        }
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
                        async move { handle_admin_request(req, state, peer_addr, addr).await }
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

    fn request(method: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().method(method).uri("/api/v1/reload");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[tokio::test]
    async fn check_auth_reports_which_credential_matched() {
        let key = Some("k".to_string());
        assert_eq!(
            check_auth(&request("GET", &[]), &None, &None, &None, false).await,
            AuthOutcome::Allowed(AuthMethod::Open)
        );
        assert_eq!(
            check_auth(
                &request("GET", &[("X-Api-Key", "k")]),
                &key,
                &None,
                &None,
                false
            )
            .await,
            AuthOutcome::Allowed(AuthMethod::ApiKey)
        );
        assert_eq!(
            check_auth(
                &request("GET", &[("X-Api-Key", "x")]),
                &key,
                &None,
                &None,
                false
            )
            .await,
            AuthOutcome::Denied
        );
    }

    #[tokio::test]
    async fn check_auth_verifies_basic_credentials_at_their_own_cost() {
        let user = Some("admin".to_string());
        let hash = Some(crate::auth::hash_password("pw", 4));
        let header = |creds: &str| {
            format!(
                "Basic {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, creds)
            )
        };
        let good = header("admin:pw");
        let bad = header("admin:nope");
        let check = |authorization: &str, throttled: bool| {
            check_auth(
                &request("GET", &[("Authorization", authorization)]),
                &None,
                &user,
                &hash,
                throttled,
            )
        };

        // Throttled before any success: bcrypt does not run, nothing gets in.
        assert_eq!(check(&good, true).await, AuthOutcome::Throttled);
        assert_eq!(
            check(&good, false).await,
            AuthOutcome::Allowed(AuthMethod::Basic)
        );
        assert_eq!(check(&bad, false).await, AuthOutcome::Denied);
        // Throttled after a success: the remembered session keeps working,
        // the guess is refused without bcrypt.
        assert_eq!(
            check(&good, true).await,
            AuthOutcome::Allowed(AuthMethod::Basic)
        );
        assert_eq!(check(&bad, true).await, AuthOutcome::Throttled);
    }

    /// An empty credential is "unset" for `check_auth` exactly as it is for
    /// `admin_auth_configured`: `api_key = ""` must not produce a server that
    /// logs "no authentication configured" and then 401s every request, and
    /// an empty user/hash pair must not accept `Basic Og==`.
    #[tokio::test]
    async fn check_auth_treats_empty_credentials_as_unset() {
        let empty = Some(String::new());
        assert_eq!(
            check_auth(&request("GET", &[]), &empty, &None, &None, false).await,
            AuthOutcome::Allowed(AuthMethod::Open)
        );
        assert_eq!(
            check_auth(&request("GET", &[]), &empty, &empty, &empty, false).await,
            AuthOutcome::Allowed(AuthMethod::Open)
        );
        // Only a complete Basic pair counts, and an empty key never matches.
        let key = Some("k".to_string());
        assert_eq!(
            check_auth(
                &request("GET", &[("X-Api-Key", "")]),
                &key,
                &empty,
                &None,
                false
            )
            .await,
            AuthOutcome::Denied
        );
    }

    #[test]
    fn only_loopback_names_reach_the_open_admin_api() {
        let bound: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        for ok in [
            "127.0.0.1",
            "127.0.0.1:9090",
            "localhost",
            "LOCALHOST:9090",
            "[::1]",
            "[::1]:9090",
            "127.0.0.2:80",
        ] {
            assert!(is_loopback_host(ok, bound), "{ok}");
        }
        // Ce que montre une page en rebinding DNS : son propre nom.
        for bad in [
            "attacker.example",
            "attacker.example:9090",
            "localhost.attacker.example",
            "127.0.0.1.nip.io:9090",
            "10.0.0.1:9090",
            "[::1]x",
            "localhost:abc",
            "",
        ] {
            assert!(!is_loopback_host(bad, bound), "{bad}");
        }
        // The bound address itself, even when it is not 127.0.0.1.
        let other: SocketAddr = "[::1]:9090".parse().unwrap();
        assert!(is_loopback_host("[::1]:9090", other));
    }

    #[test]
    fn admin_passthrough_forwarding_headers_are_the_proxys() {
        let mut h = hyper::HeaderMap::new();
        h.insert("host", "admin.example:9090".parse().unwrap());
        h.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        h.insert("forwarded", "for=127.0.0.1".parse().unwrap());
        h.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        h.insert("x-forwarded-port", "443".parse().unwrap());
        let peer: SocketAddr = "198.51.100.9:5555".parse().unwrap();
        inject_forwarding_headers(&mut h, Some(&crate::edge::ClientInfo::direct(peer.ip())));
        assert_eq!(h["x-forwarded-for"], "198.51.100.9");
        assert_eq!(h["x-real-ip"], "198.51.100.9");
        assert_eq!(h["x-forwarded-proto"], "http");
        assert_eq!(h["x-forwarded-host"], "admin.example:9090");
        assert!(h.get("forwarded").is_none());
        assert!(h.get("x-forwarded-port").is_none());
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
    }

    #[test]
    fn failed_attempts_are_budgeted_per_ip_and_forgotten_after_the_window() {
        let failures = AuthFailures {
            by_ip: parking_lot::Mutex::new(std::collections::HashMap::new()),
        };
        let ip: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let other: std::net::IpAddr = "192.0.2.8".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..MAX_AUTH_FAILURES - 1 {
            failures.record(ip, t0);
        }
        assert_eq!(failures.blocked_for(ip, t0), None);
        failures.record(ip, t0);
        assert!(failures.blocked_for(ip, t0).is_some());
        assert_eq!(failures.blocked_for(other, t0), None, "per IP, not global");
        let later = t0 + AUTH_FAILURE_WINDOW;
        assert_eq!(failures.blocked_for(ip, later), None);
        failures.record(ip, later);
        assert_eq!(failures.blocked_for(ip, later), None, "the count restarted");
    }

    #[test]
    fn basic_auth_mutation_without_x_requested_with_is_cross_site() {
        // Exactly what a hostile page's text/plain form post looks like:
        // cached Basic credentials, no custom header.
        assert!(is_cross_site_mutation(
            &request("POST", &[]),
            AuthMethod::Basic
        ));
        assert!(!is_cross_site_mutation(
            &request("POST", &[("X-Requested-With", "soli-admin")]),
            AuthMethod::Basic
        ));
    }

    #[test]
    fn basic_auth_mutation_honours_sec_fetch_site() {
        let same = [("X-Requested-With", "x"), ("Sec-Fetch-Site", "same-origin")];
        let none = [("X-Requested-With", "x"), ("Sec-Fetch-Site", "none")];
        let cross = [("X-Requested-With", "x"), ("Sec-Fetch-Site", "cross-site")];
        let same_site = [("X-Requested-With", "x"), ("Sec-Fetch-Site", "same-site")];
        assert!(!is_cross_site_mutation(
            &request("PUT", &same),
            AuthMethod::Basic
        ));
        assert!(!is_cross_site_mutation(
            &request("PUT", &none),
            AuthMethod::Basic
        ));
        assert!(is_cross_site_mutation(
            &request("PUT", &cross),
            AuthMethod::Basic
        ));
        assert!(is_cross_site_mutation(
            &request("DELETE", &same_site),
            AuthMethod::Basic
        ));
    }

    #[test]
    fn reads_and_non_basic_callers_are_never_cross_site() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert!(!is_cross_site_mutation(
                &request(method, &[]),
                AuthMethod::Basic
            ));
        }
        // X-Api-Key is never attached by a browser on its own.
        assert!(!is_cross_site_mutation(
            &request("POST", &[]),
            AuthMethod::ApiKey
        ));
        // The open loopback default has no credential for a page to steal,
        // but a form post needs none — so it is gated like Basic.
        assert!(is_cross_site_mutation(
            &request("POST", &[]),
            AuthMethod::Open
        ));
        assert!(!is_cross_site_mutation(
            &request("POST", &[("X-Requested-With", "soli-cli")]),
            AuthMethod::Open
        ));
    }
}
