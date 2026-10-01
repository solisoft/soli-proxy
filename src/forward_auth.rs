//! Forward authentication: let an external service decide whether a request
//! may reach its route or app.
//!
//! The model is Traefik's ForwardAuth, nginx's `auth_request` and Caddy's
//! `forward_auth`: before proxying, the proxy asks an auth service — an
//! oauth2-proxy, Authelia, Authentik, a Soli app — with a bodiless `GET` that
//! carries the client's credentials (`Cookie`, `Authorization`) and a
//! description of the request (`X-Forwarded-Method`, `-Proto`, `-Host`,
//! `-Uri`, `-For`). The service answers:
//!
//! - **2xx** — let it through. The response headers the route names
//!   (`X-Auth-User`, `X-Auth-Email`, …) are copied onto the upstream request;
//! - **anything else** — a 401, a 403, a 302 to the login page: that response
//!   (status, headers — `Location`, `Set-Cookie` — and body, capped) is what
//!   the client gets, and the upstream is never contacted;
//! - **no answer** (refused, reset, timeout) — 503. Fail closed: a request is
//!   never let through because the gatekeeper was away.
//!
//! ⚠️ **The copied header names are stripped from the client's request on
//! every request, before anything else**, whatever the auth service answers
//! and even on a `@noauth` carve-out. The upstream trusts `X-Auth-User`
//! precisely because only the auth service can set it; a client sending its
//! own copy must not have it survive next to (or instead of) the real one.
//!
//! No verdict is cached: a session revoked at the auth service stops working
//! on the very next request. The subrequest goes through the proxy's shared
//! upstream connection pool, so a busy route keeps its connections to the
//! auth service alive instead of paying a handshake per request.

use crate::pool::ProxyClient;
use crate::server::{empty, full, BoxBody};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Body as _;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};

/// How long the auth service has to answer, body included, when
/// `[forward_auth] timeout_secs` is unset.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest auth-service response body relayed to the client on a denial (a
/// login page, a JSON error). A bigger one is dropped: the status and the
/// headers — `Location`, `Set-Cookie` — still go out, with an empty body.
pub const MAX_RESPONSE_BODY: usize = 64 * 1024;

/// How many response headers one route or app may copy upstream.
const MAX_COPY_HEADERS: usize = 32;

static X_FORWARDED_METHOD: HeaderName = HeaderName::from_static("x-forwarded-method");
static X_FORWARDED_URI: HeaderName = HeaderName::from_static("x-forwarded-uri");

/// The client request headers the auth service is shown, besides the
/// `X-Forwarded-Method` / `X-Forwarded-Uri` the proxy writes.
///
/// The credentials (`Cookie`, `Authorization`), what Authelia and Authentik
/// read to choose between a 401 and a redirect (`Accept`,
/// `X-Requested-With`), and the forwarding headers — which are the proxy's
/// own by the time this runs (`set_forwarding_headers` replaced the client's
/// at the door), so the auth service can trust them as much as a backend
/// does. Nothing else: the request body, its framing and the rest of the
/// client's headers are none of the auth service's business.
static FORWARDED_REQUEST_HEADERS: [HeaderName; 9] = [
    header::COOKIE,
    header::AUTHORIZATION,
    header::ACCEPT,
    header::USER_AGENT,
    HeaderName::from_static("x-requested-with"),
    HeaderName::from_static("x-forwarded-for"),
    HeaderName::from_static("x-forwarded-proto"),
    HeaderName::from_static("x-forwarded-host"),
    HeaderName::from_static("x-real-ip"),
];

/// `[forward_auth]` in `config.toml`. Every key is optional.
///
/// ```toml
/// [forward_auth]
/// timeout_secs = 5
/// # multi_tenant only: the auth services an app.infos may name.
/// allowed_urls = ["http://auth.internal:4180/oauth2/auth", "http://sso.internal:9091/api/"]
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ForwardAuthSettings {
    /// Seconds the auth service has to answer (connect, headers and the body
    /// of a denial). Unset or 0: 5. Read per request, so a reload applies it.
    pub timeout_secs: Option<u64>,
    /// In `[apps] multi_tenant` mode, the auth URLs an app's `[auth] forward`
    /// may name. Empty (the default): tenants cannot use forward-auth.
    ///
    /// The URL in `app.infos` is tenant input, and the proxy fetches it — with
    /// the visitor's cookies — and relays a denial's body to the client. Left
    /// open that is a server-side request forgery: `forward =
    /// "http://169.254.169.254/…"` or an internal admin port. An entry matches
    /// a URL with the same scheme, host and port and, when the entry's path
    /// ends in `/`, any path below it; otherwise the same path. The query
    /// string is not compared. Read at each app discovery.
    pub allowed_urls: Vec<String>,
}

impl ForwardAuthSettings {
    /// The subrequest deadline, `DEFAULT_TIMEOUT` when unset or 0.
    pub fn timeout(&self) -> Duration {
        match self.timeout_secs {
            Some(secs) if secs > 0 => Duration::from_secs(secs),
            _ => DEFAULT_TIMEOUT,
        }
    }

    /// Refuse a tenant's auth URL that no `allowed_urls` entry covers.
    pub fn check_tenant_url(&self, url: &str) -> anyhow::Result<()> {
        if url_is_allowed(&self.allowed_urls, url) {
            return Ok(());
        }
        anyhow::bail!(
            "[auth] forward = {:?} is not in [forward_auth] allowed_urls (multi_tenant mode \
             only lets an app use the auth services the operator listed)",
            url
        )
    }
}

/// Whether one of `allowed` covers `url`. See [`ForwardAuthSettings::allowed_urls`].
///
/// Both sides go through `url::Url`, which lowercases the host, drops a
/// default port and resolves `..` and `%2e%2e` segments — so `/api/../admin`
/// is compared as `/admin`, and `http://auth.internal.evil.com` is not
/// `http://auth.internal` with something after it.
fn url_is_allowed(allowed: &[String], url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    allowed.iter().any(|entry| {
        let Ok(entry) = url::Url::parse(entry) else {
            return false;
        };
        entry.scheme() == url.scheme()
            && entry.host_str().is_some()
            && entry.host_str() == url.host_str()
            && entry.port_or_known_default() == url.port_or_known_default()
            && if entry.path().ends_with('/') {
                url.path().starts_with(entry.path())
            } else {
                entry.path() == url.path()
            }
    })
}

/// A route's or an app's forward-auth: where to ask, and which of the
/// answer's headers to copy upstream.
///
/// Only ever built valid (see [`ForwardAuth::new`]), parsed once at load time
/// and shared behind an `Arc`, so a matched route hands it to the request
/// without copying anything.
#[derive(Clone)]
pub struct ForwardAuth(Arc<Inner>);

struct Inner {
    /// As written, for `proxy.conf` and the admin API.
    url: String,
    /// The same, ready for the subrequest.
    uri: Uri,
    copy_headers: Vec<HeaderName>,
}

impl ForwardAuth {
    /// Check and compile a forward-auth declaration.
    ///
    /// The URL must be `http` or `https` with a host, and carry neither
    /// credentials (they would be shown by the admin API and never sent: the
    /// client does not turn userinfo into `Authorization`) nor a fragment.
    /// Each copied header must be a valid name the proxy does not manage:
    /// not hop-by-hop or framing, not `Host`, not a forwarding header.
    pub fn new<S: AsRef<str>>(url: &str, copy_headers: &[S]) -> anyhow::Result<Self> {
        let uri = check_url(url)?;
        if copy_headers.len() > MAX_COPY_HEADERS {
            anyhow::bail!(
                "forward-auth copies at most {} response headers, got {}",
                MAX_COPY_HEADERS,
                copy_headers.len()
            );
        }
        let mut names: Vec<HeaderName> = Vec::with_capacity(copy_headers.len());
        for raw in copy_headers {
            let raw = raw.as_ref().trim();
            let name = HeaderName::from_bytes(raw.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid forward-auth header name {:?}", raw))?;
            let lower = name.as_str();
            if crate::config::PROTECTED_HEADERS.contains(&lower)
                || lower == "host"
                || crate::proxy_headers::is_forwarding_header(lower)
            {
                anyhow::bail!(
                    "forward-auth cannot copy {}: the proxy manages that header",
                    raw
                );
            }
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Ok(Self(Arc::new(Inner {
            url: url.to_string(),
            uri,
            copy_headers: names,
        })))
    }

    /// The auth URL as configured.
    pub fn url(&self) -> &str {
        &self.0.url
    }

    /// The auth response headers copied onto the upstream request (lowercase).
    pub fn copy_headers(&self) -> &[HeaderName] {
        &self.0.copy_headers
    }

    /// Re-check the URL. Construction already did; `ProxyRule::validate`
    /// calls this so the admin API's contract ("validate checks everything
    /// the parser checks") holds on its face.
    pub fn validate(&self) -> anyhow::Result<()> {
        check_url(&self.0.url).map(|_| ())
    }
}

impl std::fmt::Debug for ForwardAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardAuth")
            .field("url", &self.0.url)
            .field("copy_headers", &self.0.copy_headers)
            .finish()
    }
}

impl PartialEq for ForwardAuth {
    fn eq(&self, other: &Self) -> bool {
        self.0.url == other.0.url && self.0.copy_headers == other.0.copy_headers
    }
}

/// The JSON shape of a route's `forward_auth`:
/// `{"url": "http://auth:4180/verify", "headers": ["x-auth-user"]}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardAuthSpec {
    url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    headers: Vec<String>,
}

impl Serialize for ForwardAuth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ForwardAuthSpec {
            url: self.0.url.clone(),
            headers: self
                .0
                .copy_headers
                .iter()
                .map(|h| h.as_str().to_string())
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ForwardAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let spec = ForwardAuthSpec::deserialize(deserializer)?;
        ForwardAuth::new(&spec.url, &spec.headers).map_err(serde::de::Error::custom)
    }
}

/// Parse an auth URL: `http`/`https`, a host, no userinfo, no fragment.
fn check_url(url: &str) -> anyhow::Result<Uri> {
    let parsed = url::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid forward-auth URL {:?}: {}", url, e))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("forward-auth URL {:?} must be http:// or https://", url);
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        anyhow::bail!("forward-auth URL {:?} has no host", url);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("forward-auth URL {:?} must not carry credentials", url);
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("forward-auth URL {:?} must not carry a #fragment", url);
    }
    parsed
        .as_str()
        .parse::<Uri>()
        .map_err(|e| anyhow::anyhow!("invalid forward-auth URL {:?}: {}", url, e))
}

/// `@forward_auth:` and `@forward_auth_headers:` as `parse_rule_tail` meets
/// them, turned into a [`ForwardAuth`] once the whole line is read.
#[derive(Default)]
pub(crate) struct Directives {
    url: Option<String>,
    headers: Vec<String>,
}

impl Directives {
    /// `@forward_auth:<url>`.
    pub(crate) fn url(&mut self, value: &str) -> anyhow::Result<()> {
        if value.is_empty() {
            anyhow::bail!("@forward_auth: needs a URL");
        }
        if self.url.replace(value.to_string()).is_some() {
            anyhow::bail!("@forward_auth: given more than once");
        }
        Ok(())
    }

    /// `@forward_auth_headers:<Name>,<Name>`.
    pub(crate) fn headers(&mut self, value: &str) -> anyhow::Result<()> {
        let before = self.headers.len();
        self.headers.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_string),
        );
        if self.headers.len() == before {
            anyhow::bail!("@forward_auth_headers: needs at least one header name");
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> anyhow::Result<Option<ForwardAuth>> {
        match self.url {
            Some(url) => ForwardAuth::new(&url, &self.headers).map(Some),
            None if self.headers.is_empty() => Ok(None),
            None => anyhow::bail!("@forward_auth_headers: without @forward_auth:"),
        }
    }
}

/// Run a route's or an app's forward-auth on `req`.
///
/// Resolves to `None` when the request may proceed — with the configured
/// auth response headers now on it — or to the response to send instead.
///
/// - `exempt`: the path is a `@noauth` / `[auth] noauth` carve-out. The
///   client's copies of the copied headers are still removed, then the
///   request proceeds without asking.
/// - `send_authorization`: whether the client's `Authorization` header goes
///   to the auth service. False when the same route also has Basic Auth:
///   that header then carries the Basic password, which belongs to this
///   proxy, not to a third-party service.
pub async fn gate<B: Send>(
    client: &ProxyClient,
    auth: &ForwardAuth,
    settings: &ForwardAuthSettings,
    req: &mut Request<B>,
    exempt: bool,
    send_authorization: bool,
) -> Option<Response<BoxBody>> {
    // Always, first: a forged `X-Auth-User` must not reach the upstream —
    // not next to the real one, not on a carve-out, not ever.
    for name in auth.copy_headers() {
        req.headers_mut().remove(name);
    }
    if exempt {
        return None;
    }

    let deadline = Instant::now() + settings.timeout();
    let subrequest = build_subrequest(auth, req, send_authorization);
    let response = match timeout_at(deadline, client.request(subrequest)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            tracing::warn!(
                url = auth.url(),
                error = %e,
                "forward-auth service unreachable; answering 503"
            );
            return Some(unavailable());
        }
        Err(_) => {
            tracing::warn!(
                url = auth.url(),
                timeout_ms = settings.timeout().as_millis() as u64,
                "forward-auth service timed out; answering 503"
            );
            return Some(unavailable());
        }
    };

    let (parts, body) = response.into_parts();
    if parts.status.is_success() {
        let headers = req.headers_mut();
        for name in auth.copy_headers() {
            for value in parts.headers.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
        // Read the (normally empty) body so the connection goes back to the
        // pool; one that is too big or too slow is simply dropped with it.
        if !body.is_end_stream() {
            let _ = timeout_at(deadline, Limited::new(body, MAX_RESPONSE_BODY).collect()).await;
        }
        return None;
    }
    if parts.status.is_informational() {
        tracing::warn!(
            url = auth.url(),
            status = parts.status.as_u16(),
            "forward-auth service answered with an informational status; answering 503"
        );
        return Some(unavailable());
    }
    Some(relay_denial(parts, body, deadline).await)
}

/// The bodiless `GET` shown to the auth service.
fn build_subrequest<B>(
    auth: &ForwardAuth,
    req: &Request<B>,
    send_authorization: bool,
) -> Request<crate::pool::ProxyRequestBody> {
    let mut sub = Request::new(empty());
    *sub.method_mut() = Method::GET;
    *sub.uri_mut() = auth.0.uri.clone();
    // `Host` is left to the client, which sets the auth service's own.
    let headers = sub.headers_mut();
    let source = req.headers();
    for name in &FORWARDED_REQUEST_HEADERS {
        if !send_authorization && name == header::AUTHORIZATION {
            continue;
        }
        for value in source.get_all(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Ok(method) = HeaderValue::from_str(req.method().as_str()) {
        headers.insert(X_FORWARDED_METHOD.clone(), method);
    }
    // The request target as the client sent it: path and query, which is
    // what the auth service builds its post-login redirect from.
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    if let Ok(uri) = HeaderValue::from_str(target) {
        headers.insert(X_FORWARDED_URI.clone(), uri);
    }
    sub
}

/// The auth service's refusal, as the client will see it.
async fn relay_denial(
    parts: http::response::Parts,
    body: hyper::body::Incoming,
    deadline: Instant,
) -> Response<BoxBody> {
    let mut headers: HeaderMap = parts.headers;
    let body = match timeout_at(deadline, Limited::new(body, MAX_RESPONSE_BODY).collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        // Too big, broken or too slow: the status and headers still say no.
        _ => {
            headers.remove(header::CONTENT_ENCODING);
            Bytes::new()
        }
    };
    crate::proxy_headers::strip_hop_by_hop(&mut headers);
    // Framing is the proxy's to set for the body it actually sends.
    headers.remove(header::CONTENT_LENGTH);
    let mut response = Response::new(full(body));
    *response.status_mut() = parts.status;
    *response.headers_mut() = headers;
    response
}

/// 503 for an auth service that did not answer usably. Fail closed: the
/// request is refused, never let through unchecked.
fn unavailable() -> Response<BoxBody> {
    let mut response = Response::new(full("Authentication service unavailable"));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_must_be_http_with_a_host_and_no_credentials() {
        for good in [
            "http://auth.internal:4180/oauth2/auth",
            "https://sso.example.com/api/authz/forward-auth",
            "http://127.0.0.1:9091/verify?rd=https://login",
        ] {
            assert!(ForwardAuth::new::<&str>(good, &[]).is_ok(), "{good}");
        }
        for bad in [
            "ftp://auth/verify",
            "file:///etc/passwd",
            "unix:/run/auth.sock",
            "http://user:pw@auth/verify",
            "http://auth/verify#frag",
            "/verify",
            "auth.internal:4180",
            "",
        ] {
            assert!(ForwardAuth::new::<&str>(bad, &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn copied_headers_must_be_valid_and_not_managed_by_the_proxy() {
        let auth =
            ForwardAuth::new("http://a/v", &["X-Auth-User", "x-auth-user", "X-Email"]).unwrap();
        // Lowercased and deduplicated.
        assert_eq!(auth.copy_headers().len(), 2);
        assert_eq!(auth.copy_headers()[0].as_str(), "x-auth-user");
        // Authorization may be copied (a token minted for the upstream).
        assert!(ForwardAuth::new("http://a/v", &["Authorization"]).is_ok());
        for bad in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "X-Forwarded-For",
            "X-Real-IP",
            "Forwarded",
            "bad header",
        ] {
            assert!(ForwardAuth::new("http://a/v", &[bad]).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..=MAX_COPY_HEADERS).map(|i| format!("x-h{i}")).collect();
        assert!(ForwardAuth::new("http://a/v", &many).is_err());
    }

    #[test]
    fn json_round_trips_and_refuses_bad_input() {
        let auth = ForwardAuth::new("http://a:1/v", &["X-Auth-User"]).unwrap();
        let json = serde_json::to_value(&auth).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"url": "http://a:1/v", "headers": ["x-auth-user"]})
        );
        let back: ForwardAuth = serde_json::from_value(json).unwrap();
        assert_eq!(back, auth);
        // No headers: the key is omitted, and accepted back absent.
        let bare: ForwardAuth = serde_json::from_str(r#"{"url":"http://a/v"}"#).unwrap();
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            r#"{"url":"http://a/v"}"#
        );
        assert!(serde_json::from_str::<ForwardAuth>(r#"{"url":"ftp://a/v"}"#).is_err());
        assert!(serde_json::from_str::<ForwardAuth>(r#"{"url":"http://a","x":1}"#).is_err());
    }

    #[test]
    fn directives_need_a_url_and_are_given_once() {
        let mut d = Directives::default();
        d.url("http://a/v").unwrap();
        d.headers("X-Auth-User, X-Auth-Email").unwrap();
        let auth = d.finish().unwrap().unwrap();
        assert_eq!(auth.copy_headers().len(), 2);

        let mut twice = Directives::default();
        twice.url("http://a/v").unwrap();
        assert!(twice.url("http://b/v").is_err());

        let mut orphan = Directives::default();
        orphan.headers("X-Auth-User").unwrap();
        assert!(orphan.finish().is_err());

        assert!(Directives::default().headers(",").is_err());
        assert!(Directives::default().finish().unwrap().is_none());
    }

    #[test]
    fn tenant_allowlist_compares_origin_and_path() {
        let allowed = vec![
            "http://auth.internal:4180/oauth2/auth".to_string(),
            "https://sso.internal/api/".to_string(),
        ];
        let settings = ForwardAuthSettings {
            timeout_secs: None,
            allowed_urls: allowed.clone(),
        };
        for ok in [
            "http://auth.internal:4180/oauth2/auth",
            "http://AUTH.internal:4180/oauth2/auth?allowed_groups=dev",
            "https://sso.internal/api/authz/forward-auth",
            "https://sso.internal:443/api/verify",
        ] {
            assert!(url_is_allowed(&allowed, ok), "{ok}");
            assert!(settings.check_tenant_url(ok).is_ok(), "{ok}");
        }
        for refused in [
            "http://auth.internal:4181/oauth2/auth",
            "https://auth.internal:4180/oauth2/auth",
            "http://auth.internal.evil.com:4180/oauth2/auth",
            "http://auth.internal:4180/oauth2/auth/x",
            "http://auth.internal:4180/oauth2/authx",
            "https://sso.internal/api",
            "https://sso.internal/api/../admin",
            "https://sso.internal/api/%2e%2e/admin",
            "http://sso.internal/api/verify",
            "http://169.254.169.254/latest/meta-data/",
            "not a url",
        ] {
            assert!(!url_is_allowed(&allowed, refused), "{refused}");
        }
        // Nothing listed: nothing allowed.
        assert!(ForwardAuthSettings::default()
            .check_tenant_url("http://auth.internal:4180/oauth2/auth")
            .is_err());
    }

    #[test]
    fn timeout_defaults_to_five_seconds() {
        assert_eq!(ForwardAuthSettings::default().timeout(), DEFAULT_TIMEOUT);
        let zero = ForwardAuthSettings {
            timeout_secs: Some(0),
            ..Default::default()
        };
        assert_eq!(zero.timeout(), DEFAULT_TIMEOUT);
        let two = ForwardAuthSettings {
            timeout_secs: Some(2),
            ..Default::default()
        };
        assert_eq!(two.timeout(), Duration::from_secs(2));
    }

    #[test]
    fn the_subrequest_carries_credentials_and_the_request_description() {
        let auth = ForwardAuth::new("http://auth:4180/verify", &["X-Auth-User"]).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/app/page?x=1")
            .header("cookie", "a=1")
            .header("cookie", "b=2")
            .header("authorization", "Bearer t")
            .header("x-forwarded-for", "203.0.113.7")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "app.example.com")
            .header("content-type", "application/json")
            .header("x-secret", "not for the auth service")
            .body(())
            .unwrap();
        let sub = build_subrequest(&auth, &req, true);
        assert_eq!(sub.method(), Method::GET);
        assert_eq!(sub.uri(), "http://auth:4180/verify");
        let h = sub.headers();
        assert_eq!(h.get_all("cookie").iter().count(), 2);
        assert_eq!(h["authorization"], "Bearer t");
        assert_eq!(h["x-forwarded-method"], "POST");
        assert_eq!(h["x-forwarded-uri"], "/app/page?x=1");
        assert_eq!(h["x-forwarded-for"], "203.0.113.7");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["x-forwarded-host"], "app.example.com");
        assert!(h.get("content-type").is_none());
        assert!(h.get("x-secret").is_none());
        assert!(h.get("host").is_none());

        // Basic Auth on the same route: its password stays here.
        let sub = build_subrequest(&auth, &req, false);
        assert!(sub.headers().get("authorization").is_none());
        assert_eq!(sub.headers().get_all("cookie").iter().count(), 2);
    }
}
