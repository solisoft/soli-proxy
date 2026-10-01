//! Maintenance mode: answer 503 with a page, on purpose, for the whole proxy
//! or for one app, while letting the operator's own traffic through.
//!
//! Two ways to switch it, deliberately not more:
//!
//! - **The admin API** — `PUT /api/v1/maintenance` (everything) and
//!   `PUT /api/v1/apps/{name}/maintenance` (one app), with
//!   `{"enabled": true, "retry_after": 600, "message": "…"}`. The state is
//!   persisted to `run/maintenance.json` (written atomically) so a restart in
//!   the middle of a maintenance window does not reopen the site.
//! - **A flag file** — `<site>/maintenance.flag` exists → that app is in
//!   maintenance. For deploy scripts that run on the box without admin
//!   credentials (a tenant's, in multi-tenant mode): `touch` it before the
//!   migration, `rm` it after. The sites watcher picks it up within a second
//!   or two.
//!
//! Not an `app.infos` key: maintenance is a state the site is in for an hour,
//! not part of its configuration, and toggling it by rewriting a TOML file
//! from a script is clumsier and riskier than creating or removing a file.
//!
//! Requests from `[maintenance] allow_ips` (CIDRs) and to `allow_paths` go
//! through as usual, as do ACME challenges and the proxy's own health and
//! metrics endpoints.

use crate::server::BoxBody;
use arc_swap::ArcSwap;
use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where the state is persisted, alongside the rest of `run/`.
pub const STATE_FILE: &str = "./run/maintenance.json";

/// Longest `Retry-After` accepted: a week.
const MAX_RETRY_AFTER: u64 = 7 * 24 * 3600;

/// Longest maintenance message.
const MAX_MESSAGE_LEN: usize = 1024;

/// `[maintenance]` in `config.toml`: policy, not state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceConfig {
    /// `Retry-After` when a toggle does not say. Default 300 seconds.
    pub retry_after: u64,
    /// Client addresses served normally during maintenance: an IP or a CIDR
    /// (`203.0.113.7`, `10.0.0.0/8`, `2001:db8::/32`).
    pub allow_ips: Vec<String>,
    /// Paths served normally during maintenance, `@noauth` syntax: an exact
    /// path or a prefix ending in `*` (`/up`, `/status/*`).
    pub allow_paths: Vec<String>,
    #[serde(skip)]
    nets: Vec<(IpAddr, u8)>,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            retry_after: 300,
            allow_ips: Vec::new(),
            allow_paths: Vec::new(),
            nets: Vec::new(),
        }
    }
}

/// `addr` or `addr/prefix`, with the prefix length checked.
fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match text.trim().split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text.trim(), None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let ip = ip.to_canonical();
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
        None => max,
    };
    Some((ip, prefix))
}

fn in_net(ip: IpAddr, (net, prefix): (IpAddr, u8)) -> bool {
    match (ip.to_canonical(), net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

impl MaintenanceConfig {
    /// Validate the section and parse its networks, once per loaded config.
    pub fn validated(mut self) -> anyhow::Result<Self> {
        if self.retry_after > MAX_RETRY_AFTER {
            anyhow::bail!(
                "[maintenance] retry_after = {} is above the {} second ceiling",
                self.retry_after,
                MAX_RETRY_AFTER
            );
        }
        self.nets = self
            .allow_ips
            .iter()
            .map(|t| {
                parse_cidr(t).ok_or_else(|| {
                    anyhow::anyhow!(
                        "[maintenance] allow_ips entry {:?} is not an IP address or CIDR",
                        t
                    )
                })
            })
            .collect::<anyhow::Result<_>>()?;
        for p in &self.allow_paths {
            if crate::config::validate_auth_exempt_path(p).is_none() {
                anyhow::bail!(
                    "[maintenance] allow_paths entry {:?} is invalid: expected an absolute path \
                     such as /up or /status/*, with no '..' segment and no percent-encoding",
                    p
                );
            }
        }
        Ok(self)
    }

    fn allows_ip(&self, ip: Option<IpAddr>) -> bool {
        ip.is_some_and(|ip| self.nets.iter().any(|net| in_net(ip, *net)))
    }
}

/// One maintenance window: the whole proxy's, or one app's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// `Retry-After`, in seconds. `None`: `[maintenance] retry_after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// Shown on the page (`{{message}}`) and in the plain-text body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// When it was switched on (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

/// Which windows are open. What `run/maintenance.json` holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<Window>,
    /// By app name.
    pub apps: BTreeMap<String, Window>,
}

/// The body of `PUT /api/v1/maintenance` and
/// `PUT /api/v1/apps/{name}/maintenance`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    pub enabled: bool,
    #[serde(default)]
    pub retry_after: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
}

impl Toggle {
    /// The window this toggle opens, or `None` to close it.
    pub fn into_window(self) -> Result<Option<Window>, String> {
        if let Some(r) = self.retry_after {
            if r > MAX_RETRY_AFTER {
                return Err(format!("retry_after is above {} seconds", MAX_RETRY_AFTER));
            }
        }
        if let Some(ref m) = self.message {
            if m.len() > MAX_MESSAGE_LEN {
                return Err(format!("message is longer than {} bytes", MAX_MESSAGE_LEN));
            }
            if m.chars().any(|c| c.is_control() && c != '\n') {
                return Err("message contains control characters".to_string());
            }
        }
        Ok(self.enabled.then(|| Window {
            retry_after: self.retry_after,
            message: self.message.filter(|m| !m.is_empty()),
            since: Some(chrono::Utc::now().to_rfc3339()),
        }))
    }
}

/// The live maintenance state, shared by the request path (read, lock-free)
/// and the admin API (write, persisted).
#[derive(Default)]
pub struct Maintenance {
    state: ArcSwap<MaintenanceState>,
    /// Where the state is persisted; also serialises writers, so the file
    /// and the published state never disagree. `None`: in memory only (tests,
    /// one-shot CLI commands).
    persist_to: parking_lot::Mutex<Option<PathBuf>>,
}

impl std::fmt::Debug for Maintenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Maintenance")
            .field(&self.state.load())
            .finish()
    }
}

impl Maintenance {
    pub fn snapshot(&self) -> Arc<MaintenanceState> {
        self.state.load_full()
    }

    /// Persist to `path` from now on, starting from what it holds. A file
    /// that does not parse is an error rather than "no maintenance": silently
    /// reopening a site that was closed on purpose is the worse failure.
    pub fn persist_to(&self, path: impl Into<PathBuf>) -> anyhow::Result<()> {
        let path = path.into();
        let mut slot = self.persist_to.lock();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let state: MaintenanceState = serde_json::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))?;
                if state.global.is_some() || !state.apps.is_empty() {
                    tracing::warn!(
                        "maintenance mode restored from {}: global={}, apps={:?}",
                        path.display(),
                        state.global.is_some(),
                        state.apps.keys().collect::<Vec<_>>()
                    );
                }
                self.state.store(Arc::new(state));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("{}: {}", path.display(), e),
        }
        *slot = Some(path);
        Ok(())
    }

    /// Open or close the proxy-wide window.
    pub fn set_global(&self, window: Option<Window>) -> anyhow::Result<Arc<MaintenanceState>> {
        self.update(|state| state.global = window)
    }

    /// Open or close `app`'s window.
    pub fn set_app(
        &self,
        app: &str,
        window: Option<Window>,
    ) -> anyhow::Result<Arc<MaintenanceState>> {
        self.update(|state| match window {
            Some(w) => {
                state.apps.insert(app.to_string(), w);
            }
            None => {
                state.apps.remove(app);
            }
        })
    }

    fn update(
        &self,
        change: impl FnOnce(&mut MaintenanceState),
    ) -> anyhow::Result<Arc<MaintenanceState>> {
        let path = self.persist_to.lock();
        let mut next = MaintenanceState::clone(&self.state.load());
        change(&mut next);
        // Written before it is published: if the disk refuses, the state
        // stays what the file says and the caller hears about it.
        if let Some(path) = path.as_deref() {
            write_state(path, &next)?;
        }
        let next = Arc::new(next);
        self.state.store(next.clone());
        Ok(next)
    }
}

fn write_state(path: &Path, state: &MaintenanceState) -> anyhow::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(state)?;
    crate::config::write_atomic(path, &json)
        .map_err(|e| anyhow::anyhow!("cannot write {}: {}", path.display(), e))
}

/// The client address maintenance mode judges `allow_ips` against: the real
/// client as the door resolved it (trusted proxies, PROXY protocol).
pub(crate) fn client_ip<B>(req: &Request<B>, peer: Option<SocketAddr>) -> Option<IpAddr> {
    // The door (`crate::edge`) has already decided who the client is: the
    // peer, or — behind a trusted proxy — the address its forwarding headers
    // name. Without that record (a request built in a test), the peer.
    crate::edge::client_ip(req.extensions()).or_else(|| peer.map(|a| a.ip()))
}

/// Paths that keep working whatever the mode: ACME challenges (a certificate
/// must not expire because a site was closed for an evening) and the proxy's
/// own health and metrics endpoints (a load balancer in front must not pull
/// the proxy that is serving the maintenance page).
fn always_allowed(path: &str, config: &crate::config::Config) -> bool {
    if path.starts_with("/.well-known/acme-challenge/") {
        return true;
    }
    if config.health.enabled != Some(false) {
        let live = config
            .health
            .liveness_path
            .as_deref()
            .unwrap_or("/health/live");
        let ready = config
            .health
            .readiness_path
            .as_deref()
            .unwrap_or("/health/ready");
        if path == live || path == ready {
            return true;
        }
    }
    path == config.metrics.endpoint.as_deref().unwrap_or("/metrics")
}

/// The 503 to send instead of serving `req`, if it falls in an open window.
///
/// When nothing is in maintenance — the steady state — this is one atomic
/// load and two flag reads.
pub fn check<B>(
    req: &Request<B>,
    config: &crate::config::Config,
    maintenance: &Maintenance,
    apps: Option<&crate::app::AppManager>,
    peer: Option<SocketAddr>,
) -> Option<Response<BoxBody>> {
    let state = maintenance.state.load();
    let flagged = apps.is_some_and(|m| m.any_maintenance_flag());
    if state.global.is_none() && state.apps.is_empty() && !flagged {
        return None;
    }

    let host_value = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or("");
    let host = host_value.split(':').next().unwrap_or(host_value);
    // The app that serves this request, not merely one claiming the host: a
    // tenant's derived claim on an apex the operator's rule (or a cluster
    // push) serves must not put that apex into maintenance with its flag.
    let route =
        apps.and_then(|m| m.serving_route(host, crate::server::static_route(req, &config.rules)));

    let flag_window = Window::default();
    let window = match (&state.global, &route) {
        (Some(global), _) => global,
        (None, Some(route)) => match state.apps.get(&*route.app) {
            Some(w) => w,
            None if route.maintenance => &flag_window,
            None => return None,
        },
        (None, None) => return None,
    };

    let path = req.uri().path();
    let policy = &config.maintenance;
    if always_allowed(path, config)
        || crate::config::path_is_auth_exempt(&policy.allow_paths, path)
        || policy.allows_ip(client_ip(req, peer))
    {
        return None;
    }

    let retry_after = window.retry_after.unwrap_or(policy.retry_after);
    let message = window.message.as_deref().unwrap_or("");
    let mut resp = if super::accepts_html(req.headers()) {
        let template = route
            .as_ref()
            .and_then(|r| r.error_pages.as_deref())
            .and_then(|p| p.maintenance())
            .or_else(|| {
                config
                    .error_pages
                    .pages
                    .as_deref()
                    .and_then(|p| p.maintenance())
            })
            .unwrap_or(BUILTIN_PAGE);
        // The ID the door stamped, under whatever `request_id_header` names.
        let request_id = crate::edge::request_id(req.extensions())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let html = super::error_pages::render(
            template,
            &super::error_pages::PageVars {
                status: StatusCode::SERVICE_UNAVAILABLE,
                host: truncate(host_value, 256),
                request_id: truncate(request_id, 256),
                message,
            },
        );
        let mut resp = Response::new(crate::server::full(Bytes::new()));
        *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        super::error_pages::html_response(resp, html)
    } else {
        let text = if message.is_empty() {
            "Service Unavailable: down for maintenance\n".to_string()
        } else {
            format!("Service Unavailable: {}\n", message)
        };
        let mut resp = Response::new(crate::server::full(Bytes::from(text)));
        *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    };
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    super::mark_owned(&mut resp, super::BodyOwner::Rendered);
    Some(resp)
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The page served when no `maintenance.html` exists.
const BUILTIN_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Down for maintenance</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f6f4;color:#222}
main{max-width:32rem;padding:2rem}
h1{font-size:1.5rem;margin:0 0 .5rem}
p{margin:.5rem 0;color:#555}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}p{color:#aaa}}
</style>
</head>
<body>
<main>
<h1>Down for maintenance</h1>
<p>{{host}} is being worked on and will be back shortly.</p>
<p>{{message}}</p>
</main>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[test]
    fn cidrs_match_their_networks() {
        let net = |s| parse_cidr(s).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_net(ip("10.1.2.3"), net("10.0.0.0/8")));
        assert!(!in_net(ip("11.1.2.3"), net("10.0.0.0/8")));
        assert!(in_net(ip("203.0.113.7"), net("203.0.113.7")));
        assert!(!in_net(ip("203.0.113.8"), net("203.0.113.7")));
        assert!(in_net(ip("1.2.3.4"), net("0.0.0.0/0")));
        // A dual-stack listener reports IPv4 peers as mapped IPv6.
        assert!(in_net(ip("::ffff:10.0.0.1"), net("10.0.0.0/8")));
        assert!(in_net(ip("2001:db8::1"), net("2001:db8::/32")));
        assert!(!in_net(ip("2001:db9::1"), net("2001:db8::/32")));
        assert!(!in_net(ip("10.0.0.1"), net("::/0")));
        for bad in ["10.0.0.0/33", "::/129", "nope", "10.0.0.0/", "/8"] {
            assert!(parse_cidr(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn invalid_policy_is_refused() {
        let bad = |c: MaintenanceConfig| c.validated().is_err();
        assert!(bad(MaintenanceConfig {
            allow_ips: vec!["10.0.0.0/40".into()],
            ..Default::default()
        }));
        assert!(bad(MaintenanceConfig {
            allow_paths: vec!["up".into()],
            ..Default::default()
        }));
        assert!(bad(MaintenanceConfig {
            retry_after: MAX_RETRY_AFTER + 1,
            ..Default::default()
        }));
    }

    #[test]
    fn toggles_are_validated() {
        let t = |json: &str| serde_json::from_str::<Toggle>(json).unwrap().into_window();
        assert!(t(r#"{"enabled": false}"#).unwrap().is_none());
        let w = t(r#"{"enabled": true, "retry_after": 60, "message": "back at 5"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(w.retry_after, Some(60));
        assert_eq!(w.message.as_deref(), Some("back at 5"));
        assert!(t(r#"{"enabled": true, "retry_after": 99999999}"#).is_err());
        assert!(t(r#"{"enabled": true, "message": "a\u0000b"}"#).is_err());
        assert!(serde_json::from_str::<Toggle>(r#"{"enabled": true, "extra": 1}"#).is_err());
    }

    #[test]
    fn state_survives_a_restart_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/maintenance.json");
        let first = Maintenance::default();
        first.persist_to(&path).unwrap();
        first
            .set_global(Some(Window {
                retry_after: Some(120),
                message: Some("upgrading".into()),
                since: None,
            }))
            .unwrap();
        first.set_app("shop", Some(Window::default())).unwrap();

        let second = Maintenance::default();
        second.persist_to(&path).unwrap();
        assert_eq!(*second.snapshot(), *first.snapshot());

        second.set_global(None).unwrap();
        second.set_app("shop", None).unwrap();
        let third = Maintenance::default();
        third.persist_to(&path).unwrap();
        assert_eq!(*third.snapshot(), MaintenanceState::default());

        // A file that does not parse is an error, not an open site.
        std::fs::write(&path, "{nope").unwrap();
        assert!(Maintenance::default().persist_to(&path).is_err());
    }

    fn request(path: &str, accept: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header("host", "site.example:8080")
            .header("accept", accept)
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn global_window_answers_503_except_for_allowlisted_traffic() {
        let mut config = crate::response::test_config();
        config.maintenance = MaintenanceConfig {
            retry_after: 42,
            allow_ips: vec!["10.0.0.0/8".into()],
            allow_paths: vec!["/up".into(), "/status/*".into()],
            ..Default::default()
        }
        .validated()
        .unwrap();
        let maintenance = Maintenance::default();
        let peer: SocketAddr = "198.51.100.1:5000".parse().unwrap();

        assert!(
            check(
                &request("/", "text/html"),
                &config,
                &maintenance,
                None,
                Some(peer)
            )
            .is_none(),
            "nothing open"
        );

        maintenance
            .set_global(Some(Window {
                message: Some("<back soon>".into()),
                ..Default::default()
            }))
            .unwrap();

        let resp = check(
            &request("/", "text/html"),
            &config,
            &maintenance,
            None,
            Some(peer),
        )
        .expect("closed");
        assert_eq!(resp.status(), 503);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "42");
        assert_eq!(
            crate::response::tag(&resp).map(|t| t.owner),
            Some(crate::response::BodyOwner::Rendered)
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("site.example:8080 is being worked on"),
            "{body}"
        );
        assert!(
            body.contains("&lt;back soon&gt;"),
            "message escaped: {body}"
        );

        let resp = check(
            &request("/api", "*/*"),
            &config,
            &maintenance,
            None,
            Some(peer),
        )
        .unwrap();
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Service Unavailable: <back soon>\n");

        for open in [
            "/up",
            "/status/db",
            "/.well-known/acme-challenge/t",
            "/health/live",
        ] {
            assert!(
                check(
                    &request(open, "*/*"),
                    &config,
                    &maintenance,
                    None,
                    Some(peer)
                )
                .is_none(),
                "{open}"
            );
        }
        // Allowlisted paths compare literally and fail closed.
        assert!(check(
            &request("/u%70", "*/*"),
            &config,
            &maintenance,
            None,
            Some(peer)
        )
        .is_some());
        let office: SocketAddr = "10.20.30.40:1".parse().unwrap();
        assert!(check(
            &request("/", "*/*"),
            &config,
            &maintenance,
            None,
            Some(office)
        )
        .is_none());
        assert!(check(&request("/", "*/*"), &config, &maintenance, None, None).is_some());
    }
}
