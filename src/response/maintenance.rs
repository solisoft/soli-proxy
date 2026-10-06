//! Maintenance mode: answer 503 with a page, on purpose, for the whole proxy
//! or for one app, while letting the operator's own traffic through.
//!
//! Two ways to switch it, deliberately not more:
//!
//! - **The admin API** — `PUT /api/v1/maintenance` (everything) and
//!   `PUT /api/v1/apps/{name}/maintenance` (one app), with
//!   `{"enabled": true, "for_secs": 1800, "message": "…"}` (or `"until":
//!   "<RFC 3339>"`, or neither: open until switched off). The state is
//!   persisted to `run/maintenance.json` (written atomically) so a restart in
//!   the middle of a maintenance window does not reopen the site, and a window
//!   with an end closes by itself then. `soli-proxy maintenance` drives it
//!   from the command line, and the TUI's `M` from the apps screen.
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
//!
//! The page: the app's own (`<site>/error_pages/maintenance.html`, then
//! `<site>/public/maintenance.html`), else `[error_pages] dir`'s, else the
//! built-in one — in French or English after the browser's `Accept-Language`
//! (or `[maintenance] language`), with the time the site is back when the
//! window has an end, reloading itself once the site answers again. While an
//! app is closed the proxy serves `/maintenance/<file>` from its
//! `public/maintenance/`, so the app's own page can keep its stylesheet and
//! logo though the app is down.

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

/// Longest window a toggle may ask for: a week, like `Retry-After`.
const MAX_WINDOW_SECS: u64 = MAX_RETRY_AFTER;

/// Largest file served from an app's `public/maintenance/`.
const MAX_ASSET_BYTES: u64 = 1024 * 1024;

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
    /// The built-in page's language: `auto` (the browser's, French or
    /// English; the default), `fr` or `en`.
    pub language: String,
    #[serde(skip)]
    nets: Vec<(IpAddr, u8)>,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            retry_after: 300,
            allow_ips: Vec::new(),
            allow_paths: Vec::new(),
            language: "auto".to_string(),
            nets: Vec::new(),
        }
    }
}

/// `addr` or `addr/prefix`, with the prefix length checked.
pub(crate) fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
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

pub(crate) fn in_net(ip: IpAddr, (net, prefix): (IpAddr, u8)) -> bool {
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
        if !matches!(self.language.as_str(), "auto" | "fr" | "en") {
            anyhow::bail!(
                "[maintenance] language = {:?}: expected \"auto\", \"fr\" or \"en\"",
                self.language
            );
        }
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
    /// When it closes by itself (RFC 3339); `None`: when switched off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

impl Window {
    fn until_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.until
            .as_deref()
            .and_then(|u| chrono::DateTime::parse_from_rfc3339(u).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    }

    /// Its end has passed: closed, whatever the state file still says.
    pub fn expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.until_time().is_some_and(|u| u <= now)
    }

    /// `Retry-After`: what the window asked for, else the time left before
    /// its end, else the policy's default.
    fn retry_after(&self, default: u64, now: chrono::DateTime<chrono::Utc>) -> u64 {
        self.retry_after.unwrap_or_else(|| match self.until_time() {
            Some(u) => (u - now).num_seconds().max(1) as u64,
            None => default,
        })
    }
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
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    pub enabled: bool,
    #[serde(default)]
    pub retry_after: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
    /// Close by itself at this time (RFC 3339)...
    #[serde(default)]
    pub until: Option<String>,
    /// ...or this many seconds from now.
    #[serde(default)]
    pub for_secs: Option<u64>,
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
        let now = chrono::Utc::now();
        let until = match (self.until.as_deref(), self.for_secs) {
            (Some(_), Some(_)) => return Err("give until or for_secs, not both".to_string()),
            (Some(u), None) => {
                let t = chrono::DateTime::parse_from_rfc3339(u)
                    .map_err(|_| format!("until {u:?} is not an RFC 3339 time"))?
                    .with_timezone(&chrono::Utc);
                if t <= now {
                    return Err(format!("until {u:?} is in the past"));
                }
                if (t - now).num_seconds() as u64 > MAX_WINDOW_SECS {
                    return Err(format!("until is more than {MAX_WINDOW_SECS} seconds away"));
                }
                Some(t)
            }
            (None, Some(0)) => return Err("for_secs must be at least 1".to_string()),
            (None, Some(secs)) if secs > MAX_WINDOW_SECS => {
                return Err(format!("for_secs is above {MAX_WINDOW_SECS} seconds"))
            }
            (None, Some(secs)) => Some(now + chrono::Duration::seconds(secs as i64)),
            (None, None) => None,
        };
        Ok(self.enabled.then(|| Window {
            retry_after: self.retry_after,
            message: self.message.filter(|m| !m.is_empty()),
            since: Some(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            until: until.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        }))
    }
}

/// `90s`, `30m`, `2h`, `1h30m`, `1d` in seconds — what `soli-proxy
/// maintenance on --for` and the TUI take. A bare number is refused rather
/// than guessed.
pub fn parse_duration(text: &str) -> anyhow::Result<u64> {
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut units = 0;
    for c in text.trim().chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: u64 = digits
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration {:?}", text))?;
        digits.clear();
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => anyhow::bail!("invalid duration {:?}: units are s, m, h, d", text),
        };
        total = total.saturating_add(n.saturating_mul(unit));
        units += 1;
    }
    if !digits.is_empty() || units == 0 {
        anyhow::bail!(
            "invalid duration {:?}: give a unit, e.g. 30m, 2h, 1h30m",
            text
        );
    }
    Ok(total)
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

    /// Close the windows whose end has passed, and persist that. Returns
    /// what it closed: `"*"` for the proxy-wide window, else app names.
    pub fn expire_due(&self, now: chrono::DateTime<chrono::Utc>) -> anyhow::Result<Vec<String>> {
        let current = self.state.load();
        let due_global = current.global.as_ref().is_some_and(|w| w.expired(now));
        let due_apps: Vec<String> = current
            .apps
            .iter()
            .filter(|(_, w)| w.expired(now))
            .map(|(name, _)| name.clone())
            .collect();
        if !due_global && due_apps.is_empty() {
            return Ok(Vec::new());
        }
        self.update(|state| {
            if state.global.as_ref().is_some_and(|w| w.expired(now)) {
                state.global = None;
            }
            state.apps.retain(|_, w| !w.expired(now));
        })?;
        let mut closed = due_apps;
        if due_global {
            closed.insert(0, "*".to_string());
        }
        Ok(closed)
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
pub(crate) fn always_allowed(path: &str, config: &crate::config::Config) -> bool {
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

    // A window past its end is closed already, even before the expiry task
    // has removed it from the state file.
    let now = chrono::Utc::now();
    let open = |w: &Option<Window>| w.as_ref().filter(|w| !w.expired(now)).cloned();
    let flag_window = Window::default();
    let window = match (open(&state.global), &route) {
        (Some(global), _) => global,
        (None, Some(route)) => match state.apps.get(&*route.app).filter(|w| !w.expired(now)) {
            Some(w) => w.clone(),
            None if route.maintenance => flag_window,
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
    // The app's own maintenance page may need its stylesheet and images.
    if let (Some(route), Some(file)) = (&route, path.strip_prefix("/maintenance/")) {
        let tenant = apps.is_some_and(|m| m.multi_tenant());
        if let Some(resp) = serve_asset(&route.site, file, !tenant) {
            return Some(resp);
        }
    }

    let retry_after = window.retry_after(policy.retry_after, now);
    let message = window.message.as_deref().unwrap_or("");
    let mut resp = if super::accepts_html(req.headers()) {
        // The ID the door stamped, under whatever `request_id_header` names.
        let request_id = crate::edge::request_id(req.extensions())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host = truncate(host_value, 256);
        let app = route
            .as_ref()
            .and_then(|r| r.display_name.as_deref())
            .unwrap_or(host);
        let vars = super::error_pages::PageVars {
            status: StatusCode::SERVICE_UNAVAILABLE,
            host,
            request_id: truncate(request_id, 256),
            message,
            app,
            since: window.since.as_deref().unwrap_or(""),
            until: window.until.as_deref().unwrap_or(""),
        };
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
            });
        let html = match template {
            Some(template) => super::error_pages::render(template, &vars),
            None => builtin_page(language(req, &policy.language), &vars, window.until_time()),
        };
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

/// `/maintenance/<file>` from the app's `public/maintenance/`, while it is
/// closed: one level, plain file names only, 1 MiB at most. `None` sends
/// the request on to the maintenance page (a 503) like any other.
fn serve_asset(site: &Path, file: &str, follow_symlinks: bool) -> Option<Response<BoxBody>> {
    let valid = !file.is_empty()
        && file.len() <= 128
        && !file.starts_with('.')
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !valid {
        return None;
    }
    let bytes = match super::error_pages::read_site_bytes(
        site,
        "public/maintenance",
        file,
        follow_symlinks,
        MAX_ASSET_BYTES,
    ) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(e) => {
            tracing::debug!("maintenance asset {}: {:#}", file, e);
            return None;
        }
    };
    let ext = file.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let content_type = match ext.as_str() {
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        _ => return None,
    };
    let mut resp = Response::new(crate::server::full(Bytes::from(bytes)));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    super::mark_owned(&mut resp, super::BodyOwner::Rendered);
    Some(resp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Fr,
    En,
}

/// The built-in page's language: `[maintenance] language`, or with `auto`
/// the one of French and English the browser ranks higher (English when it
/// names neither).
fn language<B>(req: &Request<B>, setting: &str) -> Lang {
    match setting {
        "fr" => return Lang::Fr,
        "en" => return Lang::En,
        _ => {}
    }
    let header = req
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (mut fr, mut en) = (0.0_f64, 0.0_f64);
    for (pos, item) in header.split(',').enumerate() {
        let mut parts = item.split(';');
        let tag = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parts
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|q| q.trim().parse::<f64>().ok())
            .unwrap_or(1.0);
        // Earlier entries win ties: browsers list the preferred one first.
        let weight = q - pos as f64 * 1e-6;
        let primary = tag.split('-').next().unwrap_or("");
        if primary == "fr" && weight > fr {
            fr = weight;
        } else if primary == "en" && weight > en {
            en = weight;
        }
    }
    if fr > en {
        Lang::Fr
    } else {
        Lang::En
    }
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The page served when neither the app nor `[error_pages] dir` has a
/// `maintenance.html`: one self-contained file (no request leaves it but its
/// own check that the site is back), in the visitor's language, light or dark
/// after their system, with the time the site is back when the window has an
/// end. Under 6 KB.
fn builtin_page(
    lang: Lang,
    vars: &super::error_pages::PageVars<'_>,
    until: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    let esc = |s: &str| {
        let mut out = String::new();
        super::push_html_escaped(&mut out, s);
        out
    };
    let (html_lang, title, lead, back_at, back_soon, live) = match lang {
        Lang::Fr => (
            "fr",
            "On revient très vite",
            format!(
                "{} est en maintenance. Rien n’est perdu : revenez dans un moment.",
                esc(vars.app)
            ),
            "Retour prévu vers",
            "Retour dès que possible.",
            "Cette page se recharge seule au retour du site",
        ),
        Lang::En => (
            "en",
            "We’ll be right back",
            format!(
                "{} is down for maintenance. Nothing is lost: come back in a little while.",
                esc(vars.app)
            ),
            "Back around",
            "Back as soon as possible.",
            "This page reloads itself when the site is back",
        ),
    };
    let message = if vars.message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"msg\">{}</p>", esc(vars.message))
    };
    // Without JavaScript the time reads in UTC; the script rewrites it in
    // the visitor's own time zone, with the minutes left.
    let eta = match until {
        Some(u) => format!(
            "<div class=\"eta\" data-until=\"{iso}\" data-lang=\"{html_lang}\"><b>{back_at} <span class=\"at\">{utc} UTC</span></b><span class=\"in\"></span></div>",
            iso = u.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            utc = u.format("%H:%M"),
        ),
        None => format!("<div class=\"eta\"><b>{back_soon}</b></div>"),
    };
    let rid = if vars.request_id.is_empty() {
        "503".to_string()
    } else {
        format!("503 · {}", esc(vars.request_id))
    };
    BUILTIN_PAGE
        .replace("{{lang}}", html_lang)
        .replace("{{title}}", title)
        .replace("{{site}}", &esc(vars.host))
        .replace("{{lead}}", &lead)
        .replace("{{message}}", &message)
        .replace("{{eta}}", &eta)
        .replace("{{live}}", live)
        .replace("{{rid}}", &rid)
}

/// The built-in page's markup; [`builtin_page`] fills it.
const BUILTIN_PAGE: &str = r##"<!doctype html>
<html lang="{{lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{title}} · {{site}}</title>
<style>
:root{--bg:#f6f5f1;--card:#fff;--fg:#1d2220;--muted:#5f6a64;--line:#e3e2dc;--accent:#2f6f5e;--tint:#e7f0ec;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#121514;--card:#1a1f1d;--fg:#e7ece9;--muted:#9aa59f;--line:#2a312e;--accent:#83c7b1;--tint:#1f2c27}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;padding:20px}
.bar{position:fixed;top:0;left:0;right:0;height:3px;overflow:hidden;background:var(--line)}
.bar i{position:absolute;top:0;bottom:0;width:30%;background:var(--accent);border-radius:3px;animation:s 2.4s ease-in-out infinite}
@keyframes s{0%{left:-30%}100%{left:100%}}
main{width:100%;max-width:30rem;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px 26px 22px;display:grid;gap:14px}
.icon{width:44px;height:44px;border-radius:12px;background:var(--tint);display:grid;place-items:center}
.icon svg{width:24px;height:24px;stroke:var(--accent)}
.site{font:600 13px ui-monospace,Menlo,monospace;color:var(--muted);letter-spacing:.02em;overflow-wrap:anywhere}
h1{margin:0;font-size:1.6rem;line-height:1.2;letter-spacing:-.01em}
p{margin:0;color:var(--muted)}
.msg{color:var(--fg);background:var(--tint);border-radius:10px;padding:10px 12px;white-space:pre-line}
.eta{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}
.eta b{font-size:1.05rem}
.eta .in{color:var(--muted);font-size:.95rem}
footer{border-top:1px solid var(--line);padding-top:12px;display:flex;flex-wrap:wrap;gap:6px 14px;justify-content:space-between;font-size:.82rem;color:var(--muted)}
.live{display:inline-flex;gap:6px;align-items:center}
.live i{width:7px;height:7px;border-radius:50%;background:var(--accent);animation:p 2s ease-in-out infinite}
@keyframes p{50%{opacity:.25}}
.rid{font-family:ui-monospace,Menlo,monospace}
@media (prefers-reduced-motion:reduce){.bar i,.live i{animation:none}.bar i{left:0;width:100%;opacity:.5}}
</style>
</head>
<body>
<div class="bar" aria-hidden="true"><i></i></div>
<main>
<div class="icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8V20h3.2l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.4 2.4-2.3-.6-.6-2.3z"/></svg></div>
<div class="site">{{site}}</div>
<h1>{{title}}</h1>
<p>{{lead}}</p>
{{message}}
{{eta}}
<footer><span class="live"><i></i>{{live}}</span><span class="rid">{{rid}}</span></footer>
</main>
<script>
(function(){
var e=document.querySelector(".eta[data-until]");
function eta(){if(!e)return;var u=new Date(e.dataset.until),fr=e.dataset.lang==="fr",m=Math.max(1,Math.round((u-Date.now())/60000));
var h=u.getHours(),mi=("0"+u.getMinutes()).slice(-2);e.querySelector(".at").textContent=fr?h+"h"+mi:("0"+h).slice(-2)+":"+mi;
e.querySelector(".in").textContent=u>Date.now()?(fr?"dans environ "+m+" min":"in about "+m+" min"):"";}
eta();setInterval(eta,15000);
function check(){fetch(location.href,{method:"HEAD",cache:"no-store"}).then(function(r){if(r.status!==503)location.reload();},function(){});}
setInterval(check,30000);
})();
</script>
</body>
</html>
"##;

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
                until: None,
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
            body.contains("site.example:8080 is down for maintenance"),
            "{body}"
        );
        assert!(
            body.contains("Back as soon as possible."),
            "no end set: {body}"
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

    #[test]
    fn a_toggle_can_set_an_end() {
        let w = Toggle {
            enabled: true,
            for_secs: Some(1800),
            ..Default::default()
        }
        .into_window()
        .unwrap()
        .unwrap();
        let now = chrono::Utc::now();
        assert!(!w.expired(now));
        assert!((1795..=1800).contains(&w.retry_after(300, now)));
        assert!(w.expired(now + chrono::Duration::seconds(1801)));

        let until = (now + chrono::Duration::hours(2)).to_rfc3339();
        let w = Toggle {
            enabled: true,
            until: Some(until),
            ..Default::default()
        }
        .into_window()
        .unwrap()
        .unwrap();
        assert!(w.until.is_some());

        for bad in [
            Toggle {
                enabled: true,
                for_secs: Some(0),
                ..Default::default()
            },
            Toggle {
                enabled: true,
                for_secs: Some(MAX_WINDOW_SECS + 1),
                ..Default::default()
            },
            Toggle {
                enabled: true,
                until: Some("tomorrow".into()),
                ..Default::default()
            },
            Toggle {
                enabled: true,
                until: Some("2001-01-01T00:00:00Z".into()),
                ..Default::default()
            },
            Toggle {
                enabled: true,
                until: Some((now + chrono::Duration::hours(1)).to_rfc3339()),
                for_secs: Some(60),
                ..Default::default()
            },
        ] {
            assert!(bad.into_window().is_err());
        }
    }

    #[test]
    fn windows_past_their_end_are_closed_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/maintenance.json");
        let m = Maintenance::default();
        m.persist_to(&path).unwrap();
        let now = chrono::Utc::now();
        let ended = Window {
            until: Some((now - chrono::Duration::seconds(5)).to_rfc3339()),
            ..Default::default()
        };
        let running = Window {
            until: Some((now + chrono::Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };
        m.set_app("old", Some(ended.clone())).unwrap();
        m.set_app("new", Some(running)).unwrap();
        m.set_global(Some(ended)).unwrap();
        assert_eq!(
            m.expire_due(now).unwrap(),
            vec!["*".to_string(), "old".to_string()]
        );
        let state = m.snapshot();
        assert!(state.global.is_none());
        assert_eq!(state.apps.keys().collect::<Vec<_>>(), vec!["new"]);
        let reloaded = Maintenance::default();
        reloaded.persist_to(&path).unwrap();
        assert_eq!(
            reloaded.snapshot().apps.keys().collect::<Vec<_>>(),
            vec!["new"]
        );
        assert!(m.expire_due(now).unwrap().is_empty());
    }

    #[test]
    fn the_page_follows_the_browser_language() {
        let req = |al: &str| {
            Request::builder()
                .header("accept-language", al)
                .body(())
                .unwrap()
        };
        assert_eq!(language(&req("fr-FR,fr;q=0.9,en;q=0.8"), "auto"), Lang::Fr);
        assert_eq!(language(&req("en-US,en;q=0.9,fr;q=0.8"), "auto"), Lang::En);
        assert_eq!(language(&req("de-DE,fr;q=0.5"), "auto"), Lang::Fr);
        assert_eq!(language(&req("de-DE"), "auto"), Lang::En);
        assert_eq!(language(&req(""), "auto"), Lang::En);
        assert_eq!(language(&req("en"), "fr"), Lang::Fr);
        assert!(MaintenanceConfig {
            language: "es".into(),
            ..Default::default()
        }
        .validated()
        .is_err());
    }

    #[tokio::test]
    async fn the_builtin_page_says_when_the_site_is_back() {
        let vars = crate::response::error_pages::PageVars {
            host: "shop.example",
            app: "La <Boutique>",
            message: "Mise à jour",
            request_id: "abc",
            ..Default::default()
        };
        let until = chrono::DateTime::parse_from_rfc3339("2026-10-06T14:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let fr = builtin_page(Lang::Fr, &vars, Some(until));
        assert!(fr.contains("<html lang=\"fr\">"));
        assert!(fr.contains("On revient très vite"));
        assert!(
            fr.contains("La &lt;Boutique&gt; est en maintenance"),
            "{fr}"
        );
        assert!(fr.contains("Retour prévu vers <span class=\"at\">14:30 UTC</span>"));
        assert!(fr.contains("data-until=\"2026-10-06T14:30:00Z\""));
        assert!(fr.contains("503 · abc"));
        assert!(fr.len() < 6 * 1024, "{} bytes", fr.len());
        let en = builtin_page(Lang::En, &vars, None);
        assert!(en.contains("Back as soon as possible."));
        assert!(!en.contains("data-until=\""), "no end, no time to show");
    }

    #[test]
    fn maintenance_assets_are_plain_files_of_public_maintenance() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path().join("public/maintenance");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("style.css"), "body{}").unwrap();
        std::fs::write(assets.join("notes.exe"), "x").unwrap();
        std::fs::write(dir.path().join("public/secret.css"), "no").unwrap();

        let resp = serve_asset(dir.path(), "style.css", true).expect("served");
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );
        for refused in [
            "../secret.css",
            "a/b.css",
            ".hidden.css",
            "notes.exe",
            "missing.css",
            "",
        ] {
            assert!(
                serve_asset(dir.path(), refused, true).is_none(),
                "{refused}"
            );
        }
        assert!(
            serve_asset(dir.path(), "style.css", false).is_some(),
            "no symlink involved"
        );
    }

    #[test]
    fn durations_need_a_unit() {
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("1h30m").unwrap(), 5400);
        assert_eq!(parse_duration("2d").unwrap(), 172800);
        for bad in ["", "30", "m", "1x", "1h30"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
