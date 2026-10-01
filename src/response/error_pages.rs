//! Custom HTML pages for the errors the proxy itself generates.
//!
//! The proxy's own errors — 502 when a backend is unreachable, 503 when every
//! target's circuit is open, 504 on a timeout, 421 for an unknown host, 401,
//! 413, 429… — are short plain-text bodies. With `[error_pages] dir` set, a
//! browser gets an HTML page instead:
//!
//! ```text
//! /etc/soli-proxy/errors/
//!   502.html        one status
//!   5xx.html        any other 5xx
//!   4xx.html        any other 4xx
//!   default.html    anything else
//!   maintenance.html  the maintenance-mode page (see `maintenance`)
//! ```
//!
//! An app can carry its own in `<site>/error_pages/`, consulted first for
//! requests to its hosts. Pages are read once, when the config is loaded (or
//! the app discovered) — never per request — and each is capped at 64 KiB.
//!
//! Only proxy-generated errors are replaced. A backend's own error page is
//! the backend's business, and a Lua `deny` carries the body its script
//! chose; `intercept_upstream_errors = true` extends the pages to backend
//! errors too. A client that does not list `text/html` in `Accept` (an API
//! client, `curl`) keeps getting the plain text.
//!
//! Templates may use `{{status}}`, `{{reason}}`, `{{host}}`, `{{request_id}}`
//! and, in the maintenance page, `{{message}}`. Values are HTML-escaped.
//! `{{request_id}}` is the `X-Request-Id` of the response if the proxy set
//! one, else the request's `X-Request-Id` header, else empty.

use crate::server::BoxBody;
use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// `[error_pages]` in `config.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ErrorPagesConfig {
    /// Directory holding the pages. Unset: no global pages.
    pub dir: Option<PathBuf>,
    /// Also replace error responses (4xx/5xx) that came from a backend.
    /// Default `false`: a backend's error page is its own.
    pub intercept_upstream_errors: bool,
    /// The pages read from `dir` when the config was loaded.
    #[serde(skip)]
    pub pages: Option<Arc<ErrorPages>>,
}

impl ErrorPagesConfig {
    /// Read the pages from `dir`. A missing or unreadable directory, or a page
    /// over the size cap, fails the config load like any other error in it:
    /// fatal at startup, the previous config kept on a reload.
    pub fn loaded(mut self) -> anyhow::Result<Self> {
        self.pages = match &self.dir {
            Some(dir) => {
                let pages = ErrorPages::load(dir, &mut |name| {
                    crate::app::read_tenant_file(&dir.join(name), true)
                })
                .map_err(|e| anyhow::anyhow!("[error_pages] dir {}: {}", dir.display(), e))?;
                Some(Arc::new(pages))
            }
            None => None,
        };
        Ok(self)
    }
}

/// Largest total size of one app's pages. Each is also capped at 64 KiB
/// (`read_tenant_file`); this bounds what a tenant can make the proxy hold.
const MAX_APP_PAGES_BYTES: usize = 256 * 1024;

/// A set of loaded pages.
#[derive(Default)]
pub struct ErrorPages {
    by_status: HashMap<u16, String>,
    client_errors: Option<String>,
    server_errors: Option<String>,
    default: Option<String>,
    maintenance: Option<String>,
}

impl std::fmt::Debug for ErrorPages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut statuses: Vec<_> = self.by_status.keys().collect();
        statuses.sort();
        f.debug_struct("ErrorPages")
            .field("statuses", &statuses)
            .field("4xx", &self.client_errors.is_some())
            .field("5xx", &self.server_errors.is_some())
            .field("default", &self.default.is_some())
            .field("maintenance", &self.maintenance.is_some())
            .finish()
    }
}

/// Where a file name goes, if it is a page name at all.
enum Slot {
    Status(u16),
    ClientErrors,
    ServerErrors,
    Default,
    Maintenance,
}

fn slot_for(file_name: &str) -> Option<Slot> {
    let stem = file_name.strip_suffix(".html")?;
    Some(match stem {
        "4xx" => Slot::ClientErrors,
        "5xx" => Slot::ServerErrors,
        "default" => Slot::Default,
        "maintenance" => Slot::Maintenance,
        _ if stem.len() == 3 && stem.bytes().all(|b| b.is_ascii_digit()) => {
            let status: u16 = stem.parse().ok()?;
            if !(400..=599).contains(&status) {
                return None;
            }
            Slot::Status(status)
        }
        _ => return None,
    })
}

impl ErrorPages {
    /// Read every page in `dir` through `read` (a file name to its content).
    /// Other files are ignored.
    fn load(
        dir: &Path,
        read: &mut dyn FnMut(&str) -> anyhow::Result<Option<String>>,
    ) -> anyhow::Result<Self> {
        let mut names: Vec<String> = std::fs::read_dir(dir)?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| slot_for(name).is_some())
            .collect();
        names.sort();
        let mut pages = ErrorPages::default();
        for name in names {
            let Some(content) = read(&name)? else {
                continue;
            };
            match slot_for(&name).expect("filtered above") {
                Slot::Status(status) => {
                    pages.by_status.insert(status, content);
                }
                Slot::ClientErrors => pages.client_errors = Some(content),
                Slot::ServerErrors => pages.server_errors = Some(content),
                Slot::Default => pages.default = Some(content),
                Slot::Maintenance => pages.maintenance = Some(content),
            }
        }
        Ok(pages)
    }

    /// Load an app's `error_pages/` directory, which its tenant controls.
    ///
    /// `Ok(None)` when there is none. With `follow_symlinks` false (multi-
    /// tenant mode) neither the directory nor a page may be a symlink: the
    /// directory is opened `O_NOFOLLOW` and its pages read through that open
    /// descriptor (`/proc/self/fd/N/<page>`), so swapping the directory for a
    /// symlink after the check cannot redirect the reads to a file the tenant
    /// should not see — and then serve it as their error page. Each page goes
    /// through `read_tenant_file` (regular files only, non-blocking open,
    /// 64 KiB), and an app's pages together are capped at 256 KiB.
    pub fn load_for_site(site: &Path, follow_symlinks: bool) -> anyhow::Result<Option<Self>> {
        let dir = site.join("error_pages");
        if follow_symlinks {
            if !dir.is_dir() {
                return Ok(None);
            }
            return Self::load_capped(&dir).map(Some);
        }
        let handle = match open_dir_nofollow(&dir) {
            Ok(Some(handle)) => handle,
            Ok(None) => return Ok(None),
            Err(e) => anyhow::bail!("{}: {}", dir.display(), e),
        };
        let via_fd = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw()));
        Self::load_capped_nofollow(&via_fd).map(Some)
    }

    fn load_capped(dir: &Path) -> anyhow::Result<Self> {
        let mut total = 0usize;
        Self::load(dir, &mut |name| {
            capped(
                &mut total,
                crate::app::read_tenant_file(&dir.join(name), true)?,
            )
        })
    }

    fn load_capped_nofollow(dir: &Path) -> anyhow::Result<Self> {
        let mut total = 0usize;
        Self::load(dir, &mut |name| {
            capped(
                &mut total,
                crate::app::read_tenant_file(&dir.join(name), false)?,
            )
        })
    }

    pub fn is_empty(&self) -> bool {
        self.by_status.is_empty()
            && self.client_errors.is_none()
            && self.server_errors.is_none()
            && self.default.is_none()
            && self.maintenance.is_none()
    }

    /// The page for `status`: its own, then its class's, then the default.
    pub fn for_status(&self, status: u16) -> Option<&str> {
        self.by_status
            .get(&status)
            .or(match status {
                400..=499 => self.client_errors.as_ref(),
                500..=599 => self.server_errors.as_ref(),
                _ => None,
            })
            .or(self.default.as_ref())
            .map(String::as_str)
    }

    pub fn maintenance(&self) -> Option<&str> {
        self.maintenance.as_deref()
    }
}

fn capped(total: &mut usize, content: Option<String>) -> anyhow::Result<Option<String>> {
    if let Some(ref c) = content {
        *total += c.len();
        if *total > MAX_APP_PAGES_BYTES {
            anyhow::bail!(
                "pages total more than {} bytes; the rest are ignored",
                MAX_APP_PAGES_BYTES
            );
        }
    }
    Ok(content)
}

/// An open directory descriptor, closed on drop.
struct DirFd(std::fs::File);

impl DirFd {
    fn as_raw(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.0.as_raw_fd()
    }
}

/// Open `dir` as a directory without following a symlink in its last
/// component. `Ok(None)` when it does not exist.
fn open_dir_nofollow(dir: &Path) -> std::io::Result<Option<DirFd>> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
    {
        Ok(file) => Ok(Some(DirFd(file))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => Err(
            std::io::Error::other("not a directory, or a symlink (not followed)"),
        ),
        Err(e) => Err(e),
    }
}

/// The values a page is filled with.
pub(crate) struct PageVars<'a> {
    pub status: StatusCode,
    pub host: &'a str,
    pub request_id: &'a str,
    pub message: &'a str,
}

/// Fill a template's `{{variables}}`, escaping each value. Unknown
/// `{{names}}` are left as written.
pub(crate) fn render(template: &str, vars: &PageVars<'_>) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = after[..end].trim();
        let value: Option<&str> = match name {
            "status" => Some(vars.status.as_str()),
            "reason" => Some(vars.status.canonical_reason().unwrap_or("")),
            "host" => Some(vars.host),
            "request_id" => Some(vars.request_id),
            "message" => Some(vars.message),
            _ => None,
        };
        match value {
            Some(v) => super::push_html_escaped(&mut out, v),
            None => out.push_str(&rest[start..start + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Longest client-supplied value (`Host`, `X-Request-Id`) put into a page.
const MAX_VAR_LEN: usize = 256;

fn header_str(v: Option<&HeaderValue>) -> &str {
    let s = v.and_then(|v| v.to_str().ok()).unwrap_or("");
    match s.char_indices().nth(MAX_VAR_LEN) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// What a page needs from the request, captured before the request is
/// consumed. Only built when there are pages to serve and the client takes
/// HTML; every other request carries a `None` and pays nothing more.
pub struct ErrorCtx {
    host: Option<HeaderValue>,
    request_id: Option<HeaderValue>,
    /// Set when some app has pages: looked up by host, on the error path only.
    apps: Option<Arc<crate::app::AppManager>>,
}

/// Capture what a page will need, if a page could be served at all.
pub fn capture<B>(
    req: &Request<B>,
    config: &crate::config::Config,
    apps: Option<&Arc<crate::app::AppManager>>,
) -> Option<ErrorCtx> {
    let apps = apps.filter(|m| m.any_error_pages()).cloned();
    if (config.error_pages.pages.is_none() && apps.is_none()) || !super::accepts_html(req.headers())
    {
        return None;
    }
    let host = req.headers().get(header::HOST).cloned().or_else(|| {
        req.uri()
            .authority()
            .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
    });
    Some(ErrorCtx {
        host,
        request_id: req.headers().get("x-request-id").cloned(),
        apps,
    })
}

/// The pages of the app serving `host`, if it has any.
pub(crate) fn app_pages(
    apps: &crate::app::AppManager,
    host_header: &str,
) -> Option<Arc<ErrorPages>> {
    let host = host_header.split(':').next().unwrap_or(host_header);
    apps.routes().get(host)?.error_pages.clone()
}

/// Replace a proxy-generated error's body with its page, when there is one.
pub fn apply(
    result: Result<Response<BoxBody>, hyper::Error>,
    ctx: Option<ErrorCtx>,
    config: &crate::config::Config,
) -> Result<Response<BoxBody>, hyper::Error> {
    let resp = result?;
    let Some(ctx) = ctx else {
        return Ok(resp);
    };
    let status = resp.status();
    if !status.is_client_error() && !status.is_server_error() {
        return Ok(resp);
    }
    let replaceable = match super::tag(&resp).map(|t| t.owner) {
        None => true,
        Some(super::BodyOwner::Upstream) => config.error_pages.intercept_upstream_errors,
        Some(super::BodyOwner::Script | super::BodyOwner::Rendered) => false,
    };
    if !replaceable {
        return Ok(resp);
    }
    let host = header_str(ctx.host.as_ref());
    let app_pages = ctx.apps.as_deref().and_then(|m| app_pages(m, host));
    let template = app_pages
        .as_deref()
        .and_then(|p| p.for_status(status.as_u16()))
        .or_else(|| {
            config
                .error_pages
                .pages
                .as_deref()
                .and_then(|p| p.for_status(status.as_u16()))
        });
    let Some(template) = template else {
        return Ok(resp);
    };
    let request_id = header_str(
        resp.headers()
            .get("x-request-id")
            .or(ctx.request_id.as_ref()),
    )
    .to_string();
    let html = render(
        template,
        &PageVars {
            status,
            host,
            request_id: &request_id,
            message: "",
        },
    );
    Ok(html_response(resp, html))
}

/// `resp` with `html` as its body: its status and its other headers
/// (`Retry-After`, `WWW-Authenticate`, `Allow`…) are kept.
pub(crate) fn html_response(resp: Response<BoxBody>, html: String) -> Response<BoxBody> {
    let (mut parts, _) = resp.into_parts();
    let headers = &mut parts.headers;
    headers.remove(header::CONTENT_ENCODING);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(html.len()));
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    Response::from_parts(parts, crate::server::full(Bytes::from(html)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn vars(status: u16) -> PageVars<'static> {
        PageVars {
            status: StatusCode::from_u16(status).unwrap(),
            host: "<b>evil.example</b>",
            request_id: "abc\"123",
            message: "",
        }
    }

    #[test]
    fn templates_fill_and_escape() {
        let out = render(
            "<h1>{{status}} {{ reason }}</h1><p>{{host}}</p><i>{{request_id}}</i>{{unknown}}{{",
            &vars(502),
        );
        assert_eq!(
            out,
            "<h1>502 Bad Gateway</h1><p>&lt;b&gt;evil.example&lt;/b&gt;</p>\
             <i>abc&quot;123</i>{{unknown}}{{"
        );
    }

    #[test]
    fn page_names_map_to_slots() {
        assert!(matches!(slot_for("502.html"), Some(Slot::Status(502))));
        assert!(matches!(slot_for("4xx.html"), Some(Slot::ClientErrors)));
        assert!(matches!(
            slot_for("maintenance.html"),
            Some(Slot::Maintenance)
        ));
        assert!(slot_for("302.html").is_none());
        assert!(slot_for("502.htm").is_none());
        assert!(slot_for("index.html").is_none());
        assert!(slot_for("5022.html").is_none());
    }

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn lookup_falls_back_from_status_to_class_to_default() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "502.html", "five-oh-two");
        write(dir.path(), "5xx.html", "server");
        write(dir.path(), "default.html", "anything");
        write(dir.path(), "notes.txt", "ignored");
        let config = ErrorPagesConfig {
            dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        }
        .loaded()
        .unwrap();
        let pages = config.pages.unwrap();
        assert_eq!(pages.for_status(502), Some("five-oh-two"));
        assert_eq!(pages.for_status(504), Some("server"));
        assert_eq!(pages.for_status(404), Some("anything"));
        assert_eq!(pages.maintenance(), None);
    }

    #[test]
    fn a_missing_or_oversized_global_dir_fails_the_load() {
        let config = ErrorPagesConfig {
            dir: Some(PathBuf::from("/nonexistent/soli-error-pages")),
            ..Default::default()
        };
        assert!(config.loaded().is_err());

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "502.html", &"x".repeat(65 * 1024));
        let config = ErrorPagesConfig {
            dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert!(config.loaded().is_err());
    }

    #[test]
    fn tenant_pages_refuse_symlinks_in_multi_tenant_mode() {
        let site = tempfile::tempdir().unwrap();
        let secret = tempfile::tempdir().unwrap();
        write(secret.path(), "502.html", "operator secret");

        // The directory itself a symlink to somewhere else.
        std::os::unix::fs::symlink(secret.path(), site.path().join("error_pages")).unwrap();
        assert!(ErrorPages::load_for_site(site.path(), false).is_err());
        // Single-tenant: the operator wrote it, the link is followed.
        let pages = ErrorPages::load_for_site(site.path(), true)
            .unwrap()
            .unwrap();
        assert_eq!(pages.for_status(502), Some("operator secret"));

        // A page that is a symlink.
        std::fs::remove_file(site.path().join("error_pages")).unwrap();
        std::fs::create_dir(site.path().join("error_pages")).unwrap();
        std::os::unix::fs::symlink(
            secret.path().join("502.html"),
            site.path().join("error_pages/502.html"),
        )
        .unwrap();
        assert!(ErrorPages::load_for_site(site.path(), false).is_err());

        // A plain page loads.
        std::fs::remove_file(site.path().join("error_pages/502.html")).unwrap();
        write(&site.path().join("error_pages"), "503.html", "tenant page");
        let pages = ErrorPages::load_for_site(site.path(), false)
            .unwrap()
            .unwrap();
        assert_eq!(pages.for_status(503), Some("tenant page"));

        // No directory at all.
        let empty = tempfile::tempdir().unwrap();
        assert!(ErrorPages::load_for_site(empty.path(), false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn tenant_pages_are_capped_in_total() {
        let site = tempfile::tempdir().unwrap();
        let dir = site.path().join("error_pages");
        std::fs::create_dir(&dir).unwrap();
        for status in 500..505 {
            write(&dir, &format!("{status}.html"), &"x".repeat(60 * 1024));
        }
        assert!(ErrorPages::load_for_site(site.path(), false).is_err());
    }

    fn config_with(dir: &Path, intercept: bool) -> crate::config::Config {
        let mut config = crate::response::test_config();
        config.error_pages = ErrorPagesConfig {
            dir: Some(dir.to_path_buf()),
            intercept_upstream_errors: intercept,
            pages: None,
        }
        .loaded()
        .unwrap();
        config
    }

    fn request(accept: &str) -> Request<()> {
        Request::builder()
            .uri("/x")
            .header("host", "site.example")
            .header("accept", accept)
            .header("x-request-id", "req-1")
            .body(())
            .unwrap()
    }

    fn error(status: u16) -> Response<BoxBody> {
        let mut resp = Response::new(crate::server::full("Bad Gateway"));
        *resp.status_mut() = StatusCode::from_u16(status).unwrap();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        resp
    }

    async fn body(resp: Response<BoxBody>) -> String {
        String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn only_proxy_errors_are_replaced_and_only_for_html_clients() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "5xx.html",
            "<p>{{status}} on {{host}} ({{request_id}})</p>",
        );
        let config = config_with(dir.path(), false);
        let html = request("text/html,*/*;q=0.8");

        // A proxy-generated 502 for a browser: the page.
        let ctx = capture(&html, &config, None);
        let resp = apply(Ok(error(502)), ctx, &config).unwrap();
        assert_eq!(resp.status(), 502);
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(
            resp.headers()[header::RETRY_AFTER],
            "1",
            "other headers kept"
        );
        assert_eq!(body(resp).await, "<p>502 on site.example (req-1)</p>");

        // An API client: plain text, as before.
        assert!(capture(&request("application/json"), &config, None).is_none());

        // A backend's own 502: left alone.
        let mut upstream = error(502);
        crate::response::mark_upstream(&mut upstream, None);
        let resp = apply(Ok(upstream), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "Bad Gateway");

        // A Lua deny: left alone.
        let mut denied = error(503);
        crate::response::mark_owned(&mut denied, crate::response::BodyOwner::Script);
        let resp = apply(Ok(denied), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "Bad Gateway");

        // A success is never touched; a 4xx without a page neither.
        let ok = Response::new(crate::server::full("fine"));
        let resp = apply(Ok(ok), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "fine");
        let resp = apply(Ok(error(404)), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "Bad Gateway");

        // The response's own X-Request-Id wins over the request's.
        let mut with_id = error(504);
        with_id
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("resp-9"));
        let resp = apply(Ok(with_id), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "<p>504 on site.example (resp-9)</p>");

        // intercept_upstream_errors extends the pages to backend errors.
        let config = config_with(dir.path(), true);
        let mut upstream = error(500);
        crate::response::mark_upstream(&mut upstream, None);
        let resp = apply(Ok(upstream), capture(&html, &config, None), &config).unwrap();
        assert_eq!(body(resp).await, "<p>500 on site.example (req-1)</p>");
    }
}
