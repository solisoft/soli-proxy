//! What happens to a response on its way out of the proxy, after routing has
//! produced it: compression ([`compress`]), the HTML pages that replace the
//! proxy's own plain-text errors ([`error_pages`]), and maintenance mode
//! ([`maintenance`]), which answers before routing for a site that is down on
//! purpose.
//!
//! The request path calls into these modules from a handful of small call
//! sites in `server/mod.rs`; the logic lives here.

pub mod compress;
pub mod error_pages;
pub mod maintenance;

use hyper::Response;

/// Who wrote a response's body, when it was not the proxy's own error path.
///
/// Error pages replace only what the proxy itself generated: a backend's 404
/// is the backend's page, and a Lua `deny` carries the body its script chose.
/// Responses are tagged where they are produced, and an untagged error is,
/// by elimination, the proxy's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyOwner {
    /// Relayed from a backend (possibly with Lua `on_response` edits).
    Upstream,
    /// A Lua hook's `deny`.
    Script,
    /// Already rendered by the proxy as a page — the maintenance response.
    Rendered,
}

/// Response extension carrying [`BodyOwner`] and the route's or app's
/// compression override (`@compress:on|off`, `compress =` in `app.infos`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseTag {
    pub owner: BodyOwner,
    pub compress: Option<bool>,
}

/// Tag a backend's response.
///
/// Inserting an extension allocates (the extensions map is created on first
/// insert), so this only does it when the tag will be read: an error status,
/// which error pages must leave alone, or a compression override. An ordinary
/// 200 on a route without `@compress:` pays nothing.
///
/// Called again after a Lua `on_response` hook rewrote the status: an
/// override already on the response is kept.
pub fn mark_upstream<B>(resp: &mut Response<B>, compress: Option<bool>) {
    let compress = compress.or_else(|| tag(resp).and_then(|t| t.compress));
    if compress.is_some() || resp.status().as_u16() >= 400 {
        resp.extensions_mut().insert(ResponseTag {
            owner: BodyOwner::Upstream,
            compress,
        });
    }
}

/// Tag a response whose body a Lua hook (or the proxy's own page renderer)
/// chose, so error pages never replace it.
pub fn mark_owned<B>(resp: &mut Response<B>, owner: BodyOwner) {
    let compress = tag(resp).and_then(|t| t.compress);
    resp.extensions_mut()
        .insert(ResponseTag { owner, compress });
}

/// The tag on `resp`, if any.
pub(crate) fn tag<B>(resp: &Response<B>) -> Option<ResponseTag> {
    resp.extensions().get::<ResponseTag>().copied()
}

/// Whether the client takes HTML: some `Accept` header lists `text/html`.
/// `*/*` alone does not count — `curl` and a script's `fetch` send that, and
/// they want the plain-text error they always got. No allocation.
pub(crate) fn accepts_html(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(hyper::header::ACCEPT)
        .iter()
        .any(|v| contains_ignore_ascii_case(v.as_bytes(), b"text/html"))
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Escape `value` for HTML text and attribute context. Every template
/// variable goes through this: `{{host}}` and `{{request_id}}` are whatever
/// the client sent.
pub(crate) fn push_html_escaped(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// A loaded `Config` with nothing configured, for unit tests.
#[cfg(test)]
pub(crate) fn test_config() -> crate::config::Config {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("proxy.conf");
    std::fs::write(&conf, "").unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        "[server]\nbind = \"127.0.0.1:0\"\nhttps_port = 443\n",
    )
    .unwrap();
    let manager = crate::config::ConfigManager::new(conf.to_str().unwrap()).unwrap();
    let config = manager.get_config();
    (*config).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escaping_covers_markup_and_quotes() {
        let mut out = String::new();
        push_html_escaped(&mut out, r#"<script>"a'&b"</script>"#);
        assert_eq!(out, "&lt;script&gt;&quot;a&#39;&amp;b&quot;&lt;/script&gt;");
    }

    #[test]
    fn accepts_html_reads_every_accept_header() {
        let mut headers = hyper::HeaderMap::new();
        assert!(!accepts_html(&headers));
        headers.append(hyper::header::ACCEPT, "*/*".parse().unwrap());
        assert!(!accepts_html(&headers));
        headers.append(
            hyper::header::ACCEPT,
            "Text/HTML,application/xhtml+xml;q=0.9".parse().unwrap(),
        );
        assert!(accepts_html(&headers));
    }

    #[test]
    fn plain_upstream_success_is_not_tagged() {
        let mut ok = Response::new(());
        mark_upstream(&mut ok, None);
        assert_eq!(tag(&ok), None);

        let mut err = Response::new(());
        *err.status_mut() = hyper::StatusCode::NOT_FOUND;
        mark_upstream(&mut err, None);
        assert_eq!(tag(&err).map(|t| t.owner), Some(BodyOwner::Upstream));

        let mut off = Response::new(());
        mark_upstream(&mut off, Some(false));
        assert_eq!(tag(&off).and_then(|t| t.compress), Some(false));
    }
}
