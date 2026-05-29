//! Shared header-handling helpers used by both the public proxy
//! (`src/server/mod.rs`) and the admin app passthrough (`src/admin/mod.rs`).

/// Headers that must never cross the proxy/upstream boundary, per RFC 7230 §6.1.
/// `connection` is captured separately because we need to read its value (to
/// strip Connection-listed headers) before removing the header itself.
const HOP_BY_HOP: &[&str] = &[
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip RFC 7230 §6.1 hop-by-hop headers and any header whose name appears in
/// the request's `Connection:` header before forwarding upstream.
///
/// Order matters: the `Connection` value must be captured before `connection`
/// is removed, otherwise the Connection-listed strip becomes a no-op and
/// client-nominated hop-by-hop headers leak through.
pub fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let conn_header = headers
        .get("connection")
        .and_then(|v| v.to_str().ok().map(String::from));
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    headers.remove("connection");
    if let Some(conn) = conn_header {
        for name in conn.split(',').map(str::trim) {
            if !name.is_empty() {
                headers.remove(name);
            }
        }
    }
}

/// Coalesce multiple `Cookie` request headers into a single `Cookie:` line.
///
/// HTTP/2 clients (every modern browser) routinely split the cookies of a
/// request across several `cookie` header fields — RFC 7540 §8.1.2.5 explicitly
/// allows this and requires an intermediary converting to HTTP/1.1 to
/// concatenate them into one field joined by "; ". We terminate HTTP/2 from the
/// client and forward to HTTP/1.1 upstreams, so we must do that join here.
///
/// Without it, HTTP/1.1 servers that read only the first `Cookie` header (e.g.
/// redbean) see just the first cookie and treat every other cookie as missing —
/// which silently breaks cookie-based auth for browser traffic while leaving
/// single-header clients like curl unaffected.
pub fn coalesce_cookies(headers: &mut hyper::HeaderMap) {
    use hyper::header::COOKIE;
    // Fast path: 0 or 1 cookie header is already RFC-compliant for HTTP/1.1.
    if headers.get_all(COOKIE).iter().take(2).count() <= 1 {
        return;
    }
    let joined = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    // Only rewrite if the joined value is a valid header value; otherwise leave
    // the originals untouched rather than dropping the cookies entirely.
    if let Ok(value) = hyper::header::HeaderValue::from_str(&joined) {
        headers.remove(COOKIE);
        headers.insert(COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn removes_const_hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("upgrade", "h2c".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.get("keep-alive").is_none());
        assert!(h.get("upgrade").is_none());
        assert!(h.get("transfer-encoding").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn removes_connection_listed_headers() {
        let mut h = HeaderMap::new();
        h.insert("connection", "X-Auth, X-Custom".parse().unwrap());
        h.insert("x-auth", "secret".parse().unwrap());
        h.insert("x-custom", "1".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.get("connection").is_none());
        assert!(
            h.get("x-auth").is_none(),
            "Connection-listed X-Auth should be stripped"
        );
        assert!(
            h.get("x-custom").is_none(),
            "Connection-listed X-Custom should be stripped"
        );
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn handles_missing_connection_header() {
        let mut h = HeaderMap::new();
        h.insert("x-keep", "yes".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn ignores_empty_connection_entries() {
        let mut h = HeaderMap::new();
        h.insert("connection", ", ,X-Foo,".parse().unwrap());
        h.insert("x-foo", "v".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.get("x-foo").is_none());
    }

    #[test]
    fn coalesces_split_cookie_headers() {
        let mut h = HeaderMap::new();
        h.append("cookie", "sdb_server=abc".parse().unwrap());
        h.append("cookie", "sdb_token=xyz".parse().unwrap());
        coalesce_cookies(&mut h);
        assert_eq!(h.get_all("cookie").iter().count(), 1);
        assert_eq!(h.get("cookie").unwrap(), "sdb_server=abc; sdb_token=xyz");
    }

    #[test]
    fn leaves_single_cookie_header_untouched() {
        let mut h = HeaderMap::new();
        h.insert("cookie", "sdb_server=abc; sdb_token=xyz".parse().unwrap());
        coalesce_cookies(&mut h);
        assert_eq!(h.get_all("cookie").iter().count(), 1);
        assert_eq!(h.get("cookie").unwrap(), "sdb_server=abc; sdb_token=xyz");
    }

    #[test]
    fn coalesce_no_cookie_is_noop() {
        let mut h = HeaderMap::new();
        h.insert("x-keep", "yes".parse().unwrap());
        coalesce_cookies(&mut h);
        assert!(h.get("cookie").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn coalesce_skips_empty_fields() {
        let mut h = HeaderMap::new();
        h.append("cookie", "a=1".parse().unwrap());
        h.append("cookie", "".parse().unwrap());
        h.append("cookie", "b=2".parse().unwrap());
        coalesce_cookies(&mut h);
        assert_eq!(h.get("cookie").unwrap(), "a=1; b=2");
    }
}
