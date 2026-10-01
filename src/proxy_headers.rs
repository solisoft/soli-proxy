//! Shared header-handling helpers used by both the public proxy
//! (`src/server/mod.rs`) and the admin app passthrough (`src/admin/mod.rs`).

use hyper::header::{
    HeaderName, HeaderValue, CONNECTION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use std::net::IpAddr;

/// Headers that must never cross the proxy/upstream boundary, per RFC 7230 §6.1.
/// `connection` is handled separately because we need to read its value (to
/// strip Connection-listed headers) before removing the header itself.
/// `proxy-connection` is not in the RFC but is the pre-standard spelling some
/// clients still send, and no backend has a use for it.
///
/// Static `HeaderName`s rather than `&str`: `HeaderMap::remove(&str)` parses
/// and validates the name on every call, eight times per request.
static HOP_BY_HOP: [HeaderName; 8] = [
    HeaderName::from_static("keep-alive"),
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
    HeaderName::from_static("proxy-connection"),
];

/// Strip RFC 7230 §6.1 hop-by-hop headers and any header whose name appears in
/// the request's `Connection:` header(s) before forwarding upstream.
///
/// Order matters: the `Connection` values must be read before `connection`
/// is removed, otherwise the Connection-listed strip becomes a no-op and
/// client-nominated hop-by-hop headers leak through. *Every* `Connection`
/// field is read, not just the first — `Connection: keep-alive` followed by
/// `Connection: x-secret` is two fields of one list (RFC 9110 §5.3).
///
/// The proxy runs this on the inbound request *before* any Lua hook sees it,
/// so a client's `Connection: x-user` cannot delete a header a script set —
/// it would otherwise be applied after the script, to the script's output.
pub fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .filter_map(|n| HeaderName::from_bytes(n.as_bytes()).ok())
        .collect();
    for h in &HOP_BY_HOP {
        headers.remove(h);
    }
    headers.remove(CONNECTION);
    for name in listed {
        headers.remove(name);
    }
}

/// Whether `name` (lower-case, as `HeaderName::as_str` yields it) is one of
/// the headers a proxy uses to describe the client to the backend:
/// `Forwarded`, any `X-Forwarded-*`, `X-Real-IP`. A client must never be the
/// one supplying them — see `set_forwarding_headers`.
pub fn is_forwarding_header(name: &str) -> bool {
    name == "forwarded" || name == "x-real-ip" || name.starts_with("x-forwarded-")
}

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Replace every client-supplied forwarding header with the proxy's own view
/// of the connection.
///
/// Backends trust these headers — for the client address in logs and rate
/// limits, for "was this HTTPS" in secure-cookie and redirect logic, for the
/// public host in absolute URLs. Anything the client sent under these names
/// is a claim, not a fact: `X-Real-IP: 127.0.0.1` would otherwise reach the
/// backend verbatim and pass an "admin from localhost only" check. So all of
/// `Forwarded`, `X-Forwarded-*` and `X-Real-IP` are removed first, then
/// `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` (the Host the
/// client asked for, before any rewrite) and `X-Real-IP` are set from what the
/// proxy itself observed.
///
/// Here the proxy is the edge: the chain starts here, so `X-Forwarded-For` is
/// the client address alone, not appended to. A request from a peer listed in
/// `[server] trusted_proxies` goes through `set_forwarding_headers_for`
/// instead, which keeps that proxy's chain.
pub fn set_forwarding_headers(
    headers: &mut hyper::HeaderMap,
    client_ip: Option<IpAddr>,
    is_tls: bool,
    original_host: Option<&str>,
) {
    strip_forwarding_headers(headers);
    if let Some(ip) = client_ip {
        if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
            headers.insert(X_FORWARDED_FOR.clone(), v.clone());
            headers.insert(X_REAL_IP.clone(), v);
        }
    }
    headers.insert(
        X_FORWARDED_PROTO.clone(),
        HeaderValue::from_static(if is_tls { "https" } else { "http" }),
    );
    if let Some(host) = original_host {
        if let Ok(v) = HeaderValue::from_str(host) {
            headers.insert(X_FORWARDED_HOST.clone(), v);
        }
    }
}

/// `set_forwarding_headers` for a request whose client was decided at the door
/// (see `crate::edge::ClientInfo`).
///
/// From a peer that is not a trusted proxy this is exactly
/// `set_forwarding_headers` with the peer as the client. From a trusted proxy
/// the chain it built is kept: `X-Forwarded-For` becomes the inbound chain
/// with the peer *appended* (every proxy adds the hop it received from), and
/// its `X-Forwarded-Proto` is kept when it says `http` or `https` — the proxy
/// in front is the one that saw the client's scheme. `X-Real-IP` is the
/// client the walk found. Everything else in the family is still dropped and
/// `X-Forwarded-Host` is still the Host as received.
pub fn set_forwarding_headers_for(
    headers: &mut hyper::HeaderMap,
    client: Option<&crate::edge::ClientInfo>,
    is_tls: bool,
    original_host: Option<&str>,
) {
    let Some(client) = client.filter(|c| c.trusted_peer) else {
        return set_forwarding_headers(headers, client.map(|c| c.ip), is_tls, original_host);
    };
    let mut chain = String::new();
    for field in headers.get_all(&X_FORWARDED_FOR) {
        if let Ok(v) = field.to_str() {
            let v = v.trim().trim_matches(',').trim();
            if !v.is_empty() {
                chain.push_str(v);
                chain.push_str(", ");
            }
        }
    }
    {
        use std::fmt::Write;
        let _ = write!(chain, "{}", client.peer);
    }
    let proto = headers
        .get(&X_FORWARDED_PROTO)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| match v.trim() {
            p if p.eq_ignore_ascii_case("https") => Some("https"),
            p if p.eq_ignore_ascii_case("http") => Some("http"),
            _ => None,
        });
    set_forwarding_headers(headers, Some(client.ip), is_tls, original_host);
    if let Ok(v) = HeaderValue::from_str(&chain) {
        headers.insert(X_FORWARDED_FOR.clone(), v);
    }
    if let Some(proto) = proto {
        headers.insert(X_FORWARDED_PROTO.clone(), HeaderValue::from_static(proto));
    }
}

/// Remove `Forwarded`, every `X-Forwarded-*` and `X-Real-IP`.
pub fn strip_forwarding_headers(headers: &mut hyper::HeaderMap) {
    // Fast path: most requests carry none, and collecting names allocates.
    if !headers.keys().any(|k| is_forwarding_header(k.as_str())) {
        return;
    }
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|k| is_forwarding_header(k.as_str()))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
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
    if let Ok(value) = HeaderValue::from_str(&joined) {
        headers.remove(COOKIE);
        headers.insert(COOKIE, value);
    }
}

/// Extract the host portion of an authority string, dropping any port.
/// Handles bracketed IPv6 literals (`[::1]:8080` -> `::1`).
fn host_part(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// Align the `Origin` header with a rewritten `Host` when forwarding to an
/// external https target under a different name.
///
/// When the target is `https://`, the proxy rewrites `Host` to the backend's
/// own authority (matching the TLS SNI). Backends that enforce CSRF by
/// comparing `Origin` against the request authority — Phoenix/Bonfire's
/// "Origin X does not match request authority Y" — then reject every
/// same-origin POST and WebSocket upgrade, because `Origin` still carries the
/// client-facing domain.
///
/// Only a same-origin request is rewritten: the Origin host must match the
/// client-facing Host. A genuinely cross-site `Origin` is forwarded untouched
/// so the backend's CSRF check still sees and rejects it.
pub fn rewrite_same_origin(
    headers: &mut hyper::HeaderMap,
    client_host: &str,
    backend_origin: &str,
) {
    use hyper::header::ORIGIN;
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return;
    };
    // Origin is scheme "://" authority (or the literal "null", which won't
    // split and is left alone).
    let Some((_, origin_authority)) = origin.split_once("://") else {
        return;
    };
    if !host_part(origin_authority).eq_ignore_ascii_case(host_part(client_host)) {
        return;
    }
    if let Ok(v) = HeaderValue::from_str(backend_origin) {
        headers.insert(ORIGIN, v);
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
    fn reads_every_connection_field_not_just_the_first() {
        let mut h = HeaderMap::new();
        h.append("connection", "keep-alive".parse().unwrap());
        h.append("connection", "x-secret".parse().unwrap());
        h.insert("x-secret", "1".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(
            h.get("x-secret").is_none(),
            "a header named in the second Connection field must be stripped"
        );
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn strips_proxy_connection() {
        let mut h = HeaderMap::new();
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.get("proxy-connection").is_none());
    }

    #[test]
    fn forwarding_headers_replace_every_client_claim() {
        let mut h = HeaderMap::new();
        h.insert("forwarded", "for=1.1.1.1;proto=https".parse().unwrap());
        h.append("x-forwarded-for", "1.1.1.1".parse().unwrap());
        h.append("x-forwarded-for", "2.2.2.2".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        h.insert("x-forwarded-host", "evil.example".parse().unwrap());
        h.insert("x-forwarded-port", "443".parse().unwrap());
        h.insert("x-forwarded-prefix", "/admin".parse().unwrap());
        h.insert("x-forwarded-ssl", "on".parse().unwrap());
        h.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        set_forwarding_headers(
            &mut h,
            Some("9.9.9.9".parse().unwrap()),
            false,
            Some("real.example"),
        );
        assert!(h.get("forwarded").is_none());
        assert!(h.get("x-forwarded-port").is_none());
        assert!(h.get("x-forwarded-prefix").is_none());
        assert!(h.get("x-forwarded-ssl").is_none());
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "9.9.9.9");
        assert_eq!(h.get("x-real-ip").unwrap(), "9.9.9.9");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "real.example");
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn forwarding_headers_without_peer_or_host_set_no_address() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        h.insert("x-forwarded-host", "evil.example".parse().unwrap());
        set_forwarding_headers(&mut h, None, true, None);
        assert!(h.get("x-real-ip").is_none());
        assert!(h.get("x-forwarded-for").is_none());
        assert!(h.get("x-forwarded-host").is_none());
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn a_trusted_peer_has_its_chain_appended_to_and_its_proto_kept() {
        use crate::edge::ClientInfo;
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.append("x-forwarded-for", "10.0.0.7".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        h.insert("x-forwarded-port", "443".parse().unwrap());
        h.insert("x-real-ip", "6.6.6.6".parse().unwrap());
        let client = ClientInfo {
            ip: "1.2.3.4".parse().unwrap(),
            peer: "10.0.0.1".parse().unwrap(),
            trusted_peer: true,
        };
        set_forwarding_headers_for(&mut h, Some(&client), false, Some("real.example"));
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(
            h.get("x-forwarded-for").unwrap(),
            "1.2.3.4, 10.0.0.7, 10.0.0.1"
        );
        assert_eq!(h.get("x-real-ip").unwrap(), "1.2.3.4");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert!(h.get("x-forwarded-port").is_none());
        assert_eq!(h.get("x-forwarded-host").unwrap(), "real.example");

        // A proto that is neither http nor https is replaced by the proxy's.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "gopher".parse().unwrap());
        set_forwarding_headers_for(&mut h, Some(&client), true, None);
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.1");

        // An untrusted peer: today's behaviour, the chain and proto replaced.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        let direct = ClientInfo::direct("9.9.9.9".parse().unwrap());
        set_forwarding_headers_for(&mut h, Some(&direct), false, None);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "9.9.9.9");
        assert_eq!(h.get("x-real-ip").unwrap(), "9.9.9.9");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn is_forwarding_header_matches_the_family() {
        for n in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-whatever",
            "x-real-ip",
        ] {
            assert!(is_forwarding_header(n), "{n}");
        }
        for n in ["x-forwarded", "x-real", "forwarded-for", "host"] {
            assert!(!is_forwarding_header(n), "{n}");
        }
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
    fn rewrites_same_origin_to_backend() {
        let mut h = HeaderMap::new();
        h.insert("origin", "https://bonfire-app.pro".parse().unwrap());
        rewrite_same_origin(&mut h, "bonfire-app.pro", "https://bonfire.solisoft.net");
        assert_eq!(h.get("origin").unwrap(), "https://bonfire.solisoft.net");
    }

    #[test]
    fn rewrites_same_origin_ignoring_ports_and_case() {
        let mut h = HeaderMap::new();
        h.insert("origin", "https://Bonfire-App.pro:8443".parse().unwrap());
        rewrite_same_origin(
            &mut h,
            "bonfire-app.pro:443",
            "https://bonfire.solisoft.net",
        );
        assert_eq!(h.get("origin").unwrap(), "https://bonfire.solisoft.net");
    }

    #[test]
    fn leaves_cross_site_origin_untouched() {
        let mut h = HeaderMap::new();
        h.insert("origin", "https://evil.example".parse().unwrap());
        rewrite_same_origin(&mut h, "bonfire-app.pro", "https://bonfire.solisoft.net");
        assert_eq!(h.get("origin").unwrap(), "https://evil.example");
    }

    #[test]
    fn leaves_null_origin_untouched() {
        let mut h = HeaderMap::new();
        h.insert("origin", "null".parse().unwrap());
        rewrite_same_origin(&mut h, "bonfire-app.pro", "https://bonfire.solisoft.net");
        assert_eq!(h.get("origin").unwrap(), "null");
    }

    #[test]
    fn rewrite_without_origin_is_noop() {
        let mut h = HeaderMap::new();
        h.insert("x-keep", "yes".parse().unwrap());
        rewrite_same_origin(&mut h, "bonfire-app.pro", "https://bonfire.solisoft.net");
        assert!(h.get("origin").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn host_part_handles_ipv6() {
        assert_eq!(host_part("[::1]:8080"), "::1");
        assert_eq!(host_part("example.com:443"), "example.com");
        assert_eq!(host_part("example.com"), "example.com");
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
