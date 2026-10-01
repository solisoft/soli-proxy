//! The edge of the proxy: who the client is, which request this is.
//!
//! ```toml
//! [server]
//! trusted_proxies = ["cloudflare", "10.0.0.0/8"]  # whose forwarding headers count
//! real_ip_header = "X-Forwarded-For"              # or "CF-Connecting-IP", "X-Real-IP"
//! proxy_protocol = "off"                          # "v1" | "v2" | "any", or { https = "v2" }
//! request_id_header = "X-Request-Id"              # "" turns request IDs off
//! ```
//!
//! **Client identity.** Out of the box the proxy is the edge: the TCP peer is
//! the client, and every `X-Forwarded-For` it sent is a claim, dropped. Behind
//! Cloudflare or a load balancer that made every client look like the
//! balancer — one rate-limit bucket for the whole internet, the balancer's
//! address in every log and in `X-Real-IP`. `trusted_proxies` names the peers
//! whose word is taken: for a request from one of them, the client is found by
//! walking `X-Forwarded-For` from the right, skipping the trusted hops — the
//! first address that is not a trusted proxy is the client (`real_ip_header`
//! may name a single-address header instead). A request from any other peer is
//! handled exactly as before. The result, a [`ClientInfo`], is put in the
//! request's extensions at the door; [`client_ip`] reads it back.
//!
//! **PROXY protocol** (v1 text, v2 binary): a TCP balancer that cannot add
//! headers — an AWS NLB, HAProxy in TCP mode — prepends the client's address to
//! the connection instead. Opt-in per listener, accepted only from
//! `trusted_proxies` (any other peer is disconnected), read before TLS and
//! HTTP; the address it carries is the connection's peer for everything after,
//! the per-IP connection cap included.
//!
//! **Request IDs.** Every request gets one, forwarded upstream and returned to
//! the client under `request_id_header`. An incoming ID is kept only from a
//! trusted peer, and only when it is 1–128 visible ASCII characters; otherwise
//! the proxy generates 128 random bits as 32 hex digits.

use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Address ranges
// ---------------------------------------------------------------------------

/// Cloudflare's published edge ranges, the `"cloudflare"` preset.
///
/// To refresh, compare with <https://www.cloudflare.com/ips-v4> and
/// <https://www.cloudflare.com/ips-v6> (plain text, one CIDR per line) and
/// update both lists; `cloudflare_preset_parses` checks they still parse. The
/// lists change rarely — the last addition was years ago — but a range missing
/// here means requests through it are attributed to Cloudflare's address
/// rather than the visitor's, which is the safe way round.
pub const CLOUDFLARE_IPV4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// See [`CLOUDFLARE_IPV4`].
pub const CLOUDFLARE_IPV6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// The `"private"` preset: RFC 1918 and IPv6 unique-local addresses — a
/// balancer on the same private network.
const PRIVATE_RANGES: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

/// The `"loopback"` preset: a tunnel daemon (cloudflared, …) on this host.
const LOOPBACK_RANGES: &[&str] = &["127.0.0.0/8", "::1/128"];

/// The address as the rest of the proxy compares it: an IPv4-mapped IPv6
/// address (what a dual-stack `[::]` listener reports for an IPv4 peer) is
/// its IPv4 address, or `10.0.0.0/8` would never match it.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// One `address/prefix` range, stored as (network, mask).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cidr {
    V4(u32, u32),
    V6(u128, u128),
}

impl Cidr {
    /// `10.0.0.0/8`, `2400:cb00::/32`, or a bare address (a /32 or /128).
    /// Host bits under the mask are ignored, as every CIDR tool does.
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("{:?} is not an IP address or CIDR range", s))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = match prefix {
            None => max,
            Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse().unwrap_or(u32::MAX)
            }
            Some(_) => u32::MAX,
        };
        if prefix > max {
            return Err(format!("{:?}: the prefix length must be 0 to {}", s, max));
        }
        Ok(match ip {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                Cidr::V4(u32::from(a) & mask, mask)
            }
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                // `::ffff:10.0.0.0/104` is `10.0.0.0/8`: addresses are
                // compared in their canonical (unmapped) form.
                Some(v4) if prefix >= 96 => {
                    let mask = u32::MAX.checked_shl(128 - prefix).unwrap_or(0);
                    Cidr::V4(u32::from(v4) & mask, mask)
                }
                _ => {
                    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                    Cidr::V6(u128::from(a) & mask, mask)
                }
            },
        })
    }
}

/// `[server] trusted_proxies`: the peers whose forwarding headers, request ID
/// and PROXY protocol header are believed.
///
/// Entries are CIDR ranges, bare addresses, or the presets `"cloudflare"`,
/// `"private"` and `"loopback"`. Empty (the default) trusts nobody.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    /// As written, for serialization.
    entries: Vec<String>,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl TrustedProxies {
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        let mut out = TrustedProxies::default();
        for entry in entries {
            let entry = entry.as_ref().trim();
            let preset: Option<&[&[&str]]> = match entry.to_ascii_lowercase().as_str() {
                "cloudflare" => Some(&[CLOUDFLARE_IPV4, CLOUDFLARE_IPV6]),
                "private" => Some(&[PRIVATE_RANGES]),
                "loopback" => Some(&[LOOPBACK_RANGES]),
                _ => None,
            };
            let ranges: Vec<&str> = match preset {
                Some(lists) => lists.iter().flat_map(|l| l.iter().copied()).collect(),
                None => vec![entry],
            };
            for range in ranges {
                match Cidr::parse(range).map_err(|e| format!("trusted_proxies: {}", e))? {
                    Cidr::V4(n, m) => out.v4.push((n, m)),
                    Cidr::V6(n, m) => out.v6.push((n, m)),
                }
            }
            out.entries.push(entry.to_string());
        }
        Ok(out)
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Whether `ip` is in one of the ranges. A linear scan: the Cloudflare
    /// preset is 22 ranges, each a mask and a compare.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match canonical_ip(ip) {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().any(|&(n, m)| a & m == n)
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().any(|&(n, m)| a & m == n)
            }
        }
    }
}

impl Serialize for TrustedProxies {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.entries.serialize(s)
    }
}

impl<'de> Deserialize<'de> for TrustedProxies {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // A single string (`trusted_proxies = "cloudflare"`) or a list.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        let list = match OneOrMany::deserialize(d)? {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        };
        TrustedProxies::parse(&list).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// `[server] real_ip_header`: where a trusted peer says who the client is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RealIpHeader {
    /// The `X-Forwarded-For` chain, walked right to left (the default).
    #[default]
    XForwardedFor,
    /// A header holding the client address alone, set by the trusted proxy:
    /// `CF-Connecting-IP`, `X-Real-IP`, `True-Client-IP`, `Fly-Client-IP`…
    Single(HeaderName),
}

impl Serialize for RealIpHeader {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            RealIpHeader::XForwardedFor => s.serialize_str("X-Forwarded-For"),
            RealIpHeader::Single(name) => s.serialize_str(name.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for RealIpHeader {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let name = raw.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("x-forwarded-for") {
            return Ok(RealIpHeader::XForwardedFor);
        }
        if name.eq_ignore_ascii_case("forwarded") {
            return Err(serde::de::Error::custom(
                "real_ip_header: the RFC 7239 Forwarded header is not supported; use \
                 X-Forwarded-For or a single-address header such as CF-Connecting-IP",
            ));
        }
        HeaderName::from_bytes(name.as_bytes())
            .map(RealIpHeader::Single)
            .map_err(|_| {
                serde::de::Error::custom(format!("real_ip_header: {:?} is not a header name", raw))
            })
    }
}

/// Which PROXY protocol versions a listener expects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    #[default]
    Off,
    V1,
    V2,
    Any,
}

impl ProxyProtocolMode {
    fn accepts_v1(self) -> bool {
        matches!(self, ProxyProtocolMode::V1 | ProxyProtocolMode::Any)
    }
    fn accepts_v2(self) -> bool {
        matches!(self, ProxyProtocolMode::V2 | ProxyProtocolMode::Any)
    }
}

/// `[server] proxy_protocol`: one mode for both listeners
/// (`proxy_protocol = "v2"`), or one each
/// (`proxy_protocol = { http = "off", https = "v2" }`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyProtocolConfig {
    pub http: ProxyProtocolMode,
    pub https: ProxyProtocolMode,
}

impl Serialize for ProxyProtocolConfig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        if self.http == self.https {
            return self.http.serialize(s);
        }
        let mut map = s.serialize_map(Some(2))?;
        map.serialize_entry("http", &self.http)?;
        map.serialize_entry("https", &self.https)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProxyProtocolConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PerListener {
            #[serde(default)]
            http: ProxyProtocolMode,
            #[serde(default)]
            https: ProxyProtocolMode,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Shape {
            Both(ProxyProtocolMode),
            Each(PerListener),
        }
        match Shape::deserialize(d).map_err(|_| {
            serde::de::Error::custom(
                "proxy_protocol: expected \"off\", \"v1\", \"v2\", \"any\", or a table \
                 { http = …, https = … } of those",
            )
        })? {
            Shape::Both(m) => Ok(ProxyProtocolConfig { http: m, https: m }),
            Shape::Each(p) => Ok(ProxyProtocolConfig {
                http: p.http,
                https: p.https,
            }),
        }
    }
}

/// `[server] request_id_header`: the header carrying the request ID, or none
/// (`""`) to turn request IDs off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestIdHeader(pub Option<HeaderName>);

impl Default for RequestIdHeader {
    fn default() -> Self {
        RequestIdHeader(Some(HeaderName::from_static("x-request-id")))
    }
}

impl Serialize for RequestIdHeader {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_ref().map_or("", |n| n.as_str()))
    }
}

impl<'de> Deserialize<'de> for RequestIdHeader {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let name = raw.trim();
        if name.is_empty() {
            return Ok(RequestIdHeader(None));
        }
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            serde::de::Error::custom(format!("request_id_header: {:?} is not a header name", raw))
        })?;
        // The forwarding family is replaced at the door, and the framing and
        // routing headers are not the proxy's to stamp.
        let reserved = crate::proxy_headers::is_forwarding_header(header.as_str())
            || matches!(
                header.as_str(),
                "host"
                    | "connection"
                    | "content-length"
                    | "transfer-encoding"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "keep-alive"
                    | "cookie"
                    | "set-cookie"
                    | "authorization"
            );
        if reserved {
            return Err(serde::de::Error::custom(format!(
                "request_id_header: {:?} is reserved; pick a dedicated header",
                raw
            )));
        }
        Ok(RequestIdHeader(Some(header)))
    }
}

/// The `[server]` keys this module owns, flattened into `ServerConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeConfig {
    #[serde(default)]
    pub trusted_proxies: TrustedProxies,
    #[serde(default)]
    pub real_ip_header: RealIpHeader,
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
    #[serde(default)]
    pub request_id_header: RequestIdHeader,
}

/// Which listener a connection came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Http,
    Https,
}

impl EdgeConfig {
    /// Checks across keys: PROXY protocol is only ever accepted from a trusted
    /// peer, so enabling it with nobody trusted would refuse every connection.
    pub fn validate(&self) -> anyhow::Result<()> {
        let pp_on = self.proxy_protocol.http != ProxyProtocolMode::Off
            || self.proxy_protocol.https != ProxyProtocolMode::Off;
        if pp_on && self.trusted_proxies.is_empty() {
            anyhow::bail!(
                "[server] proxy_protocol is on but trusted_proxies is empty: the PROXY \
                 header is only accepted from trusted peers, so every connection would be \
                 refused. List the balancer's addresses in trusted_proxies."
            );
        }
        Ok(())
    }

    /// The PROXY protocol mode for `listener`, `None` when off.
    pub fn proxy_protocol_for(&self, listener: Listener) -> Option<ProxyProtocolMode> {
        let mode = match listener {
            Listener::Http => self.proxy_protocol.http,
            Listener::Https => self.proxy_protocol.https,
        };
        (mode != ProxyProtocolMode::Off).then_some(mode)
    }

    /// Whether `peer` is a trusted proxy.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        !self.trusted_proxies.is_empty() && self.trusted_proxies.contains(peer)
    }
}

// ---------------------------------------------------------------------------
// Client identity
// ---------------------------------------------------------------------------

/// Who sent a request, as the proxy decided at the door. In the request's
/// extensions for every request with a known peer; read it with [`client_ip`]
/// or [`client_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    /// The client: the peer itself, or — when the peer is a trusted proxy —
    /// the address its forwarding headers name. Use this for identity (rate
    /// limits, logs, allowlists).
    pub ip: IpAddr,
    /// The connection's peer: the TCP peer, or the source a PROXY protocol
    /// header carried.
    pub peer: IpAddr,
    /// Whether `peer` is in `trusted_proxies` — whether its forwarding
    /// headers and request ID were believed.
    pub trusted_peer: bool,
}

/// Longest `X-Forwarded-For` walk: past this many hops, all trusted, the
/// last one reached is taken as the client. Bounds the work a client can
/// cause by sending a long chain through a trusted proxy that appends to it.
const MAX_XFF_HOPS: usize = 32;

impl ClientInfo {
    /// A peer that is not a trusted proxy: it is the client.
    pub fn direct(peer: IpAddr) -> Self {
        let peer = canonical_ip(peer);
        ClientInfo {
            ip: peer,
            peer,
            trusted_peer: false,
        }
    }

    /// Decide who the client is for a request from `peer` carrying `headers`.
    pub fn resolve(peer: IpAddr, headers: &HeaderMap, cfg: &EdgeConfig) -> Self {
        let peer = canonical_ip(peer);
        if !cfg.trusts(peer) {
            return ClientInfo::direct(peer);
        }
        let ip = match &cfg.real_ip_header {
            RealIpHeader::XForwardedFor => client_from_xff(headers, &cfg.trusted_proxies),
            RealIpHeader::Single(name) => headers
                .get_all(name)
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(parse_forwarded_ip),
        };
        ClientInfo {
            ip: ip.map(canonical_ip).unwrap_or(peer),
            peer,
            trusted_peer: true,
        }
    }
}

/// The client named by an `X-Forwarded-For` chain that reached us through a
/// trusted proxy: walking right to left (most recent hop first), the first
/// address that is not itself a trusted proxy. Everything to its left was
/// written by the client or by proxies we know nothing about, so it is not
/// believed. When every hop is trusted the leftmost is the client; an entry
/// that is not an address stops the walk at the last good hop. `None` when
/// there is no usable entry at all (the peer is then the client).
fn client_from_xff(headers: &HeaderMap, trusted: &TrustedProxies) -> Option<IpAddr> {
    let mut last = None;
    let mut hops = 0;
    for field in headers.get_all(&X_FORWARDED_FOR).iter().rev() {
        let Ok(field) = field.to_str() else {
            return last;
        };
        for entry in field.rsplit(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some(ip) = parse_forwarded_ip(entry) else {
                return last;
            };
            let ip = canonical_ip(ip);
            if !trusted.contains(ip) {
                return Some(ip);
            }
            last = Some(ip);
            hops += 1;
            if hops >= MAX_XFF_HOPS {
                return last;
            }
        }
    }
    last
}

/// One address as forwarding headers write it: `1.2.3.4`, `1.2.3.4:5678`,
/// `2001:db8::1`, `[2001:db8::1]` or `[2001:db8::1]:443`.
fn parse_forwarded_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let (addr, port) = s.split_once(':')?;
    if !is_port(port) {
        return None;
    }
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

fn is_port(s: &str) -> bool {
    !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())
}

/// The client address the proxy decided on for this request (see
/// [`ClientInfo::ip`]). `None` only for a request with no known peer.
pub fn client_ip(ext: &http::Extensions) -> Option<IpAddr> {
    ext.get::<ClientInfo>().map(|c| c.ip)
}

/// The whole [`ClientInfo`] for this request.
pub fn client_info(ext: &http::Extensions) -> Option<&ClientInfo> {
    ext.get::<ClientInfo>()
}

/// For a peer that is not trusted, remove the header `real_ip_header` names
/// when it is not one the door already replaces. `CF-Connecting-IP` from an
/// arbitrary client is as much a claim as `X-Forwarded-For`, and the
/// operator has said backends may read it.
pub fn strip_untrusted_real_ip(headers: &mut HeaderMap, client: &ClientInfo, cfg: &EdgeConfig) {
    if client.trusted_peer {
        return;
    }
    if let RealIpHeader::Single(name) = &cfg.real_ip_header {
        if !crate::proxy_headers::is_forwarding_header(name.as_str()) {
            headers.remove(name);
        }
    }
}

// ---------------------------------------------------------------------------
// Request IDs
// ---------------------------------------------------------------------------

/// This request's ID, in its extensions (and under `request_id_header`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub HeaderValue);

/// The request ID, if request IDs are on.
pub fn request_id(ext: &http::Extensions) -> Option<&HeaderValue> {
    ext.get::<RequestId>().map(|r| &r.0)
}

/// Whether an incoming request ID is acceptable: 1 to 128 visible ASCII
/// characters (no space, no control character).
pub fn valid_request_id(v: &[u8]) -> bool {
    !v.is_empty() && v.len() <= 128 && v.iter().all(|b| (0x21..=0x7e).contains(b))
}

thread_local! {
    /// Per-thread generator state, seeded from the standard library's
    /// per-thread random hash keys (themselves from the OS, once per thread).
    static RNG: Cell<u64> = Cell::new({
        use std::hash::BuildHasher;
        std::collections::hash_map::RandomState::new().hash_one(std::time::SystemTime::now())
    });
}

/// wyrand: 64 bits per call, no syscall, no lock. IDs need to be distinct,
/// not secret.
fn next_u64() -> u64 {
    RNG.with(|state| {
        let s = state.get().wrapping_add(0xa076_1d64_78bd_642f);
        state.set(s);
        let t = u128::from(s) * u128::from(s ^ 0xe703_7ed1_a0b4_28db);
        ((t >> 64) as u64) ^ (t as u64)
    })
}

/// A fresh request ID: 128 random bits as 32 lower-case hex digits.
pub fn generate_request_id() -> HeaderValue {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, word) in [next_u64(), next_u64()].into_iter().enumerate() {
        for j in 0..16 {
            out[i * 16 + j] = HEX[((word >> (60 - 4 * j)) & 0xf) as usize];
        }
    }
    // Hex digits are always a valid header value.
    HeaderValue::from_bytes(&out).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// Give the request its ID: the one a trusted peer sent (a single, valid
/// field), or a new one. The header is set to it — replacing whatever an
/// untrusted client sent — and it is returned for the response and the logs.
pub fn stamp_request_id(
    headers: &mut HeaderMap,
    name: &HeaderName,
    trusted_peer: bool,
) -> HeaderValue {
    if trusted_peer {
        let mut fields = headers.get_all(name).iter();
        if let (Some(v), None) = (fields.next(), fields.next()) {
            if valid_request_id(v.as_bytes()) {
                return v.clone();
            }
        }
    }
    let id = generate_request_id();
    headers.insert(name.clone(), id.clone());
    id
}

// ---------------------------------------------------------------------------
// PROXY protocol
// ---------------------------------------------------------------------------

/// How long a connection on a PROXY-protocol listener may take to send its
/// header.
pub const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest PROXY header accepted, in bytes. A v1 line is at most 107 bytes;
/// a v2 header is 16 bytes plus addresses (at most 216 for UNIX sockets) plus
/// TLVs, which balancers use for small things (a VPC endpoint ID, an ALPN,
/// an SNI). Anything larger is refused rather than buffered.
pub const PROXY_HEADER_MAX: usize = 1024;

const V1_MAX: usize = 107;
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// What [`parse_proxy_header`] made of the bytes seen so far.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyHeader {
    /// Not enough bytes yet to decide.
    Incomplete,
    /// A complete header of `len` bytes. `source` is the client it names, or
    /// `None` for a header that names none (v1 `UNKNOWN`, v2 `LOCAL` — a
    /// balancer's own health check — or a non-IP family): the TCP peer stands.
    Complete {
        len: usize,
        source: Option<SocketAddr>,
    },
    /// Not a header this listener accepts.
    Invalid(&'static str),
}

/// Parse a PROXY protocol header at the start of `buf`.
pub fn parse_proxy_header(buf: &[u8], mode: ProxyProtocolMode) -> ProxyHeader {
    let Some(&first) = buf.first() else {
        return ProxyHeader::Incomplete;
    };
    if first == b'P' && mode.accepts_v1() {
        return parse_v1(buf);
    }
    if first == V2_SIGNATURE[0] && mode.accepts_v2() {
        return parse_v2(buf);
    }
    ProxyHeader::Invalid("no PROXY protocol header")
}

fn parse_v1(buf: &[u8]) -> ProxyHeader {
    const PREFIX: &[u8] = b"PROXY ";
    let n = buf.len().min(PREFIX.len());
    if buf[..n] != PREFIX[..n] {
        return ProxyHeader::Invalid("no PROXY protocol header");
    }
    let window = &buf[..buf.len().min(V1_MAX)];
    let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= V1_MAX {
            ProxyHeader::Invalid("PROXY v1 line too long")
        } else {
            ProxyHeader::Incomplete
        };
    };
    let Ok(line) = std::str::from_utf8(&buf[PREFIX.len()..end]) else {
        return ProxyHeader::Invalid("PROXY v1 line is not ASCII");
    };
    let len = end + 2;
    let mut parts = line.split(' ');
    let proto = parts.next().unwrap_or("");
    if proto == "UNKNOWN" {
        // "the receiver must ignore anything presented before the CRLF"
        return ProxyHeader::Complete { len, source: None };
    }
    let fields: Vec<&str> = parts.collect();
    let &[src, dst, sport, dport] = fields.as_slice() else {
        return ProxyHeader::Invalid("PROXY v1 line is malformed");
    };
    let src: Option<IpAddr> = match proto {
        "TCP4" => src.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
        "TCP6" => src.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        _ => return ProxyHeader::Invalid("PROXY v1 protocol is not TCP4, TCP6 or UNKNOWN"),
    };
    let ports_ok = [sport, dport]
        .iter()
        .all(|p| is_port(p) && (p.len() == 1 || !p.starts_with('0')) && p.parse::<u16>().is_ok());
    let dst_ok = match proto {
        "TCP4" => dst.parse::<Ipv4Addr>().is_ok(),
        _ => dst.parse::<Ipv6Addr>().is_ok(),
    };
    match (src, ports_ok && dst_ok) {
        (Some(ip), true) => ProxyHeader::Complete {
            len,
            source: Some(SocketAddr::new(ip, sport.parse().unwrap_or(0))),
        },
        _ => ProxyHeader::Invalid("PROXY v1 addresses are malformed"),
    }
}

fn parse_v2(buf: &[u8]) -> ProxyHeader {
    let n = buf.len().min(V2_SIGNATURE.len());
    if buf[..n] != V2_SIGNATURE[..n] {
        return ProxyHeader::Invalid("no PROXY protocol header");
    }
    if buf.len() < 16 {
        return ProxyHeader::Incomplete;
    }
    let version = buf[12] >> 4;
    let command = buf[12] & 0x0f;
    if version != 2 {
        return ProxyHeader::Invalid("PROXY v2 version is not 2");
    }
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let len = 16 + addr_len;
    if len > PROXY_HEADER_MAX {
        return ProxyHeader::Invalid("PROXY v2 header too large");
    }
    if buf.len() < len {
        return ProxyHeader::Incomplete;
    }
    let body = &buf[16..len];
    match command {
        // LOCAL: the balancer speaking for itself (a health check).
        0x0 => return ProxyHeader::Complete { len, source: None },
        0x1 => {}
        _ => return ProxyHeader::Invalid("PROXY v2 command is not LOCAL or PROXY"),
    }
    let family = buf[13] >> 4;
    let transport = buf[13] & 0x0f;
    match family {
        // UNSPEC, UNIX: no IP address to take.
        0x0 | 0x3 => ProxyHeader::Complete { len, source: None },
        0x1 | 0x2 if transport != 0x1 => ProxyHeader::Invalid("PROXY v2 transport is not STREAM"),
        0x1 => {
            if body.len() < 12 {
                return ProxyHeader::Invalid("PROXY v2 IPv4 addresses are truncated");
            }
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            ProxyHeader::Complete {
                len,
                source: Some(SocketAddr::new(IpAddr::V4(ip), port)),
            }
        }
        0x2 => {
            if body.len() < 36 {
                return ProxyHeader::Invalid("PROXY v2 IPv6 addresses are truncated");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            ProxyHeader::Complete {
                len,
                source: Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
            }
        }
        _ => ProxyHeader::Invalid("PROXY v2 address family is unknown"),
    }
}

/// Read and consume the PROXY header at the start of `stream`, within
/// [`PROXY_HEADER_TIMEOUT`]. Returns the client address it carries, or `None`
/// when it names none (keep the TCP peer). An error means the connection must
/// be closed.
///
/// The header is peeked, then exactly its length read, so the bytes after it
/// (a TLS ClientHello, an HTTP request) stay in the socket for whoever reads
/// next — no wrapper stream needed. Headers arrive in one segment in practice;
/// should one be split, the peek is retried every few milliseconds.
pub async fn read_proxy_header(
    stream: &mut tokio::net::TcpStream,
    mode: ProxyProtocolMode,
) -> std::io::Result<Option<SocketAddr>> {
    use std::io::{Error, ErrorKind};
    use tokio::io::AsyncReadExt;
    let deadline = tokio::time::Instant::now() + PROXY_HEADER_TIMEOUT;
    let timed_out = || Error::new(ErrorKind::TimedOut, "no PROXY protocol header in time");
    let mut buf = [0u8; PROXY_HEADER_MAX];
    loop {
        let n = tokio::time::timeout_at(deadline, stream.peek(&mut buf))
            .await
            .map_err(|_| timed_out())??;
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before its PROXY protocol header",
            ));
        }
        match parse_proxy_header(&buf[..n], mode) {
            ProxyHeader::Complete { len, source } => {
                stream.read_exact(&mut buf[..len]).await?;
                return Ok(source);
            }
            ProxyHeader::Invalid(why) => return Err(Error::new(ErrorKind::InvalidData, why)),
            ProxyHeader::Incomplete => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(timed_out());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted(list: &[&str]) -> EdgeConfig {
        EdgeConfig {
            trusted_proxies: TrustedProxies::parse(list).unwrap(),
            ..Default::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let t = TrustedProxies::parse(&["10.0.0.0/8", "192.168.1.7", "2400:cb00::/32"]).unwrap();
        assert!(t.contains(ip("10.1.2.3")));
        assert!(!t.contains(ip("11.0.0.1")));
        assert!(t.contains(ip("192.168.1.7")));
        assert!(!t.contains(ip("192.168.1.8")));
        assert!(t.contains(ip("2400:cb00:1::1")));
        assert!(!t.contains(ip("2400:cb01::1")));
        // A dual-stack listener reports IPv4 peers mapped.
        assert!(t.contains(ip("::ffff:10.9.9.9")));
        // Host bits are ignored; /0 matches its whole family.
        let t = TrustedProxies::parse(&["10.1.2.3/8", "0.0.0.0/0"]).unwrap();
        assert!(t.contains(ip("8.8.8.8")));
        assert!(!t.contains(ip("::1")));
        for bad in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/x",
            "nope",
            "10.0.0/8",
            "",
        ] {
            assert!(TrustedProxies::parse(&[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cloudflare_preset_parses() {
        let t = TrustedProxies::parse(&["Cloudflare"]).unwrap();
        assert_eq!(t.v4.len(), CLOUDFLARE_IPV4.len());
        assert_eq!(t.v6.len(), CLOUDFLARE_IPV6.len());
        assert!(t.contains(ip("173.245.48.1")));
        assert!(t.contains(ip("2606:4700::6810:84e5")));
        assert!(!t.contains(ip("1.1.1.1")));
        let t = TrustedProxies::parse(&["private", "loopback"]).unwrap();
        assert!(t.contains(ip("172.20.0.1")) && t.contains(ip("::1")) && t.contains(ip("fd00::1")));
    }

    #[test]
    fn untrusted_peer_is_the_client_whatever_it_claims() {
        let cfg = trusted(&["10.0.0.0/8"]);
        let c = ClientInfo::resolve(ip("203.0.113.5"), &xff(&["1.2.3.4"]), &cfg);
        assert_eq!(c, ClientInfo::direct(ip("203.0.113.5")));
        // Nobody trusted: today's behaviour.
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["1.2.3.4"]), &EdgeConfig::default());
        assert_eq!(c.ip, ip("10.0.0.1"));
        assert!(!c.trusted_peer);
    }

    #[test]
    fn xff_is_walked_right_to_left_skipping_trusted_hops() {
        let cfg = trusted(&["10.0.0.0/8"]);
        // client, spoofed-by-client, real client, internal hop
        let h = xff(&["6.6.6.6, 1.2.3.4", "10.0.0.7"]);
        let c = ClientInfo::resolve(ip("10.0.0.1"), &h, &cfg);
        assert_eq!(c.ip, ip("1.2.3.4"));
        assert_eq!(c.peer, ip("10.0.0.1"));
        assert!(c.trusted_peer);
        // Every hop trusted: the leftmost is the client.
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["10.0.0.3, 10.0.0.2"]), &cfg);
        assert_eq!(c.ip, ip("10.0.0.3"));
        // No header: the peer.
        let c = ClientInfo::resolve(ip("10.0.0.1"), &HeaderMap::new(), &cfg);
        assert_eq!(c.ip, ip("10.0.0.1"));
        // Garbage stops the walk at the last good hop.
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["1.2.3.4, junk, 10.0.0.9"]), &cfg);
        assert_eq!(c.ip, ip("10.0.0.9"));
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["junk"]), &cfg);
        assert_eq!(c.ip, ip("10.0.0.1"));
        // Ports, brackets and mapped addresses.
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["1.2.3.4:5555"]), &cfg);
        assert_eq!(c.ip, ip("1.2.3.4"));
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&["[2001:db8::1]:443"]), &cfg);
        assert_eq!(c.ip, ip("2001:db8::1"));
        let c = ClientInfo::resolve(ip("::ffff:10.0.0.1"), &xff(&["::ffff:1.2.3.4"]), &cfg);
        assert_eq!(c.ip, ip("1.2.3.4"));
        assert_eq!(c.peer, ip("10.0.0.1"));
    }

    #[test]
    fn a_long_trusted_chain_is_cut_short() {
        let cfg = trusted(&["10.0.0.0/8"]);
        let chain = vec!["10.0.0.5"; 1000].join(", ");
        let c = ClientInfo::resolve(ip("10.0.0.1"), &xff(&[&chain]), &cfg);
        assert_eq!(c.ip, ip("10.0.0.5"));
    }

    #[test]
    fn a_single_address_header_can_name_the_client() {
        let mut cfg = trusted(&["cloudflare"]);
        cfg.real_ip_header = RealIpHeader::Single(HeaderName::from_static("cf-connecting-ip"));
        let mut h = xff(&["9.9.9.9"]);
        h.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        let c = ClientInfo::resolve(ip("173.245.48.10"), &h, &cfg);
        assert_eq!(c.ip, ip("198.51.100.7"));
        // Unparseable: the peer.
        h.insert("cf-connecting-ip", "x".parse().unwrap());
        assert_eq!(
            ClientInfo::resolve(ip("173.245.48.10"), &h, &cfg).ip,
            ip("173.245.48.10")
        );
        // From an untrusted peer the header is stripped.
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "127.0.0.1".parse().unwrap());
        let c = ClientInfo::resolve(ip("203.0.113.1"), &h, &cfg);
        strip_untrusted_real_ip(&mut h, &c, &cfg);
        assert!(h.get("cf-connecting-ip").is_none());
    }

    #[test]
    fn config_keys_deserialize() {
        #[derive(Deserialize)]
        struct T {
            #[serde(flatten)]
            edge: EdgeConfig,
        }
        let t: T = toml::from_str("").unwrap();
        assert_eq!(t.edge, EdgeConfig::default());
        assert_eq!(
            t.edge.request_id_header.0.as_ref().map(|n| n.as_str()),
            Some("x-request-id")
        );
        let t: T = toml::from_str(
            r#"
trusted_proxies = "cloudflare"
real_ip_header = "CF-Connecting-IP"
proxy_protocol = { https = "v2" }
request_id_header = ""
"#,
        )
        .unwrap();
        assert!(t.edge.trusts(ip("173.245.48.1")));
        assert_eq!(
            t.edge.real_ip_header,
            RealIpHeader::Single(HeaderName::from_static("cf-connecting-ip"))
        );
        assert_eq!(t.edge.proxy_protocol_for(Listener::Http), None);
        assert_eq!(
            t.edge.proxy_protocol_for(Listener::Https),
            Some(ProxyProtocolMode::V2)
        );
        assert_eq!(t.edge.request_id_header.0, None);
        let t: T =
            toml::from_str("proxy_protocol = \"any\"\ntrusted_proxies = [\"10.0.0.1\"]").unwrap();
        assert_eq!(t.edge.proxy_protocol.http, ProxyProtocolMode::Any);
        assert!(t.edge.validate().is_ok());
        for bad in [
            "trusted_proxies = [\"10.0.0.0/40\"]",
            "real_ip_header = \"Forwarded\"",
            "real_ip_header = \"bad header\"",
            "proxy_protocol = \"v3\"",
            "proxy_protocol = { http = \"v1\", tcp = \"v2\" }",
            "request_id_header = \"X-Forwarded-Id\"",
            "request_id_header = \"Host\"",
        ] {
            assert!(toml::from_str::<T>(bad).is_err(), "{bad}");
        }
        // PROXY protocol with nobody trusted would refuse every connection.
        let t: T = toml::from_str("proxy_protocol = \"v1\"").unwrap();
        assert!(t.edge.validate().is_err());
    }

    #[test]
    fn request_ids_are_kept_only_from_trusted_peers_and_only_when_valid() {
        let name = HeaderName::from_static("x-request-id");
        let mut h = HeaderMap::new();
        h.insert(&name, "abc-123".parse().unwrap());
        assert_eq!(stamp_request_id(&mut h, &name, true), "abc-123");
        assert_eq!(h.get(&name).unwrap(), "abc-123");
        // Untrusted: replaced.
        let id = stamp_request_id(&mut h, &name, false);
        assert_ne!(id, "abc-123");
        assert_eq!(h.get(&name).unwrap(), &id);
        assert_eq!(h.get_all(&name).iter().count(), 1);
        // Trusted but invalid, or repeated: replaced.
        for bad in ["has space", &"x".repeat(129), ""] {
            let mut h = HeaderMap::new();
            h.insert(&name, HeaderValue::from_str(bad).unwrap());
            assert_ne!(stamp_request_id(&mut h, &name, true), bad);
        }
        let mut h = HeaderMap::new();
        h.append(&name, "a".parse().unwrap());
        h.append(&name, "b".parse().unwrap());
        let id = stamp_request_id(&mut h, &name, true);
        assert_eq!(h.get_all(&name).iter().collect::<Vec<_>>(), vec![&id]);
        assert!(valid_request_id(&[b'x'; 128]));
        assert!(!valid_request_id("é".as_bytes()));
    }

    #[test]
    fn generated_request_ids_are_32_hex_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let id = generate_request_id();
            let s = id.to_str().unwrap().to_string();
            assert_eq!(s.len(), 32);
            assert!(s
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            assert!(seen.insert(s));
        }
    }

    fn v2(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut out = V2_SIGNATURE.to_vec();
        out.push(0x20 | command);
        out.push(family);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn proxy_v1_headers() {
        use ProxyProtocolMode::*;
        let line = b"PROXY TCP4 198.51.100.22 203.0.113.7 35646 443\r\nGET / HTTP/1.1\r\n";
        assert_eq!(
            parse_proxy_header(line, V1),
            ProxyHeader::Complete {
                len: 48,
                source: Some("198.51.100.22:35646".parse().unwrap())
            }
        );
        assert!(matches!(
            parse_proxy_header(line, Any),
            ProxyHeader::Complete { .. }
        ));
        assert!(matches!(
            parse_proxy_header(line, V2),
            ProxyHeader::Invalid(_)
        ));
        let line6 = b"PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n";
        assert_eq!(
            parse_proxy_header(line6, V1),
            ProxyHeader::Complete {
                len: line6.len(),
                source: Some("[2001:db8::1]:1".parse().unwrap())
            }
        );
        assert_eq!(
            parse_proxy_header(b"PROXY UNKNOWN whatever\r\n", V1),
            ProxyHeader::Complete {
                len: 24,
                source: None
            }
        );
        // Truncated: wait for more; every prefix of a good line is incomplete.
        for cut in 0..48 {
            assert_eq!(
                parse_proxy_header(&line[..cut], V1),
                ProxyHeader::Incomplete,
                "{cut}"
            );
        }
        for bad in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"PROXY TCP4 198.51.100.22 203.0.113.7 35646\r\n",
            b"PROXY TCP4 2001:db8::1 203.0.113.7 1 2\r\n",
            b"PROXY TCP6 1.2.3.4 2001:db8::2 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 65536 1\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 01 1\r\n",
            b"PROXY TCP4  1.2.3.4 5.6.7.8 1 1\r\n",
            b"PROXY UDP4 1.2.3.4 5.6.7.8 1 1\r\n",
            b"PROXX TCP4 1.2.3.4 5.6.7.8 1 1\r\n",
            b"PROXY TCP4 \xff.2.3.4 5.6.7.8 1 1\r\n",
        ] {
            assert!(
                matches!(parse_proxy_header(bad, V1), ProxyHeader::Invalid(_)),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // No CRLF within 107 bytes: refused, not buffered forever.
        let long = [b"PROXY TCP4 ".as_slice(), &[b'1'; 200]].concat();
        assert!(matches!(
            parse_proxy_header(&long, V1),
            ProxyHeader::Invalid(_)
        ));
    }

    #[test]
    fn proxy_v2_headers() {
        use ProxyProtocolMode::*;
        let mut v4 = vec![198, 51, 100, 22, 203, 0, 113, 7];
        v4.extend_from_slice(&35646u16.to_be_bytes());
        v4.extend_from_slice(&443u16.to_be_bytes());
        let hdr = v2(1, 0x11, &v4);
        assert_eq!(
            parse_proxy_header(&hdr, V2),
            ProxyHeader::Complete {
                len: 28,
                source: Some("198.51.100.22:35646".parse().unwrap())
            }
        );
        assert!(matches!(
            parse_proxy_header(&hdr, V1),
            ProxyHeader::Invalid(_)
        ));
        // TLVs after the addresses are skipped.
        let mut with_tlv = v4.clone();
        with_tlv.extend_from_slice(&[0x01, 0x00, 0x02, b'h', b'2']);
        let hdr_tlv = v2(1, 0x11, &with_tlv);
        assert!(matches!(
            parse_proxy_header(&hdr_tlv, Any),
            ProxyHeader::Complete { len: 33, .. }
        ));
        // IPv6.
        let mut v6 = Vec::new();
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0, 80, 1, 187]);
        assert_eq!(
            parse_proxy_header(&v2(1, 0x21, &v6), V2),
            ProxyHeader::Complete {
                len: 52,
                source: Some("[2001:db8::1]:80".parse().unwrap())
            }
        );
        // LOCAL (health check) and UNSPEC carry no client.
        assert_eq!(
            parse_proxy_header(&v2(0, 0x00, &[]), V2),
            ProxyHeader::Complete {
                len: 16,
                source: None
            }
        );
        assert_eq!(
            parse_proxy_header(&v2(1, 0x00, &[]), V2),
            ProxyHeader::Complete {
                len: 16,
                source: None
            }
        );
        // Every truncation is incomplete.
        for cut in 0..hdr.len() {
            assert_eq!(
                parse_proxy_header(&hdr[..cut], V2),
                ProxyHeader::Incomplete,
                "{cut}"
            );
        }
        // Malformed.
        let mut bad_version = hdr.clone();
        bad_version[12] = 0x11;
        let mut bad_command = hdr.clone();
        bad_command[12] = 0x2f;
        let mut bad_sig = hdr.clone();
        bad_sig[5] = 0;
        for bad in [
            bad_version,
            bad_command,
            bad_sig,
            v2(1, 0x11, &v4[..8]),                 // addresses truncated
            v2(1, 0x21, &v4),                      // v6 family, v4-sized body
            v2(1, 0x12, &v4),                      // DGRAM
            v2(1, 0x41, &v4),                      // unknown family
            v2(1, 0x11, &[0u8; PROXY_HEADER_MAX]), // too large
        ] {
            assert!(
                matches!(parse_proxy_header(&bad, V2), ProxyHeader::Invalid(_)),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn reading_a_proxy_header_leaves_the_rest_in_the_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Split across two writes, to exercise the incomplete path.
            s.write_all(b"PROXY TCP4 198.51.100.22 203.0.")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(b"113.7 35646 443\r\nhello").await.unwrap();
            s
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let source = read_proxy_header(&mut server, ProxyProtocolMode::Any)
            .await
            .unwrap();
        assert_eq!(source, Some("198.51.100.22:35646".parse().unwrap()));
        let mut rest = [0u8; 5];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"hello");
        drop(client.await.unwrap());

        // A client that speaks HTTP straight away is refused.
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            s
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let err = read_proxy_header(&mut server, ProxyProtocolMode::V2)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        drop(client.await.unwrap());
    }
}
