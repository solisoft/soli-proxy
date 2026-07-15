// When scripting feature is disabled, OptionalLuaEngine = () and cloning it triggers warnings
#![allow(clippy::let_unit_value, clippy::clone_on_copy, clippy::unit_arg)]

use crate::acme::ChallengeStore;
use crate::app::AppManager;
use crate::auth;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::pool::{is_body_limit_error, proxy_request_body, ConnectionPool, ProxyClient};
use crate::shutdown::ShutdownCoordinator;
use anyhow::Result;
use bytes::Bytes;
use governor::{Quota, RateLimiter as GovernorRateLimiter};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// Per-IP token-bucket rate limiter shared across the whole proxy AND
/// the admin API. Re-exported from `crate::lib` so `main.rs` (which owns
/// the construction site) can plumb a single Arc to both surfaces — that
/// way the configured RPS budget is global, not per-listener.
pub type IpRateLimiter = GovernorRateLimiter<
    IpAddr,
    governor::state::keyed::DefaultKeyedStateStore<IpAddr>,
    governor::clock::DefaultClock,
>;

#[cfg(feature = "scripting")]
use crate::scripting::{LuaEngine, LuaRequest, RequestHookResult, RouteHookResult};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// Body wrapper that adds each streamed data frame's length to a set of
/// byte counters (global + per-app `bytes_sent`). Counting happens as the
/// response streams to the client, after the request handler has already
/// recorded the rest of its metrics.
struct CountingBody {
    inner: BoxBody,
    counters: Vec<Arc<AtomicU64>>,
}

impl CountingBody {
    fn new(inner: BoxBody, counters: Vec<Arc<AtomicU64>>) -> Self {
        Self { inner, counters }
    }
}

impl hyper::body::Body for CountingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let res = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(frame))) = &res {
            if let Some(data) = frame.data_ref() {
                let n = data.len() as u64;
                for counter in &this.counters {
                    counter.fetch_add(n, Ordering::Relaxed);
                }
            }
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Longest byte token the streaming HTML rewriter must be able to test at a
/// chunk boundary (`action="/` is 9 bytes; `</script` is 8). We hold the last
/// `REWRITE_MAX_TOKEN - 1` bytes of each frame back as carry-over so a token
/// split across two upstream chunks is still recognised on the next frame.
const REWRITE_MAX_TOKEN: usize = 9;

/// Case-insensitive ASCII prefix match.
fn ci_starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Stateful HTML URL rewriter shared by the streaming bodies below. It rewrites
/// root-relative `href`/`src`/`action` URLs to include a path prefix
/// (`href="/x"` -> `href="/solidb/x"`) incrementally: each `process` call may
/// hold back a small carry-over tail so a token split across two calls is still
/// matched on the next call.
///
/// Rewriting is suppressed inside `<script>...</script>` element bodies so
/// inline JavaScript (and any CSP nonce/hash computed over it) is never mutated;
/// attributes in the `<script ...>` start tag itself (e.g. an external `src`)
/// are still rewritten so prefix-mounted apps load their scripts correctly.
struct HtmlRewriter {
    repl_href: Vec<u8>,
    repl_src: Vec<u8>,
    repl_action: Vec<u8>,
    carry: Vec<u8>,
    /// Inside a `<script ...>` start tag (before its closing `>`).
    pending_script_open: bool,
    /// Inside a `<script>...</script>` body — rewriting suppressed here.
    in_script_body: bool,
}

impl HtmlRewriter {
    fn new(prefix: &str) -> Self {
        let p = prefix.as_bytes();
        let build = |attr: &[u8]| {
            let mut v = attr.to_vec();
            v.extend_from_slice(p);
            v.push(b'/');
            v
        };
        Self {
            repl_href: build(b"href=\""),
            repl_src: build(b"src=\""),
            repl_action: build(b"action=\""),
            carry: Vec::new(),
            pending_script_open: false,
            in_script_body: false,
        }
    }

    /// If `s` starts with a rewritable attribute prefix, return the consumed
    /// length and its replacement bytes.
    fn match_needle(&self, s: &[u8]) -> Option<(usize, &[u8])> {
        if s.starts_with(b"action=\"/") {
            Some((9, &self.repl_action))
        } else if s.starts_with(b"href=\"/") {
            Some((7, &self.repl_href))
        } else if s.starts_with(b"src=\"/") {
            Some((6, &self.repl_src))
        } else {
            None
        }
    }

    /// Rewrite `input` (prepended with any carry-over from the previous call).
    /// When `flush` is false, the trailing `REWRITE_MAX_TOKEN - 1` bytes are
    /// retained as carry so a token straddling the next call is still matched;
    /// when true (end of stream) everything is emitted.
    fn process(&mut self, input: &[u8], flush: bool) -> Vec<u8> {
        let mut combined = std::mem::take(&mut self.carry);
        combined.extend_from_slice(input);
        let boundary = if flush {
            combined.len()
        } else {
            combined.len().saturating_sub(REWRITE_MAX_TOKEN - 1)
        };
        let mut out: Vec<u8> = Vec::with_capacity(combined.len() + 16);
        let mut i = 0;
        while i < boundary {
            let rest = &combined[i..];
            if self.in_script_body {
                if ci_starts_with(rest, b"</script") {
                    self.in_script_body = false;
                    out.extend_from_slice(&combined[i..i + 8]);
                    i += 8;
                } else {
                    out.push(combined[i]);
                    i += 1;
                }
                continue;
            }
            if self.pending_script_open {
                if combined[i] == b'>' {
                    self.pending_script_open = false;
                    self.in_script_body = true;
                    out.push(b'>');
                    i += 1;
                } else if let Some((nlen, repl)) = self.match_needle(rest) {
                    out.extend_from_slice(repl);
                    i += nlen;
                } else {
                    out.push(combined[i]);
                    i += 1;
                }
                continue;
            }
            if combined[i] == b'<' && ci_starts_with(rest, b"<script") {
                self.pending_script_open = true;
                out.extend_from_slice(&combined[i..i + 7]);
                i += 7;
            } else if let Some((nlen, repl)) = self.match_needle(rest) {
                out.extend_from_slice(repl);
                i += nlen;
            } else {
                out.push(combined[i]);
                i += 1;
            }
        }
        self.carry = combined[i..].to_vec();
        out
    }
}

/// Streaming body that rewrites an *uncompressed* HTML response (see
/// `HtmlRewriter`) as bytes flow through, instead of buffering the whole thing.
/// This restores progressive delivery / time-to-first-byte for HTML served
/// under a path-prefix mount: the previous `body.collect().await` gated the
/// first byte to the client on the backend's *entire* response completing,
/// turning a progressively-rendered page into a "blank then dump" stall.
struct RewritingBody {
    inner: BoxBody,
    rewriter: HtmlRewriter,
    done: bool,
}

impl RewritingBody {
    fn new(inner: BoxBody, prefix: &str) -> Self {
        Self {
            inner,
            rewriter: HtmlRewriter::new(prefix),
            done: false,
        }
    }
}

impl hyper::body::Body for RewritingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let out = this.rewriter.process(&data, false);
                        if out.is_empty() {
                            // Everything held back as carry — poll for more.
                            continue;
                        }
                        return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(out)))));
                    }
                    // Non-data frame (e.g. trailers): pass through untouched.
                    Err(non_data) => return Poll::Ready(Some(Ok(non_data))),
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.done = true;
                    let out = this.rewriter.process(&[], true);
                    if out.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(out)))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Streaming body that incrementally gzip-decodes the upstream response and
/// rewrites it (see `HtmlRewriter`) as it flows. This lets gzip-compressed HTML
/// served under a path-prefix mount stream to the client instead of being
/// buffered and decoded in one shot. The body is emitted decoded (identity);
/// the caller drops the `content-encoding`/`content-length` headers to match.
/// Result of parsing a gzip member header.
enum GzHeader {
    /// Not enough bytes yet to determine the full header length.
    NeedMore,
    /// Not a valid gzip header (bad magic / method).
    Invalid,
    /// Header occupies this many leading bytes; the deflate stream follows.
    Len(usize),
}

/// Parse a gzip member header (RFC 1952) and return its length. The fixed part
/// is 10 bytes; optional FEXTRA/FNAME/FCOMMENT/FHCRC fields (signalled by the
/// FLG byte) follow and are skipped. Server-generated gzip almost always has
/// FLG = 0 (just the 10-byte header), but we handle the optional fields so a
/// header split across read frames is parsed correctly.
fn parse_gzip_header(b: &[u8]) -> GzHeader {
    if b.len() < 10 {
        return GzHeader::NeedMore;
    }
    if b[0] != 0x1f || b[1] != 0x8b || b[2] != 8 {
        return GzHeader::Invalid;
    }
    let flg = b[3];
    let mut pos = 10;
    if flg & 0x04 != 0 {
        // FEXTRA: 2-byte length + that many bytes.
        if b.len() < pos + 2 {
            return GzHeader::NeedMore;
        }
        let xlen = u16::from_le_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        // FNAME: NUL-terminated.
        match b.get(pos..).and_then(|s| s.iter().position(|&c| c == 0)) {
            Some(i) => pos += i + 1,
            None => return GzHeader::NeedMore,
        }
    }
    if flg & 0x10 != 0 {
        // FCOMMENT: NUL-terminated.
        match b.get(pos..).and_then(|s| s.iter().position(|&c| c == 0)) {
            Some(i) => pos += i + 1,
            None => return GzHeader::NeedMore,
        }
    }
    if flg & 0x02 != 0 {
        // FHCRC: 2 bytes.
        pos += 2;
    }
    if b.len() < pos {
        return GzHeader::NeedMore;
    }
    GzHeader::Len(pos)
}

struct DecodingRewritingBody {
    inner: BoxBody,
    /// Raw-DEFLATE decoder. flate2's `new_gzip` needs a zlib backend, so we
    /// strip the gzip header ourselves and inflate the raw deflate payload
    /// (the 8-byte gzip footer is simply ignored once the stream ends).
    decoder: flate2::Decompress,
    header_done: bool,
    header_buf: Vec<u8>,
    decoder_ended: bool,
    rewriter: HtmlRewriter,
    done: bool,
}

impl DecodingRewritingBody {
    fn new_gzip(inner: BoxBody, prefix: &str) -> Self {
        Self {
            inner,
            decoder: flate2::Decompress::new(false),
            header_done: false,
            header_buf: Vec::new(),
            decoder_ended: false,
            rewriter: HtmlRewriter::new(prefix),
            done: false,
        }
    }

    /// Strip the gzip header (buffering only the few header bytes), then inflate
    /// the deflate payload into `out`.
    fn inflate(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if self.decoder_ended {
            return;
        }
        if !self.header_done {
            self.header_buf.extend_from_slice(input);
            match parse_gzip_header(&self.header_buf) {
                GzHeader::NeedMore => return,
                GzHeader::Invalid => {
                    self.decoder_ended = true;
                    return;
                }
                GzHeader::Len(n) => {
                    self.header_done = true;
                    let rest = self.header_buf[n..].to_vec();
                    self.header_buf = Vec::new();
                    self.inflate_deflate(&rest, out);
                }
            }
            return;
        }
        self.inflate_deflate(input, out);
    }

    /// Drive the raw-deflate decoder over `input` until it is drained (or the
    /// deflate stream ends).
    fn inflate_deflate(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if self.decoder_ended {
            return;
        }
        let mut in_off = 0;
        let mut buf = [0u8; 16384];
        loop {
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status =
                self.decoder
                    .decompress(&input[in_off..], &mut buf, flate2::FlushDecompress::None);
            let consumed = (self.decoder.total_in() - before_in) as usize;
            let produced = (self.decoder.total_out() - before_out) as usize;
            in_off += consumed;
            out.extend_from_slice(&buf[..produced]);
            match status {
                Ok(flate2::Status::StreamEnd) => {
                    self.decoder_ended = true;
                    return;
                }
                Ok(_) => {
                    // No forward progress (and input remains) → can't proceed.
                    if consumed == 0 && produced == 0 {
                        return;
                    }
                    // All input consumed and the output buffer had spare room →
                    // nothing more is pending right now.
                    if in_off >= input.len() && produced < buf.len() {
                        return;
                    }
                    // else: more input, or output buffer filled — keep looping.
                }
                Err(_) => {
                    // Corrupt/unexpected stream: stop decoding.
                    self.decoder_ended = true;
                    return;
                }
            }
        }
    }
}

impl hyper::body::Body for DecodingRewritingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let mut raw = Vec::new();
                        this.inflate(&data, &mut raw);
                        if raw.is_empty() {
                            continue;
                        }
                        let out = this.rewriter.process(&raw, false);
                        if out.is_empty() {
                            continue;
                        }
                        return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(out)))));
                    }
                    Err(non_data) => return Poll::Ready(Some(Ok(non_data))),
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.done = true;
                    let raw = Vec::new();
                    let mut out = this.rewriter.process(&raw, false);
                    out.extend(this.rewriter.process(&[], true));
                    if out.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(out)))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Request body size as declared by the client. Chunked uploads carry no
/// Content-Length and count as 0 — the body is streamed straight to the
/// backend without inspection.
fn request_content_length(req: &Request<Incoming>) -> u64 {
    req.headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Object-safe alias for a bidirectional byte stream — lets the WebSocket
/// backend path treat plain-TCP and TLS connections uniformly.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Shared TLS connector for `https`/`wss` WebSocket backends (webpki roots,
/// mirroring the HTTP pool's connector in `crate::pool`).
fn ws_backend_tls_connector() -> &'static tokio_rustls::TlsConnector {
    static CONNECTOR: std::sync::LazyLock<tokio_rustls::TlsConnector> =
        std::sync::LazyLock::new(|| {
            let roots = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tokio_rustls::TlsConnector::from(Arc::new(config))
        });
    &CONNECTOR
}

/// Format an error with its full source chain (`outer: cause: root`) so
/// connect failures show the underlying reason, not just "client error".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        s.push_str(": ");
        s.push_str(&cause.to_string());
        source = cause.source();
    }
    s
}

#[cfg(feature = "scripting")]
type OptionalLuaEngine = Option<LuaEngine>;
#[cfg(not(feature = "scripting"))]
type OptionalLuaEngine = ();

pub struct LoadBalancerState {
    /// Per-rule round-robin/weighted counters. Grows on demand so hot-reloaded
    /// routes beyond the startup rule count still get an independent counter
    /// (previously every route shared `counters[0]`).
    counters: parking_lot::RwLock<Vec<AtomicUsize>>,
}

impl LoadBalancerState {
    pub fn new(_num_rules: usize) -> Self {
        Self {
            counters: parking_lot::RwLock::new(Vec::new()),
        }
    }

    fn bump(&self, rule_idx: usize) -> usize {
        {
            let counters = self.counters.read();
            if rule_idx < counters.len() {
                return counters[rule_idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut counters = self.counters.write();
        while counters.len() <= rule_idx {
            counters.push(AtomicUsize::new(0));
        }
        counters[rule_idx].fetch_add(1, Ordering::Relaxed)
    }

    pub fn select_index(&self, rule_idx: usize, num_targets: usize) -> usize {
        if num_targets == 0 {
            return 0;
        }
        self.bump(rule_idx) % num_targets
    }
}

/// Resolve which managed app served a request, from the target URL's port.
async fn app_name_for_target(
    app_manager: &Option<Arc<AppManager>>,
    target_url: &str,
) -> Option<String> {
    let manager = app_manager.as_ref()?;
    let url = url::Url::parse(target_url).ok()?;
    let port = url.port()?;
    manager.get_app_name(port).await
}

static X_FORWARDED_PROTO_HTTPS: std::sync::LazyLock<HeaderValue> =
    std::sync::LazyLock::new(|| HeaderValue::from_static("https"));
static X_FORWARDED_PROTO_HTTP: std::sync::LazyLock<HeaderValue> =
    std::sync::LazyLock::new(|| HeaderValue::from_static("http"));

const MAX_HTML_REWRITE_SIZE: usize = 10 * 1024 * 1024;

/// Default HSTS max-age (2 years) used when `tls.hsts_max_age_seconds` is
/// unset. Matches the IETF recommendation and the value required by
/// hstspreload.org for browser preload submission.
const HSTS_DEFAULT_MAX_AGE: u64 = 63072000;

/// Build the `Strict-Transport-Security` header value from `tls`. Returns
/// `None` when `hsts_max_age_seconds` is explicitly set to 0 — the operator
/// has opted out. RFC 6797 §7.2 forbids browsers from honouring the header
/// over plaintext HTTP, so callers MUST gate this on `is_tls`.
fn hsts_header_value(tls: &crate::config::TlsConfig) -> Option<HeaderValue> {
    let max_age = tls.hsts_max_age_seconds.unwrap_or(HSTS_DEFAULT_MAX_AGE);
    if max_age == 0 {
        return None;
    }
    let mut value = format!("max-age={}", max_age);
    if tls.hsts_include_subdomains.unwrap_or(true) {
        value.push_str("; includeSubDomains");
    }
    HeaderValue::from_str(&value).ok()
}

/// Verify Basic Auth credentials against stored hashes
/// Returns true if credentials are valid, false otherwise
fn verify_basic_auth(req: &Request<Incoming>, auth_entries: &[crate::auth::BasicAuth]) -> bool {
    if auth_entries.is_empty() {
        return true;
    }

    let auth_header = req.headers().get("authorization");
    if auth_header.is_none() {
        return false;
    }

    let header_value = auth_header.unwrap().to_str().unwrap_or("");
    if !header_value.starts_with("Basic ") {
        return false;
    }

    let encoded = &header_value[6..];
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .unwrap_or_default();
    let creds = String::from_utf8_lossy(&decoded);

    if let Some((username, password)) = creds.split_once(':') {
        let username_bytes = username.as_bytes();
        // Locate the matching account without breaking early, so the loop's
        // timing doesn't depend on which entry (if any) matched.
        let mut matched_hash: Option<&str> = None;
        for entry in auth_entries {
            if constant_time_eq(entry.username.as_bytes(), username_bytes) {
                matched_hash = Some(entry.hash.as_str());
            }
        }
        // Always run exactly one bcrypt verify — against the matched hash, or a
        // dummy when the username is unknown — so a wrong username and a wrong
        // password take the same time (no user enumeration via timing).
        let hash = matched_hash.unwrap_or_else(|| auth::dummy_hash());
        let password_ok = auth::verify_password(password, hash);
        return matched_hash.is_some() && password_ok;
    }

    false
}

/// Constant-time byte comparison to prevent timing attacks on username comparison.
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

/// Create 401 Unauthorized response with WWW-Authenticate header
fn create_auth_required_response() -> Response<BoxBody> {
    let body = http_body_util::Full::new(Bytes::from("Authentication required")).boxed();
    Response::builder()
        .status(401)
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .body(body)
        .unwrap()
}

fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(8192)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub struct ProxyServer {
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    tls_acceptor: Option<TlsAcceptor>,
    https_addr: Option<SocketAddr>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    /// Single permit pool shared across every HTTP and HTTPS accept loop. Each
    /// accepted connection holds one permit until its handler task ends; the
    /// semaphore therefore caps total simultaneous connections per process.
    /// `None` disables the cap (matches the prior behaviour).
    connection_limit: Option<Arc<Semaphore>>,
    /// Per-IP rate limiter consulted at the top of every request. `None`
    /// when `[rate_limiting].enabled` is unset/false.
    rate_limiter: Option<Arc<IpRateLimiter>>,
}

fn build_connection_limit(config: &ConfigManager) -> Option<Arc<Semaphore>> {
    config
        .get_config()
        .limits
        .max_connections
        .filter(|&n| n > 0)
        .map(|n| Arc::new(Semaphore::new(n as usize)))
}

/// Forward one half of a bidirectional WebSocket connection (reader→writer)
/// with three DoS guards: idle-read timeout, absolute lifetime deadline,
/// and a per-direction byte cap. Returns when any guard trips, when EOF
/// is observed, or when the writer errors. Used by both the proxy and the
/// admin app passthrough.
pub(crate) async fn forward_ws_half<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
    deadline: std::time::Instant,
    max_bytes: u64,
    byte_counter: Option<Arc<AtomicU64>>,
) -> tokio::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let until_deadline = deadline.saturating_duration_since(now);
        let next_timeout = std::cmp::min(idle_timeout, until_deadline);

        let n = match tokio::time::timeout(next_timeout, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        let new_total = total.saturating_add(n as u64);
        if new_total > max_bytes {
            return Ok(());
        }
        total = new_total;
        if let Some(ref counter) = byte_counter {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
        writer.write_all(&buf[..n]).await?;
    }
}

/// Build a per-IP token-bucket rate limiter from the [rate_limiting] config
/// section. Returns `None` when disabled or when the configured quota is
/// non-positive (the resulting limiter would be useless or panic at quota
/// construction). The same limiter is then shared across every accept loop
/// so the cap is per-process, not per-listener.
pub fn build_rate_limiter(config: &ConfigManager) -> Option<Arc<IpRateLimiter>> {
    let cfg = config.get_config();
    let rl = &cfg.rate_limiting;
    if rl.enabled != Some(true) {
        return None;
    }
    let rps = rl.requests_per_second?;
    let burst = rl.burst_size.unwrap_or(rps);
    let rps_nz = NonZeroU32::new(rps.min(u32::MAX as u64) as u32)?;
    let burst_nz = NonZeroU32::new(burst.min(u32::MAX as u64).max(1) as u32)?;
    let quota = Quota::per_second(rps_nz).allow_burst(burst_nz);
    Some(Arc::new(GovernorRateLimiter::keyed(quota)))
}

/// Build the trailing header lines for a forwarded WebSocket upgrade. Drops
/// hop-by-hop headers (RFC 7230 §6.1) and any header nominated by the
/// client's `Connection:` value, then re-injects proxy-derived
/// `X-Forwarded-{For,Proto,Host}` so a client cannot spoof source IP /
/// proto / host on the upgrade. `Host`, `Upgrade`, `Connection`, and the
/// `Sec-WebSocket-*` framing headers are also skipped because the caller
/// emits them explicitly. Output ends with each line CRLF-terminated; the
/// caller appends the final blank-line terminator.
fn build_ws_extra_headers(
    headers: &hyper::HeaderMap,
    peer_addr: Option<SocketAddr>,
    is_tls: bool,
    host_header: &str,
) -> String {
    let connection_listed: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mut out = String::new();
    for (name, value) in headers {
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
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host" => continue,
            _ => {}
        }
        if connection_listed.iter().any(|n| n == name_str) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            if contains_crlf(name_str) || contains_crlf(v) {
                continue;
            }
            out.push_str(&format!("{}: {}\r\n", name_str, v));
        }
    }

    if let Some(peer) = peer_addr {
        out.push_str(&format!("X-Forwarded-For: {}\r\n", peer.ip()));
    }
    out.push_str(&format!(
        "X-Forwarded-Proto: {}\r\n",
        if is_tls { "https" } else { "http" }
    ));
    if !contains_crlf(host_header) {
        out.push_str(&format!("X-Forwarded-Host: {}\r\n", host_header));
    }
    out
}

impl ProxyServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
        circuit_breaker: SharedCircuitBreaker,
        app_manager: Option<Arc<AppManager>>,
        rate_limiter: Option<Arc<IpRateLimiter>>,
    ) -> Result<Self> {
        let num_rules = config.get_config().rules.len();
        let connection_limit = build_connection_limit(&config);
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: None,
            https_addr: None,
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer: Arc::new(LoadBalancerState::new(num_rules)),
            connection_limit,
            rate_limiter,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_https(
        config: Arc<ConfigManager>,
        shutdown: ShutdownCoordinator,
        tls_acceptor: TlsAcceptor,
        https_addr: SocketAddr,
        metrics: SharedMetrics,
        challenge_store: ChallengeStore,
        lua_engine: OptionalLuaEngine,
        circuit_breaker: SharedCircuitBreaker,
        app_manager: Option<Arc<AppManager>>,
        rate_limiter: Option<Arc<IpRateLimiter>>,
    ) -> Result<Self> {
        let num_rules = config.get_config().rules.len();
        let connection_limit = build_connection_limit(&config);
        Ok(Self {
            config,
            shutdown,
            tls_acceptor: Some(tls_acceptor),
            https_addr: Some(https_addr),
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer: Arc::new(LoadBalancerState::new(num_rules)),
            connection_limit,
            rate_limiter,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let cfg = self.config.get_config();
        let http_addr: SocketAddr = cfg.server.bind.parse()?;
        let https_addr = self.https_addr;

        let has_https = https_addr.is_some();
        let num_listeners = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // One shared connection pool for every accept loop (HTTP + HTTPS).
        // Clones are cheap and share idle keep-alive sockets across listeners.
        let shared_client = ConnectionPool::new().client();
        let app_manager = self.app_manager.clone();
        for i in 0..num_listeners {
            let config_clone = self.config.clone();
            let shutdown_clone = self.shutdown.clone();
            let metrics_clone = self.metrics.clone();
            let challenge_store_clone = self.challenge_store.clone();
            let lua_clone = self.lua_engine.clone();
            let cb_clone = self.circuit_breaker.clone();
            let am_clone = app_manager.clone();
            let lb_clone = self.load_balancer.clone();
            let cl_clone = self.connection_limit.clone();
            let rl_clone = self.rate_limiter.clone();
            let client = shared_client.clone();

            tokio::spawn(async move {
                if let Err(e) = run_http_server(
                    http_addr,
                    config_clone,
                    shutdown_clone,
                    metrics_clone,
                    challenge_store_clone,
                    lua_clone,
                    cb_clone,
                    am_clone,
                    lb_clone,
                    cl_clone,
                    rl_clone,
                    client,
                )
                .await
                {
                    tracing::error!("HTTP/1.1 server error (listener {}): {}", i, e);
                }
            });
        }

        if let Some(https_addr) = https_addr {
            for i in 0..num_listeners {
                let config_clone = self.config.clone();
                let shutdown_clone = self.shutdown.clone();
                let acceptor = self.tls_acceptor.as_ref().unwrap().clone();
                let metrics_clone = self.metrics.clone();
                let challenge_store_clone = self.challenge_store.clone();
                let lua_clone = self.lua_engine.clone();
                let cb_clone = self.circuit_breaker.clone();
                let am_clone = app_manager.clone();
                let lb_clone = self.load_balancer.clone();
                let cl_clone = self.connection_limit.clone();
                let rl_clone = self.rate_limiter.clone();
                let client = shared_client.clone();

                tokio::spawn(async move {
                    if let Err(e) = run_https_server(
                        https_addr,
                        config_clone,
                        shutdown_clone,
                        acceptor,
                        metrics_clone,
                        challenge_store_clone,
                        lua_clone,
                        cb_clone,
                        am_clone,
                        lb_clone,
                        cl_clone,
                        rl_clone,
                        client,
                    )
                    .await
                    {
                        tracing::error!("HTTPS/2 server error (listener {}): {}", i, e);
                    }
                });
            }
        }

        // Periodic GC for the rate-limiter dashmap when enabled. Without this,
        // governor's keyed state store grows by one entry per unique IP that
        // has ever hit the proxy and never shrinks. retain_recent evicts
        // entries whose token state has been at full capacity for longer than
        // the longest reasonable backoff (i.e. IPs that have gone silent).
        if let Some(limiter) = self.rate_limiter.clone() {
            let mut shutdown_rx = self.shutdown.subscribe();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                // interval() fires immediately on first poll — skip that
                // tick so we don't sweep the just-built (empty) map.
                tick.tick().await;
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        _ = tick.tick() => {
                            limiter.retain_recent();
                        }
                    }
                }
            });
        }

        tracing::info!(
            "HTTP/1.1 server listening on {} ({} accept loops)",
            http_addr,
            num_listeners
        );
        if has_https {
            tracing::info!(
                "HTTPS/2 server listening on {} ({} accept loops)",
                https_addr.unwrap(),
                num_listeners
            );
        }

        loop {
            if self.shutdown.is_shutting_down() {
                tracing::info!("Shutting down servers...");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_http_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    connection_limit: Option<Arc<Semaphore>>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
    client: ProxyClient,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        // Wait for a connection permit before accepting. This applies
        // backpressure at the OS level (the listen() backlog absorbs the
        // overflow) instead of draining the accept queue and queuing tasks.
        let permit: Option<OwnedSemaphorePermit> = match connection_limit.as_ref() {
            Some(s) => tokio::select! {
                _ = shutdown_rx.recv() => break,
                p = s.clone().acquire_owned() => match p {
                    Ok(p) => Some(p),
                    Err(_) => break, // semaphore closed
                },
            },
            None => None,
        };

        tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let client = client.clone();
                    let config = config.clone();
                    let metrics = metrics.clone();
                    let cs = challenge_store.clone();
                    let lua = lua_engine.clone();
                    let cb = circuit_breaker.clone();
                    let am = app_manager.clone();
                    let lb = load_balancer.clone();
                    let sd = shutdown.clone();
                    let rl = rate_limiter.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // released when this task ends
                        if let Err(e) = handle_http11_connection(
                            stream, client, config, metrics, cs, lua, cb, am, lb, sd, rl,
                        )
                        .await
                        {
                            // anyhow error: `{:#}` prints the full chain
                            tracing::debug!("HTTP/1.1 connection error: {:#}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("HTTP/1.1 accept error: {}", e);
                    // permit drops here, returning the slot to the pool
                }
            },
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_https_server(
    addr: SocketAddr,
    config: Arc<ConfigManager>,
    shutdown: ShutdownCoordinator,
    acceptor: TlsAcceptor,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    connection_limit: Option<Arc<Semaphore>>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
    client: ProxyClient,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        // Same permit-then-accept pattern as run_http_server. The permit
        // covers the TLS handshake too, so a flood of bogus ClientHellos
        // can't bypass the cap by stalling in handshake.
        let permit: Option<OwnedSemaphorePermit> = match connection_limit.as_ref() {
            Some(s) => tokio::select! {
                _ = shutdown_rx.recv() => break,
                p = s.clone().acquire_owned() => match p {
                    Ok(p) => Some(p),
                    Err(_) => break,
                },
            },
            None => None,
        };

        tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    let client = client.clone();
                    let config = config.clone();
                    let acceptor = acceptor.clone();
                    let metrics = metrics.clone();
                    let cs = challenge_store.clone();
                    let lua = lua_engine.clone();
                    let cb = circuit_breaker.clone();
                    let am = app_manager.clone();
                    let lb = load_balancer.clone();
                    let sd = shutdown.clone();
                    let rl = rate_limiter.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // released when this task ends
                        const TLS_HANDSHAKE_TIMEOUT: tokio::time::Duration =
                            tokio::time::Duration::from_secs(10);
                        match tokio::time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(tls_stream)) => {
                                metrics.inc_tls_connections();
                                if let Err(e) = handle_https2_connection(
                                    tls_stream, client, config, metrics, cs, lua, cb, am, lb, sd,
                                    rl,
                                )
                                .await
                                {
                                    tracing::debug!("HTTPS/2 connection error: {}", e);
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("TLS accept error (client incompatible): {}", e);
                            }
                            Err(_) => {
                                tracing::debug!("TLS handshake timed out after {:?}s", TLS_HANDSHAKE_TIMEOUT);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("HTTPS/2 accept error: {}", e);
                }
            },
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_http11_connection(
    stream: tokio::net::TcpStream,
    client: ProxyClient,
    config: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    shutdown: ShutdownCoordinator,
    rate_limiter: Option<Arc<IpRateLimiter>>,
) -> Result<()> {
    let peer_addr = stream.peer_addr().ok();
    let io = TokioIo::new(stream);
    let config_inner = config.get_config();
    let header_timeout = config_inner
        .limits
        .keep_alive_timeout
        .map(Duration::from_secs);
    let svc = service_fn(move |req| {
        handle_request(
            req,
            client.clone(),
            config.clone(),
            metrics.clone(),
            challenge_store.clone(),
            lua_engine.clone(),
            circuit_breaker.clone(),
            app_manager.clone(),
            load_balancer.clone(),
            false,
            peer_addr,
            rate_limiter.clone(),
        )
    });

    let conn = match header_timeout {
        // hyper 1.9 panics with "timeout `header_read_timeout` set, but no
        // timer set" if `.timer(...)` isn't called when any time-based
        // feature is enabled, so call it on both branches for symmetry.
        Some(timeout) => hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .keep_alive(true)
            .pipeline_flush(true)
            .header_read_timeout(timeout)
            .serve_connection(io, svc)
            .with_upgrades(),
        None => hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .keep_alive(true)
            .pipeline_flush(true)
            .serve_connection(io, svc)
            .with_upgrades(),
    };
    let mut conn = std::pin::pin!(conn);
    let mut shutdown_rx = shutdown.subscribe();

    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!("HTTP/1.1 connection error: {}", error_chain(&e));
            }
        }
        _ = shutdown_rx.recv() => {
            // Send Connection: close after the in-flight request completes
            // so the Mac's browser knows to drop its keep-alive socket instead
            // of detecting a dead peer on the next request (saves ~30s).
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await {
                tracing::debug!("HTTP/1.1 graceful shutdown error: {}", e);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_https2_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client: ProxyClient,
    config: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    shutdown: ShutdownCoordinator,
    rate_limiter: Option<Arc<IpRateLimiter>>,
) -> Result<()> {
    let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");

    let peer_addr = stream.get_ref().0.peer_addr().ok();
    let io = TokioIo::new(stream);
    let mut shutdown_rx = shutdown.subscribe();

    if is_h2 {
        let exec = TokioExecutor::new();
        let svc = service_fn(move |req| {
            let cfg = config.clone();
            let fut = handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
                lua_engine.clone(),
                circuit_breaker.clone(),
                app_manager.clone(),
                load_balancer.clone(),
                true,
                peer_addr,
                rate_limiter.clone(),
            );
            async move {
                let mut resp = fut.await?;
                if let Some(v) = hsts_header_value(&cfg.get_config().tls) {
                    resp.headers_mut().insert("Strict-Transport-Security", v);
                }
                Ok::<_, hyper::Error>(resp)
            }
        });
        let conn = hyper::server::conn::http2::Builder::new(exec)
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_concurrent_streams(250)
            .serve_connection(io, svc);
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!("HTTPS/2 connection error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                // Emit HTTP/2 GOAWAY so the browser closes its multiplexed
                // connection promptly. Without this, Chrome waits ~30s on
                // its HTTP/2 PING timeout before retrying on a fresh conn.
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/2 graceful shutdown error: {}", e);
                }
            }
        }
    } else {
        let config_inner = config.get_config();
        let header_timeout = config_inner
            .limits
            .keep_alive_timeout
            .map(Duration::from_secs);
        let svc = service_fn(move |req| {
            let cfg = config.clone();
            let fut = handle_request(
                req,
                client.clone(),
                config.clone(),
                metrics.clone(),
                challenge_store.clone(),
                lua_engine.clone(),
                circuit_breaker.clone(),
                app_manager.clone(),
                load_balancer.clone(),
                true,
                peer_addr,
                rate_limiter.clone(),
            );
            async move {
                let mut resp = fut.await?;
                if let Some(v) = hsts_header_value(&cfg.get_config().tls) {
                    resp.headers_mut().insert("Strict-Transport-Security", v);
                }
                Ok::<_, hyper::Error>(resp)
            }
        });
        let conn = match header_timeout {
            Some(timeout) => hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .keep_alive(true)
                .pipeline_flush(true)
                .header_read_timeout(timeout)
                .serve_connection(io, svc)
                .with_upgrades(),
            None => hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .keep_alive(true)
                .pipeline_flush(true)
                .serve_connection(io, svc)
                .with_upgrades(),
        };
        let mut conn = std::pin::pin!(conn);

        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!("HTTPS/1.1 connection error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/1.1 graceful shutdown error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Extract headers from a hyper request into a HashMap for Lua consumption.
#[cfg(feature = "scripting")]
fn extract_headers(req: &Request<Incoming>) -> std::collections::HashMap<String, String> {
    req.headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Build a LuaRequest from a hyper Request.
#[cfg(feature = "scripting")]
fn build_lua_request(req: &Request<Incoming>) -> LuaRequest {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()))
        .unwrap_or_default();

    let content_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    LuaRequest {
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        headers: extract_headers(req),
        host,
        content_length,
    }
}

/// Extract response headers into a HashMap for Lua consumption.
#[cfg(feature = "scripting")]
fn extract_response_headers(
    headers: &hyper::HeaderMap,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Entry point for every served request. When `[logging].log_endpoints` is
/// true it wraps the handler to emit one structured log line per request —
/// covering all return paths (proxied responses, rate-limit/size rejections,
/// timeouts, health/metrics, Lua denials, websockets). Otherwise it delegates
/// straight to `handle_request_inner` with no added work. The flag is read
/// from the current config on each request, so hot reloads take effect.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<Incoming>,
    client: ProxyClient,
    config_manager: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let log_endpoints = config_manager
        .get_config()
        .logging
        .log_endpoints
        .unwrap_or(false);
    if !log_endpoints {
        return handle_request_inner(
            req,
            client,
            config_manager,
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer,
            is_tls,
            peer_addr,
            rate_limiter,
        )
        .await;
    }

    // Capture identifying fields before `req` is moved into the handler.
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let host = req
        .uri()
        .host()
        .map(|h| h.to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    let scheme = if is_tls { "https" } else { "http" };
    let client_ip = peer_addr.map(|a| a.ip().to_string()).unwrap_or_default();
    let start = std::time::Instant::now();

    let result = handle_request_inner(
        req,
        client,
        config_manager,
        metrics,
        challenge_store,
        lua_engine,
        circuit_breaker,
        app_manager,
        load_balancer,
        is_tls,
        peer_addr,
        rate_limiter,
    )
    .await;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    match &result {
        Ok(resp) => tracing::info!(
            layer = "endpoint",
            method = %method,
            scheme = scheme,
            host = %host,
            path = %path,
            status = resp.status().as_u16(),
            elapsed_ms = elapsed_ms,
            client_ip = %client_ip,
            "endpoint request"
        ),
        Err(e) => tracing::info!(
            layer = "endpoint",
            method = %method,
            scheme = scheme,
            host = %host,
            path = %path,
            error = %e,
            elapsed_ms = elapsed_ms,
            client_ip = %client_ip,
            "endpoint request failed"
        ),
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_request_inner(
    req: Request<Incoming>,
    client: ProxyClient,
    config_manager: Arc<ConfigManager>,
    metrics: SharedMetrics,
    challenge_store: ChallengeStore,
    lua_engine: OptionalLuaEngine,
    circuit_breaker: SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start_time = std::time::Instant::now();
    metrics.inc_in_flight();
    let config = config_manager.get_config();

    // ACME challenge check — must come before all other routing.
    // ACME challenges originate from Let's Encrypt validators and are
    // intentionally exempt from per-IP rate limits.
    if let Some(response) = handle_acme_challenge(&req, &challenge_store) {
        metrics.dec_in_flight();
        return Ok(response);
    }

    // Per-IP rate limiting. Applied after ACME so issuance can't be denied
    // by a noisy neighbour, and before all routing so denied requests
    // never touch upstream connection pools or Lua hooks. Requests with
    // no observable peer (UNIX socket, error path) skip the check.
    if let (Some(limiter), Some(peer)) = (rate_limiter.as_ref(), peer_addr) {
        if limiter.check_key(&peer.ip()).is_err() {
            metrics.dec_in_flight();
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 429, duration);
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

    // HTTP to HTTPS redirect when TLS is off and force_https is enabled
    if !is_tls && config.tls.force_https {
        let raw_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| req.uri().host())
            .unwrap_or("localhost");
        // Prefer Host header (not absolute-form authority) and only redirect to
        // requests we actually serve — prevents open redirects via forged Host.
        // A host counts as served if it's localhost/an IP, if any routing rule
        // matches (Domain/DomainPath/Exact/Prefix/Regex/Default — so path-based
        // and catch-all routes still redirect), or if it's a managed app domain.
        let host_ok = is_configured_host(raw_host, &config)
            || find_matching_rule(&req, &config.rules).is_some()
            || match &app_manager {
                Some(m) => m.resolve_app_target(raw_host.split(':').next().unwrap_or(raw_host)).await.is_some(),
                None => false,
            };
        let host_for_redirect = if host_ok {
            raw_host
        } else {
            metrics.dec_in_flight();
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 400, duration);
            let body = http_body_util::Full::new(Bytes::from("Bad Request")).boxed();
            return Ok(Response::builder()
                .status(400)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        };
        let path = req.uri().path();
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        let location = format!("https://{}{}{}", host_for_redirect, path, query);
        metrics.dec_in_flight();
        // RFC 6797 §7.2: HSTS over plaintext is ignored by browsers, so this
        // header on the 308 is non-load-bearing — the canonical home is the
        // HTTPS path, set by the TLS service wrapper. Kept here for consistency
        // with the configured policy in case any non-browser client honours it.
        let mut builder = Response::builder()
            .status(308)
            .header("Location", &location);
        if let Some(v) = hsts_header_value(&config.tls) {
            builder = builder.header("Strict-Transport-Security", v);
        }
        return Ok(builder
            .body(http_body_util::Full::new(Bytes::new()).boxed())
            .unwrap());
    }

    // Fast-path body size limit: reject when Content-Length already exceeds the
    // cap. Chunked / HTTP/2 bodies without Content-Length are enforced later by
    // streaming through `proxy_request_body` + Limited (returns 413 on overflow).
    if let Some(max_size) = config.limits.max_request_size {
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if content_length > max_size {
            metrics.dec_in_flight();
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 413, duration);
            return Ok(payload_too_large());
        }
    }

    if is_metrics_request(
        &req,
        config.metrics.endpoint.as_deref().unwrap_or("/metrics"),
    ) {
        let is_loopback = peer_addr.map(|a| a.ip().is_loopback()).unwrap_or(false);
        if !is_loopback {
            let duration = start_time.elapsed();
            metrics.dec_in_flight();
            metrics.record_request(0, 0, 403, duration);
            let body = http_body_util::Full::new(Bytes::from("Forbidden")).boxed();
            return Ok(Response::builder()
                .status(403)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
        let duration = start_time.elapsed();
        metrics.dec_in_flight();
        let metrics_output = metrics.format_metrics();
        metrics.record_request(0, metrics_output.len() as u64, 200, duration);
        let body = http_body_util::Full::new(Bytes::from(metrics_output)).boxed();
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    if is_health_request(&req, &config.health) {
        let duration = start_time.elapsed();
        metrics.dec_in_flight();
        metrics.record_request(0, 0, 200, duration);
        let body = http_body_util::Full::new(Bytes::from("OK")).boxed();
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    // --- Lua on_request hook ---
    #[cfg(feature = "scripting")]
    let mut req = req;
    #[cfg(feature = "scripting")]
    if let Some(ref engine) = lua_engine {
        if engine.has_on_request() {
            let mut lua_req = build_lua_request(&req);
            match engine.call_on_request(&mut lua_req) {
                RequestHookResult::Deny { status, body } => {
                    metrics.dec_in_flight();
                    let duration = start_time.elapsed();
                    metrics.record_request(0, body.len() as u64, status, duration);
                    let resp_body = http_body_util::Full::new(Bytes::from(body)).boxed();
                    return Ok(Response::builder().status(status).body(resp_body).unwrap());
                }
                RequestHookResult::Continue(updated_req) => {
                    apply_lua_request_mods(&mut req, &updated_req);
                }
            }
        }
    }

    let is_websocket = is_websocket_request(&req);

    if is_websocket {
        if let Some(matched) = find_matching_rule(&req, &config.rules) {
            if !matched.auth.is_empty() && !verify_basic_auth(&req, &matched.auth) {
                metrics.dec_in_flight();
                return Ok(create_auth_required_response());
            }
        }
        return handle_websocket_request(
            req,
            client,
            &config,
            &metrics,
            start_time,
            app_manager.clone(),
            is_tls,
            peer_addr,
        )
        .await;
    }

    // Always enforce a request timeout. Falls back to 60s when the config
    // omits `[limits].request_timeout` — e.g. a deployed config.toml missing
    // the field, or the .conf route format which can't express it. Without a
    // default, a stuck backend hangs the client indefinitely ("pending" in the
    // browser) instead of returning a bounded 504.
    let timeout_sec = Duration::from_secs(config.limits.request_timeout.unwrap_or(60));

    // Capture before `req` is moved into the handler, for the timeout log
    // and byte accounting.
    let req_method = req.method().clone();
    let req_path = req.uri().path().to_string();
    let req_bytes_in = request_content_length(&req);

    let handle_fut = handle_regular_request(
        req,
        client,
        &config,
        &lua_engine,
        &circuit_breaker,
        app_manager.clone(),
        load_balancer.clone(),
        is_tls,
        peer_addr,
    );
    let result = match timeout(timeout_sec, handle_fut).await {
        Ok(res) => res,
        Err(_) => {
            metrics.dec_in_flight();
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 504, duration);
            tracing::warn!(
                layer = "proxy",
                method = %req_method,
                path = %req_path,
                timeout_secs = timeout_sec.as_secs(),
                elapsed_ms = duration.as_millis() as u64,
                "regular request timed out; returning 504"
            );
            let body = http_body_util::Full::new(Bytes::from("Gateway Timeout")).boxed();
            return Ok(Response::builder()
                .status(504)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    };
    let duration = start_time.elapsed();

    metrics.dec_in_flight();

    match result {
        #[allow(unused_variables)]
        Ok((response, _target_url, route_scripts)) => {
            let status = response.status().as_u16();

            // --- Lua on_request_end hooks (global + route) ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                let lua_req = LuaRequest {
                    method: String::new(),
                    path: String::new(),
                    headers: std::collections::HashMap::new(),
                    host: String::new(),
                    content_length: 0,
                };
                let duration_ms = duration.as_secs_f64() * 1000.0;

                // Global on_request_end
                if engine.has_on_request_end() {
                    engine.call_on_request_end(&lua_req, status, duration_ms, &_target_url);
                }

                // Route-specific on_request_end
                for script_name in &route_scripts {
                    engine.call_route_on_request_end(
                        script_name,
                        &lua_req,
                        status,
                        duration_ms,
                        &_target_url,
                    );
                }
            }

            // Record now with the request size; response bytes stream after
            // this point, so they are counted by the CountingBody wrapper as
            // frames flow to the client.
            metrics.record_request(req_bytes_in, 0, status, duration);
            let app_name = app_name_for_target(&app_manager, &_target_url).await;
            if let Some(ref name) = app_name {
                metrics.record_app_request(name, req_bytes_in, 0, status, duration);
            }

            let mut counters = vec![metrics.bytes_sent.clone()];
            if let Some(ref name) = app_name {
                counters.push(metrics.app_bytes_sent_counter(name));
            }

            let (parts, body) = response.into_parts();
            let boxed = body.map_err(|_| unreachable!()).boxed();
            let counted = BodyExt::boxed(CountingBody::new(boxed, counters));
            Ok(Response::from_parts(parts, counted))
        }
        Err(e) => {
            metrics.inc_errors();
            Err(e)
        }
    }
}

fn is_websocket_request(req: &Request<Incoming>) -> bool {
    if let Some(upgrade) = req.headers().get("upgrade") {
        if let Ok(s) = upgrade.to_str() {
            return s.eq_ignore_ascii_case("websocket");
        }
    }
    false
}

fn is_metrics_request(req: &Request<Incoming>, endpoint: &str) -> bool {
    req.uri().path() == endpoint
}

fn is_health_request(req: &Request<Incoming>, health_config: &crate::config::HealthConfig) -> bool {
    if health_config.enabled == Some(false) {
        return false;
    }
    let path = req.uri().path();
    let liveness_path = health_config
        .liveness_path
        .as_deref()
        .unwrap_or("/health/live");
    let readiness_path = health_config
        .readiness_path
        .as_deref()
        .unwrap_or("/health/ready");
    path == liveness_path || path == readiness_path
}


/// True if `s` contains CR or LF (unsafe in raw HTTP request lines/headers).
fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

/// Case-insensitive host equality (ports already stripped by callers).
fn host_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Validate a proxy target URL after config resolution or Lua `on_route` override.
/// Only `http://`, `https://`, and `redirect://` with a non-empty host are allowed.
fn validate_proxy_target_url(url: &str) -> bool {
    if url.starts_with("redirect://") {
        let rest = url.strip_prefix("redirect://").unwrap_or("");
        if rest.is_empty() || contains_crlf(rest) {
            return false;
        }
        // Host is everything before the first `/` (path may follow).
        let host = rest.split('/').next().unwrap_or("");
        let host = host.split('@').next_back().unwrap_or(host); // drop userinfo if any
        let host = host.split('%').next().unwrap_or(host);
        return !host.is_empty()
            && !host.starts_with('[') // reject raw IPv6 form without brackets for simplicity? allow
            && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    }
    match url::Url::parse(url) {
        Ok(u) => {
            matches!(u.scheme(), "http" | "https")
                && u.host().is_some()
                && !contains_crlf(url)
        }
        Err(_) => false,
    }
}

/// Whether `host` (no port) appears as a configured domain rule or is localhost.
fn is_configured_host(host: &str, config: &crate::config::Config) -> bool {
    let host = host.split(':').next().unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    for rule in &config.rules {
        match &rule.matcher {
            crate::config::RuleMatcher::Domain(d)
            | crate::config::RuleMatcher::DomainPath(d, _)
                if host_eq(d, host) =>
            {
                return true;
            }
            _ => {}
        }
    }
    // Also allow ACME/app-registered domains tracked on the live config via rules only.
    false
}

/// Build a 413 Payload Too Large response body.
fn payload_too_large() -> Response<BoxBody> {
    Response::builder()
        .status(413)
        .header("Content-Type", "text/plain")
        .body(http_body_util::Full::new(Bytes::from("Payload Too Large")).boxed())
        .unwrap()
}

/// Map a failed backend request to 413 when the inbound body hit max_request_size.
fn backend_error_response(e: &(dyn std::error::Error + 'static)) -> Response<BoxBody> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if is_body_limit_error(err) {
            return payload_too_large();
        }
        source = err.source();
    }
    Response::builder()
        .status(502)
        .body(http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed())
        .unwrap()
}

#[cfg(feature = "scripting")]
fn apply_lua_request_mods(req: &mut Request<Incoming>, lua_req: &LuaRequest) {
    // Apply path rewrite from Lua (preserve query string).
    if lua_req.path != req.uri().path() {
        let mut parts = req.uri().clone().into_parts();
        let path_and_query = match req.uri().query() {
            Some(q) => format!("{}?{}", lua_req.path, q),
            None => lua_req.path.clone(),
        };
        if let Ok(pq) = path_and_query.parse::<http::uri::PathAndQuery>() {
            parts.path_and_query = Some(pq);
            if let Ok(uri) = hyper::Uri::from_parts(parts) {
                *req.uri_mut() = uri;
            }
        }
    }

    // Apply header mutations: Lua owns the full header map after on_request.
    // Remove headers not present in lua_req, then insert only the ones Lua
    // actually changed. Hop-by-hop and Host are still handled later in the
    // proxy path.
    let headers = req.headers_mut();
    let keep: std::collections::HashSet<String> = lua_req
        .headers
        .keys()
        .map(|k| k.to_ascii_lowercase())
        .collect();
    let to_remove: Vec<_> = headers
        .keys()
        .filter(|k| !keep.contains(k.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(name);
    }
    for (name, value) in &lua_req.headers {
        // The Lua view of headers is a lossy `HashMap<String, String>`:
        // duplicate-valued headers collapse to one entry and non-UTF8 values
        // become "". Skip re-inserting a header Lua left unchanged so we keep
        // the original bytes / duplicate values intact — only overwrite when
        // the value genuinely differs from every value currently present.
        let unchanged = {
            let existing = headers.get_all(name.as_str());
            let mut iter = existing.iter();
            let has_any = iter.next().is_some();
            (value.is_empty() && has_any)
                || existing
                    .iter()
                    .any(|v| v.to_str().map(|s| s == value).unwrap_or(false))
        };
        if unchanged {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            name.parse::<hyper::header::HeaderName>(),
            HeaderValue::from_str(value),
        ) {
            headers.insert(hn, hv);
        }
    }
}

fn handle_acme_challenge(
    req: &Request<Incoming>,
    challenge_store: &ChallengeStore,
) -> Option<Response<BoxBody>> {
    let path = req.uri().path();
    let prefix = "/.well-known/acme-challenge/";

    if !path.starts_with(prefix) {
        return None;
    }

    let token = &path[prefix.len()..];

    if let Ok(store) = challenge_store.read() {
        if let Some(key_auth) = store.get(token) {
            let body = http_body_util::Full::new(Bytes::from(key_auth.clone())).boxed();
            return Some(
                Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(body)
                    .unwrap(),
            );
        }
    }

    let body = http_body_util::Full::new(Bytes::from("Challenge not found")).boxed();
    Some(Response::builder().status(404).body(body).unwrap())
}

#[allow(clippy::too_many_arguments)]
async fn handle_websocket_request(
    mut req: Request<Incoming>,
    _client: ProxyClient,
    config: &crate::config::Config,
    metrics: &SharedMetrics,
    _start_time: std::time::Instant,
    app_manager: Option<Arc<AppManager>>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()));

    let route = find_matching_rule(&req, &config.rules);
    // Whole-domain rules (AppendPath) defer to AppManager so blue-green
    // deployment keeps working; explicit DomainPath carve-outs (StripPrefix,
    // e.g. "host/solidb/* -> ...") are more specific than the app and win.
    let override_with_app = match (&route, &host, &app_manager) {
        (Some(matched), Some(h), Some(manager))
            if matched.from_domain_rule
                && matches!(matched.resolution, UrlResolution::AppendPath) =>
        {
            manager.resolve_app_target(h).await.is_some()
        }
        _ => false,
    };
    let target_result = if override_with_app {
        None
    } else {
        find_target(&req, &config.rules)
    };

    let target_url = match target_result {
        Some((url, _, _, _)) => url,
        None => {
            if let (Some(ref manager), Some(ref h)) = (app_manager, host) {
                if let Some(target) = manager.resolve_app_target(h).await {
                    let path = req.uri().path();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{}", q))
                        .unwrap_or_default();
                    if target.url.as_str().ends_with('/') {
                        format!("{}{}{}", target.url, &path[1..], query)
                    } else {
                        format!("{}{}{}", target.url, path, query)
                    }
                } else {
                    metrics.inc_errors();
                    let body =
                        http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
                    return Ok(Response::builder().status(421).body(body).unwrap());
                }
            } else {
                metrics.inc_errors();
                let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
                return Ok(Response::builder().status(421).body(body).unwrap());
            }
        }
    };

    // A redirect:// target answers upgrade attempts with the 301 too —
    // browsers re-resolve the socket URL after following the page redirect.
    if target_url.starts_with("redirect://") {
        return Ok(build_redirect_response(&target_url));
    }

    // Extract host:port from target URL (e.g. "http://127.0.0.1:3000/path" -> "127.0.0.1:3000")
    let (backend_addr, backend_host, backend_tls) = match url::Url::parse(&target_url) {
        Ok(u) => {
            let tls = matches!(u.scheme(), "https" | "wss");
            let host = u.host_str().unwrap_or("127.0.0.1").to_string();
            let port = u.port().unwrap_or(if tls { 443 } else { 80 });
            (format!("{}:{}", host, port), host, tls)
        }
        Err(_) => {
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from("Bad backend URL")).boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
    };

    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let client_host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&backend_addr)
        .to_string();

    // Like the HTTP path: a TLS backend is an external origin that expects
    // its own name as Host (matching the SNI); the client's host still
    // reaches it via X-Forwarded-Host (in extra_headers below).
    let host_header = if backend_tls {
        backend_host.clone()
    } else {
        client_host.clone()
    };

    // Defense-in-depth: never interpolate CRLF into the raw upgrade request.
    if contains_crlf(&path)
        || contains_crlf(&query)
        || contains_crlf(&host_header)
        || contains_crlf(&client_host)
    {
        metrics.inc_errors();
        let body = http_body_util::Full::new(Bytes::from("Bad Request")).boxed();
        return Ok(Response::builder().status(400).body(body).unwrap());
    }

    // With Host rewritten to the backend's name, a same-origin upgrade's
    // `Origin: https://<client host>` trips origin checks (Phoenix
    // check_origin); align it. Cross-site Origins pass through untouched.
    if backend_tls {
        let backend_origin = format!("https://{}", backend_host);
        crate::proxy_headers::rewrite_same_origin(req.headers_mut(), &client_host, &backend_origin);
    }

    let extra_headers = build_ws_extra_headers(req.headers(), peer_addr, is_tls, &client_host);

    // debug-level: per-message upgrade chatter floods info logs (see
    // `[logging].log_endpoints` for per-request access logging instead)
    tracing::debug!(
        "WebSocket upgrade request to {}{}{}",
        backend_addr,
        path,
        query
    );

    // Connect to the backend. Bounded by a 5s connect timeout (matching the
    // HTTP pool's connect_timeout): the WS upgrade path runs before the
    // request-timeout wrapper, so an unbounded connect to a black-holed
    // backend would otherwise hang the upgrade indefinitely.
    let tcp = match timeout(Duration::from_secs(5), TcpStream::connect(&backend_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("Failed to connect to backend for WebSocket: {}", e);
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from("Backend not reachable")).boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
        Err(_) => {
            tracing::warn!(
                layer = "proxy_ws",
                backend = %backend_addr,
                path = %path,
                timeout_secs = 5,
                "websocket backend connect timed out; returning 504"
            );
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from("Gateway Timeout")).boxed();
            return Ok(Response::builder().status(504).body(body).unwrap());
        }
    };

    // Wrap the stream in TLS when the backend target is https/wss.
    let backend: Box<dyn AsyncStream> = if backend_tls {
        let server_name = match rustls_pki_types::ServerName::try_from(backend_host.clone()) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(
                    "Invalid TLS server name for WebSocket backend {}: {}",
                    backend_host,
                    e
                );
                metrics.inc_errors();
                let body = http_body_util::Full::new(Bytes::from("Bad backend URL")).boxed();
                return Ok(Response::builder().status(502).body(body).unwrap());
            }
        };
        match timeout(
            Duration::from_secs(5),
            ws_backend_tls_connector().connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => Box::new(s),
            Ok(Err(e)) => {
                tracing::error!(
                    "TLS handshake with WebSocket backend {} failed: {}",
                    backend_addr,
                    e
                );
                metrics.inc_errors();
                let body = http_body_util::Full::new(Bytes::from("Backend not reachable")).boxed();
                return Ok(Response::builder().status(502).body(body).unwrap());
            }
            Err(_) => {
                tracing::warn!(
                    layer = "proxy_ws",
                    backend = %backend_addr,
                    path = %path,
                    timeout_secs = 5,
                    "websocket backend TLS handshake timed out; returning 504"
                );
                metrics.inc_errors();
                let body = http_body_util::Full::new(Bytes::from("Gateway Timeout")).boxed();
                return Ok(Response::builder().status(504).body(body).unwrap());
            }
        }
    } else {
        Box::new(tcp)
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

    if contains_crlf(&ws_key)
        || contains_crlf(&ws_version)
        || ws_protocol.as_deref().is_some_and(contains_crlf)
    {
        metrics.inc_errors();
        let body = http_body_util::Full::new(Bytes::from("Bad Request")).boxed();
        return Ok(Response::builder().status(400).body(body).unwrap());
    }

    let mut handshake = format!(
        "GET {}{} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: {}\r\n",
        path, query, host_header, ws_key, ws_version,
    );
    if let Some(proto) = &ws_protocol {
        handshake.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", proto));
    }
    handshake.push_str(&extra_headers);
    handshake.push_str("\r\n");

    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    if let Err(e) = backend_write.write_all(handshake.as_bytes()).await {
        tracing::error!("Failed to send WebSocket handshake to backend: {}", e);
        metrics.inc_errors();
        let body =
            http_body_util::Full::new(Bytes::from("Failed to initiate WebSocket with backend"))
                .boxed();
        return Ok(Response::builder().status(502).body(body).unwrap());
    }

    // Read the backend's 101 response. Bounded by a timeout so a backend that
    // accepts the socket (connect already succeeded above) but never sends the
    // upgrade response cannot hang the client indefinitely.
    let mut response_buf = vec![0u8; 4096];
    let n = match timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut backend_read, &mut response_buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        Ok(_) => {
            tracing::error!("No response from backend for WebSocket upgrade");
            metrics.inc_errors();
            let body = http_body_util::Full::new(Bytes::from(
                "Backend did not respond to WebSocket upgrade",
            ))
            .boxed();
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
        Err(_) => {
            tracing::error!("Backend timed out sending WebSocket upgrade response");
            metrics.inc_errors();
            let body =
                http_body_util::Full::new(Bytes::from("Backend timed out on WebSocket upgrade"))
                    .boxed();
            return Ok(Response::builder().status(504).body(body).unwrap());
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    let status_ok = response_str
        .lines()
        .next()
        .map(|l| l.starts_with("HTTP/1.1 101") || l.starts_with("HTTP/1.0 101"))
        .unwrap_or(false);
    if !status_ok {
        tracing::error!(
            "Backend rejected WebSocket upgrade: {}",
            response_str.lines().next().unwrap_or("")
        );
        metrics.inc_errors();
        let body =
            http_body_util::Full::new(Bytes::from("Backend rejected WebSocket upgrade")).boxed();
        return Ok(Response::builder().status(502).body(body).unwrap());
    }

    // Extract headers from backend 101 response
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

    // Check for trailing data after the HTTP response headers.
    // The backend may send WebSocket frames immediately after the 101
    // response; if they arrive in the same TCP segment as the response
    // headers they would be in our buffer and must be forwarded.
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
    let backend_stream = backend_read.unsplit(backend_write);

    // Snapshot WS limits while we still have access to `config` (the spawned
    // task captures only what's needed by-value).
    let ws_idle = Duration::from_secs(config.limits.websocket_idle_timeout_secs.unwrap_or(300));
    let ws_lifetime =
        Duration::from_secs(config.limits.websocket_max_lifetime_secs.unwrap_or(3600));
    let ws_max_bytes = config
        .limits
        .websocket_max_bytes_per_direction
        .unwrap_or(1_073_741_824);
    let ws_deadline = std::time::Instant::now() + ws_lifetime;

    // Byte counters for the copy task: backend→client counts as sent,
    // client→backend as received.
    let ws_bytes_sent = metrics.bytes_sent.clone();
    let ws_bytes_received = metrics.bytes_received.clone();

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

                // Run both halves with the configured idle-timeout, lifetime
                // deadline, and byte cap. select! ensures that as soon as
                // either direction terminates (EOF, timeout, byte cap, or
                // error), the other half is dropped — a half-closed forwarder
                // is useless and would otherwise hold both ends open.
                tokio::select! {
                    _ = forward_ws_half(br, cw, ws_idle, ws_deadline, ws_max_bytes, Some(ws_bytes_sent)) => {},
                    _ = forward_ws_half(cr, bw, ws_idle, ws_deadline, ws_max_bytes, Some(ws_bytes_received)) => {},
                }
            }
            Err(e) => {
                tracing::error!("WebSocket client upgrade failed: {}", e);
            }
        }
    });

    metrics.dec_in_flight();

    // Return 101 Switching Protocols to the client
    let mut resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key);
    if let Some(proto) = resp_protocol {
        resp = resp.header("Sec-WebSocket-Protocol", proto);
    }
    Ok(resp
        .body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap())
}

/// Returns (Response, target_url_for_logging, route_scripts)
#[allow(clippy::too_many_arguments)]
async fn handle_regular_request(
    req: Request<Incoming>,
    client: ProxyClient,
    config: &crate::config::Config,
    lua_engine: &OptionalLuaEngine,
    circuit_breaker: &SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
) -> Result<(Response<BoxBody>, String, Vec<String>), hyper::Error> {
    let route = find_matching_rule(&req, &config.rules);
    // Prefer the Host header over the URI authority. An HTTP/1.1 absolute-form
    // request can carry an attacker-controlled authority that would otherwise
    // bypass per-host routing rules. Mirrors the shape applied in
    // find_matching_rule and handle_websocket_request.
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()));
    tracing::debug!(
        "handle_regular_request: uri.host={:?}, selected.host={:?}, rules.len={}",
        req.uri().host(),
        host,
        config.rules.len()
    );

    // When a static domain rule matches but AppManager manages this domain,
    // prefer dynamic app routing so blue-green deployment works correctly.
    // Whole-domain rules (AppendPath) defer to AppManager so blue-green
    // deployment keeps working; explicit DomainPath carve-outs (StripPrefix,
    // e.g. "host/solidb/* -> ...") are more specific than the app and win.
    let override_with_app = match (&route, &host, &app_manager) {
        (Some(matched), Some(h), Some(manager))
            if matched.from_domain_rule
                && matches!(matched.resolution, UrlResolution::AppendPath) =>
        {
            manager.resolve_app_target(h).await.is_some()
        }
        _ => false,
    };
    let route = if override_with_app { None } else { route };

    match route {
        #[allow(unused_mut, unused_variables)]
        Some(matched_route) => {
            let path = req.uri().path().to_string();
            let from_domain_rule = matched_route.from_domain_rule;
            let matched_prefix = matched_route.matched_prefix(is_tls);
            let html_rewrite_prefix = matched_route.html_rewrite_prefix();

            if !matched_route.auth.is_empty() && !verify_basic_auth(&req, &matched_route.auth) {
                tracing::debug!("Basic auth failed for {}", req.uri().path());
                return Ok((create_auth_required_response(), String::new(), vec![]));
            }
            let route_scripts = matched_route.route_scripts.clone();
            let query = req.uri().query().map(|q| q.to_string());

            // Select an available target via circuit breaker
            let target_selection = select_target(
                &matched_route,
                &path,
                query.as_deref(),
                circuit_breaker,
                &load_balancer,
            );
            let (mut target_url, base_url) = match target_selection {
                Some((url, base)) => (url, base),
                None => {
                    // All targets are circuit-broken
                    let body =
                        http_body_util::Full::new(Bytes::from("Service Unavailable")).boxed();
                    return Ok((
                        Response::builder()
                            .status(503)
                            .body(body)
                            .expect("Failed to build response"),
                        String::new(),
                        route_scripts,
                    ));
                }
            };
            // --- Lua route-specific on_request hooks ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                for script_name in &route_scripts {
                    let mut lua_req = build_lua_request(&req);
                    match engine.call_route_on_request(script_name, &mut lua_req) {
                        RequestHookResult::Deny { status, body } => {
                            let resp_body = http_body_util::Full::new(Bytes::from(body)).boxed();
                            return Ok((
                                Response::builder().status(status).body(resp_body).unwrap(),
                                target_url,
                                route_scripts.clone(),
                            ));
                        }
                        RequestHookResult::Continue(_) => {}
                    }
                }
            }

            // --- Lua on_route hook (global) ---
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                if engine.has_on_route() {
                    let lua_req = build_lua_request(&req);
                    match engine.call_on_route(&lua_req, &target_url) {
                        RouteHookResult::Override(new_url) => {
                            if validate_proxy_target_url(&new_url) {
                                target_url = new_url;
                            } else {
                                tracing::warn!(
                                    "Lua on_route returned disallowed target URL, ignoring: {}",
                                    new_url
                                );
                            }
                        }
                        RouteHookResult::Default => {}
                    }
                }
                // Route-specific on_route hooks
                for script_name in &route_scripts {
                    let lua_req = build_lua_request(&req);
                    match engine.call_route_on_route(script_name, &lua_req, &target_url) {
                        RouteHookResult::Override(new_url) => {
                            if validate_proxy_target_url(&new_url) {
                                target_url = new_url;
                            } else {
                                tracing::warn!(
                                    "Lua on_route ({}) returned disallowed target URL, ignoring: {}",
                                    script_name,
                                    new_url
                                );
                            }
                        }
                        RouteHookResult::Default => {}
                    }
                }
            }

            // Reject non-http(s)/redirect targets (config misparse). Validate the
            // backend authority (`base_url`), not the resolved `target_url`, so we
            // don't re-parse the request path/query on every request — and because
            // Lua overrides were already validated above when they replaced it.
            if !validate_proxy_target_url(&base_url) {
                tracing::warn!("Refusing to proxy disallowed target URL: {}", target_url);
                let body = http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                return Ok((
                    Response::builder().status(502).body(body).unwrap(),
                    target_url,
                    route_scripts,
                ));
            }

            // A redirect:// target short-circuits proxying: 301 to the same
            // path/query on the new origin. Used to move a site to a new
            // canonical domain (`old.example -> redirect://new.example`).
            // Checked after the on_route hooks so Lua can also return one.
            if target_url.starts_with("redirect://") {
                return Ok((
                    build_redirect_response(&target_url),
                    target_url,
                    route_scripts,
                ));
            }

            // An https target is an external origin whose vhost/CDN expects
            // its own name as Host (matching the TLS SNI) — forwarding the
            // client's Host there gets rejected (e.g. Cloudflare 403). The
            // original host is still passed via X-Forwarded-Host.
            let https_target = target_url.starts_with("https://");

            // Only extract host_header when needed (domain rules and https
            // targets). Prefer the Host header over URI authority so an
            // absolute-form request cannot inject an arbitrary
            // X-Forwarded-Host into the backend.
            let host_header = if from_domain_rule || https_target {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.to_string())
                    .or_else(|| req.uri().host().map(|h| h.to_string()))
            } else {
                None
            };

            let (mut parts, body) = req.into_parts();

            // Move headers directly instead of cloning one by one
            let uri = match target_url.parse::<hyper::Uri>() {
                Ok(uri) => uri,
                Err(e) => {
                    tracing::warn!(
                        "Invalid URI from Lua hook or target URL: {}: {}",
                        target_url,
                        e
                    );
                    let body = http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                    return Ok((
                        Response::builder().status(502).body(body).unwrap(),
                        target_url,
                        route_scripts,
                    ));
                }
            };
            parts.uri = uri;
            parts.version = http::Version::HTTP_11;
            parts.extensions = http::Extensions::new();

            // Rewrite Host to the https origin's own authority (see
            // https_target above); the client's host goes to X-Forwarded-Host.
            if https_target {
                if let Some(authority) = parts.uri.authority() {
                    if let Ok(v) = HeaderValue::from_str(authority.as_str()) {
                        parts.headers.insert(hyper::header::HOST, v);
                    }
                    // With Host rewritten, a same-origin `Origin: https://<client
                    // host>` no longer matches the request authority and trips
                    // CSRF origin checks (Phoenix/Bonfire). Align it; cross-site
                    // Origins pass through untouched.
                    if let Some(client_host) = &host_header {
                        let backend_origin = format!("https://{}", authority);
                        crate::proxy_headers::rewrite_same_origin(
                            &mut parts.headers,
                            client_host,
                            &backend_origin,
                        );
                    }
                }
            }

            crate::proxy_headers::strip_hop_by_hop(&mut parts.headers);
            // HTTP/2 browsers split cookies across multiple `cookie` fields;
            // join them before forwarding to the HTTP/1.1 upstream so servers
            // that read only the first Cookie header (redbean) see them all.
            crate::proxy_headers::coalesce_cookies(&mut parts.headers);

            let outbound_body = proxy_request_body(body, config.limits.max_request_size);
            let mut request = Request::from_parts(parts, outbound_body);

            request.headers_mut().insert(
                "X-Forwarded-For",
                peer_addr
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            request.headers_mut().insert(
                "X-Forwarded-Proto",
                if is_tls {
                    X_FORWARDED_PROTO_HTTPS.clone()
                } else {
                    X_FORWARDED_PROTO_HTTP.clone()
                },
            );

            if from_domain_rule || https_target {
                if let Some(host) = host_header {
                    if let Ok(v) = HeaderValue::from_str(&host) {
                        request.headers_mut().insert("X-Forwarded-Host", v);
                    }
                }
            }

            match client.request(request).await {
                Ok(mut response) => {
                    // Hop-by-hop headers are per-connection and must not be
                    // relayed (RFC 7230 §6.1). In particular a chunked
                    // upstream's `Transfer-Encoding` header survives while
                    // hyper has already de-chunked the body — re-sending it
                    // makes the h1 server abort with User(UnexpectedHeader).
                    crate::proxy_headers::strip_hop_by_hop(response.headers_mut());

                    // --- Circuit breaker: record success or failure ---
                    let status_code = response.status().as_u16();
                    if circuit_breaker.is_failure_status(status_code) {
                        circuit_breaker.record_failure(&base_url);
                    } else {
                        circuit_breaker.record_success(&base_url);
                    }

                    // --- Lua on_response hooks (global + route) ---
                    #[cfg(feature = "scripting")]
                    if let Some(ref engine) = lua_engine {
                        let has_global = engine.has_on_response();
                        let has_route = !route_scripts.is_empty();

                        if has_global || has_route {
                            use crate::scripting::ResponseMod;

                            let lua_req = LuaRequest {
                                method: String::new(),
                                path: String::new(),
                                headers: std::collections::HashMap::new(),
                                host: String::new(),
                                content_length: 0,
                            };
                            let resp_headers = extract_response_headers(response.headers());
                            let resp_status = response.status().as_u16();

                            // Collect all mods: global first, then route scripts
                            let mut all_mods: Vec<ResponseMod> = Vec::new();
                            if has_global {
                                all_mods.push(engine.call_on_response(
                                    &lua_req,
                                    resp_status,
                                    &resp_headers,
                                ));
                            }
                            for script_name in &route_scripts {
                                all_mods.push(engine.call_route_on_response(
                                    script_name,
                                    &lua_req,
                                    resp_status,
                                    &resp_headers,
                                ));
                            }

                            // Merge all mods
                            let mut merged = ResponseMod::default();
                            for mods in all_mods {
                                merged.set_headers.extend(mods.set_headers);
                                merged.remove_headers.extend(mods.remove_headers);
                                if mods.replace_body.is_some() {
                                    merged.replace_body = mods.replace_body;
                                }
                                if mods.override_status.is_some() {
                                    merged.override_status = mods.override_status;
                                }
                            }

                            // Apply modifications if any
                            if !merged.set_headers.is_empty()
                                || !merged.remove_headers.is_empty()
                                || merged.replace_body.is_some()
                                || merged.override_status.is_some()
                            {
                                let (mut parts, body) = response.into_parts();

                                if let Some(status) = merged.override_status {
                                    parts.status =
                                        hyper::StatusCode::from_u16(status).unwrap_or(parts.status);
                                }

                                for name in &merged.remove_headers {
                                    if let Ok(header_name) =
                                        name.parse::<hyper::header::HeaderName>()
                                    {
                                        parts.headers.remove(header_name);
                                    }
                                }

                                for (name, value) in &merged.set_headers {
                                    if let (Ok(header_name), Ok(header_value)) = (
                                        name.parse::<hyper::header::HeaderName>(),
                                        value.parse::<HeaderValue>(),
                                    ) {
                                        parts.headers.insert(header_name, header_value);
                                    }
                                }

                                if let Some(new_body) = merged.replace_body {
                                    let new_bytes = Bytes::from(new_body);
                                    parts.headers.remove("content-length");
                                    parts.headers.insert(
                                        "content-length",
                                        new_bytes.len().to_string().parse().unwrap(),
                                    );
                                    let boxed = http_body_util::Full::new(new_bytes).boxed();
                                    return Ok((
                                        Response::from_parts(parts, boxed),
                                        target_url,
                                        route_scripts.clone(),
                                    ));
                                }

                                let boxed = body.map_err(|_| unreachable!()).boxed();
                                return Ok((
                                    Response::from_parts(parts, boxed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }
                        }
                    }

                    // Rewrite Location header for redirects when a prefix is matched
                    // This ensures redirects go through the proxy, not directly to the backend
                    if let Some(prefix) = matched_prefix.as_ref() {
                        if (300..400).contains(&status_code) {
                            if let Some(location) = response.headers().get("location") {
                                if let Ok(location_str) = location.to_str() {
                                    if location_str.starts_with('/') {
                                        let new_location = format!("{}{}", prefix, location_str);
                                        let (mut parts, body) = response.into_parts();
                                        parts
                                            .headers
                                            .insert("location", new_location.parse().unwrap());
                                        let boxed = body.map_err(|_| unreachable!()).boxed();
                                        return Ok((
                                            Response::from_parts(parts, boxed),
                                            target_url,
                                            route_scripts,
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    let is_html = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.starts_with("text/html"))
                        .unwrap_or(false);

                    // The rewrite below can only decode gzip/deflate. Bodies
                    // with any other encoding (br, zstd — common from CDN
                    // origins) must pass through untouched: mangling them
                    // through from_utf8_lossy and dropping content-encoding
                    // serves compressed bytes as text.
                    let rewritable_encoding = response
                        .headers()
                        .get("content-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(|enc| {
                            enc.split(',').map(str::trim).all(|e| {
                                matches!(
                                    e.to_ascii_lowercase().as_str(),
                                    "gzip" | "x-gzip" | "deflate" | "identity" | ""
                                )
                            })
                        })
                        .unwrap_or(true);

                    if is_html && rewritable_encoding {
                        // Only path-prefix (StripPrefix) routes need URL
                        // rewriting; whole-domain apps stream through untouched
                        // (see `html_rewrite_prefix`), so their HTML is never
                        // buffered/decoded.
                        if let Some(prefix) = html_rewrite_prefix {
                            // Rewriting changes the body length, so a fixed
                            // Content-Length no longer applies — both streaming
                            // paths below drop it and let hyper stream chunked.
                            let encoding = response
                                .headers()
                                .get("content-encoding")
                                .and_then(|v| v.to_str().ok())
                                .map(|e| e.to_ascii_lowercase())
                                .unwrap_or_default();

                            // Uncompressed HTML: rewrite on the fly so the client
                            // receives bytes as the backend produces them.
                            if !encoding.contains("gzip") && !encoding.contains("deflate") {
                                let (mut parts, body) = response.into_parts();
                                parts.headers.remove("content-length");
                                let inner = body.map_err(|_| unreachable!()).boxed();
                                let rewritten = RewritingBody::new(inner, &prefix).boxed();
                                return Ok((
                                    Response::from_parts(parts, rewritten),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }

                            // gzip HTML: incrementally decode + rewrite as it
                            // streams (emitted identity), so compressed pages on
                            // a path-prefix mount no longer buffer the whole body.
                            if encoding.contains("gzip") {
                                let (mut parts, body) = response.into_parts();
                                parts.headers.remove("content-encoding");
                                parts.headers.remove("content-length");
                                let inner = body.map_err(|_| unreachable!()).boxed();
                                let streamed =
                                    DecodingRewritingBody::new_gzip(inner, &prefix).boxed();
                                return Ok((
                                    Response::from_parts(parts, streamed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }

                            // deflate (rare): fall back to the bounded buffered
                            // decode + rewrite path below.
                            let (parts, body) = response.into_parts();
                            let body_bytes = body
                                .collect()
                                .await
                                .map(|collected| collected.to_bytes())
                                .unwrap_or_default();

                            if body_bytes.len() <= MAX_HTML_REWRITE_SIZE {
                                let is_gzip = parts
                                    .headers
                                    .get("content-encoding")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|v| v.contains("gzip"))
                                    .unwrap_or(false);
                                let is_deflate = parts
                                    .headers
                                    .get("content-encoding")
                                    .and_then(|v| v.to_str().ok())
                                    .map(|v| v.contains("deflate"))
                                    .unwrap_or(false);

                                let raw_bytes = if is_gzip {
                                    use std::io::Read;
                                    let mut decoder = flate2::read::GzDecoder::new(&body_bytes[..]);
                                    let mut decoded = Vec::new();
                                    decoder.read_to_end(&mut decoded).unwrap_or_default();
                                    Bytes::from(decoded)
                                } else if is_deflate {
                                    use std::io::Read;
                                    let mut decoder =
                                        flate2::read::DeflateDecoder::new(&body_bytes[..]);
                                    let mut decoded = Vec::new();
                                    decoder.read_to_end(&mut decoded).unwrap_or_default();
                                    Bytes::from(decoded)
                                } else {
                                    body_bytes.clone()
                                };

                                let html = String::from_utf8_lossy(&raw_bytes);
                                if html.contains("<script")
                                    && (html.contains("integrity=") || html.contains("nonce="))
                                {
                                    tracing::warn!(
                                        "Skipping HTML rewrite for prefix {} due to SRI/nonce attributes",
                                        prefix
                                    );
                                    // raw_bytes is the *decoded* body — the
                                    // original encoding/length headers no
                                    // longer describe it.
                                    let mut parts = parts;
                                    parts.headers.remove("content-encoding");
                                    parts.headers.remove("content-length");
                                    parts.headers.insert(
                                        "content-length",
                                        raw_bytes.len().to_string().parse().unwrap(),
                                    );
                                    let body = http_body_util::Full::new(raw_bytes).boxed();
                                    return Ok((
                                        Response::from_parts(parts, body),
                                        target_url,
                                        route_scripts.clone(),
                                    ));
                                }
                                let rewritten = html
                                    .replace("href=\"/", &format!("href=\"{}/", prefix))
                                    .replace("src=\"/", &format!("src=\"{}/", prefix))
                                    .replace("action=\"/", &format!("action=\"{}/", prefix));
                                let rewritten_bytes = Bytes::from(rewritten);
                                let mut parts = parts;
                                parts.headers.remove("content-encoding");
                                parts.headers.remove("content-length");
                                parts.headers.insert(
                                    "content-length",
                                    rewritten_bytes.len().to_string().parse().unwrap(),
                                );
                                let boxed = http_body_util::Full::new(rewritten_bytes).boxed();
                                return Ok((
                                    Response::from_parts(parts, boxed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            } else {
                                let body = http_body_util::Full::new(body_bytes).boxed();
                                return Ok((
                                    Response::from_parts(parts, body),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }
                        }
                    }

                    let (parts, body) = response.into_parts();
                    let boxed = body.map_err(|_| unreachable!()).boxed();
                    Ok((
                        Response::from_parts(parts, boxed),
                        target_url,
                        route_scripts,
                    ))
                }
                Err(e) => {
                    // A body-limit rejection is the client's fault, not the
                    // backend's — the backend never saw a completed request, so
                    // do not count it against the circuit breaker (otherwise
                    // oversized uploads could trip a healthy backend offline).
                    if !is_body_limit_error(&e) {
                        circuit_breaker.record_failure(&base_url);
                    }
                    tracing::error!(
                        "Backend request failed: {} (target: {})",
                        error_chain(&e),
                        target_url
                    );
                    Ok((
                        backend_error_response(&e),
                        target_url,
                        route_scripts,
                    ))
                }
            }
        }
        None => {
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
                .or_else(|| req.uri().host().map(|h| h.to_string()));
            let app_manager_available = app_manager.is_some();

            if let (Some(ref manager), Some(ref h)) = (app_manager, host) {
                if let Some(target) = manager.resolve_app_target(h).await {
                    let base_url = target.url.to_string();
                    let path = req.uri().path();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{}", q))
                        .unwrap_or_default();
                    let target_url = if target.url.as_str().ends_with('/') {
                        format!("{}{}{}", target.url, &path[1..], query)
                    } else {
                        format!("{}{}{}", target.url, path, query)
                    };
                    let forwarded_host = h.clone();

                    let (mut parts, body) = req.into_parts();
                    let uri = match target_url.parse::<hyper::Uri>() {
                        Ok(uri) => uri,
                        Err(e) => {
                            tracing::warn!(
                                "Invalid URI in app-managed path: {}: {}",
                                target_url,
                                e
                            );
                            let body =
                                http_body_util::Full::new(Bytes::from("Bad Gateway")).boxed();
                            return Ok((
                                Response::builder().status(502).body(body).unwrap(),
                                target_url,
                                vec![],
                            ));
                        }
                    };
                    parts.uri = uri;
                    parts.version = http::Version::HTTP_11;
                    parts.extensions = http::Extensions::new();

                    // HTTP/2 browsers split cookies across multiple `cookie`
                    // fields; join them before forwarding to the HTTP/1.1
                    // upstream so servers that read only the first Cookie header
                    // (redbean) see them all. This app-managed path is what the
                    // proxy-deployed redbean apps (e.g. db.solisoft.test) use.
                    crate::proxy_headers::coalesce_cookies(&mut parts.headers);

                    let outbound_body = proxy_request_body(body, config.limits.max_request_size);
                    let mut request = Request::from_parts(parts, outbound_body);
                    request.headers_mut().insert(
                        "X-Forwarded-For",
                        peer_addr
                            .map(|addr| addr.ip().to_string())
                            .unwrap_or_default()
                            .parse()
                            .unwrap_or_else(|_| HeaderValue::from_static("")),
                    );
                    request.headers_mut().insert(
                        "X-Forwarded-Proto",
                        if is_tls {
                            X_FORWARDED_PROTO_HTTPS.clone()
                        } else {
                            X_FORWARDED_PROTO_HTTP.clone()
                        },
                    );
                    if let Ok(v) = HeaderValue::from_str(&forwarded_host) {
                        request.headers_mut().insert("X-Forwarded-Host", v);
                    }

                    match client.request(request).await {
                        Ok(mut response) => {
                            // Hop-by-hop headers must not be relayed (see the
                            // route path above).
                            crate::proxy_headers::strip_hop_by_hop(response.headers_mut());

                            let status_code = response.status().as_u16();
                            if circuit_breaker.is_failure_status(status_code) {
                                circuit_breaker.record_failure(&base_url);
                            } else {
                                circuit_breaker.record_success(&base_url);
                            }
                            let (parts, body) = response.into_parts();
                            let boxed = body.map_err(|_| unreachable!()).boxed();
                            return Ok((Response::from_parts(parts, boxed), target_url, vec![]));
                        }
                        Err(e) => {
                            // A body-limit rejection is client-caused (oversized
                            // upload); the backend never saw a failed request, so
                            // skip both the failure count and the async failover —
                            // otherwise a client could trip a healthy app offline.
                            let body_limit = is_body_limit_error(&e);
                            if !body_limit {
                                circuit_breaker.record_failure(&base_url);
                            }
                            tracing::error!(
                                "Backend request failed: {} (target: {})",
                                error_chain(&e),
                                target_url
                            );
                            // Trigger immediate async failover so the next
                            // request hits a healthy backend (skip on body-limit
                            // 413 — the backend never saw a failed request).
                            if !body_limit {
                                let mgr = manager.clone();
                                let host = h.clone();
                                tokio::spawn(async move {
                                    if let Some(app_name) = mgr.app_name_for_host(&host).await {
                                        mgr.trigger_async_failover(app_name);
                                    }
                                });
                            }
                            return Ok((
                                backend_error_response(&e),
                                target_url,
                                vec![],
                            ));
                        }
                    }
                }
            }

            let _ = lua_engine;
            tracing::warn!("Returning 421 Misdirected Request - no route found for host, app_manager available: {}", app_manager_available);
            let body = http_body_util::Full::new(Bytes::from("Misdirected Request")).boxed();
            Ok((
                Response::builder()
                    .status(421)
                    .body(body)
                    .expect("Failed to build response"),
                String::new(),
                vec![],
            ))
        }
    }
}

/// How the target URL is resolved from the matched route
enum UrlResolution {
    /// Domain, Default: append full request path
    AppendPath,
    /// DomainPath, Prefix: strip prefix, append suffix
    StripPrefix(String),
    /// Exact, Regex: use target URL as-is
    Identity,
}

/// A matched routing rule with all the info needed to resolve a target URL
struct MatchedRoute<'a> {
    targets: &'a [crate::config::Target],
    from_domain_rule: bool,
    resolution: UrlResolution,
    route_scripts: Vec<String>,
    auth: Vec<crate::auth::BasicAuth>,
    load_balancing: &'a crate::config::LoadBalancingStrategy,
    host: String,
    /// Index into `config.rules` — used for independent per-route LB counters.
    rule_idx: usize,
}

impl<'a> MatchedRoute<'a> {
    fn matched_prefix(&self, is_tls: bool) -> Option<String> {
        match &self.resolution {
            UrlResolution::StripPrefix(prefix) => Some(prefix.trim_end_matches('/').to_string()),
            UrlResolution::AppendPath => {
                let scheme = if is_tls { "https" } else { "http" };
                Some(format!("{}://{}", scheme, self.host))
            }
            _ => None,
        }
    }

    /// Path prefix to splice into root-relative HTML URLs (`href="/x"` ->
    /// `href="/prefix/x"`). Only path-based (StripPrefix) routes need this: a
    /// whole-domain (AppendPath) app serves its HTML at the domain root, so
    /// root-relative URLs already resolve correctly. Rewriting them there to
    /// absolute `https://host/...` URLs is a pointless no-op that would force
    /// the response to be buffered (and gzip-decoded) for nothing — the very
    /// thing that stalls progressive HTML delivery. Returning None lets such
    /// responses stream straight through, compression intact.
    fn html_rewrite_prefix(&self) -> Option<String> {
        match &self.resolution {
            UrlResolution::StripPrefix(prefix) => Some(prefix.trim_end_matches('/').to_string()),
            _ => None,
        }
    }
}

/// Resolve a target URL based on the resolution strategy
fn resolve_target_url(
    target: &crate::config::Target,
    path: &str,
    query: Option<&str>,
    resolution: &UrlResolution,
) -> String {
    let target_str = target.url.as_str();
    let qs = match query {
        Some(q) if !q.is_empty() => format!("?{}", q),
        _ => String::new(),
    };
    match resolution {
        UrlResolution::AppendPath => {
            if target_str.ends_with('/') {
                format!("{}{}{}", target_str, &path[1..], qs)
            } else {
                format!("{}{}{}", target_str, path, qs)
            }
        }
        UrlResolution::StripPrefix(prefix) => {
            let suffix = if path.len() >= prefix.len() {
                &path[prefix.len()..]
            } else {
                ""
            };
            format!("{}{}{}", target_str, suffix, qs)
        }
        UrlResolution::Identity => {
            if qs.is_empty() {
                target_str.to_owned()
            } else {
                format!("{}{}", target_str, qs)
            }
        }
    }
}

/// Build the 301 response for a `redirect://` rule target. The resolved
/// target already carries the request's path/query appended by
/// `resolve_target_url`; only the scheme is swapped to https. Redirect rules
/// always point at an https destination — the proxy itself only serves
/// redirects for domains it terminates TLS for.
fn build_redirect_response(target_url: &str) -> Response<BoxBody> {
    let rest = target_url.strip_prefix("redirect://").unwrap_or(target_url);
    let location = format!("https://{}", rest);
    match HeaderValue::from_str(&location) {
        Ok(loc) => Response::builder()
            .status(301)
            .header(hyper::header::LOCATION, loc)
            .body(http_body_util::Full::new(Bytes::from("Moved Permanently")).boxed())
            .unwrap(),
        // A request path with bytes invalid in a header value cannot be
        // reflected into Location; reject rather than emit a broken redirect.
        Err(_) => Response::builder()
            .status(400)
            .body(http_body_util::Full::new(Bytes::from("Bad Request")).boxed())
            .unwrap(),
    }
}

/// Pure routing: find which rule matches the request.
/// Host matching is case-insensitive; the first matching rule wins.
fn find_matching_rule<'a>(
    req: &Request<Incoming>,
    rules: &'a [crate::config::ProxyRule],
) -> Option<MatchedRoute<'a>> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()))?;

    let path = req.uri().path();
    // Domain / DomainPath — case-insensitive host match, first rule wins.
    // A single linear scan is used regardless of rule count: routing does one
    // lookup per request, so building a transient index (O(rules) allocations
    // every request) would cost more than the scan it replaces.
    for (i, rule) in rules.iter().enumerate() {
        match &rule.matcher {
            crate::config::RuleMatcher::Domain(domain)
                if host_eq(domain.as_str(), host.as_str()) && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: true,
                    resolution: UrlResolution::AppendPath,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: domain.clone(),
                    rule_idx: i,
                });
            }
            crate::config::RuleMatcher::DomainPath(domain, path_prefix)
                if host_eq(domain.as_str(), host.as_str()) && !rule.targets.is_empty() =>
            {
                let matches = path.starts_with(path_prefix.as_str())
                    || (path_prefix.ends_with('/')
                        && path == path_prefix.trim_end_matches('/'));
                if matches {
                    return Some(MatchedRoute {
                        targets: &rule.targets,
                        from_domain_rule: true,
                        resolution: UrlResolution::StripPrefix(path_prefix.clone()),
                        route_scripts: rule.scripts.clone(),
                        auth: rule.auth.clone(),
                        load_balancing: &rule.load_balancing,
                        host: domain.clone(),
                        rule_idx: i,
                    });
                }
            }
            _ => {}
        }
    }

    // Check specific rules (Exact, Prefix, Regex) before Default
    for (i, rule) in rules.iter().enumerate() {
        match &rule.matcher {
            crate::config::RuleMatcher::Exact(exact)
                if path == exact && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                    rule_idx: i,
                });
            }
            crate::config::RuleMatcher::Prefix(prefix) if !rule.targets.is_empty() => {
                // Match /db against prefix /db/ (path without trailing slash)
                let matches = path.starts_with(prefix.as_str())
                    || (prefix.ends_with('/') && path == prefix.trim_end_matches('/'));
                if matches {
                    return Some(MatchedRoute {
                        targets: &rule.targets,
                        from_domain_rule: false,
                        resolution: UrlResolution::StripPrefix(prefix.clone()),
                        route_scripts: rule.scripts.clone(),
                        auth: rule.auth.clone(),
                        load_balancing: &rule.load_balancing,
                        host: host.to_string(),
                        rule_idx: i,
                    });
                }
            }
            crate::config::RuleMatcher::Regex(ref rm)
                if rm.is_match(path) && !rule.targets.is_empty() =>
            {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                    rule_idx: i,
                });
            }
            _ => {}
        }
    }

    // Fall back to Default rule
    for (i, rule) in rules.iter().enumerate() {
        if let crate::config::RuleMatcher::Default = &rule.matcher {
            if !rule.targets.is_empty() {
                return Some(MatchedRoute {
                    targets: &rule.targets,
                    from_domain_rule: false,
                    resolution: UrlResolution::Identity,
                    route_scripts: rule.scripts.clone(),
                    auth: rule.auth.clone(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                    rule_idx: i,
                });
            }
        }
    }

    None
}

/// Select a target based on the load balancing strategy.
/// Returns (resolved_url, base_url) for logging and circuit breaker tracking.
fn select_target(
    route: &MatchedRoute<'_>,
    path: &str,
    query: Option<&str>,
    circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
    load_balancer: &LoadBalancerState,
) -> Option<(String, String)> {
    let targets = route.targets;
    if targets.is_empty() {
        return None;
    }

    match route.load_balancing {
        crate::config::LoadBalancingStrategy::Failover => {
            // Failover: use first available target (circuit breaker aware)
            for target in targets {
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
        crate::config::LoadBalancingStrategy::RoundRobin => {
            // Round-robin: cycle through all targets, skip unhealthy ones
            let num_targets = targets.len();
            if num_targets == 0 {
                return None;
            }
            let start_idx = load_balancer.select_index(route.rule_idx, num_targets);

            for i in 0..num_targets {
                let idx = (start_idx + i) % num_targets;
                let target = &targets[idx];
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
        crate::config::LoadBalancingStrategy::Weighted => {
            // Weighted: use weights to determine distribution, skip unhealthy
            let total_weight: u32 = targets.iter().map(|t| t.weight as u32).sum();
            // All weights zero: fall through to "first available" below instead
            // of recursing on the same Weighted route (which would loop forever).
            if total_weight > 0 {
                let start_idx =
                    (load_balancer.bump(route.rule_idx) % total_weight as usize) as u32;
                let mut cumulative = 0u32;

                for target in targets.iter() {
                    cumulative += target.weight as u32;
                    let base_url = target.url.as_str().to_owned();
                    if cumulative > start_idx && circuit_breaker.is_available(&base_url) {
                        let resolved =
                            resolve_target_url(target, path, query, &route.resolution);
                        return Some((resolved, base_url));
                    }
                }
            }

            // Fallback: try any available target
            for target in targets {
                let base_url = target.url.as_str().to_owned();
                if circuit_breaker.is_available(&base_url) {
                    let resolved = resolve_target_url(target, path, query, &route.resolution);
                    return Some((resolved, base_url));
                }
            }
            None
        }
    }
}

/// Backward-compatible wrapper: returns (target_url, from_domain_rule, matched_prefix, route_scripts)
fn find_target(
    req: &Request<Incoming>,
    rules: &[crate::config::ProxyRule],
) -> Option<(String, bool, Option<String>, Vec<String>)> {
    let route = find_matching_rule(req, rules)?;
    let path = req.uri().path();
    let query = req.uri().query();
    let target = route.targets.first()?;
    let resolved = resolve_target_url(target, path, query, &route.resolution);
    let matched_prefix = route.matched_prefix(false);
    Some((
        resolved,
        route.from_domain_rule,
        matched_prefix,
        route.route_scripts,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `chunks` through a fresh `HtmlRewriter` (mimicking how frames
    /// arrive), then flush, and return the concatenated rewritten output.
    fn rewrite_chunks(prefix: &str, chunks: &[&str]) -> String {
        let mut rw = HtmlRewriter::new(prefix);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(rw.process(c.as_bytes(), false));
        }
        out.extend(rw.process(&[], true));
        String::from_utf8(out).unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_decode_and_rewrite_streaming() {
        let html = r#"<a href="/x"><img src="/y"><form action="/z"></form>"#;
        let compressed = gzip(html.as_bytes());
        let inner = http_body_util::Empty::<Bytes>::new().boxed();
        let mut d = DecodingRewritingBody::new_gzip(inner, "/solidb");
        // Feed the gzip stream in two halves to exercise incremental decode.
        let mid = compressed.len() / 2;
        let mut raw = Vec::new();
        d.inflate(&compressed[..mid], &mut raw);
        d.inflate(&compressed[mid..], &mut raw);
        let mut out = d.rewriter.process(&raw, false);
        out.extend(d.rewriter.process(&[], true));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a href="/solidb/x"><img src="/solidb/y"><form action="/solidb/z"></form>"#
        );
        assert!(d.decoder_ended);
    }

    #[test]
    fn rewrites_root_relative_attrs() {
        let html = r#"<a href="/x"><img src="/y"><form action="/z">"#;
        assert_eq!(
            rewrite_chunks("/solidb", &[html]),
            r#"<a href="/solidb/x"><img src="/solidb/y"><form action="/solidb/z">"#
        );
    }

    #[test]
    fn rewrites_across_chunk_boundary() {
        // The `href="/` token is split between two upstream frames.
        let out = rewrite_chunks("/solidb", &["<a hr", "ef=\"/x\">"]);
        assert_eq!(out, r#"<a href="/solidb/x">"#);
    }

    #[test]
    fn leaves_inline_script_body_untouched_but_rewrites_start_tag() {
        let html = r#"<script src="/app.js">var u = "/api"; el.innerHTML = '<a href="/no">';</script><a href="/yes">"#;
        // The external script's start-tag `src` is rewritten; literals inside the
        // inline JS body are left alone; markup after `</script>` resumes rewriting.
        assert_eq!(
            rewrite_chunks("/solidb", &[html]),
            r#"<script src="/solidb/app.js">var u = "/api"; el.innerHTML = '<a href="/no">';</script><a href="/solidb/yes">"#
        );
    }

    #[test]
    fn does_not_rewrite_absolute_or_relative_urls() {
        let html = r##"<a href="https://x/y"><a href="rel"><a href="#frag">"##;
        assert_eq!(rewrite_chunks("/p", &[html]), html);
    }

    #[test]
    fn rewrites_single_byte_chunks() {
        // Pathological: every byte arrives in its own frame.
        let html = r#"<link href="/a.css">"#;
        let chunks: Vec<String> = html.chars().map(|c| c.to_string()).collect();
        let refs: Vec<&str> = chunks.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            rewrite_chunks("/solidb", &refs),
            r#"<link href="/solidb/a.css">"#
        );
    }

    #[test]
    fn redirect_response_carries_path_and_query() {
        let resp = build_redirect_response("redirect://bonfire-app.pro/feed?page=2");
        assert_eq!(resp.status(), 301);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "https://bonfire-app.pro/feed?page=2"
        );
    }

    #[test]
    fn redirect_target_resolves_with_request_path() {
        let target = crate::config::Target {
            url: url::Url::parse("redirect://bonfire-app.pro").unwrap(),
            weight: 100,
        };
        let resolved = resolve_target_url(
            &target,
            "/some/path",
            Some("q=1"),
            &UrlResolution::AppendPath,
        );
        assert_eq!(resolved, "redirect://bonfire-app.pro/some/path?q=1");
    }

    #[test]
    fn redirect_response_rejects_bad_header_bytes() {
        let resp = build_redirect_response("redirect://bonfire-app.pro/\u{7f}");
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn validate_proxy_target_allows_http_https_redirect() {
        assert!(validate_proxy_target_url("http://127.0.0.1:3000/path"));
        assert!(validate_proxy_target_url("https://example.com/"));
        assert!(validate_proxy_target_url("redirect://new.example.com/path"));
    }

    #[test]
    fn validate_proxy_target_rejects_dangerous_schemes() {
        assert!(!validate_proxy_target_url("file:///etc/passwd"));
        assert!(!validate_proxy_target_url("gopher://evil"));
        assert!(!validate_proxy_target_url("ftp://evil"));
        assert!(!validate_proxy_target_url("redirect://"));
        assert!(!validate_proxy_target_url("http://evil\r\nHost: x"));
        assert!(!validate_proxy_target_url("not a url"));
    }

    #[test]
    fn host_eq_is_case_insensitive() {
        assert!(host_eq("Example.COM", "example.com"));
        assert!(!host_eq("example.com", "other.com"));
    }

    #[test]
    fn contains_crlf_detects_control_chars() {
        assert!(contains_crlf("a\rb"));
        assert!(contains_crlf("a\nb"));
        assert!(!contains_crlf("safe-path"));
    }

    #[test]
    fn test_load_balancer_state_select_index() {
        let lb = LoadBalancerState::new(1);

        // First call should return 0
        assert_eq!(lb.select_index(0, 3), 0);
        // Second call should return 1
        assert_eq!(lb.select_index(0, 3), 1);
        // Third call should return 2
        assert_eq!(lb.select_index(0, 3), 2);
        // Fourth call wraps around to 0
        assert_eq!(lb.select_index(0, 3), 0);
    }

    #[test]
    fn test_load_balancer_state_zero_targets() {
        let lb = LoadBalancerState::new(1);
        assert_eq!(lb.select_index(0, 0), 0);
    }

    #[test]
    fn weighted_zero_weights_falls_back_without_recursing() {
        // All-zero weights must not infinitely recurse into select_target; the
        // strategy should fall back to the first available target.
        let targets = vec![
            crate::config::Target {
                url: url::Url::parse("http://127.0.0.1:3001").unwrap(),
                weight: 0,
            },
            crate::config::Target {
                url: url::Url::parse("http://127.0.0.1:3002").unwrap(),
                weight: 0,
            },
        ];
        let strategy = crate::config::LoadBalancingStrategy::Weighted;
        let route = MatchedRoute {
            targets: &targets,
            from_domain_rule: false,
            resolution: UrlResolution::AppendPath,
            route_scripts: vec![],
            auth: vec![],
            load_balancing: &strategy,
            host: "example.com".to_string(),
            rule_idx: 0,
        };
        let cb = crate::circuit_breaker::CircuitBreaker::new(
            crate::circuit_breaker::CircuitBreakerConfig::default(),
        );
        let lb = LoadBalancerState::new(1);
        // A fresh breaker leaves every target available, so the fallback loop
        // returns the first one (rather than looping forever).
        let selected = select_target(&route, "/p", None, &cb, &lb);
        assert_eq!(selected.unwrap().1, "http://127.0.0.1:3001/");
    }

    fn xff_count(s: &str) -> usize {
        s.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:"))
            .count()
    }

    fn header_value<'a>(s: &'a str, name: &str) -> Option<&'a str> {
        let want = format!("{}:", name.to_ascii_lowercase());
        s.lines()
            .find(|l| l.to_ascii_lowercase().starts_with(&want))
            .and_then(|l| l.split_once(':').map(|(_, v)| v.trim()))
    }

    #[test]
    fn ws_extra_headers_replaces_client_xff() {
        let mut h = hyper::HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        h.insert("x-forwarded-host", "evil.example".parse().unwrap());
        let peer: SocketAddr = "9.9.9.9:54321".parse().unwrap();
        let out = build_ws_extra_headers(&h, Some(peer), false, "real.example");
        assert_eq!(xff_count(&out), 1, "exactly one X-Forwarded-For line");
        assert_eq!(header_value(&out, "X-Forwarded-For"), Some("9.9.9.9"));
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("http"));
        assert_eq!(header_value(&out, "X-Forwarded-Host"), Some("real.example"));
    }

    #[test]
    fn ws_extra_headers_injects_when_client_sent_none() {
        let h = hyper::HeaderMap::new();
        let peer: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let out = build_ws_extra_headers(&h, Some(peer), true, "api.example");
        assert_eq!(header_value(&out, "X-Forwarded-For"), Some("10.0.0.1"));
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("https"));
        assert_eq!(header_value(&out, "X-Forwarded-Host"), Some("api.example"));
    }

    #[test]
    fn ws_extra_headers_strips_hop_by_hop() {
        let mut h = hyper::HeaderMap::new();
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("te", "trailers".parse().unwrap());
        h.insert("trailer", "Expires".parse().unwrap());
        h.insert("proxy-authorization", "Basic ...".parse().unwrap());
        h.insert("cookie", "sid=abc".parse().unwrap());
        let out = build_ws_extra_headers(&h, None, false, "example");
        assert!(header_value(&out, "Transfer-Encoding").is_none());
        assert!(header_value(&out, "Keep-Alive").is_none());
        assert!(header_value(&out, "TE").is_none());
        assert!(header_value(&out, "Trailer").is_none());
        assert!(header_value(&out, "Proxy-Authorization").is_none());
        assert_eq!(header_value(&out, "Cookie"), Some("sid=abc"));
    }

    #[test]
    fn ws_extra_headers_strips_connection_listed() {
        let mut h = hyper::HeaderMap::new();
        h.insert("connection", "X-Custom, X-Other".parse().unwrap());
        h.insert("x-custom", "secret".parse().unwrap());
        h.insert("x-other", "1".parse().unwrap());
        h.insert("x-keep", "yes".parse().unwrap());
        let out = build_ws_extra_headers(&h, None, false, "example");
        assert!(
            header_value(&out, "X-Custom").is_none(),
            "Connection-listed header must be stripped"
        );
        assert!(header_value(&out, "X-Other").is_none());
        assert_eq!(header_value(&out, "X-Keep"), Some("yes"));
    }

    #[test]
    fn ws_extra_headers_skips_framing_headers() {
        let mut h = hyper::HeaderMap::new();
        h.insert("host", "example".parse().unwrap());
        h.insert("upgrade", "websocket".parse().unwrap());
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("sec-websocket-key", "abc".parse().unwrap());
        h.insert("sec-websocket-version", "13".parse().unwrap());
        h.insert("sec-websocket-protocol", "chat".parse().unwrap());
        let out = build_ws_extra_headers(&h, None, false, "example");
        assert!(header_value(&out, "Host").is_none());
        assert!(header_value(&out, "Upgrade").is_none());
        assert!(header_value(&out, "Connection").is_none());
        assert!(header_value(&out, "Sec-WebSocket-Key").is_none());
        assert!(header_value(&out, "Sec-WebSocket-Version").is_none());
        assert!(header_value(&out, "Sec-WebSocket-Protocol").is_none());
    }

    fn tls_cfg(max_age: Option<u64>, include_subdomains: Option<bool>) -> crate::config::TlsConfig {
        crate::config::TlsConfig {
            mode: "auto".into(),
            cache_dir: "./certs".into(),
            force_https: true,
            hsts_max_age_seconds: max_age,
            hsts_include_subdomains: include_subdomains,
        }
    }

    #[test]
    fn hsts_default_is_two_years_with_include_subdomains() {
        let v = hsts_header_value(&tls_cfg(None, None)).unwrap();
        assert_eq!(v.to_str().unwrap(), "max-age=63072000; includeSubDomains");
    }

    #[test]
    fn hsts_respects_configured_max_age() {
        let v = hsts_header_value(&tls_cfg(Some(86400), None)).unwrap();
        assert_eq!(v.to_str().unwrap(), "max-age=86400; includeSubDomains");
    }

    #[test]
    fn hsts_drops_include_subdomains_when_opted_out() {
        let v = hsts_header_value(&tls_cfg(None, Some(false))).unwrap();
        assert_eq!(v.to_str().unwrap(), "max-age=63072000");
    }

    #[test]
    fn hsts_disabled_when_max_age_zero() {
        assert!(hsts_header_value(&tls_cfg(Some(0), None)).is_none());
        // Even with includeSubDomains=true, max-age=0 disables the header.
        assert!(hsts_header_value(&tls_cfg(Some(0), Some(true))).is_none());
    }

    #[test]
    fn ws_extra_headers_omits_xff_when_peer_unknown() {
        let h = hyper::HeaderMap::new();
        let out = build_ws_extra_headers(&h, None, false, "example");
        assert_eq!(xff_count(&out), 0);
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("http"));
        assert_eq!(header_value(&out, "X-Forwarded-Host"), Some("example"));
    }
}
