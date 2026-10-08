// When scripting feature is disabled, OptionalLuaEngine = () and cloning it triggers warnings
#![allow(clippy::let_unit_value, clippy::clone_on_copy, clippy::unit_arg)]

use crate::acme::ChallengeStore;
use crate::app::AppManager;
use crate::auth;
use crate::circuit_breaker::SharedCircuitBreaker;
use crate::config::ConfigManager;
use crate::metrics::SharedMetrics;
use crate::pool::{
    is_body_limit_error, is_client_body_error, BoxError, ConnectionPool, ProxyClient,
};
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
use std::borrow::Cow;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
use crate::scripting::{Hook, LuaEngine, LuaRequest, RequestHookResult, RouteHookResult};

/// The address a per-client budget is charged to: the rate limiter's key and
/// the per-IP connection cap's.
///
/// IPv4 addresses count individually. An IPv6 client counts per /64: a single
/// subscriber is routinely handed a whole /64 and can pick a fresh source
/// address for every request, so keying the full 128 bits gave each client
/// 2^64 independent budgets. An IPv4-mapped IPv6 address (what a dual-stack
/// `[::]` listener reports for an IPv4 peer) is unwrapped to its IPv4 form so
/// the same client is not counted under two keys.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(
                u128::from(v6) & 0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
            )),
        },
    }
}

/// Default for `[limits] max_connections_per_ip` when unset.
const DEFAULT_MAX_CONNECTIONS_PER_IP: u64 = 256;

/// Caps how many connections one client address (see `client_key`) may hold
/// open at once, across every HTTP and HTTPS accept loop.
///
/// `max_connections` alone bounds the process, not the client: a single
/// address could take every permit and lock everyone else out. Sharded so the
/// accept loops on different cores rarely meet on the same lock.
pub(crate) struct PerIpLimiter {
    max: u32,
    shards: Vec<parking_lot::Mutex<std::collections::HashMap<IpAddr, u32>>>,
}

const PER_IP_SHARDS: usize = 32;

impl PerIpLimiter {
    pub(crate) fn new(max: u32) -> Self {
        Self {
            max,
            shards: (0..PER_IP_SHARDS)
                .map(|_| parking_lot::Mutex::new(std::collections::HashMap::new()))
                .collect(),
        }
    }

    fn shard(&self, key: &IpAddr) -> &parking_lot::Mutex<std::collections::HashMap<IpAddr, u32>> {
        let h = match key {
            IpAddr::V4(a) => u32::from(*a) as u64,
            IpAddr::V6(a) => (u128::from(*a) >> 64) as u64,
        };
        // Fibonacci hashing: the top bits of the product are well mixed even
        // for sequential addresses.
        let idx = (h.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 59) as usize;
        &self.shards[idx % PER_IP_SHARDS]
    }

    /// Count one more connection for `ip`, or refuse it when the address is
    /// already at the cap. The returned guard gives the slot back on drop.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PerIpGuard> {
        let key = client_key(ip);
        let mut map = self.shard(&key).lock();
        let count = map.entry(key).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(PerIpGuard {
            limiter: self.clone(),
            key,
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

/// One connection's slot in a `PerIpLimiter`.
pub(crate) struct PerIpGuard {
    limiter: Arc<PerIpLimiter>,
    key: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut map = self.limiter.shard(&self.key).lock();
        if let Some(count) = map.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                // Forget the address entirely, or the map grows by one entry
                // for every client that has ever connected.
                map.remove(&self.key);
            }
        }
    }
}

fn build_per_ip_limiter(config: &ConfigManager) -> Option<Arc<PerIpLimiter>> {
    let max = config
        .get_config()
        .limits
        .max_connections_per_ip
        .unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_IP);
    (max > 0).then(|| Arc::new(PerIpLimiter::new(max.min(u32::MAX as u64) as u32)))
}

/// What one accepted connection holds against the proxy's connection limits:
/// its `max_connections` permit and its per-IP slot. Shared (`Arc`) because a
/// WebSocket tunnel outlives the HTTP connection it was upgraded from — hyper
/// finishes serving the connection as soon as it hands the socket over — and
/// the tunnel must keep holding both, or every upgraded socket would be an
/// uncounted connection. The service inserts a clone into each request's
/// extensions; the tunnel task takes one from there.
#[derive(Clone)]
struct ConnLease(Arc<ConnGuard>);

struct ConnGuard {
    _permit: Option<OwnedSemaphorePermit>,
    _per_ip: Option<PerIpGuard>,
    /// A PROXY header that names no client (v1 `UNKNOWN`, v2 `LOCAL`, an
    /// unspecified or Unix address): the trusted balancer speaking for
    /// itself, or for someone it would not name. The connection is served
    /// — the balancer's health checks arrive this way — but the forwarding
    /// headers, request ID and `X-Forwarded-Proto` on it are not believed:
    /// whoever is on the other end wrote them.
    headers_untrusted: bool,
}

impl ConnLease {
    fn new(permit: Option<OwnedSemaphorePermit>, per_ip: Option<PerIpGuard>) -> Self {
        Self(Arc::new(ConnGuard {
            _permit: permit,
            _per_ip: per_ip,
            headers_untrusted: false,
        }))
    }

    /// See [`ConnGuard::headers_untrusted`]. Called before the lease is
    /// shared; were it somehow shared already, the connection is refused
    /// (`None`) rather than left trusted.
    fn untrusted_headers(self) -> Option<Self> {
        let mut guard = Arc::try_unwrap(self.0).ok()?;
        guard.headers_untrusted = true;
        Some(Self(Arc::new(guard)))
    }

    fn headers_untrusted(&self) -> bool {
        self.0.headers_untrusted
    }

    /// Add the per-IP slot to a lease taken without one: on a PROXY-protocol
    /// listener the client is only known once the header is read. The lease
    /// has not been shared yet at that point, so the unwrap cannot fail; if it
    /// somehow did, the connection would simply go uncounted per IP.
    fn with_per_ip(self, per_ip: Option<PerIpGuard>) -> Self {
        let Some(per_ip) = per_ip else {
            return self;
        };
        match Arc::try_unwrap(self.0) {
            Ok(guard) => Self(Arc::new(ConnGuard {
                _per_ip: Some(per_ip),
                ..guard
            })),
            Err(shared) => Self(shared),
        }
    }
}

/// Response body type for everything the proxy answers.
///
/// The error type is a boxed error, not `Infallible`: a proxied body is the
/// backend's `Incoming`, and a backend can fail mid-body (connection reset,
/// truncated chunk, h2 `RST_STREAM`). With `Infallible` that error had to be
/// mapped through `unreachable!()`, which panicked the connection task. Now it
/// propagates, and hyper aborts the client stream the honest way — a reset
/// (h2) or a closed connection without the terminating chunk (HTTP/1), so the
/// client sees a truncated response rather than a complete-looking one.
pub(crate) type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// `resp` with `open` held until its body has been sent (or dropped): an app
/// streaming a long response — server-sent events, a big download — is busy
/// for scale to zero until the last byte, not just until the headers.
fn hold_open(resp: Response<BoxBody>, open: Option<crate::app::OpenRequest>) -> Response<BoxBody> {
    let Some(open) = open else {
        return resp;
    };
    let (parts, body) = resp.into_parts();
    Response::from_parts(
        parts,
        HeldBody {
            inner: body,
            _open: open,
        }
        .boxed(),
    )
}

struct HeldBody {
    inner: BoxBody,
    _open: crate::app::OpenRequest,
}

impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// A complete in-memory body.
pub(crate) fn full(b: impl Into<Bytes>) -> BoxBody {
    http_body_util::Full::new(b.into())
        .map_err(|never| match never {})
        .boxed()
}

/// An empty body.
pub(crate) fn empty() -> BoxBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

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
    type Error = BoxError;

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
    type Error = BoxError;

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
    type Error = BoxError;

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
) -> Option<Arc<str>> {
    app_manager.as_ref()?.app_for_target_url(target_url).await
}

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

/// Pause after a failed `accept()` before trying again.
///
/// Out of file descriptors (`EMFILE`/`ENFILE`) or socket buffers (`ENOBUFS`,
/// `ENOMEM`), `accept()` fails at once, every time, until something closes —
/// and retrying straight away spins the accept loop at 100% of a core, logging
/// an error per spin, while the connections that would free a descriptor
/// starve for CPU. Those get a short sleep. Anything else (a peer that reset
/// before we accepted it, `ECONNABORTED`) is per-connection and retried at
/// once.
async fn accept_error_backoff(e: &std::io::Error) {
    let resource_exhausted = matches!(
        e.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
    );
    if resource_exhausted {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The HSTS header for `config`, built once per loaded config rather than with
/// a `format!` on every HTTPS response. The cache holds the config it was
/// built from and is rebuilt when a reload swaps in a new one.
fn hsts_for(config: &Arc<crate::config::Config>) -> Option<HeaderValue> {
    type Cached = (Arc<crate::config::Config>, Option<HeaderValue>);
    static CACHE: arc_swap::ArcSwapOption<Cached> = arc_swap::ArcSwapOption::const_empty();
    if let Some(cached) = &*CACHE.load() {
        if Arc::ptr_eq(&cached.0, config) {
            return cached.1.clone();
        }
    }
    let value = hsts_header_value(&config.tls);
    CACHE.store(Some(Arc::new((config.clone(), value.clone()))));
    value
}

/// The request path as rules match it: percent-encoded *unreserved*
/// characters (`A-Z a-z 0-9 - . _ ~`) decoded, runs of `/` collapsed to one.
///
/// RFC 3986 §6.2.2 makes those spellings equivalent, and backends treat them
/// so — `/%61dmin/x` and `//admin/x` both reach `/admin/x`. Matched raw, they
/// missed an `/admin/* @auth` rule and fell through to a broader rule without
/// it: a password-protected path served with no password. Everything else is
/// left as sent: reserved characters stay encoded (`%2F` is not `/`), and case
/// is not folded. Only matching uses this form; the backend still receives
/// the path the client sent. Borrowed — no allocation — for the ordinary path
/// that needs no change.
fn canonical_match_path(path: &str) -> Cow<'_, str> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    fn unreserved_at(bytes: &[u8], i: usize) -> Option<u8> {
        if bytes.get(i) != Some(&b'%') {
            return None;
        }
        let c = hex(*bytes.get(i + 1)?)? << 4 | hex(*bytes.get(i + 2)?)?;
        (c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')).then_some(c)
    }

    let bytes = path.as_bytes();
    let needs_work = bytes.iter().enumerate().any(|(i, &b)| {
        (b == b'/' && bytes.get(i + 1) == Some(&b'/')) || unreserved_at(bytes, i).is_some()
    });
    if !needs_work {
        return Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(c) = unreserved_at(bytes, i) {
            out.push(c as char);
            i += 3;
            continue;
        }
        let b = bytes[i];
        if b == b'/' && out.ends_with('/') {
            i += 1;
            continue;
        }
        // Copy the (possibly multi-byte) character starting here intact.
        let ch_len = path[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&path[i..i + ch_len]);
        i += ch_len;
    }
    Cow::Owned(out)
}

/// The matching form (`canonical_match_path`) of a request's path.
fn request_match_path<B>(req: &Request<B>) -> Cow<'_, str> {
    canonical_match_path(req.uri().path())
}

/// Parse a `Host` value strictly as `host[:port]`: a DNS name or IPv4 literal
/// made of `[A-Za-z0-9.-]`, or a bracketed IPv6 literal, then an optional
/// all-digit port that fits in a `u16`. Returns the host and port as written.
///
/// Anything else — userinfo (`example.com:@evil.com`), a path, whitespace,
/// a second colon — is refused, so a value taken from here can be pasted into
/// a URL without changing which host the URL names.
fn parse_host_port(value: &str) -> Option<(&str, Option<&str>)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let literal = &rest[..end];
        literal.parse::<Ipv6Addr>().ok()?;
        let host = &value[..end + 2];
        match &rest[end + 1..] {
            "" => (host, None),
            tail => (host, Some(tail.strip_prefix(':')?)),
        }
    } else {
        match value.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (value, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    if !host.starts_with('[')
        && !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse::<u16>().ok()?;
    }
    Some((host, port))
}

/// Response for a Lua hook that denied the request. A script chooses the
/// status, and `Response::builder().status(n)` rejects anything outside
/// 100..=999 — which used to reach an `.unwrap()` and panic the connection
/// task. Only 200..=599 is honoured: a 1xx is not a final response, and the
/// rest is not HTTP. Anything else is logged and answered 500.
#[cfg(feature = "scripting")]
fn lua_deny_response(status: u16, body: String) -> Response<BoxBody> {
    let status = match hyper::StatusCode::from_u16(status) {
        Ok(s) if (200..=599).contains(&status) => s,
        _ => {
            tracing::error!(
                "Lua hook denied with invalid status {}; answering 500 instead",
                status
            );
            hyper::StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    let mut resp = Response::new(full(Bytes::from(body)));
    *resp.status_mut() = status;
    // The script chose this body: custom error pages leave it alone.
    crate::response::mark_owned(&mut resp, crate::response::BodyOwner::Script);
    resp
}

fn plain_response(status: u16, body: &'static str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(full(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

/// Refuse requests the proxy cannot route safely, before anything looks at
/// them. Returns the response to send, or `None` to carry on.
///
/// - `CONNECT` (405): this is a reverse proxy, not a tunnel.
/// - A request target that is not origin-form — authority-form
///   (`GET example.com:443`) or asterisk-form (`*`) — has no path to route
///   on, and the code below slices `path[1..]`. `OPTIONS *` is the one
///   legitimate use of `*` (a server-wide capability probe) and is answered
///   here directly; anything else is 400.
/// - More than one `Host` header (400, RFC 9112 §3.2): the proxy and a
///   backend could each pick a different one and disagree about which site
///   the request is for.
/// - On HTTP/2, a `Host` header that names a different authority than
///   `:authority` (400, RFC 9113 §8.3.1): same disagreement, one layer down.
fn reject_malformed_request<B>(req: &Request<B>) -> Option<Response<BoxBody>> {
    if req.method() == hyper::Method::CONNECT {
        let mut resp = plain_response(405, "Method Not Allowed");
        resp.headers_mut().insert(
            hyper::header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        return Some(resp);
    }
    let path = req.uri().path();
    if !path.starts_with('/') {
        if req.method() == hyper::Method::OPTIONS && path == "*" {
            let mut resp = Response::new(empty());
            resp.headers_mut().insert(
                hyper::header::ALLOW,
                HeaderValue::from_static("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"),
            );
            return Some(resp);
        }
        return Some(plain_response(400, "Bad Request"));
    }
    let mut hosts = req.headers().get_all(hyper::header::HOST).iter();
    let first_host = hosts.next();
    if hosts.next().is_some() {
        return Some(plain_response(400, "Bad Request"));
    }
    // Userinfo has no place in a request's host (RFC 9110 §4.2.4, §7.2):
    // `:authority: x@site.example` with no Host was looked up raw by
    // maintenance and as `site.example` by routing — two answers to "which
    // site is this". Refused, from the authority and from `Host` alike.
    if req
        .uri()
        .authority()
        .is_some_and(|a| a.as_str().contains('@'))
        || first_host.is_some_and(|h| h.as_bytes().contains(&b'@'))
    {
        return Some(plain_response(400, "Bad Request"));
    }
    if req.version() == http::Version::HTTP_2 {
        if let (Some(host), Some(authority)) = (first_host, req.uri().authority()) {
            let same = host
                .to_str()
                .map(|h| h.eq_ignore_ascii_case(authority.as_str()))
                .unwrap_or(false);
            if !same {
                return Some(plain_response(400, "Bad Request"));
            }
        }
    }
    None
}

/// The Host the client asked for, as sent: the `Host` header, or the request
/// target's authority when there is none (HTTP/2's `:authority`). Used for
/// `X-Forwarded-Host`, before any rewrite of `Host` for an https target.
fn original_host<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
}

/// Check Basic Auth credentials against a route's or an app's accounts.
///
/// Resolves to `None` when the request may proceed, or to the response to send
/// instead: 401 for a missing or wrong credential, 503 when the bcrypt pool
/// stayed saturated (see `auth::Verdict::Busy`).
///
/// ⚠️ **Une vérification par identifiant, pas par requête — et jamais sur un
/// worker tokio.** bcrypt coûte ~300 ms au facteur 12, par conception. Rejoué
/// sur chaque requête, il le fait payer à la page, puis à sa feuille de style,
/// puis à chacune de ses images ; exécuté sur un worker, une quarantaine de
/// mauvais mots de passe par seconde suffisait à geler tout le proxy. Seuls les
/// succès sont mémorisés, et bcrypt tourne sur le pool bloquant borné de
/// `auth::run_bcrypt`. Voir `auth::verify_basic`.
///
/// Not an `async fn`: the header is copied out first, so the future borrows
/// only the accounts and never the request, and stays `Send` whatever the body
/// type.
fn verify_basic_auth<'a>(
    req: &Request<Incoming>,
    auth_entries: &'a [crate::auth::BasicAuth],
) -> impl std::future::Future<Output = Option<Response<BoxBody>>> + Send + 'a {
    verify_basic_auth_headers(req.headers(), auth_entries)
}

/// [`verify_basic_auth`] on a request's headers, whatever its body type.
fn verify_basic_auth_headers<'a>(
    headers: &hyper::HeaderMap,
    auth_entries: &'a [crate::auth::BasicAuth],
) -> impl std::future::Future<Output = Option<Response<BoxBody>>> + Send + 'a {
    let authorization = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    async move {
        if auth_entries.is_empty() {
            return None;
        }
        match auth::verify_basic(auth_entries, authorization.as_deref()).await {
            auth::Verdict::Granted => None,
            auth::Verdict::Denied => Some(create_auth_required_response()),
            auth::Verdict::Busy => Some(create_auth_busy_response()),
        }
    }
}

/// An app's `[auth] forward`, after its Basic Auth (which the caller ran):
/// `None` lets the request through. Same contract as a rule's — see
/// `MatchedRoute::authorize` and `forward_auth::gate`.
async fn app_forward_auth(
    auth: &crate::app::AppAuth,
    req: &mut Request<Incoming>,
    client: &ProxyClient,
    config: &crate::config::Config,
) -> Option<Response<BoxBody>> {
    let forward_auth = auth.forward.as_ref()?;
    let exempt = auth.is_exempt(&request_match_path(req));
    let send_authorization = auth.users.is_empty();
    crate::forward_auth::gate(
        client,
        forward_auth,
        &config.forward_auth,
        req,
        exempt,
        send_authorization,
    )
    .await
}

/// Create 401 Unauthorized response with WWW-Authenticate header
fn create_auth_required_response() -> Response<BoxBody> {
    let body = full(Bytes::from("Authentication required"));
    Response::builder()
        .status(401)
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .body(body)
        .unwrap()
}

/// 503 for a credential that could not be checked: every bcrypt slot stayed
/// busy (a password-guessing flood, most likely). Not 401 — the client did
/// nothing wrong, and a browser shown 401 would prompt for a password it has.
fn create_auth_busy_response() -> Response<BoxBody> {
    let body = full(Bytes::from("Authentication temporarily unavailable"));
    Response::builder()
        .status(503)
        .header("Retry-After", "1")
        .body(body)
        .unwrap()
}

fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    // Socket activation: systemd holds the port across restarts.
    if let Some(listener) = crate::systemd::inherited_listener(addr) {
        listener.set_nonblocking(true)?;
        return Ok(TcpListener::from_std(listener)?);
    }
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // `[::]` serves IPv4 too, whatever net.ipv6.bindv6only says.
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into()).map_err(|e| bind_error(addr, e))?;
    socket.listen(8192)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

/// Checks that an address is bindable, without accepting anything on it.
///
/// Deliberately stops short of `listen()`. A socket that has listened is in the
/// kernel's accept queue for that port, so a connection arriving in the moment
/// before it is dropped gets an RST — a restart would then reject a handful of
/// real requests to find out something it can learn without them.
fn probe_bind(addr: SocketAddr) -> Result<()> {
    if crate::systemd::has_inherited(addr) {
        return Ok(()); // bound already, by systemd
    }
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // `[::]` serves IPv4 too, whatever net.ipv6.bindv6only says.
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into()).map_err(|e| bind_error(addr, e))?;
    Ok(())
}

/// Turns a bind failure into something that names its own fix.
///
/// `Permission denied (os error 13)` on port 80 is almost always one thing: the
/// binary lost `cap_net_bind_service`. Every tool that replaces a file —
/// `cp`, `install`, `mv` across filesystems, an unpacked release archive —
/// drops file capabilities silently, so the proxy comes back after a routine
/// upgrade unable to bind the only two ports it exists to serve. The errno
/// alone sends a person looking at firewalls and SELinux; naming `setcap` is
/// the difference between a minute and an afternoon.
fn bind_error(addr: SocketAddr, source: std::io::Error) -> anyhow::Error {
    if source.kind() == std::io::ErrorKind::PermissionDenied && addr.port() < 1024 {
        return anyhow::anyhow!(
            "cannot bind {addr}: permission denied. Ports below 1024 need a capability this \
             process does not have. Grant it to the binary — `sudo setcap \
             cap_net_bind_service=+ep $(command -v soli-proxy)` — and start the proxy again. \
             Note that capabilities live on the file, not the path: replacing the binary with \
             cp/install/mv removes them, so this recurs after every upgrade unless setcap is \
             part of it."
        );
    }
    anyhow::Error::new(source).context(format!("cannot bind {addr}"))
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
    /// Per-client-address cap on simultaneous connections, shared by every
    /// accept loop like `connection_limit`. `None` when
    /// `[limits].max_connections_per_ip = 0`.
    per_ip_limit: Option<Arc<PerIpLimiter>>,
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
    // One timer for the life of the tunnel, pushed forward on every read,
    // rather than a fresh `timeout` (a new timer-wheel entry) per frame.
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let until_deadline = deadline.saturating_duration_since(now);
        let next_timeout = std::cmp::min(idle_timeout, until_deadline);
        idle.as_mut()
            .reset(tokio::time::Instant::now() + next_timeout);

        let n = tokio::select! {
            biased;
            read = reader.read(&mut buf) => match read {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            },
            _ = &mut idle => return Ok(()),
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
/// client's `Connection:` value, drops every `Forwarded` / `X-Forwarded-*` /
/// `X-Real-IP` header, then re-injects proxy-derived
/// `X-Forwarded-{For,Proto,Host}` and `X-Real-IP` so a client cannot spoof
/// source IP / proto / host on the upgrade. `Host`, `Upgrade`, `Connection`, and the
/// `Sec-WebSocket-*` framing headers are also skipped because the caller
/// emits them explicitly. Output ends with each line CRLF-terminated; the
/// caller appends the final blank-line terminator.
///
/// For a client behind a trusted proxy, `X-Forwarded-For` and
/// `X-Forwarded-Proto` are the ones the door built (`headers` is the request
/// after `set_forwarding_headers_for`): that proxy's chain with its address
/// appended, and the scheme it saw.
fn build_ws_extra_headers(
    headers: &hyper::HeaderMap,
    client: Option<&crate::edge::ClientInfo>,
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
            | "sec-websocket-protocol" => continue,
            _ => {}
        }
        // Every forwarding header is re-derived below from what the proxy
        // saw, never relayed from the client (see `set_forwarding_headers`).
        if crate::proxy_headers::is_forwarding_header(name_str) {
            continue;
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

    let mut proto = if is_tls { "https" } else { "http" };
    if let Some(who) = client {
        let mut chain = String::new();
        if who.trusted_peer {
            for v in headers.get_all("x-forwarded-for") {
                match v.to_str() {
                    Ok(v) if !contains_crlf(v) && !v.trim().is_empty() => {
                        if !chain.is_empty() {
                            chain.push_str(", ");
                        }
                        chain.push_str(v.trim());
                    }
                    _ => {}
                }
            }
            if let Some(p) = crate::edge::forwarded_proto(headers) {
                proto = p;
            }
        }
        if chain.is_empty() {
            chain = who.ip.to_string();
        }
        out.push_str(&format!("X-Forwarded-For: {}\r\n", chain));
        out.push_str(&format!("X-Real-IP: {}\r\n", who.ip));
    }
    out.push_str(&format!("X-Forwarded-Proto: {}\r\n", proto));
    if !contains_crlf(host_header) {
        out.push_str(&format!("X-Forwarded-Host: {}\r\n", host_header));
    }
    out
}

/// Apply a rule's `headers { }` block to a WebSocket upgrade: `extra` is the
/// header lines [`build_ws_extra_headers`] produced, `host` the `Host` the
/// handshake will carry. Returns both, edited — a block may set `Host` like
/// on the HTTP path. The handshake's own lines (`Upgrade`, `Connection`,
/// `Sec-WebSocket-*`) are written by the caller and cannot be set here; every
/// value went through `HeaderValue`, so none can carry a line break.
fn apply_ws_header_rules(
    extra: &str,
    host: &str,
    rules: &[crate::config::HeaderRule],
    vars: &crate::config::HeaderVars<'_>,
) -> (String, String) {
    let mut map = hyper::HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(host) {
        map.insert(hyper::header::HOST, v);
    }
    for line in extra.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(name), Ok(value)) = (
                hyper::header::HeaderName::from_bytes(name.trim().as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                map.append(name, value);
            }
        }
    }
    crate::config::apply_header_rules(&mut map, rules, vars);
    let host = map
        .remove(hyper::header::HOST)
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_else(|| host.to_string());
    let mut out = String::new();
    for (name, value) in &map {
        let name = name.as_str();
        if name.starts_with("sec-websocket-") || matches!(name, "upgrade" | "connection") {
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.push_str(&format!("{}: {}\r\n", name, v));
        }
    }
    (out, host)
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
        let per_ip_limit = build_per_ip_limiter(&config);
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
            per_ip_limit,
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
        let per_ip_limit = build_per_ip_limiter(&config);
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
            per_ip_limit,
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

        // Bind is checked here, before a single accept loop is spawned.
        //
        // Every listener binds inside its own task, so a bind failure used to
        // reach nothing but `tracing::error!` from a detached task — and the
        // line below still announced the proxy as listening. All 32 loops could
        // die of EACCES and the process would sit in its idle loop looking
        // healthy, admin API answering, apps supervised, front door shut. That
        // is the worst shape a failure can take: everything that reports says
        // fine, and only real traffic disagrees.
        //
        // The probe binds without listening, so it never lands in an accept
        // queue and no connection is lost to it. It exists to make the errno
        // arrive on the startup path, where `?` can stop the process.
        probe_bind(http_addr)?;
        if let Some(addr) = https_addr {
            probe_bind(addr)?;
        }

        for addr in crate::systemd::unused_inherited()
            .into_iter()
            .filter(|a| !crate::systemd::has_inherited(http_addr) || a.port() != http_addr.port())
        {
            if https_addr.is_some_and(|h| h.port() == addr.port()) {
                continue;
            }
            tracing::warn!(
                "systemd passed a socket for {} that the configuration does not listen on \
                 ([server] bind / https_port): ListenStream= and config.toml disagree",
                addr
            );
        }

        // One shared connection pool for every accept loop (HTTP + HTTPS).
        // Clones are cheap and share idle keep-alive sockets across listeners.
        let shared_client = ConnectionPool::new().client();
        // Active health checks of static targets (`@health`,
        // `[health_checks]`), kept in step with every reload.
        crate::upstream::health::spawn(
            self.config.clone(),
            self.circuit_breaker.clone(),
            shared_client.clone(),
            self.shutdown.clone(),
        );
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
            let ip_clone = self.per_ip_limit.clone();
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
                    ip_clone,
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
                let ip_clone = self.per_ip_limit.clone();
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
                        ip_clone,
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

/// How long an accepted connection may wait for a `max_connections` slot
/// before it is closed.
const CONNECTION_SLOT_WAIT: Duration = Duration::from_secs(10);

/// Admit an accepted connection: a per-IP slot, then a `max_connections`
/// permit. `None` means the caller drops the socket, which closes it.
///
/// The permit is taken *after* `accept`, never before. Each accept loop (one
/// per core, per listener) used to wait for a permit and only then call
/// `accept`, so every idle loop sat on a permit it had no connection for: with
/// `max_connections` below the number of loops — or simply near the limit —
/// the permits could all be parked in, say, the HTTPS loops while HTTP
/// connections waited in the backlog for a slot nobody was using.
///
/// Now the loop accepts, then waits for a permit *inline*, which keeps the
/// backpressure the old order gave: while it waits it accepts nothing, the
/// listen backlog absorbs the overflow, and at most one connection per loop
/// is held without a slot. The semaphore is FIFO, so slots go to waiting
/// connections in arrival order whichever listener they came in on. A
/// connection that cannot get a slot within `CONNECTION_SLOT_WAIT` is closed
/// rather than kept in limbo. The per-IP cap is checked first: it is cheap,
/// and a client over it is refused without queueing behind anyone.
async fn admit(
    connection_limit: Option<&Arc<Semaphore>>,
    per_ip_limit: Option<&Arc<PerIpLimiter>>,
    peer: SocketAddr,
) -> Option<ConnLease> {
    let per_ip = match per_ip_limit {
        Some(limiter) => match limiter.try_acquire(peer.ip()) {
            Some(guard) => Some(guard),
            None => {
                tracing::debug!(
                    "refusing connection from {}: max_connections_per_ip reached",
                    peer.ip()
                );
                return None;
            }
        },
        None => None,
    };
    let permit = match connection_limit {
        Some(s) => match s.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(tokio::sync::TryAcquireError::Closed) => return None,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                match timeout(CONNECTION_SLOT_WAIT, s.clone().acquire_owned()).await {
                    Ok(Ok(p)) => Some(p),
                    _ => {
                        tracing::warn!(
                            "closing connection from {}: no max_connections slot within {:?}",
                            peer.ip(),
                            CONNECTION_SLOT_WAIT
                        );
                        return None;
                    }
                }
            }
        },
        None => None,
    };
    Some(ConnLease::new(permit, per_ip))
}

/// Per-connection edge decisions taken at accept time, before the TCP peer's
/// first byte is read: the listener's PROXY protocol mode, and whether the
/// peer is a trusted proxy. `None` means the connection must be closed — a
/// PROXY-protocol listener only takes connections from trusted proxies.
///
/// The per-IP connection cap is keyed on the TCP peer here, since no request
/// header has been read yet: a client behind a trusted proxy that does not
/// speak PROXY protocol is never capped individually. The trusted proxy
/// itself is exempt — it carries everyone's connections — and stays bounded
/// by `max_connections`. With PROXY protocol on, the cap is applied to the
/// address the header carries, in `read_proxy_protocol`.
fn edge_accept(
    config: &ConfigManager,
    listener: crate::edge::Listener,
    peer: SocketAddr,
) -> Option<(Option<crate::edge::ProxyProtocolMode>, bool)> {
    let cfg = config.get_config();
    let edge = &cfg.server.edge;
    let pp = edge.proxy_protocol_for(listener);
    let trusted = edge.trusts(peer.ip());
    if pp.is_some() && !trusted {
        tracing::debug!(
            "refusing connection from {}: PROXY protocol is only accepted from trusted_proxies",
            peer.ip()
        );
        return None;
    }
    Some((pp, trusted))
}

/// On a PROXY-protocol listener, read the header and make the address it
/// carries the connection's peer — for the per-IP cap (taken here), the rate
/// limiter, forwarding headers, logs. `None`: close the connection (no valid
/// header in time, or the carried client is over its per-IP cap).
async fn read_proxy_protocol(
    mut stream: TcpStream,
    peer: SocketAddr,
    lease: ConnLease,
    mode: Option<crate::edge::ProxyProtocolMode>,
    config: &ConfigManager,
    per_ip_limit: Option<&Arc<PerIpLimiter>>,
) -> Option<(TcpStream, SocketAddr, ConnLease)> {
    let Some(mode) = mode else {
        return Some((stream, peer, lease));
    };
    let source = match crate::edge::read_proxy_header(&mut stream, mode).await {
        Ok(Some(source)) => source,
        // LOCAL / UNKNOWN / no address: the balancer speaking for itself (a
        // health check). Served, as the balancer — capped per IP like a
        // client, and with its forwarding headers ignored: on such a
        // connection they are whatever the other end wrote, and believing
        // them let a client pick its own address, request ID and scheme.
        Ok(None) => {
            let per_ip = match per_ip_limit {
                Some(limiter) => Some(limiter.try_acquire(peer.ip())?),
                None => None,
            };
            return Some((stream, peer, lease.with_per_ip(per_ip).untrusted_headers()?));
        }
        Err(e) => {
            tracing::debug!("closing connection from {}: {}", peer.ip(), e);
            return None;
        }
    };
    let exempt = config.get_config().server.edge.trusts(source.ip());
    let per_ip = match per_ip_limit.filter(|_| !exempt) {
        Some(limiter) => match limiter.try_acquire(source.ip()) {
            Some(guard) => Some(guard),
            None => {
                tracing::debug!(
                    "refusing connection from {} (via {}): max_connections_per_ip reached",
                    source.ip(),
                    peer.ip()
                );
                return None;
            }
        },
        None => None,
    };
    Some((stream, source, lease.with_per_ip(per_ip)))
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
    per_ip_limit: Option<Arc<PerIpLimiter>>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
    client: ProxyClient,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::error!("HTTP/1.1 accept error: {}", e);
                    accept_error_backoff(&e).await;
                    continue;
                }
            },
        };
        let Some((pp, trusted)) = edge_accept(&config, crate::edge::Listener::Http, peer) else {
            continue;
        };
        let ip_cap = per_ip_limit.as_ref().filter(|_| !trusted && pp.is_none());
        let lease = tokio::select! {
            _ = shutdown_rx.recv() => break,
            lease = admit(connection_limit.as_ref(), ip_cap, peer) => lease,
        };
        let Some(lease) = lease else {
            continue; // refused: dropping the stream closes it
        };
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
        let ip_limit = per_ip_limit.clone();
        tokio::spawn(async move {
            let Some((stream, peer, lease)) =
                read_proxy_protocol(stream, peer, lease, pp, &config, ip_limit.as_ref()).await
            else {
                return;
            };
            // The lease (permit + per-IP slot) lives in the
            // connection's service; a WebSocket tunnel takes its
            // own clone, so it outlives this task when needed.
            if let Err(e) = handle_http11_connection(
                stream, peer, client, config, metrics, cs, lua, cb, am, lb, sd, rl, lease,
            )
            .await
            {
                // anyhow error: `{:#}` prints the full chain
                tracing::debug!("HTTP/1.1 connection error: {:#}", e);
            }
        });
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
    per_ip_limit: Option<Arc<PerIpLimiter>>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
    client: ProxyClient,
) -> Result<()> {
    let listener = create_listener(addr)?;
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown_rx.recv() => break,
            accept_result = listener.accept() => match accept_result {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::error!("HTTPS/2 accept error: {}", e);
                    accept_error_backoff(&e).await;
                    continue;
                }
            },
        };
        let Some((pp, trusted)) = edge_accept(&config, crate::edge::Listener::Https, peer) else {
            continue;
        };
        let ip_cap = per_ip_limit.as_ref().filter(|_| !trusted && pp.is_none());
        // The permit covers the TLS handshake too, so a flood of bogus
        // ClientHellos can't bypass the cap by stalling in handshake.
        let lease = tokio::select! {
            _ = shutdown_rx.recv() => break,
            lease = admit(connection_limit.as_ref(), ip_cap, peer) => lease,
        };
        let Some(lease) = lease else {
            continue; // refused: dropping the stream closes it
        };
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
        let ip_limit = per_ip_limit.clone();
        tokio::spawn(async move {
            // The PROXY header comes before the TLS ClientHello.
            let Some((stream, peer, lease)) =
                read_proxy_protocol(stream, peer, lease, pp, &config, ip_limit.as_ref()).await
            else {
                return;
            };
            // Held through the handshake; then handed to the
            // connection's service (see run_http_server).
            const TLS_HANDSHAKE_TIMEOUT: tokio::time::Duration =
                tokio::time::Duration::from_secs(10);
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    metrics.inc_tls_connections();
                    if let Err(e) = handle_https2_connection(
                        tls_stream, peer, client, config, metrics, cs, lua, cb, am, lb, sd, rl,
                        lease,
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

    Ok(())
}

/// Default for `[limits].keep_alive_timeout` when unset: how long an HTTP/1
/// connection may take to send a request head — which, since hyper re-arms
/// the timer after every response, also bounds an idle keep-alive connection
/// — and how long an HTTP/2 connection may sit with no request in flight.
const DEFAULT_KEEP_ALIVE_TIMEOUT_SECS: u64 = 30;

/// HTTP/2 PING cadence, and how long to wait for the answer before declaring
/// the peer dead. Without them a client that vanished without a FIN (a phone
/// switching networks) holds its connection — and its permit — until TCP
/// keep-alive gives up hours later.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// The idle bound for this config (see `DEFAULT_KEEP_ALIVE_TIMEOUT_SECS`).
fn keep_alive_timeout(limits: &crate::config::LimitsConfig) -> Duration {
    Duration::from_secs(
        limits
            .keep_alive_timeout
            .filter(|&s| s > 0)
            .unwrap_or(DEFAULT_KEEP_ALIVE_TIMEOUT_SECS),
    )
}

/// Request activity on one HTTP/2 connection, for its idle timeout. hyper's
/// HTTP/2 server has no idle or preface timeout of its own: a client that
/// completes the TLS handshake, negotiates h2 and then sends nothing — not
/// even the connection preface — kept its connection and its
/// `max_connections` permit forever.
struct H2Activity {
    epoch: std::time::Instant,
    /// Requests whose service future is running.
    in_flight: AtomicUsize,
    /// Milliseconds since `epoch` at the last request start or finish.
    last_ms: AtomicU64,
    /// Whether any request has arrived — i.e. the h2 handshake completed.
    seen_request: std::sync::atomic::AtomicBool,
}

impl H2Activity {
    fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
            in_flight: AtomicUsize::new(0),
            last_ms: AtomicU64::new(0),
            seen_request: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        self.last_ms
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn start(self: &Arc<Self>) -> H2InFlight {
        self.seen_request.store(true, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        self.touch();
        H2InFlight(self.clone())
    }

    /// How long the connection has had no request in flight (zero while one is).
    fn idle_for(&self) -> Duration {
        if self.in_flight.load(Ordering::Acquire) > 0 {
            return Duration::ZERO;
        }
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last)
    }
}

/// Marks one request in flight; a drop (completion or a reset stream
/// cancelling the future) ends it.
struct H2InFlight(Arc<H2Activity>);

impl Drop for H2InFlight {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve one HTTP/1.1 connection (plain or TLS) until it closes or the
/// process shuts down.
#[allow(clippy::too_many_arguments)]
async fn serve_http1<I>(
    io: TokioIo<I>,
    label: &'static str,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
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
    lease: ConnLease,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let header_timeout = keep_alive_timeout(&config.get_config().limits);
    let svc = service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(lease.clone());
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
            is_tls,
            peer_addr,
            rate_limiter.clone(),
        )
    });

    // `header_read_timeout` is always set: hyper re-arms it each time it
    // starts reading the next request head, so it bounds both a slow head
    // and an idle keep-alive connection. hyper 1.9 panics with "timeout
    // `header_read_timeout` set, but no timer set" without `.timer(...)`.
    // No `pipeline_flush`: it makes hyper's write buffer report room at all
    // times (`can_buffer()` is `flush_pipeline || …`), so a response body was
    // read from the backend as fast as the backend sent it, whatever the
    // client's speed. A 120 MB download to a slow client sat in the proxy's
    // memory in under a second, and the backend's request was over long
    // before the client's. Without it hyper stops reading the body once
    // ~400 KB wait to be written.
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(true)
        .header_read_timeout(header_timeout)
        .serve_connection(io, svc)
        .with_upgrades();
    let mut conn = std::pin::pin!(conn);
    // Counts this connection as in flight for the shutdown drain.
    let mut shutdown_rx = shutdown.track_connection();

    tokio::select! {
        res = conn.as_mut() => {
            if let Err(e) = res {
                tracing::debug!("{} connection error: {}", label, error_chain(&e));
            }
        }
        _ = shutdown_rx.recv() => {
            // Send Connection: close after the in-flight request completes
            // so the Mac's browser knows to drop its keep-alive socket instead
            // of detecting a dead peer on the next request (saves ~30s).
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await {
                tracing::debug!("{} graceful shutdown error: {}", label, e);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_http11_connection(
    stream: tokio::net::TcpStream,
    // The TCP peer, or the client a PROXY protocol header named.
    peer: SocketAddr,
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
    lease: ConnLease,
) -> Result<()> {
    let peer_addr = Some(peer);
    serve_http1(
        TokioIo::new(stream),
        "HTTP/1.1",
        false,
        peer_addr,
        client,
        config,
        metrics,
        challenge_store,
        lua_engine,
        circuit_breaker,
        app_manager,
        load_balancer,
        shutdown,
        rate_limiter,
        lease,
    )
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_https2_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    // The TCP peer, or the client a PROXY protocol header named.
    peer: SocketAddr,
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
    lease: ConnLease,
) -> Result<()> {
    let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");

    let peer_addr = Some(peer);
    let io = TokioIo::new(stream);

    if !is_h2 {
        serve_http1(
            io,
            "HTTPS/1.1",
            true,
            peer_addr,
            client,
            config,
            metrics,
            challenge_store,
            lua_engine,
            circuit_breaker,
            app_manager,
            load_balancer,
            shutdown,
            rate_limiter,
            lease,
        )
        .await;
        return Ok(());
    }

    let mut shutdown_rx = shutdown.track_connection();
    let idle_timeout = keep_alive_timeout(&config.get_config().limits);
    let activity = Arc::new(H2Activity::new());
    let svc_activity = activity.clone();
    let exec = TokioExecutor::new();
    let svc = service_fn(move |mut req: Request<Incoming>| {
        let in_flight = svc_activity.start();
        req.extensions_mut().insert(lease.clone());
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
            let _in_flight = in_flight;
            fut.await
        }
    });
    let conn = hyper::server::conn::http2::Builder::new(exec)
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
        .initial_stream_window_size(1024 * 1024)
        .initial_connection_window_size(2 * 1024 * 1024)
        .max_concurrent_streams(250)
        .serve_connection(io, svc);
    let mut conn = std::pin::pin!(conn);

    // Check for idleness a few times per timeout period.
    let check_every = (idle_timeout / 4).max(Duration::from_millis(250));
    loop {
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::debug!("HTTPS/2 connection error: {}", e);
                }
                break;
            }
            _ = shutdown_rx.recv() => {
                // Emit HTTP/2 GOAWAY so the browser closes its multiplexed
                // connection promptly. Without this, Chrome waits ~30s on
                // its HTTP/2 PING timeout before retrying on a fresh conn.
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/2 graceful shutdown error: {}", e);
                }
                break;
            }
            _ = tokio::time::sleep(check_every) => {
                if activity.idle_for() < idle_timeout {
                    continue;
                }
                if !activity.seen_request.load(Ordering::Relaxed) {
                    // Never sent a request — possibly not even the preface,
                    // in which case hyper's graceful shutdown would wait for
                    // a handshake that is not coming. Just drop it.
                    tracing::debug!("HTTPS/2 connection sent no request in {:?}; closing", idle_timeout);
                    break;
                }
                // Idle: GOAWAY, and let any response still streaming finish.
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!("HTTPS/2 idle shutdown error: {}", e);
                }
                break;
            }
        }
    }

    Ok(())
}

/// Separator the Lua view uses to join repeated fields of one header: `; `
/// for `Cookie` (how HTTP/2 split cookies are rejoined, RFC 9113 §8.2.3),
/// `, ` for everything else (RFC 9110 §5.3).
#[cfg(feature = "scripting")]
fn lua_header_separator(name: &hyper::header::HeaderName) -> &'static str {
    if name == hyper::header::COOKIE {
        "; "
    } else {
        ", "
    }
}

/// The Lua view of one header: every field of it, joined (see
/// `lua_header_separator`). A non-UTF-8 field reads as "".
///
/// Repeated fields used to collapse to the *last* one, which hid duplicates
/// from scripts: a client sending `X-User: evil` then `X-User: alice` showed
/// the script `alice`, and the backend — which reads the first — got `evil`.
#[cfg(feature = "scripting")]
fn lua_header_view(headers: &hyper::HeaderMap, name: &hyper::header::HeaderName) -> String {
    let sep = lua_header_separator(name);
    let mut out = String::new();
    for (i, v) in headers.get_all(name).iter().enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(v.to_str().unwrap_or(""));
    }
    out
}

/// Whether `value` is exactly what `lua_header_view` shows for `name` (and the
/// header is present), compared without building the joined string.
#[cfg(feature = "scripting")]
fn lua_header_view_equals(
    headers: &hyper::HeaderMap,
    name: &hyper::header::HeaderName,
    value: &str,
) -> bool {
    let sep = lua_header_separator(name);
    let mut rest = value;
    let mut seen = false;
    for v in headers.get_all(name) {
        if seen {
            match rest.strip_prefix(sep) {
                Some(r) => rest = r,
                None => return false,
            }
        }
        seen = true;
        match rest.strip_prefix(v.to_str().unwrap_or("")) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    seen && rest.is_empty()
}

/// Extract headers from a hyper request into a HashMap for Lua consumption,
/// one entry per header name (see `lua_header_view`).
#[cfg(feature = "scripting")]
fn extract_headers<B>(req: &Request<B>) -> std::collections::HashMap<String, String> {
    let headers = req.headers();
    let mut map = std::collections::HashMap::with_capacity(headers.keys_len());
    for name in headers.keys() {
        // `HeaderName::as_str` is already lower-case.
        map.insert(name.as_str().to_string(), lua_header_view(headers, name));
    }
    map
}

/// Build a LuaRequest from a hyper Request.
#[cfg(feature = "scripting")]
fn build_lua_request<B>(req: &Request<B>) -> LuaRequest {
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
        client_ip: crate::edge::client_ip(req.extensions()).map(|ip| ip.to_string()),
        request_id: crate::edge::request_id(req.extensions())
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
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

/// Entry point for every served request: the door (see `crate::edge`).
///
/// Before anything else looks at the request it decides who the client is
/// (`ClientInfo`, in the extensions: the peer, or — from a trusted proxy —
/// the address its forwarding headers name) and gives the request its ID.
/// After, it returns the ID on the response and, with `[logging] access_log`
/// on, hands the response to the access log, which writes its line when the
/// body has been sent.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    mut req: Request<Incoming>,
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
    // The config is loaded once per request and handed down, rather than
    // re-loaded (an `ArcSwap` load plus an `Arc` clone) at each layer.
    let config = config_manager.get_config();
    let edge = &config.server.edge;
    let mut trusted_peer = false;
    if let Some(peer) = peer_addr {
        // A PROXY header that named no client: the peer is the balancer, but
        // what it relays is not its word (see `ConnGuard::headers_untrusted`).
        let who = if req
            .extensions()
            .get::<ConnLease>()
            .is_some_and(ConnLease::headers_untrusted)
        {
            crate::edge::ClientInfo::direct(peer.ip())
        } else {
            crate::edge::ClientInfo::resolve(peer.ip(), req.headers(), edge)
        };
        crate::edge::strip_untrusted_real_ip(req.headers_mut(), &who, edge);
        trusted_peer = who.trusted_peer;
        req.extensions_mut().insert(who);
    }
    let request_id = edge.request_id_header.0.as_ref().map(|name| {
        let id = crate::edge::stamp_request_id(req.headers_mut(), name, trusted_peer);
        req.extensions_mut()
            .insert(crate::edge::RequestId(id.clone()));
        (name.clone(), id)
    });
    let access = crate::access_log::begin(&req, is_tls);

    // Maintenance mode answers before anything else looks at the request —
    // but after the door, so its allowlist sees the real client and its 503
    // carries the request ID and reaches the access log. It lets ACME
    // challenges, the health endpoints and allowlisted traffic through.
    // A malformed request (userinfo in its authority, two Hosts…) is not
    // looked at here: `handle_request_inner` refuses it with a 400 first
    // thing, and its host is not one maintenance should judge.
    //
    // `[bots]` goes first: a banned scanner or a refused crawler is not shown
    // the maintenance page either.
    let malformed = reject_malformed_request(&req).is_some();
    let bots = &config_manager.bots;
    let verdict = match malformed {
        true => crate::response::bots::Verdict::Pass { count_404: None },
        false => {
            crate::response::bots::check(&req, &config, bots, app_manager.as_deref(), peer_addr)
        }
    };
    let (refusal, count_404) = match verdict {
        crate::response::bots::Verdict::Refuse(resp) => (Some(resp), None),
        crate::response::bots::Verdict::Pass { count_404 } => (None, count_404),
    };
    let early = match (malformed, refusal) {
        (_, Some(resp)) => Some((resp, "bots")),
        (true, None) => None,
        (false, None) => crate::response::maintenance::check(
            &req,
            &config,
            &config_manager.maintenance,
            app_manager.as_deref(),
            peer_addr,
        )
        .map(|resp| (resp, "maintenance")),
    };
    let mut result = if let Some((resp, answered_by)) = early {
        metrics.record_request(0, 0, resp.status().as_u16(), Duration::ZERO);
        // Not served by `serve_request`, so logged here: a 403 a client
        // complains about must be findable in the request log.
        if config.logging.log_endpoints.unwrap_or(false) {
            log_early_response(&req, is_tls, resp.status().as_u16(), answered_by);
        }
        with_hsts(Ok(resp), is_tls, &config)
    } else {
        // What a custom error page would need, kept only if one could be served.
        let error_page = crate::response::error_pages::capture(&req, &config, app_manager.as_ref());
        let result = serve_request(
            req,
            client,
            config.clone(),
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
        let result = crate::response::error_pages::apply(result, error_page, &config);
        if let Ok(resp) = &result {
            crate::response::bots::after(bots, &config, count_404, resp.status().as_u16());
        }
        result
    };

    if let (Ok(resp), Some((name, id))) = (&mut result, request_id) {
        resp.headers_mut().insert(name, id);
    }
    match (result, access) {
        (Ok(resp), Some(line)) => Ok(crate::access_log::finish(resp, line)),
        (Err(e), Some(line)) => {
            crate::access_log::failed(line);
            Err(e)
        }
        (result, None) => result,
    }
}

/// The request-log line (`log_endpoints`) for a response the proxy gave
/// before routing — a `[bots]` refusal, a maintenance page — with what gave
/// it as `answered_by`.
fn log_early_response<B>(req: &Request<B>, is_tls: bool, status: u16, answered_by: &str) {
    let host = req
        .uri()
        .host()
        .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let client_ip = crate::edge::client_ip(req.extensions())
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let user_agent: String = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .chars()
                .take(256)
                .collect()
        })
        .unwrap_or_default();
    tracing::info!(
        layer = "endpoint",
        method = %req.method(),
        scheme = if is_tls { "https" } else { "http" },
        host = %host,
        path = %req.uri().path(),
        status = status,
        elapsed_ms = 0u64,
        client_ip = %client_ip,
        user_agent = %user_agent,
        answered_by = answered_by,
        "endpoint request"
    );
}

/// Serve one request once the door has seen it. When `[logging].log_endpoints`
/// is true it wraps the handler to emit one structured log line per request —
/// covering all return paths (proxied responses, rate-limit/size rejections,
/// timeouts, health/metrics, Lua denials, websockets). Otherwise it delegates
/// straight to `handle_request_inner` with no added work. The flag is read
/// from the current config on each request, so hot reloads take effect.
#[allow(clippy::too_many_arguments)]
async fn serve_request(
    req: Request<Incoming>,
    client: ProxyClient,
    config: Arc<crate::config::Config>,
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
    let log_endpoints = config.logging.log_endpoints.unwrap_or(false);
    if !log_endpoints {
        let result = handle_request_inner(
            req,
            client,
            config.clone(),
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
        return with_hsts(result, is_tls, &config);
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
    let client_ip = crate::edge::client_ip(req.extensions())
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    // Who is asking, for telling crawlers and scanners apart in the logs.
    // Clipped: a 16 KiB User-Agent would otherwise make a 16 KiB line.
    let user_agent: String = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .chars()
                .take(256)
                .collect()
        })
        .unwrap_or_default();
    let start = std::time::Instant::now();

    let result = handle_request_inner(
        req,
        client,
        config.clone(),
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
            user_agent = %user_agent,
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
            user_agent = %user_agent,
            "endpoint request failed"
        ),
    }
    with_hsts(result, is_tls, &config)
}

/// Add the configured `Strict-Transport-Security` header to a response served
/// over TLS. RFC 6797 §7.2: browsers ignore it over plaintext, so plain HTTP
/// responses never carry it (the force_https 308 sets its own).
fn with_hsts(
    result: Result<Response<BoxBody>, hyper::Error>,
    is_tls: bool,
    config: &Arc<crate::config::Config>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let mut resp = result?;
    if is_tls {
        if let Some(v) = hsts_for(config) {
            resp.headers_mut()
                .insert(hyper::header::STRICT_TRANSPORT_SECURITY, v);
        }
    }
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
async fn handle_request_inner(
    req: Request<Incoming>,
    client: ProxyClient,
    config: Arc<crate::config::Config>,
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
    // Decrements on every way out of this function, WebSocket paths included.
    let _in_flight = metrics.in_flight_guard();
    // Who the client is, as decided at the door (`handle_request`): the peer,
    // or the client a trusted proxy named. Every per-client decision below —
    // rate limit, metrics access, forwarding headers — is taken on it.
    let client_info = crate::edge::client_info(req.extensions())
        .copied()
        .or_else(|| peer_addr.map(|a| crate::edge::ClientInfo::direct(a.ip())));

    // Requests with no routable path, CONNECT, duplicate or conflicting Host:
    // refused before anything — ACME, rate limiting, routing — looks at them.
    if let Some(response) = reject_malformed_request(&req) {
        metrics.record_request(0, 0, response.status().as_u16(), start_time.elapsed());
        return Ok(response);
    }

    // ACME challenge check — must come before all other routing.
    // ACME challenges originate from Let's Encrypt validators and are
    // intentionally exempt from per-IP rate limits.
    if let Some(response) = handle_acme_challenge(&req, &challenge_store) {
        return Ok(response);
    }

    // Per-IP rate limiting. Applied after ACME so issuance can't be denied
    // by a noisy neighbour, and before all routing so denied requests
    // never touch upstream connection pools or Lua hooks. Requests with
    // no observable peer (UNIX socket, error path) skip the check.
    if let (Some(limiter), Some(who)) = (rate_limiter.as_ref(), client_info) {
        if limiter.check_key(&client_key(who.ip)).is_err() {
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 429, duration);
            let body = full(Bytes::from_static(b"Rate limit exceeded"));
            return Ok(Response::builder()
                .status(429)
                .header("Retry-After", "1")
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    }

    // Reject dot-segment / encoded-slash paths before any rule matching. Rules
    // match `starts_with(prefix)` on the raw path and per-route auth / Lua deny
    // hooks bind to the matched rule, so `/api/../admin/users` would pass the
    // open `/api/` rule's checks and land on `/admin/users` at any backend that
    // normalises dot segments (`%2e%2e` and `%2f` variants likewise). Rejecting
    // beats normalising: no routing semantics change for legitimate paths.
    // This is the single choke point for both the HTTP and WebSocket paths.
    if has_dot_segment_or_encoded_slash(
        req.uri().path(),
        config.server.allow_encoded_slash.unwrap_or(false),
    ) {
        let duration = start_time.elapsed();
        metrics.record_request(0, 0, 400, duration);
        let body = full(Bytes::from("Bad Request"));
        return Ok(Response::builder()
            .status(400)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    // A `redirect_from` host of an app: straight to its `domain` over HTTPS,
    // in one hop even from plain HTTP (before force_https), WebSocket
    // upgrades included, and without waking the app. After the ACME
    // challenge above, so the redirected host still gets its certificate.
    if let Some(manager) = &app_manager {
        if let Some(response) = app_redirect(&req, manager, &config) {
            metrics.record_request(0, 0, response.status().as_u16(), start_time.elapsed());
            return Ok(response);
        }
    }

    // HTTP to HTTPS redirect when TLS is off and force_https is enabled —
    // unless a trusted proxy in front already terminated HTTPS (it would be
    // redirected to where it already is, forever).
    if !is_tls
        && config.tls.force_https
        && !crate::edge::forwarded_https(req.headers(), req.extensions())
    {
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
        // Cluster-pushed domains count too. Without them a plain-HTTP request
        // for a domain the cluster routes was answered 400 here, before the
        // redirect to the HTTPS side that serves it.
        // The Location is rebuilt from a strictly parsed host[:port], never
        // from the raw header: `Host: example.com:@evil.com` passed the
        // served-host check (everything before the first `:` is a served
        // name) and became `https://example.com:@evil.com/` — userinfo
        // `example.com:`, host `evil.com`. An open redirect.
        let parsed = parse_host_port(raw_host);
        let host_ok = match parsed {
            Some((bare, _)) => {
                is_configured_host(bare, &config)
                    || find_matching_rule(&req, &config.rules).is_some()
                    || match &app_manager {
                        Some(m) => {
                            m.app_name_for_host(bare).await.is_some()
                                || m.external_routes.serves(bare)
                        }
                        None => false,
                    }
            }
            None => false,
        };
        let host_for_redirect = if let (true, Some((bare, port))) = (host_ok, parsed) {
            match port {
                Some(p) => format!("{}:{}", bare, p),
                None => bare.to_string(),
            }
        } else {
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 400, duration);
            let body = full(Bytes::from("Bad Request"));
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
        let Ok(location) = HeaderValue::from_str(&location) else {
            return Ok(plain_response(400, "Bad Request"));
        };
        // RFC 6797 §7.2: HSTS over plaintext is ignored by browsers, so this
        // header on the 308 is non-load-bearing — the canonical home is the
        // HTTPS path, set by `with_hsts`. Kept here for consistency
        // with the configured policy in case any non-browser client honours it.
        let mut builder = Response::builder()
            .status(308)
            .header("Location", &location);
        if let Some(v) = hsts_for(&config) {
            builder = builder.header("Strict-Transport-Security", v);
        }
        return Ok(builder.body(empty()).unwrap());
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
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 413, duration);
            return Ok(payload_too_large());
        }
    }

    if is_metrics_request(
        &req,
        config.metrics.endpoint.as_deref().unwrap_or("/metrics"),
    ) {
        // Local means the connection itself comes from this host: the TCP
        // peer (or the PROXY header's source), never a forwarded claim — a
        // trusted range that covers a tenant's container would otherwise let
        // it say `X-Forwarded-For: 127.0.0.1`. And the client too, so a
        // front proxy on this host relaying a remote client is not local.
        let is_loopback =
            client_info.is_some_and(|who| who.peer.is_loopback() && who.ip.is_loopback());
        if !is_loopback {
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 403, duration);
            let body = full(Bytes::from("Forbidden"));
            return Ok(Response::builder()
                .status(403)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
        let duration = start_time.elapsed();
        let metrics_output = metrics.format_metrics();
        metrics.record_request(0, metrics_output.len() as u64, 200, duration);
        let body = full(Bytes::from(metrics_output));
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    if is_health_request(&req, &config.health) {
        let duration = start_time.elapsed();
        metrics.record_request(0, 0, 200, duration);
        let body = full(Bytes::from("OK"));
        return Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/plain")
            .body(body)
            .unwrap());
    }

    // Decide this before the hop-by-hop strip below removes `Upgrade`. hyper
    // has already recorded the upgrade on the request itself, so the header
    // is not needed again: the tunnel writes its own.
    let is_websocket = is_websocket_request(&req);

    // Sanitise the inbound headers once, here, before any Lua hook or any
    // proxying path sees them:
    // - hop-by-hop headers, and every header the client nominated in
    //   `Connection`, go now — not after the scripts ran, where a client's
    //   `Connection: x-user` would delete the `x-user` a script had just set;
    // - `Forwarded` / `X-Forwarded-*` / `X-Real-IP` are replaced by the
    //   proxy's own view, so scripts and every backend path (rules, apps,
    //   WebSocket) see the real client, never the client's claim about itself.
    let mut req = req;
    {
        let host = original_host(&req);
        crate::proxy_headers::strip_hop_by_hop(req.headers_mut());
        crate::proxy_headers::set_forwarding_headers_for(
            req.headers_mut(),
            client_info.as_ref(),
            is_tls,
            host.as_deref(),
        );
        // A client naming the request-ID header in `Connection` must not
        // get it stripped on the way upstream.
        if let (Some(name), Some(id)) = (
            config.server.edge.request_id_header.0.as_ref(),
            crate::edge::request_id(req.extensions()),
        ) {
            if !req.headers().contains_key(name) {
                let id = id.clone();
                req.headers_mut().insert(name.clone(), id);
            }
        }
    }

    // --- Lua on_request hook ---
    // The Lua view of the request, once built, is reused by the later hooks
    // (on_request_end) instead of being rebuilt from the request.
    #[cfg(feature = "scripting")]
    let mut lua_view: Option<LuaRequest> = None;
    #[cfg(feature = "scripting")]
    if let Some(ref engine) = lua_engine {
        if engine.has_on_request() {
            let mut lua_req = build_lua_request(&req);
            match engine.call_on_request(&mut lua_req) {
                RequestHookResult::Deny { status, body } => {
                    let duration = start_time.elapsed();
                    let len = body.len() as u64;
                    let resp = lua_deny_response(status, body);
                    metrics.record_request(0, len, resp.status().as_u16(), duration);
                    return Ok(resp);
                }
                RequestHookResult::Continue(updated_req) => {
                    apply_lua_request_mods(&mut req, &updated_req);
                    lua_view = Some(updated_req);
                }
            }
        }
    }

    if is_websocket {
        // The gates — the rule's `@auth` then `@forward_auth`, or the app's
        // — run inside, once it is known which of the two serves.
        return handle_websocket_request(
            req,
            client,
            &config,
            &metrics,
            start_time,
            app_manager.clone(),
            is_tls,
            peer_addr,
            &lua_engine,
            &circuit_breaker,
            &load_balancer,
        )
        .await;
    }

    // Always enforce a request timeout. Falls back to 60s when the config
    // omits `[limits].request_timeout` — e.g. a deployed config.toml missing
    // the field, or the .conf route format which can't express it. Without a
    // default, a stuck backend hangs the client indefinitely ("pending" in the
    // browser) instead of returning a bounded 504.
    // A rule's `@timeout` overrides it; the rule is only looked up when some
    // rule has one.
    let timeout_sec = crate::upstream::request_timeout(
        &config,
        if config.upstream.route_timeouts {
            // Not the rule's when an app takes its whole-domain rule over
            // (`override_with_app` in handle_regular_request): the rule does
            // not serve the request, so neither does its `@timeout`.
            find_matching_rule(&req, &config.rules)
                .filter(|m| {
                    let whole_domain =
                        m.from_domain_rule && matches!(m.resolution, UrlResolution::AppendPath);
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .map(|h| h.split(':').next().unwrap_or(h))
                        .or_else(|| req.uri().host());
                    !(whole_domain
                        && app_manager.as_ref().zip(host).is_some_and(|(am, h)| {
                            am.serving_route(h, crate::app::StaticRoute::WholeDomain)
                                .is_some()
                        }))
                })
                .map(|m| m.rule_idx)
        } else {
            None
        },
    );

    // Capture before `req` is moved into the handler, for the timeout log
    // and byte accounting. A `Method`/`Uri` clone is a refcount bump, not a
    // copy of the path.
    let req_method = req.method().clone();
    let req_uri = req.uri().clone();
    let req_bytes_in = request_content_length(&req);
    let compression = crate::response::compress::Requested::capture(&req, &config.compression);

    // What on_request_end will be shown: the request as the hooks left it.
    // Only kept when some script defines that hook.
    #[cfg(feature = "scripting")]
    let lua_end_view: Option<LuaRequest> = match lua_engine {
        Some(ref engine) if engine.may_run_on_request_end() => {
            Some(lua_view.take().unwrap_or_else(|| build_lua_request(&req)))
        }
        _ => None,
    };

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
            let duration = start_time.elapsed();
            metrics.record_request(0, 0, 504, duration);
            tracing::warn!(
                layer = "proxy",
                method = %req_method,
                path = %req_uri.path(),
                timeout_secs = timeout_sec.as_secs(),
                elapsed_ms = duration.as_millis() as u64,
                "regular request timed out; returning 504"
            );
            let body = full(Bytes::from("Gateway Timeout"));
            return Ok(Response::builder()
                .status(504)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap());
        }
    };
    let duration = start_time.elapsed();

    match result {
        #[allow(unused_variables)]
        Ok((response, _target_url, route_scripts)) => {
            let status = response.status().as_u16();

            // --- Lua on_request_end hooks (global + route) ---
            #[cfg(feature = "scripting")]
            if let (Some(ref engine), Some(lua_req)) = (&lua_engine, &lua_end_view) {
                let duration_ms = duration.as_secs_f64() * 1000.0;

                // Global on_request_end
                if engine.has_on_request_end() {
                    engine.call_on_request_end(lua_req, status, duration_ms, &_target_url);
                }

                // Route-specific on_request_end
                for script_name in &route_scripts {
                    engine.call_route_on_request_end(
                        script_name,
                        lua_req,
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

            // After the HTML rewrite (handle_regular_request), so a rewritten
            // page is compressed; before counting, so bytes_sent is the wire.
            let response =
                crate::response::compress::apply(response, compression, &config.compression);
            let (mut parts, body) = response.into_parts();
            if crate::access_log::enabled() {
                parts.extensions.insert(crate::access_log::Upstream {
                    target: _target_url,
                    app: app_name,
                });
            }
            let boxed = body.map_err(BoxError::from).boxed();
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

/// `path` without its leading `/`, for joining onto a target URL that ends
/// in one. Total — never panics — even on a path that has no leading slash.
fn strip_leading_slash(path: &str) -> &str {
    path.strip_prefix('/').unwrap_or(path)
}

/// The URL an app-managed request goes to: the slot's (or pushed instance's)
/// base URL, then the request's path and query.
fn app_target_url(base: &url::Url, uri: &hyper::Uri) -> String {
    let path = uri.path();
    let query = uri.query();
    let mut out =
        String::with_capacity(base.as_str().len() + path.len() + query.map_or(0, |q| q.len() + 1));
    out.push_str(base.as_str());
    if base.as_str().ends_with('/') {
        out.push_str(strip_leading_slash(path));
    } else {
        out.push_str(path);
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
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
/// Only `http://`, `https://`, `h2c://` and `redirect://` with a non-empty
/// host are allowed, and `unix:/absolute/path.sock` (which
/// `apply_route_hook_result` refuses from a script).
fn validate_proxy_target_url(url: &str) -> bool {
    if url.starts_with("unix:") {
        return !contains_crlf(url)
            && url::Url::parse(url).is_ok_and(|u| crate::upstream::validate_target(&u).is_ok());
    }
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
            matches!(u.scheme(), "http" | "https" | "h2c")
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
        .body(full(Bytes::from("Payload Too Large")))
        .unwrap()
}

/// Decode a buffered gzip/deflate body (`encoding` is the lower-cased
/// `Content-Encoding`), producing at most `cap` bytes. `None` when the output
/// would exceed `cap` or the stream is not valid: the caller then passes the
/// body through untouched rather than buffer a decompression bomb.
fn inflate_capped(body: &[u8], encoding: &str, cap: usize) -> Option<Bytes> {
    use std::io::Read;
    let mut decoded = Vec::new();
    // One byte over the cap tells "exactly at the cap" from "over it".
    let limit = cap as u64 + 1;
    let read = if encoding.contains("gzip") {
        flate2::read::GzDecoder::new(body)
            .take(limit)
            .read_to_end(&mut decoded)
    } else if encoding.contains("deflate") {
        flate2::read::DeflateDecoder::new(body)
            .take(limit)
            .read_to_end(&mut decoded)
    } else {
        return Some(Bytes::copy_from_slice(body));
    };
    match read {
        Ok(_) if decoded.len() <= cap => Some(Bytes::from(decoded)),
        _ => None,
    }
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
    if is_client_body_error(e) {
        // The client broke off its own request body; nobody is likely
        // listening, but the log and metrics should not say "Bad Gateway".
        return plain_response(400, "Bad Request");
    }
    Response::builder()
        .status(502)
        .body(full(Bytes::from("Bad Gateway")))
        .unwrap()
}

#[cfg(feature = "scripting")]
fn apply_lua_request_mods<B>(req: &mut Request<B>, lua_req: &LuaRequest) {
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
        let Ok(hn) = name.parse::<hyper::header::HeaderName>() else {
            continue;
        };
        // The Lua view of a header joins its repeated fields and shows a
        // non-UTF-8 value as "" (see `lua_header_view`). A header whose view
        // Lua left exactly as it was is kept as is — original bytes and
        // separate fields intact. Anything else is *replaced*, every field
        // of it: a value Lua set must not travel next to a client duplicate
        // the backend might read first.
        if lua_header_view_equals(headers, &hn, value) {
            continue;
        }
        if let Ok(hv) = HeaderValue::from_str(value) {
            headers.insert(hn, hv);
        }
    }
}

/// Run a matched route's Lua hooks, in order: each route script's
/// `on_request` (deny, or header/path changes applied to `req`), the global
/// `on_route`, then each route script's `on_route` (may override
/// `target_url`). Returns the response to send when a hook denies.
///
/// Shared by the HTTP and the WebSocket paths. The upgrade path used to skip
/// all of it: a route guarded by `@script:auth.lua` was open to anyone who
/// added `Upgrade: websocket`, with whatever `X-User` they cared to send.
///
/// The Lua view of the request is built once, and only if some hook will run.
#[cfg(feature = "scripting")]
fn run_route_hooks(
    engine: &LuaEngine,
    req: &mut Request<Incoming>,
    route_scripts: &[String],
    target_url: &mut String,
    overridden: &mut bool,
) -> Option<Response<BoxBody>> {
    let mut view: Option<LuaRequest> = None;
    for script_name in route_scripts {
        if !engine.route_has_hook(script_name, Hook::Request) {
            continue;
        }
        let mut lua_req = view.take().unwrap_or_else(|| build_lua_request(req));
        match engine.call_route_on_request(script_name, &mut lua_req) {
            RequestHookResult::Deny { status, body } => {
                return Some(lua_deny_response(status, body));
            }
            // Apply the script's mutations to the real request so they feed
            // the next script and the outbound build — same as the global
            // on_request path. Without this a client-supplied header the
            // script meant to overwrite (e.g. x-user) would be forwarded
            // verbatim.
            RequestHookResult::Continue(updated) => {
                apply_lua_request_mods(req, &updated);
                view = Some(updated);
            }
        }
    }

    let global = engine.has_on_route();
    let any_route = route_scripts
        .iter()
        .any(|s| engine.route_has_hook(s, Hook::Route));
    if !global && !any_route {
        return None;
    }
    let lua_req = view.unwrap_or_else(|| build_lua_request(req));
    if global {
        let result = engine.call_on_route(&lua_req, target_url.as_str());
        if let Some(resp) = apply_route_hook_result(result, target_url, overridden, "on_route") {
            return Some(resp);
        }
    }
    for script_name in route_scripts {
        if !engine.route_has_hook(script_name, Hook::Route) {
            continue;
        }
        let result = engine.call_route_on_route(script_name, &lua_req, target_url.as_str());
        if let Some(resp) = apply_route_hook_result(result, target_url, overridden, script_name) {
            return Some(resp);
        }
    }
    None
}

/// Apply one `on_route` result: an override replaces the target if it is an
/// allowed URL; a raised hook denies — fail closed rather than proxy to the
/// default target it may have meant to steer away from.
#[cfg(feature = "scripting")]
fn apply_route_hook_result(
    result: RouteHookResult,
    target_url: &mut String,
    overridden: &mut bool,
    hook: &str,
) -> Option<Response<BoxBody>> {
    match result {
        RouteHookResult::Override(new_url) => {
            // A Unix socket is reachable only as a configured target: a
            // script assembling a URL from request data must not be able to
            // point the proxy at /var/run/docker.sock.
            if validate_proxy_target_url(&new_url) && !new_url.starts_with("unix:") {
                *target_url = new_url;
                *overridden = true;
            } else {
                tracing::warn!(
                    "Lua {} returned disallowed target URL, ignoring: {}",
                    hook,
                    new_url
                );
            }
            None
        }
        RouteHookResult::Default => None,
        RouteHookResult::Deny { status, body } => Some(lua_deny_response(status, body)),
    }
}

/// Whether an `on_response` hook will run for a request on `route_scripts` —
/// decided before the request is consumed, so its Lua view is only kept when
/// it will be used.
#[cfg(feature = "scripting")]
fn wants_on_response(engine: &LuaEngine, route_scripts: &[String]) -> bool {
    engine.has_on_response()
        || route_scripts
            .iter()
            .any(|s| engine.route_has_hook(s, Hook::Response))
}

/// Run the global and route `on_response` hooks and merge what they asked
/// for (later scripts win). `None` when no hook asked for anything.
#[cfg(feature = "scripting")]
fn lua_response_mods(
    engine: &LuaEngine,
    lua_req: &LuaRequest,
    route_scripts: &[String],
    status: u16,
    headers: &hyper::HeaderMap,
) -> Option<crate::scripting::ResponseMod> {
    use crate::scripting::ResponseMod;
    if !wants_on_response(engine, route_scripts) {
        return None;
    }
    let resp_headers = extract_response_headers(headers);
    let mut all_mods: Vec<ResponseMod> = Vec::new();
    if engine.has_on_response() {
        all_mods.push(engine.call_on_response(lua_req, status, &resp_headers));
    }
    for script_name in route_scripts {
        if engine.route_has_hook(script_name, Hook::Response) {
            all_mods.push(engine.call_route_on_response(
                script_name,
                lua_req,
                status,
                &resp_headers,
            ));
        }
    }
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
    let changed = !merged.set_headers.is_empty()
        || !merged.remove_headers.is_empty()
        || merged.replace_body.is_some()
        || merged.override_status.is_some();
    changed.then_some(merged)
}

/// Apply merged `on_response` modifications to a backend response.
#[cfg(feature = "scripting")]
fn apply_response_mods(
    response: Response<Incoming>,
    merged: crate::scripting::ResponseMod,
) -> Response<BoxBody> {
    let (mut parts, body) = response.into_parts();

    if let Some(status) = merged.override_status {
        // Same range a deny may use (see `lua_deny_response`).
        if (200..=599).contains(&status) {
            parts.status = hyper::StatusCode::from_u16(status).unwrap_or(parts.status);
        }
    }

    for name in &merged.remove_headers {
        if let Ok(header_name) = name.parse::<hyper::header::HeaderName>() {
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
        parts.headers.insert(
            hyper::header::CONTENT_LENGTH,
            HeaderValue::from(new_bytes.len()),
        );
        let mut resp = Response::from_parts(parts, full(new_bytes));
        // The script wrote this body: error pages leave it alone.
        crate::response::mark_owned(&mut resp, crate::response::BodyOwner::Script);
        return resp;
    }

    let mut resp = Response::from_parts(parts, body.map_err(BoxError::from).boxed());
    // A status the script turned into an error is still the backend's body.
    crate::response::mark_upstream(&mut resp, None);
    resp
}

/// True when `path` (the raw, undecoded request path) contains a dot
/// segment in any spelling a backend might normalise away — literal or
/// percent-encoded dots, terminated by `/`, the end of the path, a `;` path
/// parameter (Tomcat, Jetty, Spring: `/api/..;/admin`), or a backslash (IIS
/// and anything that treats `\` as `/`) — or, unless `allow_encoded_slash`,
/// an encoded slash anywhere.
///
/// Both `/` and `%2F` count as segment boundaries for the dot-segment scan,
/// so `..%2Fadmin` and `%2F..` are caught even when encoded slashes are
/// allowed through for backends whose API paths carry them (GitLab's
/// `group%2Fproject`, S3-style keys).
fn has_dot_segment_or_encoded_slash(path: &str, allow_encoded_slash: bool) -> bool {
    // `%XY` at `i`, case-insensitive hex digits.
    fn is_pct(bytes: &[u8], i: usize, hi: u8, lo: u8) -> bool {
        bytes.len() >= i + 3
            && bytes[i] == b'%'
            && (bytes[i + 1] | 0x20) == hi
            && (bytes[i + 2] | 0x20) == lo
    }
    // Length of a segment separator at `i` (`/`, `\`, `%2F`, `%5C`), if any.
    fn separator_len(bytes: &[u8], i: usize) -> Option<usize> {
        match bytes.get(i) {
            Some(b'/') | Some(b'\\') => Some(1),
            Some(b'%') if is_pct(bytes, i, b'2', b'f') || is_pct(bytes, i, b'5', b'c') => Some(3),
            _ => None,
        }
    }
    // Length of a dot-segment terminator at `i`: a separator, `;` / `%3B`,
    // or the end of the path.
    fn terminator_len(bytes: &[u8], i: usize) -> Option<usize> {
        if i == bytes.len() {
            return Some(0);
        }
        separator_len(bytes, i).or_else(|| match bytes[i] {
            b';' => Some(1),
            b'%' if is_pct(bytes, i, b'3', b'b') => Some(3),
            _ => None,
        })
    }

    let bytes = path.as_bytes();
    let mut i = 0;
    let mut at_segment_start = true;
    while i < bytes.len() {
        if !allow_encoded_slash && is_pct(bytes, i, b'2', b'f') {
            return true;
        }
        if at_segment_start {
            // Count leading dots (literal or `%2e`); a segment made of exactly
            // one or two dots is a dot segment.
            let mut j = i;
            let mut dots = 0usize;
            loop {
                if j < bytes.len() && bytes[j] == b'.' {
                    dots += 1;
                    j += 1;
                } else if is_pct(bytes, j, b'2', b'e') {
                    dots += 1;
                    j += 3;
                } else {
                    break;
                }
            }
            if (1..=2).contains(&dots) && terminator_len(bytes, j).is_some() {
                return true;
            }
        }
        match separator_len(bytes, i) {
            Some(n) => {
                at_segment_start = true;
                i += n;
            }
            None => {
                at_segment_start = false;
                i += 1;
            }
        }
    }
    false
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
            let body = full(Bytes::from(key_auth.clone()));
            return Some(
                Response::builder()
                    .status(200)
                    .header("Content-Type", "text/plain")
                    .body(body)
                    .unwrap(),
            );
        }
    }

    let body = full(Bytes::from("Challenge not found"));
    Some(Response::builder().status(404).body(body).unwrap())
}

#[allow(clippy::too_many_arguments)]
async fn handle_websocket_request(
    mut req: Request<Incoming>,
    client: ProxyClient,
    config: &crate::config::Config,
    metrics: &SharedMetrics,
    _start_time: std::time::Instant,
    app_manager: Option<Arc<AppManager>>,
    is_tls: bool,
    peer_addr: Option<SocketAddr>,
    lua_engine: &OptionalLuaEngine,
    circuit_breaker: &SharedCircuitBreaker,
    load_balancer: &LoadBalancerState,
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
            manager.overrides_domain_rule(h).await
        }
        _ => false,
    };
    // As on the HTTP path: when the app takes the request over, the rule is
    // out of it — its gates included (they used to run as well, so both
    // auths applied and forward-auth was asked twice).
    let route = if override_with_app { None } else { route };

    // For a rule: the configured target the tunnel goes to (the circuit
    // breaker's key) and whether a Lua hook replaced the URL.
    let mut ws_target: Option<(String, bool)> = None;
    // For an app, held by the tunnel: the app is not idle while it is up.
    let mut ws_open: Option<crate::app::OpenRequest> = None;
    let target_url = match &route {
        Some(matched) => {
            // Same gates as the HTTP path, `@auth` then `@forward_auth`,
            // before anything is tunnelled.
            if let Some(denied) = matched.authorize(&mut req, &client, config).await {
                return Ok(denied);
            }
            // The same target choice as HTTP: the rule's balancing, past
            // targets whose breaker is open or that health checks marked
            // down. It used to be the first target, whatever its state.
            let match_path = request_match_path(&req);
            let path = match matched.resolution {
                UrlResolution::StripPrefix(_) => &*match_path,
                _ => req.uri().path(),
            };
            let Some((mut url, base)) = select_target(
                matched,
                path,
                req.uri().query(),
                circuit_breaker,
                load_balancer,
            ) else {
                metrics.inc_errors();
                let body = full(Bytes::from("Service Unavailable"));
                return Ok(Response::builder().status(503).body(body).unwrap());
            };
            // A matched route runs the same Lua hooks as a plain request —
            // route on_request (deny / header rewrite), global and route
            // on_route (deny / target override) — before anything is
            // tunnelled.
            #[allow(unused_mut)]
            let mut overridden = false;
            #[cfg(feature = "scripting")]
            if let Some(engine) = lua_engine.as_ref() {
                if let Some(resp) = run_route_hooks(
                    engine,
                    &mut req,
                    matched.route_scripts,
                    &mut url,
                    &mut overridden,
                ) {
                    return Ok(resp);
                }
            }
            #[cfg(not(feature = "scripting"))]
            let _ = lua_engine;
            ws_target = Some((base, overridden));
            url
        }
        None => {
            if let (Some(ref manager), Some(ref h)) = (app_manager, host) {
                if let Some(crate::app::AppTarget {
                    target, auth, open, ..
                }) = manager.resolve_app_request(h, &|_| true).await
                {
                    // Counted as a visitor, and as a WebSocket until the
                    // tunnel closes.
                    let client_ip = crate::edge::client_ip(req.extensions());
                    ws_open = open.map(|o| {
                        if let Some(ip) = client_ip {
                            o.note_visitor(ip);
                        }
                        o.websocket(client_ip)
                    });
                    // Same gate as the HTTP path: an upgrade must not be a way
                    // around the app's Basic Auth.
                    if let Some(auth) = auth {
                        if auth.requires_auth(&request_match_path(&req)) {
                            if let Some(denied) = verify_basic_auth(&req, &auth.users).await {
                                metrics.inc_errors();
                                return Ok(denied);
                            }
                        }
                        if let Some(denied) =
                            app_forward_auth(&auth, &mut req, &client, config).await
                        {
                            metrics.inc_errors();
                            return Ok(denied);
                        }
                    }
                    let path = req.uri().path();
                    let query = req
                        .uri()
                        .query()
                        .map(|q| format!("?{}", q))
                        .unwrap_or_default();
                    if target.url.as_str().ends_with('/') {
                        format!("{}{}{}", target.url, strip_leading_slash(path), query)
                    } else {
                        format!("{}{}{}", target.url, path, query)
                    }
                } else {
                    metrics.inc_errors();
                    let body = full(Bytes::from("Misdirected Request"));
                    return Ok(Response::builder().status(421).body(body).unwrap());
                }
            } else {
                metrics.inc_errors();
                let body = full(Bytes::from("Misdirected Request"));
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
            let body = full(Bytes::from("Bad backend URL"));
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
        let body = full(Bytes::from("Bad Request"));
        return Ok(Response::builder().status(400).body(body).unwrap());
    }

    // With Host rewritten to the backend's name, a same-origin upgrade's
    // `Origin: https://<client host>` trips origin checks (Phoenix
    // check_origin); align it. Cross-site Origins pass through untouched.
    if backend_tls {
        let backend_origin = format!("https://{}", backend_host);
        crate::proxy_headers::rewrite_same_origin(req.headers_mut(), &client_host, &backend_origin);
    }

    let client_info = crate::edge::client_info(req.extensions())
        .copied()
        .or_else(|| peer_addr.map(|a| crate::edge::ClientInfo::direct(a.ip())));
    let extra_headers =
        build_ws_extra_headers(req.headers(), client_info.as_ref(), is_tls, &client_host);
    // The rule's `headers { }` block applies to the upgrade request too — it
    // is an ordinary HTTP request until the 101 — and last, as on the HTTP
    // path, so it can override the forwarding headers.
    let mut host_header = host_header;
    let extra_headers = match route.as_ref().map(|m| (m, &config.rules[m.rule_idx])) {
        Some((matched, rule)) if !rule.headers.is_empty() => {
            let vars = crate::config::HeaderVars {
                client_ip: client_info.map(|c| c.ip),
                scheme: if is_tls { "https" } else { "http" },
                host: &matched.host,
            };
            let (extra, host) =
                apply_ws_header_rules(&extra_headers, &host_header, &rule.headers, &vars);
            host_header = host;
            extra
        }
        _ => extra_headers,
    };
    // The rule's client for this tunnel: its TLS settings and connect
    // timeout — the configured target's, or, after a Lua override, only if
    // the new URL is one of the rule's own origins (see
    // `UpstreamOptions::client_for`).
    let rule_client = route
        .as_ref()
        .zip(ws_target.as_ref())
        .and_then(|(m, (base, overridden))| {
            config.rules[m.rule_idx]
                .upstream
                .client_for((!overridden).then_some(base.as_str()), &target_url)
        });
    let connect_timeout = rule_client
        .map(|c| c.connect_timeout())
        .unwrap_or(crate::pool::DEFAULT_CONNECT_TIMEOUT);
    // A failed connect or handshake counts against the target's breaker, a
    // 101 for it: `select_target` may have handed out a half-open probe.
    let breaker_key = ws_target
        .as_ref()
        .filter(|(_, overridden)| !overridden)
        .map(|(base, _)| base.clone());
    let record_failure = || {
        if let Some(key) = &breaker_key {
            circuit_breaker.record_failure(key);
        }
    };

    // debug-level: per-message upgrade chatter floods info logs (see
    // `[logging].log_endpoints` for per-request access logging instead)
    tracing::debug!(
        "WebSocket upgrade request to {}{}{}",
        backend_addr,
        path,
        query
    );

    // A `unix:` target: the tunnel goes to its socket. Its requests are
    // addressed to a placeholder host (`crate::upstream::routing_url`), so
    // the socket is taken from the rule — the first target, as above — unless
    // a script sent the upgrade elsewhere.
    let unix_socket = ws_target
        .as_ref()
        .filter(|(_, overridden)| !overridden && backend_host == crate::upstream::UNIX_AUTHORITY)
        .and_then(|(base, _)| url::Url::parse(base).ok())
        .filter(|u| u.scheme() == "unix")
        .map(|u| u.path().to_string());
    let backend: Box<dyn AsyncStream> = if let Some(socket) = unix_socket {
        match timeout(connect_timeout, tokio::net::UnixStream::connect(&socket)).await {
            Ok(Ok(s)) => Box::new(s),
            Ok(Err(e)) => {
                tracing::error!("Failed to connect to {} for WebSocket: {}", socket, e);
                record_failure();
                metrics.inc_errors();
                let body = full(Bytes::from("Backend not reachable"));
                return Ok(Response::builder().status(502).body(body).unwrap());
            }
            Err(_) => {
                record_failure();
                metrics.inc_errors();
                let body = full(Bytes::from("Gateway Timeout"));
                return Ok(Response::builder().status(504).body(body).unwrap());
            }
        }
    } else {
        // Connect to the backend. Bounded by a 5s connect timeout (matching the
        // HTTP pool's connect_timeout): the WS upgrade path runs before the
        // request-timeout wrapper, so an unbounded connect to a black-holed
        // backend would otherwise hang the upgrade indefinitely.
        let tcp = match timeout(connect_timeout, TcpStream::connect(&backend_addr)).await {
            Ok(Ok(s)) => {
                // Frames are small and latency-bound; without TCP_NODELAY Nagle
                // holds each one back waiting for the previous one's ACK. The
                // client side and the HTTP pool already set it.
                let _ = s.set_nodelay(true);
                s
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to connect to backend for WebSocket: {}", e);
                record_failure();
                metrics.inc_errors();
                let body = full(Bytes::from("Backend not reachable"));
                return Ok(Response::builder().status(502).body(body).unwrap());
            }
            Err(_) => {
                tracing::warn!(
                    layer = "proxy_ws",
                    backend = %backend_addr,
                    path = %path,
                    timeout_ms = connect_timeout.as_millis() as u64,
                    "websocket backend connect timed out; returning 504"
                );
                record_failure();
                metrics.inc_errors();
                let body = full(Bytes::from("Gateway Timeout"));
                return Ok(Response::builder().status(504).body(body).unwrap());
            }
        };

        // Wrap the stream in TLS when the backend target is https/wss.
        if backend_tls {
            // The rule's `@tls_ca` / `@tls_sni` / `@tls_client_cert` /
            // `@tls_insecure` apply to its WebSockets as to its requests.
            let rule_tls = rule_client.and_then(|c| c.websocket_tls());
            let (connector, sni) = match rule_tls {
                Some((connector, sni)) => (connector, sni.cloned()),
                None => (ws_backend_tls_connector(), None),
            };
            let server_name = match sni.map_or_else(
                || rustls_pki_types::ServerName::try_from(backend_host.clone()),
                Ok,
            ) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(
                        "Invalid TLS server name for WebSocket backend {}: {}",
                        backend_host,
                        e
                    );
                    metrics.inc_errors();
                    let body = full(Bytes::from("Bad backend URL"));
                    return Ok(Response::builder().status(502).body(body).unwrap());
                }
            };
            match timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await {
                Ok(Ok(s)) => Box::new(s),
                Ok(Err(e)) => {
                    tracing::error!(
                        "TLS handshake with WebSocket backend {} failed: {}",
                        backend_addr,
                        e
                    );
                    record_failure();
                    metrics.inc_errors();
                    let body = full(Bytes::from("Backend not reachable"));
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
                    record_failure();
                    metrics.inc_errors();
                    let body = full(Bytes::from("Gateway Timeout"));
                    return Ok(Response::builder().status(504).body(body).unwrap());
                }
            }
        } else {
            Box::new(tcp)
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

    if contains_crlf(&ws_key)
        || contains_crlf(&ws_version)
        || ws_protocol.as_deref().is_some_and(contains_crlf)
    {
        metrics.inc_errors();
        let body = full(Bytes::from("Bad Request"));
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
        let body = full(Bytes::from("Failed to initiate WebSocket with backend"));
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
            record_failure();
            metrics.inc_errors();
            let body = full(Bytes::from("Backend did not respond to WebSocket upgrade"));
            return Ok(Response::builder().status(502).body(body).unwrap());
        }
        Err(_) => {
            tracing::error!("Backend timed out sending WebSocket upgrade response");
            record_failure();
            metrics.inc_errors();
            let body = full(Bytes::from("Backend timed out on WebSocket upgrade"));
            return Ok(Response::builder().status(504).body(body).unwrap());
        }
    };

    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    let status_ok = response_str
        .lines()
        .next()
        .map(|l| l.starts_with("HTTP/1.1 101") || l.starts_with("HTTP/1.0 101"))
        .unwrap_or(false);
    if let Some(key) = &breaker_key {
        // The backend answered: alive, unless its answer is a failure status.
        let status = response_str
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok());
        match status {
            Some(code) if !status_ok && circuit_breaker.is_failure_status(code) => {
                circuit_breaker.record_failure(key)
            }
            _ => circuit_breaker.record_success(key),
        }
    }
    if !status_ok {
        tracing::error!(
            "Backend rejected WebSocket upgrade: {}",
            response_str.lines().next().unwrap_or("")
        );
        metrics.inc_errors();
        let body = full(Bytes::from("Backend rejected WebSocket upgrade"));
        return Ok(Response::builder().status(502).body(body).unwrap());
    }

    // Extract headers from backend 101 response
    let Some((accept_key, resp_protocol)) = ws_upgrade_response_headers(&response_str) else {
        tracing::error!("Backend sent WebSocket upgrade headers that are not valid header values");
        metrics.inc_errors();
        return Ok(plain_response(502, "Backend rejected WebSocket upgrade"));
    };

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

    // The tunnel outlives this request's connection — hyper finishes serving
    // it once the socket is handed over — so it takes its own hold on the
    // connection's `max_connections` permit and per-IP slot. Without it every
    // open WebSocket was a connection the limits no longer counted.
    let lease = req.extensions().get::<ConnLease>().cloned();

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
        let _lease = lease; // released when the tunnel closes
        let _open = ws_open; // the app stays awake while the tunnel is up
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

    // Return 101 Switching Protocols to the client
    let mut resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key);
    if let Some(proto) = resp_protocol {
        resp = resp.header("Sec-WebSocket-Protocol", proto);
    }
    Ok(resp.body(empty()).unwrap())
}

/// The `Sec-WebSocket-Accept` and `Sec-WebSocket-Protocol` values of a
/// backend's raw 101 response, as header values for the client's 101 — or
/// `None` when either carries bytes a header value cannot hold (a control
/// character, a lone CR, DEL). They used to go into `Response::builder()` as
/// strings, and such a byte from the backend panicked the connection on the
/// final `.unwrap()`.
pub(crate) fn ws_upgrade_response_headers(
    response_str: &str,
) -> Option<(HeaderValue, Option<HeaderValue>)> {
    let mut accept_key = HeaderValue::from_static("");
    let mut resp_protocol = None;
    for line in response_str.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accept_key = HeaderValue::from_str(value.trim()).ok()?;
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                resp_protocol = Some(HeaderValue::from_str(value.trim()).ok()?);
            }
        }
    }
    Some((accept_key, resp_protocol))
}

/// Returns (Response, target_url_for_logging, route_scripts)
#[allow(clippy::too_many_arguments)]
async fn handle_regular_request(
    mut req: Request<Incoming>,
    client: ProxyClient,
    config: &crate::config::Config,
    lua_engine: &OptionalLuaEngine,
    circuit_breaker: &SharedCircuitBreaker,
    app_manager: Option<Arc<AppManager>>,
    load_balancer: Arc<LoadBalancerState>,
    is_tls: bool,
    // Only for a rule's `headers { }` block (`$client_ip`): the forwarding
    // headers themselves were set at the door, in handle_request_inner.
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
            manager.overrides_domain_rule(h).await
        }
        _ => false,
    };
    let route = if override_with_app { None } else { route };

    match route {
        #[allow(unused_mut, unused_variables)]
        Some(matched_route) => {
            let matched_prefix = matched_route.matched_prefix(is_tls);
            let html_rewrite_prefix = matched_route.html_rewrite_prefix();
            let route_scripts = matched_route.route_scripts.to_vec();

            // `@auth`, then `@forward_auth`; `@noauth` is judged on the same
            // canonical path the rule was matched on (see
            // `canonical_match_path`).
            if let Some(denied) = matched_route.authorize(&mut req, &client, config).await {
                tracing::debug!("auth refused {}", req.uri().path());
                return Ok((denied, String::new(), vec![]));
            }
            let (mut target_url, base_url) = {
                let raw_path = req.uri().path();
                let match_path = canonical_match_path(raw_path);
                // A prefix rule strips the prefix it matched, so it must strip
                // it from the form it matched — slicing `prefix.len()` bytes
                // off `//admin/x` or `/%61dmin/x` would cut in the wrong
                // place. Every other resolution forwards the path as sent.
                let target_path = match matched_route.resolution {
                    UrlResolution::StripPrefix(_) => &*match_path,
                    _ => raw_path,
                };

                // Select an available target via circuit breaker
                let target_selection = select_target(
                    &matched_route,
                    target_path,
                    req.uri().query(),
                    circuit_breaker,
                    &load_balancer,
                );
                match target_selection {
                    Some((url, base)) => (url, base),
                    None => {
                        // All targets are circuit-broken
                        let body = full(Bytes::from("Service Unavailable"));
                        return Ok((
                            Response::builder()
                                .status(503)
                                .body(body)
                                .expect("Failed to build response"),
                            String::new(),
                            route_scripts,
                        ));
                    }
                }
            };

            // A failed attempt may be retried on the rule's next target
            // (`crate::upstream::retry`); the URI is kept to resolve it.
            let rule = &config.rules[matched_route.rule_idx];
            let mut retries = match matched_route.targets.len() {
                0 | 1 => 0,
                _ => rule.upstream.retries.unwrap_or(config.upstream.retries),
            };
            let retry_uri = (retries > 0).then(|| req.uri().clone());

            // --- Lua route hooks: route on_request, global + route on_route ---
            #[cfg(feature = "scripting")]
            let mut req = req;
            // Set when a hook chose the target: it is then the only one.
            #[allow(unused_mut)]
            let mut overridden = false;
            #[cfg(feature = "scripting")]
            if let Some(ref engine) = lua_engine {
                if let Some(resp) = run_route_hooks(
                    engine,
                    &mut req,
                    &route_scripts,
                    &mut target_url,
                    &mut overridden,
                ) {
                    return Ok((resp, target_url, route_scripts));
                }
            }
            if overridden {
                retries = 0;
            }

            // Reject non-http(s)/redirect targets (config misparse). Validate the
            // backend authority (`base_url`), not the resolved `target_url`, so we
            // don't re-parse the request path/query on every request — and because
            // Lua overrides were already validated above when they replaced it.
            if !validate_proxy_target_url(&base_url) {
                tracing::warn!("Refusing to proxy disallowed target URL: {}", target_url);
                let body = full(Bytes::from("Bad Gateway"));
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

            // What on_response will be shown, captured before the request is
            // consumed — only when some on_response hook will run.
            #[cfg(feature = "scripting")]
            let lua_resp_view: Option<LuaRequest> = match lua_engine {
                Some(ref engine) if wants_on_response(engine, &route_scripts) => {
                    Some(build_lua_request(&req))
                }
                _ => None,
            };

            // `$client_ip` for a `headers { }` block: the client the door
            // resolved (behind a trusted proxy, the address it forwarded) —
            // read before the extensions that carry it are dropped below, or
            // it was always the TCP peer.
            let client_ip = crate::edge::client_ip(req.extensions()).or(peer_addr.map(|a| a.ip()));
            let (mut parts, body) = req.into_parts();
            parts.extensions = http::Extensions::new();
            // The client's hop-by-hop headers went at the door (see
            // handle_request_inner); this pass only catches any a script added.
            crate::proxy_headers::strip_hop_by_hop(&mut parts.headers);
            // HTTP/2 browsers split cookies across multiple `cookie` fields;
            // join them before forwarding to the HTTP/1.1 upstream so servers
            // that read only the first Cookie header (redbean) see them all.
            crate::proxy_headers::coalesce_cookies(&mut parts.headers);
            // X-Forwarded-For/-Proto/-Host and X-Real-IP were set from the
            // proxy's own view when the request came in (handle_request_inner),
            // with the client's original Host — before the https rewrite below.

            let header_vars = crate::config::HeaderVars {
                client_ip,
                scheme: if is_tls { "https" } else { "http" },
                host: &matched_route.host,
            };
            // What depends on the target, redone for every attempt: `parts`
            // still carries the client's URI and headers, `uri` is where this
            // attempt goes.
            let prepare = |parts: &mut http::request::Parts, uri: hyper::Uri| {
                // An https target is an external origin whose vhost/CDN
                // expects its own name as Host (matching the TLS SNI) —
                // forwarding the client's Host there gets rejected (e.g.
                // Cloudflare 403). The original host is still passed via
                // X-Forwarded-Host.
                if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                    if let Some(authority) = uri.authority() {
                        let client_host = parts
                            .headers
                            .get(hyper::header::HOST)
                            .and_then(|h| h.to_str().ok())
                            .map(|h| h.to_string())
                            .or_else(|| parts.uri.host().map(|h| h.to_string()));
                        if let Ok(v) = HeaderValue::from_str(authority.as_str()) {
                            parts.headers.insert(hyper::header::HOST, v);
                        }
                        // With Host rewritten, a same-origin `Origin: https://<client
                        // host>` no longer matches the request authority and trips
                        // CSRF origin checks (Phoenix/Bonfire). Align it; cross-site
                        // Origins pass through untouched.
                        if let Some(client_host) = &client_host {
                            let backend_origin = format!("https://{}", authority);
                            crate::proxy_headers::rewrite_same_origin(
                                &mut parts.headers,
                                client_host,
                                &backend_origin,
                            );
                        }
                    }
                }
                parts.uri = uri;
                // The rule's `headers { }` block, applied last so it can
                // override the forwarding headers normalised above.
                if !rule.headers.is_empty() {
                    crate::config::apply_header_rules(
                        &mut parts.headers,
                        &rule.headers,
                        &header_vars,
                    );
                }
            };
            let next = |tried: &[String], _: crate::upstream::retry::Failure| {
                let uri = retry_uri.as_ref()?;
                let match_path = canonical_match_path(uri.path());
                let path = match matched_route.resolution {
                    UrlResolution::StripPrefix(_) => &*match_path,
                    _ => uri.path(),
                };
                next_target(
                    &matched_route,
                    rule,
                    path,
                    uri.query(),
                    circuit_breaker,
                    tried,
                )
            };
            let mut attempt = crate::upstream::Attempt {
                client: rule
                    .upstream
                    .client_for((!overridden).then_some(base_url.as_str()), &target_url),
                target_url,
                base_url,
            };
            let sent = crate::upstream::retry::send(
                crate::upstream::retry::Exchange {
                    shared: &client,
                    breaker: circuit_breaker,
                    retries,
                    retry_on: &config.upstream.retry_on,
                    try_duration: config.upstream.try_duration,
                    max_body: config.limits.max_request_size,
                },
                parts,
                body,
                &mut attempt,
                prepare,
                next,
            )
            .await;
            let crate::upstream::Attempt {
                target_url,
                base_url,
                ..
            } = attempt;

            match sent {
                Ok(mut response) => {
                    // Hop-by-hop headers are per-connection and must not be
                    // relayed (RFC 7230 §6.1). In particular a chunked
                    // upstream's `Transfer-Encoding` header survives while
                    // hyper has already de-chunked the body — re-sending it
                    // makes the h1 server abort with User(UnexpectedHeader).
                    crate::proxy_headers::strip_hop_by_hop(response.headers_mut());
                    crate::response::mark_upstream(
                        &mut response,
                        config.rules[matched_route.rule_idx].compress,
                    );

                    // --- Circuit breaker: record success or failure ---
                    let status_code = response.status().as_u16();
                    if circuit_breaker.is_failure_status(status_code) {
                        circuit_breaker.record_failure(&base_url);
                    } else {
                        circuit_breaker.record_success(&base_url);
                    }

                    // --- Lua on_response hooks (global + route) ---
                    #[cfg(feature = "scripting")]
                    if let (Some(ref engine), Some(lua_req)) = (lua_engine, &lua_resp_view) {
                        if let Some(mods) = lua_response_mods(
                            engine,
                            lua_req,
                            &route_scripts,
                            status_code,
                            response.headers(),
                        ) {
                            return Ok((
                                apply_response_mods(response, mods),
                                target_url,
                                route_scripts,
                            ));
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
                                        // Fallible: a value that cannot be a
                                        // header leaves Location as it was.
                                        if let Ok(v) = HeaderValue::from_str(&new_location) {
                                            let (mut parts, body) = response.into_parts();
                                            parts.headers.insert(hyper::header::LOCATION, v);
                                            let boxed = body.map_err(BoxError::from).boxed();
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
                                let inner = body.map_err(BoxError::from).boxed();
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
                                let inner = body.map_err(BoxError::from).boxed();
                                let streamed =
                                    DecodingRewritingBody::new_gzip(inner, &prefix).boxed();
                                return Ok((
                                    Response::from_parts(parts, streamed),
                                    target_url,
                                    route_scripts.clone(),
                                ));
                            }

                            // deflate (rare): bounded buffered decode + rewrite.
                            // Bounded on both sides — a deflate stream inflates
                            // ~1000:1, so a 10 MB cap on the compressed body
                            // alone still let a backend have the proxy
                            // allocate gigabytes:
                            // - compressed body over the cap: part of it has
                            //   been read, so it can no longer be passed
                            //   through intact → 502;
                            // - decoded body over the cap, or not valid
                            //   deflate: passed through untouched, still
                            //   compressed, unrewritten.
                            let (parts, body) = response.into_parts();
                            let body_bytes =
                                match http_body_util::Limited::new(body, MAX_HTML_REWRITE_SIZE)
                                    .collect()
                                    .await
                                {
                                    Ok(collected) => collected.to_bytes(),
                                    Err(e) => {
                                        tracing::warn!(
                                        "Not rewriting deflate HTML for prefix {}: {} (target: {})",
                                        prefix,
                                        e,
                                        target_url
                                    );
                                        let body = full(Bytes::from("Bad Gateway"));
                                        return Ok((
                                            Response::builder().status(502).body(body).unwrap(),
                                            target_url,
                                            route_scripts.clone(),
                                        ));
                                    }
                                };

                            let Some(raw_bytes) =
                                inflate_capped(&body_bytes, &encoding, MAX_HTML_REWRITE_SIZE)
                            else {
                                let body = full(body_bytes);
                                return Ok((
                                    Response::from_parts(parts, body),
                                    target_url,
                                    route_scripts.clone(),
                                ));
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
                                parts.headers.insert(
                                    hyper::header::CONTENT_LENGTH,
                                    HeaderValue::from(raw_bytes.len()),
                                );
                                let body = full(raw_bytes);
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
                            parts.headers.insert(
                                hyper::header::CONTENT_LENGTH,
                                HeaderValue::from(rewritten_bytes.len()),
                            );
                            let boxed = full(rewritten_bytes);
                            return Ok((
                                Response::from_parts(parts, boxed),
                                target_url,
                                route_scripts.clone(),
                            ));
                        }
                    }

                    let (parts, body) = response.into_parts();
                    let boxed = body.map_err(BoxError::from).boxed();
                    Ok((
                        Response::from_parts(parts, boxed),
                        target_url,
                        route_scripts,
                    ))
                }
                Err(crate::upstream::SendError::BadUri(e)) => {
                    tracing::warn!(
                        "Invalid URI from Lua hook or target URL: {}: {}",
                        target_url,
                        e
                    );
                    let body = full(Bytes::from("Bad Gateway"));
                    Ok((
                        Response::builder().status(502).body(body).unwrap(),
                        target_url,
                        route_scripts,
                    ))
                }
                Err(crate::upstream::SendError::Upstream(e)) => {
                    // A failure caused by the inbound body — over the size
                    // limit, or the client aborting / resetting its upload —
                    // is the client's fault, not the backend's: the backend
                    // never saw a completed request. Do not count it against
                    // the circuit breaker, or a client that starts uploads
                    // and drops them could trip a healthy backend offline.
                    if !is_client_body_error(&e) {
                        circuit_breaker.record_failure(&base_url);
                    }
                    tracing::error!(
                        "Backend request failed: {} (target: {})",
                        error_chain(&e),
                        target_url
                    );
                    Ok((backend_error_response(&e), target_url, route_scripts))
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
                // The circuit breaker is keyed by the target's URL as written,
                // which is what `base_url` below records failures under.
                let available = |url: &str| circuit_breaker.is_available(url);
                // One resolution — target, app and auth from the same entry;
                // it also wakes an app asleep, holding this request.
                if let Some(crate::app::AppTarget {
                    target,
                    standby,
                    app: served_app,
                    auth,
                    compress,
                    open,
                }) = manager.resolve_app_request(h, &available).await
                {
                    if let (Some(open), Some(ip)) =
                        (&open, crate::edge::client_ip(req.extensions()))
                    {
                        open.note_visitor(ip);
                    }
                    // App domains are routed here, not through `config.rules`
                    // (`sync_routes` prunes static rules for them), so a
                    // route's `@auth` can never cover an app. `[auth]` in
                    // app.infos is where an app declares its own.
                    if let Some(auth) = auth {
                        if auth.requires_auth(&request_match_path(&req)) {
                            if let Some(denied) = verify_basic_auth(&req, &auth.users).await {
                                tracing::debug!(
                                    "Basic auth failed for app {} {}",
                                    h,
                                    req.uri().path()
                                );
                                return Ok((denied, String::new(), vec![]));
                            }
                        }
                        if let Some(denied) =
                            app_forward_auth(&auth, &mut req, &client, config).await
                        {
                            return Ok((denied, String::new(), vec![]));
                        }
                    }
                    let base_url = target.url.to_string();
                    let target_url = app_target_url(&target.url, req.uri());

                    // Global on_response runs for apps too (they have no
                    // route scripts); its Lua view is kept only if it will.
                    #[cfg(feature = "scripting")]
                    let lua_resp_view: Option<LuaRequest> = match lua_engine {
                        Some(ref engine) if engine.has_on_response() => {
                            Some(build_lua_request(&req))
                        }
                        _ => None,
                    };

                    // A retry goes to the app's other running slot (a
                    // blue/green deploy in progress, or draining), or for a
                    // cluster-pushed domain to another of its instances.
                    let elsewhere = match served_app {
                        Some(_) => standby.is_some(),
                        None => manager.external_routes.instances(h) > 1,
                    };
                    let retries = if elsewhere {
                        config.upstream.retries
                    } else {
                        0
                    };
                    let retry_uri = (retries > 0).then(|| req.uri().clone());

                    let (mut parts, body) = req.into_parts();
                    parts.extensions = http::Extensions::new();

                    // Same hygiene as the route path: hop-by-hop headers never
                    // cross (the client's went at the door; this catches any a
                    // script added).
                    crate::proxy_headers::strip_hop_by_hop(&mut parts.headers);
                    // HTTP/2 browsers split cookies across multiple `cookie`
                    // fields; join them before forwarding to the HTTP/1.1
                    // upstream so servers that read only the first Cookie header
                    // (redbean) see them all. This app-managed path is what the
                    // proxy-deployed redbean apps (e.g. db.solisoft.test) use.
                    crate::proxy_headers::coalesce_cookies(&mut parts.headers);

                    // X-Forwarded-* / X-Real-IP: set at the door from the
                    // proxy's own view (handle_request_inner).
                    let mut standby = standby;
                    let mut failed_over = false;
                    let next = |tried: &[String], failure: crate::upstream::retry::Failure| {
                        use crate::upstream::retry::Failure;
                        // The live slot failed outright: fail the app over now
                        // rather than after the next request fails too.
                        if !failed_over && matches!(failure, Failure::Connect | Failure::Error) {
                            if let Some(app) = &served_app {
                                failed_over = true;
                                manager.trigger_async_failover(app.to_string());
                            }
                        }
                        let uri = retry_uri.as_ref()?;
                        let untried = |url: &str| !tried.iter().any(|t| t == url);
                        // `is_available` is asked once per candidate: on a
                        // half-open breaker the first call takes the probe
                        // permit and a second says no — the pushed instance
                        // `pick` had just cleared was then dropped.
                        let next = match standby.take() {
                            Some(t) => Some(t).filter(|t| {
                                untried(t.url.as_str())
                                    && circuit_breaker.is_available(t.url.as_str())
                            }),
                            None if served_app.is_none() => {
                                // `pick` falls back to an instance nobody
                                // cleared; only the one the predicate passed
                                // will do.
                                let cleared = parking_lot::Mutex::new(None::<String>);
                                manager
                                    .external_routes
                                    .pick(h, &|url| {
                                        let ok = untried(url) && circuit_breaker.is_available(url);
                                        if ok {
                                            *cleared.lock() = Some(url.to_string());
                                        }
                                        ok
                                    })
                                    .filter(|t| cleared.lock().as_deref() == Some(t.url.as_str()))
                            }
                            None => None,
                        }?;
                        Some(crate::upstream::Attempt {
                            target_url: app_target_url(&next.url, uri),
                            base_url: next.url.to_string(),
                            client: None,
                        })
                    };
                    let mut attempt = crate::upstream::Attempt {
                        target_url,
                        base_url,
                        client: None,
                    };
                    let sent = crate::upstream::retry::send(
                        crate::upstream::retry::Exchange {
                            shared: &client,
                            breaker: circuit_breaker,
                            retries,
                            retry_on: &config.upstream.retry_on,
                            try_duration: config.upstream.try_duration,
                            max_body: config.limits.max_request_size,
                        },
                        parts,
                        body,
                        &mut attempt,
                        |parts, uri| parts.uri = uri,
                        next,
                    )
                    .await;
                    let crate::upstream::Attempt {
                        target_url,
                        base_url,
                        ..
                    } = attempt;

                    match sent {
                        Ok(mut response) => {
                            // Hop-by-hop headers must not be relayed (see the
                            // route path above).
                            crate::proxy_headers::strip_hop_by_hop(response.headers_mut());
                            crate::response::mark_upstream(&mut response, compress);

                            let status_code = response.status().as_u16();
                            if circuit_breaker.is_failure_status(status_code) {
                                circuit_breaker.record_failure(&base_url);
                            } else {
                                circuit_breaker.record_success(&base_url);
                            }

                            #[cfg(feature = "scripting")]
                            if let (Some(ref engine), Some(lua_req)) = (lua_engine, &lua_resp_view)
                            {
                                if let Some(mods) = lua_response_mods(
                                    engine,
                                    lua_req,
                                    &[],
                                    status_code,
                                    response.headers(),
                                ) {
                                    return Ok((
                                        hold_open(apply_response_mods(response, mods), open),
                                        target_url,
                                        vec![],
                                    ));
                                }
                            }

                            let (parts, body) = response.into_parts();
                            let boxed = body.map_err(BoxError::from).boxed();
                            return Ok((
                                hold_open(Response::from_parts(parts, boxed), open),
                                target_url,
                                vec![],
                            ));
                        }
                        Err(crate::upstream::SendError::BadUri(e)) => {
                            tracing::warn!(
                                "Invalid URI in app-managed path: {}: {}",
                                target_url,
                                e
                            );
                            let body = full(Bytes::from("Bad Gateway"));
                            return Ok((
                                Response::builder().status(502).body(body).unwrap(),
                                target_url,
                                vec![],
                            ));
                        }
                        Err(crate::upstream::SendError::Upstream(e)) => {
                            // A body-limit rejection or an aborted upload is
                            // client-caused; the backend never saw a failed
                            // request, so skip both the failure count and the
                            // async failover — otherwise a client could trip a
                            // healthy app offline.
                            let body_limit = is_client_body_error(&e);
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
                            if let (false, false, Some(app_name)) =
                                (body_limit, failed_over, served_app)
                            {
                                manager.trigger_async_failover(app_name.to_string());
                            }
                            return Ok((backend_error_response(&e), target_url, vec![]));
                        }
                    }
                }
            }

            let _ = lua_engine;
            tracing::warn!("Returning 421 Misdirected Request - no route found for host, app_manager available: {}", app_manager_available);
            let body = full(Bytes::from("Misdirected Request"));
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
enum UrlResolution<'a> {
    /// Domain: append full request path
    AppendPath,
    /// DomainPath, Prefix: strip prefix, append suffix
    StripPrefix(&'a str),
    /// Exact, Default: use target URL as-is (the query string is kept).
    /// `default` appended the path until 0.8.0 (d942bb5), which switched it
    /// here; the README documents the current behaviour.
    Identity,
    /// Regex: substitute the pattern's capture groups (`$1`, `${name}`) into
    /// the target's path and query
    Regex(&'a crate::config::RegexMatcher),
}

/// A matched routing rule with all the info needed to resolve a target URL
struct MatchedRoute<'a> {
    targets: &'a [crate::config::Target],
    from_domain_rule: bool,
    resolution: UrlResolution<'a>,
    // Borrowed from the rule: a match used to clone the scripts, every
    // Basic-auth account (two Strings each) and the `@noauth` list, per request.
    route_scripts: &'a [String],
    auth: &'a [crate::auth::BasicAuth],
    auth_exempt: &'a [String],
    forward_auth: Option<&'a crate::forward_auth::ForwardAuth>,
    load_balancing: &'a crate::config::LoadBalancingStrategy,
    host: String,
    /// Index into `config.rules` — used for independent per-route LB counters.
    rule_idx: usize,
}

impl<'a> MatchedRoute<'a> {
    /// Whether this request must present Basic Auth credentials.
    ///
    /// False when the rule has no `@auth` entries at all, and false for the
    /// `@noauth` carve-outs on a protected rule — the escape hatch for
    /// machine-to-machine callers (a Stripe webhook, a health probe) that
    /// cannot send a password. `path` is the raw request path, matched before
    /// any prefix stripping, so operators write the URL they actually see.
    fn requires_auth(&self, path: &str) -> bool {
        !self.auth.is_empty() && !crate::config::path_is_auth_exempt(self.auth_exempt, path)
    }

    /// Run this rule's `@auth`, then its `@forward_auth`: both must pass, and
    /// a `@noauth` path skips both. `None` lets the request through.
    async fn authorize<B: Send>(
        &self,
        req: &mut Request<B>,
        client: &ProxyClient,
        config: &crate::config::Config,
    ) -> Option<Response<BoxBody>> {
        let (basic, exempt) = {
            let path = request_match_path(req);
            (
                self.requires_auth(&path),
                crate::config::path_is_auth_exempt(self.auth_exempt, &path),
            )
        };
        if basic {
            let denied = verify_basic_auth_headers(req.headers(), self.auth).await;
            if denied.is_some() {
                return denied;
            }
        }
        let forward_auth = self.forward_auth?;
        let send_authorization = self.auth.is_empty();
        crate::forward_auth::gate(
            client,
            forward_auth,
            &config.forward_auth,
            req,
            exempt,
            send_authorization,
        )
        .await
    }

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

/// Append `suffix` — a request path, or what is left of one once a route
/// prefix was stripped — to `base`, always as a *path*.
///
/// Plain concatenation is not that. A `redirect://` target has an empty path
/// (`redirect://new.example`, non-special schemes get no implicit `/`), so
/// `example.com/old/* -> redirect://new.example` plus `/old/.evil.com/` used to
/// produce `redirect://new.example.evil.com/` — the suffix extended the
/// *authority* and the 301 sent visitors to a host the operator never named.
/// The same concatenation turned `http://h/v2` + `x` into `http://h/v2x`. The
/// rule here: exactly one `/` between base and suffix, whatever either side
/// ends or starts with. An empty suffix (an empty or authority-form request
/// path) leaves `base` alone instead of panicking on `&path[1..]`.
fn push_joined_path(out: &mut String, base: &str, suffix: &str) {
    out.push_str(base);
    if suffix.is_empty() {
        return;
    }
    match (base.ends_with('/'), suffix.strip_prefix('/')) {
        (true, Some(rest)) => out.push_str(rest),
        (true, None) | (false, Some(_)) => out.push_str(suffix),
        (false, None) => {
            out.push('/');
            out.push_str(suffix);
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
    // A `unix:` target's path names its socket: requests to it are built on
    // a placeholder origin (see `crate::upstream::routing_url`).
    let routing = crate::upstream::routing_url(&target.url);
    let base = routing.as_str();
    let query = query.filter(|q| !q.is_empty());
    let mut out = String::with_capacity(base.len() + path.len() + query.map_or(0, |q| q.len() + 1));
    match resolution {
        UrlResolution::AppendPath => push_joined_path(&mut out, base, path),
        UrlResolution::StripPrefix(prefix) => {
            // `path` is either under the prefix or the prefix minus its
            // trailing slash (`/db` for `/db/`), which leaves nothing to add.
            let suffix = path.strip_prefix(*prefix).unwrap_or("");
            push_joined_path(&mut out, base, suffix)
        }
        UrlResolution::Identity => out.push_str(base),
        UrlResolution::Regex(rm) => {
            // Captures go into the path and query only: the scheme and
            // authority are copied verbatim, so a capture can never change
            // which host the request is sent to.
            let head = &routing[..url::Position::BeforePath];
            let tail = &base[head.len()..];
            out.push_str(head);
            match tail
                .contains('$')
                .then(|| rm.regex.captures(path))
                .flatten()
            {
                Some(caps) => crate::config::expand_captures(tail, &caps, &mut out),
                None => out.push_str(tail),
            }
        }
    }
    if let Some(q) = query {
        // A target that carries its own query string gets the client's
        // appended to it, not a second `?`.
        out.push(if out.contains('?') { '&' } else { '?' });
        out.push_str(q);
    }

    // Defence in depth for the join above: whatever was appended must not
    // have changed the target's authority. The scheme://host:port prefix is
    // still there by construction; the byte after it must end the authority.
    let authority = &routing[..url::Position::AfterPort];
    if !matches!(
        out.as_bytes().get(authority.len()),
        None | Some(b'/' | b'?')
    ) {
        tracing::warn!(
            "Resolved URL {:?} would change the authority of target {}; using the bare target",
            out,
            base
        );
        return base.to_owned();
    }
    out
}

/// Build the 301 response for a `redirect://` rule target. The resolved
/// target already carries the request's path/query appended by
/// `resolve_target_url`; only the scheme is swapped to https. Redirect rules
/// always point at an https destination — the proxy itself only serves
/// redirects for domains it terminates TLS for.
/// The redirect for a request to a host an app lists in `redirect_from`:
/// `https://<its domain><path>?<query>`, with the app's `redirect_status`.
/// `None` for any other host.
fn app_redirect<B>(
    req: &Request<B>,
    manager: &AppManager,
    config: &crate::config::Config,
) -> Option<Response<BoxBody>> {
    let raw_host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host())?;
    let (host, _) = parse_host_port(raw_host)?;
    let route =
        manager.serving_route(&host.to_ascii_lowercase(), static_route(req, &config.rules))?;
    let redirect = route.redirect_to.as_ref()?;
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let location = format!("https://{}{}{}", redirect.host, req.uri().path(), query);
    let status = hyper::StatusCode::from_u16(redirect.status)
        .unwrap_or(hyper::StatusCode::MOVED_PERMANENTLY);
    Some(match HeaderValue::from_str(&location) {
        Ok(loc) => Response::builder()
            .status(status)
            .header(hyper::header::LOCATION, loc)
            .body(full(Bytes::from(
                status.canonical_reason().unwrap_or("Moved").to_string(),
            )))
            .unwrap(),
        Err(_) => Response::builder()
            .status(400)
            .body(full(Bytes::from("Bad Request")))
            .unwrap(),
    })
}

fn build_redirect_response(target_url: &str) -> Response<BoxBody> {
    let rest = target_url.strip_prefix("redirect://").unwrap_or(target_url);
    let location = format!("https://{}", rest);
    match HeaderValue::from_str(&location) {
        Ok(loc) => Response::builder()
            .status(301)
            .header(hyper::header::LOCATION, loc)
            .body(full(Bytes::from("Moved Permanently")))
            .unwrap(),
        // A request path with bytes invalid in a header value cannot be
        // reflected into Location; reject rather than emit a broken redirect.
        Err(_) => Response::builder()
            .status(400)
            .body(full(Bytes::from("Bad Request")))
            .unwrap(),
    }
}

/// What the static rules make of `req`, for
/// [`AppManager::serving_route`](crate::app::AppManager::serving_route): the
/// same match routing does, so that what follows the serving app (its error
/// pages, its maintenance flag) follows the same precedence.
pub(crate) fn static_route<B>(
    req: &Request<B>,
    rules: &[crate::config::ProxyRule],
) -> crate::app::StaticRoute {
    match find_matching_rule(req, rules) {
        None => crate::app::StaticRoute::None,
        Some(m) if m.from_domain_rule && matches!(m.resolution, UrlResolution::AppendPath) => {
            crate::app::StaticRoute::WholeDomain
        }
        Some(_) => crate::app::StaticRoute::Other,
    }
}

/// Pure routing: find which rule matches the request.
/// Host matching is case-insensitive; the first matching rule wins.
fn find_matching_rule<'a, B>(
    req: &Request<B>,
    rules: &'a [crate::config::ProxyRule],
) -> Option<MatchedRoute<'a>> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()))?;

    // Rules match the canonical form of the path (`canonical_match_path`):
    // `//admin/x` and `/%61dmin/x` must hit an `/admin/*` rule exactly as
    // `/admin/x` does, not slip past it to a broader rule without its @auth.
    let match_path = request_match_path(req);
    let path: &str = &match_path;
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
                    route_scripts: &rule.scripts,
                    auth: &rule.auth,
                    auth_exempt: &rule.auth_exempt,
                    forward_auth: rule.forward_auth.as_ref(),
                    load_balancing: &rule.load_balancing,
                    host: domain.clone(),
                    rule_idx: i,
                });
            }
            crate::config::RuleMatcher::DomainPath(domain, path_prefix)
                if host_eq(domain.as_str(), host.as_str()) && !rule.targets.is_empty() =>
            {
                let matches = path.starts_with(path_prefix.as_str())
                    || (path_prefix.ends_with('/') && path == path_prefix.trim_end_matches('/'));
                if matches {
                    return Some(MatchedRoute {
                        targets: &rule.targets,
                        from_domain_rule: true,
                        resolution: UrlResolution::StripPrefix(path_prefix.as_str()),
                        route_scripts: &rule.scripts,
                        auth: &rule.auth,
                        auth_exempt: &rule.auth_exempt,
                        forward_auth: rule.forward_auth.as_ref(),
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
                    route_scripts: &rule.scripts,
                    auth: &rule.auth,
                    auth_exempt: &rule.auth_exempt,
                    forward_auth: rule.forward_auth.as_ref(),
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
                        resolution: UrlResolution::StripPrefix(prefix.as_str()),
                        route_scripts: &rule.scripts,
                        auth: &rule.auth,
                        auth_exempt: &rule.auth_exempt,
                        forward_auth: rule.forward_auth.as_ref(),
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
                    resolution: UrlResolution::Regex(rm),
                    route_scripts: &rule.scripts,
                    auth: &rule.auth,
                    auth_exempt: &rule.auth_exempt,
                    forward_auth: rule.forward_auth.as_ref(),
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
                    route_scripts: &rule.scripts,
                    auth: &rule.auth,
                    auth_exempt: &rule.auth_exempt,
                    forward_auth: rule.forward_auth.as_ref(),
                    load_balancing: &rule.load_balancing,
                    host: host.to_string(),
                    rule_idx: i,
                });
            }
        }
    }

    None
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Stride for the weighted schedule: the integer coprime with `total`
/// closest to `total / φ`. Stepping through `0..total` by it visits every
/// slot once per cycle (so each target gets exactly its weight) and spreads
/// consecutive picks across the targets' ranges instead of sending a run of
/// `weight` requests to each in turn — for 70:30 (reduced to 7:3 first)
/// the sequence is A B A A B A A B A A, the same as nginx's smooth weighted
/// round-robin, without a lock or per-rule mutable state.
fn weighted_stride(total: usize) -> usize {
    if total <= 2 {
        return 1;
    }
    let ideal = (total as f64 * 0.618_033_988_75).round() as usize;
    (0..total)
        .flat_map(|d| [ideal.saturating_add(d), ideal.saturating_sub(d)])
        .find(|&c| c > 0 && c < total && gcd(c, total) == 1)
        .unwrap_or(1)
}

/// Select a target based on the load balancing strategy.
/// Returns (resolved_url, base_url) for logging and circuit breaker tracking.
///
/// Candidates are checked against the circuit breaker by `&str`; only the
/// chosen target's URL is copied (this used to allocate a `String` for every
/// candidate examined).
fn select_target(
    route: &MatchedRoute<'_>,
    path: &str,
    query: Option<&str>,
    circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
    load_balancer: &LoadBalancerState,
) -> Option<(String, String)> {
    let targets = route.targets;
    let num_targets = targets.len();
    if num_targets == 0 {
        return None;
    }
    let pick = |target: &crate::config::Target| {
        let resolved = resolve_target_url(target, path, query, &route.resolution);
        (resolved, target.url.as_str().to_owned())
    };
    let available =
        |target: &crate::config::Target| circuit_breaker.is_available(target.url.as_str());

    match route.load_balancing {
        crate::config::LoadBalancingStrategy::Failover => {
            // Failover: use first available target (circuit breaker aware)
            targets.iter().find(|t| available(t)).map(pick)
        }
        crate::config::LoadBalancingStrategy::RoundRobin => {
            // Round-robin: cycle through all targets, skip unhealthy ones
            let start_idx = load_balancer.select_index(route.rule_idx, num_targets);
            (0..num_targets)
                .map(|i| &targets[(start_idx + i) % num_targets])
                .find(|t| available(t))
                .map(pick)
        }
        crate::config::LoadBalancingStrategy::Weighted => {
            // Weighted: slot `k` of each cycle of `total` requests maps, via
            // the stride permutation, onto the target whose cumulative weight
            // range holds it. Weight 0 means drained: never chosen while a
            // weighted target is available.
            // Weights are reduced by their common divisor first, so 70:30
            // cycles like 7:3 — a short cycle interleaves more evenly.
            let divisor = targets.iter().fold(0, |g, t| gcd(g, t.weight as usize));
            if divisor > 0 {
                let total: usize = targets.iter().map(|t| t.weight as usize / divisor).sum();
                let k = load_balancer.bump(route.rule_idx) % total;
                let slot = ((k as u64 * weighted_stride(total) as u64) % total as u64) as usize;
                let mut cumulative = 0;
                let chosen = targets
                    .iter()
                    .position(|t| {
                        cumulative += t.weight as usize / divisor;
                        slot < cumulative
                    })
                    .unwrap_or(0);
                // The chosen target, or — if its breaker is open — the next
                // weighted one along that is available.
                if let Some(target) = (0..num_targets)
                    .map(|i| &targets[(chosen + i) % num_targets])
                    .find(|t| t.weight > 0 && available(t))
                {
                    return Some(pick(target));
                }
            }

            // Every weighted target is down (or all weights are zero): any
            // available target, drained ones included, beats a 503.
            targets.iter().find(|t| available(t)).map(pick)
        }
    }
}

/// Where a failed attempt on `route` is retried: the next target after the
/// last one that failed, in rule order (round-robin and failover alike walk
/// that order), that has not been tried yet, is available (circuit breaker,
/// health checks) and can be proxied to. A drained `weight:0` target only
/// when no other is left.
fn next_target<'a>(
    route: &MatchedRoute<'_>,
    rule: &'a crate::config::ProxyRule,
    path: &str,
    query: Option<&str>,
    circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
    tried: &[String],
) -> Option<crate::upstream::Attempt<'a>> {
    let targets = route.targets;
    let n = targets.len();
    let start = tried
        .last()
        .and_then(|last| targets.iter().position(|t| t.url.as_str() == last))
        .map_or(0, |i| i + 1);
    let candidates = (0..n).map(|k| &targets[(start + k) % n]).filter(|t| {
        let url = t.url.as_str();
        !tried.iter().any(|u| u == url)
            && !url.starts_with("redirect://")
            && validate_proxy_target_url(url)
    });
    // Two disjoint passes, so no target's half-open probe permit is claimed
    // by a check whose answer is then ignored.
    let chosen = candidates
        .clone()
        .filter(|t| t.weight > 0)
        .find(|t| circuit_breaker.is_available(t.url.as_str()))
        .or_else(|| {
            candidates
                .filter(|t| t.weight == 0)
                .find(|t| circuit_breaker.is_available(t.url.as_str()))
        })?;
    let target_url = resolve_target_url(chosen, path, query, &route.resolution);
    let base_url = chosen.url.as_str();
    Some(crate::upstream::Attempt {
        client: rule.upstream.client_for(Some(base_url), &target_url),
        target_url,
        base_url: base_url.to_string(),
    })
}

#[cfg(test)]
/// Backward-compatible wrapper: returns (target_url, from_domain_rule, matched_prefix, route_scripts)
fn find_target<B>(
    req: &Request<B>,
    rules: &[crate::config::ProxyRule],
) -> Option<(String, bool, Option<String>, Vec<String>)> {
    let route = find_matching_rule(req, rules)?;
    // A prefix is stripped from the form it was matched on (see
    // handle_regular_request); other resolutions forward the path as sent.
    let match_path = request_match_path(req);
    let path = match route.resolution {
        UrlResolution::StripPrefix(_) => &*match_path,
        _ => req.uri().path(),
    };
    let query = req.uri().query();
    let target = route.targets.first()?;
    let resolved = resolve_target_url(target, path, query, &route.resolution);
    let matched_prefix = route.matched_prefix(false);
    Some((
        resolved,
        route.from_domain_rule,
        matched_prefix,
        route.route_scripts.to_vec(),
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
    fn ws_upgrade_headers_with_bad_bytes_are_refused_not_panicked_on() {
        let ok = "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: abc=\r\n\
                  sec-websocket-protocol: chat\r\n\r\n";
        let (accept, proto) = ws_upgrade_response_headers(ok).unwrap();
        assert_eq!(accept, "abc=");
        assert_eq!(proto.unwrap(), "chat");
        // A backend byte that is not valid in a header (a control character,
        // a lone CR, DEL) makes the upgrade fail cleanly.
        let bad = "HTTP/1.1 101 x\r\nSec-WebSocket-Accept: a\rb\x01\r\n\r\n";
        assert!(ws_upgrade_response_headers(bad).is_none());
        let del = "HTTP/1.1 101 x\r\nSec-WebSocket-Protocol: a\x7fb\r\n\r\n";
        assert!(ws_upgrade_response_headers(del).is_none());
        // No accept header: an empty value, as before.
        let (accept, proto) = ws_upgrade_response_headers("HTTP/1.1 101 x\r\n\r\n").unwrap();
        assert_eq!(accept, "");
        assert!(proto.is_none());
    }

    #[test]
    fn gzip_decode_and_rewrite_streaming() {
        let html = r#"<a href="/x"><img src="/y"><form action="/z"></form>"#;
        let compressed = gzip(html.as_bytes());
        let inner = empty();
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

    fn target(url: &str) -> crate::config::Target {
        crate::config::Target {
            url: url::Url::parse(url).unwrap(),
            weight: 100,
        }
    }

    /// Regression: a prefix rule pointing at a `redirect://` target has an
    /// empty target path, and the stripped suffix used to be glued straight
    /// onto the authority — `/old/.evil.com/` redirected to
    /// `https://new.example.evil.com/`.
    #[test]
    fn redirect_prefix_suffix_cannot_extend_the_authority() {
        let t = target("redirect://new.example");
        let strip = UrlResolution::StripPrefix("/old/");
        for (path, want) in [
            ("/old/.evil.com/", "redirect://new.example/.evil.com/"),
            ("/old/@evil.com", "redirect://new.example/@evil.com"),
            ("/old/:8080/x", "redirect://new.example/:8080/x"),
            ("/old/page", "redirect://new.example/page"),
            ("/old", "redirect://new.example"),
            ("/old/", "redirect://new.example"),
        ] {
            let resolved = resolve_target_url(&t, path, None, &strip);
            assert_eq!(resolved, want, "path {path:?}");
            let location = build_redirect_response(&resolved)
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let host = url::Url::parse(&location)
                .unwrap()
                .host_str()
                .unwrap()
                .to_string();
            assert_eq!(host, "new.example", "path {path:?} -> {location}");
        }
        // Whole-domain redirect rules join the same way.
        assert_eq!(
            resolve_target_url(&t, "/x.evil.com", None, &UrlResolution::AppendPath),
            "redirect://new.example/x.evil.com"
        );
    }

    #[test]
    fn resolve_target_url_joins_with_exactly_one_slash() {
        let strip = UrlResolution::StripPrefix("/api/");
        assert_eq!(
            resolve_target_url(&target("http://h:8080"), "/api/users", None, &strip),
            "http://h:8080/users"
        );
        // A target with a path of its own no longer gets the suffix glued on.
        assert_eq!(
            resolve_target_url(&target("http://h/v2"), "/api/users", None, &strip),
            "http://h/v2/users"
        );
        assert_eq!(
            resolve_target_url(&target("http://h/v2/"), "/api/users", None, &strip),
            "http://h/v2/users"
        );
        let strip_no_slash = UrlResolution::StripPrefix("/api");
        assert_eq!(
            resolve_target_url(&target("http://h/"), "/api/users", None, &strip_no_slash),
            "http://h/users"
        );
    }

    /// An empty path (authority-form, a malformed request) must not panic.
    #[test]
    fn resolve_target_url_handles_an_empty_path() {
        assert_eq!(
            resolve_target_url(&target("http://h/"), "", None, &UrlResolution::AppendPath),
            "http://h/"
        );
        assert_eq!(
            resolve_target_url(
                &target("http://h/"),
                "",
                Some("a=1"),
                &UrlResolution::StripPrefix("/x/")
            ),
            "http://h/?a=1"
        );
    }

    #[test]
    fn resolve_target_url_appends_query_to_a_target_query() {
        assert_eq!(
            resolve_target_url(
                &target("http://h/x?static=1"),
                "/ignored",
                Some("q=2"),
                &UrlResolution::Identity
            ),
            "http://h/x?static=1&q=2"
        );
    }

    #[test]
    fn redirect_response_rejects_bad_header_bytes() {
        let resp = build_redirect_response("redirect://bonfire-app.pro/\u{7f}");
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn dot_segment_traversal_rejected_before_rule_matching() {
        // Literal, percent-encoded, mixed-case and encoded-slash variants.
        for p in [
            "/a/../b",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a/.%2e/b",
            "/a/./b",
            "/a/%2e/b",
            "/a%2fb",
            "/a%2Fb",
            "/api/..",
            "/api/../admin/users",
            "/.",
            "/..",
            "..",
            // Servlet-container path parameters and backslash separators:
            // Tomcat strips `;x` and IIS treats `\\` as `/` before normalising.
            "/api/..;/admin/users",
            "/api/.;/admin",
            "/api/%2e%2e;/admin/users",
            "/api/..%3b/admin/users",
            "/api/..\\admin",
            "/api\\..\\admin",
            "/api/..%5cadmin",
            "/api/..%5Cadmin",
        ] {
            assert!(
                has_dot_segment_or_encoded_slash(p, false),
                "should reject {p:?}"
            );
        }
    }

    #[test]
    fn dot_segment_check_accepts_legitimate_paths() {
        for p in [
            "/",
            "/a/..b",
            "/a/b..",
            "/a/...",
            "/.well-known/acme-challenge/tok",
            "/a/b.c",
            "/a/b/",
            "/a%20b",
            "/a/%2ex",
            "/a/x%2e",
            "/a/x;v=1/b",
            "/a/x..;/b",
            "",
        ] {
            assert!(
                !has_dot_segment_or_encoded_slash(p, false),
                "should accept {p:?}"
            );
        }
    }

    /// With `allow_encoded_slash`, `%2F` inside a segment is data (GitLab's
    /// `group%2Fproject`), but it still counts as a segment boundary for the
    /// dot-segment scan, so it cannot be used to spell a traversal.
    #[test]
    fn encoded_slash_opt_in_keeps_dot_segments_rejected() {
        for p in [
            "/api/v4/projects/group%2Fproject/repository/branches",
            "/a%2fb",
            "/o/redirect_uri=https:%2F%2Fexample.com%2Fcb",
        ] {
            assert!(
                !has_dot_segment_or_encoded_slash(p, true),
                "should accept {p:?}"
            );
            assert!(
                has_dot_segment_or_encoded_slash(p, false),
                "default rejects {p:?}"
            );
        }
        for p in [
            "/api/..%2Fadmin/users",
            "/api%2F..%2Fadmin",
            "/api%2F../admin",
            "/api/%2e%2e%2Fadmin",
            "/api/.%2Fadmin",
            "/api%2f..",
        ] {
            assert!(
                has_dot_segment_or_encoded_slash(p, true),
                "should reject {p:?}"
            );
        }
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
            route_scripts: &[],
            auth: &[],
            auth_exempt: &[],
            forward_auth: None,
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

    fn weighted_route<'a>(
        targets: &'a [crate::config::Target],
        strategy: &'a crate::config::LoadBalancingStrategy,
    ) -> MatchedRoute<'a> {
        MatchedRoute {
            targets,
            from_domain_rule: false,
            resolution: UrlResolution::AppendPath,
            route_scripts: &[],
            auth: &[],
            auth_exempt: &[],
            forward_auth: None,
            load_balancing: strategy,
            host: "example.com".to_string(),
            rule_idx: 0,
        }
    }

    fn weighted(url: &str, weight: u8) -> crate::config::Target {
        crate::config::Target {
            url: url::Url::parse(url).unwrap(),
            weight,
        }
    }

    /// `weight:70` / `weight:30` must split traffic 70/30 exactly over each
    /// cycle, and interleave rather than send 70 in a row to one target.
    #[test]
    fn weighted_selection_follows_the_weights_and_interleaves() {
        let targets = vec![
            weighted("http://heavy:8080", 70),
            weighted("http://light:8080", 30),
        ];
        let strategy = crate::config::LoadBalancingStrategy::Weighted;
        let route = weighted_route(&targets, &strategy);
        let cb = crate::circuit_breaker::CircuitBreaker::new(
            crate::circuit_breaker::CircuitBreakerConfig::default(),
        );
        let lb = LoadBalancerState::new(1);
        let picks: Vec<bool> = (0..1000)
            .map(|_| select_target(&route, "/x", None, &cb, &lb).unwrap().1 == "http://heavy:8080/")
            .collect();
        assert_eq!(picks.iter().filter(|h| **h).count(), 700);
        // Smoothness: no run of the heavy target longer than 3, and every
        // window of 10 holds exactly 3 light picks (7:3 reduces to a cycle of
        // 10 at the stride used).
        let longest_run = picks.split(|h| !*h).map(|run| run.len()).max().unwrap();
        assert!(longest_run <= 3, "longest run {longest_run}");
        for window in picks.chunks(100) {
            assert_eq!(window.iter().filter(|h| !**h).count(), 30);
        }

        // Three targets, uneven weights.
        let targets = vec![
            weighted("http://a:1", 5),
            weighted("http://b:1", 3),
            weighted("http://c:1", 2),
        ];
        let route = weighted_route(&targets, &strategy);
        let lb = LoadBalancerState::new(1);
        let mut counts = std::collections::HashMap::new();
        for _ in 0..1000 {
            let (_, base) = select_target(&route, "/", None, &cb, &lb).unwrap();
            *counts.entry(base).or_insert(0) += 1;
        }
        assert_eq!(counts["http://a:1/"], 500);
        assert_eq!(counts["http://b:1/"], 300);
        assert_eq!(counts["http://c:1/"], 200);
    }

    #[test]
    fn weight_zero_drains_a_target() {
        let targets = vec![weighted("http://old:1", 0), weighted("http://new:1", 10)];
        let strategy = crate::config::LoadBalancingStrategy::Weighted;
        let route = weighted_route(&targets, &strategy);
        let cb = crate::circuit_breaker::CircuitBreaker::new(
            crate::circuit_breaker::CircuitBreakerConfig::default(),
        );
        let lb = LoadBalancerState::new(1);
        for _ in 0..50 {
            assert_eq!(
                select_target(&route, "/", None, &cb, &lb).unwrap().1,
                "http://new:1/"
            );
        }
    }

    #[test]
    fn weighted_stride_is_coprime_with_the_total() {
        for total in 1..2000 {
            let s = weighted_stride(total);
            let mut seen = vec![false; total];
            for k in 0..total {
                seen[(k * s) % total] = true;
            }
            assert!(seen.iter().all(|v| *v), "total {total} stride {s}");
        }
    }

    #[test]
    fn regex_target_substitutes_captures_and_keeps_the_query() {
        let rm = crate::config::RegexMatcher::new(r"^/users/(\d+)(?:/(?P<tab>\w+))?$").unwrap();
        let resolution = UrlResolution::Regex(&rm);
        let t = target("http://user-service:8080/users/$1/${tab}");
        assert_eq!(
            resolve_target_url(&t, "/users/42/posts", Some("page=2"), &resolution),
            "http://user-service:8080/users/42/posts?page=2"
        );
        // A group that did not take part expands to nothing.
        assert_eq!(
            resolve_target_url(&t, "/users/7", None, &resolution),
            "http://user-service:8080/users/7/"
        );
        // A target without references is used as-is.
        assert_eq!(
            resolve_target_url(
                &target("http://u:8080/fixed"),
                "/users/7",
                None,
                &resolution
            ),
            "http://u:8080/fixed"
        );
    }

    /// A capture lands in the path, never the authority, whatever the
    /// pattern and target look like.
    #[test]
    fn regex_captures_cannot_change_the_target_host() {
        let rm = crate::config::RegexMatcher::new(r"^/go/(.*)$").unwrap();
        let resolution = UrlResolution::Regex(&rm);
        let t = target("http://backend:8080/$1");
        let resolved = resolve_target_url(&t, "/go/@evil.com/x", None, &resolution);
        assert_eq!(resolved, "http://backend:8080/@evil.com/x");
        assert_eq!(
            url::Url::parse(&resolved).unwrap().host_str(),
            Some("backend")
        );
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
        let who = crate::edge::ClientInfo::direct(peer.ip());
        let out = build_ws_extra_headers(&h, Some(&who), false, "real.example");
        assert_eq!(xff_count(&out), 1, "exactly one X-Forwarded-For line");
        assert_eq!(header_value(&out, "X-Forwarded-For"), Some("9.9.9.9"));
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("http"));
        assert_eq!(header_value(&out, "X-Forwarded-Host"), Some("real.example"));
    }

    #[test]
    fn ws_extra_headers_injects_when_client_sent_none() {
        let h = hyper::HeaderMap::new();
        let peer: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let who = crate::edge::ClientInfo::direct(peer.ip());
        let out = build_ws_extra_headers(&h, Some(&who), true, "api.example");
        assert_eq!(header_value(&out, "X-Forwarded-For"), Some("10.0.0.1"));
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("https"));
        assert_eq!(header_value(&out, "X-Forwarded-Host"), Some("api.example"));
    }

    #[test]
    fn ws_extra_headers_keep_a_trusted_proxys_chain_and_scheme() {
        // As the door leaves them for a request through a trusted proxy.
        let mut h = hyper::HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4, 10.0.0.1".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        let who = crate::edge::ClientInfo {
            ip: "1.2.3.4".parse().unwrap(),
            peer: "10.0.0.1".parse().unwrap(),
            trusted_peer: true,
        };
        let out = build_ws_extra_headers(&h, Some(&who), false, "real.example");
        assert_eq!(xff_count(&out), 1);
        assert_eq!(
            header_value(&out, "X-Forwarded-For"),
            Some("1.2.3.4, 10.0.0.1")
        );
        assert_eq!(header_value(&out, "X-Real-IP"), Some("1.2.3.4"));
        assert_eq!(header_value(&out, "X-Forwarded-Proto"), Some("https"));
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
            min_version: None,
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

    // ---- request hardening ----

    fn rule(matcher: crate::config::RuleMatcher, auth: bool) -> crate::config::ProxyRule {
        crate::config::ProxyRule {
            matcher,
            targets: vec![crate::config::Target {
                url: url::Url::parse("http://127.0.0.1:3000/").unwrap(),
                weight: 100,
            }],
            headers: vec![],
            scripts: vec![],
            auth: if auth {
                vec![crate::auth::BasicAuth {
                    username: "admin".into(),
                    hash: "x".into(),
                }]
            } else {
                vec![]
            },
            auth_exempt: vec![],
            load_balancing: Default::default(),
            forward_auth: None,
            compress: None,
            upstream: Default::default(),
        }
    }

    fn get(path: &str, host: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header("host", host)
            .body(())
            .unwrap()
    }

    #[test]
    fn canonical_path_decodes_unreserved_and_collapses_slashes() {
        assert_eq!(canonical_match_path("/admin/x"), "/admin/x");
        assert!(matches!(canonical_match_path("/admin/x"), Cow::Borrowed(_)));
        assert_eq!(canonical_match_path("//admin/x"), "/admin/x");
        assert_eq!(canonical_match_path("/admin///x"), "/admin/x");
        assert_eq!(canonical_match_path("/%61dmin/x"), "/admin/x");
        assert_eq!(canonical_match_path("/%41%2d%2E%5f%7E9"), "/A-._~9");
        // Reserved characters stay encoded, case is not folded.
        assert_eq!(canonical_match_path("/a%2Fb%3Fc%20d"), "/a%2Fb%3Fc%20d");
        assert_eq!(canonical_match_path("/Admin"), "/Admin");
        // Truncated or non-hex escapes are left alone.
        assert_eq!(canonical_match_path("/a%6"), "/a%6");
        assert_eq!(canonical_match_path("/a%zz"), "/a%zz");
    }

    #[test]
    fn encoded_or_doubled_slash_paths_still_hit_the_protected_rule() {
        use crate::config::RuleMatcher;
        let rules = vec![
            rule(RuleMatcher::Prefix("/admin/".into()), true),
            rule(RuleMatcher::Prefix("/".into()), false),
        ];
        for path in [
            "/admin/x",
            "//admin/x",
            "/%61dmin/x",
            "/%61dmin//x",
            "///admin/x",
        ] {
            let req = get(path, "example.com");
            let m = find_matching_rule(&req, &rules).expect("a rule matches");
            assert_eq!(m.rule_idx, 0, "{path} must match the /admin/ rule");
            assert!(m.requires_auth(&request_match_path(&req)), "{path}");
        }
        let m = find_matching_rule(&get("/public", "example.com"), &rules).unwrap();
        assert_eq!(m.rule_idx, 1);
    }

    #[test]
    fn domain_path_and_exact_rules_match_canonically() {
        use crate::config::RuleMatcher;
        let rules = vec![
            rule(
                RuleMatcher::DomainPath("example.com".into(), "/admin/".into()),
                true,
            ),
            rule(RuleMatcher::Exact("/secret".into()), true),
            rule(RuleMatcher::Domain("example.com".into()), false),
        ];
        let m = find_matching_rule(&get("//%61dmin/users", "example.com"), &rules).unwrap();
        assert_eq!(m.rule_idx, 0);
        let m = find_matching_rule(&get("//%73ecret", "other.com"), &rules).unwrap();
        assert_eq!(m.rule_idx, 1);
    }

    #[test]
    fn strip_prefix_target_is_built_from_the_matched_form() {
        use crate::config::RuleMatcher;
        let rules = vec![rule(RuleMatcher::Prefix("/api/".into()), false)];
        let (url, ..) = find_target(&get("//%61pi/users?x=1", "h"), &rules).unwrap();
        assert_eq!(url, "http://127.0.0.1:3000/users?x=1");
    }

    #[test]
    fn host_port_parser_is_strict() {
        assert_eq!(parse_host_port("example.com"), Some(("example.com", None)));
        assert_eq!(
            parse_host_port("example.com:8443"),
            Some(("example.com", Some("8443")))
        );
        assert_eq!(parse_host_port("[::1]:443"), Some(("[::1]", Some("443"))));
        assert_eq!(parse_host_port("[::1]"), Some(("[::1]", None)));
        for bad in [
            "example.com:@evil.com",
            "example.com@evil.com",
            "example.com:80@evil.com",
            "example.com/evil",
            "example.com:",
            "example.com:99999",
            "example.com:1:2",
            "example.com:+80",
            "",
            ":80",
            "[::1",
            "[nothex]:80",
            "[::1]x",
            "exa mple.com",
        ] {
            assert_eq!(parse_host_port(bad), None, "{bad:?} must be refused");
        }
    }

    #[cfg(feature = "scripting")]
    #[test]
    fn lua_deny_status_is_clamped_not_panicking() {
        assert_eq!(lua_deny_response(403, "no".into()).status(), 403);
        assert_eq!(lua_deny_response(599, String::new()).status(), 599);
        for bad in [0u16, 42, 101, 600, 999, 1000, u16::MAX] {
            assert_eq!(lua_deny_response(bad, String::new()).status(), 500, "{bad}");
        }
    }

    #[test]
    fn malformed_targets_and_hosts_are_refused() {
        let connect = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(())
            .unwrap();
        assert_eq!(reject_malformed_request(&connect).unwrap().status(), 405);

        let authority_form = Request::builder()
            .uri("example.com:80")
            .header("host", "example.com")
            .body(())
            .unwrap();
        assert_eq!(
            reject_malformed_request(&authority_form).unwrap().status(),
            400
        );

        let star = Request::builder()
            .method("OPTIONS")
            .uri("*")
            .body(())
            .unwrap();
        let resp = reject_malformed_request(&star).unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().contains_key("allow"));

        let star_get = Request::builder().uri("*").body(()).unwrap();
        assert_eq!(reject_malformed_request(&star_get).unwrap().status(), 400);

        let two_hosts = Request::builder()
            .uri("/")
            .header("host", "a.example")
            .header("host", "b.example")
            .body(())
            .unwrap();
        assert_eq!(reject_malformed_request(&two_hosts).unwrap().status(), 400);

        let h2_mismatch = Request::builder()
            .version(http::Version::HTTP_2)
            .uri("https://a.example/")
            .header("host", "b.example")
            .body(())
            .unwrap();
        assert_eq!(
            reject_malformed_request(&h2_mismatch).unwrap().status(),
            400
        );

        let h2_match = Request::builder()
            .version(http::Version::HTTP_2)
            .uri("https://a.example/")
            .header("host", "A.example")
            .body(())
            .unwrap();
        assert!(reject_malformed_request(&h2_match).is_none());
        assert!(reject_malformed_request(&get("/x", "a.example")).is_none());

        // Userinfo in the authority (HTTP/2, no Host) or in Host: 400.
        let userinfo = Request::builder()
            .version(http::Version::HTTP_2)
            .uri("https://x@a.example/x")
            .body(())
            .unwrap();
        assert_eq!(reject_malformed_request(&userinfo).unwrap().status(), 400);
        assert_eq!(
            reject_malformed_request(&get("/x", "a.example:@evil.example"))
                .unwrap()
                .status(),
            400
        );
    }

    #[test]
    fn strip_leading_slash_is_total() {
        assert_eq!(strip_leading_slash("/a"), "a");
        assert_eq!(strip_leading_slash(""), "");
        assert_eq!(strip_leading_slash("*"), "*");
    }

    #[test]
    fn ipv6_clients_are_keyed_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(other));
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(client_key(v4), v4);
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(client_key(mapped), v4);
    }

    #[test]
    fn per_ip_limiter_caps_and_releases() {
        let limiter = Arc::new(PerIpLimiter::new(2));
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let g1 = limiter.try_acquire(ip).unwrap();
        let g2 = limiter.try_acquire(ip).unwrap();
        assert!(limiter.try_acquire(ip).is_none(), "third must be refused");
        // Another address has its own budget; a sibling in the same /64 not.
        assert!(limiter
            .try_acquire("198.51.100.2".parse().unwrap())
            .is_some());
        let v6a = limiter.try_acquire("2001:db8::1".parse().unwrap()).unwrap();
        let v6b = limiter.try_acquire("2001:db8::2".parse().unwrap()).unwrap();
        assert!(limiter
            .try_acquire("2001:db8::3".parse().unwrap())
            .is_none());
        drop(g1);
        let g3 = limiter
            .try_acquire(ip)
            .expect("a released slot is reusable");
        drop((g2, g3, v6a, v6b));
        assert_eq!(limiter.tracked(), 0, "idle addresses are forgotten");
    }

    #[test]
    fn inflate_is_capped_against_bombs() {
        use std::io::Write;
        let html = vec![b'a'; 100_000];
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&html).unwrap();
        let deflated = e.finish().unwrap();
        assert!(deflated.len() < 1_000);
        // Under the cap: decoded in full.
        let out = inflate_capped(&deflated, "deflate", 100_000).unwrap();
        assert_eq!(out.len(), 100_000);
        // Over the cap: refused instead of buffered.
        assert!(inflate_capped(&deflated, "deflate", 99_999).is_none());
        // Garbage: refused.
        assert!(inflate_capped(b"not deflate at all", "deflate", 1_000).is_none());
        // Gzip goes through the same cap.
        let gz = gzip(&html);
        assert!(inflate_capped(&gz, "gzip", 1_000).is_none());
        assert_eq!(inflate_capped(&gz, "gzip", 100_000).unwrap().len(), 100_000);
    }

    #[test]
    fn ws_extra_headers_drop_every_forwarding_header() {
        let mut h = hyper::HeaderMap::new();
        h.insert("forwarded", "for=1.2.3.4".parse().unwrap());
        h.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        h.insert("x-forwarded-port", "443".parse().unwrap());
        h.insert("x-forwarded-prefix", "/admin".parse().unwrap());
        let peer: SocketAddr = "9.9.9.9:1".parse().unwrap();
        let who = crate::edge::ClientInfo::direct(peer.ip());
        let out = build_ws_extra_headers(&h, Some(&who), false, "real.example");
        assert!(header_value(&out, "Forwarded").is_none());
        assert!(header_value(&out, "X-Forwarded-Port").is_none());
        assert!(header_value(&out, "X-Forwarded-Prefix").is_none());
        assert_eq!(header_value(&out, "X-Real-IP"), Some("9.9.9.9"));
    }

    #[test]
    fn h2_activity_tracks_idleness() {
        let a = Arc::new(H2Activity::new());
        assert!(!a.seen_request.load(Ordering::Relaxed));
        let guard = a.start();
        assert!(a.seen_request.load(Ordering::Relaxed));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(a.idle_for(), Duration::ZERO, "busy while in flight");
        drop(guard);
        std::thread::sleep(Duration::from_millis(20));
        assert!(a.idle_for() >= Duration::from_millis(15));
    }

    #[test]
    fn keep_alive_timeout_defaults_to_thirty_seconds() {
        let mut limits = crate::config::LimitsConfig::default();
        assert_eq!(keep_alive_timeout(&limits), Duration::from_secs(30));
        limits.keep_alive_timeout = Some(0);
        assert_eq!(keep_alive_timeout(&limits), Duration::from_secs(30));
        limits.keep_alive_timeout = Some(5);
        assert_eq!(keep_alive_timeout(&limits), Duration::from_secs(5));
    }

    #[cfg(feature = "scripting")]
    fn lua_req_with(headers: &[(&str, &str)]) -> LuaRequest {
        LuaRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            host: String::new(),
            content_length: 0,
            ..Default::default()
        }
    }

    #[cfg(feature = "scripting")]
    #[test]
    fn lua_view_joins_duplicates_and_write_back_replaces_them() {
        let mut req = Request::builder()
            .uri("/")
            .header("x-user", "evil")
            .header("x-user", "alice")
            .header("cookie", "a=1")
            .header("cookie", "b=2")
            .body(())
            .unwrap();
        let view = extract_headers(&req);
        assert_eq!(view["x-user"], "evil, alice");
        assert_eq!(view["cookie"], "a=1; b=2");

        // Untouched by the script: every field kept as sent.
        apply_lua_request_mods(
            &mut req,
            &lua_req_with(&[("x-user", "evil, alice"), ("cookie", "a=1; b=2")]),
        );
        assert_eq!(req.headers().get_all("x-user").iter().count(), 2);
        assert_eq!(req.headers().get_all("cookie").iter().count(), 2);

        // Set to one of the client's own values: still replaces all of them,
        // so the backend cannot read the other one first.
        apply_lua_request_mods(
            &mut req,
            &lua_req_with(&[("x-user", "alice"), ("cookie", "a=1; b=2")]),
        );
        let users: Vec<_> = req.headers().get_all("x-user").iter().collect();
        assert_eq!(users, vec!["alice"]);
    }

    #[test]
    fn probing_a_high_port_succeeds_and_leaves_nothing_listening() {
        // The probe must not become a listener. If it did, the restart window
        // would hand RSTs to whatever connected during it.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(probe_bind(addr).is_ok());
    }

    #[test]
    fn probing_a_privileged_port_without_the_capability_names_setcap() {
        // Port 80 is the case that actually happens: a binary replaced by
        // cp/install loses cap_net_bind_service and comes back deaf. Skipped
        // where the process can bind low ports anyway (root, or a lowered
        // ip_unprivileged_port_start), because there the errno never occurs.
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        match probe_bind(addr) {
            Ok(()) => {} // allowed to bind here; nothing to assert
            Err(e) => {
                let text = e.to_string();
                assert!(text.contains("setcap"), "{text}");
                assert!(text.contains("cap_net_bind_service"), "{text}");
                // The recurrence is the part people lose an afternoon to.
                assert!(text.contains("cp/install"), "{text}");
            }
        }
    }

    #[test]
    fn a_bind_failure_that_is_not_permission_keeps_its_own_error() {
        // Only EACCES on a privileged port gets the setcap advice. Anything
        // else must not be dressed up as a capability problem — sending
        // someone to setcap for EADDRNOTAVAIL wastes the same afternoon in the
        // other direction.
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let err = bind_error(
            addr,
            std::io::Error::from(std::io::ErrorKind::AddrNotAvailable),
        );
        let text = err.to_string();
        assert!(text.contains("cannot bind 127.0.0.1:80"), "{text}");
        assert!(!text.contains("setcap"), "{text}");
    }

    #[test]
    fn permission_denied_on_a_high_port_is_not_blamed_on_capabilities() {
        // Above 1024 no capability is involved, so EACCES means something else
        // — a seccomp filter, an LSM, a container policy. Naming setcap there
        // is a confident wrong answer.
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let err = bind_error(
            addr,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(!err.to_string().contains("setcap"), "{err}");
    }
}
