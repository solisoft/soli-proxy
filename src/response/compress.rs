//! Response compression: gzip, brotli and zstd, streamed.
//!
//! The proxy compresses a backend's response when the client asked for it
//! (`Accept-Encoding`), the backend did not already, and the response is the
//! kind that shrinks (text, JSON, JavaScript, SVG, wasm…). Off unless
//! `[compression] enabled = true`, or a route's `@compress:on`.
//!
//! **Why off by default.** Compression is the most expensive thing a proxy
//! can do to a response — passthrough moves gigabytes per second per core;
//! gzip at level 5 manages ~50–80 MB/s, brotli at 4 ~60–100 MB/s, zstd at 3
//! ~300 MB/s. Turned on by an upgrade, it would multiply the proxy's CPU per
//! text byte by one to two orders of magnitude without anyone asking. It also
//! changes what clients and caches see (weak ETags, `Vary`), and compressing
//! responses that reflect request input next to a secret (a CSRF token) is
//! what BREACH exploits — an app that chose not to compress may have chosen
//! on purpose. Caddy, nginx and Traefik make it opt-in too.
//!
//! **Not on the async workers for long.** Encoding happens inside the body's
//! `poll_frame`, so it runs on a tokio worker — but at most
//! [`INPUT_BUDGET`] bytes of input per poll (a fraction of a millisecond at
//! the default levels), after which the body yields. A large in-memory body
//! is split across polls rather than compressed in one go.
//!
//! **Streaming is preserved.** Input is compressed without flushing while the
//! backend keeps producing; the moment the backend has nothing more to give
//! (its body returns `Pending`), the encoder is flushed and what it holds is
//! sent. A progressively rendered page, or a chunked JSON stream, reaches the
//! client as it is produced, at the cost of a few bytes per flush.

use crate::pool::BoxError;
use crate::server::BoxBody;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::Response;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Input compressed per `poll_frame` before the body yields to the scheduler.
pub const INPUT_BUDGET: usize = 64 * 1024;

/// Compressed output accumulated before it is sent as a frame.
const OUTPUT_CHUNK: usize = 16 * 1024;

/// A content coding the proxy can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coding {
    #[serde(rename = "br")]
    Brotli,
    #[serde(rename = "zstd")]
    Zstd,
    #[serde(rename = "gzip")]
    Gzip,
}

impl Coding {
    pub fn token(self) -> &'static str {
        match self {
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
            Coding::Gzip => "gzip",
        }
    }
}

/// `[compression]` in `config.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionConfig {
    /// Compress eligible responses on every route and app that does not opt
    /// out. Default `false`: see the module documentation.
    pub enabled: bool,
    /// The codings offered, in the proxy's order of preference when a client
    /// accepts several equally. Default `["br", "zstd", "gzip"]`.
    pub algorithms: Vec<Coding>,
    /// 1–9. Default 5.
    pub gzip_level: u32,
    /// 0–11. Default 4: brotli's levels above ~5 cost several times more CPU
    /// for a few percent.
    pub brotli_level: u32,
    /// 1–19. Default 3, zstd's own default.
    pub zstd_level: i32,
    /// Responses whose `Content-Length` is below this are sent as they are:
    /// compressing a few hundred bytes saves little and can even grow them.
    /// A response without a length is compressed. Default 1024.
    pub min_length: u64,
    /// Media types compressed. `type/*` matches a whole type, `*+json` (or
    /// `*/*+json`) a structured-syntax suffix; anything else is an exact media
    /// type, compared without parameters and case.
    pub types: Vec<String>,
    #[serde(skip)]
    patterns: Vec<TypePattern>,
}

/// The media types compressed by default: text and the textual formats of
/// the web. Images, video, fonts in woff/woff2 and archives are already
/// compressed and are left out.
pub const DEFAULT_TYPES: &[&str] = &[
    "text/*",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/xml",
    "application/wasm",
    "application/x-ndjson",
    "application/vnd.ms-fontobject",
    "application/x-font-ttf",
    "font/ttf",
    "font/otf",
    "image/svg+xml",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "*+json",
    "*+xml",
];

impl Default for CompressionConfig {
    fn default() -> Self {
        let mut config = Self {
            enabled: false,
            algorithms: vec![Coding::Brotli, Coding::Zstd, Coding::Gzip],
            gzip_level: 5,
            brotli_level: 4,
            zstd_level: 3,
            min_length: 1024,
            types: DEFAULT_TYPES.iter().map(|s| s.to_string()).collect(),
            patterns: Vec::new(),
        };
        config.patterns = compile_types(&config.types);
        config
    }
}

#[derive(Clone, Debug)]
enum TypePattern {
    /// `text/*`, stored as `text/`.
    Prefix(String),
    /// `*+json`, stored as `+json`.
    Suffix(String),
    Exact(String),
}

fn compile_types(types: &[String]) -> Vec<TypePattern> {
    types
        .iter()
        .map(|t| {
            let t = t.trim().to_ascii_lowercase();
            if let Some(suffix) = t.strip_prefix("*/*+").or_else(|| t.strip_prefix("*+")) {
                TypePattern::Suffix(format!("+{}", suffix))
            } else if t == "*/*" || t == "*" {
                TypePattern::Prefix(String::new())
            } else if let Some(main) = t.strip_suffix("/*") {
                TypePattern::Prefix(format!("{}/", main))
            } else {
                TypePattern::Exact(t)
            }
        })
        .collect()
}

impl CompressionConfig {
    /// Validate the section and compile its media types. Called once per
    /// loaded config; an invalid section is a load error like any other.
    pub fn validated(mut self) -> anyhow::Result<Self> {
        if !(1..=9).contains(&self.gzip_level) {
            anyhow::bail!(
                "[compression] gzip_level = {} (expected 1 to 9)",
                self.gzip_level
            );
        }
        if self.brotli_level > 11 {
            anyhow::bail!(
                "[compression] brotli_level = {} (expected 0 to 11)",
                self.brotli_level
            );
        }
        // 20–22 are zstd's "ultra" levels, with windows of up to 128 MB per
        // response being compressed: not something to run per request.
        if !(1..=19).contains(&self.zstd_level) {
            anyhow::bail!(
                "[compression] zstd_level = {} (expected 1 to 19)",
                self.zstd_level
            );
        }
        let mut seen = Vec::new();
        self.algorithms.retain(|a| {
            let first = !seen.contains(a);
            seen.push(*a);
            first
        });
        if self.enabled && self.algorithms.is_empty() {
            anyhow::bail!("[compression] is enabled with an empty `algorithms` list");
        }
        for t in &self.types {
            if t.trim().is_empty() || t.contains(';') {
                anyhow::bail!(
                    "[compression] types entry {:?} is not a media type (no parameters)",
                    t
                );
            }
        }
        self.patterns = compile_types(&self.types);
        Ok(self)
    }

    fn type_allowed(&self, essence: &str) -> bool {
        let essence = essence.as_bytes();
        self.patterns.iter().any(|p| match p {
            TypePattern::Prefix(prefix) => {
                essence.len() >= prefix.len()
                    && essence[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
            }
            TypePattern::Suffix(suffix) => {
                essence.len() > suffix.len()
                    && essence[essence.len() - suffix.len()..]
                        .eq_ignore_ascii_case(suffix.as_bytes())
            }
            TypePattern::Exact(exact) => essence.eq_ignore_ascii_case(exact.as_bytes()),
        })
    }
}

/// The value of a route's `@compress:` directive: `on` or `off`.
pub fn parse_directive(value: &str) -> anyhow::Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => anyhow::bail!(
            "@compress:{} (expected @compress:on or @compress:off)",
            other
        ),
    }
}

/// Quality values are kept in thousandths, as the grammar allows exactly
/// three decimals (RFC 9110 §12.4.2).
type Q = u16;

/// Parse a `q` parameter's value; `None` when it is not a valid qvalue.
fn parse_q(value: &str) -> Option<Q> {
    let value = value.trim();
    let (int, frac) = value.split_once('.').unwrap_or((value, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut thousandths: Q = 0;
    for (i, b) in frac.bytes().enumerate() {
        thousandths += Q::from(b - b'0') * [100, 10, 1][i];
    }
    match int {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// Choose the coding for a response to a request with these headers, from
/// the configured `algorithms`. `None` means identity.
///
/// RFC 9110 §12.5.3: a coding not listed is acceptable only through `*`;
/// `q=0` refuses one. The highest q wins; a tie goes to the configured order
/// (br before zstd before gzip by default). Identity is compared only when
/// the client ranked it (`identity;q=…`, or `*`), and a coding never loses a
/// tie to it. No header at all
/// means no compression: in theory "anything", in practice a client that
/// never asked (a health probe, a script) and may not decode what it gets.
/// No allocation.
pub fn negotiate(headers: &HeaderMap, config: &CompressionConfig) -> Option<Coding> {
    let mut values = headers.get_all(header::ACCEPT_ENCODING).iter().peekable();
    values.peek()?;
    // br, zstd, gzip, identity, *
    let mut q: [Option<Q>; 5] = [None; 5];
    for value in values {
        let Ok(value) = value.to_str() else { continue };
        for item in value.split(',') {
            let mut parts = item.split(';');
            let name = parts.next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            let mut quality = Some(1000);
            for param in parts {
                if let Some((k, v)) = param.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("q") {
                        quality = parse_q(v);
                    }
                }
            }
            // An unparseable q makes the whole entry unusable: ignored.
            let Some(quality) = quality else { continue };
            let slot = if name.eq_ignore_ascii_case("br") {
                0
            } else if name.eq_ignore_ascii_case("zstd") {
                1
            } else if name.eq_ignore_ascii_case("gzip") || name.eq_ignore_ascii_case("x-gzip") {
                2
            } else if name.eq_ignore_ascii_case("identity") {
                3
            } else if name == "*" {
                4
            } else {
                continue;
            };
            // Listed twice: keep the more generous value.
            q[slot] = Some(q[slot].map_or(quality, |old| old.max(quality)));
        }
    }
    let star = q[4];
    // Identity competes only when the client ranked it, by name or through
    // `*`. Left unranked it is merely "not refused": `gzip;q=0.8` still
    // means "gzip, please", not "identity at 1 beats gzip at 0.8".
    let identity = q[3].or(star).unwrap_or(0);
    let mut best: Option<(Coding, Q)> = None;
    for &coding in &config.algorithms {
        let slot = match coding {
            Coding::Brotli => 0,
            Coding::Zstd => 1,
            Coding::Gzip => 2,
        };
        let quality = q[slot].or(star).unwrap_or(0);
        if quality > 0 && best.is_none_or(|(_, b)| quality > b) {
            best = Some((coding, quality));
        }
    }
    match best {
        Some((coding, quality)) if quality >= identity => Some(coding),
        _ => None,
    }
}

/// What the request said that compression needs, captured before the request
/// is consumed.
#[derive(Clone, Copy, Debug)]
pub struct Requested {
    coding: Option<Coding>,
    head: bool,
}

impl Requested {
    pub fn capture<B>(req: &hyper::Request<B>, config: &CompressionConfig) -> Self {
        Self {
            coding: negotiate(req.headers(), config),
            head: req.method() == hyper::Method::HEAD,
        }
    }
}

fn header_has_token(headers: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',').any(|t| {
                t.trim()
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case(token)
            })
        })
    })
}

/// Whether the body already carries a content coding: any coding other than
/// `identity`, in any `Content-Encoding` field, in any position. Only the
/// first field's whole value used to be compared, so `identity, gzip` (or a
/// second field) was taken for identity and gzipped again — a body the
/// client then decoded once and got garbage.
fn already_encoded(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|field| match field.to_str() {
            Ok(v) => v
                .split(',')
                .map(str::trim)
                .any(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity")),
            // Not even text: certainly not something to encode over.
            Err(_) => true,
        })
}

/// Whether `resp` is a candidate for compression at all — independently of
/// what this client accepts, so that `Vary` is set on every response another
/// client could get compressed.
fn eligible(resp: &Response<BoxBody>, config: &CompressionConfig) -> bool {
    let status = resp.status().as_u16();
    // 1xx carry no body; 204/304 none either; a 206 is a byte range of the
    // identity representation, which recoding would make meaningless.
    if status < 200 || matches!(status, 204 | 206 | 304) {
        return false;
    }
    let headers = resp.headers();
    if already_encoded(headers) {
        return false;
    }
    if headers.contains_key(header::CONTENT_RANGE) {
        return false;
    }
    let Some(essence) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or("").trim())
    else {
        return false;
    };
    // Server-sent events must reach the client event by event; they are
    // left alone whatever `types` says.
    if essence.eq_ignore_ascii_case("text/event-stream") || !config.type_allowed(essence) {
        return false;
    }
    if header_has_token(headers, header::CACHE_CONTROL, "no-transform") {
        return false;
    }
    let length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| resp.body().size_hint().exact());
    !matches!(length, Some(n) if n < config.min_length)
}

/// Add `Accept-Encoding` to `Vary` unless it is there (or `Vary: *`).
fn add_vary(headers: &mut HeaderMap) {
    let present = headers.get_all(header::VARY).iter().any(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.eq_ignore_ascii_case("accept-encoding")
            })
        })
    });
    if !present {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

/// Compress `resp` when everything allows it; otherwise return it untouched
/// (save for `Vary`, when another client could get it compressed).
///
/// `enabled` is the global switch; a route's `@compress:` or an app's
/// `compress =`, carried on the response as a [`super::ResponseTag`],
/// overrides it either way.
pub fn apply(
    mut resp: Response<BoxBody>,
    requested: Requested,
    config: &CompressionConfig,
) -> Response<BoxBody> {
    let enabled = super::tag(&resp)
        .and_then(|t| t.compress)
        .unwrap_or(config.enabled);
    if !enabled || !eligible(&resp, config) {
        return resp;
    }
    add_vary(resp.headers_mut());
    let Some(coding) = requested.coding else {
        return resp;
    };
    // A HEAD response has no body to compress. It still says it varies.
    if requested.head {
        return resp;
    }
    let encoder = match Encoder::new(coding, config) {
        Ok(encoder) => encoder,
        Err(e) => {
            tracing::warn!("cannot start {} encoder: {}", coding.token(), e);
            return resp;
        }
    };
    let (mut parts, body) = resp.into_parts();
    let headers = &mut parts.headers;
    headers.remove(header::CONTENT_LENGTH);
    // Byte ranges would now address the compressed stream.
    headers.remove(header::ACCEPT_RANGES);
    headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(coding.token()),
    );
    // A strong validator promises byte-identical content; the compressed
    // representation is not the one the backend tagged (RFC 9110 §8.8.1).
    if let Some(etag) = headers.get(header::ETAG) {
        if etag.as_bytes().starts_with(b"\"") {
            let mut weak = Vec::with_capacity(etag.len() + 2);
            weak.extend_from_slice(b"W/");
            weak.extend_from_slice(etag.as_bytes());
            if let Ok(v) = HeaderValue::from_bytes(&weak) {
                headers.insert(header::ETAG, v);
            }
        }
    }
    Response::from_parts(parts, CompressBody::new(body, encoder).boxed())
}

/// One coding's streaming encoder, writing into an in-memory buffer that the
/// body drains after each step.
enum Encoder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

/// brotli's window: 2^20 = 1 MiB. Its default (22, 4 MiB) is memory held per
/// response being compressed, for little gain on web payloads.
const BROTLI_LGWIN: u32 = 20;

impl Encoder {
    fn new(coding: Coding, config: &CompressionConfig) -> std::io::Result<Self> {
        Ok(match coding {
            Coding::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(config.gzip_level),
            )),
            Coding::Brotli => Encoder::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                config.brotli_level,
                BROTLI_LGWIN,
            ))),
            Coding::Zstd => Encoder::Zstd(zstd::stream::write::Encoder::new(
                Vec::new(),
                config.zstd_level,
            )?),
        })
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Encoder::Gzip(e) => e.write_all(data),
            Encoder::Brotli(e) => e.write_all(data),
            Encoder::Zstd(e) => e.write_all(data),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Encoder::Gzip(e) => e.flush(),
            Encoder::Brotli(e) => e.flush(),
            Encoder::Zstd(e) => e.flush(),
        }
    }

    fn buffered(&mut self) -> &mut Vec<u8> {
        match self {
            Encoder::Gzip(e) => e.get_mut(),
            Encoder::Brotli(e) => e.get_mut(),
            Encoder::Zstd(e) => e.get_mut(),
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(self.buffered())
    }

    /// Write the stream's end and return everything still buffered.
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Encoder::Gzip(e) => e.finish(),
            // `into_inner` ends the brotli stream (BROTLI_OPERATION_FINISH).
            Encoder::Brotli(e) => Ok(e.into_inner()),
            Encoder::Zstd(e) => e.finish(),
        }
    }
}

/// A response body compressed as it streams. See the module documentation
/// for how it bounds its time on a worker and keeps streaming responses live.
struct CompressBody {
    inner: BoxBody,
    encoder: Option<Encoder>,
    /// Input taken from the backend but not yet fed to the encoder.
    pending: Bytes,
    /// Input was written since the last flush.
    dirty: bool,
    inner_done: bool,
    /// The backend's trailers, sent after the compressed stream ends.
    trailers: Option<HeaderMap>,
    done: bool,
}

impl CompressBody {
    fn new(inner: BoxBody, encoder: Encoder) -> Self {
        Self {
            inner,
            encoder: Some(encoder),
            pending: Bytes::new(),
            dirty: false,
            inner_done: false,
            trailers: None,
            done: false,
        }
    }
}

fn data_frame(out: Vec<u8>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))))
}

impl Body for CompressBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        let mut budget = INPUT_BUDGET;
        loop {
            let Some(encoder) = this.encoder.as_mut() else {
                // The compressed stream has ended: trailers, then the end.
                if let Some(trailers) = this.trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                this.done = true;
                return Poll::Ready(None);
            };

            // Feed what was taken from the backend, within this poll's budget.
            while !this.pending.is_empty() {
                let chunk = this.pending.split_to(this.pending.len().min(budget));
                budget -= chunk.len();
                encoder.write(&chunk)?;
                this.dirty = true;
                if encoder.buffered().len() >= OUTPUT_CHUNK {
                    return data_frame(encoder.take());
                }
                if budget == 0 {
                    let out = encoder.take();
                    if !out.is_empty() {
                        return data_frame(out);
                    }
                    // Nothing to send yet, but this poll has done its share:
                    // let the worker run something else, and come back.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }

            if this.inner_done {
                let encoder = this.encoder.take().expect("checked above");
                let out = encoder.finish()?;
                if !out.is_empty() {
                    return data_frame(out);
                }
                continue;
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.pending = data,
                    Err(frame) => {
                        // Trailers end the body.
                        if let Ok(trailers) = frame.into_trailers() {
                            this.trailers = Some(trailers);
                            this.inner_done = true;
                        }
                    }
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => this.inner_done = true,
                Poll::Pending => {
                    // The backend is thinking: send what we have rather than
                    // sit on it until it speaks again.
                    if this.dirty {
                        this.dirty = false;
                        encoder.flush()?;
                        let out = encoder.take();
                        if !out.is_empty() {
                            return data_frame(out);
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::full;
    use std::io::Read;

    fn headers(accept: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in accept {
            h.append(header::ACCEPT_ENCODING, v.parse().unwrap());
        }
        h
    }

    fn pick(accept: &[&str]) -> Option<&'static str> {
        negotiate(&headers(accept), &CompressionConfig::default()).map(Coding::token)
    }

    #[test]
    fn any_non_identity_coding_counts_as_encoded() {
        let h = |values: &[&str]| {
            let mut h = http::HeaderMap::new();
            for v in values {
                h.append(header::CONTENT_ENCODING, v.parse().unwrap());
            }
            h
        };
        assert!(!already_encoded(&h(&[])));
        assert!(!already_encoded(&h(&["identity"])));
        assert!(!already_encoded(&h(&["Identity", ""])));
        assert!(already_encoded(&h(&["gzip"])));
        assert!(already_encoded(&h(&["identity, gzip"])));
        assert!(already_encoded(&h(&["identity", "br"])));
    }

    #[test]
    fn negotiation_table() {
        let cases: &[(&[&str], Option<&str>)] = &[
            (&[], None),
            (&[""], None),
            (&["gzip"], Some("gzip")),
            (&["x-gzip"], Some("gzip")),
            (&["GZIP, Deflate"], Some("gzip")),
            (&["gzip, deflate, br"], Some("br")),
            (&["gzip, deflate, br, zstd"], Some("br")),
            (&["gzip, zstd"], Some("zstd")),
            (&["br;q=0.5, gzip"], Some("gzip")),
            (&["br;q=0.9, zstd;q=0.9, gzip;q=0.9"], Some("br")),
            (&["br;q=0, gzip;q=0"], None),
            (&["*"], Some("br")),
            (&["*;q=0.5, br;q=0"], Some("zstd")),
            (&["identity"], None),
            (&["deflate"], None),
            // identity preferred over the only coding offered
            (&["gzip;q=0.5, identity"], None),
            // `*` ranks identity and the unlisted codings alike
            (&["gzip;q=0.5, *"], Some("br")),
            (&["gzip;q=0.5, br;q=0.4, zstd;q=0, *"], None),
            // an unranked identity does not compete
            (&["gzip;q=0.5"], Some("gzip")),
            // ...but a coding at the same q as identity wins
            (&["gzip;q=0.5, identity;q=0.5"], Some("gzip")),
            // identity refused through *: a coding still answers
            (&["gzip;q=0.1, *;q=0"], Some("gzip")),
            // malformed q: the entry is ignored, not taken as q=1
            (&["br;q=2, gzip"], Some("gzip")),
            (&["br;q=0.0001, gzip"], Some("gzip")),
            (&["br;q=abc"], None),
            (&["gzip;q=1.000"], Some("gzip")),
            (&["gzip;q=0.001"], Some("gzip")),
            // several headers combine
            (&["gzip", "br"], Some("br")),
            // listed twice: the more generous value
            (&["br;q=0, br;q=1"], Some("br")),
        ];
        for (accept, expected) in cases {
            assert_eq!(pick(accept), *expected, "Accept-Encoding: {:?}", accept);
        }
    }

    #[test]
    fn negotiation_follows_the_configured_algorithms() {
        let config = CompressionConfig {
            algorithms: vec![Coding::Gzip, Coding::Brotli],
            ..CompressionConfig::default()
        }
        .validated()
        .unwrap();
        let pick = |v: &str| negotiate(&headers(&[v]), &config);
        assert_eq!(
            pick("br, gzip"),
            Some(Coding::Gzip),
            "configured order breaks ties"
        );
        assert_eq!(pick("zstd"), None, "zstd is not offered");
        assert_eq!(pick("zstd, br;q=0.5"), Some(Coding::Brotli));
    }

    #[test]
    fn qvalues_parse_to_thousandths() {
        assert_eq!(parse_q("1"), Some(1000));
        assert_eq!(parse_q("1."), Some(1000));
        assert_eq!(parse_q("0.5"), Some(500));
        assert_eq!(parse_q(" 0.25 "), Some(250));
        assert_eq!(parse_q("0.125"), Some(125));
        assert_eq!(parse_q("0"), Some(0));
        assert_eq!(parse_q("1.5"), None);
        assert_eq!(parse_q("2"), None);
        assert_eq!(parse_q("0.1234"), None);
        assert_eq!(parse_q("-1"), None);
        assert_eq!(parse_q(""), None);
    }

    #[test]
    fn invalid_sections_are_refused() {
        let bad = |c: CompressionConfig| c.validated().is_err();
        assert!(bad(CompressionConfig {
            gzip_level: 0,
            ..Default::default()
        }));
        assert!(bad(CompressionConfig {
            brotli_level: 12,
            ..Default::default()
        }));
        assert!(bad(CompressionConfig {
            zstd_level: 22,
            ..Default::default()
        }));
        assert!(bad(CompressionConfig {
            enabled: true,
            algorithms: vec![],
            ..Default::default()
        }));
        assert!(bad(CompressionConfig {
            types: vec!["text/html; charset=utf-8".into()],
            ..Default::default()
        }));
        let parsed: CompressionConfig =
            toml::from_str("enabled = true\nalgorithms = [\"gzip\", \"gzip\", \"br\"]").unwrap();
        let parsed = parsed.validated().unwrap();
        assert_eq!(parsed.algorithms, vec![Coding::Gzip, Coding::Brotli]);
        assert!(toml::from_str::<CompressionConfig>("algorithms = [\"lzma\"]").is_err());
    }

    #[test]
    fn media_type_patterns() {
        let config = CompressionConfig::default();
        for yes in [
            "text/html",
            "TEXT/CSS",
            "application/json",
            "application/problem+json",
            "application/atom+xml",
            "image/svg+xml",
            "application/wasm",
        ] {
            assert!(config.type_allowed(yes), "{yes}");
        }
        for no in [
            "image/png",
            "font/woff2",
            "application/octet-stream",
            "application/zip",
            "+json",
            "application/grpc",
        ] {
            assert!(!config.type_allowed(no), "{no}");
        }
    }

    fn response(ct: Option<&str>, body: &'static [u8]) -> Response<BoxBody> {
        let mut resp = Response::new(full(Bytes::from_static(body)));
        if let Some(ct) = ct {
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, ct.parse().unwrap());
        }
        resp
    }

    fn enabled() -> CompressionConfig {
        CompressionConfig {
            enabled: true,
            ..Default::default()
        }
        .validated()
        .unwrap()
    }

    fn wants(coding: Coding) -> Requested {
        Requested {
            coding: Some(coding),
            head: false,
        }
    }

    async fn body_bytes(resp: Response<BoxBody>) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn decode(coding: Coding, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match coding {
            Coding::Gzip => {
                flate2::read::GzDecoder::new(data)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            Coding::Brotli => {
                brotli::Decompressor::new(data, 4096)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            Coding::Zstd => out = zstd::stream::decode_all(data).unwrap(),
        }
        out
    }

    const PAGE: &[u8] = include_bytes!("compress.rs");

    #[tokio::test]
    async fn each_coding_round_trips() {
        for coding in [Coding::Gzip, Coding::Brotli, Coding::Zstd] {
            let mut resp = response(Some("text/plain; charset=utf-8"), PAGE);
            resp.headers_mut()
                .insert(header::ETAG, "\"v1\"".parse().unwrap());
            resp.headers_mut()
                .insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
            let resp = apply(resp, wants(coding), &enabled());
            let h = resp.headers();
            assert_eq!(h[header::CONTENT_ENCODING], coding.token());
            assert_eq!(h[header::VARY], "Accept-Encoding");
            assert_eq!(h[header::ETAG], "W/\"v1\"");
            assert!(!h.contains_key(header::CONTENT_LENGTH));
            assert!(!h.contains_key(header::ACCEPT_RANGES));
            let compressed = body_bytes(resp).await;
            assert!(
                compressed.len() < PAGE.len() / 2,
                "{coding:?} did not shrink"
            );
            assert_eq!(decode(coding, &compressed), PAGE, "{coding:?}");
        }
    }

    /// A body arriving in many frames, some large enough to exceed a poll's
    /// budget, decodes back to the concatenation.
    #[tokio::test]
    async fn streamed_frames_round_trip() {
        let big: Vec<u8> = (0..300_000u32)
            .flat_map(|i| format!("line {} of the stream\n", i % 977).into_bytes())
            .collect();
        for coding in [Coding::Gzip, Coding::Brotli, Coding::Zstd] {
            let chunks: Vec<Result<Frame<Bytes>, BoxError>> = big
                .chunks(100_000)
                .chain(std::iter::once(&b"tail"[..]))
                .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
                .collect();
            let stream = futures_util::stream::iter(chunks);
            let body = http_body_util::StreamBody::new(stream).boxed();
            let mut resp = Response::new(body);
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            let resp = apply(resp, wants(coding), &enabled());
            let mut expected = big.clone();
            expected.extend_from_slice(b"tail");
            assert_eq!(decode(coding, &body_bytes(resp).await), expected);
        }
    }

    /// A backend that pauses mid-body: what it sent so far is flushed to the
    /// client instead of waiting in the encoder.
    #[tokio::test]
    async fn a_pause_in_the_backend_flushes_what_was_sent() {
        let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(4);
        let body = http_body_util::StreamBody::new(rx).boxed();
        let mut resp = Response::new(body);
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, "text/html".parse().unwrap());
        let resp = apply(resp, wants(Coding::Gzip), &enabled());
        let mut body = resp.into_body();
        use futures::SinkExt;
        tx.send(Ok(Frame::data(Bytes::from_static(
            b"<html><body>first part",
        ))))
        .await
        .unwrap();
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
            .await
            .expect("the first part must be flushed while the backend waits")
            .unwrap()
            .unwrap();
        let first = frame.into_data().unwrap();
        // A sync-flushed gzip prefix decodes to everything written so far.
        let mut decoder = flate2::write::GzDecoder::new(Vec::new());
        decoder.write_all(&first).unwrap();
        decoder.flush().unwrap();
        assert_eq!(decoder.get_ref().as_slice(), b"<html><body>first part");
        drop(tx);
    }

    #[tokio::test]
    async fn exclusions_leave_the_response_alone() {
        let config = enabled();
        let unchanged = |resp: Response<BoxBody>| {
            let resp = apply(resp, wants(Coding::Gzip), &config);
            resp.headers()
                .get(header::CONTENT_ENCODING)
                .is_none_or(|v| v != "gzip")
        };

        // Not a compressible type, or no type at all.
        assert!(unchanged(response(Some("image/png"), PAGE)));
        assert!(unchanged(response(None, PAGE)));
        // Server-sent events, even though text/* is allowed.
        assert!(unchanged(response(Some("text/event-stream"), PAGE)));
        // Too small.
        assert!(unchanged(response(Some("text/plain"), b"tiny")));
        // Already encoded by the backend.
        let mut r = response(Some("text/plain"), PAGE);
        r.headers_mut()
            .insert(header::CONTENT_ENCODING, "br".parse().unwrap());
        assert!(unchanged(r));
        // no-transform.
        let mut r = response(Some("text/plain"), PAGE);
        r.headers_mut().insert(
            header::CACHE_CONTROL,
            "public, no-transform".parse().unwrap(),
        );
        assert!(unchanged(r));
        // Statuses without a body to compress, and partial content.
        for status in [101, 204, 206, 304] {
            let mut r = response(Some("text/plain"), PAGE);
            *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            assert!(unchanged(r), "{status}");
        }
        // A HEAD request: not compressed, but Vary is set.
        let r = apply(
            response(Some("text/plain"), PAGE),
            Requested {
                coding: Some(Coding::Gzip),
                head: true,
            },
            &config,
        );
        assert!(!r.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(r.headers()[header::VARY], "Accept-Encoding");
        // A client that does not accept a coding: Vary, no encoding.
        let r = apply(
            response(Some("text/plain"), PAGE),
            Requested {
                coding: None,
                head: false,
            },
            &config,
        );
        assert!(!r.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(r.headers()[header::VARY], "Accept-Encoding");
        // Vary already naming Accept-Encoding is not repeated.
        let mut r = response(Some("text/plain"), PAGE);
        r.headers_mut()
            .insert(header::VARY, "Origin, accept-encoding".parse().unwrap());
        let r = apply(r, wants(Coding::Gzip), &config);
        assert_eq!(r.headers().get_all(header::VARY).iter().count(), 1);
        // A weak ETag stays as it is.
        let mut r = response(Some("text/plain"), PAGE);
        r.headers_mut()
            .insert(header::ETAG, "W/\"x\"".parse().unwrap());
        let r = apply(r, wants(Coding::Gzip), &config);
        assert_eq!(r.headers()[header::ETAG], "W/\"x\"");
    }

    #[test]
    fn route_and_app_overrides_beat_the_global_switch() {
        let off = CompressionConfig::default().validated().unwrap();
        let on = enabled();

        let mut r = response(Some("text/plain"), PAGE);
        crate::response::mark_upstream(&mut r, Some(true));
        let r = apply(r, wants(Coding::Gzip), &off);
        assert_eq!(
            r.headers()[header::CONTENT_ENCODING],
            "gzip",
            "@compress:on"
        );

        let mut r = response(Some("text/plain"), PAGE);
        crate::response::mark_upstream(&mut r, Some(false));
        let r = apply(r, wants(Coding::Gzip), &on);
        assert!(
            !r.headers().contains_key(header::CONTENT_ENCODING),
            "@compress:off"
        );
        assert!(!r.headers().contains_key(header::VARY));

        let r = apply(
            response(Some("text/plain"), PAGE),
            wants(Coding::Gzip),
            &off,
        );
        assert!(
            !r.headers().contains_key(header::CONTENT_ENCODING),
            "off by default"
        );
    }
}
