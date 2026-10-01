//! The access log: one line per completed request.
//!
//! ```toml
//! [logging]
//! access_log = "/var/log/soli-proxy/access.log"  # "off" (default), "stdout", "stderr"
//! access_log_format = "json"                      # or "combined"
//! ```
//!
//! A line is written when the response body has been handed to the
//! connection in full — or abandoned, when the client went away or the
//! backend failed mid-body — so it carries the bytes actually sent and the
//! whole duration, not just the time to the response head. For a WebSocket
//! that is the 101: the tunnel's lifetime and traffic are not in the line.
//! `bytes_in` is the request's `Content-Length` (0 for a chunked upload).
//!
//! Lines are formatted into a per-thread buffer that is reused from one
//! request to the next, then handed to the same non-blocking writer the
//! proxy's own log uses (`tracing_appender::non_blocking`, a dedicated
//! thread doing the I/O). That writer is lossy: if the disk cannot keep up
//! and its queue fills, lines are dropped rather than the request path
//! blocking. File output rotates like `[logging] output`, by `max_size` and
//! `max_files`. The destination is read at startup.

use std::cell::RefCell;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use http_body_util::BodyExt;
use hyper::header::{HeaderValue, CONTENT_LENGTH, HOST, REFERER, USER_AGENT};
use hyper::{Method, Request, Response, Uri, Version};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::config::LoggingConfig;
use crate::pool::BoxError;
use crate::server::BoxBody;

/// Line format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessLogFormat {
    /// One JSON object per line.
    Json,
    /// Apache/nginx "combined", with the proxy's own fields appended as
    /// `key=value` — log analysers that read combined ignore the tail.
    Combined,
}

/// Where the access log goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessLogDest {
    Stdout,
    Stderr,
    File(PathBuf),
}

/// Resolve `[logging] access_log`: `None` when off. A daemon has no
/// terminal, so there `stdout`/`stderr` mean `${SOLI_LOG_DIR:-.}/access.log`.
pub fn destination(value: Option<&str>, daemon: bool) -> Result<Option<AccessLogDest>> {
    let dest = match value.map(str::trim) {
        None | Some("") | Some("off") | Some("false") | Some("none") => return Ok(None),
        Some("stdout") => AccessLogDest::Stdout,
        Some("stderr") => AccessLogDest::Stderr,
        Some(other) => {
            let path = other.strip_prefix("file:").unwrap_or(other).trim();
            if path.is_empty() {
                anyhow::bail!(
                    "invalid [logging] access_log {:?} (expected \"off\", \"stdout\", \"stderr\" \
                     or a file path)",
                    other
                );
            }
            AccessLogDest::File(PathBuf::from(path))
        }
    };
    Ok(Some(match dest {
        AccessLogDest::Stdout | AccessLogDest::Stderr if daemon => {
            let dir = std::env::var("SOLI_LOG_DIR").unwrap_or_else(|_| ".".to_string());
            AccessLogDest::File(PathBuf::from(dir).join("access.log"))
        }
        dest => dest,
    }))
}

/// Resolve `[logging] access_log_format`.
pub fn format(value: Option<&str>) -> Result<AccessLogFormat> {
    match value.map(str::trim) {
        None | Some("") | Some("json") => Ok(AccessLogFormat::Json),
        Some("combined") => Ok(AccessLogFormat::Combined),
        Some(other) => anyhow::bail!(
            "invalid [logging] access_log_format {:?} (expected \"json\" or \"combined\")",
            other
        ),
    }
}

struct Sink {
    format: AccessLogFormat,
    writer: NonBlocking,
}

static SINK: OnceLock<Sink> = OnceLock::new();
static GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

/// Open the access log `cfg` describes, if any. Once per process.
pub fn init(cfg: &LoggingConfig, daemon: bool) -> Result<()> {
    let Some(dest) = destination(cfg.access_log.as_deref(), daemon)? else {
        return Ok(());
    };
    let format = format(cfg.access_log_format.as_deref())?;
    let (writer, guard) = match &dest {
        AccessLogDest::Stdout => tracing_appender::non_blocking(std::io::stdout()),
        AccessLogDest::Stderr => tracing_appender::non_blocking(std::io::stderr()),
        AccessLogDest::File(path) => {
            let (max_size, max_files) = crate::logging::rotation(cfg)?;
            let file = crate::logging::RotatingFile::open(path, max_size, max_files)
                .map_err(|e| anyhow::anyhow!("cannot open access log {}: {}", path.display(), e))?;
            tracing_appender::non_blocking(file)
        }
    };
    SINK.set(Sink { format, writer })
        .map_err(|_| anyhow::anyhow!("the access log is already open"))?;
    *GUARD.lock().unwrap_or_else(|e| e.into_inner()) = Some(guard);
    Ok(())
}

/// Whether an access log is open.
pub fn enabled() -> bool {
    SINK.get().is_some()
}

/// Flush and stop the writer (before `process::exit`).
pub fn flush() {
    let guard = GUARD.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(guard);
}

/// Where a proxied request went, for its access-log line: set by the request
/// path in the response's extensions (only while the access log is on).
#[derive(Clone, Debug)]
pub struct Upstream {
    pub target: String,
    pub app: Option<std::sync::Arc<str>>,
}

/// What is known about a request when it arrives.
pub struct Pending {
    start: Instant,
    method: Method,
    uri: Uri,
    version: Version,
    host: Option<HeaderValue>,
    user_agent: Option<HeaderValue>,
    referer: Option<HeaderValue>,
    client_ip: Option<IpAddr>,
    request_id: Option<HeaderValue>,
    tls: bool,
    bytes_in: u64,
    status: u16,
    upstream: Option<Upstream>,
}

/// Start a line for `req`, or `None` when the access log is off. Call it once
/// the door has put the client and the request ID in the extensions. Header
/// values and the URI are reference-counted: nothing is copied here.
pub fn begin<B>(req: &Request<B>, tls: bool) -> Option<Box<Pending>> {
    SINK.get()?;
    let headers = req.headers();
    Some(Box::new(Pending {
        start: Instant::now(),
        method: req.method().clone(),
        uri: req.uri().clone(),
        version: req.version(),
        host: headers.get(HOST).cloned(),
        user_agent: headers.get(USER_AGENT).cloned(),
        referer: headers.get(REFERER).cloned(),
        client_ip: crate::edge::client_ip(req.extensions()),
        request_id: crate::edge::request_id(req.extensions()).cloned(),
        tls,
        bytes_in: headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        status: 0,
        upstream: None,
    }))
}

/// Attach the line to the response: it is written when the body ends.
pub fn finish(resp: Response<BoxBody>, mut pending: Box<Pending>) -> Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    pending.status = parts.status.as_u16();
    pending.upstream = parts.extensions.remove::<Upstream>();
    let body = LoggedBody {
        inner: body,
        bytes: 0,
        ended: false,
        failed: false,
        pending: Some(pending),
    };
    Response::from_parts(parts, BodyExt::boxed(body))
}

/// Write the line of a request that produced no response at all (the
/// connection's service failed); its status is logged as 0.
pub fn failed(pending: Box<Pending>) {
    write_line(&pending, 0, false);
}

/// Response body that counts what it streams and writes the line on drop —
/// which hyper does once the body is sent, or abandoned.
struct LoggedBody {
    inner: BoxBody,
    bytes: u64,
    ended: bool,
    failed: bool,
    pending: Option<Box<Pending>>,
}

impl hyper::body::Body for LoggedBody {
    type Data = bytes::Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, Self::Error>>> {
        use std::task::Poll;
        let this = self.get_mut();
        let res = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &res {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(_))) => this.failed = true,
            Poll::Ready(None) => this.ended = true,
            Poll::Pending => {}
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

impl Drop for LoggedBody {
    fn drop(&mut self) {
        use hyper::body::Body as _;
        if let Some(pending) = self.pending.take() {
            let complete = !self.failed && (self.ended || self.inner.is_end_stream());
            write_line(&pending, self.bytes, complete);
        }
    }
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(512));
}

fn write_line(p: &Pending, bytes_out: u64, complete: bool) {
    let Some(sink) = SINK.get() else {
        return;
    };
    let micros = p.start.elapsed().as_micros() as u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let _ = BUF.try_with(|cell| {
        let Ok(mut buf) = cell.try_borrow_mut() else {
            return;
        };
        buf.clear();
        match sink.format {
            AccessLogFormat::Json => format_json(&mut buf, p, bytes_out, micros, now, complete),
            AccessLogFormat::Combined => format_combined(&mut buf, p, bytes_out, micros, now),
        }
        buf.push(b'\n');
        let mut writer = sink.writer.clone();
        let _ = writer.write_all(&buf);
        // One huge line (a 16 KiB User-Agent) must not pin the memory.
        if buf.capacity() > 64 * 1024 {
            *buf = Vec::with_capacity(512);
        }
    });
}

fn protocol(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

/// The request's host: `Host`, or the URI authority (HTTP/2's `:authority`).
fn host_of(p: &Pending) -> Option<&[u8]> {
    p.host
        .as_ref()
        .map(|h| h.as_bytes())
        .or_else(|| p.uri.authority().map(|a| a.as_str().as_bytes()))
}

fn path_of(p: &Pending) -> &str {
    p.uri.path_and_query().map_or("/", |pq| pq.as_str())
}

fn format_json(
    buf: &mut Vec<u8>,
    p: &Pending,
    bytes_out: u64,
    micros: u64,
    now: std::time::Duration,
    complete: bool,
) {
    buf.extend_from_slice(b"{\"ts\":\"");
    write_rfc3339(buf, now);
    buf.extend_from_slice(b"\",\"client_ip\":");
    match p.client_ip {
        Some(ip) => {
            let _ = write!(buf, "\"{}\"", ip);
        }
        None => buf.extend_from_slice(b"null"),
    }
    buf.extend_from_slice(b",\"method\":");
    json_str(buf, p.method.as_str().as_bytes());
    buf.extend_from_slice(b",\"host\":");
    json_opt(buf, host_of(p));
    buf.extend_from_slice(b",\"path\":");
    json_str(buf, path_of(p).as_bytes());
    let _ = write!(
        buf,
        ",\"protocol\":\"{}\",\"status\":{},\"bytes_in\":{},\"bytes_out\":{},\"duration_ms\":{}.{:03}",
        protocol(p.version),
        p.status,
        p.bytes_in,
        bytes_out,
        micros / 1000,
        micros % 1000
    );
    buf.extend_from_slice(b",\"upstream\":");
    json_opt(buf, p.upstream.as_ref().map(|u| u.target.as_bytes()));
    buf.extend_from_slice(b",\"app\":");
    json_opt(
        buf,
        p.upstream
            .as_ref()
            .and_then(|u| u.app.as_deref())
            .map(str::as_bytes),
    );
    buf.extend_from_slice(b",\"request_id\":");
    json_opt(buf, p.request_id.as_ref().map(|v| v.as_bytes()));
    buf.extend_from_slice(b",\"user_agent\":");
    json_opt(buf, p.user_agent.as_ref().map(|v| v.as_bytes()));
    buf.extend_from_slice(b",\"referer\":");
    json_opt(buf, p.referer.as_ref().map(|v| v.as_bytes()));
    let _ = write!(buf, ",\"tls\":{},\"complete\":{}}}", p.tls, complete);
}

fn format_combined(
    buf: &mut Vec<u8>,
    p: &Pending,
    bytes_out: u64,
    micros: u64,
    now: std::time::Duration,
) {
    match p.client_ip {
        Some(ip) => {
            let _ = write!(buf, "{}", ip);
        }
        None => buf.push(b'-'),
    }
    buf.extend_from_slice(b" - - [");
    write_clf_time(buf, now);
    buf.extend_from_slice(b"] \"");
    quoted_inner(buf, p.method.as_str().as_bytes());
    buf.push(b' ');
    quoted_inner(buf, path_of(p).as_bytes());
    let _ = write!(
        buf,
        " {}\" {} {} ",
        protocol(p.version),
        p.status,
        bytes_out
    );
    quoted_or_dash(buf, p.referer.as_ref().map(|v| v.as_bytes()));
    buf.push(b' ');
    quoted_or_dash(buf, p.user_agent.as_ref().map(|v| v.as_bytes()));
    buf.extend_from_slice(b" host=");
    quoted_or_dash(buf, host_of(p));
    let _ = write!(
        buf,
        " rt={}.{:06} rid=",
        micros / 1_000_000,
        micros % 1_000_000
    );
    match &p.request_id {
        // Request IDs are visible ASCII: no quoting needed.
        Some(id) => quoted_inner(buf, id.as_bytes()),
        None => buf.push(b'-'),
    }
    buf.extend_from_slice(b" upstream=");
    quoted_or_dash(buf, p.upstream.as_ref().map(|u| u.target.as_bytes()));
    buf.extend_from_slice(b" app=");
    quoted_or_dash(
        buf,
        p.upstream
            .as_ref()
            .and_then(|u| u.app.as_deref())
            .map(str::as_bytes),
    );
    let _ = write!(
        buf,
        " tls={} in={}",
        if p.tls { 'y' } else { 'n' },
        p.bytes_in
    );
}

/// A JSON string. Header values may hold any byte but CR/LF/NUL: valid UTF-8
/// goes through as is, anything else is escaped byte by byte (as Latin-1).
fn json_str(buf: &mut Vec<u8>, s: &[u8]) {
    let utf8 = std::str::from_utf8(s).is_ok();
    buf.push(b'"');
    for &b in s {
        match b {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            0x20..=0x7e => buf.push(b),
            0x80..=0xff if utf8 => buf.push(b),
            _ => {
                let _ = write!(buf, "\\u{:04x}", b);
            }
        }
    }
    buf.push(b'"');
}

fn json_opt(buf: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => json_str(buf, s),
        None => buf.extend_from_slice(b"null"),
    }
}

/// The inside of a combined-format quoted field: `"` and `\` escaped, any
/// byte that is not printable ASCII written `\xHH` (as nginx does), so a
/// field can never end a line or forge another.
fn quoted_inner(buf: &mut Vec<u8>, s: &[u8]) {
    for &b in s {
        match b {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            0x20..=0x7e => buf.push(b),
            _ => {
                let _ = write!(buf, "\\x{:02X}", b);
            }
        }
    }
}

fn quoted_or_dash(buf: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => {
            buf.push(b'"');
            quoted_inner(buf, s);
            buf.push(b'"');
        }
        None => buf.push(b'-'),
    }
}

/// (year, month, day) of a day count since 1970-01-01 (proleptic Gregorian;
/// Howard Hinnant's `civil_from_days`). Plain integer arithmetic: no
/// allocation, no time-zone database.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn split_time(now: std::time::Duration) -> ((i64, u32, u32), u64, u64, u64, u32) {
    let secs = now.as_secs();
    let date = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    (
        date,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        now.subsec_millis(),
    )
}

/// `2026-10-01T12:34:56.789Z`
fn write_rfc3339(buf: &mut Vec<u8>, now: std::time::Duration) {
    let ((y, mo, d), h, mi, s, ms) = split_time(now);
    let _ = write!(
        buf,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, ms
    );
}

/// `01/Oct/2026:12:34:56 +0000`
fn write_clf_time(buf: &mut Vec<u8>, now: std::time::Duration) {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let ((y, mo, d), h, mi, s, _) = split_time(now);
    let _ = write!(
        buf,
        "{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
        d,
        MONTHS[(mo as usize - 1) % 12],
        y,
        h,
        mi,
        s
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pending() -> Pending {
        Pending {
            start: Instant::now(),
            method: Method::GET,
            uri: "/a/b?c=1".parse().unwrap(),
            version: Version::HTTP_11,
            host: Some(HeaderValue::from_static("example.com")),
            user_agent: Some(HeaderValue::from_static("curl/8.0 \"quoted\" \\ back")),
            referer: None,
            client_ip: Some("203.0.113.9".parse().unwrap()),
            request_id: Some(HeaderValue::from_static("0123abcd")),
            tls: true,
            bytes_in: 12,
            status: 200,
            upstream: Some(Upstream {
                target: "http://127.0.0.1:3000/a/b".into(),
                app: Some("blog".into()),
            }),
        }
    }

    // 2026-10-01T12:34:56.789Z
    const NOW: Duration = Duration::from_millis(1_790_858_096_789);

    #[test]
    fn dates_match_chrono() {
        for secs in [
            0i64,
            951_782_400,
            1_790_858_096,
            4_107_542_400,
            86_399,
            1_709_164_800,
        ] {
            let ours = {
                let mut b = Vec::new();
                write_rfc3339(&mut b, Duration::from_secs(secs as u64));
                String::from_utf8(b).unwrap()
            };
            let theirs = chrono::DateTime::from_timestamp(secs, 0)
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string();
            assert_eq!(ours, theirs);
            let ours = {
                let mut b = Vec::new();
                write_clf_time(&mut b, Duration::from_secs(secs as u64));
                String::from_utf8(b).unwrap()
            };
            let theirs = chrono::DateTime::from_timestamp(secs, 0)
                .unwrap()
                .format("%d/%b/%Y:%H:%M:%S +0000")
                .to_string();
            assert_eq!(ours, theirs);
        }
    }

    #[test]
    fn json_line_is_valid_json_with_every_field() {
        let mut buf = Vec::new();
        format_json(&mut buf, &pending(), 345, 12_345, NOW, true);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["ts"], "2026-10-01T12:34:56.789Z");
        assert_eq!(v["client_ip"], "203.0.113.9");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["host"], "example.com");
        assert_eq!(v["path"], "/a/b?c=1");
        assert_eq!(v["protocol"], "HTTP/1.1");
        assert_eq!(v["status"], 200);
        assert_eq!(v["bytes_in"], 12);
        assert_eq!(v["bytes_out"], 345);
        assert_eq!(v["duration_ms"].as_f64().unwrap(), 12.345);
        assert_eq!(v["upstream"], "http://127.0.0.1:3000/a/b");
        assert_eq!(v["app"], "blog");
        assert_eq!(v["request_id"], "0123abcd");
        assert_eq!(v["user_agent"], "curl/8.0 \"quoted\" \\ back");
        assert!(v["referer"].is_null());
        assert_eq!(v["tls"], true);
        assert_eq!(v["complete"], true);
    }

    #[test]
    fn json_escapes_control_and_non_utf8_bytes() {
        let mut buf = Vec::new();
        json_str(&mut buf, b"a\tb\x01");
        assert_eq!(buf, b"\"a\\u0009b\\u0001\"");
        let mut buf = Vec::new();
        json_str(&mut buf, "café".as_bytes());
        assert_eq!(serde_json::from_slice::<String>(&buf).unwrap(), "café");
        let mut buf = Vec::new();
        json_str(&mut buf, b"\xff\xfe");
        assert_eq!(
            serde_json::from_slice::<String>(&buf).unwrap(),
            "\u{ff}\u{fe}"
        );
    }

    #[test]
    fn combined_line_has_the_standard_prefix() {
        let mut p = pending();
        p.upstream = None;
        p.request_id = None;
        let mut buf = Vec::new();
        format_combined(&mut buf, &p, 345, 1_234_567, NOW);
        let line = String::from_utf8(buf).unwrap();
        assert_eq!(
            line,
            "203.0.113.9 - - [01/Oct/2026:12:34:56 +0000] \"GET /a/b?c=1 HTTP/1.1\" 200 345 - \
             \"curl/8.0 \\\"quoted\\\" \\\\ back\" host=\"example.com\" rt=1.234567 rid=- \
             upstream=- app=- tls=y in=12"
        );
        // A byte that could end the line is escaped.
        let mut buf = Vec::new();
        quoted_inner(&mut buf, b"a\nb\xff");
        assert_eq!(buf, b"a\\x0Ab\\xFF");
    }

    #[test]
    fn destinations_and_formats() {
        assert_eq!(destination(None, false).unwrap(), None);
        assert_eq!(destination(Some("off"), false).unwrap(), None);
        assert_eq!(
            destination(Some("stdout"), false).unwrap(),
            Some(AccessLogDest::Stdout)
        );
        assert_eq!(
            destination(Some("/var/log/a.log"), false).unwrap(),
            Some(AccessLogDest::File("/var/log/a.log".into()))
        );
        assert_eq!(
            destination(Some("file:/var/log/a.log"), false).unwrap(),
            Some(AccessLogDest::File("/var/log/a.log".into()))
        );
        assert!(matches!(
            destination(Some("stdout"), true).unwrap(),
            Some(AccessLogDest::File(p)) if p.ends_with("access.log")
        ));
        assert!(destination(Some("file:"), false).is_err());
        assert_eq!(format(None).unwrap(), AccessLogFormat::Json);
        assert_eq!(format(Some("combined")).unwrap(), AccessLogFormat::Combined);
        assert!(format(Some("common")).is_err());
    }
}
