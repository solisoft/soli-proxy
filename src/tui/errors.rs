//! Parsing of request-failure events from the daemon's `proxy.log`.
//!
//! The daemon has no structured per-error store — it only increments atomic
//! counters. The richest source of individual, timestamped request failures is
//! the access log emitted by `[logging].log_endpoints = true` (see
//! `src/server/mod.rs`), written as `tracing` JSON lines:
//!
//! ```json
//! {"timestamp":"..","level":"INFO","fields":{"message":"endpoint request",
//!   "method":"GET","host":"x","path":"/","status":502,"elapsed_ms":3,..},"target":".."}
//! ```
//!
//! A request is a failure when the message is `"endpoint request failed"` (the
//! handler returned an error, e.g. backend connect failure) or when it is
//! `"endpoint request"` with a 5xx status — mirroring the metrics' own success
//! definition of `200..500` (`src/metrics.rs`).

use std::io::{Read, Seek, SeekFrom};

/// A single parsed request-failure event.
#[derive(Clone)]
pub struct ErrorEntry {
    pub timestamp: String,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub client_ip: Option<String>,
    pub elapsed_ms: Option<u64>,
}

/// Only parse the tail of the log — it can grow large and this runs on every
/// ~2s tick.
const TAIL_BYTES: u64 = 256 * 1024;
/// Cap on how many failures we keep in memory / show.
const MAX_ERRORS: usize = 500;

/// Resolve the daemon log path the same way `get_log_path()` does in `main.rs`:
/// `${SOLI_LOG_DIR:-.}/proxy.log`.
fn log_path() -> String {
    let dir = std::env::var("SOLI_LOG_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/proxy.log", dir)
}

/// Read the tail of `proxy.log`, parse request-failure lines, and return them
/// oldest-first (so `G`/scroll-to-bottom lands on the most recent, consistent
/// with the log viewer). Best effort: returns empty on any IO/parse trouble.
pub fn load_request_errors() -> Vec<ErrorEntry> {
    let path = log_path();
    let Ok(mut file) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return Vec::new();
    };

    let start = len.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        // Tail may slice a multi-byte UTF-8 char; fall back to lossy bytes.
        let mut bytes = Vec::new();
        if file.seek(SeekFrom::Start(start)).is_err() || file.read_to_end(&mut bytes).is_err() {
            return Vec::new();
        }
        buf = String::from_utf8_lossy(&bytes).into_owned();
    }

    let mut lines = buf.lines();
    // The first line is likely a partial record from slicing mid-file — drop it
    // unless we started at the very beginning of the file.
    if start > 0 {
        lines.next();
    }

    let mut out: Vec<ErrorEntry> = lines.filter_map(parse_failure_line).collect();
    if out.len() > MAX_ERRORS {
        out.drain(0..out.len() - MAX_ERRORS);
    }
    out
}

/// Parse one JSON log line into an `ErrorEntry` if it represents a request
/// failure, else `None`.
fn parse_failure_line(line: &str) -> Option<ErrorEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let fields = v.get("fields")?;
    let message = fields.get("message").and_then(|m| m.as_str())?;

    let status = fields
        .get("status")
        .and_then(|s| s.as_u64())
        .map(|s| s as u16);

    let is_failure = match message {
        "endpoint request failed" => true,
        "endpoint request" => status.is_some_and(|s| s >= 500),
        _ => false,
    };
    if !is_failure {
        return None;
    }

    let str_field = |key: &str| fields.get(key).and_then(|x| x.as_str()).map(String::from);

    Some(ErrorEntry {
        timestamp: v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
        method: str_field("method"),
        host: str_field("host"),
        path: str_field("path"),
        status,
        error: str_field("error"),
        client_ip: str_field("client_ip"),
        elapsed_ms: fields.get("elapsed_ms").and_then(|e| e.as_u64()),
    })
}

impl ErrorEntry {
    /// One-line status token for the list view: `502` or `ERR`.
    pub fn status_label(&self) -> String {
        match self.status {
            Some(s) => s.to_string(),
            None => "ERR".to_string(),
        }
    }

    /// Render the full multi-line block shown in the detail modal and copied to
    /// the clipboard.
    pub fn detail_block(&self) -> String {
        let dash = "-".to_string();
        let mut s = String::new();
        s.push_str(&format!("Time:      {}\n", self.timestamp));
        s.push_str(&format!("Status:    {}\n", self.status_label()));
        s.push_str(&format!(
            "Method:    {}\n",
            self.method.as_ref().unwrap_or(&dash)
        ));
        s.push_str(&format!(
            "Host:      {}\n",
            self.host.as_ref().unwrap_or(&dash)
        ));
        s.push_str(&format!(
            "Path:      {}\n",
            self.path.as_ref().unwrap_or(&dash)
        ));
        s.push_str(&format!(
            "Client IP: {}\n",
            self.client_ip.as_ref().unwrap_or(&dash)
        ));
        s.push_str(&format!(
            "Elapsed:   {}\n",
            self.elapsed_ms
                .map(|m| format!("{} ms", m))
                .unwrap_or_else(|| dash.clone())
        ));
        if let Some(ref e) = self.error {
            s.push_str(&format!("Error:     {}\n", e));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ_5XX: &str = r#"{"timestamp":"2026-06-04T09:20:32.276889Z","level":"INFO","fields":{"message":"endpoint request","layer":"endpoint","method":"POST","scheme":"https","host":"bonfire.solisoft.test","path":"/_jobs/run/X","status":500,"elapsed_ms":1,"client_ip":"192.168.1.30"},"target":"soli_proxy::server"}"#;
    const REQ_2XX: &str = r#"{"timestamp":"2026-06-04T09:20:32Z","level":"INFO","fields":{"message":"endpoint request","method":"GET","status":200},"target":"soli_proxy::server"}"#;
    const REQ_4XX: &str = r#"{"timestamp":"2026-06-04T09:20:32Z","level":"INFO","fields":{"message":"endpoint request","method":"GET","status":404},"target":"soli_proxy::server"}"#;
    const REQ_FAILED: &str = r#"{"timestamp":"2026-06-04T09:20:32Z","level":"INFO","fields":{"message":"endpoint request failed","method":"GET","host":"x","path":"/","error":"connection refused","client_ip":"1.2.3.4","elapsed_ms":3},"target":"soli_proxy::server"}"#;
    const OTHER: &str = r#"{"timestamp":"2026-06-04T09:20:32Z","level":"INFO","fields":{"message":"App manager initialized"},"target":"soli_proxy"}"#;

    #[test]
    fn keeps_5xx_and_failed_only() {
        let e = parse_failure_line(REQ_5XX).expect("5xx is a failure");
        assert_eq!(e.status, Some(500));
        assert_eq!(e.method.as_deref(), Some("POST"));
        assert_eq!(e.path.as_deref(), Some("/_jobs/run/X"));

        let f = parse_failure_line(REQ_FAILED).expect("failed request is a failure");
        assert_eq!(f.status, None);
        assert_eq!(f.error.as_deref(), Some("connection refused"));
        assert_eq!(f.status_label(), "ERR");

        assert!(parse_failure_line(REQ_2XX).is_none());
        assert!(parse_failure_line(REQ_4XX).is_none());
        assert!(parse_failure_line(OTHER).is_none());
        assert!(parse_failure_line("not json").is_none());
    }

    #[test]
    fn detail_block_includes_key_fields() {
        let block = parse_failure_line(REQ_5XX).unwrap().detail_block();
        assert!(block.contains("Status:    500"));
        assert!(block.contains("Host:      bonfire.solisoft.test"));
        assert!(block.contains("2026-06-04T09:20:32.276889Z"));
    }
}
