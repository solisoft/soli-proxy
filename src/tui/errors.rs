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
    /// Logged since 1.4; empty when the client sent none.
    pub user_agent: Option<String>,
}

/// How much of the log the first read covers, from its end. A dev proxy logs
/// a line per request — livereload sockets and asset fetches included — so
/// the 256 KB this used to read held a few hundred lines and the failures of
/// an hour ago were already out of sight while the counters still showed
/// them. Lines that cannot be failures are skipped before any JSON parsing,
/// so a large window stays cheap.
const INITIAL_SCAN_BYTES: u64 = 16 * 1024 * 1024;
/// Most a single refresh reads: a burst beyond it skips ahead rather than
/// stalling the screen.
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;
/// Cap on how many entries we keep in memory / show.
const MAX_ERRORS: usize = 500;

/// Follows the daemon's log: one scan of its last [`INITIAL_SCAN_BYTES`],
/// then only what was appended since, a tick at a time. Survives rotation and
/// truncation (the file shrinking starts it over from the top).
pub struct ErrorLog {
    path: std::path::PathBuf,
    offset: Option<u64>,
    /// A line cut by the end of the last read, completed by the next one.
    partial: Vec<u8>,
    /// Oldest first.
    entries: std::collections::VecDeque<ErrorEntry>,
}

impl ErrorLog {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            offset: None,
            partial: Vec::new(),
            entries: std::collections::VecDeque::new(),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Read what the log gained since the last call. Best effort: a missing
    /// or unreadable file leaves the entries as they were.
    pub fn refresh(&mut self) {
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return;
        };
        let Ok(len) = file.metadata().map(|m| m.len()) else {
            return;
        };
        let mut start = match self.offset {
            None => len.saturating_sub(INITIAL_SCAN_BYTES),
            // Rotated or truncated: what is there now is new.
            Some(off) if len < off => 0,
            Some(off) => off,
        };
        if len - start > MAX_READ_BYTES {
            start = len - MAX_READ_BYTES;
            self.partial.clear();
        }
        // Started mid-file, not where the last read stopped: the first line
        // is cut. Skip it.
        let cut = start > 0 && self.offset != Some(start);
        if file.seek(SeekFrom::Start(start)).is_err() {
            return;
        }
        let mut bytes = Vec::with_capacity((len - start) as usize);
        if (&mut file)
            .take(len - start)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return;
        }
        self.offset = Some(start + bytes.len() as u64);
        let mut data = std::mem::take(&mut self.partial);
        if cut {
            data.clear();
        }
        data.extend_from_slice(&bytes);
        let complete = match data.iter().rposition(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => {
                self.partial = data;
                return;
            }
        };
        self.partial = data[complete..].to_vec();
        let text = String::from_utf8_lossy(&data[..complete]);
        let mut lines = text.lines();
        if cut {
            lines.next();
        }
        for line in lines {
            if !may_be_failure(line) {
                continue;
            }
            if let Some(e) = parse_failure_line(line) {
                if self.entries.len() >= MAX_ERRORS {
                    self.entries.pop_front();
                }
                self.entries.push_back(e);
            }
        }
    }

    /// Every entry kept, newest first.
    pub fn newest_first(&self) -> Vec<ErrorEntry> {
        self.entries.iter().rev().cloned().collect()
    }
}

/// A cheap test that skips the lines that cannot be failures — most of
/// them — before any JSON parsing.
fn may_be_failure(line: &str) -> bool {
    line.contains("endpoint request failed")
        || line.contains("\"status\":5")
        || line.contains("\"status\":404")
}

/// Read the tail of the daemon's log at `path` and return its failures and
/// 404s oldest-first: an [`ErrorLog`]'s first read, for one-off callers.
pub fn load_request_errors(path: &std::path::Path) -> Vec<ErrorEntry> {
    let mut log = ErrorLog::new(path.to_path_buf());
    log.refresh();
    log.entries.into_iter().collect()
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

    // Failures, and the 404s: a missing page is not the server's fault, but
    // which URLs are asked for and missing (a broken link, a scanner) is
    // worth seeing next to them.
    let is_failure = match message {
        "endpoint request failed" => true,
        "endpoint request" => status.is_some_and(|s| s >= 500 || s == 404),
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
        user_agent: str_field("user_agent").filter(|u| !u.is_empty()),
    })
}

impl ErrorEntry {
    /// Identifies the failure across re-reads of the log, to tell which
    /// rows are new.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.timestamp,
            self.host.as_deref().unwrap_or(""),
            self.path.as_deref().unwrap_or(""),
            self.status_label()
        )
    }

    /// Local wall-clock time of the failure, `HH:MM:SS`; the raw timestamp
    /// when it does not parse.
    pub fn clock(&self) -> String {
        chrono::DateTime::parse_from_rfc3339(&self.timestamp)
            .map(|t| {
                t.with_timezone(&chrono::Local)
                    .format("%H:%M:%S")
                    .to_string()
            })
            .unwrap_or_else(|_| self.timestamp.clone())
    }

    /// A 5xx, or a request that got no response at all.
    pub fn is_server_error(&self) -> bool {
        self.status.is_none_or(|s| s >= 500)
    }

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
        if let Some(ref ua) = self.user_agent {
            s.push_str(&format!("Agent:     {}\n", ua));
        }
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
    fn keeps_5xx_failed_and_404_only() {
        let e = parse_failure_line(REQ_5XX).expect("5xx is a failure");
        assert_eq!(e.status, Some(500));
        assert_eq!(e.method.as_deref(), Some("POST"));
        assert_eq!(e.path.as_deref(), Some("/_jobs/run/X"));

        let f = parse_failure_line(REQ_FAILED).expect("failed request is a failure");
        assert_eq!(f.status, None);
        assert_eq!(f.error.as_deref(), Some("connection refused"));
        assert_eq!(f.status_label(), "ERR");

        assert!(e.is_server_error() && f.is_server_error());

        let nf = parse_failure_line(REQ_4XX).expect("a 404 is kept");
        assert_eq!(nf.status, Some(404));
        assert!(!nf.is_server_error());

        assert!(parse_failure_line(REQ_2XX).is_none());
        assert!(parse_failure_line(&REQ_4XX.replace("404", "403")).is_none());
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

#[cfg(test)]
mod follow_tests {
    use super::*;
    use std::io::Write;

    fn line(status: u16, path: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-10-06T09:00:00Z","level":"INFO","fields":{{"message":"endpoint request","method":"GET","host":"a.test","path":"{path}","status":{status}}},"target":"soli_proxy::server"}}"#
        ) + "\n"
    }

    #[test]
    fn follows_appends_partial_lines_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut f = std::fs::File::create(&path).unwrap();
        // A failure buried under thousands of ordinary lines is still found.
        f.write_all(line(502, "/old").as_bytes()).unwrap();
        for _ in 0..5000 {
            f.write_all(line(200, "/ok").as_bytes()).unwrap();
        }
        f.flush().unwrap();

        let mut log = ErrorLog::new(path.clone());
        log.refresh();
        assert_eq!(log.newest_first().len(), 1);

        // An append is picked up, even one cut mid-line between two reads.
        let next = line(404, "/missing");
        let (a, b) = next.split_at(40);
        f.write_all(a.as_bytes()).unwrap();
        f.flush().unwrap();
        log.refresh();
        assert_eq!(log.newest_first().len(), 1, "half a line is not a line");
        f.write_all(b.as_bytes()).unwrap();
        f.flush().unwrap();
        log.refresh();
        let rows = log.newest_first();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path.as_deref(), Some("/missing"));

        // Rotation: the file starts over, and what is in it now is new.
        drop(f);
        std::fs::write(&path, line(500, "/after")).unwrap();
        log.refresh();
        assert_eq!(log.newest_first()[0].path.as_deref(), Some("/after"));
    }
}
