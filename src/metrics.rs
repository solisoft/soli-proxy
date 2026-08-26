use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
struct CpuSnapshot {
    total_time: u64,
    timestamp: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_in_flight: usize,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors_total: u64,
    pub tls_connections: u64,
    pub avg_response_time_ms: f64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppMetricsJson {
    pub requests: u64,
    /// Unix milliseconds of this app's most recent request, or `None` if it has
    /// had none since the proxy started.
    ///
    /// The signal an idleness policy needs, and the reason it is a wall-clock
    /// timestamp rather than an age: a caller comparing ages has to trust that its
    /// clock and the proxy's tick at the same rate over an interval it did not
    /// choose. A timestamp it can subtract from its own clock is one fewer
    /// assumption, and the skew shows up as a bounded error rather than a drift.
    ///
    /// `None` is deliberately not zero. An app that has never been requested and
    /// one requested at the epoch are different facts, and a policy that suspends
    /// on "age since 0" would suspend everything on the first pass after a proxy
    /// restart.
    pub last_request_ms: Option<u64>,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub avg_response_time_ms: f64,
    pub errors: u64,
    pub memory_rss_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SlotMetrics {
    pub memory_rss_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
}

/// One app's resource use, added up across the slots that are running.
///
/// Summed rather than taken from the live slot alone: during a blue/green
/// deploy both slots hold their memory, and that overlap is exactly the moment
/// an app costs the most. Reporting only the serving slot would understate the
/// peak — and this figure is the basis for metered billing, so understating it
/// is not a display bug.
///
/// **`None` is not zero.** An app with no running process has *no measurement*,
/// which is a different statement from "measured, and it was zero". A stopped
/// app that reads as `0 MB` looks free; one that reads as `null` looks absent,
/// which is what it is. The same holds for CPU: the first sample of a process
/// has no previous sample to difference against, so it stays `None` rather
/// than reading as an idle 0%.
pub fn sum_slot_metrics(slots: &[SlotMetrics]) -> SlotMetrics {
    let mut memory_rss_bytes: Option<u64> = None;
    let mut cpu_percent: Option<f64> = None;

    for slot in slots {
        if let Some(rss) = slot.memory_rss_bytes {
            memory_rss_bytes = Some(memory_rss_bytes.unwrap_or(0).saturating_add(rss));
        }
        if let Some(cpu) = slot.cpu_percent {
            cpu_percent = Some(cpu_percent.unwrap_or(0.0) + cpu);
        }
    }

    SlotMetrics {
        memory_rss_bytes,
        cpu_percent,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AppSystemMetrics {
    pub blue: SlotMetrics,
    pub green: SlotMetrics,
}

#[derive(Clone)]
pub struct AppMetrics {
    pub requests_total: Arc<AtomicU64>,
    /// Unix milliseconds of the last request. 0 means "none yet".
    pub last_request_ms: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub response_time_nanos_sum: Arc<AtomicU64>,
    pub response_time_count: Arc<AtomicU64>,
    pub errors_total: Arc<AtomicU64>,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            last_request_ms: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            response_time_nanos_sum: Arc::new(AtomicU64::new(0)),
            response_time_count: Arc::new(AtomicU64::new(0)),
            errors_total: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Wall-clock milliseconds since the Unix epoch.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 0 is the sentinel for "no request yet", and it must not reach a caller as a
/// timestamp — see [`AppMetricsJson::last_request_ms`].
fn nonzero(ms: u64) -> Option<u64> {
    (ms != 0).then_some(ms)
}

/// Status code array size: covers HTTP codes 100-599
const STATUS_ARRAY_SIZE: usize = 512;

#[derive(Clone)]
pub struct Metrics {
    pub requests_total: Arc<AtomicU64>,
    pub requests_in_flight: Arc<AtomicUsize>,
    pub bytes_received: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    response_time_nanos_sum: Arc<AtomicU64>,
    response_time_count: Arc<AtomicU64>,
    status_codes: Arc<[AtomicU64; STATUS_ARRAY_SIZE]>,
    tls_connections: Arc<AtomicU64>,
    pub errors_total: Arc<AtomicU64>,
    last_request_nanos: Arc<AtomicU64>,
    epoch_start: Instant,
    app_metrics: Arc<parking_lot::RwLock<HashMap<String, AppMetrics>>>,
    cpu_snapshots: Arc<parking_lot::RwLock<HashMap<u32, CpuSnapshot>>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_in_flight: Arc::new(AtomicUsize::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            response_time_nanos_sum: Arc::new(AtomicU64::new(0)),
            response_time_count: Arc::new(AtomicU64::new(0)),
            status_codes: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            tls_connections: Arc::new(AtomicU64::new(0)),
            errors_total: Arc::new(AtomicU64::new(0)),
            last_request_nanos: Arc::new(AtomicU64::new(0)),
            epoch_start: Instant::now(),
            app_metrics: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            cpu_snapshots: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    /// Clonable handle to an app's `bytes_sent` counter (creates the app
    /// entry if needed). Used by the streaming response-body counter, which
    /// outlives the request handler.
    pub fn app_bytes_sent_counter(&self, app_name: &str) -> Arc<AtomicU64> {
        let mut apps = self.app_metrics.write();
        apps.entry(app_name.to_string())
            .or_default()
            .bytes_sent
            .clone()
    }

    pub fn get_app_metrics(&self, app_name: &str) -> Option<AppMetricsJson> {
        let apps = self.app_metrics.read();
        apps.get(app_name).map(|m| AppMetricsJson {
            last_request_ms: nonzero(m.last_request_ms.load(Ordering::Relaxed)),
            requests: m.requests_total.load(Ordering::Relaxed),
            bytes_received: m.bytes_received.load(Ordering::Relaxed),
            bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
            avg_response_time_ms: {
                let count = m.response_time_count.load(Ordering::Relaxed);
                if count == 0 {
                    0.0
                } else {
                    let sum = m.response_time_nanos_sum.load(Ordering::Relaxed);
                    (sum as f64) / (count as f64) / 1_000_000.0
                }
            },
            errors: m.errors_total.load(Ordering::Relaxed),
            memory_rss_bytes: None,
            cpu_percent: None,
        })
    }

    pub fn get_all_app_metrics(&self) -> HashMap<String, AppMetricsJson> {
        let apps = self.app_metrics.read();
        apps.iter()
            .map(|(name, m)| {
                (
                    name.clone(),
                    AppMetricsJson {
                        last_request_ms: nonzero(m.last_request_ms.load(Ordering::Relaxed)),
                        requests: m.requests_total.load(Ordering::Relaxed),
                        bytes_received: m.bytes_received.load(Ordering::Relaxed),
                        bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
                        avg_response_time_ms: {
                            let count = m.response_time_count.load(Ordering::Relaxed);
                            if count == 0 {
                                0.0
                            } else {
                                let sum = m.response_time_nanos_sum.load(Ordering::Relaxed);
                                (sum as f64) / (count as f64) / 1_000_000.0
                            }
                        },
                        errors: m.errors_total.load(Ordering::Relaxed),
                        memory_rss_bytes: None,
                        cpu_percent: None,
                    },
                )
            })
            .collect()
    }

    #[cfg(unix)]
    pub fn get_process_stats(&self, pid: u32) -> Option<SlotMetrics> {
        let stat_path = format!("/proc/{}/stat", pid);
        let status_path = format!("/proc/{}/status", pid);

        let mut memory_bytes: Option<u64> = None;
        if let Ok(content) = std::fs::read_to_string(&status_path) {
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            memory_bytes = Some(kb * 1024);
                        }
                    }
                    break;
                }
            }
        }

        let mut cpu_percent: Option<f64> = None;
        if let Ok(content) = std::fs::read_to_string(&stat_path) {
            // `rfind`, not `find`: `comm` is the executable name in parentheses
            // and may itself contain `)`. Finding the first one shifts every
            // field after it, silently.
            if let Some(close) = content.rfind(')') {
                let parts: Vec<&str> = content[close + 2..].split_whitespace().collect();
                {
                    if parts.len() >= 14 {
                        // The slice starts at field 3, so field N is
                        // `parts[N - 3]`: utime is field 14 and stime is 15.
                        //
                        // This read `parts[12]` and `parts[13]`, which are
                        // **stime and cutime** — measured on the running proxy,
                        // `ps` reported 46s of CPU while this computed 160s.
                        // `cutime` accumulates the CPU of reaped children and
                        // never decreases, so every app restart inflated the
                        // figure permanently. Soli Cloud meters usage from
                        // these numbers, so the error was about to become a
                        // billing error.
                        let utime: u64 = parts[11].parse().unwrap_or(0);
                        let stime: u64 = parts[12].parse().unwrap_or(0);
                        let total_time = utime + stime;

                        let now = Instant::now();
                        let prev = self.cpu_snapshots.read().get(&pid).cloned();

                        if let Some(prev_snapshot) = prev {
                            let delta_time = now.duration_since(prev_snapshot.timestamp);
                            if delta_time.as_secs_f64() > 0.0 {
                                let delta_cpu = total_time as f64 - prev_snapshot.total_time as f64;
                                // `sysconf(_SC_CLK_TCK)`, not a hardcoded
                                // 100. It is 100 on every mainstream x86 Linux
                                // and not guaranteed — a wrong divisor scales
                                // every CPU figure by a constant nobody
                                // notices until they compare with `top`.
                                let hz = clock_ticks_per_second();
                                cpu_percent =
                                    Some((delta_cpu / hz) / delta_time.as_secs_f64() * 100.0);
                            }
                        }

                        self.cpu_snapshots.write().insert(
                            pid,
                            CpuSnapshot {
                                total_time,
                                timestamp: now,
                            },
                        );
                    }
                }
            }
        }

        if memory_bytes.is_none() && cpu_percent.is_none() {
            return None;
        }

        Some(SlotMetrics {
            memory_rss_bytes: memory_bytes,
            cpu_percent,
        })
    }

    #[cfg(not(unix))]
    pub fn get_process_stats(&self, _pid: u32) -> Option<SlotMetrics> {
        None
    }

    pub fn record_request(
        &self,
        bytes_in: u64,
        bytes_out: u64,
        status: u16,
        duration: std::time::Duration,
    ) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);

        // Lock-free EWMA: accumulate nanos sum and count
        self.response_time_nanos_sum
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
        self.response_time_count.fetch_add(1, Ordering::Relaxed);

        // Lock-free status code: index by (code - 100), bounds-checked
        if status >= 100 && (status as usize - 100) < STATUS_ARRAY_SIZE {
            self.status_codes[status as usize - 100].fetch_add(1, Ordering::Relaxed);
        }

        // Lock-free last request time
        let nanos = self.epoch_start.elapsed().as_nanos() as u64;
        self.last_request_nanos.store(nanos, Ordering::Relaxed);
    }

    pub fn record_app_request(
        &self,
        app_name: &str,
        bytes_in: u64,
        bytes_out: u64,
        status: u16,
        duration: std::time::Duration,
    ) {
        let success = (200..500).contains(&status);
        self.record_app_request_with_success(app_name, bytes_in, bytes_out, duration, success);
    }

    pub fn record_app_request_with_success(
        &self,
        app_name: &str,
        bytes_in: u64,
        bytes_out: u64,
        duration: std::time::Duration,
        success: bool,
    ) {
        let app_name = app_name.to_string();
        {
            let mut apps = self.app_metrics.write();
            apps.entry(app_name.clone()).or_default();
        }

        let app_metrics = {
            let apps = self.app_metrics.read();
            apps.get(&app_name).cloned()
        };

        if let Some(metrics) = app_metrics {
            metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            // Stored, not maxed: the clock can step backwards over NTP, and a
            // monotone-only field would then freeze an app's last-request time at
            // a future value and keep it from ever looking idle.
            metrics
                .last_request_ms
                .store(unix_millis(), Ordering::Relaxed);
            metrics
                .bytes_received
                .fetch_add(bytes_in, Ordering::Relaxed);
            metrics.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);
            metrics
                .response_time_nanos_sum
                .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
            metrics.response_time_count.fetch_add(1, Ordering::Relaxed);
            if !success {
                metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn inc_in_flight(&self) {
        self.requests_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_in_flight(&self) {
        self.requests_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_tls_connections(&self) {
        self.tls_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of metrics for the TUI dashboard.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let requests = self.requests_total.load(Ordering::Relaxed);
        let in_flight = self.requests_in_flight.load(Ordering::Relaxed);
        let bytes_in = self.bytes_received.load(Ordering::Relaxed);
        let bytes_out = self.bytes_sent.load(Ordering::Relaxed);
        let tls = self.tls_connections.load(Ordering::Relaxed);
        let errors = self.errors_total.load(Ordering::Relaxed);

        let avg_response_time_ms = {
            let count = self.response_time_count.load(Ordering::Relaxed);
            if count == 0 {
                0.0
            } else {
                let sum = self.response_time_nanos_sum.load(Ordering::Relaxed);
                (sum as f64) / (count as f64) / 1_000_000.0
            }
        };

        let mut status_2xx = 0u64;
        let mut status_3xx = 0u64;
        let mut status_4xx = 0u64;
        let mut status_5xx = 0u64;
        for i in 0..STATUS_ARRAY_SIZE {
            let count = self.status_codes[i].load(Ordering::Relaxed);
            if count > 0 {
                let code = (i + 100) as u16;
                match code {
                    200..=299 => status_2xx += count,
                    300..=399 => status_3xx += count,
                    400..=499 => status_4xx += count,
                    500..=599 => status_5xx += count,
                    _ => {}
                }
            }
        }

        MetricsSnapshot {
            requests_total: requests,
            requests_in_flight: in_flight,
            bytes_received: bytes_in,
            bytes_sent: bytes_out,
            errors_total: errors,
            tls_connections: tls,
            avg_response_time_ms,
            status_2xx,
            status_3xx,
            status_4xx,
            status_5xx,
        }
    }

    pub fn format_metrics(&self) -> String {
        let requests = self.requests_total.load(Ordering::Relaxed);
        let in_flight = self.requests_in_flight.load(Ordering::Relaxed);
        let bytes_in = self.bytes_received.load(Ordering::Relaxed);
        let bytes_out = self.bytes_sent.load(Ordering::Relaxed);
        let tls = self.tls_connections.load(Ordering::Relaxed);
        let errors = self.errors_total.load(Ordering::Relaxed);

        let avg_response_time = {
            let count = self.response_time_count.load(Ordering::Relaxed);
            if count == 0 {
                0.0
            } else {
                let sum = self.response_time_nanos_sum.load(Ordering::Relaxed);
                (sum as f64) / (count as f64) / 1_000_000_000.0
            }
        };

        // Collect non-zero status codes from the array
        let mut status_entries: Vec<(u16, u64)> = Vec::new();
        for i in 0..STATUS_ARRAY_SIZE {
            let count = self.status_codes[i].load(Ordering::Relaxed);
            if count > 0 {
                status_entries.push(((i + 100) as u16, count));
            }
        }

        let mut output = String::new();
        output.push_str("# HELP proxy_requests_total Total number of HTTP requests\n");
        output.push_str("# TYPE proxy_requests_total counter\n");
        output.push_str(&format!("proxy_requests_total {}\n", requests));

        output.push_str(
            "# HELP proxy_requests_in_flight Number of requests currently being processed\n",
        );
        output.push_str("# TYPE proxy_requests_in_flight gauge\n");
        output.push_str(&format!("proxy_requests_in_flight {}\n", in_flight));

        output.push_str("# HELP proxy_bytes_received Total bytes received from clients\n");
        output.push_str("# TYPE proxy_bytes_received counter\n");
        output.push_str(&format!("proxy_bytes_received {}\n", bytes_in));

        output.push_str("# HELP proxy_bytes_sent Total bytes sent to clients\n");
        output.push_str("# TYPE proxy_bytes_sent counter\n");
        output.push_str(&format!("proxy_bytes_sent {}\n", bytes_out));

        output.push_str("# HELP proxy_response_time_seconds Average response time in seconds\n");
        output.push_str("# TYPE proxy_response_time_seconds gauge\n");
        output.push_str(&format!(
            "proxy_response_time_seconds {}\n",
            avg_response_time
        ));

        output.push_str("# HELP proxy_tls_connections_total Total number of TLS connections\n");
        output.push_str("# TYPE proxy_tls_connections_total counter\n");
        output.push_str(&format!("proxy_tls_connections_total {}\n", tls));

        output.push_str("# HELP proxy_errors_total Total number of proxy errors\n");
        output.push_str("# TYPE proxy_errors_total counter\n");
        output.push_str(&format!("proxy_errors_total {}\n", errors));

        output.push_str("# HELP proxy_response_status_codes_total HTTP response status codes\n");
        output.push_str("# TYPE proxy_response_status_codes_total counter\n");
        for (code, count) in status_entries.iter() {
            output.push_str(&format!(
                "proxy_response_status_codes_total{{code=\"{}\"}} {}\n",
                code, count
            ));
        }

        output
    }
}

pub type SharedMetrics = Arc<Metrics>;

pub fn new_metrics() -> SharedMetrics {
    Arc::new(Metrics::new())
}

/// `sysconf(_SC_CLK_TCK)` — the number of `/proc/<pid>/stat` clock ticks in a
/// second.
///
/// 100 on mainstream x86 Linux, and not guaranteed to be: it is a kernel build
/// option. Read once, because the value cannot change under a running kernel.
fn clock_ticks_per_second() -> f64 {
    use std::sync::OnceLock;
    static TICKS: OnceLock<f64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        // SAFETY: `sysconf` is thread-safe and takes no pointer arguments.
        let raw = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if raw > 0 {
            raw as f64
        } else {
            100.0
        }
    })
}

#[cfg(test)]
mod proc_stat_field_tests {
    /// The field offsets, isolated so they can be asserted without a process.
    ///
    /// `/proc/<pid>/stat` is `pid (comm) state ppid …`; a parser that slices
    /// after `comm` starts at field 3, so field N lives at `parts[N - 3]`.
    /// utime is field 14, stime is 15, cutime is 16.
    fn cpu_ticks(raw: &str) -> Option<(u64, u64)> {
        let close = raw.rfind(')')?;
        let parts: Vec<&str> = raw[close + 2..].split_whitespace().collect();
        if parts.len() < 14 {
            return None;
        }
        Some((parts[11].parse().ok()?, parts[12].parse().ok()?))
    }

    /// Fields 1..17 with utime=100, stime=200, cutime=9000.
    fn sample(comm: &str) -> String {
        format!("42 ({comm}) S 1 42 42 0 -1 4194560 500 0 0 0 100 200 9000 300 20 0 1 0 900",)
    }

    #[test]
    fn utime_and_stime_are_read_not_stime_and_cutime() {
        // The bug this replaces: reading one field late gave stime + cutime.
        // Measured on the running proxy, `ps` said 46s and the old arithmetic
        // said 160s — and Soli Cloud meters usage from this.
        assert_eq!(cpu_ticks(&sample("soli-proxy")), Some((100, 200)));
    }

    #[test]
    fn a_comm_containing_a_paren_does_not_shift_every_field() {
        // `comm` is whatever the executable is called, parentheses included.
        // Finding the *first* `)` instead of the last shifts the whole slice
        // and the numbers stay plausible, which is the worst kind of wrong.
        assert_eq!(cpu_ticks(&sample("wei(rd)name")), Some((100, 200)));
        assert_eq!(cpu_ticks(&sample("a) b")), Some((100, 200)));
    }

    #[test]
    fn cutime_is_not_counted() {
        // It accumulates the CPU of reaped children and never decreases, so
        // including it made every app restart inflate the figure for good.
        let (utime, stime) = cpu_ticks(&sample("soli")).unwrap();
        assert_ne!(utime + stime, 200 + 9000);
        assert_eq!(utime + stime, 300);
    }

    #[test]
    fn a_truncated_line_is_rejected_rather_than_guessed() {
        assert_eq!(cpu_ticks("42 (soli) S 1 42"), None);
        assert_eq!(cpu_ticks("no parens here"), None);
    }

    #[test]
    fn the_clock_rate_is_positive() {
        // A zero or negative `sysconf` result would divide CPU time by zero.
        assert!(super::clock_ticks_per_second() > 0.0);
    }
}

#[cfg(test)]
mod slot_sum_tests {
    use super::{sum_slot_metrics, SlotMetrics};

    fn slot(rss: Option<u64>, cpu: Option<f64>) -> SlotMetrics {
        SlotMetrics {
            memory_rss_bytes: rss,
            cpu_percent: cpu,
        }
    }

    #[test]
    fn both_slots_count_during_a_blue_green_overlap() {
        // The window where an app costs the most: the new slot is up and the
        // old one has not been reaped. Charging for the serving slot alone
        // would bill less than the machine is actually holding.
        let totals = sum_slot_metrics(&[
            slot(Some(120 * 1024 * 1024), Some(4.0)),
            slot(Some(80 * 1024 * 1024), Some(1.5)),
        ]);
        assert_eq!(totals.memory_rss_bytes, Some(200 * 1024 * 1024));
        assert_eq!(totals.cpu_percent, Some(5.5));
    }

    #[test]
    fn an_app_with_no_running_process_is_unmeasured_not_zero() {
        // `0 MB` reads as "running, and free". `null` reads as "not running".
        // Only the second is true, and a metered plan that cannot tell them
        // apart bills a stopped app as a live one that happens to be idle.
        let totals = sum_slot_metrics(&[]);
        assert_eq!(totals.memory_rss_bytes, None);
        assert_eq!(totals.cpu_percent, None);
    }

    #[test]
    fn a_measured_slot_is_not_dragged_to_none_by_an_unmeasured_one() {
        // One slot answering and one not is the ordinary case — a stopped blue
        // beside a running green. The answer is the running slot's figure, not
        // "unknown" and not the running slot plus a phantom zero.
        let totals = sum_slot_metrics(&[slot(None, None), slot(Some(64), Some(2.0))]);
        assert_eq!(totals.memory_rss_bytes, Some(64));
        assert_eq!(totals.cpu_percent, Some(2.0));
    }

    #[test]
    fn memory_present_without_cpu_keeps_cpu_absent() {
        // The first sample of a process has no earlier sample to difference
        // against, so CPU is genuinely unknown while RSS is already known.
        // Filling the gap with 0.0 would report a busy app as idle for one
        // scrape, which is the direction that hides a runaway.
        let totals = sum_slot_metrics(&[slot(Some(1024), None)]);
        assert_eq!(totals.memory_rss_bytes, Some(1024));
        assert_eq!(totals.cpu_percent, None);
    }

    #[test]
    fn a_pathological_total_saturates_rather_than_wrapping() {
        // Two slots cannot really hold `u64::MAX` between them, but a wrapped
        // sum would report a colossal app as a tiny one — silently, and in the
        // number a bill is computed from.
        let totals = sum_slot_metrics(&[slot(Some(u64::MAX), None), slot(Some(4096), None)]);
        assert_eq!(totals.memory_rss_bytes, Some(u64::MAX));
    }
}

#[cfg(test)]
mod idle_signal_tests {
    use super::*;

    fn ms_now() -> u64 {
        unix_millis()
    }

    #[test]
    fn an_app_that_was_never_requested_reports_none_rather_than_the_epoch() {
        // The trap this field exists to avoid. A policy that suspends on "age
        // since last_request_ms" would, with 0 in there, compute an age of
        // fifty-odd years for every app the proxy has not served yet — and
        // suspend the whole fleet on its first pass after a restart.
        let metrics = Metrics::new();
        let _ = metrics.app_bytes_sent_counter("never-served");
        let json = metrics
            .get_app_metrics("never-served")
            .expect("the app entry exists");
        assert_eq!(json.requests, 0);
        assert_eq!(json.last_request_ms, None);
    }

    #[test]
    fn a_request_stamps_the_app_and_nothing_else() {
        let metrics = Metrics::new();
        let before = ms_now();
        metrics.record_app_request("served", 10, 20, 200, std::time::Duration::from_millis(1));
        let after = ms_now();

        let json = metrics.get_app_metrics("served").expect("recorded");
        let stamp = json.last_request_ms.expect("a served app has a timestamp");
        assert!(
            (before..=after).contains(&stamp),
            "{stamp} is outside [{before}, {after}]"
        );

        // Per app, not global: an idle app must not look busy because a *different*
        // app was requested, which is the whole point of tracking it here rather
        // than reading the proxy-wide counter.
        let _ = metrics.app_bytes_sent_counter("idle");
        assert_eq!(
            metrics.get_app_metrics("idle").unwrap().last_request_ms,
            None
        );
    }

    #[test]
    fn the_stamp_is_visible_through_the_all_apps_view() {
        // The endpoint an orchestrator reads is `/api/v1/app-metrics`, which goes
        // through this path and not through `get_app_metrics`.
        let metrics = Metrics::new();
        metrics.record_app_request("served", 1, 1, 200, std::time::Duration::from_millis(1));
        let all = metrics.get_all_app_metrics();
        assert!(all.get("served").unwrap().last_request_ms.is_some());
    }

    #[test]
    fn a_later_request_moves_the_stamp_forward() {
        let metrics = Metrics::new();
        metrics.record_app_request("served", 1, 1, 200, std::time::Duration::from_millis(1));
        let first = metrics
            .get_app_metrics("served")
            .unwrap()
            .last_request_ms
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        metrics.record_app_request("served", 1, 1, 200, std::time::Duration::from_millis(1));
        let second = metrics
            .get_app_metrics("served")
            .unwrap()
            .last_request_ms
            .unwrap();
        assert!(second > first, "{second} did not move past {first}");
    }

    #[test]
    fn a_failed_request_still_counts_as_activity() {
        // A 500 is traffic. Suspending an app because every request to it is
        // failing would take away the thing an operator is trying to look at.
        let metrics = Metrics::new();
        metrics.record_app_request("broken", 1, 1, 500, std::time::Duration::from_millis(1));
        let json = metrics.get_app_metrics("broken").unwrap();
        assert_eq!(json.errors, 1);
        assert!(json.last_request_ms.is_some());
    }
}
