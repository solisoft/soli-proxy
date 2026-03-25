use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
struct CpuSnapshot {
    total_time: u64,
    timestamp: Instant,
}

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

#[derive(Debug, Clone, serde::Serialize)]
pub struct AppSystemMetrics {
    pub blue: SlotMetrics,
    pub green: SlotMetrics,
}

#[derive(Clone)]
pub struct AppMetrics {
    pub requests_total: Arc<AtomicU64>,
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

    pub fn get_app_metrics(&self, app_name: &str) -> Option<AppMetricsJson> {
        let apps = self.app_metrics.read();
        apps.get(app_name).map(|m| AppMetricsJson {
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
            if let Some(idx) = content.find('(') {
                if let Some(idx2) = content[idx..].find(')') {
                    let parts: Vec<&str> = content[idx + idx2 + 2..].split_whitespace().collect();
                    if parts.len() >= 14 {
                        let utime: u64 = parts[12].parse().unwrap_or(0);
                        let stime: u64 = parts[13].parse().unwrap_or(0);
                        let total_time = utime + stime;

                        let now = Instant::now();
                        let prev = self.cpu_snapshots.read().get(&pid).cloned();

                        if let Some(prev_snapshot) = prev {
                            let delta_time = now.duration_since(prev_snapshot.timestamp);
                            if delta_time.as_secs_f64() > 0.0 {
                                let delta_cpu = total_time as f64 - prev_snapshot.total_time as f64;
                                let hz = 100.0;
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
