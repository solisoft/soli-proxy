use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AppMetricsJson {
    pub requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub avg_response_time_ms: f64,
    pub errors: u64,
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
    requests_total: Arc<AtomicU64>,
    requests_in_flight: Arc<AtomicUsize>,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    response_time_nanos_sum: Arc<AtomicU64>,
    response_time_count: Arc<AtomicU64>,
    status_codes: Arc<[AtomicU64; STATUS_ARRAY_SIZE]>,
    tls_connections: Arc<AtomicU64>,
    errors_total: Arc<AtomicU64>,
    last_request_nanos: Arc<AtomicU64>,
    epoch_start: Instant,
    app_metrics: Arc<parking_lot::RwLock<HashMap<String, AppMetrics>>>,
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
                    },
                )
            })
            .collect()
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
        let success = status >= 200 && status < 400;
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
            apps.entry(app_name.clone()).or_insert_with(AppMetrics::new);
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
