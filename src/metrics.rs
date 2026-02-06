use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

#[derive(Clone)]
pub struct Metrics {
    requests_total: Arc<AtomicU64>,
    requests_in_flight: Arc<AtomicUsize>,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    response_times: Arc<RwLock<VecDeque<std::time::Duration>>>,
    status_codes: Arc<RwLock<HashMap<u16, Arc<AtomicU64>>>>,
    tls_connections: Arc<AtomicU64>,
    errors_total: Arc<AtomicU64>,
    last_request_time: Arc<RwLock<Option<Instant>>>,
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
            response_times: Arc::new(RwLock::new(VecDeque::with_capacity(1001))),
            status_codes: Arc::new(RwLock::new(HashMap::new())),
            tls_connections: Arc::new(AtomicU64::new(0)),
            errors_total: Arc::new(AtomicU64::new(0)),
            last_request_time: Arc::new(RwLock::new(None)),
        }
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

        {
            let mut times = self.response_times.write().unwrap();
            times.push_back(duration);
            if times.len() > 1000 {
                times.pop_front();
            }
        }

        {
            let mut codes = self.status_codes.write().unwrap();
            codes
                .entry(status)
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .fetch_add(1, Ordering::Relaxed);
        }

        {
            let mut last = self.last_request_time.write().unwrap();
            *last = Some(Instant::now());
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
            let times = self.response_times.read().unwrap();
            if times.is_empty() {
                0.0
            } else {
                times.iter().sum::<std::time::Duration>().as_secs_f64() / times.len() as f64
            }
        };

        let status_codes: Vec<(u16, u64)> = {
            let codes = self.status_codes.read().unwrap();
            codes
                .iter()
                .map(|(&k, v)| (k, v.load(Ordering::Relaxed)))
                .collect()
        };
        let mut sorted: Vec<_> = status_codes;
        sorted.sort_by_key(|&(k, _)| k);

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
        for (code, count) in sorted.iter() {
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
