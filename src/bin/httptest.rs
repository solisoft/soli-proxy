use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::{
    new_challenge_store, new_metrics, run_admin_server, AdminState, ConfigManager, ProxyServer,
    ShutdownCoordinator,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Parse a simple CLI flag value: --flag value
fn parse_arg(args: &[String], flag: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Spawn a minimal HTTP backend that returns 200 OK with a small body.
async fn spawn_mock_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req| async {
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from_static(b"OK"),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });

    port
}

/// Create a temp directory with proxy.conf and config.toml.
fn write_temp_config(backend_port: u16, proxy_port: u16, admin_port: u16) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("soli-httptest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");

    std::fs::write(
        dir.join("proxy.conf"),
        format!("default -> http://127.0.0.1:{}\n", backend_port),
    )
    .expect("failed to write proxy.conf");

    std::fs::write(
        dir.join("config.toml"),
        format!(
            "[server]\nbind = \"127.0.0.1:{}\"\nhttps_port = 0\n\n[admin]\nenabled = true\nbind = \"127.0.0.1:{}\"\n",
            proxy_port, admin_port
        ),
    )
    .expect("failed to write config.toml");

    dir
}

/// Wait for an HTTP endpoint to respond (any status).
async fn wait_ready(url: &str, label: &str) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let req = hyper::Request::builder()
            .uri(url)
            .body(Full::new(Bytes::new()))
            .unwrap();
        if client.request(req).await.is_ok() {
            return;
        }
    }
    eprintln!("[warn] {} never became ready", label);
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Run a load test against the given URI and return (latencies_ms, error_count).
async fn run_load(
    uri: String,
    total_requests: usize,
    concurrency: usize,
) -> (Vec<f64>, u64, Duration) {
    let requests_per_worker = total_requests / concurrency;
    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let uri = uri.clone();
        let handle = tokio::spawn(async move {
            let conn = HttpConnector::new();
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build(conn);

            let mut latencies = Vec::with_capacity(requests_per_worker);
            let mut errors = 0u64;

            for _ in 0..requests_per_worker {
                let req = hyper::Request::builder()
                    .uri(&uri)
                    .body(Full::new(Bytes::new()))
                    .unwrap();

                let req_start = Instant::now();
                match client.request(req).await {
                    Ok(res) => {
                        let elapsed = req_start.elapsed();
                        latencies.push(elapsed.as_secs_f64() * 1000.0);
                        if res.status().as_u16() >= 400 {
                            errors += 1;
                        }
                    }
                    Err(_) => {
                        errors += 1;
                        latencies.push(req_start.elapsed().as_secs_f64() * 1000.0);
                    }
                }
            }

            (latencies, errors)
        });
        handles.push(handle);
    }

    let mut all_latencies = Vec::with_capacity(total_requests);
    let mut total_errors = 0u64;
    for handle in handles {
        if let Ok((latencies, errors)) = handle.await {
            all_latencies.extend(latencies);
            total_errors += errors;
        }
    }
    let elapsed = start.elapsed();
    (all_latencies, total_errors, elapsed)
}

fn print_results(label: &str, mut latencies: Vec<f64>, errors: u64, elapsed: Duration) {
    let actual = latencies.len();
    let rps = actual as f64 / elapsed.as_secs_f64();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!();
    println!("  {} Results:", label);
    println!("    Completed:  {}", actual);
    println!("    Errors:     {}", errors);
    println!("    Duration:   {:.2?}", elapsed);
    println!("    Throughput: {:.2} req/s", rps);
    println!("    p50:  {:.3} ms", percentile(&latencies, 50.0));
    println!("    p95:  {:.3} ms", percentile(&latencies, 95.0));
    println!("    p99:  {:.3} ms", percentile(&latencies, 99.0));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let total_requests = parse_arg(&args, "--requests", 10_000);
    let concurrency = parse_arg(&args, "--concurrency", 100);

    println!("==========================================");
    println!("Soli Proxy — End-to-End Throughput Test");
    println!("==========================================");

    // 1. Pick ports
    let proxy_port = portpicker::pick_unused_port().expect("no free port");
    let admin_port = portpicker::pick_unused_port().expect("no free port");

    // 2. Spawn mock backend
    let backend_port = spawn_mock_backend().await;
    println!("Mock backend on port {}", backend_port);

    // 3. Write temp config
    let config_dir = write_temp_config(backend_port, proxy_port, admin_port);
    let config_path = config_dir.join("proxy.conf").to_str().unwrap().to_string();

    // 4. Start proxy + admin
    let config = Arc::new(ConfigManager::new(&config_path).expect("failed to load config"));
    let shutdown = ShutdownCoordinator::new();
    let metrics = new_metrics();
    let challenge_store = new_challenge_store();
    let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig::default()));

    #[cfg(feature = "scripting")]
    let lua_engine: Option<soli_proxy::LuaEngine> = None;
    #[cfg(not(feature = "scripting"))]
    let lua_engine = ();

    let server = ProxyServer::new(
        config.clone(),
        shutdown.clone(),
        metrics.clone(),
        challenge_store,
        lua_engine,
        cb.clone(),
        None,
    )
    .expect("failed to create proxy server");

    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("Proxy error: {}", e);
        }
    });

    let admin_state = Arc::new(AdminState {
        config_manager: config,
        metrics,
        start_time: Instant::now(),
        circuit_breaker: cb,
        app_manager: None,
    });
    tokio::spawn(async move {
        if let Err(e) = run_admin_server(admin_state).await {
            eprintln!("Admin error: {}", e);
        }
    });

    println!(
        "Proxy on port {},  Admin on port {}",
        proxy_port, admin_port
    );
    println!(
        "Requests: {}   Concurrency: {}",
        total_requests, concurrency
    );
    println!("------------------------------------------");

    // 5. Wait for both servers
    let proxy_url = format!("http://127.0.0.1:{}/", proxy_port);
    let admin_url = format!("http://127.0.0.1:{}/api/v1/status", admin_port);
    wait_ready(&proxy_url, "proxy").await;
    wait_ready(&admin_url, "admin").await;

    // 6. Benchmark: Proxy (default route → backend)
    println!();
    println!("[1/2] Proxy: default → mock backend");
    let (lat, err, dur) = run_load(proxy_url, total_requests, concurrency).await;
    print_results("Proxy", lat, err, dur);

    // 7. Benchmark: Admin /api/v1/status
    println!();
    println!("[2/2] Admin: GET /api/v1/status");
    let (lat, err, dur) = run_load(admin_url, total_requests, concurrency).await;
    print_results("Admin", lat, err, dur);

    println!();
    println!("==========================================");

    // 8. Cleanup
    shutdown.initiate();
    let _ = std::fs::remove_dir_all(&config_dir);
}
