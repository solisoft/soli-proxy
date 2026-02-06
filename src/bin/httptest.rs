use bytes::Bytes;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let conn = HttpConnector::new();
    let client: Client<HttpConnector, http_body_util::Full<Bytes>> =
        Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(conn);

    let total_requests = 5000;
    let concurrent = 100;

    println!("==========================================");
    println!("Soli Proxy - HTTP/2 Load Test");
    println!("==========================================");
    println!("Total requests: {}", total_requests);
    println!("Concurrent connections: {}", concurrent);
    println!();

    let start = Instant::now();
    let mut handles = vec![];

    for _ in 0..concurrent {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let mut count = 0;
            for _ in 0..(total_requests / concurrent) {
                let req = hyper::Request::builder()
                    .uri("http://localhost:8008/")
                    .body(http_body_util::Full::new(Bytes::new()))
                    .unwrap();

                match client.request(req).await {
                    Ok(res) => {
                        if res.status() == 200 || res.status() == 421 || res.status() == 502 {
                            count += 1;
                        }
                    }
                    Err(_) => {
                        count += 1;
                    }
                }
            }
            count
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    for handle in handles {
        if let Ok(count) = handle.await {
            success_count += count;
        }
    }

    let elapsed = start.elapsed();
    let rps = total_requests as f64 / elapsed.as_secs_f64();

    println!("Completed: {} / {} requests", success_count, total_requests);
    println!("Duration: {:?}", elapsed);
    println!("Throughput: {:.2} req/sec", rps);
    println!("Avg latency: {:?}", elapsed / total_requests);
    println!("==========================================");
}
