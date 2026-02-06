use http::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PooledConnection {
    pub client: Client<HttpConnector, hyper::body::Incoming>,
    pub last_used: Instant,
    pub uri: Uri,
}

pub struct ConnectionPool {
    pools: Arc<Mutex<HashMap<String, PooledConnection>>>,
    _max_idle: usize,
    max_age: Duration,
    connector: HttpConnector,
}

impl ConnectionPool {
    pub fn new(max_idle: usize, max_age: Duration) -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            _max_idle: max_idle,
            max_age,
            connector: HttpConnector::new(),
        }
    }

    pub async fn get_client(&self, uri: &Uri) -> Client<HttpConnector, hyper::body::Incoming> {
        let uri_str = uri.to_string();
        let mut pools = self.pools.lock().await;

        if let Some(conn) = pools.get(&uri_str) {
            if conn.last_used.elapsed() < self.max_age {
                let client = Client::builder(TokioExecutor::new())
                    .http2_only(true)
                    .build(self.connector.clone());
                return client;
            }
            pools.remove(&uri_str);
        }

        Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(self.connector.clone())
    }

    pub async fn cleanup(&self) {
        let mut pools = self.pools.lock().await;
        let now = Instant::now();
        pools.retain(|_, conn| now.duration_since(conn.last_used) < self.max_age);
    }
}

pub fn create_optimized_client() -> Client<HttpConnector, hyper::body::Incoming> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(30)));

    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(connector)
}

pub struct BackendPool {
    clients: Vec<Client<HttpConnector, hyper::body::Incoming>>,
    current: usize,
}

impl BackendPool {
    pub fn new(targets: &[Uri]) -> Self {
        let clients: Vec<_> = targets
            .iter()
            .map(|_| {
                let mut connector = HttpConnector::new();
                connector.set_nodelay(true);
                connector.set_keepalive(Some(Duration::from_secs(30)));
                Client::builder(TokioExecutor::new())
                    .http2_only(true)
                    .build(connector)
            })
            .collect();

        Self {
            clients,
            current: 0,
        }
    }

    pub fn get_client(&mut self) -> &mut Client<HttpConnector, hyper::body::Incoming> {
        let idx = self.current;
        self.current = (self.current + 1) % self.clients.len();
        &mut self.clients[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_creation() {
        let pool = ConnectionPool::new(10, Duration::from_secs(60));
        assert!(pool._max_idle == 10);
        assert!(pool.max_age == Duration::from_secs(60));
    }
}
