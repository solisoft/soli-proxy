use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

/// The hyper client type used to proxy requests to backends.
/// The `HttpsConnector` wrapper handles both `http://` and `https://`
/// targets (TLS via rustls with webpki roots).
pub type ProxyClient = Client<HttpsConnector<HttpConnector>, Incoming>;

/// A shared connection pool for proxying HTTP requests to backends.
///
/// Wraps a hyper `Client` which maintains its own internal pool of
/// keep-alive connections (configured via `pool_max_idle_per_host` and
/// `pool_idle_timeout`). Cloning is cheap — all clones share the same
/// underlying pool — so a single `ConnectionPool` can be handed out
/// to every accept loop / task.
#[derive(Clone)]
pub struct ConnectionPool {
    client: ProxyClient,
}

impl ConnectionPool {
    /// Create a new connection pool with sensible defaults for reverse proxying.
    pub fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_keepalive(Some(Duration::from_secs(30)));
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        // Let https:// URIs through to the TLS layer below instead of
        // rejecting them at connect time.
        connector.enforce_http(false);

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(connector);

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(256)
            .pool_idle_timeout(Duration::from_secs(60))
            .build(https);

        Self { client }
    }

    /// Get a clone of the underlying hyper client.
    ///
    /// The returned client shares the same connection pool as all other
    /// clones, so idle connections are reused transparently.
    pub fn client(&self) -> ProxyClient {
        self.client.clone()
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation_and_clone() {
        // The TLS connector needs a process-default crypto provider (main.rs
        // installs it at startup; tests must do it themselves).
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pool = ConnectionPool::new();
        // Cloning should be cheap (Arc under the hood)
        let _pool2 = pool.clone();
        // Getting a client should succeed
        let _client = pool.client();
    }
}
