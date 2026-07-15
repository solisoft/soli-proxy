use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::time::Duration;

/// Error type for outbound proxy request bodies (Incoming map + size limits).
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Type-erased request body used when forwarding to backends.
pub type ProxyRequestBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// The hyper client type used to proxy requests to backends.
/// The `HttpsConnector` wrapper handles both `http://` and `https://`
/// targets (TLS via rustls with webpki roots).
pub type ProxyClient = Client<HttpsConnector<HttpConnector>, ProxyRequestBody>;

/// Wrap an inbound `Incoming` body for outbound proxying, optionally enforcing
/// a hard byte cap as frames are streamed (covers HTTP/2 and chunked bodies
/// that omit or understate `Content-Length`).
pub fn proxy_request_body(body: Incoming, max_size: Option<usize>) -> ProxyRequestBody {
    match max_size {
        // `Limited`'s error type is already `BoxError`.
        Some(max) => http_body_util::Limited::new(body, max).boxed(),
        None => body.map_err(|e| -> BoxError { Box::new(e) }).boxed(),
    }
}

/// True when a client.request failure was caused by the inbound body exceeding
/// `max_request_size` (streamed limit), so callers can return 413 instead of 502.
pub fn is_body_limit_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        // Primary: the concrete type surfaced by `http_body_util::Limited`.
        if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
            return true;
        }
        // Fallback: intermediate layers may box the error behind `Box<dyn Error>`
        // so the concrete type is hidden; match its Display as a backstop.
        if e.to_string().contains("length limit exceeded") {
            return true;
        }
        source = e.source();
    }
    false
}

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
            // A pool timer is REQUIRED for `pool_idle_timeout` to take effect
            // (hyper-util docs). Without it the idle timeout is a silent no-op:
            // idle connections are never recycled by age, so the pool keeps
            // handing out keep-alive connections the backend has already closed.
            // Reusing such a half-closed socket stalls the request for seconds
            // (until TCP gives up and hyper retries) — observed as intermittent
            // multi-second hangs on otherwise-fast AJAX/asset requests.
            .pool_timer(TokioTimer::new())
            // Recycle idle connections well before typical backend keep-alive
            // timeouts (Cowboy/Bandit/nginx default to ~60s) so the proxy always
            // drops a connection before the backend does, avoiding the stale-
            // reuse race. Backends are usually localhost, so reconnecting is
            // cheap. If a backend uses a very short keep-alive (e.g. Node's 5s
            // default), lower this below it or raise the backend's.
            .pool_idle_timeout(Duration::from_secs(15))
            // Cap idle sockets per backend host so a multi-tenant deploy with
            // many origins cannot grow unbounded keep-alive pools.
            .pool_max_idle_per_host(64)
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

    #[test]
    fn is_body_limit_error_detects_length_limit() {
        #[derive(Debug)]
        struct Fake;
        impl std::fmt::Display for Fake {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "length limit exceeded")
            }
        }
        impl std::error::Error for Fake {}
        let err: BoxError = Box::new(Fake);
        assert!(is_body_limit_error(err.as_ref()));
    }

    #[test]
    fn is_body_limit_error_ignores_unrelated() {
        #[derive(Debug)]
        struct Other;
        impl std::fmt::Display for Other {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connection reset")
            }
        }
        impl std::error::Error for Other {}
        let err: BoxError = Box::new(Other);
        assert!(!is_body_limit_error(err.as_ref()));
    }
}
