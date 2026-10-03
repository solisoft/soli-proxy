//! Sending a request upstream, and retrying it on another target when the
//! first one failed in a way that is safe to replay.
//!
//! What is safe:
//! - a **connect failure** (refused, unreachable, connect timeout, TLS
//!   handshake): nothing reached the upstream, so any request may go to the
//!   next target — its body too, which was never read (see [`Rewindable`]);
//! - **any other failure before a response** (a reset, a connection closed
//!   mid-request), or a **502/503 named in `retry_on`**: the upstream may
//!   have acted on the request, so only an idempotent method (GET, HEAD,
//!   OPTIONS, PUT, DELETE, TRACE) without a body is replayed.
//!
//! Every failed attempt is recorded in the circuit breaker, like a failure
//! without a retry is.

use crate::circuit_breaker::CircuitBreaker;
use crate::pool::{
    is_client_body_error, proxy_request_body, BoxError, ProxyClient, ProxyRequestBody,
};
use anyhow::{bail, Result};
use bytes::Bytes;
use http::request::Parts;
use http::uri::{Authority, Scheme};
use http::{Method, Uri, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HOST, TE};
use hyper::{Request, Response};
use serde::Serialize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use super::UpstreamClient;

/// Which failures `[upstream] retry_on` retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryOn {
    /// `"connect"`: the connection could not be made.
    pub connect: bool,
    /// `"error"`: the exchange failed before a response (idempotent,
    /// bodiless requests only).
    pub error: bool,
    /// `"502"`, `"503"`, `"504"`: the upstream answered with this status
    /// (idempotent, bodiless requests only).
    pub statuses: Vec<u16>,
}

impl Default for RetryOn {
    /// `["connect", "error"]`: retrying a status is opt-in, since a 503 is
    /// often an answer the backend means.
    fn default() -> Self {
        Self {
            connect: true,
            error: true,
            statuses: Vec::new(),
        }
    }
}

impl RetryOn {
    pub fn parse(list: &[String]) -> Result<Self> {
        let mut out = Self {
            connect: false,
            error: false,
            statuses: Vec::new(),
        };
        for item in list {
            match item.trim() {
                "connect" => out.connect = true,
                // `reset` reads naturally too; it is the same thing.
                "error" | "reset" => out.error = true,
                s => match s.parse::<u16>() {
                    Ok(code @ (500 | 502 | 503 | 504)) => {
                        if !out.statuses.contains(&code) {
                            out.statuses.push(code)
                        }
                    }
                    _ => bail!(
                        "unknown retry_on value {:?} (expected \"connect\", \"error\", \
                         \"500\", \"502\", \"503\" or \"504\")",
                        item
                    ),
                },
            }
        }
        Ok(out)
    }
}

impl Serialize for RetryOn {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut items: Vec<String> = Vec::new();
        if self.connect {
            items.push("connect".into());
        }
        if self.error {
            items.push("error".into());
        }
        items.extend(self.statuses.iter().map(|c| c.to_string()));
        items.serialize(s)
    }
}

/// Where one attempt goes.
pub struct Attempt<'a> {
    /// The full URL the request is sent to.
    pub target_url: String,
    /// The configured target it came from — what the circuit breaker counts.
    pub base_url: String,
    /// `None`: the shared pool.
    pub client: Option<&'a UpstreamClient>,
}

/// Why the previous attempt is being retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Connect,
    Error,
    Status(u16),
}

/// What went wrong with the last attempt.
#[derive(Debug)]
pub enum SendError {
    /// The target URL is not a valid request URI.
    BadUri(http::uri::InvalidUri),
    /// The exchange failed; the error says how.
    Upstream(hyper_util::client::legacy::Error),
}

/// The fixed inputs of [`send`].
pub struct Exchange<'a> {
    pub shared: &'a ProxyClient,
    pub breaker: &'a CircuitBreaker,
    /// Further attempts allowed after the first. Zero when no other target
    /// exists, so nothing is kept around for a retry that cannot happen.
    pub retries: u32,
    pub retry_on: &'a RetryOn,
    pub try_duration: Option<Duration>,
    pub max_body: Option<usize>,
}

/// Idempotent methods (RFC 9110 §9.2.2): sending one twice has the effect of
/// sending it once.
pub fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE
    )
}

/// The request URI for `target_url`: an `h2c://` target is sent as `http://`
/// (the scheme only told the proxy to use HTTP/2 prior knowledge).
pub fn outbound_uri(target_url: &str) -> std::result::Result<Uri, http::uri::InvalidUri> {
    let uri: Uri = target_url.parse()?;
    if uri.scheme_str() != Some("h2c") {
        return Ok(uri);
    }
    let mut parts = uri.into_parts();
    parts.scheme = Some(Scheme::HTTP);
    // Scheme and authority are both present, so this cannot fail.
    Ok(Uri::from_parts(parts).expect("an absolute URI stays valid with an http scheme"))
}

/// Finish a request's head for `client`: the HTTP version it will speak and
/// the headers that version allows.
///
/// - HTTP/1.1 upstreams do not get `TE` at all (the proxy kept only
///   `TE: trailers` from the client, which is for HTTP/2 upstreams — gRPC
///   requires it);
/// - an HTTP/2 request must not carry a `Host` that differs from its
///   `:authority` (RFC 9113 §8.3.1). For a Unix socket, whose URI authority is
///   only a placeholder, the client's Host becomes the authority; elsewhere a
///   differing Host is dropped (the client's is in `X-Forwarded-Host`).
pub fn finish_head(parts: &mut Parts, client: Option<&UpstreamClient>) {
    let Some(client) = client.filter(|c| c.is_h2()) else {
        parts.version = Version::HTTP_11;
        parts.headers.remove(TE);
        return;
    };
    parts.version = Version::HTTP_2;
    let Some(host) = parts.headers.get(HOST) else {
        return;
    };
    if client.is_unix() {
        if let Ok(authority) = Authority::try_from(host.as_bytes()) {
            let mut uri = std::mem::take(&mut parts.uri).into_parts();
            uri.authority = Some(authority);
            if let Ok(rebuilt) = Uri::from_parts(uri) {
                parts.uri = rebuilt;
            }
        }
    }
    if parts.uri.authority().map(|a| a.as_str().as_bytes()) != Some(host.as_bytes()) {
        parts.headers.remove(HOST);
    }
}

/// Send the request, retrying on other targets as the policy allows.
///
/// `head` is the request as it leaves the proxy for any target: method,
/// headers, the client's original URI. Per attempt, its URI is replaced by
/// the attempt's and `prepare` adjusts whatever depends on the target (it
/// receives the head still carrying the client's URI, and the new one).
/// `next` names the next target after a failure, given the targets tried so
/// far; it is called only when a retry is allowed.
///
/// On return, `attempt` is the last target tried. Intermediate failures were
/// recorded in the circuit breaker; the last attempt's outcome is the
/// caller's to record, as it was before retries existed.
pub async fn send<'a, P, N>(
    ex: Exchange<'a>,
    head: Parts,
    body: Incoming,
    attempt: &mut Attempt<'a>,
    mut prepare: P,
    mut next: N,
) -> std::result::Result<Response<Incoming>, SendError>
where
    P: FnMut(&mut Parts, Uri) + Send,
    N: FnMut(&[String], Failure) -> Option<Attempt<'a>> + Send,
{
    let bodiless = body.is_end_stream();
    let replayable = bodiless && is_idempotent(&head.method);
    let mut left = ex.retries;
    let mut source = if bodiless {
        BodySource::Empty
    } else if left > 0 {
        BodySource::Rewind(Arc::new(parking_lot::Mutex::new(Some(proxy_request_body(
            body,
            ex.max_body,
        )))))
    } else {
        BodySource::Once(Some(proxy_request_body(body, ex.max_body)))
    };
    let mut head = Some(head);
    let started = Instant::now();
    let mut tried: Vec<String> = Vec::new();

    loop {
        let uri = outbound_uri(&attempt.target_url).map_err(SendError::BadUri)?;
        // The last possible attempt takes the head; earlier ones send a copy
        // so the next one can start from the original again.
        let mut parts = if left == 0 {
            head.take()
                .expect("the head is kept until the last attempt")
        } else {
            copy_head(
                head.as_ref()
                    .expect("the head is kept until the last attempt"),
            )
        };
        prepare(&mut parts, uri);
        finish_head(&mut parts, attempt.client);
        let Some(body) = source.next_body() else {
            // Only reachable if a body that had started streaming were asked
            // for again, which the checks below rule out.
            unreachable!("a request body is replayed only if it was never read");
        };
        let request = Request::from_parts(parts, body);
        let result = match attempt.client {
            Some(client) => client.request(request).await,
            None => ex.shared.request(request).await,
        };

        let failure = match &result {
            Ok(response) => {
                let status = response.status().as_u16();
                if !(replayable && ex.retry_on.statuses.contains(&status)) {
                    return result.map_err(SendError::Upstream);
                }
                Failure::Status(status)
            }
            // The client's own upload failed: nothing to retry, and nothing
            // for the breaker either.
            Err(e) if is_client_body_error(e) => return result.map_err(SendError::Upstream),
            Err(e) if e.is_connect() => Failure::Connect,
            Err(_) => Failure::Error,
        };
        let allowed = match failure {
            Failure::Connect => ex.retry_on.connect && source.can_replay(),
            Failure::Error => ex.retry_on.error && replayable,
            Failure::Status(_) => true,
        };
        let in_time = ex.try_duration.is_none_or(|d| started.elapsed() < d);
        if left == 0 || !allowed || !in_time {
            return result.map_err(SendError::Upstream);
        }
        tried.push(attempt.base_url.clone());
        let Some(following) = next(&tried, failure) else {
            return result.map_err(SendError::Upstream);
        };

        // This attempt is over: it counts, like any other.
        match &result {
            Ok(response) if !ex.breaker.is_failure_status(response.status().as_u16()) => {
                ex.breaker.record_success(&attempt.base_url)
            }
            _ => ex.breaker.record_failure(&attempt.base_url),
        }
        let why = match &result {
            Ok(response) => format!("status {}", response.status().as_u16()),
            Err(e) => error_chain(e),
        };
        tracing::warn!(
            layer = "proxy",
            failed = %attempt.target_url,
            next = %following.target_url,
            reason = %why,
            "upstream attempt failed; retrying on another target"
        );
        *attempt = following;
        left -= 1;
    }
}

/// `err` and its sources, `: `-separated.
pub(crate) fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(e) = source {
        out.push_str(": ");
        out.push_str(&e.to_string());
        source = e.source();
    }
    out
}

/// A copy of a request head for one attempt (`Parts` is not `Clone`: its
/// extensions may not be). Extensions are not copied; the proxy clears them
/// before sending anyway.
fn copy_head(head: &Parts) -> Parts {
    let (mut parts, ()) = Request::new(()).into_parts();
    parts.method = head.method.clone();
    parts.uri = head.uri.clone();
    parts.version = head.version;
    parts.headers = head.headers.clone();
    parts
}

/// Where each attempt's body comes from.
enum BodySource {
    /// No body: every attempt gets an empty one.
    Empty,
    /// Sent once; no retry can need it again.
    Once(Option<ProxyRequestBody>),
    /// Handed to an attempt in a [`Rewindable`], which gives it back if the
    /// attempt ended before reading it.
    Rewind(Arc<parking_lot::Mutex<Option<ProxyRequestBody>>>),
}

impl BodySource {
    fn next_body(&mut self) -> Option<ProxyRequestBody> {
        match self {
            BodySource::Empty => Some(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            ),
            BodySource::Once(body) => body.take(),
            BodySource::Rewind(slot) => {
                let body = slot.lock().take()?;
                Some(
                    Rewindable {
                        inner: Some(body),
                        slot: slot.clone(),
                        started: false,
                    }
                    .boxed(),
                )
            }
        }
    }

    /// Whether another attempt can be given the body.
    fn can_replay(&self) -> bool {
        match self {
            BodySource::Empty => true,
            BodySource::Once(_) => false,
            BodySource::Rewind(slot) => slot.lock().is_some(),
        }
    }
}

/// A request body that goes back to its slot when dropped unread.
///
/// hyper reads a request body only once the connection is up and the head is
/// on its way, so after a connect failure the body is untouched: dropping
/// the failed request returns it here, and the next attempt sends it whole.
/// Once a single frame has been read, it is consumed for good.
struct Rewindable {
    inner: Option<ProxyRequestBody>,
    slot: Arc<parking_lot::Mutex<Option<ProxyRequestBody>>>,
    started: bool,
}

impl Body for Rewindable {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        this.started = true;
        match this.inner.as_mut() {
            Some(body) => Pin::new(body).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(|b| b.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), |b| b.size_hint())
    }
}

impl Drop for Rewindable {
    fn drop(&mut self) {
        if !self.started {
            if let Some(body) = self.inner.take() {
                *self.slot.lock() = Some(body);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_on_parses_its_vocabulary() {
        let r = RetryOn::parse(&["connect".into(), "reset".into(), "503".into(), "503".into()])
            .unwrap();
        assert!(r.connect && r.error);
        assert_eq!(r.statuses, vec![503]);
        assert!(RetryOn::parse(&["404".into()]).is_err());
        assert!(RetryOn::parse(&["timeout".into()]).is_err());
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!(["connect", "error", "503"])
        );
    }

    #[test]
    fn idempotent_methods() {
        for m in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"] {
            assert!(is_idempotent(&m.parse().unwrap()), "{m}");
        }
        for m in ["POST", "PATCH", "CONNECT"] {
            assert!(!is_idempotent(&m.parse().unwrap()), "{m}");
        }
    }

    #[test]
    fn h2c_targets_go_out_as_http() {
        let uri = outbound_uri("h2c://grpc:50051/pkg.Svc/Call?x=1").unwrap();
        assert_eq!(uri.to_string(), "http://grpc:50051/pkg.Svc/Call?x=1");
        let uri = outbound_uri("https://a.example/x").unwrap();
        assert_eq!(uri.to_string(), "https://a.example/x");
    }

    fn head(host: &str, uri: &str) -> Parts {
        let (mut parts, ()) = Request::get(uri)
            .header(HOST, host)
            .header(TE, "trailers")
            .body(())
            .unwrap()
            .into_parts();
        parts.version = Version::HTTP_11;
        parts
    }

    #[test]
    fn http1_upstreams_never_see_te() {
        let mut parts = head("example.com", "http://backend:8080/x");
        finish_head(&mut parts, None);
        assert_eq!(parts.version, Version::HTTP_11);
        assert!(parts.headers.get(TE).is_none());
        assert_eq!(parts.headers[HOST], "example.com");
    }

    #[test]
    fn http2_upstreams_keep_te_trailers_and_a_consistent_host() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let h2c = super::super::client::default_h2c();
        let mut parts = head("example.com", "http://grpc:50051/x");
        finish_head(&mut parts, Some(h2c));
        assert_eq!(parts.version, Version::HTTP_2);
        assert_eq!(parts.headers[TE], "trailers");
        assert!(
            parts.headers.get(HOST).is_none(),
            "Host differed from :authority"
        );

        let mut parts = head("grpc:50051", "http://grpc:50051/x");
        finish_head(&mut parts, Some(h2c));
        assert_eq!(parts.headers[HOST], "grpc:50051");
    }

    #[test]
    fn an_unread_body_goes_back_to_its_slot() {
        let body: ProxyRequestBody = http_body_util::Full::new(Bytes::from_static(b"payload"))
            .map_err(|never| match never {})
            .boxed();
        let mut source = BodySource::Rewind(Arc::new(parking_lot::Mutex::new(Some(body))));
        let first = source.next_body().unwrap();
        assert!(!source.can_replay(), "the attempt holds it");
        drop(first);
        assert!(source.can_replay(), "dropped unread: back in the slot");

        let mut second = source.next_body().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let frame = rt.block_on(second.frame()).unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"payload"));
        drop(second);
        assert!(!source.can_replay(), "a body that was read is gone");
    }

    /// A health check's `error sending request for url (…)` reads the same
    /// for an app that hangs and an app that is gone; the chain tells them
    /// apart.
    #[tokio::test]
    async fn error_chain_tells_a_timeout_from_a_refused_connection() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();

        // Accepts the connection, never answers: a wedged app.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_url = format!("http://{}/up", silent.local_addr().unwrap());
        let held = tokio::spawn(async move {
            let (_socket, _) = silent.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let err = client.get(&silent_url).send().await.unwrap_err();
        let chain = error_chain(&err);
        assert!(chain.contains("timed out"), "{chain}");
        held.abort();

        // Nothing listening: an app that exited.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_url = format!("http://{}/up", closed.local_addr().unwrap());
        drop(closed);
        let err = client.get(&closed_url).send().await.unwrap_err();
        let chain = error_chain(&err);
        assert!(!chain.contains("timed out"), "{chain}");
        assert!(chain.len() > err.to_string().len(), "{chain}");
    }
}
