//! A hyper connector for `unix:/path.sock` targets.
//!
//! Written here rather than pulled in (hyperlocal and friends are thin and
//! irregularly maintained): one connector per socket, which ignores the
//! request URI — requests to a socket are addressed to the placeholder
//! `http://unix.invalid/` (see `super::routing_url`) — and dials the socket
//! within the connect timeout.

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::UnixStream;

/// Connects every request to one Unix socket.
#[derive(Clone, Debug)]
pub struct UnixConnector {
    path: Arc<Path>,
    timeout: Duration,
}

impl UnixConnector {
    pub fn new(path: PathBuf, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
        }
    }
}

impl tower::Service<Uri> for UnixConnector {
    type Response = UnixIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UnixIo>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _dst: Uri) -> Self::Future {
        let path = self.path.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(timeout, UnixStream::connect(&*path)).await {
                Ok(stream) => stream
                    .map(|s| UnixIo(TokioIo::new(s)))
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {}", path.display(), e))),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{}: connect timed out", path.display()),
                )),
            }
        })
    }
}

/// A connected socket, as hyper wants it.
pub struct UnixIo(TokioIo<UnixStream>);

impl Connection for UnixIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Read for UnixIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl Write for UnixIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::Service;

    #[tokio::test]
    async fn connects_to_the_socket_whatever_the_uri() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.is_ok() });
        let mut c = UnixConnector::new(path, Duration::from_secs(1));
        let uri: Uri = "http://unix.invalid/anything".parse().unwrap();
        assert!(c.call(uri).await.is_ok());
        assert!(accept.await.unwrap());
    }

    #[tokio::test]
    async fn a_missing_socket_names_its_path() {
        let mut c = UnixConnector::new("/nonexistent/soli.sock".into(), Duration::from_secs(1));
        let err = c
            .call("http://unix.invalid/".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("/nonexistent/soli.sock"));
    }
}
