use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

/// Process-wide shutdown signal, and the count of connections still being
/// served, which is what a graceful stop waits on.
#[derive(Clone)]
pub struct ShutdownCoordinator {
    shutdown_tx: broadcast::Sender<()>,
    is_shutting_down: Arc<AtomicBool>,
    /// Connections whose HTTP serving future is still running — see
    /// [`ShutdownCoordinator::track_connection`].
    active: Arc<AtomicUsize>,
}

/// How a [`ShutdownCoordinator::drain`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Every tracked connection finished within the grace period.
    Drained,
    /// The grace period ran out with this many connections still open.
    TimedOut(usize),
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            shutdown_tx,
            is_shutting_down: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn initiate(&self) {
        self.is_shutting_down.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// [`Self::subscribe`] for a connection being served: the connection
    /// counts as in flight until the returned watch is dropped.
    ///
    /// Held for exactly as long as the serving future runs — which, once
    /// shutdown is initiated, is until hyper's graceful shutdown has finished
    /// the response in progress (HTTP/1) or every open stream (HTTP/2, after
    /// GOAWAY). Counting connections rather than requests is deliberate: a
    /// request is over for the proxy's metrics when its response *head* is
    /// ready, while its body may still be streaming; it is the connection
    /// that ends when the body does. An upgraded WebSocket leaves the count
    /// when hyper hands its socket over — a tunnel has no request to finish,
    /// and waiting on one would hold every restart for the full grace period.
    pub fn track_connection(&self) -> ConnectionWatch {
        self.active.fetch_add(1, Ordering::AcqRel);
        ConnectionWatch {
            rx: self.shutdown_tx.subscribe(),
            active: self.active.clone(),
        }
    }

    /// Connections still being served (see [`Self::track_connection`]).
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::SeqCst)
    }

    /// Wait until no tracked connection is left, or `grace` has passed.
    ///
    /// Call after [`Self::initiate`]: the listeners have stopped accepting,
    /// idle keep-alive connections close at once, and what remains is
    /// requests in progress. Polled rather than notified — this runs once per
    /// process lifetime, and 50 ms is well under anything a client notices.
    pub async fn drain(&self, grace: Duration) -> DrainOutcome {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let open = self.active_connections();
            if open == 0 {
                return DrainOutcome::Drained;
            }
            if tokio::time::Instant::now() >= deadline {
                return DrainOutcome::TimedOut(open);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// A served connection's view of the shutdown signal; it counts as in flight
/// until dropped. See [`ShutdownCoordinator::track_connection`].
pub struct ConnectionWatch {
    rx: broadcast::Receiver<()>,
    active: Arc<AtomicUsize>,
}

impl ConnectionWatch {
    /// Resolves when shutdown is initiated, like `broadcast::Receiver::recv`.
    pub async fn recv(&mut self) -> Result<(), broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

impl Drop for ConnectionWatch {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_waits_for_tracked_connections_only_as_long_as_needed() {
        let shutdown = ShutdownCoordinator::new();
        // Nothing open: done at once.
        assert_eq!(
            shutdown.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );

        let mut watch = shutdown.track_connection();
        assert_eq!(shutdown.active_connections(), 1);
        let serving = tokio::spawn(async move {
            // A connection finishing its response after the signal.
            watch.recv().await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(watch);
        });
        // Let the task reach `recv` before the signal is sent.
        tokio::task::yield_now().await;
        shutdown.initiate();
        let started = std::time::Instant::now();
        assert_eq!(
            shutdown.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        serving.await.unwrap();
        assert_eq!(shutdown.active_connections(), 0);
    }

    #[tokio::test]
    async fn drain_gives_up_after_the_grace_period() {
        let shutdown = ShutdownCoordinator::new();
        let _stuck = shutdown.track_connection();
        shutdown.initiate();
        assert_eq!(
            shutdown.drain(Duration::from_millis(120)).await,
            DrainOutcome::TimedOut(1)
        );
    }
}
