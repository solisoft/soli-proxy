use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub success_threshold: u32,
    pub failure_status_codes: Vec<u16>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            success_threshold: 2,
            failure_status_codes: vec![502, 503, 504],
        }
    }
}

impl CircuitBreakerConfig {
    pub fn from_toml(toml: Option<&crate::config::CircuitBreakerTomlConfig>) -> Self {
        match toml {
            Some(t) => Self {
                failure_threshold: t.failure_threshold.unwrap_or(5),
                recovery_timeout: Duration::from_secs(t.recovery_timeout_secs.unwrap_or(30)),
                success_threshold: t.success_threshold.unwrap_or(2),
                failure_status_codes: t
                    .failure_status_codes
                    .clone()
                    .unwrap_or_else(|| vec![502, 503, 504]),
            },
            None => Self::default(),
        }
    }
}

struct TargetState {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    consecutive_successes: AtomicU32,
    /// Nanos since `epoch_start` when the breaker was opened
    opened_at_nanos: AtomicU64,
    /// In half-open state, only one probe request is allowed through
    probe_permit: AtomicBool,
}

impl TargetState {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            opened_at_nanos: AtomicU64::new(0),
            probe_permit: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerInfo {
    pub state: String,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

pub struct CircuitBreaker {
    targets: RwLock<HashMap<String, Arc<TargetState>>>,
    config: CircuitBreakerConfig,
    epoch_start: Instant,
}

pub type SharedCircuitBreaker = Arc<CircuitBreaker>;

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            targets: RwLock::new(HashMap::new()),
            config,
            epoch_start: Instant::now(),
        }
    }

    fn get_or_create(&self, target_url: &str) -> Arc<TargetState> {
        // Fast path: read lock
        {
            let targets = self.targets.read().unwrap();
            if let Some(state) = targets.get(target_url) {
                return state.clone();
            }
        }
        // Slow path: write lock for new target
        let mut targets = self.targets.write().unwrap();
        targets
            .entry(target_url.to_string())
            .or_insert_with(|| Arc::new(TargetState::new()))
            .clone()
    }

    fn now_nanos(&self) -> u64 {
        self.epoch_start.elapsed().as_nanos() as u64
    }

    /// Check if a target is available to receive traffic.
    /// In Closed state: always available.
    /// In Open state: available only if recovery_timeout has elapsed (transitions to HalfOpen).
    /// In HalfOpen state: available only if the probe permit can be claimed.
    pub fn is_available(&self, target_url: &str) -> bool {
        let state = self.get_or_create(target_url);
        let current = state.state.load(Ordering::Acquire);

        match current {
            STATE_CLOSED => true,
            STATE_OPEN => {
                let opened_at = state.opened_at_nanos.load(Ordering::Acquire);
                let elapsed_nanos = self.now_nanos().saturating_sub(opened_at);
                if elapsed_nanos >= self.config.recovery_timeout.as_nanos() as u64 {
                    // Try to transition Open -> HalfOpen
                    if state
                        .state
                        .compare_exchange(
                            STATE_OPEN,
                            STATE_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        state.consecutive_successes.store(0, Ordering::Release);
                        state.probe_permit.store(true, Ordering::Release);
                        // Claim the probe permit we just set
                        state
                            .probe_permit
                            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    } else {
                        // Another thread already transitioned; try to claim probe
                        state
                            .probe_permit
                            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    }
                } else {
                    false
                }
            }
            STATE_HALF_OPEN => {
                // Only one probe at a time
                state
                    .probe_permit
                    .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }
            _ => false,
        }
    }

    pub fn record_success(&self, target_url: &str) {
        let state = self.get_or_create(target_url);
        let current = state.state.load(Ordering::Acquire);

        match current {
            STATE_CLOSED => {
                state.consecutive_failures.store(0, Ordering::Release);
            }
            STATE_HALF_OPEN => {
                let successes = state.consecutive_successes.fetch_add(1, Ordering::AcqRel) + 1;
                if successes >= self.config.success_threshold {
                    // HalfOpen -> Closed
                    if state
                        .state
                        .compare_exchange(
                            STATE_HALF_OPEN,
                            STATE_CLOSED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        state.consecutive_failures.store(0, Ordering::Release);
                        state.consecutive_successes.store(0, Ordering::Release);
                        tracing::info!("Circuit breaker CLOSED for {} (recovered)", target_url);
                    }
                } else {
                    // Allow next probe
                    state.probe_permit.store(true, Ordering::Release);
                }
            }
            _ => {}
        }
    }

    pub fn record_failure(&self, target_url: &str) {
        let state = self.get_or_create(target_url);
        let current = state.state.load(Ordering::Acquire);

        match current {
            STATE_CLOSED => {
                state.consecutive_successes.store(0, Ordering::Release);
                let failures = state.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
                if failures >= self.config.failure_threshold {
                    // Closed -> Open
                    if state
                        .state
                        .compare_exchange(
                            STATE_CLOSED,
                            STATE_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        state
                            .opened_at_nanos
                            .store(self.now_nanos(), Ordering::Release);
                        tracing::warn!(
                            "Circuit breaker OPEN for {} ({} consecutive failures)",
                            target_url,
                            failures
                        );
                    }
                }
            }
            STATE_HALF_OPEN => {
                // Probe failed, go back to Open
                if state
                    .state
                    .compare_exchange(
                        STATE_HALF_OPEN,
                        STATE_OPEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    state
                        .opened_at_nanos
                        .store(self.now_nanos(), Ordering::Release);
                    state.consecutive_successes.store(0, Ordering::Release);
                    tracing::warn!(
                        "Circuit breaker re-OPENED for {} (probe failed)",
                        target_url
                    );
                }
            }
            _ => {}
        }
    }

    pub fn is_failure_status(&self, status: u16) -> bool {
        self.config.failure_status_codes.contains(&status)
    }

    pub fn get_states(&self) -> HashMap<String, CircuitBreakerInfo> {
        let targets = self.targets.read().unwrap();
        targets
            .iter()
            .map(|(url, state)| {
                let s = state.state.load(Ordering::Acquire);
                let state_str = match s {
                    STATE_CLOSED => "closed",
                    STATE_OPEN => "open",
                    STATE_HALF_OPEN => "half_open",
                    _ => "unknown",
                };
                (
                    url.clone(),
                    CircuitBreakerInfo {
                        state: state_str.to_string(),
                        consecutive_failures: state.consecutive_failures.load(Ordering::Relaxed),
                        consecutive_successes: state.consecutive_successes.load(Ordering::Relaxed),
                    },
                )
            })
            .collect()
    }

    pub fn reset(&self) {
        let targets = self.targets.read().unwrap();
        for (url, state) in targets.iter() {
            state.state.store(STATE_CLOSED, Ordering::Release);
            state.consecutive_failures.store(0, Ordering::Release);
            state.consecutive_successes.store(0, Ordering::Release);
            state.probe_permit.store(false, Ordering::Release);
            tracing::info!("Circuit breaker reset for {}", url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            recovery_timeout: Duration::from_millis(50),
            success_threshold: 2,
            failure_status_codes: vec![502, 503, 504],
        }
    }

    #[test]
    fn test_new_target_is_closed_and_available() {
        let cb = CircuitBreaker::new(test_config());
        assert!(cb.is_available("http://backend:8080"));
    }

    #[test]
    fn test_closed_to_open_after_threshold_failures() {
        let cb = CircuitBreaker::new(test_config());
        let url = "http://backend:8080";

        cb.record_failure(url);
        assert!(cb.is_available(url));
        cb.record_failure(url);
        assert!(cb.is_available(url));
        cb.record_failure(url); // 3rd failure = threshold

        // Should now be open
        assert!(!cb.is_available(url));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(test_config());
        let url = "http://backend:8080";

        cb.record_failure(url);
        cb.record_failure(url);
        cb.record_success(url); // resets
        cb.record_failure(url);
        cb.record_failure(url);

        // Should still be closed (only 2 consecutive failures)
        assert!(cb.is_available(url));
    }

    #[test]
    fn test_open_to_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(10),
            success_threshold: 1,
            failure_status_codes: vec![502],
        };
        let cb = CircuitBreaker::new(config);
        let url = "http://backend:8080";

        cb.record_failure(url); // trips breaker
        assert!(!cb.is_available(url));

        std::thread::sleep(Duration::from_millis(20));

        // Should transition to half-open and allow one probe
        assert!(cb.is_available(url));
        // Second request should be blocked (probe permit consumed)
        assert!(!cb.is_available(url));
    }

    #[test]
    fn test_half_open_to_closed_after_success_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(10),
            success_threshold: 2,
            failure_status_codes: vec![502],
        };
        let cb = CircuitBreaker::new(config);
        let url = "http://backend:8080";

        cb.record_failure(url);
        std::thread::sleep(Duration::from_millis(20));

        // First probe
        assert!(cb.is_available(url));
        cb.record_success(url); // 1st success, issues new probe permit

        // Second probe
        assert!(cb.is_available(url));
        cb.record_success(url); // 2nd success = threshold, transitions to closed

        // Should be fully closed now
        assert!(cb.is_available(url));
        assert!(cb.is_available(url)); // unlimited access
    }

    #[test]
    fn test_half_open_to_open_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(10),
            success_threshold: 2,
            failure_status_codes: vec![502],
        };
        let cb = CircuitBreaker::new(config);
        let url = "http://backend:8080";

        cb.record_failure(url);
        std::thread::sleep(Duration::from_millis(20));

        assert!(cb.is_available(url)); // probe
        cb.record_failure(url); // probe failed

        // Should be back to open
        assert!(!cb.is_available(url));
    }

    #[test]
    fn test_failure_status_codes() {
        let cb = CircuitBreaker::new(test_config());
        assert!(cb.is_failure_status(502));
        assert!(cb.is_failure_status(503));
        assert!(cb.is_failure_status(504));
        assert!(!cb.is_failure_status(200));
        assert!(!cb.is_failure_status(404));
        assert!(!cb.is_failure_status(500));
    }

    #[test]
    fn test_get_states() {
        let cb = CircuitBreaker::new(test_config());
        let url = "http://backend:8080";

        cb.record_failure(url);
        let states = cb.get_states();
        let info = states.get(url).unwrap();
        assert_eq!(info.state, "closed");
        assert_eq!(info.consecutive_failures, 1);
    }

    #[test]
    fn test_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(300),
            success_threshold: 1,
            failure_status_codes: vec![502],
        };
        let cb = CircuitBreaker::new(config);
        let url = "http://backend:8080";

        cb.record_failure(url);
        assert!(!cb.is_available(url)); // open

        cb.reset();
        assert!(cb.is_available(url)); // closed again
    }

    #[test]
    fn test_multiple_targets_independent() {
        let cb = CircuitBreaker::new(test_config());
        let url1 = "http://backend1:8080";
        let url2 = "http://backend2:8080";

        cb.record_failure(url1);
        cb.record_failure(url1);
        cb.record_failure(url1); // trips url1

        assert!(!cb.is_available(url1));
        assert!(cb.is_available(url2)); // url2 unaffected
    }
}
