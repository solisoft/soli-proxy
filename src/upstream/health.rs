//! Active health checks for the targets of `proxy.conf` rules.
//!
//! Managed apps have their own monitor; a static target used to be judged
//! only by the circuit breaker, from live traffic — so a dead backend was
//! found out by failing real requests, and found again every recovery
//! timeout. With `@health:/path` on a rule (or `[health_checks]
//! default_path` for all of them), a background task probes each distinct
//! target and records its verdict in the circuit breaker, where target
//! selection already looks: a target that fails `unhealthy_threshold` probes
//! in a row is skipped until it passes `healthy_threshold` in a row.
//!
//! The probe set follows the configuration: a supervisor compares it after
//! every reload and, when it changed, aborts every probe task before starting
//! the new ones, so a reload never leaves a stale task probing a removed
//! target. A target that is no longer checked has its verdict cleared, so it
//! cannot stay "down" on the word of a check that no longer exists.

use super::client::UpstreamClient;
use super::retry::{finish_head, outbound_uri};
use crate::circuit_breaker::{Health, SharedCircuitBreaker};
use crate::config::{Config, ConfigManager};
use crate::pool::ProxyClient;
use crate::shutdown::ShutdownCoordinator;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{HeaderValue, HOST, USER_AGENT};
use hyper::{Request, Uri};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// How often the supervisor looks for a new configuration.
const SUPERVISE_EVERY: Duration = Duration::from_secs(1);

/// One target to probe, and how.
#[derive(Clone)]
struct Probe {
    /// The target as configured: the circuit breaker's key.
    base_url: String,
    /// What to request.
    uri: Uri,
    client: Option<Arc<UpstreamClient>>,
    interval: Duration,
    timeout: Duration,
    unhealthy_threshold: u32,
    healthy_threshold: u32,
}

impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        self.base_url == other.base_url
            && self.uri == other.uri
            && self.interval == other.interval
            && self.timeout == other.timeout
            && self.unhealthy_threshold == other.unhealthy_threshold
            && self.healthy_threshold == other.healthy_threshold
            && match (&self.client, &other.client) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }
}

/// The probes a configuration asks for. A target that several rules name is
/// probed once, as the first of them says.
fn plan(config: &Config) -> Vec<Probe> {
    let defaults = &config.health_checks;
    let mut probes: Vec<Probe> = Vec::new();
    for rule in &config.rules {
        let path = match rule.upstream.health.as_deref() {
            Some("off") => continue,
            Some(path) => path,
            None => match defaults.default_path.as_deref() {
                Some(path) => path,
                None => continue,
            },
        };
        let interval = rule
            .upstream
            .health_interval_ms
            .map_or(defaults.interval, Duration::from_millis);
        for target in &rule.targets {
            let base_url = target.url.as_str();
            if target.url.scheme() == "redirect" || probes.iter().any(|p| p.base_url == base_url) {
                continue;
            }
            // The health path is a path on the target's origin, whatever
            // path the target itself carries.
            let origin = super::routing_url(&target.url);
            let origin = &origin[..url::Position::BeforePath];
            let Ok(uri) = outbound_uri(&format!("{}{}", origin, path)) else {
                tracing::warn!("health check: cannot probe {}{}", origin, path);
                continue;
            };
            let client = rule.upstream.target_client(base_url);
            probes.push(Probe {
                base_url: base_url.to_string(),
                uri,
                client,
                interval,
                timeout: defaults.timeout,
                unhealthy_threshold: defaults.unhealthy_threshold,
                healthy_threshold: defaults.healthy_threshold,
            });
        }
    }
    probes
}

/// Start the supervisor: it keeps one probe task per checked target, in step
/// with the configuration, until shutdown.
pub fn spawn(
    config: Arc<ConfigManager>,
    breaker: SharedCircuitBreaker,
    shared: ProxyClient,
    shutdown: ShutdownCoordinator,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut stop = shutdown.subscribe();
        let mut seen: Option<Arc<Config>> = None;
        let mut current: Vec<Probe> = Vec::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        let mut tick = tokio::time::interval(SUPERVISE_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = stop.recv() => break,
                _ = tick.tick() => {}
            }
            let cfg = config.get_config();
            if seen.as_ref().is_some_and(|s| Arc::ptr_eq(s, &cfg)) {
                continue;
            }
            let wanted = plan(&cfg);
            seen = Some(cfg);
            if wanted == current {
                continue;
            }
            for task in tasks.drain(..) {
                task.abort();
            }
            for old in &current {
                if !wanted.iter().any(|p| p.base_url == old.base_url) {
                    breaker.set_health(&old.base_url, Health::Unknown);
                }
            }
            if !wanted.is_empty() {
                tracing::info!(targets = wanted.len(), "health checks (re)started");
            }
            tasks = wanted
                .iter()
                .map(|p| tokio::spawn(run(p.clone(), breaker.clone(), shared.clone())))
                .collect();
            current = wanted;
        }
        for task in tasks {
            task.abort();
        }
    })
}

/// Probe one target forever (until aborted).
async fn run(probe: Probe, breaker: SharedCircuitBreaker, shared: ProxyClient) {
    let mut tick = tokio::time::interval(probe.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut failures, mut successes) = (0u32, 0u32);
    loop {
        tick.tick().await;
        let verdict = check(&probe, &shared).await;
        let current = breaker.health(&probe.base_url);
        match verdict {
            Ok(()) => {
                failures = 0;
                successes = successes.saturating_add(1);
                // The first answer settles an unknown target at once; one
                // marked down must prove itself `healthy_threshold` times.
                if current == Health::Unknown
                    || (current == Health::Down && successes >= probe.healthy_threshold)
                {
                    breaker.set_health(&probe.base_url, Health::Up);
                    if current == Health::Down {
                        tracing::info!(target = %probe.base_url, "health check: target is back up");
                    }
                }
            }
            Err(reason) => {
                successes = 0;
                failures = failures.saturating_add(1);
                if current != Health::Down && failures >= probe.unhealthy_threshold {
                    breaker.set_health(&probe.base_url, Health::Down);
                    tracing::warn!(
                        target = %probe.base_url,
                        reason = %reason,
                        failures,
                        "health check: target marked down"
                    );
                } else {
                    tracing::debug!(target = %probe.base_url, reason = %reason, "health check failed");
                }
            }
        }
    }
}

static PROBE_AGENT: HeaderValue = HeaderValue::from_static("soli-proxy-health-check");

/// One probe. Healthy is any answer below 500 within the timeout — a 404
/// means the backend is up and the path is wrong, which is logged, not acted
/// on (the app monitor draws the same line).
async fn check(probe: &Probe, shared: &ProxyClient) -> Result<(), String> {
    let (mut parts, ()) = Request::get(probe.uri.clone())
        .body(())
        .expect("a GET with a valid URI builds")
        .into_parts();
    parts.headers.insert(USER_AGENT, PROBE_AGENT.clone());
    let client = probe.client.as_deref();
    if client.is_some_and(UpstreamClient::is_unix) {
        parts
            .headers
            .insert(HOST, HeaderValue::from_static("localhost"));
    }
    finish_head(&mut parts, client);
    let body = http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed();
    let request = Request::from_parts(parts, body);
    let sent = match client {
        Some(c) => c.request(request),
        None => shared.request(request),
    };
    match tokio::time::timeout(probe.timeout, sent).await {
        Err(_) => Err(format!("no answer within {:?}", probe.timeout)),
        Ok(Err(e)) => Err(super::retry::error_chain(&e)),
        Ok(Ok(resp)) if resp.status().is_server_error() => Err(format!("status {}", resp.status())),
        Ok(Ok(resp)) => {
            if resp.status().is_client_error() {
                tracing::warn!(
                    target = %probe.base_url,
                    status = resp.status().as_u16(),
                    "health check path answers {}; the target counts as up — is the path right?",
                    resp.status()
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyRule, RuleMatcher, Target};
    use crate::upstream::{HealthChecksConfig, UpstreamOptions};

    fn rule(targets: &[&str], health: Option<&str>) -> ProxyRule {
        ProxyRule {
            matcher: RuleMatcher::Default,
            targets: targets
                .iter()
                .map(|u| Target {
                    url: url::Url::parse(u).unwrap(),
                    weight: 100,
                })
                .collect(),
            headers: vec![],
            scripts: vec![],
            auth: vec![],
            auth_exempt: vec![],
            load_balancing: Default::default(),
            upstream: UpstreamOptions {
                health: health.map(str::to_string),
                ..Default::default()
            },
        }
    }

    fn config(rules: Vec<ProxyRule>, default_path: Option<&str>) -> Config {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[server]\nbind = \"127.0.0.1:1\"\nhttps_port = 8443\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("proxy.conf"), "").unwrap();
        let mgr = ConfigManager::new(dir.path().join("proxy.conf").to_str().unwrap()).unwrap();
        let mut cfg = (*mgr.get_config()).clone();
        cfg.rules = rules;
        cfg.health_checks = HealthChecksConfig {
            default_path: default_path.map(str::to_string),
            ..Default::default()
        };
        cfg
    }

    #[test]
    fn probes_follow_the_directives_and_dedupe_targets() {
        let cfg = config(
            vec![
                rule(&["http://a:1/v2", "http://b:2"], Some("/healthz")),
                rule(&["http://a:1/v2"], Some("/other")),
                rule(&["http://c:3"], None),
                rule(&["redirect://d.example"], Some("/up")),
            ],
            None,
        );
        let probes = plan(&cfg);
        let uris: Vec<String> = probes.iter().map(|p| p.uri.to_string()).collect();
        assert_eq!(uris, vec!["http://a:1/healthz", "http://b:2/healthz"]);
        assert_eq!(probes[0].base_url, "http://a:1/v2");
    }

    #[test]
    fn a_default_path_covers_every_rule_but_the_ones_that_opt_out() {
        let cfg = config(
            vec![
                rule(&["http://a:1"], None),
                rule(&["http://b:2"], Some("off")),
                rule(&["unix:/run/c.sock"], None),
            ],
            Some("/up"),
        );
        let uris: Vec<String> = plan(&cfg).iter().map(|p| p.uri.to_string()).collect();
        assert_eq!(uris, vec!["http://a:1/up", "http://unix.invalid/up"]);
    }
}
