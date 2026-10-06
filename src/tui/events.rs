//! What just happened, as the TUI shows it: the daemon's app events (deploy
//! stages, sleep, wake-ups) from `GET /api/v1/events/apps`, plus request
//! failures the TUI reads from the log, folded into
//!
//! - a short journal for the dashboard's "events" column, and
//! - per-app deploy progress, for the steppers on the dashboard and the apps
//!   screen.
//!
//! The SSE stream is read by a task on the TUI's runtime ([`spawn_listener`]);
//! the render thread only ever locks [`EventFeed`] to copy what it draws.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Entries kept in the journal.
const JOURNAL_LEN: usize = 40;
/// How long a finished deploy keeps showing its result.
const FINISHED_SHOWN: Duration = Duration::from_secs(4);
/// A deploy with no news for this long is assumed lost (the stream dropped
/// its end) and stops being drawn.
const STALE_DEPLOY: Duration = Duration::from_secs(180);

/// An event of the daemon's SSE stream (`AppEvent`, serialized with
/// `#[serde(tag = "type")]`). Unknown types are skipped, so a newer daemon
/// does not break an older TUI.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RemoteEvent {
    DeployStage {
        app_name: String,
        slot: String,
        #[serde(default)]
        from: String,
        stage: String,
        #[serde(default)]
        detail: Option<String>,
    },
    Asleep {
        app_name: String,
        idle_secs: u64,
    },
    Waking {
        app_name: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Start,
    Health,
    Switch,
    Drain,
}

impl Stage {
    pub const ALL: [Stage; 4] = [Stage::Start, Stage::Health, Stage::Switch, Stage::Drain];

    pub fn label(self) -> &'static str {
        match self {
            Stage::Start => "start",
            Stage::Health => "health",
            Stage::Switch => "switch",
            Stage::Drain => "drain",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "start" => Some(Stage::Start),
            "health" => Some(Stage::Health),
            "switch" => Some(Stage::Switch),
            "drain" => Some(Stage::Drain),
            _ => None,
        }
    }
}

/// A deploy as far as the stream told us.
#[derive(Debug, Clone)]
pub struct DeployProgress {
    pub slot: String,
    pub from: String,
    pub stage: Stage,
    pub started: Instant,
    pub stage_since: Instant,
    /// Seconds the old slot is given to drain, once in [`Stage::Drain`].
    pub drain_secs: Option<u64>,
    /// `Some(ok)` once done or failed, with when.
    pub finished: Option<(Instant, bool)>,
    pub detail: Option<String>,
    /// Started by a request for a sleeping app.
    pub wake: bool,
}

impl DeployProgress {
    /// Whether `stage` is behind the current one (or everything is, once
    /// the deploy succeeded).
    pub fn passed(&self, stage: Stage) -> bool {
        if matches!(self.finished, Some((_, true))) {
            return true;
        }
        let idx = |s: Stage| Stage::ALL.iter().position(|x| *x == s).unwrap_or(0);
        idx(stage) < idx(self.stage)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Deploy,
    Traffic,
    Done,
    Failed,
    Asleep,
    Waking,
    Error,
    Maintenance,
}

#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub at: Instant,
    /// Local wall-clock time, `HH:MM:SS`.
    pub clock: String,
    pub app: String,
    pub text: String,
    pub kind: EventKind,
}

#[derive(Debug, Default)]
pub struct EventFeed {
    pub journal: VecDeque<JournalEntry>,
    deploys: HashMap<String, DeployProgress>,
    waking: HashMap<String, Instant>,
    /// The SSE stream is currently connected.
    pub connected: bool,
}

impl EventFeed {
    pub fn push(&mut self, at: Instant, app: &str, text: String, kind: EventKind) {
        if self.journal.len() >= JOURNAL_LEN {
            self.journal.pop_front();
        }
        self.journal.push_back(JournalEntry {
            at,
            clock: chrono::Local::now().format("%H:%M:%S").to_string(),
            app: app.to_string(),
            text,
            kind,
        });
    }

    pub fn apply(&mut self, event: RemoteEvent, now: Instant) {
        match event {
            RemoteEvent::DeployStage {
                app_name,
                slot,
                from,
                stage,
                detail,
            } => self.apply_stage(app_name, slot, from, &stage, detail, now),
            RemoteEvent::Asleep {
                app_name,
                idle_secs,
            } => {
                let text = format!("asleep · {} idle", fmt_idle(idle_secs));
                self.push(now, &app_name, text, EventKind::Asleep);
            }
            RemoteEvent::Waking { app_name } => {
                self.waking.insert(app_name.clone(), now);
                self.push(
                    now,
                    &app_name,
                    "waking · a request".into(),
                    EventKind::Waking,
                );
            }
            RemoteEvent::Other => {}
        }
    }

    fn apply_stage(
        &mut self,
        app: String,
        slot: String,
        from: String,
        stage: &str,
        detail: Option<String>,
        now: Instant,
    ) {
        let wake = self.waking.contains_key(&app);
        match stage {
            "done" | "failed" => {
                let ok = stage == "done";
                let (took, wake) = match self.deploys.get_mut(&app) {
                    Some(d) => {
                        d.finished = Some((now, ok));
                        d.detail = detail.clone();
                        (now.duration_since(d.started), d.wake)
                    }
                    None => (Duration::ZERO, wake),
                };
                self.waking.remove(&app);
                let secs = format!("{:.1} s", took.as_secs_f64());
                let (text, kind) = match (ok, wake) {
                    (true, true) => (format!("awake in {secs}"), EventKind::Done),
                    (true, false) => (format!("live on {slot} in {secs}"), EventKind::Done),
                    (false, _) => (
                        format!("deploy failed: {}", detail.unwrap_or_default()),
                        EventKind::Failed,
                    ),
                };
                self.push(now, &app, text, kind);
            }
            other => {
                let Some(stage) = Stage::parse(other) else {
                    return;
                };
                if stage == Stage::Start {
                    self.deploys.insert(
                        app.clone(),
                        DeployProgress {
                            slot: slot.clone(),
                            from: from.clone(),
                            stage,
                            started: now,
                            stage_since: now,
                            drain_secs: None,
                            finished: None,
                            detail: None,
                            wake,
                        },
                    );
                    if !wake {
                        self.push(now, &app, format!("deploy → {slot}"), EventKind::Deploy);
                    }
                    return;
                }
                let entry = self.deploys.entry(app.clone()).or_insert(DeployProgress {
                    slot: slot.clone(),
                    from: from.clone(),
                    stage,
                    started: now,
                    stage_since: now,
                    drain_secs: None,
                    finished: None,
                    detail: None,
                    wake,
                });
                entry.stage = stage;
                entry.stage_since = now;
                if stage == Stage::Drain {
                    entry.drain_secs = detail.as_deref().and_then(|d| d.parse().ok());
                }
                if stage == Stage::Switch && !entry.wake {
                    self.push(now, &app, format!("traffic → {slot}"), EventKind::Traffic);
                }
            }
        }
    }

    /// Deploys still worth drawing at `now`: running ones, and finished ones
    /// for a few seconds.
    pub fn deploys(&self, now: Instant) -> HashMap<String, DeployProgress> {
        self.deploys
            .iter()
            .filter(|(_, d)| match d.finished {
                Some((at, _)) => now.duration_since(at) < FINISHED_SHOWN,
                None => now.duration_since(d.stage_since) < STALE_DEPLOY,
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Apps a request is waking right now.
    pub fn waking(&self, now: Instant) -> Vec<String> {
        self.waking
            .iter()
            .filter(|(_, at)| now.duration_since(**at) < STALE_DEPLOY)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Forget finished deploys and lost wake-ups, so the maps stay small.
    pub fn prune(&mut self, now: Instant) {
        self.deploys.retain(|_, d| match d.finished {
            Some((at, _)) => now.duration_since(at) < FINISHED_SHOWN,
            None => now.duration_since(d.stage_since) < STALE_DEPLOY,
        });
        self.waking
            .retain(|_, at| now.duration_since(*at) < STALE_DEPLOY);
    }
}

fn fmt_idle(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Split complete SSE frames off `buf`, returning the `data:` payloads in
/// order and leaving a partial frame in place.
pub fn drain_sse_data(buf: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(end) = buf.find("\n\n") {
        let frame: String = buf.drain(..end + 2).collect();
        for line in frame.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                out.push(data.trim_start().to_string());
            }
        }
    }
    out
}

/// Follow the daemon's app event stream for as long as the TUI runs,
/// reconnecting every few seconds when it drops or the daemon is down.
pub fn spawn_listener(
    runtime: &tokio::runtime::Runtime,
    config_manager: Arc<crate::config::ConfigManager>,
    creds: super::AdminCredentials,
    feed: Arc<Mutex<EventFeed>>,
) {
    runtime.spawn(async move {
        // No overall timeout: the response is a stream that never ends.
        let Ok(client) = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .build()
        else {
            return;
        };
        loop {
            let cfg = config_manager.get_config();
            if cfg.admin.enabled.unwrap_or(true) {
                let addr = cfg
                    .admin
                    .bind
                    .replace("0.0.0.0:", "127.0.0.1:")
                    .replace("[::]:", "127.0.0.1:");
                let url = format!("http://{addr}/api/v1/events/apps");
                if let Ok(mut resp) = creds.apply(client.get(&url)).send().await {
                    if resp.status().is_success() {
                        set_connected(&feed, true);
                        let mut buf = String::new();
                        while let Ok(Some(chunk)) = resp.chunk().await {
                            buf.push_str(&String::from_utf8_lossy(&chunk));
                            let payloads = drain_sse_data(&mut buf);
                            if payloads.is_empty() {
                                continue;
                            }
                            let now = Instant::now();
                            if let Ok(mut f) = feed.lock() {
                                for data in payloads {
                                    if let Ok(event) = serde_json::from_str::<RemoteEvent>(&data) {
                                        f.apply(event, now);
                                    }
                                }
                            }
                        }
                        set_connected(&feed, false);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

fn set_connected(feed: &Mutex<EventFeed>, connected: bool) {
    if let Ok(mut f) = feed.lock() {
        f.connected = connected;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(app: &str, slot: &str, stage: &str, detail: Option<&str>) -> RemoteEvent {
        RemoteEvent::DeployStage {
            app_name: app.into(),
            slot: slot.into(),
            from: "blue".into(),
            stage: stage.into(),
            detail: detail.map(Into::into),
        }
    }

    #[test]
    fn parses_the_daemon_events_and_skips_unknown_ones() {
        let e: RemoteEvent = serde_json::from_str(
            r#"{"type":"DeployStage","app_name":"shop","slot":"green","from":"blue","stage":"drain","detail":"10"}"#,
        )
        .unwrap();
        assert_eq!(e, stage("shop", "green", "drain", Some("10")));
        let e: RemoteEvent =
            serde_json::from_str(r#"{"type":"Asleep","app_name":"agri","idle_secs":910}"#).unwrap();
        assert_eq!(
            e,
            RemoteEvent::Asleep {
                app_name: "agri".into(),
                idle_secs: 910
            }
        );
        let e: RemoteEvent = serde_json::from_str(
            r#"{"type":"StatusChanged","app_name":"x","slot":"blue","status":"running"}"#,
        )
        .unwrap();
        assert_eq!(e, RemoteEvent::Other);
    }

    #[test]
    fn a_deploy_walks_its_stages_and_is_journaled() {
        let mut feed = EventFeed::default();
        let t0 = Instant::now();
        feed.apply(stage("shop", "green", "start", None), t0);
        feed.apply(
            stage("shop", "green", "health", None),
            t0 + Duration::from_secs(1),
        );
        let d = &feed.deploys(t0 + Duration::from_secs(1))["shop"];
        assert_eq!(d.stage, Stage::Health);
        assert!(d.passed(Stage::Start) && !d.passed(Stage::Switch));
        feed.apply(
            stage("shop", "green", "switch", None),
            t0 + Duration::from_secs(2),
        );
        feed.apply(
            stage("shop", "green", "drain", Some("10")),
            t0 + Duration::from_secs(3),
        );
        assert_eq!(
            feed.deploys(t0 + Duration::from_secs(3))["shop"].drain_secs,
            Some(10)
        );
        feed.apply(
            stage("shop", "green", "done", None),
            t0 + Duration::from_secs(13),
        );
        let d = &feed.deploys(t0 + Duration::from_secs(14))["shop"];
        assert!(matches!(d.finished, Some((_, true))));
        assert!(d.passed(Stage::Drain));
        // Shown for a few seconds after it ends, then gone.
        assert!(feed.deploys(t0 + Duration::from_secs(30)).is_empty());

        let texts: Vec<&str> = feed.journal.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "deploy → green",
                "traffic → green",
                "live on green in 13.0 s"
            ]
        );
    }

    #[test]
    fn a_wake_up_reads_as_one() {
        let mut feed = EventFeed::default();
        let t0 = Instant::now();
        feed.apply(
            RemoteEvent::Waking {
                app_name: "agri".into(),
            },
            t0,
        );
        assert_eq!(feed.waking(t0), vec!["agri".to_string()]);
        feed.apply(stage("agri", "blue", "start", None), t0);
        feed.apply(stage("agri", "blue", "switch", None), t0);
        feed.apply(
            stage("agri", "blue", "done", None),
            t0 + Duration::from_millis(1400),
        );
        assert!(feed.waking(t0).is_empty());
        let texts: Vec<&str> = feed.journal.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(texts, ["waking · a request", "awake in 1.4 s"]);
    }

    #[test]
    fn sse_frames_are_split_on_blank_lines() {
        let mut buf = String::from("data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: {\"c\"");
        assert_eq!(drain_sse_data(&mut buf), ["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(buf, "data: {\"c\"");
        buf.push_str(":3}\n\n");
        assert_eq!(drain_sse_data(&mut buf), ["{\"c\":3}"]);
        assert!(buf.is_empty());
    }
}
