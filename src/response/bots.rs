//! Bots: user agents to refuse, trap paths that ban, a 404 budget.
//!
//! `[bots]` in `config.toml` (and `[bots]` in an `app.infos` for one app)
//! turns on three independent defences, all off by default:
//!
//! - `block_agents`: a `User-Agent` containing one of these (presets such as
//!   `"ai-training"` or plain substrings, case-insensitive) gets a 403.
//! - `traps`: a request for a path no site here serves — `/.env`,
//!   `/wp-login.php`, `/.git/config` — gets a 404 and its client is banned
//!   for `ban_secs`, on every app.
//! - `max_404_per_minute`: a client past that many 404s in a minute is banned
//!   the same way.
//!
//! A banned client gets a 403 for everything until the ban ends. Bans live in
//! memory: a restart forgets them, and a scanner that comes back is banned
//! again on its first probe.
//!
//! Requests a page made a browser send — an image, a script, a link followed
//! from another site, which carry `Sec-Fetch-Site` — never ban anyone: any
//! site could otherwise put `<img src="https://your.site/.env">` on its pages
//! and have its visitors banned from yours. Scanners do not send that
//! header; one that forges it gets a 404 and is not banned.
//!
//! Never refused or banned: `allow_ips`, loopback, the `trusted_proxies`
//! themselves (banning a Cloudflare edge would ban everyone behind it), and
//! the paths that always work (ACME challenges, the proxy's health and
//! metrics endpoints).

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::server::BoxBody;

/// Longest ban `ban_secs` may ask for: a week.
const MAX_BAN_SECS: u64 = 7 * 24 * 3600;
/// Clients tracked at once, banned or counted. Past it the oldest bans
/// make room, and the 404 counts start over.
const MAX_TRACKED: usize = 65_536;
/// Shortest `block_agents` entry: two letters would match half the web.
const MIN_AGENT_LEN: usize = 3;
/// Longest reason kept with a ban (a method, a host and a path).
const MAX_REASON: usize = 200;

/// Crawlers that collect pages to train models.
const AI_TRAINING: &[&str] = &[
    "gptbot",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "ccbot",
    "bytespider",
    "cohere-training-data-crawler",
    "meta-externalagent",
    "diffbot",
    "imagesiftbot",
    "omgilibot",
    "timpibot",
    "ai2bot",
    "img2dataset",
    "friendlycrawler",
    "iaskspider",
    "kangaroo bot",
    "pangubot",
    "panscient",
    "webzio-extended",
];
/// Assistants fetching a page because someone asked them a question, and
/// the AI search engines that index for them.
const AI_ASSISTANTS: &[&str] = &[
    "chatgpt-user",
    "oai-searchbot",
    "claude-user",
    "claude-searchbot",
    "perplexitybot",
    "perplexity-user",
    "duckassistbot",
    "mistralai-user",
    "youbot",
    "amazonbot",
    "meta-externalfetcher",
    "cohere-ai",
    "phindbot",
];
/// SEO tools' crawlers: backlink and keyword databases.
const SEO: &[&str] = &[
    "ahrefsbot",
    "semrushbot",
    "mj12bot",
    "dotbot",
    "blexbot",
    "dataforseobot",
    "serpstatbot",
    "seekportbot",
    "barkrowler",
    "megaindex",
];
/// Vulnerability and port scanners that say what they are.
const SCANNERS: &[&str] = &[
    "zgrab",
    "masscan",
    "nuclei",
    "sqlmap",
    "nikto",
    "nmap scripting engine",
    "wpscan",
    "l9explore",
    "l9tcpid",
    "censysinspect",
    "expanse",
    "internetmeasurement",
    "modatscanner",
    "fuzz faster u fool",
    "gobuster",
    "dirbuster",
];

/// `block_agents` presets, by name.
pub const PRESETS: &[(&str, &[&str])] = &[
    ("ai-training", AI_TRAINING),
    ("ai-assistants", AI_ASSISTANTS),
    ("seo", SEO),
    ("scanners", SCANNERS),
];

/// Paths `traps = true` bans on unless `trap_paths` replaces them: files and
/// admin pages scanners look for, which none of a Soli proxy's apps serve.
/// An app that does (a WordPress) sets `traps = false` in its `app.infos`.
pub const DEFAULT_TRAP_PATHS: &[&str] = &[
    "/.env*",
    "/.git/*",
    "/.svn/*",
    "/.aws/*",
    "/.ssh/*",
    "/.DS_Store",
    "/wp-login.php",
    "/wp-admin/*",
    "/wp-includes/*",
    "/wp-content/*",
    "/wp-config.php*",
    "/xmlrpc.php",
    "/phpmyadmin*",
    "/phpMyAdmin*",
    "/pma/*",
    "/vendor/phpunit/*",
    "/cgi-bin/*",
    "/boaform/*",
    "/HNAP1",
];

/// A compiled `block_agents`: lowercase needles, each with the name it is
/// reported under (its preset, or the entry itself).
#[derive(Clone, Debug, Default)]
pub struct AgentList(Vec<(Box<str>, Arc<str>)>);

impl AgentList {
    /// Expand presets and check the entries. `what` names the setting in
    /// errors.
    pub fn compile(entries: &[String], what: &str) -> anyhow::Result<Self> {
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if let Some((name, needles)) = PRESETS.iter().find(|(n, _)| *n == entry) {
                let label: Arc<str> = Arc::from(*name);
                out.extend(needles.iter().map(|n| (Box::from(*n), label.clone())));
            } else if entry.chars().count() < MIN_AGENT_LEN {
                anyhow::bail!(
                    "{what} entry {entry:?} is too short: a user agent substring needs at least \
                     {MIN_AGENT_LEN} characters (presets: {})",
                    preset_names()
                );
            } else {
                out.push((Box::from(entry.to_lowercase()), Arc::from(entry)));
            }
        }
        Ok(Self(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The name of the entry `agent` matches, if any.
    pub fn matches(&self, agent: &[u8]) -> Option<&Arc<str>> {
        self.0
            .iter()
            .find(|(needle, _)| contains_ignore_ascii_case(agent, needle.as_bytes()))
            .map(|(_, label)| label)
    }
}

fn preset_names() -> String {
    PRESETS
        .iter()
        .map(|(n, _)| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `needle` is lowercase already.
fn contains_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || hay.windows(needle.len()).any(|w| {
            w.iter()
                .zip(needle)
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
}

/// `[bots]` in `config.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BotsConfig {
    /// The master switch: `false` turns everything below off, bans
    /// included, except on the sites whose `app.infos` says `enabled = true`.
    pub enabled: bool,
    /// User agents refused with a 403: presets (`"ai-training"`,
    /// `"ai-assistants"`, `"seo"`, `"scanners"`) or substrings,
    /// case-insensitive.
    pub block_agents: Vec<String>,
    /// Ban a client that asks for one of `trap_paths`.
    pub traps: bool,
    /// The trap paths, `@noauth` syntax (exact, or a prefix ending in `*`).
    /// Unset: [`DEFAULT_TRAP_PATHS`].
    pub trap_paths: Option<Vec<String>>,
    /// Ban a client past this many 404s in a minute. 0 (the default): off.
    pub max_404_per_minute: u32,
    /// How long a ban lasts. Default an hour.
    pub ban_secs: u64,
    /// Clients never refused nor banned: IPs or CIDRs.
    pub allow_ips: Vec<String>,
    #[serde(skip)]
    agents: AgentList,
    #[serde(skip)]
    nets: Vec<(IpAddr, u8)>,
}

impl Default for BotsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_agents: Vec::new(),
            traps: false,
            trap_paths: None,
            max_404_per_minute: 0,
            ban_secs: 3600,
            allow_ips: Vec::new(),
            agents: AgentList::default(),
            nets: Vec::new(),
        }
    }
}

impl BotsConfig {
    /// Validate the section and compile it, once per loaded config.
    pub fn validated(mut self) -> anyhow::Result<Self> {
        self.agents = AgentList::compile(&self.block_agents, "[bots] block_agents")?;
        if self.ban_secs == 0 || self.ban_secs > MAX_BAN_SECS {
            anyhow::bail!(
                "[bots] ban_secs = {}: expected 1 to {} seconds",
                self.ban_secs,
                MAX_BAN_SECS
            );
        }
        for p in self.trap_paths.iter().flatten() {
            if crate::config::validate_auth_exempt_path(p).is_none() {
                anyhow::bail!(
                    "[bots] trap_paths entry {p:?} is invalid: expected an absolute path such as \
                     /.env or /wp-admin/*, with no '..' segment and no percent-encoding"
                );
            }
        }
        self.nets = self
            .allow_ips
            .iter()
            .map(|t| {
                super::maintenance::parse_cidr(t).ok_or_else(|| {
                    anyhow::anyhow!("[bots] allow_ips entry {t:?} is not an IP address or CIDR")
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(self)
    }

    /// Nothing to do for any request, unless an app asks for something or a
    /// ban is in force.
    fn inert(&self) -> bool {
        self.agents.is_empty() && !self.traps && self.max_404_per_minute == 0
    }

    fn is_trap(&self, path: &str) -> bool {
        match &self.trap_paths {
            Some(paths) => crate::config::path_is_auth_exempt(paths, path),
            None => DEFAULT_TRAP_PATHS
                .iter()
                .any(|p| match p.strip_suffix('*') {
                    Some(prefix) => path.starts_with(prefix),
                    None => path == *p,
                }),
        }
    }
}

/// `[bots]` in an `app.infos`: what this app changes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AppBots {
    /// `false`: nothing of `[bots]` applies to this site — no refused agent,
    /// no trap, no 404 count, and a banned client is served. `true`: it
    /// applies here even when `config.toml` says `enabled = false`.
    pub enabled: Option<bool>,
    /// `false`: requests to this app never get a client banned — neither its
    /// trap paths nor its 404s (a WordPress serves `/wp-admin/`). `true`
    /// turns traps on for this app when `config.toml` leaves them off.
    pub traps: Option<bool>,
    /// Replaces `[bots] block_agents` for this app (`[]`: refuse none).
    pub block_agents: Option<Vec<String>>,
}

impl AppBots {
    pub fn is_set(&self) -> bool {
        self.enabled.is_some() || self.traps.is_some() || self.block_agents.is_some()
    }

    /// Check the entries; the error names the app's file.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(agents) = &self.block_agents {
            AgentList::compile(agents, "[bots] block_agents")?;
        }
        Ok(())
    }

    /// The per-request form, `None` when the app changes nothing.
    pub fn compiled(&self) -> Option<Arc<AppBotsPolicy>> {
        if !self.is_set() {
            return None;
        }
        let agents = self
            .block_agents
            .as_ref()
            .map(|a| AgentList::compile(a, "[bots] block_agents").unwrap_or_default());
        Some(Arc::new(AppBotsPolicy {
            enabled: self.enabled,
            traps: self.traps,
            agents,
        }))
    }
}

/// An app's `[bots]`, compiled.
#[derive(Debug)]
pub struct AppBotsPolicy {
    pub enabled: Option<bool>,
    pub traps: Option<bool>,
    pub agents: Option<AgentList>,
}

/// One ban.
#[derive(Clone, Debug)]
pub struct Ban {
    pub until: Instant,
    pub since: chrono::DateTime<chrono::Utc>,
    pub reason: String,
}

/// What the bans and counters look like, for the admin API.
#[derive(Debug, Serialize)]
pub struct BotsSnapshot {
    pub bans: Vec<BanInfo>,
    /// Bans since the proxy started (ended ones included).
    pub banned_total: u64,
    /// Requests refused for their user agent, by the entry they matched.
    pub blocked: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct BanInfo {
    /// The client, or its /64 for IPv6.
    pub ip: String,
    pub since: String,
    pub until: String,
    pub reason: String,
}

/// Runtime state: bans, 404 counts and counters. Shared by every clone of
/// the `ConfigManager`, and kept across reloads.
#[derive(Default)]
pub struct Bots {
    bans: Mutex<HashMap<IpAddr, Ban>>,
    /// Bans in `bans`, read without the lock on every request.
    ban_count: AtomicUsize,
    /// 404s per client in the current minute: (minute, count).
    misses: Mutex<HashMap<IpAddr, (u64, u32)>>,
    banned_total: AtomicU64,
    blocked: Mutex<HashMap<Arc<str>, u64>>,
}

impl Bots {
    /// The ban on `ip`, if one is in force. One atomic load when none is.
    pub fn banned(&self, ip: IpAddr, now: Instant) -> bool {
        if self.ban_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let key = crate::server::client_key(ip);
        let mut bans = self.bans.lock();
        match bans.get(&key) {
            Some(ban) if ban.until > now => true,
            Some(_) => {
                bans.remove(&key);
                self.ban_count.store(bans.len(), Ordering::Relaxed);
                false
            }
            None => false,
        }
    }

    /// Ban `ip` for `secs`. Logged once; a ban already in force is extended.
    pub fn ban(&self, ip: IpAddr, secs: u64, reason: &str, now: Instant) {
        let key = crate::server::client_key(ip);
        let mut reason = reason.to_string();
        if reason.len() > MAX_REASON {
            let mut cut = MAX_REASON;
            while !reason.is_char_boundary(cut) {
                cut -= 1;
            }
            reason.truncate(cut);
        }
        let mut bans = self.bans.lock();
        if bans.len() >= MAX_TRACKED {
            bans.retain(|_, b| b.until > now);
            if bans.len() >= MAX_TRACKED {
                // Still full: the ban ending soonest makes room.
                if let Some(first) = bans.iter().min_by_key(|(_, b)| b.until).map(|(k, _)| *k) {
                    bans.remove(&first);
                }
            }
        }
        let until = now + Duration::from_secs(secs);
        let since = match bans.get(&key).filter(|b| b.until > now) {
            // Extended: still the same ban, started when it started.
            Some(ban) => ban.since,
            None => {
                let who = shown(&key);
                tracing::warn!(client = %who, "bots: banned {} for {}s: {}", who, secs, reason);
                self.banned_total.fetch_add(1, Ordering::Relaxed);
                chrono::Utc::now()
            }
        };
        bans.insert(
            key,
            Ban {
                until,
                since,
                reason,
            },
        );
        self.ban_count.store(bans.len(), Ordering::Relaxed);
    }

    /// Lift the ban on `ip` (or its /64). Whether there was one.
    pub fn unban(&self, ip: IpAddr) -> bool {
        let key = crate::server::client_key(ip);
        let mut bans = self.bans.lock();
        let had = bans.remove(&key).is_some();
        self.ban_count.store(bans.len(), Ordering::Relaxed);
        if had {
            let who = shown(&key);
            tracing::info!(client = %who, "bots: ban on {} lifted", who);
        }
        had
    }

    /// Count a 404 for `ip`; ban it past `limit` in a minute.
    pub fn note_404(&self, ip: IpAddr, limit: u32, ban_secs: u64, now: Instant) {
        let key = crate::server::client_key(ip);
        let minute = unix_minute();
        let over = {
            let mut misses = self.misses.lock();
            if misses.len() >= MAX_TRACKED {
                misses.retain(|_, (m, _)| *m == minute);
                if misses.len() >= MAX_TRACKED {
                    misses.clear();
                }
            }
            let entry = misses.entry(key).or_insert((minute, 0));
            if entry.0 != minute {
                *entry = (minute, 0);
            }
            entry.1 += 1;
            let over = entry.1 > limit;
            if over {
                misses.remove(&key);
            }
            over
        };
        if over {
            self.ban(
                ip,
                ban_secs,
                &format!("more than {limit} 404s in a minute"),
                now,
            );
        }
    }

    fn note_blocked(&self, label: &Arc<str>) {
        *self.blocked.lock().entry(label.clone()).or_default() += 1;
    }

    pub fn snapshot(&self) -> BotsSnapshot {
        let now = Instant::now();
        let wall = chrono::Utc::now();
        let mut bans: Vec<BanInfo> = self
            .bans
            .lock()
            .iter()
            .filter(|(_, b)| b.until > now)
            .map(|(ip, b)| {
                let left = b.until.saturating_duration_since(now);
                let until = wall + chrono::Duration::from_std(left).unwrap_or_default();
                BanInfo {
                    ip: shown(ip),
                    since: b.since.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    until: until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    reason: b.reason.clone(),
                }
            })
            .collect();
        bans.sort_by(|a, b| b.since.cmp(&a.since));
        BotsSnapshot {
            bans,
            banned_total: self.banned_total.load(Ordering::Relaxed),
            blocked: self
                .blocked
                .lock()
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
        }
    }
}

/// A ban's key as people read it: the address, or its /64.
fn shown(key: &IpAddr) -> String {
    match key {
        IpAddr::V6(_) => format!("{key}/64"),
        IpAddr::V4(_) => key.to_string(),
    }
}

fn unix_minute() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

/// What the request path does with a request.
pub enum Verdict {
    /// Serve it. `count_404`: a 404 answer counts against its client.
    Pass { count_404: Option<IpAddr> },
    /// Answer this instead.
    Refuse(Response<BoxBody>),
}

const PASS: Verdict = Verdict::Pass { count_404: None };

/// Whether a page made the browser send this request (`Sec-Fetch-Site` is
/// set, and is not `none`, which a typed address or a bookmark sends).
fn page_initiated<B>(req: &Request<B>) -> bool {
    req.headers()
        .get("sec-fetch-site")
        .is_some_and(|v| v.as_bytes() != b"none")
}

/// Judge `req` before it is served. When `[bots]` is off, no app sets
/// `[bots]` and nobody is banned — the steady state of most proxies — this
/// is three loads and a comparison.
pub fn check<B>(
    req: &Request<B>,
    config: &crate::config::Config,
    bots: &Bots,
    apps: Option<&crate::app::AppManager>,
    peer: Option<SocketAddr>,
) -> Verdict {
    let policy = &config.bots;
    let app_rules = apps.is_some_and(|m| m.any_bots());
    if !app_rules
        && (!policy.enabled || policy.inert() && bots.ban_count.load(Ordering::Relaxed) == 0)
    {
        return PASS;
    }
    let path = req.uri().path();
    if super::maintenance::always_allowed(path, config) {
        return PASS;
    }
    let Some(ip) = super::maintenance::client_ip(req, peer) else {
        return PASS;
    };
    if ip.is_loopback()
        || ip.to_canonical().is_loopback()
        || policy
            .nets
            .iter()
            .any(|n| super::maintenance::in_net(ip, *n))
        || config.server.edge.trusts(ip)
    {
        return PASS;
    }
    let app = if app_rules {
        let host_value = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri().authority().map(|a| a.as_str()))
            .unwrap_or("");
        let host = host_value.split(':').next().unwrap_or(host_value);
        apps.and_then(|m| m.serving_route(host, crate::server::static_route(req, &config.rules)))
            .and_then(|r| r.bots.clone())
    } else {
        None
    };
    // A site's own switch wins over the global one, both ways.
    if !app
        .as_ref()
        .and_then(|a| a.enabled)
        .unwrap_or(policy.enabled)
    {
        return PASS;
    }
    let now = Instant::now();
    if bots.banned(ip, now) {
        return Verdict::Refuse(refusal(StatusCode::FORBIDDEN, "Forbidden\n"));
    }

    let agents = app
        .as_ref()
        .and_then(|a| a.agents.as_ref())
        .unwrap_or(&policy.agents);
    if !agents.is_empty() {
        let agent = req
            .headers()
            .get(header::USER_AGENT)
            .map(|v| v.as_bytes())
            .unwrap_or(b"");
        if let Some(label) = agents.matches(agent) {
            bots.note_blocked(label);
            tracing::debug!(client = %ip, agent = %String::from_utf8_lossy(agent), "bots: refused {}", label);
            return Verdict::Refuse(refusal(StatusCode::FORBIDDEN, "Forbidden\n"));
        }
    }

    let app_traps = app.as_ref().and_then(|a| a.traps);
    if app_traps == Some(false) || page_initiated(req) {
        return PASS;
    }
    if app_traps.unwrap_or(policy.traps) && policy.is_trap(path) {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        bots.ban(ip, policy.ban_secs, &format!("{path} on {host}"), now);
        return Verdict::Refuse(refusal(StatusCode::NOT_FOUND, "Not Found\n"));
    }
    Verdict::Pass {
        count_404: (policy.max_404_per_minute > 0).then_some(ip),
    }
}

/// After the response: count a 404 against the client `check` named.
pub fn after(bots: &Bots, config: &crate::config::Config, client: Option<IpAddr>, status: u16) {
    if let (Some(ip), 404) = (client, status) {
        let policy = &config.bots;
        bots.note_404(
            ip,
            policy.max_404_per_minute,
            policy.ban_secs,
            Instant::now(),
        );
    }
}

fn refusal(status: StatusCode, text: &'static str) -> Response<BoxBody> {
    let mut resp = Response::new(crate::server::full(Bytes::from_static(text.as_bytes())));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    super::mark_owned(&mut resp, super::BodyOwner::Rendered);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> crate::config::Config {
        let mut c = crate::response::test_config();
        c.bots = toml::from_str::<BotsConfig>(toml)
            .expect("parses")
            .validated()
            .expect("valid");
        c
    }

    fn req(path: &str, agent: &str, ip: &str) -> Request<()> {
        let mut r = Request::builder()
            .uri(path)
            .header("host", "shop.example.com")
            .header("user-agent", agent)
            .body(())
            .unwrap();
        r.extensions_mut()
            .insert(crate::edge::ClientInfo::direct(ip.parse().unwrap()));
        r
    }

    fn refused(v: &Verdict) -> Option<u16> {
        match v {
            Verdict::Refuse(r) => Some(r.status().as_u16()),
            Verdict::Pass { .. } => None,
        }
    }

    #[test]
    fn presets_and_substrings_match_case_insensitively() {
        let list = AgentList::compile(&["ai-training".to_string(), "EvilBot".to_string()], "test")
            .unwrap();
        let ua = b"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2)";
        assert_eq!(list.matches(ua).map(|l| &**l), Some("ai-training"));
        assert_eq!(list.matches(b"evilbot/2").map(|l| &**l), Some("EvilBot"));
        assert!(list
            .matches(b"Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
            .is_none());
        assert!(list.matches(b"Googlebot/2.1").is_none());
        assert!(AgentList::compile(&["ab".to_string()], "test").is_err());
    }

    #[test]
    fn a_blocked_agent_gets_a_403_and_is_counted() {
        let c = config(r#"block_agents = ["ai-training", "scanners"]"#);
        let bots = Bots::default();
        let v = check(
            &req("/", "CCBot/2.0", "198.51.100.7"),
            &c,
            &bots,
            None,
            None,
        );
        assert_eq!(refused(&v), Some(403));
        let v = check(
            &req("/", "Mozilla/5.0 Firefox", "198.51.100.7"),
            &c,
            &bots,
            None,
            None,
        );
        assert_eq!(refused(&v), None);
        assert_eq!(bots.snapshot().blocked.get("ai-training"), Some(&1));
    }

    #[test]
    fn a_trap_bans_the_client_everywhere_but_not_a_page_s_subrequest() {
        let c = config("traps = true\nban_secs = 60");
        let bots = Bots::default();
        let ip = "203.0.113.9";
        // An <img src="/.env"> on someone's page: a 404, nobody banned.
        let mut from_page = req("/.env", "Mozilla/5.0", ip);
        from_page
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert_eq!(refused(&check(&from_page, &c, &bots, None, None)), None);
        assert_eq!(
            refused(&check(&req("/", "x", ip), &c, &bots, None, None)),
            None
        );

        assert_eq!(
            refused(&check(
                &req("/.env.production", "curl/8", ip),
                &c,
                &bots,
                None,
                None
            )),
            Some(404)
        );
        assert_eq!(
            refused(&check(&req("/", "Mozilla/5.0", ip), &c, &bots, None, None)),
            Some(403)
        );
        // Another client is untouched; so is the ACME challenge path.
        assert_eq!(
            refused(&check(
                &req("/", "x", "203.0.113.10"),
                &c,
                &bots,
                None,
                None
            )),
            None
        );
        assert_eq!(
            refused(&check(
                &req("/.well-known/acme-challenge/t", "x", ip),
                &c,
                &bots,
                None,
                None
            )),
            None
        );
        let snap = bots.snapshot();
        assert_eq!(snap.bans.len(), 1);
        assert_eq!(snap.bans[0].reason, "/.env.production on shop.example.com");
        assert!(bots.unban(ip.parse().unwrap()));
        assert_eq!(
            refused(&check(&req("/", "x", ip), &c, &bots, None, None)),
            None
        );
    }

    #[test]
    fn allowed_and_trusted_clients_are_never_banned() {
        let mut c = config("traps = true\nallow_ips = [\"10.0.0.0/8\"]");
        c.server.edge.trusted_proxies =
            crate::edge::TrustedProxies::parse(&["192.0.2.0/24".to_string()]).unwrap();
        let bots = Bots::default();
        for ip in ["10.1.2.3", "127.0.0.1", "192.0.2.5"] {
            assert_eq!(
                refused(&check(&req("/.env", "x", ip), &c, &bots, None, None)),
                None,
                "{ip}"
            );
        }
        assert!(bots.snapshot().bans.is_empty());
    }

    #[test]
    fn too_many_404s_ban_and_ipv6_is_banned_per_64() {
        let c = config("max_404_per_minute = 3");
        let bots = Bots::default();
        let ip: IpAddr = "2001:db8:1:2::5".parse().unwrap();
        for _ in 0..3 {
            after(&bots, &c, Some(ip), 404);
        }
        after(&bots, &c, Some(ip), 200);
        assert!(!bots.banned(ip, Instant::now()));
        after(&bots, &c, Some(ip), 404);
        let neighbour: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        assert!(bots.banned(neighbour, Instant::now()));
        assert_eq!(bots.snapshot().bans[0].ip, "2001:db8:1:2::/64");
    }

    #[test]
    fn bans_end() {
        let bots = Bots::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let now = Instant::now();
        bots.ban(ip, 1, "test", now);
        assert!(bots.banned(ip, now));
        assert!(!bots.banned(ip, now + Duration::from_secs(2)));
        assert!(bots.snapshot().bans.is_empty());
    }

    #[test]
    fn the_global_switch_turns_everything_off_bans_included() {
        let c = config("enabled = false\ntraps = true\nblock_agents = [\"scanners\"]");
        let bots = Bots::default();
        let ip = "198.51.100.20";
        bots.ban(ip.parse().unwrap(), 60, "earlier", Instant::now());
        for (path, agent) in [("/", "x"), ("/.env", "curl/8"), ("/", "sqlmap/1.7")] {
            let v = check(&req(path, agent, ip), &c, &bots, None, None);
            assert!(
                matches!(v, Verdict::Pass { count_404: None }),
                "{path} {agent}"
            );
        }
        assert_eq!(bots.snapshot().bans.len(), 1, "the ban itself is kept");
    }

    #[test]
    fn the_section_is_checked() {
        let bad = |t: &str| {
            toml::from_str::<BotsConfig>(t)
                .unwrap()
                .validated()
                .is_err()
        };
        assert!(bad("ban_secs = 0"));
        assert!(bad("ban_secs = 99999999"));
        assert!(bad(r#"trap_paths = ["no-slash"]"#));
        assert!(bad(r#"allow_ips = ["not an ip"]"#));
        assert!(bad(r#"block_agents = ["go"]"#));
        assert!(toml::from_str::<BotsConfig>("unknown = 1").is_err());
        let c = config(
            r#"traps = true
trap_paths = ["/secret", "/admin/*"]"#,
        );
        assert!(c.bots.is_trap("/admin/x") && c.bots.is_trap("/secret"));
        assert!(!c.bots.is_trap("/.env"));
    }
}
