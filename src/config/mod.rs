pub mod serializer;

use crate::auth::BasicAuth;
use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::mpsc;
use url::Url;

#[async_trait::async_trait]
pub trait ConfigManagerTrait: Send + Sync {
    async fn reload(&self) -> Result<()>;
    fn get_config(&self) -> Arc<Config>;
    fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()>;
    fn add_route(&self, rule: ProxyRule) -> Result<()>;
    fn remove_route(&self, index: usize) -> Result<()>;
    fn register_app_acme_domains(&self, domains: Vec<String>);
    fn unregister_app_acme_domain(&self, domain: &str);
    fn get_all_acme_domains(&self) -> Vec<String>;
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct TomlConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
    pub scripting: Option<ScriptingTomlConfig>,
    pub admin: Option<AdminConfig>,
    pub circuit_breaker: Option<CircuitBreakerTomlConfig>,
    #[serde(default)]
    pub apps: Option<AppsTomlConfig>,
    #[serde(default)]
    pub limits: Option<LimitsTomlConfig>,
    #[serde(default)]
    pub health: Option<HealthConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub rate_limiting: Option<RateLimitingConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CircuitBreakerTomlConfig {
    pub failure_threshold: Option<u32>,
    pub recovery_timeout_secs: Option<u64>,
    pub success_threshold: Option<u32>,
    pub failure_status_codes: Option<Vec<u16>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct AppsTomlConfig {
    pub default_user: Option<String>,
    pub default_group: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct LimitsTomlConfig {
    pub max_connections: Option<u64>,
    pub max_request_size: Option<String>,
    pub keep_alive_timeout: Option<u64>,
    pub request_timeout: Option<u64>,
    pub websocket_idle_timeout_secs: Option<u64>,
    pub websocket_max_lifetime_secs: Option<u64>,
    pub websocket_max_bytes_per_direction: Option<u64>,
}

pub fn parse_size(value: &str) -> Option<usize> {
    let value = value.trim().to_uppercase();
    let (num_str, multiplier) = if value.ends_with("GB") {
        (&value[..value.len() - 2], 1024 * 1024 * 1024)
    } else if value.ends_with("MB") {
        ((&value[..value.len() - 2]), 1024 * 1024)
    } else if value.ends_with("KB") {
        ((&value[..value.len() - 2]), 1024)
    } else {
        (&value[..], 1)
    };

    num_str
        .trim()
        .parse::<usize>()
        .ok()?
        .checked_mul(multiplier)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: Option<bool>,
    pub bind: String,
    // Read from `[admin].api_key` in config.toml, but never serialized back
    // out (e.g. when the config is rewritten) so the secret doesn't leak.
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    #[serde(default, skip)]
    pub username: Option<String>,
    #[serde(default, skip)]
    pub password_hash: Option<String>,
}

fn default_admin_enabled() -> Option<bool> {
    Some(true)
}

fn looks_like_bcrypt_hash(s: &str) -> bool {
    s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$")
}

impl Default for AdminConfig {
    fn default() -> Self {
        let dotenv_loaded = dotenv::dotenv().is_ok();
        let username = std::env::var("ADMIN_USER").ok();
        let password_hash = std::env::var("ADMIN_PASSWORD").ok();

        if dotenv_loaded {
            tracing::debug!("Loaded environment from .env file");
        }

        if let Some(ref hash) = password_hash {
            if !looks_like_bcrypt_hash(hash) {
                tracing::warn!(
                    "ADMIN_PASSWORD does not look like a valid bcrypt hash (expected $2a$/$2b$/$2y$ prefix). \
                    The value was stored as-is and login attempts will fail. \
                    Set ADMIN_PASSWORD_HASH instead, or use ADMIN_PASSWORD to supply a plaintext password \
                    that will be hashed at startup."
                );
            }
        }

        Self {
            enabled: Some(true),
            bind: "127.0.0.1:9090".to_string(),
            api_key: None,
            username,
            password_hash,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ScriptingTomlConfig {
    pub enabled: bool,
    pub scripts_dir: Option<String>,
    pub hook_timeout_ms: Option<u64>,
    /// Environment variables exposed to Lua scripts. Defaults to empty so a
    /// pre-existing config.toml without this field still parses — without the
    /// default, the entire TOML deserialize fails, the proxy silently falls
    /// back to ServerConfig::default() (bind = 0.0.0.0:8080), and port 80 is
    /// no longer bound.
    #[serde(default)]
    pub exposed_env: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerConfig {
    pub bind: String,
    pub https_port: u16,
    #[serde(default)]
    pub worker_threads: Option<WorkerThreads>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_string(),
            https_port: 443,
            worker_threads: None,
        }
    }
}

/// Tokio worker-thread setting. Accepts either the literal string `"auto"` or
/// a positive integer in `config.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerThreads {
    Auto,
    Count(u16),
}

impl Serialize for WorkerThreads {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            WorkerThreads::Auto => serializer.serialize_str("auto"),
            WorkerThreads::Count(n) => serializer.serialize_u16(*n),
        }
    }
}

impl<'de> Deserialize<'de> for WorkerThreads {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = WorkerThreads;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "\"auto\" or a positive integer up to {}", u16::MAX)
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v == 0 || v > u16::MAX as u64 {
                    return Err(E::custom(format!(
                        "worker_threads must be in 1..={}",
                        u16::MAX
                    )));
                }
                Ok(WorkerThreads::Count(v as u16))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v <= 0 || v > u16::MAX as i64 {
                    return Err(E::custom(format!(
                        "worker_threads must be in 1..={}",
                        u16::MAX
                    )));
                }
                Ok(WorkerThreads::Count(v as u16))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.eq_ignore_ascii_case("auto") {
                    Ok(WorkerThreads::Auto)
                } else {
                    Err(E::custom(format!(
                        "unknown worker_threads value: {:?} (expected \"auto\" or an integer)",
                        v
                    )))
                }
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// Read just the `worker_threads` setting from `config.toml` next to
/// `config_path`. Returns `None` when the file is missing or the field is
/// unset, letting the caller fall back to its own default.
pub fn read_worker_threads(config_path: &str) -> Option<WorkerThreads> {
    let path = PathBuf::from(config_path);
    let toml_path = path.parent().unwrap_or(Path::new(".")).join("config.toml");
    let content = std::fs::read_to_string(&toml_path).ok()?;
    let toml_config: TomlConfig = toml::from_str(&content).ok()?;
    toml_config.server.worker_threads
}

/// Decide how many Tokio worker threads to use given the `--dev` flag and the
/// `worker_threads` setting from `config.toml`. Returns `Some(n)` for an
/// explicit count, or `None` to let Tokio auto-detect (one worker per core).
pub fn resolve_worker_threads(dev_mode: bool, config: Option<&WorkerThreads>) -> Option<usize> {
    match config {
        Some(WorkerThreads::Count(n)) => Some(*n as usize),
        Some(WorkerThreads::Auto) => None,
        None if dev_mode => Some(1),
        None => None,
    }
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct TlsConfig {
    pub mode: String,
    pub cache_dir: String,
    #[serde(default = "default_force_https")]
    pub force_https: bool,
    /// HSTS `max-age` in seconds. Set to 0 (or omit and rely on the default)
    /// to disable. When unset, defaults to 63072000 (2 years), the value
    /// recommended by the IETF and required for HSTS preload submission.
    #[serde(default)]
    pub hsts_max_age_seconds: Option<u64>,
    /// Whether to append `; includeSubDomains` to the HSTS header. Operators
    /// on shared parent domains (e.g. apex `example.com` serves multiple
    /// independent subdomains) need to opt out. Defaults to `true`.
    #[serde(default)]
    pub hsts_include_subdomains: Option<bool>,
}

fn default_force_https() -> bool {
    true
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct LetsEncryptConfig {
    pub staging: bool,
    pub email: String,
    pub terms_agreed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub letsencrypt: Option<LetsEncryptConfig>,
    pub scripting: ScriptingTomlConfig,
    pub admin: AdminConfig,
    pub circuit_breaker: Option<CircuitBreakerTomlConfig>,
    pub apps: AppsTomlConfig,
    pub rules: Vec<ProxyRule>,
    pub global_scripts: Vec<String>,
    pub limits: LimitsConfig,
    pub health: HealthConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub rate_limiting: RateLimitingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct LimitsConfig {
    pub max_connections: Option<u64>,
    pub max_request_size: Option<usize>,
    pub keep_alive_timeout: Option<u64>,
    pub request_timeout: Option<u64>,
    /// Drop a forwarded WebSocket if either direction is silent for longer
    /// than this many seconds. Default 300.
    pub websocket_idle_timeout_secs: Option<u64>,
    /// Absolute lifetime cap on a forwarded WebSocket. Default 3600 (1h).
    pub websocket_max_lifetime_secs: Option<u64>,
    /// Per-direction byte cap; closes the connection once exceeded.
    /// Default 1_073_741_824 (1 GiB).
    pub websocket_max_bytes_per_direction: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct HealthConfig {
    pub enabled: Option<bool>,
    pub liveness_path: Option<String>,
    pub readiness_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct MetricsConfig {
    pub enabled: Option<bool>,
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct LoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub include_request_body: Option<bool>,
    pub include_response_body: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct RateLimitingConfig {
    pub enabled: Option<bool>,
    pub strategy: Option<String>,
    pub requests_per_second: Option<u64>,
    pub burst_size: Option<u64>,
    pub redis_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub enum LoadBalancingStrategy {
    #[default]
    #[serde(rename = "round-robin")]
    RoundRobin,
    #[serde(rename = "weighted")]
    Weighted,
    #[serde(rename = "failover")]
    Failover,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyRule {
    pub matcher: RuleMatcher,
    pub targets: Vec<Target>,
    pub headers: Vec<HeaderRule>,
    pub scripts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<BasicAuth>,
    #[serde(default)]
    pub load_balancing: LoadBalancingStrategy,
}

#[derive(Clone, Debug)]
pub enum RuleMatcher {
    Default,
    Prefix(String),
    Regex(RegexMatcher),
    Exact(String),
    Domain(String),
    DomainPath(String, String),
}

/// Wrapper around Regex that stores the original pattern for serialization
#[derive(Clone, Debug)]
pub struct RegexMatcher {
    pub pattern: String,
    pub regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: &str) -> Result<Self> {
        Ok(Self {
            pattern: pattern.to_string(),
            regex: Regex::new(pattern)?,
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl Serialize for RuleMatcher {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            RuleMatcher::Default => {
                map.serialize_entry("type", "default")?;
            }
            RuleMatcher::Prefix(v) => {
                map.serialize_entry("type", "prefix")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::Regex(rm) => {
                map.serialize_entry("type", "regex")?;
                map.serialize_entry("value", &rm.pattern)?;
            }
            RuleMatcher::Exact(v) => {
                map.serialize_entry("type", "exact")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::Domain(v) => {
                map.serialize_entry("type", "domain")?;
                map.serialize_entry("value", v)?;
            }
            RuleMatcher::DomainPath(d, p) => {
                map.serialize_entry("type", "domain_path")?;
                map.serialize_entry("domain", d)?;
                map.serialize_entry("path", p)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for RuleMatcher {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| D::Error::custom("expected object"))?;
        let matcher_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| D::Error::custom("missing 'type' field"))?;

        match matcher_type {
            "default" => Ok(RuleMatcher::Default),
            "exact" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Exact(v.to_string()))
            }
            "prefix" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Prefix(v.to_string()))
            }
            "regex" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                let rm = RegexMatcher::new(v)
                    .map_err(|e| D::Error::custom(format!("invalid regex: {}", e)))?;
                Ok(RuleMatcher::Regex(rm))
            }
            "domain" => {
                let v = obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'value'"))?;
                Ok(RuleMatcher::Domain(v.to_string()))
            }
            "domain_path" => {
                let d = obj
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'domain'"))?;
                let p = obj
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| D::Error::custom("missing 'path'"))?;
                Ok(RuleMatcher::DomainPath(d.to_string(), p.to_string()))
            }
            other => Err(D::Error::custom(format!("unknown matcher type: {}", other))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub url: Url,
    pub weight: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

impl Config {
    /// Extract unique domain names from Domain and DomainPath rules,
    /// filtering out IPs and "localhost".
    pub fn acme_domains(&self) -> Vec<String> {
        let mut domains = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for rule in &self.rules {
            let domain = match &rule.matcher {
                RuleMatcher::Domain(d) => Some(d.as_str()),
                RuleMatcher::DomainPath(d, _) => Some(d.as_str()),
                _ => None,
            };

            if let Some(d) = domain {
                if d == "localhost" || d.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                if seen.insert(d.to_string()) {
                    domains.push(d.to_string());
                }
            }
        }

        domains
    }
}

pub struct ConfigManager {
    config: Arc<ArcSwap<Config>>,
    config_path: PathBuf,
    _watcher: Option<RecommendedWatcher>,
    suppress_watch: Arc<AtomicBool>,
    app_acme_domains: Arc<RwLock<Vec<String>>>,
}

impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            config_path: self.config_path.clone(),
            _watcher: None,
            suppress_watch: self.suppress_watch.clone(),
            app_acme_domains: self.app_acme_domains.clone(),
        }
    }
}

impl ConfigManager {
    pub fn new(config_path: &str) -> Result<Self> {
        let path = PathBuf::from(config_path);
        let config = Self::load_config(&path, &path)?;
        Ok(Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            config_path: path,
            _watcher: None,
            suppress_watch: Arc::new(AtomicBool::new(false)),
            app_acme_domains: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn suppress_watch(&self) -> &Arc<AtomicBool> {
        &self.suppress_watch
    }

    fn load_config(proxy_conf_path: &Path, config_path: &Path) -> Result<Config> {
        let content = std::fs::read_to_string(proxy_conf_path).unwrap_or_default();
        let (rules, global_scripts) = parse_proxy_config(&content)?;
        let config_dir = config_path.parent().unwrap_or(Path::new("."));
        let config_toml_path = config_dir.join("config.toml");
        let toml_content = if config_toml_path.exists() {
            std::fs::read_to_string(&config_toml_path).ok()
        } else {
            let default_config = r#"# Soli Proxy Configuration
# Server settings
[server]
bind = "0.0.0.0:80"
https_port = 443
worker_threads = 1  # dev default; set to "auto" or omit for one worker per CPU (production)

# TLS Configuration
[tls]
mode = "auto"
cache_dir = "./certs"

# Logging Configuration
[logging]
level = "info"
format = "json"
output = "stdout"
include_request_body = true
include_response_body = true

# Metrics Configuration
[metrics]
enabled = true
endpoint = "/metrics"

# Health Check Configuration
[health]
enabled = true
liveness_path = "/health/live"
readiness_path = "/health/ready"

# Limits Configuration
[limits]
max_connections = 10000
max_request_size = "10MB"
keep_alive_timeout = 30
request_timeout = 60

# Rate Limiting Configuration
[rate_limiting]
enabled = true
strategy = "token_bucket"
requests_per_second = 1000
burst_size = 2000
redis_url = "redis://localhost:6379"

# Apps Configuration (defaults for deployed apps)
# [apps]
# default_user = "rocky"
# default_group = "rocky"

# Circuit Breaker Configuration
[circuit_breaker]
failure_threshold = 5
recovery_timeout_secs = 30
success_threshold = 2
failure_status_codes = [502, 503, 504]

# Admin REST API Configuration
# Default binds to loopback only. Exposing on a non-loopback address
# requires api_key or username+password_hash — the proxy refuses to
# start the admin API otherwise.
[admin]
enabled = true
bind = "127.0.0.1:9090"

# Lua Scripting Configuration
[scripting]
enabled = false
scripts_dir = "./scripts/lua"
hook_timeout_ms = 10

# Authentication Configuration
[auth]
enabled = false
auth_type = "basic"
realm = "Restricted"
"#;
            std::fs::write(&config_toml_path, default_config).ok();
            Some(default_config.to_string())
        };
        let toml_config: TomlConfig =
            match toml_content.as_ref().and_then(|c| toml::from_str(c).ok()) {
                Some(cfg) => cfg,
                None => {
                    if config_toml_path.exists() {
                        tracing::error!(
                            "Failed to parse config.toml at {} — check for TOML syntax errors. \
                        Starting with defaults; your edits are being ignored.",
                            config_toml_path.display()
                        );
                    }
                    TomlConfig::default()
                }
            };

        Ok(Config {
            server: toml_config.server,
            tls: toml_config.tls,
            letsencrypt: toml_config.letsencrypt,
            scripting: toml_config.scripting.unwrap_or_default(),
            admin: {
                let mut admin = toml_config.admin.unwrap_or_default();
                if admin.username.is_none() {
                    admin.username = std::env::var("ADMIN_USER").ok();
                }
                if admin.password_hash.is_none() {
                    admin.password_hash = std::env::var("ADMIN_PASSWORD").ok();
                }
                admin
            },
            circuit_breaker: toml_config.circuit_breaker,
            apps: toml_config.apps.unwrap_or_default(),
            rules,
            global_scripts,
            limits: LimitsConfig {
                max_connections: toml_config.limits.as_ref().and_then(|l| l.max_connections),
                max_request_size: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.max_request_size.as_ref())
                    .and_then(|s| parse_size(s)),
                keep_alive_timeout: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.keep_alive_timeout),
                request_timeout: toml_config.limits.as_ref().and_then(|l| l.request_timeout),
                websocket_idle_timeout_secs: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.websocket_idle_timeout_secs),
                websocket_max_lifetime_secs: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.websocket_max_lifetime_secs),
                websocket_max_bytes_per_direction: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.websocket_max_bytes_per_direction),
            },
            health: toml_config.health.unwrap_or_default(),
            metrics: toml_config.metrics.unwrap_or_default(),
            logging: toml_config.logging.unwrap_or_default(),
            rate_limiting: toml_config.rate_limiting.unwrap_or_default(),
        })
    }

    pub fn get_config(&self) -> Arc<Config> {
        self.config.load().clone()
    }

    pub fn start_watcher(&mut self) -> Result<()> {
        // Ensure the file exists so the watcher has something to watch
        if !self.config_path.exists() {
            if let Some(parent) = self.config_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&self.config_path, "")?;
        }

        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();
        let suppress = self.suppress_watch.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        tracing::info!("Watching config file: {}", config_path.display());

        let reload_path = self.config_path.clone();
        let config_store = self.config.clone();

        std::thread::spawn(move || {
            while let Some(res) = rx.blocking_recv() {
                match res {
                    Ok(event) => {
                        if event.kind.is_modify() {
                            if suppress.swap(false, Ordering::SeqCst) {
                                tracing::debug!(
                                    "Suppressing file watcher reload (admin API write)"
                                );
                                continue;
                            }
                            tracing::info!("Config file changed, reloading...");
                            match Self::load_config(&reload_path, &reload_path) {
                                Ok(new_config) => {
                                    config_store.store(Arc::new(new_config));
                                    tracing::info!("Configuration reloaded successfully");
                                }
                                Err(e) => {
                                    tracing::error!("Failed to reload config: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => tracing::error!("Watch error: {}", e),
                }
            }
        });

        // Store the watcher to keep it alive
        self._watcher = Some(watcher);

        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        let new_config = Self::load_config(&self.config_path, &self.config_path)?;
        self.config.store(Arc::new(new_config));
        tracing::info!("Configuration reloaded successfully");
        Ok(())
    }

    pub fn register_app_acme_domains(&self, domains: Vec<String>) {
        let mut registered = self.app_acme_domains.write().unwrap();
        for domain in domains {
            if !registered.contains(&domain) {
                registered.push(domain);
            }
        }
    }

    pub fn unregister_app_acme_domain(&self, domain: &str) {
        let mut registered = self.app_acme_domains.write().unwrap();
        registered.retain(|d| d != domain);
    }

    pub fn get_all_acme_domains(&self) -> Vec<String> {
        let mut domains = self.config.load().acme_domains();
        let app_domains = self.app_acme_domains.read().unwrap();
        for domain in app_domains.iter() {
            if !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }
        domains
    }

    /// Persist current rules to proxy.conf and swap in-memory config
    fn persist_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        let content = serializer::serialize_proxy_conf(&rules, &global_scripts);
        self.suppress_watch.store(true, Ordering::SeqCst);
        std::fs::write(&self.config_path, &content)?;
        let mut config = (*self.config.load().as_ref()).clone();
        config.rules = rules;
        config.global_scripts = global_scripts;
        self.config.store(Arc::new(config));
        tracing::info!("Configuration persisted to {}", self.config_path.display());
        Ok(())
    }

    pub fn add_route(&self, rule: ProxyRule) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        rules.push(rule);
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn update_route(&self, index: usize, rule: ProxyRule) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        if index >= rules.len() {
            anyhow::bail!(
                "Route index {} out of range (have {} routes)",
                index,
                rules.len()
            );
        }
        rules[index] = rule;
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn remove_route(&self, index: usize) -> Result<()> {
        let cfg = self.get_config();
        let mut rules = cfg.rules.clone();
        if index >= rules.len() {
            anyhow::bail!(
                "Route index {} out of range (have {} routes)",
                index,
                rules.len()
            );
        }
        rules.remove(index);
        self.persist_rules(rules, cfg.global_scripts.clone())
    }

    pub fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        self.persist_rules(rules, global_scripts)
    }
}

#[async_trait::async_trait]
impl ConfigManagerTrait for ConfigManager {
    async fn reload(&self) -> Result<()> {
        self.reload().await
    }

    fn get_config(&self) -> Arc<Config> {
        self.get_config()
    }

    fn update_rules(&self, rules: Vec<ProxyRule>, global_scripts: Vec<String>) -> Result<()> {
        self.update_rules(rules, global_scripts)
    }

    fn add_route(&self, rule: ProxyRule) -> Result<()> {
        self.add_route(rule)
    }

    fn remove_route(&self, index: usize) -> Result<()> {
        self.remove_route(index)
    }

    fn register_app_acme_domains(&self, domains: Vec<String>) {
        self.register_app_acme_domains(domains)
    }

    fn unregister_app_acme_domain(&self, domain: &str) {
        self.unregister_app_acme_domain(domain)
    }

    fn get_all_acme_domains(&self) -> Vec<String> {
        self.get_all_acme_domains()
    }
}

/// Validate a script name: must end in .lua, no path traversal chars, no null bytes.
fn validate_script_name(name: &str) -> Option<String> {
    if name.contains('\0') {
        return None;
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    if !name.ends_with(".lua") {
        return None;
    }
    Some(name.to_string())
}

/// Extract `@script:a.lua,b.lua` from a string, returning (remaining_str, scripts_vec).
fn extract_scripts(s: &str) -> (&str, Vec<String>) {
    if let Some(idx) = s.find("@script:") {
        let before = s[..idx].trim();
        let after = &s[idx + "@script:".len()..];
        let script_part = after.split_whitespace().next().unwrap_or(after);
        let scripts: Vec<String> = script_part
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(validate_script_name)
            .collect();
        (before, scripts)
    } else {
        (s, Vec::new())
    }
}

/// Extract `@auth:user:hash` entries from a string, returning (remaining_str, auth_vec).
/// Multiple @auth entries can appear: `@auth:user1:hash1 @auth:user2:hash2`
/// Hash is everything after the second colon (bcrypt hashes start with $2a$, $2b$, $2y$)
fn extract_auth(s: &str) -> (String, Vec<BasicAuth>) {
    let mut auth_entries = Vec::new();
    let mut remaining = s.to_string();

    while let Some(idx) = remaining.find("@auth:") {
        // Keep the part BEFORE @auth:
        let before = &remaining[..idx];
        let after = &remaining[idx + "@auth:".len()..];

        // Find the end of this auth entry (whitespace or end of string)
        let end_idx = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());

        let auth_part = &after[..end_idx];

        // Parse username:hash - hash is everything after the first colon
        if let Some((username, hash)) = auth_part.split_once(':') {
            if !username.is_empty() && !hash.is_empty() {
                auth_entries.push(BasicAuth {
                    username: username.to_string(),
                    hash: hash.to_string(),
                });
            }
        }

        // Continue with the part BEFORE this @auth, plus any remaining after it
        let rest = &after[end_idx..];
        remaining = if rest.is_empty() {
            before.to_string()
        } else {
            format!("{}{}", before, rest)
        };
    }

    (remaining.trim().to_string(), auth_entries)
}

/// Extract `@lb:strategy` from a string, returning (remaining_str, strategy).
/// Example: `@lb:round-robin` or `@lb:weighted` or `@lb:failover`
fn extract_load_balancing(s: &str) -> (String, LoadBalancingStrategy) {
    if let Some(idx) = s.find("@lb:") {
        let before = &s[..idx];
        let after = &s[idx + "@lb:".len()..];

        let end_idx = after
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after.len());

        let strategy_str = &after[..end_idx];
        let strategy = match strategy_str {
            "round-robin" => LoadBalancingStrategy::RoundRobin,
            "weighted" => LoadBalancingStrategy::Weighted,
            "failover" => LoadBalancingStrategy::Failover,
            _ => LoadBalancingStrategy::default(),
        };

        let rest = &after[end_idx..];
        let remaining = if rest.is_empty() {
            before.to_string()
        } else {
            format!("{}{}", before, rest)
        };

        (remaining.trim().to_string(), strategy)
    } else {
        (s.to_string(), LoadBalancingStrategy::default())
    }
}

fn parse_proxy_config(content: &str) -> Result<(Vec<ProxyRule>, Vec<String>)> {
    let mut rules = Vec::new();
    let mut global_scripts = Vec::new();

    // Join continuation lines (backslash at end of line)
    let mut joined_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        if let Some(current) = joined_lines.last_mut() {
            if current.ends_with('\\') {
                current.pop(); // remove the backslash
                current.push_str(line.trim());
                continue;
            }
        }
        joined_lines.push(line.to_string());
    }

    for line in &joined_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handle [global] @script:cors.lua,logging.lua
        if trimmed.starts_with("[global]") {
            let rest = trimmed.strip_prefix("[global]").unwrap().trim();
            let (_, scripts) = extract_scripts(rest);
            global_scripts.extend(scripts);
            continue;
        }

        if let Some((source, target_str)) = trimmed.split_once("->") {
            let source = source.trim();
            // Extract @script: from the target side
            let (target_str, route_scripts) = extract_scripts(target_str.trim());
            // Extract @auth: entries from the target side
            let (target_str, auth_entries) = extract_auth(target_str);
            // Extract @lb: load balancing strategy
            let (target_str, load_balancing) = extract_load_balancing(&target_str);

            let matcher = if source == "default" || source == "*" {
                RuleMatcher::Default
            } else if let Some(pattern) = source.strip_prefix("~") {
                RuleMatcher::Regex(RegexMatcher::new(pattern)?)
            } else if !source.starts_with('/')
                && (source.contains('.') || source.parse::<std::net::IpAddr>().is_ok())
            {
                if let Some((domain, path)) = source.split_once('/') {
                    if path.is_empty() || path == "*" {
                        RuleMatcher::Domain(domain.to_string())
                    } else if path.ends_with("/*") {
                        let path_prefix = path.trim_end_matches('*').to_string();
                        let path_prefix = if path_prefix.starts_with('/') {
                            path_prefix
                        } else {
                            format!("/{}", path_prefix)
                        };
                        RuleMatcher::DomainPath(domain.to_string(), path_prefix)
                    } else {
                        RuleMatcher::DomainPath(domain.to_string(), path.to_string())
                    }
                } else {
                    RuleMatcher::Domain(source.to_string())
                }
            } else if source.ends_with("/*") {
                RuleMatcher::Prefix(source.trim_end_matches('*').to_string())
            } else {
                RuleMatcher::Exact(source.to_string())
            };

            let targets: Vec<Target> = target_str
                .split(',')
                .map(|t| {
                    Ok(Target {
                        url: Url::parse(t.trim())?,
                        weight: 100,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            rules.push(ProxyRule {
                matcher,
                targets,
                headers: vec![],
                scripts: route_scripts,
                auth: auth_entries,
                load_balancing,
            });
        }
    }

    Ok((rules, global_scripts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripting_config_parses_without_exposed_env_field() {
        // Regression: when ScriptingTomlConfig.exposed_env had no #[serde(default)],
        // any pre-existing config.toml omitting the field caused the entire
        // TomlConfig deserialize to fail. The error was swallowed at the
        // load_config call site and the proxy fell back to ServerConfig::default()
        // (bind = 0.0.0.0:8080), silently un-binding port 80.
        let toml_src = r#"
[server]
bind = "0.0.0.0:80"
https_port = 443

[tls]
mode = "auto"
cache_dir = "./certs"

[scripting]
enabled = false
scripts_dir = "./scripts/lua"
hook_timeout_ms = 10
"#;
        let cfg: TomlConfig = toml::from_str(toml_src)
            .expect("config without exposed_env must parse to keep operator's bind");
        assert_eq!(cfg.server.bind, "0.0.0.0:80");
        assert_eq!(cfg.server.https_port, 443);
        let scripting = cfg.scripting.expect("scripting section present");
        assert!(!scripting.enabled);
        assert!(scripting.exposed_env.is_empty());
    }

    #[test]
    fn test_backslash_continuation_joins_lines() {
        let config = "/api/* -> http://backend1:8080, \\\n          http://backend2:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 2);
        assert_eq!(rules[0].targets[0].url.as_str(), "http://backend1:8080/");
        assert_eq!(rules[0].targets[1].url.as_str(), "http://backend2:8080/");
    }

    #[test]
    fn test_multiple_continuation_lines() {
        let config = "/api/* -> http://backend1:8080, \\\n\
                       http://backend2:8080, \\\n\
                       http://backend3:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 3);
        assert_eq!(rules[0].targets[2].url.as_str(), "http://backend3:8080/");
    }

    #[test]
    fn test_backslash_mid_line_not_continuation() {
        let config = "/path -> http://localhost:8080\n\
                       ~^/foo\\dbar$ -> http://localhost:9090\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_continuation_trims_whitespace() {
        let config = "/api/* -> http://a:8080,   \\\n   http://b:8080,  \\\n   http://c:8080\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 3);
    }

    #[test]
    fn test_continuation_with_scripts() {
        let config = "/api/* -> http://a:8080, \\\n\
                       http://b:8080 @script:auth.lua\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].targets.len(), 2);
        assert_eq!(rules[0].scripts, vec!["auth.lua"]);
    }

    #[test]
    fn test_no_continuation_normal_config() {
        let config = "/api/* -> http://backend:8080\ndefault -> http://localhost:3000\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_auth_parsing() {
        let config = r#"
/db/* -> http://localhost:8080/ @auth:demo:$2b$12$YFlnIiACnSaAcxDWQlYjeedxq/3GvhvoGhRTYHMqLifJrETSqOZQa
"#;
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].auth.len(), 1);
        assert_eq!(rules[0].auth[0].username, "demo");
        assert!(rules[0].auth[0].hash.starts_with("$2b$"));
        assert_eq!(rules[0].targets.len(), 1);
        assert_eq!(rules[0].targets[0].url.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn test_multiple_auth_users() {
        let config = r#"
secure.example.com -> http://localhost:9000/ @auth:admin:$2b$12$hash1 @auth:user:$2b$12$hash2
"#;
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].auth.len(), 2);
        assert_eq!(rules[0].auth[0].username, "admin");
        assert_eq!(rules[0].auth[1].username, "user");
    }

    #[test]
    fn test_load_balancing_round_robin() {
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:round-robin";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::RoundRobin);
        assert_eq!(rules[0].targets.len(), 2);
    }

    #[test]
    fn test_load_balancing_weighted() {
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:weighted";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Weighted);
    }

    #[test]
    fn test_load_balancing_failover() {
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:failover";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Failover);
    }

    #[test]
    fn test_load_balancing_default_is_round_robin() {
        let config = "/api/* -> http://b1:8080, http://b2:8080";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::RoundRobin);
    }

    #[test]
    fn test_load_balancing_with_scripts() {
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:failover @script:auth.lua";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Failover);
        assert_eq!(rules[0].scripts, vec!["auth.lua"]);
    }

    #[test]
    fn test_load_balancing_unknown_strategy_defaults_to_round_robin() {
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:unknown";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::RoundRobin);
    }

    #[test]
    fn test_resolve_worker_threads_dev_no_config() {
        assert_eq!(resolve_worker_threads(true, None), Some(1));
    }

    #[test]
    fn test_resolve_worker_threads_dev_explicit_count_overrides() {
        assert_eq!(
            resolve_worker_threads(true, Some(&WorkerThreads::Count(4))),
            Some(4)
        );
    }

    #[test]
    fn test_resolve_worker_threads_dev_explicit_auto() {
        assert_eq!(
            resolve_worker_threads(true, Some(&WorkerThreads::Auto)),
            None
        );
    }

    #[test]
    fn test_resolve_worker_threads_prod_no_config() {
        assert_eq!(resolve_worker_threads(false, None), None);
    }

    #[test]
    fn test_resolve_worker_threads_prod_explicit_count() {
        assert_eq!(
            resolve_worker_threads(false, Some(&WorkerThreads::Count(8))),
            Some(8)
        );
    }

    #[test]
    fn test_worker_threads_deserialize_auto_string() {
        let toml = r#"
[server]
bind = "0.0.0.0:80"
https_port = 443
worker_threads = "auto"
"#;
        let cfg: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.worker_threads, Some(WorkerThreads::Auto));
    }

    #[test]
    fn test_worker_threads_deserialize_integer() {
        let toml = r#"
[server]
bind = "0.0.0.0:80"
https_port = 443
worker_threads = 4
"#;
        let cfg: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.worker_threads, Some(WorkerThreads::Count(4)));
    }

    #[test]
    fn test_worker_threads_deserialize_missing_is_none() {
        let toml = r#"
[server]
bind = "0.0.0.0:80"
https_port = 443
"#;
        let cfg: TomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server.worker_threads, None);
    }

    #[test]
    fn test_read_worker_threads_from_config_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("config.toml");
        std::fs::write(
            &toml_path,
            r#"
[server]
bind = "0.0.0.0:80"
https_port = 443
worker_threads = 2
"#,
        )
        .unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "").unwrap();

        let got = read_worker_threads(proxy_conf.to_str().unwrap());
        assert_eq!(got, Some(WorkerThreads::Count(2)));
    }

    #[test]
    fn test_read_worker_threads_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "").unwrap();
        // No config.toml in dir.
        assert_eq!(read_worker_threads(proxy_conf.to_str().unwrap()), None);
    }
}
