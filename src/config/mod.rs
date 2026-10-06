pub mod serializer;

use crate::auth::BasicAuth;
use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    #[serde(default)]
    pub forward_auth: Option<crate::forward_auth::ForwardAuthSettings>,
    #[serde(default)]
    pub compression: Option<crate::response::compress::CompressionConfig>,
    #[serde(default)]
    pub error_pages: Option<crate::response::error_pages::ErrorPagesConfig>,
    #[serde(default)]
    pub maintenance: Option<crate::response::maintenance::MaintenanceConfig>,
    #[serde(default)]
    pub upstream: Option<crate::upstream::UpstreamTomlConfig>,
    #[serde(default)]
    pub health_checks: Option<crate::upstream::HealthChecksTomlConfig>,
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
    /// Name of the per-site file whose mtime triggers a blue/green deploy when
    /// touched. Looked up at the site root, e.g. `sites/<domain>/restart.txt`.
    pub restart_trigger_file: Option<String>,
    /// How often to stat the trigger file, in seconds. `0` disables the
    /// mechanism entirely.
    pub restart_trigger_poll_secs: Option<u64>,
    /// Treat every app as untrusted code (`[apps] multi_tenant = true`).
    ///
    /// The native spawn path is not a sandbox: it clears the environment and
    /// sets `PR_SET_NO_NEW_PRIVS`, but the process still reads the host
    /// filesystem — other tenants' site directories, `certs/`, and the proxy's
    /// own `config.toml` with its admin credentials — and can dial the database
    /// and cache on localhost. That is fine when you wrote every app and fatal
    /// when you did not.
    ///
    /// With this set, apps must declare a `docker_image` and are started with
    /// the hardening in `mandatory_docker_args`, which tenant config cannot
    /// weaken.
    pub multi_tenant: Option<bool>,
    /// Memory ceiling applied to every container, e.g. `"512m"`.
    pub tenant_memory: Option<String>,
    /// CPU ceiling applied to every container, e.g. `"1.0"`.
    pub tenant_cpus: Option<String>,
    /// Uid:gid containers run as. Never root, never the proxy's own uid.
    pub tenant_user: Option<String>,
    /// Scale to zero: seconds without a request before an app is stopped and
    /// restarted on demand. The default for apps whose `app.infos` does not
    /// set `idle_timeout`: [`DEFAULT_IDLE_TIMEOUT_SECS`] (15 minutes), or `0`
    /// — never — under `--dev`. `0` here leaves every app running.
    pub idle_timeout: Option<u64>,
    /// Platform-owned port range for app slots (default 20000-30000). In
    /// multi_tenant mode it is the only range used; otherwise it backs an app
    /// whose own `port_range_*` is unusable. Accessor: `app_port_range`.
    pub port_range_start: Option<u16>,
    pub port_range_end: Option<u16>,
    /// Consecutive failed health checks before failover (default 3).
    pub health_failure_threshold: Option<u32>,
    /// Forward `HTTP_PROXY` & co. into tenant containers (default false), and
    /// separately allow values carrying `user:password@` (default false).
    pub tenant_proxy_env: Option<bool>,
    pub tenant_proxy_env_credentials: Option<bool>,
    /// Whether stopping the proxy also stops every app it manages. Default
    /// `false` (apps keep running and the next proxy adopts them), except in
    /// `--dev` where it defaults to `true`. Accessor: `stop_on_shutdown`.
    pub stop_on_shutdown: Option<bool>,
}

/// Default name of the per-site deploy trigger file.
pub const DEFAULT_RESTART_TRIGGER_FILE: &str = "restart.txt";
/// Default polling interval for the deploy trigger file, in seconds.
pub const DEFAULT_RESTART_TRIGGER_POLL_SECS: u64 = 2;
/// `[apps] idle_timeout` when unset: an app sleeps after 15 minutes without a
/// request (or an open one: a streaming response, a WebSocket).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

impl AppsTomlConfig {
    pub fn restart_trigger_file(&self) -> String {
        self.restart_trigger_file
            .clone()
            .unwrap_or_else(|| DEFAULT_RESTART_TRIGGER_FILE.to_string())
    }

    pub fn restart_trigger_poll_secs(&self) -> u64 {
        self.restart_trigger_poll_secs
            .unwrap_or(DEFAULT_RESTART_TRIGGER_POLL_SECS)
    }

    /// Fleet-wide idle threshold, in seconds. `0` means apps never sleep.
    ///
    /// Unset, apps sleep after 15 minutes without a request — except under
    /// `--dev`, where a laptop's apps are the developer's own and a second's
    /// wait after every coffee break helps nobody.
    pub fn idle_timeout(&self, dev_mode: bool) -> u64 {
        self.idle_timeout.unwrap_or(if dev_mode {
            0
        } else {
            DEFAULT_IDLE_TIMEOUT_SECS
        })
    }

    /// Whether a proxy that is stopping takes its apps down with it.
    ///
    /// Off by default: a proxy restart (an upgrade, a crash, `systemctl
    /// restart`) used to stop every app and cold-start it again, a fleet-wide
    /// outage for a change that concerned none of them. Apps now outlive the
    /// proxy and the next one adopts them. `--dev` keeps the old behaviour
    /// unless this is set, so Ctrl-C in a terminal still cleans up after
    /// itself.
    pub fn stop_on_shutdown(&self, dev_mode: bool) -> bool {
        self.stop_on_shutdown.unwrap_or(dev_mode)
    }

    /// Whether apps are untrusted. Defaults to `false` so existing
    /// single-tenant deployments are unchanged.
    pub fn multi_tenant(&self) -> bool {
        self.multi_tenant.unwrap_or(false)
    }

    /// Container flags the platform imposes on every tenant app.
    ///
    /// Returned *after* the app's own `docker_options`, so `docker run` takes
    /// these as the effective values — the tenant cannot opt out of its own
    /// resource limits or re-acquire capabilities. It is a mandatory floor, not
    /// a default.
    ///
    /// Docker alone has a long history of container escapes; this raises the
    /// cost of one but is not a substitute for a VM boundary. Treat it as the
    /// first step toward gVisor or Firecracker, not the finish line.
    pub fn mandatory_docker_args(&self) -> Vec<String> {
        let mut args: Vec<String> = vec![
            // No writes to the image; anything the app needs to write goes to
            // the tmpfs below, which cannot hold executables.
            "--read-only".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,noexec,nosuid,size=64m".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            // A fork bomb in one tenant must not take the host down with it.
            "--pids-limit".to_string(),
            "256".to_string(),
        ];

        args.push("--memory".to_string());
        args.push(
            self.tenant_memory
                .clone()
                .unwrap_or_else(|| "512m".to_string()),
        );
        args.push("--cpus".to_string());
        args.push(
            self.tenant_cpus
                .clone()
                .unwrap_or_else(|| "1.0".to_string()),
        );
        args.push("--user".to_string());
        args.push(
            self.tenant_user
                .clone()
                .unwrap_or_else(|| "10000:10000".to_string()),
        );
        args
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct LimitsTomlConfig {
    pub max_connections: Option<u64>,
    pub max_connections_per_ip: Option<u64>,
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

impl AdminConfig {
    /// Treat an empty credential as unset, everywhere at once.
    ///
    /// A templated `config.toml` with an unresolved variable yields
    /// `api_key = ""`, and `ADMIN_USER=""` is easy to export by accident.
    /// Left as `Some("")`, the server's "is any auth configured" check and its
    /// request-time check disagreed: the loopback guard logged "no
    /// authentication configured" while every request got a bare 401, and an
    /// empty user/password pair was bcrypt-hashed into a credential that
    /// `Authorization: Basic Og==` satisfied. Normalising here, before the
    /// plaintext-hashing step, keeps both checks looking at the same thing.
    fn drop_empty_credentials(&mut self) {
        let non_empty = |v: &mut Option<String>| {
            if v.as_deref().is_some_and(str::is_empty) {
                *v = None;
            }
        };
        non_empty(&mut self.api_key);
        non_empty(&mut self.username);
        non_empty(&mut self.password_hash);
    }
}

/// Pure defaults. Credentials from the environment (and from the `.env` file
/// next to the config) are layered on in `load_config`, which is the one place
/// that knows where the config lives.
impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: Some(true),
            bind: "127.0.0.1:9090".to_string(),
            api_key: None,
            username: None,
            password_hash: None,
        }
    }
}

/// The only variables a `.env` file may supply.
const DOTENV_KEYS: &[&str] = &["ADMIN_USER", "ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH"];

/// Admin credentials from `<config dir>/.env`, read without touching the
/// process environment.
///
/// This used to be `dotenv::dotenv()`, which has two problems. The crate is
/// unmaintained (RUSTSEC-2021-0141). And it searches the working directory
/// *and every parent* for a `.env`, then exports whatever it finds: a stray
/// file in `/srv` or `$HOME` could set `ADMIN_USER`/`ADMIN_PASSWORD` — the
/// admin API's credentials — or `HTTP_PROXY`, which the proxy passes on to
/// every app it spawns. Now exactly one file is read, the one beside
/// `config.toml`, only the three admin keys are taken from it, and nothing is
/// exported: real environment variables still win, and no other code (Lua's
/// `env`, app spawning) ever sees `.env` content.
///
/// A missing file is normal. A file that exists but does not parse is an
/// error, like a malformed `config.toml`: silently dropping it would drop the
/// credentials it was written to provide.
fn read_dotenv_credentials(config_dir: &Path) -> Result<std::collections::HashMap<String, String>> {
    let path = config_dir.join(".env");
    let iter = match dotenvy::from_path_iter(&path) {
        Ok(iter) => iter,
        Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Default::default())
        }
        Err(e) => anyhow::bail!("failed to read {}: {}", path.display(), e),
    };
    let mut found = std::collections::HashMap::new();
    for item in iter {
        let (key, value) =
            item.map_err(|e| anyhow::anyhow!("failed to parse {}: {}", path.display(), e))?;
        if DOTENV_KEYS.contains(&key.as_str()) {
            found.insert(key, value);
        } else {
            tracing::warn!(
                "{}: ignoring {} (only {} are read from this file)",
                path.display(),
                key,
                DOTENV_KEYS.join(", ")
            );
        }
    }
    if !found.is_empty() {
        tracing::debug!("Loaded admin credentials from {}", path.display());
    }
    Ok(found)
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
    /// Let request paths containing an encoded slash (`%2F`) through instead
    /// of answering 400. Default `false`: a backend that decodes `%2F` before
    /// routing would see `/admin%2Fusers` as `/admin/users`, a path the
    /// proxy's prefix rules and per-route auth never matched. Turn it on for
    /// backends whose API paths carry `%2F` as data (GitLab's
    /// `group%2Fproject`, S3-style object keys); dot segments spelled with
    /// `%2F` (`..%2F`) are still rejected.
    #[serde(default)]
    pub allow_encoded_slash: Option<bool>,
    /// Seconds a stopping proxy waits for in-flight requests to finish after
    /// it stops accepting (default 10, at most 3600). See
    /// [`ServerConfig::shutdown_grace_period`].
    #[serde(default)]
    pub shutdown_grace_period: Option<u64>,
    /// `trusted_proxies`, `real_ip_header`, `proxy_protocol` and
    /// `request_id_header`: who the client is and which request this is (see
    /// `crate::edge`). Hot-reloaded, read per connection and per request.
    #[serde(flatten)]
    pub edge: crate::edge::EdgeConfig,
}

/// Default for `[server] shutdown_grace_period`, in seconds.
pub const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 10;
/// Ceiling for `[server] shutdown_grace_period`: past it, a stop that never
/// finishes is indistinguishable from a hung one.
pub const MAX_SHUTDOWN_GRACE_SECS: u64 = 3600;

impl ServerConfig {
    /// How long SIGTERM/SIGINT waits for in-flight requests before the
    /// process exits: new connections are refused at once, idle ones are
    /// closed, and requests already running get up to this long to finish.
    pub fn shutdown_grace_period(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.shutdown_grace_period
                .unwrap_or(DEFAULT_SHUTDOWN_GRACE_SECS)
                .min(MAX_SHUTDOWN_GRACE_SECS),
        )
    }

    /// The HTTPS listener: `https_port` on the same address as `bind`.
    ///
    /// It used to be `0.0.0.0:<https_port>` whatever `bind` said, so a proxy
    /// bound to `127.0.0.1:80` (behind another balancer) or to one interface
    /// of a multi-homed host still served HTTPS on every IPv4 interface — and
    /// on none of the IPv6 ones. `bind = "[::]:80"` now gives a dual-stack
    /// listener on both ports (IPv4 clients arrive as `::ffff:a.b.c.d`).
    pub fn https_addr(&self) -> Result<std::net::SocketAddr> {
        let http: std::net::SocketAddr = self.bind.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid [server] bind {:?}: {} (expected IP:port, e.g. \"0.0.0.0:80\" or \"[::]:80\")",
                self.bind,
                e
            )
        })?;
        Ok(std::net::SocketAddr::new(http.ip(), self.https_port))
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_string(),
            https_port: 443,
            worker_threads: None,
            allow_encoded_slash: None,
            shutdown_grace_period: None,
            edge: Default::default(),
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

/// Read just `[server] shutdown_grace_period` from the `config.toml` next to
/// `config_path` — what `soli-proxy -d` waits for when it replaces a running
/// daemon. The default when the file is missing or does not parse.
pub fn read_shutdown_grace_period(config_path: &str) -> std::time::Duration {
    let path = PathBuf::from(config_path);
    let toml_path = path.parent().unwrap_or(Path::new(".")).join("config.toml");
    std::fs::read_to_string(&toml_path)
        .ok()
        .and_then(|content| toml::from_str::<TomlConfig>(&content).ok())
        .map(|cfg| cfg.server)
        .unwrap_or_default()
        .shutdown_grace_period()
}

/// The ports the proxy's listeners would take, from `[server] bind` and
/// `https_port` in the `config.toml` next to `config_path` (the defaults
/// when the file is missing or does not parse). Read before startup, to
/// tell whether another proxy already holds them.
pub fn read_listen_ports(config_path: &str) -> Vec<u16> {
    let path = PathBuf::from(config_path);
    let toml_path = path.parent().unwrap_or(Path::new(".")).join("config.toml");
    let server = std::fs::read_to_string(&toml_path)
        .ok()
        .and_then(|content| toml::from_str::<TomlConfig>(&content).ok())
        .map(|cfg| cfg.server)
        .unwrap_or_default();
    let mut ports = vec![server.https_port];
    if let Ok(http) = server.bind.parse::<std::net::SocketAddr>() {
        ports.insert(0, http.port());
    }
    ports
}

/// Read just `[logging]` from the `config.toml` next to `config_path`, before
/// the logger exists. Defaults when the file is missing; a file that does not
/// parse also yields defaults here, and `ConfigManager::new` then reports the
/// parse error through the logger this configured.
pub fn read_logging_config(config_path: &str) -> LoggingConfig {
    let path = PathBuf::from(config_path);
    let toml_path = path.parent().unwrap_or(Path::new(".")).join("config.toml");
    std::fs::read_to_string(&toml_path)
        .ok()
        .and_then(|content| toml::from_str::<TomlConfig>(&content).ok())
        .and_then(|cfg| cfg.logging)
        .unwrap_or_default()
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
    /// Lowest TLS version accepted: `"1.2"` (the default) or `"1.3"`.
    #[serde(default)]
    pub min_version: Option<String>,
}

impl TlsConfig {
    /// `min_version` as a protocol floor; anything but "1.2"/"1.3" is an error.
    pub fn min_version(&self) -> Result<crate::acme::TlsMinVersion> {
        match self.min_version.as_deref().map(str::trim) {
            None | Some("") | Some("1.2") => Ok(crate::acme::TlsMinVersion::Tls12),
            Some("1.3") => Ok(crate::acme::TlsMinVersion::Tls13),
            Some(other) => anyhow::bail!(
                "invalid [tls] min_version {:?} (expected \"1.2\" or \"1.3\")",
                other
            ),
        }
    }
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
    pub forward_auth: crate::forward_auth::ForwardAuthSettings,
    /// `[compression]`, validated (see `response::compress`).
    pub compression: crate::response::compress::CompressionConfig,
    /// `[error_pages]`, with its pages read at load time.
    pub error_pages: crate::response::error_pages::ErrorPagesConfig,
    /// `[maintenance]`: allowlists and defaults. The on/off state is not
    /// configuration; it lives in `ConfigManager::maintenance`.
    pub maintenance: crate::response::maintenance::MaintenanceConfig,
    /// `[upstream]`: retries.
    pub upstream: crate::upstream::UpstreamConfig,
    /// `[health_checks]`: active checks of static targets.
    pub health_checks: crate::upstream::HealthChecksConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct LimitsConfig {
    pub max_connections: Option<u64>,
    /// Simultaneous connections one client address may hold (an IPv6 client
    /// counts per /64). Unset = 256; 0 disables the cap. Read at startup.
    pub max_connections_per_ip: Option<u64>,
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
    /// `trace` … `error`, or a `tracing` filter directive. Default `info`
    /// (or `RUST_LOG` when this is unset). Read at startup only.
    pub level: Option<String>,
    /// `json` (default) or `text`. Read at startup only.
    pub format: Option<String>,
    /// `stdout` (default), `stderr` or `file:/path`. Read at startup only.
    pub output: Option<String>,
    /// File output: rotate past this size, e.g. `"100MB"` (the default);
    /// `"0"` never rotates.
    pub max_size: Option<String>,
    /// File output: rotated files kept besides the live one. Default 5.
    pub max_files: Option<u32>,
    pub include_request_body: Option<bool>,
    pub include_response_body: Option<bool>,
    /// When true, emit one structured log line per served request (method,
    /// path, host, status, latency). Honoured on hot reload. Default false.
    pub log_endpoints: Option<bool>,
    /// Access log: `off` (the default), `stdout`, `stderr` or a file path
    /// (rotated like `output`, by `max_size`/`max_files`). Read at startup.
    pub access_log: Option<String>,
    /// `json` (the default) or `combined` (Apache/nginx combined, with the
    /// proxy's fields appended as `key=value`). Read at startup.
    pub access_log_format: Option<String>,
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

// `deny_unknown_fields` on the rule and everything nested in it: a
// cross-site `text/plain` form post can only reach the admin API if its
// body still deserializes as a rule, and rejecting stray keys removes one
// more way to smuggle a valid payload past the browser's preflight rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRule {
    pub matcher: RuleMatcher,
    pub targets: Vec<Target>,
    pub headers: Vec<HeaderRule>,
    pub scripts: Vec<String>,
    #[serde(default)]
    pub auth: Vec<BasicAuth>,
    /// Request paths on this rule that are served without Basic Auth.
    ///
    /// Only meaningful when `auth` is non-empty: a whole-domain rule can be
    /// password-protected while a machine-to-machine endpoint on it (a Stripe
    /// webhook, a health check) stays reachable. Each entry is either an exact
    /// path (`/hooks/stripe`) or a prefix ending in `*` (`/hooks/*`).
    #[serde(default)]
    pub auth_exempt: Vec<String>,
    #[serde(default)]
    pub load_balancing: LoadBalancingStrategy,
    /// `@forward_auth:` (+ `@forward_auth_headers:`): an auth service asked
    /// before every request on this rule, after `@auth` when both are set.
    /// `@noauth` paths skip it too. See `crate::forward_auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<crate::forward_auth::ForwardAuth>,
    /// `@compress:on` / `@compress:off`: compress this route's responses, or
    /// never, whatever `[compression] enabled` says. `None` follows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<bool>,
    /// `@retries`, `@timeout`, `@h2`, `@tls_*`, `@health`, ... (see
    /// `crate::upstream`).
    #[serde(
        default,
        skip_serializing_if = "crate::upstream::UpstreamOptions::is_default"
    )]
    pub upstream: crate::upstream::UpstreamOptions,
}

impl ProxyRule {
    /// Resolve `hash: ""` auth entries against the rule this one replaces.
    ///
    /// The admin API never returns password hashes, so a client that edits a
    /// protected route submits its existing users with an empty hash meaning
    /// "keep". An empty hash for a username the old rule does not have is an
    /// error: writing it would produce `@auth:user:` on disk, which the parser
    /// discards, and the route would silently lose its protection.
    pub fn carry_forward_auth_hashes(&mut self, existing: Option<&ProxyRule>) -> Result<()> {
        for entry in &mut self.auth {
            if !entry.hash.is_empty() {
                continue;
            }
            let kept = existing.and_then(|old| {
                old.auth
                    .iter()
                    .find(|a| a.username == entry.username && !a.hash.is_empty())
            });
            match kept {
                Some(old) => entry.hash = old.hash.clone(),
                None => anyhow::bail!("auth entry for {} has no password hash", entry.username),
            }
        }
        Ok(())
    }

    /// True when `path` is one of this rule's Basic Auth carve-outs.
    pub fn is_auth_exempt(&self, path: &str) -> bool {
        path_is_auth_exempt(&self.auth_exempt, path)
    }

    /// Everything the `.conf` parser checks that a rule arriving as JSON
    /// through the admin API (which never goes through the parser) must also
    /// satisfy before it is written to disk.
    pub fn validate(&self) -> Result<()> {
        self.validate_auth_exempt()?;
        self.validate_conf_tokens()?;
        if let Some(forward_auth) = &self.forward_auth {
            forward_auth.validate()?;
        }
        for header in &self.headers {
            header.validate()?;
        }
        if let RuleMatcher::Regex(rm) = &self.matcher {
            for target in &self.targets {
                check_capture_refs(&target.url, &rm.regex)?;
            }
        }
        self.upstream.validate(&self.targets)?;
        Ok(())
    }

    /// Refuse a string the `proxy.conf` serializer would write verbatim but
    /// could not read back as the same token: whitespace splits a token, a
    /// newline starts a new line — a whole rule, injected — `->` moves the
    /// arrow, a trailing backslash continues the line onto the next rule.
    /// Run on rules from the admin API (through [`Self::validate`]) and by the
    /// parser. (Targets and forward-auth URLs are written from parsed `Url`s,
    /// header lines are checked by `HeaderRule::validate`, upstream
    /// directives by `UpstreamOptions::validate`.)
    pub fn validate_conf_tokens(&self) -> Result<()> {
        fn matcher(value: &str) -> Result<()> {
            check_conf_token("route matcher", value, &[])?;
            if value.contains("->") || value.starts_with('#') {
                anyhow::bail!("route matcher {:?} cannot be written to proxy.conf", value);
            }
            Ok(())
        }
        match &self.matcher {
            RuleMatcher::Default => {}
            RuleMatcher::Exact(v) | RuleMatcher::Prefix(v) | RuleMatcher::Domain(v) => matcher(v)?,
            RuleMatcher::DomainPath(domain, path) => {
                matcher(domain)?;
                matcher(path)?;
            }
            // A pattern may hold spaces (the matcher is everything before the
            // arrow), but no line break, no arrow and no edge whitespace.
            RuleMatcher::Regex(rm) => {
                let p = &rm.pattern;
                if p.chars().any(char::is_control) || p.contains("->") || p.trim() != p {
                    anyhow::bail!("regex {:?} cannot be written to proxy.conf", p);
                }
            }
        }
        for entry in &self.auth {
            check_conf_token("auth username", &entry.username, &[':'])?;
            check_conf_token("auth hash", &entry.hash, &[])?;
        }
        for pattern in &self.auth_exempt {
            check_conf_token("auth_exempt path", pattern, &[','])?;
        }
        for script in &self.scripts {
            if validate_script_name(script).is_none() {
                anyhow::bail!("invalid script name {:?}", script);
            }
            check_conf_token("script", script, &[','])?;
        }
        Ok(())
    }

    /// Reject `auth_exempt` patterns that cannot be matched literally.
    ///
    /// The `.conf` parser drops such entries with a warning, but a rule
    /// arriving as JSON through the admin API never goes through it — without
    /// this, `auth_exempt: ["/"]` or a `..` pattern would be written to disk
    /// and silently mean something different after the next reload.
    pub fn validate_auth_exempt(&self) -> Result<()> {
        for pattern in &self.auth_exempt {
            if validate_auth_exempt_path(pattern).is_none() {
                anyhow::bail!(
                    "invalid auth_exempt path {:?}: expected an absolute path such as \
                     /hooks/stripe or /hooks/*, with no '..' segment and no percent-encoding",
                    pattern
                );
            }
        }
        Ok(())
    }
}

/// True when `path` matches one of the `@noauth:` patterns.
///
/// Patterns are either an exact path (`/hooks/stripe`) or a prefix ending in
/// `*` (`/hooks/*`, which also matches the bare `/hooks`, mirroring how
/// `Prefix` route matchers behave).
///
/// This function decides whether to *skip* authentication, so it fails closed
/// on anything it cannot compare literally: a path carrying percent-encoding
/// or a `..` segment is never exempt, even if it textually matches. Otherwise
/// `/hooks/stripe/%2e%2e/admin` — which the backend may well resolve to
/// `/admin` — would walk out of the carve-out with the password check skipped.
pub fn path_is_auth_exempt(patterns: &[String], path: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    if path.contains('%') || path.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    patterns
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix) || path == prefix.trim_end_matches('/'),
            None => path == pattern,
        })
}

/// Validate one `@noauth:` pattern: absolute path, no null bytes, no `..`.
///
/// Returns `None` for anything else — a pattern that cannot be compared
/// literally must not silently widen into an auth bypass.
pub(crate) fn validate_auth_exempt_path(pattern: &str) -> Option<String> {
    if !pattern.starts_with('/') || pattern.contains('\0') {
        return None;
    }
    if pattern.contains('%') || pattern.split('/').any(|seg| seg == ".." || seg == ".") {
        return None;
    }
    Some(pattern.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Two regex matchers are the same rule when their patterns are.
impl PartialEq for RegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for RegexMatcher {}

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
#[serde(deny_unknown_fields)]
pub struct Target {
    pub url: Url,
    pub weight: u8,
}

/// One line of a rule's `headers { }` block in proxy.conf, applied to the
/// upstream request: `Name: value` sets the header (replacing any value the
/// client sent), `-Name` removes it. Values may use `$client_ip`, `$scheme` and
/// `$host`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRule {
    pub name: String,
    #[serde(default)]
    pub value: String,
    /// Remove the header instead of setting it (`-Name` in proxy.conf).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove: bool,
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

/// Replace `path` with `contents` atomically.
///
/// `fs::write` truncates and then writes: a crash, a full disk or a concurrent
/// reader in between sees an empty or half-written proxy.conf, aliases.json,
/// app_state.json or ports.lock — and the next start reads that as the truth.
/// This writes a temporary file in the same directory, fsyncs it, renames it
/// over the target (atomic on one filesystem) and fsyncs the directory, so a
/// reader sees the old file or the new one, never a mix. The target's
/// permissions carry over, and a symlinked target is replaced at the file it
/// points to rather than turned into a regular file.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let path = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let written: std::io::Result<()> = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        if let Ok(meta) = std::fs::metadata(&path) {
            file.set_permissions(meta.permissions())?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    // The rename is only durable once the directory entry is.
    if let Ok(dir) = std::fs::File::open(&dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Content fingerprint for `ConfigManager`'s own-write check. Never 0, which
/// means "nothing written yet".
fn content_hash(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish().max(1)
}

pub struct ConfigManager {
    config: Arc<ArcSwap<Config>>,
    config_path: PathBuf,
    _watcher: Option<RecommendedWatcher>,
    /// Hash of the proxy.conf content this process last wrote (0: none).
    /// The watcher skips an event whose file still hashes to it — the
    /// change is already in memory — and reloads on anything else.
    own_write_hash: Arc<AtomicU64>,
    app_acme_domains: Arc<RwLock<Vec<String>>>,
    /// Maintenance mode's on/off state: runtime state the admin API toggles,
    /// not configuration, so it survives reloads. Shared by every clone.
    pub maintenance: Arc<crate::response::maintenance::Maintenance>,
}

impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            config_path: self.config_path.clone(),
            _watcher: None,
            own_write_hash: self.own_write_hash.clone(),
            app_acme_domains: self.app_acme_domains.clone(),
            maintenance: self.maintenance.clone(),
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
            own_write_hash: Arc::new(AtomicU64::new(0)),
            app_acme_domains: Arc::new(RwLock::new(Vec::new())),
            maintenance: Arc::default(),
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    fn load_config(proxy_conf_path: &Path, config_path: &Path) -> Result<Config> {
        let content = std::fs::read_to_string(proxy_conf_path).unwrap_or_default();
        let (rules, global_scripts) = parse_proxy_config(&content)?;
        let config_dir = config_path.parent().unwrap_or(Path::new("."));
        let config_toml_path = config_dir.join("config.toml");
        let toml_content = if config_toml_path.exists() {
            std::fs::read_to_string(&config_toml_path).map_err(|e| {
                anyhow::anyhow!("failed to read {}: {}", config_toml_path.display(), e)
            })?
        } else {
            let default_config = r#"# Soli Proxy Configuration
# Server settings
[server]
bind = "0.0.0.0:80"
https_port = 443
worker_threads = 1  # dev default; set to "auto" or omit for one worker per CPU (production)
# shutdown_grace_period = 10  # seconds in-flight requests get on stop/restart
# Behind a CDN/balancer: whose X-Forwarded-For to believe (CIDRs or "cloudflare").
# trusted_proxies = []
# request_id_header = "X-Request-Id"   # "" = off

# TLS Configuration
[tls]
mode = "auto"
cache_dir = "./certs"

# Logging Configuration
[logging]
level = "info"
format = "json"
output = "stdout"
# Body logging flags are reserved; currently unused.
include_request_body = false
include_response_body = false
# access_log = "off"         # "stdout", "stderr" or a file path
# access_log_format = "json" # or "combined"

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
# max_connections_per_ip = 256   # per client address (IPv6: per /64); 0 = off
max_request_size = "10MB"
keep_alive_timeout = 30          # header read / idle connection timeout, seconds
request_timeout = 60

# Rate Limiting Configuration (in-process; redis_url is unused if present)
[rate_limiting]
enabled = true
strategy = "token_bucket"
requests_per_second = 1000
burst_size = 2000

# Apps Configuration (defaults for deployed apps)
# [apps]
# default_user = "rocky"
# default_group = "rocky"
# Touching sites/<domain>/restart.txt triggers a blue/green deploy of that app.
# Detected by polling (inotify cannot see through the symlinks in sites/).
# restart_trigger_file = "restart.txt"
# restart_trigger_poll_secs = 2   # 0 disables the trigger entirely
# idle_timeout = 900              # scale to zero: seconds idle before an app is
#                                 # stopped and restarted on demand (default 900,
#                                 # 0 under --dev; 0 = never); per-app
#                                 # `idle_timeout` in app.infos overrides this
# Untrusted apps: require a docker_image and impose container hardening the
# app cannot weaken (read-only rootfs, cap-drop ALL, no-new-privileges,
# pids/memory/cpu limits, non-root uid). Apps without an image fail to deploy
# rather than falling back to the unsandboxed native path. Default false.
# multi_tenant = true
# tenant_memory = "512m"
# tenant_cpus = "1.0"
# tenant_user = "10000:10000"
# Slot ports. With multi_tenant, the only range used (app.infos cannot pick).
# port_range_start = 20000
# port_range_end = 30000
# Tenant containers do not get the proxy's HTTP(S)_PROXY unless asked, nor
# one carrying user:password@ unless asked twice.
# tenant_proxy_env = false
# tenant_proxy_env_credentials = false
# Consecutive failed health checks (no answer, or 5xx) before failover.
# health_failure_threshold = 3
# Apps keep running when the proxy stops or restarts, and the next proxy
# adopts them. true = stop them with the proxy (the default under --dev).
# stop_on_shutdown = false

# Circuit Breaker Configuration
[circuit_breaker]
failure_threshold = 5
recovery_timeout_secs = 30
success_threshold = 2
failure_status_codes = [502, 503, 504]

# Upstream retries: a failed attempt goes to the rule's next target when that
# is safe (a connect failure; otherwise idempotent requests without a body).
# [upstream]
# retries = 1
# retry_on = ["connect", "error"]   # may add "502", "503", "504", "500"
# try_duration = "5s"

# Active health checks of proxy.conf targets (@health:/path per route).
# [health_checks]
# default_path = "/healthz"
# interval = "10s"
# timeout = "2s"
# unhealthy_threshold = 3
# healthy_threshold = 2

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

# Response compression (gzip/brotli/zstd). Off by default; see the README.
# [compression]
# enabled = true

# Custom HTML pages for the proxy's own errors: 502.html, 5xx.html, ...
# [error_pages]
# dir = "./errors"

# Maintenance mode allowlists (toggle with PUT /api/v1/maintenance).
# [maintenance]
# allow_ips = ["10.0.0.0/8"]
# allow_paths = ["/up"]

# Authentication: HTTP Basic per route (@auth:user:hash in proxy.conf), per app
# ([auth.users] in app.infos) and for the admin API (api_key above, or
# ADMIN_USER + ADMIN_PASSWORD_HASH). Hashes: `soli-proxy hash-password`.
# Forward authentication to an SSO service: @forward_auth:URL per route,
# [auth] forward per app; tuned below (see README "Forward authentication").
# [forward_auth]
# timeout_secs = 5
# allowed_urls = []   # multi_tenant: the auth services an app.infos may name
"#;
            std::fs::write(&config_toml_path, default_config).ok();
            default_config.to_string()
        };
        // A config.toml that exists but does not parse is an error, never a
        // default. Substituting `TomlConfig::default()` on a typo used to drop
        // `[admin].api_key` on the next reload while the listener stayed bound
        // to whatever address it started on — an unauthenticated admin API
        // that reported "reloaded successfully". Returning Err here makes a
        // corrupt file fatal at startup and a no-op on reload (the previous
        // config stays in place).
        let toml_config: TomlConfig = toml::from_str(&toml_content).map_err(|e| {
            anyhow::anyhow!("failed to parse {}: {}", config_toml_path.display(), e)
        })?;
        Self::assemble(toml_config, rules, global_scripts, config_dir)
    }

    /// Build the effective [`Config`] from an already parsed `config.toml` and
    /// `proxy.conf`, folding in the admin credentials from the environment and
    /// `<config_dir>/.env`. Touches no file but `.env`, which is what lets
    /// `soli-proxy check` and `POST /api/v1/config/validate` run the very code
    /// a start would.
    pub(crate) fn assemble(
        toml_config: TomlConfig,
        rules: Vec<ProxyRule>,
        global_scripts: Vec<String>,
        config_dir: &Path,
    ) -> Result<Config> {
        // Edge settings are cross-checked here, so `check` and the validate
        // endpoint refuse what a start would (proxy_protocol without
        // trusted_proxies, say).
        toml_config.server.edge.validate()?;
        let dotenv = read_dotenv_credentials(config_dir)?;
        // The process environment wins over the `.env` file.
        let env = |key: &str| std::env::var(key).ok().or_else(|| dotenv.get(key).cloned());

        let mut config = Config {
            server: toml_config.server,
            tls: toml_config.tls,
            letsencrypt: toml_config.letsencrypt,
            scripting: toml_config.scripting.unwrap_or_default(),
            admin: {
                let mut admin = toml_config.admin.unwrap_or_default();
                if admin.username.is_none() {
                    admin.username = env("ADMIN_USER");
                }
                if admin.password_hash.is_none() {
                    // Prefer the explicit hash env; fall back to ADMIN_PASSWORD
                    // which may be either a bcrypt hash or (legacy) plaintext.
                    admin.password_hash =
                        env("ADMIN_PASSWORD_HASH").or_else(|| env("ADMIN_PASSWORD"));
                }
                admin.drop_empty_credentials();
                if let Some(ref mut hash) = admin.password_hash {
                    if !looks_like_bcrypt_hash(hash) {
                        tracing::warn!(
                            "ADMIN_PASSWORD looks like plaintext; hashing at startup. \
                             Prefer storing a bcrypt hash in ADMIN_PASSWORD_HASH."
                        );
                        *hash = crate::auth::generate_hash(hash);
                    }
                }
                admin
            },
            circuit_breaker: toml_config.circuit_breaker,
            apps: toml_config.apps.unwrap_or_default(),
            rules,
            global_scripts,
            limits: LimitsConfig {
                max_connections: toml_config.limits.as_ref().and_then(|l| l.max_connections),
                max_connections_per_ip: toml_config
                    .limits
                    .as_ref()
                    .and_then(|l| l.max_connections_per_ip),
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
            forward_auth: toml_config.forward_auth.unwrap_or_default(),
            compression: toml_config.compression.unwrap_or_default().validated()?,
            error_pages: toml_config.error_pages.unwrap_or_default().loaded()?,
            maintenance: toml_config.maintenance.unwrap_or_default().validated()?,
            upstream: crate::upstream::UpstreamConfig::from_toml(toml_config.upstream.as_ref())?,
            health_checks: crate::upstream::HealthChecksConfig::from_toml(
                toml_config.health_checks.as_ref(),
            )?,
        };
        // Per-rule upstream clients (`@h2`, `@tls_*`, unix sockets, ...):
        // built here, once, so a request only reads the one it needs.
        crate::upstream::prepare(&mut config)?;
        Ok(config)
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

        // Watch the directory, not the file. Writes are atomic renames now
        // (see `write_atomic`), and an inotify watch on a file follows its
        // inode: the first rename would leave it watching the replaced copy,
        // deaf to every later edit. A symlinked proxy.conf is followed to its
        // target, whose directory is the one that sees the renames.
        let config_path =
            std::fs::canonicalize(&self.config_path).unwrap_or_else(|_| self.config_path.clone());
        let watch_dir = match config_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let file_name = config_path.file_name().map(|n| n.to_os_string());

        let (tx, mut rx) = mpsc::channel(16);
        let own_write_hash = self.own_write_hash.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                // Only events naming proxy.conf itself; the directory may hold
                // config.toml, certs and whatever else.
                if let Ok(ref event) = res {
                    let ours = event
                        .paths
                        .iter()
                        .any(|p| p.file_name() == file_name.as_deref());
                    if !ours || !(event.kind.is_modify() || event.kind.is_create()) {
                        return;
                    }
                }
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;

        watcher.watch(&watch_dir, RecursiveMode::NonRecursive)?;

        tracing::info!("Watching config file: {}", config_path.display());

        let reload_path = self.config_path.clone();
        let config_store = self.config.clone();

        std::thread::spawn(move || {
            while let Some(res) = rx.blocking_recv() {
                match res {
                    Ok(_) => {
                        // A write of ours raises several events (create, write,
                        // rename) and an editor's save raises its own mix, so
                        // counting them cannot tell the two apart; the content
                        // can. Skip only while the file is byte-for-byte what we
                        // last wrote — that version is already in memory.
                        let on_disk = std::fs::read(&reload_path).unwrap_or_default();
                        let written = own_write_hash.load(Ordering::SeqCst);
                        if written != 0 && content_hash(&on_disk) == written {
                            tracing::debug!("Ignoring watcher event for our own proxy.conf write");
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
        // Never write `@auth:user:` to disk: the parser discards it on the
        // next reload and the route ends up unprotected. Callers are expected
        // to have resolved empty hashes (`carry_forward_auth_hashes`) already;
        // this is the last line of defence.
        validate_global_scripts(&global_scripts)?;
        for rule in &rules {
            rule.validate()?;
            if let Some(entry) = rule.auth.iter().find(|a| a.hash.is_empty()) {
                anyhow::bail!(
                    "refusing to persist rule {:?}: auth entry for {} has no password hash",
                    rule.matcher,
                    entry.username
                );
            }
        }
        let content = serializer::serialize_proxy_conf(&rules, &global_scripts);
        // Build the candidate first — `prepare` reads `@tls_ca` /
        // `@tls_client_cert` files and builds the clients — and write only a
        // configuration that loads. The file used to be written (and recorded
        // as our own write) before, so a route whose TLS file was missing
        // answered 500 yet sat in proxy.conf, failing the next reload.
        let mut config = (*self.config.load().as_ref()).clone();
        config.rules = rules;
        config.global_scripts = global_scripts;
        crate::upstream::prepare(&mut config)?;
        self.own_write_hash
            .store(content_hash(content.as_bytes()), Ordering::SeqCst);
        write_atomic(&self.config_path, content.as_bytes())?;
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

/// Refuse a value the `proxy.conf` serializer writes verbatim as one token
/// (or one item of a comma list, with `,` in `also`) if it could not come
/// back as the same token: whitespace or a control character in it — a `\n`
/// injects a line of the attacker's choosing — or a trailing backslash, which
/// the parser takes for a line continuation.
pub(crate) fn check_conf_token(what: &str, value: &str, also: &[char]) -> Result<()> {
    if let Some(c) = value
        .chars()
        .find(|c| c.is_whitespace() || c.is_control() || also.contains(c))
    {
        anyhow::bail!(
            "{} {:?} contains {:?}, which cannot be written to proxy.conf",
            what,
            value,
            c
        );
    }
    if value.ends_with('\\') {
        anyhow::bail!(
            "{} {:?} cannot end in a backslash (a proxy.conf line continuation)",
            what,
            value
        );
    }
    Ok(())
}

/// `[global] @script:` names arriving through the admin API: written to
/// `proxy.conf` verbatim, as a comma list, like a rule's.
pub fn validate_global_scripts(scripts: &[String]) -> Result<()> {
    for script in scripts {
        if validate_script_name(script).is_none() {
            anyhow::bail!("invalid global script name {:?}", script);
        }
        check_conf_token("global script", script, &[','])?;
    }
    Ok(())
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

/// Parse a `@script:a.lua,b.lua` list. Every name must be valid: dropping one
/// silently would leave the route running without a hook the operator wrote
/// down (an auth script, say).
fn parse_script_list(list: &str) -> Result<Vec<String>> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|name| {
            validate_script_name(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid script name {:?} in @script: (expected a plain file name \
                     ending in .lua, with no path)",
                    name
                )
            })
        })
        .collect()
}

/// Weight given to a target that does not say `weight:N`.
pub const DEFAULT_TARGET_WEIGHT: u8 = 100;

/// Everything to the right of `->`: the targets and the `@` directives.
#[derive(Default)]
struct RuleTail {
    targets: Vec<Target>,
    scripts: Vec<String>,
    auth: Vec<BasicAuth>,
    auth_exempt: Vec<String>,
    load_balancing: Option<LoadBalancingStrategy>,
    /// Whether any target carried an explicit `weight:N`.
    weighted: bool,
    forward_auth: Option<crate::forward_auth::ForwardAuth>,
    compress: Option<bool>,
    upstream: crate::upstream::UpstreamOptions,
}

/// Parse the right-hand side of a rule.
///
/// Directives are whitespace-separated tokens starting with `@`, and may sit
/// anywhere after the arrow; everything else is the comma-separated target
/// list, each target optionally preceded by `weight:N`. Anything the parser
/// does not understand is an error — the previous parser dropped malformed
/// `@auth` entries (serving the route unprotected), unknown `@lb` strategies,
/// invalid script names and whatever followed a `@script:` list, each with at
/// most a log line.
fn parse_rule_tail(tail: &str) -> Result<RuleTail> {
    let mut out = RuleTail::default();
    let mut target_text = String::new();
    let mut forward_auth = crate::forward_auth::Directives::default();

    for token in tail.split_whitespace() {
        let Some(directive) = token.strip_prefix('@') else {
            if !target_text.is_empty() {
                target_text.push(' ');
            }
            target_text.push_str(token);
            continue;
        };
        let (kind, value) = match directive.split_once(':') {
            Some(kv) => kv,
            // `@h2`, `@tls_insecure`: flags, written without a value.
            None if crate::upstream::is_flag(directive) => (directive, ""),
            None => anyhow::bail!("malformed directive {:?} (expected @name:value)", token),
        };
        match kind {
            "script" => out.scripts.extend(parse_script_list(value)?),
            "auth" => match value.split_once(':') {
                Some((user, hash)) if !user.is_empty() && !hash.is_empty() => {
                    // A hash bcrypt would choke on — or one whose cost would
                    // pin a CPU for minutes per attempt — is refused like any
                    // other malformed entry: the previous config, and its
                    // protection, stay in force.
                    crate::auth::validate_hash(hash)
                        .map_err(|e| anyhow::anyhow!("@auth entry for {:?}: {}", user, e))?;
                    out.auth.push(BasicAuth {
                        username: user.to_string(),
                        hash: hash.to_string(),
                    })
                }
                // Refusing the file keeps the previous config — and its
                // protection — in place; dropping the entry served the route
                // without the credential the operator wrote down.
                _ => anyhow::bail!("malformed {:?} (expected @auth:user:bcrypt-hash)", token),
            },
            "noauth" => {
                for pattern in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    let valid = validate_auth_exempt_path(pattern).ok_or_else(|| {
                        anyhow::anyhow!(
                            "invalid @noauth path {:?}: expected an absolute path such as \
                             /hooks/stripe or /hooks/*, with no '..' segment and no \
                             percent-encoding",
                            pattern
                        )
                    })?;
                    out.auth_exempt.push(valid);
                }
            }
            "lb" => {
                let strategy = match value {
                    "round-robin" => LoadBalancingStrategy::RoundRobin,
                    "weighted" => LoadBalancingStrategy::Weighted,
                    "failover" => LoadBalancingStrategy::Failover,
                    other => anyhow::bail!(
                        "unknown load-balancing strategy {:?} (expected round-robin, \
                         weighted or failover)",
                        other
                    ),
                };
                if out.load_balancing.replace(strategy).is_some() {
                    anyhow::bail!("@lb: given more than once");
                }
            }
            "forward_auth" => forward_auth.url(value)?,
            "forward_auth_headers" => forward_auth.headers(value)?,
            "compress" => {
                let on = crate::response::compress::parse_directive(value)?;
                if out.compress.replace(on).is_some() {
                    anyhow::bail!("@compress: given more than once");
                }
            }
            k if crate::upstream::is_directive(k) => out.upstream.apply_directive(k, value)?,
            other => anyhow::bail!(
                "unknown directive @{}: (expected @script:, @auth:, @noauth:, @lb:, \
                 @forward_auth:, @forward_auth_headers:, @compress:, @retries:, @timeout:, \
                 @connect_timeout:, @h2, @tls_ca:, @tls_insecure, @tls_sni:, @tls_client_cert:, \
                 @health: or @health_interval:)",
                other
            ),
        }
    }
    out.forward_auth = forward_auth.finish()?;

    for item in target_text.split(',') {
        let item = item.trim();
        if item.is_empty() {
            anyhow::bail!("empty target (a stray comma, or no target at all)");
        }
        let mut words = item.split_whitespace();
        let first = words.next().unwrap_or_default();
        let (weight, url) = match first.strip_prefix("weight:") {
            Some(n) => {
                let weight = n.parse::<u8>().map_err(|_| {
                    anyhow::anyhow!("invalid weight {:?} (expected an integer from 0 to 255)", n)
                })?;
                out.weighted = true;
                (weight, words.next().unwrap_or_default())
            }
            None => (DEFAULT_TARGET_WEIGHT, first),
        };
        if url.is_empty() {
            anyhow::bail!("{:?} has a weight but no URL", item);
        }
        if let Some(extra) = words.next() {
            anyhow::bail!(
                "unexpected {:?} after target {:?} (separate targets with commas)",
                extra,
                url
            );
        }
        let url =
            Url::parse(url).map_err(|e| anyhow::anyhow!("invalid target {:?}: {}", url, e))?;
        crate::upstream::validate_target(&url)?;
        out.targets.push(Target { url, weight });
    }
    Ok(out)
}

/// Turn the left-hand side of a rule into a matcher.
fn parse_matcher(source: &str) -> Result<RuleMatcher> {
    if source.is_empty() {
        anyhow::bail!("missing route source before ->");
    }
    Ok(if source == "default" || source == "*" {
        RuleMatcher::Default
    } else if let Some(pattern) = source.strip_prefix("~") {
        RuleMatcher::Regex(RegexMatcher::new(pattern)?)
    } else if !source.starts_with('/')
        && (source.contains('.') || source.parse::<std::net::IpAddr>().is_ok())
    {
        if let Some((domain, path)) = source.split_once('/') {
            if path.is_empty() || path == "*" {
                RuleMatcher::Domain(domain.to_string())
            } else {
                // `split_once` ate the slash: `example.com/api` used to
                // become the prefix "api", which no request path (they all
                // start with '/') could match — and which the serializer
                // wrote back as `example.comapi`.
                let path = path.strip_suffix('*').unwrap_or(path);
                RuleMatcher::DomainPath(domain.to_string(), format!("/{}", path))
            }
        } else {
            RuleMatcher::Domain(source.to_string())
        }
    } else if source.ends_with("/*") {
        RuleMatcher::Prefix(source.trim_end_matches('*').to_string())
    } else {
        RuleMatcher::Exact(source.to_string())
    })
}

/// Capture reference in a regex rule's target: `$1`, `${1}`, `${name}`.
enum CaptureRef<'a> {
    Index(usize),
    Name(&'a str),
}

/// Parse the capture reference at the start of `s`, the text right after a
/// `$`. Returns it with the number of bytes it spans, or `None` when the `$`
/// is literal. `Url` percent-encodes braces in a path, so `${name}` written in
/// proxy.conf is stored as `$%7Bname%7D`; both spellings are accepted.
fn parse_capture_ref(s: &str) -> Option<(CaptureRef<'_>, usize)> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 {
        return Some((CaptureRef::Index(s[..digits].parse().ok()?), digits));
    }
    for (open, close) in [("{", "}"), ("%7B", "%7D")] {
        if let Some(rest) = s.strip_prefix(open) {
            let end = rest.find(close)?;
            let name = &rest[..end];
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return None;
            }
            let r = match name.parse::<usize>() {
                Ok(i) => CaptureRef::Index(i),
                Err(_) => CaptureRef::Name(name),
            };
            return Some((r, open.len() + end + close.len()));
        }
    }
    None
}

/// Substitute `$1` / `${name}` in `template` with the groups of `caps`.
/// A group that did not participate in the match expands to nothing.
pub fn expand_captures(template: &str, caps: &regex::Captures<'_>, out: &mut String) {
    let mut rest = template;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        match parse_capture_ref(after) {
            Some((r, len)) => {
                let m = match r {
                    CaptureRef::Index(i) => caps.get(i),
                    CaptureRef::Name(name) => caps.name(name),
                };
                out.push_str(m.map_or("", |m| m.as_str()));
                rest = &after[len..];
            }
            None => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
}

/// Refuse a regex rule whose target names a group the pattern does not have:
/// `$2` against a one-group pattern would otherwise expand to nothing on
/// every request.
fn check_capture_refs(target: &Url, regex: &Regex) -> Result<()> {
    let mut rest = &target[url::Position::BeforePath..];
    while let Some(pos) = rest.find('$') {
        let after = &rest[pos + 1..];
        let Some((r, len)) = parse_capture_ref(after) else {
            rest = after;
            continue;
        };
        match r {
            CaptureRef::Index(i) if i >= regex.captures_len() => anyhow::bail!(
                "target {} refers to ${} but the pattern has only {} capture group(s)",
                target,
                i,
                regex.captures_len() - 1
            ),
            CaptureRef::Name(name) if !regex.capture_names().flatten().any(|n| n == name) => {
                anyhow::bail!(
                    "target {} refers to ${{{}}}, which the pattern does not define",
                    target,
                    name
                )
            }
            _ => {}
        }
        rest = &after[len..];
    }
    Ok(())
}

/// Hop-by-hop and framing headers a `headers { }` block may not touch: they
/// describe the client connection, not the request, and the proxy manages
/// them itself.
pub(crate) const PROTECTED_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
];

/// Variables a header value may use.
pub const HEADER_VARIABLES: &[&str] = &["client_ip", "scheme", "host"];

/// Per-request values for the variables in a `headers { }` block.
pub struct HeaderVars<'a> {
    /// `$client_ip`: the TCP peer's address, never a client-supplied header.
    pub client_ip: Option<std::net::IpAddr>,
    /// `$scheme`: `http` or `https`, as the client connected.
    pub scheme: &'a str,
    /// `$host`: the host the request was routed on, without port.
    pub host: &'a str,
}

/// Walk a header value template, handing literal text and variable names to
/// `f`. `$$` is a literal `$`; a `$` not followed by a name is literal too.
fn walk_header_template<'a>(template: &'a str, mut f: impl FnMut(Result<&'a str, &'a str>)) {
    let mut rest = template;
    while let Some(pos) = rest.find('$') {
        f(Ok(&rest[..pos]));
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            f(Ok("$"));
            rest = tail;
            continue;
        }
        let len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if len == 0 {
            f(Ok("$"));
        } else {
            f(Err(&after[..len]));
        }
        rest = &after[len..];
    }
    f(Ok(rest));
}

impl HeaderRule {
    /// Check the rule once, at load time, so applying it per request cannot
    /// fail: a valid name, not a hop-by-hop header, only known variables, and
    /// a value that is a legal header value whatever they expand to.
    pub fn validate(&self) -> Result<()> {
        let name = http::HeaderName::from_bytes(self.name.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid header name {:?}", self.name))?;
        if PROTECTED_HEADERS.contains(&name.as_str()) {
            anyhow::bail!(
                "header {} is managed by the proxy and cannot be set in a headers block",
                self.name
            );
        }
        if self.remove {
            if !self.value.is_empty() {
                anyhow::bail!("removal of {} cannot carry a value", self.name);
            }
            return Ok(());
        }
        let mut sample = String::new();
        let mut unknown = None;
        walk_header_template(&self.value, |part| match part {
            Ok(text) => sample.push_str(text),
            Err(var) if HEADER_VARIABLES.contains(&var) => sample.push('x'),
            Err(var) => {
                if unknown.is_none() {
                    unknown = Some(var.to_string());
                }
            }
        });
        if let Some(var) = unknown {
            anyhow::bail!(
                "unknown variable ${} in header {} (known: ${})",
                var,
                self.name,
                HEADER_VARIABLES.join(", $")
            );
        }
        http::HeaderValue::from_str(&sample).map_err(|_| {
            anyhow::anyhow!("invalid value for header {}: {:?}", self.name, self.value)
        })?;
        Ok(())
    }

    fn expand(&self, vars: &HeaderVars<'_>) -> String {
        let mut out = String::with_capacity(self.value.len() + 16);
        walk_header_template(&self.value, |part| match part {
            Ok(text) => out.push_str(text),
            Err("client_ip") => {
                if let Some(ip) = vars.client_ip {
                    use std::fmt::Write;
                    let _ = write!(out, "{}", ip);
                }
            }
            Err("scheme") => out.push_str(vars.scheme),
            Err("host") => out.push_str(vars.host),
            // Unreachable for a validated rule; keep the text as written.
            Err(var) => {
                out.push('$');
                out.push_str(var);
            }
        });
        out
    }
}

/// Apply a rule's `headers { }` block to an upstream request.
///
/// Called after the proxy has normalised the forwarding headers, so a block
/// can override them (`X-Forwarded-Proto: https` behind a TLS-terminating
/// load balancer) or remove them.
pub fn apply_header_rules(
    headers: &mut http::HeaderMap,
    rules: &[HeaderRule],
    vars: &HeaderVars<'_>,
) {
    for rule in rules {
        let Ok(name) = http::HeaderName::from_bytes(rule.name.as_bytes()) else {
            continue;
        };
        if rule.remove {
            headers.remove(&name);
            continue;
        }
        match http::HeaderValue::from_str(&rule.expand(vars)) {
            Ok(value) => {
                headers.insert(name, value);
            }
            // `$host` comes from the request and could in principle carry
            // bytes a header value cannot; skip rather than forward garbage.
            Err(_) => tracing::warn!("Skipping header {}: expanded value is invalid", rule.name),
        }
    }
}

/// Parse one line of a `headers { }` block: `Name: value` or `-Name`.
fn parse_header_line(line: &str) -> Result<HeaderRule> {
    let rule = if let Some(name) = line.strip_prefix('-') {
        HeaderRule {
            name: name.trim().to_string(),
            value: String::new(),
            remove: true,
        }
    } else {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            anyhow::anyhow!(
                "expected `Name: value` or `-Name` inside a headers block, got {:?}",
                line
            )
        })?;
        HeaderRule {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
            remove: false,
        }
    };
    rule.validate()?;
    Ok(rule)
}

pub(crate) fn parse_proxy_config(content: &str) -> Result<(Vec<ProxyRule>, Vec<String>)> {
    let mut rules: Vec<ProxyRule> = Vec::new();
    let mut global_scripts = Vec::new();

    // Join continuation lines (backslash at end of line), remembering the
    // number of the line each logical line started on for error messages.
    let mut joined_lines: Vec<(usize, String)> = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if let Some((_, current)) = joined_lines.last_mut() {
            if current.ends_with('\\') {
                current.pop(); // remove the backslash
                current.push_str(line.trim());
                continue;
            }
        }
        joined_lines.push((idx + 1, line.to_string()));
    }

    let at = |line_no: usize, e: anyhow::Error| anyhow::anyhow!("line {}: {}", line_no, e);
    let mut lines = joined_lines.iter();
    while let Some((line_no, line)) = lines.next() {
        let line_no = *line_no;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // [global] @script:cors.lua,logging.lua
        if let Some(rest) = trimmed.strip_prefix("[global]") {
            let tail = parse_rule_tail_directives_only(rest).map_err(|e| at(line_no, e))?;
            global_scripts.extend(tail);
            continue;
        }

        // A `headers {` block applies to the rule right above it.
        if trimmed
            .strip_prefix("headers")
            .is_some_and(|rest| rest.trim() == "{")
        {
            let Some(rule) = rules.last_mut() else {
                return Err(at(
                    line_no,
                    anyhow::anyhow!("a headers block must follow the rule it applies to"),
                ));
            };
            let mut closed = false;
            for (inner_no, inner) in lines.by_ref() {
                let inner = inner.trim();
                if inner.is_empty() || inner.starts_with('#') {
                    continue;
                }
                if inner == "}" {
                    closed = true;
                    break;
                }
                let header = parse_header_line(inner).map_err(|e| at(*inner_no, e))?;
                rule.headers.push(header);
            }
            if !closed {
                return Err(at(
                    line_no,
                    anyhow::anyhow!("headers block is never closed with `}}`"),
                ));
            }
            continue;
        }

        let Some((source, target_str)) = trimmed.split_once("->") else {
            return Err(at(
                line_no,
                anyhow::anyhow!(
                    "cannot parse {:?}: expected `source -> target`, a `headers {{` block \
                     or `[global] @script:...`",
                    trimmed
                ),
            ));
        };
        let rule = parse_rule(source.trim(), target_str).map_err(|e| at(line_no, e))?;
        rules.push(rule);
    }

    Ok((rules, global_scripts))
}

/// `[global]` takes `@script:` directives and nothing else.
fn parse_rule_tail_directives_only(rest: &str) -> Result<Vec<String>> {
    let mut scripts = Vec::new();
    for token in rest.split_whitespace() {
        match token.strip_prefix("@script:") {
            Some(list) => scripts.extend(parse_script_list(list)?),
            None => anyhow::bail!(
                "unexpected {:?} after [global] (only @script: is allowed there)",
                token
            ),
        }
    }
    Ok(scripts)
}

fn parse_rule(source: &str, target_str: &str) -> Result<ProxyRule> {
    let matcher = parse_matcher(source)?;
    let tail = parse_rule_tail(target_str)?;
    if let RuleMatcher::Regex(rm) = &matcher {
        for target in &tail.targets {
            check_capture_refs(&target.url, &rm.regex)?;
        }
    }
    tail.upstream.validate(&tail.targets)?;
    // `weight:N` on a target means weighted balancing unless the rule says
    // otherwise — that is how the README has always written it.
    let load_balancing = tail.load_balancing.unwrap_or(if tail.weighted {
        LoadBalancingStrategy::Weighted
    } else {
        LoadBalancingStrategy::default()
    });
    let rule = ProxyRule {
        matcher,
        targets: tail.targets,
        headers: vec![],
        scripts: tail.scripts,
        auth: tail.auth,
        auth_exempt: tail.auth_exempt,
        load_balancing,
        forward_auth: tail.forward_auth,
        compress: tail.compress,
        upstream: tail.upstream,
    };
    // What a rewrite would write back must read back the same.
    rule.validate_conf_tokens()?;
    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_restart_trigger_defaults_when_absent() {
        // Existing config.toml files have no [apps] section at all, and the
        // ones that do only set default_user/default_group.
        let cfg: TomlConfig = toml::from_str(
            r#"
[apps]
default_user = "rocky"
"#,
        )
        .expect("[apps] without trigger keys must still parse");
        let apps = cfg.apps.unwrap_or_default();
        assert_eq!(apps.restart_trigger_file(), "restart.txt");
        assert_eq!(apps.restart_trigger_poll_secs(), 2);
    }

    #[test]
    fn apps_idle_timeout_defaults_to_fifteen_minutes_except_in_dev() {
        // Scale to zero is opt-in: a config that predates the key must leave
        // every app running.
        let cfg: TomlConfig = toml::from_str("[apps]\ndefault_user = \"rocky\"\n").unwrap();
        let apps = cfg.apps.unwrap_or_default();
        assert_eq!(apps.idle_timeout(false), 900);
        assert_eq!(apps.idle_timeout(true), 0);
        let cfg: TomlConfig = toml::from_str("[apps]\nidle_timeout = 1800\n").unwrap();
        let apps = cfg.apps.unwrap_or_default();
        assert_eq!(apps.idle_timeout(false), 1800);
        assert_eq!(
            apps.idle_timeout(true),
            1800,
            "an explicit value wins in dev too"
        );
        let cfg: TomlConfig = toml::from_str("[apps]\nidle_timeout = 0\n").unwrap();
        assert_eq!(cfg.apps.unwrap_or_default().idle_timeout(false), 0);
    }

    #[test]
    fn apps_restart_trigger_overrides_are_read() {
        let cfg: TomlConfig = toml::from_str(
            r#"
[apps]
restart_trigger_file = ".deploy"
restart_trigger_poll_secs = 0
"#,
        )
        .expect("trigger overrides must parse");
        let apps = cfg.apps.unwrap_or_default();
        assert_eq!(apps.restart_trigger_file(), ".deploy");
        // 0 disables the poller entirely.
        assert_eq!(apps.restart_trigger_poll_secs(), 0);
    }

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
    fn test_redirect_target_parses_as_domain_rule() {
        let config = "bonfire.solisoft.net -> redirect://bonfire-app.pro\n";
        let (rules, _) = parse_proxy_config(config).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(
            &rules[0].matcher,
            RuleMatcher::Domain(d) if d == "bonfire.solisoft.net"
        ));
        assert_eq!(rules[0].targets.len(), 1);
        assert_eq!(
            rules[0].targets[0].url.as_str(),
            "redirect://bonfire-app.pro"
        );
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
secure.example.com -> http://localhost:9000/ @auth:admin:$2b$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01231 @auth:user:$2b$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01232
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
    fn test_load_balancing_unknown_strategy_is_an_error() {
        // It used to fall back to round-robin silently.
        let config = "/api/* -> http://b1:8080, http://b2:8080 @lb:unknown";
        let err = parse_proxy_config(config).unwrap_err().to_string();
        assert!(err.contains("line 1") && err.contains("unknown"), "{err}");
    }

    #[test]
    fn weights_are_parsed_and_imply_weighted_balancing() {
        // The README syntax, with no @lb: — it used to parse every target at
        // weight 100 (and fail on the `weight:70 ` prefix as a URL).
        let (rules, _) = parse_proxy_config(
            "/api/heavy -> weight:70 http://heavy:8080, weight:30 http://light:8080\n",
        )
        .unwrap();
        let weights: Vec<u8> = rules[0].targets.iter().map(|t| t.weight).collect();
        assert_eq!(weights, vec![70, 30]);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Weighted);
        assert_eq!(rules[0].targets[1].url.as_str(), "http://light:8080/");

        // An explicit @lb: wins over the implication; unweighted targets get
        // the default.
        let (rules, _) =
            parse_proxy_config("/a/* -> weight:0 http://a:1, http://b:1 @lb:failover").unwrap();
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Failover);
        assert_eq!(rules[0].targets[0].weight, 0);
        assert_eq!(rules[0].targets[1].weight, DEFAULT_TARGET_WEIGHT);
    }

    #[test]
    fn bad_weights_are_errors() {
        for bad in [
            "weight:256 http://a:1",
            "weight:-1 http://a:1",
            "weight:x http://a:1",
            "weight:5",
            "http://a:1 weight:5",
        ] {
            assert!(
                parse_proxy_config(&format!("/a/* -> {bad}")).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn headers_block_attaches_to_the_rule_above() {
        let conf = "\
/api/* -> http://localhost:8080
headers {
    # comments are fine
    X-Real-IP: $client_ip
    X-Forwarded-Proto: $scheme
    X-Route: api for $host, costs $$5
    -Cookie
}
default -> http://localhost:3000
";
        let (rules, _) = parse_proxy_config(conf).unwrap();
        assert_eq!(rules.len(), 2);
        let h = &rules[0].headers;
        assert_eq!(h.len(), 4);
        assert_eq!(
            (h[0].name.as_str(), h[0].value.as_str()),
            ("X-Real-IP", "$client_ip")
        );
        assert!(h[3].remove && h[3].name == "Cookie");
        assert!(rules[1].headers.is_empty());

        let mut map = http::HeaderMap::new();
        map.insert("cookie", http::HeaderValue::from_static("session=1"));
        map.insert("x-forwarded-proto", http::HeaderValue::from_static("http"));
        apply_header_rules(
            &mut map,
            h,
            &HeaderVars {
                client_ip: Some("203.0.113.9".parse().unwrap()),
                scheme: "https",
                host: "api.example.com",
            },
        );
        assert_eq!(map["x-real-ip"], "203.0.113.9");
        assert_eq!(map["x-forwarded-proto"], "https");
        assert_eq!(map["x-route"], "api for api.example.com, costs $5");
        assert!(map.get("cookie").is_none());
    }

    #[test]
    fn bad_headers_blocks_are_errors() {
        for (conf, why) in [
            ("headers {\nX-A: 1\n}\n", "no rule above"),
            ("/a -> http://a:1\nheaders {\nX-A: 1\n", "never closed"),
            ("/a -> http://a:1\nheaders {\nX-A 1\n}\n", "no colon"),
            (
                "/a -> http://a:1\nheaders {\nX-A: $nope\n}\n",
                "unknown variable",
            ),
            (
                "/a -> http://a:1\nheaders {\nBad Name: 1\n}\n",
                "invalid name",
            ),
            (
                "/a -> http://a:1\nheaders {\nTransfer-Encoding: chunked\n}\n",
                "hop-by-hop",
            ),
            (
                "/a -> http://a:1\nheaders {\nConnection: close\n}\n",
                "hop-by-hop",
            ),
        ] {
            assert!(parse_proxy_config(conf).is_err(), "{why}: {conf:?}");
        }
    }

    /// Lines the parser does not understand used to be skipped without a
    /// word — a typo'd arrow made a route vanish.
    #[test]
    fn unparseable_lines_are_errors_with_their_line_number() {
        let err = parse_proxy_config("/a -> http://a:1\n\n/b => http://b:1\n")
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("line 3:"), "{err}");
        for bad in [
            "/a -> http://a:1 @bogus:1",
            "/a -> http://a:1 @script:../x.lua",
            "/a -> http://a:1 @script:x.sh",
            "/a -> http://a:1,",
            " -> http://a:1",
            "/a -> http://a:1 @lb:failover @lb:weighted",
            "[global] @script:a.lua junk",
        ] {
            assert!(parse_proxy_config(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// The old `@script:` extractor kept only the text *before* it, so a
    /// directive written after the script list was silently lost.
    #[test]
    fn directives_after_a_script_list_are_kept() {
        let (rules, _) =
            parse_proxy_config("/a/* -> http://a:1, http://b:1 @script:x.lua,y.lua @lb:failover")
                .unwrap();
        assert_eq!(rules[0].scripts, vec!["x.lua", "y.lua"]);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Failover);
    }

    #[test]
    fn forward_auth_directives_parse_and_are_checked() {
        let (rules, _) = parse_proxy_config(
            "app.example.com -> http://a:1 @forward_auth:http://auth:4180/verify \
             @forward_auth_headers:X-Auth-User,X-Auth-Email @noauth:/hooks/*\n",
        )
        .unwrap();
        let fa = rules[0].forward_auth.as_ref().unwrap();
        assert_eq!(fa.url(), "http://auth:4180/verify");
        assert_eq!(fa.copy_headers().len(), 2);
        assert_eq!(rules[0].auth_exempt, vec!["/hooks/*"]);
        assert!(rules[0].validate().is_ok());

        for bad in [
            // Headers with nowhere to copy them from.
            "/a/* -> http://a:1 @forward_auth_headers:X-Auth-User",
            "/a/* -> http://a:1 @forward_auth:http://x/v @forward_auth:http://y/v",
            "/a/* -> http://a:1 @forward_auth:ftp://auth/verify",
            "/a/* -> http://a:1 @forward_auth:http://u:p@auth/verify",
            "/a/* -> http://a:1 @forward_auth:/verify",
            "/a/* -> http://a:1 @forward_auth:",
            "/a/* -> http://a:1 @forward_auth:http://x/v @forward_auth_headers:Host",
            "/a/* -> http://a:1 @forward_auth:http://x/v @forward_auth_headers:X-Forwarded-For",
        ] {
            assert!(parse_proxy_config(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// A route arriving as JSON through the admin API carries forward-auth
    /// as `{"url", "headers"}`, checked on the way in.
    #[test]
    fn forward_auth_json_is_validated() {
        let json = r#"{"matcher":{"type":"prefix","value":"/a/"},"targets":[{"url":"http://a:1/","weight":100}],
            "headers":[],"scripts":[],
            "forward_auth":{"url":"http://auth:4180/verify","headers":["X-Auth-User"]}}"#;
        let rule: ProxyRule = serde_json::from_str(json).unwrap();
        assert!(rule.validate().is_ok());
        let back = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            back["forward_auth"],
            serde_json::json!({"url": "http://auth:4180/verify", "headers": ["x-auth-user"]})
        );
        let again: ProxyRule = serde_json::from_value(back).unwrap();
        assert_eq!(again.forward_auth, rule.forward_auth);

        let bad = json.replace("http://auth:4180/verify", "gopher://auth/verify");
        assert!(serde_json::from_str::<ProxyRule>(&bad).is_err());
        // No forward-auth: the key is not emitted at all.
        let plain = r#"{"matcher":{"type":"prefix","value":"/a/"},"targets":[{"url":"http://a:1/","weight":100}],
            "headers":[],"scripts":[]}"#;
        let rule: ProxyRule = serde_json::from_str(plain).unwrap();
        assert!(serde_json::to_value(&rule)
            .unwrap()
            .get("forward_auth")
            .is_none());
    }

    #[test]
    fn domain_path_rules_keep_their_leading_slash() {
        let (rules, _) =
            parse_proxy_config("example.com/api -> http://a:1\nexample.com/old/* -> http://b:1\n")
                .unwrap();
        assert_eq!(
            rules[0].matcher,
            RuleMatcher::DomainPath("example.com".into(), "/api".into())
        );
        assert_eq!(
            rules[1].matcher,
            RuleMatcher::DomainPath("example.com".into(), "/old/".into())
        );
    }

    #[test]
    fn regex_targets_may_only_name_groups_the_pattern_has() {
        assert!(parse_proxy_config(r"~^/users/(\d+)$ -> http://u:8080/users/$1").is_ok());
        assert!(parse_proxy_config(r"~^/u/(?P<id>\d+)$ -> http://u:8080/users/${id}").is_ok());
        assert!(parse_proxy_config(r"~^/users/(\d+)$ -> http://u:8080/users/$2").is_err());
        assert!(parse_proxy_config(r"~^/u/(?P<id>\d+)$ -> http://u:8080/${name}").is_err());
    }

    #[test]
    fn expand_captures_substitutes_numbered_and_named_groups() {
        let re = Regex::new(r"^/u/(?P<id>\d+)/(\w+)$").unwrap();
        let caps = re.captures("/u/42/edit").unwrap();
        let mut out = String::new();
        expand_captures("/users/$1/$2?id=${id}&n=$%7Bid%7D&cost=$", &caps, &mut out);
        assert_eq!(out, "/users/42/edit?id=42&n=42&cost=$");
    }

    #[test]
    fn rules_with_headers_and_weights_survive_admin_validation() {
        let (rules, _) = parse_proxy_config(
            "/a/* -> weight:3 http://a:1, weight:1 http://b:1\nheaders {\nX-A: $scheme\n}\n",
        )
        .unwrap();
        assert!(rules[0].validate().is_ok());
        let mut bad = rules[0].clone();
        bad.headers[0].value = "$nope".to_string();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn https_listens_on_the_bind_address() {
        let server = |bind: &str| ServerConfig {
            bind: bind.to_string(),
            https_port: 8443,
            ..Default::default()
        };
        assert_eq!(
            server("127.0.0.1:8080").https_addr().unwrap().to_string(),
            "127.0.0.1:8443"
        );
        assert_eq!(
            server("[::]:80").https_addr().unwrap().to_string(),
            "[::]:8443"
        );
        assert_eq!(
            server("0.0.0.0:80").https_addr().unwrap().to_string(),
            "0.0.0.0:8443"
        );
        assert!(server("localhost:80").https_addr().is_err());
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

    const VALID_TOML: &str = r#"
[admin]
enabled = true
bind = "0.0.0.0:9090"
api_key = "secret123"
"#;

    #[tokio::test]
    async fn reload_with_corrupt_config_toml_fails_and_keeps_previous_config() {
        // Regression: a parse error used to substitute TomlConfig::default(),
        // which dropped [admin].api_key while the listener stayed bound to
        // 0.0.0.0 — reload() reported success and the admin API was open.
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        let toml_path = dir.path().join("config.toml");
        std::fs::write(&proxy_conf, "default -> http://localhost:3000\n").unwrap();
        std::fs::write(&toml_path, VALID_TOML).unwrap();

        let manager = ConfigManager::new(proxy_conf.to_str().unwrap()).unwrap();
        let before = manager.get_config();
        assert_eq!(before.admin.api_key.as_deref(), Some("secret123"));
        assert_eq!(before.admin.bind, "0.0.0.0:9090");

        std::fs::write(&toml_path, "[admin\nthis is not toml").unwrap();
        std::fs::write(&proxy_conf, "default -> http://localhost:4000\n").unwrap();

        let err = manager
            .reload()
            .await
            .expect_err("corrupt config.toml must fail reload");
        assert!(err.to_string().contains("config.toml"), "{err}");

        let after = manager.get_config();
        assert!(
            Arc::ptr_eq(&before, &after),
            "config was swapped on a failed reload"
        );
        assert_eq!(after.admin.api_key.as_deref(), Some("secret123"));
        assert_eq!(
            after.rules[0].targets[0].url.as_str(),
            "http://localhost:3000/"
        );
    }

    #[test]
    fn startup_with_corrupt_config_toml_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "").unwrap();
        std::fs::write(dir.path().join("config.toml"), "[server\nbind = ").unwrap();

        assert!(ConfigManager::new(proxy_conf.to_str().unwrap()).is_err());
    }

    #[test]
    fn startup_without_config_toml_uses_defaults() {
        // A missing file is not an error: the defaults are written out.
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "").unwrap();

        let manager = ConfigManager::new(proxy_conf.to_str().unwrap()).unwrap();
        assert!(dir.path().join("config.toml").exists());
        assert_eq!(manager.get_config().admin.bind, "127.0.0.1:9090");
    }

    fn rule_with_auth(auth: Vec<BasicAuth>) -> ProxyRule {
        ProxyRule {
            matcher: RuleMatcher::Prefix("/db/".to_string()),
            targets: vec![Target {
                url: Url::parse("http://localhost:8080").unwrap(),
                weight: 100,
            }],
            headers: vec![],
            scripts: vec![],
            auth,
            auth_exempt: vec![],
            load_balancing: LoadBalancingStrategy::default(),
            forward_auth: None,
            compress: None,
            upstream: Default::default(),
        }
    }

    #[test]
    fn noauth_parses_comma_separated_paths() {
        let (rules, _) = parse_proxy_config(
            "/x/* -> http://localhost:8080/ @noauth:/hooks/stripe,/health @lb:weighted",
        )
        .unwrap();
        assert_eq!(rules[0].auth_exempt, vec!["/hooks/stripe", "/health"]);
        assert_eq!(rules[0].load_balancing, LoadBalancingStrategy::Weighted);
        assert_eq!(rules[0].targets[0].url.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn noauth_patterns_it_cannot_match_literally_are_errors() {
        // Relative, traversing and percent-encoded patterns can never be
        // exempt (the backend may resolve them somewhere else entirely). They
        // used to be dropped with a warning; now the file is refused, so the
        // operator learns the carve-out they wrote does not exist.
        for bad in ["hooks", "/a/../b", "/c%2f", "/../"] {
            let conf = format!("/x/* -> http://x/ @noauth:/ok/*,{bad}");
            assert!(
                parse_proxy_config(&conf).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn conf_rule_parses_auth_and_noauth_together() {
        let (rules, _) = parse_proxy_config(
            "app.example.com -> http://localhost:8080/ @auth:admin:$2b$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123X \
             @noauth:/webhooks/stripe,/hooks/*\n",
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].auth.len(), 1);
        assert_eq!(rules[0].auth_exempt, vec!["/webhooks/stripe", "/hooks/*"]);
        // The directives must not leak into the target URL.
        assert_eq!(rules[0].targets[0].url.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn auth_exempt_matches_exact_paths_and_star_prefixes() {
        let patterns = vec!["/webhooks/stripe".to_string(), "/hooks/*".to_string()];
        assert!(path_is_auth_exempt(&patterns, "/webhooks/stripe"));
        // Exact patterns are exact: no children, no siblings.
        assert!(!path_is_auth_exempt(&patterns, "/webhooks/stripe/extra"));
        assert!(!path_is_auth_exempt(&patterns, "/webhooks/stripe2"));
        // `/hooks/*` covers the subtree and the bare prefix, mirroring how
        // `Prefix` route matchers behave.
        assert!(path_is_auth_exempt(&patterns, "/hooks/github"));
        assert!(path_is_auth_exempt(&patterns, "/hooks/"));
        assert!(path_is_auth_exempt(&patterns, "/hooks"));
        assert!(!path_is_auth_exempt(&patterns, "/hooksy"));
        assert!(!path_is_auth_exempt(&patterns, "/admin"));
        // No patterns at all means nothing is exempt.
        assert!(!path_is_auth_exempt(&[], "/hooks/github"));
    }

    /// The exemption decides whether to SKIP the password check, so a request
    /// path that does not compare literally must never match — the backend may
    /// normalize `/hooks/../admin` to `/admin` after the proxy waved it past.
    #[test]
    fn auth_exempt_fails_closed_on_traversal_and_encoding() {
        let patterns = vec!["/hooks/*".to_string()];
        assert!(!path_is_auth_exempt(&patterns, "/hooks/../admin"));
        assert!(!path_is_auth_exempt(&patterns, "/hooks/./secret"));
        assert!(!path_is_auth_exempt(&patterns, "/hooks/%2e%2e/admin"));
        assert!(!path_is_auth_exempt(&patterns, "/hooks/a%2fb"));
    }

    #[test]
    fn validate_auth_exempt_rejects_what_the_parser_would_drop() {
        // The admin API accepts rules as JSON and never runs the .conf parser,
        // so the same patterns must be refused there with an error.
        let mut rule = rule_with_auth(vec![basic(
            "admin",
            "$2b$04$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123X",
        )]);
        rule.auth_exempt = vec!["/hooks/*".to_string(), "/health".to_string()];
        assert!(rule.validate_auth_exempt().is_ok());

        for bad in ["hooks", "/a/../b", "/c%2f", "*", ""] {
            rule.auth_exempt = vec![bad.to_string()];
            assert!(
                rule.validate_auth_exempt().is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    fn basic(username: &str, hash: &str) -> BasicAuth {
        BasicAuth {
            username: username.to_string(),
            hash: hash.to_string(),
        }
    }

    #[test]
    fn admin_config_drops_empty_credentials() {
        let mut admin = AdminConfig {
            enabled: Some(true),
            bind: "127.0.0.1:9090".to_string(),
            api_key: Some(String::new()),
            username: Some(String::new()),
            password_hash: Some(String::new()),
        };
        admin.drop_empty_credentials();
        assert_eq!(admin.api_key, None);
        assert_eq!(admin.username, None);
        assert_eq!(admin.password_hash, None);

        let toml_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            toml_dir.path().join("config.toml"),
            "[admin]\nbind = \"127.0.0.1:9090\"\napi_key = \"\"\n",
        )
        .unwrap();
        std::fs::write(
            toml_dir.path().join("proxy.conf"),
            "default -> http://localhost:3000\n",
        )
        .unwrap();
        let manager =
            ConfigManager::new(toml_dir.path().join("proxy.conf").to_str().unwrap()).unwrap();
        assert_eq!(manager.get_config().admin.api_key, None);
    }

    #[test]
    fn carry_forward_keeps_existing_hash_and_rejects_unknown_user() {
        let existing = rule_with_auth(vec![basic("demo", "$2b$12$old")]);

        let mut incoming = rule_with_auth(vec![basic("demo", ""), basic("other", "$2b$12$new")]);
        incoming.carry_forward_auth_hashes(Some(&existing)).unwrap();
        assert_eq!(incoming.auth[0].hash, "$2b$12$old");
        assert_eq!(incoming.auth[1].hash, "$2b$12$new");

        let mut incoming = rule_with_auth(vec![basic("stranger", "")]);
        let err = incoming
            .carry_forward_auth_hashes(Some(&existing))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "auth entry for stranger has no password hash"
        );

        let mut incoming = rule_with_auth(vec![basic("demo", "")]);
        assert!(incoming.carry_forward_auth_hashes(None).is_err());
    }

    #[test]
    fn persist_rules_refuses_empty_auth_hash() {
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "default -> http://localhost:3000\n").unwrap();
        let manager = ConfigManager::new(proxy_conf.to_str().unwrap()).unwrap();

        let err = manager
            .add_route(rule_with_auth(vec![basic("demo", "")]))
            .unwrap_err();
        assert!(err.to_string().contains("no password hash"), "{err}");

        // Neither disk nor memory changed.
        assert_eq!(manager.get_config().rules.len(), 1);
        let on_disk = std::fs::read_to_string(&proxy_conf).unwrap();
        assert!(!on_disk.contains("@auth"), "{on_disk}");
    }

    /// A malformed `@auth` entry used to be dropped with a warning, and the
    /// route was then served without that credential. Refusing the file keeps
    /// the previous (protected) config instead.
    #[test]
    fn malformed_auth_entry_is_an_error() {
        for bad in ["@auth:demo:", "@auth::$2b$x", "@auth:demo"] {
            let conf = format!("/x/* -> http://localhost:8080/ {bad} @auth:ok:$2b$x");
            assert!(
                parse_proxy_config(&conf).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// `.env` is read from the config's own directory only, never a parent,
    /// only the admin keys are taken, and nothing reaches the process
    /// environment (where `HTTP_PROXY` would be handed to every spawned app).
    #[test]
    fn dotenv_is_read_beside_the_config_only_and_never_exported() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::write(
            parent.path().join(".env"),
            "ADMIN_USER=from-parent\nADMIN_PASSWORD_HASH=$2b$12$parent\n",
        )
        .unwrap();
        let dir = parent.path().join("conf");
        std::fs::create_dir(&dir).unwrap();

        // No .env beside the config: the parent's is not consulted.
        assert!(read_dotenv_credentials(&dir).unwrap().is_empty());

        std::fs::write(
            dir.join(".env"),
            "ADMIN_USER=alice\nADMIN_PASSWORD_HASH='$2b$12$abc'\nSOLI_DOTENV_TEST_PROXY=http://evil:3128\n",
        )
        .unwrap();
        let creds = read_dotenv_credentials(&dir).unwrap();
        assert_eq!(creds.get("ADMIN_USER").map(String::as_str), Some("alice"));
        assert_eq!(
            creds.get("ADMIN_PASSWORD_HASH").map(String::as_str),
            Some("$2b$12$abc")
        );
        assert!(!creds.contains_key("SOLI_DOTENV_TEST_PROXY"));
        assert!(std::env::var("SOLI_DOTENV_TEST_PROXY").is_err());

        // And it is what load_config uses when the environment is silent.
        if std::env::var("ADMIN_USER").is_err() {
            std::fs::write(dir.join("proxy.conf"), "").unwrap();
            let manager = ConfigManager::new(dir.join("proxy.conf").to_str().unwrap()).unwrap();
            assert_eq!(
                manager.get_config().admin.username.as_deref(),
                Some("alice")
            );
        }
    }

    #[test]
    fn malformed_dotenv_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "ADMIN_USER='unterminated\n").unwrap();
        assert!(read_dotenv_credentials(dir.path()).is_err());
    }

    #[test]
    fn test_read_worker_threads_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let proxy_conf = dir.path().join("proxy.conf");
        std::fs::write(&proxy_conf, "").unwrap();
        // No config.toml in dir.
        assert_eq!(read_worker_threads(proxy_conf.to_str().unwrap()), None);
    }

    /// The replacement is whole or absent, carries the old permissions, goes
    /// through a symlink to its target, and leaves no temporary file behind.
    #[test]
    fn write_atomic_replaces_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("proxy.conf");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&target, b"new contents").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new contents");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let link = dir.path().join("link.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"via link").unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "via link");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// The watcher's own-write check: the fingerprint of what was written
    /// matches the file until someone else changes a byte, and is never the
    /// "nothing written" sentinel.
    #[test]
    fn content_hash_tells_our_write_from_an_edit() {
        let ours = content_hash(b"default -> http://localhost:3000\n");
        assert_ne!(ours, 0);
        assert_eq!(ours, content_hash(b"default -> http://localhost:3000\n"));
        assert_ne!(ours, content_hash(b"default -> http://localhost:3001\n"));
        assert_ne!(content_hash(b""), 0);
    }
}
