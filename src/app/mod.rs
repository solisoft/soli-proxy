use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use url::Url;

pub mod deployment;
pub mod external;
pub mod port_manager;

use crate::circuit_breaker::SharedCircuitBreaker;
use crate::metrics::Metrics as AppMetrics;
pub use deployment::{DeploymentManager, DeploymentStatus, ProcessExit, SlotOwnership};
pub use port_manager::{PortAllocator, PortManager};

/// Authentication for an app, from the `[auth]` section of `app.infos`:
///
/// ```toml
/// [auth]
/// noauth = ["/webhooks/stripe", "/hooks/*"]
/// # Forward authentication (optional): ask an SSO service first.
/// forward = "http://auth.internal:4180/oauth2/auth"
/// forward_headers = ["X-Auth-Request-User", "X-Auth-Request-Email"]
///
/// [auth.users]
/// admin = "$2b$12$..."
/// ```
///
/// Apps are routed by `AppManager`, not by `proxy.conf` rules — `sync_routes`
/// actively prunes whole-domain static rules for app-managed domains — so a
/// `@auth` rule on one cannot protect an app. (A `host/path/*` carve-out
/// survives, because it shadows nothing; see `shadowing_domain`.) This is the equivalent, living where the rest of the
/// app's config already lives.
///
/// Basic Auth (`users`) and forward-auth (`forward`) may be combined: Basic
/// runs first and both must pass; `noauth` paths skip both. In
/// `[apps] multi_tenant` mode `forward` must be covered by `[forward_auth]
/// allowed_urls` (checked at discovery), since the proxy fetches it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "AppAuthToml")]
pub struct AppAuth {
    /// Accounts allowed through, parsed from a `username = "bcrypt hash"`
    /// table into the same shape route auth uses.
    pub users: Vec<crate::auth::BasicAuth>,
    /// Paths served without credentials, same syntax as the `@noauth:`
    /// directive on a route: an exact path, or a prefix ending in `*`.
    pub noauth: Vec<String>,
    /// `forward` + `forward_headers`, checked and compiled at load time.
    pub forward: Option<crate::forward_auth::ForwardAuth>,
}

/// `[auth]` as written. `forward` and `forward_headers` only mean something
/// together, so they are compiled into one [`crate::forward_auth::ForwardAuth`]
/// — and a bad URL fails the manifest — on the way to [`AppAuth`].
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AppAuthToml {
    #[serde(deserialize_with = "deserialize_auth_users")]
    users: Vec<crate::auth::BasicAuth>,
    noauth: Vec<String>,
    forward: Option<String>,
    forward_headers: Vec<String>,
}

impl TryFrom<AppAuthToml> for AppAuth {
    type Error = String;

    fn try_from(raw: AppAuthToml) -> Result<Self, String> {
        let forward = match raw.forward {
            Some(url) => Some(
                crate::forward_auth::ForwardAuth::new(&url, &raw.forward_headers)
                    .map_err(|e| format!("[auth] forward: {e:#}"))?,
            ),
            None if raw.forward_headers.is_empty() => None,
            None => return Err("[auth] forward_headers is set without forward".to_string()),
        };
        Ok(Self {
            users: raw.users,
            noauth: raw.noauth,
            forward,
        })
    }
}

/// Read `[auth.users]` as a `username = "hash"` table.
///
/// A `BTreeMap` rather than a `HashMap` so the order is stable: it decides
/// which duplicate wins nothing here, but it keeps `GET /api/v1/apps` output
/// and log lines from reshuffling between runs.
fn deserialize_auth_users<'de, D>(d: D) -> Result<Vec<crate::auth::BasicAuth>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let table = std::collections::BTreeMap::<String, String>::deserialize(d)?;
    Ok(table
        .into_iter()
        .map(|(username, hash)| crate::auth::BasicAuth { username, hash })
        .collect())
}

/// Serialized for the admin API, which must never hand back password hashes
/// (the route-auth API has the same contract). Usernames are emitted so the
/// UI can show who is configured; `users` is not accepted back on input, so
/// there is no round trip to break.
impl Serialize for AppAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(4))?;
        let usernames: Vec<&str> = self.users.iter().map(|u| u.username.as_str()).collect();
        map.serialize_entry("usernames", &usernames)?;
        map.serialize_entry("noauth", &self.noauth)?;
        let forward_headers: Vec<&str> = self
            .forward
            .iter()
            .flat_map(|f| f.copy_headers().iter().map(|h| h.as_str()))
            .collect();
        map.serialize_entry("forward", &self.forward.as_ref().map(|f| f.url()))?;
        map.serialize_entry("forward_headers", &forward_headers)?;
        map.end()
    }
}

impl AppAuth {
    /// Whether a request for `path` must present credentials.
    pub fn requires_auth(&self, path: &str) -> bool {
        !self.users.is_empty() && !self.is_exempt(path)
    }

    /// Whether `path` is one of the `noauth` carve-outs (skipping Basic Auth
    /// and forward-auth alike).
    pub fn is_exempt(&self, path: &str) -> bool {
        crate::config::path_is_auth_exempt(&self.noauth, path)
    }

    /// Whether this section gates anything: accounts, or a forward-auth.
    pub fn is_active(&self) -> bool {
        !self.users.is_empty() || self.forward.is_some()
    }

    /// Reject a manifest whose auth section cannot be enforced as written.
    ///
    /// An empty username or hash would be a silently unusable account, and a
    /// `noauth` pattern that cannot be compared literally is refused for the
    /// same reason the route directive refuses it: it must never widen into a
    /// bypass. Callers treat this as a load failure, so the app is skipped
    /// rather than served with auth the operator thinks is on. A cluster push
    /// carrying auth for a domain goes through the same check.
    pub(crate) fn validate(&self) -> Result<(), anyhow::Error> {
        for user in &self.users {
            if user.username.is_empty() {
                anyhow::bail!("[auth.users] has an entry with an empty username");
            }
            if user.hash.is_empty() {
                anyhow::bail!(
                    "[auth.users] entry {:?} has an empty password hash (generate one with \
                     `hash-password`)",
                    user.username
                );
            }
            // The hash is written by whoever owns the manifest — a tenant, in
            // multi-tenant mode — and its cost is a work factor they would be
            // choosing for the proxy's CPU: `$2b$31$` is days of bcrypt per
            // request. Only well-formed hashes at cost 4..=13 are accepted.
            if let Err(e) = crate::auth::validate_hash(&user.hash) {
                anyhow::bail!(
                    "[auth.users] entry {:?} has an unusable password hash: {}",
                    user.username,
                    e
                );
            }
        }
        for pattern in &self.noauth {
            if crate::config::validate_auth_exempt_path(pattern).is_none() {
                anyhow::bail!(
                    "auth.noauth path {:?} is invalid: expected an absolute path such as \
                     /webhooks/stripe or /hooks/*, with no '..' segment and no percent-encoding",
                    pattern
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub name: String,
    pub domain: String,
    pub start_script: Option<String>,
    pub stop_script: Option<String>,
    pub health_check: Option<String>,
    pub graceful_timeout: u32,
    pub drain_delay: u32,
    pub port_range_start: u16,
    pub port_range_end: u16,
    pub workers: u16,
    pub user: Option<String>,
    pub group: Option<String>,
    pub docker_image: Option<String>,
    pub docker_options: Option<String>,
    pub docker_network: Option<String>,
    /// HTTP Basic Auth for this app's domains. Empty by default.
    pub auth: AppAuth,
    /// Seconds without a request before the proxy stops the app and restarts
    /// it on the next one (scale to zero). `None` inherits `[apps]
    /// idle_timeout` from `config.toml`; `0` means the app is never put to
    /// sleep — the default, and the only sane one for anything with cron
    /// jobs, sockets or a warm cache it cannot rebuild in a second.
    #[serde(default)]
    pub idle_timeout: Option<u64>,
    /// `compress = false` keeps the proxy from compressing this app's
    /// responses; `true` asks for it even with `[compression] enabled =
    /// false` (ignored in multi-tenant mode, where it would spend the
    /// operator's CPU). Unset follows `[compression]`.
    #[serde(default)]
    pub compress: Option<bool>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            domain: String::new(),
            start_script: None,
            stop_script: None,
            health_check: Some("/health".to_string()),
            graceful_timeout: 30,
            drain_delay: 5,
            port_range_start: 20000,
            port_range_end: 30000,
            workers: 1,
            user: None,
            group: None,
            docker_image: None,
            docker_options: None,
            docker_network: None,
            auth: AppAuth::default(),
            idle_timeout: None,
            compress: None,
        }
    }
}

/// The environment overlay sections an `app.infos` may carry. Which one is
/// folded in is decided by the proxy's `--dev` flag — the same flag that
/// already appends `--dev` to an auto-detected Soli start script and registers
/// each app's `.test` alias — so an app has one manifest and the environment
/// it runs in picks the values, instead of dev and prod drifting apart in two
/// files nobody diffs.
///
/// Both sections are optional and a manifest carrying neither parses exactly
/// as it did before they existed.
const ENV_SECTIONS: [&str; 2] = ["development", "production"];

/// Every root key `AppConfig` understands.
///
/// Serde ignores what it does not recognise here, without a word: `worker = 4`
/// has always run the app with one worker and said nothing. Ignoring stays the
/// behaviour — refusing the manifest would take a running app off the routing
/// table over a stray key — but discovery now logs what it skipped, which is
/// the difference between a five-minute puzzle and a five-hour one. The
/// overlay sections make the stakes higher: a key that lands in the wrong
/// section is ignored just as quietly.
///
/// `known_root_keys_match_app_config` fails if a field is added to
/// `AppConfig` without being listed here.
const KNOWN_ROOT_KEYS: [&str; 18] = [
    "name",
    "domain",
    "start_script",
    "stop_script",
    "health_check",
    "graceful_timeout",
    "drain_delay",
    "port_range_start",
    "port_range_end",
    "workers",
    "user",
    "group",
    "docker_image",
    "docker_options",
    "docker_network",
    "auth",
    "idle_timeout",
    "compress",
];

/// Parse an `app.infos`, folding in the overlay for the environment this proxy
/// runs as.
///
/// ```toml
/// workers = 4
/// idle_timeout = 1800
///
/// [development]
/// workers = 1          # one worker and no sleeping while developing
/// idle_timeout = 0
/// ```
///
/// The active section is applied key by key over the top-level table, and a
/// nested table merges into its counterpart rather than replacing it — so
/// `[production.auth.users]` adds accounts without discarding the `noauth`
/// list written at the top level. The inactive section is dropped unread:
/// `[production]` may name settings this proxy build has never heard of, and a
/// developer's machine will not refuse to start over them.
///
/// `label` names the app in log lines, and is the site directory name.
fn parse_app_infos(content: &str, dev_mode: bool, label: &str) -> Result<AppConfig, anyhow::Error> {
    let mut root: toml::Table = toml::from_str(content)?;
    let active = if dev_mode {
        "development"
    } else {
        "production"
    };

    let mut overlay = None;
    for section in ENV_SECTIONS {
        let Some(value) = root.remove(section) else {
            continue;
        };
        let found = value.type_str();
        let toml::Value::Table(table) = value else {
            anyhow::bail!("[{section}] in app.infos must be a section, found a {found}");
        };
        if section == active {
            overlay = Some(table);
        }
    }

    warn_unknown_keys(&root, label, None);

    let Some(overlay) = overlay else {
        // No overlay to apply: deserialize the source text itself rather than
        // the table we parsed to look for sections. Identical result, and it
        // keeps the line and column spans `toml` attaches to a type error —
        // which is most manifests, so most error messages.
        return Ok(toml::from_str(content)?);
    };

    warn_unknown_keys(&overlay, label, Some(active));
    merge_into(&mut root, overlay);
    Ok(toml::Value::Table(root).try_into()?)
}

/// Apply `overlay` onto `base`, recursing so a table present on both sides
/// merges key by key instead of replacing wholesale.
fn merge_into(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(base_table)), toml::Value::Table(overlay_table)) => {
                merge_into(base_table, overlay_table);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Log the keys of `table` that `AppConfig` will silently drop. `section` is
/// the overlay the table came from, or `None` for the manifest's top level.
fn warn_unknown_keys(table: &toml::Table, label: &str, section: Option<&str>) {
    for key in table.keys() {
        if KNOWN_ROOT_KEYS.contains(&key.as_str()) {
            continue;
        }
        match section {
            Some(section) => tracing::warn!(
                "app.infos for {}: unknown setting {:?} in [{}] — ignored",
                label,
                key,
                section
            ),
            None => tracing::warn!(
                "app.infos for {}: unknown setting {:?} — ignored",
                label,
                key
            ),
        }
    }
}

/// Largest `app.infos` the proxy will read. A real manifest is a few hundred
/// bytes; the cap is what keeps a tenant's `app.infos -> /dev/zero` (or a
/// multi-gigabyte file) from being read into memory whole.
pub(crate) const MAX_TENANT_FILE_BYTES: u64 = 64 * 1024;

/// Ceiling on `graceful_timeout` and `drain_delay`, in seconds.
const MAX_APP_TIMEOUT_SECS: u32 = 3600;

/// Read a small file that a tenant controls, safely.
///
/// `std::fs::read_to_string` on tenant input fails three ways at once: a FIFO
/// blocks the reading thread forever (and discovery ran it on an async
/// worker, under the lock every request takes), a symlink to `/dev/zero` is
/// read until the process is OOM-killed — at every boot, so the proxy
/// crash-loops — and a symlink can point at a file the tenant should not be
/// able to name. So: open with `O_NONBLOCK` (a FIFO opens immediately instead
/// of waiting for a writer), refuse anything but a regular file after
/// `fstat`, and read at most [`MAX_TENANT_FILE_BYTES`]. With `follow_symlinks`
/// false the open also carries `O_NOFOLLOW`, so a symlink in the last
/// component is an error rather than an indirection.
///
/// `Ok(None)` means the file does not exist, which is not an error: most
/// manifests are optional.
pub(crate) fn read_tenant_file(
    path: &Path,
    follow_symlinks: bool,
) -> Result<Option<String>, anyhow::Error> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
    if !follow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("{} is a symlink, which is not followed", path.display())
        }
        Err(e) => return Err(anyhow::anyhow!("cannot open {}: {}", path.display(), e)),
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    if meta.len() > MAX_TENANT_FILE_BYTES {
        anyhow::bail!(
            "{} is {} bytes, above the {} byte limit",
            path.display(),
            meta.len(),
            MAX_TENANT_FILE_BYTES
        );
    }
    // The size above is a hint, not a bound: the file can grow between the
    // fstat and the read. `take` is the bound.
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_TENANT_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_TENANT_FILE_BYTES {
        anyhow::bail!(
            "{} is above the {} byte limit",
            path.display(),
            MAX_TENANT_FILE_BYTES
        );
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{} is not UTF-8", path.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInstance {
    pub name: String,
    pub slot: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub status: InstanceStatus,
    pub last_started: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstanceStatus {
    Stopped,
    Starting,
    Running,
    Unhealthy,
    Failed,
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceStatus::Stopped => write!(f, "Stopped"),
            InstanceStatus::Starting => write!(f, "Starting"),
            InstanceStatus::Running => write!(f, "Running"),
            InstanceStatus::Unhealthy => write!(f, "Unhealthy"),
            InstanceStatus::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub config: AppConfig,
    pub path: PathBuf,
    pub blue: AppInstance,
    pub green: AppInstance,
    pub current_slot: String,
    /// True when the app failed to start and automatic remediation has been
    /// suspended. Derived from `AppManager` state on read, never persisted.
    #[serde(default, skip_deserializing)]
    pub quarantined: bool,
    /// `<site>/maintenance.flag` exists (see `response::maintenance`). The
    /// admin API's `GET /apps` also reports a window opened through the API.
    #[serde(default, skip_deserializing)]
    pub maintenance: bool,
    /// Pages from `<site>/error_pages/`, read at discovery.
    #[serde(skip)]
    pub error_pages: Option<Arc<crate::response::error_pages::ErrorPages>>,
}

impl AppInfo {
    /// Load an app from its site directory.
    ///
    /// `multi_tenant` means `app.infos` is tenant input: `name` and `domain`
    /// are then bound to the directory name (the one thing the operator, not
    /// the tenant, chose), so a tenant cannot claim another site's `Host` or
    /// another app's entry in the apps map. Single-tenant keeps them free-form
    /// — the operator wrote both sides.
    pub fn from_path(
        path: &std::path::Path,
        dev_mode: bool,
        multi_tenant: bool,
    ) -> Result<Self, anyhow::Error> {
        // Validate that folder name is a valid domain (contains at least one dot)
        let folder_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !is_valid_domain(folder_name) {
            return Err(anyhow::anyhow!(
                "folder '{}' is not a valid domain (must contain at least one dot)",
                folder_name
            ));
        }

        // In multi_tenant mode the file is tenant input, and so is its *type*:
        // a symlink is not followed (it could name another tenant's manifest,
        // or a host file whose first line a TOML error would then quote into
        // the log). Either way it must be a small regular file.
        let mut config = match read_tenant_file(&path.join("app.infos"), !multi_tenant)? {
            Some(content) if !content.trim().is_empty() => {
                parse_app_infos(&content, dev_mode, folder_name)?
            }
            _ => AppConfig::default(),
        };

        // Bound the two timeouts: a deploy sleeps `drain_delay` with the old
        // slot still holding its memory, and a stop waits `graceful_timeout`
        // before escalating — a year-long value would pin a slot (and, for a
        // tenant, its share of the host) indefinitely.
        for (value, label) in [
            (&mut config.graceful_timeout, "graceful_timeout"),
            (&mut config.drain_delay, "drain_delay"),
        ] {
            if *value > MAX_APP_TIMEOUT_SECS {
                tracing::warn!(
                    "app.infos for {}: {} = {} is above the {}s ceiling, clamped",
                    folder_name,
                    label,
                    value,
                    MAX_APP_TIMEOUT_SECS
                );
                *value = MAX_APP_TIMEOUT_SECS;
            }
        }

        // Clamp drain_delay to be less than graceful_timeout
        if config.drain_delay >= config.graceful_timeout {
            config.drain_delay = config.graceful_timeout / 2;
        }

        let app_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        // Name fallback: use directory name if not set in app.infos
        if config.name.is_empty() {
            config.name = app_name.clone();
        }

        // Load-time validation, so a bad manifest is skipped (and logged) by
        // discovery instead of reaching container names, log paths, the
        // routing table or the admin UI. `name` and `domain` are hostnames;
        // `health_check` is a URL path the proxy will request.
        validate_hostname_field(&config.name, "name", folder_name)?;
        if !config.domain.is_empty() {
            validate_hostname_field(&config.domain, "domain", folder_name)?;
        }
        if let Some(ref health_check) = config.health_check {
            validate_health_check_path(health_check)?;
        }
        config.auth.validate()?;
        if multi_tenant && config.compress == Some(true) {
            // Opting in spends the operator's CPU, which is the operator's
            // call (`[compression] enabled`); opting out is the tenant's.
            config.compress = None;
        }

        if multi_tenant {
            if config.name != app_name {
                anyhow::bail!(
                    "name {:?} must equal the site directory name {:?} in multi_tenant mode",
                    config.name,
                    app_name
                );
            }
            // An app may answer for its own domain or its `www.` twin only.
            // (`strip_www` already maps `www.<dir>` back to `<dir>`; the empty
            // domain is the bundled `_admin`, which is never routed publicly.)
            if !config.domain.is_empty()
                && config.domain != app_name
                && config.domain != format!("www.{}", app_name)
            {
                anyhow::bail!(
                    "domain {:?} must equal the site directory name {:?} (or www.{}) in \
                     multi_tenant mode",
                    config.domain,
                    app_name,
                    app_name
                );
            }
        }

        // LuaOnBeans auto-detection: if no start_script and luaonbeans.org binary exists
        if config.start_script.is_none() && path.join("luaonbeans.org").exists() {
            config.start_script = Some("./luaonbeans.org -D . -p $PORT -s".to_string());
            config.health_check = Some("/".to_string());
            if config.domain.is_empty() {
                config.domain = app_name.clone();
            }
        }

        // Soli auto-detection: if no start_script and app/models directory exists
        if config.start_script.is_none()
            && path.join("app").exists()
            && path.join("app/models").exists()
        {
            let start_script = if dev_mode {
                "soli serve . --dev --port $PORT --workers $WORKERS".to_string()
            } else {
                "soli serve . --port $PORT --workers $WORKERS".to_string()
            };
            config.start_script = Some(start_script);
            // Gate blue/green promotion on Soli's built-in readiness probe
            // rather than a bare liveness check. `/up` returns 503 until the
            // app's session-store connection is warmed and 200 afterwards, so
            // `wait_for_health` keeps the old slot serving until the new slot
            // can actually complete a session round-trip — instead of switching
            // traffic the moment the HTTP server answers `/` and landing real
            // requests in the cold-connection window (a ~10s stall). Requires
            // a Soli runtime new enough to serve `/up` (every current build).
            config.health_check = Some("/up".to_string());
            if config.domain.is_empty() {
                config.domain = app_name.clone();
            }
        }

        Ok(Self {
            config,
            path: path.to_path_buf(),
            blue: AppInstance {
                name: app_name.clone(),
                slot: "blue".to_string(),
                port: 0,
                pid: None,
                status: InstanceStatus::Stopped,
                last_started: None,
            },
            green: AppInstance {
                name: app_name.clone(),
                slot: "green".to_string(),
                port: 0,
                pid: None,
                status: InstanceStatus::Stopped,
                last_started: None,
            },
            current_slot: "blue".to_string(),
            quarantined: false,
            // Presence is all that counts; a symlink is not followed.
            maintenance: std::fs::symlink_metadata(path.join(MAINTENANCE_FLAG)).is_ok(),
            error_pages: load_site_error_pages(path, folder_name, multi_tenant),
        })
    }
}

/// The file whose presence puts an app in maintenance mode.
pub const MAINTENANCE_FLAG: &str = "maintenance.flag";

/// An app's own error pages, if it has any. A directory that cannot be read
/// costs the app its pages, not its place in the routing table.
fn load_site_error_pages(
    path: &Path,
    label: &str,
    multi_tenant: bool,
) -> Option<Arc<crate::response::error_pages::ErrorPages>> {
    match crate::response::error_pages::ErrorPages::load_for_site(path, !multi_tenant) {
        Ok(Some(pages)) if !pages.is_empty() => Some(Arc::new(pages)),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!("{}: error_pages ignored: {:#}", label, e);
            None
        }
    }
}

#[derive(Clone)]
pub struct AppManager {
    sites_dir: PathBuf,
    port_allocator: Arc<PortManager>,
    apps: Arc<Mutex<HashMap<String, AppInfo>>>,
    config_manager: Arc<dyn super::config::ConfigManagerTrait + Send + Sync>,
    pub deployment_manager: Arc<DeploymentManager>,
    watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    acme_service: Arc<Mutex<Option<Arc<crate::acme::AcmeService>>>>,
    dev_mode: bool,
    /// `[apps] multi_tenant`: treat `app.infos` as untrusted. See
    /// `AppInfo::from_path` for what that changes at load time.
    multi_tenant: bool,
    event_tx: broadcast::Sender<AppEvent>,
    #[allow(dead_code)]
    health_check_path: String,
    health_check_interval_secs: u64,
    circuit_breaker: Option<SharedCircuitBreaker>,
    process_exit_rx:
        Arc<parking_lot::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ProcessExit>>>>,
    last_failover: Arc<parking_lot::Mutex<HashMap<String, std::time::Instant>>>,
    failure_count: Arc<parking_lot::Mutex<HashMap<String, u32>>>,
    /// Consecutive failed health checks per app; see `check_health`.
    health_failures: Arc<parking_lot::Mutex<HashMap<String, u32>>>,
    /// `[apps] health_failure_threshold`.
    health_failure_threshold: u32,
    /// Apps whose start failed and for which automatic remediation (health-check
    /// failover, process-exit failover) is suspended until an explicit deploy.
    quarantined: Arc<parking_lot::Mutex<HashSet<String>>>,
    /// app name -> mtime of its trigger file as of the last poll. The outer
    /// `Option` distinguishes "never polled" (no entry) from "file absent"
    /// (`Some(None)`); the first poll only records a baseline.
    restart_triggers: Arc<parking_lot::Mutex<HashMap<String, Option<SystemTime>>>>,
    restart_trigger_file: String,
    /// Routes served but not supervised here — the cluster migration seam.
    ///
    /// Empty by default, and an empty table changes no behaviour anywhere.
    pub external_routes: Arc<external::ExternalRouteTable>,
    restart_trigger_poll_secs: u64,
    /// `[apps] idle_timeout` from `config.toml`: the sleep threshold for apps
    /// whose `app.infos` does not set one. `0` (the default) disables it.
    default_idle_timeout: u64,
    /// When each app last received a request, keyed by app name: milliseconds
    /// since `epoch`, plus one, so that 0 means "not observed yet" — the
    /// reaper starts its clock on first sight rather than sleeping the app
    /// on the spot. Atomics, so the request path records itself with a
    /// store; the routing table holds the same cells.
    activity: Arc<parking_lot::Mutex<HashMap<String, Arc<AtomicU64>>>>,
    epoch: std::time::Instant,
    /// Apps the reaper stopped for inactivity. A request for one of these is
    /// held while the app is started again, instead of answering 421.
    asleep: Arc<parking_lot::Mutex<HashSet<String>>>,
    /// Extra domain -> app name mappings, managed through the admin API.
    ///
    /// A site directory gives an app exactly one domain, which ties "the URL"
    /// to "the checkout currently behind it". Aliases break that coupling: many
    /// domains can point at one running app, and repointing an alias is an
    /// atomic map swap with no restart — the primitive behind production
    /// aliases, per-branch URLs and instant rollback.
    aliases: Arc<parking_lot::Mutex<HashMap<String, String>>>,
    /// The routing table, rebuilt and swapped whenever something it depends
    /// on changes (apps, slots, processes, aliases) and read lock-free by
    /// every request: one load and one hash lookup.
    routes: Arc<ArcSwap<AppRoutes>>,
    /// Serialises discoveries: see `discover_apps_inner`.
    discover_lock: Arc<Mutex<()>>,
    /// `[apps] port_range_*`, validated at construction.
    port_range: (u16, u16),
    /// The proxy's own listener ports, never handed to an app.
    reserved_ports: Vec<u16>,
}

/// Where the alias table is persisted, alongside `app_state.json` and
/// `ports.lock`. Paths in `run/` are CWD-relative, matching the rest of the
/// runtime state.
const ALIASES_FILE: &str = "./run/aliases.json";

/// The native processes this proxy spawned, with their start times, so a
/// restarted proxy reclaims its own leftovers and nothing else.
const SPAWN_REGISTRY_FILE: &str = "./run/spawned.json";

/// Convert a domain to its `.test` alias by replacing the TLD.
/// e.g. "soli.solisoft.net" → "soli.solisoft.test"
fn dev_domain(domain: &str) -> Option<String> {
    if domain.ends_with(".test") || domain.ends_with(".localhost") {
        return None;
    }
    let dot = domain.rfind('.')?;
    Some(format!("{}.test", &domain[..dot]))
}

/// Check if a domain is eligible for ACME cert issuance
/// (not localhost, not an IP address).
fn is_acme_eligible(domain: &str) -> bool {
    domain != "localhost"
        && !domain.ends_with(".localhost")
        && !domain.ends_with(".test")
        && domain.parse::<std::net::IpAddr>().is_err()
}

/// Check if a folder name is a valid domain (must contain at least one dot, or start with underscore).
fn is_valid_domain(name: &str) -> bool {
    !name.is_empty() && (!name.starts_with('.') && (name.contains('.') || name.starts_with('_')))
}

/// Check an `app.infos` hostname field (`name`, `domain`) against the charset
/// `[A-Za-z0-9._-]`. That is RFC 1123 plus `_`: underscores are not valid in
/// DNS host labels but are common in site directory names (`my_app.test`),
/// were accepted before this check existed, and are harmless everywhere the
/// value is used (container names, log paths, the routing table, the admin
/// UI). A leading `_` is reserved for bundled apps and is only accepted when
/// the site directory itself starts with `_` — otherwise a tenant directory
/// could name itself `_admin` and take over the bundled admin app's entry in
/// the apps map.
fn validate_hostname_field(
    value: &str,
    label: &str,
    folder_name: &str,
) -> Result<(), anyhow::Error> {
    let body = match value.strip_prefix('_') {
        Some(rest) => {
            if !folder_name.starts_with('_') {
                anyhow::bail!(
                    "{} {:?} starts with '_', which is reserved for bundled apps",
                    label,
                    value
                );
            }
            rest
        }
        None => value,
    };
    if body.is_empty()
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!(
            "{} {:?} is not a valid hostname (letters, digits, '.', '-' and '_' only)",
            label,
            value
        );
    }
    Ok(())
}

/// `health_check` is interpolated into the URL the proxy polls and exported to
/// the container as `HEALTH_CHECK`: it must be an absolute URL path made of
/// unreserved characters plus `/ ? = & %`.
fn validate_health_check_path(path: &str) -> Result<(), anyhow::Error> {
    let valid = path.starts_with('/')
        && path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '.' | '_' | '~' | '/' | '?' | '=' | '&' | '%')
        });
    if !valid {
        anyhow::bail!(
            "health_check {:?} must be an absolute URL path (unreserved characters and / ? = & % only)",
            path
        );
    }
    Ok(())
}

/// Get the non-www version of a domain if it starts with www.
/// e.g. "www.solisoft.net" → Some("solisoft.net")
fn strip_www(domain: &str) -> Option<String> {
    if domain.starts_with("www.") && domain.len() > 4 {
        Some(domain[4..].to_string())
    } else {
        None
    }
}

/// How a host came to point at an app. Decides who wins a host two apps
/// could both answer for: declared beats alias beats derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The app's own `domain`.
    Declared,
    /// An admin-managed alias (`set_alias`).
    Alias,
    /// Derived from `domain` by the proxy: its `www.`-stripped apex, or its
    /// `.test` twin in dev mode. Nobody chose it explicitly, so it never
    /// displaces an explicit claim — and in multi_tenant mode, where the
    /// `domain` it derives from is tenant input, it does not displace an
    /// operator's static rule or a cluster-pushed route either.
    Derived,
}

/// Where one host goes, and everything the request path needs about it.
///
/// Routing, Basic Auth, idle tracking and metrics attribution are all read
/// from this one entry. They used to be four separate lookups with four
/// separate rules — routing skipped apps that were not running, the name
/// lookup did not — so a `www.` twin could be served a request while another
/// app's `[auth]` (or none) was enforced on it.
#[derive(Debug)]
pub struct AppRoute {
    pub app: Arc<str>,
    pub claim: Claim,
    /// `http://127.0.0.1:<port>/` of the live slot, or `None` while the app
    /// has no running process (stopped, asleep, failed). Such an app still
    /// owns its hosts — nobody else is routed them — it just cannot serve.
    pub target: Option<Url>,
    pub port: u16,
    pub health_check: Option<String>,
    /// The app's `[auth]`, when it has accounts.
    pub auth: Option<Arc<AppAuth>>,
    /// `compress =` from `app.infos`.
    pub compress: Option<bool>,
    /// `<site>/maintenance.flag` exists.
    pub maintenance: bool,
    /// The app's `error_pages/`.
    pub error_pages: Option<Arc<crate::response::error_pages::ErrorPages>>,
    /// The app's idle clock (see `AppManager::touch`), shared by all of its
    /// hosts and across rebuilds: a request records itself with one store.
    activity: Arc<AtomicU64>,
}

/// A resolved request: where to send it, and — for the proxy's own apps —
/// which app that is and the Basic Auth it requires.
#[derive(Debug, Clone)]
pub struct AppTarget {
    pub target: super::config::Target,
    /// `None` for a cluster-pushed route.
    pub app: Option<Arc<str>>,
    pub auth: Option<Arc<AppAuth>>,
    /// The app's `compress =`; `None` for a cluster-pushed route.
    pub compress: Option<bool>,
}

/// The routing table for every app the proxy manages: host -> entry, plus
/// slot port -> app for attributing a proxied request to its app.
#[derive(Debug, Default)]
pub struct AppRoutes {
    hosts: HashMap<String, Arc<AppRoute>>,
    ports: HashMap<u16, Arc<str>>,
    /// Some app has a `maintenance.flag`: the request path looks hosts up
    /// for maintenance only then.
    any_maintenance: bool,
    /// Some app has error pages: only then is a request's host kept for them.
    any_error_pages: bool,
}

impl AppRoutes {
    pub fn get(&self, host: &str) -> Option<&Arc<AppRoute>> {
        self.hosts.get(host)
    }
}

/// The port of the slot that should take traffic: the current slot, or the
/// other one when the current slot has no process (so a dead `current_slot`
/// does not mean a permanent 421 while the other slot runs). `None` when
/// neither slot has a process.
fn live_port(app: &AppInfo) -> Option<u16> {
    let (current, other) = if app.current_slot == "blue" {
        (&app.blue, &app.green)
    } else {
        (&app.green, &app.blue)
    };
    [current, other]
        .into_iter()
        .find(|instance| instance.pid.is_some() && instance.port > 0)
        .map(|instance| instance.port)
}

/// Build the routing table from the apps map and the alias table.
///
/// Deterministic whatever the maps' iteration order: claims are taken in
/// three passes — declared domains, then aliases, then derived domains — and
/// within a pass apps are visited in name order (aliases in domain order).
/// A host, once claimed, is never overwritten. A clash on a declared domain
/// is logged as an error, since it is a misconfiguration that leaves one app
/// unreachable; a derived clash is routine (`x/` and `www.x/` both map to
/// `x`) and stays at debug.
///
/// Ownership does not depend on whether an app is running: a stopped app
/// keeps its hosts (with no target) instead of releasing them to whichever
/// app derives the same name. Otherwise stopping a site would hand its apex
/// to a `www.` directory owned by someone else.
fn build_routes(
    apps: &HashMap<String, AppInfo>,
    aliases: &HashMap<String, String>,
    dev_mode: bool,
    activity: &mut HashMap<String, Arc<AtomicU64>>,
) -> AppRoutes {
    let mut ordered: Vec<&AppInfo> = apps.values().collect();
    ordered.sort_by(|a, b| a.config.name.cmp(&b.config.name));

    // An entry per claimed host; an app's entries share its idle clock.
    let mut entry = |app: &AppInfo, claim: Claim| AppRoute {
        app: Arc::from(app.config.name.as_str()),
        claim,
        target: live_port(app)
            .and_then(|port| Url::parse(&format!("http://127.0.0.1:{}/", port)).ok()),
        port: live_port(app).unwrap_or(0),
        health_check: app.config.health_check.clone(),
        auth: app
            .config
            .auth
            .is_active()
            .then(|| Arc::new(app.config.auth.clone())),
        compress: app.config.compress,
        maintenance: app.maintenance,
        error_pages: app.error_pages.clone(),
        activity: activity.entry(app.config.name.clone()).or_default().clone(),
    };
    let mut routes = AppRoutes::default();
    let mut claim = |host: String, app: &AppInfo, kind: Claim| {
        if let Some(existing) = routes.hosts.get(&host) {
            if kind == Claim::Declared {
                tracing::error!(
                    "app {} declares domain {}, already claimed by app {}; keeping the first",
                    app.config.name,
                    host,
                    existing.app
                );
            } else {
                tracing::debug!(
                    "{:?} host {} of app {} is already claimed by app {}",
                    kind,
                    host,
                    app.config.name,
                    existing.app
                );
            }
            return;
        }
        routes.hosts.insert(host, Arc::new(entry(app, kind)));
    };

    // The bundled `_admin` app is served only via the authenticated admin
    // listener (which reaches it through `get_app("_admin")` directly). It
    // must never be reachable through the public proxy's Host-based app
    // routing: the admin API strips credentials before forwarding, so
    // `_admin` does no auth of its own, and exposing it here would let any
    // client reach the admin UI/actions unauthenticated with
    // `Host: <admin-domain>`. Same for an alias pointing at it.
    let routable = |app: &AppInfo| app.config.name != "_admin" && !app.config.domain.is_empty();

    for app in ordered.iter().copied().filter(|app| routable(app)) {
        claim(app.config.domain.clone(), app, Claim::Declared);
    }

    // Aliases resolve to whatever their target app is serving right now, so
    // repointing one takes effect on the next request without touching the
    // running processes. After the declared pass, so an alias can never
    // shadow an app's own domain.
    let mut alias_list: Vec<(&String, &String)> = aliases.iter().collect();
    alias_list.sort();
    for (alias, target) in alias_list {
        if let Some(app) = apps.get(target).filter(|app| app.config.name != "_admin") {
            claim(alias.clone(), app, Claim::Alias);
        }
    }

    for app in ordered.iter().copied().filter(|app| routable(app)) {
        if let Some(apex) = strip_www(&app.config.domain) {
            claim(apex, app, Claim::Derived);
        }
        if dev_mode {
            if let Some(dev) = dev_domain(&app.config.domain) {
                claim(dev, app, Claim::Derived);
            }
        }
    }

    routes.any_maintenance = routes.hosts.values().any(|r| r.maintenance);
    routes.any_error_pages = routes.hosts.values().any(|r| r.error_pages.is_some());

    for app in &ordered {
        let name: Arc<str> = Arc::from(app.config.name.as_str());
        for port in [app.blue.port, app.green.port] {
            if port > 0 {
                routes.ports.entry(port).or_insert_with(|| name.clone());
            }
        }
    }

    routes
}

/// The port of a loopback target URL (`http://127.0.0.1:20001/x`), parsed by
/// hand: this runs once per proxied request, to attribute it to an app.
fn loopback_port(target_url: &str) -> Option<u16> {
    let rest = target_url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (host, port) = authority.rsplit_once(':')?;
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
        .then(|| port.parse().ok())
        .flatten()
}

/// Load every site directory under `sites_dir`, in path order.
///
/// Synchronous and lock-free on purpose: discovery runs it on the blocking
/// pool, so a site directory that is slow to read (or built to be) costs a
/// blocking thread, never an async worker or the apps lock.
pub(crate) fn scan_sites(
    sites_dir: &Path,
    dev_mode: bool,
    multi_tenant: bool,
) -> std::io::Result<Vec<(PathBuf, Result<AppInfo, anyhow::Error>)>> {
    // Directory order is filesystem-dependent; sort so that when two
    // directories collide on a name, "first wins" is stable across restarts.
    let mut entries: Vec<PathBuf> = std::fs::read_dir(sites_dir)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();

    let mut out = Vec::new();
    for path in entries {
        // Skip directories starting with '.' (like .claude)
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') {
                continue;
            }
        }
        // `is_dir` follows a symlinked site, which is the common layout.
        if path.is_dir() {
            let result = AppInfo::from_path(&path, dev_mode, multi_tenant);
            out.push((path, result));
        }
    }
    Ok(out)
}

/// Why a port range cannot be used for app slots, if it cannot.
///
/// Below 1024 are the privileged ports (and in practice every system service
/// worth squatting); `reserved` are the proxy's own listeners, which are not
/// bound yet when discovery first allocates at boot — so the allocator's
/// bind probe would happily hand the admin port to an app. The size cap keeps
/// the allocator's linear probe bounded.
pub(crate) fn port_range_problem(start: u16, end: u16, reserved: &[u16]) -> Option<String> {
    if start < 1024 {
        return Some(format!("starts at {start}, below 1024"));
    }
    if end <= start {
        return Some(format!(
            "{start}-{end} holds fewer than the two ports blue/green needs"
        ));
    }
    if u32::from(end - start) + 1 > MAX_PORT_RANGE_SIZE {
        return Some(format!(
            "{start}-{end} spans more than {MAX_PORT_RANGE_SIZE} ports"
        ));
    }
    if let Some(port) = reserved.iter().find(|p| (start..=end).contains(*p)) {
        return Some(format!(
            "{start}-{end} contains port {port}, one of the proxy's own listeners"
        ));
    }
    None
}

/// Largest app port range accepted.
const MAX_PORT_RANGE_SIZE: u32 = 20_000;

/// The ports the proxy itself listens on, from its configuration.
pub(crate) fn proxy_listener_ports(cfg: &crate::config::Config) -> Vec<u16> {
    let port_of = |bind: &str| {
        bind.rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
    };
    [
        port_of(&cfg.server.bind),
        Some(cfg.server.https_port),
        port_of(&cfg.admin.bind),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Defaults for the platform-owned app port range (`[apps] port_range_start`
/// / `port_range_end`), the same values `AppConfig` has always defaulted to.
const DEFAULT_APP_PORT_RANGE: (u16, u16) = (20000, 30000);

impl crate::config::AppsTomlConfig {
    /// The platform's app port range: every app's range in multi_tenant mode,
    /// and the fallback for an app whose own range is unusable otherwise.
    pub fn app_port_range(&self) -> (u16, u16) {
        (
            self.port_range_start.unwrap_or(DEFAULT_APP_PORT_RANGE.0),
            self.port_range_end.unwrap_or(DEFAULT_APP_PORT_RANGE.1),
        )
    }

    /// Consecutive failed health checks before an app is failed over.
    pub fn health_failure_threshold(&self) -> u32 {
        self.health_failure_threshold.unwrap_or(3).max(1)
    }

    /// Whether the proxy's egress variables (`HTTP_PROXY` & co.) reach tenant
    /// containers. Off by default in multi_tenant mode: they are the
    /// operator's, and often carry credentials.
    pub fn tenant_proxy_env(&self) -> bool {
        self.tenant_proxy_env.unwrap_or(false)
    }

    /// Whether a forwarded variable may carry `user:password@` — only with
    /// this explicit second opt-in.
    pub fn tenant_proxy_env_credentials(&self) -> bool {
        self.tenant_proxy_env_credentials.unwrap_or(false)
    }
}

/// Check if a port is currently in use by attempting to connect to it.
async fn is_port_in_use(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    tokio::task::spawn_blocking(move || {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)).is_ok()
    })
    .await
    .unwrap_or(false)
}

/// What one health-check response says about an app.
#[derive(Debug, Clone, PartialEq)]
enum HealthVerdict {
    Healthy,
    /// The app answered, with a 4xx: it is up, its health path is not.
    Misconfigured(u16),
    /// Cannot serve: no answer, or a 5xx.
    Failed(String),
}

fn health_verdict(status: u16) -> HealthVerdict {
    match status {
        200..=299 => HealthVerdict::Healthy,
        400..=499 => HealthVerdict::Misconfigured(status),
        _ => HealthVerdict::Failed(format!("HTTP {}", status)),
    }
}

/// Decide whether a change to a site's trigger file should fire a deploy, and
/// return the mtime to remember for the next poll.
///
/// `baseline` is the entry previously recorded for this app: `None` means the
/// app has never been polled, `Some(&None)` means the file was absent last time.
/// The first poll of an app only records a baseline — otherwise every daemon
/// restart would redeploy every site that already has a trigger file on disk,
/// on top of the auto-start `discover_apps()` already performs.
fn trigger_decision(
    baseline: Option<&Option<SystemTime>>,
    current: Option<SystemTime>,
) -> (bool, Option<SystemTime>) {
    match baseline {
        // First time we look at this app: record, never fire.
        None => (false, current),
        // File appeared, or was touched/rewritten since the last poll.
        Some(previous) => (current.is_some() && *previous != current, current),
    }
}

/// Whether a sites-watcher event (outside dev mode) can change what
/// discovery finds. `relative` is the path under the sites directory.
///
/// Depth 1 is a site directory: it matters when it appears, disappears or
/// is renamed — not when its metadata changes, which a tenant can do at will.
/// Depth 2 matters only for `app.infos` itself. (The restart trigger file is
/// polled, not watched; see `check_restart_triggers`.)
fn watch_event_is_relevant(relative: &Path, kind: &notify::EventKind) -> bool {
    use notify::event::ModifyKind;
    use notify::EventKind;
    match relative.components().count() {
        1 => matches!(
            kind,
            EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
        ),
        2 => relative
            .file_name()
            .is_some_and(|name| name == "app.infos" || name == MAINTENANCE_FLAG),
        _ => false,
    }
}

/// Make the per-site watches match `sites`: watch new site directories
/// (non-recursively — inotify follows a symlinked site to its target),
/// unwatch removed ones. Best effort: a site that cannot be watched is still
/// found by the next rediscovery.
fn sync_site_watches(
    watcher: &mut RecommendedWatcher,
    watched: &mut HashSet<PathBuf>,
    sites: &[PathBuf],
) {
    let wanted: HashSet<&PathBuf> = sites.iter().collect();
    watched.retain(|path| {
        if wanted.contains(path) {
            return true;
        }
        let _ = watcher.unwatch(path);
        false
    });
    for path in sites {
        if watched.contains(path) {
            continue;
        }
        match watcher.watch(path, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched.insert(path.clone());
            }
            Err(e) => tracing::warn!("Cannot watch {}: {}", path.display(), e),
        }
    }
}

/// Extract app names from changed file paths, filtering out irrelevant directories.
/// Each path is expected to be under `sites_dir/<app_name>/...`.
fn affected_app_names(
    sites_dir: &Path,
    paths: &HashSet<PathBuf>,
    trigger_file: &str,
) -> HashSet<String> {
    const IGNORED_SEGMENTS: &[&str] = &["node_modules", ".git", "tmp", "target"];

    let mut names = HashSet::new();
    for path in paths {
        let relative = match path.strip_prefix(sites_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip paths in irrelevant directories
        let skip = relative.components().any(|c| {
            if let std::path::Component::Normal(s) = c {
                IGNORED_SEGMENTS
                    .iter()
                    .any(|ignored| s.to_str() == Some(*ignored))
            } else {
                false
            }
        });
        if skip {
            continue;
        }

        // Skip top-level files that have their own handling: `app.infos` is
        // picked up by discover_apps, and the trigger file is polled separately
        // (sites that are real directories, like _admin, would otherwise be
        // restarted twice for one touch).
        if relative.components().count() == 2 {
            if let Some(filename) = relative.file_name() {
                if filename == "app.infos"
                    || filename == MAINTENANCE_FLAG
                    || filename == trigger_file
                {
                    continue;
                }
            }
        }

        // First component is the app directory name
        if let Some(std::path::Component::Normal(app_dir)) = relative.components().next() {
            if let Some(name) = app_dir.to_str() {
                names.insert(name.to_string());
            }
        }
    }
    names
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum AppEvent {
    StatusChanged {
        app_name: String,
        slot: String,
        status: String,
    },
    Deployed {
        app_name: String,
        slot: String,
    },
    Stopped {
        app_name: String,
        slot: String,
    },
    Restarted {
        app_name: String,
    },
}

/// The domain a static rule would shadow an app on, if it would shadow one.
///
/// Only a whole-domain rule can: it claims every path, so an app-managed
/// domain that also carries `host -> http://…` never reaches the AppManager
/// and a blue-green switch moves nothing. A `host/path/* -> …` carve-out
/// claims one prefix and is *meant* to beat the app there — `override_with_app`
/// in `server/mod.rs` defers to the AppManager for domain rules precisely so
/// that a DomainPath still wins. Returning `Some` for one had `sync_routes`
/// delete it and rewrite proxy.conf, on every restart and every traffic
/// switch, taking an operator's hand-written route with it.
fn shadowing_domain(matcher: &super::config::RuleMatcher) -> Option<&str> {
    match matcher {
        super::config::RuleMatcher::Domain(d) => Some(d.as_str()),
        _ => None,
    }
}

impl AppManager {
    pub fn new(
        sites_dir: &str,
        port_allocator: Arc<PortManager>,
        config_manager: Arc<dyn super::config::ConfigManagerTrait + Send + Sync>,
        dev_mode: bool,
    ) -> Result<Self, anyhow::Error> {
        Self::with_health_check(sites_dir, port_allocator, config_manager, dev_mode, "/", 30)
    }

    pub fn with_health_check(
        sites_dir: &str,
        port_allocator: Arc<PortManager>,
        config_manager: Arc<dyn super::config::ConfigManagerTrait + Send + Sync>,
        dev_mode: bool,
        health_check_path: &str,
        health_check_interval_secs: u64,
    ) -> Result<Self, anyhow::Error> {
        let sites_path = PathBuf::from(sites_dir);
        if !sites_path.exists() {
            std::fs::create_dir_all(&sites_path)?;
        }

        let cfg = config_manager.get_config();
        let (process_exit_tx, process_exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let multi_tenant = cfg.apps.multi_tenant();
        if multi_tenant {
            tracing::info!(
                "multi_tenant mode: apps must declare a docker_image and are started with \
                 platform-imposed container hardening"
            );
        }
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                dev_mode,
                cfg.apps.default_user.clone(),
                cfg.apps.default_group.clone(),
                process_exit_tx,
            )
            .with_tenant_isolation(multi_tenant, cfg.apps.mandatory_docker_args())
            .with_tenant_env(
                cfg.apps.tenant_proxy_env(),
                cfg.apps.tenant_proxy_env_credentials(),
            )
            .with_spawn_registry(PathBuf::from(SPAWN_REGISTRY_FILE)),
        );
        let (event_tx, _) = broadcast::channel(32);

        let reserved_ports = proxy_listener_ports(&cfg);
        let port_range = {
            let (start, end) = cfg.apps.app_port_range();
            match port_range_problem(start, end, &reserved_ports) {
                None => (start, end),
                Some(problem) => {
                    tracing::error!(
                        "[apps] port range unusable ({}); using {}-{}",
                        problem,
                        DEFAULT_APP_PORT_RANGE.0,
                        DEFAULT_APP_PORT_RANGE.1
                    );
                    DEFAULT_APP_PORT_RANGE
                }
            }
        };

        let manager = Self {
            sites_dir: sites_path,
            port_allocator,
            apps: Arc::new(Mutex::new(HashMap::new())),
            config_manager,
            deployment_manager,
            watcher: Arc::new(Mutex::new(None)),
            acme_service: Arc::new(Mutex::new(None)),
            dev_mode,
            multi_tenant,
            event_tx,
            health_check_path: health_check_path.to_string(),
            health_check_interval_secs,
            circuit_breaker: None,
            process_exit_rx: Arc::new(parking_lot::Mutex::new(Some(process_exit_rx))),
            last_failover: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            failure_count: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            health_failures: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            health_failure_threshold: cfg.apps.health_failure_threshold(),
            quarantined: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            restart_triggers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            restart_trigger_file: cfg.apps.restart_trigger_file(),
            restart_trigger_poll_secs: cfg.apps.restart_trigger_poll_secs(),
            default_idle_timeout: cfg.apps.idle_timeout(),
            activity: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            epoch: std::time::Instant::now(),
            asleep: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            aliases: Arc::new(parking_lot::Mutex::new(read_aliases_file())),
            routes: Arc::new(ArcSwap::from_pointee(AppRoutes::default())),
            external_routes: Arc::new(external::ExternalRouteTable::default()),
            discover_lock: Arc::new(Mutex::new(())),
            port_range,
            reserved_ports,
        };

        Ok(manager)
    }

    /// The port range an app's slots are allocated from.
    ///
    /// Multi-tenant: always the platform's. A tenant choosing its own range
    /// could aim it at 5432, the admin port, or a band another tenant's slots
    /// live in. Single-tenant: the app's own, when it is usable.
    fn port_range_for(&self, config: &AppConfig) -> (u16, u16) {
        let requested = (config.port_range_start, config.port_range_end);
        if self.multi_tenant {
            let default = AppConfig::default();
            let declared = requested != (default.port_range_start, default.port_range_end);
            if declared && requested != self.port_range {
                tracing::warn!(
                    "app.infos for {}: port_range_start/port_range_end are ignored in \
                     multi_tenant mode; using the platform range {}-{}",
                    config.name,
                    self.port_range.0,
                    self.port_range.1
                );
            }
            return self.port_range;
        }
        match port_range_problem(requested.0, requested.1, &self.reserved_ports) {
            None => requested,
            Some(problem) => {
                tracing::error!(
                    "app.infos for {}: port range unusable ({}); using {}-{}",
                    config.name,
                    problem,
                    self.port_range.0,
                    self.port_range.1
                );
                self.port_range
            }
        }
    }

    /// Clean up after an app whose site directory is gone.
    ///
    /// Multi-tenant docker apps are stopped and their private network
    /// removed: the tenant was deprovisioned, and an untrusted container that
    /// outlives its site is still running someone's code on the host. Other
    /// apps are left running as before — dropping them from the map is all
    /// discovery ever did — so an operator who moves a directory does not
    /// take a site down by accident.
    fn retire_removed_app(&self, app: AppInfo) {
        if !(self.multi_tenant && app.config.docker_image.is_some()) {
            return;
        }
        let dm = self.deployment_manager.clone();
        tokio::spawn(async move {
            for slot in ["blue", "green"] {
                if let Err(e) = dm.stop_instance(&app, slot).await {
                    tracing::warn!("Failed to stop {} slot {}: {}", app.config.name, slot, e);
                }
            }
            dm.remove_app_network(&app.config.name).await;
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AppEvent> {
        self.event_tx.subscribe()
    }

    fn emit_event(&self, event: AppEvent) {
        let _ = self.event_tx.send(event);
    }

    pub fn set_circuit_breaker(&mut self, cb: SharedCircuitBreaker) {
        self.circuit_breaker = Some(cb);
    }

    pub async fn set_acme_service(&self, service: Arc<crate::acme::AcmeService>) {
        *self.acme_service.lock().await = Some(service);
    }

    /// The routing table: one entry per host, see [`AppRoute`].
    pub fn routes(&self) -> Arc<AppRoutes> {
        self.routes.load_full()
    }

    /// Whether some app has a `maintenance.flag`. One atomic load.
    pub fn any_maintenance_flag(&self) -> bool {
        self.routes.load().any_maintenance
    }

    /// Whether some app has error pages. One atomic load.
    pub fn any_error_pages(&self) -> bool {
        self.routes.load().any_error_pages
    }

    /// Rebuild the routing table from `apps` and publish it.
    ///
    /// Called with the apps lock held, after every change routing depends on
    /// — discovery, a slot's process starting or going away, a traffic
    /// switch, an alias — so tables are published in lock order and no
    /// reader is handed an older table after a newer one. The request path
    /// never builds anything: it used to lock the apps map up to five times
    /// per request and rebuild a domain table on each, under the one mutex
    /// every deploy and health check also takes.
    fn publish_routes(&self, apps: &HashMap<String, AppInfo>) {
        let aliases = self.aliases.lock();
        let mut activity = self.activity.lock();
        activity.retain(|name, _| apps.contains_key(name));
        let routes = build_routes(apps, &aliases, self.dev_mode, &mut activity);
        self.routes.store(Arc::new(routes));
    }

    /// Milliseconds since `epoch`, plus one (0 is "never").
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64 + 1
    }

    /// `app_name`'s idle clock.
    fn activity_cell(&self, app_name: &str) -> Arc<AtomicU64> {
        self.activity
            .lock()
            .entry(app_name.to_string())
            .or_default()
            .clone()
    }

    /// Domain -> (port, health_check) for every host currently served by a
    /// running app.
    pub async fn get_running_app_domains(&self) -> HashMap<String, (u16, Option<String>)> {
        self.routes()
            .hosts
            .iter()
            .filter(|(_, route)| route.target.is_some())
            .map(|(host, route)| (host.clone(), (route.port, route.health_check.clone())))
            .collect()
    }

    /// Current alias table (domain -> app name).
    pub async fn get_aliases(&self) -> HashMap<String, String> {
        self.aliases.lock().clone()
    }

    /// Point `domain` at `app`, replacing any existing alias for that domain.
    ///
    /// Rejects a domain that is already an app's own site domain: those are
    /// owned by the sites directory, and letting an alias override one would
    /// make routing depend on map iteration order.
    pub async fn set_alias(&self, domain: &str, app: &str) -> Result<(), anyhow::Error> {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() || !domain.contains('.') {
            anyhow::bail!("Invalid alias domain: {}", domain);
        }
        if app == "_admin" {
            anyhow::bail!("Refusing to alias the bundled admin app");
        }

        {
            let apps = self.apps.lock().await;
            if !apps.contains_key(app) {
                anyhow::bail!("App not found: {}", app);
            }
            if let Some(owner) = apps.values().find(|info| info.config.domain == domain) {
                anyhow::bail!(
                    "{} is already the site domain of app {}",
                    domain,
                    owner.config.name
                );
            }
            self.aliases.lock().insert(domain.clone(), app.to_string());
            self.publish_routes(&apps);
        }

        self.persist_aliases().await;
        tracing::info!("Alias {} -> {}", domain, app);

        // Register the alias for a certificate and drop any static rule that
        // would now shadow it.
        self.sync_routes().await;
        Ok(())
    }

    /// Remove an alias. Returns whether it existed.
    pub async fn remove_alias(&self, domain: &str) -> bool {
        let domain = domain.trim().to_lowercase();
        let removed = {
            let apps = self.apps.lock().await;
            let removed = self.aliases.lock().remove(&domain).is_some();
            if removed {
                self.publish_routes(&apps);
            }
            removed
        };
        if removed {
            self.persist_aliases().await;
            tracing::info!("Removed alias {}", domain);
        }
        removed
    }

    async fn persist_aliases(&self) {
        let state = {
            let aliases = self.aliases.lock();
            serde_json::Value::Object(
                aliases
                    .iter()
                    .map(|(domain, app)| (domain.clone(), serde_json::Value::String(app.clone())))
                    .collect(),
            )
        };
        let path = PathBuf::from(ALIASES_FILE);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&state) {
            Ok(content) => {
                if let Err(e) = crate::config::write_atomic(&path, content.as_bytes()) {
                    tracing::error!("Failed to write {}: {}", ALIASES_FILE, e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize aliases: {}", e),
        }
    }

    pub async fn resolve_app_target(&self, host: &str) -> Option<super::config::Target> {
        self.resolve_app_target_with(host, &|_| true).await
    }

    /// [`Self::resolve_app_request`], for callers that only need the target.
    pub async fn resolve_app_target_with(
        &self,
        host: &str,
        is_available: &(dyn Fn(&str) -> bool + Sync),
    ) -> Option<super::config::Target> {
        self.resolve_app_request(host, is_available)
            .await
            .map(|resolved| resolved.target)
    }

    /// Resolve a request for `host`: where it goes, which app that is, and
    /// the Basic Auth to enforce — all from one routing entry, so the app
    /// whose credentials are checked is always the app that is served.
    ///
    /// Records the request for scale to zero, and wakes a sleeping app (the
    /// request is held until it is healthy) rather than answering 421.
    /// Cluster-pushed routes come back with no app, and with the `auth` the
    /// pusher sent for that domain (see [`Self::auth_for_host`]).
    pub async fn resolve_app_request(
        &self,
        host: &str,
        is_available: &(dyn Fn(&str) -> bool + Sync),
    ) -> Option<AppTarget> {
        let mut route = self.routes().get(host).cloned();
        if let Some(ref r) = route {
            r.activity.store(self.now_ms(), Ordering::Relaxed);
            if r.target.is_none() && self.is_asleep(&r.app) {
                match self.wake(&r.app).await {
                    // Woken and healthy: this request is the one that woke
                    // it, and it should be served, not told 421.
                    Ok(()) => route = self.routes().get(host).cloned(),
                    Err(e) => tracing::warn!("Could not wake {} for {}: {}", r.app, host, e),
                }
            }
        }
        if let Some(route) = route {
            // A derived claim is the weakest there is; in multi_tenant mode it
            // is tenant input and yields to a route the cluster pushed.
            let yields = self.multi_tenant
                && route.claim == Claim::Derived
                && self.external_routes.serves(host);
            if let (Some(url), false) = (&route.target, yields) {
                return Some(AppTarget {
                    target: super::config::Target {
                        url: url.clone(),
                        weight: 100,
                    },
                    app: Some(route.app.clone()),
                    auth: route.auth.clone(),
                    compress: route.compress,
                });
            }
        }
        // Then routes pushed from the cluster. **After** the proxy's own apps,
        // never before: during a migration a domain may briefly exist on both
        // sides, and the node that actually holds the process has to win.
        // Preferring the pushed table would hand traffic to a workload that may
        // not have started yet.
        self.external_routes
            .pick(host, is_available)
            .map(|target| AppTarget {
                target,
                app: None,
                // A pushed target is a raw workload port: nothing in front of
                // it enforces the app's `[auth]` but this proxy.
                auth: self.external_routes.auth(host).map(Arc::new),
                compress: None,
            })
    }

    /// Whether a whole-domain static rule for `host` should step aside for
    /// the app manager (`override_with_app` in the server).
    ///
    /// Any claim does in single-tenant mode, where the operator wrote both
    /// the rule and the manifest. In multi_tenant mode a derived claim does
    /// not: `www.example.com/` deriving `example.com` would otherwise take
    /// the operator's own rule for the apex — and whatever `@auth` it had.
    pub async fn overrides_domain_rule(&self, host: &str) -> bool {
        self.routes()
            .get(host)
            .is_some_and(|route| !(self.multi_tenant && route.claim == Claim::Derived))
    }

    /// The app a proxied request went to, from its target URL's port: how a
    /// request is attributed to an app for per-app metrics, including one
    /// that reached an app's port through a static rule.
    pub async fn app_for_target_url(&self, target_url: &str) -> Option<Arc<str>> {
        let port = loopback_port(target_url)?;
        self.routes().ports.get(&port).cloned()
    }

    /// Every domain this proxy will answer for — its own apps plus pushed ones.
    ///
    /// Used where the *set* of domains matters rather than where each one
    /// points: ACME registration and stale-static-rule pruning. Kept separate
    /// from `get_running_app_domains`, whose value type is a local port and
    /// means nothing for a workload on another machine.
    pub async fn all_routable_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self.get_running_app_domains().await.into_keys().collect();
        // A sleeping app has no process and so no running domain, but it is
        // still ours: its certificate must stay registered and its static
        // rules pruned, or the first request after a nap would find nothing to
        // wake.
        let asleep = self.asleep.lock().clone();
        if !asleep.is_empty() {
            let apps = self.apps.lock().await;
            for name in asleep {
                if let Some(app) = apps.get(&name) {
                    domains.extend(self.domains_of(&app.config));
                }
            }
        }
        domains.extend(self.external_routes.domains());
        domains.sort();
        domains.dedup();
        domains
    }

    /// Basic Auth configured for the app serving `host`, if any.
    ///
    /// `None` — the common case — means the request needs no credential check
    /// at all, so a request for an unprotected app never clones anything.
    ///
    /// Only an app that is actually serving `host` answers for its own
    /// `[auth]`: one that owns the host but is not running has no request to
    /// protect — and the request then goes to a cluster-pushed route, if there
    /// is one, whose auth applies instead.
    ///
    /// ⚠️ **A cluster-pushed domain is enforced here too, or nowhere.** Its
    /// target is the workload's raw port on another node — no proxy runs in
    /// front of it there — so the `[auth]` the pusher sends along with the
    /// route (`PUT /api/v1/routing-table`, `auth`) is checked by this proxy.
    /// A pushed domain without one is served open. A local app wins over a
    /// pushed route for the same host, as it does for routing.
    pub async fn auth_for_host(&self, host: &str) -> Option<Arc<AppAuth>> {
        let routes = self.routes();
        if let Some(route) = routes.get(host) {
            if route.target.is_some() {
                return route.auth.clone();
            }
        }
        self.external_routes.auth(host).map(Arc::new)
    }

    /// The app that owns `host` — by its declared domain, an alias, or a
    /// derived domain, whether or not it is running. Ties are settled the way
    /// [`build_routes`] settles them, so this is always the app that would
    /// serve the host.
    pub async fn app_name_for_host(&self, host: &str) -> Option<String> {
        self.routes().get(host).map(|route| route.app.to_string())
    }

    /// Trigger a failover for the given app in a background task.
    /// Used by the request handler as a safety net when a backend connection fails.
    pub fn trigger_async_failover(&self, app_name: String) {
        let manager = self.clone();
        tokio::spawn(async move {
            // Skip if a deploy is already in progress
            if manager.deployment_manager.is_deploying(&app_name) {
                tracing::debug!(
                    "Skipping request-triggered failover for {} — deploy already in progress",
                    app_name
                );
                return;
            }
            if manager.is_quarantined(&app_name) {
                tracing::debug!(
                    "Skipping request-triggered failover for {} — app is quarantined",
                    app_name
                );
                return;
            }
            tracing::warn!(
                "Request-triggered failover for {} (backend connection failed)",
                app_name
            );
            if let Err(e) = manager.failover(&app_name).await {
                tracing::error!("Request-triggered failover failed for {}: {}", app_name, e);
            }
        });
    }

    pub async fn discover_apps(&self) -> Result<(), anyhow::Error> {
        self.discover_apps_inner(true).await
    }

    /// Discover apps without auto-starting them. Used by the TUI to populate
    /// the app list without interfering with an already-running daemon.
    pub async fn discover_apps_readonly(&self) -> Result<(), anyhow::Error> {
        self.discover_apps_inner(false).await
    }

    async fn discover_apps_inner(&self, auto_start: bool) -> Result<(), anyhow::Error> {
        // One discovery at a time. The phases below release the apps lock
        // between them, so two overlapping scans could otherwise both take an
        // app for new and both queue its auto-start.
        let _discovering = self.discover_lock.lock().await;
        tracing::info!("Discovering apps in {}", self.sites_dir.display());

        // Phase 1 — the filesystem, on the blocking pool and under no lock.
        // Every `app.infos` read and parse happens here: this used to run on
        // an async worker while holding the lock every proxied request takes,
        // so one slow (or hostile) site directory stalled all routing.
        let sites_dir = self.sites_dir.clone();
        let (dev_mode, multi_tenant) = (self.dev_mode, self.multi_tenant);
        let scanned =
            tokio::task::spawn_blocking(move || scan_sites(&sites_dir, dev_mode, multi_tenant))
                .await
                .map_err(|e| anyhow::anyhow!("site scan failed: {}", e))??;

        let mut seen_names: HashSet<String> = HashSet::new();
        let mut loaded: Vec<AppInfo> = Vec::new();
        // In multi_tenant mode an `[auth] forward` URL is tenant input the
        // proxy will fetch: only the operator's `[forward_auth] allowed_urls`.
        let forward_auth_settings =
            multi_tenant.then(|| self.config_manager.get_config().forward_auth.clone());
        for (path, result) in scanned {
            let result = result.and_then(|app_info| {
                if let (Some(settings), Some(forward)) =
                    (&forward_auth_settings, &app_info.config.auth.forward)
                {
                    settings.check_tenant_url(forward.url())?;
                }
                Ok(app_info)
            });
            match result {
                Ok(app_info) => {
                    let name = app_info.config.name.clone();
                    // Two directories resolving to one name would otherwise
                    // share an apps-map entry: the later one inherits the
                    // earlier one's ports and PIDs while replacing its path
                    // and start command. Keep the first, never overwrite.
                    if !seen_names.insert(name.clone()) {
                        tracing::error!(
                            "Skipping {}: app name {:?} is already taken by another site \
                             directory in this scan",
                            path.display(),
                            name
                        );
                        continue;
                    }
                    loaded.push(app_info);
                }
                Err(e) => {
                    tracing::warn!("Failed to load app from {}: {:#}", path.display(), e);
                }
            }
        }

        // Phase 2 — ports for the apps not in the map yet, again without the
        // apps lock: allocation probes the OS and persists `ports.lock`.
        let known: HashSet<String> = {
            let apps = self.apps.lock().await;
            loaded
                .iter()
                .filter(|app| apps.contains_key(&app.config.name))
                .map(|app| app.config.name.clone())
                .collect()
        };
        for app_info in loaded
            .iter_mut()
            .filter(|app| !known.contains(&app.config.name))
        {
            let (start, end) = self.port_range_for(&app_info.config);
            for slot in ["blue", "green"] {
                match self
                    .port_allocator
                    .allocate_with_range(&app_info.config.name, slot, start, end)
                    .await
                {
                    Ok(port) if slot == "blue" => app_info.blue.port = port,
                    Ok(port) => app_info.green.port = port,
                    Err(e) => tracing::error!(
                        "Failed to allocate {} port for {}: {}",
                        slot,
                        app_info.config.name,
                        e
                    ),
                }
            }
        }

        // Phase 3 — apply, under a lock held only for map updates.
        let mut apps_to_start: Vec<String> = Vec::new();
        let removed: Vec<AppInfo> = {
            let mut apps = self.apps.lock().await;
            for mut app_info in loaded {
                let name = app_info.config.name.clone();
                if let Some(existing) = apps.get(&name) {
                    // Preserve runtime state from existing entry
                    app_info.blue.port = existing.blue.port;
                    app_info.blue.pid = existing.blue.pid;
                    app_info.blue.status = existing.blue.status.clone();
                    app_info.blue.last_started = existing.blue.last_started.clone();
                    app_info.green.port = existing.green.port;
                    app_info.green.pid = existing.green.pid;
                    app_info.green.status = existing.green.status.clone();
                    app_info.green.last_started = existing.green.last_started.clone();
                    app_info.current_slot = existing.current_slot.clone();
                    tracing::debug!("Refreshed config for app: {}", name);
                } else {
                    tracing::info!("Discovered new app: {}", name);
                    if app_info.config.start_script.is_some()
                        && !self.deployment_manager.is_deploying(&name)
                    {
                        apps_to_start.push(name.clone());
                    }
                }
                apps.insert(name, app_info);
            }

            // Remove apps that no longer exist on disk
            let gone: Vec<String> = apps
                .keys()
                .filter(|name| !seen_names.contains(*name))
                .cloned()
                .collect();
            let removed = gone.iter().filter_map(|name| apps.remove(name)).collect();
            self.publish_routes(&apps);
            removed
        };
        for app in removed {
            tracing::info!("App {} no longer exists on disk", app.config.name);
            self.retire_removed_app(app);
        }

        // Before anything is started: take over what a previous proxy left
        // running. Done here, ahead of the listeners, so an adopted app is in
        // the routing table for the very first request after a restart.
        if auto_start && !apps_to_start.is_empty() {
            let adopted = self.adopt_running(&apps_to_start).await;
            apps_to_start.retain(|name| !adopted.contains(name));
        }

        // Auto-start discovered apps in parallel (locks are per-app) and
        // return WITHOUT awaiting the deploy task. The caller (main.rs) then
        // proceeds to bind the HTTP/HTTPS listeners immediately, so a single
        // broken app that hits its 30s wait_for_health timeout cannot hold
        // every other app's domain offline.
        //
        // Each app becomes reachable through the proxy as soon as its own
        // deploy finishes; failing apps retry/timeout in the background.
        // `sync_routes` runs inside the background task so stale static
        // rules and `.test`-domain TLS SANs are refreshed once all apps
        // settle, without blocking startup.
        if auto_start {
            let manager = self.clone();
            tokio::spawn(async move {
                let mut handles = Vec::new();
                for app_name in apps_to_start {
                    let mgr = manager.clone();
                    handles.push(tokio::spawn(async move {
                        // Reclaim both slots' ports from a previous daemon's
                        // processes. Only processes this proxy recorded
                        // spawning are killed: a port can be held by anything
                        // (a database, another service, a squatter), and
                        // "listens on my port" is not "is mine".
                        if let Some(app) = mgr.get_app(&app_name).await {
                            for (slot_name, port) in
                                [("blue", app.blue.port), ("green", app.green.port)]
                            {
                                if is_port_in_use(port).await {
                                    mgr.deployment_manager
                                        .reclaim_port(&app, slot_name, port)
                                        .await;
                                }
                            }
                        }
                        tracing::info!("Auto-starting app: {}", app_name);
                        if let Err(e) = mgr.deploy(&app_name, "blue").await {
                            tracing::error!("Failed to auto-start {}: {:#}", app_name, e);
                        }
                    }));
                }
                for handle in handles {
                    let _ = handle.await;
                }
                manager.sync_routes().await;
            });
        }
        Ok(())
    }

    /// Adopt the instances a previous proxy left running for `names`, and
    /// return the apps adopted. See [`Self::try_adopt`] for what qualifies.
    async fn adopt_running(&self, names: &[String]) -> HashSet<String> {
        use futures::StreamExt;

        // The slot each app was last promoted to. Discovery defaults every
        // app to blue; this is what says which slot was serving.
        let persisted = read_app_state_file().unwrap_or_default();
        let candidates: Vec<(AppInfo, String)> = {
            let apps = self.apps.lock().await;
            names
                .iter()
                .filter_map(|name| apps.get(name))
                .map(|app| {
                    let slot = persisted
                        .get(&app.config.name)
                        .and_then(|v| v.as_str())
                        .filter(|s| matches!(*s, "blue" | "green"))
                        .unwrap_or(app.current_slot.as_str())
                        .to_string();
                    (app.clone(), slot)
                })
                .collect()
        };
        // Bounded: each check is a `docker inspect` or a port lookup plus a
        // health probe, and a host can have hundreds of sites.
        let outcomes: Vec<(AppInfo, Option<(String, u32)>)> =
            futures::stream::iter(candidates.into_iter().map(|(app, slot)| {
                let manager = self.clone();
                async move {
                    let outcome = manager.try_adopt(&app, &slot).await;
                    (app, outcome)
                }
            }))
            .buffer_unordered(16)
            .collect()
            .await;

        let adopted: Vec<(AppInfo, String, u32)> = outcomes
            .into_iter()
            .filter_map(|(app, outcome)| outcome.map(|(slot, pid)| (app, slot, pid)))
            .collect();
        if adopted.is_empty() {
            return HashSet::new();
        }
        {
            let mut apps = self.apps.lock().await;
            for (app, slot, pid) in &adopted {
                if let Some(entry) = apps.get_mut(&app.config.name) {
                    let instance = if slot == "blue" {
                        &mut entry.blue
                    } else {
                        &mut entry.green
                    };
                    instance.pid = Some(*pid);
                    instance.status = InstanceStatus::Running;
                    entry.current_slot = slot.clone();
                }
            }
            write_app_state_file(&apps);
            self.publish_routes(&apps);
        }
        let mut names = HashSet::new();
        for (app, slot, pid) in adopted {
            let name = app.config.name.clone();
            self.deployment_manager.watch_adopted(&app, &slot, pid);
            self.touch(&name);
            self.emit_event(AppEvent::StatusChanged {
                app_name: name.clone(),
                slot,
                status: "running".to_string(),
            });
            names.insert(name);
        }
        tracing::info!(
            "Adopted {} app(s) left running by the previous proxy",
            names.len()
        );
        names
    }

    /// Decide whether `app` can be taken over as it runs, trying the slot it
    /// was last promoted to (`preferred`) first. Returns the slot and PID
    /// adopted, after stopping whatever else of ours runs for the app.
    ///
    /// An instance is adopted only when [`DeploymentManager::verify_slot`]
    /// proves it is this proxy's, launched exactly as it would be now, *and*
    /// it answers its health check (a 2xx, or a 4xx — the app is up and only
    /// the path is wrong, as the health monitor reads it). Otherwise:
    ///
    /// * ours but stale or unhealthy — stopped, and the app starts afresh;
    /// * ours in the other slot (a deploy interrupted by the restart) —
    ///   stopped;
    /// * not provably ours — left alone, not adopted; the fresh start then
    ///   meets it as it always did (and refuses to kill it).
    async fn try_adopt(&self, app: &AppInfo, preferred: &str) -> Option<(String, u32)> {
        let dm = &self.deployment_manager;
        let name = &app.config.name;
        let other = if preferred == "blue" { "green" } else { "blue" };
        let mut adopted: Option<(String, u32)> = None;
        for slot in [preferred, other] {
            match dm.verify_slot(app, slot).await {
                SlotOwnership::Absent => {}
                SlotOwnership::Ours { pid } if adopted.is_none() => {
                    match self.probe_adoptable(app, slot).await {
                        Ok(()) => {
                            tracing::info!(
                                "Adopting {} slot {} (PID {}), left running by the previous proxy",
                                name,
                                slot,
                                pid
                            );
                            adopted = Some((slot.to_string(), pid));
                        }
                        Err(reason) => {
                            tracing::warn!(
                                "Not adopting {} slot {} (PID {}): health check {}; stopping it \
                                 and starting afresh",
                                name,
                                slot,
                                pid,
                                reason
                            );
                            dm.terminate(app, slot, pid).await;
                        }
                    }
                }
                SlotOwnership::Ours { pid } => {
                    tracing::info!(
                        "Stopping {} slot {} (PID {}): a deploy the restart interrupted",
                        name,
                        slot,
                        pid
                    );
                    dm.terminate(app, slot, pid).await;
                }
                SlotOwnership::Stale { pid, reason } => {
                    tracing::warn!(
                        "Not adopting {} slot {}: {}; stopping it",
                        name,
                        slot,
                        reason
                    );
                    match pid {
                        Some(pid) => dm.terminate(app, slot, pid).await,
                        None => {
                            let _ = dm.stop_instance(app, slot).await;
                        }
                    }
                }
                SlotOwnership::Unverifiable(reason) => tracing::warn!(
                    "Not adopting {} slot {}: {}; leaving it alone",
                    name,
                    slot,
                    reason
                ),
            }
        }
        adopted
    }

    /// One health check for adoption: three tries, half a second apart, so a
    /// GC pause does not cost an app its restart-free takeover.
    async fn probe_adoptable(&self, app: &AppInfo, slot: &str) -> Result<(), String> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        let path = app.config.health_check.as_deref().unwrap_or("/health");
        let url = format!("http://127.0.0.1:{}{}", port, path);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .map_err(|e| e.to_string())?;
        let mut last = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            match client.get(&url).send().await {
                Ok(resp) => match health_verdict(resp.status().as_u16()) {
                    HealthVerdict::Healthy | HealthVerdict::Misconfigured(_) => return Ok(()),
                    HealthVerdict::Failed(reason) => last = reason,
                },
                Err(e) => last = e.to_string(),
            }
        }
        Err(format!("on {} failed: {}", url, last))
    }

    /// Names of the site directories under `sites_dir` — the domains the
    /// operator has provisioned, as opposed to whatever each `app.infos`
    /// declares.
    fn site_directory_names(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.sites_dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .collect()
    }

    /// Synchronize proxy routes with discovered apps.
    ///
    /// Removes stale static rules from proxy.conf for domains now managed by
    /// the AppManager (which handles blue-green routing dynamically).
    async fn sync_routes(&self) {
        // The *set* of managed domains, which now includes ones the cluster
        // serves. A static rule left in place for a cluster-managed domain
        // would shadow the pushed route, and the symptom — one domain still
        // reaching the old backend after a migration — is the hardest kind to
        // spot because everything else works.
        let managed: std::collections::HashSet<String> =
            self.all_routable_domains().await.into_iter().collect();

        // Pruning a static rule is destructive (it rewrites proxy.conf), so
        // only domains chosen by the operator or the cluster may cause it: a
        // site directory name, an admin-set alias, or a pushed route. An
        // app's declared `domain` on its own does not qualify — in
        // multi_tenant mode that string is tenant input, and letting it
        // delete the operator's rule for someone else's domain is a hijack.
        let prunable: HashSet<String> = self
            .site_directory_names()
            .into_iter()
            .chain(self.aliases.lock().keys().cloned())
            .chain(self.external_routes.domains())
            .collect();

        // Remove static proxy.conf rules for app-managed domains so they
        // don't shadow the dynamic blue-green routing. Whole-domain rules
        // only — see `shadowing_domain` for why a path carve-out stays.
        let cfg = self.config_manager.get_config();
        let original_len = cfg.rules.len();
        let rules: Vec<_> = cfg
            .rules
            .iter()
            .filter(|rule| {
                if let Some(d) = shadowing_domain(&rule.matcher) {
                    if managed.contains(d) && prunable.contains(d) {
                        tracing::info!("Removing stale static rule for app-managed domain: {}", d);
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        if rules.len() < original_len {
            if let Err(e) = self
                .config_manager
                .update_rules(rules, cfg.global_scripts.clone())
            {
                tracing::error!("Failed to clean up stale proxy.conf rules: {}", e);
            }
        }

        // Certificates follow the same set: a domain the cluster serves through
        // this proxy still needs a certificate from it.
        let acme_eligible: Vec<String> = managed
            .iter()
            .filter(|d| is_acme_eligible(d))
            .cloned()
            .collect();

        if !acme_eligible.is_empty() {
            self.config_manager
                .register_app_acme_domains(acme_eligible.clone());
        }

        if let Some(ref acme) = *self.acme_service.lock().await {
            for domain in &managed {
                if is_acme_eligible(domain) {
                    let acme = acme.clone();
                    let domain = domain.clone();
                    tokio::spawn(async move {
                        if let Err(e) = acme.ensure_certificate(&domain).await {
                            tracing::error!("Failed to issue cert for {}: {}", domain, e);
                        }
                    });
                }
            }
        }
    }

    /// Watch the sites directory and rediscover apps when it changes.
    ///
    /// Outside dev mode only what discovery reads is watched: the sites
    /// directory itself (a site created, removed or renamed) and each site's
    /// own directory, non-recursively, for its `app.infos`. The tree used to
    /// be watched recursively, which hands every tenant a way to exhaust the
    /// host's inotify watches (one per directory it creates) and to trigger a
    /// full rediscovery with any write anywhere in its site. Dev mode keeps
    /// the recursive watch: restarting an app when its code changes is the
    /// point there, and the code is the developer's own.
    ///
    /// Events are coalesced until the tree has been quiet for 500 ms (at most
    /// 5 s), and two rediscoveries are at least 2 s apart, so a burst of
    /// writes costs one rediscovery rather than one per event.
    pub async fn start_watcher(&self) -> Result<(), anyhow::Error> {
        // Only "something changed" travels; the paths matter for the dev
        // restart. A full channel means a rediscovery is already due, so an
        // event that does not fit is dropped rather than queued.
        let (tx, mut rx) = mpsc::channel::<Vec<PathBuf>>(256);
        let sites_dir = self.sites_dir.clone();
        let manager = self.clone();
        let dev_mode = self.dev_mode;

        let watch_path = if sites_dir.is_symlink() {
            sites_dir.canonicalize()?
        } else {
            sites_dir.clone()
        };

        let roots = [sites_dir.clone(), watch_path.clone()];
        let callback_sites_dir = sites_dir.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else {
                    return;
                };
                if !(event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove()) {
                    return;
                }
                let paths: Vec<PathBuf> = event
                    .paths
                    .iter()
                    .filter_map(|path| {
                        let relative =
                            roots.iter().find_map(|root| path.strip_prefix(root).ok())?;
                        (dev_mode || watch_event_is_relevant(relative, &event.kind))
                            .then(|| callback_sites_dir.join(relative))
                    })
                    .collect();
                if !paths.is_empty() {
                    let _ = tx.try_send(paths);
                }
            },
            notify::Config::default(),
        )?;

        let mut watched_sites: HashSet<PathBuf> = HashSet::new();
        if dev_mode {
            watcher.watch(&watch_path, RecursiveMode::Recursive)?;
        } else {
            watcher.watch(&watch_path, RecursiveMode::NonRecursive)?;
            sync_site_watches(
                &mut watcher,
                &mut watched_sites,
                &self.site_directory_paths(),
            );
        }

        *self.watcher.lock().await = Some(watcher);

        tokio::spawn(async move {
            const QUIET: std::time::Duration = std::time::Duration::from_millis(500);
            const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
            const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

            while let Some(first) = rx.recv().await {
                let mut changed_paths: HashSet<PathBuf> = first.into_iter().collect();
                let started = tokio::time::Instant::now();
                // Coalesce until quiet, or until MAX_WAIT under a steady stream.
                while started.elapsed() < MAX_WAIT {
                    match tokio::time::timeout(QUIET, rx.recv()).await {
                        Ok(Some(paths)) => changed_paths.extend(paths),
                        Ok(None) | Err(_) => break,
                    }
                }

                tracing::info!("Apps directory changed, rediscovering...");
                if let Err(e) = manager.discover_apps().await {
                    tracing::error!("Failed to rediscover apps: {}", e);
                }

                if !manager.dev_mode {
                    // Follow sites coming and going.
                    let sites = manager.site_directory_paths();
                    if let Some(watcher) = manager.watcher.lock().await.as_mut() {
                        sync_site_watches(watcher, &mut watched_sites, &sites);
                    }
                }

                // In dev mode, restart affected apps that are currently running
                if manager.dev_mode {
                    let app_names = affected_app_names(
                        &sites_dir,
                        &changed_paths,
                        &manager.restart_trigger_file,
                    );
                    if !app_names.is_empty() {
                        let running_apps: Vec<String> = {
                            let apps = manager.apps.lock().await;
                            app_names
                                .into_iter()
                                .filter(|name| {
                                    apps.get(name).is_some_and(|app| {
                                        let instance = if app.current_slot == "blue" {
                                            &app.blue
                                        } else {
                                            &app.green
                                        };
                                        instance.status == InstanceStatus::Running
                                    })
                                })
                                .collect()
                        };
                        for app_name in running_apps {
                            tracing::info!(
                                "Dev mode: restarting app '{}' due to file changes",
                                app_name
                            );
                            if let Err(e) = manager.restart(&app_name).await {
                                tracing::error!("Failed to restart app '{}': {}", app_name, e);
                            }
                        }
                    }
                }

                tokio::time::sleep(MIN_INTERVAL).await;
            }
        });

        Ok(())
    }

    /// Paths of the site directories under `sites_dir`, as discovery sees
    /// them (a symlinked site keeps its `sites/<name>` path).
    fn site_directory_paths(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(&self.sites_dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_dir()
                    && !path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with('.'))
            })
            .collect()
    }

    pub async fn list_apps(&self) -> Vec<AppInfo> {
        let quarantined = self.quarantined.lock().clone();
        self.apps
            .lock()
            .await
            .values()
            .filter(|&a| a.config.name != "_admin")
            .cloned()
            .map(|mut a| {
                a.quarantined = quarantined.contains(&a.config.name);
                a
            })
            .collect()
    }

    /// Synchronous version for use from non-async contexts (e.g. TUI).
    pub fn list_apps_sync(&self) -> Vec<AppInfo> {
        self.apps
            .blocking_lock()
            .values()
            .filter(|a| a.config.name != "_admin")
            .cloned()
            .collect()
    }

    /// Probe ports to detect which apps are actually running.
    /// Call after `discover_apps` in non-server contexts (e.g. TUI).
    pub fn probe_running_apps(&self) {
        let mut apps = self.apps.blocking_lock();
        for app in apps.values_mut() {
            for (inst, _slot) in [(&mut app.blue, "blue"), (&mut app.green, "green")] {
                if inst.port > 0 {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], inst.port));
                    let is_up = std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_millis(200),
                    )
                    .is_ok();
                    if is_up {
                        inst.status = InstanceStatus::Running;
                        inst.pid = find_pid_by_port(inst.port);
                    } else {
                        inst.status = InstanceStatus::Stopped;
                        inst.pid = None;
                    }
                }
            }
        }
        self.publish_routes(&apps);
    }

    /// Lightweight refresh: validate existing PIDs, re-detect missing ones.
    /// Called on each TUI tick — avoids full probe overhead.
    pub fn refresh_pids(&self) {
        let mut apps = self.apps.blocking_lock();
        for app in apps.values_mut() {
            for (inst, _slot) in [(&mut app.blue, "blue"), (&mut app.green, "green")] {
                if inst.port == 0 {
                    continue;
                }

                // Check if existing PID is still alive
                if let Some(pid) = inst.pid {
                    let proc_path = format!("/proc/{}", pid);
                    if !std::path::Path::new(&proc_path).exists() {
                        inst.pid = None;
                    }
                }

                // Re-detect PID if missing
                if inst.pid.is_none() {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], inst.port));
                    let is_up = std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_millis(100),
                    )
                    .is_ok();
                    if is_up {
                        inst.status = InstanceStatus::Running;
                        inst.pid = find_pid_by_port(inst.port);
                    } else if matches!(inst.status, InstanceStatus::Running) {
                        inst.status = InstanceStatus::Stopped;
                    }
                }
            }
        }
        self.publish_routes(&apps);
    }

    /// Load app state (current_slot) from disk so TUI can see deploys that happened
    /// while TUI was not running.
    pub fn load_app_state(&self) {
        if let Some(state) = read_app_state_file() {
            let mut apps = self.apps.blocking_lock();
            apply_app_state(&mut apps, &state);
            self.publish_routes(&apps);
        }
    }

    /// Async variant of [`Self::load_app_state`] for callers already inside a
    /// runtime, where `blocking_lock()` would panic.
    pub async fn load_app_state_async(&self) {
        if let Some(state) = read_app_state_file() {
            let mut apps = self.apps.lock().await;
            apply_app_state(&mut apps, &state);
            self.publish_routes(&apps);
        }
    }

    /// Save app state (current_slot) to disk so other processes (e.g. TUI) can see it.
    pub async fn save_app_state(&self) {
        write_app_state_file(&*self.apps.lock().await);
    }

    pub async fn get_app(&self, name: &str) -> Option<AppInfo> {
        self.apps.lock().await.get(name).cloned().map(|mut a| {
            a.quarantined = self.is_quarantined(name);
            a
        })
    }

    pub async fn get_app_name(&self, port: u16) -> Option<String> {
        self.port_allocator.get_app_name(port).await
    }

    /// The OS processes behind each app, by app name.
    ///
    /// Both slots when both are up: a blue/green deploy runs two, and an app's
    /// memory during that window is the pair. Slots with no pid are omitted
    /// rather than reported as absent processes.
    ///
    /// A Soli app's workers are **threads, not child processes** — measured on
    /// this host, `--workers 2` gives one pid with ten threads and no children
    /// — so a slot's pid accounts for the whole app and there is no tree to
    /// walk. That would stop being true for a container-backed app, where the
    /// real process is a child of the container daemon; none exist here today,
    /// and this comment is the marker for when one does.
    pub async fn running_pids(&self) -> HashMap<String, Vec<u32>> {
        let apps = self.apps.lock().await;
        apps.iter()
            .map(|(name, app)| {
                let pids = [&app.blue, &app.green]
                    .iter()
                    .filter_map(|instance| instance.pid)
                    .collect();
                (name.clone(), pids)
            })
            .collect()
    }

    pub async fn get_system_metrics(&self, metrics: &AppMetrics) -> serde_json::Value {
        let apps = self.apps.lock().await;
        let mut result = serde_json::Map::new();

        for (name, app) in apps.iter() {
            let mut app_metrics = serde_json::Map::new();

            if let Some(pid) = app.blue.pid {
                if let Some(stats) = metrics.get_process_stats(pid) {
                    app_metrics.insert(
                        "blue".to_string(),
                        serde_json::to_value(stats).unwrap_or_default(),
                    );
                }
            }

            if let Some(pid) = app.green.pid {
                if let Some(stats) = metrics.get_process_stats(pid) {
                    app_metrics.insert(
                        "green".to_string(),
                        serde_json::to_value(stats).unwrap_or_default(),
                    );
                }
            }

            result.insert(name.clone(), serde_json::Value::Object(app_metrics));
        }

        serde_json::Value::Object(result)
    }

    pub async fn allocate_ports(&self, app_name: &str) -> Result<(u16, u16), anyhow::Error> {
        let (start, end) = self.port_range;
        let blue_port = self
            .port_allocator
            .allocate_with_range(app_name, "blue", start, end)
            .await?;
        let green_port = self
            .port_allocator
            .allocate_with_range(app_name, "green", start, end)
            .await?;
        Ok((blue_port, green_port))
    }

    pub async fn deploy(&self, app_name: &str, slot: &str) -> Result<(), anyhow::Error> {
        tracing::info!("Starting deploy for {} to slot {}", app_name, slot);

        if !self.deployment_manager.mark_deploying(app_name) {
            anyhow::bail!("Deployment already in progress for {}", app_name);
        }
        let dm = self.deployment_manager.clone();
        let deploy_name = app_name.to_string();
        let _guard = scopeguard::guard((), move |_| {
            dm.unmark_deploying(&deploy_name);
        });

        // Every explicit deploy path (CLI, admin API, trigger file, auto-start,
        // restart, rollback) funnels through here, so this is the single place
        // that lifts a quarantine. `failover` is gated before it reaches this.
        self.clear_quarantine(app_name);
        // Likewise the single place an app stops being asleep: whoever starts
        // it — a held request or an operator — it is awake from here on, and
        // its idle clock restarts so the reaper does not stop it again at once.
        self.asleep.lock().remove(app_name);
        self.touch(app_name);

        let app = self
            .apps
            .lock()
            .await
            .get(app_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?;

        let old_slot = app.current_slot.clone();

        // Stop existing process on target slot
        let target_pid = {
            let apps = self.apps.lock().await;
            let a = apps.get(app_name).unwrap();
            if slot == "blue" {
                a.blue.pid
            } else {
                a.green.pid
            }
        };
        if let Some(pid) = target_pid {
            self.deployment_manager.terminate(&app, slot, pid).await;
        }

        // Start new instance
        tracing::info!("Starting {} slot {}", app.config.name, slot);
        let pid = match self.deployment_manager.start_instance(&app, slot).await {
            Ok(pid) => pid,
            Err(e) => {
                // Spawn itself failed (bad start_script, port conflict, missing
                // binary...). Quarantine so the health loop does not retry it
                // every 30s; the previous slot, if any, keeps serving.
                {
                    let mut apps = self.apps.lock().await;
                    if let Some(app_entry) = apps.get_mut(app_name) {
                        let instance = if slot == "blue" {
                            &mut app_entry.blue
                        } else {
                            &mut app_entry.green
                        };
                        instance.pid = None;
                        instance.status = InstanceStatus::Failed;
                    }
                    self.publish_routes(&apps);
                }
                self.emit_event(AppEvent::StatusChanged {
                    app_name: app_name.to_string(),
                    slot: slot.to_string(),
                    status: "failed".to_string(),
                });
                self.quarantine(
                    app_name,
                    &format!("slot {} could not be spawned: {:#}", slot, e),
                );
                return Err(e);
            }
        };
        tracing::info!("Started {} slot {} with PID {}", app.config.name, slot, pid);

        // Update state with new PID
        {
            let mut apps = self.apps.lock().await;
            let app_entry = match apps.get_mut(app_name) {
                Some(a) => a,
                None => {
                    tracing::error!("App {} removed during deploy, aborting", app_name);
                    return Err(anyhow::anyhow!("App {} no longer exists", app_name));
                }
            };
            let instance = if slot == "blue" {
                &mut app_entry.blue
            } else {
                &mut app_entry.green
            };
            instance.pid = Some(pid);
            instance.status = InstanceStatus::Running;
            instance.last_started = Some(chrono::Utc::now().to_rfc3339());
            self.publish_routes(&apps);
        }

        // Wait for health check. wait_for_health returns a descriptive error
        // (with the app's last health-response error and a pointer to the log
        // file) so we just propagate it.
        if let Err(e) = self
            .deployment_manager
            .wait_for_health(&app, slot, pid)
            .await
        {
            tracing::error!("{}", e);
            self.deployment_manager.terminate(&app, slot, pid).await;
            {
                let mut apps = self.apps.lock().await;
                if let Some(app_entry) = apps.get_mut(app_name) {
                    let instance = if slot == "blue" {
                        &mut app_entry.blue
                    } else {
                        &mut app_entry.green
                    };
                    instance.pid = None;
                    instance.status = InstanceStatus::Failed;
                }
                self.publish_routes(&apps);
            }
            self.emit_event(AppEvent::StatusChanged {
                app_name: app_name.to_string(),
                slot: slot.to_string(),
                status: "failed".to_string(),
            });
            // The app failed to start: stop here instead of letting the health
            // loop retry forever. The previous slot, if any, keeps serving.
            self.quarantine(
                app_name,
                &format!(
                    "slot {} failed to start (see run/logs/{}/{}.log)",
                    slot, app_name, slot
                ),
            );
            return Err(e);
        }
        tracing::info!("Health check passed for {} slot {}", app.config.name, slot);

        // Switch traffic AND persist atomically
        {
            let mut apps = self.apps.lock().await;
            if let Some(app_entry) = apps.get_mut(app_name) {
                app_entry.current_slot = slot.to_string();
            }

            // Persist while still holding the lock to prevent load_app_state()
            // from reverting the switch with stale disk data
            write_app_state_file(&apps);
            self.publish_routes(&apps);
        }
        // Verify the routing state after switch
        {
            let apps = self.apps.lock().await;
            if let Some(a) = apps.get(app_name) {
                tracing::info!(
                    "Traffic switched {} → {}: domain={} current_slot={} blue(port={}, pid={:?}) green(port={}, pid={:?})",
                    old_slot, slot, a.config.domain, a.current_slot,
                    a.blue.port, a.blue.pid, a.green.port, a.green.pid
                );
            }
        }

        self.sync_routes().await;
        let _ = self.config_manager.reload().await;

        // Reset circuit breaker
        if let Some(ref cb) = self.circuit_breaker {
            let port = if slot == "blue" {
                app.blue.port
            } else {
                app.green.port
            };
            cb.reset_target(&format!("http://127.0.0.1:{}/", port));
        }

        // Stop old slot (skip if same slot)
        if old_slot != slot && old_slot != "unknown" {
            let old_pid = {
                let apps = self.apps.lock().await;
                match apps.get(app_name) {
                    Some(a) if old_slot == "blue" => a.blue.pid,
                    Some(a) => a.green.pid,
                    None => {
                        tracing::warn!("App {} removed during deploy drain phase", app_name);
                        None
                    }
                }
            };
            if let Some(pid) = old_pid {
                let drain = app.config.drain_delay as u64;
                if drain > 0 {
                    tracing::info!("Draining old slot {} for {}s", old_slot, drain);
                    tokio::time::sleep(std::time::Duration::from_secs(drain)).await;
                }
                self.deployment_manager
                    .terminate(&app, &old_slot, pid)
                    .await;
                {
                    let mut apps = self.apps.lock().await;
                    if let Some(app_entry) = apps.get_mut(app_name) {
                        let instance = if old_slot == "blue" {
                            &mut app_entry.blue
                        } else {
                            &mut app_entry.green
                        };
                        instance.pid = None;
                        instance.status = InstanceStatus::Stopped;
                    }
                    self.publish_routes(&apps);
                }
                tracing::info!("Stopped old slot {}", old_slot);
            }
        }

        tracing::info!("Deploy completed for {} to slot {}", app_name, slot);

        // Reset failure counts on successful deploy
        {
            let mut failure_count = self.failure_count.lock();
            failure_count.insert(app_name.to_string(), 0);
        }
        self.health_failures.lock().remove(app_name);

        self.emit_event(AppEvent::Deployed {
            app_name: app_name.to_string(),
            slot: slot.to_string(),
        });
        self.emit_event(AppEvent::StatusChanged {
            app_name: app_name.to_string(),
            slot: slot.to_string(),
            status: "running".to_string(),
        });
        Ok(())
    }

    pub async fn restart(&self, app_name: &str) -> Result<(), anyhow::Error> {
        let target_slot = {
            let apps = self.apps.lock().await;
            let app = apps
                .get(app_name)
                .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?;
            // Deploy to the OTHER slot for zero-downtime restart:
            // new slot starts → health check → traffic switch → old slot stops
            if app.current_slot == "blue" {
                "green".to_string()
            } else {
                "blue".to_string()
            }
        };

        self.deploy(app_name, &target_slot).await
    }

    pub async fn failover(&self, app_name: &str) -> Result<(), anyhow::Error> {
        // A sleeping app is stopped on purpose. Failover is the proxy's
        // self-healing primitive — the health check and the process-exit
        // monitor both reach it — so gating it here is what stops scale-to-zero
        // from fighting them: without this the reaper stops the app, the
        // monitor sees the exit and redeploys it to the other slot, and the
        // next tick stops it again, forever. Only a request (through `wake`,
        // which clears `asleep`) or an explicit deploy brings it back.
        if self.is_asleep(app_name) {
            tracing::debug!(
                "Skipping failover for {} — asleep (scale to zero)",
                app_name
            );
            return Ok(());
        }
        // Quarantined apps are left alone: a failed start must not turn into an
        // endless restart loop. Only an explicit deploy clears this.
        if self.is_quarantined(app_name) {
            tracing::warn!(
                "Skipping failover for {} — app is quarantined after a failed start",
                app_name
            );
            return Ok(());
        }

        let target_slot = {
            let apps = self.apps.lock().await;
            let app = apps
                .get(app_name)
                .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?;
            if app.current_slot == "blue" {
                "green".to_string()
            } else {
                "blue".to_string()
            }
        };
        tracing::warn!(
            "Health check failed on current slot, failing over {} to slot {}",
            app_name,
            target_slot
        );
        self.deploy(app_name, &target_slot).await
    }

    pub async fn rollback(&self, app_name: &str) -> Result<(), anyhow::Error> {
        // Rollback = deploy to the opposite slot (same as restart)
        self.restart(app_name).await
    }

    pub async fn stop(&self, app_name: &str) -> Result<(), anyhow::Error> {
        let (app, slot) = {
            let apps = self.apps.lock().await;
            let app = apps
                .get(app_name)
                .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?
                .clone();
            let slot = app.current_slot.clone();
            (app, slot)
        };
        let app = self.with_recorded_pids(app);

        self.deployment_manager.stop_instance(&app, &slot).await?;

        {
            let mut apps = self.apps.lock().await;
            if let Some(app_info) = apps.get_mut(app_name) {
                let instance = if slot == "blue" {
                    &mut app_info.blue
                } else {
                    &mut app_info.green
                };
                instance.status = InstanceStatus::Stopped;
                instance.pid = None;
            }
            self.publish_routes(&apps);
        }

        self.emit_event(AppEvent::Stopped {
            app_name: app_name.to_string(),
            slot: slot.clone(),
        });
        self.emit_event(AppEvent::StatusChanged {
            app_name: app_name.to_string(),
            slot,
            status: "stopped".to_string(),
        });

        Ok(())
    }

    /// Stop every app this proxy manages, both slots, and then every other
    /// process it recorded spawning.
    ///
    /// No longer what a proxy shutdown does by default (see `[apps]
    /// stop_on_shutdown`); it is what `soli-proxy stop --all` and `POST
    /// /api/v1/apps/stop-all` ask for. It works from a fresh process too:
    /// a slot's PID comes from the spawn registry when this proxy did not
    /// start it, and a container is stopped by its name. Apps stop in
    /// parallel, each within its own `graceful_timeout`.
    pub async fn stop_all(&self) {
        use futures::StreamExt;

        let apps: Vec<AppInfo> = {
            let apps_guard = self.apps.lock().await;
            apps_guard.values().cloned().collect()
        };
        let mut stops = futures::stream::iter(apps.into_iter().map(|app| {
            let manager = self.clone();
            async move {
                let app = manager.with_recorded_pids(app);
                for (slot, pid) in [("blue", app.blue.pid), ("green", app.green.pid)] {
                    if app.config.docker_image.is_none() && pid.is_none() {
                        continue;
                    }
                    // An intended stop, not a crash for the container
                    // monitor to report (a native stop marks itself).
                    if let (Some(pid), Some(_)) = (pid, &app.config.docker_image) {
                        manager.deployment_manager.mark_stopping(pid);
                    }
                    if let Err(e) = manager.deployment_manager.stop_instance(&app, slot).await {
                        tracing::error!(
                            "Failed to stop {} slot for {}: {}",
                            slot,
                            app.config.name,
                            e
                        );
                    }
                }
                let mut apps_guard = manager.apps.lock().await;
                if let Some(app_info) = apps_guard.get_mut(&app.config.name) {
                    app_info.blue.status = InstanceStatus::Stopped;
                    app_info.blue.pid = None;
                    app_info.green.status = InstanceStatus::Stopped;
                    app_info.green.pid = None;
                }
                manager.publish_routes(&apps_guard);
            }
        }))
        .buffer_unordered(16);
        while stops.next().await.is_some() {}
        drop(stops);

        // Whatever is left: processes of apps whose site directory is gone.
        self.deployment_manager
            .stop_all_recorded(std::time::Duration::from_secs(5))
            .await;
    }

    /// `app` with each slot's PID filled in from the spawn registry where the
    /// map has none — the case of a slot started by a proxy that has since
    /// exited, seen from a CLI that is not the daemon.
    fn with_recorded_pids(&self, mut app: AppInfo) -> AppInfo {
        if app.config.docker_image.is_none() {
            let name = app.config.name.clone();
            for instance in [&mut app.blue, &mut app.green] {
                if instance.pid.is_none() {
                    instance.pid = self.deployment_manager.recorded_pid(&name, &instance.slot);
                }
            }
        }
        app
    }

    /// Poll every running app's health check once; fail an app over after
    /// `[apps] health_failure_threshold` consecutive failures (default 3).
    ///
    /// A failure is what says the app cannot serve: no connection, a
    /// timeout, or a 5xx. A 4xx is not one — the app answered, so it is up;
    /// a 404 or 401 on a health path almost always means the path is wrong,
    /// and failing over would restart a working app every interval. It is
    /// logged as a warning instead. One failure on its own is not acted on
    /// either: a GC pause or a slow request during a deploy elsewhere used to
    /// cost a full blue/green restart.
    pub async fn check_health(&self) {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let apps: Vec<(String, u16, String)> = {
            let apps_guard = self.apps.lock().await;
            apps_guard
                .iter()
                .filter_map(|(name, app)| {
                    let (port, pid) = if app.current_slot == "blue" {
                        (app.blue.port, app.blue.pid)
                    } else {
                        (app.green.port, app.green.pid)
                    };
                    let health_path = app.config.health_check.as_deref().unwrap_or("/");
                    if port > 0 && pid.is_some() {
                        Some((name.clone(), port, health_path.to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        for (app_name, port, health_path) in apps {
            if self.deployment_manager.is_deploying(&app_name) {
                continue;
            }
            if self.is_quarantined(&app_name) {
                continue;
            }
            if self.is_asleep(&app_name) {
                continue;
            }
            let url = format!("http://127.0.0.1:{}{}", port, health_path);
            let verdict = match http_client.get(&url).send().await {
                Ok(resp) => health_verdict(resp.status().as_u16()),
                Err(e) => HealthVerdict::Failed(e.to_string()),
            };
            match verdict {
                HealthVerdict::Healthy => {
                    tracing::debug!("Health check OK for {} on port {}", app_name, port);
                    self.health_failures.lock().remove(&app_name);
                }
                HealthVerdict::Misconfigured(status) => {
                    tracing::warn!(
                        "Health check {} for {} answered HTTP {}: the app is up, but its \
                         health_check path looks wrong. Not counted as a failure.",
                        url,
                        app_name,
                        status
                    );
                    self.health_failures.lock().remove(&app_name);
                }
                HealthVerdict::Failed(reason) => {
                    let failures = {
                        let mut counts = self.health_failures.lock();
                        let count = counts.entry(app_name.clone()).or_insert(0);
                        *count += 1;
                        *count
                    };
                    if failures < self.health_failure_threshold {
                        tracing::warn!(
                            "Health check failed for {} on port {}: {} ({}/{} before failover)",
                            app_name,
                            port,
                            reason,
                            failures,
                            self.health_failure_threshold
                        );
                        continue;
                    }
                    tracing::warn!(
                        "Health check failed for {} on port {}: {} — {} consecutive failures, \
                         failing over",
                        app_name,
                        port,
                        reason,
                        failures
                    );
                    self.health_failures.lock().remove(&app_name);
                    if let Err(e) = self.failover(&app_name).await {
                        tracing::error!("Failed to failover {}: {}", app_name, e);
                    }
                }
            }
        }
    }

    /// True when automatic remediation is suspended for this app after a failed
    /// start. Cleared by any explicit deploy.
    pub fn is_quarantined(&self, app_name: &str) -> bool {
        self.quarantined.lock().contains(app_name)
    }

    fn quarantine(&self, app_name: &str, reason: &str) {
        let newly = self.quarantined.lock().insert(app_name.to_string());
        if newly {
            tracing::error!(
                "App '{}' quarantined: {}. Automatic restarts are suspended — \
                 fix the app and `touch {}/{}`, or run `soli-proxy restart {}`",
                app_name,
                reason,
                app_name,
                self.restart_trigger_file,
                app_name
            );
        }
        self.emit_event(AppEvent::StatusChanged {
            app_name: app_name.to_string(),
            slot: "-".to_string(),
            status: "quarantined".to_string(),
        });
    }

    fn clear_quarantine(&self, app_name: &str) {
        if self.quarantined.lock().remove(app_name) {
            tracing::info!(
                "App '{}' released from quarantine by an explicit deploy",
                app_name
            );
        }
    }

    /// Poll each site's trigger file and restart the apps whose file was touched
    /// since the last tick.
    ///
    /// This is a polling loop rather than an extension of the `notify` watcher
    /// on purpose: inotify does not traverse symlinks, and sites are typically
    /// symlinks into out-of-tree repositories, so no event is ever produced for
    /// a file inside them. `AppInfo.path` keeps the un-canonicalized
    /// `sites/<domain>` path and `fs::metadata` follows symlinks, so a single
    /// stat per site per tick is enough.
    pub async fn check_restart_triggers(&self) {
        let candidates: Vec<(String, PathBuf)> = {
            let apps = self.apps.lock().await;
            apps.iter()
                .filter(|(_, app)| app.config.start_script.is_some())
                .map(|(name, app)| (name.clone(), app.path.clone()))
                .collect()
        };

        let mut to_restart: Vec<String> = Vec::new();
        {
            let mut triggers = self.restart_triggers.lock();
            let live: HashSet<&String> = candidates.iter().map(|(name, _)| name).collect();
            triggers.retain(|name, _| live.contains(name));

            for (name, path) in &candidates {
                let current = std::fs::metadata(path.join(&self.restart_trigger_file))
                    .and_then(|m| m.modified())
                    .ok();
                let (fire, remember) = trigger_decision(triggers.get(name), current);
                // Record before restarting so a deploy that outlives several
                // ticks cannot re-trigger itself.
                triggers.insert(name.clone(), remember);
                if fire {
                    to_restart.push(name.clone());
                }
            }
        }

        for app_name in to_restart {
            if self.deployment_manager.is_deploying(&app_name) {
                tracing::info!(
                    "Restart trigger detected for {} — deploy already in progress, skipping",
                    app_name
                );
                continue;
            }
            tracing::info!(
                "Restart trigger detected for {} ({} touched), deploying",
                app_name,
                self.restart_trigger_file
            );
            // Detached: a deploy waits on the health check for up to 30s and
            // must not delay trigger detection for the other sites.
            let manager = self.clone();
            tokio::spawn(async move {
                if let Err(e) = manager.restart(&app_name).await {
                    tracing::error!("Triggered restart failed for {}: {:#}", app_name, e);
                }
            });
        }
    }

    // ---------------------------------------------------------------------
    // Scale to zero
    // ---------------------------------------------------------------------

    /// The domains a request for `config` may arrive on: the declared one, its
    /// `www.`-stripped twin, and the `.test` twin in dev — the same set
    /// `build_routes` claims for it (aliases aside).
    fn domains_of(&self, config: &AppConfig) -> Vec<String> {
        let mut out = Vec::with_capacity(3);
        if config.domain.is_empty() {
            return out;
        }
        out.push(config.domain.clone());
        if let Some(non_www) = strip_www(&config.domain) {
            out.push(non_www);
        }
        if self.dev_mode {
            if let Some(dev) = dev_domain(&config.domain) {
                out.push(dev);
            }
        }
        out
    }

    /// Seconds of inactivity after which `app` is put to sleep; `0` never.
    ///
    /// `_admin` never sleeps whatever its manifest says: the admin listener
    /// reaches it directly, not through `resolve_app_target`, so nothing
    /// would ever wake it.
    fn idle_timeout_for(&self, app: &AppInfo) -> u64 {
        if app.config.name == "_admin" {
            return 0;
        }
        app.config.idle_timeout.unwrap_or(self.default_idle_timeout)
    }

    /// Record that a request just arrived for `host`.
    pub async fn note_activity(&self, host: &str) {
        if let Some(route) = self.routes().get(host) {
            route.activity.store(self.now_ms(), Ordering::Relaxed);
        }
    }

    /// Restart `app_name`'s idle clock.
    fn touch(&self, app_name: &str) {
        self.activity_cell(app_name)
            .store(self.now_ms(), Ordering::Relaxed);
    }

    /// Whether the reaper has stopped `app_name` for inactivity.
    pub fn is_asleep(&self, app_name: &str) -> bool {
        self.asleep.lock().contains(app_name)
    }

    /// If `host` belongs to a sleeping app, start it and wait until it is
    /// healthy. `true` means the caller should resolve the target again.
    pub async fn wake_if_asleep(&self, host: &str) -> bool {
        let Some(name) = self.app_name_for_host(host).await else {
            return false;
        };
        if !self.is_asleep(&name) {
            return false;
        }
        match self.wake(&name).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("Could not wake {} for {}: {}", name, host, e);
                false
            }
        }
    }

    /// Start a sleeping app on its current slot and return once it answers its
    /// health check.
    ///
    /// Concurrent wakes serialise on the deploy lock: the first caller runs
    /// the deploy, the others see "already in progress" and poll until a PID
    /// appears. Bounded, because a wake that cannot finish must fail the held
    /// requests rather than park them forever.
    pub async fn wake(&self, app_name: &str) -> Result<(), anyhow::Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            let (running, slot) = {
                let apps = self.apps.lock().await;
                let app = apps
                    .get(app_name)
                    .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?;
                let pid = if app.current_slot == "blue" {
                    app.blue.pid
                } else {
                    app.green.pid
                };
                (pid.is_some(), app.current_slot.clone())
            };
            if running {
                self.asleep.lock().remove(app_name);
                self.touch(app_name);
                return Ok(());
            }
            match self.deploy(app_name, &slot).await {
                Ok(()) => {
                    tracing::info!("{} woke up on slot {}", app_name, slot);
                    return Ok(());
                }
                Err(e) if e.to_string().contains("already in progress") => {
                    if std::time::Instant::now() >= deadline {
                        anyhow::bail!("timed out waiting for {} to wake", app_name);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Stop every app that has been idle past its threshold. Run by
    /// [`spawn_idle_reaper`](Self::spawn_idle_reaper).
    pub async fn reap_idle(&self) {
        let now = self.now_ms();
        let candidates: Vec<(String, u64)> = {
            let apps = self.apps.lock().await;
            apps.values()
                .filter_map(|app| {
                    let timeout = self.idle_timeout_for(app);
                    let pid = if app.current_slot == "blue" {
                        app.blue.pid
                    } else {
                        app.green.pid
                    };
                    (timeout > 0 && pid.is_some()).then(|| (app.config.name.clone(), timeout))
                })
                .collect()
        };
        for (name, timeout) in candidates {
            let cell = self.activity_cell(&name);
            let last = cell.load(Ordering::Relaxed);
            if last == 0 {
                // First sight: start the clock now. An app that came up
                // before the reaper did is not idle by definition.
                cell.store(now, Ordering::Relaxed);
                continue;
            }
            let idle_for = std::time::Duration::from_millis(now.saturating_sub(last));
            if idle_for.as_secs() < timeout {
                continue;
            }
            if self.deployment_manager.is_deploying(&name) || self.is_quarantined(&name) {
                continue;
            }
            match self.stop(&name).await {
                Ok(()) => {
                    self.asleep.lock().insert(name.clone());
                    tracing::info!(
                        "{} put to sleep after {}s without a request (idle_timeout = {}s)",
                        name,
                        idle_for.as_secs(),
                        timeout
                    );
                }
                Err(e) => tracing::warn!("Could not put {} to sleep: {}", name, e),
            }
        }
    }

    /// Check for idle apps every 30 seconds. A no-op unless some app opted
    /// in, so a fleet with no `idle_timeout` anywhere pays only the scan.
    pub fn spawn_idle_reaper(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                manager.reap_idle().await;
            }
        });
    }

    /// Spawn the trigger-file poller. No-op when the poll interval is 0.
    pub fn spawn_restart_trigger_watcher(&self) {
        let interval_secs = self.restart_trigger_poll_secs;
        if interval_secs == 0 {
            tracing::info!("Restart trigger file polling disabled (poll interval is 0)");
            return;
        }
        tracing::info!(
            "Watching for '<site>/{}' every {}s to trigger deploys",
            self.restart_trigger_file,
            interval_secs
        );
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                manager.check_restart_triggers().await;
            }
        });
    }

    pub fn spawn_health_check(&self) {
        let manager = self.clone();
        let interval_secs = self.health_check_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                tracing::debug!("Running scheduled health check...");
                manager.check_health().await;
            }
        });
    }

    /// Listens for unexpected process exits and triggers immediate failover.
    /// This eliminates the delay between process death and the next scheduled
    /// health check, achieving near-zero downtime on unexpected crashes.
    pub fn spawn_process_exit_monitor(&self) {
        let mut rx = self
            .process_exit_rx
            .lock()
            .take()
            .expect("monitor already spawned");
        let manager = self.clone();
        tokio::spawn(async move {
            while let Some(exit) = rx.recv().await {
                // An app the reaper put to sleep exits on purpose; its stop is
                // not a crash to heal from.
                if manager.is_asleep(&exit.app_name) {
                    tracing::debug!(
                        "Ignoring exit of {} — asleep (scale to zero)",
                        exit.app_name
                    );
                    continue;
                }
                tracing::warn!(
                    "Detected unexpected exit of {} slot {} (PID {}), triggering immediate failover",
                    exit.app_name,
                    exit.slot,
                    exit.pid
                );

                // Check failure count - stop after 3 consecutive failures
                let exhausted = {
                    let mut failure_count = manager.failure_count.lock();
                    let count = failure_count.entry(exit.app_name.clone()).or_insert(0);
                    *count += 1;
                    if *count > 3 {
                        Some(*count)
                    } else {
                        None
                    }
                };
                if let Some(count) = exhausted {
                    manager.quarantine(
                        &exit.app_name,
                        &format!("{} consecutive unexpected exits, giving up", count),
                    );
                    continue;
                }

                // Verify the PID still matches the current slot — if it was
                // already replaced by a concurrent deploy, skip failover.
                let failover_app = {
                    let apps = manager.apps.lock().await;
                    apps.get(&exit.app_name)
                        .filter(|app| {
                            let current_pid = if app.current_slot == "blue" {
                                app.blue.pid
                            } else {
                                app.green.pid
                            };
                            // Only failover if the dead PID is still the active one
                            current_pid == Some(exit.pid) && app.current_slot == exit.slot
                        })
                        .cloned()
                };

                if let Some(app) = failover_app {
                    // Kill the dead process's entire group to clean up
                    // any surviving worker processes. The main process is
                    // dead but workers (started via --workers N) may still
                    // be running and could interfere with the replacement.
                    // (A container is stopped by name, which also removes
                    // it before docker's own restart policy can act.)
                    manager
                        .deployment_manager
                        .terminate(&app, &exit.slot, exit.pid)
                        .await;

                    // Clear the dead PID so health checks and routing
                    // know this slot is gone
                    {
                        let mut apps = manager.apps.lock().await;
                        if let Some(app) = apps.get_mut(&exit.app_name) {
                            let instance = if exit.slot == "blue" {
                                &mut app.blue
                            } else {
                                &mut app.green
                            };
                            instance.pid = None;
                            instance.status = InstanceStatus::Failed;
                        }
                        manager.publish_routes(&apps);
                    }

                    // Record failover time for cooldown
                    {
                        let mut last_failover = manager.last_failover.lock();
                        last_failover.insert(exit.app_name.clone(), std::time::Instant::now());
                    }

                    if let Err(e) = manager.failover(&exit.app_name).await {
                        tracing::error!("Immediate failover failed for {}: {}", exit.app_name, e);
                    }
                } else {
                    tracing::debug!(
                        "Skipping failover for {} — PID {} is no longer the active slot",
                        exit.app_name,
                        exit.pid
                    );
                }
            }
        });
    }
}

/// Read `run/aliases.json` (domain -> app name). A missing or malformed file
/// yields an empty table: aliases are additive routing, so losing them degrades
/// to site-domain-only routing rather than preventing startup.
fn read_aliases_file() -> HashMap<String, String> {
    read_aliases_from(std::path::Path::new(ALIASES_FILE))
}

/// The same read, against an explicit path.
///
/// Split out so a test can point at a temp file instead of moving the *process*
/// working directory to make a relative constant resolve. Two tests doing that in
/// parallel raced: one restored the previous directory while the other was still
/// writing, and the write landed somewhere that no longer existed. A test that has
/// to mutate global state to reach the code under test is telling you the code
/// wants a parameter.
fn read_aliases_from(path: &std::path::Path) -> HashMap<String, String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    match serde_json::from_str::<HashMap<String, String>>(&content) {
        Ok(aliases) => {
            tracing::info!("Loaded {} alias(es) from {}", aliases.len(), path.display());
            aliases
        }
        Err(e) => {
            tracing::error!("Ignoring malformed {}: {}", path.display(), e);
            HashMap::new()
        }
    }
}

/// Read `run/app_state.json` (app name -> current_slot), written on every
/// promotion so other processes can recover the live slot.
fn read_app_state_file() -> Option<serde_json::Map<String, serde_json::Value>> {
    let state_file = PathBuf::from("./run/app_state.json");
    let content = std::fs::read_to_string(&state_file).ok()?;
    let state = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    let apps = state.as_object().cloned();
    if apps.is_some() {
        tracing::debug!("Loaded app state from {:?}", state_file);
    }
    apps
}

/// Write `run/app_state.json` (app name -> current_slot), atomically: the
/// TUI and the next start both read it, and a torn file reverts every app to
/// its default slot.
fn write_app_state_file(apps: &HashMap<String, AppInfo>) {
    let state_file = PathBuf::from("./run/app_state.json");
    if let Some(parent) = state_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let map: serde_json::Map<String, serde_json::Value> = apps
        .iter()
        .map(|(name, app)| {
            (
                name.clone(),
                serde_json::Value::String(app.current_slot.clone()),
            )
        })
        .collect();
    match serde_json::to_string_pretty(&serde_json::Value::Object(map)) {
        Ok(content) => {
            if let Err(e) = crate::config::write_atomic(&state_file, content.as_bytes()) {
                tracing::error!("Failed to write {}: {}", state_file.display(), e);
            } else {
                tracing::debug!("Saved app state to {:?}", state_file);
            }
        }
        Err(e) => tracing::error!("Failed to serialize app state: {}", e),
    }
}

fn apply_app_state(
    apps: &mut HashMap<String, AppInfo>,
    state: &serde_json::Map<String, serde_json::Value>,
) {
    for (name, slot) in state {
        if let Some(slot_str) = slot.as_str() {
            if let Some(app_info) = apps.get_mut(name) {
                app_info.current_slot = slot_str.to_string();
            }
        }
    }
}

/// Try to find the PID of a process listening on a given port.
/// Uses `ss` first, falls back to scanning /proc/net/tcp + /proc/*/fd.
pub(crate) fn find_pid_by_port(port: u16) -> Option<u32> {
    // Try ss first (fast, but may not show PIDs without root)
    if let Some(pid) = find_pid_by_ss(port) {
        return Some(pid);
    }
    // Fallback: /proc/net/tcp inode scan
    find_pid_by_proc_net(port)
}

fn find_pid_by_ss(port: u16) -> Option<u32> {
    let output = std::process::Command::new("ss")
        .args(["-tlnp", &format!("sport = :{}", port)])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(pid_start) = line.find("pid=") {
            let rest = &line[pid_start + 4..];
            let pid_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let pid: u32 = pid_str.parse().ok()?;
            if pid < 2 {
                return None;
            }
            return Some(pid);
        }
    }
    None
}

fn find_pid_by_proc_net(port: u16) -> Option<u32> {
    // 1. Find the socket inode for the port in /proc/net/tcp
    let hex_port = format!("{:04X}", port);
    let tcp_content = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let mut target_inode: Option<u64> = None;

    for line in tcp_content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // fields[1] = local_address (hex_ip:hex_port)
        // fields[3] = state (0A = LISTEN)
        // fields[9] = inode
        if fields[3] != "0A" {
            continue; // Not LISTEN
        }
        if let Some(colon) = fields[1].rfind(':') {
            if fields[1][colon + 1..] == hex_port {
                target_inode = fields[9].parse().ok();
                break;
            }
        }
    }

    let inode = target_inode?;

    // 2. Scan /proc/*/fd/ for a socket with that inode
    let expected = format!("socket:[{}]", inode);
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let fd_dir = entry.path().join("fd");
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    if link.to_string_lossy() == expected {
                        let pid: u32 = name_str.parse().ok()?;
                        if pid < 2 {
                            return None;
                        }
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The alias file is best-effort state: a corrupt or absent one must not
    /// stop the proxy booting, because aliases are additive routing and losing
    /// them degrades to site-domain-only rather than to no service.
    #[test]
    fn malformed_alias_file_is_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("aliases.json");

        std::fs::write(&path, "{ this is not json").unwrap();
        assert!(read_aliases_from(&path).is_empty());

        std::fs::write(&path, r#"{"a.example.com":"app-one"}"#).unwrap();
        let aliases = read_aliases_from(&path);
        assert_eq!(
            aliases.get("a.example.com").map(String::as_str),
            Some("app-one")
        );
    }

    /// A path carve-out on an app-managed domain must survive `sync_routes`.
    ///
    /// This is a regression with a face: `eui.solisoft.net/_eui/* ->
    /// https://eui-data.solisoft.net/_eui/` is how a page on one site opens an
    /// EUI session served by another, and it is written by hand because no
    /// deployment can write it. Pruning DomainPath deleted it on every restart
    /// and every traffic switch, rewriting proxy.conf without it — so it went
    /// missing during a deploy, which is both the likeliest moment and the
    /// hardest one to attribute.
    #[test]
    fn a_path_carve_out_on_an_app_domain_is_not_pruned() {
        use crate::config::RuleMatcher;

        let whole = RuleMatcher::Domain("eui.solisoft.net".to_string());
        assert_eq!(shadowing_domain(&whole), Some("eui.solisoft.net"));

        let carve_out =
            RuleMatcher::DomainPath("eui.solisoft.net".to_string(), "/_eui/".to_string());
        assert_eq!(
            shadowing_domain(&carve_out),
            None,
            "a path carve-out claims one prefix, not the domain, so it shadows no app"
        );
    }

    /// The other matchers were never pruned and must stay that way: a bare
    /// path rule carries no domain to match an app against, and `default`
    /// exists to catch what nothing else did.
    #[test]
    fn rules_without_a_domain_are_never_pruned() {
        use crate::config::RuleMatcher;

        assert_eq!(
            shadowing_domain(&RuleMatcher::Prefix("/_eui/".to_string())),
            None
        );
        assert_eq!(
            shadowing_domain(&RuleMatcher::Exact("/health".to_string())),
            None
        );
        assert_eq!(shadowing_domain(&RuleMatcher::Default), None);
    }

    #[test]
    fn missing_alias_file_yields_an_empty_table() {
        let temp_dir = TempDir::new().unwrap();
        assert!(read_aliases_from(&temp_dir.path().join("absent.json")).is_empty());
    }

    /// The constant the running proxy reads, so the split above cannot drift into
    /// testing a path production never uses.
    #[test]
    fn the_default_alias_path_is_the_one_the_proxy_reads() {
        assert_eq!(ALIASES_FILE, "./run/aliases.json");
    }

    #[test]
    fn idle_timeout_is_absent_zero_or_seconds() {
        // Three distinct states, and the difference between the first two is
        // the whole point: `None` inherits the fleet default from config.toml,
        // `Some(0)` pins the app awake even under such a default.
        let dir = TempDir::new().unwrap();
        let inherit = write_app(&dir, "inherit.example.com", "");
        assert_eq!(
            AppInfo::from_path(&inherit, false, false)
                .unwrap()
                .config
                .idle_timeout,
            None
        );
        let pinned = write_app(&dir, "pinned.example.com", "idle_timeout = 0\n");
        assert_eq!(
            AppInfo::from_path(&pinned, false, false)
                .unwrap()
                .config
                .idle_timeout,
            Some(0)
        );
        let sleepy = write_app(&dir, "sleepy.example.com", "idle_timeout = 900\n");
        assert_eq!(
            AppInfo::from_path(&sleepy, false, false)
                .unwrap()
                .config
                .idle_timeout,
            Some(900)
        );
    }

    /// A tenant's `app.infos` used to be read with `read_to_string` on an
    /// async worker under the global apps lock: a FIFO hung all routing, and
    /// a symlink to `/dev/zero` grew the proxy until it was OOM-killed — at
    /// every boot. Every one of those must now fail fast, as a load error.
    #[test]
    fn hostile_app_infos_fail_fast() {
        let dir = TempDir::new().unwrap();
        let site = |name: &str| {
            let path = dir.path().join(name);
            std::fs::create_dir_all(&path).unwrap();
            path
        };

        let fifo = site("fifo.example.com");
        let c_path =
            std::ffi::CString::new(fifo.join("app.infos").to_str().unwrap().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        // On a thread, so a regression shows up as a failure, not a hang.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(AppInfo::from_path(&fifo, false, false).is_err());
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(true),
            "a FIFO app.infos must be refused without blocking"
        );

        let zero = site("zero.example.com");
        std::os::unix::fs::symlink("/dev/zero", zero.join("app.infos")).unwrap();
        for multi_tenant in [false, true] {
            let err = AppInfo::from_path(&zero, false, multi_tenant).unwrap_err();
            let err = format!("{err:#}");
            assert!(
                err.contains("not a regular file") || err.contains("symlink"),
                "{err}"
            );
        }

        let huge = site("huge.example.com");
        std::fs::write(
            huge.join("app.infos"),
            format!("# {}\n", "x".repeat(MAX_TENANT_FILE_BYTES as usize)),
        )
        .unwrap();
        assert!(AppInfo::from_path(&huge, false, false).is_err());

        // A symlink to a real manifest: followed for the operator, refused
        // for a tenant (it could name another tenant's file, or a host file
        // a TOML error would quote into the log).
        let linked = site("linked.example.com");
        let real = dir.path().join("shared.infos");
        std::fs::write(&real, "workers = 3\n").unwrap();
        std::os::unix::fs::symlink(&real, linked.join("app.infos")).unwrap();
        assert_eq!(
            AppInfo::from_path(&linked, false, false)
                .unwrap()
                .config
                .workers,
            3
        );
        assert!(AppInfo::from_path(&linked, false, true).is_err());
    }

    /// Year-long timeouts would pin a draining slot (and its memory) for as
    /// long as the tenant likes.
    #[test]
    fn timeouts_are_bounded() {
        let dir = TempDir::new().unwrap();
        let path = write_app(
            &dir,
            "slow.example.com",
            "graceful_timeout = 4000000000\ndrain_delay = 4000000000\n",
        );
        let config = AppInfo::from_path(&path, false, true).unwrap().config;
        assert_eq!(config.graceful_timeout, MAX_APP_TIMEOUT_SECS);
        assert!(config.drain_delay < config.graceful_timeout);
    }

    /// A tenant (or a typo) must not point slots at a privileged port, the
    /// proxy's own listeners, or an unbounded range.
    #[test]
    fn port_ranges_are_validated() {
        let reserved = [80, 443, 9090];
        assert_eq!(port_range_problem(20000, 30000, &reserved), None);
        assert!(port_range_problem(5432, 5432, &reserved).is_some());
        assert!(port_range_problem(80, 2000, &reserved).is_some());
        assert!(port_range_problem(9000, 9100, &reserved)
            .unwrap()
            .contains("9090"));
        assert!(port_range_problem(30000, 20000, &reserved).is_some());
        assert!(port_range_problem(1024, 65535, &reserved).is_some());

        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[server]\nbind = \"0.0.0.0:8080\"\nhttps_port = 8443\n\n\
             [admin]\nbind = \"127.0.0.1:9091\"\n",
        )
        .unwrap();
        let cfg =
            crate::config::ConfigManager::new(dir.path().join("proxy.conf").to_str().unwrap())
                .unwrap()
                .get_config();
        let mut ports = proxy_listener_ports(&cfg);
        ports.sort_unstable();
        assert_eq!(ports, vec![8080, 8443, 9091]);
    }

    /// Multi-tenant: the tenant's range is ignored for the platform's.
    /// Single-tenant: the app's own range, unless it is unusable.
    #[tokio::test]
    async fn tenant_port_ranges_are_platform_owned() {
        for multi_tenant in [true, false] {
            let temp_dir = TempDir::new().unwrap();
            let sites = temp_dir.path().join("sites");
            std::fs::create_dir_all(&sites).unwrap();
            std::fs::write(
                temp_dir.path().join("config.toml"),
                format!(
                    "[apps]\nmulti_tenant = {multi_tenant}\nport_range_start = 34000\n\
                     port_range_end = 34099\n"
                ),
            )
            .unwrap();
            let manager = test_manager(&temp_dir, &sites);
            let mut config = AppConfig {
                name: "app.example.com".to_string(),
                port_range_start: 35000,
                port_range_end: 35099,
                ..AppConfig::default()
            };
            let expected = if multi_tenant {
                (34000, 34099)
            } else {
                (35000, 35099)
            };
            assert_eq!(manager.port_range_for(&config), expected);
            // Privileged ports: never, in either mode.
            config.port_range_start = 80;
            config.port_range_end = 81;
            assert_eq!(manager.port_range_for(&config), (34000, 34099));
        }
    }

    fn write_app(dir: &TempDir, name: &str, manifest: &str) -> std::path::PathBuf {
        let app_path = dir.path().join(name);
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("app.infos"), manifest).unwrap();
        app_path
    }

    #[test]
    fn app_infos_parses_the_auth_section() {
        let dir = TempDir::new().unwrap();
        let path = write_app(
            &dir,
            "shop.example.com",
            r#"
name = "shop.example.com"
domain = "shop.example.com"

[auth]
noauth = ["/webhooks/stripe", "/hooks/*"]

[auth.users]
admin = "$2b$12$adminhashadminhashadminhashadminhashadminhashadminhas"
qa = "$2b$12$qahashqahashqahashqahashqahashqahashqahashqahashqahas"
"#,
        );

        let info = AppInfo::from_path(&path, false, false).unwrap();
        let auth = &info.config.auth;
        // Table order is normalised, so the list is stable across runs.
        assert_eq!(
            auth.users
                .iter()
                .map(|u| u.username.as_str())
                .collect::<Vec<_>>(),
            vec!["admin", "qa"]
        );
        assert_eq!(
            auth.users[0].hash,
            "$2b$12$adminhashadminhashadminhashadminhashadminhashadminhas"
        );
        assert_eq!(auth.noauth, vec!["/webhooks/stripe", "/hooks/*"]);
    }

    /// An app with no `[auth]` section is unprotected, exactly as before.
    #[test]
    fn app_infos_without_auth_requires_no_credentials() {
        let dir = TempDir::new().unwrap();
        let path = write_app(
            &dir,
            "open.example.com",
            "name = \"open.example.com\"\ndomain = \"open.example.com\"\n",
        );
        let info = AppInfo::from_path(&path, false, false).unwrap();
        assert!(info.config.auth.users.is_empty());
        assert!(!info.config.auth.requires_auth("/"));
    }

    #[test]
    fn app_auth_exempts_noauth_paths_and_fails_closed() {
        let auth = AppAuth {
            users: vec![crate::auth::BasicAuth {
                username: "admin".to_string(),
                hash: "$2b$12$hash".to_string(),
            }],
            noauth: vec!["/webhooks/stripe".to_string(), "/hooks/*".to_string()],
            forward: None,
        };

        assert!(!auth.requires_auth("/webhooks/stripe"));
        assert!(!auth.requires_auth("/hooks/github"));
        assert!(!auth.requires_auth("/hooks"));
        // Everything else on the app stays protected.
        assert!(auth.requires_auth("/"));
        assert!(auth.requires_auth("/admin"));
        assert!(auth.requires_auth("/webhooks/stripe/inner"));
        // Same fail-closed rule as the route directive: a path that does not
        // compare literally is never exempt.
        assert!(auth.requires_auth("/hooks/../admin"));
        assert!(auth.requires_auth("/hooks/%2e%2e/admin"));
    }

    /// A manifest whose auth cannot be enforced as written must fail to load:
    /// the app is skipped and logged, rather than served wide open while the
    /// operator believes a password is in place.
    #[test]
    fn app_infos_with_unusable_auth_is_rejected() {
        let dir = TempDir::new().unwrap();

        for (case, section) in [
            ("empty hash", "[auth.users]\nadmin = \"\"\n"),
            // Un locataire ne choisit pas le facteur de cout du proxy :
            // `$2b$31$` coute des jours de CPU par requete.
            (
                "tenant-chosen cost",
                "[auth.users]\nadmin = \"$2b$31$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            ),
            ("malformed hash", "[auth.users]\nadmin = \"$2b$12$short\"\n"),
            (
                "traversing noauth",
                "noauth = [\"/a/../b\"]\n\n[auth.users]\nadmin = \"$2b$12$hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh\"\n",
            ),
            (
                "relative noauth",
                "noauth = [\"hooks\"]\n\n[auth.users]\nadmin = \"$2b$12$hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh\"\n",
            ),
            (
                "encoded noauth",
                "noauth = [\"/c%2f\"]\n\n[auth.users]\nadmin = \"$2b$12$hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh\"\n",
            ),
        ] {
            let path = write_app(
                &dir,
                "bad.example.com",
                &format!(
                    "name = \"bad.example.com\"\ndomain = \"bad.example.com\"\n\n[auth]\n{}",
                    section
                ),
            );
            assert!(
                AppInfo::from_path(&path, false, false).is_err(),
                "{case} must be rejected"
            );
        }
    }

    #[test]
    fn app_infos_parses_forward_auth() {
        let dir = TempDir::new().unwrap();
        let path = write_app(
            &dir,
            "sso.example.com",
            r#"
name = "sso.example.com"
domain = "sso.example.com"

[auth]
noauth = ["/up"]
forward = "http://auth.internal:4180/oauth2/auth"
forward_headers = ["X-Auth-Request-User", "X-Auth-Request-Email"]
"#,
        );
        let info = AppInfo::from_path(&path, false, false).unwrap();
        let auth = &info.config.auth;
        assert!(auth.users.is_empty());
        assert!(auth.is_active());
        // No accounts: Basic Auth is off, forward-auth gates the app.
        assert!(!auth.requires_auth("/"));
        assert!(auth.is_exempt("/up"));
        let forward = auth.forward.as_ref().unwrap();
        assert_eq!(forward.url(), "http://auth.internal:4180/oauth2/auth");
        assert_eq!(forward.copy_headers().len(), 2);

        let json = serde_json::to_value(auth).unwrap();
        assert_eq!(json["forward"], "http://auth.internal:4180/oauth2/auth");
        assert_eq!(
            json["forward_headers"],
            serde_json::json!(["x-auth-request-user", "x-auth-request-email"])
        );

        for (case, section) in [
            ("headers without a URL", "forward_headers = [\"X-User\"]\n"),
            ("not http", "forward = \"file:///etc/passwd\"\n"),
            ("no host", "forward = \"http://\"\n"),
            ("credentials", "forward = \"http://u:p@auth/verify\"\n"),
            (
                "a managed header",
                "forward = \"http://auth/verify\"\nforward_headers = [\"Host\"]\n",
            ),
            ("unknown key", "forward_url = \"http://auth/verify\"\n"),
        ] {
            let path = write_app(
                &dir,
                "bad.example.com",
                &format!(
                    "name = \"bad.example.com\"\ndomain = \"bad.example.com\"\n\n[auth]\n{}",
                    section
                ),
            );
            assert!(
                AppInfo::from_path(&path, false, false).is_err(),
                "{case} must be rejected"
            );
        }
    }

    /// The admin API must never hand back password hashes — the route-auth
    /// endpoints have the same contract.
    #[test]
    fn serialized_app_auth_carries_usernames_but_no_hashes() {
        let auth = AppAuth {
            users: vec![crate::auth::BasicAuth {
                username: "admin".to_string(),
                hash: "$2b$12$supersecret".to_string(),
            }],
            noauth: vec!["/hooks/*".to_string()],
            forward: None,
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("admin"), "{json}");
        assert!(json.contains("/hooks/*"), "{json}");
        assert!(!json.contains("supersecret"), "{json}");
        assert!(!json.contains("$2b$12$"), "{json}");
    }

    #[tokio::test]
    async fn test_app_info_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("test.solisoft.net");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_infos = r#"
name = "test.solisoft.net"
domain = "test.solisoft.net"
start_script = "./start.sh"
stop_script = "./stop.sh"
health_check = "/health"
graceful_timeout = 30
port_range_start = 20000
port_range_end = 30000
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.name, "test.solisoft.net");
        assert_eq!(app_info.config.domain, "test.solisoft.net");
        assert_eq!(app_info.config.start_script, Some("./start.sh".to_string()));
    }

    #[test]
    fn test_dev_domain() {
        assert_eq!(
            dev_domain("soli.solisoft.net"),
            Some("soli.solisoft.test".to_string())
        );
        assert_eq!(
            dev_domain("app.example.com"),
            Some("app.example.test".to_string())
        );
        assert_eq!(dev_domain("example.org"), Some("example.test".to_string()));
        // Already .test — skip
        assert_eq!(dev_domain("app.example.test"), None);
        // .localhost — skip
        assert_eq!(dev_domain("app.localhost"), None);
        // No dot at all
        assert_eq!(dev_domain("localhost"), None);
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("www.solisoft.net"));
        assert!(is_valid_domain("solisoft.net"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("_admin"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("myapp"));
        assert!(!is_valid_domain(".claude"));
        assert!(!is_valid_domain(".hidden"));
    }

    #[test]
    fn test_strip_www() {
        assert_eq!(
            strip_www("www.solisoft.net"),
            Some("solisoft.net".to_string())
        );
        assert_eq!(
            strip_www("www.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(strip_www("solisoft.net"), None);
        assert_eq!(strip_www("www."), None);
        assert_eq!(strip_www("wwww.solisoft.net"), None);
    }

    #[test]
    fn test_is_acme_eligible_excludes_dev() {
        assert!(!is_acme_eligible("app.example.test"));
        assert!(!is_acme_eligible("localhost"));
        assert!(!is_acme_eligible("app.localhost"));
        assert!(is_acme_eligible("app.example.com"));
    }

    #[test]
    fn test_luaonbeans_auto_detected_no_app_infos() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("luaonbeans.org"), b"").unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.name, "myapp.example.com");
        assert_eq!(app_info.config.domain, "myapp.example.com");
        assert_eq!(
            app_info.config.start_script,
            Some("./luaonbeans.org -D . -p $PORT -s".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/".to_string()));
    }

    /// Single-tenant: the operator wrote `app.infos`, so `domain` may differ
    /// from the directory name. (Multi-tenant binds it — see
    /// `multi_tenant_rejects_domain_not_bound_to_directory`.)
    #[test]
    fn test_luaonbeans_auto_detected_with_partial_app_infos() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("luaonbeans.org"), b"").unwrap();

        let app_infos = r#"
name = "myapp.example.com"
domain = "custom.example.com"
graceful_timeout = 30
port_range_start = 20000
port_range_end = 30000
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.name, "myapp.example.com");
        assert_eq!(app_info.config.domain, "custom.example.com");
        assert_eq!(
            app_info.config.start_script,
            Some("./luaonbeans.org -D . -p $PORT -s".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/".to_string()));
    }

    fn site_with_app_infos(sites: &Path, dir: &str, app_infos: &str) -> PathBuf {
        let app_path = sites.join(dir);
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();
        app_path
    }

    /// One manifest, two environments: `--dev` takes `[development]` and
    /// everything else takes `[production]`.
    #[test]
    fn env_overlay_follows_dev_mode() {
        let manifest = r#"
name = "app.example.com"
workers = 4
idle_timeout = 1800

[development]
workers = 1
idle_timeout = 0

[production]
workers = 8
"#;

        let dev = parse_app_infos(manifest, true, "app.example.com").unwrap();
        assert_eq!(dev.workers, 1);
        assert_eq!(dev.idle_timeout, Some(0));

        let prod = parse_app_infos(manifest, false, "app.example.com").unwrap();
        assert_eq!(prod.workers, 8);
        // Untouched by `[production]`, so the top-level value stands.
        assert_eq!(prod.idle_timeout, Some(1800));
        // And neither section leaks into the other.
        assert_eq!(prod.name, "app.example.com");
    }

    /// Every manifest written before the sections existed must parse to
    /// exactly what it parsed to before — the overlay is opt-in or it is a
    /// migration.
    #[test]
    fn manifest_without_env_sections_is_unchanged() {
        let manifest = r#"
name = "app.example.com"
domain = "app.example.com"
start_script = "soli serve . --port $PORT --workers $WORKERS"
workers = 2
health_check = "/health"
graceful_timeout = 30
port_range_start = 20000
port_range_end = 30000
"#;

        for dev_mode in [true, false] {
            let config = parse_app_infos(manifest, dev_mode, "app.example.com").unwrap();
            assert_eq!(config.workers, 2);
            assert_eq!(config.graceful_timeout, 30);
            assert_eq!(config.health_check.as_deref(), Some("/health"));
            assert_eq!(config.port_range_start, 20000);
            assert_eq!(config.idle_timeout, None);
        }
    }

    /// A section merges into its top-level counterpart key by key. Replacing
    /// it wholesale would mean `[production.auth.users]` silently dropping the
    /// `noauth` list — an app's webhook path losing its exemption because
    /// somebody added a password.
    #[test]
    fn env_overlay_merges_nested_sections() {
        let manifest = r#"
name = "app.example.com"

[auth]
noauth = ["/webhooks/stripe"]

[production.auth.users]
admin = "$2b$12$hash"
"#;

        let prod = parse_app_infos(manifest, false, "app.example.com").unwrap();
        assert_eq!(prod.auth.noauth, vec!["/webhooks/stripe".to_string()]);
        assert_eq!(prod.auth.users.len(), 1);
        assert_eq!(prod.auth.users[0].username, "admin");

        // In dev the section is not applied, so the app has no accounts.
        let dev = parse_app_infos(manifest, true, "app.example.com").unwrap();
        assert_eq!(dev.auth.noauth, vec!["/webhooks/stripe".to_string()]);
        assert!(dev.auth.users.is_empty());
    }

    /// The inactive section is dropped unread, so a `[production]` written for
    /// a newer proxy does not stop a developer's machine from starting the
    /// app.
    #[test]
    fn inactive_env_section_is_not_validated() {
        let manifest = r#"
name = "app.example.com"

[production]
some_setting_from_the_future = { nested = true }
"#;
        assert!(parse_app_infos(manifest, true, "app.example.com").is_ok());
    }

    /// `development = 1` is a typo with a plausible shape; saying so beats
    /// serde's "invalid type" on a key the operator thinks is a section.
    #[test]
    fn env_section_must_be_a_table() {
        let err = parse_app_infos("development = 1\n", true, "app.example.com").unwrap_err();
        assert!(err.to_string().contains("must be a section"), "{}", err);
    }

    /// An unrecognised key has always been ignored. It still is — the app
    /// loads — and the warning is what is new.
    #[test]
    fn unknown_keys_are_ignored_not_fatal() {
        let manifest = r#"
name = "app.example.com"
worker = 4

[development]
typo_here = true
"#;
        let config = parse_app_infos(manifest, true, "app.example.com").unwrap();
        assert_eq!(config.workers, 1);
    }

    /// `KNOWN_ROOT_KEYS` drives the warning, so a field added to `AppConfig`
    /// without being listed would make that field itself look unknown.
    #[test]
    fn known_root_keys_match_app_config() {
        // Every `Option` set, so nothing is skipped on the way out. Written as
        // a full literal on purpose: adding a field to `AppConfig` breaks this
        // line until the list below is updated too.
        let config = AppConfig {
            name: "app.example.com".to_string(),
            domain: "app.example.com".to_string(),
            start_script: Some("soli serve .".to_string()),
            stop_script: Some("true".to_string()),
            health_check: Some("/up".to_string()),
            graceful_timeout: 30,
            drain_delay: 5,
            port_range_start: 20000,
            port_range_end: 30000,
            workers: 1,
            user: Some("rocky".to_string()),
            group: Some("rocky".to_string()),
            docker_image: Some("alpine".to_string()),
            docker_options: Some("--rm".to_string()),
            docker_network: Some("soli-apps".to_string()),
            auth: AppAuth::default(),
            idle_timeout: Some(0),
            compress: Some(false),
        };

        let toml::Value::Table(table) = toml::Value::try_from(config).unwrap() else {
            panic!("AppConfig serializes to a table");
        };
        let mut serialized: Vec<&str> = table.keys().map(String::as_str).collect();
        serialized.sort_unstable();
        let mut known = KNOWN_ROOT_KEYS.to_vec();
        known.sort_unstable();
        assert_eq!(serialized, known);
    }

    /// The overlay reaches apps through discovery, not only through the
    /// parser — `from_path` passes the mode it was given.
    #[test]
    fn from_path_applies_the_env_overlay() {
        let temp_dir = TempDir::new().unwrap();
        let path = site_with_app_infos(
            temp_dir.path(),
            "app.example.com",
            "name = \"app.example.com\"\nworkers = 4\n\n[development]\nworkers = 1\n",
        );

        assert_eq!(
            AppInfo::from_path(&path, true, false)
                .unwrap()
                .config
                .workers,
            1
        );
        assert_eq!(
            AppInfo::from_path(&path, false, false)
                .unwrap()
                .config
                .workers,
            4
        );
    }

    /// Multi-tenant: `domain` is tenant input. A tenant in `evil.example.com/`
    /// declaring `domain = "victim.example.com"` would otherwise be routed
    /// the victim's `Host` and prune the victim's static rule.
    #[test]
    fn multi_tenant_rejects_domain_not_bound_to_directory() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path();

        let hijack = site_with_app_infos(
            sites,
            "evil.example.com",
            "domain = \"victim.example.com\"\n",
        );
        let err = AppInfo::from_path(&hijack, false, true).unwrap_err();
        assert!(err.to_string().contains("domain"), "{}", err);
        // ...but the same manifest is still accepted single-tenant.
        assert!(AppInfo::from_path(&hijack, false, false).is_ok());

        // Own domain, its www. twin and no domain at all are fine.
        for domain in ["evil.example.com", "www.evil.example.com", ""] {
            let ok = site_with_app_infos(
                sites,
                "evil.example.com",
                &format!("domain = \"{}\"\n", domain),
            );
            assert!(
                AppInfo::from_path(&ok, false, true).is_ok(),
                "domain {:?} should be accepted",
                domain
            );
        }
    }

    /// Multi-tenant: `name` keys the apps map, so a tenant naming itself after
    /// another directory would merge into (and take over) that app's entry.
    #[test]
    fn multi_tenant_rejects_name_not_bound_to_directory() {
        let temp_dir = TempDir::new().unwrap();
        let path = site_with_app_infos(
            temp_dir.path(),
            "evil.example.com",
            "name = \"victim.example.com\"\n",
        );
        let err = AppInfo::from_path(&path, false, true).unwrap_err();
        assert!(err.to_string().contains("name"), "{}", err);
        assert!(AppInfo::from_path(&path, false, false).is_ok());

        let own = site_with_app_infos(
            temp_dir.path(),
            "evil.example.com",
            "name = \"evil.example.com\"\n",
        );
        assert!(AppInfo::from_path(&own, false, true).is_ok());
    }

    /// `_`-prefixed names are the bundled apps' namespace (`_admin`). Only a
    /// directory that itself starts with `_` may use one, in either mode.
    #[test]
    fn underscore_names_are_reserved_for_bundled_directories() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path();

        let impostor = site_with_app_infos(sites, "evil.example.com", "name = \"_admin\"\n");
        assert!(AppInfo::from_path(&impostor, false, false).is_err());
        assert!(AppInfo::from_path(&impostor, false, true).is_err());

        let bundled = site_with_app_infos(sites, "_admin", "name = \"_admin\"\ndomain = \"\"\n");
        let app = AppInfo::from_path(&bundled, false, true).unwrap();
        assert_eq!(app.config.name, "_admin");
        assert_eq!(app.config.domain, "");
    }

    /// `name`/`domain` reach container names, log paths and the admin UI:
    /// hostname charset only, in both modes.
    #[test]
    fn name_and_domain_must_be_hostnames() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path();
        for manifest in [
            "name = \"<script>alert(1)</script>\"\n",
            "name = \"a b.example.com\"\n",
            "name = \"a/b.example.com\"\n",
            "domain = \"<img src=x onerror=alert(1)>\"\n",
            "domain = \"evil.example.com;rm\"\n",
            "domain = \"пример.example.com\"\n",
        ] {
            let path = site_with_app_infos(sites, "app.example.com", manifest);
            assert!(
                AppInfo::from_path(&path, false, false).is_err(),
                "should reject {:?}",
                manifest
            );
        }
        let path = site_with_app_infos(
            sites,
            "app.example.com",
            "name = \"App-1.example.com\"\ndomain = \"www.app.example.com\"\n",
        );
        assert!(AppInfo::from_path(&path, false, false).is_ok());

        // Underscores were accepted before this check existed (only a dot was
        // required) and existing `sites/my_app.example.com` directories must
        // keep loading after an upgrade.
        let path = site_with_app_infos(
            sites,
            "my_app.example.com",
            "name = \"my_app.example.com\"\ndomain = \"my_app.example.com\"\n",
        );
        assert!(AppInfo::from_path(&path, false, false).is_ok());
        assert!(AppInfo::from_path(&path, false, true).is_ok());
    }

    /// `health_check` is interpolated into a URL and exported as an env var.
    #[test]
    fn health_check_must_be_a_url_path() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path();
        for health_check in [
            "health",
            "",
            "/health\"><script>",
            "/health <b>",
            "/health\n",
            "http://evil.example.com/",
        ] {
            let path = site_with_app_infos(
                sites,
                "app.example.com",
                &format!("health_check = {:?}\n", health_check),
            );
            assert!(
                AppInfo::from_path(&path, false, false).is_err(),
                "should reject {:?}",
                health_check
            );
        }
        for health_check in ["/", "/up", "/health?deep=1&x=a%20b", "/v1/_status.json"] {
            let path = site_with_app_infos(
                sites,
                "app.example.com",
                &format!("health_check = {:?}\n", health_check),
            );
            assert!(
                AppInfo::from_path(&path, false, false).is_ok(),
                "should accept {:?}",
                health_check
            );
        }
    }

    fn running_app(name: &str, domain: &str, port: u16) -> AppInfo {
        let instance = |slot: &str, port: u16, pid: Option<u32>| AppInstance {
            name: name.to_string(),
            slot: slot.to_string(),
            port,
            pid,
            status: InstanceStatus::Running,
            last_started: None,
        };
        AppInfo {
            config: AppConfig {
                name: name.to_string(),
                domain: domain.to_string(),
                ..AppConfig::default()
            },
            path: PathBuf::from(format!("/srv/sites/{}", name)),
            blue: instance("blue", port, Some(4242)),
            green: instance("green", port + 1, None),
            current_slot: "blue".to_string(),
            quarantined: false,
            maintenance: false,
            error_pages: None,
        }
    }

    /// Two apps claiming one domain: the first (by name) keeps it; the second
    /// must not overwrite the routing entry, whatever the map's iteration
    /// order.
    #[test]
    fn duplicate_domain_keeps_first_app() {
        let mut apps = HashMap::new();
        apps.insert(
            "victim.example.com".to_string(),
            running_app("victim.example.com", "victim.example.com", 20000),
        );
        apps.insert(
            "zzz-evil.example.com".to_string(),
            running_app("zzz-evil.example.com", "victim.example.com", 21000),
        );

        let port_of = |routes: &AppRoutes, host: &str| routes.get(host).map(|r| r.port);
        for _ in 0..8 {
            let routes = build_routes(&apps, &HashMap::new(), false, &mut HashMap::new());
            assert_eq!(port_of(&routes, "victim.example.com"), Some(20000));
        }

        // A derived domain (www-stripped) cannot displace an app's own one either.
        apps.insert(
            "www.victim.example.com".to_string(),
            running_app("www.victim.example.com", "www.victim.example.com", 22000),
        );
        let routes = build_routes(&apps, &HashMap::new(), false, &mut HashMap::new());
        assert_eq!(port_of(&routes, "victim.example.com"), Some(20000));
        assert_eq!(port_of(&routes, "www.victim.example.com"), Some(22000));
    }

    /// The `www.` hijack: `www.victim.example.com/` derives the apex
    /// `victim.example.com`. While the victim app ran, the declared claim
    /// won; the moment it stopped, routing (running apps only) handed the
    /// apex to the `www.` app while the auth lookup (all apps) still answered
    /// with the victim's `[auth]` — or the reverse, none. Ownership no longer
    /// depends on running state, and everything comes from the one entry.
    #[test]
    fn a_stopped_app_keeps_its_domain_from_a_www_twin() {
        let mut victim = running_app("victim.example.com", "victim.example.com", 20000);
        victim.blue.pid = None;
        victim.config.auth.users = vec![crate::auth::BasicAuth {
            username: "admin".to_string(),
            hash: "$2b$12$hash".to_string(),
        }];
        let mut apps = HashMap::new();
        apps.insert("victim.example.com".to_string(), victim);
        apps.insert(
            "www.victim.example.com".to_string(),
            running_app("www.victim.example.com", "www.victim.example.com", 22000),
        );

        let routes = build_routes(&apps, &HashMap::new(), false, &mut HashMap::new());
        let apex = routes.get("victim.example.com").unwrap();
        assert_eq!(&*apex.app, "victim.example.com");
        assert_eq!(apex.claim, Claim::Declared);
        assert!(apex.target.is_none(), "stopped: owned, but not served");
        let www = routes.get("www.victim.example.com").unwrap();
        assert_eq!(&*www.app, "www.victim.example.com");
        assert!(www.auth.is_none());
    }

    /// Declared beats alias beats derived, and an alias resolves to its own
    /// app even when that app's declared domain went to someone else.
    #[test]
    fn claims_are_ranked_declared_alias_derived() {
        let mut apps = HashMap::new();
        apps.insert(
            "aaa.example.com".to_string(),
            running_app("aaa.example.com", "www.shop.example.com", 20000),
        );
        apps.insert(
            "zzz.example.com".to_string(),
            running_app("zzz.example.com", "zzz.example.com", 21000),
        );
        let aliases: HashMap<String, String> = [
            (
                "shop.example.com".to_string(),
                "zzz.example.com".to_string(),
            ),
            ("zzz.example.com".to_string(), "aaa.example.com".to_string()),
        ]
        .into_iter()
        .collect();

        let routes = build_routes(&apps, &aliases, false, &mut HashMap::new());
        // The alias outranks aaa's derived apex...
        let shop = routes.get("shop.example.com").unwrap();
        assert_eq!((&*shop.app, shop.claim), ("zzz.example.com", Claim::Alias));
        assert_eq!(shop.port, 21000);
        // ...and cannot shadow a declared domain.
        let zzz = routes.get("zzz.example.com").unwrap();
        assert_eq!((&*zzz.app, zzz.claim), ("zzz.example.com", Claim::Declared));
        // Slot ports attribute requests to their app.
        assert_eq!(
            routes.ports.get(&20001).map(|a| &**a),
            Some("aaa.example.com")
        );
    }

    #[test]
    fn loopback_port_reads_only_local_targets() {
        assert_eq!(loopback_port("http://127.0.0.1:20001/x?y"), Some(20001));
        assert_eq!(loopback_port("http://localhost:20001"), Some(20001));
        assert_eq!(loopback_port("http://10.0.0.5:20001/"), None);
        assert_eq!(loopback_port("http://127.0.0.1/"), None);
        assert_eq!(loopback_port("garbage"), None);
    }

    /// Multi-tenant: a claim derived from tenant input (`www.example.com/`'s
    /// apex) does not take an operator's static rule for that apex, while a
    /// declared domain still does. Single-tenant keeps both.
    #[tokio::test]
    async fn multi_tenant_derived_claim_does_not_override_a_static_rule() {
        for multi_tenant in [true, false] {
            let temp_dir = TempDir::new().unwrap();
            let sites = temp_dir.path().join("sites");
            site_with_app_infos(
                &sites,
                "www.example.com",
                "name = \"www.example.com\"\ndomain = \"www.example.com\"\n",
            );
            std::fs::write(
                temp_dir.path().join("config.toml"),
                format!("[apps]\nmulti_tenant = {multi_tenant}\n"),
            )
            .unwrap();
            let manager = test_manager(&temp_dir, &sites);
            manager.discover_apps_readonly().await.unwrap();

            assert!(manager.overrides_domain_rule("www.example.com").await);
            assert_eq!(
                manager.overrides_domain_rule("example.com").await,
                !multi_tenant,
                "multi_tenant = {multi_tenant}"
            );
            // The derived host is still the app's when no rule claims it.
            assert_eq!(
                manager.app_name_for_host("example.com").await.as_deref(),
                Some("www.example.com")
            );
        }
    }

    /// In multi_tenant mode `[auth] forward` is a URL the tenant makes the
    /// proxy fetch: only the operator's `[forward_auth] allowed_urls` load.
    #[tokio::test]
    async fn multi_tenant_forward_auth_must_be_allowlisted() {
        for multi_tenant in [true, false] {
            let temp_dir = TempDir::new().unwrap();
            let sites = temp_dir.path().join("sites");
            site_with_app_infos(
                &sites,
                "allowed.example.com",
                "name = \"allowed.example.com\"\ndomain = \"allowed.example.com\"\n\n\
                 [auth]\nforward = \"http://auth.internal:4180/oauth2/auth\"\n",
            );
            site_with_app_infos(
                &sites,
                "ssrf.example.com",
                "name = \"ssrf.example.com\"\ndomain = \"ssrf.example.com\"\n\n\
                 [auth]\nforward = \"http://169.254.169.254/latest/meta-data/\"\n",
            );
            std::fs::write(
                temp_dir.path().join("config.toml"),
                format!(
                    "[apps]\nmulti_tenant = {multi_tenant}\n\n[forward_auth]\n\
                     allowed_urls = [\"http://auth.internal:4180/oauth2/\"]\n"
                ),
            )
            .unwrap();
            let manager = test_manager(&temp_dir, &sites);
            manager.discover_apps_readonly().await.unwrap();
            mark_running(&manager, "allowed.example.com").await;

            assert!(manager
                .auth_for_host("allowed.example.com")
                .await
                .is_some_and(|auth| auth.forward.is_some()));
            // Refused in multi_tenant mode; the operator's own manifest
            // (single-tenant) may name any auth service.
            assert_eq!(
                manager
                    .app_name_for_host("ssrf.example.com")
                    .await
                    .is_some(),
                !multi_tenant,
                "multi_tenant = {multi_tenant}"
            );
        }
    }

    /// Two site directories that resolve to one app name (single-tenant, where
    /// `name` is free-form): the second is skipped, and the first entry keeps
    /// The seam the proxy relies on: the `Host` it routes on must resolve to
    /// the same app whose `[auth]` it then enforces — including the derived
    /// `www.`-stripped form and admin-managed aliases, which are routed but
    /// are not the app's declared domain.
    #[tokio::test]
    async fn auth_for_host_resolves_declared_derived_and_aliased_domains() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path().join("sites");
        site_with_app_infos(
            &sites,
            "shop.example.com",
            r#"
name = "shop.example.com"
domain = "www.shop.example.com"

[auth]
noauth = ["/webhooks/stripe"]

[auth.users]
admin = "$2b$12$adminhashadminhashadminhashadminhashadminhashadminhas"
"#,
        );
        site_with_app_infos(
            &sites,
            "open.example.com",
            "name = \"open.example.com\"\ndomain = \"open.example.com\"\n",
        );

        let manager = test_manager(&temp_dir, &sites);
        manager.discover_apps_readonly().await.unwrap();

        // Not running: the hosts are the app's, but nothing is served on
        // them, so there is nothing to protect yet.
        assert!(manager.auth_for_host("shop.example.com").await.is_none());
        mark_running(&manager, "shop.example.com").await;
        mark_running(&manager, "open.example.com").await;

        // Declared domain and its www-stripped twin both carry the auth.
        for host in ["www.shop.example.com", "shop.example.com"] {
            let auth = manager
                .auth_for_host(host)
                .await
                .unwrap_or_else(|| panic!("{host} should be protected"));
            assert_eq!(auth.users[0].username, "admin");
            assert!(auth.requires_auth("/"));
            assert!(!auth.requires_auth("/webhooks/stripe"));
        }

        // An alias is routed to the app, so it inherits the app's auth.
        manager
            .set_alias("alias.example.com", "shop.example.com")
            .await
            .unwrap();
        assert!(manager.auth_for_host("alias.example.com").await.is_some());

        // An app with no [auth] costs nothing and stays open, and an unknown
        // host resolves to no app at all.
        assert!(manager.auth_for_host("open.example.com").await.is_none());
        assert!(manager.auth_for_host("nobody.example.com").await.is_none());
    }

    /// The published table follows the app's state: a slot coming up gives
    /// its hosts a target, stopping it takes the target away (the app keeps
    /// the host), and a routed request restarts the idle clock with a store.
    #[tokio::test]
    async fn the_routing_table_follows_app_state() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path().join("sites");
        site_with_app_infos(
            &sites,
            "live.example.com",
            "name = \"live.example.com\"\ndomain = \"live.example.com\"\n",
        );
        let manager = test_manager(&temp_dir, &sites);
        manager.discover_apps_readonly().await.unwrap();

        let route = manager.routes().get("live.example.com").cloned().unwrap();
        assert!(route.target.is_none());
        assert!(manager
            .resolve_app_request("live.example.com", &|_| true)
            .await
            .is_none());

        mark_running(&manager, "live.example.com").await;
        let resolved = manager
            .resolve_app_request("live.example.com", &|_| true)
            .await
            .unwrap();
        assert_eq!(resolved.app.as_deref(), Some("live.example.com"));
        assert_eq!(resolved.target.url.host_str(), Some("127.0.0.1"));
        let port = resolved.target.url.port().unwrap();
        assert_eq!(
            manager
                .app_for_target_url(&format!("http://127.0.0.1:{port}/x"))
                .await
                .as_deref(),
            Some("live.example.com")
        );
        assert_ne!(
            manager
                .activity_cell("live.example.com")
                .load(Ordering::Relaxed),
            0,
            "a routed request is recorded for scale to zero"
        );

        // PID 4242 was never spawned by this proxy, so stopping the slot
        // signals nothing — but the slot is gone from routing.
        manager.stop("live.example.com").await.unwrap();
        let route = manager.routes().get("live.example.com").cloned().unwrap();
        assert!(route.target.is_none());
        assert_eq!(&*route.app, "live.example.com");
    }

    #[test]
    fn health_verdicts() {
        assert_eq!(health_verdict(200), HealthVerdict::Healthy);
        assert_eq!(health_verdict(204), HealthVerdict::Healthy);
        // Up, but the path is wrong: never a reason to restart the app.
        assert_eq!(health_verdict(404), HealthVerdict::Misconfigured(404));
        assert_eq!(health_verdict(401), HealthVerdict::Misconfigured(401));
        assert!(matches!(health_verdict(500), HealthVerdict::Failed(_)));
        assert!(matches!(health_verdict(503), HealthVerdict::Failed(_)));
    }

    /// One bad answer is not a dead app: failover waits for
    /// `health_failure_threshold` (3) consecutive failures.
    #[tokio::test]
    async fn health_failover_waits_for_consecutive_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\
                              connection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path().join("sites");
        site_with_app_infos(
            &sites,
            "sick.example.com",
            "name = \"sick.example.com\"\nhealth_check = \"/health\"\n",
        );
        let manager = test_manager(&temp_dir, &sites);
        manager.discover_apps_readonly().await.unwrap();
        {
            let mut apps = manager.apps.lock().await;
            let app = apps.get_mut("sick.example.com").unwrap();
            app.blue.port = port;
            app.blue.pid = Some(4242);
            app.current_slot = "blue".to_string();
            manager.publish_routes(&apps);
        }

        for _ in 0..2 {
            manager.check_health().await;
            assert!(!manager.is_quarantined("sick.example.com"));
        }
        // The third failure fails over. This app has no start script, so the
        // failover's deploy fails and quarantines it — the observable sign
        // that it ran.
        manager.check_health().await;
        assert!(manager.is_quarantined("sick.example.com"));
    }

    /// An AppManager over `sites`, with its proxy.conf, config.toml and run
    /// directory inside `temp_dir`.
    fn test_manager(temp_dir: &TempDir, sites: &Path) -> AppManager {
        let config_manager = Arc::new(
            crate::config::ConfigManager::new(temp_dir.path().join("proxy.conf").to_str().unwrap())
                .unwrap(),
        );
        let port_manager =
            Arc::new(PortManager::new(temp_dir.path().join("run").to_str().unwrap()).unwrap());
        AppManager::new(sites.to_str().unwrap(), port_manager, config_manager, false).unwrap()
    }

    /// `maintenance.flag`, `error_pages/` and `compress` reach the routing
    /// table, and a rediscovery after the flag goes away clears it.
    #[tokio::test]
    async fn site_response_settings_reach_the_routing_table() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path().join("sites");
        let site = site_with_app_infos(
            &sites,
            "shop.example.com",
            "name = \"shop.example.com\"\ndomain = \"shop.example.com\"\ncompress = false\n",
        );
        std::fs::create_dir(site.join("error_pages")).unwrap();
        std::fs::write(site.join("error_pages/502.html"), "shop 502").unwrap();
        std::fs::write(site.join(MAINTENANCE_FLAG), "").unwrap();
        site_with_app_infos(
            &sites,
            "plain.example.com",
            "name = \"plain.example.com\"\ndomain = \"plain.example.com\"\n",
        );

        let manager = test_manager(&temp_dir, &sites);
        manager.discover_apps_readonly().await.unwrap();
        assert!(manager.any_maintenance_flag());
        assert!(manager.any_error_pages());
        let routes = manager.routes();
        let shop = routes.get("shop.example.com").unwrap();
        assert!(shop.maintenance);
        assert_eq!(shop.compress, Some(false));
        assert_eq!(
            shop.error_pages.as_ref().unwrap().for_status(502),
            Some("shop 502")
        );
        let plain = routes.get("plain.example.com").unwrap();
        assert!(!plain.maintenance && plain.error_pages.is_none() && plain.compress.is_none());

        mark_running(&manager, "shop.example.com").await;
        let resolved = manager
            .resolve_app_request("shop.example.com", &|_| true)
            .await
            .unwrap();
        assert_eq!(resolved.compress, Some(false));

        std::fs::remove_file(site.join(MAINTENANCE_FLAG)).unwrap();
        manager.discover_apps_readonly().await.unwrap();
        assert!(!manager.any_maintenance_flag());
        assert!(
            !manager
                .routes()
                .get("shop.example.com")
                .unwrap()
                .maintenance
        );
    }

    /// A tenant may opt its app out of compression, never into it.
    #[test]
    fn multi_tenant_compress_opt_in_is_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let on = site_with_app_infos(temp_dir.path(), "on.example.com", "compress = true\n");
        let off = site_with_app_infos(temp_dir.path(), "off.example.com", "compress = false\n");
        let load = |p: &Path, mt| AppInfo::from_path(p, false, mt).unwrap().config.compress;
        assert_eq!(load(&on, true), None);
        assert_eq!(load(&on, false), Some(true));
        assert_eq!(load(&off, true), Some(false));
    }

    /// Give `name` a live blue slot, as a deploy would.
    async fn mark_running(manager: &AppManager, name: &str) {
        let mut apps = manager.apps.lock().await;
        let app = apps.get_mut(name).unwrap();
        app.blue.pid = Some(4242);
        app.blue.status = InstanceStatus::Running;
        app.current_slot = "blue".to_string();
        manager.publish_routes(&apps);
    }

    /// its own path and start command instead of inheriting the second's.
    #[tokio::test]
    async fn duplicate_app_name_keeps_first_directory() {
        let temp_dir = TempDir::new().unwrap();
        let sites = temp_dir.path().join("sites");
        let first = site_with_app_infos(
            &sites,
            "aaa.example.com",
            "name = \"shared.example.com\"\nstart_script = \"./first\"\n",
        );
        site_with_app_infos(
            &sites,
            "zzz.example.com",
            "name = \"shared.example.com\"\nstart_script = \"./second\"\n",
        );

        let config_manager = Arc::new(
            crate::config::ConfigManager::new(temp_dir.path().join("proxy.conf").to_str().unwrap())
                .unwrap(),
        );
        let port_manager =
            Arc::new(PortManager::new(temp_dir.path().join("run").to_str().unwrap()).unwrap());
        let manager =
            AppManager::new(sites.to_str().unwrap(), port_manager, config_manager, false).unwrap();

        // Twice: a rescan must not let the second directory in either.
        for _ in 0..2 {
            manager.discover_apps_readonly().await.unwrap();
            let app = manager.get_app("shared.example.com").await.unwrap();
            assert_eq!(app.path, first);
            assert_eq!(app.config.start_script.as_deref(), Some("./first"));
            assert_eq!(manager.list_apps().await.len(), 1);
        }
    }

    #[test]
    fn test_no_override_when_start_script_set() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("luaonbeans.org"), b"").unwrap();

        let app_infos = r#"
name = "myapp.example.com"
domain = "myapp.example.com"
start_script = "./custom-start.sh"
health_check = "/health"
graceful_timeout = 30
port_range_start = 20000
port_range_end = 30000
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(
            app_info.config.start_script,
            Some("./custom-start.sh".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_soli_auto_detected_uses_readiness_probe() {
        // An auto-detected Soli app (app/ + app/models/, no explicit
        // start_script) must gate promotion on the built-in `/up` readiness
        // probe, not a bare liveness check — otherwise blue/green switches
        // traffic into the cold session-connection window.
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(app_path.join("app/models")).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(
            app_info.config.start_script,
            Some("soli serve . --port $PORT --workers $WORKERS".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/up".to_string()));
    }

    #[test]
    fn test_no_detection_without_luaonbeans_or_app_infos() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("emptyapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.name, "emptyapp.example.com");
        assert!(app_info.config.start_script.is_none());
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_health_check_default_path() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_health_check_custom_path() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_infos = r#"
name = "myapp.example.com"
domain = "myapp.example.com"
health_check = "/status"
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path, false, false).unwrap();
        assert_eq!(app_info.config.health_check, Some("/status".to_string()));
    }

    // --- restart trigger file ---

    fn at(secs: u64) -> Option<SystemTime> {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }

    #[test]
    fn test_trigger_first_poll_records_baseline_without_firing() {
        // A daemon restart must not redeploy every site that already has a
        // trigger file sitting on disk.
        let (fire, remember) = trigger_decision(None, at(1000));
        assert!(!fire);
        assert_eq!(remember, at(1000));

        // Same when the file is absent.
        let (fire, remember) = trigger_decision(None, None);
        assert!(!fire);
        assert_eq!(remember, None);
    }

    #[test]
    fn test_trigger_fires_when_file_appears() {
        let baseline = None;
        let (fire, remember) = trigger_decision(Some(&baseline), at(1000));
        assert!(fire);
        assert_eq!(remember, at(1000));
    }

    #[test]
    fn test_trigger_fires_when_mtime_changes() {
        let baseline = at(1000);
        let (fire, _) = trigger_decision(Some(&baseline), at(1001));
        assert!(fire);
    }

    #[test]
    fn test_trigger_quiet_when_mtime_unchanged() {
        let baseline = at(1000);
        let (fire, remember) = trigger_decision(Some(&baseline), at(1000));
        assert!(!fire);
        assert_eq!(remember, at(1000));
    }

    #[test]
    fn test_trigger_quiet_when_file_removed() {
        let baseline = at(1000);
        let (fire, remember) = trigger_decision(Some(&baseline), None);
        assert!(!fire, "removing the trigger file must not deploy");
        assert_eq!(remember, None);
    }

    #[test]
    fn test_trigger_fires_again_after_file_removed_and_recreated() {
        let baseline = None; // recorded after the removal above
        let (fire, _) = trigger_decision(Some(&baseline), at(2000));
        assert!(fire);
    }

    // --- affected_app_names ---

    /// Outside dev mode the watcher reacts to sites appearing, disappearing
    /// or being renamed, and to `app.infos` — not to a tenant's other writes.
    #[test]
    fn watcher_reacts_only_to_what_discovery_reads() {
        use notify::event::{CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind};
        use notify::EventKind;
        let create = EventKind::Create(CreateKind::Any);
        let write = EventKind::Modify(ModifyKind::Data(DataChange::Any));
        let rename = EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::Any));

        assert!(watch_event_is_relevant(
            Path::new("new.example.com"),
            &create
        ));
        assert!(watch_event_is_relevant(
            Path::new("old.example.com"),
            &EventKind::Remove(RemoveKind::Any)
        ));
        assert!(watch_event_is_relevant(
            Path::new("moved.example.com"),
            &rename
        ));
        assert!(!watch_event_is_relevant(
            Path::new("app.example.com"),
            &EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any))
        ));

        assert!(watch_event_is_relevant(
            Path::new("app.example.com/app.infos"),
            &write
        ));
        assert!(watch_event_is_relevant(
            Path::new("app.example.com/app.infos"),
            &rename
        ));
        assert!(!watch_event_is_relevant(
            Path::new("app.example.com/index.html"),
            &write
        ));
        assert!(!watch_event_is_relevant(
            Path::new("app.example.com/restart.txt"),
            &create
        ));
        assert!(watch_event_is_relevant(
            Path::new("app.example.com/maintenance.flag"),
            &create
        ));
        assert!(watch_event_is_relevant(
            Path::new("app.example.com/maintenance.flag"),
            &EventKind::Remove(RemoveKind::Any)
        ));
        assert!(!watch_event_is_relevant(
            Path::new("app.example.com/deep/app.infos"),
            &create
        ));
    }

    #[test]
    fn test_affected_app_names_skips_top_level_trigger_file() {
        let sites_dir = PathBuf::from("/srv/sites");
        let paths: HashSet<PathBuf> = [sites_dir.join("foo.example.com/restart.txt")]
            .into_iter()
            .collect();
        // The poller owns the trigger file; the dev watcher must not also
        // restart real-directory sites like _admin.
        assert!(affected_app_names(&sites_dir, &paths, "restart.txt").is_empty());
    }

    #[test]
    fn test_affected_app_names_still_detects_code_changes() {
        let sites_dir = PathBuf::from("/srv/sites");
        let paths: HashSet<PathBuf> = [
            sites_dir.join("foo.example.com/app/models/user.lua"),
            sites_dir.join("foo.example.com/restart.txt"),
        ]
        .into_iter()
        .collect();
        let names = affected_app_names(&sites_dir, &paths, "restart.txt");
        assert_eq!(names.len(), 1);
        assert!(names.contains("foo.example.com"));
    }

    #[test]
    fn test_affected_app_names_trigger_file_name_is_configurable() {
        let sites_dir = PathBuf::from("/srv/sites");
        let paths: HashSet<PathBuf> = [sites_dir.join("foo.example.com/.deploy")]
            .into_iter()
            .collect();
        assert!(affected_app_names(&sites_dir, &paths, ".deploy").is_empty());
        // ...and is not skipped under a different configured name.
        assert!(!affected_app_names(&sites_dir, &paths, "restart.txt").is_empty());
    }
}
