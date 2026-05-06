use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use url::Url;

pub mod deployment;
pub mod port_manager;

use crate::circuit_breaker::SharedCircuitBreaker;
use crate::metrics::Metrics as AppMetrics;
pub use deployment::{DeploymentManager, DeploymentStatus, ProcessExit};
pub use port_manager::{PortAllocator, PortManager};

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
        }
    }
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
}

impl AppInfo {
    pub fn from_path(path: &std::path::Path, dev_mode: bool) -> Result<Self, anyhow::Error> {
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

        let app_infos_path = path.join("app.infos");

        let mut config = if app_infos_path.exists() {
            let content = std::fs::read_to_string(&app_infos_path)?;
            if content.trim().is_empty() {
                AppConfig::default()
            } else {
                toml::from_str(&content)?
            }
        } else {
            AppConfig::default()
        };

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
            config.health_check = Some("/".to_string());
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
        })
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
    event_tx: broadcast::Sender<AppEvent>,
    #[allow(dead_code)]
    health_check_path: String,
    health_check_interval_secs: u64,
    circuit_breaker: Option<SharedCircuitBreaker>,
    process_exit_rx:
        Arc<parking_lot::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ProcessExit>>>>,
    last_failover: Arc<parking_lot::Mutex<HashMap<String, std::time::Instant>>>,
    failure_count: Arc<parking_lot::Mutex<HashMap<String, u32>>>,
}

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

/// Get the non-www version of a domain if it starts with www.
/// e.g. "www.solisoft.net" → Some("solisoft.net")
fn strip_www(domain: &str) -> Option<String> {
    if domain.starts_with("www.") && domain.len() > 4 {
        Some(domain[4..].to_string())
    } else {
        None
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

/// Kill a process group (SIGTERM, wait, then SIGKILL if needed).
async fn kill_process_group(pid: u32) {
    if pid < 2 {
        return;
    }
    let pgid = format!("-{}", pid);
    let _ = tokio::process::Command::new("kill")
        .arg("-TERM")
        .arg("--")
        .arg(&pgid)
        .output()
        .await;

    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let output = tokio::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output()
            .await;
        if let Ok(o) = output {
            if !o.status.success() {
                return; // Process is dead
            }
        }
    }

    // Force kill
    let _ = tokio::process::Command::new("kill")
        .arg("-9")
        .arg("--")
        .arg(&pgid)
        .output()
        .await;
}

/// Extract app names from changed file paths, filtering out irrelevant directories.
/// Each path is expected to be under `sites_dir/<app_name>/...`.
fn affected_app_names(sites_dir: &Path, paths: &HashSet<PathBuf>) -> HashSet<String> {
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

        // Skip if the only changed file is app.infos (handled by discover_apps)
        if relative.components().count() == 2 {
            if let Some(filename) = relative.file_name() {
                if filename == "app.infos" {
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
        let deployment_manager = Arc::new(DeploymentManager::new(
            dev_mode,
            cfg.apps.default_user.clone(),
            cfg.apps.default_group.clone(),
            process_exit_tx,
        ));
        let (event_tx, _) = broadcast::channel(32);

        let manager = Self {
            sites_dir: sites_path,
            port_allocator,
            apps: Arc::new(Mutex::new(HashMap::new())),
            config_manager,
            deployment_manager,
            watcher: Arc::new(Mutex::new(None)),
            acme_service: Arc::new(Mutex::new(None)),
            dev_mode,
            event_tx,
            health_check_path: health_check_path.to_string(),
            health_check_interval_secs,
            circuit_breaker: None,
            process_exit_rx: Arc::new(parking_lot::Mutex::new(Some(process_exit_rx))),
            last_failover: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            failure_count: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        };

        Ok(manager)
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

    pub async fn get_running_app_domains(&self) -> HashMap<String, (u16, Option<String>)> {
        let apps = self.apps.lock().await;
        let mut result = HashMap::new();
        for app in apps.values() {
            if app.config.domain.is_empty() {
                tracing::debug!(
                    "get_running_app_domains: app {} has empty domain, skipping",
                    app.config.name
                );
                continue;
            }
            let (port, pid) = if app.current_slot == "blue" {
                (app.blue.port, app.blue.pid)
            } else {
                (app.green.port, app.green.pid)
            };
            tracing::debug!("get_running_app_domains: app {} domain={} current_slot={} blue_port={} blue_pid={:?} green_port={} green_pid={:?}",
                app.config.name, app.config.domain, app.current_slot, app.blue.port, app.blue.pid, app.green.port, app.green.pid);
            // If current slot has no PID, fall back to the other slot.
            // This prevents permanent 421 when current_slot points to a
            // dead slot but the other slot has a running process.
            let (port, pid) = if pid.is_none() {
                tracing::debug!(
                    "get_running_app_domains: app {} has no pid for slot {}, trying other slot",
                    app.config.name,
                    app.current_slot
                );
                if app.current_slot == "blue" {
                    (app.green.port, app.green.pid)
                } else {
                    (app.blue.port, app.blue.pid)
                }
            } else {
                (port, pid)
            };
            if pid.is_none() {
                tracing::debug!(
                    "get_running_app_domains: app {} has no pid on either slot, skipping",
                    app.config.name,
                );
                continue;
            }
            result.insert(
                app.config.domain.clone(),
                (port, app.config.health_check.clone()),
            );
            if let Some(non_www) = strip_www(&app.config.domain) {
                result.insert(non_www, (port, app.config.health_check.clone()));
            }
            if self.dev_mode {
                if let Some(dev) = dev_domain(&app.config.domain) {
                    result.insert(dev, (port, app.config.health_check.clone()));
                }
            }
        }
        result
    }

    pub async fn resolve_app_target(&self, host: &str) -> Option<super::config::Target> {
        let app_domains = self.get_running_app_domains().await;
        tracing::debug!(
            "resolve_app_target: host={}, available_domains={:?}",
            host,
            app_domains.keys().collect::<Vec<_>>()
        );
        if let Some((port, _)) = app_domains.get(host) {
            let url = format!("http://localhost:{}", port);
            if let Ok(url) = Url::parse(&url) {
                return Some(super::config::Target { url, weight: 100 });
            }
        }
        None
    }

    /// Find the app name for a given host domain.
    pub async fn app_name_for_host(&self, host: &str) -> Option<String> {
        let apps = self.apps.lock().await;
        for (name, app) in apps.iter() {
            if app.config.domain == host {
                return Some(name.clone());
            }
            if strip_www(&app.config.domain).as_deref() == Some(host) {
                return Some(name.clone());
            }
            if self.dev_mode && dev_domain(&app.config.domain).as_deref() == Some(host) {
                return Some(name.clone());
            }
        }
        None
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
        tracing::info!("Discovering apps in {}", self.sites_dir.display());
        let mut apps_to_start: Vec<String> = Vec::new();

        {
            let mut apps = self.apps.lock().await;

            // Track which apps still exist on disk
            let mut seen_names: HashSet<String> = HashSet::new();

            for entry in std::fs::read_dir(&self.sites_dir)? {
                let entry = entry?;
                let path = entry.path();

                // Skip directories starting with '.' (like .claude)
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') {
                        continue;
                    }
                }

                let resolved_path = if path.is_symlink() {
                    match path.canonicalize() {
                        Ok(p) => p,
                        Err(_) => path.clone(),
                    }
                } else {
                    path.clone()
                };
                if resolved_path.is_dir() {
                    match AppInfo::from_path(&path, self.dev_mode) {
                        Ok(mut app_info) => {
                            let name = app_info.config.name.clone();
                            seen_names.insert(name.clone());

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
                                // Allocate ports for new apps only
                                let port_range_start = app_info.config.port_range_start;
                                let port_range_end = app_info.config.port_range_end;
                                match self
                                    .port_allocator
                                    .allocate_with_range(
                                        &app_info.config.name,
                                        "blue",
                                        port_range_start,
                                        port_range_end,
                                    )
                                    .await
                                {
                                    Ok(port) => app_info.blue.port = port,
                                    Err(e) => tracing::error!(
                                        "Failed to allocate blue port for {}: {}",
                                        app_info.config.name,
                                        e
                                    ),
                                }
                                match self
                                    .port_allocator
                                    .allocate_with_range(
                                        &app_info.config.name,
                                        "green",
                                        port_range_start,
                                        port_range_end,
                                    )
                                    .await
                                {
                                    Ok(port) => app_info.green.port = port,
                                    Err(e) => tracing::error!(
                                        "Failed to allocate green port for {}: {}",
                                        app_info.config.name,
                                        e
                                    ),
                                }
                                if app_info.config.start_script.is_some()
                                    && !self.deployment_manager.is_deploying(&name)
                                {
                                    apps_to_start.push(name.clone());
                                }
                            }
                            apps.insert(name, app_info);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load app from {}: {}", path.display(), e);
                        }
                    }
                }
            }

            // Remove apps that no longer exist on disk
            apps.retain(|name, _| seen_names.contains(name));
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
                        // Kill orphaned processes on both slots from previous daemon
                        if let Some(app) = mgr.get_app(&app_name).await {
                            for (slot_name, port) in
                                [("blue", app.blue.port), ("green", app.green.port)]
                            {
                                if is_port_in_use(port).await {
                                    if let Some(orphan_pid) = find_pid_by_port(port) {
                                        tracing::warn!(
                                            "Killing orphaned process {} on {} port {} for {}",
                                            orphan_pid,
                                            slot_name,
                                            port,
                                            app_name
                                        );
                                        mgr.deployment_manager.mark_stopping(orphan_pid);
                                        kill_process_group(orphan_pid).await;
                                    }
                                }
                            }
                        }
                        tracing::info!("Auto-starting app: {}", app_name);
                        if let Err(e) = mgr.deploy(&app_name, "blue").await {
                            tracing::error!("Failed to auto-start {}: {}", app_name, e);
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

    /// Synchronize proxy routes with discovered apps.
    ///
    /// Removes stale static rules from proxy.conf for domains now managed by
    /// the AppManager (which handles blue-green routing dynamically).
    async fn sync_routes(&self) {
        let app_domains = self.get_running_app_domains().await;

        // Remove static proxy.conf rules for app-managed domains so they
        // don't shadow the dynamic blue-green routing.
        let cfg = self.config_manager.get_config();
        let original_len = cfg.rules.len();
        let rules: Vec<_> = cfg
            .rules
            .iter()
            .filter(|rule| {
                let domain = match &rule.matcher {
                    super::config::RuleMatcher::Domain(d) => Some(d.as_str()),
                    super::config::RuleMatcher::DomainPath(d, _) => Some(d.as_str()),
                    _ => None,
                };
                if let Some(d) = domain {
                    if app_domains.contains_key(d) {
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

        let acme_eligible: Vec<String> = app_domains
            .keys()
            .filter(|d| is_acme_eligible(d))
            .cloned()
            .collect();

        if !acme_eligible.is_empty() {
            self.config_manager
                .register_app_acme_domains(acme_eligible.clone());
        }

        if let Some(ref acme) = *self.acme_service.lock().await {
            for domain in app_domains.keys() {
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

    pub async fn start_watcher(&self) -> Result<(), anyhow::Error> {
        let (tx, mut rx) = mpsc::channel(100);
        let sites_dir = self.sites_dir.clone();
        let manager = self.clone();

        let watch_path = if sites_dir.is_symlink() {
            sites_dir.canonicalize()?
        } else {
            sites_dir.clone()
        };

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;

        watcher.watch(&watch_path, RecursiveMode::Recursive)?;

        *self.watcher.lock().await = Some(watcher);

        tokio::spawn(async move {
            loop {
                // Wait for the first relevant event, collecting changed paths
                let mut changed_paths: HashSet<PathBuf> = HashSet::new();
                let mut got_event = false;
                while let Some(res) = rx.recv().await {
                    if let Ok(event) = res {
                        if event.kind.is_modify()
                            || event.kind.is_create()
                            || event.kind.is_remove()
                        {
                            changed_paths.extend(event.paths);
                            got_event = true;
                            break;
                        }
                    }
                }
                if !got_event {
                    break; // channel closed
                }

                // Debounce: drain any events arriving within 500ms, collecting paths
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                while let Ok(res) = rx.try_recv() {
                    if let Ok(event) = res {
                        changed_paths.extend(event.paths);
                    }
                }

                tracing::info!("Apps directory changed, rediscovering...");
                if let Err(e) = manager.discover_apps().await {
                    tracing::error!("Failed to rediscover apps: {}", e);
                }

                // In dev mode, restart affected apps that are currently running
                if manager.dev_mode {
                    let app_names = affected_app_names(&sites_dir, &changed_paths);
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
            }
        });

        Ok(())
    }

    pub async fn list_apps(&self) -> Vec<AppInfo> {
        self.apps
            .lock()
            .await
            .values()
            .filter(|&a| a.config.name != "_admin")
            .cloned()
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
    }

    /// Load app state (current_slot) from disk so TUI can see deploys that happened
    /// while TUI was not running.
    pub fn load_app_state(&self) {
        let state_file = PathBuf::from("./run/app_state.json");
        if !state_file.exists() {
            return;
        }
        if let Ok(content) = std::fs::read_to_string(&state_file) {
            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(apps) = state.as_object() {
                    let mut apps_guard = self.apps.blocking_lock();
                    for (name, slot) in apps {
                        if let Some(slot_str) = slot.as_str() {
                            if let Some(app_info) = apps_guard.get_mut(name) {
                                app_info.current_slot = slot_str.to_string();
                            }
                        }
                    }
                    tracing::debug!("Loaded app state from {:?}", state_file);
                }
            }
        }
    }

    /// Save app state (current_slot) to disk so other processes (e.g. TUI) can see it.
    pub async fn save_app_state(&self) {
        let state_file = PathBuf::from("./run/app_state.json");
        if let Some(parent) = state_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let state: serde_json::Value = {
            let apps_guard = self.apps.lock().await;
            let mut map = serde_json::Map::new();
            for (name, app) in apps_guard.iter() {
                map.insert(
                    name.clone(),
                    serde_json::Value::String(app.current_slot.clone()),
                );
            }
            serde_json::Value::Object(map)
        };
        if let Ok(content) = serde_json::to_string_pretty(&state) {
            let _ = std::fs::write(&state_file, content);
            tracing::debug!("Saved app state to {:?}", state_file);
        }
    }

    pub async fn get_app(&self, name: &str) -> Option<AppInfo> {
        self.apps.lock().await.get(name).cloned()
    }

    pub async fn get_app_name(&self, port: u16) -> Option<String> {
        self.port_allocator.get_app_name(port).await
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
        let blue_port = self.port_allocator.allocate(app_name, "blue").await?;
        let green_port = self.port_allocator.allocate(app_name, "green").await?;
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
            self.deployment_manager.mark_stopping(pid);
            kill_process_group(pid).await;
        }

        // Start new instance
        tracing::info!("Starting {} slot {}", app.config.name, slot);
        let pid = self.deployment_manager.start_instance(&app, slot).await?;
        tracing::info!("Started {} slot {} with PID {}", app.config.name, slot, pid);

        // Update state with new PID
        {
            let mut apps = self.apps.lock().await;
            let instance = if slot == "blue" {
                &mut apps.get_mut(app_name).unwrap().blue
            } else {
                &mut apps.get_mut(app_name).unwrap().green
            };
            instance.pid = Some(pid);
            instance.status = InstanceStatus::Running;
            instance.last_started = Some(chrono::Utc::now().to_rfc3339());
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
            self.deployment_manager.mark_stopping(pid);
            kill_process_group(pid).await;
            {
                let mut apps = self.apps.lock().await;
                let instance = if slot == "blue" {
                    &mut apps.get_mut(app_name).unwrap().blue
                } else {
                    &mut apps.get_mut(app_name).unwrap().green
                };
                instance.pid = None;
                instance.status = InstanceStatus::Failed;
            }
            return Err(e);
        }
        tracing::info!("Health check passed for {} slot {}", app.config.name, slot);

        // Switch traffic AND persist atomically
        {
            let mut apps = self.apps.lock().await;
            apps.get_mut(app_name).unwrap().current_slot = slot.to_string();

            // Persist while still holding the lock to prevent load_app_state()
            // from reverting the switch with stale disk data
            let state_file = PathBuf::from("./run/app_state.json");
            if let Some(parent) = state_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut map = serde_json::Map::new();
            for (name, app) in apps.iter() {
                map.insert(
                    name.clone(),
                    serde_json::Value::String(app.current_slot.clone()),
                );
            }
            if let Ok(content) = serde_json::to_string_pretty(&serde_json::Value::Object(map)) {
                let _ = std::fs::write(&state_file, content);
            }
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
            cb.reset_target(&format!("http://localhost:{}/", port));
        }

        // Stop old slot (skip if same slot)
        if old_slot != slot && old_slot != "unknown" {
            let old_pid = {
                let apps = self.apps.lock().await;
                let a = apps.get(app_name).unwrap();
                if old_slot == "blue" {
                    a.blue.pid
                } else {
                    a.green.pid
                }
            };
            if let Some(pid) = old_pid {
                let drain = app.config.drain_delay as u64;
                if drain > 0 {
                    tracing::info!("Draining old slot {} for {}s", old_slot, drain);
                    tokio::time::sleep(std::time::Duration::from_secs(drain)).await;
                }
                self.deployment_manager.mark_stopping(pid);
                kill_process_group(pid).await;
                {
                    let mut apps = self.apps.lock().await;
                    let instance = if old_slot == "blue" {
                        &mut apps.get_mut(app_name).unwrap().blue
                    } else {
                        &mut apps.get_mut(app_name).unwrap().green
                    };
                    instance.pid = None;
                    instance.status = InstanceStatus::Stopped;
                }
                tracing::info!("Stopped old slot {}", old_slot);
            }
        }

        tracing::info!("Deploy completed for {} to slot {}", app_name, slot);

        // Reset failure count on successful deploy
        {
            let mut failure_count = self.failure_count.lock();
            failure_count.insert(app_name.to_string(), 0);
        }

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

    pub async fn stop_all(&self) {
        let apps: Vec<String> = {
            let apps_guard = self.apps.lock().await;
            apps_guard.keys().cloned().collect()
        };

        for app_name in apps {
            // Stop both blue and green slots
            let app = {
                let apps_guard = self.apps.lock().await;
                apps_guard.get(&app_name).cloned()
            };
            if let Some(app) = app {
                // Stop blue slot
                if app.blue.status == InstanceStatus::Running && app.blue.pid.is_some() {
                    if let Err(e) = self.deployment_manager.stop_instance(&app, "blue").await {
                        tracing::error!("Failed to stop blue slot for {}: {}", app_name, e);
                    }
                }
                // Stop green slot
                if app.green.status == InstanceStatus::Running && app.green.pid.is_some() {
                    if let Err(e) = self.deployment_manager.stop_instance(&app, "green").await {
                        tracing::error!("Failed to stop green slot for {}: {}", app_name, e);
                    }
                }
                // Update status in map
                let mut apps_guard = self.apps.lock().await;
                if let Some(app_info) = apps_guard.get_mut(&app_name) {
                    app_info.blue.status = InstanceStatus::Stopped;
                    app_info.blue.pid = None;
                    app_info.green.status = InstanceStatus::Stopped;
                    app_info.green.pid = None;
                }
            }
        }
    }

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
            let url_health = format!("http://localhost:{}{}", port, health_path);
            let url_root = format!("http://localhost:{}/", port);
            let healthy = match http_client.get(&url_health).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("Health check OK for {} on port {}", app_name, port);
                    true
                }
                Ok(resp) if resp.status() == 404 => {
                    tracing::debug!(
                        "Health check returned 404 for {} on port {}, trying fallback /",
                        app_name,
                        port
                    );
                    match http_client.get(&url_root).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::debug!(
                                "Health check fallback OK for {} on port {}",
                                app_name,
                                port
                            );
                            true
                        }
                        Ok(_) => {
                            tracing::debug!(
                                "Health check fallback returned non-2xx for {} on port {}",
                                app_name,
                                port
                            );
                            false
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Health check fallback failed for {} on port {}: {}",
                                app_name,
                                port,
                                e
                            );
                            false
                        }
                    }
                }
                Ok(_) => {
                    tracing::debug!(
                        "Health check returned non-2xx for {} on port {}",
                        app_name,
                        port
                    );
                    false
                }
                Err(e) => {
                    tracing::warn!(
                        "Health check failed for {} on port {}: {}, failing over",
                        app_name,
                        port,
                        e
                    );
                    if let Err(e) = self.failover(&app_name).await {
                        tracing::error!("Failed to failover {}: {}", app_name, e);
                    }
                    continue;
                }
            };
            if !healthy {
                if let Err(e) = self.failover(&app_name).await {
                    tracing::error!("Failed to failover {}: {}", app_name, e);
                }
            }
        }
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
                tracing::warn!(
                    "Detected unexpected exit of {} slot {} (PID {}), triggering immediate failover",
                    exit.app_name,
                    exit.slot,
                    exit.pid
                );

                // Check failure count - stop after 3 consecutive failures
                {
                    let mut failure_count = manager.failure_count.lock();
                    let count = failure_count.entry(exit.app_name.clone()).or_insert(0);
                    *count += 1;
                    if *count > 3 {
                        tracing::error!(
                            "Skipping failover for {} — {} consecutive failures, giving up",
                            exit.app_name,
                            count
                        );
                        continue;
                    }
                }

                // Verify the PID still matches the current slot — if it was
                // already replaced by a concurrent deploy, skip failover.
                let should_failover = {
                    let apps = manager.apps.lock().await;
                    if let Some(app) = apps.get(&exit.app_name) {
                        let current_pid = if app.current_slot == "blue" {
                            app.blue.pid
                        } else {
                            app.green.pid
                        };
                        // Only failover if the dead PID is still the active one
                        current_pid == Some(exit.pid) && app.current_slot == exit.slot
                    } else {
                        false
                    }
                };

                if should_failover {
                    // Kill the dead process's entire group to clean up
                    // any surviving worker processes. The main process is
                    // dead but workers (started via --workers N) may still
                    // be running and could interfere with the replacement.
                    kill_process_group(exit.pid).await;

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

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
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

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
        assert_eq!(app_info.config.name, "myapp.example.com");
        assert_eq!(app_info.config.domain, "myapp.example.com");
        assert_eq!(
            app_info.config.start_script,
            Some("./luaonbeans.org -D . -p $PORT -s".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/".to_string()));
    }

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

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
        assert_eq!(app_info.config.name, "myapp.example.com");
        assert_eq!(app_info.config.domain, "custom.example.com");
        assert_eq!(
            app_info.config.start_script,
            Some("./luaonbeans.org -D . -p $PORT -s".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/".to_string()));
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

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
        assert_eq!(
            app_info.config.start_script,
            Some("./custom-start.sh".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_no_detection_without_luaonbeans_or_app_infos() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("emptyapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
        assert_eq!(app_info.config.name, "emptyapp.example.com");
        assert!(app_info.config.start_script.is_none());
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_health_check_default_path() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("myapp.example.com");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
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

        let app_info = AppInfo::from_path(&app_path, false).unwrap();
        assert_eq!(app_info.config.health_check, Some("/status".to_string()));
    }
}
