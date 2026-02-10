use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use url::Url;

pub mod deployment;
pub mod port_manager;

pub use deployment::{DeploymentManager, DeploymentStatus};
pub use port_manager::{PortAllocator, PortManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub domain: String,
    pub start_script: Option<String>,
    pub stop_script: Option<String>,
    pub health_check: Option<String>,
    pub graceful_timeout: u32,
    pub port_range_start: u16,
    pub port_range_end: u16,
    #[serde(default = "default_workers")]
    pub workers: u16,
}

fn default_workers() -> u16 {
    1
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
            port_range_start: 9000,
            port_range_end: 9999,
            workers: 1,
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
    pub fn from_path(path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let app_infos_path = path.join("app.infos");

        let mut config = if app_infos_path.exists() {
            let content = std::fs::read_to_string(&app_infos_path)?;
            toml::from_str(&content)?
        } else {
            AppConfig::default()
        };

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

impl AppManager {
    pub fn new(
        sites_dir: &str,
        port_allocator: Arc<PortManager>,
        config_manager: Arc<dyn super::config::ConfigManagerTrait + Send + Sync>,
        dev_mode: bool,
    ) -> Result<Self, anyhow::Error> {
        let sites_path = PathBuf::from(sites_dir);
        if !sites_path.exists() {
            std::fs::create_dir_all(&sites_path)?;
        }

        let deployment_manager = Arc::new(DeploymentManager::new(dev_mode));

        Ok(Self {
            sites_dir: sites_path,
            port_allocator,
            apps: Arc::new(Mutex::new(HashMap::new())),
            config_manager,
            deployment_manager,
            watcher: Arc::new(Mutex::new(None)),
            acme_service: Arc::new(Mutex::new(None)),
            dev_mode,
        })
    }

    pub async fn set_acme_service(&self, service: Arc<crate::acme::AcmeService>) {
        *self.acme_service.lock().await = Some(service);
    }

    pub async fn discover_apps(&self) -> Result<(), anyhow::Error> {
        tracing::info!("Discovering apps in {}", self.sites_dir.display());
        let mut apps_to_start: Vec<String> = Vec::new();

        {
            let mut apps = self.apps.lock().await;

            // Track which apps still exist on disk
            let mut seen_names: HashSet<String> = HashSet::new();

            for entry in std::fs::read_dir(&self.sites_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    match AppInfo::from_path(&path) {
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
                                match self
                                    .port_allocator
                                    .allocate(&app_info.config.name, "blue")
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
                                    .allocate(&app_info.config.name, "green")
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
                                    && !self.deployment_manager.is_deploying().await
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

        // Auto-start discovered apps sequentially (deployment lock is global)
        if !apps_to_start.is_empty() {
            let manager = self.clone();
            tokio::spawn(async move {
                for app_name in apps_to_start {
                    tracing::info!("Auto-starting app: {}", app_name);
                    if let Err(e) = manager.deploy(&app_name, "blue").await {
                        tracing::error!("Failed to auto-start {}: {}", app_name, e);
                    }
                }
            });
        }

        self.sync_routes().await;
        Ok(())
    }

    /// Synchronize proxy routes with discovered apps.
    /// Adds Domain routes for apps that don't have one yet,
    /// and removes orphaned auto-registered routes for apps that no longer exist.
    async fn sync_routes(&self) {
        let apps = self.apps.lock().await;
        let cfg = self.config_manager.get_config();
        let mut rules = cfg.rules.clone();
        let global_scripts = cfg.global_scripts.clone();

        // Collect domains from discovered apps
        let mut app_domains: HashMap<String, u16> = HashMap::new();
        for app in apps.values() {
            if !app.config.domain.is_empty() {
                let port = if app.current_slot == "blue" {
                    app.blue.port
                } else {
                    app.green.port
                };
                app_domains.insert(app.config.domain.clone(), port);
                // In dev mode, also register .dev alias
                if self.dev_mode {
                    if let Some(dev) = dev_domain(&app.config.domain) {
                        app_domains.insert(dev, port);
                    }
                }
            }
        }

        // Find existing Domain rules and their domains
        let mut existing_domains: HashMap<String, usize> = HashMap::new();
        for (i, rule) in rules.iter().enumerate() {
            if let super::config::RuleMatcher::Domain(ref domain) = rule.matcher {
                existing_domains.insert(domain.clone(), i);
            }
        }

        let mut changed = false;

        // Add or update routes for discovered apps
        for (domain, port) in &app_domains {
            let target_url = format!("http://localhost:{}", port);
            if let Some(&idx) = existing_domains.get(domain) {
                // Route exists — update target if port changed
                let current_target = rules[idx].targets.first().map(|t| t.url.to_string());
                let expected = format!("{}/", target_url);
                if current_target.as_deref() != Some(&expected) {
                    if let Ok(url) = Url::parse(&target_url) {
                        rules[idx].targets = vec![super::config::Target { url, weight: 100 }];
                        changed = true;
                        tracing::info!("Updated route for domain {} -> {}", domain, target_url);
                    }
                }
            } else {
                // No route for this domain — add one
                if let Ok(url) = Url::parse(&target_url) {
                    rules.push(super::config::ProxyRule {
                        matcher: super::config::RuleMatcher::Domain(domain.clone()),
                        targets: vec![super::config::Target { url, weight: 100 }],
                        headers: vec![],
                        scripts: vec![],
                    });
                    changed = true;
                    tracing::info!("Added route for domain {} -> {}", domain, target_url);
                }
            }
        }

        // Remove orphaned Domain routes (domain not in any discovered app)
        let mut indices_to_remove: Vec<usize> = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            if let super::config::RuleMatcher::Domain(ref domain) = rule.matcher {
                if !app_domains.contains_key(domain) {
                    // Check if the target looks like an auto-registered localhost route
                    let is_auto = rule
                        .targets
                        .iter()
                        .all(|t| t.url.host_str() == Some("localhost"));
                    if is_auto {
                        indices_to_remove.push(i);
                        tracing::info!("Removing orphaned route for domain {}", domain);
                    }
                }
            }
        }

        // Remove in reverse order to preserve indices
        for idx in indices_to_remove.into_iter().rev() {
            rules.remove(idx);
            changed = true;
        }

        if changed {
            if let Err(e) = self.config_manager.update_rules(rules, global_scripts) {
                tracing::error!("Failed to sync routes: {}", e);
            }
        }

        // Trigger ACME cert issuance for ACME-eligible app domains
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

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            notify::Config::default(),
        )?;

        watcher.watch(&sites_dir, RecursiveMode::Recursive)?;

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

    pub async fn get_app(&self, name: &str) -> Option<AppInfo> {
        self.apps.lock().await.get(name).cloned()
    }

    pub async fn get_app_name(&self, port: u16) -> Option<String> {
        self.port_allocator.get_app_name(port).await
    }

    pub async fn allocate_ports(&self, app_name: &str) -> Result<(u16, u16), anyhow::Error> {
        let blue_port = self.port_allocator.allocate(app_name, "blue").await?;
        let green_port = self.port_allocator.allocate(app_name, "green").await?;
        Ok((blue_port, green_port))
    }

    pub async fn deploy(&self, app_name: &str, slot: &str) -> Result<(), anyhow::Error> {
        tracing::info!("Starting deploy for {} to slot {}", app_name, slot);

        let app = {
            let apps = self.apps.lock().await;
            match apps.get(app_name) {
                Some(app) => {
                    tracing::debug!(
                        "Found app {}: blue={}:{}, green={}:{}",
                        app_name,
                        app.blue.status,
                        app.blue.port,
                        app.green.status,
                        app.green.port
                    );
                    app.clone()
                }
                None => {
                    tracing::error!("App not found: {}", app_name);
                    return Err(anyhow::anyhow!("App not found: {}", app_name));
                }
            }
        };

        tracing::info!("Deploying {} to slot {}", app.config.name, slot);
        let pid = self.deployment_manager.deploy(&app, slot).await?;
        tracing::info!("Deploy started, PID: {}", pid);

        // Get the old slot name and PID before updating
        let old_slot_name;
        let old_pid;
        {
            let apps = self.apps.lock().await;
            match apps.get(app_name) {
                Some(a) => {
                    old_slot_name = a.current_slot.clone();
                    old_pid = if old_slot_name == "blue" {
                        a.blue.pid
                    } else {
                        a.green.pid
                    };
                    tracing::info!(
                        "Current slot: {}, old_slot_name: {}, old_pid: {:?}",
                        app_name,
                        old_slot_name,
                        old_pid
                    );
                }
                None => {
                    old_slot_name = "unknown".to_string();
                    old_pid = None;
                    tracing::error!("App {} not found in apps map!", app_name);
                }
            }
        }

        // Update app info: mark new slot as running, store PID, and switch traffic
        {
            let mut apps = self.apps.lock().await;
            if let Some(app_info) = apps.get_mut(app_name) {
                let instance = if slot == "blue" {
                    &mut app_info.blue
                } else {
                    &mut app_info.green
                };
                instance.status = InstanceStatus::Running;
                instance.pid = Some(pid);
                instance.last_started = Some(chrono::Utc::now().to_rfc3339());

                // Switch traffic
                app_info.current_slot = slot.to_string();
                tracing::info!("Switched traffic from {} to {}", old_slot_name, slot);
            } else {
                tracing::error!("App {} not found in map after deploy!", app_name);
            }
        }

        // Stop the old slot if it was running
        tracing::info!(
            "Checking if should stop old slot: old_slot_name={}, slot={}",
            old_slot_name,
            slot
        );
        if old_slot_name != "unknown" && old_slot_name != slot {
            if let Some(pid) = old_pid {
                tracing::info!("Stopping old slot {} (PID: {})", old_slot_name, pid);
                self.deployment_manager
                    .stop_instance(&app, &old_slot_name)
                    .await?;
                tracing::info!("Old slot {} stopped", old_slot_name);

                // Update old slot status to Stopped
                let mut apps = self.apps.lock().await;
                if let Some(app_info) = apps.get_mut(app_name) {
                    let old_instance = if old_slot_name == "blue" {
                        &mut app_info.blue
                    } else {
                        &mut app_info.green
                    };
                    old_instance.status = InstanceStatus::Stopped;
                    old_instance.pid = None;
                }
            } else {
                tracing::warn!(
                    "No PID found for old slot {} (status may already be stopped)",
                    old_slot_name
                );
            }
        }

        self.sync_routes().await;
        tracing::info!("Deploy completed for {} to slot {}", app_name, slot);
        Ok(())
    }

    pub async fn restart(&self, app_name: &str) -> Result<(), anyhow::Error> {
        let slot = {
            let apps = self.apps.lock().await;
            let app = apps
                .get(app_name)
                .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?;
            app.current_slot.clone()
        };

        self.stop(app_name).await?;
        self.deploy(app_name, &slot).await
    }

    pub async fn rollback(&self, app_name: &str) -> Result<(), anyhow::Error> {
        let (app, target_slot, old_slot) = {
            let apps = self.apps.lock().await;
            let app = apps
                .get(app_name)
                .ok_or_else(|| anyhow::anyhow!("App not found: {}", app_name))?
                .clone();
            let target_slot = if app.current_slot == "blue" {
                "green"
            } else {
                "blue"
            };
            (
                app.clone(),
                target_slot.to_string(),
                app.current_slot.clone(),
            )
        };

        let pid = self.deployment_manager.deploy(&app, &target_slot).await?;

        {
            let mut apps = self.apps.lock().await;
            if let Some(app_info) = apps.get_mut(app_name) {
                app_info.current_slot = target_slot.clone();
                let instance = if target_slot == "blue" {
                    &mut app_info.blue
                } else {
                    &mut app_info.green
                };
                instance.status = InstanceStatus::Running;
                instance.pid = Some(pid);
            }
        }

        // Stop the old slot
        let old_pid = {
            let apps = self.apps.lock().await;
            apps.get(app_name).and_then(|a| {
                if old_slot == "blue" {
                    a.blue.pid
                } else {
                    a.green.pid
                }
            })
        };
        if let Some(pid) = old_pid {
            tracing::info!(
                "Stopping old slot {} (PID: {}) during rollback",
                old_slot,
                pid
            );
            self.deployment_manager
                .stop_instance(&app, &old_slot)
                .await?;
            // Update old slot status
            let mut apps = self.apps.lock().await;
            if let Some(app_info) = apps.get_mut(app_name) {
                let old_instance = if old_slot == "blue" {
                    &mut app_info.blue
                } else {
                    &mut app_info.green
                };
                old_instance.status = InstanceStatus::Stopped;
                old_instance.pid = None;
            }
        }

        self.sync_routes().await;
        Ok(())
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
port_range_start = 9000
port_range_end = 9999
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path).unwrap();
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

        let app_info = AppInfo::from_path(&app_path).unwrap();
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
        let app_path = temp_dir.path().join("myapp");
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("luaonbeans.org"), b"").unwrap();

        let app_infos = r#"
name = "myapp"
domain = "custom.example.com"
graceful_timeout = 30
port_range_start = 9000
port_range_end = 9999
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path).unwrap();
        assert_eq!(app_info.config.name, "myapp");
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
        let app_path = temp_dir.path().join("myapp");
        std::fs::create_dir_all(&app_path).unwrap();
        std::fs::write(app_path.join("luaonbeans.org"), b"").unwrap();

        let app_infos = r#"
name = "myapp"
domain = "myapp.example.com"
start_script = "./custom-start.sh"
health_check = "/health"
graceful_timeout = 30
port_range_start = 9000
port_range_end = 9999
"#;
        std::fs::write(app_path.join("app.infos"), app_infos).unwrap();

        let app_info = AppInfo::from_path(&app_path).unwrap();
        assert_eq!(
            app_info.config.start_script,
            Some("./custom-start.sh".to_string())
        );
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }

    #[test]
    fn test_no_detection_without_luaonbeans_or_app_infos() {
        let temp_dir = TempDir::new().unwrap();
        let app_path = temp_dir.path().join("emptyapp");
        std::fs::create_dir_all(&app_path).unwrap();

        let app_info = AppInfo::from_path(&app_path).unwrap();
        assert_eq!(app_info.config.name, "emptyapp");
        assert!(app_info.config.start_script.is_none());
        assert_eq!(app_info.config.health_check, Some("/health".to_string()));
    }
}
