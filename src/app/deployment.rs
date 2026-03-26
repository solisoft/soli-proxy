use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;

use super::AppInfo;

/// Validate that a name is safe for use in filesystem paths.
/// Rejects empty strings, path separators, "..", and control characters.
fn validate_path_component(name: &str, label: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{} cannot be empty", label);
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        anyhow::bail!("{} contains invalid path characters: {:?}", label, name);
    }
    if name == "." || name == ".." || name.contains("..") {
        anyhow::bail!("{} contains path traversal: {:?}", label, name);
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("{} contains control characters: {:?}", label, name);
    }
    Ok(())
}

/// Parse a start script into a program and arguments without using a shell.
/// Performs variable substitution for $PORT and $WORKERS.
/// This avoids shell injection by never passing the script through `sh -c`.
fn parse_start_command(script: &str, port: u16, workers: u16) -> Result<(String, Vec<String>)> {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    if tokens.is_empty() {
        anyhow::bail!("Start script is empty");
    }

    let port_str = port.to_string();
    let workers_str = workers.to_string();

    let program = tokens[0]
        .replace("$PORT", &port_str)
        .replace("$WORKERS", &workers_str);

    let args: Vec<String> = tokens[1..]
        .iter()
        .map(|t| {
            t.replace("$PORT", &port_str)
                .replace("$WORKERS", &workers_str)
        })
        .collect();

    Ok((program, args))
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeploymentStatus {
    Idle,
    Deploying,
    RollingBack,
    Failed(String),
}

pub struct DeploymentManager {
    /// Per-app deployment locks: contains app names currently being deployed
    deploying_apps: Arc<Mutex<HashSet<String>>>,
    dev_mode: bool,
    http_client: reqwest::Client,
    default_user: Option<String>,
    default_group: Option<String>,
}

impl Default for DeploymentManager {
    fn default() -> Self {
        Self::new(false, None, None)
    }
}

impl DeploymentManager {
    pub fn new(
        dev_mode: bool,
        default_user: Option<String>,
        default_group: Option<String>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            deploying_apps: Arc::new(Mutex::new(HashSet::new())),
            dev_mode,
            http_client,
            default_user,
            default_group,
        }
    }

    pub fn is_deploying(&self, app_name: &str) -> bool {
        self.deploying_apps.lock().unwrap().contains(app_name)
    }

    async fn check_port_in_use(&self, port: u16) -> bool {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(100)).is_ok()
    }

    /// Mark an app as deploying (prevents concurrent deploys).
    /// Returns false if a deploy is already in progress.
    pub fn mark_deploying(&self, app_name: &str) -> bool {
        let mut deploying = self.deploying_apps.lock().unwrap();
        if deploying.contains(app_name) {
            return false;
        }
        deploying.insert(app_name.to_string());
        true
    }

    /// Unmark an app as deploying.
    pub fn unmark_deploying(&self, app_name: &str) {
        self.deploying_apps.lock().unwrap().remove(app_name);
    }

    /// Deploy an app to a slot. Returns the PID of the started process.
    pub async fn deploy(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        {
            let mut deploying = self.deploying_apps.lock().unwrap();
            if deploying.contains(&app.config.name) {
                anyhow::bail!("Deployment already in progress for {}", app.config.name);
            }
            deploying.insert(app.config.name.clone());
        }

        let deploying_apps = self.deploying_apps.clone();
        let app_name = app.config.name.clone();
        let _guard = scopeguard::guard((), move |_| {
            deploying_apps.lock().unwrap().remove(&app_name);
        });

        tracing::info!(
            "Starting deployment of {} to slot {}",
            app.config.name,
            slot
        );

        let pid = self.start_instance(app, slot).await?;

        let healthy = self.wait_for_health(app, slot).await?;

        if !healthy {
            self.stop_instance(app, slot).await?;
            anyhow::bail!("Health check failed for {} slot", slot);
        }

        tracing::info!("Health check passed for {} slot {}", app.config.name, slot);
        Ok(pid)
    }

    pub async fn start_instance(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        // Validate slot and app name to prevent path traversal in log paths
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        validate_path_component(&app.config.name, "App name")?;

        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };

        if self.check_port_in_use(port).await {
            anyhow::bail!(
                "Port {} is already in use by another process. Cannot start {} slot {}",
                port,
                app.config.name,
                slot
            );
        }

        let base_script = if let Some(ref script) = app.config.start_script {
            script.clone()
        } else if app.path.join("app").exists() && app.path.join("app/models").exists() {
            "soli serve .".to_string()
        } else {
            anyhow::bail!("No start script configured for {}", app.config.name)
        };

        let script = if self.dev_mode && base_script.starts_with("soli ") {
            format!("{} --dev", base_script)
        } else {
            base_script.clone()
        };

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        // Parse the script into program + args instead of using `sh -c`
        // to prevent shell injection from malicious app.infos files.
        let (program, args) = parse_start_command(&script, port, app.config.workers)?;

        let mut cmd = tokio::process::Command::new(&program);
        cmd.args(&args)
            .current_dir(&app.path)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("PORT", port.to_string())
            .env("WORKERS", app.config.workers.to_string())
            .stdout(std::process::Stdio::from(output.try_clone()?))
            .stderr(std::process::Stdio::from(output));

        let user = app.config.user.as_ref().or(self.default_user.as_ref());
        let group = app.config.group.as_ref().or(self.default_group.as_ref());

        if let (Some(user), Some(group)) = (user, group) {
            let uid = resolve_user(user)?;
            let gid = resolve_group(group)?;
            cmd.uid(uid).gid(gid);
            tracing::info!(
                "Running {} as user {} (uid: {}, gid: {})",
                app.config.name,
                user,
                uid,
                gid
            );
        } else if let Some(user) = user {
            let uid = resolve_user(user)?;
            let gid = resolve_group(user)?;
            cmd.uid(uid).gid(gid);
            tracing::info!(
                "Running {} as user {} (uid: {}, gid: {})",
                app.config.name,
                user,
                uid,
                gid
            );
        }

        let cmd = unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()?
        };

        let pid = cmd.id().unwrap_or(0);
        tracing::info!("Started {} slot {} with PID {}", app.config.name, slot, pid);

        Ok(pid)
    }

    pub async fn stop_instance(&self, app: &AppInfo, slot: &str) -> Result<()> {
        let pid = if slot == "blue" {
            app.blue.pid
        } else {
            app.green.pid
        };

        if let Some(pid) = pid {
            tracing::info!("Stopping {} slot {} (PID: {})", app.config.name, slot, pid);

            #[cfg(unix)]
            {
                // Kill the entire process group (negative PID) so child processes are included
                let pgid = format!("-{}", pid);

                tokio::process::Command::new("kill")
                    .arg("-TERM")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await?;

                let timeout = app.config.graceful_timeout as u64;
                let mut waited_ms = 0u64;
                while waited_ms < timeout * 1000 {
                    let output = tokio::process::Command::new("kill")
                        .arg("-0")
                        .arg(pid.to_string())
                        .output()
                        .await?;

                    if !output.status.success() {
                        tracing::info!("Process {} terminated gracefully", pid);
                        return Ok(());
                    }
                    let delay = if waited_ms < 500 { 50 } else { 200 };
                    sleep(Duration::from_millis(delay)).await;
                    waited_ms += delay;
                }

                tracing::warn!("Force killing process group {}", pid);
                tokio::process::Command::new("kill")
                    .arg("-9")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn wait_for_health(&self, app: &AppInfo, slot: &str) -> Result<bool> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        let health_path = app.config.health_check.as_deref().unwrap_or("/health");

        let url = format!("http://localhost:{}{}", port, health_path);
        let timeout_secs = 30;

        for i in 0..timeout_secs {
            sleep(Duration::from_secs(1)).await;

            match self.http_client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "Health check passed for {} slot {} after {}s",
                        app.config.name,
                        slot,
                        i + 1
                    );
                    return Ok(true);
                }
                Ok(_) => {
                    tracing::debug!(
                        "Health check response for {} slot {}: {}",
                        app.config.name,
                        slot,
                        i + 1
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "Health check failed for {} slot {}: {} ({})",
                        app.config.name,
                        slot,
                        e,
                        i + 1
                    );
                }
            }
        }

        Ok(false)
    }

    pub async fn switch_traffic(&self, app: &AppInfo, new_slot: &str) -> Result<()> {
        tracing::info!(
            "Switching traffic for {} to slot {}",
            app.config.name,
            new_slot
        );

        let old_slot = if new_slot == "blue" { "green" } else { "blue" };
        self.stop_instance(app, old_slot).await?;

        Ok(())
    }

    pub async fn rollback(&self, app: &AppInfo) -> Result<()> {
        let target_slot = if app.current_slot == "blue" {
            "green"
        } else {
            "blue"
        };
        self.deploy(app, target_slot).await?;
        Ok(())
    }

    pub async fn get_deployment_log(&self, app_name: &str, slot: &str) -> Result<String> {
        validate_path_component(app_name, "App name")?;
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        let log_path = PathBuf::from(format!("run/logs/{}/{}.log", app_name, slot));
        if log_path.exists() {
            Ok(std::fs::read_to_string(&log_path)?)
        } else {
            Ok(String::new())
        }
    }
}

fn resolve_user(user: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_user = CString::new(user)?;
    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        anyhow::bail!("User '{}' not found", user);
    }
    Ok(unsafe { (*passwd).pw_uid })
}

fn resolve_group(group: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_group = CString::new(group)?;
    let grp = unsafe { libc::getgrnam(c_group.as_ptr()) };
    if grp.is_null() {
        anyhow::bail!("Group '{}' not found", group);
    }
    Ok(unsafe { (*grp).gr_gid })
}
