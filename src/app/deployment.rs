use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use super::AppInfo;

/// Notification sent when a managed process exits unexpectedly.
#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub app_name: String,
    pub slot: String,
    pub pid: u32,
}

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

async fn ensure_docker_network(network_name: &str) -> Result<()> {
    let output = tokio::process::Command::new("docker")
        .args(["network", "inspect", network_name])
        .output()
        .await?;

    if !output.status.success() {
        tracing::info!("Creating Docker network: {}", network_name);
        let output = tokio::process::Command::new("docker")
            .args(["network", "create", "--driver", "bridge", network_name])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Failed to create Docker network {}: {}",
                network_name,
                stderr
            );
        }
        tracing::info!("Docker network {} created", network_name);
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
    /// PIDs that are being intentionally stopped (not unexpected exits)
    stopping_pids: Arc<Mutex<HashSet<u32>>>,
    /// Channel to notify AppManager of unexpected process exits
    process_exit_tx: mpsc::UnboundedSender<ProcessExit>,
    dev_mode: bool,
    http_client: reqwest::Client,
    default_user: Option<String>,
    default_group: Option<String>,
}

impl DeploymentManager {
    pub fn new(
        dev_mode: bool,
        default_user: Option<String>,
        default_group: Option<String>,
        process_exit_tx: mpsc::UnboundedSender<ProcessExit>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            deploying_apps: Arc::new(Mutex::new(HashSet::new())),
            stopping_pids: Arc::new(Mutex::new(HashSet::new())),
            process_exit_tx,
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

    /// Mark a PID as being intentionally stopped, so the process exit
    /// monitor ignores its death.
    pub fn mark_stopping(&self, pid: u32) {
        self.stopping_pids.lock().unwrap().insert(pid);
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
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        validate_path_component(&app.config.name, "App name")?;

        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };

        if let Some(ref docker_image) = app.config.docker_image {
            return self
                .start_docker_instance(app, slot, port, docker_image)
                .await;
        }

        self.start_native_instance(app, slot, port).await
    }

    async fn start_docker_instance(
        &self,
        app: &AppInfo,
        slot: &str,
        port: u16,
        docker_image: &str,
    ) -> Result<u32> {
        let container_name = format!("{}-{}", app.config.name, slot);

        let _ = self.stop_docker_container(&container_name).await;

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

        let docker_network = app.config.docker_network.as_deref().unwrap_or("soli-apps");

        ensure_docker_network(docker_network).await?;

        let mut docker_args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--network".to_string(),
            docker_network.to_string(),
        ];

        if let Some(ref options) = app.config.docker_options {
            docker_args.push(options.clone());
        }

        docker_args.push("-e".to_string());
        docker_args.push(format!("PORT={}", port));
        docker_args.push("-e".to_string());
        docker_args.push(format!("WORKERS={}", app.config.workers));

        if let Some(ref health_check) = app.config.health_check {
            docker_args.push("-e".to_string());
            docker_args.push(format!("HEALTH_CHECK={}", health_check));
        }

        docker_args.push(docker_image.to_string());

        let shell_cmd = if script.contains(" ") {
            format!("/bin/sh -c '{}'", script.replace("'", "'\\''"))
        } else {
            script.clone()
        };
        docker_args.push(shell_cmd);

        tracing::info!(
            "Starting Docker container {} for {} slot {} with image {}",
            container_name,
            app.config.name,
            slot,
            docker_image
        );

        let output_text = tokio::process::Command::new("docker")
            .args(&docker_args)
            .current_dir(&app.path)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::from(output))
            .output()
            .await?;

        if !output_text.status.success() {
            anyhow::bail!(
                "Docker run failed for {} slot {}: {}",
                app.config.name,
                slot,
                String::from_utf8_lossy(&output_text.stderr)
            );
        }

        let container_id = String::from_utf8_lossy(&output_text.stdout)
            .trim()
            .to_string();
        let pid = self.get_container_pid(&container_name).await?;

        tracing::info!(
            "Started Docker container {} ({} slot {}) with PID {}",
            container_id,
            app.config.name,
            slot,
            pid
        );

        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let container_id_for_monitoring = container_id.clone();
        let stopping_pids = self.stopping_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
                let status = tokio::process::Command::new("docker")
                    .args([
                        "inspect",
                        "-f",
                        "{{.State.Status}}",
                        &container_id_for_monitoring,
                    ])
                    .output()
                    .await;

                match status {
                    Ok(output) if output.status.success() => {
                        let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if status_str == "exited" || status_str == "dead" {
                            tracing::warn!(
                                "Container {} ({} slot {}) exited",
                                container_id_for_monitoring,
                                app_name,
                                slot_name
                            );
                            break;
                        }
                    }
                    Ok(_) | Err(_) => {
                        tracing::warn!(
                            "Container {} ({} slot {}) no longer exists",
                            container_id_for_monitoring,
                            app_name,
                            slot_name
                        );
                        break;
                    }
                }
            }
            // If intentional stop, skip notification
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            let _ = exit_tx.send(ProcessExit {
                app_name,
                slot: slot_name,
                pid,
            });
        });

        Ok(pid)
    }

    async fn get_container_pid(&self, container_name: &str) -> Result<u32> {
        let output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.State.Pid}}", container_name])
            .output()
            .await?;

        if !output.status.success() {
            anyhow::bail!("Failed to get PID for container {}", container_name);
        }

        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        pid_str
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("Invalid PID from docker inspect: {}", pid_str))
    }

    async fn stop_docker_container(&self, container_name: &str) -> Result<()> {
        let check_output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Id}}", container_name])
            .output()
            .await?;

        if check_output.status.success() {
            tracing::info!("Stopping existing container {}", container_name);
            let _ = tokio::process::Command::new("docker")
                .args(["stop", "-t", "30", container_name])
                .output()
                .await;
            let _ = tokio::process::Command::new("docker")
                .args(["rm", "-f", container_name])
                .output()
                .await;
        }
        Ok(())
    }

    async fn start_native_instance(&self, app: &AppInfo, slot: &str, port: u16) -> Result<u32> {
        if self.check_port_in_use(port).await {
            if let Some(orphan_pid) = super::find_pid_by_port(port) {
                tracing::warn!(
                    "Killing orphaned process {} on port {} before starting {} slot {}",
                    orphan_pid,
                    port,
                    app.config.name,
                    slot
                );
                // Mark as intentional stop so the process exit monitor
                // doesn't trigger a spurious failover when the orphan dies.
                self.stopping_pids.lock().unwrap().insert(orphan_pid);
                let pgid = format!("-{}", orphan_pid);
                let _ = tokio::process::Command::new("kill")
                    .arg("-TERM")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await;

                // Wait for port to be free AND process to fully exit.
                // Just waiting for the port is not enough — the orphan's
                // shutdown sequence may still be running and could kill the
                // replacement process (e.g. via a shared PID/lock file).
                for _ in 0..20 {
                    sleep(Duration::from_millis(100)).await;
                    if !self.check_port_in_use(port).await {
                        break;
                    }
                }

                // Always SIGKILL the orphan group after port is free —
                // the main process may have released the port but worker
                // children can still be alive running shutdown handlers
                // that interfere with the replacement process.
                let _ = tokio::process::Command::new("kill")
                    .arg("-9")
                    .arg("--")
                    .arg(&pgid)
                    .output()
                    .await;

                // Wait for the entire process group to be gone
                for _ in 0..20 {
                    sleep(Duration::from_millis(100)).await;
                    let alive = tokio::process::Command::new("kill")
                        .arg("-0")
                        .arg("--")
                        .arg(&pgid)
                        .output()
                        .await
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if !alive {
                        break;
                    }
                }
            }

            if self.check_port_in_use(port).await {
                anyhow::bail!(
                    "Port {} is already in use by another process. Cannot start {} slot {}",
                    port,
                    app.config.name,
                    slot
                );
            }
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

        let mut child = unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()?
        };

        let pid = child.id().unwrap_or(0);
        tracing::info!(
            "Started {} slot {} with PID {} using command: {} {:?}",
            app.config.name,
            slot,
            pid,
            program,
            args
        );
        tracing::info!("Full start command: {} {}", program, args.join(" "));

        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let stopping_pids = self.stopping_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        if let Some(signal) = status.signal() {
                            tracing::warn!(
                                "Process {} ({} slot {}) killed by signal {}",
                                pid,
                                app_name,
                                slot_name,
                                signal
                            );
                        } else {
                            tracing::warn!(
                                "Process {} ({} slot {}) exited with status {}",
                                pid,
                                app_name,
                                slot_name,
                                status
                            );
                        }
                    }
                    #[cfg(not(unix))]
                    tracing::warn!(
                        "Process {} ({} slot {}) exited with status {}",
                        pid,
                        app_name,
                        slot_name,
                        status
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to wait for process {} ({} slot {}): {}",
                        pid,
                        app_name,
                        slot_name,
                        e
                    );
                }
            }
            // If this was an intentional stop, just clean up the marker
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            // Unexpected exit — notify AppManager for immediate failover
            let _ = exit_tx.send(ProcessExit {
                app_name,
                slot: slot_name,
                pid,
            });
        });

        Ok(pid)
    }

    pub async fn stop_instance(&self, app: &AppInfo, slot: &str) -> Result<()> {
        if let Some(ref _docker_image) = app.config.docker_image {
            let container_name = format!("{}-{}", app.config.name, slot);
            return self.stop_docker_container(&container_name).await;
        }

        let pid = if slot == "blue" {
            app.blue.pid
        } else {
            app.green.pid
        };

        if let Some(pid) = pid {
            // Mark as intentional stop so the exit monitor ignores it
            self.stopping_pids.lock().unwrap().insert(pid);

            // Drain delay: let in-flight requests finish before sending SIGTERM
            let drain = app.config.drain_delay as u64;
            if drain > 0 {
                tracing::info!(
                    "Draining {} slot {} for {}s before SIGTERM (PID: {})",
                    app.config.name,
                    slot,
                    drain,
                    pid
                );
                sleep(Duration::from_secs(drain)).await;
            }

            tracing::info!("Stopping {} slot {} (PID: {})", app.config.name, slot, pid);

            #[cfg(unix)]
            {
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
            // Sleep between retries, but try immediately on the first attempt
            if i > 0 {
                sleep(Duration::from_secs(1)).await;
            }

            match self.http_client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "Health check passed for {} slot {} after {}s",
                        app.config.name,
                        slot,
                        i
                    );
                    return Ok(true);
                }
                Ok(_) => {
                    tracing::debug!(
                        "Health check response for {} slot {}: attempt {}",
                        app.config.name,
                        slot,
                        i + 1
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "Health check failed for {} slot {}: {} (attempt {})",
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
