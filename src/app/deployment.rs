use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
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

/// Validate that docker_options does not contain flags that would break
/// container isolation or expose the host.
///
/// Normalizes `--flag=value` to `--flag value` and lowercases before checking,
/// so `--pid=host` and `--pid host` are caught identically and a denied flag
/// can't be smuggled past the previous substring denylist by changing the
/// `=`/space separator or casing. `docker_options` comes from on-disk
/// `app.infos`, so this is defense-in-depth against a compromised/misconfigured
/// app rather than a network-facing check.
fn validate_docker_options(options: &str) -> Result<()> {
    // `=` is treated as a token separator so value-bearing flags normalize to
    // two tokens; this makes the host-namespace and mount checks below uniform.
    let normalized = options.to_lowercase().replace('=', " ");
    let tokens: Vec<&str> = normalized.split_whitespace().collect();

    // Flags that grant host access / capabilities outright — disallowed with
    // any value.
    const DENIED_FLAGS: &[&str] = &[
        "--privileged",
        "--cap-add",
        "--device",
        "--security-opt",
        "--userns",
        "--cgroupns",
        "--pid-mode",
    ];
    // Namespace flags that are only dangerous when set to the host namespace.
    const HOST_NS_FLAGS: &[&str] = &["--pid", "--ipc", "--uts", "--network", "--net"];
    // Bind-mount flags whose source we inspect for host-exposing paths.
    const MOUNT_FLAGS: &[&str] = &["-v", "--volume", "--mount"];

    for (i, tok) in tokens.iter().enumerate() {
        if DENIED_FLAGS.contains(tok) {
            anyhow::bail!("docker_options contains disallowed flag: {}", tok);
        }
        if HOST_NS_FLAGS.contains(tok) && tokens.get(i + 1).is_some_and(|v| *v == "host") {
            anyhow::bail!(
                "docker_options requests the host {} namespace, which is disallowed",
                tok
            );
        }
        if MOUNT_FLAGS.contains(tok) {
            if let Some(spec) = tokens.get(i + 1) {
                // Mounting the docker socket grants full control of the daemon;
                // mounting the host root filesystem exposes everything.
                if spec.contains("docker.sock") || spec.starts_with("/:") || *spec == "/" {
                    anyhow::bail!("docker_options contains a disallowed host mount: {}", spec);
                }
            }
        }
    }

    // Belt-and-braces: the docker socket must never appear anywhere, even if a
    // mount is expressed in a form the per-token check above doesn't split
    // cleanly (e.g. `--mount type=bind,source=/var/run/docker.sock,...`).
    if normalized.contains("docker.sock") {
        anyhow::bail!("docker_options mounts the docker socket, which is disallowed");
    }

    Ok(())
}
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
    /// PIDs that exited unexpectedly, mapped to a human-readable reason.
    /// Read by `wait_for_health` so it can bail out as soon as the process it
    /// is waiting on dies, instead of polling a dead port for 30s.
    exited_pids: Arc<Mutex<HashMap<u32, String>>>,
    /// Ports currently mapped to PIDs that we spawned (port -> pid).
    /// Used to verify we only kill processes we spawned, not unrelated listeners.
    spawned_pids: Arc<Mutex<HashMap<u16, u32>>>,
    /// Channel to notify AppManager of unexpected process exits
    process_exit_tx: mpsc::UnboundedSender<ProcessExit>,
    dev_mode: bool,
    http_client: reqwest::Client,
    default_user: Option<String>,
    default_group: Option<String>,
    /// Untrusted-tenant mode: require containers and impose hardening the app
    /// cannot weaken. See `AppsTomlConfig::multi_tenant`.
    multi_tenant: bool,
    /// Container flags appended after the app's own `docker_options`, so the
    /// platform's values win.
    mandatory_docker_args: Vec<String>,
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
            exited_pids: Arc::new(Mutex::new(HashMap::new())),
            spawned_pids: Arc::new(Mutex::new(HashMap::new())),
            process_exit_tx,
            dev_mode,
            http_client,
            default_user,
            default_group,
            multi_tenant: false,
            mandatory_docker_args: Vec::new(),
        }
    }

    /// Enable untrusted-tenant mode with the platform's mandatory container
    /// flags. Off by default, so existing single-tenant deployments are
    /// unaffected.
    pub fn with_tenant_isolation(mut self, enabled: bool, mandatory_args: Vec<String>) -> Self {
        self.multi_tenant = enabled;
        self.mandatory_docker_args = mandatory_args;
        self
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

        if let Err(e) = self.wait_for_health(app, slot, pid).await {
            self.stop_instance(app, slot).await?;
            return Err(e);
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

        // Refuse to start untrusted code outside a container. The native path
        // gives a tenant process the host filesystem — every other tenant's
        // site directory, `certs/`, and `config.toml` with the admin API key —
        // so falling back to it under multi-tenant mode would silently undo the
        // isolation the mode exists to provide. Failing the deploy is the point.
        if self.multi_tenant {
            anyhow::bail!(
                "{} has no docker_image, and [apps] multi_tenant = true forbids the native \
                 start path: it does not isolate the app from the host filesystem or from \
                 other tenants",
                app.config.name
            );
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
            validate_docker_options(options)?;
            // Split into individual argv tokens: pushing the whole string as a
            // single argument makes docker treat e.g. "-e FOO=bar" as one
            // (invalid) flag. Whitespace-splitting matches how a shell would
            // tokenize simple options (no quoting/escaping is supported).
            for token in options.split_whitespace() {
                docker_args.push(token.to_string());
            }
        }

        // Platform hardening goes last so it wins: `docker run` takes the final
        // occurrence of a repeated flag, so an app that sets its own --memory
        // or --user cannot raise its ceiling or become root.
        docker_args.extend(self.mandatory_docker_args.iter().cloned());

        docker_args.push("-e".to_string());
        docker_args.push(format!("PORT={}", port));
        docker_args.push("-e".to_string());
        docker_args.push(format!("WORKERS={}", app.config.workers));

        if let Some(ref health_check) = app.config.health_check {
            docker_args.push("-e".to_string());
            docker_args.push(format!("HEALTH_CHECK={}", health_check));
        }

        docker_args.push(docker_image.to_string());

        // Never use a shell for the container command — same argv parsing as
        // the native spawn path, so a compromised start_script cannot inject
        // via `/bin/sh -c`.
        let (program, args) = parse_start_command(&script, port, app.config.workers)?;
        docker_args.push(program);
        docker_args.extend(args);

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
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("LANG", std::env::var("LANG").unwrap_or_default())
            .env("TZ", std::env::var("TZ").unwrap_or_default())
            .env("PORT", port.to_string())
            .env("WORKERS", app.config.workers.to_string())
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
        let exited_pids = self.exited_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            let reason = loop {
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
                            let reason = format!("container {}", status_str);
                            tracing::warn!(
                                "Container {} ({} slot {}) {}",
                                container_id_for_monitoring,
                                app_name,
                                slot_name,
                                reason
                            );
                            break reason;
                        }
                    }
                    Ok(_) | Err(_) => {
                        let reason = "container no longer exists".to_string();
                        tracing::warn!(
                            "Container {} ({} slot {}) {}",
                            container_id_for_monitoring,
                            app_name,
                            slot_name,
                            reason
                        );
                        break reason;
                    }
                }
            };
            // If intentional stop, skip notification
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            exited_pids.lock().unwrap().insert(pid, reason);
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
                let spawned_pid = self.spawned_pids.lock().unwrap().get(&port).copied();
                if orphan_pid <= 1 {
                    tracing::warn!(
                        "Rejecting unsafe PID {} on port {} for {} slot {}",
                        orphan_pid,
                        port,
                        app.config.name,
                        slot
                    );
                } else if orphan_pid != spawned_pid.unwrap_or(0) {
                    tracing::warn!(
                        "Port {} is in use by PID {} which was not spawned by the proxy. \
                         Refusing to kill it for {} slot {}",
                        port,
                        orphan_pid,
                        app.config.name,
                        slot
                    );
                } else {
                    tracing::warn!(
                        "Killing orphaned process {} on port {} before starting {} slot {}",
                        orphan_pid,
                        port,
                        app.config.name,
                        slot
                    );
                    self.stopping_pids.lock().unwrap().insert(orphan_pid);
                    let pgid = format!("-{}", orphan_pid);
                    let _ = tokio::process::Command::new("kill")
                        .arg("-TERM")
                        .arg("--")
                        .arg(&pgid)
                        .output()
                        .await;

                    for _ in 0..20 {
                        sleep(Duration::from_millis(100)).await;
                        if !self.check_port_in_use(port).await {
                            break;
                        }
                    }

                    let _ = tokio::process::Command::new("kill")
                        .arg("-9")
                        .arg("--")
                        .arg(&pgid)
                        .output()
                        .await;

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
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("LANG", std::env::var("LANG").unwrap_or_default())
            .env("TZ", std::env::var("TZ").unwrap_or_default())
            .env("PORT", port.to_string())
            .env("WORKERS", app.config.workers.to_string())
            .args(&args)
            .current_dir(&app.path)
            .stdout(std::process::Stdio::from(output.try_clone()?))
            .stderr(std::process::Stdio::from(output));

        let user = app.config.user.as_ref().or(self.default_user.as_ref());
        let group = app.config.group.as_ref().or(self.default_group.as_ref());

        #[cfg(unix)]
        let proxy_is_root = unsafe { libc::geteuid() } == 0;

        #[cfg(unix)]
        if proxy_is_root && user.is_none() {
            anyhow::bail!(
                "Refusing to spawn {} as root: no user/group configured. \
                 Set `user` in app.infos or default_user in [apps], or run the proxy as non-root.",
                app.config.name
            );
        }

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

        let run_as = match user {
            Some(user) => format!("as user `{}`", user),
            None => "as the proxy's own user".to_string(),
        };
        let mut child = unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                #[cfg(target_os = "linux")]
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                Ok(())
            })
            .spawn()
        }
        .with_context(|| {
            format!(
                "Failed to spawn `{}` for {} (in {}) {}. \
                 A `Permission denied` error usually means that user cannot execute the \
                 program or traverse the working directory — check file ownership/permissions \
                 (e.g. `ls -l {0}`) and that every parent directory is accessible to that user.",
                program,
                app.config.name,
                app.path.display(),
                run_as,
            )
        })?;

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

        if pid > 0 {
            self.spawned_pids.lock().unwrap().insert(port, pid);
        }

        let app_name = app.config.name.clone();
        let slot_name = slot.to_string();
        let stopping_pids = self.stopping_pids.clone();
        let exited_pids = self.exited_pids.clone();
        let exit_tx = self.process_exit_tx.clone();
        tokio::spawn(async move {
            let reason = match child.wait().await {
                Ok(status) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        if let Some(signal) = status.signal() {
                            format!("killed by signal {}", signal)
                        } else if let Some(code) = status.code() {
                            format!("exited with status {}", code)
                        } else {
                            format!("exited ({})", status)
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        if let Some(code) = status.code() {
                            format!("exited with status {}", code)
                        } else {
                            format!("exited ({})", status)
                        }
                    }
                }
                Err(e) => format!("wait failed: {}", e),
            };
            tracing::warn!(
                "Process {} ({} slot {}) {}",
                pid,
                app_name,
                slot_name,
                reason
            );
            // If this was an intentional stop, just clean up the marker
            if stopping_pids.lock().unwrap().remove(&pid) {
                return;
            }
            // Unexpected exit — record reason so wait_for_health can surface
            // it, then notify AppManager for immediate failover
            exited_pids.lock().unwrap().insert(pid, reason);
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
            if slot == "blue" {
                self.spawned_pids.lock().unwrap().remove(&app.blue.port);
            } else {
                self.spawned_pids.lock().unwrap().remove(&app.green.port);
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

    pub async fn wait_for_health(&self, app: &AppInfo, slot: &str, pid: u32) -> Result<()> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };
        let health_path = app.config.health_check.as_deref().unwrap_or("/health");

        let url = format!("http://localhost:{}{}", port, health_path);
        let log_path = format!("run/logs/{}/{}.log", app.config.name, slot);
        let timeout_secs = 30;
        let mut last_err: Option<String> = None;

        for i in 0..timeout_secs {
            // Sleep between retries, but try immediately on the first attempt
            if i > 0 {
                sleep(Duration::from_secs(1)).await;
            }

            // Bail early if the process already died — no point polling a dead
            // port for the full 30s.
            if let Some(reason) = self.exited_pids.lock().unwrap().get(&pid).cloned() {
                anyhow::bail!(
                    "{} slot {} (PID {}) {} before becoming healthy on {} (see {} for app output)",
                    app.config.name,
                    slot,
                    pid,
                    reason,
                    url,
                    log_path,
                );
            }

            match self.http_client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "Health check passed for {} slot {} after {}s",
                        app.config.name,
                        slot,
                        i
                    );
                    return Ok(());
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::debug!(
                        "Health check response for {} slot {}: HTTP {} (attempt {})",
                        app.config.name,
                        slot,
                        status,
                        i + 1
                    );
                    last_err = Some(format!("HTTP {}", status));
                }
                Err(e) => {
                    tracing::debug!(
                        "Health check failed for {} slot {}: {} (attempt {})",
                        app.config.name,
                        slot,
                        e,
                        i + 1
                    );
                    last_err = Some(e.to_string());
                }
            }
        }

        anyhow::bail!(
            "{} slot {} did not become healthy on {} within {}s (last error: {}; see {} for app output)",
            app.config.name,
            slot,
            url,
            timeout_secs,
            last_err.as_deref().unwrap_or("none"),
            log_path,
        );
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
        /// Cap admin log responses so a multi-GB log cannot OOM the proxy.
        const MAX_LOG_BYTES: u64 = 256 * 1024;

        validate_path_component(app_name, "App name")?;
        if slot != "blue" && slot != "green" {
            anyhow::bail!("Invalid slot name: {:?}", slot);
        }
        let log_path = PathBuf::from(format!("run/logs/{}/{}.log", app_name, slot));
        if !log_path.exists() {
            return Ok(String::new());
        }
        let meta = std::fs::metadata(&log_path)?;
        let file = std::fs::File::open(&log_path)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut file = file;
        let mut buf = Vec::new();
        if meta.len() > MAX_LOG_BYTES {
            file.seek(SeekFrom::End(-(MAX_LOG_BYTES as i64)))?;
            // Drop a partial first line so the response starts cleanly.
            let mut skip = [0u8; 1];
            while file.read(&mut skip)? == 1 && skip[0] != b'\n' {}
            file.read_to_end(&mut buf)?;
        } else {
            file.read_to_end(&mut buf)?;
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

fn resolve_user(user: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_user = CString::new(user)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8 as libc::c_char; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // getpwnam_r is the thread-safe variant: the non-reentrant getpwnam
        // returns a pointer into a shared static buffer that a concurrent
        // lookup (here, or anywhere else in the process) can overwrite.
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if ret == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if ret != 0 {
            anyhow::bail!(
                "Failed to look up user '{}': {}",
                user,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        break;
    }
    if result.is_null() {
        anyhow::bail!("User '{}' not found", user);
    }
    Ok(pwd.pw_uid)
}

fn resolve_group(group: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_group = CString::new(group)?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8 as libc::c_char; 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    loop {
        // getgrnam_r: thread-safe counterpart of getgrnam (see resolve_user).
        let ret = unsafe {
            libc::getgrnam_r(
                c_group.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if ret == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if ret != 0 {
            anyhow::bail!(
                "Failed to look up group '{}': {}",
                group,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        break;
    }
    if result.is_null() {
        anyhow::bail!("Group '{}' not found", group);
    }
    Ok(grp.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::{parse_start_command, validate_docker_options, validate_path_component};

    /// The hardening is a floor, not a default: it is appended after the app's
    /// own `docker_options`, and `docker run` honours the last occurrence of a
    /// repeated flag. A tenant that sets `--memory 64g --user 0:0` must still
    /// end up with the platform's ceiling and a non-root uid.
    #[test]
    fn mandatory_docker_args_override_app_supplied_ones() {
        let cfg = crate::config::AppsTomlConfig {
            multi_tenant: Some(true),
            tenant_memory: Some("256m".to_string()),
            tenant_cpus: Some("0.5".to_string()),
            ..Default::default()
        };

        let app_options = ["--memory", "64g", "--user", "0:0"];
        let mut argv: Vec<String> = app_options.iter().map(|s| s.to_string()).collect();
        argv.extend(cfg.mandatory_docker_args());

        let last_value = |flag: &str| -> Option<String> {
            argv.iter()
                .enumerate()
                .rfind(|(_, tok)| tok.as_str() == flag)
                .and_then(|(i, _)| argv.get(i + 1).cloned())
        };

        assert_eq!(last_value("--memory").as_deref(), Some("256m"));
        assert_eq!(last_value("--cpus").as_deref(), Some("0.5"));
        assert_eq!(last_value("--user").as_deref(), Some("10000:10000"));
        assert!(argv.iter().any(|a| a == "--read-only"));
        assert!(argv.iter().any(|a| a == "--cap-drop"));
        assert!(argv.iter().any(|a| a == "no-new-privileges"));
        assert!(argv.iter().any(|a| a == "--pids-limit"));
    }

    #[test]
    fn multi_tenant_defaults_off_so_existing_deployments_are_unchanged() {
        let cfg = crate::config::AppsTomlConfig::default();
        assert!(!cfg.multi_tenant());
    }

    #[test]
    fn docker_options_allows_benign_flags() {
        assert!(validate_docker_options("-e FOO=bar --memory 512m").is_ok());
        assert!(validate_docker_options("-v /srv/data:/data:ro").is_ok());
        assert!(validate_docker_options("").is_ok());
    }

    #[test]
    fn docker_options_rejects_privileged_and_caps() {
        assert!(validate_docker_options("--privileged").is_err());
        assert!(validate_docker_options("--cap-add=NET_ADMIN").is_err());
        assert!(validate_docker_options("--CAP-ADD SYS_ADMIN").is_err());
        assert!(validate_docker_options("--device /dev/kmsg").is_err());
        assert!(validate_docker_options("--security-opt seccomp=unconfined").is_err());
    }

    #[test]
    fn docker_options_rejects_host_namespaces_regardless_of_separator() {
        assert!(validate_docker_options("--pid=host").is_err());
        assert!(validate_docker_options("--pid host").is_err());
        assert!(validate_docker_options("--network=host").is_err());
        assert!(validate_docker_options("--net host").is_err());
        assert!(validate_docker_options("--ipc host").is_err());
        assert!(validate_docker_options("--uts=host").is_err());
        // A user-defined network name (not "host") is fine.
        assert!(validate_docker_options("--network my-net").is_ok());
    }

    #[test]
    fn docker_options_rejects_host_mounts() {
        assert!(validate_docker_options("-v /:/host").is_err());
        assert!(
            validate_docker_options("--volume /var/run/docker.sock:/var/run/docker.sock").is_err()
        );
        assert!(validate_docker_options(
            "--mount type=bind,source=/var/run/docker.sock,target=/sock"
        )
        .is_err());
    }

    #[test]
    fn start_command_substitutes_port_and_workers_without_shell() {
        let (program, args) =
            parse_start_command("./serve --port $PORT -w $WORKERS", 8080, 4).expect("parses");
        assert_eq!(program, "./serve");
        assert_eq!(args, vec!["--port", "8080", "-w", "4"]);
    }

    #[test]
    fn path_component_rejects_traversal() {
        assert!(validate_path_component("myapp", "App name").is_ok());
        assert!(validate_path_component("..", "App name").is_err());
        assert!(validate_path_component("a/b", "App name").is_err());
        assert!(validate_path_component("a\0b", "App name").is_err());
    }
}
