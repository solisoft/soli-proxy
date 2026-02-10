use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use super::AppInfo;

#[derive(Debug, Clone, PartialEq)]
pub enum DeploymentStatus {
    Idle,
    Deploying,
    RollingBack,
    Failed(String),
}

pub struct DeploymentManager {
    status: Arc<AtomicBool>,
    dev_mode: bool,
}

impl Default for DeploymentManager {
    fn default() -> Self {
        Self::new(false)
    }
}

impl DeploymentManager {
    pub fn new(dev_mode: bool) -> Self {
        Self {
            status: Arc::new(AtomicBool::new(false)),
            dev_mode,
        }
    }

    pub async fn is_deploying(&self) -> bool {
        self.status.load(Ordering::SeqCst)
    }

    /// Deploy an app to a slot. Returns the PID of the started process.
    pub async fn deploy(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        if self.status.load(Ordering::SeqCst) {
            anyhow::bail!("Another deployment is in progress");
        }

        self.status.store(true, Ordering::SeqCst);
        let _guard = scopeguard::guard((), |_| {
            self.status.store(false, Ordering::SeqCst);
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

    async fn start_instance(&self, app: &AppInfo, slot: &str) -> Result<u32> {
        let port = if slot == "blue" {
            app.blue.port
        } else {
            app.green.port
        };

        let base_script =
            app.config.start_script.as_ref().ok_or_else(|| {
                anyhow::anyhow!("No start script configured for {}", app.config.name)
            })?;

        let script = if self.dev_mode {
            format!("{} --dev", base_script)
        } else {
            base_script.clone()
        };

        let output_file = PathBuf::from(format!("run/logs/{}/{}.log", app.config.name, slot));
        std::fs::create_dir_all(output_file.parent().unwrap())?;

        let output = std::fs::File::create(&output_file)?;

        let cmd = unsafe {
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .current_dir(&app.path)
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("PORT", port.to_string())
                .env("WORKERS", app.config.workers.to_string())
                .stdout(std::process::Stdio::from(output.try_clone()?))
                .stderr(std::process::Stdio::from(output))
                .pre_exec(|| {
                    // Create a new process group so we can kill the entire group later
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
                for _ in 0..timeout {
                    let output = tokio::process::Command::new("kill")
                        .arg("-0")
                        .arg(pid.to_string())
                        .output()
                        .await?;

                    if !output.status.success() {
                        tracing::info!("Process {} terminated gracefully", pid);
                        return Ok(());
                    }
                    sleep(Duration::from_secs(1)).await;
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

    async fn wait_for_health(&self, app: &AppInfo, slot: &str) -> Result<bool> {
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

            match reqwest::Client::new().get(&url).send().await {
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
        let log_path = PathBuf::from(format!("run/logs/{}/{}.log", app_name, slot));
        if log_path.exists() {
            Ok(std::fs::read_to_string(&log_path)?)
        } else {
            Ok(String::new())
        }
    }
}
