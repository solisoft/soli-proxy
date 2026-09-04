use anyhow::Result;
use clap::Parser;
use soli_proxy::acme;
use soli_proxy::app::{AppEvent, AppManager, PortManager};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::new_challenge_store;
use soli_proxy::new_metrics;
use soli_proxy::AdminState;
use soli_proxy::ConfigManager;
use soli_proxy::ProxyServer;
use soli_proxy::ShutdownCoordinator;
use soli_proxy::TlsManager;
use std::fs;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio_rustls::TlsAcceptor;

fn daemonize() -> Result<()> {
    unsafe {
        #[cfg(unix)]
        {
            let pid = libc::fork();
            if pid < 0 {
                return Err(anyhow::anyhow!("Failed to fork process"));
            }
            if pid > 0 {
                std::process::exit(0);
            }
            libc::setsid();

            let null_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR, 0);
            if null_fd >= 0 {
                libc::dup2(null_fd, libc::STDIN_FILENO);
                libc::dup2(null_fd, libc::STDOUT_FILENO);
                libc::dup2(null_fd, libc::STDERR_FILENO);
                if null_fd > 2 {
                    libc::close(null_fd);
                }
            }
        }
    }
    Ok(())
}

fn get_pid_dir() -> String {
    std::env::var("SOLI_PID_DIR").unwrap_or_else(|_| ".".to_string())
}

fn get_log_dir() -> String {
    std::env::var("SOLI_LOG_DIR").unwrap_or_else(|_| ".".to_string())
}

fn get_pid_path() -> String {
    format!("{}/proxy.pid", get_pid_dir())
}

fn get_log_path() -> String {
    format!("{}/proxy.log", get_log_dir())
}

fn write_pid_file() -> Result<String> {
    let pid_path = get_pid_path();
    let pid_dir = std::path::Path::new(&pid_path).parent().unwrap();
    fs::create_dir_all(pid_dir).ok();
    fs::write(&pid_path, std::process::id().to_string())?;
    Ok(pid_path)
}

fn cleanup_pid() {
    let pid_path = get_pid_path();
    let _ = fs::remove_file(&pid_path);
}

fn is_process_running(pid: i32) -> bool {
    unsafe {
        let result = libc::kill(pid, 0);
        result == 0
    }
}

fn kill_existing_daemon() -> Result<()> {
    let pid_path = get_pid_path();
    if let Ok(content) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = content.trim().parse::<i32>() {
            if pid > 0 && is_process_running(pid) {
                println!("Stopping existing daemon (PID: {})...", pid);
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }

                let max_wait = std::time::Duration::from_secs(10);
                let start = std::time::Instant::now();
                let check_interval = std::time::Duration::from_millis(100);

                while start.elapsed() < max_wait {
                    if !is_process_running(pid) {
                        println!("Daemon stopped successfully");
                        break;
                    }
                    std::thread::sleep(check_interval);
                }

                if is_process_running(pid) {
                    println!("Daemon did not stop gracefully, forcing kill...");
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        let _ = fs::remove_file(&pid_path);
    }
    Ok(())
}

fn setup_logging(daemon: bool) -> Result<()> {
    if daemon {
        let log_path = get_log_path();
        let log_dir = std::path::Path::new(&log_path).parent().unwrap();
        fs::create_dir_all(log_dir).ok();

        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(file)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .init();
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "soli-proxy")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[arg(short, long, default_value = "./proxy.conf")]
    conf: String,

    #[arg(short, long)]
    daemon: bool,

    #[arg(long)]
    dev: bool,

    #[arg(long, default_value = "true")]
    watch: bool,

    #[arg(long, default_value = "./sites")]
    sites_dir: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Parser, Debug)]
enum Commands {
    Tui {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        #[arg(long, default_value = "./sites")]
        sites_dir: String,

        #[arg(long)]
        dev: bool,
    },
    Update {
        #[arg(long)]
        reinstall: bool,

        /// Skip SHA-256 verification of the downloaded release artifact.
        /// Only use for releases predating checksum emission. The standard
        /// path requires a `.sha256` sibling file in the GitHub release.
        #[arg(long)]
        allow_unverified: bool,
    },
    Deploy {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    Restart {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    Stop {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    Logs {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::Tui {
        conf,
        sites_dir,
        dev,
    }) = cli.command
    {
        return soli_proxy::tui::run_tui_with_config(&conf, &sites_dir, dev);
    }

    if let Some(Commands::Update {
        reinstall,
        allow_unverified,
    }) = cli.command
    {
        return run_update(reinstall, allow_unverified);
    }

    if let Some(Commands::Deploy { conf, app_name }) = cli.command {
        return run_app_command(&conf, &app_name, "deploy");
    }

    if let Some(Commands::Restart { conf, app_name }) = cli.command {
        return run_app_command(&conf, &app_name, "restart");
    }

    if let Some(Commands::Stop { conf, app_name }) = cli.command {
        return run_app_command(&conf, &app_name, "stop");
    }

    if let Some(Commands::Logs { conf, app_name }) = cli.command {
        return run_app_command(&conf, &app_name, "logs");
    }

    if !std::path::Path::new(&cli.conf).exists() {
        eprintln!(
            "Error: config file '{}' not found in current directory",
            cli.conf
        );
        std::process::exit(1);
    }

    if cli.daemon {
        kill_existing_daemon()?;
        daemonize()?;
        let _ = write_pid_file()?;
    }

    let worker_threads_cfg = soli_proxy::config::read_worker_threads(&cli.conf);
    let resolved_workers =
        soli_proxy::config::resolve_worker_threads(cli.dev, worker_threads_cfg.as_ref());

    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    rt_builder.enable_all();
    if let Some(n) = resolved_workers {
        rt_builder.worker_threads(n);
    }
    let rt = rt_builder.build()?;
    rt.block_on(async move {
        run_server(&cli.conf, cli.daemon, cli.dev, cli.watch, &cli.sites_dir).await
    })
}

/// Compute the SHA-256 digest of a file as lowercase hex.
fn sha256_hex(path: &std::path::Path) -> Result<String> {
    use sha2::Digest;
    let bytes = std::fs::read(path)?;
    let digest = sha2::Sha256::digest(&bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{:02x}", b));
    }
    Ok(hex)
}

/// Parse the leading 64-char lowercase-hex digest from a `.sha256` file body.
/// Accepts both `<digest>` and `<digest>  <filename>` shasum-format lines.
fn parse_sha256_file(content: &str) -> Result<String> {
    let token = content
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty .sha256 file"))?;
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("malformed .sha256 file: expected 64-char hex digest");
    }
    Ok(token.to_ascii_lowercase())
}

fn run_update(reinstall: bool, allow_unverified: bool) -> Result<()> {
    let repo = "solisoft/soli-proxy";
    let current_version = env!("CARGO_PKG_VERSION");

    println!("Current version: {}", current_version);

    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        anyhow::bail!("Unsupported operating system");
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        anyhow::bail!("Unsupported architecture");
    };

    println!("Detected platform: {}-{}", os, arch);

    // Fetch latest release tag
    println!("Fetching latest release info...");
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let output = Command::new("curl").args(["-fsSL", &api_url]).output()?;

    if !output.status.success() {
        anyhow::bail!("Failed to fetch release info from GitHub API");
    }

    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| anyhow::anyhow!("Failed to parse GitHub API response"))?;

    let tag = response["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No tag_name in GitHub API response"))?;
    let tag_version = tag.trim_start_matches('v');

    if !reinstall && current_version == tag_version {
        println!("Already on latest version: {}", tag);
        return Ok(());
    }

    println!("Latest version: {}", tag);

    // Download and extract
    let tarball = format!("soli-proxy-{}-{}.tar.gz", os, arch);
    let download_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, tarball
    );
    let sha256_url = format!("{}.sha256", download_url);

    let tmp_dir = Command::new("mktemp").arg("-d").output()?;
    let tmp_dir = String::from_utf8_lossy(&tmp_dir.stdout).trim().to_string();
    let tarball_path = format!("{}/{}", tmp_dir, tarball);
    let sha256_path = format!("{}.sha256", tarball_path);

    println!("Downloading {}...", download_url);
    let dl = Command::new("curl")
        .args(["-fsSL", "-o", &tarball_path, &download_url])
        .output()?;
    if !dl.status.success() {
        let _ = fs::remove_dir_all(&tmp_dir);
        anyhow::bail!(
            "Failed to download {}. Does this release have prebuilt binaries?",
            download_url
        );
    }

    // Verify SHA-256. The release pipeline emits a sibling `.sha256` file for
    // each tarball. If it is missing or does not match, refuse to install
    // unless --allow-unverified is set. TLS to github.com is not enough
    // protection against a compromised release artifact.
    println!("Verifying SHA-256...");
    let sha_dl = Command::new("curl")
        .args(["-fsSL", "-o", &sha256_path, &sha256_url])
        .output()?;

    if sha_dl.status.success() {
        let sha_content = std::fs::read_to_string(&sha256_path).unwrap_or_default();
        let expected = parse_sha256_file(&sha_content).map_err(|e| {
            let _ = fs::remove_dir_all(&tmp_dir);
            anyhow::anyhow!("Could not parse {}: {}", sha256_url, e)
        })?;
        let actual = sha256_hex(std::path::Path::new(&tarball_path)).map_err(|e| {
            let _ = fs::remove_dir_all(&tmp_dir);
            anyhow::anyhow!("Failed to hash downloaded tarball: {}", e)
        })?;
        if expected != actual {
            let _ = fs::remove_dir_all(&tmp_dir);
            anyhow::bail!(
                "SHA-256 mismatch for {}\n  expected: {}\n  actual:   {}\n\
                 Refusing to install. The release artifact may have been tampered with.",
                tarball,
                expected,
                actual
            );
        }
        println!("SHA-256 OK ({}).", actual);
    } else if allow_unverified {
        eprintln!(
            "WARNING: no .sha256 sibling found at {}. \
             Proceeding without verification because --allow-unverified was passed. \
             A compromised release would install silently.",
            sha256_url
        );
    } else {
        let _ = fs::remove_dir_all(&tmp_dir);
        anyhow::bail!(
            "No .sha256 file found at {}. Refusing to install unverified binary.\n\
             If you trust this release (e.g. it predates checksum emission), \
             re-run with `--allow-unverified`.",
            sha256_url
        );
    }

    println!("Extracting...");
    let tar = Command::new("tar")
        .args(["xzf", &tarball_path, "-C", &tmp_dir])
        .output()?;
    if !tar.status.success() {
        let _ = fs::remove_dir_all(&tmp_dir);
        anyhow::bail!("Failed to extract tarball");
    }

    let new_binary = format!("{}/soli-proxy", tmp_dir);
    if !std::path::Path::new(&new_binary).exists() {
        let _ = fs::remove_dir_all(&tmp_dir);
        anyhow::bail!("soli-proxy binary not found in tarball");
    }

    // Install to the same location as the currently running binary
    let current_exe = std::env::current_exe()?;
    let install_path = current_exe.canonicalize().unwrap_or(current_exe);
    let is_dev_binary = install_path.to_string_lossy().contains("target/");

    if is_dev_binary {
        println!("\nDevelopment binary detected.");
        println!("New binary downloaded to: {}", new_binary);
        println!("\nTo install, run:");
        println!(
            "  sudo install -m 755 {} /usr/local/bin/soli-proxy",
            new_binary
        );
    } else {
        println!("Installing to {}...", install_path.display());

        // Use `install -m 755` like install.sh — atomic replacement, handles running binaries
        let install_path_str = install_path.to_string_lossy();
        let result = Command::new("install")
            .args(["-m", "755", &new_binary, &*install_path_str])
            .output()?;

        if !result.status.success() {
            // We do NOT auto-escalate to sudo — silently invoking sudo from a
            // background command is a sharp edge. Tell the user what to run.
            let _ = fs::remove_dir_all(&tmp_dir);
            anyhow::bail!(
                "Failed to install binary to {}.\n\
                 If this is a permission error, re-run as root or run:\n  \
                 sudo install -m 755 {} {}",
                install_path.display(),
                new_binary,
                install_path.display()
            );
        }

        let _ = fs::remove_dir_all(&tmp_dir);

        println!("Soli-proxy {} installed successfully!", tag);

        if reinstall {
            println!("Restarting soli-proxy...");
            std::process::exit(0);
        }
    }

    Ok(())
}

fn run_app_command(config_path: &str, app_name: &str, action: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let config_manager = ConfigManager::new(config_path)?;
        let config_ref = Arc::new(config_manager);

        // If a daemon is running, delegate through its admin API: only the
        // daemon knows which slot is live and owns the app PIDs. A standalone
        // AppManager here would target the live slot whenever the daemon last
        // promoted green, and can never replace processes it didn't spawn.
        if matches!(action, "deploy" | "restart" | "stop") {
            match delegate_to_daemon(&config_ref, app_name, action).await {
                DaemonDelegation::Done(message) => {
                    println!("{}", message);
                    return Ok(());
                }
                DaemonDelegation::Refused(err) => return Err(err),
                DaemonDelegation::NoDaemon => {}
            }
        }

        let port_manager = Arc::new(PortManager::new("./run").unwrap());
        let _ = port_manager.load().await;

        let app_manager =
            AppManager::new("./sites", port_manager.clone(), config_ref.clone(), false)?;
        let app_manager = Arc::new(app_manager);
        app_manager.spawn_process_exit_monitor();

        if let Err(e) = app_manager.discover_apps_readonly().await {
            tracing::error!("Failed to discover apps: {}", e);
        }
        // Fresh discovery defaults every app's current_slot to blue; read the
        // slot persisted at last promotion so deploy/restart act on reality.
        app_manager.load_app_state_async().await;

        match action {
            "deploy" => {
                let target_slot =
                    app_manager
                        .get_app(app_name)
                        .await
                        .map_or("blue".to_string(), |app| {
                            if app.current_slot == "blue" {
                                "green".to_string()
                            } else {
                                "blue".to_string()
                            }
                        });
                app_manager.deploy(app_name, &target_slot).await?;
                println!("{} deployed successfully", app_name);
            }
            "restart" => {
                app_manager.restart(app_name).await?;
                println!("{} restarted successfully", app_name);
            }
            "stop" => {
                app_manager.stop(app_name).await?;
                println!("{} stopped successfully", app_name);
            }
            "logs" => {
                let blue_log = app_manager
                    .deployment_manager
                    .get_deployment_log(app_name, "blue")
                    .await
                    .unwrap_or_default();
                let green_log = app_manager
                    .deployment_manager
                    .get_deployment_log(app_name, "green")
                    .await
                    .unwrap_or_default();
                println!("=== {} (blue) ===", app_name);
                println!("{}", blue_log);
                println!("=== {} (green) ===", app_name);
                println!("{}", green_log);
            }
            _ => {
                anyhow::bail!("Unknown action: {}", action);
            }
        }
        Ok(())
    })
}

enum DaemonDelegation {
    /// The daemon handled the action; contains the success message to print.
    Done(String),
    /// A daemon is running but the action failed. Do NOT fall back to a
    /// standalone AppManager — it would fight the daemon over the same apps.
    Refused(anyhow::Error),
    /// Nothing is listening on the admin bind address.
    NoDaemon,
}

/// Ask the running daemon to perform `action` on `app_name` via its admin API
/// (`POST /api/v1/apps/<name>/<action>`), authenticated with `[admin].api_key`.
async fn delegate_to_daemon(
    config: &Arc<ConfigManager>,
    app_name: &str,
    action: &str,
) -> DaemonDelegation {
    let cfg = config.get_config();
    if !cfg.admin.enabled.unwrap_or(true) {
        return DaemonDelegation::NoDaemon;
    }
    // Wildcard binds aren't connectable as-is.
    let admin_addr = cfg
        .admin
        .bind
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "127.0.0.1:");

    // Probe first: any HTTP response (even 401) proves a daemon is listening;
    // only a connect failure means there is none. The action request itself
    // gets a long timeout (deploy blocks on health checks and drain_delay),
    // and by then a transport error must not trigger the standalone fallback.
    let Ok(probe) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return DaemonDelegation::NoDaemon;
    };
    if probe
        .get(format!("http://{}/api/v1/apps", admin_addr))
        .send()
        .await
        .is_err()
    {
        return DaemonDelegation::NoDaemon;
    }

    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
    else {
        return DaemonDelegation::NoDaemon;
    };
    let mut req = client
        .post(format!(
            "http://{}/api/v1/apps/{}/{}",
            admin_addr, app_name, action
        ))
        // Marks this as a non-browser mutation for the admin CSRF gate.
        .header("X-Requested-With", "soli-cli");
    if let Some(ref key) = cfg.admin.api_key {
        req = req.header("X-Api-Key", key);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return DaemonDelegation::Refused(anyhow::anyhow!(
                "daemon detected on {} but the {} request failed: {}",
                admin_addr,
                action,
                e
            ))
        }
    };

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let json: Option<serde_json::Value> = serde_json::from_str(&body).ok();

    if status.is_success() {
        let past_tense = match action {
            "deploy" => "deployed",
            "restart" => "restarted",
            "stop" => "stopped",
            _ => action,
        };
        let slot = json
            .as_ref()
            .and_then(|v| v["data"]["slot"].as_str())
            .map(|s| format!(" (slot {})", s))
            .unwrap_or_default();
        return DaemonDelegation::Done(format!(
            "{} {} successfully via daemon{}",
            app_name, past_tense, slot
        ));
    }

    let detail = json
        .as_ref()
        .and_then(|v| v["error"].as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("HTTP {}", status));
    let hint = if status == reqwest::StatusCode::UNAUTHORIZED {
        "\nThe daemon's admin API requires authentication; set [admin].api_key \
         in the config so the CLI can authenticate."
    } else {
        ""
    };
    DaemonDelegation::Refused(anyhow::anyhow!(
        "daemon on {} rejected {} for {}: {}{}",
        admin_addr,
        action,
        app_name,
        detail,
        hint
    ))
}

async fn run_server(
    config_path: &str,
    daemon_mode: bool,
    dev_mode: bool,
    watch: bool,
    sites_dir: &str,
) -> Result<()> {
    setup_logging(daemon_mode)?;

    if daemon_mode {
        eprintln!("Started in daemon mode. PID: {}", std::process::id());
    }

    if dev_mode {
        tracing::info!("Dev mode enabled: apps will be started with --dev flag");
    }

    // Install default crypto provider for rustls 0.23
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut config_manager = ConfigManager::new(config_path)?;
    if watch || dev_mode {
        config_manager.start_watcher()?;
    }

    let shutdown = ShutdownCoordinator::new();
    let shutdown_for_signal = shutdown.clone();
    let config_ref = Arc::new(config_manager);
    let metrics = new_metrics();
    let challenge_store = new_challenge_store();

    // Create circuit breaker from config
    let cb_config =
        CircuitBreakerConfig::from_toml(config_ref.get_config().circuit_breaker.as_ref());
    let circuit_breaker = Arc::new(CircuitBreaker::new(cb_config));
    // Pre-register known backends so the first request under load does not
    // contend on the targets write lock.
    {
        let cfg = config_ref.get_config();
        let urls: Vec<String> = cfg
            .rules
            .iter()
            .flat_map(|r| r.targets.iter().map(|t| t.url.as_str().to_owned()))
            .collect();
        circuit_breaker.prewarm(urls);
    }

    // Initialize Lua scripting engine if feature is enabled and config says so
    #[cfg(feature = "scripting")]
    let lua_engine: Option<soli_proxy::LuaEngine> = {
        let cfg = config_ref.get_config();
        if cfg.scripting.enabled {
            let scripts_dir = std::path::PathBuf::from(
                cfg.scripting
                    .scripts_dir
                    .as_deref()
                    .unwrap_or("./scripts/lua"),
            );
            let hook_timeout =
                std::time::Duration::from_millis(cfg.scripting.hook_timeout_ms.unwrap_or(10));
            let num_states = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);

            // Collect unique route script names from all rules
            let mut route_script_names: Vec<String> = cfg
                .rules
                .iter()
                .flat_map(|r| r.scripts.iter().cloned())
                .collect();
            route_script_names.sort();
            route_script_names.dedup();

            let has_named_scripts =
                !cfg.global_scripts.is_empty() || !route_script_names.is_empty();

            let result = if has_named_scripts {
                tracing::info!(
                    "Lua scripting: {} global scripts, {} unique route scripts",
                    cfg.global_scripts.len(),
                    route_script_names.len()
                );
                soli_proxy::LuaEngine::with_route_scripts(
                    &scripts_dir,
                    num_states,
                    hook_timeout,
                    &cfg.global_scripts,
                    &route_script_names,
                    &cfg.scripting.exposed_env,
                )
            } else {
                soli_proxy::LuaEngine::new(
                    &scripts_dir,
                    num_states,
                    hook_timeout,
                    &cfg.scripting.exposed_env,
                )
            };

            match result {
                Ok(engine) => {
                    tracing::info!("Lua scripting engine initialized ({} states)", num_states);
                    Some(engine)
                }
                Err(e) => {
                    tracing::error!("Failed to initialize Lua scripting engine: {}", e);
                    None
                }
            }
        } else {
            tracing::info!("Lua scripting disabled");
            None
        }
    };
    #[cfg(not(feature = "scripting"))]
    let lua_engine = ();

    let cfg = config_ref.get_config();

    let mut tls_manager = TlsManager::new(&cfg.tls)?;

    // Always load self-signed fallback
    if let Err(e) = tls_manager.load_self_signed_fallback() {
        tracing::warn!("Failed to load self-signed fallback: {}", e);
    }

    let is_letsencrypt = cfg.tls.mode == "letsencrypt";
    let domains = cfg.acme_domains();

    if is_letsencrypt {
        // Pre-warm the resolver from the proxy.conf domain list so any
        // already-issued ACME certs are ready before the first handshake.
        if let Err(e) = tls_manager.load_cached_certs(&domains) {
            tracing::warn!("Failed to load cached ACME certs: {}", e);
        }
    }
    // Always scan cache_dir for per-domain and wildcard certs the operator
    // dropped in manually (mkcert in dev, externally-issued in prod). This
    // is what makes `_wildcard.<parent>.cert.pem` files actually load — the
    // letsencrypt-only gating used to silently swallow them in `auto` mode.
    if let Err(e) = tls_manager.load_all_cached_certs() {
        tracing::warn!("Failed to load all cached certs: {}", e);
    }

    // Build the TLS ServerConfig with the cert resolver
    tls_manager.build()?;

    // Initialize app manager for automatic app discovery and routing
    let port_manager = Arc::new(PortManager::new("./run").unwrap());
    let _ = port_manager.load().await;

    let app_manager: Option<Arc<AppManager>> = match AppManager::new(
        sites_dir,
        port_manager.clone(),
        config_ref.clone(),
        dev_mode,
    ) {
        Ok(mut m) => {
            tracing::info!("App manager initialized for {}", sites_dir);
            m.set_circuit_breaker(circuit_breaker.clone());
            m.spawn_health_check();
            m.spawn_process_exit_monitor();
            m.spawn_restart_trigger_watcher();
            Some(Arc::new(m))
        }
        Err(e) => {
            tracing::error!("Failed to initialize app manager: {}", e);
            None
        }
    };

    let admin_metrics = metrics.clone();
    let server_app_manager = app_manager.clone();

    // Build the per-IP rate limiter once so the proxy and admin API share
    // a single token bucket — the configured RPS budget is global, not
    // per-listener.
    let rate_limiter = soli_proxy::build_rate_limiter(&config_ref);
    let admin_rate_limiter = rate_limiter.clone();

    let server = match tls_manager.server_config() {
        Some(config) => {
            let https_addr: SocketAddr = format!("0.0.0.0:{}", cfg.server.https_port).parse()?;
            let tls_acceptor = TlsAcceptor::from(config.clone());
            tracing::info!("HTTPS enabled on port {}", cfg.server.https_port);
            ProxyServer::with_https(
                config_ref.clone(),
                shutdown,
                tls_acceptor,
                https_addr,
                metrics,
                challenge_store.clone(),
                lua_engine,
                circuit_breaker.clone(),
                server_app_manager,
                rate_limiter,
            )?
        }
        None => {
            tracing::warn!("TLS not available. HTTPS disabled.");
            ProxyServer::new(
                config_ref.clone(),
                shutdown,
                metrics,
                challenge_store.clone(),
                lua_engine,
                circuit_breaker.clone(),
                server_app_manager,
                rate_limiter,
            )?
        }
    };

    // Spawn ACME certificate issuance if mode is letsencrypt
    if is_letsencrypt {
        if let Some(le_config) = &cfg.letsencrypt {
            let le_config = le_config.clone();
            let cache_dir = tls_manager.cache_dir().clone();
            let resolver = tls_manager.cert_resolver();
            let cs = challenge_store.clone();
            let acme_domains = domains.clone();
            let config_ref_clone = config_ref.clone();
            let app_manager_for_acme = app_manager.clone();

            tokio::spawn(async move {
                match acme::get_or_create_account(&le_config, &cache_dir).await {
                    Ok(account) => {
                        let account = Arc::new(account);

                        // Issue certs for domains that need them
                        for domain in &acme_domains {
                            if !acme::cert_expires_soon(&cache_dir, domain) {
                                tracing::info!(
                                    "Certificate for {} is valid, skipping issuance",
                                    domain
                                );
                                continue;
                            }

                            tracing::info!("Issuing certificate for {}...", domain);
                            match acme::issue_certificate(
                                &account,
                                std::slice::from_ref(domain),
                                &cs,
                            )
                            .await
                            {
                                Ok((cert_pem, key_pem)) => {
                                    if let Err(e) = acme::save_certificate(
                                        &cache_dir, domain, &cert_pem, &key_pem,
                                    ) {
                                        tracing::error!(
                                            "Failed to save cert for {}: {}",
                                            domain,
                                            e
                                        );
                                        continue;
                                    }
                                    match acme::certified_key_from_pem(
                                        cert_pem.as_bytes(),
                                        key_pem.as_bytes(),
                                    ) {
                                        Ok(ck) => {
                                            resolver.set_cert(domain, Arc::new(ck));
                                            tracing::info!("Certificate for {} installed", domain);
                                        }
                                        Err(e) => tracing::error!(
                                            "Failed to parse cert for {}: {}",
                                            domain,
                                            e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to issue cert for {}: {}", domain, e)
                                }
                            }
                        }

                        // Create AcmeService and set on AppManager for dynamic cert issuance
                        let acme_service = Arc::new(soli_proxy::AcmeService::new(
                            account.clone(),
                            cs.clone(),
                            resolver.clone(),
                            cache_dir.clone(),
                        ));

                        if let Some(ref manager) = app_manager_for_acme {
                            manager.set_acme_service(acme_service).await;
                            // Re-run discover to issue certs for already-discovered domains
                            if let Err(e) = manager.discover_apps().await {
                                tracing::error!("Failed to re-sync apps after ACME init: {}", e);
                            }
                        }

                        // Start renewal loop with dynamic domain list
                        acme::spawn_renewal_task(
                            account,
                            config_ref_clone,
                            cache_dir,
                            cs,
                            resolver,
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create ACME account: {}. Continuing with self-signed certs.",
                            e
                        );
                    }
                }
            });
        } else {
            tracing::warn!("TLS mode is 'letsencrypt' but [letsencrypt] config section is missing");
        }
    }

    // Discover apps and clean stale routes BEFORE accepting connections.
    // App deploys are spawned in the background by discover_apps(), so this
    // only blocks until discovery + route cleanup finishes (fast).
    if let Some(ref manager) = app_manager {
        if let Err(e) = manager.discover_apps().await {
            tracing::error!("Failed to discover apps: {}", e);
        }

        // In dev mode, regenerate the self-signed fallback cert to include .test domains
        if dev_mode {
            let app_domains = manager.get_running_app_domains().await;
            let test_domains: Vec<String> = app_domains
                .keys()
                .filter(|d| d.ends_with(".test"))
                .cloned()
                .collect();
            if !test_domains.is_empty() {
                tracing::info!(
                    "Regenerating fallback cert with .test domains: {:?}",
                    test_domains
                );
                if let Err(e) = tls_manager.regenerate_fallback_with_sans(&test_domains) {
                    tracing::error!("Failed to regenerate fallback cert: {}", e);
                }
                // Rebuild TLS server config with new cert
                if let Err(e) = tls_manager.build() {
                    tracing::error!("Failed to rebuild TLS config: {}", e);
                }
            }
        }

        let manager_clone = manager.clone();
        let watch_enabled = watch || dev_mode;
        if watch_enabled {
            tokio::spawn(async move {
                if let Err(e) = manager_clone.start_watcher().await {
                    tracing::error!("Failed to start app watcher: {}", e);
                }
            });
        }

        if dev_mode {
            let mut tls_mgr = tls_manager.clone();
            let mgr_for_events = manager.clone();
            tokio::spawn(async move {
                let mut rx = mgr_for_events.subscribe();
                loop {
                    if let Ok(event) = rx.recv().await {
                        if matches!(event, AppEvent::Deployed { .. }) {
                            let domains = mgr_for_events.get_running_app_domains().await;
                            let test_domains: Vec<String> = domains
                                .keys()
                                .filter(|d| d.ends_with(".test"))
                                .cloned()
                                .collect();
                            if !test_domains.is_empty() {
                                tracing::info!(
                                    "Dev mode: regenerating fallback cert with .test domains: {:?}",
                                    test_domains
                                );
                                if let Err(e) = tls_mgr.regenerate_fallback_with_sans(&test_domains)
                                {
                                    tracing::error!("Failed to regenerate fallback cert: {}", e);
                                }
                                if let Err(e) = tls_mgr.build() {
                                    tracing::error!("Failed to rebuild TLS config: {}", e);
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // Spawn admin API server if enabled
    if cfg.admin.enabled.unwrap_or(true) {
        let admin_state = Arc::new(AdminState {
            config_manager: config_ref.clone(),
            metrics: admin_metrics,
            start_time: Instant::now(),
            circuit_breaker: circuit_breaker.clone(),
            app_manager: app_manager.clone(),
            rate_limiter: admin_rate_limiter,
            tls_manager: Some(tls_manager.clone()),
            challenge_store: Some(challenge_store.clone()),
        });
        tokio::spawn(async move {
            if let Err(e) = soli_proxy::run_admin_server(admin_state).await {
                tracing::error!("Admin server error: {}", e);
            }
        });
    }

    let app_manager_for_signal = app_manager;

    tokio::spawn(async move {
        let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1()).unwrap();
        loop {
            sigusr1.recv().await;
            tracing::info!("Received SIGUSR1, reloading config...");
            if let Err(e) = config_ref.reload().await {
                tracing::error!("Failed to reload config: {}", e);
            }
        }
    });

    let daemon_clone = daemon_mode;
    tokio::spawn(async move {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }
        tracing::info!("Received shutdown signal, draining connections...");

        // Tell the HTTP/HTTPS servers to stop accepting new connections and
        // send GOAWAY / Connection: close on the in-flight ones. Without this,
        // browsers keep the dead HTTP/2 socket cached for ~30s before noticing.
        shutdown_for_signal.initiate();

        // Give the in-flight connections a moment to flush GOAWAY frames and
        // any in-progress response bodies.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        tracing::info!("Stopping all managed apps...");
        if let Some(manager) = app_manager_for_signal {
            manager.stop_all().await;
        }
        if daemon_clone {
            cleanup_pid();
        }
        std::process::exit(0);
    });

    tracing::info!("Proxy server starting on {}", cfg.server.bind);
    server.run().await?;

    if daemon_mode {
        cleanup_pid();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha256_file_accepts_bare_digest() {
        let d = "abcd1234".repeat(8);
        assert_eq!(parse_sha256_file(&d).unwrap(), d);
    }

    #[test]
    fn parse_sha256_file_accepts_shasum_format() {
        let d = "abcd1234".repeat(8);
        let body = format!("{}  soli-proxy-linux-amd64.tar.gz\n", d);
        assert_eq!(parse_sha256_file(&body).unwrap(), d);
    }

    #[test]
    fn parse_sha256_file_normalizes_to_lowercase() {
        let upper = "ABCD1234".repeat(8);
        let lower = "abcd1234".repeat(8);
        assert_eq!(parse_sha256_file(&upper).unwrap(), lower);
    }

    #[test]
    fn parse_sha256_file_rejects_short_digest() {
        assert!(parse_sha256_file("abcd1234").is_err());
    }

    #[test]
    fn parse_sha256_file_rejects_non_hex() {
        let bad = format!("{}xyzZ", "a".repeat(60));
        assert!(parse_sha256_file(&bad).is_err());
    }

    #[test]
    fn parse_sha256_file_rejects_empty() {
        assert!(parse_sha256_file("").is_err());
        assert!(parse_sha256_file("   \n").is_err());
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let dir = std::env::temp_dir();
        let path = dir.join(format!("soli_proxy_sha256_test_{}.bin", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let hex = sha256_hex(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
