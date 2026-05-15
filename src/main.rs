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

    if let Some(Commands::Update { reinstall }) = cli.command {
        return run_update(reinstall);
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

fn run_update(reinstall: bool) -> Result<()> {
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

    let tmp_dir = Command::new("mktemp").arg("-d").output()?;
    let tmp_dir = String::from_utf8_lossy(&tmp_dir.stdout).trim().to_string();

    println!("Downloading {}...", download_url);
    let dl = Command::new("curl")
        .args([
            "-fsSL",
            "-o",
            &format!("{}/{}", tmp_dir, tarball),
            &download_url,
        ])
        .output()?;
    if !dl.status.success() {
        let _ = fs::remove_dir_all(&tmp_dir);
        anyhow::bail!(
            "Failed to download {}. Does this release have prebuilt binaries?",
            download_url
        );
    }

    println!("Extracting...");
    let tar = Command::new("tar")
        .args(["xzf", &format!("{}/{}", tmp_dir, tarball), "-C", &tmp_dir])
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
            // Retry with sudo if permission denied
            println!("Retrying with sudo...");
            let result = Command::new("sudo")
                .args(["install", "-m", "755", &new_binary, &*install_path_str])
                .output()?;
            if !result.status.success() {
                let _ = fs::remove_dir_all(&tmp_dir);
                anyhow::bail!("Failed to install binary to {}", install_path.display());
            }
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
    if action == "logs" {
        return run_app_logs(app_name);
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move { run_app_api_command(config_path, app_name, action).await })
}

fn run_app_logs(app_name: &str) -> Result<()> {
    let read_slot = |slot: &str| -> String {
        let log_path = std::path::PathBuf::from(format!("run/logs/{}/{}.log", app_name, slot));
        if log_path.exists() {
            fs::read_to_string(&log_path).unwrap_or_default()
        } else {
            String::new()
        }
    };
    println!("=== {} (blue) ===", app_name);
    println!("{}", read_slot("blue"));
    println!("=== {} (green) ===", app_name);
    println!("{}", read_slot("green"));
    Ok(())
}

async fn run_app_api_command(config_path: &str, app_name: &str, action: &str) -> Result<()> {
    let endpoint = match action {
        "deploy" | "restart" | "stop" => action,
        _ => anyhow::bail!("Unknown action: {}", action),
    };

    let config_manager = ConfigManager::new(config_path)?;
    let cfg = config_manager.get_config();
    if cfg.admin.enabled != Some(true) {
        anyhow::bail!(
            "Admin API is not enabled in {}. The CLI '{}' command requires \
             [admin] enabled = true so it can talk to the running proxy daemon.",
            config_path,
            action
        );
    }

    let admin_addr = cfg
        .admin
        .bind
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "127.0.0.1:");
    let url = format!(
        "http://{}/api/v1/apps/{}/{}",
        admin_addr, app_name, endpoint
    );

    send_app_action_request(&url, cfg.admin.api_key.as_deref(), app_name, action).await
}

async fn send_app_action_request(
    url: &str,
    api_key: Option<&str>,
    app_name: &str,
    action: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let mut req = client.post(url);
    if let Some(key) = api_key {
        req = req.header("X-Api-Key", key);
    }
    let resp = req.send().await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to reach proxy admin API at {}: {}. Is the daemon running?",
            url,
            e
        )
    })?;
    let status = resp.status();
    if status.is_success() {
        println!("{} {} succeeded", app_name, action);
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Admin API returned HTTP {} for {} {}: {}",
            status.as_u16(),
            action,
            app_name,
            body
        )
    }
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
                )
            } else {
                soli_proxy::LuaEngine::new(&scripts_dir, num_states, hook_timeout)
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
        // Load any cached ACME certs from disk
        if let Err(e) = tls_manager.load_cached_certs(&domains) {
            tracing::warn!("Failed to load cached ACME certs: {}", e);
        }
        // Also load all cached certs to catch app domains not in proxy.conf
        if let Err(e) = tls_manager.load_all_cached_certs() {
            tracing::warn!("Failed to load all cached certs: {}", e);
        }
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
            Some(Arc::new(m))
        }
        Err(e) => {
            tracing::error!("Failed to initialize app manager: {}", e);
            None
        }
    };

    let admin_metrics = metrics.clone();
    let server_app_manager = app_manager.clone();

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

    tracing::info!("Proxy server starting on port 8008");
    server.run().await?;

    if daemon_mode {
        cleanup_pid();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_mock_admin(
        response: &'static str,
    ) -> (u16, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut total = String::new();
            // Read until we see end of headers
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total.push_str(&String::from_utf8_lossy(&buf[..n]));
                if total.contains("\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
            let _ = tx.send(total);
        });

        (port, rx)
    }

    #[tokio::test]
    async fn send_app_action_request_sends_correct_url_and_api_key() {
        let (port, captured) =
            spawn_mock_admin("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let url = format!("http://127.0.0.1:{}/api/v1/apps/myapp/deploy", port);

        let result = send_app_action_request(&url, Some("secret-key-123"), "myapp", "deploy").await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let request = captured.await.unwrap();
        let first_line = request.lines().next().unwrap_or("");
        assert!(
            first_line.starts_with("POST /api/v1/apps/myapp/deploy "),
            "unexpected request line: {}",
            first_line
        );
        assert!(
            request
                .lines()
                .any(|l| l.eq_ignore_ascii_case("X-Api-Key: secret-key-123")),
            "X-Api-Key header missing in request: {}",
            request
        );
    }

    #[tokio::test]
    async fn send_app_action_request_omits_api_key_when_unset() {
        let (port, captured) =
            spawn_mock_admin("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let url = format!("http://127.0.0.1:{}/api/v1/apps/myapp/restart", port);

        let result = send_app_action_request(&url, None, "myapp", "restart").await;
        assert!(result.is_ok());

        let request = captured.await.unwrap();
        assert!(
            !request
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("x-api-key:")),
            "X-Api-Key header should not be sent when api_key is None: {}",
            request
        );
    }

    #[tokio::test]
    async fn send_app_action_request_surfaces_http_error() {
        let (port, _captured) =
            spawn_mock_admin("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 10\r\n\r\nbad-deploy")
                .await;
        let url = format!("http://127.0.0.1:{}/api/v1/apps/myapp/deploy", port);

        let err = send_app_action_request(&url, None, "myapp", "deploy")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("502") && msg.contains("bad-deploy"),
            "expected error to mention status and body, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn send_app_action_request_errors_on_unreachable_daemon() {
        // Bind a port, then drop the listener so the port is free again.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let url = format!("http://127.0.0.1:{}/api/v1/apps/myapp/deploy", port);
        let err = send_app_action_request(&url, None, "myapp", "deploy")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Failed to reach proxy admin API"),
            "expected reachability error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn run_app_api_command_errors_when_admin_disabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        let proxy_conf = temp_dir.path().join("proxy.conf");
        let toml_conf = temp_dir.path().join("config.toml");
        std::fs::write(&proxy_conf, "default -> http://localhost:3000\n").unwrap();
        std::fs::write(
            &toml_conf,
            "[admin]\nenabled = false\nbind = \"127.0.0.1:9090\"\n",
        )
        .unwrap();

        let err = run_app_api_command(proxy_conf.to_str().unwrap(), "myapp", "deploy")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Admin API is not enabled"),
            "got: {}",
            err
        );
    }
}
