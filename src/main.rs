use anyhow::Result;
use soli_proxy::acme;
use soli_proxy::new_challenge_store;
use soli_proxy::new_metrics;
use soli_proxy::AdminState;
use soli_proxy::ConfigManager;
use soli_proxy::ProxyServer;
use soli_proxy::ShutdownCoordinator;
use soli_proxy::TlsManager;
use std::fs;
use std::net::SocketAddr;
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
    std::env::var("SOLI_PID_DIR").unwrap_or_else(|_| "/run".to_string())
}

fn get_log_dir() -> String {
    std::env::var("SOLI_LOG_DIR").unwrap_or_else(|_| "/var/log".to_string())
}

fn write_pid_file() -> Result<String> {
    let pid_dir = get_pid_dir();
    let pid_path = format!("{}/soli-proxy.pid", pid_dir);
    fs::create_dir_all(&pid_dir).ok();
    fs::write(&pid_path, std::process::id().to_string())?;
    Ok(pid_path)
}

fn setup_logging(daemon: bool) -> Result<()> {
    if daemon {
        let log_dir = get_log_dir();
        let log_path = format!("{}/soli-proxy.log", log_dir);
        fs::create_dir_all(&log_dir).ok();

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

fn cleanup_pid() {
    let pid_path = format!("{}/soli-proxy.pid", get_pid_dir());
    let _ = fs::remove_file(&pid_path);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut config_path = "./proxy.conf";
    let mut daemon_mode = false;

    for arg in &args {
        if arg == "-d" || arg == "--daemon" {
            daemon_mode = true;
        } else if !arg.starts_with('-') && arg != &args[0] {
            config_path = arg.as_str();
        }
    }

    if daemon_mode {
        daemonize()?;
        let _ = write_pid_file()?;
    }

    setup_logging(daemon_mode)?;

    if daemon_mode {
        eprintln!("Started in daemon mode. PID: {}", std::process::id());
    }

    // Install default crypto provider for rustls 0.23
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config_manager = ConfigManager::new(config_path)?;
    config_manager.start_watcher()?;

    let shutdown = ShutdownCoordinator::new();
    let config_ref = Arc::new(config_manager);
    let metrics = new_metrics();
    let challenge_store = new_challenge_store();

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
    }

    // Build the TLS ServerConfig with the cert resolver
    tls_manager.build()?;

    let admin_metrics = metrics.clone();

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

            tokio::spawn(async move {
                match acme::get_or_create_account(&le_config, &cache_dir).await {
                    Ok(account) => {
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

                        // Start renewal loop
                        acme::spawn_renewal_task(account, acme_domains, cache_dir, cs, resolver);
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

    // Spawn admin API server if enabled
    if cfg.admin.enabled {
        let admin_state = Arc::new(AdminState {
            config_manager: config_ref.clone(),
            metrics: admin_metrics,
            start_time: Instant::now(),
        });
        tokio::spawn(async move {
            if let Err(e) = soli_proxy::run_admin_server(admin_state).await {
                tracing::error!("Admin server error: {}", e);
            }
        });
    }

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
        sigterm.recv().await;
        tracing::info!("Received SIGTERM, shutting down...");
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
