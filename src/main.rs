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

fn get_pid_path() -> String {
    format!("{}/proxy.pid", get_pid_dir())
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

/// Stop the daemon `proxy.pid` names, waiting for its drain: `-d` replaces a
/// running daemon this way. Its apps keep running (unless `[apps]
/// stop_on_shutdown` says otherwise) and the new daemon adopts them.
fn kill_existing_daemon(config_path: &str) -> Result<()> {
    let pid_path = get_pid_path();
    if let Ok(content) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = content.trim().parse::<i32>() {
            if pid > 0 && is_process_running(pid) {
                println!("Stopping existing daemon (PID: {})...", pid);
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }

                // The old daemon drains for up to its grace period, then
                // exits; a little more covers the rest of its shutdown.
                let max_wait = soli_proxy::config::read_shutdown_grace_period(config_path)
                    + std::time::Duration::from_secs(5);
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

#[derive(Parser, Debug)]
#[command(name = "soli-proxy")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Reverse proxy with automatic HTTPS, Lua scripting and blue-green app deploys")]
struct Cli {
    /// Routing rules file. config.toml (and an optional .env) are read from
    /// the same directory.
    #[arg(short, long, default_value = "./proxy.conf")]
    conf: String,

    /// Fork into the background, writing proxy.pid and proxy.log.
    #[arg(short, long)]
    daemon: bool,

    /// Development mode: .test aliases, one worker, apps started with --dev.
    #[arg(long)]
    dev: bool,

    /// Reload proxy.conf and rescan sites when they change. `--watch false`
    /// turns it off (a bare `bool` flag could only ever be set to true).
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    watch: bool,

    /// Directory holding one sub-directory per app, named after its domain.
    #[arg(long, default_value = "./sites")]
    sites_dir: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Interactive terminal UI.
    Tui {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        #[arg(long, default_value = "./sites")]
        sites_dir: String,

        #[arg(long)]
        dev: bool,
    },
    /// Self-update from the latest GitHub release.
    Update {
        #[arg(long)]
        reinstall: bool,

        /// Skip SHA-256 verification of the downloaded release artifact.
        /// Only use for releases predating checksum emission. The standard
        /// path requires a `.sha256` sibling file in the GitHub release.
        #[arg(long)]
        allow_unverified: bool,
    },
    /// Blue-green deploy an app: start the other slot, then switch to it.
    Deploy {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    /// Restart an app's active slot.
    Restart {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    /// Stop an app, or with --all every app. The proxy keeps running.
    ///
    /// Apps outlive a proxy stop or restart (`[apps] stop_on_shutdown`), and
    /// the next proxy adopts them: `stop --all` is how to take them all down,
    /// e.g. before `systemctl stop soli-proxy` on a host being retired.
    Stop {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        /// Stop every app (both slots) and every process the proxy recorded
        /// spawning, through the running daemon — or directly when none runs.
        #[arg(long, visible_alias = "apps", conflicts_with = "app_name")]
        all: bool,

        /// Sites directory, for --all when no daemon is running.
        #[arg(long, default_value = "./sites")]
        sites_dir: String,

        #[arg(required_unless_present = "all")]
        app_name: Option<String>,
    },
    /// Validate config.toml, proxy.conf and every site's app.infos without
    /// starting anything or binding a port. Prints each problem as
    /// `file:line: error|warning: message`; exits 1 if there is an error.
    Check {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        #[arg(long, default_value = "./sites")]
        sites_dir: String,

        /// Check as `--dev` would load: the [development] sections of
        /// app.infos, `soli serve --dev`.
        #[arg(long)]
        dev: bool,
    },
    /// Close an app (or the whole proxy) for maintenance, reopen it, or list
    /// what is closed. Goes through the running daemon's admin API.
    Maintenance {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        #[command(subcommand)]
        action: MaintenanceAction,
    },
    /// Put an app to sleep now (stopped; its next request starts it again).
    /// Goes through the running daemon's admin API.
    Sleep {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    /// Who `[bots]` banned and what it refused, or lift a ban. Goes through
    /// the running daemon's admin API.
    Bots {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        #[command(subcommand)]
        action: Option<BotsAction>,
    },
    /// Print an app's deployment logs (both slots).
    Logs {
        #[arg(short, long, default_value = "./proxy.conf")]
        conf: String,

        app_name: String,
    },
    /// Print a bcrypt hash for `@auth:user:<hash>`, `[auth.users]` in
    /// app.infos, or ADMIN_PASSWORD_HASH. The password is prompted for (twice,
    /// without echo), or read from the first line of stdin when it is not a
    /// terminal; it is never taken from the command line.
    HashPassword {
        /// bcrypt cost factor. Each step doubles the time to verify; 12 takes
        /// ~0.25 s, and the proxy caches verified credentials.
        #[arg(long, default_value_t = 12, value_parser = clap::value_parser!(u32).range(4..=13))]
        cost: u32,
    },
}

#[derive(clap::Subcommand, Debug)]
enum MaintenanceAction {
    /// Close an app (its name) or the whole proxy (`all`): visitors get the
    /// maintenance page, `[maintenance] allow_ips` and `allow_paths` still
    /// go through.
    On {
        target: String,
        /// Reopen by itself after this long: `90s`, `30m`, `2h`, `1h30m`, `1d`.
        #[arg(long = "for", value_name = "DURATION", conflicts_with = "until")]
        for_: Option<String>,
        /// Reopen by itself at this time (RFC 3339, e.g. 2026-10-06T14:30:00Z).
        #[arg(long)]
        until: Option<String>,
        /// Shown on the page, e.g. "Mise à jour de la base de données".
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Reopen an app, or the whole proxy (`all`).
    Off { target: String },
    /// What is closed, since when and until when.
    Status,
}

#[derive(clap::Subcommand, Debug)]
enum BotsAction {
    /// The bans in force and the user agents refused (the default).
    Status,
    /// Lift the ban on a client.
    Unban { ip: String },
    /// Add a trap path: a client asking for it is banned. An exact path
    /// (/HNAP1), a prefix (/old-admin/*), a suffix (*.php) or a fragment
    /// found anywhere (*/.env*). Kept across restarts.
    Trap { pattern: String },
    /// Remove a trap path added with `trap` (or from the TUI).
    Untrap { pattern: String },
}

/// `soli-proxy -c prod.conf maintenance on all` must reach the proxy of
/// `prod.conf`: a subcommand's own `-c` / `--sites-dir` default to
/// `./proxy.conf` / `./sites`, so a path given before the subcommand would
/// otherwise be silently dropped. One given after it still wins.
fn inherit_global_paths(cli: &mut Cli) {
    const CONF: &str = "./proxy.conf";
    const SITES: &str = "./sites";
    let (top_conf, top_sites) = (cli.conf.clone(), cli.sites_dir.clone());
    let conf = |c: &mut String| {
        if c == CONF {
            c.clone_from(&top_conf);
        }
    };
    let sites = |s: &mut String| {
        if s == SITES {
            s.clone_from(&top_sites);
        }
    };
    match &mut cli.command {
        Some(Commands::Tui {
            conf: c,
            sites_dir: s,
            ..
        })
        | Some(Commands::Stop {
            conf: c,
            sites_dir: s,
            ..
        })
        | Some(Commands::Check {
            conf: c,
            sites_dir: s,
            ..
        }) => {
            conf(c);
            sites(s);
        }
        Some(Commands::Deploy { conf: c, .. })
        | Some(Commands::Restart { conf: c, .. })
        | Some(Commands::Maintenance { conf: c, .. })
        | Some(Commands::Bots { conf: c, .. })
        | Some(Commands::Sleep { conf: c, .. })
        | Some(Commands::Logs { conf: c, .. }) => conf(c),
        _ => {}
    }
}

fn main() -> Result<()> {
    // Before any thread exists: the sockets systemd passed (socket
    // activation) are claimed and hidden from everything spawned later.
    soli_proxy::systemd::take_listen_fds();
    let mut cli = Cli::parse();
    inherit_global_paths(&mut cli);

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

    if let Some(Commands::Stop {
        conf,
        all,
        sites_dir,
        app_name,
    }) = cli.command
    {
        if all {
            return run_stop_all(&conf, &sites_dir);
        }
        // clap guarantees a name without --all.
        return run_app_command(&conf, &app_name.unwrap_or_default(), "stop");
    }

    if let Some(Commands::Check {
        conf,
        sites_dir,
        dev,
    }) = cli.command
    {
        return run_check(&conf, &sites_dir, dev);
    }

    if let Some(Commands::Logs { conf, app_name }) = cli.command {
        return run_app_command(&conf, &app_name, "logs");
    }

    if let Some(Commands::HashPassword { cost }) = cli.command {
        return run_hash_password(cost);
    }

    if let Some(Commands::Maintenance { conf, action }) = cli.command {
        return run_maintenance(&conf, action);
    }

    if let Some(Commands::Sleep { conf, app_name }) = cli.command {
        let path = format!("/api/v1/apps/{app_name}/sleep");
        admin_call(
            &conf,
            "apps are put to sleep",
            reqwest::Method::POST,
            &path,
            None,
        )?;
        println!("{app_name} is asleep; its next request starts it");
        return Ok(());
    }

    if let Some(Commands::Bots { conf, action }) = cli.command {
        return run_bots(&conf, action.unwrap_or(BotsAction::Status));
    }

    if !std::path::Path::new(&cli.conf).exists() {
        eprintln!(
            "Error: config file '{}' not found in current directory",
            cli.conf
        );
        std::process::exit(1);
    }

    // Next to a proxy systemd runs, a second one on the same ports would
    // share them (SO_REUSEPORT) and fight it over the apps — and `-d` would
    // first stop it through proxy.pid. Refused, foreground or daemon alike.
    let ports = soli_proxy::config::read_listen_ports(&cli.conf);
    if let Some(instance) = soli_proxy::systemd::conflicting_instance(&ports) {
        eprintln!("Error: {}", instance.refusal());
        std::process::exit(1);
    }

    if cli.daemon {
        kill_existing_daemon(&cli.conf)?;
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
    let result = rt.block_on(async move {
        run_server(&cli.conf, cli.daemon, cli.dev, cli.watch, &cli.sites_dir).await
    });
    // Do not wait on whatever is still running (watchers, a health probe):
    // the drain is over and the apps are, deliberately, left as they are.
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    result
}

/// `soli-proxy check`: every problem on stdout, a summary, exit status 1 on
/// any error.
fn run_check(conf: &str, sites_dir: &str, dev: bool) -> Result<()> {
    // The loaders report some findings (unknown app.infos keys, clamped
    // timeouts) only as log warnings; show them, on stderr, without
    // timestamps.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .without_time()
        .try_init();

    let report = soli_proxy::check::check_installation(
        std::path::Path::new(conf),
        std::path::Path::new(sites_dir),
        dev,
    );
    for problem in &report.problems {
        println!("{}", problem);
    }
    let summary = format!(
        "{} error(s), {} warning(s); {} site(s) checked",
        report.errors(),
        report.warnings(),
        report.sites_checked
    );
    if report.has_errors() {
        eprintln!("check failed: {}", summary);
        std::process::exit(1);
    }
    println!("ok: {}", summary);
    Ok(())
}

/// `soli-proxy stop --all`.
fn run_stop_all(config_path: &str, sites_dir: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let config_ref = Arc::new(ConfigManager::new(config_path)?);
        match delegate_to_daemon(
            &config_ref,
            "/api/v1/apps/stop-all",
            "stop-all",
            "every app",
        )
        .await
        {
            DaemonDelegation::Done(_) => {
                println!("Every app stopped via daemon");
                return Ok(());
            }
            DaemonDelegation::Refused(err) => return Err(err),
            DaemonDelegation::NoDaemon => {}
        }

        // No daemon: what runs was left by one that has exited. Containers
        // are found by name from the sites, native processes by the spawn
        // registry — nothing else is signalled.
        let port_manager = Arc::new(PortManager::new("./run")?);
        let _ = port_manager.load().await;
        let app_manager = AppManager::new(sites_dir, port_manager, config_ref, false)?;
        if let Err(e) = app_manager.discover_apps_readonly().await {
            tracing::error!("Failed to discover apps: {}", e);
        }
        app_manager.stop_all().await;
        println!("Every app stopped");
        Ok(())
    })
}

/// `soli-proxy hash-password`: the hash alone on stdout, so it can be captured
/// (`HASH=$(soli-proxy hash-password)`); prompts and hints go to stderr.
fn run_hash_password(cost: u32) -> Result<()> {
    use std::io::IsTerminal;
    let password = if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("Password: ")?;
        let again = rpassword::prompt_password("Confirm:  ")?;
        if first != again {
            anyhow::bail!("passwords do not match");
        }
        first
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    println!("{}", hash_password_checked(&password, cost)?);
    eprintln!("Use it as `@auth:<user>:<hash>` in proxy.conf, `<user> = \"<hash>\"` under");
    eprintln!("[auth.users] in app.infos, or ADMIN_PASSWORD_HASH for the admin API.");
    Ok(())
}

fn hash_password_checked(password: &str, cost: u32) -> Result<String> {
    if password.is_empty() {
        anyhow::bail!("the password is empty");
    }
    Ok(soli_proxy::auth::hash_password(password, cost))
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

/// Whether `getcap`'s report of a file grants the port-binding capability.
///
/// Split out from the call so the parsing is testable without a binary that
/// has one. `getcap` prints nothing at all for a file with no capabilities,
/// and one line naming them when it has any; the format has changed spelling
/// between versions (`= cap_net_bind_service+ep` and
/// `cap_net_bind_service=ep`), so this asks only whether the name appears.
fn grants_bind_capability(getcap_output: &str) -> bool {
    getcap_output.contains("cap_net_bind_service")
}

/// Does the binary at `path` currently carry the capability?
///
/// A missing `getcap` — a container, a musl image — answers "no", which is
/// the safe way round: the worst it costs is advice nobody needed.
#[cfg(target_os = "linux")]
fn has_bind_capability(path: &std::path::Path) -> bool {
    Command::new("getcap")
        .arg(path)
        .output()
        .map(|o| grants_bind_capability(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(false)
}

/// Put `cap_net_bind_service` back on the freshly installed binary.
///
/// Capabilities live on the file and not on the path, so `install` — like
/// `cp`, `mv` across filesystems, or unpacking a release — drops them. The
/// proxy then comes back up unable to bind the only two ports it exists to
/// serve, and says so only at that point: after a restart, with the sites
/// already down. Re-applying it here is the difference between an upgrade
/// and an outage.
///
/// Three attempts, in order, and no escalation that the operator has not
/// already authorised:
///
///   1. `setcap` directly, which works when the update ran as root;
///   2. `sudo -n setcap`, which is non-interactive and succeeds only where
///      `deploy/soli-proxy-setcap.sudoers` has been installed — a grant for
///      this one command, argument and path, made deliberately in advance;
///   3. nothing, and the exact command to run printed instead.
///
/// It never prompts. A password prompt from inside an update is the sharp
/// edge this file already refuses to have.
#[cfg(target_os = "linux")]
fn restore_bind_capability(path: &std::path::Path) {
    let arg = "cap_net_bind_service=+ep";
    let ran = |program: &str, args: &[&str]| -> bool {
        Command::new(program)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    let shown = path.display();
    if ran("setcap", &[arg, &shown.to_string()]) {
        println!("Restored cap_net_bind_service on {shown}.");
        return;
    }
    if ran("sudo", &["-n", "setcap", arg, &shown.to_string()]) {
        println!("Restored cap_net_bind_service on {shown} (via the sudoers grant).");
        return;
    }
    println!();
    println!("This binary had cap_net_bind_service and the new one does not:");
    println!("installing a file drops the capabilities that were on it.");
    println!("Until it is back, the proxy cannot bind :80 or :443.");
    println!();
    println!("  sudo setcap {arg} {shown}");
    println!();
    println!("To stop this recurring, install the sudoers grant that lets the");
    println!("proxy do it for itself — deploy/soli-proxy-setcap.sudoers.");
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
        // Asked before the install, because afterwards there is nothing left
        // to ask: the file that carried the capability is gone. A binary that
        // never had one is left alone — this restores what was there, it does
        // not decide that a proxy ought to have it.
        #[cfg(target_os = "linux")]
        let had_capability = has_bind_capability(&install_path);

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

        #[cfg(target_os = "linux")]
        if had_capability {
            restore_bind_capability(&install_path);
        }

        print_upgrade_restart_hint();
    }

    Ok(())
}

/// What to do once the binary is replaced. `update` does not restart the
/// proxy itself — it cannot know how it was started — but a restart is now
/// safe to do at any time: the old process drains its in-flight requests
/// (`[server] shutdown_grace_period`) and exits without stopping a single
/// app, and the new one adopts every app still running.
fn print_upgrade_restart_hint() {
    println!();
    println!("The running proxy keeps the old version until it is restarted.");
    println!("Restarting drains in-flight requests and leaves every app running;");
    println!("the new proxy adopts them, so no app is stopped or cold-started:");
    println!();
    println!("  systemd:      sudo systemctl restart soli-proxy");
    println!(
        "  daemon (-d):  soli-proxy -d [same flags as before]   (replaces the running daemon)"
    );
    println!();
    println!("Check the configuration against the new version first:");
    println!("  soli-proxy check --conf <proxy.conf> --sites-dir <sites>");
}

fn run_maintenance(config_path: &str, action: MaintenanceAction) -> Result<()> {
    let (method, path, body) = match &action {
        MaintenanceAction::On {
            target,
            for_,
            until,
            message,
        } => {
            let mut toggle = serde_json::json!({ "enabled": true });
            if let Some(d) = for_ {
                toggle["for_secs"] =
                    serde_json::json!(soli_proxy::response::maintenance::parse_duration(d)?);
            }
            if let Some(u) = until {
                toggle["until"] = serde_json::json!(u);
            }
            if let Some(m) = message {
                toggle["message"] = serde_json::json!(m);
            }
            (reqwest::Method::PUT, maintenance_path(target), Some(toggle))
        }
        MaintenanceAction::Off { target } => (
            reqwest::Method::PUT,
            maintenance_path(target),
            Some(serde_json::json!({ "enabled": false })),
        ),
        MaintenanceAction::Status => (
            reqwest::Method::GET,
            "/api/v1/maintenance".to_string(),
            None,
        ),
    };

    let json = admin_call(
        config_path,
        "maintenance mode is switched",
        method,
        &path,
        body,
    )?;

    match action {
        MaintenanceAction::On { target, .. } => {
            let window = if target == "all" {
                &json["data"]["global"]
            } else {
                &json["data"]["apps"][&target]
            };
            let until = window["until"]
                .as_str()
                .map(|u| format!(" until {u}"))
                .unwrap_or_else(|| " until switched off".to_string());
            println!("{} closed for maintenance{until}", describe_target(&target));
        }
        MaintenanceAction::Off { target } => {
            println!("{} reopened", describe_target(&target));
        }
        MaintenanceAction::Status => print_maintenance_status(&json["data"]),
    }
    Ok(())
}

/// One call to the running daemon's admin API, at the address and with the
/// key of `config_path`'s `config.toml`. `what` starts the error when the
/// admin API is off ("maintenance mode is switched").
fn admin_call(
    config_path: &str,
    what: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let config = ConfigManager::new(config_path)?;
    let cfg = config.get_config();
    if !cfg.admin.enabled.unwrap_or(true) {
        anyhow::bail!("{what} through the admin API, and [admin] enabled = false");
    }
    let admin = cfg
        .admin
        .bind
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "127.0.0.1:");
    let api_key = cfg.admin.api_key.clone();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let mut req = client
            .request(method, format!("http://{admin}{path}"))
            .header("X-Requested-With", "soli-cli");
        if let Some(key) = &api_key {
            req = req.header("X-Api-Key", key);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.map_err(|e| {
            anyhow::anyhow!("no daemon answering on {admin} (is soli-proxy running?): {e}")
        })?;
        let status = resp.status();
        let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            let detail = json["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| format!("HTTP {status}"));
            let hint = if status == reqwest::StatusCode::UNAUTHORIZED {
                " (set [admin] api_key in config.toml)"
            } else {
                ""
            };
            anyhow::bail!("{detail}{hint}");
        }
        Ok::<_, anyhow::Error>(json)
    })
}

fn run_bots(config_path: &str, action: BotsAction) -> Result<()> {
    match action {
        BotsAction::Unban { ip } => {
            let path = format!("/api/v1/bots/bans/{ip}");
            admin_call(
                config_path,
                "bans are managed",
                reqwest::Method::DELETE,
                &path,
                None,
            )?;
            println!("{ip} unbanned");
        }
        BotsAction::Trap { pattern } => {
            let json = admin_call(
                config_path,
                "trap paths are managed",
                reqwest::Method::POST,
                "/api/v1/bots/traps",
                Some(serde_json::json!({ "pattern": pattern })),
            )?;
            let data = &json["data"];
            if data["added"].as_bool() == Some(true) {
                println!("{pattern} is a trap: a client asking for it is banned");
            } else {
                println!("{pattern} was a trap already");
            }
            if data["traps_on"].as_bool() == Some(false) {
                println!(
                    "note: [bots] traps = false in config.toml; traps apply only on sites that \
                     turn them on"
                );
            }
        }
        BotsAction::Untrap { pattern } => {
            admin_call(
                config_path,
                "trap paths are managed",
                reqwest::Method::DELETE,
                "/api/v1/bots/traps",
                Some(serde_json::json!({ "pattern": pattern })),
            )?;
            println!("{pattern} is no longer a trap");
        }
        BotsAction::Status => {
            let json = admin_call(
                config_path,
                "bans are listed",
                reqwest::Method::GET,
                "/api/v1/bots",
                None,
            )?;
            print_bots_status(&json["data"]);
        }
    }
    Ok(())
}

fn print_bots_status(data: &serde_json::Value) {
    let policy = &data["policy"];
    let agents: Vec<&str> = policy["block_agents"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut on = Vec::new();
    if !agents.is_empty() {
        on.push(format!("refusing {}", agents.join(", ")));
    }
    if policy["traps"].as_bool() == Some(true) {
        on.push("traps".to_string());
    }
    if let Some(n) = policy["max_404_per_minute"].as_u64().filter(|n| *n > 0) {
        on.push(format!("ban past {n} 404s a minute"));
    }
    if policy["enabled"].as_bool() == Some(false) {
        println!("[bots] is off (enabled = false); sites with enabled = true still use it.");
    } else if on.is_empty() {
        println!("[bots] is off (apps may still set their own).");
    } else {
        println!(
            "[bots]: {} · bans last {}s",
            on.join(" · "),
            policy["ban_secs"].as_u64().unwrap_or(0)
        );
    }
    let bans = data["bans"].as_array().cloned().unwrap_or_default();
    println!(
        "\n{} banned now, {} since the proxy started:",
        bans.len(),
        data["banned_total"].as_u64().unwrap_or(0)
    );
    for b in &bans {
        println!(
            "  {:<24} until {}  {}",
            b["ip"].as_str().unwrap_or(""),
            b["until"].as_str().unwrap_or(""),
            b["reason"].as_str().unwrap_or("")
        );
    }
    if let Some(traps) = data["custom_traps"].as_array().filter(|t| !t.is_empty()) {
        println!("\nTrap paths added at run time (soli-proxy bots untrap <path> removes one):");
        for t in traps.iter().filter_map(|t| t.as_str()) {
            println!("  {t}");
        }
    }
    if let Some(blocked) = data["blocked"].as_object().filter(|b| !b.is_empty()) {
        println!("\nRefused for their user agent:");
        let mut rows: Vec<_> = blocked.iter().collect();
        rows.sort_by_key(|(_, n)| std::cmp::Reverse(n.as_u64().unwrap_or(0)));
        for (name, n) in rows {
            println!("  {name:<24} {}", n.as_u64().unwrap_or(0));
        }
    }
}

fn maintenance_path(target: &str) -> String {
    if target == "all" {
        "/api/v1/maintenance".to_string()
    } else {
        format!("/api/v1/apps/{target}/maintenance")
    }
}

fn describe_target(target: &str) -> String {
    if target == "all" {
        "the whole proxy".to_string()
    } else {
        target.to_string()
    }
}

fn print_maintenance_status(data: &serde_json::Value) {
    let line = |name: &str, w: &serde_json::Value| {
        let mut parts = Vec::new();
        if let Some(s) = w["since"].as_str() {
            parts.push(format!("since {s}"));
        }
        parts.push(match w["until"].as_str() {
            Some(u) => format!("until {u}"),
            None => "until switched off".to_string(),
        });
        if let Some(m) = w["message"].as_str() {
            parts.push(format!("\"{m}\""));
        }
        println!("  {name:<32} {}", parts.join("  "));
    };
    let mut any = false;
    if data["global"].is_object() {
        println!("The whole proxy is closed:");
        line("all", &data["global"]);
        any = true;
    }
    if let Some(apps) = data["apps"].as_object().filter(|a| !a.is_empty()) {
        println!("Apps closed through the API:");
        for (name, w) in apps {
            line(name, w);
        }
        any = true;
    }
    if let Some(flagged) = data["flagged"].as_array().filter(|f| !f.is_empty()) {
        println!("Apps closed by their maintenance.flag file:");
        for name in flagged.iter().filter_map(|n| n.as_str()) {
            println!("  {name}");
        }
        any = true;
    }
    if !any {
        println!("Nothing is in maintenance.");
    }
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
            let path = format!("/api/v1/apps/{}/{}", app_name, action);
            match delegate_to_daemon(&config_ref, &path, action, app_name).await {
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
/// (`POST <path>`, e.g. `/api/v1/apps/<name>/<action>`), authenticated with
/// `[admin].api_key`.
async fn delegate_to_daemon(
    config: &Arc<ConfigManager>,
    path: &str,
    action: &str,
    app_name: &str,
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
        .post(format!("http://{}{}", admin_addr, path))
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
    // `[logging]` is read ahead of the rest of the config so that errors in
    // the rest are reported in the configured format and place.
    let logging_config = soli_proxy::config::read_logging_config(config_path);
    soli_proxy::logging::init(&logging_config, daemon_mode)?;
    soli_proxy::access_log::init(&logging_config, daemon_mode)?;

    if daemon_mode {
        eprintln!("Started in daemon mode. PID: {}", std::process::id());
    }

    if dev_mode {
        tracing::info!("Dev mode enabled: apps will be started with --dev flag");
    }

    // Install default crypto provider for rustls 0.23
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut config_manager = ConfigManager::new(config_path)?;
    // Apps are left running for the next proxy to adopt — unless systemd
    // kills them with it. Said once per start, where an operator looks.
    if !config_manager.get_config().apps.stop_on_shutdown(dev_mode) {
        if let Some(warning) = soli_proxy::systemd::unit_kills_apps() {
            tracing::warn!("{}", warning);
        }
    }
    if watch || dev_mode {
        config_manager.start_watcher()?;
    }

    // Maintenance windows opened through the admin API outlive a restart.
    config_manager
        .maintenance
        .persist_to(soli_proxy::response::maintenance::STATE_FILE)?;
    // Trap paths added from the TUI or the admin API outlive a restart too.
    config_manager
        .bots
        .persist_traps_to(soli_proxy::response::bots::TRAPS_FILE)?;

    let shutdown = ShutdownCoordinator::new();
    let shutdown_for_signal = shutdown.clone();
    let shutdown_for_drain = shutdown.clone();
    let config_ref = Arc::new(config_manager);
    // Windows opened with an end close by themselves. The request path
    // already treats them as closed past their end; this takes them out of
    // the state (and run/maintenance.json) so the API and the TUI agree.
    {
        let config = config_ref.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                match config.maintenance.expire_due(chrono::Utc::now()) {
                    Ok(closed) => {
                        for name in closed {
                            if name == "*" {
                                tracing::warn!(
                                    "maintenance mode off for the whole proxy: its end time passed"
                                );
                            } else {
                                tracing::warn!(
                                    "maintenance mode off for {}: its end time passed",
                                    name
                                );
                            }
                        }
                    }
                    Err(e) => tracing::error!("Could not close ended maintenance windows: {:#}", e),
                }
            }
        });
    }
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
            m.spawn_idle_reaper();
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
            let https_addr: SocketAddr = cfg.server.https_addr()?;
            let tls_acceptor = TlsAcceptor::from(config.clone());
            tracing::info!("HTTPS enabled on {}", https_addr);
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
            // Sleeping apps included: their first request comes over TLS.
            let mut test_domains: Vec<String> = manager
                .app_hosts()
                .into_iter()
                .filter(|d| d.ends_with(".test"))
                .collect();
            test_domains.sort();
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
                            let mut test_domains: Vec<String> = mgr_for_events
                                .app_hosts()
                                .into_iter()
                                .filter(|d| d.ends_with(".test"))
                                .collect();
                            test_domains.sort();
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

    let config_for_shutdown = config_ref.clone();

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

    tokio::spawn(async move {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }
        tracing::info!(
            "Received shutdown signal: no longer accepting, draining in-flight requests \
             (signal again to exit at once)"
        );
        // The listeners stop accepting; idle connections close; in-flight
        // HTTP/1 responses finish with `Connection: close` and HTTP/2 gets
        // GOAWAY, so browsers drop the socket instead of noticing a dead
        // peer ~30 s later. `run_server` then waits for the drain.
        shutdown_for_signal.initiate();

        // An operator who sends a second signal wants out now.
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }
        tracing::warn!("Second shutdown signal: exiting without finishing the drain");
        if daemon_mode {
            cleanup_pid();
        }
        // exit() skips destructors: flush the queued log lines first.
        soli_proxy::logging::flush();
        std::process::exit(130);
    });

    tracing::info!("Proxy server starting on {}", cfg.server.bind);
    // Returns once shutdown is initiated and the accept loops have stopped.
    server.run().await?;

    let cfg = config_for_shutdown.get_config();
    let grace = cfg.server.shutdown_grace_period();
    let started = Instant::now();
    match shutdown_for_drain.drain(grace).await {
        soli_proxy::shutdown::DrainOutcome::Drained => {
            tracing::info!("Drained in {} ms", started.elapsed().as_millis())
        }
        soli_proxy::shutdown::DrainOutcome::TimedOut(open) => tracing::warn!(
            "{} connection(s) still open after the {} s grace period \
             ([server] shutdown_grace_period); closing them",
            open,
            grace.as_secs()
        ),
    }

    // Apps are not the proxy's to take down on a restart: they keep running
    // and the next proxy adopts them (see `AppManager::adopt_running`).
    if let Some(manager) = app_manager {
        if cfg.apps.stop_on_shutdown(dev_mode) {
            tracing::info!("Stopping all managed apps ([apps] stop_on_shutdown)...");
            manager.stop_all().await;
        } else {
            tracing::info!(
                "Leaving apps running for the next proxy to adopt \
                 ([apps] stop_on_shutdown = false; `soli-proxy stop --all` stops them)"
            );
        }
    }

    if daemon_mode {
        cleanup_pid();
    }
    tracing::info!("Proxy stopped");
    soli_proxy::logging::flush();

    Ok(())
}

#[cfg(test)]
mod tests {
    /// `getcap` has spelled this two ways across versions, and prints nothing
    /// at all for a file with no capabilities — which is the common case and
    /// must read as "no" rather than as a parse failure.
    #[test]
    fn the_bind_capability_is_recognised_however_getcap_spells_it() {
        use super::grants_bind_capability;

        assert!(grants_bind_capability(
            "/home/soli/.local/bin/soli-proxy = cap_net_bind_service+ep\n"
        ));
        assert!(grants_bind_capability(
            "/home/soli/.local/bin/soli-proxy cap_net_bind_service=ep\n"
        ));
        // A file with no capabilities: `getcap` says nothing.
        assert!(!grants_bind_capability(""));
        // A different capability is not this one. Restoring what was not
        // there would be this function deciding policy, which is not its job.
        assert!(!grants_bind_capability("/usr/bin/ping = cap_net_raw+ep\n"));
    }

    use super::*;

    #[test]
    fn hash_password_produces_a_verifiable_bcrypt_hash() {
        let hash = hash_password_checked("correct horse", 4).unwrap();
        assert!(hash.starts_with("$2b$04$"), "{hash}");
        assert!(soli_proxy::auth::verify_password("correct horse", &hash));
        assert!(hash_password_checked("", 4).is_err());
    }

    #[test]
    fn hash_password_is_a_subcommand() {
        let cli = Cli::try_parse_from(["soli-proxy", "hash-password", "--cost", "10"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::HashPassword { cost: 10 })
        ));
        // The password never comes from argv, and the cost is bounded.
        assert!(Cli::try_parse_from(["soli-proxy", "hash-password", "secret"]).is_err());
        assert!(Cli::try_parse_from(["soli-proxy", "hash-password", "--cost", "3"]).is_err());
    }

    #[test]
    fn stop_takes_an_app_or_all_but_not_both() {
        let cli = Cli::try_parse_from(["soli-proxy", "stop", "site.example.com"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Stop { all: false, app_name: Some(ref n), .. }) if n == "site.example.com"
        ));
        for flag in ["--all", "--apps"] {
            let cli = Cli::try_parse_from(["soli-proxy", "stop", flag]).unwrap();
            assert!(matches!(
                cli.command,
                Some(Commands::Stop {
                    all: true,
                    app_name: None,
                    ..
                })
            ));
        }
        assert!(Cli::try_parse_from(["soli-proxy", "stop"]).is_err());
        assert!(Cli::try_parse_from(["soli-proxy", "stop", "--all", "site.example.com"]).is_err());
    }

    #[test]
    fn watch_can_be_turned_off() {
        assert!(Cli::try_parse_from(["soli-proxy"]).unwrap().watch);
        assert!(
            Cli::try_parse_from(["soli-proxy", "--watch"])
                .unwrap()
                .watch
        );
        assert!(
            !Cli::try_parse_from(["soli-proxy", "--watch", "false"])
                .unwrap()
                .watch
        );
    }

    #[test]
    fn check_accepts_the_main_commands_path_flags() {
        let cli = Cli::try_parse_from([
            "soli-proxy",
            "check",
            "--conf",
            "/etc/soli-proxy/proxy.conf",
            "--sites-dir",
            "/srv/sites",
            "--dev",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Check { ref conf, ref sites_dir, dev: true })
                if conf == "/etc/soli-proxy/proxy.conf" && sites_dir == "/srv/sites"
        ));
    }

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
