pub mod app;
pub mod route_form;
pub mod screens;

use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

use crate::app::AppManager;
use crate::auth::verify_password;
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::config::ConfigManager;
use crate::metrics::Metrics;

pub struct TuiContext {
    pub config_manager: Arc<ConfigManager>,
    pub metrics: Metrics,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub app_manager: Option<Arc<AppManager>>,
    pub start_time: Instant,
    pub auth_required: bool,
    pub runtime: tokio::runtime::Runtime,
}

impl TuiContext {
    pub fn new(
        config_manager: Arc<ConfigManager>,
        metrics: Metrics,
        circuit_breaker: Arc<CircuitBreaker>,
        app_manager: Option<Arc<AppManager>>,
        auth_required: bool,
        runtime: tokio::runtime::Runtime,
    ) -> Self {
        Self {
            config_manager,
            metrics,
            circuit_breaker,
            app_manager,
            start_time: Instant::now(),
            auth_required,
            runtime,
        }
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let cfg = self.config_manager.get_config();
        if let Some(ref hash) = cfg.admin.password_hash {
            verify_password(password, hash)
        } else {
            false
        }
    }

    /// Run an async app manager operation.
    pub fn run_app_action<F, T>(&self, f: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T, anyhow::Error>>,
    {
        self.runtime.block_on(f)
    }
}

pub fn authenticate(ctx: &TuiContext) -> Result<bool> {
    use std::io::{self, Write};

    if !ctx.auth_required {
        return Ok(true);
    }

    let cfg = ctx.config_manager.get_config();
    let username = cfg.admin.username.as_deref().unwrap_or("admin");

    let mut attempts = 0;
    let max_attempts = 3;

    while attempts < max_attempts {
        print!("\x1b[2J\x1b[H");
        println!("Soli Proxy TUI - Authentication Required");
        println!("========================================");
        println!("Username: {}", username);
        print!("Password: ");
        io::stdout().flush()?;

        let password = rpassword::read_password()?;

        if ctx.verify_password(&password) {
            println!("\nAuthentication successful!");
            std::thread::sleep(std::time::Duration::from_millis(500));
            return Ok(true);
        }

        attempts += 1;
        println!(
            "\nAuthentication failed. {} attempt(s) remaining.",
            max_attempts - attempts
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("Maximum attempts reached. Exiting.");
    Ok(false)
}

pub fn run_tui(ctx: TuiContext) -> Result<()> {
    if !authenticate(&ctx)? {
        anyhow::bail!("Authentication failed");
    }

    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        ratatui::restore();
        original_hook(panic_info);
    }));

    let mut terminal = ratatui::init();
    let result = run_tui_loop(&mut terminal, ctx);

    // Always restore the terminal
    ratatui::restore();

    result
}

fn run_tui_loop(terminal: &mut ratatui::DefaultTerminal, ctx: TuiContext) -> Result<()> {
    use std::time::{Duration, Instant};

    let mut app = app::TuiApp::new(ctx);
    terminal.draw(|f| app.render(f))?;

    let tick_rate = Duration::from_secs(2);
    let mut last_tick = Instant::now();

    loop {
        // Poll more frequently when a background action is running
        let poll_timeout = if app.has_pending_action() {
            Duration::from_millis(200)
        } else {
            tick_rate.saturating_sub(last_tick.elapsed())
        };

        if crossterm::event::poll(poll_timeout)? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if app.handle_key(key) {
                    break;
                }
            }
        }

        if app.has_pending_action() {
            app.check_pending_action();
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }

        terminal.draw(|f| app.render(f))?;
    }

    Ok(())
}

pub fn run_tui_with_config(conf_path: &str, sites_dir: &str, dev_mode: bool) -> Result<()> {
    let config_manager = Arc::new(ConfigManager::new(conf_path)?);
    let metrics = crate::new_metrics();
    let cb_config =
        CircuitBreakerConfig::from_toml(config_manager.get_config().circuit_breaker.as_ref());
    let circuit_breaker = Arc::new(CircuitBreaker::new(cb_config));

    let cfg = config_manager.get_config();
    let auth_required = cfg.admin.password_hash.is_some();

    let rt = tokio::runtime::Runtime::new()?;

    let app_manager: Option<Arc<AppManager>> = if let Ok(port_manager) =
        crate::app::PortManager::new("./run")
    {
        let port_manager = Arc::new(port_manager);
        // Load existing port assignments from disk
        if let Err(e) = rt.block_on(port_manager.load()) {
            tracing::warn!("Failed to load port assignments: {}", e);
        }
        if let Ok(m) = AppManager::new(sites_dir, port_manager, config_manager.clone(), dev_mode) {
            let mgr = Arc::new(m);
            let _guard = rt.enter();
            mgr.spawn_process_exit_monitor();
            drop(_guard);
            if let Err(e) = rt.block_on(mgr.discover_apps_readonly()) {
                tracing::warn!("Failed to discover apps: {}", e);
            }
            // Probe ports to detect actually running instances
            mgr.probe_running_apps();
            // Load app state (current_slot) from disk to see deploys that happened
            // while TUI was not running
            mgr.load_app_state();
            Some(mgr)
        } else {
            None
        }
    } else {
        None
    };

    let ctx = TuiContext::new(
        config_manager,
        (*metrics).clone(),
        circuit_breaker,
        app_manager,
        auth_required,
        rt,
    );

    run_tui(ctx)
}
