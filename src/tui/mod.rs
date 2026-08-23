pub mod app;
pub mod errors;
pub mod route_form;
pub mod screens;
pub mod theme;

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

pub fn authenticate(ctx: &TuiContext, terminal: &mut ratatui::DefaultTerminal) -> Result<bool> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::{
        layout::Alignment,
        style::{Color, Style},
        widgets::{Block, Borders, Paragraph},
    };
    use std::time::Duration;

    if !ctx.auth_required {
        return Ok(true);
    }

    let cfg = ctx.config_manager.get_config();
    let username = cfg.admin.username.as_deref().unwrap_or("admin").to_string();
    let mut password = String::new();
    let mut attempts = 0u32;
    let max_attempts: u32 = 3;
    let mut error: Option<String> = None;

    loop {
        terminal.draw(|f| {
            let area = theme::centered_modal(f.area(), 52, 11);
            let block = Block::default()
                .title(" Soli Proxy ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::ACCENT));
            f.render_widget(block, area);
            let inner = theme::inner(area);
            let masked: String = "•".repeat(password.len());
            let remaining = max_attempts.saturating_sub(attempts);
            let body = format!(
                "\n  Sign in as {username}\n\n  Password: {masked}_\n\n  {}\n  {} attempt(s) left  ·  Esc to quit",
                error.as_deref().unwrap_or(""),
                remaining
            );
            f.render_widget(
                Paragraph::new(body)
                    .style(Style::default().fg(Color::White))
                    .alignment(Alignment::Left),
                inner,
            );
        })?;

        if crossterm::event::poll(Duration::from_millis(100))? {
            match crossterm::event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    // Raw mode is on, so Ctrl+C is ours to honour.
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                    if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d')) {
                        return Ok(false);
                    }
                    match key.code {
                        // Esc quits on an empty field, clears it otherwise. Never
                        // bind a printable character here: it would make every
                        // password starting with that character unenterable.
                        KeyCode::Esc if password.is_empty() => return Ok(false),
                        KeyCode::Esc => {
                            password.clear();
                            error = None;
                        }
                        KeyCode::Enter => {
                            if ctx.verify_password(&password) {
                                return Ok(true);
                            }
                            attempts += 1;
                            password.clear();
                            if attempts >= max_attempts {
                                return Ok(false);
                            }
                            error =
                                Some(format!("Wrong password. {} left.", max_attempts - attempts));
                        }
                        KeyCode::Char(c) if !ctrl => {
                            password.push(c);
                            error = None;
                        }
                        KeyCode::Backspace => {
                            password.pop();
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
}

/// Button-press/release + wheel reporting in SGR encoding.
///
/// Deliberately *not* crossterm's `EnableMouseCapture`, which also turns on
/// `?1002`/`?1003` (drag and any-motion tracking). Those flood the event loop
/// with a redraw for every pixel of pointer movement, and the wider capture
/// takes over the terminal's own text selection — which matters here because
/// the Errors screen's copy path is OSC 52 with drag-select as the fallback.
const MOUSE_ON: &str = "\x1b[?1000h\x1b[?1006h";
const MOUSE_OFF: &str = "\x1b[?1006l\x1b[?1000l";

fn set_mouse_reporting(on: bool) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = out.write_all(if on { MOUSE_ON } else { MOUSE_OFF }.as_bytes());
    let _ = out.flush();
}

pub fn run_tui(ctx: TuiContext) -> Result<()> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        set_mouse_reporting(false);
        ratatui::restore();
        original_hook(panic_info);
    }));

    let mut terminal = ratatui::init();
    set_mouse_reporting(true);

    let result = (|| {
        if !authenticate(&ctx, &mut terminal)? {
            anyhow::bail!("Authentication failed");
        }
        run_tui_loop(&mut terminal, ctx)
    })();

    set_mouse_reporting(false);
    ratatui::restore();

    result
}

fn run_tui_loop(terminal: &mut ratatui::DefaultTerminal, ctx: TuiContext) -> Result<()> {
    use std::time::{Duration, Instant};

    let mut app = app::TuiApp::new(ctx);
    terminal.draw(|f| app.render(f))?;

    let metrics_tick = Duration::from_secs(1);
    let poll_timeout = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        // Only repaint when something actually moved. The loop wakes ten times a
        // second to animate the spinner and expire toasts; redrawing on every
        // wake (and on every mouse event) burns CPU for an identical frame.
        let mut dirty = false;

        if crossterm::event::poll(poll_timeout)? {
            match crossterm::event::read()? {
                crossterm::event::Event::Key(key) => {
                    if app.handle_key(key) {
                        break;
                    }
                    dirty = true;
                }
                crossterm::event::Event::Mouse(mouse) => {
                    dirty |= app.handle_mouse(mouse);
                }
                crossterm::event::Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }

        if app.has_pending_action() {
            app.check_pending_action();
            dirty = true;
        }

        dirty |= app.on_frame();

        if last_tick.elapsed() >= metrics_tick {
            app.on_tick();
            last_tick = Instant::now();
            dirty = true;
        }

        if dirty {
            terminal.draw(|f| app.render(f))?;
        }
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
