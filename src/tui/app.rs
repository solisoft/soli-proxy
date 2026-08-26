use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Stylize,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::ConfigManager;
use crate::metrics::{AppMetricsJson, MetricsSnapshot};

use super::errors::{load_request_errors, ErrorEntry};
use super::theme;
use super::{route_form::RouteForm, screens, TuiContext};

/// Per-app stats combining traffic (from admin API) and system (from /proc).
#[derive(Clone, Default)]
pub struct AppStats {
    pub requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub avg_response_time_ms: f64,
    pub errors: u64,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
}

/// Rolling history for sparkline charts.
pub struct AppHistory {
    pub cpu: VecDeque<u64>,
    pub mem: VecDeque<u64>,
}

const HISTORY_LEN: usize = 60; // 60 samples × 1s = 1 minute

/// How often the background poller re-reads the daemon's admin API.
const DAEMON_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// State of the daemon's admin API. "Not reachable" and "not enabled" are
/// different things: a proxy running with `admin.enabled = false` is perfectly
/// healthy, it just has no metrics endpoint to offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaemonStatus {
    /// No poll has completed yet.
    #[default]
    Connecting,
    Ok,
    /// Admin API is enabled but did not answer.
    Unreachable,
    /// `admin.enabled = false` — nothing to connect to, nothing wrong.
    Disabled,
}

impl DaemonStatus {
    /// Short footer badge.
    pub fn badge(self) -> &'static str {
        match self {
            DaemonStatus::Connecting => " daemon … ",
            DaemonStatus::Ok => " daemon ● ",
            DaemonStatus::Unreachable => " daemon ✕ ",
            DaemonStatus::Disabled => " daemon ○ ",
        }
    }

    pub fn color(self) -> Color {
        match self {
            DaemonStatus::Connecting => theme::MUTED,
            DaemonStatus::Ok => theme::SUCCESS,
            DaemonStatus::Unreachable => theme::DANGER,
            DaemonStatus::Disabled => theme::MUTED,
        }
    }

    /// Why the metric panes are empty, when they are.
    pub fn explain(self) -> &'static str {
        match self {
            DaemonStatus::Connecting => "connecting",
            DaemonStatus::Ok => "",
            DaemonStatus::Unreachable => "daemon unreachable",
            DaemonStatus::Disabled => "admin api off",
        }
    }

    pub fn is_ok(self) -> bool {
        self == DaemonStatus::Ok
    }
}

/// One completed poll of the admin API.
#[derive(Default)]
struct DaemonSample {
    apps: HashMap<String, AppMetricsJson>,
    global: Option<MetricsSnapshot>,
    status: DaemonStatus,
    /// Incremented per completed poll so the UI can tell a fresh sample from a
    /// repeat read of the same one.
    seq: u64,
}

/// Handle to the background poller. The fetch used to run inline on the render
/// thread via `block_on`, which froze the UI for the whole request timeout on
/// every tick — worst exactly when the daemon was down and you most wanted to
/// look around. Now the UI only ever reads the last completed sample.
struct DaemonFeed {
    latest: Arc<Mutex<DaemonSample>>,
    wake: Arc<tokio::sync::Notify>,
}

impl DaemonFeed {
    fn spawn(runtime: &tokio::runtime::Runtime, config_manager: Arc<ConfigManager>) -> Self {
        let latest = Arc::new(Mutex::new(DaemonSample::default()));
        let wake = Arc::new(tokio::sync::Notify::new());
        let cell = latest.clone();
        let signal = wake.clone();

        runtime.spawn(async move {
            // Off the render thread, so the timeout can be generous, and the
            // client (with its connection pool) is built once rather than per tick.
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_millis(1500))
                .build()
            {
                Ok(client) => client,
                Err(_) => {
                    if let Ok(mut slot) = cell.lock() {
                        slot.status = DaemonStatus::Unreachable;
                        slot.seq = slot.seq.wrapping_add(1);
                    }
                    return;
                }
            };

            loop {
                let sample = poll_daemon(&client, &config_manager).await;
                if let Ok(mut slot) = cell.lock() {
                    let seq = slot.seq.wrapping_add(1);
                    *slot = DaemonSample { seq, ..sample };
                }
                tokio::select! {
                    _ = tokio::time::sleep(DAEMON_POLL_INTERVAL) => {}
                    _ = signal.notified() => {}
                }
            }
        });

        Self { latest, wake }
    }

    /// Ask the poller to fetch again now instead of waiting out its interval.
    fn request_refresh(&self) {
        self.wake.notify_one();
    }
}

/// Fetch per-app and global traffic metrics from the daemon's admin API.
/// Best effort: an unreachable daemon yields an `Unreachable` sample rather
/// than an error, so the UI keeps running with whatever it last knew.
async fn poll_daemon(client: &reqwest::Client, config_manager: &ConfigManager) -> DaemonSample {
    let cfg = config_manager.get_config();
    if !cfg.admin.enabled.unwrap_or(true) {
        return DaemonSample {
            status: DaemonStatus::Disabled,
            ..Default::default()
        };
    }

    // Convert "0.0.0.0:9090" to "127.0.0.1:9090" for local connections
    let admin_addr = cfg
        .admin
        .bind
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "127.0.0.1:");
    let apps_url = format!("http://{}/api/v1/app-metrics", admin_addr);
    let global_url = format!("http://{}/api/v1/metrics", admin_addr);
    let api_key = cfg.admin.api_key.clone();

    let with_key = |mut req: reqwest::RequestBuilder| {
        if let Some(ref key) = api_key {
            req = req.header("X-Api-Key", key);
        }
        req
    };

    // Admin API wraps JSON responses in {"ok": true, "data": ...}
    #[derive(serde::Deserialize)]
    struct Envelope {
        data: HashMap<String, AppMetricsJson>,
    }

    let (apps, global) = tokio::join!(
        async {
            let resp = with_key(client.get(&apps_url)).send().await.ok()?;
            resp.json::<Envelope>().await.ok().map(|e| e.data)
        },
        async {
            let resp = with_key(client.get(&global_url)).send().await.ok()?;
            let text = resp.text().await.ok()?;
            Some(parse_prometheus_snapshot(&text))
        }
    );

    let status = if apps.is_some() || global.is_some() {
        DaemonStatus::Ok
    } else {
        DaemonStatus::Unreachable
    };

    DaemonSample {
        apps: apps.unwrap_or_default(),
        global,
        status,
        seq: 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    Routes,
    Apps,
    Circuits,
    Errors,
    Config,
    Help,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Modal {
    None,
    RouteForm,
    DeleteConfirm(usize),
    AppActionMenu(String, usize),      // app_name, selected action index
    AppActionProgress(String, String), // app_name, action description
    AppActionResult(String),           // result message
    LogViewer(String, String),
    ErrorDetail(usize), // index into TuiApp::errors
}

const APP_ACTIONS: &[&str] = &["Deploy", "Restart", "Stop", "Rollback", "View Logs"];

/// How long a transient status flash stays on screen.
const TOAST_TTL: Duration = Duration::from_secs(2);

/// Largest scroll offset that still fills the viewport: the top of the last
/// page, not the index of the last row. Every screen renders its rows as
/// `.skip(scroll_offset).take(visible)`, so an offset of `len - 1` would leave
/// exactly one row on screen.
fn max_offset(len: usize, visible: usize) -> usize {
    len.saturating_sub(visible.max(1))
}

pub struct TuiApp {
    ctx: TuiContext,
    current_screen: Screen,
    modal: Modal,
    search_query: String,
    search_active: bool,
    scroll_offset: usize,
    selected_index: usize,
    help_show: bool,
    route_form: Option<RouteForm>,
    pub app_stats: HashMap<String, AppStats>,
    pub app_history: HashMap<String, AppHistory>,
    /// Global traffic snapshot fetched from the daemon's admin API.
    /// The TUI runs in its own process, so the local metrics registry is empty.
    remote_snapshot: Option<MetricsSnapshot>,
    /// Tick counter driving the periodic full PID re-probe.
    ticks: u64,
    pending_action: Option<tokio::task::JoinHandle<Result<String, String>>>,
    filtered_apps_count: usize,
    log_viewer_page: usize,
    log_viewer_max_offset: usize,
    log_auto_follow: bool,
    /// Request failures parsed from proxy.log, oldest-first.
    errors: Vec<ErrorEntry>,
    /// Transient "copied to clipboard" flash for the error detail modal.
    error_copied: bool,
    toast: Option<(String, Instant)>,
    /// Background poller for the daemon's admin API.
    daemon: DaemonFeed,
    daemon_status: DaemonStatus,
    /// `seq` of the last sample folded into `rps_history`, so a tick that
    /// re-reads an unchanged sample does not fabricate a rate of zero.
    last_daemon_seq: u64,
    rps_history: VecDeque<u64>,
    last_requests_total: u64,
    last_metrics_at: Option<Instant>,
    frame_ticks: u64,
    /// Cached `proxy.conf` text and line count for the Config screen, so it is
    /// not re-read from disk on every frame.
    config_text: String,
    config_line_count: usize,
    last_sidebar: Rect,
    last_body: Rect,
    visible_height: usize,
}

impl TuiApp {
    pub fn new(ctx: TuiContext) -> Self {
        let daemon = DaemonFeed::spawn(&ctx.runtime, ctx.config_manager.clone());
        let mut app = Self {
            ctx,
            current_screen: Screen::Dashboard,
            modal: Modal::None,
            search_query: String::new(),
            search_active: false,
            scroll_offset: 0,
            selected_index: 0,
            help_show: false,
            route_form: None,
            app_stats: HashMap::new(),
            app_history: HashMap::new(),
            remote_snapshot: None,
            ticks: 0,
            pending_action: None,
            filtered_apps_count: 0,
            log_viewer_page: 1,
            log_viewer_max_offset: 0,
            log_auto_follow: true,
            errors: Vec::new(),
            error_copied: false,
            toast: None,
            daemon,
            daemon_status: DaemonStatus::Connecting,
            last_daemon_seq: 0,
            rps_history: VecDeque::with_capacity(HISTORY_LEN),
            last_requests_total: 0,
            last_metrics_at: None,
            frame_ticks: 0,
            config_text: String::new(),
            config_line_count: 0,
            last_sidebar: Rect::default(),
            last_body: Rect::default(),
            visible_height: 20,
        };
        app.collect_stats();
        app
    }

    fn show_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// Collect all per-app stats: traffic from the background daemon poller +
    /// system stats from /proc. Never blocks on the network.
    fn collect_stats(&mut self) {
        let (traffic, global, status, seq) = self.read_daemon_sample();
        self.daemon_status = status;

        // Only fold a sample into the rate history once. Re-reading the same
        // sample would show a delta of zero over a growing interval.
        let fresh = seq != self.last_daemon_seq;
        self.last_daemon_seq = seq;
        if fresh {
            if let Some(ref snap) = global {
                let now = Instant::now();
                if let Some(prev_at) = self.last_metrics_at {
                    let elapsed = now.duration_since(prev_at).as_secs_f64();
                    let rps = theme::rps_from_delta(
                        self.last_requests_total,
                        snap.requests_total,
                        elapsed,
                    );
                    if self.rps_history.len() >= HISTORY_LEN {
                        self.rps_history.pop_front();
                    }
                    self.rps_history.push_back(rps);
                }
                self.last_requests_total = snap.requests_total;
                self.last_metrics_at = Some(now);
            } else {
                // Daemon went away: drop the stale anchor so the first sample
                // after it returns is not averaged across the whole outage.
                self.last_metrics_at = None;
            }
        }
        self.remote_snapshot = global;

        // Re-probe PIDs for apps that lost theirs, then collect /proc stats
        if let Some(ref mgr) = self.ctx.app_manager {
            mgr.refresh_pids();
        }

        let apps = self
            .ctx
            .app_manager
            .as_ref()
            .map(|m| m.list_apps_sync())
            .unwrap_or_default();

        for app in &apps {
            let inst = if app.current_slot == "blue" {
                &app.blue
            } else {
                &app.green
            };

            let name = &app.config.name;

            // Start with traffic data from the daemon (if available)
            let mut stats = traffic
                .get(name)
                .map(|m| AppStats {
                    requests: m.requests,
                    bytes_received: m.bytes_received,
                    bytes_sent: m.bytes_sent,
                    avg_response_time_ms: m.avg_response_time_ms,
                    errors: m.errors,
                    cpu_percent: None,
                    memory_bytes: None,
                })
                .unwrap_or_default();

            // Read system metrics from /proc
            if let Some(pid) = inst.pid {
                if let Some(proc_stats) = self.ctx.metrics.get_process_stats(pid) {
                    stats.cpu_percent = proc_stats.cpu_percent;
                    stats.memory_bytes = proc_stats.memory_rss_bytes;
                }
            }

            // Update history
            let history = self
                .app_history
                .entry(name.clone())
                .or_insert_with(|| AppHistory {
                    cpu: VecDeque::with_capacity(HISTORY_LEN),
                    mem: VecDeque::with_capacity(HISTORY_LEN),
                });

            let cpu_val = stats.cpu_percent.map(|c| (c * 10.0) as u64).unwrap_or(0);
            let mem_val = stats.memory_bytes.unwrap_or(0);

            if history.cpu.len() >= HISTORY_LEN {
                history.cpu.pop_front();
            }
            history.cpu.push_back(cpu_val);

            if history.mem.len() >= HISTORY_LEN {
                history.mem.pop_front();
            }
            history.mem.push_back(mem_val);

            self.app_stats.insert(name.clone(), stats);
        }

        // Parse individual request failures from proxy.log for the Errors screen.
        self.errors = load_request_errors();

        // Cached for the Config screen, which used to re-read the file on every
        // frame and had no way to know how far it could scroll.
        self.config_text = std::fs::read_to_string(self.ctx.config_manager.config_path())
            .unwrap_or_else(|e| format!("Failed to read config file: {e}"));
        self.config_line_count = self.config_text.lines().count();

        self.clamp_scroll();
    }

    /// Copy the newest sample produced by the background poller. Lock
    /// contention is a few microseconds and there is no I/O on this path, so
    /// this is safe to call from the render thread.
    fn read_daemon_sample(
        &self,
    ) -> (
        HashMap<String, AppMetricsJson>,
        Option<MetricsSnapshot>,
        DaemonStatus,
        u64,
    ) {
        match self.daemon.latest.lock() {
            Ok(slot) => (slot.apps.clone(), slot.global, slot.status, slot.seq),
            // Poisoned only if the poller panicked mid-write; report it rather
            // than propagating the panic into the render loop.
            Err(_) => (
                HashMap::new(),
                None,
                DaemonStatus::Unreachable,
                self.last_daemon_seq,
            ),
        }
    }

    /// Called on each tick (auto-refresh).
    pub fn on_tick(&mut self) {
        self.ticks += 1;
        if let Some(ref mgr) = self.ctx.app_manager {
            // Reload app state from disk to see deploys that happened via API
            mgr.load_app_state();
            // `refresh_pids` (in collect_stats) only validates that /proc/<pid>
            // still exists, which a recycled PID passes. Periodically re-probe
            // every port so displayed PIDs are re-verified against the actual
            // listener.
            if self.ticks.is_multiple_of(15) {
                mgr.probe_running_apps();
            }
        }
        self.collect_stats();
        self.check_pending_action();
    }

    /// Per-loop housekeeping. Returns true when the frame needs repainting, so
    /// an idle TUI does not redraw ten times a second for an identical image.
    pub fn on_frame(&mut self) -> bool {
        self.frame_ticks += 1;
        let mut dirty = false;
        if let Some((_, at)) = self.toast {
            if at.elapsed() >= TOAST_TTL {
                self.toast = None;
                dirty = true;
            }
        }
        // The footer spinner animates only while an action is in flight.
        dirty || self.pending_action.is_some()
    }

    pub fn has_pending_action(&self) -> bool {
        self.pending_action.is_some()
    }

    pub fn check_pending_action(&mut self) {
        let finished = self
            .pending_action
            .as_ref()
            .is_some_and(|h| h.is_finished());
        if !finished {
            return;
        }
        let handle = self.pending_action.take().unwrap();
        match self.ctx.runtime.block_on(handle) {
            Ok(Ok(msg)) => {
                if let Some(ref mgr) = self.ctx.app_manager {
                    mgr.probe_running_apps();
                }
                self.modal = Modal::None;
                self.show_toast(msg);
            }
            Ok(Err(e)) => {
                self.modal = Modal::AppActionResult(format!("Error: {}", e));
            }
            Err(e) => {
                self.modal = Modal::AppActionResult(format!("Error: {}", e));
            }
        }
    }

    pub fn render(&mut self, f: &mut Frame) {
        let size = f.area();
        let (sidebar, rest) = theme::split_shell(size);
        let has_toast = self.toast.is_some();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(if has_toast { 1 } else { 0 }),
                Constraint::Length(1),
            ])
            .split(rest);

        self.last_sidebar = sidebar;
        self.last_body = chunks[0];
        // Panel rows minus the title chip and the column header.
        self.visible_height = (chunks[0].height.saturating_sub(2) as usize).max(1);
        // The terminal may have been resized since the last input event.
        self.clamp_scroll();

        let nav_idx = match self.current_screen {
            Screen::Dashboard => 0,
            Screen::Routes => 1,
            Screen::Apps => 2,
            Screen::Circuits => 3,
            Screen::Errors => 4,
            Screen::Config => 5,
            Screen::Help => 0,
        };
        theme::render_sidebar(f, sidebar, nav_idx, env!("CARGO_PKG_VERSION"));
        self.render_main(f, chunks[0]);
        if has_toast {
            if let Some((ref msg, _)) = self.toast {
                theme::render_toast(f, chunks[1], msg);
            }
        }
        self.render_footer(f, chunks[2]);

        if self.help_show {
            self.render_help(f, chunks[0]);
        }

        match &self.modal {
            Modal::RouteForm => self.render_route_form_modal(f),
            Modal::DeleteConfirm(idx) => self.render_delete_confirm(f, *idx),
            Modal::AppActionMenu(app_name, selected) => {
                self.render_app_action_menu(f, app_name, *selected)
            }
            Modal::AppActionProgress(app_name, action) => {
                self.render_app_action_progress(f, app_name, action)
            }
            Modal::AppActionResult(msg) => self.render_app_action_result(f, msg),
            Modal::LogViewer(app_name, slot) => {
                let app_name = app_name.clone();
                let slot = slot.clone();
                self.render_log_viewer(f, &app_name, &slot);
            }
            Modal::ErrorDetail(idx) => self.render_error_detail(f, *idx),
            Modal::None => {}
        }
    }

    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        if key.kind != crossterm::event::KeyEventKind::Press {
            return false;
        }

        if self.help_show {
            self.help_show = false;
            return false;
        }

        match &self.modal {
            Modal::None => self.handle_normal_key(key),
            Modal::RouteForm => self.handle_route_form_key(key),
            Modal::DeleteConfirm(_) => self.handle_delete_modal_key(key),
            Modal::AppActionMenu(_, _) => self.handle_app_action_menu_key(key),
            Modal::AppActionProgress(_, _) => self.handle_app_action_progress_key(key),
            Modal::AppActionResult(_) => self.handle_app_action_result_key(key),
            Modal::LogViewer(_, _) => self.handle_log_viewer_key(key),
            Modal::ErrorDetail(_) => self.handle_error_detail_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;

        if self.search_active {
            match key.code {
                KeyCode::Esc => {
                    self.search_active = false;
                    self.search_query.clear();
                }
                KeyCode::Enter => {
                    self.search_active = false;
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                }
                _ => {}
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => {
                self.help_show = true;
            }
            KeyCode::Char('r') => {
                self.refresh_data();
            }
            KeyCode::Char('1') => self.jump_screen(Screen::Dashboard),
            KeyCode::Char('2') => self.jump_screen(Screen::Routes),
            KeyCode::Char('3') => self.jump_screen(Screen::Apps),
            KeyCode::Char('4') => self.jump_screen(Screen::Circuits),
            KeyCode::Char('5') => self.jump_screen(Screen::Errors),
            KeyCode::Char('6') => self.jump_screen(Screen::Config),
            KeyCode::PageDown => {
                let page = self.get_visible_height().max(1) as i32;
                self.move_selection(page);
            }
            KeyCode::PageUp => {
                let page = self.get_visible_height().max(1) as i32;
                self.move_selection(-page);
            }
            KeyCode::Char('/') => {
                self.search_active = true;
            }
            KeyCode::Esc => {
                self.selected_index = 0;
                self.scroll_offset = 0;
            }
            KeyCode::Char('g') => {
                self.scroll_offset = 0;
                self.selected_index = 0;
            }
            KeyCode::Char('G') => {
                self.scroll_to_bottom();
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
            }
            KeyCode::Tab => {
                self.cycle_screen(1);
            }
            KeyCode::BackTab => {
                self.cycle_screen(-1);
            }
            KeyCode::Enter => {
                self.handle_enter();
            }
            KeyCode::Char('a') if self.current_screen == Screen::Routes => {
                self.route_form = Some(RouteForm::new_empty());
                self.modal = Modal::RouteForm;
            }
            KeyCode::Char('d') if self.current_screen == Screen::Routes => {
                if let Some(rule_idx) = self.resolve_route_index() {
                    self.modal = Modal::DeleteConfirm(rule_idx);
                }
            }
            KeyCode::Char('e') if self.current_screen == Screen::Routes => {
                if let Some(rule_idx) = self.resolve_route_index() {
                    let rules = &self.ctx.config_manager.get_config().rules;
                    if rule_idx < rules.len() {
                        self.route_form = Some(RouteForm::from_rule(&rules[rule_idx], rule_idx));
                        self.modal = Modal::RouteForm;
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn handle_route_form_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;

        let form = match self.route_form.as_mut() {
            Some(f) => f,
            None => {
                self.modal = Modal::None;
                return false;
            }
        };

        form.error = None;

        // Auth field has its own key handling
        if form.is_auth_input_mode() {
            match key.code {
                KeyCode::Esc => form.auth_cancel_add(),
                KeyCode::Tab | KeyCode::Enter => {
                    if form.auth_mode == super::route_form::AuthMode::AddUsername {
                        form.auth_advance_to_password();
                    } else {
                        // AddPassword: Enter confirms
                        form.auth_confirm_add();
                    }
                }
                KeyCode::BackTab if form.auth_mode == super::route_form::AuthMode::AddPassword => {
                    form.auth_mode = super::route_form::AuthMode::AddUsername;
                    form.cursor_pos = form.auth_new_username.len();
                }
                KeyCode::Char(c) => form.insert_char(c),
                KeyCode::Backspace => form.delete_char(),
                KeyCode::Left => form.move_cursor_left(),
                KeyCode::Right => form.move_cursor_right(),
                _ => {}
            }
            return false;
        }

        if form.is_auth_list_mode() {
            match key.code {
                KeyCode::Esc => {
                    self.route_form = None;
                    self.modal = Modal::None;
                }
                KeyCode::Tab => form.next_field(),
                KeyCode::BackTab => form.prev_field(),
                KeyCode::Char('a') => form.auth_start_add(),
                KeyCode::Char('d') => form.auth_remove_selected(),
                KeyCode::Char('j') | KeyCode::Down => form.auth_move_selection(1),
                KeyCode::Char('k') | KeyCode::Up => form.auth_move_selection(-1),
                KeyCode::Enter => self.save_route_form(),
                _ => {}
            }
            return false;
        }

        // Normal field handling (text fields, select fields)
        match key.code {
            KeyCode::Esc => {
                self.route_form = None;
                self.modal = Modal::None;
            }
            KeyCode::Tab => form.next_field(),
            KeyCode::BackTab => form.prev_field(),
            KeyCode::Left => {
                if form.is_select_field() {
                    form.cycle_select(-1);
                } else {
                    form.move_cursor_left();
                }
            }
            KeyCode::Right => {
                if form.is_select_field() {
                    form.cycle_select(1);
                } else {
                    form.move_cursor_right();
                }
            }
            KeyCode::Char(c) if !form.is_select_field() => {
                form.insert_char(c);
            }
            KeyCode::Backspace if !form.is_select_field() => {
                form.delete_char();
            }
            KeyCode::Enter => self.save_route_form(),
            _ => {}
        }
        false
    }

    fn save_route_form(&mut self) {
        let form = match self.route_form.as_ref() {
            Some(f) => f,
            None => return,
        };

        match form.build_rule() {
            Ok(rule) => {
                let result = if let Some(idx) = form.edit_index {
                    self.ctx.config_manager.update_route(idx, rule)
                } else {
                    self.ctx.config_manager.add_route(rule)
                };
                match result {
                    Ok(()) => {
                        self.route_form = None;
                        self.modal = Modal::None;
                    }
                    Err(e) => {
                        if let Some(f) = self.route_form.as_mut() {
                            f.error = Some(format!("Save failed: {}", e));
                        }
                    }
                }
            }
            Err(e) => {
                if let Some(f) = self.route_form.as_mut() {
                    f.error = Some(e.to_string());
                }
            }
        }
    }

    fn handle_delete_modal_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.modal = Modal::None;
            }
            KeyCode::Char('y') | KeyCode::Enter => {
                if let Modal::DeleteConfirm(idx) = self.modal {
                    if let Err(e) = self.ctx.config_manager.remove_route(idx) {
                        tracing::error!("Failed to delete route: {}", e);
                    }
                }
                self.modal = Modal::None;
            }
            _ => {}
        }
        false
    }

    fn handle_app_action_menu_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if let Modal::AppActionMenu(name, sel) = &self.modal {
                    let new_sel = (*sel + 1).min(APP_ACTIONS.len() - 1);
                    self.modal = Modal::AppActionMenu(name.clone(), new_sel);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if let Modal::AppActionMenu(name, sel) = &self.modal {
                    let new_sel = sel.saturating_sub(1);
                    self.modal = Modal::AppActionMenu(name.clone(), new_sel);
                }
            }
            KeyCode::Enter => {
                if let Modal::AppActionMenu(name, sel) = self.modal.clone() {
                    self.execute_app_action(&name, sel);
                }
            }
            _ => {}
        }
        false
    }

    fn handle_app_action_result_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                self.modal = Modal::None;
            }
            _ => {}
        }
        false
    }

    fn execute_app_action(&mut self, app_name: &str, action_idx: usize) {
        let action = APP_ACTIONS[action_idx];

        // View Logs: read-only, stays local
        if action == "View Logs" {
            if let Some(ref mgr) = self.ctx.app_manager {
                let apps = mgr.list_apps_sync();
                if let Some(app) = apps.iter().find(|a| a.config.name == app_name) {
                    self.scroll_offset = 0;
                    self.log_auto_follow = true;
                    self.modal =
                        Modal::LogViewer(app.config.name.clone(), app.current_slot.clone());
                    return;
                }
            }
            self.modal = Modal::None;
            return;
        }

        let name = app_name.to_string();
        let action_desc = format!("{}ing {}", action.trim_end_matches('y'), name);

        // Call proxy's admin API to perform the action
        // The proxy's AppManager handles process lifecycle properly
        let cfg = self.ctx.config_manager.get_config();
        if cfg.admin.enabled != Some(true) {
            self.modal = Modal::AppActionResult("Admin API not enabled".to_string());
            return;
        }

        // Convert "0.0.0.0:9016" to "127.0.0.1:9016" for local connections
        let admin_addr = cfg
            .admin
            .bind
            .replace("0.0.0.0:", "127.0.0.1:")
            .replace("[::]:", "127.0.0.1:");
        let endpoint = match action {
            "Deploy" => "deploy",
            "Restart" => "restart",
            "Stop" => "stop",
            "Rollback" => "rollback",
            _ => return,
        };
        let url = format!("http://{}/api/v1/apps/{}/{}", admin_addr, name, endpoint);
        let api_key = cfg.admin.api_key.clone();

        let handle = self.ctx.runtime.spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .map_err(|e| e.to_string())?;
            let mut req = client.post(&url);
            if let Some(ref key) = api_key {
                req = req.header("X-Api-Key", key);
            }
            let resp = req.send().await.map_err(|e| e.to_string())?;
            if resp.status().is_success() {
                Ok(format!("{} completed for {}", action, name))
            } else {
                let body = resp.text().await.unwrap_or_default();
                Err(format!("Failed: {}", body))
            }
        });

        self.pending_action = Some(handle);
        self.modal = Modal::AppActionProgress(app_name.to_string(), action_desc);
    }

    fn handle_app_action_progress_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        if key.code == KeyCode::Esc {
            // Dismiss the progress modal but let the action continue in background
            self.modal = Modal::None;
        }
        false
    }

    fn render_app_action_progress(&self, f: &mut Frame, app_name: &str, action: &str) {
        let area = f.area();
        let w = 50u16.min(area.width.saturating_sub(4));
        let h = 6u16.min(area.height.saturating_sub(4));
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let block = Block::default()
            .title(format!(" {} ", action))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));

        let text = Paragraph::new(format!("\n{}...\n\nPress Esc to dismiss", app_name))
            .block(block)
            .alignment(Alignment::Center);

        f.render_widget(text, modal_area);
    }

    fn handle_log_viewer_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        let page = self.log_viewer_page.max(1);
        let max = self.log_viewer_max_offset;
        match key.code {
            KeyCode::Esc => {
                self.log_auto_follow = true;
                self.modal = Modal::None;
            }
            KeyCode::Char('k') | KeyCode::Up | KeyCode::PageUp => {
                self.log_auto_follow = false;
                if key.code == KeyCode::PageUp {
                    self.scroll_offset = self.scroll_offset.saturating_sub(page);
                } else {
                    self.scroll_offset = self.scroll_offset.saturating_sub(1);
                }
            }
            KeyCode::Char('j') | KeyCode::Down | KeyCode::PageDown | KeyCode::Char(' ') => {
                self.log_auto_follow = false;
                if key.code == KeyCode::PageDown || key.code == KeyCode::Char(' ') {
                    self.scroll_offset = (self.scroll_offset + page).min(max);
                } else {
                    self.scroll_offset = (self.scroll_offset + 1).min(max);
                }
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.scroll_offset = max;
                self.log_auto_follow = false;
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.scroll_offset = 0;
                self.log_auto_follow = true;
            }
            _ => {}
        }
        false
    }

    fn handle_error_detail_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        let Modal::ErrorDetail(idx) = self.modal else {
            return false;
        };
        let last = self.errors.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
            }
            KeyCode::Char('j') | KeyCode::Down | KeyCode::Char('n') => {
                let new_idx = (idx + 1).min(last);
                self.selected_index = new_idx;
                self.error_copied = false;
                self.modal = Modal::ErrorDetail(new_idx);
            }
            KeyCode::Char('k') | KeyCode::Up | KeyCode::Char('p') => {
                let new_idx = idx.saturating_sub(1);
                self.selected_index = new_idx;
                self.error_copied = false;
                self.modal = Modal::ErrorDetail(new_idx);
            }
            KeyCode::Char('y') | KeyCode::Char('c') => {
                if let Some(entry) = self.errors.get(idx) {
                    copy_to_clipboard_osc52(&entry.detail_block());
                    self.error_copied = true;
                }
            }
            _ => {}
        }
        false
    }

    fn render_error_detail(&self, f: &mut Frame, idx: usize) {
        let Some(entry) = self.errors.get(idx) else {
            return;
        };

        let area = f.area();
        let w = area.width.saturating_sub(10).min(90);
        let h = area.height.saturating_sub(6).min(16);
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let copied = if self.error_copied { " [copied]" } else { "" };
        let block = Block::default()
            .title(format!(
                " Error {}/{}{} [j/k:nav  y:copy  Esc:close] ",
                idx + 1,
                self.errors.len(),
                copied
            ))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));

        let paragraph = Paragraph::new(entry.detail_block()).block(block);
        f.render_widget(paragraph, modal_area);
    }

    fn cycle_screen(&mut self, dir: i32) {
        self.current_screen = match self.current_screen {
            Screen::Dashboard => {
                if dir > 0 {
                    Screen::Routes
                } else {
                    Screen::Config
                }
            }
            Screen::Routes => {
                if dir > 0 {
                    Screen::Apps
                } else {
                    Screen::Dashboard
                }
            }
            Screen::Apps => {
                if dir > 0 {
                    Screen::Circuits
                } else {
                    Screen::Routes
                }
            }
            Screen::Circuits => {
                if dir > 0 {
                    Screen::Errors
                } else {
                    Screen::Apps
                }
            }
            Screen::Errors => {
                if dir > 0 {
                    Screen::Config
                } else {
                    Screen::Circuits
                }
            }
            Screen::Config => {
                if dir > 0 {
                    Screen::Dashboard
                } else {
                    Screen::Errors
                }
            }
            Screen::Help => Screen::Dashboard,
        };
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    fn move_selection(&mut self, dir: i32) {
        if self.scrolls_text() {
            self.scroll_text(dir);
            return;
        }
        let max = self.get_max_selection();
        if max == 0 {
            return;
        }
        let max_idx = (max as i32) - 1;
        let new_idx = ((self.selected_index as i32) + dir).clamp(0, max_idx);
        self.selected_index = new_idx as usize;
        let visible = self.get_visible_height() as i32;
        let scroll_threshold = (self.scroll_offset as i32) + visible - 2;
        if self.selected_index as i32 >= scroll_threshold {
            self.scroll_offset = ((self.selected_index as i32) + 2 - visible).max(0) as usize;
        }
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        }
    }

    fn get_max_selection(&self) -> usize {
        match self.current_screen {
            Screen::Dashboard => 0,
            // The filtered count, not the full one: with a search active the
            // screen renders fewer rows than the config holds, and a cursor
            // past the end scrolls the list into empty space.
            Screen::Routes => {
                let rules = self.ctx.config_manager.get_config().rules.clone();
                screens::routes::filter_indices(&rules, &self.search_query).len()
            }
            Screen::Apps => self.filtered_apps_count,
            Screen::Circuits => self.ctx.circuit_breaker.get_states().len(),
            Screen::Errors => self.errors.len(),
            Screen::Config => 0,
            Screen::Help => 0,
        }
    }

    fn get_visible_height(&self) -> usize {
        self.visible_height.max(1)
    }

    /// Screens that scroll a block of text rather than moving a row cursor.
    /// They have no selectable rows, so `get_max_selection` is 0 for them and
    /// the cursor-based path would refuse to move at all.
    fn scrolls_text(&self) -> bool {
        matches!(self.current_screen, Screen::Config)
    }

    fn text_line_count(&self) -> usize {
        match self.current_screen {
            Screen::Config => self.config_line_count,
            _ => 0,
        }
    }

    fn max_text_offset(&self) -> usize {
        max_offset(self.text_line_count(), self.get_visible_height())
    }

    fn scroll_text(&mut self, dir: i32) {
        let max_offset = self.max_text_offset() as i64;
        let next = (self.scroll_offset as i64 + dir as i64).clamp(0, max_offset);
        self.scroll_offset = next as usize;
    }

    /// Keep the viewport in range after the underlying content changes — a
    /// search filter shrinking the list, errors rotating out of proxy.log, the
    /// config file being edited, or the terminal being resized.
    fn clamp_scroll(&mut self) {
        if self.scrolls_text() {
            self.scroll_offset = self.scroll_offset.min(self.max_text_offset());
            return;
        }
        let len = self.get_max_selection();
        if len == 0 {
            self.selected_index = 0;
            self.scroll_offset = 0;
            return;
        }
        self.selected_index = self.selected_index.min(len - 1);
        self.scroll_offset = self
            .scroll_offset
            .min(max_offset(len, self.get_visible_height()));
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        }
    }

    fn jump_screen(&mut self, screen: Screen) {
        self.current_screen = screen;
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    /// Returns true when the event changed something worth repainting.
    pub fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) -> bool {
        use crossterm::event::MouseEventKind;
        if self.help_show || self.modal != Modal::None {
            return false;
        }
        match mouse.kind {
            MouseEventKind::Down(_) => {
                if let Some(idx) = theme::nav_at(self.last_sidebar, mouse.column, mouse.row) {
                    let screen = match idx {
                        0 => Screen::Dashboard,
                        1 => Screen::Routes,
                        2 => Screen::Apps,
                        3 => Screen::Circuits,
                        4 => Screen::Errors,
                        5 => Screen::Config,
                        _ => return false,
                    };
                    self.jump_screen(screen);
                    return true;
                }
                // Row 0 of the panel is the title chip and row 1 the column
                // header; data rows start at +2. Clamping instead of offsetting
                // would make a click on the header select the first row.
                let first_row = self.last_body.y.saturating_add(2);
                let past_end = self.last_body.y.saturating_add(self.last_body.height);
                if mouse.row >= first_row && mouse.row < past_end {
                    let rel = (mouse.row - first_row) as usize;
                    let idx = self.scroll_offset + rel;
                    if idx < self.get_max_selection() && idx != self.selected_index {
                        self.selected_index = idx;
                        return true;
                    }
                }
                false
            }
            MouseEventKind::ScrollDown => {
                self.move_selection(1);
                true
            }
            MouseEventKind::ScrollUp => {
                self.move_selection(-1);
                true
            }
            _ => false,
        }
    }

    fn scroll_to_bottom(&mut self) {
        if self.scrolls_text() {
            self.scroll_offset = self.max_text_offset();
            return;
        }
        let max = self.get_max_selection();
        if max > 0 {
            self.selected_index = max - 1;
            self.scroll_offset = max_offset(max, self.get_visible_height());
        }
    }

    fn handle_enter(&mut self) {
        if self.current_screen == Screen::Errors {
            if self.selected_index < self.errors.len() {
                self.error_copied = false;
                self.modal = Modal::ErrorDetail(self.selected_index);
            }
            return;
        }
        if let Screen::Apps = self.current_screen {
            if let Some(ref mgr) = self.ctx.app_manager {
                let all_apps = mgr.list_apps_sync();
                let mut apps: Vec<_> = if self.search_query.is_empty() {
                    all_apps
                } else {
                    let search_lower = self.search_query.to_lowercase();
                    all_apps
                        .into_iter()
                        .filter(|app| {
                            app.config.name.to_lowercase().contains(&search_lower)
                                || app.config.domain.to_lowercase().contains(&search_lower)
                        })
                        .collect()
                };
                apps.sort_by(|a, b| {
                    a.config
                        .name
                        .to_lowercase()
                        .cmp(&b.config.name.to_lowercase())
                });
                if self.selected_index < apps.len() {
                    let app_name = apps[self.selected_index].config.name.clone();
                    self.modal = Modal::AppActionMenu(app_name, 0);
                }
            }
        }
    }

    /// Map the current selected_index to the actual rule index in config,
    /// accounting for search filtering.
    /// Map the on-screen cursor back to an index into `config.rules`.
    /// Uses the same predicate the Routes screen renders with, so `e`/`d`
    /// always act on the row the user is looking at.
    fn resolve_route_index(&self) -> Option<usize> {
        let rules = self.ctx.config_manager.get_config().rules.clone();
        screens::routes::filter_indices(&rules, &self.search_query)
            .get(self.selected_index)
            .copied()
    }

    fn refresh_data(&mut self) {
        // Kick the poller; its next sample lands on a later tick. The local
        // (/proc, log, config) half refreshes synchronously right here.
        self.daemon.request_refresh();
        self.collect_stats();
        self.show_toast("refreshed");
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        match self.current_screen {
            Screen::Dashboard => screens::dashboard::render(
                f,
                area,
                &self.ctx,
                self.remote_snapshot.as_ref(),
                self.daemon_status,
                &self.rps_history,
            ),
            Screen::Routes => screens::routes::render(
                f,
                area,
                &self.ctx,
                self.selected_index,
                self.scroll_offset,
                &self.search_query,
            ),
            Screen::Apps => {
                let all_apps = self
                    .ctx
                    .app_manager
                    .as_ref()
                    .map(|m| m.list_apps_sync())
                    .unwrap_or_default();
                let filtered_count = if self.search_query.is_empty() {
                    all_apps.len()
                } else {
                    let search_lower = self.search_query.to_lowercase();
                    all_apps
                        .into_iter()
                        .filter(|app| {
                            app.config.name.to_lowercase().contains(&search_lower)
                                || app.config.domain.to_lowercase().contains(&search_lower)
                        })
                        .count()
                };
                if self.selected_index >= filtered_count && filtered_count > 0 {
                    self.selected_index = filtered_count - 1;
                }
                self.filtered_apps_count = filtered_count;
                screens::apps::render(
                    f,
                    area,
                    &self.ctx,
                    &screens::apps::AppsView {
                        selected_index: self.selected_index,
                        scroll_offset: self.scroll_offset,
                        search_query: &self.search_query,
                        app_stats: &self.app_stats,
                        app_history: &self.app_history,
                    },
                )
            }
            Screen::Circuits => screens::circuits::render(
                f,
                area,
                &self.ctx,
                self.selected_index,
                self.scroll_offset,
            ),
            Screen::Errors => screens::errors::render(
                f,
                area,
                &self.errors,
                self.selected_index,
                self.scroll_offset,
            ),
            Screen::Config => screens::config_viewer::render(
                f,
                area,
                &self.config_text,
                self.scroll_offset,
                self.config_line_count,
            ),
            Screen::Help => {}
        }
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        if self.search_active {
            let paragraph = Paragraph::new(format!(" / {}_  Esc:cancel", self.search_query))
                .style(Style::default().fg(theme::WARN));
            f.render_widget(paragraph, area);
            return;
        }

        let keys = match self.modal {
            Modal::None => match self.current_screen {
                Screen::Routes => "1-6 nav  j/k  a add  e edit  d delete  /  r  ?  q",
                Screen::Apps => "1-6 nav  j/k  Enter action  /  r  ?  q",
                Screen::Errors => "1-6 nav  j/k  Enter detail  r  ?  q",
                Screen::Circuits => "1-6 nav  j/k  r  ?  q",
                Screen::Config => "1-6 nav  j/k  r  ?  q",
                _ => "1-6 nav  Tab cycle  r  ?  q",
            },
            Modal::RouteForm => "Tab fields  Enter save  Esc cancel",
            Modal::DeleteConfirm(_) => "y confirm  n/Esc cancel",
            Modal::AppActionMenu(_, _) => "j/k  Enter  Esc",
            Modal::AppActionProgress(_, _) => "Esc dismiss (action continues)",
            Modal::AppActionResult(_) => "Esc/Enter close",
            Modal::LogViewer(_, _) => "j/k scroll  G follow  Esc close",
            Modal::ErrorDetail(_) => "j/k  y copy  Esc",
        };

        let daemon = Span::styled(
            self.daemon_status.badge(),
            Style::default().fg(self.daemon_status.color()),
        );
        let spinner = if self.pending_action.is_some() {
            Span::styled(
                format!(" {} ", theme::spinner_frame(self.frame_ticks)),
                Style::default().fg(theme::WARN),
            )
        } else {
            Span::raw("")
        };

        let line = Line::from(vec![
            Span::styled(format!(" {keys} "), Style::default().fg(theme::MUTED)),
            Span::raw("  "),
            spinner,
            daemon,
        ]);
        f.render_widget(Paragraph::new(line).alignment(Alignment::Left), area);
    }

    fn render_help(&self, f: &mut Frame, area: Rect) {
        let modal = theme::centered_modal(area, 64, 22);
        f.render_widget(Clear, modal);
        let help_text = "\
  1-6            Jump to screen     Tab / S-Tab  Cycle
  j/k  PgUp/Dn   Move               g / G        First / last
  /              Search             r            Refresh now
  Enter          Select / open      Esc          Back
  a/e/d          Route add/edit/del
  Mouse          Click nav, click rows, wheel scrolls
  q              Quit

  Apps: Enter → Deploy / Restart / Stop / Rollback / Logs
  Errors: Enter detail · y copy (OSC 52)

  Any key closes this overlay";
        let block = theme::list_block("help");
        f.render_widget(
            Paragraph::new(help_text)
                .block(block)
                .style(Style::default().fg(theme::FG)),
            modal,
        );
    }

    fn render_route_form_modal(&self, f: &mut Frame) {
        let form = match self.route_form.as_ref() {
            Some(f) => f,
            None => return,
        };

        let area = f.area();
        // Dynamic height: base 20 + extra lines for auth entries
        let extra_auth = form.auth_render_height();
        let modal_height = (22 + extra_auth).min(area.height.saturating_sub(2));
        let modal_width = (area.width).clamp(40, 76);
        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_area = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_area);

        let title = if form.edit_index.is_some() {
            " Edit Route "
        } else {
            " Add Route "
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));

        f.render_widget(block, modal_area);

        let inner = Rect::new(
            modal_area.x + 2,
            modal_area.y + 1,
            modal_area.width.saturating_sub(4),
            modal_area.height.saturating_sub(2),
        );

        let field_count = 6;
        let mut y_offset = 0u16;

        for i in 0..field_count {
            if y_offset + 2 > inner.height {
                break;
            }

            let is_active = i == form.active_field;

            let label = form.field_label(i);
            let hint = form.field_hint(i);

            // Label line
            let label_style = if is_active {
                Style::default().fg(Color::Yellow).bold()
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let label_area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
            let label_text = format!("{}: {}", label, hint);
            f.render_widget(Paragraph::new(label_text).style(label_style), label_area);
            y_offset += 1;

            // Auth field: special rendering
            if i == 3 {
                y_offset = self.render_auth_field(f, form, inner, y_offset, is_active);
            } else {
                // Normal value line
                let value = form.field_value(i);
                let value_area = Rect::new(
                    inner.x + 2,
                    inner.y + y_offset,
                    inner.width.saturating_sub(2),
                    1,
                );

                let is_text = !form.is_select_field() || i == 3;
                let display_value = if is_active && is_text {
                    with_cursor(&value, form.cursor_pos)
                } else if value.is_empty() && is_text {
                    "(empty)".to_string()
                } else {
                    value
                };

                let value_style = if is_active {
                    Style::default().fg(Color::White).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::White)
                };

                f.render_widget(Paragraph::new(display_value).style(value_style), value_area);
                y_offset += 1;
            }

            // spacing
            if y_offset < inner.height {
                y_offset += 1;
            }
        }

        // Error message
        if let Some(ref err) = form.error {
            if y_offset < inner.height {
                let err_area = Rect::new(inner.x, inner.y + y_offset, inner.width, 1);
                f.render_widget(
                    Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red).bold()),
                    err_area,
                );
            }
        }

        // Footer hint
        let footer_y = modal_area.y + modal_area.height - 2;
        if footer_y > modal_area.y {
            let hint_area = Rect::new(
                modal_area.x + 2,
                footer_y,
                modal_area.width.saturating_sub(4),
                1,
            );
            f.render_widget(
                Paragraph::new("Tab:next | Shift+Tab:prev | Enter:save | Esc:cancel")
                    .style(Style::default().fg(Color::DarkGray)),
                hint_area,
            );
        }
    }

    /// Render the Auth field with user list and add-credential inputs.
    /// Returns the updated y_offset after rendering.
    fn render_auth_field(
        &self,
        f: &mut Frame,
        form: &RouteForm,
        inner: Rect,
        mut y_offset: u16,
        is_active: bool,
    ) -> u16 {
        use super::route_form::AuthMode;

        let indent = inner.x + 2;
        let w = inner.width.saturating_sub(2);

        // Show existing users
        if form.auth_list.is_empty() && form.auth_mode == AuthMode::List {
            let area = Rect::new(indent, inner.y + y_offset, w, 1);
            let style = if is_active {
                Style::default().fg(Color::DarkGray).bg(Color::DarkGray)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            f.render_widget(Paragraph::new("(no credentials)").style(style), area);
            y_offset += 1;
        } else {
            for (idx, entry) in form.auth_list.iter().enumerate() {
                if inner.y + y_offset >= inner.y + inner.height {
                    break;
                }
                let area = Rect::new(indent, inner.y + y_offset, w, 1);
                let is_selected =
                    is_active && form.auth_mode == AuthMode::List && idx == form.auth_selected;

                let prefix = if is_selected { "> " } else { "  " };
                let text = format!("{}{}", prefix, entry.username);

                let style = if is_selected {
                    Style::default().fg(Color::White).bg(Color::Blue)
                } else if is_active {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };

                f.render_widget(Paragraph::new(text).style(style), area);
                y_offset += 1;
            }
        }

        // Add-credential sub-form
        match form.auth_mode {
            AuthMode::AddUsername => {
                if inner.y + y_offset < inner.y + inner.height {
                    let area = Rect::new(indent, inner.y + y_offset, w, 1);
                    let display = format!(
                        "  Username: {}",
                        with_cursor(&form.auth_new_username, form.cursor_pos)
                    );
                    f.render_widget(
                        Paragraph::new(display)
                            .style(Style::default().fg(Color::White).bg(Color::DarkGray)),
                        area,
                    );
                    y_offset += 1;
                }
            }
            AuthMode::AddPassword => {
                // Show username (confirmed)
                if inner.y + y_offset < inner.y + inner.height {
                    let area = Rect::new(indent, inner.y + y_offset, w, 1);
                    let text = format!("  Username: {}", form.auth_new_username);
                    f.render_widget(
                        Paragraph::new(text).style(Style::default().fg(Color::Green)),
                        area,
                    );
                    y_offset += 1;
                }
                // Password input (masked)
                if inner.y + y_offset < inner.y + inner.height {
                    let area = Rect::new(indent, inner.y + y_offset, w, 1);
                    let masked: String = "\u{2022}".repeat(form.auth_new_password.len());
                    let display = format!("  Password: {}", with_cursor(&masked, form.cursor_pos));
                    f.render_widget(
                        Paragraph::new(display)
                            .style(Style::default().fg(Color::White).bg(Color::DarkGray)),
                        area,
                    );
                    y_offset += 1;
                }
            }
            AuthMode::List => {}
        }

        y_offset
    }

    fn render_delete_confirm(&self, f: &mut Frame, idx: usize) {
        let rules = &self.ctx.config_manager.get_config().rules;
        if idx >= rules.len() {
            return;
        }

        let rule = &rules[idx];
        let matcher_str = format!("{:?}", rule.matcher);

        let area = f.area();
        let w = 54u16.min(area.width.saturating_sub(4));
        let h = 8u16.min(area.height.saturating_sub(4));
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let block = Block::default()
            .title(" Confirm Delete ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));

        let text = Paragraph::new(format!(
            "\nDelete route #{} ?\n\nMatcher: {}\n\n(y)es / (n)o",
            idx + 1,
            matcher_str
        ))
        .block(block)
        .alignment(Alignment::Center);

        f.render_widget(text, modal_area);
    }

    fn render_app_action_menu(&self, f: &mut Frame, app_name: &str, selected: usize) {
        let area = f.area();
        let h = (APP_ACTIONS.len() as u16 + 4).min(area.height.saturating_sub(4));
        let w = 40u16.min(area.width.saturating_sub(4));
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let block = Block::default()
            .title(format!(" {} ", app_name))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));
        f.render_widget(block, modal_area);

        let inner = Rect::new(
            modal_area.x + 3,
            modal_area.y + 1,
            modal_area.width.saturating_sub(6),
            modal_area.height.saturating_sub(2),
        );

        for (i, action) in APP_ACTIONS.iter().enumerate() {
            if i as u16 >= inner.height {
                break;
            }
            let is_sel = i == selected;
            let prefix = if is_sel { "> " } else { "  " };
            let style = if is_sel {
                Style::default().fg(Color::White).bg(Color::Blue).bold()
            } else {
                Style::default().fg(Color::White)
            };
            let row_area = Rect::new(inner.x, inner.y + i as u16, inner.width, 1);
            f.render_widget(
                Paragraph::new(format!("{}{}", prefix, action)).style(style),
                row_area,
            );
        }

        let hint_y = modal_area.y + modal_area.height - 2;
        if hint_y > modal_area.y + 1 {
            let hint_area = Rect::new(
                modal_area.x + 2,
                hint_y,
                modal_area.width.saturating_sub(4),
                1,
            );
            f.render_widget(
                Paragraph::new("j/k:move  Enter:confirm  Esc:cancel")
                    .style(Style::default().fg(Color::DarkGray)),
                hint_area,
            );
        }
    }

    fn render_app_action_result(&self, f: &mut Frame, msg: &str) {
        let area = f.area();
        let w = 50u16.min(area.width.saturating_sub(4));
        let h = 6u16.min(area.height.saturating_sub(4));
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let is_error = msg.starts_with("Error:");
        let border_color = if is_error { Color::Red } else { Color::Green };

        let block = Block::default()
            .title(" Result ")
            .borders(Borders::ALL)
            .style(Style::default().fg(border_color));

        let text = Paragraph::new(format!("\n{}\n\nPress Esc to close", msg))
            .block(block)
            .alignment(Alignment::Center);

        f.render_widget(text, modal_area);
    }

    fn render_log_viewer(&mut self, f: &mut Frame, app_name: &str, slot: &str) {
        let log_path = format!("./run/logs/{}/{}.log", app_name, slot);
        let log_content = tail_file(&log_path, 256 * 1024);

        let lines: Vec<&str> = log_content.lines().collect();
        let total_lines = lines.len();

        let area = f.area();
        let w = area.width.saturating_sub(6);
        let h = area.height.saturating_sub(6);
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let modal_area = Rect::new(x, y, w, h);

        f.render_widget(Clear, modal_area);

        let visible_height = h.saturating_sub(2) as usize;
        let max_offset = total_lines.saturating_sub(visible_height);
        self.log_viewer_page = visible_height.max(1);
        self.log_viewer_max_offset = max_offset;

        if self.log_auto_follow {
            self.scroll_offset = 0;
        } else if self.scroll_offset > max_offset {
            self.scroll_offset = max_offset;
        }

        let start = total_lines.saturating_sub(self.scroll_offset + visible_height);
        let end = total_lines.saturating_sub(self.scroll_offset);
        let start = start.min(total_lines);
        let end = end.min(total_lines);
        let visible_lines: Vec<String> = lines[start..end].iter().map(|s| s.to_string()).collect();
        let display_text = visible_lines.join("\n");

        let follow_label = if self.log_auto_follow {
            "[FOLLOW]".to_string()
        } else {
            "[PAUSED - G to resume]".to_string()
        };
        let block = Block::default()
            .title(format!(
                " Logs: {} ({}) {} {}/{} [j/k PgUp/PgDn g/G, Esc:close] ",
                app_name,
                slot,
                follow_label,
                start + 1,
                total_lines
            ))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(colorize_log(&display_text)).block(block);

        f.render_widget(paragraph, modal_area);
    }
}

/// Last `max_bytes` of a log file, as text.
///
/// Reads bytes rather than a `String`: seeking to a byte offset can land
/// mid-codepoint, and a single non-UTF-8 byte anywhere in the file would make
/// `read_to_string` fail — leaving the viewer blank with no explanation.
fn tail_file(path: &str, max_bytes: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return format!("Cannot read {path}: {e}"),
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let truncated = len > max_bytes;
    if truncated {
        let _ = file.seek(SeekFrom::Start(len - max_bytes));
    }
    let mut bytes = Vec::new();
    if let Err(e) = file.read_to_end(&mut bytes) {
        return format!("Cannot read {path}: {e}");
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        // Drop the partial first line left by the seek.
        match text.find('\n') {
            Some(i) => text.replace_range(..=i, ""),
            None => text.clear(),
        }
    }
    text
}

fn colorize_log(text: &str) -> ratatui::text::Text<'static> {
    use ratatui::text::{Line, Span, Text};
    let lines: Vec<Line> = text
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            let style = if lower.contains("error") || lower.contains("fatal") {
                Style::default().fg(theme::DANGER)
            } else if lower.contains("warn") {
                Style::default().fg(theme::WARN)
            } else {
                Style::default().fg(theme::FG)
            };
            Line::from(Span::styled(line.to_string(), style))
        })
        .collect();
    Text::from(lines)
}

/// Copy `text` to the terminal clipboard via the OSC52 escape sequence. Works
/// locally and over SSH without any display server or extra dependency. Note:
/// tmux requires `set -g set-clipboard on` to forward the sequence.
fn copy_to_clipboard_osc52(text: &str) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::io::Write;
    let payload = STANDARD.encode(text.as_bytes());
    let mut out = std::io::stdout();
    // ratatui owns the alternate screen, but the escape still reaches the
    // emulator. Flush so it isn't left in the buffer until the next redraw.
    let _ = write!(out, "\x1b]52;c;{}\x07", payload);
    let _ = out.flush();
}

/// Parse the daemon's Prometheus text exposition into a `MetricsSnapshot`.
fn parse_prometheus_snapshot(text: &str) -> MetricsSnapshot {
    let mut snap = MetricsSnapshot {
        requests_total: 0,
        requests_in_flight: 0,
        bytes_received: 0,
        bytes_sent: 0,
        errors_total: 0,
        tls_connections: 0,
        avg_response_time_ms: 0.0,
        status_2xx: 0,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
    };

    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };

        match name {
            "proxy_requests_total" => snap.requests_total = value as u64,
            "proxy_requests_in_flight" => snap.requests_in_flight = value as usize,
            "proxy_bytes_received" => snap.bytes_received = value as u64,
            "proxy_bytes_sent" => snap.bytes_sent = value as u64,
            "proxy_response_time_seconds" => snap.avg_response_time_ms = value * 1000.0,
            "proxy_tls_connections_total" => snap.tls_connections = value as u64,
            "proxy_errors_total" => snap.errors_total = value as u64,
            _ => {
                // proxy_response_status_codes_total{code="200"} 432
                if let Some(code) = name
                    .strip_prefix("proxy_response_status_codes_total{code=\"")
                    .and_then(|s| s.strip_suffix("\"}"))
                {
                    match code.chars().next() {
                        Some('2') => snap.status_2xx += value as u64,
                        Some('3') => snap.status_3xx += value as u64,
                        Some('4') => snap.status_4xx += value as u64,
                        Some('5') => snap.status_5xx += value as u64,
                        _ => {}
                    }
                }
            }
        }
    }

    snap
}

fn with_cursor(text: &str, cursor_pos: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let pos = cursor_pos.min(chars.len());
    let mut display = String::new();
    for (i, ch) in chars.iter().enumerate() {
        if i == pos {
            display.push('|');
        }
        display.push(*ch);
    }
    if pos >= chars.len() {
        display.push('|');
    }
    display
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prometheus_snapshot_extracts_all_fields() {
        let text = "\
# HELP proxy_requests_total Total number of HTTP requests
# TYPE proxy_requests_total counter
proxy_requests_total 446
proxy_requests_in_flight 34
proxy_bytes_received 1024
proxy_bytes_sent 2048
proxy_response_time_seconds 0.012381441365470853
proxy_tls_connections_total 1345
proxy_errors_total 34
proxy_response_status_codes_total{code=\"200\"} 432
proxy_response_status_codes_total{code=\"301\"} 5
proxy_response_status_codes_total{code=\"421\"} 2
proxy_response_status_codes_total{code=\"500\"} 6
proxy_response_status_codes_total{code=\"502\"} 6
";
        let snap = parse_prometheus_snapshot(text);
        assert_eq!(snap.requests_total, 446);
        assert_eq!(snap.requests_in_flight, 34);
        assert_eq!(snap.bytes_received, 1024);
        assert_eq!(snap.bytes_sent, 2048);
        assert!((snap.avg_response_time_ms - 12.381441365470853).abs() < 1e-9);
        assert_eq!(snap.tls_connections, 1345);
        assert_eq!(snap.errors_total, 34);
        assert_eq!(snap.status_2xx, 432);
        assert_eq!(snap.status_3xx, 5);
        assert_eq!(snap.status_4xx, 2);
        assert_eq!(snap.status_5xx, 12);
    }

    #[test]
    fn parse_prometheus_snapshot_handles_empty_input() {
        let snap = parse_prometheus_snapshot("");
        assert_eq!(snap.requests_total, 0);
        assert_eq!(snap.avg_response_time_ms, 0.0);
    }

    #[test]
    fn max_offset_keeps_the_last_page_full() {
        // 100 rows in a 20-row viewport: the last page starts at 80, not 99.
        assert_eq!(max_offset(100, 20), 80);
        // Everything fits: never scroll.
        assert_eq!(max_offset(5, 20), 0);
        assert_eq!(max_offset(0, 20), 0);
        // A degenerate viewport must not divide by / subtract zero.
        assert_eq!(max_offset(10, 0), 9);
    }

    #[test]
    fn tail_file_reports_missing_and_unreadable_files() {
        let text = tail_file("/definitely/not/a/log/file.log", 1024);
        assert!(text.starts_with("Cannot read"), "{text}");
    }

    #[test]
    fn tail_file_survives_non_utf8_bytes() {
        let dir = std::env::temp_dir().join("soli-tail-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.log");
        // An invalid UTF-8 byte used to make read_to_string fail, leaving the
        // log viewer blank with no indication why.
        std::fs::write(&path, b"first line\n\xffsecond line\n").unwrap();

        let text = tail_file(path.to_str().unwrap(), 1024);
        assert!(text.contains("first line"), "{text}");
        assert!(text.contains("second line"), "{text}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tail_file_drops_the_partial_first_line() {
        let dir = std::env::temp_dir().join("soli-tail-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("long.log");
        std::fs::write(&path, "aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n").unwrap();

        // 16 bytes back lands mid-way through the "bbb" line.
        let text = tail_file(path.to_str().unwrap(), 16);
        assert!(!text.contains("aaaa"), "{text}");
        assert!(text.starts_with("cccccccccc"), "{text}");
        let _ = std::fs::remove_file(&path);
    }
}
