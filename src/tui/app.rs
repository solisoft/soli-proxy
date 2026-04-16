use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use std::collections::{HashMap, VecDeque};

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

const HISTORY_LEN: usize = 60; // 60 samples × 2s = 2 minutes

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    Routes,
    Apps,
    Circuits,
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
}

const APP_ACTIONS: &[&str] = &["Deploy", "Restart", "Stop", "Rollback", "View Logs"];

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
    pending_action: Option<tokio::task::JoinHandle<Result<String, String>>>,
    filtered_apps_count: usize,
}

impl TuiApp {
    pub fn new(ctx: TuiContext) -> Self {
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
            pending_action: None,
            filtered_apps_count: 0,
        };
        app.collect_stats();
        app
    }

    /// Collect all per-app stats: traffic from admin API + system from /proc.
    fn collect_stats(&mut self) {
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

            // Start with empty stats (no API calls)
            let mut stats = AppStats::default();

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
    }

    /// Called on each tick (auto-refresh).
    pub fn on_tick(&mut self) {
        // Reload app state from disk to see deploys that happened via API
        if let Some(ref mgr) = self.ctx.app_manager {
            mgr.load_app_state();
        }
        self.collect_stats();
        self.check_pending_action();
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
            Ok(Ok(_msg)) => {
                // Re-probe after action to update status
                if let Some(ref mgr) = self.ctx.app_manager {
                    mgr.probe_running_apps();
                }
                // Clear the progress modal silently on success
                self.modal = Modal::None;
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
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(size);

        self.render_header(f, chunks[0]);

        if self.help_show {
            self.render_help(f, chunks[1]);
        } else {
            self.render_main(f, chunks[1]);
        }

        self.render_footer(f, chunks[2]);

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
            Modal::LogViewer(app_name, slot) => self.render_log_viewer(f, app_name, slot),
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
            KeyCode::Char('a') => {
                if self.current_screen == Screen::Routes {
                    self.route_form = Some(RouteForm::new_empty());
                    self.modal = Modal::RouteForm;
                }
            }
            KeyCode::Char('d') => {
                if self.current_screen == Screen::Routes {
                    if let Some(rule_idx) = self.resolve_route_index() {
                        self.modal = Modal::DeleteConfirm(rule_idx);
                    }
                }
            }
            KeyCode::Char('e') => {
                if self.current_screen == Screen::Routes {
                    if let Some(rule_idx) = self.resolve_route_index() {
                        let rules = &self.ctx.config_manager.get_config().rules;
                        if rule_idx < rules.len() {
                            self.route_form =
                                Some(RouteForm::from_rule(&rules[rule_idx], rule_idx));
                            self.modal = Modal::RouteForm;
                        }
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
                KeyCode::BackTab => {
                    if form.auth_mode == super::route_form::AuthMode::AddPassword {
                        form.auth_mode = super::route_form::AuthMode::AddUsername;
                        form.cursor_pos = form.auth_new_username.len();
                    }
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
            KeyCode::Char(c) => {
                if !form.is_select_field() {
                    form.insert_char(c);
                }
            }
            KeyCode::Backspace => {
                if !form.is_select_field() {
                    form.delete_char();
                }
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
        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_offset += 1;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::Char('g') => {
                self.scroll_offset = 0;
            }
            KeyCode::Char('G') => {
                self.scroll_to_bottom();
            }
            _ => {}
        }
        false
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
                    Screen::Config
                } else {
                    Screen::Apps
                }
            }
            Screen::Config => {
                if dir > 0 {
                    Screen::Dashboard
                } else {
                    Screen::Circuits
                }
            }
            Screen::Help => Screen::Dashboard,
        };
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    fn move_selection(&mut self, dir: i32) {
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
            Screen::Routes => self.ctx.config_manager.get_config().rules.len(),
            Screen::Apps => self.filtered_apps_count,
            Screen::Circuits => self.ctx.circuit_breaker.get_states().len(),
            Screen::Config => 0,
            Screen::Help => 0,
        }
    }

    fn get_visible_height(&self) -> usize {
        20
    }

    fn scroll_to_bottom(&mut self) {
        let max = self.get_max_selection();
        if max > 0 {
            self.scroll_offset = max.saturating_sub(1);
            self.selected_index = max - 1;
        }
    }

    fn handle_enter(&mut self) {
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
    fn resolve_route_index(&self) -> Option<usize> {
        let rules = self.ctx.config_manager.get_config().rules.clone();
        if self.search_query.is_empty() {
            if self.selected_index < rules.len() {
                Some(self.selected_index)
            } else {
                None
            }
        } else {
            let search_lower = self.search_query.to_lowercase();
            let filtered: Vec<usize> = rules
                .iter()
                .enumerate()
                .filter(|(idx, rule)| {
                    let matcher_str = format!("{:?}", rule.matcher).to_lowercase();
                    let targets_str: String = rule
                        .targets
                        .iter()
                        .map(|t| t.url.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let auth_str: String = rule
                        .auth
                        .iter()
                        .map(|a| a.username.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let scripts_str = rule.scripts.join(", ");
                    matcher_str.contains(&search_lower)
                        || targets_str.to_lowercase().contains(&search_lower)
                        || auth_str.to_lowercase().contains(&search_lower)
                        || scripts_str.to_lowercase().contains(&search_lower)
                        || idx.to_string() == search_lower
                })
                .map(|(idx, _)| idx)
                .collect();
            filtered.get(self.selected_index).copied()
        }
    }

    fn refresh_data(&mut self) {}

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let screen_names = ["Dashboard", "Routes", "Apps", "Circuits", "Config"];
        let current_idx = match self.current_screen {
            Screen::Dashboard => 0,
            Screen::Routes => 1,
            Screen::Apps => 2,
            Screen::Circuits => 3,
            Screen::Config => 4,
            Screen::Help => return,
        };

        let mut header_text = String::new();
        for (i, name) in screen_names.iter().enumerate() {
            if i == current_idx {
                header_text.push_str(&format!("[ {} ] ", name));
            } else {
                header_text.push_str(&format!("  {}   ", name));
            }
        }

        let paragraph = Paragraph::new(header_text)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        f.render_widget(paragraph, area);
    }

    fn render_main(&mut self, f: &mut Frame, area: Rect) {
        match self.current_screen {
            Screen::Dashboard => screens::dashboard::render(f, area, &self.ctx),
            Screen::Routes => {
                screens::routes::render(f, area, &self.ctx, self.selected_index, &self.search_query)
            }
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
            Screen::Circuits => screens::circuits::render(f, area, &self.ctx, self.selected_index),
            Screen::Config => screens::config_viewer::render(f, area, &self.ctx),
            Screen::Help => {}
        }
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let mut footer_text = String::new();
        footer_text.push_str(
            " q:quit | ?:help | /:search | r:refresh | j/k:move | Tab:cycle | Enter:select",
        );
        if self.current_screen == Screen::Routes {
            footer_text.push_str(" | a:add | e:edit | d:delete");
        }

        if self.search_active {
            footer_text = format!("Search: {}_", self.search_query);
        }

        let paragraph = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Left);
        f.render_widget(paragraph, area);
    }

    fn render_help(&self, f: &mut Frame, area: Rect) {
        let help_text = vec![
            "",
            "  SOLI PROXY TUI - HELP",
            "  =====================",
            "",
            "  NAVIGATION",
            "    j / Down       Move down",
            "    k / Up         Move up",
            "    g              Go to first item",
            "    G              Go to last item",
            "    Tab            Next screen",
            "    Shift+Tab      Previous screen",
            "    Enter          Select / Open",
            "    Esc            Go back / Clear",
            "",
            "  ACTIONS",
            "    q              Quit",
            "    ?              Toggle this help",
            "    /              Search filter",
            "    r              Refresh data",
            "",
            "  ROUTES SCREEN",
            "    a              Add new route",
            "    e              Edit selected route",
            "    d              Delete selected route",
            "",
            "  ROUTE FORM",
            "    Tab/Shift+Tab  Navigate fields",
            "    Left/Right     Change select options",
            "    Enter          Save route",
            "    Esc            Cancel",
            "",
            "  APPS SCREEN",
            "    Enter          Open action menu",
            "                   (Deploy/Restart/Stop/Rollback/Logs)",
            "",
            "  Press any key to close this help",
        ];

        let block = Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(help_text.join("\n"))
            .block(block)
            .style(Style::default().fg(Color::White));
        f.render_widget(paragraph, area);
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

    fn render_log_viewer(&self, f: &mut Frame, app_name: &str, slot: &str) {
        let log_path = format!("./run/logs/{}/{}.log", app_name, slot);
        let log_content =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "No log file found.".to_string());

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
        let start = self.scroll_offset.min(total_lines.saturating_sub(1));
        let end = (start + visible_height).min(total_lines);
        let visible_lines: Vec<String> = lines[start..end].iter().map(|s| s.to_string()).collect();
        let display_text = visible_lines.join("\n");

        let block = Block::default()
            .title(format!(
                " Logs: {} ({}) [{}/{}] [j/k:scroll, Esc:close] ",
                app_name,
                slot,
                start + 1,
                total_lines
            ))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(display_text).block(block);

        f.render_widget(paragraph, modal_area);
    }
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
