use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::metrics::MetricsSnapshot;
use crate::tui::TuiContext;

/// `remote_snap` carries traffic counters fetched from the daemon's admin
/// API; the TUI's own metrics registry is empty (separate process), so it
/// is only used as a fallback when the daemon is unreachable.
pub fn render(f: &mut Frame, area: Rect, ctx: &TuiContext, remote_snap: Option<&MetricsSnapshot>) {
    let local_snap = ctx.metrics.snapshot();
    let snap = remote_snap.unwrap_or(&local_snap);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Server + Traffic
            Constraint::Length(8),  // Resources + Status codes
            Constraint::Min(4),     // Apps / Circuits
        ])
        .split(area);

    // Row 1: Server Info | Traffic
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);

    render_server_info(f, top_cols[0], ctx);
    render_traffic(f, top_cols[1], snap);

    // Row 2: Resources | Status Codes
    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    render_resources(f, mid_cols[0], ctx);
    render_status_codes(f, mid_cols[1], snap);

    // Row 3: Apps quick view
    render_apps_overview(f, rows[2], ctx);
}

fn render_server_info(f: &mut Frame, area: Rect, ctx: &TuiContext) {
    let cfg = ctx.config_manager.get_config();
    let uptime = ctx.uptime();

    let block = Block::default()
        .title(" Server ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = inner_area(area);

    let uptime_str = format_uptime(uptime);
    let tls_str = if cfg.tls.mode.is_empty() || cfg.tls.mode == "disabled" {
        "disabled".to_string()
    } else {
        cfg.tls.mode.clone()
    };

    let admin_str = if cfg.admin.enabled.unwrap_or(true) {
        cfg.admin.bind.clone()
    } else {
        "disabled".to_string()
    };

    let rows = vec![
        kv_row(
            "",
            format!("Soli Proxy v{}", env!("CARGO_PKG_VERSION")),
            Color::Green,
        ),
        kv_row("Listen", cfg.server.bind.clone(), Color::White),
        kv_row("HTTPS", format!(":{}", cfg.server.https_port), Color::White),
        kv_row("TLS", tls_str, Color::White),
        kv_row("Admin", admin_str, Color::White),
        kv_row(
            "Auth",
            if ctx.auth_required { "enabled" } else { "-" }.to_string(),
            Color::White,
        ),
        kv_row("Uptime", uptime_str, Color::Yellow),
    ];

    let table = Table::new(rows, [Constraint::Length(10), Constraint::Min(10)]);
    f.render_widget(table, inner);
}

fn render_traffic(f: &mut Frame, area: Rect, snap: &MetricsSnapshot) {
    let block = Block::default()
        .title(" Traffic ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = inner_area(area);

    let error_str = if snap.requests_total > 0 && snap.errors_total > 0 {
        format!(
            "{} ({:.2}%)",
            format_number(snap.errors_total),
            (snap.errors_total as f64 / snap.requests_total as f64) * 100.0
        )
    } else {
        format_number(snap.errors_total)
    };

    let resp_time_str = if snap.avg_response_time_ms > 0.0 {
        if snap.avg_response_time_ms >= 1000.0 {
            format!("{:.2} s", snap.avg_response_time_ms / 1000.0)
        } else {
            format!("{:.1} ms", snap.avg_response_time_ms)
        }
    } else {
        "-".to_string()
    };

    let error_color = if snap.errors_total > 0 {
        Color::Red
    } else {
        Color::Green
    };

    let rows = vec![
        kv_row("Requests", format_number(snap.requests_total), Color::Cyan),
        kv_row(
            "In Flight",
            format_number(snap.requests_in_flight as u64),
            Color::Cyan,
        ),
        kv_row("Avg Resp", resp_time_str, Color::Cyan),
        kv_row("Bytes In", format_bytes(snap.bytes_received), Color::Cyan),
        kv_row("Bytes Out", format_bytes(snap.bytes_sent), Color::Cyan),
        kv_row(
            "TLS Conns",
            format_number(snap.tls_connections),
            Color::Cyan,
        ),
        kv_row("Errors", error_str, error_color),
    ];

    let table = Table::new(rows, [Constraint::Length(12), Constraint::Min(10)]);
    f.render_widget(table, inner);
}

fn render_resources(f: &mut Frame, area: Rect, ctx: &TuiContext) {
    let cfg = ctx.config_manager.get_config();

    let block = Block::default()
        .title(" Resources ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = inner_area(area);

    let apps = ctx
        .app_manager
        .as_ref()
        .map(|m| m.list_apps_sync())
        .unwrap_or_default();

    let running = apps
        .iter()
        .filter(|a| {
            let inst = if a.current_slot == "blue" {
                &a.blue
            } else {
                &a.green
            };
            matches!(inst.status, crate::app::InstanceStatus::Running)
        })
        .count();

    let apps_str = if apps.is_empty() {
        "-".to_string()
    } else {
        format!("{} ({} running)", apps.len(), running)
    };

    let circuits = ctx.circuit_breaker.get_states();
    let open = circuits.values().filter(|s| s.state == "open").count();
    let half = circuits.values().filter(|s| s.state == "half_open").count();

    let circuits_str = if circuits.is_empty() {
        "none".to_string()
    } else if open == 0 && half == 0 {
        format!("{} (all healthy)", circuits.len())
    } else {
        let mut parts = vec![format!("{} total", circuits.len())];
        if open > 0 {
            parts.push(format!("{} open", open));
        }
        if half > 0 {
            parts.push(format!("{} half-open", half));
        }
        parts.join(", ")
    };

    let circuits_color = if open > 0 {
        Color::Red
    } else if half > 0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let scripts_str = if cfg.global_scripts.is_empty() {
        "-".to_string()
    } else {
        cfg.global_scripts.join(", ")
    };

    let rows = vec![
        kv_row("Routes", cfg.rules.len().to_string(), Color::White),
        kv_row("Apps", apps_str, Color::White),
        kv_row("Scripts", scripts_str, Color::Magenta),
        Row::new(vec![
            Cell::from("Circuits").style(Style::default().fg(Color::DarkGray)),
            Cell::from(circuits_str).style(Style::default().fg(circuits_color)),
        ]),
    ];

    let table = Table::new(rows, [Constraint::Length(10), Constraint::Min(10)]);
    f.render_widget(table, inner);
}

fn render_status_codes(f: &mut Frame, area: Rect, snap: &MetricsSnapshot) {
    let block = Block::default()
        .title(" HTTP Status ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = inner_area(area);

    let total = snap.status_2xx + snap.status_3xx + snap.status_4xx + snap.status_5xx;

    if total == 0 {
        let text = Paragraph::new("No requests yet.").style(Style::default().fg(Color::DarkGray));
        f.render_widget(text, inner);
        return;
    }

    let bar_width = inner.width.saturating_sub(18) as usize;

    let rows = vec![
        status_row("2xx", snap.status_2xx, total, bar_width, Color::Green),
        status_row("3xx", snap.status_3xx, total, bar_width, Color::Blue),
        status_row("4xx", snap.status_4xx, total, bar_width, Color::Yellow),
        status_row("5xx", snap.status_5xx, total, bar_width, Color::Red),
    ];

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Min(8),
        ],
    );
    f.render_widget(table, inner);
}

fn render_apps_overview(f: &mut Frame, area: Rect, ctx: &TuiContext) {
    let block = Block::default()
        .title(" Applications ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = inner_area(area);

    let apps = ctx
        .app_manager
        .as_ref()
        .map(|m| m.list_apps_sync())
        .unwrap_or_default();

    if apps.is_empty() {
        let text =
            Paragraph::new("No apps discovered.").style(Style::default().fg(Color::DarkGray));
        f.render_widget(text, inner);
        return;
    }

    let header = Row::new(vec!["Name", "Domain", "Slot", "Status", "Port"])
        .style(Style::default().fg(Color::DarkGray).bold());

    let max_rows = inner.height.saturating_sub(1) as usize;

    let rows: Vec<Row> = apps
        .iter()
        .take(max_rows)
        .map(|app| {
            let inst = if app.current_slot == "blue" {
                &app.blue
            } else {
                &app.green
            };

            let (status_str, status_color) = match inst.status {
                crate::app::InstanceStatus::Running => ("Running", Color::Green),
                crate::app::InstanceStatus::Starting => ("Starting", Color::Yellow),
                crate::app::InstanceStatus::Stopped => ("Stopped", Color::DarkGray),
                crate::app::InstanceStatus::Unhealthy => ("Unhealthy", Color::Red),
                crate::app::InstanceStatus::Failed => ("Failed", Color::Red),
            };

            let port_str = if inst.port > 0 {
                format!(":{}", inst.port)
            } else {
                "-".to_string()
            };

            Row::new(vec![
                Cell::from(app.config.name.clone()).style(Style::default().fg(Color::White)),
                Cell::from(app.config.domain.clone()).style(Style::default().fg(Color::White)),
                Cell::from(app.current_slot.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(status_str).style(Style::default().fg(status_color)),
                Cell::from(port_str).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let overflow = apps.len().saturating_sub(max_rows);

    let table = Table::new(
        std::iter::once(header).chain(rows),
        [
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);

    if overflow > 0 {
        let hint = format!(" +{} more (see Apps tab) ", overflow);
        let hint_len = hint.len() as u16;
        if area.width > hint_len + 2 {
            let hint_area = Rect::new(area.x + area.width - hint_len - 1, area.y, hint_len, 1);
            f.render_widget(
                Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
                hint_area,
            );
        }
    }
}

// ── helpers ────────────────────────────────────────────

fn inner_area(area: Rect) -> Rect {
    Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    )
}

fn kv_row(label: &str, value: String, value_color: Color) -> Row<'static> {
    Row::new(vec![
        Cell::from(label.to_string()).style(Style::default().fg(Color::DarkGray)),
        Cell::from(value).style(Style::default().fg(value_color)),
    ])
}

fn status_row(label: &str, count: u64, total: u64, bar_width: usize, color: Color) -> Row<'static> {
    let pct = if total > 0 {
        (count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
    let bar: String = "\u{2588}".repeat(filled);

    Row::new(vec![
        Cell::from(label.to_string()).style(Style::default().fg(color).bold()),
        Cell::from(format_number(count)).style(Style::default().fg(Color::White)),
        Cell::from(bar).style(Style::default().fg(color)),
    ])
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_uptime(uptime: std::time::Duration) -> String {
    let secs = uptime.as_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, s)
    } else if mins > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", s)
    }
}
