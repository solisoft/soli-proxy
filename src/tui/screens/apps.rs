use std::collections::HashMap;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
    Frame,
};

use crate::tui::app::{AppHistory, AppStats};
use crate::tui::TuiContext;

pub struct AppsView<'a> {
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub search_query: &'a str,
    pub app_stats: &'a HashMap<String, AppStats>,
    pub app_history: &'a HashMap<String, AppHistory>,
}

pub fn render(f: &mut Frame, area: Rect, ctx: &TuiContext, view: &AppsView) {
    let all_apps = if let Some(ref mgr) = ctx.app_manager {
        mgr.list_apps_sync()
    } else {
        Vec::new()
    };

    if all_apps.is_empty() {
        let block = Block::default()
            .title(" Applications ")
            .borders(Borders::ALL);
        f.render_widget(block, area);
        let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);
        let msg = if ctx.app_manager.is_none() {
            "App manager not available. Check sites/ directory."
        } else {
            "No apps discovered. Apps are auto-discovered from the sites/ directory."
        };
        f.render_widget(Paragraph::new(msg), inner);
        return;
    }

    let total_count = all_apps.len();
    let mut apps: Vec<_> = if view.search_query.is_empty() {
        all_apps
    } else {
        let search_lower = view.search_query.to_lowercase();
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

    if apps.is_empty() && total_count > 0 {
        let block = Block::default()
            .title(format!(
                " Applications (no match for '{}') ",
                view.search_query
            ))
            .borders(Borders::ALL);
        f.render_widget(block, area);
        let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);
        f.render_widget(Paragraph::new("No apps match your search."), inner);
        return;
    }

    let has_detail = view.selected_index < apps.len();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_detail {
            vec![Constraint::Min(6), Constraint::Length(10)]
        } else {
            vec![Constraint::Min(6), Constraint::Length(0)]
        })
        .split(area);

    render_app_table(
        f,
        chunks[0],
        &apps,
        view.selected_index,
        view.scroll_offset,
        view.app_stats,
    );

    if has_detail {
        let app = &apps[view.selected_index];
        let stats = view.app_stats.get(&app.config.name);
        let history = view.app_history.get(&app.config.name);
        render_app_detail(f, chunks[1], app, stats, history);
    }
}

fn render_app_table(
    f: &mut Frame,
    area: Rect,
    apps: &[crate::app::AppInfo],
    selected_index: usize,
    scroll_offset: usize,
    app_stats: &HashMap<String, AppStats>,
) {
    let block = Block::default()
        .title(" Applications ")
        .borders(Borders::ALL);
    f.render_widget(block, area);

    let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);

    let header = Row::new(vec![
        "Name", "Domain", "Status", "CPU", "Memory", "Reqs", "Errors", "Avg RT",
    ])
    .style(Style::default().fg(Color::Green).bold());

    let max_rows = inner.height.saturating_sub(1) as usize;

    let rows: Vec<Row> = apps
        .iter()
        .skip(scroll_offset)
        .take(max_rows)
        .enumerate()
        .map(|(idx, app)| {
            let visual_idx = scroll_offset + idx;
            let is_selected = visual_idx == selected_index;
            let inst = if app.current_slot == "blue" {
                &app.blue
            } else {
                &app.green
            };

            let status_color = match inst.status {
                crate::app::InstanceStatus::Running => Color::Green,
                crate::app::InstanceStatus::Starting => Color::Yellow,
                crate::app::InstanceStatus::Stopped => Color::DarkGray,
                crate::app::InstanceStatus::Unhealthy => Color::Red,
                crate::app::InstanceStatus::Failed => Color::Red,
            };

            let style = if is_selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            let s = app_stats.get(&app.config.name);

            let cpu = s
                .and_then(|s| s.cpu_percent)
                .map(|c| format!("{:.1}%", c))
                .unwrap_or_else(|| "-".to_string());

            let mem = s
                .and_then(|s| s.memory_bytes)
                .map(fmt_bytes)
                .unwrap_or_else(|| "-".to_string());

            let reqs = s.map_or("-".to_string(), |s| fmt_num(s.requests));
            let errs = s.map_or("-".to_string(), |s| {
                if s.errors > 0 {
                    fmt_num(s.errors)
                } else {
                    "0".to_string()
                }
            });
            let avg_rt = s.map_or("-".to_string(), |s| {
                if s.avg_response_time_ms > 0.0 {
                    fmt_ms(s.avg_response_time_ms)
                } else {
                    "-".to_string()
                }
            });

            let err_style = if is_selected {
                style
            } else if s.is_some_and(|s| s.errors > 0) {
                Style::default().fg(Color::Red)
            } else {
                style
            };

            Row::new(vec![
                Cell::from(app.config.name.clone()).style(style),
                Cell::from(app.config.domain.clone()).style(style),
                Cell::from(inst.status.to_string()).style(style.fg(status_color)),
                Cell::from(cpu).style(style),
                Cell::from(mem).style(style),
                Cell::from(reqs).style(style),
                Cell::from(errs).style(err_style),
                Cell::from(avg_rt).style(style),
            ])
        })
        .collect();

    let table = Table::new(
        std::iter::once(header).chain(rows),
        [
            Constraint::Percentage(15),
            Constraint::Percentage(18),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);
}

fn render_app_detail(
    f: &mut Frame,
    area: Rect,
    app: &crate::app::AppInfo,
    stats: Option<&AppStats>,
    history: Option<&AppHistory>,
) {
    let block = Block::default()
        .title(format!(" {} ", app.config.name))
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );

    // Split: info (left) | charts (right)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(38), Constraint::Min(20)])
        .split(inner);

    render_detail_info(f, cols[0], app, stats);
    render_detail_charts(f, cols[1], stats, history);
}

fn render_detail_info(
    f: &mut Frame,
    area: Rect,
    app: &crate::app::AppInfo,
    stats: Option<&AppStats>,
) {
    let inst = if app.current_slot == "blue" {
        &app.blue
    } else {
        &app.green
    };

    let pid_str = inst
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".to_string());
    let port_str = if inst.port > 0 {
        format!(":{}", inst.port)
    } else {
        "-".to_string()
    };

    let (reqs, errs, avg_rt, bytes_in, bytes_out) = if let Some(s) = stats {
        (
            fmt_num(s.requests),
            fmt_num(s.errors),
            if s.avg_response_time_ms > 0.0 {
                fmt_ms(s.avg_response_time_ms)
            } else {
                "-".to_string()
            },
            fmt_bytes(s.bytes_received),
            fmt_bytes(s.bytes_sent),
        )
    } else {
        ("-".into(), "-".into(), "-".into(), "-".into(), "-".into())
    };

    // Two-column info table
    let info_rows = vec![
        Row::new(vec![
            Cell::from("Requests").style(Style::default().fg(Color::DarkGray)),
            Cell::from(reqs).style(Style::default().fg(Color::Cyan)),
            Cell::from("Port").style(Style::default().fg(Color::DarkGray)),
            Cell::from(port_str).style(Style::default().fg(Color::White)),
        ]),
        Row::new(vec![
            Cell::from("Errors").style(Style::default().fg(Color::DarkGray)),
            Cell::from(errs).style(Style::default().fg(if stats.is_some_and(|s| s.errors > 0) {
                Color::Red
            } else {
                Color::White
            })),
            Cell::from("PID").style(Style::default().fg(Color::DarkGray)),
            Cell::from(pid_str).style(Style::default().fg(Color::White)),
        ]),
        Row::new(vec![
            Cell::from("Avg RT").style(Style::default().fg(Color::DarkGray)),
            Cell::from(avg_rt).style(Style::default().fg(Color::Cyan)),
            Cell::from("Slot").style(Style::default().fg(Color::DarkGray)),
            Cell::from(app.current_slot.clone()).style(Style::default().fg(Color::White)),
        ]),
        Row::new(vec![
            Cell::from("Bytes In").style(Style::default().fg(Color::DarkGray)),
            Cell::from(bytes_in).style(Style::default().fg(Color::Cyan)),
            Cell::from("Bytes Out").style(Style::default().fg(Color::DarkGray)),
            Cell::from(bytes_out).style(Style::default().fg(Color::Cyan)),
        ]),
    ];

    let table = Table::new(
        info_rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(6),
        ],
    );
    f.render_widget(table, area);
}

fn render_detail_charts(
    f: &mut Frame,
    area: Rect,
    stats: Option<&AppStats>,
    history: Option<&AppHistory>,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // CPU chart
    let cpu_now = stats
        .and_then(|s| s.cpu_percent)
        .map(|c| format!("{:.1}%", c))
        .unwrap_or_else(|| "-".to_string());

    let cpu_block = Block::default()
        .title(format!(" CPU {} ", cpu_now))
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));

    if let Some(h) = history {
        let cpu_data: Vec<u64> = h.cpu.iter().copied().collect();
        let sparkline = Sparkline::default()
            .block(cpu_block)
            .data(&cpu_data)
            .max(1000) // 100.0% × 10
            .style(Style::default().fg(Color::Green));
        f.render_widget(sparkline, rows[0]);
    } else {
        f.render_widget(cpu_block, rows[0]);
    }

    // Memory chart
    let mem_now = stats
        .and_then(|s| s.memory_bytes)
        .map(fmt_bytes)
        .unwrap_or_else(|| "-".to_string());

    let mem_block = Block::default()
        .title(format!(" Mem {} ", mem_now))
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));

    if let Some(h) = history {
        let mem_data: Vec<u64> = h.mem.iter().copied().collect();
        let max_mem = mem_data.iter().copied().max().unwrap_or(1).max(1);
        let sparkline = Sparkline::default()
            .block(mem_block)
            .data(&mem_data)
            .max(max_mem)
            .style(Style::default().fg(Color::Magenta));
        f.render_widget(sparkline, rows[1]);
    } else {
        f.render_widget(mem_block, rows[1]);
    }
}

// ── helpers ────────────────────────────────────────────

fn fmt_num(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.1} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else if ms >= 1.0 {
        format!("{:.1}ms", ms)
    } else {
        format!("{:.0}us", ms * 1000.0)
    }
}
