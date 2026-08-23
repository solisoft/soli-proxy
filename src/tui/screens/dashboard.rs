use std::collections::VecDeque;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Cell, Paragraph, Row, Sparkline, Table},
    Frame,
};

use crate::metrics::MetricsSnapshot;
use crate::tui::app::DaemonStatus;
use crate::tui::theme;
use crate::tui::TuiContext;

/// `remote_snap` carries traffic counters fetched from the daemon's admin API.
/// The TUI runs in its own process, so its local metrics registry is always
/// empty — `status` is what decides whether the numbers mean anything.
pub fn render(
    f: &mut Frame,
    area: Rect,
    ctx: &TuiContext,
    remote_snap: Option<&MetricsSnapshot>,
    status: DaemonStatus,
    rps_history: &VecDeque<u64>,
) {
    let local_snap = ctx.metrics.snapshot();
    let snap = remote_snap.unwrap_or(&local_snap);
    let have_metrics = remote_snap.is_some();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(6),
        ])
        .split(area);

    render_kpis(f, rows[0], snap, have_metrics, status, rps_history);
    render_rps_and_status(f, rows[1], snap, have_metrics, rps_history);
    render_meta(f, rows[2], ctx, status);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(rows[3]);
    render_apps_overview(f, bottom[0], ctx);
    render_server(f, bottom[1], ctx, snap, have_metrics);
}

fn render_kpis(
    f: &mut Frame,
    area: Rect,
    snap: &MetricsSnapshot,
    have_metrics: bool,
    status: DaemonStatus,
    rps_history: &VecDeque<u64>,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    // Without a sample the counters are not "zero", they are unknown — say
    // which of the two it is rather than showing a confident 0.
    if !have_metrics {
        // `Ok` with no global sample means the metrics endpoint specifically
        // did not answer, which `explain()` has nothing to say about.
        let why = match status.explain() {
            "" => "no metrics",
            other => other,
        };
        theme::kpi(f, cols[0], "—", why, status.color());
        theme::kpi(f, cols[1], "—", "req / s", theme::MUTED);
        theme::kpi(f, cols[2], "—", "avg latency", theme::MUTED);
        theme::kpi(f, cols[3], "—", "error rate", theme::MUTED);
        return;
    }

    let rps = rps_history.back().copied().unwrap_or(0);
    let lat = if snap.avg_response_time_ms > 0.0 {
        theme::fmt_ms(snap.avg_response_time_ms)
    } else {
        "-".into()
    };
    let err = if snap.requests_total > 0 && snap.errors_total > 0 {
        format!(
            "{:.2}%",
            (snap.errors_total as f64 / snap.requests_total as f64) * 100.0
        )
    } else {
        "0%".into()
    };

    theme::kpi(
        f,
        cols[0],
        &theme::fmt_num(snap.requests_total),
        "requests",
        theme::ACCENT,
    );
    theme::kpi(f, cols[1], &rps.to_string(), "req / s", theme::SUCCESS);
    theme::kpi(f, cols[2], &lat, "avg latency", theme::WARN);
    theme::kpi(
        f,
        cols[3],
        &err,
        "error rate",
        if snap.errors_total > 0 {
            theme::DANGER
        } else {
            theme::SUCCESS
        },
    );
}

fn render_rps_and_status(
    f: &mut Frame,
    area: Rect,
    snap: &MetricsSnapshot,
    have_metrics: bool,
    rps_history: &VecDeque<u64>,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let rps_now = rps_history.back().copied().unwrap_or(0);
    let spark_block = theme::list_block(&format!("live rps  {rps_now}"));
    if rps_history.is_empty() {
        f.render_widget(spark_block, cols[0]);
    } else {
        let data: Vec<u64> = rps_history.iter().copied().collect();
        let max = data.iter().copied().max().unwrap_or(1).max(1);
        let sparkline = Sparkline::default()
            .block(spark_block)
            .data(&data)
            .max(max)
            .style(Style::default().fg(theme::ACCENT));
        f.render_widget(sparkline, cols[0]);
    }

    let total = snap.status_2xx + snap.status_3xx + snap.status_4xx + snap.status_5xx;
    f.render_widget(theme::list_block("http"), cols[1]);
    let inner = theme::body(cols[1]);
    if !have_metrics || total == 0 {
        f.render_widget(
            Paragraph::new("no traffic yet").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        return;
    }
    let bar_width = inner.width.saturating_sub(16) as usize;
    let rows = vec![
        status_row("2xx", snap.status_2xx, total, bar_width, theme::SUCCESS),
        status_row(
            "3xx",
            snap.status_3xx,
            total,
            bar_width,
            Color::Rgb(139, 233, 253),
        ),
        status_row("4xx", snap.status_4xx, total, bar_width, theme::WARN),
        status_row("5xx", snap.status_5xx, total, bar_width, theme::DANGER),
    ];
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(8),
                Constraint::Min(6),
            ],
        ),
        inner,
    );
}

fn render_meta(f: &mut Frame, area: Rect, ctx: &TuiContext, status: DaemonStatus) {
    let cfg = ctx.config_manager.get_config();
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
    let circuits = ctx.circuit_breaker.get_states();
    let open = circuits.values().filter(|s| s.state == "open").count();
    let half = circuits.values().filter(|s| s.state == "half_open").count();

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    theme::kpi(
        f,
        cols[0],
        &theme::fmt_uptime(ctx.uptime()),
        &format!("up  {}  :{}", cfg.server.bind, cfg.server.https_port),
        theme::ACCENT,
    );
    theme::kpi(
        f,
        cols[1],
        &format!("{running}/{}", apps.len()),
        "apps running",
        theme::SUCCESS,
    );
    theme::kpi(
        f,
        cols[2],
        &cfg.rules.len().to_string(),
        "routes",
        theme::MAGENTA,
    );

    let (cval, ccol) = if open > 0 {
        (format!("{open} open"), theme::DANGER)
    } else if half > 0 {
        (format!("{half} half-open"), theme::WARN)
    } else {
        (circuits.len().to_string(), theme::SUCCESS)
    };
    // Circuit state is local to this process, so it stays meaningful whatever
    // the admin API is doing; only annotate when that distinction matters.
    let clabel = if status.is_ok() {
        "circuits".to_string()
    } else {
        format!("circuits · {}", status.explain())
    };
    theme::kpi(f, cols[3], &cval, &clabel, ccol);
}

/// Listener/TLS configuration plus the traffic counters that do not fit in the
/// KPI strip (bytes moved, in-flight requests, TLS connections).
fn render_server(
    f: &mut Frame,
    area: Rect,
    ctx: &TuiContext,
    snap: &MetricsSnapshot,
    have_metrics: bool,
) {
    let cfg = ctx.config_manager.get_config();
    f.render_widget(theme::list_block("server"), area);
    let inner = theme::body(area);

    let tls = if cfg.tls.mode.is_empty() || cfg.tls.mode == "disabled" {
        "disabled".to_string()
    } else {
        cfg.tls.mode.clone()
    };
    let admin = if cfg.admin.enabled.unwrap_or(true) {
        cfg.admin.bind.clone()
    } else {
        "disabled".to_string()
    };
    let scripts = if cfg.global_scripts.is_empty() {
        "-".to_string()
    } else {
        cfg.global_scripts.join(", ")
    };
    let unknown = |s: String| if have_metrics { s } else { "—".to_string() };

    let rows = vec![
        kv("listen", cfg.server.bind.clone(), theme::FG),
        kv("https", format!(":{}", cfg.server.https_port), theme::FG),
        kv("tls", tls, theme::FG),
        kv("admin", admin, theme::FG),
        kv(
            "auth",
            if ctx.auth_required { "enabled" } else { "-" }.to_string(),
            theme::FG,
        ),
        kv("scripts", scripts, theme::MAGENTA),
        kv(
            "in flight",
            unknown(theme::fmt_num(snap.requests_in_flight as u64)),
            theme::FG,
        ),
        kv(
            "bytes in",
            unknown(theme::fmt_bytes(snap.bytes_received)),
            theme::FG,
        ),
        kv(
            "bytes out",
            unknown(theme::fmt_bytes(snap.bytes_sent)),
            theme::FG,
        ),
        kv(
            "tls conns",
            unknown(theme::fmt_num(snap.tls_connections)),
            theme::FG,
        ),
        kv(
            "errors",
            unknown(theme::fmt_num(snap.errors_total)),
            if snap.errors_total > 0 && have_metrics {
                theme::DANGER
            } else {
                theme::FG
            },
        ),
    ];

    f.render_widget(
        Table::new(rows, [Constraint::Length(10), Constraint::Min(8)]),
        inner,
    );
}

fn kv(label: &str, value: String, color: Color) -> Row<'static> {
    Row::new(vec![
        Cell::from(label.to_string()).style(Style::default().fg(theme::MUTED)),
        Cell::from(value).style(Style::default().fg(color)),
    ])
}

fn render_apps_overview(f: &mut Frame, area: Rect, ctx: &TuiContext) {
    let apps = ctx
        .app_manager
        .as_ref()
        .map(|m| m.list_apps_sync())
        .unwrap_or_default();

    f.render_widget(theme::list_block("apps"), area);
    let inner = theme::body(area);

    if apps.is_empty() {
        f.render_widget(
            Paragraph::new("no apps in sites/").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        return;
    }

    let header = Row::new(vec!["name", "domain", "slot", "status", "port"])
        .style(Style::default().fg(theme::MUTED).bold());

    let max_rows = inner.height.saturating_sub(1) as usize;
    // Leave room for the overflow hint when the list does not fit.
    let overflow = apps.len().saturating_sub(max_rows);
    let shown = if overflow > 0 {
        max_rows.saturating_sub(1)
    } else {
        max_rows
    };

    let mut rows: Vec<Row> = apps
        .iter()
        .take(shown)
        .map(|app| {
            let inst = if app.current_slot == "blue" {
                &app.blue
            } else {
                &app.green
            };
            let (status_str, status_color) = match inst.status {
                crate::app::InstanceStatus::Running => ("● run", theme::SUCCESS),
                crate::app::InstanceStatus::Starting => ("● start", theme::WARN),
                crate::app::InstanceStatus::Stopped => ("○ stop", theme::MUTED),
                crate::app::InstanceStatus::Unhealthy => ("● sick", theme::DANGER),
                crate::app::InstanceStatus::Failed => ("● fail", theme::DANGER),
            };
            let port_str = if inst.port > 0 {
                format!(":{}", inst.port)
            } else {
                "-".into()
            };
            Row::new(vec![
                Cell::from(app.config.name.clone()).style(Style::default().fg(theme::FG)),
                Cell::from(app.config.domain.clone()).style(Style::default().fg(theme::MUTED)),
                Cell::from(app.current_slot.clone()).style(Style::default().fg(theme::MUTED)),
                Cell::from(status_str).style(Style::default().fg(status_color)),
                Cell::from(port_str).style(Style::default().fg(theme::MUTED)),
            ])
        })
        .collect();

    if overflow > 0 {
        rows.push(Row::new(vec![Cell::from(format!(
            "+{overflow} more — press 3"
        ))
        .style(Style::default().fg(theme::MUTED))]));
    }

    f.render_widget(
        Table::new(
            std::iter::once(header).chain(rows),
            [
                Constraint::Percentage(20),
                Constraint::Percentage(35),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .column_spacing(1),
        inner,
    );
}

fn status_row(label: &str, count: u64, total: u64, bar_width: usize, color: Color) -> Row<'static> {
    let pct = if total > 0 {
        (count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
    let bar: String = "█".repeat(filled);
    Row::new(vec![
        Cell::from(label.to_string()).style(Style::default().fg(color).bold()),
        Cell::from(theme::fmt_num(count)).style(Style::default().fg(theme::FG)),
        Cell::from(bar).style(Style::default().fg(color)),
    ])
}
