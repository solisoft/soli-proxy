use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Style},
    widgets::{Cell, Paragraph, Row, Table},
    Frame,
};

use crate::circuit_breaker::CircuitBreakerInfo;
use crate::tui::app::DaemonStatus;

/// `states` is the daemon's circuit-breaker table (`GET
/// /api/v1/circuit-breaker`), or `None` when it could not be fetched — which
/// is said as such, rather than shown as an empty (all-healthy) list.
pub fn render(
    f: &mut Frame,
    area: Rect,
    states: Option<&[(String, CircuitBreakerInfo)]>,
    status: DaemonStatus,
    selected_index: usize,
    scroll_offset: usize,
) {
    let block = crate::tui::theme::list_block("circuits");
    f.render_widget(block, area);

    let inner = crate::tui::theme::body(area);

    let Some(states) = states else {
        let why = match status {
            DaemonStatus::Ok => "the daemon did not return it",
            other => other.explain(),
        };
        let text = Paragraph::new(format!(
            "Circuit-breaker state unavailable ({why}). It lives in the running proxy and is \
             read from its admin API (GET /api/v1/circuit-breaker)."
        ))
        .style(Style::default().fg(crate::tui::theme::MUTED));
        f.render_widget(text, inner);
        return;
    };

    if states.is_empty() {
        let text = Paragraph::new(
            "No backend has been tracked yet. Circuit breakers appear here once a target \
             has served (or failed) a request.",
        );
        f.render_widget(text, inner);
        return;
    }

    let header = Row::new(vec!["Target", "State", "Health", "Failures", "Successes"])
        .style(Style::default().fg(crate::tui::theme::ACCENT).bold());

    let max_rows = inner.height.saturating_sub(1) as usize;
    let rows: Vec<Row> = states
        .iter()
        .skip(scroll_offset)
        .take(max_rows)
        .enumerate()
        .map(|(idx, (url, info))| {
            let is_selected = scroll_offset + idx == selected_index;

            let state_color = match info.state.as_str() {
                "open" => Color::Red,
                "half_open" => Color::Yellow,
                _ => Color::Green,
            };

            // The active health check's verdict, when one covers the target.
            let (health, health_color) = match info.health.as_deref() {
                Some("down") => ("down", Color::Red),
                Some("up") => ("up", Color::Green),
                _ => ("-", crate::tui::theme::MUTED),
            };

            let style = crate::tui::theme::row_style(is_selected);

            Row::new(vec![
                Cell::from(url.as_str()).style(style),
                Cell::from(info.state.as_str()).style(style.fg(state_color)),
                Cell::from(health).style(style.fg(health_color)),
                Cell::from(info.consecutive_failures.to_string()).style(style),
                Cell::from(info.consecutive_successes.to_string()).style(style),
            ])
        })
        .collect();

    let table = Table::new(
        std::iter::once(header).chain(rows),
        [
            Constraint::Min(30),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);
}
