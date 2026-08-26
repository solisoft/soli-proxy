use ratatui::{
    layout::{Constraint, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Cell, Paragraph, Row, Table},
    Frame,
};

use crate::tui::TuiContext;

pub fn render(
    f: &mut Frame,
    area: Rect,
    ctx: &TuiContext,
    selected_index: usize,
    scroll_offset: usize,
) {
    let block = crate::tui::theme::list_block("circuits");
    f.render_widget(block, area);

    let inner = crate::tui::theme::body(area);

    let states = ctx.circuit_breaker.get_states();

    if states.is_empty() {
        let text =
            Paragraph::new("No circuit breakers active. Circuit breakers track backend failures.");
        f.render_widget(text, inner);
        return;
    }

    let header = Row::new(vec!["Target", "State", "Failures", "Successes"])
        .style(Style::default().fg(crate::tui::theme::ACCENT).bold());

    let states_vec: Vec<(String, crate::circuit_breaker::CircuitBreakerInfo)> =
        states.into_iter().collect();

    let max_rows = inner.height.saturating_sub(1) as usize;
    let rows: Vec<Row> = states_vec
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

            let style = crate::tui::theme::row_style(is_selected);

            Row::new(vec![
                Cell::from(url.as_str()).style(style),
                Cell::from(info.state.as_str()).style(style.fg(state_color)),
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
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);
}
