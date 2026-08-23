use ratatui::{
    layout::{Constraint, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Cell, Paragraph, Row, Table},
    Frame,
};

use crate::tui::errors::ErrorEntry;

pub fn render(
    f: &mut Frame,
    area: Rect,
    entries: &[ErrorEntry],
    selected_index: usize,
    scroll_offset: usize,
) {
    let block = crate::tui::theme::list_block(&format!("errors  {}", entries.len()));
    f.render_widget(block, area);

    let inner = crate::tui::theme::body(area);

    if entries.is_empty() {
        let msg = Paragraph::new(
            "No request failures recorded.\n\n\
             Request-level errors are read from proxy.log and require\n\
             [logging].log_endpoints = true in proxy.conf.",
        );
        f.render_widget(msg, inner);
        return;
    }

    let header = Row::new(vec!["Time", "Status", "Method", "Host", "Path"])
        .style(Style::default().fg(crate::tui::theme::ACCENT).bold());

    let max_rows = inner.height.saturating_sub(1) as usize;

    let rows: Vec<Row> = entries
        .iter()
        .skip(scroll_offset)
        .take(max_rows)
        .enumerate()
        .map(|(idx, e)| {
            let visual_idx = scroll_offset + idx;
            let is_selected = visual_idx == selected_index;

            let style = crate::tui::theme::row_style(is_selected);
            // 5xx and connect failures are always red unless the row is selected.
            let status_style = if is_selected {
                style
            } else {
                Style::default().fg(Color::Red)
            };

            Row::new(vec![
                Cell::from(fmt_time(&e.timestamp)).style(style),
                Cell::from(e.status_label()).style(status_style),
                Cell::from(e.method.clone().unwrap_or_else(|| "-".into())).style(style),
                Cell::from(e.host.clone().unwrap_or_else(|| "-".into())).style(style),
                Cell::from(e.path.clone().unwrap_or_else(|| "-".into())).style(style),
            ])
        })
        .collect();

    let table = Table::new(
        std::iter::once(header).chain(rows),
        [
            Constraint::Length(23),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Percentage(30),
            Constraint::Min(10),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);
}

/// Trim the RFC3339 timestamp to `YYYY-MM-DD HH:MM:SS` for the list view.
fn fmt_time(ts: &str) -> String {
    // "2026-03-22T15:45:32.214537Z" -> "2026-03-22 15:45:32"
    let trimmed = ts.split('.').next().unwrap_or(ts);
    trimmed.replacen('T', " ", 1)
}
