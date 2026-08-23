use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    widgets::Paragraph,
    Frame,
};

use crate::tui::theme;

/// Renders `proxy.conf` from the text cached by `TuiApp` — reading the file
/// here would mean a disk hit on every frame, and the caller needs the line
/// count anyway to know how far `scroll_offset` may go.
pub fn render(f: &mut Frame, area: Rect, config_text: &str, scroll_offset: usize, lines: usize) {
    f.render_widget(theme::list_block("proxy.conf"), area);

    let inner = theme::body(area);
    let visible: Vec<&str> = config_text
        .lines()
        .skip(scroll_offset)
        .take(inner.height as usize)
        .collect();

    f.render_widget(
        Paragraph::new(visible.join("\n")).style(Style::default().fg(theme::FG)),
        inner,
    );

    // Scroll affordance: without a cursor there is nothing else to say whether
    // the view is at the top, in the middle, or at the end of the file.
    if lines > inner.height as usize && inner.width > 8 {
        let end = (scroll_offset + inner.height as usize).min(lines);
        let hint = format!(" {}-{end} of {lines} · j/k ", scroll_offset + 1);
        let w = (hint.chars().count() as u16).min(inner.width);
        let hint_area = Rect::new(inner.x + inner.width.saturating_sub(w), area.y, w, 1);
        f.render_widget(
            Paragraph::new(hint)
                .style(Style::default().fg(theme::MUTED))
                .alignment(Alignment::Right),
            hint_area,
        );
    }
}
