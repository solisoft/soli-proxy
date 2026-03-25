use ratatui::{
    layout::Rect,
    style::Style,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::TuiContext;

pub fn render(f: &mut Frame, area: Rect, ctx: &TuiContext) {
    let block = Block::default().title(" proxy.conf ").borders(Borders::ALL);
    f.render_widget(block, area);

    let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);

    let config_path = ctx.config_manager.config_path();
    let config_content = std::fs::read_to_string(config_path)
        .unwrap_or_else(|_| "Failed to read config file.".to_string());

    let lines: Vec<&str> = config_content.lines().collect();
    let visible_lines: Vec<String> = lines
        .iter()
        .take(inner.height as usize)
        .map(|s| s.to_string())
        .collect();
    let display_text = visible_lines.join("\n");

    let paragraph =
        Paragraph::new(display_text).style(Style::default().fg(ratatui::style::Color::White));

    f.render_widget(paragraph, inner);
}
