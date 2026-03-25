use ratatui::{
    layout::{Constraint, Rect},
    prelude::Stylize,
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::tui::TuiContext;

pub fn render(
    f: &mut Frame,
    area: Rect,
    ctx: &TuiContext,
    selected_index: usize,
    search_query: &str,
) {
    let rules = ctx.config_manager.get_config().rules.clone();

    let block = Block::default().title(" Routes ").borders(Borders::ALL);
    f.render_widget(block, area);

    let inner = Rect::new(area.x + 1, area.y + 1, area.width - 2, area.height - 2);

    if rules.is_empty() {
        let text =
            Paragraph::new("No routes configured. Press 'a' to add a route.");
        f.render_widget(text, inner);
        return;
    }

    let header = Row::new(vec!["#", "Matcher", "Targets", "Auth", "Scripts", "LB"])
        .style(Style::default().fg(Color::Green).bold());

    let filtered_rules: Vec<(usize, &crate::config::ProxyRule)> = rules
        .iter()
        .enumerate()
        .filter(|(idx, rule)| {
            if search_query.is_empty() {
                return true;
            }
            let search_lower = search_query.to_lowercase();
            let matcher_str = format_matcher(&rule.matcher).to_lowercase();
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
        .collect();

    let rows: Vec<Row> = filtered_rules
        .iter()
        .enumerate()
        .map(|(display_idx, (idx, rule))| {
            let is_selected = display_idx == selected_index;
            let matcher_str = format_matcher(&rule.matcher);
            let targets_str: String = rule
                .targets
                .iter()
                .map(|t| t.url.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let lb_str = format_lb(&rule.load_balancing);

            let auth_str = if rule.auth.is_empty() {
                "-".to_string()
            } else {
                let names: Vec<&str> = rule.auth.iter().map(|a| a.username.as_str()).collect();
                if names.len() <= 2 {
                    names.join(", ")
                } else {
                    format!("{} +{}", names[0], names.len() - 1)
                }
            };

            let scripts_str = if rule.scripts.is_empty() {
                "-".to_string()
            } else if rule.scripts.len() == 1 {
                rule.scripts[0].clone()
            } else {
                format!("{} +{}", rule.scripts[0], rule.scripts.len() - 1)
            };

            let style = if is_selected {
                Style::default().bg(Color::Blue).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            let auth_style = if is_selected {
                style
            } else if !rule.auth.is_empty() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let scripts_style = if is_selected {
                style
            } else if !rule.scripts.is_empty() {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            Row::new(vec![
                Cell::from((idx + 1).to_string()).style(style),
                Cell::from(matcher_str).style(style),
                Cell::from(targets_str).style(style),
                Cell::from(auth_str).style(auth_style),
                Cell::from(scripts_str).style(scripts_style),
                Cell::from(lb_str).style(style),
            ])
        })
        .collect();

    let table = Table::new(
        std::iter::once(header).chain(rows.into_iter()),
        [
            Constraint::Length(4),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(12),
        ],
    )
    .column_spacing(1);

    f.render_widget(table, inner);

    if !search_query.is_empty() {
        let search_width = 25u16.min(area.width.saturating_sub(2));
        let search_block = Block::default()
            .title(format!(" Filter: {} ", search_query))
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));
        let search_area = Rect::new(area.x + area.width - search_width, area.y, search_width, 3);
        f.render_widget(search_block, search_area);
    }
}

fn format_matcher(matcher: &crate::config::RuleMatcher) -> String {
    match matcher {
        crate::config::RuleMatcher::Default => "default".to_string(),
        crate::config::RuleMatcher::Prefix(v) => format!("{}*", v),
        crate::config::RuleMatcher::Exact(v) => v.clone(),
        crate::config::RuleMatcher::Domain(v) => v.clone(),
        crate::config::RuleMatcher::DomainPath(d, p) => format!("{}{}", d, p),
        crate::config::RuleMatcher::Regex(rm) => format!("~{}", rm.pattern),
    }
}

fn format_lb(lb: &crate::config::LoadBalancingStrategy) -> String {
    match lb {
        crate::config::LoadBalancingStrategy::RoundRobin => "round-robin".to_string(),
        crate::config::LoadBalancingStrategy::Weighted => "weighted".to_string(),
        crate::config::LoadBalancingStrategy::Failover => "failover".to_string(),
    }
}
