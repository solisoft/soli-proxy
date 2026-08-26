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
    scroll_offset: usize,
    search_query: &str,
) {
    let rules = ctx.config_manager.get_config().rules.clone();

    let block = crate::tui::theme::list_block("routes");
    f.render_widget(block, area);

    let inner = crate::tui::theme::body(area);

    if rules.is_empty() {
        let text = Paragraph::new("No routes configured. Press a to add a route.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(text, inner);
        return;
    }

    let header = Row::new(vec!["#", "Matcher", "Targets", "Auth", "Scripts", "LB"])
        .style(Style::default().fg(crate::tui::theme::ACCENT).bold());

    let filtered_rules: Vec<(usize, &crate::config::ProxyRule)> =
        filter_indices(&rules, search_query)
            .into_iter()
            .map(|idx| (idx, &rules[idx]))
            .collect();

    let max_rows = inner.height.saturating_sub(1) as usize;
    let rows: Vec<Row> = filtered_rules
        .iter()
        .skip(scroll_offset)
        .take(max_rows)
        .enumerate()
        .map(|(display_idx, (idx, rule))| {
            let is_selected = scroll_offset + display_idx == selected_index;
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

            let style = crate::tui::theme::row_style(is_selected);

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
        std::iter::once(header).chain(rows),
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

/// Indices of the rules matching `search_query`, in display order.
///
/// Shared with `TuiApp::resolve_route_index` and `get_max_selection` so that a
/// row's position on screen always maps back to the same rule. These used to be
/// two separate predicates — this one matched on `format_matcher`, the other on
/// the matcher's `Debug` output — which meant a search could line up rows on
/// screen with a different rule than `d` would delete.
pub fn filter_indices(rules: &[crate::config::ProxyRule], search_query: &str) -> Vec<usize> {
    if search_query.is_empty() {
        return (0..rules.len()).collect();
    }
    let needle = search_query.to_lowercase();
    rules
        .iter()
        .enumerate()
        .filter(|(idx, rule)| {
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
            format_matcher(&rule.matcher)
                .to_lowercase()
                .contains(&needle)
                || targets_str.to_lowercase().contains(&needle)
                || auth_str.to_lowercase().contains(&needle)
                || scripts_str.to_lowercase().contains(&needle)
                || idx.to_string() == needle
        })
        .map(|(idx, _)| idx)
        .collect()
}
