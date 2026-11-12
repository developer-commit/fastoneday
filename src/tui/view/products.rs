use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph},
};

use super::util::{fit, spinner};
use crate::{
    app::{REMOTE_READABLE_BUILD, build_major},
    domain::{Family, PatchPair},
    tui::{
        state::{App, Focus, Names},
        theme,
    },
};

/// How a row's packages will be read.
fn access(pair: &PatchPair) -> (&'static str, &'static str) {
    match pair.family {
        Family::OfficeC2r => ("⚡", "CDN"),
        Family::OfficeMsi => ("⬇", "CAB"),
        Family::Windows if build_major(pair) >= REMOTE_READABLE_BUILD => ("⚡", "range"),
        Family::Windows => ("⬇", "MSU"),
    }
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Products;
    let pairs = app.pairs();
    let title = format!(" Product · patch pair ({}) ", pairs.len());
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(title, theme::title()));
    if pairs.is_empty() {
        let text = match &app.report {
            Some(report) if !report.detail.unsupported.is_empty() => {
                let mut lines = vec![Line::from(Span::styled(
                    "Nothing acquirable. Skipped:",
                    theme::strong(),
                ))];
                lines.extend(
                    report
                        .detail
                        .unsupported
                        .iter()
                        .take(8)
                        .map(|s| Line::from(Span::styled(format!("· {s}"), theme::dim()))),
                );
                lines
            }
            _ => vec![Line::from(Span::styled(
                "Load a CVE to see the products it affects.",
                theme::dim(),
            ))],
        };
        frame.render_widget(Paragraph::new(text).block(block), area);
        return;
    }
    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = pairs
        .iter()
        .enumerate()
        .map(|(i, pair)| {
            let (icon, how) = access(pair);
            let star = if i == 0 {
                Span::styled("★ ", theme::strong().fg(theme::WARN))
            } else {
                Span::raw("  ")
            };
            let state = match app.names_for(pair) {
                Some(Names::Loading) => {
                    Span::styled(format!(" {}", spinner(app.tick)), theme::dim())
                }
                Some(Names::Ready { .. }) => Span::styled(" ✔", theme::dim().fg(theme::OK)),
                Some(Names::Failed(_)) => Span::styled(" !", theme::dim().fg(theme::WARN)),
                None => Span::raw("  "),
            };
            let updates = format!(
                "{} → {}",
                short_update(&pair.before.label()),
                short_update(&pair.after.label())
            );
            // star(2) + space + updates + " ⚡ range"(8) + state(2) + highlight symbol(1)
            let name_width = width.saturating_sub(updates.chars().count() + 14).max(8);
            ListItem::new(Line::from(vec![
                star,
                Span::styled(
                    format!(
                        "{:<w$}",
                        fit(&pair.short_product(), name_width),
                        w = name_width
                    ),
                    theme::strong(),
                ),
                Span::raw(" "),
                Span::raw(updates),
                Span::styled(format!(" {icon} {how}"), theme::dim()),
                state,
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(theme::selected())
        .highlight_symbol("▶");
    frame.render_stateful_widget(
        list,
        area,
        &mut ListState::default().with_selected(Some(app.product)),
    );
}

/// `16.0.17932.21140` → `17932.21140`; KBs unchanged.
fn short_update(label: &str) -> String {
    label.strip_prefix("16.0.").unwrap_or(label).to_owned()
}
