use ratatui::{
    Frame,
    layout::{Constraint, Layout, Position, Rect},
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph},
};

use super::util::{fit, spinner};
use crate::tui::{
    state::{App, Focus, Names},
    theme,
};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Binary;
    let status = match app.selected_pair().and_then(|p| app.names_for(p)) {
        Some(Names::Loading) => format!(" {} reading package… ", spinner(app.tick)),
        Some(Names::Ready { names, .. }) => format!(" {} binaries in the update ", names.len()),
        Some(Names::Failed(error)) => format!(" package list unavailable: {} ", fit(error, 48)),
        None => String::new(),
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(" Binary ", theme::title()))
        .title_bottom(Line::from(Span::styled(status, theme::dim())).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [input_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);

    let typed = if app.binary.value().is_empty() {
        Span::styled("type to search · Enter fetch", theme::dim())
    } else {
        Span::raw(app.binary.value().to_owned())
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("› ", theme::title()), typed])),
        input_area,
    );
    if focused {
        frame.set_cursor_position(Position::new(
            (input_area.x + 2 + app.binary.cursor() as u16)
                .min(input_area.right().saturating_sub(1)),
            input_area.y,
        ));
    }

    if app.options.is_empty() {
        let hint = if app.report.is_none() {
            "Candidates appear after a CVE is loaded."
        } else if app.binary.value().is_empty() {
            "No binary inferred — type its file name (e.g. ntfs.sys)."
        } else {
            "No match; Enter uses the typed name as is."
        };
        frame.render_widget(Paragraph::new(Span::styled(hint, theme::dim())), list_area);
        return;
    }
    let width = list_area.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .options
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let lead = if i == 0 && o.score.is_some() && app.binary.value().is_empty() {
                Span::styled("★ ", theme::strong().fg(theme::WARN))
            } else {
                Span::raw("  ")
            };
            let score = o
                .score
                .map(|s| format!("{s:>3} "))
                .unwrap_or_else(|| "    ".into());
            let name_w = 22.min(width / 2);
            ListItem::new(Line::from(vec![
                lead,
                Span::styled(
                    format!("{:<w$}", fit(&o.name, name_w), w = name_w),
                    theme::strong(),
                ),
                Span::styled(score, theme::dim().fg(theme::ACCENT)),
                Span::styled(fit(&o.why, width.saturating_sub(name_w + 8)), theme::dim()),
            ]))
        })
        .collect();
    let list = List::new(items).highlight_style(theme::selected());
    frame.render_stateful_widget(
        list,
        list_area,
        &mut ListState::default().with_selected(Some(app.option)),
    );
}
