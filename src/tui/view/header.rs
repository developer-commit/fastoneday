//! Title bar: name, version, where you are in the flow, and the workspace.

use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::util::{columns, fit_left, spinner};
use crate::tui::{
    state::{App, Focus, StepMark},
    theme,
};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![
        Span::styled(" fastoneday ", theme::key()),
        Span::styled(format!(" {} ", env!("CARGO_PKG_VERSION")), theme::dim()),
        Span::raw(" "),
    ];
    for (i, step) in Focus::ALL.into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" › ", theme::dim()));
        }
        let mark = app.step_mark(step);
        let current = app.focus == step;
        let mut style = match mark {
            StepMark::Done => theme::fg(theme::OK),
            StepMark::Failed => theme::fg(theme::BAD),
            StepMark::Running => theme::fg(theme::ACCENT),
            StepMark::Pending => theme::dim(),
        };
        if current {
            style = theme::title().add_modifier(Modifier::UNDERLINED);
        }
        spans.push(Span::styled(
            format!("{} {}", step.number(), step.label()),
            style,
        ));
        let suffix = match mark {
            StepMark::Done => Some(("✔".to_owned(), theme::fg(theme::OK))),
            StepMark::Failed => Some(("✖".to_owned(), theme::fg(theme::BAD))),
            StepMark::Running => Some((spinner(app.tick).to_owned(), theme::fg(theme::ACCENT))),
            StepMark::Pending => None,
        };
        if let Some((symbol, style)) = suffix {
            spans.push(Span::styled(format!(" {symbol}"), style));
        }
    }
    let used: usize = spans.iter().map(|s| columns(&s.content)).sum();
    let room = (area.width as usize).saturating_sub(used + 3);
    if room >= 12 {
        let path = fit_left(&app.workspace, room);
        let pad = room.saturating_sub(columns(&path));
        spans.push(Span::raw(" ".repeat(pad + 2)));
        spans.push(Span::styled(path, theme::dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
