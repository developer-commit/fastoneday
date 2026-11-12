use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::{
    state::{App, Focus},
    theme,
};

pub fn header(frame: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled(" fastoneday ", theme::key()),
        Span::styled(format!(" v{} ", env!("CARGO_PKG_VERSION")), theme::dim()),
        Span::raw(" CVE → patched binary → exact before/after, hash-verified "),
        Span::styled(format!("  {}", app.workspace), theme::dim()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(status) = app.status_text() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!(" {status}"),
                theme::strong().fg(theme::WARN),
            )),
            area,
        );
        return;
    }
    let running = app.job.as_ref().is_some_and(|j| j.is_running());
    let mut keys: Vec<(&str, &str)> = match app.focus {
        Focus::Cve => vec![
            ("Enter", "load"),
            ("↑↓", "suggestions"),
            ("Tab", "complete"),
        ],
        Focus::Products => vec![("↑↓", "product"), ("Enter", "fetch")],
        Focus::Binary => vec![("Enter", "fetch"), ("↑↓", "choose"), ("Tab", "complete")],
    };
    keys.push(("Shift-Tab", "pane"));
    if running {
        keys.push(("Esc", "cancel"));
    }
    keys.extend([("F1", "help"), ("Ctrl-C", "quit")]);
    let mut spans = Vec::new();
    for (key, what) in keys {
        spans.push(Span::styled(format!(" {key} "), theme::key()));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
