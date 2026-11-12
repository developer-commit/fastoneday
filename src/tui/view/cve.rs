use ratatui::{
    Frame,
    layout::{Position, Rect},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use super::util::{fit, spinner};
use crate::tui::{
    state::{App, Focus},
    theme,
};

pub fn input(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Cve;
    let hint = if app.cve.value().is_empty() {
        Span::styled(
            "CVE id or words from the title — e.g. 2024-38193, clfs, excel",
            theme::dim(),
        )
    } else {
        Span::raw(app.cve.value().to_owned())
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(" CVE ", theme::title()));
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("› ", theme::title()), hint])).block(block),
        area,
    );
    if focused {
        let x = area.x + 3 + app.cve.cursor() as u16;
        frame.set_cursor_position(Position::new(
            x.min(area.right().saturating_sub(2)),
            area.y + 1,
        ));
        if app.popup_open && !app.suggestions.is_empty() {
            popup(frame, area, app);
        }
    }
}

fn popup(frame: &mut Frame, anchor: Rect, app: &App) {
    let height = (app.suggestions.len() as u16 + 2).min(12);
    let area = Rect {
        x: anchor.x + 2,
        y: anchor.bottom(),
        width: anchor.width.saturating_sub(4).min(110),
        height,
    }
    .intersection(frame.area());
    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = app
        .suggestions
        .iter()
        .map(|s| {
            let mark = if s.exploited {
                Span::styled("⚠ ", theme::strong().fg(theme::BAD))
            } else if s.from_history {
                Span::styled("↺ ", theme::dim())
            } else {
                Span::raw("  ")
            };
            let id = Span::styled(format!("{:<16}", s.id), theme::strong());
            let rest = width.saturating_sub(20);
            let title = fit(&s.title, rest * 2 / 3);
            let detail = fit(&s.detail, rest.saturating_sub(title.chars().count() + 2));
            ListItem::new(Line::from(vec![
                mark,
                id,
                Span::raw(title),
                Span::raw("  "),
                Span::styled(detail, theme::dim()),
            ]))
        })
        .collect();
    let title = if app.recent.is_empty() && app.recent_error.is_none() {
        " suggestions (loading recent CVEs…) "
    } else {
        " ↑↓ choose · Tab/→ complete · Enter load "
    };
    let list = List::new(items)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(theme::border(true))
                .title(title),
        )
        .highlight_style(theme::selected());
    frame.render_widget(Clear, area);
    frame.render_stateful_widget(
        list,
        area,
        &mut ListState::default().with_selected(Some(app.suggestion)),
    );
}

pub fn info(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(false));
    let lines: Vec<Line> = if let Some(cve) = &app.loading {
        vec![Line::from(vec![
            Span::styled(format!("{} ", spinner(app.tick)), theme::title()),
            Span::raw(format!("Looking up {cve} in the Security Update Guide…")),
        ])]
    } else if let Some(error) = &app.load_error {
        vec![Line::from(Span::styled(
            format!("✖ {error}"),
            theme::strong().fg(theme::BAD),
        ))]
    } else if let Some(report) = &app.report {
        let s = &report.detail.summary;
        let mut meta = vec![
            Span::styled(s.released.clone(), theme::dim()),
            Span::raw(" · "),
            Span::raw(s.severity.clone()),
            Span::raw(" · "),
            Span::raw(s.impact.clone()),
        ];
        if s.exploited {
            meta.push(Span::styled(
                "  ⚠ exploited in the wild",
                theme::strong().fg(theme::BAD),
            ));
        }
        if let Some(cwe) = report.detail.cwe.first() {
            meta.push(Span::styled(format!("  {cwe}"), theme::dim()));
        }
        if let Some(app_name) = &report.office_app {
            meta.push(Span::styled(format!("  Office: {app_name}"), theme::dim()));
        }
        vec![
            Line::from(vec![
                Span::styled(format!("{}  ", s.id), theme::title()),
                Span::styled(s.title.clone(), theme::strong()),
            ]),
            Line::from(meta),
            Line::from(Span::styled(
                fit(
                    &report.detail.description,
                    (area.width as usize).saturating_sub(4) * 2,
                ),
                theme::dim(),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "Welcome. Start typing a CVE id or a component name above.",
                theme::strong(),
            )),
            Line::from(Span::styled(
                "fastoneday finds the update that fixed it, the binary it patched, and fetches the exact",
                theme::dim(),
            )),
            Line::from(Span::styled(
                "before/after files from Microsoft (Update Catalog, Symbol Server, Office CDN), hash-verified.",
                theme::dim(),
            )),
        ]
    };
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}
