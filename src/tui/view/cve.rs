//! ① CVE: the search box, its suggestion list and the CVE card.

use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use super::util::{columns, fit, highlight, spinner};
use crate::{
    domain::CveId,
    tui::{
        layout::{self, Areas},
        state::{App, Focus},
        theme,
    },
};

pub fn input(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Cve;
    let typed = app.cve.value();
    let (status, status_style) = if let Some(cve) = &app.loading {
        (
            format!("{} looking up {cve}", spinner(app.tick)),
            theme::fg(theme::ACCENT),
        )
    } else if app.typed_is_loaded() {
        ("✔ loaded · Enter next step".into(), theme::fg(theme::OK))
    } else if CveId::parse(typed).is_ok() {
        ("✔ valid id · Enter to load".into(), theme::fg(theme::OK))
    } else if !typed.trim().is_empty() && focused {
        match app.suggestions.len() {
            0 => ("no match".into(), theme::fg(theme::WARN)),
            1 => ("1 match".into(), theme::dim()),
            n => (format!("{n} matches"), theme::dim()),
        }
    } else {
        (String::new(), theme::dim())
    };
    let content = if typed.is_empty() {
        Span::styled(
            "CVE id or words from its title — e.g. 2024-38193, clfs, defender",
            theme::dim(),
        )
    } else {
        Span::styled(typed.to_owned(), theme::strong())
    };
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(" ① CVE ", theme::title()));
    if !status.is_empty() {
        block = block
            .title(Line::from(Span::styled(format!(" {status} "), status_style)).right_aligned());
    }
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("› ", theme::title()),
            content,
        ]))
        .block(block),
        area,
    );
    if focused && !app.show_help {
        let x = area.x + 3 + columns(&typed[..cursor_byte(typed, app.cve.cursor())]) as u16;
        frame.set_cursor_position(Position::new(
            x.min(area.right().saturating_sub(2)),
            area.y + 1,
        ));
    }
}

fn cursor_byte(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(i, _)| i)
}

/// The suggestion list, drawn over the panes under the search box.
pub fn dropdown(frame: &mut Frame, areas: &Areas, app: &App) {
    if !(app.focus == Focus::Cve && app.popup_open && !app.suggestions.is_empty()) || app.show_help
    {
        return;
    }
    let area = layout::dropdown(areas, app.suggestions.len());
    if area.height < 3 {
        return;
    }
    let width = area.width.saturating_sub(4) as usize;
    let needles = query_words(app.cve.value());
    let items: Vec<ListItem> = app
        .suggestions
        .iter()
        .map(|s| {
            let mark = if s.exploited {
                Span::styled("⚠ ", theme::bad())
            } else if s.from_history {
                Span::styled("↺ ", theme::dim())
            } else {
                Span::raw("  ")
            };
            let mut spans = vec![mark];
            spans.extend(highlight(
                &format!("{:<17}", s.id),
                &needles,
                theme::strong(),
                theme::matched(),
            ));
            let rest = width.saturating_sub(20);
            let detail = fit(&s.detail, (rest / 3).max(12));
            let title_room = rest.saturating_sub(columns(&detail) + 2);
            let title = fit(&s.title, title_room);
            let pad = title_room.saturating_sub(columns(&title));
            spans.extend(highlight(
                &title,
                &needles,
                theme::fg(Color::Reset),
                theme::matched(),
            ));
            spans.push(Span::raw(" ".repeat(pad + 2)));
            spans.push(Span::styled(detail, theme::dim()));
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = if app.recent.is_empty() && app.recent_error.is_none() {
        " loading recent CVEs… ".to_owned()
    } else {
        format!(
            " {} of {} · ↑↓ choose · Tab complete · Enter load ",
            app.suggestion + 1,
            app.suggestions.len()
        )
    };
    let legend =
        Line::from(Span::styled(" ⚠ exploited · ↺ history ", theme::dim())).right_aligned();
    let list = List::new(items)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(theme::border(true))
                .title(Span::styled(title, theme::dim()))
                .title_bottom(legend),
        )
        .highlight_style(theme::selected(true));
    frame.render_widget(Clear, area);
    frame.render_stateful_widget(
        list,
        area,
        &mut ListState::default().with_selected(Some(app.suggestion)),
    );
}

/// Words to highlight: the id digits or each search word.
fn query_words(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    let upper = trimmed.to_ascii_uppercase();
    let id = upper.strip_prefix("CVE-").unwrap_or(&upper);
    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return vec![id.to_owned()];
    }
    trimmed.split_whitespace().map(str::to_owned).collect()
}

pub fn card(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(false));
    let inner_width = area.width.saturating_sub(4) as usize;
    let rows = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = if let Some(cve) = &app.loading {
        vec![Line::from(vec![
            Span::styled(format!("{} ", spinner(app.tick)), theme::title()),
            Span::raw(format!(
                "Looking up {cve} in Microsoft's Security Update Guide…"
            )),
        ])]
    } else if let Some(failure) = &app.load_error {
        let mut lines = vec![Line::from(Span::styled(
            format!("✖ {}", failure.message),
            theme::bad(),
        ))];
        if let Some(hint) = &failure.hint {
            lines.push(Line::from(vec![
                Span::styled("→ ", theme::title()),
                Span::raw(hint.clone()),
            ]));
        }
        lines
    } else if let Some(report) = &app.report {
        let s = &report.detail.summary;
        let severity_color = match s.severity.to_ascii_lowercase().as_str() {
            "critical" => theme::BAD,
            "important" => theme::WARN,
            _ => theme::DIM,
        };
        let mut meta = Vec::new();
        if s.exploited {
            meta.push(Span::styled(" ⚠ EXPLOITED ", theme::badge(theme::BAD)));
            meta.push(Span::raw(" "));
        }
        if !s.severity.is_empty() {
            meta.push(Span::styled(
                format!(" {} ", s.severity),
                theme::badge(severity_color),
            ));
            meta.push(Span::raw(" "));
        }
        let mut facts = vec![s.impact.clone(), s.released.clone()];
        facts.extend(report.detail.cwe.first().cloned());
        if !s.tag.is_empty() {
            facts.push(s.tag.clone());
        }
        if let Some(app_name) = &report.office_app {
            facts.push(format!("Office: {app_name}"));
        }
        let facts: Vec<String> = facts.into_iter().filter(|f| !f.is_empty()).collect();
        meta.push(Span::styled(
            fit(&facts.join(" · "), inner_width.saturating_sub(24)),
            theme::dim(),
        ));
        let mut lines = vec![
            Line::from(vec![
                Span::styled(format!("{}  ", s.id), theme::title()),
                Span::styled(s.title.clone(), theme::strong()),
            ]),
            Line::from(meta),
        ];
        if rows > 2 {
            lines.push(Line::from(Span::styled(
                fit(&report.detail.description, inner_width * (rows - 2)),
                theme::dim(),
            )));
        }
        lines
    } else {
        vec![
            Line::from(vec![
                Span::styled("Welcome. ", theme::strong()),
                Span::raw(
                    "Pick a CVE and fastoneday fetches the exact vulnerable and fixed builds of the binary it patched.",
                ),
            ]),
            Line::from(vec![
                Span::styled("① ", theme::title()),
                Span::raw("type an id or keywords, Enter   "),
                Span::styled("② ", theme::title()),
                Span::raw("Enter on its patch pair   "),
                Span::styled("③ ", theme::title()),
                Span::raw("Enter on a binary of that update   "),
                Span::styled("?", theme::title()),
                Span::raw(" help"),
            ]),
            Line::from(Span::styled(
                "Sources: Security Update Guide, Update Catalog, Office CDN, Defender CDN, Symbol Server — every file hash-verified.",
                theme::dim(),
            )),
        ]
    };
    let lines: Vec<Line> = lines.into_iter().take(rows.max(1)).collect();
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}
