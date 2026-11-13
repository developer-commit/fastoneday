//! Bottom of the screen: a transient message line and the keys that matter
//! right now (the full list is behind `?`).

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::util::{columns, fit};
use crate::tui::{
    complete::OptionKind,
    state::{App, Files, Focus, JobState, Level},
    theme,
};

pub fn toast(frame: &mut Frame, area: Rect, app: &App) {
    let Some(toast) = app.toast_text() else {
        return;
    };
    let (icon, style) = match toast.level {
        Level::Info => ("ℹ", theme::fg(theme::ACCENT)),
        Level::Success => ("✔", theme::ok()),
        Level::Warn => ("⚠", theme::warn()),
        Level::Error => ("✖", theme::bad()),
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {icon} "), style),
            Span::styled(
                fit(&toast.text, area.width.saturating_sub(4) as usize),
                style,
            ),
        ])),
        area,
    );
}

pub fn keys(frame: &mut Frame, area: Rect, app: &App) {
    let state = app.job.as_ref().map(|j| &j.state);
    let running = app.running();
    let mut keys: Vec<(&str, &str)> = match app.focus {
        Focus::Cve if app.popup_open && !app.suggestions.is_empty() => {
            vec![
                ("Enter", "load"),
                ("↑↓", "choose"),
                ("Tab", "complete"),
                ("Esc", "close list"),
            ]
        }
        Focus::Cve if app.typed_is_loaded() => vec![("Enter", "next"), ("↓", "suggestions")],
        Focus::Cve => vec![("Enter", "load"), ("↓", "suggestions")],
        Focus::Products if app.pairs().is_empty() => vec![("n", "new CVE")],
        Focus::Products => vec![
            ("↑↓", "patch pair"),
            ("Enter", "list its binaries"),
            ("Esc", "back"),
        ],
        Focus::Binary
            if app.binary.value().is_empty()
                && app.listing_job().is_none()
                && matches!(app.selected_files(), Some(Files::NeedsDownload { .. })) =>
        {
            vec![
                ("Enter", "download & list its files"),
                ("type", "a file name"),
                ("Esc", "back"),
            ]
        }
        Focus::Binary if app.binary.value().is_empty() && app.listing_job().is_some() => {
            vec![("type", "a file name to fetch it now"), ("Esc", "back")]
        }
        Focus::Binary if app.selection().is_none() && !app.options.is_empty() => {
            vec![("↓", "browse the update's files"), ("Esc", "back")]
        }
        Focus::Binary
            if app
                .selected_option()
                .is_some_and(|o| o.kind == OptionKind::Typed) =>
        {
            vec![
                ("Enter", "fetch as typed"),
                ("↑↓", "choose"),
                ("Esc", "back"),
            ]
        }
        Focus::Binary if app.tab_completes() => {
            vec![
                ("Enter", "fetch"),
                ("↑↓", "choose"),
                ("Tab", "complete"),
                ("Esc", "back"),
            ]
        }
        Focus::Binary => vec![("Enter", "fetch"), ("↑↓", "choose"), ("Esc", "back")],
        Focus::Fetch => match state {
            Some(JobState::Done(_)) => vec![
                ("o", "open folder"),
                ("y", "copy path"),
                ("Enter", "fetch again"),
                ("n", "new CVE"),
            ],
            Some(JobState::Failed(_) | JobState::Cancelled) => {
                vec![("r", "retry"), ("Esc", "back"), ("n", "new CVE")]
            }
            Some(JobState::Listed) => vec![("Esc", "back to ③"), ("n", "new CVE")],
            Some(JobState::Running) => vec![],
            None => vec![("Enter", "fetch"), ("Esc", "back")],
        },
    };
    if running {
        keys.push(("Esc Esc", "cancel"));
    }
    if !app.tab_completes() && !(app.focus == Focus::Cve && app.popup_open) {
        keys.push(("Tab", "next pane"));
    }
    let quit = match app.focus {
        Focus::Products | Focus::Fetch => "q quit",
        _ => "Ctrl-C quit",
    };
    let right = format!(" ? help · {quit} ");
    let width = area.width as usize;
    let cost = |(key, what): &(&str, &str)| columns(key) + columns(what) + 5;
    // Least important hints go first when the line is too narrow; `? help`
    // always stays reachable.
    while keys.len() > 1 && keys.iter().map(cost).sum::<usize>() + columns(&right) > width {
        keys.pop();
    }
    let mut spans = Vec::new();
    for (key, what) in &keys {
        spans.push(Span::styled(format!(" {key} "), theme::key()));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    let used: usize = spans.iter().map(|s| columns(&s.content)).sum();
    let room = width.saturating_sub(used);
    if room >= columns(&right) {
        spans.push(Span::raw(" ".repeat(room - columns(&right))));
        spans.push(Span::styled(right, theme::dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
