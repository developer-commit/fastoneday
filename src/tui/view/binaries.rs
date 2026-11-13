//! ③ Binary: which file of the selected patch pair's update to fetch.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Position, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Wrap},
};

use super::util::{columns, fit, highlight, spinner};
use crate::{
    app::{Comparison, PairListing},
    domain::{BinaryName, PatchPair},
    tui::{
        complete::OptionKind,
        layout,
        state::{App, Files, Focus, size_label, update_label},
        theme,
    },
};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Binary;
    let pair = app.selected_pair();
    let files = app.selected_files();
    let title = match pair {
        Some(pair) => format!(" ③ Binary · files of {} ", update_label(&pair.after)),
        None => " ③ Binary ".to_owned(),
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(title, theme::title()))
        .title_bottom(
            Line::from(Span::styled(
                status(app, files, area.width.saturating_sub(4) as usize),
                theme::dim(),
            ))
            .right_aligned(),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [input_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);

    let typed = app.binary.value();
    let content = if typed.is_empty() {
        let hint = match files {
            _ if app.report.is_none() => "load a CVE first",
            None => "pick a patch pair in ②",
            Some(Files::Ready(_)) => "type to search its files · ↓ browse · Enter fetch",
            Some(Files::NeedsDownload { .. }) => "Enter lists its files · or type a file name",
            Some(_) => "type any file name · Enter fetch",
        };
        Span::styled(hint, theme::dim())
    } else {
        Span::styled(typed.to_owned(), theme::strong())
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("› ", theme::title()),
            content,
        ])),
        input_area,
    );
    if focused && !app.show_help {
        frame.set_cursor_position(Position::new(
            (input_area.x
                + 2
                + columns(&typed.chars().take(app.binary.cursor()).collect::<String>()) as u16)
                .min(input_area.right().saturating_sub(1)),
            input_area.y,
        ));
    }

    let width = list_area.width.saturating_sub(2) as usize;
    if app.options.is_empty() {
        let lines = match (pair, files) {
            // Not asked yet (the ② cursor is still moving): about to load.
            (Some(pair), files) if typed.trim().is_empty() => {
                waiting(app, pair, files.unwrap_or(&Files::Loading))
            }
            (None, _) if app.report.is_none() => vec![dim(
                "The files of the patch pair you pick appear here; ★ marks the one Microsoft's text points to.",
            )],
            (None, _) => vec![dim("This CVE has no patch pair that can be fetched.")],
            _ => match BinaryName::parse(typed) {
                Err(e) => vec![dim(&e.to_string())],
                Ok(_) => vec![],
            },
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), list_area);
        return;
    }

    // Nothing recommended: say why above the list, once.
    let listing = app.listing();
    let mut list_area = list_area;
    if typed.is_empty()
        && let Some(listing) = listing
        && listing.pick().is_none()
        && list_area.height > 3
    {
        let [note, rest] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(list_area);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                fit(&no_pick(app, listing), width + 2),
                theme::warn(),
            ))),
            note,
        );
        list_area = rest;
    }

    // Only the visible rows are built: an update can list thousands of files.
    let selected = app.selection();
    let offset = layout::list_offset(selected.unwrap_or(0), list_area.height);
    // The typed row's note; the footer adds "Enter fetch as typed".
    let typed_note = match files {
        Some(Files::Ready(_)) => ("not in this update", theme::warn()),
        Some(Files::Loading) => ("list still loading", theme::dim()),
        Some(Files::NeedsDownload { .. }) => ("list not read yet", theme::dim()),
        _ => ("", theme::dim()),
    };
    let needles: Vec<String> = typed.split_whitespace().map(str::to_owned).collect();
    // As wide as the longest name (so columns hold while scrolling), at most 24.
    let longest = app
        .options
        .iter()
        .map(|o| columns(&o.name))
        .max()
        .unwrap_or(0);
    let name_w = longest.clamp(12, 24).min(width / 2);
    let items: Vec<ListItem> = app
        .options
        .iter()
        .enumerate()
        .skip(offset)
        .take(list_area.height as usize)
        .map(|(i, o)| {
            let lead = match o.kind {
                OptionKind::Candidate if i == 0 && typed.is_empty() && o.recommended => {
                    Span::styled("★ ", theme::warn())
                }
                OptionKind::Typed => Span::styled("+ ", theme::title()),
                _ => Span::raw("  "),
            };
            let name_style = if o.changed == Some(false) {
                theme::dim()
            } else {
                theme::strong()
            };
            let mut spans = vec![lead];
            spans.extend(highlight(
                &format!("{:<w$}", fit(&o.name, name_w), w = name_w),
                &needles,
                name_style,
                theme::matched(),
            ));
            // Only candidates have a score; the other notes start right after
            // the name so they fit a narrow pane.
            let room = width.saturating_sub(name_w + 1);
            match o.kind {
                OptionKind::Candidate => {
                    let score = o.score.map(|s| format!(" {s:>3} ")).unwrap_or_default();
                    let rest = room.saturating_sub(columns(&score));
                    let why_style = match o.changed {
                        Some(false) => theme::fg(theme::WARN),
                        _ => theme::fg(Color::Reset),
                    };
                    spans.push(Span::styled(score, theme::fg(theme::ACCENT)));
                    spans.push(Span::styled(fit(&o.why, rest), why_style));
                }
                OptionKind::Package => {
                    let (note, style) = match o.changed {
                        Some(true) => ("changed", theme::fg(theme::ACCENT)),
                        Some(false) => ("same in both updates", theme::dim()),
                        None => ("", theme::dim()),
                    };
                    spans.push(Span::styled(format!(" {}", fit(note, room)), style));
                }
                OptionKind::Typed => spans.push(Span::styled(
                    format!(" {}", fit(typed_note.0, room)),
                    typed_note.1,
                )),
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let list = List::new(items).highlight_style(theme::selected(focused));
    frame.render_stateful_widget(
        list,
        list_area,
        &mut ListState::default().with_selected(selected.map(|i| i - offset)),
    );
}

/// Bottom-right summary: position in the list, how the pair compares —
/// least important parts dropped first so it fits `width` columns.
fn status(app: &App, files: Option<&Files>, width: usize) -> String {
    let position = match app.selection() {
        Some(i) => Some(format!("{} of {}", i + 1, app.options.len())),
        None if !app.options.is_empty() => Some("↓ to browse".to_owned()),
        None => None,
    };
    let before = app
        .selected_pair()
        .map(|p| update_label(&p.before))
        .unwrap_or_default();
    // Most important first.
    let parts: Vec<String> = match files {
        Some(Files::Loading) => vec![format!("{} reading the file list…", spinner(app.tick))],
        Some(Files::Ready(listing)) => {
            let compared = match &listing.comparison {
                Comparison::Pending => {
                    Some(format!("{} comparing with {before}…", spinner(app.tick)))
                }
                Comparison::Done => Some(format!(
                    "{} changed since {before}",
                    listing.files.changed_count().unwrap_or(0)
                )),
                Comparison::Unavailable(_) => Some(format!("not compared with {before}")),
                Comparison::NotApplicable => None,
            };
            let count = format!("{} files", listing.files.names.len());
            [position, compared, Some(count)]
                .into_iter()
                .flatten()
                .collect()
        }
        Some(Files::Failed(error)) => vec![format!("file list unavailable: {}", fit(error, 40))],
        Some(Files::NeedsDownload { .. }) if app.listing_job().is_some() => {
            vec![format!("{} downloading — progress in ④", spinner(app.tick))]
        }
        Some(Files::NeedsDownload { size, .. }) => vec![match size {
            Some(size) => format!("list needs the {} package", size_label(*size)),
            None => "list needs the package download".to_owned(),
        }],
        None => position.into_iter().collect(),
    };
    let mut kept = parts.len();
    loop {
        let text = parts[..kept].join(" · ");
        if kept <= 1 || columns(&text) + 2 <= width {
            return if text.is_empty() {
                text
            } else {
                format!(" {} ", fit(&text, width.saturating_sub(2)))
            };
        }
        kept -= 1;
    }
}

/// What the pane says while the selected pair's list is not shown yet.
fn waiting(app: &App, pair: &PatchPair, files: &Files) -> Vec<Line<'static>> {
    let update = update_label(&pair.after);
    let mut lines = match files {
        Files::Loading => vec![Line::from(vec![
            Span::styled(format!("{} ", spinner(app.tick)), theme::title()),
            Span::raw(format!(
                "Reading the files of {update} ({}) — ★ is picked from them.",
                pair.short_product()
            )),
        ])],
        Files::NeedsDownload { package, size } => {
            let size = size
                .map(|s| format!(", {}", size_label(s)))
                .unwrap_or_default();
            if app.listing_job().is_some() {
                vec![Line::from(vec![
                    Span::styled(format!("{} ", spinner(app.tick)), theme::title()),
                    Span::raw(format!(
                        "Downloading {update}'s package{size} to list its files — progress in ④ (Esc twice cancels)."
                    )),
                ])]
            } else {
                vec![
                    Line::from(Span::raw(format!(
                        "{update} lists its files only inside its package ({package}{size})."
                    ))),
                    Line::from(vec![
                        Span::styled("Enter ", theme::strong()),
                        Span::raw(
                            "downloads it once and lists them (cached — the fetch reuses it) · or type a file name to fetch it directly.",
                        ),
                    ]),
                ]
            }
        }
        Files::Failed(error) => vec![
            Line::from(Span::styled(
                format!("✖ {update}'s files could not be read: {error}"),
                theme::bad(),
            )),
            Line::from(Span::styled(
                "Ctrl-R retries · or type a file name to fetch it anyway.",
                theme::dim(),
            )),
        ],
        Files::Ready(_) => vec![dim(&format!("{update} carries no files."))],
    };
    let hints: Vec<&str> = app
        .hints()
        .iter()
        .take(4)
        .map(|c| c.name.as_str())
        .collect();
    if !hints.is_empty() && matches!(files, Files::Loading | Files::NeedsDownload { .. }) {
        lines.push(Line::from(Span::styled(
            format!(
                "Microsoft's text points to {} — checked against {update} once its files are known.",
                hints.join(", ")
            ),
            theme::dim(),
        )));
    }
    lines
}

/// Why nothing is ★ in a listed update.
fn no_pick(app: &App, listing: &PairListing) -> String {
    let update = app
        .selected_pair()
        .map(|p| update_label(&p.after))
        .unwrap_or_default();
    if !listing.candidates.is_empty() {
        return format!(
            "Microsoft's candidates are unchanged in this pair — {update} did not fix them"
        );
    }
    let missing: Vec<&str> = listing.missing.iter().take(3).map(|n| n.as_str()).collect();
    if missing.is_empty() {
        format!("Microsoft's text names no file of {update} — choose one below or type its name")
    } else {
        format!(
            "{update} does not carry {} (named by Microsoft's text) — choose a file below",
            missing.join(", ")
        )
    }
}

fn dim(text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_owned(), theme::dim()))
}
