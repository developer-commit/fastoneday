//! ④ Fetch: what will be fetched, live progress, and the result.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
};

use super::util::{bar, bytes, columns, fit, fit_left, rate, seconds, spinner};
use crate::{
    domain::Acquired,
    tui::{
        state::{App, Focus, Job, JobKind, JobState, StepState, display_path},
        theme,
    },
};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Fetch;
    let width = area.width.saturating_sub(4) as usize;
    let Some(job) = &app.job else {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(theme::border(focused))
            .title(Span::styled(" ④ Fetch ", theme::title()));
        frame.render_widget(
            Paragraph::new(idle(app, width))
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    };
    let elapsed = seconds(job.elapsed());
    let (title, style) = match &job.state {
        JobState::Running if job.kind == JobKind::List => (
            format!(
                " ④ Fetch · {} listing {} · {} · {elapsed} ",
                spinner(app.tick),
                job.binary,
                job.product
            ),
            theme::title(),
        ),
        JobState::Listed => (
            format!(" ④ Fetch · ✔ {} listed · {} ", job.binary, job.product),
            theme::ok(),
        ),
        JobState::Running => (
            format!(
                " ④ Fetch · {} {} · {} · {elapsed} ",
                spinner(app.tick),
                job.binary,
                job.product
            ),
            theme::title(),
        ),
        JobState::Done(_) => (
            format!(
                " ④ Fetch · ✔ {} · {} · done in {elapsed} ",
                job.binary, job.product
            ),
            theme::ok(),
        ),
        JobState::Failed(_) if job.kind == JobKind::List => (
            format!(" ④ Fetch · ✖ listing {} · {} ", job.binary, job.product),
            theme::bad(),
        ),
        JobState::Failed(_) => (
            format!(" ④ Fetch · ✖ {} · {} ", job.binary, job.product),
            theme::bad(),
        ),
        JobState::Cancelled if job.kind == JobKind::List => (
            format!(
                " ④ Fetch · ◼ listing {} · cancelled — Enter in ③ resumes the download ",
                job.binary
            ),
            theme::warn(),
        ),
        JobState::Cancelled => (
            format!(" ④ Fetch · ◼ {} · cancelled ", job.binary),
            theme::warn(),
        ),
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused || job.is_running()))
        .title(Span::styled(title, style));
    let mut lines = match &job.state {
        JobState::Done(result) => {
            let mut lines = vec![
                side_line("before", &result.before, width),
                side_line("after", &result.after, width),
                Line::from(vec![
                    Span::styled("  folder ", theme::strong()),
                    Span::styled(
                        fit_left(&display_path(&result.directory), width.saturating_sub(10)),
                        theme::strong(),
                    ),
                ]),
                Line::from(Span::styled(
                    fit(
                        "  manifest.json · README.txt · PDBs next to each binary",
                        width,
                    ),
                    theme::dim(),
                )),
            ];
            if result.before.sha256 == result.after.sha256 {
                lines.insert(
                    0,
                    Line::from(Span::styled(
                        "⚠ both sides are identical — this update did not change the file; the fix is elsewhere",
                        theme::warn(),
                    )),
                );
            }
            lines
        }
        JobState::Failed(failure) => {
            let mut lines = steps(job, app.tick, width);
            lines.push(Line::from(Span::styled(
                format!("✖ {}", failure.message),
                theme::bad(),
            )));
            if let Some(hint) = &failure.hint {
                lines.push(Line::from(vec![
                    Span::styled("→ ", theme::title()),
                    Span::raw(hint.clone()),
                ]));
            }
            lines
        }
        JobState::Listed => {
            let mut lines = steps(job, app.tick, width);
            lines.push(Line::from(vec![
                Span::styled("→ ", theme::title()),
                Span::raw(format!(
                    "{}'s files are in ③ — pick a binary there; the fetch reuses this download.",
                    job.binary
                )),
            ]));
            lines
        }
        _ => steps(job, app.tick, width),
    };
    // Keep the newest lines in view.
    let visible = area.height.saturating_sub(2) as usize;
    if lines.len() > visible {
        lines.drain(..lines.len() - visible);
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn idle(app: &App, width: usize) -> Vec<Line<'static>> {
    match (app.selected_pair(), app.chosen_binary()) {
        (Some(pair), Some(binary)) => vec![
            Line::from(vec![
                Span::styled("Ready  ", theme::ok()),
                Span::styled(binary.to_string(), theme::strong()),
                Span::raw(fit(
                    &format!(
                        " · {} · before {} → after {}",
                        pair.short_product(),
                        pair.before,
                        pair.after
                    ),
                    width.saturating_sub(binary.as_str().len() + 8),
                )),
            ]),
            Line::from(Span::styled(
                "Press Enter to fetch both sides — each file is checked against Microsoft's hash or signature before it is saved.",
                theme::dim(),
            )),
        ],
        (Some(pair), None) => vec![Line::from(Span::styled(
            format!(
                "Pick a binary of {} in ③ (or type a file name), then press Enter.",
                crate::tui::state::update_label(&pair.after)
            ),
            theme::dim(),
        ))],
        _ => vec![Line::from(Span::styled(
            format!(
                "Cases are saved under {}",
                fit_left(&app.workspace, width.saturating_sub(23))
            ),
            theme::dim(),
        ))],
    }
}

fn side_line(label: &str, side: &Acquired, width: usize) -> Line<'static> {
    let verified = match &side.verified_with {
        Some(digest) => format!("{} ✔", digest.algorithm.name()),
        None => "unverified".into(),
    };
    let pdb = if side.pdb.is_some() {
        "PDB ✔"
    } else {
        "no PDB"
    };
    Line::from(vec![
        Span::styled(format!("  {label:<6} "), theme::strong()),
        Span::styled(
            format!("{:<16} ", side.version.as_deref().unwrap_or("?")),
            theme::fg(theme::ACCENT),
        ),
        Span::styled(format!("{verified} · {pdb} · "), theme::fg(theme::OK)),
        Span::styled(
            fit(&side.how.summary(), width.saturating_sub(48)),
            theme::dim(),
        ),
    ])
}

fn steps(job: &Job, tick: u64, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for note in &job.notes {
        lines.push(Line::from(Span::styled(
            fit(&format!("• {note}"), width),
            theme::dim(),
        )));
    }
    for step in &job.steps {
        let (icon, style) = match step.state {
            StepState::Running => (spinner(tick).to_owned(), theme::title()),
            StepState::Done => ("✔".to_owned(), theme::ok()),
            StepState::Failed => ("✖".to_owned(), theme::bad()),
        };
        if step.state == StepState::Running {
            lines.push(Line::from(vec![
                Span::styled(format!("{icon} "), style),
                Span::raw(fit(&step.label, width.saturating_sub(2))),
            ]));
            // The transfer goes on its own line so it never wraps mid-number.
            let speed = rate(step.done, step.started.elapsed())
                .map(|s| format!(" · {s}"))
                .unwrap_or_default();
            let progress = match step.total.filter(|t| *t > 0) {
                Some(total) => Some(format!(
                    "  {} {:>3}% · {} of {}{speed}",
                    bar(step.done, total, (width / 4).clamp(10, 30)),
                    step.done * 100 / total.max(1),
                    bytes(step.done),
                    bytes(total)
                )),
                None if step.done > 0 => Some(format!("  {}{speed}", bytes(step.done))),
                None => None,
            };
            if let Some(progress) = progress {
                lines.push(Line::from(Span::styled(
                    fit(&progress, width),
                    theme::dim(),
                )));
            }
            continue;
        }
        let elapsed = step
            .elapsed
            .map(|e| format!(" ({})", seconds(e)))
            .unwrap_or_default();
        let detail = if step.detail.is_empty() {
            String::new()
        } else {
            format!(" — {}", step.detail)
        };
        let label_room = width.saturating_sub(2 + columns(&elapsed));
        let label = fit(
            &step.label,
            label_room.saturating_sub(columns(&detail).min(label_room / 2)),
        );
        let detail_room = label_room.saturating_sub(columns(&label));
        lines.push(Line::from(vec![
            Span::styled(format!("{icon} "), style),
            Span::raw(label),
            Span::styled(fit(&detail, detail_room), theme::dim()),
            Span::styled(elapsed, theme::dim()),
        ]));
    }
    lines
}
