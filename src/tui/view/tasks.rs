use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
};

use super::util::{bar, bytes, fit, seconds, spinner};
use crate::tui::{
    state::{App, Job, JobState, StepState},
    theme,
};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let Some(job) = &app.job else {
        idle(frame, area, app);
        return;
    };
    let (title, style) = match &job.state {
        JobState::Running => (
            format!(" {} Fetching {} ", spinner(app.tick), job.title),
            theme::title(),
        ),
        JobState::Done(_) => (format!(" ✔ {} ", job.title), theme::strong().fg(theme::OK)),
        JobState::Failed(_) => (format!(" ✖ {} ", job.title), theme::strong().fg(theme::BAD)),
        JobState::Cancelled => (
            format!(" ◼ {} (cancelled) ", job.title),
            theme::strong().fg(theme::WARN),
        ),
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(job.is_running()))
        .title(Span::styled(title, style));
    let inner_width = area.width.saturating_sub(4) as usize;
    let mut lines = step_lines(job, app.tick, inner_width);
    match &job.state {
        JobState::Done(result) => {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("→ ", theme::strong().fg(theme::OK)),
                Span::styled(result.directory.display().to_string(), theme::strong()),
            ]));
            for side in [&result.before, &result.after] {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<6} ", side.side.label()), theme::strong()),
                    Span::raw(format!("{:<20} ", side.version.as_deref().unwrap_or("?"))),
                    Span::raw(format!("{:<11} ", side.update.label())),
                    Span::styled(
                        format!("sha256 {}…  ", &side.sha256.hex[..16]),
                        theme::dim(),
                    ),
                    Span::styled(
                        fit(&side.how.summary(), inner_width.saturating_sub(70)),
                        theme::dim(),
                    ),
                ]));
            }
            if let Some(f) = job.finished {
                lines.push(Line::from(Span::styled(
                    format!(
                        "  done in {} · manifest.json and README.txt written · Enter fetches again",
                        seconds(f)
                    ),
                    theme::dim(),
                )));
            }
        }
        JobState::Failed(error) => {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                format!("✖ {error}"),
                theme::strong().fg(theme::BAD),
            )));
            lines.push(Line::from(Span::styled(
                "  Try another product row (↑↓ in the product list) or another binary.",
                theme::dim(),
            )));
        }
        _ => {}
    }
    // Keep the newest lines visible.
    let visible = area.height.saturating_sub(2) as usize;
    let skip = lines.len().saturating_sub(visible);
    let lines: Vec<Line> = lines.into_iter().skip(skip).collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn step_lines(job: &Job, tick: u64, width: usize) -> Vec<Line<'static>> {
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
            StepState::Done => ("✔".to_owned(), theme::strong().fg(theme::OK)),
            StepState::Failed => ("✖".to_owned(), theme::strong().fg(theme::BAD)),
        };
        let mut spans = vec![
            Span::styled(format!("{icon} "), style),
            Span::raw(fit(&step.label, width.saturating_sub(40))),
        ];
        match step.state {
            StepState::Running => {
                if let Some(total) = step.total.filter(|t| *t > 0) {
                    spans.push(Span::styled(
                        format!(
                            "  {} {:>3}% {}/{}",
                            bar(step.done, total, 16),
                            step.done * 100 / total.max(1),
                            bytes(step.done),
                            bytes(total)
                        ),
                        theme::dim(),
                    ));
                } else if step.done > 0 {
                    spans.push(Span::styled(
                        format!("  {}", bytes(step.done)),
                        theme::dim(),
                    ));
                }
            }
            _ => {
                if !step.detail.is_empty() {
                    spans.push(Span::styled(
                        format!(
                            " — {}",
                            fit(&step.detail, width.saturating_sub(step.label.len() + 16))
                        ),
                        theme::dim(),
                    ));
                }
                if let Some(e) = step.elapsed {
                    spans.push(Span::styled(format!(" ({})", seconds(e)), theme::dim()));
                }
            }
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn idle(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(false))
        .title(Span::styled(" Progress ", theme::title()));
    let mut lines = vec![Line::from(Span::styled("Nothing running.", theme::dim()))];
    if let (Some(pair), Some(binary)) = (app.selected_pair(), app.chosen_binary()) {
        lines = vec![
            Line::from(vec![
                Span::styled("Ready: ", theme::strong()),
                Span::raw(format!(
                    "{binary} · {} · {} → {}",
                    pair.short_product(),
                    pair.before,
                    pair.after
                )),
            ]),
            Line::from(Span::styled(
                "Press Enter to fetch both sides. Each file is checked against the hash Microsoft ships in the update.",
                theme::dim(),
            )),
        ];
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("workspace: {}", app.workspace),
        theme::dim(),
    )));
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}
