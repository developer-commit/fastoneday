//! ② Patch pair: which product's (before update → fixing update) pair the
//! binary is chosen from.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Wrap},
};

use super::util::{columns, fit, spinner};
use crate::{
    app::{REMOTE_READABLE_BUILD, build_major},
    domain::{Family, PatchPair},
    tui::{
        state::{App, Files, Focus},
        theme,
    },
};

/// How a row's files will be read: icon, short tag, longer explanation.
/// Once the row's update has been opened, what actually happened wins over
/// the guess from its build number.
fn access(pair: &PatchPair, files: Option<&Files>) -> (&'static str, &'static str, &'static str) {
    match files {
        Some(Files::NeedsDownload { .. }) => {
            return ("↓", "MSU", "downloads the whole package once (cached)");
        }
        Some(Files::Ready(listing)) if pair.family == Family::Windows => {
            return if listing.files.remote {
                ("»", "range", "reads only the needed parts of the package")
            } else {
                ("↓", "MSU", "uses the downloaded package (cached)")
            };
        }
        _ => {}
    }
    match pair.family {
        Family::DefenderEngine => (
            "»",
            "CDN",
            "reads only the file's bytes from the Defender CDN",
        ),
        Family::OfficeC2r => (
            "»",
            "CDN",
            "reads only the needed files from the Office CDN",
        ),
        Family::OfficeMsi => ("↓", "CAB", "downloads the whole update package once"),
        Family::Windows if build_major(pair) >= REMOTE_READABLE_BUILD => {
            ("»", "range", "reads only the needed parts of the package")
        }
        Family::Windows => ("↓", "MSU", "downloads the whole package once (cached)"),
    }
}

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Products;
    let pairs = app.pairs();
    let title = if pairs.is_empty() {
        " ② Patch pair ".to_owned()
    } else {
        format!(" ② Patch pair · {} ", pairs.len())
    };
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(Span::styled(title, theme::title()));
    if let Some(pair) = app.selected_pair() {
        let (icon, _, why) = access(pair, app.files_for(pair));
        let star = if app.product == 0 {
            "★ recommended · "
        } else {
            ""
        };
        let fixed = pair
            .fixed_build
            .as_deref()
            .map(|b| format!("fixed in {b} · "))
            .unwrap_or_default();
        let note = fit(
            &format!(" {star}{fixed}{icon} {why} "),
            area.width.saturating_sub(4) as usize,
        );
        block = block.title_bottom(Line::from(Span::styled(note, theme::dim())).right_aligned());
    }
    if pairs.is_empty() {
        frame.render_widget(
            Paragraph::new(empty_state(app))
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let widest =
        |f: &dyn Fn(&PatchPair) -> String| pairs.iter().map(|p| columns(&f(p))).max().unwrap_or(0);
    let updates_width = widest(&|p| {
        format!(
            "{} → {}",
            short_update(&p.before.label()),
            short_update(&p.after.label())
        )
    });
    let tail_width = widest(&|p| {
        let (icon, how, _) = access(p, app.files_for(p));
        format!(" {icon} {how}")
    });
    // Each row: highlight symbol (1), star (2), name, space, updates, tail,
    // state (2) inside the borders (2).
    let name_width = (area.width as usize)
        .saturating_sub(updates_width + tail_width + 8)
        .max(8);
    let items: Vec<ListItem> = pairs
        .iter()
        .enumerate()
        .map(|(i, pair)| {
            let (icon, how, _) = access(pair, app.files_for(pair));
            let star = if i == 0 {
                Span::styled("★ ", theme::warn())
            } else {
                Span::raw("  ")
            };
            let state = match app.files_for(pair) {
                Some(Files::Loading) => {
                    Span::styled(format!(" {}", spinner(app.tick)), theme::dim())
                }
                Some(Files::Ready(_)) => Span::styled(" ✔", theme::fg(theme::OK)),
                Some(Files::Failed(_)) => Span::styled(" !", theme::fg(theme::WARN)),
                Some(Files::NeedsDownload { .. }) | None => Span::raw("  "),
            };
            let updates = format!(
                "{} → {}",
                short_update(&pair.before.label()),
                short_update(&pair.after.label())
            );
            let tail = format!(" {icon} {how}");
            ListItem::new(Line::from(vec![
                star,
                Span::styled(
                    format!("{:<w$}", fit(&pair.label(), name_width), w = name_width),
                    theme::strong(),
                ),
                Span::raw(" "),
                Span::raw(format!("{updates:<updates_width$}")),
                Span::styled(format!("{tail:<tail_width$}"), theme::dim()),
                state,
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(theme::selected(focused))
        .highlight_symbol(if focused { "▶" } else { " " });
    frame.render_stateful_widget(
        list,
        area,
        &mut ListState::default().with_selected(Some(app.product)),
    );
}

fn empty_state(app: &App) -> Vec<Line<'static>> {
    let Some(report) = &app.report else {
        return vec![
            Line::from(Span::styled(
                "The patch pairs Microsoft lists for this CVE appear here: per product, the update that fixed it and the one it replaced.",
                theme::dim(),
            )),
            Line::from(Span::styled(
                "★ marks the recommended pair: newest Windows on x64 when it can be read remotely. The binary is then chosen from its update's files.",
                theme::dim(),
            )),
        ];
    };
    let mut lines = vec![Line::from(Span::styled(
        "No product of this CVE can be fetched automatically.",
        theme::warn(),
    ))];
    if !report.detail.unsupported.is_empty() {
        lines.push(Line::from(Span::styled("Why:", theme::strong())));
        for reason in &report.detail.unsupported {
            lines.push(Line::from(vec![
                Span::styled("  · ", theme::dim()),
                Span::raw(reason.clone()),
            ]));
        }
    }
    lines.push(Line::from(vec![
        Span::styled("→ ", theme::title()),
        Span::raw("Press n to look up another CVE."),
    ]));
    lines
}

/// `16.0.17932.21140` → `17932.21140`; KBs and engine versions unchanged.
fn short_update(label: &str) -> String {
    label.strip_prefix("16.0.").unwrap_or(label).to_owned()
}
