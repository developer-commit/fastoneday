//! The `?` overlay: every key, grouped by where it works.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Paragraph, Wrap},
};

use crate::tui::theme;

/// `(key, what)`; a row with an empty key and a value is a section title.
const HELP: &[(&str, &str)] = &[
    ("", "The flow"),
    (
        "①→④",
        "type a CVE · Enter · ② pick its patch pair (★) · Enter · ③ pick a binary of that pair's update (★) · Enter fetches",
    ),
    ("", "Anywhere"),
    (
        "Tab / Shift-Tab",
        "next / previous pane (in a search box Tab first completes the highlighted item)",
    ),
    (
        "Esc",
        "close the list · go back one pane · twice while a job runs: cancel it",
    ),
    ("Ctrl-R", "retry the failed lookup, file list or fetch"),
    ("? / F1", "this help (any key closes it)"),
    ("Ctrl-C", "cancel a running job, or quit"),
    (
        "mouse",
        "click a pane or row · double-click to use it · wheel scrolls · Shift/Option-drag selects text",
    ),
    ("", "① CVE"),
    (
        "text",
        "an id (2024-38193, CVE-2024-38193) or title words (clfs, excel rce, defender)",
    ),
    (
        "↑↓ / Enter",
        "pick a suggestion / load it · ⚠ exploited in the wild · ↺ from your history",
    ),
    ("Ctrl-W / Ctrl-U", "delete a word / clear"),
    ("", "② Patch pair"),
    (
        "↑↓ j k / Enter",
        "choose a row (update replaced → update with the fix) / list the binaries of its update",
    ),
    (
        "★ · hotpatch",
        "recommended pair · a no-reboot hotpatch next to the cumulative update of the same product",
    ),
    (
        "» / ↓",
        "only the needed bytes are read / the whole package is downloaded once (cached)",
    ),
    ("", "③ Binary — always a file of the pair's update"),
    (
        "★",
        "the file Microsoft's text points to (name, component, Office app) among the update's files",
    ),
    (
        "changed · same",
        "differs from the update it replaced · identical there (never ★: nothing to diff)",
    ),
    (
        "any name",
        "search the update's files · + fetches the name exactly as typed · ↓ packages: Enter lists them",
    ),
    ("", "④ Fetch"),
    (
        "o / y",
        "open the case folder / copy its path (OSC 52 clipboard)",
    ),
    ("r · n · q", "retry · look up another CVE · quit"),
    ("", "Where the files come from"),
    (
        "Windows",
        "the KB's package in the Update Catalog; deltas rebuilt or taken from the Symbol Server",
    ),
    (
        "Office",
        "the Office CDN (Click-to-Run) or the Catalog (MSI)",
    ),
    (
        "Defender",
        "the Defender CDN package Microsoft's release notes name for the engine version",
    ),
    (
        "verified",
        "every file must match Microsoft's hash or Authenticode signature before it is saved",
    ),
];

pub fn draw(frame: &mut Frame, area: Rect) {
    let width = area.width.saturating_sub(4).min(110);
    let height = (HELP.len() as u16 + 3).min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(key, what)| {
            if key.is_empty() {
                Line::from(Span::styled(what.to_string(), theme::title()))
            } else {
                Line::from(vec![
                    Span::styled(format!("  {key:<17} "), theme::strong()),
                    Span::raw(*what),
                ])
            }
        })
        .collect();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(theme::border(true))
                .title(Span::styled(" help ", theme::title()))
                .title(Line::from(Span::styled(" any key closes ", theme::dim())).right_aligned()),
        ),
        popup,
    );
}
