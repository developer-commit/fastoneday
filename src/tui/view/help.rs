use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Paragraph, Wrap},
};

use crate::tui::theme;

const HELP: &[(&str, &str)] = &[
    (
        "Flow",
        "type a CVE → Enter → (product and binary are pre-selected) → Enter",
    ),
    (
        "CVE box",
        "id or title words · ↑↓ pick · Tab/→ complete · Enter load",
    ),
    (
        "Products",
        "★ recommended · ⚡ read remotely in seconds · ⬇ whole package download",
    ),
    (
        "Binary",
        "★ best guess · typing searches the files in the update · Tab completes",
    ),
    (
        "Tab / Shift-Tab",
        "next / previous pane (Tab completes first if a suggestion is open)",
    ),
    (
        "Esc",
        "close suggestions · cancel a running fetch · back to the CVE box",
    ),
    ("Ctrl-W / Ctrl-U", "delete word / clear input"),
    ("Ctrl-C", "cancel a running fetch, or quit"),
    ("", ""),
    (
        "Source of truth",
        "the KB's Update Catalog package, or the Office CDN build",
    ),
    (
        "Exact bytes",
        "full file · null delta · Symbol Server by the package's identity ·",
    ),
    (
        "",
        "delta applied to the checkpoint or release-image baseline",
    ),
    (
        "Verification",
        "every file must match the hash Microsoft put in the package",
    ),
    (
        "Output",
        "cases/<CVE>/<binary>/<product>/{before,after}/ + PDBs + manifest.json",
    ),
];

pub fn draw(frame: &mut Frame, area: Rect) {
    let width = area.width.saturating_sub(4).min(96);
    let height = (HELP.len() as u16 + 4).min(area.height);
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:>16}  "), theme::title()),
                Span::raw(*v),
            ])
        })
        .collect();
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" help · any key closes "),
        ),
        popup,
    );
}
