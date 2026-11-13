//! Colours and styles in one place. Honours `NO_COLOR` (https://no-color.org):
//! when it is set, meaning is carried by symbols and bold/reverse only.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

pub const ACCENT: Color = Color::Cyan;
pub const OK: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const BAD: Color = Color::Red;
pub const DIM: Color = Color::DarkGray;

fn colors() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()))
}

/// Foreground colour, or nothing under `NO_COLOR`.
pub fn fg(color: Color) -> Style {
    if colors() {
        Style::new().fg(color)
    } else {
        Style::new()
    }
}

pub fn title() -> Style {
    fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn border(focused: bool) -> Style {
    match (focused, colors()) {
        (true, true) => Style::new().fg(ACCENT),
        (true, false) => Style::new().add_modifier(Modifier::BOLD),
        (false, true) => Style::new().fg(DIM),
        (false, false) => Style::new().add_modifier(Modifier::DIM),
    }
}

pub fn dim() -> Style {
    if colors() {
        Style::new().fg(DIM)
    } else {
        Style::new().add_modifier(Modifier::DIM)
    }
}

pub fn strong() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

pub fn ok() -> Style {
    fg(OK).add_modifier(Modifier::BOLD)
}

pub fn warn() -> Style {
    fg(WARN).add_modifier(Modifier::BOLD)
}

pub fn bad() -> Style {
    fg(BAD).add_modifier(Modifier::BOLD)
}

/// The highlighted row of the focused list; a subtler mark when the list
/// does not have focus, so it is always clear where keys go.
pub fn selected(focused: bool) -> Style {
    if focused {
        Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }
}

/// Matched characters in search results.
pub fn matched() -> Style {
    fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// A key cap in the footer, e.g. ` Enter `.
pub fn key() -> Style {
    if colors() {
        Style::new().fg(Color::Black).bg(ACCENT)
    } else {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}

/// A small inverted label such as a severity badge.
pub fn badge(color: Color) -> Style {
    if colors() {
        Style::new()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}
