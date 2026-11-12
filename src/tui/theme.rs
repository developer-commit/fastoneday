//! Colours and styles in one place.

use ratatui::style::{Color, Modifier, Style};

pub const ACCENT: Color = Color::Cyan;
pub const OK: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const BAD: Color = Color::Red;
pub const DIM: Color = Color::DarkGray;

pub fn title() -> Style {
    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn border(focused: bool) -> Style {
    if focused {
        Style::new().fg(ACCENT)
    } else {
        Style::new().fg(DIM)
    }
}

pub fn dim() -> Style {
    Style::new().fg(DIM)
}

pub fn selected() -> Style {
    Style::new()
        .bg(Color::Rgb(40, 60, 80))
        .add_modifier(Modifier::BOLD)
}

pub fn key() -> Style {
    Style::new().fg(Color::Black).bg(ACCENT)
}

pub fn strong() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}
