//! Rendering. Every function here is a pure projection of [`App`].

mod binaries;
mod cve;
mod fetch;
mod footer;
mod header;
mod help;
mod products;
mod util;

use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    layout::{self, MIN_HEIGHT, MIN_WIDTH},
    state::App,
    theme,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let screen = frame.area();
    if layout::too_small(screen) {
        too_small(frame, screen);
        return;
    }
    let areas = layout::compute(screen, app);
    header::draw(frame, areas.header, app);
    cve::input(frame, areas.cve, app);
    cve::card(frame, areas.card, app);
    products::draw(frame, areas.products, app);
    binaries::draw(frame, areas.binary, app);
    fetch::draw(frame, areas.fetch, app);
    footer::toast(frame, areas.toast, app);
    footer::keys(frame, areas.footer, app);
    // Overlays last so they sit on top of the panes.
    cve::dropdown(frame, &areas, app);
    if app.show_help {
        help::draw(frame, screen);
    }
}

fn too_small(frame: &mut Frame, screen: Rect) {
    let lines = vec![
        Line::from(Span::styled("Terminal too small", theme::warn())),
        Line::from(Span::styled(
            format!(
                "fastoneday needs at least {MIN_WIDTH}×{MIN_HEIGHT}; this one is {}×{}.",
                screen.width, screen.height
            ),
            theme::dim(),
        )),
        Line::from(Span::styled(
            "Resize the window, or press Ctrl-C to quit.",
            theme::dim(),
        )),
    ];
    let y = screen.height.saturating_sub(3) / 2;
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        Rect {
            y: screen.y + y,
            height: 3.min(screen.height),
            ..screen
        },
    );
}
