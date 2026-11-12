//! Rendering. Every function here is a pure projection of [`App`].

mod binaries;
mod cve;
mod footer;
mod help;
mod products;
mod tasks;
mod util;

use ratatui::{
    Frame,
    layout::{Constraint, Layout},
};

use super::state::App;

pub fn draw(frame: &mut Frame, app: &App) {
    let [header, cve_input, info, middle, tasks_area, footer_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Min(8),
        Constraint::Percentage(36),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [products_area, binaries_area] =
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)]).areas(middle);

    footer::header(frame, header, app);
    cve::info(frame, info, app);
    products::draw(frame, products_area, app);
    binaries::draw(frame, binaries_area, app);
    tasks::draw(frame, tasks_area, app);
    footer::draw(frame, footer_area, app);
    // Drawn last so the suggestion popup overlays the panes below it.
    cve::input(frame, cve_input, app);
    if app.show_help {
        help::draw(frame, frame.area());
    }
}
