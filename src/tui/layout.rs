//! Where everything goes on screen. Shared by drawing and by mouse
//! hit-testing, so a click always lands on what is drawn there.

use ratatui::layout::{Constraint, Layout, Rect};

use super::state::App;

/// Below this the screen shows a "terminal too small" notice instead.
pub const MIN_WIDTH: u16 = 64;
pub const MIN_HEIGHT: u16 = 18;
/// From this width the product and binary panes sit side by side.
const WIDE: u16 = 100;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Areas {
    pub screen: Rect,
    pub header: Rect,
    pub cve: Rect,
    pub card: Rect,
    pub products: Rect,
    pub binary: Rect,
    pub fetch: Rect,
    /// Zero height when there is no message.
    pub toast: Rect,
    pub footer: Rect,
}

pub fn too_small(screen: Rect) -> bool {
    screen.width < MIN_WIDTH || screen.height < MIN_HEIGHT
}

pub fn compute(screen: Rect, app: &App) -> Areas {
    let card = match screen.height {
        34.. => 6,
        26.. => 5,
        _ => 3,
    };
    let toast = u16::from(app.toast_text().is_some());
    let fixed = 1 + 3 + card + toast + 1;
    let rest = screen.height.saturating_sub(fixed);
    let fetch = if app.job.is_some() {
        (rest * 2 / 5).max(8).min(rest.saturating_sub(6))
    } else {
        4.min(rest.saturating_sub(6))
    };
    let [header, cve, card, middle, fetch, toast, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(card),
        Constraint::Min(6),
        Constraint::Length(fetch),
        Constraint::Length(toast),
        Constraint::Length(1),
    ])
    .areas(screen);
    let [products, binary] = if screen.width >= WIDE {
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)]).areas(middle)
    } else {
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(middle)
    };
    Areas {
        screen,
        header,
        cve,
        card,
        products,
        binary,
        fetch,
        toast,
        footer,
    }
}

/// The CVE suggestion list: right under the input, same width, never over
/// the footer.
pub fn dropdown(areas: &Areas, rows: usize) -> Rect {
    let top = areas.cve.bottom();
    let room = areas.footer.y.saturating_sub(top);
    Rect {
        x: areas.cve.x,
        y: top,
        width: areas.cve.width,
        // At least as tall as the CVE card, so no stray card border shows.
        height: (rows as u16 + 2).max(areas.card.height).min(room).min(14),
    }
}

/// First visible row of a list of `height` rows showing `selected`, the
/// same rule ratatui applies when it scrolls the selection into view.
pub fn list_offset(selected: usize, height: u16) -> usize {
    (selected + 1).saturating_sub(height.max(1) as usize)
}

/// Inside of a bordered block.
pub fn inner(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

pub fn contains(area: Rect, x: u16, y: u16) -> bool {
    x >= area.x && x < area.right() && y >= area.y && y < area.bottom()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_keep_the_selection_visible() {
        assert_eq!(list_offset(0, 5), 0);
        assert_eq!(list_offset(4, 5), 0);
        assert_eq!(list_offset(5, 5), 1);
        assert_eq!(list_offset(12, 5), 8);
    }
}
