//! Terminal user interface: one screen, four panes that follow the flow
//! (① CVE → ② Patch pair → ③ Binary of that pair's update → ④ Fetch). Work happens on [`Worker`]
//! threads; this loop only draws and routes input.

mod actions;
mod complete;
mod input;
mod layout;
mod state;
mod theme;
mod view;

use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use ratatui::crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as TermEvent, KeyEventKind},
    execute,
};

use crate::{
    app::{Services, Worker},
    error::{Error, Result},
};
use state::App;

const FRAME: Duration = Duration::from_millis(80);

pub fn run(services: Arc<Services>, initial: Option<String>) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let worker = Worker::new(services, tx);
    let mut terminal = ratatui::try_init().map_err(|e| Error::io("start the terminal UI", e))?;
    // Mouse support is a convenience; a terminal that refuses it still works.
    let mouse = execute!(std::io::stdout(), EnableMouseCapture).is_ok();
    let mut app = App::new(worker, initial);
    let result = (|| -> Result<()> {
        let mut last_tick = Instant::now();
        while !app.quit {
            app.screen = terminal
                .size()
                .map(|s| ratatui::layout::Rect::new(0, 0, s.width, s.height))
                .map_err(|e| Error::io("read the terminal size", e))?;
            terminal
                .draw(|frame| view::draw(frame, &app))
                .map_err(|e| Error::io("draw", e))?;
            let timeout = FRAME.saturating_sub(last_tick.elapsed());
            if event::poll(timeout).map_err(|e| Error::io("read input", e))? {
                match event::read().map_err(|e| Error::io("read input", e))? {
                    TermEvent::Key(key) if key.kind != KeyEventKind::Release => app.on_key(key),
                    TermEvent::Mouse(mouse) => app.on_mouse(mouse),
                    _ => {}
                }
            }
            while let Ok(event) = rx.try_recv() {
                app.on_event(event);
            }
            if last_tick.elapsed() >= FRAME {
                app.on_tick();
                last_tick = Instant::now();
            }
        }
        Ok(())
    })();
    if mouse {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    result
}
