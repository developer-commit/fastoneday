//! Terminal user interface: one screen, three panes (CVE, product, binary)
//! and a live progress log. Work happens on [`Worker`] threads; this loop
//! only draws and routes input.

mod complete;
mod input;
mod state;
mod theme;
mod view;

use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use ratatui::crossterm::event::{self, Event as TermEvent, KeyEventKind};

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
    let mut app = App::new(worker, initial);
    let result = (|| -> Result<()> {
        let mut last_tick = Instant::now();
        while !app.quit {
            terminal
                .draw(|frame| view::draw(frame, &app))
                .map_err(|e| Error::io("draw", e))?;
            let timeout = FRAME.saturating_sub(last_tick.elapsed());
            if event::poll(timeout).map_err(|e| Error::io("read input", e))?
                && let TermEvent::Key(key) =
                    event::read().map_err(|e| Error::io("read input", e))?
                && key.kind != KeyEventKind::Release
            {
                app.on_key(key);
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
    ratatui::restore();
    result
}
