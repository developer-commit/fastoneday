//! [`Progress`] implementation that turns engine steps into UI events.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::Sender,
    },
    time::{Duration, Instant},
};

use super::events::{Event, JobId};
use crate::{
    acquire::{Progress, Step},
    io::Meter,
};

const THROTTLE: Duration = Duration::from_millis(120);

pub struct ChannelProgress {
    tx: Sender<Event>,
    job: JobId,
    next: AtomicU64,
}

impl ChannelProgress {
    pub fn new(tx: Sender<Event>, job: JobId) -> Self {
        Self {
            tx,
            job,
            next: AtomicU64::new(1),
        }
    }
}

impl Progress for ChannelProgress {
    fn step(&self, label: String) -> Arc<dyn Step> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(Event::StepStarted {
            job: self.job,
            step: id,
            label,
        });
        Arc::new(ChannelStep {
            tx: self.tx.clone(),
            job: self.job,
            id,
            done: AtomicU64::new(0),
            total: Mutex::new(None),
            last: Mutex::new(Instant::now() - THROTTLE),
            finished: AtomicBool::new(false),
        })
    }

    fn note(&self, message: String) {
        let _ = self.tx.send(Event::Note {
            job: self.job,
            text: message,
        });
    }
}

struct ChannelStep {
    tx: Sender<Event>,
    job: JobId,
    id: u64,
    done: AtomicU64,
    total: Mutex<Option<u64>>,
    last: Mutex<Instant>,
    finished: AtomicBool,
}

impl ChannelStep {
    fn emit(&self, force: bool) {
        let mut last = self.last.lock().expect("step clock");
        if !force && last.elapsed() < THROTTLE {
            return;
        }
        *last = Instant::now();
        let _ = self.tx.send(Event::StepProgress {
            job: self.job,
            step: self.id,
            done: self.done.load(Ordering::Relaxed),
            total: *self.total.lock().expect("total"),
        });
    }
}

impl Meter for ChannelStep {
    fn total(&self, bytes: Option<u64>) {
        *self.total.lock().expect("total") = bytes;
        self.emit(true);
    }

    fn advance(&self, bytes: u64) {
        self.done.fetch_add(bytes, Ordering::Relaxed);
        self.emit(false);
    }
}

impl Step for ChannelStep {
    fn finish(&self, detail: String) {
        if !self.finished.swap(true, Ordering::SeqCst) {
            let _ = self.tx.send(Event::StepFinished {
                job: self.job,
                step: self.id,
                ok: true,
                detail,
            });
        }
    }

    fn transferred(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }
}

impl Drop for ChannelStep {
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::SeqCst) {
            let _ = self.tx.send(Event::StepFinished {
                job: self.job,
                step: self.id,
                ok: false,
                detail: String::new(),
            });
        }
    }
}
