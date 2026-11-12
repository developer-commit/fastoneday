use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::error::{Error, Result};

/// Cooperative cancellation shared between the UI and workers.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// `Err(Cancelled)` once cancelled; sprinkle in long loops.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Receives byte-level progress for the current step.
pub trait Meter: Send + Sync {
    /// Expected total for the current transfer, when known.
    fn total(&self, bytes: Option<u64>);
    /// Bytes transferred (or processed) since the last call.
    fn advance(&self, bytes: u64);
}

/// A meter that ignores everything.
pub struct NullMeter;

impl Meter for NullMeter {
    fn total(&self, _: Option<u64>) {}
    fn advance(&self, _: u64) {}
}
