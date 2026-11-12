use std::sync::Arc;

use crate::io::Meter;

/// Where the engine reports what it is doing. The UI implements this; a
/// step that is dropped without `finish` counts as failed.
pub trait Progress: Send + Sync {
    fn step(&self, label: String) -> Arc<dyn Step>;
    fn note(&self, message: String);
}

pub trait Step: Meter {
    fn finish(&self, detail: String);

    /// Bytes reported through this step's meter so far.
    fn transferred(&self) -> u64 {
        0
    }
}

/// Discards all progress (tests, background prefetches).
pub struct Silent;

struct SilentStep;

impl Meter for SilentStep {
    fn total(&self, _: Option<u64>) {}
    fn advance(&self, _: u64) {}
}

impl Step for SilentStep {
    fn finish(&self, _: String) {}
}

impl Progress for Silent {
    fn step(&self, _: String) -> Arc<dyn Step> {
        Arc::new(SilentStep)
    }
    fn note(&self, _: String) {}
}
