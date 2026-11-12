use super::{ReadAt, Source, check_bounds};
use crate::error::Result;

/// A window `[start, start + len)` of another source.
pub struct SliceSource {
    inner: Source,
    start: u64,
    len: u64,
}

impl SliceSource {
    pub fn new(inner: Source, start: u64, len: u64) -> Self {
        Self { inner, start, len }
    }
}

impl ReadAt for SliceSource {
    fn size(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds("slice", self.len, offset, buf.len())?;
        self.inner.read_exact_at(self.start + offset, buf)
    }
}
