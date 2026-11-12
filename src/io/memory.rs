use super::{ReadAt, check_bounds};
use crate::error::Result;

/// An owned in-memory buffer.
pub struct MemorySource {
    data: Vec<u8>,
}

impl MemorySource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl ReadAt for MemorySource {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds("memory buffer", self.size(), offset, buf.len())?;
        let start = offset as usize;
        buf.copy_from_slice(&self.data[start..start + buf.len()]);
        Ok(())
    }
}
