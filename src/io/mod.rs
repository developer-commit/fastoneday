//! Random-access byte sources.
//!
//! Every container parser reads through [`ReadAt`], so the same CAB/WIM code
//! works on a local file, an in-memory buffer, a slice of another source, a
//! decompressed CAB folder, or a remote file fetched with HTTP range requests.

mod control;
mod cursor;
mod file;
mod memory;
mod slice;

use std::sync::Arc;

pub use control::{Cancel, Meter, NullMeter};
pub use cursor::SourceCursor;
pub use file::FileSource;
pub use memory::MemorySource;
pub use slice::SliceSource;

use crate::error::{Error, Result};

/// Positional, thread-safe reads.
pub trait ReadAt: Send + Sync {
    /// Total length in bytes.
    fn size(&self) -> u64;

    /// Fill `buf` completely from `offset` or fail.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Convenience: read `len` bytes at `offset` into a new vector.
    fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Shared handle to any source.
pub type Source = Arc<dyn ReadAt>;

/// Bounds check shared by implementations.
pub(crate) fn check_bounds(what: &str, size: u64, offset: u64, len: usize) -> Result<()> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Ok(()),
        _ => Err(Error::format(
            what,
            format!("read of {len} bytes at {offset} is beyond the end ({size} bytes)"),
        )),
    }
}

/// Little-endian field helpers used by the binary parsers.
pub mod le {
    pub fn u16(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }
    pub fn u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
    }
    pub fn u64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
    }
}
