use super::{ReadAt, check_bounds};
use crate::error::{Error, Result};

/// A remote file of which only some pieces were fetched (for example a
/// cabinet's header and one of its folders). Reads must fall inside fetched
/// bytes (adjacent pieces may be spanned); anything else is an error rather
/// than a silent zero fill.
pub struct SparseSource {
    size: u64,
    pieces: Vec<(u64, Vec<u8>)>,
}

impl SparseSource {
    pub fn new(size: u64) -> Self {
        Self {
            size,
            pieces: Vec::new(),
        }
    }

    /// Adds the bytes that start at `offset`.
    pub fn with(mut self, offset: u64, data: Vec<u8>) -> Self {
        self.pieces.push((offset, data));
        self
    }
}

impl ReadAt for SparseSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds("partial download", self.size, offset, buf.len())?;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let (start, data) = self
                .pieces
                .iter()
                .find(|(start, data)| *start <= at && at < start + data.len() as u64)
                .ok_or_else(|| {
                    Error::format("partial download", format!("byte {at} was not downloaded"))
                })?;
            let from = (at - start) as usize;
            let take = (data.len() - from).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&data[from..from + take]);
            done += take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_inside_fetched_pieces() {
        let source = SparseSource::new(100)
            .with(0, vec![1, 2, 3])
            .with(50, vec![7, 8, 9, 10]);
        assert_eq!(source.read_vec(1, 2).unwrap(), [2, 3]);
        assert_eq!(source.read_vec(51, 3).unwrap(), [8, 9, 10]);
        assert!(source.read_vec(2, 2).is_err());
        let joined = SparseSource::new(10)
            .with(0, vec![1, 2])
            .with(2, vec![3, 4]);
        assert_eq!(joined.read_vec(1, 3).unwrap(), [2, 3, 4]);
        assert!(source.read_vec(20, 1).is_err());
        assert!(source.read_vec(99, 2).is_err());
    }
}
