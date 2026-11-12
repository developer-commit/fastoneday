use std::io::{self, Read, Seek, SeekFrom};

use super::Source;

/// `Read + Seek` adapter over a [`Source`], for crates that want a stream.
pub struct SourceCursor {
    source: Source,
    position: u64,
}

impl SourceCursor {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            position: 0,
        }
    }
}

impl Read for SourceCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.source.size();
        if self.position >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((size - self.position) as usize);
        self.source
            .read_exact_at(self.position, &mut buf[..n])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.source.size() as i128;
        let target = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => size + d as i128,
            SeekFrom::Current(d) => self.position as i128 + d as i128,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}
