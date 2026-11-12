//! Compressed WIM resources: the chunk framing (ours) around chunk
//! decompression (wimlib's, via `fastoneday-codecs`).
//!
//! * Non-solid resources: a table of `chunks - 1` offsets (4 bytes, or 8 for
//!   resources over 4 GiB) followed by independently compressed chunks of
//!   the header's chunk size.
//! * Solid resources (ESD, update metadata images): a 16-byte header
//!   (uncompressed size, chunk size, format) and a table of `chunks`
//!   compressed sizes, then the chunks.
//!
//! A chunk whose stored size equals its uncompressed size is stored verbatim.
//! These rules follow wimlib's own reader (`resource.c`, `blob_table.c`).

use std::ops::Range;

use fastoneday_codecs::wim::{ChunkCodec, ChunkDecompressor};

use super::header::{Resource, WimCompression};
use crate::{
    error::{Error, Result},
    io::{ReadAt, le},
};

pub fn codec_for(compression: WimCompression) -> Option<ChunkCodec> {
    match compression {
        WimCompression::None => None,
        WimCompression::Xpress => Some(ChunkCodec::Xpress),
        WimCompression::Lzx => Some(ChunkCodec::Lzx),
        WimCompression::Lzms => Some(ChunkCodec::Lzms),
    }
}

fn decode(
    decompressor: Option<&mut ChunkDecompressor>,
    raw: &[u8],
    plain_len: usize,
) -> Result<Vec<u8>> {
    if raw.len() == plain_len {
        return Ok(raw.to_vec());
    }
    if raw.len() > plain_len {
        return Err(Error::format(
            "WIM chunk",
            "stored chunk is larger than its plaintext",
        ));
    }
    let Some(decompressor) = decompressor else {
        return Err(Error::format(
            "WIM chunk",
            "compressed chunk in an uncompressed resource",
        ));
    };
    decompressor
        .decompress(raw, plain_len)
        .map_err(|e| Error::format("WIM chunk", e.to_string()))
}

fn check_chunk_size(chunk_size: u64) -> Result<()> {
    if chunk_size.is_power_of_two() && chunk_size <= 1 << 30 {
        Ok(())
    } else {
        Err(Error::format(
            "WIM resource",
            format!("invalid chunk size {chunk_size}"),
        ))
    }
}

/// Reads and decompresses a whole non-solid resource.
pub fn read_chunked(
    source: &dyn ReadAt,
    resource: &Resource,
    chunk_size: usize,
    codec: ChunkCodec,
) -> Result<Vec<u8>> {
    let total = resource.original_size as usize;
    if total == 0 {
        return Ok(Vec::new());
    }
    check_chunk_size(chunk_size as u64)?;
    let raw = source.read_vec(resource.offset, resource.stored_size as usize)?;
    let chunks = total.div_ceil(chunk_size);
    let entry = if resource.original_size > u32::MAX as u64 {
        8
    } else {
        4
    };
    let table_len = (chunks - 1) * entry;
    let data = raw
        .get(table_len..)
        .ok_or_else(|| Error::format("WIM resource", "chunk table does not fit"))?;
    let mut bounds = Vec::with_capacity(chunks + 1);
    bounds.push(0usize);
    for i in 0..chunks - 1 {
        bounds.push(if entry == 8 {
            le::u64(&raw, i * 8) as usize
        } else {
            le::u32(&raw, i * 4) as usize
        });
    }
    bounds.push(data.len());

    let mut decompressor = ChunkDecompressor::new(codec, chunk_size)
        .map_err(|e| Error::format("WIM resource", e.to_string()))?;
    let mut out = Vec::with_capacity(total);
    for i in 0..chunks {
        let (start, end) = (bounds[i], bounds[i + 1]);
        if end < start || end > data.len() {
            return Err(Error::format("WIM resource", "chunk offsets out of order"));
        }
        let plain = if i + 1 < chunks {
            chunk_size
        } else {
            total - chunk_size * (chunks - 1)
        };
        out.extend_from_slice(&decode(Some(&mut decompressor), &data[start..end], plain)?);
    }
    Ok(out)
}

/// Layout of one solid resource.
#[derive(Debug, Clone)]
pub struct SolidLayout {
    uncompressed: u64,
    chunk_size: u64,
    /// `None`: format 0, every chunk is stored.
    codec: Option<ChunkCodec>,
    /// Offset of each chunk within the resource, plus the end.
    bounds: Vec<u64>,
}

const SOLID_HEADER: usize = 16;

impl SolidLayout {
    pub fn read(source: &dyn ReadAt, resource: &Resource) -> Result<Self> {
        let header = source.read_vec(resource.offset, SOLID_HEADER)?;
        let uncompressed = le::u64(&header, 0);
        let chunk_size = le::u32(&header, 8) as u64;
        let codec = match le::u32(&header, 12) {
            0 => None,
            1 => Some(ChunkCodec::Xpress),
            2 => Some(ChunkCodec::Lzx),
            3 => Some(ChunkCodec::Lzms),
            other => {
                return Err(Error::format(
                    "WIM solid resource",
                    format!("unknown compression format {other}"),
                ));
            }
        };
        check_chunk_size(chunk_size)?;
        let chunks = uncompressed.div_ceil(chunk_size) as usize;
        let table_len = chunks
            .checked_mul(4)
            .filter(|len| (SOLID_HEADER + len) as u64 <= resource.stored_size)
            .ok_or_else(|| Error::format("WIM solid resource", "chunk table does not fit"))?;
        let table = source.read_vec(resource.offset + SOLID_HEADER as u64, table_len)?;
        let mut bounds = Vec::with_capacity(chunks + 1);
        let mut at = (SOLID_HEADER + table_len) as u64;
        bounds.push(at);
        for i in 0..chunks {
            at += le::u32(&table, i * 4) as u64;
            bounds.push(at);
        }
        if at > resource.stored_size {
            return Err(Error::format(
                "WIM solid resource",
                "chunks run past the resource",
            ));
        }
        Ok(Self {
            uncompressed,
            chunk_size,
            codec,
            bounds,
        })
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed
    }

    fn chunk_count(&self) -> usize {
        self.bounds.len() - 1
    }

    fn plain_len(&self, i: usize) -> usize {
        if i + 1 < self.chunk_count() {
            self.chunk_size as usize
        } else {
            (self.uncompressed - self.chunk_size * (self.chunk_count() as u64 - 1)) as usize
        }
    }

    fn chunks_for(&self, offset: u64, len: u64) -> Range<usize> {
        let first = (offset / self.chunk_size) as usize;
        let last = ((offset + len - 1) / self.chunk_size) as usize;
        first..last + 1
    }

    /// Plaintext `[offset, offset + len)` of this resource, decoding only
    /// the chunks that cover it.
    pub fn read_range(
        &self,
        source: &dyn ReadAt,
        resource: &Resource,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if offset + len > self.uncompressed {
            return Err(Error::format(
                "WIM solid resource",
                "range beyond the resource",
            ));
        }
        let chunks = self.chunks_for(offset, len);
        let mut decompressor = self
            .codec
            .map(|codec| ChunkDecompressor::new(codec, self.chunk_size as usize))
            .transpose()
            .map_err(|e| Error::format("WIM solid resource", e.to_string()))?;
        let mut plain = Vec::new();
        for i in chunks.clone() {
            let raw = source.read_vec(
                resource.offset + self.bounds[i],
                (self.bounds[i + 1] - self.bounds[i]) as usize,
            )?;
            plain.extend_from_slice(&decode(decompressor.as_mut(), &raw, self.plain_len(i))?);
        }
        let skip = (offset - chunks.start as u64 * self.chunk_size) as usize;
        Ok(plain[skip..skip + len as usize].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemorySource;

    fn resource(offset: u64, stored: u64, original: u64) -> Resource {
        Resource {
            stored_size: stored,
            flags: 0x04,
            offset,
            original_size: original,
        }
    }

    #[test]
    fn reads_chunked_resources_with_stored_chunks() {
        // Two stored chunks of 4 bytes and a 2-byte tail; table has 2 entries.
        let mut raw = Vec::new();
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&8u32.to_le_bytes());
        raw.extend_from_slice(b"abcdefghij");
        let source = MemorySource::new(raw.clone());
        let r = resource(0, raw.len() as u64, 10);
        assert_eq!(
            read_chunked(&source, &r, 4, ChunkCodec::Lzms).unwrap(),
            b"abcdefghij"
        );
        assert!(
            read_chunked(&source, &r, 3, ChunkCodec::Lzms).is_err(),
            "chunk size must be a power of two"
        );
    }

    #[test]
    fn decodes_compressed_chunks_through_wimlib() {
        // A chunked LZMS resource with one compressed and one stored chunk.
        let first: Vec<u8> = b"compressible "
            .iter()
            .copied()
            .cycle()
            .take(64 * 1024)
            .collect();
        let second: Vec<u8> = (0..1000u32).map(|i| (i * 131 % 256) as u8).collect();
        let packed = lzms::compress(&first).unwrap();
        assert!(packed.len() < first.len());
        let mut raw = Vec::new();
        raw.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        raw.extend_from_slice(&packed);
        raw.extend_from_slice(&second);
        let source = MemorySource::new(raw.clone());
        let r = resource(0, raw.len() as u64, (first.len() + second.len()) as u64);
        let plain = read_chunked(&source, &r, 64 * 1024, ChunkCodec::Lzms).unwrap();
        assert_eq!(&plain[..first.len()], &first[..]);
        assert_eq!(&plain[first.len()..], &second[..]);
    }

    #[test]
    fn reads_ranges_of_solid_resources() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&10u64.to_le_bytes());
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // format 0: stored
        for size in [4u32, 4, 2] {
            raw.extend_from_slice(&size.to_le_bytes());
        }
        raw.extend_from_slice(b"abcdefghij");
        let source = MemorySource::new(raw.clone());
        let r = resource(0, raw.len() as u64, 0x1_0000_0000);
        let layout = SolidLayout::read(&source, &r).unwrap();
        assert_eq!(layout.uncompressed_size(), 10);
        assert_eq!(layout.read_range(&source, &r, 3, 5).unwrap(), b"defgh");
        assert_eq!(layout.read_range(&source, &r, 8, 2).unwrap(), b"ij");
        assert!(layout.read_range(&source, &r, 8, 3).is_err());
    }
}
