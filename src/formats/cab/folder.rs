//! Access to the uncompressed stream of one CAB folder.
//!
//! * `None`/MSZIP folders are random access: CFDATA headers are indexed once
//!   and each 32 KiB block is decoded on demand (stored blocks are copied).
//! * LZX folders are inherently sequential and are streamed through
//!   libmspack's decoder (`fastoneday-codecs`).

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};

use fastoneday_codecs::lzx;

use super::{
    header::{Compression, FolderEntry},
    mszip,
};
use crate::{
    error::{Error, Result},
    io::{Cancel, ReadAt, Source, check_bounds, le},
};

#[derive(Debug, Clone, Copy)]
struct Block {
    /// Absolute offset of the block's compressed bytes.
    data_offset: u64,
    compressed: u32,
    uncompressed: u32,
    /// Offset of the block in the folder's uncompressed stream.
    start: u64,
}

fn index_blocks(source: &dyn ReadAt, folder: &FolderEntry, reserve: usize) -> Result<Vec<Block>> {
    let mut blocks = Vec::with_capacity(folder.block_count as usize);
    let mut at = folder.data_offset;
    let mut start = 0u64;
    let mut header = vec![0u8; 8];
    for _ in 0..folder.block_count {
        source.read_exact_at(at, &mut header)?;
        let compressed = le::u16(&header, 4) as u32;
        let uncompressed = le::u16(&header, 6) as u32;
        let data_offset = at + 8 + reserve as u64;
        blocks.push(Block {
            data_offset,
            compressed,
            uncompressed,
            start,
        });
        start += uncompressed as u64;
        at = data_offset + compressed as u64;
    }
    Ok(blocks)
}

/// Random-access view of a stored or MSZIP folder.
pub struct FolderView {
    source: Source,
    blocks: Vec<Block>,
    compression: Compression,
    size: u64,
    cache: Mutex<VecDeque<(usize, Arc<Vec<u8>>)>>,
}

const CACHE_BLOCKS: usize = 192;

impl FolderView {
    pub fn new(source: Source, folder: &FolderEntry, reserve: usize) -> Result<Self> {
        if !matches!(folder.compression, Compression::None | Compression::MsZip) {
            return Err(Error::Unsupported(
                "random access needs a stored or MSZIP folder".into(),
            ));
        }
        let blocks = index_blocks(source.as_ref(), folder, reserve)?;
        let size = blocks
            .last()
            .map(|b| b.start + b.uncompressed as u64)
            .unwrap_or(0);
        Ok(Self {
            source,
            blocks,
            compression: folder.compression,
            size,
            cache: Mutex::new(VecDeque::new()),
        })
    }

    fn cached(&self, index: usize) -> Option<Arc<Vec<u8>>> {
        self.cache
            .lock()
            .expect("folder cache")
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, data)| data.clone())
    }

    fn remember(&self, index: usize, data: Arc<Vec<u8>>) {
        let mut cache = self.cache.lock().expect("folder cache");
        cache.push_front((index, data));
        cache.truncate(CACHE_BLOCKS);
    }

    fn raw(&self, index: usize) -> Result<Vec<u8>> {
        let block = self.blocks[index];
        self.source
            .read_vec(block.data_offset, block.compressed as usize)
    }

    /// Decoded bytes of block `index`.
    fn block(&self, index: usize) -> Result<Arc<Vec<u8>>> {
        if let Some(data) = self.cached(index) {
            return Ok(data);
        }
        if self.compression == Compression::None {
            let data = Arc::new(self.raw(index)?);
            self.remember(index, data.clone());
            return Ok(data);
        }
        // Walk back to a block that decodes on its own (stored, cached or the
        // first one), then decode forward so every dictionary is available.
        let mut first = index;
        let mut pending = Vec::new();
        loop {
            if self.cached(first).is_some() {
                break;
            }
            let raw = self.raw(first)?;
            let independent = first == 0
                || mszip::stored_payload(&raw, self.blocks[first].uncompressed as usize).is_some();
            pending.push((first, raw));
            if independent {
                break;
            }
            first -= 1;
        }
        let mut previous = if pending.last().map(|(i, _)| *i) != Some(first) {
            self.cached(first)
        } else {
            None
        };
        for (i, raw) in pending.into_iter().rev() {
            let expected = self.blocks[i].uncompressed as usize;
            let data = match mszip::stored_payload(&raw, expected) {
                Some(payload) => payload.to_vec(),
                None => {
                    let dictionary = previous.as_ref().map(|d| d.as_slice()).unwrap_or(&[]);
                    mszip::inflate(&raw, dictionary, expected)?
                }
            };
            let data = Arc::new(data);
            self.remember(i, data.clone());
            previous = Some(data);
        }
        Ok(previous.expect("at least one block decoded"))
    }

    fn block_for(&self, offset: u64) -> usize {
        self.blocks
            .partition_point(|b| b.start + b.uncompressed as u64 <= offset)
    }
}

impl ReadAt for FolderView {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds("cabinet folder", self.size, offset, buf.len())?;
        let mut written = 0usize;
        while written < buf.len() {
            let position = offset + written as u64;
            let index = self.block_for(position);
            let data = self.block(index)?;
            let within = (position - self.blocks[index].start) as usize;
            let take = (data.len() - within).min(buf.len() - written);
            buf[written..written + take].copy_from_slice(&data[within..within + take]);
            written += take;
        }
        Ok(())
    }
}

/// Streams a folder of any supported compression from its start, calling
/// `sink(offset, bytes)` with consecutive plaintext until `until` bytes are
/// done. Stored/MSZIP folders are decoded block by block; LZX folders go
/// through libmspack's decoder, fed lazily one CFDATA block at a time.
pub fn stream(
    source: &dyn ReadAt,
    folder: &FolderEntry,
    reserve: usize,
    until: u64,
    cancel: &Cancel,
    mut sink: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    let blocks = index_blocks(source, folder, reserve)?;
    match folder.compression {
        Compression::Lzx { window_bits } => {
            stream_lzx(source, &blocks, window_bits, until, cancel, &mut sink)
        }
        Compression::Quantum => Err(Error::Unsupported(
            "Quantum-compressed cabinets are not supported".into(),
        )),
        Compression::None | Compression::MsZip => {
            let mut previous: Vec<u8> = Vec::new();
            for block in blocks {
                if block.start >= until {
                    break;
                }
                cancel.check()?;
                let raw = source.read_vec(block.data_offset, block.compressed as usize)?;
                let expected = block.uncompressed as usize;
                let data = if folder.compression == Compression::None {
                    raw
                } else {
                    match mszip::stored_payload(&raw, expected) {
                        Some(payload) => payload.to_vec(),
                        None => mszip::inflate(&raw, &previous, expected)?,
                    }
                };
                if data.len() != expected {
                    return Err(Error::format("cabinet block", "size mismatch"));
                }
                sink(block.start, &data)?;
                previous = data;
            }
            Ok(())
        }
    }
}

fn stream_lzx(
    source: &dyn ReadAt,
    blocks: &[Block],
    window_bits: u8,
    until: u64,
    cancel: &Cancel,
    sink: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    let total: u64 = blocks.iter().map(|b| b.uncompressed as u64).sum();
    // The decoder sees io::Error; the real cause is kept here and returned.
    let mut input_error: Option<Error> = None;
    let mut sink_error: Option<Error> = None;

    let mut next_block = 0usize;
    let mut pending: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let mut input = |buf: &mut [u8]| -> io::Result<usize> {
        while consumed == pending.len() {
            let Some(block) = blocks.get(next_block) else {
                return Ok(0);
            };
            let fetched = cancel
                .check()
                .and_then(|()| source.read_vec(block.data_offset, block.compressed as usize));
            match fetched {
                Ok(raw) => pending = raw,
                Err(e) => {
                    let message = e.to_string();
                    input_error = Some(e);
                    return Err(io::Error::other(message));
                }
            }
            consumed = 0;
            next_block += 1;
        }
        let n = buf.len().min(pending.len() - consumed);
        buf[..n].copy_from_slice(&pending[consumed..consumed + n]);
        consumed += n;
        Ok(n)
    };
    let mut produced = 0u64;
    let mut output = |chunk: &[u8]| -> io::Result<()> {
        if let Err(e) = sink(produced, chunk) {
            let message = e.to_string();
            sink_error = Some(e);
            return Err(io::Error::other(message));
        }
        produced += chunk.len() as u64;
        Ok(())
    };
    let result = lzx::decode_cab_folder(
        window_bits,
        total,
        until.min(total),
        &mut input,
        &mut output,
    );
    if let Some(error) = input_error.or(sink_error) {
        return Err(error);
    }
    result.map_err(|e| Error::format("LZX folder", e.to_string()))
}
