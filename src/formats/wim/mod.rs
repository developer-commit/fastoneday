//! Windows Imaging (WIM/ESD) reader over any [`ReadAt`] source.
//!
//! Handles uncompressed images (24H2+ MSU containers) and XPRESS/LZX/LZMS
//! resources, chunked or solid (update metadata images, ESDs, install.wim).
//! Framing is parsed here; chunks are decompressed by wimlib. Only the chunks
//! covering a requested file are read, so remote images cost little.

mod blobs;
mod dentry;
mod header;
mod resource;

use std::sync::{Arc, Mutex};

pub use dentry::Entry;
pub use header::WimCompression;

use crate::{
    error::{Error, Result},
    io::{ReadAt, Source, le},
};
use blobs::{BlobLocation, BlobTable};
use header::{Header, Resource};
use resource::SolidLayout;

/// Parsed solid-resource layouts, keyed by (group, resource index).
type LayoutCache = Mutex<Vec<((usize, usize), Arc<SolidLayout>)>>;

pub struct Wim {
    source: Source,
    header: Header,
    blobs: BlobTable,
    entries: Vec<Entry>,
    layouts: LayoutCache,
}

impl Wim {
    /// Opens the WIM's main image: the one with the largest metadata (the
    /// install image of an ESD; the only image of an update container).
    pub fn open(source: Source) -> Result<Self> {
        let header = header::parse(source.as_ref())?;
        let table = read_plain(source.as_ref(), &header.blob_table)?;
        let blobs = blobs::parse(&table);
        let metadata = *blobs
            .metadata
            .iter()
            .max_by_key(|r| r.original_size)
            .ok_or_else(|| Error::format("WIM", "no image metadata resource"))?;
        let mut wim = Self {
            source,
            header,
            blobs,
            entries: Vec::new(),
            layouts: Mutex::new(Vec::new()),
        };
        let metadata = wim.read_resource(&metadata)?;
        wim.entries = dentry::parse(&metadata)?;
        Ok(wim)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Case-insensitive lookup of a file by path (`/` separators).
    pub fn find(&self, path: &str) -> Option<&Entry> {
        let wanted = path.trim_start_matches('/');
        self.entries
            .iter()
            .find(|e| !e.is_dir && e.path.eq_ignore_ascii_case(wanted))
    }

    /// Byte range of a stored (uncompressed, non-solid) file inside the WIM,
    /// so callers can read slices of it directly.
    pub fn stored_range(&self, entry: &Entry) -> Option<(u64, u64)> {
        match self.blobs.blobs.get(&entry.hash)? {
            BlobLocation::Resource(r) if !r.is_compressed() => Some((r.offset, r.original_size)),
            _ => None,
        }
    }

    /// Full contents of a file, checked against the blob's SHA-1.
    pub fn read(&self, entry: &Entry) -> Result<Vec<u8>> {
        if entry.hash == [0u8; 20] {
            return Ok(Vec::new());
        }
        let data = self.read_unverified(entry)?;
        let actual = crate::domain::Digest::of(crate::domain::HashAlgorithm::Sha1, &data);
        let expected =
            crate::domain::Digest::from_bytes(crate::domain::HashAlgorithm::Sha1, &entry.hash);
        if actual != expected {
            return Err(Error::Integrity {
                what: format!("WIM file {}", entry.path),
                algorithm: "SHA-1",
                expected: expected.hex,
                actual: actual.hex,
            });
        }
        Ok(data)
    }

    fn read_unverified(&self, entry: &Entry) -> Result<Vec<u8>> {
        match *self
            .blobs
            .blobs
            .get(&entry.hash)
            .ok_or_else(|| Error::format("WIM", format!("no blob for `{}`", entry.path)))?
        {
            BlobLocation::Resource(resource) => self.read_resource(&resource),
            BlobLocation::Solid {
                group,
                offset,
                size,
            } => self.read_solid(group, offset, size),
        }
    }

    fn read_resource(&self, resource: &Resource) -> Result<Vec<u8>> {
        if !resource.is_compressed() {
            return read_plain(self.source.as_ref(), resource);
        }
        let codec = resource::codec_for(self.header.compression)
            .ok_or_else(|| Error::format("WIM", "compressed resource in an uncompressed image"))?;
        // Version 1.09 images leave the field zero and use 32 KiB chunks.
        let chunk = match self.header.chunk_size {
            0 => 32 * 1024,
            size => size as usize,
        };
        resource::read_chunked(self.source.as_ref(), resource, chunk, codec)
    }

    fn layout(&self, group: usize, index: usize, resource: &Resource) -> Result<Arc<SolidLayout>> {
        if let Some((_, layout)) = self
            .layouts
            .lock()
            .expect("layouts")
            .iter()
            .find(|(key, _)| *key == (group, index))
        {
            return Ok(layout.clone());
        }
        let layout = Arc::new(SolidLayout::read(self.source.as_ref(), resource)?);
        self.layouts
            .lock()
            .expect("layouts")
            .push(((group, index), layout.clone()));
        Ok(layout)
    }

    fn read_solid(&self, group: usize, offset: u64, size: u64) -> Result<Vec<u8>> {
        let resources = self
            .blobs
            .solid_groups
            .get(group)
            .ok_or_else(|| Error::format("WIM", "solid group out of range"))?;
        let mut out = Vec::with_capacity(size as usize);
        let mut base = 0u64;
        for (index, resource) in resources.iter().enumerate() {
            let layout = self.layout(group, index, resource)?;
            let total = layout.uncompressed_size();
            let (start, end) = (offset.max(base), (offset + size).min(base + total));
            if start < end {
                out.extend_from_slice(&layout.read_range(
                    self.source.as_ref(),
                    resource,
                    start - base,
                    end - start,
                )?);
            }
            base += total;
        }
        if out.len() as u64 != size {
            return Err(Error::format("WIM", "solid blob is truncated"));
        }
        Ok(out)
    }

    /// The image's XML description (UTF-16).
    pub fn xml(&self) -> Result<String> {
        let raw = read_plain(self.source.as_ref(), &self.header.xml)?;
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| le::u16(c, 0)).collect();
        Ok(String::from_utf16_lossy(&units)
            .trim_start_matches('\u{feff}')
            .to_owned())
    }

    pub fn version(&self) -> u32 {
        self.header.version
    }
}

fn read_plain(source: &dyn ReadAt, resource: &Resource) -> Result<Vec<u8>> {
    source.read_vec(
        resource.offset,
        resource.original_size.max(resource.stored_size) as usize,
    )
}
