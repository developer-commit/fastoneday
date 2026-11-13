//! Microsoft Cabinet (CAB/MSU) reader.
//!
//! Members of stored/MSZIP folders are exposed as random-access sources, so
//! nested cabinets (MSU → CAB → CAB → payload CAB) can be walked without
//! extracting the outer layers. LZX folders are decoded in one sequential pass.

mod folder;
mod header;
mod mszip;

use std::{collections::HashMap, fs::File, io::Write, path::Path, sync::Arc};

pub use header::{Compression, FileEntry};

use crate::{
    error::{Error, Result},
    io::{Cancel, FileSource, MemorySource, SliceSource, Source, le},
};
use folder::FolderView;
use header::Header;

/// Members smaller than this are kept in memory when materialized.
const IN_MEMORY_LIMIT: u64 = 64 << 20;
/// Plaintext bytes in every CFDATA block but a folder's last.
const BLOCK: u64 = 32 << 10;

pub struct Cabinet {
    source: Source,
    header: Header,
    views: std::sync::Mutex<HashMap<u16, Arc<FolderView>>>,
}

impl Cabinet {
    pub fn open(source: Source) -> Result<Self> {
        let header = header::parse(source.as_ref())?;
        Ok(Self {
            source,
            header,
            views: Default::default(),
        })
    }

    pub fn files(&self) -> &[FileEntry] {
        &self.header.files
    }

    /// Case-insensitive lookup by full member name.
    pub fn find(&self, name: &str) -> Option<&FileEntry> {
        self.header
            .files
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    /// Byte range of a folder's CFDATA blocks: from its first block to the
    /// next folder's (or the end of the cabinet).
    pub fn folder_span(&self, folder: u16) -> (u64, u64) {
        let start = self.header.folders[folder as usize].data_offset;
        let end = self
            .header
            .folders
            .iter()
            .map(|f| f.data_offset)
            .filter(|&offset| offset > start)
            .min()
            .unwrap_or(self.header.size);
        (start, end)
    }

    /// `cbCabinet`: the size the header declares for the whole cabinet.
    pub fn size(&self) -> u64 {
        self.header.size
    }

    /// Where a member of a stored (uncompressed) folder lies, worked out
    /// without reading the folder. Such folders keep the member verbatim in
    /// full 32 KiB blocks, so a remote reader can fetch exactly those blocks;
    /// [`StoredSpan::unstore`] then checks every block header it relied on.
    pub fn stored_span(&self, file: &FileEntry) -> Option<StoredSpan> {
        let folder = &self.header.folders[file.folder as usize];
        if folder.compression != Compression::None || file.size == 0 {
            return None;
        }
        let reserve = self.header.data_reserve;
        let stride = 8 + reserve as u64 + BLOCK;
        let begin = file.offset as u64;
        let end = begin + file.size as u64;
        let (first, last) = (begin / BLOCK, (end - 1) / BLOCK);
        if last >= folder.block_count as u64 {
            return None;
        }
        let offset = folder.data_offset + first * stride;
        let (_, folder_end) = self.folder_span(file.folder);
        let len = (folder.data_offset + (last + 1) * stride)
            .min(folder_end)
            .checked_sub(offset)?;
        Some(StoredSpan {
            offset,
            len,
            first_block: first,
            last_block: last,
            folder_blocks: folder.block_count as u64,
            skip: (begin - first * BLOCK) as usize,
            size: file.size as usize,
            reserve,
        })
    }

    pub fn compression_of(&self, file: &FileEntry) -> Compression {
        self.header.folders[file.folder as usize].compression
    }

    /// Whether `open_member` can serve this member without decoding the
    /// whole folder.
    pub fn is_random_access(&self, file: &FileEntry) -> bool {
        matches!(
            self.compression_of(file),
            Compression::None | Compression::MsZip
        )
    }

    /// A source for one member. Stored/MSZIP members are lazy views; LZX
    /// members are decoded once into memory or into a file under `spill_dir`.
    pub fn open_member(
        &self,
        file: &FileEntry,
        spill_dir: &Path,
        cancel: &Cancel,
    ) -> Result<Source> {
        if self.is_random_access(file) {
            let view = self.view(file.folder)?;
            return Ok(Arc::new(SliceSource::new(
                view,
                file.offset as u64,
                file.size as u64,
            )));
        }
        if (file.size as u64) <= IN_MEMORY_LIMIT {
            let mut data = self.extract(&[file], cancel)?;
            return Ok(Arc::new(MemorySource::new(data.remove(0))));
        }
        std::fs::create_dir_all(spill_dir)
            .map_err(|e| Error::io(format!("create {}", spill_dir.display()), e))?;
        let path = spill_dir.join(format!(
            "member-{}-{}.bin",
            std::process::id(),
            file.name.replace(['\\', '/', ':'], "_")
        ));
        let mut out =
            File::create(&path).map_err(|e| Error::io(format!("create {}", path.display()), e))?;
        let begin = file.offset as u64;
        let end = begin + file.size as u64;
        let folder = &self.header.folders[file.folder as usize];
        folder::stream(
            self.source.as_ref(),
            folder,
            self.header.data_reserve,
            end,
            cancel,
            |start, block| {
                let block_end = start + block.len() as u64;
                if block_end > begin && start < end {
                    let from = begin.saturating_sub(start) as usize;
                    let to = (end.min(block_end) - start) as usize;
                    out.write_all(&block[from..to])
                        .map_err(|e| Error::io(format!("write {}", path.display()), e))?;
                }
                Ok(())
            },
        )?;
        drop(out);
        Ok(Arc::new(FileSource::open(&path)?))
    }

    /// Decodes the given members (any compression) in one pass per folder.
    pub fn extract(&self, files: &[&FileEntry], cancel: &Cancel) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = files
            .iter()
            .map(|f| Vec::with_capacity(f.size as usize))
            .collect();
        let mut by_folder: HashMap<u16, Vec<usize>> = HashMap::new();
        for (i, f) in files.iter().enumerate() {
            by_folder.entry(f.folder).or_default().push(i);
        }
        for (folder_index, wanted) in by_folder {
            let folder = &self.header.folders[folder_index as usize];
            if matches!(folder.compression, Compression::None | Compression::MsZip) {
                let view = self.view(folder_index)?;
                for i in wanted {
                    out[i] = crate::io::ReadAt::read_vec(
                        view.as_ref(),
                        files[i].offset as u64,
                        files[i].size as usize,
                    )?;
                }
                continue;
            }
            let until = wanted
                .iter()
                .map(|&i| files[i].offset as u64 + files[i].size as u64)
                .max()
                .unwrap_or(0);
            folder::stream(
                self.source.as_ref(),
                folder,
                self.header.data_reserve,
                until,
                cancel,
                |start, block| {
                    let block_end = start + block.len() as u64;
                    for &i in &wanted {
                        let begin = files[i].offset as u64;
                        let end = begin + files[i].size as u64;
                        if block_end > begin && start < end {
                            let from = begin.saturating_sub(start) as usize;
                            let to = (end.min(block_end) - start) as usize;
                            out[i].extend_from_slice(&block[from..to]);
                        }
                    }
                    Ok(())
                },
            )?;
        }
        for (data, file) in out.iter().zip(files) {
            if data.len() != file.size as usize {
                return Err(Error::format(
                    "cabinet",
                    format!("member `{}` is truncated", file.name),
                ));
            }
        }
        Ok(out)
    }

    fn view(&self, folder: u16) -> Result<Arc<FolderView>> {
        if let Some(view) = self.views.lock().expect("views").get(&folder) {
            return Ok(view.clone());
        }
        let entry = &self.header.folders[folder as usize];
        let view = Arc::new(FolderView::new(
            self.source.clone(),
            entry,
            self.header.data_reserve,
        )?);
        self.views
            .lock()
            .expect("views")
            .insert(folder, view.clone());
        Ok(view)
    }
}

/// The CFDATA blocks that hold one member of a stored folder (see
/// [`Cabinet::stored_span`]).
#[derive(Debug, Clone)]
pub struct StoredSpan {
    /// Cabinet offset of the first block header to fetch.
    pub offset: u64,
    /// Bytes to fetch from there.
    pub len: u64,
    first_block: u64,
    last_block: u64,
    folder_blocks: u64,
    /// Member bytes start this far into the first block's data.
    skip: usize,
    size: usize,
    reserve: usize,
}

impl StoredSpan {
    /// The member's bytes, cut out of the fetched blocks in place. Fails
    /// when a block is not the full stored block the span assumed.
    pub fn unstore(&self, mut blocks: Vec<u8>) -> Result<Vec<u8>> {
        let bad = |detail: String| Error::format("cabinet", detail);
        let (mut read, mut written, mut skip) = (0usize, 0usize, self.skip);
        for block in self.first_block..=self.last_block {
            let header = blocks
                .get(read..read + 8)
                .ok_or_else(|| bad(format!("block {block} was not downloaded")))?;
            let stored = le::u16(header, 4) as usize;
            let plain = le::u16(header, 6) as usize;
            let full = block + 1 == self.folder_blocks || plain == BLOCK as usize;
            let data = read + 8 + self.reserve;
            if stored != plain
                || plain == 0
                || !full
                || skip >= plain
                || data + plain > blocks.len()
            {
                return Err(bad(format!(
                    "block {block} is not a full stored block ({stored} → {plain} bytes)"
                )));
            }
            let take = (plain - skip).min(self.size - written);
            blocks.copy_within(data + skip..data + skip + take, written);
            written += take;
            skip = 0;
            read = data + plain;
        }
        if written != self.size {
            return Err(bad(format!(
                "stored member ends after {written} of {} bytes",
                self.size
            )));
        }
        blocks.truncate(written);
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-folder stored cabinet holding `files`, with `block`-byte blocks.
    fn stored_cabinet(files: &[(&str, &[u8])], block: usize) -> Vec<u8> {
        let plain: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
        let chunks: Vec<&[u8]> = plain.chunks(block).collect();
        let names: usize = files.iter().map(|(n, _)| 16 + n.len() + 1).sum();
        let data_offset = 36 + 8 + names;
        let mut cab = Vec::new();
        cab.extend_from_slice(b"MSCF\0\0\0\0");
        let total = data_offset + chunks.iter().map(|c| 8 + c.len()).sum::<usize>();
        cab.extend_from_slice(&(total as u32).to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&44u32.to_le_bytes()); // coffFiles
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&[3, 1]); // version
        cab.extend_from_slice(&1u16.to_le_bytes()); // folders
        cab.extend_from_slice(&(files.len() as u16).to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes()); // flags
        cab.extend_from_slice(&0u16.to_le_bytes()); // setID
        cab.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
        cab.extend_from_slice(&(data_offset as u32).to_le_bytes());
        cab.extend_from_slice(&(chunks.len() as u16).to_le_bytes());
        cab.extend_from_slice(&0u16.to_le_bytes()); // stored
        let mut offset = 0u32;
        for (name, data) in files {
            cab.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cab.extend_from_slice(&offset.to_le_bytes());
            cab.extend_from_slice(&[0; 8]); // folder 0, date, time, attribs
            cab.extend_from_slice(name.as_bytes());
            cab.push(0);
            offset += data.len() as u32;
        }
        assert_eq!(cab.len(), data_offset);
        for chunk in chunks {
            cab.extend_from_slice(&0u32.to_le_bytes());
            cab.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            cab.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            cab.extend_from_slice(chunk);
        }
        cab
    }

    #[test]
    fn reads_a_stored_member_from_its_own_blocks() {
        let a: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let b: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
        let cab = stored_cabinet(&[("a.vdm", &a), ("b.vdm", &b)], BLOCK as usize);
        let cabinet = Cabinet::open(Arc::new(MemorySource::new(cab.clone()))).unwrap();
        let file = cabinet.find("B.VDM").unwrap().clone();
        let span = cabinet.stored_span(&file).unwrap();
        // b starts inside the second block: the first block is not fetched.
        assert!(span.offset > 44);
        let fetched = cab[span.offset as usize..(span.offset + span.len) as usize].to_vec();
        assert_eq!(span.unstore(fetched).unwrap(), b);
        assert_eq!(cabinet.extract(&[&file], &Cancel::new()).unwrap()[0], b);

        // Blocks that are not the standard size are refused, not misread.
        let odd = stored_cabinet(&[("a.vdm", &a), ("b.vdm", &b)], 1000);
        let cabinet = Cabinet::open(Arc::new(MemorySource::new(odd.clone()))).unwrap();
        let file = cabinet.find("b.vdm").unwrap().clone();
        let span = cabinet.stored_span(&file).unwrap();
        let end = ((span.offset + span.len) as usize).min(odd.len());
        assert!(
            span.unstore(odd[span.offset as usize..end].to_vec())
                .is_err()
        );
    }
}
