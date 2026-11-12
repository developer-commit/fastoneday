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
    io::{Cancel, FileSource, MemorySource, SliceSource, Source},
};
use folder::FolderView;
use header::Header;

/// Members smaller than this are kept in memory when materialized.
const IN_MEMORY_LIMIT: u64 = 64 << 20;

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
