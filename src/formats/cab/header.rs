//! CFHEADER / CFFOLDER / CFFILE parsing.

use crate::{
    error::{Error, Result},
    io::{ReadAt, le},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    MsZip,
    Lzx { window_bits: u8 },
    Quantum,
}

impl Compression {
    fn from_raw(raw: u16) -> Self {
        match raw & 0x000f {
            0 => Self::None,
            1 => Self::MsZip,
            2 => Self::Quantum,
            _ => Self::Lzx {
                window_bits: ((raw >> 8) & 0x1f) as u8,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct FolderEntry {
    /// Absolute offset of the first CFDATA block.
    pub data_offset: u64,
    pub block_count: u16,
    pub compression: Compression,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub size: u32,
    pub folder: u16,
    /// Offset of the file inside its folder's uncompressed stream.
    pub offset: u32,
}

#[derive(Debug, Clone)]
pub struct Header {
    /// `cbCabinet`: total size of the cabinet file.
    pub size: u64,
    pub folders: Vec<FolderEntry>,
    pub files: Vec<FileEntry>,
    /// Reserved bytes at the start of each CFDATA block.
    pub data_reserve: usize,
}

pub fn parse(source: &dyn ReadAt) -> Result<Header> {
    let size = source.size();
    let first = source.read_vec(0, 64.min(size as usize))?;
    if first.len() < 36 || &first[..4] != b"MSCF" {
        return Err(Error::format("cabinet", "missing MSCF signature"));
    }
    let cabinet_size = le::u32(&first, 8) as u64;
    let files_offset = le::u32(&first, 16) as u64;
    let folder_count = le::u16(&first, 26) as usize;
    let file_count = le::u16(&first, 28) as usize;
    let flags = le::u16(&first, 30);

    // Header + folder table + file table normally sit in the first few MB.
    let table_end = files_offset + file_count as u64 * 300 + 4096;
    let head = source.read_vec(0, table_end.min(size) as usize)?;

    let mut at = 36usize;
    let (mut folder_reserve, mut data_reserve) = (0usize, 0usize);
    if flags & 0x0004 != 0 {
        let header_reserve = le::u16(&head, at) as usize;
        folder_reserve = head[at + 2] as usize;
        data_reserve = head[at + 3] as usize;
        at += 4 + header_reserve;
    }
    for flag in [0x0001u16, 0x0002] {
        if flags & flag != 0 {
            // Previous / next cabinet name and disk label.
            for _ in 0..2 {
                at = skip_cstring(&head, at)?;
            }
        }
    }

    let mut folders = Vec::with_capacity(folder_count);
    for _ in 0..folder_count {
        let entry = head
            .get(at..at + 8)
            .ok_or_else(|| Error::format("cabinet", "folder table truncated"))?;
        folders.push(FolderEntry {
            data_offset: le::u32(entry, 0) as u64,
            block_count: le::u16(entry, 4),
            compression: Compression::from_raw(le::u16(entry, 6)),
        });
        at += 8 + folder_reserve;
    }

    let mut files = Vec::with_capacity(file_count);
    let mut at = files_offset as usize;
    for _ in 0..file_count {
        let entry = head
            .get(at..at + 16)
            .ok_or_else(|| Error::format("cabinet", "file table truncated"))?;
        let size = le::u32(entry, 0);
        let offset = le::u32(entry, 4);
        let folder = le::u16(entry, 8);
        let attributes = le::u16(entry, 14);
        let name_start = at + 16;
        let name_end = skip_cstring(&head, name_start)? - 1;
        let raw_name = &head[name_start..name_end];
        let name = if attributes & 0x80 != 0 {
            String::from_utf8_lossy(raw_name).into_owned()
        } else {
            raw_name.iter().map(|&b| b as char).collect()
        };
        at = name_end + 1;
        if (folder as usize) < folders.len() {
            files.push(FileEntry {
                name,
                size,
                folder,
                offset,
            });
        }
    }
    Ok(Header {
        size: cabinet_size,
        folders,
        files,
        data_reserve,
    })
}

fn skip_cstring(data: &[u8], at: usize) -> Result<usize> {
    data.get(at..)
        .and_then(|rest| rest.iter().position(|&b| b == 0))
        .map(|end| at + end + 1)
        .ok_or_else(|| Error::format("cabinet", "unterminated string in header"))
}
