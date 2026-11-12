//! Just enough PE parsing for identification: Symbol Server keys, the
//! CodeView (PDB) record and the version resource.

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    io::le,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeView {
    pub pdb_name: String,
    pub guid: [u8; 16],
    pub age: u32,
}

impl CodeView {
    /// `GUID` (upper-case, no dashes) followed by the age in hex: the
    /// directory name the Symbol Server uses for PDBs.
    pub fn symbol_key(&self) -> String {
        let g = &self.guid;
        format!(
            "{:08X}{:04X}{:04X}{}{:X}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8..]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
            self.age
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeInfo {
    pub machine: u16,
    pub time_date_stamp: u32,
    pub size_of_image: u32,
    pub file_version: Option<String>,
    pub codeview: Option<CodeView>,
}

impl PeInfo {
    /// Directory key on the Microsoft Symbol Server for this image.
    pub fn symbol_key(&self) -> String {
        format!("{:08X}{:x}", self.time_date_stamp, self.size_of_image)
    }

    pub fn machine_label(&self) -> &'static str {
        match self.machine {
            0x8664 => "x64",
            0xaa64 => "arm64",
            0x014c => "x86",
            0xa641 => "arm64ec",
            _ => "other",
        }
    }
}

struct Section {
    va: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
}

pub fn parse(data: &[u8]) -> Result<PeInfo> {
    let bad = |detail: &str| Error::format("PE image", detail.to_string());
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err(bad("missing MZ header"));
    }
    let pe = le::u32(data, 0x3c) as usize;
    if data.len() < pe + 24 || &data[pe..pe + 4] != b"PE\0\0" {
        return Err(bad("missing PE signature"));
    }
    let machine = le::u16(data, pe + 4);
    let section_count = le::u16(data, pe + 6) as usize;
    let time_date_stamp = le::u32(data, pe + 8);
    let optional_size = le::u16(data, pe + 20) as usize;
    let opt = pe + 24;
    if data.len() < opt + optional_size || optional_size < 96 {
        return Err(bad("optional header truncated"));
    }
    let magic = le::u16(data, opt);
    let directories = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return Err(bad("unknown optional header magic")),
    };
    let size_of_image = le::u32(data, opt + 56);
    let directory = |index: usize| -> Option<(u32, u32)> {
        let at = directories + index * 8;
        (at + 8 <= opt + optional_size).then(|| (le::u32(data, at), le::u32(data, at + 4)))
    };

    let mut sections = Vec::with_capacity(section_count);
    let table = opt + optional_size;
    for i in 0..section_count {
        let at = table + i * 40;
        if at + 40 > data.len() {
            break;
        }
        sections.push(Section {
            virtual_size: le::u32(data, at + 8),
            va: le::u32(data, at + 12),
            raw_size: le::u32(data, at + 16),
            raw_offset: le::u32(data, at + 20),
        });
    }
    let to_offset = |rva: u32| -> Option<usize> {
        sections.iter().find_map(|s| {
            let span = s.virtual_size.max(s.raw_size);
            (rva >= s.va && rva < s.va.saturating_add(span))
                .then(|| (s.raw_offset + (rva - s.va)) as usize)
                .filter(|off| *off < data.len())
        })
    };

    let codeview = directory(6).and_then(|(rva, size)| {
        let start = to_offset(rva)?;
        (0..size as usize / 28).find_map(|i| {
            let entry = data.get(start + i * 28..start + i * 28 + 28)?;
            if le::u32(entry, 12) != 2 {
                return None;
            }
            let raw = le::u32(entry, 24) as usize;
            let len = le::u32(entry, 16) as usize;
            let record = data.get(raw..raw + len)?;
            if record.len() < 24 || &record[..4] != b"RSDS" {
                return None;
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&record[4..20]);
            let age = le::u32(record, 20);
            let path_bytes = &record[24..];
            let end = path_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(path_bytes.len());
            let path = String::from_utf8_lossy(&path_bytes[..end]).into_owned();
            let pdb_name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_owned();
            (!pdb_name.is_empty()).then_some(CodeView {
                pdb_name,
                guid,
                age,
            })
        })
    });

    let file_version = directory(2)
        .and_then(|(rva, _)| to_offset(rva).map(|off| (rva, off)))
        .and_then(|(base_rva, base)| version_resource(data, base_rva, base, &to_offset));

    Ok(PeInfo {
        machine,
        time_date_stamp,
        size_of_image,
        file_version,
        codeview,
    })
}

/// RT_VERSION → first name → first language → VS_FIXEDFILEINFO.
fn version_resource(
    data: &[u8],
    _base_rva: u32,
    base: usize,
    to_offset: &dyn Fn(u32) -> Option<usize>,
) -> Option<String> {
    let entries = |dir: usize| -> Option<Vec<(u32, u32)>> {
        let header = data.get(dir..dir + 16)?;
        let count = le::u16(header, 12) as usize + le::u16(header, 14) as usize;
        (0..count)
            .map(|i| {
                let e = data.get(dir + 16 + i * 8..dir + 24 + i * 8)?;
                Some((le::u32(e, 0), le::u32(e, 4)))
            })
            .collect()
    };
    let (_, type_dir) = entries(base)?.into_iter().find(|(id, _)| *id == 16)?;
    let mut node = type_dir;
    for _ in 0..2 {
        if node & 0x8000_0000 == 0 {
            return None;
        }
        let (_, next) = *entries(base + (node & 0x7fff_ffff) as usize)?.first()?;
        node = next;
    }
    let data_entry = data.get(base + node as usize..base + node as usize + 16)?;
    let start = to_offset(le::u32(data_entry, 0))?;
    let blob = data.get(start..start + le::u32(data_entry, 4) as usize)?;
    let at = blob
        .windows(4)
        .position(|w| w == 0xFEEF04BDu32.to_le_bytes())?;
    let fixed = blob.get(at..at + 16)?;
    let ms = le::u32(fixed, 8);
    let ls = le::u32(fixed, 12);
    Some(format!(
        "{}.{}.{}.{}",
        ms >> 16,
        ms & 0xffff,
        ls >> 16,
        ls & 0xffff
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_symbol_keys() {
        let info = PeInfo {
            machine: 0x8664,
            time_date_stamp: 0x53af4121,
            size_of_image: 0xae000,
            file_version: None,
            codeview: None,
        };
        assert_eq!(info.symbol_key(), "53AF4121ae000");
        let cv = CodeView {
            pdb_name: "afd.pdb".into(),
            guid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 9, 10, 11, 12, 13, 14, 15, 16,
            ],
            age: 1,
        };
        assert_eq!(cv.symbol_key(), "0403020106050807090A0B0C0D0E0F101");
    }

    #[test]
    fn rejects_non_pe() {
        assert!(parse(b"not a pe").is_err());
    }
}
