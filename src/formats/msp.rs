//! Windows Installer patches (`.msp`): OLE compound files whose cabinet
//! streams hold the updated files (Office MSI updates ship full files).

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use crate::{
    error::{Error, Result},
    io::{FileSource, MemorySource, Source, SourceCursor},
};

/// Streams larger than this are copied to `spill_dir` instead of memory.
const IN_MEMORY_LIMIT: u64 = 64 << 20;

/// An embedded cabinet stream.
pub struct PatchCabinet {
    pub stream: String,
    pub data: Source,
}

/// Every stream of the patch's root storage that is a cabinet.
pub fn cabinets(msp: Source, spill_dir: &Path) -> Result<Vec<PatchCabinet>> {
    let mut compound = cfb::CompoundFile::open(SourceCursor::new(msp))
        .map_err(|e| Error::format("MSP patch", e.to_string()))?;
    let streams: Vec<(std::path::PathBuf, u64)> = compound
        .read_root_storage()
        .filter(|entry| entry.is_stream())
        .map(|entry| (entry.path().to_path_buf(), entry.len()))
        .collect();
    let mut out = Vec::new();
    for (path, len) in streams {
        if len < 64 {
            continue;
        }
        let mut stream = compound
            .open_stream(&path)
            .map_err(|e| Error::format("MSP patch", e.to_string()))?;
        let mut magic = [0u8; 4];
        if stream.read_exact(&mut magic).is_err() || &magic != b"MSCF" {
            continue;
        }
        let name = decode_stream_name(path.to_string_lossy().trim_start_matches(['/', '\\']));
        let data: Source = if len <= IN_MEMORY_LIMIT {
            let mut data = magic.to_vec();
            data.reserve(len as usize);
            stream
                .read_to_end(&mut data)
                .map_err(|e| Error::format("MSP patch", e.to_string()))?;
            Arc::new(MemorySource::new(data))
        } else {
            std::fs::create_dir_all(spill_dir)
                .map_err(|e| Error::io(format!("create {}", spill_dir.display()), e))?;
            let file_path = spill_dir.join(format!(
                "msp-{}-{}.cab",
                std::process::id(),
                name.replace(['/', '\\', '!'], "_")
            ));
            let mut file = File::create(&file_path)
                .map_err(|e| Error::io(format!("create {}", file_path.display()), e))?;
            file.write_all(&magic)
                .map_err(|e| Error::io("write spill", e))?;
            std::io::copy(&mut stream, &mut file).map_err(|e| Error::io("write spill", e))?;
            drop(file);
            Arc::new(FileSource::open(&file_path)?)
        };
        out.push(PatchCabinet { stream: name, data });
    }
    if out.is_empty() {
        return Err(Error::format("MSP patch", "no embedded cabinet stream"));
    }
    Ok(out)
}

/// Windows Installer packs stream names two base-64 symbols per UTF-16 unit.
pub fn decode_stream_name(name: &str) -> String {
    const SYMBOLS: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut out = String::new();
    for ch in name.chars() {
        let v = ch as u32;
        match v {
            0x3800..=0x47ff => {
                let x = v - 0x3800;
                out.push(SYMBOLS[(x & 0x3f) as usize] as char);
                out.push(SYMBOLS[((x >> 6) & 0x3f) as usize] as char);
            }
            0x4800..=0x483f => out.push(SYMBOLS[(v - 0x4800) as usize] as char),
            0x4840 => out.push('!'),
            _ => out.push(ch),
        }
    }
    out
}

/// Office file keys look like `OUTLOOK.EXE`, `MSO.DLL_0005` or
/// `MAPIR.DLL_1033`; this returns the plain lower-case file name.
pub fn file_name_from_key(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    match lower.rsplit_once('_') {
        Some((stem, suffix))
            if !suffix.is_empty()
                && suffix.bytes().all(|b| b.is_ascii_digit())
                && stem.contains('.') =>
        {
            stem.to_owned()
        }
        _ => lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_msi_stream_names() {
        assert_eq!(
            decode_stream_name("\u{3a99}\u{3b1d}\u{47d1}\u{3a8c}\u{480b}"),
            "PATCH_CAB"
        );
    }

    #[test]
    fn strips_office_key_suffixes() {
        assert_eq!(file_name_from_key("EMSMDB32.DLL_0005"), "emsmdb32.dll");
        assert_eq!(file_name_from_key("MAPIR.DLL_1033"), "mapir.dll");
        assert_eq!(file_name_from_key("OUTLOOK.EXE"), "outlook.exe");
        assert_eq!(file_name_from_key("SCNPST64C.DLL"), "scnpst64c.dll");
    }
}
