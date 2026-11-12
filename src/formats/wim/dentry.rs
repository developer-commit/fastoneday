//! Directory entries of a WIM image (the metadata resource).

use crate::{
    error::{Error, Result},
    io::le,
};

#[derive(Debug, Clone)]
pub struct Entry {
    /// `/`-separated path from the image root, without a leading slash.
    pub path: String,
    pub is_dir: bool,
    /// SHA-1 of the unnamed data stream (all zero for empty files).
    pub hash: [u8; 20],
}

const ATTRIBUTE_DIRECTORY: u32 = 0x10;

pub fn parse(metadata: &[u8]) -> Result<Vec<Entry>> {
    if metadata.len() < 8 {
        return Err(Error::format("WIM metadata", "too short"));
    }
    let security_len = le::u32(metadata, 0) as usize;
    let root = security_len.div_ceil(8) * 8;
    let root_subdir = field_u64(metadata, root + 16)? as usize;
    let mut out = Vec::new();
    let mut stack = vec![(root_subdir, String::new(), 0usize)];
    while let Some((offset, prefix, depth)) = stack.pop() {
        if depth > 64 {
            return Err(Error::format("WIM metadata", "directory nesting too deep"));
        }
        walk_siblings(metadata, offset, &prefix, depth, &mut out, &mut stack)?;
    }
    Ok(out)
}

fn walk_siblings(
    m: &[u8],
    mut offset: usize,
    prefix: &str,
    depth: usize,
    out: &mut Vec<Entry>,
    stack: &mut Vec<(usize, String, usize)>,
) -> Result<()> {
    if offset == 0 {
        return Ok(());
    }
    loop {
        let length = field_u64(m, offset)? as usize;
        if length == 0 {
            return Ok(());
        }
        if length < 102 || offset + length > m.len() {
            return Err(Error::format(
                "WIM metadata",
                "invalid directory entry length",
            ));
        }
        let attributes = le::u32(m, offset + 8);
        let subdir = le::u64(m, offset + 16) as usize;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&m[offset + 64..offset + 84]);
        let streams = le::u16(m, offset + 96) as usize;
        let name_len = le::u16(m, offset + 100) as usize;
        let name_bytes = m
            .get(offset + 102..offset + 102 + name_len)
            .ok_or_else(|| Error::format("WIM metadata", "name runs past entry"))?;
        let units: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&units);
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let is_dir = attributes & ATTRIBUTE_DIRECTORY != 0;

        let mut next = offset + length.div_ceil(8) * 8;
        for _ in 0..streams {
            let stream_len = field_u64(m, next)? as usize;
            if stream_len == 0 {
                break;
            }
            // An unnamed extra stream carries the file data on some images.
            let stream_name_len = le::u16(m, next + 36) as usize;
            if stream_name_len == 0 && hash == [0u8; 20] {
                hash.copy_from_slice(&m[next + 16..next + 36]);
            }
            next += stream_len.div_ceil(8) * 8;
        }

        out.push(Entry {
            path: path.clone(),
            is_dir,
            hash,
        });
        if is_dir && subdir != 0 {
            stack.push((subdir, path, depth + 1));
        }
        offset = next;
    }
}

fn field_u64(m: &[u8], at: usize) -> Result<u64> {
    m.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
        .ok_or_else(|| Error::format("WIM metadata", "entry beyond end of resource"))
}
