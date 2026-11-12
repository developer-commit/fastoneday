//! The target PE identity carried in an MSDelta PE preprocess buffer.
//!
//! For PE targets, MSDelta stores the target's image base, checksum and
//! `TimeDateStamp`, followed by a rift table mapping section RVAs to file
//! offsets. Together with the target size from the delta header this pins
//! down the Microsoft Symbol Server key (`TimeDateStamp` + `SizeOfImage`)
//! without needing the base file.

use serde::{Deserialize, Serialize};

use super::bits::{BitReader, IntFormat};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeIdentity {
    pub image_base: u64,
    pub checksum: u32,
    pub time_date_stamp: u32,
    /// `(rva, file_offset)` for each section start, ascending by RVA.
    pub sections: Vec<(u64, u64)>,
}

impl PeIdentity {
    pub fn parse(preprocess: &[u8]) -> Result<Self> {
        let mut reader = BitReader::new(preprocess)?;
        let image_base = reader.read_bits(64)?;
        let checksum = reader.read_bits(32)? as u32;
        let time_date_stamp = reader.read_bits(32)? as u32;
        let mut sections = read_rift(&mut reader)?;
        sections.sort_unstable();
        sections.dedup();
        Ok(Self {
            image_base,
            checksum,
            time_date_stamp,
            sections,
        })
    }

    /// Plausible `SizeOfImage` values, most likely first.
    ///
    /// The last section starts at a known RVA; its virtual extent is bounded by
    /// the bytes left in the file after its raw offset (an embedded
    /// Authenticode signature shrinks it, hence the descending walk).
    pub fn size_of_image_candidates(&self, file_size: u64, limit: usize) -> Vec<u32> {
        const PAGE: u64 = 0x1000;
        let Some(&(last_rva, last_raw)) = self.sections.iter().filter(|(rva, _)| *rva > 0).max()
        else {
            return Vec::new();
        };
        let extent = file_size.saturating_sub(last_raw).max(1);
        let lowest = (last_rva + PAGE).div_ceil(PAGE) * PAGE;
        let highest = (last_rva + extent).div_ceil(PAGE) * PAGE;
        let mut out = Vec::new();
        let mut size = highest;
        while size >= lowest && out.len() < limit {
            out.push(size as u32);
            size -= PAGE;
        }
        for extra in 1..=2 {
            if out.len() < limit {
                out.push((highest + extra * PAGE) as u32);
            }
        }
        out
    }
}

/// `RiftTable::FromBitReader`: entries are delta-coded with two Huffman
/// integer formats.
fn read_rift(reader: &mut BitReader<'_>) -> Result<Vec<(u64, u64)>> {
    if reader.read_bits(1)? == 0 {
        return Ok(Vec::new());
    }
    let source_format = IntFormat::read(reader)?;
    let target_format = IntFormat::read(reader)?;
    let count = reader.read_i64()?;
    if count < 0 || count as usize > reader.remaining() {
        return Err(crate::error::Error::format(
            "delta rift table",
            "entry count out of range",
        ));
    }
    let mut source = 0i64;
    let mut target = 0i64;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        source = source.wrapping_add(source_format.read_number(reader)?);
        target = target.wrapping_add(target_format.read_number(reader)?);
        let file_offset = target.wrapping_add(source);
        if source >= 0 && file_offset >= 0 {
            entries.push((source as u64, file_offset as u64));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::PeIdentity;

    #[test]
    fn size_candidates_cover_the_signed_driver_case() {
        // afd.sys 10.0.26100.1455: last section .reloc at 0xa8000 (raw 0xa8000),
        // file 0xB05A0 bytes with a 0x25A0-byte certificate; SizeOfImage 0xAE000.
        let id = PeIdentity {
            image_base: 0x1c0000000,
            checksum: 0,
            time_date_stamp: 0x53af4121,
            sections: vec![(0, 0), (0x1000, 0x1000), (0xa8000, 0xa8000)],
        };
        let candidates = id.size_of_image_candidates(0xB05A0, 64);
        assert_eq!(candidates[0], 0xB1000);
        assert!(candidates.contains(&0xAE000));
    }
}
