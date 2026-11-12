//! MSDelta (PA19/PA30/PA31) payloads as found in Windows update packages:
//! the 4-byte CRC prefix used inside PSF/CAB payloads, the embedded target
//! size and hash, and the target PE identity. Applying deltas is the job of
//! [`crate::delta_engine`].

mod bits;
mod identity;

pub use identity::PeIdentity;

use crate::{
    domain::{Digest, HashAlgorithm},
    error::{Error, Result},
};

/// What a delta says about the file it produces.
#[derive(Debug, Clone)]
pub struct DeltaInfo {
    /// `PA19`, `PA30` or `PA31`.
    pub format: &'static str,
    /// Reverse deltas reconstruct the *older* file from the newer one.
    pub reverse: bool,
    pub target_size: u64,
    /// Hash of the produced file as published by Microsoft, when present.
    pub target_hash: Option<Digest>,
    /// Present for executable (PE) targets.
    pub pe: Option<PeIdentity>,
}

/// Removes the CRC32 prefix that PSF and CAB payloads put before the magic.
pub fn strip_prefix(blob: &[u8]) -> &[u8] {
    let has_magic = |b: &[u8]| {
        matches!(
            b,
            [b'P', b'A', b'3', b'0' | b'1', ..] | [b'P', b'A', b'1', b'9', ..]
        )
    };
    if !has_magic(blob) && blob.len() > 8 && has_magic(&blob[4..]) {
        &blob[4..]
    } else {
        blob
    }
}

pub fn is_delta(blob: &[u8]) -> bool {
    let blob = strip_prefix(blob);
    blob.starts_with(b"PA30") || blob.starts_with(b"PA31") || blob.starts_with(b"PA19")
}

pub fn inspect(blob: &[u8]) -> Result<DeltaInfo> {
    let delta = strip_prefix(blob);
    let header = msdelta::pa30::parse_header(delta)
        .map_err(|e| Error::format("delta header", e.to_string()))?;
    let format = match header.version {
        msdelta::pa30::FormatVersion::PA19 => "PA19",
        msdelta::pa30::FormatVersion::PA30 => "PA30",
        msdelta::pa30::FormatVersion::PA31 => "PA31",
    };
    let target_hash = HashAlgorithm::from_alg_id(header.hash_alg_id as u32)
        .filter(|_| !header.target_hash.is_empty())
        .map(|alg| Digest::from_bytes(alg, &header.target_hash));
    let reverse = header.file_type_set & 0x100 != 0;
    let pe = if format != "PA19" && header.file_type != 1 && !reverse {
        msdelta::pa30::parse(delta)
            .ok()
            .filter(|parsed| !parsed.preprocess.is_empty())
            .and_then(|parsed| PeIdentity::parse(&parsed.preprocess).ok())
    } else {
        None
    };
    Ok(DeltaInfo {
        format,
        reverse,
        target_size: header.target_size.max(0) as u64,
        target_hash,
        pe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_crc_prefix_only_when_present() {
        let mut blob = vec![1, 2, 3, 4];
        blob.extend_from_slice(b"PA30rest");
        assert_eq!(strip_prefix(&blob), b"PA30rest");
        assert_eq!(strip_prefix(b"PA31x"), b"PA31x");
        assert!(is_delta(&blob));
        assert!(!is_delta(b"MZ\x90\0"));
    }
}
