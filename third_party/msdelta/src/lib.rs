//! Pure-Rust encoder and decoder for Microsoft's MSDelta binary patch format.
//!
//! Supports PA30, PA31, and PA19 delta formats, the DCM wrapper used for
//! Windows component manifests, and all associated compression codecs
//! (PseudoLzx, BsDiff, LZX, LZMS).
//!
//! # Quick start
//!
//! ```no_run
//! # let base_manifest = vec![0u8; 100];
//! # let (old_file, new_file) = (vec![0u8; 10], vec![0u8; 10]);
//! // Decode a DCM-wrapped manifest
//! let compressed = std::fs::read("manifest.dcm").unwrap();
//! let pa30_data = msdelta::dcm::strip(&compressed).unwrap();
//! let xml = msdelta::pa30::apply(&base_manifest, pa30_data).unwrap();
//!
//! // Create a delta
//! let delta = msdelta::pa30::create(&old_file, &new_file).unwrap();
//!
//! // Create a delta with integrity hash
//! use msdelta::pa30::{CreateOptions, HASH_ALG_SHA256};
//! let delta = CreateOptions::new()
//!     .hash_algorithm(HASH_ALG_SHA256)
//!     .execute(&old_file, &new_file)
//!     .unwrap();
//! ```

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input too short")]
    Truncated,
    #[error("bad magic (expected {expected:?}, got {got:?})")]
    BadMagic {
        expected: &'static [u8],
        got: Vec<u8>,
    },
    #[error("bitstream exhausted: needed {needed} bits, {available} available")]
    BitstreamExhausted { needed: u32, available: u32 },
    #[error("invalid variable-length integer encoding")]
    InvalidVarInt,
    #[error("target hash too large ({size} bytes, max {max})")]
    HashTooLarge { size: usize, max: usize },
    #[error("malformed stream: {0}")]
    Malformed(&'static str),
    /// The delta requires a PE transform this crate does not yet faithfully
    /// implement. Returned up front instead of silently producing wrong bytes
    /// (which would only surface as a late hash mismatch). See TODO.md.
    #[error("unsupported transform: {0}")]
    Unsupported(&'static str),
    #[error("target hash mismatch (expected {expected}, got {got})")]
    HashMismatch { expected: String, got: String },
    #[error("PA19: {0}")]
    Pa19(String),
    #[error("base manifest extraction: {0}")]
    BaseManifest(&'static str),
    #[error(transparent)]
    Lzms(#[from] lzms::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
pub(crate) mod bitstream;
#[allow(dead_code)]
pub(crate) mod bsdiff;
pub mod dcm;
#[allow(dead_code)]
pub(crate) mod huffman;
#[allow(dead_code)]
pub(crate) mod lzx;
pub mod pa19;
pub mod pa30;
#[allow(dead_code)]
pub(crate) mod pe;
#[cfg(feature = "winsxs")]
pub mod winsxs;
#[allow(dead_code)]
pub(crate) mod xpress;

/// Decoder entry points exposed only under the `fuzzing` feature so the fuzz
/// harnesses can target the bit-level codecs directly (these are internal
/// `pub(crate)` items in normal builds).
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use crate::Result;

    /// Fuzz the XPRESS_HUFF Compression-API container decoder.
    pub fn xpress_decompress_container(data: &[u8]) -> Result<Vec<u8>> {
        crate::xpress::decompress_container(data)
    }

    /// Decode the PseudoLzx patch codec directly (returns partial output on
    /// error) for differential debugging against real artifacts.
    pub fn lzx_decompress_partial(
        reference: &[u8],
        patch_data: &[u8],
        target_size: usize,
    ) -> (Vec<u8>, Option<crate::Error>) {
        crate::lzx::decompress_partial(reference, patch_data, target_size)
    }

    /// Apply the x86 `0xE8` un-translation in place (differential debug).
    pub fn undo_x86_e8_translation(buf: &mut [u8]) -> u32 {
        crate::pe::transform::undo_x86_e8_translation(buf)
    }

    /// The amd64 length decoder used by `TransformDisasmX64`: (length,
    /// remappable-field offset, remap?).
    pub fn disasm_amd64(code: &[u8]) -> (u8, u8, bool) {
        let i = crate::pe::transform::disasm_amd64(code);
        (i.len, i.field_off, i.remap)
    }

    /// The decoder's opcode tables: 1-byte ModRM kinds, 0F ModRM kinds,
    /// 1-byte immediate kinds, 0F immediate kinds.
    pub fn disasm_amd64_tables() -> [[u8; 256]; 4] {
        use crate::pe::transform::{IMM_0F, IMM_1B, MODRM_0F, MODRM_1B};
        [MODRM_1B, MODRM_0F, IMM_1B, IMM_0F]
    }

    /// For a managed image: named file ranges of its CLI structures (metadata
    /// tables per table id, heaps, IL method bodies) for diff attribution.
    /// `(T(source), output, per-byte copy source or -1, rift as (target, source) pairs)`.
    #[allow(clippy::type_complexity)]
    pub fn trace_copies(
        reference: &[u8],
        delta: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<i64>, Vec<(i64, i64)>)> {
        let (tsrc, out, csrc, rift) = crate::pa30::trace_copies(reference, delta)?;
        let pairs = rift.entries.iter().map(|e| (e.source, e.target)).collect();
        Ok((tsrc, out, csrc, pairs))
    }

    pub fn cli_regions(image: &[u8]) -> Vec<(String, usize, usize)> {
        crate::pe::cli::diagnostics::regions(image)
    }

    /// Table columns pointing into `#Blob`: (heap offset, owner).
    pub fn cli_blob_refs(image: &[u8]) -> Vec<(u32, String)> {
        crate::pe::cli::diagnostics::blob_refs(image)
    }

    /// Metadata table row counts of a managed image.
    pub fn cli_row_counts(image: &[u8]) -> Vec<u32> {
        crate::pe::cli::metadata::parse_cli_metadata_from_pe(
            image,
            crate::pe::cli::schema::CliSchemaFlavor::Cli4,
        )
        .map(|m| m.row_counts.to_vec())
        .unwrap_or_default()
    }

    /// File offset and size of the `#Blob` heap.
    pub fn cli_blob_heap(image: &[u8]) -> Option<(usize, usize)> {
        crate::pe::cli::diagnostics::blob_heap(image)
    }

    /// Apply without the target-hash check, returning the reconstructed bytes
    /// even when they are wrong (differential debugging against native output).
    pub fn apply_unverified(reference: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
        crate::pa30::apply_impl(reference, delta, false)
    }

    /// The transformed source T(source) the PseudoLzx stage copies from (for
    /// PE deltas) and a summary of the delta header and PE preprocess state.
    pub fn diagnose(reference: &[u8], delta: &[u8]) -> Result<(Option<Vec<u8>>, String)> {
        crate::pa30::diagnose(reference, delta)
    }

    /// Fuzz the reverse-delta (`ReversePatchFormat`) apply against a reference.
    pub fn apply_reversal(
        target: &[u8],
        reversal_data: &[u8],
        source_size: usize,
    ) -> Result<Vec<u8>> {
        crate::pa30::reverse::apply_reversal(target, reversal_data, source_size)
    }
}
