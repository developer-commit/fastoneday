//! WIM/ESD chunk decompression via wimlib.

use std::{ffi::c_int, ptr::NonNull, sync::Once};

use crate::{CodecError, ffi};

/// Compression of a WIM resource chunk (wimlib's numbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkCodec {
    Xpress = 1,
    Lzx = 2,
    Lzms = 3,
}

/// A reusable wimlib decompressor for chunks up to `max_chunk` bytes.
pub struct ChunkDecompressor {
    raw: NonNull<ffi::WimlibDecompressor>,
    codec: ChunkCodec,
    max_chunk: usize,
}

// SAFETY: a wimlib decompressor holds no thread-affine state; it is only
// ever used through `&mut self`.
unsafe impl Send for ChunkDecompressor {}

impl ChunkDecompressor {
    pub fn new(codec: ChunkCodec, max_chunk: usize) -> Result<Self, CodecError> {
        // wimlib calls its global init (CPU feature detection) from every
        // wimlib_create_decompressor. Running it once here first means those
        // later calls only ever read the already-published state.
        static GLOBAL_INIT: Once = Once::new();
        // SAFETY: no arguments to get wrong; idempotent.
        GLOBAL_INIT.call_once(|| unsafe {
            ffi::wimlib_global_init(0);
        });
        let mut raw = std::ptr::null_mut();
        // SAFETY: wimlib writes a decompressor pointer on success.
        let rc = unsafe { ffi::wimlib_create_decompressor(codec as c_int, max_chunk, &mut raw) };
        match (rc, NonNull::new(raw)) {
            (0, Some(raw)) => Ok(Self {
                raw,
                codec,
                max_chunk,
            }),
            (0, None) => Err(CodecError::OutOfMemory),
            (code, _) => Err(CodecError::InvalidParameter(format!(
                "{codec:?} decompressor for {max_chunk}-byte chunks (wimlib error {code})"
            ))),
        }
    }

    pub fn codec(&self) -> ChunkCodec {
        self.codec
    }

    pub fn max_chunk(&self) -> usize {
        self.max_chunk
    }

    /// Decompresses one chunk into `output`, whose length must be the
    /// chunk's exact uncompressed size.
    pub fn decompress_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), CodecError> {
        if output.len() > self.max_chunk {
            return Err(CodecError::InvalidParameter(format!(
                "chunk of {} bytes exceeds {}",
                output.len(),
                self.max_chunk
            )));
        }
        // SAFETY: both buffers are valid for their lengths for the call.
        let rc = unsafe {
            ffi::wimlib_decompress(
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr().cast(),
                output.len(),
                self.raw.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(CodecError::Corrupt(format!("{:?} chunk", self.codec)))
        }
    }

    pub fn decompress(
        &mut self,
        input: &[u8],
        uncompressed_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        let mut out = vec![0u8; uncompressed_len];
        self.decompress_into(input, &mut out)?;
        Ok(out)
    }
}

impl Drop for ChunkDecompressor {
    fn drop(&mut self) {
        // SAFETY: created by wimlib_create_decompressor, freed once.
        unsafe { ffi::wimlib_free_decompressor(self.raw.as_ptr()) };
    }
}

/// One-shot convenience for a single chunk.
pub fn decompress_chunk(
    codec: ChunkCodec,
    input: &[u8],
    uncompressed_len: usize,
) -> Result<Vec<u8>, CodecError> {
    ChunkDecompressor::new(codec, uncompressed_len.max(1))?.decompress(input, uncompressed_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Vec<u8>> {
        let text = b"Windows update packages are mostly LZMS-compressed WIM images. ".repeat(4096);
        let mut x86 = Vec::new();
        for i in 0..60_000u32 {
            // E8 call opcodes with relative targets exercise the x86 filter.
            x86.push(0xE8);
            x86.extend_from_slice(&(i.wrapping_mul(2654435761) % 4096).to_le_bytes());
            x86.extend_from_slice(&[0x48, 0x8B, 0xC1, 0x90]);
        }
        let mut noise = Vec::with_capacity(300_000);
        let mut state = 0x1234_5678u32;
        for _ in 0..300_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise.push((state >> 24) as u8 & 0x0F);
        }
        vec![text, x86, noise]
    }

    #[test]
    fn wimlib_lzms_decodes_what_an_independent_encoder_produced() {
        for data in samples() {
            let compressed = lzms::compress(&data).expect("lzms encode");
            assert!(compressed.len() < data.len());
            let decoded =
                decompress_chunk(ChunkCodec::Lzms, &compressed, data.len()).expect("wimlib decode");
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn reuses_a_decompressor_and_enforces_its_chunk_limit() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc".repeat(1000);
        let compressed = lzms::compress(&data).unwrap();
        let mut d = ChunkDecompressor::new(ChunkCodec::Lzms, 1 << 20).unwrap();
        assert_eq!(d.decompress(&compressed, data.len()).unwrap(), data);
        assert_eq!(d.decompress(&compressed, data.len()).unwrap(), data);
        // LZMS has no internal checksum: corrupt input is caught by the
        // SHA-1 every WIM blob carries, not here. Oversized output is.
        assert!(d.decompress(&compressed, (1 << 20) + 1).is_err());
        assert!(ChunkDecompressor::new(ChunkCodec::Lzx, 64 << 20).is_err());
    }
}
