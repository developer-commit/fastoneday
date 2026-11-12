//! CAB LZX via libmspack's `lzxd`.

use std::{
    any::Any,
    ffi::{c_int, c_void},
    io,
    panic::{self, AssertUnwindSafe},
};

use crate::{CodecError, ffi};

/// Callbacks plus the first error or panic either of them raised. Panics
/// cannot unwind through C, so they are parked here and resumed once the
/// decoder has returned.
struct Callbacks<'a> {
    input: &'a mut dyn FnMut(&mut [u8]) -> io::Result<usize>,
    output: &'a mut dyn FnMut(&[u8]) -> io::Result<()>,
    error: Option<io::Error>,
    panic: Option<Box<dyn Any + Send>>,
}

unsafe extern "C" fn read_trampoline(ctx: *mut c_void, buffer: *mut c_void, bytes: c_int) -> c_int {
    // SAFETY: `ctx` is the `Callbacks` owned by `decode_cab_folder`, alive for
    // the whole C call, and libmspack never calls back concurrently.
    let callbacks = unsafe { &mut *(ctx as *mut Callbacks<'_>) };
    if bytes <= 0 {
        return 0;
    }
    // SAFETY: libmspack passes a writable buffer of `bytes` bytes.
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, bytes as usize) };
    match panic::catch_unwind(AssertUnwindSafe(|| (callbacks.input)(slice))) {
        Ok(Ok(n)) => n.min(bytes as usize) as c_int,
        Ok(Err(e)) => {
            callbacks.error.get_or_insert(e);
            -1
        }
        Err(payload) => {
            callbacks.panic.get_or_insert(payload);
            -1
        }
    }
}

unsafe extern "C" fn write_trampoline(
    ctx: *mut c_void,
    buffer: *const c_void,
    bytes: c_int,
) -> c_int {
    // SAFETY: as in `read_trampoline`.
    let callbacks = unsafe { &mut *(ctx as *mut Callbacks<'_>) };
    if bytes <= 0 {
        return 0;
    }
    // SAFETY: libmspack passes `bytes` readable bytes.
    let slice = unsafe { std::slice::from_raw_parts(buffer as *const u8, bytes as usize) };
    match panic::catch_unwind(AssertUnwindSafe(|| (callbacks.output)(slice))) {
        Ok(Ok(())) => bytes,
        Ok(Err(e)) => {
            callbacks.error.get_or_insert(e);
            -1
        }
        Err(payload) => {
            callbacks.panic.get_or_insert(payload);
            -1
        }
    }
}

fn mspack_error(code: c_int) -> &'static str {
    match code {
        1 => "bad arguments",
        3 => "read error",
        4 => "write error",
        6 => "out of memory",
        8 => "bad data format",
        11 => "error during decompression",
        _ => "decompression failed",
    }
}

/// Decodes the uncompressed stream of an LZX-compressed CAB folder.
///
/// * `window_bits`: from the folder's compression type (15–21).
/// * `total_len`: the folder's full uncompressed size (sum of `cbUncomp`).
/// * `decode_len`: how many leading bytes to produce (≤ `total_len`).
/// * `input`: yields the folder's CFDATA payloads, concatenated, in order;
///   returning `Ok(0)` signals the end of input.
/// * `output`: receives the plaintext in order.
pub fn decode_cab_folder(
    window_bits: u8,
    total_len: u64,
    decode_len: u64,
    input: &mut dyn FnMut(&mut [u8]) -> io::Result<usize>,
    output: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Result<(), CodecError> {
    if !(15..=21).contains(&window_bits) {
        return Err(CodecError::InvalidParameter(format!(
            "LZX window 2^{window_bits}"
        )));
    }
    let total = i64::try_from(total_len)
        .map_err(|_| CodecError::InvalidParameter("folder too large".into()))?;
    let wanted = decode_len.min(total_len) as i64;
    let mut callbacks = Callbacks {
        input,
        output,
        error: None,
        panic: None,
    };
    let ctx = &mut callbacks as *mut Callbacks<'_> as *mut c_void;
    // SAFETY: the callbacks outlive the stream, which is freed before return.
    let stream = unsafe {
        ffi::fod_lzx_new(
            ctx,
            read_trampoline,
            write_trampoline,
            window_bits as c_int,
            0,
            total,
        )
    };
    if stream.is_null() {
        return Err(CodecError::OutOfMemory);
    }
    // SAFETY: `stream` is valid until `fod_lzx_free`.
    let rc = unsafe { ffi::fod_lzx_decompress(stream, wanted) };
    // SAFETY: freed exactly once.
    unsafe { ffi::fod_lzx_free(stream) };
    if let Some(payload) = callbacks.panic.take() {
        panic::resume_unwind(payload);
    }
    if let Some(error) = callbacks.error.take() {
        return Err(CodecError::Io(error));
    }
    match rc {
        0 => Ok(()),
        6 => Err(CodecError::OutOfMemory),
        code => Err(CodecError::Corrupt(format!("LZX: {}", mspack_error(code)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LZX bit writer: bits are packed MSB-first into little-endian 16-bit
    /// words, as in the format's specification.
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            for i in (0..count).rev() {
                self.acc = (self.acc << 1) | ((value >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out.extend_from_slice(&(self.acc as u16).to_le_bytes());
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }

        /// Pads to the next word boundary (lzxd skips 1–16 bits here).
        fn align(&mut self) {
            let pad = if self.n == 0 { 16 } else { 16 - self.n };
            self.put(0, pad);
        }
    }

    /// One frame stored as an LZX "uncompressed" block.
    fn uncompressed_frame(data: &[u8]) -> Vec<u8> {
        let mut bits = Bits::default();
        bits.put(0, 1); // no E8 translation
        bits.put(3, 3); // block type: uncompressed
        bits.put((data.len() >> 8) as u32, 16);
        bits.put((data.len() & 0xff) as u32, 8);
        bits.align();
        let mut out = bits.out;
        for r in [1u32, 1, 1] {
            out.extend_from_slice(&r.to_le_bytes());
        }
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    #[test]
    fn decodes_an_uncompressed_lzx_frame_through_callbacks() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let stream = uncompressed_frame(&data);
        let mut cursor = 0usize;
        let mut input = |buf: &mut [u8]| -> io::Result<usize> {
            let n = buf.len().min(stream.len() - cursor);
            buf[..n].copy_from_slice(&stream[cursor..cursor + n]);
            cursor += n;
            Ok(n)
        };
        let mut produced = Vec::new();
        let mut output = |chunk: &[u8]| -> io::Result<()> {
            produced.extend_from_slice(chunk);
            Ok(())
        };
        decode_cab_folder(
            15,
            data.len() as u64,
            data.len() as u64,
            &mut input,
            &mut output,
        )
        .unwrap();
        assert_eq!(produced, data);
    }

    #[test]
    fn surfaces_callback_errors() {
        let mut input = |_: &mut [u8]| -> io::Result<usize> { Err(io::Error::other("boom")) };
        let mut output = |_: &[u8]| -> io::Result<()> { Ok(()) };
        let err = decode_cab_folder(15, 100, 100, &mut input, &mut output).unwrap_err();
        assert!(matches!(err, CodecError::Io(_)), "{err}");
    }

    #[test]
    #[should_panic(expected = "sink exploded")]
    fn callback_panics_resume_after_the_decoder_returns() {
        let stream = uncompressed_frame(b"panic test data!");
        let mut cursor = 0usize;
        let mut input = |buf: &mut [u8]| -> io::Result<usize> {
            let n = buf.len().min(stream.len() - cursor);
            buf[..n].copy_from_slice(&stream[cursor..cursor + n]);
            cursor += n;
            Ok(n)
        };
        let mut output = |_: &[u8]| -> io::Result<()> { panic!("sink exploded") };
        let _ = decode_cab_folder(15, 16, 16, &mut input, &mut output);
    }

    #[test]
    fn rejects_bad_windows() {
        let mut input = |_: &mut [u8]| -> io::Result<usize> { Ok(0) };
        let mut output = |_: &[u8]| -> io::Result<()> { Ok(()) };
        assert!(decode_cab_folder(30, 1, 1, &mut input, &mut output).is_err());
    }
}
