//! Raw bindings to the vendored C code (see `csrc/`).

use std::ffi::{c_int, c_longlong, c_void};

pub type ReadFn =
    unsafe extern "C" fn(ctx: *mut c_void, buffer: *mut c_void, bytes: c_int) -> c_int;
pub type WriteFn =
    unsafe extern "C" fn(ctx: *mut c_void, buffer: *const c_void, bytes: c_int) -> c_int;

#[repr(C)]
pub struct FodLzx {
    _private: [u8; 0],
}

#[repr(C)]
pub struct WimlibDecompressor {
    _private: [u8; 0],
}

unsafe extern "C" {
    pub fn fod_lzx_new(
        ctx: *mut c_void,
        read: ReadFn,
        write: WriteFn,
        window_bits: c_int,
        reset_interval: c_int,
        output_length: c_longlong,
    ) -> *mut FodLzx;
    pub fn fod_lzx_decompress(stream: *mut FodLzx, out_bytes: c_longlong) -> c_int;
    pub fn fod_lzx_free(stream: *mut FodLzx);

    pub fn wimlib_global_init(init_flags: c_int) -> c_int;
    pub fn wimlib_create_decompressor(
        compression_type: c_int,
        max_block_size: usize,
        decompressor: *mut *mut WimlibDecompressor,
    ) -> c_int;
    pub fn wimlib_decompress(
        compressed: *const c_void,
        compressed_size: usize,
        uncompressed: *mut c_void,
        uncompressed_size: usize,
        decompressor: *mut WimlibDecompressor,
    ) -> c_int;
    pub fn wimlib_free_decompressor(decompressor: *mut WimlibDecompressor);
}
