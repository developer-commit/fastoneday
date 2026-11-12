//! Battle-tested C decompressors, vendored and built from source:
//!
//! * [`lzx`] — LZX for CAB folders, from **libmspack** (the library behind
//!   cabextract, LGPL-2.1).
//! * [`wim`] — LZMS, LZX and XPRESS chunks of WIM/ESD resources, from
//!   **wimlib** (LGPL-2.1-or-later option of its dual license).
//!
//! Exact upstream versions and licenses are recorded in
//! `third_party/README.md`. All `unsafe` FFI is contained in this crate.

mod ffi;
pub mod lzx;
pub mod wim;

use std::{fmt, io};

#[derive(Debug)]
pub enum CodecError {
    /// A parameter the C library rejects (window size, block size, ...).
    InvalidParameter(String),
    OutOfMemory,
    /// The compressed data is corrupt or truncated.
    Corrupt(String),
    /// A callback supplying input or consuming output failed.
    Io(io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(what) => write!(f, "invalid decompressor parameter: {what}"),
            Self::OutOfMemory => f.write_str("decompressor out of memory"),
            Self::Corrupt(what) => write!(f, "corrupt compressed data: {what}"),
            Self::Io(e) => write!(f, "decompressor I/O: {e}"),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
