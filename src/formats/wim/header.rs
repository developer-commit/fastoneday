//! WIM header and resource descriptors.

use crate::{
    error::{Error, Result},
    io::{ReadAt, le},
};

pub const HEADER_SIZE: usize = 208;
const FLAG_COMPRESSION: u32 = 0x0000_0002;
const FLAG_XPRESS: u32 = 0x0002_0000;
const FLAG_LZX: u32 = 0x0004_0000;
const FLAG_LZMS: u32 = 0x0008_0000;

pub const RES_METADATA: u8 = 0x02;
pub const RES_COMPRESSED: u8 = 0x04;
pub const RES_SOLID: u8 = 0x10;

/// Marker in `original_size` for the descriptor of a solid resource.
pub const SOLID_MAGIC: u64 = 0x1_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WimCompression {
    None,
    Xpress,
    Lzx,
    Lzms,
}

/// `RESHDR_DISK_SHORT`: 7-byte size, flags, offset, original size.
#[derive(Debug, Clone, Copy, Default)]
pub struct Resource {
    pub stored_size: u64,
    pub flags: u8,
    pub offset: u64,
    pub original_size: u64,
}

impl Resource {
    pub fn parse(b: &[u8]) -> Self {
        let mut size = [0u8; 8];
        size[..7].copy_from_slice(&b[..7]);
        Self {
            stored_size: u64::from_le_bytes(size),
            flags: b[7],
            offset: le::u64(b, 8),
            original_size: le::u64(b, 16),
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & RES_COMPRESSED != 0
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub chunk_size: u32,
    pub compression: WimCompression,
    pub blob_table: Resource,
    pub xml: Resource,
}

pub fn parse(source: &dyn ReadAt) -> Result<Header> {
    let b = source.read_vec(0, HEADER_SIZE)?;
    if &b[..8] != b"MSWIM\0\0\0" {
        return Err(Error::format("WIM", "missing MSWIM signature"));
    }
    let flags = le::u32(&b, 16);
    let compression = if flags & FLAG_COMPRESSION == 0 {
        WimCompression::None
    } else if flags & FLAG_LZMS != 0 {
        WimCompression::Lzms
    } else if flags & FLAG_LZX != 0 {
        WimCompression::Lzx
    } else if flags & FLAG_XPRESS != 0 {
        WimCompression::Xpress
    } else {
        return Err(Error::format(
            "WIM",
            format!("unknown compression flags {flags:#x}"),
        ));
    };
    let total_parts = le::u16(&b, 42);
    if total_parts > 1 {
        return Err(Error::Unsupported(
            "split (multi-part) WIM files are not supported".into(),
        ));
    }
    Ok(Header {
        version: le::u32(&b, 12),
        chunk_size: le::u32(&b, 20),
        compression,
        blob_table: Resource::parse(&b[48..72]),
        xml: Resource::parse(&b[72..96]),
    })
}
