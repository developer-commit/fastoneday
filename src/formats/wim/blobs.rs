//! The blob (lookup) table: SHA-1 → where the bytes live.

use std::collections::HashMap;

use super::header::{RES_METADATA, RES_SOLID, Resource, SOLID_MAGIC};

/// Where a blob's uncompressed bytes come from.
#[derive(Debug, Clone, Copy)]
pub enum BlobLocation {
    /// A standalone (possibly chunk-compressed) resource.
    Resource(Resource),
    /// `size` bytes at `offset` inside the uncompressed contents of solid
    /// group `group`.
    Solid {
        group: usize,
        offset: u64,
        size: u64,
    },
}

#[derive(Debug, Default)]
pub struct BlobTable {
    pub blobs: HashMap<[u8; 20], BlobLocation>,
    pub metadata: Vec<Resource>,
    /// Solid resources, concatenated in table order, form one virtual stream;
    /// solid blob offsets index into that stream (verified on ESD images
    /// whose blob offsets run monotonically across every solid resource).
    pub solid_groups: Vec<Vec<Resource>>,
}

pub fn parse(table: &[u8]) -> BlobTable {
    let mut out = BlobTable::default();
    let mut solid = Vec::new();
    for entry in table.chunks_exact(50) {
        let resource = Resource::parse(&entry[..24]);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&entry[30..50]);
        if resource.flags & RES_SOLID != 0 && resource.original_size == SOLID_MAGIC {
            solid.push(resource);
        } else if resource.flags & RES_METADATA != 0 {
            out.metadata.push(resource);
        } else if resource.flags & RES_SOLID != 0 {
            out.blobs.insert(
                hash,
                BlobLocation::Solid {
                    group: 0,
                    offset: resource.offset,
                    size: resource.stored_size,
                },
            );
        } else {
            out.blobs.insert(hash, BlobLocation::Resource(resource));
        }
    }
    out.solid_groups.push(solid);
    out
}
