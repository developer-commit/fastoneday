//! Update packages as a uniform list of payloads.
//!
//! Whatever the container (24H2+ WIM-based MSU, CAB-era MSU, Office MSP,
//! Click-to-Run stream), a package becomes a [`PackageIndex`]: which files it
//! carries, in which form (full, null delta, forward delta), and how to read
//! the stored bytes back.

mod c2r;
mod index;
mod msp;
mod msu_cab;
mod msu_wim;

use std::sync::Arc;

pub use c2r::C2rPackage;
pub use index::{Locator, PackageIndex, PayloadEntry};
pub use msp::OfficeMspPackage;
pub use msu_cab::CabMsuPackage;
pub use msu_wim::WimMsuPackage;

use crate::{
    error::Result,
    io::{Cancel, Meter, ReadAt},
};

/// An opened package that can hand back stored payload bytes.
pub trait UpdatePackage: Send + Sync {
    fn index(&self) -> &PackageIndex;

    /// The stored bytes of `entry` (a delta or a file, per `entry.kind`).
    fn read(&self, entry: &PayloadEntry, meter: &dyn Meter, cancel: &Cancel) -> Result<Vec<u8>>;
}

/// Shape of a Windows package, decided from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsuShape {
    /// `MSWIM`: uncompressed WIM container, readable with HTTP ranges.
    Wim,
    /// `MSCF`: cabinet, must be downloaded and unpacked.
    Cab,
}

pub fn sniff(source: &dyn ReadAt) -> Result<MsuShape> {
    let magic = source.read_vec(0, 5.min(source.size() as usize))?;
    if magic.starts_with(b"MSWIM") {
        Ok(MsuShape::Wim)
    } else if magic.starts_with(b"MSCF") {
        Ok(MsuShape::Cab)
    } else {
        Err(crate::error::Error::format(
            "update package",
            "neither a WIM nor a cabinet",
        ))
    }
}

pub type SharedPackage = Arc<dyn UpdatePackage>;
