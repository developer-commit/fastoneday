//! Windows 11 24H2+ / Server 2025 packages: the MSU is an uncompressed WIM
//! holding a `.psf` (payloads) and an LZMS `.wim` (manifests and the
//! `express.psf.cix.xml` index). Everything is read with HTTP ranges, so a
//! multi-gigabyte MSU costs a few dozen megabytes.

use std::sync::Arc;

use super::{Locator, PackageIndex, PayloadEntry, UpdatePackage};
use crate::{
    error::{Error, Result},
    formats::{cix, component::PayloadPath, wim::Wim},
    io::{Cancel, Meter, SliceSource, Source},
};

pub struct WimMsuPackage {
    source: Source,
    index: PackageIndex,
}

impl WimMsuPackage {
    pub fn open(source: Source, label: String) -> Result<Self> {
        let index = Self::build_index(&source, label)?;
        Ok(Self { source, index })
    }

    /// Reuses an index built earlier (from the cache).
    pub fn with_index(source: Source, index: PackageIndex) -> Self {
        Self { source, index }
    }

    fn build_index(source: &Source, label: String) -> Result<PackageIndex> {
        let outer = Wim::open(source.clone())?;
        let pick = |ext: &str| {
            outer
                .entries()
                .iter()
                .filter(|e| !e.is_dir && e.path.to_ascii_lowercase().ends_with(ext))
                .max_by_key(|e| outer.stored_range(e).map(|(_, len)| len).unwrap_or(0))
                .cloned()
        };
        let psf = pick(".psf").ok_or_else(|| Error::format("MSU", "no .psf payload inside"))?;
        let metadata =
            pick(".wim").ok_or_else(|| Error::format("MSU", "no metadata .wim inside"))?;
        let (psf_offset, _) = outer
            .stored_range(&psf)
            .ok_or_else(|| Error::format("MSU", "the .psf is not stored uncompressed"))?;
        let (wim_offset, wim_len) = outer
            .stored_range(&metadata)
            .ok_or_else(|| Error::format("MSU", "the metadata .wim is not stored uncompressed"))?;

        let inner = Wim::open(Arc::new(SliceSource::new(
            source.clone(),
            wim_offset,
            wim_len,
        )))?;
        let cix_entry = inner
            .find("express.psf.cix.xml")
            .ok_or_else(|| Error::format("MSU", "express.psf.cix.xml not found"))?;
        let xml = inner.read(cix_entry)?;
        let entries = cix::parse(&xml)?
            .into_iter()
            .filter_map(|e| {
                let path = PayloadPath::parse(&e.name)?;
                Some(PayloadEntry {
                    version: Some(path.component.version.clone()),
                    file_name: path.file_name,
                    kind: path.kind,
                    component: Some(path.component),
                    size: e.source_length,
                    sha256: e.sha256,
                    locator: Locator::Psf {
                        member: Vec::new(),
                        offset: psf_offset + e.offset,
                        length: e.source_length,
                        pa30: e.source_type.eq_ignore_ascii_case("PA30"),
                    },
                    path: e.name,
                })
            })
            .collect();
        Ok(PackageIndex { label, entries })
    }
}

impl UpdatePackage for WimMsuPackage {
    fn index(&self) -> &PackageIndex {
        &self.index
    }

    fn read(&self, entry: &PayloadEntry, meter: &dyn Meter, cancel: &Cancel) -> Result<Vec<u8>> {
        cancel.check()?;
        match &entry.locator {
            Locator::Psf {
                member,
                offset,
                length,
                ..
            } if member.is_empty() => {
                meter.total(Some(*length));
                let bytes = self.source.read_vec(*offset, *length as usize)?;
                meter.advance(*length);
                Ok(bytes)
            }
            _ => Err(Error::format(
                "MSU",
                "payload locator does not belong to this package",
            )),
        }
    }
}
