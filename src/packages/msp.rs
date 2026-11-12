//! MSI-based Office security updates: a Catalog cabinet holding an `.msp`
//! whose embedded cabinet carries complete files keyed by MSI file keys.

use std::{path::Path, sync::Arc};

use super::{Locator, PackageIndex, PayloadEntry, UpdatePackage};
use crate::{
    error::{Error, Result},
    formats::{cab::Cabinet, component::PayloadKind, msp},
    io::{Cancel, Meter, Source},
};

pub struct OfficeMspPackage {
    cabinets: Vec<(String, Arc<Cabinet>)>,
    index: PackageIndex,
}

impl OfficeMspPackage {
    pub fn open(package: Source, label: String, spill_dir: &Path, cancel: &Cancel) -> Result<Self> {
        let outer = Cabinet::open(package)?;
        let msp_file = outer
            .files()
            .iter()
            .find(|f| f.name.to_ascii_lowercase().ends_with(".msp"))
            .cloned()
            .ok_or_else(|| Error::format("Office update", "no .msp inside the cabinet"))?;
        let msp_source = outer.open_member(&msp_file, spill_dir, cancel)?;
        let mut cabinets = Vec::new();
        let mut entries = Vec::new();
        for patch in msp::cabinets(msp_source, spill_dir)? {
            let cab = Arc::new(Cabinet::open(patch.data)?);
            for file in cab.files() {
                entries.push(PayloadEntry {
                    path: file.name.clone(),
                    file_name: msp::file_name_from_key(&file.name),
                    kind: PayloadKind::Full,
                    component: None,
                    version: None,
                    size: file.size as u64,
                    sha256: None,
                    locator: Locator::Msp {
                        stream: patch.stream.clone(),
                        key: file.name.clone(),
                    },
                });
            }
            cabinets.push((patch.stream, cab));
        }
        Ok(Self {
            cabinets,
            index: PackageIndex { label, entries },
        })
    }
}

impl UpdatePackage for OfficeMspPackage {
    fn index(&self) -> &PackageIndex {
        &self.index
    }

    fn read(&self, entry: &PayloadEntry, meter: &dyn Meter, cancel: &Cancel) -> Result<Vec<u8>> {
        let Locator::Msp { stream, key } = &entry.locator else {
            return Err(Error::format(
                "Office update",
                "payload locator does not belong to this package",
            ));
        };
        let (_, cab) = self
            .cabinets
            .iter()
            .find(|(name, _)| name == stream)
            .ok_or_else(|| Error::format("Office update", format!("stream `{stream}` missing")))?;
        let file = cab
            .find(key)
            .cloned()
            .ok_or_else(|| Error::format("Office update", format!("`{key}` missing")))?;
        meter.total(Some(file.size as u64));
        let data = cab.extract(&[&file], cancel)?.remove(0);
        meter.advance(file.size as u64);
        Ok(data)
    }
}
