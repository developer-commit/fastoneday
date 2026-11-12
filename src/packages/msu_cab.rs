//! Cabinet-era packages (Windows 10, Windows 11 ≤ 23H2, Server 2016–2022).
//!
//! The MSU is a cabinet of cabinets. Payloads are either members of the
//! innermost cabinets (`<component>\f\file`) or ranges of a `.psf` described
//! by an `express.psf.cix.xml` in an inner cabinet. Stored/MSZIP layers are
//! read in place; LZX layers are streamed.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use super::{Locator, PackageIndex, PayloadEntry, UpdatePackage};
use crate::{
    error::{Error, Result},
    formats::{cab::Cabinet, cix, component::PayloadPath},
    io::{Cancel, Meter, Source},
};

const SKIP_PREFIXES: &[&str] = &["ssu-", "desktopdeployment", "wsusscan", "onepackage"];
const MAX_DEPTH: usize = 5;

pub struct CabMsuPackage {
    root: Arc<Cabinet>,
    spill_dir: PathBuf,
    index: PackageIndex,
    /// Opened nested cabinets by chain.
    opened: Mutex<HashMap<Vec<String>, Arc<Cabinet>>>,
}

impl CabMsuPackage {
    pub fn open(
        source: Source,
        label: String,
        spill_dir: PathBuf,
        cancel: &Cancel,
    ) -> Result<Self> {
        let root = Arc::new(Cabinet::open(source)?);
        let package = Self {
            root,
            spill_dir,
            index: PackageIndex {
                label,
                entries: Vec::new(),
            },
            opened: Mutex::new(HashMap::new()),
        };
        let mut entries = Vec::new();
        package.walk(&package.root.clone(), &mut Vec::new(), &mut entries, cancel)?;
        if entries.is_empty() {
            return Err(Error::format(
                "update package",
                "no component payloads found",
            ));
        }
        Ok(Self {
            index: PackageIndex {
                label: package.index.label.clone(),
                entries,
            },
            ..package
        })
    }

    pub fn with_index(source: Source, index: PackageIndex, spill_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            root: Arc::new(Cabinet::open(source)?),
            spill_dir,
            index,
            opened: Mutex::new(HashMap::new()),
        })
    }

    fn walk(
        &self,
        cab: &Arc<Cabinet>,
        chain: &mut Vec<String>,
        out: &mut Vec<PayloadEntry>,
        cancel: &Cancel,
    ) -> Result<()> {
        cancel.check()?;
        if chain.len() > MAX_DEPTH {
            return Ok(());
        }
        if let Some(cix_member) = cab.find("express.psf.cix.xml").cloned() {
            let xml = cab.extract(&[&cix_member], cancel)?.remove(0);
            let psf_chain = self.locate_psf(chain)?;
            for e in cix::parse(&xml)? {
                let Some(path) = PayloadPath::parse(&e.name) else {
                    continue;
                };
                out.push(PayloadEntry {
                    version: Some(path.component.version.clone()),
                    file_name: path.file_name,
                    kind: path.kind,
                    component: Some(path.component),
                    size: e.source_length,
                    sha256: e.sha256,
                    locator: Locator::Psf {
                        member: psf_chain.clone(),
                        offset: e.offset,
                        length: e.source_length,
                        pa30: e.source_type.eq_ignore_ascii_case("PA30"),
                    },
                    path: e.name,
                });
            }
            return Ok(());
        }
        for file in cab.files() {
            if let Some(path) = PayloadPath::parse(&file.name) {
                let mut full = chain.clone();
                full.push(file.name.clone());
                out.push(PayloadEntry {
                    version: Some(path.component.version.clone()),
                    file_name: path.file_name,
                    kind: path.kind,
                    component: Some(path.component),
                    size: file.size as u64,
                    sha256: None,
                    locator: Locator::Cab { chain: full },
                    path: file.name.clone(),
                });
            }
        }
        let nested: Vec<_> = cab
            .files()
            .iter()
            .filter(|f| {
                let lower = f.name.to_ascii_lowercase();
                lower.ends_with(".cab")
                    && !lower.contains('\\')
                    && !SKIP_PREFIXES.iter().any(|p| lower.starts_with(p))
            })
            .cloned()
            .collect();
        for file in nested {
            chain.push(file.name.clone());
            let child = self.cabinet(chain, cancel)?;
            self.walk(&child, chain, out, cancel)?;
            chain.pop();
        }
        Ok(())
    }

    /// The `.psf` sits next to the cabinet holding the index, or in the root.
    fn locate_psf(&self, chain: &[String]) -> Result<Vec<String>> {
        for depth in (0..=chain.len().saturating_sub(1)).rev() {
            let parent_chain = &chain[..depth];
            let parent = self.cabinet(parent_chain, &Cancel::new())?;
            if let Some(psf) = parent
                .files()
                .iter()
                .find(|f| f.name.to_ascii_lowercase().ends_with(".psf"))
            {
                let mut found = parent_chain.to_vec();
                found.push(psf.name.clone());
                return Ok(found);
            }
        }
        Err(Error::format(
            "update package",
            "express index found but no .psf payload",
        ))
    }

    /// Opens the cabinet at `chain` (empty = the MSU itself), memoized.
    fn cabinet(&self, chain: &[String], cancel: &Cancel) -> Result<Arc<Cabinet>> {
        if chain.is_empty() {
            return Ok(self.root.clone());
        }
        if let Some(cab) = self.opened.lock().expect("opened").get(chain) {
            return Ok(cab.clone());
        }
        let parent = self.cabinet(&chain[..chain.len() - 1], cancel)?;
        let source = self.member_source(&parent, &chain[chain.len() - 1], cancel)?;
        let cab = Arc::new(Cabinet::open(source)?);
        self.opened
            .lock()
            .expect("opened")
            .insert(chain.to_vec(), cab.clone());
        Ok(cab)
    }

    fn member_source(&self, parent: &Cabinet, name: &str, cancel: &Cancel) -> Result<Source> {
        let file = parent
            .find(name)
            .cloned()
            .ok_or_else(|| Error::format("update package", format!("member `{name}` vanished")))?;
        parent.open_member(&file, &self.spill_dir, cancel)
    }
}

impl UpdatePackage for CabMsuPackage {
    fn index(&self) -> &PackageIndex {
        &self.index
    }

    fn read(&self, entry: &PayloadEntry, meter: &dyn Meter, cancel: &Cancel) -> Result<Vec<u8>> {
        match &entry.locator {
            Locator::Cab { chain } => {
                let (member, parents) = chain
                    .split_last()
                    .ok_or_else(|| Error::format("update package", "empty chain"))?;
                let cab = self.cabinet(parents, cancel)?;
                let file = cab.find(member).cloned().ok_or_else(|| {
                    Error::format("update package", format!("`{member}` missing"))
                })?;
                meter.total(Some(file.size as u64));
                let data = cab.extract(&[&file], cancel)?.remove(0);
                meter.advance(file.size as u64);
                Ok(data)
            }
            Locator::Psf {
                member,
                offset,
                length,
                ..
            } if !member.is_empty() => {
                let (psf_name, parents) = member.split_last().expect("non-empty");
                let cab = self.cabinet(parents, cancel)?;
                let psf = self.member_source(&cab, psf_name, cancel)?;
                meter.total(Some(*length));
                let data = psf.read_vec(*offset, *length as usize)?;
                meter.advance(*length);
                Ok(data)
            }
            _ => Err(Error::format(
                "update package",
                "payload locator does not belong to this package",
            )),
        }
    }
}
