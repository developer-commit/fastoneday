//! The acquisition path: one function from (patch pair, side, binary) to an
//! exact, hash-verified file. Package access, materialization and the
//! per-family flows are separate modules.

mod baseline;
mod loader;
mod materialize;
mod office;
mod progress;
mod windows;

use std::sync::Arc;

pub use loader::PackageLoader;
pub use materialize::Materialized;
pub use progress::{Progress, Silent, Step};

use crate::{
    domain::{BinaryName, Family, PatchPair, Side, UpdateRef},
    error::{Error, Result},
    formats::pe,
    io::Cancel,
    net::Http,
    sources::symbols::SymbolServer,
    store::Cache,
};

pub struct Engine {
    pub(crate) loader: PackageLoader,
    pub(crate) symbols: SymbolServer,
    pub(crate) baseline: baseline::ReleaseBaseline,
}

/// Steering for the before side: stay on the component/path the after side used.
#[derive(Debug, Clone, Default)]
pub struct Hint {
    pub component: Option<crate::formats::component::Component>,
    pub path: Option<String>,
}

impl Hint {
    pub fn from(materialized: &Materialized) -> Self {
        Self {
            component: materialized.entry.component.clone(),
            path: Some(materialized.entry.path.clone()),
        }
    }

    pub fn component_key(&self) -> Option<String> {
        self.component
            .as_ref()
            .map(crate::formats::component::Component::key)
    }
}

impl Engine {
    pub fn new(http: Arc<Http>, cache: Cache) -> Self {
        Self {
            loader: PackageLoader::new(http.clone(), cache.clone()),
            baseline: baseline::ReleaseBaseline::new(http.clone(), cache),
            symbols: SymbolServer::new(http),
        }
    }

    pub fn acquire(
        &self,
        pair: &PatchPair,
        side: Side,
        binary: &BinaryName,
        hint: &Hint,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Materialized> {
        let update = match side {
            Side::Before => &pair.before,
            Side::After => &pair.after,
        };
        let mut result = match (pair.family, update) {
            (Family::Windows, UpdateRef::Kb { kb }) => {
                windows::acquire(self, pair, kb, binary, hint, progress, cancel)
            }
            (Family::OfficeMsi, UpdateRef::Kb { kb }) => {
                office::acquire_msi(self, pair, kb, binary, progress, cancel)
            }
            (Family::OfficeC2r, UpdateRef::OfficeBuild { channel, version }) => {
                office::acquire_c2r(
                    self,
                    pair,
                    (channel, version),
                    binary,
                    hint.path.as_deref(),
                    progress,
                    cancel,
                )
            }
            _ => Err(Error::Unsupported(format!(
                "{} cannot use update {update}",
                pair.family.label()
            ))),
        }?;
        if (result.version.is_none() || pair.family != Family::Windows)
            && let Ok(info) = pe::parse(&result.bytes)
        {
            result.version = info.file_version.or(result.version);
        }
        Ok(result)
    }

    /// Binary names carried by the fixing update (for completion and to
    /// confirm detection). With `allow_download == false`, returns `None`
    /// rather than downloading a whole package.
    pub fn after_package_names(
        &self,
        pair: &PatchPair,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Option<Vec<String>>> {
        let package = match (pair.family, &pair.after) {
            (Family::Windows, UpdateRef::Kb { kb }) => {
                let catalog =
                    self.loader
                        .catalog_package(kb, &pair.product, pair.arch, progress)?;
                self.loader
                    .windows_with(kb, catalog.primary(), allow_download, progress, cancel)?
            }
            (Family::OfficeMsi, UpdateRef::Kb { kb }) => {
                let catalog =
                    self.loader
                        .catalog_package(kb, &pair.product, pair.arch, progress)?;
                self.loader.office_msi_with(
                    kb,
                    catalog.primary(),
                    allow_download,
                    progress,
                    cancel,
                )?
            }
            (Family::OfficeC2r, UpdateRef::OfficeBuild { channel, version }) => {
                let channel = crate::sources::office::Channel::from_short(channel)
                    .ok_or_else(|| Error::Input(format!("unknown channel {channel}")))?;
                Some(
                    self.loader
                        .c2r(channel, version, pair.arch, progress, cancel)?,
                )
            }
            _ => None,
        };
        Ok(package.map(|p| p.index().binary_names()))
    }

    /// The PDB matching `image`, when the Symbol Server has it.
    pub fn pdb(&self, image: &[u8]) -> Result<Option<(String, Vec<u8>)>> {
        let Some(codeview) = pe::parse(image).ok().and_then(|i| i.codeview) else {
            return Ok(None);
        };
        Ok(self
            .symbols
            .pdb(&codeview)?
            .map(|bytes| (codeview.pdb_name.clone(), bytes)))
    }
}
