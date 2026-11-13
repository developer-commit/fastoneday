//! The acquisition path: one function from (patch pair, side, binary) to an
//! exact, hash-verified file. Package access, materialization and the
//! per-family flows are separate modules.

mod baseline;
mod defender;
mod loader;
mod materialize;
mod office;
mod progress;
mod windows;

use std::sync::Arc;

pub use defender::DefenderPackage;

/// What the Symbol Server has for a file's debug symbols.
pub enum Pdb {
    /// The file names no PDB (not a PE image, or no CodeView record — e.g.
    /// resource-only `.mui` and `.vdm` files).
    NotNamed,
    NotPublished,
    Found {
        name: String,
        bytes: Vec<u8>,
    },
}
pub use loader::{Opened, PackageLoader};
pub use materialize::Materialized;
pub use progress::{Progress, Silent, Step};

use crate::{
    domain::{BinaryName, Family, PatchPair, Side, UpdateRef},
    error::{Error, Result},
    formats::pe,
    io::Cancel,
    net::Http,
    packages::SharedPackage,
    sources::symbols::SymbolServer,
    store::Cache,
};

/// What one update of a patch pair carries (see [`Engine::update_files`]).
pub enum UpdateFiles {
    /// A package whose index lists every payload.
    Package {
        package: SharedPackage,
        /// Read in place rather than from a downloaded copy.
        remote: bool,
    },
    /// File names only (a Defender package's cabinet).
    Names(Vec<String>),
    /// The package must be downloaded whole before its files are known.
    NeedsDownload { name: String, size: Option<u64> },
}

pub struct Engine {
    pub(crate) loader: PackageLoader,
    pub(crate) symbols: SymbolServer,
    pub(crate) baseline: baseline::ReleaseBaseline,
    pub(crate) http: Arc<Http>,
    pub(crate) cache: Cache,
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
            baseline: baseline::ReleaseBaseline::new(http.clone(), cache.clone()),
            symbols: SymbolServer::new(http.clone()),
            http,
            cache,
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
            (Family::DefenderEngine, UpdateRef::Engine { version }) => {
                defender::acquire(self, pair, version, binary, progress, cancel)
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

    /// What one side of `pair` carries, for listing its files. With
    /// `allow_download == false` a package that is only readable after a
    /// full download is reported as [`UpdateFiles::NeedsDownload`] instead.
    pub fn update_files(
        &self,
        pair: &PatchPair,
        side: Side,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<UpdateFiles> {
        let update = match side {
            Side::Before => &pair.before,
            Side::After => &pair.after,
        };
        let opened = match (pair.family, update) {
            (Family::Windows, UpdateRef::Kb { kb }) => {
                let catalog = self.catalog(pair, kb, progress)?;
                self.loader
                    .windows_with(kb, catalog.primary(), allow_download, progress, cancel)?
            }
            (Family::OfficeMsi, UpdateRef::Kb { kb }) => {
                let catalog = self.catalog(pair, kb, progress)?;
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
                Opened::Package {
                    package: self
                        .loader
                        .c2r(channel, version, pair.arch, progress, cancel)?,
                    remote: true,
                }
            }
            (Family::DefenderEngine, UpdateRef::Engine { version }) => {
                return self
                    .defender_files(version, pair.arch, progress)
                    .map(UpdateFiles::Names);
            }
            _ => {
                return Err(Error::Unsupported(format!(
                    "{} cannot use update {update}",
                    pair.family.label()
                )));
            }
        };
        Ok(match opened {
            Opened::Package { package, remote } => UpdateFiles::Package { package, remote },
            Opened::NeedsDownload { name, size } => UpdateFiles::NeedsDownload { name, size },
        })
    }

    /// The Update Catalog entry of `kb` for `pair`'s product. A hotpatch the
    /// Catalog does not list gets a reason that says so.
    pub(crate) fn catalog(
        &self,
        pair: &PatchPair,
        kb: &str,
        progress: &dyn Progress,
    ) -> Result<crate::sources::catalog::CatalogPackage> {
        self.loader
            .catalog_package(kb, &pair.product, pair.arch, progress)
            .map_err(|e| match e {
                Error::NotFound(_) if pair.kind.eq_ignore_ascii_case("hotpatch") => {
                    Error::NotFound(format!(
                        "{kb} is a hotpatch and the Update Catalog does not list it (hotpatches \
                         usually ship only through Windows Update); pick the cumulative update \
                         row of {}",
                        pair.short_product()
                    ))
                }
                other => other,
            })
    }

    /// The PDB matching `image`, when the Symbol Server has it.
    pub fn pdb(&self, image: &[u8]) -> Result<Pdb> {
        let Some(codeview) = pe::parse(image).ok().and_then(|i| i.codeview) else {
            return Ok(Pdb::NotNamed);
        };
        Ok(match self.symbols.pdb(&codeview)? {
            Some(bytes) => Pdb::Found {
                name: codeview.pdb_name.clone(),
                bytes,
            },
            None => Pdb::NotPublished,
        })
    }
}
