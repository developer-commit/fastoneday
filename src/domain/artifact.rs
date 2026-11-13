use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{BinaryName, CveId, Digest, PatchPair, UpdateRef};

/// Which side of the patch a binary belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Before,
    After,
}

impl Side {
    pub fn label(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// How the exact bytes were produced. Every variant ends in a hash check
/// against a value that came from Microsoft's own update package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Materialization {
    /// The package stores the complete file.
    FullFile { package: String },
    /// A null (from-empty) delta in the package was expanded.
    NullDelta {
        package: String,
        /// The MSDelta implementation that produced the bytes.
        #[serde(default)]
        engine: String,
    },
    /// Identity from the package's forward delta; bytes from the Microsoft
    /// Symbol Server.
    SymbolServer { package: String, url: String },
    /// The unchanged file taken from the release (RTM) install image.
    ReleaseImage { image: String },
    /// A member of a Microsoft Defender security intelligence package
    /// (`mpam-fe.exe`), checked against its Authenticode digest.
    DefenderPackage { package: String, url: String },
    /// Forward delta applied to a base that was itself materialized.
    DeltaApplied {
        package: String,
        base_version: String,
        base_package: String,
        /// The MSDelta implementation that produced the bytes.
        #[serde(default)]
        engine: String,
    },
}

impl Materialization {
    pub fn summary(&self) -> String {
        match self {
            Self::FullFile { package } => format!("full file from {package}"),
            Self::NullDelta { package, .. } => format!("expanded from {package}"),
            Self::SymbolServer { package, .. } => {
                format!("Symbol Server, identity from {package}")
            }
            Self::ReleaseImage { image } => format!("release image {image}"),
            Self::DefenderPackage { package, .. } => format!("Defender package {package}"),
            Self::DeltaApplied {
                package,
                base_version,
                engine,
                ..
            } => format!("delta from {package} applied to {base_version} ({engine})"),
        }
    }
}

/// One acquired, verified binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acquired {
    pub side: Side,
    pub update: UpdateRef,
    pub name: BinaryName,
    /// File version from the package component or the PE version resource.
    pub version: Option<String>,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Digest,
    /// The hash Microsoft published for this file that we verified against.
    pub verified_with: Option<Digest>,
    pub how: Materialization,
    pub pdb: Option<PathBuf>,
}

/// The finished diffing case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub cve: CveId,
    pub pair: PatchPair,
    pub binary: BinaryName,
    pub directory: PathBuf,
    pub before: Acquired,
    pub after: Acquired,
}
