use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{acquisition::Architecture, catalog::CatalogRecoveryProvenance};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinbindexResolveRequest {
    pub driver_name: String,
    pub kb_code: String,
    pub os_version: String,
    pub architecture: Option<Architecture>,
    pub selected_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinbindexRecord {
    pub driver_name: String,
    pub sha256: String,
    pub kb_code: String,
    pub requested_os: String,
    pub matched_windows_version: String,
    pub matched_alias: String,
    pub architecture: Architecture,
    pub timestamp: u32,
    pub virtual_size: u64,
    pub index_url: String,
    pub download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum CatalogFallbackReason {
    SymbolUnavailable { status_code: u16 },
    SymbolHashMismatch { actual_sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AcquisitionProvenance {
    SymbolServer,
    Catalog {
        fallback_reason: CatalogFallbackReason,
        recovery: Box<CatalogRecoveryProvenance>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadResult {
    pub destination: PathBuf,
    pub sha256: String,
    pub source_url: String,
    pub bytes_written: u64,
    pub reused: bool,
    pub record: WinbindexRecord,
    pub provenance: AcquisitionProvenance,
}
