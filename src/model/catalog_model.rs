use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{acquisition::Architecture, uup::UupBaseProvenance};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogUpdate {
    pub update_id: String,
    pub title: String,
    pub product: String,
    pub classification: String,
    pub last_updated: String,
    pub version: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDetail {
    pub update_id: String,
    pub title: String,
    pub architecture: Architecture,
    pub products: String,
    pub kb_numbers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPackage {
    pub update_id: String,
    pub url: String,
    pub filename: String,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRecoveryRequest {
    pub driver_name: String,
    pub kb_code: String,
    pub os_version: String,
    pub architecture: Architecture,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsfPayloadKind {
    Forward,
    Neutral,
    Reverse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsfPayload {
    pub psf_path: PathBuf,
    pub member_path: String,
    pub kind: PsfPayloadKind,
    pub source_type: String,
    pub offset: u64,
    pub length: u64,
    pub source_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum CatalogExtraction {
    MsuDirect {
        extractor: String,
    },
    CabDirect {
        extractor: String,
        cab: String,
    },
    PsfNeutral {
        member_path: String,
    },
    PsfNullDelta {
        hydrator: String,
        member_path: String,
    },
    PsfMsdelta {
        hydrator: String,
        base_sha256: String,
        member_path: String,
    },
    PsfRtmMsdelta {
        hydrator: String,
        hydrator_revision: Option<String>,
        base_sha256: String,
        member_path: String,
        base: Box<UupBaseProvenance>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPackageProvenance {
    pub package: CatalogPackage,
    pub downloaded_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRecoveryProvenance {
    pub update: CatalogUpdate,
    pub package: CatalogPackageProvenance,
    pub extraction: CatalogExtraction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRecoveredBinary {
    pub destination: PathBuf,
    pub sha256: String,
    pub bytes_written: u64,
    pub reused: bool,
    pub source_url: String,
    pub provenance: CatalogRecoveryProvenance,
}
