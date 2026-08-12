use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::acquisition::Architecture;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UupResolveRequest {
    pub driver_name: String,
    pub os_version: String,
    pub architecture: Architecture,
    pub member_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UupBaseProvenance {
    pub required_baseline: String,
    pub metadata_source: String,
    pub media_source: String,
    #[serde(alias = "uup_update_id")]
    pub update_id: String,
    #[serde(alias = "uup_title")]
    pub update_title: String,
    #[serde(alias = "uup_media")]
    pub media_name: String,
    #[serde(alias = "uup_media_sha1")]
    pub media_sha1: String,
    pub base_sha256: String,
    #[serde(default)]
    pub cache_reused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBase {
    pub path: PathBuf,
    pub sha256: String,
    pub provenance: UupBaseProvenance,
    pub reference_path: Option<PathBuf>,
}
