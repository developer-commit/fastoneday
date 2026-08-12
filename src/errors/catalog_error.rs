use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::acquisition::{Architecture, HashAlgorithm};

use super::{BoxError, ClassifiedError, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogStage {
    Search,
    Detail,
    DownloadDialog,
    PackageDownload,
    Extraction,
    Publish,
}

impl fmt::Display for CatalogStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Search => "search",
            Self::Detail => "detail",
            Self::DownloadDialog => "download_dialog",
            Self::PackageDownload => "package_download",
            Self::Extraction => "extraction",
            Self::Publish => "publish",
        })
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("Catalog request failed during `{stage}`")]
    Network {
        stage: CatalogStage,
        url: Option<String>,
        #[source]
        source: BoxError,
    },

    #[error("Catalog returned HTTP {status_code} during `{stage}`")]
    Http {
        stage: CatalogStage,
        url: Option<String>,
        status_code: u16,
    },

    #[error("no Catalog update for {kb_code} / {os_version} / {architecture}")]
    UpdateNotFound {
        kb_code: String,
        os_version: String,
        architecture: Architecture,
    },

    #[error("multiple Catalog updates for {kb_code} / {os_version} / {architecture}")]
    AmbiguousUpdate {
        kb_code: String,
        os_version: String,
        architecture: Architecture,
        candidate_ids: Vec<String>,
    },

    #[error("invalid Catalog payload during `{stage}`: {reason}")]
    InvalidPayload { stage: CatalogStage, reason: String },

    #[error("required Catalog recovery tool `{tool}` is unavailable: {remediation}")]
    ToolUnavailable { tool: String, remediation: String },

    #[error("could not hydrate `{driver_name}`: {reason}")]
    HydrationFailed { driver_name: String, reason: String },

    #[error("external tool `{tool}` failed with status {status:?}: {stderr}")]
    ToolFailed {
        tool: String,
        status: Option<i32>,
        stderr: String,
    },

    #[error("{algorithm} mismatch for `{path}`: expected {expected}, found {actual}")]
    HashMismatch {
        algorithm: HashAlgorithm,
        expected: String,
        actual: String,
        path: PathBuf,
    },

    #[error("could not publish recovered artifact to `{path}`")]
    Publish {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl ClassifiedError for CatalogError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Network { .. } | Self::Http { .. } => ErrorCode::NetworkFetch,
            Self::UpdateNotFound { .. } => ErrorCode::NotFound,
            Self::AmbiguousUpdate { .. } => ErrorCode::AmbiguousSelection,
            Self::ToolUnavailable { .. } => ErrorCode::ExternalToolUnavailable,
            Self::ToolFailed { .. } => ErrorCode::ExternalToolFailed,
            Self::InvalidPayload { .. }
            | Self::HydrationFailed { .. }
            | Self::HashMismatch { .. }
            | Self::Publish { .. } => ErrorCode::ArtifactIntegrity,
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Network { .. } => true,
            Self::Http { status_code, .. } => *status_code == 429 || *status_code >= 500,
            _ => false,
        }
    }
}
