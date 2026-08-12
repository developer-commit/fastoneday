use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::acquisition::{Architecture, HashAlgorithm};

use super::{BoxError, ClassifiedError, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UupStage {
    BuildList,
    MediaList,
    MediaDownload,
    ComponentExtraction,
    Cache,
}

impl fmt::Display for UupStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BuildList => "build_list",
            Self::MediaList => "media_list",
            Self::MediaDownload => "media_download",
            Self::ComponentExtraction => "component_extraction",
            Self::Cache => "cache",
        })
    }
}

#[derive(Debug, Error)]
pub enum UupError {
    #[error("invalid UUP component member `{member_path}`")]
    InvalidComponent { member_path: String },

    #[error("UUP request to `{url}` failed")]
    Network {
        url: String,
        #[source]
        source: BoxError,
    },

    #[error("UUP returned HTTP {status_code} for `{url}`")]
    Http { url: String, status_code: u16 },

    #[error("invalid UUP payload during `{stage}`: {reason}")]
    InvalidPayload { stage: UupStage, reason: String },

    #[error("could not select one UUP build {build} for {architecture}")]
    BuildSelection {
        build: String,
        architecture: Architecture,
        candidate_count: usize,
    },

    #[error("could not select one UUP media object; candidates: {candidate_count}")]
    MediaSelection { candidate_count: usize },

    #[error("UUP media is too large: {size_bytes} bytes exceeds {max_bytes}")]
    MediaTooLarge { size_bytes: u64, max_bytes: u64 },

    #[error("UUP artifact `{path}` failed {algorithm} verification")]
    HashMismatch {
        path: PathBuf,
        algorithm: HashAlgorithm,
        expected: String,
        actual: String,
    },

    #[error("required external tool `{tool}` is unavailable")]
    ToolUnavailable { tool: String },

    #[error("external tool `{tool}` failed with status {status:?}: {stderr}")]
    ToolFailed {
        tool: String,
        status: Option<i32>,
        stderr: String,
    },

    #[error("invalid UUP cache artifact `{path}`: {reason}")]
    CacheIntegrity { path: PathBuf, reason: String },

    #[error("could not publish UUP artifact to `{path}`")]
    Publish {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl ClassifiedError for UupError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidComponent { .. } => ErrorCode::InvalidInput,
            Self::Network { .. } | Self::Http { .. } => ErrorCode::NetworkFetch,
            Self::BuildSelection {
                candidate_count: 0, ..
            }
            | Self::MediaSelection { candidate_count: 0 } => ErrorCode::NotFound,
            Self::BuildSelection { .. } | Self::MediaSelection { .. } => {
                ErrorCode::AmbiguousSelection
            }
            Self::ToolUnavailable { .. } => ErrorCode::ExternalToolUnavailable,
            Self::ToolFailed { .. } => ErrorCode::ExternalToolFailed,
            Self::InvalidPayload { .. }
            | Self::MediaTooLarge { .. }
            | Self::HashMismatch { .. }
            | Self::CacheIntegrity { .. }
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
