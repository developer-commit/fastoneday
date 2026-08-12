use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{BoxError, ClassifiedError, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WinbindexStage {
    Gzip,
    Json,
    Selection,
    Download,
    Publish,
}

impl fmt::Display for WinbindexStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Gzip => "gzip",
            Self::Json => "json",
            Self::Selection => "selection",
            Self::Download => "download",
            Self::Publish => "publish",
        })
    }
}

#[derive(Debug, Error)]
pub enum WinbindexError {
    #[error("invalid driver name `{value}`")]
    InvalidDriverName { value: String },

    #[error("invalid KB code `{value}`")]
    InvalidKbCode { value: String },

    #[error("invalid SHA-256 digest `{value}`")]
    InvalidSha256 { value: String },

    #[error("unsupported Windows architecture `{value}`")]
    UnsupportedArchitecture { value: String },

    #[error("Winbindex request to `{url}` failed after {attempts} attempts")]
    Network {
        url: String,
        attempts: u32,
        #[source]
        source: BoxError,
    },

    #[error("Winbindex returned HTTP {status_code} for `{url}`")]
    Http { url: String, status_code: u16 },

    #[error("invalid Winbindex payload during `{stage}`: {reason}")]
    InvalidPayload {
        stage: WinbindexStage,
        reason: String,
    },

    #[error("no Winbindex record for {driver_name} / {kb_code} / {os_version}")]
    RecordNotFound {
        driver_name: String,
        kb_code: String,
        os_version: String,
    },

    #[error("multiple Winbindex records for {driver_name} / {kb_code} / {os_version}")]
    AmbiguousRecord {
        driver_name: String,
        kb_code: String,
        os_version: String,
        candidate_hashes: Vec<String>,
    },

    #[error("downloaded symbol object hash does not match {expected_sha256}")]
    HashMismatch {
        expected_sha256: String,
        actual_sha256: String,
        path: PathBuf,
        source_url: String,
        bytes_received: u64,
    },

    #[error("destination `{path}` already contains a different artifact")]
    DestinationCollision {
        path: PathBuf,
        expected_sha256: String,
        actual_sha256: String,
    },

    #[error("could not publish artifact to `{path}`")]
    Publish {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl ClassifiedError for WinbindexError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidDriverName { .. }
            | Self::InvalidKbCode { .. }
            | Self::InvalidSha256 { .. } => ErrorCode::InvalidInput,
            Self::UnsupportedArchitecture { .. } => ErrorCode::UnsupportedArchitecture,
            Self::Network { .. } | Self::Http { .. } => ErrorCode::NetworkFetch,
            Self::RecordNotFound { .. } => ErrorCode::NotFound,
            Self::AmbiguousRecord { .. } => ErrorCode::AmbiguousSelection,
            Self::InvalidPayload { .. }
            | Self::HashMismatch { .. }
            | Self::DestinationCollision { .. }
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
