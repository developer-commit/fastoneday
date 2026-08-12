use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{BoxError, ClassifiedError, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsrcEndpoint {
    Vulnerability,
    AffectedProduct,
}

impl fmt::Display for MsrcEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Vulnerability => "vulnerability",
            Self::AffectedProduct => "affectedProduct",
        })
    }
}

#[derive(Debug, Error)]
pub enum CveError {
    #[error("invalid CVE code `{value}`")]
    InvalidCode { value: String },

    #[error("MSRC request to `{endpoint}` failed after {attempts} attempts")]
    Network {
        endpoint: MsrcEndpoint,
        attempts: u32,
        #[source]
        source: BoxError,
    },

    #[error("MSRC returned HTTP {status_code} for `{endpoint}`")]
    Http {
        endpoint: MsrcEndpoint,
        status_code: u16,
    },

    #[error("invalid MSRC payload from `{endpoint}`: {reason}")]
    InvalidPayload {
        endpoint: MsrcEndpoint,
        reason: String,
    },
}

impl ClassifiedError for CveError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidCode { .. } => ErrorCode::InvalidInput,
            Self::Network { .. } | Self::Http { .. } => ErrorCode::NetworkFetch,
            Self::InvalidPayload { .. } => ErrorCode::ArtifactIntegrity,
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Network { .. } => true,
            Self::Http { status_code, .. } => *status_code == 429 || *status_code >= 500,
            Self::InvalidCode { .. } | Self::InvalidPayload { .. } => false,
        }
    }
}
