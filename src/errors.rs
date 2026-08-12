mod catalog_error;
mod cve_error;
mod driver_error;
mod uup_error;
mod winbindex_error;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use catalog_error::{CatalogError, CatalogStage};
pub use cve_error::{CveError, MsrcEndpoint};
pub use driver_error::DriverError;
pub use uup_error::{UupError, UupStage};
pub use winbindex_error::{WinbindexError, WinbindexStage};

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    NetworkFetch,
    ArtifactIntegrity,
    NotFound,
    AmbiguousSelection,
    ExternalToolUnavailable,
    ExternalToolFailed,
    UnsupportedArchitecture,
}

pub trait ClassifiedError: std::error::Error {
    fn code(&self) -> ErrorCode;

    fn retryable(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum FastOneDayError {
    #[error(transparent)]
    Cve(#[from] CveError),
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error(transparent)]
    Winbindex(#[from] WinbindexError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Uup(#[from] UupError),
}

impl ClassifiedError for FastOneDayError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Cve(error) => error.code(),
            Self::Driver(error) => error.code(),
            Self::Winbindex(error) => error.code(),
            Self::Catalog(error) => error.code(),
            Self::Uup(error) => error.code(),
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Cve(error) => error.retryable(),
            Self::Driver(error) => error.retryable(),
            Self::Winbindex(error) => error.retryable(),
            Self::Catalog(error) => error.retryable(),
            Self::Uup(error) => error.retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClassifiedError, CveError, ErrorCode, MsrcEndpoint, WinbindexError};

    #[test]
    fn retryability_is_derived_from_the_variant() {
        let throttled = CveError::Http {
            endpoint: MsrcEndpoint::Vulnerability,
            status_code: 429,
        };
        let malformed = CveError::InvalidPayload {
            endpoint: MsrcEndpoint::Vulnerability,
            reason: "missing field".into(),
        };

        assert!(throttled.retryable());
        assert!(!malformed.retryable());
    }

    #[test]
    fn not_found_is_not_reported_as_ambiguous() {
        let error = WinbindexError::RecordNotFound {
            driver_name: "example.sys".into(),
            kb_code: "KB1".into(),
            os_version: "Windows 11 x64".into(),
        };

        assert_eq!(error.code(), ErrorCode::NotFound);
    }
}
