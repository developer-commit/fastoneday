mod download_service;
mod info_service;

use thiserror::Error;

use crate::errors::{
    CatalogError, ClassifiedError, CveError, DriverError, ErrorCode, WinbindexError,
};

pub use download_service::{DownloadRequest, DownloadService, ProductDownload};
pub use info_service::{CveInfo, InfoService};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Cve(#[from] CveError),

    #[error(transparent)]
    Driver(#[from] DriverError),

    #[error(transparent)]
    Winbindex(#[from] WinbindexError),

    #[error(transparent)]
    Catalog(#[from] CatalogError),

    #[error("a driver must be selected for {cve_code}; candidates: {candidates:?}")]
    DriverNotConfirmed {
        cve_code: String,
        candidates: Vec<String>,
    },

    #[error("product `{requested}` was not found; available products: {available:?}")]
    ProductNotFound {
        requested: String,
        available: Vec<String>,
    },

    #[error("product `{requested}` matches more than one patch row: {candidates:?}")]
    AmbiguousProduct {
        requested: String,
        candidates: Vec<String>,
    },

    #[error("a before KB must be selected for `{product}`; candidates: {candidates:?}")]
    BeforeKbRequired {
        product: String,
        candidates: Vec<String>,
    },

    #[error("before KB `{value}` is not valid for `{product}`; candidates: {candidates:?}")]
    InvalidBeforeKb {
        product: String,
        value: String,
        candidates: Vec<String>,
    },
}

impl ClassifiedError for ServiceError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Cve(error) => error.code(),
            Self::Driver(error) => error.code(),
            Self::Winbindex(error) => error.code(),
            Self::Catalog(error) => error.code(),
            Self::DriverNotConfirmed { candidates, .. } => {
                if candidates.is_empty() {
                    ErrorCode::NotFound
                } else {
                    ErrorCode::AmbiguousSelection
                }
            }
            Self::ProductNotFound { .. } => ErrorCode::NotFound,
            Self::AmbiguousProduct { .. } | Self::BeforeKbRequired { .. } => {
                ErrorCode::AmbiguousSelection
            }
            Self::InvalidBeforeKb { .. } => ErrorCode::InvalidInput,
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Cve(error) => error.retryable(),
            Self::Driver(error) => error.retryable(),
            Self::Winbindex(error) => error.retryable(),
            Self::Catalog(error) => error.retryable(),
            Self::DriverNotConfirmed { .. }
            | Self::ProductNotFound { .. }
            | Self::AmbiguousProduct { .. }
            | Self::BeforeKbRequired { .. }
            | Self::InvalidBeforeKb { .. } => false,
        }
    }
}
