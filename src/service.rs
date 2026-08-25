mod download_service;
mod info_service;

use thiserror::Error;

use crate::errors::{
    CatalogError, ClassifiedError, CveError, DriverError, ErrorCode, UupError, WinbindexError,
};
use crate::model::{acquisition::Architecture, cve::ProductPatch};

pub use download_service::{DownloadRequest, DownloadService, ProductDownload};
pub use info_service::{CveInfo, InfoService};

pub(crate) fn downloadable_patches(
    catalog: &[ProductPatch],
) -> impl Iterator<Item = (&ProductPatch, Architecture)> {
    catalog
        .iter()
        .filter_map(|patch| match patch.architecture.as_str() {
            "x64" => Some((patch, Architecture::X64)),
            "arm64" => Some((patch, Architecture::Arm64)),
            _ => None,
        })
}

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

    #[error(transparent)]
    Uup(#[from] UupError),

    #[error("a driver must be selected for {cve_code}; candidates: {candidates:?}")]
    DriverNotConfirmed {
        cve_code: String,
        candidates: Vec<String>,
    },

    #[error("selection number {selection_number} is outside the displayed range 1..={available}")]
    SelectionNumberOutOfRange {
        selection_number: usize,
        available: usize,
    },
}

impl ClassifiedError for ServiceError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Cve(error) => error.code(),
            Self::Driver(error) => error.code(),
            Self::Winbindex(error) => error.code(),
            Self::Catalog(error) => error.code(),
            Self::Uup(error) => error.code(),
            Self::DriverNotConfirmed { candidates, .. } => {
                if candidates.is_empty() {
                    ErrorCode::NotFound
                } else {
                    ErrorCode::AmbiguousSelection
                }
            }
            Self::SelectionNumberOutOfRange { .. } => ErrorCode::InvalidInput,
        }
    }

    fn retryable(&self) -> bool {
        match self {
            Self::Cve(error) => error.retryable(),
            Self::Driver(error) => error.retryable(),
            Self::Winbindex(error) => error.retryable(),
            Self::Catalog(error) => error.retryable(),
            Self::Uup(error) => error.retryable(),
            Self::DriverNotConfirmed { .. } | Self::SelectionNumberOutOfRange { .. } => false,
        }
    }
}
