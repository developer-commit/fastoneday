use std::path::Path;

use crate::{
    errors::CatalogError,
    model::catalog::{CatalogRecoveredBinary, CatalogRecoveryRequest},
};

/// Recovers an exact driver from Microsoft Update Catalog.
///
/// Search-page parsing, package selection, MSU extraction, PSF hydration, and
/// integrity checks stay behind this boundary. The expected Winbindex SHA-256
/// is part of the recovery request and remains the final identity authority.
pub trait CatalogPort: Send + Sync {
    fn recover(
        &self,
        request: &CatalogRecoveryRequest,
        destination: &Path,
    ) -> Result<CatalogRecoveredBinary, CatalogError>;
}
