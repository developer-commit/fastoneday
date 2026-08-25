use std::path::Path;

use crate::{
    errors::{UupError, UupStage},
    model::uup::{ResolvedBase, UupResolveRequest},
};

/// Resolves the RTM base image needed to hydrate a Catalog PSF payload.
///
/// `confirm` persists the resolved base identity only after the caller has
/// verified that hydration produced the expected target hash.
pub trait UupPort: Send + Sync {
    fn resolve(&self, request: &UupResolveRequest) -> Result<ResolvedBase, UupError>;

    fn confirm(&self, candidate: &ResolvedBase) -> Result<(), UupError>;

    fn acquire_exact(
        &self,
        request: &UupResolveRequest,
        expected_sha256: &str,
        destination: &Path,
    ) -> Result<(ResolvedBase, bool), UupError> {
        let _ = (request, expected_sha256, destination);
        Err(UupError::InvalidPayload {
            stage: UupStage::Cache,
            reason: "exact UUP acquisition is not implemented by this adapter".into(),
        })
    }
}
