use crate::{
    errors::UupError,
    model::uup::{ResolvedBase, UupResolveRequest},
};

/// Resolves the RTM base image needed to hydrate a Catalog PSF payload.
///
/// `confirm` persists the resolved base identity only after the caller has
/// verified that hydration produced the expected target hash.
pub trait UupPort: Send + Sync {
    fn resolve(&self, request: &UupResolveRequest) -> Result<ResolvedBase, UupError>;

    fn confirm(&self, candidate: &ResolvedBase) -> Result<(), UupError>;
}
