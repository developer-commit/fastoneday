use crate::{errors::CveError, model::cve::MsrcFetchResult};

/// Retrieves one CVE as a raw and normalized metadata snapshot.
///
/// CVE validation, HTTP retries, response parsing, and normalization belong to
/// the adapter. Consumers receive the combined fetch result used by the info
/// service and workspace persistence.
pub trait CvePort: Send + Sync {
    fn fetch(&self, cve_code: &str) -> Result<MsrcFetchResult, CveError>;
}
