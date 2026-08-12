use std::path::Path;

use crate::{
    errors::WinbindexError,
    model::winbindex::{DownloadResult, WinbindexRecord, WinbindexResolveRequest},
};

/// Resolves an exact Winbindex record and retrieves its symbol-server object.
///
/// Resolution and download are separate operations so the download service can
/// retain the selected SHA-256 identity while falling back to Catalog when the
/// symbol object is missing or has the wrong hash.
pub trait WinbindexPort: Send + Sync {
    fn resolve(&self, request: &WinbindexResolveRequest)
    -> Result<WinbindexRecord, WinbindexError>;

    fn download(
        &self,
        record: &WinbindexRecord,
        destination: &Path,
    ) -> Result<DownloadResult, WinbindexError>;

    /// Performs the normal Winbindex path without a Catalog fallback.
    fn acquire(
        &self,
        request: &WinbindexResolveRequest,
        destination: &Path,
    ) -> Result<DownloadResult, WinbindexError> {
        let record = self.resolve(request)?;
        self.download(&record, destination)
    }
}
