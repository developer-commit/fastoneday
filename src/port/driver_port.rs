use crate::{
    errors::DriverError,
    model::{cve::CveMetadata, driver::DriverResolution},
};

/// Resolves a Windows driver from normalized CVE metadata.
///
/// The resolver remains deterministic and performs no I/O. An explicit
/// override is passed separately so that its evidence can be distinguished
/// from automatically derived evidence.
pub trait DriverPort: Send + Sync {
    fn resolve(
        &self,
        metadata: &CveMetadata,
        override_name: Option<&str>,
    ) -> Result<DriverResolution, DriverError>;
}
