use crate::{
    driver_resolver::resolve_driver,
    errors::DriverError,
    model::{cve::CveMetadata, driver::DriverResolution},
    port::DriverPort,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct DriverAdapter;

impl DriverPort for DriverAdapter {
    fn resolve(
        &self,
        metadata: &CveMetadata,
        override_name: Option<&str>,
    ) -> Result<DriverResolution, DriverError> {
        resolve_driver(metadata, override_name)
    }
}
