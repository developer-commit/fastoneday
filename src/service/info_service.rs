use serde::{Deserialize, Serialize};

use crate::{
    model::{cve::MsrcFetchResult, driver::DriverResolution},
    port::{CvePort, DriverPort},
};

use super::ServiceError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve: MsrcFetchResult,
    pub driver: DriverResolution,
}

pub struct InfoService<'a> {
    cve: &'a dyn CvePort,
    driver: &'a dyn DriverPort,
}

impl<'a> InfoService<'a> {
    pub fn new(cve: &'a dyn CvePort, driver: &'a dyn DriverPort) -> Self {
        Self { cve, driver }
    }

    pub fn get(
        &self,
        cve_code: &str,
        driver_override: Option<&str>,
    ) -> Result<CveInfo, ServiceError> {
        let cve = self.cve.fetch(cve_code)?;
        let driver = self.driver.resolve(&cve.normalized, driver_override)?;
        Ok(CveInfo { cve, driver })
    }
}
