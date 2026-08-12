//! Application-facing boundaries for metadata lookup and binary acquisition.

mod catalog_port;
mod cve_port;
mod driver_port;
mod uup_port;
mod winbindex_port;

pub use catalog_port::CatalogPort;
pub use cve_port::CvePort;
pub use driver_port::DriverPort;
pub use uup_port::UupPort;
pub use winbindex_port::WinbindexPort;
