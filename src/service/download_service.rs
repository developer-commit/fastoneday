use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    errors::WinbindexError,
    model::{
        acquisition::Architecture,
        catalog::CatalogRecoveryRequest,
        cve::ProductPatch,
        winbindex::{
            AcquisitionProvenance, CatalogFallbackReason, DownloadResult, WinbindexResolveRequest,
        },
    },
    port::{CatalogPort, CvePort, DriverPort, WinbindexPort},
};

use super::{ServiceError, downloadable_patches};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRequest {
    pub cve_code: String,
    pub selection_number: usize,
    pub output_directory: PathBuf,
    pub driver_override: Option<String>,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductDownload {
    pub cve_code: String,
    pub product: String,
    pub driver_name: String,
    pub before_kb: String,
    pub after_kb: String,
    pub before: DownloadResult,
    pub after: DownloadResult,
}

pub struct DownloadService<'a> {
    cve: &'a dyn CvePort,
    driver: &'a dyn DriverPort,
    winbindex: &'a dyn WinbindexPort,
    catalog: &'a dyn CatalogPort,
}

impl<'a> DownloadService<'a> {
    pub fn new(
        cve: &'a dyn CvePort,
        driver: &'a dyn DriverPort,
        winbindex: &'a dyn WinbindexPort,
        catalog: &'a dyn CatalogPort,
    ) -> Self {
        Self {
            cve,
            driver,
            winbindex,
            catalog,
        }
    }

    pub fn download(&self, request: &DownloadRequest) -> Result<ProductDownload, ServiceError> {
        let fetched = self.cve.fetch(&request.cve_code)?;
        let resolution = self
            .driver
            .resolve(&fetched.normalized, request.driver_override.as_deref())?;
        let driver_name =
            resolution
                .confirmed_driver()
                .ok_or_else(|| ServiceError::DriverNotConfirmed {
                    cve_code: fetched.normalized.cve_code.clone(),
                    candidates: resolution.candidates().map(str::to_owned).collect(),
                })?;
        let (patch, architecture) =
            select_product(&fetched.normalized.catalog, request.selection_number)?;
        let before_kb = patch.before_kb.clone();
        let after_kb = patch.after_kb.clone();

        let before = self.acquire(
            driver_name,
            &before_kb,
            &patch.os_version,
            architecture,
            request.before_sha256.as_deref(),
            request.output_directory.join("before").join(driver_name),
        )?;
        let after = self.acquire(
            driver_name,
            &after_kb,
            &patch.os_version,
            architecture,
            request.after_sha256.as_deref(),
            request.output_directory.join("after").join(driver_name),
        )?;

        Ok(ProductDownload {
            cve_code: fetched.normalized.cve_code.clone(),
            product: patch.os_version.clone(),
            driver_name: driver_name.to_owned(),
            before_kb,
            after_kb,
            before,
            after,
        })
    }

    fn acquire(
        &self,
        driver_name: &str,
        kb_code: &str,
        os_version: &str,
        architecture: Architecture,
        selected_sha256: Option<&str>,
        destination: PathBuf,
    ) -> Result<DownloadResult, ServiceError> {
        let record = self.winbindex.resolve(&WinbindexResolveRequest {
            driver_name: driver_name.to_owned(),
            kb_code: kb_code.to_owned(),
            os_version: os_version.to_owned(),
            architecture: Some(architecture),
            selected_sha256: selected_sha256.map(str::to_owned),
        })?;

        match self.winbindex.download(&record, &destination) {
            Ok(download) => Ok(download),
            Err(error @ WinbindexError::HashMismatch { .. }) => {
                let reason = match &error {
                    WinbindexError::HashMismatch { actual_sha256, .. } => {
                        CatalogFallbackReason::SymbolHashMismatch {
                            actual_sha256: actual_sha256.clone(),
                        }
                    }
                    _ => unreachable!("the match arm restricts this variant"),
                };
                self.recover(record, destination, reason)
            }
            Err(WinbindexError::Http {
                status_code: status @ (404 | 410),
                ..
            }) => self.recover(
                record,
                destination,
                CatalogFallbackReason::SymbolUnavailable {
                    status_code: status,
                },
            ),
            Err(error) => Err(error.into()),
        }
    }

    fn recover(
        &self,
        record: crate::model::winbindex::WinbindexRecord,
        destination: PathBuf,
        fallback_reason: CatalogFallbackReason,
    ) -> Result<DownloadResult, ServiceError> {
        let recovered = self.catalog.recover(
            &CatalogRecoveryRequest {
                driver_name: record.driver_name.clone(),
                kb_code: record.kb_code.clone(),
                os_version: record.requested_os.clone(),
                architecture: record.architecture,
                expected_sha256: record.sha256.clone(),
            },
            &destination,
        )?;

        Ok(DownloadResult {
            destination: recovered.destination,
            sha256: recovered.sha256,
            source_url: recovered.source_url,
            bytes_written: recovered.bytes_written,
            reused: recovered.reused,
            record,
            provenance: AcquisitionProvenance::Catalog {
                fallback_reason,
                recovery: Box::new(recovered.provenance),
            },
        })
    }
}

fn select_product(
    catalog: &[ProductPatch],
    selection_number: usize,
) -> Result<(&ProductPatch, Architecture), ServiceError> {
    let patches = downloadable_patches(catalog).collect::<Vec<_>>();
    selection_number
        .checked_sub(1)
        .and_then(|index| patches.get(index).copied())
        .ok_or(ServiceError::SelectionNumberOutOfRange {
            selection_number,
            available: patches.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(product: &str, before_kb: &str, after_kb: &str) -> ProductPatch {
        ProductPatch {
            product_id: 1,
            os_version: product.into(),
            architecture: "x64".into(),
            update_kind: "Security Update".into(),
            before_kb: before_kb.into(),
            after_kb: after_kb.into(),
        }
    }

    #[test]
    fn selection_number_chooses_an_exact_row() {
        let rows = vec![
            patch("Windows 11 x64", "KB1", "KB2"),
            patch("Windows 11 x64", "KB2", "KB3"),
        ];

        let (selected, architecture) = select_product(&rows, 2).unwrap();
        assert_eq!(selected.after_kb, "KB3");
        assert_eq!(architecture, Architecture::X64);
    }

    #[test]
    fn rejects_a_selection_number_outside_the_displayed_range() {
        let rows = vec![patch("Windows 11 x64", "KB1", "KB2")];

        assert!(select_product(&rows, 0).is_err());
        assert!(select_product(&rows, 2).is_err());
    }

    #[test]
    fn selection_numbers_only_include_supported_architectures() {
        let mut x86 = patch("Windows Server 2008 for 32-bit Systems", "KB1", "KB2");
        x86.architecture = "x86".into();
        let x64 = patch("Windows 11 x64", "KB2", "KB3");

        let rows = vec![x86, x64];
        let (selected, architecture) = select_product(&rows, 1).unwrap();
        assert_eq!(selected.after_kb, "KB3");
        assert_eq!(architecture, Architecture::X64);
        assert!(select_product(&rows, 2).is_err());
    }
}
