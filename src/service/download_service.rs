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
    port::{CatalogPort, CvePort, DriverPort, UupPort, WinbindexPort},
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
    uup: Option<&'a dyn UupPort>,
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
            uup: None,
        }
    }

    pub fn with_uup(mut self, uup: &'a dyn UupPort) -> Self {
        self.uup = Some(uup);
        self
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
        let before_destination = request.output_directory.join(output_filename(
            "before",
            &before_kb,
            driver_name,
            &patch.os_version,
        ));
        let after_destination = request.output_directory.join(output_filename(
            "after",
            &after_kb,
            driver_name,
            &patch.os_version,
        ));

        let before = self.acquire(
            WinbindexResolveRequest {
                driver_name: driver_name.to_owned(),
                kb_code: before_kb.clone(),
                os_version: patch.os_version.clone(),
                architecture: Some(architecture),
                selected_sha256: request.before_sha256.clone(),
            },
            Some(&after_kb),
            before_destination,
        )?;
        let after = self.acquire(
            WinbindexResolveRequest {
                driver_name: driver_name.to_owned(),
                kb_code: after_kb.clone(),
                os_version: patch.os_version.clone(),
                architecture: Some(architecture),
                selected_sha256: request.after_sha256.clone(),
            },
            None,
            after_destination,
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
        request: WinbindexResolveRequest,
        successor_kb_code: Option<&str>,
        destination: PathBuf,
    ) -> Result<DownloadResult, ServiceError> {
        let record = match successor_kb_code {
            Some(successor) => self.winbindex.resolve_predecessor(&request, successor)?,
            None => self.winbindex.resolve(&request)?,
        };

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
                if record.component_member_path.is_some() && self.uup.is_some() {
                    self.recover_base(record, destination, reason)
                } else {
                    self.recover(record, destination, reason)
                }
            }
            Err(WinbindexError::Http {
                status_code: status @ (404 | 410),
                ..
            }) => {
                let reason = CatalogFallbackReason::SymbolUnavailable {
                    status_code: status,
                };
                if record.component_member_path.is_some() && self.uup.is_some() {
                    self.recover_base(record, destination, reason)
                } else {
                    self.recover(record, destination, reason)
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn recover_base(
        &self,
        record: crate::model::winbindex::WinbindexRecord,
        destination: PathBuf,
        fallback_reason: CatalogFallbackReason,
    ) -> Result<DownloadResult, ServiceError> {
        let member_path = record
            .component_member_path
            .as_ref()
            .expect("BASE recovery requires a component member path");
        let uup = self.uup.expect("BASE recovery requires a UUP adapter");
        let (resolved, reused) = uup.acquire_exact(
            &crate::model::uup::UupResolveRequest {
                driver_name: record.driver_name.clone(),
                os_version: record.requested_os.clone(),
                architecture: record.architecture,
                member_path: member_path.clone(),
            },
            &record.sha256,
            &destination,
        )?;
        let bytes_written = destination
            .metadata()
            .map_err(|source| crate::errors::UupError::Publish {
                path: destination.clone(),
                source,
            })?
            .len();
        Ok(DownloadResult {
            destination,
            sha256: resolved.sha256,
            source_url: resolved.provenance.media_source.clone(),
            bytes_written,
            reused,
            record,
            provenance: AcquisitionProvenance::UupBase {
                fallback_reason,
                base: Box::new(resolved.provenance),
            },
        })
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

fn output_filename(stage: &str, kb_code: &str, driver_name: &str, os_version: &str) -> String {
    let (driver_stem, extension) = driver_name.rsplit_once('.').unwrap_or((driver_name, ""));
    let os_version = filename_component(os_version);
    let base = format!("{stage}_{kb_code}_{driver_stem}_{os_version}");
    if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    }
}

fn filename_component(value: &str) -> String {
    let mut component = String::with_capacity(value.len());
    let mut separated = true;

    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            component.push(character);
            separated = false;
        } else if !separated {
            component.push('_');
            separated = true;
        }
    }

    if component.ends_with('_') {
        component.pop();
    }
    if component.is_empty() {
        "unknown".into()
    } else {
        component
    }
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

    #[test]
    fn builds_flat_output_names_with_the_driver_extension_at_the_end() {
        assert_eq!(
            output_filename(
                "before",
                "KB5016629",
                "clfs.sys",
                "Windows 11 version 21H2 for x64-based Systems",
            ),
            "before_KB5016629_clfs_Windows_11_version_21H2_for_x64_based_Systems.sys"
        );
    }

    #[test]
    fn collapses_os_version_punctuation_into_single_underscores() {
        assert_eq!(
            output_filename(
                "after",
                "KB5017316",
                "clfs.sys",
                " Windows Server 2022, 23H2 Edition (Server Core installation) ",
            ),
            "after_KB5017316_clfs_Windows_Server_2022_23H2_Edition_Server_Core_installation.sys"
        );
    }
}
