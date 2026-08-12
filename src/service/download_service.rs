use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    errors::WinbindexError,
    model::{
        catalog::CatalogRecoveryRequest,
        cve::{BeforeKb, ProductPatch},
        winbindex::{
            AcquisitionProvenance, CatalogFallbackReason, DownloadResult, WinbindexResolveRequest,
        },
    },
    port::{CatalogPort, CvePort, DriverPort, WinbindexPort},
};

use super::ServiceError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRequest {
    pub cve_code: String,
    pub product: String,
    pub output_directory: PathBuf,
    pub driver_override: Option<String>,
    pub before_kb: Option<String>,
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
        let patch = select_product(
            &fetched.normalized.catalog,
            &request.product,
            request.before_kb.as_deref(),
        )?;
        let before_kb = select_before_kb(patch, request.before_kb.as_deref())?;
        let after_kb = patch.after_kb.clone();

        let before = self.acquire(
            driver_name,
            &before_kb,
            &patch.os_version,
            request.before_sha256.as_deref(),
            request.output_directory.join("before").join(driver_name),
        )?;
        let after = self.acquire(
            driver_name,
            &after_kb,
            &patch.os_version,
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
        selected_sha256: Option<&str>,
        destination: PathBuf,
    ) -> Result<DownloadResult, ServiceError> {
        let record = self.winbindex.resolve(&WinbindexResolveRequest {
            driver_name: driver_name.to_owned(),
            kb_code: kb_code.to_owned(),
            os_version: os_version.to_owned(),
            architecture: None,
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

fn select_product<'a>(
    catalog: &'a [ProductPatch],
    requested: &str,
    selected_before_kb: Option<&str>,
) -> Result<&'a ProductPatch, ServiceError> {
    let requested = requested.trim();
    let matches = catalog
        .iter()
        .filter(|patch| patch.os_version.eq_ignore_ascii_case(requested))
        .collect::<Vec<_>>();

    if matches.is_empty() {
        let mut available = catalog
            .iter()
            .map(|patch| patch.os_version.clone())
            .collect::<Vec<_>>();
        available.sort_by_key(|name| name.to_ascii_lowercase());
        available.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        return Err(ServiceError::ProductNotFound {
            requested: requested.to_owned(),
            available,
        });
    }

    if matches.len() == 1 {
        return Ok(matches[0]);
    }

    if let Some(value) = selected_before_kb {
        let normalized = normalize_kb(value).ok_or_else(|| ServiceError::InvalidBeforeKb {
            product: requested.to_owned(),
            value: value.to_owned(),
            candidates: before_kb_candidates(&matches),
        })?;
        let selected = matches
            .iter()
            .copied()
            .filter(|patch| {
                patch
                    .before_kb
                    .candidates()
                    .iter()
                    .filter_map(|candidate| normalize_kb(candidate))
                    .any(|candidate| candidate == normalized)
            })
            .collect::<Vec<_>>();
        match selected.as_slice() {
            [patch] => return Ok(*patch),
            [] => {
                return Err(ServiceError::InvalidBeforeKb {
                    product: requested.to_owned(),
                    value: value.to_owned(),
                    candidates: before_kb_candidates(&matches),
                });
            }
            _ => {}
        }
    }

    let ready = matches
        .iter()
        .copied()
        .filter(|patch| matches!(patch.before_kb, BeforeKb::Available(_)))
        .collect::<Vec<_>>();
    if ready.len() == 1 {
        return Ok(ready[0]);
    }

    Err(ServiceError::AmbiguousProduct {
        requested: requested.to_owned(),
        candidates: matches.iter().map(|patch| patch_label(patch)).collect(),
    })
}

fn before_kb_candidates(patches: &[&ProductPatch]) -> Vec<String> {
    let mut candidates = patches
        .iter()
        .flat_map(|patch| patch.before_kb.candidates())
        .filter_map(|candidate| normalize_kb(candidate))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn select_before_kb(patch: &ProductPatch, selected: Option<&str>) -> Result<String, ServiceError> {
    let candidates = patch
        .before_kb
        .candidates()
        .iter()
        .map(|value| normalize_kb(value))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();

    if let Some(value) = selected {
        let normalized = normalize_kb(value).ok_or_else(|| ServiceError::InvalidBeforeKb {
            product: patch.os_version.clone(),
            value: value.to_owned(),
            candidates: candidates.clone(),
        })?;
        if !candidates.is_empty() && !candidates.contains(&normalized) {
            return Err(ServiceError::InvalidBeforeKb {
                product: patch.os_version.clone(),
                value: value.to_owned(),
                candidates,
            });
        }
        return Ok(normalized);
    }

    patch
        .before_kb
        .selected()
        .map(str::to_owned)
        .ok_or_else(|| ServiceError::BeforeKbRequired {
            product: patch.os_version.clone(),
            candidates,
        })
}

fn normalize_kb(value: &str) -> Option<String> {
    let compact = value.trim().to_ascii_uppercase().replace(' ', "");
    let digits = compact.strip_prefix("KB")?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| format!("KB{digits}"))
}

fn patch_label(patch: &ProductPatch) -> String {
    let before = match &patch.before_kb {
        BeforeKb::Available(kb) => kb.clone(),
        BeforeKb::Missing => "?".into(),
        BeforeKb::Ambiguous(candidates) => candidates.join("/"),
    };
    format!("{before} -> {}", patch.after_kb)
}

#[cfg(test)]
mod tests {
    use crate::model::cve::BeforeKb;

    use super::*;

    fn patch(product: &str, before_kb: BeforeKb, after_kb: &str) -> ProductPatch {
        ProductPatch {
            os_version: product.into(),
            before_kb,
            after_kb: after_kb.into(),
        }
    }

    #[test]
    fn selects_the_only_complete_row_for_a_product() {
        let rows = vec![
            patch("Windows 11 x64", BeforeKb::Missing, "KB3"),
            patch("Windows 11 x64", BeforeKb::Available("KB1".into()), "KB2"),
        ];

        let selected = select_product(&rows, "windows 11 x64", None).unwrap();
        assert_eq!(selected.after_kb, "KB2");
    }

    #[test]
    fn before_kb_selects_one_of_multiple_rows_for_the_same_product() {
        let product = "Windows 11 Version 24H2 for x64-based Systems";
        let rows = vec![
            patch(
                product,
                BeforeKb::Available("KB5051987".into()),
                "KB5053598",
            ),
            patch(
                product,
                BeforeKb::Available("KB5052105".into()),
                "KB5053636",
            ),
        ];

        let selected = select_product(&rows, product, Some("kb 5052105")).unwrap();

        assert_eq!(selected.after_kb, "KB5053636");
    }

    #[test]
    fn accepts_only_a_reported_ambiguous_before_kb() {
        let patch = patch(
            "Windows 11 x64",
            BeforeKb::Ambiguous(vec!["KB1".into(), "KB2".into()]),
            "KB3",
        );

        assert_eq!(select_before_kb(&patch, Some("kb 2")).unwrap(), "KB2");
        assert!(select_before_kb(&patch, Some("KB4")).is_err());
    }
}
