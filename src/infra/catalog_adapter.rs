use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use regex::Regex;
use reqwest::blocking::{Client, Response};
use roxmltree::Document;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};
use url::Url;

use crate::{
    errors::{CatalogError, CatalogStage},
    model::{
        acquisition::{Architecture, HashAlgorithm},
        catalog::{
            CatalogDetail, CatalogExtraction, CatalogPackage, CatalogPackageProvenance,
            CatalogRecoveredBinary, CatalogRecoveryProvenance, CatalogRecoveryRequest,
            CatalogUpdate, PsfPayload, PsfPayloadKind,
        },
        uup::UupResolveRequest,
    },
    port::{CatalogPort, UupPort},
};

use super::{
    default_cache_directory, digest_file, format_bytes, hex, report_download_progress,
    uup_adapter::UupAdapter,
    winbindex_adapter::{is_sha256, normalize_driver_name, normalize_kb_code},
};

const SEARCH_URL: &str = "https://www.catalog.update.microsoft.com/Search.aspx";
const DETAIL_URL: &str = "https://www.catalog.update.microsoft.com/ScopedViewInline.aspx";
const DOWNLOAD_URL: &str = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx";
const MSDELTA_REVISION: &str = "fb5ab88843e854f3fd32d553984d8685ae643913";
const MSDELTA_HYDRATOR: &str = "jlevere/msdelta@fb5ab88843e854f3fd32d553984d8685ae643913";
const MAX_DELTA_BYTES: usize = 64 * 1024 * 1024;
const MAX_HYDRATED_DRIVER_BYTES: i64 = 64 * 1024 * 1024;
const LZMS_API_MAGIC: [u8; 4] = 0xC0E5_510Au32.to_le_bytes();

const GUID: &str = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}";

static SEARCH_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<tr[^>]+id=["'](?P<id>{GUID})_R\d+["'][^>]*>(?P<body>.*?)</tr>"#
    ))
    .expect("valid Catalog row regex")
});
static SEARCH_CELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<td[^>]+id=["'](?P<id>{GUID})_C(?P<cell>[1-7])_R\d+["'][^>]*>(?P<body>.*?)</td>"#
    ))
    .expect("valid Catalog cell regex")
});
static ORIGINAL_SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<span[^>]+id=["'](?P<id>{GUID})_originalSize["'][^>]*>(?P<size>.*?)</span>"#
    ))
    .expect("valid Catalog size regex")
});
static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("valid HTML tag regex"));
static KB_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{6,8}\b").expect("valid KB regex"));
static RELEASE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:version\s+)?(\d{2}h\d)\b").expect("valid release regex")
});
static ARCH_X64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:x64|amd64)[- ]based\b").expect("valid x64 regex"));
static ARCH_ARM64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:arm64|aarch64)[- ]based\b").expect("valid arm64 regex"));
static JS_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)downloadInformation\[(?P<group>\d+)](?:\.files\[(?P<file>\d+)])?\.(?P<field>updateID|url|digest|sha256|fileName)\s*=\s*'(?P<value>(?:\\.|[^'])*)'\s*;"#,
    )
    .expect("valid download dialog regex")
});

#[derive(Debug, Clone)]
pub struct CatalogAdapter {
    client: Client,
    cache_directory: PathBuf,
    seven_zip: Option<PathBuf>,
    base_root: Option<PathBuf>,
    request_timeout: Duration,
    download_timeout: Duration,
    max_package_bytes: u64,
    show_progress: bool,
    uup: UupAdapter,
}

impl Default for CatalogAdapter {
    fn default() -> Self {
        let cache_directory = env::var_os("ONEDAY_CATALOG_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(default_cache_directory);
        let client = Client::builder()
            .user_agent("fastoneday/0.1 Microsoft-Catalog-Client")
            .build()
            .expect("static HTTP client configuration is valid");
        Self {
            client,
            uup: UupAdapter::with_cache_directory(&cache_directory),
            cache_directory,
            seven_zip: env::var_os("ONEDAY_7ZIP").map(PathBuf::from),
            base_root: env::var_os("ONEDAY_CATALOG_BASE_ROOT").map(PathBuf::from),
            request_timeout: Duration::from_secs(60),
            download_timeout: Duration::from_secs(900),
            max_package_bytes: 4 * 1024 * 1024 * 1024,
            show_progress: false,
        }
    }
}

impl CatalogAdapter {
    pub fn with_cache_directory(cache_directory: impl Into<PathBuf>) -> Self {
        let cache_directory = cache_directory.into();
        Self {
            uup: UupAdapter::with_cache_directory(&cache_directory),
            cache_directory,
            ..Self::default()
        }
    }

    pub fn with_progress(mut self) -> Self {
        self.show_progress = true;
        self.uup = self.uup.with_progress();
        self
    }

    fn resolve_update(
        &self,
        request: &CatalogRecoveryRequest,
    ) -> Result<CatalogUpdate, CatalogError> {
        let html = self.get_text(
            SEARCH_URL,
            &[("q", request.kb_code.as_str())],
            CatalogStage::Search,
        )?;
        let updates = parse_search(&html)?;
        let update = select_update(&updates, request)?;
        let detail_html = self.get_text(
            DETAIL_URL,
            &[("updateid", update.update_id.as_str())],
            CatalogStage::Detail,
        )?;
        let detail = parse_detail(&detail_html)?;
        validate_detail(&update, &detail, request)?;
        Ok(update)
    }

    fn resolve_package(&self, update: &CatalogUpdate) -> Result<CatalogPackage, CatalogError> {
        let update_ids = serde_json::json!([{
            "size": 0,
            "uidInfo": update.update_id,
            "updateID": update.update_id,
        }])
        .to_string();
        let response = self
            .client
            .post(DOWNLOAD_URL)
            .form(&[("updateIDs", update_ids.as_str())])
            .timeout(self.request_timeout)
            .send()
            .map_err(|source| CatalogError::Network {
                stage: CatalogStage::DownloadDialog,
                url: Some(DOWNLOAD_URL.into()),
                source: Box::new(source),
            })?;
        let html = response_text(response, CatalogStage::DownloadDialog, Some(DOWNLOAD_URL))?;
        let packages = parse_download_dialog(&html, &update.update_id)?;
        let mut msu = packages
            .into_iter()
            .filter(|package| package.filename.to_ascii_lowercase().ends_with(".msu"))
            .collect::<Vec<_>>();
        if msu.len() != 1 {
            return Err(CatalogError::InvalidPayload {
                stage: CatalogStage::DownloadDialog,
                reason: format!("expected one MSU package, found {}", msu.len()),
            });
        }
        Ok(msu.pop().expect("one package was checked"))
    }

    fn download_package(
        &self,
        package: &CatalogPackage,
        expected_size: u64,
    ) -> Result<PathBuf, CatalogError> {
        let cache_name = package
            .sha256
            .as_ref()
            .or(package.sha1.as_ref())
            .cloned()
            .unwrap_or_else(|| hex(&Sha256::digest(package.url.as_bytes())));
        let suffix = Path::new(&package.filename)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("msu");
        let destination = self
            .cache_directory
            .join("packages")
            .join(format!("{cache_name}.{suffix}"));
        if self.show_progress {
            eprintln!("catalog media: {}", package.filename);
            eprintln!(
                "catalog size: {} ({expected_size} bytes)",
                format_bytes(expected_size)
            );
            eprintln!("catalog cache: {}", destination.display());
        }
        if destination.is_file() {
            verify_package(&destination, package, expected_size)?;
            if self.show_progress {
                eprintln!("catalog cache status: reused");
            }
            return Ok(destination);
        }
        let parent = destination
            .parent()
            .expect("package cache path has a parent");
        fs::create_dir_all(parent).map_err(|source| CatalogError::Publish {
            path: destination.clone(),
            source,
        })?;
        let mut response = self
            .client
            .get(&package.url)
            .timeout(self.download_timeout)
            .send()
            .map_err(|source| CatalogError::Network {
                stage: CatalogStage::PackageDownload,
                url: Some(package.url.clone()),
                source: Box::new(source),
            })?;
        ensure_success(&response, CatalogStage::PackageDownload, Some(&package.url))?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_package_bytes)
        {
            return Err(CatalogError::InvalidPayload {
                stage: CatalogStage::PackageDownload,
                reason: "package exceeds configured maximum size".into(),
            });
        }

        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|source| CatalogError::Publish {
                path: destination.clone(),
                source,
            })?;
        let mut total = 0_u64;
        let mut next_percent = 0_u64;
        let mut buffer = [0_u8; 1024 * 1024];
        if self.show_progress {
            report_download_progress("catalog download", 0, expected_size, &mut next_percent);
        }
        loop {
            let count = response
                .read(&mut buffer)
                .map_err(|source| CatalogError::Network {
                    stage: CatalogStage::PackageDownload,
                    url: Some(package.url.clone()),
                    source: Box::new(source),
                })?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > self.max_package_bytes {
                return Err(CatalogError::InvalidPayload {
                    stage: CatalogStage::PackageDownload,
                    reason: "package exceeds configured maximum size".into(),
                });
            }
            temporary
                .write_all(&buffer[..count])
                .map_err(|source| CatalogError::Publish {
                    path: destination.clone(),
                    source,
                })?;
            if self.show_progress {
                report_download_progress(
                    "catalog download",
                    total,
                    expected_size,
                    &mut next_percent,
                );
            }
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| CatalogError::Publish {
                path: destination.clone(),
                source,
            })?;
        verify_package(temporary.path(), package, expected_size)?;
        let reused = match fs::hard_link(temporary.path(), &destination) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_package(&destination, package, expected_size)?;
                true
            }
            Err(source) => {
                return Err(CatalogError::Publish {
                    path: destination,
                    source,
                });
            }
        };
        if self.show_progress {
            eprintln!(
                "catalog cache status: {}",
                if reused { "reused" } else { "saved" }
            );
        }
        Ok(destination)
    }

    fn extract(
        &self,
        package: &Path,
        request: &CatalogRecoveryRequest,
        work: &Path,
    ) -> Result<(PathBuf, CatalogExtraction), CatalogError> {
        let seven_zip = self
            .seven_zip
            .clone()
            .filter(|path| path.is_file())
            .or_else(|| find_command(&["7z", "7zz"]))
            .ok_or_else(|| CatalogError::ToolUnavailable {
                tool: "7z".into(),
                remediation: "install 7-Zip or set ONEDAY_7ZIP".into(),
            })?;
        let outer = work.join("outer");
        extract_archive(&seven_zip, package, &outer)?;
        if let Some(candidate) = find_exact_driver(&outer, request)? {
            return Ok((
                candidate,
                CatalogExtraction::MsuDirect {
                    extractor: executable_name(&seven_zip),
                },
            ));
        }

        let mut cabs = collect_files(&outer)?
            .into_iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case("cab"))
            })
            .collect::<Vec<_>>();
        cabs.sort();
        for (index, cab) in cabs.iter().enumerate() {
            let nested = work.join(format!("cab-{index:02}"));
            extract_archive(&seven_zip, cab, &nested)?;
            if let Some(candidate) = find_exact_driver(&nested, request)? {
                return Ok((
                    candidate,
                    CatalogExtraction::CabDirect {
                        extractor: executable_name(&seven_zip),
                        cab: cab
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                    },
                ));
            }
        }

        let payloads = discover_psf_payloads(work, request)?;
        for (index, payload) in payloads
            .iter()
            .filter(|payload| payload.kind == PsfPayloadKind::Neutral)
            .enumerate()
        {
            let candidate = work
                .join("neutral")
                .join(format!("{index:02}-{}", request.driver_name));
            extract_psf_blob(payload, &candidate)?;
            if digest_file::<Sha256>(&candidate).map_err(|source| CatalogError::Publish {
                path: candidate.clone(),
                source,
            })? == request.expected_sha256
            {
                return Ok((
                    candidate,
                    CatalogExtraction::PsfNeutral {
                        member_path: payload.member_path.clone(),
                    },
                ));
            }
            fs::remove_file(candidate).ok();
        }

        self.hydrate_psf(&payloads, request, work)
    }

    fn hydrate_psf(
        &self,
        payloads: &[PsfPayload],
        request: &CatalogRecoveryRequest,
        work: &Path,
    ) -> Result<(PathBuf, CatalogExtraction), CatalogError> {
        let forward = payloads
            .iter()
            .filter(|payload| payload.kind == PsfPayloadKind::Forward)
            .collect::<Vec<_>>();
        let neutral = payloads
            .iter()
            .filter(|payload| payload.kind == PsfPayloadKind::Neutral)
            .collect::<Vec<_>>();
        if forward.is_empty() && neutral.is_empty() {
            return Err(CatalogError::HydrationFailed {
                driver_name: request.driver_name.clone(),
                reason: "no usable PSF payload was found".into(),
            });
        }
        let deltas = work.join("deltas");
        fs::create_dir_all(&deltas).map_err(|source| CatalogError::Publish {
            path: deltas.clone(),
            source,
        })?;

        for (index, payload) in neutral.iter().enumerate() {
            let delta = deltas.join(format!("neutral-{index:02}.delta"));
            extract_psf_blob(payload, &delta)?;
            let output = work
                .join("hydrated")
                .join(format!("neutral-{index:02}.sys"));
            if apply_delta_bytes(&[], &delta, &output, &request.expected_sha256)? {
                return Ok((
                    output,
                    CatalogExtraction::PsfNullDelta {
                        hydrator: MSDELTA_HYDRATOR.into(),
                        member_path: payload.member_path.clone(),
                    },
                ));
            }
        }

        let local_bases = self
            .base_root
            .as_deref()
            .map(collect_files)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&request.driver_name))
            })
            .collect::<Vec<_>>();

        for (index, payload) in forward.iter().enumerate() {
            let delta = deltas.join(format!("forward-{index:02}.delta"));
            extract_psf_blob(payload, &delta)?;
            for (base_index, base) in local_bases.iter().enumerate() {
                let output = work
                    .join("hydrated")
                    .join(format!("{index:02}-{base_index:02}.sys"));
                if apply_delta(base, &delta, &output, &request.expected_sha256)? {
                    let base_sha256 =
                        digest_file::<Sha256>(base).map_err(|source| CatalogError::Publish {
                            path: base.clone(),
                            source,
                        })?;
                    return Ok((
                        output,
                        CatalogExtraction::PsfMsdelta {
                            hydrator: MSDELTA_HYDRATOR.into(),
                            base_sha256,
                            member_path: payload.member_path.clone(),
                        },
                    ));
                }
            }

            let resolved = self
                .uup
                .resolve(&UupResolveRequest {
                    driver_name: request.driver_name.clone(),
                    os_version: request.os_version.clone(),
                    architecture: request.architecture,
                    member_path: payload.member_path.clone(),
                })
                .map_err(|error| CatalogError::HydrationFailed {
                    driver_name: request.driver_name.clone(),
                    reason: error.to_string(),
                })?;
            let output = work.join("hydrated").join(format!("{index:02}-rtm.sys"));
            if apply_delta(&resolved.path, &delta, &output, &request.expected_sha256)? {
                self.uup
                    .confirm(&resolved)
                    .map_err(|error| CatalogError::HydrationFailed {
                        driver_name: request.driver_name.clone(),
                        reason: error.to_string(),
                    })?;
                return Ok((
                    output,
                    CatalogExtraction::PsfRtmMsdelta {
                        hydrator: "jlevere/msdelta".into(),
                        hydrator_revision: Some(MSDELTA_REVISION.into()),
                        base_sha256: resolved.sha256,
                        member_path: payload.member_path.clone(),
                        base: Box::new(resolved.provenance),
                    },
                ));
            }
        }

        Err(CatalogError::HydrationFailed {
            driver_name: request.driver_name.clone(),
            reason: "no base and delta combination produced the expected hash".into(),
        })
    }

    fn get_text(
        &self,
        url: &str,
        query: &[(&str, &str)],
        stage: CatalogStage,
    ) -> Result<String, CatalogError> {
        let response = self
            .client
            .get(url)
            .query(query)
            .timeout(self.request_timeout)
            .send()
            .map_err(|source| CatalogError::Network {
                stage,
                url: Some(url.into()),
                source: Box::new(source),
            })?;
        response_text(response, stage, Some(url))
    }
}

impl CatalogPort for CatalogAdapter {
    fn recover(
        &self,
        request: &CatalogRecoveryRequest,
        destination: &Path,
    ) -> Result<CatalogRecoveredBinary, CatalogError> {
        let normalized_driver = normalize_driver_name(&request.driver_name).map_err(|error| {
            CatalogError::InvalidPayload {
                stage: CatalogStage::Search,
                reason: error.to_string(),
            }
        })?;
        let normalized_kb =
            normalize_kb_code(&request.kb_code).map_err(|error| CatalogError::InvalidPayload {
                stage: CatalogStage::Search,
                reason: error.to_string(),
            })?;
        let expected_sha256 = request.expected_sha256.trim().to_ascii_lowercase();
        if !is_sha256(&expected_sha256) {
            return Err(CatalogError::InvalidPayload {
                stage: CatalogStage::Search,
                reason: "expected SHA-256 is invalid".into(),
            });
        }
        let request = CatalogRecoveryRequest {
            driver_name: normalized_driver,
            kb_code: normalized_kb,
            os_version: request.os_version.trim().to_owned(),
            architecture: request.architecture,
            expected_sha256,
        };

        let update = self.resolve_update(&request)?;
        let package = self.resolve_package(&update)?;
        let package_path = self.download_package(&package, update.size_bytes)?;
        let downloaded_sha256 =
            digest_file::<Sha256>(&package_path).map_err(|source| CatalogError::Publish {
                path: package_path.clone(),
                source,
            })?;
        let work = TempDir::new().map_err(|source| CatalogError::Publish {
            path: env::temp_dir(),
            source,
        })?;
        let (candidate, extraction) = self.extract(&package_path, &request, work.path())?;
        let actual_sha256 =
            digest_file::<Sha256>(&candidate).map_err(|source| CatalogError::Publish {
                path: candidate.clone(),
                source,
            })?;
        if actual_sha256 != request.expected_sha256 {
            return Err(CatalogError::HashMismatch {
                algorithm: HashAlgorithm::Sha256,
                expected: request.expected_sha256.clone(),
                actual: actual_sha256,
                path: candidate,
            });
        }
        let reused = publish_exact(&candidate, destination, &request.expected_sha256)?;
        let bytes_written = destination
            .metadata()
            .map_err(|source| CatalogError::Publish {
                path: destination.to_owned(),
                source,
            })?
            .len();
        Ok(CatalogRecoveredBinary {
            destination: destination.to_owned(),
            sha256: request.expected_sha256.clone(),
            bytes_written,
            reused,
            source_url: package.url.clone(),
            provenance: CatalogRecoveryProvenance {
                update,
                package: CatalogPackageProvenance {
                    package,
                    downloaded_sha256,
                },
                extraction,
            },
        })
    }
}

fn parse_search(html: &str) -> Result<Vec<CatalogUpdate>, CatalogError> {
    if !html.contains("ctl00_catalogBody_updateMatches") {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::Search,
            reason: "results table is missing".into(),
        });
    }
    let mut rows = Vec::new();
    for row in SEARCH_ROW.captures_iter(html) {
        let update_id = row["id"].to_ascii_lowercase();
        let body = &row["body"];
        let mut cells = BTreeMap::<usize, String>::new();
        for cell in SEARCH_CELL.captures_iter(body) {
            if !cell["id"].eq_ignore_ascii_case(&update_id) {
                continue;
            }
            let index = cell["cell"]
                .parse::<usize>()
                .expect("cell regex is numeric");
            cells.insert(index, clean_html(&cell["body"]));
        }
        let size = ORIGINAL_SIZE
            .captures(body)
            .filter(|capture| capture["id"].eq_ignore_ascii_case(&update_id))
            .map(|capture| clean_html(&capture["size"]))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| CatalogError::InvalidPayload {
                stage: CatalogStage::Search,
                reason: format!("row {update_id} has no valid original size"),
            })?;
        rows.push(CatalogUpdate {
            update_id,
            title: cells.remove(&1).unwrap_or_default(),
            product: cells.remove(&2).unwrap_or_default(),
            classification: cells.remove(&3).unwrap_or_default(),
            last_updated: cells.remove(&4).unwrap_or_default(),
            version: cells.remove(&5).unwrap_or_default(),
            size_bytes: size,
        });
    }
    Ok(rows)
}

fn select_update(
    updates: &[CatalogUpdate],
    request: &CatalogRecoveryRequest,
) -> Result<CatalogUpdate, CatalogError> {
    let aliases = product_aliases(&request.os_version);
    let requested_release = release_token(&request.os_version);
    let candidates = updates
        .iter()
        .filter(|update| {
            let title = update.title.to_ascii_lowercase();
            let normalized = product_key(&format!("{} {}", update.title, update.product));
            title.contains(&request.kb_code.to_ascii_lowercase())
                && title.contains("cumulative update")
                && !title.contains("dynamic cumulative update")
                && !title.contains("preview")
                && title_matches_architecture(&title, request.architecture)
                && aliases.iter().any(|alias| normalized.contains(alias))
                && requested_release.as_ref().is_none_or(|release| {
                    release_token(&update.title)
                        .as_ref()
                        .is_none_or(|candidate| candidate == release)
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [update] => Ok(update.clone()),
        [] => Err(CatalogError::UpdateNotFound {
            kb_code: request.kb_code.clone(),
            os_version: request.os_version.clone(),
            architecture: request.architecture,
        }),
        _ => Err(CatalogError::AmbiguousUpdate {
            kb_code: request.kb_code.clone(),
            os_version: request.os_version.clone(),
            architecture: request.architecture,
            candidate_ids: candidates
                .into_iter()
                .map(|update| update.update_id)
                .collect(),
        }),
    }
}

fn parse_detail(html: &str) -> Result<CatalogDetail, CatalogError> {
    let title = element_text(html, "ScopedViewHandler_titleText").unwrap_or_default();
    let update_id = element_text(html, "ScopedViewHandler_UpdateID")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !Regex::new(&format!(r"(?i)^{GUID}$"))
        .expect("valid GUID regex")
        .is_match(&update_id)
    {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::Detail,
            reason: "detail page has no valid update ID".into(),
        });
    }
    let architecture =
        architecture_from_title(&title).ok_or_else(|| CatalogError::InvalidPayload {
            stage: CatalogStage::Detail,
            reason: "detail title has no unambiguous supported architecture".into(),
        })?;
    let products = element_text(html, "productsDiv")
        .unwrap_or_default()
        .replace("Supported products:", "")
        .trim()
        .to_owned();
    let kb_text = element_text(html, "kbDiv").unwrap_or_default();
    let kb_numbers = KB_NUMBER
        .find_iter(&kb_text)
        .map(|number| format!("KB{}", number.as_str()))
        .collect();
    Ok(CatalogDetail {
        update_id,
        title,
        architecture,
        products,
        kb_numbers,
    })
}

fn validate_detail(
    update: &CatalogUpdate,
    detail: &CatalogDetail,
    request: &CatalogRecoveryRequest,
) -> Result<(), CatalogError> {
    let product = product_key(&format!("{} {}", detail.title, detail.products));
    let valid = detail.update_id == update.update_id
        && detail.title == update.title
        && detail.architecture == request.architecture
        && detail.kb_numbers.contains(&request.kb_code)
        && product_aliases(&request.os_version)
            .iter()
            .any(|alias| product.contains(alias));
    if valid {
        Ok(())
    } else {
        Err(CatalogError::InvalidPayload {
            stage: CatalogStage::Detail,
            reason: "search result and detail page do not agree".into(),
        })
    }
}

fn parse_download_dialog(
    html: &str,
    requested_id: &str,
) -> Result<Vec<CatalogPackage>, CatalogError> {
    let mut groups = BTreeMap::<usize, BTreeMap<String, String>>::new();
    let mut files = BTreeMap::<(usize, usize), BTreeMap<String, String>>::new();
    for capture in JS_ASSIGNMENT.captures_iter(html) {
        let group = capture["group"].parse().expect("group regex is numeric");
        let value = capture["value"].replace("\\'", "'").replace("\\\\", "\\");
        if let Some(file) = capture.name("file") {
            files
                .entry((group, file.as_str().parse().expect("file regex is numeric")))
                .or_default()
                .insert(capture["field"].into(), value);
        } else {
            groups
                .entry(group)
                .or_default()
                .insert(capture["field"].into(), value);
        }
    }
    let mut packages = Vec::new();
    for ((group, _), fields) in files {
        if groups
            .get(&group)
            .and_then(|values| values.get("updateID"))
            .is_none_or(|value| !value.eq_ignore_ascii_case(requested_id))
        {
            continue;
        }
        let url = fields.get("url").cloned().unwrap_or_default();
        let filename = fields.get("fileName").cloned().unwrap_or_default();
        validate_package_url(&url, &filename)?;
        let sha1 = decode_package_digest(fields.get("digest").map(String::as_str), "SHA-1", 20)?;
        let sha256 =
            decode_package_digest(fields.get("sha256").map(String::as_str), "SHA-256", 32)?;
        packages.push(CatalogPackage {
            update_id: requested_id.to_ascii_lowercase(),
            url,
            filename,
            sha1,
            sha256,
        });
    }
    if packages.is_empty() {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::DownloadDialog,
            reason: "download URL is missing".into(),
        });
    }
    Ok(packages)
}

fn decode_package_digest(
    value: Option<&str>,
    name: &str,
    expected_length: usize,
) -> Result<Option<String>, CatalogError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(value)
        .map_err(|error| CatalogError::InvalidPayload {
            stage: CatalogStage::DownloadDialog,
            reason: format!("invalid package {name}: {error}"),
        })?;
    if bytes.len() != expected_length {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::DownloadDialog,
            reason: format!("package {name} has an invalid length"),
        });
    }
    Ok(Some(hex(&bytes)))
}

fn validate_package_url(value: &str, filename: &str) -> Result<(), CatalogError> {
    let url = Url::parse(value).map_err(|_| CatalogError::InvalidPayload {
        stage: CatalogStage::DownloadDialog,
        reason: "package URL is invalid".into(),
    })?;
    let host_ok = url.host_str().is_some_and(|host| {
        let host = host.to_ascii_lowercase();
        host == "download.windowsupdate.com"
            || host.ends_with(".download.windowsupdate.com")
            || host == "download.microsoft.com"
            || host.ends_with(".download.microsoft.com")
            || host == "catalog.sf.dl.delivery.mp.microsoft.com"
    });
    let path_name = url
        .path_segments()
        .and_then(Iterator::last)
        .unwrap_or_default();
    let suffix_ok = filename.to_ascii_lowercase().ends_with(".msu")
        || filename.to_ascii_lowercase().ends_with(".cab");
    if url.scheme() == "https"
        && host_ok
        && path_name.eq_ignore_ascii_case(
            Path::new(filename)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
        )
        && suffix_ok
    {
        Ok(())
    } else {
        Err(CatalogError::InvalidPayload {
            stage: CatalogStage::DownloadDialog,
            reason: "package URL is not an allowed Microsoft download URL".into(),
        })
    }
}

fn response_text(
    response: Response,
    stage: CatalogStage,
    url: Option<&str>,
) -> Result<String, CatalogError> {
    ensure_success(&response, stage, url)?;
    response.text().map_err(|source| CatalogError::Network {
        stage,
        url: url.map(str::to_owned),
        source: Box::new(source),
    })
}

fn ensure_success(
    response: &Response,
    stage: CatalogStage,
    url: Option<&str>,
) -> Result<(), CatalogError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(CatalogError::Http {
            stage,
            url: url.map(str::to_owned),
            status_code: response.status().as_u16(),
        })
    }
}

fn verify_package(
    path: &Path,
    package: &CatalogPackage,
    expected_size: u64,
) -> Result<(), CatalogError> {
    let size = path
        .metadata()
        .map_err(|source| CatalogError::Publish {
            path: path.to_owned(),
            source,
        })?
        .len();
    if size != expected_size {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::PackageDownload,
            reason: format!("expected {expected_size} bytes, found {size}"),
        });
    }
    if let Some(expected) = &package.sha1 {
        let actual = digest_file::<Sha1>(path).map_err(|source| CatalogError::Publish {
            path: path.to_owned(),
            source,
        })?;
        if &actual != expected {
            return Err(CatalogError::HashMismatch {
                algorithm: HashAlgorithm::Sha1,
                expected: expected.clone(),
                actual,
                path: path.to_owned(),
            });
        }
    }
    if let Some(expected) = &package.sha256 {
        let actual = digest_file::<Sha256>(path).map_err(|source| CatalogError::Publish {
            path: path.to_owned(),
            source,
        })?;
        if &actual != expected {
            return Err(CatalogError::HashMismatch {
                algorithm: HashAlgorithm::Sha256,
                expected: expected.clone(),
                actual,
                path: path.to_owned(),
            });
        }
    }
    Ok(())
}

fn discover_psf_payloads(
    root: &Path,
    request: &CatalogRecoveryRequest,
) -> Result<Vec<PsfPayload>, CatalogError> {
    let mut cix_files = collect_files(root)?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("express.psf.cix.xml"))
        })
        .collect::<Vec<_>>();
    cix_files.sort();
    let arch_prefix = match request.architecture {
        Architecture::X64 => "amd64_",
        Architecture::Arm64 => "arm64_",
    };
    let mut payloads = Vec::new();
    for cix in cix_files {
        let psf_path = find_psf_for_cix(root, &cix)?;
        let xml = fs::read_to_string(&cix).map_err(|source| CatalogError::Publish {
            path: cix.clone(),
            source,
        })?;
        let document = Document::parse(&xml).map_err(|error| CatalogError::InvalidPayload {
            stage: CatalogStage::Extraction,
            reason: format!("invalid CIX XML: {error}"),
        })?;
        for file in document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "File")
        {
            let member = file.attribute("name").unwrap_or_default();
            let normalized = member.replace('\\', "/");
            let Some((kind, filename)) = psf_member(&normalized) else {
                continue;
            };
            if !filename.eq_ignore_ascii_case(&request.driver_name)
                || !normalized.to_ascii_lowercase().starts_with(arch_prefix)
            {
                continue;
            }
            let source = file
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Source")
                .ok_or_else(|| CatalogError::InvalidPayload {
                    stage: CatalogStage::Extraction,
                    reason: format!("CIX source is missing for {member}"),
                })?;
            let offset = source
                .attribute("offset")
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| CatalogError::InvalidPayload {
                    stage: CatalogStage::Extraction,
                    reason: format!("CIX offset is invalid for {member}"),
                })?;
            let length = source
                .attribute("length")
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| CatalogError::InvalidPayload {
                    stage: CatalogStage::Extraction,
                    reason: format!("CIX length is invalid for {member}"),
                })?;
            let source_sha256 = source
                .descendants()
                .find(|node| {
                    node.is_element()
                        && node.tag_name().name() == "Hash"
                        && node
                            .attribute("alg")
                            .is_some_and(|alg| alg.eq_ignore_ascii_case("sha256"))
                })
                .and_then(|node| node.attribute("value"))
                .map(|value| value.to_ascii_lowercase());
            payloads.push(PsfPayload {
                psf_path: psf_path.clone(),
                member_path: member.into(),
                kind,
                source_type: source.attribute("type").unwrap_or_default().into(),
                offset,
                length,
                source_sha256,
            });
        }
    }
    Ok(payloads)
}

fn find_psf_for_cix(root: &Path, cix: &Path) -> Result<PathBuf, CatalogError> {
    let mut nearby = Vec::new();
    for directory in [cix.parent(), cix.parent().and_then(Path::parent)]
        .into_iter()
        .flatten()
    {
        nearby.extend(
            fs::read_dir(directory)
                .map_err(|source| CatalogError::Publish {
                    path: directory.to_owned(),
                    source,
                })?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|value| value.eq_ignore_ascii_case("psf"))
                }),
        );
    }
    nearby.sort();
    nearby.dedup();
    let candidates = if nearby.is_empty() {
        collect_files(root)?
            .into_iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|value| value.eq_ignore_ascii_case("psf"))
            })
            .collect::<Vec<_>>()
    } else {
        nearby
    };
    match candidates.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(CatalogError::InvalidPayload {
            stage: CatalogStage::Extraction,
            reason: format!(
                "expected one PSF for {}, found {}",
                cix.display(),
                candidates.len()
            ),
        }),
    }
}

fn psf_member(path: &str) -> Option<(PsfPayloadKind, &str)> {
    let mut parts = path.rsplit('/');
    let filename = parts.next()?;
    let kind = match parts.next()?.to_ascii_lowercase().as_str() {
        "f" => PsfPayloadKind::Forward,
        "n" => PsfPayloadKind::Neutral,
        "r" => PsfPayloadKind::Reverse,
        _ => return None,
    };
    Some((kind, filename))
}

fn extract_psf_blob(payload: &PsfPayload, destination: &Path) -> Result<(), CatalogError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source| CatalogError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    }
    let mut source = fs::File::open(&payload.psf_path).map_err(|source| CatalogError::Publish {
        path: payload.psf_path.clone(),
        source,
    })?;
    source
        .seek(SeekFrom::Start(payload.offset))
        .map_err(|source| CatalogError::Publish {
            path: payload.psf_path.clone(),
            source,
        })?;
    let length = usize::try_from(payload.length).map_err(|_| CatalogError::InvalidPayload {
        stage: CatalogStage::Extraction,
        reason: "PSF blob is too large for this platform".into(),
    })?;
    let mut bytes = vec![0_u8; length];
    source
        .read_exact(&mut bytes)
        .map_err(|source| CatalogError::Publish {
            path: payload.psf_path.clone(),
            source,
        })?;
    if let Some(expected) = &payload.source_sha256 {
        let actual = hex(&Sha256::digest(&bytes));
        if &actual != expected {
            return Err(CatalogError::HashMismatch {
                algorithm: HashAlgorithm::Sha256,
                expected: expected.clone(),
                actual,
                path: payload.psf_path.clone(),
            });
        }
    }
    if !matches!(bytes.get(..4), Some(b"PA19" | b"PA30" | b"PA31"))
        && matches!(bytes.get(4..8), Some(b"PA19" | b"PA30" | b"PA31"))
    {
        bytes.drain(..4);
    }
    fs::write(destination, bytes).map_err(|source| CatalogError::Publish {
        path: destination.to_owned(),
        source,
    })
}

fn apply_delta(
    base: &Path,
    delta: &Path,
    output: &Path,
    expected_sha256: &str,
) -> Result<bool, CatalogError> {
    let base = fs::read(base).map_err(|source| CatalogError::Publish {
        path: base.to_owned(),
        source,
    })?;
    apply_delta_bytes(&base, delta, output, expected_sha256)
}

fn apply_delta_bytes(
    base: &[u8],
    delta: &Path,
    output: &Path,
    expected_sha256: &str,
) -> Result<bool, CatalogError> {
    let delta = fs::read(delta).map_err(|source| CatalogError::Publish {
        path: delta.to_owned(),
        source,
    })?;
    let delta = if msdelta::dcm::is_dcm(&delta) {
        match msdelta::dcm::strip(&delta) {
            Ok(delta) => delta,
            Err(_) => return Ok(false),
        }
    } else {
        &delta
    };
    if delta.len() > MAX_DELTA_BYTES || !is_safe_forward_delta(delta) {
        return Ok(false);
    }
    let hydrated = match msdelta::pa30::apply(base, delta) {
        Ok(hydrated) => hydrated,
        Err(_) => {
            fs::remove_file(output).ok();
            return Ok(false);
        }
    };
    if hex(&Sha256::digest(&hydrated)) != expected_sha256 {
        fs::remove_file(output).ok();
        return Ok(false);
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|source| CatalogError::Publish {
            path: output.to_owned(),
            source,
        })?;
    }
    fs::write(output, hydrated).map_err(|source| CatalogError::Publish {
        path: output.to_owned(),
        source,
    })?;
    Ok(true)
}

fn is_safe_forward_delta(delta: &[u8]) -> bool {
    let Ok(parsed) = msdelta::pa30::parse(delta) else {
        return false;
    };
    if !is_safe_delta_header(&parsed.header) {
        return false;
    }
    if parsed.patch_data.starts_with(&LZMS_API_MAGIC) {
        let Some(total) = parsed.patch_data.get(8..16) else {
            return false;
        };
        let total = u64::from_le_bytes(total.try_into().expect("slice length checked"));
        if total > MAX_HYDRATED_DRIVER_BYTES as u64 {
            return false;
        }
    }
    true
}

fn is_safe_delta_header(header: &msdelta::pa30::Header) -> bool {
    use msdelta::pa30::FormatVersion;

    matches!(header.version, FormatVersion::PA30 | FormatVersion::PA31)
        && header.file_type_set & 0x100 == 0
        && (0..=MAX_HYDRATED_DRIVER_BYTES).contains(&header.target_size)
}

fn extract_archive(
    executable: &Path,
    archive: &Path,
    destination: &Path,
) -> Result<(), CatalogError> {
    fs::create_dir_all(destination).map_err(|source| CatalogError::Publish {
        path: destination.to_owned(),
        source,
    })?;
    let completed = Command::new(executable)
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", destination.display()))
        .arg(archive)
        .output()
        .map_err(|_| CatalogError::ToolUnavailable {
            tool: executable.display().to_string(),
            remediation: "verify the configured 7z executable".into(),
        })?;
    if completed.status.success() {
        Ok(())
    } else {
        Err(CatalogError::ToolFailed {
            tool: executable.display().to_string(),
            status: completed.status.code(),
            stderr: tail(&completed.stderr, 2000),
        })
    }
}

fn find_exact_driver(
    root: &Path,
    request: &CatalogRecoveryRequest,
) -> Result<Option<PathBuf>, CatalogError> {
    let mut matches = Vec::new();
    for path in collect_files(root)? {
        if path
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(&request.driver_name))
            && !path.is_symlink()
        {
            let digest = digest_file::<Sha256>(&path).map_err(|source| CatalogError::Publish {
                path: path.clone(),
                source,
            })?;
            if digest == request.expected_sha256 {
                matches.push(path);
            }
        }
    }
    matches.sort();
    Ok(matches.into_iter().next())
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, CatalogError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| CatalogError::Publish {
            path: directory.clone(),
            source,
        })? {
            let path = entry
                .map_err(|source| CatalogError::Publish {
                    path: directory.clone(),
                    source,
                })?
                .path();
            if path.is_symlink() {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn publish_exact(source: &Path, destination: &Path, expected: &str) -> Result<bool, CatalogError> {
    if destination.is_symlink() || destination.as_os_str().is_empty() {
        return Err(CatalogError::InvalidPayload {
            stage: CatalogStage::Publish,
            reason: "destination must be an explicit, non-symlink file path".into(),
        });
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source| CatalogError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    }
    if destination.exists() {
        let actual =
            digest_file::<Sha256>(destination).map_err(|source| CatalogError::Publish {
                path: destination.to_owned(),
                source,
            })?;
        return if actual == expected {
            Ok(true)
        } else {
            Err(CatalogError::HashMismatch {
                algorithm: HashAlgorithm::Sha256,
                expected: expected.into(),
                actual,
                path: destination.to_owned(),
            })
        };
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let mut input = fs::File::open(source).map_err(|source_error| CatalogError::Publish {
        path: source.to_owned(),
        source: source_error,
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| CatalogError::Publish {
        path: destination.to_owned(),
        source,
    })?;
    std::io::copy(&mut input, &mut temporary).map_err(|source| CatalogError::Publish {
        path: destination.to_owned(),
        source,
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| CatalogError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    let actual =
        digest_file::<Sha256>(temporary.path()).map_err(|source| CatalogError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    if actual != expected {
        return Err(CatalogError::HashMismatch {
            algorithm: HashAlgorithm::Sha256,
            expected: expected.into(),
            actual,
            path: temporary.path().to_owned(),
        });
    }
    match fs::hard_link(temporary.path(), destination) {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual =
                digest_file::<Sha256>(destination).map_err(|source| CatalogError::Publish {
                    path: destination.to_owned(),
                    source,
                })?;
            if actual == expected {
                Ok(true)
            } else {
                Err(CatalogError::HashMismatch {
                    algorithm: HashAlgorithm::Sha256,
                    expected: expected.into(),
                    actual,
                    path: destination.to_owned(),
                })
            }
        }
        Err(source) => Err(CatalogError::Publish {
            path: destination.to_owned(),
            source,
        }),
    }
}

fn product_aliases(value: &str) -> Vec<String> {
    let key = product_key(value);
    let mut aliases = vec![key.clone()];
    let server_2022 = key.contains("windowsserver2022") || key.contains("server2022");
    if server_2022 && release_token(value).as_deref() == Some("23h2") {
        aliases.push("microsoftserveroperatingsystem23h2".into());
    } else if server_2022 {
        aliases.extend([
            "windowsserver2022".into(),
            "microsoftserveroperatingsystem21h2".into(),
        ]);
    } else if key.contains("windowsserver2025") || key.contains("server2025") {
        aliases.extend([
            "windowsserver2025".into(),
            "microsoftserveroperatingsystem24h2".into(),
        ]);
    } else if key.contains("windows11") {
        aliases.push("windows11".into());
    } else if key.contains("windows10") {
        aliases.push("windows10".into());
    }
    aliases.retain(|alias| !alias.is_empty());
    aliases.sort();
    aliases.dedup();
    aliases
}

fn product_key(value: &str) -> String {
    static ARCH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:x64|amd64|arm64|aarch64|x86)[- ]based\s+systems?\b")
            .expect("valid product architecture regex")
    });
    static VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bversion\s+\d{2}h\d\b").expect("valid version regex"));
    static EDITION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:server core installation|desktop experience)\b")
            .expect("valid edition regex")
    });
    static NON_ALNUM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[^a-z0-9]+").expect("valid cleanup regex"));
    let lower = value.to_ascii_lowercase();
    let value = ARCH.replace_all(&lower, " ");
    let value = VERSION.replace_all(&value, " ");
    let value = EDITION.replace_all(&value, " ");
    NON_ALNUM.replace_all(&value, "").into_owned()
}

fn release_token(value: &str) -> Option<String> {
    RELEASE
        .captures(value)
        .and_then(|capture| capture.get(1))
        .map(|release| release.as_str().to_ascii_lowercase())
}

fn title_matches_architecture(title: &str, architecture: Architecture) -> bool {
    architecture_from_title(title) == Some(architecture)
}

fn architecture_from_title(title: &str) -> Option<Architecture> {
    match (ARCH_X64.is_match(title), ARCH_ARM64.is_match(title)) {
        (true, false) => Some(Architecture::X64),
        (false, true) => Some(Architecture::Arm64),
        _ => None,
    }
}

fn element_text(html: &str, id: &str) -> Option<String> {
    for tag in ["span", "div"] {
        let pattern = Regex::new(&format!(
            r#"(?is)<{tag}\b[^>]*\bid=["']{}["'][^>]*>(?P<body>.*?)</{tag}\s*>"#,
            regex::escape(id)
        ))
        .expect("escaped element regex is valid");
        if let Some(capture) = pattern.captures(html) {
            return Some(clean_html(&capture["body"]));
        }
    }
    None
}

fn clean_html(value: &str) -> String {
    TAG.replace_all(value, " ")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn find_command(names: &[&str]) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
            .find(|candidate| candidate.is_file())
    })
}

fn executable_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn tail(bytes: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .rev()
        .take(limit)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{
        apply_delta, hex, is_safe_delta_header, is_safe_forward_delta, parse_detail,
        parse_download_dialog, select_update, validate_package_url,
    };
    use crate::model::{
        acquisition::Architecture,
        catalog::{CatalogRecoveryRequest, CatalogUpdate},
    };

    #[test]
    fn selects_only_the_matching_regular_cumulative_update() {
        let request = CatalogRecoveryRequest {
            driver_name: "example.sys".into(),
            kb_code: "KB5000001".into(),
            os_version: "Windows 11 Version 24H2 for x64-based Systems".into(),
            architecture: Architecture::X64,
            expected_sha256: "a".repeat(64),
        };
        let updates = vec![CatalogUpdate {
            update_id: "11111111-1111-1111-1111-111111111111".into(),
            title: "2026-01 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5000001)".into(),
            product: "Windows 11".into(),
            classification: String::new(),
            last_updated: String::new(),
            version: String::new(),
            size_bytes: 1,
        }];

        assert_eq!(
            select_update(&updates, &request).unwrap().update_id,
            updates[0].update_id
        );
    }

    #[test]
    fn selects_server_2022_23h2_without_matching_regular_server_2022() {
        let request = CatalogRecoveryRequest {
            driver_name: "example.sys".into(),
            kb_code: "KB5000001".into(),
            os_version: "Windows Server 2022, 23H2 Edition (Server Core installation)".into(),
            architecture: Architecture::X64,
            expected_sha256: "a".repeat(64),
        };
        let updates = vec![
            CatalogUpdate {
                update_id: "11111111-1111-1111-1111-111111111111".into(),
                title: "2026-01 Cumulative Update for Windows Server 2022 for x64-based Systems (KB5000001)".into(),
                product: "Windows Server 2022".into(),
                classification: String::new(),
                last_updated: String::new(),
                version: String::new(),
                size_bytes: 1,
            },
            CatalogUpdate {
                update_id: "22222222-2222-2222-2222-222222222222".into(),
                title: "2026-01 Cumulative Update for Microsoft server operating system version 23H2 for x64-based Systems (KB5000001)".into(),
                product: "Microsoft Server operating system-23H2".into(),
                classification: String::new(),
                last_updated: String::new(),
                version: String::new(),
                size_bytes: 1,
            },
        ];

        assert_eq!(
            select_update(&updates, &request).unwrap().update_id,
            updates[1].update_id
        );
    }

    #[test]
    fn rejects_untrusted_download_dialog_urls() {
        let html = concat!(
            "downloadInformation[0].updateID = '11111111-1111-1111-1111-111111111111';",
            "downloadInformation[0].files[0].url = 'https://evil.example/file.msu';",
            "downloadInformation[0].files[0].fileName = 'file.msu';"
        );
        assert!(parse_download_dialog(html, "11111111-1111-1111-1111-111111111111").is_err());
    }

    #[test]
    fn derives_x64_detail_architecture_from_the_title_when_catalog_reports_na() {
        let html = concat!(
            "<span id='ScopedViewHandler_titleText'>",
            "2024-06 Cumulative Update for Windows 11 Version 22H2 ",
            "for x64-based Systems (KB5039212)",
            "</span>",
            "<span id='ScopedViewHandler_UpdateID'>11111111-1111-1111-1111-111111111111</span>",
            "<div id='archDiv'><span>Architecture:</span> n/a</div>",
            "<div id='productsDiv'><span>Supported products:</span> Windows 11</div>",
            "<div id='kbDiv'><span>KB article numbers:</span> 5039212</div>",
        );

        let detail = parse_detail(html).unwrap();

        assert_eq!(detail.architecture, Architecture::X64);
        assert_eq!(detail.products, "Windows 11");
        assert_eq!(detail.kb_numbers, ["KB5039212"]);
    }

    #[test]
    fn derives_arm64_detail_architecture_from_the_title() {
        let html = concat!(
            "<span id='ScopedViewHandler_titleText'>",
            "2024-06 Cumulative Update for Windows 11 Version 22H2 ",
            "for ARM64-based Systems (KB5039212)",
            "</span>",
            "<span id='ScopedViewHandler_UpdateID'>11111111-1111-1111-1111-111111111111</span>",
            "<div id='archDiv'><span>Architecture:</span> n/a</div>",
        );

        assert_eq!(
            parse_detail(html).unwrap().architecture,
            Architecture::Arm64
        );
    }

    #[test]
    fn rejects_detail_titles_without_one_supported_architecture() {
        let detail = |title: &str| {
            format!(
                "<span id='ScopedViewHandler_titleText'>{title}</span>\
                 <span id='ScopedViewHandler_UpdateID'>11111111-1111-1111-1111-111111111111</span>"
            )
        };

        assert!(parse_detail(&detail("Cumulative Update (KB5000001)")).is_err());
        assert!(
            parse_detail(&detail(
                "Cumulative Update for x64-based and ARM64-based Systems (KB5000001)"
            ))
            .is_err()
        );
    }

    #[test]
    fn parses_current_catalog_download_metadata() {
        let html = concat!(
            "downloadInformation[0].updateID = '15cddec9-ad48-4f0f-bc76-0f60359a5f6d';",
            "downloadInformation[0].files[0].url = ",
            "'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/",
            "a2fe5398-6f24-46ee-a533-372dc30bfd82/public/",
            "windows11.0-kb5039212-x64_2b67855a5e73c7a873e6bdca512c8c106b429196.msu';",
            "downloadInformation[0].files[0].digest = 'K2eFWl5zx6hz5r3KUSyMEGtCkZY=';",
            "downloadInformation[0].files[0].sha256 = ",
            "'1Gk0YE41XqmsYfwRMPjQfOm5hZDqJoR/ivHhS4EYLzc=';",
            "downloadInformation[0].files[0].fileName = ",
            "'windows11.0-kb5039212-x64_2b67855a5e73c7a873e6bdca512c8c106b429196.msu';",
        );

        let package = parse_download_dialog(html, "15cddec9-ad48-4f0f-bc76-0f60359a5f6d")
            .unwrap()
            .pop()
            .unwrap();

        assert_eq!(
            package.sha1.as_deref(),
            Some("2b67855a5e73c7a873e6bdca512c8c106b429196")
        );
        assert_eq!(
            package.sha256.as_deref(),
            Some("d46934604e355ea9ac61fc1130f8d07ce9b98590ea26847f8af1e14b81182f37")
        );
    }

    #[test]
    fn rejects_invalid_base64_catalog_sha256() {
        let html = concat!(
            "downloadInformation[0].updateID = '11111111-1111-1111-1111-111111111111';",
            "downloadInformation[0].files[0].url = ",
            "'https://catalog.sf.dl.delivery.mp.microsoft.com/files/file.msu';",
            "downloadInformation[0].files[0].sha256 = 'not-base64';",
            "downloadInformation[0].files[0].fileName = 'file.msu';",
        );

        assert!(parse_download_dialog(html, "11111111-1111-1111-1111-111111111111").is_err());
    }

    #[test]
    fn rejects_catalog_cdn_lookalike_hosts() {
        assert!(
            validate_package_url(
                "https://catalog.sf.dl.delivery.mp.microsoft.com.evil.example/file.msu",
                "file.msu"
            )
            .is_err()
        );
    }

    #[test]
    fn applies_delta_through_the_linked_library() {
        let directory = tempdir().unwrap();
        let base = b"unpatched driver bytes";
        let target = b"patched driver bytes";
        let delta = msdelta::pa30::create(base, target).unwrap();
        let base_path = directory.path().join("base.sys");
        let delta_path = directory.path().join("driver.delta");
        let output_path = directory.path().join("output.sys");
        fs::write(&base_path, base).unwrap();
        fs::write(&delta_path, delta).unwrap();
        let expected_sha256 = hex(&Sha256::digest(target));

        assert!(apply_delta(&base_path, &delta_path, &output_path, &expected_sha256).unwrap());
        assert_eq!(fs::read(output_path).unwrap(), target);
    }

    #[test]
    fn rejects_reverse_deltas_at_the_library_boundary() {
        let base = b"unpatched driver bytes";
        let target = b"patched driver bytes";
        let forward = msdelta::pa30::create(base, target).unwrap();
        let mut reverse_header = msdelta::pa30::get_info(&forward).unwrap();
        reverse_header.file_type_set |= 0x100;

        assert!(is_safe_forward_delta(&forward));
        assert!(!is_safe_delta_header(&reverse_header));
    }
}
