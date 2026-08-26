use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
    sync::LazyLock,
    thread,
    time::Duration,
};

use flate2::read::GzDecoder;
use regex::Regex;
use reqwest::blocking::{Client, Response};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::{
    errors::{WinbindexError, WinbindexStage},
    model::{
        acquisition::Architecture,
        winbindex::{
            AcquisitionProvenance, DownloadResult, WinbindexRecord, WinbindexResolveRequest,
        },
    },
    port::WinbindexPort,
};

use super::{digest_file, hex, transfer_buffer};

const X64_INDEX_ROOT: &str = "https://winbindex.m417z.com/data/by_filename_compressed";
const ARM64_INDEX_ROOT: &str = "https://m417z.com/winbindex-data-arm64/by_filename_compressed";
const SYMBOL_ROOT: &str = "https://msdl.microsoft.com/download/symbols";

static ARCH_X64: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:x64|amd64|x86[-_ ]?64|64[- ]?bit)\b").expect("valid x64 regex")
});
static ARCH_X86: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:x86|32[- ]?bit|i[3-6]86)\b").expect("valid x86 regex"));
static RELEASE_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:\d{4}|\d{2}H\d)$").expect("valid release regex"));
static SERVER_OS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bwindows server(?:,|\s|$)").expect("valid server regex"));
static OS_NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:microsoft|windows|version|for|based|systems?|operating|core|installation|desktop|experience|edition)\b",
    )
    .expect("valid OS noise regex")
});
static ARCH_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:arm64|aarch64|amd64|x64|x86_64)[- ]based\b")
        .expect("valid architecture suffix regex")
});
static NON_ALNUM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^a-z0-9]+").expect("valid non-alphanumeric regex"));

#[derive(Debug, Clone)]
pub struct WinbindexAdapter {
    client: Client,
    index_timeout: Duration,
    download_timeout: Duration,
    retries: u32,
    backoff: Duration,
}

impl Default for WinbindexAdapter {
    fn default() -> Self {
        Self {
            client: Client::new(),
            index_timeout: Duration::from_secs(30),
            download_timeout: Duration::from_secs(300),
            retries: 2,
            backoff: Duration::from_millis(250),
        }
    }
}

impl WinbindexAdapter {
    pub fn fetch_index(
        &self,
        driver_name: &str,
        architecture: Architecture,
    ) -> Result<Value, WinbindexError> {
        let driver_name = normalize_driver_name(driver_name)?;
        let url = index_url(&driver_name, architecture);
        let response = self.get(&url, self.index_timeout)?;
        let mut decoder = GzDecoder::new(response);
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .map_err(|error| WinbindexError::InvalidPayload {
                stage: WinbindexStage::Gzip,
                reason: error.to_string(),
            })?;
        let payload = serde_json::from_slice::<Value>(&decoded).map_err(|error| {
            WinbindexError::InvalidPayload {
                stage: WinbindexStage::Json,
                reason: error.to_string(),
            }
        })?;
        if !payload.is_object() {
            return Err(WinbindexError::InvalidPayload {
                stage: WinbindexStage::Json,
                reason: "root must be an object".into(),
            });
        }
        Ok(payload)
    }

    fn get(&self, url: &str, timeout: Duration) -> Result<Response, WinbindexError> {
        for attempt in 0..=self.retries {
            let response = self.client.get(url).timeout(timeout).send();
            let response = match response {
                Ok(response) => response,
                Err(source) if attempt < self.retries => {
                    thread::sleep(self.backoff.saturating_mul(2_u32.saturating_pow(attempt)));
                    drop(source);
                    continue;
                }
                Err(source) => {
                    return Err(WinbindexError::Network {
                        url: url.into(),
                        attempts: attempt + 1,
                        source: Box::new(source),
                    });
                }
            };

            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }
            let status_code = status.as_u16();
            if (status_code == 429 || status.is_server_error()) && attempt < self.retries {
                thread::sleep(self.backoff.saturating_mul(2_u32.saturating_pow(attempt)));
                continue;
            }
            return Err(WinbindexError::Http {
                url: url.into(),
                status_code,
            });
        }
        unreachable!("the retry loop always returns on its final attempt")
    }
}

impl WinbindexPort for WinbindexAdapter {
    fn resolve(
        &self,
        request: &WinbindexResolveRequest,
    ) -> Result<WinbindexRecord, WinbindexError> {
        let architecture = request
            .architecture
            .map(Ok)
            .unwrap_or_else(|| architecture_from_os(&request.os_version))?;
        let records = self.fetch_index(&request.driver_name, architecture)?;
        select_record(&records, request, architecture)
    }

    fn resolve_predecessor(
        &self,
        request: &WinbindexResolveRequest,
        successor_kb_code: &str,
    ) -> Result<WinbindexRecord, WinbindexError> {
        let architecture = request
            .architecture
            .map(Ok)
            .unwrap_or_else(|| architecture_from_os(&request.os_version))?;
        let records = self.fetch_index(&request.driver_name, architecture)?;
        select_record_with_successor(&records, request, architecture, Some(successor_kb_code))
    }

    fn download(
        &self,
        record: &WinbindexRecord,
        destination: &Path,
    ) -> Result<DownloadResult, WinbindexError> {
        validate_destination(destination)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| WinbindexError::Publish {
                path: destination.to_owned(),
                source,
            })?;
        }

        if destination.exists() {
            let actual_sha256 =
                digest_file::<Sha256>(destination).map_err(|source| WinbindexError::Publish {
                    path: destination.to_owned(),
                    source,
                })?;
            if actual_sha256 != record.sha256 {
                return Err(WinbindexError::DestinationCollision {
                    path: destination.to_owned(),
                    expected_sha256: record.sha256.clone(),
                    actual_sha256,
                });
            }
            return Ok(DownloadResult {
                destination: destination.to_owned(),
                sha256: record.sha256.clone(),
                source_url: record.download_url.clone(),
                bytes_written: destination
                    .metadata()
                    .map_err(|source| WinbindexError::Publish {
                        path: destination.to_owned(),
                        source,
                    })?
                    .len(),
                reused: true,
                record: record.clone(),
                provenance: AcquisitionProvenance::SymbolServer,
            });
        }

        let mut response = self.get(&record.download_url, self.download_timeout)?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|source| WinbindexError::Publish {
                path: destination.to_owned(),
                source,
            })?;
        let mut digest = Sha256::new();
        let mut bytes_written = 0_u64;
        let mut buffer = transfer_buffer();

        loop {
            let count = response
                .read(&mut buffer)
                .map_err(|source| WinbindexError::Network {
                    url: record.download_url.clone(),
                    attempts: 1,
                    source: Box::new(source),
                })?;
            if count == 0 {
                break;
            }
            temporary
                .write_all(&buffer[..count])
                .map_err(|source| WinbindexError::Publish {
                    path: destination.to_owned(),
                    source,
                })?;
            digest.update(&buffer[..count]);
            bytes_written += count as u64;
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| WinbindexError::Publish {
                path: destination.to_owned(),
                source,
            })?;

        let actual_sha256 = hex(&digest.finalize());
        if actual_sha256 != record.sha256 {
            return Err(WinbindexError::HashMismatch {
                expected_sha256: record.sha256.clone(),
                actual_sha256,
                path: destination.to_owned(),
                source_url: record.download_url.clone(),
                bytes_received: bytes_written,
            });
        }

        match fs::hard_link(temporary.path(), destination) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = digest_file::<Sha256>(destination).map_err(|source| {
                    WinbindexError::Publish {
                        path: destination.to_owned(),
                        source,
                    }
                })?;
                if existing != record.sha256 {
                    return Err(WinbindexError::DestinationCollision {
                        path: destination.to_owned(),
                        expected_sha256: record.sha256.clone(),
                        actual_sha256: existing,
                    });
                }
                return Ok(DownloadResult {
                    destination: destination.to_owned(),
                    sha256: record.sha256.clone(),
                    source_url: record.download_url.clone(),
                    bytes_written: destination
                        .metadata()
                        .map_err(|source| WinbindexError::Publish {
                            path: destination.to_owned(),
                            source,
                        })?
                        .len(),
                    reused: true,
                    record: record.clone(),
                    provenance: AcquisitionProvenance::SymbolServer,
                });
            }
            Err(source) => {
                return Err(WinbindexError::Publish {
                    path: destination.to_owned(),
                    source,
                });
            }
        }

        Ok(DownloadResult {
            destination: destination.to_owned(),
            sha256: record.sha256.clone(),
            source_url: record.download_url.clone(),
            bytes_written,
            reused: false,
            record: record.clone(),
            provenance: AcquisitionProvenance::SymbolServer,
        })
    }
}

#[derive(Clone)]
struct Candidate<'a> {
    score: usize,
    windows_version: &'a str,
    alias: &'a str,
    record: &'a Map<String, Value>,
    component_member_path: Option<String>,
}

pub(crate) fn select_record(
    records: &Value,
    request: &WinbindexResolveRequest,
    architecture: Architecture,
) -> Result<WinbindexRecord, WinbindexError> {
    select_record_with_successor(records, request, architecture, None)
}

fn select_record_with_successor(
    records: &Value,
    request: &WinbindexResolveRequest,
    architecture: Architecture,
    successor_kb_code: Option<&str>,
) -> Result<WinbindexRecord, WinbindexError> {
    let records = records
        .as_object()
        .ok_or_else(|| WinbindexError::InvalidPayload {
            stage: WinbindexStage::Selection,
            reason: "root must be an object".into(),
        })?;
    let driver_name = normalize_driver_name(&request.driver_name)?;
    let kb_code = normalize_kb_code(&request.kb_code)?;
    let requested_os = request.os_version.trim();
    let target_os = normalize_os_name(requested_os);
    if target_os.is_empty() {
        return Err(WinbindexError::UnsupportedArchitecture {
            value: request.os_version.clone(),
        });
    }

    let mut candidates = BTreeMap::<String, Candidate<'_>>::new();
    for (raw_sha, raw_record) in records {
        let record = raw_record
            .as_object()
            .ok_or_else(|| WinbindexError::InvalidPayload {
                stage: WinbindexStage::Selection,
                reason: format!("record {raw_sha:?} must be an object"),
            })?;
        let versions = object_or_empty(record.get("windowsVersions")).ok_or_else(|| {
            WinbindexError::InvalidPayload {
                stage: WinbindexStage::Selection,
                reason: format!("record {raw_sha:?}.windowsVersions must be an object"),
            }
        })?;

        for (windows_version, raw_updates) in versions {
            let updates =
                raw_updates
                    .as_object()
                    .ok_or_else(|| WinbindexError::InvalidPayload {
                        stage: WinbindexStage::Selection,
                        reason: format!("updates for {windows_version:?} must be an object"),
                    })?;
            for (raw_kb, raw_update) in updates {
                if normalize_kb_code(raw_kb).ok().as_deref() != Some(&kb_code) {
                    continue;
                }
                let update =
                    raw_update
                        .as_object()
                        .ok_or_else(|| WinbindexError::InvalidPayload {
                            stage: WinbindexStage::Selection,
                            reason: format!("update {raw_kb:?} must be an object"),
                        })?;
                for alias in expanded_aliases(windows_version, update)? {
                    let score = alias_score(&target_os, alias);
                    if score == 0 {
                        continue;
                    }
                    let candidate = Candidate {
                        score,
                        windows_version,
                        alias,
                        record,
                        component_member_path: None,
                    };
                    let replace =
                        candidates
                            .get(&raw_sha.to_ascii_lowercase())
                            .is_none_or(|previous| {
                                score > previous.score
                                    || (score == previous.score
                                        && (
                                            windows_version.to_ascii_lowercase(),
                                            alias.to_ascii_lowercase(),
                                        ) < (
                                            previous.windows_version.to_ascii_lowercase(),
                                            previous.alias.to_ascii_lowercase(),
                                        ))
                            });
                    if replace {
                        candidates.insert(raw_sha.to_ascii_lowercase(), candidate);
                    }
                }
            }
        }
    }

    if candidates.is_empty()
        && let Some(successor_kb_code) = successor_kb_code
    {
        let successor_kb_code = normalize_kb_code(successor_kb_code)?;
        if let Some((sha256, candidate)) = inherited_base_candidate(
            records,
            &driver_name,
            &target_os,
            &successor_kb_code,
            architecture,
        ) {
            candidates.insert(sha256, candidate);
        }
    }
    if candidates.is_empty() {
        return Err(WinbindexError::RecordNotFound {
            driver_name,
            kb_code,
            os_version: requested_os.into(),
        });
    }
    let hashes = if let Some(selected) = &request.selected_sha256 {
        let selected = selected.trim().to_ascii_lowercase();
        if !is_sha256(&selected) {
            return Err(WinbindexError::InvalidSha256 {
                value: selected.clone(),
            });
        }
        if !candidates.contains_key(&selected) {
            return Err(WinbindexError::RecordNotFound {
                driver_name,
                kb_code,
                os_version: requested_os.into(),
            });
        }
        vec![selected]
    } else {
        candidates.keys().cloned().collect::<Vec<_>>()
    };
    if hashes.len() != 1 {
        return Err(WinbindexError::AmbiguousRecord {
            driver_name,
            kb_code,
            os_version: requested_os.into(),
            candidate_hashes: hashes,
        });
    }

    let sha256 = hashes.into_iter().next().expect("one hash was checked");
    if !is_sha256(&sha256) {
        return Err(WinbindexError::InvalidPayload {
            stage: WinbindexStage::Selection,
            reason: format!("record key is not a SHA-256 digest: {sha256:?}"),
        });
    }
    let selected = &candidates[&sha256];
    let file_info = object_or_empty(selected.record.get("fileInfo")).ok_or_else(|| {
        WinbindexError::InvalidPayload {
            stage: WinbindexStage::Selection,
            reason: "fileInfo must be an object".into(),
        }
    })?;
    let timestamp = integer(file_info.get("timestamp"), "timestamp")?;
    let virtual_size = integer(file_info.get("virtualSize"), "virtualSize")?;
    let timestamp = u32::try_from(timestamp).map_err(|_| WinbindexError::InvalidPayload {
        stage: WinbindexStage::Selection,
        reason: "fileInfo.timestamp exceeds u32".into(),
    })?;
    if virtual_size == 0 {
        return Err(WinbindexError::InvalidPayload {
            stage: WinbindexStage::Selection,
            reason: "fileInfo.virtualSize must be positive".into(),
        });
    }

    Ok(WinbindexRecord {
        driver_name: driver_name.clone(),
        sha256,
        kb_code,
        requested_os: requested_os.into(),
        matched_windows_version: selected.windows_version.into(),
        matched_alias: selected.alias.into(),
        component_member_path: selected.component_member_path.clone(),
        architecture,
        timestamp,
        virtual_size,
        index_url: index_url(&driver_name, architecture),
        download_url: symbol_url(&driver_name, timestamp, virtual_size),
    })
}

#[derive(Clone, Copy)]
struct SuccessorCandidate<'a> {
    score: usize,
    windows_version: &'a str,
    alias: &'a str,
    update: &'a Map<String, Value>,
}

fn inherited_base_candidate<'a>(
    records: &'a Map<String, Value>,
    driver_name: &str,
    target_os: &str,
    successor_kb_code: &str,
    architecture: Architecture,
) -> Option<(String, Candidate<'a>)> {
    let mut successors = BTreeMap::<String, SuccessorCandidate<'_>>::new();
    for (raw_sha, raw_record) in records {
        let record = raw_record.as_object()?;
        let versions = object_or_empty(record.get("windowsVersions"))?;
        for (windows_version, raw_updates) in versions {
            let updates = raw_updates.as_object()?;
            let update = updates.iter().find_map(|(kb, update)| {
                (normalize_kb_code(kb).ok().as_deref() == Some(successor_kb_code))
                    .then(|| update.as_object())
                    .flatten()
            });
            let Some(update) = update else { continue };
            for alias in expanded_aliases(windows_version, update).ok()? {
                let score = alias_score(target_os, alias);
                if score == 0 {
                    continue;
                }
                let candidate = SuccessorCandidate {
                    score,
                    windows_version,
                    alias,
                    update,
                };
                let key = raw_sha.to_ascii_lowercase();
                if successors.get(&key).is_none_or(|previous| {
                    score > previous.score
                        || (score == previous.score
                            && (windows_version.as_str(), alias)
                                < (previous.windows_version, previous.alias))
                }) {
                    successors.insert(key, candidate);
                }
            }
        }
    }

    if successors.len() != 1 {
        return None;
    }
    let (successor_sha256, successor) =
        successors.iter().next().expect("one successor was checked");
    if alias_score(target_os, successor.windows_version) < 10_000 {
        return None;
    }
    let successor_date = release_date(successor.update)?;
    let component_member_path = component_member_path(successor.update, driver_name, architecture)?;

    let mut bases = BTreeMap::<String, &'a Map<String, Value>>::new();
    let mut prior_hashes = Vec::new();
    for (raw_sha, raw_record) in records {
        let record = raw_record.as_object()?;
        let versions = object_or_empty(record.get("windowsVersions"))?;
        for (windows_version, raw_updates) in versions {
            let updates = raw_updates.as_object()?;
            for (raw_kb, raw_update) in updates {
                let sha256 = raw_sha.to_ascii_lowercase();
                if raw_kb.eq_ignore_ascii_case("BASE") {
                    if alias_score(target_os, windows_version) >= 10_000 {
                        bases.insert(sha256, record);
                    }
                    continue;
                }
                let update = raw_update.as_object()?;
                let applies = expanded_aliases(windows_version, update)
                    .ok()?
                    .iter()
                    .any(|alias| alias_score(target_os, alias) >= 10_000);
                if !applies {
                    continue;
                }
                let date = release_date(update)?;
                if date < successor_date {
                    prior_hashes.push(sha256);
                } else if date == successor_date && &sha256 != successor_sha256 {
                    return None;
                }
            }
        }
    }

    if bases.len() != 1 {
        return None;
    }
    let (base_sha256, base_record) = bases.into_iter().next().expect("one base was checked");
    if prior_hashes.iter().any(|sha256| sha256 != &base_sha256) {
        return None;
    }
    Some((
        base_sha256,
        Candidate {
            score: successor.score,
            windows_version: successor.windows_version,
            alias: successor.alias,
            record: base_record,
            component_member_path: Some(component_member_path),
        },
    ))
}

fn release_date(update: &Map<String, Value>) -> Option<&str> {
    let value = update
        .get("updateInfo")?
        .as_object()?
        .get("releaseDate")?
        .as_str()?;
    let bytes = value.as_bytes();
    (bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit()))
    .then_some(value)
}

fn component_member_path(
    update: &Map<String, Value>,
    driver_name: &str,
    architecture: Architecture,
) -> Option<String> {
    let assemblies = update.get("assemblies")?.as_object()?;
    let expected_architecture: &[&str] = match architecture {
        Architecture::X64 => &["amd64", "x64"],
        Architecture::Arm64 => &["arm64", "aarch64"],
    };
    let mut paths = Vec::new();
    for (name, raw_assembly) in assemblies {
        let assembly = raw_assembly.as_object()?;
        let identity = object_or_empty(assembly.get("assemblyIdentity"))?;
        let matches_architecture = identity
            .get("processorArchitecture")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                expected_architecture
                    .iter()
                    .any(|expected| value.eq_ignore_ascii_case(expected))
            });
        if !matches_architecture {
            continue;
        }
        let attributes = assembly.get("attributes")?.as_array()?;
        let contains_driver = attributes.iter().any(|raw_attribute| {
            raw_attribute.as_object().is_some_and(|attribute| {
                ["name", "sourceName"].iter().any(|field| {
                    attribute
                        .get(*field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.eq_ignore_ascii_case(driver_name))
                })
            })
        });
        if contains_driver {
            paths.push(format!(r"{name}\f\{driver_name}"));
        }
    }
    paths.sort();
    paths.dedup();
    match paths.as_slice() {
        [path] => Some(path.clone()),
        _ => None,
    }
}

pub(crate) fn normalize_driver_name(value: &str) -> Result<String, WinbindexError> {
    let name = value.trim().to_ascii_lowercase();
    let bytes = name.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && (bytes.ends_with(b".sys") || name == "ntosknl.exe")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    valid
        .then_some(name)
        .ok_or_else(|| WinbindexError::InvalidDriverName {
            value: value.into(),
        })
}

pub(crate) fn normalize_kb_code(value: &str) -> Result<String, WinbindexError> {
    let normalized = value.trim().to_ascii_uppercase().replace(' ', "");
    let digits = normalized.strip_prefix("KB").unwrap_or(&normalized);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(format!("KB{digits}"))
    } else {
        Err(WinbindexError::InvalidKbCode {
            value: value.into(),
        })
    }
}

pub(crate) fn architecture_from_os(value: &str) -> Result<Architecture, WinbindexError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("arm64") || normalized.contains("aarch64") {
        return Ok(Architecture::Arm64);
    }
    if ARCH_X86.is_match(&normalized) {
        return Err(WinbindexError::UnsupportedArchitecture {
            value: format!("32-bit target: {value}"),
        });
    }
    if ARCH_X64.is_match(&normalized) || SERVER_OS.is_match(&normalized) {
        return Ok(Architecture::X64);
    }
    Err(WinbindexError::UnsupportedArchitecture {
        value: value.into(),
    })
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn index_url(driver_name: &str, architecture: Architecture) -> String {
    let root = match architecture {
        Architecture::X64 => X64_INDEX_ROOT,
        Architecture::Arm64 => ARM64_INDEX_ROOT,
    };
    let mut url = Url::parse(root).expect("static Winbindex URL is valid");
    url.path_segments_mut()
        .expect("static Winbindex URL supports path segments")
        .push(&format!("{driver_name}.json.gz"));
    url.into()
}

fn symbol_url(driver_name: &str, timestamp: u32, virtual_size: u64) -> String {
    let file_id = format!("{timestamp:08X}{virtual_size:x}");
    let mut url = Url::parse(SYMBOL_ROOT).expect("static Symbol Server URL is valid");
    url.path_segments_mut()
        .expect("static Symbol Server URL supports path segments")
        .push(driver_name)
        .push(&file_id)
        .push(driver_name);
    url.into()
}

fn normalize_os_name(value: &str) -> String {
    let lowered = value
        .to_ascii_lowercase()
        .replace("microsoft server operating system", "server");
    let no_arch = ARCH_SUFFIX.replace_all(&lowered, " ");
    let no_noise = OS_NOISE.replace_all(&no_arch, " ");
    NON_ALNUM.replace_all(&no_noise, "").into_owned()
}

fn expanded_aliases<'a>(
    windows_version: &'a str,
    update: &'a Map<String, Value>,
) -> Result<Vec<&'a str>, WinbindexError> {
    let update_info = object_or_empty(update.get("updateInfo")).ok_or_else(|| {
        WinbindexError::InvalidPayload {
            stage: WinbindexStage::Selection,
            reason: "updateInfo must be an object".into(),
        }
    })?;
    let others = match update_info.get("otherWindowsVersions") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(values)) => values.as_slice(),
        Some(_) => {
            return Err(WinbindexError::InvalidPayload {
                stage: WinbindexStage::Selection,
                reason: "otherWindowsVersions must be an array".into(),
            });
        }
    };

    let mut aliases = vec![windows_version];
    for alias in others {
        if let Some(alias) = alias.as_str().filter(|alias| !alias.is_empty()) {
            aliases.push(alias);
        }
    }
    Ok(aliases)
}

fn alias_score(target_os: &str, alias: &str) -> usize {
    let expanded;
    let alias = if let Some((product, release)) = alias.split_once('-') {
        expanded = format!("Windows {product} {release}");
        &expanded
    } else if RELEASE_ONLY.is_match(alias) {
        expanded = format!("Windows 10 {alias}");
        &expanded
    } else {
        alias
    };
    let normalized = normalize_os_name(alias);
    if normalized.is_empty() {
        return 0;
    }
    if target_os == normalized {
        return 10_000 + normalized.len();
    }
    let shorter = target_os.len().min(normalized.len());
    if shorter >= 4
        && (target_os.starts_with(&normalized)
            || normalized.starts_with(target_os)
            || target_os.ends_with(&normalized)
            || normalized.ends_with(target_os))
    {
        1_000 + shorter
    } else {
        0
    }
}

fn object_or_empty(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value {
        None | Some(Value::Null) => Some(empty_object()),
        Some(Value::Object(object)) => Some(object),
        Some(_) => None,
    }
}

fn empty_object() -> &'static Map<String, Value> {
    static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);
    &EMPTY
}

fn integer(value: Option<&Value>, field: &str) -> Result<u64, WinbindexError> {
    let parsed = match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .map_or_else(
                || text.parse().ok(),
                |hex| u64::from_str_radix(hex, 16).ok(),
            ),
        _ => None,
    };
    parsed.ok_or_else(|| WinbindexError::InvalidPayload {
        stage: WinbindexStage::Selection,
        reason: format!("fileInfo.{field} must be a non-negative integer"),
    })
}

fn validate_destination(destination: &Path) -> Result<(), WinbindexError> {
    if destination.as_os_str().is_empty() || destination.is_dir() || destination.is_symlink() {
        return Err(WinbindexError::InvalidPayload {
            stage: WinbindexStage::Publish,
            reason: "destination must be an explicit, non-symlink file path".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        architecture_from_os, normalize_driver_name, select_record, select_record_with_successor,
    };
    use crate::model::{acquisition::Architecture, winbindex::WinbindexResolveRequest};

    #[test]
    fn selects_one_exact_record() {
        let sha = "a".repeat(64);
        let records = json!({
            sha.clone(): {
                "fileInfo": {"timestamp": 1, "virtualSize": 4096},
                "windowsVersions": {
                    "11-24H2": {
                        "KB5000001": {"updateInfo": {"otherWindowsVersions": []}}
                    }
                }
            }
        });
        let request = WinbindexResolveRequest {
            driver_name: "example.sys".into(),
            kb_code: "KB5000001".into(),
            os_version: "Windows 11 Version 24H2 for x64-based Systems".into(),
            architecture: Some(Architecture::X64),
            selected_sha256: None,
        };

        let selected = select_record(&records, &request, Architecture::X64).unwrap();
        assert_eq!(selected.sha256, sha);
        assert_eq!(selected.matched_alias, "11-24H2");
    }

    #[test]
    fn inherits_the_base_only_when_the_successor_is_the_first_file_change() {
        let base_sha = "a".repeat(64);
        let successor_sha = "b".repeat(64);
        let assembly = "amd64_microsoft-windows-kernelstreaming_31bf3856ad364e35_10.0.22621.1848_none_373e89dd11989298";
        let records = json!({
            base_sha.clone(): {
                "fileInfo": {"timestamp": 1, "virtualSize": 4096},
                "windowsVersions": {
                    "11-22H2": {"BASE": {}}
                }
            },
            successor_sha: {
                "fileInfo": {"timestamp": 2, "virtualSize": 4096},
                "windowsVersions": {
                    "11-22H2": {
                        "KB5027231": {
                            "updateInfo": {"releaseDate": "2023-06-13"},
                            "assemblies": {
                                assembly: {
                                    "assemblyIdentity": {"processorArchitecture": "amd64"},
                                    "attributes": [{"name": "mskssrv.sys"}]
                                }
                            }
                        }
                    }
                }
            }
        });
        let request = WinbindexResolveRequest {
            driver_name: "mskssrv.sys".into(),
            kb_code: "KB5026372".into(),
            os_version: "Windows 11 Version 22H2 for x64-based Systems".into(),
            architecture: Some(Architecture::X64),
            selected_sha256: None,
        };

        let selected =
            select_record_with_successor(&records, &request, Architecture::X64, Some("KB5027231"))
                .unwrap();

        assert_eq!(selected.sha256, base_sha);
        assert_eq!(selected.kb_code, "KB5026372");
        assert_eq!(
            selected.component_member_path.as_deref(),
            Some(
                "amd64_microsoft-windows-kernelstreaming_31bf3856ad364e35_10.0.22621.1848_none_373e89dd11989298\\f\\mskssrv.sys"
            )
        );
    }

    #[test]
    fn does_not_inherit_the_base_across_a_same_day_file_change() {
        let records = json!({
            "a".repeat(64): {
                "fileInfo": {"timestamp": 1, "virtualSize": 4096},
                "windowsVersions": {"11-22H2": {"BASE": {}}}
            },
            "b".repeat(64): {
                "fileInfo": {"timestamp": 2, "virtualSize": 4096},
                "windowsVersions": {
                    "10-22H2": {
                        "KB5026000": {"updateInfo": {
                            "releaseDate": "2023-06-13",
                            "otherWindowsVersions": ["11-22H2"]
                        }}
                    }
                }
            },
            "c".repeat(64): {
                "fileInfo": {"timestamp": 3, "virtualSize": 4096},
                "windowsVersions": {
                    "11-22H2": {
                        "KB5027231": {
                            "updateInfo": {"releaseDate": "2023-06-13"},
                            "assemblies": {
                                "amd64_component_31bf3856ad364e35_10.0.22621.1848_none_hash": {
                                    "assemblyIdentity": {"processorArchitecture": "amd64"},
                                    "attributes": [{"name": "mskssrv.sys"}]
                                }
                            }
                        }
                    }
                }
            }
        });
        let request = WinbindexResolveRequest {
            driver_name: "mskssrv.sys".into(),
            kb_code: "KB5026372".into(),
            os_version: "Windows 11 Version 22H2 for x64-based Systems".into(),
            architecture: Some(Architecture::X64),
            selected_sha256: None,
        };

        assert!(
            select_record_with_successor(&records, &request, Architecture::X64, Some("KB5027231"))
                .is_err()
        );
    }

    #[test]
    fn does_not_treat_a_32_bit_server_as_x64() {
        assert!(
            architecture_from_os("Windows Server 2008 for 32-bit Systems Service Pack 2").is_err()
        );
    }

    #[test]
    fn allows_ntosknl_exe_as_the_only_exe_exception() {
        assert_eq!(normalize_driver_name("NtoSknl.EXE").unwrap(), "ntosknl.exe");
        assert!(normalize_driver_name("other.exe").is_err());
    }
}
