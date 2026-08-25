use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
    time::Duration,
};

use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use crate::{
    errors::{UupError, UupStage},
    model::{
        acquisition::{Architecture, HashAlgorithm},
        uup::{ResolvedBase, UupBaseProvenance, UupResolveRequest},
    },
    port::UupPort,
};

use super::{
    default_cache_directory, digest_file, format_bytes, hex, report_download_progress,
    transfer_buffer,
    winbindex_adapter::{is_sha256, normalize_driver_name},
};

const UUP_LIST_URL: &str = "https://api.uupdump.net/listid.php";
const UUP_GET_URL: &str = "https://api.uupdump.net/get.php";

static COMPONENT_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?P<prefix>(?:amd64|arm64)_.+?_[0-9a-f]{16})_(?:10\.0\.)?(?P<build>\d+)\.\d+_none_[^\\]+\\f\\(?P<filename>[^\\]+)$",
    )
    .expect("valid component member regex")
});

#[derive(Debug, Clone)]
pub struct UupAdapter {
    client: Client,
    cache_directory: PathBuf,
    seven_zip: Option<PathBuf>,
    metadata_timeout: Duration,
    download_timeout: Duration,
    max_media_bytes: u64,
    show_progress: bool,
}

impl Default for UupAdapter {
    fn default() -> Self {
        let cache_directory = env::var_os("ONEDAY_CATALOG_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(default_cache_directory);
        Self {
            client: Client::new(),
            cache_directory,
            seven_zip: env::var_os("ONEDAY_7ZIP").map(PathBuf::from),
            metadata_timeout: Duration::from_secs(120),
            download_timeout: Duration::from_secs(1800),
            max_media_bytes: 8 * 1024 * 1024 * 1024,
            show_progress: false,
        }
    }
}

impl UupAdapter {
    pub fn with_cache_directory(cache_directory: impl Into<PathBuf>) -> Self {
        Self {
            cache_directory: cache_directory.into(),
            ..Self::default()
        }
    }

    pub(crate) fn with_progress(mut self) -> Self {
        self.show_progress = true;
        self
    }

    fn resolve_uncached(
        &self,
        request: &UupResolveRequest,
        spec: &ComponentSpec,
        reference_path: PathBuf,
    ) -> Result<ResolvedBase, UupError> {
        let build = self.resolve_build(&spec.build, &request.os_version, request.architecture)?;
        let media = self.resolve_media(&build, &request.os_version)?;
        let media_path = self.download_media(&media)?;
        let bytes = self.extract_component(
            &media_path,
            &request.driver_name,
            &spec.prefix,
            &spec.baseline,
        )?;
        let base_sha256 = hex(&Sha256::digest(&bytes));
        let base_path = self
            .cache_directory
            .join("bases")
            .join(format!("{base_sha256}.sys"));
        publish_bytes(&bytes, &base_path)?;

        Ok(ResolvedBase {
            path: base_path,
            sha256: base_sha256.clone(),
            provenance: UupBaseProvenance {
                required_baseline: spec.baseline.clone(),
                metadata_source: "https://api.uupdump.net".into(),
                media_source: "microsoft_uup_cdn".into(),
                update_id: build.uuid,
                update_title: build.title,
                media_name: media.name,
                media_sha1: media.sha1,
                base_sha256,
                cache_reused: false,
            },
            reference_path: Some(reference_path),
        })
    }

    fn resolve_build(
        &self,
        build_number: &str,
        os_version: &str,
        architecture: Architecture,
    ) -> Result<UupBuild, UupError> {
        let payload = self.get_json(
            UUP_LIST_URL,
            &[("search", build_number), ("sortByDate", "1")],
            UupStage::BuildList,
        )?;
        let builds = response_object(&payload, UupStage::BuildList)?
            .get("builds")
            .and_then(Value::as_object)
            .ok_or_else(|| UupError::InvalidPayload {
                stage: UupStage::BuildList,
                reason: "response.builds must be an object".into(),
            })?;
        let expected_arch = match architecture {
            Architecture::X64 => "amd64",
            Architecture::Arm64 => "arm64",
        };
        let os = os_version.to_ascii_lowercase();
        let family = if os.contains("server") {
            "windows server"
        } else if os.contains("windows 10") {
            "windows 10"
        } else {
            "windows 11"
        };

        let candidates = builds
            .values()
            .filter_map(Value::as_object)
            .filter(|item| text(item, "build").is_some_and(|value| value == build_number))
            .filter(|item| {
                text(item, "arch").is_some_and(|value| value.eq_ignore_ascii_case(expected_arch))
            })
            .filter(|item| {
                text(item, "title").is_some_and(|value| value.to_ascii_lowercase().contains(family))
            })
            .collect::<Vec<_>>();
        let candidates = prefer_non_insider_builds(candidates);
        if candidates.len() != 1 {
            return Err(UupError::BuildSelection {
                build: build_number.into(),
                architecture,
                candidate_count: candidates.len(),
            });
        }
        let selected = candidates[0];
        Ok(UupBuild {
            uuid: required_text(selected, "uuid", UupStage::BuildList)?,
            title: required_text(selected, "title", UupStage::BuildList)?,
        })
    }

    fn resolve_media(&self, build: &UupBuild, os_version: &str) -> Result<UupMedia, UupError> {
        let mut query = vec![("id", build.uuid.as_str()), ("noLinks", "0")];
        if !os_version.to_ascii_lowercase().contains("server") {
            query.extend([("lang", "en-us"), ("edition", "core")]);
        }
        let payload = self.get_json(UUP_GET_URL, &query, UupStage::MediaList)?;
        let files = response_object(&payload, UupStage::MediaList)?
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| UupError::InvalidPayload {
                stage: UupStage::MediaList,
                reason: "response.files must be an object".into(),
            })?;

        let server = os_version.to_ascii_lowercase().contains("server");
        let names = files
            .keys()
            .filter(|name| {
                if server {
                    let lower = name.to_ascii_lowercase();
                    lower.ends_with("_en-us.esd") && lower.contains("server")
                } else {
                    name.as_str() == "core_en-us.esd"
                }
            })
            .collect::<Vec<_>>();
        if names.len() != 1 {
            return Err(UupError::MediaSelection {
                candidate_count: names.len(),
            });
        }
        let name = names[0];
        let item = files[name]
            .as_object()
            .ok_or_else(|| UupError::InvalidPayload {
                stage: UupStage::MediaList,
                reason: format!("media record {name:?} must be an object"),
            })?;
        let sha1 = required_text(item, "sha1", UupStage::MediaList)?.to_ascii_lowercase();
        if sha1.len() != 40 || !sha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(UupError::InvalidPayload {
                stage: UupStage::MediaList,
                reason: "media sha1 must be a 40-character hexadecimal digest".into(),
            });
        }
        let size = value_u64(item.get("size")).ok_or_else(|| UupError::InvalidPayload {
            stage: UupStage::MediaList,
            reason: "media size must be a positive integer".into(),
        })?;
        if size == 0 {
            return Err(UupError::InvalidPayload {
                stage: UupStage::MediaList,
                reason: "media size must be positive".into(),
            });
        }
        let url = required_text(item, "url", UupStage::MediaList)?;
        validate_uup_url(&url)?;
        Ok(UupMedia {
            name: name.clone(),
            sha1,
            size,
            url,
        })
    }

    fn download_media(&self, media: &UupMedia) -> Result<PathBuf, UupError> {
        if media.size > self.max_media_bytes {
            return Err(UupError::MediaTooLarge {
                size_bytes: media.size,
                max_bytes: self.max_media_bytes,
            });
        }
        let destination = self
            .cache_directory
            .join("media")
            .join(format!("{}.esd", media.sha1));
        if self.show_progress {
            eprintln!("uup media: {}", media.name);
            eprintln!(
                "uup size: {} ({} bytes)",
                format_bytes(media.size),
                media.size
            );
            eprintln!("uup cache: {}", destination.display());
        }
        if destination.is_symlink() {
            return Err(UupError::CacheIntegrity {
                path: destination,
                reason: "cache entry must not be a symbolic link".into(),
            });
        }
        if destination.is_file() {
            verify_media(&destination, media)?;
            if self.show_progress {
                eprintln!("uup cache status: reused");
            }
            return Ok(destination);
        }
        let parent = destination
            .parent()
            .expect("media destination has a parent");
        fs::create_dir_all(parent).map_err(|source| UupError::Publish {
            path: destination.clone(),
            source,
        })?;

        let mut response = self
            .client
            .get(&media.url)
            .timeout(self.download_timeout)
            .send()
            .map_err(|source| UupError::Network {
                url: media.url.clone(),
                source: Box::new(source),
            })?;
        if !response.status().is_success() {
            return Err(UupError::Http {
                url: media.url.clone(),
                status_code: response.status().as_u16(),
            });
        }

        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| UupError::Publish {
            path: destination.clone(),
            source,
        })?;
        let mut total = 0_u64;
        let mut next_percent = 0_u64;
        let mut buffer = transfer_buffer();
        if self.show_progress {
            report_download_progress("uup download", 0, media.size, &mut next_percent);
        }
        loop {
            let count = response
                .read(&mut buffer)
                .map_err(|source| UupError::Network {
                    url: media.url.clone(),
                    source: Box::new(source),
                })?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > self.max_media_bytes {
                return Err(UupError::MediaTooLarge {
                    size_bytes: total,
                    max_bytes: self.max_media_bytes,
                });
            }
            temporary
                .write_all(&buffer[..count])
                .map_err(|source| UupError::Publish {
                    path: destination.clone(),
                    source,
                })?;
            if self.show_progress {
                report_download_progress("uup download", total, media.size, &mut next_percent);
            }
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| UupError::Publish {
                path: destination.clone(),
                source,
            })?;
        verify_media(temporary.path(), media)?;
        let reused = match fs::hard_link(temporary.path(), &destination) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_media(&destination, media)?;
                true
            }
            Err(source) => {
                return Err(UupError::Publish {
                    path: destination,
                    source,
                });
            }
        };
        if self.show_progress {
            eprintln!(
                "uup cache status: {}",
                if reused { "reused" } else { "saved" }
            );
        }
        Ok(destination)
    }

    fn extract_component(
        &self,
        media_path: &Path,
        driver_name: &str,
        component_prefix: &str,
        baseline: &str,
    ) -> Result<Vec<u8>, UupError> {
        let seven_zip = self
            .seven_zip
            .clone()
            .filter(|path| path.is_file())
            .or_else(|| find_command(&["7z", "7zz"]))
            .ok_or_else(|| UupError::ToolUnavailable { tool: "7z".into() })?;
        let listed = run_command(
            &seven_zip,
            &[
                "l",
                "-ba",
                "-r",
                &media_path.to_string_lossy(),
                &format!("*{driver_name}"),
            ],
        )?;
        let pattern = Regex::new(&format!(
            r"(?i)(?P<path>\d+/Windows/WinSxS/{}_{}_none_[^/]+/{})$",
            regex::escape(component_prefix),
            regex::escape(baseline),
            regex::escape(driver_name),
        ))
        .expect("escaped component regex is valid");
        let paths = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .filter_map(|line| {
                pattern
                    .captures(&line.replace('\\', "/"))
                    .and_then(|captures| captures.name("path"))
                    .map(|value| value.as_str().to_owned())
            })
            .collect::<Vec<_>>();
        let Some(path) = paths.iter().min() else {
            return Err(UupError::InvalidPayload {
                stage: UupStage::ComponentExtraction,
                reason: format!("component {driver_name} for {baseline} was not found"),
            });
        };
        let extracted = run_command(
            &seven_zip,
            &["e", "-so", &media_path.to_string_lossy(), path],
        )?;
        if extracted.stdout.is_empty() {
            return Err(UupError::InvalidPayload {
                stage: UupStage::ComponentExtraction,
                reason: "7z returned an empty component".into(),
            });
        }
        Ok(extracted.stdout)
    }

    fn get_json(
        &self,
        url: &str,
        query: &[(&str, &str)],
        stage: UupStage,
    ) -> Result<Value, UupError> {
        let response = self
            .client
            .get(url)
            .query(query)
            .timeout(self.metadata_timeout)
            .send()
            .map_err(|source| UupError::Network {
                url: url.into(),
                source: Box::new(source),
            })?;
        if !response.status().is_success() {
            return Err(UupError::Http {
                url: url.into(),
                status_code: response.status().as_u16(),
            });
        }
        response.json().map_err(|error| UupError::InvalidPayload {
            stage,
            reason: format!("malformed JSON: {error}"),
        })
    }
}

impl UupPort for UupAdapter {
    fn resolve(&self, request: &UupResolveRequest) -> Result<ResolvedBase, UupError> {
        let driver_name = normalize_driver_name(&request.driver_name).map_err(|_| {
            UupError::InvalidComponent {
                member_path: request.member_path.clone(),
            }
        })?;
        let request = UupResolveRequest {
            driver_name,
            os_version: request.os_version.trim().to_owned(),
            architecture: request.architecture,
            member_path: request.member_path.clone(),
        };
        let spec = parse_component(
            &request.member_path,
            &request.driver_name,
            request.architecture,
        )?;
        let cache_key = hex(&Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                request.architecture, spec.baseline, spec.prefix, request.driver_name
            )
            .as_bytes(),
        ));
        let reference_path = self
            .cache_directory
            .join("base-refs")
            .join(format!("{cache_key}.json"));
        if let Some(cached) = load_reference(&reference_path, &self.cache_directory)? {
            if self.show_progress {
                eprintln!("uup base cache: reused {}", cached.path.display());
            }
            return Ok(cached);
        }
        self.resolve_uncached(&request, &spec, reference_path)
    }

    fn confirm(&self, candidate: &ResolvedBase) -> Result<(), UupError> {
        let Some(reference_path) = &candidate.reference_path else {
            return Ok(());
        };
        let reference = BaseReference {
            base_sha256: candidate.sha256.clone(),
            provenance: UupBaseProvenance {
                cache_reused: false,
                ..candidate.provenance.clone()
            },
        };
        let bytes = serde_json::to_vec(&reference).map_err(|error| UupError::CacheIntegrity {
            path: reference_path.clone(),
            reason: error.to_string(),
        })?;
        publish_bytes(&bytes, reference_path)
    }

    fn acquire_exact(
        &self,
        request: &UupResolveRequest,
        expected_sha256: &str,
        destination: &Path,
    ) -> Result<(ResolvedBase, bool), UupError> {
        let expected_sha256 = expected_sha256.trim().to_ascii_lowercase();
        if !is_sha256(&expected_sha256) {
            return Err(UupError::InvalidPayload {
                stage: UupStage::Cache,
                reason: "expected SHA-256 is invalid".into(),
            });
        }

        let resolved = self.resolve(request)?;
        if resolved.sha256 != expected_sha256 {
            return Err(UupError::HashMismatch {
                path: resolved.path.clone(),
                algorithm: HashAlgorithm::Sha256,
                expected: expected_sha256,
                actual: resolved.sha256.clone(),
            });
        }
        let bytes = fs::read(&resolved.path).map_err(|source| UupError::Publish {
            path: resolved.path.clone(),
            source,
        })?;
        let actual = hex(&Sha256::digest(&bytes));
        if actual != expected_sha256 {
            return Err(UupError::HashMismatch {
                path: resolved.path.clone(),
                algorithm: HashAlgorithm::Sha256,
                expected: expected_sha256,
                actual,
            });
        }
        self.confirm(&resolved)?;
        let reused = destination.is_file();
        publish_bytes(&bytes, destination)?;
        Ok((resolved, reused))
    }
}

#[derive(Debug)]
struct ComponentSpec {
    prefix: String,
    build: String,
    baseline: String,
}

#[derive(Debug)]
struct UupBuild {
    uuid: String,
    title: String,
}

#[derive(Debug)]
struct UupMedia {
    name: String,
    sha1: String,
    size: u64,
    url: String,
}

fn prefer_non_insider_builds(candidates: Vec<&Map<String, Value>>) -> Vec<&Map<String, Value>> {
    let non_insider = candidates
        .iter()
        .copied()
        .filter(|item| {
            text(item, "title")
                .is_some_and(|title| !title.to_ascii_lowercase().contains("insider preview"))
        })
        .collect::<Vec<_>>();
    if non_insider.is_empty() {
        candidates
    } else {
        non_insider
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BaseReference {
    base_sha256: String,
    provenance: UupBaseProvenance,
}

fn parse_component(
    member_path: &str,
    driver_name: &str,
    architecture: Architecture,
) -> Result<ComponentSpec, UupError> {
    let captures =
        COMPONENT_MEMBER
            .captures(member_path)
            .ok_or_else(|| UupError::InvalidComponent {
                member_path: member_path.into(),
            })?;
    let prefix = captures["prefix"].to_owned();
    let expected_prefix = match architecture {
        Architecture::X64 => "amd64_",
        Architecture::Arm64 => "arm64_",
    };
    if !prefix.to_ascii_lowercase().starts_with(expected_prefix)
        || !captures["filename"].eq_ignore_ascii_case(driver_name)
    {
        return Err(UupError::InvalidComponent {
            member_path: member_path.into(),
        });
    }
    let build = captures["build"].to_owned();
    Ok(ComponentSpec {
        prefix,
        baseline: format!("10.0.{build}.1"),
        build: format!("{build}.1"),
    })
}

fn response_object(payload: &Value, stage: UupStage) -> Result<&Map<String, Value>, UupError> {
    payload
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| UupError::InvalidPayload {
            stage,
            reason: "response must be an object".into(),
        })
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

fn required_text(
    object: &Map<String, Value>,
    field: &str,
    stage: UupStage,
) -> Result<String, UupError> {
    text(object, field)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| UupError::InvalidPayload {
            stage,
            reason: format!("{field} must be a non-empty string"),
        })
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn validate_uup_url(value: &str) -> Result<(), UupError> {
    let url = Url::parse(value).map_err(|_| UupError::InvalidPayload {
        stage: UupStage::MediaList,
        reason: "media URL is invalid".into(),
    })?;
    let trusted = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| {
            let host = host.to_ascii_lowercase();
            host == "delivery.mp.microsoft.com" || host.ends_with(".delivery.mp.microsoft.com")
        });
    if trusted {
        Ok(())
    } else {
        Err(UupError::InvalidPayload {
            stage: UupStage::MediaList,
            reason: "media URL must point to the Microsoft UUP CDN".into(),
        })
    }
}

fn verify_media(path: &Path, media: &UupMedia) -> Result<(), UupError> {
    let size = path
        .metadata()
        .map_err(|source| UupError::Publish {
            path: path.to_owned(),
            source,
        })?
        .len();
    if size != media.size {
        return Err(UupError::CacheIntegrity {
            path: path.to_owned(),
            reason: format!("expected {} bytes, found {size}", media.size),
        });
    }
    let actual = digest_file::<Sha1>(path).map_err(|source| UupError::Publish {
        path: path.to_owned(),
        source,
    })?;
    if actual != media.sha1 {
        return Err(UupError::HashMismatch {
            path: path.to_owned(),
            algorithm: HashAlgorithm::Sha1,
            expected: media.sha1.clone(),
            actual,
        });
    }
    Ok(())
}

fn load_reference(path: &Path, cache: &Path) -> Result<Option<ResolvedBase>, UupError> {
    if !path.exists() {
        return Ok(None);
    }
    if path.is_symlink() || !path.is_file() {
        return Err(UupError::CacheIntegrity {
            path: path.to_owned(),
            reason: "reference must be a regular file".into(),
        });
    }
    let bytes = fs::read(path).map_err(|source| UupError::Publish {
        path: path.to_owned(),
        source,
    })?;
    let mut reference: BaseReference =
        serde_json::from_slice(&bytes).map_err(|error| UupError::CacheIntegrity {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
    if !is_sha256(&reference.base_sha256) {
        return Err(UupError::CacheIntegrity {
            path: path.to_owned(),
            reason: "base_sha256 is invalid".into(),
        });
    }
    let base_path = cache
        .join("bases")
        .join(format!("{}.sys", reference.base_sha256));
    if base_path.is_symlink() || !base_path.is_file() {
        return Err(UupError::CacheIntegrity {
            path: base_path,
            reason: "base cache entry must be a regular file".into(),
        });
    }
    let actual = digest_file::<Sha256>(&base_path).map_err(|source| UupError::Publish {
        path: base_path.clone(),
        source,
    })?;
    if actual != reference.base_sha256 {
        return Err(UupError::HashMismatch {
            path: base_path,
            algorithm: HashAlgorithm::Sha256,
            expected: reference.base_sha256,
            actual,
        });
    }
    reference.provenance.cache_reused = true;
    Ok(Some(ResolvedBase {
        path: base_path,
        sha256: actual,
        provenance: reference.provenance,
        reference_path: None,
    }))
}

fn publish_bytes(bytes: &[u8], destination: &Path) -> Result<(), UupError> {
    let parent = destination
        .parent()
        .expect("cache destination has a parent");
    fs::create_dir_all(parent).map_err(|source| UupError::Publish {
        path: destination.to_owned(),
        source,
    })?;
    let expected = hex(&Sha256::digest(bytes));
    if destination.is_symlink() {
        return Err(UupError::CacheIntegrity {
            path: destination.to_owned(),
            reason: "destination must not be a symbolic link".into(),
        });
    }
    if destination.is_file() {
        let actual = digest_file::<Sha256>(destination).map_err(|source| UupError::Publish {
            path: destination.to_owned(),
            source,
        })?;
        return if actual == expected {
            Ok(())
        } else {
            Err(UupError::CacheIntegrity {
                path: destination.to_owned(),
                reason: "existing file has different content".into(),
            })
        };
    }

    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| UupError::Publish {
        path: destination.to_owned(),
        source,
    })?;
    temporary
        .write_all(bytes)
        .map_err(|source| UupError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| UupError::Publish {
            path: destination.to_owned(),
            source,
        })?;
    match fs::hard_link(temporary.path(), destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual =
                digest_file::<Sha256>(destination).map_err(|source| UupError::Publish {
                    path: destination.to_owned(),
                    source,
                })?;
            if actual == expected {
                Ok(())
            } else {
                Err(UupError::CacheIntegrity {
                    path: destination.to_owned(),
                    reason: "concurrently published file has different content".into(),
                })
            }
        }
        Err(source) => Err(UupError::Publish {
            path: destination.to_owned(),
            source,
        }),
    }
}

fn find_command(names: &[&str]) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
            .find(|candidate| candidate.is_file())
    })
}

fn run_command(executable: &Path, arguments: &[&str]) -> Result<std::process::Output, UupError> {
    let output = Command::new(executable)
        .args(arguments)
        .output()
        .map_err(|_| UupError::ToolUnavailable {
            tool: executable.display().to_string(),
        })?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(UupError::ToolFailed {
            tool: executable.display().to_string(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .chars()
                .rev()
                .take(1000)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{
        UupAdapter, hex, load_reference, parse_component, prefer_non_insider_builds, text,
    };
    use crate::model::acquisition::Architecture;
    use crate::port::UupPort;

    #[test]
    fn parses_matching_component_member() {
        let member = concat!(
            "amd64_microsoft-windows-example_31bf3856ad364e35_",
            "10.0.26100.1_none_deadbeef\\f\\example.sys"
        );
        let parsed = parse_component(member, "example.sys", Architecture::X64).unwrap();
        assert_eq!(parsed.build, "26100.1");
        assert_eq!(parsed.baseline, "10.0.26100.1");
    }

    #[test]
    fn prefers_the_retail_uup_build_but_keeps_a_lone_insider_rtm() {
        let builds = json!([
            {
                "title": "Windows 11, version 22H2 (22621.1)",
                "uuid": "retail"
            },
            {
                "title": "Windows 11, version 22H2 Insider Preview 10.0.22621.1",
                "uuid": "insider-one"
            },
            {
                "title": "Windows 11 Insider Preview 22621.1",
                "uuid": "insider-two"
            }
        ]);
        let candidates = builds
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_object().unwrap())
            .collect();
        let selected = prefer_non_insider_builds(candidates);

        assert_eq!(selected.len(), 1);
        assert_eq!(text(selected[0], "uuid"), Some("retail"));

        let legacy = json!({
            "title": "Windows 11 Insider Preview 10.0.22000.1",
            "uuid": "legacy-insider"
        });
        let selected = prefer_non_insider_builds(vec![legacy.as_object().unwrap()]);
        assert_eq!(text(selected[0], "uuid"), Some("legacy-insider"));

        let retail_one = json!({"title": "Windows 11 (22621.1)", "uuid": "retail-one"});
        let retail_two = json!({"title": "Windows 11 (22621.1)", "uuid": "retail-two"});
        let selected = prefer_non_insider_builds(vec![
            retail_one.as_object().unwrap(),
            retail_two.as_object().unwrap(),
        ]);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn loads_reference_written_with_legacy_uup_field_names() {
        let cache = tempfile::tempdir().unwrap();
        let base = b"cached base driver";
        let base_sha256 = hex(&Sha256::digest(base));
        let base_path = cache
            .path()
            .join("bases")
            .join(format!("{base_sha256}.sys"));
        fs::create_dir_all(base_path.parent().unwrap()).unwrap();
        fs::write(&base_path, base).unwrap();

        let reference_path = cache.path().join("base-refs/reference.json");
        fs::create_dir_all(reference_path.parent().unwrap()).unwrap();
        let reference = json!({
            "base_sha256": base_sha256,
            "provenance": {
                "required_baseline": "10.0.22000.1",
                "metadata_source": "https://api.uupdump.net",
                "media_source": "microsoft_uup_cdn",
                "uup_update_id": "legacy-update-id",
                "uup_title": "legacy title",
                "uup_media": "core_en-us.esd",
                "uup_media_sha1": "a793ab6b8386711ea17e8abf7ce2a33c99caeae9",
                "base_sha256": base_sha256
            }
        });
        let reference_bytes = serde_json::to_vec(&reference).unwrap();
        fs::write(&reference_path, &reference_bytes).unwrap();

        let resolved = load_reference(&reference_path, cache.path())
            .unwrap()
            .expect("legacy reference should be reusable");

        assert_eq!(resolved.provenance.update_id, "legacy-update-id");
        assert_eq!(resolved.provenance.update_title, "legacy title");
        assert_eq!(resolved.provenance.media_name, "core_en-us.esd");
        assert!(resolved.provenance.cache_reused);
        assert_eq!(resolved.reference_path, None);

        UupAdapter::with_cache_directory(cache.path())
            .confirm(&resolved)
            .unwrap();
        assert_eq!(fs::read(reference_path).unwrap(), reference_bytes);
    }
}
