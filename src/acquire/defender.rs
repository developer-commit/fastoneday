//! Microsoft Defender engine: the security intelligence package that carries
//! a given engine is located through Microsoft's own release notes and read
//! from the Defender CDN with two range requests: the cabinet header, then
//! the bytes that hold the chosen file (the compressed folder for the engine,
//! or exactly the file's blocks for the stored signature databases).

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use super::{Engine, materialize::Materialized, progress::Progress};
use crate::{
    domain::{Arch, BinaryName, Materialization, PatchPair},
    error::{Error, Result},
    formats::{
        authenticode,
        cab::{Cabinet, FileEntry},
        component::PayloadKind,
        pe,
    },
    io::{Cancel, MemorySource, NullMeter, SliceSource, SparseSource},
    packages::{Locator, PayloadEntry},
    sources::defender::{self, EngineRelease},
};

/// How long the parsed release notes are trusted before they are re-read.
const RELEASES_TTL: Duration = Duration::from_secs(12 * 3600);
/// Re-read sooner when an engine is missing (it may be brand new).
const RELEASES_REFRESH: Duration = Duration::from_secs(10 * 60);
/// The cabinet header sits in the first few hundred KiB of `mpam-fe.exe`.
const HEAD: u64 = 1 << 20;
const AREA: &str = "defender";

/// A security intelligence package that is known to carry `engine`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefenderPackage {
    pub signature: String,
    pub engine: String,
    pub arch: Arch,
    pub url: String,
    pub size: u64,
}

impl DefenderPackage {
    pub fn label(&self) -> String {
        format!(
            "mpam-fe.exe {} (engine {}, {})",
            self.signature, self.engine, self.arch
        )
    }
}

impl Engine {
    /// Engine → security intelligence versions, from Microsoft Learn.
    fn defender_releases(&self, max_age: Duration) -> Result<Vec<EngineRelease>> {
        if let Some(hit) =
            self.cache
                .load_json::<Vec<EngineRelease>>(AREA, "releases", Some(max_age))
        {
            return Ok(hit);
        }
        let mut pages = Vec::new();
        let mut last_error = None;
        for url in defender::RELEASE_NOTES {
            match self
                .http
                .get_text(url, "reading the Microsoft Defender release notes")
            {
                Ok(html) => pages.push(defender::parse_release_notes(&html)),
                Err(e) => last_error = Some(e),
            }
        }
        let releases = defender::merge(&pages);
        if releases.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                Error::format(
                    "Microsoft Defender release notes",
                    "no engine versions were listed",
                )
            }));
        }
        self.cache.store_json(AREA, "releases", &releases)?;
        Ok(releases)
    }

    /// The newest documented engine before `engine` (for CVEs whose FAQ
    /// does not name the last affected version).
    pub fn defender_previous_engine(&self, engine: &str) -> Result<Option<String>> {
        let releases = self.defender_releases(RELEASES_TTL)?;
        Ok(defender::previous_engine(&releases, engine).map(str::to_owned))
    }

    /// Locates the package carrying `engine` for `arch`.
    pub fn defender_package(
        &self,
        engine: &str,
        arch: Arch,
        progress: &dyn Progress,
    ) -> Result<DefenderPackage> {
        let key = format!("package-{engine}-{}", defender::cdn_arch(arch));
        if let Some(hit) = self.cache.load_json::<DefenderPackage>(AREA, &key, None) {
            return Ok(hit);
        }
        let step = progress.step(format!(
            "Microsoft Defender release notes · package for engine {engine} ({arch})"
        ));
        let mut releases = self.defender_releases(RELEASES_TTL)?;
        if !releases.iter().any(|r| r.engine == engine) {
            releases = self.defender_releases(RELEASES_REFRESH)?;
        }
        let Some(release) = releases.iter().find(|r| r.engine == engine) else {
            return Err(Error::NotFound(format!(
                "engine {engine} is not listed in Microsoft's Defender release notes, \
                 so the package that carries it cannot be located"
            )));
        };
        for signature in &release.signatures {
            let url = defender::package_url(signature, engine, arch);
            match self.http.content_length(&url, "checking the Defender CDN") {
                Ok(size) => {
                    let package = DefenderPackage {
                        signature: signature.clone(),
                        engine: engine.to_owned(),
                        arch,
                        url,
                        size,
                    };
                    self.cache.store_json(AREA, &key, &package)?;
                    step.finish(format!(
                        "security intelligence {signature} · {:.0} MB package",
                        size as f64 / 1_048_576.0
                    ));
                    return Ok(package);
                }
                Err(Error::Http { status: 404, .. }) => continue,
                Err(Error::Http { status: 403, .. }) => return Err(rate_limited()),
                Err(e) => return Err(e),
            }
        }
        Err(Error::NotFound(format!(
            "Microsoft's Defender CDN no longer hosts a package with engine {engine} \
             (tried security intelligence {})",
            release.signatures.join(", ")
        )))
    }

    /// The first MiB of a package, where its cabinet header lives (cached).
    fn defender_head(&self, package: &DefenderPackage) -> Result<Vec<u8>> {
        let key = format!(
            "head-{}-{}-{}.bin",
            package.signature,
            package.engine,
            defender::cdn_arch(package.arch)
        );
        if let Some(hit) = self.cache.load_bytes(AREA, &key) {
            return Ok(hit);
        }
        let head = self
            .http
            .get_range(
                &package.url,
                0,
                HEAD.min(package.size),
                "reading the Defender package header",
                &NullMeter,
            )
            .map_err(forbidden_as_rate_limit)?;
        self.cache.store_bytes(AREA, &key, &head)?;
        Ok(head)
    }

    /// Every file in the package (completion and detection).
    pub fn defender_files(
        &self,
        engine: &str,
        arch: Arch,
        progress: &dyn Progress,
    ) -> Result<Vec<String>> {
        let package = self.defender_package(engine, arch, progress)?;
        let head = self.defender_head(&package)?;
        let (_, cabinet) = open_cabinet(head)?;
        let mut names: Vec<String> = cabinet
            .files()
            .iter()
            .map(|f| f.name.to_ascii_lowercase())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }
}

pub fn acquire(
    engine: &Engine,
    pair: &PatchPair,
    version: &str,
    binary: &BinaryName,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Materialized> {
    let package = engine.defender_package(version, pair.arch, progress)?;
    cancel.check()?;
    let step = progress.step(format!("Reading {binary} from {}", package.label()));
    let head = engine.defender_head(&package)?;
    let (cab_offset, cabinet) = open_cabinet(head.clone())?;
    let file = find_member(&cabinet, binary, &package)?;
    let fetch = |offset: u64, len: u64| {
        step.total(Some(len));
        engine
            .http
            .get_range(
                &package.url,
                cab_offset + offset,
                len,
                "reading the Defender package",
                step.as_ref(),
            )
            .map_err(forbidden_as_rate_limit)
    };
    // A stored folder holds the file verbatim: fetch exactly its blocks.
    let mut read = 0;
    let stored = match cabinet.stored_span(&file) {
        Some(span) => {
            let blocks = fetch(span.offset, span.len)?;
            read += span.len;
            span.unstore(blocks).ok()
        }
        None => None,
    };
    let bytes = match stored {
        Some(bytes) => bytes,
        None => {
            // Compressed (the engine's LZX folder): the whole folder, joined
            // with the header bytes already at hand.
            let (start, end) = cabinet.folder_span(file.folder);
            let known = head.len() as u64 - cab_offset;
            let from = start.max(known).min(end);
            let folder = fetch(from, end - from)?;
            let cabinet = Cabinet::open(Arc::new(
                SparseSource::new(cabinet.size())
                    .with(0, head[cab_offset as usize..].to_vec())
                    .with(from, folder),
            ))?;
            read += end - from;
            cancel.check()?;
            cabinet.extract(&[&file], cancel)?.remove(0)
        }
    };

    let verified =
        authenticode::verify(&bytes, binary.as_str())?.ok_or_else(|| Error::Integrity {
            what: format!("{binary} from {}", package.label()),
            algorithm: "Authenticode",
            expected: "a signed file".into(),
            actual: "no signature".into(),
        })?;
    let file_version = pe::parse(&bytes).ok().and_then(|info| info.file_version);
    if binary.as_str() == "mpengine.dll" && file_version.as_deref() != Some(version) {
        return Err(Error::Integrity {
            what: format!("mpengine.dll from {}", package.label()),
            algorithm: "file version",
            expected: version.to_owned(),
            actual: file_version.unwrap_or_else(|| "none".into()),
        });
    }
    step.finish(format!(
        "{:.1} MB read · {} bytes · Authenticode {} ok",
        read as f64 / 1_048_576.0,
        bytes.len(),
        verified.algorithm.name()
    ));
    let version = file_version.unwrap_or_else(|| version.to_owned());
    Ok(Materialized {
        version: Some(version.clone()),
        how: Materialization::DefenderPackage {
            package: package.label(),
            url: package.url.clone(),
        },
        verified_with: Some(verified),
        entry: PayloadEntry {
            path: format!("mpam-fe.exe/{}", file.name),
            file_name: binary.as_str().to_owned(),
            kind: PayloadKind::Full,
            component: None,
            version: Some(version),
            size: bytes.len() as u64,
            sha256: None,
            locator: Locator::Cab {
                chain: vec!["mpam-fe.exe".into(), file.name.clone()],
            },
        },
        bytes,
    })
}

/// The cabinet inside `mpam-fe.exe` (a self-extracting PE), opened over the
/// bytes we have. Returns its offset in the package.
fn open_cabinet(head: Vec<u8>) -> Result<(u64, Cabinet)> {
    let at = find_cabinet(&head).ok_or_else(|| {
        Error::format(
            "Defender package",
            "no cabinet in the first MiB of mpam-fe.exe",
        )
    })?;
    let len = head.len() as u64 - at;
    let cabinet = Cabinet::open(Arc::new(SliceSource::new(
        Arc::new(MemorySource::new(head)),
        at,
        len,
    )))?;
    Ok((at, cabinet))
}

/// First `MSCF` signature with a plausible header.
fn find_cabinet(data: &[u8]) -> Option<u64> {
    let mut from = 0;
    while let Some(i) = data[from..]
        .windows(8)
        .position(|w| w == b"MSCF\0\0\0\0")
        .map(|i| from + i)
    {
        let header = data.get(i..i + 36)?;
        let size = u32::from_le_bytes(header[8..12].try_into().ok()?);
        let folders = u16::from_le_bytes(header[26..28].try_into().ok()?);
        let files = u16::from_le_bytes(header[28..30].try_into().ok()?);
        if size > 36 && folders > 0 && files > 0 {
            return Some(i as u64);
        }
        from = i + 4;
    }
    None
}

fn find_member(
    cabinet: &Cabinet,
    binary: &BinaryName,
    package: &DefenderPackage,
) -> Result<FileEntry> {
    cabinet.find(binary.as_str()).cloned().ok_or_else(|| {
        let names: Vec<&str> = cabinet.files().iter().map(|f| f.name.as_str()).collect();
        Error::NotFound(format!(
            "{binary} is not in {} (it contains {})",
            package.label(),
            names.join(", ")
        ))
    })
}

fn rate_limited() -> Error {
    Error::Unsupported(
        "Microsoft's Defender CDN is refusing requests for now (HTTP 403, rate limit) — \
         wait a few minutes and try again"
            .into(),
    )
}

fn forbidden_as_rate_limit(error: Error) -> Error {
    match error {
        Error::Http { status: 403, .. } => rate_limited(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_embedded_cabinet() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"MSCF\0\0\0\0");
        data.extend_from_slice(&[0; 28]);
        assert_eq!(find_cabinet(&data), None, "zero sizes are not a cabinet");
        let at = data.len();
        let mut header = b"MSCF\0\0\0\0".to_vec();
        header.extend_from_slice(&1000u32.to_le_bytes());
        header.extend_from_slice(&[0; 14]);
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&2u16.to_le_bytes());
        header.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&header);
        assert_eq!(find_cabinet(&data), Some(at as u64));
    }
}
