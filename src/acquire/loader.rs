//! Opens update packages, choosing remote (range) or downloaded access, and
//! caches catalog lookups and payload indexes.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use regex::Regex;

use super::progress::Progress;
use crate::{
    domain::{Arch, Digest, HashAlgorithm, slugify},
    error::{Error, Result},
    io::{Cancel, FileSource, ReadAt, Source},
    net::{Http, HttpRangeSource},
    packages::{
        C2rPackage, CabMsuPackage, MsuShape, OfficeMspPackage, PackageIndex, SharedPackage,
        UpdatePackage, WimMsuPackage, sniff,
    },
    sources::{
        catalog::{CatalogClient, CatalogPackage, PackageFile},
        office::{Channel, OfficeCdn},
    },
    store::{Cache, hash_file},
};

static SHA1_IN_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"_([0-9a-fA-F]{40})\.(?:msu|cab)$").expect("regex"));
static KB_IN_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)-kb(\d{6,8})-").expect("regex"));
const CATALOG_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// Bump when the index format changes.
const INDEX_VERSION: u32 = 1;

pub struct PackageLoader {
    http: Arc<Http>,
    catalog: CatalogClient,
    cache: Cache,
    opened: Mutex<HashMap<String, SharedPackage>>,
}

impl PackageLoader {
    pub fn new(http: Arc<Http>, cache: Cache) -> Self {
        Self {
            catalog: CatalogClient::new(http.clone()),
            http,
            cache,
            opened: Mutex::new(HashMap::new()),
        }
    }

    pub fn catalog_package(
        &self,
        kb: &str,
        product: &str,
        arch: Arch,
        progress: &dyn Progress,
    ) -> Result<CatalogPackage> {
        let key = format!("{kb}-{arch}-{}", slugify(product));
        if let Some(hit) =
            self.cache
                .load_json::<CatalogPackage>("catalog", &key, Some(CATALOG_TTL))
        {
            return Ok(hit);
        }
        let step = progress.step(format!("Update Catalog · {kb}"));
        let package = self.catalog.package(kb, product, arch)?;
        step.finish(format!(
            "{} ({} file{})",
            package.update.title,
            package.files.len(),
            if package.files.len() == 1 { "" } else { "s" }
        ));
        self.cache.store_json("catalog", &key, &package)?;
        Ok(package)
    }

    fn memo(&self, key: &str) -> Option<SharedPackage> {
        self.opened.lock().expect("opened").get(key).cloned()
    }

    fn remember(&self, key: &str, package: SharedPackage) -> SharedPackage {
        self.opened
            .lock()
            .expect("opened")
            .insert(key.to_owned(), package.clone());
        package
    }

    /// A Windows update package (`.msu`), remote when possible.
    pub fn windows(
        &self,
        kb: &str,
        file: &PackageFile,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<SharedPackage> {
        self.windows_with(kb, file, true, progress, cancel)?
            .ok_or_else(|| Error::NotFound(format!("{} needs a download", file.name)))
    }

    /// Like [`Self::windows`], but returns `None` instead of starting a large
    /// download when the package cannot be read remotely.
    pub fn windows_with(
        &self,
        kb: &str,
        file: &PackageFile,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Option<SharedPackage>> {
        if let Some(hit) = self.memo(&file.url) {
            return Ok(Some(hit));
        }
        // A prerequisite (checkpoint) package carries its own KB in its name.
        let own_kb = KB_IN_NAME
            .captures(&file.name)
            .map(|c| format!("KB{}", &c[1]));
        let kb = own_kb.as_deref().unwrap_or(kb);
        let label = format!("{kb} · {}", file.name);
        let index_key = format!("v{INDEX_VERSION}-{}", package_key(file));
        let remote = Arc::new(HttpRangeSource::open(
            self.http.clone(),
            &file.url,
            &format!("reading {}", file.name),
        )?);
        let package: SharedPackage = match sniff(remote.as_ref())? {
            MsuShape::Wim => {
                let step = progress.step(format!("Reading the {kb} index remotely (HTTP range)"));
                remote.set_meter(step.clone());
                let source: Source = remote.clone();
                let package = match self
                    .cache
                    .load_json::<PackageIndex>("packages", &index_key, None)
                {
                    Some(index) => WimMsuPackage::with_index(
                        source,
                        PackageIndex {
                            label: label.clone(),
                            ..index
                        },
                    ),
                    None => {
                        let package = WimMsuPackage::open(source, label)?;
                        self.cache
                            .store_json("packages", &index_key, package.index())?;
                        package
                    }
                };
                let read = step.transferred();
                step.finish(if read == 0 {
                    format!("{} payloads (index cached)", package_len(&package))
                } else {
                    format!(
                        "{} payloads · {} MB read of a {} MB package",
                        package_len(&package),
                        mb(read),
                        mb(ReadAt::size(remote.as_ref()))
                    )
                });
                remote.set_meter(Arc::new(crate::io::NullMeter));
                Arc::new(package)
            }
            MsuShape::Cab => {
                if !allow_download && !self.is_downloaded(file) {
                    return Ok(None);
                }
                let path =
                    self.download(file, Some(ReadAt::size(remote.as_ref())), progress, cancel)?;
                let step = progress.step(format!("Indexing {}", file.name));
                let source: Source = Arc::new(FileSource::open(&path)?);
                let package = match self
                    .cache
                    .load_json::<PackageIndex>("packages", &index_key, None)
                {
                    Some(index) => CabMsuPackage::with_index(
                        source,
                        PackageIndex {
                            label: label.clone(),
                            ..index
                        },
                        self.cache.spill(),
                    )?,
                    None => {
                        let package =
                            CabMsuPackage::open(source, label, self.cache.spill(), cancel)?;
                        self.cache.store_json(
                            "packages",
                            &index_key,
                            UpdatePackage::index(&package),
                        )?;
                        package
                    }
                };
                step.finish(format!(
                    "{} payloads",
                    UpdatePackage::index(&package).entries.len()
                ));
                Arc::new(package)
            }
        };
        Ok(Some(self.remember(&file.url, package)))
    }

    /// An MSI-Office update cabinet (always downloaded; ~100 MB).
    pub fn office_msi(
        &self,
        kb: &str,
        file: &PackageFile,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<SharedPackage> {
        self.office_msi_with(kb, file, true, progress, cancel)?
            .ok_or_else(|| Error::NotFound(format!("{} needs a download", file.name)))
    }

    pub fn office_msi_with(
        &self,
        kb: &str,
        file: &PackageFile,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Option<SharedPackage>> {
        if let Some(hit) = self.memo(&file.url) {
            return Ok(Some(hit));
        }
        if !allow_download && !self.is_downloaded(file) {
            return Ok(None);
        }
        let path = self.download(file, None, progress, cancel)?;
        let step = progress.step(format!("Opening the {kb} patch"));
        let package = OfficeMspPackage::open(
            Arc::new(FileSource::open(&path)?),
            format!("{kb} · {}", file.name),
            &self.cache.spill(),
            cancel,
        )?;
        step.finish(format!(
            "{} files",
            UpdatePackage::index(&package).entries.len()
        ));
        Ok(Some(self.remember(&file.url, Arc::new(package))))
    }

    fn download_path(&self, file: &PackageFile) -> PathBuf {
        self.cache
            .downloads()
            .join(crate::store::sanitize(&file.name))
    }

    fn is_downloaded(&self, file: &PackageFile) -> bool {
        let path = self.download_path(file);
        path.is_file() && path.with_extension("verified").is_file()
    }

    /// A Click-to-Run build.
    pub fn c2r(
        &self,
        channel: Channel,
        build: &str,
        arch: Arch,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<SharedPackage> {
        let key = format!("c2r-{}-{build}-{arch}", channel.short());
        if let Some(hit) = self.memo(&key) {
            return Ok(hit);
        }
        let step = progress.step(format!("Office CDN · {build} ({}) index", channel.short()));
        let package = C2rPackage::open(
            OfficeCdn::new(self.http.clone()),
            channel,
            build,
            arch,
            cancel,
        )?;
        step.finish(format!(
            "{} files",
            UpdatePackage::index(&package).entries.len()
        ));
        Ok(self.remember(&key, Arc::new(package)))
    }

    /// Downloads `file` into the cache once and verifies it against the
    /// Catalog's digest (or the SHA-1 embedded in Microsoft's file name).
    fn download(
        &self,
        file: &PackageFile,
        size: Option<u64>,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<PathBuf> {
        let path = self.download_path(file);
        let marker = path.with_extension("verified");
        if path.is_file() && marker.is_file() {
            progress.note(format!("Reusing cached {}", file.name));
            return Ok(path);
        }
        let step = progress.step(format!("Downloading {}", file.name));
        self.http.download(
            &file.url,
            &path,
            size,
            &format!("downloading {}", file.name),
            step.as_ref(),
            cancel,
        )?;
        step.finish(format!(
            "{} MB",
            mb(fs::metadata(&path).map(|m| m.len()).unwrap_or(0))
        ));

        let expected = file
            .sha256
            .as_deref()
            .map(|h| Digest::new(HashAlgorithm::Sha256, h))
            .or_else(|| {
                file.sha1
                    .as_deref()
                    .map(|h| Digest::new(HashAlgorithm::Sha1, h))
            })
            .or_else(|| {
                SHA1_IN_NAME
                    .captures(&file.name)
                    .map(|c| Digest::new(HashAlgorithm::Sha1, &c[1]))
            })
            .transpose()?;
        if let Some(expected) = expected {
            let step = progress.step(format!(
                "Verifying {} ({})",
                file.name,
                expected.algorithm.name()
            ));
            let actual = hash_file(&path, expected.algorithm)?;
            if actual != expected {
                let _ = fs::remove_file(&path);
                return Err(Error::Integrity {
                    what: file.name.clone(),
                    algorithm: expected.algorithm.name(),
                    expected: expected.hex,
                    actual: actual.hex,
                });
            }
            step.finish("matches the Update Catalog".into());
        }
        crate::store::write_atomic(&marker, b"ok")?;
        Ok(path)
    }
}

/// Stable cache key for a package file.
fn package_key(file: &PackageFile) -> String {
    file.sha1
        .clone()
        .or_else(|| file.sha256.clone())
        .or_else(|| {
            SHA1_IN_NAME
                .captures(&file.name)
                .map(|c| c[1].to_ascii_lowercase())
        })
        .unwrap_or_else(|| crate::store::sanitize(&file.name))
}

fn package_len(p: &WimMsuPackage) -> usize {
    UpdatePackage::index(p).entries.len()
}

fn mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}
