//! Opens update packages, choosing remote (range) or downloaded access, and
//! caches catalog lookups and payload indexes.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    thread,
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
    /// Files being downloaded right now; a second request waits for the first.
    downloading: Mutex<HashSet<PathBuf>>,
}

/// A package opened for reading, or why it was not.
pub enum Opened {
    Package {
        package: SharedPackage,
        /// Read in place (HTTP ranges) rather than from a downloaded copy.
        remote: bool,
    },
    /// Only readable after a full download, which was not allowed.
    NeedsDownload { name: String, size: Option<u64> },
}

impl Opened {
    /// The package, or `NotFound` when it still needs a download.
    pub fn package(self) -> Result<SharedPackage> {
        match self {
            Self::Package { package, .. } => Ok(package),
            Self::NeedsDownload { name, .. } => {
                Err(Error::NotFound(format!("{name} needs a download")))
            }
        }
    }
}

impl PackageLoader {
    pub fn new(http: Arc<Http>, cache: Cache) -> Self {
        Self {
            catalog: CatalogClient::new(http.clone()),
            http,
            cache,
            opened: Mutex::new(HashMap::new()),
            downloading: Mutex::new(HashSet::new()),
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
            .package()
    }

    /// Like [`Self::windows`], but reports [`Opened::NeedsDownload`] instead
    /// of starting a large download when the package cannot be read remotely.
    pub fn windows_with(
        &self,
        kb: &str,
        file: &PackageFile,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Opened> {
        if let Some(hit) = self.memo(&file.url) {
            let remote = !self.is_downloaded(file);
            return Ok(Opened::Package {
                package: hit,
                remote,
            });
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
        let (package, read_remotely): (SharedPackage, bool) = match sniff(remote.as_ref())? {
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
                (Arc::new(package), true)
            }
            MsuShape::Cab => {
                if !allow_download && !self.is_downloaded(file) {
                    return Ok(Opened::NeedsDownload {
                        name: file.name.clone(),
                        size: Some(ReadAt::size(remote.as_ref())),
                    });
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
                (Arc::new(package), false)
            }
        };
        Ok(Opened::Package {
            package: self.remember(&file.url, package),
            remote: read_remotely,
        })
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
            .package()
    }

    pub fn office_msi_with(
        &self,
        kb: &str,
        file: &PackageFile,
        allow_download: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Opened> {
        if let Some(hit) = self.memo(&file.url) {
            return Ok(Opened::Package {
                package: hit,
                remote: false,
            });
        }
        if !allow_download && !self.is_downloaded(file) {
            return Ok(Opened::NeedsDownload {
                name: file.name.clone(),
                size: self
                    .http
                    .content_length(&file.url, &format!("sizing {}", file.name))
                    .ok(),
            });
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
        Ok(Opened::Package {
            package: self.remember(&file.url, Arc::new(package)),
            remote: false,
        })
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
        // A file list and a fetch may want the same package at once.
        let _claim = self.claim(&path, cancel)?;
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

impl PackageLoader {
    /// Waits until no other thread is downloading `path`, then holds it.
    fn claim(&self, path: &Path, cancel: &Cancel) -> Result<Claim<'_>> {
        loop {
            cancel.check()?;
            if self
                .downloading
                .lock()
                .expect("downloading")
                .insert(path.to_path_buf())
            {
                return Ok(Claim {
                    set: &self.downloading,
                    path: path.to_path_buf(),
                });
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

struct Claim<'a> {
    set: &'a Mutex<HashSet<PathBuf>>,
    path: PathBuf,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.set.lock().expect("downloading").remove(&self.path);
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
