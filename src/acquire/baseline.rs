//! The release (RTM) baseline: the install image of build `<major>.1`, read
//! remotely with HTTP ranges. Used when a forward delta's baseline is the
//! release build (no checkpoint update covers it) and for files that never
//! changed since release.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{materialize::Materialized, progress::Progress};
use crate::{
    domain::{Arch, Digest, HashAlgorithm, Materialization},
    error::{Error, Result},
    formats::{
        component::{Component, PayloadKind},
        wim::Wim,
    },
    io::{Cancel, NullMeter, Source},
    net::{Http, HttpRangeSource},
    packages::{Locator, PayloadEntry},
    sources::uup::{ReleaseImage, UupClient},
    store::Cache,
};

/// Image URLs are time-limited; re-resolve after this.
const IMAGE_TTL: Duration = Duration::from_secs(3600);

type Key = (u32, Arch, bool);

pub struct ReleaseBaseline {
    http: Arc<Http>,
    uup: UupClient,
    cache: Cache,
    opened: Mutex<HashMap<Key, Arc<(ReleaseImage, Wim)>>>,
}

impl ReleaseBaseline {
    pub fn new(http: Arc<Http>, cache: Cache) -> Self {
        Self {
            uup: UupClient::new(http.clone()),
            http,
            cache,
            opened: Mutex::new(HashMap::new()),
        }
    }

    /// The file of `component` as shipped in the release image, if present.
    pub fn file(
        &self,
        component: &Component,
        file_name: &str,
        arch: Arch,
        prefer_server: bool,
        progress: &dyn Progress,
        cancel: &Cancel,
    ) -> Result<Option<Materialized>> {
        cancel.check()?;
        let Some(major) = component
            .version
            .split('.')
            .nth(2)
            .and_then(|b| b.parse::<u32>().ok())
        else {
            return Ok(None);
        };
        let image = self.open(major, arch, prefer_server, progress)?;
        let (release, wim) = image.as_ref();
        let prefix = format!(
            "windows/winsxs/{}_{}_{}_",
            component.arch, component.name, component.token
        );
        let culture = format!("_{}_", component.culture);
        let suffix = format!("/{file_name}");
        let mut hits: Vec<_> = wim
            .entries()
            .iter()
            .filter(|e| {
                let p = e.path.to_ascii_lowercase();
                !e.is_dir && p.starts_with(&prefix) && p.contains(&culture) && p.ends_with(&suffix)
            })
            .collect();
        hits.sort_by_key(|e| e.path.len());
        let Some(entry) = hits.first() else {
            return Ok(None);
        };
        let step = progress.step(format!(
            "Release image · {file_name} from {} ({})",
            release.name, release.build
        ));
        let bytes = wim.read(entry)?;
        let version = entry
            .path
            .split('/')
            .nth(2)
            .and_then(Component::parse)
            .map(|c| c.version);
        step.finish(format!("{} bytes, SHA-1 matches the image", bytes.len()));
        let sha1 = Digest::of(HashAlgorithm::Sha1, &bytes);
        Ok(Some(Materialized {
            bytes,
            version,
            how: Materialization::ReleaseImage {
                image: format!("{} ({})", release.name, release.build),
            },
            verified_with: Some(sha1),
            entry: PayloadEntry {
                path: entry.path.clone(),
                file_name: file_name.to_owned(),
                kind: PayloadKind::Full,
                component: Some(component.clone()),
                version: None,
                size: 0,
                sha256: None,
                locator: Locator::Stream {
                    path: entry.path.clone(),
                },
            },
        }))
    }

    fn open(
        &self,
        major: u32,
        arch: Arch,
        prefer_server: bool,
        progress: &dyn Progress,
    ) -> Result<Arc<(ReleaseImage, Wim)>> {
        let key = (major, arch, prefer_server);
        if let Some(hit) = self.opened.lock().expect("images").get(&key) {
            return Ok(hit.clone());
        }
        let step = progress.step(format!("Release image · locating build {major}.1 ({arch})"));
        let cache_key = format!(
            "{major}-{arch}-{}",
            if prefer_server { "server" } else { "client" }
        );
        let release = match self.cache.load_json::<ReleaseImage>(
            "release-images",
            &cache_key,
            Some(IMAGE_TTL),
        ) {
            Some(hit) => hit,
            None => {
                let found = self.uup.release_image(major, arch, prefer_server)?;
                self.cache
                    .store_json("release-images", &cache_key, &found)?;
                found
            }
        };
        let remote = Arc::new(HttpRangeSource::open(
            self.http.clone(),
            &release.url,
            &format!("reading {}", release.name),
        )?);
        remote.set_meter(step.clone());
        let source: Source = remote.clone();
        let wim = Wim::open(source).map_err(|e| match e {
            Error::Http { .. } | Error::Network { .. } => e,
            other => Error::format("release image", other.to_string()),
        })?;
        remote.set_meter(Arc::new(NullMeter));
        step.finish(format!(
            "{} ({}), {} files indexed, {:.1} MB read",
            release.name,
            release.title,
            wim.entries().len(),
            step.transferred() as f64 / 1048576.0
        ));
        let opened = Arc::new((release, wim));
        self.opened
            .lock()
            .expect("images")
            .insert(key, opened.clone());
        Ok(opened)
    }
}
