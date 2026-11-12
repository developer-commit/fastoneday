use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::{Serialize, de::DeserializeOwned};

use super::write_atomic;
use crate::error::Result;

/// Content and metadata cache under `<workspace>/cache`.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Full packages that cannot be read remotely (CAB-era MSUs, Office CABs).
    pub fn downloads(&self) -> PathBuf {
        self.root.join("downloads")
    }

    /// Scratch space for large decoded members.
    pub fn spill(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn entry(&self, area: &str, key: &str) -> PathBuf {
        self.root.join(area).join(sanitize(key))
    }

    pub fn load_json<T: DeserializeOwned>(
        &self,
        area: &str,
        key: &str,
        max_age: Option<Duration>,
    ) -> Option<T> {
        let path = self.entry(area, &format!("{key}.json"));
        if let Some(max_age) = max_age {
            let age = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())?;
            if age > max_age {
                return None;
            }
        }
        let bytes = fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn store_json<T: Serialize>(&self, area: &str, key: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value).expect("cache values serialize");
        write_atomic(&self.entry(area, &format!("{key}.json")), &bytes)
    }

    pub fn load_bytes(&self, area: &str, key: &str) -> Option<Vec<u8>> {
        fs::read(self.entry(area, key)).ok()
    }

    pub fn store_bytes(&self, area: &str, key: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.entry(area, key), bytes)
    }

    /// Removes decoded scratch files left by earlier runs.
    pub fn clear_spill(&self) {
        let _ = fs::remove_dir_all(self.spill());
    }
}

/// Keeps cache keys to a safe file-name alphabet.
pub fn sanitize(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_json_and_respects_age() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path());
        cache.store_json("a", "k/1", &vec![1, 2, 3]).unwrap();
        assert_eq!(
            cache.load_json::<Vec<u32>>("a", "k/1", None),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            cache.load_json::<Vec<u32>>("a", "k/1", Some(Duration::from_secs(3600))),
            Some(vec![1, 2, 3])
        );
        assert!(cache.load_json::<Vec<u32>>("a", "missing", None).is_none());
        assert_eq!(sanitize("KB5041571 x64/24H2"), "KB5041571_x64_24H2");
    }
}
