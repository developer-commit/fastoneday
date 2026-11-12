use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use super::write_atomic;
use crate::{domain::CveId, error::Result};

const KEEP: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub cve: CveId,
    pub title: String,
    pub binary: Option<String>,
}

/// Recently used CVEs (most recent first), for completion.
#[derive(Debug)]
pub struct History {
    path: PathBuf,
    entries: Vec<HistoryEntry>,
}

impl History {
    pub fn load(path: PathBuf) -> Self {
        let entries = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    pub fn record(&mut self, cve: &CveId, title: &str, binary: Option<&str>) -> Result<()> {
        let previous_binary = self
            .entries
            .iter()
            .find(|e| &e.cve == cve)
            .and_then(|e| e.binary.clone());
        self.entries.retain(|e| &e.cve != cve);
        self.entries.insert(
            0,
            HistoryEntry {
                cve: cve.clone(),
                title: title.to_owned(),
                binary: binary.map(str::to_owned).or(previous_binary),
            },
        );
        self.entries.truncate(KEEP);
        write_atomic(
            &self.path,
            &serde_json::to_vec_pretty(&self.entries).expect("history serializes"),
        )
    }

    pub fn last_binary(&self, cve: &CveId) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| &e.cve == cve)
            .and_then(|e| e.binary.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_most_recent_first_and_remembers_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        let a = CveId::parse("CVE-2024-0001").unwrap();
        let b = CveId::parse("CVE-2024-0002").unwrap();
        let mut h = History::load(path.clone());
        h.record(&a, "A", Some("afd.sys")).unwrap();
        h.record(&b, "B", None).unwrap();
        h.record(&a, "A", None).unwrap();
        let h = History::load(path);
        assert_eq!(h.entries()[0].cve, a);
        assert_eq!(h.last_binary(&a), Some("afd.sys"));
    }
}
