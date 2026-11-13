use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use super::C2rPackage;
use crate::{
    domain::{Arch, BinaryName, Change},
    formats::component::{Component, PayloadKind},
};

/// How to find a payload's stored bytes inside its package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum Locator {
    /// A range of a PSF. `member` is the cabinet path of the `.psf` (CAB-era
    /// MSU) or empty when `offset` is absolute in the package (WIM-era MSU).
    Psf {
        member: Vec<String>,
        offset: u64,
        length: u64,
        /// Stored as a PA30 delta from nothing.
        pa30: bool,
    },
    /// A member reached through nested cabinets.
    Cab { chain: Vec<String> },
    /// A file key in an MSP's embedded cabinet.
    Msp { stream: String, key: String },
    /// A path in a Click-to-Run stream.
    Stream { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadEntry {
    /// Path as written in the package.
    pub path: String,
    /// Lower-case file name.
    pub file_name: String,
    pub kind: PayloadKind,
    pub component: Option<Component>,
    /// File version, when the package states it.
    pub version: Option<String>,
    /// Stored size.
    pub size: u64,
    /// SHA-256 of the payload as published in the package index.
    pub sha256: Option<String>,
    pub locator: Locator,
}

impl PayloadEntry {
    /// Lower is better: native component, culture-neutral, real binary.
    fn preference(&self, arch: Arch) -> (u8, u8, u8) {
        let arch_rank = match &self.component {
            Some(c) => arch
                .native_component_prefixes()
                .iter()
                .position(|p| *p == c.arch)
                .map(|p| p as u8)
                .unwrap_or(5),
            None => 0,
        };
        let culture = self
            .component
            .as_ref()
            .map(|c| u8::from(!c.is_neutral()))
            .unwrap_or(0);
        let kind = match self.kind {
            PayloadKind::Full => 0,
            PayloadKind::Null => 1,
            PayloadKind::Forward => 2,
            PayloadKind::Reverse => 9,
        };
        (arch_rank, culture, kind)
    }

    pub fn component_key(&self) -> Option<String> {
        self.component.as_ref().map(Component::key)
    }

    pub fn is_native(&self, arch: Arch) -> bool {
        self.component
            .as_ref()
            .is_none_or(|c| arch.native_component_prefixes().contains(&c.arch.as_str()))
    }
}

/// Everything one package carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIndex {
    /// Human label, e.g. `KB5041571 · windows11.0-kb5041571-x64_….msu`.
    pub label: String,
    pub entries: Vec<PayloadEntry>,
}

impl PackageIndex {
    /// Entries for `name`, best first. Reverse deltas are never returned.
    pub fn find(&self, name: &BinaryName, arch: Arch) -> Vec<&PayloadEntry> {
        let mut hits: Vec<&PayloadEntry> = self
            .entries
            .iter()
            .filter(|e| e.file_name == name.as_str() && e.kind != PayloadKind::Reverse)
            .collect();
        hits.sort_by_key(|e| e.preference(arch));
        hits
    }

    /// The entry of the same component (any version) and file, if present.
    pub fn find_component(&self, component_key: &str, name: &str) -> Option<&PayloadEntry> {
        self.entries.iter().find(|e| {
            e.file_name == name
                && e.kind != PayloadKind::Reverse
                && e.component_key().as_deref() == Some(component_key)
        })
    }

    /// Every distinct file name in the package (completion and browsing).
    pub fn file_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.kind != PayloadKind::Reverse)
            .map(|e| e.file_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// How each file of this (the after) package differs from `before`, for
    /// the copy a fetch would use (native component, else the preferred
    /// Click-to-Run path).
    ///
    /// Serviced components compare by version: a component the before
    /// package does not carry is still at its servicing baseline there, so
    /// the file changed. Componentless entries (Click-to-Run) compare by
    /// path and SHA-256. Files whose state cannot be told (no hashes, e.g.
    /// Office MSP) are left out.
    pub fn changes_from(&self, before: &PackageIndex, arch: Arch) -> BTreeMap<String, Change> {
        let mut by_component: HashMap<(String, &str), &PayloadEntry> = HashMap::new();
        let mut by_path: HashMap<String, &PayloadEntry> = HashMap::new();
        for e in before
            .entries
            .iter()
            .filter(|e| e.kind != PayloadKind::Reverse)
        {
            match e.component_key() {
                Some(key) => {
                    by_component.insert((key, e.file_name.as_str()), e);
                }
                None => {
                    by_path.insert(e.path.to_ascii_lowercase(), e);
                }
            }
        }
        let rank = |e: &PayloadEntry| (e.preference(arch), C2rPackage::path_rank(&e.path, arch));
        let mut used: BTreeMap<&str, &PayloadEntry> = BTreeMap::new();
        for e in self
            .entries
            .iter()
            .filter(|e| e.kind != PayloadKind::Reverse)
        {
            used.entry(e.file_name.as_str())
                .and_modify(|kept| {
                    if rank(e) < rank(kept) {
                        *kept = e;
                    }
                })
                .or_insert(e);
        }
        let mut out = BTreeMap::new();
        for (name, after) in used {
            let change = match after.component_key() {
                Some(key) => match by_component.get(&(key, name)) {
                    Some(b) if b.version.is_some() && b.version == after.version => Change::Same,
                    found => Change::Changed {
                        before: found.and_then(|b| b.version.clone()),
                        after: after.version.clone(),
                    },
                },
                None => match by_path.get(&after.path.to_ascii_lowercase()) {
                    _ if after.sha256.is_none() => continue,
                    Some(b) if b.sha256.is_none() => continue,
                    Some(b) if b.sha256 == after.sha256 => Change::Same,
                    found => Change::Changed {
                        before: found.and_then(|b| b.version.clone()),
                        after: after.version.clone(),
                    },
                },
            };
            out.insert(name.to_owned(), change);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(component: &str, kind: PayloadKind, file: &str) -> PayloadEntry {
        let component = Component::parse(component).unwrap();
        PayloadEntry {
            path: format!("{}\\f\\{file}", component.key()),
            file_name: file.into(),
            kind,
            version: Some(component.version.clone()),
            component: Some(component),
            size: 1,
            sha256: None,
            locator: Locator::Cab { chain: vec![] },
        }
    }

    fn office(path: &str, sha256: &str) -> PayloadEntry {
        PayloadEntry {
            path: path.into(),
            file_name: path.rsplit('\\').next().unwrap().to_ascii_lowercase(),
            kind: PayloadKind::Full,
            component: None,
            version: Some("16.0.1".into()),
            size: 1,
            sha256: Some(sha256.into()),
            locator: Locator::Stream { path: path.into() },
        }
    }

    fn index(entries: Vec<PayloadEntry>) -> PackageIndex {
        PackageIndex {
            label: "test".into(),
            entries,
        }
    }

    #[test]
    fn serviced_files_compare_by_component_version() {
        let ntfs = |v: &str| format!("amd64_microsoft-windows-ntfs_31bf3856ad364e35_{v}_none_0");
        let afd =
            |v: &str| format!("amd64_microsoft-windows-winsock-core_31bf3856ad364e35_{v}_none_0");
        let wow = "wow64_microsoft-windows-ntfs_31bf3856ad364e35_10.0.26100.9_none_0";
        let after = index(vec![
            win(&ntfs("10.0.26100.2"), PayloadKind::Forward, "ntfs.sys"),
            win(&ntfs("10.0.26100.2"), PayloadKind::Reverse, "ntfs.sys"),
            win(wow, PayloadKind::Forward, "ntfs.sys"),
            win(&afd("10.0.26100.1"), PayloadKind::Forward, "afd.sys"),
            win(&afd("10.0.26100.1"), PayloadKind::Forward, "new.sys"),
        ]);
        let before = index(vec![
            win(&ntfs("10.0.26100.1"), PayloadKind::Forward, "ntfs.sys"),
            win(&afd("10.0.26100.1"), PayloadKind::Forward, "afd.sys"),
        ]);
        let changes = after.changes_from(&before, Arch::X64);
        // The native amd64 copy is compared, not the wow64 one.
        assert_eq!(
            changes["ntfs.sys"],
            Change::Changed {
                before: Some("10.0.26100.1".into()),
                after: Some("10.0.26100.2".into())
            }
        );
        assert_eq!(changes["afd.sys"], Change::Same);
        // Not in the before package: still the baseline copy there.
        assert_eq!(
            changes["new.sys"],
            Change::Changed {
                before: None,
                after: Some("10.0.26100.1".into())
            }
        );
    }

    #[test]
    fn click_to_run_files_compare_by_path_and_hash() {
        let after = index(vec![
            office("root\\Office16\\EXCEL.EXE", "aa"),
            office("root\\vfs\\ProgramFilesCommonX86\\mso.dll", "x86"),
            office("root\\vfs\\ProgramFilesCommonX64\\mso.dll", "bb"),
        ]);
        let before = index(vec![
            office("root\\Office16\\EXCEL.EXE", "aa"),
            office("root\\vfs\\ProgramFilesCommonX64\\mso.dll", "cc"),
        ]);
        let changes = after.changes_from(&before, Arch::X64);
        assert_eq!(changes["excel.exe"], Change::Same);
        assert!(matches!(changes["mso.dll"], Change::Changed { .. }));
        let mut unhashed = office("root\\Office16\\WWLIB.DLL", "");
        unhashed.sha256 = None;
        assert!(
            index(vec![unhashed])
                .changes_from(&before, Arch::X64)
                .is_empty()
        );
    }
}
