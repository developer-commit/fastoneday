use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    domain::{Arch, BinaryName, PE_EXTENSIONS},
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

    /// Distinct binary file names, for completion.
    pub fn binary_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| {
                e.file_name
                    .rsplit_once('.')
                    .is_some_and(|(_, ext)| PE_EXTENSIONS.contains(&ext) && ext != "mui")
            })
            .map(|e| e.file_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}
