//! A Click-to-Run build as a package: the stream index lists every file with
//! its SHA-256; files are fetched with one HTTP range each.

use super::{Locator, PackageIndex, PayloadEntry, UpdatePackage};
use crate::{
    domain::Arch,
    error::{Error, Result},
    formats::{c2r::StreamIndex, component::PayloadKind},
    io::{Cancel, Meter},
    sources::office::{Channel, OfficeCdn, StreamLocation},
};

pub struct C2rPackage {
    cdn: OfficeCdn,
    stream: StreamIndex,
    dat_url: String,
    index: PackageIndex,
}

impl C2rPackage {
    pub fn open(
        cdn: OfficeCdn,
        channel: Channel,
        build: &str,
        arch: Arch,
        cancel: &Cancel,
    ) -> Result<Self> {
        let (stream, dat_url) = cdn.index(channel, build, arch, cancel)?;
        let mut entries: Vec<PayloadEntry> = stream
            .files()
            .map(|f| PayloadEntry {
                path: f.path.clone(),
                file_name: f.file_name(),
                kind: PayloadKind::Full,
                component: None,
                version: Some(build.to_owned()),
                size: f.size,
                sha256: Some(f.sha256.clone()),
                locator: Locator::Stream {
                    path: f.path.clone(),
                },
            })
            .collect();
        // The stream index is a hash map; a stable order keeps the choice
        // between copies of one file (several install paths) the same on
        // every run, for the fetch and for the before/after comparison.
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            cdn,
            stream,
            dat_url,
            index: PackageIndex {
                label: format!("Office {build} ({})", channel.short()),
                entries,
            },
        })
    }

    /// Ranks paths for `arch`: 64-bit installs keep native DLLs under
    /// `ProgramFilesCommonX64`/`root\Office16`, 32-bit copies under X86.
    pub fn path_rank(path: &str, arch: Arch) -> u8 {
        let p = path.to_ascii_lowercase();
        let x86_dir = p.contains("x86") || p.contains("(x86)");
        match arch {
            Arch::X64 | Arch::Arm64 if x86_dir => 2,
            Arch::X86 if p.contains("x64") => 2,
            _ if p.starts_with("root\\office16\\") => 0,
            _ => 1,
        }
    }
}

impl UpdatePackage for C2rPackage {
    fn index(&self) -> &PackageIndex {
        &self.index
    }

    fn read(&self, entry: &PayloadEntry, meter: &dyn Meter, cancel: &Cancel) -> Result<Vec<u8>> {
        cancel.check()?;
        let Locator::Stream { path } = &entry.locator else {
            return Err(Error::format(
                "Office stream",
                "payload locator does not belong to this package",
            ));
        };
        let file = self
            .stream
            .get(path)
            .cloned()
            .ok_or_else(|| Error::format("Office stream", format!("`{path}` missing")))?;
        self.cdn.fetch(
            &StreamLocation {
                dat_url: self.dat_url.clone(),
                file,
            },
            meter,
        )
    }
}
