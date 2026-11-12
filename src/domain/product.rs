use std::fmt;

use serde::{Deserialize, Serialize};

/// CPU architecture of a product (and of the binaries we fetch for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X64,
    Arm64,
    X86,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
            Self::X86 => "x86",
        }
    }

    /// WinSxS component prefixes that hold native binaries for this arch,
    /// in preference order. `wow64`/`x86` components inside x64 packages are
    /// the 32-bit copies and are offered as alternatives, not defaults.
    pub fn native_component_prefixes(self) -> &'static [&'static str] {
        match self {
            Self::X64 => &["amd64", "msil"],
            Self::Arm64 => &["arm64", "msil"],
            Self::X86 => &["x86", "msil"],
        }
    }

    /// Words used in Microsoft Update Catalog titles for this architecture.
    pub fn catalog_markers(self) -> &'static [&'static str] {
        match self {
            Self::X64 => &["x64-based", "x64", "amd64", "64-bit edition"],
            Self::Arm64 => &["arm64-based", "arm64"],
            Self::X86 => &["x86-based", "32-bit edition", "x86"],
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Which acquisition pipeline a product uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Windows cumulative/monthly updates from the Update Catalog.
    Windows,
    /// MSI-based Office (2016) security updates (`*.msp` in a Catalog CAB).
    OfficeMsi,
    /// Click-to-Run Office (Microsoft 365 Apps, Office 2019/2021/2024).
    OfficeC2r,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::OfficeMsi => "Office (MSI)",
            Self::OfficeC2r => "Office (Click-to-Run)",
        }
    }
}

/// One side of a patch pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpdateRef {
    /// A knowledge-base article, e.g. `KB5041571`.
    Kb { kb: String },
    /// An Office Click-to-Run build on a CDN channel.
    OfficeBuild { channel: String, version: String },
}

impl UpdateRef {
    pub fn kb(kb: impl Into<String>) -> Self {
        Self::Kb { kb: kb.into() }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kb { kb } => kb.clone(),
            Self::OfficeBuild { version, .. } => version.clone(),
        }
    }
}

impl fmt::Display for UpdateRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A product plus the update that fixed the CVE and the update it replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchPair {
    /// Full MSRC product name.
    pub product: String,
    pub family: Family,
    pub arch: Arch,
    /// MSRC download name ("Security Update", "Monthly Rollup", "Hotpatch").
    pub kind: String,
    pub before: UpdateRef,
    pub after: UpdateRef,
    /// Build that contains the fix, when MSRC reports it.
    pub fixed_build: Option<String>,
}

impl PatchPair {
    /// Compact product label for lists, e.g. `Windows 11 24H2 x64`.
    pub fn short_product(&self) -> String {
        let mut name = self.product.clone();
        for (from, to) in [
            (" for x64-based Systems", ""),
            (" for x64-based systems", ""),
            (" for ARM64-based Systems", ""),
            (" for ARM64-based systems", ""),
            (" for arm64-based Systems", ""),
            (" for 32-bit Systems", ""),
            (" for 64-bit Systems", ""),
            (" for 64-bit editions", ""),
            (" for 32-bit editions", ""),
            (" (64-bit edition)", ""),
            (" (32-bit edition)", ""),
            (" (Click-to-Run)", ""),
            (" (Server Core installation)", " Core"),
            (", 23H2 Edition", " 23H2"),
            ("Microsoft 365 Apps for Enterprise", "M365 Apps"),
            ("(Current Channel)", "Current"),
            ("Microsoft Office ", "Office "),
            ("Microsoft Outlook ", "Outlook "),
            ("Windows Server ", "Server "),
            (" Service Pack ", " SP"),
            ("Version ", ""),
            ("version ", ""),
        ] {
            name = name.replace(from, to);
        }
        format!(
            "{} {}",
            name.split_whitespace().collect::<Vec<_>>().join(" "),
            self.arch
        )
    }

    /// Stable directory-safe name for the workspace layout.
    pub fn slug(&self) -> String {
        slugify(&format!("{}-{}", self.short_product(), self.kind))
    }
}

/// Lower-case, `[a-z0-9-]` only, no repeated separators.
pub fn slugify(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".into()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(product: &str, arch: Arch) -> PatchPair {
        PatchPair {
            product: product.into(),
            family: Family::Windows,
            arch,
            kind: "Security Update".into(),
            before: UpdateRef::kb("KB1"),
            after: UpdateRef::kb("KB2"),
            fixed_build: None,
        }
    }

    #[test]
    fn shortens_msrc_product_names() {
        let p = pair("Windows 11 Version 24H2 for x64-based Systems", Arch::X64);
        assert_eq!(p.short_product(), "Windows 11 24H2 x64");
        let core = pair(
            "Windows Server 2022, 23H2 Edition (Server Core installation)",
            Arch::X64,
        );
        assert_eq!(core.short_product(), "Server 2022 23H2 Core x64");
        let office = pair(
            "Microsoft 365 Apps for Enterprise (Current Channel)",
            Arch::X64,
        );
        assert_eq!(office.short_product(), "M365 Apps Current x64");
        assert_eq!(p.slug(), "windows-11-24h2-x64-security-update");
    }

    #[test]
    fn slugify_collapses_punctuation() {
        assert_eq!(
            slugify("Windows Server 2022, 23H2 (Core)"),
            "windows-server-2022-23h2-core"
        );
        assert_eq!(slugify("!!"), "unknown");
    }
}
