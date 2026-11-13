use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A plain, lower-cased file name (`afd.sys`, `mso.dll`, `mpasbase.vdm`,
/// `hosts`, ...). Any file an update ships can be named; the only rule is
/// that it is a single file name that is safe to write locally — never a
/// path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BinaryName(String);

/// Extensions we treat as diffable PE images.
pub const PE_EXTENSIONS: &[&str] = &[
    "sys", "dll", "exe", "ocx", "cpl", "drv", "efi", "scr", "mui", "tlb", "ax", "acm", "tsp",
    "winmd", "fae", "hol",
];

impl BinaryName {
    pub fn parse(input: &str) -> Result<Self> {
        let name = input.trim().to_ascii_lowercase();
        let reserved = {
            // Windows device names cannot be file names, with or without an extension.
            let stem = name.split('.').next().unwrap_or_default();
            matches!(stem, "con" | "prn" | "aux" | "nul")
                || (stem.len() == 4
                    && (stem.starts_with("com") || stem.starts_with("lpt"))
                    && stem.as_bytes()[3].is_ascii_digit()
                    && stem.as_bytes()[3] != b'0')
        };
        let valid = !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.ends_with('.')
            && !reserved
            && !name.chars().any(|c| {
                c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
            });
        if valid {
            Ok(Self(name))
        } else {
            Err(Error::Input(format!(
                "`{}` is not a plain file name (no folders, and none of : * ? \" < > |)",
                input.trim()
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn extension(&self) -> &str {
        self.0.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("")
    }

    pub fn is_pe_like(&self) -> bool {
        PE_EXTENSIONS.contains(&self.extension())
    }
}

impl fmt::Display for BinaryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for BinaryName {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<BinaryName> for String {
    fn from(value: BinaryName) -> Self {
        value.0
    }
}

/// Why a binary was suggested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// The file name appears literally in the given MSRC field.
    NamedIn(String),
    /// A component rule matched the given phrase.
    Component(String),
    /// The file's stem is a word of the given MSRC field (`ntfs` → `ntfs.sys`).
    StemIn(String),
    /// The file differs between the two updates of the patch pair.
    Changed,
    /// Both updates of the patch pair carry the same version: diffing it
    /// would show nothing.
    Unchanged,
    /// The user typed it.
    User,
}

impl Evidence {
    pub fn label(&self) -> String {
        match self {
            Self::NamedIn(field) => format!("named in {field}"),
            Self::Component(phrase) => format!("component: {phrase}"),
            Self::StemIn(field) => format!("{field} names it"),
            Self::Changed => "changed".into(),
            Self::Unchanged => "same in both updates".into(),
            Self::User => "manual".into(),
        }
    }
}

/// A ranked suggestion for the binary to diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub name: BinaryName,
    /// 0..=100; higher is more likely.
    pub score: u8,
    pub evidence: Vec<Evidence>,
}

impl Candidate {
    /// Whether it may be offered as the pick: a file the patch pair left
    /// unchanged never is.
    pub fn recommended(&self) -> bool {
        !self.evidence.contains(&Evidence::Unchanged)
    }
}

/// How one file differs between the two updates of a patch pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    /// The after update carries a different file. Versions as the packages
    /// state them; `before` is `None` when the before update does not carry
    /// the file at all (it still has its servicing baseline's copy).
    Changed {
        before: Option<String>,
        after: Option<String>,
    },
    /// Both updates carry the same version (or the same hash).
    Same,
}

/// The files of a patch pair's fixing update — the only binaries the pair
/// offers — and, when the update it replaced could be read too, how each
/// differs from that update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairFiles {
    /// Distinct lower-case file names, sorted.
    pub names: Vec<String>,
    /// Per file name; `None` until the before update has been compared.
    pub changes: Option<BTreeMap<String, Change>>,
    /// The package was read in place (HTTP ranges or a CDN index) rather
    /// than downloaded whole.
    pub remote: bool,
}

impl PairFiles {
    pub fn contains(&self, name: &str) -> bool {
        self.names
            .binary_search_by(|n| n.as_str().cmp(name))
            .is_ok()
    }

    pub fn change(&self, name: &str) -> Option<&Change> {
        self.changes.as_ref()?.get(name)
    }

    /// How many files differ from the before update, once compared.
    pub fn changed_count(&self) -> Option<usize> {
        self.changes.as_ref().map(|c| {
            c.values()
                .filter(|c| matches!(c, Change::Changed { .. }))
                .count()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryName;

    #[test]
    fn accepts_any_plain_file_name() {
        assert_eq!(
            BinaryName::parse("NtOsKrnl.EXE").unwrap().as_str(),
            "ntoskrnl.exe"
        );
        for good in [
            "api-ms-win-core-file-l1-1-0.dll",
            "mpasbase.vdm",
            "hosts",
            "a b.dll",
            ".sys",
            "microsoft.windows.common-controls.manifest",
            "~$template.dotm",
        ] {
            assert!(BinaryName::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "../x.sys",
            "dir\\x.dll",
            "c:x.dll",
            "x?.dll",
            "x.dll.",
            "con",
            "nul.txt",
            "com1.sys",
            "..",
            "",
        ] {
            assert!(BinaryName::parse(bad).is_err(), "{bad}");
        }
    }
}
