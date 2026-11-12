use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A plain, lower-cased file name of a Windows or Office binary (`afd.sys`,
/// `ntoskrnl.exe`, `mso.dll`, ...). Never contains a path.
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
        let valid = !name.is_empty()
            && name.len() <= 128
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
            && name
                .rsplit_once('.')
                .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty());
        if valid {
            Ok(Self(name))
        } else {
            Err(Error::Input(format!(
                "`{}` is not a plain binary file name like afd.sys or mso.dll",
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
    /// The file is present in the fixing update package.
    InPackage,
    /// The user typed it.
    User,
}

impl Evidence {
    pub fn label(&self) -> String {
        match self {
            Self::NamedIn(field) => format!("named in {field}"),
            Self::Component(phrase) => format!("component: {phrase}"),
            Self::InPackage => "in update package".into(),
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

#[cfg(test)]
mod tests {
    use super::BinaryName;

    #[test]
    fn accepts_plain_names_only() {
        assert_eq!(
            BinaryName::parse("NtOsKrnl.EXE").unwrap().as_str(),
            "ntoskrnl.exe"
        );
        assert!(BinaryName::parse("api-ms-win-core-file-l1-1-0.dll").is_ok());
        for bad in ["../x.sys", "dir\\x.dll", "noext", ".sys", "a b.dll", ""] {
            assert!(BinaryName::parse(bad).is_err(), "{bad}");
        }
    }
}
