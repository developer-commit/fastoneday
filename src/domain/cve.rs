use std::fmt;

use serde::{Deserialize, Serialize};

use super::product::PatchPair;
use crate::error::{Error, Result};

/// A validated `CVE-YYYY-NNNN…` identifier in canonical upper case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CveId(String);

impl CveId {
    /// Accepts `CVE-2024-38193`, `cve-2024-38193` and the bare `2024-38193`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim().to_ascii_uppercase();
        let body = trimmed.strip_prefix("CVE-").unwrap_or(&trimmed);
        let mut parts = body.split('-');
        let year = parts.next().unwrap_or_default();
        let number = parts.next().unwrap_or_default();
        let valid = parts.next().is_none()
            && year.len() == 4
            && year.bytes().all(|b| b.is_ascii_digit())
            && (4..=7).contains(&number.len())
            && number.bytes().all(|b| b.is_ascii_digit());
        if valid {
            Ok(Self(format!("CVE-{year}-{number}")))
        } else {
            Err(Error::Input(format!(
                "`{}` is not a CVE id (expected CVE-YYYY-NNNN)",
                input.trim()
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for CveId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<CveId> for String {
    fn from(value: CveId) -> Self {
        value.0
    }
}

/// One line of the CVE picker: enough to recognise and rank a CVE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveSummary {
    pub id: CveId,
    pub title: String,
    /// MSRC "tag", usually the component (e.g. "Windows Kernel").
    pub tag: String,
    /// `YYYY-MM-DD`.
    pub released: String,
    pub severity: String,
    pub impact: String,
    pub exploited: bool,
}

/// Everything the UI needs after a CVE is looked up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDetail {
    pub summary: CveSummary,
    pub description: String,
    /// FAQ / mitigation article text; used as detection evidence.
    pub articles: Vec<String>,
    pub cwe: Vec<String>,
    /// Patch pairs we can acquire (sorted, best first).
    pub patches: Vec<PatchPair>,
    /// Affected products we cannot acquire, with the reason.
    pub unsupported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::CveId;

    #[test]
    fn normalises_case_and_prefix() {
        assert_eq!(
            CveId::parse(" cve-2024-38193 ").unwrap().as_str(),
            "CVE-2024-38193"
        );
        assert_eq!(
            CveId::parse("2026-119853").unwrap().as_str(),
            "CVE-2026-119853"
        );
    }

    #[test]
    fn rejects_malformed_ids() {
        for bad in [
            "CVE-24-1234",
            "CVE-2024-12",
            "CVE-2024-12a4",
            "CVE-2024-1234-1",
            "",
        ] {
            assert!(CveId::parse(bad).is_err(), "{bad}");
        }
    }
}
