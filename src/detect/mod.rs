//! Which binary did a CVE most likely patch?
//!
//! Evidence, strongest first: a file name written in MSRC text, a component
//! rule matching the title/tag, the Office application that the release
//! notes list the CVE under, and presence in the fixing update package.

mod rules;
mod text;

use std::collections::BTreeMap;

pub use text::file_names;

use crate::domain::{BinaryName, Candidate, CveDetail, Evidence, Family};

pub struct Signals<'a> {
    pub detail: &'a CveDetail,
    /// Application heading from the Office security release notes.
    pub office_app: Option<&'a str>,
    /// Binaries carried by the fixing update, when known.
    pub package_names: Option<&'a [String]>,
}

pub fn rank(signals: &Signals<'_>) -> Vec<Candidate> {
    let detail = signals.detail;
    let mut scores: BTreeMap<String, (u8, Vec<Evidence>)> = BTreeMap::new();
    let mut add = |name: &str, score: u8, evidence: Evidence| {
        let entry = scores.entry(name.to_owned()).or_insert((0, Vec::new()));
        entry.0 = entry.0.max(score);
        if !entry.1.contains(&evidence) {
            entry.1.push(evidence);
        }
    };

    let fields: [(&str, &str, u8); 3] = [
        ("title", detail.summary.title.as_str(), 95),
        ("tag", detail.summary.tag.as_str(), 95),
        ("description", detail.description.as_str(), 85),
    ];
    for (field, value, score) in fields {
        for name in text::file_names(value) {
            add(&name, score, Evidence::NamedIn(field.into()));
        }
    }
    for article in &detail.articles {
        for name in text::file_names(article) {
            add(&name, 75, Evidence::NamedIn("FAQ".into()));
        }
    }

    let is_office = detail.patches.iter().any(|p| p.family != Family::Windows)
        || detail.summary.tag.to_ascii_lowercase().contains("office");
    let title_tag = text::normalize(&format!("{} {}", detail.summary.title, detail.summary.tag));
    let description = text::normalize(&detail.description);
    let rule_sets: &[&[rules::Rule]] = if is_office {
        &[rules::OFFICE, rules::WINDOWS]
    } else {
        &[rules::WINDOWS]
    };
    for set in rule_sets {
        for rule in *set {
            for phrase in rule.phrases {
                let needle = format!(" {phrase} ");
                let base = if title_tag.contains(&needle) {
                    rule.weight
                } else if description.contains(&needle) {
                    rule.weight.saturating_sub(15)
                } else {
                    continue;
                };
                for (i, binary) in rule.binaries.iter().enumerate() {
                    add(
                        binary,
                        base.saturating_sub(i as u8 * 6),
                        Evidence::Component((*phrase).into()),
                    );
                }
            }
        }
    }

    if let Some(app) = signals.office_app {
        let app_norm = text::normalize(app);
        for rule in rules::OFFICE {
            if rule
                .phrases
                .iter()
                .any(|p| app_norm.contains(&format!(" {p} ")))
            {
                for (i, binary) in rule.binaries.iter().enumerate() {
                    add(
                        binary,
                        82u8.saturating_sub(i as u8 * 6),
                        Evidence::Component(format!("Office {app}")),
                    );
                }
                break;
            }
        }
    }

    let mut out: Vec<Candidate> = scores
        .into_iter()
        .filter_map(|(name, (mut score, mut evidence))| {
            let name = BinaryName::parse(&name).ok()?;
            if let Some(present) = signals.package_names {
                if present.iter().any(|n| n == name.as_str()) {
                    score = score.saturating_add(8).min(100);
                    evidence.push(Evidence::InPackage);
                } else {
                    score /= 3;
                }
            }
            Some(Candidate {
                name,
                score,
                evidence,
            })
        })
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CveId, CveSummary};

    fn detail(title: &str, tag: &str, description: &str) -> CveDetail {
        CveDetail {
            summary: CveSummary {
                id: CveId::parse("CVE-2024-0001").unwrap(),
                title: title.into(),
                tag: tag.into(),
                released: String::new(),
                severity: String::new(),
                impact: String::new(),
                exploited: false,
            },
            description: description.into(),
            articles: vec![],
            cwe: vec![],
            patches: vec![],
            unsupported: vec![],
        }
    }

    #[test]
    fn explicit_names_beat_rules() {
        let d = detail(
            "Windows Kernel Elevation of Privilege Vulnerability",
            "Windows Kernel",
            "Bug in ntfs.sys",
        );
        let ranked = rank(&Signals {
            detail: &d,
            office_app: None,
            package_names: None,
        });
        assert_eq!(ranked[0].name.as_str(), "ntfs.sys");
        assert!(ranked.iter().any(|c| c.name.as_str() == "ntoskrnl.exe"));
    }

    #[test]
    fn package_presence_reorders_rule_candidates() {
        let d = detail(
            "Win32k Elevation of Privilege Vulnerability",
            "Windows Win32K - GRFX",
            "",
        );
        let names = vec!["win32kbase.sys".to_string()];
        let ranked = rank(&Signals {
            detail: &d,
            office_app: None,
            package_names: Some(&names),
        });
        assert_eq!(ranked[0].name.as_str(), "win32kbase.sys");
        assert!(ranked[0].evidence.contains(&Evidence::InPackage));
    }

    #[test]
    fn office_app_from_release_notes() {
        let d = detail(
            "Microsoft Excel Remote Code Execution Vulnerability",
            "Microsoft Office Excel",
            "",
        );
        let ranked = rank(&Signals {
            detail: &d,
            office_app: Some("Excel"),
            package_names: None,
        });
        assert_eq!(ranked[0].name.as_str(), "excel.exe");
    }

    #[test]
    fn afd_title_maps_to_afd_sys() {
        let d = detail(
            "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
            "Windows Ancillary Function Driver for WinSock",
            "",
        );
        let ranked = rank(&Signals {
            detail: &d,
            office_app: None,
            package_names: None,
        });
        assert_eq!(ranked[0].name.as_str(), "afd.sys");
    }
}
