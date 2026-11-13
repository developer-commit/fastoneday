//! Which binary did a CVE most likely patch?
//!
//! Two stages. [`hints`] reads Microsoft's own text — a file name written in
//! MSRC fields, a component rule matching the title/tag, the Office
//! application the release notes list the CVE under — and knows nothing of
//! any package. [`recommend`] then narrows those hints to the files a patch
//! pair's fixing update actually carries, which is the only list a binary is
//! picked from: a hinted name the update does not carry is reported, never
//! offered, and a file the pair left unchanged is never the pick.

mod rules;
mod text;

use std::collections::{BTreeMap, BTreeSet};

pub use text::file_names;

use crate::domain::{BinaryName, Candidate, Change, CveDetail, Evidence, Family, PairFiles};

pub struct Signals<'a> {
    pub detail: &'a CveDetail,
    /// Application heading from the Office security release notes.
    pub office_app: Option<&'a str>,
}

/// Binary names Microsoft's text points to, best first. Not checked against
/// any update; see [`recommend`].
pub fn hints(signals: &Signals<'_>) -> Vec<Candidate> {
    let detail = signals.detail;
    let mut scores = Scores::default();

    let fields: [(&str, &str, u8); 3] = [
        ("title", detail.summary.title.as_str(), 95),
        ("tag", detail.summary.tag.as_str(), 95),
        ("description", detail.description.as_str(), 85),
    ];
    for (field, value, score) in fields {
        for name in text::file_names(value) {
            scores.add(&name, score, Evidence::NamedIn(field.into()));
        }
    }
    for article in &detail.articles {
        for name in text::file_names(article) {
            scores.add(&name, 75, Evidence::NamedIn("FAQ".into()));
        }
    }

    let is_office = detail
        .patches
        .iter()
        .any(|p| matches!(p.family, Family::OfficeMsi | Family::OfficeC2r))
        || detail.summary.tag.to_ascii_lowercase().contains("office");
    if detail
        .patches
        .iter()
        .any(|p| p.family == Family::DefenderEngine)
    {
        scores.add(
            "mpengine.dll",
            92,
            Evidence::Component("Malware Protection Engine".into()),
        );
    }
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
                    scores.add(
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
                    scores.add(
                        binary,
                        82u8.saturating_sub(i as u8 * 6),
                        Evidence::Component(format!("Office {app}")),
                    );
                }
                break;
            }
        }
    }
    scores.into_candidates()
}

/// MSRC's hints narrowed to one patch pair's fixing update.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recommendation {
    /// Files of the update with evidence, best first. The first one that is
    /// [`Candidate::recommended`] is the pick; files the pair left unchanged
    /// stay listed (marked) but are never picked.
    pub candidates: Vec<Candidate>,
    /// Hinted names the update does not carry.
    pub missing: Vec<BinaryName>,
}

/// Ranks the files of `files` (one update's file list) with `hints`.
///
/// When no hint names a file the update carries, file stems that are words
/// of the title or tag (`NTFS` → `ntfs.sys`) stand in, so the pick still
/// comes from the update itself. Change information, when present, moves
/// changed files up and unchanged ones down.
pub fn recommend(detail: &CveDetail, hints: &[Candidate], files: &PairFiles) -> Recommendation {
    let mut scores = Scores::default();
    let mut missing = Vec::new();
    for hint in hints {
        if files.contains(hint.name.as_str()) {
            for evidence in &hint.evidence {
                scores.add(hint.name.as_str(), hint.score, evidence.clone());
            }
        } else {
            missing.push(hint.name.clone());
        }
    }
    if scores.is_empty() {
        for (name, score, evidence) in stem_matches(detail, &files.names) {
            scores.add(&name, score, evidence);
        }
    }
    let mut candidates = scores.into_candidates();
    for candidate in &mut candidates {
        match files.change(candidate.name.as_str()) {
            Some(Change::Changed { .. }) => {
                candidate.score = candidate.score.saturating_add(5).min(100);
                candidate.evidence.insert(0, Evidence::Changed);
            }
            Some(Change::Same) => {
                candidate.score /= 3;
                candidate.evidence.insert(0, Evidence::Unchanged);
            }
            None => {}
        }
    }
    candidates.sort_by(|a, b| {
        b.recommended()
            .cmp(&a.recommended())
            .then(b.score.cmp(&a.score))
            .then_with(|| a.name.cmp(&b.name))
    });
    Recommendation {
        candidates,
        missing,
    }
}

/// Words that name no particular binary even when a file happens to be
/// called that.
const GENERIC: &[&str] = &[
    "windows",
    "microsoft",
    "office",
    "vulnerability",
    "elevation",
    "privilege",
    "remote",
    "code",
    "execution",
    "information",
    "disclosure",
    "denial",
    "service",
    "services",
    "security",
    "feature",
    "bypass",
    "spoofing",
    "tampering",
    "driver",
    "drivers",
    "system",
    "server",
    "client",
    "core",
    "file",
    "files",
    "update",
    "user",
    "mode",
    "component",
    "library",
    "manager",
    "host",
    "provider",
    "framework",
    "runtime",
    "engine",
    "platform",
    "application",
    "network",
    "kernel",
    "graphics",
    "media",
    "print",
    "setup",
    "install",
    "installer",
    "common",
    "control",
    "data",
    "edge",
    "local",
    "access",
    "management",
    "support",
    "storage",
    "web",
    "online",
    "cloud",
    "store",
    "search",
    "shell",
    "help",
];

/// Files of the update whose stem is a title/tag word (or two adjacent
/// words run together: `DWM Core` → `dwmcore.dll`), or a description word.
fn stem_matches(detail: &CveDetail, names: &[String]) -> Vec<(String, u8, Evidence)> {
    let words = |text: &str| -> BTreeSet<String> {
        let words: Vec<String> = text::normalize(text)
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let pairs = words.windows(2).map(|w| format!("{}{}", w[0], w[1]));
        words.iter().cloned().chain(pairs).collect()
    };
    let title = words(&format!("{} {}", detail.summary.title, detail.summary.tag));
    let description = words(&detail.description);
    let mut out = Vec::new();
    for name in names {
        let Ok(binary) = BinaryName::parse(name) else {
            continue;
        };
        if !binary.is_pe_like() || binary.extension() == "mui" {
            continue;
        }
        let stem = name.split('.').next().unwrap_or_default();
        if stem.len() < 4 || GENERIC.contains(&stem) {
            continue;
        }
        if title.contains(stem) {
            out.push((name.clone(), 70, Evidence::StemIn("title".into())));
        } else if description.contains(stem) {
            out.push((name.clone(), 55, Evidence::StemIn("description".into())));
        }
    }
    out
}

/// Best score and every distinct piece of evidence per name.
#[derive(Default)]
struct Scores(BTreeMap<String, (u8, Vec<Evidence>)>);

impl Scores {
    fn add(&mut self, name: &str, score: u8, evidence: Evidence) {
        let entry = self.0.entry(name.to_owned()).or_insert((0, Vec::new()));
        entry.0 = entry.0.max(score);
        if !entry.1.contains(&evidence) {
            entry.1.push(evidence);
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn into_candidates(self) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self
            .0
            .into_iter()
            .filter_map(|(name, (score, evidence))| {
                Some(Candidate {
                    name: BinaryName::parse(&name).ok()?,
                    score,
                    evidence,
                })
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
        out
    }
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

    fn signals(d: &CveDetail) -> Signals<'_> {
        Signals {
            detail: d,
            office_app: None,
        }
    }

    fn files(names: &[&str]) -> PairFiles {
        let mut names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        names.sort();
        PairFiles {
            names,
            changes: None,
            remote: true,
        }
    }

    fn picked(r: &Recommendation) -> Option<&str> {
        r.candidates
            .iter()
            .find(|c| c.recommended())
            .map(|c| c.name.as_str())
    }

    #[test]
    fn explicit_names_beat_rules() {
        let d = detail(
            "Windows Kernel Elevation of Privilege Vulnerability",
            "Windows Kernel",
            "Bug in ntfs.sys",
        );
        let ranked = hints(&signals(&d));
        assert_eq!(ranked[0].name.as_str(), "ntfs.sys");
        assert!(ranked.iter().any(|c| c.name.as_str() == "ntoskrnl.exe"));
    }

    #[test]
    fn only_files_of_the_update_are_recommended() {
        let d = detail(
            "Win32k Elevation of Privilege Vulnerability",
            "Windows Win32K - GRFX",
            "",
        );
        let hinted = hints(&signals(&d));
        assert_eq!(hinted[0].name.as_str(), "win32kfull.sys");
        let r = recommend(
            &d,
            &hinted,
            &files(&["win32kbase.sys", "ntoskrnl.exe", "x.dll"]),
        );
        let names: Vec<&str> = r.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["win32kbase.sys"]);
        let missing: Vec<&str> = r.missing.iter().map(|n| n.as_str()).collect();
        assert_eq!(missing, ["win32kfull.sys", "win32k.sys"]);
    }

    #[test]
    fn unchanged_files_are_never_the_pick() {
        let d = detail(
            "Windows SMB Elevation of Privilege Vulnerability",
            "Windows SMB",
            "",
        );
        let hinted = hints(&signals(&d));
        let mut list = files(&["srv2.sys", "mrxsmb.sys", "srvnet.sys"]);
        list.changes = Some(BTreeMap::from([
            ("srv2.sys".to_string(), Change::Same),
            (
                "mrxsmb.sys".to_string(),
                Change::Changed {
                    before: Some("1".into()),
                    after: Some("2".into()),
                },
            ),
            ("srvnet.sys".to_string(), Change::Same),
        ]));
        let r = recommend(&d, &hinted, &list);
        assert_eq!(picked(&r), Some("mrxsmb.sys"));
        assert_eq!(r.candidates[0].evidence[0], Evidence::Changed);
        let srv2 = r
            .candidates
            .iter()
            .find(|c| c.name.as_str() == "srv2.sys")
            .unwrap();
        assert!(!srv2.recommended());

        // Every hinted file unchanged: listed, but nothing is picked.
        list.changes = Some(
            list.names
                .iter()
                .map(|n| (n.clone(), Change::Same))
                .collect(),
        );
        let r = recommend(&d, &hinted, &list);
        assert_eq!(r.candidates.len(), 3);
        assert_eq!(picked(&r), None);
    }

    #[test]
    fn stems_of_update_files_stand_in_for_missing_rules() {
        let d = detail(
            "Windows DWM Core Library Elevation of Privilege Vulnerability",
            "Windows Telemetry Widget",
            "",
        );
        // No hint names a file of this update…
        let hinted = vec![Candidate {
            name: BinaryName::parse("dwm.exe").unwrap(),
            score: 80,
            evidence: vec![Evidence::Component("x".into())],
        }];
        let r = recommend(
            &d,
            &hinted,
            &files(&[
                "dwmcore.dll",
                "telemetry.dll",
                "windows.dll",
                "dwmcore.dll.mui",
            ]),
        );
        let names: Vec<&str> = r.candidates.iter().map(|c| c.name.as_str()).collect();
        // …so file stems that are title words (or two run together) are used.
        assert_eq!(names, ["dwmcore.dll", "telemetry.dll"]);
        assert_eq!(r.candidates[0].evidence, [Evidence::StemIn("title".into())]);
    }

    #[test]
    fn office_app_from_release_notes() {
        let d = detail(
            "Microsoft Excel Remote Code Execution Vulnerability",
            "Microsoft Office Excel",
            "",
        );
        let ranked = hints(&Signals {
            detail: &d,
            office_app: Some("Excel"),
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
        let ranked = hints(&signals(&d));
        assert_eq!(ranked[0].name.as_str(), "afd.sys");
    }
}
