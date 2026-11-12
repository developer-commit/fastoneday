//! Completion sources for the two inputs.

use std::collections::BTreeSet;

use crate::{
    domain::{Candidate, CveSummary},
    store::HistoryEntry,
};

/// A row in the CVE suggestion popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveSuggestion {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub from_history: bool,
    pub exploited: bool,
}

/// Matches by id prefix (`2026-119`, `cve-2026-11…`) or by words in the
/// title/tag (`clfs`, `excel rce`). History first, then exploited, then newest.
pub fn cve_suggestions(
    input: &str,
    history: &[HistoryEntry],
    recent: &[CveSummary],
    limit: usize,
) -> Vec<CveSuggestion> {
    let query = input.trim().to_ascii_uppercase();
    let id_query = query.strip_prefix("CVE-").unwrap_or(&query).to_owned();
    let looks_like_id =
        !id_query.is_empty() && id_query.bytes().all(|b| b.is_ascii_digit() || b == b'-');
    let words: Vec<String> = input
        .split_whitespace()
        .map(|w| w.to_ascii_lowercase())
        .collect();
    let matches = |id: &str, text: &str| {
        if query.is_empty() {
            return true;
        }
        if looks_like_id {
            return id.trim_start_matches("CVE-").starts_with(&id_query) || id.contains(&id_query);
        }
        let text = text.to_ascii_lowercase();
        words
            .iter()
            .all(|w| text.contains(w.as_str()) || id.to_ascii_lowercase().contains(w.as_str()))
    };

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for h in history {
        let id = h.cve.as_str();
        if matches(id, &h.title) && seen.insert(id.to_owned()) {
            out.push(CveSuggestion {
                id: id.to_owned(),
                title: h.title.clone(),
                detail: h
                    .binary
                    .clone()
                    .map(|b| format!("history · {b}"))
                    .unwrap_or_else(|| "history".into()),
                from_history: true,
                exploited: false,
            });
        }
    }
    let mut fresh: Vec<&CveSummary> = recent
        .iter()
        .filter(|c| matches(c.id.as_str(), &format!("{} {}", c.title, c.tag)))
        .collect();
    fresh.sort_by(|a, b| {
        b.exploited
            .cmp(&a.exploited)
            .then(b.released.cmp(&a.released))
    });
    for c in fresh {
        if seen.insert(c.id.as_str().to_owned()) {
            out.push(CveSuggestion {
                id: c.id.as_str().to_owned(),
                title: c.title.clone(),
                detail: format!("{} · {}", c.released, c.tag),
                from_history: false,
                exploited: c.exploited,
            });
        }
        if out.len() >= limit * 4 {
            break;
        }
    }
    out.truncate(limit);
    out
}

/// A row in the binary list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryOption {
    pub name: String,
    pub score: Option<u8>,
    pub why: String,
}

/// Detected candidates first (filtered by the input), then names from the
/// fixing package: prefix matches before substring matches.
pub fn binary_options(
    input: &str,
    candidates: &[Candidate],
    package: &[String],
    limit: usize,
) -> Vec<BinaryOption> {
    let q = input.trim().to_ascii_lowercase();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for c in candidates {
        if (q.is_empty() || c.name.as_str().contains(&q)) && seen.insert(c.name.as_str().to_owned())
        {
            out.push(BinaryOption {
                name: c.name.as_str().to_owned(),
                score: Some(c.score),
                why: c
                    .evidence
                    .iter()
                    .map(|e| e.label())
                    .collect::<Vec<_>>()
                    .join(" · "),
            });
        }
    }
    if !q.is_empty() {
        let prefix = package.iter().filter(|n| n.starts_with(&q));
        let inner = package
            .iter()
            .filter(|n| !n.starts_with(&q) && n.contains(&q));
        for name in prefix.chain(inner) {
            if seen.insert(name.clone()) {
                out.push(BinaryOption {
                    name: name.clone(),
                    score: None,
                    why: "in update package".into(),
                });
            }
            if out.len() >= limit {
                break;
            }
        }
    }
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BinaryName, CveId, Evidence};

    fn summary(id: &str, title: &str, exploited: bool, released: &str) -> CveSummary {
        CveSummary {
            id: CveId::parse(id).unwrap(),
            title: title.into(),
            tag: String::new(),
            released: released.into(),
            severity: String::new(),
            impact: String::new(),
            exploited,
        }
    }

    #[test]
    fn suggests_by_prefix_and_words() {
        let recent = vec![
            summary(
                "CVE-2026-119933",
                "Windows NTFS Elevation of Privilege Vulnerability",
                false,
                "2026-11-10",
            ),
            summary(
                "CVE-2026-118703",
                "Microsoft Office Excel Remote Code Execution Vulnerability",
                true,
                "2026-11-10",
            ),
        ];
        let history = vec![HistoryEntry {
            cve: CveId::parse("CVE-2024-38193").unwrap(),
            title: "Windows Ancillary Function Driver".into(),
            binary: Some("afd.sys".into()),
        }];
        assert_eq!(
            cve_suggestions("2026-1199", &history, &recent, 5)[0].id,
            "CVE-2026-119933"
        );
        assert_eq!(cve_suggestions("excel rce", &history, &recent, 5).len(), 0);
        assert_eq!(
            cve_suggestions("excel remote", &history, &recent, 5)[0].id,
            "CVE-2026-118703"
        );
        let all = cve_suggestions("", &history, &recent, 5);
        assert!(all[0].from_history);
        assert!(all[1].exploited);
    }

    #[test]
    fn binary_options_merge_candidates_and_package_names() {
        let candidates = vec![Candidate {
            name: BinaryName::parse("win32kfull.sys").unwrap(),
            score: 75,
            evidence: vec![Evidence::Component("win32k".into())],
        }];
        let package = vec![
            "win32k.sys".to_string(),
            "win32kbase.sys".into(),
            "xwin32k.dll".into(),
        ];
        let names: Vec<String> = binary_options("win32k", &candidates, &package, 10)
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert_eq!(
            names,
            vec![
                "win32kfull.sys",
                "win32k.sys",
                "win32kbase.sys",
                "xwin32k.dll"
            ]
        );
        assert_eq!(binary_options("", &candidates, &package, 10).len(), 1);
    }
}
