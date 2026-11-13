//! Completion sources for the two inputs.

use std::collections::BTreeSet;

use crate::{
    app::PairListing,
    domain::{BinaryName, Candidate, Change, CveSummary},
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

/// Where a row in the binary list comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionKind {
    /// A file of the pair's update that Microsoft's text points to (scored;
    /// ★ for the pick).
    Candidate,
    /// Any other file of the pair's update.
    Package,
    /// The name exactly as typed, whether or not the update lists it.
    Typed,
}

/// A row in the binary list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryOption {
    pub name: String,
    pub kind: OptionKind,
    pub score: Option<u8>,
    /// The evidence, for candidates.
    pub why: String,
    /// A candidate that may be the pick (the pair did not leave it unchanged).
    pub recommended: bool,
    /// Whether the pair changed the file, once compared with its before update.
    pub changed: Option<bool>,
}

/// Every row of the binary list — all of it from the pair's fixing update,
/// nothing held back:
///
/// * the update's files that Microsoft's text points to first (best first),
///   then every other file of the update: binaries the pair changed, those
///   it left unchanged, then non-binary files (prefix matches before
///   substring matches while searching);
/// * an exact match moves to the top;
/// * otherwise the typed name itself is offered too, so any file can be
///   fetched. It leads when it reads as a complete file name that nothing
///   listed starts with (`mpsvc.dll`), and trails while it is a fragment of
///   listed names (`ntfs.s`, `32k`), so Enter still completes those.
pub fn binary_options(input: &str, listing: Option<&PairListing>) -> Vec<BinaryOption> {
    let q = input.trim().to_ascii_lowercase();
    let (candidates, names): (&[Candidate], &[String]) = match listing {
        Some(l) => (&l.candidates, &l.files.names),
        None => (&[], &[]),
    };
    let changed = |name: &str| -> Option<bool> {
        listing
            .and_then(|l| l.files.change(name))
            .map(|c| matches!(c, Change::Changed { .. }))
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for c in candidates {
        if (q.is_empty() || c.name.as_str().contains(&q)) && seen.insert(c.name.as_str()) {
            out.push(BinaryOption {
                name: c.name.as_str().to_owned(),
                kind: OptionKind::Candidate,
                score: Some(c.score),
                why: c
                    .evidence
                    .iter()
                    .map(|e| e.label())
                    .collect::<Vec<_>>()
                    .join(" · "),
                recommended: c.recommended(),
                changed: changed(c.name.as_str()),
            });
        }
    }
    // Binaries the pair changed first, then those it left alone, then the
    // update's other files (resources, INFs, scripts…), each alphabetical.
    let group = |name: &str| -> u8 {
        let binary =
            BinaryName::parse(name).is_ok_and(|b| b.is_pe_like() && b.extension() != "mui");
        let same = changed(name) == Some(false);
        u8::from(!binary) * 2 + u8::from(same)
    };
    let mut prefix: Vec<&String> = names.iter().filter(|n| n.starts_with(&q)).collect();
    prefix.sort_by_key(|n| group(n));
    let mut inner: Vec<&String> = names
        .iter()
        .filter(|n| !q.is_empty() && !n.starts_with(&q) && n.contains(&q))
        .collect();
    inner.sort_by_key(|n| group(n));
    for name in prefix.into_iter().chain(inner) {
        if seen.insert(name.as_str()) {
            out.push(BinaryOption {
                name: name.clone(),
                kind: OptionKind::Package,
                score: None,
                why: String::new(),
                recommended: false,
                changed: changed(name),
            });
        }
    }
    if q.is_empty() {
        return out;
    }
    if let Some(i) = out.iter().position(|o| o.name == q) {
        let exact = out.remove(i);
        out.insert(0, exact);
        return out;
    }
    let Ok(name) = BinaryName::parse(&q) else {
        return out;
    };
    let typed = BinaryOption {
        name: name.as_str().to_owned(),
        kind: OptionKind::Typed,
        score: None,
        why: String::new(),
        recommended: false,
        changed: None,
    };
    let complete = q
        .rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty() && ext.len() <= 8)
        && !out.iter().any(|o| o.name.starts_with(&q));
    if complete {
        out.insert(0, typed);
    } else {
        out.push(typed);
    }
    out
}

/// Whether the highlighted row counts before the user moved to it. With
/// nothing typed only the pick does — never whichever file of the update
/// happens to sort first, nor a file the pair left unchanged.
pub fn usable_unpicked(typed: &str, row: &BinaryOption) -> bool {
    !typed.trim().is_empty() || (row.kind == OptionKind::Candidate && row.recommended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::Comparison,
        domain::{BinaryName, CveId, Evidence, PairFiles},
    };

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

    fn listing(candidates: Vec<Candidate>, names: &[&str]) -> PairListing {
        PairListing {
            files: PairFiles {
                names: names.iter().map(|n| n.to_string()).collect(),
                changes: None,
                remote: true,
            },
            candidates,
            missing: vec![],
            comparison: Comparison::Pending,
        }
    }

    #[test]
    fn binary_options_offer_every_file_and_the_typed_name() {
        let candidates = vec![Candidate {
            name: BinaryName::parse("win32kfull.sys").unwrap(),
            score: 75,
            evidence: vec![Evidence::Component("win32k".into())],
        }];
        let files = listing(
            candidates.clone(),
            &[
                "mpsvc.dll.mui",
                "win32k.sys",
                "win32kbase.sys",
                "win32kfull.sys",
                "xwin32k.dll",
            ],
        );
        let rows = |q: &str| -> Vec<(String, OptionKind)> {
            binary_options(q, Some(&files))
                .into_iter()
                .map(|o| (o.name, o.kind))
                .collect()
        };
        let names = |q: &str| -> Vec<String> { rows(q).into_iter().map(|(n, _)| n).collect() };
        // Nothing typed: the candidate, then the rest of the update's files.
        assert_eq!(rows("").len(), 5);
        assert_eq!(
            rows("")[0],
            ("win32kfull.sys".into(), OptionKind::Candidate)
        );
        // A fragment: matches first, the fragment itself last.
        assert_eq!(
            names("win32k"),
            [
                "win32kfull.sys",
                "win32k.sys",
                "win32kbase.sys",
                "xwin32k.dll",
                "win32k"
            ]
        );
        assert_eq!(names("WIN32K.S")[0], "win32k.sys");
        // An exact match leads and nothing is added.
        assert_eq!(names("win32k.sys"), ["win32k.sys"]);
        // A complete name the update does not list: offered first.
        assert_eq!(
            rows("MpEngine.dll"),
            [("mpengine.dll".into(), OptionKind::Typed)]
        );
        assert_eq!(names("k.sys"), ["k.sys", "win32k.sys"]);
        // ... unless a listed name continues it.
        assert_eq!(names("mpsvc.dll"), ["mpsvc.dll.mui", "mpsvc.dll"]);
        // Never a path.
        assert!(rows("../x.sys").is_empty());
        // No list yet: only what is typed.
        assert_eq!(
            binary_options("afd.sys", None)
                .into_iter()
                .map(|o| o.kind)
                .collect::<Vec<_>>(),
            [OptionKind::Typed]
        );
    }

    #[test]
    fn only_the_pick_counts_before_the_user_moves() {
        let pick = Candidate {
            name: BinaryName::parse("afd.sys").unwrap(),
            score: 85,
            evidence: vec![Evidence::Component("afd".into())],
        };
        let same = Candidate {
            evidence: vec![Evidence::Unchanged, Evidence::Component("afd".into())],
            ..pick.clone()
        };
        let plain = listing(vec![], &["afd.sys", "tcpip.sys"]);
        let rows = binary_options("", Some(&plain));
        assert!(!usable_unpicked("", &rows[0]));
        assert!(usable_unpicked(
            "tcp",
            &binary_options("tcp", Some(&plain))[0]
        ));
        let picked = listing(vec![pick], &["afd.sys", "tcpip.sys"]);
        assert!(usable_unpicked("", &binary_options("", Some(&picked))[0]));
        // A candidate the pair left unchanged is listed, but not the pick.
        let unchanged = listing(vec![same], &["afd.sys", "tcpip.sys"]);
        let rows = binary_options("", Some(&unchanged));
        assert_eq!(rows[0].kind, OptionKind::Candidate);
        assert!(!usable_unpicked("", &rows[0]));
    }

    #[test]
    fn rows_carry_how_the_pair_changed_the_file() {
        let mut files = listing(vec![], &["afd.sys", "tcpip.sys", "x.sys"]);
        files.files.changes = Some(
            [
                (
                    "afd.sys".to_string(),
                    Change::Changed {
                        before: None,
                        after: None,
                    },
                ),
                ("tcpip.sys".to_string(), Change::Same),
            ]
            .into(),
        );
        let rows: Vec<(String, Option<bool>)> = binary_options("", Some(&files))
            .into_iter()
            .map(|o| (o.name, o.changed))
            .collect();
        // Changed (or not yet known) binaries before unchanged ones.
        assert_eq!(
            rows,
            [
                ("afd.sys".to_string(), Some(true)),
                ("x.sys".to_string(), None),
                ("tcpip.sys".to_string(), Some(false)),
            ]
        );
    }

    #[test]
    fn binaries_come_before_other_files() {
        let files = listing(
            vec![],
            &[
                "0a1b-guid",
                "1.chunk.js",
                "afd.sys",
                "afd.sys.mui",
                "zz.dll",
            ],
        );
        let names: Vec<String> = binary_options("", Some(&files))
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert_eq!(
            names,
            [
                "afd.sys",
                "zz.dll",
                "0a1b-guid",
                "1.chunk.js",
                "afd.sys.mui"
            ]
        );
        let names: Vec<String> = binary_options("afd", Some(&files))
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert_eq!(names, ["afd.sys", "afd.sys.mui", "afd"]);
    }
}
