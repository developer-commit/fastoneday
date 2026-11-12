//! The four things a user does: browse CVEs, load one, see what the fixing
//! update carries, and fetch a before/after pair.

use std::time::Duration;

use super::{
    events::CveReport,
    policy::{REMOTE_READABLE_BUILD, build_major, rank_pairs},
    services::Services,
};
use crate::{
    acquire::{Hint, Materialized, Progress},
    detect::{self, Signals},
    domain::{
        Acquired, Arch, BinaryName, Candidate, CaseResult, CveDetail, CveId, CveSummary, Digest,
        Family, PatchPair, Side, UpdateRef,
    },
    error::{Error, Result},
    io::Cancel,
    sources::office::{Channel, RELEASE_NOTES_URL, Release, parse_release_notes},
};

const RECENT_TTL: Duration = Duration::from_secs(6 * 3600);
const RELEASES_TTL: Duration = Duration::from_secs(12 * 3600);

/// Recent Microsoft CVEs for the picker (cached for a few hours).
pub fn recent_cves(services: &Services) -> Result<Vec<CveSummary>> {
    if let Some(hit) =
        services
            .cache
            .load_json::<Vec<CveSummary>>("msrc", "recent", Some(RECENT_TTL))
    {
        return Ok(hit);
    }
    let list = services.msrc.recent(1000)?;
    services.cache.store_json("msrc", "recent", &list)?;
    Ok(list)
}

fn office_releases(services: &Services) -> Result<Vec<Release>> {
    if let Some(hit) =
        services
            .cache
            .load_json::<Vec<Release>>("office", "security-releases", Some(RELEASES_TTL))
    {
        return Ok(hit);
    }
    let html = services.http.get_text(
        RELEASE_NOTES_URL,
        "reading the Office security release notes",
    )?;
    let releases = parse_release_notes(&html);
    services
        .cache
        .store_json("office", "security-releases", &releases)?;
    Ok(releases)
}

/// MSRC metadata, every acquirable patch pair (ranked) and binary guesses.
pub fn load_cve(services: &Services, cve: &CveId) -> Result<CveReport> {
    let record = services.msrc.record(cve)?;
    let mut pairs = record.kb_pairs.clone();
    let mut unsupported = record.unsupported.clone();
    let mut office_app = None;
    let mentions_office = record.c2r_products.len()
        + record
            .kb_pairs
            .iter()
            .filter(|p| p.family == Family::OfficeMsi)
            .count()
        > 0
        || format!("{} {}", record.summary.title, record.summary.tag)
            .to_ascii_lowercase()
            .contains("office");
    if mentions_office {
        match office_releases(services) {
            Ok(releases) => {
                let (c2r, app, skipped) = click_to_run_pairs(cve, &record.c2r_products, &releases);
                pairs.extend(c2r);
                office_app = app;
                unsupported.extend(skipped);
            }
            Err(e) => unsupported.push(format!("Click-to-Run builds unavailable: {e}")),
        }
    }
    let detail = CveDetail {
        summary: record.summary,
        description: record.description,
        articles: record.articles,
        cwe: record.cwe,
        patches: rank_pairs(pairs),
        unsupported,
    };
    let candidates = detect::rank(&Signals {
        detail: &detail,
        office_app: office_app.as_deref(),
        package_names: None,
    });
    let remembered_binary = {
        let mut history = services.history.lock().expect("history");
        let remembered = history.last_binary(cve).map(str::to_owned);
        let _ = history.record(cve, &detail.summary.title, None);
        remembered
    };
    Ok(CveReport {
        detail,
        office_app,
        candidates,
        remembered_binary,
    })
}

/// Pairs for Click-to-Run products: the build of the release that fixed the
/// CVE, and the same channel's build from the previous security release.
///
/// The release notes are authoritative for Click-to-Run: when they list the
/// CVE but MSRC names no Click-to-Run product, the LTSC and Current channels
/// are offered for x64.
pub fn click_to_run_pairs(
    cve: &CveId,
    products: &[(String, Arch)],
    releases: &[Release],
) -> (Vec<PatchPair>, Option<String>, Vec<String>) {
    let Some((index, release)) = releases
        .iter()
        .enumerate()
        .find(|(_, r)| r.fixes(cve).is_some())
    else {
        let skipped = products
            .iter()
            .map(|(p, _)| format!("{p} (not listed in the Office security release notes)"))
            .collect();
        return (Vec::new(), None, skipped);
    };
    let app = release.fixes(cve).map(str::to_owned);
    let defaults: Vec<(String, Arch)>;
    let products = if products.is_empty() {
        defaults = vec![
            (
                "Microsoft Office LTSC 2024 (Click-to-Run)".to_owned(),
                Arch::X64,
            ),
            (
                "Microsoft Office LTSC 2021 (Click-to-Run)".to_owned(),
                Arch::X64,
            ),
            (
                "Microsoft 365 Apps for Enterprise (Current Channel)".to_owned(),
                Arch::X64,
            ),
        ];
        &defaults[..]
    } else {
        products
    };
    let mut pairs = Vec::new();
    let mut skipped = Vec::new();
    for (product, arch) in products {
        let Some(channel) = Channel::for_product(product) else {
            skipped.push(format!("{product} (unknown Click-to-Run channel)"));
            continue;
        };
        let labels = channel.release_labels();
        let (Some(after), Some(before)) = (
            release.build_for(labels),
            releases[index + 1..]
                .iter()
                .find_map(|r| r.build_for(labels)),
        ) else {
            skipped.push(format!(
                "{product} (no {} builds around {})",
                labels[0], release.date
            ));
            continue;
        };
        pairs.push(PatchPair {
            product: product.clone(),
            family: Family::OfficeC2r,
            arch: *arch,
            kind: format!("{} channel", channel.short()),
            before: UpdateRef::OfficeBuild {
                channel: channel.short().into(),
                version: before.build.clone(),
            },
            after: UpdateRef::OfficeBuild {
                channel: channel.short().into(),
                version: after.build.clone(),
            },
            fixed_build: Some(after.build.clone()),
        });
    }
    (pairs, app, skipped)
}

/// Binaries carried by the fixing update, and candidates re-ranked with
/// that knowledge. Returns `None` when it would require a large download.
pub fn package_names(
    services: &Services,
    report: &CveReport,
    pair: &PatchPair,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Option<(Vec<String>, Vec<Candidate>)>> {
    let Some(names) = services
        .engine
        .after_package_names(pair, false, progress, cancel)?
    else {
        return Ok(None);
    };
    let candidates = detect::rank(&Signals {
        detail: &report.detail,
        office_app: report.office_app.as_deref(),
        package_names: Some(&names),
    });
    Ok(Some((names, candidates)))
}

/// Like [`acquire_case`], but when `pair` cannot yield a verified binary yet
/// (baseline not reachable, decoder limitation) the next remote-readable rows
/// of the same family and architecture are tried. Used when the user kept
/// the recommended row.
pub fn acquire_case_with_fallback(
    services: &Services,
    report: &CveReport,
    pair: &PatchPair,
    binary: &BinaryName,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<CaseResult> {
    let first = match acquire_case(services, report, pair, binary, progress, cancel) {
        Ok(result) => return Ok(result),
        Err(e) if is_recoverable(&e) => e,
        Err(e) => return Err(e),
    };
    let alternatives = report
        .detail
        .patches
        .iter()
        .filter(|p| *p != pair && p.family == pair.family && p.arch == pair.arch && is_remote(p))
        .take(3);
    for alternative in alternatives {
        cancel.check()?;
        progress.note(format!(
            "{} could not be completed ({}); trying {} instead",
            pair.short_product(),
            first.category(),
            alternative.short_product()
        ));
        match acquire_case(services, report, alternative, binary, progress, cancel) {
            Ok(result) => return Ok(result),
            Err(e) if is_recoverable(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(first)
}

fn is_recoverable(error: &Error) -> bool {
    matches!(
        error,
        Error::NotFound(_) | Error::Integrity { .. } | Error::Unsupported(_)
    )
}

fn is_remote(pair: &PatchPair) -> bool {
    match pair.family {
        Family::OfficeC2r => true,
        Family::Windows => build_major(pair) >= REMOTE_READABLE_BUILD,
        Family::OfficeMsi => false,
    }
}

/// Fetches, verifies and writes both sides; returns the case summary.
pub fn acquire_case(
    services: &Services,
    report: &CveReport,
    pair: &PatchPair,
    binary: &BinaryName,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<CaseResult> {
    let cve = &report.detail.summary.id;
    progress.note(format!(
        "{cve} · {binary} · {} ({} → {})",
        pair.short_product(),
        pair.before,
        pair.after
    ));
    let after = services.engine.acquire(
        pair,
        Side::After,
        binary,
        &Hint::default(),
        progress,
        cancel,
    )?;
    cancel.check()?;
    let before = services.engine.acquire(
        pair,
        Side::Before,
        binary,
        &Hint::from(&after),
        progress,
        cancel,
    )?;
    if before.bytes == after.bytes {
        progress.note(format!(
            "warning: {binary} is identical in {} and {} — this update did not change it; the vulnerable code is elsewhere",
            pair.before, pair.after
        ));
    }

    let directory = services.workspace.case_dir(cve, binary, pair);
    let write = |side: Side, update: &UpdateRef, m: Materialized| -> Result<Acquired> {
        let path = services
            .workspace
            .write_side(&directory, side, binary.as_str(), &m.bytes)?;
        let pdb = if services.settings.fetch_pdbs {
            let step = progress.step(format!(
                "Symbol Server · PDB for the {} binary",
                side.label()
            ));
            match services.engine.pdb(&m.bytes) {
                Ok(Some((name, bytes))) => {
                    let path = services
                        .workspace
                        .write_side(&directory, side, &name, &bytes)?;
                    step.finish(format!("{name} ({} KB)", bytes.len() / 1024));
                    Some(path)
                }
                Ok(None) => {
                    step.finish("not published".into());
                    None
                }
                Err(e) => {
                    step.finish(format!("skipped: {e}"));
                    None
                }
            }
        } else {
            None
        };
        Ok(Acquired {
            side,
            update: update.clone(),
            name: binary.clone(),
            version: m.version,
            size: m.bytes.len() as u64,
            sha256: Digest::sha256(&m.bytes),
            verified_with: m.verified_with,
            how: m.how,
            path,
            pdb,
        })
    };
    let after = write(Side::After, &pair.after, after)?;
    let before = write(Side::Before, &pair.before, before)?;
    let result = CaseResult {
        cve: cve.clone(),
        pair: pair.clone(),
        binary: binary.clone(),
        directory: directory.clone(),
        before,
        after,
    };
    services.workspace.write_manifest(&result)?;
    let _ = services.history.lock().expect("history").record(
        cve,
        &report.detail.summary.title,
        Some(binary.as_str()),
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::office::ReleaseBuild;

    fn release(date: &str, build: &str, ltsc: &str, cves: &[&str]) -> Release {
        Release {
            date: date.into(),
            builds: vec![
                ReleaseBuild {
                    channel: "Current Channel".into(),
                    version: "2610".into(),
                    build: build.into(),
                },
                ReleaseBuild {
                    channel: "Office LTSC 2021 Volume Licensed".into(),
                    version: "2108".into(),
                    build: ltsc.into(),
                },
            ],
            apps: vec![(
                "Excel".into(),
                cves.iter().map(|c| CveId::parse(c).unwrap()).collect(),
            )],
        }
    }

    #[test]
    fn click_to_run_pairs_use_the_previous_release_as_before() {
        let releases = vec![
            release(
                "November 10, 2026",
                "16.0.20527.20196",
                "16.0.14334.21048",
                &["CVE-2026-116927"],
            ),
            release(
                "October 13, 2026",
                "16.0.20430.20182",
                "16.0.14334.21002",
                &["CVE-2026-100001"],
            ),
        ];
        let cve = CveId::parse("CVE-2026-116927").unwrap();
        let products = vec![
            (
                "Microsoft 365 Apps for Enterprise for 64-bit Systems".to_string(),
                Arch::X64,
            ),
            (
                "Microsoft Office LTSC 2021 for 64-bit editions".to_string(),
                Arch::X64,
            ),
            (
                "Microsoft Office LTSC 2024 for 64-bit editions".to_string(),
                Arch::X64,
            ),
        ];
        let (pairs, app, skipped) = click_to_run_pairs(&cve, &products, &releases);
        assert_eq!(app.as_deref(), Some("Excel"));
        assert_eq!(pairs.len(), 2);
        assert_eq!(
            pairs[1].before,
            UpdateRef::OfficeBuild {
                channel: "LTSC2021".into(),
                version: "16.0.14334.21002".into()
            }
        );
        assert_eq!(skipped.len(), 1);
    }
}
