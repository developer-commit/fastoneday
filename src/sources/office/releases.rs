//! "Release notes for Microsoft Office security updates" on Microsoft Learn:
//! one section per security release, listing the build of every channel and
//! the CVEs fixed, grouped by application.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::domain::CveId;

pub const RELEASE_NOTES_URL: &str =
    "https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates";

static SECTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<h2[^>]*>\s*([^<]+?)\s*</h2>"#).expect("regex"));
static BUILD_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)([A-Za-z0-9 ()\-]+?)\s*:\s*Version\s+(\d{4})\s*\(Build\s+(\d+\.\d+)\)")
        .expect("regex")
});
static APP_HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)^<h3[^>]*>\s*(.*?)\s*</h3>"#).expect("regex"));
static CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"CVE-\d{4}-\d{4,7}").expect("regex"));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBuild {
    /// Channel label as written on the page, e.g. `Current Channel`.
    pub channel: String,
    /// Feature version, e.g. `2610`.
    pub version: String,
    /// Full build, e.g. `16.0.20527.20196`.
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// Heading text, e.g. `November 10, 2026`.
    pub date: String,
    pub builds: Vec<ReleaseBuild>,
    /// `(application, CVEs)`, e.g. `("Excel", [...])`.
    pub apps: Vec<(String, Vec<CveId>)>,
}

impl Release {
    pub fn fixes(&self, cve: &CveId) -> Option<&str> {
        self.apps
            .iter()
            .find(|(_, cves)| cves.contains(cve))
            .map(|(app, _)| app.as_str())
    }

    /// The (newest) build listed for a channel label or one of its aliases.
    pub fn build_for(&self, labels: &[&str]) -> Option<&ReleaseBuild> {
        self.builds
            .iter()
            .find(|b| labels.iter().any(|l| b.channel.eq_ignore_ascii_case(l)))
    }
}

/// Newest release first, as on the page.
pub fn parse_release_notes(html: &str) -> Vec<Release> {
    let headings: Vec<(usize, usize, String)> = SECTION
        .captures_iter(html)
        .map(|c| {
            let m = c.get(0).expect("match");
            (m.start(), m.end(), c[1].trim().to_owned())
        })
        .filter(|(_, _, title)| {
            title.split_whitespace().count() == 3 && title.chars().any(|c| c.is_ascii_digit())
        })
        .collect();
    let mut releases = Vec::new();
    for (i, (_, end, date)) in headings.iter().enumerate() {
        let stop = headings.get(i + 1).map(|h| h.0).unwrap_or(html.len());
        let body = &html[*end..stop];
        let first_app = body.find("<h3").unwrap_or(body.len());
        let builds_html = body[..first_app]
            .replace("<br>", "\n")
            .replace("<br/>", "\n");
        let builds = BUILD_LINE
            .captures_iter(&strip_tags(&builds_html))
            .map(|c| ReleaseBuild {
                channel: normalize_channel(c[1].trim()),
                version: c[2].to_owned(),
                build: format!("16.0.{}", &c[3]),
            })
            .collect::<Vec<_>>();
        let apps = split_keep(&body[first_app..], "<h3")
            .into_iter()
            .filter_map(|section| {
                let heading = APP_HEADING.captures(section)?;
                let name = strip_tags(&heading[1]).trim().to_owned();
                let mut cves = CVE
                    .find_iter(&section[heading.get(0)?.end()..])
                    .filter_map(|m| CveId::parse(m.as_str()).ok())
                    .collect::<Vec<_>>();
                cves.sort();
                cves.dedup();
                (!cves.is_empty()).then_some((name, cves))
            })
            .collect();
        if !builds.is_empty() {
            releases.push(Release {
                date: date.clone(),
                builds,
                apps,
            });
        }
    }
    releases
}

/// Splits `text` before every occurrence of `marker` (keeping the marker).
fn split_keep<'a>(text: &'a str, marker: &str) -> Vec<&'a str> {
    let mut starts: Vec<usize> = text.match_indices(marker).map(|(i, _)| i).collect();
    starts.push(text.len());
    starts.windows(2).map(|w| &text[w[0]..w[1]]).collect()
}

fn strip_tags(html: &str) -> String {
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("regex"));
    TAG.replace_all(html, "").replace("&amp;", "&")
}

/// `Semi-Annual Enterprise Channel (receives ...)` → `Semi-Annual Enterprise Channel`.
fn normalize_channel(label: &str) -> String {
    label.split(" (").next().unwrap_or(label).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<h2 id="november-10-2026">November 10, 2026</h2>
<p>Current Channel: Version 2610 (Build 20527.20196)<br>
Semi-Annual Enterprise Channel (receives Monthly Enterprise Channel builds): Version 2610 (Build 20527.20192)<br>
Office LTSC 2021 Volume Licensed: Version 2108 (Build 14334.21048)</p>
<h3 id="excel">Excel</h3>
<ul><li><a href="x">CVE-2026-116927</a></li></ul>
<h3 id="office-suite">Office suite</h3>
<ul><li><a href="x">CVE-2026-110068</a></li></ul>
<h3 id="outlook">Outlook</h3>
<ul><li><a href="x">CVE-2026-119996</a></li></ul>
<h2 id="october-13-2026">October 13, 2026</h2>
<p>Current Channel: Version 2609 (Build 20430.20182)<br>
Office LTSC 2021 Volume Licensed: Version 2108 (Build 14334.21002)</p>
<h3 id="word">Word</h3><ul><li>CVE-2026-100001</li></ul>"#;

    #[test]
    fn parses_sections_builds_and_apps() {
        let releases = parse_release_notes(PAGE);
        assert_eq!(releases.len(), 2);
        let nov = &releases[0];
        assert_eq!(nov.date, "November 10, 2026");
        assert_eq!(
            nov.build_for(&["Current Channel"]).unwrap().build,
            "16.0.20527.20196"
        );
        assert_eq!(
            nov.build_for(&["Semi-Annual Enterprise Channel"])
                .unwrap()
                .version,
            "2610"
        );
        let cve = CveId::parse("CVE-2026-116927").unwrap();
        assert_eq!(nov.fixes(&cve), Some("Excel"));
        assert_eq!(nov.apps.len(), 3);
        assert_eq!(
            nov.fixes(&CveId::parse("CVE-2026-110068").unwrap()),
            Some("Office suite")
        );
        assert_eq!(
            nov.fixes(&CveId::parse("CVE-2026-119996").unwrap()),
            Some("Outlook")
        );
        assert_eq!(
            releases[1]
                .build_for(&["Office LTSC 2021 Volume Licensed"])
                .unwrap()
                .build,
            "16.0.14334.21002"
        );
    }
}
