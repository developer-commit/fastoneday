//! Microsoft Defender antimalware engine packages.
//!
//! The engine (`mpengine.dll`) ships inside the full security intelligence
//! package `mpam-fe.exe` on Microsoft's Defender CDN. A package is addressed
//! by its security intelligence version *and* the engine it carries, so the
//! engine version alone is not enough. Microsoft documents, for every engine
//! release, the security intelligence version it shipped with — in the
//! Defender release notes on Microsoft Learn. That table is the index; the
//! CDN is the only source of bytes.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::domain::Arch;

/// Recent Defender releases, then the older ("technical upgrade support")
/// list. Both use the same `Engine: … Security intelligence …: …` layout.
pub const RELEASE_NOTES: [&str; 2] = [
    "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases",
    "https://learn.microsoft.com/en-us/defender-endpoint/msda-updates-previous-versions-technical-upgrade-support",
];

const CDN: &str = "https://definitionupdates.microsoft.com/packages/content/mpam-fe.exe";

/// Files in `mpam-fe.exe` that are executables worth diffing.
pub const BINARIES: [&str; 2] = ["mpengine.dll", "mpsigstub.exe"];

/// One engine and the security intelligence versions documented with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineRelease {
    pub engine: String,
    /// In document order; the first one that the CDN still hosts is used.
    pub signatures: Vec<String>,
}

/// `(engine, security intelligence version)` pairs from a release-notes page.
pub fn parse_release_notes(html: &str) -> Vec<(String, String)> {
    static ENGINE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"Engine:\s*(1\.1\.\d{4,5}\.\d+)").expect("regex"));
    static SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"Security intelligence(?: update version)?:\s*(1\.\d{3,4}\.\d+\.\d+)")
            .expect("regex")
    });
    let text = page_text(html);
    let engines: Vec<(usize, usize, &str)> = ENGINE
        .captures_iter(&text)
        .map(|c| {
            let m = c.get(0).expect("match");
            (m.start(), m.end(), c.get(1).expect("group").as_str())
        })
        .collect();
    let signatures: Vec<(usize, &str)> = SIGNATURE
        .captures_iter(&text)
        .map(|c| {
            (
                c.get(0).expect("match").start(),
                c.get(1).expect("group").as_str(),
            )
        })
        .collect();
    let mut out = Vec::new();
    for (i, &(_, end, engine)) in engines.iter().enumerate() {
        // The security intelligence version that belongs to this engine
        // comes after it and before the next engine is mentioned.
        let limit = engines.get(i + 1).map_or(text.len(), |next| next.0);
        if let Some((_, signature)) = signatures
            .iter()
            .find(|(at, _)| *at >= end && *at < limit && *at - end < 400)
        {
            out.push((engine.to_owned(), (*signature).to_owned()));
        }
    }
    out
}

/// Folds pairs from several pages into one entry per engine, newest first.
pub fn merge(pages: &[Vec<(String, String)>]) -> Vec<EngineRelease> {
    let mut releases: Vec<EngineRelease> = Vec::new();
    for (engine, signature) in pages.iter().flatten() {
        match releases.iter_mut().find(|r| &r.engine == engine) {
            Some(release) => {
                if !release.signatures.contains(signature) {
                    release.signatures.push(signature.clone());
                }
            }
            None => releases.push(EngineRelease {
                engine: engine.clone(),
                signatures: vec![signature.clone()],
            }),
        }
    }
    releases.sort_by_key(|r| std::cmp::Reverse(version_key(&r.engine)));
    releases
}

/// The newest documented engine older than `engine`.
pub fn previous_engine<'a>(releases: &'a [EngineRelease], engine: &str) -> Option<&'a str> {
    let key = version_key(engine)?;
    releases
        .iter()
        .filter_map(|r| Some((version_key(&r.engine)?, r.engine.as_str())))
        .filter(|(k, _)| *k < key)
        .max_by_key(|(k, _)| *k)
        .map(|(_, e)| e)
}

/// `1.1.26060.3008` → `[1, 1, 26060, 3008]`.
pub fn version_key(version: &str) -> Option<[u32; 4]> {
    let mut parts = version.trim().split('.').map(str::parse::<u32>);
    let key = [
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    ];
    parts.next().is_none().then_some(key)
}

/// Whether `version` looks like an antimalware engine version (`1.1.x.y`).
pub fn is_engine_version(version: &str) -> bool {
    version_key(version).is_some_and(|k| k[0] == 1 && k[1] == 1)
}

/// The architecture name the Defender CDN uses.
pub fn cdn_arch(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "amd64",
        Arch::X86 => "x86",
        Arch::Arm64 => "arm64",
    }
}

/// Address of the full security intelligence package carrying `engine`.
pub fn package_url(signature: &str, engine: &str, arch: Arch) -> String {
    format!(
        "{CDN}?packageType=Signatures&packageVersion={signature}&arch={}&engineVersion={engine}",
        cdn_arch(arch)
    )
}

/// Readable text of an HTML page: no scripts, styles or tags.
fn page_text(html: &str) -> String {
    static BLOCKS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)<script\b.*?</script>|<style\b.*?</style>").expect("regex")
    });
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").expect("regex"));
    let text = BLOCKS.replace_all(html, " ");
    let text = TAG.replace_all(&text, " ");
    let text = text
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
        .replace("&#39;", "'")
        .replace("&quot;", "\"");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECENT: &str = r#"<div><h3>Linux 101.26052.0012</h3><p>July 2026 - Release version: 30.126052.0012.0 -
        Engine version: 1.1.26040.3001 - Signature version: 1.449.136.0</p>
        <h3>Windows Antivirus Platform 4.18.26060.3008 / Engine 1.1.26060.3008</h3>
        <p>June 2026 - Platform: 4.18.26060.3008 - Engine: 1.1.26060.3008 -
        Security intelligence: 1.455.25.0</p>
        <h3>Windows Antivirus Platform 4.18.26050.15 / Engine 1.1.26050.11</h3>
        <p>May 2026 - Platform: 4.18.26050.15 - Engine: <strong>1.1.26050.11</strong> -
        Security intelligence: 1.453.4.0</p><script>var x = "Engine: 1.1.1.1";</script></div>"#;

    const PREVIOUS: &str = r#"<h2>February-2026 (Platform: 4.18.26020.6 | Engine: 1.1.26020.3)</h2>
        <p>Security intelligence update version: <strong>1.447.2.0</strong><br>
        Release date: March 25, 2026 (Engine) / March 25, 2026 (Platform)<br>
        Platform: 4.18.26020.6<br>Engine: 1.1.26020.3<br>Support phase: ...</p>
        <h2>January-2026 (Platform: 4.18.26010.5 | Engine: 1.1.26010.1)</h2>
        <p>Security intelligence update version: <strong>1.445.6.0</strong></p>"#;

    #[test]
    fn pairs_each_engine_with_its_own_security_intelligence_version() {
        assert_eq!(
            parse_release_notes(RECENT),
            vec![
                ("1.1.26060.3008".to_owned(), "1.455.25.0".to_owned()),
                ("1.1.26050.11".to_owned(), "1.453.4.0".to_owned()),
            ]
        );
        assert_eq!(
            parse_release_notes(PREVIOUS),
            vec![
                ("1.1.26020.3".to_owned(), "1.447.2.0".to_owned()),
                ("1.1.26010.1".to_owned(), "1.445.6.0".to_owned()),
            ]
        );
    }

    #[test]
    fn merges_pages_and_finds_the_previous_engine() {
        let releases = merge(&[
            parse_release_notes(RECENT),
            parse_release_notes(PREVIOUS),
            vec![("1.1.26010.1".into(), "1.443.820.0".into())],
        ]);
        let engines: Vec<&str> = releases.iter().map(|r| r.engine.as_str()).collect();
        assert_eq!(
            engines,
            [
                "1.1.26060.3008",
                "1.1.26050.11",
                "1.1.26020.3",
                "1.1.26010.1"
            ]
        );
        assert_eq!(releases[3].signatures, ["1.445.6.0", "1.443.820.0"]);
        assert_eq!(
            previous_engine(&releases, "1.1.26060.3008"),
            Some("1.1.26050.11")
        );
        assert_eq!(previous_engine(&releases, "1.1.26010.1"), None);
    }

    #[test]
    fn builds_cdn_addresses() {
        assert!(is_engine_version("1.1.26060.3008"));
        assert!(!is_engine_version("4.18.26060.3008"));
        assert_eq!(
            package_url("1.455.25.0", "1.1.26060.3008", Arch::X64),
            "https://definitionupdates.microsoft.com/packages/content/mpam-fe.exe?packageType=Signatures&packageVersion=1.455.25.0&arch=amd64&engineVersion=1.1.26060.3008"
        );
    }
}
