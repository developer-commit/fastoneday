//! MSRC JSON → domain types.

use std::{collections::BTreeSet, sync::LazyLock};

use regex::Regex;
use serde_json::{Map, Value};

use crate::{
    domain::{Arch, CveId, CveSummary, Family, PatchPair, UpdateRef},
    error::{Error, Result},
};

static KB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:KB)?\s*([0-9]{6,8})\s*$").expect("regex"));
static KB_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:KB\s*)?([0-9]{6,8})").expect("regex"));
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("regex"));
static LAST_AFFECTED_ENGINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)last version[^0-9]{0,120}?affected[^0-9]{0,60}(1\.1\.\d{4,5}\.\d+)")
        .expect("regex")
});
static FIRST_FIXED_ENGINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)first version[^0-9]{0,160}?addressed[^0-9]{0,60}(1\.1\.\d{4,5}\.\d+)")
        .expect("regex")
});

/// What one CVE looks like after normalisation.
#[derive(Debug, Clone)]
pub struct MsrcRecord {
    pub summary: CveSummary,
    pub description: String,
    pub articles: Vec<String>,
    pub cwe: Vec<String>,
    /// Windows and MSI-Office rows with a before → after KB edge.
    pub kb_pairs: Vec<PatchPair>,
    /// Click-to-Run Office rows (MSRC gives no build; resolved elsewhere).
    pub c2r_products: Vec<(String, Arch)>,
    /// The Microsoft Defender antimalware engine row, when the CVE is fixed
    /// by an engine update.
    pub engine: Option<EngineFix>,
    /// Affected products we cannot acquire, with a reason.
    pub unsupported: Vec<String>,
}

/// An engine-fixed CVE: MSRC names the fixing engine version (and usually,
/// in the FAQ, the last affected one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFix {
    pub product: String,
    /// Last affected engine, when the FAQ states it.
    pub before: Option<String>,
    /// First fixed engine.
    pub after: String,
}

/// `(last affected, first fixed)` engine versions stated in FAQ text.
pub fn engine_versions(articles: &[String]) -> (Option<String>, Option<String>) {
    let find = |re: &Regex| {
        articles
            .iter()
            .find_map(|a| re.captures(a).map(|c| c[1].to_owned()))
    };
    (find(&LAST_AFFECTED_ENGINE), find(&FIRST_FIXED_ENGINE))
}

pub fn normalize_summary(row: &Value) -> Option<CveSummary> {
    let row = row.as_object()?;
    if text(row, "issuingCna").is_some_and(|cna| cna != "Microsoft") || truthy(row, "isMariner") {
        return None;
    }
    Some(CveSummary {
        id: CveId::parse(text(row, "cveNumber")?).ok()?,
        title: text(row, "cveTitle").unwrap_or_default().trim().to_owned(),
        tag: text(row, "tag").unwrap_or_default().trim().to_owned(),
        released: text(row, "releaseDate")
            .unwrap_or_default()
            .chars()
            .take(10)
            .collect(),
        severity: text(row, "severity").unwrap_or_default().to_owned(),
        impact: text(row, "impact").unwrap_or_default().to_owned(),
        exploited: text(row, "exploited").is_some_and(|v| v.eq_ignore_ascii_case("yes")),
    })
}

pub fn normalize_detail(
    cve: &CveId,
    vulnerability: &Value,
    products: &Value,
) -> Result<MsrcRecord> {
    let info = vulnerability
        .as_object()
        .ok_or_else(|| Error::format("MSRC vulnerability", "not a JSON object"))?;
    let returned = text(info, "cveNumber").unwrap_or(cve.as_str());
    if !returned.eq_ignore_ascii_case(cve.as_str()) {
        return Err(Error::format(
            "MSRC vulnerability",
            format!("asked for {cve}, got {returned}"),
        ));
    }
    let summary = CveSummary {
        id: cve.clone(),
        title: text(info, "cveTitle").unwrap_or_default().trim().to_owned(),
        tag: text(info, "tag").unwrap_or_default().trim().to_owned(),
        released: text(info, "releaseDate")
            .unwrap_or_default()
            .chars()
            .take(10)
            .collect(),
        severity: text(info, "severity").unwrap_or_default().to_owned(),
        impact: text(info, "impact").unwrap_or_default().to_owned(),
        exploited: text(info, "exploited").is_some_and(|v| v.eq_ignore_ascii_case("yes")),
    };
    let description = {
        let raw = text(info, "unformattedDescription")
            .filter(|s| !s.trim().is_empty())
            .or_else(|| text(info, "description"))
            .unwrap_or_default();
        plain_text(raw)
    };
    let articles: Vec<String> = array(info, "articles")
        .iter()
        .filter_map(Value::as_object)
        .map(|a| {
            plain_text(&format!(
                "{} {}",
                text(a, "title").unwrap_or_default(),
                text(a, "description").unwrap_or_default()
            ))
        })
        .filter(|s| !s.is_empty())
        .collect();
    let cwe = array(info, "cweList")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut kb_pairs = Vec::new();
    let mut c2r_products = Vec::new();
    let mut engine = None;
    let mut unsupported = BTreeSet::new();
    let rows = products
        .as_object()
        .map(|o| array(o, "value"))
        .ok_or_else(|| Error::format("MSRC affected products", "not a JSON object"))?;
    for row in rows.iter().filter_map(Value::as_object) {
        let product = text(row, "product").unwrap_or_default().trim().to_owned();
        let family_name = text(row, "productFamily").unwrap_or_default();
        let lower = product.to_ascii_lowercase();
        if lower.contains("malware protection engine") {
            let (faq_before, faq_after) = engine_versions(&articles);
            let fixed = array(row, "kbArticles")
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|a| a.get("fixedBuildNumber").map(value_text))
                .find(|v| crate::sources::defender::is_engine_version(v));
            match fixed.or(faq_after) {
                Some(after) if engine.is_none() => {
                    engine = Some(EngineFix {
                        product: product.clone(),
                        before: faq_before,
                        after,
                    });
                }
                Some(_) => {}
                None => {
                    unsupported.insert(format!(
                        "{product} (MSRC does not name the engine version with the fix)"
                    ));
                }
            }
            continue;
        }
        let family = match family_name {
            "Windows" | "ESU" => Some(Family::Windows),
            "Microsoft Office" => Some(Family::OfficeMsi),
            _ => None,
        };
        let Some(family) = family else {
            let reason = if lower.contains("antimalware platform") {
                "Defender platform updates are not supported yet; engine updates are".to_owned()
            } else if family_name.is_empty() {
                "MSRC lists no product family".to_owned()
            } else {
                format!("{family_name} products are not supported")
            };
            unsupported.insert(format!("{product} ({reason})"));
            continue;
        };
        let Some(arch) = architecture(
            text(row, "architecture").unwrap_or_default(),
            &product,
            text(row, "cpe").unwrap_or_default(),
        ) else {
            unsupported.insert(format!(
                "{product} (MSRC does not say which CPU architecture)"
            ));
            continue;
        };
        for article in array(row, "kbArticles").iter().filter_map(Value::as_object) {
            let name = article
                .get("articleName")
                .map(value_text)
                .unwrap_or_default();
            if family == Family::OfficeMsi && name.eq_ignore_ascii_case("Click to Run") {
                if !c2r_products
                    .iter()
                    .any(|(p, a)| p == &product && *a == arch)
                {
                    c2r_products.push((product.clone(), arch));
                }
                continue;
            }
            let Some(after) = KB.captures(&name).map(|c| format!("KB{}", &c[1])) else {
                continue;
            };
            let before: BTreeSet<String> = article
                .get("supercedence")
                .map(value_text)
                .map(|s| {
                    KB_LIST
                        .captures_iter(&s)
                        .map(|c| format!("KB{}", &c[1]))
                        .collect()
                })
                .unwrap_or_default();
            if before.is_empty() {
                unsupported.insert(format!(
                    "{product} {after} (MSRC lists no superseded update)"
                ));
                continue;
            }
            let kind = update_kind(family, article);
            for before in before.into_iter().filter(|b| *b != after) {
                let pair = PatchPair {
                    product: product.clone(),
                    family,
                    arch,
                    kind: kind.clone(),
                    before: UpdateRef::kb(before),
                    after: UpdateRef::kb(after.clone()),
                    fixed_build: article
                        .get("fixedBuildNumber")
                        .map(value_text)
                        .filter(|s| !s.is_empty()),
                };
                if !kb_pairs.contains(&pair) {
                    kb_pairs.push(pair);
                }
            }
        }
    }
    Ok(MsrcRecord {
        summary,
        description,
        articles,
        cwe,
        kb_pairs,
        c2r_products,
        engine,
        unsupported: unsupported.into_iter().collect(),
    })
}

/// MSRC's download name, except that a Windows "Security Update" needing no
/// reboot is a hotpatch: MSRC lists it next to the cumulative update of the
/// same product, with the same name and a different KB and build.
fn update_kind(family: Family, article: &Map<String, Value>) -> String {
    let name = text(article, "downloadName").unwrap_or_default().trim();
    let no_reboot = article
        .get("rebootRequired")
        .map(value_text)
        .is_some_and(|v| v.eq_ignore_ascii_case("no"));
    if family == Family::Windows
        && no_reboot
        && (name.is_empty() || name.eq_ignore_ascii_case("security update"))
    {
        "Hotpatch".into()
    } else {
        name.to_owned()
    }
}

fn architecture(value: &str, product: &str, cpe: &str) -> Option<Arch> {
    let product = product.to_ascii_lowercase();
    let cpe = cpe.to_ascii_lowercase();
    let value = value.trim().to_ascii_lowercase();
    let arm64 = product.contains("arm64") || cpe.contains(":arm64:");
    match value.as_str() {
        "x64" | "amd64" => Some(Arch::X64),
        "x86" => Some(Arch::X86),
        "arm64" => Some(Arch::Arm64),
        "arm" if arm64 => Some(Arch::Arm64),
        "arm" => None,
        _ if arm64 => Some(Arch::Arm64),
        _ if product.contains("32-bit") || product.contains("x86") => Some(Arch::X86),
        _ if product.contains("x64")
            || product.contains("64-bit")
            || product.contains("server") =>
        {
            Some(Arch::X64)
        }
        _ => None,
    }
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

fn truthy(object: &Map<String, Value>, field: &str) -> bool {
    match object.get(field) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn array<'a>(object: &'a Map<String, Value>, field: &str) -> &'a [Value] {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn plain_text(value: &str) -> String {
    let stripped = TAG.replace_all(value, " ");
    let decoded = stripped
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cve() -> CveId {
        CveId::parse("CVE-2024-38193").unwrap()
    }

    fn vuln() -> Value {
        json!({"cveNumber": "CVE-2024-38193", "cveTitle": "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
               "tag": "Windows Ancillary Function Driver for WinSock", "exploited": "Yes", "releaseDate": "2024-08-13T07:00:00Z",
               "articles": [{"title": "FAQ", "description": "<p>What <b>privileges</b>?</p>"}], "cweList": ["CWE-416: Use After Free"]})
    }

    #[test]
    fn builds_kb_pairs_and_collects_click_to_run_rows() {
        let products = json!({"value": [
            {"product": "Windows 11 Version 24H2 for x64-based Systems", "productFamily": "Windows", "architecture": "x64",
             "kbArticles": [{"articleName": "5041571", "downloadName": "Security Update", "supercedence": "5040435", "fixedBuildNumber": "10.0.26100.1457"}]},
            {"product": "Windows 11 Version 24H2 for ARM64-based Systems", "productFamily": "Windows", "architecture": "ARM",
             "kbArticles": [{"articleName": "5041571", "downloadName": "Security Update", "supercedence": "5040435"}]},
            {"product": "Microsoft 365 Apps for Enterprise for 64-bit Systems", "productFamily": "Microsoft Office", "architecture": "x64",
             "kbArticles": [{"articleName": "Click to Run", "downloadName": "Security Update"}]},
            {"product": "Microsoft Office 2016 (64-bit edition)", "productFamily": "Microsoft Office", "architecture": "x64",
             "kbArticles": [{"articleName": "5002620", "downloadName": "Security Update", "supercedence": "5002591"}]},
            {"product": "Windows 10 for 32-bit Systems", "productFamily": "Windows", "architecture": "x86",
             "kbArticles": [{"articleName": "5041782", "downloadName": "Security Update", "supercedence": "5041782"}]},
            {"product": "Visual Studio 2022", "productFamily": "Developer Tools", "architecture": "x64", "kbArticles": []}
        ]});
        let record = normalize_detail(&cve(), &vuln(), &products).unwrap();
        assert!(record.summary.exploited);
        assert_eq!(record.articles, vec!["FAQ What privileges ?".to_string()]);
        assert_eq!(record.kb_pairs.len(), 3);
        assert_eq!(record.kb_pairs[0].after, UpdateRef::kb("KB5041571"));
        assert_eq!(
            record.kb_pairs[0].fixed_build.as_deref(),
            Some("10.0.26100.1457")
        );
        assert_eq!(record.kb_pairs[1].arch, Arch::Arm64);
        assert_eq!(record.kb_pairs[2].family, Family::OfficeMsi);
        assert_eq!(
            record.c2r_products,
            vec![(
                "Microsoft 365 Apps for Enterprise for 64-bit Systems".to_string(),
                Arch::X64
            )]
        );
        assert_eq!(record.unsupported.len(), 1);
        assert_eq!(
            record.unsupported[0],
            "Visual Studio 2022 (Developer Tools products are not supported)"
        );
    }

    #[test]
    fn a_windows_update_without_reboot_is_a_hotpatch() {
        let products = json!({"value": [
            {"product": "Windows Server 2025", "productFamily": "Windows", "architecture": "x64",
             "kbArticles": [
                {"articleName": "5131080", "downloadName": "Security Update", "supercedence": "5126646",
                 "fixedBuildNumber": "10.0.26100.33822", "rebootRequired": "Yes"},
                {"articleName": "5131077", "downloadName": "Security Update", "supercedence": "5126646",
                 "fixedBuildNumber": "10.0.26100.33730", "rebootRequired": "No"}]},
            {"product": "Microsoft Office 2016 (64-bit edition)", "productFamily": "Microsoft Office", "architecture": "x64",
             "kbArticles": [{"articleName": "5002620", "downloadName": "Security Update", "supercedence": "5002591", "rebootRequired": "No"}]}
        ]});
        let record = normalize_detail(&cve(), &vuln(), &products).unwrap();
        let kinds: Vec<(String, &str)> = record
            .kb_pairs
            .iter()
            .map(|p| (p.after.label(), p.kind.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("KB5131080".to_string(), "Security Update"),
                ("KB5131077".to_string(), "Hotpatch"),
                ("KB5002620".to_string(), "Security Update")
            ]
        );
    }

    #[test]
    fn reads_defender_engine_versions_from_the_faq() {
        let vulnerability = json!({"cveNumber": "CVE-2024-38193", "cveTitle": "Microsoft Defender Elevation of Privilege Vulnerability",
            "articles": [{"title": "", "description": "<p>Last version of the Microsoft Malware Protection Engine affected by this vulnerability</p><p>1.1.26050.11</p><p>First version of the Microsoft Malware Protection Engine with this vulnerability addressed</p><p>1.1.26060.3008</p>"}]});
        let products = json!({"value": [
            {"product": "Microsoft Malware Protection Engine", "productFamily": "System Center", "architecture": null,
             "kbArticles": [{"articleName": "Release Notes", "downloadName": "Security Update", "fixedBuildNumber": "1.1.26060.3008"}]},
            {"product": "Microsoft Defender Antimalware Platform", "productFamily": "System Center", "architecture": null,
             "kbArticles": [{"articleName": "Release Notes", "fixedBuildNumber": "4.18.26060.3008"}]}
        ]});
        let record = normalize_detail(&cve(), &vulnerability, &products).unwrap();
        assert_eq!(
            record.engine,
            Some(EngineFix {
                product: "Microsoft Malware Protection Engine".into(),
                before: Some("1.1.26050.11".into()),
                after: "1.1.26060.3008".into(),
            })
        );
        assert!(record.kb_pairs.is_empty());
        assert_eq!(
            record.unsupported,
            [
                "Microsoft Defender Antimalware Platform (Defender platform updates are not supported yet; engine updates are)"
            ]
        );
    }

    #[test]
    fn skips_third_party_cves_in_listings() {
        assert!(
            normalize_summary(&json!({"cveNumber": "CVE-2026-0001", "issuingCna": "Chrome"}))
                .is_none()
        );
        let s = normalize_summary(&json!({"cveNumber": "CVE-2026-0002", "issuingCna": "Microsoft", "cveTitle": " X ", "releaseDate": "2026-11-10T08:00:00-08:00"})).unwrap();
        assert_eq!(s.title, "X");
        assert_eq!(s.released, "2026-11-10");
    }
}
