//! HTML/JS scraping of catalog pages.

use std::{collections::BTreeMap, sync::LazyLock};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    domain::to_hex,
    error::{Error, Result},
};

const GUID: &str = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}";

static ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<tr[^>]+id=["'](?P<id>{GUID})_R\d+["'][^>]*>(?P<body>.*?)</tr>"#
    ))
    .expect("regex")
});
static CELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<td[^>]+id=["'](?P<id>{GUID})_C(?P<cell>[1-7])_R\d+["'][^>]*>(?P<body>.*?)</td>"#
    ))
    .expect("regex")
});
static SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)<span[^>]+id=["'](?P<id>{GUID})_originalSize["'][^>]*>(?P<size>.*?)</span>"#
    ))
    .expect("regex")
});
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("regex"));
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)downloadInformation\[(?P<group>\d+)](?:\.files\[(?P<file>\d+)])?\.(?P<field>updateID|url|digest|sha256|fileName)\s*=\s*'(?P<value>(?:\\.|[^'])*)'\s*;"#,
    )
    .expect("regex")
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogUpdate {
    pub id: String,
    pub title: String,
    pub products: String,
    pub classification: String,
    pub last_updated: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageFile {
    pub url: String,
    pub name: String,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

pub fn search_results(html: &str) -> Result<Vec<CatalogUpdate>> {
    if html.contains("ctl00_catalogBody_noResultText") {
        return Ok(Vec::new());
    }
    if !html.contains("ctl00_catalogBody_updateMatches") {
        return Err(Error::format(
            "Update Catalog search page",
            "results table is missing",
        ));
    }
    let mut out = Vec::new();
    for row in ROW.captures_iter(html) {
        let id = row["id"].to_ascii_lowercase();
        let body = &row["body"];
        let mut cells = BTreeMap::new();
        for cell in CELL.captures_iter(body) {
            if cell["id"].eq_ignore_ascii_case(&id) {
                cells.insert(
                    cell["cell"].parse::<u8>().unwrap_or(0),
                    clean(&cell["body"]),
                );
            }
        }
        let size = SIZE
            .captures(body)
            .and_then(|c| clean(&c["size"]).parse::<u64>().ok())
            .unwrap_or(0);
        out.push(CatalogUpdate {
            id,
            title: cells.remove(&1).unwrap_or_default(),
            products: cells.remove(&2).unwrap_or_default(),
            classification: cells.remove(&3).unwrap_or_default(),
            last_updated: cells.remove(&4).unwrap_or_default(),
            size,
        });
    }
    Ok(out)
}

pub fn download_dialog(html: &str, update_id: &str) -> Result<Vec<PackageFile>> {
    let mut groups: BTreeMap<usize, String> = BTreeMap::new();
    let mut files: BTreeMap<(usize, usize), BTreeMap<String, String>> = BTreeMap::new();
    for c in ASSIGNMENT.captures_iter(html) {
        let group: usize = c["group"].parse().unwrap_or(0);
        let value = c["value"].replace("\\'", "'").replace("\\\\", "\\");
        match c.name("file") {
            Some(file) => {
                files
                    .entry((group, file.as_str().parse().unwrap_or(0)))
                    .or_default()
                    .insert(c["field"].to_owned(), value);
            }
            None if &c["field"] == "updateID" => {
                groups.insert(group, value);
            }
            None => {}
        }
    }
    let mut out = Vec::new();
    for ((group, _), fields) in files {
        if !groups
            .get(&group)
            .is_some_and(|id| id.eq_ignore_ascii_case(update_id))
        {
            continue;
        }
        let url = fields.get("url").cloned().unwrap_or_default();
        let name = fields
            .get("fileName")
            .cloned()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| url.rsplit('/').next().unwrap_or_default().to_owned());
        validate_url(&url)?;
        out.push(PackageFile {
            sha1: digest(fields.get("digest"), 20)?,
            sha256: digest(fields.get("sha256"), 32)?,
            url,
            name,
        });
    }
    if out.is_empty() {
        return Err(Error::format(
            "Update Catalog download dialog",
            "no download links",
        ));
    }
    Ok(out)
}

fn digest(value: Option<&String>, len: usize) -> Result<Option<String>> {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(value)
        .map_err(|e| Error::format("Update Catalog digest", e.to_string()))?;
    if bytes.len() != len {
        return Err(Error::format("Update Catalog digest", "unexpected length"));
    }
    Ok(Some(to_hex(&bytes)))
}

/// Only Microsoft download hosts over HTTP(S) are accepted.
fn validate_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| {
            Error::format("Update Catalog link", format!("unexpected scheme in {url}"))
        })?;
    let host = rest
        .split(['/', ':', '?'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let trusted = [
        "windowsupdate.com",
        "download.microsoft.com",
        "delivery.mp.microsoft.com",
    ]
    .iter()
    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")));
    if trusted {
        Ok(())
    } else {
        Err(Error::format(
            "Update Catalog link",
            format!("untrusted host {host}"),
        ))
    }
}

fn clean(html: &str) -> String {
    TAG.replace_all(html, " ")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_file_dialogs_in_order() {
        let html = concat!(
            "downloadInformation[0].updateID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';",
            "downloadInformation[0].files[0].url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/f/windows11.0-kb5043080-x64_ab.msu';",
            "downloadInformation[0].files[0].digest = 'K2eFWl5zx6hz5r3KUSyMEGtCkZY=';",
            "downloadInformation[0].files[0].fileName = 'windows11.0-kb5043080-x64_ab.msu';",
            "downloadInformation[0].files[1].url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/f/windows11.0-kb5132061-x64_cd.msu';",
            "downloadInformation[0].files[1].fileName = 'windows11.0-kb5132061-x64_cd.msu';",
        );
        let files = download_dialog(html, "AAAAAAAA-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0].sha1.as_deref(),
            Some("2b67855a5e73c7a873e6bdca512c8c106b429196")
        );
        assert!(files[1].name.contains("kb5132061"));
    }

    #[test]
    fn rejects_lookalike_hosts() {
        assert!(
            validate_url("https://catalog.sf.dl.delivery.mp.microsoft.com.evil.example/x.msu")
                .is_err()
        );
        assert!(validate_url("https://download.windowsupdate.com/c/x.msu").is_ok());
        assert!(validate_url("ftp://download.windowsupdate.com/x.msu").is_err());
    }

    #[test]
    fn empty_search_is_not_an_error() {
        assert!(
            search_results("<span id=\"ctl00_catalogBody_noResultText\">")
                .unwrap()
                .is_empty()
        );
    }
}
