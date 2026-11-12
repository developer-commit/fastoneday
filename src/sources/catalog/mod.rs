//! Microsoft Update Catalog: KB → update entry → package file(s).
//!
//! This is the single source of truth for Windows and MSI-Office binaries:
//! every byte we hand out is either inside the package it returns or is
//! verified against a hash that package carries.

mod parse;
mod select;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use parse::{CatalogUpdate, PackageFile};
pub use select::{pick_update, title_matches_product};

use crate::{
    domain::Arch,
    error::{Error, Result},
    net::{Http, encode_query},
};

const SEARCH: &str = "https://www.catalog.update.microsoft.com/Search.aspx";
const DOWNLOAD_DIALOG: &str = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx";

/// The catalog entry chosen for a KB/product/arch and its downloadable files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPackage {
    pub kb: String,
    pub update: CatalogUpdate,
    /// The KB's own package first, then prerequisites (e.g. the checkpoint
    /// cumulative update of Windows 11 24H2 and later).
    pub files: Vec<PackageFile>,
}

impl CatalogPackage {
    pub fn primary(&self) -> &PackageFile {
        &self.files[0]
    }

    pub fn prerequisites(&self) -> &[PackageFile] {
        &self.files[1..]
    }
}

pub struct CatalogClient {
    http: Arc<Http>,
}

impl CatalogClient {
    pub fn new(http: Arc<Http>) -> Self {
        Self { http }
    }

    pub fn search(&self, query: &str) -> Result<Vec<CatalogUpdate>> {
        let url = format!("{SEARCH}?{}", encode_query(&[("q", query)]));
        let html = self
            .http
            .get_text(&url, &format!("searching the Update Catalog for {query}"))?;
        parse::search_results(&html)
    }

    pub fn files(&self, update: &CatalogUpdate) -> Result<Vec<PackageFile>> {
        let ids = serde_json::json!([{"size": 0, "uidInfo": update.id, "updateID": update.id}])
            .to_string();
        let html = self.http.post_form(
            DOWNLOAD_DIALOG,
            &[("updateIDs", ids.as_str())],
            &format!("listing files of {}", update.title),
        )?;
        parse::download_dialog(&html, &update.id)
    }

    /// Finds the update for `kb` matching the product and architecture and
    /// lists its files, the KB's own package first.
    pub fn package(&self, kb: &str, product: &str, arch: Arch) -> Result<CatalogPackage> {
        let updates = self.search(kb)?;
        if updates.is_empty() {
            return Err(Error::NotFound(format!(
                "the Update Catalog no longer lists {kb} (Microsoft removes some superseded updates); \
                 pick a newer product row"
            )));
        }
        let update = pick_update(&updates, kb, product, arch)?;
        let mut files = self.files(&update)?;
        let kb_lower = kb.to_ascii_lowercase();
        files.sort_by_key(|f| !f.name.to_ascii_lowercase().contains(&kb_lower));
        if files.is_empty() {
            return Err(Error::NotFound(format!(
                "{} has no downloadable files",
                update.title
            )));
        }
        Ok(CatalogPackage {
            kb: kb.to_owned(),
            update,
            files,
        })
    }
}
