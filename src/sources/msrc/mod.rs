//! Microsoft Security Response Center "Security Update Guide" API.

mod normalize;

use std::sync::Arc;

pub use normalize::{MsrcRecord, normalize_detail, normalize_summary};

use crate::{
    domain::{CveId, CveSummary},
    error::{Error, Result},
    net::{Http, encode_query},
};

const BASE: &str = "https://api.msrc.microsoft.com/sug/v2.0/en-US";

pub struct MsrcClient {
    http: Arc<Http>,
}

impl MsrcClient {
    pub fn new(http: Arc<Http>) -> Self {
        Self { http }
    }

    /// Vulnerability metadata plus every affected product row.
    pub fn record(&self, cve: &CveId) -> Result<MsrcRecord> {
        let context = format!("fetching {cve} from MSRC");
        let vulnerability = self
            .http
            .get_json(&format!("{BASE}/vulnerability/{cve}"), &context)
            .map_err(|e| match e {
                Error::Http { status: 404, .. } => {
                    Error::NotFound(format!("MSRC has no record of {cve}"))
                }
                other => other,
            })?;
        let query = encode_query(&[
            ("$orderBy", "releaseDate desc"),
            ("$filter", &format!("cveNumber eq '{cve}'")),
        ]);
        let products = self
            .http
            .get_json(&format!("{BASE}/affectedProduct?{query}"), &context)?;
        normalize_detail(cve, &vulnerability, &products)
    }

    /// The most recent Microsoft-issued CVEs (newest first) for autocomplete.
    pub fn recent(&self, limit: usize) -> Result<Vec<CveSummary>> {
        let query = encode_query(&[
            ("$orderBy", "releaseDate desc"),
            ("$top", &limit.to_string()),
        ]);
        let payload = self.http.get_json(
            &format!("{BASE}/vulnerability?{query}"),
            "listing recent CVEs",
        )?;
        Ok(payload
            .get("value")
            .and_then(|v| v.as_array())
            .map(|rows| rows.iter().filter_map(normalize_summary).collect())
            .unwrap_or_default())
    }
}
