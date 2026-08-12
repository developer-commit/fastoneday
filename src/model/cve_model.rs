use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One exact MSRC supersedence edge for a product, architecture, and update channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPatch {
    pub product_id: u64,
    pub os_version: String,
    pub architecture: String,
    pub update_kind: String,
    pub before_kb: String,
    pub after_kb: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsrcArticle {
    pub article_type: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveMetadata {
    pub title: String,
    pub cve_code: String,
    pub tag: String,
    pub impact: String,
    pub issuing_cna: String,
    pub is_mariner: bool,
    pub catalog: Vec<ProductPatch>,
    pub articles: Vec<MsrcArticle>,
    pub cwe_list: Vec<String>,
    pub release_date: String,
    pub latest_revision_date: String,
    pub description: String,
}

/// Owned snapshots of the two unmodified MSRC JSON responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsrcRawData {
    pub cve_code: String,
    pub vulnerability_response: Value,
    pub affected_product_response: Value,
    pub fetched_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsrcFetchResult {
    pub raw: MsrcRawData,
    pub normalized: CveMetadata,
}
