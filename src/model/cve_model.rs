use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BeforeKb {
    Available(String),
    Missing,
    Ambiguous(Vec<String>),
}

impl BeforeKb {
    pub fn selected(&self) -> Option<&str> {
        match self {
            Self::Available(kb) => Some(kb),
            Self::Missing | Self::Ambiguous(_) => None,
        }
    }

    pub fn candidates(&self) -> &[String] {
        match self {
            Self::Available(kb) => std::slice::from_ref(kb),
            Self::Ambiguous(candidates) => candidates,
            Self::Missing => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPatch {
    pub os_version: String,
    pub before_kb: BeforeKb,
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

#[cfg(test)]
mod tests {
    use super::BeforeKb;

    #[test]
    fn before_kb_encodes_selection_as_one_state() {
        let ambiguous = BeforeKb::Ambiguous(vec!["KB1".into(), "KB2".into()]);

        assert_eq!(ambiguous.selected(), None);
        assert_eq!(ambiguous.candidates(), ["KB1", "KB2"]);
    }
}
