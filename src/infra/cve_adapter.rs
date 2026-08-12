use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::LazyLock,
    thread,
    time::Duration,
};

use regex::Regex;
use reqwest::blocking::Client;
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    errors::{CveError, MsrcEndpoint},
    model::cve::{CveMetadata, MsrcArticle, MsrcFetchResult, MsrcRawData, ProductPatch},
    port::CvePort,
};

const DEFAULT_BASE_URL: &str = "https://api.msrc.microsoft.com/sug/v2.0/en-US";

static KB_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bKB\s*([0-9]+)\b").expect("valid KB regex"));
static SUPERSEDENCE_KB_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\bKB\s*)?([0-9]+)\b").expect("valid supersedence KB regex")
});
static HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("valid HTML tag regex"));

#[derive(Debug, Clone)]
pub struct CveAdapter {
    client: Client,
    base_url: String,
    timeout: Duration,
    retries: u32,
    backoff: Duration,
}

impl Default for CveAdapter {
    fn default() -> Self {
        Self {
            client: Client::new(),
            base_url: DEFAULT_BASE_URL.into(),
            timeout: Duration::from_secs(30),
            retries: 2,
            backoff: Duration::from_millis(250),
        }
    }
}

impl CveAdapter {
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            ..Self::default()
        }
    }

    pub fn fetch_raw(&self, cve_code: &str) -> Result<MsrcRawData, CveError> {
        let cve_code = normalize_cve_code(cve_code)?;
        let vulnerability = self.get_json(
            MsrcEndpoint::Vulnerability,
            &format!("vulnerability/{cve_code}"),
            &[],
        )?;
        let affected_products = self.get_json(
            MsrcEndpoint::AffectedProduct,
            "affectedProduct",
            &[
                ("$orderBy", "releaseDate desc"),
                ("$filter", &format!("cveNumber eq '{cve_code}'")),
            ],
        )?;

        Ok(MsrcRawData {
            cve_code,
            vulnerability_response: vulnerability,
            affected_product_response: affected_products,
            fetched_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .expect("RFC 3339 can represent the current UTC time"),
        })
    }

    fn get_json(
        &self,
        endpoint: MsrcEndpoint,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<Value, CveError> {
        let url = format!("{}/{path}", self.base_url);

        for attempt in 0..=self.retries {
            let response = self
                .client
                .get(&url)
                .query(query)
                .timeout(self.timeout)
                .send();
            let response = match response {
                Ok(response) => response,
                Err(source) if attempt < self.retries => {
                    thread::sleep(self.backoff.saturating_mul(2_u32.saturating_pow(attempt)));
                    drop(source);
                    continue;
                }
                Err(source) => {
                    return Err(CveError::Network {
                        endpoint,
                        attempts: attempt + 1,
                        source: Box::new(source),
                    });
                }
            };

            let status = response.status();
            if !status.is_success() {
                let status_code = status.as_u16();
                if (status_code == 429 || status.is_server_error()) && attempt < self.retries {
                    thread::sleep(self.backoff.saturating_mul(2_u32.saturating_pow(attempt)));
                    continue;
                }
                return Err(CveError::Http {
                    endpoint,
                    status_code,
                });
            }

            let payload = response
                .json::<Value>()
                .map_err(|error| CveError::InvalidPayload {
                    endpoint,
                    reason: format!("malformed JSON: {error}"),
                })?;
            require_object(&payload, endpoint, "response")?;
            return Ok(payload);
        }

        unreachable!("the retry loop always returns on its final attempt")
    }
}

impl CvePort for CveAdapter {
    fn fetch(&self, cve_code: &str) -> Result<MsrcFetchResult, CveError> {
        let raw = self.fetch_raw(cve_code)?;
        let normalized = normalize_msrc(&raw)?;
        Ok(MsrcFetchResult { raw, normalized })
    }
}

pub fn normalize_cve_code(value: &str) -> Result<String, CveError> {
    let normalized = value.trim().to_ascii_uppercase();
    let mut parts = normalized.split('-');
    let valid = parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_some_and(|number| {
            number.len() >= 4 && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        && parts.next().is_none();

    if valid {
        Ok(normalized)
    } else {
        Err(CveError::InvalidCode {
            value: value.to_owned(),
        })
    }
}

pub fn normalize_msrc(raw: &MsrcRawData) -> Result<CveMetadata, CveError> {
    let info = require_object(
        &raw.vulnerability_response,
        MsrcEndpoint::Vulnerability,
        "response",
    )?;
    let affected = require_object(
        &raw.affected_product_response,
        MsrcEndpoint::AffectedProduct,
        "response",
    )?;

    let response_code = optional_text(info, "cveNumber", MsrcEndpoint::Vulnerability)?;
    let returned_code = response_code.as_deref().unwrap_or(&raw.cve_code);
    let cve_code = normalize_cve_code(returned_code).map_err(|_| CveError::InvalidPayload {
        endpoint: MsrcEndpoint::Vulnerability,
        reason: format!("cveNumber is invalid: {returned_code:?}"),
    })?;
    if cve_code != raw.cve_code {
        return Err(CveError::InvalidPayload {
            endpoint: MsrcEndpoint::Vulnerability,
            reason: format!("returned {cve_code} for requested {}", raw.cve_code),
        });
    }

    let products = optional_array(affected, "value", MsrcEndpoint::AffectedProduct)?;
    let mut patches =
        BTreeMap::<(String, String, String, String, String, u64), ProductPatch>::new();
    for (product_index, product) in products.iter().enumerate() {
        let product = require_object(
            product,
            MsrcEndpoint::AffectedProduct,
            &format!("value[{product_index}]"),
        )?;
        let os_version = optional_text(product, "product", MsrcEndpoint::AffectedProduct)?
            .unwrap_or_default()
            .trim()
            .to_owned();
        let product_id = product
            .get("productId")
            .and_then(Value::as_u64)
            .ok_or_else(|| CveError::InvalidPayload {
                endpoint: MsrcEndpoint::AffectedProduct,
                reason: format!("value[{product_index}].productId must be a non-negative integer"),
            })?;
        let cpe = optional_text(product, "cpe", MsrcEndpoint::AffectedProduct)?.unwrap_or_default();
        let architecture = normalize_architecture(
            optional_text(product, "architecture", MsrcEndpoint::AffectedProduct)?
                .as_deref()
                .unwrap_or_default(),
            &os_version,
            &cpe,
        );
        let articles = optional_array(product, "kbArticles", MsrcEndpoint::AffectedProduct)?;

        for (article_index, article) in articles.iter().enumerate() {
            let article = require_object(
                article,
                MsrcEndpoint::AffectedProduct,
                &format!("value[{product_index}].kbArticles[{article_index}]"),
            )?;
            // `supercedence` is a 0..N set of incoming edges, not a list from
            // which one predecessor should be guessed.
            let before_kbs =
                normalize_kb_candidates(article.get("supercedence")).map_err(|()| {
                    CveError::InvalidPayload {
                        endpoint: MsrcEndpoint::AffectedProduct,
                        reason: format!(
                            "value[{product_index}].kbArticles[{article_index}].supercedence \
                         must be a string or non-negative integer"
                        ),
                    }
                })?;
            if before_kbs.is_empty() {
                continue;
            }
            let after_kb = article
                .get("articleName")
                .and_then(normalize_kb)
                .ok_or_else(|| CveError::InvalidPayload {
                    endpoint: MsrcEndpoint::AffectedProduct,
                    reason: format!(
                        "value[{product_index}].kbArticles[{article_index}].articleName \
                         does not identify a patched KB"
                    ),
                })?;
            let update_kind =
                optional_text(article, "downloadName", MsrcEndpoint::AffectedProduct)?
                    .unwrap_or_default()
                    .trim()
                    .to_owned();

            for before_kb in before_kbs {
                // A supersedence edge must be irreflexive. MSRC occasionally
                // publishes the patched article itself in this field.
                if before_kb == after_kb {
                    continue;
                }
                let key = (
                    os_version.to_ascii_lowercase(),
                    architecture.to_ascii_lowercase(),
                    update_kind.to_ascii_lowercase(),
                    after_kb.clone(),
                    before_kb.clone(),
                    product_id,
                );
                let candidate = ProductPatch {
                    product_id,
                    os_version: os_version.clone(),
                    architecture: architecture.clone(),
                    update_kind: update_kind.clone(),
                    before_kb,
                    after_kb: after_kb.clone(),
                };
                patches
                    .entry(key)
                    .and_modify(|current| {
                        if candidate.os_version < current.os_version {
                            *current = candidate.clone();
                        }
                    })
                    .or_insert(candidate);
            }
        }
    }

    let article_values = optional_array(info, "articles", MsrcEndpoint::Vulnerability)?;
    let mut articles = Vec::with_capacity(article_values.len());
    for (index, article) in article_values.iter().enumerate() {
        let article = require_object(
            article,
            MsrcEndpoint::Vulnerability,
            &format!("articles[{index}]"),
        )?;
        articles.push(MsrcArticle {
            article_type: optional_text(article, "articleType", MsrcEndpoint::Vulnerability)?
                .unwrap_or_default(),
            title: plain_text(
                optional_text(article, "title", MsrcEndpoint::Vulnerability)?
                    .as_deref()
                    .unwrap_or_default(),
            ),
            description: plain_text(
                optional_text(article, "description", MsrcEndpoint::Vulnerability)?
                    .as_deref()
                    .unwrap_or_default(),
            ),
        });
    }

    let mut seen_cwes = HashSet::new();
    let mut cwe_list = Vec::new();
    for value in optional_array(info, "cweList", MsrcEndpoint::Vulnerability)? {
        let Some(cwe) = value.as_str() else {
            return Err(CveError::InvalidPayload {
                endpoint: MsrcEndpoint::Vulnerability,
                reason: "cweList must contain strings".into(),
            });
        };
        if !cwe.is_empty() && seen_cwes.insert(cwe.to_owned()) {
            cwe_list.push(cwe.to_owned());
        }
    }

    let unformatted = optional_text(info, "unformattedDescription", MsrcEndpoint::Vulnerability)?
        .unwrap_or_default();
    let description = if unformatted.trim().is_empty() {
        plain_text(
            optional_text(info, "description", MsrcEndpoint::Vulnerability)?
                .as_deref()
                .unwrap_or_default(),
        )
    } else {
        unformatted.trim().to_owned()
    };

    Ok(CveMetadata {
        title: optional_text(info, "cveTitle", MsrcEndpoint::Vulnerability)?.unwrap_or_default(),
        cve_code,
        tag: optional_text(info, "tag", MsrcEndpoint::Vulnerability)?.unwrap_or_default(),
        impact: optional_text(info, "impact", MsrcEndpoint::Vulnerability)?.unwrap_or_default(),
        issuing_cna: optional_text(info, "issuingCna", MsrcEndpoint::Vulnerability)?
            .unwrap_or_default(),
        is_mariner: optional_bool(info, "isMariner", MsrcEndpoint::Vulnerability)?,
        catalog: patches.into_values().collect(),
        articles,
        cwe_list,
        release_date: optional_text(info, "releaseDate", MsrcEndpoint::Vulnerability)?
            .unwrap_or_default(),
        latest_revision_date: optional_text(
            info,
            "latestRevisionDate",
            MsrcEndpoint::Vulnerability,
        )?
        .unwrap_or_default(),
        description,
    })
}

fn require_object<'a>(
    value: &'a Value,
    endpoint: MsrcEndpoint,
    field: &str,
) -> Result<&'a Map<String, Value>, CveError> {
    value.as_object().ok_or_else(|| CveError::InvalidPayload {
        endpoint,
        reason: format!("{field} must be a JSON object"),
    })
}

fn optional_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    endpoint: MsrcEndpoint,
) -> Result<&'a [Value], CveError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(CveError::InvalidPayload {
            endpoint,
            reason: format!("{field} must be a JSON array"),
        }),
    }
}

fn optional_text(
    object: &Map<String, Value>,
    field: &str,
    endpoint: MsrcEndpoint,
) -> Result<Option<String>, CveError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(CveError::InvalidPayload {
            endpoint,
            reason: format!("{field} must be a string"),
        }),
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    field: &str,
    endpoint: MsrcEndpoint,
) -> Result<bool, CveError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(CveError::InvalidPayload {
            endpoint,
            reason: format!("{field} must be a boolean"),
        }),
    }
}

fn normalize_kb(value: &Value) -> Option<String> {
    if let Some(number) = value.as_u64() {
        return Some(format!("KB{number}"));
    }
    let text = value.as_str()?.trim();
    if text.bytes().all(|byte| byte.is_ascii_digit()) && !text.is_empty() {
        return Some(format!("KB{text}"));
    }
    KB_PATTERN
        .captures(text)
        .and_then(|capture| capture.get(1))
        .map(|number| format!("KB{}", number.as_str()))
}

fn normalize_kb_candidates(value: Option<&Value>) -> Result<Vec<String>, ()> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(number) = value.as_u64() {
        return Ok(vec![format!("KB{number}")]);
    }
    let Some(text) = value.as_str() else {
        return Err(());
    };
    Ok(SUPERSEDENCE_KB_PATTERN
        .captures_iter(text)
        .filter_map(|capture| capture.get(1))
        .map(|number| format!("KB{}", number.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn normalize_architecture(value: &str, os_version: &str, cpe: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => infer_architecture(os_version, cpe),
        "x64" | "amd64" => "x64".into(),
        "x86" => "x86".into(),
        "arm64" | "aarch64" => "arm64".into(),
        "arm"
            if os_version.to_ascii_lowercase().contains("arm64")
                || cpe.to_ascii_lowercase().contains(":arm64:") =>
        {
            "arm64".into()
        }
        "arm" => "arm".into(),
        _ => normalized,
    }
}

fn infer_architecture(os_version: &str, cpe: &str) -> String {
    let normalized = os_version.to_ascii_lowercase();
    let cpe = cpe.to_ascii_lowercase();
    if normalized.contains("arm64") || normalized.contains("aarch64") || cpe.contains(":arm64:") {
        "arm64".into()
    } else if normalized.contains("itanium")
        || normalized.contains("ia64")
        || cpe.contains(":ia64:")
    {
        "ia64".into()
    } else if normalized.contains("32-bit") || normalized.contains("x86") || cpe.contains(":x86:") {
        "x86".into()
    } else if normalized.contains("x64")
        || normalized.contains("64-bit")
        || normalized.contains("server")
    {
        "x64".into()
    } else if normalized.contains("windows rt") {
        "arm".into()
    } else {
        "unknown".into()
    }
}

fn plain_text(value: &str) -> String {
    let without_tags = HTML_TAG.replace_all(value, " ");
    let decoded = without_tags
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    let mut normalized = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    for punctuation in [".", ",", ";", ":", "!", "?"] {
        normalized = normalized.replace(&format!(" {punctuation}"), punctuation);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{normalize_cve_code, normalize_msrc};
    use crate::model::cve::MsrcRawData;

    fn raw(products: Value) -> MsrcRawData {
        MsrcRawData {
            cve_code: "CVE-2026-1234".into(),
            vulnerability_response: json!({
                "cveNumber": "CVE-2026-1234",
                "cveTitle": "Example",
                "articles": [],
                "cweList": []
            }),
            affected_product_response: json!({"value": products}),
            fetched_at: String::new(),
        }
    }

    #[test]
    fn rejects_malformed_cve_codes() {
        assert!(normalize_cve_code("CVE-2026-12").is_err());
        assert_eq!(
            normalize_cve_code(" cve-2026-1234 ").unwrap(),
            "CVE-2026-1234"
        );
    }

    #[test]
    fn expands_every_supersedence_value_into_an_exact_edge() {
        let metadata = normalize_msrc(&raw(json!([{
            "productId": 12390,
            "product": "Windows 11 Version 24H2 for x64-based Systems",
            "architecture": "x64",
            "kbArticles": [{
                "articleName": "KB5000003",
                "downloadName": "Security Update",
                "supercedence": "5000001, KB5000002"
            }]
        }])))
        .unwrap();

        assert_eq!(metadata.catalog.len(), 2);
        assert_eq!(metadata.catalog[0].before_kb, "KB5000001");
        assert_eq!(metadata.catalog[1].before_kb, "KB5000002");
        assert!(
            metadata
                .catalog
                .iter()
                .all(|patch| patch.after_kb == "KB5000003")
        );
        assert_eq!(metadata.catalog[0].product_id, 12390);
        assert_eq!(metadata.catalog[0].architecture, "x64");
        assert_eq!(metadata.catalog[0].update_kind, "Security Update");
    }

    #[test]
    fn omits_articles_without_an_edge_and_self_edges() {
        let metadata = normalize_msrc(&raw(json!([{
            "productId": 9312,
            "product": "Windows Server 2008 for 32-bit Systems Service Pack 2",
            "architecture": "x86",
            "kbArticles": [
                {
                    "articleName": "5017358",
                    "downloadName": "Monthly Rollup",
                    "supercedence": "5016669"
                },
                {
                    "articleName": "not a KB article",
                    "downloadName": "Security Only"
                },
                {
                    "articleName": "5019999",
                    "downloadName": "Bad API row",
                    "supercedence": "5019999"
                }
            ]
        }])))
        .unwrap();

        assert_eq!(metadata.catalog.len(), 1);
        let patch = &metadata.catalog[0];
        assert_eq!(patch.architecture, "x86");
        assert_eq!(patch.update_kind, "Monthly Rollup");
        assert_eq!(patch.before_kb, "KB5016669");
        assert_eq!(patch.after_kb, "KB5017358");
    }

    #[test]
    fn preserves_multiple_valid_update_channels() {
        let metadata = normalize_msrc(&raw(json!([{
            "productId": 12390,
            "product": "Windows 11 Version 24H2 for x64-based Systems",
            "architecture": "x64",
            "kbArticles": [
                {
                    "articleName": "5079473",
                    "downloadName": "Security Update",
                    "supercedence": "5077181"
                },
                {
                    "articleName": "5084597",
                    "downloadName": "Hotpatch",
                    "supercedence": "5077212"
                }
            ]
        }])))
        .unwrap();

        assert_eq!(metadata.catalog.len(), 2);
        assert_eq!(metadata.catalog[0].update_kind, "Hotpatch");
        assert_eq!(metadata.catalog[1].update_kind, "Security Update");
    }

    #[test]
    fn normalizes_msrc_arm_to_the_architecture_named_by_the_product() {
        let metadata = normalize_msrc(&raw(json!([{
            "productId": 12389,
            "product": "Windows 11 Version 24H2 for ARM64-based Systems",
            "architecture": "ARM",
            "kbArticles": [{
                "articleName": "5000002",
                "downloadName": "Security Update",
                "supercedence": "5000001"
            }]
        }])))
        .unwrap();

        assert_eq!(metadata.catalog[0].architecture, "arm64");
    }

    #[test]
    fn uses_cpe_to_distinguish_modern_arm64_from_arm32() {
        let metadata = normalize_msrc(&raw(json!([{
            "productId": 20437,
            "product": "Windows 11 Version 25H2 for ARM systems",
            "architecture": "ARM",
            "cpe": "cpe:2.3:o:microsoft:windows_11_25H2:{bv}:*:*:*:*:*:arm64:*",
            "kbArticles": [{
                "articleName": "5000002",
                "downloadName": "Security Update",
                "supercedence": "5000001"
            }]
        }])))
        .unwrap();

        assert_eq!(metadata.catalog[0].architecture, "arm64");
    }

    #[test]
    fn infers_architecture_when_legacy_msrc_rows_omit_it() {
        let metadata = normalize_msrc(&raw(json!([
            {
                "productId": 10048,
                "product": "Windows 7 for x64-based Systems Service Pack 1",
                "architecture": null,
                "kbArticles": [{
                    "articleName": "4093118",
                    "downloadName": "Monthly Rollup",
                    "supercedence": "4088875, 4100480"
                }]
            },
            {
                "productId": 9312,
                "product": "Windows Server 2008 for 32-bit Systems Service Pack 2",
                "architecture": null,
                "kbArticles": [{
                    "articleName": "4093224",
                    "downloadName": "Security Update",
                    "supercedence": "4089344"
                }]
            }
        ])))
        .unwrap();

        assert_eq!(metadata.catalog.len(), 3);
        assert_eq!(metadata.catalog[0].architecture, "x64");
        assert_eq!(metadata.catalog[2].architecture, "x86");
    }
}
