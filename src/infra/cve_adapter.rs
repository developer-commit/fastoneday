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
    model::cve::{BeforeKb, CveMetadata, MsrcArticle, MsrcFetchResult, MsrcRawData, ProductPatch},
    port::CvePort,
};

const DEFAULT_BASE_URL: &str = "https://api.msrc.microsoft.com/sug/v2.0/en-US";

static KB_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bKB\s*([0-9]+)\b").expect("valid KB regex"));
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
    let mut patches = BTreeMap::<(String, String, String), ProductPatch>::new();
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
        let articles = optional_array(product, "kbArticles", MsrcEndpoint::AffectedProduct)?;

        for (article_index, article) in articles.iter().enumerate() {
            let article = require_object(
                article,
                MsrcEndpoint::AffectedProduct,
                &format!("value[{product_index}].kbArticles[{article_index}]"),
            )?;
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
            let candidates = normalize_kb_candidates(article.get("supercedence"));
            let before_kb = match candidates.len() {
                0 => BeforeKb::Missing,
                1 => BeforeKb::Available(candidates[0].clone()),
                _ => BeforeKb::Ambiguous(candidates.clone()),
            };
            let key = (
                os_version.to_ascii_lowercase(),
                after_kb.clone(),
                candidates.join("|"),
            );
            let candidate = ProductPatch {
                os_version: os_version.clone(),
                before_kb,
                after_kb,
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

fn normalize_kb_candidates(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    if let Some(number) = value.as_u64() {
        return vec![format!("KB{number}")];
    }
    let Some(text) = value.as_str() else {
        return Vec::new();
    };
    if text.bytes().all(|byte| byte.is_ascii_digit()) && !text.is_empty() {
        return vec![format!("KB{text}")];
    }
    KB_PATTERN
        .captures_iter(text)
        .filter_map(|capture| capture.get(1))
        .map(|number| format!("KB{}", number.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
    use serde_json::json;

    use super::{normalize_cve_code, normalize_msrc};
    use crate::model::cve::{BeforeKb, MsrcRawData};

    #[test]
    fn rejects_malformed_cve_codes() {
        assert!(normalize_cve_code("CVE-2026-12").is_err());
        assert_eq!(
            normalize_cve_code(" cve-2026-1234 ").unwrap(),
            "CVE-2026-1234"
        );
    }

    #[test]
    fn normalizes_kb_state_without_redundant_fields() {
        let raw = MsrcRawData {
            cve_code: "CVE-2026-1234".into(),
            vulnerability_response: json!({
                "cveNumber": "CVE-2026-1234",
                "cveTitle": "Example",
                "articles": [],
                "cweList": []
            }),
            affected_product_response: json!({
                "value": [{
                    "product": "Windows 11 Version 24H2 for x64-based Systems",
                    "kbArticles": [{
                        "articleName": "KB5000003",
                        "supercedence": "KB5000001, KB5000002"
                    }]
                }]
            }),
            fetched_at: String::new(),
        };

        let metadata = normalize_msrc(&raw).unwrap();
        assert!(matches!(
            metadata.catalog[0].before_kb,
            BeforeKb::Ambiguous(_)
        ));
    }
}
