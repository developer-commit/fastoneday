//! Minimal RFC 3986 percent-encoding (we build OData URLs by hand because the
//! MSRC API rejects `+` for spaces).

/// Percent-encodes everything except unreserved characters.
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `k1=v1&k2=v2` with both sides encoded.
pub fn encode_query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_odata_queries() {
        assert_eq!(
            encode_query(&[("$filter", "cveNumber eq 'CVE-1'")]),
            "%24filter=cveNumber%20eq%20%27CVE-1%27"
        );
    }
}
