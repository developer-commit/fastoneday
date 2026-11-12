//! Choosing the catalog entry that corresponds to an MSRC product row.

use std::sync::LazyLock;

use regex::Regex;

use super::CatalogUpdate;
use crate::{
    domain::Arch,
    error::{Error, Result},
};

static RELEASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(\d{2}h\d|\d{4})\b").expect("regex"));

/// Picks the single update for `kb` that matches the architecture and, when
/// several remain, the product release.
pub fn pick_update(
    updates: &[CatalogUpdate],
    kb: &str,
    product: &str,
    arch: Arch,
) -> Result<CatalogUpdate> {
    let kb_lower = kb.to_ascii_lowercase();
    let mut candidates: Vec<&CatalogUpdate> = updates
        .iter()
        .filter(|u| {
            let title = u.title.to_ascii_lowercase();
            title.contains(&kb_lower)
                && !title.contains("dynamic")
                && !title.contains("safe os")
                && !title.contains("setup update")
                && arch_matches(&title, arch)
        })
        .collect();
    if candidates.len() > 1 {
        let narrowed: Vec<&CatalogUpdate> = candidates
            .iter()
            .copied()
            .filter(|u| title_matches_product(&u.title, product))
            .collect();
        if !narrowed.is_empty() {
            candidates = narrowed;
        }
    }
    // Several entries (e.g. 22H2 and 23H2) often share one package; any of
    // them is fine then, and the first is the newest listing.
    candidates
        .first()
        .map(|u| (*u).clone())
        .ok_or_else(|| Error::NotFound(format!("no {arch} package for {kb} in the Update Catalog")))
}

fn arch_matches(title: &str, arch: Arch) -> bool {
    let has = |w: &str| title.contains(w);
    let x64 = has("x64") || has("amd64") || has("64-bit edition");
    let arm64 = has("arm64");
    let x86 = has("x86") || has("32-bit");
    if !x64 && !arm64 && !x86 {
        // Single-architecture products (e.g. Office server) name none.
        return true;
    }
    match arch {
        Arch::X64 => x64 && !arm64,
        Arch::Arm64 => arm64,
        Arch::X86 => x86 && !arm64,
    }
}

/// Loose match between a catalog title and an MSRC product name: the same
/// release token (`24H2`, `2022`, ...) or product family.
pub fn title_matches_product(title: &str, product: &str) -> bool {
    let title_l = title.to_ascii_lowercase();
    let product_l = product.to_ascii_lowercase();
    let tokens: Vec<String> = RELEASE
        .captures_iter(&product_l)
        .map(|c| c[1].to_owned())
        .collect();
    if tokens.is_empty() {
        return true;
    }
    tokens.iter().any(|t| title_l.contains(t.as_str()))
        || (product_l.contains("server 2022") && title_l.contains("server operating system"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(id: &str, title: &str) -> CatalogUpdate {
        CatalogUpdate {
            id: id.into(),
            title: title.into(),
            products: String::new(),
            classification: String::new(),
            last_updated: String::new(),
            size: 0,
        }
    }

    #[test]
    fn picks_by_architecture_and_release() {
        let updates = vec![
            update(
                "1",
                "2024-08 Cumulative Update for Windows 11 Version 22H2 for x64-based Systems (KB5041585)",
            ),
            update(
                "2",
                "2024-08 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5041585)",
            ),
            update(
                "3",
                "2024-08 Cumulative Update for Windows 11 Version 23H2 for arm64-based Systems (KB5041585)",
            ),
            update(
                "4",
                "2024-08 Dynamic Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5041585)",
            ),
        ];
        let p = pick_update(
            &updates,
            "KB5041585",
            "Windows 11 Version 23H2 for x64-based Systems",
            Arch::X64,
        )
        .unwrap();
        assert_eq!(p.id, "2");
        let p = pick_update(
            &updates,
            "KB5041585",
            "Windows 11 Version 23H2 for ARM64-based Systems",
            Arch::Arm64,
        )
        .unwrap();
        assert_eq!(p.id, "3");
    }

    #[test]
    fn matches_office_editions() {
        let updates = vec![
            update(
                "a",
                "Security Update for Microsoft Outlook 2016 (KB5002600) 32-Bit Edition",
            ),
            update(
                "b",
                "Security Update for Microsoft Outlook 2016 (KB5002600) 64-Bit Edition",
            ),
        ];
        assert_eq!(
            pick_update(
                &updates,
                "KB5002600",
                "Microsoft Outlook 2016 (64-bit edition)",
                Arch::X64
            )
            .unwrap()
            .id,
            "b"
        );
        assert_eq!(
            pick_update(
                &updates,
                "KB5002600",
                "Microsoft Outlook 2016 (32-bit edition)",
                Arch::X86
            )
            .unwrap()
            .id,
            "a"
        );
    }
}
