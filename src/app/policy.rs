//! Which patch pair to offer first, and folding duplicate rows.

use std::cmp::Reverse;

use crate::{
    domain::{Arch, Family, PatchPair, UpdateRef},
    sources::office::Channel,
};

/// First build whose cumulative updates ship as WIM-based MSUs.
pub const REMOTE_READABLE_BUILD: u32 = 26100;

/// Sorts best-first and removes rows that would fetch the same files.
///
/// Preference: newest Windows client build on x64 (cleanest, fastest:
/// 24H2+ packages are read remotely), then servers, then Office — Click-to-
/// Run LTSC channels first because their builds only differ by security
/// fixes, which keeps diffs small.
pub fn rank_pairs(mut pairs: Vec<PatchPair>) -> Vec<PatchPair> {
    pairs.sort_by_key(|p| {
        (
            family_rank(p),
            // 24H2+ packages are read remotely in seconds; older ones need a
            // full package download.
            u8::from(build_major(p) < REMOTE_READABLE_BUILD),
            arch_rank(p.arch),
            u8::from(p.product.to_ascii_lowercase().contains("server")),
            Reverse(build_major(p)),
            kind_rank(&p.kind),
            u8::from(p.product.contains("Server Core")),
            p.product.clone(),
        )
    });
    let mut out: Vec<PatchPair> = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let duplicate = out.iter().any(|kept| {
            kept.family == pair.family
                && kept.arch == pair.arch
                && kept.before == pair.before
                && kept.after == pair.after
        });
        if !duplicate {
            out.push(pair);
        }
    }
    out
}

fn family_rank(p: &PatchPair) -> u8 {
    match (&p.family, &p.after) {
        (Family::Windows, _) => 0,
        (Family::OfficeC2r, UpdateRef::OfficeBuild { channel, .. }) => {
            match Channel::from_short(channel) {
                Some(Channel::Ltsc2024) => 1,
                Some(Channel::Ltsc2021) => 2,
                Some(Channel::Current) => 3,
                _ => 4,
            }
        }
        (Family::OfficeC2r, _) => 4,
        (Family::OfficeMsi, _) => 5,
    }
}

/// `10.0.26100.1457` → 26100.
pub fn build_major(p: &PatchPair) -> u32 {
    p.fixed_build
        .as_deref()
        .and_then(|b| b.split('.').nth(2))
        .and_then(|b| b.parse().ok())
        .unwrap_or(0)
}

fn arch_rank(arch: Arch) -> u8 {
    match arch {
        Arch::X64 => 0,
        Arch::Arm64 => 1,
        Arch::X86 => 2,
    }
}

fn kind_rank(kind: &str) -> u8 {
    match kind.to_ascii_lowercase().as_str() {
        "security update" => 0,
        "monthly rollup" => 1,
        "hotpatch" => 3,
        "security only" => 4,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(product: &str, arch: Arch, build: &str, before: &str, after: &str) -> PatchPair {
        PatchPair {
            product: product.into(),
            family: Family::Windows,
            arch,
            kind: "Security Update".into(),
            before: UpdateRef::kb(before),
            after: UpdateRef::kb(after),
            fixed_build: Some(build.into()),
        }
    }

    #[test]
    fn newest_client_x64_first_and_duplicates_folded() {
        let ranked = rank_pairs(vec![
            win(
                "Windows Server 2022 (Server Core installation)",
                Arch::X64,
                "10.0.20348.2655",
                "KB1",
                "KB2",
            ),
            win(
                "Windows 11 Version 23H2 for x64-based Systems",
                Arch::X64,
                "10.0.22631.4037",
                "KB3",
                "KB4",
            ),
            win(
                "Windows 11 Version 24H2 for ARM64-based Systems",
                Arch::Arm64,
                "10.0.26100.1457",
                "KB5",
                "KB6",
            ),
            win(
                "Windows 11 Version 24H2 for x64-based Systems",
                Arch::X64,
                "10.0.26100.1457",
                "KB5",
                "KB6",
            ),
            win(
                "Windows Server 2022",
                Arch::X64,
                "10.0.20348.2655",
                "KB1",
                "KB2",
            ),
            win(
                "Windows 11 Version 22H2 for x64-based Systems",
                Arch::X64,
                "10.0.22621.4037",
                "KB3",
                "KB4",
            ),
        ]);
        let names: Vec<&str> = ranked.iter().map(|p| p.product.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Windows 11 Version 24H2 for x64-based Systems",
                "Windows 11 Version 24H2 for ARM64-based Systems",
                "Windows 11 Version 23H2 for x64-based Systems",
                "Windows Server 2022",
            ]
        );
        let server_23h2 = win(
            "Windows Server 2022, 23H2 Edition (Server Core installation)",
            Arch::X64,
            "10.0.25398.1085",
            "KB7",
            "KB8",
        );
        let client_23h2 = win(
            "Windows 11 Version 23H2 for x64-based Systems",
            Arch::X64,
            "10.0.22631.4037",
            "KB3",
            "KB4",
        );
        let ranked = rank_pairs(vec![server_23h2, client_23h2]);
        assert!(ranked[0].product.starts_with("Windows 11"));
    }
}
