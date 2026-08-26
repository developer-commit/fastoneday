use crate::errors::DriverError;
use crate::model::cve::CveMetadata;
use crate::model::driver::{
    DriverCandidate, DriverEvidence, DriverOutcome, DriverResolution, EvidenceSource,
    UnresolvedReason,
};
use std::collections::{BTreeMap, BTreeSet};

pub const RULE_SET_VERSION: &str = "2026.08.1";

type ComponentRule = (&'static str, &'static str, &'static [&'static str]);

const COMPONENT_RULES: &[ComponentRule] = &[
    (
        "common-log-file-system",
        "clfs.sys",
        &[
            "windows common log file system driver",
            "common log file system driver",
        ],
    ),
    ("ntfs", "ntfs.sys", &["windows ntfs"]),
    (
        "cloud-files-minifilter",
        "cldflt.sys",
        &["windows cloud files mini filter driver"],
    ),
    (
        "fast-fat",
        "fastfat.sys",
        &[
            "windows fast fat file system driver",
            "windows fast fat driver",
        ],
    ),
    (
        "ancillary-function-winsock",
        "afd.sys",
        &["windows ancillary function driver for winsock"],
    ),
    (
        "storage-vsp",
        "storvsp.sys",
        &["windows storage vsp driver", "storvsp driver"],
    ),
    (
        "usb-audio-class",
        "usbaudio.sys",
        &[
            "windows usb audio class driver",
            "usb audio class system driver",
        ],
    ),
    (
        "tdi-translation",
        "tdx.sys",
        &[
            "windows tdi translation driver",
            "windows transport driver interface tdi translation driver",
            "windows tdx",
        ],
    ),
    (
        "smb-server-network-transport",
        "srvnet.sys",
        &["windows smb server network transport driver"],
    ),
    (
        "wfp-ndis-lightweight-filter",
        "wfplwfs.sys",
        &["windows wfp ndis lightweight filter driver"],
    ),
    (
        "lua-file-virtualization-filter",
        "luafv.sys",
        &[
            "windows lua file virtualization filter driver",
            "windows luafv",
        ],
    ),
    (
        "container-isolation-fs-filter",
        "unionfs.sys",
        &["windows container isolation fs filter driver"],
    ),
    (
        "applocker-filter",
        "applockerfltr.sys",
        &["applocker filter driver"],
    ),
    (
        "multiple-unc-provider",
        "mup.sys",
        &[
            "windows multiple unc provider driver",
            "multiple unc provider kernel driver",
        ],
    ),
];

pub fn resolve_driver(
    metadata: &CveMetadata,
    override_name: Option<&str>,
) -> Result<DriverResolution, DriverError> {
    if let Some(value) = override_name {
        return Ok(resolution(
            &metadata.cve_code,
            DriverOutcome::Confirmed {
                driver: DriverCandidate {
                    name: normalize_driver_name(value)?,
                    evidence: vec![DriverEvidence::UserOverride],
                },
            },
        ));
    }

    if metadata.is_mariner {
        return Ok(resolution(
            &metadata.cve_code,
            DriverOutcome::Unresolved {
                reason: UnresolvedReason::Mariner,
            },
        ));
    }

    let mut evidence = BTreeMap::<String, BTreeSet<DriverEvidence>>::new();
    let mut explicit_core_count = BTreeMap::<String, u8>::new();

    collect_evidence(
        EvidenceSource::Title,
        &metadata.title,
        true,
        &mut evidence,
        &mut explicit_core_count,
    );
    collect_evidence(
        EvidenceSource::Tag,
        &metadata.tag,
        true,
        &mut evidence,
        &mut explicit_core_count,
    );
    collect_evidence(
        EvidenceSource::Description,
        &metadata.description,
        true,
        &mut evidence,
        &mut explicit_core_count,
    );

    for (index, article) in metadata.articles.iter().enumerate() {
        collect_evidence(
            EvidenceSource::Article(index),
            &format!("{} {}", article.title, article.description),
            false,
            &mut evidence,
            &mut explicit_core_count,
        );
    }

    let mut drivers = evidence
        .into_iter()
        .map(|(name, evidence)| DriverCandidate {
            name,
            evidence: evidence.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    match drivers.len() {
        0 => Ok(resolution(
            &metadata.cve_code,
            DriverOutcome::Unresolved {
                reason: UnresolvedReason::NoEvidence,
            },
        )),
        1 => {
            let driver = drivers.pop().expect("length checked");
            let confirmed = explicit_core_count
                .get(&driver.name)
                .is_some_and(|count| *count >= 2);

            Ok(resolution(
                &metadata.cve_code,
                if confirmed {
                    DriverOutcome::Confirmed { driver }
                } else {
                    DriverOutcome::Probable { driver }
                },
            ))
        }
        _ => Ok(resolution(
            &metadata.cve_code,
            DriverOutcome::Conflict { drivers },
        )),
    }
}

fn resolution(cve_code: &str, outcome: DriverOutcome) -> DriverResolution {
    DriverResolution {
        cve_code: cve_code.to_owned(),
        rule_version: RULE_SET_VERSION.to_owned(),
        outcome,
    }
}

fn collect_evidence(
    source: EvidenceSource,
    text: &str,
    core: bool,
    evidence: &mut BTreeMap<String, BTreeSet<DriverEvidence>>,
    explicit_core_count: &mut BTreeMap<String, u8>,
) {
    for name in extract_sys_names(text) {
        evidence
            .entry(name.clone())
            .or_default()
            .insert(DriverEvidence::ExplicitFilename { source });

        if core {
            *explicit_core_count.entry(name).or_default() += 1;
        }
    }

    let normalized = normalize_component_text(text);
    for &(rule_id, driver_name, aliases) in COMPONENT_RULES {
        for &alias in aliases {
            if normalized.contains(&format!(" {alias} ")) {
                evidence.entry(driver_name.to_owned()).or_default().insert(
                    DriverEvidence::ComponentRule {
                        source,
                        rule_id: rule_id.to_owned(),
                        matched_alias: alias.to_owned(),
                    },
                );
            }
        }
    }
}

fn normalize_driver_name(value: &str) -> Result<String, DriverError> {
    let name = value.trim().to_ascii_lowercase();
    let bytes = name.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && (bytes.ends_with(b".sys") || name == "ntoskrnl.exe")
        && bytes.iter().copied().all(is_filename_char);

    valid
        .then_some(name)
        .ok_or_else(|| DriverError::InvalidName {
            value: value.to_owned(),
        })
}

fn extract_sys_names(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut names = BTreeSet::new();
    let mut start = 0;

    while start < bytes.len() {
        let valid_start = bytes[start].is_ascii_alphanumeric()
            && (start == 0 || !is_boundary_blocker(bytes[start - 1]));

        if valid_start {
            let mut end = start + 1;
            let mut matched_end = None;

            loop {
                if ends_with_sys(&bytes[start..end])
                    && (end == bytes.len() || !is_boundary_blocker(bytes[end]))
                {
                    matched_end = Some(end);
                }

                if end == bytes.len() || !is_filename_char(bytes[end]) {
                    break;
                }
                end += 1;
            }

            if let Some(end) = matched_end {
                names.insert(text[start..end].to_ascii_lowercase());
                start = end;
                continue;
            }
        }

        start += 1;
    }

    names
}

fn normalize_component_text(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len() + 2);
    normalized.push(' ');
    let mut separated = false;

    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separated && !normalized.ends_with(' ') {
                normalized.push(' ');
            }
            normalized.push(byte.to_ascii_lowercase() as char);
            separated = false;
        } else {
            separated = true;
        }
    }

    if !normalized.ends_with(' ') {
        normalized.push(' ');
    }
    normalized
}

fn is_filename_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_boundary_blocker(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn ends_with_sys(value: &[u8]) -> bool {
    value.len() >= 4
        && value[value.len() - 4] == b'.'
        && value[value.len() - 3].eq_ignore_ascii_case(&b's')
        && value[value.len() - 2].eq_ignore_ascii_case(&b'y')
        && value[value.len() - 1].eq_ignore_ascii_case(&b's')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::cve::{CveMetadata, MsrcArticle};

    fn metadata(title: &str) -> CveMetadata {
        CveMetadata {
            title: title.to_owned(),
            cve_code: "CVE-2026-0001".to_owned(),
            tag: String::new(),
            impact: String::new(),
            issuing_cna: String::new(),
            is_mariner: false,
            catalog: vec![],
            articles: Vec::<MsrcArticle>::new(),
            cwe_list: vec![],
            release_date: String::new(),
            latest_revision_date: String::new(),
            description: String::new(),
        }
    }

    #[test]
    fn confirms_the_same_explicit_name_in_two_core_fields() {
        let mut metadata = metadata("StorVsp.sys vulnerability");
        metadata.description = "Issue in storvsp.SYS".to_owned();

        let result = resolve_driver(&metadata, None).unwrap();
        assert!(matches!(result.outcome, DriverOutcome::Confirmed { .. }));
    }

    #[test]
    fn recognizes_the_msrc_usb_audio_title() {
        let metadata =
            metadata("USB Audio Class System Driver Remote Code Execution Vulnerability");

        let result = resolve_driver(&metadata, None).unwrap();
        assert!(matches!(
            result.outcome,
            DriverOutcome::Probable { driver } if driver.name == "usbaudio.sys"
        ));
    }

    #[test]
    fn detects_conflicting_rules() {
        let mut metadata = metadata("Windows Common Log File System Driver vulnerability");
        metadata.tag = "Windows NTFS".to_owned();

        let result = resolve_driver(&metadata, None).unwrap();
        let DriverOutcome::Conflict { drivers } = result.outcome else {
            panic!("expected conflict");
        };
        assert_eq!(
            drivers
                .into_iter()
                .map(|driver| driver.name)
                .collect::<Vec<_>>(),
            ["clfs.sys", "ntfs.sys"]
        );
    }

    #[test]
    fn rejects_filename_prefix_and_suffix_tricks() {
        assert_eq!(
            extract_sys_names("x-ntfs.sys-extra example.sys")
                .into_iter()
                .collect::<Vec<_>>(),
            ["example.sys"]
        );
        assert!(normalize_driver_name("../evil.sys").is_err());
    }

    #[test]
    fn allows_ntoskrnl_exe_as_the_only_exe_exception() {
        assert_eq!(
            normalize_driver_name("NtoSkrnl.EXE").unwrap(),
            "ntoskrnl.exe"
        );
        assert!(normalize_driver_name("other.exe").is_err());
    }
}
