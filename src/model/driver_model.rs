use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverResolution {
    pub cve_code: String,
    pub rule_version: String,
    #[serde(flatten)]
    pub outcome: DriverOutcome,
}

impl DriverResolution {
    pub fn confirmed_driver(&self) -> Option<&str> {
        match &self.outcome {
            DriverOutcome::Confirmed { driver } => Some(&driver.name),
            DriverOutcome::Probable { .. }
            | DriverOutcome::Conflict { .. }
            | DriverOutcome::Unresolved { .. } => None,
        }
    }

    pub fn candidates(&self) -> impl Iterator<Item = &str> {
        let candidates: &[DriverCandidate] = match &self.outcome {
            DriverOutcome::Confirmed { driver } | DriverOutcome::Probable { driver } => {
                std::slice::from_ref(driver)
            }
            DriverOutcome::Conflict { drivers } => drivers,
            DriverOutcome::Unresolved { .. } => &[],
        };
        candidates.iter().map(|candidate| candidate.name.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriverOutcome {
    Confirmed { driver: DriverCandidate },
    Probable { driver: DriverCandidate },
    Conflict { drivers: Vec<DriverCandidate> },
    Unresolved { reason: UnresolvedReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverCandidate {
    pub name: String,
    pub evidence: Vec<DriverEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriverEvidence {
    ExplicitFilename {
        source: EvidenceSource,
    },
    ComponentRule {
        source: EvidenceSource,
        rule_id: String,
        matched_alias: String,
    },
    UserOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Title,
    Tag,
    Description,
    Article(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnresolvedReason {
    Mariner,
    NoEvidence,
}
