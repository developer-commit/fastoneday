use crate::{
    domain::{BinaryName, Candidate, CaseResult, CveDetail, CveId, CveSummary, PatchPair},
    store::HistoryEntry,
};

pub type JobId = u64;

/// A loaded CVE, ready to pick a product and binary.
#[derive(Debug, Clone)]
pub struct CveReport {
    pub detail: CveDetail,
    /// Office application the release notes list this CVE under.
    pub office_app: Option<String>,
    pub candidates: Vec<Candidate>,
    /// The binary used last time for this CVE.
    pub remembered_binary: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Command {
    LoadSuggestions,
    LoadCve(CveId),
    /// Read the fixing package's file list (completion + detection).
    Prefetch {
        report: Box<CveReport>,
        pair: PatchPair,
    },
    /// Fetch both sides. With `fallback`, other remote-readable rows are tried
    /// when this one cannot produce a verified binary yet.
    Acquire {
        job: JobId,
        report: Box<CveReport>,
        pair: PatchPair,
        binary: BinaryName,
        fallback: bool,
    },
    Cancel {
        job: JobId,
    },
}

#[derive(Debug, Clone)]
pub enum Event {
    Suggestions {
        recent: Vec<CveSummary>,
        history: Vec<HistoryEntry>,
    },
    SuggestionsFailed(String),
    CveLoading(CveId),
    CveLoaded(Box<CveReport>),
    CveFailed {
        cve: CveId,
        error: String,
    },
    PackageNames {
        pair: PatchPair,
        names: Vec<String>,
        candidates: Vec<Candidate>,
    },
    PackageNamesFailed {
        pair: PatchPair,
        error: String,
    },
    StepStarted {
        job: JobId,
        step: u64,
        label: String,
    },
    StepProgress {
        job: JobId,
        step: u64,
        done: u64,
        total: Option<u64>,
    },
    StepFinished {
        job: JobId,
        step: u64,
        ok: bool,
        detail: String,
    },
    Note {
        job: JobId,
        text: String,
    },
    CaseDone {
        job: JobId,
        result: Box<CaseResult>,
    },
    CaseFailed {
        job: JobId,
        error: String,
    },
}
