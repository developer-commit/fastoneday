use crate::{
    domain::{
        BinaryName, Candidate, CaseResult, CveDetail, CveId, CveSummary, PairFiles, PatchPair,
    },
    store::HistoryEntry,
};

pub type JobId = u64;

/// A loaded CVE, ready to pick a patch pair and then a binary from it.
#[derive(Debug, Clone)]
pub struct CveReport {
    pub detail: CveDetail,
    /// Office application the release notes list this CVE under.
    pub office_app: Option<String>,
    /// Binary names Microsoft's text points to. Not checked against any
    /// update: a binary is only ever picked from a pair's [`PairListing`].
    pub hints: Vec<Candidate>,
    /// The binary used last time for this CVE.
    pub remembered_binary: Option<String>,
}

/// The binaries one patch pair offers: the files of its fixing update, with
/// MSRC's hints narrowed to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairListing {
    pub files: PairFiles,
    /// Files of the update with evidence, best first (see [`Self::pick`]).
    pub candidates: Vec<Candidate>,
    /// Hinted names the update does not carry.
    pub missing: Vec<BinaryName>,
    pub comparison: Comparison,
}

impl PairListing {
    /// The recommended binary: the best candidate the pair did not leave
    /// unchanged.
    pub fn pick(&self) -> Option<&Candidate> {
        self.candidates.iter().find(|c| c.recommended())
    }
}

/// Whether the listed files were compared with the pair's before update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    /// Not yet (the TUI does it in the background, after the list shows).
    Pending,
    /// `files.changes` holds the result.
    Done,
    /// Could not be compared without a package download (or at all); why.
    Unavailable(String),
    /// The update lists names only (Defender packages); every file changes.
    NotApplicable,
}

#[derive(Debug, Clone)]
pub enum Command {
    LoadSuggestions,
    LoadCve(CveId),
    /// List the pair's fixing update (no package download), then compare it
    /// with the before update. Replaces the previous prefetch.
    Prefetch {
        report: Box<CveReport>,
        pair: PatchPair,
    },
    /// Like `Prefetch`, but downloads the fixing update's package when that
    /// is the only way to list it; runs as a job with progress.
    ListFiles {
        job: JobId,
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
        hint: Option<String>,
    },
    /// The pair's file list (sent again once compared with the before side).
    /// `cve` is the report it was ranked for: two CVEs can share a pair.
    PairListed {
        cve: CveId,
        pair: PatchPair,
        listing: Box<PairListing>,
    },
    /// The fixing update's files are only known after downloading its
    /// package (on request, or by fetching).
    PairNeedsDownload {
        cve: CveId,
        pair: PatchPair,
        package: String,
        size: Option<u64>,
    },
    PairListFailed {
        cve: CveId,
        pair: PatchPair,
        error: String,
    },
    /// A `ListFiles` job finished.
    ListDone {
        job: JobId,
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
        hint: Option<String>,
        cancelled: bool,
    },
}
