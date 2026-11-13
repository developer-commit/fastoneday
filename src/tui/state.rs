//! UI state and how it reacts to keys, the mouse and worker events.
//! Rendering lives in `view`; this module never draws.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind},
    layout::Rect,
};

use super::{
    actions,
    complete::{BinaryOption, CveSuggestion, binary_options, cve_suggestions, usable_unpicked},
    input::TextInput,
    layout::{self, Areas},
};
use crate::{
    app::{Command, Comparison, CveReport, Event, JobId, PairListing, Worker},
    domain::{BinaryName, Candidate, CaseResult, CveId, CveSummary, PatchPair, UpdateRef},
    store::HistoryEntry,
};

const SUGGESTION_ROWS: usize = 10;
/// A second Esc / q within this window confirms a destructive action.
const CONFIRM_WINDOW: Duration = Duration::from_secs(3);
const DOUBLE_CLICK: Duration = Duration::from_millis(450);
/// Moving through ② reads a row's files only once the cursor rests.
const PREFETCH_DELAY: Duration = Duration::from_millis(350);

/// The four steps of the flow, in order. Each is one pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Cve,
    Products,
    Binary,
    Fetch,
}

impl Focus {
    pub const ALL: [Self; 4] = [Self::Cve, Self::Products, Self::Binary, Self::Fetch];

    pub fn number(self) -> &'static str {
        match self {
            Self::Cve => "①",
            Self::Products => "②",
            Self::Binary => "③",
            Self::Fetch => "④",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cve => "CVE",
            Self::Products => "Patch pair",
            Self::Binary => "Binary",
            Self::Fetch => "Fetch",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Cve => Self::Products,
            Self::Products => Self::Binary,
            Self::Binary => Self::Fetch,
            Self::Fetch => Self::Cve,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Cve => Self::Fetch,
            Self::Products => Self::Cve,
            Self::Binary => Self::Products,
            Self::Fetch => Self::Binary,
        }
    }
}

/// What is known about the files of a patch pair's fixing update — the
/// only list a binary is picked from.
#[derive(Debug, Clone)]
pub enum Files {
    /// Being read in place (no package download).
    Loading,
    Ready(Arc<PairListing>),
    Failed(String),
    /// Only known after downloading the update's package; Enter in ③ does
    /// that (the fetch reuses the download).
    NeedsDownload {
        package: String,
        size: Option<u64>,
    },
}

/// An error plus what the user can do about it.
#[derive(Debug, Clone)]
pub struct Failure {
    pub message: String,
    pub hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StepView {
    pub id: u64,
    pub label: String,
    pub detail: String,
    pub done: u64,
    pub total: Option<u64>,
    pub state: StepState,
    pub started: Instant,
    pub elapsed: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
pub enum JobState {
    Running,
    Done(Box<CaseResult>),
    /// A listing job finished: the pair's files are in ③.
    Listed,
    Failed(Failure),
    Cancelled,
}

/// What a job does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// Fetch both sides of a binary.
    Fetch,
    /// Download a pair's package to list its files.
    List,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub kind: JobKind,
    pub pair: PatchPair,
    /// The binary (fetch) or the update being listed.
    pub binary: String,
    pub product: String,
    pub steps: Vec<StepView>,
    pub notes: Vec<String>,
    pub state: JobState,
    pub started: Instant,
    pub finished: Option<Duration>,
}

impl Job {
    pub fn is_running(&self) -> bool {
        matches!(self.state, JobState::Running)
    }

    pub fn elapsed(&self) -> Duration {
        self.finished.unwrap_or_else(|| self.started.elapsed())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub level: Level,
    pub at: Instant,
}

/// Progress of one step of the flow, for the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepMark {
    Pending,
    Done,
    Running,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Armed {
    CancelFetch,
    Quit,
}

pub struct App {
    worker: Worker,
    pub workspace: String,
    pub focus: Focus,

    pub cve: TextInput,
    pub popup_open: bool,
    pub suggestions: Vec<CveSuggestion>,
    pub suggestion: usize,
    pub recent: Vec<CveSummary>,
    pub history: Vec<HistoryEntry>,
    pub recent_error: Option<String>,

    pub loading: Option<CveId>,
    pub load_error: Option<Failure>,
    pub report: Option<Arc<CveReport>>,
    pub product: usize,

    pub binary: TextInput,
    pub options: Vec<BinaryOption>,
    pub option: usize,
    /// The user moved to a row themselves (see [`App::selection`]).
    picked: bool,
    /// Per patch pair (see [`pair_key`]).
    pub files: HashMap<String, Files>,
    /// The pair whose background listing is in flight; starting another
    /// one cancels it.
    prefetching: Option<String>,
    /// When to list the row the ② cursor stopped on.
    prefetch_due: Option<Instant>,
    /// The binary used last time for this CVE, until a list offers it.
    remembered: Option<String>,

    pub job: Option<Job>,
    next_job: JobId,

    pub show_help: bool,
    pub toast: Option<Toast>,
    pub tick: u64,
    pub quit: bool,
    /// Terminal size, for mouse hit-testing.
    pub screen: Rect,
    armed: Option<(Armed, Instant)>,
    last_click: Option<(Instant, u16, u16)>,
}

impl App {
    pub fn new(worker: Worker, initial: Option<String>) -> Self {
        let workspace = display_path(&worker.services().settings.workspace);
        let mut app = Self {
            worker,
            workspace,
            focus: Focus::Cve,
            cve: TextInput::default(),
            popup_open: true,
            suggestions: Vec::new(),
            suggestion: 0,
            recent: Vec::new(),
            history: Vec::new(),
            recent_error: None,
            loading: None,
            load_error: None,
            report: None,
            product: 0,
            binary: TextInput::default(),
            options: Vec::new(),
            option: 0,
            picked: false,
            files: HashMap::new(),
            prefetching: None,
            prefetch_due: None,
            remembered: None,
            job: None,
            next_job: 1,
            show_help: false,
            toast: None,
            tick: 0,
            quit: false,
            screen: Rect::default(),
            armed: None,
            last_click: None,
        };
        app.worker.submit(Command::LoadSuggestions);
        app.history_bump();
        if let Some(initial) = initial {
            app.cve.set(initial.clone());
            match CveId::parse(&initial) {
                Ok(cve) => app.load(cve),
                Err(e) => app.notify(Level::Warn, e.to_string()),
            }
        }
        app
    }

    // ----- derived data -------------------------------------------------

    pub fn pairs(&self) -> &[PatchPair] {
        self.report
            .as_ref()
            .map(|r| r.detail.patches.as_slice())
            .unwrap_or(&[])
    }

    pub fn selected_pair(&self) -> Option<&PatchPair> {
        self.pairs().get(self.product)
    }

    pub fn files_for(&self, pair: &PatchPair) -> Option<&Files> {
        self.files.get(&pair_key(pair))
    }

    /// What is known about the selected pair's files.
    pub fn selected_files(&self) -> Option<&Files> {
        self.selected_pair().and_then(|p| self.files_for(p))
    }

    /// The selected pair's file list, once read.
    pub fn listing(&self) -> Option<&PairListing> {
        match self.selected_files() {
            Some(Files::Ready(listing)) => Some(listing),
            _ => None,
        }
    }

    /// MSRC's hints (not yet checked against any update).
    pub fn hints(&self) -> &[Candidate] {
        self.report.as_ref().map_or(&[], |r| r.hints.as_slice())
    }

    /// The listing job running for the selected pair, if any.
    pub fn listing_job(&self) -> Option<&Job> {
        let pair = self.selected_pair()?;
        self.job
            .as_ref()
            .filter(|j| j.kind == JobKind::List && j.is_running() && &j.pair == pair)
    }

    /// The highlighted binary row. With nothing typed, a plain file of the
    /// update counts only once the user moved to it, so Enter never fetches
    /// whichever file happens to sort first.
    pub fn selection(&self) -> Option<usize> {
        let row = self.options.get(self.option)?;
        (self.picked || usable_unpicked(self.binary.value(), row)).then_some(self.option)
    }

    pub fn selected_option(&self) -> Option<&BinaryOption> {
        self.selection().map(|i| &self.options[i])
    }

    pub fn chosen_binary(&self) -> Option<BinaryName> {
        if self.options.is_empty() {
            return BinaryName::parse(self.binary.value()).ok();
        }
        let row = &self.options[self.selection()?];
        BinaryName::parse(&row.name).ok()
    }

    /// The typed text is exactly the CVE that is already shown.
    pub fn typed_is_loaded(&self) -> bool {
        self.report.as_ref().is_some_and(|r| {
            CveId::parse(self.cve.value()).is_ok_and(|typed| typed == r.detail.summary.id)
        })
    }

    pub fn running(&self) -> bool {
        self.job.as_ref().is_some_and(Job::is_running)
    }

    pub fn done_case(&self) -> Option<&CaseResult> {
        match self.job.as_ref().map(|j| &j.state) {
            Some(JobState::Done(result)) => Some(result),
            _ => None,
        }
    }

    /// A fetch (not a listing) is running.
    fn fetching(&self) -> bool {
        self.job
            .as_ref()
            .is_some_and(|j| j.kind == JobKind::Fetch && j.is_running())
    }

    pub fn can_retry(&self) -> bool {
        self.load_error.is_some()
            || matches!(
                self.job.as_ref().map(|j| &j.state),
                Some(JobState::Failed(_) | JobState::Cancelled)
            )
    }

    /// Header breadcrumb state of each step.
    pub fn step_mark(&self, step: Focus) -> StepMark {
        match step {
            Focus::Cve if self.loading.is_some() => StepMark::Running,
            Focus::Cve if self.load_error.is_some() => StepMark::Failed,
            Focus::Cve if self.report.is_some() => StepMark::Done,
            Focus::Products if self.selected_pair().is_some() => StepMark::Done,
            Focus::Products
                if self
                    .report
                    .as_ref()
                    .is_some_and(|r| r.detail.patches.is_empty()) =>
            {
                StepMark::Failed
            }
            Focus::Binary if self.report.is_some() && self.chosen_binary().is_some() => {
                StepMark::Done
            }
            Focus::Fetch => match self.job.as_ref().map(|j| (j.kind, &j.state)) {
                Some((_, JobState::Running)) => StepMark::Running,
                Some((_, JobState::Done(_))) => StepMark::Done,
                Some((JobKind::Fetch, JobState::Failed(_))) => StepMark::Failed,
                _ => StepMark::Pending,
            },
            _ => StepMark::Pending,
        }
    }

    pub fn toast_text(&self) -> Option<&Toast> {
        self.toast.as_ref().filter(|t| {
            let ttl = match t.level {
                Level::Error => 10,
                Level::Warn => 6,
                _ => 4,
            };
            t.at.elapsed() < Duration::from_secs(ttl)
        })
    }

    pub fn notify(&mut self, level: Level, text: impl Into<String>) {
        self.toast = Some(Toast {
            text: text.into(),
            level,
            at: Instant::now(),
        });
    }

    fn armed(&self, what: Armed) -> bool {
        self.armed
            .is_some_and(|(a, at)| a == what && at.elapsed() < CONFIRM_WINDOW)
    }

    fn arm(&mut self, what: Armed, message: &str) {
        self.armed = Some((what, Instant::now()));
        self.notify(Level::Warn, message);
    }

    fn refresh_suggestions(&mut self) {
        self.suggestions = cve_suggestions(
            self.cve.value(),
            &self.history,
            &self.recent,
            SUGGESTION_ROWS,
        );
        self.suggestion = self
            .suggestion
            .min(self.suggestions.len().saturating_sub(1));
    }

    /// Rebuilds the binary rows from the selected pair's list. A row the
    /// user moved to stays highlighted while it is still listed.
    fn refresh_options(&mut self) {
        let keep = self
            .picked
            .then(|| self.options.get(self.option).map(|o| o.name.clone()))
            .flatten();
        self.options = binary_options(self.binary.value(), self.listing());
        match keep.and_then(|name| self.options.iter().position(|o| o.name == name)) {
            Some(i) => self.option = i,
            None => {
                self.option = 0;
                self.picked = false;
            }
        }
        // The binary used last time, once the selected pair's list has it.
        if !self.picked
            && self.binary.value().is_empty()
            && self.listing().is_some()
            && let Some(name) = self.remembered.take()
            && let Some(i) = self.options.iter().position(|o| o.name == name)
        {
            self.option = i;
            self.picked = true;
        }
    }

    /// Moves the binary highlight; the first move from "nothing chosen yet"
    /// lands on the top row.
    fn move_option(&mut self, delta: isize) {
        if self.options.is_empty() {
            return;
        }
        if self.selection().is_some() {
            let last = self.options.len() as isize - 1;
            self.option = (self.option as isize + delta).clamp(0, last) as usize;
        }
        self.picked = true;
    }

    // ----- commands -----------------------------------------------------

    fn load(&mut self, cve: CveId) {
        if self.running() {
            let what = if self.fetching() {
                "A fetch"
            } else {
                "A file-list download"
            };
            self.notify(
                Level::Warn,
                format!("{what} is still running — press Esc twice to cancel it first"),
            );
            return;
        }
        self.loading = Some(cve.clone());
        self.load_error = None;
        self.popup_open = false;
        self.worker.submit(Command::LoadCve(cve));
    }

    /// Lists the selected pair's files in the background (never downloads a
    /// package). Also picks up a listing or comparison that an earlier
    /// prefetch left unfinished when the user moved on.
    fn prefetch_selected(&mut self) {
        self.prefetch_due = None;
        let (Some(report), Some(pair)) = (self.report.clone(), self.selected_pair().cloned())
        else {
            return;
        };
        let key = pair_key(&pair);
        // The listing in flight for another row is about to be cancelled:
        // forget it rather than leave that row spinning.
        if let Some(previous) = self.prefetching.take_if(|p| *p != key)
            && matches!(self.files.get(&previous), Some(Files::Loading))
        {
            self.files.remove(&previous);
        }
        let in_flight = self.prefetching.as_deref() == Some(key.as_str());
        let needed = match self.files.get(&key) {
            None => true,
            Some(Files::Loading) => !in_flight,
            Some(Files::Ready(listing)) => listing.comparison == Comparison::Pending && !in_flight,
            Some(Files::Failed(_) | Files::NeedsDownload { .. }) => false,
        };
        if !needed {
            return;
        }
        if !matches!(self.files.get(&key), Some(Files::Ready(_))) {
            self.files.insert(key.clone(), Files::Loading);
        }
        self.prefetching = Some(key);
        self.worker.submit(Command::Prefetch {
            report: Box::new((*report).clone()),
            pair,
        });
    }

    /// ② Enter: use this patch pair — its binaries are listed in ③.
    fn confirm_pair(&mut self) {
        let Some(pair) = self.selected_pair().cloned() else {
            return;
        };
        self.focus = Focus::Binary;
        self.prefetch_selected();
        let update = update_label(&pair.after);
        match self.selected_files() {
            Some(Files::NeedsDownload { size, .. }) => {
                let size = size
                    .map(|s| format!(" ({})", size_label(s)))
                    .unwrap_or_default();
                self.notify(
                    Level::Info,
                    format!(
                        "{update} lists its files only inside its package{size} — Enter downloads it, or type a file name"
                    ),
                );
            }
            Some(Files::Ready(listing)) => {
                let pick = listing.pick().map(|c| c.name.clone());
                match (self.chosen_binary(), pick) {
                    (Some(chosen), Some(pick)) if chosen == pick => self.notify(
                        Level::Info,
                        format!("★ {pick} is recommended from {update}'s files — Enter fetches it"),
                    ),
                    (Some(chosen), _) => self.notify(
                        Level::Info,
                        format!("{chosen} is picked from {update}'s files — Enter fetches it"),
                    ),
                    (None, _) => self.notify(
                        Level::Warn,
                        format!(
                            "No file of {update} matches Microsoft's text — ↓ to choose one, or type its name"
                        ),
                    ),
                }
            }
            _ => self.toast = None,
        }
    }

    /// ③ Enter: fetch the chosen binary, or — when nothing is chosen yet —
    /// do what it takes to get the pair's list.
    fn enter_binary(&mut self) {
        if self.chosen_binary().is_some() {
            return self.start();
        }
        if self.prefetch_due.is_some() {
            self.prefetch_selected();
        }
        let update = self
            .selected_pair()
            .map(|p| update_label(&p.after))
            .unwrap_or_default();
        match self.selected_files() {
            Some(Files::NeedsDownload { .. }) if self.listing_job().is_none() => {
                self.start_listing()
            }
            Some(Files::NeedsDownload { .. }) => self.notify(
                Level::Info,
                format!("Downloading {update} — its files appear here when done"),
            ),
            Some(Files::Loading) => self.notify(
                Level::Info,
                format!("Reading {update}'s files — the recommendation appears in a moment"),
            ),
            Some(Files::Failed(_)) => self.notify(
                Level::Warn,
                format!("{update}'s files could not be read — Ctrl-R retries, or type a file name"),
            ),
            Some(Files::Ready(_)) if !self.options.is_empty() => self.notify(
                Level::Info,
                format!(
                    "Nothing is recommended from {update} — ↓ to choose a file, or type its name"
                ),
            ),
            _ => self.start(),
        }
    }

    fn start(&mut self) {
        let (Some(report), Some(pair)) = (self.report.clone(), self.selected_pair().cloned())
        else {
            if self.report.is_some() {
                self.notify(
                    Level::Warn,
                    "This CVE has no patch pair that can be fetched",
                );
            } else {
                self.notify(
                    Level::Info,
                    "Load a CVE first — type its id and press Enter",
                );
                self.focus = Focus::Cve;
            }
            return;
        };
        let Some(binary) = self.chosen_binary() else {
            self.notify(
                Level::Info,
                "Pick a binary from the list, or type a file name like afd.sys",
            );
            self.focus = Focus::Binary;
            return;
        };
        if self.fetching() {
            self.notify(Level::Info, "Already fetching — press Esc twice to cancel");
            return;
        }
        // A listing download still running is superseded: the fetch needs
        // the same package and resumes that download.
        let id = self.next_job;
        self.next_job += 1;
        self.job = Some(Job {
            id,
            kind: JobKind::Fetch,
            pair: pair.clone(),
            binary: binary.to_string(),
            product: pair.short_product(),
            steps: Vec::new(),
            notes: Vec::new(),
            state: JobState::Running,
            started: Instant::now(),
            finished: None,
        });
        self.focus = Focus::Fetch;
        self.toast = None;
        self.worker.submit(Command::Acquire {
            job: id,
            report: Box::new((*report).clone()),
            pair,
            binary,
            // Only the recommended row may fall back; an explicit choice is kept.
            fallback: self.product == 0,
        });
    }

    /// Downloads the selected pair's package to list its files (a job, shown
    /// in ④ with progress; cancel with Esc Esc).
    fn start_listing(&mut self) {
        let (Some(report), Some(pair)) = (self.report.clone(), self.selected_pair().cloned())
        else {
            return;
        };
        if self.running() {
            self.notify(
                Level::Info,
                "Wait for the running job, or press Esc twice to cancel it",
            );
            return;
        }
        let id = self.next_job;
        self.next_job += 1;
        self.job = Some(Job {
            id,
            kind: JobKind::List,
            pair: pair.clone(),
            binary: update_label(&pair.after),
            product: pair.short_product(),
            steps: Vec::new(),
            notes: Vec::new(),
            state: JobState::Running,
            started: Instant::now(),
            finished: None,
        });
        self.toast = None;
        self.worker.submit(Command::ListFiles {
            job: id,
            report: Box::new((*report).clone()),
            pair,
        });
    }

    fn cancel_job(&mut self) {
        if let Some(job) = &self.job
            && job.is_running()
        {
            self.worker.submit(Command::Cancel { job: job.id });
            self.notify(Level::Info, "Cancelling…");
        }
    }

    fn retry(&mut self) {
        if self.load_error.is_some() {
            match CveId::parse(self.cve.value()) {
                Ok(cve) => self.load(cve),
                Err(e) => self.notify(Level::Warn, e.to_string()),
            }
        } else if matches!(self.selected_files(), Some(Files::Failed(_))) && !self.running() {
            if let Some(pair) = self.selected_pair() {
                self.files.remove(&pair_key(pair));
            }
            self.prefetch_selected();
        } else if self.can_retry() {
            match self.job.as_ref().map(|j| j.kind) {
                Some(JobKind::List) => {
                    if let Some(pair) = self.job.as_ref().map(|j| j.pair.clone())
                        && let Some(i) = self.pairs().iter().position(|p| *p == pair)
                    {
                        self.product = i;
                        self.on_product_changed();
                    }
                    self.start_listing();
                }
                _ => self.start(),
            }
        } else {
            self.notify(Level::Info, "Nothing to retry");
        }
    }

    fn new_cve(&mut self) {
        self.focus = Focus::Cve;
        self.cve.clear();
        self.popup_open = true;
        self.suggestion = 0;
        self.refresh_suggestions();
    }

    fn open_case(&mut self) {
        let Some(dir) = self.done_case().map(|c| c.directory.clone()) else {
            self.notify(Level::Info, "Nothing fetched yet");
            return;
        };
        match actions::open_folder(&dir) {
            Ok(()) => self.notify(Level::Success, format!("Opened {}", display_path(&dir))),
            Err(e) => self.notify(Level::Error, format!("Could not open the folder: {e}")),
        }
    }

    fn copy_case_path(&mut self) {
        let Some(dir) = self.done_case().map(|c| absolute(&c.directory)) else {
            self.notify(Level::Info, "Nothing fetched yet");
            return;
        };
        match actions::copy_to_clipboard(&dir.display().to_string()) {
            Ok(()) => self.notify(Level::Success, "Path copied to the clipboard"),
            Err(e) => self.notify(Level::Error, format!("Could not copy: {e}")),
        }
    }

    fn request_quit(&mut self) {
        if !self.running() || self.armed(Armed::Quit) {
            self.cancel_job();
            self.quit = true;
        } else {
            self.arm(
                Armed::Quit,
                "A fetch is running — press q again to cancel it and quit",
            );
        }
    }

    // ----- worker events ------------------------------------------------

    pub fn on_event(&mut self, event: Event) {
        match event {
            Event::Suggestions { recent, history } => {
                self.recent = recent;
                self.history = history;
                self.refresh_suggestions();
            }
            Event::SuggestionsFailed(error) => self.recent_error = Some(error),
            Event::CveLoading(cve) => self.loading = Some(cve),
            Event::CveLoaded(report) => self.on_loaded(*report),
            Event::CveFailed { cve, error, hint } => {
                if self.loading.as_ref() == Some(&cve) {
                    self.loading = None;
                    self.load_error = Some(Failure {
                        message: error,
                        hint,
                    });
                    self.focus = Focus::Cve;
                }
            }
            Event::PairListed { cve, .. }
            | Event::PairNeedsDownload { cve, .. }
            | Event::PairListFailed { cve, .. }
                if !self.shows(&cve) => {}
            Event::PairListed { pair, listing, .. } => {
                let key = pair_key(&pair);
                if listing.comparison != Comparison::Pending
                    && self.prefetching.as_deref() == Some(key.as_str())
                {
                    self.prefetching = None;
                }
                self.files.insert(key, Files::Ready(Arc::new(*listing)));
                if self.selected_pair() == Some(&pair) {
                    self.refresh_options();
                }
            }
            Event::PairNeedsDownload {
                pair,
                package,
                size,
                ..
            } => {
                let key = pair_key(&pair);
                if self.prefetching.as_deref() == Some(key.as_str()) {
                    self.prefetching = None;
                }
                self.files
                    .insert(key, Files::NeedsDownload { package, size });
            }
            Event::PairListFailed { pair, error, .. } => {
                let key = pair_key(&pair);
                if self.prefetching.as_deref() == Some(key.as_str()) {
                    self.prefetching = None;
                }
                self.files.insert(key, Files::Failed(error));
            }
            Event::ListDone { job } => {
                let selected = self.selected_pair().cloned();
                if let Some(j) = self.job_mut(job) {
                    j.finished = Some(j.started.elapsed());
                    j.state = JobState::Listed;
                    let pair = j.pair.clone();
                    if selected.as_ref() == Some(&pair) {
                        self.focus = Focus::Binary;
                        let update = update_label(&pair.after);
                        let text = match self.listing() {
                            Some(listing) => match listing.pick() {
                                Some(pick) => format!(
                                    "{} files in {update} · ★ {} recommended — Enter fetches it",
                                    listing.files.names.len(),
                                    pick.name
                                ),
                                None => format!(
                                    "{} files in {update} — none matches Microsoft's text; ↓ to choose one",
                                    listing.files.names.len()
                                ),
                            },
                            None => format!("{update} listed"),
                        };
                        self.notify(Level::Success, text);
                    }
                }
            }
            Event::StepStarted { job, step, label } => {
                if let Some(j) = self.job_mut(job) {
                    j.steps.push(StepView {
                        id: step,
                        label,
                        detail: String::new(),
                        done: 0,
                        total: None,
                        state: StepState::Running,
                        started: Instant::now(),
                        elapsed: None,
                    });
                }
            }
            Event::StepProgress {
                job,
                step,
                done,
                total,
            } => {
                if let Some(s) = self
                    .job_mut(job)
                    .and_then(|j| j.steps.iter_mut().find(|s| s.id == step))
                {
                    s.done = done;
                    s.total = total;
                }
            }
            Event::StepFinished {
                job,
                step,
                ok,
                detail,
            } => {
                if let Some(s) = self
                    .job_mut(job)
                    .and_then(|j| j.steps.iter_mut().find(|s| s.id == step))
                {
                    s.state = if ok {
                        StepState::Done
                    } else {
                        StepState::Failed
                    };
                    s.detail = detail;
                    s.elapsed = Some(s.started.elapsed());
                }
            }
            Event::Note { job, text } => {
                if let Some(j) = self.job_mut(job) {
                    j.notes.push(text);
                }
            }
            Event::CaseDone { job, result } => {
                let message = format!("Fetched {} — press o to open the folder", result.binary);
                if let Some(j) = self.job_mut(job) {
                    j.finished = Some(j.started.elapsed());
                    j.state = JobState::Done(result);
                    self.notify(Level::Success, message);
                }
                self.relist_downloaded();
                self.history_bump();
            }
            Event::CaseFailed {
                job,
                error,
                hint,
                cancelled,
            } => {
                if let Some(j) = self.job_mut(job) {
                    j.finished = Some(j.started.elapsed());
                    j.state = if cancelled {
                        JobState::Cancelled
                    } else {
                        JobState::Failed(Failure {
                            message: error,
                            hint,
                        })
                    };
                }
            }
        }
    }

    /// Whether `cve` is the CVE on screen.
    fn shows(&self, cve: &CveId) -> bool {
        self.report
            .as_ref()
            .is_some_and(|r| &r.detail.summary.id == cve)
    }

    /// A fetch downloads the package a "needs download" list was waiting
    /// for: list the selected pair again, now without a download.
    fn relist_downloaded(&mut self) {
        if let Some(pair) = self.selected_pair()
            && matches!(self.files_for(pair), Some(Files::NeedsDownload { .. }))
        {
            self.files.remove(&pair_key(pair));
            self.prefetch_selected();
        }
    }

    fn on_loaded(&mut self, report: CveReport) {
        if self.loading.as_ref() != Some(&report.detail.summary.id) {
            return;
        }
        self.loading = None;
        self.cve.set(report.detail.summary.id.as_str());
        self.product = 0;
        self.binary.clear();
        self.picked = false;
        self.remembered = report.remembered_binary.clone();
        let empty = report.detail.patches.is_empty();
        let unsupported = report.detail.unsupported.len();
        self.report = Some(Arc::new(report));
        self.files.clear();
        self.prefetching = None;
        self.refresh_options();
        // ② comes next: the binary is chosen from the pair's update.
        self.focus = Focus::Products;
        if empty {
            let text = match unsupported {
                0 => "MSRC lists no affected product for this CVE".to_owned(),
                1 => "Its only affected product cannot be fetched — see ② for why".to_owned(),
                n => format!("None of its {n} affected products can be fetched — see ② for why"),
            };
            self.notify(Level::Warn, text);
        } else {
            self.notify(
                Level::Info,
                "★ is the recommended patch pair — Enter lists the binaries of its update",
            );
            self.prefetch_selected();
        }
        self.history_bump();
    }

    fn job_mut(&mut self, id: JobId) -> Option<&mut Job> {
        self.job.as_mut().filter(|j| j.id == id)
    }

    fn history_bump(&mut self) {
        self.history = self
            .worker
            .services()
            .history
            .lock()
            .expect("history")
            .entries()
            .to_vec();
        self.refresh_suggestions();
    }

    // ----- keys ---------------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if self.running() {
                self.cancel_job();
            } else {
                self.quit = true;
            }
            return;
        }
        if ctrl && key.code == KeyCode::Char('q') {
            self.cancel_job();
            self.quit = true;
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        match key.code {
            KeyCode::F(1) | KeyCode::Char('?') => {
                self.show_help = true;
                return;
            }
            KeyCode::Char('r') if ctrl => {
                self.retry();
                return;
            }
            KeyCode::Esc => {
                self.on_escape();
                return;
            }
            KeyCode::BackTab => {
                self.focus = self.focus.previous();
                self.on_focus_changed();
                return;
            }
            KeyCode::Tab if self.tab_completes() => {}
            KeyCode::Tab => {
                self.focus = self.focus.next();
                self.on_focus_changed();
                return;
            }
            _ => {}
        }
        match self.focus {
            Focus::Cve => self.on_cve_key(key, ctrl),
            Focus::Products => self.on_products_key(key),
            Focus::Binary => self.on_binary_key(key, ctrl),
            Focus::Fetch => self.on_fetch_key(key),
        }
    }

    /// Tab completes the highlighted suggestion before it moves focus.
    pub fn tab_completes(&self) -> bool {
        match self.focus {
            Focus::Cve => {
                self.popup_open
                    && self
                        .suggestions
                        .get(self.suggestion)
                        .is_some_and(|s| s.id != self.cve.value())
            }
            Focus::Binary => {
                !self.binary.value().is_empty()
                    && self
                        .selection()
                        .is_some_and(|i| self.options[i].name != self.binary.value())
            }
            _ => false,
        }
    }

    fn on_focus_changed(&mut self) {
        if self.focus == Focus::Cve {
            self.popup_open = !self.typed_is_loaded();
            self.refresh_suggestions();
        }
    }

    fn on_escape(&mut self) {
        if self.focus == Focus::Cve && self.popup_open {
            self.popup_open = false;
        } else if self.running() {
            if self.armed(Armed::CancelFetch) {
                self.armed = None;
                self.cancel_job();
            } else {
                self.arm(Armed::CancelFetch, "Press Esc again to cancel the fetch");
            }
        } else if self.focus != Focus::Cve {
            self.focus = self.focus.previous();
            self.on_focus_changed();
        }
    }

    fn on_cve_key(&mut self, key: KeyEvent, ctrl: bool) {
        match key.code {
            KeyCode::Up => {
                self.popup_open = true;
                self.suggestion = self.suggestion.saturating_sub(1);
            }
            KeyCode::Down => {
                if self.popup_open {
                    self.suggestion =
                        (self.suggestion + 1).min(self.suggestions.len().saturating_sub(1));
                } else {
                    self.popup_open = true;
                    self.refresh_suggestions();
                }
            }
            KeyCode::PageUp => self.suggestion = self.suggestion.saturating_sub(5),
            KeyCode::PageDown => {
                self.suggestion =
                    (self.suggestion + 5).min(self.suggestions.len().saturating_sub(1))
            }
            KeyCode::Tab => self.accept_suggestion(),
            KeyCode::Enter => self.submit_cve(),
            KeyCode::Char('w') if ctrl => self.edit_cve(TextInput::delete_word),
            KeyCode::Char('u') if ctrl => self.edit_cve(TextInput::clear),
            KeyCode::Char(c) if !ctrl => self.edit_cve(|t| t.insert(c)),
            KeyCode::Backspace => self.edit_cve(TextInput::backspace),
            KeyCode::Delete => self.edit_cve(TextInput::delete),
            KeyCode::Left => self.cve.left(),
            KeyCode::Right => {
                if self.cve.at_end() && self.popup_open {
                    self.accept_suggestion();
                } else {
                    self.cve.right();
                }
            }
            KeyCode::Home => self.cve.home(),
            KeyCode::End => self.cve.end(),
            _ => {}
        }
    }

    fn accept_suggestion(&mut self) {
        if let Some(s) = self.suggestions.get(self.suggestion).cloned() {
            self.cve.set(s.id);
            self.refresh_suggestions();
        }
    }

    fn submit_cve(&mut self) {
        let typed = self.cve.value().trim().to_owned();
        let exact = CveId::parse(&typed).ok();
        if exact.is_some() && self.typed_is_loaded() && self.loading.is_none() {
            // Already shown: Enter moves on to the next step.
            self.popup_open = false;
            self.focus = if self.pairs().is_empty() {
                Focus::Products
            } else {
                Focus::Binary
            };
            return;
        }
        let picked = if self.popup_open && exact.is_none() {
            self.suggestions
                .get(self.suggestion)
                .and_then(|s| CveId::parse(&s.id).ok())
        } else {
            None
        };
        match exact.or(picked) {
            Some(cve) => {
                self.cve.set(cve.as_str());
                self.load(cve);
            }
            None if typed.is_empty() => self.notify(
                Level::Info,
                "Type a CVE id (e.g. CVE-2024-38193) or words from its title",
            ),
            None => self.notify(
                Level::Warn,
                format!("No CVE matches `{typed}` — try fewer words or a full id"),
            ),
        }
    }

    fn edit_cve(&mut self, edit: impl FnOnce(&mut TextInput)) {
        edit(&mut self.cve);
        self.popup_open = true;
        self.suggestion = 0;
        self.refresh_suggestions();
    }

    fn on_products_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => return self.request_quit(),
            KeyCode::Char('r') => return self.retry(),
            KeyCode::Char('n') => return self.new_cve(),
            _ => {}
        }
        let count = self.pairs().len();
        if count == 0 {
            if key.code == KeyCode::Enter {
                self.new_cve();
            }
            return;
        }
        let before = self.product;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.product = self.product.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.product = (self.product + 1).min(count - 1),
            KeyCode::PageUp => self.product = self.product.saturating_sub(8),
            KeyCode::PageDown => self.product = (self.product + 8).min(count - 1),
            KeyCode::Home | KeyCode::Char('g') => self.product = 0,
            KeyCode::End | KeyCode::Char('G') => self.product = count - 1,
            KeyCode::Enter => self.confirm_pair(),
            _ => {}
        }
        if before != self.product {
            self.on_product_changed();
        }
    }

    fn on_product_changed(&mut self) {
        // A row picked in another pair's list means nothing here.
        self.picked = false;
        self.prefetch_due = Some(Instant::now() + PREFETCH_DELAY);
        self.refresh_options();
    }

    fn on_binary_key(&mut self, key: KeyEvent, ctrl: bool) {
        match key.code {
            KeyCode::Up => self.move_option(-1),
            KeyCode::Down => self.move_option(1),
            KeyCode::PageUp => self.move_option(-8),
            KeyCode::PageDown => self.move_option(8),
            KeyCode::Tab => self.complete_binary(),
            KeyCode::Enter => self.enter_binary(),
            KeyCode::Char('w') if ctrl => self.edit_binary(TextInput::delete_word),
            KeyCode::Char('u') if ctrl => self.edit_binary(TextInput::clear),
            KeyCode::Char(c) if !ctrl => self.edit_binary(|t| t.insert(c)),
            KeyCode::Backspace => self.edit_binary(TextInput::backspace),
            KeyCode::Delete => self.edit_binary(TextInput::delete),
            KeyCode::Left => self.binary.left(),
            KeyCode::Right => {
                if self.binary.at_end() {
                    self.complete_binary();
                } else {
                    self.binary.right();
                }
            }
            KeyCode::Home => self.binary.home(),
            KeyCode::End => self.binary.end(),
            _ => {}
        }
    }

    /// Puts the highlighted row's name into the search box.
    fn complete_binary(&mut self) {
        if let Some(name) = self.selection().map(|i| self.options[i].name.clone()) {
            self.binary.set(name);
            self.refresh_options();
        }
    }

    fn edit_binary(&mut self, edit: impl FnOnce(&mut TextInput)) {
        edit(&mut self.binary);
        self.option = 0;
        self.picked = false;
        // "Recommended … picked" no longer describes what is chosen.
        if self.toast.as_ref().is_some_and(|t| t.level == Level::Info) {
            self.toast = None;
        }
        self.options = binary_options(self.binary.value(), self.listing());
    }

    fn on_fetch_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if !self.running() {
                    self.start();
                }
            }
            KeyCode::Char('r') => self.retry(),
            KeyCode::Char('o') => self.open_case(),
            KeyCode::Char('y') | KeyCode::Char('c') => self.copy_case_path(),
            KeyCode::Char('n') => self.new_cve(),
            KeyCode::Char('q') => self.request_quit(),
            _ => {}
        }
    }

    // ----- mouse --------------------------------------------------------

    pub fn on_mouse(&mut self, mouse: MouseEvent) {
        if self.show_help {
            if matches!(mouse.kind, MouseEventKind::Down(_)) {
                self.show_help = false;
            }
            return;
        }
        let areas = layout::compute(self.screen, self);
        let (x, y) = (mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let double = self
                    .last_click
                    .is_some_and(|(at, cx, cy)| at.elapsed() < DOUBLE_CLICK && cx == x && cy == y);
                self.last_click = Some((Instant::now(), x, y));
                self.click(&areas, x, y, double);
            }
            MouseEventKind::ScrollDown => self.scroll(&areas, x, y, 1),
            MouseEventKind::ScrollUp => self.scroll(&areas, x, y, -1),
            _ => {}
        }
    }

    fn dropdown_visible(&self) -> bool {
        self.focus == Focus::Cve && self.popup_open && !self.suggestions.is_empty()
    }

    fn click(&mut self, areas: &Areas, x: u16, y: u16, double: bool) {
        if self.dropdown_visible() {
            let drop = layout::dropdown(areas, self.suggestions.len());
            if layout::contains(drop, x, y) {
                let inner = layout::inner(drop);
                if layout::contains(inner, x, y) {
                    let offset = layout::list_offset(self.suggestion, inner.height);
                    let row = offset + (y - inner.y) as usize;
                    if row < self.suggestions.len() {
                        self.suggestion = row;
                        if double {
                            self.accept_suggestion();
                            self.submit_cve();
                        }
                    }
                }
                return;
            }
        }
        let target = [
            (areas.cve, Focus::Cve),
            (areas.products, Focus::Products),
            (areas.binary, Focus::Binary),
            (areas.fetch, Focus::Fetch),
        ]
        .into_iter()
        .find(|(area, _)| layout::contains(*area, x, y));
        let Some((area, focus)) = target else {
            return;
        };
        if self.focus != focus {
            self.focus = focus;
            self.on_focus_changed();
        }
        match focus {
            Focus::Products => {
                let inner = layout::inner(area);
                if layout::contains(inner, x, y) && !self.pairs().is_empty() {
                    let offset = layout::list_offset(self.product, inner.height);
                    let row = offset + (y - inner.y) as usize;
                    if row < self.pairs().len() {
                        if row != self.product {
                            self.product = row;
                            self.on_product_changed();
                        } else if double {
                            self.confirm_pair();
                        }
                    }
                }
            }
            Focus::Binary => {
                // Row 0 of the inner area is the search box.
                let inner = layout::inner(area);
                let list_top = inner.y + 1;
                if y >= list_top && y < inner.bottom() && !self.options.is_empty() {
                    let offset = layout::list_offset(self.option, inner.height.saturating_sub(1));
                    let row = offset + (y - list_top) as usize;
                    if row < self.options.len() {
                        let again = self.selection() == Some(row);
                        self.option = row;
                        self.picked = true;
                        if again && double {
                            self.enter_binary();
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn scroll(&mut self, areas: &Areas, x: u16, y: u16, delta: isize) {
        let step = |value: usize, len: usize| -> usize {
            (value as isize + delta).clamp(0, len.saturating_sub(1) as isize) as usize
        };
        if self.dropdown_visible()
            && layout::contains(layout::dropdown(areas, self.suggestions.len()), x, y)
        {
            self.suggestion = step(self.suggestion, self.suggestions.len());
        } else if layout::contains(areas.products, x, y) && !self.pairs().is_empty() {
            let next = step(self.product, self.pairs().len());
            if next != self.product {
                self.product = next;
                self.on_product_changed();
            }
        } else if layout::contains(areas.binary, x, y) {
            self.move_option(delta);
        }
    }

    pub fn on_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        if self.prefetch_due.is_some_and(|due| Instant::now() >= due) {
            self.prefetch_selected();
        }
    }
}

/// How an update is named on screen: `KB5041571`, `build 17932.21140`,
/// `engine 1.1.25010.7`.
pub fn update_label(update: &UpdateRef) -> String {
    match update {
        UpdateRef::Kb { kb } => kb.clone(),
        UpdateRef::OfficeBuild { version, .. } => {
            format!("build {}", version.strip_prefix("16.0.").unwrap_or(version))
        }
        UpdateRef::Engine { version } => format!("engine {version}"),
    }
}

/// `990 MB`, `1.8 GB`.
pub fn size_label(bytes: u64) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    if mb >= 1024.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else {
        format!("{mb:.0} MB")
    }
}

/// Identity of a patch pair row for the file-list cache.
pub fn pair_key(pair: &PatchPair) -> String {
    format!(
        "{:?}|{}|{}|{}",
        pair.family, pair.arch, pair.before, pair.after
    )
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Absolute path with the home directory shown as `~`.
pub fn display_path(path: &Path) -> String {
    let full = absolute(path);
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home.and_then(|h| full.strip_prefix(&h).ok().map(Path::to_path_buf)) {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => full.display().to_string(),
    }
}
