//! UI state and how it reacts to keys and worker events. Rendering lives in
//! `view`; this module never draws.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{
    complete::{BinaryOption, CveSuggestion, binary_options, cve_suggestions},
    input::TextInput,
};
use crate::{
    app::{Command, CveReport, Event, JobId, Worker},
    domain::{BinaryName, Candidate, CaseResult, CveId, CveSummary, PatchPair},
    store::HistoryEntry,
};

const SUGGESTION_ROWS: usize = 8;
const BINARY_ROWS: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Cve,
    Products,
    Binary,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Self::Cve => Self::Products,
            Self::Products => Self::Binary,
            Self::Binary => Self::Cve,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Cve => Self::Binary,
            Self::Products => Self::Cve,
            Self::Binary => Self::Products,
        }
    }
}

/// What we know about the fixing package of a product row.
#[derive(Debug, Clone)]
pub enum Names {
    Loading,
    Ready {
        names: Vec<String>,
        candidates: Vec<Candidate>,
    },
    Failed(String),
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
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub title: String,
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
    pub load_error: Option<String>,
    pub report: Option<Arc<CveReport>>,
    pub product: usize,

    pub binary: TextInput,
    pub options: Vec<BinaryOption>,
    pub option: usize,
    pub names: HashMap<String, Names>,

    pub job: Option<Job>,
    next_job: JobId,

    pub show_help: bool,
    pub status: Option<(String, Instant)>,
    pub tick: u64,
    pub quit: bool,
}

impl App {
    pub fn new(worker: Worker, initial: Option<String>) -> Self {
        let workspace = worker.services().settings.workspace.display().to_string();
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
            names: HashMap::new(),
            job: None,
            next_job: 1,
            show_help: false,
            status: None,
            tick: 0,
            quit: false,
        };
        app.worker.submit(Command::LoadSuggestions);
        if let Some(initial) = initial {
            app.cve.set(initial.clone());
            match CveId::parse(&initial) {
                Ok(cve) => app.load(cve),
                Err(e) => app.flash(e.to_string()),
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

    pub fn names_for(&self, pair: &PatchPair) -> Option<&Names> {
        self.names.get(&pair_key(pair))
    }

    /// Candidates refined by the selected product's package when known.
    pub fn candidates(&self) -> Vec<Candidate> {
        let base = self
            .report
            .as_ref()
            .map(|r| r.candidates.clone())
            .unwrap_or_default();
        match self.selected_pair().and_then(|p| self.names_for(p)) {
            Some(Names::Ready { candidates, .. }) => candidates.clone(),
            _ => base,
        }
    }

    fn package_names(&self) -> Vec<String> {
        match self.selected_pair().and_then(|p| self.names_for(p)) {
            Some(Names::Ready { names, .. }) => names.clone(),
            _ => Vec::new(),
        }
    }

    pub fn chosen_binary(&self) -> Option<BinaryName> {
        if let Some(option) = self.options.get(self.option) {
            return BinaryName::parse(&option.name).ok();
        }
        BinaryName::parse(self.binary.value()).ok()
    }

    pub fn flash(&mut self, message: impl Into<String>) {
        self.status = Some((message.into(), Instant::now()));
    }

    pub fn status_text(&self) -> Option<&str> {
        self.status
            .as_ref()
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(6))
            .map(|(m, _)| m.as_str())
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

    fn refresh_options(&mut self) {
        let keep = self.options.get(self.option).map(|o| o.name.clone());
        self.options = binary_options(
            self.binary.value(),
            &self.candidates(),
            &self.package_names(),
            BINARY_ROWS,
        );
        self.option = keep
            .and_then(|name| self.options.iter().position(|o| o.name == name))
            .unwrap_or(0);
    }

    // ----- commands -----------------------------------------------------

    fn load(&mut self, cve: CveId) {
        if self.job.as_ref().is_some_and(Job::is_running) {
            self.flash("A fetch is running — press Esc to cancel it first");
            return;
        }
        self.loading = Some(cve.clone());
        self.load_error = None;
        self.popup_open = false;
        self.worker.submit(Command::LoadCve(cve));
    }

    fn prefetch_selected(&mut self) {
        let (Some(report), Some(pair)) = (self.report.clone(), self.selected_pair().cloned())
        else {
            return;
        };
        let key = pair_key(&pair);
        if self.names.contains_key(&key) {
            return;
        }
        self.names.insert(key, Names::Loading);
        self.worker.submit(Command::Prefetch {
            report: Box::new((*report).clone()),
            pair,
        });
    }

    fn start(&mut self) {
        let (Some(report), Some(pair)) = (self.report.clone(), self.selected_pair().cloned())
        else {
            self.flash("Load a CVE first");
            return;
        };
        let Some(binary) = self.chosen_binary() else {
            self.flash("Pick a binary from the list or type a file name like afd.sys");
            self.focus = Focus::Binary;
            return;
        };
        if self.job.as_ref().is_some_and(Job::is_running) {
            self.flash("Already fetching — Esc cancels");
            return;
        }
        let id = self.next_job;
        self.next_job += 1;
        self.job = Some(Job {
            id,
            title: format!("{binary} · {}", pair.short_product()),
            steps: Vec::new(),
            notes: Vec::new(),
            state: JobState::Running,
            started: Instant::now(),
            finished: None,
        });
        self.worker.submit(Command::Acquire {
            job: id,
            report: Box::new((*report).clone()),
            pair,
            binary,
            // Only the recommended row may fall back; an explicit choice is kept.
            fallback: self.product == 0,
        });
    }

    fn cancel_job(&mut self) -> bool {
        match &mut self.job {
            Some(job) if job.is_running() => {
                self.worker.submit(Command::Cancel { job: job.id });
                self.flash("Cancelling…");
                true
            }
            _ => false,
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
            Event::CveLoaded(report) => {
                if self.loading.as_ref() != Some(&report.detail.summary.id) {
                    return;
                }
                self.loading = None;
                self.cve.set(report.detail.summary.id.as_str());
                self.product = 0;
                self.binary.clear();
                let remembered = report.remembered_binary.clone();
                let empty = report.detail.patches.is_empty();
                self.report = Some(Arc::new(*report));
                self.names.clear();
                self.refresh_options();
                if let Some(name) = remembered
                    && let Some(i) = self.options.iter().position(|o| o.name == name)
                {
                    self.option = i;
                }
                if empty {
                    self.focus = Focus::Cve;
                    self.flash(
                        "No acquirable product for this CVE (see the list of skipped products)",
                    );
                } else {
                    self.focus = Focus::Binary;
                    self.prefetch_selected();
                }
                self.history_bump();
            }
            Event::CveFailed { cve, error } => {
                if self.loading.as_ref() == Some(&cve) {
                    self.loading = None;
                    self.load_error = Some(error);
                    self.focus = Focus::Cve;
                }
            }
            Event::PackageNames {
                pair,
                names,
                candidates,
            } => {
                self.names
                    .insert(pair_key(&pair), Names::Ready { names, candidates });
                self.refresh_options();
            }
            Event::PackageNamesFailed { pair, error } => {
                self.names.insert(pair_key(&pair), Names::Failed(error));
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
                if let Some(j) = self.job_mut(job) {
                    j.finished = Some(j.started.elapsed());
                    j.state = JobState::Done(result);
                }
                self.history_bump();
            }
            Event::CaseFailed { job, error } => {
                if let Some(j) = self.job_mut(job) {
                    j.finished = Some(j.started.elapsed());
                    j.state = if error == "cancelled" {
                        JobState::Cancelled
                    } else {
                        JobState::Failed(error)
                    };
                }
            }
        }
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
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            if !self.cancel_job() || matches!(key.code, KeyCode::Char('q')) {
                self.quit = true;
            }
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        match key.code {
            KeyCode::F(1) => {
                self.show_help = true;
                return;
            }
            KeyCode::Char('?') if self.focus == Focus::Products => {
                self.show_help = true;
                return;
            }
            KeyCode::Esc => {
                if self.focus == Focus::Cve && self.popup_open {
                    self.popup_open = false;
                } else if !self.cancel_job() {
                    self.focus = Focus::Cve;
                    self.popup_open = true;
                    self.refresh_suggestions();
                }
                return;
            }
            KeyCode::BackTab => {
                self.focus = self.focus.previous();
                return;
            }
            KeyCode::Tab
                if !(self.focus == Focus::Cve
                    && self.popup_open
                    && !self.suggestions.is_empty()) =>
            {
                if self.focus == Focus::Binary
                    && !self.options.is_empty()
                    && !self.binary.value().is_empty()
                {
                    // Tab completes the highlighted binary first.
                    let name = self.options[self.option].name.clone();
                    if self.binary.value() != name {
                        self.binary.set(name);
                        self.refresh_options();
                        return;
                    }
                }
                self.focus = self.focus.next();
                if self.focus == Focus::Cve {
                    self.popup_open = true;
                    self.refresh_suggestions();
                }
                return;
            }
            _ => {}
        }
        match self.focus {
            Focus::Cve => self.on_cve_key(key, ctrl),
            Focus::Products => self.on_products_key(key),
            Focus::Binary => self.on_binary_key(key, ctrl),
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
            KeyCode::Tab => {
                if let Some(s) = self.suggestions.get(self.suggestion) {
                    self.cve.set(s.id.clone());
                    self.refresh_suggestions();
                }
            }
            KeyCode::Enter => {
                let typed = self.cve.value().trim().to_owned();
                let exact = CveId::parse(&typed).ok();
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
                    None if typed.is_empty() => {
                        self.flash("Type a CVE id (e.g. CVE-2024-38193) or words from its title")
                    }
                    None => self.flash(format!(
                        "`{typed}` is not a CVE id — pick a suggestion with ↑/↓"
                    )),
                }
            }
            KeyCode::Char('w') if ctrl => self.edit_cve(|t| t.delete_word()),
            KeyCode::Char('u') if ctrl => self.edit_cve(TextInput::clear),
            KeyCode::Char(c) if !ctrl => self.edit_cve(|t| t.insert(c)),
            KeyCode::Backspace => self.edit_cve(TextInput::backspace),
            KeyCode::Delete => self.edit_cve(TextInput::delete),
            KeyCode::Left => self.cve.left(),
            KeyCode::Right => {
                if self.cve.at_end() {
                    if let Some(s) = self.suggestions.get(self.suggestion).cloned() {
                        self.cve.set(s.id);
                        self.refresh_suggestions();
                    }
                } else {
                    self.cve.right();
                }
            }
            KeyCode::Home => self.cve.home(),
            KeyCode::End => self.cve.end(),
            _ => {}
        }
    }

    fn edit_cve(&mut self, edit: impl FnOnce(&mut TextInput)) {
        edit(&mut self.cve);
        self.popup_open = true;
        self.suggestion = 0;
        self.refresh_suggestions();
    }

    fn on_products_key(&mut self, key: KeyEvent) {
        let count = self.pairs().len();
        if count == 0 {
            return;
        }
        let before = self.product;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.product = self.product.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.product = (self.product + 1).min(count - 1),
            KeyCode::PageUp => self.product = self.product.saturating_sub(8),
            KeyCode::PageDown => self.product = (self.product + 8).min(count - 1),
            KeyCode::Home => self.product = 0,
            KeyCode::End => self.product = count - 1,
            KeyCode::Enter => {
                if self.chosen_binary().is_some() {
                    self.start();
                } else {
                    self.focus = Focus::Binary;
                }
            }
            _ => {}
        }
        if before != self.product {
            self.prefetch_selected();
            self.refresh_options();
        }
    }

    fn on_binary_key(&mut self, key: KeyEvent, ctrl: bool) {
        match key.code {
            KeyCode::Up => self.option = self.option.saturating_sub(1),
            KeyCode::Down => {
                self.option = (self.option + 1).min(self.options.len().saturating_sub(1))
            }
            KeyCode::PageUp => self.option = self.option.saturating_sub(8),
            KeyCode::PageDown => {
                self.option = (self.option + 8).min(self.options.len().saturating_sub(1))
            }
            KeyCode::Enter => self.start(),
            KeyCode::Char('w') if ctrl => self.edit_binary(TextInput::delete_word),
            KeyCode::Char('u') if ctrl => self.edit_binary(TextInput::clear),
            KeyCode::Char(c) if !ctrl => self.edit_binary(|t| t.insert(c)),
            KeyCode::Backspace => self.edit_binary(TextInput::backspace),
            KeyCode::Delete => self.edit_binary(TextInput::delete),
            KeyCode::Left => self.binary.left(),
            KeyCode::Right => {
                if self.binary.at_end() {
                    if let Some(o) = self.options.get(self.option).cloned() {
                        self.binary.set(o.name);
                        self.refresh_options();
                    }
                } else {
                    self.binary.right();
                }
            }
            KeyCode::Home => self.binary.home(),
            KeyCode::End => self.binary.end(),
            _ => {}
        }
    }

    fn edit_binary(&mut self, edit: impl FnOnce(&mut TextInput)) {
        edit(&mut self.binary);
        self.option = 0;
        self.options = binary_options(
            self.binary.value(),
            &self.candidates(),
            &self.package_names(),
            BINARY_ROWS,
        );
    }

    pub fn on_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }
}

/// Identity of a product row for the names cache.
pub fn pair_key(pair: &PatchPair) -> String {
    format!(
        "{:?}|{}|{}|{}",
        pair.family, pair.arch, pair.before, pair.after
    )
}
