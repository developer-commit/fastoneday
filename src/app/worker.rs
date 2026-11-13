//! Runs commands on background threads so the UI never blocks.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, mpsc::Sender},
    thread,
};

use super::{
    events::{Command, Comparison, CveReport, Event, JobId},
    progress::ChannelProgress,
    services::Services,
    usecases::{self, Listing},
};
use crate::{
    acquire::{Progress, Silent},
    domain::PatchPair,
    error::{Error, Result},
    io::Cancel,
};

pub struct Worker {
    services: Arc<Services>,
    events: Sender<Event>,
    jobs: Arc<Mutex<HashMap<JobId, Cancel>>>,
    prefetch: Mutex<Option<Cancel>>,
}

impl Worker {
    pub fn new(services: Arc<Services>, events: Sender<Event>) -> Self {
        Self {
            services,
            events,
            jobs: Arc::default(),
            prefetch: Mutex::new(None),
        }
    }

    pub fn services(&self) -> &Arc<Services> {
        &self.services
    }

    pub fn submit(&self, command: Command) {
        let services = self.services.clone();
        let tx = self.events.clone();
        match command {
            Command::LoadSuggestions => {
                thread::spawn(move || {
                    let history = services.history.lock().expect("history").entries().to_vec();
                    match usecases::recent_cves(&services) {
                        Ok(recent) => tx.send(Event::Suggestions { recent, history }),
                        Err(e) => {
                            let _ = tx.send(Event::Suggestions {
                                recent: Vec::new(),
                                history,
                            });
                            tx.send(Event::SuggestionsFailed(e.to_string()))
                        }
                    }
                    .ok();
                });
            }
            Command::LoadCve(cve) => {
                thread::spawn(move || {
                    let _ = tx.send(Event::CveLoading(cve.clone()));
                    let event = match usecases::load_cve(&services, &cve) {
                        Ok(report) => Event::CveLoaded(Box::new(report)),
                        Err(e) => Event::CveFailed {
                            cve,
                            hint: super::hints::lookup(&e),
                            error: e.to_string(),
                        },
                    };
                    let _ = tx.send(event);
                });
            }
            Command::Prefetch { report, pair } => {
                let cancel = Cancel::new();
                if let Some(previous) = self
                    .prefetch
                    .lock()
                    .expect("prefetch")
                    .replace(cancel.clone())
                {
                    previous.cancel();
                }
                thread::spawn(move || {
                    let _ =
                        list_and_compare(&services, &report, &pair, false, &Silent, &cancel, &tx);
                });
            }
            Command::ListFiles { job, report, pair } => {
                let cancel = self.register(job);
                let jobs = self.jobs.clone();
                thread::spawn(move || {
                    let progress = ChannelProgress::new(tx.clone(), job);
                    let event = match list_and_compare(
                        &services, &report, &pair, true, &progress, &cancel, &tx,
                    ) {
                        Ok(()) => Event::ListDone { job },
                        Err(e) => Event::CaseFailed {
                            job,
                            hint: super::hints::fetch(&e),
                            cancelled: matches!(e, Error::Cancelled),
                            error: e.to_string(),
                        },
                    };
                    drop(progress);
                    jobs.lock().expect("jobs").remove(&job);
                    let _ = tx.send(event);
                });
            }
            Command::Acquire {
                job,
                report,
                pair,
                binary,
                fallback,
            } => {
                let cancel = self.register(job);
                let jobs = self.jobs.clone();
                thread::spawn(move || {
                    let progress = ChannelProgress::new(tx.clone(), job);
                    let run = if fallback {
                        usecases::acquire_case_with_fallback
                    } else {
                        usecases::acquire_case
                    };
                    let event = match run(&services, &report, &pair, &binary, &progress, &cancel) {
                        Ok(result) => Event::CaseDone {
                            job,
                            result: Box::new(result),
                        },
                        Err(e) => Event::CaseFailed {
                            job,
                            hint: super::hints::fetch(&e),
                            cancelled: matches!(e, Error::Cancelled),
                            error: e.to_string(),
                        },
                    };
                    drop(progress);
                    jobs.lock().expect("jobs").remove(&job);
                    let _ = tx.send(event);
                });
            }
            Command::Cancel { job } => {
                if let Some(cancel) = self.jobs.lock().expect("jobs").get(&job) {
                    cancel.cancel();
                }
            }
        }
    }

    /// One job runs at a time: a new one cancels the others.
    fn register(&self, job: JobId) -> Cancel {
        let cancel = Cancel::new();
        let mut jobs = self.jobs.lock().expect("jobs");
        for other in jobs.values() {
            other.cancel();
        }
        jobs.insert(job, cancel.clone());
        cancel
    }
}

/// Lists `pair` and reports it at once, then compares it with the before
/// update and reports it again. Every outcome becomes an event; the error is
/// also returned so a job can report how it ended.
fn list_and_compare(
    services: &Services,
    report: &CveReport,
    pair: &PatchPair,
    allow_download: bool,
    progress: &dyn Progress,
    cancel: &Cancel,
    tx: &Sender<Event>,
) -> Result<()> {
    let cve = &report.detail.summary.id;
    let listed = usecases::list_pair(services, report, pair, allow_download, progress, cancel);
    let mut listing = match listed {
        Ok(Listing::Ready(listing)) => listing,
        Ok(Listing::NeedsDownload { package, size }) => {
            let _ = tx.send(Event::PairNeedsDownload {
                cve: cve.clone(),
                pair: pair.clone(),
                package,
                size,
            });
            return Ok(());
        }
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Err(e) => {
            let _ = tx.send(Event::PairListFailed {
                cve: cve.clone(),
                pair: pair.clone(),
                error: e.to_string(),
            });
            return Err(e);
        }
    };
    let _ = tx.send(Event::PairListed {
        cve: cve.clone(),
        pair: pair.clone(),
        listing: Box::new(listing.clone()),
    });
    if listing.comparison == Comparison::Pending {
        usecases::compare_pair(services, report, pair, &mut listing, progress, cancel)?;
        let _ = tx.send(Event::PairListed {
            cve: cve.clone(),
            pair: pair.clone(),
            listing: Box::new(listing),
        });
    }
    Ok(())
}
