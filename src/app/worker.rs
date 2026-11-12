//! Runs commands on background threads so the UI never blocks.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, mpsc::Sender},
    thread,
};

use super::{
    events::{Command, Event, JobId},
    progress::ChannelProgress,
    services::Services,
    usecases,
};
use crate::{acquire::Silent, error::Error, io::Cancel};

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
                    let event = match usecases::package_names(
                        &services, &report, &pair, &Silent, &cancel,
                    ) {
                        Ok(Some((names, candidates))) => Event::PackageNames {
                            pair,
                            names,
                            candidates,
                        },
                        Ok(None) => return,
                        Err(Error::Cancelled) => return,
                        Err(e) => Event::PackageNamesFailed {
                            pair,
                            error: e.to_string(),
                        },
                    };
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
                let cancel = Cancel::new();
                {
                    let mut jobs = self.jobs.lock().expect("jobs");
                    for other in jobs.values() {
                        other.cancel();
                    }
                    jobs.insert(job, cancel.clone());
                }
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
}
