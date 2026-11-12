//! Use cases, independent of any UI. The TUI (or the headless runner) sends
//! [`Command`]s to a [`Worker`] and renders the [`Event`]s that come back.

mod events;
mod policy;
mod progress;
mod services;
mod usecases;
mod worker;

pub use events::{Command, CveReport, Event, JobId};
pub use policy::{REMOTE_READABLE_BUILD, build_major, rank_pairs};
pub use progress::ChannelProgress;
pub use services::Services;
pub use usecases::{
    acquire_case, acquire_case_with_fallback, load_cve, package_names, recent_cves,
};
pub use worker::Worker;
