//! Use cases, independent of any UI. The TUI (or the headless runner) sends
//! [`Command`]s to a [`Worker`] and renders the [`Event`]s that come back.

mod events;
pub mod hints;
mod policy;
mod progress;
mod services;
mod usecases;
mod worker;

pub use events::{Command, Comparison, CveReport, Event, JobId, PairListing};
pub use policy::{REMOTE_READABLE_BUILD, build_major, rank_pairs};
pub use progress::ChannelProgress;
pub use services::Services;
pub use usecases::{
    Listing, acquire_case, acquire_case_with_fallback, compare_pair, list_pair, load_cve,
    recent_cves,
};
pub use worker::Worker;
