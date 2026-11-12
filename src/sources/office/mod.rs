//! Office Click-to-Run: security release notes (CVE → builds per channel)
//! and the Office CDN (build → exact files).

mod cdn;
mod releases;

pub use cdn::{Channel, OfficeCdn, StreamLocation};
pub use releases::{RELEASE_NOTES_URL, Release, ReleaseBuild, parse_release_notes};
