//! MSDelta engines: Microsoft's own implementation where it exists (the
//! `UpdateCompression.dll` / `msdelta.dll` that ship with Windows), and the
//! vendored portable decoder everywhere else.
//!
//! Callers still verify every output against the size and hash stored in
//! the update package, so the engine only affects *whether* a binary can be
//! rebuilt, never whether a wrong one is accepted.

mod portable;

#[cfg(windows)]
mod native;

use std::sync::OnceLock;

use crate::{
    error::{Error, Result},
    formats::delta::strip_prefix,
};

/// Overrides engine selection: `portable` forces the vendored decoder.
pub const ENGINE_ENV: &str = "FASTONEDAY_DELTA_ENGINE";

pub trait DeltaEngine: Send + Sync {
    /// Applies a PA19/PA30/PA31 delta (CRC prefix already removed) to
    /// `base` (empty for null deltas). Returns the output and the name of
    /// the implementation that produced it.
    fn apply(&self, base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, &'static str)>;

    fn describe(&self) -> &'static str;
}

/// The output of a delta application and who produced it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub bytes: Vec<u8>,
    pub engine: &'static str,
}

static ACTIVE: OnceLock<Box<dyn DeltaEngine>> = OnceLock::new();

/// The engine in use for this process.
pub fn active() -> &'static dyn DeltaEngine {
    ACTIVE.get_or_init(select).as_ref()
}

fn select() -> Box<dyn DeltaEngine> {
    let forced_portable =
        std::env::var(ENGINE_ENV).is_ok_and(|v| v.eq_ignore_ascii_case("portable"));
    #[cfg(windows)]
    if !forced_portable && let Some(native) = native::NativeEngine::load() {
        return Box::new(native);
    }
    let _ = forced_portable;
    Box::new(portable::PortableEngine)
}

/// Applies a delta as stored in a package (CRC prefix allowed). If the
/// official engine rejects it, the portable decoder gets one attempt; the
/// caller's hash check decides either way.
pub fn apply(base: &[u8], blob: &[u8]) -> Result<Applied> {
    let delta = strip_prefix(blob);
    let preferred = active();
    let first = match preferred.apply(base, delta) {
        Ok((bytes, engine)) => return Ok(Applied { bytes, engine }),
        Err(e) => e,
    };
    if preferred.describe() == portable::NAME {
        return Err(first);
    }
    match portable::PortableEngine.apply(base, delta) {
        Ok((bytes, engine)) => Ok(Applied { bytes, engine }),
        Err(second) => Err(both_failed(preferred.describe(), first, second)),
    }
}

/// One error naming both engines. It stays an integrity failure if either
/// engine got as far as producing output that failed the embedded hash.
fn both_failed(preferred: &str, first: Error, second: Error) -> Error {
    let summary = format!("{preferred}: {first}; {}: {second}", portable::NAME);
    match (first, second) {
        (
            Error::Integrity {
                expected, actual, ..
            },
            _,
        )
        | (
            _,
            Error::Integrity {
                expected, actual, ..
            },
        ) => Error::Integrity {
            what: summary,
            algorithm: "embedded hash",
            expected,
            actual,
        },
        _ => Error::format("delta", summary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Digest;

    #[test]
    fn a_double_failure_names_both_engines_and_stays_an_integrity_error() {
        let mismatch = || Error::Integrity {
            what: "delta output".into(),
            algorithm: "embedded hash",
            expected: "aa".into(),
            actual: "bb".into(),
        };
        let refused = || Error::format("delta", "ApplyDeltaB rejected the delta");
        let err = both_failed("Microsoft msdelta.dll", refused(), mismatch());
        assert!(matches!(err, Error::Integrity { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("Microsoft msdelta.dll") && text.contains(portable::NAME),
            "{text}"
        );
        assert!(matches!(
            both_failed("x", refused(), refused()),
            Error::Format { .. }
        ));
    }

    #[test]
    fn null_delta_round_trip() {
        let target = b"hello world, this is a raw payload".to_vec();
        let delta = msdelta::pa30::CreateOptions::new()
            .hash_algorithm(msdelta::pa30::HASH_ALG_SHA256)
            .execute(&[], &target)
            .unwrap();
        let info = crate::formats::delta::inspect(&delta).unwrap();
        assert_eq!(info.target_hash.unwrap(), Digest::sha256(&target));
        let applied = apply(&[], &delta).unwrap();
        assert_eq!(applied.bytes, target);
        assert!(!applied.engine.is_empty());
    }

    #[test]
    fn forward_delta_round_trip_and_wrong_base_is_rejected() {
        let base = b"the quick brown fox jumps over the lazy dog".repeat(50);
        let mut target = base.clone();
        target[100..110].copy_from_slice(b"0123456789");
        let delta = msdelta::pa30::CreateOptions::new()
            .hash_algorithm(msdelta::pa30::HASH_ALG_SHA256)
            .execute(&base, &target)
            .unwrap();
        assert_eq!(apply(&base, &delta).unwrap().bytes, target);
        let mut wrong = base.clone();
        wrong[0] ^= 0xff;
        assert!(apply(&wrong, &delta).is_err());
    }
}
