//! The vendored pure-Rust decoder (`third_party/msdelta`).

use super::DeltaEngine;
use crate::error::{Error, Result};

pub struct PortableEngine;

pub const NAME: &str = "msdelta (portable Rust, vendored)";

impl DeltaEngine for PortableEngine {
    fn apply(&self, base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, &'static str)> {
        msdelta::pa30::apply(base, delta)
            .map(|bytes| (bytes, NAME))
            .map_err(|e| match e {
                msdelta::Error::HashMismatch { expected, got } => Error::Integrity {
                    what: "delta output".into(),
                    algorithm: "embedded hash",
                    expected,
                    actual: got,
                },
                msdelta::Error::Unsupported(what) => Error::Unsupported(format!(
                    "the portable MSDelta decoder does not support this delta yet ({what})"
                )),
                other => Error::format("delta", other.to_string()),
            })
    }

    fn describe(&self) -> &'static str {
        NAME
    }
}
