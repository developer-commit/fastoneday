//! Payload → exact binary.
//!
//! * full file / PA30-stored full file → as is
//! * null delta → expanded from nothing
//! * forward delta → (A) Microsoft Symbol Server, keyed by the PE identity in
//!   the delta, or (B) the delta applied to its baseline (the same component
//!   from the package's checkpoint update)
//!
//! Every result is checked against a hash taken from the package itself.

use super::progress::Progress;
use crate::{
    delta_engine,
    domain::{Digest, HashAlgorithm, Materialization},
    error::{Error, Result},
    formats::{
        component::PayloadKind,
        delta::{self, DeltaInfo},
    },
    io::Cancel,
    packages::{Locator, PayloadEntry, UpdatePackage},
    sources::symbols::SymbolServer,
};

/// An exact binary plus how we got it.
#[derive(Debug, Clone)]
pub struct Materialized {
    pub bytes: Vec<u8>,
    pub version: Option<String>,
    pub how: Materialization,
    pub verified_with: Option<Digest>,
    pub entry: PayloadEntry,
}

/// Supplies the baseline file for a forward delta, when one is reachable.
pub type BaseLookup<'a> = dyn Fn(&PayloadEntry) -> Result<Option<Materialized>> + 'a;

pub struct Materializer<'a> {
    pub symbols: &'a SymbolServer,
    pub progress: &'a dyn Progress,
    pub cancel: &'a Cancel,
}

impl Materializer<'_> {
    pub fn run(
        &self,
        package: &dyn UpdatePackage,
        entry: &PayloadEntry,
        bases: &BaseLookup<'_>,
    ) -> Result<Materialized> {
        let label = package.index().label.clone();
        let what = match &entry.version {
            Some(version) => format!("{version} {}", entry.kind.label()),
            None => entry.kind.label().to_owned(),
        };
        let step = self.progress.step(format!(
            "Reading {} ({what}) from {}",
            entry.file_name,
            short_label(&label)
        ));
        let stored = package.read(entry, step.as_ref(), self.cancel)?;
        let payload = match &entry.locator {
            Locator::Psf { pa30: true, .. } => delta_engine::apply(&[], &stored)?.bytes,
            _ => stored,
        };
        let payload_hash = entry
            .sha256
            .as_deref()
            .map(|h| Digest::new(HashAlgorithm::Sha256, h))
            .transpose()?;
        if let Some(expected) = &payload_hash {
            expected.verify(&format!("{} payload", entry.file_name), &payload)?;
        }
        step.finish(format!(
            "{} bytes{}",
            payload.len(),
            if payload_hash.is_some() {
                ", SHA-256 ok"
            } else {
                ""
            }
        ));

        match entry.kind {
            PayloadKind::Full => Ok(Materialized {
                bytes: payload,
                version: entry.version.clone(),
                how: Materialization::FullFile { package: label },
                verified_with: payload_hash,
                entry: entry.clone(),
            }),
            PayloadKind::Null => {
                let info = delta::inspect(&payload)?;
                let applied = delta_engine::apply(&[], &payload)?;
                check(&info, &applied.bytes, &entry.file_name)?;
                Ok(Materialized {
                    bytes: applied.bytes,
                    version: entry.version.clone(),
                    how: Materialization::NullDelta {
                        package: label,
                        engine: applied.engine.to_owned(),
                    },
                    verified_with: info.target_hash,
                    entry: entry.clone(),
                })
            }
            PayloadKind::Forward => self.forward(entry, &label, &payload, bases),
            PayloadKind::Reverse => Err(Error::Unsupported(
                "reverse deltas are not materialized".into(),
            )),
        }
    }

    fn forward(
        &self,
        entry: &PayloadEntry,
        label: &str,
        payload: &[u8],
        bases: &BaseLookup<'_>,
    ) -> Result<Materialized> {
        let info = delta::inspect(payload)?;
        let version = entry.version.clone();
        let mut symbol_note = String::from("no PE identity in the delta");

        if let Some(pe) = &info.pe {
            let step = self.progress.step(format!(
                "Symbol Server · {} {} (timestamp {:08X})",
                entry.file_name,
                version.as_deref().unwrap_or(""),
                pe.time_date_stamp
            ));
            match self
                .symbols
                .locate_image(&entry.file_name, pe, info.target_size, self.cancel)
            {
                Ok(Some(url)) => {
                    let bytes = self.symbols.download(&url)?;
                    match check(&info, &bytes, &entry.file_name) {
                        Ok(()) => {
                            step.finish(format!(
                                "found, {} bytes, hash matches the update",
                                bytes.len()
                            ));
                            return Ok(Materialized {
                                bytes,
                                version,
                                how: Materialization::SymbolServer {
                                    package: label.to_owned(),
                                    url,
                                },
                                verified_with: info.target_hash,
                                entry: entry.clone(),
                            });
                        }
                        Err(Error::Integrity { .. }) => {
                            // Same TimeDateStamp/SizeOfImage, different bytes: Microsoft
                            // re-released the file and the Symbol Server entry was replaced.
                            let served = crate::formats::pe::parse(&bytes)
                                .ok()
                                .and_then(|p| p.file_version)
                                .unwrap_or_else(|| "another build".into());
                            symbol_note = format!(
                                "the Symbol Server serves {served} under this identity (a re-release), not the exact file"
                            );
                            step.finish(symbol_note.clone());
                        }
                        Err(other) => return Err(other),
                    }
                }
                Ok(None) => {
                    symbol_note = "not published on the Symbol Server (yet)".into();
                    step.finish(symbol_note.clone());
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(e) => {
                    symbol_note = format!("Symbol Server unreachable: {e}");
                    step.finish(symbol_note.clone());
                }
            }
        }

        let step = self.progress.step(format!(
            "Reconstructing {} from its servicing baseline",
            entry.file_name
        ));
        let Some(base) = bases(entry)? else {
            return Err(Error::NotFound(format!(
                "{} {}: {symbol_note}; rebuilding it needs the release (RTM) baseline, which no update \
                 package contains. Rows on a servicing branch with a checkpoint update (24H2/25H2/26H2, \
                 Server 2025) can rebuild it.",
                entry.file_name,
                version.as_deref().unwrap_or("")
            )));
        };
        let applied = delta_engine::apply(&base.bytes, payload).map_err(|e| match e {
            Error::Integrity { what, .. } => Error::Integrity {
                what: format!(
                    "{} {} ({symbol_note}); rebuilding it from {} did not reproduce Microsoft's \
                     hash, so it was discarded [{what}]",
                    entry.file_name,
                    version.as_deref().unwrap_or(""),
                    base.version.as_deref().unwrap_or("the baseline")
                ),
                algorithm: "embedded hash",
                expected: info
                    .target_hash
                    .as_ref()
                    .map(|d| d.hex.clone())
                    .unwrap_or_default(),
                actual: "decoder output".into(),
            },
            other => other,
        })?;
        check(&info, &applied.bytes, &entry.file_name)?;
        step.finish(format!(
            "applied to {} with {} → {} bytes, hash matches the update",
            base.version.as_deref().unwrap_or("baseline"),
            applied.engine,
            applied.bytes.len()
        ));
        Ok(Materialized {
            bytes: applied.bytes,
            version,
            how: Materialization::DeltaApplied {
                package: label.to_owned(),
                base_version: base.version.clone().unwrap_or_default(),
                base_package: base.how.summary(),
                engine: applied.engine.to_owned(),
            },
            verified_with: info.target_hash,
            entry: entry.clone(),
        })
    }
}

/// Size and (when present) hash must match what the delta promises.
fn check(info: &DeltaInfo, bytes: &[u8], name: &str) -> Result<()> {
    if bytes.len() as u64 != info.target_size {
        return Err(Error::Integrity {
            what: name.to_owned(),
            algorithm: "size",
            expected: info.target_size.to_string(),
            actual: bytes.len().to_string(),
        });
    }
    if let Some(expected) = &info.target_hash {
        expected.verify(name, bytes)?;
    }
    Ok(())
}

fn short_label(label: &str) -> &str {
    label.split(" · ").next().unwrap_or(label)
}
