//! Office: MSI updates through the Catalog, Click-to-Run builds through the
//! Office CDN. Both ship complete files.

use super::{
    Engine,
    materialize::{Materialized, Materializer},
    progress::Progress,
};
use crate::{
    domain::{BinaryName, PatchPair},
    error::{Error, Result},
    io::Cancel,
    packages::{C2rPackage, PayloadEntry, SharedPackage},
    sources::office::Channel,
};

pub fn acquire_msi(
    engine: &Engine,
    pair: &PatchPair,
    kb: &str,
    binary: &BinaryName,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Materialized> {
    let catalog = engine
        .loader
        .catalog_package(kb, &pair.product, pair.arch, progress)?;
    let package = engine
        .loader
        .office_msi(kb, catalog.primary(), progress, cancel)?;
    let entry = pick(&package, binary, pair, None)?;
    run(engine, &package, &entry, progress, cancel)
}

pub fn acquire_c2r(
    engine: &Engine,
    pair: &PatchPair,
    (channel, build): (&str, &str),
    binary: &BinaryName,
    preferred_path: Option<&str>,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Materialized> {
    let channel = Channel::from_short(channel)
        .ok_or_else(|| Error::Input(format!("unknown Click-to-Run channel `{channel}`")))?;
    let package = engine
        .loader
        .c2r(channel, build, pair.arch, progress, cancel)?;
    let entry = pick(&package, binary, pair, preferred_path)?;
    run(engine, &package, &entry, progress, cancel)
}

fn pick(
    package: &SharedPackage,
    binary: &BinaryName,
    pair: &PatchPair,
    preferred_path: Option<&str>,
) -> Result<PayloadEntry> {
    let mut hits = package.index().find(binary, pair.arch);
    hits.sort_by_key(|e| C2rPackage::path_rank(&e.path, pair.arch));
    if let Some(path) = preferred_path
        && let Some(hit) = hits.iter().find(|e| e.path.eq_ignore_ascii_case(path))
    {
        return Ok((*hit).clone());
    }
    hits.first().map(|e| (*e).clone()).ok_or_else(|| {
        let stem = binary
            .as_str()
            .split('.')
            .next()
            .unwrap_or_default()
            .to_owned();
        let similar: Vec<String> = package
            .index()
            .binary_names()
            .into_iter()
            .filter(|n| stem.len() >= 3 && n.contains(&stem))
            .take(6)
            .collect();
        Error::NotFound(format!(
            "{binary} is not in {}{}",
            package.index().label,
            if similar.is_empty() {
                String::new()
            } else {
                format!("; similar: {}", similar.join(", "))
            }
        ))
    })
}

fn run(
    engine: &Engine,
    package: &SharedPackage,
    entry: &PayloadEntry,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Materialized> {
    let materializer = Materializer {
        symbols: &engine.symbols,
        progress,
        cancel,
    };
    let none = |_: &PayloadEntry| Ok(None);
    materializer.run(package.as_ref(), entry, &none)
}
