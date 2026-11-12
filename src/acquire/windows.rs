//! Windows: KB → Catalog package (+ checkpoint prerequisites) → payload →
//! exact binary.

use super::{
    Engine, Hint,
    materialize::{Materialized, Materializer},
    progress::Progress,
};
use crate::{
    domain::{BinaryName, PatchPair},
    error::{Error, Result},
    io::Cancel,
    packages::{PayloadEntry, SharedPackage},
};

pub fn acquire(
    engine: &Engine,
    pair: &PatchPair,
    kb: &str,
    binary: &BinaryName,
    hint: &Hint,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Materialized> {
    let prefer_key = hint.component_key();
    let prefer_component = prefer_key.as_deref();
    let catalog = engine
        .loader
        .catalog_package(kb, &pair.product, pair.arch, progress)?;
    let primary = engine
        .loader
        .windows(kb, catalog.primary(), progress, cancel)?;

    // The KB's own package first, then its prerequisites (the checkpoint
    // update on 24H2+), which hold files unchanged since the checkpoint.
    let mut chosen: Option<(SharedPackage, PayloadEntry, bool)> =
        pick(&primary, binary, pair, prefer_component).map(|e| (primary.clone(), e, true));
    if chosen.is_none() {
        for file in catalog.prerequisites() {
            let package = engine.loader.windows(kb, file, progress, cancel)?;
            if let Some(entry) = pick(&package, binary, pair, prefer_component) {
                progress.note(format!(
                    "{binary} is unchanged since the checkpoint; using {}",
                    file.name
                ));
                chosen = Some((package, entry, false));
                break;
            }
        }
    }
    let prefer_server = pair.product.to_ascii_lowercase().contains("server");
    if chosen.is_none()
        && let Some(component) = &hint.component
    {
        // Same component as the other side but absent from this update and its
        // checkpoint: the file is still the release build.
        if let Some(rtm) = engine.baseline.file(
            component,
            binary.as_str(),
            pair.arch,
            prefer_server,
            progress,
            cancel,
        )? {
            progress.note(format!(
                "{binary} is unchanged since the release build in {kb}; using the release image"
            ));
            return Ok(rtm);
        }
    }
    let Some((package, entry, from_primary)) = chosen else {
        let suggestions = similar_names(&primary, binary);
        return Err(Error::NotFound(format!(
            "{binary} is not serviced by {kb}{}{}",
            if catalog.prerequisites().is_empty() {
                ""
            } else {
                " or its checkpoint"
            },
            if suggestions.is_empty() {
                " (it may be unchanged since the release build)".to_owned()
            } else {
                format!("; similar names in the package: {}", suggestions.join(", "))
            }
        )));
    };

    let materializer = Materializer {
        symbols: &engine.symbols,
        progress,
        cancel,
    };
    // Baseline of a forward delta: the checkpoint's copy when the KB is a
    // post-checkpoint update, otherwise the release (RTM) image's copy.
    let bases = |entry: &PayloadEntry| -> Result<Option<Materialized>> {
        let Some(key) = entry.component_key() else {
            return Ok(None);
        };
        if from_primary {
            for file in catalog.prerequisites() {
                let checkpoint = engine.loader.windows(kb, file, progress, cancel)?;
                if let Some(base) = checkpoint
                    .index()
                    .find_component(&key, &entry.file_name)
                    .cloned()
                {
                    let release = |e: &PayloadEntry| {
                        release_base(engine, e, pair, prefer_server, progress, cancel)
                    };
                    return materializer
                        .run(checkpoint.as_ref(), &base, &release)
                        .map(Some);
                }
            }
        }
        release_base(engine, entry, pair, prefer_server, progress, cancel)
    };
    materializer.run(package.as_ref(), &entry, &bases)
}

fn release_base(
    engine: &Engine,
    entry: &PayloadEntry,
    pair: &PatchPair,
    prefer_server: bool,
    progress: &dyn Progress,
    cancel: &Cancel,
) -> Result<Option<Materialized>> {
    let Some(component) = &entry.component else {
        return Ok(None);
    };
    match engine.baseline.file(
        component,
        &entry.file_name,
        pair.arch,
        prefer_server,
        progress,
        cancel,
    ) {
        Ok(found) => Ok(found),
        Err(Error::Cancelled) => Err(Error::Cancelled),
        Err(e) => {
            progress.note(format!("release image unavailable: {e}"));
            Ok(None)
        }
    }
}

/// Entries the after side named, the same component on the before side.
fn pick(
    package: &SharedPackage,
    binary: &BinaryName,
    pair: &PatchPair,
    prefer_component: Option<&str>,
) -> Option<PayloadEntry> {
    let hits = package.index().find(binary, pair.arch);
    if let Some(key) = prefer_component
        && let Some(hit) = hits
            .iter()
            .find(|e| e.component_key().as_deref() == Some(key))
    {
        return Some((*hit).clone());
    }
    hits.into_iter()
        .find(|e| e.is_native(pair.arch))
        .or_else(|| package.index().find(binary, pair.arch).into_iter().next())
        .cloned()
}

fn similar_names(package: &SharedPackage, binary: &BinaryName) -> Vec<String> {
    let stem = binary.as_str().split('.').next().unwrap_or_default();
    package
        .index()
        .binary_names()
        .into_iter()
        .filter(|n| stem.len() >= 3 && n.contains(stem))
        .take(6)
        .collect()
}
