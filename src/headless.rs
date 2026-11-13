//! Non-interactive runner (`fastoneday fetch …`) for scripts and CI. Uses the
//! same use cases as the TUI and prints progress to stderr.

use std::{
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::{
    acquire::{Progress, Step},
    app::{
        Comparison, CveReport, Listing, PairListing, Services, acquire_case,
        acquire_case_with_fallback, compare_pair, list_pair, load_cve,
    },
    domain::{BinaryName, Change, CveId, Evidence, PatchPair},
    error::{Error, Result},
    io::{Cancel, Meter},
};

pub struct FetchArgs {
    pub cve: String,
    pub binary: Option<String>,
    /// 1-based row in the product list; `None` = recommended.
    pub product: Option<usize>,
    pub list_only: bool,
}

pub fn run(services: Arc<Services>, args: FetchArgs) -> Result<()> {
    let cve = CveId::parse(&args.cve)?;
    eprintln!("Looking up {cve} …");
    let report = load_cve(&services, &cve)?;
    let detail = &report.detail;
    println!("{} — {}", detail.summary.id, detail.summary.title);
    println!(
        "  {} · {} · {}{}",
        detail.summary.released,
        detail.summary.severity,
        detail.summary.impact,
        if detail.summary.exploited {
            " · EXPLOITED"
        } else {
            ""
        }
    );
    println!("patch pairs (update replaced → update with the fix):");
    for (i, pair) in detail.patches.iter().enumerate() {
        println!(
            " {}{:<5} {:<36} {} → {}  {}",
            if i == 0 { "★" } else { " " },
            format!("[{}]", i + 1),
            pair.label(),
            pair.before,
            pair.after,
            pair.fixed_build.as_deref().unwrap_or(&pair.kind)
        );
    }
    if detail.patches.is_empty() {
        println!("  (none can be fetched)");
    }
    if !detail.unsupported.is_empty() {
        println!("not fetchable:");
        for skipped in &detail.unsupported {
            println!("  · {skipped}");
        }
    }
    if detail.patches.is_empty() {
        if args.list_only {
            return Ok(());
        }
        return Err(Error::Unsupported(format!(
            "none of the products affected by {cve} can be fetched (reasons above)"
        )));
    }
    let index = args.product.unwrap_or(1);
    let pair = detail
        .patches
        .get(index.wrapping_sub(1))
        .cloned()
        .ok_or_else(|| {
            Error::Input(format!(
                "patch pair [{index}] does not exist; pick 1 to {}",
                detail.patches.len()
            ))
        })?;
    let progress = TextProgress::default();
    let cancel = Cancel::new();

    // The binary comes from this pair's fixing update: list its files
    // (downloading the package only when fetching needs it anyway).
    println!(
        "binaries of [{index}] {} — files of {}:",
        pair.label(),
        pair.after
    );
    let listed = list_pair(
        &services,
        &report,
        &pair,
        !args.list_only,
        &progress,
        &cancel,
    );
    let listing = match listed {
        Ok(Listing::Ready(mut listing)) => {
            compare_pair(&services, &report, &pair, &mut listing, &progress, &cancel)?;
            print_listing(&pair, &listing);
            Some(listing)
        }
        Ok(Listing::NeedsDownload { package, size }) => {
            let size = size
                .map(|s| format!(", {:.0} MB", s as f64 / 1048576.0))
                .unwrap_or_default();
            println!(
                "  listed only inside its package ({package}{size}); run without --list to download it (cached) and pick from it"
            );
            print_hints(&report);
            None
        }
        Err(e) if args.binary.is_some() && !matches!(e, Error::Cancelled) => {
            println!("  file list unavailable: {e}");
            None
        }
        Err(e) => return Err(e),
    };
    if args.list_only {
        return Ok(());
    }
    let binary = match args.binary {
        Some(name) => BinaryName::parse(&name)?,
        None => listing
            .as_ref()
            .and_then(|l| l.pick())
            .map(|c| c.name.clone())
            .ok_or_else(|| Error::Input(no_pick(&pair, listing.as_ref())))?,
    };
    eprintln!("Fetching {binary} for {} …", pair.short_product());
    let result = if args.product.is_some() {
        acquire_case(&services, &report, &pair, &binary, &progress, &cancel)?
    } else {
        acquire_case_with_fallback(&services, &report, &pair, &binary, &progress, &cancel)?
    };
    println!("\ncase: {}", result.directory.display());
    for side in [&result.before, &result.after] {
        println!(
            "  {:<6} {:<18} {:<10} sha256 {}  ({})",
            side.side.label(),
            side.version.as_deref().unwrap_or("?"),
            side.update.label(),
            side.sha256.hex,
            side.how.summary()
        );
    }
    Ok(())
}

fn print_listing(pair: &PatchPair, listing: &PairListing) {
    let compared = match &listing.comparison {
        Comparison::Done => format!(
            " · {} changed since {}",
            listing.files.changed_count().unwrap_or(0),
            pair.before
        ),
        Comparison::Unavailable(why) => format!(" · not compared with {} ({why})", pair.before),
        Comparison::Pending | Comparison::NotApplicable => String::new(),
    };
    println!("  {} files{compared}", listing.files.names.len());
    let pick = listing.pick().map(|c| c.name.clone());
    for c in listing.candidates.iter().take(8) {
        let mut why: Vec<String> = Vec::new();
        if let Some(Change::Changed { before, after }) = listing.files.change(c.name.as_str()) {
            let before = before.as_deref().unwrap_or("baseline");
            why.push(match after {
                Some(after) => format!("changed {before} → {after}"),
                None => "changed".into(),
            });
        }
        why.extend(
            c.evidence
                .iter()
                .filter(|e| **e != Evidence::Changed)
                .map(|e| e.label()),
        );
        println!(
            "  {} {:<24} {:>3}  {}",
            if pick.as_ref() == Some(&c.name) {
                "★"
            } else {
                " "
            },
            c.name.as_str(),
            c.score,
            why.join(" · ")
        );
    }
    if listing.candidates.is_empty() {
        println!("  (no file of {} matches Microsoft's text)", pair.after);
    }
    if !listing.missing.is_empty() {
        let names: Vec<&str> = listing.missing.iter().map(|n| n.as_str()).collect();
        println!(
            "  not in {}: {} (named by Microsoft's text)",
            pair.after,
            names.join(", ")
        );
    }
}

fn print_hints(report: &CveReport) {
    let names: Vec<&str> = report
        .hints
        .iter()
        .take(6)
        .map(|c| c.name.as_str())
        .collect();
    if !names.is_empty() {
        println!(
            "  Microsoft's text points to: {} (not checked against the update yet)",
            names.join(", ")
        );
    }
}

fn no_pick(pair: &PatchPair, listing: Option<&PairListing>) -> String {
    match listing {
        Some(l) if !l.candidates.is_empty() => format!(
            "Microsoft's candidates are unchanged between {} and {}; pass --binary NAME to fetch one anyway",
            pair.before, pair.after
        ),
        Some(_) => format!(
            "no file of {} matches Microsoft's text; pass --binary NAME (--list shows the candidates)",
            pair.after
        ),
        None => "the update's files are unknown; pass --binary NAME".into(),
    }
}

#[derive(Default)]
struct TextProgress {
    started: Mutex<Option<Instant>>,
}

impl Progress for TextProgress {
    fn step(&self, label: String) -> Arc<dyn Step> {
        self.started
            .lock()
            .expect("clock")
            .get_or_insert_with(Instant::now);
        eprintln!("  → {label}");
        Arc::new(TextStep {
            bytes: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    fn note(&self, message: String) {
        eprintln!("  • {message}");
    }
}

struct TextStep {
    bytes: AtomicU64,
    started: Instant,
}

impl Meter for TextStep {
    fn total(&self, _: Option<u64>) {}
    fn advance(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Step for TextStep {
    fn finish(&self, detail: String) {
        let bytes = self.bytes.load(Ordering::Relaxed);
        let transfer = if bytes > 0 {
            format!(" [{:.1} MB]", bytes as f64 / 1048576.0)
        } else {
            String::new()
        };
        eprintln!(
            "    ✔ {detail}{transfer} ({:.1}s)",
            self.started.elapsed().as_secs_f64()
        );
        let _ = std::io::stderr().flush();
    }

    fn transferred(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}
