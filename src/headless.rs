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
    app::{Services, acquire_case, acquire_case_with_fallback, load_cve, package_names},
    domain::{BinaryName, CveId},
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
    println!("products:");
    for (i, pair) in detail.patches.iter().enumerate() {
        println!(
            "  [{}] {:<44} {} → {}  ({})",
            i + 1,
            pair.short_product(),
            pair.before,
            pair.after,
            pair.kind
        );
    }
    for skipped in &detail.unsupported {
        println!("  (skipped) {skipped}");
    }
    println!("binary candidates:");
    for c in report.candidates.iter().take(8) {
        let why: Vec<String> = c.evidence.iter().map(|e| e.label()).collect();
        println!("  {:<24} {:>3}  {}", c.name, c.score, why.join(", "));
    }
    if args.list_only {
        return Ok(());
    }

    let index = args.product.unwrap_or(1);
    let pair = detail
        .patches
        .get(index.wrapping_sub(1))
        .cloned()
        .ok_or_else(|| Error::Input(format!("product [{index}] does not exist")))?;
    let progress = TextProgress::default();
    let cancel = Cancel::new();
    let binary = match args.binary {
        Some(name) => BinaryName::parse(&name)?,
        None => {
            let refined = package_names(&services, &report, &pair, &progress, &cancel)?
                .map(|(_, candidates)| candidates)
                .unwrap_or_else(|| report.candidates.clone());
            refined.first().map(|c| c.name.clone()).ok_or_else(|| {
                Error::Input("no binary could be inferred; pass --binary NAME".into())
            })?
        }
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
