mod catalog_adapter;
mod cve_adapter;
mod driver_adapter;
mod uup_adapter;
mod winbindex_adapter;

use std::{
    env,
    fmt::Write as _,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use sha2::digest::Digest;

pub use catalog_adapter::CatalogAdapter;
pub use cve_adapter::CveAdapter;
pub use driver_adapter::DriverAdapter;
pub use uup_adapter::UupAdapter;
pub use winbindex_adapter::WinbindexAdapter;

fn default_cache_directory() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(Path::to_owned))
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("fastoneday-cache")
}

fn digest_file<D>(path: &Path) -> io::Result<String>
where
    D: Digest + Default,
{
    let mut file = File::open(path)?;
    let mut digest = D::new();
    let mut buffer = [0_u8; 1024 * 1024];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }

    Ok(hex(digest.finalize().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn format_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn report_download_progress(label: &str, received: u64, total: u64, next_percent: &mut u64) {
    let percent = received
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(100)
        .min(100);
    if percent < *next_percent {
        return;
    }

    eprintln!(
        "{label}: {} / {} ({percent}%)",
        format_bytes(received.min(total)),
        format_bytes(total)
    );
    *next_percent = (percent / 10 + 1).saturating_mul(10);
}

#[cfg(test)]
mod tests {
    use super::{default_cache_directory, format_bytes};
    use std::env;

    #[test]
    fn formats_download_sizes() {
        assert_eq!(format_bytes(42), "42 B");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn default_cache_is_next_to_the_current_executable() {
        let executable = env::current_exe().unwrap();
        let cache = default_cache_directory();

        assert_eq!(cache.parent(), executable.parent());
        assert_eq!(cache.file_name().unwrap(), "fastoneday-cache");
    }
}
