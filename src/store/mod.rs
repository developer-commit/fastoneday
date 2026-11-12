//! Everything we persist: the download/index cache, the CVE history used for
//! completion, and the per-case output layout.

mod cache;
mod history;
mod workspace;

pub use cache::{Cache, sanitize};
pub use history::{History, HistoryEntry};
pub use workspace::Workspace;

use std::{fs, path::Path};

use crate::error::{Error, Result};

/// Writes `bytes` to `path` atomically (temporary file + rename).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::io(format!("create {}", parent.display()), e))?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        std::process::id()
    ));
    fs::write(&tmp, bytes).map_err(|e| Error::io(format!("write {}", tmp.display()), e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(format!("publish {}", path.display()), e))
}

/// Streams a file through a hash.
pub fn hash_file(
    path: &Path,
    algorithm: crate::domain::HashAlgorithm,
) -> Result<crate::domain::Digest> {
    use std::io::Read;

    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256};

    let mut file =
        fs::File::open(path).map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let mut buf = vec![0u8; 1 << 20];
    macro_rules! run {
        ($hasher:expr) => {{
            let mut h = $hasher;
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| Error::io(format!("read {}", path.display()), e))?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            h.finalize().to_vec()
        }};
    }
    let raw = match algorithm {
        crate::domain::HashAlgorithm::Md5 => run!(Md5::new()),
        crate::domain::HashAlgorithm::Sha1 => run!(Sha1::new()),
        crate::domain::HashAlgorithm::Sha256 => run!(Sha256::new()),
    };
    Ok(crate::domain::Digest::from_bytes(algorithm, &raw))
}
