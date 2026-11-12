use std::{fs::File, path::Path};

use super::{ReadAt, check_bounds};
use crate::error::{Error, Result};

/// A local file read with positional I/O (no shared cursor, so it is `Sync`).
pub struct FileSource {
    file: File,
    size: u64,
    label: String,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| Error::io(format!("open {}", path.display()), e))?;
        let size = file
            .metadata()
            .map_err(|e| Error::io(format!("stat {}", path.display()), e))?
            .len();
        Ok(Self {
            file,
            size,
            label: path.display().to_string(),
        })
    }
}

impl ReadAt for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(&self.label, self.size, offset, buf.len())?;
        positional_read(&self.file, offset, buf)
            .map_err(|e| Error::io(format!("read {}", self.label), e))
    }
}

#[cfg(unix)]
fn positional_read(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn positional_read(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of file",
                ));
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
