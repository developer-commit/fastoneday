use std::path::{Path, PathBuf};

use super::write_atomic;
use crate::{
    domain::{BinaryName, CaseResult, CveId, PatchPair, Side},
    error::Result,
};

/// Output layout:
///
/// ```text
/// cases/<CVE>/<binary>/<product-slug>/
///   before/<binary>   before/<name>.pdb
///   after/<binary>    after/<name>.pdb
///   manifest.json     README.txt
/// ```
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn case_dir(&self, cve: &CveId, binary: &BinaryName, pair: &PatchPair) -> PathBuf {
        self.root
            .join(cve.as_str())
            .join(binary.as_str())
            .join(pair.slug())
    }

    pub fn write_side(&self, dir: &Path, side: Side, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = dir.join(side.label()).join(name);
        write_atomic(&path, bytes)?;
        Ok(path)
    }

    pub fn write_manifest(&self, result: &CaseResult) -> Result<PathBuf> {
        let path = result.directory.join("manifest.json");
        write_atomic(
            &path,
            &serde_json::to_vec_pretty(result).expect("case serializes"),
        )?;
        let readme = format!(
            "{cve} — {binary} ({product})\n\n\
             before: {bv} from {bu}\n  {bp}\n  sha256 {bh}\n  {bhow}\n\n\
             after:  {av} from {au}\n  {ap}\n  sha256 {ah}\n  {ahow}\n\n\
             Diff the two folders with BinDiff, Diaphora or Ghidra Version Tracking;\n\
             PDBs (when published) sit next to each binary.\n",
            cve = result.cve,
            binary = result.binary,
            product = result.pair.product,
            bv = result.before.version.as_deref().unwrap_or("?"),
            bu = result.before.update,
            bp = result.before.path.display(),
            bh = result.before.sha256.hex,
            bhow = result.before.how.summary(),
            av = result.after.version.as_deref().unwrap_or("?"),
            au = result.after.update,
            ap = result.after.path.display(),
            ah = result.after.sha256.hex,
            ahow = result.after.how.summary(),
        );
        write_atomic(&result.directory.join("README.txt"), readme.as_bytes())?;
        Ok(path)
    }
}
