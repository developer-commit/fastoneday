//! Plain data shared by every layer. No I/O happens here.

mod artifact;
mod binary;
mod cve;
mod digest;
mod product;

pub use artifact::{Acquired, CaseResult, Materialization, Side};
pub use binary::{BinaryName, Candidate, Change, Evidence, PE_EXTENSIONS, PairFiles};
pub use cve::{CveDetail, CveId, CveSummary};
pub use digest::{Digest, HashAlgorithm, to_hex};
pub use product::{Arch, Family, PatchPair, UpdateRef, slugify};
