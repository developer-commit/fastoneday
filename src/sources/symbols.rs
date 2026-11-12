//! Microsoft Symbol Server: PE images keyed by `TimeDateStamp` + `SizeOfImage`
//! and PDBs keyed by CodeView GUID + age.

use std::{sync::Arc, thread};

use crate::{
    error::{Error, Result},
    formats::{cab::Cabinet, delta::PeIdentity, pe::CodeView},
    io::{Cancel, MemorySource},
    net::Http,
};

const BASE: &str = "https://msdl.microsoft.com/download/symbols";
const PARALLEL_PROBES: usize = 8;
const MAX_CANDIDATES: usize = 72;
const MAX_IMAGE: u64 = 512 << 20;

pub struct SymbolServer {
    http: Arc<Http>,
}

impl SymbolServer {
    pub fn new(http: Arc<Http>) -> Self {
        Self { http }
    }

    pub fn image_url(name: &str, time_date_stamp: u32, size_of_image: u32) -> String {
        format!("{BASE}/{name}/{time_date_stamp:08X}{size_of_image:x}/{name}")
    }

    /// Finds the URL of the image whose identity came from an update delta.
    /// `SizeOfImage` is not in the delta, so plausible values are probed.
    pub fn locate_image(
        &self,
        name: &str,
        identity: &PeIdentity,
        file_size: u64,
        cancel: &Cancel,
    ) -> Result<Option<String>> {
        let candidates = identity.size_of_image_candidates(file_size, MAX_CANDIDATES);
        for batch in candidates.chunks(PARALLEL_PROBES) {
            cancel.check()?;
            let found = thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|&size| {
                        let url = Self::image_url(name, identity.time_date_stamp, size);
                        scope.spawn(move || {
                            let status = self
                                .http
                                .head_status(&url, "probing the Microsoft Symbol Server");
                            (url, status)
                        })
                    })
                    .collect();
                let mut found = None;
                let mut failure = None;
                for handle in handles {
                    match handle.join().expect("probe thread") {
                        (url, Ok(200)) if found.is_none() => found = Some(url),
                        (_, Err(e)) => failure = Some(e),
                        _ => {}
                    }
                }
                match (found, failure) {
                    (Some(url), _) => Ok(Some(url)),
                    (None, Some(e)) => Err(e),
                    (None, None) => Ok(None),
                }
            })?;
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub fn download(&self, url: &str) -> Result<Vec<u8>> {
        self.http.get_bytes(
            url,
            MAX_IMAGE,
            "downloading from the Microsoft Symbol Server",
        )
    }

    /// The PDB for an image, if published. Handles the compressed `.pd_` form.
    pub fn pdb(&self, codeview: &CodeView) -> Result<Option<Vec<u8>>> {
        let key = codeview.symbol_key();
        let name = &codeview.pdb_name;
        let plain = format!("{BASE}/{name}/{key}/{name}");
        match self.http.get_bytes(&plain, MAX_IMAGE, "downloading a PDB") {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(Error::Http { status: 404, .. }) => {}
            Err(e) => return Err(e),
        }
        let mut compressed_name = name.clone();
        compressed_name.pop();
        compressed_name.push('_');
        let url = format!("{BASE}/{name}/{key}/{compressed_name}");
        let packed = match self.http.get_bytes(&url, MAX_IMAGE, "downloading a PDB") {
            Ok(bytes) => bytes,
            Err(Error::Http { status: 404, .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let cab = Cabinet::open(Arc::new(MemorySource::new(packed)))?;
        let file = cab
            .files()
            .first()
            .cloned()
            .ok_or_else(|| Error::format("compressed PDB", "empty cabinet"))?;
        let mut data = cab.extract(&[&file], &Cancel::new())?;
        Ok(Some(data.remove(0)))
    }
}
