//! The Office CDN: `pr/<channel>/Office/Data/<build>/` holds `s640.cab`
//! (stream index) and `stream.x64.x-none.dat` (the files). Builds stay
//! available for years, which makes any security build reproducible.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    domain::Arch,
    error::{Error, Result},
    formats::{
        c2r::{StreamFile, StreamIndex},
        cab::Cabinet,
    },
    io::{Cancel, MemorySource, Meter},
    net::Http,
};

const CDN: &str = "http://officecdn.microsoft.com/pr";

/// A Click-to-Run update channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Channel {
    Current,
    MonthlyEnterprise,
    SemiAnnual,
    Ltsc2024,
    Ltsc2021,
    Office2019,
}

impl Channel {
    pub const ALL: [Channel; 6] = [
        Self::Current,
        Self::MonthlyEnterprise,
        Self::SemiAnnual,
        Self::Ltsc2024,
        Self::Ltsc2021,
        Self::Office2019,
    ];

    pub fn guid(self) -> &'static str {
        match self {
            Self::Current => "492350f6-3a01-4f97-b9c0-c7c6ddf67d60",
            Self::MonthlyEnterprise => "55336b82-a18d-4dd6-b5f6-9e5095c314a6",
            Self::SemiAnnual => "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114",
            Self::Ltsc2024 => "7983bac0-e531-40cf-be00-fd24fe66619c",
            Self::Ltsc2021 => "5030841d-c919-4594-8d2d-84ae4f96e58e",
            Self::Office2019 => "f2e724c1-748f-4b47-8fb8-8e0d210e9208",
        }
    }

    /// Channel labels used in the security release notes (current name
    /// first, then historical names).
    pub fn release_labels(self) -> &'static [&'static str] {
        match self {
            Self::Current => &["Current Channel", "Monthly Channel"],
            Self::MonthlyEnterprise => &["Monthly Enterprise Channel"],
            Self::SemiAnnual => &["Semi-Annual Enterprise Channel", "Semi-Annual Channel"],
            Self::Ltsc2024 => &["Office LTSC 2024 Volume Licensed"],
            Self::Ltsc2021 => &["Office LTSC 2021 Volume Licensed"],
            Self::Office2019 => &["Office 2019 Volume Licensed"],
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::Current => "Current",
            Self::MonthlyEnterprise => "MonthlyEnterprise",
            Self::SemiAnnual => "SemiAnnual",
            Self::Ltsc2024 => "LTSC2024",
            Self::Ltsc2021 => "LTSC2021",
            Self::Office2019 => "Office2019",
        }
    }

    pub fn from_short(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.short().eq_ignore_ascii_case(value))
    }

    /// Channel serving an MSRC Click-to-Run product row.
    pub fn for_product(product: &str) -> Option<Self> {
        let p = product.to_ascii_lowercase();
        if p.contains("365 apps")
            || p.contains("current channel")
            || p.contains("office 2024") && !p.contains("ltsc")
            || p.contains("office 2021") && !p.contains("ltsc")
        {
            Some(Self::Current)
        } else if p.contains("ltsc 2024") {
            Some(Self::Ltsc2024)
        } else if p.contains("ltsc 2021") {
            Some(Self::Ltsc2021)
        } else if p.contains("office 2019") {
            Some(Self::Office2019)
        } else {
            None
        }
    }
}

/// Where a file lives in a build's stream.
#[derive(Debug, Clone)]
pub struct StreamLocation {
    pub dat_url: String,
    pub file: StreamFile,
}

pub struct OfficeCdn {
    http: Arc<Http>,
}

impl OfficeCdn {
    pub fn new(http: Arc<Http>) -> Self {
        Self { http }
    }

    fn build_base(channel: Channel, build: &str) -> String {
        format!("{CDN}/{}/Office/Data/{build}", channel.guid())
    }

    fn platform(arch: Arch) -> Result<&'static str> {
        match arch {
            Arch::X64 => Ok("64"),
            Arch::X86 => Ok("32"),
            Arch::Arm64 => Err(Error::Unsupported(
                "arm64 Click-to-Run streams are not supported yet".into(),
            )),
        }
    }

    /// The `stream.*.x-none.db` index of a build (language-neutral files).
    pub fn index(
        &self,
        channel: Channel,
        build: &str,
        arch: Arch,
        cancel: &Cancel,
    ) -> Result<(StreamIndex, String)> {
        let bits = Self::platform(arch)?;
        let base = Self::build_base(channel, build);
        let cab_url = format!("{base}/s{bits}0.cab");
        let cab_bytes = self
            .http
            .get_bytes(
                &cab_url,
                64 << 20,
                &format!("downloading the Office {build} stream index"),
            )
            .map_err(|e| match e {
                Error::Http { status: 404, .. } => Error::NotFound(format!(
                    "Office build {build} is not on the {} channel CDN",
                    channel.short()
                )),
                other => other,
            })?;
        let cab = Cabinet::open(Arc::new(MemorySource::new(cab_bytes)))?;
        let db_name = format!("stream.x{bits}.x-none.db");
        let entry = cab.find(&db_name).cloned().ok_or_else(|| {
            Error::format(
                "Office stream index",
                format!("{db_name} missing from s{bits}0.cab"),
            )
        })?;
        let db = cab.extract(&[&entry], cancel)?.remove(0);
        let index = StreamIndex::parse(&db)?;
        Ok((index, format!("{base}/stream.x{bits}.x-none.dat")))
    }

    /// Downloads the file's compressed chunks (one range per contiguous run)
    /// and inflates them, verifying every chunk and the whole-file SHA-256.
    pub fn fetch(&self, location: &StreamLocation, meter: &dyn Meter) -> Result<Vec<u8>> {
        let runs = location.file.dat_runs();
        meter.total(Some(runs.iter().map(|(_, len)| len).sum()));
        let mut fetched = Vec::with_capacity(runs.len());
        for (offset, len) in runs {
            let bytes = self.http.get_range(
                &location.dat_url,
                offset,
                len,
                "downloading from the Office CDN",
                meter,
            )?;
            fetched.push((offset, bytes));
        }
        location.file.assemble_runs(&fetched)
    }
}

#[cfg(test)]
mod tests {
    use super::Channel;

    #[test]
    fn maps_msrc_products_to_channels() {
        assert_eq!(
            Channel::for_product("Microsoft 365 Apps for Enterprise for 64-bit Systems"),
            Some(Channel::Current)
        );
        assert_eq!(
            Channel::for_product("Microsoft Office LTSC 2021 for 64-bit editions"),
            Some(Channel::Ltsc2021)
        );
        assert_eq!(
            Channel::for_product("Microsoft Office LTSC 2024 for 32-bit editions"),
            Some(Channel::Ltsc2024)
        );
        assert_eq!(
            Channel::for_product("Microsoft Office 2019 for 64-bit editions"),
            Some(Channel::Office2019)
        );
        assert_eq!(
            Channel::for_product("Microsoft Office 2016 (64-bit edition)"),
            None
        );
    }
}
