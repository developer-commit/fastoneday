//! Release (RTM) images. The UUP index at `api.uupdump.net` is used only to
//! *locate* the install image of a build on Microsoft's CDN; nothing it says
//! is trusted: WIM blobs carry SHA-1s and every rebuilt binary must match the
//! hash stored in the Microsoft update package.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    domain::Arch,
    error::{Error, Result},
    net::{Http, encode_query},
};

const LIST: &str = "https://api.uupdump.net/listid.php";
const GET: &str = "https://api.uupdump.net/get.php";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseImage {
    /// e.g. `20348.1`
    pub build: String,
    pub title: String,
    /// e.g. `ServerStandard_en-us.esd`
    pub name: String,
    pub url: String,
    pub size: u64,
    pub sha1: String,
}

pub struct UupClient {
    http: Arc<Http>,
}

impl UupClient {
    pub fn new(http: Arc<Http>) -> Self {
        Self { http }
    }

    /// The en-US install image of build `<major>.1` for `arch`, trying
    /// matching releases until one resolves (server first when asked).
    pub fn release_image(
        &self,
        major: u32,
        arch: Arch,
        prefer_server: bool,
    ) -> Result<ReleaseImage> {
        let build = format!("{major}.1");
        let url = format!(
            "{LIST}?{}",
            encode_query(&[("search", &build), ("sortByDate", "1")])
        );
        let listing = self
            .http
            .get_json(&url, &format!("locating the {build} release image"))?;
        let builds: Vec<&Value> = match listing.pointer("/response/builds") {
            Some(Value::Object(map)) => map.values().collect(),
            Some(Value::Array(list)) => list.iter().collect(),
            _ => return Err(Error::format("UUP listing", "no builds")),
        };
        let wanted_arch = match arch {
            Arch::X64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::X86 => "x86",
        };
        let mut candidates: Vec<(u8, String, String)> = builds
            .into_iter()
            .filter(|b| b.get("build").and_then(Value::as_str) == Some(build.as_str()))
            .filter(|b| b.get("arch").and_then(Value::as_str) == Some(wanted_arch))
            .filter_map(|b| {
                let title = b.get("title")?.as_str()?.to_owned();
                let uuid = b.get("uuid")?.as_str()?.to_owned();
                let lower = title.to_ascii_lowercase();
                if lower.contains("azure stack")
                    || lower.starts_with("cumulative update")
                    || lower.starts_with("security update")
                {
                    return None;
                }
                let server = lower.contains("server");
                let rank =
                    u8::from(server != prefer_server) * 2 + u8::from(lower.contains("insider"));
                Some((rank, title, uuid))
            })
            .collect();
        candidates.sort();
        let mut last_error = Error::NotFound(format!("no {build} {arch} release image is indexed"));
        for (_, title, uuid) in candidates.into_iter().take(4) {
            match self.image_of(&uuid, &build, &title) {
                Ok(image) => return Ok(image),
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    }

    fn image_of(&self, uuid: &str, build: &str, title: &str) -> Result<ReleaseImage> {
        let url = format!(
            "{GET}?{}",
            encode_query(&[("id", uuid), ("lang", "en-us"), ("noLinks", "0")])
        );
        let payload = self
            .http
            .get_json(&url, &format!("listing files of {title}"))?;
        let files = payload
            .pointer("/response/files")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::NotFound(format!("no file list for {title}")))?;
        const PREFERRED: &[&str] = &[
            "professional_en-us.esd",
            "core_en-us.esd",
            "serverstandard_en-us.esd",
            "serverdatacenter_en-us.esd",
            "enterprise_en-us.esd",
        ];
        let name = PREFERRED
            .iter()
            .find_map(|want| files.keys().find(|k| k.eq_ignore_ascii_case(want)))
            .or_else(|| {
                files
                    .iter()
                    .filter(|(k, _)| k.to_ascii_lowercase().ends_with("_en-us.esd"))
                    .max_by_key(|(_, v)| v.get("size").and_then(value_u64).unwrap_or(0))
                    .map(|(k, _)| k)
            })
            .ok_or_else(|| Error::NotFound(format!("{title} has no en-US install image")))?
            .clone();
        let file = &files[&name];
        let url = file
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let host_ok = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .is_some_and(|host| {
                host.ends_with(".delivery.mp.microsoft.com") || host.ends_with(".windowsupdate.com")
            });
        if !host_ok {
            return Err(Error::format(
                "UUP file list",
                "image URL is not on a Microsoft CDN",
            ));
        }
        Ok(ReleaseImage {
            build: build.to_owned(),
            title: title.to_owned(),
            size: file.get("size").and_then(value_u64).unwrap_or(0),
            sha1: file
                .get("sha1")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase(),
            name,
            url,
        })
    }
}

fn value_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
