//! WinSxS component identities and update-package payload paths.
//!
//! A component directory looks like
//! `amd64_microsoft-windows-winsock-core_31bf3856ad364e35_10.0.26100.1455_none_73aeb15d0e6fdbcb`
//! and payloads inside update packages are `<component>\f\afd.sys` (forward
//! delta), `<component>\n\x.mui` (null delta) or `<component>\x.dll` (full).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// `amd64`, `wow64`, `x86`, `arm64`, `msil`, ...
    pub arch: String,
    pub name: String,
    pub token: String,
    pub version: String,
    pub culture: String,
}

impl Component {
    /// Parses from the right because names may contain underscores.
    pub fn parse(dir: &str) -> Option<Self> {
        let parts: Vec<&str> = dir.split('_').collect();
        if parts.len() < 6 {
            return None;
        }
        let n = parts.len();
        let version = parts[n - 3];
        if !version
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        Some(Self {
            arch: parts[0].to_ascii_lowercase(),
            name: parts[1..n - 4].join("_").to_ascii_lowercase(),
            token: parts[n - 4].to_ascii_lowercase(),
            version: version.to_owned(),
            culture: parts[n - 2].to_ascii_lowercase(),
        })
    }

    /// Identity without the version: the same component across updates.
    pub fn key(&self) -> String {
        format!(
            "{}_{}_{}_{}",
            self.arch, self.name, self.token, self.culture
        )
    }

    pub fn is_neutral(&self) -> bool {
        self.culture == "none"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    /// `f\`: delta from the servicing baseline to this version.
    Forward,
    /// `r\`: delta from this version back to the baseline.
    Reverse,
    /// `n\`: delta from nothing (a compressed full file).
    Null,
    /// The complete file.
    Full,
}

impl PayloadKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Forward => "forward delta",
            Self::Reverse => "reverse delta",
            Self::Null => "null delta",
            Self::Full => "full file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadPath {
    pub component: Component,
    pub kind: PayloadKind,
    /// Lower-case file name.
    pub file_name: String,
}

impl PayloadPath {
    pub fn parse(path: &str) -> Option<Self> {
        let parts: Vec<&str> = path.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
        let (dir, kind, file) = match parts.as_slice() {
            [dir, kind, file] => (
                *dir,
                match kind.to_ascii_lowercase().as_str() {
                    "f" => PayloadKind::Forward,
                    "r" => PayloadKind::Reverse,
                    "n" => PayloadKind::Null,
                    _ => return None,
                },
                *file,
            ),
            [dir, file] => (*dir, PayloadKind::Full, *file),
            _ => return None,
        };
        Some(Self {
            component: Component::parse(dir)?,
            kind,
            file_name: file.to_ascii_lowercase(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_component_with_underscores_in_the_name() {
        let c = Component::parse(
            "amd64_dual_usbxhci.inf_31bf3856ad364e35_10.0.26100.1301_none_deb1afd211130fa3",
        )
        .unwrap();
        assert_eq!(c.arch, "amd64");
        assert_eq!(c.name, "dual_usbxhci.inf");
        assert_eq!(c.version, "10.0.26100.1301");
        assert_eq!(c.key(), "amd64_dual_usbxhci.inf_31bf3856ad364e35_none");
    }

    #[test]
    fn parses_payload_paths() {
        let p = PayloadPath::parse(
            "amd64_microsoft-windows-winsock-core_31bf3856ad364e35_10.0.26100.1455_none_73aeb15d0e6fdbcb\\f\\afd.sys",
        )
        .unwrap();
        assert_eq!(p.kind, PayloadKind::Forward);
        assert_eq!(p.file_name, "afd.sys");
        assert_eq!(p.component.version, "10.0.26100.1455");
        let full = PayloadPath::parse(
            "x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.0.26100.712_none_cd8d4426f23735f0\\GdiPlus.dll",
        )
        .unwrap();
        assert_eq!(full.kind, PayloadKind::Full);
        assert_eq!(full.file_name, "gdiplus.dll");
        assert!(PayloadPath::parse("Windows11.0-KB5041571-x64.psf").is_none());
    }
}
