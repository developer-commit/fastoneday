use std::fmt;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }

    /// Maps a Windows `ALG_ID` (as stored in MSDelta headers).
    pub fn from_alg_id(alg_id: u32) -> Option<Self> {
        match alg_id {
            0x8003 => Some(Self::Md5),
            0x8004 => Some(Self::Sha1),
            0x800c => Some(Self::Sha256),
            _ => None,
        }
    }

    fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

/// A hash value with its algorithm; hex is always lower case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: HashAlgorithm,
    pub hex: String,
}

impl Digest {
    pub fn new(algorithm: HashAlgorithm, hex: &str) -> Result<Self> {
        let hex = hex.trim().to_ascii_lowercase();
        if hex.len() == algorithm.hex_len() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self { algorithm, hex })
        } else {
            Err(Error::format(
                "digest",
                format!("invalid {} `{hex}`", algorithm.name()),
            ))
        }
    }

    pub fn from_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Self {
        Self {
            algorithm,
            hex: to_hex(bytes),
        }
    }

    pub fn of(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let raw = match algorithm {
            HashAlgorithm::Md5 => Md5::digest(data).to_vec(),
            HashAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        };
        Self::from_bytes(algorithm, &raw)
    }

    pub fn sha256(data: &[u8]) -> Self {
        Self::of(HashAlgorithm::Sha256, data)
    }

    /// `Ok(())` when `data` hashes to this digest; an integrity error otherwise.
    pub fn verify(&self, what: &str, data: &[u8]) -> Result<()> {
        let actual = Self::of(self.algorithm, data);
        if actual.hex == self.hex {
            Ok(())
        } else {
            Err(Error::Integrity {
                what: what.into(),
                algorithm: self.algorithm.name(),
                expected: self.hex.clone(),
                actual: actual.hex,
            })
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm.name(), self.hex)
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_and_reports_mismatch() {
        let d = Digest::sha256(b"abc");
        assert_eq!(
            d.hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(d.verify("x", b"abc").is_ok());
        assert!(d.verify("x", b"abd").is_err());
        assert_eq!(
            HashAlgorithm::from_alg_id(0x800c),
            Some(HashAlgorithm::Sha256)
        );
    }
}
