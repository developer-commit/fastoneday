//! Authenticode image digest check.
//!
//! A signed PE carries, inside its PKCS#7 signature, the hash Microsoft took
//! of the image (`SpcIndirectDataContent.messageDigest`). Recomputing that
//! hash over the same byte ranges proves the file is byte-for-byte what was
//! signed. This module does exactly that and nothing more: it does not
//! validate the certificate chain or the RSA signature itself.

use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::{
    domain::{Digest, HashAlgorithm},
    error::{Error, Result},
    io::le,
};

/// `1.3.6.1.4.1.311.2.1.4` (SPC_INDIRECT_DATA_OBJID).
const SPC_INDIRECT_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
/// `2.16.840.1.101.3.4.2.1`.
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `1.3.14.3.2.26`.
const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];

/// Where the hashed regions of a PE image are.
struct Layout {
    checksum: usize,
    security_entry: usize,
    certificates: usize,
}

/// Recomputes the image hash and compares it with the signed one.
///
/// `Ok(Some(digest))` when they match, `Ok(None)` for an unsigned image and
/// an [`Error::Integrity`] when the bytes differ from what was signed.
pub fn verify(image: &[u8], what: &str) -> Result<Option<Digest>> {
    let Some((layout, blob)) = signature_blob(image)? else {
        return Ok(None);
    };
    let (algorithm, signed) = message_digest(blob)?;
    let actual = image_digest(image, &layout, algorithm);
    if actual != signed {
        return Err(Error::Integrity {
            what: format!("{what} (Authenticode)"),
            algorithm: algorithm.name(),
            expected: Digest::from_bytes(algorithm, &signed).hex,
            actual: Digest::from_bytes(algorithm, &actual).hex,
        });
    }
    Ok(Some(Digest::from_bytes(algorithm, &signed)))
}

fn signature_blob(image: &[u8]) -> Result<Option<(Layout, &[u8])>> {
    let bad = |detail: &str| Error::format("Authenticode", detail.to_string());
    if image.len() < 0x40 || &image[..2] != b"MZ" {
        return Err(bad("not a PE image"));
    }
    let pe = le::u32(image, 0x3c) as usize;
    let opt = pe + 24;
    if image.len() < opt + 2 || &image[pe..pe + 4] != b"PE\0\0" {
        return Err(bad("missing PE signature"));
    }
    let directories = match le::u16(image, opt) {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return Err(bad("unknown optional header magic")),
    };
    let security_entry = directories + 4 * 8;
    if image.len() < security_entry + 8 {
        return Err(bad("data directories truncated"));
    }
    let offset = le::u32(image, security_entry) as usize;
    let size = le::u32(image, security_entry + 4) as usize;
    if offset == 0 || size == 0 {
        return Ok(None);
    }
    let table = image
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| bad("bad table size"))?,
        )
        .ok_or_else(|| bad("certificate table outside the file"))?;
    // WIN_CERTIFICATE: length, revision, type (2 = PKCS#7 SignedData).
    if table.len() < 8 || le::u16(table, 6) != 2 {
        return Err(bad("no PKCS#7 certificate"));
    }
    let length = (le::u32(table, 0) as usize).min(table.len());
    Ok(Some((
        Layout {
            checksum: opt + 64,
            security_entry,
            certificates: offset,
        },
        &table[8..length],
    )))
}

/// Hash of the image without the checksum, the security directory entry
/// and the certificate table itself.
fn image_digest(image: &[u8], layout: &Layout, algorithm: HashAlgorithm) -> Vec<u8> {
    let ranges = [
        0..layout.checksum,
        layout.checksum + 4..layout.security_entry,
        layout.security_entry + 8..layout.certificates,
    ];
    match algorithm {
        HashAlgorithm::Sha1 => {
            let mut h = Sha1::new();
            ranges.into_iter().for_each(|r| h.update(&image[r]));
            h.finalize().to_vec()
        }
        _ => {
            let mut h = Sha256::new();
            ranges.into_iter().for_each(|r| h.update(&image[r]));
            h.finalize().to_vec()
        }
    }
}

/// ContentInfo → SignedData → encapContentInfo → SpcIndirectDataContent →
/// DigestInfo → (algorithm, digest).
fn message_digest(blob: &[u8]) -> Result<(HashAlgorithm, Vec<u8>)> {
    let bad = |detail: &str| Error::format("Authenticode signature", detail.to_string());
    let content_info = Der::new(blob)
        .expect(0x30)
        .ok_or_else(|| bad("no ContentInfo"))?;
    let mut fields = Der::new(content_info);
    fields.expect(0x06).ok_or_else(|| bad("no content type"))?;
    let explicit = fields.expect(0xa0).ok_or_else(|| bad("no signed data"))?;
    let signed_data = Der::new(explicit)
        .expect(0x30)
        .ok_or_else(|| bad("no SignedData"))?;
    let mut fields = Der::new(signed_data);
    fields.expect(0x02).ok_or_else(|| bad("no version"))?;
    fields
        .expect(0x31)
        .ok_or_else(|| bad("no digest algorithms"))?;
    let encapsulated = fields.expect(0x30).ok_or_else(|| bad("no content info"))?;
    let mut fields = Der::new(encapsulated);
    if fields.expect(0x06) != Some(SPC_INDIRECT_DATA) {
        return Err(bad("not an Authenticode signature"));
    }
    let mut content = fields.expect(0xa0).ok_or_else(|| bad("no indirect data"))?;
    // Some encoders wrap the content in an OCTET STRING.
    if let Some(inner) = Der::new(content).expect(0x04) {
        content = inner;
    }
    let indirect = Der::new(content)
        .expect(0x30)
        .ok_or_else(|| bad("no indirect data"))?;
    let mut fields = Der::new(indirect);
    fields.expect(0x30).ok_or_else(|| bad("no attribute"))?;
    let digest_info = fields.expect(0x30).ok_or_else(|| bad("no digest info"))?;
    let mut fields = Der::new(digest_info);
    let algorithm_id = fields
        .expect(0x30)
        .ok_or_else(|| bad("no digest algorithm"))?;
    let digest = fields.expect(0x04).ok_or_else(|| bad("no digest"))?;
    let algorithm = match Der::new(algorithm_id).expect(0x06) {
        Some(SHA256_OID) => HashAlgorithm::Sha256,
        Some(SHA1_OID) => HashAlgorithm::Sha1,
        _ => return Err(Error::Unsupported("Authenticode digest algorithm".into())),
    };
    Ok((algorithm, digest.to_vec()))
}

/// A cursor over consecutive DER elements.
struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// The content of the next element if its tag is `tag`.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (&found, rest) = self.data.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let len = rest[..count]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            rest = &rest[count..];
            len
        };
        let content = rest.get(..len)?;
        self.data = &rest[len..];
        (found == tag).then_some(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ whose security directory points at `blob`.
    fn signed_image(digest: &[u8], oid: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opt = 0x80 + 24;
        image[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[0x150] = 0xaa; // some content that is hashed
        let der = |tag: u8, content: &[u8]| {
            let mut out = vec![tag];
            if content.len() < 0x80 {
                out.push(content.len() as u8);
            } else {
                out.push(0x82);
                out.extend_from_slice(&(content.len() as u16).to_be_bytes());
            }
            out.extend_from_slice(content);
            out
        };
        let algorithm = der(0x30, &[der(0x06, oid), vec![0x05, 0x00]].concat());
        let digest_info = der(0x30, &[algorithm, der(0x04, digest)].concat());
        let indirect = der(0x30, &[der(0x30, &[]), digest_info].concat());
        let encapsulated = der(
            0x30,
            &[der(0x06, SPC_INDIRECT_DATA), der(0xa0, &indirect)].concat(),
        );
        let signed_data = der(
            0x30,
            &[der(0x02, &[1]), der(0x31, &[]), encapsulated].concat(),
        );
        let content_info = der(
            0x30,
            &[der(0x06, &[0x2a]), der(0xa0, &signed_data)].concat(),
        );
        let mut table = Vec::new();
        table.extend_from_slice(&((content_info.len() + 8) as u32).to_le_bytes());
        table.extend_from_slice(&0x0200u16.to_le_bytes());
        table.extend_from_slice(&2u16.to_le_bytes());
        table.extend_from_slice(&content_info);
        let at = image.len();
        let entry = opt + 112 + 4 * 8;
        image[entry..entry + 4].copy_from_slice(&(at as u32).to_le_bytes());
        image[entry + 4..entry + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
        image.extend_from_slice(&table);
        image
    }

    fn digest_of(image: &[u8]) -> Vec<u8> {
        let (layout, _) = signature_blob(image).unwrap().unwrap();
        image_digest(image, &layout, HashAlgorithm::Sha256)
    }

    #[test]
    fn verifies_matching_digest_and_rejects_tampering() {
        let placeholder = signed_image(&[0u8; 32], SHA256_OID);
        let good = digest_of(&placeholder);
        let image = signed_image(&good, SHA256_OID);
        let ok = verify(&image, "test.dll").unwrap().unwrap();
        assert_eq!(ok.algorithm, HashAlgorithm::Sha256);
        assert_eq!(ok.hex, Digest::from_bytes(HashAlgorithm::Sha256, &good).hex);

        // The checksum field is excluded from the hash...
        let mut checksum_changed = image.clone();
        checksum_changed[0x80 + 24 + 64] ^= 0xff;
        assert!(verify(&checksum_changed, "test.dll").unwrap().is_some());
        // ...but any other byte is not.
        let mut tampered = image;
        tampered[0x150] ^= 0xff;
        assert!(matches!(
            verify(&tampered, "test.dll"),
            Err(Error::Integrity { .. })
        ));
    }

    #[test]
    fn unsigned_images_have_no_digest() {
        let mut image = vec![0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x80 + 24..0x80 + 26].copy_from_slice(&0x10bu16.to_le_bytes());
        assert_eq!(verify(&image, "x.dll").unwrap(), None);
    }
}
