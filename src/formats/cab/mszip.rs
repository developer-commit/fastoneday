//! MSZIP: one raw-deflate stream per CFDATA block, where back-references may
//! reach into the previous block's output (a 32 KiB preset dictionary).

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Error, Result};

/// Returns the payload of a block that is a single final *stored* deflate
/// block — the common case for already-compressed content — without
/// needing the dictionary.
pub fn stored_payload(block: &[u8], uncompressed: usize) -> Option<&[u8]> {
    if block.len() != 2 + 5 + uncompressed || &block[..2] != b"CK" {
        return None;
    }
    let header = block[2];
    let len = u16::from_le_bytes([block[3], block[4]]) as usize;
    let nlen = u16::from_le_bytes([block[5], block[6]]);
    (header & 0x07 == 0x01 && len == uncompressed && nlen == !(len as u16)).then(|| &block[7..])
}

/// Inflates one block, priming the window with `dictionary`.
pub fn inflate(block: &[u8], dictionary: &[u8], uncompressed: usize) -> Result<Vec<u8>> {
    if block.len() < 2 || &block[..2] != b"CK" {
        return Err(Error::format("MSZIP block", "missing CK signature"));
    }
    let mut decoder = Decompress::new(false);
    if !dictionary.is_empty() {
        let dictionary = &dictionary[dictionary.len().saturating_sub(32 * 1024)..];
        let len = dictionary.len() as u16;
        let mut primer = Vec::with_capacity(dictionary.len() + 5);
        primer.push(0x00);
        primer.extend_from_slice(&len.to_le_bytes());
        primer.extend_from_slice(&(!len).to_le_bytes());
        primer.extend_from_slice(dictionary);
        let mut sink = Vec::with_capacity(dictionary.len());
        decoder
            .decompress_vec(&primer, &mut sink, FlushDecompress::Sync)
            .map_err(|e| Error::format("MSZIP block", e.to_string()))?;
    }
    let mut out = Vec::with_capacity(uncompressed);
    let status = decoder
        .decompress_vec(&block[2..], &mut out, FlushDecompress::Finish)
        .map_err(|e| Error::format("MSZIP block", e.to_string()))?;
    if out.len() != uncompressed
        || !matches!(status, Status::StreamEnd | Status::Ok | Status::BufError)
    {
        return Err(Error::format(
            "MSZIP block",
            format!("expected {uncompressed} bytes, produced {}", out.len()),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    /// Two MSZIP blocks the way CAB writers produce them: one deflate stream,
    /// sync-flushed between blocks, so block 2 may reference block 1.
    fn two_blocks(first: &[u8], second: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut c = Compress::new(Compression::best(), false);
        let mut a = Vec::with_capacity(first.len() + 64);
        c.compress_vec(first, &mut a, FlushCompress::Sync).unwrap();
        let mut b = Vec::with_capacity(second.len() + 64);
        c.compress_vec(second, &mut b, FlushCompress::Finish)
            .unwrap();
        let mut block1 = b"CK".to_vec();
        block1.extend_from_slice(&a);
        // Terminate block 1 with an empty final stored block.
        block1.extend_from_slice(&[0x03, 0x00]);
        let mut block2 = b"CK".to_vec();
        block2.extend_from_slice(&b);
        (block1, block2)
    }

    #[test]
    fn inflates_with_and_without_a_dictionary() {
        let first = b"the quick brown fox jumps over the lazy dog ".repeat(10);
        let second = b"the quick brown fox jumps over the lazy dog again".to_vec();
        let (block1, block2) = two_blocks(&first, &second);
        assert_eq!(inflate(&block1, &[], first.len()).unwrap(), first);
        assert_eq!(inflate(&block2, &first, second.len()).unwrap(), second);
    }

    #[test]
    fn recognises_stored_blocks() {
        let payload = vec![7u8; 16];
        let mut block = b"CK".to_vec();
        block.push(0x01);
        block.extend_from_slice(&16u16.to_le_bytes());
        block.extend_from_slice(&(!16u16).to_le_bytes());
        block.extend_from_slice(&payload);
        assert_eq!(stored_payload(&block, 16), Some(&payload[..]));
        assert_eq!(inflate(&block, &[], 16).unwrap(), payload);
    }
}
