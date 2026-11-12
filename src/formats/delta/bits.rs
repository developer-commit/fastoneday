//! LSB-first bit reader with MSDelta's integer encodings.
//!
//! Semantics follow msdelta's `BitReader` (jlevere/msdelta, MIT/Apache-2.0):
//! the first three bits of a buffer give the number of padding bits at its
//! end, values are read least-significant bit first, and signed integers use
//! a nibble-count prefix.

use crate::error::{Error, Result};

pub struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position.
    pos: usize,
    /// One past the last readable bit.
    limit: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let first = *data.first().ok_or_else(|| truncated("empty bitstream"))?;
        let padding = (first & 7) as usize;
        let total = data.len() * 8;
        if total < 3 + padding {
            return Err(truncated("bitstream shorter than its header"));
        }
        Ok(Self {
            data,
            pos: 3,
            limit: total - padding,
        })
    }

    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }

    fn bit(&self, index: usize) -> u64 {
        ((self.data[index / 8] >> (index % 8)) & 1) as u64
    }

    pub fn peek_bits(&self, n: usize) -> u64 {
        let available = (self.data.len() * 8).saturating_sub(self.pos).min(n);
        let mut value = 0u64;
        for i in 0..available {
            value |= self.bit(self.pos + i) << i;
        }
        value
    }

    pub fn read_bits(&mut self, n: usize) -> Result<u64> {
        debug_assert!(n <= 64);
        if self.pos + n > self.data.len() * 8 {
            return Err(truncated("bitstream exhausted"));
        }
        let value = self.peek_bits(n);
        self.pos += n;
        Ok(value)
    }

    /// `IntFunctions::ReadBit` signed varint: `k` zero bits, a one bit, then
    /// `4 * (k + 1)` value bits.
    pub fn read_i64(&mut self) -> Result<i64> {
        let mut zeros = 0usize;
        while zeros < 16 {
            if self.read_bits(1)? == 1 {
                let value_bits = (zeros + 1) * 4;
                let value = if value_bits <= 32 {
                    self.read_bits(value_bits)?
                } else {
                    let low = self.read_bits(32)?;
                    let high = self.read_bits(value_bits - 32)?;
                    (high << 32) | low
                };
                return Ok(value as i64);
            }
            zeros += 1;
        }
        Err(Error::format(
            "delta bitstream",
            "invalid variable-length integer",
        ))
    }
}

fn truncated(detail: &str) -> Error {
    Error::format("delta bitstream", detail)
}

/// Canonical Huffman code as MSDelta builds it (codes assigned from the
/// longest length down, transmitted least-significant bit first).
pub struct Huffman {
    /// `(length, code-as-read)` → symbol, grouped by length.
    by_len: Vec<Vec<(u32, u16)>>,
}

impl Huffman {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let max_len = *lengths.iter().max().unwrap_or(&0) as usize;
        if max_len > 16 {
            return Err(Error::format("delta huffman", "code length above 16"));
        }
        let mut count = vec![0u32; max_len + 1];
        for &len in lengths {
            count[len as usize] += 1;
        }
        count[0] = 0;
        let mut next = vec![0u32; max_len + 1];
        let mut acc = 0u32;
        for len in (1..=max_len).rev() {
            next[len] = acc;
            acc = (acc + count[len]) >> 1;
        }
        let mut by_len = vec![Vec::new(); max_len + 1];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = len as usize;
            let canonical = next[len];
            next[len] += 1;
            let mut reversed = 0u32;
            for bit in 0..len {
                reversed |= ((canonical >> bit) & 1) << (len - 1 - bit);
            }
            by_len[len].push((reversed, symbol as u16));
        }
        Ok(Self { by_len })
    }

    pub fn read_symbol(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        for (len, codes) in self.by_len.iter().enumerate().skip(1) {
            if codes.is_empty() {
                continue;
            }
            let peek = reader.peek_bits(len) as u32;
            if let Some((_, symbol)) = codes.iter().find(|(code, _)| *code == peek) {
                reader.read_bits(len)?;
                return Ok(*symbol);
            }
        }
        Err(Error::format("delta huffman", "no code matches the input"))
    }
}

const INT_SYMBOLS: usize = 252;
const INT_HALF: usize = 126;

/// Huffman-coded signed integers (`IntFormat` in msdelta).
pub struct IntFormat {
    table: Huffman,
}

impl IntFormat {
    pub fn read(reader: &mut BitReader<'_>) -> Result<Self> {
        let num_pos = reader.read_bits(8)? as usize;
        let num_neg = reader.read_bits(8)? as usize;
        let num_default = reader.read_bits(8)? as usize;
        if num_pos > INT_HALF || num_neg > INT_HALF || num_default > INT_SYMBOLS - num_pos - num_neg
        {
            return Err(Error::format("delta int format", "header out of range"));
        }
        let mut lengths = vec![0u8; INT_SYMBOLS];
        for slot in &mut lengths[..num_pos] {
            *slot = (reader.read_bits(4)? as u8).wrapping_add(1);
        }
        for slot in &mut lengths[INT_HALF..INT_HALF + num_neg] {
            *slot = (reader.read_bits(4)? as u8).wrapping_add(1);
        }
        let default_len = (reader.read_bits(4)? as u8).wrapping_add(1);
        if default_len > 16 {
            return Err(Error::format("delta int format", "default length above 16"));
        }

        let mut len = default_len;
        let mut remaining = num_default;
        for (i, slot) in lengths.iter_mut().enumerate().take(INT_HALF).skip(num_pos) {
            if remaining == 0 {
                len = len.saturating_sub(1);
                remaining = (INT_SYMBOLS - num_pos - num_neg).saturating_sub(i);
            }
            *slot = len;
            remaining = remaining.saturating_sub(1);
        }

        let mut len = default_len;
        let mut remaining = num_default.saturating_sub(INT_HALF - num_pos);
        for (i, slot) in lengths.iter_mut().enumerate().skip(INT_HALF + num_neg) {
            if remaining == 0 {
                len = len.saturating_sub(1);
                remaining = INT_HALF.saturating_sub(i - INT_HALF);
            }
            *slot = len;
            remaining = remaining.saturating_sub(1);
        }

        Ok(Self {
            table: Huffman::from_lengths(&lengths)?,
        })
    }

    pub fn read_number(&self, reader: &mut BitReader<'_>) -> Result<i64> {
        let symbol = self.table.read_symbol(reader)? as usize;
        let (magnitude, negative) = if symbol < INT_HALF {
            (symbol, false)
        } else {
            (symbol - INT_HALF, true)
        };
        let value = if magnitude <= 3 {
            magnitude as i64
        } else {
            let half = (magnitude >> 1) - 1;
            let base = (magnitude & 1) as i64 + 2;
            (base << half) | reader.read_bits(half)? as i64
        };
        Ok(if negative { !value } else { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_msdelta_header_varints() {
        // From msdelta's own fixture: FileTypeSet=1, FileType=1, Flags=0x20000,
        // TargetSize=415, HashAlgId=0.
        let data = [
            0x18, 0x03, 0x02, 0x00, 0x08, 0x3f, 0x23, 0x04, 0x01, 0x9a, 0x00,
        ];
        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 0x20000);
        assert_eq!(r.read_i64().unwrap(), 415);
        assert_eq!(r.read_i64().unwrap(), 0);
    }

    #[test]
    fn huffman_round_trips_a_complete_code() {
        // lengths 1,2,3,3 form a complete prefix code.
        let table = Huffman::from_lengths(&[1, 2, 3, 3]).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for codes in &table.by_len {
            for (code, sym) in codes {
                seen.insert((*code, *sym));
            }
        }
        assert_eq!(seen.len(), 4);
    }
}
