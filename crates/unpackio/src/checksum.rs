//! CRC-32 support for 7z integrity fields.

use crate::{Error, Result};

const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

// The index is a compile-time counter in 0..256, not archive-derived data.
#[allow(clippy::indexing_slicing)]
const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_usize;
    let mut initial = 0_u32;
    while index < table.len() {
        let mut value = initial;
        let mut bit = 0_u8;
        while bit < 8 {
            value = if value & 1 == 0 {
                value >> 1
            } else {
                (value >> 1) ^ CRC32_POLYNOMIAL
            };
            bit = bit.saturating_add(1);
        }
        table[index] = value;
        index = index.saturating_add(1);
        initial = initial.saturating_add(1);
    }
    table
}

const CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Incremental CRC-32/ISO-HDLC state used by checked archive reads.
pub(crate) struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub(crate) const fn new() -> Self {
        Self { state: u32::MAX }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<()> {
        for byte in bytes {
            let [low, _, _, _] = self.state.to_le_bytes();
            let table_index = usize::from(low ^ byte);
            let Some(table_value) = CRC32_TABLE.get(table_index) else {
                return Err(Error::Format {
                    detail: String::from("internal CRC-32 table index is invalid"),
                });
            };
            self.state = *table_value ^ (self.state >> 8);
        }
        Ok(())
    }

    pub(crate) const fn finalize(self) -> u32 {
        !self.state
    }

    #[cfg(test)]
    pub(crate) fn checksum(bytes: &[u8]) -> Result<u32> {
        let mut checksum = Self::new();
        checksum.update(bytes)?;
        Ok(checksum.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::Crc32;

    #[test]
    fn matches_standard_crc32_vectors() -> crate::Result<()> {
        assert_eq!(Crc32::checksum(b"")?, 0);
        assert_eq!(Crc32::checksum(b"123456789")?, 0xcbf4_3926);
        Ok(())
    }

    #[test]
    fn incremental_updates_match_one_shot() -> crate::Result<()> {
        let input = b"123456789";
        let expected = Crc32::checksum(input)?;
        for split in 0..=input.len() {
            let Some(first) = input.get(..split) else {
                continue;
            };
            let Some(second) = input.get(split..) else {
                continue;
            };
            let mut checksum = Crc32::new();
            checksum.update(first)?;
            checksum.update(second)?;
            assert_eq!(checksum.finalize(), expected);
        }
        Ok(())
    }
}
