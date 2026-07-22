//! Allocation-free, bounds-checked parsing of an existing byte slice.

use crate::{Error, Result};

pub(crate) struct BoundedReader<'data> {
    bytes: &'data [u8],
    position: usize,
}

impl<'data> BoundedReader<'data> {
    pub(crate) const fn new(bytes: &'data [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn read_bytes(&mut self, length: u64) -> Result<&'data [u8]> {
        let requested = usize::try_from(length).map_err(|_| Error::Format {
            detail: String::from("byte range length is not representable on this platform"),
        })?;
        let end = self
            .position
            .checked_add(requested)
            .ok_or_else(|| Error::Format {
                detail: String::from("byte range end overflows this platform"),
            })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| Error::Format {
                detail: String::from("truncated bounded byte range"),
            })?;
        self.position = end;
        Ok(bytes)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        bytes.first().copied().ok_or_else(|| Error::Format {
            detail: String::from("truncated byte value"),
        })
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        let value = <[u8; 4]>::try_from(bytes).map_err(|_| Error::Format {
            detail: String::from("truncated little-endian u32"),
        })?;
        Ok(u32::from_le_bytes(value))
    }

    pub(crate) fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        let value = <[u8; 8]>::try_from(bytes).map_err(|_| Error::Format {
            detail: String::from("truncated little-endian u64"),
        })?;
        Ok(u64::from_le_bytes(value))
    }

    pub(crate) fn read_7z_uint(&mut self) -> Result<u64> {
        let first = self.read_u8()?;
        let mut mask = 0x80_u8;
        let mut value = 0_u64;

        for shift in [0_u32, 8, 16, 24, 32, 40, 48, 56] {
            if first & mask == 0 {
                let low_mask = mask.checked_sub(1).ok_or_else(|| Error::Format {
                    detail: String::from("7z integer mask underflows"),
                })?;
                value |= u64::from(first & low_mask) << shift;
                return Ok(value);
            }

            value |= u64::from(self.read_u8()?) << shift;
            mask >>= 1;
        }

        Ok(value)
    }

    pub(crate) fn parse_exact<T, Parse>(
        &mut self,
        length: u64,
        unconsumed_detail: &'static str,
        parse: Parse,
    ) -> Result<T>
    where
        Parse: FnOnce(&mut BoundedReader<'_>) -> Result<T>,
    {
        let bytes = self.read_bytes(length)?;
        let mut child = Self::new(bytes);
        let value = parse(&mut child)?;
        child.finish(unconsumed_detail)?;
        Ok(value)
    }

    pub(crate) fn finish(self, unconsumed_detail: &'static str) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Format {
                detail: String::from(unconsumed_detail),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedReader;
    use crate::ErrorKind;

    #[test]
    fn reads_7z_integer_boundary_encodings() -> crate::Result<()> {
        let cases: &[(&[u8], u64)] = &[
            (&[0x00], 0),
            (&[0x7f], 127),
            (&[0x80, 0x80], 128),
            (&[0xbf, 0xff], 16_383),
            (&[0xc0, 0x00, 0x40], 16_384),
            (
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                u64::MAX,
            ),
        ];

        for (encoded, expected) in cases {
            let mut reader = BoundedReader::new(encoded);
            assert_eq!(reader.read_7z_uint()?, *expected);
            reader.finish("integer was not consumed exactly")?;
        }
        Ok(())
    }

    #[test]
    fn exhaustively_decodes_one_and_two_byte_integers() -> crate::Result<()> {
        for first in 0_u8..=0x7f {
            let encoded = [first];
            let mut reader = BoundedReader::new(&encoded);
            assert_eq!(reader.read_7z_uint()?, u64::from(first));
            reader.finish("one-byte integer was not consumed exactly")?;
        }

        for high in 0_u8..=0x3f {
            for low in 0_u8..=u8::MAX {
                let encoded = [0x80 | high, low];
                let expected = (u64::from(high) << 8) | u64::from(low);
                let mut reader = BoundedReader::new(&encoded);
                assert_eq!(reader.read_7z_uint()?, expected);
                reader.finish("two-byte integer was not consumed exactly")?;
            }
        }
        Ok(())
    }

    #[test]
    fn rejects_every_truncation_of_long_integer() {
        let encoded = [0xff_u8; 9];
        for length in 0..encoded.len() {
            let Some(prefix) = encoded.get(..length) else {
                continue;
            };
            let mut reader = BoundedReader::new(prefix);
            assert_eq!(
                reader.read_7z_uint().err().map(|error| error.kind()),
                Some(ErrorKind::Format)
            );
        }
    }

    #[test]
    fn exact_child_reader_rejects_trailing_property_bytes() {
        let mut outer = BoundedReader::new(&[0xaa, 0xbb]);
        let result = outer.parse_exact(2, "property was not consumed exactly", |child| {
            child.read_u8()
        });
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
    }

    #[test]
    fn exact_child_reader_accepts_complete_consumption() -> crate::Result<()> {
        let mut outer = BoundedReader::new(&[0xaa, 0xbb, 0xcc]);
        let pair = outer.parse_exact(2, "property was not consumed exactly", |child| {
            Ok((child.read_u8()?, child.read_u8()?))
        })?;
        assert_eq!(pair, (0xaa, 0xbb));
        assert_eq!(outer.read_u8()?, 0xcc);
        outer.finish("outer reader has trailing bytes")
    }
}
