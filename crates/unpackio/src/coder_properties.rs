//! Shared semantic validation for bounded coder-property records.

use crate::{Result, parse_util::format_error};

const PPMD_CANONICAL_PROPERTY_BYTES: usize = 5;
const PPMD_PY7ZR_PROPERTY_BYTES: usize = 7;
const PPMD_MINIMUM_MEMORY_BYTES: u32 = 1 << 11;
const PPMD_MINIMUM_ORDER: u8 = 2;
const PPMD_MAXIMUM_ORDER: u8 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PpmdProperties {
    order: u8,
    memory_size: u32,
}

impl PpmdProperties {
    pub(crate) const fn order(self) -> u8 {
        self.order
    }

    pub(crate) const fn memory_size(self) -> u32 {
        self.memory_size
    }
}

pub(crate) fn parse_ppmd_properties(properties: &[u8]) -> Result<PpmdProperties> {
    let canonical = match properties.len() {
        PPMD_CANONICAL_PROPERTY_BYTES => properties,
        PPMD_PY7ZR_PROPERTY_BYTES => {
            let reserved = properties
                .get(PPMD_CANONICAL_PROPERTY_BYTES..PPMD_PY7ZR_PROPERTY_BYTES)
                .ok_or_else(|| format_error("PPMd reserved properties are truncated"))?;
            if reserved != [0, 0] {
                return Err(format_error("PPMd reserved properties must be zero"));
            }
            properties
                .get(..PPMD_CANONICAL_PROPERTY_BYTES)
                .ok_or_else(|| format_error("PPMd canonical properties are truncated"))?
        }
        _ => {
            return Err(format_error(
                "PPMd properties must contain exactly five bytes, or seven bytes with two zero reserved bytes",
            ));
        }
    };
    let bytes = <[u8; PPMD_CANONICAL_PROPERTY_BYTES]>::try_from(canonical)
        .map_err(|_| format_error("PPMd canonical properties have the wrong length"))?;
    let order = bytes
        .first()
        .copied()
        .ok_or_else(|| format_error("PPMd order property is missing"))?;
    if !(PPMD_MINIMUM_ORDER..=PPMD_MAXIMUM_ORDER).contains(&order) {
        return Err(format_error("PPMd order is outside 2 through 64"));
    }
    let memory_size = u32::from_le_bytes(
        bytes
            .get(1..PPMD_CANONICAL_PROPERTY_BYTES)
            .ok_or_else(|| format_error("PPMd memory property is truncated"))?
            .try_into()
            .map_err(|_| format_error("PPMd memory property has the wrong length"))?,
    );
    if memory_size < PPMD_MINIMUM_MEMORY_BYTES {
        return Err(format_error("PPMd memory size is below the format minimum"));
    }
    Ok(PpmdProperties { order, memory_size })
}

#[cfg(test)]
mod tests {
    use super::{PpmdProperties, parse_ppmd_properties};
    use crate::{Error, Result};

    const CANONICAL: &[u8] = &[6, 0, 0, 1, 0];

    #[test]
    fn accepts_canonical_and_zero_reserved_py7zr_properties() -> Result<()> {
        let expected = PpmdProperties {
            order: 6,
            memory_size: 64 * 1024,
        };
        assert_eq!(parse_ppmd_properties(CANONICAL)?, expected);
        assert_eq!(parse_ppmd_properties(&[6, 0, 0, 1, 0, 0, 0])?, expected);
        Ok(())
    }

    #[test]
    fn rejects_nonzero_reserved_bytes_and_every_other_length() {
        for properties in [[6, 0, 0, 1, 0, 1, 0], [6, 0, 0, 1, 0, 0, 1]] {
            assert!(matches!(
                parse_ppmd_properties(&properties),
                Err(Error::Format { .. })
            ));
        }
        for length in 0..=9 {
            if matches!(length, 5 | 7) {
                continue;
            }
            let mut properties = CANONICAL.to_vec();
            properties.resize(length, 0);
            assert!(matches!(
                parse_ppmd_properties(&properties),
                Err(Error::Format { .. })
            ));
        }
    }
}
