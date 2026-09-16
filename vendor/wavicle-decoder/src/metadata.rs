//! Metadata sub-block framing: the typed, length-prefixed run that fills a
//! block after its 32-byte header.
//!
//! Framing per the format document: one id byte (function id in the low six
//! bits, plus [`meta::ODD_SIZE`] and [`meta::LARGE`] flags), then a one- or
//! three-byte little-endian word count, then `words * 2` data bytes, always
//! even-padded in the stream even when the logical length is odd.

use crate::error::{Error, Scope};
use crate::format::meta;

/// One parsed sub-block, borrowing its payload from the block.
#[derive(Clone, Copy, Debug)]
pub struct SubBlock<'a> {
    /// Function id (`raw_id & ID_MASK`).
    pub id: u8,
    /// Payload with any odd-size padding byte already trimmed.
    pub data: &'a [u8],
}

impl SubBlock<'_> {
    /// Whether a decoder may skip this sub-block when it does not know it.
    pub fn optional(self) -> bool {
        self.id & meta::OPTIONAL != 0
    }
}

/// Iterator over the sub-blocks of one block's metadata region.
pub struct SubBlocks<'a> {
    rest: &'a [u8],
}

impl<'a> SubBlocks<'a> {
    pub fn new(metadata_region: &'a [u8]) -> Self {
        Self {
            rest: metadata_region,
        }
    }
}

impl<'a> Iterator for SubBlocks<'a> {
    type Item = Result<SubBlock<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let raw_id = self.rest.first().copied()?;
        let id = raw_id & meta::ID_MASK;
        let large = raw_id & meta::LARGE != 0;
        let header_len = if large { 4 } else { 2 };
        if self.rest.len() < header_len {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        }
        let words = if large {
            let [_, low, middle, high, ..] = self.rest else {
                self.rest = &[];
                return Some(Err(Error::BadSubBlock { id }));
            };
            u32::from(*low) | (u32::from(*middle) << 8) | (u32::from(*high) << 16)
        } else {
            let [_, low, ..] = self.rest else {
                self.rest = &[];
                return Some(Err(Error::BadSubBlock { id }));
            };
            u32::from(*low)
        };
        let Some(stored) = usize::try_from(words)
            .ok()
            .and_then(|word_count| word_count.checked_mul(2))
        else {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        };
        let Some(total) = header_len.checked_add(stored) else {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        };
        if self.rest.len() < total {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        }
        let Some(mut data) = self.rest.get(header_len..total) else {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        };
        if raw_id & meta::ODD_SIZE != 0 {
            if data.is_empty() {
                self.rest = &[];
                return Some(Err(Error::BadSubBlock { id }));
            }
            let Some(logical_len) = data.len().checked_sub(1) else {
                self.rest = &[];
                return Some(Err(Error::BadSubBlock { id }));
            };
            let Some(logical) = data.get(..logical_len) else {
                self.rest = &[];
                return Some(Err(Error::BadSubBlock { id }));
            };
            data = logical;
        }
        let Some(rest) = self.rest.get(total..) else {
            self.rest = &[];
            return Some(Err(Error::BadSubBlock { id }));
        };
        self.rest = rest;
        Some(Ok(SubBlock { id, data }))
    }
}

/// Scope gate for a sub-block id: out-of-scope content is rejected loudly,
/// unknown required ids are an error, unknown optional ids are fine to skip.
pub fn check_scope(sub: SubBlock<'_>) -> Result<(), Error> {
    match sub.id {
        meta::WVC_BITSTREAM | meta::SHAPING_WEIGHTS | meta::HYBRID_PROFILE => {
            Err(Error::OutOfScope(Scope::Hybrid))
        }
        meta::DSD_BLOCK => Err(Error::OutOfScope(Scope::Dsd)),
        meta::CHANNEL_INFO => {
            // First payload byte is the channel count; >2 is out of scope.
            match sub.data.first() {
                Some(&n) if n > 2 => Err(Error::OutOfScope(Scope::MoreThanTwoChannels)),
                Some(_) => Ok(()),
                None => Err(Error::BadSubBlock { id: sub.id }),
            }
        }
        id if id <= 0x1f && !known_required(id) => Err(Error::UnknownRequiredId(id)),
        _ => Ok(()),
    }
}

fn known_required(id: u8) -> bool {
    matches!(
        id,
        meta::DUMMY
            | meta::ENCODER_INFO
            | meta::DECORR_TERMS
            | meta::DECORR_WEIGHTS
            | meta::DECORR_SAMPLES
            | meta::ENTROPY_VARS
            | meta::HYBRID_PROFILE
            | meta::SHAPING_WEIGHTS
            | meta::FLOAT_INFO
            | meta::INT32_INFO
            | meta::WV_BITSTREAM
            | meta::WVC_BITSTREAM
            | meta::WVX_BITSTREAM
            | meta::CHANNEL_INFO
            | meta::DSD_BLOCK
    )
}
