//! Bounds-checked cursor for standalone compressed-stream structures.

use super::stream_format_error;
use crate::Result;

pub(super) struct StreamCursor<'data> {
    bytes: &'data [u8],
    position: usize,
    format: &'static str,
}

impl<'data> StreamCursor<'data> {
    pub(super) const fn new(bytes: &'data [u8], format: &'static str) -> Self {
        Self {
            bytes,
            position: 0,
            format,
        }
    }

    pub(super) const fn position(&self) -> usize {
        self.position
    }

    pub(super) fn remaining(&self) -> Result<&'data [u8]> {
        self.bytes
            .get(self.position..)
            .ok_or_else(|| stream_format_error(self.format, "cursor position is out of range"))
    }

    pub(super) fn read_bytes(
        &mut self,
        length: usize,
        truncated_detail: &'static str,
    ) -> Result<&'data [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| stream_format_error(self.format, "byte range end overflows"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| stream_format_error(self.format, truncated_detail))?;
        self.position = end;
        Ok(bytes)
    }

    pub(super) fn skip_u64(&mut self, length: u64, truncated_detail: &'static str) -> Result<()> {
        let length = usize::try_from(length).map_err(|_| {
            stream_format_error(
                self.format,
                "byte range is not representable on this platform",
            )
        })?;
        self.read_bytes(length, truncated_detail).map(|_| ())
    }

    pub(super) fn read_u8(&mut self, truncated_detail: &'static str) -> Result<u8> {
        self.read_bytes(1, truncated_detail)?
            .first()
            .copied()
            .ok_or_else(|| stream_format_error(self.format, truncated_detail))
    }

    pub(super) fn read_u24_le(&mut self, truncated_detail: &'static str) -> Result<u32> {
        let bytes = self.read_bytes(3, truncated_detail)?;
        let low = bytes
            .first()
            .copied()
            .ok_or_else(|| stream_format_error(self.format, truncated_detail))?;
        let middle = bytes
            .get(1)
            .copied()
            .ok_or_else(|| stream_format_error(self.format, truncated_detail))?;
        let high = bytes
            .get(2)
            .copied()
            .ok_or_else(|| stream_format_error(self.format, truncated_detail))?;
        Ok(u32::from(low) | (u32::from(middle) << 8) | (u32::from(high) << 16))
    }

    pub(super) fn read_u32_le(&mut self, truncated_detail: &'static str) -> Result<u32> {
        let bytes = <[u8; 4]>::try_from(self.read_bytes(4, truncated_detail)?)
            .map_err(|_| stream_format_error(self.format, truncated_detail))?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(super) fn read_le(&mut self, length: usize, truncated_detail: &'static str) -> Result<u64> {
        let bytes = self.read_bytes(length, truncated_detail)?;
        let mut value = 0_u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            let shift = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(8))
                .ok_or_else(|| stream_format_error(self.format, "integer shift overflows"))?;
            value |= u64::from(byte)
                .checked_shl(shift)
                .ok_or_else(|| stream_format_error(self.format, "integer value overflows"))?;
        }
        Ok(value)
    }
}
