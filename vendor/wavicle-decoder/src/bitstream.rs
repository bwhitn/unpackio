//! LSB-first bit reader over a `WV_BITSTREAM` payload.
//!
//! Portions derived from WavPack (dbry/WavPack, `wavpack_local.h` getbit /
//! getbits macros and `open_utils.c` bs_open_read), Copyright (c) David Bryant
//! / Conifer Software, BSD-3-Clause; see ATTRIBUTION.md.
//!
//! Semantics mirror the reference exactly: bits come LSB-first from each byte
//! through a shift register (`sr`) holding `bc` unconsumed bits. Reading past
//! the end sets a sticky error flag and yields zero bytes; the reference wraps
//! to the buffer start instead, but a valid stream never reads past its end,
//! and the block CRC turns any such divergence into a hard error either way.

/// Bit reader with the reference's shift-register semantics.
pub struct BitReader<'a> {
    buf: &'a [u8],
    /// Index of the next byte to load into `sr`.
    next: usize,
    sr: u32,
    bc: u32,
    error: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            next: 0,
            sr: 0,
            bc: 0,
            error: false,
        }
    }

    /// Whether a read ever ran past the end of the payload.
    pub fn errored(&self) -> bool {
        self.error
    }

    fn load_byte(&mut self) -> u32 {
        match self.buf.get(self.next) {
            Some(&b) => {
                let Some(next) = self.next.checked_add(1) else {
                    self.error = true;
                    return 0;
                };
                self.next = next;
                u32::from(b)
            }
            None => {
                self.error = true;
                0
            }
        }
    }

    /// One bit, LSB-first.
    pub fn getbit(&mut self) -> u32 {
        if self.bc > 0 {
            self.bc -= 1;
        } else {
            self.sr = self.load_byte();
            self.bc = 7;
        }
        let bit = self.sr & 1;
        self.sr >>= 1;
        bit
    }

    /// Read `nbits` (1..=31) as an unsigned value, LSB-first: the reference
    /// `getbits` macro. The caller masks to the bits it wants, as in C.
    pub fn getbits(&mut self, nbits: u32) -> u32 {
        if nbits > 31 {
            self.error = true;
            return 0;
        }
        let mut local_sr = u64::from(self.sr);
        while self.bc < nbits {
            local_sr |= u64::from(self.load_byte()) << self.bc;
            self.bc += 8;
        }
        let value = u32::try_from(local_sr & u64::from(u32::MAX)).unwrap_or_default();
        self.bc -= nbits;
        self.sr = u32::try_from((local_sr >> nbits) & u64::from(u32::MAX)).unwrap_or_default();
        value
    }

    /// Read an unsigned code in `0..=maxcode`, the reference `read_code`:
    /// a fixed bit count when the range is a power of two, otherwise the
    /// minimum count with one conditional extra bit.
    pub fn read_code(&mut self, maxcode: u32) -> u32 {
        if maxcode < 2 {
            return if maxcode != 0 { self.getbit() } else { 0 };
        }
        let bitcount = 32 - maxcode.leading_zeros();
        if bitcount > 31 {
            self.error = true;
            return 0;
        }
        let extras = u32::try_from((1u64 << bitcount) - u64::from(maxcode) - 1).unwrap_or_default();

        // Accumulate into a wide register so bc may exceed 32 transiently,
        // matching the reference's 64-bit `local_sr` path.
        let mut local_sr = u64::from(self.sr);
        while self.bc < bitcount {
            local_sr |= u64::from(self.load_byte()) << self.bc;
            self.bc += 8;
        }

        let low = u32::try_from(local_sr & u64::from(u32::MAX)).unwrap_or_default();
        let mut code = low & ((1u32 << (bitcount - 1)) - 1);
        let used = if code >= extras {
            let next_bit = u32::try_from((local_sr >> (bitcount - 1)) & 1).unwrap_or_default();
            code = (code << 1).wrapping_sub(extras).wrapping_add(next_bit);
            bitcount
        } else {
            bitcount - 1
        };
        self.bc -= used;
        self.sr = u32::try_from((local_sr >> used) & u64::from(u32::MAX)).unwrap_or_default();
        code
    }

    /// Count leading one-bits (the unary prefix), consuming them and the
    /// terminating zero, up to the reference's escape structure. Returns the
    /// fully decoded `ones_count`, or `None` at end-of-stream (the all-ones
    /// terminator). Mirrors the portable variant in `read_words.c`.
    pub fn read_ones_count(&mut self, limit_ones: u32) -> Option<u32> {
        let mut ones_count = 0u32;
        let limit = limit_ones.checked_add(1)?;
        while ones_count < limit && self.getbit() != 0 {
            ones_count += 1;
        }
        if ones_count >= limit_ones {
            if ones_count == limit {
                return None;
            }
            // Escape: an Elias-gamma-style count follows.
            let decoded = self.read_egc_count()?;
            ones_count = decoded.checked_add(limit_ones)?;
        }
        Some(ones_count)
    }

    /// The shared escape encoding: a unary bit-length (up to 33), then that
    /// many minus one literal low bits with an implicit top bit. Used for both
    /// long ones-runs and zero-run lengths.
    pub fn read_egc_count(&mut self) -> Option<u32> {
        let mut cbits = 0u32;
        while cbits < 33 && self.getbit() != 0 {
            cbits += 1;
        }
        if cbits == 33 {
            return None;
        }
        if cbits < 2 {
            return Some(cbits);
        }
        let mut mask = 1u32;
        let mut value = 0u32;
        let mut remaining = cbits;
        loop {
            remaining -= 1;
            if remaining == 0 {
                break;
            }
            if self.getbit() != 0 {
                value |= mask;
            }
            mask <<= 1;
        }
        Some(value | mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_come_lsb_first() {
        // 0b1010_0110 -> bits 0,1,1,0,0,1,0,1
        let mut r = BitReader::new(&[0b1010_0110]);
        let bits: Vec<u32> = (0..8).map(|_| r.getbit()).collect();
        assert_eq!(bits, [0, 1, 1, 0, 0, 1, 0, 1]);
        assert!(!r.errored());
        r.getbit();
        assert!(r.errored());
    }

    #[test]
    fn read_code_powers_of_two_are_fixed_width() {
        // maxcode = 3: always 2 bits. Bits stream LSB-first from the byte,
        // but within one code the first-read bit is the HIGH bit (the
        // reference's (code << 1) | next_bit reconstruction), so byte
        // 0b1110_0100 (bit sequence 0,0,1,0,0,1,1,1) decodes 0,2,1,3.
        let mut r = BitReader::new(&[0b1110_0100]);
        assert_eq!(r.read_code(3), 0);
        assert_eq!(r.read_code(3), 2);
        assert_eq!(r.read_code(3), 1);
        assert_eq!(r.read_code(3), 3);
    }
}
