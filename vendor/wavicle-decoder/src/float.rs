//! 32-bit IEEE float reconstruction (decode half).
//!
//! Portions derived from WavPack (dbry/WavPack, `unpack_floats.c` and the f32
//! accessor macros in `wavpack_local.h`), Copyright (c) David Bryant / Conifer
//! Software, BSD-3-Clause; see ATTRIBUTION.md.
//!
//! No floating-point math runs here. The decorrelated integers are aligned
//! mantissas; this module rebuilds the exact 32-bit IEEE-754 pattern (sign,
//! 8-bit exponent, 23-bit mantissa) using integer ops only, restoring the
//! residual low bits from the `wvx` stream and preserving signed zero,
//! denormals, infinities, and NaN payloads bit-for-bit. The decoded buffer
//! then holds those bit patterns as `i32`, which a consumer reads with
//! `f32::from_bits`.

#[cfg(feature = "decode")]
use crate::bitstream::BitReader;
#[cfg(feature = "decode")]
use crate::error::Error;

fn i32_bits(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

fn u32_bits(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}

pub const FLOAT_SHIFT_ONES: u8 = 1;
pub const FLOAT_SHIFT_SAME: u8 = 2;
pub const FLOAT_SHIFT_SENT: u8 = 4;
pub const FLOAT_ZEROS_SENT: u8 = 8;
pub const FLOAT_NEG_ZEROS: u8 = 0x10;
#[allow(dead_code)]
pub const FLOAT_EXCEPTIONS: u8 = 0x20;

/// The `ID_FLOAT_INFO` payload (4 bytes).
#[derive(Clone, Copy, Debug)]
pub struct FloatInfo {
    pub flags: u8,
    pub shift: u8,
    pub max_exp: u8,
    /// Only used by host-side normalization, which wavicle does not apply.
    pub norm_exp: u8,
}

impl FloatInfo {
    #[cfg(feature = "decode")]
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let b: [u8; 4] = data
            .try_into()
            .map_err(|_| Error::BadSubBlock { id: 0x08 })?;
        Ok(Self {
            flags: b[0],
            shift: b[1],
            max_exp: b[2],
            norm_exp: b[3],
        })
    }
}

// The read-side f32 field accessors.
#[inline]
fn get_mantissa(f: u32) -> u32 {
    f & 0x7fffff
}
#[inline]
fn get_exponent(f: u32) -> u32 {
    (f >> 23) & 0xff
}
#[inline]
fn get_sign(f: u32) -> u32 {
    (f >> 31) & 1
}
// The f32-as-i32 field write accessors (decode reconstruction).
#[cfg(feature = "decode")]
#[inline]
fn set_mantissa(f: &mut u32, v: u32) {
    *f = (*f & !0x7fffff) | (v & 0x7fffff);
}
#[cfg(feature = "decode")]
#[inline]
fn set_exponent(f: &mut u32, v: u32) {
    *f = (*f & !0x7f80_0000) | ((v << 23) & 0x7f80_0000);
}
#[cfg(feature = "decode")]
#[inline]
fn set_sign(f: &mut u32, v: u32) {
    *f = (*f & !0x8000_0000) | ((v << 31) & 0x8000_0000);
}

/// The lossless `float_values`: reconstruct exact IEEE bits, restoring residual
/// bits from `xbits`. `min_shifted_zeros`/`max_shifted_ones` come from the wvx
/// "new"-format prefix (0 for classic wvx). Returns the updated `crc_x`.
#[cfg(feature = "decode")]
#[allow(clippy::too_many_arguments)]
pub fn float_values(
    values: &mut [i32],
    info: FloatInfo,
    min_shifted_zeros: u32,
    max_shifted_ones: u32,
    xbits: &mut BitReader<'_>,
    mut crc: u32,
) -> u32 {
    let shift = u32::from(info.shift) & 0x1f;
    let flags = info.flags;

    for value in values.iter_mut() {
        let mut exp = i32::from(info.max_exp);
        let mut outval: u32 = 0;

        if *value == 0 {
            if flags & FLOAT_ZEROS_SENT != 0 {
                if xbits.getbit() != 0 {
                    set_mantissa(&mut outval, xbits.getbits(23));
                    if exp >= 25 {
                        set_exponent(&mut outval, xbits.getbits(8));
                    }
                    set_sign(&mut outval, xbits.getbit());
                } else if flags & FLOAT_NEG_ZEROS != 0 {
                    set_sign(&mut outval, xbits.getbit());
                }
            }
        } else {
            let mut v = i32_bits(*value) << shift;
            if u32_bits(v) < 0 {
                v = i32_bits(u32_bits(v).wrapping_neg());
                set_sign(&mut outval, 1);
            }

            if v == 0x1000000 {
                if xbits.getbit() != 0 {
                    set_mantissa(&mut outval, xbits.getbits(23));
                }
                set_exponent(&mut outval, 255);
            } else {
                let mut shift_count = 0i32;
                if exp != 0 {
                    loop {
                        if v & 0x800000 != 0 {
                            break;
                        }
                        exp -= 1;
                        if exp == 0 {
                            break;
                        }
                        shift_count += 1;
                        v <<= 1;
                    }
                }
                shift_count &= 0x1f;
                if shift_count != 0 {
                    let sc = u32::try_from(shift_count).unwrap_or_default();
                    if flags & FLOAT_SHIFT_ONES != 0
                        || (flags & FLOAT_SHIFT_SAME != 0 && xbits.getbit() != 0)
                    {
                        v |= (1u32 << sc) - 1;
                    } else if flags & FLOAT_SHIFT_SENT != 0 {
                        let mask = (1u32 << sc) - 1;
                        let mut num_zeros = 0u32;
                        if max_shifted_ones != 0 && sc > max_shifted_ones {
                            num_zeros = sc - max_shifted_ones;
                        }
                        if min_shifted_zeros > num_zeros {
                            num_zeros = if min_shifted_zeros > sc {
                                sc
                            } else {
                                min_shifted_zeros
                            };
                        }
                        if sc > num_zeros {
                            let n = sc - num_zeros;
                            let temp = xbits.getbits(n);
                            v |= (temp << num_zeros) & mask;
                        }
                    }
                }
                set_mantissa(&mut outval, v);
                set_exponent(&mut outval, u32::try_from(exp).unwrap_or_default());
            }
        }

        crc = crc
            .wrapping_mul(27)
            .wrapping_add(get_mantissa(outval).wrapping_mul(9))
            .wrapping_add(get_exponent(outval).wrapping_mul(3))
            .wrapping_add(get_sign(outval));
        *value = u32_bits(outval);
    }

    crc
}

/// `float_values_nowvx`: the reconstruction used when no `wvx` stream is
/// present. Lossless only when the encoder determined no residual was needed.
#[cfg(feature = "decode")]
pub fn float_values_nowvx(values: &mut [i32], info: FloatInfo) {
    let shift = u32::from(info.shift) & 0x1f;
    let flags = info.flags;

    for value in values.iter_mut() {
        let mut exp = i32::from(info.max_exp);
        let mut outval: u32 = 0;

        if *value != 0 {
            let mut v = i32_bits(*value) << shift;
            if u32_bits(v) < 0 {
                v = i32_bits(u32_bits(v).wrapping_neg());
                set_sign(&mut outval, 1);
            }

            if v >= 0x1000000 {
                while v & 0xf000000 != 0 {
                    v >>= 1;
                    exp += 1;
                }
            } else if exp != 0 {
                let mut shift_count = 0i32;
                loop {
                    if v & 0x800000 != 0 {
                        break;
                    }
                    exp -= 1;
                    if exp == 0 {
                        break;
                    }
                    shift_count += 1;
                    v <<= 1;
                }
                shift_count &= 0x1f;
                if shift_count != 0 && flags & FLOAT_SHIFT_ONES != 0 {
                    v |= (1u32 << shift_count) - 1;
                }
            }

            set_mantissa(&mut outval, v);
            set_exponent(&mut outval, u32::try_from(exp).unwrap_or_default());
        }

        *value = u32_bits(outval);
    }
}
