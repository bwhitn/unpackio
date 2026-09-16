//! The decode driver: whole-stream lossless decode to interleaved samples.
//!
//! Shaped after `unpack_samples` in the reference `unpack.c` (dbry/WavPack,
//! BSD-3-Clause; see ATTRIBUTION.md), narrowed to the lossless integer path
//! this milestone implements. One deliberate divergence: where the reference
//! silently mutes a block on CRC mismatch or over-magnitude samples, wavicle
//! returns a hard error, because a silently-zeroed block would change decoded
//! content (and any content-addressed identity over it) without a signal.

use crate::bitstream::BitReader;
use crate::block::Blocks;
use crate::decorr::{
    DecorrPass, decorr_mono_pass, decorr_stereo_pass, read_decorr_samples, read_decorr_terms,
    read_decorr_weights,
};
use crate::entropy::WordsDecoder;
use crate::error::Error;
use crate::float::{FloatInfo, float_values, float_values_nowvx};
use crate::format::{Flags, meta};

fn i32_bits(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

fn u32_bits(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}

fn split_wvx(payload: &[u8]) -> Result<(u32, &[u8]), Error> {
    if payload.len() <= 4 || payload.len() % 2 != 0 {
        return Err(Error::BadSubBlock {
            id: meta::WVX_BITSTREAM,
        });
    }
    let crc = payload
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::BadSubBlock {
            id: meta::WVX_BITSTREAM,
        })?;
    let bitstream = payload.get(4..).ok_or(Error::BadSubBlock {
        id: meta::WVX_BITSTREAM,
    })?;
    Ok((crc, bitstream))
}

/// A fully decoded stream: interleaved samples plus the facts needed to
/// interpret them.
#[derive(Clone, Debug)]
pub struct DecodedStream {
    /// Interleaved output samples (mono: one per frame; stereo: two).
    pub samples: Vec<i32>,
    pub channels: u32,
    pub sample_rate: u32,
    pub bits_per_sample: u32,
    pub is_float: bool,
}

/// Decode an entire `.wv` byte stream losslessly.
///
/// M1 scope: 16-bit integer PCM, mono or stereo (including false stereo and
/// joint stereo). Float and extended-integer streams parse but return
/// [`Error::NotYetImplemented`].
pub fn decode_stream(stream: &[u8]) -> Result<DecodedStream, Error> {
    let mut out: Option<DecodedStream> = None;

    for block in Blocks::new(stream) {
        let block = block?;
        let h = block.header;
        if h.block_samples == 0 {
            continue;
        }
        if h.flags.bytes_per_sample() == 1 {
            return Err(Error::NotYetImplemented("8-bit integer decode"));
        }

        let samples = decode_block(&block)?;
        let rate = match h.flags.sample_rate() {
            Some(r) => r,
            None => custom_sample_rate(&block)
                .ok_or(Error::MissingSubBlock("sample rate for non-standard index"))?,
        };

        match &mut out {
            None => {
                out = Some(DecodedStream {
                    samples,
                    channels: h.flags.output_channels(),
                    sample_rate: rate,
                    bits_per_sample: h.flags.bytes_per_sample() * 8,
                    is_float: h.flags.is_float(),
                })
            }
            Some(existing) => {
                existing
                    .samples
                    .try_reserve_exact(samples.len())
                    .map_err(|_| Error::AllocationFailed {
                        elements: samples.len(),
                    })?;
                existing.samples.extend_from_slice(&samples);
            }
        }
    }

    out.ok_or(Error::Truncated { need: 32, have: 0 })
}

/// The true sample rate from a block's `ID_SAMPLE_RATE` sub-block (3-byte LE),
/// used when the header rate index is the non-standard marker (0xF).
fn custom_sample_rate(block: &crate::block::Block<'_>) -> Option<u32> {
    for sub in block.sub_blocks().flatten() {
        if sub.id == meta::SAMPLE_RATE && sub.data.len() >= 3 {
            let [low, middle, high] = sub
                .data
                .get(..3)
                .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())?;
            return Some(u32::from(low) | (u32::from(middle) << 8) | (u32::from(high) << 16));
        }
    }
    None
}

/// Decode one audio block to its output samples (already un-joint-stereoed,
/// shifted, false-stereo-expanded, and CRC-checked).
fn decode_block(block: &crate::block::Block<'_>) -> Result<Vec<i32>, Error> {
    let h = &block.header;
    let flags = h.flags;
    // MONO_DATA in the reference: the stored stream is one channel either
    // because the file is mono or because identical channels collapsed.
    let mono_data = flags.mono_stored() || flags.0 & Flags::FALSE_STEREO != 0;

    let mut passes: Option<Vec<DecorrPass>> = None;
    let mut words: Option<WordsDecoder> = None;
    let mut wv_payload: Option<&[u8]> = None;
    let mut int32_info: Option<[u8; 4]> = None;
    let mut float_info: Option<FloatInfo> = None;
    let mut wvx: Option<(&[u8], bool)> = None; // (payload incl. crc, new format)

    for sub in block.sub_blocks() {
        let sub = sub?;
        crate::metadata::check_scope(sub)?;
        match sub.id {
            meta::DECORR_TERMS => passes = Some(read_decorr_terms(sub.data, mono_data)?),
            meta::DECORR_WEIGHTS => {
                let p = passes
                    .as_mut()
                    .ok_or(Error::MissingSubBlock("decorr terms before weights"))?;
                read_decorr_weights(sub.data, p, mono_data)?;
            }
            meta::DECORR_SAMPLES => {
                let p = passes
                    .as_mut()
                    .ok_or(Error::MissingSubBlock("decorr terms before samples"))?;
                read_decorr_samples(sub.data, p, mono_data)?;
            }
            meta::ENTROPY_VARS => {
                words = Some(WordsDecoder::from_entropy_vars(sub.data, mono_data)?)
            }
            meta::WV_BITSTREAM => wv_payload = Some(sub.data),
            meta::INT32_INFO => {
                let b: [u8; 4] = sub
                    .data
                    .try_into()
                    .map_err(|_| Error::BadSubBlock { id: sub.id })?;
                int32_info = Some(b);
            }
            meta::FLOAT_INFO => float_info = Some(FloatInfo::parse(sub.data)?),
            meta::WVX_BITSTREAM => wvx = Some((sub.data, false)),
            meta::WVX_NEW_BITSTREAM => wvx = Some((sub.data, true)),
            _ => {}
        }
    }

    let mut passes = passes.ok_or(Error::MissingSubBlock("decorr terms"))?;
    let mut words = words.ok_or(Error::MissingSubBlock("entropy vars"))?;
    let wv = wv_payload.ok_or(Error::MissingSubBlock("wv bitstream"))?;

    let frames =
        usize::try_from(h.block_samples).map_err(|_| Error::BadBlockSize(h.block_samples))?;
    let stored_len = if mono_data {
        frames
    } else {
        frames
            .checked_mul(2)
            .ok_or(Error::AllocationFailed { elements: frames })?
    };
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(stored_len)
        .map_err(|_| Error::AllocationFailed {
            elements: stored_len,
        })?;
    buffer.resize(stored_len, 0_i32);

    let mut bs = BitReader::new(wv);
    let produced = words.get_words_lossless(&mut bs, &mut buffer, h.block_samples, mono_data);
    if produced != h.block_samples || bs.errored() {
        return Err(Error::Truncated {
            need: usize::try_from(h.block_samples)
                .map_err(|_| Error::BadBlockSize(h.block_samples))?,
            have: usize::try_from(produced).map_err(|_| Error::BadBlockSize(produced))?,
        });
    }

    if mono_data {
        for pass in passes.iter_mut() {
            decorr_mono_pass(pass, &mut buffer)?;
        }
    } else {
        for pass in passes.iter_mut() {
            decorr_stereo_pass(pass, &mut buffer)?;
        }
    }

    // Joint-stereo un-mix and the block CRC, in the reference's one pass.
    let mut crc: u32 = 0xffffffff;
    let mute_limit = (1i64 << flags.magnitude()) + 2;
    if mono_data {
        for s in buffer.iter() {
            if i64::from(*s).abs() > mute_limit {
                return Err(Error::OverMagnitude);
            }
            crc = crc.wrapping_mul(3).wrapping_add(i32_bits(*s));
        }
    } else {
        let joint = flags.0 & Flags::JOINT_STEREO != 0;
        for f in buffer.chunks_exact_mut(2) {
            let [left, right] = f else {
                return Err(Error::BadBlockSize(h.block_samples));
            };
            if joint {
                *right = right.wrapping_sub(*left >> 1);
                *left = left.wrapping_add(*right);
            }
            crc = crc
                .wrapping_add(crc << 3)
                .wrapping_add(i32_bits(*left) << 1)
                .wrapping_add(i32_bits(*left))
                .wrapping_add(i32_bits(*right));
            if i64::from(*left).abs() > mute_limit || i64::from(*right).abs() > mute_limit {
                return Err(Error::OverMagnitude);
            }
        }
    }

    if crc != h.crc {
        return Err(Error::CrcMismatch {
            stored: h.crc,
            computed: crc,
        });
    }

    // Fixup, per the reference `fixup_samples`. Float takes its own path and
    // returns; otherwise extended-integer restoration then the final shift.
    if flags.is_float() {
        let info = float_info.ok_or(Error::MissingSubBlock("float info"))?;
        match wvx {
            Some((payload, is_new)) => {
                let (crc_wvx, bitstream) = split_wvx(payload)?;
                let mut xbits = BitReader::new(bitstream);
                let (min_zeros, max_ones) = if is_new {
                    (xbits.getbits(5) & 0x1f, xbits.getbits(5) & 0x1f)
                } else {
                    (0, 0)
                };
                let crc_x = float_values(
                    &mut buffer,
                    info,
                    min_zeros,
                    max_ones,
                    &mut xbits,
                    0xffffffff,
                );
                if xbits.errored() {
                    return Err(Error::Truncated { need: 1, have: 0 });
                }
                if crc_x != crc_wvx {
                    return Err(Error::CrcMismatch {
                        stored: crc_wvx,
                        computed: crc_x,
                    });
                }
            }
            None => float_values_nowvx(&mut buffer, info),
        }
        return finish_false_stereo(buffer, flags, frames);
    }

    let mut shift = flags.output_shift();

    if flags.0 & Flags::INT32_DATA != 0 {
        let info = int32_info.ok_or(Error::MissingSubBlock("int32 info"))?;
        let sent_bits = u32::from(info[0]) & 0x1f;
        let zeros = u32::from(info[1]) & 0x1f;
        let ones = u32::from(info[2]) & 0x1f;
        let dups = u32::from(info[3]) & 0x1f;

        if let Some((payload, is_new)) = wvx {
            // First four bytes are the stored CRC of the restored samples.
            let (crc_wvx, bitstream) = split_wvx(payload)?;
            let mut xbits = BitReader::new(bitstream);
            let max_width = if is_new { xbits.getbits(5) & 0x1f } else { 0 };

            let mask = (1u32 << sent_bits) - 1;
            let mut crc_x: u32 = 0xffffffff;
            for v in buffer.iter_mut() {
                if sent_bits != 0 {
                    if max_width != 0 {
                        let pvalue = i32_bits(if *v < 0 { !*v } else { *v });
                        let vbits = if pvalue == 0 {
                            0
                        } else {
                            32 - pvalue.leading_zeros()
                        };
                        let width = vbits + sent_bits;
                        let bits_to_read = if width <= max_width {
                            i32::try_from(sent_bits).map_err(|_| Error::BadSubBlock {
                                id: meta::INT32_INFO,
                            })?
                        } else {
                            i32::try_from(sent_bits)
                                .and_then(|sent| {
                                    i32::try_from(width - max_width).map(|excess| sent - excess)
                                })
                                .map_err(|_| Error::BadSubBlock {
                                    id: meta::INT32_INFO,
                                })?
                        };
                        if bits_to_read > 0 {
                            let n =
                                u32::try_from(bits_to_read).map_err(|_| Error::BadSubBlock {
                                    id: meta::INT32_INFO,
                                })?;
                            let data = xbits.getbits(n) & ((1u32 << n) - 1);
                            *v = u32_bits(((i32_bits(*v) << n) | data) << (sent_bits - n));
                        } else {
                            *v = u32_bits(i32_bits(*v) << sent_bits);
                        }
                    } else {
                        let data = xbits.getbits(sent_bits) & mask;
                        *v = u32_bits((i32_bits(*v) << sent_bits) | data);
                    }
                }
                if zeros != 0 {
                    *v = u32_bits(i32_bits(*v) << zeros);
                } else if ones != 0 {
                    *v = u32_bits(((i32_bits(*v).wrapping_add(1)) << ones).wrapping_sub(1));
                } else if dups != 0 {
                    let low = i32_bits(*v) & 1;
                    *v = u32_bits(((i32_bits(*v).wrapping_add(low)) << dups).wrapping_sub(low));
                }
                crc_x = crc_x
                    .wrapping_mul(9)
                    .wrapping_add((i32_bits(*v) & 0xffff).wrapping_mul(3))
                    .wrapping_add((i32_bits(*v) >> 16) & 0xffff);
            }
            if xbits.errored() {
                return Err(Error::Truncated { need: 1, have: 0 });
            }
            if crc_x != crc_wvx {
                return Err(Error::CrcMismatch {
                    stored: crc_wvx,
                    computed: crc_x,
                });
            }
        } else if sent_bits == 0 && (zeros + ones + dups) != 0 {
            for v in buffer.iter_mut() {
                if zeros != 0 {
                    *v = u32_bits(i32_bits(*v) << zeros);
                } else if ones != 0 {
                    *v = u32_bits(((i32_bits(*v).wrapping_add(1)) << ones).wrapping_sub(1));
                } else if dups != 0 {
                    let low = i32_bits(*v) & 1;
                    *v = u32_bits(((i32_bits(*v).wrapping_add(low)) << dups).wrapping_sub(low));
                }
            }
        } else {
            shift = shift.wrapping_add(
                zeros
                    .wrapping_add(sent_bits)
                    .wrapping_add(ones)
                    .wrapping_add(dups),
            );
        }
    }

    let shift = shift & 0x1f;
    if shift != 0 {
        for s in buffer.iter_mut() {
            *s = u32_bits(i32_bits(*s) << shift);
        }
    }

    finish_false_stereo(buffer, flags, frames)
}

/// FALSE_STEREO expands a mono-stored block to interleaved stereo output.
fn finish_false_stereo(buffer: Vec<i32>, flags: Flags, frames: usize) -> Result<Vec<i32>, Error> {
    if flags.0 & Flags::FALSE_STEREO == 0 {
        return Ok(buffer);
    }
    let expanded_len = frames
        .checked_mul(2)
        .ok_or(Error::AllocationFailed { elements: frames })?;
    let mut expanded = Vec::new();
    expanded
        .try_reserve_exact(expanded_len)
        .map_err(|_| Error::AllocationFailed {
            elements: expanded_len,
        })?;
    for s in &buffer {
        expanded.push(*s);
        expanded.push(*s);
    }
    Ok(expanded)
}
