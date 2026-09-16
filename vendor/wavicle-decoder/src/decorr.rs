//! Inverse decorrelation: metadata parsing and the mono/stereo passes.
//!
//! Portions derived from WavPack (dbry/WavPack, `decorr_utils.c`, `unpack.c`,
//! and the weight macros in `wavpack_local.h`), Copyright (c) David Bryant /
//! Conifer Software, BSD-3-Clause; see ATTRIBUTION.md.
//!
//! Terms, weights, and sample history arrive in metadata sub-blocks stored in
//! the *opposite* order from the pass array (last pass first), and every
//! arithmetic step below must match the reference bit-for-bit: the weight
//! application rounding, the sign-trick weight updates, and the +/-1024 clip
//! used by the cross-channel terms.

#[cfg(feature = "decode")]
use crate::entropy::wp_exp2s;
use crate::error::Error;

pub const MAX_TERM: usize = 8;
const MAX_TERM_I32: i32 = 8;
const MAX_NTERMS: usize = 16;

#[derive(Clone, Debug, Default)]
pub struct DecorrPass {
    pub term: i32,
    pub delta: i32,
    pub weight_a: i32,
    pub weight_b: i32,
    pub samples_a: [i32; MAX_TERM],
    pub samples_b: [i32; MAX_TERM],
}

/// Parse `ID_DECORR_TERMS`. `passes[0]` receives the *last* stored byte.
#[cfg(feature = "decode")]
pub fn read_decorr_terms(data: &[u8], mono: bool) -> Result<Vec<DecorrPass>, Error> {
    if data.len() > MAX_NTERMS {
        return Err(Error::BadSubBlock { id: 0x02 });
    }
    let mut passes = Vec::new();
    passes
        .try_reserve_exact(data.len())
        .map_err(|_| Error::AllocationFailed {
            elements: data.len(),
        })?;
    passes.resize(data.len(), DecorrPass::default());
    for (i, &byte) in data.iter().enumerate() {
        let index = data
            .len()
            .checked_sub(i)
            .and_then(|value| value.checked_sub(1))
            .ok_or(Error::BadSubBlock { id: 0x02 })?;
        let pass = passes
            .get_mut(index)
            .ok_or(Error::BadSubBlock { id: 0x02 })?;
        pass.term = i32::from(byte & 0x1f) - 5;
        pass.delta = i32::from((byte >> 5) & 0x7);
        let term = pass.term;
        let valid = term != 0
            && term >= -3
            && !(term > MAX_TERM_I32 && term < 17)
            && term <= 18
            && !(mono && term < 0);
        if !valid {
            return Err(Error::BadSubBlock { id: 0x02 });
        }
    }
    Ok(passes)
}

/// `restore_weight` from `entropy_utils.c`.
#[cfg(feature = "decode")]
fn restore_weight(weight: i8) -> i32 {
    let mut result = i32::from(weight) * 8;
    if result > 0 {
        result += (result + 64) >> 7;
    }
    result
}

/// Parse `ID_DECORR_WEIGHTS`: stored from the last pass backward.
#[cfg(feature = "decode")]
pub fn read_decorr_weights(
    data: &[u8],
    passes: &mut [DecorrPass],
    mono: bool,
) -> Result<(), Error> {
    let termcnt = if mono { data.len() } else { data.len() / 2 };
    if termcnt > passes.len() {
        return Err(Error::BadSubBlock { id: 0x03 });
    }
    let mut bytes = data.iter();
    for pass in passes.iter_mut().rev().take(termcnt) {
        let weight_a = bytes
            .next()
            .copied()
            .ok_or(Error::BadSubBlock { id: 0x03 })?;
        pass.weight_a = restore_weight(i8::from_ne_bytes([weight_a]));
        if !mono {
            let weight_b = bytes
                .next()
                .copied()
                .ok_or(Error::BadSubBlock { id: 0x03 })?;
            pass.weight_b = restore_weight(i8::from_ne_bytes([weight_b]));
        }
    }
    Ok(())
}

/// Parse `ID_DECORR_SAMPLES`: history from the last pass backward, layout
/// depending on each pass's term.
#[cfg(feature = "decode")]
pub fn read_decorr_samples(
    data: &[u8],
    passes: &mut [DecorrPass],
    mono: bool,
) -> Result<(), Error> {
    fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], Error> {
        let end = pos.checked_add(n).ok_or(Error::BadSubBlock { id: 0x04 })?;
        let s = data.get(*pos..end).ok_or(Error::BadSubBlock { id: 0x04 })?;
        *pos = end;
        Ok(s)
    }
    fn exp(b: &[u8], offset: usize) -> Result<i32, Error> {
        let end = offset
            .checked_add(2)
            .ok_or(Error::BadSubBlock { id: 0x04 })?;
        let pair = b
            .get(offset..end)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or(Error::BadSubBlock { id: 0x04 })?;
        Ok(wp_exp2s(i32::from(i16::from_le_bytes(pair))))
    }

    let mut pos = 0usize;
    for pass in passes.iter_mut().rev() {
        if pos >= data.len() {
            break;
        }
        if pass.term > MAX_TERM_I32 {
            let b = take(data, &mut pos, if mono { 4 } else { 8 })?;
            pass.samples_a[0] = exp(b, 0)?;
            pass.samples_a[1] = exp(b, 2)?;
            if !mono {
                pass.samples_b[0] = exp(b, 4)?;
                pass.samples_b[1] = exp(b, 6)?;
            }
        } else if pass.term < 0 {
            let b = take(data, &mut pos, 4)?;
            pass.samples_a[0] = exp(b, 0)?;
            pass.samples_b[0] = exp(b, 2)?;
        } else {
            let term = usize::try_from(pass.term).map_err(|_| Error::BadSubBlock { id: 0x04 })?;
            for m in 0..term {
                let b = take(data, &mut pos, if mono { 2 } else { 4 })?;
                let sample_a = pass
                    .samples_a
                    .get_mut(m)
                    .ok_or(Error::BadSubBlock { id: 0x04 })?;
                *sample_a = exp(b, 0)?;
                if !mono {
                    let sample_b = pass
                        .samples_b
                        .get_mut(m)
                        .ok_or(Error::BadSubBlock { id: 0x04 })?;
                    *sample_b = exp(b, 2)?;
                }
            }
        }
    }
    if pos != data.len() {
        return Err(Error::BadSubBlock { id: 0x04 });
    }
    Ok(())
}

/// `apply_weight`: the reference's dual path, chosen per sample magnitude.
#[inline]
fn apply_weight(weight: i32, sample: i32) -> i32 {
    if i16::try_from(sample).is_err() {
        // apply_weight_f: split multiply to survive 32-bit overflow.
        ((((sample & 0xffff).wrapping_mul(weight)) >> 9)
            .wrapping_add(((sample & !0xffff) >> 9).wrapping_mul(weight))
            .wrapping_add(1))
            >> 1
    } else {
        // apply_weight_i
        (weight.wrapping_mul(sample).wrapping_add(512)) >> 10
    }
}

/// `update_weight`: nudge by delta toward agreement of signs.
#[inline]
fn update_weight(weight: &mut i32, delta: i32, source: i32, result: i32) {
    if source != 0 && result != 0 {
        let s = (source ^ result) >> 31;
        *weight = (delta ^ s).wrapping_add(weight.wrapping_sub(s));
    }
}

/// `update_weight_clip`: as above but clipped to +/-1024 (cross-channel terms).
#[inline]
#[cfg(feature = "decode")]
fn update_weight_clip(weight: &mut i32, delta: i32, source: i32, result: i32) {
    if source != 0 && result != 0 {
        let s = (source ^ result) >> 31;
        let mut w = (*weight ^ s).wrapping_add(delta - s);
        if w > 1024 {
            w = 1024;
        }
        *weight = (w ^ s) - s;
    }
}

/// One inverse pass over a mono buffer (`decorr_mono_pass`).
#[cfg(feature = "decode")]
pub fn decorr_mono_pass(dpp: &mut DecorrPass, buffer: &mut [i32]) -> Result<(), Error> {
    let delta = dpp.delta;
    let mut weight = dpp.weight_a;

    match dpp.term {
        17 => {
            for s in buffer.iter_mut() {
                let sam = 2i32
                    .wrapping_mul(dpp.samples_a[0])
                    .wrapping_sub(dpp.samples_a[1]);
                dpp.samples_a[1] = dpp.samples_a[0];
                let out = apply_weight(weight, sam).wrapping_add(*s);
                update_weight(&mut weight, delta, sam, *s);
                dpp.samples_a[0] = out;
                *s = out;
            }
        }
        18 => {
            for s in buffer.iter_mut() {
                let sam = (3i32
                    .wrapping_mul(dpp.samples_a[0])
                    .wrapping_sub(dpp.samples_a[1]))
                    >> 1;
                dpp.samples_a[1] = dpp.samples_a[0];
                let out = apply_weight(weight, sam).wrapping_add(*s);
                update_weight(&mut weight, delta, sam, *s);
                dpp.samples_a[0] = out;
                *s = out;
            }
        }
        term @ 1..=8 => {
            let mut m = 0usize;
            let mut k = usize::try_from(term).map_err(|_| Error::BadSubBlock { id: 0x02 })?
                & (MAX_TERM - 1);
            for s in buffer.iter_mut() {
                let sam = dpp
                    .samples_a
                    .get(m)
                    .copied()
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                let out = apply_weight(weight, sam).wrapping_add(*s);
                update_weight(&mut weight, delta, sam, *s);
                let history = dpp
                    .samples_a
                    .get_mut(k)
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                *history = out;
                *s = out;
                m = (m + 1) & (MAX_TERM - 1);
                k = (k + 1) & (MAX_TERM - 1);
            }
            if m != 0 {
                let temp = dpp.samples_a;
                for (k, slot) in dpp.samples_a.iter_mut().enumerate() {
                    let index = (m + k) & (MAX_TERM - 1);
                    *slot = temp
                        .get(index)
                        .copied()
                        .ok_or(Error::BadSubBlock { id: 0x02 })?;
                }
            }
        }
        _ => return Err(Error::BadSubBlock { id: 0x02 }),
    }
    dpp.weight_a = weight;
    Ok(())
}

/// One inverse pass over an interleaved stereo buffer (`decorr_stereo_pass`).
#[cfg(feature = "decode")]
pub fn decorr_stereo_pass(dpp: &mut DecorrPass, buffer: &mut [i32]) -> Result<(), Error> {
    let delta = dpp.delta;

    match dpp.term {
        17 => {
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam = 2i32
                    .wrapping_mul(dpp.samples_a[0])
                    .wrapping_sub(dpp.samples_a[1]);
                dpp.samples_a[1] = dpp.samples_a[0];
                let tmp = *left;
                let out = apply_weight(dpp.weight_a, sam).wrapping_add(tmp);
                dpp.samples_a[0] = out;
                *left = out;
                update_weight(&mut dpp.weight_a, delta, sam, tmp);

                let sam = 2i32
                    .wrapping_mul(dpp.samples_b[0])
                    .wrapping_sub(dpp.samples_b[1]);
                dpp.samples_b[1] = dpp.samples_b[0];
                let tmp = *right;
                let out = apply_weight(dpp.weight_b, sam).wrapping_add(tmp);
                dpp.samples_b[0] = out;
                *right = out;
                update_weight(&mut dpp.weight_b, delta, sam, tmp);
            }
        }
        18 => {
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam = dpp.samples_a[0]
                    .wrapping_add(dpp.samples_a[0].wrapping_sub(dpp.samples_a[1]) >> 1);
                dpp.samples_a[1] = dpp.samples_a[0];
                let tmp = *left;
                let out = apply_weight(dpp.weight_a, sam).wrapping_add(tmp);
                dpp.samples_a[0] = out;
                *left = out;
                update_weight(&mut dpp.weight_a, delta, sam, tmp);

                let sam = dpp.samples_b[0]
                    .wrapping_add(dpp.samples_b[0].wrapping_sub(dpp.samples_b[1]) >> 1);
                dpp.samples_b[1] = dpp.samples_b[0];
                let tmp = *right;
                let out = apply_weight(dpp.weight_b, sam).wrapping_add(tmp);
                dpp.samples_b[0] = out;
                *right = out;
                update_weight(&mut dpp.weight_b, delta, sam, tmp);
            }
        }
        term @ 1..=8 => {
            let mut m = 0usize;
            let mut k = usize::try_from(term).map_err(|_| Error::BadSubBlock { id: 0x02 })?
                & (MAX_TERM - 1);
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam = dpp
                    .samples_a
                    .get(m)
                    .copied()
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                let out = apply_weight(dpp.weight_a, sam).wrapping_add(*left);
                update_weight(&mut dpp.weight_a, delta, sam, *left);
                let history_a = dpp
                    .samples_a
                    .get_mut(k)
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                *history_a = out;
                *left = out;

                let sam = dpp
                    .samples_b
                    .get(m)
                    .copied()
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                let out = apply_weight(dpp.weight_b, sam).wrapping_add(*right);
                update_weight(&mut dpp.weight_b, delta, sam, *right);
                let history_b = dpp
                    .samples_b
                    .get_mut(k)
                    .ok_or(Error::BadSubBlock { id: 0x02 })?;
                *history_b = out;
                *right = out;

                m = (m + 1) & (MAX_TERM - 1);
                k = (k + 1) & (MAX_TERM - 1);
            }
        }
        -1 => {
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam = left.wrapping_add(apply_weight(dpp.weight_a, dpp.samples_a[0]));
                update_weight_clip(&mut dpp.weight_a, delta, dpp.samples_a[0], *left);
                *left = sam;
                let out = right.wrapping_add(apply_weight(dpp.weight_b, sam));
                update_weight_clip(&mut dpp.weight_b, delta, sam, *right);
                dpp.samples_a[0] = out;
                *right = out;
            }
        }
        -2 => {
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam = right.wrapping_add(apply_weight(dpp.weight_b, dpp.samples_b[0]));
                update_weight_clip(&mut dpp.weight_b, delta, dpp.samples_b[0], *right);
                *right = sam;
                let out = left.wrapping_add(apply_weight(dpp.weight_a, sam));
                update_weight_clip(&mut dpp.weight_a, delta, sam, *left);
                dpp.samples_b[0] = out;
                *left = out;
            }
        }
        -3 => {
            for f in buffer.chunks_exact_mut(2) {
                let [left, right] = f else {
                    return Err(Error::BadSubBlock { id: 0x02 });
                };
                let sam_a = left.wrapping_add(apply_weight(dpp.weight_a, dpp.samples_a[0]));
                update_weight_clip(&mut dpp.weight_a, delta, dpp.samples_a[0], *left);
                let sam_b = right.wrapping_add(apply_weight(dpp.weight_b, dpp.samples_b[0]));
                update_weight_clip(&mut dpp.weight_b, delta, dpp.samples_b[0], *right);
                *left = sam_a;
                dpp.samples_b[0] = sam_a;
                *right = sam_b;
                dpp.samples_a[0] = sam_b;
            }
        }
        _ => return Err(Error::BadSubBlock { id: 0x02 }),
    }
    Ok(())
}
