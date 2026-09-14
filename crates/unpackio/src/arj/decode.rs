//! Bounded ARJ methods 0 through 4.
//!
//! Methods 1--3 use `delharc` 0.6.2's static LH6 decoder through the audited
//! boundary recorded in `DEPENDENCIES.md` and `PROVENANCE.md`. Method 4 is a
//! checked safe-Rust adaptation of the ARJ "fastest" bit grammar documented
//! there. The project code in this module is MIT licensed; adapted
//! method-4 portions also retain their recorded Apache-2.0 provenance.

use std::panic::{AssertUnwindSafe, catch_unwind};

use delharc::{
    CompressionMethod as LhaCompressionMethod,
    decode::{Decoder, DecoderAny},
};

use super::ArjCompressionMethod;
use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, try_reserve, u64_to_usize, usize_to_u64,
    },
};

// delharc's LH6/LH7 decoder allocates a 64-KiB ring plus two fixed-capacity
// Huffman tables (1,060 two-byte nodes). Round that complete decoder state up
// before its constructor can allocate anything.
const STATIC_LZH_DECODER_BYTES: u64 = 68 * 1024;
const FASTEST_DICTIONARY_BYTES: u64 = 8 * 1024;

pub(super) fn decode(
    compressed: &[u8],
    method: ArjCompressionMethod,
    original_size: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        original_size,
        limits.max_entry_output_bytes(),
        LimitKind::EntryOutputBytes,
    )?;
    match method {
        ArjCompressionMethod::Stored => decode_stored(compressed, original_size, control),
        ArjCompressionMethod::CompressedMost
        | ArjCompressionMethod::Compressed
        | ArjCompressionMethod::CompressedFaster => {
            decode_static_lzh(compressed, original_size, limits, control)
        }
        ArjCompressionMethod::CompressedFastest => {
            decode_fastest(compressed, original_size, limits, control)
        }
        ArjCompressionMethod::NoDataNoCrc | ArjCompressionMethod::NoData => {
            if compressed.is_empty() && original_size == 0 {
                control.checkpoint(0)?;
                Ok(Vec::new())
            } else {
                Err(arj_format("no-data method declares member bytes"))
            }
        }
        ArjCompressionMethod::Unknown(identifier) => Err(Error::UnsupportedMethod {
            method_id: Box::from([identifier]),
        }),
    }
}

fn decode_stored(
    compressed: &[u8],
    original_size: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let compressed_size = usize_to_u64(compressed.len(), "ARJ stored size is not representable")?;
    if compressed_size != original_size {
        return Err(arj_format("stored size does not match original size"));
    }
    let mut output = Vec::new();
    try_reserve(&mut output, compressed.len())?;
    for chunk in compressed.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(
            usize_to_u64(chunk.len(), "ARJ stored chunk length is not representable")?
                .checked_mul(2)
                .ok_or_else(|| arj_format("stored work accounting overflows"))?,
        )?;
        output.extend_from_slice(chunk);
    }
    Ok(output)
}

fn decode_static_lzh(
    compressed: &[u8],
    original_size: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        STATIC_LZH_DECODER_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    control.consume_bytes(compressed)?;
    let output_size = u64_to_usize(
        original_size,
        "ARJ original size is not representable on this platform",
    )?;
    let mut output = Vec::new();
    try_reserve(&mut output, output_size)?;
    output.resize(output_size, 0);
    let mut decoder = catch_unwind(AssertUnwindSafe(|| {
        DecoderAny::new_from_compression(LhaCompressionMethod::Lh6, compressed)
    }))
    .map_err(|_| arj_format("static LZH decoder rejected the stream"))?;
    for chunk in output.chunks_mut(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "ARJ decoded chunk length is not representable",
        )?)?;
        let decoded = catch_unwind(AssertUnwindSafe(|| decoder.fill_buffer(chunk)))
            .map_err(|_| arj_format("static LZH decoder panicked on malformed input"))?;
        decoded.map_err(|_| arj_format("static LZH stream is invalid or truncated"))?;
    }
    Ok(output)
}

fn decode_fastest(
    compressed: &[u8],
    original_size: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        FASTEST_DICTIONARY_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    control.consume_bytes(compressed)?;
    let output_size = u64_to_usize(
        original_size,
        "ARJ original size is not representable on this platform",
    )?;
    let mut output = Vec::new();
    try_reserve(&mut output, output_size)?;
    let mut bits = MsbBits::new(compressed);
    while output.len() < output_size {
        control.checkpoint(1)?;
        let length_code = decode_variable(&mut bits, 0, 7)?;
        if length_code == 0 {
            let literal = u8::try_from(bits.read(8)?)
                .map_err(|_| arj_format("literal is not representable"))?;
            output.push(literal);
            continue;
        }
        let repeat = usize::from(length_code)
            .checked_add(2)
            .ok_or_else(|| arj_format("match length overflows"))?;
        let remaining = output_size
            .checked_sub(output.len())
            .ok_or_else(|| arj_format("decoded output length underflows"))?;
        if repeat > remaining {
            return Err(arj_format("match exceeds the declared output size"));
        }
        let back_pointer = usize::from(decode_variable(&mut bits, 9, 13)?);
        let distance = back_pointer
            .checked_add(1)
            .ok_or_else(|| arj_format("match distance overflows"))?;
        if distance > output.len() {
            return Err(arj_format("match points before the decoded output"));
        }
        for _ in 0..repeat {
            control.checkpoint(1)?;
            let source = output
                .len()
                .checked_sub(distance)
                .ok_or_else(|| arj_format("match source underflows"))?;
            let byte = output
                .get(source)
                .copied()
                .ok_or_else(|| arj_format("match source is out of range"))?;
            output.push(byte);
        }
    }
    Ok(output)
}

fn decode_variable(bits: &mut MsbBits<'_>, from: u8, to: u8) -> Result<u16> {
    let mut additional = 0_u16;
    let mut exponent = 1_u16
        .checked_shl(u32::from(from))
        .ok_or_else(|| arj_format("variable-code exponent overflows"))?;
    let mut width = from;
    while width < to {
        if bits.read(1)? == 0 {
            break;
        }
        additional = additional
            .checked_add(exponent)
            .ok_or_else(|| arj_format("variable-code prefix overflows"))?;
        exponent = exponent
            .checked_mul(2)
            .ok_or_else(|| arj_format("variable-code exponent overflows"))?;
        width = width
            .checked_add(1)
            .ok_or_else(|| arj_format("variable-code width overflows"))?;
    }
    let suffix = if width == 0 { 0 } else { bits.read(width)? };
    suffix
        .checked_add(additional)
        .ok_or_else(|| arj_format("variable-code value overflows"))
}

struct MsbBits<'data> {
    bytes: &'data [u8],
    byte_offset: usize,
    bit_offset: u8,
}

impl<'data> MsbBits<'data> {
    const fn new(bytes: &'data [u8]) -> Self {
        Self {
            bytes,
            byte_offset: 0,
            bit_offset: 0,
        }
    }

    fn read(&mut self, count: u8) -> Result<u16> {
        if count > 16 {
            return Err(arj_format("bit read is too wide"));
        }
        let mut value = 0_u16;
        let mut remaining = count;
        while remaining > 0 {
            let byte = self
                .bytes
                .get(self.byte_offset)
                .copied()
                .ok_or_else(|| arj_format("compressed bitstream is truncated"))?;
            let shift = 7_u8
                .checked_sub(self.bit_offset)
                .ok_or_else(|| arj_format("bit offset underflows"))?;
            let bit = u16::from((byte >> shift) & 1);
            value = value
                .checked_mul(2)
                .and_then(|current| current.checked_add(bit))
                .ok_or_else(|| arj_format("bit value overflows"))?;
            self.bit_offset = self
                .bit_offset
                .checked_add(1)
                .ok_or_else(|| arj_format("bit offset overflows"))?;
            if self.bit_offset == 8 {
                self.bit_offset = 0;
                self.byte_offset = self
                    .byte_offset
                    .checked_add(1)
                    .ok_or_else(|| arj_format("byte offset overflows"))?;
            }
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| arj_format("bit count underflows"))?;
        }
        Ok(value)
    }
}

fn arj_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ARJ: {detail}"),
    }
}
