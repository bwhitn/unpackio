//! Unix `compress` (`.Z`) header parsing and LZW decompression.
//!
//! The stream behavior is adapted from NetBSD `usr.bin/compress/zopen.c`,
//! revision `bd9f26305380f03b3821f55381448a82827d6749` (BSD-3-Clause).
//! The Rust data structures, checked arithmetic, resource controls, and writer
//! integration are original to this project. See `PROVENANCE.md` and
//! `LICENSE-NETBSD-ZOPEN-BSD-3-CLAUSE`.

use std::{
    io::{self, Write},
    mem::size_of,
};

use super::{
    ExtractionControl, UNIX_COMPRESS_MAGIC, UnixCompressStreamInfo, check_frame_count,
    stream_format_error,
};
use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{CONTROL_CHUNK_SIZE, check_limit, usize_to_u64},
};

const HEADER_BYTES: usize = 3;
const INITIAL_CODE_BITS: u8 = 9;
const CLEAR_CODE: u16 = 256;
const FIRST_BLOCK_CODE: u32 = 257;
const FIRST_PLAIN_CODE: u32 = 256;
const MINIMUM_CODE_BITS: u8 = 9;
const MAXIMUM_CODE_BITS: u8 = 16;
const BLOCK_MODE_FLAG: u8 = 0x80;
const RESERVED_FLAGS: u8 = 0x60;
const CODE_BITS_MASK: u8 = 0x1f;

#[derive(Clone, Copy)]
pub(super) struct UnixCompressLayout {
    maximum_code_bits: u8,
    block_mode: bool,
    dictionary_entries: usize,
    dictionary_bytes: u64,
}

impl UnixCompressLayout {
    pub(super) fn extract<W: Write>(
        &self,
        input: &[u8],
        control: &mut ExtractionControl<'_, W>,
    ) -> Result<()> {
        check_limit(
            self.dictionary_bytes,
            control.limits().max_dictionary_bytes(),
            LimitKind::DictionaryBytes,
        )?;
        control.checkpoint(self.dictionary_bytes)?;
        let payload = input.get(HEADER_BYTES..).ok_or_else(|| {
            stream_format_error("unix-compress", "validated payload range is unavailable")
        })?;
        for chunk in payload.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "Unix compress input chunk is not representable as u64",
            )?)?;
        }
        decode_lzw(
            payload,
            self.maximum_code_bits,
            self.block_mode,
            self.dictionary_entries,
            control,
        )?;
        control.finish_frame(false)
    }
}

pub(super) fn parse(
    input: &[u8],
    limits: Limits,
) -> Result<(UnixCompressStreamInfo, UnixCompressLayout)> {
    let header = input
        .get(..HEADER_BYTES)
        .ok_or_else(|| stream_format_error("unix-compress", "header is truncated"))?;
    if header.get(..UNIX_COMPRESS_MAGIC.len()) != Some(UNIX_COMPRESS_MAGIC) {
        return Err(stream_format_error("unix-compress", "magic does not match"));
    }
    check_frame_count(1, limits)?;
    let flags = header
        .get(2)
        .copied()
        .ok_or_else(|| stream_format_error("unix-compress", "flags byte is truncated"))?;
    if flags & RESERVED_FLAGS != 0 {
        return Err(stream_format_error(
            "unix-compress",
            "reserved header flags are set",
        ));
    }
    let maximum_code_bits = flags & CODE_BITS_MASK;
    if !(MINIMUM_CODE_BITS..=MAXIMUM_CODE_BITS).contains(&maximum_code_bits) {
        return Err(stream_format_error(
            "unix-compress",
            "maximum code width is outside 9 through 16 bits",
        ));
    }
    let dictionary_entries = 1_usize
        .checked_shl(u32::from(maximum_code_bits))
        .ok_or_else(|| stream_format_error("unix-compress", "dictionary size overflows"))?;
    let bytes_per_entry = size_of::<u16>()
        .checked_add(size_of::<u8>())
        .and_then(|bytes| bytes.checked_add(size_of::<u8>()))
        .ok_or_else(|| stream_format_error("unix-compress", "dictionary entry size overflows"))?;
    let dictionary_bytes = dictionary_entries
        .checked_mul(bytes_per_entry)
        .ok_or_else(|| stream_format_error("unix-compress", "dictionary byte size overflows"))?;
    let dictionary_bytes = u64::try_from(dictionary_bytes).map_err(|_| {
        stream_format_error(
            "unix-compress",
            "dictionary byte size is not representable as u64",
        )
    })?;
    check_limit(
        dictionary_bytes,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let block_mode = flags & BLOCK_MODE_FLAG != 0;
    let info = UnixCompressStreamInfo {
        maximum_code_bits,
        block_mode,
        dictionary_bytes,
    };
    Ok((
        info,
        UnixCompressLayout {
            maximum_code_bits,
            block_mode,
            dictionary_entries,
            dictionary_bytes,
        },
    ))
}

fn decode_lzw<W: Write>(
    input: &[u8],
    maximum_code_bits: u8,
    block_mode: bool,
    dictionary_entries: usize,
    control: &mut ExtractionControl<'_, W>,
) -> Result<()> {
    let mut prefixes = fallible_filled_vec(dictionary_entries, 0_u16)?;
    let mut suffixes = fallible_filled_vec(dictionary_entries, 0_u8)?;
    let mut expansion = fallible_filled_vec(dictionary_entries, 0_u8)?;
    expansion.clear();
    for literal in 0_u16..=u16::from(u8::MAX) {
        let index = usize::from(literal);
        let suffix = suffixes.get_mut(index).ok_or_else(|| {
            stream_format_error("unix-compress", "literal table index is unavailable")
        })?;
        *suffix = u8::try_from(literal).map_err(|_| {
            stream_format_error("unix-compress", "literal value is not representable")
        })?;
    }

    let maximum_codes = 1_u32
        .checked_shl(u32::from(maximum_code_bits))
        .ok_or_else(|| stream_format_error("unix-compress", "maximum code count overflows"))?;
    let mut code_bits = INITIAL_CODE_BITS;
    let mut maximum_current_code = maximum_code_for_width(code_bits, maximum_code_bits)?;
    let mut next_code = if block_mode {
        FIRST_BLOCK_CODE
    } else {
        FIRST_PLAIN_CODE
    };
    let mut previous_code: Option<u16> = None;
    let mut first_character = 0_u8;
    let mut reader = CodeReader::new(input);
    let mut force_refill = false;

    loop {
        control.checkpoint(1)?;
        if next_code > maximum_current_code && code_bits < maximum_code_bits {
            code_bits = code_bits
                .checked_add(1)
                .ok_or_else(|| stream_format_error("unix-compress", "code width overflows"))?;
            maximum_current_code = maximum_code_for_width(code_bits, maximum_code_bits)?;
            force_refill = true;
        }
        let Some(encoded_code) = reader.next_code(code_bits, force_refill)? else {
            break;
        };
        force_refill = false;
        if block_mode && encoded_code == CLEAR_CODE {
            code_bits = INITIAL_CODE_BITS;
            maximum_current_code = maximum_code_for_width(code_bits, maximum_code_bits)?;
            next_code = FIRST_BLOCK_CODE;
            previous_code = None;
            expansion.clear();
            force_refill = true;
            continue;
        }

        let encoded_code_u32 = u32::from(encoded_code);
        if previous_code.is_none() {
            if encoded_code_u32 > u32::from(u8::MAX) {
                return Err(stream_format_error(
                    "unix-compress",
                    "first code after reset is not a literal",
                ));
            }
            let literal = u8::try_from(encoded_code).map_err(|_| {
                stream_format_error("unix-compress", "literal code is not representable")
            })?;
            control.checkpoint(1)?;
            control.write_output(std::slice::from_ref(&literal))?;
            first_character = literal;
            previous_code = Some(encoded_code);
            continue;
        }

        expansion.clear();
        let mut code = encoded_code;
        if encoded_code_u32 == next_code {
            expansion.push(first_character);
            code = previous_code.ok_or_else(|| {
                stream_format_error("unix-compress", "previous code is unavailable")
            })?;
        } else if encoded_code_u32 > next_code {
            return Err(stream_format_error(
                "unix-compress",
                "code references an uninitialized dictionary entry",
            ));
        }

        let mut traversed = 0_usize;
        while u32::from(code) > u32::from(u8::MAX) {
            control.checkpoint(1)?;
            traversed = traversed.checked_add(1).ok_or_else(|| {
                stream_format_error("unix-compress", "dictionary traversal count overflows")
            })?;
            if traversed > dictionary_entries {
                return Err(stream_format_error(
                    "unix-compress",
                    "dictionary prefix chain contains a cycle",
                ));
            }
            let index = usize::from(code);
            if u32::from(code) >= next_code {
                return Err(stream_format_error(
                    "unix-compress",
                    "dictionary prefix references an unavailable code",
                ));
            }
            let suffix = suffixes.get(index).copied().ok_or_else(|| {
                stream_format_error("unix-compress", "dictionary suffix is unavailable")
            })?;
            expansion.push(suffix);
            code = prefixes.get(index).copied().ok_or_else(|| {
                stream_format_error("unix-compress", "dictionary prefix is unavailable")
            })?;
        }
        first_character = u8::try_from(code).map_err(|_| {
            stream_format_error("unix-compress", "expanded literal is not representable")
        })?;
        expansion.push(first_character);
        write_reversed(&mut expansion, control)?;

        if next_code < maximum_codes {
            let index = usize::try_from(next_code).map_err(|_| {
                stream_format_error("unix-compress", "next code is not representable")
            })?;
            let prefix = prefixes.get_mut(index).ok_or_else(|| {
                stream_format_error("unix-compress", "next dictionary prefix is unavailable")
            })?;
            *prefix = previous_code.ok_or_else(|| {
                stream_format_error("unix-compress", "previous code is unavailable")
            })?;
            let suffix = suffixes.get_mut(index).ok_or_else(|| {
                stream_format_error("unix-compress", "next dictionary suffix is unavailable")
            })?;
            *suffix = first_character;
            next_code = next_code.checked_add(1).ok_or_else(|| {
                stream_format_error("unix-compress", "next dictionary code overflows")
            })?;
        }
        previous_code = Some(encoded_code);
    }
    Ok(())
}

fn maximum_code_for_width(width: u8, maximum_width: u8) -> Result<u32> {
    let codes = 1_u32
        .checked_shl(u32::from(width))
        .ok_or_else(|| stream_format_error("unix-compress", "code-width shift overflows"))?;
    if width == maximum_width {
        Ok(codes)
    } else {
        codes
            .checked_sub(1)
            .ok_or_else(|| stream_format_error("unix-compress", "maximum code underflows"))
    }
}

fn fallible_filled_vec<T: Clone>(length: usize, value: T) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Unix compress dictionary allocation failed",
        ))
    })?;
    values.resize(length, value);
    Ok(values)
}

fn write_reversed<W: Write>(
    expansion: &mut Vec<u8>,
    control: &mut ExtractionControl<'_, W>,
) -> Result<()> {
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    while !expansion.is_empty() {
        let count = expansion.len().min(buffer.len());
        for destination in buffer.iter_mut().take(count) {
            *destination = expansion.pop().ok_or_else(|| {
                stream_format_error("unix-compress", "expansion stack ended unexpectedly")
            })?;
        }
        control.checkpoint(usize_to_u64(
            count,
            "Unix compress output chunk is not representable as u64",
        )?)?;
        let output = buffer.get(..count).ok_or_else(|| {
            stream_format_error("unix-compress", "output buffer range is invalid")
        })?;
        control.write_output(output)?;
    }
    Ok(())
}

struct CodeReader<'input> {
    input: &'input [u8],
    position: usize,
    group_start: usize,
    group_length: usize,
    bit_offset: usize,
    valid_bits: usize,
}

impl<'input> CodeReader<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self {
            input,
            position: 0,
            group_start: 0,
            group_length: 0,
            bit_offset: 0,
            valid_bits: 0,
        }
    }

    fn next_code(&mut self, width: u8, force_refill: bool) -> Result<Option<u16>> {
        let width = usize::from(width);
        if force_refill || self.bit_offset >= self.valid_bits {
            let remaining = self.input.get(self.position..).ok_or_else(|| {
                stream_format_error("unix-compress", "code-reader position is out of range")
            })?;
            if remaining.is_empty() {
                return Ok(None);
            }
            self.group_start = self.position;
            self.group_length = remaining.len().min(width);
            self.position = self
                .position
                .checked_add(self.group_length)
                .ok_or_else(|| {
                    stream_format_error("unix-compress", "code-reader position overflows")
                })?;
            let group_bits = self.group_length.checked_mul(8).ok_or_else(|| {
                stream_format_error("unix-compress", "code group bit count overflows")
            })?;
            let complete_codes = group_bits
                .checked_div(width)
                .ok_or_else(|| stream_format_error("unix-compress", "code width is zero"))?;
            self.valid_bits = complete_codes.checked_mul(width).ok_or_else(|| {
                stream_format_error("unix-compress", "valid code bit count overflows")
            })?;
            self.bit_offset = 0;
            if complete_codes == 0 {
                return Ok(None);
            }
        }

        let group_end = self
            .group_start
            .checked_add(self.group_length)
            .ok_or_else(|| stream_format_error("unix-compress", "code group range overflows"))?;
        let group = self
            .input
            .get(self.group_start..group_end)
            .ok_or_else(|| stream_format_error("unix-compress", "code group is unavailable"))?;
        let mut value = 0_u32;
        for output_bit in 0..width {
            let source_bit = self.bit_offset.checked_add(output_bit).ok_or_else(|| {
                stream_format_error("unix-compress", "source bit offset overflows")
            })?;
            let source_byte = source_bit.checked_div(8).ok_or_else(|| {
                stream_format_error("unix-compress", "source byte division failed")
            })?;
            let bit_in_byte = source_bit % 8;
            let byte = group
                .get(source_byte)
                .copied()
                .ok_or_else(|| stream_format_error("unix-compress", "encoded code is truncated"))?;
            let bit = u32::from((byte >> bit_in_byte) & 1);
            let shift = u32::try_from(output_bit).map_err(|_| {
                stream_format_error("unix-compress", "output bit is not representable")
            })?;
            value |= bit
                .checked_shl(shift)
                .ok_or_else(|| stream_format_error("unix-compress", "decoded code overflows"))?;
        }
        self.bit_offset = self
            .bit_offset
            .checked_add(width)
            .ok_or_else(|| stream_format_error("unix-compress", "code bit offset overflows"))?;
        let value = u16::try_from(value).map_err(|_| {
            stream_format_error("unix-compress", "decoded code is not representable")
        })?;
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CompressedStream, StreamFormat, StreamInfoKind};
    use super::{
        BLOCK_MODE_FLAG, CLEAR_CODE, FIRST_BLOCK_CODE, INITIAL_CODE_BITS, maximum_code_for_width,
    };
    use crate::{CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget};

    // Generated by macOS 26.5.1 /usr/bin/compress (SHA-256
    // bf8cb1cefedfbf86fbb38dd42278fcad8fe020f3b8989897f1a0b2187aabdda5)
    // from the exact bytes b"hello unix compress\n". The fixture itself is
    // data, not imported implementation code.
    const HELLO_DOT_Z: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0x44, 0x1d, 0x37, 0x69, 0xf0, 0x80,
        0x18, 0xf3, 0xa6, 0x0d, 0x1c, 0x39, 0x65, 0xe6, 0xcc, 0x51, 0x00,
    ];

    fn flush_codes(
        output: &mut Vec<u8>,
        group: &mut Vec<u16>,
        width: u8,
        padded: bool,
    ) -> Result<()> {
        if group.is_empty() {
            return Ok(());
        }
        let width = usize::from(width);
        let meaningful_bits = group.len().checked_mul(width).ok_or_else(|| {
            super::stream_format_error("unix-compress", "test code-group bit count overflows")
        })?;
        let meaningful_bytes = meaningful_bits
            .checked_add(7)
            .and_then(|bits| bits.checked_div(8))
            .ok_or_else(|| {
                super::stream_format_error("unix-compress", "test code-group size overflows")
            })?;
        let byte_count = if padded { width } else { meaningful_bytes };
        let mut encoded = vec![0_u8; byte_count];
        for (code_index, code) in group.iter().copied().enumerate() {
            let code_start = code_index.checked_mul(width).ok_or_else(|| {
                super::stream_format_error("unix-compress", "test code offset overflows")
            })?;
            for code_bit in 0..width {
                let shift = u32::try_from(code_bit).map_err(|_| {
                    super::stream_format_error(
                        "unix-compress",
                        "test code bit is not representable",
                    )
                })?;
                let shifted = u32::from(code).checked_shr(shift).ok_or_else(|| {
                    super::stream_format_error("unix-compress", "test source bit overflows")
                })?;
                if shifted & 1 == 0 {
                    continue;
                }
                let destination_bit = code_start.checked_add(code_bit).ok_or_else(|| {
                    super::stream_format_error("unix-compress", "test destination bit overflows")
                })?;
                let destination_byte = destination_bit.checked_div(8).ok_or_else(|| {
                    super::stream_format_error(
                        "unix-compress",
                        "test destination byte division failed",
                    )
                })?;
                let bit_in_byte = destination_bit % 8;
                let byte = encoded.get_mut(destination_byte).ok_or_else(|| {
                    super::stream_format_error(
                        "unix-compress",
                        "test destination byte is unavailable",
                    )
                })?;
                *byte |= 1_u8
                    .checked_shl(u32::try_from(bit_in_byte).map_err(|_| {
                        super::stream_format_error(
                            "unix-compress",
                            "test destination bit is not representable",
                        )
                    })?)
                    .ok_or_else(|| {
                        super::stream_format_error(
                            "unix-compress",
                            "test destination bit overflows",
                        )
                    })?;
            }
        }
        output.extend_from_slice(&encoded);
        group.clear();
        Ok(())
    }

    fn literal_code_stream(
        codes: &[u16],
        maximum_code_bits: u8,
        block_mode: bool,
    ) -> Result<Vec<u8>> {
        let flags = if block_mode {
            BLOCK_MODE_FLAG | maximum_code_bits
        } else {
            maximum_code_bits
        };
        let mut output = vec![0x1f, 0x9d, flags];
        let mut group = Vec::new();
        let mut width = INITIAL_CODE_BITS;
        let mut maximum_current = maximum_code_for_width(width, maximum_code_bits)?;
        let mut next_code = if block_mode {
            FIRST_BLOCK_CODE
        } else {
            super::FIRST_PLAIN_CODE
        };
        let mut has_previous = false;

        for code in codes.iter().copied() {
            if next_code > maximum_current && width < maximum_code_bits {
                flush_codes(&mut output, &mut group, width, true)?;
                width = width.checked_add(1).ok_or_else(|| {
                    super::stream_format_error("unix-compress", "test code width overflows")
                })?;
                maximum_current = maximum_code_for_width(width, maximum_code_bits)?;
            }
            group.push(code);
            if group.len() == 8 {
                flush_codes(&mut output, &mut group, width, true)?;
            }
            if block_mode && code == CLEAR_CODE {
                flush_codes(&mut output, &mut group, width, true)?;
                width = INITIAL_CODE_BITS;
                maximum_current = maximum_code_for_width(width, maximum_code_bits)?;
                next_code = FIRST_BLOCK_CODE;
                has_previous = false;
            } else if has_previous {
                let maximum_codes =
                    1_u32
                        .checked_shl(u32::from(maximum_code_bits))
                        .ok_or_else(|| {
                            super::stream_format_error(
                                "unix-compress",
                                "test maximum code count overflows",
                            )
                        })?;
                if next_code < maximum_codes {
                    next_code = next_code.checked_add(1).ok_or_else(|| {
                        super::stream_format_error("unix-compress", "test next code overflows")
                    })?;
                }
            } else {
                has_previous = true;
            }
        }
        flush_codes(&mut output, &mut group, width, false)?;
        Ok(output)
    }

    #[test]
    fn bsd_oracle_fixture_reports_info_and_extracts_exactly() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut open_budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes(
            HELLO_DOT_Z.to_vec(),
            Limits::default(),
            &cancellation,
            &mut open_budget,
        )?;
        assert_eq!(stream.info().format(), StreamFormat::UnixCompress);
        assert_eq!(stream.info().uncompressed_size(), None);
        let StreamInfoKind::UnixCompress(info) = stream.info().kind() else {
            return Err(super::stream_format_error(
                "unix-compress",
                "wrong test info kind",
            ));
        };
        assert_eq!(info.maximum_code_bits(), 16);
        assert!(info.block_mode());
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            b"hello unix compress\n"
        );
        Ok(())
    }

    #[test]
    fn generated_literals_cross_widths_and_clear_reset() -> Result<()> {
        let mut codes = Vec::new();
        let mut expected = Vec::new();
        for index in 0_u16..1_100 {
            if index == 700 {
                codes.push(CLEAR_CODE);
            }
            let literal = u8::try_from(index % 251).map_err(|_| {
                super::stream_format_error("unix-compress", "test literal is not representable")
            })?;
            codes.push(u16::from(literal));
            expected.push(literal);
        }
        let bytes = literal_code_stream(&codes, 12, true)?;
        let cancellation = CancellationToken::new();
        let mut open_budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes,
            StreamFormat::UnixCompress,
            Limits::default(),
            &cancellation,
            &mut open_budget,
        )?;
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            expected
        );
        Ok(())
    }

    #[test]
    fn generated_non_block_stream_crosses_a_width_boundary() -> Result<()> {
        let mut codes = Vec::new();
        let mut expected = Vec::new();
        for index in 0_u16..700 {
            let literal = u8::try_from(index % 253).map_err(|_| {
                super::stream_format_error("unix-compress", "test literal is not representable")
            })?;
            codes.push(u16::from(literal));
            expected.push(literal);
        }
        let bytes = literal_code_stream(&codes, 12, false)?;
        let cancellation = CancellationToken::new();
        let mut open_budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes,
            StreamFormat::UnixCompress,
            Limits::default(),
            &cancellation,
            &mut open_budget,
        )?;
        let StreamInfoKind::UnixCompress(info) = stream.info().kind() else {
            return Err(super::stream_format_error(
                "unix-compress",
                "wrong test info kind",
            ));
        };
        assert!(!info.block_mode());
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            expected
        );
        Ok(())
    }

    #[test]
    fn header_validation_rejects_reserved_width_and_truncation() {
        for bytes in [
            Vec::new(),
            vec![0x1f],
            vec![0x1f, 0x9d],
            vec![0x1f, 0x9d, 0x60 | 16],
            vec![0x1f, 0x9d, 8],
            vec![0x1f, 0x9d, 17],
        ] {
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            assert_eq!(
                CompressedStream::open_bytes_as(
                    bytes,
                    StreamFormat::UnixCompress,
                    Limits::default(),
                    &cancellation,
                    &mut budget,
                )
                .err()
                .map(|error| error.kind()),
                Some(ErrorKind::Format)
            );
        }
    }

    #[test]
    fn dictionary_output_work_and_cancellation_limits_apply() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let frame_limited = CompressedStream::open_bytes_as(
            HELLO_DOT_Z.to_vec(),
            StreamFormat::UnixCompress,
            Limits::builder().max_stream_frames(0).build(),
            &cancellation,
            &mut budget,
        );
        assert!(matches!(
            frame_limited,
            Err(Error::LimitExceeded {
                limit: LimitKind::StreamFrames,
                ..
            })
        ));

        let mut budget = WorkBudget::unlimited();
        let dictionary_limited = CompressedStream::open_bytes_as(
            HELLO_DOT_Z.to_vec(),
            StreamFormat::UnixCompress,
            Limits::builder().max_dictionary_bytes(262_143).build(),
            &cancellation,
            &mut budget,
        );
        assert!(matches!(
            dictionary_limited,
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                ..
            })
        ));

        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            HELLO_DOT_Z.to_vec(),
            StreamFormat::UnixCompress,
            Limits::builder().max_total_output_bytes(5).build(),
            &cancellation,
            &mut budget,
        )?;
        let mut extraction_budget = WorkBudget::unlimited();
        assert!(matches!(
            stream.verify(&cancellation, &mut extraction_budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                ..
            })
        ));

        let mut work_limited = WorkBudget::bounded(1);
        assert!(matches!(
            stream.verify(&cancellation, &mut work_limited),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut extraction_budget = WorkBudget::unlimited();
        assert!(matches!(
            stream.verify(&cancelled, &mut extraction_budget),
            Err(Error::Cancelled)
        ));
        Ok(())
    }
}
