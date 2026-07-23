//! Bounded adapters for permissively licensed compression decoders.

use std::{
    cell::Cell,
    io::{self, Read},
    panic::{AssertUnwindSafe, catch_unwind},
};

use miniz_oxide::{
    DataFormat, MZFlush, MZStatus,
    inflate::stream::{InflateState, inflate},
};

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, format_error, u64_to_usize, usize_to_u64,
    },
};

const DEFLATE_DICTIONARY_BYTES: u64 = 32 * 1024;
// Includes the maximum Brotli ring buffer plus conservative decode tables.
const BROTLI_DICTIONARY_BYTES: u64 = 32 * 1024 * 1024;
// A linked 8 MiB LZ4 frame reserves an 8 MiB source block, two destination
// blocks, and a 64 KiB history window before producing output.
const LZ4_WORKING_BYTES: u64 = 24 * 1024 * 1024 + 64 * 1024;
const BROTLI_FRAME_BYTES: usize = 16;
const BROTLI_FRAME_MAGIC: u32 = 0x184d_2a50;
const BROTLI_FRAME_SIZE: u32 = 8;
const BROTLI_MAGIC: u16 = 0x5242;
const LZ4_MAGIC: &[u8] = &[0x04, 0x22, 0x4d, 0x18];
const LZ4_MINIMUM_FRAME_BYTES: usize = 11;
const ZSTD_MAGIC: u32 = 0xfd2f_b528;

pub(crate) struct ControlledInput<'input> {
    bytes: &'input [u8],
    position: usize,
    consumed: &'input Cell<usize>,
    cancellation: crate::CancellationToken,
}

impl<'input> ControlledInput<'input> {
    pub(crate) fn new(
        bytes: &'input [u8],
        consumed: &'input Cell<usize>,
        cancellation: crate::CancellationToken,
    ) -> Self {
        Self {
            bytes,
            position: 0,
            consumed,
            cancellation,
        }
    }
}

impl Read for ControlledInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.cancellation.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "archive operation cancelled")
        })?;
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.bytes.get(self.position..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder input position is invalid",
            )
        })?;
        if remaining.is_empty() {
            return Ok(0);
        }
        let count = remaining.len().min(output.len()).min(CONTROL_CHUNK_SIZE);
        let source = remaining.get(..count).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "decoder input range is invalid")
        })?;
        let destination = output.get_mut(..count).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder output range is invalid",
            )
        })?;
        destination.copy_from_slice(source);
        self.position = self.position.checked_add(count).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder input position overflows",
            )
        })?;
        self.consumed.set(self.position);
        Ok(count)
    }
}

fn reserve_output(output: &mut Vec<u8>, additional: usize) -> Result<()> {
    output.try_reserve(additional).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "decoder output allocation failed",
        ))
    })
}

fn append_output(
    output: &mut Vec<u8>,
    bytes: &[u8],
    expected: Option<u64>,
    maximum: u64,
) -> Result<()> {
    let current = usize_to_u64(
        output.len(),
        "decoder output length is not representable as u64",
    )?;
    let additional = usize_to_u64(
        bytes.len(),
        "decoder output chunk length is not representable as u64",
    )?;
    let next = current
        .checked_add(additional)
        .ok_or_else(|| format_error("decoder output length overflows"))?;
    if expected.is_some_and(|declared| next > declared) {
        return Err(format_error(
            "decoded coder output exceeds its declared size",
        ));
    }
    check_limit(next, maximum, LimitKind::TotalOutputBytes)?;
    reserve_output(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn decode_reader<R: Read>(
    mut reader: R,
    consumed: &Cell<usize>,
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
    error_detail: &'static str,
) -> Result<Vec<u8>> {
    if let Some(size) = expected {
        check_limit(size, maximum, LimitKind::TotalOutputBytes)?;
    }
    let mut output = Vec::new();
    let initial_capacity = expected
        .map(|size| size.min(1024 * 1024))
        .map_or(Ok(0), |size| {
            u64_to_usize(
                size,
                "initial decoder output capacity is not representable on this platform",
            )
        })?;
    reserve_output(&mut output, initial_capacity)?;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    let mut charged_input = 0_usize;
    loop {
        control.checkpoint(0)?;
        let result = catch_unwind(AssertUnwindSafe(|| reader.read(&mut buffer)));
        let read = match result {
            Ok(Ok(read)) => read,
            Ok(Err(_)) | Err(_) => {
                control.checkpoint(0)?;
                return Err(format_error(error_detail));
            }
        };
        let input_position = consumed.get();
        let input_delta = input_position
            .checked_sub(charged_input)
            .ok_or_else(|| format_error("decoder input accounting underflows"))?;
        charged_input = input_position;
        let work = input_delta
            .checked_add(read)
            .and_then(|units| units.checked_add(1))
            .ok_or_else(|| format_error("decoder work accounting overflows"))?;
        control.checkpoint(usize_to_u64(
            work,
            "decoder work is not representable as u64",
        )?)?;
        if read == 0 {
            break;
        }
        let bytes = buffer
            .get(..read)
            .ok_or_else(|| format_error("decoder returned an invalid output length"))?;
        append_output(&mut output, bytes, expected, maximum)?;
    }
    let actual = usize_to_u64(
        output.len(),
        "decoded output size is not representable as u64",
    )?;
    if expected.is_some_and(|size| size != actual) {
        return Err(format_error(
            "decoded coder output size does not match its declaration",
        ));
    }
    Ok(output)
}

pub(crate) fn decode_deflate(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        DEFLATE_DICTIONARY_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    if let Some(size) = expected {
        check_limit(size, maximum, LimitKind::TotalOutputBytes)?;
    }
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut input_position = 0_usize;
    let mut output = Vec::new();
    let initial_capacity = expected
        .map(|size| size.min(1024 * 1024))
        .map_or(Ok(0), |size| {
            u64_to_usize(
                size,
                "initial Deflate output capacity is not representable on this platform",
            )
        })?;
    reserve_output(&mut output, initial_capacity)?;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    loop {
        control.checkpoint(0)?;
        let remaining = input
            .get(input_position..)
            .ok_or_else(|| format_error("Deflate input position is out of range"))?;
        let flush = if remaining.is_empty() {
            MZFlush::Finish
        } else {
            MZFlush::None
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            inflate(&mut state, remaining, &mut buffer, flush)
        }))
        .map_err(|_| format_error("Deflate decoder rejected its stream"))?;
        input_position = input_position
            .checked_add(result.bytes_consumed)
            .ok_or_else(|| format_error("Deflate input position overflows"))?;
        let work = result
            .bytes_consumed
            .checked_add(result.bytes_written)
            .and_then(|units| units.checked_add(1))
            .ok_or_else(|| format_error("Deflate work accounting overflows"))?;
        control.checkpoint(usize_to_u64(
            work,
            "Deflate work is not representable as u64",
        )?)?;
        let bytes = buffer
            .get(..result.bytes_written)
            .ok_or_else(|| format_error("Deflate returned an invalid output length"))?;
        append_output(&mut output, bytes, expected, maximum)?;
        match result.status {
            Ok(MZStatus::StreamEnd) => {
                if input_position != input.len() {
                    return Err(format_error("Deflate stream has trailing input"));
                }
                break;
            }
            Ok(MZStatus::Ok) => {
                if result.bytes_consumed == 0 && result.bytes_written == 0 {
                    return Err(format_error("Deflate decoder made no progress"));
                }
            }
            Ok(MZStatus::NeedDict) | Err(_) => {
                return Err(format_error("invalid or truncated Deflate stream"));
            }
        }
    }
    let actual = usize_to_u64(
        output.len(),
        "Deflate output size is not representable as u64",
    )?;
    if expected.is_some_and(|size| size != actual) {
        return Err(format_error(
            "decoded coder output size does not match its declaration",
        ));
    }
    Ok(output)
}

pub(crate) fn decode_bzip2(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let header = input
        .get(..4)
        .ok_or_else(|| format_error("BZip2 stream header is truncated"))?;
    let block_digit = header
        .get(3)
        .copied()
        .ok_or_else(|| format_error("BZip2 block-size byte is missing"))?;
    if header.get(..3) != Some(b"BZh") || !(b'1'..=b'9').contains(&block_digit) {
        return Err(format_error("invalid BZip2 stream header"));
    }
    let block_multiplier = block_digit
        .checked_sub(b'0')
        .ok_or_else(|| format_error("BZip2 block size underflows"))?;
    let block_bytes = u64::from(block_multiplier)
        .checked_mul(100_000)
        .ok_or_else(|| format_error("BZip2 block size overflows"))?;
    // bzip2-rs reserves one byte input block and a u32 inverse-BWT table.
    let working_bytes = block_bytes
        .checked_mul(5)
        .ok_or_else(|| format_error("BZip2 working memory size overflows"))?;
    check_limit(
        working_bytes,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let consumed = Cell::new(0);
    let input = ControlledInput::new(input, &consumed, control.cancellation_token());
    let reader = bzip2_rs::DecoderReader::new(input);
    decode_reader(
        reader,
        &consumed,
        expected,
        maximum,
        control,
        "invalid or truncated BZip2 stream",
    )
}

fn brotli_payload(input: &[u8]) -> Result<&[u8]> {
    let Some(frame) = input.get(..BROTLI_FRAME_BYTES) else {
        return Ok(input);
    };
    let frame_magic = u32::from_le_bytes(
        frame
            .get(..4)
            .ok_or_else(|| format_error("Brotli frame magic is truncated"))?
            .try_into()
            .map_err(|_| format_error("Brotli frame magic has the wrong length"))?,
    );
    let frame_size = u32::from_le_bytes(
        frame
            .get(4..8)
            .ok_or_else(|| format_error("Brotli frame size is truncated"))?
            .try_into()
            .map_err(|_| format_error("Brotli frame size has the wrong length"))?,
    );
    let brotli_magic = u16::from_le_bytes(
        frame
            .get(12..14)
            .ok_or_else(|| format_error("Brotli marker is truncated"))?
            .try_into()
            .map_err(|_| format_error("Brotli marker has the wrong length"))?,
    );
    if frame_magic == BROTLI_FRAME_MAGIC
        && frame_size == BROTLI_FRAME_SIZE
        && brotli_magic == BROTLI_MAGIC
    {
        input
            .get(BROTLI_FRAME_BYTES..)
            .ok_or_else(|| format_error("Brotli framed payload is truncated"))
    } else {
        Ok(input)
    }
}

pub(crate) fn decode_brotli(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        BROTLI_DICTIONARY_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let payload = brotli_payload(input)?;
    let consumed = Cell::new(0);
    let input = ControlledInput::new(payload, &consumed, control.cancellation_token());
    let reader = brotli_decompressor::Decompressor::new(input, CONTROL_CHUNK_SIZE);
    decode_reader(
        reader,
        &consumed,
        expected,
        maximum,
        control,
        "invalid or truncated Brotli stream",
    )
}

pub(crate) fn decode_lz4(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    if input.get(..LZ4_MAGIC.len()) != Some(LZ4_MAGIC) || input.len() < LZ4_MINIMUM_FRAME_BYTES {
        return Err(format_error("invalid or truncated LZ4 frame header"));
    }
    check_limit(
        LZ4_WORKING_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let consumed = Cell::new(0);
    let input = ControlledInput::new(input, &consumed, control.cancellation_token());
    let reader = lz4_flex::frame::FrameDecoder::new(input);
    decode_reader(
        reader,
        &consumed,
        expected,
        maximum,
        control,
        "invalid or truncated LZ4 frame",
    )
}

fn read_little_endian(input: &[u8], offset: usize, length: usize) -> Result<u64> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format_error("Zstandard header range overflows"))?;
    let bytes = input
        .get(offset..end)
        .ok_or_else(|| format_error("Zstandard frame header is truncated"))?;
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let shift = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(8))
            .ok_or_else(|| format_error("Zstandard header shift overflows"))?;
        value |= u64::from(byte)
            .checked_shl(shift)
            .ok_or_else(|| format_error("Zstandard header value overflows"))?;
    }
    Ok(value)
}

fn zstd_window_bytes(input: &[u8], expected: Option<u64>) -> Result<u64> {
    let magic = u32::try_from(read_little_endian(input, 0, 4)?)
        .map_err(|_| format_error("Zstandard magic is not representable as u32"))?;
    if magic != ZSTD_MAGIC {
        return Err(format_error("invalid Zstandard frame magic"));
    }
    let descriptor = input
        .get(4)
        .copied()
        .ok_or_else(|| format_error("Zstandard frame descriptor is truncated"))?;
    if descriptor & 0x18 != 0 {
        return Err(format_error("invalid Zstandard frame descriptor flags"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let mut offset = 5_usize;
    let descriptor_window = if single_segment {
        None
    } else {
        let byte = input
            .get(offset)
            .copied()
            .ok_or_else(|| format_error("Zstandard window descriptor is truncated"))?;
        offset = offset
            .checked_add(1)
            .ok_or_else(|| format_error("Zstandard header offset overflows"))?;
        let exponent = u32::from(byte >> 3)
            .checked_add(10)
            .ok_or_else(|| format_error("Zstandard window exponent overflows"))?;
        let base = 1_u64
            .checked_shl(exponent)
            .ok_or_else(|| format_error("Zstandard window size overflows"))?;
        Some(
            base.checked_add(
                base.checked_div(8)
                    .and_then(|unit| unit.checked_mul(u64::from(byte & 7)))
                    .ok_or_else(|| format_error("Zstandard window mantissa overflows"))?,
            )
            .ok_or_else(|| format_error("Zstandard window size overflows"))?,
        )
    };
    let dictionary_length = match descriptor & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => return Err(format_error("invalid Zstandard dictionary flag")),
    };
    let dictionary_id = read_little_endian(input, offset, dictionary_length)?;
    if dictionary_id != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("zstd-dictionary"),
        });
    }
    offset = offset
        .checked_add(dictionary_length)
        .ok_or_else(|| format_error("Zstandard header offset overflows"))?;
    let size_flag = descriptor >> 6;
    let content_length = match (size_flag, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        (3, _) => 8,
        _ => return Err(format_error("invalid Zstandard content-size flag")),
    };
    let mut content_size = read_little_endian(input, offset, content_length)?;
    if content_length == 2 {
        content_size = content_size
            .checked_add(256)
            .ok_or_else(|| format_error("Zstandard content size overflows"))?;
    }
    if content_length != 0 && expected.is_some_and(|size| size != content_size) {
        return Err(format_error(
            "Zstandard content size does not match the coder output size",
        ));
    }
    Ok(descriptor_window.unwrap_or(content_size))
}

pub(crate) fn decode_zstd(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let window = zstd_window_bytes(input, expected)?;
    check_limit(
        window,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let consumed = Cell::new(0);
    let input = ControlledInput::new(input, &consumed, control.cancellation_token());
    let reader = catch_unwind(AssertUnwindSafe(|| {
        ruzstd::decoding::StreamingDecoder::new(input)
    }))
    .map_err(|_| format_error("Zstandard decoder rejected its frame"))?
    .map_err(|_| format_error("invalid or truncated Zstandard frame"))?;
    decode_reader(
        reader,
        &consumed,
        expected,
        maximum,
        control,
        "invalid or truncated Zstandard frame",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        BROTLI_DICTIONARY_BYTES, DEFLATE_DICTIONARY_BYTES, LZ4_WORKING_BYTES, brotli_payload,
        decode_brotli, decode_bzip2, decode_deflate, decode_lz4, decode_zstd, zstd_window_bytes,
    };
    use crate::{
        CancellationToken, Error, LimitKind, Limits, Result, WorkBudget,
        parse_util::{ParseControl, usize_to_u64},
    };

    const EMPTY_LZ4_FRAME: &[u8] = &[
        0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82, 0x00, 0x00, 0x00, 0x00,
    ];
    const COMPLETE_BROTLI_HELLO: &[u8] = b"\x8f\x02\x80hello\n\x03";
    const BROTLI_HELLO: &[u8] = b"hello\n";

    fn with_control<T>(operation: impl FnOnce(&mut ParseControl<'_>) -> T) -> T {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        operation(&mut control)
    }

    #[test]
    fn recognizes_the_private_brotli_prefix() -> Result<()> {
        let mut bytes = Vec::from([
            0x50, 0x2a, 0x4d, 0x18, 8, 0, 0, 0, 3, 0, 0, 0, b'B', b'R', 1, 0,
        ]);
        bytes.extend_from_slice(b"abc");
        assert_eq!(brotli_payload(&bytes)?, b"abc");
        Ok(())
    }

    #[test]
    fn does_not_strip_an_unrecognized_brotli_prefix() -> Result<()> {
        let bytes = [0_u8; 16];
        assert_eq!(brotli_payload(&bytes)?, bytes);
        Ok(())
    }

    #[test]
    fn complete_brotli_succeeds_and_flush_only_style_stream_fails() -> Result<()> {
        let decoded = with_control(|control| {
            decode_brotli(
                COMPLETE_BROTLI_HELLO,
                Some(6),
                6,
                Limits::default(),
                control,
            )
        })?;
        assert_eq!(decoded, BROTLI_HELLO);

        // Model a flush-only interoperability boundary without importing an
        // external stream by removing only this complete vector's terminal byte.
        let unfinished = COMPLETE_BROTLI_HELLO
            .get(..COMPLETE_BROTLI_HELLO.len().saturating_sub(1))
            .ok_or_else(|| crate::parse_util::format_error("Brotli test vector is empty"))?;
        assert!(matches!(
            with_control(|control| {
                decode_brotli(unfinished, Some(6), 6, Limits::default(), control)
            }),
            Err(Error::Format { .. })
        ));
        Ok(())
    }

    #[test]
    fn reads_a_single_segment_zstd_window() -> Result<()> {
        let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 12];
        assert_eq!(zstd_window_bytes(&bytes, Some(12))?, 12);
        Ok(())
    }

    #[test]
    fn deflate_roundtrip_and_output_preflight_are_bounded() -> Result<()> {
        let plain = b"bounded raw Deflate";
        let plain_len = usize_to_u64(plain.len(), "test payload length is not representable")?;
        let limited_maximum = plain_len
            .checked_sub(1)
            .ok_or_else(|| crate::parse_util::format_error("test payload is empty"))?;
        let compressed = miniz_oxide::deflate::compress_to_vec(plain, 6);
        let decoded = with_control(|control| {
            decode_deflate(
                &compressed,
                Some(plain_len),
                1024,
                Limits::default(),
                control,
            )
        })?;
        assert_eq!(decoded, plain);
        let decoded_unknown = with_control(|control| {
            decode_deflate(&compressed, None, 1024, Limits::default(), control)
        })?;
        assert_eq!(decoded_unknown, plain);
        for end in 0..compressed.len() {
            let prefix = compressed.get(..end).unwrap_or_default();
            assert!(
                with_control(|control| {
                    decode_deflate(prefix, None, 1024, Limits::default(), control)
                })
                .is_err(),
                "Deflate final-block truncation at byte {end} was accepted"
            );
        }
        let limited = with_control(|control| {
            decode_deflate(
                &compressed,
                Some(plain_len),
                limited_maximum,
                Limits::default(),
                control,
            )
        });
        assert!(matches!(
            limited,
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn codec_working_memory_is_checked_before_decoder_construction() {
        let cases = [
            with_control(|control| {
                decode_deflate(
                    &[],
                    Some(0),
                    0,
                    Limits::builder()
                        .max_dictionary_bytes(DEFLATE_DICTIONARY_BYTES - 1)
                        .build(),
                    control,
                )
            }),
            with_control(|control| {
                decode_bzip2(
                    b"BZh9",
                    Some(0),
                    0,
                    Limits::builder().max_dictionary_bytes(4_499_999).build(),
                    control,
                )
            }),
            with_control(|control| {
                decode_brotli(
                    &[],
                    Some(0),
                    0,
                    Limits::builder()
                        .max_dictionary_bytes(BROTLI_DICTIONARY_BYTES - 1)
                        .build(),
                    control,
                )
            }),
            with_control(|control| {
                decode_lz4(
                    EMPTY_LZ4_FRAME,
                    Some(0),
                    0,
                    Limits::builder()
                        .max_dictionary_bytes(LZ4_WORKING_BYTES - 1)
                        .build(),
                    control,
                )
            }),
            with_control(|control| {
                decode_zstd(
                    &[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xff],
                    None,
                    0,
                    Limits::builder().max_dictionary_bytes(1024).build(),
                    control,
                )
            }),
        ];
        for result in cases {
            assert!(matches!(
                result,
                Err(Error::LimitExceeded {
                    limit: LimitKind::DictionaryBytes,
                    ..
                })
            ));
        }
    }

    #[test]
    fn cancellation_is_not_reclassified_by_reader_adapters() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_lz4(EMPTY_LZ4_FRAME, None, 1024, Limits::default(), &mut control);
        assert!(matches!(result, Err(Error::Cancelled)));
    }

    #[test]
    fn truncated_codec_streams_are_format_errors() {
        let cases = [
            (
                "Deflate",
                with_control(|control| decode_deflate(&[], Some(0), 0, Limits::default(), control)),
            ),
            (
                "BZip2",
                with_control(|control| {
                    decode_bzip2(b"BZh1", Some(0), 0, Limits::default(), control)
                }),
            ),
            (
                "Brotli",
                with_control(|control| {
                    decode_brotli(&[0xff], Some(0), 0, Limits::default(), control)
                }),
            ),
            (
                "LZ4",
                with_control(|control| {
                    decode_lz4(
                        &[0x04, 0x22, 0x4d, 0x18],
                        Some(0),
                        0,
                        Limits::default(),
                        control,
                    )
                }),
            ),
            (
                "Zstandard",
                with_control(|control| decode_zstd(&[], Some(0), 0, Limits::default(), control)),
            ),
        ];
        for (name, result) in cases {
            assert!(
                matches!(result, Err(Error::Format { .. })),
                "{name} returned {result:?}"
            );
        }
    }
}
