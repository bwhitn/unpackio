//! Validated Zstandard frame layout and bounded extraction.

use std::{
    cell::Cell,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
};

use super::{
    ControlledInput, ExtractionControl, SKIPPABLE_MAGIC_END, SKIPPABLE_MAGIC_START,
    ZSTANDARD_MAGIC, ZstandardStreamInfo, check_frame_count, cursor::StreamCursor, pump_reader,
    push_layout, stream_checksum_error, stream_format_error, unsupported_stream_feature,
};
use crate::{LimitKind, Limits, Result, parse_util::check_limit};

const MAXIMUM_BLOCK_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy)]
struct ZstandardFrame {
    start: usize,
    end: usize,
    content_size: Option<u64>,
    window_bytes: u64,
    checksum: bool,
    dictionary: bool,
}

pub(super) struct ZstandardLayout {
    frames: Vec<ZstandardFrame>,
}

impl ZstandardLayout {
    pub(super) fn extract<W: Write>(
        &self,
        input: &[u8],
        control: &mut ExtractionControl<'_, W>,
    ) -> Result<()> {
        for (index, frame) in self.frames.iter().copied().enumerate() {
            let frame_index = u64::try_from(index).map_err(|_| {
                stream_format_error("zstandard", "frame index is not representable")
            })?;
            control.checkpoint(0)?;
            check_limit(
                frame.window_bytes,
                control.limits().max_dictionary_bytes(),
                LimitKind::DictionaryBytes,
            )?;
            if frame.dictionary {
                return Err(unsupported_stream_feature(
                    "zstandard",
                    "external-dictionary",
                ));
            }
            let frame_bytes = input.get(frame.start..frame.end).ok_or_else(|| {
                stream_format_error("zstandard", "validated frame range is unavailable")
            })?;
            let consumed = Cell::new(0);
            let source = ControlledInput::new(frame_bytes, &consumed, control.cancellation_token());
            let decoder = catch_unwind(AssertUnwindSafe(|| {
                ruzstd::decoding::StreamingDecoder::new(source)
            }))
            .map_err(|_| stream_format_error("zstandard", "decoder panicked while opening frame"))?
            .map_err(|_| stream_format_error("zstandard", "decoder rejected frame header"))?;
            let mut decoder = decoder;
            pump_reader(
                &mut decoder,
                &consumed,
                frame.content_size,
                "zstandard",
                frame_index,
                control,
                |_| false,
            )?;
            if consumed.get() != frame_bytes.len() {
                return Err(stream_format_error(
                    "zstandard",
                    "decoder did not consume exactly one frame",
                ));
            }
            if frame.checksum {
                let stored = decoder.decoder.get_checksum_from_data().ok_or_else(|| {
                    stream_format_error("zstandard", "frame checksum was not finalized")
                })?;
                let calculated = decoder.decoder.get_calculated_checksum().ok_or_else(|| {
                    stream_format_error("zstandard", "frame checksum was not calculated")
                })?;
                if stored != calculated {
                    return Err(stream_checksum_error("zstandard", frame_index));
                }
            }
            control.finish_frame(frame.checksum)?;
        }
        Ok(())
    }
}

pub(super) fn parse(
    input: &[u8],
    limits: Limits,
) -> Result<(ZstandardStreamInfo, Option<u64>, ZstandardLayout)> {
    let mut cursor = StreamCursor::new(input, "zstandard");
    let mut frames = Vec::new();
    let mut total_frames = 0_u64;
    let mut data_frames = 0_u64;
    let mut skippable_frames = 0_u64;
    let mut checksum_frames = 0_u64;
    let mut dictionary_frames = 0_u64;
    let mut maximum_window_bytes = 0_u64;
    let mut aggregate_size = Some(0_u64);

    while !cursor.remaining()?.is_empty() {
        total_frames = total_frames
            .checked_add(1)
            .ok_or_else(|| stream_format_error("zstandard", "frame count overflows"))?;
        check_frame_count(total_frames, limits)?;
        let start = cursor.position();
        let magic = cursor.read_u32_le("frame magic is truncated")?;
        if (SKIPPABLE_MAGIC_START..=SKIPPABLE_MAGIC_END).contains(&magic) {
            let length = cursor.read_u32_le("skippable frame size is truncated")?;
            cursor.skip_u64(u64::from(length), "skippable frame payload is truncated")?;
            skippable_frames = skippable_frames.checked_add(1).ok_or_else(|| {
                stream_format_error("zstandard", "skippable frame count overflows")
            })?;
            continue;
        }
        if magic != ZSTANDARD_MAGIC {
            return Err(stream_format_error("zstandard", "unexpected frame magic"));
        }
        let parsed = parse_frame(&mut cursor)?;
        check_limit(
            parsed.window_bytes,
            limits.max_dictionary_bytes(),
            LimitKind::DictionaryBytes,
        )?;
        data_frames = data_frames
            .checked_add(1)
            .ok_or_else(|| stream_format_error("zstandard", "data frame count overflows"))?;
        if parsed.checksum {
            checksum_frames = checksum_frames.checked_add(1).ok_or_else(|| {
                stream_format_error("zstandard", "checksum frame count overflows")
            })?;
        }
        if parsed.dictionary {
            dictionary_frames = dictionary_frames.checked_add(1).ok_or_else(|| {
                stream_format_error("zstandard", "dictionary frame count overflows")
            })?;
        }
        maximum_window_bytes = maximum_window_bytes.max(parsed.window_bytes);
        aggregate_size = match (aggregate_size, parsed.content_size) {
            (Some(total), Some(size)) => Some(total.checked_add(size).ok_or_else(|| {
                stream_format_error("zstandard", "aggregate content size overflows")
            })?),
            _ => None,
        };
        push_layout(
            &mut frames,
            ZstandardFrame {
                start,
                end: cursor.position(),
                content_size: parsed.content_size,
                window_bytes: parsed.window_bytes,
                checksum: parsed.checksum,
                dictionary: parsed.dictionary,
            },
        )?;
    }
    if data_frames == 0 {
        return Err(stream_format_error(
            "zstandard",
            "stream contains no data frame",
        ));
    }
    Ok((
        ZstandardStreamInfo {
            frame_count: data_frames,
            skippable_frame_count: skippable_frames,
            content_checksum_frame_count: checksum_frames,
            dictionary_frame_count: dictionary_frames,
            maximum_window_bytes,
        },
        aggregate_size,
        ZstandardLayout { frames },
    ))
}

struct ParsedFrame {
    content_size: Option<u64>,
    window_bytes: u64,
    checksum: bool,
    dictionary: bool,
}

fn parse_frame(cursor: &mut StreamCursor<'_>) -> Result<ParsedFrame> {
    let descriptor = cursor.read_u8("frame descriptor is truncated")?;
    if descriptor & 0x08 != 0 {
        return Err(stream_format_error(
            "zstandard",
            "reserved frame descriptor bit is set",
        ));
    }
    let single_segment = descriptor & 0x20 != 0;
    let window_descriptor = if single_segment {
        None
    } else {
        Some(cursor.read_u8("window descriptor is truncated")?)
    };
    let dictionary_length = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => return Err(stream_format_error("zstandard", "invalid dictionary flag")),
    };
    let dictionary_id = cursor.read_le(dictionary_length, "dictionary ID is truncated")?;
    let content_length = match (descriptor >> 6, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        (3, _) => 8,
        _ => {
            return Err(stream_format_error(
                "zstandard",
                "invalid content-size flag",
            ));
        }
    };
    let content_size = if content_length == 0 {
        None
    } else {
        let mut value = cursor.read_le(content_length, "frame content size is truncated")?;
        if content_length == 2 {
            value = value
                .checked_add(256)
                .ok_or_else(|| stream_format_error("zstandard", "frame content size overflows"))?;
        }
        Some(value)
    };
    let window_bytes = match (single_segment, content_size, window_descriptor) {
        (true, Some(size), None) => size,
        (false, _, Some(window)) => {
            let exponent = u32::from(window >> 3)
                .checked_add(10)
                .ok_or_else(|| stream_format_error("zstandard", "window exponent overflows"))?;
            let base = 1_u64
                .checked_shl(exponent)
                .ok_or_else(|| stream_format_error("zstandard", "window size overflows"))?;
            base.checked_add(
                base.checked_div(8)
                    .and_then(|unit| unit.checked_mul(u64::from(window & 0x07)))
                    .ok_or_else(|| stream_format_error("zstandard", "window mantissa overflows"))?,
            )
            .ok_or_else(|| stream_format_error("zstandard", "window size overflows"))?
        }
        _ => {
            return Err(stream_format_error(
                "zstandard",
                "frame header is internally inconsistent",
            ));
        }
    };
    let maximum_block_bytes = window_bytes.min(MAXIMUM_BLOCK_BYTES);
    loop {
        let block_header = cursor.read_u24_le("block header is truncated")?;
        let last = block_header & 1 != 0;
        let block_type = (block_header >> 1) & 0x03;
        let block_size = u64::from(block_header >> 3);
        if block_size > maximum_block_bytes {
            return Err(stream_format_error(
                "zstandard",
                "block exceeds the frame maximum size",
            ));
        }
        let payload_size = match block_type {
            0 | 2 => block_size,
            1 => 1,
            3 => {
                return Err(stream_format_error(
                    "zstandard",
                    "reserved block type is used",
                ));
            }
            _ => return Err(stream_format_error("zstandard", "invalid block type")),
        };
        cursor.skip_u64(payload_size, "block payload is truncated")?;
        if last {
            break;
        }
    }
    let checksum = descriptor & 0x04 != 0;
    if checksum {
        cursor.read_u32_le("content checksum is truncated")?;
    }
    Ok(ParsedFrame {
        content_size,
        window_bytes,
        checksum,
        dictionary: dictionary_id != 0,
    })
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use twox_hash::XxHash64;

    use super::super::{CompressedStream, StreamFormat, StreamInfoKind};
    use crate::{CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget};

    fn raw_frame(plain: &[u8], checksum: bool) -> Result<Vec<u8>> {
        let length = u8::try_from(plain.len()).map_err(|_| {
            super::stream_format_error("zstandard", "test frame exceeds one-byte size")
        })?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&super::ZSTANDARD_MAGIC.to_le_bytes());
        bytes.push(0x20 | if checksum { 0x04 } else { 0 });
        bytes.push(length);
        let block_header = u32::from(length)
            .checked_shl(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                super::stream_format_error("zstandard", "test block header overflows")
            })?;
        let serialized = block_header.to_le_bytes();
        bytes.extend_from_slice(serialized.get(..3).ok_or_else(|| {
            super::stream_format_error("zstandard", "test block header is unavailable")
        })?);
        bytes.extend_from_slice(plain);
        if checksum {
            let mut hasher = XxHash64::with_seed(0);
            hasher.write(plain);
            let checksum = u32::try_from(hasher.finish() & u64::from(u32::MAX)).map_err(|_| {
                super::stream_format_error("zstandard", "test checksum is not representable")
            })?;
            bytes.extend_from_slice(&checksum.to_le_bytes());
        }
        Ok(bytes)
    }

    fn dictionary_frame(plain: &[u8]) -> Result<Vec<u8>> {
        let length = u8::try_from(plain.len()).map_err(|_| {
            super::stream_format_error("zstandard", "test frame exceeds one-byte size")
        })?;
        let block_header = u32::from(length)
            .checked_shl(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                super::stream_format_error("zstandard", "test block header overflows")
            })?;
        let serialized = block_header.to_le_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&super::ZSTANDARD_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&[0x21, 7, length]);
        bytes.extend_from_slice(serialized.get(..3).ok_or_else(|| {
            super::stream_format_error("zstandard", "test block header is unavailable")
        })?);
        bytes.extend_from_slice(plain);
        Ok(bytes)
    }

    #[test]
    fn concatenated_checked_frames_report_and_extract() -> Result<()> {
        let mut bytes = raw_frame(b"zstd ", true)?;
        bytes.extend_from_slice(&0x184d_2a50_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(b"tag");
        bytes.extend_from_slice(&raw_frame(b"stream", true)?);
        let cancellation = CancellationToken::new();
        let mut open_budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes(
            bytes,
            Limits::default(),
            &cancellation,
            &mut open_budget,
        )?;
        assert_eq!(stream.info().format(), StreamFormat::Zstandard);
        assert_eq!(stream.info().uncompressed_size(), Some(11));
        let StreamInfoKind::Zstandard(info) = stream.info().kind() else {
            return Err(super::stream_format_error(
                "zstandard",
                "wrong test info kind",
            ));
        };
        assert_eq!(info.frame_count(), 2);
        assert_eq!(info.skippable_frame_count(), 1);
        assert_eq!(info.content_checksum_frame_count(), 2);
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            b"zstd stream"
        );
        Ok(())
    }

    #[test]
    fn checksum_corruption_is_not_success() -> Result<()> {
        let mut bytes = raw_frame(b"checksum", true)?;
        let checksum = bytes
            .last_mut()
            .ok_or_else(|| super::stream_format_error("zstandard", "test frame is empty"))?;
        *checksum ^= 1;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes,
            StreamFormat::Zstandard,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream
                .verify(&cancellation, &mut extraction_budget)
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Checksum)
        );
        Ok(())
    }

    #[test]
    fn every_truncation_is_rejected_before_decoding() -> Result<()> {
        let bytes = raw_frame(b"truncated", true)?;
        for length in 0..bytes.len() {
            let prefix = bytes.get(..length).ok_or_else(|| {
                super::stream_format_error("zstandard", "test prefix range is invalid")
            })?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            assert!(
                CompressedStream::open_bytes_as(
                    prefix.to_vec(),
                    StreamFormat::Zstandard,
                    Limits::default(),
                    &cancellation,
                    &mut budget,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn dictionaries_are_listable_but_typed_unsupported_for_extraction() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            dictionary_frame(b"dictionary")?,
            StreamFormat::Zstandard,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let StreamInfoKind::Zstandard(info) = stream.info().kind() else {
            return Err(super::stream_format_error(
                "zstandard",
                "wrong test info kind",
            ));
        };
        assert_eq!(info.dictionary_frame_count(), 1);
        let mut extraction_budget = WorkBudget::unlimited();
        assert!(matches!(
            stream.verify(&cancellation, &mut extraction_budget),
            Err(Error::UnsupportedStreamFeature { format, feature })
                if format == "zstandard" && feature == "external-dictionary"
        ));
        Ok(())
    }

    #[test]
    fn window_frame_and_output_limits_are_enforced_before_or_during_decode() -> Result<()> {
        let mut unknown_size = Vec::new();
        unknown_size.extend_from_slice(&super::ZSTANDARD_MAGIC.to_le_bytes());
        unknown_size.extend_from_slice(&[0, 0, 1, 0, 0]);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            CompressedStream::open_bytes_as(
                unknown_size,
                StreamFormat::Zstandard,
                Limits::builder().max_dictionary_bytes(1023).build(),
                &cancellation,
                &mut budget,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                requested: 1024,
                maximum: 1023,
            })
        ));

        let bytes = raw_frame(b"bounded", false)?;
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes,
            StreamFormat::Zstandard,
            Limits::builder().max_total_output_bytes(6).build(),
            &cancellation,
            &mut budget,
        );
        assert!(matches!(
            stream,
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 7,
                maximum: 6,
            })
        ));
        Ok(())
    }

    #[test]
    fn total_frame_limit_counts_skippable_frames() -> Result<()> {
        let mut bytes = raw_frame(b"one", false)?;
        bytes.extend_from_slice(&0x184d_2a50_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&raw_frame(b"two", false)?);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            CompressedStream::open_bytes_as(
                bytes,
                StreamFormat::Zstandard,
                Limits::builder().max_stream_frames(2).build(),
                &cancellation,
                &mut budget,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::StreamFrames,
                requested: 3,
                maximum: 2,
            })
        ));
        Ok(())
    }
}
