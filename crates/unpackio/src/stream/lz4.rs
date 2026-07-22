//! Validated LZ4 frame layout and bounded extraction.

use std::{cell::Cell, hash::Hasher, io::Write};

use twox_hash::XxHash32;

use super::{
    ControlledInput, ExtractionControl, LZ4_LEGACY_MAGIC, LZ4_MAGIC, Lz4StreamInfo,
    SKIPPABLE_MAGIC_END, SKIPPABLE_MAGIC_START, check_frame_count, cursor::StreamCursor,
    pump_reader, push_layout, stream_checksum_error, stream_format_error,
    unsupported_stream_feature,
};
use crate::{LimitKind, Limits, Result, parse_util::check_limit};

const LEGACY_BLOCK_BYTES: u64 = 8 * 1024 * 1024;
const LZ4_HISTORY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy)]
struct Lz4Frame {
    start: usize,
    end: usize,
    content_size: Option<u64>,
    checksum: bool,
    dictionary: bool,
    working_bytes: u64,
}

pub(super) struct Lz4Layout {
    frames: Vec<Lz4Frame>,
}

impl Lz4Layout {
    pub(super) fn extract<W: Write>(
        &self,
        input: &[u8],
        control: &mut ExtractionControl<'_, W>,
    ) -> Result<()> {
        for (index, frame) in self.frames.iter().copied().enumerate() {
            let frame_index = u64::try_from(index)
                .map_err(|_| stream_format_error("lz4", "frame index is not representable"))?;
            control.checkpoint(0)?;
            check_limit(
                frame.working_bytes,
                control.limits().max_dictionary_bytes(),
                LimitKind::DictionaryBytes,
            )?;
            if frame.dictionary {
                return Err(unsupported_stream_feature("lz4", "external-dictionary"));
            }
            let frame_bytes = input.get(frame.start..frame.end).ok_or_else(|| {
                stream_format_error("lz4", "validated frame range is unavailable")
            })?;
            let consumed = Cell::new(0);
            let source = ControlledInput::new(frame_bytes, &consumed, control.cancellation_token());
            let mut reader = lz4_flex::frame::FrameDecoder::new(source);
            pump_reader(
                &mut reader,
                &consumed,
                frame.content_size,
                "lz4",
                frame_index,
                control,
                is_lz4_checksum_error,
            )?;
            if consumed.get() != frame_bytes.len() {
                return Err(stream_format_error(
                    "lz4",
                    "decoder did not consume exactly one frame",
                ));
            }
            control.finish_frame(frame.checksum)?;
        }
        Ok(())
    }
}

pub(super) fn parse(
    input: &[u8],
    limits: Limits,
) -> Result<(Lz4StreamInfo, Option<u64>, Lz4Layout)> {
    let mut cursor = StreamCursor::new(input, "lz4");
    let mut frames = Vec::new();
    let mut total_frames = 0_u64;
    let mut data_frames = 0_u64;
    let mut skippable_frames = 0_u64;
    let mut legacy_frames = 0_u64;
    let mut content_checksum_frames = 0_u64;
    let mut block_checksum_frames = 0_u64;
    let mut dictionary_frames = 0_u64;
    let mut maximum_block_bytes = 0_u64;
    let mut aggregate_size = Some(0_u64);

    while !cursor.remaining()?.is_empty() {
        total_frames = total_frames
            .checked_add(1)
            .ok_or_else(|| stream_format_error("lz4", "frame count overflows"))?;
        check_frame_count(total_frames, limits)?;
        let start = cursor.position();
        let magic = cursor.read_u32_le("frame magic is truncated")?;
        if (SKIPPABLE_MAGIC_START..=SKIPPABLE_MAGIC_END).contains(&magic) {
            let length = cursor.read_u32_le("skippable frame size is truncated")?;
            cursor.skip_u64(u64::from(length), "skippable frame payload is truncated")?;
            skippable_frames = skippable_frames
                .checked_add(1)
                .ok_or_else(|| stream_format_error("lz4", "skippable frame count overflows"))?;
            continue;
        }

        let parsed = match magic {
            LZ4_MAGIC => parse_standard_frame(&mut cursor, input, start, data_frames)?,
            LZ4_LEGACY_MAGIC => {
                legacy_frames = legacy_frames
                    .checked_add(1)
                    .ok_or_else(|| stream_format_error("lz4", "legacy frame count overflows"))?;
                parse_legacy_frame(&mut cursor, start)?
            }
            _ => return Err(stream_format_error("lz4", "unexpected frame magic")),
        };
        data_frames = data_frames
            .checked_add(1)
            .ok_or_else(|| stream_format_error("lz4", "data frame count overflows"))?;
        if parsed.content_checksum {
            content_checksum_frames = content_checksum_frames.checked_add(1).ok_or_else(|| {
                stream_format_error("lz4", "content-checksum frame count overflows")
            })?;
        }
        if parsed.block_checksums {
            block_checksum_frames = block_checksum_frames.checked_add(1).ok_or_else(|| {
                stream_format_error("lz4", "block-checksum frame count overflows")
            })?;
        }
        if parsed.dictionary {
            dictionary_frames = dictionary_frames
                .checked_add(1)
                .ok_or_else(|| stream_format_error("lz4", "dictionary frame count overflows"))?;
        }
        maximum_block_bytes = maximum_block_bytes.max(parsed.maximum_block_bytes);
        aggregate_size =
            match (aggregate_size, parsed.content_size) {
                (Some(total), Some(size)) => Some(total.checked_add(size).ok_or_else(|| {
                    stream_format_error("lz4", "aggregate content size overflows")
                })?),
                _ => None,
            };
        push_layout(
            &mut frames,
            Lz4Frame {
                start,
                end: cursor.position(),
                content_size: parsed.content_size,
                checksum: parsed.content_checksum || parsed.block_checksums,
                dictionary: parsed.dictionary,
                working_bytes: parsed.working_bytes,
            },
        )?;
    }

    if data_frames == 0 {
        return Err(stream_format_error("lz4", "stream contains no data frame"));
    }
    Ok((
        Lz4StreamInfo {
            frame_count: data_frames,
            skippable_frame_count: skippable_frames,
            legacy_frame_count: legacy_frames,
            content_checksum_frame_count: content_checksum_frames,
            block_checksum_frame_count: block_checksum_frames,
            dictionary_frame_count: dictionary_frames,
            maximum_block_bytes,
        },
        aggregate_size,
        Lz4Layout { frames },
    ))
}

struct ParsedFrame {
    content_size: Option<u64>,
    content_checksum: bool,
    block_checksums: bool,
    dictionary: bool,
    maximum_block_bytes: u64,
    working_bytes: u64,
}

fn parse_standard_frame(
    cursor: &mut StreamCursor<'_>,
    input: &[u8],
    start: usize,
    frame_index: u64,
) -> Result<ParsedFrame> {
    let descriptor_start = start
        .checked_add(4)
        .ok_or_else(|| stream_format_error("lz4", "descriptor offset overflows"))?;
    let flags = cursor.read_u8("frame flags are truncated")?;
    let block_descriptor = cursor.read_u8("block descriptor is truncated")?;
    if flags & 0xc0 != 0x40 {
        return Err(stream_format_error("lz4", "unsupported frame version"));
    }
    if flags & 0x02 != 0 || block_descriptor & 0x8f != 0 {
        return Err(stream_format_error(
            "lz4",
            "reserved descriptor bits are set",
        ));
    }
    let maximum_block_bytes = match (block_descriptor >> 4) & 0x07 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => return Err(stream_format_error("lz4", "invalid maximum block size")),
    };
    let content_size = if flags & 0x08 != 0 {
        Some(cursor.read_le(8, "content size is truncated")?)
    } else {
        None
    };
    let dictionary = flags & 0x01 != 0;
    if dictionary {
        cursor.read_u32_le("dictionary ID is truncated")?;
    }
    let checksum_position = cursor.position();
    let expected_header_checksum = cursor.read_u8("header checksum is truncated")?;
    let descriptor = input
        .get(descriptor_start..checksum_position)
        .ok_or_else(|| stream_format_error("lz4", "descriptor range is invalid"))?;
    let mut hasher = XxHash32::with_seed(0);
    hasher.write(descriptor);
    let calculated = u8::try_from((hasher.finish() >> 8) & 0xff)
        .map_err(|_| stream_format_error("lz4", "header checksum is not representable"))?;
    if calculated != expected_header_checksum {
        return Err(stream_checksum_error("lz4", frame_index));
    }

    let block_checksums = flags & 0x10 != 0;
    loop {
        let header = cursor.read_u32_le("block header is truncated")?;
        if header == 0 {
            break;
        }
        let block_size = u64::from(header & 0x7fff_ffff);
        if block_size == 0 {
            return Err(stream_format_error(
                "lz4",
                "non-end block has a zero payload size",
            ));
        }
        if block_size > maximum_block_bytes {
            return Err(stream_format_error(
                "lz4",
                "block exceeds the declared maximum size",
            ));
        }
        cursor.skip_u64(block_size, "block payload is truncated")?;
        if block_checksums {
            cursor.read_u32_le("block checksum is truncated")?;
        }
    }
    let content_checksum = flags & 0x04 != 0;
    if content_checksum {
        cursor.read_u32_le("content checksum is truncated")?;
    }
    let working_bytes = maximum_block_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(LZ4_HISTORY_BYTES))
        .ok_or_else(|| stream_format_error("lz4", "working memory size overflows"))?;
    Ok(ParsedFrame {
        content_size,
        content_checksum,
        block_checksums,
        dictionary,
        maximum_block_bytes,
        working_bytes,
    })
}

fn parse_legacy_frame(cursor: &mut StreamCursor<'_>, start: usize) -> Result<ParsedFrame> {
    loop {
        let remaining = cursor.remaining()?;
        if remaining.is_empty() {
            break;
        }
        let Some(next_bytes) = remaining.get(..4) else {
            return Err(stream_format_error(
                "lz4",
                "legacy block header is truncated",
            ));
        };
        let next = u32::from_le_bytes(
            <[u8; 4]>::try_from(next_bytes)
                .map_err(|_| stream_format_error("lz4", "legacy block header is truncated"))?,
        );
        if cursor.position() != start
            && matches!(
                next,
                LZ4_MAGIC | LZ4_LEGACY_MAGIC | SKIPPABLE_MAGIC_START..=SKIPPABLE_MAGIC_END
            )
        {
            break;
        }
        let block_size = cursor.read_u32_le("legacy block header is truncated")?;
        if block_size == 0 {
            break;
        }
        if u64::from(block_size) > LEGACY_BLOCK_BYTES {
            return Err(stream_format_error("lz4", "legacy block exceeds eight MiB"));
        }
        cursor.skip_u64(u64::from(block_size), "legacy block payload is truncated")?;
    }
    let working_bytes = LEGACY_BLOCK_BYTES
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(LZ4_HISTORY_BYTES))
        .ok_or_else(|| stream_format_error("lz4", "legacy working memory size overflows"))?;
    Ok(ParsedFrame {
        content_size: None,
        content_checksum: false,
        block_checksums: false,
        dictionary: false,
        maximum_block_bytes: LEGACY_BLOCK_BYTES,
        working_bytes,
    })
}

fn is_lz4_checksum_error(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<lz4_flex::frame::Error>())
        .is_some_and(|error| {
            matches!(
                error,
                lz4_flex::frame::Error::HeaderChecksumError
                    | lz4_flex::frame::Error::BlockChecksumError
                    | lz4_flex::frame::Error::ContentChecksumError
            )
        })
}

#[cfg(test)]
mod tests {
    use std::{hash::Hasher, io::Write};

    use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
    use twox_hash::XxHash32;

    use super::super::{CompressedStream, StreamFormat, StreamInfoKind};
    use crate::{CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget};

    fn encoded(plain: &[u8], checksum: bool) -> Result<Vec<u8>> {
        let info = FrameInfo::new()
            .content_size(Some(u64::try_from(plain.len()).map_err(|_| {
                super::stream_format_error("lz4", "test input length is not representable")
            })?))
            .content_checksum(checksum)
            .block_checksums(checksum)
            .block_mode(BlockMode::Linked)
            .block_size(BlockSize::Max64KB);
        let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
        encoder.write_all(plain).map_err(crate::Error::Io)?;
        encoder
            .finish()
            .map_err(|error| crate::Error::Io(error.into()))
    }

    fn legacy_encoded(plain: &[u8]) -> Result<Vec<u8>> {
        let block = lz4_flex::block::compress(plain);
        let block_size = u32::try_from(block.len()).map_err(|_| {
            super::stream_format_error("lz4", "test legacy block size is not representable")
        })?;
        let mut frame = Vec::new();
        frame.extend_from_slice(&super::LZ4_LEGACY_MAGIC.to_le_bytes());
        frame.extend_from_slice(&block_size.to_le_bytes());
        frame.extend_from_slice(&block);
        Ok(frame)
    }

    fn dictionary_frame(plain: &[u8]) -> Result<Vec<u8>> {
        let length = u64::try_from(plain.len()).map_err(|_| {
            super::stream_format_error("lz4", "test input length is not representable")
        })?;
        let block_length = u32::try_from(plain.len()).map_err(|_| {
            super::stream_format_error("lz4", "test block length is not representable")
        })?;
        let block_header =
            block_length
                .checked_add(1_u32.checked_shl(31).ok_or_else(|| {
                    super::stream_format_error("lz4", "test block flag overflows")
                })?)
                .ok_or_else(|| super::stream_format_error("lz4", "test block header overflows"))?;
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&[0x49, 0x40]);
        descriptor.extend_from_slice(&length.to_le_bytes());
        descriptor.extend_from_slice(&7_u32.to_le_bytes());
        let mut hasher = XxHash32::with_seed(0);
        hasher.write(&descriptor);
        let header_checksum = u8::try_from((hasher.finish() >> 8) & 0xff).map_err(|_| {
            super::stream_format_error("lz4", "test header checksum is not representable")
        })?;
        let mut frame = Vec::new();
        frame.extend_from_slice(&super::LZ4_MAGIC.to_le_bytes());
        frame.extend_from_slice(&descriptor);
        frame.push(header_checksum);
        frame.extend_from_slice(&block_header.to_le_bytes());
        frame.extend_from_slice(plain);
        frame.extend_from_slice(&0_u32.to_le_bytes());
        Ok(frame)
    }

    #[test]
    fn complete_checked_frame_reports_info_and_extracts() -> Result<()> {
        let bytes = encoded(b"standalone lz4", true)?;
        let cancellation = CancellationToken::new();
        let mut open_budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes(
            bytes,
            Limits::default(),
            &cancellation,
            &mut open_budget,
        )?;
        assert_eq!(stream.info().format(), StreamFormat::Lz4);
        assert_eq!(stream.info().uncompressed_size(), Some(14));
        let StreamInfoKind::Lz4(info) = stream.info().kind() else {
            return Err(super::stream_format_error("lz4", "wrong test info kind"));
        };
        assert_eq!(info.frame_count(), 1);
        assert_eq!(info.content_checksum_frame_count(), 1);
        assert_eq!(info.block_checksum_frame_count(), 1);
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            b"standalone lz4"
        );
        Ok(())
    }

    #[test]
    fn corruption_and_every_truncation_fail() -> Result<()> {
        let bytes = encoded(b"checked lz4 payload", true)?;
        for length in 0..bytes.len() {
            let prefix = bytes
                .get(..length)
                .ok_or_else(|| super::stream_format_error("lz4", "test prefix range is invalid"))?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            assert!(
                CompressedStream::open_bytes_as(
                    prefix.to_vec(),
                    StreamFormat::Lz4,
                    Limits::default(),
                    &cancellation,
                    &mut budget,
                )
                .is_err()
            );
        }

        let mut corrupt = bytes;
        let payload_index = corrupt
            .iter()
            .position(|byte| *byte == b'c')
            .ok_or_else(|| super::stream_format_error("lz4", "test payload byte is missing"))?;
        let byte = corrupt
            .get_mut(payload_index)
            .ok_or_else(|| super::stream_format_error("lz4", "test payload byte is unavailable"))?;
        *byte ^= 1;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            corrupt,
            StreamFormat::Lz4,
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

        let invalid_empty_block = vec![
            0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            CompressedStream::open_bytes_as(
                invalid_empty_block,
                StreamFormat::Lz4,
                Limits::default(),
                &cancellation,
                &mut budget,
            ),
            Err(Error::StreamFormat { .. })
        ));
        Ok(())
    }

    #[test]
    fn concatenated_skippable_legacy_and_frame_limits_are_validated() -> Result<()> {
        let mut bytes = encoded(b"first", false)?;
        bytes.extend_from_slice(&0x184d_2a50_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(b"tag");
        bytes.extend_from_slice(&legacy_encoded(b" legacy")?);

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes.clone(),
            StreamFormat::Lz4,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let StreamInfoKind::Lz4(info) = stream.info().kind() else {
            return Err(super::stream_format_error("lz4", "wrong test info kind"));
        };
        assert_eq!(info.frame_count(), 2);
        assert_eq!(info.skippable_frame_count(), 1);
        assert_eq!(info.legacy_frame_count(), 1);
        let mut extraction_budget = WorkBudget::unlimited();
        assert_eq!(
            stream.decompress(&cancellation, &mut extraction_budget)?,
            b"first legacy"
        );

        let mut limited_budget = WorkBudget::unlimited();
        assert!(matches!(
            CompressedStream::open_bytes_as(
                bytes,
                StreamFormat::Lz4,
                Limits::builder().max_stream_frames(2).build(),
                &cancellation,
                &mut limited_budget,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::StreamFrames,
                requested: 3,
                maximum: 2,
            })
        ));
        Ok(())
    }

    #[test]
    fn dictionary_frames_list_but_extract_as_typed_unsupported() -> Result<()> {
        let bytes = dictionary_frame(b"dictionary")?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let stream = CompressedStream::open_bytes_as(
            bytes,
            StreamFormat::Lz4,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let StreamInfoKind::Lz4(info) = stream.info().kind() else {
            return Err(super::stream_format_error("lz4", "wrong test info kind"));
        };
        assert_eq!(info.dictionary_frame_count(), 1);
        let mut extraction_budget = WorkBudget::unlimited();
        assert!(matches!(
            stream.verify(&cancellation, &mut extraction_budget),
            Err(Error::UnsupportedStreamFeature { format, feature })
                if format == "lz4" && feature == "external-dictionary"
        ));
        Ok(())
    }
}
