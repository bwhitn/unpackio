//! Bounded WinZip WavPack (ZIP method 97) adapter.
//!
//! PKWARE APPNOTE 5.9 defines the method payload as a complete WavPack stream.
//! WinZip's documented profile uses the legacy WavPack 4 stream, lossless
//! RIFF/WAVE input, and exact wrapper preservation. A decoder-only local fork
//! pinned to the last permissively licensed `wavicle` release is called one
//! bounded block at a time behind structural, allocation, work, cancellation,
//! and panic guards. `PROVENANCE.md` records the exact specifications, source
//! revisions, package checksum, patches, and audit boundary.

use std::panic::{AssertUnwindSafe, catch_unwind};

use wavicle::{
    DecodedStream,
    error::{Error as WavicleError, Scope as WavicleScope},
};

use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, format_error, try_reserve, usize_to_u64},
};

const HEADER_LEN: usize = 32;
const MIN_STREAM_VERSION: u16 = 0x0402;
const WINZIP_STREAM_VERSION: u16 = 0x0407;
const MAX_BLOCK_BYTES: u64 = 1 << 20;
const MAX_BLOCK_SAMPLES: u32 = 131_072;
const MAX_WINZIP_CHANNELS: u16 = 16;
const MAX_DECORRELATION_TERMS: usize = 16;
const FIXED_DECODER_WORKING_BYTES: u64 = 8 * 1024;

const FLAG_BYTES_STORED: u32 = 0x3;
const FLAG_MONO: u32 = 0x4;
const FLAG_HYBRID: u32 = 0x8;
const FLAG_HYBRID_SHAPE: u32 = 0x40;
const FLAG_FLOAT: u32 = 0x80;
const FLAG_HYBRID_BITRATE: u32 = 0x200;
const FLAG_HYBRID_BALANCE: u32 = 0x400;
const FLAG_INITIAL: u32 = 0x800;
const FLAG_FINAL: u32 = 0x1000;
const FLAG_SHIFT_MASK: u32 = 0x1f << 13;
const FLAG_SAMPLE_RATE_MASK: u32 = 0xf << 23;
const FLAG_CHECKSUM: u32 = 0x1000_0000;
const FLAG_NEW_SHAPING: u32 = 0x2000_0000;
const FLAG_FALSE_STEREO: u32 = 0x4000_0000;
const FLAG_DSD: u32 = 0x8000_0000;

const META_ID_MASK: u8 = 0x3f;
const META_ODD_SIZE: u8 = 0x40;
const META_LARGE: u8 = 0x80;
const META_DUMMY: u8 = 0x00;
const META_ENCODER_INFO: u8 = 0x01;
const META_DECORR_TERMS: u8 = 0x02;
const META_DECORR_WEIGHTS: u8 = 0x03;
const META_DECORR_SAMPLES: u8 = 0x04;
const META_ENTROPY_VARS: u8 = 0x05;
const META_HYBRID_PROFILE: u8 = 0x06;
const META_SHAPING_WEIGHTS: u8 = 0x07;
const META_FLOAT_INFO: u8 = 0x08;
const META_INT32_INFO: u8 = 0x09;
const META_WV_BITSTREAM: u8 = 0x0a;
const META_WVC_BITSTREAM: u8 = 0x0b;
const META_WVX_BITSTREAM: u8 = 0x0c;
const META_CHANNEL_INFO: u8 = 0x0d;
const META_DSD_BLOCK: u8 = 0x0e;
const META_RIFF_HEADER: u8 = 0x21;
const META_RIFF_TRAILER: u8 = 0x22;
const META_ALT_HEADER: u8 = 0x23;
const META_ALT_TRAILER: u8 = 0x24;
const META_CONFIG_BLOCK: u8 = 0x25;
const META_MD5: u8 = 0x26;
const META_SAMPLE_RATE: u8 = 0x27;
const META_ALT_EXTENSION: u8 = 0x28;
const META_ALT_MD5: u8 = 0x29;
const META_NEW_CONFIG: u8 = 0x2a;
const META_CHANNEL_IDENTITIES: u8 = 0x2b;
const META_NEW_WVX: u8 = 0x2c;
const META_BLOCK_CHECKSUM: u8 = 0x2f;
const PATCHED_OPTIONAL_ID: u8 = 0x30;

#[derive(Clone, Copy)]
struct BlockHeader {
    version: u16,
    block_index: u64,
    total_samples: Option<u64>,
    block_samples: u32,
    flags: u32,
}

impl BlockHeader {
    fn bytes_per_sample(self) -> usize {
        match self.flags & FLAG_BYTES_STORED {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => 4,
        }
    }

    fn is_float(self) -> bool {
        self.flags & FLAG_FLOAT != 0
    }

    fn is_initial(self) -> bool {
        self.flags & FLAG_INITIAL != 0
    }

    fn is_final(self) -> bool {
        self.flags & FLAG_FINAL != 0
    }

    fn output_channels(self) -> u16 {
        if self.flags & FLAG_MONO != 0 { 1 } else { 2 }
    }

    fn format_signature(self) -> u32 {
        self.flags
            & (FLAG_BYTES_STORED | FLAG_FLOAT | 0x100 | FLAG_SHIFT_MASK | FLAG_SAMPLE_RATE_MASK)
    }
}

#[derive(Clone, Copy)]
struct Block<'input> {
    header: BlockHeader,
    raw: &'input [u8],
    metadata: &'input [u8],
}

#[derive(Clone, Copy, Default)]
struct MetadataSummary<'input> {
    riff_header: Option<&'input [u8]>,
    riff_trailer: Option<&'input [u8]>,
    channel_count: Option<u16>,
    stream_count: Option<u16>,
    channel_id_offset: Option<usize>,
    decorrelation_terms: usize,
    has_audio_metadata: bool,
}

fn unsupported(feature: &'static str) -> Error {
    Error::UnsupportedFeature {
        feature: String::from(feature),
    }
}

fn le_u16(bytes: &[u8], offset: usize, detail: &'static str) -> Result<u16> {
    let end = offset.checked_add(2).ok_or_else(|| format_error(detail))?;
    let raw = bytes.get(offset..end).ok_or_else(|| format_error(detail))?;
    let array = <[u8; 2]>::try_from(raw).map_err(|_| format_error(detail))?;
    Ok(u16::from_le_bytes(array))
}

fn le_u32(bytes: &[u8], offset: usize, detail: &'static str) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| format_error(detail))?;
    let raw = bytes.get(offset..end).ok_or_else(|| format_error(detail))?;
    let array = <[u8; 4]>::try_from(raw).map_err(|_| format_error(detail))?;
    Ok(u32::from_le_bytes(array))
}

fn parse_header(bytes: &[u8]) -> Result<(BlockHeader, usize)> {
    let fixed = bytes
        .get(..HEADER_LEN)
        .ok_or_else(|| format_error("ZIP WavPack block header is truncated"))?;
    if fixed.get(..4) != Some(b"wvpk".as_slice()) {
        return Err(format_error("ZIP WavPack block signature is invalid"));
    }
    let stored_size = le_u32(fixed, 4, "ZIP WavPack block size is truncated")?;
    let block_size = u64::from(stored_size)
        .checked_add(8)
        .ok_or_else(|| format_error("ZIP WavPack block size overflows"))?;
    if block_size < usize_to_u64(HEADER_LEN, "ZIP WavPack header size is invalid")?
        || block_size > MAX_BLOCK_BYTES
    {
        return Err(format_error("ZIP WavPack block size is invalid"));
    }
    let block_size = usize::try_from(block_size)
        .map_err(|_| format_error("ZIP WavPack block size is not representable"))?;
    let version = le_u16(fixed, 8, "ZIP WavPack stream version is truncated")?;
    if !(MIN_STREAM_VERSION..=WINZIP_STREAM_VERSION).contains(&version) {
        return Err(unsupported("zip-wavpack-non-winzip-stream-version"));
    }
    let block_index_high = u64::from(
        fixed
            .get(10)
            .copied()
            .ok_or_else(|| format_error("ZIP WavPack block index is truncated"))?,
    );
    let total_samples_high = u64::from(
        fixed
            .get(11)
            .copied()
            .ok_or_else(|| format_error("ZIP WavPack sample count is truncated"))?,
    );
    let total_samples_low = le_u32(fixed, 12, "ZIP WavPack sample count is truncated")?;
    let block_index = (block_index_high << 32)
        | u64::from(le_u32(fixed, 16, "ZIP WavPack block index is truncated")?);
    let total_samples = if total_samples_low == u32::MAX {
        None
    } else {
        Some(
            (total_samples_high << 32)
                .checked_sub(total_samples_high)
                .and_then(|value| value.checked_add(u64::from(total_samples_low)))
                .ok_or_else(|| format_error("ZIP WavPack sample count overflows"))?,
        )
    };
    let block_samples = le_u32(fixed, 20, "ZIP WavPack block sample count is truncated")?;
    if block_samples > MAX_BLOCK_SAMPLES {
        return Err(format_error(
            "ZIP WavPack block sample count exceeds the format maximum",
        ));
    }
    let flags = le_u32(fixed, 24, "ZIP WavPack flags are truncated")?;
    if flags
        & (FLAG_HYBRID
            | FLAG_HYBRID_SHAPE
            | FLAG_HYBRID_BITRATE
            | FLAG_HYBRID_BALANCE
            | FLAG_NEW_SHAPING)
        != 0
    {
        return Err(unsupported("zip-wavpack-hybrid"));
    }
    if flags & FLAG_DSD != 0 {
        return Err(unsupported("zip-wavpack-dsd"));
    }
    if flags & FLAG_CHECKSUM != 0 {
        return Err(unsupported("zip-wavpack-v5-block-checksum"));
    }
    if flags & FLAG_FALSE_STEREO != 0 {
        return Err(unsupported("zip-wavpack-mono-optimization"));
    }
    if flags & FLAG_FLOAT != 0 && (flags & FLAG_BYTES_STORED) != 3 {
        return Err(format_error(
            "ZIP WavPack floating-point samples must use four bytes",
        ));
    }
    Ok((
        BlockHeader {
            version,
            block_index,
            total_samples,
            block_samples,
            flags,
        },
        block_size,
    ))
}

fn parse_blocks<'input>(
    input: &'input [u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<Block<'input>>> {
    check_limit(
        usize_to_u64(
            input.len(),
            "ZIP WavPack input size is not representable as u64",
        )?,
        limits.max_total_input_bytes(),
        LimitKind::TotalInputBytes,
    )?;
    if input.is_empty() {
        return Err(format_error("ZIP WavPack stream is empty"));
    }
    let mut blocks = Vec::new();
    let mut position = 0_usize;
    while position < input.len() {
        let count = usize_to_u64(
            blocks
                .len()
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP WavPack block count overflows"))?,
            "ZIP WavPack block count is not representable as u64",
        )?;
        check_limit(count, limits.max_stream_frames(), LimitKind::StreamFrames)?;
        let remaining = input
            .get(position..)
            .ok_or_else(|| format_error("ZIP WavPack block position is invalid"))?;
        let (header, block_size) = parse_header(remaining)?;
        let end = position
            .checked_add(block_size)
            .ok_or_else(|| format_error("ZIP WavPack block range overflows"))?;
        let raw = input
            .get(position..end)
            .ok_or_else(|| format_error("ZIP WavPack block is truncated"))?;
        let metadata = raw
            .get(HEADER_LEN..)
            .ok_or_else(|| format_error("ZIP WavPack metadata range is invalid"))?;
        control.checkpoint(usize_to_u64(
            HEADER_LEN,
            "ZIP WavPack header work is not representable as u64",
        )?)?;
        try_reserve(&mut blocks, 1)?;
        blocks.push(Block {
            header,
            raw,
            metadata,
        });
        position = end;
    }
    Ok(blocks)
}

fn mark_unique(seen: &mut [bool; 15], id: u8) -> Result<()> {
    let slot = seen
        .get_mut(usize::from(id))
        .ok_or_else(|| format_error("ZIP WavPack metadata identifier is invalid"))?;
    if *slot {
        return Err(format_error("ZIP WavPack decoding metadata is duplicated"));
    }
    *slot = true;
    Ok(())
}

fn summarize_metadata<'input>(
    block: Block<'input>,
    property_count: &mut u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<MetadataSummary<'input>> {
    let mut summary = MetadataSummary::default();
    let mut seen = [false; 15];
    let mut position = 0_usize;
    while position < block.metadata.len() {
        *property_count = property_count
            .checked_add(1)
            .ok_or_else(|| format_error("ZIP WavPack metadata count overflows"))?;
        check_limit(
            *property_count,
            limits.max_header_properties(),
            LimitKind::HeaderProperties,
        )?;
        let raw_id = block
            .metadata
            .get(position)
            .copied()
            .ok_or_else(|| format_error("ZIP WavPack metadata identifier is truncated"))?;
        let id = raw_id & META_ID_MASK;
        let large = raw_id & META_LARGE != 0;
        let header_size = if large { 4_usize } else { 2_usize };
        let header_end = position
            .checked_add(header_size)
            .ok_or_else(|| format_error("ZIP WavPack metadata header overflows"))?;
        let header = block
            .metadata
            .get(position..header_end)
            .ok_or_else(|| format_error("ZIP WavPack metadata header is truncated"))?;
        let low = u32::from(
            header
                .get(1)
                .copied()
                .ok_or_else(|| format_error("ZIP WavPack metadata size is truncated"))?,
        );
        let words = if large {
            low | (u32::from(
                header
                    .get(2)
                    .copied()
                    .ok_or_else(|| format_error("ZIP WavPack metadata size is truncated"))?,
            ) << 8)
                | (u32::from(
                    header
                        .get(3)
                        .copied()
                        .ok_or_else(|| format_error("ZIP WavPack metadata size is truncated"))?,
                ) << 16)
        } else {
            low
        };
        let stored_size = usize::try_from(
            u64::from(words)
                .checked_mul(2)
                .ok_or_else(|| format_error("ZIP WavPack metadata size overflows"))?,
        )
        .map_err(|_| format_error("ZIP WavPack metadata size is not representable"))?;
        let stored_end = header_end
            .checked_add(stored_size)
            .ok_or_else(|| format_error("ZIP WavPack metadata range overflows"))?;
        let stored = block
            .metadata
            .get(header_end..stored_end)
            .ok_or_else(|| format_error("ZIP WavPack metadata payload is truncated"))?;
        let data = if raw_id & META_ODD_SIZE != 0 {
            let logical_size = stored_size
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP WavPack odd metadata size is invalid"))?;
            stored
                .get(..logical_size)
                .ok_or_else(|| format_error("ZIP WavPack metadata range is invalid"))?
        } else {
            stored
        };
        check_limit(
            usize_to_u64(
                data.len(),
                "ZIP WavPack metadata size is not representable as u64",
            )?,
            limits.max_coder_property_bytes(),
            LimitKind::CoderPropertyBytes,
        )?;
        let work = header_size
            .checked_add(data.len())
            .ok_or_else(|| format_error("ZIP WavPack metadata work overflows"))?;
        control.checkpoint(usize_to_u64(
            work,
            "ZIP WavPack metadata work is not representable as u64",
        )?)?;

        if (META_DECORR_TERMS..=META_DSD_BLOCK).contains(&id) {
            mark_unique(&mut seen, id)?;
            summary.has_audio_metadata = true;
        }
        match id {
            META_DUMMY | META_ENCODER_INFO | META_DECORR_WEIGHTS | META_DECORR_SAMPLES
            | META_ENTROPY_VARS | META_FLOAT_INFO | META_INT32_INFO | META_WV_BITSTREAM
            | META_WVX_BITSTREAM | META_CONFIG_BLOCK | META_MD5 => {}
            META_DECORR_TERMS => {
                if data.len() > MAX_DECORRELATION_TERMS {
                    return Err(format_error(
                        "ZIP WavPack decorrelation term count exceeds the format maximum",
                    ));
                }
                summary.decorrelation_terms = data.len();
            }
            META_HYBRID_PROFILE | META_SHAPING_WEIGHTS | META_WVC_BITSTREAM => {
                return Err(unsupported("zip-wavpack-hybrid"));
            }
            META_CHANNEL_INFO => {
                let first = data
                    .first()
                    .copied()
                    .ok_or_else(|| format_error("ZIP WavPack channel metadata is empty"))?;
                let (channels, streams, mask_bytes) = match data.len() {
                    1..=5 => (
                        u16::from(first),
                        None,
                        data.get(1..).ok_or_else(|| {
                            format_error("ZIP WavPack channel mask is unavailable")
                        })?,
                    ),
                    6 => {
                        let stream_low = data
                            .get(1)
                            .copied()
                            .ok_or_else(|| format_error("ZIP WavPack stream count is missing"))?;
                        let high = data.get(2).copied().ok_or_else(|| {
                            format_error("ZIP WavPack channel metadata is truncated")
                        })?;
                        let channels = (u16::from(first) | (u16::from(high & 0x0f) << 8))
                            .checked_add(1)
                            .ok_or_else(|| format_error("ZIP WavPack channel count overflows"))?;
                        let streams = (u16::from(stream_low) | (u16::from(high & 0xf0) << 4))
                            .checked_add(1)
                            .ok_or_else(|| format_error("ZIP WavPack stream count overflows"))?;
                        let twice_streams = streams
                            .checked_mul(2)
                            .ok_or_else(|| format_error("ZIP WavPack stream count overflows"))?;
                        if channels < streams || channels > twice_streams {
                            return Err(format_error(
                                "ZIP WavPack channel and stream counts are inconsistent",
                            ));
                        }
                        (
                            channels,
                            Some(streams),
                            data.get(3..).ok_or_else(|| {
                                format_error("ZIP WavPack channel mask is unavailable")
                            })?,
                        )
                    }
                    _ => return Err(unsupported("zip-wavpack-v5-channel-layout")),
                };
                if channels == 0 {
                    return Err(format_error("ZIP WavPack channel count is zero"));
                }
                if channels > MAX_WINZIP_CHANNELS {
                    return Err(unsupported("zip-wavpack-more-than-16-channels"));
                }
                let mask_channel_count = mask_bytes
                    .iter()
                    .try_fold(0_u32, |count, byte| count.checked_add(byte.count_ones()))
                    .ok_or_else(|| format_error("ZIP WavPack channel mask overflows"))?;
                if mask_channel_count > u32::from(channels) {
                    return Err(format_error(
                        "ZIP WavPack channel mask exceeds the channel count",
                    ));
                }
                summary.channel_count = Some(channels);
                summary.stream_count = streams;
                summary.channel_id_offset = Some(
                    HEADER_LEN
                        .checked_add(position)
                        .ok_or_else(|| format_error("ZIP WavPack metadata offset overflows"))?,
                );
            }
            META_DSD_BLOCK => return Err(unsupported("zip-wavpack-dsd")),
            META_RIFF_HEADER => {
                if summary.riff_header.replace(data).is_some() {
                    return Err(format_error("ZIP WavPack RIFF header is duplicated"));
                }
            }
            META_RIFF_TRAILER => {
                if summary.riff_trailer.replace(data).is_some() {
                    return Err(format_error("ZIP WavPack RIFF trailer is duplicated"));
                }
            }
            META_ALT_HEADER | META_ALT_TRAILER | META_ALT_EXTENSION | META_ALT_MD5 => {
                return Err(unsupported("zip-wavpack-non-riff-wrapper"));
            }
            META_SAMPLE_RATE => {
                if data.len() != 3 {
                    return Err(format_error("ZIP WavPack sample-rate metadata is invalid"));
                }
            }
            META_NEW_CONFIG | META_NEW_WVX | META_CHANNEL_IDENTITIES => {
                return Err(unsupported("zip-wavpack-v5-metadata"));
            }
            META_BLOCK_CHECKSUM => {
                return Err(unsupported("zip-wavpack-v5-block-checksum"));
            }
            required if required <= 0x1f => {
                return Err(unsupported("zip-wavpack-unknown-required-metadata"));
            }
            _ => {}
        }
        position = stored_end;
    }
    Ok(summary)
}

fn append_bounded(output: &mut Vec<u8>, bytes: &[u8], expected: u64, maximum: u64) -> Result<()> {
    let current = usize_to_u64(
        output.len(),
        "ZIP WavPack output size is not representable as u64",
    )?;
    let additional = usize_to_u64(
        bytes.len(),
        "ZIP WavPack output chunk is not representable as u64",
    )?;
    let next = current
        .checked_add(additional)
        .ok_or_else(|| format_error("ZIP WavPack output size overflows"))?;
    if next > expected {
        return Err(format_error(
            "ZIP WavPack output exceeds the ZIP size declaration",
        ));
    }
    check_limit(next, maximum, LimitKind::TotalOutputBytes)?;
    try_reserve(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_zeroed(output: &mut Vec<u8>, count: usize, expected: u64, maximum: u64) -> Result<usize> {
    let start = output.len();
    let next = start
        .checked_add(count)
        .ok_or_else(|| format_error("ZIP WavPack output size overflows"))?;
    let next_u64 = usize_to_u64(next, "ZIP WavPack output size is not representable as u64")?;
    if next_u64 > expected {
        return Err(format_error(
            "ZIP WavPack samples exceed the ZIP size declaration",
        ));
    }
    check_limit(next_u64, maximum, LimitKind::TotalOutputBytes)?;
    try_reserve(output, count)?;
    output.resize(next, 0);
    Ok(start)
}

fn validate_wave_format(
    data: &[u8],
    channels: u16,
    bytes_per_sample: usize,
    is_float: bool,
) -> Result<()> {
    if data.len() < 16 {
        return Err(format_error("ZIP WavPack RIFF format chunk is truncated"));
    }
    let tag = le_u16(data, 0, "ZIP WavPack RIFF format tag is truncated")?;
    let wave_channels = le_u16(data, 2, "ZIP WavPack RIFF channel count is truncated")?;
    let block_align = le_u16(data, 12, "ZIP WavPack RIFF block alignment is truncated")?;
    let container_bits = le_u16(data, 14, "ZIP WavPack RIFF sample width is truncated")?;
    let expected_align = u16::try_from(
        usize::from(channels)
            .checked_mul(bytes_per_sample)
            .ok_or_else(|| format_error("ZIP WavPack RIFF block alignment overflows"))?,
    )
    .map_err(|_| format_error("ZIP WavPack RIFF block alignment is invalid"))?;
    let expected_bits = u16::try_from(
        bytes_per_sample
            .checked_mul(8)
            .ok_or_else(|| format_error("ZIP WavPack sample width overflows"))?,
    )
    .map_err(|_| format_error("ZIP WavPack sample width is invalid"))?;
    if wave_channels != channels || block_align != expected_align || container_bits != expected_bits
    {
        return Err(format_error(
            "ZIP WavPack stream disagrees with its RIFF format",
        ));
    }
    let actual_tag = if tag == 0xfffe {
        if data.len() < 40
            || le_u16(data, 16, "ZIP WavPack extensible format size is truncated")? < 22
        {
            return Err(format_error(
                "ZIP WavPack extensible RIFF format is truncated",
            ));
        }
        let valid_bits = le_u16(data, 18, "ZIP WavPack valid sample width is truncated")?;
        if valid_bits == 0 || valid_bits > container_bits {
            return Err(format_error("ZIP WavPack valid sample width is invalid"));
        }
        let guid_tail = data
            .get(28..40)
            .ok_or_else(|| format_error("ZIP WavPack RIFF subtype is truncated"))?;
        if guid_tail
            != [
                0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
            ]
        {
            return Err(unsupported("zip-wavpack-non-pcm-wave-subtype"));
        }
        le_u32(data, 24, "ZIP WavPack RIFF subtype is truncated")?
    } else {
        u32::from(tag)
    };
    let expected_tag = if is_float { 3 } else { 1 };
    if actual_tag != expected_tag {
        return Err(unsupported("zip-wavpack-non-pcm-wave-subtype"));
    }
    Ok(())
}

fn validate_riff_header(
    header: &[u8],
    channels: u16,
    bytes_per_sample: usize,
    is_float: bool,
    sample_bytes: u64,
) -> Result<()> {
    if header.len() < 12
        || header.get(..4) != Some(b"RIFF".as_slice())
        || header.get(8..12) != Some(b"WAVE".as_slice())
    {
        return Err(unsupported("zip-wavpack-non-riff-wrapper"));
    }
    let expected_data_size =
        u32::try_from(sample_bytes).map_err(|_| unsupported("zip-wavpack-rf64-wrapper"))?;
    let mut position = 12_usize;
    let mut saw_format = false;
    while position < header.len() {
        let chunk_header_end = position
            .checked_add(8)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk range overflows"))?;
        let chunk_header = header
            .get(position..chunk_header_end)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk header is truncated"))?;
        let id = chunk_header
            .get(..4)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk identifier is truncated"))?;
        let size = usize::try_from(le_u32(
            chunk_header,
            4,
            "ZIP WavPack RIFF chunk size is truncated",
        )?)
        .map_err(|_| format_error("ZIP WavPack RIFF chunk size is not representable"))?;
        if id == b"data" {
            if !saw_format || chunk_header_end != header.len() {
                return Err(format_error(
                    "ZIP WavPack RIFF data chunk is not the wrapper boundary",
                ));
            }
            if u32::try_from(size).ok() != Some(expected_data_size) {
                return Err(format_error(
                    "ZIP WavPack RIFF data size disagrees with the stream",
                ));
            }
            return Ok(());
        }
        let data_end = chunk_header_end
            .checked_add(size)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk range overflows"))?;
        let padded_end = data_end
            .checked_add(size & 1)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk padding overflows"))?;
        let data = header
            .get(chunk_header_end..data_end)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk is truncated"))?;
        header
            .get(data_end..padded_end)
            .ok_or_else(|| format_error("ZIP WavPack RIFF chunk padding is truncated"))?;
        if id == b"fmt " {
            if saw_format {
                return Err(format_error("ZIP WavPack RIFF format is duplicated"));
            }
            validate_wave_format(data, channels, bytes_per_sample, is_float)?;
            saw_format = true;
        }
        position = padded_end;
    }
    Err(format_error("ZIP WavPack RIFF data chunk is missing"))
}

fn map_wavicle_error(error: WavicleError) -> Error {
    match error {
        WavicleError::CrcMismatch { .. } => Error::Checksum {
            scope: ChecksumScope::PackedStream,
            member_index: None,
        },
        WavicleError::OutOfScope(scope) => match scope {
            WavicleScope::Dsd => unsupported("zip-wavpack-dsd"),
            WavicleScope::Hybrid | WavicleScope::CorrectionFile => {
                unsupported("zip-wavpack-hybrid")
            }
            WavicleScope::MoreThanTwoChannels | WavicleScope::MultichannelSpanning => {
                unsupported("zip-wavpack-unhandled-channel-layout")
            }
        },
        WavicleError::UnsupportedVersion(_) => unsupported("zip-wavpack-non-winzip-stream-version"),
        WavicleError::NotYetImplemented(_) => unsupported("zip-wavpack-codec-feature"),
        WavicleError::AllocationFailed { .. } => Error::Io(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "ZIP WavPack decoder allocation failed",
        )),
        _ => format_error("ZIP WavPack decoder rejected the block"),
    }
}

fn decode_block(
    block: Block<'_>,
    summary: MetadataSummary<'_>,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<DecodedStream> {
    let frame_count = u64::from(block.header.block_samples);
    let channel_count = u64::from(block.header.output_channels());
    let sample_values = frame_count
        .checked_mul(channel_count)
        .ok_or_else(|| format_error("ZIP WavPack sample count overflows"))?;
    let raw_size = usize_to_u64(block.raw.len(), "ZIP WavPack block size is invalid")?;
    let sample_storage = frame_count
        .checked_mul(16)
        .and_then(|value| value.checked_add(raw_size))
        .and_then(|value| value.checked_add(FIXED_DECODER_WORKING_BYTES))
        .ok_or_else(|| format_error("ZIP WavPack decoder memory accounting overflows"))?;
    check_limit(
        sample_storage,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let pass_work = usize_to_u64(
        summary.decorrelation_terms,
        "ZIP WavPack decorrelation term count is not representable",
    )?
    .checked_add(64)
    .ok_or_else(|| format_error("ZIP WavPack decoder work accounting overflows"))?;
    let work = sample_values
        .checked_mul(pass_work)
        .and_then(|value| value.checked_add(raw_size))
        .ok_or_else(|| format_error("ZIP WavPack decoder work accounting overflows"))?;
    control.checkpoint(work)?;

    let sample_rate_index = (block.header.flags & FLAG_SAMPLE_RATE_MASK) >> 23;
    let patch_channel = summary.channel_count.is_some_and(|channels| channels > 2);
    let needs_patch =
        block.header.bytes_per_sample() == 1 || sample_rate_index == 0xf || patch_channel;
    let mut patched = Vec::new();
    let decoder_input = if needs_patch {
        try_reserve(&mut patched, block.raw.len())?;
        patched.extend_from_slice(block.raw);
        let mut flags = block.header.flags;
        if block.header.bytes_per_sample() == 1 {
            // The admitted decoder's residual path is sample-width agnostic;
            // its public driver rejects 8-bit solely as a declared-scope gate.
            // Presenting a 16-bit container flag bypasses that gate without
            // changing entropy, decorrelation, fixup, or sample CRC semantics.
            flags = (flags & !FLAG_BYTES_STORED) | 1;
        }
        if sample_rate_index == 0xf {
            // Sample rate is metadata only and does not participate in decode.
            flags = (flags & !FLAG_SAMPLE_RATE_MASK) | (9 << 23);
        }
        let flag_bytes = patched
            .get_mut(24..28)
            .ok_or_else(|| format_error("ZIP WavPack patched flags are unavailable"))?;
        flag_bytes.copy_from_slice(&flags.to_le_bytes());
        if patch_channel {
            let offset = summary
                .channel_id_offset
                .ok_or_else(|| format_error("ZIP WavPack channel metadata offset is missing"))?;
            let raw_id = patched
                .get_mut(offset)
                .ok_or_else(|| format_error("ZIP WavPack channel metadata is unavailable"))?;
            *raw_id = (*raw_id & (META_ODD_SIZE | META_LARGE)) | PATCHED_OPTIONAL_ID;
        }
        patched.as_slice()
    } else {
        block.raw
    };

    let decoded = catch_unwind(AssertUnwindSafe(|| wavicle::decode_stream(decoder_input)))
        .map_err(|_| format_error("ZIP WavPack decoder panicked"))?
        .map_err(map_wavicle_error)?;
    control.checkpoint(0)?;
    if decoded.channels != u32::from(block.header.output_channels()) {
        return Err(format_error(
            "ZIP WavPack decoder returned an invalid channel count",
        ));
    }
    let expected_values = usize::try_from(sample_values)
        .map_err(|_| format_error("ZIP WavPack sample count is not representable"))?;
    if decoded.samples.len() != expected_values {
        return Err(format_error(
            "ZIP WavPack decoder returned an invalid sample count",
        ));
    }
    Ok(decoded)
}

fn write_stream_samples(
    output: &mut [u8],
    samples: &[i32],
    frames: usize,
    stream_channels: usize,
    total_channels: usize,
    channel_offset: usize,
    bytes_per_sample: usize,
) -> Result<()> {
    let expected_values = frames
        .checked_mul(stream_channels)
        .ok_or_else(|| format_error("ZIP WavPack sample count overflows"))?;
    if samples.len() != expected_values {
        return Err(format_error("ZIP WavPack sample count is invalid"));
    }
    for frame in 0..frames {
        for channel in 0..stream_channels {
            let source_index = frame
                .checked_mul(stream_channels)
                .and_then(|value| value.checked_add(channel))
                .ok_or_else(|| format_error("ZIP WavPack source sample index overflows"))?;
            let destination_sample = frame
                .checked_mul(total_channels)
                .and_then(|value| value.checked_add(channel_offset))
                .and_then(|value| value.checked_add(channel))
                .ok_or_else(|| format_error("ZIP WavPack output sample index overflows"))?;
            let destination = destination_sample
                .checked_mul(bytes_per_sample)
                .ok_or_else(|| format_error("ZIP WavPack output byte index overflows"))?;
            let destination_end = destination
                .checked_add(bytes_per_sample)
                .ok_or_else(|| format_error("ZIP WavPack output sample range overflows"))?;
            let sample = samples
                .get(source_index)
                .copied()
                .ok_or_else(|| format_error("ZIP WavPack source sample is unavailable"))?;
            let bytes = output
                .get_mut(destination..destination_end)
                .ok_or_else(|| format_error("ZIP WavPack output sample is unavailable"))?;
            if bytes_per_sample == 1 {
                let byte = bytes
                    .first_mut()
                    .ok_or_else(|| format_error("ZIP WavPack output byte is unavailable"))?;
                let unsigned = sample
                    .checked_add(0x80)
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| format_error("ZIP WavPack 8-bit sample is out of range"))?;
                *byte = unsigned;
            } else {
                let source = sample.to_le_bytes();
                let source = source
                    .get(..bytes_per_sample)
                    .ok_or_else(|| format_error("ZIP WavPack sample width is invalid"))?;
                bytes.copy_from_slice(source);
            }
        }
    }
    Ok(())
}

/// Decodes one complete WavPack stream carried by ZIP method 97.
pub(crate) fn decode_zip_wavpack(
    input: &[u8],
    expected: u64,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(expected, maximum, LimitKind::TotalOutputBytes)?;
    let blocks = parse_blocks(input, limits, control)?;
    let version = blocks
        .first()
        .map(|block| block.header.version)
        .ok_or_else(|| format_error("ZIP WavPack stream contains no blocks"))?;
    if blocks.iter().any(|block| block.header.version != version) {
        return Err(format_error("ZIP WavPack stream version changes"));
    }
    let mut summaries = Vec::new();
    try_reserve(&mut summaries, blocks.len())?;
    let mut property_count = 0_u64;
    for block in &blocks {
        summaries.push(summarize_metadata(
            *block,
            &mut property_count,
            limits,
            control,
        )?);
    }

    let mut output = Vec::new();
    let mut position = 0_usize;
    let mut saw_audio = false;
    let mut decoded_frames = 0_u64;
    let mut total_samples: Option<u64> = None;
    let mut channel_count: Option<u16> = None;
    let mut channel_stream_count: Option<u16> = None;
    let mut format_signature: Option<u32> = None;
    let mut bytes_per_sample: Option<usize> = None;
    let mut floating_point: Option<bool> = None;
    let mut stream_version: Option<u16> = None;
    let mut audio_stream_count = 0_u64;

    while position < blocks.len() {
        let block = *blocks
            .get(position)
            .ok_or_else(|| format_error("ZIP WavPack block is unavailable"))?;
        let summary = *summaries
            .get(position)
            .ok_or_else(|| format_error("ZIP WavPack metadata summary is unavailable"))?;
        if block.header.block_samples == 0 {
            if summary.has_audio_metadata {
                return Err(format_error(
                    "ZIP WavPack metadata-only block contains audio coding data",
                ));
            }
            if let Some(header) = summary.riff_header {
                if saw_audio {
                    return Err(format_error("ZIP WavPack RIFF header follows audio"));
                }
                append_bounded(&mut output, header, expected, maximum)?;
            }
            if let Some(trailer) = summary.riff_trailer {
                if !saw_audio || Some(decoded_frames) != total_samples {
                    return Err(format_error("ZIP WavPack RIFF trailer precedes audio end"));
                }
                append_bounded(&mut output, trailer, expected, maximum)?;
            }
            position = position
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP WavPack block position overflows"))?;
            continue;
        }

        if !block.header.is_initial() {
            return Err(format_error(
                "ZIP WavPack channel group lacks an initial block",
            ));
        }
        if block.header.block_index != decoded_frames {
            return Err(format_error("ZIP WavPack audio blocks are not contiguous"));
        }
        let group_frames = block.header.block_samples;
        let group_index = block.header.block_index;
        let mut group_end = position;
        let mut group_channels = 0_u16;
        let mut group_streams = 0_u16;
        let mut group_channel_declaration = None;
        let mut group_stream_declaration = None;
        let mut first = true;
        loop {
            let channel_block = *blocks
                .get(group_end)
                .ok_or_else(|| format_error("ZIP WavPack channel group is truncated"))?;
            let channel_summary = *summaries
                .get(group_end)
                .ok_or_else(|| format_error("ZIP WavPack metadata summary is unavailable"))?;
            if channel_block.header.block_samples == 0
                || channel_block.header.block_index != group_index
                || channel_block.header.block_samples != group_frames
            {
                return Err(format_error("ZIP WavPack channel group is inconsistent"));
            }
            if channel_block.header.is_initial() != first {
                return Err(format_error(
                    "ZIP WavPack channel group has invalid boundary flags",
                ));
            }
            if channel_block.header.version != block.header.version
                || channel_block.header.format_signature() != block.header.format_signature()
            {
                return Err(format_error(
                    "ZIP WavPack channel group changes the audio format",
                ));
            }
            if let Some(declared) = channel_summary.channel_count {
                if !first || group_channel_declaration.replace(declared).is_some() {
                    return Err(format_error("ZIP WavPack channel declaration is misplaced"));
                }
                group_stream_declaration = channel_summary.stream_count;
            }
            group_channels = group_channels
                .checked_add(channel_block.header.output_channels())
                .ok_or_else(|| format_error("ZIP WavPack channel count overflows"))?;
            group_streams = group_streams
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP WavPack stream count overflows"))?;
            audio_stream_count = audio_stream_count
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP WavPack stream count overflows"))?;
            check_limit(
                audio_stream_count,
                limits.max_total_streams(),
                LimitKind::TotalStreams,
            )?;
            if channel_block.header.is_final() {
                group_end = group_end
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP WavPack group range overflows"))?;
                break;
            }
            group_end = group_end
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP WavPack group range overflows"))?;
            first = false;
        }
        check_limit(
            u64::from(group_channels),
            limits.max_streams_per_folder(),
            LimitKind::StreamsPerFolder,
        )?;
        if group_stream_declaration.is_some_and(|declared| declared != group_streams) {
            return Err(format_error(
                "ZIP WavPack channel blocks disagree with their stream declaration",
            ));
        }
        if channel_stream_count.is_some_and(|previous| previous != group_streams) {
            return Err(format_error("ZIP WavPack channel stream count changes"));
        }
        channel_stream_count = Some(group_streams);

        let declared_total = block
            .header
            .total_samples
            .ok_or_else(|| unsupported("zip-wavpack-unknown-sample-count"))?;
        if declared_total == 0 {
            return Err(format_error("ZIP WavPack total sample count is zero"));
        }
        if let Some(previous) = total_samples {
            if previous != declared_total {
                return Err(format_error("ZIP WavPack total sample count changes"));
            }
        } else {
            total_samples = Some(declared_total);
        }
        let after_group = decoded_frames
            .checked_add(u64::from(group_frames))
            .ok_or_else(|| format_error("ZIP WavPack decoded sample count overflows"))?;
        if after_group > declared_total {
            return Err(format_error(
                "ZIP WavPack blocks exceed the total sample count",
            ));
        }

        for index in position..group_end {
            let channel_block = *blocks
                .get(index)
                .ok_or_else(|| format_error("ZIP WavPack channel block is unavailable"))?;
            if let Some(block_total) = channel_block.header.total_samples {
                if block_total != declared_total {
                    return Err(format_error("ZIP WavPack total sample count changes"));
                }
            }
            let channel_summary = *summaries
                .get(index)
                .ok_or_else(|| format_error("ZIP WavPack metadata summary is unavailable"))?;
            if let Some(header) = channel_summary.riff_header {
                if saw_audio {
                    return Err(format_error("ZIP WavPack RIFF header follows audio"));
                }
                append_bounded(&mut output, header, expected, maximum)?;
            }
            if channel_summary.riff_trailer.is_some() && after_group != declared_total {
                return Err(format_error("ZIP WavPack RIFF trailer precedes audio end"));
            }
        }

        let declared_channels = group_channel_declaration.or(channel_count);
        let effective_channels = declared_channels.unwrap_or(group_channels);
        if effective_channels != group_channels {
            return Err(format_error(
                "ZIP WavPack channel blocks disagree with their declaration",
            ));
        }
        if channel_count.is_some_and(|previous| previous != effective_channels) {
            return Err(format_error("ZIP WavPack channel count changes"));
        }
        channel_count = Some(effective_channels);
        if group_channels > 2 && group_channel_declaration.is_none() && !saw_audio {
            return Err(format_error(
                "ZIP WavPack multichannel stream lacks channel metadata",
            ));
        }

        let group_bytes_per_sample = block.header.bytes_per_sample();
        let group_float = block.header.is_float();
        if format_signature.is_some_and(|seen| seen != block.header.format_signature())
            || bytes_per_sample.is_some_and(|seen| seen != group_bytes_per_sample)
            || floating_point.is_some_and(|seen| seen != group_float)
            || stream_version.is_some_and(|seen| seen != block.header.version)
        {
            return Err(format_error("ZIP WavPack audio format changes"));
        }
        format_signature = Some(block.header.format_signature());
        bytes_per_sample = Some(group_bytes_per_sample);
        floating_point = Some(group_float);
        stream_version = Some(block.header.version);

        if !saw_audio {
            let sample_bytes = declared_total
                .checked_mul(u64::from(effective_channels))
                .and_then(|value| value.checked_mul(u64::try_from(group_bytes_per_sample).ok()?))
                .ok_or_else(|| format_error("ZIP WavPack output sample size overflows"))?;
            if sample_bytes > expected {
                return Err(format_error(
                    "ZIP WavPack samples exceed the ZIP size declaration",
                ));
            }
            validate_riff_header(
                &output,
                effective_channels,
                group_bytes_per_sample,
                group_float,
                sample_bytes,
            )?;
            saw_audio = true;
        }

        let group_byte_count = usize::try_from(
            u64::from(group_frames)
                .checked_mul(u64::from(effective_channels))
                .and_then(|value| value.checked_mul(u64::try_from(group_bytes_per_sample).ok()?))
                .ok_or_else(|| format_error("ZIP WavPack group size overflows"))?,
        )
        .map_err(|_| format_error("ZIP WavPack group size is not representable"))?;
        let group_start = append_zeroed(&mut output, group_byte_count, expected, maximum)?;
        let group_end_offset = group_start
            .checked_add(group_byte_count)
            .ok_or_else(|| format_error("ZIP WavPack group output range overflows"))?;
        let group_output = output
            .get_mut(group_start..group_end_offset)
            .ok_or_else(|| format_error("ZIP WavPack group output is unavailable"))?;
        let mut channel_offset = 0_usize;
        for index in position..group_end {
            let channel_block = *blocks
                .get(index)
                .ok_or_else(|| format_error("ZIP WavPack channel block is unavailable"))?;
            let channel_summary = *summaries
                .get(index)
                .ok_or_else(|| format_error("ZIP WavPack metadata summary is unavailable"))?;
            let decoded = decode_block(channel_block, channel_summary, limits, control)?;
            let stream_channels = usize::try_from(decoded.channels)
                .map_err(|_| format_error("ZIP WavPack channel count is not representable"))?;
            write_stream_samples(
                group_output,
                &decoded.samples,
                usize::try_from(group_frames)
                    .map_err(|_| format_error("ZIP WavPack frame count is not representable"))?,
                stream_channels,
                usize::from(effective_channels),
                channel_offset,
                group_bytes_per_sample,
            )?;
            channel_offset = channel_offset
                .checked_add(stream_channels)
                .ok_or_else(|| format_error("ZIP WavPack channel offset overflows"))?;
        }
        if channel_offset != usize::from(effective_channels) {
            return Err(format_error("ZIP WavPack channel group is incomplete"));
        }
        decoded_frames = after_group;

        for index in position..group_end {
            let channel_summary = *summaries
                .get(index)
                .ok_or_else(|| format_error("ZIP WavPack metadata summary is unavailable"))?;
            if let Some(trailer) = channel_summary.riff_trailer {
                append_bounded(&mut output, trailer, expected, maximum)?;
            }
        }
        position = group_end;
    }

    if !saw_audio {
        return Err(format_error("ZIP WavPack stream contains no audio"));
    }
    if Some(decoded_frames) != total_samples {
        return Err(format_error(
            "ZIP WavPack stream ends before its sample count",
        ));
    }
    let actual = usize_to_u64(
        output.len(),
        "ZIP WavPack output size is not representable as u64",
    )?;
    if actual != expected {
        return Err(format_error(
            "ZIP WavPack output size differs from the ZIP declaration",
        ));
    }
    let riff_size = le_u32(&output, 4, "ZIP WavPack RIFF size is truncated")?;
    let expected_riff_size = actual
        .checked_sub(8)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| unsupported("zip-wavpack-rf64-wrapper"))?;
    if riff_size != expected_riff_size {
        return Err(format_error(
            "ZIP WavPack RIFF size disagrees with the reconstructed output",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::write_stream_samples;

    #[test]
    fn eight_bit_sample_conversion_is_checked() {
        let mut output = [0_u8; 2];
        assert!(write_stream_samples(&mut output, &[-128, 127], 2, 1, 1, 0, 1).is_ok());
        assert_eq!(output, [0, 255]);

        let mut invalid = [0_u8; 1];
        assert!(write_stream_samples(&mut invalid, &[128], 1, 1, 1, 0, 1).is_err());
        assert!(write_stream_samples(&mut invalid, &[-129], 1, 1, 1, 0, 1).is_err());
    }
}
