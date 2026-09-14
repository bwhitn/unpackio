//! Checked XZ container preflight and bounded LZMA2 block decoding.
//!
//! The container rules are independently expressed from the public-domain XZ
//! 1.0.4 format document recorded in `PROVENANCE.md`. LZMA2 entropy decoding
//! and size-preserving filters reuse the existing checked, fallibly allocating
//! in-tree implementations.

use sha2::{Digest, Sha256};

use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    checksum::Crc32,
    decode::{
        METHOD_ARM, METHOD_ARM_THUMB, METHOD_ARM64, METHOD_BCJ, METHOD_DELTA, METHOD_IA64,
        METHOD_PPC, METHOD_RISCV, METHOD_SPARC, decode_filter_in_place, decode_lzma2,
    },
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, try_reserve, usize_to_u64,
    },
};

const XZ_HEADER_BYTES: u64 = 12;
const XZ_FOOTER_BYTES: u64 = 12;
const XZ_MINIMUM_STREAM_BYTES: u64 = 32;
const XZ_MAGIC: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0];
const XZ_INTERNAL_FILTER_ID_START: u64 = 1_u64 << 62;
const XZ_MAX_FILTERS: usize = 4;
const CRC64_XZ_POLYNOMIAL: u64 = 0xc96c_5795_d787_0f42;

/// The enclosing format controls diagnostics, checksum scope, and the WinZip
/// method-95 restriction to at most one prefilter from XZ 1.0.4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XzProfile {
    PackagePayload,
    ZipMember { member_index: u64 },
}

impl XzProfile {
    fn format(self, detail: &'static str) -> Error {
        let prefix = match self {
            Self::PackagePayload => "package XZ",
            Self::ZipMember { .. } => "ZIP: XZ",
        };
        Error::Format {
            detail: format!("{prefix} {detail}"),
        }
    }

    const fn checksum(self) -> Error {
        match self {
            Self::PackagePayload => Error::Checksum {
                scope: ChecksumScope::PackagePayload,
                member_index: None,
            },
            Self::ZipMember { member_index } => Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(member_index),
            },
        }
    }

    const fn is_zip_method_95(self) -> bool {
        matches!(self, Self::ZipMember { .. })
    }

    fn contextualize(self, error: Error) -> Error {
        match error {
            Error::Format { detail } => {
                let prefix = match self {
                    Self::PackagePayload => "package XZ",
                    Self::ZipMember { .. } => "ZIP: XZ",
                };
                Error::Format {
                    detail: format!("{prefix} {detail}"),
                }
            }
            other => other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XzCheck {
    None,
    Crc32,
    Crc64,
    Sha256,
}

impl XzCheck {
    const fn from_id(identifier: u8) -> Option<Self> {
        match identifier {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Crc32),
            0x04 => Some(Self::Crc64),
            0x0a => Some(Self::Sha256),
            _ => None,
        }
    }

    const fn size(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Crc32 => 4,
            Self::Crc64 => 8,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FilterPlan {
    identifier: u64,
    properties_start: u64,
    properties_size: u64,
}

#[derive(Clone, Copy, Debug)]
struct BlockPlan {
    compressed_start: u64,
    compressed_size: u64,
    check_start: u64,
    uncompressed_size: u64,
    dictionary_property: u8,
    filters: [Option<FilterPlan>; XZ_MAX_FILTERS],
    filter_count: usize,
}

#[derive(Debug)]
struct XzPlan {
    blocks: Vec<BlockPlan>,
    check: XzCheck,
    total_output: u64,
}

pub(crate) fn decode_xz(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<Vec<u8>> {
    if let Some(size) = expected {
        check_limit(size, maximum, LimitKind::TotalOutputBytes)?;
    }
    let plan = preflight_xz(input, expected, maximum, limits, control, profile)?;
    let mut output = Vec::new();
    for block in &plan.blocks {
        let compressed = checked_range(
            input,
            block.compressed_start,
            block.compressed_size,
            "XZ compressed-data range overflows",
            "XZ compressed data is truncated",
        )
        .map_err(|error| profile.contextualize(error))?;
        let mut decoded = decode_lzma2(
            compressed,
            &[block.dictionary_property],
            Some(block.uncompressed_size),
            maximum,
            control,
        )
        .map_err(|error| profile.contextualize(error))?;
        apply_prefilters(input, block, &mut decoded, control, profile)?;
        let expected_check = checked_range(
            input,
            block.check_start,
            plan.check.size(),
            "XZ Block Check range overflows",
            "XZ Block Check is truncated",
        )
        .map_err(|error| profile.contextualize(error))?;
        verify_block_check(&decoded, expected_check, plan.check, control, profile)?;

        if output.is_empty() {
            output = decoded;
        } else {
            let current =
                usize_to_u64(output.len(), "XZ output length is not representable as u64")?;
            let additional = usize_to_u64(
                decoded.len(),
                "XZ Block output length is not representable as u64",
            )?;
            let next = current
                .checked_add(additional)
                .ok_or_else(|| profile.format("decoded output size overflows"))?;
            check_limit(next, maximum, LimitKind::TotalOutputBytes)?;
            try_reserve(&mut output, decoded.len())?;
            output.extend_from_slice(&decoded);
        }
    }
    let actual = usize_to_u64(output.len(), "XZ output length is not representable as u64")?;
    if actual != plan.total_output {
        return Err(profile.format("decoded output differs from the Index"));
    }
    Ok(output)
}

fn preflight_xz(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<XzPlan> {
    let input_size = usize_to_u64(input.len(), "XZ input size is not representable")?;
    if input_size % 4 != 0 {
        return Err(profile.format("input size is not a multiple of four bytes"));
    }
    let mut stream_end = input_size;
    loop {
        if stream_end < 4 {
            break;
        }
        let padding_start = stream_end
            .checked_sub(4)
            .ok_or_else(|| profile.format("Stream Padding offset underflows"))?;
        let tail = checked_range(
            input,
            padding_start,
            4,
            "XZ Stream Padding range overflows",
            "XZ Stream Padding is truncated",
        )
        .map_err(|error| profile.contextualize(error))?;
        control.consume_bytes(tail)?;
        if tail.iter().all(|byte| *byte == 0) {
            stream_end = padding_start;
        } else {
            break;
        }
    }
    if stream_end < XZ_MINIMUM_STREAM_BYTES {
        return Err(profile.format("Stream is truncated"));
    }

    let header = checked_range(
        input,
        0,
        XZ_HEADER_BYTES,
        "XZ Stream Header range overflows",
        "XZ Stream Header is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    if header.get(..XZ_MAGIC.len()) != Some(XZ_MAGIC) {
        return Err(profile.format("Stream Header magic is invalid"));
    }
    let stream_flags = header
        .get(6..8)
        .ok_or_else(|| profile.format("Stream Flags are truncated"))?;
    verify_crc32(
        stream_flags,
        le_u32(header, 8, profile, "Stream Header CRC is truncated")?,
        control,
        profile,
    )?;
    let version = stream_flags
        .first()
        .copied()
        .ok_or_else(|| profile.format("Stream version flag is missing"))?;
    let check_identifier = stream_flags
        .get(1)
        .copied()
        .ok_or_else(|| profile.format("Stream Check flag is missing"))?;
    if version != 0 || check_identifier & 0xf0 != 0 {
        return Err(profile.format("Stream Flags contain reserved bits"));
    }
    let check = XzCheck::from_id(check_identifier).ok_or_else(|| Error::UnsupportedFeature {
        feature: String::from("xz-check-type"),
    })?;

    let footer_start = stream_end
        .checked_sub(XZ_FOOTER_BYTES)
        .ok_or_else(|| profile.format("Stream Footer offset underflows"))?;
    let footer = checked_range(
        input,
        footer_start,
        XZ_FOOTER_BYTES,
        "XZ Stream Footer range overflows",
        "XZ Stream Footer is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    if footer.get(10..12) != Some(b"YZ") || footer.get(8..10) != Some(stream_flags) {
        return Err(profile.format("Stream Footer magic or flags do not match"));
    }
    let footer_crc_input = footer
        .get(4..10)
        .ok_or_else(|| profile.format("Stream Footer CRC range is truncated"))?;
    verify_crc32(
        footer_crc_input,
        le_u32(footer, 0, profile, "Stream Footer CRC is truncated")?,
        control,
        profile,
    )?;
    let backward = u64::from(le_u32(footer, 4, profile, "Backward Size is truncated")?);
    let index_size = backward
        .checked_add(1)
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| profile.format("Index size overflows"))?;
    check_limit(
        index_size,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    let index_start = footer_start
        .checked_sub(index_size)
        .ok_or_else(|| profile.format("Index offset underflows"))?;
    let index = checked_range(
        input,
        index_start,
        index_size,
        "XZ Index range overflows",
        "XZ Index is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    if index.len() < 8 || index.first().copied() != Some(0) {
        return Err(profile.format("Index Indicator is invalid"));
    }
    control.checkpoint(1)?;
    let crc_start = index_size
        .checked_sub(4)
        .ok_or_else(|| profile.format("Index CRC offset underflows"))?;
    let index_body = checked_range(
        index,
        0,
        crc_start,
        "XZ Index body range overflows",
        "XZ Index body is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    verify_crc32(
        index_body,
        le_u32(index, crc_start, profile, "Index CRC is truncated")?,
        control,
        profile,
    )?;

    let (record_count, mut position) = read_vli(index_body, 1, control, profile)?;
    check_limit(
        record_count,
        limits.max_stream_frames(),
        LimitKind::StreamFrames,
    )?;
    let capacity = usize::try_from(record_count)
        .map_err(|_| profile.format("Block count is not representable on this platform"))?;
    let mut blocks = Vec::new();
    try_reserve(&mut blocks, capacity)?;
    let mut block_offset = XZ_HEADER_BYTES;
    let mut total_output = 0_u64;
    let mut total_coders = 0_u64;
    let mut header_bytes = XZ_HEADER_BYTES
        .checked_add(XZ_FOOTER_BYTES)
        .and_then(|value| value.checked_add(index_size))
        .ok_or_else(|| profile.format("header accounting overflows"))?;
    check_limit(
        header_bytes,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    for _ in 0..record_count {
        let (unpadded_size, next) = read_vli(index_body, position, control, profile)?;
        let (uncompressed_size, after) = read_vli(index_body, next, control, profile)?;
        position = after;
        if unpadded_size == 0 {
            return Err(profile.format("Index contains a zero Unpadded Size"));
        }
        let (block, physical_end, block_header_size) = preflight_block(
            input,
            block_offset,
            unpadded_size,
            uncompressed_size,
            check,
            limits,
            control,
            profile,
        )?;
        let block_coders = u64::try_from(block.filter_count)
            .map_err(|_| profile.format("Block filter count is not representable"))?;
        total_coders = total_coders
            .checked_add(block_coders)
            .ok_or_else(|| profile.format("total filter count overflows"))?;
        check_limit(
            total_coders,
            limits.max_total_coders(),
            LimitKind::TotalCoders,
        )?;
        header_bytes = header_bytes
            .checked_add(block_header_size)
            .ok_or_else(|| profile.format("header accounting overflows"))?;
        check_limit(
            header_bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        total_output = total_output
            .checked_add(uncompressed_size)
            .ok_or_else(|| profile.format("declared output size overflows"))?;
        check_limit(total_output, maximum, LimitKind::TotalOutputBytes)?;
        blocks.push(block);
        block_offset = physical_end;
    }
    validate_index_padding(index_body, position, control, profile)?;
    if block_offset != index_start {
        return Err(profile.format("Block records do not reach the Index exactly"));
    }
    if expected.is_some_and(|size| size != total_output) {
        return Err(profile.format("Index output size differs from its declaration"));
    }
    Ok(XzPlan {
        blocks,
        check,
        total_output,
    })
}

#[allow(clippy::too_many_arguments)]
fn preflight_block(
    input: &[u8],
    offset: u64,
    unpadded_size: u64,
    uncompressed_size: u64,
    check: XzCheck,
    limits: Limits,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<(BlockPlan, u64, u64)> {
    let encoded_size = checked_range(
        input,
        offset,
        1,
        "XZ Block Header range overflows",
        "XZ Block Header is truncated",
    )
    .map_err(|error| profile.contextualize(error))?
    .first()
    .copied()
    .ok_or_else(|| profile.format("Block Header Size is missing"))?;
    control.checkpoint(1)?;
    if encoded_size == 0 {
        return Err(profile.format("Block Header unexpectedly starts the Index"));
    }
    let header_size = u64::from(encoded_size)
        .checked_add(1)
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| profile.format("Block Header size overflows"))?;
    if !(8..=1024).contains(&header_size) || header_size > unpadded_size {
        return Err(profile.format("Block Header size is invalid"));
    }
    check_limit(
        header_size,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    let header = checked_range(
        input,
        offset,
        header_size,
        "XZ Block Header range overflows",
        "XZ Block Header is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    let crc_start = header_size
        .checked_sub(4)
        .ok_or_else(|| profile.format("Block Header CRC offset underflows"))?;
    let body = checked_range(
        header,
        0,
        crc_start,
        "XZ Block Header body range overflows",
        "XZ Block Header body is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    verify_crc32(
        body,
        le_u32(header, crc_start, profile, "Block Header CRC is truncated")?,
        control,
        profile,
    )?;
    let flags = body
        .get(1)
        .copied()
        .ok_or_else(|| profile.format("Block Flags are truncated"))?;
    control.checkpoint(1)?;
    if flags & 0x3c != 0 {
        return Err(profile.format("Block Flags contain reserved bits"));
    }
    let filter_count = usize::from((flags & 3) + 1);
    if profile.is_zip_method_95() && filter_count > 2 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("zip-xz-filter-count"),
        });
    }
    check_limit(
        u64::try_from(filter_count)
            .map_err(|_| profile.format("Block filter count is not representable"))?,
        limits.max_coders_per_folder(),
        LimitKind::CodersPerFolder,
    )?;

    let mut position = 2_u64;
    let declared_compressed = if flags & 0x40 != 0 {
        let (value, next) = read_vli(body, position, control, profile)?;
        position = next;
        Some(value)
    } else {
        None
    };
    let declared_uncompressed = if flags & 0x80 != 0 {
        let (value, next) = read_vli(body, position, control, profile)?;
        position = next;
        Some(value)
    } else {
        None
    };

    let mut filters = [None; XZ_MAX_FILTERS];
    let mut dictionary_property = None;
    for ordinal in 0..filter_count {
        let (identifier, next) = read_vli(body, position, control, profile)?;
        if identifier >= XZ_INTERNAL_FILTER_ID_START {
            return Err(profile.format("Block uses a reserved internal Filter ID"));
        }
        let (property_size, property_start) = read_vli(body, next, control, profile)?;
        check_limit(
            property_size,
            limits.max_coder_property_bytes(),
            LimitKind::CoderPropertyBytes,
        )?;
        let properties = checked_range(
            body,
            property_start,
            property_size,
            "XZ Filter Properties range overflows",
            "XZ Filter Properties are truncated",
        )
        .map_err(|error| profile.contextualize(error))?;
        control.consume_bytes(properties)?;
        position = property_start
            .checked_add(property_size)
            .ok_or_else(|| profile.format("Filter Properties offset overflows"))?;
        let last = ordinal
            .checked_add(1)
            .is_some_and(|value| value == filter_count);
        let parsed_dictionary = validate_filter(identifier, properties, last, profile)?;
        if let Some(dictionary) = parsed_dictionary {
            check_limit(
                u64::from(dictionary),
                limits.max_dictionary_bytes(),
                LimitKind::DictionaryBytes,
            )?;
            dictionary_property = properties.first().copied();
        }
        let absolute_properties_start = offset
            .checked_add(property_start)
            .ok_or_else(|| profile.format("Filter Properties absolute offset overflows"))?;
        let slot = filters
            .get_mut(ordinal)
            .ok_or_else(|| profile.format("Block filter count exceeds its fixed bound"))?;
        *slot = Some(FilterPlan {
            identifier,
            properties_start: absolute_properties_start,
            properties_size: property_size,
        });
    }
    let dictionary_property =
        dictionary_property.ok_or_else(|| profile.format("Block has no final LZMA2 filter"))?;
    let body_size = usize_to_u64(body.len(), "XZ Block Header size is not representable")?;
    let padding_size = body_size
        .checked_sub(position)
        .ok_or_else(|| profile.format("Block Header fields exceed its declared size"))?;
    let header_padding = checked_range(
        body,
        position,
        padding_size,
        "XZ Block Header Padding range overflows",
        "XZ Block Header Padding is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    control.consume_bytes(header_padding)?;
    if header_padding.iter().any(|byte| *byte != 0) {
        return Err(profile.format("Block Header Padding is nonzero"));
    }

    let fixed_size = header_size
        .checked_add(check.size())
        .ok_or_else(|| profile.format("Block fixed size overflows"))?;
    let compressed_size = unpadded_size
        .checked_sub(fixed_size)
        .ok_or_else(|| profile.format("Index Unpadded Size is smaller than the Block"))?;
    if compressed_size == 0 {
        return Err(profile.format("Block Compressed Data is empty"));
    }
    if declared_compressed.is_some_and(|size| size != compressed_size) {
        return Err(profile.format("Block Compressed Size differs from the Index record"));
    }
    if declared_uncompressed.is_some_and(|size| size != uncompressed_size) {
        return Err(profile.format("Block Uncompressed Size differs from the Index record"));
    }
    let compressed_start = offset
        .checked_add(header_size)
        .ok_or_else(|| profile.format("Block Compressed Data offset overflows"))?;
    checked_range(
        input,
        compressed_start,
        compressed_size,
        "XZ Block Compressed Data range overflows",
        "XZ Block Compressed Data is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    let block_padding_size = padding_for(compressed_size, profile)?;
    let block_padding_start = compressed_start
        .checked_add(compressed_size)
        .ok_or_else(|| profile.format("Block Padding offset overflows"))?;
    let block_padding = checked_range(
        input,
        block_padding_start,
        block_padding_size,
        "XZ Block Padding range overflows",
        "XZ Block Padding is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    control.consume_bytes(block_padding)?;
    if block_padding.iter().any(|byte| *byte != 0) {
        return Err(profile.format("Block Padding is nonzero"));
    }
    let check_start = block_padding_start
        .checked_add(block_padding_size)
        .ok_or_else(|| profile.format("Block Check offset overflows"))?;
    let physical_end = check_start
        .checked_add(check.size())
        .ok_or_else(|| profile.format("Block physical end overflows"))?;
    checked_range(
        input,
        check_start,
        check.size(),
        "XZ Block Check range overflows",
        "XZ Block Check is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    let indexed_end = align_up(
        offset
            .checked_add(unpadded_size)
            .ok_or_else(|| profile.format("Block indexed end overflows"))?,
        4,
        profile,
    )?;
    if physical_end != indexed_end {
        return Err(profile.format("Block layout disagrees with its Index record"));
    }
    Ok((
        BlockPlan {
            compressed_start,
            compressed_size,
            check_start,
            uncompressed_size,
            dictionary_property,
            filters,
            filter_count,
        },
        physical_end,
        header_size,
    ))
}

fn validate_filter(
    identifier: u64,
    properties: &[u8],
    last: bool,
    profile: XzProfile,
) -> Result<Option<u32>> {
    match identifier {
        0x21 => {
            if !last {
                return Err(profile.format("LZMA2 is not the final Block filter"));
            }
            let property = properties
                .first()
                .copied()
                .filter(|_| properties.len() == 1)
                .ok_or_else(|| {
                    profile.format("LZMA2 Filter Properties must contain exactly one byte")
                })?;
            if property > 40 {
                return Err(profile.format("LZMA2 dictionary property is invalid"));
            }
            let dictionary = if property == 40 {
                u32::MAX
            } else {
                let base = u32::from(2 | (property & 1));
                base.checked_shl(u32::from(property / 2 + 11))
                    .ok_or_else(|| profile.format("LZMA2 dictionary size overflows"))?
            };
            Ok(Some(dictionary))
        }
        0x03 => {
            if last {
                return Err(profile.format("Delta cannot be the final Block filter"));
            }
            if properties.len() != 1 {
                return Err(profile.format("Delta Filter Properties must contain exactly one byte"));
            }
            Ok(None)
        }
        0x04..=0x09 => {
            if last {
                return Err(profile.format("BCJ cannot be the final Block filter"));
            }
            validate_bcj_properties(identifier, properties, profile)?;
            Ok(None)
        }
        0x0a | 0x0b if !profile.is_zip_method_95() => {
            if last {
                return Err(profile.format("BCJ cannot be the final Block filter"));
            }
            validate_bcj_properties(identifier, properties, profile)?;
            Ok(None)
        }
        0x0a | 0x0b => Err(Error::UnsupportedFeature {
            feature: String::from("zip-xz-post-1.0.4-filter"),
        }),
        _ => Err(Error::UnsupportedFeature {
            feature: String::from("xz-filter"),
        }),
    }
}

fn validate_bcj_properties(identifier: u64, properties: &[u8], profile: XzProfile) -> Result<()> {
    if properties.is_empty() {
        return Ok(());
    }
    let encoded = <[u8; 4]>::try_from(properties)
        .map_err(|_| profile.format("BCJ Filter Properties must be empty or four bytes"))?;
    let start = u32::from_le_bytes(encoded);
    let alignment = match identifier {
        0x04 => 1,
        0x05 | 0x07 | 0x09 | 0x0a => 4,
        0x06 => 16,
        0x08 | 0x0b => 2,
        _ => return Err(profile.format("BCJ Filter ID is invalid")),
    };
    if start % alignment != 0 {
        return Err(profile.format("BCJ start offset violates its alignment"));
    }
    Ok(())
}

fn apply_prefilters(
    input: &[u8],
    block: &BlockPlan,
    output: &mut [u8],
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<()> {
    let prefilter_count = block
        .filter_count
        .checked_sub(1)
        .ok_or_else(|| profile.format("Block has no LZMA2 filter"))?;
    for ordinal in (0..prefilter_count).rev() {
        let filter = block
            .filters
            .get(ordinal)
            .copied()
            .flatten()
            .ok_or_else(|| profile.format("Block prefilter plan is incomplete"))?;
        let properties = checked_range(
            input,
            filter.properties_start,
            filter.properties_size,
            "XZ prefilter properties range overflows",
            "XZ prefilter properties are truncated",
        )
        .map_err(|error| profile.contextualize(error))?;
        let method = match filter.identifier {
            0x03 => METHOD_DELTA,
            0x04 => METHOD_BCJ,
            0x05 => METHOD_PPC,
            0x06 => METHOD_IA64,
            0x07 => METHOD_ARM,
            0x08 => METHOD_ARM_THUMB,
            0x09 => METHOD_SPARC,
            0x0a => METHOD_ARM64,
            0x0b => METHOD_RISCV,
            _ => return Err(profile.format("Block prefilter plan contains an unknown Filter ID")),
        };
        decode_filter_in_place(method, properties, output, control)
            .map_err(|error| profile.contextualize(error))?;
    }
    Ok(())
}

fn verify_block_check(
    output: &[u8],
    expected: &[u8],
    check: XzCheck,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<()> {
    let matches = match check {
        XzCheck::None => expected.is_empty(),
        XzCheck::Crc32 => {
            let mut checksum = Crc32::new();
            for chunk in output.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "XZ CRC-32 chunk length is not representable",
                )?)?;
                checksum.update(chunk)?;
            }
            checksum.finalize().to_le_bytes().as_slice() == expected
        }
        XzCheck::Crc64 => {
            let mut checksum = Crc64Xz::new();
            for chunk in output.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "XZ CRC-64 chunk length is not representable",
                )?)?;
                checksum.update(chunk)?;
            }
            checksum.finalize().to_le_bytes().as_slice() == expected
        }
        XzCheck::Sha256 => {
            let mut checksum = Sha256::new();
            for chunk in output.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "XZ SHA-256 chunk length is not representable",
                )?)?;
                checksum.update(chunk);
            }
            let actual = checksum.finalize();
            let actual: &[u8] = actual.as_ref();
            actual == expected
        }
    };
    if matches {
        Ok(())
    } else {
        Err(profile.checksum())
    }
}

fn validate_index_padding(
    index_body: &[u8],
    position: u64,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<()> {
    let body_size = usize_to_u64(index_body.len(), "XZ Index size is not representable")?;
    let padding_size = body_size
        .checked_sub(position)
        .ok_or_else(|| profile.format("Index records exceed the Index size"))?;
    let expected_padding = padding_for(position, profile)?;
    if padding_size != expected_padding {
        return Err(profile.format("Index Padding length is invalid"));
    }
    let padding = checked_range(
        index_body,
        position,
        padding_size,
        "XZ Index Padding range overflows",
        "XZ Index Padding is truncated",
    )
    .map_err(|error| profile.contextualize(error))?;
    control.consume_bytes(padding)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(profile.format("Index Padding is nonzero"));
    }
    Ok(())
}

fn verify_crc32(
    bytes: &[u8],
    expected: u32,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<()> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "XZ CRC-32 chunk length is not representable",
        )?)?;
        checksum.update(chunk)?;
    }
    if checksum.finalize() == expected {
        Ok(())
    } else {
        Err(profile.checksum())
    }
}

fn read_vli(
    bytes: &[u8],
    start: u64,
    control: &mut ParseControl<'_>,
    profile: XzProfile,
) -> Result<(u64, u64)> {
    let mut value = 0_u64;
    let mut position = start;
    for ordinal in 0_u32..9 {
        let byte = checked_range(
            bytes,
            position,
            1,
            "XZ VLI range overflows",
            "XZ VLI is truncated",
        )
        .map_err(|error| profile.contextualize(error))?
        .first()
        .copied()
        .ok_or_else(|| profile.format("VLI byte is missing"))?;
        control.checkpoint(1)?;
        if ordinal == 8 && byte > 0x7f {
            return Err(profile.format("VLI exceeds the 63-bit domain"));
        }
        let shift = ordinal
            .checked_mul(7)
            .ok_or_else(|| profile.format("VLI shift overflows"))?;
        let shifted = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| profile.format("VLI value overflows"))?;
        value = value
            .checked_add(shifted)
            .ok_or_else(|| profile.format("VLI value overflows"))?;
        position = position
            .checked_add(1)
            .ok_or_else(|| profile.format("VLI position overflows"))?;
        if byte & 0x80 == 0 {
            if ordinal != 0 && byte == 0 {
                return Err(profile.format("VLI is not minimally encoded"));
            }
            return Ok((value, position));
        }
    }
    Err(profile.format("VLI is too long"))
}

fn le_u32(
    bytes: &[u8],
    offset: impl TryInto<u64>,
    profile: XzProfile,
    detail: &'static str,
) -> Result<u32> {
    let offset = offset.try_into().map_err(|_| profile.format(detail))?;
    let value = checked_range(bytes, offset, 4, detail, detail)
        .map_err(|error| profile.contextualize(error))?;
    Ok(u32::from_le_bytes(
        <[u8; 4]>::try_from(value).map_err(|_| profile.format(detail))?,
    ))
}

fn padding_for(value: u64, profile: XzProfile) -> Result<u64> {
    let remainder = value % 4;
    if remainder == 0 {
        Ok(0)
    } else {
        4_u64
            .checked_sub(remainder)
            .ok_or_else(|| profile.format("padding calculation underflows"))
    }
}

fn align_up(value: u64, alignment: u64, profile: XzProfile) -> Result<u64> {
    let remainder = value % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment
            .checked_sub(remainder)
            .ok_or_else(|| profile.format("alignment underflows"))?
    };
    value
        .checked_add(padding)
        .ok_or_else(|| profile.format("alignment overflows"))
}

// The table is generated only from a compile-time counter in 0..256. The
// reflected polynomial and initial/final complement are the CRC-64/XZ values
// specified by XZ 1.0.4 section 6.
#[allow(clippy::indexing_slicing)]
const fn make_crc64_xz_table() -> [u64; 256] {
    let mut table = [0_u64; 256];
    let mut index = 0_usize;
    let mut initial = 0_u64;
    while index < table.len() {
        let mut value = initial;
        let mut bit = 0_u8;
        while bit < 8 {
            value = if value & 1 == 0 {
                value >> 1
            } else {
                (value >> 1) ^ CRC64_XZ_POLYNOMIAL
            };
            bit = bit.saturating_add(1);
        }
        table[index] = value;
        index = index.saturating_add(1);
        initial = initial.saturating_add(1);
    }
    table
}

const CRC64_XZ_TABLE: [u64; 256] = make_crc64_xz_table();

struct Crc64Xz {
    state: u64,
}

impl Crc64Xz {
    const fn new() -> Self {
        Self { state: u64::MAX }
    }

    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        for byte in bytes {
            let low = self.state.to_le_bytes()[0];
            let table_index = usize::from(low ^ byte);
            let table_value = CRC64_XZ_TABLE
                .get(table_index)
                .ok_or_else(|| Error::Format {
                    detail: String::from("internal CRC-64/XZ table index is invalid"),
                })?;
            self.state = *table_value ^ (self.state >> 8);
        }
        Ok(())
    }

    const fn finalize(self) -> u64 {
        !self.state
    }
}

#[cfg(test)]
mod tests {
    use super::Crc64Xz;

    #[test]
    fn crc64_xz_matches_standard_check_value() -> crate::Result<()> {
        let mut checksum = Crc64Xz::new();
        checksum.update(b"123456789")?;
        assert_eq!(checksum.finalize(), 0x995d_c9bb_df19_39fa);
        Ok(())
    }
}
