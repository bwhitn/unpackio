//! RPM payload decompression with pre-allocation resource checks.

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::RpmPayloadCompression;
use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    checksum::Crc32,
    decode::{ControlledInput, decode_bzip2, decode_deflate, decode_reader, decode_zstd},
    parse_util::{ParseControl, check_limit, checked_range, try_reserve, usize_to_u64},
};

const GZIP_FIXED_BYTES: usize = 10;
const GZIP_TRAILER_BYTES: usize = 8;
const XZ_HEADER_BYTES: u64 = 12;
const XZ_FOOTER_BYTES: u64 = 12;
const XZ_MAGIC: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0];

pub(super) fn decode_payload(
    input: &[u8],
    compression: RpmPayloadCompression,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let maximum = limits.max_total_output_bytes();
    let compression = match compression {
        RpmPayloadCompression::None => PayloadCompression::None,
        RpmPayloadCompression::Gzip => PayloadCompression::Gzip,
        RpmPayloadCompression::Bzip2 => PayloadCompression::Bzip2,
        RpmPayloadCompression::Xz => PayloadCompression::Xz,
        RpmPayloadCompression::Lzma => PayloadCompression::Lzma,
        RpmPayloadCompression::Zstandard => PayloadCompression::Zstandard,
        RpmPayloadCompression::Unknown => Err(Error::UnsupportedFeature {
            feature: String::from("rpm-payload-compression"),
        })?,
    };
    decode_container_payload(input, compression, limits, maximum, control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PayloadCompression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    Zstandard,
}

pub(crate) fn decode_container_payload(
    input: &[u8],
    compression: PayloadCompression,
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        maximum,
        limits.max_total_output_bytes(),
        LimitKind::TotalOutputBytes,
    )?;
    match compression {
        PayloadCompression::None => copy_uncompressed(input, maximum, control),
        PayloadCompression::Gzip => decode_gzip(input, limits, maximum, control),
        PayloadCompression::Bzip2 => decode_bzip2(input, None, maximum, limits, control),
        PayloadCompression::Xz => decode_xz(input, limits, maximum, control),
        PayloadCompression::Lzma => decode_legacy_lzma(input, limits, maximum, control),
        PayloadCompression::Zstandard => decode_zstd(input, None, maximum, limits, control),
    }
}

fn copy_uncompressed(
    input: &[u8],
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        usize_to_u64(input.len(), "RPM payload size is not representable")?,
        maximum,
        LimitKind::TotalOutputBytes,
    )?;
    let mut output = Vec::new();
    try_reserve(&mut output, input.len())?;
    for chunk in input.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(
            usize_to_u64(chunk.len(), "RPM payload chunk is not representable")?
                .checked_mul(2)
                .ok_or_else(|| rpm_format("payload work accounting overflows"))?,
        )?;
        output.extend_from_slice(chunk);
    }
    Ok(output)
}

fn decode_gzip(
    input: &[u8],
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let header = input
        .get(..GZIP_FIXED_BYTES)
        .ok_or_else(|| rpm_format("gzip header is truncated"))?;
    control.consume_bytes(header)?;
    if header.get(..2) != Some(&[0x1f, 0x8b]) || header.get(2).copied() != Some(8) {
        return Err(rpm_format("gzip header or compression method is invalid"));
    }
    let flags = header
        .get(3)
        .copied()
        .ok_or_else(|| rpm_format("gzip flags are truncated"))?;
    if flags & 0xe0 != 0 {
        return Err(rpm_format("gzip reserved flags are nonzero"));
    }
    let mut position = GZIP_FIXED_BYTES;
    if flags & 0x04 != 0 {
        let extra_start = position;
        let length_end = position
            .checked_add(2)
            .ok_or_else(|| rpm_format("gzip extra-length range overflows"))?;
        let length_bytes = input
            .get(position..length_end)
            .ok_or_else(|| rpm_format("gzip extra length is truncated"))?;
        let length = usize::from(u16::from_le_bytes(
            <[u8; 2]>::try_from(length_bytes)
                .map_err(|_| rpm_format("gzip extra length is truncated"))?,
        ));
        position = position
            .checked_add(2)
            .and_then(|offset| offset.checked_add(length))
            .ok_or_else(|| rpm_format("gzip extra range overflows"))?;
        input
            .get(..position)
            .ok_or_else(|| rpm_format("gzip extra field is truncated"))?;
        let extra = input
            .get(extra_start..position)
            .ok_or_else(|| rpm_format("gzip extra field range is invalid"))?;
        control.consume_bytes(extra)?;
    }
    if flags & 0x08 != 0 {
        position = skip_c_string(input, position, "gzip file name is not terminated", control)?;
    }
    if flags & 0x10 != 0 {
        position = skip_c_string(input, position, "gzip comment is not terminated", control)?;
    }
    check_limit(
        u64::try_from(position).map_err(|_| rpm_format("gzip header size is not representable"))?,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    if flags & 0x02 != 0 {
        let expected = le_u16(input, position, "gzip header CRC is truncated")?;
        let header_bytes = input
            .get(..position)
            .ok_or_else(|| rpm_format("gzip header CRC range is invalid"))?;
        let mut checksum = Crc32::new();
        for chunk in header_bytes.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "gzip header checksum chunk is not representable",
            )?)?;
            checksum.update(chunk)?;
        }
        let [low, high, _, _] = checksum.finalize().to_le_bytes();
        if expected != u16::from_le_bytes([low, high]) {
            return Err(Error::Checksum {
                scope: ChecksumScope::PackagePayload,
                member_index: None,
            });
        }
        position = position
            .checked_add(2)
            .ok_or_else(|| rpm_format("gzip header offset overflows"))?;
        control.checkpoint(2)?;
        check_limit(
            u64::try_from(position)
                .map_err(|_| rpm_format("gzip header size is not representable"))?,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
    }
    let trailer_start = input
        .len()
        .checked_sub(GZIP_TRAILER_BYTES)
        .ok_or_else(|| rpm_format("gzip trailer is truncated"))?;
    if position > trailer_start {
        return Err(rpm_format("gzip compressed-data range is invalid"));
    }
    let compressed = input
        .get(position..trailer_start)
        .ok_or_else(|| rpm_format("gzip compressed data is truncated"))?;
    let output = decode_deflate(compressed, None, maximum, limits, control)?;
    let expected_crc = le_u32(input, trailer_start, "gzip trailer CRC is truncated")?;
    let expected_size = le_u32(
        input,
        trailer_start
            .checked_add(4)
            .ok_or_else(|| rpm_format("gzip trailer offset overflows"))?,
        "gzip trailer size is truncated",
    )?;
    let mut checksum = Crc32::new();
    for chunk in output.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "gzip checksum chunk is not representable",
        )?)?;
        checksum.update(chunk)?;
    }
    let actual_size = u32::try_from(output.len() & 0xffff_ffff)
        .map_err(|_| rpm_format("gzip output size modulo is not representable"))?;
    if checksum.finalize() != expected_crc || actual_size != expected_size {
        return Err(Error::Checksum {
            scope: ChecksumScope::PackagePayload,
            member_index: None,
        });
    }
    Ok(output)
}

fn decode_legacy_lzma(
    input: &[u8],
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let header = input
        .get(..13)
        .ok_or_else(|| rpm_format("legacy LZMA header is truncated"))?;
    let dictionary = le_u32(header, 1, "legacy LZMA dictionary is truncated")?;
    check_limit(
        u64::from(dictionary.max(1)),
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let configured_memory_kib = limits.max_dictionary_bytes() / 1024;
    let memory_kib = if configured_memory_kib > u64::from(u32::MAX) {
        u32::MAX
    } else {
        u32::try_from(configured_memory_kib)
            .map_err(|_| rpm_format("legacy LZMA memory limit is not representable"))?
    };
    let consumed = Cell::new(0);
    let controlled = ControlledInput::new(input, &consumed, control.cancellation_token());
    let reader = catch_unwind(AssertUnwindSafe(|| {
        lzma_rust2::LzmaReader::new_mem_limit(controlled, memory_kib, None)
    }))
    .map_err(|_| rpm_format("legacy LZMA decoder rejected its header"))?
    .map_err(|_| rpm_format("legacy LZMA header or memory request is invalid"))?;
    decode_reader(
        reader,
        &consumed,
        None,
        maximum,
        control,
        "invalid or truncated legacy LZMA payload",
    )
}

fn decode_xz(
    input: &[u8],
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let stream_end = preflight_xz(input, limits, maximum, control)?;
    let stream = checked_range(
        input,
        0,
        stream_end,
        "XZ stream range overflows",
        "XZ stream is truncated",
    )?;
    let consumed = Cell::new(0);
    let controlled = ControlledInput::new(stream, &consumed, control.cancellation_token());
    let reader = lzma_rust2::XzReader::new(controlled, false);
    let output = decode_reader(
        reader,
        &consumed,
        None,
        maximum,
        control,
        "invalid or truncated XZ payload",
    )?;
    if consumed.get() != stream.len() {
        return Err(rpm_format("XZ decoder did not consume the complete stream"));
    }
    Ok(output)
}

fn preflight_xz(
    input: &[u8],
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<u64> {
    let mut stream_end = usize_to_u64(input.len(), "XZ input size is not representable")?;
    loop {
        if stream_end < 4 {
            break;
        }
        let tail = checked_range(
            input,
            stream_end
                .checked_sub(4)
                .ok_or_else(|| rpm_format("XZ stream-padding offset underflows"))?,
            4,
            "XZ stream-padding range overflows",
            "XZ stream padding is truncated",
        )?;
        if tail.iter().all(|byte| *byte == 0) {
            stream_end = stream_end
                .checked_sub(4)
                .ok_or_else(|| rpm_format("XZ stream-padding offset underflows"))?;
        } else {
            break;
        }
    }
    if stream_end < XZ_HEADER_BYTES + XZ_FOOTER_BYTES {
        return Err(rpm_format("XZ stream is truncated"));
    }
    let header = checked_range(
        input,
        0,
        XZ_HEADER_BYTES,
        "XZ header range overflows",
        "XZ header is truncated",
    )?;
    if header.get(..6) != Some(XZ_MAGIC) {
        return Err(rpm_format("XZ magic is invalid"));
    }
    verify_xz_crc(
        header
            .get(6..8)
            .ok_or_else(|| rpm_format("XZ stream flags are truncated"))?,
        le_u32(header, 8, "XZ header CRC is truncated")?,
        control,
    )?;
    let stream_flags = header
        .get(6..8)
        .ok_or_else(|| rpm_format("XZ stream flags are truncated"))?;
    if stream_flags.first().copied() != Some(0)
        || stream_flags
            .get(1)
            .copied()
            .is_none_or(|flag| flag & 0xf0 != 0)
    {
        return Err(rpm_format("XZ stream flags are invalid"));
    }
    let footer_start = stream_end
        .checked_sub(XZ_FOOTER_BYTES)
        .ok_or_else(|| rpm_format("XZ footer offset underflows"))?;
    let footer = checked_range(
        input,
        footer_start,
        XZ_FOOTER_BYTES,
        "XZ footer range overflows",
        "XZ footer is truncated",
    )?;
    if footer.get(10..12) != Some(b"YZ") || footer.get(8..10) != Some(stream_flags) {
        return Err(rpm_format("XZ footer magic or flags do not match"));
    }
    verify_xz_crc(
        footer
            .get(4..10)
            .ok_or_else(|| rpm_format("XZ footer CRC range is truncated"))?,
        le_u32(footer, 0, "XZ footer CRC is truncated")?,
        control,
    )?;
    let backward = u64::from(le_u32(footer, 4, "XZ backward size is truncated")?);
    let index_size = backward
        .checked_add(1)
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| rpm_format("XZ index size overflows"))?;
    let index_start = footer_start
        .checked_sub(index_size)
        .ok_or_else(|| rpm_format("XZ index offset underflows"))?;
    let index = checked_range(
        input,
        index_start,
        index_size,
        "XZ index range overflows",
        "XZ index is truncated",
    )?;
    if index.len() < 8 || index.first().copied() != Some(0) {
        return Err(rpm_format("XZ index indicator is invalid"));
    }
    let crc_start = index_size
        .checked_sub(4)
        .ok_or_else(|| rpm_format("XZ index CRC offset underflows"))?;
    let index_body = checked_range(
        index,
        0,
        crc_start,
        "XZ index body range overflows",
        "XZ index body is truncated",
    )?;
    let expected_index_crc = le_u32(index, crc_start, "XZ index CRC is truncated")?;
    verify_xz_crc(index_body, expected_index_crc, control)?;
    let (record_count, mut position) = read_vli(index_body, 1)?;
    check_limit(
        record_count,
        limits.max_stream_frames(),
        LimitKind::StreamFrames,
    )?;
    let mut block_offset = XZ_HEADER_BYTES;
    let mut total_output = 0_u64;
    for _ in 0..record_count {
        let (unpadded, next) = read_vli(index_body, position)?;
        let (uncompressed, after) = read_vli(index_body, next)?;
        position = after;
        if unpadded == 0 {
            return Err(rpm_format("XZ index contains a zero block size"));
        }
        preflight_xz_block(input, block_offset, unpadded, limits, control)?;
        block_offset = align_up(
            block_offset
                .checked_add(unpadded)
                .ok_or_else(|| rpm_format("XZ block range overflows"))?,
            4,
        )?;
        total_output = total_output
            .checked_add(uncompressed)
            .ok_or_else(|| rpm_format("XZ declared output size overflows"))?;
        check_limit(total_output, maximum, LimitKind::TotalOutputBytes)?;
    }
    let padding = index_body
        .get(
            usize::try_from(position)
                .map_err(|_| rpm_format("XZ index position is not representable"))?..,
        )
        .ok_or_else(|| rpm_format("XZ index padding range is invalid"))?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(rpm_format("XZ index padding is nonzero"));
    }
    if block_offset != index_start {
        return Err(rpm_format("XZ block records do not reach the index"));
    }
    Ok(stream_end)
}

fn preflight_xz_block(
    input: &[u8],
    offset: u64,
    unpadded_size: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let encoded_size = checked_range(
        input,
        offset,
        1,
        "XZ block-header range overflows",
        "XZ block header is truncated",
    )?
    .first()
    .copied()
    .ok_or_else(|| rpm_format("XZ block-header size is missing"))?;
    if encoded_size == 0 {
        return Err(rpm_format("XZ block header unexpectedly starts the index"));
    }
    let header_size = u64::from(encoded_size)
        .checked_add(1)
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| rpm_format("XZ block-header size overflows"))?;
    if !(8..=1024).contains(&header_size) || header_size > unpadded_size {
        return Err(rpm_format("XZ block-header size is invalid"));
    }
    let header = checked_range(
        input,
        offset,
        header_size,
        "XZ block-header range overflows",
        "XZ block header is truncated",
    )?;
    let crc_start = header_size
        .checked_sub(4)
        .ok_or_else(|| rpm_format("XZ block-header CRC offset underflows"))?;
    let body = checked_range(
        header,
        0,
        crc_start,
        "XZ block-header body range overflows",
        "XZ block-header body is truncated",
    )?;
    verify_xz_crc(
        body,
        le_u32(header, crc_start, "XZ block-header CRC is truncated")?,
        control,
    )?;
    let flags = body
        .get(1)
        .copied()
        .ok_or_else(|| rpm_format("XZ block flags are truncated"))?;
    if flags & 0x3c != 0 {
        return Err(rpm_format("XZ block reserved flags are nonzero"));
    }
    let filter_count = u64::from((flags & 3) + 1);
    let mut position = 2_u64;
    if flags & 0x40 != 0 {
        position = read_vli(body, position)?.1;
    }
    if flags & 0x80 != 0 {
        position = read_vli(body, position)?.1;
    }
    let mut last_filter = None;
    for _ in 0..filter_count {
        let (identifier, next) = read_vli(body, position)?;
        let (property_size, property_start) = read_vli(body, next)?;
        let properties = checked_range(
            body,
            property_start,
            property_size,
            "XZ filter-property range overflows",
            "XZ filter properties are truncated",
        )?;
        position = property_start
            .checked_add(property_size)
            .ok_or_else(|| rpm_format("XZ filter-property offset overflows"))?;
        last_filter = Some((identifier, properties));
    }
    let padding = checked_range(
        body,
        position,
        usize_to_u64(body.len(), "XZ block-header size is not representable")?
            .checked_sub(position)
            .ok_or_else(|| rpm_format("XZ block-header padding underflows"))?,
        "XZ block-header padding range overflows",
        "XZ block-header padding is truncated",
    )?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(rpm_format("XZ block-header padding is nonzero"));
    }
    let (identifier, properties) =
        last_filter.ok_or_else(|| rpm_format("XZ block has no filter"))?;
    if identifier != 0x21 || properties.len() != 1 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("xz-filter-chain-without-lzma2-root"),
        });
    }
    let property = properties
        .first()
        .copied()
        .ok_or_else(|| rpm_format("XZ LZMA2 property is missing"))?;
    if property > 40 {
        return Err(rpm_format("XZ LZMA2 dictionary property is invalid"));
    }
    let dictionary = if property == 40 {
        u64::from(u32::MAX)
    } else {
        let base = u64::from(2 | (property & 1));
        base.checked_shl(u32::from(property / 2 + 11))
            .ok_or_else(|| rpm_format("XZ dictionary size overflows"))?
    };
    check_limit(
        dictionary,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )
}

fn verify_xz_crc(bytes: &[u8], expected: u32, control: &mut ParseControl<'_>) -> Result<()> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "XZ checksum chunk is not representable",
        )?)?;
        checksum.update(chunk)?;
    }
    if checksum.finalize() == expected {
        Ok(())
    } else {
        Err(Error::Checksum {
            scope: ChecksumScope::PackagePayload,
            member_index: None,
        })
    }
}

fn read_vli(bytes: &[u8], start: u64) -> Result<(u64, u64)> {
    let mut value = 0_u64;
    let mut position = start;
    for ordinal in 0_u32..9 {
        let byte = checked_range(
            bytes,
            position,
            1,
            "XZ VLI range overflows",
            "XZ VLI is truncated",
        )?
        .first()
        .copied()
        .ok_or_else(|| rpm_format("XZ VLI byte is missing"))?;
        if ordinal == 8 && byte > 0x7f {
            return Err(rpm_format("XZ VLI is too large"));
        }
        let shift = ordinal
            .checked_mul(7)
            .ok_or_else(|| rpm_format("XZ VLI shift overflows"))?;
        let shifted = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| rpm_format("XZ VLI value overflows"))?;
        value = value
            .checked_add(shifted)
            .ok_or_else(|| rpm_format("XZ VLI value overflows"))?;
        position = position
            .checked_add(1)
            .ok_or_else(|| rpm_format("XZ VLI position overflows"))?;
        if byte & 0x80 == 0 {
            if ordinal != 0 && byte == 0 {
                return Err(rpm_format("XZ VLI is not minimally encoded"));
            }
            return Ok((value, position));
        }
    }
    Err(rpm_format("XZ VLI is too long"))
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let remainder = value % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment
            .checked_sub(remainder)
            .ok_or_else(|| rpm_format("XZ alignment underflows"))?
    };
    value
        .checked_add(padding)
        .ok_or_else(|| rpm_format("XZ alignment overflows"))
}

fn skip_c_string(
    bytes: &[u8],
    start: usize,
    detail: &'static str,
    control: &mut ParseControl<'_>,
) -> Result<usize> {
    let remaining = bytes.get(start..).ok_or_else(|| rpm_format(detail))?;
    let mut length = 0_usize;
    for chunk in remaining.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "gzip string chunk is not representable",
        )?)?;
        if let Some(relative) = chunk.iter().position(|byte| *byte == 0) {
            length = length
                .checked_add(relative)
                .ok_or_else(|| rpm_format("gzip string length overflows"))?;
            return start
                .checked_add(length)
                .and_then(|offset| offset.checked_add(1))
                .ok_or_else(|| rpm_format("gzip string offset overflows"));
        }
        length = length
            .checked_add(chunk.len())
            .ok_or_else(|| rpm_format("gzip string length overflows"))?;
    }
    Err(rpm_format(detail))
}

fn le_u16(bytes: &[u8], offset: usize, detail: &'static str) -> Result<u16> {
    let offset = u64::try_from(offset).map_err(|_| rpm_format(detail))?;
    let value = checked_range(bytes, offset, 2, detail, detail)?;
    Ok(u16::from_le_bytes(
        <[u8; 2]>::try_from(value).map_err(|_| rpm_format(detail))?,
    ))
}

fn le_u32(bytes: &[u8], offset: impl TryInto<u64>, detail: &'static str) -> Result<u32> {
    let offset = offset.try_into().map_err(|_| rpm_format(detail))?;
    let value = checked_range(bytes, offset, 4, detail, detail)?;
    Ok(u32::from_le_bytes(
        <[u8; 4]>::try_from(value).map_err(|_| rpm_format(detail))?,
    ))
}

pub(super) fn sha256_hex(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<String> {
    digest_hex(Sha256::new(), bytes, 64, control)
}

pub(super) fn sha1_hex(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<String> {
    digest_hex(Sha1::new(), bytes, 40, control)
}

fn digest_hex(
    mut hasher: impl Digest,
    bytes: &[u8],
    encoded_length: usize,
    control: &mut ParseControl<'_>,
) -> Result<String> {
    for chunk in bytes.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "RPM digest chunk is not representable",
        )?)?;
        hasher.update(chunk);
    }
    let digest = hasher.finalize();
    let mut encoded = String::new();
    encoded.try_reserve(encoded_length).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "RPM digest allocation failed",
        ))
    })?;
    for byte in digest.iter() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| rpm_format("RPM digest formatting failed"))?;
    }
    Ok(encoded)
}

fn rpm_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("RPM: {detail}"),
    }
}
