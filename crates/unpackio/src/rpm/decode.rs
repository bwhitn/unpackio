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
    decode::{
        ControlledInput, XzProfile, decode_bzip2, decode_deflate, decode_reader, decode_xz,
        decode_zstd,
    },
    parse_util::{ParseControl, check_limit, checked_range, try_reserve, usize_to_u64},
};

const GZIP_FIXED_BYTES: usize = 10;
const GZIP_TRAILER_BYTES: usize = 8;

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
        PayloadCompression::Xz => decode_xz(
            input,
            None,
            maximum,
            limits,
            control,
            XzProfile::PackagePayload,
        ),
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
