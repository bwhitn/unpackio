//! ZIP structural parsing and validation.

use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
};

use rawzip::ZipLocator;

use super::{WinZipAes, ZipCompressionMethod, ZipEncryption, ZipEntry, ZipTimestamp, cp437};
use crate::{
    Error, LimitKind, Limits, Result,
    checksum::Crc32,
    parse_util::{ParseControl, check_limit, checked_range, copy_bytes, try_reserve, usize_to_u64},
};

const CENTRAL_FIXED_BYTES: u64 = 46;
const LOCAL_FIXED_BYTES: u64 = 30;
const EOCD_FIXED_BYTES: u64 = 22;
const EOCD_SEARCH_BYTES: u64 = 65_557;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_STRONG_ENCRYPTION: u16 = 0x0017;
const EXTRA_UNICODE_PATH: u16 = 0x7075;
const EXTRA_WINZIP_AES: u16 = 0x9901;
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
const FLAG_UTF8: u16 = 1 << 11;
const FLAG_MASKED_HEADER_VALUES: u16 = 1 << 13;

pub(super) struct ParsedZip {
    pub(super) entries: Vec<ZipEntry>,
    pub(super) comment: Box<[u8]>,
}

#[derive(Clone, Copy)]
struct CentralFixed {
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    method: u16,
    modified_time: u16,
    modified_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_length: u16,
    extra_length: u16,
    comment_length: u16,
    disk_start: u16,
    internal_attributes: u16,
    external_attributes: u32,
    local_header_offset: u32,
}

#[derive(Clone, Copy)]
struct ResolvedCentral {
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    disk_start: u32,
    descriptor_uses_zip64: bool,
}

#[derive(Clone, Copy)]
struct LocalFixed {
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_length: u16,
    extra_length: u16,
}

pub(super) fn parse(
    bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ParsedZip> {
    catch_unwind(AssertUnwindSafe(|| parse_inner(bytes, limits, control)))
        .map_err(|_| zip_format("structural parser rejected hostile input"))?
}

fn parse_inner(bytes: &[u8], limits: Limits, control: &mut ParseControl<'_>) -> Result<ParsedZip> {
    let slice_start = locate_zip_slice_start(bytes, limits, control)?;
    let archive_bytes = bytes
        .get(slice_start..)
        .ok_or_else(|| zip_format("ZIP image start is outside the input"))?;
    let slice_start = usize_to_u64(slice_start, "ZIP image start is not representable")?;
    let archive = ZipLocator::new()
        .max_search_space(EOCD_SEARCH_BYTES)
        .locate_in_slice(archive_bytes)
        .map_err(|(_, _)| zip_format("end of central directory is missing or invalid"))?;
    let end_offset = absolute_offset(slice_start, archive.end_offset())?;
    let input_size = usize_to_u64(bytes.len(), "ZIP input size is not representable as u64")?;
    if end_offset != input_size {
        return Err(zip_format(
            "end of central directory does not consume the complete input",
        ));
    }
    let directory_offset = absolute_offset(slice_start, archive.directory_offset())?;
    let eocd_offset = absolute_offset(slice_start, archive.eocd_offset())?;
    if directory_offset > eocd_offset || eocd_offset > input_size {
        return Err(zip_format("central-directory bounds are invalid"));
    }
    let header_bytes = input_size
        .checked_sub(directory_offset)
        .ok_or_else(|| zip_format("ZIP header size underflows"))?;
    check_limit(
        header_bytes,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    validate_single_disk(bytes, eocd_offset, slice_start)?;

    let entry_hint = archive.entries_hint();
    check_limit(entry_hint, limits.max_files(), LimitKind::Files)?;
    let capacity = usize::try_from(entry_hint)
        .map_err(|_| zip_format("ZIP entry count is not representable on this platform"))?;
    let mut entries = Vec::new();
    try_reserve(&mut entries, capacity)?;
    let mut ranges = Vec::new();
    try_reserve(&mut ranges, capacity)?;
    let mut iterator = archive.entries();
    let mut count = 0_u64;
    let mut total_name_bytes = 0_u64;
    let mut base_offset = None;
    while let Some(raw_entry) = iterator
        .next_entry()
        .map_err(|_| zip_format("central-directory entry is malformed"))?
    {
        control.checkpoint(1)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| zip_format("ZIP entry count overflows"))?;
        check_limit(count, limits.max_files(), LimitKind::Files)?;
        let central_offset = absolute_offset(slice_start, raw_entry.central_directory_offset())?;
        let fixed = parse_central_fixed(bytes, central_offset)?;
        let variable_start = central_offset
            .checked_add(CENTRAL_FIXED_BYTES)
            .ok_or_else(|| zip_format("central-directory variable offset overflows"))?;
        let name_length = u64::from(fixed.name_length);
        let extra_length = u64::from(fixed.extra_length);
        let comment_length = u64::from(fixed.comment_length);
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|length| length.checked_add(comment_length))
            .ok_or_else(|| zip_format("central-directory variable length overflows"))?;
        let variable = checked_range(
            bytes,
            variable_start,
            variable_length,
            "central-directory variable range overflows",
            "central-directory variable range is truncated",
        )?;
        let name_end = usize::from(fixed.name_length);
        let extra_end = name_end
            .checked_add(usize::from(fixed.extra_length))
            .ok_or_else(|| zip_format("central-directory extra offset overflows"))?;
        let name = variable
            .get(..name_end)
            .ok_or_else(|| zip_format("central-directory name is truncated"))?;
        let extra = variable
            .get(name_end..extra_end)
            .ok_or_else(|| zip_format("central-directory extra fields are truncated"))?;
        let comment = variable
            .get(extra_end..)
            .ok_or_else(|| zip_format("central-directory comment is truncated"))?;
        if raw_entry.file_path().as_bytes() != name {
            return Err(zip_format("structural parser disagrees on an entry name"));
        }
        validate_extra_fields(extra)?;
        check_limit(
            name_length,
            limits.max_name_bytes_per_entry(),
            LimitKind::NameBytesPerEntry,
        )?;
        total_name_bytes = total_name_bytes
            .checked_add(name_length)
            .ok_or_else(|| zip_format("total ZIP name bytes overflow"))?;
        check_limit(
            total_name_bytes,
            limits.max_total_name_bytes(),
            LimitKind::TotalNameBytes,
        )?;

        let resolved = resolve_central(fixed, extra)?;
        if resolved.compressed_size != raw_entry.compressed_size_hint()
            || resolved.uncompressed_size != raw_entry.uncompressed_size_hint()
        {
            return Err(zip_format(
                "structural parser disagrees on ZIP64 entry sizes",
            ));
        }
        if resolved.disk_start != 0 {
            return Err(Error::UnsupportedFeature {
                feature: String::from("split-zip-archive"),
            });
        }
        check_limit(
            resolved.uncompressed_size,
            limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        check_limit(
            resolved.compressed_size,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        let corrected_local = absolute_offset(slice_start, raw_entry.local_header_offset())?;
        let observed_base = corrected_local
            .checked_sub(resolved.local_header_offset)
            .ok_or_else(|| zip_format("SFX base offset underflows"))?;
        if base_offset.is_some_and(|expected| expected != observed_base) {
            return Err(zip_format("entry offsets disagree on the SFX base"));
        }
        base_offset = Some(observed_base);
        let local = validate_local(
            bytes,
            corrected_local,
            name,
            extra,
            fixed,
            resolved,
            directory_offset,
        )?;
        let entry_index = count
            .checked_sub(1)
            .ok_or_else(|| zip_format("ZIP entry index underflows"))?;
        ranges.push((corrected_local, local.record_end, entry_index));

        let aes = parse_aes(extra, fixed.method)?;
        let strong = fixed.flags & (FLAG_STRONG_ENCRYPTION | FLAG_MASKED_HEADER_VALUES) != 0
            || find_unique_extra(extra, EXTRA_STRONG_ENCRYPTION)?.is_some();
        let encrypted = fixed.flags & FLAG_ENCRYPTED != 0;
        let encryption = if strong {
            ZipEncryption::Strong
        } else if let Some(aes) = aes {
            if !encrypted {
                return Err(zip_format("WinZip AES entry omits the encryption flag"));
            }
            ZipEncryption::WinZipAes {
                vendor_version: aes.vendor_version,
                key_bits: u16::try_from(aes.key_bytes)
                    .ok()
                    .and_then(|bytes| bytes.checked_mul(8))
                    .ok_or_else(|| zip_format("WinZip AES key size overflows"))?,
            }
        } else if encrypted {
            ZipEncryption::ZipCrypto
        } else {
            ZipEncryption::None
        };
        let effective_method = aes.map_or(fixed.method, |value| value.method);
        let crc32 = if aes.is_some_and(|value| value.vendor_version == 2) {
            if fixed.crc32 != 0 {
                return Err(zip_format("AE-2 entry must store a zero CRC"));
            }
            None
        } else {
            Some(fixed.crc32)
        };
        let display_name = decode_name(name, fixed.flags, extra, control)?;
        let creator = fixed.version_made_by >> 8;
        let unix_mode = matches!(creator, 3 | 19).then_some(fixed.external_attributes >> 16);
        let [time_high, _] = fixed.modified_time.to_be_bytes();
        let [crc_high, _, _, _] = fixed.crc32.to_be_bytes();
        let zipcrypto_check_byte = if fixed.flags & FLAG_DATA_DESCRIPTOR != 0 {
            time_high
        } else {
            crc_high
        };
        let entry = ZipEntry {
            index: entry_index,
            raw_name: copy_bytes(name, control)?,
            name: display_name,
            raw_comment: copy_bytes(comment, control)?,
            extra: copy_bytes(extra, control)?,
            compression: ZipCompressionMethod::from_id(effective_method),
            encryption,
            compressed_size: resolved.compressed_size,
            uncompressed_size: resolved.uncompressed_size,
            crc32,
            is_directory: name.last() == Some(&b'/'),
            unix_mode,
            modified: parse_dos_timestamp(fixed.modified_date, fixed.modified_time),
            modified_time_raw: fixed.modified_time,
            modified_date_raw: fixed.modified_date,
            version_made_by: fixed.version_made_by,
            version_needed: fixed.version_needed,
            flags: fixed.flags,
            internal_attributes: fixed.internal_attributes,
            external_attributes: fixed.external_attributes,
            local_header_offset: corrected_local,
            data_start: local.data_start,
            data_end: local.data_end,
            zipcrypto_check_byte,
            aes: aes.map(|value| WinZipAes {
                vendor_version: value.vendor_version,
                key_bytes: value.key_bytes,
            }),
        };
        entries.push(entry);
    }
    if count != entry_hint {
        return Err(zip_format(
            "central-directory entry count differs from the EOCD declaration",
        ));
    }
    validate_non_overlapping(&mut ranges, directory_offset)?;
    let comment = archive.comment().as_bytes();
    check_limit(
        usize_to_u64(
            comment.len(),
            "ZIP comment length is not representable as u64",
        )?,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    Ok(ParsedZip {
        entries,
        comment: copy_bytes(comment, control)?,
    })
}

fn locate_zip_slice_start(
    bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<usize> {
    let search_bound = usize::try_from(EOCD_SEARCH_BYTES)
        .map_err(|_| zip_format("EOCD search bound is not representable"))?;
    let scan_start = if bytes.len() >= search_bound {
        bytes
            .len()
            .checked_sub(search_bound)
            .ok_or_else(|| zip_format("EOCD scan offset underflows"))?
    } else {
        0
    };
    let scan = bytes
        .get(scan_start..)
        .ok_or_else(|| zip_format("EOCD search range is invalid"))?;
    control.consume_bytes(scan)?;
    let minimum = usize::try_from(EOCD_FIXED_BYTES)
        .map_err(|_| zip_format("EOCD fixed size is not representable"))?;
    let last = scan
        .len()
        .checked_sub(minimum)
        .ok_or_else(|| zip_format("EOCD is truncated"))?;
    let mut eocd = None;
    for relative in (0..=last).rev() {
        let candidate = scan
            .get(relative..)
            .ok_or_else(|| zip_format("EOCD candidate range is invalid"))?;
        if candidate.get(..4) != Some(&EOCD_SIGNATURE.to_le_bytes()) {
            continue;
        }
        let comment_length =
            usize::from(le_u16(candidate, 20, "EOCD comment length is truncated")?);
        let expected = minimum
            .checked_add(comment_length)
            .ok_or_else(|| zip_format("EOCD length overflows"))?;
        if candidate.len() == expected {
            eocd = Some(
                scan_start
                    .checked_add(relative)
                    .ok_or_else(|| zip_format("EOCD input offset overflows"))?,
            );
            break;
        }
    }
    let eocd = eocd.ok_or_else(|| zip_format("end of central directory is missing"))?;
    let fixed = bytes
        .get(eocd..)
        .and_then(|remaining| remaining.get(..minimum))
        .ok_or_else(|| zip_format("EOCD fixed record is truncated"))?;
    let zip64 = le_u16(fixed, 8, "EOCD disk entry count is truncated")? == u16::MAX
        || le_u16(fixed, 10, "EOCD total entry count is truncated")? == u16::MAX
        || le_u32(fixed, 12, "EOCD directory size is truncated")? == u32::MAX
        || le_u32(fixed, 16, "EOCD directory offset is truncated")? == u32::MAX;
    if !zip64 {
        return Ok(0);
    }
    let locator = eocd
        .checked_sub(20)
        .ok_or_else(|| zip_format("ZIP64 locator offset underflows"))?;
    if le_u32(
        bytes,
        usize_to_u64(locator, "ZIP64 locator is not representable")?,
        "ZIP64 locator is truncated",
    )? != ZIP64_LOCATOR_SIGNATURE
    {
        return Err(zip_format("ZIP64 locator signature is invalid"));
    }
    let declared = le_u64(
        bytes,
        usize_to_u64(
            locator
                .checked_add(8)
                .ok_or_else(|| zip_format("ZIP64 locator offset overflows"))?,
            "ZIP64 locator offset is not representable",
        )?,
        "ZIP64 EOCD offset is truncated",
    )?;
    let maximum_search = match usize::try_from(limits.max_header_bytes()) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    let record_scan_start = if locator >= maximum_search {
        locator
            .checked_sub(maximum_search)
            .ok_or_else(|| zip_format("ZIP64 EOCD scan offset underflows"))?
    } else {
        0
    };
    let record_scan = bytes
        .get(record_scan_start..locator)
        .ok_or_else(|| zip_format("ZIP64 EOCD search range is invalid"))?;
    control.consume_bytes(record_scan)?;
    let mut actual = None;
    for (relative, signature) in record_scan.windows(4).enumerate().rev() {
        if signature != ZIP64_EOCD_SIGNATURE.to_le_bytes() {
            continue;
        }
        let candidate = record_scan_start
            .checked_add(relative)
            .ok_or_else(|| zip_format("ZIP64 EOCD candidate offset overflows"))?;
        let size_offset = candidate
            .checked_add(4)
            .ok_or_else(|| zip_format("ZIP64 EOCD size offset overflows"))?;
        let size = le_u64(
            bytes,
            usize_to_u64(size_offset, "ZIP64 EOCD size offset is not representable")?,
            "ZIP64 EOCD size is truncated",
        )?;
        if size < 44 {
            continue;
        }
        let end = usize_to_u64(candidate, "ZIP64 EOCD offset is not representable")?
            .checked_add(12)
            .and_then(|offset| offset.checked_add(size))
            .ok_or_else(|| zip_format("ZIP64 EOCD range overflows"))?;
        if end == usize_to_u64(locator, "ZIP64 locator offset is not representable")? {
            actual = Some(candidate);
            break;
        }
    }
    let actual = actual.ok_or_else(|| zip_format("ZIP64 EOCD record is missing"))?;
    let declared = usize::try_from(declared)
        .map_err(|_| zip_format("ZIP64 EOCD offset is not representable"))?;
    let prefix = actual
        .checked_sub(declared)
        .ok_or_else(|| zip_format("ZIP64 SFX base offset underflows"))?;
    check_limit(
        usize_to_u64(prefix, "ZIP SFX prefix length is not representable")?,
        limits.sfx_scan_limit(),
        LimitKind::SfxScanBytes,
    )?;
    Ok(prefix)
}

fn absolute_offset(base: u64, relative: u64) -> Result<u64> {
    base.checked_add(relative)
        .ok_or_else(|| zip_format("ZIP absolute offset overflows"))
}

#[derive(Clone, Copy)]
struct LocalRange {
    data_start: u64,
    data_end: u64,
    record_end: u64,
}

fn validate_local(
    bytes: &[u8],
    offset: u64,
    central_name: &[u8],
    central_extra: &[u8],
    central: CentralFixed,
    resolved: ResolvedCentral,
    directory_offset: u64,
) -> Result<LocalRange> {
    let fixed = parse_local_fixed(bytes, offset)?;
    if fixed.flags != central.flags || fixed.method != central.method {
        return Err(zip_format(
            "local and central entry method or flags do not match",
        ));
    }
    let variable_start = offset
        .checked_add(LOCAL_FIXED_BYTES)
        .ok_or_else(|| zip_format("local-header variable offset overflows"))?;
    let variable_length = u64::from(fixed.name_length)
        .checked_add(u64::from(fixed.extra_length))
        .ok_or_else(|| zip_format("local-header variable length overflows"))?;
    let variable = checked_range(
        bytes,
        variable_start,
        variable_length,
        "local-header variable range overflows",
        "local-header variable range is truncated",
    )?;
    let name_end = usize::from(fixed.name_length);
    let local_name = variable
        .get(..name_end)
        .ok_or_else(|| zip_format("local-header name is truncated"))?;
    let local_extra = variable
        .get(name_end..)
        .ok_or_else(|| zip_format("local-header extra fields are truncated"))?;
    if local_name != central_name {
        return Err(zip_format("local and central entry names do not match"));
    }
    validate_extra_fields(local_extra)?;
    let central_aes = parse_aes(central_extra, central.method)?;
    let local_aes = parse_aes(local_extra, fixed.method)?;
    if central_aes != local_aes {
        return Err(zip_format(
            "local and central WinZip AES fields do not match",
        ));
    }
    let data_start = variable_start
        .checked_add(variable_length)
        .ok_or_else(|| zip_format("ZIP entry data offset overflows"))?;
    let data_end = data_start
        .checked_add(resolved.compressed_size)
        .ok_or_else(|| zip_format("ZIP entry data range overflows"))?;
    if data_end > directory_offset {
        return Err(zip_format("ZIP entry data overlaps the central directory"));
    }
    let has_descriptor = fixed.flags & FLAG_DATA_DESCRIPTOR != 0;
    let record_end = if has_descriptor {
        validate_descriptor(
            bytes,
            data_end,
            central.crc32,
            resolved.compressed_size,
            resolved.uncompressed_size,
            resolved.descriptor_uses_zip64,
            directory_offset,
        )?
    } else {
        let (local_compressed, local_uncompressed) = resolve_local_sizes(fixed, local_extra)?;
        if fixed.crc32 != central.crc32
            || local_compressed != resolved.compressed_size
            || local_uncompressed != resolved.uncompressed_size
        {
            return Err(zip_format(
                "local and central entry CRC or sizes do not match",
            ));
        }
        data_end
    };
    Ok(LocalRange {
        data_start,
        data_end,
        record_end,
    })
}

fn validate_descriptor(
    bytes: &[u8],
    offset: u64,
    expected_crc: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
    zip64: bool,
    directory_offset: u64,
) -> Result<u64> {
    let first = le_u32(bytes, offset, "data descriptor is truncated")?;
    if first == DATA_DESCRIPTOR_SIGNATURE {
        let signed_start = offset
            .checked_add(4)
            .ok_or_else(|| zip_format("data-descriptor offset overflows"))?;
        if let Ok(end) = validate_descriptor_values(
            bytes,
            signed_start,
            expected_crc,
            expected_compressed,
            expected_uncompressed,
            zip64,
            directory_offset,
        ) {
            return Ok(end);
        }
        // The descriptor signature is optional, so a CRC-32 whose numeric
        // value equals the signature must also be tried as an unsigned record.
    }
    validate_descriptor_values(
        bytes,
        offset,
        expected_crc,
        expected_compressed,
        expected_uncompressed,
        zip64,
        directory_offset,
    )
}

fn validate_descriptor_values(
    bytes: &[u8],
    values_start: u64,
    expected_crc: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
    zip64: bool,
    directory_offset: u64,
) -> Result<u64> {
    let crc = le_u32(bytes, values_start, "data descriptor CRC is truncated")?;
    let sizes_start = values_start
        .checked_add(4)
        .ok_or_else(|| zip_format("data-descriptor size offset overflows"))?;
    let (compressed, uncompressed, size_bytes) = if zip64 {
        (
            le_u64(
                bytes,
                sizes_start,
                "ZIP64 descriptor compressed size is truncated",
            )?,
            le_u64(
                bytes,
                sizes_start
                    .checked_add(8)
                    .ok_or_else(|| zip_format("ZIP64 descriptor offset overflows"))?,
                "ZIP64 descriptor uncompressed size is truncated",
            )?,
            16_u64,
        )
    } else {
        (
            u64::from(le_u32(
                bytes,
                sizes_start,
                "data descriptor compressed size is truncated",
            )?),
            u64::from(le_u32(
                bytes,
                sizes_start
                    .checked_add(4)
                    .ok_or_else(|| zip_format("data-descriptor offset overflows"))?,
                "data descriptor uncompressed size is truncated",
            )?),
            8_u64,
        )
    };
    if crc != expected_crc
        || compressed != expected_compressed
        || uncompressed != expected_uncompressed
    {
        return Err(zip_format(
            "data descriptor disagrees with the central entry",
        ));
    }
    let end = sizes_start
        .checked_add(size_bytes)
        .ok_or_else(|| zip_format("data-descriptor range overflows"))?;
    if end > directory_offset {
        return Err(zip_format("data descriptor overlaps the central directory"));
    }
    Ok(end)
}

fn resolve_local_sizes(fixed: LocalFixed, extra: &[u8]) -> Result<(u64, u64)> {
    let needs_uncompressed = fixed.uncompressed_size == u32::MAX;
    let needs_compressed = fixed.compressed_size == u32::MAX;
    if !needs_uncompressed && !needs_compressed {
        return Ok((
            u64::from(fixed.compressed_size),
            u64::from(fixed.uncompressed_size),
        ));
    }
    let field = find_unique_extra(extra, EXTRA_ZIP64)?
        .ok_or_else(|| zip_format("local ZIP64 sizes are missing"))?;
    let mut position = 0_u64;
    let uncompressed = if needs_uncompressed {
        let value = le_u64(
            field,
            position,
            "local ZIP64 uncompressed size is truncated",
        )?;
        position = position
            .checked_add(8)
            .ok_or_else(|| zip_format("local ZIP64 offset overflows"))?;
        value
    } else {
        u64::from(fixed.uncompressed_size)
    };
    let compressed = if needs_compressed {
        let value = le_u64(field, position, "local ZIP64 compressed size is truncated")?;
        position = position
            .checked_add(8)
            .ok_or_else(|| zip_format("local ZIP64 offset overflows"))?;
        value
    } else {
        u64::from(fixed.compressed_size)
    };
    if position != usize_to_u64(field.len(), "local ZIP64 field size is not representable")? {
        return Err(zip_format("local ZIP64 size field has trailing bytes"));
    }
    Ok((compressed, uncompressed))
}

fn resolve_central(fixed: CentralFixed, extra: &[u8]) -> Result<ResolvedCentral> {
    let needs_uncompressed = fixed.uncompressed_size == u32::MAX;
    let needs_compressed = fixed.compressed_size == u32::MAX;
    let needs_offset = fixed.local_header_offset == u32::MAX;
    let needs_disk = fixed.disk_start == u16::MAX;
    let uses_zip64 = needs_uncompressed || needs_compressed || needs_offset || needs_disk;
    if !uses_zip64 {
        return Ok(ResolvedCentral {
            compressed_size: u64::from(fixed.compressed_size),
            uncompressed_size: u64::from(fixed.uncompressed_size),
            local_header_offset: u64::from(fixed.local_header_offset),
            disk_start: u32::from(fixed.disk_start),
            descriptor_uses_zip64: false,
        });
    }
    let field = find_unique_extra(extra, EXTRA_ZIP64)?
        .ok_or_else(|| zip_format("central ZIP64 field is missing"))?;
    let mut position = 0_u64;
    let uncompressed_size = if needs_uncompressed {
        let value = le_u64(field, position, "ZIP64 uncompressed size is truncated")?;
        position = advance(position, 8, "ZIP64 field offset overflows")?;
        value
    } else {
        u64::from(fixed.uncompressed_size)
    };
    let compressed_size = if needs_compressed {
        let value = le_u64(field, position, "ZIP64 compressed size is truncated")?;
        position = advance(position, 8, "ZIP64 field offset overflows")?;
        value
    } else {
        u64::from(fixed.compressed_size)
    };
    let local_header_offset = if needs_offset {
        let value = le_u64(field, position, "ZIP64 local-header offset is truncated")?;
        position = advance(position, 8, "ZIP64 field offset overflows")?;
        value
    } else {
        u64::from(fixed.local_header_offset)
    };
    let disk_start = if needs_disk {
        let value = le_u32(field, position, "ZIP64 disk number is truncated")?;
        position = advance(position, 4, "ZIP64 field offset overflows")?;
        value
    } else {
        u32::from(fixed.disk_start)
    };
    if position != usize_to_u64(field.len(), "ZIP64 field size is not representable")? {
        return Err(zip_format("central ZIP64 field has trailing bytes"));
    }
    Ok(ResolvedCentral {
        compressed_size,
        uncompressed_size,
        local_header_offset,
        disk_start,
        descriptor_uses_zip64: needs_uncompressed || needs_compressed,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedAes {
    vendor_version: u16,
    key_bytes: usize,
    method: u16,
}

fn parse_aes(extra: &[u8], header_method: u16) -> Result<Option<ParsedAes>> {
    let field = find_unique_extra(extra, EXTRA_WINZIP_AES)?;
    if header_method != 99 {
        if field.is_some() {
            return Err(zip_format("WinZip AES field appears on a non-AES method"));
        }
        return Ok(None);
    }
    let field = field.ok_or_else(|| zip_format("WinZip AES field is missing"))?;
    if field.len() != 7 {
        return Err(zip_format("WinZip AES field must contain seven bytes"));
    }
    let vendor_version = le_u16(field, 0, "WinZip AES vendor version is truncated")?;
    if !matches!(vendor_version, 1 | 2) {
        return Err(zip_format("WinZip AES vendor version is unsupported"));
    }
    if field.get(2..4) != Some(b"AE") {
        return Err(zip_format("WinZip AES vendor identifier is invalid"));
    }
    let strength = field
        .get(4)
        .copied()
        .ok_or_else(|| zip_format("WinZip AES strength is missing"))?;
    let key_bytes = match strength {
        1 => 16,
        2 => 24,
        3 => 32,
        _ => return Err(zip_format("WinZip AES strength is invalid")),
    };
    let method = le_u16(field, 5, "WinZip AES compression method is truncated")?;
    if method == 99 {
        return Err(zip_format("WinZip AES method recursively wraps itself"));
    }
    Ok(Some(ParsedAes {
        vendor_version,
        key_bytes,
        method,
    }))
}

fn decode_name(
    raw_name: &[u8],
    flags: u16,
    extra: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<String> {
    if let Some(unicode) = find_unique_extra(extra, EXTRA_UNICODE_PATH)? {
        if unicode.len() >= 5 && unicode.first() == Some(&1) {
            let expected_crc = le_u32(unicode, 1, "Unicode-path CRC is truncated")?;
            let mut checksum = Crc32::new();
            checksum.update(raw_name)?;
            if checksum.finalize() == expected_crc {
                let utf8 = unicode
                    .get(5..)
                    .ok_or_else(|| zip_format("Unicode-path value is truncated"))?;
                control.consume_bytes(utf8)?;
                return copy_utf8(utf8, "Unicode-path value is not valid UTF-8");
            }
        }
    }
    control.consume_bytes(raw_name)?;
    if flags & FLAG_UTF8 != 0 {
        copy_utf8(raw_name, "UTF-8 name flag is set on an invalid name")
    } else {
        cp437::decode(raw_name)
    }
}

fn copy_utf8(bytes: &[u8], detail: &'static str) -> Result<String> {
    let source = std::str::from_utf8(bytes).map_err(|_| zip_format(detail))?;
    let mut value = String::new();
    value.try_reserve(source.len()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "ZIP string allocation failed",
        ))
    })?;
    value.push_str(source);
    Ok(value)
}

fn validate_extra_fields(bytes: &[u8]) -> Result<()> {
    let mut position = 0_u64;
    let length = usize_to_u64(bytes.len(), "ZIP extra-field size is not representable")?;
    while position < length {
        let header = checked_range(
            bytes,
            position,
            4,
            "ZIP extra-field header range overflows",
            "ZIP extra-field header is truncated",
        )?;
        let body_length = u64::from(le_u16(header, 2, "ZIP extra-field length is truncated")?);
        position = advance(position, 4, "ZIP extra-field offset overflows")?;
        checked_range(
            bytes,
            position,
            body_length,
            "ZIP extra-field body range overflows",
            "ZIP extra-field body is truncated",
        )?;
        position = advance(position, body_length, "ZIP extra-field offset overflows")?;
    }
    if position != length {
        return Err(zip_format("ZIP extra fields were not consumed exactly"));
    }
    Ok(())
}

fn find_unique_extra(bytes: &[u8], identifier: u16) -> Result<Option<&[u8]>> {
    let mut position = 0_u64;
    let length = usize_to_u64(bytes.len(), "ZIP extra-field size is not representable")?;
    let mut found = None;
    while position < length {
        let field_identifier = le_u16(bytes, position, "ZIP extra-field identifier is truncated")?;
        let body_length = u64::from(le_u16(
            bytes,
            advance(position, 2, "ZIP extra-field offset overflows")?,
            "ZIP extra-field length is truncated",
        )?);
        let body_start = advance(position, 4, "ZIP extra-field offset overflows")?;
        let body = checked_range(
            bytes,
            body_start,
            body_length,
            "ZIP extra-field range overflows",
            "ZIP extra-field body is truncated",
        )?;
        if field_identifier == identifier && found.replace(body).is_some() {
            return Err(zip_format("critical ZIP extra field is duplicated"));
        }
        position = advance(body_start, body_length, "ZIP extra-field offset overflows")?;
    }
    Ok(found)
}

fn validate_single_disk(bytes: &[u8], eocd_offset: u64, image_start: u64) -> Result<()> {
    let fixed = checked_range(
        bytes,
        eocd_offset,
        EOCD_FIXED_BYTES,
        "EOCD range overflows",
        "EOCD is truncated",
    )?;
    if le_u32(fixed, 0, "EOCD signature is truncated")? != EOCD_SIGNATURE {
        return Err(zip_format("EOCD signature is invalid"));
    }
    let disk = le_u16(fixed, 4, "EOCD disk number is truncated")?;
    let directory_disk = le_u16(fixed, 6, "EOCD directory disk is truncated")?;
    let disk_entries = le_u16(fixed, 8, "EOCD disk entry count is truncated")?;
    let total_entries = le_u16(fixed, 10, "EOCD total entry count is truncated")?;
    if disk != 0 || directory_disk != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("split-zip-archive"),
        });
    }
    if disk_entries != total_entries && disk_entries != u16::MAX && total_entries != u16::MAX {
        return Err(Error::UnsupportedFeature {
            feature: String::from("split-zip-archive"),
        });
    }
    let zip64 = disk_entries == u16::MAX
        || total_entries == u16::MAX
        || le_u32(fixed, 12, "EOCD directory size is truncated")? == u32::MAX
        || le_u32(fixed, 16, "EOCD directory offset is truncated")? == u32::MAX;
    if !zip64 {
        return Ok(());
    }
    let locator_offset = eocd_offset
        .checked_sub(20)
        .ok_or_else(|| zip_format("ZIP64 locator offset underflows"))?;
    if le_u32(bytes, locator_offset, "ZIP64 locator is truncated")? != ZIP64_LOCATOR_SIGNATURE {
        return Err(zip_format("ZIP64 locator signature is invalid"));
    }
    let zip64_disk = le_u32(
        bytes,
        advance(locator_offset, 4, "ZIP64 locator offset overflows")?,
        "ZIP64 locator disk is truncated",
    )?;
    let zip64_offset = le_u64(
        bytes,
        advance(locator_offset, 8, "ZIP64 locator offset overflows")?,
        "ZIP64 EOCD offset is truncated",
    )?;
    let disks = le_u32(
        bytes,
        advance(locator_offset, 16, "ZIP64 locator offset overflows")?,
        "ZIP64 disk count is truncated",
    )?;
    if zip64_disk != 0 || disks != 1 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("split-zip-archive"),
        });
    }
    let zip64_offset = absolute_offset(image_start, zip64_offset)?;
    if le_u32(bytes, zip64_offset, "ZIP64 EOCD is truncated")? != ZIP64_EOCD_SIGNATURE {
        return Err(zip_format("ZIP64 EOCD signature is invalid"));
    }
    let disk_number = le_u32(
        bytes,
        advance(zip64_offset, 16, "ZIP64 EOCD offset overflows")?,
        "ZIP64 EOCD disk number is truncated",
    )?;
    let directory_disk_number = le_u32(
        bytes,
        advance(zip64_offset, 20, "ZIP64 EOCD offset overflows")?,
        "ZIP64 EOCD directory disk is truncated",
    )?;
    let entries_on_disk = le_u64(
        bytes,
        advance(zip64_offset, 24, "ZIP64 EOCD offset overflows")?,
        "ZIP64 EOCD disk entry count is truncated",
    )?;
    let all_entries = le_u64(
        bytes,
        advance(zip64_offset, 32, "ZIP64 EOCD offset overflows")?,
        "ZIP64 EOCD total entry count is truncated",
    )?;
    if disk_number != 0 || directory_disk_number != 0 || entries_on_disk != all_entries {
        return Err(Error::UnsupportedFeature {
            feature: String::from("split-zip-archive"),
        });
    }
    Ok(())
}

fn validate_non_overlapping(ranges: &mut [(u64, u64, u64)], directory_offset: u64) -> Result<()> {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut previous_end = 0_u64;
    for (start, end, _) in ranges.iter().copied() {
        if start < previous_end || end < start || end > directory_offset {
            return Err(zip_format("ZIP local entry ranges overlap or are invalid"));
        }
        previous_end = end;
    }
    Ok(())
}

fn parse_central_fixed(bytes: &[u8], offset: u64) -> Result<CentralFixed> {
    let fixed = checked_range(
        bytes,
        offset,
        CENTRAL_FIXED_BYTES,
        "central-directory fixed range overflows",
        "central-directory fixed record is truncated",
    )?;
    if le_u32(fixed, 0, "central-directory signature is truncated")? != CENTRAL_SIGNATURE {
        return Err(zip_format("central-directory signature is invalid"));
    }
    Ok(CentralFixed {
        version_made_by: le_u16(fixed, 4, "version-made-by field is truncated")?,
        version_needed: le_u16(fixed, 6, "version-needed field is truncated")?,
        flags: le_u16(fixed, 8, "entry flags are truncated")?,
        method: le_u16(fixed, 10, "entry method is truncated")?,
        modified_time: le_u16(fixed, 12, "entry time is truncated")?,
        modified_date: le_u16(fixed, 14, "entry date is truncated")?,
        crc32: le_u32(fixed, 16, "entry CRC is truncated")?,
        compressed_size: le_u32(fixed, 20, "compressed size is truncated")?,
        uncompressed_size: le_u32(fixed, 24, "uncompressed size is truncated")?,
        name_length: le_u16(fixed, 28, "name length is truncated")?,
        extra_length: le_u16(fixed, 30, "extra length is truncated")?,
        comment_length: le_u16(fixed, 32, "comment length is truncated")?,
        disk_start: le_u16(fixed, 34, "disk-start field is truncated")?,
        internal_attributes: le_u16(fixed, 36, "internal attributes are truncated")?,
        external_attributes: le_u32(fixed, 38, "external attributes are truncated")?,
        local_header_offset: le_u32(fixed, 42, "local-header offset is truncated")?,
    })
}

fn parse_local_fixed(bytes: &[u8], offset: u64) -> Result<LocalFixed> {
    let fixed = checked_range(
        bytes,
        offset,
        LOCAL_FIXED_BYTES,
        "local-header fixed range overflows",
        "local-header fixed record is truncated",
    )?;
    if le_u32(fixed, 0, "local-header signature is truncated")? != LOCAL_SIGNATURE {
        return Err(zip_format("local-header signature is invalid"));
    }
    Ok(LocalFixed {
        flags: le_u16(fixed, 6, "local flags are truncated")?,
        method: le_u16(fixed, 8, "local method is truncated")?,
        crc32: le_u32(fixed, 14, "local CRC is truncated")?,
        compressed_size: le_u32(fixed, 18, "local compressed size is truncated")?,
        uncompressed_size: le_u32(fixed, 22, "local uncompressed size is truncated")?,
        name_length: le_u16(fixed, 26, "local name length is truncated")?,
        extra_length: le_u16(fixed, 28, "local extra length is truncated")?,
    })
}

fn parse_dos_timestamp(date: u16, time: u16) -> Option<ZipTimestamp> {
    let day = u8::try_from(date & 0x1f).ok()?;
    let month = u8::try_from((date >> 5) & 0x0f).ok()?;
    let year = 1980 + ((date >> 9) & 0x7f);
    let second = u8::try_from((time & 0x1f) * 2).ok()?;
    let minute = u8::try_from((time >> 5) & 0x3f).ok()?;
    let hour = u8::try_from((time >> 11) & 0x1f).ok()?;
    if month == 0 || month > 12 || day == 0 || day > 31 || minute > 59 || hour > 23 {
        None
    } else {
        Some(ZipTimestamp {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }
}

fn le_u16(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u16> {
    let value = checked_range(bytes, offset, 2, detail, detail)?;
    let array = <[u8; 2]>::try_from(value).map_err(|_| zip_format(detail))?;
    Ok(u16::from_le_bytes(array))
}

fn le_u32(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u32> {
    let value = checked_range(bytes, offset, 4, detail, detail)?;
    let array = <[u8; 4]>::try_from(value).map_err(|_| zip_format(detail))?;
    Ok(u32::from_le_bytes(array))
}

fn le_u64(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u64> {
    let value = checked_range(bytes, offset, 8, detail, detail)?;
    let array = <[u8; 8]>::try_from(value).map_err(|_| zip_format(detail))?;
    Ok(u64::from_le_bytes(array))
}

fn advance(offset: u64, amount: u64, detail: &'static str) -> Result<u64> {
    offset.checked_add(amount).ok_or_else(|| zip_format(detail))
}

fn zip_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ZIP: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{DATA_DESCRIPTOR_SIGNATURE, parse_dos_timestamp, validate_descriptor};
    use crate::Result;

    #[test]
    fn validates_dos_components() {
        assert!(parse_dos_timestamp(0, 0).is_none());
        let timestamp = parse_dos_timestamp(0x5021, 0);
        assert_eq!(timestamp.map(super::ZipTimestamp::year), Some(2020));
        assert_eq!(timestamp.map(super::ZipTimestamp::month), Some(1));
        assert_eq!(timestamp.map(super::ZipTimestamp::day), Some(1));
    }

    #[test]
    fn accepts_unsigned_descriptor_whose_crc_equals_the_optional_signature() -> Result<()> {
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&DATA_DESCRIPTOR_SIGNATURE.to_le_bytes());
        descriptor.extend_from_slice(&3_u32.to_le_bytes());
        descriptor.extend_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            validate_descriptor(&descriptor, 0, DATA_DESCRIPTOR_SIGNATURE, 3, 3, false, 12,)?,
            12
        );
        Ok(())
    }
}
