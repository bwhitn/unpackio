//! Checked V7, ustar, GNU-extension, and POSIX pax tar parsing for `.deb` payloads.

use super::{DebEntry, DebEntryKind, DebSection};
use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, checked_range, copy_bytes, try_reserve, usize_to_u64},
};

const BLOCK_BYTES: u64 = 512;

#[derive(Default)]
pub(super) struct ArchiveTotals {
    pub(super) files: u64,
    pub(super) name_bytes: u64,
    pub(super) header_bytes: u64,
    pub(super) next_entry_index: u64,
    pub(super) properties: u64,
}

#[derive(Clone, Default)]
struct PaxValues {
    path: Option<Box<[u8]>>,
    link_path: Option<Box<[u8]>>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    modified_time: Option<i64>,
    user_name: Option<Box<[u8]>>,
    group_name: Option<Box<[u8]>>,
}

pub(super) fn parse(
    bytes: &[u8],
    section: DebSection,
    limits: Limits,
    totals: &mut ArchiveTotals,
    control: &mut ParseControl<'_>,
) -> Result<Vec<DebEntry>> {
    let input_size = usize_to_u64(bytes.len(), "tar input size is not representable")?;
    let mut offset = 0_u64;
    let mut entries = Vec::new();
    let mut global_pax = PaxValues::default();
    let mut local_pax = None;
    let mut long_name = None;
    let mut long_link = None;
    let mut saw_end = false;

    while offset < input_size {
        control.checkpoint(1)?;
        let header = checked_range(
            bytes,
            offset,
            BLOCK_BYTES,
            "tar header range overflows",
            "tar header is truncated",
        )?;
        totals.header_bytes = totals
            .header_bytes
            .checked_add(BLOCK_BYTES)
            .ok_or_else(|| deb_format("total tar header bytes overflow"))?;
        check_limit(
            totals.header_bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        if header.iter().all(|byte| *byte == 0) {
            let second_offset = offset
                .checked_add(BLOCK_BYTES)
                .ok_or_else(|| deb_format("tar end marker offset overflows"))?;
            let second = checked_range(
                bytes,
                second_offset,
                BLOCK_BYTES,
                "tar end marker range overflows",
                "tar second end block is truncated",
            )?;
            if second.iter().any(|byte| *byte != 0) {
                return Err(deb_format("tar second end block is nonzero"));
            }
            totals.header_bytes = totals
                .header_bytes
                .checked_add(BLOCK_BYTES)
                .ok_or_else(|| deb_format("total tar header bytes overflow"))?;
            check_limit(
                totals.header_bytes,
                limits.max_header_bytes(),
                LimitKind::HeaderBytes,
            )?;
            let trailing_start = second_offset
                .checked_add(BLOCK_BYTES)
                .ok_or_else(|| deb_format("tar trailing offset overflows"))?;
            let trailing_length = input_size
                .checked_sub(trailing_start)
                .ok_or_else(|| deb_format("tar trailing range underflows"))?;
            let trailing = checked_range(
                bytes,
                trailing_start,
                trailing_length,
                "tar trailing range overflows",
                "tar trailing range is truncated",
            )?;
            if trailing.iter().any(|byte| *byte != 0) {
                return Err(deb_format("tar has nonzero bytes after its end marker"));
            }
            control.consume_bytes(trailing)?;
            saw_end = true;
            break;
        }

        verify_header_checksum(header, control)?;
        validate_magic(header)?;
        let header_size = tar_u64(header, 124, 12, "tar size is invalid")?;
        let type_flag = header
            .get(156)
            .copied()
            .ok_or_else(|| deb_format("tar type flag is truncated"))?;
        let data_start = offset
            .checked_add(BLOCK_BYTES)
            .ok_or_else(|| deb_format("tar data offset overflows"))?;

        if matches!(type_flag, b'g' | b'x' | b'L' | b'K') {
            check_limit(
                header_size,
                limits.max_header_bytes(),
                LimitKind::HeaderBytes,
            )?;
            totals.header_bytes = totals
                .header_bytes
                .checked_add(header_size)
                .ok_or_else(|| deb_format("total tar header bytes overflow"))?;
            check_limit(
                totals.header_bytes,
                limits.max_header_bytes(),
                LimitKind::HeaderBytes,
            )?;
            let data = checked_range(
                bytes,
                data_start,
                header_size,
                "tar extension data range overflows",
                "tar extension data is truncated",
            )?;
            match type_flag {
                b'g' => parse_pax(data, &mut global_pax, limits, totals, control)?,
                b'x' => {
                    let mut values = PaxValues::default();
                    parse_pax(data, &mut values, limits, totals, control)?;
                    local_pax = Some(values);
                }
                b'L' => long_name = Some(parse_long_value(data, limits, control)?),
                b'K' => long_link = Some(parse_long_value(data, limits, control)?),
                _ => return Err(deb_format("internal tar extension dispatch is invalid")),
            }
            offset = next_record_offset(data_start, header_size)?;
            continue;
        }

        let local = local_pax.take().unwrap_or_default();
        let header_name = header_path(header, limits, control)?;
        let pending_long_name = long_name.take();
        let name = local
            .path
            .as_deref()
            .or(global_pax.path.as_deref())
            .or(pending_long_name.as_deref())
            .unwrap_or(&header_name);
        validate_name(name, limits, totals)?;

        let header_link = tar_string(header, 157, 100, "tar link name is truncated")?;
        let pending_long_link = long_link.take();
        let link = local
            .link_path
            .as_deref()
            .or(global_pax.link_path.as_deref())
            .or(pending_long_link.as_deref())
            .or((!header_link.is_empty()).then_some(header_link));
        if let Some(value) = link {
            if value.contains(&0) {
                return Err(deb_format("tar link name contains NUL"));
            }
            check_limit(
                usize_to_u64(value.len(), "tar link name length is not representable")?,
                limits.max_name_bytes_per_entry(),
                LimitKind::NameBytesPerEntry,
            )?;
        }

        let size = local.size.or(global_pax.size).unwrap_or(header_size);
        check_limit(
            size,
            limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| deb_format("tar member data range overflows"))?;
        let _ = checked_range(
            bytes,
            data_start,
            size,
            "tar member data range overflows",
            "tar member data is truncated",
        )?;
        totals.files = totals
            .files
            .checked_add(1)
            .ok_or_else(|| deb_format("total Debian entry count overflows"))?;
        check_limit(totals.files, limits.max_files(), LimitKind::Files)?;
        let index = totals.next_entry_index;
        totals.next_entry_index = totals
            .next_entry_index
            .checked_add(1)
            .ok_or_else(|| deb_format("Debian entry index overflows"))?;
        let mode_value = tar_u64(header, 100, 8, "tar mode is invalid")?;
        let mode = u32::try_from(mode_value).map_err(|_| deb_format("tar mode is too large"))?;
        let uid =
            local
                .uid
                .or(global_pax.uid)
                .unwrap_or(tar_u64(header, 108, 8, "tar uid is invalid")?);
        let gid =
            local
                .gid
                .or(global_pax.gid)
                .unwrap_or(tar_u64(header, 116, 8, "tar gid is invalid")?);
        let modified_time = local
            .modified_time
            .or(global_pax.modified_time)
            .or(Some(tar_i64(header, 136, 12, "tar mtime is invalid")?));
        let header_user = tar_string(header, 265, 32, "tar user name is truncated")?;
        let header_group = tar_string(header, 297, 32, "tar group name is truncated")?;
        let user_name = local
            .user_name
            .as_deref()
            .or(global_pax.user_name.as_deref())
            .or((!header_user.is_empty()).then_some(header_user));
        let group_name = local
            .group_name
            .as_deref()
            .or(global_pax.group_name.as_deref())
            .or((!header_group.is_empty()).then_some(header_group));
        let kind = DebEntryKind::from_type_flag(type_flag);
        let device_major = if matches!(
            kind,
            DebEntryKind::BlockDevice | DebEntryKind::CharacterDevice
        ) {
            let value = tar_u64(header, 329, 8, "tar device major is invalid")?;
            Some(u32::try_from(value).map_err(|_| deb_format("tar device major is too large"))?)
        } else {
            None
        };
        let device_minor = if matches!(
            kind,
            DebEntryKind::BlockDevice | DebEntryKind::CharacterDevice
        ) {
            let value = tar_u64(header, 337, 8, "tar device minor is invalid")?;
            Some(u32::try_from(value).map_err(|_| deb_format("tar device minor is too large"))?)
        } else {
            None
        };
        let checksum = tar_u64(header, 148, 8, "tar checksum is invalid")?;
        let checksum =
            u32::try_from(checksum).map_err(|_| deb_format("tar checksum is too large"))?;
        if entries.len() == entries.capacity() {
            try_reserve(&mut entries, 1)?;
        }
        entries.push(DebEntry {
            index,
            section,
            raw_name: copy_bytes(name, control)?,
            raw_link_name: copy_optional(link, control)?,
            kind,
            mode,
            uid,
            gid,
            modified_time,
            size,
            user_name: copy_optional(user_name, control)?,
            group_name: copy_optional(group_name, control)?,
            device_major,
            device_minor,
            header_checksum: checksum,
            data_start,
            data_end,
        });
        offset = next_record_offset(data_start, size)?;
    }
    if !saw_end {
        return Err(deb_format("tar end marker is missing"));
    }
    if local_pax.is_some() || long_name.is_some() || long_link.is_some() {
        return Err(deb_format("tar extension header has no following member"));
    }
    Ok(entries)
}

impl DebEntryKind {
    fn from_type_flag(value: u8) -> Self {
        match value {
            0 | b'0' | b'7' => Self::Regular,
            b'1' => Self::HardLink,
            b'2' => Self::SymbolicLink,
            b'3' => Self::CharacterDevice,
            b'4' => Self::BlockDevice,
            b'5' => Self::Directory,
            b'6' => Self::Fifo,
            other => Self::Other(other),
        }
    }
}

fn verify_header_checksum(header: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let expected = tar_u64(header, 148, 8, "tar checksum is invalid")?;
    let mut unsigned = 0_u64;
    let mut signed = 0_i64;
    for (index, byte) in header.iter().copied().enumerate() {
        control.checkpoint(1)?;
        let value = if (148..156).contains(&index) {
            b' '
        } else {
            byte
        };
        unsigned = unsigned
            .checked_add(u64::from(value))
            .ok_or_else(|| deb_format("tar checksum overflows"))?;
        signed = signed
            .checked_add(i64::from(i8::from_ne_bytes([value])))
            .ok_or_else(|| deb_format("tar signed checksum overflows"))?;
    }
    let signed_matches = u64::try_from(signed).ok() == Some(expected);
    if unsigned != expected && !signed_matches {
        return Err(crate::Error::Checksum {
            scope: crate::ChecksumScope::PackageHeader,
            member_index: None,
        });
    }
    Ok(())
}

fn validate_magic(header: &[u8]) -> Result<()> {
    let magic = header
        .get(257..263)
        .ok_or_else(|| deb_format("tar magic is truncated"))?;
    if magic == b"ustar\0" || magic == b"ustar " || magic.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(deb_format("tar magic is invalid"))
    }
}

fn header_path(header: &[u8], limits: Limits, control: &mut ParseControl<'_>) -> Result<Box<[u8]>> {
    let name = tar_string(header, 0, 100, "tar name is truncated")?;
    let prefix = tar_string(header, 345, 155, "tar prefix is truncated")?;
    if prefix.is_empty() {
        return copy_bytes(name, control);
    }
    let total = prefix
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(name.len()))
        .ok_or_else(|| deb_format("tar path length overflows"))?;
    check_limit(
        usize_to_u64(total, "tar path length is not representable")?,
        limits.max_name_bytes_per_entry(),
        LimitKind::NameBytesPerEntry,
    )?;
    let mut value = Vec::new();
    try_reserve(&mut value, total)?;
    control.checkpoint(usize_to_u64(
        total,
        "tar path copy length is not representable",
    )?)?;
    value.extend_from_slice(prefix);
    value.push(b'/');
    value.extend_from_slice(name);
    Ok(value.into_boxed_slice())
}

fn validate_name(name: &[u8], limits: Limits, totals: &mut ArchiveTotals) -> Result<()> {
    if name.is_empty() {
        return Err(deb_format("tar member name is empty"));
    }
    if name.contains(&0) {
        return Err(deb_format("tar member name contains NUL"));
    }
    let length = usize_to_u64(name.len(), "tar member name length is not representable")?;
    check_limit(
        length,
        limits.max_name_bytes_per_entry(),
        LimitKind::NameBytesPerEntry,
    )?;
    totals.name_bytes = totals
        .name_bytes
        .checked_add(length)
        .ok_or_else(|| deb_format("total Debian name bytes overflow"))?;
    check_limit(
        totals.name_bytes,
        limits.max_total_name_bytes(),
        LimitKind::TotalNameBytes,
    )
}

fn parse_pax(
    data: &[u8],
    values: &mut PaxValues,
    limits: Limits,
    totals: &mut ArchiveTotals,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let mut offset = 0_u64;
    let data_size = usize_to_u64(data.len(), "pax data length is not representable")?;
    while offset < data_size {
        control.checkpoint(1)?;
        totals.properties = totals
            .properties
            .checked_add(1)
            .ok_or_else(|| deb_format("pax property count overflows"))?;
        check_limit(
            totals.properties,
            limits.max_header_properties(),
            LimitKind::HeaderProperties,
        )?;
        let remaining = checked_range(
            data,
            offset,
            data_size
                .checked_sub(offset)
                .ok_or_else(|| deb_format("pax remaining length underflows"))?,
            "pax record range overflows",
            "pax record is truncated",
        )?;
        let separator = remaining
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| deb_format("pax record length is not terminated"))?;
        let length_digits = remaining
            .get(..separator)
            .ok_or_else(|| deb_format("pax record length range is invalid"))?;
        let record_length = decimal_bytes(length_digits, "pax record length is invalid")?;
        if record_length == 0 {
            return Err(deb_format("pax record length is zero"));
        }
        let record = checked_range(
            data,
            offset,
            record_length,
            "pax record range overflows",
            "pax record is truncated",
        )?;
        if record.last() != Some(&b'\n') {
            return Err(deb_format("pax record is not newline terminated"));
        }
        let prefix_bytes = separator
            .checked_add(1)
            .ok_or_else(|| deb_format("pax record prefix length overflows"))?;
        let prefix_bytes = u64::try_from(prefix_bytes)
            .map_err(|_| deb_format("pax record prefix length is not representable"))?;
        let body_length = record_length
            .checked_sub(prefix_bytes)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| deb_format("pax record body length underflows"))?;
        let body = checked_range(
            record,
            prefix_bytes,
            body_length,
            "pax record body range overflows",
            "pax record body is truncated",
        )?;
        let equals = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| deb_format("pax record has no equals separator"))?;
        let key = body
            .get(..equals)
            .ok_or_else(|| deb_format("pax key range is invalid"))?;
        let value_start = equals
            .checked_add(1)
            .ok_or_else(|| deb_format("pax value offset overflows"))?;
        let value = body
            .get(value_start..)
            .ok_or_else(|| deb_format("pax value range is invalid"))?;
        apply_pax_value(key, value, values, limits, control)?;
        offset = offset
            .checked_add(record_length)
            .ok_or_else(|| deb_format("pax record offset overflows"))?;
    }
    if offset != data_size {
        return Err(deb_format("pax records were not consumed exactly"));
    }
    Ok(())
}

fn apply_pax_value(
    key: &[u8],
    value: &[u8],
    values: &mut PaxValues,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    match key {
        b"path" => values.path = Some(copy_pax_name(value, limits, control)?),
        b"linkpath" => values.link_path = Some(copy_pax_name(value, limits, control)?),
        b"size" => values.size = Some(decimal_bytes(value, "pax size is invalid")?),
        b"uid" => values.uid = Some(decimal_bytes(value, "pax uid is invalid")?),
        b"gid" => values.gid = Some(decimal_bytes(value, "pax gid is invalid")?),
        b"mtime" => values.modified_time = Some(pax_time(value)?),
        b"uname" => values.user_name = Some(copy_pax_name(value, limits, control)?),
        b"gname" => values.group_name = Some(copy_pax_name(value, limits, control)?),
        _ => control.consume_bytes(value)?,
    }
    Ok(())
}

fn copy_pax_name(
    value: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Box<[u8]>> {
    if value.contains(&0) {
        return Err(deb_format("pax string contains NUL"));
    }
    check_limit(
        usize_to_u64(value.len(), "pax string length is not representable")?,
        limits.max_name_bytes_per_entry(),
        LimitKind::NameBytesPerEntry,
    )?;
    copy_bytes(value, control)
}

fn parse_long_value(
    data: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Box<[u8]>> {
    let mut end = data.len();
    while end > 0 {
        let previous = end
            .checked_sub(1)
            .ok_or_else(|| deb_format("GNU tar string length underflows"))?;
        let byte = data
            .get(previous)
            .copied()
            .ok_or_else(|| deb_format("GNU tar string is truncated"))?;
        if matches!(byte, 0 | b'\n') {
            end = previous;
        } else {
            break;
        }
    }
    let value = data
        .get(..end)
        .ok_or_else(|| deb_format("GNU tar string range is invalid"))?;
    copy_pax_name(value, limits, control)
}

fn tar_string<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    length: u64,
    detail: &'static str,
) -> Result<&'bytes [u8]> {
    let field = checked_range(bytes, offset, length, detail, detail)?;
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let value = field.get(..end).ok_or_else(|| deb_format(detail))?;
    let remainder = field.get(end..).ok_or_else(|| deb_format(detail))?;
    if remainder.iter().any(|byte| *byte != 0 && *byte != b' ') {
        return Err(deb_format("tar string padding is invalid"));
    }
    Ok(value)
}

fn tar_u64(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<u64> {
    let value = tar_i128(bytes, offset, length, detail)?;
    u64::try_from(value).map_err(|_| deb_format(detail))
}

fn tar_i64(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<i64> {
    let value = tar_i128(bytes, offset, length, detail)?;
    i64::try_from(value).map_err(|_| deb_format(detail))
}

fn tar_i128(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<i128> {
    let field = checked_range(bytes, offset, length, detail, detail)?;
    let first = field.first().copied().ok_or_else(|| deb_format(detail))?;
    if first & 0x80 != 0 {
        let bit_count = field
            .len()
            .checked_mul(8)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| deb_format(detail))?;
        if bit_count >= 127 {
            return Err(deb_format(detail));
        }
        let mut value = i128::from(first & 0x7f);
        for byte in field.iter().copied().skip(1) {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(i128::from(byte)))
                .ok_or_else(|| deb_format(detail))?;
        }
        let sign_shift = u32::try_from(bit_count.checked_sub(1).ok_or_else(|| deb_format(detail))?)
            .map_err(|_| deb_format(detail))?;
        let magnitude_shift = u32::try_from(bit_count).map_err(|_| deb_format(detail))?;
        let sign = 1_i128
            .checked_shl(sign_shift)
            .ok_or_else(|| deb_format(detail))?;
        if value & sign != 0 {
            let modulus = 1_i128
                .checked_shl(magnitude_shift)
                .ok_or_else(|| deb_format(detail))?;
            value = value
                .checked_sub(modulus)
                .ok_or_else(|| deb_format(detail))?;
        }
        return Ok(value);
    }
    let mut value = 0_i128;
    let mut saw_digit = false;
    let mut trailing = false;
    for byte in field.iter().copied() {
        if matches!(byte, 0 | b' ') {
            if saw_digit {
                trailing = true;
            }
            continue;
        }
        if trailing {
            return Err(deb_format(detail));
        }
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit < 8)
            .ok_or_else(|| deb_format(detail))?;
        saw_digit = true;
        value = value
            .checked_mul(8)
            .and_then(|current| current.checked_add(i128::from(digit)))
            .ok_or_else(|| deb_format(detail))?;
    }
    Ok(value)
}

fn decimal_bytes(bytes: &[u8], detail: &'static str) -> Result<u64> {
    if bytes.is_empty() {
        return Err(deb_format(detail));
    }
    let mut value = 0_u64;
    for byte in bytes.iter().copied() {
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit < 10)
            .ok_or_else(|| deb_format(detail))?;
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(digit)))
            .ok_or_else(|| deb_format(detail))?;
    }
    Ok(value)
}

fn pax_time(bytes: &[u8]) -> Result<i64> {
    let (negative, digits) = if bytes.first() == Some(&b'-') {
        (
            true,
            bytes
                .get(1..)
                .ok_or_else(|| deb_format("pax mtime is invalid"))?,
        )
    } else {
        (false, bytes)
    };
    let seconds = digits
        .split(|byte| *byte == b'.')
        .next()
        .ok_or_else(|| deb_format("pax mtime is invalid"))?;
    let value = decimal_bytes(seconds, "pax mtime is invalid")?;
    let value = i64::try_from(value).map_err(|_| deb_format("pax mtime is too large"))?;
    if negative {
        value
            .checked_neg()
            .ok_or_else(|| deb_format("pax mtime overflows"))
    } else {
        Ok(value)
    }
}

fn copy_optional(
    value: Option<&[u8]>,
    control: &mut ParseControl<'_>,
) -> Result<Option<Box<[u8]>>> {
    value.map(|bytes| copy_bytes(bytes, control)).transpose()
}

fn next_record_offset(data_start: u64, size: u64) -> Result<u64> {
    let data_end = data_start
        .checked_add(size)
        .ok_or_else(|| deb_format("tar record data range overflows"))?;
    align_up(data_end, BLOCK_BYTES)
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let remainder = value % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment
            .checked_sub(remainder)
            .ok_or_else(|| deb_format("tar alignment underflows"))?
    };
    value
        .checked_add(padding)
        .ok_or_else(|| deb_format("tar alignment overflows"))
}

fn deb_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("Debian package: {detail}"),
    }
}
