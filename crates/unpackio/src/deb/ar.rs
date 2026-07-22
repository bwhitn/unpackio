//! Checked System V ar parsing for Debian package members.

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, checked_range, copy_bytes, try_reserve, usize_to_u64},
};

const GLOBAL_HEADER: &[u8] = b"!<arch>\n";
const MEMBER_HEADER_BYTES: u64 = 60;

#[derive(Debug)]
pub(super) struct ArMember {
    pub(super) index: u64,
    pub(super) raw_name: Box<[u8]>,
    pub(super) modified_time: u64,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
    pub(super) size: u64,
    pub(super) data_start: u64,
    pub(super) data_end: u64,
}

pub(super) fn parse(
    bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<ArMember>> {
    let magic = checked_range(
        bytes,
        0,
        usize_to_u64(GLOBAL_HEADER.len(), "ar magic length is not representable")?,
        "ar magic range overflows",
        "ar global header is truncated",
    )?;
    control.consume_bytes(magic)?;
    if magic != GLOBAL_HEADER {
        return Err(deb_format("ar global header is invalid"));
    }
    let input_size = usize_to_u64(bytes.len(), "ar input size is not representable")?;
    let mut offset = usize_to_u64(GLOBAL_HEADER.len(), "ar header length is not representable")?;
    let mut entries = Vec::new();
    let mut total_name_bytes = 0_u64;
    let mut total_header_bytes = 0_u64;
    while offset < input_size {
        control.checkpoint(1)?;
        total_header_bytes = total_header_bytes
            .checked_add(MEMBER_HEADER_BYTES)
            .ok_or_else(|| deb_format("total ar header bytes overflow"))?;
        check_limit(
            total_header_bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        let header = checked_range(
            bytes,
            offset,
            MEMBER_HEADER_BYTES,
            "ar member header range overflows",
            "ar member header is truncated",
        )?;
        control.consume_bytes(header)?;
        if header.get(58..60) != Some(&b"`\n"[..]) {
            return Err(deb_format("ar member header terminator is invalid"));
        }
        let name_field = header
            .get(..16)
            .ok_or_else(|| deb_format("ar member name is truncated"))?;
        let raw_name = parse_name(name_field)?;
        let name_length =
            usize_to_u64(raw_name.len(), "ar member name length is not representable")?;
        check_limit(
            name_length,
            limits.max_name_bytes_per_entry(),
            LimitKind::NameBytesPerEntry,
        )?;
        total_name_bytes = total_name_bytes
            .checked_add(name_length)
            .ok_or_else(|| deb_format("total ar member name bytes overflow"))?;
        check_limit(
            total_name_bytes,
            limits.max_total_name_bytes(),
            LimitKind::TotalNameBytes,
        )?;
        let modified_time = decimal_u64(header, 16, 12, "ar timestamp is invalid")?;
        let uid_value = decimal_u64(header, 28, 6, "ar uid is invalid")?;
        let gid_value = decimal_u64(header, 34, 6, "ar gid is invalid")?;
        let uid = u32::try_from(uid_value).map_err(|_| deb_format("ar uid is too large"))?;
        let gid = u32::try_from(gid_value).map_err(|_| deb_format("ar gid is too large"))?;
        let mode_value = octal_u64(header, 40, 8, "ar mode is invalid")?;
        let mode = u32::try_from(mode_value).map_err(|_| deb_format("ar mode is too large"))?;
        let size = decimal_u64(header, 48, 10, "ar member size is invalid")?;
        let data_start = offset
            .checked_add(MEMBER_HEADER_BYTES)
            .ok_or_else(|| deb_format("ar member data offset overflows"))?;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| deb_format("ar member data range overflows"))?;
        let _ = checked_range(
            bytes,
            data_start,
            size,
            "ar member data range overflows",
            "ar member data is truncated",
        )?;
        let next_count = usize_to_u64(entries.len(), "ar member count is not representable")?
            .checked_add(1)
            .ok_or_else(|| deb_format("ar member count overflows"))?;
        check_limit(next_count, limits.max_files(), LimitKind::Files)?;
        if entries.len() == entries.capacity() {
            try_reserve(&mut entries, 1)?;
        }
        entries.push(ArMember {
            index: next_count
                .checked_sub(1)
                .ok_or_else(|| deb_format("ar member index underflows"))?,
            raw_name: copy_bytes(raw_name, control)?,
            modified_time,
            uid,
            gid,
            mode,
            size,
            data_start,
            data_end,
        });
        offset = data_end;
        if size & 1 != 0 {
            let padding = checked_range(
                bytes,
                offset,
                1,
                "ar padding range overflows",
                "ar member padding is truncated",
            )?;
            if padding != b"\n" {
                return Err(deb_format("ar member padding is invalid"));
            }
            offset = offset
                .checked_add(1)
                .ok_or_else(|| deb_format("ar member padding offset overflows"))?;
        }
    }
    Ok(entries)
}

fn parse_name(field: &[u8]) -> Result<&[u8]> {
    let mut end = field.len();
    while end > 0 {
        let previous = end
            .checked_sub(1)
            .ok_or_else(|| deb_format("ar name trimming underflows"))?;
        let byte = field
            .get(previous)
            .copied()
            .ok_or_else(|| deb_format("ar name field is truncated"))?;
        if byte == b' ' {
            end = previous;
        } else {
            break;
        }
    }
    let mut name = field
        .get(..end)
        .ok_or_else(|| deb_format("ar name range is invalid"))?;
    if name.ends_with(b"/") && name != b"/" && name != b"//" {
        let without_slash = name
            .len()
            .checked_sub(1)
            .ok_or_else(|| deb_format("ar name length underflows"))?;
        name = name
            .get(..without_slash)
            .ok_or_else(|| deb_format("ar name range is invalid"))?;
    }
    if name.is_empty() {
        return Err(deb_format("ar member name is empty"));
    }
    if name.contains(&0) {
        return Err(deb_format("ar member name contains NUL"));
    }
    if name.starts_with(b"#1/") || name == b"//" || name.starts_with(b"/") {
        return Err(Error::UnsupportedFeature {
            feature: String::from("deb-non-system-v-ar-name"),
        });
    }
    Ok(name)
}

fn decimal_u64(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<u64> {
    positional_u64(bytes, offset, length, 10, detail)
}

fn octal_u64(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<u64> {
    positional_u64(bytes, offset, length, 8, detail)
}

fn positional_u64(
    bytes: &[u8],
    offset: u64,
    length: u64,
    radix: u8,
    detail: &'static str,
) -> Result<u64> {
    let field = checked_range(bytes, offset, length, detail, detail)?;
    let mut value = 0_u64;
    let mut saw_digit = false;
    let mut trailing_space = false;
    for byte in field.iter().copied() {
        if byte == b' ' {
            if saw_digit {
                trailing_space = true;
            }
            continue;
        }
        if trailing_space {
            return Err(deb_format(detail));
        }
        let digit = byte
            .checked_sub(b'0')
            .filter(|digit| *digit < radix)
            .ok_or_else(|| deb_format(detail))?;
        saw_digit = true;
        value = value
            .checked_mul(u64::from(radix))
            .and_then(|current| current.checked_add(u64::from(digit)))
            .ok_or_else(|| deb_format(detail))?;
    }
    if saw_digit { Ok(value) } else { Ok(0) }
}

fn deb_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("Debian package: {detail}"),
    }
}
