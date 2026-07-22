//! Bounded RPM lead and header-store parsing.

use super::{RpmHeader, RpmHeaderEntry, RpmLead, RpmValue};
use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, checked_range, copy_bytes, try_reserve, usize_to_u64},
};
use std::mem::size_of;

const LEAD_BYTES: u64 = 96;
const LEAD_MAGIC: &[u8] = &[0xed, 0xab, 0xee, 0xdb];
const HEADER_MAGIC: &[u8] = &[0x8e, 0xad, 0xe8];
const HEADER_FIXED_BYTES: u64 = 16;
const INDEX_BYTES: u64 = 16;

pub(super) struct ParsedHeaders {
    pub(super) lead: RpmLead,
    pub(super) signature: RpmHeader,
    pub(super) header: RpmHeader,
    pub(super) main_start: u64,
    pub(super) payload_start: u64,
}

pub(super) fn parse(
    bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ParsedHeaders> {
    let mut model = ModelAccount::new(limits.max_header_bytes());
    let lead_bytes = checked_range(
        bytes,
        0,
        LEAD_BYTES,
        "RPM lead range overflows",
        "RPM lead is truncated",
    )?;
    control.consume_bytes(lead_bytes)?;
    if lead_bytes.get(..4) != Some(LEAD_MAGIC) {
        return Err(rpm_format("lead magic is invalid"));
    }
    let major = lead_bytes
        .get(4)
        .copied()
        .ok_or_else(|| rpm_format("lead major version is missing"))?;
    let minor = lead_bytes
        .get(5)
        .copied()
        .ok_or_else(|| rpm_format("lead minor version is missing"))?;
    if !matches!(major, 3 | 4) {
        return Err(Error::UnsupportedFeature {
            feature: format!("rpm-major-version-{major}"),
        });
    }
    let package_type = be_u16(lead_bytes, 6, "lead package type is truncated")?;
    let architecture = be_u16(lead_bytes, 8, "lead architecture is truncated")?;
    let raw_name = lead_bytes
        .get(10..76)
        .ok_or_else(|| rpm_format("lead package name is truncated"))?;
    let name_end = match raw_name.iter().position(|byte| *byte == 0) {
        Some(position) => position,
        None => raw_name.len(),
    };
    let name = raw_name
        .get(..name_end)
        .ok_or_else(|| rpm_format("lead package-name range is invalid"))?;
    check_limit(
        usize_to_u64(name.len(), "RPM lead name length is not representable")?,
        limits.max_name_bytes_per_entry(),
        LimitKind::NameBytesPerEntry,
    )?;
    model.charge(usize_to_u64(
        name.len(),
        "RPM lead name allocation is not representable",
    )?)?;
    let operating_system = be_u16(lead_bytes, 76, "lead operating system is truncated")?;
    let signature_type = be_u16(lead_bytes, 78, "lead signature type is truncated")?;
    let reserved = <[u8; 16]>::try_from(
        lead_bytes
            .get(80..96)
            .ok_or_else(|| rpm_format("lead reserved bytes are truncated"))?,
    )
    .map_err(|_| rpm_format("lead reserved bytes have the wrong length"))?;
    let lead = RpmLead {
        major,
        minor,
        package_type,
        architecture,
        name: copy_bytes(name, control)?,
        operating_system,
        signature_type,
        reserved,
    };

    let (signature, signature_end) = parse_header(bytes, LEAD_BYTES, limits, control, &mut model)?;
    let main_start = align_up(signature_end, 8, "RPM signature alignment overflows")?;
    let padding_length = main_start
        .checked_sub(signature_end)
        .ok_or_else(|| rpm_format("RPM signature padding underflows"))?;
    let padding = checked_range(
        bytes,
        signature_end,
        padding_length,
        "RPM signature padding range overflows",
        "RPM signature padding is truncated",
    )?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(rpm_format("RPM signature padding is not zero"));
    }
    let (header, payload_start) = parse_header(bytes, main_start, limits, control, &mut model)?;
    Ok(ParsedHeaders {
        lead,
        signature,
        header,
        main_start,
        payload_start,
    })
}

fn parse_header(
    bytes: &[u8],
    start: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
    model: &mut ModelAccount,
) -> Result<(RpmHeader, u64)> {
    let fixed = checked_range(
        bytes,
        start,
        HEADER_FIXED_BYTES,
        "RPM header fixed range overflows",
        "RPM header fixed record is truncated",
    )?;
    if fixed.get(..3) != Some(HEADER_MAGIC) {
        return Err(rpm_format("header magic is invalid"));
    }
    if fixed.get(3).copied() != Some(1) {
        return Err(Error::UnsupportedFeature {
            feature: String::from("rpm-header-version"),
        });
    }
    if fixed
        .get(4..8)
        .ok_or_else(|| rpm_format("header reserved bytes are truncated"))?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(rpm_format("header reserved bytes are nonzero"));
    }
    let count = u64::from(be_u32(fixed, 8, "header index count is truncated")?);
    let store_size = u64::from(be_u32(fixed, 12, "header store size is truncated")?);
    check_limit(
        count,
        limits.max_header_properties(),
        LimitKind::HeaderProperties,
    )?;
    let index_size = count
        .checked_mul(INDEX_BYTES)
        .ok_or_else(|| rpm_format("header index size overflows"))?;
    let store_start = start
        .checked_add(HEADER_FIXED_BYTES)
        .and_then(|offset| offset.checked_add(index_size))
        .ok_or_else(|| rpm_format("header store offset overflows"))?;
    let end = store_start
        .checked_add(store_size)
        .ok_or_else(|| rpm_format("header range overflows"))?;
    let header_size = end
        .checked_sub(start)
        .ok_or_else(|| rpm_format("header size underflows"))?;
    check_limit(
        header_size,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    let complete = checked_range(
        bytes,
        start,
        header_size,
        "RPM header range overflows",
        "RPM header is truncated",
    )?;
    control.consume_bytes(complete)?;
    let store = checked_range(
        bytes,
        store_start,
        store_size,
        "RPM header store range overflows",
        "RPM header store is truncated",
    )?;
    let capacity = usize::try_from(count)
        .map_err(|_| rpm_format("header index count is not representable"))?;
    model.charge_elements::<RpmHeaderEntry>(count)?;
    let mut entries = Vec::new();
    try_reserve(&mut entries, capacity)?;
    for ordinal in 0..count {
        control.checkpoint(1)?;
        let index_start = start
            .checked_add(HEADER_FIXED_BYTES)
            .and_then(|offset| offset.checked_add(ordinal.checked_mul(INDEX_BYTES)?))
            .ok_or_else(|| rpm_format("header index offset overflows"))?;
        let index = checked_range(
            bytes,
            index_start,
            INDEX_BYTES,
            "RPM header index range overflows",
            "RPM header index is truncated",
        )?;
        let tag = be_u32(index, 0, "header tag is truncated")?;
        let value_type = be_u32(index, 4, "header value type is truncated")?;
        let offset = u64::from(be_u32(index, 8, "header value offset is truncated")?);
        let value_count = u64::from(be_u32(index, 12, "header value count is truncated")?);
        let value = parse_value(store, value_type, offset, value_count, control, model)?;
        entries.push(RpmHeaderEntry { tag, value });
    }
    Ok((
        RpmHeader {
            entries: entries.into_boxed_slice(),
            raw_size: header_size,
        },
        end,
    ))
}

fn parse_value(
    store: &[u8],
    value_type: u32,
    offset: u64,
    count: u64,
    control: &mut ParseControl<'_>,
    model: &mut ModelAccount,
) -> Result<RpmValue> {
    match value_type {
        0 => {
            if count != 0 {
                return Err(rpm_format("NULL header value has a nonzero count"));
            }
            Ok(RpmValue::Null)
        }
        1 => Ok(RpmValue::Char(copy_fixed(
            store, offset, count, 1, control, model,
        )?)),
        2 => Ok(RpmValue::Int8(copy_fixed(
            store, offset, count, 1, control, model,
        )?)),
        3 => {
            require_alignment(offset, 2)?;
            model.charge_elements::<u16>(count)?;
            Ok(RpmValue::Int16(parse_int16(store, offset, count)?))
        }
        4 => {
            require_alignment(offset, 4)?;
            model.charge_elements::<u32>(count)?;
            Ok(RpmValue::Int32(parse_int32(store, offset, count)?))
        }
        5 => {
            require_alignment(offset, 8)?;
            model.charge_elements::<u64>(count)?;
            Ok(RpmValue::Int64(parse_int64(store, offset, count)?))
        }
        6 => {
            if count != 1 {
                return Err(rpm_format("STRING header value count must be one"));
            }
            Ok(RpmValue::String(parse_string(
                store, offset, control, model,
            )?))
        }
        7 => Ok(RpmValue::Binary(copy_fixed(
            store, offset, count, 1, control, model,
        )?)),
        8 => Ok(RpmValue::StringArray(parse_strings(
            store, offset, count, control, model,
        )?)),
        9 => Ok(RpmValue::I18nString(parse_strings(
            store, offset, count, control, model,
        )?)),
        other => Err(Error::UnsupportedFeature {
            feature: format!("rpm-header-type-{other}"),
        }),
    }
}

fn copy_fixed(
    store: &[u8],
    offset: u64,
    count: u64,
    width: u64,
    control: &mut ParseControl<'_>,
    model: &mut ModelAccount,
) -> Result<Box<[u8]>> {
    let length = count
        .checked_mul(width)
        .ok_or_else(|| rpm_format("header value byte length overflows"))?;
    let bytes = checked_range(
        store,
        offset,
        length,
        "RPM header value range overflows",
        "RPM header value is out of the store",
    )?;
    model.charge(length)?;
    copy_bytes(bytes, control)
}

fn parse_int16(store: &[u8], offset: u64, count: u64) -> Result<Box<[u16]>> {
    preflight_numeric(store, offset, count, 2)?;
    let capacity =
        usize::try_from(count).map_err(|_| rpm_format("INT16 count is not representable"))?;
    let mut values = Vec::new();
    try_reserve(&mut values, capacity)?;
    for ordinal in 0..count {
        let position = offset
            .checked_add(
                ordinal
                    .checked_mul(2)
                    .ok_or_else(|| rpm_format("INT16 offset overflows"))?,
            )
            .ok_or_else(|| rpm_format("INT16 offset overflows"))?;
        values.push(be_u16(store, position, "INT16 value is truncated")?);
    }
    Ok(values.into_boxed_slice())
}

fn parse_int32(store: &[u8], offset: u64, count: u64) -> Result<Box<[u32]>> {
    preflight_numeric(store, offset, count, 4)?;
    let capacity =
        usize::try_from(count).map_err(|_| rpm_format("INT32 count is not representable"))?;
    let mut values = Vec::new();
    try_reserve(&mut values, capacity)?;
    for ordinal in 0..count {
        let position = offset
            .checked_add(
                ordinal
                    .checked_mul(4)
                    .ok_or_else(|| rpm_format("INT32 offset overflows"))?,
            )
            .ok_or_else(|| rpm_format("INT32 offset overflows"))?;
        values.push(be_u32(store, position, "INT32 value is truncated")?);
    }
    Ok(values.into_boxed_slice())
}

fn parse_int64(store: &[u8], offset: u64, count: u64) -> Result<Box<[u64]>> {
    preflight_numeric(store, offset, count, 8)?;
    let capacity =
        usize::try_from(count).map_err(|_| rpm_format("INT64 count is not representable"))?;
    let mut values = Vec::new();
    try_reserve(&mut values, capacity)?;
    for ordinal in 0..count {
        let position = offset
            .checked_add(
                ordinal
                    .checked_mul(8)
                    .ok_or_else(|| rpm_format("INT64 offset overflows"))?,
            )
            .ok_or_else(|| rpm_format("INT64 offset overflows"))?;
        values.push(be_u64(store, position, "INT64 value is truncated")?);
    }
    Ok(values.into_boxed_slice())
}

fn parse_string(
    store: &[u8],
    offset: u64,
    control: &mut ParseControl<'_>,
    model: &mut ModelAccount,
) -> Result<Box<[u8]>> {
    let start =
        usize::try_from(offset).map_err(|_| rpm_format("string offset is not representable"))?;
    let remaining = store
        .get(start..)
        .ok_or_else(|| rpm_format("string offset is outside the header store"))?;
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| rpm_format("header string is not NUL terminated"))?;
    let value = remaining
        .get(..length)
        .ok_or_else(|| rpm_format("header string range is invalid"))?;
    model.charge(usize_to_u64(
        value.len(),
        "RPM header string allocation is not representable",
    )?)?;
    copy_bytes(value, control)
}

fn parse_strings(
    store: &[u8],
    offset: u64,
    count: u64,
    control: &mut ParseControl<'_>,
    model: &mut ModelAccount,
) -> Result<Box<[Box<[u8]>]>> {
    let minimum_end = offset
        .checked_add(count)
        .ok_or_else(|| rpm_format("string-array minimum range overflows"))?;
    if minimum_end
        > usize_to_u64(
            store.len(),
            "RPM header store size is not representable as u64",
        )?
    {
        return Err(rpm_format("string-array count exceeds the header store"));
    }
    let capacity = usize::try_from(count)
        .map_err(|_| rpm_format("string-array count is not representable"))?;
    model.charge_elements::<Box<[u8]>>(count)?;
    let mut values = Vec::new();
    try_reserve(&mut values, capacity)?;
    let mut position = offset;
    for _ in 0..count {
        let value = parse_string(store, position, control, model)?;
        position = position
            .checked_add(
                usize_to_u64(value.len(), "header string length is not representable")?
                    .checked_add(1)
                    .ok_or_else(|| rpm_format("header string length overflows"))?,
            )
            .ok_or_else(|| rpm_format("header string-array offset overflows"))?;
        values.push(value);
    }
    Ok(values.into_boxed_slice())
}

fn preflight_numeric(store: &[u8], offset: u64, count: u64, width: u64) -> Result<()> {
    let length = count
        .checked_mul(width)
        .ok_or_else(|| rpm_format("numeric header value length overflows"))?;
    checked_range(
        store,
        offset,
        length,
        "numeric header value range overflows",
        "numeric header value is outside the store",
    )?;
    Ok(())
}

fn require_alignment(offset: u64, alignment: u64) -> Result<()> {
    if offset % alignment == 0 {
        Ok(())
    } else {
        Err(rpm_format("numeric header value is misaligned"))
    }
}

struct ModelAccount {
    retained: u64,
    maximum: u64,
}

impl ModelAccount {
    const fn new(maximum: u64) -> Self {
        Self {
            retained: 0,
            maximum,
        }
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        let requested = self
            .retained
            .checked_add(bytes)
            .ok_or(Error::LimitExceeded {
                limit: LimitKind::HeaderBytes,
                requested: u64::MAX,
                maximum: self.maximum,
            })?;
        check_limit(requested, self.maximum, LimitKind::HeaderBytes)?;
        self.retained = requested;
        Ok(())
    }

    fn charge_elements<T>(&mut self, count: u64) -> Result<()> {
        let width = usize_to_u64(
            size_of::<T>(),
            "RPM header model element size is not representable",
        )?;
        let bytes = count.checked_mul(width).ok_or(Error::LimitExceeded {
            limit: LimitKind::HeaderBytes,
            requested: u64::MAX,
            maximum: self.maximum,
        })?;
        self.charge(bytes)
    }
}

fn align_up(value: u64, alignment: u64, detail: &'static str) -> Result<u64> {
    let remainder = value % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment
            .checked_sub(remainder)
            .ok_or_else(|| rpm_format(detail))?
    };
    value.checked_add(padding).ok_or_else(|| rpm_format(detail))
}

fn be_u16(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u16> {
    let value = checked_range(bytes, offset, 2, detail, detail)?;
    let array = <[u8; 2]>::try_from(value).map_err(|_| rpm_format(detail))?;
    Ok(u16::from_be_bytes(array))
}

fn be_u32(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u32> {
    let value = checked_range(bytes, offset, 4, detail, detail)?;
    let array = <[u8; 4]>::try_from(value).map_err(|_| rpm_format(detail))?;
    Ok(u32::from_be_bytes(array))
}

fn be_u64(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u64> {
    let value = checked_range(bytes, offset, 8, detail, detail)?;
    let array = <[u8; 8]>::try_from(value).map_err(|_| rpm_format(detail))?;
    Ok(u64::from_be_bytes(array))
}

fn rpm_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("RPM: {detail}"),
    }
}
