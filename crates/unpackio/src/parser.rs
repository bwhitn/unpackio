//! Signature, fixed-header, and stored next-header envelope parsing.

use crate::{
    CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
    bounded::BoundedReader,
    checksum::Crc32,
    model::{ArchiveVersion, HeaderEnvelope, NextHeaderKind, ParsedArchive, ParsedNextHeader},
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, format_error, usize_to_u64,
    },
    raw::{ParseState, parse_next_header, parse_next_header_with_external_folders},
    validate::validate_next_header,
};

const SIGNATURE: &[u8; 6] = b"7z\xbc\xaf\x27\x1c";
const FIXED_HEADER_SIZE: u64 = 32;
const START_HEADER_OFFSET: u64 = 12;
const START_HEADER_SIZE: u64 = 20;
const ID_HEADER: u8 = 0x01;
const ID_ENCODED_HEADER: u8 = 0x17;

struct RawSignatureHeader {
    major: u8,
    minor: u8,
    start_crc: u32,
    next_offset: u64,
    next_size: u64,
    next_crc: u32,
}

fn parse_raw_signature_header(bytes: &[u8]) -> Result<RawSignatureHeader> {
    let mut archive = BoundedReader::new(bytes);
    archive.parse_exact(
        FIXED_HEADER_SIZE,
        "fixed 7z header was not consumed exactly",
        |fixed| {
            let signature = fixed.read_bytes(6)?;
            if signature != SIGNATURE {
                return Err(format_error("invalid 7z signature"));
            }

            Ok(RawSignatureHeader {
                major: fixed.read_u8()?,
                minor: fixed.read_u8()?,
                start_crc: fixed.read_u32_le()?,
                next_offset: fixed.read_u64_le()?,
                next_size: fixed.read_u64_le()?,
                next_crc: fixed.read_u32_le()?,
            })
        },
    )
}

fn crc32_with_control(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "CRC chunk length is not representable as u64",
        )?)?;
        checksum.update(chunk)?;
    }
    Ok(checksum.finalize())
}

fn parse_candidate(
    bytes: &[u8],
    signature_offset: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<HeaderEnvelope> {
    control.checkpoint(FIXED_HEADER_SIZE)?;
    let candidate_bytes = checked_range(
        bytes,
        signature_offset,
        FIXED_HEADER_SIZE,
        "fixed-header range overflows",
        "truncated fixed 7z header",
    )?;
    let raw = parse_raw_signature_header(candidate_bytes)?;

    let start_fields = checked_range(
        candidate_bytes,
        START_HEADER_OFFSET,
        START_HEADER_SIZE,
        "start-header range overflows",
        "truncated start-header fields",
    )?;
    if crc32_with_control(start_fields, control)? != raw.start_crc {
        return Err(Error::Checksum {
            scope: ChecksumScope::StartHeader,
            member_index: None,
        });
    }

    if raw.major != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("7z-major-version"),
        });
    }

    if raw.next_size > limits.max_header_bytes() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::HeaderBytes,
            requested: raw.next_size,
            maximum: limits.max_header_bytes(),
        });
    }

    let after_fixed = signature_offset
        .checked_add(FIXED_HEADER_SIZE)
        .ok_or_else(|| format_error("fixed-header end overflows"))?;
    let next_header_offset = after_fixed
        .checked_add(raw.next_offset)
        .ok_or_else(|| format_error("next-header offset overflows"))?;
    let next_header = checked_range(
        bytes,
        next_header_offset,
        raw.next_size,
        "next-header end overflows",
        "truncated next-header range",
    )?;

    if crc32_with_control(next_header, control)? != raw.next_crc {
        return Err(Error::Checksum {
            scope: ChecksumScope::NextHeader,
            member_index: None,
        });
    }

    let next_header_kind = match next_header.first().copied() {
        Some(ID_HEADER) => NextHeaderKind::Header,
        Some(ID_ENCODED_HEADER) => NextHeaderKind::EncodedHeader,
        Some(_) => return Err(format_error("unexpected next-header identifier")),
        None => return Err(format_error("next header is empty")),
    };

    Ok(HeaderEnvelope::new(
        signature_offset,
        ArchiveVersion::new(raw.major, raw.minor),
        next_header_offset,
        raw.next_size,
        raw.next_crc,
        next_header_kind,
    ))
}

fn candidate_error_is_fatal(error: &Error) -> bool {
    matches!(
        error,
        Error::Cancelled
            | Error::Io(_)
            | Error::LimitExceeded {
                limit: LimitKind::WorkUnits | LimitKind::TotalInputBytes,
                ..
            }
    )
}

fn candidate_declares_more_bytes(
    bytes: &[u8],
    signature_offset: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Option<bool>> {
    let input_length = usize_to_u64(
        bytes.len(),
        "archive input length is not representable as u64",
    )?;
    let fixed_end = signature_offset
        .checked_add(FIXED_HEADER_SIZE)
        .ok_or_else(|| format_error("fixed-header end overflows"))?;
    if fixed_end > input_length {
        return Ok(Some(true));
    }
    let candidate_bytes = checked_range(
        bytes,
        signature_offset,
        FIXED_HEADER_SIZE,
        "fixed-header range overflows",
        "truncated fixed 7z header",
    )?;
    let raw = parse_raw_signature_header(candidate_bytes)?;
    let start_fields = checked_range(
        candidate_bytes,
        START_HEADER_OFFSET,
        START_HEADER_SIZE,
        "start-header range overflows",
        "truncated start-header fields",
    )?;
    if crc32_with_control(start_fields, control)? != raw.start_crc {
        return Ok(None);
    }
    if raw.next_size > limits.max_header_bytes() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::HeaderBytes,
            requested: raw.next_size,
            maximum: limits.max_header_bytes(),
        });
    }
    let required = fixed_end
        .checked_add(raw.next_offset)
        .and_then(|offset| offset.checked_add(raw.next_size))
        .ok_or_else(|| format_error("declared archive end overflows"))?;
    Ok(Some(required > input_length))
}

pub(crate) fn archive_declares_more_bytes(
    bytes: &[u8],
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> Result<bool> {
    let input_length = usize_to_u64(
        bytes.len(),
        "archive input length is not representable as u64",
    )?;
    check_limit(
        input_length,
        limits.max_total_input_bytes(),
        LimitKind::TotalInputBytes,
    )?;
    let mut control = ParseControl::new(cancellation, budget);
    if bytes.starts_with(SIGNATURE) {
        return Ok(candidate_declares_more_bytes(bytes, 0, limits, &mut control)?.unwrap_or(false));
    }
    let Some(last_possible_offset) = input_length.checked_sub(usize_to_u64(
        SIGNATURE.len(),
        "7z signature length is not representable as u64",
    )?) else {
        return Ok(false);
    };
    let last_scanned_offset = last_possible_offset.min(limits.sfx_scan_limit());
    let scan_length = last_scanned_offset
        .checked_add(usize_to_u64(
            SIGNATURE.len(),
            "7z signature length is not representable as u64",
        )?)
        .ok_or_else(|| format_error("SFX scan range overflows"))?;
    let scan_bytes = checked_range(
        bytes,
        0,
        scan_length,
        "SFX scan range overflows",
        "truncated SFX scan range",
    )?;
    for (offset, window) in scan_bytes.windows(SIGNATURE.len()).enumerate() {
        control.checkpoint(1)?;
        if window != SIGNATURE {
            continue;
        }
        let offset = usize_to_u64(offset, "SFX signature offset is not representable as u64")?;
        if let Some(requires_more) =
            candidate_declares_more_bytes(bytes, offset, limits, &mut control)?
        {
            return Ok(requires_more);
        }
    }
    Ok(false)
}

/// Parses and verifies the signature/start-header envelope from archive bytes.
///
/// The supplied slice is borrowed only for this call. The function allocates
/// no archive-derived buffers, validates the total-input and header limits,
/// bounds SFX scanning, uses checked offset arithmetic, and verifies both the
/// start-header and stored next-header CRCs. It intentionally does not parse
/// the next-header body into files, streams, folders, or coders yet.
#[cfg(any(test, feature = "unstable-internals"))]
pub fn parse_archive_header(
    bytes: &[u8],
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> Result<HeaderEnvelope> {
    let input_length = usize_to_u64(
        bytes.len(),
        "archive input length is not representable as u64",
    )?;
    if input_length > limits.max_total_input_bytes() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::TotalInputBytes,
            requested: input_length,
            maximum: limits.max_total_input_bytes(),
        });
    }

    let mut control = ParseControl::new(cancellation, budget);

    if bytes.starts_with(SIGNATURE) {
        return parse_candidate(bytes, 0, limits, &mut control);
    }

    let Some(last_possible_offset) = input_length.checked_sub(usize_to_u64(
        SIGNATURE.len(),
        "7z signature length is not representable as u64",
    )?) else {
        return Err(format_error("7z signature was not found"));
    };
    let last_scanned_offset = last_possible_offset.min(limits.sfx_scan_limit());
    let scan_length = last_scanned_offset
        .checked_add(usize_to_u64(
            SIGNATURE.len(),
            "7z signature length is not representable as u64",
        )?)
        .ok_or_else(|| format_error("SFX scan range overflows"))?;
    let scan_bytes = checked_range(
        bytes,
        0,
        scan_length,
        "SFX scan range overflows",
        "truncated SFX scan range",
    )?;

    let mut first_candidate_error = None;
    for (offset, window) in scan_bytes.windows(SIGNATURE.len()).enumerate() {
        control.checkpoint(1)?;
        if window != SIGNATURE {
            continue;
        }

        let offset = usize_to_u64(offset, "SFX signature offset is not representable as u64")?;
        match parse_candidate(bytes, offset, limits, &mut control) {
            Ok(header) => return Ok(header),
            Err(error) if candidate_error_is_fatal(&error) => return Err(error),
            Err(error) => {
                if first_candidate_error.is_none() {
                    first_candidate_error = Some(error);
                }
            }
        }
    }

    match first_candidate_error {
        Some(error) => Err(error),
        None => Err(format_error("7z signature was not found")),
    }
}

/// Parses a complete stored next header into a validated owned archive model.
///
/// This verifies the signature, start-header, and stored next-header CRCs;
/// parses every bounded syntax record; and validates stream graphs, ranges,
/// counts, file mappings, metadata vectors, known decoder memory declarations,
/// and external-property references. An encoded header is returned as a
/// validated stream descriptor because decoding begins in a later phase.
pub fn parse_archive(
    bytes: &[u8],
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> Result<ParsedArchive> {
    fn validated_candidate(
        bytes: &[u8],
        signature_offset: u64,
        limits: Limits,
        control: &mut ParseControl<'_>,
    ) -> Result<ParsedArchive> {
        let envelope = parse_candidate(bytes, signature_offset, limits, control)?;
        let next_header = checked_range(
            bytes,
            envelope.next_header_offset(),
            envelope.next_header_size(),
            "next-header end overflows during body parsing",
            "next-header range was truncated during body parsing",
        )?;
        let mut state = ParseState::default();
        let raw = parse_next_header(next_header, &mut state, limits, control)?;
        let validated = validate_next_header(raw, envelope, bytes, limits, control)?;
        Ok(ParsedArchive::new(envelope, validated))
    }

    let input_length = usize_to_u64(
        bytes.len(),
        "archive input length is not representable as u64",
    )?;
    if input_length > limits.max_total_input_bytes() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::TotalInputBytes,
            requested: input_length,
            maximum: limits.max_total_input_bytes(),
        });
    }
    let mut control = ParseControl::new(cancellation, budget);
    if bytes.starts_with(SIGNATURE) {
        return validated_candidate(bytes, 0, limits, &mut control);
    }

    let Some(last_possible_offset) = input_length.checked_sub(usize_to_u64(
        SIGNATURE.len(),
        "7z signature length is not representable as u64",
    )?) else {
        return Err(format_error("7z signature was not found"));
    };
    let last_scanned_offset = last_possible_offset.min(limits.sfx_scan_limit());
    let scan_length = last_scanned_offset
        .checked_add(usize_to_u64(
            SIGNATURE.len(),
            "7z signature length is not representable as u64",
        )?)
        .ok_or_else(|| format_error("SFX scan range overflows"))?;
    let scan_bytes = checked_range(
        bytes,
        0,
        scan_length,
        "SFX scan range overflows",
        "truncated SFX scan range",
    )?;
    let mut first_candidate_error = None;
    for (offset, window) in scan_bytes.windows(SIGNATURE.len()).enumerate() {
        control.checkpoint(1)?;
        if window != SIGNATURE {
            continue;
        }
        let offset = usize_to_u64(offset, "SFX signature offset is not representable as u64")?;
        match validated_candidate(bytes, offset, limits, &mut control) {
            Ok(archive) => return Ok(archive),
            Err(error) if candidate_error_is_fatal(&error) => return Err(error),
            Err(error) => {
                if first_candidate_error.is_none() {
                    first_candidate_error = Some(error);
                }
            }
        }
    }
    match first_candidate_error {
        Some(error) => Err(error),
        None => Err(format_error("7z signature was not found")),
    }
}

pub(crate) fn parse_decoded_next_header(
    decoded: &[u8],
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ParsedNextHeader> {
    let decoded_size = usize_to_u64(
        decoded.len(),
        "decoded header size is not representable as u64",
    )?;
    if decoded_size > limits.max_header_bytes() {
        return Err(Error::LimitExceeded {
            limit: LimitKind::HeaderBytes,
            requested: decoded_size,
            maximum: limits.max_header_bytes(),
        });
    }
    let mut state = ParseState::default();
    let raw = parse_next_header(decoded, &mut state, limits, control)?;
    validate_next_header(raw, envelope, archive_bytes, limits, control)
}

pub(crate) fn parse_next_header_from_external_folders(
    header_bytes: &[u8],
    data_index: u64,
    folder_bytes: &[u8],
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ParsedNextHeader> {
    let header_size = usize_to_u64(
        header_bytes.len(),
        "external-folder header size is not representable as u64",
    )?;
    check_limit(
        header_size,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )?;
    let mut state = ParseState::default();
    let raw = parse_next_header_with_external_folders(
        header_bytes,
        data_index,
        folder_bytes,
        &mut state,
        limits,
        control,
    )?;
    validate_next_header(raw, envelope, archive_bytes, limits, control)
}

#[cfg(test)]
mod tests {
    use super::{FIXED_HEADER_SIZE, SIGNATURE, parse_archive_header};
    use crate::{
        CancellationToken, ChecksumScope, Error, ErrorKind, LimitKind, Limits, WorkBudget,
        checksum::Crc32,
        model::{HeaderEnvelope, NextHeaderKind},
    };

    fn make_archive(
        prefix: &[u8],
        major: u8,
        minor: u8,
        next_offset: u64,
        next_size: u64,
        next_crc: u32,
        trailing_bytes: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let mut start_fields = Vec::new();
        start_fields.extend_from_slice(&next_offset.to_le_bytes());
        start_fields.extend_from_slice(&next_size.to_le_bytes());
        start_fields.extend_from_slice(&next_crc.to_le_bytes());
        let start_crc = Crc32::checksum(&start_fields)?;

        let mut archive = Vec::new();
        archive.extend_from_slice(prefix);
        archive.extend_from_slice(SIGNATURE);
        archive.push(major);
        archive.push(minor);
        archive.extend_from_slice(&start_crc.to_le_bytes());
        archive.extend_from_slice(&start_fields);
        archive.extend_from_slice(trailing_bytes);
        Ok(archive)
    }

    fn make_plain_archive(prefix: &[u8], header: &[u8]) -> crate::Result<Vec<u8>> {
        let size = u64::try_from(header.len()).map_err(|_| Error::Format {
            detail: String::from("test header is too large"),
        })?;
        make_archive(prefix, 0, 4, 0, size, Crc32::checksum(header)?, header)
    }

    fn parse(bytes: &[u8], limits: Limits) -> crate::Result<HeaderEnvelope> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        parse_archive_header(bytes, limits, &cancellation, &mut budget)
    }

    #[test]
    fn validates_plain_and_encoded_header_envelopes() -> crate::Result<()> {
        let plain = make_plain_archive(&[], &[0x01, 0x00])?;
        let parsed = parse(&plain, Limits::default())?;
        assert_eq!(parsed.signature_offset(), 0);
        assert_eq!(parsed.version().major(), 0);
        assert_eq!(parsed.version().minor(), 4);
        assert_eq!(parsed.next_header_offset(), FIXED_HEADER_SIZE);
        assert_eq!(parsed.next_header_size(), 2);
        assert_eq!(parsed.next_header_kind(), NextHeaderKind::Header);

        let encoded = make_plain_archive(&[], &[0x17, 0x00])?;
        assert_eq!(
            parse(&encoded, Limits::default())?.next_header_kind(),
            NextHeaderKind::EncodedHeader
        );
        Ok(())
    }

    #[test]
    fn finds_sfx_after_a_false_signature_candidate() -> crate::Result<()> {
        let mut prefix = Vec::from([0x90_u8]);
        prefix.extend_from_slice(SIGNATURE);
        prefix.extend_from_slice(&[0_u8; 40]);
        let archive = make_plain_archive(&prefix, &[0x01, 0x00])?;
        let parsed = parse(&archive, Limits::default())?;
        assert_eq!(
            parsed.signature_offset(),
            u64::try_from(prefix.len()).map_err(|_| {
                Error::Format {
                    detail: String::from("test prefix is too large"),
                }
            })?
        );
        Ok(())
    }

    #[test]
    fn candidate_local_limit_error_does_not_hide_later_sfx() -> crate::Result<()> {
        let false_candidate = make_archive(&[0x90], 0, 4, 0, 3, 0, &[])?;
        let archive = make_plain_archive(&false_candidate, &[0x01, 0x00])?;
        let limits = Limits::builder().max_header_bytes(2).build();
        assert_eq!(
            parse(&archive, limits)?.signature_offset(),
            u64::try_from(false_candidate.len()).map_err(|_| Error::Format {
                detail: String::from("test prefix is too large"),
            })?
        );
        Ok(())
    }

    #[test]
    fn regular_archive_is_allowed_when_sfx_scan_is_disabled() -> crate::Result<()> {
        let archive = make_plain_archive(&[], &[0x01, 0x00])?;
        let limits = Limits::builder().sfx_scan_limit(0).build();
        assert_eq!(parse(&archive, limits)?.signature_offset(), 0);
        Ok(())
    }

    #[test]
    fn enforces_sfx_scan_limit() -> crate::Result<()> {
        let archive = make_plain_archive(&[0_u8; 4], &[0x01, 0x00])?;
        let exact_limits = Limits::builder().sfx_scan_limit(4).build();
        assert_eq!(parse(&archive, exact_limits)?.signature_offset(), 4);

        let limits = Limits::builder().sfx_scan_limit(3).build();
        assert_eq!(
            parse(&archive, limits).err().map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
        Ok(())
    }

    #[test]
    fn rejects_start_and_next_header_crc_corruption() -> crate::Result<()> {
        let valid_header = [0x01, 0x00];
        let valid_crc = Crc32::checksum(&valid_header)?;
        let mut bad_start = make_archive(&[], 0, 4, 0, 2, valid_crc, &valid_header)?;
        let Some(start_crc_byte) = bad_start.get_mut(8) else {
            return Err(Error::Format {
                detail: String::from("test archive lacks a start CRC byte"),
            });
        };
        *start_crc_byte ^= 1;
        let start_error = parse(&bad_start, Limits::default());
        assert!(matches!(
            start_error,
            Err(Error::Checksum {
                scope: ChecksumScope::StartHeader,
                member_index: None
            })
        ));

        let bad_next = make_archive(&[], 0, 4, 0, 2, valid_crc ^ 1, &valid_header)?;
        let next_error = parse(&bad_next, Limits::default());
        assert!(matches!(
            next_error,
            Err(Error::Checksum {
                scope: ChecksumScope::NextHeader,
                member_index: None
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_all_truncations_without_panicking() -> crate::Result<()> {
        let archive = make_plain_archive(&[], &[0x01, 0x00])?;
        for length in 0..archive.len() {
            let Some(truncated) = archive.get(..length) else {
                continue;
            };
            assert!(
                parse(truncated, Limits::default()).is_err(),
                "length {length}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_overflowed_next_header_offset() -> crate::Result<()> {
        let archive = make_archive(&[], 0, 4, u64::MAX, 1, 0, &[])?;
        assert_eq!(
            parse(&archive, Limits::default())
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
        Ok(())
    }

    #[test]
    fn checks_header_and_total_input_limits_before_ranges() -> crate::Result<()> {
        let archive = make_archive(&[], 0, 4, u64::MAX, 2, 0, &[])?;
        let header_limits = Limits::builder().max_header_bytes(1).build();
        assert!(matches!(
            parse(&archive, header_limits),
            Err(Error::LimitExceeded {
                limit: LimitKind::HeaderBytes,
                requested: 2,
                maximum: 1
            })
        ));

        let input_length = u64::try_from(archive.len()).map_err(|_| Error::Format {
            detail: String::from("test archive length is too large"),
        })?;
        let input_limits = Limits::builder()
            .max_total_input_bytes(input_length.saturating_sub(1))
            .build();
        assert!(matches!(
            parse(&archive, input_limits),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalInputBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn cancellation_and_work_budget_stop_parsing() -> crate::Result<()> {
        let archive = make_plain_archive(&[], &[0x01, 0x00])?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut unlimited = WorkBudget::unlimited();
        assert_eq!(
            parse_archive_header(&archive, Limits::default(), &cancellation, &mut unlimited)
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Cancelled)
        );

        let running = CancellationToken::new();
        let mut insufficient = WorkBudget::bounded(31);
        assert!(matches!(
            parse_archive_header(&archive, Limits::default(), &running, &mut insufficient),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn distinguishes_unsupported_version_from_malformed_header() -> crate::Result<()> {
        let header = [0x01, 0x00];
        let unsupported = make_archive(&[], 1, 0, 0, 2, Crc32::checksum(&header)?, &header)?;
        assert_eq!(
            parse(&unsupported, Limits::default())
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::UnsupportedFeature)
        );

        let unexpected = make_plain_archive(&[], &[0x99])?;
        assert_eq!(
            parse(&unexpected, Limits::default())
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
        Ok(())
    }
}
