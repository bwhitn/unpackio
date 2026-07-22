#![forbid(unsafe_code)]
//! Generated canonical and py7zr-compatible PPMd property regressions.

use unpackio::{Archive, CancellationToken, Error, LimitKind, Limits, Result, WorkBudget};

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const CANONICAL_PROPERTIES: &[u8] = &[0x06, 0x00, 0x00, 0x01, 0x00];
const PY7ZR_PROPERTIES: &[u8] = &[0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
const PPMD_PACKED: &[u8] = &[
    0x00, 0x50, 0x01, 0xe2, 0xfb, 0xf5, 0x0f, 0xe5, 0x00, 0x93, 0xf9, 0x01, 0xda, 0xf2, 0xa8, 0x02,
    0x8b, 0x72, 0x66, 0x5b, 0x34, 0xaa, 0x5a, 0xfc, 0xd6, 0xbb, 0xf6, 0x4e, 0x79, 0xab, 0x83, 0xe5,
    0xa9, 0x16, 0x93, 0x8d, 0x10, 0x93, 0x1a, 0xdf, 0x38, 0xab, 0xa2, 0x72, 0xf6, 0x12, 0x2d, 0x98,
    0x00,
];
const PPMD_OUTPUT: &[u8] = b"PPMd fuzz seed: alpha beta gamma delta 0123456789\n";

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}

fn push_uint(bytes: &mut Vec<u8>, value: u64) -> Result<()> {
    const PREFIXES: &[u8] = &[0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe];
    let little_endian = value.to_le_bytes();
    for extra_bytes in 0..8_usize {
        let bit_count = extra_bytes
            .checked_add(1)
            .and_then(|count| count.checked_mul(7))
            .ok_or_else(|| std::io::Error::other("test integer bit count overflows"))?;
        let limit = 1_u64
            .checked_shl(
                u32::try_from(bit_count)
                    .map_err(|_| std::io::Error::other("test bit count is out of range"))?,
            )
            .ok_or_else(|| std::io::Error::other("test integer limit shift overflows"))?;
        if value >= limit {
            continue;
        }
        let shift = extra_bytes
            .checked_mul(8)
            .ok_or_else(|| std::io::Error::other("test integer shift overflows"))?;
        let shift = u32::try_from(shift)
            .map_err(|_| std::io::Error::other("test integer shift is out of range"))?;
        let high = u8::try_from(value >> shift)
            .map_err(|_| std::io::Error::other("test integer high byte is out of range"))?;
        let prefix = PREFIXES
            .get(extra_bytes)
            .copied()
            .ok_or_else(|| std::io::Error::other("test integer prefix is missing"))?;
        bytes.push(prefix | high);
        bytes.extend_from_slice(
            little_endian
                .get(..extra_bytes)
                .ok_or_else(|| std::io::Error::other("test integer suffix is missing"))?,
        );
        return Ok(());
    }
    bytes.push(u8::MAX);
    bytes.extend_from_slice(&little_endian);
    Ok(())
}

fn finish_archive(next_header: &[u8]) -> Result<Vec<u8>> {
    let packed_size = u64::try_from(PPMD_PACKED.len())
        .map_err(|_| std::io::Error::other("test packed size is out of range"))?;
    let mut start_fields = Vec::new();
    start_fields.extend_from_slice(&packed_size.to_le_bytes());
    start_fields.extend_from_slice(
        &u64::try_from(next_header.len())
            .map_err(|_| std::io::Error::other("test header size is out of range"))?
            .to_le_bytes(),
    );
    start_fields.extend_from_slice(&crc32(next_header).to_le_bytes());
    let mut archive = Vec::new();
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(PPMD_PACKED);
    archive.extend_from_slice(next_header);
    Ok(archive)
}

fn ppmd_archive(properties: &[u8]) -> Result<Vec<u8>> {
    let packed_size = u64::try_from(PPMD_PACKED.len())
        .map_err(|_| std::io::Error::other("test packed size is out of range"))?;
    let unpacked_size = u64::try_from(PPMD_OUTPUT.len())
        .map_err(|_| std::io::Error::other("test output size is out of range"))?;
    let mut streams = Vec::new();
    streams.push(0x06);
    push_uint(&mut streams, 0)?;
    push_uint(&mut streams, 1)?;
    streams.push(0x09);
    push_uint(&mut streams, packed_size)?;
    streams.extend_from_slice(&[0x0a, 1]);
    streams.extend_from_slice(&crc32(PPMD_PACKED).to_le_bytes());
    streams.extend_from_slice(&[0x00, 0x07, 0x0b]);
    push_uint(&mut streams, 1)?;
    streams.push(0);
    push_uint(&mut streams, 1)?;
    streams.push(0x23);
    streams.extend_from_slice(METHOD_PPMD);
    push_uint(
        &mut streams,
        u64::try_from(properties.len())
            .map_err(|_| std::io::Error::other("test property size is out of range"))?,
    )?;
    streams.extend_from_slice(properties);
    streams.push(0x0c);
    push_uint(&mut streams, unpacked_size)?;
    streams.extend_from_slice(&[0x0a, 1]);
    streams.extend_from_slice(&crc32(PPMD_OUTPUT).to_le_bytes());
    streams.extend_from_slice(&[0x00, 0x00]);

    let mut next_header = Vec::new();
    next_header.extend_from_slice(&[0x01, 0x04]);
    next_header.extend_from_slice(&streams);
    next_header.extend_from_slice(&[0x05, 0x01, 0x00, 0x00]);
    finish_archive(&next_header)
}

fn truncated_ppmd_property_archive() -> Result<Vec<u8>> {
    let packed_size = u64::try_from(PPMD_PACKED.len())
        .map_err(|_| std::io::Error::other("test packed size is out of range"))?;
    let mut next_header = Vec::new();
    next_header.extend_from_slice(&[0x01, 0x04, 0x06]);
    push_uint(&mut next_header, 0)?;
    push_uint(&mut next_header, 1)?;
    next_header.push(0x09);
    push_uint(&mut next_header, packed_size)?;
    next_header.extend_from_slice(&[0x0a, 1]);
    next_header.extend_from_slice(&crc32(PPMD_PACKED).to_le_bytes());
    next_header.extend_from_slice(&[0x00, 0x07, 0x0b]);
    push_uint(&mut next_header, 1)?;
    next_header.push(0);
    push_uint(&mut next_header, 1)?;
    next_header.push(0x23);
    next_header.extend_from_slice(METHOD_PPMD);
    push_uint(&mut next_header, 7)?;
    next_header.extend_from_slice(
        PY7ZR_PROPERTIES
            .get(..6)
            .ok_or_else(|| std::io::Error::other("test PPMd properties are truncated"))?,
    );
    finish_archive(&next_header)
}

fn open(properties: &[u8], limits: Limits) -> Result<Archive> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    Archive::open_bytes(
        ppmd_archive(properties)?,
        limits,
        &cancellation,
        &mut budget,
    )
}

#[test]
fn canonical_and_py7zr_properties_extract_exact_bytes() -> Result<()> {
    for properties in [CANONICAL_PROPERTIES, PY7ZR_PROPERTIES] {
        let archive = open(properties, Limits::default())?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            PPMD_OUTPUT
        );
    }
    Ok(())
}

#[test]
fn nonzero_reserved_bytes_and_other_property_lengths_are_rejected() -> Result<()> {
    for properties in [[6, 0, 0, 1, 0, 1, 0], [6, 0, 0, 1, 0, 0, 1]] {
        assert!(matches!(
            open(&properties, Limits::default()),
            Err(Error::Format { .. })
        ));
    }
    for length in 0..=9 {
        if matches!(length, 5 | 7) {
            continue;
        }
        let mut properties = CANONICAL_PROPERTIES.to_vec();
        properties.resize(length, 0);
        assert!(matches!(
            open(&properties, Limits::default()),
            Err(Error::Format { .. })
        ));
    }
    Ok(())
}

#[test]
fn declared_seven_byte_properties_reject_truncated_input() -> Result<()> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        Archive::open_bytes(
            truncated_ppmd_property_archive()?,
            Limits::default(),
            &cancellation,
            &mut budget,
        ),
        Err(Error::Format { .. })
    ));
    Ok(())
}

#[test]
fn py7zr_properties_keep_dictionary_output_work_and_cancellation_bounds() -> Result<()> {
    assert!(matches!(
        open(
            PY7ZR_PROPERTIES,
            Limits::builder()
                .max_dictionary_bytes((64 * 1024) - 1)
                .build(),
        ),
        Err(Error::LimitExceeded {
            limit: LimitKind::DictionaryBytes,
            requested: 65_536,
            maximum: 65_535,
        })
    ));

    let archive = open(PY7ZR_PROPERTIES, Limits::default())?;
    let cancellation = CancellationToken::new();
    let mut output_budget = WorkBudget::bounded(0);
    assert!(matches!(
        archive.extract_entry_to(0, &mut Vec::new(), &cancellation, &mut output_budget),
        Err(Error::LimitExceeded {
            limit: LimitKind::WorkUnits,
            ..
        })
    ));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        archive.extract_entry_to(0, &mut Vec::new(), &cancelled, &mut budget),
        Err(Error::Cancelled)
    ));

    let limited = open(
        PY7ZR_PROPERTIES,
        Limits::builder().max_total_output_bytes(49).build(),
    )?;
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        limited.extract_entry_to(0, &mut Vec::new(), &cancellation, &mut budget),
        Err(Error::LimitExceeded {
            limit: LimitKind::TotalOutputBytes,
            requested: 50,
            maximum: 49,
        })
    ));
    Ok(())
}
