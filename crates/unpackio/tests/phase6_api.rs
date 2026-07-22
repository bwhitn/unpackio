#![forbid(unsafe_code)]
//! Stable public-API contract tests with an independently generated Copy archive.

use std::{
    error::Error as StdError,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use unpackio::{
    Archive, CancellationToken, ChecksumScope, EntryKind, Error, Limits, MemoryVolumeProvider,
    WorkBudget, validate_safe_utf16_path,
};

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";

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

fn push_small_uint(bytes: &mut Vec<u8>, value: u64) -> Result<(), Box<dyn StdError>> {
    let value = u8::try_from(value)?;
    if value >= 0x80 {
        return Err(String::from("test fixture integer exceeds one-byte 7z encoding").into());
    }
    bytes.push(value);
    Ok(())
}

fn copy_archive(payload: &[u8], name: &[u16]) -> Result<Vec<u8>, Box<dyn StdError>> {
    let size = u64::try_from(payload.len())?;
    let payload_crc = crc32(payload);

    let mut streams = Vec::from([0x06]);
    push_small_uint(&mut streams, 0)?;
    push_small_uint(&mut streams, 1)?;
    streams.push(0x09);
    push_small_uint(&mut streams, size)?;
    streams.push(0x00);
    streams.extend_from_slice(&[0x07, 0x0b]);
    push_small_uint(&mut streams, 1)?;
    streams.push(0);
    push_small_uint(&mut streams, 1)?;
    streams.extend_from_slice(&[1, 0]);
    streams.push(0x0c);
    push_small_uint(&mut streams, size)?;
    streams.extend_from_slice(&[0x0a, 1]);
    streams.extend_from_slice(&payload_crc.to_le_bytes());
    streams.extend_from_slice(&[0x00, 0x00]);

    let mut name_property = Vec::from([0]);
    for unit in name {
        name_property.extend_from_slice(&unit.to_le_bytes());
    }
    name_property.extend_from_slice(&0_u16.to_le_bytes());
    let mut files = Vec::new();
    push_small_uint(&mut files, 1)?;
    files.push(0x11);
    push_small_uint(&mut files, u64::try_from(name_property.len())?)?;
    files.extend_from_slice(&name_property);
    files.push(0x00);

    let mut next_header = Vec::from([0x01, 0x04]);
    next_header.extend_from_slice(&streams);
    next_header.push(0x05);
    next_header.extend_from_slice(&files);
    next_header.push(0x00);

    let mut start_fields = Vec::new();
    start_fields.extend_from_slice(&size.to_le_bytes());
    start_fields.extend_from_slice(&u64::try_from(next_header.len())?.to_le_bytes());
    start_fields.extend_from_slice(&crc32(&next_header).to_le_bytes());
    let mut archive = Vec::new();
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&next_header);
    Ok(archive)
}

fn temporary_path() -> Result<PathBuf, Box<dyn StdError>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "unpackio-phase6-api-{}-{nonce}.7z",
        std::process::id()
    )))
}

#[test]
fn stable_open_list_stream_and_sink_contract() -> Result<(), Box<dyn StdError>> {
    let payload = b"phase-six-public-api";
    let name: Vec<u16> = "directory/member.bin".encode_utf16().collect();
    let bytes = copy_archive(payload, &name)?;
    let archive_len = u64::try_from(bytes.len())?;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut open_budget)?;

    assert!(!archive.is_empty());
    assert_eq!(archive.entries().len(), 1);
    let entry = archive.entry(0).ok_or("member zero is missing")?;
    assert_eq!(entry.kind(), EntryKind::File);
    assert_eq!(entry.raw_name(), Some(name.as_slice()));
    assert_eq!(entry.name_lossy().as_deref(), Some("directory/member.bin"));
    assert_eq!(entry.size(), Some(u64::try_from(payload.len())?));
    assert_eq!(entry.crc32(), Some(crc32(payload)));
    assert!(validate_safe_utf16_path(&name).is_ok());
    assert!(archive.entry(1).is_none());
    assert_eq!(archive.limits(), Limits::default());

    let resources = archive.resources();
    assert_eq!(resources.input_bytes(), archive_len);
    assert!(resources.metadata_bytes() > 0);
    assert_eq!(resources.password_bytes(), 0);
    assert_eq!(
        resources.retained_bytes(),
        resources
            .input_bytes()
            .checked_add(resources.metadata_bytes())
            .ok_or("test resource total overflows")?
    );

    let mut stream_budget = WorkBudget::unlimited();
    let mut reader = archive.open_member(0, &cancellation, &mut stream_budget)?;
    assert_eq!(reader.member_index(), 0);
    assert_eq!(reader.size()?, u64::try_from(payload.len())?);
    assert_eq!(reader.remaining()?, u64::try_from(payload.len())?);
    assert_eq!(reader.retained_bytes()?, u64::try_from(payload.len())?);
    let mut prefix = [0_u8; 5];
    let read = reader.read_chunk(&mut prefix)?;
    assert_eq!(read, prefix.len());
    assert_eq!(&prefix, b"phase");
    assert_eq!(
        reader.remaining()?,
        u64::try_from(
            payload
                .len()
                .checked_sub(prefix.len())
                .ok_or("test underflow")?
        )?
    );
    reader.finish()?;

    let mut extracted = Vec::new();
    let mut extract_budget = WorkBudget::unlimited();
    let written =
        archive.extract_entry_to(0, &mut extracted, &cancellation, &mut extract_budget)?;
    assert_eq!(written, u64::try_from(payload.len())?);
    assert_eq!(extracted, payload);

    let password_bytes = copy_archive(payload, &name)?;
    let mut password_budget = WorkBudget::unlimited();
    let password_archive = Archive::open_bytes_with_password(
        password_bytes,
        Limits::default(),
        "phase6",
        &cancellation,
        &mut password_budget,
    )?;
    assert!(password_archive.resources().password_bytes() > 0);
    Ok(())
}

#[test]
fn stable_path_and_volume_opening_contract() -> Result<(), Box<dyn StdError>> {
    let bytes = copy_archive(b"volumes", &"v.bin".encode_utf16().collect::<Vec<_>>())?;
    let split = bytes.len().checked_div(2).ok_or("test split overflows")?;
    let first = bytes
        .get(..split)
        .ok_or("first test part is missing")?
        .to_vec();
    let second = bytes
        .get(split..)
        .ok_or("second test part is missing")?
        .to_vec();
    let mut provider = MemoryVolumeProvider::new(vec![first, second]);
    let cancellation = CancellationToken::new();
    let mut volume_budget = WorkBudget::unlimited();
    let archive = Archive::open_volumes(
        &mut provider,
        "memory.001",
        Limits::default(),
        &cancellation,
        &mut volume_budget,
    )?;
    assert_eq!(archive.entries().len(), 1);

    let path = temporary_path()?;
    fs::write(&path, &bytes)?;
    let mut path_budget = WorkBudget::unlimited();
    let result = Archive::open_path(&path, Limits::default(), &cancellation, &mut path_budget);
    let remove_result = fs::remove_file(&path);
    let path_archive = result?;
    remove_result?;
    assert_eq!(path_archive.entries().len(), 1);
    Ok(())
}

#[test]
fn stable_helpers_withhold_success_on_crc_failure() -> Result<(), Box<dyn StdError>> {
    let payload = b"checksum";
    let mut bytes = copy_archive(payload, &"bad.bin".encode_utf16().collect::<Vec<_>>())?;
    let payload_offset = 32_usize;
    let byte = bytes
        .get_mut(payload_offset)
        .ok_or("test payload byte is missing")?;
    *byte ^= 1;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut open_budget)?;
    let mut output = Vec::new();
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        archive.extract_entry_to(0, &mut output, &cancellation, &mut budget),
        Err(Error::Checksum {
            scope: ChecksumScope::Folder | ChecksumScope::Member,
            ..
        })
    ));
    Ok(())
}
