#![no_main]
#![forbid(unsafe_code)]

#[path = "support.rs"]
mod support;

use libfuzzer_sys::fuzz_target;
use unpackio::{
    ArjArchive, CancellationToken, CpioArchive, DebArchive, Limits, RpmArchive, WorkBudget,
    ZipArchive,
};

const MAXIMUM_FUZZ_INPUT: usize = 256 * 1024;
const MAXIMUM_GENERATED_PAYLOAD: usize = 255;
const MEMBER_NAME: &[u8] = b"fuzz.bin";

fn limits() -> Limits {
    Limits::builder()
        .max_header_bytes(64 * 1024)
        .max_files(64)
        .max_stream_frames(64)
        .max_header_properties(128)
        .max_name_bytes_per_entry(4096)
        .max_total_name_bytes(16 * 1024)
        .max_dictionary_bytes(32 * 1024 * 1024)
        .max_entry_output_bytes(512 * 1024)
        .max_total_output_bytes(1024 * 1024)
        .max_total_input_bytes(512 * 1024)
        .sfx_scan_limit(64 * 1024)
        .build()
}

fn exercise_zip(bytes: Vec<u8>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = ZipArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_rpm(bytes: Vec<u8>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = RpmArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_cpio(bytes: Vec<u8>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = CpioArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_deb(bytes: Vec<u8>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = DebArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_arj(bytes: Vec<u8>) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = ArjArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn append_le_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_le_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn stored_zip(payload: &[u8]) -> Option<Vec<u8>> {
    let payload_size = u32::try_from(payload.len()).ok()?;
    let name_size = u16::try_from(MEMBER_NAME.len()).ok()?;
    let checksum = support::crc32(payload);
    let mut output = Vec::new();

    append_le_u32(&mut output, 0x0403_4b50);
    append_le_u16(&mut output, 20);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u32(&mut output, checksum);
    append_le_u32(&mut output, payload_size);
    append_le_u32(&mut output, payload_size);
    append_le_u16(&mut output, name_size);
    append_le_u16(&mut output, 0);
    output.extend_from_slice(MEMBER_NAME);
    output.extend_from_slice(payload);

    let directory_offset = u32::try_from(output.len()).ok()?;
    append_le_u32(&mut output, 0x0201_4b50);
    append_le_u16(&mut output, 0x031e);
    append_le_u16(&mut output, 20);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u32(&mut output, checksum);
    append_le_u32(&mut output, payload_size);
    append_le_u32(&mut output, payload_size);
    append_le_u16(&mut output, name_size);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u32(&mut output, 0o100_644_u32.checked_shl(16)?);
    append_le_u32(&mut output, 0);
    output.extend_from_slice(MEMBER_NAME);

    let directory_end = u32::try_from(output.len()).ok()?;
    let directory_size = directory_end.checked_sub(directory_offset)?;
    append_le_u32(&mut output, 0x0605_4b50);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 1);
    append_le_u16(&mut output, 1);
    append_le_u32(&mut output, directory_size);
    append_le_u32(&mut output, directory_offset);
    append_le_u16(&mut output, 0);
    Some(output)
}

fn append_be_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_hex_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn append_cpio_record(
    output: &mut Vec<u8>,
    magic: &[u8; 6],
    name: &[u8],
    payload: &[u8],
    checksum: u32,
) -> Option<()> {
    let payload_size = u32::try_from(payload.len()).ok()?;
    let name_size = u32::try_from(name.len().checked_add(1)?).ok()?;
    output.extend_from_slice(magic);
    for value in [
        1,
        0o100_644,
        1000,
        1000,
        1,
        1_700_000_000,
        payload_size,
        0,
        0,
        0,
        0,
        name_size,
        checksum,
    ] {
        append_hex_u32(output, value);
    }
    output.extend_from_slice(name);
    output.push(0);
    while output.len() % 4 != 0 {
        output.push(0);
    }
    output.extend_from_slice(payload);
    while output.len() % 4 != 0 {
        output.push(0);
    }
    Some(())
}

fn rpm_header(values: &[(u32, &[u8])]) -> Option<Vec<u8>> {
    let mut indices = Vec::new();
    let mut store = Vec::new();
    for (tag, value) in values {
        append_be_u32(&mut indices, *tag);
        append_be_u32(&mut indices, 6);
        append_be_u32(&mut indices, u32::try_from(store.len()).ok()?);
        append_be_u32(&mut indices, 1);
        store.extend_from_slice(value);
        store.push(0);
    }
    let mut output = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
    append_be_u32(&mut output, u32::try_from(values.len()).ok()?);
    append_be_u32(&mut output, u32::try_from(store.len()).ok()?);
    output.extend_from_slice(&indices);
    output.extend_from_slice(&store);
    Some(output)
}

fn uncompressed_rpm(payload: &[u8]) -> Option<Vec<u8>> {
    let cpio = uncompressed_cpio(payload)?;

    let mut output = vec![0_u8; 96];
    output
        .get_mut(..4)?
        .copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    *output.get_mut(4)? = 3;
    output.get_mut(6..8)?.copy_from_slice(&0_u16.to_be_bytes());
    output.get_mut(8..10)?.copy_from_slice(&1_u16.to_be_bytes());
    output.get_mut(10..14)?.copy_from_slice(b"fuzz");
    output
        .get_mut(76..78)?
        .copy_from_slice(&1_u16.to_be_bytes());
    output
        .get_mut(78..80)?
        .copy_from_slice(&5_u16.to_be_bytes());
    output.extend_from_slice(&rpm_header(&[])?);
    while output.len() % 8 != 0 {
        output.push(0);
    }
    output.extend_from_slice(&rpm_header(&[(1124, b"cpio"), (1125, b"none")])?);
    output.extend_from_slice(&cpio);
    Some(output)
}

fn uncompressed_cpio(payload: &[u8]) -> Option<Vec<u8>> {
    let mut cpio = Vec::new();
    let checksum = payload
        .iter()
        .try_fold(0_u32, |sum, byte| sum.checked_add(u32::from(*byte)))?;
    append_cpio_record(&mut cpio, b"070702", MEMBER_NAME, payload, checksum)?;
    append_cpio_record(&mut cpio, b"070701", b"TRAILER!!!", b"", 0)?;
    Some(cpio)
}

fn write_tar_octal(header: &mut [u8], offset: usize, width: usize, value: u64) -> Option<()> {
    let digits = width.checked_sub(1)?;
    let encoded = format!("{value:0digits$o}");
    if encoded.len() != digits {
        return None;
    }
    let end = offset.checked_add(width)?;
    let field = header.get_mut(offset..end)?;
    field.fill(0);
    field.get_mut(..digits)?.copy_from_slice(encoded.as_bytes());
    Some(())
}

fn append_tar_entry(output: &mut Vec<u8>, name: &[u8], payload: &[u8]) -> Option<()> {
    let mut header = [0_u8; 512];
    header.get_mut(..name.len())?.copy_from_slice(name);
    write_tar_octal(&mut header, 100, 8, 0o644)?;
    write_tar_octal(&mut header, 108, 8, 1000)?;
    write_tar_octal(&mut header, 116, 8, 1000)?;
    write_tar_octal(&mut header, 124, 12, u64::try_from(payload.len()).ok()?)?;
    write_tar_octal(&mut header, 136, 12, 1_700_000_000)?;
    header.get_mut(148..156)?.fill(b' ');
    *header.get_mut(156)? = b'0';
    header.get_mut(257..263)?.copy_from_slice(b"ustar\0");
    header.get_mut(263..265)?.copy_from_slice(b"00");
    let checksum = header
        .iter()
        .try_fold(0_u64, |sum, byte| sum.checked_add(u64::from(*byte)))?;
    let checksum_text = format!("{checksum:06o}\0 ");
    header
        .get_mut(148..156)?
        .copy_from_slice(checksum_text.as_bytes());
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    while output.len() % 512 != 0 {
        output.push(0);
    }
    Some(())
}

fn single_entry_tar(name: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    append_tar_entry(&mut output, name, payload)?;
    let new_length = output.len().checked_add(1024)?;
    output.resize(new_length, 0);
    Some(output)
}

fn append_ar_member(output: &mut Vec<u8>, name: &[u8], payload: &[u8]) -> Option<()> {
    if name.is_empty() || name.len() > 15 {
        return None;
    }
    let mut header = [b' '; 60];
    header.get_mut(..name.len())?.copy_from_slice(name);
    *header.get_mut(name.len())? = b'/';
    for (range, value) in [
        (16..28, format!("{:<12}", 1_700_000_000)),
        (28..34, format!("{:<6}", 0)),
        (34..40, format!("{:<6}", 0)),
        (40..48, format!("{:<8o}", 0o100_644)),
        (48..58, format!("{:<10}", payload.len())),
    ] {
        header.get_mut(range)?.copy_from_slice(value.as_bytes());
    }
    header.get_mut(58..60)?.copy_from_slice(b"`\n");
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    if payload.len() % 2 != 0 {
        output.push(b'\n');
    }
    Some(())
}

fn uncompressed_deb(payload: &[u8]) -> Option<Vec<u8>> {
    let control = single_entry_tar(b"control", b"Package: fuzz\n")?;
    let data = single_entry_tar(MEMBER_NAME, payload)?;
    let mut output = b"!<arch>\n".to_vec();
    append_ar_member(&mut output, b"debian-binary", b"2.0\n")?;
    append_ar_member(&mut output, b"control.tar", &control)?;
    append_ar_member(&mut output, b"data.tar", &data)?;
    Some(output)
}

fn append_arj_header(output: &mut Vec<u8>, basic: &[u8]) -> Option<()> {
    output.extend_from_slice(&[0x60, 0xea]);
    append_le_u16(output, u16::try_from(basic.len()).ok()?);
    output.extend_from_slice(basic);
    append_le_u32(output, support::crc32(basic));
    append_le_u16(output, 0);
    Some(())
}

fn stored_arj(payload: &[u8]) -> Option<Vec<u8>> {
    let payload_size = u32::try_from(payload.len()).ok()?;
    let mut main = vec![0_u8; 30];
    *main.get_mut(0)? = 30;
    *main.get_mut(1)? = 11;
    *main.get_mut(2)? = 1;
    *main.get_mut(3)? = 2;
    *main.get_mut(6)? = 2;
    main.extend_from_slice(b"fuzz.arj\0\0");

    let mut local = vec![0_u8; 30];
    *local.get_mut(0)? = 30;
    *local.get_mut(1)? = 11;
    *local.get_mut(2)? = 1;
    *local.get_mut(3)? = 2;
    local
        .get_mut(12..16)?
        .copy_from_slice(&payload_size.to_le_bytes());
    local
        .get_mut(16..20)?
        .copy_from_slice(&payload_size.to_le_bytes());
    local
        .get_mut(20..24)?
        .copy_from_slice(&support::crc32(payload).to_le_bytes());
    local.extend_from_slice(MEMBER_NAME);
    local.extend_from_slice(&[0, 0]);

    let mut output = Vec::new();
    append_arj_header(&mut output, &main)?;
    append_arj_header(&mut output, &local)?;
    output.extend_from_slice(payload);
    output.extend_from_slice(&[0x60, 0xea, 0, 0]);
    Some(output)
}

fn exercise_generated_zip(bytes: Vec<u8>, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let Ok(archive) = ZipArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) else {
        panic!("in-process generated ZIP was rejected");
    };
    let mut output = Vec::new();
    if archive
        .extract_entry_to(0, &mut output, &cancellation, &mut budget)
        .is_err()
    {
        panic!("in-process generated ZIP failed extraction");
    }
    assert_eq!(output, expected);
}

fn exercise_generated_rpm(bytes: Vec<u8>, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let Ok(archive) = RpmArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) else {
        panic!("in-process generated RPM was rejected");
    };
    let mut output = Vec::new();
    if archive
        .extract_entry_to(0, &mut output, &cancellation, &mut budget)
        .is_err()
    {
        panic!("in-process generated RPM failed extraction");
    }
    assert_eq!(output, expected);
}

fn exercise_generated_cpio(bytes: Vec<u8>, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let Ok(archive) = CpioArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) else {
        panic!("in-process generated CPIO was rejected");
    };
    let mut output = Vec::new();
    if archive
        .extract_entry_to(0, &mut output, &cancellation, &mut budget)
        .is_err()
    {
        panic!("in-process generated CPIO failed extraction");
    }
    assert_eq!(output, expected);
}

fn exercise_generated_deb(bytes: Vec<u8>, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let Ok(archive) = DebArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) else {
        panic!("in-process generated Debian package was rejected");
    };
    let mut output = Vec::new();
    if archive
        .extract_entry_to(1, &mut output, &cancellation, &mut budget)
        .is_err()
    {
        panic!("in-process generated Debian package failed extraction");
    }
    assert_eq!(output, expected);
}

fn exercise_generated_arj(bytes: Vec<u8>, expected: &[u8]) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let Ok(archive) = ArjArchive::open_bytes(bytes, limits(), &cancellation, &mut budget) else {
        panic!("in-process generated ARJ was rejected");
    };
    let mut output = Vec::new();
    if archive
        .extract_entry_to(0, &mut output, &cancellation, &mut budget)
        .is_err()
    {
        panic!("in-process generated ARJ failed extraction");
    }
    assert_eq!(output, expected);
}

fuzz_target!(|data: &[u8]| {
    let arbitrary_end = data.len().min(MAXIMUM_FUZZ_INPUT);
    let arbitrary = match data.get(..arbitrary_end) {
        Some(value) => value,
        None => &[],
    };
    exercise_zip(arbitrary.to_vec());
    exercise_rpm(arbitrary.to_vec());
    exercise_cpio(arbitrary.to_vec());
    exercise_deb(arbitrary.to_vec());
    exercise_arj(arbitrary.to_vec());

    let payload_end = data.len().min(MAXIMUM_GENERATED_PAYLOAD);
    let payload = match data.get(..payload_end) {
        Some(value) => value,
        None => &[],
    };
    if let Some(zip) = stored_zip(payload) {
        exercise_generated_zip(zip, payload);
    }
    if let Some(rpm) = uncompressed_rpm(payload) {
        exercise_generated_rpm(rpm, payload);
    }
    if let Some(cpio) = uncompressed_cpio(payload) {
        exercise_generated_cpio(cpio, payload);
    }
    if let Some(deb) = uncompressed_deb(payload) {
        exercise_generated_deb(deb, payload);
    }
    if let Some(arj) = stored_arj(payload) {
        exercise_generated_arj(arj, payload);
    }
});
