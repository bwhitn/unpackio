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
// XZ Utils 5.8.3 encoded the project-authored `abc` bytes as one method-95
// compatible XZ stream with a 64 KiB dictionary and Check type NONE.
const XZ_ABC: &[u8] = &[
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x00, 0xff, 0x12, 0xd9, 0x41, 0x02, 0x00, 0x21, 0x01,
    0x08, 0x00, 0x00, 0x00, 0xd8, 0x0f, 0x23, 0x13, 0x01, 0x00, 0x02, 0x61, 0x62, 0x63, 0x00, 0x00,
    0x00, 0x01, 0x13, 0x03, 0x03, 0xa5, 0x60, 0xd8, 0x06, 0x72, 0x9e, 0x7a, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x59, 0x5a,
];
// Stock 7zz 26.02 encoded the project-authored `abc` bytes with ZIP PPMd-I,
// order 2, 1 MiB, and Restart restoration.
const PPMD_ABC: &[u8] = &[0x01, 0x00, 0x61, 0x03, 0x6e, 0x81, 0x2d, 0x4c, 0x00];
const WAVPACK_PCM8_HEX: &[u8] =
    include_bytes!("../../crates/unpackio/tests/fixtures/method97/pcm8_mono.wv.hex");
const WAVPACK_PCM8_WAVE_HEX: &[u8] =
    include_bytes!("../../crates/unpackio/tests/fixtures/method97/pcm8_mono.wav.hex");
const WINZIP_JPEG_ARCHIVE_B64: &[u8] =
    include_bytes!("../../crates/unpackio/tests/fixtures/method96/winzip21-method96.zipx.b64");
const WINZIP_JPEG_SOURCE_B64: &[u8] = include_bytes!(
    "../../crates/unpackio/tests/fixtures/method96/method96-project-authored.jpg.b64"
);

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Some(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(byte.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

fn decode_hex_fixture(encoded: &[u8]) -> Option<Vec<u8>> {
    let digits = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let mut chunks = digits.chunks_exact(2);
    let mut output = Vec::with_capacity(digits.len() / 2);
    for chunk in chunks.by_ref() {
        let high = hex_nibble(*chunk.first()?)?;
        let low = hex_nibble(*chunk.get(1)?)?;
        output.push(high.checked_mul(16)?.checked_add(low)?);
    }
    if !chunks.remainder().is_empty() {
        return None;
    }
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.saturating_sub(b'A')),
        b'a'..=b'z' => Some(byte.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(byte.saturating_sub(b'0').saturating_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(64),
        _ => None,
    }
}

fn decode_base64_fixture(encoded: &[u8]) -> Option<Vec<u8>> {
    let compact = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.len() % 4 != 0 {
        return None;
    }
    let capacity = compact.len().checked_div(4)?.checked_mul(3)?;
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).ok()?;
    for chunk in compact.chunks_exact(4) {
        let [first, second, third, fourth] = <[u8; 4]>::try_from(chunk).ok()?;
        let first = base64_value(first)?;
        let second = base64_value(second)?;
        let third = base64_value(third)?;
        let fourth = base64_value(fourth)?;
        if first >= 64 || second >= 64 {
            return None;
        }
        output.push((first << 2) | (second >> 4));
        if third < 64 {
            output.push((second << 4) | (third >> 2));
        }
        if fourth < 64 {
            if third >= 64 {
                return None;
            }
            output.push((third << 6) | fourth);
        }
    }
    Some(output)
}

fn winzip_jpeg_fixture() -> Option<(Vec<u8>, Vec<u8>)> {
    let archive = decode_base64_fixture(WINZIP_JPEG_ARCHIVE_B64)?;
    let source = decode_base64_fixture(WINZIP_JPEG_SOURCE_B64)?;
    let payload_end = 59_usize.checked_add(3_155)?;
    let payload = archive.get(59..payload_end)?.to_vec();
    Some((payload, source))
}

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

fn encoded_zip(payload: &[u8], decoded: &[u8], method: u16, version: u16) -> Option<Vec<u8>> {
    let payload_size = u32::try_from(payload.len()).ok()?;
    let decoded_size = u32::try_from(decoded.len()).ok()?;
    let name_size = u16::try_from(MEMBER_NAME.len()).ok()?;
    let checksum = support::crc32(decoded);
    let mut output = Vec::new();

    append_le_u32(&mut output, 0x0403_4b50);
    append_le_u16(&mut output, version);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, method);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u32(&mut output, checksum);
    append_le_u32(&mut output, payload_size);
    append_le_u32(&mut output, decoded_size);
    append_le_u16(&mut output, name_size);
    append_le_u16(&mut output, 0);
    output.extend_from_slice(MEMBER_NAME);
    output.extend_from_slice(payload);

    let directory_offset = u32::try_from(output.len()).ok()?;
    append_le_u32(&mut output, 0x0201_4b50);
    append_le_u16(&mut output, 0x031e);
    append_le_u16(&mut output, version);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, method);
    append_le_u16(&mut output, 0);
    append_le_u16(&mut output, 0);
    append_le_u32(&mut output, checksum);
    append_le_u32(&mut output, payload_size);
    append_le_u32(&mut output, decoded_size);
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

fn stored_zip(payload: &[u8]) -> Option<Vec<u8>> {
    encoded_zip(payload, payload, 0, 20)
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
    if let Some(zip) = encoded_zip(XZ_ABC, b"abc", 95, 20) {
        exercise_generated_zip(zip, b"abc");
    }
    if let Some(zip) = encoded_zip(PPMD_ABC, b"abc", 98, 20) {
        exercise_generated_zip(zip, b"abc");
    }
    if let (Some(wavpack), Some(wave)) = (
        decode_hex_fixture(WAVPACK_PCM8_HEX),
        decode_hex_fixture(WAVPACK_PCM8_WAVE_HEX),
    ) {
        if let Some(zip) = encoded_zip(&wavpack, &wave, 97, 20) {
            exercise_generated_zip(zip, &wave);
        }
    }
    let method_selector = arbitrary.first().copied().unwrap_or_default();
    if method_selector & 0x3f == 0 {
        if let Some((jpeg_payload, jpeg)) = winzip_jpeg_fixture() {
            if let Some(zip) = encoded_zip(&jpeg_payload, &jpeg, 96, 20) {
                exercise_generated_zip(zip, &jpeg);
            }
            if !jpeg_payload.is_empty() {
                let high = usize::from(arbitrary.get(1).copied().unwrap_or_default());
                let low = usize::from(arbitrary.get(2).copied().unwrap_or_default());
                let selected = high
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(low));
                if let Some(selected) = selected {
                    let offset = selected % jpeg_payload.len();
                    let mask = arbitrary.get(3).copied().unwrap_or(1).max(1);
                    let mut hostile_jpeg = jpeg_payload.clone();
                    if let Some(byte) = hostile_jpeg.get_mut(offset) {
                        *byte ^= mask;
                    }
                    if let Some(zip) = encoded_zip(&hostile_jpeg, &jpeg, 96, 20) {
                        exercise_zip(zip);
                    }
                    if let Some(prefix) = jpeg_payload.get(..offset) {
                        if let Some(zip) = encoded_zip(prefix, &jpeg, 96, 20) {
                            exercise_zip(zip);
                        }
                    }
                }
            }
        }
    }
    if !arbitrary.is_empty() {
        let mut hostile_xz = XZ_ABC.to_vec();
        let selector = match arbitrary.first() {
            Some(value) => *value,
            None => 0,
        };
        let offset = usize::from(selector) % hostile_xz.len();
        let mask = match arbitrary.get(1) {
            Some(value) => (*value).max(1),
            None => 1,
        };
        if let Some(byte) = hostile_xz.get_mut(offset) {
            *byte ^= mask;
        }
        if let Some(zip) = encoded_zip(&hostile_xz, b"abc", 95, 20) {
            exercise_zip(zip);
        }
        let prefix_size = usize::from(selector) % XZ_ABC.len();
        if let Some(prefix) = XZ_ABC.get(..prefix_size) {
            if let Some(zip) = encoded_zip(prefix, b"abc", 95, 20) {
                exercise_zip(zip);
            }
        }

        let mut hostile_ppmd = PPMD_ABC.to_vec();
        let ppmd_offset = usize::from(selector) % hostile_ppmd.len();
        if let Some(byte) = hostile_ppmd.get_mut(ppmd_offset) {
            *byte ^= mask;
        }
        if let Some(zip) = encoded_zip(&hostile_ppmd, b"abc", 98, 20) {
            exercise_zip(zip);
        }
        let ppmd_prefix_size = usize::from(selector) % PPMD_ABC.len();
        if let Some(prefix) = PPMD_ABC.get(..ppmd_prefix_size) {
            if let Some(zip) = encoded_zip(prefix, b"abc", 98, 20) {
                exercise_zip(zip);
            }
        }

        if let (Some(mut hostile_wavpack), Some(wave)) = (
            decode_hex_fixture(WAVPACK_PCM8_HEX),
            decode_hex_fixture(WAVPACK_PCM8_WAVE_HEX),
        ) {
            let wavpack_offset = usize::from(selector) % hostile_wavpack.len();
            if let Some(byte) = hostile_wavpack.get_mut(wavpack_offset) {
                *byte ^= mask;
            }
            if let Some(zip) = encoded_zip(&hostile_wavpack, &wave, 97, 20) {
                exercise_zip(zip);
            }
            let prefix_size = usize::from(selector) % hostile_wavpack.len();
            if let Some(prefix) = hostile_wavpack.get(..prefix_size) {
                if let Some(zip) = encoded_zip(prefix, &wave, 97, 20) {
                    exercise_zip(zip);
                }
            }
        }
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
