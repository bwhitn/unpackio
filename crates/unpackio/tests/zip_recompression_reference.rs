#![forbid(unsafe_code)]
//! Provenance-pinned WinZip MP3/JPEG interoperability fixtures.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use unpackio::{
    CancellationToken, Error, Limits, Result, WorkBudget, ZipArchive, ZipCompressionMethod,
    ZipEncryption,
};

const METHOD_94_SOURCE: &str = include_str!("fixtures/method94/method94-project-authored.mp3.b64");
const METHOD_94_ARCHIVE: &str = include_str!("fixtures/method94/winzip21-method94.zipx.b64");
const METHOD_96_SOURCE: &str = include_str!("fixtures/method96/method96-project-authored.jpg.b64");
const METHOD_96_ARCHIVE: &str = include_str!("fixtures/method96/winzip21-method96.zipx.b64");

struct FixtureCase {
    source: &'static str,
    archive: &'static str,
    name: &'static str,
    raw_name: &'static [u8],
    method: ZipCompressionMethod,
    compressed_size: u64,
    uncompressed_size: u64,
    crc32: u32,
    source_sha256: &'static str,
    payload_sha256: &'static str,
    archive_sha256: &'static str,
}

const CASES: [FixtureCase; 2] = [
    FixtureCase {
        source: METHOD_94_SOURCE,
        archive: METHOD_94_ARCHIVE,
        name: "method94-project-authored.mp3",
        raw_name: b"method94-project-authored.mp3",
        method: ZipCompressionMethod::Mp3,
        compressed_size: 216,
        uncompressed_size: 55_587,
        crc32: 0xe6cd_b0ac,
        source_sha256: "372d875979967b2d95b48c2ded842a2a6bbd295c50d2455f8ad9829d2826aa0e",
        payload_sha256: "e348bb86122aaf35d1f4c136a0be6e025bf3ce2b5304aa1f17c962b5fff81de6",
        archive_sha256: "4cb0f2e7d5fae6f13d708ad79cf4721064675a50f6582d936aa41573e308a841",
    },
    FixtureCase {
        source: METHOD_96_SOURCE,
        archive: METHOD_96_ARCHIVE,
        name: "method96-project-authored.jpg",
        raw_name: b"method96-project-authored.jpg",
        method: ZipCompressionMethod::Jpeg,
        compressed_size: 3_155,
        uncompressed_size: 7_823,
        crc32: 0x7422_fe59,
        source_sha256: "95ef01838a55308006fabf6d2e512123a37916067cce58dd5076c89da43e2244",
        payload_sha256: "b8c58ce398a10deae01f74e0632971765f9d6a1df53148584bf91c44e52dc091",
        archive_sha256: "47454618f65cef060c2ba1d96b8b36d8028681ac693f9be3d57e791ec57c15e1",
    },
];

#[test]
fn winzip21_method_94_and_96_fixtures_are_pinned() -> Result<()> {
    for case in &CASES {
        let source = decode_base64(case.source)?;
        assert_eq!(u64_from_usize(source.len())?, case.uncompressed_size);
        assert_eq!(crc32(&source), case.crc32);
        assert_eq!(sha256_hex(&source)?, case.source_sha256);

        let archive_bytes = decode_base64(case.archive)?;
        assert_eq!(sha256_hex(&archive_bytes)?, case.archive_sha256);
        assert_eq!(le_u16(&archive_bytes, 4)?, 20);
        assert_eq!(le_u16(&archive_bytes, 6)?, 0);
        assert_eq!(le_u16(&archive_bytes, 8)?, case.method.id());
        assert_eq!(le_u32(&archive_bytes, 14)?, case.crc32);
        assert_eq!(u64::from(le_u32(&archive_bytes, 18)?), case.compressed_size);
        assert_eq!(
            u64::from(le_u32(&archive_bytes, 22)?),
            case.uncompressed_size
        );
        let (payload_offset, payload) = first_local_payload(&archive_bytes)?;
        assert_eq!(payload_offset, 59);
        assert_eq!(u64_from_usize(payload.len())?, case.compressed_size);
        assert_eq!(sha256_hex(payload)?, case.payload_sha256);

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive =
            ZipArchive::open_bytes(archive_bytes, Limits::default(), &cancellation, &mut budget)?;
        assert_eq!(archive.entries().len(), 1);
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| fixture_error("WinZip fixture has no member"))?;
        assert_eq!(entry.index(), 0);
        assert_eq!(entry.raw_name(), case.raw_name);
        assert_eq!(entry.name(), case.name);
        assert_eq!(entry.compression_method(), case.method);
        assert_eq!(entry.encryption(), ZipEncryption::None);
        assert_eq!(entry.version_needed(), 20);
        assert_eq!(entry.flags(), 0);
        assert_eq!(entry.compressed_size(), case.compressed_size);
        assert_eq!(entry.uncompressed_size(), case.uncompressed_size);
        assert_eq!(entry.crc32(), Some(case.crc32));

        if case.method == ZipCompressionMethod::Jpeg {
            let mut output = Vec::new();
            archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
            assert_eq!(output, source);
            let mut verify_budget = WorkBudget::unlimited();
            archive.verify(&cancellation, &mut verify_budget)?;
        } else {
            let mut output = Vec::new();
            let error = archive
                .extract_entry_to(0, &mut output, &cancellation, &mut budget)
                .err()
                .ok_or_else(|| fixture_error("unsupported WinZip fixture extracted"))?;
            assert!(output.is_empty());
            assert_unsupported(error, case.method.id());

            let mut verify_budget = WorkBudget::unlimited();
            let error = archive
                .verify(&cancellation, &mut verify_budget)
                .err()
                .ok_or_else(|| fixture_error("unsupported WinZip fixture verified"))?;
            assert_unsupported(error, case.method.id());
        }
    }
    Ok(())
}

fn first_local_payload(bytes: &[u8]) -> Result<(usize, &[u8])> {
    if bytes.get(..4) != Some(b"PK\x03\x04".as_slice()) {
        return Err(fixture_error("WinZip local-header signature is invalid"));
    }
    let compressed_size = usize::try_from(le_u32(bytes, 18)?)
        .map_err(|_| fixture_error("WinZip compressed size is not representable"))?;
    let name_size = usize::from(le_u16(bytes, 26)?);
    let extra_size = usize::from(le_u16(bytes, 28)?);
    let data_start = 30_usize
        .checked_add(name_size)
        .and_then(|value| value.checked_add(extra_size))
        .ok_or_else(|| fixture_error("WinZip local-header range overflows"))?;
    let data_end = data_start
        .checked_add(compressed_size)
        .ok_or_else(|| fixture_error("WinZip payload range overflows"))?;
    let payload = bytes
        .get(data_start..data_end)
        .ok_or_else(|| fixture_error("WinZip payload is truncated"))?;
    Ok((data_start, payload))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !value
}

fn assert_unsupported(error: Error, identifier: u16) {
    assert!(matches!(
        error,
        Error::UnsupportedMethod { method_id }
            if method_id.as_ref() == identifier.to_le_bytes()
    ));
}

fn sha256_hex(bytes: &[u8]) -> Result<String> {
    let mut output = String::new();
    output
        .try_reserve_exact(64)
        .map_err(|_| allocation_error())?;
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}")
            .map_err(|_| fixture_error("SHA-256 formatting failed"))?;
    }
    Ok(output)
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| fixture_error("WinZip u16 range overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| fixture_error("WinZip u16 is truncated"))?;
    let array = <[u8; 2]>::try_from(value).map_err(|_| fixture_error("WinZip u16 is truncated"))?;
    Ok(u16::from_le_bytes(array))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| fixture_error("WinZip u32 range overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| fixture_error("WinZip u32 is truncated"))?;
    let array = <[u8; 4]>::try_from(value).map_err(|_| fixture_error("WinZip u32 is truncated"))?;
    Ok(u32::from_le_bytes(array))
}

fn u64_from_usize(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| fixture_error("fixture size is not representable as u64"))
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
    let mut compact = Vec::new();
    compact
        .try_reserve_exact(encoded.len())
        .map_err(|_| allocation_error())?;
    compact.extend(encoded.bytes().filter(|byte| !byte.is_ascii_whitespace()));
    if compact.len() % 4 != 0 {
        return Err(fixture_error("base64 fixture length is invalid"));
    }
    let capacity = compact
        .len()
        .checked_div(4)
        .and_then(|value| value.checked_mul(3))
        .ok_or_else(|| fixture_error("base64 decoded length overflows"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| allocation_error())?;
    for chunk in compact.chunks_exact(4) {
        let first = base64_value(required(chunk, 0)?)?;
        let second = base64_value(required(chunk, 1)?)?;
        let third_byte = required(chunk, 2)?;
        let fourth_byte = required(chunk, 3)?;
        let third = base64_value(third_byte)?;
        let fourth = base64_value(fourth_byte)?;
        if first >= 64 || second >= 64 {
            return Err(fixture_error("base64 padding is misplaced"));
        }
        output.push((first << 2) | (second >> 4));
        if third < 64 {
            output.push((second << 4) | (third >> 2));
            if fourth < 64 {
                output.push((third << 6) | fourth);
            } else if fourth_byte != b'=' {
                return Err(fixture_error("base64 fourth character is invalid"));
            }
        } else if third_byte != b'=' || fourth_byte != b'=' {
            return Err(fixture_error("base64 padding is invalid"));
        }
    }
    Ok(output)
}

fn required(bytes: &[u8], index: usize) -> Result<u8> {
    bytes
        .get(index)
        .copied()
        .ok_or_else(|| fixture_error("base64 quartet is truncated"))
}

fn base64_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => byte
            .checked_sub(b'A')
            .ok_or_else(|| fixture_error("base64 value underflows")),
        b'a'..=b'z' => byte
            .checked_sub(b'a')
            .and_then(|value| value.checked_add(26))
            .ok_or_else(|| fixture_error("base64 value overflows")),
        b'0'..=b'9' => byte
            .checked_sub(b'0')
            .and_then(|value| value.checked_add(52))
            .ok_or_else(|| fixture_error("base64 value overflows")),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Ok(64),
        _ => Err(fixture_error("base64 character is invalid")),
    }
}

fn fixture_error(detail: &'static str) -> Error {
    Error::Format {
        detail: String::from(detail),
    }
}

fn allocation_error() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::OutOfMemory,
        "WinZip reference fixture allocation failed",
    ))
}
