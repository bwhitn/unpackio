//! Redistributable real-encoder ARJ method fixtures and extraction oracles.

use sha2::{Digest, Sha256};
use unpackio::{
    ArjArchive, CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget,
};

const METHOD_1: &str = include_str!("fixtures/arj/method1.arj.b64");
const METHOD_2: &str = include_str!("fixtures/arj/method2.arj.b64");
const METHOD_3: &str = include_str!("fixtures/arj/method3.arj.b64");
const METHOD_4: &str = include_str!("fixtures/arj/method4.arj.b64");

const LICENSE_SHA256: [u8; 32] = [
    0xc7, 0x1d, 0x23, 0x9d, 0xf9, 0x17, 0x26, 0xfc, 0x51, 0x9c, 0x6e, 0xb7, 0x2d, 0x31, 0x8e, 0xc6,
    0x58, 0x20, 0x62, 0x72, 0x32, 0xb2, 0xf7, 0x96, 0x21, 0x9e, 0x87, 0xdc, 0xf3, 0x5d, 0x0a, 0xb4,
];

#[test]
fn extracts_real_arj_methods_one_through_four() -> Result<()> {
    for (encoded, method) in [
        (METHOD_1, 1_u8),
        (METHOD_2, 2),
        (METHOD_3, 3),
        (METHOD_4, 4),
    ] {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ArjArchive::open_bytes(
            decode_base64(encoded)?,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let entry = archive.entries().first().ok_or_else(|| Error::Format {
            detail: String::from("ARJ reference fixture has no member"),
        })?;
        assert_eq!(entry.raw_name(), b"LICENSE");
        assert_eq!(entry.compression_method().id(), method);
        assert_eq!(entry.size(), 11_357);
        let mut output = Vec::new();
        archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
        let actual: [u8; 32] = Sha256::digest(&output).into();
        assert_eq!(actual, LICENSE_SHA256);
    }
    Ok(())
}

#[test]
fn real_arj_methods_reject_data_corruption_and_resource_exhaustion() -> Result<()> {
    for (encoded, dictionary_bytes) in [
        (METHOD_1, 68_u64 * 1024),
        (METHOD_2, 68 * 1024),
        (METHOD_3, 68 * 1024),
        (METHOD_4, 8 * 1024),
    ] {
        let bytes = decode_base64(encoded)?;
        let (data_start, data_size) = first_member_data_range(&bytes)?;
        let mutation = data_start
            .checked_add(data_size / 2)
            .ok_or_else(|| fixture_error("ARJ mutation offset overflows"))?;
        let mut corrupt = bytes.clone();
        let byte = corrupt
            .get_mut(mutation)
            .ok_or_else(|| fixture_error("ARJ mutation byte is missing"))?;
        *byte ^= 1;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive =
            ArjArchive::open_bytes(corrupt, Limits::default(), &cancellation, &mut budget)?;
        let error = archive
            .verify(&cancellation, &mut budget)
            .err()
            .ok_or_else(|| fixture_error("corrupted ARJ member verified"))?;
        assert!(matches!(
            error.kind(),
            ErrorKind::Format | ErrorKind::Checksum
        ));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive =
            ArjArchive::open_bytes(bytes.clone(), Limits::default(), &cancellation, &mut budget)?;
        let dictionary_limit = Limits::builder()
            .max_dictionary_bytes(
                dictionary_bytes
                    .checked_sub(1)
                    .ok_or_else(|| fixture_error("ARJ dictionary test limit underflows"))?,
            )
            .build();
        let mut budget = WorkBudget::unlimited();
        let limited =
            ArjArchive::open_bytes(bytes.clone(), dictionary_limit, &cancellation, &mut budget)?;
        assert!(matches!(
            limited.verify(&cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                ..
            })
        ));

        let mut exhausted = WorkBudget::bounded(0);
        assert!(matches!(
            archive.verify(&cancellation, &mut exhausted),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancelled, &mut budget),
            Err(Error::Cancelled)
        ));

        let output_limit = Limits::builder().max_entry_output_bytes(11_356).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            ArjArchive::open_bytes(bytes, output_limit, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                requested: 11_357,
                maximum: 11_356,
            })
        ));
    }
    Ok(())
}

fn first_member_data_range(bytes: &[u8]) -> Result<(usize, usize)> {
    let local_header = header_end_with_extensions(bytes, 0)?;
    let basic_start = local_header
        .checked_add(4)
        .ok_or_else(|| fixture_error("ARJ local basic-header offset overflows"))?;
    let compressed_size_offset = basic_start
        .checked_add(12)
        .ok_or_else(|| fixture_error("ARJ compressed-size offset overflows"))?;
    let compressed_size = usize::try_from(le_u32(bytes, compressed_size_offset)?)
        .map_err(|_| fixture_error("ARJ compressed size is not representable"))?;
    let data_start = header_end_with_extensions(bytes, local_header)?;
    let data_end = data_start
        .checked_add(compressed_size)
        .ok_or_else(|| fixture_error("ARJ member data range overflows"))?;
    let _ = bytes
        .get(data_start..data_end)
        .ok_or_else(|| fixture_error("ARJ member data is truncated"))?;
    if compressed_size == 0 {
        return Err(fixture_error(
            "ARJ reference fixture has no compressed bytes",
        ));
    }
    Ok((data_start, compressed_size))
}

fn header_end_with_extensions(bytes: &[u8], offset: usize) -> Result<usize> {
    let magic_end = offset
        .checked_add(2)
        .ok_or_else(|| fixture_error("ARJ fixture magic range overflows"))?;
    if bytes.get(offset..magic_end) != Some(&[0x60, 0xea]) {
        return Err(fixture_error("ARJ fixture header magic is invalid"));
    }
    let size_offset = offset
        .checked_add(2)
        .ok_or_else(|| fixture_error("ARJ header size offset overflows"))?;
    let size = usize::from(le_u16(bytes, size_offset)?);
    if size == 0 {
        return Err(fixture_error("ARJ fixture header is terminal"));
    }
    let mut next = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(size))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| fixture_error("ARJ header range overflows"))?;
    let _ = bytes
        .get(offset..next)
        .ok_or_else(|| fixture_error("ARJ header is truncated"))?;
    loop {
        let extension_size = usize::from(le_u16(bytes, next)?);
        next = next
            .checked_add(2)
            .ok_or_else(|| fixture_error("ARJ extension offset overflows"))?;
        if extension_size == 0 {
            return Ok(next);
        }
        next = next
            .checked_add(extension_size)
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| fixture_error("ARJ extension range overflows"))?;
        let _ = bytes
            .get(..next)
            .ok_or_else(|| fixture_error("ARJ extension is truncated"))?;
    }
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| fixture_error("ARJ u16 range overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| fixture_error("ARJ u16 is truncated"))?;
    let array = <[u8; 2]>::try_from(value).map_err(|_| fixture_error("ARJ u16 is truncated"))?;
    Ok(u16::from_le_bytes(array))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| fixture_error("ARJ u32 range overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| fixture_error("ARJ u32 is truncated"))?;
    let array = <[u8; 4]>::try_from(value).map_err(|_| fixture_error("ARJ u32 is truncated"))?;
    Ok(u32::from_le_bytes(array))
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
        "ARJ reference fixture allocation failed",
    ))
}
