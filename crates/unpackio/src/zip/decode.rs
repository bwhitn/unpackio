//! ZIP entry decryption, decompression, and integrity completion.

use super::{ZipCompressionMethod, ZipEncryption, ZipEntry, crypto::ZipPassword};
use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    checksum::Crc32,
    decode::{
        XzProfile, decode_bzip2, decode_deflate, decode_deflate64, decode_lzma, decode_xz,
        decode_zip_ppmd, decode_zstd,
    },
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, try_reserve, usize_to_u64,
    },
};

const FLAG_ENHANCED_DEFLATE: u16 = 1 << 4;
const FLAG_PATCHED_DATA: u16 = 1 << 5;
const FLAG_LZMA_EOS: u16 = 1 << 1;

pub(super) fn decode_entry(
    archive: &[u8],
    entry: &ZipEntry,
    password: Option<&ZipPassword>,
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        entry.uncompressed_size,
        limits.max_entry_output_bytes(),
        LimitKind::EntryOutputBytes,
    )?;
    check_limit(
        entry.uncompressed_size,
        maximum,
        LimitKind::TotalOutputBytes,
    )?;
    if entry.flags & FLAG_PATCHED_DATA != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("zip-patched-data"),
        });
    }
    if entry.flags & FLAG_ENHANCED_DEFLATE != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("zip-enhanced-deflate"),
        });
    }
    if entry.encryption == ZipEncryption::Strong {
        return Err(Error::UnsupportedFeature {
            feature: String::from("zip-strong-encryption"),
        });
    }
    if matches!(
        entry.compression,
        ZipCompressionMethod::Mp3
            | ZipCompressionMethod::Jpeg
            | ZipCompressionMethod::WavPack
            | ZipCompressionMethod::Unknown(_)
    ) {
        return Err(unsupported_method(entry.compression));
    }
    let encrypted = checked_range(
        archive,
        entry.data_start,
        entry
            .data_end
            .checked_sub(entry.data_start)
            .ok_or_else(|| zip_format("entry data range underflows"))?,
        "entry data range overflows",
        "entry data is truncated",
    )?;
    let plaintext = match entry.encryption {
        ZipEncryption::None => None,
        ZipEncryption::ZipCrypto => Some(super::crypto::decrypt_zipcrypto(
            encrypted,
            password,
            entry.zipcrypto_check_byte,
            control,
        )?),
        ZipEncryption::WinZipAes { .. } => {
            let aes = entry
                .aes
                .ok_or_else(|| zip_format("WinZip AES metadata is missing"))?;
            Some(super::crypto::decrypt_winzip_aes(
                encrypted,
                password,
                aes.key_bytes,
                limits,
                control,
            )?)
        }
        ZipEncryption::Strong => {
            return Err(Error::UnsupportedFeature {
                feature: String::from("zip-strong-encryption"),
            });
        }
    };
    let compressed = match plaintext.as_deref() {
        Some(value) => value,
        None => encrypted,
    };
    let decoded =
        decode_compressed(compressed, entry, limits, maximum, control).map_err(|error| {
            if entry.encryption == ZipEncryption::None {
                error
            } else {
                match error {
                    Error::Format { .. } | Error::Checksum { .. } => Error::WrongPasswordOrCorrupt,
                    other => other,
                }
            }
        })?;
    let actual = usize_to_u64(
        decoded.len(),
        "ZIP decoded size is not representable as u64",
    )?;
    if actual != entry.uncompressed_size {
        return if entry.encryption == ZipEncryption::None {
            Err(zip_format(
                "decoded size differs from the central declaration",
            ))
        } else {
            Err(Error::WrongPasswordOrCorrupt)
        };
    }
    if let Some(expected) = entry.crc32 {
        let mut checksum = Crc32::new();
        for chunk in decoded.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "ZIP checksum chunk length is not representable as u64",
            )?)?;
            checksum.update(chunk)?;
        }
        if checksum.finalize() != expected {
            return if entry.encryption == ZipEncryption::None {
                Err(Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(entry.index),
                })
            } else {
                Err(Error::WrongPasswordOrCorrupt)
            };
        }
    }
    Ok(decoded)
}

fn decode_compressed(
    input: &[u8],
    entry: &ZipEntry,
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let expected = Some(entry.uncompressed_size);
    match entry.compression {
        ZipCompressionMethod::Stored => copy_stored(input, entry.uncompressed_size, control),
        ZipCompressionMethod::Deflate => decode_deflate(input, expected, maximum, limits, control),
        ZipCompressionMethod::Deflate64 => {
            decode_deflate64(input, expected, maximum, limits, control)
        }
        ZipCompressionMethod::Bzip2 => decode_bzip2(input, expected, maximum, limits, control),
        ZipCompressionMethod::Lzma => decode_zip_lzma(input, entry, limits, maximum, control),
        ZipCompressionMethod::Zstandard | ZipCompressionMethod::ZstandardDeprecated => {
            decode_zstd(input, expected, maximum, limits, control)
        }
        ZipCompressionMethod::Xz => {
            if entry.version_needed < 20 {
                return Err(zip_format("XZ entries require ZIP version 2.0 or later"));
            }
            decode_xz(
                input,
                expected,
                maximum,
                limits,
                control,
                XzProfile::ZipMember {
                    member_index: entry.index,
                },
            )
        }
        ZipCompressionMethod::Ppmd => {
            if entry.version_needed < 20 {
                return Err(zip_format("PPMd entries require ZIP version 2.0 or later"));
            }
            decode_zip_ppmd(input, entry.uncompressed_size, maximum, limits, control)
        }
        ZipCompressionMethod::Mp3
        | ZipCompressionMethod::Jpeg
        | ZipCompressionMethod::WavPack
        | ZipCompressionMethod::Unknown(_) => Err(unsupported_method(entry.compression)),
    }
}

fn unsupported_method(method: ZipCompressionMethod) -> Error {
    Error::UnsupportedMethod {
        method_id: Box::from(method.id().to_le_bytes()),
    }
}

fn copy_stored(input: &[u8], expected: u64, control: &mut ParseControl<'_>) -> Result<Vec<u8>> {
    if usize_to_u64(input.len(), "stored ZIP size is not representable as u64")? != expected {
        return Err(zip_format("stored entry size differs from its declaration"));
    }
    let mut output = Vec::new();
    try_reserve(&mut output, input.len())?;
    for chunk in input.chunks(CONTROL_CHUNK_SIZE) {
        let work = usize_to_u64(
            chunk.len(),
            "stored ZIP chunk length is not representable as u64",
        )?
        .checked_mul(2)
        .ok_or_else(|| zip_format("stored ZIP work accounting overflows"))?;
        control.checkpoint(work)?;
        output.extend_from_slice(chunk);
    }
    Ok(output)
}

fn decode_zip_lzma(
    input: &[u8],
    entry: &ZipEntry,
    limits: Limits,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let header = input
        .get(..4)
        .ok_or_else(|| zip_format("LZMA entry header is truncated"))?;
    let property_length = u16::from_le_bytes(
        <[u8; 2]>::try_from(
            header
                .get(2..4)
                .ok_or_else(|| zip_format("LZMA property length is truncated"))?,
        )
        .map_err(|_| zip_format("LZMA property length is truncated"))?,
    );
    if property_length != 5 {
        return Err(zip_format(
            "ZIP LZMA properties must contain exactly five bytes",
        ));
    }
    let properties_end = 4_usize
        .checked_add(usize::from(property_length))
        .ok_or_else(|| zip_format("ZIP LZMA property range overflows"))?;
    let properties = input
        .get(4..properties_end)
        .ok_or_else(|| zip_format("ZIP LZMA properties are truncated"))?;
    let payload = input
        .get(properties_end..)
        .ok_or_else(|| zip_format("ZIP LZMA payload is truncated"))?;
    let dictionary = u32::from_le_bytes(
        <[u8; 4]>::try_from(
            properties
                .get(1..5)
                .ok_or_else(|| zip_format("ZIP LZMA dictionary is truncated"))?,
        )
        .map_err(|_| zip_format("ZIP LZMA dictionary is truncated"))?,
    );
    check_limit(
        u64::from(dictionary.max(1)),
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let expected = if entry.flags & FLAG_LZMA_EOS != 0 {
        None
    } else {
        Some(entry.uncompressed_size)
    };
    decode_lzma(payload, properties, expected, maximum, control)
}

fn zip_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ZIP: {detail}"),
    }
}
