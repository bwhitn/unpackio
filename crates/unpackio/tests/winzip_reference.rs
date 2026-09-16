#![forbid(unsafe_code)]
//! Opt-in validation of pinned local ZIP/ZIPX interoperability samples.
//!
//! `CORPUS.md` distinguishes the historical WinZip-attributed archives from
//! fresh, reproducibly authored WinZip 21/24 evidence and the supplemental
//! PPMd archive whose producing tool is not recorded.

use std::{error::Error as StdError, fmt::Write as _, fs, path::Path};

use sha2::{Digest, Sha256};
use unpackio::{
    CancellationToken, Limits, WorkBudget, ZipArchive, ZipCompressionMethod, ZipEncryption,
};

struct ArchiveCase {
    filename: &'static str,
    archive_sha256: &'static str,
    compression: ZipCompressionMethod,
    version_needed: u16,
    entry_count: usize,
}

struct MemberExpectation {
    size: u64,
    crc32: u32,
    sha256: &'static str,
}

struct ReproducibleArchiveCase {
    filename: &'static str,
    archive_sha256: &'static str,
    compression: ZipCompressionMethod,
    version_needed: u16,
    compressed_size: u64,
}

const MEMBERS: [MemberExpectation; 3] = [
    MemberExpectation {
        size: 45_056,
        crc32: 0xcfb1_09c8,
        sha256: "8557928804f57ecc340b3bb38b095a3607474ec8deb0076f316fcfe02b562106",
    },
    MemberExpectation {
        size: 40_372,
        crc32: 0x0888_14e3,
        sha256: "b251c7501fb0f55dd4a92feabe0a6f5733bc40a02679498155fae9b30138fc53",
    },
    MemberExpectation {
        size: 15_498,
        crc32: 0x9bd1_60fa,
        sha256: "4d581d93d369f6e1c9b295ff38d82dabd577f927dfaf0c35818c015c85e322d9",
    },
];

const CASES: [ArchiveCase; 5] = [
    ArchiveCase {
        filename: "WinZip26_BZip2.zipx",
        archive_sha256: "9348eec1f46601bd0d238a15373d60e8f0815f81da76d23c6671e7f54f3c98fe",
        compression: ZipCompressionMethod::Bzip2,
        version_needed: 46,
        entry_count: 5,
    },
    ArchiveCase {
        filename: "WinZip26_LZMA.zipx",
        archive_sha256: "1ecd6aaf943f80f5fbd12225f24877f52676527ce8353946b94c5a579cd6fcf2",
        compression: ZipCompressionMethod::Lzma,
        version_needed: 63,
        entry_count: 5,
    },
    ArchiveCase {
        filename: "WinZip27_XZ.zipx",
        archive_sha256: "4a88881c8e5aa3c45d67991969023af3572c910602248061ce3b049080c6c069",
        compression: ZipCompressionMethod::Xz,
        version_needed: 20,
        entry_count: 3,
    },
    ArchiveCase {
        filename: "WinZip27_ZSTD.zipx",
        archive_sha256: "d2bd5d90448b15a9c7450edbc7e5afae66d75482f5a48c74918c74898d8d75ea",
        compression: ZipCompressionMethod::Zstandard,
        version_needed: 20,
        entry_count: 3,
    },
    ArchiveCase {
        filename: "Zip.ppmd.zip",
        archive_sha256: "957ad400590021536ba46ad494eaf60f2daa134c188c14b63175f9bfba9a4f5a",
        compression: ZipCompressionMethod::Ppmd,
        version_needed: 63,
        entry_count: 6,
    },
];

const REPRODUCIBLE_CASES: [ReproducibleArchiveCase; 4] = [
    ReproducibleArchiveCase {
        filename: "winzip24-bzip2-replacement.zipx",
        archive_sha256: "b9e29b673894538ac684f5969bf7a1b659261c6c7a4b6e44493a921bdd2a6a69",
        compression: ZipCompressionMethod::Bzip2,
        version_needed: 46,
        compressed_size: 180,
    },
    ReproducibleArchiveCase {
        filename: "winzip24-lzma-replacement.zipx",
        archive_sha256: "99f5fde3b733db5f29c45b4ad93abca595c41c8896043006aca19d94a162133f",
        compression: ZipCompressionMethod::Lzma,
        version_needed: 63,
        compressed_size: 161,
    },
    ReproducibleArchiveCase {
        filename: "winzip24-xz-replacement.zipx",
        archive_sha256: "730a78de0a36a82a2dbcd258a0ab1e65f385c6ba36f2f4c53ba9c7877fd27257",
        compression: ZipCompressionMethod::Xz,
        version_needed: 20,
        compressed_size: 208,
    },
    ReproducibleArchiveCase {
        filename: "winzip24-zstd-replacement.zipx",
        archive_sha256: "49d159dd440832a05ba7e4ff3807b0c432d2c6af766547e525eb6a8f30c1401e",
        compression: ZipCompressionMethod::Zstandard,
        version_needed: 20,
        compressed_size: 85,
    },
];

const REPRODUCIBLE_MEMBER_NAME: &str = "method98-project-authored.txt";
const REPRODUCIBLE_MEMBER_SHA256: &str =
    "2f0f080056a61e094ebf01451fecdcaf854d2eedfe50abb250fa08ea8d38f91a";
const REPRODUCIBLE_MEMBER_SIZE: u64 = 208_896;
const REPRODUCIBLE_MEMBER_CRC32: u32 = 0x916d_57c5;
const WINZIP_21_PRODUCT_VERSION: &str = "21.0 (12288)";
const WINZIP_24_PRODUCT_VERSION: &str = "24.0 (14033)";
const WINZIP_21_WAVPACK_ARCHIVE_SHA256: &str =
    "f4ac3979e467ab6da8204448e5c4c9023e7708c53e38b8f222978d803d0f16fd";
const WINZIP_21_WAVPACK_OUTPUT_SHA256: &str =
    "6b89a12ab1e6de5b35ed11956a92daeb95c736757014d73816dc7985f32c3503";

fn sha256_hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}")?;
    }
    Ok(output)
}

fn verify_single_member_archive(
    label: &str,
    archive_bytes: Vec<u8>,
    original: &[u8],
    compression: ZipCompressionMethod,
    version_needed: u16,
    compressed_size: u64,
) -> Result<(), Box<dyn StdError>> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive =
        ZipArchive::open_bytes(archive_bytes, Limits::default(), &cancellation, &mut budget)?;
    if archive.entries().len() != 1 {
        return Err(format!("{label}: archive must contain exactly one entry").into());
    }
    let entry = archive
        .entries()
        .first()
        .ok_or_else(|| format!("{label}: archive has no entry"))?;
    if entry.is_directory()
        || entry.name() != REPRODUCIBLE_MEMBER_NAME
        || entry.compression_method() != compression
        || entry.encryption() != ZipEncryption::None
        || entry.version_needed() != version_needed
        || entry.compressed_size() != compressed_size
        || entry.uncompressed_size() != REPRODUCIBLE_MEMBER_SIZE
        || entry.crc32() != Some(REPRODUCIBLE_MEMBER_CRC32)
    {
        return Err(format!("{label}: member metadata differs").into());
    }

    let mut decoded = Vec::new();
    archive.extract_entry_to(entry.index(), &mut decoded, &cancellation, &mut budget)?;
    if decoded != original {
        return Err(format!("{label}: extraction differs from the original bytes").into());
    }
    let mut verify_budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut verify_budget)?;
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_WINZIP_TESTDATA pointing at the pinned local-only sample directory"]
fn external_pinned_zipx_archives_match_expected_outputs() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_WINZIP_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_TESTDATA is not set"))?;
    let root = Path::new(&root);

    for case in CASES {
        let path = root.join(case.filename);
        let bytes = fs::read(&path)?;
        if sha256_hex(&bytes)? != case.archive_sha256 {
            return Err(format!("{}: archive SHA-256 differs", case.filename).into());
        }

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        if archive.entries().len() != case.entry_count {
            return Err(format!("{}: entry count differs", case.filename).into());
        }

        let files = archive
            .entries()
            .iter()
            .filter(|entry| !entry.is_directory())
            .collect::<Vec<_>>();
        if files.len() != MEMBERS.len() {
            return Err(format!("{}: regular-file count differs", case.filename).into());
        }

        for (entry, expected) in files.iter().zip(&MEMBERS) {
            if entry.compression_method() != case.compression
                || entry.encryption() != ZipEncryption::None
                || entry.version_needed() != case.version_needed
                || entry.uncompressed_size() != expected.size
                || entry.crc32() != Some(expected.crc32)
            {
                return Err(format!("{}:{}: metadata differs", case.filename, entry.name()).into());
            }

            let mut decoded = Vec::new();
            archive.extract_entry_to(entry.index(), &mut decoded, &cancellation, &mut budget)?;
            if sha256_hex(&decoded)? != expected.sha256 {
                return Err(
                    format!("{}:{}: output SHA-256 differs", case.filename, entry.name()).into(),
                );
            }
        }

        let mut verify_budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut verify_budget)?;
    }

    Ok(())
}

#[test]
#[ignore = "requires fresh, provenance-recorded WinZip 24 replacement archives"]
fn external_reproducible_winzip24_archives_match_project_input() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_WINZIP_REPLACEMENT_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_REPLACEMENT_TESTDATA is not set"))?;
    let original_path = std::env::var_os("UNPACKIO_WINZIP_REPLACEMENT_ORIGINAL")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_REPLACEMENT_ORIGINAL is not set"))?;
    let product_version = std::env::var("UNPACKIO_WINZIP_REPLACEMENT_PRODUCT_VERSION")?;
    let authoring_recipe = std::env::var("UNPACKIO_WINZIP_REPLACEMENT_AUTHORING_RECIPE")?;
    if product_version != WINZIP_24_PRODUCT_VERSION || authoring_recipe.trim().is_empty() {
        return Err("WinZip 24 product version or authoring recipe differs".into());
    }

    let root = Path::new(&root);
    let original = fs::read(original_path)?;
    if original.len() as u64 != REPRODUCIBLE_MEMBER_SIZE
        || sha256_hex(&original)? != REPRODUCIBLE_MEMBER_SHA256
    {
        return Err("replacement input size or SHA-256 differs".into());
    }

    for case in REPRODUCIBLE_CASES {
        let archive_bytes = fs::read(root.join(case.filename))?;
        if sha256_hex(&archive_bytes)? != case.archive_sha256 {
            return Err(format!("{}: archive SHA-256 differs", case.filename).into());
        }
        verify_single_member_archive(
            case.filename,
            archive_bytes,
            &original,
            case.compression,
            case.version_needed,
            case.compressed_size,
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "requires a freshly generated, provenance-recorded Windows WinZip method-98 oracle"]
fn external_winzip_ppmd_oracle_matches_project_input() -> Result<(), Box<dyn StdError>> {
    let archive_path = std::env::var_os("UNPACKIO_WINZIP_PPMD_ARCHIVE")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_PPMD_ARCHIVE is not set"))?;
    let original_path = std::env::var_os("UNPACKIO_WINZIP_PPMD_ORIGINAL")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_PPMD_ORIGINAL is not set"))?;
    let product_version = std::env::var("UNPACKIO_WINZIP_PPMD_PRODUCT_VERSION")?;
    let authoring_recipe = std::env::var("UNPACKIO_WINZIP_PPMD_AUTHORING_RECIPE")?;
    if product_version != WINZIP_21_PRODUCT_VERSION || authoring_recipe.trim().is_empty() {
        return Err("WinZip 21 product version or PPMd authoring recipe differs".into());
    }

    let archive_bytes = fs::read(archive_path)?;
    if sha256_hex(&archive_bytes)?
        != "7ce980e5e69c83416ef0b010318212498203146128cb1f7ef3f3bf8a98fa8dbb"
    {
        return Err("WinZip PPMd archive SHA-256 differs".into());
    }
    let original = fs::read(original_path)?;
    if sha256_hex(&original)? != REPRODUCIBLE_MEMBER_SHA256 {
        return Err("WinZip PPMd original SHA-256 differs".into());
    }
    verify_single_member_archive(
        "WinZip PPMd",
        archive_bytes,
        &original,
        ZipCompressionMethod::Ppmd,
        20,
        142,
    )
}

#[test]
#[ignore = "requires a freshly generated, provenance-recorded Windows WinZip method-97 oracle"]
fn external_winzip_wavpack_oracle_matches_original_wave() -> Result<(), Box<dyn StdError>> {
    let archive_path = std::env::var_os("UNPACKIO_WINZIP_WAVPACK_ARCHIVE")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_WAVPACK_ARCHIVE is not set"))?;
    let original_path = std::env::var_os("UNPACKIO_WINZIP_WAVPACK_ORIGINAL")
        .ok_or_else(|| String::from("UNPACKIO_WINZIP_WAVPACK_ORIGINAL is not set"))?;
    let expected_archive_hash = std::env::var("UNPACKIO_WINZIP_WAVPACK_ARCHIVE_SHA256")?;
    let expected_output_hash = std::env::var("UNPACKIO_WINZIP_WAVPACK_OUTPUT_SHA256")?;
    let product_version = std::env::var("UNPACKIO_WINZIP_PRODUCT_VERSION")?;
    let authoring_recipe = std::env::var("UNPACKIO_WINZIP_AUTHORING_RECIPE")?;
    if product_version != WINZIP_21_PRODUCT_VERSION
        || expected_archive_hash != WINZIP_21_WAVPACK_ARCHIVE_SHA256
        || expected_output_hash != WINZIP_21_WAVPACK_OUTPUT_SHA256
        || authoring_recipe.trim().is_empty()
    {
        return Err("WinZip WavPack provenance values differ from the recorded evidence".into());
    }

    let archive_bytes = fs::read(archive_path)?;
    let original = fs::read(original_path)?;
    if sha256_hex(&archive_bytes)? != WINZIP_21_WAVPACK_ARCHIVE_SHA256 {
        return Err("WinZip WavPack archive SHA-256 differs".into());
    }
    if sha256_hex(&original)? != WINZIP_21_WAVPACK_OUTPUT_SHA256 {
        return Err("WinZip WavPack original SHA-256 differs".into());
    }

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive =
        ZipArchive::open_bytes(archive_bytes, Limits::default(), &cancellation, &mut budget)?;
    let files = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory())
        .collect::<Vec<_>>();
    let entry = files
        .first()
        .copied()
        .ok_or_else(|| String::from("WinZip WavPack archive has no regular member"))?;
    if files.len() != 1
        || entry.compression_method() != ZipCompressionMethod::WavPack
        || entry.encryption() != ZipEncryption::None
        || entry.version_needed() != 20
        || entry.name() != "pcm16_multiblock.wav"
        || entry.compressed_size() != 334
        || entry.uncompressed_size() != 300_076
        || entry.crc32() != Some(0x460b_ad65)
    {
        return Err("WinZip oracle must contain one unencrypted method-97 member".into());
    }

    let mut decoded = Vec::new();
    archive.extract_entry_to(entry.index(), &mut decoded, &cancellation, &mut budget)?;
    if decoded != original {
        return Err("WinZip WavPack extraction differs from the original bytes".into());
    }
    let mut verify_budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut verify_budget)?;
    Ok(())
}
