#![forbid(unsafe_code)]
//! Opt-in validation of pinned local ZIP/ZIPX interoperability samples.
//!
//! `CORPUS.md` distinguishes the four WinZip-attributed archives from the
//! supplemental PPMd archive whose producing tool is not recorded.

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

fn sha256_hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}")?;
    }
    Ok(output)
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
