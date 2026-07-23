#![forbid(unsafe_code)]
//! Opt-in structural checks against an externally stored audited 7z corpus.

use std::{error::Error as StdError, fs, path::Path};

use unpackio::{CancellationToken, Limits, WorkBudget, parse_archive};

fn parse_path(path: &Path) -> Result<(), Box<dyn StdError>> {
    let bytes = fs::read(path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    if let Err(error) = parse_archive(&bytes, Limits::default(), &cancellation, &mut budget) {
        return Err(format!("{}: {error}", path.display()).into());
    }
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA pointing at the audited testdata directory"]
fn audited_valid_corpus_has_valid_models() -> Result<(), Box<dyn StdError>> {
    let Some(root) = std::env::var_os("UNPACKIO_7Z_TESTDATA") else {
        return Err(String::from("UNPACKIO_7Z_TESTDATA is not set").into());
    };
    let root = Path::new(&root);
    let names = [
        "7zcracker.7z",
        "aes7z.7z",
        "arm.7z",
        "arm64.7z",
        "bcj.7z",
        "bcj2.7z",
        "brotli.7z",
        "bzip2.7z",
        "copy.7z",
        "deflate.7z",
        "delta.7z",
        "empty.7z",
        "empty2.7z",
        "file_and_empty.7z",
        "issue87.7z",
        "lz4.7z",
        "lzma.7z",
        "lzma1900.7z",
        "lzma2.7z",
        "ppc.7z",
        "ppmd.7z",
        "pr472.7z",
        "sfx.exe",
        "sparc.7z",
        "t0.7z",
        "t1.7z",
        "t2.7z",
        "t3.7z",
        "t4.7z",
        "t5.7z",
        "zstd.7z",
    ];

    for name in names {
        parse_path(&root.join(name))?;
    }

    let mut joined_volumes = Vec::new();
    for suffix in 1_u8..=6 {
        let name = format!("multi.7z.{suffix:03}");
        let part = fs::read(root.join(name))?;
        joined_volumes.try_reserve(part.len())?;
        joined_volumes.extend_from_slice(&part);
    }
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    parse_archive(
        &joined_volumes,
        Limits::default(),
        &cancellation,
        &mut budget,
    )?;

    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA pointing at the audited testdata directory"]
fn audited_missing_unpack_regression_is_rejected() -> Result<(), Box<dyn StdError>> {
    let Some(root) = std::env::var_os("UNPACKIO_7Z_TESTDATA") else {
        return Err(String::from("UNPACKIO_7Z_TESTDATA is not set").into());
    };
    let path = Path::new(&root).join("COMPRESS-492.7z");
    let bytes = fs::read(&path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    if parse_archive(&bytes, Limits::default(), &cancellation, &mut budget).is_ok() {
        return Err(format!("{} unexpectedly produced a model", path.display()).into());
    }
    Ok(())
}
