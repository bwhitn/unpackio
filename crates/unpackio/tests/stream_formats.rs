//! Public standalone-stream API and optional external-oracle regressions.

use std::{env, fs};

use unpackio::{CancellationToken, CompressedStream, Limits, Result, StreamFormat, WorkBudget};

#[test]
fn unix_compress_open_path_does_not_derive_an_output_path() -> Result<()> {
    const FIXTURE: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x68, 0xca, 0xb0, 0x61, 0xf3, 0x06, 0x44, 0x1d, 0x37, 0x69, 0xf0, 0x80,
        0x18, 0xf3, 0xa6, 0x0d, 0x1c, 0x39, 0x65, 0xe6, 0xcc, 0x51, 0x00,
    ];
    let path = env::temp_dir().join(format!(
        "unpackio-stream-open-path-{}-{}.Z",
        std::process::id(),
        FIXTURE.len()
    ));
    fs::write(&path, FIXTURE)?;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let stream =
        CompressedStream::open_path(&path, Limits::default(), &cancellation, &mut open_budget);
    fs::remove_file(&path)?;
    let stream = stream?;
    assert_eq!(stream.info().format(), StreamFormat::UnixCompress);
    let mut extraction_budget = WorkBudget::unlimited();
    assert_eq!(
        stream.decompress(&cancellation, &mut extraction_budget)?,
        b"hello unix compress\n"
    );
    Ok(())
}

#[test]
fn optional_unix_compress_oracle_fixture_matches_exact_bytes() -> Result<()> {
    let Some(compressed_path) = env::var_os("UNPACKIO_UNIX_COMPRESS_FIXTURE") else {
        return Ok(());
    };
    let Some(expected_path) = env::var_os("UNPACKIO_UNIX_COMPRESS_EXPECTED") else {
        return Ok(());
    };
    let expected = fs::read(expected_path)?;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let stream = CompressedStream::open_path_as(
        std::path::Path::new(&compressed_path),
        StreamFormat::UnixCompress,
        Limits::default(),
        &cancellation,
        &mut open_budget,
    )?;
    let mut extraction_budget = WorkBudget::unlimited();
    assert_eq!(
        stream.decompress(&cancellation, &mut extraction_budget)?,
        expected
    );
    Ok(())
}

#[test]
fn optional_external_stream_fixture_matches_exact_bytes() -> Result<()> {
    let Some(compressed_path) = env::var_os("UNPACKIO_STREAM_FIXTURE") else {
        return Ok(());
    };
    let Some(expected_path) = env::var_os("UNPACKIO_STREAM_EXPECTED") else {
        return Ok(());
    };
    let Some(format) = env::var_os("UNPACKIO_STREAM_FORMAT") else {
        return Ok(());
    };
    let format = match format.to_str() {
        Some("lz4") => StreamFormat::Lz4,
        Some("zstandard") => StreamFormat::Zstandard,
        Some("unix-compress") => StreamFormat::UnixCompress,
        _ => return Ok(()),
    };
    let expected = fs::read(expected_path)?;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let stream = CompressedStream::open_path_as(
        std::path::Path::new(&compressed_path),
        format,
        Limits::default(),
        &cancellation,
        &mut open_budget,
    )?;
    let mut extraction_budget = WorkBudget::unlimited();
    assert_eq!(
        stream.decompress(&cancellation, &mut extraction_budget)?,
        expected
    );
    Ok(())
}
