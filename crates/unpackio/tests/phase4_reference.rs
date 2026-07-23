#![forbid(unsafe_code)]
//! Opt-in Phase 4 checks against the audited external fixture set.

use std::{
    error::Error as StdError,
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use unpackio::{
    Archive, CancellationToken, Error, ErrorKind, LimitKind, Limits, MemoryVolumeProvider,
    WorkBudget,
};

struct OracleEntry {
    path: String,
    size: u64,
    crc: Option<u32>,
}

fn oracle_metadata(
    path: &Path,
    password: Option<&str>,
) -> Result<Vec<OracleEntry>, Box<dyn StdError>> {
    let mut command = Command::new("7zz");
    command.args(["l", "-slt"]);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(path).env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(format!(
            "7zz metadata listing failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let listing = String::from_utf8(output.stdout)?.replace("\r\n", "\n");
    let (_, records) = listing
        .split_once("\n----------\n")
        .ok_or_else(|| format!("7zz listing has no entry section: {}", path.display()))?;
    let mut entries = Vec::new();
    for record in records.split("\n\n") {
        let mut member_path = None;
        let mut size = None;
        let mut crc = None;
        for line in record.lines() {
            if let Some(value) = line.strip_prefix("Path = ") {
                member_path = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("Size = ") {
                size = Some(value.parse::<u64>()?);
            } else if let Some(value) = line.strip_prefix("CRC = ") {
                crc = Some(u32::from_str_radix(value, 16)?);
            }
        }
        if let Some(path) = member_path {
            entries.push(OracleEntry {
                path,
                size: size.ok_or_else(|| String::from("7zz entry has no size"))?,
                crc,
            });
        }
    }
    Ok(entries)
}

fn oracle_member(
    path: &Path,
    name: &str,
    password: Option<&str>,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut command = Command::new("7zz");
    command.args(["x", "-so", "-y"]);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(path).arg("--").arg(name).output()?;
    if !output.status.success() {
        return Err(format!(
            "7zz extraction failed for {}:{name}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn compare_to_7zz(
    root: &Path,
    name: &str,
    password: Option<&str>,
) -> Result<(), Box<dyn StdError>> {
    let path = root.join(name);
    let archive = open_fixture(&path, password)?;
    let oracle = oracle_metadata(&path, password)?;
    if archive.entries().len() != oracle.len() {
        return Err(format!("{name}: entry-count mismatch").into());
    }
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    for (index, (entry, expected)) in archive.entries().iter().zip(&oracle).enumerate() {
        let raw_name = entry
            .raw_name()
            .ok_or_else(|| format!("{name}: member {index} has no name"))?;
        let member_name = String::from_utf16_lossy(raw_name);
        if member_name != expected.path {
            return Err(format!("{name}: path mismatch at member {index}").into());
        }
        let declared_size = entry.size().unwrap_or(0);
        if declared_size != expected.size {
            return Err(format!("{name}:{member_name}: size metadata mismatch").into());
        }
        let declared_crc = entry.crc32();
        if declared_crc != expected.crc {
            return Err(format!("{name}:{member_name}: CRC metadata mismatch").into());
        }
        if !entry.has_stream() {
            continue;
        }
        let rust = archive.extract_entry(u64::try_from(index)?, &cancellation, &mut budget)?;
        let expected_bytes = oracle_member(&path, &member_name, password)?;
        if rust.len() != expected_bytes.len()
            || Sha256::digest(&rust) != Sha256::digest(&expected_bytes)
            || rust != expected_bytes
        {
            return Err(format!("{name}:{member_name}: byte/SHA-256 mismatch").into());
        }
    }
    verify_archive(&archive)?;
    Ok(())
}

fn compare_private_fixture(
    root: &Path,
    baseline_name: &str,
    private_name: &str,
) -> Result<(), Box<dyn StdError>> {
    let baseline = open_fixture(&root.join(baseline_name), None)?;
    let private = open_fixture(&root.join(private_name), None)?;
    if baseline.entries().len() != private.entries().len() {
        return Err(format!("{private_name}: entry count differs from {baseline_name}").into());
    }
    for (index, (expected, actual)) in baseline.entries().iter().zip(private.entries()).enumerate()
    {
        if expected.raw_name() != actual.raw_name()
            || expected.has_stream() != actual.has_stream()
            || expected.is_empty_file() != actual.is_empty_file()
            || expected.is_anti_item() != actual.is_anti_item()
            || expected.size() != actual.size()
            || expected.crc32() != actual.crc32()
        {
            return Err(format!(
                "{private_name}: core metadata differs from {baseline_name} at member {index}"
            )
            .into());
        }
    }
    let cancellation = CancellationToken::new();
    let mut baseline_budget = WorkBudget::unlimited();
    let mut private_budget = WorkBudget::unlimited();
    for index in 0..baseline.entries().len() {
        let index = u64::try_from(index)?;
        let expected = baseline.extract_entry(index, &cancellation, &mut baseline_budget)?;
        let actual = private.extract_entry(index, &cancellation, &mut private_budget)?;
        if Sha256::digest(&expected) != Sha256::digest(&actual) || expected != actual {
            return Err(format!("{private_name}: output mismatch at member {index}").into());
        }
    }
    verify_archive(&private)?;
    Ok(())
}

fn open_fixture(path: &Path, password: Option<&str>) -> unpackio::Result<Archive> {
    let bytes = fs::read(path).map_err(unpackio::Error::Io)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    match password {
        Some(password) => Archive::open_bytes_with_password(
            bytes,
            Limits::default(),
            password,
            &cancellation,
            &mut budget,
        ),
        None => Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
    }
}

fn verify_fixture(path: &Path, password: Option<&str>) -> unpackio::Result<()> {
    let archive = open_fixture(path, password)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut budget)
}

fn verify_archive(archive: &Archive) -> unpackio::Result<()> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut budget)
}

fn split_into_five(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let chunk_size = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_div(5))
        .ok_or_else(|| String::from("five-part split size overflows"))?;
    if chunk_size == 0 {
        return Err(String::from(
            "fixture is too small to split into five parts",
        ));
    }
    let parts: Vec<Vec<u8>> = bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect();
    if parts.len() != 5 {
        return Err(format!("expected five parts, got {}", parts.len()));
    }
    Ok(parts)
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA"]
fn phase4_codec_and_encryption_fixtures_verify() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);
    for name in [
        "deflate.7z",
        "bzip2.7z",
        "ppmd.7z",
        "brotli.7z",
        "lz4.7z",
        "zstd.7z",
    ] {
        verify_fixture(&root.join(name), None)
            .map_err(|error| format!("{name} failed verification: {error}"))?;
    }
    for (name, password) in [
        ("aes7z.7z", "password"),
        ("t2.7z", "password"),
        ("t3.7z", "password"),
        ("t4.7z", "password"),
        ("t5.7z", "password"),
        ("7zcracker.7z", "876"),
    ] {
        verify_fixture(&root.join(name), Some(password))
            .map_err(|error| format!("{name} failed encrypted verification: {error}"))?;
    }
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA and 7zz"]
fn standard_phase4_methods_match_7zz_bytes_and_metadata() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);
    for name in ["deflate.7z", "bzip2.7z", "ppmd.7z"] {
        compare_to_7zz(root, name, None)
            .map_err(|error| format!("differential check failed for {name}: {error}"))?;
    }
    for name in ["aes7z.7z", "t2.7z", "t4.7z"] {
        compare_to_7zz(root, name, Some("password"))
            .map_err(|error| format!("encrypted differential check failed for {name}: {error}"))?;
    }
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA; private methods use deflate oracle data"]
fn private_phase4_methods_match_oracle_baseline() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);
    compare_to_7zz(root, "deflate.7z", None)?;
    for name in ["brotli.7z", "lz4.7z", "zstd.7z"] {
        compare_private_fixture(root, "deflate.7z", name)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA and 7zz"]
fn generated_encrypted_bcj_chain_matches_7zz() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let source = Path::new(&root).join("sfx.exe");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "unpackio-encrypted-bcj-oracle-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let output = Command::new("7zz")
            .current_dir(&directory)
            .args([
                "a",
                "oracle.7z",
                "-ppassword",
                "-mhe=on",
                "-m0=BCJ",
                "-m1=LZMA2",
            ])
            .arg(&source)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "7zz encrypted BCJ fixture creation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        compare_to_7zz(&directory, "oracle.7z", Some("password"))
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA"]
fn encrypted_fixtures_distinguish_password_states() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);
    let required = open_fixture(&root.join("t2.7z"), None);
    assert_eq!(
        required.as_ref().err().map(unpackio::Error::kind),
        Some(ErrorKind::PasswordRequired)
    );
    let wrong_header = open_fixture(&root.join("t2.7z"), Some("notpassword"));
    assert_eq!(
        wrong_header.as_ref().err().map(unpackio::Error::kind),
        Some(ErrorKind::WrongPasswordOrCorrupt)
    );
    let wrong_data = verify_fixture(&root.join("t4.7z"), Some("notpassword"));
    assert_eq!(
        wrong_data.as_ref().err().map(unpackio::Error::kind),
        Some(ErrorKind::WrongPasswordOrCorrupt)
    );
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA"]
fn sequential_and_encrypted_memory_volumes_verify() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive = Archive::open_path(
        &root.join("multi.7z.001"),
        Limits::default(),
        &cancellation,
        &mut budget,
    )?;
    verify_archive(&archive)?;

    let unencrypted = fs::read(root.join("deflate.7z"))?;
    let mut provider = MemoryVolumeProvider::new(split_into_five(&unencrypted)?);
    let mut budget = WorkBudget::unlimited();
    let archive = Archive::open_volumes(
        &mut provider,
        "unencrypted.7z.001",
        Limits::default(),
        &cancellation,
        &mut budget,
    )?;
    verify_archive(&archive)?;

    let encrypted = fs::read(root.join("aes7z.7z"))?;
    let mut provider = MemoryVolumeProvider::new(split_into_five(&encrypted)?);
    let mut budget = WorkBudget::unlimited();
    let archive = Archive::open_volumes_with_password(
        &mut provider,
        "encrypted.7z.001",
        Limits::default(),
        "password",
        &cancellation,
        &mut budget,
    )?;
    verify_archive(&archive)?;
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA"]
fn missing_and_limited_volumes_are_typed() -> Result<(), Box<dyn StdError>> {
    let root = std::env::var_os("UNPACKIO_7Z_TESTDATA")
        .ok_or_else(|| String::from("UNPACKIO_7Z_TESTDATA is not set"))?;
    let root = Path::new(&root);
    let mut first_five = Vec::new();
    for ordinal in 1..=5 {
        first_five.push(fs::read(root.join(format!("multi.7z.{ordinal:03}")))?);
    }
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let mut provider = MemoryVolumeProvider::new(first_five.clone());
    let missing = Archive::open_volumes(
        &mut provider,
        "multi.7z.001",
        Limits::default(),
        &cancellation,
        &mut budget,
    );
    assert!(matches!(
        missing,
        Err(Error::MissingVolume { expected }) if expected == "multi.7z.006"
    ));

    let mut provider = MemoryVolumeProvider::new(first_five);
    let limits = Limits::builder().max_volumes(4).build();
    let mut budget = WorkBudget::unlimited();
    let limited = Archive::open_volumes(
        &mut provider,
        "multi.7z.001",
        limits,
        &cancellation,
        &mut budget,
    );
    assert!(matches!(
        limited,
        Err(Error::LimitExceeded {
            limit: LimitKind::Volumes,
            requested: 5,
            maximum: 4,
        })
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "requires 7zz and symlink support"]
fn generated_symlink_metadata_and_target_match_oracle() -> Result<(), Box<dyn StdError>> {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "unpackio-symlink-oracle-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        fs::write(directory.join("target.txt"), b"symlink target\n")?;
        symlink("target.txt", directory.join("link"))?;
        let output = Command::new("7zz")
            .current_dir(&directory)
            .args(["a", "-snl", "oracle.7z", "link", "target.txt"])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "7zz symlink fixture creation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_path(
            &directory.join("oracle.7z"),
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let (index, link) = archive
            .entries()
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.raw_name()
                    == Some(
                        &[
                            u16::from(b'l'),
                            u16::from(b'i'),
                            u16::from(b'n'),
                            u16::from(b'k'),
                        ][..],
                    )
            })
            .ok_or_else(|| String::from("generated symlink entry is missing"))?;
        if !link.is_symlink() {
            return Err(String::from("Unix extension mode did not identify the symlink").into());
        }
        let filesystem_mode = fs::symlink_metadata(directory.join("link"))?
            .permissions()
            .mode();
        let archive_mode = link
            .unix_mode()
            .ok_or_else(|| String::from("archive symlink has no Unix mode"))?;
        if archive_mode & 0o7777 != filesystem_mode & 0o7777 {
            return Err(format!(
                "symlink permission mismatch: archive {archive_mode:o}, filesystem {filesystem_mode:o}"
            )
            .into());
        }
        let mut budget = WorkBudget::unlimited();
        let target = archive.extract_entry(u64::try_from(index)?, &cancellation, &mut budget)?;
        if target != b"target.txt" {
            return Err(format!("unexpected stored symlink target: {target:?}").into());
        }
        verify_archive(&archive)?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}
