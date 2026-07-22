#![forbid(unsafe_code)]
//! Opt-in Phase 5 differential and composed-archive oracle checks.

use std::{
    error::Error as StdError,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use unpackio::{Archive, CancellationToken, Limits, WorkBudget};

const PASSWORD: &str = "phase5-password";

struct OracleEntry {
    path: String,
    size: u64,
    crc: Option<u32>,
}

fn temporary_directory(label: &str) -> Result<PathBuf, Box<dyn StdError>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "unpackio-phase5-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn command_failure(label: &str, output: &std::process::Output) -> String {
    format!(
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn oracle_command() -> Command {
    match std::env::var_os("UNPACKIO_7ZZ") {
        Some(executable) => Command::new(executable),
        None => Command::new("7zz"),
    }
}

fn require_exact_7zz() -> Result<(), Box<dyn StdError>> {
    let output = oracle_command().arg("i").env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(command_failure("7zz version query", &output).into());
    }
    let listing = String::from_utf8(output.stdout)?;
    let banner = listing
        .lines()
        .find(|line| line.starts_with("7-Zip "))
        .ok_or_else(|| String::from("7zz version banner is missing"))?;
    if !banner.starts_with("7-Zip (z) 26.02 ") && !banner.starts_with("7-Zip 26.02 ") {
        return Err(
            format!("Phase 5 oracle requires exact stock 7zz 26.02, found {banner}").into(),
        );
    }
    Ok(())
}

fn oracle_metadata(
    path: &Path,
    password: Option<&str>,
) -> Result<Vec<OracleEntry>, Box<dyn StdError>> {
    let mut command = oracle_command();
    command.args(["l", "-slt"]);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(path).env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(command_failure("7zz metadata listing", &output).into());
    }
    let listing = String::from_utf8(output.stdout)?.replace("\r\n", "\n");
    let (_, records) = listing
        .split_once("\n----------\n")
        .ok_or_else(|| String::from("7zz listing has no entry section"))?;
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
    let mut command = oracle_command();
    command.args(["x", "-so", "-y"]);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(path).arg("--").arg(name).output()?;
    if !output.status.success() {
        return Err(command_failure("7zz member extraction", &output).into());
    }
    Ok(output.stdout)
}

fn open_archive(path: &Path, password: Option<&str>) -> unpackio::Result<Archive> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    match password {
        Some(password) => Archive::open_path_with_password(
            path,
            Limits::default(),
            password,
            &cancellation,
            &mut budget,
        ),
        None => Archive::open_path(path, Limits::default(), &cancellation, &mut budget),
    }
}

fn compare_to_oracle(path: &Path, password: Option<&str>) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let oracle = oracle_metadata(path, password)?;
    if archive.entries().len() != oracle.len() {
        return Err(String::from("archive entry count differs from 7zz").into());
    }
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    for (index, (entry, expected)) in archive.entries().iter().zip(&oracle).enumerate() {
        let raw_name = entry
            .raw_name()
            .ok_or_else(|| String::from("archive member has no raw name"))?;
        let name = String::from_utf16_lossy(raw_name);
        if name != expected.path {
            return Err(format!("member {index} name differs from 7zz").into());
        }
        let size = entry.size().unwrap_or(0);
        if size != expected.size {
            return Err(format!("member {index} size differs from 7zz").into());
        }
        if entry.crc32() != expected.crc {
            return Err(format!("member {index} CRC differs from 7zz").into());
        }
        if !entry.has_stream() {
            continue;
        }
        let rust = archive.extract_entry(u64::try_from(index)?, &cancellation, &mut budget)?;
        let expected_bytes = oracle_member(path, &name, password)?;
        if rust.len() != expected_bytes.len()
            || Sha256::digest(&rust) != Sha256::digest(&expected_bytes)
            || rust != expected_bytes
        {
            return Err(format!("member {index} bytes/SHA-256 differ from 7zz").into());
        }
    }
    let mut budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut budget)?;
    Ok(())
}

fn deterministic_bytes(length: usize) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    let mut state = 0x9e37_79b9_u32;
    for _ in 0..length {
        state ^= state.wrapping_shl(13);
        state ^= state >> 17;
        state ^= state.wrapping_shl(5);
        bytes.push(u8::try_from(state >> 24)?);
    }
    Ok(bytes)
}

fn ia64_bundle(relative_address: u32) -> Result<[u8; 16], Box<dyn StdError>> {
    let address = relative_address >> 4;
    let mut normalized = 5_u64 << 37;
    normalized |= u64::from(address & 0x000f_ffff) << 13;
    normalized |= u64::from(address & 0x0010_0000) << 16;
    let instruction = normalized.wrapping_shl(5) | 22;
    let mut bundle = [0_u8; 16];
    for index in 0..6_usize {
        let shift = u32::try_from(index)?
            .checked_mul(8)
            .ok_or("IA64 shift overflow")?;
        let slot = bundle
            .get_mut(index)
            .ok_or_else(|| String::from("IA64 fixture index is out of range"))?;
        *slot = u8::try_from((instruction >> shift) & 0xff)?;
    }
    Ok(bundle)
}

fn method_payload(name: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    match name {
        "deflate64" => {
            let mut bytes = deterministic_bytes(65_536)?;
            let repeated = bytes
                .get(..32_768)
                .ok_or_else(|| String::from("Deflate64 fixture prefix is missing"))?
                .to_vec();
            bytes.extend_from_slice(&repeated);
            for _ in 0..2048 {
                bytes.extend_from_slice(b"deflate64-long-match-vector\n");
            }
            Ok(bytes)
        }
        "ia64" => {
            let mut bytes = Vec::new();
            for relative in [0x1000, 0x20_000, 0xfff0_0000, 0x40] {
                bytes.extend_from_slice(&ia64_bundle(relative)?);
            }
            Ok(bytes)
        }
        "arm-thumb" => {
            let mut bytes = Vec::new();
            for _ in 0..64 {
                bytes.extend_from_slice(&[0, 0xf0, 0, 0xf8, 0x11, 0x22]);
            }
            Ok(bytes)
        }
        "riscv" => {
            let mut bytes = Vec::new();
            for _ in 0..64 {
                bytes.extend_from_slice(&[
                    0xef, 0, 0, 0, 0x97, 0, 0, 0, 0xe7, 0x80, 0, 0, 0x13, 0, 0, 0,
                ]);
            }
            Ok(bytes)
        }
        "swap2" | "swap4" => deterministic_bytes(4099),
        _ => Err(format!("unknown Phase 5 fixture {name}").into()),
    }
}

fn create_method_archive(
    directory: &Path,
    name: &str,
    method: &str,
    is_filter: bool,
    payload: &[u8],
) -> Result<PathBuf, Box<dyn StdError>> {
    let source_name = format!("{name}.bin");
    fs::write(directory.join(&source_name), payload)?;
    let archive = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command
        .current_dir(directory)
        .args(["a", "-y", "-t7z", "-mhc=off"]);
    if is_filter {
        command.arg("-m0=Copy").arg(format!("-m1={method}"));
    } else {
        command.arg(format!("-m0={method}"));
    }
    let output = command.arg(&archive).arg(&source_name).output()?;
    if !output.status.success() {
        return Err(command_failure("7zz Phase 5 fixture creation", &output).into());
    }
    Ok(archive)
}

fn assert_packed_data_was_transformed(
    path: &Path,
    payload: &[u8],
) -> Result<(), Box<dyn StdError>> {
    let archive = fs::read(path)?;
    let end = 32_usize
        .checked_add(payload.len())
        .ok_or_else(|| String::from("packed fixture range overflows"))?;
    let packed_prefix = archive
        .get(32..end.min(archive.len()))
        .ok_or_else(|| String::from("packed fixture range is missing"))?;
    let comparable = payload
        .get(..packed_prefix.len())
        .ok_or_else(|| String::from("payload comparison range is missing"))?;
    if packed_prefix == comparable {
        return Err(String::from("7zz filter did not transform the positive fixture").into());
    }
    Ok(())
}

fn assert_corruption_fails(path: &Path) -> Result<(), Box<dyn StdError>> {
    let mut bytes = fs::read(path)?;
    let offset_bytes = <[u8; 8]>::try_from(
        bytes
            .get(12..20)
            .ok_or_else(|| String::from("generated archive start header is truncated"))?,
    )?;
    let packed_length = usize::try_from(u64::from_le_bytes(offset_bytes))?;
    if packed_length == 0 {
        return Err(String::from("generated archive has no packed region").into());
    }
    let packed_middle = packed_length / 2;
    let mutation_index = 32_usize
        .checked_add(packed_middle)
        .ok_or_else(|| String::from("generated packed-data index overflows"))?;
    let packed_byte = bytes
        .get_mut(mutation_index)
        .ok_or_else(|| String::from("generated archive has no packed data byte"))?;
    *packed_byte ^= 0x5a;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let opened = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget);
    let failed = match opened {
        Ok(archive) => {
            let mut budget = WorkBudget::unlimited();
            archive.verify(&cancellation, &mut budget).is_err()
        }
        Err(_) => true,
    };
    if !failed {
        return Err(format!(
            "corrupted Phase 5 archive verified successfully: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[test]
#[ignore = "requires exact stock 7zz 26.02"]
fn generated_phase5_methods_match_7zz_and_reject_corruption() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("methods")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        for (name, method, is_filter) in [
            ("deflate64", "Deflate64", false),
            ("ia64", "IA64", true),
            ("arm-thumb", "ARMT", true),
            ("riscv", "RISCV", true),
            ("swap2", "Swap2", true),
            ("swap4", "Swap4", true),
        ] {
            let payload = method_payload(name)?;
            let archive = create_method_archive(&directory, name, method, is_filter, &payload)?;
            assert_packed_data_was_transformed(&archive, &payload)?;
            compare_to_oracle(&archive, None)?;
            assert_corruption_fails(&archive)?;
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

fn create_two_file_archive(
    directory: &Path,
    name: &str,
    solid: bool,
    encrypted: bool,
) -> Result<PathBuf, Box<dyn StdError>> {
    fs::write(directory.join("first.bin"), method_payload("deflate64")?)?;
    fs::write(directory.join("second.bin"), method_payload("riscv")?)?;
    let archive = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command
        .current_dir(directory)
        .args(["a", "-y", "-t7z", "-m0=Deflate64"])
        .arg(if solid { "-ms=on" } else { "-ms=off" });
    if encrypted {
        command.arg(format!("-p{PASSWORD}")).arg("-mhe=on");
    }
    let output = command
        .arg(&archive)
        .args(["first.bin", "second.bin"])
        .output()?;
    if !output.status.success() {
        return Err(command_failure("7zz composed archive creation", &output).into());
    }
    Ok(archive)
}

fn create_five_volume_archive(
    directory: &Path,
    name: &str,
    encrypted: bool,
) -> Result<PathBuf, Box<dyn StdError>> {
    let source_name = format!("{name}.bin");
    fs::write(directory.join(&source_name), deterministic_bytes(50_000)?)?;
    let base = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command.current_dir(directory).args([
        "a",
        "-y",
        "-t7z",
        "-mhc=off",
        "-m0=Copy",
        "-m1=Swap4",
        "-v12k",
    ]);
    if encrypted {
        command.arg(format!("-p{PASSWORD}")).arg("-mhe=on");
    }
    let output = command.arg(&base).arg(&source_name).output()?;
    if !output.status.success() {
        return Err(command_failure("7zz five-volume archive creation", &output).into());
    }
    let first = directory.join(format!("{name}.7z.001"));
    for ordinal in 1..=5 {
        let part = directory.join(format!("{name}.7z.{ordinal:03}"));
        if !part.is_file() {
            return Err(format!("expected five-volume part {}", part.display()).into());
        }
    }
    if directory.join(format!("{name}.7z.006")).exists() {
        return Err(String::from("generated archive has more than five volumes").into());
    }
    Ok(first)
}

#[test]
#[ignore = "requires exact stock 7zz 26.02"]
fn composed_solid_encrypted_and_five_volume_archives_match_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("composed")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let solid_encrypted = create_two_file_archive(&directory, "solid-encrypted", true, true)?;
        compare_to_oracle(&solid_encrypted, Some(PASSWORD))?;

        let non_solid = create_two_file_archive(&directory, "non-solid", false, false)?;
        compare_to_oracle(&non_solid, None)?;

        let volumes = create_five_volume_archive(&directory, "five-plain", false)?;
        compare_to_oracle(&volumes, None)?;

        let encrypted_volumes = create_five_volume_archive(&directory, "five-encrypted", true)?;
        compare_to_oracle(&encrypted_volumes, Some(PASSWORD))?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}
