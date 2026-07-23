#![forbid(unsafe_code)]
//! Opt-in decoder differential checks against an audited 7z corpus and oracle.

use std::{error::Error as StdError, fs, path::Path, process::Command};

use sha2::{Digest, Sha256};
use unpackio::{Archive, CancellationToken, Limits, WorkBudget};

struct OracleEntry {
    path: String,
    size: u64,
    crc: Option<u32>,
}

fn oracle_metadata(path: &Path) -> Result<Vec<OracleEntry>, Box<dyn StdError>> {
    let output = Command::new("7zz")
        .arg("l")
        .arg("-slt")
        .arg(path)
        .env("LC_ALL", "C")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "7zz metadata listing failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let listing = String::from_utf8(output.stdout)?.replace("\r\n", "\n");
    let (_, records) = listing.split_once("\n----------\n").ok_or_else(|| {
        format!(
            "7zz metadata listing has no entry section: {}",
            path.display()
        )
    })?;
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
        if let Some(member_path) = member_path {
            entries.push(OracleEntry {
                path: member_path,
                size: size.ok_or_else(|| {
                    format!("7zz metadata entry has no size in {}", path.display())
                })?,
                crc,
            });
        }
    }
    if entries.is_empty() {
        return Err(format!("7zz metadata listing has no entries: {}", path.display()).into());
    }
    Ok(entries)
}

fn oracle_member(path: &Path, name: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    let output = Command::new("7zz")
        .arg("x")
        .arg("-so")
        .arg("-y")
        .arg(path)
        .arg(name)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "7zz failed for {}:{name}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn compare_archive(root: &Path, filename: &str) -> Result<(), Box<dyn StdError>> {
    let path = root.join(filename);
    let bytes = fs::read(&path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
    let metadata = oracle_metadata(&path)?;
    if archive.entries().len() != metadata.len() {
        return Err(format!(
            "entry-count mismatch for {filename}: Rust {}, oracle {}",
            archive.entries().len(),
            metadata.len()
        )
        .into());
    }
    for (index, entry) in archive.entries().iter().enumerate() {
        let raw_name = entry
            .raw_name()
            .ok_or_else(|| format!("{filename}: member {index} has no inline name"))?;
        let name = String::from_utf16_lossy(raw_name);
        let oracle_metadata = metadata
            .get(index)
            .ok_or_else(|| format!("{filename}: oracle member {index} is missing"))?;
        if name != oracle_metadata.path {
            return Err(format!(
                "path mismatch for {filename} member {index}: Rust {name:?}, oracle {:?}",
                oracle_metadata.path
            )
            .into());
        }
        let declared_size = entry.size().unwrap_or(0);
        if declared_size != oracle_metadata.size {
            return Err(format!(
                "metadata size mismatch for {filename}:{name}: Rust {declared_size}, oracle {}",
                oracle_metadata.size
            )
            .into());
        }
        let declared_crc = entry.crc32();
        if declared_crc != oracle_metadata.crc {
            return Err(format!(
                "metadata CRC mismatch for {filename}:{name}: Rust {declared_crc:08x?}, oracle {:08x?}",
                oracle_metadata.crc
            )
            .into());
        }
        if !entry.has_stream() {
            continue;
        }
        let index = u64::try_from(index)?;
        let mut reader = archive.open_member(index, &cancellation, &mut budget)?;
        let capacity = usize::try_from(reader.size()?)?;
        let mut rust = Vec::with_capacity(capacity);
        let mut chunk = [0_u8; 8192];
        loop {
            let count = reader.read_chunk(&mut chunk)?;
            if count == 0 {
                break;
            }
            let bytes = chunk
                .get(..count)
                .ok_or_else(|| format!("{filename}: member read exceeded its buffer"))?;
            rust.extend_from_slice(bytes);
        }
        let oracle = oracle_member(&path, &name)?;
        if u64::try_from(rust.len())? != declared_size
            || u64::try_from(oracle.len())? != declared_size
        {
            return Err(format!(
                "size mismatch for {filename}:{name}: declared {declared_size}, Rust {}, oracle {}",
                rust.len(),
                oracle.len()
            )
            .into());
        }
        let rust_sha256 = Sha256::digest(&rust);
        let oracle_sha256 = Sha256::digest(&oracle);
        if rust_sha256 != oracle_sha256 {
            return Err(format!("SHA-256 mismatch for {filename}:{name}").into());
        }
        if rust != oracle {
            let first_difference = rust
                .iter()
                .zip(&oracle)
                .position(|(left, right)| left != right);
            let context = first_difference.and_then(|offset| {
                let start = offset.saturating_sub(8);
                let end = offset.checked_add(16)?.min(rust.len()).min(oracle.len());
                Some((rust.get(start..end)?, oracle.get(start..end)?))
            });
            return Err(format!(
                "byte mismatch for {filename}:{name}: Rust length {}, oracle length {}, first difference {first_difference:?}, context {context:02x?}",
                rust.len(),
                oracle.len()
            )
            .into());
        }
        reader.finish()?;
    }
    archive.verify(&cancellation, &mut budget)?;
    Ok(())
}

#[test]
#[ignore = "requires UNPACKIO_7Z_TESTDATA and 7zz"]
fn core_methods_match_7zz_bytes() -> Result<(), Box<dyn StdError>> {
    let Some(root) = std::env::var_os("UNPACKIO_7Z_TESTDATA") else {
        return Err(String::from("UNPACKIO_7Z_TESTDATA is not set").into());
    };
    let root = Path::new(&root);
    for filename in [
        "copy.7z", "lzma.7z", "lzma2.7z", "delta.7z", "bcj.7z", "bcj2.7z", "ppc.7z", "arm.7z",
        "arm64.7z", "sparc.7z", "sfx.exe",
    ] {
        compare_archive(root, filename)
            .map_err(|error| format!("differential check failed for {filename}: {error}"))?;
    }
    Ok(())
}
