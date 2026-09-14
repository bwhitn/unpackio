#![forbid(unsafe_code)]
//! Corpus-free differential checks using a locally installed `7zz` test oracle.

use std::{
    error::Error as StdError,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};
use unpackio::{
    Archive, CancellationToken, ErrorKind, Limits, WorkBudget, ZipArchive, ZipCompressionMethod,
};

const PASSWORD: &str = "generated-oracle-password";

#[cfg(feature = "unstable-internals")]
const KIB: usize = 1024;
#[cfg(feature = "unstable-internals")]
const MIB: usize = 1024 * KIB;

#[cfg(feature = "unstable-internals")]
const METHOD_COPY: &[u8] = &[0x00];
#[cfg(feature = "unstable-internals")]
const METHOD_DELTA: &[u8] = &[0x03];
#[cfg(feature = "unstable-internals")]
const METHOD_LZMA2: &[u8] = &[0x21];
#[cfg(feature = "unstable-internals")]
const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
#[cfg(feature = "unstable-internals")]
const METHOD_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
#[cfg(feature = "unstable-internals")]
const METHOD_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
#[cfg(feature = "unstable-internals")]
const METHOD_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
#[cfg(feature = "unstable-internals")]
const METHOD_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
#[cfg(feature = "unstable-internals")]
const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
#[cfg(feature = "unstable-internals")]
const METHOD_7Z_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];

struct OracleEntry {
    path: String,
    size: u64,
    crc: Option<u32>,
    method: Option<String>,
}

#[cfg(feature = "unstable-internals")]
struct CoderExpectation {
    method_id: &'static [u8],
    properties: Option<&'static [u8]>,
}

#[cfg(feature = "unstable-internals")]
struct MethodExpectation {
    name: &'static str,
    exact_token: Option<&'static str>,
}

#[cfg(feature = "unstable-internals")]
struct MatrixCase {
    label: &'static str,
    payload_kind: &'static str,
    payload_length: usize,
    switches: &'static [&'static str],
    password: Option<&'static str>,
    methods: &'static [MethodExpectation],
    coders: &'static [CoderExpectation],
    dictionary_bytes: u64,
}

#[cfg(feature = "unstable-internals")]
struct GeneratedMember {
    name: String,
    bytes: Vec<u8>,
}

fn temporary_directory(label: &str) -> Result<PathBuf, Box<dyn StdError>> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ordinal = COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "unpackio-generated-oracle-{label}-{}-{ordinal}",
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

fn oracle_banner(listing: &str) -> Option<&str> {
    listing.lines().find(|line| line.starts_with("7-Zip "))
}

fn require_exact_7zz() -> Result<(), Box<dyn StdError>> {
    let output = oracle_command().arg("i").env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(command_failure("7zz version query", &output).into());
    }
    let version = String::from_utf8(output.stdout)?;
    let banner =
        oracle_banner(&version).ok_or_else(|| String::from("7zz version banner is missing"))?;
    if !banner.starts_with("7-Zip (z) 26.02 ") && !banner.starts_with("7-Zip 26.02 ") {
        return Err(
            format!("generated oracle requires exact stock 7zz 26.02, found {banner}").into(),
        );
    }
    Ok(())
}

#[test]
fn exact_oracle_banner_accepts_standalone_and_windows_forms() {
    assert_eq!(
        oracle_banner("\n7-Zip (z) 26.02 (x64) : Copyright\n"),
        Some("7-Zip (z) 26.02 (x64) : Copyright")
    );
    assert_eq!(
        oracle_banner("\r\n7-Zip 26.02 (x64) : Copyright\r\n"),
        Some("7-Zip 26.02 (x64) : Copyright")
    );
}

#[cfg(feature = "unstable-internals")]
fn oracle_summary_field(
    path: &Path,
    password: Option<&str>,
    field: &str,
) -> Result<String, Box<dyn StdError>> {
    let mut command = oracle_command();
    command.args(["l", "-slt"]);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(path).env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(command_failure("7zz summary listing", &output).into());
    }
    let listing = String::from_utf8(output.stdout)?.replace("\r\n", "\n");
    let (summary, _) = listing
        .split_once("\n----------\n")
        .ok_or_else(|| String::from("7zz listing has no entry section"))?;
    let prefix = format!("{field} = ");
    summary
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| format!("7zz summary has no {field} field").into())
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
        let mut method = None;
        for line in record.lines() {
            if let Some(value) = line.strip_prefix("Path = ") {
                member_path = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("Size = ") {
                size = Some(value.parse::<u64>()?);
            } else if let Some(value) = line.strip_prefix("CRC = ") {
                if !value.is_empty() {
                    crc = Some(u32::from_str_radix(value, 16)?);
                }
            } else if let Some(value) = line.strip_prefix("Method = ") {
                method = Some(value.to_owned());
            }
        }
        if let Some(path) = member_path {
            entries.push(OracleEntry {
                path,
                size: size.ok_or_else(|| String::from("7zz entry has no size"))?,
                crc,
                method,
            });
        }
    }
    Ok(entries)
}

#[cfg(feature = "unstable-internals")]
fn assert_oracle_methods(
    path: &Path,
    password: Option<&str>,
    expected: &[MethodExpectation],
) -> Result<(), Box<dyn StdError>> {
    let entries = oracle_metadata(path, password)?;
    let entry = entries
        .first()
        .ok_or_else(|| String::from("7zz property-matrix entry is missing"))?;
    if entries.len() != 1 {
        return Err(String::from("property-matrix method check requires one entry").into());
    }
    let method = entry
        .method
        .as_deref()
        .ok_or_else(|| String::from("7zz property-matrix method is missing"))?;
    for expectation in expected {
        let found = method.split_whitespace().any(|token| {
            expectation.exact_token.map_or_else(
                || {
                    token == expectation.name
                        || token
                            .strip_prefix(expectation.name)
                            .is_some_and(|suffix| suffix.starts_with(':'))
                },
                |exact| token == exact,
            )
        });
        if !found {
            return Err(format!(
                "7zz method {method:?} did not contain the expected {} configuration",
                expectation.name
            )
            .into());
        }
    }
    Ok(())
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

fn compare_to_oracle(
    path: &Path,
    password: Option<&str>,
    expected_method: &str,
    expected_bytes: &[u8],
) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let oracle = oracle_metadata(path, password)?;
    if archive.entries().len() != oracle.len() || oracle.len() != 1 {
        return Err(String::from("generated archive does not contain exactly one entry").into());
    }
    let expected = oracle
        .first()
        .ok_or_else(|| String::from("7zz generated-entry metadata is missing"))?;
    let method = expected
        .method
        .as_deref()
        .ok_or_else(|| String::from("7zz generated-entry method is missing"))?;
    if !method.split_whitespace().any(|item| {
        item == expected_method
            || item
                .strip_prefix(expected_method)
                .is_some_and(|suffix| suffix.starts_with(':'))
    }) {
        return Err(format!(
            "7zz did not use requested method {expected_method}: reported {method}"
        )
        .into());
    }

    let entry = archive
        .entries()
        .first()
        .ok_or_else(|| String::from("Rust generated-entry metadata is missing"))?;
    let raw_name = entry
        .raw_name()
        .ok_or_else(|| String::from("generated archive member has no raw name"))?;
    let name = String::from_utf16_lossy(raw_name);
    if name != expected.path {
        return Err(String::from("generated member name differs from 7zz").into());
    }
    if entry.size() != Some(expected.size) {
        return Err(String::from("generated member size differs from 7zz").into());
    }
    if entry.crc32() != expected.crc {
        return Err(String::from("generated member CRC differs from 7zz").into());
    }

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let rust = archive.extract_entry(0, &cancellation, &mut budget)?;
    let oracle = oracle_member(path, &name, password)?;
    if rust.len() != oracle.len()
        || Sha256::digest(&rust) != Sha256::digest(&oracle)
        || rust != oracle
        || rust != expected_bytes
    {
        return Err(
            String::from("generated member bytes/SHA-256 differ from 7zz or source").into(),
        );
    }
    let mut budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut budget)?;
    Ok(())
}

fn repeated_pattern(pattern: &[u8], count: usize) -> Result<Vec<u8>, Box<dyn StdError>> {
    let capacity = pattern
        .len()
        .checked_mul(count)
        .ok_or_else(|| String::from("generated payload size overflows"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    for _ in 0..count {
        bytes.extend_from_slice(pattern);
    }
    Ok(bytes)
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

fn method_payload(name: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    match name {
        "bcj" | "bcj2" => repeated_pattern(
            &[
                0xe8, 0, 0, 0, 0, 0x90, 0xe9, 0, 0, 0, 0, 0x0f, 0x85, 0, 0, 0, 0,
            ],
            2048,
        ),
        "ppc" => repeated_pattern(&[0x48, 0, 0, 1, 0x60, 0, 0, 0], 4096),
        "arm" => repeated_pattern(&[0, 0, 0, 0xeb, 0, 0, 0, 0xea], 4096),
        "arm64" => repeated_pattern(&[0, 0, 0, 0x94, 0, 0, 0, 0x90], 4096),
        "sparc" => repeated_pattern(&[0x40, 0, 0, 0, 0x01, 0, 0, 0], 4096),
        "ppmd" => repeated_pattern(
            b"PPMd context modelling fixture: alpha beta gamma delta 0123456789\n",
            4096,
        ),
        _ => {
            let mut bytes = deterministic_bytes(32 * 1024)?;
            bytes.extend_from_slice(&repeated_pattern(
                b"unpackio generated differential fixture\n",
                2048,
            )?);
            Ok(bytes)
        }
    }
}

#[cfg(feature = "unstable-internals")]
fn sized_method_payload(name: &str, length: usize) -> Result<Vec<u8>, Box<dyn StdError>> {
    let seed = method_payload(name)?;
    if seed.is_empty() {
        return Err(String::from("property-matrix payload seed is empty").into());
    }
    let mut payload = Vec::new();
    payload.try_reserve_exact(length)?;
    while payload.len() < length {
        let remaining = length
            .checked_sub(payload.len())
            .ok_or_else(|| String::from("property-matrix payload length underflows"))?;
        let count = remaining.min(seed.len());
        let chunk = seed
            .get(..count)
            .ok_or_else(|| String::from("property-matrix payload seed range is missing"))?;
        payload.extend_from_slice(chunk);
    }
    Ok(payload)
}

fn create_archive(
    directory: &Path,
    name: &str,
    switches: &[&str],
    password: Option<&str>,
    payload: &[u8],
) -> Result<PathBuf, Box<dyn StdError>> {
    let source_name = format!("{name}.bin");
    fs::write(directory.join(&source_name), payload)?;
    let archive = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command
        .current_dir(directory)
        .args(["a", "-y", "-t7z", "-mhc=off"])
        .args(switches);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(&archive).arg(&source_name).output()?;
    if !output.status.success() {
        return Err(command_failure("7zz fixture creation", &output).into());
    }
    Ok(archive)
}

#[cfg(feature = "unstable-internals")]
fn create_archive_from_sources(
    directory: &Path,
    name: &str,
    switches: &[&str],
    password: Option<&str>,
    source_names: &[&str],
) -> Result<PathBuf, Box<dyn StdError>> {
    let archive = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command
        .current_dir(directory)
        .args(["a", "-y", "-t7z", "-mhc=off"])
        .args(switches);
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let output = command.arg(&archive).args(source_names).output()?;
    if !output.status.success() {
        return Err(command_failure("7zz multi-file fixture creation", &output).into());
    }
    Ok(archive)
}

#[cfg(feature = "unstable-internals")]
fn assert_main_coders(
    archive: &Archive,
    expected: &[CoderExpectation],
    dictionary_bytes: u64,
) -> Result<(), Box<dyn StdError>> {
    let streams = archive
        .header()
        .main_streams()
        .ok_or_else(|| String::from("property-matrix archive has no main streams"))?;
    let folder = streams
        .folders()
        .first()
        .ok_or_else(|| String::from("property-matrix archive has no folder"))?;
    if streams.folders().len() != 1 || folder.coders().len() != expected.len() {
        return Err(format!(
            "property-matrix coder count differs: expected {}, found {} in {} folders",
            expected.len(),
            folder.coders().len(),
            streams.folders().len()
        )
        .into());
    }
    for expectation in expected {
        let coder = folder
            .coders()
            .iter()
            .find(|coder| coder.method_id() == expectation.method_id)
            .ok_or_else(|| {
                format!(
                    "property-matrix coder method {:02x?} is missing",
                    expectation.method_id
                )
            })?;
        if expectation
            .properties
            .is_some_and(|properties| coder.properties() != properties)
        {
            return Err(format!(
                "property-matrix coder {:02x?} properties differ: expected {:02x?}, found {:02x?}",
                expectation.method_id,
                expectation.properties,
                coder.properties()
            )
            .into());
        }
    }
    if folder.dictionary_bytes() != dictionary_bytes {
        return Err(format!(
            "property-matrix dictionary charge differs: expected {dictionary_bytes}, found {}",
            folder.dictionary_bytes()
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn first_packed_stream(path: &Path, password: Option<&str>) -> Result<Vec<u8>, Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let stream = archive
        .header()
        .main_streams()
        .and_then(|streams| streams.pack_streams().first())
        .ok_or_else(|| String::from("property-matrix packed stream is missing"))?;
    let size = stream
        .size()
        .ok_or_else(|| String::from("generated property-matrix packed size is unknown"))?;
    let start = usize::try_from(stream.offset())?;
    let length = usize::try_from(size)?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| String::from("property-matrix packed range overflows"))?;
    let bytes = fs::read(path)?;
    let packed = bytes
        .get(start..end)
        .ok_or_else(|| String::from("property-matrix packed range is missing"))?;
    Ok(Vec::from(packed))
}

#[cfg(feature = "unstable-internals")]
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb_88320
            };
        }
    }
    !crc
}

#[cfg(feature = "unstable-internals")]
fn push_7z_uint(bytes: &mut Vec<u8>, value: u64) -> Result<(), Box<dyn StdError>> {
    const PREFIXES: &[u8] = &[0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe];
    let little_endian = value.to_le_bytes();
    for extra_bytes in 0..8_usize {
        let bit_count = extra_bytes
            .checked_add(1)
            .and_then(|count| count.checked_mul(7))
            .ok_or_else(|| String::from("matrix integer bit count overflows"))?;
        let limit = 1_u64
            .checked_shl(u32::try_from(bit_count)?)
            .ok_or_else(|| String::from("matrix integer limit shift overflows"))?;
        if value >= limit {
            continue;
        }
        let shift = extra_bytes
            .checked_mul(8)
            .ok_or_else(|| String::from("matrix integer shift overflows"))?;
        let high = u8::try_from(value >> u32::try_from(shift)?)?;
        let prefix = PREFIXES
            .get(extra_bytes)
            .copied()
            .ok_or_else(|| String::from("matrix integer prefix is missing"))?;
        bytes.push(prefix | high);
        bytes.extend_from_slice(
            little_endian
                .get(..extra_bytes)
                .ok_or_else(|| String::from("matrix integer suffix is missing"))?,
        );
        return Ok(());
    }
    bytes.push(u8::MAX);
    bytes.extend_from_slice(&little_endian);
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn read_u64_le(bytes: &[u8], start: usize) -> Result<u64, Box<dyn StdError>> {
    let end = start
        .checked_add(8)
        .ok_or_else(|| String::from("matrix u64 range overflows"))?;
    Ok(u64::from_le_bytes(<[u8; 8]>::try_from(
        bytes
            .get(start..end)
            .ok_or_else(|| String::from("matrix u64 range is missing"))?,
    )?))
}

#[cfg(feature = "unstable-internals")]
fn stored_next_header_range(bytes: &[u8]) -> Result<(usize, usize), Box<dyn StdError>> {
    let next_offset = read_u64_le(bytes, 12)?;
    let next_size = read_u64_le(bytes, 20)?;
    let start = 32_u64
        .checked_add(next_offset)
        .ok_or_else(|| String::from("matrix next-header offset overflows"))?;
    let end = start
        .checked_add(next_size)
        .ok_or_else(|| String::from("matrix next-header end overflows"))?;
    let start = usize::try_from(start)?;
    let end = usize::try_from(end)?;
    bytes
        .get(start..end)
        .ok_or_else(|| String::from("matrix next-header range is missing"))?;
    Ok((start, end))
}

#[cfg(feature = "unstable-internals")]
fn write_u32_le(bytes: &mut [u8], start: usize, value: u32) -> Result<(), Box<dyn StdError>> {
    let end = start
        .checked_add(4)
        .ok_or_else(|| String::from("matrix u32 range overflows"))?;
    bytes
        .get_mut(start..end)
        .ok_or_else(|| String::from("matrix u32 range is missing"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn refresh_header_crcs(bytes: &mut [u8]) -> Result<(), Box<dyn StdError>> {
    let (next_start, next_end) = stored_next_header_range(bytes)?;
    let next_crc = crc32(
        bytes
            .get(next_start..next_end)
            .ok_or_else(|| String::from("matrix next-header CRC range is missing"))?,
    );
    write_u32_le(bytes, 28, next_crc)?;
    let start_crc = crc32(
        bytes
            .get(12..32)
            .ok_or_else(|| String::from("matrix start-header CRC range is missing"))?,
    );
    write_u32_le(bytes, 8, start_crc)
}

#[cfg(feature = "unstable-internals")]
fn open_generated_bytes(
    bytes: Vec<u8>,
    password: Option<&str>,
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> unpackio::Result<Archive> {
    match password {
        Some(password) => {
            Archive::open_bytes_with_password(bytes, limits, password, cancellation, budget)
        }
        None => Archive::open_bytes(bytes, limits, cancellation, budget),
    }
}

#[cfg(feature = "unstable-internals")]
fn expect_error_kind<T>(
    result: unpackio::Result<T>,
    expected: ErrorKind,
    label: &str,
) -> Result<(), Box<dyn StdError>> {
    match result {
        Err(error) if error.kind() == expected => Ok(()),
        Err(error) => Err(format!(
            "{label} returned {:?} instead of {expected:?}: {error}",
            error.kind()
        )
        .into()),
        Ok(_) => Err(format!("{label} unexpectedly succeeded").into()),
    }
}

#[cfg(feature = "unstable-internals")]
fn expect_failure<T>(result: unpackio::Result<T>, label: &str) -> Result<(), Box<dyn StdError>> {
    if result.is_ok() {
        return Err(format!("{label} unexpectedly succeeded").into());
    }
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn assert_strategic_truncations(
    path: &Path,
    password: Option<&str>,
) -> Result<(), Box<dyn StdError>> {
    let bytes = fs::read(path)?;
    let (next_start, _) = stored_next_header_range(&bytes)?;
    let final_prefix = bytes
        .len()
        .checked_sub(1)
        .ok_or_else(|| String::from("matrix archive is empty"))?;
    let mut cuts = Vec::from([31_usize, next_start, final_prefix]);
    cuts.sort_unstable();
    cuts.dedup();
    for cut in cuts {
        let truncated = Vec::from(
            bytes
                .get(..cut)
                .ok_or_else(|| String::from("matrix truncation range is missing"))?,
        );
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        expect_failure(
            open_generated_bytes(
                truncated,
                password,
                Limits::default(),
                &cancellation,
                &mut budget,
            ),
            "matrix physical truncation",
        )?;
    }
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn assert_operation_controls(path: &Path, password: Option<&str>) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut budget = WorkBudget::unlimited();
    expect_error_kind(
        archive.verify(&cancelled, &mut budget),
        ErrorKind::Cancelled,
        "matrix cancelled verification",
    )?;

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(0);
    expect_error_kind(
        archive.verify(&cancellation, &mut budget),
        ErrorKind::LimitExceeded,
        "matrix zero-work verification",
    )
}

#[cfg(feature = "unstable-internals")]
fn assert_output_limit(
    path: &Path,
    password: Option<&str>,
    maximum_entry: u64,
) -> Result<(), Box<dyn StdError>> {
    let bytes = fs::read(path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive = open_generated_bytes(
        bytes,
        password,
        Limits::builder()
            .max_entry_output_bytes(maximum_entry)
            .build(),
        &cancellation,
        &mut budget,
    )?;
    expect_error_kind(
        archive.verify(&cancellation, &mut budget),
        ErrorKind::LimitExceeded,
        "matrix entry-output limit",
    )
}

#[cfg(feature = "unstable-internals")]
fn assert_dictionary_limit(
    path: &Path,
    password: Option<&str>,
    dictionary_bytes: u64,
) -> Result<(), Box<dyn StdError>> {
    let maximum = dictionary_bytes
        .checked_sub(1)
        .ok_or_else(|| String::from("matrix dictionary limit underflows"))?;
    let bytes = fs::read(path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    match open_generated_bytes(
        bytes,
        password,
        Limits::builder().max_dictionary_bytes(maximum).build(),
        &cancellation,
        &mut budget,
    ) {
        Ok(archive) => expect_error_kind(
            archive.verify(&cancellation, &mut budget),
            ErrorKind::LimitExceeded,
            "matrix decode dictionary limit",
        ),
        Err(error) => expect_error_kind::<Archive>(
            Err(error),
            ErrorKind::LimitExceeded,
            "matrix model dictionary limit",
        ),
    }
}

#[cfg(feature = "unstable-internals")]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Result<usize, Box<dyn StdError>> {
    if needle.is_empty() {
        return Err(String::from("matrix mutation pattern is empty").into());
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or_else(|| String::from("matrix mutation pattern is missing").into())
}

#[cfg(feature = "unstable-internals")]
fn assert_logical_packed_truncation(
    path: &Path,
    password: Option<&str>,
) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let streams = archive
        .header()
        .main_streams()
        .ok_or_else(|| String::from("matrix archive has no main streams"))?;
    let first_stream = streams
        .pack_streams()
        .first()
        .ok_or_else(|| String::from("matrix archive has no packed stream"))?;
    let original_size = first_stream
        .size()
        .ok_or_else(|| String::from("matrix packed stream has unknown size"))?;
    let shortened_size = original_size
        .checked_sub(1)
        .ok_or_else(|| String::from("matrix packed stream is empty"))?;

    let mut prefix = Vec::from([0x06]);
    push_7z_uint(&mut prefix, streams.pack_position())?;
    push_7z_uint(&mut prefix, u64::try_from(streams.pack_streams().len())?)?;
    prefix.push(0x09);
    let size_offset = prefix.len();
    push_7z_uint(&mut prefix, original_size)?;
    let mut replacement = Vec::new();
    push_7z_uint(&mut replacement, shortened_size)?;
    let original_encoding = prefix
        .get(size_offset..)
        .ok_or_else(|| String::from("matrix packed-size encoding is missing"))?;
    if original_encoding.len() != replacement.len() {
        return Err(String::from("matrix packed-size encoding length changed").into());
    }

    let mut bytes = fs::read(path)?;
    let (next_start, next_end) = stored_next_header_range(&bytes)?;
    let relative = find_subslice(
        bytes
            .get(next_start..next_end)
            .ok_or_else(|| String::from("matrix next-header mutation range is missing"))?,
        &prefix,
    )?;
    let absolute = next_start
        .checked_add(relative)
        .and_then(|offset| offset.checked_add(size_offset))
        .ok_or_else(|| String::from("matrix packed-size mutation offset overflows"))?;
    let end = absolute
        .checked_add(replacement.len())
        .ok_or_else(|| String::from("matrix packed-size mutation end overflows"))?;
    bytes
        .get_mut(absolute..end)
        .ok_or_else(|| String::from("matrix packed-size mutation range is missing"))?
        .copy_from_slice(&replacement);
    refresh_header_crcs(&mut bytes)?;

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let mutated = open_generated_bytes(
        bytes,
        password,
        Limits::default(),
        &cancellation,
        &mut budget,
    )?;
    expect_failure(
        mutated.verify(&cancellation, &mut budget),
        "matrix logical packed truncation",
    )
}

#[cfg(feature = "unstable-internals")]
fn first_stored_property_length_offset(
    bytes: &[u8],
    archive: &Archive,
) -> Result<Option<usize>, Box<dyn StdError>> {
    let (next_start, next_end) = stored_next_header_range(bytes)?;
    let next_header = bytes
        .get(next_start..next_end)
        .ok_or_else(|| String::from("matrix property mutation header is missing"))?;
    let Some(streams) = archive.header().main_streams() else {
        return Ok(None);
    };
    for folder in streams.folders() {
        for coder in folder.coders() {
            if coder.method_id() == METHOD_7Z_AES || coder.properties().is_empty() {
                continue;
            }
            let method_length = u8::try_from(coder.method_id().len())?;
            if method_length > 0x0f || coder.properties().len() >= 0x80 {
                return Err(
                    String::from("matrix coder descriptor is outside one-byte bounds").into(),
                );
            }
            let mut descriptor = Vec::new();
            descriptor.push(0x20 | method_length);
            descriptor.extend_from_slice(coder.method_id());
            let length_offset = descriptor.len();
            descriptor.push(u8::try_from(coder.properties().len())?);
            descriptor.extend_from_slice(coder.properties());
            if let Ok(relative) = find_subslice(next_header, &descriptor) {
                let absolute = next_start
                    .checked_add(relative)
                    .and_then(|offset| offset.checked_add(length_offset))
                    .ok_or_else(|| String::from("matrix property mutation offset overflows"))?;
                return Ok(Some(absolute));
            }
        }
    }
    Ok(None)
}

#[cfg(feature = "unstable-internals")]
fn assert_malicious_property_lengths(
    path: &Path,
    password: Option<&str>,
    required: bool,
) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let bytes = fs::read(path)?;
    let Some(length_offset) = first_stored_property_length_offset(&bytes, &archive)? else {
        if required {
            return Err(String::from("matrix plain-header coder property was not located").into());
        }
        return Ok(());
    };

    let mut oversized = bytes.clone();
    let length = oversized
        .get_mut(length_offset)
        .ok_or_else(|| String::from("matrix oversized-property byte is missing"))?;
    *length = 0x7f;
    refresh_header_crcs(&mut oversized)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    expect_error_kind(
        open_generated_bytes(
            oversized,
            password,
            Limits::builder().max_coder_property_bytes(64).build(),
            &cancellation,
            &mut budget,
        ),
        ErrorKind::LimitExceeded,
        "matrix oversized coder property",
    )?;

    let mut empty = bytes;
    let length = empty
        .get_mut(length_offset)
        .ok_or_else(|| String::from("matrix empty-property byte is missing"))?;
    *length = 0;
    refresh_header_crcs(&mut empty)?;
    let mut budget = WorkBudget::unlimited();
    expect_failure(
        open_generated_bytes(
            empty,
            password,
            Limits::default(),
            &cancellation,
            &mut budget,
        ),
        "matrix empty coder property",
    )
}

#[cfg(feature = "unstable-internals")]
fn assert_invalid_bzip2_block_header(path: &Path) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, None)?;
    let offset = archive
        .header()
        .main_streams()
        .and_then(|streams| streams.pack_streams().first())
        .ok_or_else(|| String::from("matrix BZip2 packed stream is missing"))?
        .offset();
    let mutation = offset
        .checked_add(3)
        .ok_or_else(|| String::from("matrix BZip2 header offset overflows"))?;
    let mut bytes = fs::read(path)?;
    let byte = bytes
        .get_mut(usize::try_from(mutation)?)
        .ok_or_else(|| String::from("matrix BZip2 header byte is missing"))?;
    *byte = b'0';
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let mutated = open_generated_bytes(bytes, None, Limits::default(), &cancellation, &mut budget)?;
    expect_failure(
        mutated.verify(&cancellation, &mut budget),
        "matrix invalid BZip2 block header",
    )
}

#[cfg(feature = "unstable-internals")]
fn run_matrix_case(directory: &Path, case: &MatrixCase) -> Result<PathBuf, Box<dyn StdError>> {
    let payload = sized_method_payload(case.payload_kind, case.payload_length)?;
    let archive_path = create_archive(
        directory,
        case.label,
        case.switches,
        case.password,
        &payload,
    )?;
    let primary_method = case
        .methods
        .first()
        .ok_or_else(|| String::from("property-matrix case has no method expectation"))?
        .name;
    compare_to_oracle(&archive_path, case.password, primary_method, &payload)?;
    assert_oracle_methods(&archive_path, case.password, case.methods)?;
    let archive = open_archive(&archive_path, case.password)?;
    assert_main_coders(&archive, case.coders, case.dictionary_bytes)?;
    assert_corruption_fails(&archive_path, case.password)?;
    assert_strategic_truncations(&archive_path, case.password)?;
    assert_operation_controls(&archive_path, case.password)?;
    let maximum_entry = u64::try_from(payload.len())?
        .checked_sub(1)
        .ok_or_else(|| String::from("matrix output limit underflows"))?;
    assert_output_limit(&archive_path, case.password, maximum_entry)?;
    if case.dictionary_bytes != 0 {
        assert_dictionary_limit(&archive_path, case.password, case.dictionary_bytes)?;
    }
    let encrypted_header = case.switches.contains(&"-mhe=on");
    if !encrypted_header {
        assert_logical_packed_truncation(&archive_path, case.password)?;
    }
    let has_stored_property = case.coders.iter().any(|coder| {
        coder.method_id != METHOD_7Z_AES && coder.properties.is_some_and(|value| !value.is_empty())
    });
    assert_malicious_property_lengths(
        &archive_path,
        case.password,
        has_stored_property && !encrypted_header,
    )?;
    Ok(archive_path)
}

#[cfg(feature = "unstable-internals")]
fn compare_multiple_members(
    path: &Path,
    password: Option<&str>,
    sources: &[GeneratedMember],
) -> Result<(), Box<dyn StdError>> {
    let archive = open_archive(path, password)?;
    let oracle = oracle_metadata(path, password)?;
    if archive.entries().len() != oracle.len() || oracle.len() != sources.len() {
        return Err(String::from("generated multi-file entry count differs").into());
    }
    let cancellation = CancellationToken::new();
    for (index, (entry, oracle_entry)) in archive.entries().iter().zip(&oracle).enumerate() {
        let source = sources
            .iter()
            .find(|source| source.name == oracle_entry.path)
            .ok_or_else(|| format!("generated source for {:?} is missing", oracle_entry.path))?;
        let raw_name = entry
            .raw_name()
            .ok_or_else(|| String::from("generated multi-file member has no raw name"))?;
        if String::from_utf16_lossy(raw_name) != oracle_entry.path
            || entry.size() != Some(oracle_entry.size)
            || entry.crc32() != oracle_entry.crc
            || u64::try_from(source.bytes.len())? != oracle_entry.size
        {
            return Err(format!("generated metadata differs for {:?}", oracle_entry.path).into());
        }
        let mut budget = WorkBudget::unlimited();
        let rust = archive.extract_entry(u64::try_from(index)?, &cancellation, &mut budget)?;
        let oracle_bytes = oracle_member(path, &oracle_entry.path, password)?;
        if rust != source.bytes
            || oracle_bytes != source.bytes
            || Sha256::digest(&rust) != Sha256::digest(&oracle_bytes)
        {
            return Err(format!("generated bytes differ for {:?}", oracle_entry.path).into());
        }
    }
    let mut budget = WorkBudget::unlimited();
    archive.verify(&cancellation, &mut budget)?;
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn assert_layout(
    path: &Path,
    password: Option<&str>,
    expected_solid: &str,
    expected_blocks: &str,
    expected_folders: usize,
) -> Result<(), Box<dyn StdError>> {
    if oracle_summary_field(path, password, "Solid")? != expected_solid
        || oracle_summary_field(path, password, "Blocks")? != expected_blocks
    {
        return Err(String::from("7zz solid-layout summary differs from the request").into());
    }
    let archive = open_archive(path, password)?;
    let folder_count = archive
        .header()
        .main_streams()
        .map_or(0, |streams| streams.folders().len());
    if folder_count != expected_folders {
        return Err(format!(
            "Rust solid-layout folder count differs: expected {expected_folders}, found {folder_count}"
        )
        .into());
    }
    Ok(())
}

fn assert_packed_data_was_transformed(
    path: &Path,
    payload: &[u8],
) -> Result<(), Box<dyn StdError>> {
    let archive = fs::read(path)?;
    let comparison_end = 32_usize
        .checked_add(payload.len())
        .ok_or_else(|| String::from("generated packed comparison range overflows"))?
        .min(archive.len());
    let packed_prefix = archive
        .get(32..comparison_end)
        .ok_or_else(|| String::from("generated packed comparison range is missing"))?;
    let source_prefix = payload
        .get(..packed_prefix.len())
        .ok_or_else(|| String::from("generated source comparison range is missing"))?;
    if packed_prefix == source_prefix {
        return Err(String::from("7zz filter did not transform the positive fixture").into());
    }
    Ok(())
}

fn assert_corruption_fails(path: &Path, password: Option<&str>) -> Result<(), Box<dyn StdError>> {
    let mut bytes = fs::read(path)?;
    let next_offset = <[u8; 8]>::try_from(
        bytes
            .get(12..20)
            .ok_or_else(|| String::from("generated start header is truncated"))?,
    )?;
    let packed_length = usize::try_from(u64::from_le_bytes(next_offset))?;
    if packed_length == 0 {
        return Err(String::from("generated archive has no packed region").into());
    }
    let mutation_index = 32_usize
        .checked_add(packed_length / 2)
        .ok_or_else(|| String::from("generated packed-data index overflows"))?;
    let byte = bytes
        .get_mut(mutation_index)
        .ok_or_else(|| String::from("generated packed-data byte is missing"))?;
    *byte ^= 0x5a;

    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let opened = match password {
        Some(password) => Archive::open_bytes_with_password(
            bytes,
            Limits::default(),
            password,
            &cancellation,
            &mut budget,
        ),
        None => Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
    };
    let failed = match opened {
        Ok(archive) => {
            let mut budget = WorkBudget::unlimited();
            archive.verify(&cancellation, &mut budget).is_err()
        }
        Err(_) => true,
    };
    if !failed {
        return Err(String::from("corrupted generated archive verified successfully").into());
    }
    Ok(())
}

#[test]
#[ignore = "requires stock 7zz 26.02"]
fn generated_core_methods_match_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("methods")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        for (name, method, switches, is_filter) in [
            ("copy", "Copy", &["-m0=Copy"][..], false),
            ("lzma", "LZMA", &["-m0=LZMA:d=1m"][..], false),
            ("lzma2", "LZMA2", &["-m0=LZMA2:d=1m"][..], false),
            ("delta", "Delta", &["-m0=Copy", "-m1=Delta:1"][..], true),
            ("bcj", "BCJ", &["-m0=Copy", "-m1=BCJ"][..], true),
            ("bcj2", "BCJ2", &["-m0=BCJ2"][..], true),
            ("ppc", "PPC", &["-m0=Copy", "-m1=PPC"][..], true),
            ("arm", "ARM", &["-m0=Copy", "-m1=ARM"][..], true),
            ("arm64", "ARM64", &["-m0=Copy", "-m1=ARM64"][..], true),
            ("sparc", "SPARC", &["-m0=Copy", "-m1=SPARC"][..], true),
            ("deflate", "Deflate", &["-m0=Deflate"][..], false),
            ("bzip2", "BZip2", &["-m0=BZip2"][..], false),
            ("ppmd", "PPMD", &["-m0=PPMd:o=6:mem=1m"][..], false),
        ] {
            let payload = method_payload(name)?;
            let archive = create_archive(&directory, name, switches, None, &payload)?;
            if is_filter {
                assert_packed_data_was_transformed(&archive, &payload)
                    .map_err(|error| format!("{name} transform check failed: {error}"))?;
            }
            compare_to_oracle(&archive, None, method, &payload)
                .map_err(|error| format!("{name} differential failed: {error}"))?;
            assert_corruption_fails(&archive, None)
                .map_err(|error| format!("{name} corruption check failed: {error}"))?;
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires stock 7zz 26.02"]
fn generated_zip_xz_method_95_matches_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("zip-xz-method-95")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let source_name = "method-95.bin";
        let payload = repeated_pattern(b"unpackio ZIP XZ differential payload\n", 4096)?;
        fs::write(directory.join(source_name), &payload)?;
        let path = directory.join("method-95.zip");
        let output = oracle_command()
            .current_dir(&directory)
            .args(["a", "-y", "-tzip", "-mm=XZ", "-mx=9"])
            .arg(&path)
            .arg(source_name)
            .output()?;
        if !output.status.success() {
            return Err(command_failure("7zz ZIP XZ fixture creation", &output).into());
        }
        let oracle = oracle_metadata(&path, None)?;
        let oracle_entry = oracle
            .first()
            .filter(|_| oracle.len() == 1)
            .ok_or_else(|| String::from("7zz ZIP XZ fixture has the wrong entry count"))?;
        if !oracle_entry
            .method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("xz"))
        {
            return Err(String::from("7zz did not select ZIP XZ method 95").into());
        }

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_path(&path, Limits::default(), &cancellation, &mut budget)?;
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| String::from("Rust ZIP XZ metadata is missing"))?;
        if entry.compression_method() != ZipCompressionMethod::Xz || entry.version_needed() != 20 {
            return Err(String::from("Rust ZIP XZ method/version metadata differs").into());
        }
        let mut decoded = Vec::new();
        let mut budget = WorkBudget::unlimited();
        archive.extract_entry_to(0, &mut decoded, &cancellation, &mut budget)?;
        let oracle_decoded = oracle_member(&path, source_name, None)?;
        if decoded != payload || decoded != oracle_decoded {
            return Err(String::from("Rust and 7zz ZIP XZ output differs").into());
        }
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires stock 7zz 26.02"]
fn generated_zip_ppmd_method_98_matches_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("zip-ppmd-method-98")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let source_name = "method-98.bin";
        let payload = repeated_pattern(b"unpackio ZIP PPMd-I differential payload\n", 4096)?;
        fs::write(directory.join(source_name), &payload)?;
        let path = directory.join("method-98.zip");
        let output = oracle_command()
            .current_dir(&directory)
            .args(["a", "-y", "-tzip", "-mm=PPMd", "-mx=9"])
            .arg(&path)
            .arg(source_name)
            .output()?;
        if !output.status.success() {
            return Err(command_failure("7zz ZIP PPMd fixture creation", &output).into());
        }
        let oracle = oracle_metadata(&path, None)?;
        let oracle_entry = oracle
            .first()
            .filter(|_| oracle.len() == 1)
            .ok_or_else(|| String::from("7zz ZIP PPMd fixture has the wrong entry count"))?;
        if !oracle_entry
            .method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("ppmd"))
        {
            return Err(String::from("7zz did not select ZIP PPMd method 98").into());
        }

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_path(&path, Limits::default(), &cancellation, &mut budget)?;
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| String::from("Rust ZIP PPMd metadata is missing"))?;
        if entry.compression_method() != ZipCompressionMethod::Ppmd || entry.version_needed() < 20 {
            return Err(String::from("Rust ZIP PPMd method/version metadata differs").into());
        }
        let mut decoded = Vec::new();
        let mut budget = WorkBudget::unlimited();
        archive.extract_entry_to(0, &mut decoded, &cancellation, &mut budget)?;
        let oracle_decoded = oracle_member(&path, source_name, None)?;
        if decoded != payload || decoded != oracle_decoded {
            return Err(String::from("Rust and 7zz ZIP PPMd output differs").into());
        }
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires stock 7zz 26.02"]
fn generated_encrypted_header_and_data_match_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("aes")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let payload = method_payload("copy")?;
        let encrypted_header = create_archive(
            &directory,
            "encrypted-header",
            &["-m0=Copy", "-mhe=on"],
            Some(PASSWORD),
            &payload,
        )?;
        if open_archive(&encrypted_header, None)
            .as_ref()
            .err()
            .map(unpackio::Error::kind)
            != Some(ErrorKind::PasswordRequired)
        {
            return Err(String::from("encrypted header did not require a password").into());
        }
        if open_archive(&encrypted_header, Some("wrong-password"))
            .as_ref()
            .err()
            .map(unpackio::Error::kind)
            != Some(ErrorKind::WrongPasswordOrCorrupt)
        {
            return Err(String::from("wrong header password was not typed").into());
        }
        compare_to_oracle(&encrypted_header, Some(PASSWORD), "7zAES", &payload)?;
        assert_corruption_fails(&encrypted_header, Some(PASSWORD))?;

        let encrypted_data = create_archive(
            &directory,
            "encrypted-data",
            &["-m0=Copy", "-mhe=off"],
            Some(PASSWORD),
            &payload,
        )?;
        let wrong = open_archive(&encrypted_data, Some("wrong-password"))?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        if wrong
            .verify(&cancellation, &mut budget)
            .as_ref()
            .err()
            .map(unpackio::Error::kind)
            != Some(ErrorKind::WrongPasswordOrCorrupt)
        {
            return Err(String::from("wrong data password was not typed").into());
        }
        compare_to_oracle(&encrypted_data, Some(PASSWORD), "7zAES", &payload)?;
        assert_corruption_fails(&encrypted_data, Some(PASSWORD))?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires stock 7zz 26.02"]
fn generated_sfx_prefix_matches_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("sfx")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        let payload = method_payload("copy")?;
        let archive = create_archive(&directory, "plain-for-sfx", &["-m0=Copy"], None, &payload)?;
        let archive_bytes = fs::read(&archive)?;
        let mut sfx = repeated_pattern(b"MZ synthetic unpackio test-only SFX prefix\n", 128)?;
        sfx.try_reserve(archive_bytes.len())?;
        sfx.extend_from_slice(&archive_bytes);
        let sfx_path = directory.join("synthetic-sfx.exe");
        fs::write(&sfx_path, sfx)?;
        compare_to_oracle(&sfx_path, None, "Copy", &payload)
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn run_property_chain_and_encryption_matrix(directory: &Path) -> Result<(), Box<dyn StdError>> {
    let cases = [
        MatrixCase {
            label: "matrix-lzma-d64k",
            payload_kind: "copy",
            payload_length: 192 * KIB,
            switches: &["-mf=off", "-m0=LZMA:d64k:fb32:lc3:lp0:pb2"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA",
                exact_token: Some("LZMA:16"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA,
                properties: Some(&[0x5d, 0x00, 0x00, 0x01, 0x00]),
            }],
            dictionary_bytes: 65_536,
        },
        MatrixCase {
            label: "matrix-lzma-d1m-lc2-lp1-pb1",
            payload_kind: "copy",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA:d1m:fb64:lc2:lp1:pb1"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA",
                exact_token: Some("LZMA:20:lc2:lp1:pb1"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA,
                properties: Some(&[0x38, 0x00, 0x00, 0x10, 0x00]),
            }],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-lzma-d4m-lc4-pb0",
            payload_kind: "copy",
            payload_length: 4 * MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA:d4m:fb64:lc4:lp0:pb0"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA",
                exact_token: Some("LZMA:22:lc4:pb0"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA,
                properties: Some(&[0x04, 0x00, 0x00, 0x40, 0x00]),
            }],
            dictionary_bytes: 4_194_304,
        },
        MatrixCase {
            label: "matrix-lzma2-d64k",
            payload_kind: "copy",
            payload_length: 192 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d64k"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA2",
                exact_token: Some("LZMA2:16"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA2,
                properties: Some(&[0x08]),
            }],
            dictionary_bytes: 65_536,
        },
        MatrixCase {
            label: "matrix-lzma2-d1m",
            payload_kind: "copy",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d1m"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA2",
                exact_token: Some("LZMA2:20"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA2,
                properties: Some(&[0x10]),
            }],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-lzma2-d4m",
            payload_kind: "copy",
            payload_length: 4 * MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d4m"],
            password: None,
            methods: &[MethodExpectation {
                name: "LZMA2",
                exact_token: Some("LZMA2:22"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_LZMA2,
                properties: Some(&[0x14]),
            }],
            dictionary_bytes: 4_194_304,
        },
        MatrixCase {
            label: "matrix-ppmd-o2-mem1m",
            payload_kind: "ppmd",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=PPMd:o2:mem1m"],
            password: None,
            methods: &[MethodExpectation {
                name: "PPMD",
                exact_token: Some("PPMD:o2:mem20"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_PPMD,
                properties: Some(&[0x02, 0x00, 0x00, 0x10, 0x00]),
            }],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-ppmd-o16-mem4m",
            payload_kind: "ppmd",
            payload_length: 4 * MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=PPMd:o16:mem4m"],
            password: None,
            methods: &[MethodExpectation {
                name: "PPMD",
                exact_token: Some("PPMD:o16:mem22"),
            }],
            coders: &[CoderExpectation {
                method_id: METHOD_PPMD,
                properties: Some(&[0x10, 0x00, 0x00, 0x40, 0x00]),
            }],
            dictionary_bytes: 4_194_304,
        },
        MatrixCase {
            label: "matrix-delta-distance1",
            payload_kind: "copy",
            payload_length: 256 * KIB,
            switches: &["-mf=off", "-m0=Copy", "-m1=Delta:1"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "Copy",
                    exact_token: Some("Copy"),
                },
                MethodExpectation {
                    name: "Delta",
                    exact_token: Some("Delta:1"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_COPY,
                    properties: Some(&[]),
                },
                CoderExpectation {
                    method_id: METHOD_DELTA,
                    properties: Some(&[0x00]),
                },
            ],
            dictionary_bytes: 0,
        },
        MatrixCase {
            label: "matrix-delta-distance4",
            payload_kind: "copy",
            payload_length: 256 * KIB,
            switches: &["-mf=off", "-m0=Copy", "-m1=Delta:4"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "Copy",
                    exact_token: Some("Copy"),
                },
                MethodExpectation {
                    name: "Delta",
                    exact_token: Some("Delta:4"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_COPY,
                    properties: Some(&[]),
                },
                CoderExpectation {
                    method_id: METHOD_DELTA,
                    properties: Some(&[0x03]),
                },
            ],
            dictionary_bytes: 0,
        },
        MatrixCase {
            label: "matrix-delta-distance256",
            payload_kind: "copy",
            payload_length: 256 * KIB,
            switches: &["-mf=off", "-m0=Copy", "-m1=Delta:256"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "Copy",
                    exact_token: Some("Copy"),
                },
                MethodExpectation {
                    name: "Delta",
                    exact_token: Some("Delta:256"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_COPY,
                    properties: Some(&[]),
                },
                CoderExpectation {
                    method_id: METHOD_DELTA,
                    properties: Some(&[0xff]),
                },
            ],
            dictionary_bytes: 0,
        },
        MatrixCase {
            label: "matrix-bcj-lzma2",
            payload_kind: "bcj",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d1m", "-m1=BCJ"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "LZMA2",
                    exact_token: Some("LZMA2:20"),
                },
                MethodExpectation {
                    name: "BCJ",
                    exact_token: Some("BCJ"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_LZMA2,
                    properties: Some(&[0x10]),
                },
                CoderExpectation {
                    method_id: METHOD_BCJ,
                    properties: Some(&[]),
                },
            ],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-ppc-lzma2",
            payload_kind: "ppc",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d1m", "-m1=PPC"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "LZMA2",
                    exact_token: Some("LZMA2:20"),
                },
                MethodExpectation {
                    name: "PPC",
                    exact_token: Some("PPC"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_LZMA2,
                    properties: Some(&[0x10]),
                },
                CoderExpectation {
                    method_id: METHOD_PPC,
                    properties: Some(&[]),
                },
            ],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-delta4-lzma2",
            payload_kind: "copy",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d1m", "-m1=Delta:4"],
            password: None,
            methods: &[
                MethodExpectation {
                    name: "LZMA2",
                    exact_token: Some("LZMA2:20"),
                },
                MethodExpectation {
                    name: "Delta",
                    exact_token: Some("Delta:4"),
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_LZMA2,
                    properties: Some(&[0x10]),
                },
                CoderExpectation {
                    method_id: METHOD_DELTA,
                    properties: Some(&[0x03]),
                },
            ],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-encrypted-lzma-data",
            payload_kind: "copy",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA:d1m", "-mhe=off"],
            password: Some(PASSWORD),
            methods: &[
                MethodExpectation {
                    name: "LZMA",
                    exact_token: Some("LZMA:20"),
                },
                MethodExpectation {
                    name: "7zAES",
                    exact_token: None,
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_LZMA,
                    properties: Some(&[0x5d, 0x00, 0x00, 0x10, 0x00]),
                },
                CoderExpectation {
                    method_id: METHOD_7Z_AES,
                    properties: None,
                },
            ],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-encrypted-bcj-lzma2-header",
            payload_kind: "bcj",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=LZMA2:d1m", "-m1=BCJ", "-mhe=on"],
            password: Some(PASSWORD),
            methods: &[
                MethodExpectation {
                    name: "LZMA2",
                    exact_token: Some("LZMA2:20"),
                },
                MethodExpectation {
                    name: "BCJ",
                    exact_token: Some("BCJ"),
                },
                MethodExpectation {
                    name: "7zAES",
                    exact_token: None,
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_LZMA2,
                    properties: Some(&[0x10]),
                },
                CoderExpectation {
                    method_id: METHOD_BCJ,
                    properties: Some(&[]),
                },
                CoderExpectation {
                    method_id: METHOD_7Z_AES,
                    properties: None,
                },
            ],
            dictionary_bytes: 1_048_576,
        },
        MatrixCase {
            label: "matrix-encrypted-ppmd-data",
            payload_kind: "ppmd",
            payload_length: MIB + 128 * KIB,
            switches: &["-mf=off", "-m0=PPMd:o2:mem1m", "-mhe=off"],
            password: Some(PASSWORD),
            methods: &[
                MethodExpectation {
                    name: "PPMD",
                    exact_token: Some("PPMD:o2:mem20"),
                },
                MethodExpectation {
                    name: "7zAES",
                    exact_token: None,
                },
            ],
            coders: &[
                CoderExpectation {
                    method_id: METHOD_PPMD,
                    properties: Some(&[0x02, 0x00, 0x00, 0x10, 0x00]),
                },
                CoderExpectation {
                    method_id: METHOD_7Z_AES,
                    properties: None,
                },
            ],
            dictionary_bytes: 1_048_576,
        },
    ];

    for case in cases {
        run_matrix_case(directory, &case)
            .map_err(|error| format!("{} property-matrix case failed: {error}", case.label))?;
    }
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn run_block_and_level_matrix(directory: &Path) -> Result<(), Box<dyn StdError>> {
    let bzip100 = MatrixCase {
        label: "matrix-bzip2-100k",
        payload_kind: "copy",
        payload_length: MIB + 128 * KIB,
        switches: &["-mf=off", "-m0=BZip2:d100k"],
        password: None,
        methods: &[MethodExpectation {
            name: "BZip2",
            exact_token: Some("BZip2"),
        }],
        coders: &[CoderExpectation {
            method_id: METHOD_BZIP2,
            properties: Some(&[]),
        }],
        dictionary_bytes: 0,
    };
    let bzip900 = MatrixCase {
        label: "matrix-bzip2-900k",
        payload_kind: "copy",
        payload_length: MIB + 128 * KIB,
        switches: &["-mf=off", "-m0=BZip2:d900k"],
        password: None,
        methods: &[MethodExpectation {
            name: "BZip2",
            exact_token: Some("BZip2"),
        }],
        coders: &[CoderExpectation {
            method_id: METHOD_BZIP2,
            properties: Some(&[]),
        }],
        dictionary_bytes: 0,
    };
    let bzip100_path = run_matrix_case(directory, &bzip100)?;
    let bzip900_path = run_matrix_case(directory, &bzip900)?;
    if first_packed_stream(&bzip100_path, None)?.get(..4) != Some(b"BZh1")
        || first_packed_stream(&bzip900_path, None)?.get(..4) != Some(b"BZh9")
    {
        return Err(String::from("7zz did not serialize the requested BZip2 block sizes").into());
    }
    assert_dictionary_limit(&bzip100_path, None, 500_000)?;
    assert_dictionary_limit(&bzip900_path, None, 4_500_000)?;
    assert_invalid_bzip2_block_header(&bzip100_path)?;
    assert_invalid_bzip2_block_header(&bzip900_path)?;

    let deflate1 = MatrixCase {
        label: "matrix-deflate-level1",
        payload_kind: "copy",
        payload_length: 384 * KIB,
        switches: &["-mf=off", "-m0=Deflate:x1"],
        password: None,
        methods: &[MethodExpectation {
            name: "Deflate",
            exact_token: Some("Deflate"),
        }],
        coders: &[CoderExpectation {
            method_id: METHOD_DEFLATE,
            properties: Some(&[]),
        }],
        dictionary_bytes: 0,
    };
    let deflate9 = MatrixCase {
        label: "matrix-deflate-level9",
        payload_kind: "copy",
        payload_length: 384 * KIB,
        switches: &["-mf=off", "-m0=Deflate:x9"],
        password: None,
        methods: &[MethodExpectation {
            name: "Deflate",
            exact_token: Some("Deflate"),
        }],
        coders: &[CoderExpectation {
            method_id: METHOD_DEFLATE,
            properties: Some(&[]),
        }],
        dictionary_bytes: 0,
    };
    let deflate1_path = run_matrix_case(directory, &deflate1)?;
    let deflate9_path = run_matrix_case(directory, &deflate9)?;
    if first_packed_stream(&deflate1_path, None)? == first_packed_stream(&deflate9_path, None)? {
        return Err(String::from(
            "7zz Deflate level requests produced identical packed streams for the probe payload",
        )
        .into());
    }
    assert_dictionary_limit(&deflate1_path, None, 32_768)?;
    assert_dictionary_limit(&deflate9_path, None, 32_768)?;
    Ok(())
}

#[cfg(feature = "unstable-internals")]
fn assert_solid_negative_boundaries(
    path: &Path,
    password: Option<&str>,
    plain_header: bool,
) -> Result<(), Box<dyn StdError>> {
    assert_corruption_fails(path, password)?;
    assert_strategic_truncations(path, password)?;
    assert_operation_controls(path, password)?;
    assert_output_limit(path, password, 80_u64 * 1024 - 1)?;
    assert_dictionary_limit(path, password, 65_536)?;
    if plain_header {
        assert_logical_packed_truncation(path, password)?;
    }
    assert_malicious_property_lengths(path, password, plain_header)
}

#[cfg(feature = "unstable-internals")]
fn run_solid_layout_matrix(directory: &Path) -> Result<(), Box<dyn StdError>> {
    let sources = [
        GeneratedMember {
            name: String::from("matrix-empty.bin"),
            bytes: Vec::new(),
        },
        GeneratedMember {
            name: String::from("matrix-a.bin"),
            bytes: sized_method_payload("copy", 48 * KIB)?,
        },
        GeneratedMember {
            name: String::from("matrix-b.bin"),
            bytes: sized_method_payload("ppmd", 64 * KIB)?,
        },
        GeneratedMember {
            name: String::from("matrix-c.bin"),
            bytes: sized_method_payload("bcj", 80 * KIB)?,
        },
    ];
    for source in &sources {
        fs::write(directory.join(&source.name), &source.bytes)?;
    }
    let source_names = sources
        .iter()
        .map(|source| source.name.as_str())
        .collect::<Vec<_>>();

    let solid = create_archive_from_sources(
        directory,
        "matrix-solid-on",
        &["-mf=off", "-m0=LZMA2:d64k", "-ms=on"],
        None,
        &source_names,
    )?;
    compare_multiple_members(&solid, None, &sources)?;
    assert_layout(&solid, None, "+", "1", 1)?;
    assert_solid_negative_boundaries(&solid, None, true)?;

    let nonsolid = create_archive_from_sources(
        directory,
        "matrix-solid-off",
        &["-mf=off", "-m0=LZMA2:d64k", "-ms=off"],
        None,
        &source_names,
    )?;
    compare_multiple_members(&nonsolid, None, &sources)?;
    assert_layout(&nonsolid, None, "-", "3", 3)?;
    assert_solid_negative_boundaries(&nonsolid, None, true)?;

    let encrypted = create_archive_from_sources(
        directory,
        "matrix-solid-encrypted-header",
        &["-mf=off", "-m0=LZMA2:d64k", "-ms=on", "-mhe=on"],
        Some(PASSWORD),
        &source_names,
    )?;
    if open_archive(&encrypted, None)
        .as_ref()
        .err()
        .map(unpackio::Error::kind)
        != Some(ErrorKind::PasswordRequired)
    {
        return Err(String::from("solid encrypted header did not require a password").into());
    }
    compare_multiple_members(&encrypted, Some(PASSWORD), &sources)?;
    assert_layout(&encrypted, Some(PASSWORD), "+", "1", 1)?;
    let summary_method = oracle_summary_field(&encrypted, Some(PASSWORD), "Method")?;
    if !summary_method
        .split_whitespace()
        .any(|method| method == "7zAES")
    {
        return Err(String::from("solid encrypted matrix archive did not select 7zAES").into());
    }
    assert_solid_negative_boundaries(&encrypted, Some(PASSWORD), false)?;
    Ok(())
}

#[test]
#[cfg(feature = "unstable-internals")]
#[ignore = "requires exact stock 7zz 26.02"]
fn generated_method_property_matrix_matches_7zz() -> Result<(), Box<dyn StdError>> {
    require_exact_7zz()?;
    let directory = temporary_directory("property-matrix")?;
    let result = (|| -> Result<(), Box<dyn StdError>> {
        run_property_chain_and_encryption_matrix(&directory)?;
        run_block_and_level_matrix(&directory)?;
        run_solid_layout_matrix(&directory)
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}
