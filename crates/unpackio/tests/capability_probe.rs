#![forbid(unsafe_code)]
//! Corpus-free black-box capability probes for a locally installed stock `7zz`.

use std::{
    error::Error as StdError,
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};
use unpackio::{Archive, CancellationToken, ErrorKind, Limits, WorkBudget};

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const UNKNOWN_SIZE: u64 = u64::MAX;
const PASSWORD: &str = "capability-probe-password";
const HARDLINK_PAYLOAD: &[u8] = b"hard-link capability probe";
const NORMAL_COPY_CODER: &[u8] = &[0x01, 0x00];
// The leading high bit declares another alternative coder record. This is a
// black-box grammar probe, not a compatibility fixture or parser input source.
const ALTERNATIVE_COPY_CODER: &[u8] = &[0x81, 0x00, 0x01, 0x00];

type ProbeResult<T> = Result<T, Box<dyn StdError>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Accepted,
    AcceptedWithWarning,
    Rejected,
    Synthesized,
    NotRun,
    NotApplicable,
}

impl fmt::Display for Stage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithWarning => "accepted-with-warning",
            Self::Rejected => "rejected",
            Self::Synthesized => "synthesized",
            Self::NotRun => "not-run",
            Self::NotApplicable => "not-applicable",
        };
        formatter.write_str(value)
    }
}

impl Stage {
    const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithWarning)
    }
}

struct ProbeOutcome {
    name: &'static str,
    author: Stage,
    oracle_read: Stage,
    rust_read: Stage,
    sha256: Option<String>,
    detail: String,
}

impl ProbeOutcome {
    fn not_applicable(name: &'static str, detail: &str) -> Self {
        Self {
            name,
            author: Stage::NotApplicable,
            oracle_read: Stage::NotApplicable,
            rust_read: Stage::NotApplicable,
            sha256: None,
            detail: String::from(detail),
        }
    }

    fn print_tsv(&self) {
        println!(
            "UNPACKIO_7ZZ_PROBE\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_field(self.name),
            self.author,
            self.oracle_read,
            self.rust_read,
            self.sha256.as_deref().unwrap_or("-"),
            sanitize_field(&self.detail),
        );
    }
}

struct CopyFixture<'fixture> {
    payload: &'fixture [u8],
    packed_size: u64,
    unpacked_size: u64,
    coder: &'fixture [u8],
    names: &'fixture [&'fixture str],
    first_substream_size: Option<u64>,
    file_comment: Option<&'fixture [u8]>,
    archive_comment: Option<&'fixture [u8]>,
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}

fn push_7z_uint(bytes: &mut Vec<u8>, value: u64) -> ProbeResult<()> {
    const PREFIXES: &[u8] = &[0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe];
    let little_endian = value.to_le_bytes();
    for extra_bytes in 0..8_usize {
        let bit_count = extra_bytes
            .checked_add(1)
            .and_then(|count| count.checked_mul(7))
            .ok_or_else(|| String::from("probe integer bit count overflows"))?;
        let bit_count = u32::try_from(bit_count)?;
        let limit = 1_u64
            .checked_shl(bit_count)
            .ok_or_else(|| String::from("probe integer limit shift overflows"))?;
        if value >= limit {
            continue;
        }
        let shift = extra_bytes
            .checked_mul(8)
            .ok_or_else(|| String::from("probe integer shift overflows"))?;
        let high = u8::try_from(value >> u32::try_from(shift)?)?;
        let prefix = PREFIXES
            .get(extra_bytes)
            .copied()
            .ok_or_else(|| String::from("probe integer prefix is missing"))?;
        bytes.push(prefix | high);
        bytes.extend_from_slice(
            little_endian
                .get(..extra_bytes)
                .ok_or_else(|| String::from("probe integer suffix is missing"))?,
        );
        return Ok(());
    }
    bytes.push(u8::MAX);
    bytes.extend_from_slice(&little_endian);
    Ok(())
}

fn push_property(bytes: &mut Vec<u8>, id: u8, value: &[u8]) -> ProbeResult<()> {
    bytes.push(id);
    push_7z_uint(bytes, u64::try_from(value.len())?)?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn copy_fixture(fixture: &CopyFixture<'_>) -> ProbeResult<Vec<u8>> {
    if fixture.names.is_empty() || fixture.names.len() > 2 {
        return Err(String::from("probe fixture requires one or two member names").into());
    }
    if fixture.names.len() == 2 && fixture.first_substream_size.is_none() {
        return Err(String::from("two-member probe fixture requires its first size").into());
    }
    if fixture.names.len() == 1 && fixture.first_substream_size.is_some() {
        return Err(
            String::from("one-member probe fixture cannot have a first substream size").into(),
        );
    }

    let payload_crc = crc32(fixture.payload);
    let mut streams = Vec::from([0x06]);
    push_7z_uint(&mut streams, 0)?;
    push_7z_uint(&mut streams, 1)?;
    streams.push(0x09);
    push_7z_uint(&mut streams, fixture.packed_size)?;
    streams.extend_from_slice(&[0x0a, 1]);
    streams.extend_from_slice(&payload_crc.to_le_bytes());
    streams.extend_from_slice(&[0x00, 0x07, 0x0b]);
    push_7z_uint(&mut streams, 1)?;
    streams.push(0);
    push_7z_uint(&mut streams, 1)?;
    streams.extend_from_slice(fixture.coder);
    streams.push(0x0c);
    push_7z_uint(&mut streams, fixture.unpacked_size)?;
    streams.extend_from_slice(&[0x0a, 1]);
    streams.extend_from_slice(&payload_crc.to_le_bytes());
    streams.push(0x00);
    if let Some(first_size) = fixture.first_substream_size {
        streams.extend_from_slice(&[0x08, 0x0d, 2, 0x09]);
        push_7z_uint(&mut streams, first_size)?;
        streams.push(0x00);
    }
    streams.push(0x00);

    let mut name_property = Vec::from([0]);
    for name in fixture.names {
        for unit in name.encode_utf16() {
            name_property.extend_from_slice(&unit.to_le_bytes());
        }
        name_property.extend_from_slice(&0_u16.to_le_bytes());
    }
    let mut files = Vec::new();
    push_7z_uint(&mut files, u64::try_from(fixture.names.len())?)?;
    push_property(&mut files, 0x11, &name_property)?;
    if let Some(comment) = fixture.file_comment {
        push_property(&mut files, 0x16, comment)?;
    }
    files.push(0x00);

    let mut next_header = Vec::from([0x01]);
    if let Some(comment) = fixture.archive_comment {
        next_header.push(0x02);
        push_property(&mut next_header, 0x16, comment)?;
        next_header.push(0x00);
    }
    next_header.push(0x04);
    next_header.extend_from_slice(&streams);
    next_header.push(0x05);
    next_header.extend_from_slice(&files);
    next_header.push(0x00);

    let mut start_fields = Vec::new();
    start_fields.extend_from_slice(&u64::try_from(fixture.payload.len())?.to_le_bytes());
    start_fields.extend_from_slice(&u64::try_from(next_header.len())?.to_le_bytes());
    start_fields.extend_from_slice(&crc32(&next_header).to_le_bytes());
    let mut archive = Vec::new();
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(fixture.payload);
    archive.extend_from_slice(&next_header);
    Ok(archive)
}

fn utf16_property(value: &str) -> Vec<u8> {
    let mut bytes = Vec::from([0]);
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

fn temporary_directory() -> ProbeResult<PathBuf> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ordinal = COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "unpackio-capability-probe-{}-{ordinal}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn sanitize_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\r' | '\n' => ' ',
            _ => character,
        })
        .take(320)
        .collect()
}

fn diagnostic_markers(stdout: &[u8], stderr: &[u8]) -> String {
    const MAX_LINES: usize = 6;

    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let mut diagnostics = Vec::new();
    let mut take_context = false;
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let uppercase = trimmed.to_ascii_uppercase();
        let is_marker = uppercase.contains("ERROR")
            || uppercase.contains("WARNING")
            || uppercase.contains("UNSUPPORTED")
            || uppercase.contains("E_NOTIMPL")
            || uppercase.contains("UNEXPECTED END")
            || uppercase.contains("IS NOT ARCHIVE")
            || uppercase.contains("CAN NOT");
        if is_marker || take_context {
            diagnostics.push(sanitize_field(trimmed));
            if diagnostics.len() == MAX_LINES {
                break;
            }
        }
        take_context = is_marker && trimmed.ends_with(':');
    }
    if diagnostics.is_empty() {
        String::from("none")
    } else {
        diagnostics.join(" / ")
    }
}

fn command_detail(output: &Output) -> String {
    let marker_text = diagnostic_markers(&output.stdout, &output.stderr);
    format!(
        "exit={} markers={marker_text}",
        output
            .status
            .code()
            .map_or_else(|| String::from("signal"), |code| code.to_string(),),
    )
}

fn stage(output: &Output) -> Stage {
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_uppercase();
        if stdout.contains("WARNING") || stderr.contains("WARNING") {
            Stage::AcceptedWithWarning
        } else {
            Stage::Accepted
        }
    } else {
        Stage::Rejected
    }
}

fn file_sha256(path: &Path) -> ProbeResult<Option<String>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let mut encoded = String::new();
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(Some(encoded))
}

fn oracle_command() -> Command {
    match std::env::var_os("UNPACKIO_7ZZ") {
        Some(executable) => Command::new(executable),
        None => Command::new("7zz"),
    }
}

fn oracle_2602_banner(listing: &str) -> Option<&str> {
    listing
        .lines()
        .find(|line| line.starts_with("7-Zip (z) 26.02 ") || line.starts_with("7-Zip 26.02 "))
}

fn require_7zz_2602() -> ProbeResult<String> {
    let output = oracle_command().arg("i").env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(format!("7zz capability listing failed: {}", command_detail(&output)).into());
    }
    let listing = String::from_utf8(output.stdout)?;
    let banner = oracle_2602_banner(&listing).ok_or_else(|| {
        format!(
            "capability baseline requires stock 7-Zip 26.02; observed {}",
            sanitize_field(&listing)
        )
    })?;
    if !listing
        .lines()
        .any(|line| line.contains("6F00181") && line.contains("AES256CBC"))
    {
        return Err(String::from(
            "stock 7zz 26.02 capability listing does not advertise raw AES256CBC",
        )
        .into());
    }
    Ok(String::from(banner))
}

fn oracle_test(path: &Path) -> ProbeResult<(Stage, String)> {
    let output = oracle_command()
        .args(["t", "-bd"])
        .arg(path)
        .env("LC_ALL", "C")
        .output()?;
    Ok((stage(&output), command_detail(&output)))
}

fn oracle_listing(path: &Path) -> ProbeResult<(Stage, String)> {
    let output = oracle_command()
        .args(["l", "-slt"])
        .arg(path)
        .env("LC_ALL", "C")
        .output()?;
    let detail = if output.status.success() {
        let listing = String::from_utf8_lossy(&output.stdout);
        format!(
            "comment-field={} hardlink-field={} alternate-stream-field={}",
            listing.contains("Comment ="),
            listing.contains("Hard Link ="),
            listing.contains("Alternate Stream ="),
        )
    } else {
        command_detail(&output)
    };
    Ok((stage(&output), detail))
}

fn rust_verify(path: &Path) -> ProbeResult<(Stage, String)> {
    let bytes = fs::read(path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    match Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget) {
        Ok(archive) => {
            let mut budget = WorkBudget::unlimited();
            match archive.verify(&cancellation, &mut budget) {
                Ok(()) => Ok((
                    Stage::Accepted,
                    format!("entries={}", archive.entries().len()),
                )),
                Err(error) => Ok((
                    Stage::Rejected,
                    format!("verify {:?}: {error}", error.kind()),
                )),
            }
        }
        Err(error) => Ok((Stage::Rejected, format!("open {:?}: {error}", error.kind()))),
    }
}

fn rust_members_match(path: &Path, expected: &[u8], count: usize) -> ProbeResult<(bool, String)> {
    let bytes = fs::read(path)?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive = match Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget) {
        Ok(archive) => archive,
        Err(error) => {
            return Ok((false, format!("open {:?}: {error}", error.kind())));
        }
    };
    if archive.entries().len() != count {
        return Ok((
            false,
            format!(
                "entry-count expected={count} actual={}",
                archive.entries().len()
            ),
        ));
    }
    for index in 0..count {
        let entry_index = u64::try_from(index)?;
        let mut budget = WorkBudget::unlimited();
        let member = match archive.extract_entry(entry_index, &cancellation, &mut budget) {
            Ok(member) => member,
            Err(error) => {
                return Ok((
                    false,
                    format!("entry={index} extract {:?}: {error}", error.kind()),
                ));
            }
        };
        if member.as_slice() != expected {
            return Ok((
                false,
                format!(
                    "entry={index} expected-bytes={} actual-bytes={}",
                    expected.len(),
                    member.len()
                ),
            ));
        }
    }
    Ok((true, format!("entries={count}")))
}

fn synthetic_probe(
    directory: &Path,
    name: &'static str,
    bytes: &[u8],
    inspect_listing: bool,
) -> ProbeResult<ProbeOutcome> {
    let path = directory.join(format!("{name}.7z"));
    fs::write(&path, bytes)?;
    let (oracle_read, mut detail) = oracle_test(&path)?;
    if inspect_listing {
        let (listing_stage, listing_detail) = oracle_listing(&path)?;
        detail.push_str(&format!("; listing={listing_stage}; {listing_detail}"));
    }
    let (rust_read, rust_detail) = rust_verify(&path)?;
    detail.push_str(&format!("; rust={rust_detail}"));
    Ok(ProbeOutcome {
        name,
        author: Stage::Synthesized,
        oracle_read,
        rust_read,
        sha256: file_sha256(&path)?,
        detail,
    })
}

fn authored_probe(
    directory: &Path,
    name: &'static str,
    switches: &[&str],
    inputs: &[&str],
) -> ProbeResult<ProbeOutcome> {
    let archive = directory.join(format!("{name}.7z"));
    let mut command = oracle_command();
    command
        .current_dir(directory)
        .args(["a", "-y", "-t7z", "-mhc=off"])
        .args(switches)
        .arg(&archive)
        .args(inputs)
        .env("LC_ALL", "C");
    let output = command.output()?;
    let author = stage(&output);
    let mut detail = command_detail(&output);
    let (oracle_read, rust_read) = if author.is_accepted() {
        let (oracle, oracle_detail) = oracle_test(&archive)?;
        let (listing, listing_detail) = oracle_listing(&archive)?;
        let (rust, rust_detail) = rust_verify(&archive)?;
        detail.push_str(&format!(
            "; oracle={oracle_detail}; listing={listing}; {listing_detail}; rust={rust_detail}"
        ));
        (oracle, rust)
    } else {
        (Stage::NotRun, Stage::NotRun)
    };
    Ok(ProbeOutcome {
        name,
        author,
        oracle_read,
        rust_read,
        sha256: file_sha256(&archive)?,
        detail,
    })
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> ProbeResult<Option<bool>> {
    use std::os::unix::fs::MetadataExt;

    let left = fs::metadata(left)?;
    let right = fs::metadata(right)?;
    Ok(Some(left.dev() == right.dev() && left.ino() == right.ino()))
}

#[cfg(not(unix))]
fn same_file(_left: &Path, _right: &Path) -> ProbeResult<Option<bool>> {
    Ok(None)
}

fn hardlink_probe(directory: &Path) -> ProbeResult<ProbeOutcome> {
    fs::write(directory.join("hardlink-source.bin"), HARDLINK_PAYLOAD)?;
    fs::hard_link(
        directory.join("hardlink-source.bin"),
        directory.join("hardlink-alias.bin"),
    )?;
    let mut outcome = authored_probe(
        directory,
        "hardlink",
        &["-snh"],
        &["hardlink-source.bin", "hardlink-alias.bin"],
    )?;
    if outcome.author.is_accepted() {
        let (members_match, rust_detail) =
            rust_members_match(&directory.join("hardlink.7z"), HARDLINK_PAYLOAD, 2)?;
        if !members_match {
            outcome.rust_read = Stage::Rejected;
        }
        outcome.detail.push_str(&format!(
            "; rust-members-match={members_match}; rust-members={rust_detail}"
        ));
        let extraction = directory.join("hardlink-output");
        fs::create_dir(&extraction)?;
        let output = oracle_command()
            .current_dir(directory)
            .args(["x", "-y"])
            .arg(format!("-o{}", extraction.display()))
            .arg("hardlink.7z")
            .env("LC_ALL", "C")
            .output()?;
        let relation = if output.status.success() {
            same_file(
                &extraction.join("hardlink-source.bin"),
                &extraction.join("hardlink-alias.bin"),
            )?
        } else {
            None
        };
        outcome.detail.push_str(&format!(
            "; oracle-extract={}; same-file={}",
            stage(&output),
            relation.map_or_else(|| String::from("unavailable"), |value| value.to_string()),
        ));
    }
    Ok(outcome)
}

#[cfg(unix)]
fn symlink_probe(directory: &Path) -> ProbeResult<ProbeOutcome> {
    use std::os::unix::fs::symlink;

    fs::write(
        directory.join("symlink-target.bin"),
        b"symbolic-link capability probe",
    )?;
    symlink("symlink-target.bin", directory.join("symlink-alias.bin"))?;
    let mut outcome = authored_probe(
        directory,
        "symlink",
        &["-snl"],
        &["symlink-target.bin", "symlink-alias.bin"],
    )?;
    if outcome.author.is_accepted() {
        let extraction = directory.join("symlink-output");
        fs::create_dir(&extraction)?;
        let output = oracle_command()
            .current_dir(directory)
            .args(["x", "-y"])
            .arg(format!("-o{}", extraction.display()))
            .arg("symlink.7z")
            .env("LC_ALL", "C")
            .output()?;
        let target = if output.status.success() {
            fs::read_link(extraction.join("symlink-alias.bin"))
                .ok()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| String::from("not-restored-as-link"))
        } else {
            String::from("not-extracted")
        };
        outcome.detail.push_str(&format!(
            "; oracle-extract={}; restored-target={target}",
            stage(&output),
        ));
    }
    Ok(outcome)
}

#[cfg(not(unix))]
fn symlink_probe(_directory: &Path) -> ProbeResult<ProbeOutcome> {
    Ok(ProbeOutcome::not_applicable(
        "symlink",
        "this probe requires a host that can create an unprivileged symbolic link",
    ))
}

#[cfg(windows)]
fn windows_metadata_probes(directory: &Path) -> ProbeResult<Vec<ProbeOutcome>> {
    const ADS_PAYLOAD: &[u8] = b"alternate stream";

    let security_source = directory.join("windows-security.bin");
    fs::write(&security_source, b"Windows security capability probe")?;
    let ads_source = directory.join("windows-ads.bin");
    fs::write(&ads_source, b"Windows ADS capability probe")?;
    let ads_path = PathBuf::from(format!("{}:unpackio-probe", ads_source.display()));
    fs::write(&ads_path, ADS_PAYLOAD)?;
    let ads_readback = fs::read(&ads_path)?;
    if ads_readback.as_slice() != ADS_PAYLOAD {
        return Err(String::from("Windows ADS precondition readback differs").into());
    }

    let mut control = authored_probe(
        directory,
        "windows-control",
        &[],
        &["windows-security.bin", "windows-ads.bin"],
    )?;
    control
        .detail
        .push_str("; separate-inputs=true; ads-readback=true");
    let mut security = authored_probe(
        directory,
        "nt-security",
        &["-sni"],
        &["windows-security.bin"],
    )?;
    security.detail.push_str("; separate-input=true");
    let mut ads = authored_probe(directory, "ntfs-ads", &["-sns"], &["windows-ads.bin"])?;
    ads.detail.push_str("; ads-readback=true");
    Ok(vec![control, security, ads])
}

#[cfg(not(windows))]
fn windows_metadata_probes(_directory: &Path) -> ProbeResult<Vec<ProbeOutcome>> {
    Ok(vec![
        ProbeOutcome::not_applicable(
            "windows-control",
            "this control probe runs only with Windows metadata candidates",
        ),
        ProbeOutcome::not_applicable(
            "nt-security",
            "-sni requires a Windows-generated security descriptor fixture",
        ),
        ProbeOutcome::not_applicable(
            "ntfs-ads",
            "-sns requires a Windows NTFS alternate-stream fixture",
        ),
    ])
}

fn run_capability_probes(directory: &Path) -> ProbeResult<Vec<ProbeOutcome>> {
    let payload = b"copy capability probe";
    let payload_size = u64::try_from(payload.len())?;
    let file_comment = utf16_property("file capability comment");
    let archive_comment = utf16_property("archive capability comment");
    let fixtures = [
        (
            "file-comment",
            CopyFixture {
                payload,
                packed_size: payload_size,
                unpacked_size: payload_size,
                coder: NORMAL_COPY_CODER,
                names: &["file-comment.bin"],
                first_substream_size: None,
                file_comment: Some(&file_comment),
                archive_comment: None,
            },
            true,
        ),
        (
            "archive-comment",
            CopyFixture {
                payload,
                packed_size: payload_size,
                unpacked_size: payload_size,
                coder: NORMAL_COPY_CODER,
                names: &["archive-comment.bin"],
                first_substream_size: None,
                file_comment: None,
                archive_comment: Some(&archive_comment),
            },
            true,
        ),
        (
            "alternative-copy-coder",
            CopyFixture {
                payload,
                packed_size: payload_size,
                unpacked_size: payload_size,
                coder: ALTERNATIVE_COPY_CODER,
                names: &["alternative-copy.bin"],
                first_substream_size: None,
                file_comment: None,
                archive_comment: None,
            },
            false,
        ),
        (
            "unknown-copy-unpacked-size",
            CopyFixture {
                payload,
                packed_size: payload_size,
                unpacked_size: UNKNOWN_SIZE,
                coder: NORMAL_COPY_CODER,
                names: &["unknown-unpacked.bin"],
                first_substream_size: None,
                file_comment: None,
                archive_comment: None,
            },
            false,
        ),
        (
            "unknown-packed-size",
            CopyFixture {
                payload,
                packed_size: UNKNOWN_SIZE,
                unpacked_size: payload_size,
                coder: NORMAL_COPY_CODER,
                names: &["unknown-packed.bin"],
                first_substream_size: None,
                file_comment: None,
                archive_comment: None,
            },
            false,
        ),
        (
            "unknown-nonfinal-substream-size",
            CopyFixture {
                payload,
                packed_size: payload_size,
                unpacked_size: payload_size,
                coder: NORMAL_COPY_CODER,
                names: &["unknown-first.bin", "derived-second.bin"],
                first_substream_size: Some(UNKNOWN_SIZE),
                file_comment: None,
                archive_comment: None,
            },
            false,
        ),
    ];

    let mut outcomes = Vec::new();
    outcomes.try_reserve(fixtures.len().saturating_add(7))?;
    for (name, fixture, inspect_listing) in fixtures {
        outcomes.push(synthetic_probe(
            directory,
            name,
            &copy_fixture(&fixture)?,
            inspect_listing,
        )?);
    }

    fs::write(directory.join("raw-aes.bin"), b"raw AES capability probe")?;
    outcomes.push(authored_probe(
        directory,
        "raw-aes256cbc",
        &["-m0=AES256CBC", &format!("-p{PASSWORD}")],
        &["raw-aes.bin"],
    )?);
    outcomes.push(authored_probe(
        directory,
        "raw-aes256cbc-chain",
        &["-m0=Copy", "-m1=AES256CBC", &format!("-p{PASSWORD}")],
        &["raw-aes.bin"],
    )?);
    outcomes.push(hardlink_probe(directory)?);
    outcomes.push(symlink_probe(directory)?);
    outcomes.extend(windows_metadata_probes(directory)?);
    Ok(outcomes)
}

fn require_2602_baseline(outcomes: &[ProbeOutcome]) -> ProbeResult<()> {
    let expected = [
        (
            "file-comment",
            Stage::Synthesized,
            Stage::AcceptedWithWarning,
            Stage::Accepted,
            Some("0613dd8ff540059ce5fb9cabc5ab876afa98fb9c1c6945a571a86ad4743ad6f4"),
        ),
        (
            "archive-comment",
            Stage::Synthesized,
            Stage::Accepted,
            Stage::Accepted,
            Some("ffcce8a0d54efc09c6059309be3d7c6c89ae16ad6ea156ce7d247a4bb8b0f46d"),
        ),
        (
            "alternative-copy-coder",
            Stage::Synthesized,
            Stage::Rejected,
            Stage::Rejected,
            Some("a1e1cbd05c69e982cb44fe620afbc5e7a6d27e8cd5f928a1d4c6ccd7d7e39423"),
        ),
        (
            "unknown-copy-unpacked-size",
            Stage::Synthesized,
            Stage::Rejected,
            Stage::Accepted,
            Some("4bd9c052eb719182bc574ac88bf681f7eeefa05ef949f646d285f380ac34ef1d"),
        ),
        (
            "unknown-packed-size",
            Stage::Synthesized,
            Stage::Rejected,
            Stage::Rejected,
            Some("5ee94cbc6de923ad71f97b3b9156df1019c0ac7551c65337ba0d7861704a353f"),
        ),
        (
            "unknown-nonfinal-substream-size",
            Stage::Synthesized,
            Stage::Rejected,
            Stage::Rejected,
            Some("2aa96e58bc47a5da7e42d26fc8986eea031deafacab695eec31abc2c1edf74d3"),
        ),
        (
            "raw-aes256cbc",
            Stage::Rejected,
            Stage::NotRun,
            Stage::NotRun,
            None,
        ),
        (
            "raw-aes256cbc-chain",
            Stage::Rejected,
            Stage::NotRun,
            Stage::NotRun,
            None,
        ),
    ];
    for (name, author, oracle_read, rust_read, sha256) in expected {
        let outcome = outcomes
            .iter()
            .find(|outcome| outcome.name == name)
            .ok_or_else(|| format!("7zz 26.02 baseline probe {name} is missing"))?;
        if (
            outcome.author,
            outcome.oracle_read,
            outcome.rust_read,
            outcome.sha256.as_deref(),
        ) != (author, oracle_read, rust_read, sha256)
        {
            return Err(format!(
                "7zz 26.02 baseline changed for {name}: expected ({author}, {oracle_read}, {rust_read}, {sha256:?}), observed ({}, {}, {}, {:?})",
                outcome.author,
                outcome.oracle_read,
                outcome.rust_read,
                outcome.sha256,
            )
            .into());
        }
    }
    Ok(())
}

fn require_stage_baseline(
    outcomes: &[ProbeOutcome],
    expected: &[(&str, Stage, Stage, Stage)],
) -> ProbeResult<()> {
    for (name, author, oracle_read, rust_read) in expected {
        let outcome = outcomes
            .iter()
            .find(|outcome| outcome.name == *name)
            .ok_or_else(|| format!("7zz 26.02 platform probe {name} is missing"))?;
        if (outcome.author, outcome.oracle_read, outcome.rust_read)
            != (*author, *oracle_read, *rust_read)
        {
            return Err(format!(
                "7zz 26.02 platform baseline changed for {name}: expected ({author}, {oracle_read}, {rust_read}), observed ({}, {}, {})",
                outcome.author, outcome.oracle_read, outcome.rust_read,
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_windows_2602_baseline(outcomes: &[ProbeOutcome]) -> ProbeResult<()> {
    require_stage_baseline(
        outcomes,
        &[
            (
                "windows-control",
                Stage::Accepted,
                Stage::Accepted,
                Stage::Accepted,
            ),
            ("nt-security", Stage::Rejected, Stage::NotRun, Stage::NotRun),
            ("ntfs-ads", Stage::Rejected, Stage::NotRun, Stage::NotRun),
        ],
    )
}

#[cfg(not(windows))]
fn require_windows_2602_baseline(outcomes: &[ProbeOutcome]) -> ProbeResult<()> {
    require_stage_baseline(
        outcomes,
        &[
            (
                "windows-control",
                Stage::NotApplicable,
                Stage::NotApplicable,
                Stage::NotApplicable,
            ),
            (
                "nt-security",
                Stage::NotApplicable,
                Stage::NotApplicable,
                Stage::NotApplicable,
            ),
            (
                "ntfs-ads",
                Stage::NotApplicable,
                Stage::NotApplicable,
                Stage::NotApplicable,
            ),
        ],
    )
}

fn open_bytes(bytes: Vec<u8>) -> Result<(), ErrorKind> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)
        .map_err(|error| error.kind())?;
    let mut budget = WorkBudget::unlimited();
    archive
        .verify(&cancellation, &mut budget)
        .map_err(|error| error.kind())
}

#[test]
fn synthetic_probe_fixtures_reach_their_expected_rust_boundaries() -> ProbeResult<()> {
    let payload = b"copy capability probe";
    let size = u64::try_from(payload.len())?;
    let comment = utf16_property("capability comment");
    for fixture in [
        CopyFixture {
            payload,
            packed_size: size,
            unpacked_size: size,
            coder: NORMAL_COPY_CODER,
            names: &["baseline.bin"],
            first_substream_size: None,
            file_comment: Some(&comment),
            archive_comment: None,
        },
        CopyFixture {
            payload,
            packed_size: size,
            unpacked_size: size,
            coder: NORMAL_COPY_CODER,
            names: &["baseline.bin"],
            first_substream_size: None,
            file_comment: None,
            archive_comment: Some(&comment),
        },
        CopyFixture {
            payload,
            packed_size: size,
            unpacked_size: UNKNOWN_SIZE,
            coder: NORMAL_COPY_CODER,
            names: &["unknown.bin"],
            first_substream_size: None,
            file_comment: None,
            archive_comment: None,
        },
    ] {
        if open_bytes(copy_fixture(&fixture)?) != Ok(()) {
            return Err(String::from("supported synthetic capability fixture was rejected").into());
        }
    }

    let alternative = copy_fixture(&CopyFixture {
        payload,
        packed_size: size,
        unpacked_size: size,
        coder: ALTERNATIVE_COPY_CODER,
        names: &["alternative.bin"],
        first_substream_size: None,
        file_comment: None,
        archive_comment: None,
    })?;
    if open_bytes(alternative) != Err(ErrorKind::UnsupportedFeature) {
        return Err(
            String::from("alternative-coder probe did not reach its typed boundary").into(),
        );
    }

    let unknown_packed = copy_fixture(&CopyFixture {
        payload,
        packed_size: UNKNOWN_SIZE,
        unpacked_size: size,
        coder: NORMAL_COPY_CODER,
        names: &["unknown-packed.bin"],
        first_substream_size: None,
        file_comment: None,
        archive_comment: None,
    })?;
    if open_bytes(unknown_packed) != Err(ErrorKind::UnsupportedFeature) {
        return Err(String::from("unknown-packed probe did not reach its typed boundary").into());
    }
    Ok(())
}

#[test]
fn accepts_standalone_and_windows_2602_oracle_banners() {
    assert_eq!(
        oracle_2602_banner("7-Zip (z) 26.02 (x64) : standalone\n"),
        Some("7-Zip (z) 26.02 (x64) : standalone")
    );
    assert_eq!(
        oracle_2602_banner("7-Zip 26.02 (x64) : Windows\r\n"),
        Some("7-Zip 26.02 (x64) : Windows")
    );
    assert_eq!(oracle_2602_banner("7-Zip 26.01 (x64) : Windows\r\n"), None);
}

#[test]
fn diagnostic_markers_retain_bounded_system_error_context() {
    assert_eq!(
        diagnostic_markers(b"", b"System ERROR:\r\nIncorrect function.\r\n"),
        "System ERROR: / Incorrect function."
    );
    assert_eq!(diagnostic_markers(b"ordinary output\n", b""), "none");

    let repeated =
        b"ERROR:\ncontext one\nERROR:\ncontext two\nERROR:\ncontext three\nERROR:\ncontext four\n";
    assert_eq!(diagnostic_markers(repeated, b"").split(" / ").count(), 6);
}

#[test]
#[ignore = "requires exact stock 7zz 26.02; emits a structured capability report"]
fn stock_7zz_2602_capability_probe_report() -> ProbeResult<()> {
    let version = require_7zz_2602()?;
    let directory = temporary_directory()?;
    let result = (|| -> ProbeResult<()> {
        println!("UNPACKIO_7ZZ_PROBE_VERSION\t{}", sanitize_field(&version));
        println!(
            "UNPACKIO_7ZZ_PROBE_COLUMNS\tname\tauthor\toracle-read\trust-read\tsha256\tdetail"
        );
        let outcomes = run_capability_probes(&directory)?;
        for outcome in &outcomes {
            outcome.print_tsv();
        }
        require_2602_baseline(&outcomes)?;
        require_windows_2602_baseline(&outcomes)?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&directory);
    result?;
    cleanup?;
    Ok(())
}
