//! Bounded, unpack-only ARJ archives.

mod decode;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
    checksum::Crc32,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, copy_bytes, try_reserve,
        usize_to_u64,
    },
};

const MAGIC: &[u8] = &[0x60, 0xea];
const MAX_BASIC_HEADER_BYTES: u64 = 2600;
const MAIN_FIXED_BYTES: u64 = 30;
const LOCAL_FIXED_BYTES: u64 = 30;

/// An ARJ member compression method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArjCompressionMethod {
    /// Stored bytes (method 0).
    Stored,
    /// Static-LZH "compressed most" (method 1).
    CompressedMost,
    /// Static-LZH "compressed" (method 2).
    Compressed,
    /// Static-LZH "compressed faster" (method 3).
    CompressedFaster,
    /// ARJ fastest LZ method (method 4).
    CompressedFastest,
    /// No data and no member CRC (method 8).
    NoDataNoCrc,
    /// No data with a member CRC (method 9).
    NoData,
    /// A method identifier not known by this implementation.
    Unknown(u8),
}

impl ArjCompressionMethod {
    /// Returns the exact numeric method identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::CompressedMost => 1,
            Self::Compressed => 2,
            Self::CompressedFaster => 3,
            Self::CompressedFastest => 4,
            Self::NoDataNoCrc => 8,
            Self::NoData => 9,
            Self::Unknown(identifier) => identifier,
        }
    }

    const fn from_id(identifier: u8) -> Self {
        match identifier {
            0 => Self::Stored,
            1 => Self::CompressedMost,
            2 => Self::Compressed,
            3 => Self::CompressedFaster,
            4 => Self::CompressedFastest,
            8 => Self::NoDataNoCrc,
            9 => Self::NoData,
            other => Self::Unknown(other),
        }
    }
}

/// The ARJ local-header file type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArjEntryKind {
    /// Binary file data.
    Binary,
    /// Seven-bit text data.
    Text,
    /// Comment-header data.
    Comment,
    /// A directory.
    Directory,
    /// A volume label.
    VolumeLabel,
    /// A chapter label.
    ChapterLabel,
    /// An unknown numeric file type.
    Unknown(u8),
}

impl ArjEntryKind {
    const fn from_id(identifier: u8) -> Self {
        match identifier {
            0 => Self::Binary,
            1 => Self::Text,
            2 => Self::Comment,
            3 => Self::Directory,
            4 => Self::VolumeLabel,
            5 => Self::ChapterLabel,
            other => Self::Unknown(other),
        }
    }
}

/// Owned metadata for one ARJ local member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArjEntry {
    index: u64,
    raw_name: Box<[u8]>,
    raw_comment: Box<[u8]>,
    archiver_version: u8,
    minimum_version: u8,
    host_os: u8,
    flags: u8,
    method: ArjCompressionMethod,
    kind: ArjEntryKind,
    modified_time: u32,
    compressed_size: u64,
    original_size: u64,
    crc32: Option<u32>,
    file_spec_position: u16,
    access_mode: u16,
    encrypted: bool,
    data_start: u64,
    data_end: u64,
}

impl ArjEntry {
    /// Returns the stable zero-based member index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the byte-preserving member name.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns a display-only lossy member name.
    #[must_use]
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.raw_name).into_owned()
    }

    /// Returns the byte-preserving member comment.
    #[must_use]
    pub fn raw_comment(&self) -> &[u8] {
        &self.raw_comment
    }

    /// Returns the creating archiver version.
    #[must_use]
    pub const fn archiver_version(&self) -> u8 {
        self.archiver_version
    }

    /// Returns the minimum extraction version.
    #[must_use]
    pub const fn minimum_version(&self) -> u8 {
        self.minimum_version
    }

    /// Returns the numeric host-OS identifier.
    #[must_use]
    pub const fn host_os(&self) -> u8 {
        self.host_os
    }

    /// Returns the raw local-header flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the compression method.
    #[must_use]
    pub const fn compression_method(&self) -> ArjCompressionMethod {
        self.method
    }

    /// Returns the ARJ file type.
    #[must_use]
    pub const fn kind(&self) -> ArjEntryKind {
        self.kind
    }

    /// Returns the packed DOS date/time bits.
    #[must_use]
    pub const fn modified_time_raw(&self) -> u32 {
        self.modified_time
    }

    /// Returns the stored compressed byte length.
    #[must_use]
    pub const fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Returns the declared unpacked byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.original_size
    }

    /// Returns the member CRC, absent only for method 8.
    #[must_use]
    pub const fn crc32(&self) -> Option<u32> {
        self.crc32
    }

    /// Returns the byte position of the filename portion in the stored name.
    #[must_use]
    pub const fn file_spec_position(&self) -> u16 {
        self.file_spec_position
    }

    /// Returns the host-dependent file access mode.
    #[must_use]
    pub const fn access_mode(&self) -> u16 {
        self.access_mode
    }

    /// Returns whether the member requires an ARJ password scheme.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

/// A callback boundary for natural-order ARJ extraction.
pub trait ArjEntrySink {
    /// Starts one member. Its raw name remains metadata and is never a path.
    fn begin_entry(&mut self, entry: &ArjEntry) -> Result<()>;

    /// Receives one bounded decoded member chunk.
    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> Result<()>;

    /// Reports success only after member CRC verification.
    fn finish_entry(&mut self, entry_index: u64) -> Result<()>;
}

/// An owned, bounded single-volume ARJ reader.
pub struct ArjArchive {
    bytes: Box<[u8]>,
    entries: Box<[ArjEntry]>,
    raw_name: Box<[u8]>,
    raw_comment: Box<[u8]>,
    sfx_offset: u64,
    archiver_version: u8,
    minimum_version: u8,
    host_os: u8,
    flags: u8,
    creation_time: u32,
    modification_time: u32,
    limits: Limits,
}

impl ArjArchive {
    /// Opens and validates an in-memory single-volume ARJ archive.
    ///
    /// Data CRCs are checked when entries are extracted or [`Self::verify`] is
    /// called. Names remain metadata and are never written to the filesystem.
    ///
    /// # Errors
    ///
    /// Returns a typed format, header-checksum, unsupported-feature, limit,
    /// cancellation, work-budget, or allocation error.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        check_limit(
            usize_to_u64(bytes.len(), "ARJ input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        let mut control = ParseControl::new(cancellation, budget);
        let mut totals = HeaderTotals::default();
        let (sfx_offset, main) = find_main_header(&bytes, limits, &mut totals, &mut control)?;
        let main_fields = parse_main_header(main.basic, limits, &mut control)?;
        let mut offset =
            read_extended_headers(&bytes, main.next_offset, limits, &mut totals, &mut control)?;
        if main_fields.flags & 0x04 != 0 || main_fields.last_chapter != 0 {
            return Err(Error::UnsupportedFeature {
                feature: String::from("arj-multi-volume"),
            });
        }
        if main_fields.flags & 0x08 != 0 || main_fields.flags & 0x40 != 0 {
            return Err(Error::UnsupportedFeature {
                feature: String::from("arj-security-envelope"),
            });
        }
        let mut entries = Vec::new();
        let mut total_name_bytes = usize_to_u64(
            main_fields.raw_name.len(),
            "ARJ archive name length is not representable",
        )?;
        loop {
            control.checkpoint(1)?;
            let Some(record) = read_header_at(&bytes, offset, limits, &mut totals, &mut control)?
            else {
                break;
            };
            let local = parse_local_header(record.basic, limits, &mut control)?;
            if local.flags & 0x0c != 0 || local.first_chapter != 0 || local.last_chapter != 0 {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("arj-split-member"),
                });
            }
            let data_start = read_extended_headers(
                &bytes,
                record.next_offset,
                limits,
                &mut totals,
                &mut control,
            )?;
            let data_end = data_start
                .checked_add(local.compressed_size)
                .ok_or_else(|| arj_format("member data range overflows"))?;
            let _ = checked_range(
                &bytes,
                data_start,
                local.compressed_size,
                "ARJ member data range overflows",
                "ARJ member data is truncated",
            )?;
            let next_count = usize_to_u64(entries.len(), "ARJ entry count is not representable")?
                .checked_add(1)
                .ok_or_else(|| arj_format("entry count overflows"))?;
            check_limit(next_count, limits.max_files(), LimitKind::Files)?;
            let name_length = usize_to_u64(
                local.raw_name.len(),
                "ARJ member name length is not representable",
            )?;
            check_limit(
                name_length,
                limits.max_name_bytes_per_entry(),
                LimitKind::NameBytesPerEntry,
            )?;
            total_name_bytes = total_name_bytes
                .checked_add(name_length)
                .ok_or_else(|| arj_format("total name bytes overflow"))?;
            check_limit(
                total_name_bytes,
                limits.max_total_name_bytes(),
                LimitKind::TotalNameBytes,
            )?;
            check_limit(
                local.original_size,
                limits.max_entry_output_bytes(),
                LimitKind::EntryOutputBytes,
            )?;
            if entries.len() == entries.capacity() {
                try_reserve(&mut entries, 1)?;
            }
            entries.push(ArjEntry {
                index: next_count
                    .checked_sub(1)
                    .ok_or_else(|| arj_format("entry index underflows"))?,
                raw_name: local.raw_name,
                raw_comment: local.raw_comment,
                archiver_version: local.archiver_version,
                minimum_version: local.minimum_version,
                host_os: local.host_os,
                flags: local.flags,
                method: local.method,
                kind: local.kind,
                modified_time: local.modified_time,
                compressed_size: local.compressed_size,
                original_size: local.original_size,
                crc32: local.crc32,
                file_spec_position: local.file_spec_position,
                access_mode: local.access_mode,
                encrypted: local.flags & 0x01 != 0,
                data_start,
                data_end,
            });
            offset = data_end;
        }
        let input_size = usize_to_u64(bytes.len(), "ARJ input size is not representable")?;
        let terminal_end = offset
            .checked_add(4)
            .ok_or_else(|| arj_format("end-header offset overflows"))?;
        let trailing_length = input_size
            .checked_sub(terminal_end)
            .ok_or_else(|| arj_format("terminal header extends beyond the input"))?;
        if trailing_length > 0 {
            let trailing_start = input_size
                .checked_sub(trailing_length)
                .ok_or_else(|| arj_format("trailing offset underflows"))?;
            let trailing = checked_range(
                &bytes,
                trailing_start,
                trailing_length,
                "ARJ trailing range overflows",
                "ARJ trailing range is truncated",
            )?;
            control.consume_bytes(trailing)?;
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            entries: entries.into_boxed_slice(),
            raw_name: main_fields.raw_name,
            raw_comment: main_fields.raw_comment,
            sfx_offset,
            archiver_version: main_fields.archiver_version,
            minimum_version: main_fields.minimum_version,
            host_os: main_fields.host_os,
            flags: main_fields.flags,
            creation_time: main_fields.creation_time,
            modification_time: main_fields.modification_time,
            limits,
        })
    }

    /// Opens an ARJ path without deriving extraction destinations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for input reads or any error documented by
    /// [`Self::open_bytes`].
    pub fn open_path(
        path: &Path,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let bytes = read_path(path, limits, cancellation, budget)?;
        Self::open_bytes(bytes, limits, cancellation, budget)
    }

    /// Returns entries in exact archive order, including duplicates.
    #[must_use]
    pub fn entries(&self) -> &[ArjEntry] {
        &self.entries
    }

    /// Returns one entry by stable member index.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&ArjEntry> {
        let index = usize::try_from(index).ok()?;
        self.entries.get(index)
    }

    /// Returns the byte-preserving archive name from the main header.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns the byte-preserving archive comment.
    #[must_use]
    pub fn raw_comment(&self) -> &[u8] {
        &self.raw_comment
    }

    /// Returns the offset of the validated main header, nonzero for SFX input.
    #[must_use]
    pub const fn sfx_offset(&self) -> u64 {
        self.sfx_offset
    }

    /// Returns the main-header archiver version.
    #[must_use]
    pub const fn archiver_version(&self) -> u8 {
        self.archiver_version
    }

    /// Returns the main-header minimum extraction version.
    #[must_use]
    pub const fn minimum_version(&self) -> u8 {
        self.minimum_version
    }

    /// Returns the numeric main-header host OS.
    #[must_use]
    pub const fn host_os(&self) -> u8 {
        self.host_os
    }

    /// Returns the raw main-header flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the packed archive creation DOS date/time.
    #[must_use]
    pub const fn creation_time_raw(&self) -> u32 {
        self.creation_time
    }

    /// Returns the packed archive modification DOS date/time.
    #[must_use]
    pub const fn modification_time_raw(&self) -> u32 {
        self.modification_time
    }

    /// Returns the retained limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns retained raw archive bytes for resource accounting.
    #[must_use]
    pub fn retained_input_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Decodes, verifies, and copies one entry to a caller-selected writer.
    ///
    /// # Errors
    ///
    /// Returns a typed index, password, unsupported-method, format, checksum,
    /// limit, cancellation, budget, allocation, or writer error. No bytes are
    /// written before the member CRC succeeds.
    pub fn extract_entry_to(
        &self,
        entry_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let entry = self.required_entry(entry_index)?;
        let mut control = ParseControl::new(cancellation, budget);
        let output = self.decode_verified(entry, &mut control)?;
        for chunk in output.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "ARJ output chunk length is not representable",
            )?)?;
            writer.write_all(chunk).map_err(Error::Io)?;
        }
        Ok(entry.original_size)
    }

    /// Extracts all entries in archive order with shared resource accounting.
    ///
    /// # Errors
    ///
    /// Returns the first member or sink error. `finish_entry` is called only
    /// after the member CRC succeeds and all verified bytes are delivered.
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn ArjEntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.original_size, self.limits)?;
            let output = self.decode_verified(entry, &mut control)?;
            sink.begin_entry(entry)?;
            for chunk in output.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "ARJ sink chunk length is not representable",
                )?)?;
                sink.write_entry(entry.index, chunk)?;
            }
            sink.finish_entry(entry.index)?;
        }
        Ok(total)
    }

    /// Decodes and verifies all members without retaining their output.
    ///
    /// # Errors
    ///
    /// Returns the first password, method, format, checksum, limit,
    /// cancellation, work-budget, or allocation error.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.original_size, self.limits)?;
            let _ = self.decode_verified(entry, &mut control)?;
        }
        Ok(())
    }

    fn required_entry(&self, index: u64) -> Result<&ArjEntry> {
        let index = usize::try_from(index).map_err(|_| arj_format("entry index is too large"))?;
        self.entries
            .get(index)
            .ok_or_else(|| arj_format("entry index is out of range"))
    }

    fn decode_verified(&self, entry: &ArjEntry, control: &mut ParseControl<'_>) -> Result<Vec<u8>> {
        if entry.encrypted {
            return Err(Error::PasswordRequired);
        }
        let length = entry
            .data_end
            .checked_sub(entry.data_start)
            .ok_or_else(|| arj_format("member data range underflows"))?;
        let compressed = checked_range(
            &self.bytes,
            entry.data_start,
            length,
            "ARJ member data range overflows",
            "ARJ member data range is invalid",
        )?;
        let output = decode::decode(
            compressed,
            entry.method,
            entry.original_size,
            self.limits,
            control,
        )?;
        if let Some(expected) = entry.crc32 {
            let actual = crc32(&output, control)?;
            if actual != expected {
                return Err(Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(entry.index),
                });
            }
        }
        Ok(output)
    }
}

#[derive(Default)]
struct HeaderTotals {
    bytes: u64,
    properties: u64,
}

struct HeaderRecord<'data> {
    basic: &'data [u8],
    next_offset: u64,
}

struct MainFields {
    raw_name: Box<[u8]>,
    raw_comment: Box<[u8]>,
    archiver_version: u8,
    minimum_version: u8,
    host_os: u8,
    flags: u8,
    creation_time: u32,
    modification_time: u32,
    last_chapter: u8,
}

struct LocalFields {
    raw_name: Box<[u8]>,
    raw_comment: Box<[u8]>,
    archiver_version: u8,
    minimum_version: u8,
    host_os: u8,
    flags: u8,
    method: ArjCompressionMethod,
    kind: ArjEntryKind,
    modified_time: u32,
    compressed_size: u64,
    original_size: u64,
    crc32: Option<u32>,
    file_spec_position: u16,
    access_mode: u16,
    first_chapter: u8,
    last_chapter: u8,
}

fn find_main_header<'data>(
    bytes: &'data [u8],
    limits: Limits,
    totals: &mut HeaderTotals,
    control: &mut ParseControl<'_>,
) -> Result<(u64, HeaderRecord<'data>)> {
    let mut saw_checksum_failure = false;
    let scan_limit = limits.sfx_scan_limit();
    for (position, pair) in bytes.windows(2).enumerate() {
        let position_u64 = usize_to_u64(position, "ARJ scan position is not representable")?;
        if position_u64 > scan_limit {
            break;
        }
        control.checkpoint(1)?;
        if pair != MAGIC {
            continue;
        }
        let size_offset = position_u64
            .checked_add(2)
            .ok_or_else(|| arj_format("candidate header size offset overflows"))?;
        let Ok(size) = le_u16(bytes, size_offset, "candidate header size is truncated") else {
            continue;
        };
        let size = u64::from(size);
        if size == 0 || size > MAX_BASIC_HEADER_BYTES {
            continue;
        }
        check_limit(size, limits.max_header_bytes(), LimitKind::HeaderBytes)?;
        let basic_start = position_u64
            .checked_add(4)
            .ok_or_else(|| arj_format("candidate basic-header offset overflows"))?;
        let Ok(basic) = checked_range(
            bytes,
            basic_start,
            size,
            "ARJ candidate basic-header range overflows",
            "ARJ candidate basic header is truncated",
        ) else {
            continue;
        };
        let crc_offset = basic_start
            .checked_add(size)
            .ok_or_else(|| arj_format("candidate CRC offset overflows"))?;
        let Ok(expected) = le_u32(bytes, crc_offset, "candidate header CRC is truncated") else {
            continue;
        };
        if crc32(basic, control)? != expected {
            saw_checksum_failure = true;
            continue;
        }
        account_header(size, limits, totals)?;
        let next_offset = crc_offset
            .checked_add(4)
            .ok_or_else(|| arj_format("candidate header end overflows"))?;
        return Ok((position_u64, HeaderRecord { basic, next_offset }));
    }
    if saw_checksum_failure {
        Err(Error::Checksum {
            scope: ChecksumScope::PackageHeader,
            member_index: None,
        })
    } else if usize_to_u64(bytes.len(), "ARJ input size is not representable")? > scan_limit {
        Err(Error::LimitExceeded {
            limit: LimitKind::SfxScanBytes,
            requested: scan_limit
                .checked_add(1)
                .ok_or_else(|| arj_format("SFX scan-limit report overflows"))?,
            maximum: scan_limit,
        })
    } else {
        Err(arj_format("validated main header is missing"))
    }
}

fn read_header_at<'data>(
    bytes: &'data [u8],
    offset: u64,
    limits: Limits,
    totals: &mut HeaderTotals,
    control: &mut ParseControl<'_>,
) -> Result<Option<HeaderRecord<'data>>> {
    let magic = checked_range(
        bytes,
        offset,
        2,
        "ARJ header magic range overflows",
        "ARJ header magic is truncated",
    )?;
    if magic != MAGIC {
        return Err(arj_format("local header magic is invalid"));
    }
    let size_offset = offset
        .checked_add(2)
        .ok_or_else(|| arj_format("header size offset overflows"))?;
    let size = u64::from(le_u16(bytes, size_offset, "header size is truncated")?);
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_BASIC_HEADER_BYTES {
        return Err(arj_format("basic header exceeds the format maximum"));
    }
    check_limit(size, limits.max_header_bytes(), LimitKind::HeaderBytes)?;
    let basic_start = offset
        .checked_add(4)
        .ok_or_else(|| arj_format("basic-header offset overflows"))?;
    let basic = checked_range(
        bytes,
        basic_start,
        size,
        "ARJ basic-header range overflows",
        "ARJ basic header is truncated",
    )?;
    let crc_offset = basic_start
        .checked_add(size)
        .ok_or_else(|| arj_format("header CRC offset overflows"))?;
    let expected = le_u32(bytes, crc_offset, "header CRC is truncated")?;
    if crc32(basic, control)? != expected {
        return Err(Error::Checksum {
            scope: ChecksumScope::PackageHeader,
            member_index: None,
        });
    }
    account_header(size, limits, totals)?;
    Ok(Some(HeaderRecord {
        basic,
        next_offset: crc_offset
            .checked_add(4)
            .ok_or_else(|| arj_format("header end offset overflows"))?,
    }))
}

fn read_extended_headers(
    bytes: &[u8],
    mut offset: u64,
    limits: Limits,
    totals: &mut HeaderTotals,
    control: &mut ParseControl<'_>,
) -> Result<u64> {
    loop {
        control.checkpoint(1)?;
        let size = u64::from(le_u16(bytes, offset, "extended-header size is truncated")?);
        offset = offset
            .checked_add(2)
            .ok_or_else(|| arj_format("extended-header offset overflows"))?;
        totals.bytes = totals
            .bytes
            .checked_add(2)
            .ok_or_else(|| arj_format("total header bytes overflow"))?;
        check_limit(
            totals.bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        if size == 0 {
            return Ok(offset);
        }
        totals.properties = totals
            .properties
            .checked_add(1)
            .ok_or_else(|| arj_format("extended-header count overflows"))?;
        check_limit(
            totals.properties,
            limits.max_header_properties(),
            LimitKind::HeaderProperties,
        )?;
        check_limit(size, limits.max_header_bytes(), LimitKind::HeaderBytes)?;
        let extension = checked_range(
            bytes,
            offset,
            size,
            "ARJ extended-header range overflows",
            "ARJ extended header is truncated",
        )?;
        let crc_offset = offset
            .checked_add(size)
            .ok_or_else(|| arj_format("extended-header CRC offset overflows"))?;
        let expected = le_u32(bytes, crc_offset, "extended-header CRC is truncated")?;
        if crc32(extension, control)? != expected {
            return Err(Error::Checksum {
                scope: ChecksumScope::PackageHeader,
                member_index: None,
            });
        }
        totals.bytes = totals
            .bytes
            .checked_add(size)
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| arj_format("total header bytes overflow"))?;
        check_limit(
            totals.bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        offset = crc_offset
            .checked_add(4)
            .ok_or_else(|| arj_format("extended-header end offset overflows"))?;
    }
}

fn parse_main_header(
    basic: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<MainFields> {
    if usize_to_u64(basic.len(), "ARJ main header size is not representable")? < MAIN_FIXED_BYTES {
        return Err(arj_format("main header is too short"));
    }
    let first_size = u64::from(byte(basic, 0, "main first-header size is truncated")?);
    if first_size < MAIN_FIXED_BYTES
        || first_size > usize_to_u64(basic.len(), "ARJ main header size is not representable")?
    {
        return Err(arj_format("main first-header size is invalid"));
    }
    if byte(basic, 6, "main file type is truncated")? != 2 {
        return Err(arj_format("main header file type is invalid"));
    }
    let (name, comment) = parse_strings(basic, first_size)?;
    validate_header_strings(name, comment, limits)?;
    Ok(MainFields {
        raw_name: copy_bytes(name, control)?,
        raw_comment: copy_bytes(comment, control)?,
        archiver_version: byte(basic, 1, "main archiver version is truncated")?,
        minimum_version: byte(basic, 2, "main minimum version is truncated")?,
        host_os: byte(basic, 3, "main host OS is truncated")?,
        flags: byte(basic, 4, "main flags are truncated")?,
        creation_time: le_u32(basic, 8, "main creation time is truncated")?,
        modification_time: le_u32(basic, 12, "main modification time is truncated")?,
        last_chapter: byte(basic, 29, "main last chapter is truncated")?,
    })
}

fn parse_local_header(
    basic: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<LocalFields> {
    if usize_to_u64(basic.len(), "ARJ local header size is not representable")? < LOCAL_FIXED_BYTES
    {
        return Err(arj_format("local header is too short"));
    }
    let first_size = u64::from(byte(basic, 0, "local first-header size is truncated")?);
    if first_size < LOCAL_FIXED_BYTES
        || first_size > usize_to_u64(basic.len(), "ARJ local header size is not representable")?
    {
        return Err(arj_format("local first-header size is invalid"));
    }
    let (name, comment) = parse_strings(basic, first_size)?;
    if name.is_empty() {
        return Err(arj_format("local member name is empty"));
    }
    validate_header_strings(name, comment, limits)?;
    let method = ArjCompressionMethod::from_id(byte(basic, 5, "local method is truncated")?);
    let declared_crc = le_u32(basic, 20, "local CRC is truncated")?;
    Ok(LocalFields {
        raw_name: copy_bytes(name, control)?,
        raw_comment: copy_bytes(comment, control)?,
        archiver_version: byte(basic, 1, "local archiver version is truncated")?,
        minimum_version: byte(basic, 2, "local minimum version is truncated")?,
        host_os: byte(basic, 3, "local host OS is truncated")?,
        flags: byte(basic, 4, "local flags are truncated")?,
        method,
        kind: ArjEntryKind::from_id(byte(basic, 6, "local file type is truncated")?),
        modified_time: le_u32(basic, 8, "local modification time is truncated")?,
        compressed_size: u64::from(le_u32(basic, 12, "local compressed size is truncated")?),
        original_size: u64::from(le_u32(basic, 16, "local original size is truncated")?),
        crc32: (method != ArjCompressionMethod::NoDataNoCrc).then_some(declared_crc),
        file_spec_position: le_u16(basic, 24, "local file-spec position is truncated")?,
        access_mode: le_u16(basic, 26, "local access mode is truncated")?,
        first_chapter: byte(basic, 28, "local first chapter is truncated")?,
        last_chapter: byte(basic, 29, "local last chapter is truncated")?,
    })
}

fn parse_strings(basic: &[u8], first_size: u64) -> Result<(&[u8], &[u8])> {
    let remaining_length = usize_to_u64(basic.len(), "ARJ header size is not representable")?
        .checked_sub(first_size)
        .ok_or_else(|| arj_format("header string range underflows"))?;
    let strings = checked_range(
        basic,
        first_size,
        remaining_length,
        "ARJ header string range overflows",
        "ARJ header strings are truncated",
    )?;
    let name_end = strings
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| arj_format("header name is not NUL terminated"))?;
    let name = strings
        .get(..name_end)
        .ok_or_else(|| arj_format("header name range is invalid"))?;
    let comment_start = name_end
        .checked_add(1)
        .ok_or_else(|| arj_format("header comment offset overflows"))?;
    let comments = strings
        .get(comment_start..)
        .ok_or_else(|| arj_format("header comment is truncated"))?;
    let comment_end = comments
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| arj_format("header comment is not NUL terminated"))?;
    let comment = comments
        .get(..comment_end)
        .ok_or_else(|| arj_format("header comment range is invalid"))?;
    Ok((name, comment))
}

fn validate_header_strings(name: &[u8], comment: &[u8], limits: Limits) -> Result<()> {
    check_limit(
        usize_to_u64(name.len(), "ARJ name length is not representable")?,
        limits.max_name_bytes_per_entry(),
        LimitKind::NameBytesPerEntry,
    )?;
    check_limit(
        usize_to_u64(comment.len(), "ARJ comment length is not representable")?,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )
}

fn account_header(size: u64, limits: Limits, totals: &mut HeaderTotals) -> Result<()> {
    totals.bytes = totals
        .bytes
        .checked_add(size)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| arj_format("total header bytes overflow"))?;
    check_limit(
        totals.bytes,
        limits.max_header_bytes(),
        LimitKind::HeaderBytes,
    )
}

fn crc32(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "ARJ checksum chunk length is not representable",
        )?)?;
        checksum.update(chunk)?;
    }
    Ok(checksum.finalize())
}

fn byte(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u8> {
    checked_range(bytes, offset, 1, detail, detail)?
        .first()
        .copied()
        .ok_or_else(|| arj_format(detail))
}

fn le_u16(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u16> {
    let value = checked_range(bytes, offset, 2, detail, detail)?;
    let first = value.first().copied().ok_or_else(|| arj_format(detail))?;
    let second = value.get(1).copied().ok_or_else(|| arj_format(detail))?;
    Ok(u16::from_le_bytes([first, second]))
}

fn le_u32(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u32> {
    let value = checked_range(bytes, offset, 4, detail, detail)?;
    let array = <[u8; 4]>::try_from(value).map_err(|_| arj_format(detail))?;
    Ok(u32::from_le_bytes(array))
}

fn checked_output_total(current: u64, entry_size: u64, limits: Limits) -> Result<u64> {
    check_limit(
        entry_size,
        limits.max_entry_output_bytes(),
        LimitKind::EntryOutputBytes,
    )?;
    let total = current
        .checked_add(entry_size)
        .ok_or(Error::LimitExceeded {
            limit: LimitKind::TotalOutputBytes,
            requested: u64::MAX,
            maximum: limits.max_total_output_bytes(),
        })?;
    check_limit(
        total,
        limits.max_total_output_bytes(),
        LimitKind::TotalOutputBytes,
    )?;
    Ok(total)
}

fn read_path(
    path: &Path,
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> Result<Vec<u8>> {
    let metadata = path.metadata().map_err(Error::Io)?;
    check_limit(
        metadata.len(),
        limits.max_total_input_bytes(),
        LimitKind::TotalInputBytes,
    )?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| arj_format("path size is not representable on this platform"))?;
    let mut bytes = Vec::new();
    try_reserve(&mut bytes, capacity)?;
    let mut file = File::open(path).map_err(Error::Io)?;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    loop {
        cancellation.check()?;
        let read = file.read(&mut buffer).map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| arj_format("path read returned an invalid byte count"))?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "ARJ input chunk length is not representable",
        )?)?;
        let requested = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| arj_format("path input size overflows"))?;
        check_limit(
            usize_to_u64(requested, "ARJ path input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn arj_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ARJ: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ArjArchive, ArjCompressionMethod};
    use crate::{CancellationToken, Error, LimitKind, Limits, Result, WorkBudget, checksum::Crc32};

    fn u32_len(value: usize) -> Result<u32> {
        u32::try_from(value).map_err(|_| Error::Format {
            detail: String::from("test ARJ length is too large"),
        })
    }

    fn append_header(output: &mut Vec<u8>, basic: &[u8]) -> Result<()> {
        output.extend_from_slice(super::MAGIC);
        let size = u16::try_from(basic.len()).map_err(|_| Error::Format {
            detail: String::from("test ARJ header is too large"),
        })?;
        output.extend_from_slice(&size.to_le_bytes());
        output.extend_from_slice(basic);
        output.extend_from_slice(&Crc32::checksum(basic)?.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes());
        Ok(())
    }

    fn main_header() -> Vec<u8> {
        let mut header = vec![0_u8; 30];
        if let Some(value) = header.get_mut(0) {
            *value = 30;
        }
        if let Some(value) = header.get_mut(1) {
            *value = 11;
        }
        if let Some(value) = header.get_mut(2) {
            *value = 1;
        }
        if let Some(value) = header.get_mut(3) {
            *value = 2;
        }
        if let Some(value) = header.get_mut(6) {
            *value = 2;
        }
        header.extend_from_slice(b"fixture.arj\0generated\0");
        header
    }

    fn local_header(name: &[u8], data: &[u8], method: u8, crc: u32, flags: u8) -> Result<Vec<u8>> {
        let mut header = vec![0_u8; 30];
        let values = [
            (0_usize, 30_u8),
            (1, 11),
            (2, 1),
            (3, 2),
            (4, flags),
            (5, method),
            (6, 0),
        ];
        for (offset, value) in values {
            let target = header.get_mut(offset).ok_or_else(|| Error::Format {
                detail: String::from("test ARJ local field is missing"),
            })?;
            *target = value;
        }
        header
            .get_mut(12..16)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ARJ compressed-size field is missing"),
            })?
            .copy_from_slice(&u32_len(data.len())?.to_le_bytes());
        header
            .get_mut(16..20)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ARJ original-size field is missing"),
            })?
            .copy_from_slice(&u32_len(data.len())?.to_le_bytes());
        header
            .get_mut(20..24)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ARJ CRC field is missing"),
            })?
            .copy_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(name);
        header.push(0);
        header.push(0);
        Ok(header)
    }

    fn stored_fixture(flags: u8, member_crc: Option<u32>) -> Result<Vec<u8>> {
        let data = b"hello ARJ";
        let crc = member_crc.unwrap_or(Crc32::checksum(data)?);
        method_fixture(0, data, flags, crc)
    }

    fn method_fixture(method: u8, data: &[u8], flags: u8, crc: u32) -> Result<Vec<u8>> {
        let mut archive = Vec::new();
        append_header(&mut archive, &main_header())?;
        append_header(
            &mut archive,
            &local_header(b"hello.txt", data, method, crc, flags)?,
        )?;
        archive.extend_from_slice(data);
        archive.extend_from_slice(super::MAGIC);
        archive.extend_from_slice(&0_u16.to_le_bytes());
        Ok(archive)
    }

    fn open(bytes: Vec<u8>) -> Result<ArjArchive> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        ArjArchive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)
    }

    #[test]
    fn lists_and_extracts_stored_member_with_crc() -> Result<()> {
        let archive = open(stored_fixture(0, None)?)?;
        assert_eq!(archive.raw_name(), b"fixture.arj");
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(
            archive
                .entries()
                .first()
                .map(|entry| entry.compression_method()),
            Some(ArjCompressionMethod::Stored)
        );
        let mut output = Vec::new();
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
        assert_eq!(output, b"hello ARJ");
        Ok(())
    }

    #[test]
    fn handles_sfx_no_data_methods_and_unknown_methods_explicitly() -> Result<()> {
        let fixture = stored_fixture(0, None)?;
        let mut sfx = b"MZ\x90\0bounded SFX prefix".to_vec();
        let expected_offset = u64::try_from(sfx.len()).map_err(|_| Error::Format {
            detail: String::from("test SFX prefix length is too large"),
        })?;
        sfx.extend_from_slice(&fixture);
        let archive = open(sfx)?;
        assert_eq!(archive.sfx_offset(), expected_offset);

        for method in [8_u8, 9] {
            let archive = open(method_fixture(method, b"", 0, 0)?)?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut output = Vec::new();
            archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
            assert!(output.is_empty());
            assert_eq!(
                archive.entries().first().and_then(|entry| entry.crc32()),
                (method == 9).then_some(0)
            );
        }

        let unsupported = open(method_fixture(7, b"payload", 0, 0)?)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut output = Vec::new();
        assert!(matches!(
            unsupported.extract_entry_to(0, &mut output, &cancellation, &mut budget),
            Err(Error::UnsupportedMethod { .. })
        ));

        let limits = Limits::builder()
            .sfx_scan_limit(
                expected_offset
                    .checked_sub(1)
                    .ok_or_else(|| super::arj_format("test SFX offset underflows"))?,
            )
            .build();
        let mut prefixed = b"MZ\x90\0bounded SFX prefix".to_vec();
        prefixed.extend_from_slice(&fixture);
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            ArjArchive::open_bytes(prefixed, limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::SfxScanBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_header_and_member_corruption_truncation_passwords_and_limits() -> Result<()> {
        let mut header_corrupt = stored_fixture(0, None)?;
        let local_magic = header_corrupt
            .windows(2)
            .enumerate()
            .filter_map(|(position, value)| (value == super::MAGIC).then_some(position))
            .nth(1)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ARJ local header is missing"),
            })?;
        let corrupt_offset = local_magic.checked_add(10).ok_or_else(|| Error::Format {
            detail: String::from("test ARJ corruption offset overflows"),
        })?;
        let byte = header_corrupt
            .get_mut(corrupt_offset)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ARJ header byte is missing"),
            })?;
        *byte ^= 1;
        assert!(matches!(open(header_corrupt), Err(Error::Checksum { .. })));

        let bad_crc = open(stored_fixture(0, Some(1))?)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            bad_crc.verify(&cancellation, &mut budget),
            Err(Error::Checksum { .. })
        ));

        let encrypted = open(stored_fixture(1, None)?)?;
        let mut output = Vec::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            encrypted.extract_entry_to(0, &mut output, &cancellation, &mut budget),
            Err(Error::PasswordRequired)
        ));

        let mut truncated = stored_fixture(0, None)?;
        let _ = truncated.pop();
        assert!(open(truncated).is_err());

        let limits = Limits::builder().max_files(0).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            ArjArchive::open_bytes(stored_fixture(0, None)?, limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::Files,
                ..
            })
        ));
        Ok(())
    }
}
