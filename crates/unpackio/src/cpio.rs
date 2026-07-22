//! Bounded, unpack-only CPIO archives.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, copy_bytes, try_reserve,
        usize_to_u64,
    },
};

const NEWC_HEADER_BYTES: u64 = 110;
const ODC_HEADER_BYTES: u64 = 76;
const BINARY_HEADER_BYTES: u64 = 26;
const MAGIC_NEWC: &[u8] = b"070701";
const MAGIC_CRC: &[u8] = b"070702";
const MAGIC_ODC: &[u8] = b"070707";
const MAGIC_LARGE: &[u8] = b"07070X";
const BINARY_MAGIC: u16 = 0x71c7;
const TRAILER: &[u8] = b"TRAILER!!!";

/// The concrete CPIO header representation used by an archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CpioFormat {
    /// SVR4 ASCII `newc` without per-member checksums.
    Newc,
    /// SVR4 ASCII `newc` with the byte-sum checksum field.
    CrcNewc,
    /// POSIX portable ASCII (odc).
    Odc,
    /// Historical binary CPIO with little-endian 16-bit words.
    BinaryLittleEndian,
    /// Historical binary CPIO with big-endian 16-bit words.
    BinaryBigEndian,
    /// An archive containing more than one recognized header representation.
    Mixed,
}

/// Owned metadata for one CPIO member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpioEntry {
    index: u64,
    format: CpioFormat,
    raw_name: Box<[u8]>,
    inode: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    link_count: u32,
    modified_time: u64,
    size: u64,
    device_major: u32,
    device_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
    pub(crate) checksum: Option<u32>,
    pub(crate) data_start: u64,
    pub(crate) data_end: u64,
}

impl CpioEntry {
    /// Returns the stable zero-based member-order index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns this member's concrete header representation.
    #[must_use]
    pub const fn format(&self) -> CpioFormat {
        self.format
    }

    /// Returns the exact member-name bytes.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns a display-only lossy rendering of [`Self::raw_name`].
    #[must_use]
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.raw_name).into_owned()
    }

    /// Returns the CPIO inode number.
    #[must_use]
    pub const fn inode(&self) -> u32 {
        self.inode
    }

    /// Returns the complete mode, including file-type bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the numeric owner identifier.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the numeric group identifier.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the declared hard-link count.
    #[must_use]
    pub const fn link_count(&self) -> u32 {
        self.link_count
    }

    /// Returns the POSIX timestamp in seconds since the epoch.
    #[must_use]
    pub const fn modified_time(&self) -> u64 {
        self.modified_time
    }

    /// Returns the declared member byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the source-device major number when represented separately.
    #[must_use]
    pub const fn device_major(&self) -> u32 {
        self.device_major
    }

    /// Returns the source-device minor number or legacy unsplit device value.
    #[must_use]
    pub const fn device_minor(&self) -> u32 {
        self.device_minor
    }

    /// Returns the represented-device major number when stored separately.
    #[must_use]
    pub const fn rdev_major(&self) -> u32 {
        self.rdev_major
    }

    /// Returns the represented-device minor number or legacy unsplit value.
    #[must_use]
    pub const fn rdev_minor(&self) -> u32 {
        self.rdev_minor
    }

    /// Returns the CRC-newc byte-sum checksum, or `None` for other variants.
    #[must_use]
    pub const fn checksum(&self) -> Option<u32> {
        self.checksum
    }

    /// Returns whether the mode denotes a regular file.
    #[must_use]
    pub const fn is_regular_file(&self) -> bool {
        self.mode & 0o170_000 == 0o100_000
    }

    /// Returns whether the mode denotes a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.mode & 0o170_000 == 0o040_000
    }

    /// Returns whether the mode denotes a symbolic link.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.mode & 0o170_000 == 0o120_000
    }
}

/// A callback boundary for natural-order CPIO extraction.
pub trait CpioEntrySink {
    /// Starts one member. Its raw name remains metadata and is never a path.
    fn begin_entry(&mut self, entry: &CpioEntry) -> Result<()>;

    /// Receives one bounded member chunk.
    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> Result<()>;

    /// Reports success only after applicable member integrity checks.
    fn finish_entry(&mut self, entry_index: u64) -> Result<()>;
}

/// An owned, bounded standalone CPIO reader.
pub struct CpioArchive {
    bytes: Box<[u8]>,
    entries: Box<[CpioEntry]>,
    format: CpioFormat,
    limits: Limits,
}

impl CpioArchive {
    /// Opens in-memory CPIO bytes without interpreting names as paths.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, limit, cancellation, work-budget, or
    /// allocation error.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        check_limit(
            usize_to_u64(bytes.len(), "CPIO input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        let mut control = ParseControl::new(cancellation, budget);
        let (format, entries) = parse_entries(&bytes, limits, &mut control)?;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            entries: entries.into_boxed_slice(),
            format,
            limits,
        })
    }

    /// Opens a CPIO path without deriving any extraction destination.
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

    /// Returns the archive's concrete header representation.
    #[must_use]
    pub const fn format(&self) -> CpioFormat {
        self.format
    }

    /// Returns entries in exact archive order, including duplicates.
    #[must_use]
    pub fn entries(&self) -> &[CpioEntry] {
        &self.entries
    }

    /// Returns one entry by stable archive-order index.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&CpioEntry> {
        let index = usize::try_from(index).ok()?;
        self.entries.get(index)
    }

    /// Returns the limits retained for extraction operations.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns retained input bytes for resource accounting.
    #[must_use]
    pub fn retained_input_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Returns a symlink's byte-preserving target, or `None` for other kinds.
    ///
    /// # Errors
    ///
    /// Returns a typed range or index error if retained state is inconsistent.
    pub fn symlink_target(&self, entry_index: u64) -> Result<Option<&[u8]>> {
        let entry = self.required_entry(entry_index)?;
        if !entry.is_symlink() {
            return Ok(None);
        }
        self.data(entry).map(Some)
    }

    /// Verifies and copies one member to a caller-selected writer.
    ///
    /// # Errors
    ///
    /// Returns a typed index, checksum, limit, cancellation, budget, or writer
    /// error. Integrity is checked before the first output write.
    pub fn extract_entry_to(
        &self,
        entry_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let entry = self.required_entry(entry_index)?;
        let mut control = ParseControl::new(cancellation, budget);
        let data = self.verified_data(entry, &mut control)?;
        check_limit(
            entry.size,
            self.limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        for chunk in data.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "CPIO output chunk length is not representable",
            )?)?;
            writer.write_all(chunk).map_err(Error::Io)?;
        }
        Ok(entry.size)
    }

    /// Extracts all members in archive order with shared resource accounting.
    ///
    /// # Errors
    ///
    /// Returns the first member or sink error. `finish_entry` is called only
    /// after the current member's applicable checksum succeeds.
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn CpioEntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.size, self.limits)?;
            let data = self.verified_data(entry, &mut control)?;
            sink.begin_entry(entry)?;
            for chunk in data.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "CPIO sink chunk length is not representable",
                )?)?;
                sink.write_entry(entry.index, chunk)?;
            }
            sink.finish_entry(entry.index)?;
        }
        Ok(total)
    }

    /// Rechecks every applicable member checksum and discards the bytes.
    ///
    /// # Errors
    ///
    /// Returns the first checksum, range, limit, cancellation, or budget error.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.size, self.limits)?;
            self.verified_data(entry, &mut control)?;
        }
        Ok(())
    }

    fn required_entry(&self, index: u64) -> Result<&CpioEntry> {
        let index = usize::try_from(index).map_err(|_| cpio_format("entry index is too large"))?;
        self.entries
            .get(index)
            .ok_or_else(|| cpio_format("entry index is out of range"))
    }

    fn data<'archive>(&'archive self, entry: &CpioEntry) -> Result<&'archive [u8]> {
        let length = entry
            .data_end
            .checked_sub(entry.data_start)
            .ok_or_else(|| cpio_format("member data range underflows"))?;
        checked_range(
            &self.bytes,
            entry.data_start,
            length,
            "CPIO member data range overflows",
            "CPIO member data range is invalid",
        )
    }

    fn verified_data<'archive>(
        &'archive self,
        entry: &CpioEntry,
        control: &mut ParseControl<'_>,
    ) -> Result<&'archive [u8]> {
        let data = self.data(entry)?;
        verify_checksum(data, entry, control)?;
        Ok(data)
    }
}

struct ParsedHeader {
    format: CpioFormat,
    header_bytes: u64,
    alignment: u64,
    inode: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    link_count: u32,
    modified_time: u64,
    file_size: u64,
    device_major: u32,
    device_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
    name_size: u64,
    checksum: Option<u32>,
}

pub(crate) fn parse_entries(
    payload: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<(CpioFormat, Vec<CpioEntry>)> {
    let mut entries = Vec::new();
    let mut offset = 0_u64;
    let mut total_name_bytes = 0_u64;
    let mut total_header_bytes = 0_u64;
    let payload_size = usize_to_u64(payload.len(), "CPIO payload size is not representable")?;
    let mut archive_format = None;
    let mut saw_trailer = false;
    while offset < payload_size {
        control.checkpoint(1)?;
        let parsed = parse_header(payload, offset)?;
        archive_format = Some(match archive_format {
            None => parsed.format,
            Some(CpioFormat::Mixed) => CpioFormat::Mixed,
            Some(current) if current == parsed.format => current,
            Some(_) => CpioFormat::Mixed,
        });
        total_header_bytes = total_header_bytes
            .checked_add(parsed.header_bytes)
            .and_then(|value| value.checked_add(parsed.name_size))
            .ok_or_else(|| cpio_format("total header bytes overflow"))?;
        check_limit(
            total_header_bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        if parsed.name_size == 0 {
            return Err(cpio_format("name size is zero"));
        }
        let name_start = offset
            .checked_add(parsed.header_bytes)
            .ok_or_else(|| cpio_format("name offset overflows"))?;
        let name_with_nul = checked_range(
            payload,
            name_start,
            parsed.name_size,
            "CPIO name range overflows",
            "CPIO name is truncated",
        )?;
        if name_with_nul.last() != Some(&0) {
            return Err(cpio_format("name is not NUL terminated"));
        }
        let name_length = parsed
            .name_size
            .checked_sub(1)
            .ok_or_else(|| cpio_format("name length underflows"))?;
        let name = checked_range(
            name_with_nul,
            0,
            name_length,
            "CPIO name range overflows",
            "CPIO name is truncated",
        )?;
        if name.contains(&0) {
            return Err(cpio_format("name contains an embedded NUL"));
        }
        let unaligned_data = name_start
            .checked_add(parsed.name_size)
            .ok_or_else(|| cpio_format("data offset overflows"))?;
        let data_start = align_up(unaligned_data, parsed.alignment)?;
        validate_zero_padding(payload, unaligned_data, data_start)?;
        let data_end = data_start
            .checked_add(parsed.file_size)
            .ok_or_else(|| cpio_format("data range overflows"))?;
        let data = checked_range(
            payload,
            data_start,
            parsed.file_size,
            "CPIO data range overflows",
            "CPIO member data is truncated",
        )?;
        let record_end = align_up(data_end, parsed.alignment)?;
        validate_zero_padding(payload, data_end, record_end)?;

        if name == TRAILER {
            if parsed.file_size != 0 {
                return Err(cpio_format("trailer has data"));
            }
            offset = record_end;
            saw_trailer = true;
            break;
        }

        let next_count = usize_to_u64(entries.len(), "CPIO entry count is not representable")?
            .checked_add(1)
            .ok_or_else(|| cpio_format("entry count overflows"))?;
        check_limit(next_count, limits.max_files(), LimitKind::Files)?;
        check_limit(
            name_length,
            limits.max_name_bytes_per_entry(),
            LimitKind::NameBytesPerEntry,
        )?;
        total_name_bytes = total_name_bytes
            .checked_add(name_length)
            .ok_or_else(|| cpio_format("total name bytes overflow"))?;
        check_limit(
            total_name_bytes,
            limits.max_total_name_bytes(),
            LimitKind::TotalNameBytes,
        )?;
        check_limit(
            parsed.file_size,
            limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        let entry_index = next_count
            .checked_sub(1)
            .ok_or_else(|| cpio_format("entry index underflows"))?;
        let entry = CpioEntry {
            index: entry_index,
            format: parsed.format,
            raw_name: copy_bytes(name, control)?,
            inode: parsed.inode,
            mode: parsed.mode,
            uid: parsed.uid,
            gid: parsed.gid,
            link_count: parsed.link_count,
            modified_time: parsed.modified_time,
            size: parsed.file_size,
            device_major: parsed.device_major,
            device_minor: parsed.device_minor,
            rdev_major: parsed.rdev_major,
            rdev_minor: parsed.rdev_minor,
            checksum: parsed.checksum,
            data_start,
            data_end,
        };
        verify_checksum(data, &entry, control)?;
        if entries.len() == entries.capacity() {
            try_reserve(&mut entries, 1)?;
        }
        entries.push(entry);
        offset = record_end;
    }
    if !saw_trailer {
        return Err(cpio_format("trailer is missing"));
    }
    let trailing = checked_range(
        payload,
        offset,
        payload_size
            .checked_sub(offset)
            .ok_or_else(|| cpio_format("trailing range underflows"))?,
        "CPIO trailing range overflows",
        "CPIO trailing range is truncated",
    )?;
    if trailing.iter().any(|byte| *byte != 0) {
        return Err(cpio_format("payload has nonzero bytes after its trailer"));
    }
    let format = archive_format.ok_or_else(|| cpio_format("archive is empty"))?;
    Ok((format, entries))
}

pub(crate) fn byte_sum(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "CPIO checksum chunk length is not representable",
        )?)?;
        for byte in chunk.iter().copied() {
            sum = sum.wrapping_add(u32::from(byte));
        }
    }
    Ok(sum)
}

fn parse_header(payload: &[u8], offset: u64) -> Result<ParsedHeader> {
    let prefix = checked_range(
        payload,
        offset,
        2,
        "CPIO magic range overflows",
        "CPIO magic is truncated",
    )?;
    let first = prefix
        .first()
        .copied()
        .ok_or_else(|| cpio_format("magic is truncated"))?;
    let second = prefix
        .get(1)
        .copied()
        .ok_or_else(|| cpio_format("magic is truncated"))?;
    if [first, second] == BINARY_MAGIC.to_le_bytes() {
        return parse_binary_header(payload, offset, true);
    }
    if [first, second] == BINARY_MAGIC.to_be_bytes() {
        return parse_binary_header(payload, offset, false);
    }
    let magic = checked_range(
        payload,
        offset,
        6,
        "CPIO magic range overflows",
        "CPIO magic is truncated",
    )?;
    if magic == MAGIC_LARGE {
        return Err(Error::UnsupportedFeature {
            feature: String::from("rpm-large-file-cpio"),
        });
    }
    if magic == MAGIC_NEWC || magic == MAGIC_CRC {
        parse_newc_header(payload, offset, magic == MAGIC_CRC)
    } else if magic == MAGIC_ODC {
        parse_odc_header(payload, offset)
    } else {
        Err(cpio_format("magic is invalid"))
    }
}

fn parse_newc_header(payload: &[u8], offset: u64, has_checksum: bool) -> Result<ParsedHeader> {
    let header = checked_range(
        payload,
        offset,
        NEWC_HEADER_BYTES,
        "CPIO newc header range overflows",
        "CPIO newc header is truncated",
    )?;
    let declared_checksum = hex_u32(header, 102, "CPIO checksum is invalid")?;
    if !has_checksum && declared_checksum != 0 {
        return Err(cpio_format("newc entry has a nonzero checksum field"));
    }
    Ok(ParsedHeader {
        format: if has_checksum {
            CpioFormat::CrcNewc
        } else {
            CpioFormat::Newc
        },
        header_bytes: NEWC_HEADER_BYTES,
        alignment: 4,
        inode: hex_u32(header, 6, "CPIO inode is invalid")?,
        mode: hex_u32(header, 14, "CPIO mode is invalid")?,
        uid: hex_u32(header, 22, "CPIO uid is invalid")?,
        gid: hex_u32(header, 30, "CPIO gid is invalid")?,
        link_count: hex_u32(header, 38, "CPIO link count is invalid")?,
        modified_time: u64::from(hex_u32(header, 46, "CPIO mtime is invalid")?),
        file_size: u64::from(hex_u32(header, 54, "CPIO file size is invalid")?),
        device_major: hex_u32(header, 62, "CPIO device major is invalid")?,
        device_minor: hex_u32(header, 70, "CPIO device minor is invalid")?,
        rdev_major: hex_u32(header, 78, "CPIO rdev major is invalid")?,
        rdev_minor: hex_u32(header, 86, "CPIO rdev minor is invalid")?,
        name_size: u64::from(hex_u32(header, 94, "CPIO name size is invalid")?),
        checksum: has_checksum.then_some(declared_checksum),
    })
}

fn parse_odc_header(payload: &[u8], offset: u64) -> Result<ParsedHeader> {
    let header = checked_range(
        payload,
        offset,
        ODC_HEADER_BYTES,
        "CPIO odc header range overflows",
        "CPIO odc header is truncated",
    )?;
    let device = octal_u32(header, 6, 6, "CPIO odc device is invalid")?;
    let rdev = octal_u32(header, 42, 6, "CPIO odc rdev is invalid")?;
    Ok(ParsedHeader {
        format: CpioFormat::Odc,
        header_bytes: ODC_HEADER_BYTES,
        alignment: 1,
        device_major: 0,
        device_minor: device,
        rdev_major: 0,
        rdev_minor: rdev,
        inode: octal_u32(header, 12, 6, "CPIO odc inode is invalid")?,
        mode: octal_u32(header, 18, 6, "CPIO odc mode is invalid")?,
        uid: octal_u32(header, 24, 6, "CPIO odc uid is invalid")?,
        gid: octal_u32(header, 30, 6, "CPIO odc gid is invalid")?,
        link_count: octal_u32(header, 36, 6, "CPIO odc link count is invalid")?,
        modified_time: octal_u64(header, 48, 11, "CPIO odc mtime is invalid")?,
        name_size: octal_u64(header, 59, 6, "CPIO odc name size is invalid")?,
        file_size: octal_u64(header, 65, 11, "CPIO odc file size is invalid")?,
        checksum: None,
    })
}

fn parse_binary_header(payload: &[u8], offset: u64, little_endian: bool) -> Result<ParsedHeader> {
    let header = checked_range(
        payload,
        offset,
        BINARY_HEADER_BYTES,
        "CPIO binary header range overflows",
        "CPIO binary header is truncated",
    )?;
    let word = |word_index: u64, detail: &'static str| -> Result<u16> {
        let byte_offset = word_index
            .checked_mul(2)
            .ok_or_else(|| cpio_format("binary header offset overflows"))?;
        let bytes = checked_range(header, byte_offset, 2, detail, detail)?;
        let first = bytes.first().copied().ok_or_else(|| cpio_format(detail))?;
        let second = bytes.get(1).copied().ok_or_else(|| cpio_format(detail))?;
        Ok(if little_endian {
            u16::from_le_bytes([first, second])
        } else {
            u16::from_be_bytes([first, second])
        })
    };
    if word(0, "CPIO binary magic is invalid")? != BINARY_MAGIC {
        return Err(cpio_format("binary magic is invalid"));
    }
    let device = u32::from(word(1, "CPIO binary device is invalid")?);
    let rdev = u32::from(word(7, "CPIO binary rdev is invalid")?);
    let modified_time = combine_words(
        word(8, "CPIO binary mtime is invalid")?,
        word(9, "CPIO binary mtime is invalid")?,
    );
    let file_size = combine_words(
        word(11, "CPIO binary file size is invalid")?,
        word(12, "CPIO binary file size is invalid")?,
    );
    Ok(ParsedHeader {
        format: if little_endian {
            CpioFormat::BinaryLittleEndian
        } else {
            CpioFormat::BinaryBigEndian
        },
        header_bytes: BINARY_HEADER_BYTES,
        alignment: 2,
        inode: u32::from(word(2, "CPIO binary inode is invalid")?),
        mode: u32::from(word(3, "CPIO binary mode is invalid")?),
        uid: u32::from(word(4, "CPIO binary uid is invalid")?),
        gid: u32::from(word(5, "CPIO binary gid is invalid")?),
        link_count: u32::from(word(6, "CPIO binary link count is invalid")?),
        modified_time,
        file_size,
        device_major: 0,
        device_minor: device,
        rdev_major: 0,
        rdev_minor: rdev,
        name_size: u64::from(word(10, "CPIO binary name size is invalid")?),
        checksum: None,
    })
}

fn combine_words(high: u16, low: u16) -> u64 {
    u64::from(high) << 16 | u64::from(low)
}

fn verify_checksum(data: &[u8], entry: &CpioEntry, control: &mut ParseControl<'_>) -> Result<()> {
    if let Some(expected) = entry.checksum {
        if byte_sum(data, control)? != expected {
            return Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(entry.index),
            });
        }
    }
    Ok(())
}

fn validate_zero_padding(bytes: &[u8], start: u64, end: u64) -> Result<()> {
    let length = end
        .checked_sub(start)
        .ok_or_else(|| cpio_format("padding length underflows"))?;
    let padding = checked_range(
        bytes,
        start,
        length,
        "CPIO padding range overflows",
        "CPIO padding is truncated",
    )?;
    if padding.iter().any(|byte| *byte != 0) {
        Err(cpio_format("alignment padding is nonzero"))
    } else {
        Ok(())
    }
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 {
        return Err(cpio_format("alignment is zero"));
    }
    let remainder = value % alignment;
    let padding = if remainder == 0 {
        0
    } else {
        alignment
            .checked_sub(remainder)
            .ok_or_else(|| cpio_format("alignment underflows"))?
    };
    value
        .checked_add(padding)
        .ok_or_else(|| cpio_format("alignment overflows"))
}

fn hex_u32(bytes: &[u8], offset: u64, detail: &'static str) -> Result<u32> {
    let digits = checked_range(bytes, offset, 8, detail, detail)?;
    let mut value = 0_u32;
    for digit in digits.iter().copied() {
        let nibble = match digit {
            b'0'..=b'9' => u32::from(digit.checked_sub(b'0').ok_or_else(|| cpio_format(detail))?),
            b'a'..=b'f' => u32::from(digit.checked_sub(b'a').ok_or_else(|| cpio_format(detail))?)
                .checked_add(10)
                .ok_or_else(|| cpio_format(detail))?,
            b'A'..=b'F' => u32::from(digit.checked_sub(b'A').ok_or_else(|| cpio_format(detail))?)
                .checked_add(10)
                .ok_or_else(|| cpio_format(detail))?,
            _ => return Err(cpio_format(detail)),
        };
        value = value
            .checked_mul(16)
            .and_then(|current| current.checked_add(nibble))
            .ok_or_else(|| cpio_format(detail))?;
    }
    Ok(value)
}

fn octal_u32(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<u32> {
    let value = octal_u64(bytes, offset, length, detail)?;
    u32::try_from(value).map_err(|_| cpio_format(detail))
}

fn octal_u64(bytes: &[u8], offset: u64, length: u64, detail: &'static str) -> Result<u64> {
    let digits = checked_range(bytes, offset, length, detail, detail)?;
    let mut value = 0_u64;
    for digit in digits.iter().copied() {
        let octet = digit
            .checked_sub(b'0')
            .filter(|value| *value < 8)
            .ok_or_else(|| cpio_format(detail))?;
        value = value
            .checked_mul(8)
            .and_then(|current| current.checked_add(u64::from(octet)))
            .ok_or_else(|| cpio_format(detail))?;
    }
    Ok(value)
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
        .map_err(|_| cpio_format("path size is not representable on this platform"))?;
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
            .ok_or_else(|| cpio_format("path read returned an invalid byte count"))?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "CPIO input chunk length is not representable",
        )?)?;
        let requested = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| cpio_format("path input size overflows"))?;
        check_limit(
            usize_to_u64(requested, "CPIO path input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn cpio_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("CPIO: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{CpioArchive, CpioFormat};
    use crate::{CancellationToken, Error, LimitKind, Limits, Result, WorkBudget};

    fn push_hex(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn append_newc(output: &mut Vec<u8>, name: &[u8], data: &[u8], crc: bool) {
        output.extend_from_slice(if crc { b"070702" } else { b"070701" });
        for value in [
            1,
            0o100_644,
            1000,
            1000,
            1,
            1_700_000_000,
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            0,
            0,
            0,
            0,
            u32::try_from(name.len().saturating_add(1)).unwrap_or(u32::MAX),
            if crc {
                data.iter()
                    .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
            } else {
                0
            },
        ] {
            push_hex(output, value);
        }
        output.extend_from_slice(name);
        output.push(0);
        while output.len() % 4 != 0 {
            output.push(0);
        }
        output.extend_from_slice(data);
        while output.len() % 4 != 0 {
            output.push(0);
        }
    }

    fn newc_fixture(crc: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_newc(&mut bytes, b"hello.txt", b"hello", crc);
        append_newc(&mut bytes, b"TRAILER!!!", b"", crc);
        bytes
    }

    fn append_odc(output: &mut Vec<u8>, name: &[u8], data: &[u8]) {
        output.extend_from_slice(b"070707");
        for (value, width) in [
            (0_u64, 6_usize),
            (1, 6),
            (0o100_644, 6),
            (1000, 6),
            (1000, 6),
            (1, 6),
            (0, 6),
            (1_700_000_000, 11),
            (
                u64::try_from(name.len().saturating_add(1)).unwrap_or(u64::MAX),
                6,
            ),
            (u64::try_from(data.len()).unwrap_or(u64::MAX), 11),
        ] {
            output.extend_from_slice(format!("{value:0width$o}").as_bytes());
        }
        output.extend_from_slice(name);
        output.push(0);
        output.extend_from_slice(data);
    }

    fn odc_fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        append_odc(&mut bytes, b"hello.txt", b"hello");
        append_odc(&mut bytes, b"TRAILER!!!", b"");
        bytes
    }

    fn push_binary_word(output: &mut Vec<u8>, value: u16, little_endian: bool) {
        let encoded = if little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        output.extend_from_slice(&encoded);
    }

    fn append_binary(output: &mut Vec<u8>, name: &[u8], data: &[u8], little_endian: bool) {
        let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let modified_time = 1_700_000_000_u32;
        for value in [
            super::BINARY_MAGIC,
            0,
            1,
            0o100_644,
            1000,
            1000,
            1,
            0,
            u16::try_from(modified_time >> 16).unwrap_or(u16::MAX),
            u16::try_from(modified_time & 0xffff).unwrap_or(u16::MAX),
            u16::try_from(name.len().saturating_add(1)).unwrap_or(u16::MAX),
            u16::try_from(size >> 16).unwrap_or(u16::MAX),
            u16::try_from(size & 0xffff).unwrap_or(u16::MAX),
        ] {
            push_binary_word(output, value, little_endian);
        }
        output.extend_from_slice(name);
        output.push(0);
        if output.len() % 2 != 0 {
            output.push(0);
        }
        output.extend_from_slice(data);
        if output.len() % 2 != 0 {
            output.push(0);
        }
    }

    fn binary_fixture(little_endian: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_binary(&mut bytes, b"hello.txt", b"hello", little_endian);
        append_binary(&mut bytes, b"TRAILER!!!", b"", little_endian);
        bytes
    }

    fn open(bytes: Vec<u8>) -> Result<CpioArchive> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        CpioArchive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)
    }

    #[test]
    fn opens_newc_and_crc_newc_and_extracts_exact_bytes() -> Result<()> {
        for (crc, expected_format) in [(false, CpioFormat::Newc), (true, CpioFormat::CrcNewc)] {
            let archive = open(newc_fixture(crc))?;
            assert_eq!(archive.format(), expected_format);
            assert_eq!(archive.entries().len(), 1);
            assert_eq!(
                archive.entries().first().map(|entry| entry.raw_name()),
                Some(&b"hello.txt"[..])
            );
            let mut output = Vec::new();
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
            assert_eq!(output, b"hello");
        }
        Ok(())
    }

    #[test]
    fn opens_portable_ascii_odc() -> Result<()> {
        let archive = open(odc_fixture())?;
        assert_eq!(archive.format(), CpioFormat::Odc);
        assert_eq!(archive.entries().first().map(|entry| entry.size()), Some(5));
        Ok(())
    }

    #[test]
    fn opens_both_binary_byte_orders_and_extracts_exact_bytes() -> Result<()> {
        for (little_endian, expected_format) in [
            (true, CpioFormat::BinaryLittleEndian),
            (false, CpioFormat::BinaryBigEndian),
        ] {
            let archive = open(binary_fixture(little_endian))?;
            assert_eq!(archive.format(), expected_format);
            assert_eq!(archive.entries().len(), 1);
            let mut output = Vec::new();
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            archive.extract_entry_to(0, &mut output, &cancellation, &mut budget)?;
            assert_eq!(output, b"hello");
        }
        Ok(())
    }

    #[test]
    fn rejects_truncation_checksum_corruption_and_limits() -> Result<()> {
        let mut truncated = newc_fixture(false);
        let _ = truncated.pop();
        assert!(open(truncated).is_err());

        let mut corrupt = newc_fixture(true);
        let data = corrupt
            .iter()
            .rposition(|byte| *byte == b'h')
            .ok_or_else(|| Error::Format {
                detail: String::from("test byte is missing"),
            })?;
        let byte = corrupt.get_mut(data).ok_or_else(|| Error::Format {
            detail: String::from("test byte is missing"),
        })?;
        *byte = b'H';
        assert!(matches!(open(corrupt), Err(Error::Checksum { .. })));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let limits = Limits::builder().max_files(0).build();
        assert!(matches!(
            CpioArchive::open_bytes(newc_fixture(false), limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::Files,
                ..
            })
        ));
        Ok(())
    }
}
