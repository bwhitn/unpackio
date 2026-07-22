//! Bounded, unpack-only Debian binary packages.

mod ar;
mod tar;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    CancellationToken, Error, LimitKind, Limits, Result, WorkBudget,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, try_reserve, usize_to_u64,
    },
    rpm::decode::{PayloadCompression, decode_container_payload},
};

/// The role of one outer ar member in a Debian binary package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DebMemberKind {
    /// The mandatory `debian-binary` version marker.
    DebianBinary,
    /// The compressed or uncompressed control tar stream.
    ControlArchive,
    /// The compressed or uncompressed data tar stream.
    DataArchive,
    /// An optional member whose name begins with an underscore.
    Optional,
}

/// Compression applied to a Debian control or data tar stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DebCompression {
    /// No compression (`.tar`).
    None,
    /// gzip (`.tar.gz`).
    Gzip,
    /// XZ (`.tar.xz`).
    Xz,
    /// Zstandard (`.tar.zst`).
    Zstandard,
    /// bzip2 (`.tar.bz2`, data archive only).
    Bzip2,
    /// legacy LZMA-alone (`.tar.lzma`, data archive only).
    Lzma,
}

impl From<DebCompression> for PayloadCompression {
    fn from(value: DebCompression) -> Self {
        match value {
            DebCompression::None => Self::None,
            DebCompression::Gzip => Self::Gzip,
            DebCompression::Xz => Self::Xz,
            DebCompression::Zstandard => Self::Zstandard,
            DebCompression::Bzip2 => Self::Bzip2,
            DebCompression::Lzma => Self::Lzma,
        }
    }
}

/// Owned metadata for one outer ar member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebMember {
    index: u64,
    raw_name: Box<[u8]>,
    modified_time: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    kind: DebMemberKind,
    compression: Option<DebCompression>,
    data_start: u64,
    data_end: u64,
}

impl DebMember {
    /// Returns the stable zero-based outer-member index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the exact ar member name.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns a display-only lossy member name.
    #[must_use]
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.raw_name).into_owned()
    }

    /// Returns the outer-member role.
    #[must_use]
    pub const fn kind(&self) -> DebMemberKind {
        self.kind
    }

    /// Returns the tar-stream compression, if this member is a tar stream.
    #[must_use]
    pub const fn compression(&self) -> Option<DebCompression> {
        self.compression
    }

    /// Returns the ar timestamp in seconds since the epoch.
    #[must_use]
    pub const fn modified_time(&self) -> u64 {
        self.modified_time
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

    /// Returns the ar mode bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the stored outer-member byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// The inner tar stream containing an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DebSection {
    /// Package metadata and maintainer scripts from `control.tar*`.
    Control,
    /// Installed filesystem payload from `data.tar*`.
    Data,
}

/// The tar entry type retained from a Debian package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DebEntryKind {
    /// A regular file.
    Regular,
    /// A hard-link record.
    HardLink,
    /// A symbolic-link record.
    SymbolicLink,
    /// A character-device record.
    CharacterDevice,
    /// A block-device record.
    BlockDevice,
    /// A directory.
    Directory,
    /// A FIFO.
    Fifo,
    /// A recognized tar header with another type flag.
    Other(u8),
}

/// Owned metadata for one control or data tar entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebEntry {
    pub(super) index: u64,
    pub(super) section: DebSection,
    pub(super) raw_name: Box<[u8]>,
    pub(super) raw_link_name: Option<Box<[u8]>>,
    pub(super) kind: DebEntryKind,
    pub(super) mode: u32,
    pub(super) uid: u64,
    pub(super) gid: u64,
    pub(super) modified_time: Option<i64>,
    pub(super) size: u64,
    pub(super) user_name: Option<Box<[u8]>>,
    pub(super) group_name: Option<Box<[u8]>>,
    pub(super) device_major: Option<u32>,
    pub(super) device_minor: Option<u32>,
    pub(super) header_checksum: u32,
    pub(super) data_start: u64,
    pub(super) data_end: u64,
}

impl DebEntry {
    /// Returns the stable zero-based inner-entry index across control then data.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the inner tar stream containing this entry.
    #[must_use]
    pub const fn section(&self) -> DebSection {
        self.section
    }

    /// Returns the byte-preserving tar path.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns a display-only lossy tar path.
    #[must_use]
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.raw_name).into_owned()
    }

    /// Returns the byte-preserving link target, if present.
    #[must_use]
    pub fn raw_link_name(&self) -> Option<&[u8]> {
        self.raw_link_name.as_deref()
    }

    /// Returns the tar entry type.
    #[must_use]
    pub const fn kind(&self) -> DebEntryKind {
        self.kind
    }

    /// Returns the permission and mode bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the numeric owner identifier.
    #[must_use]
    pub const fn uid(&self) -> u64 {
        self.uid
    }

    /// Returns the numeric group identifier.
    #[must_use]
    pub const fn gid(&self) -> u64 {
        self.gid
    }

    /// Returns the optional byte-preserving owner name.
    #[must_use]
    pub fn user_name(&self) -> Option<&[u8]> {
        self.user_name.as_deref()
    }

    /// Returns the optional byte-preserving group name.
    #[must_use]
    pub fn group_name(&self) -> Option<&[u8]> {
        self.group_name.as_deref()
    }

    /// Returns the modification timestamp, when representable as whole seconds.
    #[must_use]
    pub const fn modified_time(&self) -> Option<i64> {
        self.modified_time
    }

    /// Returns the declared entry byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the represented device major number.
    #[must_use]
    pub const fn device_major(&self) -> Option<u32> {
        self.device_major
    }

    /// Returns the represented device minor number.
    #[must_use]
    pub const fn device_minor(&self) -> Option<u32> {
        self.device_minor
    }

    /// Returns the verified tar header checksum.
    #[must_use]
    pub const fn header_checksum(&self) -> u32 {
        self.header_checksum
    }
}

/// A callback boundary for natural-order Debian inner-entry extraction.
pub trait DebEntrySink {
    /// Starts one entry. Its raw name remains metadata and is never a path.
    fn begin_entry(&mut self, entry: &DebEntry) -> Result<()>;

    /// Receives one bounded decoded entry chunk.
    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> Result<()>;

    /// Reports success only after all applicable validation for the entry.
    fn finish_entry(&mut self, entry_index: u64) -> Result<()>;
}

/// An owned, bounded Debian package reader.
pub struct DebArchive {
    bytes: Box<[u8]>,
    members: Box<[DebMember]>,
    control_tar: Box<[u8]>,
    data_tar: Box<[u8]>,
    entries: Box<[DebEntry]>,
    limits: Limits,
}

impl DebArchive {
    /// Opens, validates, and decodes an in-memory Debian binary package.
    ///
    /// Member names remain metadata. This method never writes to the
    /// filesystem.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, unsupported-feature, limit,
    /// cancellation, work-budget, decompression, or allocation error.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        check_limit(
            usize_to_u64(bytes.len(), "Debian package size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        check_limit(1, limits.max_recursion_depth(), LimitKind::RecursionDepth)?;
        let mut control = ParseControl::new(cancellation, budget);
        let parsed_members = ar::parse(&bytes, limits, &mut control)?;
        let (members, control_index, data_index) =
            validate_members(&bytes, parsed_members, limits, &mut control)?;
        let control_member = members
            .get(control_index)
            .ok_or_else(|| deb_format("control member index is invalid"))?;
        let data_member = members
            .get(data_index)
            .ok_or_else(|| deb_format("data member index is invalid"))?;
        let compressed_control = member_data(&bytes, control_member)?;
        let control_compression = control_member
            .compression
            .ok_or_else(|| deb_format("control compression is missing"))?;
        let control_tar = decode_container_payload(
            compressed_control,
            control_compression.into(),
            limits,
            limits.max_total_output_bytes(),
            &mut control,
        )?;
        let control_size = usize_to_u64(
            control_tar.len(),
            "decoded control tar size is not representable",
        )?;
        let remaining = limits
            .max_total_output_bytes()
            .checked_sub(control_size)
            .ok_or(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: control_size,
                maximum: limits.max_total_output_bytes(),
            })?;
        let compressed_data = member_data(&bytes, data_member)?;
        let data_compression = data_member
            .compression
            .ok_or_else(|| deb_format("data compression is missing"))?;
        let data_tar = decode_container_payload(
            compressed_data,
            data_compression.into(),
            limits,
            remaining,
            &mut control,
        )?;

        let outer_count = usize_to_u64(members.len(), "Debian member count is not representable")?;
        let mut totals = tar::ArchiveTotals {
            files: outer_count,
            name_bytes: total_member_name_bytes(&members)?,
            header_bytes: outer_count
                .checked_mul(60)
                .and_then(|value| value.checked_add(8))
                .ok_or_else(|| deb_format("outer ar header accounting overflows"))?,
            next_entry_index: 0,
            ..tar::ArchiveTotals::default()
        };
        let mut entries = tar::parse(
            &control_tar,
            DebSection::Control,
            limits,
            &mut totals,
            &mut control,
        )?;
        let mut data_entries = tar::parse(
            &data_tar,
            DebSection::Data,
            limits,
            &mut totals,
            &mut control,
        )?;
        try_reserve(&mut entries, data_entries.len())?;
        entries.append(&mut data_entries);
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            members: members.into_boxed_slice(),
            control_tar: control_tar.into_boxed_slice(),
            data_tar: data_tar.into_boxed_slice(),
            entries: entries.into_boxed_slice(),
            limits,
        })
    }

    /// Opens a Debian package path without deriving extraction destinations.
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

    /// Returns the exact outer ar members.
    #[must_use]
    pub fn members(&self) -> &[DebMember] {
        &self.members
    }

    /// Returns decoded control entries followed by decoded data entries.
    #[must_use]
    pub fn entries(&self) -> &[DebEntry] {
        &self.entries
    }

    /// Returns one inner entry by stable index.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&DebEntry> {
        let index = usize::try_from(index).ok()?;
        self.entries.get(index)
    }

    /// Returns one outer member by stable index.
    #[must_use]
    pub fn member(&self, index: u64) -> Option<&DebMember> {
        let index = usize::try_from(index).ok()?;
        self.members.get(index)
    }

    /// Returns the retained limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns retained raw package bytes.
    #[must_use]
    pub fn retained_input_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Returns retained decoded control-tar bytes.
    #[must_use]
    pub fn retained_control_bytes(&self) -> usize {
        self.control_tar.len()
    }

    /// Returns retained decoded data-tar bytes.
    #[must_use]
    pub fn retained_data_bytes(&self) -> usize {
        self.data_tar.len()
    }

    /// Copies one stored outer ar member to a caller-selected writer.
    ///
    /// # Errors
    ///
    /// Returns a typed index, limit, cancellation, budget, range, or I/O error.
    pub fn extract_member_to(
        &self,
        member_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let member = self.required_member(member_index)?;
        check_limit(
            member.size,
            self.limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        let data = member_data(&self.bytes, member)?;
        copy_to_writer(data, writer, cancellation, budget, "Debian outer member")?;
        Ok(member.size)
    }

    /// Copies one decoded inner tar entry to a caller-selected writer.
    ///
    /// # Errors
    ///
    /// Returns a typed index, limit, cancellation, budget, range, or I/O error.
    pub fn extract_entry_to(
        &self,
        entry_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let entry = self.required_entry(entry_index)?;
        check_limit(
            entry.size,
            self.limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        let data = self.entry_data(entry)?;
        copy_to_writer(data, writer, cancellation, budget, "Debian inner entry")?;
        Ok(entry.size)
    }

    /// Extracts all inner entries in control-then-data order with shared limits.
    ///
    /// # Errors
    ///
    /// Returns the first entry or sink error. `finish_entry` is called only
    /// after the entry's complete validated byte range has been delivered.
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn DebEntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.size, self.limits)?;
            let data = self.entry_data(entry)?;
            sink.begin_entry(entry)?;
            for chunk in data.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "Debian sink chunk length is not representable",
                )?)?;
                sink.write_entry(entry.index, chunk)?;
            }
            sink.finish_entry(entry.index)?;
        }
        Ok(total)
    }

    /// Rechecks every retained inner range and shared output limit.
    ///
    /// # Errors
    ///
    /// Returns a typed range, limit, cancellation, or work-budget error.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = checked_output_total(total, entry.size, self.limits)?;
            let data = self.entry_data(entry)?;
            control.consume_bytes(data)?;
        }
        Ok(())
    }

    fn required_member(&self, index: u64) -> Result<&DebMember> {
        let index = usize::try_from(index).map_err(|_| deb_format("member index is too large"))?;
        self.members
            .get(index)
            .ok_or_else(|| deb_format("member index is out of range"))
    }

    fn required_entry(&self, index: u64) -> Result<&DebEntry> {
        let index = usize::try_from(index).map_err(|_| deb_format("entry index is too large"))?;
        self.entries
            .get(index)
            .ok_or_else(|| deb_format("entry index is out of range"))
    }

    fn entry_data<'archive>(&'archive self, entry: &DebEntry) -> Result<&'archive [u8]> {
        let bytes = match entry.section {
            DebSection::Control => &self.control_tar,
            DebSection::Data => &self.data_tar,
        };
        let length = entry
            .data_end
            .checked_sub(entry.data_start)
            .ok_or_else(|| deb_format("inner entry data range underflows"))?;
        checked_range(
            bytes,
            entry.data_start,
            length,
            "Debian inner entry data range overflows",
            "Debian inner entry data range is invalid",
        )
    }
}

fn validate_members(
    bytes: &[u8],
    parsed: Vec<ar::ArMember>,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<(Vec<DebMember>, usize, usize)> {
    let first = parsed
        .first()
        .ok_or_else(|| deb_format("package has no ar members"))?;
    if first.raw_name.as_ref() != b"debian-binary" {
        return Err(deb_format("first member is not debian-binary"));
    }
    let version = checked_range(
        bytes,
        first.data_start,
        first.size,
        "debian-binary range overflows",
        "debian-binary is truncated",
    )?;
    control.consume_bytes(version)?;
    if version != b"2.0\n" {
        return Err(Error::UnsupportedFeature {
            feature: String::from("deb-format-version"),
        });
    }
    let mut members = Vec::new();
    try_reserve(&mut members, parsed.len())?;
    let mut control_index = None;
    let mut data_index = None;
    for member in parsed {
        let (kind, compression) = classify_member(&member.raw_name)?;
        match kind {
            DebMemberKind::DebianBinary => {
                if member.index != 0 {
                    return Err(deb_format("debian-binary member is duplicated"));
                }
            }
            DebMemberKind::Optional => {
                if control_index.is_some() || data_index.is_some() {
                    return Err(deb_format("optional member is out of order"));
                }
            }
            DebMemberKind::ControlArchive => {
                if control_index.is_some() || data_index.is_some() {
                    return Err(deb_format("control archive is duplicated or out of order"));
                }
                control_index = Some(members.len());
            }
            DebMemberKind::DataArchive => {
                if control_index.is_none() || data_index.is_some() {
                    return Err(deb_format("data archive is duplicated or out of order"));
                }
                data_index = Some(members.len());
            }
        }
        if data_index.is_some() && kind != DebMemberKind::DataArchive {
            return Err(deb_format("member occurs after the data archive"));
        }
        members.push(DebMember {
            index: member.index,
            raw_name: member.raw_name,
            modified_time: member.modified_time,
            uid: member.uid,
            gid: member.gid,
            mode: member.mode,
            size: member.size,
            kind,
            compression,
            data_start: member.data_start,
            data_end: member.data_end,
        });
    }
    check_limit(
        usize_to_u64(members.len(), "Debian member count is not representable")?,
        limits.max_files(),
        LimitKind::Files,
    )?;
    let control_index = control_index.ok_or_else(|| deb_format("control archive is missing"))?;
    let data_index = data_index.ok_or_else(|| deb_format("data archive is missing"))?;
    Ok((members, control_index, data_index))
}

fn classify_member(name: &[u8]) -> Result<(DebMemberKind, Option<DebCompression>)> {
    let result = match name {
        b"debian-binary" => (DebMemberKind::DebianBinary, None),
        b"control.tar" => (DebMemberKind::ControlArchive, Some(DebCompression::None)),
        b"control.tar.gz" => (DebMemberKind::ControlArchive, Some(DebCompression::Gzip)),
        b"control.tar.xz" => (DebMemberKind::ControlArchive, Some(DebCompression::Xz)),
        b"control.tar.zst" => (
            DebMemberKind::ControlArchive,
            Some(DebCompression::Zstandard),
        ),
        b"data.tar" => (DebMemberKind::DataArchive, Some(DebCompression::None)),
        b"data.tar.gz" => (DebMemberKind::DataArchive, Some(DebCompression::Gzip)),
        b"data.tar.xz" => (DebMemberKind::DataArchive, Some(DebCompression::Xz)),
        b"data.tar.zst" => (DebMemberKind::DataArchive, Some(DebCompression::Zstandard)),
        b"data.tar.bz2" => (DebMemberKind::DataArchive, Some(DebCompression::Bzip2)),
        b"data.tar.lzma" => (DebMemberKind::DataArchive, Some(DebCompression::Lzma)),
        value if value.starts_with(b"_") => (DebMemberKind::Optional, None),
        _ => {
            return Err(Error::UnsupportedFeature {
                feature: String::from("deb-outer-member"),
            });
        }
    };
    Ok(result)
}

fn member_data<'data>(bytes: &'data [u8], member: &DebMember) -> Result<&'data [u8]> {
    let length = member
        .data_end
        .checked_sub(member.data_start)
        .ok_or_else(|| deb_format("outer member data range underflows"))?;
    checked_range(
        bytes,
        member.data_start,
        length,
        "Debian outer member data range overflows",
        "Debian outer member data range is invalid",
    )
}

fn total_member_name_bytes(members: &[DebMember]) -> Result<u64> {
    let mut total = 0_u64;
    for member in members {
        total = total
            .checked_add(usize_to_u64(
                member.raw_name.len(),
                "Debian member name length is not representable",
            )?)
            .ok_or_else(|| deb_format("total Debian member name bytes overflow"))?;
    }
    Ok(total)
}

fn copy_to_writer(
    bytes: &[u8],
    writer: &mut dyn Write,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
    detail: &'static str,
) -> Result<()> {
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        cancellation.check()?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "Debian output chunk length is not representable",
        )?)?;
        writer.write_all(chunk).map_err(Error::Io)?;
    }
    if bytes.is_empty() {
        cancellation.check()?;
        budget.charge(0)?;
    }
    let _ = detail;
    Ok(())
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
        .map_err(|_| deb_format("path size is not representable on this platform"))?;
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
            .ok_or_else(|| deb_format("path read returned an invalid byte count"))?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "Debian input chunk length is not representable",
        )?)?;
        let requested = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| deb_format("path input size overflows"))?;
        check_limit(
            usize_to_u64(requested, "Debian path input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn deb_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("Debian package: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{DebArchive, DebCompression, DebEntryKind, DebMemberKind, DebSection};
    use crate::{CancellationToken, Error, LimitKind, Limits, Result, WorkBudget};

    type TarTestEntry<'data> = (&'data [u8], &'data [u8], u8, &'data [u8]);

    const GZIP_TAR: &str = include_str!("../../tests/fixtures/deb/payload.tar.gz.b64");
    const BZIP2_TAR: &str = include_str!("../../tests/fixtures/deb/payload.tar.bz2.b64");
    const XZ_TAR: &str = include_str!("../../tests/fixtures/deb/payload.tar.xz.b64");
    const LZMA_TAR: &str = include_str!("../../tests/fixtures/deb/payload.tar.lzma.b64");
    const ZSTD_TAR: &str = include_str!("../../tests/fixtures/deb/payload.tar.zst.b64");
    const COMPRESSED_FIXTURE_OUTPUT: &[u8] = b"deterministic Debian compression fixture\n";

    fn base64_value(byte: u8) -> Result<u8> {
        match byte {
            b'A'..=b'Z' => byte.checked_sub(b'A').ok_or_else(|| Error::Format {
                detail: String::from("test base64 value underflows"),
            }),
            b'a'..=b'z' => byte
                .checked_sub(b'a')
                .and_then(|value| value.checked_add(26))
                .ok_or_else(|| Error::Format {
                    detail: String::from("test base64 value overflows"),
                }),
            b'0'..=b'9' => byte
                .checked_sub(b'0')
                .and_then(|value| value.checked_add(52))
                .ok_or_else(|| Error::Format {
                    detail: String::from("test base64 value overflows"),
                }),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(64),
            _ => Err(Error::Format {
                detail: String::from("test base64 character is invalid"),
            }),
        }
    }

    fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
        let compact: Vec<u8> = encoded
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if compact.len() % 4 != 0 {
            return Err(Error::Format {
                detail: String::from("test base64 length is invalid"),
            });
        }
        let mut output = Vec::new();
        for chunk in compact.chunks_exact(4) {
            let first = base64_value(chunk.first().copied().ok_or_else(|| Error::Format {
                detail: String::from("test base64 quartet is truncated"),
            })?)?;
            let second = base64_value(chunk.get(1).copied().ok_or_else(|| Error::Format {
                detail: String::from("test base64 quartet is truncated"),
            })?)?;
            let third_byte = chunk.get(2).copied().ok_or_else(|| Error::Format {
                detail: String::from("test base64 quartet is truncated"),
            })?;
            let fourth_byte = chunk.get(3).copied().ok_or_else(|| Error::Format {
                detail: String::from("test base64 quartet is truncated"),
            })?;
            let third = base64_value(third_byte)?;
            let fourth = base64_value(fourth_byte)?;
            if first >= 64 || second >= 64 {
                return Err(Error::Format {
                    detail: String::from("test base64 padding is misplaced"),
                });
            }
            output.push((first << 2) | (second >> 4));
            if third < 64 {
                output.push((second << 4) | (third >> 2));
                if fourth < 64 {
                    output.push((third << 6) | fourth);
                } else if fourth_byte != b'=' {
                    return Err(Error::Format {
                        detail: String::from("test base64 padding is invalid"),
                    });
                }
            } else if third_byte != b'=' || fourth_byte != b'=' {
                return Err(Error::Format {
                    detail: String::from("test base64 padding is invalid"),
                });
            }
        }
        Ok(output)
    }

    fn write_octal(field: &mut [u8], value: u64) -> Result<()> {
        if field.is_empty() {
            return Err(Error::Format {
                detail: String::from("test tar numeric field is empty"),
            });
        }
        field.fill(0);
        let width = field.len().checked_sub(1).ok_or_else(|| Error::Format {
            detail: String::from("test tar numeric width underflows"),
        })?;
        let encoded = format!("{value:0width$o}");
        let destination = field.get_mut(..width).ok_or_else(|| Error::Format {
            detail: String::from("test tar numeric field is truncated"),
        })?;
        if destination.len() != encoded.len() {
            return Err(Error::Format {
                detail: String::from("test tar numeric value does not fit"),
            });
        }
        destination.copy_from_slice(encoded.as_bytes());
        Ok(())
    }

    fn append_tar_entry(
        output: &mut Vec<u8>,
        name: &[u8],
        data: &[u8],
        type_flag: u8,
        link: &[u8],
    ) -> Result<()> {
        let mut header = [0_u8; 512];
        header
            .get_mut(..name.len())
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar name is too long"),
            })?
            .copy_from_slice(name);
        write_octal(
            header.get_mut(100..108).ok_or_else(|| Error::Format {
                detail: String::from("test tar mode field is missing"),
            })?,
            0o644,
        )?;
        write_octal(
            header.get_mut(108..116).ok_or_else(|| Error::Format {
                detail: String::from("test tar uid field is missing"),
            })?,
            1000,
        )?;
        write_octal(
            header.get_mut(116..124).ok_or_else(|| Error::Format {
                detail: String::from("test tar gid field is missing"),
            })?,
            1000,
        )?;
        write_octal(
            header.get_mut(124..136).ok_or_else(|| Error::Format {
                detail: String::from("test tar size field is missing"),
            })?,
            u64::try_from(data.len()).map_err(|_| Error::Format {
                detail: String::from("test tar data length is too large"),
            })?,
        )?;
        write_octal(
            header.get_mut(136..148).ok_or_else(|| Error::Format {
                detail: String::from("test tar mtime field is missing"),
            })?,
            1_700_000_000,
        )?;
        header
            .get_mut(148..156)
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar checksum field is missing"),
            })?
            .fill(b' ');
        *header.get_mut(156).ok_or_else(|| Error::Format {
            detail: String::from("test tar type field is missing"),
        })? = type_flag;
        header
            .get_mut(157..157 + link.len())
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar link is too long"),
            })?
            .copy_from_slice(link);
        header
            .get_mut(257..263)
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar magic field is missing"),
            })?
            .copy_from_slice(b"ustar\0");
        header
            .get_mut(263..265)
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar version field is missing"),
            })?
            .copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_field = header.get_mut(148..156).ok_or_else(|| Error::Format {
            detail: String::from("test tar checksum field is missing"),
        })?;
        let encoded = format!("{checksum:06o}\0 ");
        checksum_field.copy_from_slice(encoded.as_bytes());
        output.extend_from_slice(&header);
        output.extend_from_slice(data);
        while output.len() % 512 != 0 {
            output.push(0);
        }
        Ok(())
    }

    fn tar(entries: &[TarTestEntry<'_>]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for (name, data, kind, link) in entries.iter().copied() {
            append_tar_entry(&mut output, name, data, kind, link)?;
        }
        output.resize(output.len().saturating_add(1024), 0);
        Ok(output)
    }

    fn append_ar(output: &mut Vec<u8>, name: &[u8], data: &[u8]) -> Result<()> {
        if name.len() > 15 {
            return Err(Error::Format {
                detail: String::from("test ar member name is too long"),
            });
        }
        let mut header = [b' '; 60];
        header
            .get_mut(..name.len())
            .ok_or_else(|| Error::Format {
                detail: String::from("test ar name field is missing"),
            })?
            .copy_from_slice(name);
        *header.get_mut(name.len()).ok_or_else(|| Error::Format {
            detail: String::from("test ar name slash is missing"),
        })? = b'/';
        for (range, value) in [
            (16..28, format!("{:<12}", 1_700_000_000)),
            (28..34, format!("{:<6}", 0)),
            (34..40, format!("{:<6}", 0)),
            (40..48, format!("{:<8o}", 0o100_644)),
            (48..58, format!("{:<10}", data.len())),
        ] {
            header
                .get_mut(range)
                .ok_or_else(|| Error::Format {
                    detail: String::from("test ar numeric field is missing"),
                })?
                .copy_from_slice(value.as_bytes());
        }
        header
            .get_mut(58..60)
            .ok_or_else(|| Error::Format {
                detail: String::from("test ar terminator is missing"),
            })?
            .copy_from_slice(b"`\n");
        output.extend_from_slice(&header);
        output.extend_from_slice(data);
        if data.len() % 2 != 0 {
            output.push(b'\n');
        }
        Ok(())
    }

    fn fixture() -> Result<Vec<u8>> {
        let control = tar(&[(b"control", b"Package: fixture\n", b'0', b"")])?;
        let data = tar(&[
            (b"usr/bin/tool", b"payload", b'0', b""),
            (b"usr/bin/link", b"", b'2', b"tool"),
            (b"empty", b"", b'0', b""),
        ])?;
        let mut output = b"!<arch>\n".to_vec();
        append_ar(&mut output, b"debian-binary", b"2.0\n")?;
        append_ar(&mut output, b"control.tar", &control)?;
        append_ar(&mut output, b"data.tar", &data)?;
        Ok(output)
    }

    fn compressed_fixture(
        compressed_name: &[u8],
        compressed_tar: &[u8],
        control_compressed: bool,
    ) -> Result<Vec<u8>> {
        let fallback_control = tar(&[(b"control", b"Package: fixture\n", b'0', b"")])?;
        let fallback_data = tar(&[(b"payload.txt", COMPRESSED_FIXTURE_OUTPUT, b'0', b"")])?;
        let mut output = b"!<arch>\n".to_vec();
        append_ar(&mut output, b"debian-binary", b"2.0\n")?;
        if control_compressed {
            append_ar(&mut output, compressed_name, compressed_tar)?;
            append_ar(&mut output, b"data.tar", &fallback_data)?;
        } else {
            append_ar(&mut output, b"control.tar", &fallback_control)?;
            append_ar(&mut output, compressed_name, compressed_tar)?;
        }
        Ok(output)
    }

    fn fixture_with_data_tar(data: &[u8]) -> Result<Vec<u8>> {
        let control = tar(&[(b"control", b"Package: fixture\n", b'0', b"")])?;
        let mut output = b"!<arch>\n".to_vec();
        append_ar(&mut output, b"debian-binary", b"2.0\n")?;
        append_ar(&mut output, b"control.tar", &control)?;
        append_ar(&mut output, b"data.tar", data)?;
        Ok(output)
    }

    fn open(bytes: Vec<u8>) -> Result<DebArchive> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        DebArchive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)
    }

    #[test]
    fn lists_outer_and_inner_metadata_and_extracts_exact_bytes() -> Result<()> {
        let archive = open(fixture()?)?;
        assert_eq!(archive.members().len(), 3);
        assert_eq!(
            archive.members().first().map(|member| member.kind()),
            Some(DebMemberKind::DebianBinary)
        );
        assert_eq!(archive.entries().len(), 4);
        assert_eq!(
            archive.entries().first().map(|entry| entry.section()),
            Some(DebSection::Control)
        );
        assert_eq!(
            archive.entries().get(1).map(|entry| entry.kind()),
            Some(DebEntryKind::Regular)
        );
        assert_eq!(
            archive
                .entries()
                .get(2)
                .and_then(|entry| entry.raw_link_name()),
            Some(&b"tool"[..])
        );
        let mut output = Vec::new();
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        archive.extract_entry_to(1, &mut output, &cancellation, &mut budget)?;
        assert_eq!(output, b"payload");
        Ok(())
    }

    #[test]
    fn decodes_every_permitted_debian_tar_compression() -> Result<()> {
        let gzip = decode_base64(GZIP_TAR)?;
        let xz = decode_base64(XZ_TAR)?;
        let zstd = decode_base64(ZSTD_TAR)?;
        let bzip2 = decode_base64(BZIP2_TAR)?;
        let lzma = decode_base64(LZMA_TAR)?;

        for (name, compressed, expected_compression) in [
            (
                b"control.tar.gz".as_slice(),
                gzip.as_slice(),
                DebCompression::Gzip,
            ),
            (
                b"control.tar.xz".as_slice(),
                xz.as_slice(),
                DebCompression::Xz,
            ),
            (
                b"control.tar.zst".as_slice(),
                zstd.as_slice(),
                DebCompression::Zstandard,
            ),
        ] {
            let archive = open(compressed_fixture(name, compressed, true)?)?;
            assert_eq!(
                archive
                    .members()
                    .get(1)
                    .and_then(|member| member.compression()),
                Some(expected_compression)
            );
            let entry = archive.entries().first().ok_or_else(|| Error::Format {
                detail: String::from("compressed control fixture has no entry"),
            })?;
            assert_eq!(entry.section(), DebSection::Control);
            assert_eq!(entry.raw_name(), b"payload.txt");
            let mut output = Vec::new();
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            archive.extract_entry_to(entry.index(), &mut output, &cancellation, &mut budget)?;
            assert_eq!(output, COMPRESSED_FIXTURE_OUTPUT);
        }

        for (name, compressed, expected_compression) in [
            (
                b"data.tar.gz".as_slice(),
                gzip.as_slice(),
                DebCompression::Gzip,
            ),
            (b"data.tar.xz".as_slice(), xz.as_slice(), DebCompression::Xz),
            (
                b"data.tar.zst".as_slice(),
                zstd.as_slice(),
                DebCompression::Zstandard,
            ),
            (
                b"data.tar.bz2".as_slice(),
                bzip2.as_slice(),
                DebCompression::Bzip2,
            ),
            (
                b"data.tar.lzma".as_slice(),
                lzma.as_slice(),
                DebCompression::Lzma,
            ),
        ] {
            let archive = open(compressed_fixture(name, compressed, false)?)?;
            assert_eq!(
                archive
                    .members()
                    .get(2)
                    .and_then(|member| member.compression()),
                Some(expected_compression)
            );
            let entry = archive
                .entries()
                .iter()
                .find(|entry| entry.section() == DebSection::Data)
                .ok_or_else(|| Error::Format {
                    detail: String::from("compressed data fixture has no data entry"),
                })?;
            assert_eq!(entry.raw_name(), b"payload.txt");
            let mut output = Vec::new();
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            archive.extract_entry_to(entry.index(), &mut output, &cancellation, &mut budget)?;
            assert_eq!(output, COMPRESSED_FIXTURE_OUTPUT);
        }
        Ok(())
    }

    #[test]
    fn applies_gnu_long_names_and_bounded_pax_paths() -> Result<()> {
        let gnu_name = b"usr/share/doc/fixture/a-name-that-is-deliberately-longer-than-the-classic-one-hundred-byte-tar-name-field-for-testing.txt";
        let mut gnu_value = gnu_name.to_vec();
        gnu_value.push(0);
        let gnu_tar = tar(&[
            (b"././@LongLink", &gnu_value, b'L', b""),
            (b"placeholder", b"gnu", b'0', b""),
        ])?;
        let gnu_archive = open(fixture_with_data_tar(&gnu_tar)?)?;
        let gnu_entry = gnu_archive
            .entries()
            .iter()
            .find(|entry| entry.section() == DebSection::Data)
            .ok_or_else(|| Error::Format {
                detail: String::from("GNU long-name fixture has no data entry"),
            })?;
        assert_eq!(gnu_entry.raw_name(), gnu_name);

        let pax_tar = tar(&[
            (b"PaxHeader", b"21 path=pax/path.txt\n", b'x', b""),
            (b"placeholder", b"pax", b'0', b""),
        ])?;
        let pax_archive = open(fixture_with_data_tar(&pax_tar)?)?;
        let pax_entry = pax_archive
            .entries()
            .iter()
            .find(|entry| entry.section() == DebSection::Data)
            .ok_or_else(|| Error::Format {
                detail: String::from("pax fixture has no data entry"),
            })?;
        assert_eq!(pax_entry.raw_name(), b"pax/path.txt");

        let malformed_pax = tar(&[
            (b"PaxHeader", b"22 path=pax/path.txt\n", b'x', b""),
            (b"placeholder", b"pax", b'0', b""),
        ])?;
        assert!(open(fixture_with_data_tar(&malformed_pax)?).is_err());
        Ok(())
    }

    #[test]
    fn rejects_order_version_truncation_checksum_and_limits() -> Result<()> {
        let mut bad_version = fixture()?;
        let version = bad_version
            .windows(4)
            .position(|window| window == b"2.0\n")
            .ok_or_else(|| Error::Format {
                detail: String::from("test version bytes are missing"),
            })?;
        let byte = bad_version.get_mut(version).ok_or_else(|| Error::Format {
            detail: String::from("test version byte is missing"),
        })?;
        *byte = b'3';
        assert!(matches!(
            open(bad_version),
            Err(Error::UnsupportedFeature { .. })
        ));

        let mut truncated = fixture()?;
        let _ = truncated.pop();
        assert!(open(truncated).is_err());

        let mut corrupt = fixture()?;
        let header = corrupt
            .windows(6)
            .position(|window| window == b"ustar\0")
            .ok_or_else(|| Error::Format {
                detail: String::from("test tar magic is missing"),
            })?;
        let checksum_byte = header
            .checked_sub(257)
            .and_then(|value| value.checked_add(10))
            .ok_or_else(|| Error::Format {
                detail: String::from("test checksum corruption offset overflows"),
            })?;
        let byte = corrupt
            .get_mut(checksum_byte)
            .ok_or_else(|| Error::Format {
                detail: String::from("test checksum corruption byte is missing"),
            })?;
        *byte ^= 1;
        assert!(matches!(open(corrupt), Err(Error::Checksum { .. })));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let limits = Limits::builder().max_files(3).build();
        assert!(matches!(
            DebArchive::open_bytes(fixture()?, limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::Files,
                ..
            })
        ));
        Ok(())
    }
}
