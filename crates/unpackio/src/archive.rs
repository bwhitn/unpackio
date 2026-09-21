//! Owned archive sessions and CRC-finalizing member extraction.

use std::{io::Write, mem::size_of, path::Path};

use crate::{
    CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
    checksum::Crc32,
    decode::METHOD_AES,
    execute::{DecodedFolder, decode_folder},
    metadata::{
        apply_external_properties, decode_additional_streams, resolve_external_properties,
        verify_additional_streams,
    },
    model::{
        ArchiveHeader, BindPair, Coder, ExternalProperty, FileEntry, FilesInfo, Folder,
        HeaderEnvelope, PackStream, ParsedNextHeader, StoredProperty, StreamsInfo, Substream,
    },
    parse_util::{
        CONTROL_CHUNK_SIZE, IO_CHUNK_SIZE, ParseControl, check_limit, format_error, try_reserve,
        u64_to_usize, usize_to_u64,
    },
    parser::{
        archive_declares_more_bytes, parse_archive, parse_decoded_next_header,
        parse_next_header_from_external_folders,
    },
    password::Password,
    volume::{
        PathVolumeProvider, VolumeProvider, VolumeTermination, read_sequential_volumes,
        read_single_volume,
    },
};

/// A caller-owned destination for natural-order file-entry extraction.
///
/// The archive supplies member indices and metadata but never interprets a raw
/// member name as a filesystem destination. [`EntrySink::finish_entry`] is
/// called only after that member's applicable CRC and its containing folder CRC
/// have been verified.
pub trait EntrySink {
    /// Starts one file entry with its validated decoded size.
    fn begin_entry(&mut self, member_index: u64, entry: &FileEntry, size: u64) -> Result<()>;

    /// Receives the next bounded chunk for the current file entry.
    fn write_entry(&mut self, member_index: u64, bytes: &[u8]) -> Result<()>;

    /// Finalizes one entry after its applicable integrity checks pass.
    fn finish_entry(&mut self, member_index: u64) -> Result<()>;
}

/// Accounted memory retained by an open [`Archive`].
///
/// The values cover owned archive bytes, validated model allocations, and
/// per-archive password storage. They intentionally exclude allocator
/// bookkeeping, stack frames, and temporary decoder state. Decoder working
/// memory remains bounded separately by [`Limits::max_dictionary_bytes`] and
/// [`Limits::max_total_output_bytes`]; an open [`MemberReader`] reports its
/// retained folder buffer through [`MemberReader::retained_bytes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveResources {
    input_bytes: u64,
    metadata_bytes: u64,
    password_bytes: u64,
    retained_bytes: u64,
}

impl ArchiveResources {
    /// Returns the logical archive bytes owned by the session.
    #[must_use]
    pub const fn input_bytes(self) -> u64 {
        self.input_bytes
    }

    /// Returns the validated model's accounted owned bytes.
    #[must_use]
    pub const fn metadata_bytes(self) -> u64 {
        self.metadata_bytes
    }

    /// Returns zeroizing password-buffer bytes retained by the session.
    #[must_use]
    pub const fn password_bytes(self) -> u64 {
        self.password_bytes
    }

    /// Returns the checked sum of all accounted retained categories.
    #[must_use]
    pub const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }
}

/// An owned, parsed archive ready for listing and supported-method extraction.
///
/// The session owns the original archive bytes so validated packed-stream
/// ranges remain stable. It never writes archive contents to the filesystem.
pub struct Archive {
    bytes: Box<[u8]>,
    #[cfg(feature = "unstable-internals")]
    envelope: HeaderEnvelope,
    header: ArchiveHeader,
    limits: Limits,
    password: Option<Password>,
    resources: ArchiveResources,
}

impl Archive {
    /// Parses archive bytes and resolves any supported encoded-header layers.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, limit, cancellation, password, or
    /// unsupported-method/feature error. Encrypted input without a password
    /// returns [`Error::PasswordRequired`].
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(bytes, limits, None, cancellation, budget)
    }

    /// Parses archive bytes with a password scoped to the returned session.
    ///
    /// The password is converted to the 7z UTF-16LE representation, zeroized
    /// when the archive is dropped, and is never placed in global state.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Archive::open_bytes`]. Because 7z AES-CBC
    /// is unauthenticated, an invalid password or corrupt encrypted bytes can
    /// return [`Error::WrongPasswordOrCorrupt`].
    pub fn open_bytes_with_password(
        bytes: Vec<u8>,
        limits: Limits,
        password: &str,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(
            bytes,
            limits,
            Some(Password::new(password)?),
            cancellation,
            budget,
        )
    }

    /// Opens one path, discovering sequential `.001`, `.002`, ... parts when
    /// the supplied path ends in `.001`.
    ///
    /// # Errors
    ///
    /// In addition to [`Archive::open_bytes`] errors, returns [`Error::Io`] for
    /// path I/O and [`Error::MissingVolume`] for a required sequential part.
    pub fn open_path(
        path: &Path,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_path_inner(path, limits, None, cancellation, budget)
    }

    /// Opens one path or sequential path set with a per-archive password.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Archive::open_path`] and
    /// [`Archive::open_bytes_with_password`].
    pub fn open_path_with_password(
        path: &Path,
        limits: Limits,
        password: &str,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_path_inner(
            path,
            limits,
            Some(Password::new(password)?),
            cancellation,
            budget,
        )
    }

    fn open_path_inner(
        path: &Path,
        limits: Limits,
        password: Option<Password>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let expected_name = path.to_string_lossy();
        let mut provider = PathVolumeProvider::new(path.to_path_buf());
        if path.extension() == Some(std::ffi::OsStr::new("001")) {
            return Self::open_volumes_inner(
                &mut provider,
                &expected_name,
                limits,
                password,
                cancellation,
                budget,
            );
        }
        let bytes = {
            let mut control = ParseControl::new(cancellation, budget);
            read_single_volume(&mut provider, &expected_name, limits, &mut control)?
        };
        Self::open_bytes_inner(bytes, limits, password, cancellation, budget)
    }

    /// Opens sequential `.001`, `.002`, ... data through a bounded provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingVolume`] with the expected name when a required
    /// part is absent, [`Error::Io`] for provider reads, or any parsing,
    /// checksum, limit, cancellation, or compatibility error.
    pub fn open_volumes(
        provider: &mut dyn VolumeProvider,
        first_volume_name: &str,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_volumes_inner(
            provider,
            first_volume_name,
            limits,
            None,
            cancellation,
            budget,
        )
    }

    /// Opens sequential volumes with a password owned only by the session.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Archive::open_volumes`] plus
    /// [`Error::WrongPasswordOrCorrupt`] where encrypted corruption and an
    /// invalid password cannot be distinguished.
    pub fn open_volumes_with_password(
        provider: &mut dyn VolumeProvider,
        first_volume_name: &str,
        limits: Limits,
        password: &str,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_volumes_inner(
            provider,
            first_volume_name,
            limits,
            Some(Password::new(password)?),
            cancellation,
            budget,
        )
    }

    fn open_volumes_inner(
        provider: &mut dyn VolumeProvider,
        first_volume_name: &str,
        limits: Limits,
        password: Option<Password>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let volume_bytes = {
            let mut control = ParseControl::new(cancellation, budget);
            read_sequential_volumes(provider, first_volume_name, limits, &mut control)?
        };
        let needs_more = volume_bytes.bytes.is_empty()
            || archive_declares_more_bytes(&volume_bytes.bytes, limits, cancellation, budget)?;
        let result =
            Self::open_bytes_inner(volume_bytes.bytes, limits, password, cancellation, budget);
        match result {
            Ok(archive) => Ok(archive),
            Err(_) if needs_more => match volume_bytes.termination {
                VolumeTermination::Missing(error) => Err(error),
                VolumeTermination::Limit { requested, maximum } => Err(Error::LimitExceeded {
                    limit: LimitKind::Volumes,
                    requested,
                    maximum,
                }),
            },
            Err(error) => Err(error),
        }
    }

    fn open_bytes_inner(
        bytes: Vec<u8>,
        limits: Limits,
        password: Option<Password>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let parsed = parse_archive(&bytes, limits, cancellation, budget)?;
        let (envelope, mut next_header) = parsed.into_parts();
        let mut depth = 0_u64;
        let mut decoded_header_bytes = 0_u64;
        loop {
            next_header = match next_header {
                ParsedNextHeader::Header(mut header) => {
                    let remaining_output = limits
                        .max_total_output_bytes()
                        .checked_sub(decoded_header_bytes)
                        .ok_or_else(|| {
                            format_error("external-property output accounting underflows")
                        })?;
                    let external_bytes = {
                        let mut control = ParseControl::new(cancellation, budget);
                        resolve_external_properties(
                            &mut header,
                            &bytes,
                            password.as_ref(),
                            limits,
                            remaining_output,
                            &mut control,
                        )?
                    };
                    decoded_header_bytes = decoded_header_bytes
                        .checked_add(external_bytes)
                        .ok_or_else(|| {
                            format_error("decoded metadata output accounting overflows")
                        })?;
                    check_limit(
                        decoded_header_bytes,
                        limits.max_total_output_bytes(),
                        LimitKind::TotalOutputBytes,
                    )?;
                    return Self::from_parts(
                        bytes.into_boxed_slice(),
                        envelope,
                        header,
                        limits,
                        password,
                    );
                }
                ParsedNextHeader::EncodedHeader(streams) => {
                    let encrypted = streams.folders().iter().any(folder_is_encrypted);
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| format_error("encoded-header recursion depth overflows"))?;
                    check_limit(
                        depth,
                        limits.max_recursion_depth(),
                        LimitKind::RecursionDepth,
                    )?;
                    let remaining_output = limits
                        .max_total_output_bytes()
                        .checked_sub(decoded_header_bytes)
                        .ok_or_else(|| {
                            format_error("decoded-header output accounting underflows")
                        })?;
                    let mut control = ParseControl::new(cancellation, budget);
                    let decoded = decode_encoded_header(
                        &bytes,
                        &streams,
                        limits,
                        remaining_output,
                        password.as_ref(),
                        &mut control,
                    )
                    .map_err(|error| map_encrypted_error(error, encrypted))?;
                    decoded_header_bytes = decoded_header_bytes
                        .checked_add(usize_to_u64(
                            decoded.len(),
                            "decoded header size is not representable as u64",
                        )?)
                        .ok_or_else(|| {
                            format_error("decoded-header output accounting overflows")
                        })?;
                    check_limit(
                        decoded_header_bytes,
                        limits.max_total_output_bytes(),
                        LimitKind::TotalOutputBytes,
                    )?;
                    parse_decoded_next_header(&decoded, envelope, &bytes, limits, &mut control)
                        .map_err(|error| map_encrypted_error(error, encrypted))?
                }
                ParsedNextHeader::PendingExternalFolders(pending) => {
                    depth = depth.checked_add(1).ok_or_else(|| {
                        format_error("external-folder resolution depth overflows")
                    })?;
                    check_limit(
                        depth,
                        limits.max_recursion_depth(),
                        LimitKind::RecursionDepth,
                    )?;
                    let remaining_output = limits
                        .max_total_output_bytes()
                        .checked_sub(decoded_header_bytes)
                        .ok_or_else(|| {
                            format_error("external-folder output accounting underflows")
                        })?;
                    let mut control = ParseControl::new(cancellation, budget);
                    let decoded = decode_additional_streams(
                        &bytes,
                        pending.additional_streams(),
                        password.as_ref(),
                        limits,
                        remaining_output,
                        &mut control,
                    )?;
                    decoded_header_bytes = decoded_header_bytes
                        .checked_add(decoded.total_bytes())
                        .ok_or_else(|| {
                            format_error("external-folder output accounting overflows")
                        })?;
                    check_limit(
                        decoded_header_bytes,
                        limits.max_total_output_bytes(),
                        LimitKind::TotalOutputBytes,
                    )?;
                    let folder_stream = decoded.get(pending.data_index())?;
                    let encrypted = folder_stream.encrypted();
                    let resolved = parse_next_header_from_external_folders(
                        pending.header_bytes(),
                        pending.data_index(),
                        folder_stream.bytes(),
                        envelope,
                        &bytes,
                        limits,
                        &mut control,
                    )
                    .map_err(|error| map_encrypted_error(error, encrypted))?;
                    let ParsedNextHeader::Header(mut header) = resolved else {
                        return Err(format_error(
                            "external folder resolution did not produce a plain header",
                        ));
                    };
                    apply_external_properties(&mut header, &decoded, limits, &mut control)?;
                    return Self::from_parts(
                        bytes.into_boxed_slice(),
                        envelope,
                        header,
                        limits,
                        password,
                    );
                }
            };
        }
    }

    #[cfg(feature = "unstable-internals")]
    #[doc(hidden)]
    #[must_use]
    pub const fn envelope(&self) -> HeaderEnvelope {
        self.envelope
    }

    #[cfg(feature = "unstable-internals")]
    #[doc(hidden)]
    #[must_use]
    pub const fn header(&self) -> &ArchiveHeader {
        &self.header
    }

    /// Returns member records in archive order, or an empty slice when absent.
    #[must_use]
    pub fn entries(&self) -> &[FileEntry] {
        self.header.files().map_or(&[], FilesInfo::entries)
    }

    /// Returns one metadata record by its stable archive-order index.
    #[must_use]
    pub fn entry(&self, member_index: u64) -> Option<&FileEntry> {
        usize::try_from(member_index)
            .ok()
            .and_then(|index| self.entries().get(index))
    }

    /// Returns whether the archive directory contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    /// Returns the per-session limits used for parsing and decoding.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns checked accounting for state retained by this session.
    #[must_use]
    pub const fn resources(&self) -> ArchiveResources {
        self.resources
    }

    fn from_parts(
        bytes: Box<[u8]>,
        envelope: HeaderEnvelope,
        header: ArchiveHeader,
        limits: Limits,
        password: Option<Password>,
    ) -> Result<Self> {
        let resources = measure_archive_resources(&bytes, &header, password.as_ref())?;
        #[cfg(not(feature = "unstable-internals"))]
        let _ = envelope;
        Ok(Self {
            bytes,
            #[cfg(feature = "unstable-internals")]
            envelope,
            header,
            limits,
            password,
            resources,
        })
    }

    /// Opens a bounded member reader.
    ///
    /// Folder output has already been fully decoded when this returns, but no
    /// member success is implied. The caller must consume the reader and call
    /// [`MemberReader::finish`] so member and folder CRC errors can be returned.
    ///
    /// # Errors
    ///
    /// Returns a format error for an invalid member index, a typed unsupported
    /// error for an unextractable entry, or a decoder, limit, cancellation,
    /// password, I/O, or checksum error.
    pub fn open_member<'operation>(
        &self,
        member_index: u64,
        cancellation: &'operation CancellationToken,
        budget: &'operation mut WorkBudget,
    ) -> Result<MemberReader<'operation>> {
        let member = self.member(member_index)?;
        if member.is_anti_item() {
            return Err(Error::UnsupportedFeature {
                feature: String::from("anti-item-extraction"),
            });
        }
        let Some(stream) = member.stream() else {
            if member.is_empty_file() {
                return Ok(MemberReader::new(
                    Vec::new(),
                    0,
                    0,
                    None,
                    false,
                    false,
                    member_index,
                    cancellation,
                    budget,
                ));
            }
            return Err(Error::UnsupportedFeature {
                feature: String::from("streamless-directory-extraction"),
            });
        };
        if let Some(size) = stream.size() {
            check_limit(
                size,
                self.limits.max_entry_output_bytes(),
                LimitKind::EntryOutputBytes,
            )?;
        }
        let streams = self
            .header
            .main_streams()
            .ok_or_else(|| format_error("streamed member has no MainStreamsInfo"))?;
        let mut control = ParseControl::new(cancellation, budget);
        let folder = streams
            .folders()
            .get(u64_to_usize(
                stream.folder_index(),
                "member folder index is not representable on this platform",
            )?)
            .ok_or_else(|| format_error("member folder index is out of range"))?;
        let maximum_output = folder_decode_maximum(
            folder,
            self.limits,
            self.limits.max_total_output_bytes(),
            &mut control,
        )?;
        let decoded = decode_folder(
            &self.bytes,
            streams,
            stream.folder_index(),
            self.password.as_ref(),
            self.limits,
            maximum_output,
            &mut control,
        )
        .map_err(|error| map_encrypted_error(error, folder_is_encrypted(folder)))?;
        let (start, end) = member_bounds(
            folder,
            stream.substream_index(),
            decoded.bytes.len(),
            &mut control,
        )?;
        let length = end
            .checked_sub(start)
            .ok_or_else(|| format_error("member byte range underflows"))?;
        check_limit(
            usize_to_u64(length, "member size is not representable as u64")?,
            self.limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        Ok(MemberReader::new(
            decoded.bytes,
            start,
            end,
            stream.crc(),
            decoded.crc_mismatch,
            decoded.encrypted,
            member_index,
            cancellation,
            budget,
        ))
    }

    /// Extracts one member into memory and verifies all applicable CRCs before
    /// returning success.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Archive::open_member`], reading, allocation, or
    /// [`MemberReader::finish`]. No `Ok` value is returned before integrity
    /// finalization.
    pub fn extract_entry(
        &self,
        member_index: u64,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Vec<u8>> {
        self.open_member(member_index, cancellation, budget)?
            .into_bytes()
    }

    /// Streams one member to a caller-supplied writer and returns its verified
    /// byte count. This does not derive or validate a filesystem path.
    ///
    /// The writer may observe bytes before a trailing member CRC is checked.
    /// Callers needing atomic trusted output should commit a temporary output
    /// only after this method returns `Ok`.
    ///
    /// # Errors
    ///
    /// Returns any member-opening/decoding/finalization error or [`Error::Io`]
    /// when the writer fails. The returned count exists only on verified
    /// success.
    pub fn extract_entry_to(
        &self,
        member_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut reader = self.open_member(member_index, cancellation, budget)?;
        let mut written = 0_u64;
        let mut buffer = [0_u8; IO_CHUNK_SIZE];
        loop {
            let count = reader.read_chunk(&mut buffer)?;
            if count == 0 {
                break;
            }
            let bytes = buffer
                .get(..count)
                .ok_or_else(|| format_error("member read count exceeds its output buffer"))?;
            writer.write_all(bytes)?;
            written = written
                .checked_add(usize_to_u64(
                    count,
                    "member write count is not representable as u64",
                )?)
                .ok_or_else(|| format_error("member write count overflows"))?;
        }
        reader.finish()?;
        Ok(written)
    }

    /// Decodes every additional and file stream and verifies every applicable
    /// packed-stream, folder, substream, and member CRC. Streamless directories
    /// and anti-items contain no bytes to verify.
    ///
    /// # Errors
    ///
    /// Returns the first typed parsing-model, compatibility, decoder, limit,
    /// cancellation, password, I/O, or checksum failure.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        let mut total_output = 0_u64;
        if let Some(additional_streams) = self.header.additional_streams() {
            let mut control = ParseControl::new(cancellation, budget);
            total_output = verify_additional_streams(
                &self.bytes,
                additional_streams,
                self.password.as_ref(),
                self.limits,
                self.limits.max_total_output_bytes(),
                &mut control,
            )?;
        }
        let Some(streams) = self.header.main_streams() else {
            return Ok(());
        };
        let mut streamed_entries = self
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, member)| member.has_stream());
        for (folder_index, folder) in streams.folders().iter().enumerate() {
            cancellation.check()?;
            let remaining = self
                .limits
                .max_total_output_bytes()
                .checked_sub(total_output)
                .ok_or_else(|| format_error("total decoded output accounting underflows"))?;
            let mut control = ParseControl::new(cancellation, budget);
            let maximum_output =
                folder_decode_maximum(folder, self.limits, remaining, &mut control)?;
            let decoded = decode_folder(
                &self.bytes,
                streams,
                usize_to_u64(folder_index, "folder index is not representable as u64")?,
                self.password.as_ref(),
                self.limits,
                maximum_output,
                &mut control,
            )
            .map_err(|error| map_encrypted_error(error, folder_is_encrypted(folder)))?;
            let decoded_size = usize_to_u64(
                decoded.bytes.len(),
                "decoded folder size is not representable as u64",
            )?;
            total_output = total_output
                .checked_add(decoded_size)
                .ok_or_else(|| format_error("total decoded output accounting overflows"))?;
            check_limit(
                total_output,
                self.limits.max_total_output_bytes(),
                LimitKind::TotalOutputBytes,
            )?;
            verify_folder_members(
                folder,
                folder_index,
                &decoded,
                &mut streamed_entries,
                &mut control,
            )?;
        }
        if streamed_entries.next().is_some() {
            return Err(format_error("member stream mapping exceeds the folder set"));
        }
        Ok(())
    }

    /// Extracts file entries through a caller-owned sink in natural stream
    /// order, decoding each solid folder at most once.
    ///
    /// Streamless directories and anti-items do not produce sink events. Empty
    /// files produce `begin_entry` and `finish_entry` with a zero size and no
    /// data chunk. Raw names remain metadata; this method performs no path-based
    /// filesystem operation. The return value is the verified member-byte total.
    ///
    /// A sink can observe a member's chunks before that member's trailing CRC
    /// is checked; [`EntrySink::finish_entry`] is its success boundary.
    ///
    /// # Errors
    ///
    /// Returns the first archive or sink error. On error, no later member is
    /// started and the current member is not finalized.
    #[allow(clippy::too_many_lines)]
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn EntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let streams = self.header.main_streams();
        let mut control = ParseControl::new(cancellation, budget);
        let mut current_folder = None;
        let mut decoded_folder: Option<DecodedFolder> = None;
        let mut next_substream = 0_u64;
        let mut folder_offset = 0_u64;
        let mut total_folder_output = 0_u64;
        let mut delivered = 0_u64;

        for (member_index, member) in self.entries().iter().enumerate() {
            control.checkpoint(1)?;
            let member_index =
                usize_to_u64(member_index, "member index is not representable as u64")?;
            let Some(mapping) = member.stream() else {
                if member.is_empty_file() && !member.is_anti_item() {
                    sink.begin_entry(member_index, member, 0)?;
                    sink.finish_entry(member_index)?;
                }
                continue;
            };
            let streams = streams.ok_or_else(|| {
                format_error("streamed member has no MainStreamsInfo during extraction")
            })?;
            if current_folder != Some(mapping.folder_index()) {
                if let Some(previous) = current_folder {
                    let previous_folder = streams
                        .folders()
                        .get(u64_to_usize(
                            previous,
                            "previous folder index is not representable on this platform",
                        )?)
                        .ok_or_else(|| format_error("previous folder index is out of range"))?;
                    if next_substream
                        != usize_to_u64(
                            previous_folder.substreams().len(),
                            "folder substream count is not representable as u64",
                        )?
                    {
                        return Err(format_error(
                            "natural extraction left folder substreams unmapped",
                        ));
                    }
                }
                let folder = streams
                    .folders()
                    .get(u64_to_usize(
                        mapping.folder_index(),
                        "folder index is not representable on this platform",
                    )?)
                    .ok_or_else(|| format_error("folder index is out of range"))?;
                let remaining = self
                    .limits
                    .max_total_output_bytes()
                    .checked_sub(total_folder_output)
                    .ok_or_else(|| format_error("total decoded output accounting underflows"))?;
                let maximum_output =
                    folder_decode_maximum(folder, self.limits, remaining, &mut control)?;
                let decoded = decode_folder(
                    &self.bytes,
                    streams,
                    mapping.folder_index(),
                    self.password.as_ref(),
                    self.limits,
                    maximum_output,
                    &mut control,
                )
                .map_err(|error| map_encrypted_error(error, folder_is_encrypted(folder)))?;
                let decoded_size = usize_to_u64(
                    decoded.bytes.len(),
                    "decoded folder size is not representable as u64",
                )?;
                total_folder_output = total_folder_output
                    .checked_add(decoded_size)
                    .ok_or_else(|| format_error("total decoded output accounting overflows"))?;
                check_limit(
                    total_folder_output,
                    self.limits.max_total_output_bytes(),
                    LimitKind::TotalOutputBytes,
                )?;
                if decoded.crc_mismatch {
                    if decoded.encrypted {
                        return Err(Error::WrongPasswordOrCorrupt);
                    }
                    return Err(Error::Checksum {
                        scope: ChecksumScope::Folder,
                        member_index: None,
                    });
                }
                current_folder = Some(mapping.folder_index());
                decoded_folder = Some(decoded);
                next_substream = 0;
                folder_offset = 0;
            }
            if mapping.substream_index() != next_substream {
                return Err(format_error(
                    "natural extraction member mapping is out of order",
                ));
            }
            let folder = streams
                .folders()
                .get(u64_to_usize(
                    mapping.folder_index(),
                    "folder index is not representable on this platform",
                )?)
                .ok_or_else(|| format_error("folder index is out of range"))?;
            let substream_index = u64_to_usize(
                next_substream,
                "substream index is not representable on this platform",
            )?;
            let substream = folder
                .substreams()
                .get(substream_index)
                .ok_or_else(|| format_error("substream index is out of range"))?;
            let decoded = decoded_folder
                .as_ref()
                .ok_or_else(|| format_error("decoded folder is unavailable"))?;
            let folder_size = usize_to_u64(
                decoded.bytes.len(),
                "decoded folder size is not representable as u64",
            )?;
            let end = match substream.size() {
                Some(size) => folder_offset
                    .checked_add(size)
                    .ok_or_else(|| format_error("member byte range overflows"))?,
                None if substream_index.checked_add(1) == Some(folder.substreams().len()) => {
                    folder_size
                }
                None => {
                    return Err(Error::UnsupportedFeature {
                        feature: String::from("unknown-nonfinal-substream-size"),
                    });
                }
            };
            if end > folder_size {
                return Err(format_error("member byte range exceeds folder output"));
            }
            let member_size = end
                .checked_sub(folder_offset)
                .ok_or_else(|| format_error("member byte range underflows"))?;
            check_limit(
                member_size,
                self.limits.max_entry_output_bytes(),
                LimitKind::EntryOutputBytes,
            )?;
            let start = u64_to_usize(
                folder_offset,
                "member start is not representable on this platform",
            )?;
            let end_index = u64_to_usize(end, "member end is not representable on this platform")?;
            let bytes = decoded
                .bytes
                .get(start..end_index)
                .ok_or_else(|| format_error("member byte range is outside folder output"))?;
            sink.begin_entry(member_index, member, member_size)?;
            let mut member_crc = Crc32::new();
            for chunk in bytes.chunks(IO_CHUNK_SIZE) {
                control.consume_bytes(chunk)?;
                member_crc.update(chunk)?;
                sink.write_entry(member_index, chunk)?;
            }
            if mapping
                .crc()
                .is_some_and(|expected| member_crc.finalize() != expected)
            {
                if decoded.encrypted {
                    return Err(Error::WrongPasswordOrCorrupt);
                }
                return Err(Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(member_index),
                });
            }
            sink.finish_entry(member_index)?;
            delivered = delivered
                .checked_add(member_size)
                .ok_or_else(|| format_error("delivered member byte count overflows"))?;
            folder_offset = end;
            next_substream = next_substream
                .checked_add(1)
                .ok_or_else(|| format_error("substream index overflows"))?;
        }
        if let (Some(streams), Some(folder_index)) = (streams, current_folder) {
            let folder = streams
                .folders()
                .get(u64_to_usize(
                    folder_index,
                    "final folder index is not representable on this platform",
                )?)
                .ok_or_else(|| format_error("final folder index is out of range"))?;
            if next_substream
                != usize_to_u64(
                    folder.substreams().len(),
                    "folder substream count is not representable as u64",
                )?
            {
                return Err(format_error(
                    "natural extraction left final folder substreams unmapped",
                ));
            }
        }
        Ok(delivered)
    }

    fn member(&self, member_index: u64) -> Result<&FileEntry> {
        let member_index = u64_to_usize(
            member_index,
            "member index is not representable on this platform",
        )?;
        self.entries()
            .get(member_index)
            .ok_or_else(|| format_error("member index is out of range"))
    }
}

fn add_accounted_bytes(total: &mut u64, bytes: u64, context: &'static str) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| format_error(context))?;
    Ok(())
}

fn accounted_slice_bytes<T>(length: usize, context: &'static str) -> Result<u64> {
    let bytes = length
        .checked_mul(size_of::<T>())
        .ok_or_else(|| format_error(context))?;
    usize_to_u64(bytes, context)
}

fn accounted_properties(properties: &[StoredProperty]) -> Result<u64> {
    let mut total = accounted_slice_bytes::<StoredProperty>(
        properties.len(),
        "stored-property accounting overflows",
    )?;
    for property in properties {
        add_accounted_bytes(
            &mut total,
            usize_to_u64(
                property.data().len(),
                "stored-property payload accounting overflows",
            )?,
            "stored-property payload total overflows",
        )?;
    }
    Ok(total)
}

fn accounted_streams(streams: &StreamsInfo) -> Result<u64> {
    let mut total = accounted_slice_bytes::<PackStream>(
        streams.pack_streams().len(),
        "pack-stream accounting overflows",
    )?;
    add_accounted_bytes(
        &mut total,
        accounted_slice_bytes::<Folder>(streams.folders().len(), "folder accounting overflows")?,
        "stream metadata accounting overflows",
    )?;
    for folder in streams.folders() {
        for bytes in [
            accounted_slice_bytes::<Coder>(folder.coders().len(), "coder accounting overflows")?,
            accounted_slice_bytes::<BindPair>(
                folder.bind_pairs().len(),
                "bind-pair accounting overflows",
            )?,
            accounted_slice_bytes::<u64>(
                folder.packed_input_indices().len(),
                "packed-input index accounting overflows",
            )?,
            accounted_slice_bytes::<Option<u64>>(
                folder.unpack_sizes().len(),
                "unpack-size accounting overflows",
            )?,
            accounted_slice_bytes::<u64>(
                folder.topological_coder_order().len(),
                "coder-order accounting overflows",
            )?,
            accounted_slice_bytes::<Substream>(
                folder.substreams().len(),
                "substream accounting overflows",
            )?,
        ] {
            add_accounted_bytes(&mut total, bytes, "folder metadata accounting overflows")?;
        }
        for coder in folder.coders() {
            add_accounted_bytes(
                &mut total,
                usize_to_u64(
                    coder.method_id().len(),
                    "method identifier accounting overflows",
                )?,
                "coder payload accounting overflows",
            )?;
            add_accounted_bytes(
                &mut total,
                usize_to_u64(
                    coder.properties().len(),
                    "coder-property accounting overflows",
                )?,
                "coder payload accounting overflows",
            )?;
        }
    }
    Ok(total)
}

fn accounted_files(files: &FilesInfo) -> Result<u64> {
    let mut total = accounted_slice_bytes::<FileEntry>(
        files.entries().len(),
        "file-entry accounting overflows",
    )?;
    for entry in files.entries() {
        if let Some(name) = entry.raw_name() {
            add_accounted_bytes(
                &mut total,
                accounted_slice_bytes::<u16>(name.len(), "entry-name accounting overflows")?,
                "entry-name total accounting overflows",
            )?;
        }
    }
    add_accounted_bytes(
        &mut total,
        accounted_slice_bytes::<ExternalProperty>(
            files.external_properties().len(),
            "external-property accounting overflows",
        )?,
        "file metadata accounting overflows",
    )?;
    for property in files.external_properties() {
        add_accounted_bytes(
            &mut total,
            accounted_slice_bytes::<bool>(
                property.defined_entries().len(),
                "external-property bitmap accounting overflows",
            )?,
            "external-property bitmap total overflows",
        )?;
    }
    add_accounted_bytes(
        &mut total,
        accounted_properties(files.unknown_properties())?,
        "file property accounting overflows",
    )?;
    Ok(total)
}

fn accounted_metadata(header: &ArchiveHeader) -> Result<u64> {
    let mut total = usize_to_u64(
        size_of::<ArchiveHeader>(),
        "archive-header accounting overflows",
    )?;
    add_accounted_bytes(
        &mut total,
        accounted_properties(header.archive_properties())?,
        "archive-property accounting overflows",
    )?;
    if let Some(streams) = header.additional_streams() {
        add_accounted_bytes(
            &mut total,
            accounted_streams(streams)?,
            "additional-stream accounting overflows",
        )?;
    }
    if let Some(streams) = header.main_streams() {
        add_accounted_bytes(
            &mut total,
            accounted_streams(streams)?,
            "main-stream accounting overflows",
        )?;
    }
    if let Some(files) = header.files() {
        add_accounted_bytes(
            &mut total,
            accounted_files(files)?,
            "file metadata accounting overflows",
        )?;
    }
    Ok(total)
}

fn measure_archive_resources(
    bytes: &[u8],
    header: &ArchiveHeader,
    password: Option<&Password>,
) -> Result<ArchiveResources> {
    let input_bytes = usize_to_u64(bytes.len(), "archive byte accounting overflows")?;
    let metadata_bytes = accounted_metadata(header)?;
    let password_bytes = password.map_or(Ok(0), |secret| {
        usize_to_u64(secret.retained_bytes(), "password accounting overflows")
    })?;
    let retained_bytes = input_bytes
        .checked_add(metadata_bytes)
        .and_then(|value| value.checked_add(password_bytes))
        .ok_or_else(|| format_error("archive retained-byte accounting overflows"))?;
    Ok(ArchiveResources {
        input_bytes,
        metadata_bytes,
        password_bytes,
        retained_bytes,
    })
}

fn folder_is_encrypted(folder: &Folder) -> bool {
    folder
        .coders()
        .iter()
        .any(|coder| coder.method_id() == METHOD_AES)
}

fn map_encrypted_error(error: Error, encrypted: bool) -> Error {
    if !encrypted {
        return error;
    }
    match error {
        Error::Format { .. } | Error::Checksum { .. } | Error::WrongPasswordOrCorrupt => {
            Error::WrongPasswordOrCorrupt
        }
        Error::UnsupportedMethod { .. }
        | Error::UnsupportedFeature { .. }
        | Error::StreamFormat { .. }
        | Error::StreamChecksum { .. }
        | Error::UnsupportedStreamFeature { .. }
        | Error::LimitExceeded { .. }
        | Error::MissingVolume { .. }
        | Error::PasswordRequired
        | Error::Cancelled
        | Error::Io(_) => error,
    }
}

fn decode_encoded_header(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    limits: Limits,
    maximum_output: u64,
    password: Option<&Password>,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    if streams.folders().is_empty() {
        return Err(format_error("encoded header has no folders"));
    }

    let mut declared_total = 0_u64;
    for folder in streams.folders() {
        let root_index = u64_to_usize(
            folder.root_output_index(),
            "encoded-header root output is not representable on this platform",
        )?;
        if let Some(size) = folder
            .unpack_sizes()
            .get(root_index)
            .copied()
            .ok_or_else(|| format_error("encoded-header root output size is missing"))?
        {
            declared_total = declared_total
                .checked_add(size)
                .ok_or_else(|| format_error("decoded-header declared size overflows"))?;
            check_limit(
                declared_total,
                limits.max_header_bytes(),
                LimitKind::HeaderBytes,
            )?;
            check_limit(declared_total, maximum_output, LimitKind::TotalOutputBytes)?;
        }
    }

    let maximum = limits.max_header_bytes().min(maximum_output);
    let mut header = Vec::new();
    let mut decoded_total = 0_u64;
    for (folder_index, folder) in streams.folders().iter().enumerate() {
        control.checkpoint(1)?;
        let remaining = maximum
            .checked_sub(decoded_total)
            .ok_or_else(|| format_error("decoded-header output accounting underflows"))?;
        let decoded = decode_folder(
            archive_bytes,
            streams,
            usize_to_u64(
                folder_index,
                "encoded-header folder index is not representable as u64",
            )?,
            password,
            limits,
            remaining,
            control,
        )
        .map_err(|error| map_encrypted_error(error, folder_is_encrypted(folder)))?;

        verify_encoded_header_folder(folder, &decoded, control)?;
        let folder_size = usize_to_u64(
            decoded.bytes.len(),
            "decoded-header folder size is not representable as u64",
        )?;
        decoded_total = decoded_total
            .checked_add(folder_size)
            .ok_or_else(|| format_error("decoded-header output accounting overflows"))?;
        check_limit(
            decoded_total,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        check_limit(decoded_total, maximum_output, LimitKind::TotalOutputBytes)?;

        try_reserve(&mut header, decoded.bytes.len())?;
        for chunk in decoded.bytes.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "decoded-header copy length is not representable as u64",
            )?)?;
            header.extend_from_slice(chunk);
        }
    }
    Ok(header)
}

fn verify_encoded_header_folder(
    folder: &Folder,
    decoded: &DecodedFolder,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let folder_size = usize_to_u64(
        decoded.bytes.len(),
        "decoded-header folder size is not representable as u64",
    )?;
    let mut start = 0_u64;
    for (substream_index, substream) in folder.substreams().iter().enumerate() {
        control.checkpoint(1)?;
        let end = match substream.size() {
            Some(size) => start
                .checked_add(size)
                .ok_or_else(|| format_error("encoded-header substream range overflows"))?,
            None if substream_index.checked_add(1) == Some(folder.substreams().len()) => {
                folder_size
            }
            None => {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("unknown-nonfinal-encoded-header-substream-size"),
                });
            }
        };
        if end > folder_size {
            return Err(format_error(
                "encoded-header substream range exceeds its folder output",
            ));
        }
        let bytes = decoded
            .bytes
            .get(
                u64_to_usize(
                    start,
                    "encoded-header substream start is not representable on this platform",
                )?
                    ..u64_to_usize(
                        end,
                        "encoded-header substream end is not representable on this platform",
                    )?,
            )
            .ok_or_else(|| format_error("encoded-header substream range is out of bounds"))?;
        if let Some(expected) = substream.crc() {
            if checksum(bytes, control)? != expected {
                if decoded.encrypted {
                    return Err(Error::WrongPasswordOrCorrupt);
                }
                return Err(Error::Checksum {
                    scope: ChecksumScope::EncodedHeader,
                    member_index: None,
                });
            }
        }
        start = end;
    }
    if start != folder_size {
        return Err(format_error(
            "encoded-header substreams do not consume their folder output exactly",
        ));
    }
    if decoded.crc_mismatch {
        if decoded.encrypted {
            return Err(Error::WrongPasswordOrCorrupt);
        }
        return Err(Error::Checksum {
            scope: ChecksumScope::EncodedHeader,
            member_index: None,
        });
    }
    Ok(())
}

fn checksum(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "checksum chunk length is not representable as u64",
        )?)?;
        checksum.update(chunk)?;
    }
    Ok(checksum.finalize())
}

fn folder_decode_maximum(
    folder: &Folder,
    limits: Limits,
    remaining_total: u64,
    control: &mut ParseControl<'_>,
) -> Result<u64> {
    let root_index = u64_to_usize(
        folder.root_output_index(),
        "folder root output is not representable on this platform",
    )?;
    let declared_root = folder
        .unpack_sizes()
        .get(root_index)
        .copied()
        .ok_or_else(|| format_error("folder root output size is missing"))?;
    if let Some(size) = declared_root {
        check_limit(size, remaining_total, LimitKind::TotalOutputBytes)?;
    }
    if folder.substreams().is_empty() {
        return Ok(remaining_total);
    }

    let mut permitted = 0_u64;
    let mut has_unknown_final = false;
    for (index, substream) in folder.substreams().iter().enumerate() {
        let contribution = match substream.size() {
            Some(size) => {
                check_limit(
                    size,
                    limits.max_entry_output_bytes(),
                    LimitKind::EntryOutputBytes,
                )?;
                size
            }
            None if index.checked_add(1) == Some(folder.substreams().len()) => {
                has_unknown_final = true;
                limits.max_entry_output_bytes()
            }
            None => {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("unknown-nonfinal-substream-size"),
                });
            }
        };
        permitted = permitted
            .checked_add(contribution)
            .ok_or_else(|| format_error("folder entry output allowance overflows"))?;
        control.checkpoint(1)?;
    }
    if !has_unknown_final && declared_root != Some(permitted) {
        return Err(format_error(
            "folder substream sizes do not equal its root output size",
        ));
    }
    Ok(permitted.min(remaining_total))
}

fn verify_folder_members<'entries, I>(
    folder: &Folder,
    folder_index: usize,
    decoded: &DecodedFolder,
    streamed_entries: &mut I,
    control: &mut ParseControl<'_>,
) -> Result<()>
where
    I: Iterator<Item = (usize, &'entries FileEntry)>,
{
    let folder_size = usize_to_u64(
        decoded.bytes.len(),
        "decoded folder size is not representable as u64",
    )?;
    let mut start = 0_u64;
    for (substream_index, substream) in folder.substreams().iter().enumerate() {
        control.checkpoint(1)?;
        let (member_index, member) = streamed_entries
            .next()
            .ok_or_else(|| format_error("folder substream has no mapped member"))?;
        let mapping = member
            .stream()
            .ok_or_else(|| format_error("streamed member has no validated mapping"))?;
        if mapping.folder_index()
            != usize_to_u64(folder_index, "folder index is not representable as u64")?
            || mapping.substream_index()
                != usize_to_u64(
                    substream_index,
                    "substream index is not representable as u64",
                )?
        {
            return Err(format_error("member-to-substream mapping is out of order"));
        }
        let end = match substream.size() {
            Some(size) => start
                .checked_add(size)
                .ok_or_else(|| format_error("member byte range overflows"))?,
            None if substream_index.checked_add(1) == Some(folder.substreams().len()) => {
                folder_size
            }
            None => {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("unknown-nonfinal-substream-size"),
                });
            }
        };
        if end > folder_size {
            return Err(format_error("member byte range exceeds folder output"));
        }
        let start_index =
            u64_to_usize(start, "member start is not representable on this platform")?;
        let end_index = u64_to_usize(end, "member end is not representable on this platform")?;
        let member_bytes = decoded
            .bytes
            .get(start_index..end_index)
            .ok_or_else(|| format_error("member byte range is outside folder output"))?;
        if let Some(expected) = substream.crc() {
            if checksum(member_bytes, control)? != expected {
                if decoded.encrypted {
                    return Err(Error::WrongPasswordOrCorrupt);
                }
                return Err(Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(usize_to_u64(
                        member_index,
                        "member index is not representable as u64",
                    )?),
                });
            }
        }
        start = end;
    }
    if decoded.crc_mismatch {
        if decoded.encrypted {
            return Err(Error::WrongPasswordOrCorrupt);
        }
        return Err(Error::Checksum {
            scope: ChecksumScope::Folder,
            member_index: None,
        });
    }
    Ok(())
}

fn member_bounds(
    folder: &Folder,
    substream_index: u64,
    folder_size: usize,
    control: &mut ParseControl<'_>,
) -> Result<(usize, usize)> {
    let target = u64_to_usize(
        substream_index,
        "substream index is not representable on this platform",
    )?;
    if target >= folder.substreams().len() {
        return Err(format_error("substream index is out of range"));
    }
    let mut start = 0_u64;
    for (index, substream) in folder.substreams().iter().enumerate() {
        control.checkpoint(1)?;
        if index == target {
            let end = match substream.size() {
                Some(size) => start
                    .checked_add(size)
                    .ok_or_else(|| format_error("member byte range overflows"))?,
                None if index.checked_add(1) == Some(folder.substreams().len()) => usize_to_u64(
                    folder_size,
                    "folder output size is not representable as u64",
                )?,
                None => {
                    return Err(Error::UnsupportedFeature {
                        feature: String::from("unknown-nonfinal-substream-size"),
                    });
                }
            };
            let folder_size = usize_to_u64(
                folder_size,
                "folder output size is not representable as u64",
            )?;
            if end > folder_size {
                return Err(format_error("member byte range exceeds folder output"));
            }
            return Ok((
                u64_to_usize(start, "member start is not representable on this platform")?,
                u64_to_usize(end, "member end is not representable on this platform")?,
            ));
        }
        let size = substream.size().ok_or_else(|| Error::UnsupportedFeature {
            feature: String::from("unknown-preceding-substream-size"),
        })?;
        start = start
            .checked_add(size)
            .ok_or_else(|| format_error("member start offset overflows"))?;
    }
    Err(format_error("substream index is out of range"))
}

/// A bounded member stream whose success is finalized explicitly.
pub struct MemberReader<'operation> {
    data: Vec<u8>,
    start: usize,
    end: usize,
    position: usize,
    expected_crc: Option<u32>,
    checksum: Crc32,
    folder_crc_mismatch: bool,
    encrypted: bool,
    member_index: u64,
    cancellation: &'operation CancellationToken,
    budget: &'operation mut WorkBudget,
}

impl<'operation> MemberReader<'operation> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        data: Vec<u8>,
        start: usize,
        end: usize,
        expected_crc: Option<u32>,
        folder_crc_mismatch: bool,
        encrypted: bool,
        member_index: u64,
        cancellation: &'operation CancellationToken,
        budget: &'operation mut WorkBudget,
    ) -> Self {
        Self {
            data,
            start,
            end,
            position: 0,
            expected_crc,
            checksum: Crc32::new(),
            folder_crc_mismatch,
            encrypted,
            member_index,
            cancellation,
            budget,
        }
    }

    /// Returns the member index in archive order.
    #[must_use]
    pub const fn member_index(&self) -> u64 {
        self.member_index
    }

    /// Returns the bounded member size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if an internal validated range invariant is
    /// violated or the size is not representable as `u64`.
    pub fn size(&self) -> Result<u64> {
        self.end
            .checked_sub(self.start)
            .ok_or_else(|| format_error("member length underflows"))
            .and_then(|size| usize_to_u64(size, "member size is not representable as u64"))
    }

    /// Returns bytes not yet observed through [`MemberReader::read_chunk`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if the validated reader range is inconsistent.
    pub fn remaining(&self) -> Result<u64> {
        let member_length = self
            .end
            .checked_sub(self.start)
            .ok_or_else(|| format_error("member length underflows"))?;
        let remaining = member_length
            .checked_sub(self.position)
            .ok_or_else(|| format_error("member read position exceeds its range"))?;
        usize_to_u64(
            remaining,
            "remaining member size is not representable as u64",
        )
    }

    /// Returns the decoded folder bytes retained by this reader.
    ///
    /// A solid member reader retains the complete bounded folder output, not
    /// only this member's slice. This value is therefore the relevant decoder
    /// state to include in caller-side memory accounting while the reader is
    /// alive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if the platform capacity is not representable
    /// as `u64`.
    pub fn retained_bytes(&self) -> Result<u64> {
        usize_to_u64(
            self.data.capacity(),
            "retained folder size is not representable as u64",
        )
    }

    /// Reads the next member bytes while updating its CRC and operation budget.
    ///
    /// # Errors
    ///
    /// Returns a cancellation, work-limit, or internal range error. A zero
    /// count means the member range is exhausted, not that CRC verification is
    /// complete.
    pub fn read_chunk(&mut self, output: &mut [u8]) -> Result<usize> {
        let member_length = self
            .end
            .checked_sub(self.start)
            .ok_or_else(|| format_error("member length underflows"))?;
        if output.is_empty() || self.position >= member_length {
            self.cancellation.check()?;
            return Ok(0);
        }
        let remaining = member_length
            .checked_sub(self.position)
            .ok_or_else(|| format_error("member read position exceeds its range"))?;
        let count = remaining.min(output.len());
        let absolute = self
            .start
            .checked_add(self.position)
            .ok_or_else(|| format_error("member read position overflows"))?;
        let absolute_end = absolute
            .checked_add(count)
            .ok_or_else(|| format_error("member read range overflows"))?;
        let source = self
            .data
            .get(absolute..absolute_end)
            .ok_or_else(|| format_error("member read range is outside folder output"))?;
        for chunk in source.chunks(CONTROL_CHUNK_SIZE) {
            self.cancellation.check()?;
            self.budget.charge(usize_to_u64(
                chunk.len(),
                "member read chunk length is not representable as u64",
            )?)?;
            self.checksum.update(chunk)?;
        }
        output
            .get_mut(..count)
            .ok_or_else(|| format_error("member output buffer range is invalid"))?
            .copy_from_slice(source);
        self.position = self
            .position
            .checked_add(count)
            .ok_or_else(|| format_error("member read position overflows"))?;
        Ok(count)
    }

    fn consume_remaining(&mut self) -> Result<()> {
        let member_length = self
            .end
            .checked_sub(self.start)
            .ok_or_else(|| format_error("member length underflows"))?;
        while self.position < member_length {
            let remaining = member_length
                .checked_sub(self.position)
                .ok_or_else(|| format_error("member read position exceeds its range"))?;
            let count = remaining.min(IO_CHUNK_SIZE);
            let absolute = self
                .start
                .checked_add(self.position)
                .ok_or_else(|| format_error("member read position overflows"))?;
            let absolute_end = absolute
                .checked_add(count)
                .ok_or_else(|| format_error("member read range overflows"))?;
            let source = self
                .data
                .get(absolute..absolute_end)
                .ok_or_else(|| format_error("member read range is outside folder output"))?;
            for chunk in source.chunks(CONTROL_CHUNK_SIZE) {
                self.cancellation.check()?;
                self.budget.charge(usize_to_u64(
                    chunk.len(),
                    "member read chunk length is not representable as u64",
                )?)?;
                self.checksum.update(chunk)?;
            }
            self.position = self
                .position
                .checked_add(count)
                .ok_or_else(|| format_error("member read position overflows"))?;
        }
        Ok(())
    }

    fn verify_integrity(&self) -> Result<()> {
        if self
            .expected_crc
            .is_some_and(|expected| self.checksum.finalize() != expected)
        {
            if self.encrypted {
                return Err(Error::WrongPasswordOrCorrupt);
            }
            return Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(self.member_index),
            });
        }
        if self.folder_crc_mismatch {
            if self.encrypted {
                return Err(Error::WrongPasswordOrCorrupt);
            }
            return Err(Error::Checksum {
                scope: ChecksumScope::Folder,
                member_index: None,
            });
        }
        Ok(())
    }

    fn into_bytes(mut self) -> Result<Vec<u8>> {
        self.consume_remaining()?;
        self.verify_integrity()?;
        if self.start == 0 && self.end == self.data.len() {
            return Ok(self.data);
        }
        let length = self
            .end
            .checked_sub(self.start)
            .ok_or_else(|| format_error("member length underflows"))?;
        let source = self
            .data
            .get(self.start..self.end)
            .ok_or_else(|| format_error("member byte range is outside folder output"))?;
        let mut output = Vec::new();
        try_reserve(&mut output, length)?;
        output.extend_from_slice(source);
        Ok(output)
    }

    /// Consumes unread bytes and verifies member CRC before folder CRC.
    ///
    /// `Drop` cannot return integrity failures, so callers must invoke this
    /// method before treating extraction as successful.
    ///
    /// # Errors
    ///
    /// Returns cancellation/work failures while consuming unread bytes, then
    /// the applicable member or folder checksum failure. Encrypted failures
    /// can be reported as [`Error::WrongPasswordOrCorrupt`].
    pub fn finish(mut self) -> Result<()> {
        self.consume_remaining()?;
        self.verify_integrity()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use aes::{
        Aes256,
        cipher::{Block, BlockModeEncrypt, KeyIvInit},
    };

    use super::{Archive, EntrySink};
    use crate::{
        CancellationToken, ChecksumScope, Error, LimitKind, Limits, MemoryVolumeProvider, Result,
        WorkBudget,
        checksum::Crc32,
        decode::{METHOD_COPY, METHOD_LZMA},
        model::{
            ArchiveHeader, ArchiveVersion, BindPair, Coder, FileEntry, FileStream, FilesInfo,
            Folder, HeaderEnvelope, NextHeaderKind, PackStream, StreamsInfo, Substream,
        },
        parse_util::usize_to_u64,
    };

    #[derive(Default)]
    struct CollectSink {
        entries: Vec<(u64, Vec<u8>)>,
        finished: Vec<u64>,
    }

    impl EntrySink for CollectSink {
        fn begin_entry(&mut self, member_index: u64, _entry: &FileEntry, size: u64) -> Result<()> {
            let capacity = usize::try_from(size).map_err(|_| {
                crate::parse_util::format_error("test sink size is not representable")
            })?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| crate::parse_util::format_error("test sink allocation failed"))?;
            self.entries.push((member_index, bytes));
            Ok(())
        }

        fn write_entry(&mut self, member_index: u64, bytes: &[u8]) -> Result<()> {
            let (current_index, output) = self
                .entries
                .last_mut()
                .ok_or_else(|| crate::parse_util::format_error("test sink has no current entry"))?;
            if *current_index != member_index {
                return Err(crate::parse_util::format_error(
                    "test sink member index changed",
                ));
            }
            output.extend_from_slice(bytes);
            Ok(())
        }

        fn finish_entry(&mut self, member_index: u64) -> Result<()> {
            self.finished.push(member_index);
            Ok(())
        }
    }

    fn one_member_copy_archive(
        data: &[u8],
        member_crc: Option<u32>,
        folder_crc: Option<u32>,
        packed_crc: Option<u32>,
        limits: Limits,
    ) -> Result<Archive> {
        let size = usize_to_u64(data.len(), "test member size is not representable as u64")?;
        one_member_copy_archive_with_size(
            data,
            Some(size),
            member_crc,
            folder_crc,
            packed_crc,
            limits,
        )
    }

    fn one_member_copy_archive_with_size(
        data: &[u8],
        declared_size: Option<u64>,
        member_crc: Option<u32>,
        folder_crc: Option<u32>,
        packed_crc: Option<u32>,
        limits: Limits,
    ) -> Result<Archive> {
        let size = usize_to_u64(data.len(), "test member size is not representable as u64")?;
        let coder = Coder::new(METHOD_COPY.into(), 0, 1, 0, 1, Box::default(), None);
        let folder = Folder::new(
            vec![coder].into_boxed_slice(),
            Box::<[BindPair]>::default(),
            vec![0].into_boxed_slice(),
            vec![declared_size].into_boxed_slice(),
            0,
            vec![0].into_boxed_slice(),
            folder_crc,
            vec![Substream::new(declared_size, member_crc)].into_boxed_slice(),
            0,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            vec![PackStream::new(0, Some(size), packed_crc)].into_boxed_slice(),
            vec![folder].into_boxed_slice(),
            1,
        );
        let entry = FileEntry::new(
            Some(vec![u16::from(b'm')].into_boxed_slice()),
            true,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(FileStream::new(0, 0, declared_size, member_crc)),
        );
        let header = ArchiveHeader::new(
            Box::default(),
            None,
            Some(streams),
            Some(FilesInfo::new(
                vec![entry].into_boxed_slice(),
                Box::default(),
                Box::default(),
            )),
        );
        Archive::from_parts(
            data.into(),
            HeaderEnvelope::new(
                0,
                ArchiveVersion::new(0, 4),
                size,
                0,
                0,
                NextHeaderKind::Header,
            ),
            header,
            limits,
            None,
        )
    }

    fn one_member_unknown_lzma_archive() -> Result<Archive> {
        const PACKED: &[u8] = &[
            0x00, 0x30, 0x98, 0x88, 0xa4, 0x4a, 0x8e, 0x9f, 0xff, 0xf6, 0x63, 0x80, 0x00,
        ];
        const PROPERTIES: &[u8] = &[0x5d, 0x00, 0x10, 0x00, 0x00];
        let packed_size = usize_to_u64(
            PACKED.len(),
            "test LZMA packed size is not representable as u64",
        )?;
        let member_crc = Crc32::checksum(b"abc")?;
        let coder = Coder::new(METHOD_LZMA.into(), 0, 1, 0, 1, PROPERTIES.into(), None);
        let folder = Folder::new(
            vec![coder].into_boxed_slice(),
            Box::<[BindPair]>::default(),
            vec![0].into_boxed_slice(),
            vec![None].into_boxed_slice(),
            0,
            vec![0].into_boxed_slice(),
            Some(member_crc),
            vec![Substream::new(None, Some(member_crc))].into_boxed_slice(),
            4 * 1024,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            vec![PackStream::new(
                0,
                Some(packed_size),
                Some(Crc32::checksum(PACKED)?),
            )]
            .into_boxed_slice(),
            vec![folder].into_boxed_slice(),
            1,
        );
        let entry = FileEntry::new(
            Some(vec![u16::from(b'm')].into_boxed_slice()),
            true,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            Some(FileStream::new(0, 0, None, Some(member_crc))),
        );
        let header = ArchiveHeader::new(
            Box::default(),
            None,
            Some(streams),
            Some(FilesInfo::new(
                vec![entry].into_boxed_slice(),
                Box::default(),
                Box::default(),
            )),
        );
        Archive::from_parts(
            PACKED.into(),
            HeaderEnvelope::new(
                0,
                ArchiveVersion::new(0, 4),
                packed_size,
                0,
                0,
                NextHeaderKind::Header,
            ),
            header,
            Limits::default(),
            None,
        )
    }

    fn two_member_solid_copy_archive(second_crc: u32) -> Result<Archive> {
        two_member_solid_copy_archive_with_sizes(
            [Some(2), Some(2)],
            second_crc,
            Limits::builder()
                .max_entry_output_bytes(2)
                .max_total_output_bytes(4)
                .build(),
        )
    }

    fn two_member_solid_copy_archive_with_sizes(
        sizes: [Option<u64>; 2],
        second_crc: u32,
        limits: Limits,
    ) -> Result<Archive> {
        let data = b"abcd";
        let first_crc = Crc32::checksum(b"ab")?;
        let folder_crc = Crc32::checksum(data)?;
        let coder = Coder::new(METHOD_COPY.into(), 0, 1, 0, 1, Box::default(), None);
        let root_size = if sizes.iter().all(Option::is_some) {
            Some(4)
        } else {
            None
        };
        let folder = Folder::new(
            vec![coder].into_boxed_slice(),
            Box::default(),
            vec![0].into_boxed_slice(),
            vec![root_size].into_boxed_slice(),
            0,
            vec![0].into_boxed_slice(),
            Some(folder_crc),
            vec![
                Substream::new(sizes.first().copied().flatten(), Some(first_crc)),
                Substream::new(sizes.get(1).copied().flatten(), Some(second_crc)),
            ]
            .into_boxed_slice(),
            0,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            vec![PackStream::new(0, Some(4), None)].into_boxed_slice(),
            vec![folder].into_boxed_slice(),
            2,
        );
        let mut entries = Vec::new();
        for (index, crc) in [first_crc, second_crc].into_iter().enumerate() {
            let size = sizes
                .get(index)
                .copied()
                .ok_or_else(|| crate::parse_util::format_error("test member size is missing"))?;
            entries.push(FileEntry::new(
                None,
                true,
                false,
                false,
                None,
                None,
                None,
                None,
                None,
                Some(FileStream::new(
                    0,
                    usize_to_u64(index, "test substream index is not representable as u64")?,
                    size,
                    Some(crc),
                )),
            ));
        }
        let entries = entries.into_boxed_slice();
        let header = ArchiveHeader::new(
            Box::default(),
            None,
            Some(streams),
            Some(FilesInfo::new(entries, Box::default(), Box::default())),
        );
        Archive::from_parts(
            data.as_slice().into(),
            HeaderEnvelope::new(
                0,
                ArchiveVersion::new(0, 4),
                4,
                0,
                0,
                NextHeaderKind::Header,
            ),
            header,
            limits,
            None,
        )
    }

    fn many_zero_size_substreams_archive(count: usize) -> Result<Archive> {
        let count_u64 = usize_to_u64(count, "test substream count is not representable as u64")?;
        let coder = Coder::new(METHOD_COPY.into(), 0, 1, 0, 1, Box::default(), None);
        let mut substreams = Vec::new();
        let mut entries = Vec::new();
        substreams
            .try_reserve_exact(count)
            .map_err(|_| crate::parse_util::format_error("test substream allocation failed"))?;
        entries
            .try_reserve_exact(count)
            .map_err(|_| crate::parse_util::format_error("test entry allocation failed"))?;
        for index in 0..count {
            let index = usize_to_u64(index, "test substream index is not representable as u64")?;
            substreams.push(Substream::new(Some(0), None));
            entries.push(FileEntry::new(
                None,
                true,
                false,
                false,
                None,
                None,
                None,
                None,
                None,
                Some(FileStream::new(0, index, Some(0), None)),
            ));
        }
        let folder = Folder::new(
            vec![coder].into_boxed_slice(),
            Box::default(),
            vec![0].into_boxed_slice(),
            vec![Some(0)].into_boxed_slice(),
            0,
            vec![0].into_boxed_slice(),
            None,
            substreams.into_boxed_slice(),
            0,
            0,
        );
        let header = ArchiveHeader::new(
            Box::default(),
            None,
            Some(StreamsInfo::new(
                0,
                vec![PackStream::new(0, Some(0), None)].into_boxed_slice(),
                vec![folder].into_boxed_slice(),
                count_u64,
            )),
            Some(FilesInfo::new(
                entries.into_boxed_slice(),
                Box::default(),
                Box::default(),
            )),
        );
        Archive::from_parts(
            Box::default(),
            HeaderEnvelope::new(
                0,
                ArchiveVersion::new(0, 4),
                0,
                0,
                0,
                NextHeaderKind::Header,
            ),
            header,
            Limits::default(),
            None,
        )
    }

    fn push_small_uint(bytes: &mut Vec<u8>, value: u64) -> Result<()> {
        let value = u8::try_from(value)
            .map_err(|_| crate::parse_util::format_error("test integer exceeds one byte"))?;
        if value >= 0x80 {
            return Err(crate::parse_util::format_error(
                "test integer exceeds one-byte 7z encoding",
            ));
        }
        bytes.push(value);
        Ok(())
    }

    fn copy_encoded_descriptor(
        pack_position: u64,
        packed_size: u64,
        unpacked_size: u64,
        folder_crc: Option<u32>,
    ) -> Result<Vec<u8>> {
        let mut descriptor = Vec::from([0x17, 0x06]);
        push_small_uint(&mut descriptor, pack_position)?;
        push_small_uint(&mut descriptor, 1)?;
        descriptor.push(0x09);
        push_small_uint(&mut descriptor, packed_size)?;
        descriptor.extend_from_slice(&[0x00, 0x07, 0x0b]);
        push_small_uint(&mut descriptor, 1)?;
        descriptor.push(0);
        push_small_uint(&mut descriptor, 1)?;
        descriptor.extend_from_slice(&[1, 0, 0x0c]);
        push_small_uint(&mut descriptor, unpacked_size)?;
        if let Some(crc) = folder_crc {
            descriptor.extend_from_slice(&[0x0a, 1]);
            descriptor.extend_from_slice(&crc.to_le_bytes());
        }
        descriptor.extend_from_slice(&[0x00, 0x00]);
        Ok(descriptor)
    }

    fn multi_folder_copy_encoded_descriptor(
        pack_position: u64,
        folders: &[&[u8]],
        folder_crcs: &[u32],
    ) -> Result<Vec<u8>> {
        if folders.is_empty() || folders.len() != folder_crcs.len() {
            return Err(crate::parse_util::format_error(
                "test encoded-header folder vectors are inconsistent",
            ));
        }
        let folder_count = usize_to_u64(
            folders.len(),
            "test encoded-header folder count is not representable as u64",
        )?;
        let mut descriptor = Vec::from([0x17, 0x06]);
        push_small_uint(&mut descriptor, pack_position)?;
        push_small_uint(&mut descriptor, folder_count)?;
        descriptor.push(0x09);
        for bytes in folders {
            push_small_uint(
                &mut descriptor,
                usize_to_u64(
                    bytes.len(),
                    "test encoded-header folder size is not representable as u64",
                )?,
            )?;
        }
        descriptor.extend_from_slice(&[0x00, 0x07, 0x0b]);
        push_small_uint(&mut descriptor, folder_count)?;
        descriptor.push(0);
        for _ in folders {
            descriptor.extend_from_slice(&[1, 1, 0]);
        }
        descriptor.push(0x0c);
        for bytes in folders {
            push_small_uint(
                &mut descriptor,
                usize_to_u64(
                    bytes.len(),
                    "test encoded-header unpacked size is not representable as u64",
                )?,
            )?;
        }
        descriptor.extend_from_slice(&[0x0a, 1]);
        for crc in folder_crcs {
            descriptor.extend_from_slice(&crc.to_le_bytes());
        }
        descriptor.extend_from_slice(&[0x00, 0x00]);
        Ok(descriptor)
    }

    fn multi_substream_copy_encoded_descriptor(
        pack_position: u64,
        bytes: &[u8],
        first_size: u64,
        substream_crcs: [u32; 2],
    ) -> Result<Vec<u8>> {
        let packed_size = usize_to_u64(
            bytes.len(),
            "test encoded-header packed size is not representable as u64",
        )?;
        let mut descriptor = Vec::from([0x17, 0x06]);
        push_small_uint(&mut descriptor, pack_position)?;
        push_small_uint(&mut descriptor, 1)?;
        descriptor.push(0x09);
        push_small_uint(&mut descriptor, packed_size)?;
        descriptor.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
        push_small_uint(&mut descriptor, packed_size)?;
        descriptor.extend_from_slice(&[0x0a, 1]);
        descriptor.extend_from_slice(&Crc32::checksum(bytes)?.to_le_bytes());
        descriptor.extend_from_slice(&[0x00, 0x08, 0x0d, 2, 0x09]);
        push_small_uint(&mut descriptor, first_size)?;
        descriptor.extend_from_slice(&[0x0a, 1]);
        for crc in substream_crcs {
            descriptor.extend_from_slice(&crc.to_le_bytes());
        }
        descriptor.extend_from_slice(&[0x00, 0x00]);
        Ok(descriptor)
    }

    const ENCODED_HEADER_FIRST: &[u8] = &[0x01, 0x05, 0x01, 0x0e, 0x01, 0x80, 0x0f, 0x01, 0x80];
    const ENCODED_HEADER_SECOND: &[u8] = &[0x11, 0x05, 0x00, b'x', 0x00, 0x00, 0x00, 0x00, 0x00];

    fn multi_folder_copy_encoded_header_archive(folder_crcs: [u32; 2]) -> Result<Vec<u8>> {
        let descriptor = multi_folder_copy_encoded_descriptor(
            0,
            &[ENCODED_HEADER_FIRST, ENCODED_HEADER_SECOND],
            &folder_crcs,
        )?;
        let mut header = Vec::from(ENCODED_HEADER_FIRST);
        header.extend_from_slice(ENCODED_HEADER_SECOND);
        archive_with_payload_and_next_header(&header, &descriptor)
    }

    fn single_folder_copy_encoded_header_archive() -> Result<Vec<u8>> {
        let mut header = Vec::from(ENCODED_HEADER_FIRST);
        header.extend_from_slice(ENCODED_HEADER_SECOND);
        let size = usize_to_u64(
            header.len(),
            "test encoded-header size is not representable as u64",
        )?;
        let descriptor = copy_encoded_descriptor(0, size, size, Some(Crc32::checksum(&header)?))?;
        archive_with_payload_and_next_header(&header, &descriptor)
    }

    fn multi_substream_copy_encoded_header_archive(substream_crcs: [u32; 2]) -> Result<Vec<u8>> {
        let mut header = Vec::from(ENCODED_HEADER_FIRST);
        header.extend_from_slice(ENCODED_HEADER_SECOND);
        let first_size = usize_to_u64(
            ENCODED_HEADER_FIRST.len(),
            "test encoded-header substream size is not representable as u64",
        )?;
        let descriptor =
            multi_substream_copy_encoded_descriptor(0, &header, first_size, substream_crcs)?;
        archive_with_payload_and_next_header(&header, &descriptor)
    }

    fn stock_7zz_accepts(bytes: &[u8]) -> Result<bool> {
        static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "unpackio-encoded-header-{}-{nonce}.7z",
            std::process::id(),
        ));
        fs::write(&path, bytes).map_err(Error::Io)?;
        let result = Command::new("7zz").args(["t", "-bd"]).arg(&path).output();
        let cleanup = fs::remove_file(&path);
        let output = result.map_err(Error::Io)?;
        cleanup.map_err(Error::Io)?;
        if !output.status.success() {
            eprintln!("7zz stdout:\n{}", String::from_utf8_lossy(&output.stdout));
            eprintln!("7zz stderr:\n{}", String::from_utf8_lossy(&output.stderr));
        }
        Ok(output.status.success())
    }

    fn assert_encoded_header_entry(archive: &Archive) -> Result<()> {
        if archive.entries().len() != 1 {
            return Err(crate::parse_util::format_error(
                "decoded test header has the wrong entry count",
            ));
        }
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| crate::parse_util::format_error("decoded test entry is missing"))?;
        assert_eq!(entry.raw_name(), Some(&[u16::from(b'x')][..]));
        assert!(entry.is_empty_file());
        assert_eq!(entry.size(), Some(0));
        Ok(())
    }

    fn nested_copy_encoded_header_archive() -> Result<(Vec<u8>, u64)> {
        let plain_header = [0x01, 0x00];
        let plain_size = usize_to_u64(
            plain_header.len(),
            "test plain header size is not representable as u64",
        )?;
        let inner = copy_encoded_descriptor(
            0,
            plain_size,
            plain_size,
            Some(Crc32::checksum(&plain_header)?),
        )?;
        let inner_size = usize_to_u64(
            inner.len(),
            "test inner header size is not representable as u64",
        )?;
        let outer = copy_encoded_descriptor(
            plain_size,
            inner_size,
            inner_size,
            Some(Crc32::checksum(&inner)?),
        )?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&plain_header);
        payload.extend_from_slice(&inner);
        let next_offset = usize_to_u64(
            payload.len(),
            "test payload size is not representable as u64",
        )?;
        let next_size = usize_to_u64(
            outer.len(),
            "test next header size is not representable as u64",
        )?;
        let next_crc = Crc32::checksum(&outer)?;
        let mut start_fields = Vec::new();
        start_fields.extend_from_slice(&next_offset.to_le_bytes());
        start_fields.extend_from_slice(&next_size.to_le_bytes());
        start_fields.extend_from_slice(&next_crc.to_le_bytes());
        let mut archive = Vec::from(b"7z\xbc\xaf\x27\x1c".as_slice());
        archive.extend_from_slice(&[0, 4]);
        archive.extend_from_slice(&Crc32::checksum(&start_fields)?.to_le_bytes());
        archive.extend_from_slice(&start_fields);
        archive.extend_from_slice(&payload);
        archive.extend_from_slice(&outer);
        let total_decoded = inner_size
            .checked_add(plain_size)
            .ok_or_else(|| crate::parse_util::format_error("test decoded size overflows"))?;
        Ok((archive, total_decoded))
    }

    fn archive_with_payload_and_next_header(payload: &[u8], next_header: &[u8]) -> Result<Vec<u8>> {
        let next_offset = usize_to_u64(
            payload.len(),
            "test payload size is not representable as u64",
        )?;
        let next_size = usize_to_u64(
            next_header.len(),
            "test next-header size is not representable as u64",
        )?;
        let next_crc = Crc32::checksum(next_header)?;
        let mut start_fields = Vec::new();
        start_fields.extend_from_slice(&next_offset.to_le_bytes());
        start_fields.extend_from_slice(&next_size.to_le_bytes());
        start_fields.extend_from_slice(&next_crc.to_le_bytes());
        let mut archive = Vec::from(b"7z\xbc\xaf\x27\x1c".as_slice());
        archive.extend_from_slice(&[0, 4]);
        archive.extend_from_slice(&Crc32::checksum(&start_fields)?.to_le_bytes());
        archive.extend_from_slice(&start_fields);
        archive.extend_from_slice(payload);
        archive.extend_from_slice(next_header);
        Ok(archive)
    }

    fn external_name_archive(name_stream: &[u8]) -> Result<Vec<u8>> {
        let stream_size = usize_to_u64(
            name_stream.len(),
            "test external-name size is not representable as u64",
        )?;
        let mut header = Vec::from([0x01, 0x03, 0x06]);
        push_small_uint(&mut header, 0)?;
        push_small_uint(&mut header, 1)?;
        header.push(0x09);
        push_small_uint(&mut header, stream_size)?;
        header.extend_from_slice(&[0x00, 0x07, 0x0b]);
        push_small_uint(&mut header, 1)?;
        header.push(0);
        push_small_uint(&mut header, 1)?;
        header.extend_from_slice(&[1, 0, 0x0c]);
        push_small_uint(&mut header, stream_size)?;
        header.extend_from_slice(&[
            0x00, 0x00, 0x05, 0x01, 0x0e, 0x01, 0x80, 0x0f, 0x01, 0x80, 0x11, 0x02, 0x01, 0x00,
            0x00, 0x00,
        ]);
        archive_with_payload_and_next_header(name_stream, &header)
    }

    struct AdditionalFixture<'data> {
        packed: &'data [u8],
        unpacked_size: u64,
        folder_definition: &'data [u8],
        packed_crc: Option<u32>,
        folder_crc: Option<u32>,
        substream_crc: Option<u32>,
    }

    fn unreferenced_additional_archive(
        fixture: AdditionalFixture<'_>,
        member: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if fixture.folder_crc.is_some() && fixture.substream_crc.is_some() {
            return Err(crate::parse_util::format_error(
                "test additional stream cannot declare both folder and explicit substream CRCs",
            ));
        }
        let packed_size = usize_to_u64(
            fixture.packed.len(),
            "test additional packed size is not representable as u64",
        )?;
        let mut header = Vec::from([0x01, 0x03, 0x06]);
        push_small_uint(&mut header, 0)?;
        push_small_uint(&mut header, 1)?;
        header.push(0x09);
        push_small_uint(&mut header, packed_size)?;
        if let Some(crc) = fixture.packed_crc {
            header.extend_from_slice(&[0x0a, 1]);
            header.extend_from_slice(&crc.to_le_bytes());
        }
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0]);
        header.extend_from_slice(fixture.folder_definition);
        header.push(0x0c);
        push_small_uint(&mut header, fixture.unpacked_size)?;
        if let Some(crc) = fixture.folder_crc {
            header.extend_from_slice(&[0x0a, 1]);
            header.extend_from_slice(&crc.to_le_bytes());
        }
        header.push(0x00);
        if let Some(crc) = fixture.substream_crc {
            header.extend_from_slice(&[0x08, 0x0a, 1]);
            header.extend_from_slice(&crc.to_le_bytes());
            header.push(0x00);
        }
        header.push(0x00);
        if let Some(member) = member {
            let member_size =
                usize_to_u64(member.len(), "test member size is not representable as u64")?;
            let member_crc = Crc32::checksum(member)?;
            header.extend_from_slice(&[0x04, 0x06]);
            push_small_uint(&mut header, packed_size)?;
            push_small_uint(&mut header, 1)?;
            header.push(0x09);
            push_small_uint(&mut header, member_size)?;
            header.extend_from_slice(&[0x0a, 1]);
            header.extend_from_slice(&member_crc.to_le_bytes());
            header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
            push_small_uint(&mut header, member_size)?;
            header.extend_from_slice(&[0x0a, 1]);
            header.extend_from_slice(&member_crc.to_le_bytes());
            header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x00]);
        }
        header.push(0x00);

        let member_bytes = match member {
            Some(bytes) => bytes,
            None => &[],
        };
        let capacity = fixture
            .packed
            .len()
            .checked_add(member_bytes.len())
            .ok_or_else(|| crate::parse_util::format_error("test payload size overflows"))?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(capacity)
            .map_err(|_| crate::parse_util::format_error("test payload allocation failed"))?;
        payload.extend_from_slice(fixture.packed);
        payload.extend_from_slice(member_bytes);
        archive_with_payload_and_next_header(&payload, &header)
    }

    fn direct_aes_test_block(plaintext: &[u8], password: &str) -> Result<[u8; 16]> {
        let mut key = [0_u8; 32];
        let password_bytes = password.as_bytes();
        if password_bytes.len() != 1 {
            return Err(crate::parse_util::format_error(
                "test AES password must contain one ASCII byte",
            ));
        }
        let password_byte = password_bytes
            .first()
            .copied()
            .ok_or_else(|| crate::parse_util::format_error("test AES password is empty"))?;
        key[0] = password_byte;
        let iv = [0_u8; 16];
        let mut ciphertext = [0_u8; 16];
        ciphertext
            .get_mut(..plaintext.len())
            .ok_or_else(|| crate::parse_util::format_error("test AES plaintext is too long"))?
            .copy_from_slice(plaintext);
        let mut encryptor = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
            .map_err(|_| crate::parse_util::format_error("test AES key or IV is invalid"))?;
        let block: &mut Block<cbc::Encryptor<Aes256>> = ciphertext
            .as_mut_slice()
            .try_into()
            .map_err(|_| crate::parse_util::format_error("test AES block is invalid"))?;
        encryptor.encrypt_block(block);
        Ok(ciphertext)
    }

    fn encrypted_unreferenced_additional_archive(password: &str) -> Result<Vec<u8>> {
        const ADDITIONAL: &[u8] = b"aux";
        const AES_FOLDER: &[u8] = &[1, 0x24, 0x06, 0xf1, 0x07, 0x01, 2, 0x3f, 0];
        let ciphertext = direct_aes_test_block(ADDITIONAL, password)?;
        unreferenced_additional_archive(
            AdditionalFixture {
                packed: &ciphertext,
                unpacked_size: usize_to_u64(
                    ADDITIONAL.len(),
                    "test additional output size is not representable as u64",
                )?,
                folder_definition: AES_FOLDER,
                packed_crc: Some(Crc32::checksum(&ciphertext)?),
                folder_crc: Some(Crc32::checksum(ADDITIONAL)?),
                substream_crc: None,
            },
            Some(b"payload"),
        )
    }

    fn copy_unreferenced_additional_archive(
        packed_crc: Option<u32>,
        folder_crc: Option<u32>,
        substream_crc: Option<u32>,
    ) -> Result<Vec<u8>> {
        const ADDITIONAL: &[u8] = b"aux";
        unreferenced_additional_archive(
            AdditionalFixture {
                packed: ADDITIONAL,
                unpacked_size: usize_to_u64(
                    ADDITIONAL.len(),
                    "test additional output size is not representable as u64",
                )?,
                folder_definition: &[1, 1, 0],
                packed_crc,
                folder_crc,
                substream_crc,
            },
            Some(b"payload"),
        )
    }

    fn split_across_additional_and_header(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let first_end = 33_usize;
        let second_end = bytes
            .len()
            .checked_sub(1)
            .ok_or_else(|| crate::parse_util::format_error("test archive is empty"))?;
        if second_end <= first_end {
            return Err(crate::parse_util::format_error(
                "test archive is too short for three volume parts",
            ));
        }
        let first = bytes
            .get(..first_end)
            .ok_or_else(|| crate::parse_util::format_error("test first volume is out of range"))?;
        let second = bytes
            .get(first_end..second_end)
            .ok_or_else(|| crate::parse_util::format_error("test second volume is out of range"))?;
        let third = bytes
            .get(second_end..)
            .ok_or_else(|| crate::parse_util::format_error("test third volume is out of range"))?;
        Ok(vec![first.to_vec(), second.to_vec(), third.to_vec()])
    }

    fn external_folder_archive(
        folder_definition: &[u8],
        data_index: u64,
        first_substream_crc: Option<u32>,
        additional_folder_crc: Option<u32>,
    ) -> Result<Vec<u8>> {
        const MEMBER: &[u8] = b"payload";
        let folder_size = usize_to_u64(
            folder_definition.len(),
            "test external-folder size is not representable as u64",
        )?;
        let additional_size = folder_size;
        let member_size =
            usize_to_u64(MEMBER.len(), "test member size is not representable as u64")?;
        let additional_crc = Crc32::checksum(folder_definition)?;
        let member_crc = Crc32::checksum(MEMBER)?;

        let mut header = Vec::from([0x01, 0x03, 0x06]);
        push_small_uint(&mut header, 0)?;
        push_small_uint(&mut header, 1)?;
        header.push(0x09);
        push_small_uint(&mut header, additional_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&additional_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
        push_small_uint(&mut header, additional_size)?;
        if first_substream_crc.is_none() {
            header.extend_from_slice(&[0x0a, 1]);
            header.extend_from_slice(
                &additional_folder_crc
                    .unwrap_or(additional_crc)
                    .to_le_bytes(),
            );
        }
        header.push(0x00);
        if let Some(crc) = first_substream_crc {
            header.extend_from_slice(&[0x08, 0x0a, 1]);
            header.extend_from_slice(&crc.to_le_bytes());
            header.push(0x00);
        }
        header.extend_from_slice(&[0x00, 0x04, 0x06]);
        push_small_uint(&mut header, additional_size)?;
        push_small_uint(&mut header, 1)?;
        header.push(0x09);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 1]);
        push_small_uint(&mut header, data_index)?;
        header.push(0x0c);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[
            0x00, 0x00, 0x05, 0x01, 0x11, 0x05, 0x00, b'x', 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let mut payload = Vec::new();
        payload.extend_from_slice(folder_definition);
        payload.extend_from_slice(MEMBER);
        archive_with_payload_and_next_header(&payload, &header)
    }

    fn second_external_folder_archive() -> Result<Vec<u8>> {
        const FIRST: &[u8] = &[b'x', 0, 0, 0];
        const FOLDER_DEFINITION: &[u8] = &[1, 1, 0];
        const MEMBER: &[u8] = b"payload";
        let first_size = usize_to_u64(
            FIRST.len(),
            "test first additional-stream size is not representable as u64",
        )?;
        let folder_size = usize_to_u64(
            FOLDER_DEFINITION.len(),
            "test external-folder size is not representable as u64",
        )?;
        let additional_size = first_size
            .checked_add(folder_size)
            .ok_or_else(|| crate::parse_util::format_error("test additional size overflows"))?;
        let member_size =
            usize_to_u64(MEMBER.len(), "test member size is not representable as u64")?;
        let first_crc = Crc32::checksum(FIRST)?;
        let folder_crc = Crc32::checksum(FOLDER_DEFINITION)?;
        let member_crc = Crc32::checksum(MEMBER)?;

        let mut header = Vec::from([0x01, 0x03, 0x06, 0, 2, 0x09]);
        push_small_uint(&mut header, first_size)?;
        push_small_uint(&mut header, folder_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&first_crc.to_le_bytes());
        header.extend_from_slice(&folder_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 2, 0]);
        header.extend_from_slice(&[1, 1, 0, 1, 1, 0, 0x0c]);
        push_small_uint(&mut header, first_size)?;
        push_small_uint(&mut header, folder_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&first_crc.to_le_bytes());
        header.extend_from_slice(&folder_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x04, 0x06]);
        push_small_uint(&mut header, additional_size)?;
        push_small_uint(&mut header, 1)?;
        header.push(0x09);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 1, 1, 0x0c]);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x11, 0x02, 1, 0, 0x00, 0x00]);

        let mut payload = Vec::new();
        payload.extend_from_slice(FIRST);
        payload.extend_from_slice(FOLDER_DEFINITION);
        payload.extend_from_slice(MEMBER);
        archive_with_payload_and_next_header(&payload, &header)
    }

    fn encrypted_external_folder_archive(password: &str) -> Result<Vec<u8>> {
        encrypted_external_folder_archive_with_main_position(password, 16)
    }

    fn encrypted_external_folder_archive_with_main_position(
        password: &str,
        main_pack_position: u64,
    ) -> Result<Vec<u8>> {
        const FOLDER_DEFINITION: &[u8] = &[1, 1, 0];
        const MEMBER: &[u8] = b"payload";
        let ciphertext = direct_aes_test_block(FOLDER_DEFINITION, password)?;

        let member_size =
            usize_to_u64(MEMBER.len(), "test member size is not representable as u64")?;
        let folder_crc = Crc32::checksum(FOLDER_DEFINITION)?;
        let member_crc = Crc32::checksum(MEMBER)?;
        let mut header = Vec::from([0x01, 0x03, 0x06, 0, 1, 0x09, 16, 0x0a, 1]);
        header.extend_from_slice(&Crc32::checksum(&ciphertext)?.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 0x24]);
        header.extend_from_slice(&[0x06, 0xf1, 0x07, 0x01, 2, 0x3f, 0, 0x0c, 3, 0x0a, 1]);
        header.extend_from_slice(&folder_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x04, 0x06]);
        push_small_uint(&mut header, main_pack_position)?;
        header.extend_from_slice(&[1, 0x09]);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 1, 0, 0x0c]);
        push_small_uint(&mut header, member_size)?;
        header.extend_from_slice(&[0x0a, 1]);
        header.extend_from_slice(&member_crc.to_le_bytes());
        header.extend_from_slice(&[
            0x00, 0x00, 0x05, 0x01, 0x11, 0x05, 0x00, b'x', 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let mut payload = Vec::from(ciphertext);
        payload.extend_from_slice(MEMBER);
        archive_with_payload_and_next_header(&payload, &header)
    }

    #[test]
    fn finish_and_high_level_extraction_reject_bad_member_crc() -> Result<()> {
        let data = b"copy member";
        let bad_crc = Crc32::checksum(data)? ^ 1;
        let archive = one_member_copy_archive(data, Some(bad_crc), None, None, Limits::default())?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut reader = archive.open_member(0, &cancellation, &mut budget)?;
        let mut output = [0_u8; 32];
        let count = reader.read_chunk(&mut output)?;
        assert_eq!(output.get(..count), Some(data.as_slice()));
        assert!(matches!(
            reader.finish(),
            Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(0)
            })
        ));

        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.extract_entry(0, &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(0)
            })
        ));
        Ok(())
    }

    #[test]
    fn production_open_resolves_external_name_stream_exactly() -> Result<()> {
        let bytes = external_name_archive(&[b'a', 0, 0, 0])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| crate::parse_util::format_error("external-name entry is missing"))?;
        assert_eq!(entry.raw_name(), Some(&[u16::from(b'a')][..]));
        assert!(entry.is_empty_file());

        let trailing = external_name_archive(&[b'a', 0, 0, 0, 7, 0])?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(trailing, Limits::default(), &cancellation, &mut budget,),
            Err(Error::Format { .. })
        ));
        Ok(())
    }

    #[test]
    fn production_open_resolves_external_folder_stream_exactly() -> Result<()> {
        let bytes = external_folder_archive(&[1, 1, 0], 0, None, None)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        let entry = archive
            .entries()
            .first()
            .ok_or_else(|| crate::parse_util::format_error("external-folder entry is missing"))?;
        assert_eq!(entry.raw_name(), Some(&[u16::from(b'x')][..]));
        assert_eq!(entry.size(), Some(7));
        let mut budget = WorkBudget::unlimited();
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            b"payload"
        );

        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(
            second_external_folder_archive()?,
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(
            archive.entries().first().and_then(FileEntry::raw_name),
            Some(&[u16::from(b'x')][..])
        );
        let mut budget = WorkBudget::unlimited();
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            b"payload"
        );
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    }

    #[test]
    fn external_folder_stream_rejects_truncation_trailing_bytes_and_bad_index() -> Result<()> {
        let cancellation = CancellationToken::new();
        for folder_definition in [&[1, 1][..], &[1, 1, 0, 0][..]] {
            let bytes = external_folder_archive(folder_definition, 0, None, None)?;
            let mut budget = WorkBudget::unlimited();
            assert!(matches!(
                Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
                Err(Error::Format { .. })
            ));
        }

        let bytes = external_folder_archive(&[1, 1, 0], 1, None, None)?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Format { .. })
        ));
        Ok(())
    }

    #[test]
    fn every_external_folder_archive_prefix_is_rejected() -> Result<()> {
        let bytes = second_external_folder_archive()?;
        let cancellation = CancellationToken::new();
        for end in 0..bytes.len() {
            let prefix = bytes.get(..end).ok_or_else(|| {
                crate::parse_util::format_error("external-folder prefix is out of range")
            })?;
            let mut budget = WorkBudget::unlimited();
            assert!(
                Archive::open_bytes(
                    prefix.to_vec(),
                    Limits::default(),
                    &cancellation,
                    &mut budget,
                )
                .is_err(),
                "prefix {end} unexpectedly opened",
            );
        }
        Ok(())
    }

    #[test]
    fn external_folder_stream_verifies_folder_and_substream_crcs() -> Result<()> {
        let folder_definition = [1, 1, 0];
        let cancellation = CancellationToken::new();
        let bytes = external_folder_archive(
            &folder_definition,
            0,
            Some(Crc32::checksum(&folder_definition)? ^ 1),
            None,
        )?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::AdditionalStream,
                member_index: None,
            })
        ));

        let bytes = external_folder_archive(
            &folder_definition,
            0,
            None,
            Some(Crc32::checksum(b"wrong")?),
        )?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::Folder,
                member_index: None,
            })
        ));

        let mut bytes = external_folder_archive(&folder_definition, 0, None, None)?;
        let packed_byte = bytes.get_mut(32).ok_or_else(|| {
            crate::parse_util::format_error("external-folder packed byte is missing")
        })?;
        *packed_byte ^= 1;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::PackedStream,
                member_index: None,
            })
        ));
        Ok(())
    }

    #[test]
    fn external_folder_stream_enforces_combined_coder_and_output_limits() -> Result<()> {
        let bytes = external_folder_archive(&[1, 1, 0], 0, None, None)?;
        let cancellation = CancellationToken::new();
        let limits = Limits::builder().max_total_coders(1).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes.clone(), limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalCoders,
                requested: 2,
                maximum: 1,
            })
        ));

        let limits = Limits::builder().max_total_output_bytes(2).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn encrypted_external_folder_stream_keeps_password_state_typed() -> Result<()> {
        let bytes = encrypted_external_folder_archive("a")?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes.clone(), Limits::default(), &cancellation, &mut budget,),
            Err(Error::PasswordRequired)
        ));

        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes_with_password(
                bytes.clone(),
                Limits::default(),
                "b",
                &cancellation,
                &mut budget,
            ),
            Err(Error::WrongPasswordOrCorrupt)
        ));

        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes_with_password(
            bytes,
            Limits::default(),
            "a",
            &cancellation,
            &mut budget,
        )?;
        let mut budget = WorkBudget::unlimited();
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            b"payload"
        );
        Ok(())
    }

    #[test]
    fn external_main_pack_ranges_are_validated_before_source_decode() -> Result<()> {
        let bytes = encrypted_external_folder_archive_with_main_position("a", 0)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Format { .. })
        ));
        Ok(())
    }

    #[test]
    fn verify_includes_unreferenced_additional_streams() -> Result<()> {
        let crc = Crc32::checksum(b"aux")?;
        let bytes = unreferenced_additional_archive(
            AdditionalFixture {
                packed: b"aux",
                unpacked_size: 3,
                folder_definition: &[1, 1, 0],
                packed_crc: Some(crc),
                folder_crc: Some(crc),
                substream_crc: None,
            },
            None,
        )?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        assert!(archive.entries().is_empty());
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;

        let bytes = copy_unreferenced_additional_archive(Some(crc), Some(crc), None)?;
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        let mut budget = WorkBudget::unlimited();
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            b"payload"
        );
        Ok(())
    }

    #[test]
    fn unreferenced_additional_stream_crc_failures_keep_their_scope() -> Result<()> {
        let crc = Crc32::checksum(b"aux")?;
        let cases = [
            (
                copy_unreferenced_additional_archive(Some(crc ^ 1), Some(crc), None)?,
                ChecksumScope::PackedStream,
            ),
            (
                copy_unreferenced_additional_archive(Some(crc), Some(crc ^ 1), None)?,
                ChecksumScope::Folder,
            ),
            (
                copy_unreferenced_additional_archive(Some(crc), None, Some(crc ^ 1))?,
                ChecksumScope::AdditionalStream,
            ),
        ];
        let cancellation = CancellationToken::new();
        for (bytes, expected_scope) in cases {
            let mut budget = WorkBudget::unlimited();
            let archive =
                Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
            let mut budget = WorkBudget::unlimited();
            assert!(matches!(
                archive.verify(&cancellation, &mut budget),
                Err(Error::Checksum {
                    scope,
                    member_index: None,
                }) if scope == expected_scope
            ));
        }
        Ok(())
    }

    #[test]
    fn unreferenced_encrypted_additional_stream_password_states() -> Result<()> {
        let bytes = encrypted_unreferenced_additional_archive("a")?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive =
            Archive::open_bytes(bytes.clone(), Limits::default(), &cancellation, &mut budget)?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::PasswordRequired)
        ));

        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes_with_password(
            bytes.clone(),
            Limits::default(),
            "b",
            &cancellation,
            &mut budget,
        )?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::WrongPasswordOrCorrupt)
        ));

        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes_with_password(
            bytes,
            Limits::default(),
            "a",
            &cancellation,
            &mut budget,
        )?;
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    }

    #[test]
    fn additional_and_main_verification_share_limits_and_operation_control() -> Result<()> {
        let crc = Crc32::checksum(b"aux")?;
        let bytes = copy_unreferenced_additional_archive(Some(crc), Some(crc), None)?;
        let cancellation = CancellationToken::new();
        let limits = Limits::builder().max_total_output_bytes(9).build();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes.clone(), limits, &cancellation, &mut budget)?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 7,
                maximum: 6,
            })
        ));

        let mut budget = WorkBudget::unlimited();
        let archive =
            Archive::open_bytes(bytes.clone(), Limits::default(), &cancellation, &mut budget)?;
        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn unreferenced_additional_streams_verify_across_memory_volumes() -> Result<()> {
        let crc = Crc32::checksum(b"aux")?;
        let bytes = copy_unreferenced_additional_archive(Some(crc), Some(crc), None)?;
        let mut provider = MemoryVolumeProvider::new(split_across_additional_and_header(&bytes)?);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_volumes(
            &mut provider,
            "additional.7z.001",
            Limits::default(),
            &cancellation,
            &mut budget,
        )?;
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;

        let bytes = encrypted_unreferenced_additional_archive("a")?;
        let mut provider = MemoryVolumeProvider::new(split_across_additional_and_header(&bytes)?);
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_volumes_with_password(
            &mut provider,
            "encrypted-additional.7z.001",
            Limits::default(),
            "a",
            &cancellation,
            &mut budget,
        )?;
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires stock 7zz 26.02"]
    fn stock_7zz_accepts_external_folder_stream() -> Result<()> {
        assert!(stock_7zz_accepts(&external_folder_archive(
            &[1, 1, 0],
            0,
            None,
            None,
        )?)?);
        assert!(stock_7zz_accepts(&second_external_folder_archive()?)?);
        let additional_crc = Crc32::checksum(b"aux")?;
        assert!(stock_7zz_accepts(&copy_unreferenced_additional_archive(
            Some(additional_crc),
            Some(additional_crc),
            None,
        )?)?);
        Ok(())
    }

    #[test]
    fn complete_corrupt_volume_set_preserves_checksum_error() -> Result<()> {
        let mut bytes = archive_with_payload_and_next_header(&[], &[0x01, 0x00])?;
        let final_byte = bytes.last_mut().ok_or_else(|| {
            crate::parse_util::format_error("test archive unexpectedly has no bytes")
        })?;
        *final_byte ^= 1;
        let mut provider = MemoryVolumeProvider::new(vec![bytes]);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let result = Archive::open_volumes(
            &mut provider,
            "corrupt.7z.001",
            Limits::default(),
            &cancellation,
            &mut budget,
        );
        assert!(matches!(
            result,
            Err(Error::Checksum {
                scope: ChecksumScope::NextHeader,
                member_index: None,
            })
        ));
        Ok(())
    }

    #[test]
    fn packed_and_folder_crc_failures_keep_their_scope() -> Result<()> {
        let data = b"copy member";
        let crc = Crc32::checksum(data)?;
        let cancellation = CancellationToken::new();
        let packed =
            one_member_copy_archive(data, Some(crc), Some(crc), Some(crc ^ 1), Limits::default())?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            packed.open_member(0, &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::PackedStream,
                member_index: None
            })
        ));

        let folder =
            one_member_copy_archive(data, Some(crc), Some(crc ^ 1), None, Limits::default())?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            folder.open_member(0, &cancellation, &mut budget)?.finish(),
            Err(Error::Checksum {
                scope: ChecksumScope::Folder,
                member_index: None
            })
        ));
        Ok(())
    }

    #[test]
    fn output_work_and_cancellation_limits_precede_decode_work() -> Result<()> {
        let data = b"four";
        let limits = Limits::builder().max_total_output_bytes(3).build();
        let archive = one_member_copy_archive(data, None, None, None, limits)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 4,
                maximum: 3
            })
        ));
        assert_eq!(budget.remaining(), Some(0));

        let archive = one_member_copy_archive(data, None, None, None, Limits::default())?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::Cancelled)
        ));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn per_entry_output_limit_is_preflighted_for_every_solid_member() -> Result<()> {
        let correct_second = Crc32::checksum(b"cd")?;
        let mut archive = two_member_solid_copy_archive(correct_second)?;
        archive.limits = Limits::builder()
            .max_entry_output_bytes(1)
            .max_total_output_bytes(4)
            .build();
        let cancellation = CancellationToken::new();

        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                requested: 2,
                maximum: 1
            })
        ));
        assert_eq!(budget.remaining(), Some(0));

        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                requested: 2,
                maximum: 1
            })
        ));
        assert_eq!(budget.remaining(), Some(0));

        let mut budget = WorkBudget::unlimited();
        let mut sink = CollectSink::default();
        assert!(matches!(
            archive.extract_entries_to(&mut sink, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                requested: 2,
                maximum: 1
            })
        ));
        assert!(sink.entries.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_final_member_uses_entry_output_as_a_decode_cap() -> Result<()> {
        let archive = one_member_copy_archive_with_size(
            b"four",
            None,
            None,
            None,
            None,
            Limits::builder()
                .max_entry_output_bytes(3)
                .max_total_output_bytes(8)
                .build(),
        )?;
        let cancellation = CancellationToken::new();

        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 4,
                maximum: 3
            })
        ));

        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 4,
                maximum: 3
            })
        ));
        Ok(())
    }

    #[test]
    fn unknown_lzma_member_extracts_only_after_eos_and_crc() -> Result<()> {
        let archive = one_member_unknown_lzma_archive()?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let bytes = archive.extract_entry(0, &cancellation, &mut budget)?;
        assert_eq!(bytes, b"abc");

        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;
        Ok(())
    }

    #[test]
    fn unknown_nonfinal_member_is_rejected_before_decode() -> Result<()> {
        let archive = two_member_solid_copy_archive_with_sizes(
            [None, Some(2)],
            Crc32::checksum(b"cd")?,
            Limits::default(),
        )?;
        let cancellation = CancellationToken::new();

        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.open_member(0, &cancellation, &mut budget),
            Err(Error::UnsupportedFeature { feature })
                if feature == "unknown-nonfinal-substream-size"
        ));
        assert_eq!(budget.remaining(), Some(0));

        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            archive.verify(&cancellation, &mut budget),
            Err(Error::UnsupportedFeature { feature })
                if feature == "unknown-nonfinal-substream-size"
        ));
        assert_eq!(budget.remaining(), Some(0));

        let mut budget = WorkBudget::unlimited();
        let mut sink = CollectSink::default();
        assert!(matches!(
            archive.extract_entries_to(&mut sink, &cancellation, &mut budget),
            Err(Error::UnsupportedFeature { feature })
                if feature == "unknown-nonfinal-substream-size"
        ));
        assert!(sink.entries.is_empty());
        Ok(())
    }

    #[test]
    fn solid_verify_checks_each_member_with_one_total_folder_output() -> Result<()> {
        let correct_second = Crc32::checksum(b"cd")?;
        let archive = two_member_solid_copy_archive(correct_second)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        archive.verify(&cancellation, &mut budget)?;

        let corrupt = two_member_solid_copy_archive(correct_second ^ 1)?;
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            corrupt.verify(&cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(1)
            })
        ));
        Ok(())
    }

    #[test]
    fn duplicate_names_preserve_distinct_stream_mapping() -> Result<()> {
        let second_crc = Crc32::checksum(b"cd")?;
        let mut archive = two_member_solid_copy_archive(second_crc)?;
        let entries = archive
            .header
            .files_mut()
            .ok_or_else(|| crate::parse_util::format_error("test files are missing"))?
            .entries_and_external_mut()
            .0;
        for entry in entries.iter_mut() {
            entry.set_raw_name(Box::from([u16::from(b'x')]));
        }
        assert_eq!(
            archive.entries().first().and_then(FileEntry::raw_name),
            Some(&[u16::from(b'x')][..])
        );
        assert_eq!(
            archive.entries().get(1).and_then(FileEntry::raw_name),
            Some(&[u16::from(b'x')][..])
        );
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert_eq!(archive.extract_entry(0, &cancellation, &mut budget)?, b"ab");
        assert_eq!(archive.extract_entry(1, &cancellation, &mut budget)?, b"cd");
        Ok(())
    }

    #[test]
    fn large_solid_substream_walk_is_linear_and_work_charged() -> Result<()> {
        const COUNT: usize = 10_000;
        let archive = many_zero_size_substreams_archive(COUNT)?;
        let cancellation = CancellationToken::new();
        let work = usize_to_u64(COUNT, "test work count is not representable as u64")?
            .checked_mul(2)
            .ok_or_else(|| crate::parse_util::format_error("test work count overflows"))?
            .checked_add(3)
            .ok_or_else(|| crate::parse_util::format_error("test work count overflows"))?;

        let mut verify_budget = WorkBudget::bounded(work);
        archive.verify(&cancellation, &mut verify_budget)?;
        assert_eq!(verify_budget.remaining(), Some(0));

        let mut extraction_budget = WorkBudget::bounded(work);
        let mut sink = CollectSink::default();
        assert_eq!(
            archive.extract_entries_to(&mut sink, &cancellation, &mut extraction_budget)?,
            0
        );
        assert_eq!(extraction_budget.remaining(), Some(0));
        assert_eq!(sink.entries.len(), COUNT);
        assert_eq!(sink.finished.len(), COUNT);

        let last = usize_to_u64(
            COUNT.saturating_sub(1),
            "test member index is not representable as u64",
        )?;
        let mut random_access_budget = WorkBudget::bounded(work);
        archive
            .open_member(last, &cancellation, &mut random_access_budget)?
            .finish()?;
        assert_eq!(random_access_budget.remaining(), Some(0));
        Ok(())
    }

    #[test]
    fn nested_encoded_headers_share_one_total_output_limit() -> Result<()> {
        let (bytes, total_decoded) = nested_copy_encoded_header_archive()?;
        let cancellation = CancellationToken::new();
        let maximum = total_decoded
            .checked_sub(1)
            .ok_or_else(|| crate::parse_util::format_error("test output limit underflows"))?;
        let limits = Limits::builder().max_total_output_bytes(maximum).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes.clone(), limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                ..
            })
        ));

        let limits = Limits::builder()
            .max_total_output_bytes(total_decoded)
            .build();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, limits, &cancellation, &mut budget)?;
        assert!(archive.entries().is_empty());
        Ok(())
    }

    #[test]
    fn decodes_multi_folder_encoded_header_in_stream_order() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_folder_copy_encoded_header_archive([first_crc, second_crc])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        assert_encoded_header_entry(&archive)
    }

    #[test]
    fn decodes_multi_substream_encoded_header_with_each_crc() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_substream_copy_encoded_header_archive([first_crc, second_crc])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)?;
        assert_encoded_header_entry(&archive)
    }

    #[test]
    #[ignore = "requires stock 7zz 26.02"]
    fn stock_7zz_accepts_single_folder_encoded_header_baseline() -> Result<()> {
        assert!(stock_7zz_accepts(
            &single_folder_copy_encoded_header_archive()?
        )?);
        Ok(())
    }

    #[test]
    #[ignore = "requires stock 7zz 26.02"]
    fn stock_7zz_accepts_multi_substream_and_rejects_multi_folder_encoded_headers() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        assert!(stock_7zz_accepts(
            &multi_substream_copy_encoded_header_archive([first_crc, second_crc])?
        )?);
        assert!(!stock_7zz_accepts(
            &multi_folder_copy_encoded_header_archive([first_crc, second_crc])?
        )?);
        Ok(())
    }

    #[test]
    fn multi_folder_encoded_header_preflights_combined_output_limit() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_folder_copy_encoded_header_archive([first_crc, second_crc])?;
        let cancellation = CancellationToken::new();
        let limits = Limits::builder().max_total_output_bytes(12).build();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, limits, &cancellation, &mut budget),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 18,
                maximum: 12,
            })
        ));
        Ok(())
    }

    #[test]
    fn multi_folder_encoded_header_verifies_each_folder_crc() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_folder_copy_encoded_header_archive([first_crc, second_crc ^ 1])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::EncodedHeader,
                member_index: None,
            })
        ));
        Ok(())
    }

    #[test]
    fn multi_substream_encoded_header_verifies_each_substream_crc() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_substream_copy_encoded_header_archive([first_crc, second_crc ^ 1])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::EncodedHeader,
                member_index: None,
            })
        ));
        Ok(())
    }

    #[test]
    fn every_multi_substream_encoded_header_prefix_is_rejected() -> Result<()> {
        let first_crc = Crc32::checksum(ENCODED_HEADER_FIRST)?;
        let second_crc = Crc32::checksum(ENCODED_HEADER_SECOND)?;
        let bytes = multi_substream_copy_encoded_header_archive([first_crc, second_crc])?;
        let cancellation = CancellationToken::new();
        for end in 0..bytes.len() {
            let prefix = bytes
                .get(..end)
                .ok_or_else(|| crate::parse_util::format_error("test prefix is out of range"))?;
            let mut budget = WorkBudget::unlimited();
            assert!(
                Archive::open_bytes(
                    prefix.to_vec(),
                    Limits::default(),
                    &cancellation,
                    &mut budget,
                )
                .is_err(),
                "prefix {end} unexpectedly opened",
            );
        }
        Ok(())
    }

    #[test]
    fn encoded_header_without_folders_is_malformed() -> Result<()> {
        let bytes = archive_with_payload_and_next_header(&[], &[0x17, 0x00])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Format { .. })
        ));
        Ok(())
    }

    #[test]
    fn corrupted_copy_encoded_header_fails_its_decoded_crc() -> Result<()> {
        let (mut bytes, _) = nested_copy_encoded_header_archive()?;
        let packed_header_byte = bytes
            .get_mut(32)
            .ok_or_else(|| crate::parse_util::format_error("test packed header is missing"))?;
        *packed_header_byte ^= 1;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        assert!(matches!(
            Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::EncodedHeader,
                member_index: None
            })
        ));
        Ok(())
    }

    #[test]
    fn natural_solid_sink_finishes_only_crc_verified_members() -> Result<()> {
        let second_crc = Crc32::checksum(b"cd")?;
        let archive = two_member_solid_copy_archive(second_crc)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut sink = CollectSink::default();
        assert_eq!(
            archive.extract_entries_to(&mut sink, &cancellation, &mut budget)?,
            4
        );
        assert_eq!(
            sink.entries.first().map(|entry| entry.1.as_slice()),
            Some(b"ab".as_slice())
        );
        assert_eq!(
            sink.entries.get(1).map(|entry| entry.1.as_slice()),
            Some(b"cd".as_slice())
        );
        assert_eq!(sink.finished, [0, 1]);

        let corrupt = two_member_solid_copy_archive(second_crc ^ 1)?;
        let mut budget = WorkBudget::unlimited();
        let mut sink = CollectSink::default();
        assert!(matches!(
            corrupt.extract_entries_to(&mut sink, &cancellation, &mut budget),
            Err(Error::Checksum {
                scope: ChecksumScope::Member,
                member_index: Some(1)
            })
        ));
        assert_eq!(sink.finished, [0]);
        Ok(())
    }
}
