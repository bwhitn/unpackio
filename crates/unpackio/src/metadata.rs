//! Decoding and exact application of external file-metadata streams.

use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    bounded::BoundedReader,
    checksum::Crc32,
    decode::METHOD_AES,
    execute::{DecodedFolder, decode_folder},
    model::{ArchiveHeader, ExternalProperty, FileEntry, Folder, StreamsInfo},
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, format_error, try_reserve, u64_to_usize,
        usize_to_u64,
    },
    password::Password,
    raw::{ID_ATIME, ID_CTIME, ID_MTIME, ID_NAME, ID_START_POS, ID_WIN_ATTRIBUTES},
};

fn folder_is_encrypted(folder: &Folder) -> bool {
    folder
        .coders()
        .iter()
        .any(|coder| coder.method_id() == METHOD_AES)
}

fn map_encrypted_error(error: Error, encrypted: bool) -> Error {
    if encrypted
        && matches!(
            error,
            Error::Format { .. } | Error::Checksum { .. } | Error::WrongPasswordOrCorrupt
        )
    {
        Error::WrongPasswordOrCorrupt
    } else {
        error
    }
}

fn checksum(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    let mut checksum = Crc32::new();
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "additional-stream checksum chunk is not representable as u64",
        )?)?;
        checksum.update(chunk)?;
    }
    Ok(checksum.finalize())
}

pub(crate) struct DecodedAdditionalStream {
    bytes: Box<[u8]>,
    encrypted: bool,
}

impl DecodedAdditionalStream {
    pub(crate) const fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn encrypted(&self) -> bool {
        self.encrypted
    }
}

pub(crate) struct DecodedAdditionalStreams {
    streams: Vec<DecodedAdditionalStream>,
    total_bytes: u64,
}

impl DecodedAdditionalStreams {
    pub(crate) fn get(&self, data_index: u64) -> Result<&DecodedAdditionalStream> {
        self.streams
            .get(u64_to_usize(
                data_index,
                "additional-stream index is not representable on this platform",
            )?)
            .ok_or_else(|| format_error("additional-stream index is out of range"))
    }

    pub(crate) const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

fn verify_decoded_additional_folder(
    folder: &Folder,
    decoded: &DecodedFolder,
    encrypted: bool,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if decoded.crc_mismatch {
        if encrypted {
            return Err(Error::WrongPasswordOrCorrupt);
        }
        return Err(Error::Checksum {
            scope: ChecksumScope::Folder,
            member_index: None,
        });
    }
    let folder_size = usize_to_u64(
        decoded.bytes.len(),
        "additional-stream folder output is not representable as u64",
    )?;
    let mut offset = 0_u64;
    for (substream_index, substream) in folder.substreams().iter().enumerate() {
        control.checkpoint(1)?;
        let end = match substream.size() {
            Some(size) => offset
                .checked_add(size)
                .ok_or_else(|| format_error("additional-stream range overflows"))?,
            None if substream_index
                .checked_add(1)
                .is_some_and(|index| index == folder.substreams().len()) =>
            {
                folder_size
            }
            None => {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("unknown-nonfinal-additional-stream-size"),
                });
            }
        };
        if end > folder_size {
            return Err(format_error(
                "additional-stream range exceeds its folder output",
            ));
        }
        let bytes = decoded
            .bytes
            .get(
                u64_to_usize(
                    offset,
                    "additional-stream start is not representable on this platform",
                )?
                    ..u64_to_usize(
                        end,
                        "additional-stream end is not representable on this platform",
                    )?,
            )
            .ok_or_else(|| format_error("additional-stream range is out of bounds"))?;
        if let Some(expected) = substream.crc() {
            if checksum(bytes, control)? != expected {
                if encrypted {
                    return Err(Error::WrongPasswordOrCorrupt);
                }
                return Err(Error::Checksum {
                    scope: ChecksumScope::AdditionalStream,
                    member_index: None,
                });
            }
        }
        offset = end;
    }
    if offset != folder_size {
        return Err(format_error(
            "additional streams do not consume their folder output exactly",
        ));
    }
    Ok(())
}

fn process_additional_streams<Consume>(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    password: Option<&Password>,
    limits: Limits,
    maximum_output: u64,
    control: &mut ParseControl<'_>,
    mut consume: Consume,
) -> Result<u64>
where
    Consume: FnMut(DecodedFolder, bool) -> Result<()>,
{
    let mut total_output = 0_u64;
    for (folder_index, folder) in streams.folders().iter().enumerate() {
        control.checkpoint(1)?;
        let remaining_header = limits
            .max_header_bytes()
            .checked_sub(total_output)
            .ok_or_else(|| format_error("external metadata output accounting underflows"))?;
        let remaining_total = maximum_output
            .checked_sub(total_output)
            .ok_or_else(|| format_error("external output accounting underflows"))?;
        let maximum_folder = remaining_header.min(remaining_total);
        let encrypted = folder_is_encrypted(folder);
        let decoded = decode_folder(
            archive_bytes,
            streams,
            usize_to_u64(
                folder_index,
                "additional-stream folder index is not representable as u64",
            )?,
            password,
            limits,
            maximum_folder,
            control,
        )
        .map_err(|error| map_encrypted_error(error, encrypted))?;
        let folder_size = usize_to_u64(
            decoded.bytes.len(),
            "additional-stream folder output is not representable as u64",
        )?;
        total_output = total_output
            .checked_add(folder_size)
            .ok_or_else(|| format_error("external metadata output accounting overflows"))?;
        check_limit(
            total_output,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        check_limit(total_output, maximum_output, LimitKind::TotalOutputBytes)?;
        verify_decoded_additional_folder(folder, &decoded, encrypted, control)?;
        consume(decoded, encrypted)?;
    }
    Ok(total_output)
}

pub(crate) fn decode_additional_streams(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    password: Option<&Password>,
    limits: Limits,
    maximum_output: u64,
    control: &mut ParseControl<'_>,
) -> Result<DecodedAdditionalStreams> {
    let stream_count = streams.folders().len();
    let mut outputs = Vec::new();
    try_reserve(&mut outputs, stream_count)?;
    let total_output = process_additional_streams(
        archive_bytes,
        streams,
        password,
        limits,
        maximum_output,
        control,
        |decoded, encrypted| {
            outputs.push(DecodedAdditionalStream {
                bytes: decoded.bytes.into_boxed_slice(),
                encrypted,
            });
            Ok(())
        },
    )?;
    if outputs.len() != stream_count {
        return Err(format_error(
            "decoded additional-stream count does not match its declaration",
        ));
    }
    Ok(DecodedAdditionalStreams {
        streams: outputs,
        total_bytes: total_output,
    })
}

pub(crate) fn verify_additional_streams(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    password: Option<&Password>,
    limits: Limits,
    maximum_output: u64,
    control: &mut ParseControl<'_>,
) -> Result<u64> {
    process_additional_streams(
        archive_bytes,
        streams,
        password,
        limits,
        maximum_output,
        control,
        |_decoded, _encrypted| Ok(()),
    )
}

fn read_bytes<'data>(
    reader: &mut BoundedReader<'data>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<&'data [u8]> {
    control.checkpoint(0)?;
    let bytes = reader.read_bytes(count)?;
    control.checkpoint(count)?;
    Ok(bytes)
}

fn read_u32(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u32> {
    let bytes: [u8; 4] = read_bytes(reader, 4, control)?
        .try_into()
        .map_err(|_| format_error("external u32 value is truncated"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u64> {
    let bytes: [u8; 8] = read_bytes(reader, 8, control)?
        .try_into()
        .map_err(|_| format_error("external u64 value is truncated"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn check_definition_count(entries: &[FileEntry], property: &ExternalProperty) -> Result<()> {
    if entries.len() == property.defined_entries().len() {
        Ok(())
    } else {
        Err(format_error(
            "external-property definition count does not match the file count",
        ))
    }
}

fn apply_external_names(
    entries: &mut [FileEntry],
    property: &ExternalProperty,
    data: &[u8],
    total_name_bytes: &mut u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    check_definition_count(entries, property)?;
    let mut reader = BoundedReader::new(data);
    for (entry, defined) in entries.iter_mut().zip(property.defined_entries()) {
        control.checkpoint(1)?;
        if !*defined {
            continue;
        }
        let mut name = Vec::new();
        let mut name_bytes = 0_u64;
        loop {
            let pair: [u8; 2] = read_bytes(&mut reader, 2, control)?
                .try_into()
                .map_err(|_| format_error("external UTF-16 name is truncated"))?;
            let unit = u16::from_le_bytes(pair);
            if unit == 0 {
                break;
            }
            name_bytes = name_bytes
                .checked_add(2)
                .ok_or_else(|| format_error("external name byte count overflows"))?;
            check_limit(
                name_bytes,
                limits.max_name_bytes_per_entry(),
                LimitKind::NameBytesPerEntry,
            )?;
            try_reserve(&mut name, 1)?;
            name.push(unit);
        }
        *total_name_bytes = total_name_bytes
            .checked_add(name_bytes)
            .ok_or_else(|| format_error("total external name bytes overflow"))?;
        check_limit(
            *total_name_bytes,
            limits.max_total_name_bytes(),
            LimitKind::TotalNameBytes,
        )?;
        entry.set_raw_name(name.into_boxed_slice());
    }
    reader.finish("external Name stream was not consumed exactly")
}

fn apply_external_u64(
    entries: &mut [FileEntry],
    property: &ExternalProperty,
    data: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    check_definition_count(entries, property)?;
    let mut reader = BoundedReader::new(data);
    for (entry, defined) in entries.iter_mut().zip(property.defined_entries()) {
        control.checkpoint(1)?;
        if !*defined {
            continue;
        }
        let value = read_u64(&mut reader, control)?;
        match property.property_id() {
            ID_CTIME => entry.set_creation_time(value),
            ID_ATIME => entry.set_access_time(value),
            ID_MTIME => entry.set_modification_time(value),
            ID_START_POS => entry.set_start_position(value),
            _ => return Err(format_error("external u64 property identifier is invalid")),
        }
    }
    reader.finish("external u64 property stream was not consumed exactly")
}

fn apply_external_attributes(
    entries: &mut [FileEntry],
    property: &ExternalProperty,
    data: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    check_definition_count(entries, property)?;
    let mut reader = BoundedReader::new(data);
    for (entry, defined) in entries.iter_mut().zip(property.defined_entries()) {
        control.checkpoint(1)?;
        if *defined {
            entry.set_windows_attributes(read_u32(&mut reader, control)?);
        }
    }
    reader.finish("external attribute stream was not consumed exactly")
}

fn initial_name_bytes(entries: &[FileEntry]) -> Result<u64> {
    let mut total = 0_u64;
    for entry in entries {
        let units = entry.raw_name().map_or(0, <[u16]>::len);
        let bytes = usize_to_u64(units, "name length is not representable as u64")?
            .checked_mul(2)
            .ok_or_else(|| format_error("name byte count overflows"))?;
        total = total
            .checked_add(bytes)
            .ok_or_else(|| format_error("total name byte count overflows"))?;
    }
    Ok(total)
}

pub(crate) fn apply_external_properties(
    header: &mut ArchiveHeader,
    decoded: &DecodedAdditionalStreams,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let Some(files) = header.files_mut() else {
        return Ok(());
    };
    if files.external_properties().is_empty() {
        return Ok(());
    }

    let files = header
        .files_mut()
        .ok_or_else(|| format_error("file metadata disappeared during external decoding"))?;
    let mut total_name_bytes = initial_name_bytes(files.entries())?;
    let (entries, properties) = files.entries_and_external_mut();
    for property in properties {
        control.checkpoint(1)?;
        let stream = decoded.get(property.data_index())?;
        let data = stream.bytes();
        let result = match property.property_id() {
            ID_NAME => apply_external_names(
                entries,
                property,
                data,
                &mut total_name_bytes,
                limits,
                control,
            ),
            ID_CTIME | ID_ATIME | ID_MTIME | ID_START_POS => {
                apply_external_u64(entries, property, data, control)
            }
            ID_WIN_ATTRIBUTES => apply_external_attributes(entries, property, data, control),
            _ => Err(format_error(
                "external-property descriptor has an unknown identifier",
            )),
        };
        result.map_err(|error| map_encrypted_error(error, stream.encrypted()))?;
    }
    Ok(())
}

/// Resolves every known external file property and returns decoded byte usage.
pub(crate) fn resolve_external_properties(
    header: &mut ArchiveHeader,
    archive_bytes: &[u8],
    password: Option<&Password>,
    limits: Limits,
    maximum_output: u64,
    control: &mut ParseControl<'_>,
) -> Result<u64> {
    let Some(files) = header.files() else {
        return Ok(0);
    };
    if files.external_properties().is_empty() {
        return Ok(0);
    }
    let streams = header
        .additional_streams()
        .ok_or_else(|| format_error("external file properties have no additional streams"))?;
    let decoded = decode_additional_streams(
        archive_bytes,
        streams,
        password,
        limits,
        maximum_output,
        control,
    )?;
    apply_external_properties(header, &decoded, limits, control)?;
    Ok(decoded.total_bytes())
}

#[cfg(test)]
mod tests {
    use super::resolve_external_properties;
    use crate::{
        CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
        checksum::Crc32,
        model::{
            ArchiveHeader, Coder, ExternalProperty, FileEntry, FilesInfo, Folder, PackStream,
            StreamsInfo, Substream,
        },
        parse_util::ParseControl,
        raw::{ID_ATIME, ID_CTIME, ID_MTIME, ID_NAME, ID_START_POS, ID_WIN_ATTRIBUTES},
    };

    fn external_property_header(
        bytes: &[u8],
        property_id: u8,
        folder_crc: Option<u32>,
        substream_crc: Option<u32>,
    ) -> Result<ArchiveHeader> {
        let length = u64::try_from(bytes.len()).map_err(|_| crate::Error::Format {
            detail: String::from("test stream length is not representable as u64"),
        })?;
        let coder = Coder::new(Box::from([0_u8]), 0, 1, 0, 1, Box::default(), None);
        let folder = Folder::new(
            Box::from([coder]),
            Box::default(),
            Box::from([0_u64]),
            Box::from([Some(length)]),
            0,
            Box::from([0_u64]),
            folder_crc,
            Box::from([Substream::new(Some(length), substream_crc)]),
            0,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            Box::from([PackStream::new(0, Some(length), None)]),
            Box::from([folder]),
            1,
        );
        let entry = FileEntry::new(None, false, true, false, None, None, None, None, None, None);
        let files = FilesInfo::new(
            Box::from([entry]),
            Box::from([ExternalProperty::new(property_id, 0, Box::from([true]))]),
            Box::default(),
        );
        Ok(ArchiveHeader::new(
            Box::default(),
            Some(streams),
            None,
            Some(files),
        ))
    }

    #[test]
    fn resolves_external_utf16_name_through_copy_stream() -> Result<()> {
        let bytes = [b'a', 0, 0, 0];
        let crc = Crc32::checksum(&bytes)?;
        let mut header = external_property_header(&bytes, ID_NAME, Some(crc), Some(crc))?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert_eq!(
            resolve_external_properties(
                &mut header,
                &bytes,
                None,
                Limits::default(),
                1024,
                &mut control,
            )?,
            4
        );
        assert_eq!(
            header
                .files()
                .and_then(|files| files.entries().first())
                .and_then(FileEntry::raw_name),
            Some(&[u16::from(b'a')][..])
        );
        Ok(())
    }

    #[test]
    fn rejects_trailing_external_name_bytes() -> Result<()> {
        let bytes = [b'a', 0, 0, 0, 7, 0];
        let mut header = external_property_header(&bytes, ID_NAME, None, None)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let error = resolve_external_properties(
            &mut header,
            &bytes,
            None,
            Limits::default(),
            1024,
            &mut control,
        );
        assert!(matches!(error, Err(crate::Error::Format { .. })));
        Ok(())
    }

    #[test]
    fn resolves_external_times_start_position_and_attributes() -> Result<()> {
        let value = 0x0123_4567_89ab_cdef_u64;
        for property_id in [ID_CTIME, ID_ATIME, ID_MTIME, ID_START_POS] {
            let bytes = value.to_le_bytes();
            let mut header = external_property_header(&bytes, property_id, None, None)?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut control = ParseControl::new(&cancellation, &mut budget);
            resolve_external_properties(
                &mut header,
                &bytes,
                None,
                Limits::default(),
                1024,
                &mut control,
            )?;
            let entry = header
                .files()
                .and_then(|files| files.entries().first())
                .ok_or_else(|| crate::parse_util::format_error("external u64 entry is missing"))?;
            let actual = match property_id {
                ID_CTIME => entry.creation_time(),
                ID_ATIME => entry.access_time(),
                ID_MTIME => entry.modification_time(),
                ID_START_POS => entry.start_position(),
                _ => None,
            };
            assert_eq!(actual, Some(value));
        }

        let attributes = 0xa1ed_8020_u32;
        let bytes = attributes.to_le_bytes();
        let mut header = external_property_header(&bytes, ID_WIN_ATTRIBUTES, None, None)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        resolve_external_properties(
            &mut header,
            &bytes,
            None,
            Limits::default(),
            1024,
            &mut control,
        )?;
        let entry = header
            .files()
            .and_then(|files| files.entries().first())
            .ok_or_else(|| {
                crate::parse_util::format_error("external attribute entry is missing")
            })?;
        assert_eq!(entry.windows_attributes(), Some(attributes));
        assert!(entry.is_symlink());
        Ok(())
    }

    #[test]
    fn external_folder_and_substream_crcs_remain_distinct() -> Result<()> {
        let bytes = [b'a', 0, 0, 0];
        let crc = Crc32::checksum(&bytes)?;
        let cancellation = CancellationToken::new();

        let mut header = external_property_header(&bytes, ID_NAME, Some(crc ^ 1), Some(crc))?;
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            resolve_external_properties(
                &mut header,
                &bytes,
                None,
                Limits::default(),
                1024,
                &mut control,
            ),
            Err(Error::Checksum {
                scope: ChecksumScope::Folder,
                member_index: None,
            })
        ));

        let mut header = external_property_header(&bytes, ID_NAME, Some(crc), Some(crc ^ 1))?;
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            resolve_external_properties(
                &mut header,
                &bytes,
                None,
                Limits::default(),
                1024,
                &mut control,
            ),
            Err(Error::Checksum {
                scope: ChecksumScope::AdditionalStream,
                member_index: None,
            })
        ));
        Ok(())
    }

    #[test]
    fn external_name_limit_precedes_name_allocation_growth() -> Result<()> {
        let bytes = [b'a', 0, b'b', 0, 0, 0];
        let mut header = external_property_header(&bytes, ID_NAME, None, None)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = resolve_external_properties(
            &mut header,
            &bytes,
            None,
            Limits::builder().max_name_bytes_per_entry(2).build(),
            1024,
            &mut control,
        );
        assert!(matches!(
            result,
            Err(Error::LimitExceeded {
                limit: LimitKind::NameBytesPerEntry,
                requested: 4,
                maximum: 2,
            })
        ));
        Ok(())
    }
}
