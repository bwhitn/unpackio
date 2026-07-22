//! Conversion from borrowed syntax records to the validated archive model.

use crate::{
    Error, LimitKind, Limits, Result,
    bounded::BoundedReader,
    coder_properties::parse_ppmd_properties,
    graph::validate_folder_graph,
    model::{
        ArchiveHeader, BindPair, Coder, ExternalProperty, FileEntry, FileStream, FilesInfo, Folder,
        HeaderEnvelope, PackStream, ParsedNextHeader, PendingExternalFolderHeader, StoredProperty,
        StreamsInfo, Substream,
    },
    parse_util::{
        ParseControl, check_limit, checked_range, copy_bytes, format_error, try_reserve,
        u64_to_usize, usize_to_u64,
    },
    raw::{
        ID_ANTI, ID_ATIME, ID_CTIME, ID_DUMMY, ID_EMPTY_FILE, ID_EMPTY_STREAM, ID_MTIME, ID_NAME,
        ID_START_POS, ID_WIN_ATTRIBUTES, RawFilesInfo, RawFolder, RawHeader, RawNextHeader,
        RawPackInfo, RawProperty, RawStreamsInfo,
    },
};

const FIXED_HEADER_SIZE: u64 = 32;
const UNKNOWN_SIZE: u64 = u64::MAX;
const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const METHOD_LZMA2: &[u8] = &[0x21];
const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const METHOD_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
const METHOD_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
const DEFLATE64_DICTIONARY_BYTES: u64 = 64 * 1024;

struct FolderDraft {
    coders: Box<[Coder]>,
    bind_pairs: Box<[BindPair]>,
    packed_input_indices: Box<[u64]>,
    unpack_sizes: Box<[Option<u64>]>,
    root_output_index: u64,
    root_size: Option<u64>,
    topological_coder_order: Box<[u64]>,
    crc: Option<u32>,
    dictionary_bytes: u64,
    first_pack_stream: u64,
}

enum PropertyValues<T> {
    Inline(Vec<Option<T>>),
    External { data_index: u64, defined: Vec<bool> },
}

fn push_repeated<T: Clone>(count: u64, value: T, detail: &'static str) -> Result<Vec<T>> {
    let count = u64_to_usize(count, detail)?;
    let mut values = Vec::new();
    try_reserve(&mut values, count)?;
    for _ in 0..count {
        values.push(value.clone());
    }
    Ok(values)
}

fn value_at<T: Copy>(
    values: Option<&[T]>,
    index: usize,
    detail: &'static str,
) -> Result<Option<T>> {
    match values {
        Some(items) => items
            .get(index)
            .copied()
            .map(Some)
            .ok_or_else(|| format_error(detail)),
        None => Ok(None),
    }
}

fn optional_size(value: u64) -> Option<u64> {
    (value != UNKNOWN_SIZE).then_some(value)
}

fn copy_properties(
    properties: &[RawProperty<'_>],
    control: &mut ParseControl<'_>,
) -> Result<Box<[StoredProperty]>> {
    control.checkpoint(usize_to_u64(
        properties.len(),
        "property count is not representable as u64",
    )?)?;
    let mut copied = Vec::new();
    try_reserve(&mut copied, properties.len())?;
    for property in properties {
        copied.push(StoredProperty::new(
            property.id,
            copy_bytes(property.data, control)?,
        ));
    }
    Ok(copied.into_boxed_slice())
}

fn read_u8(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u8> {
    control.checkpoint(1)?;
    reader.read_u8()
}

fn read_u32(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u32> {
    control.checkpoint(4)?;
    reader.read_u32_le()
}

fn read_u64(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u64> {
    control.checkpoint(8)?;
    reader.read_u64_le()
}

fn read_uint(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u64> {
    control.checkpoint(9)?;
    reader.read_7z_uint()
}

fn parse_bits(
    reader: &mut BoundedReader<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<bool>> {
    control.checkpoint(count)?;
    let mut values = push_repeated(
        count,
        false,
        "bit-vector count is not representable on this platform",
    )?;
    let mut byte = 0_u8;
    let mut mask = 0_u8;
    for value in &mut values {
        if mask == 0 {
            byte = read_u8(reader, control)?;
            mask = 0x80;
        }
        *value = byte & mask != 0;
        mask >>= 1;
    }
    Ok(values)
}

fn parse_optional_bits(
    reader: &mut BoundedReader<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<bool>> {
    if read_u8(reader, control)? == 0 {
        parse_bits(reader, count, control)
    } else {
        push_repeated(
            count,
            true,
            "definition count is not representable on this platform",
        )
    }
}

fn parse_defined_values<T, ReadValue>(
    data: &[u8],
    count: u64,
    control: &mut ParseControl<'_>,
    mut read_value: ReadValue,
) -> Result<PropertyValues<T>>
where
    ReadValue: FnMut(&mut BoundedReader<'_>, &mut ParseControl<'_>) -> Result<T>,
{
    let mut reader = BoundedReader::new(data);
    let defined = parse_optional_bits(&mut reader, count, control)?;
    let external = read_u8(&mut reader, control)?;
    if external != 0 {
        let data_index = read_uint(&mut reader, control)?;
        reader.finish("external property was not consumed exactly")?;
        return Ok(PropertyValues::External {
            data_index,
            defined,
        });
    }

    let mut values = Vec::new();
    try_reserve(&mut values, defined.len())?;
    for is_defined in defined {
        control.checkpoint(1)?;
        values.push(if is_defined {
            Some(read_value(&mut reader, control)?)
        } else {
            None
        });
    }
    reader.finish("inline property was not consumed exactly")?;
    Ok(PropertyValues::Inline(values))
}

fn parse_plain_bits(
    property: &RawProperty<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<bool>> {
    let mut reader = BoundedReader::new(property.data);
    let bits = parse_bits(&mut reader, count, control)?;
    reader.finish("bit-vector property was not consumed exactly")?;
    Ok(bits)
}

fn validate_data_index(data_index: u64, additional_count: u64) -> Result<()> {
    if data_index < additional_count {
        Ok(())
    } else {
        Err(format_error(
            "external property data index is outside additional streams",
        ))
    }
}

fn little_endian_u32(bytes: &[u8], detail: &'static str) -> Result<u32> {
    let bytes = <[u8; 4]>::try_from(bytes).map_err(|_| format_error(detail))?;
    Ok(u32::from_le_bytes(bytes))
}

fn validate_coder_properties(
    method_id: &[u8],
    properties: &[u8],
    limits: Limits,
) -> Result<Option<u64>> {
    let dictionary =
        if method_id == METHOD_LZMA {
            let bytes = <[u8; 5]>::try_from(properties)
                .map_err(|_| format_error("LZMA properties must contain exactly five bytes"))?;
            let parameter =
                u64::from(bytes.first().copied().ok_or_else(|| {
                    format_error("LZMA properties are missing the parameter byte")
                })?);
            let lc = parameter % 9;
            let remainder = parameter / 9;
            let lp = remainder % 5;
            let pb = remainder / 5;
            if pb > 4 || lc.checked_add(lp).is_none_or(|sum| sum > 4) {
                return Err(format_error("invalid LZMA lc/lp/pb properties"));
            }
            Some(u64::from(little_endian_u32(
                bytes
                    .get(1..5)
                    .ok_or_else(|| format_error("LZMA dictionary property is truncated"))?,
                "LZMA dictionary property is truncated",
            )?))
        } else if method_id == METHOD_LZMA2 {
            let bytes = <[u8; 1]>::try_from(properties)
                .map_err(|_| format_error("LZMA2 properties must contain exactly one byte"))?;
            let property =
                u32::from(bytes.first().copied().ok_or_else(|| {
                    format_error("LZMA2 properties are missing the dictionary byte")
                })?);
            if property > 40 {
                return Err(format_error("invalid LZMA2 dictionary property"));
            }
            let shift = property
                .checked_div(2)
                .and_then(|value| value.checked_add(11))
                .ok_or_else(|| format_error("LZMA2 dictionary shift overflows"))?;
            let base = u64::from(2_u32 | (property & 1));
            Some(
                base.checked_shl(shift)
                    .ok_or_else(|| format_error("LZMA2 dictionary size overflows"))?,
            )
        } else if method_id == METHOD_PPMD {
            Some(u64::from(parse_ppmd_properties(properties)?.memory_size()))
        } else if method_id == METHOD_DEFLATE64 {
            if !properties.is_empty() {
                return Err(format_error("Deflate64 properties must be empty"));
            }
            Some(DEFLATE64_DICTIONARY_BYTES)
        } else {
            None
        };

    if method_id == METHOD_AES {
        let mut reader = BoundedReader::new(properties);
        let first = read_u8_without_control(&mut reader)?;
        let second = read_u8_without_control(&mut reader)?;
        let salt_size = u64::from((first >> 7) & 1)
            .checked_add(u64::from(second >> 4))
            .ok_or_else(|| format_error("AES salt size overflows"))?;
        let iv_size = u64::from((first >> 6) & 1)
            .checked_add(u64::from(second & 0x0f))
            .ok_or_else(|| format_error("AES IV size overflows"))?;
        let variable_size = salt_size
            .checked_add(iv_size)
            .ok_or_else(|| format_error("AES property size overflows"))?;
        let _ = reader.read_bytes(variable_size)?;
        reader.finish("AES properties were not consumed exactly")?;
        let kdf_power = first & 0x3f;
        if kdf_power != 0x3f && kdf_power > limits.max_kdf_power() {
            return Err(Error::LimitExceeded {
                limit: LimitKind::KdfPower,
                requested: u64::from(kdf_power),
                maximum: u64::from(limits.max_kdf_power()),
            });
        }
    }

    if let Some(bytes) = dictionary {
        check_limit(
            bytes,
            limits.max_dictionary_bytes(),
            LimitKind::DictionaryBytes,
        )?;
    }
    Ok(dictionary)
}

fn read_u8_without_control(reader: &mut BoundedReader<'_>) -> Result<u8> {
    reader.read_u8()
}

#[allow(clippy::too_many_lines)]
fn validate_folder(
    raw: &RawFolder<'_>,
    folder_crc: Option<u32>,
    first_pack_stream: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<FolderDraft> {
    control.checkpoint(usize_to_u64(
        raw.coders.len(),
        "coder count is not representable as u64",
    )?)?;
    let output_count = u64_to_usize(
        raw.output_streams,
        "folder output count is not representable on this platform",
    )?;
    let mut coders = Vec::new();
    try_reserve(&mut coders, raw.coders.len())?;
    let mut input_start = 0_u64;
    let mut output_start = 0_u64;
    let mut dictionary_bytes = 0_u64;
    for raw_coder in &raw.coders {
        control.checkpoint(1)?;
        let dictionary =
            validate_coder_properties(raw_coder.method_id, raw_coder.properties, limits)?;
        if let Some(bytes) = dictionary {
            dictionary_bytes = dictionary_bytes
                .checked_add(bytes)
                .ok_or_else(|| format_error("folder dictionary accounting overflows"))?;
            check_limit(
                dictionary_bytes,
                limits.max_dictionary_bytes(),
                LimitKind::DictionaryBytes,
            )?;
        }
        coders.push(Coder::new(
            copy_bytes(raw_coder.method_id, control)?,
            input_start,
            raw_coder.input_streams,
            output_start,
            raw_coder.output_streams,
            copy_bytes(raw_coder.properties, control)?,
            dictionary,
        ));
        input_start = input_start
            .checked_add(raw_coder.input_streams)
            .ok_or_else(|| format_error("coder input range overflows"))?;
        output_start = output_start
            .checked_add(raw_coder.output_streams)
            .ok_or_else(|| format_error("coder output range overflows"))?;
    }
    if input_start != raw.input_streams || output_start != raw.output_streams {
        return Err(format_error("folder stream-port totals are inconsistent"));
    }

    let graph = validate_folder_graph(raw, control)?;
    if raw.unpack_sizes.len() != output_count {
        return Err(format_error("folder unpack-size count is inconsistent"));
    }
    let mut unpack_sizes = Vec::new();
    try_reserve(&mut unpack_sizes, raw.unpack_sizes.len())?;
    for size in &raw.unpack_sizes {
        unpack_sizes.push(optional_size(*size));
    }
    let root_index = u64_to_usize(
        graph.root_output_index,
        "root output index is not representable on this platform",
    )?;
    let root_size = unpack_sizes
        .get(root_index)
        .copied()
        .ok_or_else(|| format_error("root output size is missing"))?;

    Ok(FolderDraft {
        coders: coders.into_boxed_slice(),
        bind_pairs: graph.bind_pairs,
        packed_input_indices: graph.packed_input_indices,
        unpack_sizes: unpack_sizes.into_boxed_slice(),
        root_output_index: graph.root_output_index,
        root_size,
        topological_coder_order: graph.topological_coder_order,
        crc: folder_crc,
        dictionary_bytes,
        first_pack_stream,
    })
}

fn build_substreams(
    draft: &FolderDraft,
    count: u64,
    explicit_sizes: Option<&[u64]>,
    size_cursor: &mut usize,
    explicit_crcs: Option<&[Option<u32>]>,
    crc_cursor: &mut usize,
    control: &mut ParseControl<'_>,
) -> Result<Box<[Substream]>> {
    control.checkpoint(count)?;
    let capacity = u64_to_usize(
        count,
        "folder substream count is not representable on this platform",
    )?;
    let mut sizes = Vec::new();
    try_reserve(&mut sizes, capacity)?;
    if count == 1 {
        sizes.push(draft.root_size);
    } else if count > 1 {
        let mut total = 0_u64;
        let mut all_explicit_sizes_known = true;
        for _ in 1..count {
            control.checkpoint(1)?;
            let size = match explicit_sizes {
                Some(values) => {
                    let value = values.get(*size_cursor).copied().ok_or_else(|| {
                        format_error("explicit substream-size vector is too short")
                    })?;
                    *size_cursor = size_cursor
                        .checked_add(1)
                        .ok_or_else(|| format_error("substream-size index overflows"))?;
                    let size = optional_size(value);
                    if let Some(known_size) = size {
                        total = total
                            .checked_add(known_size)
                            .ok_or_else(|| format_error("substream-size sum overflows"))?;
                    } else {
                        all_explicit_sizes_known = false;
                    }
                    size
                }
                None => None,
            };
            sizes.push(size);
        }
        let final_size = match (draft.root_size, explicit_sizes, all_explicit_sizes_known) {
            (Some(folder_size), Some(_), true) => Some(
                folder_size
                    .checked_sub(total)
                    .ok_or_else(|| format_error("substream sizes exceed folder size"))?,
            ),
            _ => None,
        };
        sizes.push(final_size);
    }

    let inherit_folder_crc = count == 1 && draft.crc.is_some();
    let mut streams = Vec::new();
    try_reserve(&mut streams, capacity)?;
    for size in sizes {
        control.checkpoint(1)?;
        let crc = if inherit_folder_crc {
            draft.crc
        } else {
            let value = match explicit_crcs {
                Some(values) => values
                    .get(*crc_cursor)
                    .copied()
                    .ok_or_else(|| format_error("substream CRC vector is too short"))?,
                None => None,
            };
            if explicit_crcs.is_some() {
                *crc_cursor = crc_cursor
                    .checked_add(1)
                    .ok_or_else(|| format_error("substream CRC index overflows"))?;
            }
            value
        };
        streams.push(Substream::new(size, crc));
    }
    Ok(streams.into_boxed_slice())
}

fn validate_pack_ranges(
    pack: Option<&RawPackInfo>,
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    ranges: &mut Vec<(u64, u64)>,
    control: &mut ParseControl<'_>,
) -> Result<(u64, Box<[PackStream]>)> {
    let Some(pack) = pack else {
        return Ok((0, Box::default()));
    };
    let sizes = pack
        .sizes
        .as_deref()
        .ok_or_else(|| format_error("PackInfo is missing packed-stream sizes"))?;
    let stream_count = u64_to_usize(
        pack.streams,
        "packed-stream count is not representable on this platform",
    )?;
    control.checkpoint(pack.streams)?;
    if sizes.len() != stream_count {
        return Err(format_error("packed-stream size count is inconsistent"));
    }
    if pack
        .crcs
        .as_ref()
        .is_some_and(|crcs| crcs.len() != stream_count)
    {
        return Err(format_error("packed-stream CRC count is inconsistent"));
    }
    let fixed_end = envelope
        .signature_offset()
        .checked_add(FIXED_HEADER_SIZE)
        .ok_or_else(|| format_error("signature-header end overflows"))?;
    let mut offset = fixed_end
        .checked_add(pack.position)
        .ok_or_else(|| format_error("packed-data position overflows"))?;
    let section_start = offset;
    let mut streams = Vec::new();
    try_reserve(&mut streams, stream_count)?;
    for (index, raw_size) in sizes.iter().enumerate() {
        control.checkpoint(1)?;
        if *raw_size == UNKNOWN_SIZE {
            return Err(Error::UnsupportedFeature {
                feature: String::from("unknown-packed-stream-size"),
            });
        }
        let end = offset
            .checked_add(*raw_size)
            .ok_or_else(|| format_error("packed-stream range overflows"))?;
        if end > envelope.next_header_offset() {
            return Err(format_error(
                "packed stream overlaps the stored next header",
            ));
        }
        let _ = checked_range(
            archive_bytes,
            offset,
            *raw_size,
            "packed-stream range overflows",
            "packed-stream range is outside the supplied archive",
        )?;
        let crc = value_at(
            pack.crcs.as_deref(),
            index,
            "packed-stream CRC count is inconsistent",
        )?
        .flatten();
        streams.push(PackStream::new(offset, Some(*raw_size), crc));
        offset = end;
    }
    if offset > section_start {
        try_reserve(ranges, 1)?;
        ranges.push((section_start, offset));
    }
    Ok((pack.position, streams.into_boxed_slice()))
}

#[allow(clippy::too_many_lines)]
fn validate_streams(
    raw: &RawStreamsInfo<'_>,
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
    ranges: &mut Vec<(u64, u64)>,
) -> Result<StreamsInfo> {
    if raw.pack.is_some() != raw.unpack.is_some() {
        return Err(format_error("PackInfo and UnpackInfo must appear together"));
    }
    if raw.pack.is_none() {
        if raw.substreams.is_some() {
            return Err(format_error("SubStreamsInfo has no streams"));
        }
        return Ok(StreamsInfo::new(0, Box::default(), Box::default(), 0));
    }
    let (pack_position, pack_streams) =
        validate_pack_ranges(raw.pack.as_ref(), envelope, archive_bytes, ranges, control)?;
    let unpack = raw
        .unpack
        .as_ref()
        .ok_or_else(|| format_error("StreamsInfo is missing UnpackInfo"))?;
    if unpack
        .crcs
        .as_ref()
        .is_some_and(|crcs| crcs.len() != unpack.folders.len())
    {
        return Err(format_error("folder CRC count is inconsistent"));
    }
    let pack_count = usize_to_u64(
        pack_streams.len(),
        "packed-stream count is not representable as u64",
    )?;
    let mut assigned_pack_streams = 0_u64;
    let mut drafts = Vec::new();
    control.checkpoint(usize_to_u64(
        unpack.folders.len(),
        "folder count is not representable as u64",
    )?)?;
    try_reserve(&mut drafts, unpack.folders.len())?;
    for (folder_index, folder) in unpack.folders.iter().enumerate() {
        let crc = value_at(
            unpack.crcs.as_deref(),
            folder_index,
            "folder CRC count is inconsistent",
        )?
        .flatten();
        drafts.push(validate_folder(
            folder,
            crc,
            assigned_pack_streams,
            limits,
            control,
        )?);
        assigned_pack_streams = assigned_pack_streams
            .checked_add(folder.packed_streams)
            .ok_or_else(|| format_error("assigned packed-stream count overflows"))?;
    }
    if assigned_pack_streams != pack_count {
        return Err(format_error(
            "folder packed-stream total does not match PackInfo",
        ));
    }

    let counts = match raw.substreams.as_ref() {
        Some(substreams) => substreams.counts.as_slice(),
        None => &[],
    };
    if !counts.is_empty() && counts.len() != drafts.len() {
        return Err(format_error(
            "substream folder-count vector is inconsistent",
        ));
    }
    let explicit_sizes = raw
        .substreams
        .as_ref()
        .and_then(|substreams| substreams.explicit_sizes.as_deref());
    let explicit_crcs = raw
        .substreams
        .as_ref()
        .and_then(|substreams| substreams.crcs.as_deref());
    let mut size_cursor = 0_usize;
    let mut crc_cursor = 0_usize;
    let mut total_substreams = 0_u64;
    let mut folders = Vec::new();
    try_reserve(&mut folders, drafts.len())?;
    for (index, draft) in drafts.into_iter().enumerate() {
        let count = if counts.is_empty() {
            1
        } else {
            counts
                .get(index)
                .copied()
                .ok_or_else(|| format_error("substream count vector is too short"))?
        };
        total_substreams = total_substreams
            .checked_add(count)
            .ok_or_else(|| format_error("total substream count overflows"))?;
        check_limit(
            total_substreams,
            limits.max_substreams(),
            LimitKind::Substreams,
        )?;
        let substreams = build_substreams(
            &draft,
            count,
            explicit_sizes,
            &mut size_cursor,
            explicit_crcs,
            &mut crc_cursor,
            control,
        )?;
        folders.push(Folder::new(
            draft.coders,
            draft.bind_pairs,
            draft.packed_input_indices,
            draft.unpack_sizes,
            draft.root_output_index,
            draft.topological_coder_order,
            draft.crc,
            substreams,
            draft.dictionary_bytes,
            draft.first_pack_stream,
        ));
    }
    if explicit_sizes.is_some_and(|sizes| size_cursor != sizes.len()) {
        return Err(format_error("substream-size vector has unused values"));
    }
    if explicit_crcs.is_some_and(|crcs| crc_cursor != crcs.len()) {
        return Err(format_error("substream CRC vector has unused values"));
    }
    Ok(StreamsInfo::new(
        pack_position,
        pack_streams,
        folders.into_boxed_slice(),
        total_substreams,
    ))
}

fn check_non_overlapping_ranges(ranges: &mut [(u64, u64)]) -> Result<()> {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut previous_end = None;
    for (start, end) in ranges {
        if previous_end.is_some_and(|value| *start < value) {
            return Err(format_error("packed-stream ranges overlap"));
        }
        previous_end = Some(*end);
    }
    Ok(())
}

fn collect_stream_mappings(
    streams: Option<&StreamsInfo>,
    control: &mut ParseControl<'_>,
) -> Result<Vec<FileStream>> {
    let total = streams.map_or(0, StreamsInfo::substream_count);
    control.checkpoint(total)?;
    let capacity = u64_to_usize(
        total,
        "member-stream count is not representable on this platform",
    )?;
    let mut mappings = Vec::new();
    try_reserve(&mut mappings, capacity)?;
    if let Some(info) = streams {
        for (folder_index, folder) in info.folders().iter().enumerate() {
            let folder_index =
                usize_to_u64(folder_index, "folder index is not representable as u64")?;
            for (substream_index, stream) in folder.substreams().iter().enumerate() {
                control.checkpoint(1)?;
                mappings.push(FileStream::new(
                    folder_index,
                    usize_to_u64(
                        substream_index,
                        "substream index is not representable as u64",
                    )?,
                    stream.size(),
                    stream.crc(),
                ));
            }
        }
    }
    if mappings.len() != capacity {
        return Err(format_error("member-stream count is inconsistent"));
    }
    Ok(mappings)
}

fn known_property_slot<'data>(
    slot: &mut Option<&'data RawProperty<'data>>,
    property: &'data RawProperty<'data>,
) -> Result<()> {
    if slot.replace(property).is_some() {
        Err(format_error("FilesInfo property is duplicated"))
    } else {
        Ok(())
    }
}

fn parse_names(
    data: &[u8],
    count: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<PropertyValues<Box<[u16]>>> {
    let mut scan = BoundedReader::new(data);
    if read_u8(&mut scan, control)? != 0 {
        let data_index = read_uint(&mut scan, control)?;
        scan.finish("external Name property was not consumed exactly")?;
        return Ok(PropertyValues::External {
            data_index,
            defined: push_repeated(
                count,
                true,
                "file count is not representable on this platform",
            )?,
        });
    }
    let mut names_seen = 0_u64;
    let mut current_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    while names_seen < count {
        let pair = scan.read_bytes(2)?;
        control.checkpoint(2)?;
        let pair = <[u8; 2]>::try_from(pair)
            .map_err(|_| format_error("UTF-16 name code unit is truncated"))?;
        if u16::from_le_bytes(pair) == 0 {
            check_limit(
                current_bytes,
                limits.max_name_bytes_per_entry(),
                LimitKind::NameBytesPerEntry,
            )?;
            total_bytes = total_bytes
                .checked_add(current_bytes)
                .ok_or_else(|| format_error("total name bytes overflow"))?;
            check_limit(
                total_bytes,
                limits.max_total_name_bytes(),
                LimitKind::TotalNameBytes,
            )?;
            names_seen = names_seen
                .checked_add(1)
                .ok_or_else(|| format_error("name count overflows"))?;
            current_bytes = 0;
        } else {
            current_bytes = current_bytes
                .checked_add(2)
                .ok_or_else(|| format_error("name byte count overflows"))?;
            check_limit(
                current_bytes,
                limits.max_name_bytes_per_entry(),
                LimitKind::NameBytesPerEntry,
            )?;
        }
    }
    scan.finish("Name property was not consumed exactly")?;

    let mut reader = BoundedReader::new(data);
    if read_u8(&mut reader, control)? != 0 {
        return Err(format_error("Name property changed during validation"));
    }
    let capacity = u64_to_usize(count, "name count is not representable on this platform")?;
    let mut names = Vec::new();
    try_reserve(&mut names, capacity)?;
    for _ in 0..count {
        let mut name = Vec::new();
        loop {
            let pair = reader.read_bytes(2)?;
            control.checkpoint(2)?;
            let pair = <[u8; 2]>::try_from(pair)
                .map_err(|_| format_error("UTF-16 name code unit is truncated"))?;
            let code_unit = u16::from_le_bytes(pair);
            if code_unit == 0 {
                break;
            }
            try_reserve(&mut name, 1)?;
            name.push(code_unit);
        }
        names.push(Some(name.into_boxed_slice()));
    }
    reader.finish("Name property was not consumed exactly")?;
    Ok(PropertyValues::Inline(names))
}

fn apply_external<T>(
    property_id: u8,
    values: PropertyValues<T>,
    additional_count: u64,
    external: &mut Vec<ExternalProperty>,
) -> Result<Option<Vec<Option<T>>>> {
    match values {
        PropertyValues::Inline(values) => Ok(Some(values)),
        PropertyValues::External {
            data_index,
            defined,
        } => {
            validate_data_index(data_index, additional_count)?;
            try_reserve(external, 1)?;
            external.push(ExternalProperty::new(
                property_id,
                data_index,
                defined.into_boxed_slice(),
            ));
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_files(
    raw: &RawFilesInfo<'_>,
    main_streams: Option<&StreamsInfo>,
    additional_streams: Option<&StreamsInfo>,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<FilesInfo> {
    control.checkpoint(raw.count)?;
    let mut empty_stream = None;
    let mut empty_file = None;
    let mut anti = None;
    let mut name = None;
    let mut creation = None;
    let mut access = None;
    let mut modification = None;
    let mut attributes = None;
    let mut start_position = None;
    let mut unknown = Vec::new();
    for property in &raw.properties {
        match property.id {
            ID_EMPTY_STREAM => known_property_slot(&mut empty_stream, property)?,
            ID_EMPTY_FILE => known_property_slot(&mut empty_file, property)?,
            ID_ANTI => known_property_slot(&mut anti, property)?,
            ID_NAME => known_property_slot(&mut name, property)?,
            ID_CTIME => known_property_slot(&mut creation, property)?,
            ID_ATIME => known_property_slot(&mut access, property)?,
            ID_MTIME => known_property_slot(&mut modification, property)?,
            ID_WIN_ATTRIBUTES => known_property_slot(&mut attributes, property)?,
            ID_START_POS => known_property_slot(&mut start_position, property)?,
            ID_DUMMY => {
                if property.data.iter().any(|byte| *byte != 0) {
                    return Err(format_error("Dummy property contains a non-zero byte"));
                }
            }
            _ => {
                try_reserve(&mut unknown, 1)?;
                unknown.push(StoredProperty::new(
                    property.id,
                    copy_bytes(property.data, control)?,
                ));
            }
        }
    }

    let empty_streams = match empty_stream {
        Some(property) => parse_plain_bits(property, raw.count, control)?,
        None => push_repeated(
            raw.count,
            false,
            "file count is not representable on this platform",
        )?,
    };
    let empty_count = usize_to_u64(
        empty_streams.iter().filter(|value| **value).count(),
        "empty-stream count is not representable as u64",
    )?;
    let empty_file_bits = match empty_file {
        Some(property) => parse_plain_bits(property, empty_count, control)?,
        None => push_repeated(
            empty_count,
            false,
            "empty-file count is not representable on this platform",
        )?,
    };
    let anti_bits = match anti {
        Some(property) => parse_plain_bits(property, empty_count, control)?,
        None => push_repeated(
            empty_count,
            false,
            "anti-item count is not representable on this platform",
        )?,
    };

    let additional_count = match additional_streams {
        Some(streams) => usize_to_u64(
            streams.folders().len(),
            "additional-stream folder count is not representable as u64",
        )?,
        None => 0,
    };
    let mut external = Vec::new();
    let names = match name {
        Some(property) => apply_external(
            ID_NAME,
            parse_names(property.data, raw.count, limits, control)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };
    let creation_times = match creation {
        Some(property) => apply_external(
            ID_CTIME,
            parse_defined_values(property.data, raw.count, control, read_u64)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };
    let access_times = match access {
        Some(property) => apply_external(
            ID_ATIME,
            parse_defined_values(property.data, raw.count, control, read_u64)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };
    let modification_times = match modification {
        Some(property) => apply_external(
            ID_MTIME,
            parse_defined_values(property.data, raw.count, control, read_u64)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };
    let attribute_values = match attributes {
        Some(property) => apply_external(
            ID_WIN_ATTRIBUTES,
            parse_defined_values(property.data, raw.count, control, read_u32)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };
    let start_positions = match start_position {
        Some(property) => apply_external(
            ID_START_POS,
            parse_defined_values(property.data, raw.count, control, read_u64)?,
            additional_count,
            &mut external,
        )?,
        None => None,
    };

    let mappings = collect_stream_mappings(main_streams, control)?;
    let expected_mappings = empty_streams.iter().filter(|empty| !**empty).count();
    if mappings.len() != expected_mappings {
        return Err(format_error(
            "file stream count does not match main-stream substreams",
        ));
    }
    let file_capacity = u64_to_usize(
        raw.count,
        "file count is not representable on this platform",
    )?;
    let mut files = Vec::new();
    try_reserve(&mut files, file_capacity)?;
    let mut empty_cursor = 0_usize;
    let mut stream_cursor = 0_usize;
    for file_index in 0..file_capacity {
        control.checkpoint(1)?;
        let is_empty_stream = empty_streams
            .get(file_index)
            .copied()
            .ok_or_else(|| format_error("EmptyStream vector is too short"))?;
        let (is_empty_file, is_anti) = if is_empty_stream {
            let empty_value = empty_file_bits
                .get(empty_cursor)
                .copied()
                .ok_or_else(|| format_error("EmptyFile vector is too short"))?;
            let anti_value = anti_bits
                .get(empty_cursor)
                .copied()
                .ok_or_else(|| format_error("Anti vector is too short"))?;
            empty_cursor = empty_cursor
                .checked_add(1)
                .ok_or_else(|| format_error("empty-file index overflows"))?;
            (empty_value, anti_value)
        } else {
            (false, false)
        };
        let stream = if is_empty_stream {
            None
        } else {
            let value = mappings
                .get(stream_cursor)
                .copied()
                .ok_or_else(|| format_error("member-stream mapping is too short"))?;
            stream_cursor = stream_cursor
                .checked_add(1)
                .ok_or_else(|| format_error("member-stream index overflows"))?;
            Some(value)
        };
        let raw_name = match names.as_deref() {
            Some(values) => values
                .get(file_index)
                .cloned()
                .ok_or_else(|| format_error("Name vector is too short"))?,
            None => None,
        };
        files.push(FileEntry::new(
            raw_name,
            !is_empty_stream,
            is_empty_file,
            is_anti,
            value_at(
                creation_times.as_deref(),
                file_index,
                "creation-time vector is too short",
            )?
            .flatten(),
            value_at(
                access_times.as_deref(),
                file_index,
                "access-time vector is too short",
            )?
            .flatten(),
            value_at(
                modification_times.as_deref(),
                file_index,
                "modification-time vector is too short",
            )?
            .flatten(),
            value_at(
                attribute_values.as_deref(),
                file_index,
                "attribute vector is too short",
            )?
            .flatten(),
            value_at(
                start_positions.as_deref(),
                file_index,
                "StartPos vector is too short",
            )?
            .flatten(),
            stream,
        ));
    }
    if empty_cursor != empty_file_bits.len()
        || empty_cursor != anti_bits.len()
        || stream_cursor != mappings.len()
    {
        return Err(format_error("file property vectors have unused values"));
    }
    Ok(FilesInfo::new(
        files.into_boxed_slice(),
        external.into_boxed_slice(),
        unknown.into_boxed_slice(),
    ))
}

#[allow(clippy::too_many_lines)]
fn validate_plain_header(
    raw: RawHeader<'_>,
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ArchiveHeader> {
    let mut ranges = Vec::new();
    let additional_streams = match raw.additional_streams.as_ref() {
        Some(streams) => Some(validate_streams(
            streams,
            envelope,
            archive_bytes,
            limits,
            control,
            &mut ranges,
        )?),
        None => None,
    };
    let main_streams = match raw.main_streams.as_ref() {
        Some(streams) => Some(validate_streams(
            streams,
            envelope,
            archive_bytes,
            limits,
            control,
            &mut ranges,
        )?),
        None => None,
    };
    check_non_overlapping_ranges(&mut ranges)?;
    let files = match raw.files.as_ref() {
        Some(files) => Some(validate_files(
            files,
            main_streams.as_ref(),
            additional_streams.as_ref(),
            limits,
            control,
        )?),
        None => None,
    };
    Ok(ArchiveHeader::new(
        copy_properties(&raw.archive_properties, control)?,
        additional_streams,
        main_streams,
        files,
    ))
}

pub(crate) fn validate_next_header(
    raw: RawNextHeader<'_>,
    envelope: HeaderEnvelope,
    archive_bytes: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<ParsedNextHeader> {
    match raw {
        RawNextHeader::Header(header) => Ok(ParsedNextHeader::Header(validate_plain_header(
            header,
            envelope,
            archive_bytes,
            limits,
            control,
        )?)),
        RawNextHeader::ExternalFolders(pending) => {
            let mut ranges = Vec::new();
            let additional_streams = validate_streams(
                &pending.additional_streams,
                envelope,
                archive_bytes,
                limits,
                control,
                &mut ranges,
            )?;
            if pending.main_pack.is_none() {
                return Err(format_error(
                    "PackInfo and external UnpackInfo must appear together",
                ));
            }
            let _ = validate_pack_ranges(
                pending.main_pack.as_ref(),
                envelope,
                archive_bytes,
                &mut ranges,
                control,
            )?;
            check_non_overlapping_ranges(&mut ranges)?;
            validate_data_index(
                pending.data_index,
                usize_to_u64(
                    additional_streams.folders().len(),
                    "additional-stream folder count is not representable as u64",
                )?,
            )?;
            Ok(ParsedNextHeader::PendingExternalFolders(
                PendingExternalFolderHeader::new(
                    additional_streams,
                    pending.data_index,
                    copy_bytes(pending.header_bytes, control)?,
                ),
            ))
        }
        RawNextHeader::Encoded(streams) => {
            let mut ranges = Vec::new();
            let streams = validate_streams(
                &streams,
                envelope,
                archive_bytes,
                limits,
                control,
                &mut ranges,
            )?;
            check_non_overlapping_ranges(&mut ranges)?;
            Ok(ParsedNextHeader::EncodedHeader(streams))
        }
    }
}
