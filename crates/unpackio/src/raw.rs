//! Borrowed 7z next-header syntax records.

use crate::{
    Error, LimitKind, Limits, Result,
    bounded::BoundedReader,
    parse_util::{ParseControl, check_limit, format_error, try_reserve, u64_to_usize},
};

pub(crate) const ID_END: u8 = 0x00;
pub(crate) const ID_HEADER: u8 = 0x01;
pub(crate) const ID_ARCHIVE_PROPERTIES: u8 = 0x02;
pub(crate) const ID_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
pub(crate) const ID_MAIN_STREAMS_INFO: u8 = 0x04;
pub(crate) const ID_FILES_INFO: u8 = 0x05;
const ID_PACK_INFO: u8 = 0x06;
const ID_UNPACK_INFO: u8 = 0x07;
const ID_SUBSTREAMS_INFO: u8 = 0x08;
const ID_SIZE: u8 = 0x09;
const ID_CRC: u8 = 0x0a;
const ID_FOLDER: u8 = 0x0b;
const ID_CODERS_UNPACK_SIZE: u8 = 0x0c;
const ID_NUM_UNPACK_STREAM: u8 = 0x0d;
pub(crate) const ID_EMPTY_STREAM: u8 = 0x0e;
pub(crate) const ID_EMPTY_FILE: u8 = 0x0f;
pub(crate) const ID_ANTI: u8 = 0x10;
pub(crate) const ID_NAME: u8 = 0x11;
pub(crate) const ID_CTIME: u8 = 0x12;
pub(crate) const ID_ATIME: u8 = 0x13;
pub(crate) const ID_MTIME: u8 = 0x14;
pub(crate) const ID_WIN_ATTRIBUTES: u8 = 0x15;
pub(crate) const ID_ENCODED_HEADER: u8 = 0x17;
pub(crate) const ID_START_POS: u8 = 0x18;
pub(crate) const ID_DUMMY: u8 = 0x19;

#[allow(clippy::large_enum_variant)]
pub(crate) enum RawNextHeader<'data> {
    Header(RawHeader<'data>),
    Encoded(RawStreamsInfo<'data>),
    ExternalFolders(RawExternalFolderHeader<'data>),
}

pub(crate) struct RawExternalFolderHeader<'data> {
    pub(crate) additional_streams: RawStreamsInfo<'data>,
    pub(crate) main_pack: Option<RawPackInfo>,
    pub(crate) data_index: u64,
    pub(crate) header_bytes: &'data [u8],
}

pub(crate) struct RawHeader<'data> {
    pub(crate) archive_properties: Vec<RawProperty<'data>>,
    pub(crate) additional_streams: Option<RawStreamsInfo<'data>>,
    pub(crate) main_streams: Option<RawStreamsInfo<'data>>,
    pub(crate) files: Option<RawFilesInfo<'data>>,
}

pub(crate) struct RawProperty<'data> {
    pub(crate) id: u8,
    pub(crate) data: &'data [u8],
}

pub(crate) struct RawFilesInfo<'data> {
    pub(crate) count: u64,
    pub(crate) properties: Vec<RawProperty<'data>>,
}

pub(crate) struct RawStreamsInfo<'data> {
    pub(crate) pack: Option<RawPackInfo>,
    pub(crate) unpack: Option<RawUnpackInfo<'data>>,
    pub(crate) substreams: Option<RawSubstreamsInfo>,
}

pub(crate) struct RawPackInfo {
    pub(crate) position: u64,
    pub(crate) streams: u64,
    pub(crate) sizes: Option<Vec<u64>>,
    pub(crate) crcs: Option<Vec<Option<u32>>>,
}

pub(crate) struct RawUnpackInfo<'data> {
    pub(crate) folders: Vec<RawFolder<'data>>,
    pub(crate) crcs: Option<Vec<Option<u32>>>,
}

pub(crate) struct RawSubstreamsInfo {
    pub(crate) counts: Vec<u64>,
    pub(crate) explicit_sizes: Option<Vec<u64>>,
    pub(crate) crcs: Option<Vec<Option<u32>>>,
}

pub(crate) struct RawFolder<'data> {
    pub(crate) coders: Vec<RawCoder<'data>>,
    pub(crate) input_streams: u64,
    pub(crate) output_streams: u64,
    pub(crate) bind_pairs: Vec<RawBindPair>,
    pub(crate) packed_streams: u64,
    pub(crate) packed_indices: Option<Vec<u64>>,
    pub(crate) unpack_sizes: Vec<u64>,
}

pub(crate) struct RawCoder<'data> {
    pub(crate) method_id: &'data [u8],
    pub(crate) input_streams: u64,
    pub(crate) output_streams: u64,
    pub(crate) properties: &'data [u8],
}

pub(crate) struct RawBindPair {
    pub(crate) input: u64,
    pub(crate) output: u64,
}

#[derive(Clone, Copy)]
struct ExternalFolderData<'data> {
    data_index: u64,
    bytes: &'data [u8],
}

enum ParsedUnpackInfo<'data> {
    Complete(RawUnpackInfo<'data>),
    External { data_index: u64 },
}

enum ParsedStreamsInfo<'data> {
    Complete(RawStreamsInfo<'data>),
    External {
        pack: Option<RawPackInfo>,
        data_index: u64,
    },
}

#[derive(Default)]
pub(crate) struct ParseState {
    total_folders: u64,
    total_coders: u64,
    total_streams: u64,
    total_packed_streams: u64,
    total_substreams: u64,
    total_properties: u64,
}

impl ParseState {
    fn add_limited(
        value: &mut u64,
        additional: u64,
        maximum: u64,
        limit: LimitKind,
        overflow_detail: &'static str,
    ) -> Result<()> {
        let total = value
            .checked_add(additional)
            .ok_or_else(|| format_error(overflow_detail))?;
        check_limit(total, maximum, limit)?;
        *value = total;
        Ok(())
    }

    fn add_folders(&mut self, count: u64, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_folders,
            count,
            limits.max_folders(),
            LimitKind::Folders,
            "total folder count overflows",
        )
    }

    fn add_coders(&mut self, count: u64, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_coders,
            count,
            limits.max_total_coders(),
            LimitKind::TotalCoders,
            "total coder count overflows",
        )
    }

    fn add_streams(&mut self, count: u64, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_streams,
            count,
            limits.max_total_streams(),
            LimitKind::TotalStreams,
            "total stream count overflows",
        )
    }

    fn add_packed_streams(&mut self, count: u64, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_packed_streams,
            count,
            limits.max_total_streams(),
            LimitKind::TotalStreams,
            "total packed-stream count overflows",
        )
    }

    fn add_substreams(&mut self, count: u64, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_substreams,
            count,
            limits.max_substreams(),
            LimitKind::Substreams,
            "total substream count overflows",
        )
    }

    fn add_property(&mut self, limits: Limits) -> Result<()> {
        Self::add_limited(
            &mut self.total_properties,
            1,
            limits.max_header_properties(),
            LimitKind::HeaderProperties,
            "header property count overflows",
        )
    }
}

fn read_u8(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u8> {
    control.checkpoint(1)?;
    reader.read_u8()
}

fn read_u32_le(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u32> {
    control.checkpoint(4)?;
    reader.read_u32_le()
}

fn read_uint(reader: &mut BoundedReader<'_>, control: &mut ParseControl<'_>) -> Result<u64> {
    control.checkpoint(9)?;
    reader.read_7z_uint()
}

fn read_bytes<'data>(
    reader: &mut BoundedReader<'data>,
    length: u64,
    control: &mut ParseControl<'_>,
) -> Result<&'data [u8]> {
    let bytes = reader.read_bytes(length)?;
    control.consume_bytes(bytes)?;
    Ok(bytes)
}

fn count_to_usize(count: u64, detail: &'static str) -> Result<usize> {
    u64_to_usize(count, detail)
}

fn new_vec<T>(count: u64, detail: &'static str) -> Result<Vec<T>> {
    let capacity = count_to_usize(count, detail)?;
    let mut values = Vec::new();
    try_reserve(&mut values, capacity)?;
    Ok(values)
}

fn parse_bits(
    reader: &mut BoundedReader<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<bool>> {
    control.checkpoint(count)?;
    let mut values = new_vec(
        count,
        "bit-vector count is not representable on this platform",
    )?;
    let mut byte = 0_u8;
    let mut mask = 0_u8;
    for _ in 0..count {
        if mask == 0 {
            byte = read_u8(reader, control)?;
            mask = 0x80;
        }
        values.push(byte & mask != 0);
        mask >>= 1;
    }
    Ok(values)
}

#[allow(clippy::same_item_push)]
fn parse_digests(
    reader: &mut BoundedReader<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<Option<u32>>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    control.checkpoint(count)?;

    let all_defined = read_u8(reader, control)?;
    let defined = if all_defined == 0 {
        parse_bits(reader, count, control)?
    } else {
        let mut values = new_vec(
            count,
            "digest definition count is not representable on this platform",
        )?;
        for _ in 0..count {
            values.push(true);
        }
        values
    };

    let mut digests = new_vec(count, "digest count is not representable on this platform")?;
    for is_defined in defined {
        if is_defined {
            digests.push(Some(read_u32_le(reader, control)?));
        } else {
            digests.push(None);
        }
    }
    Ok(digests)
}

fn parse_sizes(
    reader: &mut BoundedReader<'_>,
    count: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u64>> {
    control.checkpoint(count)?;
    let mut sizes = new_vec(count, "size count is not representable on this platform")?;
    for _ in 0..count {
        sizes.push(read_uint(reader, control)?);
    }
    Ok(sizes)
}

fn parse_pack_info(
    reader: &mut BoundedReader<'_>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawPackInfo> {
    let position = read_uint(reader, control)?;
    let streams = read_uint(reader, control)?;
    if streams == 0 {
        return Err(format_error("PackInfo declares zero packed streams"));
    }
    state.add_packed_streams(streams, limits)?;

    let mut id = read_u8(reader, control)?;
    let sizes = if id == ID_SIZE {
        let values = parse_sizes(reader, streams, control)?;
        id = read_u8(reader, control)?;
        Some(values)
    } else {
        None
    };
    let crcs = if id == ID_CRC {
        let values = parse_digests(reader, streams, control)?;
        id = read_u8(reader, control)?;
        Some(values)
    } else {
        None
    };
    if id != ID_END {
        return Err(format_error("unexpected PackInfo identifier"));
    }

    Ok(RawPackInfo {
        position,
        streams,
        sizes,
        crcs,
    })
}

fn parse_coder<'data>(
    reader: &mut BoundedReader<'data>,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawCoder<'data>> {
    let flags = read_u8(reader, control)?;
    if flags & 0x80 != 0 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("alternative-coder-methods"),
        });
    }
    if flags & 0x40 != 0 {
        return Err(format_error("coder uses a reserved flag"));
    }

    let method_length = u64::from(flags & 0x0f);
    if method_length == 0 {
        return Err(format_error("coder method identifier is empty"));
    }
    let method_id = read_bytes(reader, method_length, control)?;

    let (input_streams, output_streams) = if flags & 0x10 != 0 {
        let input = read_uint(reader, control)?;
        let output = read_uint(reader, control)?;
        if input == 0 || output == 0 {
            return Err(format_error("coder stream counts must be non-zero"));
        }
        (input, output)
    } else {
        (1, 1)
    };

    let properties = if flags & 0x20 != 0 {
        let length = read_uint(reader, control)?;
        check_limit(
            length,
            limits.max_coder_property_bytes(),
            LimitKind::CoderPropertyBytes,
        )?;
        read_bytes(reader, length, control)?
    } else {
        &[]
    };

    Ok(RawCoder {
        method_id,
        input_streams,
        output_streams,
        properties,
    })
}

fn parse_folder<'data>(
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawFolder<'data>> {
    let coder_count = read_uint(reader, control)?;
    if coder_count == 0 {
        return Err(format_error("folder declares zero coders"));
    }
    check_limit(
        coder_count,
        limits.max_coders_per_folder(),
        LimitKind::CodersPerFolder,
    )?;
    state.add_coders(coder_count, limits)?;

    let mut coders = new_vec(
        coder_count,
        "coder count is not representable on this platform",
    )?;
    let mut input_streams = 0_u64;
    let mut output_streams = 0_u64;
    for _ in 0..coder_count {
        let coder = parse_coder(reader, limits, control)?;
        input_streams = input_streams
            .checked_add(coder.input_streams)
            .ok_or_else(|| format_error("folder input-stream count overflows"))?;
        output_streams = output_streams
            .checked_add(coder.output_streams)
            .ok_or_else(|| format_error("folder output-stream count overflows"))?;
        coders.push(coder);
    }

    let folder_streams = input_streams
        .checked_add(output_streams)
        .ok_or_else(|| format_error("folder stream-port count overflows"))?;
    check_limit(
        folder_streams,
        limits.max_streams_per_folder(),
        LimitKind::StreamsPerFolder,
    )?;
    state.add_streams(folder_streams, limits)?;
    if input_streams < output_streams {
        return Err(format_error(
            "folder has fewer input streams than output streams",
        ));
    }

    let bind_count = output_streams
        .checked_sub(1)
        .ok_or_else(|| format_error("folder bind-pair count underflows"))?;
    let mut bind_pairs = new_vec(
        bind_count,
        "bind-pair count is not representable on this platform",
    )?;
    for _ in 0..bind_count {
        bind_pairs.push(RawBindPair {
            input: read_uint(reader, control)?,
            output: read_uint(reader, control)?,
        });
    }

    let packed_streams = input_streams
        .checked_sub(bind_count)
        .ok_or_else(|| format_error("folder packed-stream count underflows"))?;
    if packed_streams == 0 {
        return Err(format_error("folder has no packed input stream"));
    }
    let packed_indices = if packed_streams == 1 {
        None
    } else {
        let mut values = new_vec(
            packed_streams,
            "packed-input count is not representable on this platform",
        )?;
        for _ in 0..packed_streams {
            values.push(read_uint(reader, control)?);
        }
        Some(values)
    };

    Ok(RawFolder {
        coders,
        input_streams,
        output_streams,
        bind_pairs,
        packed_streams,
        packed_indices,
        unpack_sizes: Vec::new(),
    })
}

fn parse_folders<'data>(
    reader: &mut BoundedReader<'data>,
    folder_count: u64,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<RawFolder<'data>>> {
    let mut folders = new_vec(
        folder_count,
        "folder count is not representable on this platform",
    )?;
    for _ in 0..folder_count {
        folders.push(parse_folder(reader, state, limits, control)?);
    }
    Ok(folders)
}

fn parse_unpack_info<'data>(
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
    external_folders: Option<ExternalFolderData<'data>>,
) -> Result<ParsedUnpackInfo<'data>> {
    if read_u8(reader, control)? != ID_FOLDER {
        return Err(format_error("UnpackInfo is missing Folder"));
    }
    let folder_count = read_uint(reader, control)?;
    if folder_count == 0 {
        return Err(format_error("UnpackInfo declares zero folders"));
    }
    state.add_folders(folder_count, limits)?;
    control.checkpoint(folder_count)?;

    let external = read_u8(reader, control)?;
    let mut folders = if external == 0 {
        parse_folders(reader, folder_count, state, limits, control)?
    } else {
        let data_index = read_uint(reader, control)?;
        let Some(source) = external_folders else {
            return Ok(ParsedUnpackInfo::External { data_index });
        };
        if source.data_index != data_index {
            return Err(format_error(
                "external folder data index changed during header resolution",
            ));
        }
        let mut external_reader = BoundedReader::new(source.bytes);
        let folders = parse_folders(&mut external_reader, folder_count, state, limits, control)?;
        external_reader.finish("external folder stream was not consumed exactly")?;
        folders
    };

    if read_u8(reader, control)? != ID_CODERS_UNPACK_SIZE {
        return Err(format_error("UnpackInfo is missing CodersUnpackSize"));
    }
    for folder in &mut folders {
        folder.unpack_sizes = parse_sizes(reader, folder.output_streams, control)?;
    }

    let mut id = read_u8(reader, control)?;
    let crcs = if id == ID_CRC {
        let values = parse_digests(reader, folder_count, control)?;
        id = read_u8(reader, control)?;
        Some(values)
    } else {
        None
    };
    if id != ID_END {
        return Err(format_error("unexpected UnpackInfo identifier"));
    }

    Ok(ParsedUnpackInfo::Complete(RawUnpackInfo { folders, crcs }))
}

#[allow(clippy::same_item_push)]
fn parse_substreams_info(
    reader: &mut BoundedReader<'_>,
    unpack: &RawUnpackInfo<'_>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawSubstreamsInfo> {
    let folder_count = u64::try_from(unpack.folders.len())
        .map_err(|_| format_error("folder count is not representable as u64"))?;
    let mut id = read_u8(reader, control)?;
    let mut counts = new_vec(
        folder_count,
        "substream folder count is not representable on this platform",
    )?;
    if id == ID_NUM_UNPACK_STREAM {
        for _ in 0..folder_count {
            counts.push(read_uint(reader, control)?);
        }
        id = read_u8(reader, control)?;
    } else {
        for _ in 0..folder_count {
            counts.push(1);
        }
    }

    let mut total_substreams = 0_u64;
    let mut explicit_size_count = 0_u64;
    for count in &counts {
        total_substreams = total_substreams
            .checked_add(*count)
            .ok_or_else(|| format_error("substream count overflows"))?;
        let additional_sizes = if *count == 0 {
            0
        } else {
            count
                .checked_sub(1)
                .ok_or_else(|| format_error("explicit substream-size count underflows"))?
        };
        explicit_size_count = explicit_size_count
            .checked_add(additional_sizes)
            .ok_or_else(|| format_error("explicit substream-size count overflows"))?;
    }
    state.add_substreams(total_substreams, limits)?;

    let explicit_sizes = if id == ID_SIZE {
        let values = parse_sizes(reader, explicit_size_count, control)?;
        id = read_u8(reader, control)?;
        Some(values)
    } else {
        None
    };

    let folder_crcs = unpack.crcs.as_deref();
    let mut digest_count = 0_u64;
    for (folder_index, count) in counts.iter().enumerate() {
        let inherited = folder_crcs
            .and_then(|crcs| crcs.get(folder_index))
            .and_then(|crc| *crc);
        if *count != 1 || inherited.is_none() {
            digest_count = digest_count
                .checked_add(*count)
                .ok_or_else(|| format_error("substream digest count overflows"))?;
        }
    }

    let crcs = if id == ID_CRC {
        let values = parse_digests(reader, digest_count, control)?;
        id = read_u8(reader, control)?;
        Some(values)
    } else {
        None
    };
    if id != ID_END {
        return Err(format_error("unexpected SubStreamsInfo identifier"));
    }

    Ok(RawSubstreamsInfo {
        counts,
        explicit_sizes,
        crcs,
    })
}

fn parse_streams_info<'data>(
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
    external_folders: Option<ExternalFolderData<'data>>,
) -> Result<ParsedStreamsInfo<'data>> {
    let mut id = read_u8(reader, control)?;
    let pack = if id == ID_PACK_INFO {
        let value = parse_pack_info(reader, state, limits, control)?;
        id = read_u8(reader, control)?;
        Some(value)
    } else {
        None
    };
    let unpack = if id == ID_UNPACK_INFO {
        let value = match parse_unpack_info(reader, state, limits, control, external_folders)? {
            ParsedUnpackInfo::Complete(value) => value,
            ParsedUnpackInfo::External { data_index } => {
                return Ok(ParsedStreamsInfo::External { pack, data_index });
            }
        };
        id = read_u8(reader, control)?;
        Some(value)
    } else {
        None
    };
    let substreams = if id == ID_SUBSTREAMS_INFO {
        let Some(unpack_info) = unpack.as_ref() else {
            return Err(format_error("SubStreamsInfo has no UnpackInfo"));
        };
        let value = parse_substreams_info(reader, unpack_info, state, limits, control)?;
        id = read_u8(reader, control)?;
        Some(value)
    } else {
        if let Some(unpack_info) = unpack.as_ref() {
            state.add_substreams(
                u64::try_from(unpack_info.folders.len()).map_err(|_| {
                    format_error("default substream count is not representable as u64")
                })?,
                limits,
            )?;
        }
        None
    };
    if id != ID_END {
        return Err(format_error("unexpected StreamsInfo identifier"));
    }
    Ok(ParsedStreamsInfo::Complete(RawStreamsInfo {
        pack,
        unpack,
        substreams,
    }))
}

fn parse_property_list<'data>(
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<RawProperty<'data>>> {
    let mut properties = Vec::new();
    loop {
        let id = read_u8(reader, control)?;
        if id == ID_END {
            return Ok(properties);
        }
        state.add_property(limits)?;
        let length = read_uint(reader, control)?;
        check_limit(length, limits.max_header_bytes(), LimitKind::HeaderBytes)?;
        let data = read_bytes(reader, length, control)?;
        properties.try_reserve_exact(1).map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "header property allocation failed",
            ))
        })?;
        properties.push(RawProperty { id, data });
    }
}

fn parse_files_info<'data>(
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawFilesInfo<'data>> {
    let count = read_uint(reader, control)?;
    check_limit(count, limits.max_files(), LimitKind::Files)?;
    let properties = parse_property_list(reader, state, limits, control)?;
    Ok(RawFilesInfo { count, properties })
}

fn parse_header_body<'data>(
    header_bytes: &'data [u8],
    reader: &mut BoundedReader<'data>,
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
    external_folders: Option<ExternalFolderData<'data>>,
) -> Result<RawNextHeader<'data>> {
    let mut id = read_u8(reader, control)?;
    let archive_properties = if id == ID_ARCHIVE_PROPERTIES {
        let properties = parse_property_list(reader, state, limits, control)?;
        id = read_u8(reader, control)?;
        properties
    } else {
        Vec::new()
    };
    let additional_streams = if id == ID_ADDITIONAL_STREAMS_INFO {
        let streams = match parse_streams_info(reader, state, limits, control, None)? {
            ParsedStreamsInfo::Complete(streams) => streams,
            ParsedStreamsInfo::External { .. } => {
                return Err(format_error(
                    "AdditionalStreamsInfo cannot source its own folder definitions",
                ));
            }
        };
        id = read_u8(reader, control)?;
        Some(streams)
    } else {
        None
    };
    let main_streams = if id == ID_MAIN_STREAMS_INFO {
        let streams = match parse_streams_info(reader, state, limits, control, external_folders)? {
            ParsedStreamsInfo::Complete(streams) => streams,
            ParsedStreamsInfo::External { pack, data_index } => {
                let additional_streams = additional_streams.ok_or_else(|| {
                    format_error("external folder definitions require AdditionalStreamsInfo")
                })?;
                return Ok(RawNextHeader::ExternalFolders(RawExternalFolderHeader {
                    additional_streams,
                    main_pack: pack,
                    data_index,
                    header_bytes,
                }));
            }
        };
        id = read_u8(reader, control)?;
        Some(streams)
    } else {
        None
    };
    let files = if id == ID_FILES_INFO {
        let files = parse_files_info(reader, state, limits, control)?;
        id = read_u8(reader, control)?;
        Some(files)
    } else {
        None
    };
    if id != ID_END {
        return Err(format_error("unexpected Header identifier"));
    }
    Ok(RawNextHeader::Header(RawHeader {
        archive_properties,
        additional_streams,
        main_streams,
        files,
    }))
}

fn parse_next_header_inner<'data>(
    bytes: &'data [u8],
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
    external_folders: Option<ExternalFolderData<'data>>,
) -> Result<RawNextHeader<'data>> {
    check_limit(1, limits.max_recursion_depth(), LimitKind::RecursionDepth)?;
    let mut reader = BoundedReader::new(bytes);
    let kind = read_u8(&mut reader, control)?;
    let header = match kind {
        ID_HEADER => {
            match parse_header_body(bytes, &mut reader, state, limits, control, external_folders)? {
                pending @ RawNextHeader::ExternalFolders(_) => return Ok(pending),
                complete => complete,
            }
        }
        ID_ENCODED_HEADER => match parse_streams_info(&mut reader, state, limits, control, None)? {
            ParsedStreamsInfo::Complete(streams) => RawNextHeader::Encoded(streams),
            ParsedStreamsInfo::External { .. } => {
                return Err(format_error(
                    "encoded-header folder definitions have no additional stream source",
                ));
            }
        },
        _ => return Err(format_error("unexpected next-header identifier")),
    };
    reader.finish("next-header body was not consumed exactly")?;
    Ok(header)
}

pub(crate) fn parse_next_header<'data>(
    bytes: &'data [u8],
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawNextHeader<'data>> {
    parse_next_header_inner(bytes, state, limits, control, None)
}

pub(crate) fn parse_next_header_with_external_folders<'data>(
    bytes: &'data [u8],
    data_index: u64,
    folder_bytes: &'data [u8],
    state: &mut ParseState,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<RawNextHeader<'data>> {
    parse_next_header_inner(
        bytes,
        state,
        limits,
        control,
        Some(ExternalFolderData {
            data_index,
            bytes: folder_bytes,
        }),
    )
}
