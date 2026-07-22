#![forbid(unsafe_code)]
//! Generated Phase 2 parser and validated-model regressions.

use std::error::Error as StdError;

use unpackio::{
    CancellationToken, Error, ErrorKind, LimitKind, Limits, ParsedNextHeader, WorkBudget,
    parse_archive, validate_safe_utf16_path,
};

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";

#[derive(Clone, Copy)]
struct CoderSpec<'data> {
    method: &'data [u8],
    inputs: u64,
    outputs: u64,
    properties: Option<&'data [u8]>,
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

fn encoded_uint(value: u64) -> Result<Vec<u8>, Box<dyn StdError>> {
    for additional in 0_u32..8 {
        let value_bits = 7_u32
            .checked_mul(
                additional
                    .checked_add(1)
                    .ok_or("test integer bit count overflow")?,
            )
            .ok_or("test integer bit count overflow")?;
        let threshold = 1_u64
            .checked_shl(value_bits)
            .ok_or("test integer threshold overflow")?;
        if value >= threshold {
            continue;
        }
        let prefix = if additional == 0 {
            0
        } else {
            u8::MAX
                .checked_shl(
                    8_u32
                        .checked_sub(additional)
                        .ok_or("test prefix shift underflow")?,
                )
                .ok_or("test prefix shift overflow")?
        };
        let low_bits = 8_u32
            .checked_mul(additional)
            .ok_or("test low-bit count overflow")?;
        let high = u8::try_from(value >> low_bits)?;
        let mut encoded = Vec::new();
        encoded.push(prefix | high);
        let additional = usize::try_from(additional)?;
        encoded.extend(value.to_le_bytes().iter().take(additional));
        return Ok(encoded);
    }
    let mut encoded = Vec::from([u8::MAX]);
    encoded.extend_from_slice(&value.to_le_bytes());
    Ok(encoded)
}

fn push_uint(bytes: &mut Vec<u8>, value: u64) -> Result<(), Box<dyn StdError>> {
    bytes.extend(encoded_uint(value)?);
    Ok(())
}

fn push_property(bytes: &mut Vec<u8>, id: u8, data: &[u8]) -> Result<(), Box<dyn StdError>> {
    bytes.push(id);
    push_uint(bytes, u64::try_from(data.len())?)?;
    bytes.extend_from_slice(data);
    Ok(())
}

fn make_archive(payload: &[u8], next_header: &[u8]) -> Result<Vec<u8>, Box<dyn StdError>> {
    let next_offset = u64::try_from(payload.len())?;
    let next_size = u64::try_from(next_header.len())?;
    let next_crc = crc32(next_header);
    let mut start_fields = Vec::new();
    start_fields.extend_from_slice(&next_offset.to_le_bytes());
    start_fields.extend_from_slice(&next_size.to_le_bytes());
    start_fields.extend_from_slice(&next_crc.to_le_bytes());
    let mut archive = Vec::new();
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(next_header);
    Ok(archive)
}

#[allow(clippy::too_many_arguments)]
fn folder_streams(
    pack_position: u64,
    pack_sizes: &[u64],
    coders: &[CoderSpec<'_>],
    bind_pairs: &[(u64, u64)],
    packed_indices: &[u64],
    unpack_sizes: &[u64],
    folder_crc: Option<u32>,
    substreams: Option<&[u8]>,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut streams = Vec::new();
    streams.push(0x06);
    push_uint(&mut streams, pack_position)?;
    push_uint(&mut streams, u64::try_from(pack_sizes.len())?)?;
    streams.push(0x09);
    for size in pack_sizes {
        push_uint(&mut streams, *size)?;
    }
    streams.push(0x00);

    streams.extend_from_slice(&[0x07, 0x0b]);
    push_uint(&mut streams, 1)?;
    streams.push(0);
    push_uint(&mut streams, u64::try_from(coders.len())?)?;
    for coder in coders {
        let method_length = u8::try_from(coder.method.len())?;
        let mut flags = method_length;
        if coder.inputs != 1 || coder.outputs != 1 {
            flags |= 0x10;
        }
        if coder.properties.is_some() {
            flags |= 0x20;
        }
        streams.push(flags);
        streams.extend_from_slice(coder.method);
        if flags & 0x10 != 0 {
            push_uint(&mut streams, coder.inputs)?;
            push_uint(&mut streams, coder.outputs)?;
        }
        if let Some(properties) = coder.properties {
            push_uint(&mut streams, u64::try_from(properties.len())?)?;
            streams.extend_from_slice(properties);
        }
    }
    for (input, output) in bind_pairs {
        push_uint(&mut streams, *input)?;
        push_uint(&mut streams, *output)?;
    }
    for index in packed_indices {
        push_uint(&mut streams, *index)?;
    }
    streams.push(0x0c);
    for size in unpack_sizes {
        push_uint(&mut streams, *size)?;
    }
    if let Some(crc) = folder_crc {
        streams.extend_from_slice(&[0x0a, 1]);
        streams.extend_from_slice(&crc.to_le_bytes());
    }
    streams.push(0x00);
    if let Some(body) = substreams {
        streams.push(0x08);
        streams.extend_from_slice(body);
    }
    streams.push(0x00);
    Ok(streams)
}

fn plain_header(streams: Option<&[u8]>, files: Option<&[u8]>) -> Vec<u8> {
    let mut header = Vec::from([0x01]);
    if let Some(streams) = streams {
        header.push(0x04);
        header.extend_from_slice(streams);
    }
    if let Some(files) = files {
        header.push(0x05);
        header.extend_from_slice(files);
    }
    header.push(0x00);
    header
}

fn files_info(count: u64, properties: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut files = Vec::new();
    push_uint(&mut files, count)?;
    for (id, data) in properties {
        push_property(&mut files, *id, data)?;
    }
    files.push(0x00);
    Ok(files)
}

fn names_property(names: &[&[u16]]) -> Vec<u8> {
    let mut data = Vec::from([0]);
    for name in names {
        for code_unit in *name {
            data.extend_from_slice(&code_unit.to_le_bytes());
        }
        data.extend_from_slice(&0_u16.to_le_bytes());
    }
    data
}

fn parse(bytes: &[u8], limits: Limits) -> unpackio::Result<unpackio::ParsedArchive> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    parse_archive(bytes, limits, &cancellation, &mut budget)
}

fn one_coder_archive(
    method: &[u8],
    properties: Option<&[u8]>,
    unpack_size: u64,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method,
            inputs: 1,
            outputs: 1,
            properties,
        }],
        &[],
        &[],
        &[unpack_size],
        None,
        None,
    )?;
    make_archive(&[], &plain_header(Some(&streams), None))
}

#[test]
fn parses_copy_stream_and_preserves_metadata() -> Result<(), Box<dyn StdError>> {
    let payload = b"abc";
    let payload_crc = crc32(payload);
    let streams = folder_streams(
        0,
        &[3],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[3],
        Some(payload_crc),
        None,
    )?;
    let name = [0x03b1_u16, 0xd800];
    let mut start_position = Vec::from([1, 0]);
    start_position.extend_from_slice(&7_u64.to_le_bytes());
    let files = files_info(
        1,
        &[(0x11, names_property(&[&name])), (0x18, start_position)],
    )?;
    let archive = make_archive(payload, &plain_header(Some(&streams), Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(files) = header.files() else {
        return Err("file model is missing".into());
    };
    let Some(file) = files.entries().first() else {
        return Err("file entry is missing".into());
    };
    assert_eq!(file.raw_name(), Some(name.as_slice()));
    assert_eq!(file.start_position(), Some(7));
    let Some(stream) = file.stream() else {
        return Err("member mapping is missing".into());
    };
    assert_eq!(stream.size(), Some(3));
    assert_eq!(stream.crc(), Some(payload_crc));
    Ok(())
}

#[test]
fn unsafe_raw_name_does_not_change_file_stream_mapping() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        None,
    )?;
    let unsafe_name: Vec<u16> = "../x".encode_utf16().collect();
    let files = files_info(1, &[(0x11, names_property(&[&unsafe_name]))])?;
    let archive = make_archive(&[], &plain_header(Some(&streams), Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(file) = header.files().and_then(|info| info.entries().first()) else {
        return Err("unsafe-name file is missing".into());
    };
    assert!(file.stream().is_some());
    let Some(raw_name) = file.raw_name() else {
        return Err("unsafe raw name is missing".into());
    };
    assert!(validate_safe_utf16_path(raw_name).is_err());
    Ok(())
}

#[test]
fn files_info_only_nonempty_file_is_a_format_error() -> Result<(), Box<dyn StdError>> {
    let files = files_info(1, &[])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn sfx_scan_continues_after_crc_correct_nested_decoy() -> Result<(), Box<dyn StdError>> {
    let malformed_files = files_info(1, &[])?;
    let decoy = make_archive(&[], &plain_header(None, Some(&malformed_files)))?;
    let real = make_archive(&[], &[0x01, 0x00])?;
    let mut sfx = Vec::from([0x90]);
    sfx.extend_from_slice(&decoy);
    let expected_offset = u64::try_from(sfx.len())?;
    sfx.extend_from_slice(&real);
    assert_eq!(
        parse(&sfx, Limits::default())?
            .envelope()
            .signature_offset(),
        expected_offset
    );
    Ok(())
}

#[test]
fn pack_info_without_unpack_info_is_a_format_error() -> Result<(), Box<dyn StdError>> {
    let streams = Vec::from([0x06, 0, 1, 0x09, 0, 0, 0]);
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn rejects_invalid_packed_stream_index_before_open() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0, 0],
        &[CoderSpec {
            method: &[0],
            inputs: 2,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[0, 2],
        &[0],
        None,
        None,
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn rejects_cyclic_folder_graph() -> Result<(), Box<dyn StdError>> {
    let coder = CoderSpec {
        method: &[0],
        inputs: 1,
        outputs: 1,
        properties: None,
    };
    let streams = folder_streams(
        0,
        &[0],
        &[coder, coder],
        &[(0, 0)],
        &[],
        &[0, 0],
        None,
        None,
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn rejects_duplicate_bind_and_packed_domains() -> Result<(), Box<dyn StdError>> {
    let coder = CoderSpec {
        method: &[0],
        inputs: 1,
        outputs: 1,
        properties: None,
    };
    for bindings in [[(1, 0), (1, 1)], [(1, 0), (2, 0)]] {
        let streams = folder_streams(
            0,
            &[0],
            &[coder, coder, coder],
            &bindings,
            &[],
            &[0, 0, 0],
            None,
            None,
        )?;
        let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
        assert_eq!(
            parse(&archive, Limits::default())
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
    }

    let streams = folder_streams(
        0,
        &[0, 0, 0],
        &[CoderSpec {
            method: &[0],
            inputs: 3,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[0, 0, 2],
        &[0],
        None,
        None,
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn validates_arbitrary_chain_graphs_and_deterministic_order() -> Result<(), Box<dyn StdError>> {
    for coder_count in 1_usize..=8 {
        let coder = CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        };
        let coders = vec![coder; coder_count];
        let mut binds = Vec::new();
        let bind_count = coder_count
            .checked_sub(1)
            .ok_or("coder chain cannot be empty")?;
        for index in 0..bind_count {
            binds.push((
                u64::try_from(index.checked_add(1).ok_or("index overflow")?)?,
                u64::try_from(index)?,
            ));
        }
        let unpack_sizes = vec![0_u64; coder_count];
        let streams = folder_streams(0, &[0], &coders, &binds, &[], &unpack_sizes, None, None)?;
        let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
        let parsed = parse(&archive, Limits::default())?;
        let ParsedNextHeader::Header(header) = parsed.next_header() else {
            return Err("plain header parsed as encoded".into());
        };
        let Some(folder) = header
            .main_streams()
            .and_then(|info| info.folders().first())
        else {
            return Err("folder model is missing".into());
        };
        let expected: Result<Vec<u64>, _> = (0..coder_count).map(u64::try_from).collect();
        assert_eq!(folder.topological_coder_order(), expected?.as_slice());
    }
    Ok(())
}

#[test]
fn validates_external_property_reference_and_definition_map() -> Result<(), Box<dyn StdError>> {
    let substreams = [0x0d, 2, 0x09, 4, 0x00];
    let additional = folder_streams(
        0,
        &[12],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[12],
        None,
        Some(&substreams),
    )?;
    let files = files_info(
        1,
        &[
            (0x0e, vec![0x80]),
            (0x11, vec![1, 0]),
            (0x12, vec![1, 1, 0]),
        ],
    )?;
    let mut header = Vec::from([0x01, 0x03]);
    header.extend_from_slice(&additional);
    header.push(0x05);
    header.extend_from_slice(&files);
    header.push(0);
    let archive = make_archive(&[0; 12], &header)?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(property) = header
        .files()
        .and_then(|info| info.external_properties().first())
    else {
        return Err("external Name property is missing".into());
    };
    assert_eq!(property.property_id(), 0x11);
    assert_eq!(property.data_index(), 0);
    assert_eq!(property.defined_entries(), &[true]);
    let Some(time_property) = header.files().and_then(|info| {
        info.external_properties()
            .iter()
            .find(|property| property.property_id() == 0x12)
    }) else {
        return Err("external creation-time property is missing".into());
    };
    assert_eq!(time_property.data_index(), 0);
    assert_eq!(time_property.defined_entries(), &[true]);
    Ok(())
}

#[test]
fn preserves_inline_file_and_archive_metadata() -> Result<(), Box<dyn StdError>> {
    let first = [u16::from(b'f')];
    let second = [u16::from(b'd')];
    let mut creation = Vec::from([0, 0x80, 0]);
    creation.extend_from_slice(&10_u64.to_le_bytes());
    let mut access = Vec::from([1, 0]);
    access.extend_from_slice(&20_u64.to_le_bytes());
    access.extend_from_slice(&21_u64.to_le_bytes());
    let mut modification = Vec::from([1, 0]);
    modification.extend_from_slice(&30_u64.to_le_bytes());
    modification.extend_from_slice(&31_u64.to_le_bytes());
    let mut attributes = Vec::from([1, 0]);
    attributes.extend_from_slice(&0x20_u32.to_le_bytes());
    attributes.extend_from_slice(&0x10_u32.to_le_bytes());
    let files = files_info(
        2,
        &[
            (0x0e, vec![0xc0]),
            (0x0f, vec![0x80]),
            (0x10, vec![0x40]),
            (0x11, names_property(&[&first, &second])),
            (0x12, creation),
            (0x13, access),
            (0x14, modification),
            (0x15, attributes),
            (0x16, vec![b'o', b'k']),
        ],
    )?;
    let mut header = Vec::from([0x01, 0x02, 0x30, 2, 7, 8, 0, 0x05]);
    header.extend_from_slice(&files);
    header.push(0);
    let archive = make_archive(&[], &header)?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(archive_property) = header.archive_properties().first() else {
        return Err("archive property is missing".into());
    };
    assert_eq!(
        (archive_property.id(), archive_property.data()),
        (0x30, &[7, 8][..])
    );
    let Some(files) = header.files() else {
        return Err("file metadata is missing".into());
    };
    let Some(file) = files.entries().first() else {
        return Err("first empty file is missing".into());
    };
    assert!(file.is_empty_file());
    assert!(!file.is_anti_item());
    assert_eq!(file.creation_time(), Some(10));
    assert_eq!(file.access_time(), Some(20));
    assert_eq!(file.modification_time(), Some(30));
    assert_eq!(file.windows_attributes(), Some(0x20));
    let Some(directory) = files.entries().get(1) else {
        return Err("anti directory is missing".into());
    };
    assert!(!directory.is_empty_file());
    assert!(directory.is_anti_item());
    assert_eq!(directory.creation_time(), None);
    assert_eq!(directory.access_time(), Some(21));
    assert_eq!(directory.modification_time(), Some(31));
    assert_eq!(directory.windows_attributes(), Some(0x10));
    let Some(comment) = files
        .unknown_properties()
        .iter()
        .find(|property| property.id() == 0x16)
    else {
        return Err("comment property is missing".into());
    };
    assert_eq!(comment.data(), b"ok");
    Ok(())
}

#[test]
fn validates_encoded_header_stream_descriptor_without_claiming_decode()
-> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        None,
    )?;
    let mut next_header = Vec::from([0x17]);
    next_header.extend_from_slice(&streams);
    let archive = make_archive(&[], &next_header)?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::EncodedHeader(info) = parsed.next_header() else {
        return Err("encoded descriptor parsed as a plain header".into());
    };
    assert_eq!(info.folders().len(), 1);
    assert_eq!(info.substream_count(), 1);
    Ok(())
}

#[test]
fn external_folder_definition_requires_additional_streams() -> Result<(), Box<dyn StdError>> {
    let next_header = [0x01, 0x04, 0x06, 0, 1, 0x09, 0, 0, 0x07, 0x0b, 1, 1, 0];
    let archive = make_archive(&[], &next_header)?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn external_folder_definition_is_staged_after_validating_additional_streams()
-> Result<(), Box<dyn StdError>> {
    let additional = folder_streams(
        0,
        &[3],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[3],
        None,
        None,
    )?;
    let mut main = Vec::from([0x06]);
    push_uint(&mut main, 3)?;
    push_uint(&mut main, 1)?;
    main.extend_from_slice(&[0x09, 0x00, 0x00, 0x07, 0x0b, 1, 1, 0, 0x0c, 0, 0, 0]);
    let mut header = Vec::from([0x01, 0x03]);
    header.extend_from_slice(&additional);
    header.push(0x04);
    header.extend_from_slice(&main);
    header.push(0);
    let archive = make_archive(&[1, 1, 0], &header)?;
    let parsed = parse(&archive, Limits::default())?;
    assert!(matches!(
        parsed.next_header(),
        ParsedNextHeader::PendingExternalFolders(_)
    ));
    Ok(())
}

#[test]
fn external_folders_cannot_self_source_or_appear_in_encoded_descriptor()
-> Result<(), Box<dyn StdError>> {
    let streams = [0x06, 0, 1, 0x09, 0, 0, 0x07, 0x0b, 1, 1, 0];
    for prefix in [0x03, 0x17] {
        let mut next_header = if prefix == 0x03 {
            Vec::from([0x01, prefix])
        } else {
            Vec::from([prefix])
        };
        next_header.extend_from_slice(&streams);
        let archive = make_archive(&[], &next_header)?;
        assert_eq!(
            parse(&archive, Limits::default())
                .err()
                .map(|error| error.kind()),
            Some(ErrorKind::Format)
        );
    }
    Ok(())
}

#[test]
fn rejects_external_property_index_outside_additional_streams() -> Result<(), Box<dyn StdError>> {
    let additional = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        None,
    )?;
    let files = files_info(1, &[(0x0e, vec![0x80]), (0x11, vec![1, 1])])?;
    let mut header = Vec::from([0x01, 0x03]);
    header.extend_from_slice(&additional);
    header.push(0x05);
    header.extend_from_slice(&files);
    header.push(0);
    let archive = make_archive(&[], &header)?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn rejects_overlapping_additional_and_main_pack_ranges() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[1],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[1],
        None,
        None,
    )?;
    let mut header = Vec::from([0x01, 0x03]);
    header.extend_from_slice(&streams);
    header.push(0x04);
    header.extend_from_slice(&streams);
    header.push(0);
    let archive = make_archive(&[0], &header)?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn enforces_name_limits_before_name_allocation() -> Result<(), Box<dyn StdError>> {
    let long_name = [u16::from(b'a'), u16::from(b'b')];
    let files = files_info(
        1,
        &[(0x0e, vec![0x80]), (0x11, names_property(&[&long_name]))],
    )?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let limits = Limits::builder().max_name_bytes_per_entry(2).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::NameBytesPerEntry,
            requested: 4,
            maximum: 2
        })
    ));

    let a = [u16::from(b'a')];
    let b = [u16::from(b'b')];
    let files = files_info(2, &[(0x0e, vec![0xc0]), (0x11, names_property(&[&a, &b]))])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let limits = Limits::builder().max_total_name_bytes(2).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::TotalNameBytes,
            requested: 4,
            maximum: 2
        })
    ));
    Ok(())
}

#[test]
fn enforces_parser_count_limits_at_their_declarations() -> Result<(), Box<dyn StdError>> {
    let files = files_info(0, &[(0x70, vec![]), (0x71, vec![])])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let limits = Limits::builder().max_header_properties(1).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::HeaderProperties,
            requested: 2,
            maximum: 1
        })
    ));

    let streams = folder_streams(
        0,
        &[0, 0],
        &[CoderSpec {
            method: &[0],
            inputs: 2,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[0, 1],
        &[0],
        None,
        None,
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    let limits = Limits::builder().max_streams_per_folder(2).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::StreamsPerFolder,
            requested: 3,
            maximum: 2
        })
    ));

    let archive = make_archive(&[], &[0x01, 0x00])?;
    let limits = Limits::builder().max_recursion_depth(0).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::RecursionDepth,
            requested: 1,
            maximum: 0
        })
    ));
    Ok(())
}

#[test]
fn enforces_substream_limit_before_substream_model_allocation() -> Result<(), Box<dyn StdError>> {
    let substreams = [0x0d, 2, 0x00];
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        Some(&substreams),
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    let limits = Limits::builder().max_substreams(1).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::Substreams,
            requested: 2,
            maximum: 1
        })
    ));

    let default_streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        None,
    )?;
    let mut header = Vec::from([0x01, 0x03]);
    header.extend_from_slice(&default_streams);
    header.push(0x04);
    header.extend_from_slice(&default_streams);
    header.push(0);
    let archive = make_archive(&[], &header)?;
    let limits = Limits::builder().max_substreams(1).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::Substreams,
            requested: 2,
            maximum: 1
        })
    ));
    Ok(())
}

#[test]
fn rejects_overflowing_folder_stream_totals() -> Result<(), Box<dyn StdError>> {
    let mut next_header = Vec::from([
        0x01, 0x04, 0x06, 0, 1, 0x09, 0, 0, 0x07, 0x0b, 1, 0, 1, 0x11, 0,
    ]);
    push_uint(&mut next_header, u64::MAX)?;
    push_uint(&mut next_header, 1)?;
    let archive = make_archive(&[], &next_header)?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn accepts_exactly_one_hundred_thousand_empty_entries() -> Result<(), Box<dyn StdError>> {
    let bits = vec![u8::MAX; 12_500];
    let files = files_info(100_000, &[(0x0e, bits.clone()), (0x0f, bits)])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    assert_eq!(
        header.files().map(|info| info.entries().len()),
        Some(100_000)
    );
    Ok(())
}

#[test]
fn nested_work_budget_stops_amplified_model_construction() -> Result<(), Box<dyn StdError>> {
    let bits = vec![u8::MAX; 12_500];
    let files = files_info(100_000, &[(0x0e, bits.clone()), (0x0f, bits)])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(50_000);
    assert!(matches!(
        parse_archive(&archive, Limits::default(), &cancellation, &mut budget),
        Err(Error::LimitExceeded {
            limit: LimitKind::WorkUnits,
            ..
        })
    ));
    Ok(())
}

#[test]
fn rejects_file_count_before_amplifying_allocation() -> Result<(), Box<dyn StdError>> {
    let files = files_info(100_001, &[])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    assert!(matches!(
        parse(&archive, Limits::default()),
        Err(Error::LimitExceeded {
            limit: LimitKind::Files,
            requested: 100_001,
            maximum: 100_000
        })
    ));
    Ok(())
}

#[test]
fn malicious_dictionary_properties_hit_memory_limit() -> Result<(), Box<dyn StdError>> {
    let cases: &[(&[u8], &[u8])] = &[
        (&[0x03, 0x01, 0x01], &[0x5d, 0, 0, 0, 0x40]),
        (&[0x21], &[40]),
        (&[0x03, 0x04, 0x01], &[4, 0, 0, 0, 0x40]),
    ];
    for (method, properties) in cases {
        let archive = one_coder_archive(method, Some(properties), 0)?;
        assert!(matches!(
            parse(&archive, Limits::default()),
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn deflate64_window_is_charged_during_model_validation() -> Result<(), Box<dyn StdError>> {
    let archive = one_coder_archive(&[0x04, 0x01, 0x09], None, 0)?;
    let limits = Limits::builder().max_dictionary_bytes(65_535).build();
    assert!(matches!(
        parse(&archive, limits),
        Err(Error::LimitExceeded {
            limit: LimitKind::DictionaryBytes,
            requested: 65_536,
            maximum: 65_535
        })
    ));
    Ok(())
}

#[test]
fn coder_property_declaration_is_limited_before_read() -> Result<(), Box<dyn StdError>> {
    let mut next_header = Vec::from([
        0x01, 0x04, 0x06, 0, 1, 0x09, 0, 0, 0x07, 0x0b, 1, 0, 1, 0x21, 0,
    ]);
    push_uint(&mut next_header, (1024 * 1024) + 1)?;
    let archive = make_archive(&[], &next_header)?;
    assert!(matches!(
        parse(&archive, Limits::default()),
        Err(Error::LimitExceeded {
            limit: LimitKind::CoderPropertyBytes,
            ..
        })
    ));
    Ok(())
}

#[test]
fn kdf_power_is_bounded_during_model_validation() -> Result<(), Box<dyn StdError>> {
    let archive = one_coder_archive(&[0x06, 0xf1, 0x07, 0x01], Some(&[0x99, 0, 0]), 0)?;
    assert!(matches!(
        parse(&archive, Limits::default()),
        Err(Error::LimitExceeded {
            limit: LimitKind::KdfPower,
            requested: 25,
            maximum: 24
        })
    ));
    Ok(())
}

#[test]
fn overflowed_pack_position_is_rejected() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        u64::MAX,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        None,
        None,
    )?;
    let archive = make_archive(&[], &plain_header(Some(&streams), None))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn bounded_properties_require_exact_consumption() -> Result<(), Box<dyn StdError>> {
    let files = files_info(1, &[(0x0e, vec![0x80, 0])])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    assert_eq!(
        parse(&archive, Limits::default())
            .err()
            .map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}

#[test]
fn unknown_properties_are_skipped_by_declared_length_and_retained() -> Result<(), Box<dyn StdError>>
{
    let files = files_info(0, &[(0x7e, vec![1, 2, 3])])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(property) = header
        .files()
        .and_then(|info| info.unknown_properties().first())
    else {
        return Err("unknown property was not retained".into());
    };
    assert_eq!(property.id(), 0x7e);
    assert_eq!(property.data(), &[1, 2, 3]);
    Ok(())
}

#[test]
fn unknown_unpack_size_and_absent_crc_remain_options() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0x7f],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[u64::MAX],
        None,
        None,
    )?;
    let files = files_info(1, &[(0x11, names_property(&[&[u16::from(b'x')]]))])?;
    let archive = make_archive(&[], &plain_header(Some(&streams), Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(stream) = header
        .files()
        .and_then(|files| files.entries().first())
        .and_then(unpackio::FileEntry::stream)
    else {
        return Err("unknown-size member mapping is missing".into());
    };
    assert_eq!(stream.size(), None);
    assert_eq!(stream.crc(), None);
    Ok(())
}

#[test]
fn defined_zero_crc_is_not_confused_with_absence() -> Result<(), Box<dyn StdError>> {
    let streams = folder_streams(
        0,
        &[0],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[0],
        Some(0),
        None,
    )?;
    let files = files_info(1, &[])?;
    let archive = make_archive(&[], &plain_header(Some(&streams), Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(stream) = header
        .files()
        .and_then(|files| files.entries().first())
        .and_then(unpackio::FileEntry::stream)
    else {
        return Err("zero-CRC member mapping is missing".into());
    };
    assert_eq!(stream.crc(), Some(0));
    Ok(())
}

#[test]
fn builds_substream_sizes_crcs_and_file_mappings() -> Result<(), Box<dyn StdError>> {
    let mut substreams = Vec::from([0x0d, 2, 0x09, 3, 0x0a, 1]);
    substreams.extend_from_slice(&11_u32.to_le_bytes());
    substreams.extend_from_slice(&22_u32.to_le_bytes());
    substreams.push(0);
    let streams = folder_streams(
        0,
        &[5],
        &[CoderSpec {
            method: &[0],
            inputs: 1,
            outputs: 1,
            properties: None,
        }],
        &[],
        &[],
        &[5],
        None,
        Some(&substreams),
    )?;
    let a = [u16::from(b'a')];
    let b = [u16::from(b'b')];
    let files = files_info(2, &[(0x11, names_property(&[&a, &b]))])?;
    let archive = make_archive(&[0; 5], &plain_header(Some(&streams), Some(&files)))?;
    let parsed = parse(&archive, Limits::default())?;
    let ParsedNextHeader::Header(header) = parsed.next_header() else {
        return Err("plain header parsed as encoded".into());
    };
    let Some(entries) = header.files().map(unpackio::FilesInfo::entries) else {
        return Err("files are missing".into());
    };
    let Some(first) = entries.first().and_then(unpackio::FileEntry::stream) else {
        return Err("first stream is missing".into());
    };
    let Some(second) = entries.get(1).and_then(unpackio::FileEntry::stream) else {
        return Err("second stream is missing".into());
    };
    assert_eq!((first.size(), first.crc()), (Some(3), Some(11)));
    assert_eq!((second.size(), second.crc()), (Some(2), Some(22)));
    Ok(())
}

#[test]
fn every_truncation_of_nested_header_is_an_error() -> Result<(), Box<dyn StdError>> {
    let archive = one_coder_archive(&[0], None, 0)?;
    for length in 0..archive.len() {
        let Some(prefix) = archive.get(..length) else {
            continue;
        };
        assert!(parse(prefix, Limits::default()).is_err(), "length {length}");
    }
    Ok(())
}

#[test]
fn crc_correct_mutations_never_bypass_model_validation_by_panicking()
-> Result<(), Box<dyn StdError>> {
    let base = plain_header(None, Some(&files_info(0, &[])?));
    for index in 0..base.len() {
        for mask in [1_u8, 0x40, 0x80, u8::MAX] {
            let mut mutated = base.clone();
            let Some(byte) = mutated.get_mut(index) else {
                return Err("mutation index is out of range".into());
            };
            *byte ^= mask;
            let archive = make_archive(&[], &mutated)?;
            let _ = parse(&archive, Limits::default());
        }
    }
    Ok(())
}

#[cfg(target_pointer_width = "32")]
#[test]
fn rejects_file_count_that_does_not_fit_usize_on_32_bit() -> Result<(), Box<dyn StdError>> {
    const FIRST_NON_USIZE_COUNT: u64 = 4_294_967_296;
    let files = files_info(FIRST_NON_USIZE_COUNT, &[])?;
    let archive = make_archive(&[], &plain_header(None, Some(&files)))?;
    let limits = Limits::builder().max_files(u64::MAX).build();
    assert_eq!(
        parse(&archive, limits).err().map(|error| error.kind()),
        Some(ErrorKind::Format)
    );
    Ok(())
}
