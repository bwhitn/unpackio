//! Execution of validated folder graphs over bounded archive byte ranges.

use crate::{
    ChecksumScope, Error, LimitKind, Limits, Result,
    checksum::Crc32,
    coder_properties::parse_ppmd_properties,
    decode::{
        METHOD_AES, METHOD_ARM, METHOD_ARM_THUMB, METHOD_ARM64, METHOD_BCJ, METHOD_BCJ2,
        METHOD_BROTLI, METHOD_BZIP2, METHOD_COPY, METHOD_DEFLATE, METHOD_DEFLATE64, METHOD_DELTA,
        METHOD_IA64, METHOD_LZ4, METHOD_LZMA, METHOD_LZMA2, METHOD_PPC, METHOD_PPMD, METHOD_RISCV,
        METHOD_SPARC, METHOD_SWAP2, METHOD_SWAP4, METHOD_ZSTD, decode_aes, decode_bcj2,
        decode_brotli, decode_bzip2, decode_deflate, decode_deflate64, decode_filter, decode_lz4,
        decode_lzma, decode_lzma2, decode_ppmd, decode_zstd,
    },
    model::{Coder, Folder, StreamsInfo},
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, format_error, try_reserve,
        u64_to_usize, usize_to_u64,
    },
    password::Password,
};

pub(crate) struct DecodedFolder {
    pub(crate) bytes: Vec<u8>,
    pub(crate) crc_mismatch: bool,
    pub(crate) encrypted: bool,
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

fn total_port_count(coders: &[Coder], inputs: bool) -> Result<usize> {
    let mut total = 0_u64;
    for coder in coders {
        total = total
            .checked_add(if inputs {
                coder.input_count()
            } else {
                coder.output_count()
            })
            .ok_or_else(|| format_error("folder port count overflows during execution"))?;
    }
    u64_to_usize(
        total,
        "folder port count is not representable on this platform during execution",
    )
}

fn empty_ports(count: usize) -> Result<Vec<Option<Vec<u8>>>> {
    let mut ports = Vec::new();
    try_reserve(&mut ports, count)?;
    ports.resize_with(count, || None);
    Ok(ports)
}

fn copy_input(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<Vec<u8>> {
    control.checkpoint(usize_to_u64(
        bytes.len(),
        "packed-input length is not representable as u64",
    )?)?;
    let mut copy = Vec::new();
    try_reserve(&mut copy, bytes.len())?;
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(0)?;
        copy.extend_from_slice(chunk);
    }
    Ok(copy)
}

fn validate_arity(coder: &Coder, inputs: u64, outputs: u64) -> Result<()> {
    if coder.input_count() == inputs && coder.output_count() == outputs {
        Ok(())
    } else {
        Err(format_error("coder stream arity does not match its method"))
    }
}

fn validate_coder_registration(coder: &Coder) -> Result<()> {
    let method = coder.method_id();
    if coder.output_count() != 1 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("multi-output-coder"),
        });
    }
    if method == METHOD_COPY {
        validate_arity(coder, 1, 1)?;
        if !coder.properties().is_empty() {
            return Err(format_error("Copy coder properties must be empty"));
        }
    } else if method == METHOD_LZMA {
        validate_arity(coder, 1, 1)?;
        if coder.properties().len() != 5 {
            return Err(format_error(
                "LZMA properties must contain exactly five bytes",
            ));
        }
    } else if method == METHOD_LZMA2 {
        validate_arity(coder, 1, 1)?;
        if coder.properties().len() != 1 {
            return Err(format_error(
                "LZMA2 properties must contain exactly one byte",
            ));
        }
    } else if method == METHOD_PPMD {
        validate_arity(coder, 1, 1)?;
        let _ = parse_ppmd_properties(coder.properties())?;
    } else if method == METHOD_DELTA {
        validate_arity(coder, 1, 1)?;
        if coder.properties().len() != 1 {
            return Err(format_error(
                "Delta properties must contain exactly one byte",
            ));
        }
    } else if matches!(
        method,
        METHOD_BCJ
            | METHOD_PPC
            | METHOD_ARM
            | METHOD_ARM64
            | METHOD_SPARC
            | METHOD_IA64
            | METHOD_ARM_THUMB
            | METHOD_RISCV
    ) {
        validate_arity(coder, 1, 1)?;
        if !matches!(coder.properties().len(), 0 | 4) {
            return Err(format_error(
                "branch filter properties must be empty or four bytes",
            ));
        }
    } else if method == METHOD_BCJ2 {
        validate_arity(coder, 4, 1)?;
        if !coder.properties().is_empty() {
            return Err(format_error("BCJ2 properties must be empty"));
        }
    } else if matches!(method, METHOD_SWAP2 | METHOD_SWAP4) {
        validate_arity(coder, 1, 1)?;
        if !coder.properties().is_empty() {
            return Err(format_error("Swap filter properties must be empty"));
        }
    } else if matches!(method, METHOD_DEFLATE | METHOD_DEFLATE64 | METHOD_BZIP2) {
        validate_arity(coder, 1, 1)?;
        if !coder.properties().is_empty() {
            return Err(format_error(
                "framed compression coder properties must be empty",
            ));
        }
    } else if matches!(method, METHOD_BROTLI | METHOD_LZ4 | METHOD_ZSTD) {
        // The pinned Go implementation treats these private-method properties
        // as opaque plugin metadata. The parser has already bounded and copied
        // them exactly; the framed stream remains self-describing.
        validate_arity(coder, 1, 1)?;
    } else if method == METHOD_AES {
        validate_arity(coder, 1, 1)?;
    } else {
        return Err(Error::UnsupportedMethod {
            method_id: method.into(),
        });
    }
    Ok(())
}

fn permits_unknown_output(method: &[u8]) -> bool {
    matches!(
        method,
        METHOD_COPY
            | METHOD_DELTA
            | METHOD_LZMA
            | METHOD_LZMA2
            | METHOD_BCJ
            | METHOD_BCJ2
            | METHOD_PPC
            | METHOD_ARM
            | METHOD_ARM64
            | METHOD_SPARC
            | METHOD_IA64
            | METHOD_ARM_THUMB
            | METHOD_RISCV
            | METHOD_SWAP2
            | METHOD_SWAP4
            | METHOD_DEFLATE
            | METHOD_DEFLATE64
    )
}

fn take_single_input(mut inputs: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    if inputs.len() != 1 {
        return Err(format_error(
            "single-input coder received the wrong stream count",
        ));
    }
    inputs
        .pop()
        .ok_or_else(|| format_error("single-input coder stream is missing"))
}

fn decode_coder(
    coder: &Coder,
    inputs: Vec<Vec<u8>>,
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    password: Option<&Password>,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let method = coder.method_id();
    if expected.is_none() && !permits_unknown_output(method) {
        return Err(Error::UnsupportedFeature {
            feature: String::from("coder-unknown-unpacked-size"),
        });
    }
    let output = if method == METHOD_COPY {
        validate_arity(coder, 1, 1)?;
        if !coder.properties().is_empty() {
            return Err(format_error("Copy coder properties must be empty"));
        }
        let input = take_single_input(inputs)?;
        check_limit(
            usize_to_u64(input.len(), "Copy output size is not representable as u64")?,
            maximum,
            LimitKind::TotalOutputBytes,
        )?;
        input
    } else if method == METHOD_LZMA {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_lzma(&input, coder.properties(), expected, maximum, control)?
    } else if method == METHOD_LZMA2 {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_lzma2(&input, coder.properties(), expected, maximum, control)?
    } else if method == METHOD_PPMD {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_ppmd(
            &input,
            coder.properties(),
            expected,
            maximum,
            limits,
            control,
        )?
    } else if matches!(
        method,
        METHOD_DELTA
            | METHOD_BCJ
            | METHOD_PPC
            | METHOD_ARM
            | METHOD_ARM64
            | METHOD_SPARC
            | METHOD_IA64
            | METHOD_ARM_THUMB
            | METHOD_RISCV
            | METHOD_SWAP2
            | METHOD_SWAP4
    ) {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        check_limit(
            usize_to_u64(
                input.len(),
                "filter output size is not representable as u64",
            )?,
            maximum,
            LimitKind::TotalOutputBytes,
        )?;
        decode_filter(method, coder.properties(), input, control)?
    } else if method == METHOD_BCJ2 {
        validate_arity(coder, 4, 1)?;
        decode_bcj2(&inputs, coder.properties(), expected, maximum, control)?
    } else if method == METHOD_DEFLATE {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_deflate(&input, expected, maximum, limits, control)?
    } else if method == METHOD_DEFLATE64 {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_deflate64(&input, expected, maximum, limits, control)?
    } else if method == METHOD_BZIP2 {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_bzip2(&input, expected, maximum, limits, control)?
    } else if method == METHOD_BROTLI {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_brotli(&input, expected, maximum, limits, control)?
    } else if method == METHOD_LZ4 {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_lz4(&input, expected, maximum, limits, control)?
    } else if method == METHOD_ZSTD {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_zstd(&input, expected, maximum, limits, control)?
    } else if method == METHOD_AES {
        validate_arity(coder, 1, 1)?;
        let input = take_single_input(inputs)?;
        decode_aes(
            input,
            coder.properties(),
            expected,
            maximum,
            limits,
            password,
            control,
        )?
    } else {
        return Err(Error::UnsupportedMethod {
            method_id: method.into(),
        });
    };
    let actual = usize_to_u64(
        output.len(),
        "decoded coder output size is not representable as u64",
    )?;
    check_limit(actual, maximum, LimitKind::TotalOutputBytes)?;
    if expected.is_some_and(|size| size != actual) {
        return Err(format_error(
            "decoded coder output size does not match its declaration",
        ));
    }
    Ok(output)
}

fn output_destinations(
    folder: &Folder,
    output_count: usize,
    control: &mut ParseControl<'_>,
) -> Result<Vec<Option<u64>>> {
    let mut destinations = Vec::new();
    try_reserve(&mut destinations, output_count)?;
    destinations.resize(output_count, None);
    for pair in folder.bind_pairs() {
        control.checkpoint(1)?;
        let output_index = u64_to_usize(
            pair.output_index(),
            "bound output index is not representable on this platform",
        )?;
        let destination = destinations
            .get_mut(output_index)
            .ok_or_else(|| format_error("bound output index is out of range"))?;
        if destination.replace(pair.input_index()).is_some() {
            return Err(format_error("validated output binding is duplicated"));
        }
    }
    Ok(destinations)
}

fn load_packed_inputs(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    folder: &Folder,
    input_ports: &mut [Option<Vec<u8>>],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    for (ordinal, input_index) in folder.packed_input_indices().iter().enumerate() {
        control.checkpoint(1)?;
        let ordinal = usize_to_u64(ordinal, "packed-stream ordinal is not representable as u64")?;
        let stream_index = folder
            .first_pack_stream()
            .checked_add(ordinal)
            .ok_or_else(|| format_error("packed-stream index overflows during execution"))?;
        let stream_index = u64_to_usize(
            stream_index,
            "packed-stream index is not representable on this platform",
        )?;
        let stream = streams
            .pack_streams()
            .get(stream_index)
            .ok_or_else(|| format_error("packed-stream index is out of range during execution"))?;
        let size = stream.size().ok_or_else(|| Error::UnsupportedFeature {
            feature: String::from("unknown-packed-stream-size"),
        })?;
        let bytes = checked_range(
            archive_bytes,
            stream.offset(),
            size,
            "packed-stream range overflows during execution",
            "packed-stream range is truncated during execution",
        )?;
        if let Some(expected) = stream.crc() {
            if checksum(bytes, control)? != expected {
                return Err(Error::Checksum {
                    scope: ChecksumScope::PackedStream,
                    member_index: None,
                });
            }
        }
        let input_index = u64_to_usize(
            *input_index,
            "packed-input port is not representable on this platform",
        )?;
        let port = input_ports
            .get_mut(input_index)
            .ok_or_else(|| format_error("packed-input port is out of range during execution"))?;
        if port.is_some() {
            return Err(format_error(
                "packed-input port was populated more than once",
            ));
        }
        *port = Some(copy_input(bytes, control)?);
    }
    Ok(())
}

pub(crate) fn decode_folder(
    archive_bytes: &[u8],
    streams: &StreamsInfo,
    folder_index: u64,
    password: Option<&Password>,
    limits: Limits,
    maximum_output: u64,
    control: &mut ParseControl<'_>,
) -> Result<DecodedFolder> {
    let folder_index = u64_to_usize(
        folder_index,
        "folder index is not representable on this platform during execution",
    )?;
    let folder = streams
        .folders()
        .get(folder_index)
        .ok_or_else(|| format_error("folder index is out of range during execution"))?;
    let encrypted = folder
        .coders()
        .iter()
        .any(|coder| coder.method_id() == METHOD_AES);
    check_limit(
        folder.dictionary_bytes(),
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let root_output_index = u64_to_usize(
        folder.root_output_index(),
        "root output index is not representable on this platform",
    )?;
    if let Some(size) = folder
        .unpack_sizes()
        .get(root_output_index)
        .copied()
        .ok_or_else(|| format_error("root output size is missing during execution"))?
    {
        check_limit(size, maximum_output, LimitKind::TotalOutputBytes)?;
    }
    for coder in folder.coders() {
        validate_coder_registration(coder)?;
        control.checkpoint(1)?;
    }
    let input_count = total_port_count(folder.coders(), true)?;
    let output_count = total_port_count(folder.coders(), false)?;
    let mut input_ports = empty_ports(input_count)?;
    let mut output_ports = empty_ports(output_count)?;
    let mut output_destinations = output_destinations(folder, output_count, control)?;
    load_packed_inputs(archive_bytes, streams, folder, &mut input_ports, control)?;

    for coder_index in folder.topological_coder_order() {
        control.checkpoint(1)?;
        let coder_index = u64_to_usize(
            *coder_index,
            "coder index is not representable on this platform during execution",
        )?;
        let coder = folder
            .coders()
            .get(coder_index)
            .ok_or_else(|| format_error("coder index is out of range during execution"))?;
        if coder.output_count() != 1 {
            return Err(Error::UnsupportedFeature {
                feature: String::from("multi-output-coder"),
            });
        }
        let mut inputs = Vec::new();
        let capacity = u64_to_usize(
            coder.input_count(),
            "coder input count is not representable on this platform",
        )?;
        try_reserve(&mut inputs, capacity)?;
        for relative in 0..coder.input_count() {
            let input_index = coder
                .input_start()
                .checked_add(relative)
                .ok_or_else(|| format_error("coder input index overflows during execution"))?;
            let input_index = u64_to_usize(
                input_index,
                "coder input index is not representable on this platform",
            )?;
            let input = input_ports
                .get_mut(input_index)
                .ok_or_else(|| format_error("coder input index is out of range during execution"))?
                .take()
                .ok_or_else(|| {
                    format_error("coder input stream is unavailable during execution")
                })?;
            inputs.push(input);
        }
        let output_index = coder.output_start();
        let output_slot = u64_to_usize(
            output_index,
            "coder output index is not representable on this platform",
        )?;
        let expected = folder
            .unpack_sizes()
            .get(output_slot)
            .copied()
            .ok_or_else(|| format_error("coder output size is missing during execution"))?;
        let coder_maximum = if output_index == folder.root_output_index() {
            maximum_output
        } else {
            limits.max_total_output_bytes()
        };
        let output = decode_coder(
            coder,
            inputs,
            expected,
            coder_maximum,
            limits,
            password,
            control,
        )?;
        let destination = output_destinations
            .get_mut(output_slot)
            .ok_or_else(|| format_error("coder output index is out of range during execution"))?
            .take();
        if let Some(destination) = destination {
            let destination = u64_to_usize(
                destination,
                "bound input index is not representable on this platform",
            )?;
            let port = input_ports.get_mut(destination).ok_or_else(|| {
                format_error("bound input index is out of range during execution")
            })?;
            if port.replace(output).is_some() {
                return Err(format_error(
                    "bound input stream was populated more than once",
                ));
            }
        } else {
            let port = output_ports.get_mut(output_slot).ok_or_else(|| {
                format_error("root output index is out of range during execution")
            })?;
            if port.replace(output).is_some() {
                return Err(format_error(
                    "root output stream was populated more than once",
                ));
            }
        }
    }
    if input_ports.iter().any(Option::is_some) {
        return Err(format_error(
            "folder execution left an input stream unconsumed",
        ));
    }
    let root = u64_to_usize(
        folder.root_output_index(),
        "root output index is not representable on this platform",
    )?;
    let bytes = output_ports
        .get_mut(root)
        .ok_or_else(|| format_error("root output index is out of range during execution"))?
        .take()
        .ok_or_else(|| format_error("root output stream is unavailable after execution"))?;
    if output_ports.iter().any(Option::is_some) {
        return Err(format_error(
            "folder execution produced multiple root streams",
        ));
    }
    let crc_mismatch = match folder.crc() {
        Some(expected) => checksum(&bytes, control)? != expected,
        None => false,
    };
    Ok(DecodedFolder {
        bytes,
        crc_mismatch,
        encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_coder, decode_folder, permits_unknown_output};
    use crate::{
        CancellationToken, Error, Limits, Result, WorkBudget,
        decode::{
            METHOD_AES, METHOD_ARM_THUMB, METHOD_BROTLI, METHOD_BZIP2, METHOD_COPY,
            METHOD_DEFLATE64, METHOD_IA64, METHOD_LZ4, METHOD_LZMA2, METHOD_PPMD, METHOD_RISCV,
            METHOD_SWAP2, METHOD_SWAP4, METHOD_ZSTD,
        },
        model::{BindPair, Coder, Folder, PackStream, StreamsInfo, Substream},
        parse_util::ParseControl,
    };

    fn execute_one_coder(method: Box<[u8]>, budget: &mut WorkBudget) -> Result<Vec<u8>> {
        let data = b"graph";
        let coder = Coder::new(method, 0, 1, 0, 1, Box::default(), None);
        let folder = Folder::new(
            vec![coder].into_boxed_slice(),
            Box::default(),
            vec![0].into_boxed_slice(),
            vec![Some(5)].into_boxed_slice(),
            0,
            vec![0].into_boxed_slice(),
            None,
            vec![Substream::new(Some(5), None)].into_boxed_slice(),
            0,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            vec![PackStream::new(0, Some(5), None)].into_boxed_slice(),
            vec![folder].into_boxed_slice(),
            1,
        );
        let cancellation = CancellationToken::new();
        let mut control = ParseControl::new(&cancellation, budget);
        Ok(decode_folder(data, &streams, 0, None, Limits::default(), 5, &mut control)?.bytes)
    }

    #[test]
    fn executes_stored_reverse_chain_in_validated_topological_order() -> Result<()> {
        let data = b"chain";
        let final_coder = Coder::new(METHOD_COPY.into(), 0, 1, 0, 1, Box::default(), None);
        let source_coder = Coder::new(METHOD_COPY.into(), 1, 1, 1, 1, Box::default(), None);
        let folder = Folder::new(
            vec![final_coder, source_coder].into_boxed_slice(),
            vec![BindPair::new(0, 1)].into_boxed_slice(),
            vec![1].into_boxed_slice(),
            vec![Some(5), Some(5)].into_boxed_slice(),
            0,
            vec![1, 0].into_boxed_slice(),
            None,
            vec![Substream::new(Some(5), None)].into_boxed_slice(),
            0,
            0,
        );
        let streams = StreamsInfo::new(
            0,
            vec![PackStream::new(0, Some(5), None)].into_boxed_slice(),
            vec![folder].into_boxed_slice(),
            1,
        );
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let decoded = decode_folder(data, &streams, 0, None, Limits::default(), 5, &mut control)?;
        assert_eq!(decoded.bytes, data);
        assert!(!decoded.crc_mismatch);
        Ok(())
    }

    #[test]
    fn unsupported_method_is_typed() {
        let mut budget = WorkBudget::bounded(0);
        assert!(matches!(
            execute_one_coder(vec![0x7f].into_boxed_slice(), &mut budget),
            Err(Error::UnsupportedMethod { method_id }) if method_id.as_ref() == [0x7f]
        ));
        assert_eq!(budget.remaining(), Some(0));
    }

    #[test]
    fn unknown_output_policy_is_explicit_and_conservative() {
        assert!(permits_unknown_output(METHOD_COPY));
        assert!(permits_unknown_output(METHOD_LZMA2));
        assert!(permits_unknown_output(METHOD_DEFLATE64));
        for method in [
            METHOD_IA64,
            METHOD_ARM_THUMB,
            METHOD_RISCV,
            METHOD_SWAP2,
            METHOD_SWAP4,
        ] {
            assert!(permits_unknown_output(method));
        }
        for method in [
            METHOD_PPMD,
            METHOD_AES,
            METHOD_BZIP2,
            METHOD_BROTLI,
            METHOD_LZ4,
            METHOD_ZSTD,
        ] {
            assert!(!permits_unknown_output(method));
        }
    }

    #[test]
    fn unknown_output_rejection_is_typed_before_codec_work() {
        let coder = Coder::new(METHOD_PPMD.into(), 0, 1, 0, 1, Box::default(), None);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_coder(
            &coder,
            vec![Vec::new()],
            None,
            0,
            Limits::default(),
            None,
            &mut control,
        );
        assert!(matches!(
            result,
            Err(Error::UnsupportedFeature { feature })
                if feature == "coder-unknown-unpacked-size"
        ));
        assert_eq!(budget.remaining(), Some(0));
    }
}
