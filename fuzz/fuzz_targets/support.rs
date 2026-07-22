#![forbid(unsafe_code)]
// Each fuzz binary selects a different subset of these shared constructors.
#![allow(dead_code)]

use aes::{
    Aes256,
    cipher::{Block, BlockModeEncrypt, KeyIvInit},
};

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const METHOD_COPY: &[u8] = &[0x00];
const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const METHOD_LZMA2: &[u8] = &[0x21];
const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const METHOD_DELTA: &[u8] = &[0x03];
const METHOD_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
const METHOD_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1b];
const METHOD_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
const METHOD_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
const METHOD_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
const METHOD_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
const METHOD_BROTLI: &[u8] = &[0x04, 0xf7, 0x11, 0x02];
const METHOD_LZ4: &[u8] = &[0x04, 0xf7, 0x11, 0x04];
const METHOD_ZSTD: &[u8] = &[0x04, 0xf7, 0x11, 0x01];
const METHOD_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
const FUZZ_PASSWORD: &str = "fuzz-password";
const GENERATED_PAYLOAD_LIMIT: usize = 64;

// `abc`, encoded as a raw LZMA1 EOS stream by XZ Utils 5.8.3. Its existing
// unit-test provenance is recorded in CORPUS.md and PROVENANCE.md.
const LZMA_ABC: &[u8] = &[
    0x00, 0x30, 0x98, 0x88, 0xa4, 0x4a, 0x8e, 0x9f, 0xff, 0xf6, 0x63, 0x80, 0x00,
];
const LZMA_ABC_PROPERTIES: &[u8] = &[0x5d, 0x00, 0x10, 0x00, 0x00];

// Synthetic text encoded by stock 7zz 26.02 as PPMd7 order 6 with a 64 KiB
// model. The exact command, hashes, and black-box provenance are recorded in
// CORPUS.md and PROVENANCE.md; no oracle-authored archive is retained.
const PPMD_SEED: &[u8] = &[
    0x00, 0x50, 0x01, 0xe2, 0xfb, 0xf5, 0x0f, 0xe5, 0x00, 0x93, 0xf9, 0x01, 0xda, 0xf2, 0xa8, 0x02,
    0x8b, 0x72, 0x66, 0x5b, 0x34, 0xaa, 0x5a, 0xfc, 0xd6, 0xbb, 0xf6, 0x4e, 0x79, 0xab, 0x83, 0xe5,
    0xa9, 0x16, 0x93, 0x8d, 0x10, 0x93, 0x1a, 0xdf, 0x38, 0xab, 0xa2, 0x72, 0xf6, 0x12, 0x2d, 0x98,
    0x00,
];
const PPMD_SEED_PROPERTIES: &[u8] = &[0x06, 0x00, 0x00, 0x01, 0x00];
const PPMD_PY7ZR_SEED_PROPERTIES: &[u8] = &[0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
const PPMD_SEED_OUTPUT: &[u8] = b"PPMd fuzz seed: alpha beta gamma delta 0123456789\n";

// Synthetic `hello\n` vectors. The BZip2 stream was produced by bzip2 1.0.8;
// the Brotli stream is the permissively licensed brotli-decompressor 5.0.3
// `reader.rs` regression. Exact hashes and provenance are recorded in the
// repository corpus/provenance ledgers.
const BZIP2_HELLO: &[u8] = &[
    0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xc1, 0xc0, 0x80, 0xe2, 0x00, 0x00,
    0x01, 0x41, 0x00, 0x00, 0x10, 0x02, 0x44, 0xa0, 0x00, 0x30, 0xcd, 0x00, 0xc3, 0x46, 0x29, 0x97,
    0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0xc1, 0xc0, 0x80, 0xe2,
];
const BROTLI_HELLO: &[u8] = b"\x8f\x02\x80hello\n\x03";
const HELLO: &[u8] = b"hello\n";

#[derive(Clone, Copy)]
struct SeedCoder<'method> {
    method: &'method [u8],
    properties: Option<&'method [u8]>,
    inputs: u64,
    outputs: u64,
}

impl<'method> SeedCoder<'method> {
    const fn simple(method: &'method [u8], properties: Option<&'method [u8]>) -> Self {
        Self {
            method,
            properties,
            inputs: 1,
            outputs: 1,
        }
    }
}

/// A deterministic, structurally valid archive assembled inside the fuzzer.
pub(crate) struct GeneratedDecoderSeed {
    archive: Vec<u8>,
    expected: Option<Vec<u8>>,
    password: Option<&'static str>,
    packed_ranges: Vec<(usize, usize)>,
    pack_size_offsets: Vec<usize>,
    property_length_offsets: Vec<usize>,
    property_byte_offsets: Vec<usize>,
    binding_offsets: Vec<usize>,
    unpack_size_offsets: Vec<usize>,
    folder_crc_offset: Option<usize>,
}

impl GeneratedDecoderSeed {
    pub(crate) fn archive(&self) -> &[u8] {
        &self.archive
    }

    pub(crate) fn expected(&self) -> Option<&[u8]> {
        self.expected.as_deref()
    }

    pub(crate) const fn password(&self) -> Option<&'static str> {
        self.password
    }

    pub(crate) fn mutated(&self, selector: u8) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.archive.len()).ok()?;
        bytes.extend_from_slice(&self.archive);
        let mutation = selector % 8;
        match mutation {
            0 => {
                let &(start, end) = select(&self.packed_ranges, selector)?;
                let width = end.checked_sub(start)?;
                if width == 0 {
                    return mutate_header_byte(bytes, self, selector);
                }
                let relative = usize::from(selector) % width;
                let offset = start.checked_add(relative)?;
                let byte = bytes.get_mut(offset)?;
                *byte ^= 0x80;
                Some(bytes)
            }
            1 => {
                if bytes.is_empty() {
                    return Some(bytes);
                }
                let cut = usize::from(selector) % bytes.len();
                bytes.truncate(cut);
                Some(bytes)
            }
            2 => {
                let offset = *select(&self.property_length_offsets, selector)?;
                *bytes.get_mut(offset)? = 0x7f;
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
            3 => {
                let Some(offset) = select(&self.property_byte_offsets, selector).copied() else {
                    return mutate_header_byte(bytes, self, selector);
                };
                *bytes.get_mut(offset)? ^= 0xff;
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
            4 => {
                let Some(offset) = select(&self.binding_offsets, selector).copied() else {
                    return mutate_header_byte(bytes, self, selector);
                };
                *bytes.get_mut(offset)? = 0x7f;
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
            5 => {
                let offset = *select(&self.unpack_size_offsets, selector)?;
                let value = bytes.get_mut(offset)?;
                *value = match value.checked_add(1) {
                    Some(next) => next & 0x7f,
                    None => 0,
                };
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
            6 => {
                let Some(offset) = self.folder_crc_offset else {
                    return mutate_header_byte(bytes, self, selector);
                };
                *bytes.get_mut(offset)? ^= 1;
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
            _ => {
                let offset = *select(&self.pack_size_offsets, selector)?;
                let value = bytes.get_mut(offset)?;
                if *value > 0 {
                    *value = value.checked_sub(1)?;
                }
                refresh_header_crcs(&mut bytes)?;
                Some(bytes)
            }
        }
    }
}

fn select<T>(values: &[T], selector: u8) -> Option<&T> {
    if values.is_empty() {
        return None;
    }
    values.get(usize::from(selector) % values.len())
}

fn mutate_header_byte(
    mut bytes: Vec<u8>,
    seed: &GeneratedDecoderSeed,
    selector: u8,
) -> Option<Vec<u8>> {
    let header_start = 32_usize.checked_add(total_packed_size(&seed.packed_ranges)?)?;
    let header_width = bytes.len().checked_sub(header_start)?;
    if header_width == 0 {
        return Some(bytes);
    }
    let offset = header_start.checked_add(usize::from(selector) % header_width)?;
    *bytes.get_mut(offset)? ^= 0x40;
    refresh_header_crcs(&mut bytes)?;
    Some(bytes)
}

fn total_packed_size(ranges: &[(usize, usize)]) -> Option<usize> {
    let mut total = 0_usize;
    for (start, end) in ranges {
        total = total.checked_add(end.checked_sub(*start)?)?;
    }
    Some(total)
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let value: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(value))
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let end = offset.checked_add(4)?;
    bytes
        .get_mut(offset..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn refresh_header_crcs(bytes: &mut [u8]) -> Option<()> {
    let next_offset = usize::try_from(read_u64_at(bytes, 12)?).ok()?;
    let next_size = usize::try_from(read_u64_at(bytes, 20)?).ok()?;
    let next_start = 32_usize.checked_add(next_offset)?;
    let next_end = next_start.checked_add(next_size)?;
    let next_crc = crc32(bytes.get(next_start..next_end)?);
    write_u32_at(bytes, 28, next_crc)?;
    let start_crc = crc32(bytes.get(12..32)?);
    write_u32_at(bytes, 8, start_crc)
}

pub(crate) fn crc32(bytes: &[u8]) -> u32 {
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

pub(crate) fn wrap_next_header(next_header: &[u8]) -> Option<Vec<u8>> {
    let next_size = u64::try_from(next_header.len()).ok()?;
    let next_crc = crc32(next_header);
    let mut start_fields = Vec::new();
    start_fields.try_reserve_exact(20).ok()?;
    start_fields.extend_from_slice(&0_u64.to_le_bytes());
    start_fields.extend_from_slice(&next_size.to_le_bytes());
    start_fields.extend_from_slice(&next_crc.to_le_bytes());
    let archive_size = 32_usize.checked_add(next_header.len())?;
    let mut archive = Vec::new();
    archive.try_reserve_exact(archive_size).ok()?;
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(next_header);
    Some(archive)
}

fn push_uint(bytes: &mut Vec<u8>, value: u64) -> Option<()> {
    for additional in 0_u32..8 {
        let value_bits = 7_u32.checked_mul(additional.checked_add(1)?)?;
        let threshold = 1_u64.checked_shl(value_bits)?;
        if value >= threshold {
            continue;
        }
        let prefix = if additional == 0 {
            0
        } else {
            u8::MAX.checked_shl(8_u32.checked_sub(additional)?)?
        };
        let high = u8::try_from(value >> 8_u32.checked_mul(additional)?).ok()?;
        bytes.push(prefix | high);
        let additional = usize::try_from(additional).ok()?;
        bytes.extend(value.to_le_bytes().iter().take(additional));
        return Some(());
    }
    bytes.push(u8::MAX);
    bytes.extend_from_slice(&value.to_le_bytes());
    Some(())
}

fn wrap_payload_and_header(payload: &[u8], next_header: &[u8]) -> Option<Vec<u8>> {
    let next_offset = u64::try_from(payload.len()).ok()?;
    let next_size = u64::try_from(next_header.len()).ok()?;
    let next_crc = crc32(next_header);
    let mut start_fields = Vec::new();
    start_fields.try_reserve_exact(20).ok()?;
    start_fields.extend_from_slice(&next_offset.to_le_bytes());
    start_fields.extend_from_slice(&next_size.to_le_bytes());
    start_fields.extend_from_slice(&next_crc.to_le_bytes());
    let capacity = 32_usize
        .checked_add(payload.len())?
        .checked_add(next_header.len())?;
    let mut archive = Vec::new();
    archive.try_reserve_exact(capacity).ok()?;
    archive.extend_from_slice(SIGNATURE);
    archive.extend_from_slice(&[0, 4]);
    archive.extend_from_slice(&crc32(&start_fields).to_le_bytes());
    archive.extend_from_slice(&start_fields);
    archive.extend_from_slice(payload);
    archive.extend_from_slice(next_header);
    Some(archive)
}

pub(crate) fn wrap_one_coder_archive(
    payload: &[u8],
    method: &[u8],
    properties: Option<&[u8]>,
    unpack_size: u64,
    folder_crc: Option<u32>,
) -> Option<Vec<u8>> {
    let mut streams = Vec::new();
    streams.try_reserve_exact(96).ok()?;
    streams.push(0x06);
    push_uint(&mut streams, 0)?;
    push_uint(&mut streams, 1)?;
    streams.push(0x09);
    push_uint(&mut streams, u64::try_from(payload.len()).ok()?)?;
    streams.push(0x00);

    streams.extend_from_slice(&[0x07, 0x0b]);
    push_uint(&mut streams, 1)?;
    streams.push(0);
    push_uint(&mut streams, 1)?;
    let mut flags = u8::try_from(method.len()).ok()?;
    if properties.is_some() {
        flags |= 0x20;
    }
    streams.push(flags);
    streams.extend_from_slice(method);
    if let Some(properties) = properties {
        push_uint(&mut streams, u64::try_from(properties.len()).ok()?)?;
        streams.extend_from_slice(properties);
    }
    streams.push(0x0c);
    push_uint(&mut streams, unpack_size)?;
    if let Some(crc) = folder_crc {
        streams.extend_from_slice(&[0x0a, 1]);
        streams.extend_from_slice(&crc.to_le_bytes());
    }
    streams.extend_from_slice(&[0x00, 0x00]);

    let mut header = Vec::new();
    header
        .try_reserve_exact(streams.len().checked_add(8)?)
        .ok()?;
    header.extend_from_slice(&[0x01, 0x04]);
    header.extend_from_slice(&streams);
    header.extend_from_slice(&[0x05, 0x01, 0x00, 0x00]);
    wrap_payload_and_header(payload, &header)
}

pub(crate) fn wrap_copy_archive(payload: &[u8]) -> Option<Vec<u8>> {
    wrap_one_coder_archive(
        payload,
        &[0],
        None,
        u64::try_from(payload.len()).ok()?,
        Some(crc32(payload)),
    )
}

pub(crate) fn wrap_external_folder_archive(
    member: &[u8],
    folder_definition: &[u8],
) -> Option<Vec<u8>> {
    let folder_size = u64::try_from(folder_definition.len()).ok()?;
    let member_size = u64::try_from(member.len()).ok()?;
    let mut header = Vec::new();
    header.try_reserve_exact(160).ok()?;
    header.extend_from_slice(&[0x01, 0x03, 0x06]);
    push_uint(&mut header, 0)?;
    push_uint(&mut header, 1)?;
    header.push(0x09);
    push_uint(&mut header, folder_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&crc32(folder_definition).to_le_bytes());
    header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
    push_uint(&mut header, folder_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&crc32(folder_definition).to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00, 0x04, 0x06]);
    push_uint(&mut header, folder_size)?;
    push_uint(&mut header, 1)?;
    header.push(0x09);
    push_uint(&mut header, member_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&crc32(member).to_le_bytes());
    header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 1, 0, 0x0c]);
    push_uint(&mut header, member_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&crc32(member).to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x00, 0x00]);

    let capacity = folder_definition.len().checked_add(member.len())?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(capacity).ok()?;
    payload.extend_from_slice(folder_definition);
    payload.extend_from_slice(member);
    wrap_payload_and_header(&payload, &header)
}

pub(crate) fn wrap_unreferenced_additional_archive(
    additional: &[u8],
    member: &[u8],
) -> Option<Vec<u8>> {
    let additional_size = u64::try_from(additional.len()).ok()?;
    let member_size = u64::try_from(member.len()).ok()?;
    let additional_crc = crc32(additional);
    let member_crc = crc32(member);
    let mut header = Vec::new();
    header.try_reserve_exact(160).ok()?;
    header.extend_from_slice(&[0x01, 0x03, 0x06]);
    push_uint(&mut header, 0)?;
    push_uint(&mut header, 1)?;
    header.push(0x09);
    push_uint(&mut header, additional_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&additional_crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
    push_uint(&mut header, additional_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&additional_crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00, 0x04, 0x06]);
    push_uint(&mut header, additional_size)?;
    push_uint(&mut header, 1)?;
    header.push(0x09);
    push_uint(&mut header, member_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&member_crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x07, 0x0b, 1, 0, 1, 1, 0, 0x0c]);
    push_uint(&mut header, member_size)?;
    header.extend_from_slice(&[0x0a, 1]);
    header.extend_from_slice(&member_crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x00, 0x00]);

    let capacity = additional.len().checked_add(member.len())?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(capacity).ok()?;
    payload.extend_from_slice(additional);
    payload.extend_from_slice(member);
    wrap_payload_and_header(&payload, &header)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Option<u64> {
    let mut total = 0_u64;
    for value in values {
        total = total.checked_add(value)?;
    }
    Some(total)
}

fn copy_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).ok()?;
    copy.extend_from_slice(bytes);
    Some(copy)
}

fn make_absolute(offsets: &mut [usize], base: usize) -> Option<()> {
    for offset in offsets {
        *offset = base.checked_add(*offset)?;
    }
    Some(())
}

#[allow(clippy::too_many_arguments)]
fn build_decoder_seed(
    packed_streams: &[Vec<u8>],
    coders: &[SeedCoder<'_>],
    bindings: &[(u64, u64)],
    packed_inputs: &[u64],
    unpack_sizes: &[u64],
    folder_crc: Option<u32>,
    expected: Option<&[u8]>,
    password: Option<&'static str>,
) -> Option<GeneratedDecoderSeed> {
    if packed_streams.is_empty() || coders.is_empty() {
        return None;
    }
    let total_inputs = checked_sum(coders.iter().map(|coder| coder.inputs))?;
    let total_outputs = checked_sum(coders.iter().map(|coder| coder.outputs))?;
    let binding_count = u64::try_from(bindings.len()).ok()?;
    if binding_count != total_outputs.checked_sub(1)? {
        return None;
    }
    let packed_count = total_inputs.checked_sub(binding_count)?;
    if usize::try_from(packed_count).ok()? != packed_streams.len()
        || packed_inputs.len() != packed_streams.len()
        || usize::try_from(total_outputs).ok()? != unpack_sizes.len()
    {
        return None;
    }

    let payload_size = packed_streams
        .iter()
        .try_fold(0_usize, |total, stream| total.checked_add(stream.len()))?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_size).ok()?;
    let mut packed_ranges = Vec::new();
    packed_ranges.try_reserve_exact(packed_streams.len()).ok()?;
    for stream in packed_streams {
        let start = 32_usize.checked_add(payload.len())?;
        payload.extend_from_slice(stream);
        let end = 32_usize.checked_add(payload.len())?;
        packed_ranges.push((start, end));
    }

    let mut header = Vec::new();
    header.try_reserve_exact(256).ok()?;
    header.extend_from_slice(&[0x01, 0x04, 0x06]);
    push_uint(&mut header, 0)?;
    push_uint(&mut header, packed_count)?;
    header.push(0x09);
    let mut pack_size_offsets = Vec::new();
    for stream in packed_streams {
        if stream.len() >= 0x80 {
            return None;
        }
        pack_size_offsets.push(header.len());
        push_uint(&mut header, u64::try_from(stream.len()).ok()?)?;
    }
    header.extend_from_slice(&[0x00, 0x07, 0x0b]);
    push_uint(&mut header, 1)?;
    header.push(0);
    push_uint(&mut header, u64::try_from(coders.len()).ok()?)?;
    let mut property_length_offsets = Vec::new();
    let mut property_byte_offsets = Vec::new();
    for coder in coders {
        let method_length = u8::try_from(coder.method.len()).ok()?;
        if method_length == 0 || method_length > 0x0f {
            return None;
        }
        let mut flags = method_length;
        if coder.inputs != 1 || coder.outputs != 1 {
            flags |= 0x10;
        }
        if coder.properties.is_some() {
            flags |= 0x20;
        }
        header.push(flags);
        header.extend_from_slice(coder.method);
        if flags & 0x10 != 0 {
            push_uint(&mut header, coder.inputs)?;
            push_uint(&mut header, coder.outputs)?;
        }
        if let Some(properties) = coder.properties {
            if properties.len() >= 0x80 {
                return None;
            }
            property_length_offsets.push(header.len());
            push_uint(&mut header, u64::try_from(properties.len()).ok()?)?;
            for byte in properties {
                property_byte_offsets.push(header.len());
                header.push(*byte);
            }
        }
    }
    let mut binding_offsets = Vec::new();
    for (input, output) in bindings {
        binding_offsets.push(header.len());
        push_uint(&mut header, *input)?;
        binding_offsets.push(header.len());
        push_uint(&mut header, *output)?;
    }
    if packed_count != 1 {
        for input in packed_inputs {
            push_uint(&mut header, *input)?;
        }
    }
    header.push(0x0c);
    let mut unpack_size_offsets = Vec::new();
    for unpack_size in unpack_sizes {
        if *unpack_size >= 0x80 {
            return None;
        }
        unpack_size_offsets.push(header.len());
        push_uint(&mut header, *unpack_size)?;
    }
    let folder_crc_offset = folder_crc.map(|crc| {
        header.extend_from_slice(&[0x0a, 1]);
        let offset = header.len();
        header.extend_from_slice(&crc.to_le_bytes());
        offset
    });
    header.extend_from_slice(&[0x00, 0x00, 0x05, 0x01, 0x00, 0x00]);

    let header_base = 32_usize.checked_add(payload.len())?;
    make_absolute(&mut pack_size_offsets, header_base)?;
    make_absolute(&mut property_length_offsets, header_base)?;
    make_absolute(&mut property_byte_offsets, header_base)?;
    make_absolute(&mut binding_offsets, header_base)?;
    make_absolute(&mut unpack_size_offsets, header_base)?;
    let folder_crc_offset = match folder_crc_offset {
        Some(offset) => Some(header_base.checked_add(offset)?),
        None => None,
    };
    let archive = wrap_payload_and_header(&payload, &header)?;
    let expected = match expected {
        Some(bytes) => Some(copy_bytes(bytes)?),
        None => None,
    };
    Some(GeneratedDecoderSeed {
        archive,
        expected,
        password,
        packed_ranges,
        pack_size_offsets,
        property_length_offsets,
        property_byte_offsets,
        binding_offsets,
        unpack_size_offsets,
        folder_crc_offset,
    })
}

fn source_bytes(data: &[u8]) -> &[u8] {
    let source = match data.get(2..) {
        Some(source) => source,
        None => &[],
    };
    match source.get(..source.len().min(GENERATED_PAYLOAD_LIMIT)) {
        Some(bounded) => bounded,
        None => &[],
    }
}

fn lzma2_uncompressed(source: &[u8]) -> Option<Vec<u8>> {
    let chunk_count = source.len().div_ceil(65_536);
    let capacity = source
        .len()
        .checked_add(chunk_count.checked_mul(3)?)?
        .checked_add(1)?;
    let mut packed = Vec::new();
    packed.try_reserve_exact(capacity).ok()?;
    for (index, chunk) in source.chunks(65_536).enumerate() {
        packed.push(if index == 0 { 1 } else { 2 });
        let encoded_length = u16::try_from(chunk.len().checked_sub(1)?).ok()?;
        packed.extend_from_slice(&encoded_length.to_be_bytes());
        packed.extend_from_slice(chunk);
    }
    packed.push(0);
    Some(packed)
}

fn deflate_stored(source: &[u8]) -> Option<Vec<u8>> {
    let chunk_count = source.len().div_ceil(65_535).max(1);
    let capacity = source.len().checked_add(chunk_count.checked_mul(5)?)?;
    let mut packed = Vec::new();
    packed.try_reserve_exact(capacity).ok()?;
    if source.is_empty() {
        packed.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        return Some(packed);
    }
    let chunks = source.chunks(65_535);
    let last_index = chunks.len().checked_sub(1)?;
    for (index, chunk) in chunks.enumerate() {
        packed.push(u8::from(index == last_index));
        let length = u16::try_from(chunk.len()).ok()?;
        packed.extend_from_slice(&length.to_le_bytes());
        packed.extend_from_slice(&(!length).to_le_bytes());
        packed.extend_from_slice(chunk);
    }
    Some(packed)
}

fn lz4_uncompressed(source: &[u8]) -> Option<Vec<u8>> {
    let capacity = 15_usize.checked_add(source.len())?;
    let mut packed = Vec::new();
    packed.try_reserve_exact(capacity).ok()?;
    // LZ4 frame v1, independent 64 KiB blocks, no optional fields. The header
    // checksum 0x82 is fixed for FLG=0x60 and BD=0x40.
    packed.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82]);
    let block_size = u32::try_from(source.len()).ok()? | 0x8000_0000;
    packed.extend_from_slice(&block_size.to_le_bytes());
    packed.extend_from_slice(source);
    packed.extend_from_slice(&0_u32.to_le_bytes());
    Some(packed)
}

fn zstd_uncompressed(source: &[u8]) -> Option<Vec<u8>> {
    let content_size = u8::try_from(source.len()).ok()?;
    let capacity = 9_usize.checked_add(source.len())?;
    let mut packed = Vec::new();
    packed.try_reserve_exact(capacity).ok()?;
    // Single-segment frame with a one-byte content size and one final raw
    // block. The block header is a 24-bit little-endian bit field.
    packed.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, content_size]);
    let block_size = u32::try_from(source.len()).ok()?;
    let block_header = block_size.checked_shl(3)?.checked_add(1)?;
    let block_bytes = block_header.to_le_bytes();
    packed.extend_from_slice(block_bytes.get(..3)?);
    packed.extend_from_slice(source);
    Some(packed)
}

fn aes_direct(source: &[u8]) -> Option<Vec<u8>> {
    let padded_length = source.len().max(1).checked_add(15)? & !15;
    let mut encrypted = Vec::new();
    encrypted.try_reserve_exact(padded_length).ok()?;
    encrypted.resize(padded_length, 0);
    encrypted.get_mut(..source.len())?.copy_from_slice(source);

    let mut key = [0_u8; 32];
    let mut key_cursor = 0_usize;
    for unit in FUZZ_PASSWORD.encode_utf16() {
        let end = key_cursor.checked_add(2)?;
        let destination = key.get_mut(key_cursor..end)?;
        destination.copy_from_slice(&unit.to_le_bytes());
        key_cursor = end;
    }
    let iv = [0_u8; 16];
    let mut encryptor = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv).ok()?;
    for chunk in encrypted.chunks_exact_mut(16) {
        let block: &mut Block<cbc::Encryptor<Aes256>> = chunk.try_into().ok()?;
        encryptor.encrypt_block(block);
    }
    Some(encrypted)
}

fn simple_seed(
    packed: Vec<u8>,
    method: &[u8],
    properties: Option<&[u8]>,
    expected: &[u8],
) -> Option<GeneratedDecoderSeed> {
    let size = u64::try_from(expected.len()).ok()?;
    build_decoder_seed(
        &[packed],
        &[SeedCoder::simple(method, properties)],
        &[],
        &[0],
        &[size],
        Some(crc32(expected)),
        Some(expected),
        None,
    )
}

fn linear_seed(
    packed: Vec<u8>,
    source: &[u8],
    first: SeedCoder<'_>,
    second: SeedCoder<'_>,
) -> Option<GeneratedDecoderSeed> {
    let size = u64::try_from(source.len()).ok()?;
    build_decoder_seed(
        &[packed],
        &[first, second],
        &[(1, 0)],
        &[0],
        &[size, size],
        None,
        None,
        None,
    )
}

fn reverse_copy_seed(source: &[u8]) -> Option<GeneratedDecoderSeed> {
    let size = u64::try_from(source.len()).ok()?;
    build_decoder_seed(
        &[copy_bytes(source)?],
        &[
            SeedCoder::simple(METHOD_COPY, None),
            SeedCoder::simple(METHOD_COPY, None),
        ],
        &[(0, 1)],
        &[1],
        &[size, size],
        Some(crc32(source)),
        Some(source),
        None,
    )
}

fn bcj2_seed(source: &[u8]) -> Option<GeneratedDecoderSeed> {
    let mut main = Vec::new();
    main.try_reserve_exact(source.len()).ok()?;
    main.extend(source.iter().map(|byte| byte & 0x7f));
    let expected = copy_bytes(&main)?;
    let size = u64::try_from(main.len()).ok()?;
    build_decoder_seed(
        &[main, Vec::new(), Vec::new(), vec![0; 5]],
        &[SeedCoder {
            method: METHOD_BCJ2,
            properties: None,
            inputs: 4,
            outputs: 1,
        }],
        &[],
        &[0, 1, 2, 3],
        &[size],
        Some(crc32(&expected)),
        Some(&expected),
        None,
    )
}

fn encrypted_seed(source: &[u8]) -> Option<GeneratedDecoderSeed> {
    let size = u64::try_from(source.len()).ok()?;
    build_decoder_seed(
        &[aes_direct(source)?],
        &[SeedCoder::simple(METHOD_AES, Some(&[0x3f, 0]))],
        &[],
        &[0],
        &[size],
        Some(crc32(source)),
        Some(source),
        Some(FUZZ_PASSWORD),
    )
}

/// Generates one of the matrix-derived positive decoder/graph seeds without
/// invoking an external tool or retaining a complete binary archive.
pub(crate) fn generated_decoder_seed(data: &[u8]) -> Option<GeneratedDecoderSeed> {
    let selector = data.first().copied().map_or(0, |value| value % 21);
    let source = source_bytes(data);
    match selector {
        0 => simple_seed(copy_bytes(source)?, METHOD_COPY, None, source),
        1 => simple_seed(
            copy_bytes(LZMA_ABC)?,
            METHOD_LZMA,
            Some(LZMA_ABC_PROPERTIES),
            b"abc",
        ),
        2 => simple_seed(
            lzma2_uncompressed(source)?,
            METHOD_LZMA2,
            Some(&[0x08]),
            source,
        ),
        3 => simple_seed(
            lzma2_uncompressed(source)?,
            METHOD_LZMA2,
            Some(&[0x10]),
            source,
        ),
        4 => simple_seed(
            lzma2_uncompressed(source)?,
            METHOD_LZMA2,
            Some(&[0x14]),
            source,
        ),
        5 => simple_seed(deflate_stored(source)?, METHOD_DEFLATE, None, source),
        6 => simple_seed(deflate_stored(source)?, METHOD_DEFLATE64, None, source),
        7 => simple_seed(copy_bytes(BZIP2_HELLO)?, METHOD_BZIP2, None, HELLO),
        8 => simple_seed(copy_bytes(BROTLI_HELLO)?, METHOD_BROTLI, None, HELLO),
        9 => simple_seed(lz4_uncompressed(source)?, METHOD_LZ4, None, source),
        10 => simple_seed(zstd_uncompressed(source)?, METHOD_ZSTD, None, source),
        11 => encrypted_seed(source),
        12 => reverse_copy_seed(source),
        13 => bcj2_seed(source),
        14 => linear_seed(
            lzma2_uncompressed(source)?,
            source,
            SeedCoder::simple(METHOD_LZMA2, Some(&[0x10])),
            SeedCoder::simple(METHOD_BCJ, None),
        ),
        15 => linear_seed(
            lzma2_uncompressed(source)?,
            source,
            SeedCoder::simple(METHOD_LZMA2, Some(&[0x10])),
            SeedCoder::simple(METHOD_PPC, None),
        ),
        16 => linear_seed(
            copy_bytes(source)?,
            source,
            SeedCoder::simple(METHOD_COPY, None),
            SeedCoder::simple(METHOD_DELTA, Some(&[0x00])),
        ),
        17 => linear_seed(
            copy_bytes(source)?,
            source,
            SeedCoder::simple(METHOD_COPY, None),
            SeedCoder::simple(METHOD_DELTA, Some(&[0x03])),
        ),
        18 => linear_seed(
            copy_bytes(source)?,
            source,
            SeedCoder::simple(METHOD_COPY, None),
            SeedCoder::simple(METHOD_DELTA, Some(&[0xff])),
        ),
        19 => simple_seed(
            copy_bytes(PPMD_SEED)?,
            METHOD_PPMD,
            Some(PPMD_SEED_PROPERTIES),
            PPMD_SEED_OUTPUT,
        ),
        _ => simple_seed(
            copy_bytes(PPMD_SEED)?,
            METHOD_PPMD,
            Some(PPMD_PY7ZR_SEED_PROPERTIES),
            PPMD_SEED_OUTPUT,
        ),
    }
}
