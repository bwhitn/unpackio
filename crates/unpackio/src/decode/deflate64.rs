//! Safe, bounded Deflate64 decoding.
//!
//! The block grammar, canonical Huffman construction, 64 KiB history, and
//! Deflate64 length/distance tables are adapted from Apache Commons Compress
//! `HuffmanDecoder.java` at commit
//! `9499ba8ed3c6dce1275ac3d0471afa414b23daff` (Apache-2.0). The Rust decoder
//! is independently structured around checked slice access, fallible output
//! growth, exact input consumption, and explicit operation control.

use std::io;

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, format_error, u64_to_usize, usize_to_u64},
};

const DEFLATE64_DICTIONARY_BYTES: u64 = 64 * 1024;
const MAX_CODE_BITS: usize = 15;
const MAX_HUFFMAN_SYMBOLS: usize = 320;
const OUTPUT_GROWTH_CHUNK: u64 = 4096;

const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

const LENGTH_BASE: [u32; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
];
const DISTANCE_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
const DISTANCE_EXTRA: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

struct BitReader<'input> {
    input: &'input [u8],
    position: usize,
    buffer: u64,
    buffered_bits: u32,
}

impl<'input> BitReader<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self {
            input,
            position: 0,
            buffer: 0,
            buffered_bits: 0,
        }
    }

    fn read_byte(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| format_error("truncated Deflate64 bitstream"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| format_error("Deflate64 input position overflows"))?;
        Ok(byte)
    }

    fn read_bits(&mut self, count: u32, control: &mut ParseControl<'_>) -> Result<u32> {
        if count > 24 {
            return Err(format_error("Deflate64 bit request is too large"));
        }
        while self.buffered_bits < count {
            let byte = self.read_byte(control)?;
            let shifted = u64::from(byte)
                .checked_shl(self.buffered_bits)
                .ok_or_else(|| format_error("Deflate64 bit buffer shift overflows"))?;
            self.buffer |= shifted;
            self.buffered_bits = self
                .buffered_bits
                .checked_add(8)
                .ok_or_else(|| format_error("Deflate64 buffered-bit count overflows"))?;
        }
        let mask = if count == 0 {
            0
        } else {
            1_u64
                .checked_shl(count)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| format_error("Deflate64 bit mask overflows"))?
        };
        let value = u32::try_from(self.buffer & mask)
            .map_err(|_| format_error("Deflate64 bit value is not representable"))?;
        self.buffer >>= count;
        self.buffered_bits = self
            .buffered_bits
            .checked_sub(count)
            .ok_or_else(|| format_error("Deflate64 buffered-bit count underflows"))?;
        Ok(value)
    }

    fn align_to_byte(&mut self) {
        self.buffer = 0;
        self.buffered_bits = 0;
    }

    fn has_trailing_bytes(&self) -> bool {
        self.position != self.input.len()
    }
}

struct Huffman {
    counts: [u16; MAX_CODE_BITS + 1],
    symbols: [u16; MAX_HUFFMAN_SYMBOLS],
    symbol_count: usize,
}

impl Huffman {
    fn from_lengths(lengths: &[u8], allow_empty: bool) -> Result<Self> {
        if lengths.len() > MAX_HUFFMAN_SYMBOLS {
            return Err(format_error("Deflate64 Huffman alphabet is too large"));
        }
        let mut counts = [0_u16; MAX_CODE_BITS + 1];
        for length in lengths {
            let length = usize::from(*length);
            if length > MAX_CODE_BITS {
                return Err(format_error("Deflate64 Huffman code is too long"));
            }
            if length != 0 {
                let count = counts
                    .get_mut(length)
                    .ok_or_else(|| format_error("Deflate64 Huffman length is out of range"))?;
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| format_error("Deflate64 Huffman count overflows"))?;
            }
        }
        let symbol_count = counts.iter().skip(1).try_fold(0_usize, |total, count| {
            total
                .checked_add(usize::from(*count))
                .ok_or_else(|| format_error("Deflate64 Huffman symbol count overflows"))
        })?;
        if symbol_count == 0 && !allow_empty {
            return Err(format_error("Deflate64 Huffman tree is empty"));
        }

        let mut available = 1_i32;
        for count in counts.iter().skip(1) {
            available = available
                .checked_mul(2)
                .and_then(|value| value.checked_sub(i32::from(*count)))
                .ok_or_else(|| format_error("Deflate64 Huffman validation overflows"))?;
            if available < 0 {
                return Err(format_error("Deflate64 Huffman tree is oversubscribed"));
            }
        }

        let mut offsets = [0_usize; MAX_CODE_BITS + 1];
        let mut running = 0_usize;
        for length in 1..=MAX_CODE_BITS {
            let offset = offsets
                .get_mut(length)
                .ok_or_else(|| format_error("Deflate64 Huffman offset is out of range"))?;
            *offset = running;
            running = running
                .checked_add(usize::from(*counts.get(length).ok_or_else(|| {
                    format_error("Deflate64 Huffman count is out of range")
                })?))
                .ok_or_else(|| format_error("Deflate64 Huffman offset overflows"))?;
        }

        let mut symbols = [0_u16; MAX_HUFFMAN_SYMBOLS];
        for (symbol, length) in lengths.iter().copied().enumerate() {
            let length = usize::from(length);
            if length == 0 {
                continue;
            }
            let destination = offsets
                .get_mut(length)
                .ok_or_else(|| format_error("Deflate64 Huffman offset is out of range"))?;
            let slot = symbols
                .get_mut(*destination)
                .ok_or_else(|| format_error("Deflate64 Huffman symbol index is out of range"))?;
            *slot = u16::try_from(symbol)
                .map_err(|_| format_error("Deflate64 Huffman symbol is not representable"))?;
            *destination = destination
                .checked_add(1)
                .ok_or_else(|| format_error("Deflate64 Huffman offset overflows"))?;
        }
        Ok(Self {
            counts,
            symbols,
            symbol_count,
        })
    }

    fn decode(&self, reader: &mut BitReader<'_>, control: &mut ParseControl<'_>) -> Result<u16> {
        let mut code = 0_u32;
        let mut first = 0_u32;
        let mut index = 0_usize;
        for length in 1..=MAX_CODE_BITS {
            code |= reader.read_bits(1, control)?;
            let count = u32::from(
                *self
                    .counts
                    .get(length)
                    .ok_or_else(|| format_error("Deflate64 Huffman count is out of range"))?,
            );
            let end = first
                .checked_add(count)
                .ok_or_else(|| format_error("Deflate64 Huffman code range overflows"))?;
            if code < end {
                let relative = usize::try_from(
                    code.checked_sub(first)
                        .ok_or_else(|| format_error("Deflate64 Huffman code underflows"))?,
                )
                .map_err(|_| format_error("Deflate64 Huffman index is not representable"))?;
                let symbol_index = index
                    .checked_add(relative)
                    .ok_or_else(|| format_error("Deflate64 Huffman index overflows"))?;
                if symbol_index >= self.symbol_count {
                    return Err(format_error("Deflate64 Huffman symbol is out of range"));
                }
                return self
                    .symbols
                    .get(symbol_index)
                    .copied()
                    .ok_or_else(|| format_error("Deflate64 Huffman symbol is missing"));
            }
            index = index
                .checked_add(usize::from(*self.counts.get(length).ok_or_else(|| {
                    format_error("Deflate64 Huffman count is out of range")
                })?))
                .ok_or_else(|| format_error("Deflate64 Huffman index overflows"))?;
            first = end
                .checked_shl(1)
                .ok_or_else(|| format_error("Deflate64 Huffman first code overflows"))?;
            code = code
                .checked_shl(1)
                .ok_or_else(|| format_error("Deflate64 Huffman code overflows"))?;
        }
        Err(format_error("invalid Deflate64 Huffman code"))
    }
}

fn reserve_output(
    output: &mut Vec<u8>,
    additional: u64,
    expected: Option<u64>,
    maximum: u64,
) -> Result<()> {
    let current = usize_to_u64(
        output.len(),
        "Deflate64 output size is not representable as u64",
    )?;
    let next = current
        .checked_add(additional)
        .ok_or_else(|| format_error("Deflate64 output size overflows"))?;
    if expected.is_some_and(|declared| next > declared) {
        return Err(format_error("Deflate64 output exceeds its declared size"));
    }
    check_limit(next, maximum, LimitKind::TotalOutputBytes)?;
    let additional = u64_to_usize(
        additional,
        "Deflate64 output growth is not representable on this platform",
    )?;
    let spare = output
        .capacity()
        .checked_sub(output.len())
        .ok_or_else(|| format_error("Deflate64 output capacity underflows"))?;
    if spare >= additional {
        return Ok(());
    }
    let ceiling = expected.unwrap_or(maximum);
    let remaining = ceiling
        .checked_sub(current)
        .ok_or_else(|| format_error("Deflate64 output allowance underflows"))?;
    let requested = additional.max(u64_to_usize(
        remaining.min(OUTPUT_GROWTH_CHUNK),
        "Deflate64 output reservation is not representable on this platform",
    )?);
    output.try_reserve_exact(requested).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Deflate64 output allocation failed",
        ))
    })
}

fn append_literal(
    output: &mut Vec<u8>,
    byte: u8,
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    reserve_output(output, 1, expected, maximum)?;
    control.checkpoint(1)?;
    output.push(byte);
    Ok(())
}

fn copy_match(
    output: &mut Vec<u8>,
    distance: u32,
    length: u32,
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if distance == 0 || u64::from(distance) > DEFLATE64_DICTIONARY_BYTES {
        return Err(format_error("Deflate64 match distance is invalid"));
    }
    let distance = usize::try_from(distance)
        .map_err(|_| format_error("Deflate64 match distance is not representable"))?;
    if distance > output.len() {
        return Err(format_error("Deflate64 match precedes available history"));
    }
    reserve_output(output, u64::from(length), expected, maximum)?;
    for _ in 0..length {
        control.checkpoint(1)?;
        let source = output
            .len()
            .checked_sub(distance)
            .ok_or_else(|| format_error("Deflate64 history index underflows"))?;
        let byte = output
            .get(source)
            .copied()
            .ok_or_else(|| format_error("Deflate64 history index is out of range"))?;
        output.push(byte);
    }
    Ok(())
}

fn fixed_trees() -> Result<(Huffman, Huffman)> {
    let mut literals = [0_u8; 288];
    for length in literals
        .get_mut(..144)
        .ok_or_else(|| format_error("Deflate64 fixed literal range is invalid"))?
    {
        *length = 8;
    }
    for length in literals
        .get_mut(144..256)
        .ok_or_else(|| format_error("Deflate64 fixed literal range is invalid"))?
    {
        *length = 9;
    }
    for length in literals
        .get_mut(256..280)
        .ok_or_else(|| format_error("Deflate64 fixed literal range is invalid"))?
    {
        *length = 7;
    }
    for length in literals
        .get_mut(280..)
        .ok_or_else(|| format_error("Deflate64 fixed literal range is invalid"))?
    {
        *length = 8;
    }
    let distances = [5_u8; 32];
    Ok((
        Huffman::from_lengths(&literals, false)?,
        Huffman::from_lengths(&distances, false)?,
    ))
}

fn dynamic_trees(
    reader: &mut BitReader<'_>,
    control: &mut ParseControl<'_>,
) -> Result<(Huffman, Huffman)> {
    let literal_count = usize::try_from(reader.read_bits(5, control)?)
        .map_err(|_| format_error("Deflate64 literal count is not representable"))?
        .checked_add(257)
        .ok_or_else(|| format_error("Deflate64 literal count overflows"))?;
    let distance_count = usize::try_from(reader.read_bits(5, control)?)
        .map_err(|_| format_error("Deflate64 distance count is not representable"))?
        .checked_add(1)
        .ok_or_else(|| format_error("Deflate64 distance count overflows"))?;
    let code_length_count = usize::try_from(reader.read_bits(4, control)?)
        .map_err(|_| format_error("Deflate64 code-length count is not representable"))?
        .checked_add(4)
        .ok_or_else(|| format_error("Deflate64 code-length count overflows"))?;
    if literal_count > 286 || distance_count > 32 || code_length_count > 19 {
        return Err(format_error("Deflate64 dynamic table count is invalid"));
    }

    let mut code_lengths = [0_u8; 19];
    for ordinal in 0..code_length_count {
        let destination = *CODE_LENGTH_ORDER
            .get(ordinal)
            .ok_or_else(|| format_error("Deflate64 code-length order is out of range"))?;
        let length = u8::try_from(reader.read_bits(3, control)?)
            .map_err(|_| format_error("Deflate64 code length is not representable"))?;
        let slot = code_lengths
            .get_mut(destination)
            .ok_or_else(|| format_error("Deflate64 code-length index is out of range"))?;
        *slot = length;
    }
    let code_tree = Huffman::from_lengths(&code_lengths, false)?;
    let total = literal_count
        .checked_add(distance_count)
        .ok_or_else(|| format_error("Deflate64 dynamic alphabet size overflows"))?;
    let mut lengths = [0_u8; 318];
    let mut position = 0_usize;
    while position < total {
        let symbol = code_tree.decode(reader, control)?;
        match symbol {
            0..=15 => {
                let slot = lengths
                    .get_mut(position)
                    .ok_or_else(|| format_error("Deflate64 dynamic length is out of range"))?;
                *slot = u8::try_from(symbol)
                    .map_err(|_| format_error("Deflate64 code length is not representable"))?;
                position = position
                    .checked_add(1)
                    .ok_or_else(|| format_error("Deflate64 dynamic length index overflows"))?;
            }
            16 => {
                let previous_index = position
                    .checked_sub(1)
                    .ok_or_else(|| format_error("Deflate64 repeat has no previous length"))?;
                let previous = lengths
                    .get(previous_index)
                    .copied()
                    .ok_or_else(|| format_error("Deflate64 previous length is out of range"))?;
                let repeat = usize::try_from(reader.read_bits(2, control)?)
                    .map_err(|_| format_error("Deflate64 repeat count is not representable"))?
                    .checked_add(3)
                    .ok_or_else(|| format_error("Deflate64 repeat count overflows"))?;
                let end = position
                    .checked_add(repeat)
                    .ok_or_else(|| format_error("Deflate64 repeat range overflows"))?;
                if end > total {
                    return Err(format_error("Deflate64 repeat exceeds its table"));
                }
                for slot in lengths
                    .get_mut(position..end)
                    .ok_or_else(|| format_error("Deflate64 repeat range is out of bounds"))?
                {
                    *slot = previous;
                }
                position = end;
            }
            17 | 18 => {
                let (bits, base) = if symbol == 17 { (3, 3) } else { (7, 11) };
                let repeat = usize::try_from(reader.read_bits(bits, control)?)
                    .map_err(|_| format_error("Deflate64 zero repeat is not representable"))?
                    .checked_add(base)
                    .ok_or_else(|| format_error("Deflate64 zero repeat overflows"))?;
                let end = position
                    .checked_add(repeat)
                    .ok_or_else(|| format_error("Deflate64 zero-repeat range overflows"))?;
                if end > total {
                    return Err(format_error("Deflate64 zero repeat exceeds its table"));
                }
                position = end;
            }
            _ => return Err(format_error("invalid Deflate64 code-length symbol")),
        }
    }

    if lengths.get(256).copied().unwrap_or(0) == 0 {
        return Err(format_error(
            "Deflate64 literal tree has no end-of-block code",
        ));
    }
    let literals = lengths
        .get(..literal_count)
        .ok_or_else(|| format_error("Deflate64 literal table is out of range"))?;
    let distances = lengths
        .get(literal_count..total)
        .ok_or_else(|| format_error("Deflate64 distance table is out of range"))?;
    Ok((
        Huffman::from_lengths(literals, false)?,
        // RFC 1951 permits a single zero-length distance declaration when a
        // dynamic block contains literals only. Any later match will fail at
        // `decode` because the tree has no symbols.
        Huffman::from_lengths(distances, true)?,
    ))
}

fn decode_compressed_block(
    reader: &mut BitReader<'_>,
    literal_tree: &Huffman,
    distance_tree: &Huffman,
    output: &mut Vec<u8>,
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    loop {
        control.checkpoint(1)?;
        let symbol = literal_tree.decode(reader, control)?;
        match symbol {
            0..=255 => append_literal(
                output,
                u8::try_from(symbol)
                    .map_err(|_| format_error("Deflate64 literal is not representable"))?,
                expected,
                maximum,
                control,
            )?,
            256 => return Ok(()),
            257..=285 => {
                let length_index = usize::from(
                    symbol
                        .checked_sub(257)
                        .ok_or_else(|| format_error("Deflate64 length index underflows"))?,
                );
                let length_base = *LENGTH_BASE
                    .get(length_index)
                    .ok_or_else(|| format_error("Deflate64 length code is out of range"))?;
                let length_extra = *LENGTH_EXTRA
                    .get(length_index)
                    .ok_or_else(|| format_error("Deflate64 length code is out of range"))?;
                let length = length_base
                    .checked_add(reader.read_bits(u32::from(length_extra), control)?)
                    .ok_or_else(|| format_error("Deflate64 match length overflows"))?;
                let distance_symbol = usize::from(distance_tree.decode(reader, control)?);
                let distance_base = *DISTANCE_BASE
                    .get(distance_symbol)
                    .ok_or_else(|| format_error("Deflate64 distance code is out of range"))?;
                let distance_extra = *DISTANCE_EXTRA
                    .get(distance_symbol)
                    .ok_or_else(|| format_error("Deflate64 distance code is out of range"))?;
                let distance = distance_base
                    .checked_add(reader.read_bits(u32::from(distance_extra), control)?)
                    .ok_or_else(|| format_error("Deflate64 match distance overflows"))?;
                copy_match(output, distance, length, expected, maximum, control)?;
            }
            _ => return Err(format_error("reserved Deflate64 literal/length code")),
        }
    }
}

fn decode_stored_block(
    reader: &mut BitReader<'_>,
    output: &mut Vec<u8>,
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    reader.align_to_byte();
    let length = reader.read_bits(16, control)?;
    let complement = reader.read_bits(16, control)?;
    if length ^ 0xffff != complement {
        return Err(format_error("invalid Deflate64 stored-block length"));
    }
    reserve_output(output, u64::from(length), expected, maximum)?;
    for _ in 0..length {
        let byte = u8::try_from(reader.read_bits(8, control)?)
            .map_err(|_| format_error("Deflate64 stored byte is not representable"))?;
        control.checkpoint(1)?;
        output.push(byte);
    }
    Ok(())
}

pub(crate) fn decode_deflate64(
    input: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        DEFLATE64_DICTIONARY_BYTES,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    if let Some(size) = expected {
        check_limit(size, maximum, LimitKind::TotalOutputBytes)?;
    }
    let mut output = Vec::new();
    if let Some(size) = expected {
        let initial = u64_to_usize(
            size.min(1024 * 1024),
            "initial Deflate64 output capacity is not representable",
        )?;
        output.try_reserve_exact(initial).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Deflate64 output allocation failed",
            ))
        })?;
    }
    let mut reader = BitReader::new(input);
    loop {
        control.checkpoint(1)?;
        let final_block = reader.read_bits(1, control)? != 0;
        match reader.read_bits(2, control)? {
            0 => decode_stored_block(&mut reader, &mut output, expected, maximum, control)?,
            1 => {
                let (literal_tree, distance_tree) = fixed_trees()?;
                decode_compressed_block(
                    &mut reader,
                    &literal_tree,
                    &distance_tree,
                    &mut output,
                    expected,
                    maximum,
                    control,
                )?;
            }
            2 => {
                let (literal_tree, distance_tree) = dynamic_trees(&mut reader, control)?;
                decode_compressed_block(
                    &mut reader,
                    &literal_tree,
                    &distance_tree,
                    &mut output,
                    expected,
                    maximum,
                    control,
                )?;
            }
            _ => return Err(format_error("reserved Deflate64 block type")),
        }
        if final_block {
            break;
        }
    }
    if reader.has_trailing_bytes() {
        return Err(format_error("Deflate64 stream has trailing input"));
    }
    let actual = usize_to_u64(
        output.len(),
        "Deflate64 output size is not representable as u64",
    )?;
    if expected.is_some_and(|size| size != actual) {
        return Err(format_error(
            "decoded coder output size does not match its declaration",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{DEFLATE64_DICTIONARY_BYTES, decode_deflate64};
    use crate::{
        CancellationToken, Error, LimitKind, Limits, WorkBudget,
        parse_util::{ParseControl, format_error},
    };

    const STORED_ABC: &[u8] = &[1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'];

    fn decode(
        bytes: &[u8],
        expected: Option<u64>,
        maximum: u64,
        limits: Limits,
    ) -> crate::Result<Vec<u8>> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        decode_deflate64(bytes, expected, maximum, limits, &mut control)
    }

    #[test]
    fn stored_block_supports_declared_and_eos_sizes() {
        assert!(
            decode(STORED_ABC, Some(3), 3, Limits::default())
                .as_deref()
                .is_ok_and(|bytes| bytes == b"abc")
        );
        assert!(
            decode(STORED_ABC, None, 3, Limits::default())
                .as_deref()
                .is_ok_and(|bytes| bytes == b"abc")
        );
    }

    #[test]
    fn dynamic_deflate_block_decodes_as_deflate64() -> crate::Result<()> {
        let mut plaintext = Vec::with_capacity(16 * 1024);
        let mut state = 0x9e37_79b9_u32;
        for _ in 0..16 * 1024 {
            state ^= state.wrapping_shl(13);
            state ^= state >> 17;
            state ^= state.wrapping_shl(5);
            plaintext.push(b'a'.wrapping_add(u8::try_from(state & 0x0f).map_err(|_| {
                format_error("dynamic Deflate64 fixture byte is not representable")
            })?));
        }
        let compressed = miniz_oxide::deflate::compress_to_vec(&plaintext, 6);
        assert!(
            compressed
                .first()
                .is_some_and(|byte| (byte >> 1) & 0x03 == 2),
            "fixture must begin with a dynamic block"
        );
        let size = u64::try_from(plaintext.len())
            .map_err(|_| format_error("dynamic Deflate64 fixture size is not representable"))?;
        let decoded = decode(&compressed, Some(size), size, Limits::default())?;
        assert_eq!(decoded, plaintext);
        Ok(())
    }

    #[test]
    fn every_stored_prefix_is_rejected() {
        for end in 0..STORED_ABC.len() {
            let prefix = STORED_ABC.get(..end).unwrap_or_default();
            assert!(decode(prefix, Some(3), 3, Limits::default()).is_err());
        }
    }

    #[test]
    fn rejects_trailing_input_and_output_overrun() {
        let mut trailing = STORED_ABC.to_vec();
        trailing.push(0);
        assert!(decode(&trailing, Some(3), 3, Limits::default()).is_err());
        assert!(decode(STORED_ABC, Some(2), 2, Limits::default()).is_err());
    }

    #[test]
    fn dictionary_limit_precedes_decode_work() {
        let limits = Limits::builder()
            .max_dictionary_bytes(DEFLATE64_DICTIONARY_BYTES - 1)
            .build();
        assert!(matches!(
            decode(STORED_ABC, Some(3), 3, limits),
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                requested: DEFLATE64_DICTIONARY_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn work_budget_interrupts_the_decode_loop() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_deflate64(STORED_ABC, Some(3), 3, Limits::default(), &mut control),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
    }
}
