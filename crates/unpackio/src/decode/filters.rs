//! Safe in-memory core filters used by 7z coder graphs.
//!
//! Delta, branch conversion, and BCJ2 semantics are adapted from the pinned
//! BSD-3-Clause Go reference at commit
//! `dcfc72a0ee9f527c55521f44ffdf1c31b732e256`. Bounds and arithmetic are
//! expressed independently with checked Rust operations.

use std::io;

use crate::{
    Error, LimitKind, Result,
    decode::{METHOD_ARM, METHOD_ARM64, METHOD_BCJ, METHOD_DELTA, METHOD_PPC, METHOD_SPARC},
    parse_util::{ParseControl, check_limit, format_error, try_reserve, usize_to_u64},
};

use super::phase5_filters::decode_phase5_filter;

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("filter word range overflows"))?;
    let word = bytes
        .get(offset..end)
        .ok_or_else(|| format_error("filter word is truncated"))?;
    let word =
        <[u8; 4]>::try_from(word).map_err(|_| format_error("filter word has the wrong length"))?;
    Ok(u32::from_le_bytes(word))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("filter word range overflows"))?;
    let word = bytes
        .get(offset..end)
        .ok_or_else(|| format_error("filter word is truncated"))?;
    let word =
        <[u8; 4]>::try_from(word).map_err(|_| format_error("filter word has the wrong length"))?;
    Ok(u32::from_be_bytes(word))
}

fn write_word(bytes: &mut [u8], offset: usize, word: [u8; 4]) -> Result<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("filter word range overflows"))?;
    bytes
        .get_mut(offset..end)
        .ok_or_else(|| format_error("filter word is truncated"))?
        .copy_from_slice(&word);
    Ok(())
}

fn starting_position(properties: &[u8]) -> Result<u32> {
    match properties {
        [] => Ok(0),
        bytes => {
            let bytes = <[u8; 4]>::try_from(bytes).map_err(|_| {
                format_error("branch filter properties must be empty or four bytes")
            })?;
            Ok(u32::from_le_bytes(bytes))
        }
    }
}

fn decode_delta(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let property = *properties
        .first()
        .ok_or_else(|| format_error("Delta properties must contain exactly one byte"))?;
    if properties.len() != 1 {
        return Err(format_error(
            "Delta properties must contain exactly one byte",
        ));
    }
    let distance = usize::from(property)
        .checked_add(1)
        .ok_or_else(|| format_error("Delta distance overflows"))?;
    let mut history = [0_u8; 256];
    let mut position = 0_u8;
    for byte in bytes {
        control.checkpoint(1)?;
        let history_index = distance
            .checked_add(usize::from(position))
            .ok_or_else(|| format_error("Delta history index overflows"))?
            & 255;
        let previous = history
            .get(history_index)
            .copied()
            .ok_or_else(|| format_error("Delta history index is out of range"))?;
        *byte = byte.wrapping_add(previous);
        let destination = history
            .get_mut(usize::from(position) & 255)
            .ok_or_else(|| format_error("Delta history destination is out of range"))?;
        *destination = *byte;
        position = position.wrapping_sub(1);
    }
    Ok(())
}

fn test_x86_msb(byte: u8) -> bool {
    byte.wrapping_add(1) & 0xfe == 0
}

#[allow(clippy::too_many_lines)]
fn decode_x86_bcj(
    bytes: &mut [u8],
    properties: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    const LOOK_AHEAD: usize = 4;
    const INSTRUCTION_SIZE: u32 = 5;
    let minimum = LOOK_AHEAD
        .checked_add(1)
        .ok_or_else(|| format_error("BCJ minimum input size overflows"))?;
    if bytes.len() < minimum {
        return Ok(());
    }
    let scan_end = bytes
        .len()
        .checked_sub(LOOK_AHEAD)
        .ok_or_else(|| format_error("BCJ scan bound underflows"))?;
    let mut instruction_pointer = starting_position(properties)?;
    let mut position = 0_usize;
    let mut mask = 0_u32;
    loop {
        let previous = position;
        while position < scan_end {
            control.checkpoint(1)?;
            let byte = bytes
                .get(position)
                .copied()
                .ok_or_else(|| format_error("BCJ opcode index is out of range"))?;
            if byte & 0xfe == 0xe8 {
                break;
            }
            position = position
                .checked_add(1)
                .ok_or_else(|| format_error("BCJ position overflows"))?;
        }
        let distance = position
            .checked_sub(previous)
            .ok_or_else(|| format_error("BCJ scan distance underflows"))?;
        if position >= scan_end {
            mask = if distance > 2 {
                0
            } else {
                mask >> u32::try_from(distance)
                    .map_err(|_| format_error("BCJ mask shift is not representable"))?
            };
            let advanced = u32::try_from(position)
                .map_err(|_| format_error("BCJ position exceeds the 32-bit address domain"))?;
            instruction_pointer = instruction_pointer.wrapping_add(advanced);
            let _ = mask;
            let _ = instruction_pointer;
            return Ok(());
        }
        if distance > 2 {
            mask = 0;
        } else {
            mask >>= u32::try_from(distance)
                .map_err(|_| format_error("BCJ mask shift is not representable"))?;
            if mask != 0 {
                let look = usize::try_from(mask >> 1)
                    .map_err(|_| format_error("BCJ mask index is not representable"))?;
                let look = position
                    .checked_add(look)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| format_error("BCJ mask index overflows"))?;
                let tested = bytes
                    .get(look)
                    .copied()
                    .ok_or_else(|| format_error("BCJ mask index is out of range"))?;
                if mask > 4 || mask == 3 || test_x86_msb(tested) {
                    mask = (mask >> 1) | 4;
                    position = position
                        .checked_add(1)
                        .ok_or_else(|| format_error("BCJ position overflows"))?;
                    continue;
                }
            }
        }
        let high_index = position
            .checked_add(4)
            .ok_or_else(|| format_error("BCJ high-byte index overflows"))?;
        let high = bytes
            .get(high_index)
            .copied()
            .ok_or_else(|| format_error("BCJ high-byte index is out of range"))?;
        if test_x86_msb(high) {
            let value_index = position
                .checked_add(1)
                .ok_or_else(|| format_error("BCJ value index overflows"))?;
            let mut value = read_u32_le(bytes, value_index)?;
            let position32 = u32::try_from(position)
                .map_err(|_| format_error("BCJ position exceeds the 32-bit address domain"))?;
            let current = instruction_pointer
                .wrapping_add(INSTRUCTION_SIZE)
                .wrapping_add(position32);
            position = position
                .checked_add(
                    usize::try_from(INSTRUCTION_SIZE)
                        .map_err(|_| format_error("BCJ instruction size is not representable"))?,
                )
                .ok_or_else(|| format_error("BCJ position overflows"))?;
            value = value.wrapping_sub(current);
            if mask != 0 {
                let shift = (mask & 6) << 2;
                let tested = u8::try_from((value >> shift) & 0xff)
                    .map_err(|_| format_error("BCJ test byte is not representable"))?;
                if test_x86_msb(tested) {
                    value ^= (0x100_u32 << shift).wrapping_sub(1);
                    value = value.wrapping_sub(current);
                }
                mask = 0;
            }
            write_word(bytes, value_index, value.to_le_bytes())?;
            let high = bytes
                .get_mut(high_index)
                .ok_or_else(|| format_error("BCJ high-byte index is out of range"))?;
            *high = 0_u8.wrapping_sub(*high & 1);
        } else {
            mask = (mask >> 1) | 4;
            position = position
                .checked_add(1)
                .ok_or_else(|| format_error("BCJ position overflows"))?;
        }
    }
}

fn decode_ppc(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let mut instruction_pointer = starting_position(properties)?;
    let mut offset = 0_usize;
    while offset.checked_add(4).is_some_and(|end| end <= bytes.len()) {
        control.checkpoint(4)?;
        let first = bytes
            .get(offset)
            .copied()
            .ok_or_else(|| format_error("PPC opcode is truncated"))?;
        let fourth = bytes
            .get(
                offset
                    .checked_add(3)
                    .ok_or_else(|| format_error("PPC index overflows"))?,
            )
            .copied()
            .ok_or_else(|| format_error("PPC opcode is truncated"))?;
        let mut value = read_u32_be(bytes, offset)?;
        if first & 0xfc == 0x48 && fourth & 3 == 1 {
            value = value.wrapping_sub(instruction_pointer);
            value &= 0x03ff_ffff;
            value |= 0x4800_0000;
            write_word(bytes, offset, value.to_be_bytes())?;
        }
        offset = offset
            .checked_add(4)
            .ok_or_else(|| format_error("PPC position overflows"))?;
        instruction_pointer = instruction_pointer.wrapping_add(4);
    }
    Ok(())
}

fn decode_arm(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let mut instruction_pointer = starting_position(properties)?.wrapping_add(4);
    let mut offset = 0_usize;
    while offset.checked_add(4).is_some_and(|end| end <= bytes.len()) {
        control.checkpoint(4)?;
        instruction_pointer = instruction_pointer.wrapping_add(4);
        let opcode = bytes
            .get(
                offset
                    .checked_add(3)
                    .ok_or_else(|| format_error("ARM index overflows"))?,
            )
            .copied()
            .ok_or_else(|| format_error("ARM opcode is truncated"))?;
        if opcode == 0xeb {
            let mut value = read_u32_le(bytes, offset)?;
            value = value.wrapping_sub(instruction_pointer >> 2);
            value &= 0x00ff_ffff;
            value |= 0xeb00_0000;
            write_word(bytes, offset, value.to_le_bytes())?;
        }
        offset = offset
            .checked_add(4)
            .ok_or_else(|| format_error("ARM position overflows"))?;
    }
    Ok(())
}

fn decode_arm64(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let mut instruction_pointer = starting_position(properties)?;
    let mut offset = 0_usize;
    while offset.checked_add(4).is_some_and(|end| end <= bytes.len()) {
        control.checkpoint(4)?;
        let original = read_u32_le(bytes, offset)?;
        if original.wrapping_sub(0x9400_0000) & 0xfc00_0000 == 0 {
            let mut value = original.wrapping_sub(instruction_pointer >> 2);
            value &= 0x03ff_ffff;
            value |= 0x9400_0000;
            write_word(bytes, offset, value.to_le_bytes())?;
        } else {
            let mut value = original.wrapping_sub(0x9000_0000);
            if value & 0x9f00_0000 == 0 {
                const FLAG: u32 = 1 << 20;
                const MASK: u32 = (1 << 24) - (FLAG << 1);
                value = value.wrapping_add(FLAG);
                if value & MASK == 0 {
                    let mut transformed = (value & 0xffff_ffe0) | (value >> 26);
                    let ip = (instruction_pointer >> 9) & !7;
                    transformed = transformed.wrapping_sub(ip);
                    value &= 0x1f;
                    value |= 0x9000_0000;
                    value |= transformed << 26;
                    value |= 0x00ff_ffe0 & ((transformed & ((FLAG << 1) - 1)).wrapping_sub(FLAG));
                    write_word(bytes, offset, value.to_le_bytes())?;
                }
            }
        }
        offset = offset
            .checked_add(4)
            .ok_or_else(|| format_error("ARM64 position overflows"))?;
        instruction_pointer = instruction_pointer.wrapping_add(4);
    }
    Ok(())
}

fn decode_sparc(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let mut instruction_pointer = starting_position(properties)?;
    let mut offset = 0_usize;
    while offset.checked_add(4).is_some_and(|end| end <= bytes.len()) {
        control.checkpoint(4)?;
        let first = bytes
            .get(offset)
            .copied()
            .ok_or_else(|| format_error("SPARC opcode is truncated"))?;
        let second = bytes
            .get(
                offset
                    .checked_add(1)
                    .ok_or_else(|| format_error("SPARC index overflows"))?,
            )
            .copied()
            .ok_or_else(|| format_error("SPARC opcode is truncated"))?;
        if (first == 0x40 && second & 0xc0 == 0) || (first == 0x7f && second >= 0xc0) {
            let mut value = read_u32_be(bytes, offset)?.wrapping_shl(2);
            value = value.wrapping_sub(instruction_pointer);
            value &= 0x01ff_ffff;
            value = value.wrapping_sub(1 << 24);
            value ^= 0xff00_0000;
            value >>= 2;
            value |= 0x4000_0000;
            write_word(bytes, offset, value.to_be_bytes())?;
        }
        offset = offset
            .checked_add(4)
            .ok_or_else(|| format_error("SPARC position overflows"))?;
        instruction_pointer = instruction_pointer.wrapping_add(4);
    }
    Ok(())
}

pub(crate) fn decode_filter(
    method: &[u8],
    properties: &[u8],
    mut bytes: Vec<u8>,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    if method == METHOD_DELTA {
        decode_delta(&mut bytes, properties, control)?;
    } else if method == METHOD_BCJ {
        decode_x86_bcj(&mut bytes, properties, control)?;
    } else if method == METHOD_PPC {
        decode_ppc(&mut bytes, properties, control)?;
    } else if method == METHOD_ARM {
        decode_arm(&mut bytes, properties, control)?;
    } else if method == METHOD_ARM64 {
        decode_arm64(&mut bytes, properties, control)?;
    } else if method == METHOD_SPARC {
        decode_sparc(&mut bytes, properties, control)?;
    } else {
        decode_phase5_filter(method, properties, &mut bytes, control)?;
    }
    Ok(bytes)
}

struct Bcj2Cursor<'input> {
    bytes: &'input [u8],
    position: usize,
}

impl<'input> Bcj2Cursor<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_byte(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| format_error("truncated BCJ2 input stream"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| format_error("BCJ2 input cursor overflows"))?;
        Ok(byte)
    }

    fn read_u32_be(&mut self, control: &mut ParseControl<'_>) -> Result<u32> {
        let mut word = [0_u8; 4];
        for slot in &mut word {
            *slot = self.read_byte(control)?;
        }
        Ok(u32::from_be_bytes(word))
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

struct Bcj2Range<'input> {
    input: Bcj2Cursor<'input>,
    range: u32,
    code: u32,
    probabilities: [u32; 258],
}

impl<'input> Bcj2Range<'input> {
    fn new(bytes: &'input [u8], control: &mut ParseControl<'_>) -> Result<Self> {
        let mut input = Bcj2Cursor::new(bytes);
        let mut code = 0_u32;
        for _ in 0..5 {
            code = code.wrapping_shl(8) | u32::from(input.read_byte(control)?);
        }
        Ok(Self {
            input,
            range: u32::MAX,
            code,
            probabilities: [1 << 10; 258],
        })
    }

    fn decode(&mut self, index: usize, control: &mut ParseControl<'_>) -> Result<bool> {
        let probability = self
            .probabilities
            .get_mut(index)
            .ok_or_else(|| format_error("BCJ2 probability index is out of range"))?;
        let bound = (self.range >> 11)
            .checked_mul(*probability)
            .ok_or_else(|| format_error("BCJ2 probability bound overflows"))?;
        let selected = if self.code < bound {
            self.range = bound;
            *probability = probability
                .checked_add((2048_u32.saturating_sub(*probability)) >> 5)
                .ok_or_else(|| format_error("BCJ2 probability overflows"))?;
            false
        } else {
            self.range = self
                .range
                .checked_sub(bound)
                .ok_or_else(|| format_error("BCJ2 range underflows"))?;
            self.code = self
                .code
                .checked_sub(bound)
                .ok_or_else(|| format_error("BCJ2 range code underflows"))?;
            *probability = probability
                .checked_sub(*probability >> 5)
                .ok_or_else(|| format_error("BCJ2 probability underflows"))?;
            true
        };
        if self.range < 1 << 24 {
            self.code = self.code.wrapping_shl(8) | u32::from(self.input.read_byte(control)?);
            self.range = self.range.wrapping_shl(8);
        }
        Ok(selected)
    }
}

fn is_bcj2_branch(previous: u8, current: u8) -> bool {
    current & 0xfe == 0xe8 || (previous == 0x0f && current & 0xf0 == 0x80)
}

fn bcj2_probability_index(previous: u8, current: u8) -> usize {
    match current {
        0xe8 => usize::from(previous),
        0xe9 => 256,
        _ => 257,
    }
}

fn reserve_output(output: &mut Vec<u8>, additional: usize, maximum: u64) -> Result<()> {
    let requested = output
        .len()
        .checked_add(additional)
        .ok_or_else(|| format_error("BCJ2 output size overflows"))?;
    check_limit(
        usize_to_u64(requested, "BCJ2 output size is not representable as u64")?,
        maximum,
        LimitKind::TotalOutputBytes,
    )?;
    output.try_reserve(additional).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "BCJ2 output allocation failed",
        ))
    })
}

pub(crate) fn decode_bcj2(
    inputs: &[Vec<u8>],
    properties: &[u8],
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    if !properties.is_empty() {
        return Err(format_error("BCJ2 properties must be empty"));
    }
    let main = inputs
        .first()
        .ok_or_else(|| format_error("BCJ2 main stream is missing"))?;
    let call = inputs
        .get(1)
        .ok_or_else(|| format_error("BCJ2 call stream is missing"))?;
    let jump = inputs
        .get(2)
        .ok_or_else(|| format_error("BCJ2 jump stream is missing"))?;
    let range = inputs
        .get(3)
        .ok_or_else(|| format_error("BCJ2 range stream is missing"))?;
    if inputs.len() != 4 {
        return Err(format_error("BCJ2 requires exactly four input streams"));
    }
    check_limit(expected.unwrap_or(0), maximum, LimitKind::TotalOutputBytes)?;
    let mut output = Vec::new();
    if let Some(expected) = expected {
        let capacity = usize::try_from(expected)
            .map_err(|_| format_error("BCJ2 output size is not representable on this platform"))?;
        try_reserve(&mut output, capacity)?;
    }
    let mut main = Bcj2Cursor::new(main);
    let mut call = Bcj2Cursor::new(call);
    let mut jump = Bcj2Cursor::new(jump);
    let mut range = Bcj2Range::new(range, control)?;
    let mut previous = 0_u8;
    let mut written = 0_u32;
    while !main.is_finished() {
        let byte = main.read_byte(control)?;
        reserve_output(&mut output, 1, maximum)?;
        output.push(byte);
        written = written.wrapping_add(1);
        if !is_bcj2_branch(previous, byte) {
            previous = byte;
            continue;
        }
        let selected = range.decode(bcj2_probability_index(previous, byte), control)?;
        if selected {
            let encoded = if byte == 0xe8 {
                call.read_u32_be(control)?
            } else {
                jump.read_u32_be(control)?
            };
            let destination = encoded.wrapping_sub(written.wrapping_add(4));
            reserve_output(&mut output, 4, maximum)?;
            output.extend_from_slice(&destination.to_le_bytes());
            previous = u8::try_from(destination >> 24)
                .map_err(|_| format_error("BCJ2 previous byte is not representable"))?;
            written = written.wrapping_add(4);
        } else {
            previous = byte;
        }
    }
    if !call.is_finished() || !jump.is_finished() {
        return Err(format_error("BCJ2 side streams were not consumed exactly"));
    }
    if let Some(expected) = expected {
        if usize_to_u64(output.len(), "BCJ2 output size is not representable as u64")? != expected {
            return Err(format_error(
                "BCJ2 output size does not match its declaration",
            ));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{decode_bcj2, decode_delta, decode_ppc, decode_x86_bcj};
    use crate::{CancellationToken, Error, LimitKind, WorkBudget, parse_util::ParseControl};

    #[test]
    fn delta_distance_one_accumulates_bytes() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let mut bytes = [1, 1, 1, 1];
        assert!(decode_delta(&mut bytes, &[0], &mut control).is_ok());
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn ppc_leaves_non_instruction_tail_unchanged() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let mut bytes = [1, 2, 3];
        assert!(decode_ppc(&mut bytes, &[], &mut control).is_ok());
        assert_eq!(bytes, [1, 2, 3]);
    }

    #[test]
    fn bcj2_passthrough_and_range_truncations_are_bounded() {
        let main = vec![b'a', b'b', b'c'];
        let call = Vec::new();
        let jump = Vec::new();
        let range = vec![0; 5];
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let output = decode_bcj2(
            &[main.clone(), call.clone(), jump.clone(), range.clone()],
            &[],
            Some(3),
            3,
            &mut control,
        );
        assert!(output.as_deref().is_ok_and(|bytes| bytes == b"abc"));

        for length in 0..range.len() {
            let truncated = range.get(..length).unwrap_or(&[]).to_vec();
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut control = ParseControl::new(&cancellation, &mut budget);
            assert!(
                decode_bcj2(
                    &[main.clone(), call.clone(), jump.clone(), truncated],
                    &[],
                    Some(3),
                    3,
                    &mut control,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn bcj2_output_limit_is_checked_before_input() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_bcj2(
                &[vec![b'a'], Vec::new(), Vec::new(), vec![0; 5]],
                &[],
                Some(1),
                0,
                &mut control,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 1,
                maximum: 0
            })
        ));
        assert_eq!(budget.remaining(), Some(0));
    }

    #[test]
    fn delta_observes_cancellation_in_its_loop() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_delta(&mut [1, 2, 3], &[0], &mut control),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn x86_scan_charges_branch_free_input() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(3);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_x86_bcj(&mut [0; 32], &[], &mut control),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
    }
}
