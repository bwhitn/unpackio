//! Size-preserving compatibility filters added after Go parity.
//!
//! The instruction layouts and bijective transforms are independently
//! expressed in safe Rust from the 0BSD XZ Utils filter descriptions at
//! commit `f3b5688159c60495f48db3942a36509671dfce89`. This module contains no
//! XZ library code or runtime dependency. Every input-derived range and
//! conversion is checked, while address arithmetic intentionally wraps in the
//! architecture's 32-bit filter domain.

use crate::{
    Error, Result,
    decode::{METHOD_ARM_THUMB, METHOD_IA64, METHOD_RISCV, METHOD_SWAP2, METHOD_SWAP4},
    parse_util::{ParseControl, format_error},
};

const IA64_BRANCH_TABLE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
];

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

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("compatibility filter word range overflows"))?;
    let word = <[u8; 4]>::try_from(
        bytes
            .get(offset..end)
            .ok_or_else(|| format_error("compatibility filter word is truncated"))?,
    )
    .map_err(|_| format_error("compatibility filter word has the wrong length"))?;
    Ok(u32::from_le_bytes(word))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("compatibility filter word range overflows"))?;
    let word = <[u8; 4]>::try_from(
        bytes
            .get(offset..end)
            .ok_or_else(|| format_error("compatibility filter word is truncated"))?,
    )
    .map_err(|_| format_error("compatibility filter word has the wrong length"))?;
    Ok(u32::from_be_bytes(word))
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format_error("compatibility filter word range overflows"))?;
    bytes
        .get_mut(offset..end)
        .ok_or_else(|| format_error("compatibility filter word is truncated"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u48_le(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(6)
        .ok_or_else(|| format_error("IA64 instruction range overflows"))?;
    let instruction = bytes
        .get(offset..end)
        .ok_or_else(|| format_error("IA64 instruction is truncated"))?;
    let mut value = 0_u64;
    for (index, byte) in instruction.iter().copied().enumerate() {
        let shift = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(8))
            .ok_or_else(|| format_error("IA64 instruction shift overflows"))?;
        value |= u64::from(byte)
            .checked_shl(shift)
            .ok_or_else(|| format_error("IA64 instruction value overflows"))?;
    }
    Ok(value)
}

fn write_u48_le(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let end = offset
        .checked_add(6)
        .ok_or_else(|| format_error("IA64 instruction range overflows"))?;
    let instruction = bytes
        .get_mut(offset..end)
        .ok_or_else(|| format_error("IA64 instruction is truncated"))?;
    for (index, byte) in instruction.iter_mut().enumerate() {
        let shift = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(8))
            .ok_or_else(|| format_error("IA64 instruction shift overflows"))?;
        *byte = u8::try_from((value >> shift) & 0xff)
            .map_err(|_| format_error("IA64 instruction byte is not representable"))?;
    }
    Ok(())
}

fn low_u32_offset(offset: usize) -> Result<u32> {
    let offset = u64::try_from(offset)
        .map_err(|_| format_error("filter offset is not representable as u64"))?;
    u32::try_from(offset & u64::from(u32::MAX))
        .map_err(|_| format_error("filter offset is not representable as u32"))
}

fn decode_swap(
    bytes: &mut [u8],
    properties: &[u8],
    width: usize,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if !properties.is_empty() {
        return Err(format_error("Swap filter properties must be empty"));
    }
    if !matches!(width, 2 | 4) {
        return Err(format_error("Swap filter width is invalid"));
    }
    let mut chunks = bytes.chunks_exact_mut(width);
    for chunk in &mut chunks {
        control.checkpoint(
            u64::try_from(width)
                .map_err(|_| format_error("Swap filter width is not representable"))?,
        )?;
        chunk.reverse();
    }
    Ok(())
}

fn decode_arm_thumb(
    bytes: &mut [u8],
    properties: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if bytes.len() < 4 {
        return Ok(());
    }
    let start = starting_position(properties)?;
    let scan_end = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| format_error("ARM Thumb scan bound underflows"))?;
    let mut offset = 0_usize;
    while offset <= scan_end {
        control.checkpoint(2)?;
        let second = bytes
            .get(
                offset
                    .checked_add(1)
                    .ok_or_else(|| format_error("ARM Thumb index overflows"))?,
            )
            .copied()
            .ok_or_else(|| format_error("ARM Thumb instruction is truncated"))?;
        let fourth = bytes
            .get(
                offset
                    .checked_add(3)
                    .ok_or_else(|| format_error("ARM Thumb index overflows"))?,
            )
            .copied()
            .ok_or_else(|| format_error("ARM Thumb instruction is truncated"))?;
        if second & 0xf8 == 0xf0 && fourth & 0xf8 == 0xf8 {
            let first = bytes
                .get(offset)
                .copied()
                .ok_or_else(|| format_error("ARM Thumb instruction is truncated"))?;
            let third = bytes
                .get(
                    offset
                        .checked_add(2)
                        .ok_or_else(|| format_error("ARM Thumb index overflows"))?,
                )
                .copied()
                .ok_or_else(|| format_error("ARM Thumb instruction is truncated"))?;
            let mut source = (u32::from(second & 7) << 19)
                | (u32::from(first) << 11)
                | (u32::from(fourth & 7) << 8)
                | u32::from(third);
            source = source.wrapping_shl(1);
            let position = start.wrapping_add(low_u32_offset(offset)?).wrapping_add(4);
            let destination = source.wrapping_sub(position) >> 1;
            let instruction = bytes
                .get_mut(
                    offset
                        ..offset
                            .checked_add(4)
                            .ok_or_else(|| format_error("ARM Thumb range overflows"))?,
                )
                .ok_or_else(|| format_error("ARM Thumb instruction is truncated"))?;
            let encoded = [
                u8::try_from((destination >> 11) & 0xff)
                    .map_err(|_| format_error("ARM Thumb byte is not representable"))?,
                0xf0 | u8::try_from((destination >> 19) & 7)
                    .map_err(|_| format_error("ARM Thumb byte is not representable"))?,
                u8::try_from(destination & 0xff)
                    .map_err(|_| format_error("ARM Thumb byte is not representable"))?,
                0xf8 | u8::try_from((destination >> 8) & 7)
                    .map_err(|_| format_error("ARM Thumb byte is not representable"))?,
            ];
            instruction.copy_from_slice(&encoded);
            offset = offset
                .checked_add(2)
                .ok_or_else(|| format_error("ARM Thumb position overflows"))?;
        }
        offset = offset
            .checked_add(2)
            .ok_or_else(|| format_error("ARM Thumb position overflows"))?;
    }
    Ok(())
}

fn decode_ia64(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    let start = starting_position(properties)?;
    let bundle_count = bytes.len() / 16;
    let process_bytes = bundle_count
        .checked_mul(16)
        .ok_or_else(|| format_error("IA64 scan size overflows"))?;
    let mut offset = 0_usize;
    while offset < process_bytes {
        control.checkpoint(16)?;
        let template = usize::from(
            bytes
                .get(offset)
                .copied()
                .ok_or_else(|| format_error("IA64 bundle is truncated"))?
                & 0x1f,
        );
        let branch_mask = *IA64_BRANCH_TABLE
            .get(template)
            .ok_or_else(|| format_error("IA64 bundle template is out of range"))?;
        let mut bit_position = 5_u32;
        for slot in 0..3_u32 {
            control.checkpoint(1)?;
            let selected = 1_u8
                .checked_shl(slot)
                .ok_or_else(|| format_error("IA64 slot mask overflows"))?;
            if branch_mask & selected == 0 {
                bit_position = bit_position
                    .checked_add(41)
                    .ok_or_else(|| format_error("IA64 bit position overflows"))?;
                continue;
            }
            let byte_position = usize::try_from(bit_position >> 3)
                .map_err(|_| format_error("IA64 byte position is not representable"))?;
            let bit_remainder = bit_position & 7;
            let instruction_offset = offset
                .checked_add(byte_position)
                .ok_or_else(|| format_error("IA64 instruction offset overflows"))?;
            let mut instruction = read_u48_le(bytes, instruction_offset)?;
            let mut normalized = instruction >> bit_remainder;
            if (normalized >> 37) & 0x0f == 5 && (normalized >> 9) & 7 == 0 {
                let low = u32::try_from((normalized >> 13) & 0x000f_ffff)
                    .map_err(|_| format_error("IA64 branch address is not representable"))?;
                let high = u32::try_from((normalized >> 36) & 1)
                    .map_err(|_| format_error("IA64 branch bit is not representable"))?;
                let source = (low | (high << 20)).wrapping_shl(4);
                let position = start.wrapping_add(low_u32_offset(offset)?);
                let destination = source.wrapping_sub(position) >> 4;
                normalized &= !(u64::from(0x008f_ffff_u32) << 13);
                normalized |= u64::from(destination & 0x000f_ffff) << 13;
                normalized |= u64::from(destination & 0x0010_0000) << 16;
                let low_mask = 1_u64
                    .checked_shl(bit_remainder)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or_else(|| format_error("IA64 instruction mask overflows"))?;
                instruction &= low_mask;
                instruction |= normalized
                    .checked_shl(bit_remainder)
                    .ok_or_else(|| format_error("IA64 instruction shift overflows"))?;
                write_u48_le(bytes, instruction_offset, instruction)?;
            }
            bit_position = bit_position
                .checked_add(41)
                .ok_or_else(|| format_error("IA64 bit position overflows"))?;
        }
        offset = offset
            .checked_add(16)
            .ok_or_else(|| format_error("IA64 bundle offset overflows"))?;
    }
    Ok(())
}

fn is_not_auipc_pair(auipc: u32, second: u32) -> bool {
    (auipc.wrapping_shl(8) ^ second.wrapping_sub(3)) & 0x000f_8003 != 0
}

fn is_not_special_auipc(auipc: u32, second_rs1: u32) -> bool {
    auipc.wrapping_sub(0x3117).wrapping_shl(18) >= second_rs1 & 0x1d
}

fn decode_riscv(bytes: &mut [u8], properties: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
    if bytes.len() < 8 {
        return Ok(());
    }
    let start = starting_position(properties)? & !1;
    let scan_end = bytes
        .len()
        .checked_sub(8)
        .ok_or_else(|| format_error("RISC-V scan bound underflows"))?;
    let mut offset = 0_usize;
    while offset <= scan_end {
        control.checkpoint(2)?;
        let first = bytes
            .get(offset)
            .copied()
            .ok_or_else(|| format_error("RISC-V instruction is truncated"))?;
        if first == 0xef {
            let second = bytes
                .get(
                    offset
                        .checked_add(1)
                        .ok_or_else(|| format_error("RISC-V index overflows"))?,
                )
                .copied()
                .ok_or_else(|| format_error("RISC-V JAL is truncated"))?;
            if second & 0x0d == 0 {
                let third = bytes
                    .get(
                        offset
                            .checked_add(2)
                            .ok_or_else(|| format_error("RISC-V index overflows"))?,
                    )
                    .copied()
                    .ok_or_else(|| format_error("RISC-V JAL is truncated"))?;
                let fourth = bytes
                    .get(
                        offset
                            .checked_add(3)
                            .ok_or_else(|| format_error("RISC-V index overflows"))?,
                    )
                    .copied()
                    .ok_or_else(|| format_error("RISC-V JAL is truncated"))?;
                let position = start.wrapping_add(low_u32_offset(offset)?);
                let address = ((u32::from(second & 0xf0)) << 13)
                    | (u32::from(third) << 9)
                    | (u32::from(fourth) << 1);
                let address = address.wrapping_sub(position);
                let instruction = bytes
                    .get_mut(
                        offset
                            ..offset
                                .checked_add(4)
                                .ok_or_else(|| format_error("RISC-V JAL range overflows"))?,
                    )
                    .ok_or_else(|| format_error("RISC-V JAL is truncated"))?;
                let decoded = [
                    first,
                    (second & 0x0f)
                        | u8::try_from((address >> 8) & 0xf0)
                            .map_err(|_| format_error("RISC-V JAL byte is not representable"))?,
                    u8::try_from(
                        ((address >> 16) & 0x0f)
                            | ((address >> 7) & 0x10)
                            | ((address << 4) & 0xe0),
                    )
                    .map_err(|_| format_error("RISC-V JAL byte is not representable"))?,
                    u8::try_from(((address >> 4) & 0x7f) | ((address >> 13) & 0x80))
                        .map_err(|_| format_error("RISC-V JAL byte is not representable"))?,
                ];
                instruction.copy_from_slice(&decoded);
                offset = offset
                    .checked_add(4)
                    .ok_or_else(|| format_error("RISC-V position overflows"))?;
                continue;
            }
        } else if first & 0x7f == 0x17 {
            let mut instruction = read_u32_le(bytes, offset)?;
            let mut second_instruction;
            if instruction & 0x0e80 != 0 {
                second_instruction = read_u32_le(
                    bytes,
                    offset
                        .checked_add(4)
                        .ok_or_else(|| format_error("RISC-V pair offset overflows"))?,
                )?;
                if is_not_auipc_pair(instruction, second_instruction) {
                    offset = offset
                        .checked_add(6)
                        .ok_or_else(|| format_error("RISC-V position overflows"))?;
                    continue;
                }
                let address = (instruction & 0xffff_f000).wrapping_add(second_instruction >> 20);
                instruction = 0x17 | (2 << 7) | second_instruction.wrapping_shl(12);
                second_instruction = address;
            } else {
                let second_rs1 = instruction >> 27;
                if is_not_special_auipc(instruction, second_rs1) {
                    offset = offset
                        .checked_add(4)
                        .ok_or_else(|| format_error("RISC-V position overflows"))?;
                    continue;
                }
                let address_offset = offset
                    .checked_add(4)
                    .ok_or_else(|| format_error("RISC-V pair offset overflows"))?;
                let position = start.wrapping_add(low_u32_offset(offset)?);
                let address = read_u32_be(bytes, address_offset)?.wrapping_sub(position);
                second_instruction = (instruction >> 12) | address.wrapping_shl(20);
                instruction =
                    0x17 | second_rs1.wrapping_shl(7) | address.wrapping_add(0x800) & 0xffff_f000;
            }
            write_u32_le(bytes, offset, instruction)?;
            write_u32_le(
                bytes,
                offset
                    .checked_add(4)
                    .ok_or_else(|| format_error("RISC-V pair offset overflows"))?,
                second_instruction,
            )?;
            offset = offset
                .checked_add(8)
                .ok_or_else(|| format_error("RISC-V position overflows"))?;
            continue;
        }
        offset = offset
            .checked_add(2)
            .ok_or_else(|| format_error("RISC-V position overflows"))?;
    }
    Ok(())
}

pub(super) fn decode_phase5_filter(
    method: &[u8],
    properties: &[u8],
    bytes: &mut [u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if method == METHOD_IA64 {
        decode_ia64(bytes, properties, control)
    } else if method == METHOD_ARM_THUMB {
        decode_arm_thumb(bytes, properties, control)
    } else if method == METHOD_RISCV {
        decode_riscv(bytes, properties, control)
    } else if method == METHOD_SWAP2 {
        decode_swap(bytes, properties, 2, control)
    } else if method == METHOD_SWAP4 {
        decode_swap(bytes, properties, 4, control)
    } else {
        Err(Error::UnsupportedMethod {
            method_id: method.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_arm_thumb, decode_ia64, decode_riscv, decode_swap};
    use crate::{CancellationToken, Error, WorkBudget, parse_util::ParseControl};

    fn with_control<T>(operation: impl FnOnce(&mut ParseControl<'_>) -> T) -> T {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        operation(&mut control)
    }

    #[test]
    fn swaps_complete_words_and_preserves_the_tail() {
        let mut swap2 = [1, 2, 3, 4, 5];
        assert!(with_control(|control| decode_swap(&mut swap2, &[], 2, control)).is_ok());
        assert_eq!(swap2, [2, 1, 4, 3, 5]);

        let mut swap4 = [1, 2, 3, 4, 5];
        assert!(with_control(|control| decode_swap(&mut swap4, &[], 4, control)).is_ok());
        assert_eq!(swap4, [4, 3, 2, 1, 5]);
    }

    #[test]
    fn arm_thumb_decodes_a_wrapped_branch() {
        let mut bytes = [0, 0xf0, 0, 0xf8];
        assert!(with_control(|control| decode_arm_thumb(&mut bytes, &[], control)).is_ok());
        assert_eq!(bytes, [0xff, 0xf7, 0xfe, 0xff]);
    }

    #[test]
    fn ia64_preserves_an_incomplete_bundle() {
        let original = [0x5a_u8; 15];
        let mut bytes = original;
        assert!(with_control(|control| decode_ia64(&mut bytes, &[], control)).is_ok());
        assert_eq!(bytes, original);
    }

    #[test]
    fn riscv_decodes_a_jal_at_a_nonzero_start() {
        let mut bytes = [0xef, 0, 0, 0x80, 0, 0, 0, 0];
        let properties = 0x100_u32.to_le_bytes();
        assert!(with_control(|control| decode_riscv(&mut bytes, &properties, control)).is_ok());
        assert_eq!(bytes, [0xef, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn branch_properties_are_consumed_exactly() {
        let mut bytes = [0_u8; 8];
        assert!(with_control(|control| decode_riscv(&mut bytes, &[0], control)).is_err());
    }

    #[test]
    fn cancellation_stops_a_phase_five_filter() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let mut bytes = [0_u8; 2];
        let result = decode_swap(&mut bytes, &[], 2, &mut control);
        assert!(matches!(result, Err(Error::Cancelled)));
    }
}
