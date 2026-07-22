//! PPMd7 (variant H) decoder adapted from the pinned MIT Go dependency.
//!
//! The source model uses integer offsets into a bounded byte heap. This port
//! retains that representation but makes every heap access and address
//! operation fallible, so corrupt model state cannot become a Rust index panic.

use std::io;

use crate::{
    Error, LimitKind, Limits, Result,
    coder_properties::parse_ppmd_properties,
    parse_util::{ParseControl, check_limit, format_error, u64_to_usize, usize_to_u64},
};

const STATE_SIZE: u32 = 6;
const UNIT_SIZE: u32 = 12;
const FIXED_UNIT_SIZE: u32 = 12;
const RAR_NODE_SIZE: u32 = 4;
const RAR_MEM_BLOCK_SIZE: u32 = 12;
const N1: usize = 4;
const N2: usize = 4;
const N3: usize = 4;
const N4: usize = (128 + 3 - N1 - 2 * N2 - 3 * N3) / 4;
const N_INDEXES: usize = N1 + N2 + N3 + N4;
const MAX_ORDER: u8 = 64;
const PERIOD_BITS: u32 = 7;
const INTERVAL: u32 = 1 << 7;
const BIN_SCALE: u32 = 1 << 14;
const MAX_FREQ_U8: u8 = 124;
const QUARTER_MAX_FREQ_U8: u8 = 31;
const MAX_FREQ_MINUS_NINE_U8: u8 = 115;
const MAX_FREQ_MINUS_FOUR_U8: u8 = 120;
const QUARTER_MAX_FREQ_MINUS_ONE_U8: u8 = 30;
const TOP_VALUE: u32 = 1 << 24;
const INIT_BIN_ESC: [u32; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

fn add(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_add(right).ok_or_else(|| format_error(detail))
}

fn sub(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_sub(right).ok_or_else(|| format_error(detail))
}

fn mul(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_mul(right).ok_or_else(|| format_error(detail))
}

struct Heap {
    bytes: Vec<u8>,
}

impl Heap {
    fn new(size: u32) -> Result<Self> {
        let size = usize::try_from(size)
            .map_err(|_| format_error("PPMd heap size is not representable on this platform"))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "PPMd heap allocation failed",
            ))
        })?;
        bytes.resize(size, 0);
        Ok(Self { bytes })
    }

    fn len_u32(&self) -> Result<u32> {
        u32::try_from(self.bytes.len())
            .map_err(|_| format_error("PPMd heap length is not representable as u32"))
    }

    fn byte(&self, address: u32) -> Result<u8> {
        let address = usize::try_from(address)
            .map_err(|_| format_error("PPMd heap address is not representable"))?;
        self.bytes
            .get(address)
            .copied()
            .ok_or_else(|| format_error("PPMd heap byte address is out of range"))
    }

    fn put_byte(&mut self, address: u32, value: u8) -> Result<()> {
        let address = usize::try_from(address)
            .map_err(|_| format_error("PPMd heap address is not representable"))?;
        let byte = self
            .bytes
            .get_mut(address)
            .ok_or_else(|| format_error("PPMd heap byte address is out of range"))?;
        *byte = value;
        Ok(())
    }

    fn u16(&self, address: u32) -> Result<u32> {
        let high_address = add(address, 1, "PPMd u16 address overflows")?;
        Ok(u32::from(self.byte(address)?) | (u32::from(self.byte(high_address)?) << 8))
    }

    fn put_u16(&mut self, address: u32, value: u32) -> Result<()> {
        let bytes = u16::try_from(value)
            .map_err(|_| format_error("PPMd u16 value is out of range"))?
            .to_le_bytes();
        let low = bytes
            .first()
            .copied()
            .ok_or_else(|| format_error("PPMd u16 low byte is unavailable"))?;
        let high = bytes
            .get(1)
            .copied()
            .ok_or_else(|| format_error("PPMd u16 high byte is unavailable"))?;
        let high_address = add(address, 1, "PPMd u16 address overflows")?;
        self.put_byte(address, low)?;
        self.put_byte(high_address, high)
    }

    fn u32(&self, address: u32) -> Result<u32> {
        let b1 = add(address, 1, "PPMd u32 address overflows")?;
        let b2 = add(address, 2, "PPMd u32 address overflows")?;
        let b3 = add(address, 3, "PPMd u32 address overflows")?;
        Ok(u32::from(self.byte(address)?)
            | (u32::from(self.byte(b1)?) << 8)
            | (u32::from(self.byte(b2)?) << 16)
            | (u32::from(self.byte(b3)?) << 24))
    }

    fn put_u32(&mut self, address: u32, value: u32) -> Result<()> {
        for shift in [0_u32, 8, 16, 24] {
            let offset = shift / 8;
            self.put_byte(
                add(address, offset, "PPMd u32 address overflows")?,
                u8::try_from((value >> shift) & 0xff)
                    .map_err(|_| format_error("PPMd u32 byte is out of range"))?,
            )?;
        }
        Ok(())
    }

    fn copy(&mut self, destination: u32, source: u32, size: u32) -> Result<()> {
        let source_end = add(source, size, "PPMd heap source range overflows")?;
        let destination_end = add(destination, size, "PPMd heap destination range overflows")?;
        let source = usize::try_from(source)
            .map_err(|_| format_error("PPMd heap source is not representable"))?;
        let source_end = usize::try_from(source_end)
            .map_err(|_| format_error("PPMd heap source end is not representable"))?;
        let destination = usize::try_from(destination)
            .map_err(|_| format_error("PPMd heap destination is not representable"))?;
        let destination_end = usize::try_from(destination_end)
            .map_err(|_| format_error("PPMd heap destination end is not representable"))?;
        if self.bytes.get(source..source_end).is_none()
            || self.bytes.get(destination..destination_end).is_none()
        {
            return Err(format_error("PPMd heap copy range is out of bounds"));
        }
        self.bytes.copy_within(source..source_end, destination);
        Ok(())
    }

    fn clear(&mut self, address: u32, size: u32) -> Result<()> {
        let end = add(address, size, "PPMd heap clear range overflows")?;
        let start = usize::try_from(address)
            .map_err(|_| format_error("PPMd heap clear start is not representable"))?;
        let end = usize::try_from(end)
            .map_err(|_| format_error("PPMd heap clear end is not representable"))?;
        self.bytes
            .get_mut(start..end)
            .ok_or_else(|| format_error("PPMd heap clear range is out of bounds"))?
            .fill(0);
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct State(u32);

#[derive(Clone, Copy, Default)]
struct StateRef {
    successor: u32,
    symbol: u8,
    frequency: u8,
}

impl StateRef {
    fn from_state(heap: &Heap, state: State) -> Result<Self> {
        Ok(Self {
            successor: state.successor(heap)?,
            symbol: state.symbol(heap)?,
            frequency: state.frequency(heap)?,
        })
    }

    fn decrement_frequency(&mut self, amount: u8) -> Result<()> {
        self.frequency = self
            .frequency
            .checked_sub(amount)
            .ok_or_else(|| format_error("PPMd saved-state frequency underflows"))?;
        Ok(())
    }
}

impl State {
    fn increment(self) -> Result<Self> {
        Ok(Self(add(
            self.0,
            STATE_SIZE,
            "PPMd state address overflows",
        )?))
    }

    fn decrement(self) -> Result<Self> {
        Ok(Self(sub(
            self.0,
            STATE_SIZE,
            "PPMd state address underflows",
        )?))
    }

    fn symbol(self, heap: &Heap) -> Result<u8> {
        heap.byte(self.0)
    }

    fn set_symbol(self, heap: &mut Heap, symbol: u8) -> Result<()> {
        heap.put_byte(self.0, symbol)
    }

    fn frequency(self, heap: &Heap) -> Result<u8> {
        heap.byte(add(self.0, 1, "PPMd state frequency address overflows")?)
    }

    fn set_frequency(self, heap: &mut Heap, frequency: u8) -> Result<()> {
        heap.put_byte(
            add(self.0, 1, "PPMd state frequency address overflows")?,
            frequency,
        )
    }

    fn increment_frequency(self, heap: &mut Heap, amount: u8) -> Result<()> {
        let frequency = self
            .frequency(heap)?
            .checked_add(amount)
            .ok_or_else(|| format_error("PPMd state frequency overflows"))?;
        self.set_frequency(heap, frequency)
    }

    fn successor(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(self.0, 2, "PPMd state successor address overflows")?)
    }

    fn set_successor(self, heap: &mut Heap, successor: u32) -> Result<()> {
        heap.put_u32(
            add(self.0, 2, "PPMd state successor address overflows")?,
            successor,
        )
    }

    fn set_ref(self, heap: &mut Heap, state: StateRef) -> Result<()> {
        self.set_symbol(heap, state.symbol)?;
        self.set_frequency(heap, state.frequency)?;
        self.set_successor(heap, state.successor)
    }

    fn copy_from(self, heap: &mut Heap, source: State) -> Result<()> {
        heap.copy(self.0, source.0, STATE_SIZE)
    }
}

fn swap_states(heap: &mut Heap, left: State, right: State) -> Result<()> {
    let mut temporary = [0_u8; STATE_SIZE as usize];
    for (offset, byte) in temporary.iter_mut().enumerate() {
        let offset = u32::try_from(offset)
            .map_err(|_| format_error("PPMd state swap offset is not representable"))?;
        *byte = heap.byte(add(left.0, offset, "PPMd state swap address overflows")?)?;
    }
    for offset in 0..STATE_SIZE {
        let value = heap.byte(add(right.0, offset, "PPMd state swap address overflows")?)?;
        heap.put_byte(
            add(left.0, offset, "PPMd state swap address overflows")?,
            value,
        )?;
    }
    for (offset, byte) in temporary.iter().copied().enumerate() {
        let offset = u32::try_from(offset)
            .map_err(|_| format_error("PPMd state swap offset is not representable"))?;
        heap.put_byte(
            add(right.0, offset, "PPMd state swap address overflows")?,
            byte,
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct Context(u32);

impl Context {
    fn num_stats(self, heap: &Heap) -> Result<u32> {
        heap.u16(self.0)
    }

    fn set_num_stats(self, heap: &mut Heap, count: u32) -> Result<()> {
        if !(1..=256).contains(&count) {
            return Err(format_error("PPMd context state count is invalid"));
        }
        heap.put_u16(self.0, count)
    }

    fn one_state(self) -> Result<State> {
        Ok(State(add(self.0, 2, "PPMd one-state address overflows")?))
    }

    fn set_one_state(self, heap: &mut Heap, state: StateRef) -> Result<()> {
        self.one_state()?.set_ref(heap, state)
    }

    fn summ_frequency(self, heap: &Heap) -> Result<u32> {
        heap.u16(add(self.0, 2, "PPMd summary frequency address overflows")?)
    }

    fn set_summ_frequency(self, heap: &mut Heap, frequency: u32) -> Result<()> {
        heap.put_u16(
            add(self.0, 2, "PPMd summary frequency address overflows")?,
            frequency,
        )
    }

    fn increment_summ_frequency(self, heap: &mut Heap, amount: u32) -> Result<()> {
        let frequency = self
            .summ_frequency(heap)?
            .checked_add(amount)
            .ok_or_else(|| format_error("PPMd summary frequency overflows"))?;
        self.set_summ_frequency(heap, frequency)
    }

    fn stats(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(self.0, 4, "PPMd stats address overflows")?)
    }

    fn set_stats(self, heap: &mut Heap, state: u32) -> Result<()> {
        heap.put_u32(add(self.0, 4, "PPMd stats address overflows")?, state)
    }

    fn suffix(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(self.0, 8, "PPMd suffix address overflows")?)
    }

    fn set_suffix(self, heap: &mut Heap, suffix: u32) -> Result<()> {
        heap.put_u32(add(self.0, 8, "PPMd suffix address overflows")?, suffix)
    }
}

#[derive(Clone, Copy, Default)]
struct See2Context {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See2Context {
    fn new(value: u32) -> Result<Self> {
        let shift = 3_u8;
        let summ = value
            .checked_shl(u32::from(shift))
            .ok_or_else(|| format_error("PPMd SEE initial summary overflows"))?;
        Ok(Self {
            summ: u16::try_from(summ)
                .map_err(|_| format_error("PPMd SEE initial summary is out of range"))?,
            shift,
            count: 4,
        })
    }

    fn mean(&mut self) -> Result<u32> {
        let mut result = u32::from(self.summ) >> self.shift;
        let result_u16 =
            u16::try_from(result).map_err(|_| format_error("PPMd SEE mean is out of range"))?;
        self.summ = self
            .summ
            .checked_sub(result_u16)
            .ok_or_else(|| format_error("PPMd SEE summary underflows"))?;
        if result == 0 {
            result = 1;
        }
        Ok(result)
    }

    fn update(&mut self) -> Result<()> {
        if u32::from(self.shift) < PERIOD_BITS {
            self.count = self
                .count
                .checked_sub(1)
                .ok_or_else(|| format_error("PPMd SEE update count underflows"))?;
            if self.count == 0 {
                self.summ = self
                    .summ
                    .checked_add(self.summ)
                    .ok_or_else(|| format_error("PPMd SEE summary overflows"))?;
                self.count = 3_u8
                    .checked_shl(u32::from(self.shift))
                    .ok_or_else(|| format_error("PPMd SEE update count overflows"))?;
                self.shift = self
                    .shift
                    .checked_add(1)
                    .ok_or_else(|| format_error("PPMd SEE shift overflows"))?;
            }
        }
        Ok(())
    }
}

struct RangeDecoder<'input> {
    input: &'input [u8],
    position: usize,
    range: u32,
    code: u32,
}

impl<'input> RangeDecoder<'input> {
    fn new(input: &'input [u8], control: &mut ParseControl<'_>) -> Result<Self> {
        let mut decoder = Self {
            input,
            position: 0,
            range: u32::MAX,
            code: 0,
        };
        for _ in 0..5 {
            let byte = decoder.read_byte(control)?;
            decoder.code = decoder.code.wrapping_shl(8) | u32::from(byte);
        }
        Ok(decoder)
    }

    fn read_byte(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| format_error("PPMd range stream is truncated"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| format_error("PPMd input position overflows"))?;
        Ok(byte)
    }

    fn normalize(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        while self.range < TOP_VALUE {
            self.code = self.code.wrapping_shl(8) | u32::from(self.read_byte(control)?);
            self.range = self
                .range
                .checked_shl(8)
                .ok_or_else(|| format_error("PPMd range normalization overflows"))?;
        }
        Ok(())
    }

    fn threshold(&mut self, total: u32) -> Result<u32> {
        if total == 0 {
            return Err(format_error("PPMd range total is zero"));
        }
        self.range = self
            .range
            .checked_div(total)
            .ok_or_else(|| format_error("PPMd range division is invalid"))?;
        if self.range == 0 {
            return Err(format_error("PPMd range collapsed to zero"));
        }
        self.code
            .checked_div(self.range)
            .ok_or_else(|| format_error("PPMd threshold division is invalid"))
    }

    fn decode(&mut self, start: u32, size: u32, control: &mut ParseControl<'_>) -> Result<()> {
        let offset = start
            .checked_mul(self.range)
            .ok_or_else(|| format_error("PPMd range offset overflows"))?;
        self.code = self
            .code
            .checked_sub(offset)
            .ok_or_else(|| format_error("PPMd range code underflows"))?;
        self.range = self
            .range
            .checked_mul(size)
            .ok_or_else(|| format_error("PPMd range size overflows"))?;
        self.normalize(control)
    }

    fn decode_bit(
        &mut self,
        size_zero: u32,
        total_bits: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let bound = (self.range >> total_bits)
            .checked_mul(size_zero)
            .ok_or_else(|| format_error("PPMd binary range bound overflows"))?;
        let symbol = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.code = self
                .code
                .checked_sub(bound)
                .ok_or_else(|| format_error("PPMd binary range code underflows"))?;
            self.range = self
                .range
                .checked_sub(bound)
                .ok_or_else(|| format_error("PPMd binary range underflows"))?;
            1
        };
        self.normalize(control)?;
        Ok(symbol)
    }
}

#[derive(Clone, Copy, Default)]
struct RarNode {
    address: u32,
}

impl RarNode {
    fn next(self, heap: &Heap) -> Result<u32> {
        heap.u32(self.address)
    }

    fn set_next(self, heap: &mut Heap, next: u32) -> Result<()> {
        heap.put_u32(self.address, next)
    }
}

#[derive(Clone, Copy, Default)]
struct MemBlock(u32);

impl MemBlock {
    fn stamp(self, heap: &Heap) -> Result<u32> {
        heap.u16(self.0)
    }

    fn set_stamp(self, heap: &mut Heap, value: u32) -> Result<()> {
        heap.put_u16(self.0, value)
    }

    fn units(self, heap: &Heap) -> Result<u32> {
        heap.u16(add(self.0, 2, "PPMd memory-block units address overflows")?)
    }

    fn set_units(self, heap: &mut Heap, units: u32) -> Result<()> {
        heap.put_u16(
            add(self.0, 2, "PPMd memory-block units address overflows")?,
            units,
        )
    }

    fn next(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(self.0, 4, "PPMd memory-block next address overflows")?)
    }

    fn set_next(self, heap: &mut Heap, next: u32) -> Result<()> {
        heap.put_u32(
            add(self.0, 4, "PPMd memory-block next address overflows")?,
            next,
        )
    }

    fn previous(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(
            self.0,
            8,
            "PPMd memory-block previous address overflows",
        )?)
    }

    fn set_previous(self, heap: &mut Heap, previous: u32) -> Result<()> {
        heap.put_u32(
            add(self.0, 8, "PPMd memory-block previous address overflows")?,
            previous,
        )
    }

    fn insert_at(self, heap: &mut Heap, after: Self) -> Result<()> {
        self.set_previous(heap, after.0)?;
        self.set_next(heap, after.next(heap)?)?;
        after.set_next(heap, self.0)?;
        MemBlock(self.next(heap)?).set_previous(heap, self.0)
    }

    fn remove(self, heap: &mut Heap) -> Result<()> {
        let previous = MemBlock(self.previous(heap)?);
        let next = MemBlock(self.next(heap)?);
        previous.set_next(heap, next.0)?;
        next.set_previous(heap, previous.0)
    }
}

struct SubAllocator {
    glue_count: u32,
    size: u32,
    units_start: u32,
    free_list_position: u32,
    heap_start: u32,
    low_unit: u32,
    high_unit: u32,
    temporary_block_position: u32,
    heap_end: u32,
    text: u32,
    fake_units_start: u32,
    units_to_index: [u32; 128],
    index_to_units: [u32; N_INDEXES],
    free_list: [RarNode; N_INDEXES],
}

impl SubAllocator {
    fn new(size: u32) -> Result<(Self, Heap)> {
        let allocation_size = add(
            mul(
                size / FIXED_UNIT_SIZE,
                UNIT_SIZE,
                "PPMd allocation size overflows",
            )?,
            UNIT_SIZE,
            "PPMd allocation size overflows",
        )?;
        let list_bytes = mul(
            u32::try_from(N_INDEXES)
                .map_err(|_| format_error("PPMd free-list count is not representable"))?,
            RAR_NODE_SIZE,
            "PPMd free-list size overflows",
        )?;
        let temporary_block_position = add(
            add(1, allocation_size, "PPMd heap layout overflows")?,
            list_bytes,
            "PPMd heap layout overflows",
        )?;
        let real_size = add(
            temporary_block_position,
            RAR_MEM_BLOCK_SIZE,
            "PPMd heap layout overflows",
        )?;
        let heap = Heap::new(real_size)?;
        let heap_start = 1;
        let heap_end = sub(
            add(heap_start, allocation_size, "PPMd heap end overflows")?,
            UNIT_SIZE,
            "PPMd heap end underflows",
        )?;
        let free_list_position = add(
            heap_start,
            allocation_size,
            "PPMd free-list position overflows",
        )?;
        let mut free_list = [RarNode::default(); N_INDEXES];
        let mut position = free_list_position;
        for node in &mut free_list {
            *node = RarNode { address: position };
            position = add(position, RAR_NODE_SIZE, "PPMd free-list address overflows")?;
        }
        Ok((
            Self {
                glue_count: 0,
                size,
                units_start: 0,
                free_list_position,
                heap_start,
                low_unit: 0,
                high_unit: 0,
                temporary_block_position,
                heap_end,
                text: 0,
                fake_units_start: 0,
                units_to_index: [0; 128],
                index_to_units: [0; N_INDEXES],
                free_list,
            },
            heap,
        ))
    }

    fn bytes_for_units(units: u32) -> Result<u32> {
        mul(UNIT_SIZE, units, "PPMd unit-byte size overflows")
    }

    fn free_index(&self, index: u32) -> Result<usize> {
        let index = usize::try_from(index)
            .map_err(|_| format_error("PPMd free-list index is not representable"))?;
        if index >= N_INDEXES {
            return Err(format_error("PPMd free-list index is out of range"));
        }
        Ok(index)
    }

    fn unit_index(&self, units_minus_one: u32) -> Result<u32> {
        let index = usize::try_from(units_minus_one)
            .map_err(|_| format_error("PPMd unit index is not representable"))?;
        self.units_to_index
            .get(index)
            .copied()
            .ok_or_else(|| format_error("PPMd unit index is out of range"))
    }

    fn units_at(&self, index: u32) -> Result<u32> {
        self.index_to_units
            .get(self.free_index(index)?)
            .copied()
            .ok_or_else(|| format_error("PPMd allocation index is out of range"))
    }

    fn insert_node(&self, heap: &mut Heap, address: u32, index: u32) -> Result<()> {
        let head = self
            .free_list
            .get(self.free_index(index)?)
            .copied()
            .ok_or_else(|| format_error("PPMd free-list head is missing"))?;
        let node = RarNode { address };
        node.set_next(heap, head.next(heap)?)?;
        head.set_next(heap, address)
    }

    fn remove_node(&self, heap: &mut Heap, index: u32) -> Result<u32> {
        let head = self
            .free_list
            .get(self.free_index(index)?)
            .copied()
            .ok_or_else(|| format_error("PPMd free-list head is missing"))?;
        let address = head.next(heap)?;
        if address == 0 {
            return Err(format_error(
                "PPMd attempted to remove an empty free-list node",
            ));
        }
        let node = RarNode { address };
        head.set_next(heap, node.next(heap)?)?;
        Ok(address)
    }

    fn split_block(
        &self,
        heap: &mut Heap,
        address: u32,
        old_index: u32,
        new_index: u32,
    ) -> Result<()> {
        let mut difference = sub(
            self.units_at(old_index)?,
            self.units_at(new_index)?,
            "PPMd split-unit difference underflows",
        )?;
        let mut remainder = add(
            address,
            Self::bytes_for_units(self.units_at(new_index)?)?,
            "PPMd split-block address overflows",
        )?;
        let mut index = self.unit_index(sub(difference, 1, "PPMd split-unit index underflows")?)?;
        if self.units_at(index)? != difference {
            index = sub(index, 1, "PPMd split allocation index underflows")?;
            self.insert_node(heap, remainder, index)?;
            let units = self.units_at(index)?;
            remainder = add(
                remainder,
                Self::bytes_for_units(units)?,
                "PPMd split-block address overflows",
            )?;
            difference = sub(difference, units, "PPMd split-unit difference underflows")?;
        }
        self.insert_node(
            heap,
            remainder,
            self.unit_index(sub(difference, 1, "PPMd split-unit index underflows")?)?,
        )
    }

    fn initialize(&mut self, heap: &mut Heap) -> Result<()> {
        let list_size = mul(
            u32::try_from(N_INDEXES)
                .map_err(|_| format_error("PPMd free-list count is not representable"))?,
            RAR_NODE_SIZE,
            "PPMd free-list size overflows",
        )?;
        heap.clear(self.free_list_position, list_size)?;
        self.text = self.heap_start;
        let secondary_units = self
            .size
            .checked_div(8)
            .and_then(|size| size.checked_div(FIXED_UNIT_SIZE))
            .and_then(|units| units.checked_mul(7))
            .ok_or_else(|| format_error("PPMd secondary allocation size overflows"))?;
        let size_two = mul(
            FIXED_UNIT_SIZE,
            secondary_units,
            "PPMd secondary allocation size overflows",
        )?;
        let real_size_two = mul(
            size_two / FIXED_UNIT_SIZE,
            UNIT_SIZE,
            "PPMd secondary allocation size overflows",
        )?;
        let size_one = sub(
            self.size,
            size_two,
            "PPMd primary allocation size underflows",
        )?;
        let real_size_one = add(
            mul(
                size_one / FIXED_UNIT_SIZE,
                UNIT_SIZE,
                "PPMd primary allocation size overflows",
            )?,
            size_one % FIXED_UNIT_SIZE,
            "PPMd primary allocation size overflows",
        )?;
        self.low_unit = add(
            self.heap_start,
            real_size_one,
            "PPMd low-unit address overflows",
        )?;
        self.units_start = self.low_unit;
        self.fake_units_start = add(
            self.heap_start,
            size_one,
            "PPMd fake-unit address overflows",
        )?;
        self.high_unit = add(
            self.low_unit,
            real_size_two,
            "PPMd high-unit address overflows",
        )?;

        let mut units = 1_u32;
        let mut index = 0_usize;
        while index < N1 {
            if let Some(slot) = self.index_to_units.get_mut(index) {
                *slot = units;
            }
            units = add(units, 1, "PPMd unit class overflows")?;
            index = index
                .checked_add(1)
                .ok_or_else(|| format_error("PPMd unit-class index overflows"))?;
        }
        units = add(units, 1, "PPMd unit class overflows")?;
        while index < N1 + N2 {
            if let Some(slot) = self.index_to_units.get_mut(index) {
                *slot = units;
            }
            units = add(units, 2, "PPMd unit class overflows")?;
            index = index
                .checked_add(1)
                .ok_or_else(|| format_error("PPMd unit-class index overflows"))?;
        }
        units = add(units, 1, "PPMd unit class overflows")?;
        while index < N1 + N2 + N3 {
            if let Some(slot) = self.index_to_units.get_mut(index) {
                *slot = units;
            }
            units = add(units, 3, "PPMd unit class overflows")?;
            index = index
                .checked_add(1)
                .ok_or_else(|| format_error("PPMd unit-class index overflows"))?;
        }
        units = add(units, 1, "PPMd unit class overflows")?;
        while index < N_INDEXES {
            if let Some(slot) = self.index_to_units.get_mut(index) {
                *slot = units;
            }
            units = add(units, 4, "PPMd unit class overflows")?;
            index = index
                .checked_add(1)
                .ok_or_else(|| format_error("PPMd unit-class index overflows"))?;
        }
        self.glue_count = 0;
        let mut class = 0_usize;
        for requested in 1_u32..=128 {
            while self
                .index_to_units
                .get(class)
                .copied()
                .ok_or_else(|| format_error("PPMd unit class is out of range"))?
                < requested
            {
                class = class
                    .checked_add(1)
                    .ok_or_else(|| format_error("PPMd unit class index overflows"))?;
            }
            let slot = self
                .units_to_index
                .get_mut(
                    usize::try_from(sub(requested, 1, "PPMd requested-unit index underflows")?)
                        .map_err(|_| {
                            format_error("PPMd requested-unit index is not representable")
                        })?,
                )
                .ok_or_else(|| format_error("PPMd requested-unit index is out of range"))?;
            *slot = u32::try_from(class)
                .map_err(|_| format_error("PPMd unit class is not representable"))?;
        }
        Ok(())
    }

    fn allocate_context(&mut self, heap: &mut Heap) -> Result<u32> {
        if self.high_unit != self.low_unit {
            self.high_unit = sub(
                self.high_unit,
                UNIT_SIZE,
                "PPMd high-unit address underflows",
            )?;
            return Ok(self.high_unit);
        }
        if self
            .free_list
            .first()
            .copied()
            .ok_or_else(|| format_error("PPMd context free-list is missing"))?
            .next(heap)?
            != 0
        {
            return self.remove_node(heap, 0);
        }
        self.allocate_units_rare(heap, 0)
    }

    fn allocate_units(&mut self, heap: &mut Heap, units: u32) -> Result<u32> {
        if !(1..=128).contains(&units) {
            return Err(format_error("PPMd allocation unit count is out of range"));
        }
        let index = self.unit_index(sub(units, 1, "PPMd unit index underflows")?)?;
        let head = self
            .free_list
            .get(self.free_index(index)?)
            .copied()
            .ok_or_else(|| format_error("PPMd allocation free-list is missing"))?;
        if head.next(heap)? != 0 {
            return self.remove_node(heap, index);
        }
        let address = self.low_unit;
        self.low_unit = add(
            self.low_unit,
            Self::bytes_for_units(self.units_at(index)?)?,
            "PPMd low-unit address overflows",
        )?;
        if self.low_unit <= self.high_unit {
            return Ok(address);
        }
        self.low_unit = sub(
            self.low_unit,
            Self::bytes_for_units(self.units_at(index)?)?,
            "PPMd low-unit address underflows",
        )?;
        self.allocate_units_rare(heap, index)
    }

    fn allocate_units_rare(&mut self, heap: &mut Heap, index: u32) -> Result<u32> {
        if self.glue_count == 0 {
            self.glue_count = 255;
            self.glue_free_blocks(heap)?;
            let head = self
                .free_list
                .get(self.free_index(index)?)
                .copied()
                .ok_or_else(|| format_error("PPMd rare free-list is missing"))?;
            if head.next(heap)? != 0 {
                return self.remove_node(heap, index);
            }
        }
        let mut larger = index;
        loop {
            larger = add(larger, 1, "PPMd allocation class overflows")?;
            if usize::try_from(larger).ok() == Some(N_INDEXES) {
                self.glue_count = self
                    .glue_count
                    .checked_sub(1)
                    .ok_or_else(|| format_error("PPMd glue counter underflows"))?;
                let bytes = Self::bytes_for_units(self.units_at(index)?)?;
                let fake_bytes = mul(
                    FIXED_UNIT_SIZE,
                    self.units_at(index)?,
                    "PPMd fake-unit byte count overflows",
                )?;
                if sub(
                    self.fake_units_start,
                    self.text,
                    "PPMd fake-unit span underflows",
                )? > fake_bytes
                {
                    self.fake_units_start = sub(
                        self.fake_units_start,
                        fake_bytes,
                        "PPMd fake-unit address underflows",
                    )?;
                    self.units_start = sub(
                        self.units_start,
                        bytes,
                        "PPMd unit-start address underflows",
                    )?;
                    return Ok(self.units_start);
                }
                return Ok(0);
            }
            let head = self
                .free_list
                .get(self.free_index(larger)?)
                .copied()
                .ok_or_else(|| format_error("PPMd larger free-list is missing"))?;
            if head.next(heap)? != 0 {
                break;
            }
        }
        let address = self.remove_node(heap, larger)?;
        self.split_block(heap, address, larger, index)?;
        Ok(address)
    }

    fn expand_units(&mut self, heap: &mut Heap, old: u32, old_units: u32) -> Result<u32> {
        let old_index = self.unit_index(sub(old_units, 1, "PPMd old-unit index underflows")?)?;
        let new_index = self.unit_index(old_units)?;
        if old_index == new_index {
            return Ok(old);
        }
        let new = self.allocate_units(heap, add(old_units, 1, "PPMd unit count overflows")?)?;
        if new != 0 {
            heap.copy(new, old, Self::bytes_for_units(old_units)?)?;
            self.insert_node(heap, old, old_index)?;
        }
        Ok(new)
    }

    fn shrink_units(
        &mut self,
        heap: &mut Heap,
        old: u32,
        old_units: u32,
        new_units: u32,
    ) -> Result<u32> {
        let old_index = self.unit_index(sub(old_units, 1, "PPMd old-unit index underflows")?)?;
        let new_index = self.unit_index(sub(new_units, 1, "PPMd new-unit index underflows")?)?;
        if old_index == new_index {
            return Ok(old);
        }
        let head = self
            .free_list
            .get(self.free_index(new_index)?)
            .copied()
            .ok_or_else(|| format_error("PPMd shrink free-list is missing"))?;
        if head.next(heap)? != 0 {
            let new = self.remove_node(heap, new_index)?;
            heap.copy(new, old, Self::bytes_for_units(new_units)?)?;
            self.insert_node(heap, old, old_index)?;
            return Ok(new);
        }
        self.split_block(heap, old, old_index, new_index)?;
        Ok(old)
    }

    fn free_units(&self, heap: &mut Heap, address: u32, old_units: u32) -> Result<()> {
        self.insert_node(
            heap,
            address,
            self.unit_index(sub(old_units, 1, "PPMd free-unit index underflows")?)?,
        )
    }

    fn glue_free_blocks(&self, heap: &mut Heap) -> Result<()> {
        let sentinel = MemBlock(self.temporary_block_position);
        if self.low_unit != self.high_unit {
            heap.put_byte(self.low_unit, 0)?;
        }
        sentinel.set_previous(heap, sentinel.0)?;
        sentinel.set_next(heap, sentinel.0)?;
        for index in 0..N_INDEXES {
            let index = u32::try_from(index)
                .map_err(|_| format_error("PPMd glue index is not representable"))?;
            loop {
                let head = self
                    .free_list
                    .get(self.free_index(index)?)
                    .copied()
                    .ok_or_else(|| format_error("PPMd glue free-list is missing"))?;
                if head.next(heap)? == 0 {
                    break;
                }
                let block = MemBlock(self.remove_node(heap, index)?);
                block.insert_at(heap, sentinel)?;
                block.set_stamp(heap, 0xffff)?;
                block.set_units(heap, self.units_at(index)?)?;
            }
        }
        let maximum_steps = heap
            .len_u32()?
            .checked_div(RAR_MEM_BLOCK_SIZE)
            .and_then(|steps| steps.checked_add(1))
            .ok_or_else(|| format_error("PPMd glue step limit overflows"))?;
        let mut block = MemBlock(sentinel.next(heap)?);
        let mut steps = 0_u32;
        while block.0 != sentinel.0 {
            steps = add(steps, 1, "PPMd glue step count overflows")?;
            if steps > maximum_steps {
                return Err(format_error("PPMd free-block list contains a cycle"));
            }
            let mut next = MemBlock(add(
                block.0,
                Self::bytes_for_units(block.units(heap)?)?,
                "PPMd adjacent block address overflows",
            )?);
            while next.stamp(heap)? == 0xffff
                && block
                    .units(heap)?
                    .checked_add(next.units(heap)?)
                    .is_some_and(|units| units < 0x1_0000)
            {
                next.remove(heap)?;
                block.set_units(
                    heap,
                    add(
                        block.units(heap)?,
                        next.units(heap)?,
                        "PPMd merged unit count overflows",
                    )?,
                )?;
                next = MemBlock(add(
                    block.0,
                    Self::bytes_for_units(block.units(heap)?)?,
                    "PPMd adjacent block address overflows",
                )?);
            }
            block = MemBlock(block.next(heap)?);
        }
        block = MemBlock(sentinel.next(heap)?);
        steps = 0;
        while block.0 != sentinel.0 {
            steps = add(steps, 1, "PPMd glue step count overflows")?;
            if steps > maximum_steps {
                return Err(format_error("PPMd free-block list contains a cycle"));
            }
            block.remove(heap)?;
            let mut units = block.units(heap)?;
            while units > 128 {
                self.insert_node(
                    heap,
                    block.0,
                    u32::try_from(N_INDEXES - 1)
                        .map_err(|_| format_error("PPMd largest class is not representable"))?,
                )?;
                block.0 = add(
                    block.0,
                    Self::bytes_for_units(128)?,
                    "PPMd glue block address overflows",
                )?;
                units = sub(units, 128, "PPMd glue unit count underflows")?;
            }
            let mut index = self.unit_index(sub(units, 1, "PPMd glue unit index underflows")?)?;
            if self.units_at(index)? != units {
                index = sub(index, 1, "PPMd glue allocation index underflows")?;
                let remainder_units = sub(
                    units,
                    self.units_at(index)?,
                    "PPMd glue remainder underflows",
                )?;
                self.insert_node(
                    heap,
                    add(
                        block.0,
                        Self::bytes_for_units(sub(
                            units,
                            remainder_units,
                            "PPMd glue prefix underflows",
                        )?)?,
                        "PPMd glue remainder address overflows",
                    )?,
                    sub(remainder_units, 1, "PPMd glue remainder index underflows")?,
                )?;
            }
            self.insert_node(heap, block.0, index)?;
            block = MemBlock(sentinel.next(heap)?);
        }
        Ok(())
    }
}

struct Model<'input> {
    char_mask: [u32; 256],
    ns_to_index: [u32; 256],
    ns_to_binary_index: [u32; 256],
    high_bit_flag: [u32; 256],
    binary_summary: [[u32; 64]; 128],
    state_stack: [u32; MAX_ORDER as usize],
    see_contexts: [[See2Context; 16]; 25],
    escape_count: u8,
    previous_success: u8,
    allocator: SubAllocator,
    heap: Heap,
    found_state: State,
    dummy_see: See2Context,
    minimum_context: Context,
    maximum_context: Context,
    initial_escape: u32,
    maximum_order: u32,
    run_length: u32,
    initial_run_length: u32,
    order_fall: u32,
    decoder: RangeDecoder<'input>,
    high_bits_flag: u32,
}

impl<'input> Model<'input> {
    fn new(
        order: u8,
        memory_size: u32,
        input: &'input [u8],
        control: &mut ParseControl<'_>,
    ) -> Result<Self> {
        control.checkpoint(0)?;
        if !(2..=MAX_ORDER).contains(&order) {
            return Err(format_error("PPMd order is outside 2 through 64"));
        }
        let (allocator, heap) = SubAllocator::new(memory_size)?;
        let decoder = RangeDecoder::new(input, control)?;
        let mut model = Self {
            char_mask: [0; 256],
            ns_to_index: [0; 256],
            ns_to_binary_index: [0; 256],
            high_bit_flag: [0; 256],
            binary_summary: [[0; 64]; 128],
            state_stack: [0; MAX_ORDER as usize],
            see_contexts: [[See2Context::default(); 16]; 25],
            escape_count: 1,
            previous_success: 0,
            allocator,
            heap,
            found_state: State::default(),
            dummy_see: See2Context::default(),
            minimum_context: Context::default(),
            maximum_context: Context::default(),
            initial_escape: 0,
            maximum_order: u32::from(order),
            run_length: 0,
            initial_run_length: 0,
            order_fall: 0,
            decoder,
            high_bits_flag: 0,
        };
        model.start_model(u32::from(order), control)?;
        if model.minimum_context.0 == 0 {
            return Err(format_error("PPMd initial context allocation failed"));
        }
        Ok(model)
    }

    fn mask_index(symbol: u8) -> usize {
        usize::from(symbol)
    }

    fn mask_value(&self, symbol: u8) -> Result<u32> {
        self.char_mask
            .get(Self::mask_index(symbol))
            .copied()
            .ok_or_else(|| format_error("PPMd character-mask index is out of range"))
    }

    fn clear_mask(&mut self, symbol: u8) -> Result<()> {
        let slot = self
            .char_mask
            .get_mut(Self::mask_index(symbol))
            .ok_or_else(|| format_error("PPMd character-mask index is out of range"))?;
        *slot = 0;
        Ok(())
    }

    fn restart_model(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        self.char_mask.fill(0);
        self.allocator.initialize(&mut self.heap)?;
        let initial_order = self.maximum_order.min(12);
        self.initial_run_length = initial_order.wrapping_neg().wrapping_sub(1);
        let address = self.allocator.allocate_context(&mut self.heap)?;
        if address == 0 {
            return Err(format_error("PPMd context allocation failed"));
        }
        self.minimum_context = Context(address);
        self.maximum_context = Context(address);
        self.minimum_context.set_suffix(&mut self.heap, 0)?;
        self.order_fall = self.maximum_order;
        self.minimum_context.set_num_stats(&mut self.heap, 256)?;
        self.minimum_context
            .set_summ_frequency(&mut self.heap, 257)?;
        let states = self.allocator.allocate_units(&mut self.heap, 128)?;
        if states == 0 {
            return Err(format_error("PPMd initial state allocation failed"));
        }
        self.found_state = State(states);
        self.minimum_context.set_stats(&mut self.heap, states)?;
        self.run_length = self.initial_run_length;
        self.previous_success = 0;
        for symbol in 0_u32..256 {
            control.checkpoint(1)?;
            let offset = mul(symbol, STATE_SIZE, "PPMd initial state offset overflows")?;
            let state = State(add(states, offset, "PPMd initial state address overflows")?);
            state.set_symbol(
                &mut self.heap,
                u8::try_from(symbol)
                    .map_err(|_| format_error("PPMd initial symbol is not representable"))?,
            )?;
            state.set_frequency(&mut self.heap, 1)?;
            state.set_successor(&mut self.heap, 0)?;
        }
        for row in 0..128_usize {
            let denominator = u32::try_from(row)
                .map_err(|_| format_error("PPMd binary row is not representable"))?
                .checked_add(2)
                .ok_or_else(|| format_error("PPMd binary denominator overflows"))?;
            for (group, initial_escape) in INIT_BIN_ESC.iter().copied().enumerate() {
                let initial = initial_escape.checked_div(denominator).ok_or_else(|| {
                    format_error("PPMd binary initialization division is invalid")
                })?;
                let value = sub(BIN_SCALE, initial, "PPMd binary initialization underflows")?;
                let mut column = group;
                while column < 64 {
                    if let Some(slot) = self
                        .binary_summary
                        .get_mut(row)
                        .and_then(|values| values.get_mut(column))
                    {
                        *slot = value;
                    }
                    column = column
                        .checked_add(8)
                        .ok_or_else(|| format_error("PPMd binary column overflows"))?;
                }
            }
        }
        for row in 0..25_usize {
            for column in 0..16_usize {
                let value = 5_u32
                    .checked_mul(
                        u32::try_from(row)
                            .map_err(|_| format_error("PPMd SEE row is not representable"))?,
                    )
                    .and_then(|value| value.checked_add(10))
                    .ok_or_else(|| format_error("PPMd SEE initial value overflows"))?;
                let slot = self
                    .see_contexts
                    .get_mut(row)
                    .and_then(|values| values.get_mut(column))
                    .ok_or_else(|| format_error("PPMd SEE context index is out of range"))?;
                *slot = See2Context::new(value)?;
            }
        }
        Ok(())
    }

    fn start_model(&mut self, maximum_order: u32, control: &mut ParseControl<'_>) -> Result<()> {
        self.escape_count = 1;
        self.maximum_order = maximum_order;
        self.restart_model(control)?;
        *self
            .ns_to_binary_index
            .get_mut(0)
            .ok_or_else(|| format_error("PPMd binary NS index zero is unavailable"))? = 0;
        *self
            .ns_to_binary_index
            .get_mut(1)
            .ok_or_else(|| format_error("PPMd binary NS index one is unavailable"))? = 2;
        for index in 2..11 {
            *self
                .ns_to_binary_index
                .get_mut(index)
                .ok_or_else(|| format_error("PPMd binary NS index is out of range"))? = 4;
        }
        for index in 11..256 {
            *self
                .ns_to_binary_index
                .get_mut(index)
                .ok_or_else(|| format_error("PPMd binary NS index is out of range"))? = 6;
        }
        for index in 0..3 {
            *self
                .ns_to_index
                .get_mut(index)
                .ok_or_else(|| format_error("PPMd NS index is out of range"))? =
                u32::try_from(index)
                    .map_err(|_| format_error("PPMd NS index is not representable"))?;
        }
        let mut remaining = 1_u32;
        let mut step = 1_u32;
        let mut value = 3_u32;
        for index in 3..256 {
            *self
                .ns_to_index
                .get_mut(index)
                .ok_or_else(|| format_error("PPMd NS index is out of range"))? = value;
            remaining = sub(remaining, 1, "PPMd NS run underflows")?;
            if remaining == 0 {
                step = add(step, 1, "PPMd NS step overflows")?;
                remaining = step;
                value = add(value, 1, "PPMd NS value overflows")?;
            }
        }
        self.high_bit_flag
            .get_mut(..0x40)
            .ok_or_else(|| format_error("PPMd high-bit low range is unavailable"))?
            .fill(0);
        self.high_bit_flag
            .get_mut(0x40..)
            .ok_or_else(|| format_error("PPMd high-bit high range is unavailable"))?
            .fill(8);
        self.dummy_see.shift = 7;
        Ok(())
    }

    fn create_child(
        &mut self,
        context: Context,
        parent_state: State,
        first_state: StateRef,
    ) -> Result<u32> {
        let address = self.allocator.allocate_context(&mut self.heap)?;
        if address == 0 {
            return Ok(0);
        }
        let child = Context(address);
        child.set_num_stats(&mut self.heap, 1)?;
        child.set_one_state(&mut self.heap, first_state)?;
        child.set_suffix(&mut self.heap, context.0)?;
        parent_state.set_successor(&mut self.heap, address)?;
        Ok(address)
    }

    fn rescale(&mut self, context: Context, control: &mut ParseControl<'_>) -> Result<()> {
        let old_count = context.num_stats(&self.heap)?;
        if old_count < 2 {
            return Err(format_error("PPMd cannot rescale a binary context"));
        }
        let first = State(context.stats(&self.heap)?);
        let mut state = self.found_state;
        let mut moved = 0_u32;
        while state.0 != first.0 {
            control.checkpoint(1)?;
            moved = add(moved, 1, "PPMd rescale movement count overflows")?;
            if moved >= old_count {
                return Err(format_error("PPMd found state is outside its context"));
            }
            let previous = state.decrement()?;
            swap_states(&mut self.heap, state, previous)?;
            state = previous;
        }
        state.increment_frequency(&mut self.heap, 4)?;
        context.increment_summ_frequency(&mut self.heap, 4)?;
        let mut escape_frequency = sub(
            context.summ_frequency(&self.heap)?,
            u32::from(state.frequency(&self.heap)?),
            "PPMd escape frequency underflows",
        )?;
        let adder = u8::from(self.order_fall != 0);
        let first_frequency = state
            .frequency(&self.heap)?
            .checked_add(adder)
            .ok_or_else(|| format_error("PPMd state frequency overflows during rescale"))?
            >> 1;
        state.set_frequency(&mut self.heap, first_frequency)?;
        context.set_summ_frequency(&mut self.heap, u32::from(first_frequency))?;
        let mut remaining = sub(old_count, 1, "PPMd rescale state count underflows")?;
        while remaining != 0 {
            control.checkpoint(1)?;
            state = state.increment()?;
            escape_frequency = sub(
                escape_frequency,
                u32::from(state.frequency(&self.heap)?),
                "PPMd escape frequency underflows",
            )?;
            let frequency = state
                .frequency(&self.heap)?
                .checked_add(adder)
                .ok_or_else(|| format_error("PPMd state frequency overflows during rescale"))?
                >> 1;
            state.set_frequency(&mut self.heap, frequency)?;
            context.increment_summ_frequency(&mut self.heap, u32::from(frequency))?;
            let previous = state.decrement()?;
            if state.frequency(&self.heap)? > previous.frequency(&self.heap)? {
                let saved = StateRef::from_state(&self.heap, state)?;
                let mut insertion = state;
                loop {
                    let source = insertion.decrement()?;
                    insertion.copy_from(&mut self.heap, source)?;
                    insertion = source;
                    if insertion.0 == first.0 {
                        break;
                    }
                    if saved.frequency <= insertion.decrement()?.frequency(&self.heap)? {
                        break;
                    }
                }
                insertion.set_ref(&mut self.heap, saved)?;
            }
            remaining = sub(remaining, 1, "PPMd rescale state count underflows")?;
        }
        let mut zero_count = 0_u32;
        while state.frequency(&self.heap)? == 0 {
            zero_count = add(zero_count, 1, "PPMd zero-state count overflows")?;
            if zero_count >= old_count {
                return Err(format_error("PPMd rescale removed every state"));
            }
            state = state.decrement()?;
        }
        if zero_count != 0 {
            escape_frequency = add(
                escape_frequency,
                zero_count,
                "PPMd escape frequency overflows",
            )?;
            let new_count = sub(
                context.num_stats(&self.heap)?,
                zero_count,
                "PPMd context state count underflows",
            )?;
            context.set_num_stats(&mut self.heap, new_count)?;
            if new_count == 1 {
                let mut saved = StateRef::from_state(&self.heap, first)?;
                loop {
                    saved.decrement_frequency(saved.frequency >> 1)?;
                    escape_frequency >>= 1;
                    if escape_frequency <= 1 {
                        break;
                    }
                }
                let old_stats = context.stats(&self.heap)?;
                let old_units = add(old_count, 1, "PPMd rescale unit count overflows")? >> 1;
                self.allocator
                    .free_units(&mut self.heap, old_stats, old_units)?;
                context.set_one_state(&mut self.heap, saved)?;
                self.found_state = context.one_state()?;
                return Ok(());
            }
        }
        escape_frequency = sub(
            escape_frequency,
            escape_frequency >> 1,
            "PPMd escape frequency underflows",
        )?;
        context.increment_summ_frequency(&mut self.heap, escape_frequency)?;
        let old_units = add(old_count, 1, "PPMd old rescale unit count overflows")? >> 1;
        let new_units = add(
            context.num_stats(&self.heap)?,
            1,
            "PPMd new rescale unit count overflows",
        )? >> 1;
        if old_units != new_units {
            let old_stats = context.stats(&self.heap)?;
            let new_stats =
                self.allocator
                    .shrink_units(&mut self.heap, old_stats, old_units, new_units)?;
            context.set_stats(&mut self.heap, new_stats)?;
        }
        self.found_state = State(context.stats(&self.heap)?);
        Ok(())
    }

    fn binary_array_index(&self, context: Context, state: State) -> Result<usize> {
        let suffix = Context(context.suffix(&self.heap)?);
        let suffix_count = suffix.num_stats(&self.heap)?;
        let binary_index = self
            .ns_to_binary_index
            .get(
                usize::try_from(sub(suffix_count, 1, "PPMd suffix state index underflows")?)
                    .map_err(|_| format_error("PPMd suffix state index is not representable"))?,
            )
            .copied()
            .ok_or_else(|| format_error("PPMd suffix state index is out of range"))?;
        let symbol_flag = self
            .high_bit_flag
            .get(Self::mask_index(state.symbol(&self.heap)?))
            .copied()
            .ok_or_else(|| format_error("PPMd symbol flag is out of range"))?;
        let run_flag = (self.run_length >> 26) & 0x20;
        let symbol_component = (self.high_bits_flag & 0xff)
            .checked_add(mul(2, symbol_flag, "PPMd symbol flag overflows")?)
            .ok_or_else(|| format_error("PPMd symbol component overflows"))?;
        let index = u32::from(self.previous_success)
            .checked_add(binary_index)
            .and_then(|value| value.checked_add(symbol_component))
            .and_then(|value| value.checked_add(run_flag))
            .ok_or_else(|| format_error("PPMd binary array index overflows"))?;
        usize::try_from(index)
            .map_err(|_| format_error("PPMd binary array index is not representable"))
    }

    fn update_first(
        &mut self,
        context: Context,
        address: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        self.found_state = State(address);
        self.found_state.increment_frequency(&mut self.heap, 4)?;
        context.increment_summ_frequency(&mut self.heap, 4)?;
        let previous = self.found_state.decrement()?;
        if self.found_state.frequency(&self.heap)? > previous.frequency(&self.heap)? {
            swap_states(&mut self.heap, self.found_state, previous)?;
            self.found_state = previous;
            if previous.frequency(&self.heap)? > MAX_FREQ_U8 {
                self.rescale(context, control)?;
            }
        }
        Ok(())
    }

    fn update_first_zero(
        &mut self,
        context: Context,
        address: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        self.found_state = State(address);
        self.previous_success = u8::from(
            2_u32
                .checked_mul(u32::from(self.found_state.frequency(&self.heap)?))
                .ok_or_else(|| format_error("PPMd frequency comparison overflows"))?
                > context.summ_frequency(&self.heap)?,
        );
        self.run_length = self
            .run_length
            .wrapping_add(u32::from(self.previous_success));
        context.increment_summ_frequency(&mut self.heap, 4)?;
        self.found_state.increment_frequency(&mut self.heap, 4)?;
        if self.found_state.frequency(&self.heap)? > MAX_FREQ_U8 {
            self.rescale(context, control)?;
        }
        Ok(())
    }

    fn update_second(
        &mut self,
        context: Context,
        address: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        self.found_state = State(address);
        self.found_state.increment_frequency(&mut self.heap, 4)?;
        context.increment_summ_frequency(&mut self.heap, 4)?;
        if self.found_state.frequency(&self.heap)? > MAX_FREQ_U8 {
            self.rescale(context, control)?;
        }
        self.escape_count = self.escape_count.wrapping_add(1);
        self.run_length = self.initial_run_length;
        Ok(())
    }

    fn find_symbol(&self, context: Context, symbol: u8) -> Result<State> {
        let count = context.num_stats(&self.heap)?;
        if count == 1 {
            let state = context.one_state()?;
            if state.symbol(&self.heap)? == symbol {
                return Ok(state);
            }
            return Err(format_error(
                "PPMd binary context does not contain its symbol",
            ));
        }
        let mut state = State(context.stats(&self.heap)?);
        let last = sub(count, 1, "PPMd context state count underflows")?;
        for index in 0..count {
            if state.symbol(&self.heap)? == symbol {
                return Ok(state);
            }
            if index != last {
                state = state.increment()?;
            }
        }
        Err(format_error(
            "PPMd context does not contain the requested symbol",
        ))
    }

    fn escape_frequency(
        &mut self,
        context: Context,
        masked: u32,
    ) -> Result<(Option<(usize, usize)>, u32)> {
        let count = context.num_stats(&self.heap)?;
        let unmasked = sub(count, masked, "PPMd unmasked state count underflows")?;
        if unmasked == 0 {
            return Err(format_error("PPMd context has no unmasked states"));
        }
        if count == 256 {
            return Ok((None, 1));
        }
        let suffix = Context(context.suffix(&self.heap)?);
        let row = self
            .ns_to_index
            .get(
                usize::try_from(sub(unmasked, 1, "PPMd SEE row underflows")?)
                    .map_err(|_| format_error("PPMd SEE row is not representable"))?,
            )
            .copied()
            .ok_or_else(|| format_error("PPMd SEE row is out of range"))?;
        let mut column = u32::from(
            unmasked
                < sub(
                    suffix.num_stats(&self.heap)?,
                    count,
                    "PPMd suffix state difference underflows",
                )?,
        );
        if context.summ_frequency(&self.heap)?
            < 11_u32
                .checked_mul(count)
                .ok_or_else(|| format_error("PPMd SEE frequency threshold overflows"))?
        {
            column = add(column, 2, "PPMd SEE column overflows")?;
        }
        if masked > unmasked {
            column = add(column, 4, "PPMd SEE column overflows")?;
        }
        column = column
            .checked_add(self.high_bits_flag & 0xff)
            .ok_or_else(|| format_error("PPMd SEE column overflows"))?;
        let row =
            usize::try_from(row).map_err(|_| format_error("PPMd SEE row is not representable"))?;
        let column = usize::try_from(column)
            .map_err(|_| format_error("PPMd SEE column is not representable"))?;
        let context = self
            .see_contexts
            .get_mut(row)
            .and_then(|values| values.get_mut(column))
            .ok_or_else(|| format_error("PPMd SEE context index is out of range"))?;
        let frequency = context.mean()?;
        Ok((Some((row, column)), frequency))
    }

    fn update_see(&mut self, slot: Option<(usize, usize)>) -> Result<()> {
        if let Some((row, column)) = slot {
            self.see_contexts
                .get_mut(row)
                .and_then(|values| values.get_mut(column))
                .ok_or_else(|| format_error("PPMd SEE context index is out of range"))?
                .update()?;
        }
        Ok(())
    }

    fn add_see_summary(&mut self, slot: Option<(usize, usize)>, amount: u32) -> Result<()> {
        if let Some((row, column)) = slot {
            let context = self
                .see_contexts
                .get_mut(row)
                .and_then(|values| values.get_mut(column))
                .ok_or_else(|| format_error("PPMd SEE context index is out of range"))?;
            let amount = u16::try_from(amount)
                .map_err(|_| format_error("PPMd SEE summary increment is out of range"))?;
            context.summ = context
                .summ
                .checked_add(amount)
                .ok_or_else(|| format_error("PPMd SEE summary overflows"))?;
        }
        Ok(())
    }

    fn create_successors(
        &mut self,
        skip_found: bool,
        parent: State,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let mut current_context = self.minimum_context;
        let up_branch = Context(self.found_state.successor(&self.heap)?);
        let mut stack_count = 0_usize;
        let mut state = State::default();
        let mut no_loop = false;
        if !skip_found {
            let slot = self
                .state_stack
                .get_mut(stack_count)
                .ok_or_else(|| format_error("PPMd successor stack is full"))?;
            *slot = self.found_state.0;
            stack_count = stack_count
                .checked_add(1)
                .ok_or_else(|| format_error("PPMd successor stack count overflows"))?;
            if current_context.suffix(&self.heap)? == 0 {
                no_loop = true;
            }
        }
        if !no_loop {
            let mut loop_entry = false;
            if parent.0 != 0 {
                state = parent;
                current_context = Context(current_context.suffix(&self.heap)?);
                loop_entry = true;
            }
            let mut climbs = 0_u32;
            let maximum_climbs = add(
                self.maximum_order,
                1,
                "PPMd successor climb limit overflows",
            )?;
            loop {
                control.checkpoint(1)?;
                climbs = add(climbs, 1, "PPMd successor climb count overflows")?;
                if climbs > maximum_climbs {
                    return Err(format_error("PPMd successor chain exceeds the model order"));
                }
                if !loop_entry {
                    current_context = Context(current_context.suffix(&self.heap)?);
                    state =
                        self.find_symbol(current_context, self.found_state.symbol(&self.heap)?)?;
                }
                loop_entry = false;
                if state.successor(&self.heap)? != up_branch.0 {
                    current_context = Context(state.successor(&self.heap)?);
                    break;
                }
                let slot = self
                    .state_stack
                    .get_mut(stack_count)
                    .ok_or_else(|| format_error("PPMd successor stack is full"))?;
                *slot = state.0;
                stack_count = stack_count
                    .checked_add(1)
                    .ok_or_else(|| format_error("PPMd successor stack count overflows"))?;
                if current_context.suffix(&self.heap)? == 0 {
                    break;
                }
            }
        }
        if stack_count == 0 {
            return Ok(current_context.0);
        }
        let mut up_state = StateRef {
            symbol: self.heap.byte(up_branch.0)?,
            successor: add(up_branch.0, 1, "PPMd up-branch successor overflows")?,
            ..StateRef::default()
        };
        if current_context.num_stats(&self.heap)? != 1 {
            if current_context.0 <= self.allocator.text {
                return Ok(0);
            }
            state = self.find_symbol(current_context, up_state.symbol)?;
            let context_frequency = u32::from(state.frequency(&self.heap)?);
            let cf = sub(context_frequency, 1, "PPMd successor frequency underflows")?;
            let s0 = sub(
                sub(
                    current_context.summ_frequency(&self.heap)?,
                    current_context.num_stats(&self.heap)?,
                    "PPMd successor total underflows",
                )?,
                cf,
                "PPMd successor total underflows",
            )?;
            if s0 == 0 {
                return Err(format_error("PPMd successor frequency denominator is zero"));
            }
            let twice_cf = mul(2, cf, "PPMd successor frequency overflows")?;
            let frequency = if twice_cf <= s0 {
                add(
                    u32::from(mul(5, cf, "PPMd successor frequency overflows")? > s0),
                    1,
                    "PPMd successor frequency overflows",
                )?
            } else {
                let numerator = sub(
                    add(
                        twice_cf,
                        mul(3, s0, "PPMd successor frequency overflows")?,
                        "PPMd successor frequency overflows",
                    )?,
                    1,
                    "PPMd successor frequency underflows",
                )?;
                let denominator = mul(2, s0, "PPMd successor denominator overflows")?;
                add(
                    numerator
                        .checked_div(denominator)
                        .ok_or_else(|| format_error("PPMd successor division is invalid"))?,
                    1,
                    "PPMd successor frequency overflows",
                )?
            };
            up_state.frequency = u8::try_from(frequency)
                .map_err(|_| format_error("PPMd successor frequency is not representable"))?;
        } else {
            up_state.frequency = current_context.one_state()?.frequency(&self.heap)?;
        }
        while stack_count != 0 {
            control.checkpoint(1)?;
            stack_count = stack_count
                .checked_sub(1)
                .ok_or_else(|| format_error("PPMd successor stack count underflows"))?;
            let parent = State(
                *self
                    .state_stack
                    .get(stack_count)
                    .ok_or_else(|| format_error("PPMd successor stack index is out of range"))?,
            );
            let child = self.create_child(current_context, parent, up_state)?;
            if child == 0 {
                return Ok(0);
            }
            current_context = Context(child);
        }
        Ok(current_context.0)
    }

    fn restart_after_update(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        self.restart_model(control)?;
        self.escape_count = 0;
        Ok(())
    }

    fn update_model(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        let mut found = StateRef::from_state(&self.heap, self.found_state)?;
        let mut state = State::default();
        let suffix_address = self.minimum_context.suffix(&self.heap)?;
        if found.frequency < QUARTER_MAX_FREQ_U8 && suffix_address != 0 {
            let suffix = Context(suffix_address);
            state = self.find_symbol(suffix, found.symbol)?;
            if suffix.num_stats(&self.heap)? != 1 {
                let first = State(suffix.stats(&self.heap)?);
                if state.0 != first.0 {
                    let previous = state.decrement()?;
                    if state.frequency(&self.heap)? >= previous.frequency(&self.heap)? {
                        swap_states(&mut self.heap, state, previous)?;
                        state = previous;
                    }
                }
                if state.frequency(&self.heap)? < MAX_FREQ_MINUS_NINE_U8 {
                    state.increment_frequency(&mut self.heap, 2)?;
                    suffix.increment_summ_frequency(&mut self.heap, 2)?;
                }
            } else if state.frequency(&self.heap)? < 32 {
                state.increment_frequency(&mut self.heap, 1)?;
            }
        }
        if self.order_fall == 0 {
            let successor = self.create_successors(true, state, control)?;
            self.found_state.set_successor(&mut self.heap, successor)?;
            self.minimum_context = Context(successor);
            self.maximum_context = Context(successor);
            if successor == 0 {
                self.restart_after_update(control)?;
            }
            return Ok(());
        }
        self.heap.put_byte(self.allocator.text, found.symbol)?;
        self.allocator.text = add(self.allocator.text, 1, "PPMd text position overflows")?;
        let mut successor = Context(self.allocator.text);
        if self.allocator.text >= self.allocator.fake_units_start {
            self.restart_after_update(control)?;
            return Ok(());
        }
        if found.successor != 0 {
            if found.successor <= self.allocator.text {
                found.successor = self.create_successors(false, state, control)?;
                if found.successor == 0 {
                    self.restart_after_update(control)?;
                    return Ok(());
                }
            }
            self.order_fall = sub(self.order_fall, 1, "PPMd order fall underflows")?;
            if self.order_fall == 0 {
                successor = Context(found.successor);
                if self.maximum_context.0 != self.minimum_context.0 {
                    self.allocator.text =
                        sub(self.allocator.text, 1, "PPMd text position underflows")?;
                }
            }
        } else {
            self.found_state
                .set_successor(&mut self.heap, successor.0)?;
            found.successor = self.minimum_context.0;
        }
        let minimum_count = self.minimum_context.num_stats(&self.heap)?;
        let s0 = sub(
            sub(
                self.minimum_context.summ_frequency(&self.heap)?,
                minimum_count,
                "PPMd model frequency total underflows",
            )?,
            u32::from(
                found
                    .frequency
                    .checked_sub(1)
                    .ok_or_else(|| format_error("PPMd found-state frequency is zero"))?,
            ),
            "PPMd model frequency total underflows",
        )?;
        let mut context = self.maximum_context;
        let mut iterations = 0_u32;
        let maximum_iterations = add(
            self.maximum_order,
            1,
            "PPMd update iteration limit overflows",
        )?;
        while context.0 != self.minimum_context.0 {
            control.checkpoint(1)?;
            iterations = add(iterations, 1, "PPMd update iteration count overflows")?;
            if iterations > maximum_iterations {
                return Err(format_error("PPMd context chain exceeds the model order"));
            }
            let mut context_count = context.num_stats(&self.heap)?;
            if context_count != 1 {
                if context_count & 1 == 0 {
                    let old_stats = context.stats(&self.heap)?;
                    let expanded = self.allocator.expand_units(
                        &mut self.heap,
                        old_stats,
                        context_count >> 1,
                    )?;
                    context.set_stats(&mut self.heap, expanded)?;
                    if expanded == 0 {
                        self.restart_after_update(control)?;
                        return Ok(());
                    }
                }
                let mut increment = u32::from(
                    mul(2, context_count, "PPMd context count overflows")? < minimum_count,
                );
                let sparse = u32::from(
                    mul(4, context_count, "PPMd context count overflows")? <= minimum_count,
                );
                let low_sum = u32::from(
                    context.summ_frequency(&self.heap)?
                        <= mul(8, context_count, "PPMd context count overflows")?,
                );
                increment = add(
                    increment,
                    mul(2, sparse & low_sum, "PPMd context increment overflows")?,
                    "PPMd context increment overflows",
                )?;
                context.increment_summ_frequency(&mut self.heap, increment)?;
            } else {
                let address = self.allocator.allocate_units(&mut self.heap, 1)?;
                if address == 0 {
                    self.restart_after_update(control)?;
                    return Ok(());
                }
                state = State(address);
                state.copy_from(&mut self.heap, context.one_state()?)?;
                context.set_stats(&mut self.heap, address)?;
                let frequency = state.frequency(&self.heap)?;
                state.set_frequency(
                    &mut self.heap,
                    if frequency < QUARTER_MAX_FREQ_MINUS_ONE_U8 {
                        frequency
                            .checked_add(frequency)
                            .ok_or_else(|| format_error("PPMd state frequency overflows"))?
                    } else {
                        MAX_FREQ_MINUS_FOUR_U8
                    },
                )?;
                let mut summary = u32::from(state.frequency(&self.heap)?)
                    .checked_add(self.initial_escape)
                    .ok_or_else(|| format_error("PPMd context summary overflows"))?;
                if minimum_count > 3 {
                    summary = add(summary, 1, "PPMd context summary overflows")?;
                }
                context.set_summ_frequency(&mut self.heap, summary)?;
            }
            let context_summary = context.summ_frequency(&self.heap)?;
            let comparison = mul(
                mul(
                    2,
                    u32::from(found.frequency),
                    "PPMd model frequency comparison overflows",
                )?,
                add(
                    context_summary,
                    6,
                    "PPMd model frequency comparison overflows",
                )?,
                "PPMd model frequency comparison overflows",
            )?;
            let total = add(s0, context_summary, "PPMd model frequency total overflows")?;
            let four_total = mul(4, total, "PPMd model frequency threshold overflows")?;
            let six_total = mul(6, total, "PPMd model frequency threshold overflows")?;
            let new_frequency = if comparison < six_total {
                context.increment_summ_frequency(&mut self.heap, 3)?;
                add(
                    add(
                        1,
                        u32::from(comparison > total),
                        "PPMd model frequency overflows",
                    )?,
                    u32::from(comparison >= four_total),
                    "PPMd model frequency overflows",
                )?
            } else {
                let nine_total = mul(9, total, "PPMd model frequency threshold overflows")?;
                let twelve_total = mul(12, total, "PPMd model frequency threshold overflows")?;
                let fifteen_total = mul(15, total, "PPMd model frequency threshold overflows")?;
                let frequency = add(
                    add(
                        add(
                            4,
                            u32::from(comparison >= nine_total),
                            "PPMd model frequency overflows",
                        )?,
                        u32::from(comparison >= twelve_total),
                        "PPMd model frequency overflows",
                    )?,
                    u32::from(comparison >= fifteen_total),
                    "PPMd model frequency overflows",
                )?;
                context.increment_summ_frequency(&mut self.heap, frequency)?;
                frequency
            };
            let offset = mul(
                context_count,
                STATE_SIZE,
                "PPMd appended state offset overflows",
            )?;
            state = State(add(
                context.stats(&self.heap)?,
                offset,
                "PPMd appended state address overflows",
            )?);
            state.set_successor(&mut self.heap, successor.0)?;
            state.set_symbol(&mut self.heap, found.symbol)?;
            state.set_frequency(
                &mut self.heap,
                u8::try_from(new_frequency)
                    .map_err(|_| format_error("PPMd model frequency is not representable"))?,
            )?;
            context_count = add(context_count, 1, "PPMd context state count overflows")?;
            context.set_num_stats(&mut self.heap, context_count)?;
            context = Context(context.suffix(&self.heap)?);
        }
        self.maximum_context = Context(found.successor);
        self.minimum_context = Context(found.successor);
        Ok(())
    }

    fn next_context(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        let address = self.found_state.successor(&self.heap)?;
        if self.order_fall == 0 && address > self.allocator.text {
            self.minimum_context = Context(address);
            self.maximum_context = Context(address);
            Ok(())
        } else {
            self.update_model(control)
        }
    }

    fn decode_char(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let state_count = self.minimum_context.num_stats(&self.heap)?;
        if state_count != 1 {
            let first = State(self.minimum_context.stats(&self.heap)?);
            let summary = self.minimum_context.summ_frequency(&self.heap)?;
            let count = self.decoder.threshold(summary)?;
            let mut state = first;
            let mut high_count = u32::from(state.frequency(&self.heap)?);
            if count < high_count {
                self.decoder
                    .decode(0, u32::from(state.frequency(&self.heap)?), control)?;
                let symbol = state.symbol(&self.heap)?;
                self.update_first_zero(self.minimum_context, state.0, control)?;
                self.next_context(control)?;
                return Ok(symbol);
            }
            self.previous_success = 0;
            let mut found = None;
            for _ in 1..state_count {
                control.checkpoint(1)?;
                state = state.increment()?;
                high_count = add(
                    high_count,
                    u32::from(state.frequency(&self.heap)?),
                    "PPMd cumulative frequency overflows",
                )?;
                if high_count > count {
                    found = Some(state);
                    break;
                }
            }
            if let Some(state) = found {
                let frequency = u32::from(state.frequency(&self.heap)?);
                self.decoder.decode(
                    sub(high_count, frequency, "PPMd frequency start underflows")?,
                    frequency,
                    control,
                )?;
                let symbol = state.symbol(&self.heap)?;
                self.update_first(self.minimum_context, state.0, control)?;
                self.next_context(control)?;
                return Ok(symbol);
            }
            if count >= summary {
                return Err(format_error("PPMd threshold exceeds the context total"));
            }
            self.high_bits_flag = self
                .high_bit_flag
                .get(Self::mask_index(self.found_state.symbol(&self.heap)?))
                .copied()
                .ok_or_else(|| format_error("PPMd found-symbol flag is out of range"))?
                & 0xff;
            self.decoder.decode(
                high_count,
                sub(summary, high_count, "PPMd escape range underflows")?,
                control,
            )?;
            self.char_mask.fill(u32::MAX);
            state = first;
            let last_state = sub(state_count, 1, "PPMd context state count underflows")?;
            for index in 0..state_count {
                self.clear_mask(state.symbol(&self.heap)?)?;
                if index != last_state {
                    state = state.increment()?;
                }
            }
        } else {
            let state = self.minimum_context.one_state()?;
            self.high_bits_flag = self
                .high_bit_flag
                .get(Self::mask_index(self.found_state.symbol(&self.heap)?))
                .copied()
                .ok_or_else(|| format_error("PPMd found-symbol flag is out of range"))?;
            let row = usize::from(
                state
                    .frequency(&self.heap)?
                    .checked_sub(1)
                    .ok_or_else(|| format_error("PPMd binary frequency is zero"))?,
            );
            let column = self.binary_array_index(self.minimum_context, state)?;
            let summary = *self
                .binary_summary
                .get(row)
                .and_then(|values| values.get(column))
                .ok_or_else(|| format_error("PPMd binary summary index is out of range"))?;
            let symbol = self.decoder.decode_bit(summary, 14, control)?;
            if symbol == 0 {
                let updated = summary
                    .wrapping_add(INTERVAL)
                    .wrapping_sub(summary.wrapping_add(1 << (PERIOD_BITS - 2)) >> PERIOD_BITS)
                    & 0xffff;
                *self
                    .binary_summary
                    .get_mut(row)
                    .and_then(|values| values.get_mut(column))
                    .ok_or_else(|| format_error("PPMd binary summary index is out of range"))? =
                    updated;
                self.found_state = state;
                let decoded = state.symbol(&self.heap)?;
                if state.frequency(&self.heap)? < 128 {
                    state.increment_frequency(&mut self.heap, 1)?;
                }
                self.previous_success = 1;
                self.run_length = self.run_length.wrapping_add(1);
                self.next_context(control)?;
                return Ok(decoded);
            }
            let updated = summary
                .wrapping_sub(summary.wrapping_add(1 << (PERIOD_BITS - 2)) >> PERIOD_BITS)
                & 0xffff;
            *self
                .binary_summary
                .get_mut(row)
                .and_then(|values| values.get_mut(column))
                .ok_or_else(|| format_error("PPMd binary summary index is out of range"))? =
                updated;
            let escape_index = usize::try_from(updated >> 10)
                .map_err(|_| format_error("PPMd escape index is not representable"))?;
            self.initial_escape = u32::from(
                *EXP_ESCAPE
                    .get(escape_index)
                    .ok_or_else(|| format_error("PPMd escape index is out of range"))?,
            );
            self.char_mask.fill(u32::MAX);
            self.clear_mask(state.symbol(&self.heap)?)?;
            self.previous_success = 0;
        }

        let mut climbs = 0_u32;
        let maximum_climbs = add(self.maximum_order, 256, "PPMd escape climb limit overflows")?;
        loop {
            control.checkpoint(1)?;
            let masked = self.minimum_context.num_stats(&self.heap)?;
            loop {
                climbs = add(climbs, 1, "PPMd escape climb count overflows")?;
                if climbs > maximum_climbs {
                    return Err(format_error("PPMd escape chain is too deep"));
                }
                self.order_fall = add(self.order_fall, 1, "PPMd order fall overflows")?;
                let suffix = self.minimum_context.suffix(&self.heap)?;
                self.minimum_context = Context(suffix);
                if suffix <= self.allocator.text || suffix > self.allocator.heap_end {
                    return Err(format_error("PPMd suffix context address is invalid"));
                }
                if self.minimum_context.num_stats(&self.heap)? != masked {
                    break;
                }
            }
            let context_count = self.minimum_context.num_stats(&self.heap)?;
            let expected_unmasked = sub(
                context_count,
                masked,
                "PPMd unmasked state count underflows",
            )?;
            let mut addresses = [0_u32; 256];
            let mut unmasked = 0_usize;
            let mut high_count = 0_u32;
            let mut state = State(self.minimum_context.stats(&self.heap)?);
            let last_context_state = sub(context_count, 1, "PPMd context state count underflows")?;
            for index in 0..context_count {
                let symbol = state.symbol(&self.heap)?;
                if self.mask_value(symbol)? != 0 {
                    let slot = addresses
                        .get_mut(unmasked)
                        .ok_or_else(|| format_error("PPMd unmasked-state array is full"))?;
                    *slot = state.0;
                    unmasked = unmasked
                        .checked_add(1)
                        .ok_or_else(|| format_error("PPMd unmasked-state count overflows"))?;
                    high_count = add(
                        high_count,
                        u32::from(state.frequency(&self.heap)?),
                        "PPMd unmasked frequency total overflows",
                    )?;
                }
                if index != last_context_state {
                    state = state.increment()?;
                }
            }
            if usize_to_u64(unmasked, "PPMd unmasked count is not representable")?
                != u64::from(expected_unmasked)
            {
                return Err(format_error("PPMd unmasked state count is inconsistent"));
            }
            let (see_slot, mut frequency_sum) =
                self.escape_frequency(self.minimum_context, masked)?;
            frequency_sum = add(
                frequency_sum,
                high_count,
                "PPMd escape frequency total overflows",
            )?;
            let count = self.decoder.threshold(frequency_sum)?;
            if count < high_count {
                let mut cumulative = 0_u32;
                let mut selected = None;
                for address in addresses
                    .get(..unmasked)
                    .ok_or_else(|| format_error("PPMd unmasked-state range is invalid"))?
                {
                    let candidate = State(*address);
                    cumulative = add(
                        cumulative,
                        u32::from(candidate.frequency(&self.heap)?),
                        "PPMd selected frequency total overflows",
                    )?;
                    if cumulative > count {
                        selected = Some(candidate);
                        break;
                    }
                }
                let selected = selected
                    .ok_or_else(|| format_error("PPMd failed to select an unmasked state"))?;
                let frequency = u32::from(selected.frequency(&self.heap)?);
                self.decoder.decode(
                    sub(
                        cumulative,
                        frequency,
                        "PPMd selected frequency start underflows",
                    )?,
                    frequency,
                    control,
                )?;
                self.update_see(see_slot)?;
                let symbol = selected.symbol(&self.heap)?;
                self.update_second(self.minimum_context, selected.0, control)?;
                self.update_model(control)?;
                return Ok(symbol);
            }
            if count >= frequency_sum {
                return Err(format_error("PPMd escape threshold exceeds its total"));
            }
            self.decoder.decode(
                high_count,
                sub(
                    frequency_sum,
                    high_count,
                    "PPMd escape frequency underflows",
                )?,
                control,
            )?;
            self.add_see_summary(see_slot, frequency_sum)?;
            for address in addresses
                .get(..unmasked)
                .ok_or_else(|| format_error("PPMd unmasked-state range is invalid"))?
            {
                let symbol = State(*address).symbol(&self.heap)?;
                self.clear_mask(symbol)?;
            }
        }
    }
}

pub(crate) fn decode_ppmd(
    input: &[u8],
    properties: &[u8],
    expected: Option<u64>,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let properties = parse_ppmd_properties(properties)?;
    let order = properties.order();
    let memory_size = properties.memory_size();
    check_limit(
        u64::from(memory_size),
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let expected = expected.ok_or_else(|| Error::UnsupportedFeature {
        feature: String::from("ppmd-unknown-unpacked-size"),
    })?;
    check_limit(expected, maximum, LimitKind::TotalOutputBytes)?;
    let output_size = u64_to_usize(
        expected,
        "PPMd output size is not representable on this platform",
    )?;
    control.checkpoint(0)?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "PPMd output allocation failed",
        ))
    })?;
    let mut model = Model::new(order, memory_size, input, control)?;
    for _ in 0..output_size {
        output.push(model.decode_char(control)?);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::decode_ppmd;
    use crate::{
        CancellationToken, Error, LimitKind, Limits, Result, WorkBudget, parse_util::ParseControl,
    };

    fn properties(order: u8, memory: u32) -> [u8; 5] {
        let [first, second, third, fourth] = memory.to_le_bytes();
        [order, first, second, third, fourth]
    }

    fn py7zr_properties(order: u8, memory: u32) -> [u8; 7] {
        let [first, second, third, fourth] = memory.to_le_bytes();
        [order, first, second, third, fourth, 0, 0]
    }

    // Synthetic text encoded by stock 7zz 26.02 with PPMd7 order 6 and a
    // 64 KiB model. CORPUS.md and PROVENANCE.md record the exact command and
    // hashes; the oracle-authored archive itself is not retained.
    const PPMD_SEED: &[u8] = &[
        0x00, 0x50, 0x01, 0xe2, 0xfb, 0xf5, 0x0f, 0xe5, 0x00, 0x93, 0xf9, 0x01, 0xda, 0xf2, 0xa8,
        0x02, 0x8b, 0x72, 0x66, 0x5b, 0x34, 0xaa, 0x5a, 0xfc, 0xd6, 0xbb, 0xf6, 0x4e, 0x79, 0xab,
        0x83, 0xe5, 0xa9, 0x16, 0x93, 0x8d, 0x10, 0x93, 0x1a, 0xdf, 0x38, 0xab, 0xa2, 0x72, 0xf6,
        0x12, 0x2d, 0x98, 0x00,
    ];
    const PPMD_SEED_OUTPUT: &[u8] = b"PPMd fuzz seed: alpha beta gamma delta 0123456789\n";

    #[test]
    fn stock_7zz_vector_decodes_and_enforces_output_work_and_truncation() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let decoded = decode_ppmd(
            PPMD_SEED,
            &properties(6, 64 * 1024),
            Some(50),
            50,
            Limits::default(),
            &mut control,
        )?;
        assert_eq!(decoded, PPMD_SEED_OUTPUT);
        assert!(budget.consumed() > 0);

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_ppmd(
                PPMD_SEED,
                &properties(6, 64 * 1024),
                Some(50),
                49,
                Limits::default(),
                &mut control,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 50,
                maximum: 49,
            })
        ));
        assert_eq!(budget.remaining(), Some(0));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_ppmd(
                PPMD_SEED,
                &properties(6, 64 * 1024),
                Some(50),
                50,
                Limits::default(),
                &mut control,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));

        for length in 0..PPMD_SEED.len() {
            let prefix = PPMD_SEED
                .get(..length)
                .ok_or_else(|| std::io::Error::other("PPMd prefix is unavailable"))?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut control = ParseControl::new(&cancellation, &mut budget);
            assert!(
                decode_ppmd(
                    prefix,
                    &properties(6, 64 * 1024),
                    Some(50),
                    50,
                    Limits::default(),
                    &mut control,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn zero_reserved_py7zr_properties_decode_the_exact_stock_vector() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let decoded = decode_ppmd(
            PPMD_SEED,
            &py7zr_properties(6, 64 * 1024),
            Some(50),
            50,
            Limits::default(),
            &mut control,
        )?;
        assert_eq!(decoded, PPMD_SEED_OUTPUT);
        assert!(budget.consumed() > 0);
        Ok(())
    }

    #[test]
    fn py7zr_properties_preserve_preallocation_resource_checks() {
        let properties = py7zr_properties(6, 64 * 1024);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let dictionary_limited = decode_ppmd(
            PPMD_SEED,
            &properties,
            Some(50),
            50,
            Limits::builder()
                .max_dictionary_bytes((64 * 1024) - 1)
                .build(),
            &mut control,
        );
        assert!(matches!(
            dictionary_limited,
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                requested: 65_536,
                maximum: 65_535,
            })
        ));
        assert_eq!(budget.consumed(), 0);

        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let output_limited = decode_ppmd(
            PPMD_SEED,
            &properties,
            Some(50),
            49,
            Limits::default(),
            &mut control,
        );
        assert!(matches!(
            output_limited,
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 50,
                maximum: 49,
            })
        ));
        assert_eq!(budget.consumed(), 0);

        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_ppmd(
                PPMD_SEED,
                &properties,
                Some(50),
                50,
                Limits::default(),
                &mut control,
            ),
            Err(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancelled, &mut budget);
        assert!(matches!(
            decode_ppmd(
                PPMD_SEED,
                &properties,
                Some(50),
                50,
                Limits::default(),
                &mut control,
            ),
            Err(Error::Cancelled)
        ));
        assert_eq!(budget.consumed(), 0);
    }

    #[test]
    fn rejects_memory_before_decoder_allocation() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let limits = Limits::builder().max_dictionary_bytes(4096).build();
        let result = decode_ppmd(&[], &properties(4, 8192), Some(0), 0, limits, &mut control);
        assert!(matches!(
            result,
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                requested: 8192,
                maximum: 4096,
            })
        ));
    }

    #[test]
    fn cancellation_precedes_output_and_model_allocations() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_ppmd(
            &[0; 4],
            &properties(4, 2048),
            Some(0),
            0,
            Limits::default(),
            &mut control,
        );
        assert!(matches!(result, Err(Error::Cancelled)));
    }

    #[test]
    fn truncated_range_state_is_a_format_error() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_ppmd(
            &[0; 3],
            &properties(4, 2048),
            Some(1),
            1,
            Limits::default(),
            &mut control,
        );
        assert!(matches!(result, Err(Error::Format { .. })));
        Ok(())
    }
}
