//! ZIP PPMd variant-I revision-1 decoder.
//!
//! The model is a safe, fallible adaptation of the original public-domain
//! PPMII sources. Modeled pointers are validated offsets into one bounded byte
//! heap. `PROVENANCE.md` records the exact sources, revisions, and hashes.

use std::io;

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, format_error, u64_to_usize},
};

const STATE_SIZE: u32 = 6;
const UNIT_SIZE: u32 = 12;
const N1: usize = 4;
const N2: usize = 4;
const N3: usize = 4;
const N4: usize = (128 + 3 - N1 - 2 * N2 - 3 * N3) / 4;
const N_INDEXES: usize = N1 + N2 + N3 + N4;
const MAX_ORDER: u8 = 16;
const MAX_UNITS: u32 = 128;
const TOP: u32 = 1 << 24;
const BOTTOM: u32 = 1 << 15;
const PERIOD_BITS: u32 = 7;
const INTERVAL: u32 = 1 << 7;
const BIN_SCALE: u32 = 1 << 14;
const MAX_FREQUENCY: u8 = 124;
const ORDER_BOUND: u8 = 9;
const INITIAL_BINARY_ESCAPES: [u16; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
const EXPONENTIAL_ESCAPES: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

fn add(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_add(right).ok_or_else(|| format_error(detail))
}

fn sub(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_sub(right).ok_or_else(|| format_error(detail))
}

fn mul(left: u32, right: u32, detail: &'static str) -> Result<u32> {
    left.checked_mul(right).ok_or_else(|| format_error(detail))
}

fn index(value: u32, detail: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| format_error(detail))
}

fn checked_slot<'a, T>(values: &'a [T], position: usize, detail: &'static str) -> Result<&'a T> {
    values.get(position).ok_or_else(|| format_error(detail))
}

fn checked_slot_mut<'a, T>(
    values: &'a mut [T],
    position: usize,
    detail: &'static str,
) -> Result<&'a mut T> {
    values.get_mut(position).ok_or_else(|| format_error(detail))
}

struct Heap {
    bytes: Vec<u8>,
}

impl Heap {
    fn new(model_size: u32) -> Result<Self> {
        // Offset zero represents a null modeled pointer.
        let size = add(model_size, 1, "ZIP PPMd heap layout overflows")?;
        let size = index(size, "ZIP PPMd heap size is not representable")?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "ZIP PPMd heap allocation failed",
            ))
        })?;
        bytes.resize(size, 0);
        Ok(Self { bytes })
    }

    fn len(&self) -> Result<u32> {
        u32::try_from(self.bytes.len())
            .map_err(|_| format_error("ZIP PPMd heap length is not representable"))
    }

    fn validate_span(&self, address: u32, length: u32) -> Result<()> {
        if address == 0 {
            return Err(format_error("ZIP PPMd null heap address was dereferenced"));
        }
        let end = add(address, length, "ZIP PPMd heap span overflows")?;
        if end > self.len()? {
            return Err(format_error("ZIP PPMd heap span is out of range"));
        }
        Ok(())
    }

    fn byte(&self, address: u32) -> Result<u8> {
        self.validate_span(address, 1)?;
        self.bytes
            .get(index(
                address,
                "ZIP PPMd heap address is not representable",
            )?)
            .copied()
            .ok_or_else(|| format_error("ZIP PPMd heap byte is unavailable"))
    }

    fn put_byte(&mut self, address: u32, value: u8) -> Result<()> {
        self.validate_span(address, 1)?;
        let slot = self
            .bytes
            .get_mut(index(
                address,
                "ZIP PPMd heap address is not representable",
            )?)
            .ok_or_else(|| format_error("ZIP PPMd heap byte is unavailable"))?;
        *slot = value;
        Ok(())
    }

    fn u16(&self, address: u32) -> Result<u16> {
        self.validate_span(address, 2)?;
        let high = add(address, 1, "ZIP PPMd u16 address overflows")?;
        Ok(u16::from(self.byte(address)?) | (u16::from(self.byte(high)?) << 8))
    }

    fn put_u16(&mut self, address: u32, value: u16) -> Result<()> {
        self.validate_span(address, 2)?;
        let bytes = value.to_le_bytes();
        self.put_byte(address, bytes[0])?;
        self.put_byte(add(address, 1, "ZIP PPMd u16 address overflows")?, bytes[1])
    }

    fn u32(&self, address: u32) -> Result<u32> {
        self.validate_span(address, 4)?;
        let mut value = 0_u32;
        for offset in 0..4_u32 {
            value |=
                u32::from(self.byte(add(address, offset, "ZIP PPMd u32 address overflows")?)?)
                    << (offset * 8);
        }
        Ok(value)
    }

    fn put_u32(&mut self, address: u32, value: u32) -> Result<()> {
        self.validate_span(address, 4)?;
        for (offset, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.put_byte(
                add(
                    address,
                    u32::try_from(offset)
                        .map_err(|_| format_error("ZIP PPMd u32 offset is invalid"))?,
                    "ZIP PPMd u32 address overflows",
                )?,
                byte,
            )?;
        }
        Ok(())
    }

    fn copy(&mut self, destination: u32, source: u32, length: u32) -> Result<()> {
        self.validate_span(source, length)?;
        self.validate_span(destination, length)?;
        let source_start = index(source, "ZIP PPMd copy source is not representable")?;
        let source_end = index(
            add(source, length, "ZIP PPMd copy source range overflows")?,
            "ZIP PPMd copy source end is not representable",
        )?;
        let destination = index(
            destination,
            "ZIP PPMd copy destination is not representable",
        )?;
        self.bytes
            .copy_within(source_start..source_end, destination);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct State(u32);

#[derive(Clone, Copy, Debug, Default)]
struct StateValue {
    symbol: u8,
    frequency: u8,
    successor: u32,
}

impl State {
    fn offset(self, amount: i32) -> Result<Self> {
        let magnitude = amount.unsigned_abs();
        let bytes = mul(magnitude, STATE_SIZE, "ZIP PPMd state offset overflows")?;
        if amount < 0 {
            Ok(Self(sub(
                self.0,
                bytes,
                "ZIP PPMd state address underflows",
            )?))
        } else {
            Ok(Self(add(
                self.0,
                bytes,
                "ZIP PPMd state address overflows",
            )?))
        }
    }

    fn symbol(self, heap: &Heap) -> Result<u8> {
        heap.byte(self.0)
    }

    fn set_symbol(self, heap: &mut Heap, value: u8) -> Result<()> {
        heap.put_byte(self.0, value)
    }

    fn frequency(self, heap: &Heap) -> Result<u8> {
        heap.byte(add(
            self.0,
            1,
            "ZIP PPMd state frequency address overflows",
        )?)
    }

    fn set_frequency(self, heap: &mut Heap, value: u8) -> Result<()> {
        heap.put_byte(
            add(self.0, 1, "ZIP PPMd state frequency address overflows")?,
            value,
        )
    }

    fn add_frequency(self, heap: &mut Heap, amount: u8) -> Result<()> {
        let value = self
            .frequency(heap)?
            .checked_add(amount)
            .ok_or_else(|| format_error("ZIP PPMd state frequency overflows"))?;
        self.set_frequency(heap, value)
    }

    fn successor(self, heap: &Heap) -> Result<u32> {
        heap.u32(add(
            self.0,
            2,
            "ZIP PPMd state successor address overflows",
        )?)
    }

    fn set_successor(self, heap: &mut Heap, value: u32) -> Result<()> {
        heap.put_u32(
            add(self.0, 2, "ZIP PPMd state successor address overflows")?,
            value,
        )
    }

    fn value(self, heap: &Heap) -> Result<StateValue> {
        Ok(StateValue {
            symbol: self.symbol(heap)?,
            frequency: self.frequency(heap)?,
            successor: self.successor(heap)?,
        })
    }

    fn set_value(self, heap: &mut Heap, value: StateValue) -> Result<()> {
        self.set_symbol(heap, value.symbol)?;
        self.set_frequency(heap, value.frequency)?;
        self.set_successor(heap, value.successor)
    }
}

fn swap_states(heap: &mut Heap, left: State, right: State) -> Result<()> {
    if left == right {
        return Ok(());
    }
    let left_value = left.value(heap)?;
    let right_value = right.value(heap)?;
    left.set_value(heap, right_value)?;
    right.set_value(heap, left_value)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Context(u32);

impl Context {
    fn num_stats(self, heap: &Heap) -> Result<u8> {
        heap.byte(self.0)
    }

    fn set_num_stats(self, heap: &mut Heap, value: u8) -> Result<()> {
        heap.put_byte(self.0, value)
    }

    fn flags(self, heap: &Heap) -> Result<u8> {
        heap.byte(add(self.0, 1, "ZIP PPMd context flags address overflows")?)
    }

    fn set_flags(self, heap: &mut Heap, value: u8) -> Result<()> {
        heap.put_byte(
            add(self.0, 1, "ZIP PPMd context flags address overflows")?,
            value,
        )
    }

    fn summary(self, heap: &Heap) -> Result<u16> {
        heap.u16(add(
            self.0,
            2,
            "ZIP PPMd context summary address overflows",
        )?)
    }

    fn set_summary(self, heap: &mut Heap, value: u16) -> Result<()> {
        heap.put_u16(
            add(self.0, 2, "ZIP PPMd context summary address overflows")?,
            value,
        )
    }

    fn add_summary(self, heap: &mut Heap, amount: u16) -> Result<()> {
        let value = self
            .summary(heap)?
            .checked_add(amount)
            .ok_or_else(|| format_error("ZIP PPMd context summary overflows"))?;
        self.set_summary(heap, value)
    }

    fn statistics(self, heap: &Heap) -> Result<State> {
        Ok(State(heap.u32(add(
            self.0,
            4,
            "ZIP PPMd context statistics address overflows",
        )?)?))
    }

    fn set_statistics(self, heap: &mut Heap, value: State) -> Result<()> {
        heap.put_u32(
            add(self.0, 4, "ZIP PPMd context statistics address overflows")?,
            value.0,
        )
    }

    fn suffix(self, heap: &Heap) -> Result<Context> {
        Ok(Context(heap.u32(add(
            self.0,
            8,
            "ZIP PPMd context suffix address overflows",
        )?)?))
    }

    fn set_suffix(self, heap: &mut Heap, value: Context) -> Result<()> {
        heap.put_u32(
            add(self.0, 8, "ZIP PPMd context suffix address overflows")?,
            value.0,
        )
    }

    fn first_state(self) -> Result<State> {
        Ok(State(add(
            self.0,
            2,
            "ZIP PPMd one-state address overflows",
        )?))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct See2 {
    summary: u16,
    shift: u8,
    count: u8,
}

impl See2 {
    fn initialize(&mut self, value: u32) -> Result<()> {
        self.shift = 3;
        self.summary = u16::try_from(value << self.shift)
            .map_err(|_| format_error("ZIP PPMd SEE summary is out of range"))?;
        self.count = 7;
        Ok(())
    }

    fn mean(&mut self) -> Result<u32> {
        let value = u32::from(self.summary) >> self.shift;
        self.summary = self
            .summary
            .checked_sub(
                u16::try_from(value)
                    .map_err(|_| format_error("ZIP PPMd SEE mean is not representable"))?,
            )
            .ok_or_else(|| format_error("ZIP PPMd SEE summary underflows"))?;
        Ok(value + u32::from(value == 0))
    }

    fn update(&mut self) -> Result<()> {
        if self.shift < PERIOD_BITS as u8 {
            self.count = self
                .count
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd SEE count underflows"))?;
            if self.count == 0 {
                self.summary = self.summary.wrapping_mul(2);
                self.count = 3_u8
                    .checked_shl(u32::from(self.shift))
                    .ok_or_else(|| format_error("ZIP PPMd SEE count shift overflows"))?;
                self.shift = self
                    .shift
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd SEE shift overflows"))?;
            }
        }
        Ok(())
    }
}

struct RangeDecoder<'a> {
    input: &'a [u8],
    position: usize,
    low: u32,
    code: u32,
    range: u32,
    low_count: u32,
    high_count: u32,
    scale: u32,
}

#[cfg(test)]
struct RangeEncoder {
    output: Vec<u8>,
    low: u32,
    range: u32,
    low_count: u32,
    high_count: u32,
    scale: u32,
}

#[cfg(test)]
impl RangeEncoder {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            low: 0,
            range: u32::MAX,
            low_count: 0,
            high_count: 0,
            scale: 0,
        }
    }

    fn normalize(&mut self) {
        loop {
            let shares_top_byte = (self.low ^ self.low.wrapping_add(self.range)) < TOP;
            if !shares_top_byte && self.range < BOTTOM {
                self.range = self.low.wrapping_neg() & (BOTTOM - 1);
            } else if !shares_top_byte {
                break;
            }
            self.output.push(self.low.to_be_bytes()[0]);
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn encode(&mut self) -> Result<()> {
        if self.scale == 0 || self.low_count >= self.high_count || self.high_count > self.scale {
            return Err(format_error("ZIP PPMd test encoder subrange is invalid"));
        }
        self.range /= self.scale;
        if self.range == 0 {
            return Err(format_error("ZIP PPMd test encoder range collapsed"));
        }
        self.low = self
            .low
            .wrapping_add(self.low_count.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(self.high_count - self.low_count);
        Ok(())
    }

    fn encode_shifted(&mut self, shift: u32) -> Result<()> {
        if self.low_count >= self.high_count || self.high_count > (1 << shift) {
            return Err(format_error(
                "ZIP PPMd test encoder binary subrange is invalid",
            ));
        }
        self.range >>= shift;
        if self.range == 0 {
            return Err(format_error("ZIP PPMd test encoder binary range collapsed"));
        }
        self.low = self
            .low
            .wrapping_add(self.low_count.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(self.high_count - self.low_count);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.output.push(self.low.to_be_bytes()[0]);
            self.low <<= 8;
        }
        self.output
    }
}

impl<'a> RangeDecoder<'a> {
    fn new(input: &'a [u8], control: &mut ParseControl<'_>) -> Result<Self> {
        let initial = input
            .get(..4)
            .ok_or_else(|| format_error("ZIP PPMd range header is truncated"))?;
        control.checkpoint(4)?;
        let mut code = 0_u32;
        for byte in initial {
            code = (code << 8) | u32::from(*byte);
        }
        if code == u32::MAX {
            return Err(format_error("ZIP PPMd range header is invalid"));
        }
        Ok(Self {
            input,
            position: 4,
            low: 0,
            code,
            range: u32::MAX,
            low_count: 0,
            high_count: 0,
            scale: 0,
        })
    }

    fn normalize(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        loop {
            let sum = self.low.wrapping_add(self.range);
            let shares_top_byte = (self.low ^ sum) < TOP;
            if !shares_top_byte && self.range < BOTTOM {
                self.range = self.low.wrapping_neg() & (BOTTOM - 1);
                if self.range == 0 {
                    return Err(format_error("ZIP PPMd range normalization collapsed"));
                }
            } else if !shares_top_byte {
                break;
            }
            let byte = self
                .input
                .get(self.position)
                .copied()
                .ok_or_else(|| format_error("ZIP PPMd range stream is truncated"))?;
            self.position = self
                .position
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd input position overflows"))?;
            control.checkpoint(1)?;
            self.code = (self.code << 8) | u32::from(byte);
            self.range <<= 8;
            self.low <<= 8;
        }
        Ok(())
    }

    fn current_count(&mut self) -> Result<u32> {
        if self.scale == 0 {
            return Err(format_error("ZIP PPMd range scale is zero"));
        }
        self.range /= self.scale;
        if self.range == 0 {
            return Err(format_error("ZIP PPMd range collapsed to zero"));
        }
        let count = self.code.wrapping_sub(self.low) / self.range;
        if count >= self.scale {
            return Err(format_error("ZIP PPMd range count exceeds its scale"));
        }
        Ok(count)
    }

    fn current_shift_count(&mut self, shift: u32) -> Result<u32> {
        let scale = 1_u32
            .checked_shl(shift)
            .ok_or_else(|| format_error("ZIP PPMd binary range scale is invalid"))?;
        self.range >>= shift;
        if self.range == 0 {
            return Err(format_error("ZIP PPMd binary range collapsed to zero"));
        }
        let count = self.code.wrapping_sub(self.low) / self.range;
        if count >= scale {
            return Err(format_error(
                "ZIP PPMd binary range count exceeds its scale",
            ));
        }
        Ok(count)
    }

    fn remove_subrange(&mut self) -> Result<()> {
        if self.low_count >= self.high_count || self.high_count > self.scale {
            return Err(format_error("ZIP PPMd subrange is invalid"));
        }
        self.low = self
            .low
            .wrapping_add(self.range.wrapping_mul(self.low_count));
        self.range = self.range.wrapping_mul(self.high_count - self.low_count);
        if self.range == 0 {
            return Err(format_error("ZIP PPMd subrange collapsed to zero"));
        }
        Ok(())
    }
}

struct Allocator {
    size: u32,
    heap_start: u32,
    text: u32,
    units_start: u32,
    low_unit: u32,
    high_unit: u32,
    glue_count: u32,
    heads: [u32; N_INDEXES],
    stamps: [u32; N_INDEXES],
    index_to_units: [u8; N_INDEXES],
    units_to_index: [u8; MAX_UNITS as usize],
}

impl Allocator {
    fn new(size: u32, heap: &mut Heap) -> Result<Self> {
        if size < 1 << 20 {
            return Err(format_error("ZIP PPMd model memory is smaller than 1 MiB"));
        }
        let heap_start = 1;
        if heap.len()? != add(size, heap_start, "ZIP PPMd heap end overflows")? {
            return Err(format_error("ZIP PPMd heap layout is inconsistent"));
        }
        let mut index_to_units = [0_u8; N_INDEXES];
        let mut table_index = 0_usize;
        let mut units = 1_u8;
        while table_index < N1 {
            *checked_slot_mut(
                &mut index_to_units,
                table_index,
                "ZIP PPMd unit class is out of range",
            )? = units;
            table_index += 1;
            units += 1;
        }
        units += 1;
        while table_index < N1 + N2 {
            *checked_slot_mut(
                &mut index_to_units,
                table_index,
                "ZIP PPMd unit class is out of range",
            )? = units;
            table_index += 1;
            units += 2;
        }
        units += 1;
        while table_index < N1 + N2 + N3 {
            *checked_slot_mut(
                &mut index_to_units,
                table_index,
                "ZIP PPMd unit class is out of range",
            )? = units;
            table_index += 1;
            units += 3;
        }
        units += 1;
        while table_index < N_INDEXES {
            *checked_slot_mut(
                &mut index_to_units,
                table_index,
                "ZIP PPMd unit class is out of range",
            )? = units;
            table_index += 1;
            units += 4;
        }
        let mut units_to_index = [0_u8; MAX_UNITS as usize];
        let mut class = 0_usize;
        for requested in 1..=MAX_UNITS {
            while u32::from(*checked_slot(
                &index_to_units,
                class,
                "ZIP PPMd unit class is out of range",
            )?) < requested
            {
                class = class
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd unit class overflows"))?;
                if class >= N_INDEXES {
                    return Err(format_error("ZIP PPMd unit class is out of range"));
                }
            }
            *checked_slot_mut(
                &mut units_to_index,
                index(
                    requested - 1,
                    "ZIP PPMd unit table index is not representable",
                )?,
                "ZIP PPMd unit table index is out of range",
            )? = u8::try_from(class)
                .map_err(|_| format_error("ZIP PPMd unit class is not representable"))?;
        }
        let heap_end = add(heap_start, size, "ZIP PPMd heap end overflows")?;
        let difference = mul(
            UNIT_SIZE,
            (size / 8 / UNIT_SIZE) * 7,
            "ZIP PPMd allocator partition overflows",
        )?;
        let units_start = sub(
            heap_end,
            difference,
            "ZIP PPMd allocator partition underflows",
        )?;
        heap.put_byte(heap_start, 0)?;
        Ok(Self {
            size,
            heap_start,
            text: heap_start,
            units_start,
            low_unit: units_start,
            high_unit: heap_end,
            glue_count: 0,
            heads: [0; N_INDEXES],
            stamps: [0; N_INDEXES],
            index_to_units,
            units_to_index,
        })
    }

    fn reset(&mut self) -> Result<()> {
        let heap_end = add(self.heap_start, self.size, "ZIP PPMd heap end overflows")?;
        let difference = mul(
            UNIT_SIZE,
            (self.size / 8 / UNIT_SIZE) * 7,
            "ZIP PPMd allocator partition overflows",
        )?;
        self.text = self.heap_start;
        self.high_unit = heap_end;
        self.units_start = sub(
            heap_end,
            difference,
            "ZIP PPMd allocator partition underflows",
        )?;
        self.low_unit = self.units_start;
        self.glue_count = 0;
        self.heads.fill(0);
        self.stamps.fill(0);
        Ok(())
    }

    fn class_for(&self, units: u32) -> Result<usize> {
        if units == 0 || units > MAX_UNITS {
            return Err(format_error("ZIP PPMd unit count is out of range"));
        }
        let slot = self
            .units_to_index
            .get(index(
                units - 1,
                "ZIP PPMd unit table index is not representable",
            )?)
            .copied()
            .ok_or_else(|| format_error("ZIP PPMd unit class is unavailable"))?;
        Ok(usize::from(slot))
    }

    fn class_units(&self, class: usize) -> Result<u32> {
        self.index_to_units
            .get(class)
            .copied()
            .map(u32::from)
            .ok_or_else(|| format_error("ZIP PPMd allocation class is out of range"))
    }

    fn bytes_for_units(units: u32) -> Result<u32> {
        mul(units, UNIT_SIZE, "ZIP PPMd unit byte count overflows")
    }

    fn insert(&mut self, heap: &mut Heap, class: usize, address: u32, units: u32) -> Result<()> {
        if address < self.heap_start {
            return Err(format_error("ZIP PPMd free-block address is invalid"));
        }
        let class_units = self.class_units(class)?;
        if units == 0 || units > class_units {
            return Err(format_error("ZIP PPMd free-block size is invalid"));
        }
        heap.validate_span(address, Self::bytes_for_units(class_units)?)?;
        let head = *self
            .heads
            .get(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list class is out of range"))?;
        heap.put_u32(address, u32::MAX)?;
        heap.put_u32(add(address, 4, "ZIP PPMd free-block link overflows")?, head)?;
        heap.put_u32(
            add(address, 8, "ZIP PPMd free-block size overflows")?,
            units,
        )?;
        *self
            .heads
            .get_mut(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list class is out of range"))? = address;
        let stamp = self
            .stamps
            .get_mut(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list stamp is unavailable"))?;
        *stamp = stamp
            .checked_add(1)
            .ok_or_else(|| format_error("ZIP PPMd free-list stamp overflows"))?;
        Ok(())
    }

    fn remove(&mut self, heap: &Heap, class: usize) -> Result<Option<u32>> {
        let head = *self
            .heads
            .get(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list class is out of range"))?;
        if head == 0 {
            return Ok(None);
        }
        let units = self.class_units(class)?;
        heap.validate_span(head, Self::bytes_for_units(units)?)?;
        if heap.u32(head)? != u32::MAX {
            return Err(format_error("ZIP PPMd free-list node stamp is invalid"));
        }
        let next = heap.u32(add(head, 4, "ZIP PPMd free-block link overflows")?)?;
        if next != 0 {
            heap.validate_span(next, UNIT_SIZE)?;
        }
        *self
            .heads
            .get_mut(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list class is out of range"))? = next;
        let stamp = self
            .stamps
            .get_mut(class)
            .ok_or_else(|| format_error("ZIP PPMd free-list stamp is unavailable"))?;
        *stamp = stamp
            .checked_sub(1)
            .ok_or_else(|| format_error("ZIP PPMd free-list stamp underflows"))?;
        Ok(Some(head))
    }

    fn split_block(
        &mut self,
        heap: &mut Heap,
        address: u32,
        old_class: usize,
        new_class: usize,
    ) -> Result<()> {
        let old_units = self.class_units(old_class)?;
        let new_units = self.class_units(new_class)?;
        let mut difference = sub(old_units, new_units, "ZIP PPMd split unit count underflows")?;
        let mut remainder = add(
            address,
            Self::bytes_for_units(new_units)?,
            "ZIP PPMd split address overflows",
        )?;
        let difference_class = self.class_for(difference)?;
        if self.class_units(difference_class)? != difference {
            let prefix_class = difference_class
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd split class underflows"))?;
            let prefix_units = self.class_units(prefix_class)?;
            self.insert(heap, prefix_class, remainder, prefix_units)?;
            remainder = add(
                remainder,
                Self::bytes_for_units(prefix_units)?,
                "ZIP PPMd split remainder address overflows",
            )?;
            difference = sub(
                difference,
                prefix_units,
                "ZIP PPMd split remainder underflows",
            )?;
        }
        let final_class = self.class_for(difference)?;
        self.insert(heap, final_class, remainder, difference)
    }

    fn allocate_units(
        &mut self,
        heap: &mut Heap,
        units: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<u32>> {
        control.checkpoint(1)?;
        let class = self.class_for(units)?;
        if let Some(address) = self.remove(heap, class)? {
            return Ok(Some(address));
        }
        let bytes = Self::bytes_for_units(self.class_units(class)?)?;
        let address = self.low_unit;
        let next = add(address, bytes, "ZIP PPMd low-unit address overflows")?;
        if next <= self.high_unit {
            self.low_unit = next;
            heap.validate_span(address, bytes)?;
            return Ok(Some(address));
        }
        self.allocate_units_rare(heap, class, control)
    }

    fn allocate_context(
        &mut self,
        heap: &mut Heap,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<u32>> {
        control.checkpoint(1)?;
        if self.high_unit != self.low_unit {
            self.high_unit = sub(
                self.high_unit,
                UNIT_SIZE,
                "ZIP PPMd high-unit address underflows",
            )?;
            heap.validate_span(self.high_unit, UNIT_SIZE)?;
            return Ok(Some(self.high_unit));
        }
        if let Some(address) = self.remove(heap, 0)? {
            return Ok(Some(address));
        }
        self.allocate_units_rare(heap, 0, control)
    }

    fn allocate_units_rare(
        &mut self,
        heap: &mut Heap,
        class: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<u32>> {
        if self.glue_count == 0 {
            self.glue_free_blocks(heap, control)?;
            if let Some(address) = self.remove(heap, class)? {
                return Ok(Some(address));
            }
        }
        let mut larger = class;
        loop {
            larger = larger
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd allocation class overflows"))?;
            if larger == N_INDEXES {
                self.glue_count = self
                    .glue_count
                    .checked_sub(1)
                    .ok_or_else(|| format_error("ZIP PPMd glue counter underflows"))?;
                let bytes = Self::bytes_for_units(self.class_units(class)?)?;
                let available = sub(self.units_start, self.text, "ZIP PPMd text gap underflows")?;
                if available <= bytes {
                    return Ok(None);
                }
                self.units_start = sub(
                    self.units_start,
                    bytes,
                    "ZIP PPMd unit-start address underflows",
                )?;
                heap.validate_span(self.units_start, bytes)?;
                return Ok(Some(self.units_start));
            }
            control.checkpoint(1)?;
            if let Some(address) = self.remove(heap, larger)? {
                self.split_block(heap, address, larger, class)?;
                return Ok(Some(address));
            }
        }
    }

    fn expand_units(
        &mut self,
        heap: &mut Heap,
        old: u32,
        old_units: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<u32>> {
        let old_class = self.class_for(old_units)?;
        let new_class =
            self.class_for(add(old_units, 1, "ZIP PPMd expanded unit count overflows")?)?;
        if old_class == new_class {
            return Ok(Some(old));
        }
        let Some(new) = self.allocate_units(heap, old_units + 1, control)? else {
            return Ok(None);
        };
        heap.copy(new, old, Self::bytes_for_units(old_units)?)?;
        self.insert(heap, old_class, old, old_units)?;
        Ok(Some(new))
    }

    fn shrink_units(
        &mut self,
        heap: &mut Heap,
        old: u32,
        old_units: u32,
        new_units: u32,
    ) -> Result<u32> {
        let old_class = self.class_for(old_units)?;
        let new_class = self.class_for(new_units)?;
        if old_class == new_class {
            return Ok(old);
        }
        if let Some(new) = self.remove(heap, new_class)? {
            heap.copy(new, old, Self::bytes_for_units(new_units)?)?;
            self.insert(heap, old_class, old, self.class_units(old_class)?)?;
            return Ok(new);
        }
        self.split_block(heap, old, old_class, new_class)?;
        Ok(old)
    }

    fn free_units(&mut self, heap: &mut Heap, address: u32, units: u32) -> Result<()> {
        let class = self.class_for(units)?;
        self.insert(heap, class, address, self.class_units(class)?)
    }

    fn special_free_unit(&mut self, heap: &mut Heap, address: u32) -> Result<()> {
        if address != self.units_start {
            self.insert(heap, 0, address, 1)
        } else {
            heap.put_u32(address, u32::MAX)?;
            self.units_start = add(
                self.units_start,
                UNIT_SIZE,
                "ZIP PPMd unit-start address overflows",
            )?;
            Ok(())
        }
    }

    fn move_units_up(&mut self, heap: &mut Heap, old: u32, units: u32) -> Result<u32> {
        let class = self.class_for(units)?;
        let head = *checked_slot(
            &self.heads,
            class,
            "ZIP PPMd free-list class is out of range",
        )?;
        let locality_limit = add(
            self.units_start,
            16 * 1024,
            "ZIP PPMd locality boundary overflows",
        )?;
        if old > locality_limit || old > head {
            return Ok(old);
        }
        let new = self
            .remove(heap, class)?
            .ok_or_else(|| format_error("ZIP PPMd move source free-list is empty"))?;
        heap.copy(new, old, Self::bytes_for_units(units)?)?;
        let class_units = self.class_units(class)?;
        if old != self.units_start {
            self.insert(heap, class, old, class_units)?;
        } else {
            self.units_start = add(
                self.units_start,
                Self::bytes_for_units(class_units)?,
                "ZIP PPMd unit-start address overflows",
            )?;
        }
        Ok(new)
    }

    fn glue_free_blocks(&mut self, heap: &mut Heap, control: &mut ParseControl<'_>) -> Result<()> {
        if self.low_unit != self.high_unit {
            heap.put_byte(self.low_unit, 0)?;
        }
        let maximum_nodes = self.size / UNIT_SIZE + 1;
        let mut nodes = Vec::new();
        for class in 0..N_INDEXES {
            while let Some(address) = self.remove(heap, class)? {
                control.checkpoint(1)?;
                if u64::try_from(nodes.len())
                    .map_err(|_| format_error("ZIP PPMd glue node count is not representable"))?
                    >= u64::from(maximum_nodes)
                {
                    return Err(format_error("ZIP PPMd free-block list contains a cycle"));
                }
                let mut units = heap.u32(add(
                    address,
                    8,
                    "ZIP PPMd free-block size address overflows",
                )?)?;
                if units == 0 {
                    continue;
                }
                if units > self.size / UNIT_SIZE {
                    return Err(format_error("ZIP PPMd free-block size is invalid"));
                }
                loop {
                    let adjacent = add(
                        address,
                        Self::bytes_for_units(units)?,
                        "ZIP PPMd adjacent block address overflows",
                    )?;
                    if adjacent >= heap.len()? || heap.u32(adjacent)? != u32::MAX {
                        break;
                    }
                    let adjacent_units =
                        heap.u32(add(adjacent, 8, "ZIP PPMd adjacent block size overflows")?)?;
                    if adjacent_units == 0 {
                        break;
                    }
                    units = add(
                        units,
                        adjacent_units,
                        "ZIP PPMd merged unit count overflows",
                    )?;
                    if units > self.size / UNIT_SIZE {
                        return Err(format_error("ZIP PPMd merged free block is too large"));
                    }
                    heap.put_u32(
                        add(adjacent, 8, "ZIP PPMd adjacent block size overflows")?,
                        0,
                    )?;
                    control.checkpoint(1)?;
                }
                heap.put_u32(
                    add(address, 8, "ZIP PPMd free-block size address overflows")?,
                    units,
                )?;
                nodes.try_reserve(1).map_err(|_| {
                    Error::Io(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "ZIP PPMd glue-node allocation failed",
                    ))
                })?;
                nodes.push(address);
            }
        }
        for mut address in nodes {
            control.checkpoint(1)?;
            let mut units = heap.u32(add(
                address,
                8,
                "ZIP PPMd free-block size address overflows",
            )?)?;
            if units == 0 {
                continue;
            }
            while units > MAX_UNITS {
                control.checkpoint(1)?;
                self.insert(heap, N_INDEXES - 1, address, MAX_UNITS)?;
                address = add(
                    address,
                    Self::bytes_for_units(MAX_UNITS)?,
                    "ZIP PPMd glue block address overflows",
                )?;
                units = sub(units, MAX_UNITS, "ZIP PPMd glue size underflows")?;
            }
            let mut class = self.class_for(units)?;
            if self.class_units(class)? != units {
                class = class
                    .checked_sub(1)
                    .ok_or_else(|| format_error("ZIP PPMd glue class underflows"))?;
                let prefix = self.class_units(class)?;
                let remainder = sub(units, prefix, "ZIP PPMd glue remainder underflows")?;
                let remainder_address = add(
                    address,
                    Self::bytes_for_units(prefix)?,
                    "ZIP PPMd glue remainder address overflows",
                )?;
                let remainder_class = index(
                    sub(remainder, 1, "ZIP PPMd glue remainder class underflows")?,
                    "ZIP PPMd glue remainder class is not representable",
                )?;
                self.insert(heap, remainder_class, remainder_address, remainder)?;
            }
            self.insert(heap, class, address, self.class_units(class)?)?;
        }
        self.glue_count = 1 << 13;
        Ok(())
    }

    fn expand_text(&mut self, heap: &mut Heap, control: &mut ParseControl<'_>) -> Result<()> {
        let mut counts = [0_u32; N_INDEXES];
        let maximum_nodes = self.size / UNIT_SIZE + 1;
        let mut steps = 0_u32;
        while self.units_start < heap.len()? && heap.u32(self.units_start)? == u32::MAX {
            steps = add(steps, 1, "ZIP PPMd text expansion step count overflows")?;
            if steps > maximum_nodes {
                return Err(format_error("ZIP PPMd text boundary contains a cycle"));
            }
            control.checkpoint(1)?;
            let units = heap.u32(add(
                self.units_start,
                8,
                "ZIP PPMd free-block size address overflows",
            )?)?;
            let class = self.class_for(units)?;
            self.units_start = add(
                self.units_start,
                Self::bytes_for_units(units)?,
                "ZIP PPMd unit-start address overflows",
            )?;
            let count = checked_slot_mut(
                &mut counts,
                class,
                "ZIP PPMd free-block class is out of range",
            )?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd free-block count overflows"))?;
            let old_address = sub(
                self.units_start,
                Self::bytes_for_units(units)?,
                "ZIP PPMd expanded block address underflows",
            )?;
            heap.put_u32(old_address, 0)?;
        }
        for (class, count) in counts.iter().copied().enumerate() {
            let mut previous = 0_u32;
            let mut current = *checked_slot(
                &self.heads,
                class,
                "ZIP PPMd free-list class is out of range",
            )?;
            let mut remaining = count;
            let mut traversed = 0_u32;
            while current != 0 && remaining != 0 {
                traversed = add(traversed, 1, "ZIP PPMd free-list traversal count overflows")?;
                if traversed > maximum_nodes {
                    return Err(format_error("ZIP PPMd free-block list contains a cycle"));
                }
                control.checkpoint(1)?;
                let next = heap.u32(add(
                    current,
                    4,
                    "ZIP PPMd free-block link address overflows",
                )?)?;
                if heap.u32(current)? == 0 {
                    if previous == 0 {
                        *checked_slot_mut(
                            &mut self.heads,
                            class,
                            "ZIP PPMd free-list class is out of range",
                        )? = next;
                    } else {
                        heap.put_u32(
                            add(previous, 4, "ZIP PPMd free-block link address overflows")?,
                            next,
                        )?;
                    }
                    let stamp = checked_slot_mut(
                        &mut self.stamps,
                        class,
                        "ZIP PPMd free-list stamp is unavailable",
                    )?;
                    *stamp = stamp
                        .checked_sub(1)
                        .ok_or_else(|| format_error("ZIP PPMd free-list stamp underflows"))?;
                    remaining -= 1;
                } else {
                    previous = current;
                }
                current = next;
            }
            if remaining != 0 {
                return Err(format_error(
                    "ZIP PPMd expanded free blocks are missing from their lists",
                ));
            }
        }
        Ok(())
    }

    fn used_memory(&self) -> Result<u32> {
        let free_units = sub(
            self.high_unit,
            self.low_unit,
            "ZIP PPMd free-unit span underflows",
        )?;
        let free_text = sub(
            self.units_start,
            self.text,
            "ZIP PPMd free-text span underflows",
        )?;
        let mut used = sub(
            sub(self.size, free_units, "ZIP PPMd used memory underflows")?,
            free_text,
            "ZIP PPMd used memory underflows",
        )?;
        for (class, stamp) in self.stamps.iter().copied().enumerate() {
            let bytes = mul(
                Self::bytes_for_units(self.class_units(class)?)?,
                stamp,
                "ZIP PPMd free-list byte count overflows",
            )?;
            used = sub(used, bytes, "ZIP PPMd used memory underflows")?;
        }
        Ok(used)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Restoration {
    Restart,
    CutOff,
    Freeze,
    Frozen,
}

impl Restoration {
    fn parse(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Restart),
            1 => Ok(Self::CutOff),
            2 => Ok(Self::Freeze),
            _ => Err(format_error(
                "ZIP PPMd restoration method is outside zero through two",
            )),
        }
    }
}

struct Model<'a> {
    heap: Heap,
    allocator: Allocator,
    decoder: RangeDecoder<'a>,
    maximum_context: Context,
    found_state: State,
    model_order: u8,
    order_fall: u8,
    initial_escape: u8,
    initial_run_length: i32,
    run_length: i32,
    previous_success: u8,
    number_masked: u8,
    restoration: Restoration,
    escape_count: u8,
    character_mask: [u8; 256],
    number_statistics_to_binary_index: [u8; 256],
    probabilities: [u8; 260],
    binary_summary: [[u16; 64]; 25],
    see2: [[See2; 32]; 24],
    dummy_see2: See2,
    #[cfg(test)]
    restoration_count: u32,
}

impl<'a> Model<'a> {
    fn new(
        order: u8,
        memory_size: u32,
        restoration: Restoration,
        input: &'a [u8],
        control: &mut ParseControl<'_>,
    ) -> Result<Self> {
        if !(2..=MAX_ORDER).contains(&order) {
            return Err(format_error(
                "ZIP PPMd order is outside two through sixteen",
            ));
        }
        let decoder = RangeDecoder::new(input, control)?;
        // Heap initialization zeroes attacker-selected model memory after its
        // dictionary limit has been validated by the caller. Charge that work
        // and observe cancellation before allocating it.
        control.checkpoint(u64::from(memory_size))?;
        let mut heap = Heap::new(memory_size)?;
        let allocator = Allocator::new(memory_size, &mut heap)?;
        let mut model = Self {
            heap,
            allocator,
            decoder,
            maximum_context: Context(0),
            found_state: State(0),
            model_order: order,
            order_fall: order,
            initial_escape: 0,
            initial_run_length: 0,
            run_length: 0,
            previous_success: 0,
            number_masked: 0,
            restoration,
            escape_count: 1,
            character_mask: [0; 256],
            number_statistics_to_binary_index: [0; 256],
            probabilities: [0; 260],
            binary_summary: [[0; 64]; 25],
            see2: [[See2::default(); 32]; 24],
            dummy_see2: See2 {
                summary: 0xaf8f,
                shift: 0xac,
                count: 0x84,
            },
            #[cfg(test)]
            restoration_count: 0,
        };
        model.initialize_tables()?;
        model.start_model(control)?;
        Ok(model)
    }

    fn initialize_tables(&mut self) -> Result<()> {
        self.number_statistics_to_binary_index[0] = 0;
        self.number_statistics_to_binary_index[1] = 2;
        self.number_statistics_to_binary_index[2..11].fill(4);
        self.number_statistics_to_binary_index[11..].fill(6);

        for (slot, value) in self.probabilities[..5].iter_mut().zip(0_u8..5) {
            *slot = value;
        }
        let mut count = 1_u32;
        let mut step = 1_u32;
        let mut probability = 5_u32;
        for slot in self.probabilities.iter_mut().skip(5) {
            *slot = u8::try_from(probability)
                .map_err(|_| format_error("ZIP PPMd probability is out of range"))?;
            count = count
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd probability count underflows"))?;
            if count == 0 {
                step = step
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd probability step overflows"))?;
                count = step;
                probability = probability
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd probability overflows"))?;
            }
        }
        Ok(())
    }

    fn start_model(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        self.character_mask.fill(0);
        self.escape_count = 1;
        self.order_fall = self.model_order;
        self.allocator.reset()?;
        self.initial_run_length = -i32::from(self.model_order.min(12)) - 1;
        self.run_length = self.initial_run_length;
        let context = self
            .allocator
            .allocate_context(&mut self.heap, control)?
            .ok_or_else(|| format_error("ZIP PPMd initial context allocation failed"))?;
        self.maximum_context = Context(context);
        self.maximum_context
            .set_suffix(&mut self.heap, Context(0))?;
        self.maximum_context.set_num_stats(&mut self.heap, 255)?;
        self.maximum_context.set_summary(&mut self.heap, 257)?;
        let statistics = self
            .allocator
            .allocate_units(&mut self.heap, 128, control)?
            .ok_or_else(|| format_error("ZIP PPMd initial state allocation failed"))?;
        self.maximum_context
            .set_statistics(&mut self.heap, State(statistics))?;
        self.previous_success = 0;
        for symbol in 0..=255_u32 {
            control.checkpoint(1)?;
            let state = State(statistics).offset(
                i32::try_from(symbol)
                    .map_err(|_| format_error("ZIP PPMd initial state index is invalid"))?,
            )?;
            state.set_symbol(
                &mut self.heap,
                u8::try_from(symbol)
                    .map_err(|_| format_error("ZIP PPMd initial symbol is invalid"))?,
            )?;
            state.set_frequency(&mut self.heap, 1)?;
            state.set_successor(&mut self.heap, 0)?;
        }

        let mut probability = 0_usize;
        let mut probability_index = 0_usize;
        while probability < self.binary_summary.len() {
            control.checkpoint(1)?;
            while self
                .probabilities
                .get(probability_index)
                .copied()
                .ok_or_else(|| format_error("ZIP PPMd probability index is out of range"))?
                == u8::try_from(probability)
                    .map_err(|_| format_error("ZIP PPMd probability is invalid"))?
            {
                probability_index = probability_index
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd probability index overflows"))?;
            }
            let row = self
                .binary_summary
                .get_mut(probability)
                .ok_or_else(|| format_error("ZIP PPMd binary row is out of range"))?;
            for (slot, escape) in row
                .iter_mut()
                .take(INITIAL_BINARY_ESCAPES.len())
                .zip(INITIAL_BINARY_ESCAPES.iter().copied())
            {
                *slot = u16::try_from(
                    BIN_SCALE
                        - u32::from(escape)
                            / u32::try_from(probability_index + 1).map_err(|_| {
                                format_error("ZIP PPMd probability divisor is invalid")
                            })?,
                )
                .map_err(|_| format_error("ZIP PPMd binary summary is out of range"))?;
            }
            let (base, repeated) = row.split_at_mut(INITIAL_BINARY_ESCAPES.len());
            for (column, slot) in repeated.iter_mut().enumerate() {
                *slot = *checked_slot(
                    base,
                    column % INITIAL_BINARY_ESCAPES.len(),
                    "ZIP PPMd initial binary summary is unavailable",
                )?;
            }
            probability += 1;
        }

        probability_index = 0;
        for probability in 0..self.see2.len() {
            control.checkpoint(1)?;
            while self
                .probabilities
                .get(probability_index + 3)
                .copied()
                .ok_or_else(|| format_error("ZIP PPMd SEE probability is out of range"))?
                == u8::try_from(probability + 3)
                    .map_err(|_| format_error("ZIP PPMd SEE probability is invalid"))?
            {
                probability_index = probability_index
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd SEE index overflows"))?;
            }
            let initial = u32::try_from(probability_index)
                .map_err(|_| format_error("ZIP PPMd SEE index is invalid"))?
                .checked_mul(2)
                .and_then(|value| value.checked_add(5))
                .ok_or_else(|| format_error("ZIP PPMd SEE initialization overflows"))?;
            for slot in self
                .see2
                .get_mut(probability)
                .ok_or_else(|| format_error("ZIP PPMd SEE row is out of range"))?
            {
                slot.initialize(initial)?;
            }
        }
        Ok(())
    }

    fn validate_context(&self, context: Context) -> Result<()> {
        if context.0 < self.allocator.units_start {
            return Err(format_error("ZIP PPMd context address is not allocated"));
        }
        self.heap.validate_span(context.0, UNIT_SIZE)
    }

    fn validate_statistics(&self, context: Context) -> Result<State> {
        self.validate_context(context)?;
        let state = context.statistics(&self.heap)?;
        let count = u32::from(context.num_stats(&self.heap)?) + 1;
        let bytes = mul(count, STATE_SIZE, "ZIP PPMd state span overflows")?;
        self.heap.validate_span(state.0, bytes)?;
        Ok(state)
    }

    fn mask(&self, symbol: u8) -> Result<u8> {
        self.character_mask
            .get(usize::from(symbol))
            .copied()
            .ok_or_else(|| format_error("ZIP PPMd character mask index is invalid"))
    }

    fn set_mask(&mut self, symbol: u8) -> Result<()> {
        *self
            .character_mask
            .get_mut(usize::from(symbol))
            .ok_or_else(|| format_error("ZIP PPMd character mask index is invalid"))? =
            self.escape_count;
        Ok(())
    }

    fn mean(value: u16) -> u16 {
        (value + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS
    }

    fn binary_indexes(&self, context: Context, state: State) -> Result<(usize, usize)> {
        let frequency = state.frequency(&self.heap)?;
        let frequency_index = frequency
            .checked_sub(1)
            .ok_or_else(|| format_error("ZIP PPMd binary state frequency is zero"))?;
        let row = usize::from(
            *self
                .probabilities
                .get(usize::from(frequency_index))
                .ok_or_else(|| format_error("ZIP PPMd binary probability is unavailable"))?,
        );
        let suffix = context.suffix(&self.heap)?;
        self.validate_context(suffix)?;
        let suffix_statistics = suffix.num_stats(&self.heap)?;
        let base = *self
            .number_statistics_to_binary_index
            .get(usize::from(suffix_statistics))
            .ok_or_else(|| format_error("ZIP PPMd binary context index is unavailable"))?;
        let run = u8::try_from((self.run_length >> 26) & 0x20)
            .map_err(|_| format_error("ZIP PPMd run-length index is invalid"))?;
        let column = base
            .checked_add(self.previous_success)
            .and_then(|value| value.checked_add(context.flags(&self.heap).ok()?))
            .and_then(|value| value.checked_add(run))
            .ok_or_else(|| format_error("ZIP PPMd binary column overflows"))?;
        if row >= 25 || usize::from(column) >= 64 {
            return Err(format_error("ZIP PPMd binary table index is out of range"));
        }
        Ok((row, usize::from(column)))
    }

    fn binary_summary_value(&self, row: usize, column: usize) -> Result<u16> {
        let values = checked_slot(
            &self.binary_summary,
            row,
            "ZIP PPMd binary row is unavailable",
        )?;
        checked_slot(values, column, "ZIP PPMd binary summary is unavailable").copied()
    }

    fn set_binary_summary(&mut self, row: usize, column: usize, value: u16) -> Result<()> {
        let values = checked_slot_mut(
            &mut self.binary_summary,
            row,
            "ZIP PPMd binary row is unavailable",
        )?;
        *checked_slot_mut(values, column, "ZIP PPMd binary summary is unavailable")? = value;
        Ok(())
    }

    fn see2_mut(&mut self, row: usize, column: usize) -> Result<&mut See2> {
        let values = checked_slot_mut(&mut self.see2, row, "ZIP PPMd SEE row is unavailable")?;
        checked_slot_mut(values, column, "ZIP PPMd SEE context is unavailable")
    }

    fn decode_binary(&mut self, context: Context) -> Result<()> {
        self.validate_context(context)?;
        if context.num_stats(&self.heap)? != 0 {
            return Err(format_error("ZIP PPMd binary context has multiple states"));
        }
        let state = context.first_state()?;
        self.heap.validate_span(state.0, STATE_SIZE)?;
        let (row, column) = self.binary_indexes(context, state)?;
        let summary = self.binary_summary_value(row, column)?;
        self.decoder.scale = BIN_SCALE;
        let count = self.decoder.current_shift_count(14)?;
        if count < u32::from(summary) {
            self.found_state = state;
            if state.frequency(&self.heap)? < 196 {
                state.add_frequency(&mut self.heap, 1)?;
            }
            self.decoder.low_count = 0;
            self.decoder.high_count = u32::from(summary);
            let adjustment = INTERVAL
                .checked_sub(u32::from(Self::mean(summary)))
                .ok_or_else(|| format_error("ZIP PPMd binary adjustment underflows"))?;
            let updated = u32::from(summary)
                .checked_add(adjustment)
                .ok_or_else(|| format_error("ZIP PPMd binary summary overflows"))?;
            self.set_binary_summary(
                row,
                column,
                u16::try_from(updated)
                    .map_err(|_| format_error("ZIP PPMd binary summary is out of range"))?,
            )?;
            self.previous_success = 1;
            self.run_length = self.run_length.wrapping_add(1);
        } else {
            self.decoder.low_count = u32::from(summary);
            let updated = summary
                .checked_sub(Self::mean(summary))
                .ok_or_else(|| format_error("ZIP PPMd binary summary underflows"))?;
            self.set_binary_summary(row, column, updated)?;
            self.decoder.high_count = BIN_SCALE;
            let escape_index = usize::from(updated >> 10);
            self.initial_escape = *EXPONENTIAL_ESCAPES
                .get(escape_index)
                .ok_or_else(|| format_error("ZIP PPMd escape index is out of range"))?;
            self.set_mask(state.symbol(&self.heap)?)?;
            self.previous_success = 0;
            self.number_masked = 0;
            self.found_state = State(0);
        }
        Ok(())
    }

    fn decode_symbol1(&mut self, context: Context, control: &mut ParseControl<'_>) -> Result<()> {
        let raw_count = context.num_stats(&self.heap)?;
        if raw_count == 0 {
            return Err(format_error("ZIP PPMd multi-state context is binary"));
        }
        let first = self.validate_statistics(context)?;
        self.decoder.scale = u32::from(context.summary(&self.heap)?);
        let count = self.decoder.current_count()?;
        let mut state = first;
        let mut high = u32::from(state.frequency(&self.heap)?);
        if count < high {
            self.decoder.low_count = 0;
            self.decoder.high_count = high;
            self.previous_success = u8::from(2 * high >= self.decoder.scale);
            self.found_state = state;
            high = high
                .checked_add(4)
                .ok_or_else(|| format_error("ZIP PPMd state frequency overflows"))?;
            state.set_frequency(
                &mut self.heap,
                u8::try_from(high)
                    .map_err(|_| format_error("ZIP PPMd state frequency is out of range"))?,
            )?;
            context.add_summary(&mut self.heap, 4)?;
            self.run_length = self
                .run_length
                .wrapping_add(i32::from(self.previous_success));
            if high > u32::from(MAX_FREQUENCY) {
                self.rescale(context, control)?;
            }
            return Ok(());
        }

        self.previous_success = 0;
        let mut remaining = u32::from(raw_count);
        loop {
            control.checkpoint(1)?;
            state = state.offset(1)?;
            high = high
                .checked_add(u32::from(state.frequency(&self.heap)?))
                .ok_or_else(|| format_error("ZIP PPMd cumulative frequency overflows"))?;
            if high > count {
                self.decoder.high_count = high;
                self.decoder.low_count = high
                    .checked_sub(u32::from(state.frequency(&self.heap)?))
                    .ok_or_else(|| format_error("ZIP PPMd frequency start underflows"))?;
                self.update1(state, context, control)?;
                return Ok(());
            }
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd state count underflows"))?;
            if remaining == 0 {
                self.decoder.low_count = high;
                self.set_mask(state.symbol(&self.heap)?)?;
                self.number_masked = raw_count;
                self.found_state = State(0);
                let mut backwards = u32::from(raw_count);
                while backwards != 0 {
                    control.checkpoint(1)?;
                    state = state.offset(-1)?;
                    self.set_mask(state.symbol(&self.heap)?)?;
                    backwards -= 1;
                }
                self.decoder.high_count = self.decoder.scale;
                return Ok(());
            }
        }
    }

    fn make_escape_frequency(&mut self, context: Context) -> Result<Option<(usize, usize)>> {
        let raw_count = context.num_stats(&self.heap)?;
        if raw_count == u8::MAX {
            self.decoder.scale = 1;
            return Ok(None);
        }
        let suffix = context.suffix(&self.heap)?;
        self.validate_context(suffix)?;
        let suffix_count = suffix.num_stats(&self.heap)?;
        let probability_index = usize::from(raw_count) + 2;
        let row = self
            .probabilities
            .get(probability_index)
            .copied()
            .ok_or_else(|| format_error("ZIP PPMd SEE probability is unavailable"))?
            .checked_sub(3)
            .ok_or_else(|| format_error("ZIP PPMd SEE row underflows"))?;
        let summary = u32::from(context.summary(&self.heap)?);
        let state_count = u32::from(raw_count) + 1;
        let column = u32::from(summary > 11 * state_count)
            + 2 * u32::from(
                2 * u32::from(raw_count) < u32::from(suffix_count) + u32::from(self.number_masked),
            )
            + u32::from(context.flags(&self.heap)?);
        let row = usize::from(row);
        let column = index(column, "ZIP PPMd SEE column is not representable")?;
        let slot = self
            .see2
            .get_mut(row)
            .and_then(|values| values.get_mut(column))
            .ok_or_else(|| format_error("ZIP PPMd SEE context index is out of range"))?;
        self.decoder.scale = slot.mean()?;
        Ok(Some((row, column)))
    }

    fn decode_symbol2(&mut self, context: Context, control: &mut ParseControl<'_>) -> Result<()> {
        let see_slot = self.make_escape_frequency(context)?;
        let raw_count = context.num_stats(&self.heap)?;
        let available = raw_count
            .checked_sub(self.number_masked)
            .ok_or_else(|| format_error("ZIP PPMd masked-state count exceeds context count"))?;
        if available == 0 {
            return Err(format_error("ZIP PPMd context has no unmasked states"));
        }
        let first = self.validate_statistics(context)?;
        let mut addresses = [0_u32; 256];
        let mut found = 0_usize;
        let mut cursor = first;
        let mut visited = 0_u32;
        let total_states = u32::from(raw_count) + 1;
        let target = usize::from(available);
        let mut high = 0_u32;
        while found < target {
            if visited >= total_states {
                return Err(format_error(
                    "ZIP PPMd unmasked state count is inconsistent",
                ));
            }
            control.checkpoint(1)?;
            let symbol = cursor.symbol(&self.heap)?;
            if self.mask(symbol)? != self.escape_count {
                high = high
                    .checked_add(u32::from(cursor.frequency(&self.heap)?))
                    .ok_or_else(|| format_error("ZIP PPMd symbol frequency total overflows"))?;
                *addresses
                    .get_mut(found)
                    .ok_or_else(|| format_error("ZIP PPMd decode-state index is invalid"))? =
                    cursor.0;
                found += 1;
            }
            visited += 1;
            if visited < total_states {
                cursor = cursor.offset(1)?;
            }
        }
        self.decoder.scale = self
            .decoder
            .scale
            .checked_add(high)
            .ok_or_else(|| format_error("ZIP PPMd escape scale overflows"))?;
        let count = self.decoder.current_count()?;
        if count < high {
            let mut cumulative = 0_u32;
            let mut selected = None;
            for address in addresses
                .get(..found)
                .ok_or_else(|| format_error("ZIP PPMd decode-state range is invalid"))?
            {
                control.checkpoint(1)?;
                let state = State(*address);
                cumulative = cumulative
                    .checked_add(u32::from(state.frequency(&self.heap)?))
                    .ok_or_else(|| format_error("ZIP PPMd symbol frequency total overflows"))?;
                if cumulative > count {
                    selected = Some(state);
                    break;
                }
            }
            let selected = selected
                .ok_or_else(|| format_error("ZIP PPMd failed to select an unmasked state"))?;
            self.decoder.high_count = cumulative;
            self.decoder.low_count = cumulative
                .checked_sub(u32::from(selected.frequency(&self.heap)?))
                .ok_or_else(|| format_error("ZIP PPMd symbol frequency start underflows"))?;
            if let Some((row, column)) = see_slot {
                self.see2_mut(row, column)?.update()?;
            } else {
                self.dummy_see2.update()?;
            }
            self.update2(selected, context, control)?;
        } else {
            self.decoder.low_count = high;
            self.decoder.high_count = self.decoder.scale;
            self.number_masked = raw_count;
            for address in addresses
                .get(..found)
                .ok_or_else(|| format_error("ZIP PPMd decode-state range is invalid"))?
            {
                control.checkpoint(1)?;
                self.set_mask(State(*address).symbol(&self.heap)?)?;
            }
            if let Some((row, column)) = see_slot {
                let increment = u16::try_from(self.decoder.scale)
                    .map_err(|_| format_error("ZIP PPMd SEE increment is out of range"))?;
                let see = self.see2_mut(row, column)?;
                see.summary = see.summary.wrapping_add(increment);
            } else {
                let increment = u16::try_from(self.decoder.scale)
                    .map_err(|_| format_error("ZIP PPMd SEE increment is out of range"))?;
                self.dummy_see2.summary = self.dummy_see2.summary.wrapping_add(increment);
            }
        }
        Ok(())
    }

    fn update1(
        &mut self,
        state: State,
        context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        self.found_state = state;
        state.add_frequency(&mut self.heap, 4)?;
        context.add_summary(&mut self.heap, 4)?;
        let first = context.statistics(&self.heap)?;
        if state != first {
            let previous = state.offset(-1)?;
            if state.frequency(&self.heap)? > previous.frequency(&self.heap)? {
                swap_states(&mut self.heap, state, previous)?;
                self.found_state = previous;
                if previous.frequency(&self.heap)? > MAX_FREQUENCY {
                    self.rescale(context, control)?;
                }
            }
        }
        Ok(())
    }

    fn update2(
        &mut self,
        state: State,
        context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        self.found_state = state;
        state.add_frequency(&mut self.heap, 4)?;
        context.add_summary(&mut self.heap, 4)?;
        if state.frequency(&self.heap)? > MAX_FREQUENCY {
            self.rescale(context, control)?;
        }
        self.escape_count = self.escape_count.wrapping_add(1);
        self.run_length = self.initial_run_length;
        Ok(())
    }

    fn rescale(&mut self, context: Context, control: &mut ParseControl<'_>) -> Result<()> {
        control.checkpoint(1)?;
        let first = self.validate_statistics(context)?;
        let raw_count = context.num_stats(&self.heap)?;
        let mut found = self.found_state;
        let mut moves = 0_u32;
        while found != first {
            if moves >= u32::from(raw_count) {
                return Err(format_error("ZIP PPMd found state is outside its context"));
            }
            let previous = found.offset(-1)?;
            swap_states(&mut self.heap, found, previous)?;
            found = previous;
            moves = moves
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd rescale traversal overflows"))?;
            control.checkpoint(1)?;
        }
        found.add_frequency(&mut self.heap, 4)?;
        context.add_summary(&mut self.heap, 4)?;
        let mut escape_frequency = u32::from(context.summary(&self.heap)?)
            .checked_sub(u32::from(found.frequency(&self.heap)?))
            .ok_or_else(|| format_error("ZIP PPMd escape frequency underflows"))?;
        let adder = u8::from(self.order_fall != 0 || self.restoration == Restoration::Frozen);
        let first_frequency = (found.frequency(&self.heap)? + adder) >> 1;
        found.set_frequency(&mut self.heap, first_frequency)?;
        context.set_summary(&mut self.heap, u16::from(first_frequency))?;

        let state_count = u32::from(raw_count) + 1;
        for state_index in 1..state_count {
            control.checkpoint(1)?;
            let state = first.offset(i32::try_from(state_index).map_err(|_| {
                format_error("ZIP PPMd rescale state index is not representable")
            })?)?;
            escape_frequency = escape_frequency
                .checked_sub(u32::from(state.frequency(&self.heap)?))
                .ok_or_else(|| format_error("ZIP PPMd escape frequency underflows"))?;
            let frequency = (state.frequency(&self.heap)? + adder) >> 1;
            state.set_frequency(&mut self.heap, frequency)?;
            context.add_summary(&mut self.heap, u16::from(frequency))?;

            if frequency > state.offset(-1)?.frequency(&self.heap)? {
                let value = state.value(&self.heap)?;
                let mut position = state;
                while position != first {
                    control.checkpoint(1)?;
                    let previous = position.offset(-1)?;
                    if value.frequency <= previous.frequency(&self.heap)? {
                        break;
                    }
                    let previous_value = previous.value(&self.heap)?;
                    position.set_value(&mut self.heap, previous_value)?;
                    position = previous;
                }
                position.set_value(&mut self.heap, value)?;
            }
        }

        let mut last_nonzero = state_count;
        while last_nonzero > 0 {
            control.checkpoint(1)?;
            let state = first.offset(i32::try_from(last_nonzero - 1).map_err(|_| {
                format_error("ZIP PPMd rescale state index is not representable")
            })?)?;
            if state.frequency(&self.heap)? != 0 {
                break;
            }
            last_nonzero -= 1;
        }
        if last_nonzero == 0 {
            return Err(format_error("ZIP PPMd rescale removed every state"));
        }
        let removed = state_count - last_nonzero;
        if removed != 0 {
            escape_frequency = escape_frequency
                .checked_add(removed)
                .ok_or_else(|| format_error("ZIP PPMd escape frequency overflows"))?;
            let old_units = (u32::from(raw_count) + 2) >> 1;
            let new_raw = u32::from(raw_count)
                .checked_sub(removed)
                .ok_or_else(|| format_error("ZIP PPMd context state count underflows"))?;
            context.set_num_stats(
                &mut self.heap,
                u8::try_from(new_raw)
                    .map_err(|_| format_error("ZIP PPMd context state count is invalid"))?,
            )?;
            if new_raw == 0 {
                let mut value = first.value(&self.heap)?;
                let escape_bias = escape_frequency
                    .checked_sub(1)
                    .ok_or_else(|| format_error("ZIP PPMd escape frequency is zero"))?;
                let numerator = 2_u32
                    .checked_mul(u32::from(value.frequency))
                    .and_then(|number| number.checked_add(escape_bias))
                    .ok_or_else(|| format_error("ZIP PPMd binary frequency overflows"))?;
                value.frequency = u8::try_from(numerator / escape_frequency)
                    .map_err(|_| format_error("ZIP PPMd binary frequency is invalid"))?
                    .min(MAX_FREQUENCY / 3);
                self.allocator
                    .free_units(&mut self.heap, first.0, old_units)?;
                let one = context.first_state()?;
                one.set_value(&mut self.heap, value)?;
                let flags = (context.flags(&self.heap)? & 0x10)
                    + if value.symbol >= 0x40 { 0x08 } else { 0 };
                context.set_flags(&mut self.heap, flags)?;
                self.found_state = one;
                return Ok(());
            }
            let new_units = (new_raw + 2) >> 1;
            let statistics =
                self.allocator
                    .shrink_units(&mut self.heap, first.0, old_units, new_units)?;
            context.set_statistics(&mut self.heap, State(statistics))?;
            let mut flags = context.flags(&self.heap)? & !0x08;
            for state_index in 0..=new_raw {
                control.checkpoint(1)?;
                let state =
                    State(statistics).offset(i32::try_from(state_index).map_err(|_| {
                        format_error("ZIP PPMd rescale state index is not representable")
                    })?)?;
                if state.symbol(&self.heap)? >= 0x40 {
                    flags |= 0x08;
                }
            }
            context.set_flags(&mut self.heap, flags)?;
        }
        escape_frequency -= escape_frequency >> 1;
        context.add_summary(
            &mut self.heap,
            u16::try_from(escape_frequency)
                .map_err(|_| format_error("ZIP PPMd escape frequency is out of range"))?,
        )?;
        let flags = context.flags(&self.heap)? | 0x04;
        context.set_flags(&mut self.heap, flags)?;
        self.found_state = context.statistics(&self.heap)?;
        Ok(())
    }

    fn refresh(
        &mut self,
        context: Context,
        old_units: u32,
        scale: bool,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let raw_count = context.num_stats(&self.heap)?;
        if raw_count == 0 {
            return Err(format_error("ZIP PPMd cannot refresh a binary context"));
        }
        let new_units = (u32::from(raw_count) + 2) >> 1;
        let old_statistics = context.statistics(&self.heap)?;
        let statistics =
            self.allocator
                .shrink_units(&mut self.heap, old_statistics.0, old_units, new_units)?;
        context.set_statistics(&mut self.heap, State(statistics))?;
        let scale_value = u8::from(scale);
        let first = State(statistics);
        let mut flags = context.flags(&self.heap)? & (0x10 + if scale { 0x04 } else { 0 });
        if first.symbol(&self.heap)? >= 0x40 {
            flags |= 0x08;
        }
        let mut escape_frequency = i32::from(context.summary(&self.heap)?);
        for state_index in 0..=u32::from(raw_count) {
            control.checkpoint(1)?;
            let state = first.offset(i32::try_from(state_index).map_err(|_| {
                format_error("ZIP PPMd refresh state index is not representable")
            })?)?;
            escape_frequency -= i32::from(state.frequency(&self.heap)?);
            let frequency = (state.frequency(&self.heap)? + scale_value) >> scale_value;
            state.set_frequency(&mut self.heap, frequency)?;
            if state_index == 0 {
                context.set_summary(&mut self.heap, u16::from(frequency))?;
            } else {
                context.add_summary(&mut self.heap, u16::from(frequency))?;
            }
            if state.symbol(&self.heap)? >= 0x40 {
                flags |= 0x08;
            }
        }
        if escape_frequency < 0 {
            return Err(format_error("ZIP PPMd escape frequency underflows"));
        }
        let escape_frequency = (escape_frequency + i32::from(scale_value)) >> scale_value;
        context.add_summary(
            &mut self.heap,
            u16::try_from(escape_frequency)
                .map_err(|_| format_error("ZIP PPMd escape frequency is out of range"))?,
        )?;
        context.set_flags(&mut self.heap, flags)
    }

    fn find_symbol(
        &mut self,
        context: Context,
        symbol: u8,
        control: &mut ParseControl<'_>,
    ) -> Result<State> {
        if context.num_stats(&self.heap)? == 0 {
            let state = context.first_state()?;
            if state.symbol(&self.heap)? == symbol {
                return Ok(state);
            }
            return Err(format_error(
                "ZIP PPMd symbol is absent from binary context",
            ));
        }
        let first = self.validate_statistics(context)?;
        let count = u32::from(context.num_stats(&self.heap)?) + 1;
        for state_index in 0..count {
            control.checkpoint(1)?;
            let state =
                first
                    .offset(i32::try_from(state_index).map_err(|_| {
                        format_error("ZIP PPMd state index is not representable")
                    })?)?;
            if state.symbol(&self.heap)? == symbol {
                return Ok(state);
            }
        }
        Err(format_error("ZIP PPMd symbol is absent from context"))
    }

    fn push_pending(
        pending: &mut [u32; MAX_ORDER as usize],
        length: &mut usize,
        state: State,
    ) -> Result<()> {
        let slot = pending
            .get_mut(*length)
            .ok_or_else(|| format_error("ZIP PPMd successor depth exceeds model order"))?;
        *slot = state.0;
        *length = length
            .checked_add(1)
            .ok_or_else(|| format_error("ZIP PPMd successor depth overflows"))?;
        Ok(())
    }

    fn create_successors(
        &mut self,
        skip: bool,
        mut state: State,
        mut context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<Context>> {
        control.checkpoint(1)?;
        let up_branch = self.found_state.successor(&self.heap)?;
        if up_branch < self.allocator.heap_start || up_branch >= self.allocator.units_start {
            return Err(format_error("ZIP PPMd successor text pointer is invalid"));
        }
        let mut pending = [0_u32; MAX_ORDER as usize];
        let mut pending_len = 0_usize;
        if !skip {
            Self::push_pending(&mut pending, &mut pending_len, self.found_state)?;
            if context.suffix(&self.heap)?.0 == 0 {
                return self.build_successors(up_branch, pending, pending_len, context, control);
            }
        }

        let mut at_loop_entry = state.0 != 0;
        if at_loop_entry {
            context = context.suffix(&self.heap)?;
            self.validate_context(context)?;
        }
        loop {
            if !at_loop_entry {
                context = context.suffix(&self.heap)?;
                self.validate_context(context)?;
                state = self.find_symbol(context, self.found_state.symbol(&self.heap)?, control)?;
                if context.num_stats(&self.heap)? != 0 {
                    if state.frequency(&self.heap)? < MAX_FREQUENCY - 9 {
                        state.add_frequency(&mut self.heap, 1)?;
                        context.add_summary(&mut self.heap, 1)?;
                    }
                } else {
                    let suffix = context.suffix(&self.heap)?;
                    self.validate_context(suffix)?;
                    if suffix.num_stats(&self.heap)? == 0 && state.frequency(&self.heap)? < 24 {
                        state.add_frequency(&mut self.heap, 1)?;
                    }
                }
            }
            at_loop_entry = false;
            if state.successor(&self.heap)? != up_branch {
                context = Context(state.successor(&self.heap)?);
                self.validate_context(context)?;
                break;
            }
            Self::push_pending(&mut pending, &mut pending_len, state)?;
            if context.suffix(&self.heap)?.0 == 0 {
                break;
            }
        }
        self.build_successors(up_branch, pending, pending_len, context, control)
    }

    fn build_successors(
        &mut self,
        up_branch: u32,
        pending: [u32; MAX_ORDER as usize],
        mut pending_len: usize,
        mut context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<Context>> {
        if pending_len == 0 {
            return Ok(Some(context));
        }
        let mut symbol = self.heap.byte(up_branch)?;
        let local_symbol = symbol;
        let local_successor = add(up_branch, 1, "ZIP PPMd successor text address overflows")?;
        if local_successor > self.allocator.units_start {
            return Err(format_error("ZIP PPMd successor text range is invalid"));
        }
        let mut local_flags = if self.found_state.symbol(&self.heap)? >= 0x40 {
            0x10
        } else {
            0
        };
        if symbol >= 0x40 {
            local_flags |= 0x08;
        }
        self.validate_context(context)?;
        let local_frequency = if context.num_stats(&self.heap)? != 0 {
            let state = self.find_symbol(context, symbol, control)?;
            let context_frequency = u32::from(state.frequency(&self.heap)?);
            let cf = context_frequency
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd successor frequency underflows"))?;
            let s0 = u32::from(context.summary(&self.heap)?)
                .checked_sub(u32::from(context.num_stats(&self.heap)?))
                .and_then(|value| value.checked_sub(cf))
                .ok_or_else(|| format_error("ZIP PPMd successor frequency total underflows"))?;
            let extra = if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                if s0 == 0 {
                    return Err(format_error("ZIP PPMd successor frequency divisor is zero"));
                }
                (cf + 2 * s0 - 3) / s0
            };
            u8::try_from(1 + extra)
                .map_err(|_| format_error("ZIP PPMd successor frequency is out of range"))?
        } else {
            context.first_state()?.frequency(&self.heap)?
        };
        symbol = local_symbol;
        while pending_len != 0 {
            control.checkpoint(1)?;
            let Some(address) = self.allocator.allocate_context(&mut self.heap, control)? else {
                return Ok(None);
            };
            let new_context = Context(address);
            new_context.set_num_stats(&mut self.heap, 0)?;
            new_context.set_flags(&mut self.heap, local_flags)?;
            let one = new_context.first_state()?;
            one.set_symbol(&mut self.heap, symbol)?;
            one.set_frequency(&mut self.heap, local_frequency)?;
            one.set_successor(&mut self.heap, local_successor)?;
            new_context.set_suffix(&mut self.heap, context)?;
            context = new_context;
            pending_len -= 1;
            State(
                *pending
                    .get(pending_len)
                    .ok_or_else(|| format_error("ZIP PPMd successor stack is invalid"))?,
            )
            .set_successor(&mut self.heap, context.0)?;
        }
        Ok(Some(context))
    }

    fn reduce_order(
        &mut self,
        mut state: State,
        mut context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<Context>> {
        control.checkpoint(1)?;
        let original_context = context;
        let up_branch = self.allocator.text;
        let symbol = self.found_state.symbol(&self.heap)?;
        let mut pending = [0_u32; MAX_ORDER as usize];
        let mut pending_len = 0_usize;
        Self::push_pending(&mut pending, &mut pending_len, self.found_state)?;
        self.found_state.set_successor(&mut self.heap, up_branch)?;
        self.order_fall = self
            .order_fall
            .checked_add(1)
            .ok_or_else(|| format_error("ZIP PPMd order fall overflows"))?;

        let mut at_loop_entry = state.0 != 0;
        if at_loop_entry {
            context = context.suffix(&self.heap)?;
            self.validate_context(context)?;
        }
        loop {
            if !at_loop_entry {
                let suffix = context.suffix(&self.heap)?;
                if suffix.0 == 0 {
                    if self.restoration == Restoration::Frozen {
                        for address in pending
                            .get(..pending_len)
                            .ok_or_else(|| format_error("ZIP PPMd successor stack is invalid"))?
                            .iter()
                            .rev()
                        {
                            State(*address).set_successor(&mut self.heap, context.0)?;
                        }
                        self.allocator.text = add(
                            self.allocator.heap_start,
                            1,
                            "ZIP PPMd frozen text address overflows",
                        )?;
                        self.order_fall = 1;
                    }
                    return Ok(Some(context));
                }
                context = suffix;
                state = self.find_symbol(context, symbol, control)?;
                if context.num_stats(&self.heap)? != 0 {
                    if state.frequency(&self.heap)? < MAX_FREQUENCY - 9 {
                        state.add_frequency(&mut self.heap, 2)?;
                        context.add_summary(&mut self.heap, 2)?;
                    }
                } else if state.frequency(&self.heap)? < 32 {
                    state.add_frequency(&mut self.heap, 1)?;
                }
            }
            at_loop_entry = false;
            if state.successor(&self.heap)? != 0 {
                break;
            }
            Self::push_pending(&mut pending, &mut pending_len, state)?;
            state.set_successor(&mut self.heap, up_branch)?;
            self.order_fall = self
                .order_fall
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd order fall overflows"))?;
        }

        if self.restoration == Restoration::Frozen {
            context = Context(state.successor(&self.heap)?);
            self.validate_context(context)?;
            for address in pending
                .get(..pending_len)
                .ok_or_else(|| format_error("ZIP PPMd successor stack is invalid"))?
                .iter()
                .rev()
            {
                State(*address).set_successor(&mut self.heap, context.0)?;
            }
            self.allocator.text = add(
                self.allocator.heap_start,
                1,
                "ZIP PPMd frozen text address overflows",
            )?;
            self.order_fall = 1;
            return Ok(Some(context));
        }
        if state.successor(&self.heap)? <= up_branch {
            let saved = self.found_state;
            self.found_state = state;
            let created = self.create_successors(false, State(0), context, control)?;
            self.found_state = saved;
            let Some(created) = created else {
                return Ok(None);
            };
            state.set_successor(&mut self.heap, created.0)?;
        }
        if self.order_fall == 1 && original_context == self.maximum_context {
            let state_successor = state.successor(&self.heap)?;
            self.found_state
                .set_successor(&mut self.heap, state_successor)?;
            self.allocator.text = sub(self.allocator.text, 1, "ZIP PPMd text address underflows")?;
        }
        let successor = Context(state.successor(&self.heap)?);
        self.validate_context(successor)?;
        Ok(Some(successor))
    }

    fn update_model(
        &mut self,
        minimum_context: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        control.checkpoint(1)?;
        let mut state = State(0);
        let mut current_context = self.maximum_context;
        let found_frequency = u32::from(self.found_state.frequency(&self.heap)?);
        let found_symbol = self.found_state.symbol(&self.heap)?;
        let mut found_successor = Context(self.found_state.successor(&self.heap)?);
        let suffix = minimum_context.suffix(&self.heap)?;

        if found_frequency < u32::from(MAX_FREQUENCY / 4) && suffix.0 != 0 {
            self.validate_context(suffix)?;
            if suffix.num_stats(&self.heap)? != 0 {
                state = self.find_symbol(suffix, found_symbol, control)?;
                let first = suffix.statistics(&self.heap)?;
                if state != first {
                    let previous = state.offset(-1)?;
                    if state.frequency(&self.heap)? >= previous.frequency(&self.heap)? {
                        swap_states(&mut self.heap, state, previous)?;
                        state = previous;
                    }
                }
                if state.frequency(&self.heap)? < MAX_FREQUENCY - 9 {
                    state.add_frequency(&mut self.heap, 2)?;
                    suffix.add_summary(&mut self.heap, 2)?;
                }
            } else {
                state = suffix.first_state()?;
                if state.frequency(&self.heap)? < 32 {
                    state.add_frequency(&mut self.heap, 1)?;
                }
            }
        }

        if self.order_fall == 0 && found_successor.0 != 0 {
            let created = self.create_successors(true, state, minimum_context, control)?;
            if let Some(created) = created {
                self.found_state.set_successor(&mut self.heap, created.0)?;
                self.maximum_context = created;
                return Ok(());
            }
            return self.restore_model(current_context, minimum_context, found_successor, control);
        }

        if self.allocator.text >= self.allocator.units_start {
            return self.restore_model(current_context, minimum_context, found_successor, control);
        }
        self.heap.put_byte(self.allocator.text, found_symbol)?;
        self.allocator.text = add(self.allocator.text, 1, "ZIP PPMd text address overflows")?;
        let mut successor = Context(self.allocator.text);
        if self.allocator.text >= self.allocator.units_start {
            return self.restore_model(current_context, minimum_context, found_successor, control);
        }

        if found_successor.0 != 0 {
            if found_successor.0 < self.allocator.units_start {
                let Some(created) =
                    self.create_successors(false, state, minimum_context, control)?
                else {
                    return self.restore_model(
                        current_context,
                        minimum_context,
                        found_successor,
                        control,
                    );
                };
                found_successor = created;
            }
        } else {
            let Some(reduced) = self.reduce_order(state, minimum_context, control)? else {
                return self.restore_model(
                    current_context,
                    minimum_context,
                    found_successor,
                    control,
                );
            };
            found_successor = reduced;
        }

        self.order_fall = self
            .order_fall
            .checked_sub(1)
            .ok_or_else(|| format_error("ZIP PPMd order fall underflows"))?;
        if self.order_fall == 0 {
            successor = found_successor;
            if self.maximum_context != minimum_context {
                self.allocator.text =
                    sub(self.allocator.text, 1, "ZIP PPMd text address underflows")?;
            }
        } else if self.restoration == Restoration::Frozen {
            successor = found_successor;
            self.allocator.text = self.allocator.heap_start;
            self.order_fall = 0;
        }

        let number_statistics = u32::from(minimum_context.num_stats(&self.heap)?);
        let s0 = u32::from(minimum_context.summary(&self.heap)?)
            .checked_sub(number_statistics)
            .and_then(|value| value.checked_sub(found_frequency))
            .ok_or_else(|| format_error("ZIP PPMd update frequency total underflows"))?;
        let flag = if found_symbol >= 0x40 { 0x08 } else { 0 };
        let mut chain_steps = 0_u8;
        while current_context != minimum_context {
            chain_steps = chain_steps
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd context-chain depth overflows"))?;
            if chain_steps > self.model_order {
                return Err(format_error("ZIP PPMd context chain exceeds model order"));
            }
            control.checkpoint(1)?;
            let ns1 = u32::from(current_context.num_stats(&self.heap)?);
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    let old_statistics = current_context.statistics(&self.heap)?;
                    let Some(expanded) = self.allocator.expand_units(
                        &mut self.heap,
                        old_statistics.0,
                        (ns1 + 1) >> 1,
                        control,
                    )?
                    else {
                        return self.restore_model(
                            current_context,
                            minimum_context,
                            found_successor,
                            control,
                        );
                    };
                    current_context.set_statistics(&mut self.heap, State(expanded))?;
                }
                if 3 * ns1 + 1 < number_statistics {
                    current_context.add_summary(&mut self.heap, 1)?;
                }
            } else {
                let Some(allocated) = self.allocator.allocate_units(&mut self.heap, 1, control)?
                else {
                    return self.restore_model(
                        current_context,
                        minimum_context,
                        found_successor,
                        control,
                    );
                };
                state = State(allocated);
                let previous_value = current_context.first_state()?.value(&self.heap)?;
                state.set_value(&mut self.heap, previous_value)?;
                current_context.set_statistics(&mut self.heap, state)?;
                let frequency = state.frequency(&self.heap)?;
                state.set_frequency(
                    &mut self.heap,
                    if frequency < MAX_FREQUENCY / 4 - 1 {
                        frequency
                            .checked_mul(2)
                            .ok_or_else(|| format_error("ZIP PPMd frequency overflows"))?
                    } else {
                        MAX_FREQUENCY - 4
                    },
                )?;
                let summary = u32::from(state.frequency(&self.heap)?)
                    .checked_add(u32::from(self.initial_escape))
                    .and_then(|value| value.checked_add(u32::from(number_statistics > 2)))
                    .ok_or_else(|| format_error("ZIP PPMd context summary overflows"))?;
                current_context.set_summary(
                    &mut self.heap,
                    u16::try_from(summary)
                        .map_err(|_| format_error("ZIP PPMd context summary is invalid"))?,
                )?;
            }

            let current_summary = u32::from(current_context.summary(&self.heap)?);
            let cf = 2_u32
                .checked_mul(found_frequency)
                .and_then(|value| value.checked_mul(current_summary + 6))
                .ok_or_else(|| format_error("ZIP PPMd update frequency overflows"))?;
            let sf = s0
                .checked_add(current_summary)
                .ok_or_else(|| format_error("ZIP PPMd update scale overflows"))?;
            let new_frequency = if cf < 6 * sf {
                current_context.add_summary(&mut self.heap, 4)?;
                1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf)
            } else {
                let value =
                    4 + u32::from(cf > 9 * sf) + u32::from(cf > 12 * sf) + u32::from(cf > 15 * sf);
                current_context.add_summary(
                    &mut self.heap,
                    u16::try_from(value)
                        .map_err(|_| format_error("ZIP PPMd new frequency is invalid"))?,
                )?;
                value
            };
            let new_raw = current_context
                .num_stats(&self.heap)?
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd context state count overflows"))?;
            current_context.set_num_stats(&mut self.heap, new_raw)?;
            let new_state = current_context
                .statistics(&self.heap)?
                .offset(i32::from(new_raw))?;
            new_state.set_successor(&mut self.heap, successor.0)?;
            new_state.set_symbol(&mut self.heap, found_symbol)?;
            new_state.set_frequency(
                &mut self.heap,
                u8::try_from(new_frequency)
                    .map_err(|_| format_error("ZIP PPMd new frequency is invalid"))?,
            )?;
            let flags = current_context.flags(&self.heap)? | flag;
            current_context.set_flags(&mut self.heap, flags)?;
            current_context = current_context.suffix(&self.heap)?;
            self.validate_context(current_context)?;
        }
        self.maximum_context = found_successor;
        Ok(())
    }

    fn cut_off(
        &mut self,
        context: Context,
        order: u8,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<Context>> {
        control.checkpoint(1)?;
        self.validate_context(context)?;
        if order > self.model_order {
            return Err(format_error("ZIP PPMd cutoff depth exceeds model order"));
        }
        let raw_count = context.num_stats(&self.heap)?;
        if raw_count == 0 {
            let state = context.first_state()?;
            let successor = state.successor(&self.heap)?;
            if successor >= self.allocator.units_start {
                if order < self.model_order {
                    let next_order = order
                        .checked_add(1)
                        .ok_or_else(|| format_error("ZIP PPMd cutoff order overflows"))?;
                    let child = self.cut_off(Context(successor), next_order, control)?;
                    state.set_successor(&mut self.heap, child.map_or(0, |value| value.0))?;
                } else {
                    state.set_successor(&mut self.heap, 0)?;
                }
                if state.successor(&self.heap)? != 0 || order <= ORDER_BOUND {
                    return Ok(Some(context));
                }
            }
            self.allocator
                .special_free_unit(&mut self.heap, context.0)?;
            return Ok(None);
        }

        let units = (u32::from(raw_count) + 2) >> 1;
        let old_statistics = context.statistics(&self.heap)?.0;
        let moved = self
            .allocator
            .move_units_up(&mut self.heap, old_statistics, units)?;
        context.set_statistics(&mut self.heap, State(moved))?;
        let first = State(moved);
        let mut retained_last = i32::from(raw_count);
        for state_index in (0..=u32::from(raw_count)).rev() {
            control.checkpoint(1)?;
            let state = first.offset(
                i32::try_from(state_index)
                    .map_err(|_| format_error("ZIP PPMd cutoff state index is invalid"))?,
            )?;
            let successor = state.successor(&self.heap)?;
            if successor < self.allocator.units_start {
                state.set_successor(&mut self.heap, 0)?;
                if retained_last < 0 {
                    return Err(format_error("ZIP PPMd cutoff state count underflows"));
                }
                swap_states(&mut self.heap, state, first.offset(retained_last)?)?;
                retained_last -= 1;
            } else if order < self.model_order {
                let next_order = order
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd cutoff order overflows"))?;
                let child = self.cut_off(Context(successor), next_order, control)?;
                state.set_successor(&mut self.heap, child.map_or(0, |value| value.0))?;
            } else {
                state.set_successor(&mut self.heap, 0)?;
            }
        }
        if retained_last != i32::from(raw_count) && order != 0 {
            if retained_last < 0 {
                self.allocator.free_units(&mut self.heap, first.0, units)?;
                self.allocator
                    .special_free_unit(&mut self.heap, context.0)?;
                return Ok(None);
            }
            let new_raw = u8::try_from(retained_last)
                .map_err(|_| format_error("ZIP PPMd cutoff state count is invalid"))?;
            context.set_num_stats(&mut self.heap, new_raw)?;
            if new_raw == 0 {
                let value = first.value(&self.heap)?;
                let one = context.first_state()?;
                one.set_value(&mut self.heap, value)?;
                let flags = (context.flags(&self.heap)? & 0x10)
                    + if value.symbol >= 0x40 { 0x08 } else { 0 };
                context.set_flags(&mut self.heap, flags)?;
                self.allocator.free_units(&mut self.heap, first.0, units)?;
                one.set_frequency(&mut self.heap, (value.frequency + 11) >> 3)?;
            } else {
                self.refresh(
                    context,
                    units,
                    u32::from(context.summary(&self.heap)?) > 16 * u32::from(new_raw),
                    control,
                )?;
            }
        }
        Ok(Some(context))
    }

    fn remove_binary_contexts(
        &mut self,
        context: Context,
        order: u8,
        control: &mut ParseControl<'_>,
    ) -> Result<Option<Context>> {
        control.checkpoint(1)?;
        self.validate_context(context)?;
        if order > self.model_order {
            return Err(format_error("ZIP PPMd freeze depth exceeds model order"));
        }
        let raw_count = context.num_stats(&self.heap)?;
        if raw_count == 0 {
            let state = context.first_state()?;
            let successor = state.successor(&self.heap)?;
            if successor >= self.allocator.units_start && order < self.model_order {
                let next_order = order
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd freeze order overflows"))?;
                let child = self.remove_binary_contexts(Context(successor), next_order, control)?;
                state.set_successor(&mut self.heap, child.map_or(0, |value| value.0))?;
            } else {
                state.set_successor(&mut self.heap, 0)?;
            }
            let suffix = context.suffix(&self.heap)?;
            self.validate_context(suffix)?;
            if state.successor(&self.heap)? == 0
                && (suffix.num_stats(&self.heap)? == 0 || suffix.flags(&self.heap)? == 0xff)
            {
                self.allocator.free_units(&mut self.heap, context.0, 1)?;
                return Ok(None);
            }
            return Ok(Some(context));
        }
        let first = self.validate_statistics(context)?;
        for state_index in (0..=u32::from(raw_count)).rev() {
            control.checkpoint(1)?;
            let state = first.offset(
                i32::try_from(state_index)
                    .map_err(|_| format_error("ZIP PPMd freeze state index is invalid"))?,
            )?;
            let successor = state.successor(&self.heap)?;
            if successor >= self.allocator.units_start && order < self.model_order {
                let next_order = order
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd freeze order overflows"))?;
                let child = self.remove_binary_contexts(Context(successor), next_order, control)?;
                state.set_successor(&mut self.heap, child.map_or(0, |value| value.0))?;
            } else {
                state.set_successor(&mut self.heap, 0)?;
            }
        }
        Ok(Some(context))
    }

    fn move_maximum_to_root(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        let maximum_steps = self.allocator.size / UNIT_SIZE + 1;
        let mut steps = 0_u32;
        loop {
            let suffix = self.maximum_context.suffix(&self.heap)?;
            if suffix.0 == 0 {
                return Ok(());
            }
            steps = steps
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd root traversal overflows"))?;
            if steps > maximum_steps {
                return Err(format_error("ZIP PPMd root context chain contains a cycle"));
            }
            self.validate_context(suffix)?;
            self.maximum_context = suffix;
            control.checkpoint(1)?;
        }
    }

    fn restore_model(
        &mut self,
        stop_context: Context,
        minimum_context: Context,
        found_successor: Context,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        control.checkpoint(1)?;
        #[cfg(test)]
        {
            self.restoration_count = self
                .restoration_count
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd restoration count overflows"))?;
        }
        self.allocator.text = self.allocator.heap_start;
        let mut context = self.maximum_context;
        let mut steps = 0_u8;
        while context != stop_context {
            steps = steps
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd restore depth overflows"))?;
            if steps > self.model_order {
                return Err(format_error("ZIP PPMd restore chain exceeds model order"));
            }
            let old_raw = context.num_stats(&self.heap)?;
            let new_raw = old_raw
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd restore state count underflows"))?;
            context.set_num_stats(&mut self.heap, new_raw)?;
            if new_raw == 0 {
                let statistics = context.statistics(&self.heap)?;
                let value = statistics.value(&self.heap)?;
                context.first_state()?.set_value(&mut self.heap, value)?;
                let flags = (context.flags(&self.heap)? & 0x10)
                    + if value.symbol >= 0x40 { 0x08 } else { 0 };
                context.set_flags(&mut self.heap, flags)?;
                self.allocator
                    .special_free_unit(&mut self.heap, statistics.0)?;
                let one = context.first_state()?;
                let frequency = (one.frequency(&self.heap)? + 11) >> 3;
                one.set_frequency(&mut self.heap, frequency)?;
            } else {
                self.refresh(context, (u32::from(new_raw) + 3) >> 1, false, control)?;
            }
            context = context.suffix(&self.heap)?;
            self.validate_context(context)?;
            control.checkpoint(1)?;
        }

        steps = 0;
        while context != minimum_context {
            steps = steps
                .checked_add(1)
                .ok_or_else(|| format_error("ZIP PPMd restore depth overflows"))?;
            if steps > self.model_order {
                return Err(format_error("ZIP PPMd restore chain exceeds model order"));
            }
            if context.num_stats(&self.heap)? == 0 {
                let one = context.first_state()?;
                let frequency = one.frequency(&self.heap)?;
                one.set_frequency(&mut self.heap, frequency - (frequency >> 1))?;
            } else {
                context.add_summary(&mut self.heap, 4)?;
                if u32::from(context.summary(&self.heap)?)
                    > 128 + 4 * u32::from(context.num_stats(&self.heap)?)
                {
                    self.refresh(
                        context,
                        (u32::from(context.num_stats(&self.heap)?) + 2) >> 1,
                        true,
                        control,
                    )?;
                }
            }
            context = context.suffix(&self.heap)?;
            self.validate_context(context)?;
            control.checkpoint(1)?;
        }

        match self.restoration {
            Restoration::Frozen => {
                self.validate_context(found_successor)?;
                self.maximum_context = found_successor;
                if self.allocator.stamps[1] & 1 == 0 {
                    self.allocator.glue_count = self
                        .allocator
                        .glue_count
                        .checked_add(1)
                        .ok_or_else(|| format_error("ZIP PPMd glue counter overflows"))?;
                }
            }
            Restoration::Freeze => {
                self.move_maximum_to_root(control)?;
                self.remove_binary_contexts(self.maximum_context, 0, control)?;
                self.restoration = Restoration::Frozen;
                self.allocator.glue_count = 0;
                self.order_fall = self.model_order;
            }
            Restoration::Restart => {
                self.start_model(control)?;
                self.escape_count = 0;
            }
            Restoration::CutOff => {
                if self.allocator.used_memory()? < self.allocator.size >> 1 {
                    self.start_model(control)?;
                    self.escape_count = 0;
                } else {
                    self.move_maximum_to_root(control)?;
                    let target = 3 * (self.allocator.size >> 2);
                    let mut passes = 0_u8;
                    loop {
                        self.cut_off(self.maximum_context, 0, control)?;
                        self.allocator.expand_text(&mut self.heap, control)?;
                        if self.allocator.used_memory()? <= target {
                            break;
                        }
                        passes = passes
                            .checked_add(1)
                            .ok_or_else(|| format_error("ZIP PPMd cutoff pass count overflows"))?;
                        if passes > self.model_order {
                            return Err(format_error("ZIP PPMd cutoff failed to release memory"));
                        }
                    }
                    self.allocator.glue_count = 0;
                    self.order_fall = self.model_order;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn encode_binary_test(&mut self, symbol: i32, encoder: &mut RangeEncoder) -> Result<()> {
        let context = self.maximum_context;
        let state = context.first_state()?;
        let (row, column) = self.binary_indexes(context, state)?;
        let summary = self.binary_summary_value(row, column)?;
        encoder.scale = BIN_SCALE;
        if i32::from(state.symbol(&self.heap)?) == symbol {
            self.found_state = state;
            if state.frequency(&self.heap)? < 196 {
                state.add_frequency(&mut self.heap, 1)?;
            }
            encoder.low_count = 0;
            encoder.high_count = u32::from(summary);
            let updated = u32::from(summary) + INTERVAL - u32::from(Self::mean(summary));
            self.set_binary_summary(
                row,
                column,
                u16::try_from(updated)
                    .map_err(|_| format_error("ZIP PPMd test binary summary is invalid"))?,
            )?;
            self.previous_success = 1;
            self.run_length = self.run_length.wrapping_add(1);
        } else {
            encoder.low_count = u32::from(summary);
            encoder.high_count = BIN_SCALE;
            let updated = summary
                .checked_sub(Self::mean(summary))
                .ok_or_else(|| format_error("ZIP PPMd test binary summary underflows"))?;
            self.set_binary_summary(row, column, updated)?;
            self.initial_escape = *EXPONENTIAL_ESCAPES
                .get(usize::from(updated >> 10))
                .ok_or_else(|| format_error("ZIP PPMd test escape index is invalid"))?;
            self.set_mask(state.symbol(&self.heap)?)?;
            self.previous_success = 0;
            self.number_masked = 0;
            self.found_state = State(0);
        }
        Ok(())
    }

    #[cfg(test)]
    fn encode_symbol1_test(
        &mut self,
        context: Context,
        symbol: i32,
        encoder: &mut RangeEncoder,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let raw_count = context.num_stats(&self.heap)?;
        let first = self.validate_statistics(context)?;
        encoder.scale = u32::from(context.summary(&self.heap)?);
        let mut state = first;
        if i32::from(state.symbol(&self.heap)?) == symbol {
            encoder.low_count = 0;
            encoder.high_count = u32::from(state.frequency(&self.heap)?);
            self.previous_success = u8::from(2 * encoder.high_count >= encoder.scale);
            self.found_state = state;
            state.add_frequency(&mut self.heap, 4)?;
            context.add_summary(&mut self.heap, 4)?;
            self.run_length = self
                .run_length
                .wrapping_add(i32::from(self.previous_success));
            if state.frequency(&self.heap)? > MAX_FREQUENCY {
                self.rescale(context, control)?;
            }
            return Ok(());
        }
        let mut low = u32::from(state.frequency(&self.heap)?);
        let mut remaining = u32::from(raw_count);
        self.previous_success = 0;
        loop {
            state = state.offset(1)?;
            if i32::from(state.symbol(&self.heap)?) == symbol {
                encoder.low_count = low;
                encoder.high_count = low
                    .checked_add(u32::from(state.frequency(&self.heap)?))
                    .ok_or_else(|| format_error("ZIP PPMd test frequency overflows"))?;
                self.update1(state, context, control)?;
                return Ok(());
            }
            low = low
                .checked_add(u32::from(state.frequency(&self.heap)?))
                .ok_or_else(|| format_error("ZIP PPMd test frequency overflows"))?;
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| format_error("ZIP PPMd test state count underflows"))?;
            if remaining == 0 {
                encoder.low_count = low;
                encoder.high_count = encoder.scale;
                self.set_mask(state.symbol(&self.heap)?)?;
                self.number_masked = raw_count;
                self.found_state = State(0);
                let mut backwards = u32::from(raw_count);
                while backwards != 0 {
                    state = state.offset(-1)?;
                    self.set_mask(state.symbol(&self.heap)?)?;
                    backwards -= 1;
                }
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    fn encode_symbol2_test(
        &mut self,
        context: Context,
        symbol: i32,
        encoder: &mut RangeEncoder,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let see_slot = self.make_escape_frequency(context)?;
        encoder.scale = self.decoder.scale;
        let raw_count = context.num_stats(&self.heap)?;
        let mut remaining = raw_count
            .checked_sub(self.number_masked)
            .ok_or_else(|| format_error("ZIP PPMd test masked-state count is invalid"))?;
        if remaining == 0 {
            return Err(format_error("ZIP PPMd test context has no unmasked states"));
        }
        let total = u32::from(raw_count) + 1;
        let mut visited = 0_u32;
        let mut state = self.validate_statistics(context)?;
        let mut low = 0_u32;
        loop {
            if visited >= total {
                return Err(format_error(
                    "ZIP PPMd test unmasked-state count is invalid",
                ));
            }
            let current_symbol = state.symbol(&self.heap)?;
            if self.mask(current_symbol)? != self.escape_count {
                self.set_mask(current_symbol)?;
                remaining -= 1;
                if i32::from(current_symbol) == symbol {
                    encoder.low_count = low;
                    encoder.high_count =
                        low.checked_add(u32::from(state.frequency(&self.heap)?))
                            .ok_or_else(|| format_error("ZIP PPMd test frequency overflows"))?;
                    let mut tail_sum = encoder.high_count;
                    let mut tail_remaining = remaining;
                    let mut tail = state;
                    let mut tail_visited = visited + 1;
                    while tail_remaining != 0 {
                        if tail_visited >= total {
                            return Err(format_error(
                                "ZIP PPMd test unmasked-state count is invalid",
                            ));
                        }
                        tail = tail.offset(1)?;
                        tail_visited += 1;
                        if self.mask(tail.symbol(&self.heap)?)? != self.escape_count {
                            tail_sum = tail_sum
                                .checked_add(u32::from(tail.frequency(&self.heap)?))
                                .ok_or_else(|| format_error("ZIP PPMd test frequency overflows"))?;
                            tail_remaining -= 1;
                        }
                    }
                    encoder.scale = encoder
                        .scale
                        .checked_add(tail_sum)
                        .ok_or_else(|| format_error("ZIP PPMd test scale overflows"))?;
                    if let Some((row, column)) = see_slot {
                        self.see2_mut(row, column)?.update()?;
                    }
                    self.update2(state, context, control)?;
                    return Ok(());
                }
                low = low
                    .checked_add(u32::from(state.frequency(&self.heap)?))
                    .ok_or_else(|| format_error("ZIP PPMd test frequency overflows"))?;
                if remaining == 0 {
                    encoder.low_count = low;
                    encoder.scale = encoder
                        .scale
                        .checked_add(low)
                        .ok_or_else(|| format_error("ZIP PPMd test scale overflows"))?;
                    encoder.high_count = encoder.scale;
                    if let Some((row, column)) = see_slot {
                        let increment = u16::try_from(encoder.scale)
                            .map_err(|_| format_error("ZIP PPMd test SEE increment is invalid"))?;
                        let see = self.see2_mut(row, column)?;
                        see.summary = see.summary.wrapping_add(increment);
                    }
                    self.number_masked = raw_count;
                    self.found_state = State(0);
                    return Ok(());
                }
            }
            visited += 1;
            state = state.offset(1)?;
        }
    }

    #[cfg(test)]
    fn encode_char_test(
        &mut self,
        symbol: i32,
        encoder: &mut RangeEncoder,
        control: &mut ParseControl<'_>,
    ) -> Result<bool> {
        let mut minimum_context = self.maximum_context;
        if minimum_context.num_stats(&self.heap)? != 0 {
            self.encode_symbol1_test(minimum_context, symbol, encoder, control)?;
            encoder.encode()?;
        } else {
            self.encode_binary_test(symbol, encoder)?;
            encoder.encode_shifted(14)?;
        }
        let maximum_suffix_steps = self.allocator.size / UNIT_SIZE + 1;
        let mut suffix_steps = 0_u32;
        while self.found_state.0 == 0 {
            encoder.normalize();
            loop {
                suffix_steps = suffix_steps
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd test suffix traversal overflows"))?;
                if suffix_steps > maximum_suffix_steps {
                    return Err(format_error("ZIP PPMd test suffix chain contains a cycle"));
                }
                self.order_fall = self
                    .order_fall
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd test order fall overflows"))?;
                minimum_context = minimum_context.suffix(&self.heap)?;
                if minimum_context.0 == 0 {
                    return Ok(false);
                }
                if minimum_context.num_stats(&self.heap)? != self.number_masked {
                    break;
                }
            }
            self.encode_symbol2_test(minimum_context, symbol, encoder, control)?;
            encoder.encode()?;
        }
        let successor = self.found_state.successor(&self.heap)?;
        if self.order_fall == 0 && successor >= self.allocator.units_start {
            self.maximum_context = Context(successor);
        } else {
            self.update_model(minimum_context, control)?;
            if self.escape_count == 0 {
                self.clear_mask();
            }
        }
        encoder.normalize();
        Ok(true)
    }

    fn clear_mask(&mut self) {
        self.escape_count = 1;
        self.character_mask.fill(0);
    }

    fn decode_char(&mut self, control: &mut ParseControl<'_>) -> Result<Option<u8>> {
        control.checkpoint(1)?;
        let mut minimum_context = self.maximum_context;
        self.validate_context(minimum_context)?;
        if minimum_context.num_stats(&self.heap)? != 0 {
            self.decode_symbol1(minimum_context, control)?;
        } else {
            self.decode_binary(minimum_context)?;
        }
        self.decoder.remove_subrange()?;

        let maximum_suffix_steps = self.allocator.size / UNIT_SIZE + 1;
        let mut suffix_steps = 0_u32;
        while self.found_state.0 == 0 {
            self.decoder.normalize(control)?;
            loop {
                suffix_steps = suffix_steps
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd suffix traversal overflows"))?;
                if suffix_steps > maximum_suffix_steps {
                    return Err(format_error("ZIP PPMd suffix chain contains a cycle"));
                }
                self.order_fall = self
                    .order_fall
                    .checked_add(1)
                    .ok_or_else(|| format_error("ZIP PPMd order fall overflows"))?;
                minimum_context = minimum_context.suffix(&self.heap)?;
                if minimum_context.0 == 0 {
                    return Ok(None);
                }
                self.validate_context(minimum_context)?;
                if minimum_context.num_stats(&self.heap)? != self.number_masked {
                    break;
                }
                control.checkpoint(1)?;
            }
            self.decode_symbol2(minimum_context, control)?;
            self.decoder.remove_subrange()?;
        }

        let symbol = self.found_state.symbol(&self.heap)?;
        let successor = self.found_state.successor(&self.heap)?;
        if self.order_fall == 0 && successor >= self.allocator.units_start {
            let context = Context(successor);
            self.validate_context(context)?;
            self.maximum_context = context;
        } else {
            self.update_model(minimum_context, control)?;
            if self.escape_count == 0 {
                self.clear_mask();
            }
        }
        self.decoder.normalize(control)?;
        Ok(Some(symbol))
    }
}

pub(crate) fn decode_zip_ppmd(
    input: &[u8],
    expected: u64,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        2,
        limits.max_coder_property_bytes(),
        LimitKind::CoderPropertyBytes,
    )?;
    check_limit(
        1,
        limits.max_coders_per_folder(),
        LimitKind::CodersPerFolder,
    )?;
    check_limit(1, limits.max_total_coders(), LimitKind::TotalCoders)?;
    let property_bytes = input
        .get(..2)
        .ok_or_else(|| format_error("ZIP PPMd property header is truncated"))?;
    let property_word = u16::from_le_bytes(
        <[u8; 2]>::try_from(property_bytes)
            .map_err(|_| format_error("ZIP PPMd property header is truncated"))?,
    );
    let order = u8::try_from((property_word & 0x000f) + 1)
        .map_err(|_| format_error("ZIP PPMd order is not representable"))?;
    if !(2..=MAX_ORDER).contains(&order) {
        return Err(format_error(
            "ZIP PPMd order is outside two through sixteen",
        ));
    }
    let memory_mib = u32::from((property_word >> 4) & 0x00ff) + 1;
    let memory_size = memory_mib
        .checked_mul(1 << 20)
        .ok_or_else(|| format_error("ZIP PPMd model memory overflows"))?;
    let restoration = Restoration::parse(
        u8::try_from(property_word >> 12)
            .map_err(|_| format_error("ZIP PPMd restoration method is invalid"))?,
    )?;
    check_limit(
        u64::from(memory_size),
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    check_limit(expected, maximum, LimitKind::TotalOutputBytes)?;
    let output_size = u64_to_usize(
        expected,
        "ZIP PPMd output size is not representable on this platform",
    )?;
    control.checkpoint(2)?;
    let range_input = input
        .get(2..)
        .ok_or_else(|| format_error("ZIP PPMd range stream is missing"))?;
    let mut model = Model::new(order, memory_size, restoration, range_input, control)?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_size).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "ZIP PPMd output allocation failed",
        ))
    })?;
    for output_index in 0..output_size {
        let symbol = model
            .decode_char(control)
            .map_err(|error| match error {
                Error::Format { detail } => Error::Format {
                    detail: format!("{detail} while decoding ZIP PPMd output byte {output_index}"),
                },
                other => other,
            })?
            .ok_or_else(|| format_error("ZIP PPMd end marker precedes the declared size"))?;
        output.push(symbol);
    }
    if model.decode_char(control)?.is_some() {
        return Err(format_error(
            "ZIP PPMd output continues beyond the declared size",
        ));
    }
    if model.decoder.position != range_input.len() {
        return Err(format_error(
            "ZIP PPMd range stream has bytes after its end marker",
        ));
    }
    Ok(output)
}

/// Produces deterministic method-98 payloads for in-crate tests only.
///
/// This is deliberately absent from production builds and public APIs; unpackio
/// remains unpack-only. The encoder drives the same model transitions in the
/// opposite range-coder direction so tests can cover all legal properties and
/// restoration paths without shipping an archive-writing surface.
#[cfg(test)]
pub(crate) fn encode_zip_ppmd_fixture_for_test(
    bytes: &[u8],
    order: u8,
    memory_mib: u16,
    restoration_value: u8,
) -> Result<(Vec<u8>, u32, u8)> {
    if !(2..=MAX_ORDER).contains(&order) {
        return Err(format_error(
            "ZIP PPMd test order is outside two through sixteen",
        ));
    }
    if !(1..=256).contains(&memory_mib) {
        return Err(format_error(
            "ZIP PPMd test memory is outside one through 256 MiB",
        ));
    }
    let restoration = Restoration::parse(restoration_value)?;
    let cancellation = crate::CancellationToken::new();
    let mut budget = crate::WorkBudget::unlimited();
    let mut control = ParseControl::new(&cancellation, &mut budget);
    let memory_size = u32::from(memory_mib)
        .checked_mul(1 << 20)
        .ok_or_else(|| format_error("ZIP PPMd test model memory overflows"))?;
    let range_seed = [0_u8; 4];
    let mut model = Model::new(order, memory_size, restoration, &range_seed, &mut control)?;
    let mut encoder = RangeEncoder::new();
    for byte in bytes {
        if !model.encode_char_test(i32::from(*byte), &mut encoder, &mut control)? {
            return Err(format_error(
                "ZIP PPMd test encoder reached its end marker early",
            ));
        }
    }
    if model.encode_char_test(-1, &mut encoder, &mut control)? {
        return Err(format_error(
            "ZIP PPMd test encoder did not emit its end marker",
        ));
    }
    let restoration_count = model.restoration_count;
    let final_restoration = match model.restoration {
        Restoration::Restart => 0,
        Restoration::CutOff => 1,
        Restoration::Freeze => 2,
        Restoration::Frozen => 3,
    };
    let properties =
        u16::from(order - 1) | ((memory_mib - 1) << 4) | (u16::from(restoration_value) << 12);
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&properties.to_le_bytes());
    encoded.extend_from_slice(&encoder.finish());
    Ok((encoded, restoration_count, final_restoration))
}

#[cfg(test)]
mod tests {
    use super::{
        Allocator, Heap, MAX_ORDER, RangeDecoder, Restoration, decode_zip_ppmd,
        encode_zip_ppmd_fixture_for_test,
    };
    use crate::{
        CancellationToken, Error, LimitKind, Limits, Result, WorkBudget, parse_util::ParseControl,
    };

    fn encode(
        bytes: &[u8],
        order: u8,
        memory_mib: u16,
        restoration: Restoration,
    ) -> Result<(Vec<u8>, u32, Restoration)> {
        let restoration_value = match restoration {
            Restoration::Restart => 0,
            Restoration::CutOff => 1,
            Restoration::Freeze | Restoration::Frozen => 2,
        };
        let (encoded, restoration_count, final_restoration) =
            encode_zip_ppmd_fixture_for_test(bytes, order, memory_mib, restoration_value)?;
        let final_restoration = match final_restoration {
            0 => Restoration::Restart,
            1 => Restoration::CutOff,
            2 => Restoration::Freeze,
            3 => Restoration::Frozen,
            _ => {
                return Err(crate::Error::Format {
                    detail: String::from("test restoration result is invalid"),
                });
            }
        };
        Ok((encoded, restoration_count, final_restoration))
    }

    fn decode(encoded: &[u8], expected: &[u8]) -> Result<Vec<u8>> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        decode_zip_ppmd(
            encoded,
            u64::try_from(expected.len()).map_err(|_| crate::Error::Format {
                detail: String::from("test output size is not representable"),
            })?,
            u64::try_from(expected.len()).map_err(|_| crate::Error::Format {
                detail: String::from("test output size is not representable"),
            })?,
            Limits::default(),
            &mut control,
        )
    }

    #[test]
    fn binary_range_count_must_remain_inside_its_scale() -> Result<()> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let mut decoder = RangeDecoder::new(&[0xff, 0xff, 0xff, 0xfe], &mut control)?;
        assert!(decoder.current_shift_count(14).is_err());
        Ok(())
    }

    #[test]
    fn glue_node_collection_recycles_through_fallible_storage() -> Result<()> {
        let model_size = 1 << 20;
        let mut heap = Heap::new(model_size)?;
        let mut allocator = Allocator::new(model_size, &mut heap)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let address = allocator
            .allocate_units(&mut heap, 1, &mut control)?
            .ok_or_else(|| crate::Error::Format {
                detail: String::from("test PPMd allocation unexpectedly failed"),
            })?;
        allocator.free_units(&mut heap, address, 1)?;
        allocator.glue_free_blocks(&mut heap, &mut control)?;
        let recycled = allocator
            .allocate_units(&mut heap, 1, &mut control)?
            .ok_or_else(|| crate::Error::Format {
                detail: String::from("test PPMd glued allocation unexpectedly failed"),
            })?;
        assert_eq!(recycled, address);
        Ok(())
    }

    #[test]
    fn all_restoration_values_round_trip_with_eos() -> Result<()> {
        let (stock_vector, restorations, final_restoration) =
            encode(b"abc", 2, 1, Restoration::Restart)?;
        assert_eq!(
            stock_vector,
            [0x01, 0x00, 0x61, 0x03, 0x6e, 0x81, 0x2d, 0x4c, 0x00]
        );
        assert_eq!(restorations, 0);
        assert_eq!(final_restoration, Restoration::Restart);

        let expected = b"ZIP PPMd-I revision 1 property and end-marker boundary\n";
        for restoration in [
            Restoration::Restart,
            Restoration::CutOff,
            Restoration::Freeze,
        ] {
            let (encoded, restorations, _) = encode(expected, 2, 1, restoration)?;
            assert_eq!(restorations, 0);
            assert_eq!(decode(&encoded, expected)?, expected);
        }
        Ok(())
    }

    #[test]
    fn every_registered_model_order_round_trips() -> Result<()> {
        let expected = b"PPMd-I order profile";
        for order in 2..=MAX_ORDER {
            let (encoded, restorations, final_restoration) =
                encode(expected, order, 1, Restoration::Restart)?;
            assert_eq!(restorations, 0);
            assert_eq!(final_restoration, Restoration::Restart);
            assert_eq!(decode(&encoded, expected)?, expected);
        }
        Ok(())
    }

    #[test]
    fn maximum_memory_property_is_limit_checked_before_allocation() -> Result<()> {
        let mut encoded = [0x01, 0x00, 0x61, 0x03, 0x6e, 0x81, 0x2d, 0x4c, 0x00];
        encoded[..2].copy_from_slice(&0x0ff1_u16.to_le_bytes());
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = decode_zip_ppmd(
            &encoded,
            3,
            3,
            Limits::builder()
                .max_dictionary_bytes(255 * 1024 * 1024)
                .build(),
            &mut control,
        );
        assert!(matches!(
            result,
            Err(Error::LimitExceeded {
                limit: LimitKind::DictionaryBytes,
                requested: 268_435_456,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn freeze_restoration_is_exercised_under_memory_pressure() -> Result<()> {
        let mut expected = Vec::with_capacity(64 * 1024);
        let mut value = 0x243f_6a88_u32;
        while expected.len() < expected.capacity() {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            expected.push((value >> 16).to_le_bytes()[0]);
        }
        let (encoded, restorations, final_restoration) =
            encode(&expected, 16, 1, Restoration::Freeze)?;
        assert!(restorations > 0);
        assert_eq!(final_restoration, Restoration::Frozen);
        assert_eq!(decode(&encoded, &expected)?, expected);
        Ok(())
    }

    #[test]
    #[ignore = "slow allocator-pressure matrix; run explicitly with --release"]
    fn every_restoration_algorithm_round_trips_under_memory_pressure() -> Result<()> {
        let mut expected = Vec::with_capacity(512 * 1024);
        let mut value = 0x1319_8a2e_u32;
        while expected.len() < expected.capacity() {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            expected.push((value >> 16).to_le_bytes()[0]);
        }
        for (restoration, expected_final) in [
            (Restoration::Restart, Restoration::Restart),
            (Restoration::CutOff, Restoration::CutOff),
            (Restoration::Freeze, Restoration::Frozen),
        ] {
            let (encoded, restorations, final_restoration) = encode(&expected, 16, 1, restoration)?;
            assert!(restorations > 0);
            assert_eq!(final_restoration, expected_final);
            assert_eq!(decode(&encoded, &expected)?, expected);
        }
        Ok(())
    }
}
