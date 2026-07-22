//! Safe, bounded raw LZMA and LZMA2 decoding.
//!
//! This decoder is an adaptation of the independently implemented BSD-3-Clause
//! Go decoder in `github.com/ulikunitz/xz` v0.5.15. It is deliberately shaped
//! around validated 7z coder properties, checked Rust arithmetic, fallible
//! allocation, and explicit operation control rather than mirroring Go types.

use std::io;

use crate::{
    Error, LimitKind, Result,
    parse_util::{
        ParseControl, check_limit, format_error, try_reserve, u64_to_usize, usize_to_u64,
    },
};

const PROB_BITS: u32 = 11;
const PROB_TOTAL: u16 = 1 << PROB_BITS;
const PROB_INITIAL: u16 = PROB_TOTAL >> 1;
const MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;
const STATE_COUNT: usize = 12;
const MAX_POSITION_BITS: usize = 4;
const POSITION_STATES: usize = 1 << MAX_POSITION_BITS;
const MIN_MATCH_LENGTH: u32 = 2;
const LENGTH_STATES: u32 = 4;
const START_POSITION_MODEL: u32 = 4;
const END_POSITION_MODEL: u32 = 14;
const POSITION_SLOT_BITS: u32 = 6;
const ALIGN_BITS: u32 = 4;
const EOS_DISTANCE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Probability(u16);

impl Probability {
    const INITIAL: Self = Self(PROB_INITIAL);

    fn decode(
        &mut self,
        range: &mut RangeDecoder<'_>,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let bound = (range.range >> PROB_BITS)
            .checked_mul(u32::from(self.0))
            .ok_or_else(|| format_error("LZMA probability bound overflows"))?;
        let bit = if range.code < bound {
            range.range = bound;
            let difference = PROB_TOTAL
                .checked_sub(self.0)
                .ok_or_else(|| format_error("LZMA probability underflows"))?;
            self.0 = self
                .0
                .checked_add(difference >> MOVE_BITS)
                .ok_or_else(|| format_error("LZMA probability overflows"))?;
            0
        } else {
            range.code = range
                .code
                .checked_sub(bound)
                .ok_or_else(|| format_error("LZMA range code underflows"))?;
            range.range = range
                .range
                .checked_sub(bound)
                .ok_or_else(|| format_error("LZMA range underflows"))?;
            self.0 = self
                .0
                .checked_sub(self.0 >> MOVE_BITS)
                .ok_or_else(|| format_error("LZMA probability underflows"))?;
            1
        };
        range.normalize(control)?;
        Ok(bit)
    }
}

struct RangeDecoder<'input> {
    input: &'input [u8],
    cursor: usize,
    range: u32,
    code: u32,
}

impl<'input> RangeDecoder<'input> {
    fn new(input: &'input [u8], control: &mut ParseControl<'_>) -> Result<Self> {
        let mut decoder = Self {
            input,
            cursor: 0,
            range: u32::MAX,
            code: 0,
        };
        if decoder.read_byte(control)? != 0 {
            return Err(format_error("LZMA range stream does not begin with zero"));
        }
        for _ in 0..4 {
            let byte = decoder.read_byte(control)?;
            decoder.code = decoder.code.wrapping_shl(8) | u32::from(byte);
        }
        if decoder.code >= decoder.range {
            return Err(format_error("invalid initial LZMA range state"));
        }
        Ok(decoder)
    }

    fn read_byte(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let byte = self
            .input
            .get(self.cursor)
            .copied()
            .ok_or_else(|| format_error("truncated LZMA range stream"))?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or_else(|| format_error("LZMA input cursor overflows"))?;
        Ok(byte)
    }

    fn normalize(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        if self.range >= TOP_VALUE {
            return Ok(());
        }
        self.range = self.range.wrapping_shl(8);
        let byte = self.read_byte(control)?;
        self.code = self.code.wrapping_shl(8) | u32::from(byte);
        Ok(())
    }

    fn decode_direct_bit(&mut self, control: &mut ParseControl<'_>) -> Result<u32> {
        self.range >>= 1;
        let bit = if self.code >= self.range {
            self.code = self
                .code
                .checked_sub(self.range)
                .ok_or_else(|| format_error("LZMA direct range code underflows"))?;
            1
        } else {
            0
        };
        self.normalize(control)?;
        Ok(bit)
    }

    const fn possibly_at_end(&self) -> bool {
        self.code == 0
    }

    fn is_finished(&self) -> bool {
        self.cursor == self.input.len()
    }
}

struct ProbabilityTree {
    probabilities: Vec<Probability>,
    bits: u32,
}

impl ProbabilityTree {
    fn new(bits: u32) -> Result<Self> {
        if !(1..=8).contains(&bits) {
            return Err(format_error("LZMA probability-tree width is invalid"));
        }
        let count = 1_usize
            .checked_shl(bits)
            .ok_or_else(|| format_error("LZMA probability-tree size overflows"))?;
        let mut probabilities = Vec::new();
        try_reserve(&mut probabilities, count)?;
        probabilities.resize(count, Probability::INITIAL);
        Ok(Self {
            probabilities,
            bits,
        })
    }

    fn reset(&mut self) {
        self.probabilities.fill(Probability::INITIAL);
    }

    fn decode(
        &mut self,
        range: &mut RangeDecoder<'_>,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let mut node = 1_usize;
        for _ in 0..self.bits {
            let bit = self
                .probabilities
                .get_mut(node)
                .ok_or_else(|| format_error("LZMA probability-tree index is out of range"))?
                .decode(range, control)?;
            let bit = usize::try_from(bit)
                .map_err(|_| format_error("LZMA decoded bit is not representable"))?;
            node = node
                .checked_mul(2)
                .and_then(|value| value.checked_add(bit))
                .ok_or_else(|| format_error("LZMA probability-tree index overflows"))?;
        }
        let base = 1_usize
            .checked_shl(self.bits)
            .ok_or_else(|| format_error("LZMA probability-tree base overflows"))?;
        let value = node
            .checked_sub(base)
            .ok_or_else(|| format_error("LZMA probability-tree value underflows"))?;
        u32::try_from(value).map_err(|_| format_error("LZMA tree value is not representable"))
    }

    fn decode_reverse(
        &mut self,
        range: &mut RangeDecoder<'_>,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let mut node = 1_usize;
        let mut value = 0_u32;
        for shift in 0..self.bits {
            let bit = self
                .probabilities
                .get_mut(node)
                .ok_or_else(|| format_error("LZMA reverse-tree index is out of range"))?
                .decode(range, control)?;
            value |= bit
                .checked_shl(shift)
                .ok_or_else(|| format_error("LZMA reverse-tree value overflows"))?;
            let bit = usize::try_from(bit)
                .map_err(|_| format_error("LZMA decoded bit is not representable"))?;
            node = node
                .checked_mul(2)
                .and_then(|item| item.checked_add(bit))
                .ok_or_else(|| format_error("LZMA reverse-tree index overflows"))?;
        }
        Ok(value)
    }
}

struct LengthDecoder {
    choice: [Probability; 2],
    low: Vec<ProbabilityTree>,
    middle: Vec<ProbabilityTree>,
    high: ProbabilityTree,
}

impl LengthDecoder {
    fn new() -> Result<Self> {
        let mut low = Vec::new();
        let mut middle = Vec::new();
        try_reserve(&mut low, POSITION_STATES)?;
        try_reserve(&mut middle, POSITION_STATES)?;
        for _ in 0..POSITION_STATES {
            low.push(ProbabilityTree::new(3)?);
            middle.push(ProbabilityTree::new(3)?);
        }
        Ok(Self {
            choice: [Probability::INITIAL; 2],
            low,
            middle,
            high: ProbabilityTree::new(8)?,
        })
    }

    fn reset(&mut self) {
        self.choice.fill(Probability::INITIAL);
        for tree in &mut self.low {
            tree.reset();
        }
        for tree in &mut self.middle {
            tree.reset();
        }
        self.high.reset();
    }

    fn decode(
        &mut self,
        range: &mut RangeDecoder<'_>,
        position_state: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        if self
            .choice
            .get_mut(0)
            .ok_or_else(|| format_error("LZMA length choice is missing"))?
            .decode(range, control)?
            == 0
        {
            return self
                .low
                .get_mut(position_state)
                .ok_or_else(|| format_error("LZMA low-length state is out of range"))?
                .decode(range, control);
        }
        if self
            .choice
            .get_mut(1)
            .ok_or_else(|| format_error("LZMA length choice is missing"))?
            .decode(range, control)?
            == 0
        {
            return self
                .middle
                .get_mut(position_state)
                .ok_or_else(|| format_error("LZMA middle-length state is out of range"))?
                .decode(range, control)?
                .checked_add(8)
                .ok_or_else(|| format_error("LZMA length overflows"));
        }
        self.high
            .decode(range, control)?
            .checked_add(16)
            .ok_or_else(|| format_error("LZMA length overflows"))
    }
}

struct DistanceDecoder {
    position_slots: Vec<ProbabilityTree>,
    position_models: Vec<ProbabilityTree>,
    alignment: ProbabilityTree,
}

impl DistanceDecoder {
    fn new() -> Result<Self> {
        let mut position_slots = Vec::new();
        try_reserve(
            &mut position_slots,
            usize::try_from(LENGTH_STATES)
                .map_err(|_| format_error("LZMA length-state count is not representable"))?,
        )?;
        for _ in 0..LENGTH_STATES {
            position_slots.push(ProbabilityTree::new(POSITION_SLOT_BITS)?);
        }
        let model_count = END_POSITION_MODEL
            .checked_sub(START_POSITION_MODEL)
            .ok_or_else(|| format_error("LZMA position-model count underflows"))?;
        let mut position_models = Vec::new();
        try_reserve(
            &mut position_models,
            usize::try_from(model_count)
                .map_err(|_| format_error("LZMA position-model count is not representable"))?,
        )?;
        for slot in START_POSITION_MODEL..END_POSITION_MODEL {
            let bits = (slot >> 1)
                .checked_sub(1)
                .ok_or_else(|| format_error("LZMA position-model width underflows"))?;
            position_models.push(ProbabilityTree::new(bits)?);
        }
        Ok(Self {
            position_slots,
            position_models,
            alignment: ProbabilityTree::new(ALIGN_BITS)?,
        })
    }

    fn reset(&mut self) {
        for tree in &mut self.position_slots {
            tree.reset();
        }
        for tree in &mut self.position_models {
            tree.reset();
        }
        self.alignment.reset();
    }

    fn decode(
        &mut self,
        range: &mut RangeDecoder<'_>,
        length: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<u32> {
        let length_state = length.min(LENGTH_STATES.saturating_sub(1));
        let length_state = usize::try_from(length_state)
            .map_err(|_| format_error("LZMA length state is not representable"))?;
        let position_slot = self
            .position_slots
            .get_mut(length_state)
            .ok_or_else(|| format_error("LZMA position-slot state is out of range"))?
            .decode(range, control)?;
        if position_slot < START_POSITION_MODEL {
            return Ok(position_slot);
        }
        let bits = (position_slot >> 1)
            .checked_sub(1)
            .ok_or_else(|| format_error("LZMA distance width underflows"))?;
        let base = (2_u32 | (position_slot & 1))
            .checked_shl(bits)
            .ok_or_else(|| format_error("LZMA distance base overflows"))?;
        if position_slot < END_POSITION_MODEL {
            let model = position_slot
                .checked_sub(START_POSITION_MODEL)
                .ok_or_else(|| format_error("LZMA position-model index underflows"))?;
            let model = usize::try_from(model)
                .map_err(|_| format_error("LZMA position-model index is not representable"))?;
            let suffix = self
                .position_models
                .get_mut(model)
                .ok_or_else(|| format_error("LZMA position-model index is out of range"))?
                .decode_reverse(range, control)?;
            return base
                .checked_add(suffix)
                .ok_or_else(|| format_error("LZMA distance overflows"));
        }
        let direct_bits = bits
            .checked_sub(ALIGN_BITS)
            .ok_or_else(|| format_error("LZMA direct-distance width underflows"))?;
        let mut direct = 0_u32;
        for _ in 0..direct_bits {
            let bit = range.decode_direct_bit(control)?;
            direct = direct
                .checked_shl(1)
                .and_then(|value| value.checked_add(bit))
                .ok_or_else(|| format_error("LZMA direct distance overflows"))?;
        }
        let direct = direct
            .checked_shl(ALIGN_BITS)
            .ok_or_else(|| format_error("LZMA direct distance overflows"))?;
        let alignment = self.alignment.decode_reverse(range, control)?;
        base.checked_add(direct)
            .and_then(|value| value.checked_add(alignment))
            .ok_or_else(|| format_error("LZMA distance overflows"))
    }
}

struct LiteralDecoder {
    probabilities: Vec<Probability>,
    literal_context_bits: u32,
    literal_position_bits: u32,
}

impl LiteralDecoder {
    fn new(literal_context_bits: u32, literal_position_bits: u32) -> Result<Self> {
        let context_bits = literal_context_bits
            .checked_add(literal_position_bits)
            .ok_or_else(|| format_error("LZMA literal context width overflows"))?;
        if context_bits > 4 {
            return Err(format_error("LZMA literal context width exceeds 7z limits"));
        }
        let contexts = 1_usize
            .checked_shl(context_bits)
            .ok_or_else(|| format_error("LZMA literal context count overflows"))?;
        let count = contexts
            .checked_mul(0x300)
            .ok_or_else(|| format_error("LZMA literal probability count overflows"))?;
        let mut probabilities = Vec::new();
        try_reserve(&mut probabilities, count)?;
        probabilities.resize(count, Probability::INITIAL);
        Ok(Self {
            probabilities,
            literal_context_bits,
            literal_position_bits,
        })
    }

    fn reset(&mut self) {
        self.probabilities.fill(Probability::INITIAL);
    }

    fn decode(
        &mut self,
        range: &mut RangeDecoder<'_>,
        state: usize,
        match_byte: u8,
        previous_byte: u8,
        position: u64,
        control: &mut ParseControl<'_>,
    ) -> Result<u8> {
        let position_mask = 1_u64
            .checked_shl(self.literal_position_bits)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| format_error("LZMA literal position mask overflows"))?;
        let position_part = (position & position_mask)
            .checked_shl(self.literal_context_bits)
            .ok_or_else(|| format_error("LZMA literal position state overflows"))?;
        let previous_part =
            u64::from(previous_byte) >> (8_u32.saturating_sub(self.literal_context_bits));
        let literal_state = position_part | previous_part;
        let base = usize::try_from(literal_state)
            .map_err(|_| format_error("LZMA literal state is not representable"))?
            .checked_mul(0x300)
            .ok_or_else(|| format_error("LZMA literal probability base overflows"))?;
        let mut symbol = 1_u32;
        if state >= 7 {
            let mut matched = u32::from(match_byte);
            loop {
                let match_bit = (matched >> 7) & 1;
                matched = matched.wrapping_shl(1);
                let index = 1_u32
                    .checked_add(match_bit)
                    .and_then(|value| value.checked_shl(8))
                    .map(|value| value | symbol)
                    .ok_or_else(|| format_error("LZMA literal match index overflows"))?;
                let index = base
                    .checked_add(usize::try_from(index).map_err(|_| {
                        format_error("LZMA literal probability index is not representable")
                    })?)
                    .ok_or_else(|| format_error("LZMA literal probability index overflows"))?;
                let bit = self
                    .probabilities
                    .get_mut(index)
                    .ok_or_else(|| format_error("LZMA literal probability index is out of range"))?
                    .decode(range, control)?;
                symbol = symbol
                    .checked_shl(1)
                    .and_then(|value| value.checked_add(bit))
                    .ok_or_else(|| format_error("LZMA literal symbol overflows"))?;
                if match_bit != bit || symbol >= 0x100 {
                    break;
                }
            }
        }
        while symbol < 0x100 {
            let index = base
                .checked_add(usize::try_from(symbol).map_err(|_| {
                    format_error("LZMA literal probability index is not representable")
                })?)
                .ok_or_else(|| format_error("LZMA literal probability index overflows"))?;
            let bit = self
                .probabilities
                .get_mut(index)
                .ok_or_else(|| format_error("LZMA literal probability index is out of range"))?
                .decode(range, control)?;
            symbol = symbol
                .checked_shl(1)
                .and_then(|value| value.checked_add(bit))
                .ok_or_else(|| format_error("LZMA literal symbol overflows"))?;
        }
        let value = symbol
            .checked_sub(0x100)
            .ok_or_else(|| format_error("LZMA literal symbol underflows"))?;
        u8::try_from(value).map_err(|_| format_error("LZMA literal is not representable"))
    }
}

struct LzmaState {
    repetitions: [u32; 4],
    is_match: [Probability; STATE_COUNT * POSITION_STATES],
    is_rep_zero_long: [Probability; STATE_COUNT * POSITION_STATES],
    is_rep: [Probability; STATE_COUNT],
    is_rep_zero: [Probability; STATE_COUNT],
    is_rep_one: [Probability; STATE_COUNT],
    is_rep_two: [Probability; STATE_COUNT],
    literal: LiteralDecoder,
    length: LengthDecoder,
    repetition_length: LengthDecoder,
    distance: DistanceDecoder,
    state: usize,
    position_mask: u64,
}

impl LzmaState {
    fn new(lc: u32, lp: u32, pb: u32) -> Result<Self> {
        if pb > 4 {
            return Err(format_error("LZMA position-bit property is invalid"));
        }
        let position_mask = 1_u64
            .checked_shl(pb)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| format_error("LZMA position mask overflows"))?;
        Ok(Self {
            repetitions: [0; 4],
            is_match: [Probability::INITIAL; STATE_COUNT * POSITION_STATES],
            is_rep_zero_long: [Probability::INITIAL; STATE_COUNT * POSITION_STATES],
            is_rep: [Probability::INITIAL; STATE_COUNT],
            is_rep_zero: [Probability::INITIAL; STATE_COUNT],
            is_rep_one: [Probability::INITIAL; STATE_COUNT],
            is_rep_two: [Probability::INITIAL; STATE_COUNT],
            literal: LiteralDecoder::new(lc, lp)?,
            length: LengthDecoder::new()?,
            repetition_length: LengthDecoder::new()?,
            distance: DistanceDecoder::new()?,
            state: 0,
            position_mask,
        })
    }

    fn reset(&mut self) {
        self.repetitions.fill(0);
        self.is_match.fill(Probability::INITIAL);
        self.is_rep_zero_long.fill(Probability::INITIAL);
        self.is_rep.fill(Probability::INITIAL);
        self.is_rep_zero.fill(Probability::INITIAL);
        self.is_rep_one.fill(Probability::INITIAL);
        self.is_rep_two.fill(Probability::INITIAL);
        self.literal.reset();
        self.length.reset();
        self.repetition_length.reset();
        self.distance.reset();
        self.state = 0;
    }

    fn update_literal(&mut self) {
        self.state = if self.state < 4 {
            0
        } else if self.state < 10 {
            self.state.saturating_sub(3)
        } else {
            self.state.saturating_sub(6)
        };
    }

    fn update_match(&mut self) {
        self.state = if self.state < 7 { 7 } else { 10 };
    }

    fn update_repetition(&mut self) {
        self.state = if self.state < 7 { 8 } else { 11 };
    }

    fn update_short_repetition(&mut self) {
        self.state = if self.state < 7 { 9 } else { 11 };
    }
}

enum Operation {
    Literal(u8),
    Match { distance: u32, length: u32 },
    End,
}

struct Output {
    bytes: Vec<u8>,
    maximum: u64,
    dictionary_size: u64,
    dictionary_start: usize,
}

impl Output {
    fn new(maximum: u64, dictionary_size: u64, expected: Option<u64>) -> Result<Self> {
        check_limit(expected.unwrap_or(0), maximum, LimitKind::TotalOutputBytes)?;
        let mut bytes = Vec::new();
        if let Some(expected) = expected {
            let capacity = u64_to_usize(
                expected,
                "LZMA output size is not representable on this platform",
            )?;
            try_reserve(&mut bytes, capacity)?;
        }
        Ok(Self {
            bytes,
            maximum,
            dictionary_size,
            dictionary_start: 0,
        })
    }

    fn reset_dictionary(&mut self) {
        self.dictionary_start = self.bytes.len();
    }

    fn position(&self) -> Result<u64> {
        usize_to_u64(
            self.bytes.len(),
            "decoded LZMA position is not representable as u64",
        )
    }

    fn dictionary_length(&self) -> Result<u64> {
        let length = self
            .bytes
            .len()
            .checked_sub(self.dictionary_start)
            .ok_or_else(|| format_error("LZMA dictionary position underflows"))?;
        usize_to_u64(length, "LZMA dictionary length is not representable as u64")
    }

    fn previous_byte(&self) -> u8 {
        self.bytes.last().copied().unwrap_or(0)
    }

    fn match_byte(&self, distance_offset: u32) -> u8 {
        let Some(distance) = usize::try_from(distance_offset)
            .ok()
            .and_then(|value| value.checked_add(1))
        else {
            return 0;
        };
        self.bytes
            .len()
            .checked_sub(distance)
            .and_then(|index| self.bytes.get(index).copied())
            .unwrap_or(0)
    }

    fn ensure_additional(&mut self, additional: u64) -> Result<()> {
        let requested = self
            .position()?
            .checked_add(additional)
            .ok_or_else(|| format_error("decoded LZMA size overflows"))?;
        check_limit(requested, self.maximum, LimitKind::TotalOutputBytes)?;
        let additional = u64_to_usize(
            additional,
            "LZMA output increment is not representable on this platform",
        )?;
        self.bytes.try_reserve(additional).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "LZMA output allocation failed",
            ))
        })
    }

    fn push(&mut self, byte: u8, control: &mut ParseControl<'_>) -> Result<()> {
        self.ensure_additional(1)?;
        control.checkpoint(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend_uncompressed(&mut self, bytes: &[u8], control: &mut ParseControl<'_>) -> Result<()> {
        self.ensure_additional(usize_to_u64(
            bytes.len(),
            "LZMA2 uncompressed chunk length is not representable as u64",
        )?)?;
        for chunk in bytes.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "LZMA2 work chunk length is not representable as u64",
            )?)?;
            self.bytes.extend_from_slice(chunk);
        }
        Ok(())
    }

    fn copy_match(
        &mut self,
        distance: u32,
        length: u32,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let distance_u64 = u64::from(distance);
        if distance_u64 == 0 {
            return Err(format_error("LZMA match distance is zero"));
        }
        if distance_u64 > self.dictionary_size {
            return Err(format_error(
                "LZMA match distance exceeds the declared dictionary",
            ));
        }
        if distance_u64 > self.dictionary_length()? {
            return Err(Error::Format {
                detail: format!(
                    "LZMA match distance {distance_u64} exceeds available history {} at output {}",
                    self.dictionary_length()?,
                    self.position()?
                ),
            });
        }
        self.ensure_additional(u64::from(length))?;
        let distance = usize::try_from(distance)
            .map_err(|_| format_error("LZMA match distance is not representable"))?;
        for _ in 0..length {
            control.checkpoint(1)?;
            let source = self
                .bytes
                .len()
                .checked_sub(distance)
                .ok_or_else(|| format_error("LZMA match source underflows"))?;
            let byte = self
                .bytes
                .get(source)
                .copied()
                .ok_or_else(|| format_error("LZMA match source is out of range"))?;
            self.bytes.push(byte);
        }
        Ok(())
    }
}

fn properties_from_byte(byte: u8) -> Result<(u32, u32, u32)> {
    let parameter = u32::from(byte);
    if parameter > 224 {
        return Err(format_error("invalid LZMA property byte"));
    }
    let lc = parameter % 9;
    let remainder = parameter / 9;
    let lp = remainder % 5;
    let pb = remainder / 5;
    if pb > 4 || lc.checked_add(lp).is_none_or(|sum| sum > 4) {
        return Err(format_error("invalid LZMA lc/lp/pb properties"));
    }
    Ok((lc, lp, pb))
}

fn decode_operation(
    state: &mut LzmaState,
    range: &mut RangeDecoder<'_>,
    output: &Output,
    control: &mut ParseControl<'_>,
) -> Result<Operation> {
    control.checkpoint(1)?;
    let position = output.position()?;
    let position_state = usize::try_from(position & state.position_mask)
        .map_err(|_| format_error("LZMA position state is not representable"))?;
    let combined = state
        .state
        .checked_mul(POSITION_STATES)
        .and_then(|value| value.checked_add(position_state))
        .ok_or_else(|| format_error("LZMA state index overflows"))?;
    if state
        .is_match
        .get_mut(combined)
        .ok_or_else(|| format_error("LZMA match state is out of range"))?
        .decode(range, control)?
        == 0
    {
        let previous = output.previous_byte();
        let matched = output.match_byte(
            *state
                .repetitions
                .first()
                .ok_or_else(|| format_error("LZMA repetition state is missing"))?,
        );
        let literal =
            state
                .literal
                .decode(range, state.state, matched, previous, position, control)?;
        state.update_literal();
        return Ok(Operation::Literal(literal));
    }
    if state
        .is_rep
        .get_mut(state.state)
        .ok_or_else(|| format_error("LZMA repetition state is out of range"))?
        .decode(range, control)?
        == 0
    {
        let rep0 = *state
            .repetitions
            .first()
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
        let rep1 = *state
            .repetitions
            .get(1)
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
        let rep2 = *state
            .repetitions
            .get(2)
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
        if let Some(item) = state.repetitions.get_mut(3) {
            *item = rep2;
        }
        if let Some(item) = state.repetitions.get_mut(2) {
            *item = rep1;
        }
        if let Some(item) = state.repetitions.get_mut(1) {
            *item = rep0;
        }
        state.update_match();
        let length_offset = state.length.decode(range, position_state, control)?;
        let distance_offset = state.distance.decode(range, length_offset, control)?;
        if let Some(item) = state.repetitions.first_mut() {
            *item = distance_offset;
        }
        if distance_offset == EOS_DISTANCE {
            return Ok(Operation::End);
        }
        return Ok(Operation::Match {
            distance: distance_offset
                .checked_add(1)
                .ok_or_else(|| format_error("LZMA match distance overflows"))?,
            length: length_offset
                .checked_add(MIN_MATCH_LENGTH)
                .ok_or_else(|| format_error("LZMA match length overflows"))?,
        });
    }

    let mut distance = *state
        .repetitions
        .first()
        .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
    let uses_previous_distance = state
        .is_rep_zero
        .get_mut(state.state)
        .ok_or_else(|| format_error("LZMA repetition-zero state is out of range"))?
        .decode(range, control)?
        != 0;
    if !uses_previous_distance {
        if state
            .is_rep_zero_long
            .get_mut(combined)
            .ok_or_else(|| format_error("LZMA short-repetition state is out of range"))?
            .decode(range, control)?
            == 0
        {
            state.update_short_repetition();
            return Ok(Operation::Match {
                distance: distance
                    .checked_add(1)
                    .ok_or_else(|| format_error("LZMA repetition distance overflows"))?,
                length: 1,
            });
        }
    } else if state
        .is_rep_one
        .get_mut(state.state)
        .ok_or_else(|| format_error("LZMA repetition-one state is out of range"))?
        .decode(range, control)?
        == 0
    {
        distance = *state
            .repetitions
            .get(1)
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
    } else {
        let use_rep_two = state
            .is_rep_two
            .get_mut(state.state)
            .ok_or_else(|| format_error("LZMA repetition-two state is out of range"))?
            .decode(range, control)?
            == 0;
        distance = if use_rep_two {
            *state
                .repetitions
                .get(2)
                .ok_or_else(|| format_error("LZMA repetition state is missing"))?
        } else {
            let value = *state
                .repetitions
                .get(3)
                .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
            let rep2 = *state
                .repetitions
                .get(2)
                .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
            if let Some(item) = state.repetitions.get_mut(3) {
                *item = rep2;
            }
            value
        };
        let rep1 = *state
            .repetitions
            .get(1)
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
        if let Some(item) = state.repetitions.get_mut(2) {
            *item = rep1;
        }
    }
    if uses_previous_distance {
        let rep0 = *state
            .repetitions
            .first()
            .ok_or_else(|| format_error("LZMA repetition state is missing"))?;
        if let Some(item) = state.repetitions.get_mut(1) {
            *item = rep0;
        }
        if let Some(item) = state.repetitions.first_mut() {
            *item = distance;
        }
    }
    let length_offset = state
        .repetition_length
        .decode(range, position_state, control)?;
    state.update_repetition();
    Ok(Operation::Match {
        distance: distance
            .checked_add(1)
            .ok_or_else(|| format_error("LZMA repetition distance overflows"))?,
        length: length_offset
            .checked_add(MIN_MATCH_LENGTH)
            .ok_or_else(|| format_error("LZMA repetition length overflows"))?,
    })
}

fn decode_stream(
    state: &mut LzmaState,
    input: &[u8],
    output: &mut Output,
    expected_increment: Option<u64>,
    require_eos: bool,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let start = output.position()?;
    let target = expected_increment
        .map(|size| {
            start
                .checked_add(size)
                .ok_or_else(|| format_error("LZMA target size overflows"))
        })
        .transpose()?;
    if let Some(target) = target {
        check_limit(target, output.maximum, LimitKind::TotalOutputBytes)?;
    }
    let mut range = RangeDecoder::new(input, control)?;
    loop {
        if let Some(size) = target {
            if output.position()? == size {
                return Ok(());
            }
        }
        let operation = decode_operation(state, &mut range, output, control)?;
        match operation {
            Operation::Literal(byte) => output.push(byte, control)?,
            Operation::Match { distance, length } => {
                if let Some(target) = target {
                    let resulting = output
                        .position()?
                        .checked_add(u64::from(length))
                        .ok_or_else(|| format_error("LZMA match result size overflows"))?;
                    if resulting > target {
                        return Err(format_error("LZMA output exceeds its declared size"));
                    }
                }
                output.copy_match(distance, length, control)?;
            }
            Operation::End => {
                if !range.possibly_at_end() {
                    return Err(format_error("LZMA range state is not final at EOS"));
                }
                if !range.is_finished() {
                    return Err(format_error("LZMA stream has trailing input after EOS"));
                }
                if let Some(target) = target {
                    if output.position()? != target {
                        return Err(format_error("LZMA EOS precedes its declared size"));
                    }
                }
                return if require_eos || target.is_some() {
                    Ok(())
                } else {
                    Err(format_error("LZMA stream ended unexpectedly"))
                };
            }
        }
    }
}

fn lzma_dictionary(properties: &[u8]) -> Result<(u8, u32)> {
    let bytes = <[u8; 5]>::try_from(properties)
        .map_err(|_| format_error("LZMA properties must contain exactly five bytes"))?;
    let dictionary = u32::from_le_bytes(
        <[u8; 4]>::try_from(
            bytes
                .get(1..5)
                .ok_or_else(|| format_error("LZMA dictionary property is truncated"))?,
        )
        .map_err(|_| format_error("LZMA dictionary property is truncated"))?,
    );
    Ok((
        *bytes
            .first()
            .ok_or_else(|| format_error("LZMA property byte is missing"))?,
        dictionary.max(1),
    ))
}

pub(crate) fn decode_lzma(
    input: &[u8],
    properties: &[u8],
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let (property, dictionary) = lzma_dictionary(properties)?;
    let (lc, lp, pb) = properties_from_byte(property)?;
    let mut state = LzmaState::new(lc, lp, pb)?;
    let mut output = Output::new(maximum, u64::from(dictionary), expected)?;
    decode_stream(
        &mut state,
        input,
        &mut output,
        expected,
        expected.is_none(),
        control,
    )?;
    Ok(output.bytes)
}

fn lzma2_dictionary(properties: &[u8]) -> Result<u64> {
    let property = *properties
        .first()
        .ok_or_else(|| format_error("LZMA2 dictionary property is missing"))?;
    if properties.len() != 1 || property > 40 {
        return Err(format_error("invalid LZMA2 dictionary property"));
    }
    let property = u32::from(property);
    let shift = (property / 2)
        .checked_add(11)
        .ok_or_else(|| format_error("LZMA2 dictionary shift overflows"))?;
    u64::from(2_u32 | (property & 1))
        .checked_shl(shift)
        .ok_or_else(|| format_error("LZMA2 dictionary size overflows"))
}

struct SliceCursor<'input> {
    bytes: &'input [u8],
    position: usize,
}

impl<'input> SliceCursor<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| format_error("truncated LZMA2 stream"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| format_error("LZMA2 input cursor overflows"))?;
        Ok(byte)
    }

    fn read_u16_be(&mut self, control: &mut ParseControl<'_>) -> Result<u16> {
        let high = self.read_u8(control)?;
        let low = self.read_u8(control)?;
        Ok((u16::from(high) << 8) | u16::from(low))
    }

    fn read_bytes(
        &mut self,
        length: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<&'input [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| format_error("LZMA2 input range overflows"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| format_error("truncated LZMA2 chunk"))?;
        control.consume_bytes(bytes)?;
        self.position = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

pub(crate) fn decode_lzma2(
    input: &[u8],
    properties: &[u8],
    expected: Option<u64>,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    let dictionary = lzma2_dictionary(properties)?;
    let mut output = Output::new(maximum, dictionary.max(1), expected)?;
    let mut input = SliceCursor::new(input);
    let mut state: Option<LzmaState> = None;
    let mut needs_dictionary_reset = true;
    let mut needs_properties = true;
    loop {
        control.checkpoint(1)?;
        let control_byte = input.read_u8(control)?;
        if control_byte == 0 {
            if !input.is_finished() {
                return Err(format_error("LZMA2 stream has trailing bytes after EOS"));
            }
            if let Some(expected) = expected {
                if output.position()? != expected {
                    return Err(format_error(
                        "LZMA2 output size does not match its declaration",
                    ));
                }
            }
            return Ok(output.bytes);
        }
        if control_byte >= 0xe0 || control_byte == 1 {
            output.reset_dictionary();
            needs_dictionary_reset = false;
            needs_properties = true;
        } else if needs_dictionary_reset {
            return Err(format_error(
                "LZMA2 stream omits its initial dictionary reset",
            ));
        }
        if control_byte >= 0x80 {
            let high = u64::from(control_byte & 0x1f)
                .checked_shl(16)
                .ok_or_else(|| format_error("LZMA2 chunk size overflows"))?;
            let unpacked = high
                .checked_add(u64::from(input.read_u16_be(control)?))
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| format_error("LZMA2 chunk size overflows"))?;
            let packed = usize::from(input.read_u16_be(control)?)
                .checked_add(1)
                .ok_or_else(|| format_error("LZMA2 packed chunk size overflows"))?;
            if control_byte >= 0xc0 {
                let property = input.read_u8(control)?;
                let (lc, lp, pb) = properties_from_byte(property)?;
                state = Some(LzmaState::new(lc, lp, pb)?);
                needs_properties = false;
            } else if needs_properties {
                return Err(format_error(
                    "LZMA2 compressed chunk omits required properties",
                ));
            } else if control_byte >= 0xa0 {
                state
                    .as_mut()
                    .ok_or_else(|| format_error("LZMA2 decoder state is missing"))?
                    .reset();
            }
            let packed = input.read_bytes(packed, control)?;
            decode_stream(
                state
                    .as_mut()
                    .ok_or_else(|| format_error("LZMA2 decoder properties are missing"))?,
                packed,
                &mut output,
                Some(unpacked),
                false,
                control,
            )?;
        } else if control_byte <= 2 {
            let unpacked = usize::from(input.read_u16_be(control)?)
                .checked_add(1)
                .ok_or_else(|| format_error("LZMA2 uncompressed chunk size overflows"))?;
            let bytes = input.read_bytes(unpacked, control)?;
            output.extend_uncompressed(bytes, control)?;
        } else {
            return Err(format_error("reserved LZMA2 control byte"));
        }
        if let Some(expected) = expected {
            if output.position()? > expected {
                return Err(format_error("LZMA2 output exceeds its declared size"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_lzma, decode_lzma2};
    use crate::{
        CancellationToken, Error, LimitKind, Result, WorkBudget, parse_util::ParseControl,
    };

    const UNCOMPRESSED_LZMA2: &[u8] = &[1, 0, 2, b'a', b'b', b'c', 0];
    // `abc`, raw LZMA1 with an EOS marker and lc=3/lp=0/pb=2/dict=4 KiB,
    // generated by XZ Utils 5.8.3 for a deterministic unknown-size regression.
    const EOS_LZMA: &[u8] = &[
        0x00, 0x30, 0x98, 0x88, 0xa4, 0x4a, 0x8e, 0x9f, 0xff, 0xf6, 0x63, 0x80, 0x00,
    ];
    const EOS_LZMA_PROPERTIES: &[u8] = &[0x5d, 0x00, 0x10, 0x00, 0x00];

    #[test]
    fn lzma2_uncompressed_chunk_decodes() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let output = decode_lzma2(UNCOMPRESSED_LZMA2, &[0], Some(3), 3, &mut control);
        assert!(output.as_deref().is_ok_and(|bytes| bytes == b"abc"));
    }

    #[test]
    fn lzma2_unknown_size_requires_and_accepts_eos() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let output = decode_lzma2(UNCOMPRESSED_LZMA2, &[0], None, 3, &mut control);
        assert!(output.as_deref().is_ok_and(|bytes| bytes == b"abc"));

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let without_eos = UNCOMPRESSED_LZMA2
            .get(..UNCOMPRESSED_LZMA2.len().saturating_sub(1))
            .unwrap_or(&[]);
        assert!(decode_lzma2(without_eos, &[0], None, 3, &mut control).is_err());
    }

    #[test]
    fn lzma_unknown_size_requires_and_accepts_eos() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let output = decode_lzma(EOS_LZMA, EOS_LZMA_PROPERTIES, None, 3, &mut control);
        assert!(output.as_deref().is_ok_and(|bytes| bytes == b"abc"));

        let mut trailing = EOS_LZMA.to_vec();
        trailing.push(0);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(
            decode_lzma(&trailing, EOS_LZMA_PROPERTIES, None, 3, &mut control).is_err(),
            "LZMA trailing input after EOS was accepted"
        );

        for end in 0..EOS_LZMA.len() {
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut control = ParseControl::new(&cancellation, &mut budget);
            let prefix = EOS_LZMA.get(..end).unwrap_or_default();
            assert!(
                decode_lzma(prefix, EOS_LZMA_PROPERTIES, None, 3, &mut control).is_err(),
                "LZMA EOS truncation at byte {end} was accepted"
            );
        }
    }

    #[test]
    fn lzma_rejects_truncated_range_state() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(decode_lzma(&[0], &[0, 0x00, 0x10, 0x00, 0x00], Some(1), 1, &mut control).is_err());
    }

    #[test]
    fn every_lzma2_prefix_is_rejected() {
        for length in 0..UNCOMPRESSED_LZMA2.len() {
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let mut control = ParseControl::new(&cancellation, &mut budget);
            let prefix = UNCOMPRESSED_LZMA2.get(..length).unwrap_or(&[]);
            assert!(decode_lzma2(prefix, &[0], Some(3), 3, &mut control).is_err());
        }
    }

    #[test]
    fn lzma2_checks_output_limit_before_work() {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_lzma2(UNCOMPRESSED_LZMA2, &[0], Some(3), 2, &mut control),
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalOutputBytes,
                requested: 3,
                maximum: 2
            })
        ));
        assert_eq!(budget.remaining(), Some(0));
    }

    #[test]
    fn lzma2_observes_cancellation_inside_input_loop() -> Result<()> {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_lzma2(UNCOMPRESSED_LZMA2, &[0], Some(3), 3, &mut control),
            Err(Error::Cancelled)
        ));
        Ok(())
    }
}
