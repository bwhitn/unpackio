//! Safe, bounded WinZip JPEG recompression (ZIP method 96) decoding.
//!
//! The arithmetic model and prediction formulas are adapted from the
//! MIT-licensed XArchive implementation identified in `PROVENANCE.md`. This
//! rewrite uses checked parsing and arithmetic, fallible allocation, explicit
//! operation control, and exact outer-stream consumption.
//!
//! Copyright (c) 2026 hors

use std::mem::size_of;

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{ParseControl, check_limit, format_error, try_reserve, usize_to_u64},
};

use super::{
    decode_lzma_exact,
    winzip_jpeg_tables::{ANTILOG_TABLE, LOG_TABLE},
};

const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
const MODEL_COUNT: usize = 28_328;

const LOG_P: [i32; 49] = [
    1024, 895, 795, 706, 628, 559, 493, 437, 379, 331, 287, 247, 212, 186, 158, 143, 127, 110, 98,
    84, 72, 65, 59, 53, 48, 45, 42, 40, 37, 35, 33, 30, 28, 26, 23, 21, 19, 17, 15, 13, 11, 9, 7,
    5, 4, 3, 2, 1, 1024,
];
const LOG_QP: [i32; 49] = [
    0, 272, 502, 726, 941, 1150, 1371, 1578, 1819, 2044, 2278, 2521, 2765, 2971, 3227, 3382, 3566,
    3788, 3965, 4200, 4435, 4590, 4737, 4899, 5050, 5147, 5250, 5325, 5441, 5527, 5617, 5758, 5863,
    5976, 6157, 6295, 6447, 6616, 6806, 7024, 7278, 7585, 7972, 8495, 8884, 9309, 10065, 11689, 0,
];
const N_MAX_LP: [i32; 49] = [
    16384, 16110, 15105, 14826, 14444, 13975, 13804, 13547, 13265, 13240, 12915, 12844, 12720,
    12648, 12482, 12441, 12319, 12320, 12250, 12180, 12168, 12155, 12154, 12084, 12096, 12105,
    12096, 12080, 12062, 12075, 12078, 12060, 12068, 12090, 12075, 12075, 12103, 12121, 12150,
    12181, 12221, 12294, 12411, 12615, 13120, 13113, 14574, 21860, 0,
];
const HALF_I: [usize; 49] = [
    8, 8, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 9, 10, 10, 10, 10, 10, 10, 9, 9, 8,
    8, 7, 7, 6, 6, 6, 5, 5, 4, 4, 3, 3, 3, 3, 2, 2, 1, 0, 0,
];
const DBL_I: [usize; 49] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10,
    10, 10, 10, 10, 10, 9, 8, 7, 6, 6, 5, 4, 3, 3, 3, 2, 1, 0,
];

const ZIGZAG: [[usize; 8]; 8] = [
    [0, 1, 5, 6, 14, 15, 27, 28],
    [2, 4, 7, 13, 16, 26, 29, 42],
    [3, 8, 12, 17, 25, 30, 41, 43],
    [9, 11, 18, 24, 31, 40, 44, 53],
    [10, 19, 23, 32, 39, 45, 52, 54],
    [20, 22, 33, 38, 46, 51, 55, 60],
    [21, 34, 37, 47, 50, 56, 59, 61],
    [35, 36, 48, 49, 57, 58, 62, 63],
];
const ROW: [usize; 64] = [
    0, 0, 1, 2, 1, 0, 0, 1, 2, 3, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3,
    4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 4, 5, 6, 7, 7, 6, 5, 6, 7, 7,
];
const COLUMN: [usize; 64] = [
    0, 1, 0, 0, 1, 2, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 6, 5, 4,
    3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 5, 6, 7, 7, 6, 7,
];

struct Input<'input> {
    bytes: &'input [u8],
    position: usize,
}

impl<'input> Input<'input> {
    const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_byte(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        let value = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| format_error("truncated WinZip JPEG stream"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG input position overflows"))?;
        Ok(value)
    }

    fn read_slice(
        &mut self,
        length: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<&'input [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| format_error("WinZip JPEG input range overflows"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| format_error("truncated WinZip JPEG stream"))?;
        control.consume_bytes(value)?;
        self.position = end;
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[derive(Clone, Copy)]
struct Bin {
    index: usize,
    dlrm: i32,
    mps: u8,
    k: u8,
}

impl Bin {
    const fn adaptive() -> Self {
        Self {
            index: 0,
            dlrm: N_MAX_LP[0],
            mps: 0,
            k: 0,
        }
    }

    const fn fixed() -> Self {
        Self {
            index: 48,
            dlrm: N_MAX_LP[0],
            mps: 0,
            k: 0,
        }
    }
}

struct ArithmeticDecoder<'cursor, 'input> {
    input: &'cursor mut Input<'input>,
    current_byte: u8,
    last_byte: u8,
    x: u32,
    lr: i32,
    lrm: i32,
    lx: i32,
}

impl<'cursor, 'input> ArithmeticDecoder<'cursor, 'input> {
    fn new(input: &'cursor mut Input<'input>, control: &mut ParseControl<'_>) -> Result<Self> {
        let mut decoder = Self {
            input,
            current_byte: 0,
            last_byte: 0,
            x: 0,
            lr: 0x1001,
            lrm: 0x1001,
            lx: 0,
        };
        let first = decoder.byte_in(control)?;
        let second = decoder.byte_in(control)?;
        decoder.x = (u32::from(first) << 8) | u32::from(second);
        decoder.lx = log_x(decoder.x)?;
        if decoder.x == 0xffff {
            let _ = decoder.byte_in(control)?;
        }
        Ok(decoder)
    }

    fn byte_in(&mut self, control: &mut ParseControl<'_>) -> Result<u8> {
        self.last_byte = self.current_byte;
        self.current_byte = self.input.read_byte(control)?;
        Ok(self.current_byte)
    }

    fn renormalize(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        while self.lr > 0x1fff {
            if self.current_byte == 0xff && self.last_byte == 0xff {
                self.x = self.x.wrapping_add(u32::from(self.byte_in(control)?));
            }
            self.x = self.x.wrapping_shl(8) | u32::from(self.byte_in(control)?);
            self.lr = self
                .lr
                .checked_sub(0x2000)
                .ok_or_else(|| format_error("WinZip JPEG arithmetic range underflows"))?;
            self.lrm = self
                .lrm
                .checked_sub(0x2000)
                .ok_or_else(|| format_error("WinZip JPEG arithmetic model range underflows"))?;
        }
        self.lx = log_x(self.x)?;
        Ok(())
    }

    fn lrm_big(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        if self.lrm > 0x7ff {
            self.renormalize(control)?;
        }
        Ok(())
    }

    fn flush(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        self.renormalize(control)?;
        if self.current_byte == 0xff && self.last_byte == 0xff {
            let _ = self.byte_in(control)?;
        }
        Ok(())
    }

    fn decode_bit(&mut self, bin: &mut Bin, control: &mut ParseControl<'_>) -> Result<u8> {
        control.checkpoint(1)?;
        self.lrm = self
            .lr
            .checked_add(bin.dlrm)
            .ok_or_else(|| format_error("WinZip JPEG arithmetic model range overflows"))?;
        self.lrm_big(control)?;
        self.lr = self
            .lr
            .checked_add(table_i32(&LOG_P, bin.index)?)
            .ok_or_else(|| format_error("WinZip JPEG arithmetic range overflows"))?;

        let mut bit = bin.mps;
        let threshold = self.lrm.min(self.lx);
        if self.lr >= threshold {
            if self.lr < self.lx {
                self.update_mps(bin, control)?;
            } else {
                self.renormalize(control)?;
                if self.lr < self.lx {
                    if self.lr >= self.lrm {
                        self.update_mps(bin, control)?;
                    }
                } else {
                    bit ^= 1;
                    bin.k = bin
                        .k
                        .checked_add(1)
                        .ok_or_else(|| format_error("WinZip JPEG probability count overflows"))?;
                    self.x = self
                        .x
                        .checked_sub(antilog_x(self.lr)?)
                        .ok_or_else(|| format_error("invalid WinZip JPEG arithmetic code state"))?;
                    self.lx = log_x(self.x)?;
                    self.update_lps(bin)?;
                }
            }
        }
        bin.dlrm = self
            .lrm
            .checked_sub(self.lr)
            .ok_or_else(|| format_error("WinZip JPEG probability distance underflows"))?;
        Ok(bit)
    }

    fn update_mps(&mut self, bin: &mut Bin, control: &mut ParseControl<'_>) -> Result<()> {
        if bin.k <= 5 {
            q_smaller(bin)?;
        }
        bin.k = 0;
        self.lrm = self
            .lr
            .checked_add(table_i32(&N_MAX_LP, bin.index)?)
            .ok_or_else(|| format_error("WinZip JPEG MPS range overflows"))?;
        self.lrm_big(control)
    }

    fn update_lps(&mut self, bin: &mut Bin) -> Result<()> {
        let increment = table_i32(&LOG_QP, bin.index)?;
        self.lr = self
            .lr
            .checked_add(increment)
            .ok_or_else(|| format_error("WinZip JPEG LPS range overflows"))?;
        self.lrm = self
            .lrm
            .checked_add(increment)
            .ok_or_else(|| format_error("WinZip JPEG LPS model range overflows"))?;
        if bin.k >= 11 {
            q_bigger(self, bin)?;
            bin.k = 0;
            self.lrm = self
                .lr
                .checked_add(table_i32(&N_MAX_LP, bin.index)?)
                .ok_or_else(|| format_error("WinZip JPEG adapted range overflows"))?;
        } else if self.lrm < self.lr {
            self.lrm = self.lr;
        }
        Ok(())
    }
}

fn table_i32(table: &[i32; 49], index: usize) -> Result<i32> {
    table
        .get(index)
        .copied()
        .ok_or_else(|| format_error("WinZip JPEG probability index is out of range"))
}

fn q_smaller(bin: &mut Bin) -> Result<()> {
    if bin.index >= 47 {
        return Ok(());
    }
    bin.index = bin
        .index
        .checked_add(1)
        .ok_or_else(|| format_error("WinZip JPEG probability index overflows"))?;
    if bin.k <= 1 {
        bin.index = bin
            .index
            .checked_add(
                *HALF_I
                    .get(bin.index)
                    .ok_or_else(|| format_error("WinZip JPEG probability index is out of range"))?,
            )
            .ok_or_else(|| format_error("WinZip JPEG probability index overflows"))?;
        if bin.k == 0 {
            bin.index =
                bin.index
                    .checked_add(*HALF_I.get(bin.index).ok_or_else(|| {
                        format_error("WinZip JPEG probability index is out of range")
                    })?)
                    .ok_or_else(|| format_error("WinZip JPEG probability index overflows"))?;
        }
    }
    if bin.index > 47 {
        return Err(format_error(
            "WinZip JPEG probability index exceeds its adaptive range",
        ));
    }
    Ok(())
}

fn decrement_index(index: &mut usize, saved: &mut usize) -> Result<()> {
    if *index > 0 {
        *index = index
            .checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG probability index underflows"))?;
    } else {
        *saved = saved
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG probability adjustment overflows"))?;
    }
    Ok(())
}

fn double_index(index: &mut usize, saved: &mut usize) -> Result<()> {
    let delta = *DBL_I
        .get(*index)
        .ok_or_else(|| format_error("WinZip JPEG probability index is out of range"))?;
    if *index > 0 {
        *index = index
            .checked_sub(delta)
            .ok_or_else(|| format_error("WinZip JPEG probability index underflows"))?;
    } else {
        *saved = saved
            .checked_add(delta)
            .ok_or_else(|| format_error("WinZip JPEG probability adjustment overflows"))?;
    }
    Ok(())
}

fn q_bigger(decoder: &mut ArithmeticDecoder<'_, '_>, bin: &mut Bin) -> Result<()> {
    if bin.index >= 48 {
        return Ok(());
    }
    let maximum = table_i32(&N_MAX_LP, bin.index)?;
    let mut dlrm = decoder
        .lrm
        .checked_sub(decoder.lr)
        .ok_or_else(|| format_error("WinZip JPEG adaptation distance underflows"))?;
    let mut saved = 0_usize;
    if dlrm >= maximum / 2 {
        dlrm = maximum
            .checked_sub(dlrm)
            .ok_or_else(|| format_error("WinZip JPEG adaptation distance is invalid"))?;
        if dlrm <= maximum / 4 {
            double_index(&mut bin.index, &mut saved)?;
        }
        double_index(&mut bin.index, &mut saved)?;
    } else {
        if dlrm >= maximum / 4 {
            decrement_index(&mut bin.index, &mut saved)?;
        }
        decrement_index(&mut bin.index, &mut saved)?;
    }
    if bin.index == 0 {
        bin.index = saved;
        bin.mps ^= 1;
    }
    if bin.index >= 48 {
        return Err(format_error(
            "WinZip JPEG probability adaptation is out of range",
        ));
    }
    decoder.lrm = decoder
        .lr
        .checked_add(dlrm)
        .ok_or_else(|| format_error("WinZip JPEG adapted model range overflows"))?;
    Ok(())
}

fn log_x(value: u32) -> Result<i32> {
    let high = value >> 12;
    if high == 0 {
        return Ok(0x2000);
    }
    let whole = if high < 512 {
        let floor_log = 31_u32
            .checked_sub(high.leading_zeros())
            .ok_or_else(|| format_error("WinZip JPEG logarithm underflows"))?;
        8_i32
            .checked_sub(
                i32::try_from(floor_log)
                    .map_err(|_| format_error("WinZip JPEG logarithm is not representable"))?,
            )
            .ok_or_else(|| format_error("WinZip JPEG logarithm underflows"))?
    } else {
        0
    };
    let shift = 8_i32
        .checked_sub(whole)
        .ok_or_else(|| format_error("WinZip JPEG logarithm shift underflows"))?;
    let shifted = if shift >= 0 {
        value
            >> u32::try_from(shift)
                .map_err(|_| format_error("WinZip JPEG logarithm shift is invalid"))?
    } else {
        value.wrapping_shl(shift.unsigned_abs())
    };
    let index = usize::try_from(shifted & 0xfff)
        .map_err(|_| format_error("WinZip JPEG logarithm index is not representable"))?;
    let fraction = i32::from(
        *LOG_TABLE
            .get(index)
            .ok_or_else(|| format_error("WinZip JPEG logarithm index is out of range"))?,
    );
    whole
        .checked_shl(10)
        .and_then(|item| item.checked_sub(fraction))
        .ok_or_else(|| format_error("WinZip JPEG logarithm overflows"))
}

fn antilog_x(lr: i32) -> Result<u32> {
    let whole = lr >> 10;
    let fraction = usize::try_from(lr & 0x3ff)
        .map_err(|_| format_error("WinZip JPEG antilogarithm index is invalid"))?;
    let value = u32::from(
        *ANTILOG_TABLE
            .get(fraction)
            .ok_or_else(|| format_error("WinZip JPEG antilogarithm index is out of range"))?,
    );
    let shift = 7_i32
        .checked_sub(whole)
        .ok_or_else(|| format_error("WinZip JPEG antilogarithm shift underflows"))?;
    if shift >= 0 {
        value
            .checked_shl(shift.unsigned_abs())
            .ok_or_else(|| format_error("WinZip JPEG antilogarithm overflows"))
    } else {
        Ok(value >> shift.unsigned_abs())
    }
}

#[derive(Clone, Copy, Default)]
struct HuffCode {
    code: u16,
    length: u8,
}

#[derive(Clone, Copy, Default)]
struct Component {
    identifier: u8,
    horizontal_factor: usize,
    vertical_factor: usize,
    quant_index: usize,
}

#[derive(Clone, Copy, Default)]
struct ScanComponent {
    component_index: usize,
    dc_table: usize,
    ac_table: usize,
}

struct Metadata {
    quant_tables: [[u16; 64]; 4],
    quant_present: [bool; 4],
    huff_codes: [[[HuffCode; 256]; 4]; 2],
    huff_present: [[bool; 4]; 2],
    bits: u8,
    height: usize,
    width: usize,
    num_components: usize,
    components: [Component; 4],
    horizontal_mcus: usize,
    vertical_mcus: usize,
    num_scan_components: usize,
    scan_components: [ScanComponent; 4],
    restart_interval: usize,
    frame_seen: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            quant_tables: [[0; 64]; 4],
            quant_present: [false; 4],
            huff_codes: [[[HuffCode::default(); 256]; 4]; 2],
            huff_present: [[false; 4]; 2],
            bits: 0,
            height: 0,
            width: 0,
            num_components: 0,
            components: [Component::default(); 4],
            horizontal_mcus: 0,
            vertical_mcus: 0,
            num_scan_components: 0,
            scan_components: [ScanComponent::default(); 4],
            restart_interval: 0,
            frame_seen: false,
        }
    }
}

enum MetadataResult {
    Scan,
    End,
}

fn parse_u16_be(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG metadata offset overflows"))?;
    let pair = <[u8; 2]>::try_from(
        bytes
            .get(offset..end)
            .ok_or_else(|| format_error("truncated WinZip JPEG metadata"))?,
    )
    .map_err(|_| format_error("truncated WinZip JPEG metadata"))?;
    Ok(u16::from_be_bytes(pair))
}

fn segment_end(bytes: &[u8], offset: usize) -> Result<usize> {
    let size = usize::from(parse_u16_be(bytes, offset)?);
    if size < 2 {
        return Err(format_error("WinZip JPEG marker segment is too short"));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format_error("WinZip JPEG marker segment overflows"))?;
    if end > bytes.len() {
        return Err(format_error("truncated WinZip JPEG marker segment"));
    }
    Ok(end)
}

fn next_marker(bytes: &[u8], mut offset: usize) -> Result<(u8, usize)> {
    if bytes.get(offset).copied() != Some(0xff) {
        return Err(format_error(
            "WinZip JPEG metadata marker prefix is missing",
        ));
    }
    while bytes.get(offset).copied() == Some(0xff) {
        offset = offset
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG metadata offset overflows"))?;
    }
    let marker = *bytes
        .get(offset)
        .ok_or_else(|| format_error("truncated WinZip JPEG metadata marker"))?;
    if marker == 0x00 || marker == 0xff {
        return Err(format_error("invalid WinZip JPEG metadata marker"));
    }
    Ok((
        marker,
        offset
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG metadata offset overflows"))?,
    ))
}

fn parse_metadata(metadata: &mut Metadata, bytes: &[u8]) -> Result<MetadataResult> {
    let mut offset = 0_usize;
    loop {
        let (marker, data_offset) = next_marker(bytes, offset)?;
        offset = data_offset;
        match marker {
            0xd8 => {}
            0xd9 => {
                if offset != bytes.len() {
                    return Err(format_error("WinZip JPEG EOI bundle has trailing metadata"));
                }
                return Ok(MetadataResult::End);
            }
            0xc4 => offset = parse_dht(metadata, bytes, offset)?,
            0xdb => offset = parse_dqt(metadata, bytes, offset)?,
            0xdd => {
                let end = segment_end(bytes, offset)?;
                if end.checked_sub(offset) != Some(4) {
                    return Err(format_error("WinZip JPEG DRI segment has an invalid size"));
                }
                let value_offset = offset
                    .checked_add(2)
                    .ok_or_else(|| format_error("WinZip JPEG DRI offset overflows"))?;
                metadata.restart_interval = usize::from(parse_u16_be(bytes, value_offset)?);
                offset = end;
            }
            0xc0 | 0xc1 => offset = parse_sof(metadata, bytes, offset, marker)?,
            0xda => {
                let end = parse_sos(metadata, bytes, offset)?;
                if end != bytes.len() {
                    return Err(format_error("WinZip JPEG SOS bundle has trailing metadata"));
                }
                return Ok(MetadataResult::Scan);
            }
            0xc2..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                return Err(Error::UnsupportedFeature {
                    feature: String::from("winzip-jpeg-nonsequential-frame"),
                });
            }
            0x01 | 0xd0..=0xd7 => {
                return Err(format_error(
                    "standalone marker is invalid in WinZip JPEG metadata",
                ));
            }
            _ => offset = segment_end(bytes, offset)?,
        }
    }
}

fn parse_dht(metadata: &mut Metadata, bytes: &[u8], offset: usize) -> Result<usize> {
    let end = segment_end(bytes, offset)?;
    let mut position = offset
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG DHT offset overflows"))?;
    if position == end {
        return Err(format_error("WinZip JPEG DHT segment is empty"));
    }
    while position < end {
        let descriptor = *bytes
            .get(position)
            .ok_or_else(|| format_error("truncated WinZip JPEG DHT descriptor"))?;
        position = position
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG DHT offset overflows"))?;
        let class = usize::from(descriptor >> 4);
        let index = usize::from(descriptor & 0x0f);
        if class > 1 || index >= 4 {
            return Err(format_error(
                "WinZip JPEG Huffman table selector is invalid",
            ));
        }
        let counts_end = position
            .checked_add(16)
            .ok_or_else(|| format_error("WinZip JPEG DHT count range overflows"))?;
        let counts = bytes
            .get(position..counts_end)
            .ok_or_else(|| format_error("truncated WinZip JPEG Huffman counts"))?;
        position = counts_end;
        let total = counts.iter().try_fold(0_usize, |sum, count| {
            sum.checked_add(usize::from(*count))
                .ok_or_else(|| format_error("WinZip JPEG Huffman symbol count overflows"))
        })?;
        if total == 0 || total > 256 {
            return Err(format_error("WinZip JPEG Huffman symbol count is invalid"));
        }
        let symbols_end = position
            .checked_add(total)
            .ok_or_else(|| format_error("WinZip JPEG Huffman symbol range overflows"))?;
        let symbols = bytes
            .get(position..symbols_end)
            .ok_or_else(|| format_error("truncated WinZip JPEG Huffman symbols"))?;
        let table = metadata
            .huff_codes
            .get_mut(class)
            .and_then(|tables| tables.get_mut(index))
            .ok_or_else(|| format_error("WinZip JPEG Huffman table is out of range"))?;
        table.fill(HuffCode::default());
        let mut seen = [false; 256];
        let mut code = 0_u32;
        let mut symbol_position = 0_usize;
        for (length_index, count) in counts.iter().copied().enumerate() {
            let length = length_index
                .checked_add(1)
                .ok_or_else(|| format_error("WinZip JPEG Huffman length overflows"))?;
            let count = usize::from(count);
            let limit =
                1_u32
                    .checked_shl(u32::try_from(length).map_err(|_| {
                        format_error("WinZip JPEG Huffman length is not representable")
                    })?)
                    .ok_or_else(|| format_error("WinZip JPEG Huffman code limit overflows"))?;
            let after = code
                .checked_add(
                    u32::try_from(count).map_err(|_| {
                        format_error("WinZip JPEG Huffman count is not representable")
                    })?,
                )
                .ok_or_else(|| format_error("WinZip JPEG Huffman code overflows"))?;
            if after > limit {
                return Err(format_error("WinZip JPEG Huffman table is oversubscribed"));
            }
            for _ in 0..count {
                let symbol = usize::from(
                    *symbols
                        .get(symbol_position)
                        .ok_or_else(|| format_error("truncated WinZip JPEG Huffman symbols"))?,
                );
                symbol_position = symbol_position
                    .checked_add(1)
                    .ok_or_else(|| format_error("WinZip JPEG symbol offset overflows"))?;
                if *seen
                    .get(symbol)
                    .ok_or_else(|| format_error("WinZip JPEG Huffman symbol is out of range"))?
                {
                    return Err(format_error("WinZip JPEG Huffman table repeats a symbol"));
                }
                *seen
                    .get_mut(symbol)
                    .ok_or_else(|| format_error("WinZip JPEG Huffman symbol is out of range"))? =
                    true;
                *table
                    .get_mut(symbol)
                    .ok_or_else(|| format_error("WinZip JPEG Huffman symbol is out of range"))? =
                    HuffCode {
                        code: u16::try_from(code)
                            .map_err(|_| format_error("WinZip JPEG Huffman code is too wide"))?,
                        length: u8::try_from(length).map_err(|_| {
                            format_error("WinZip JPEG Huffman length is not representable")
                        })?,
                    };
                code = code
                    .checked_add(1)
                    .ok_or_else(|| format_error("WinZip JPEG Huffman code overflows"))?;
            }
            code = code
                .checked_shl(1)
                .ok_or_else(|| format_error("WinZip JPEG Huffman code overflows"))?;
        }
        position = symbols_end;
        *metadata
            .huff_present
            .get_mut(class)
            .and_then(|tables| tables.get_mut(index))
            .ok_or_else(|| format_error("WinZip JPEG Huffman table is out of range"))? = true;
    }
    if position != end {
        return Err(format_error("WinZip JPEG DHT segment has trailing bytes"));
    }
    Ok(end)
}

fn parse_dqt(metadata: &mut Metadata, bytes: &[u8], offset: usize) -> Result<usize> {
    let end = segment_end(bytes, offset)?;
    let mut position = offset
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG DQT offset overflows"))?;
    if position == end {
        return Err(format_error("WinZip JPEG DQT segment is empty"));
    }
    while position < end {
        let descriptor = *bytes
            .get(position)
            .ok_or_else(|| format_error("truncated WinZip JPEG DQT descriptor"))?;
        position = position
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG DQT offset overflows"))?;
        let precision = descriptor >> 4;
        let index = usize::from(descriptor & 0x0f);
        if index >= 4 || precision > 1 {
            return Err(format_error(
                "WinZip JPEG quantization table selector is invalid",
            ));
        }
        let width = if precision == 0 { 1_usize } else { 2_usize };
        let table_bytes = 64_usize
            .checked_mul(width)
            .ok_or_else(|| format_error("WinZip JPEG quantization table size overflows"))?;
        let table_end = position
            .checked_add(table_bytes)
            .ok_or_else(|| format_error("WinZip JPEG quantization table range overflows"))?;
        if table_end > end {
            return Err(format_error("truncated WinZip JPEG quantization table"));
        }
        for coefficient in 0..64_usize {
            let value_offset = coefficient
                .checked_mul(width)
                .and_then(|value| position.checked_add(value))
                .ok_or_else(|| format_error("WinZip JPEG quantization offset overflows"))?;
            let value = if width == 1 {
                u16::from(
                    *bytes
                        .get(value_offset)
                        .ok_or_else(|| format_error("truncated WinZip JPEG quantization table"))?,
                )
            } else {
                parse_u16_be(bytes, value_offset)?
            };
            if value == 0 {
                return Err(format_error(
                    "WinZip JPEG quantization values must be nonzero",
                ));
            }
            *metadata
                .quant_tables
                .get_mut(index)
                .and_then(|table| table.get_mut(coefficient))
                .ok_or_else(|| format_error("WinZip JPEG quantization index is out of range"))? =
                value;
        }
        *metadata
            .quant_present
            .get_mut(index)
            .ok_or_else(|| format_error("WinZip JPEG quantization index is out of range"))? = true;
        position = table_end;
    }
    Ok(end)
}

fn parse_sof(metadata: &mut Metadata, bytes: &[u8], offset: usize, marker: u8) -> Result<usize> {
    let end = segment_end(bytes, offset)?;
    let size = end
        .checked_sub(offset)
        .ok_or_else(|| format_error("WinZip JPEG SOF size underflows"))?;
    if size < 11 {
        return Err(format_error("WinZip JPEG SOF segment is too short"));
    }
    let bits_offset = offset
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG SOF precision offset overflows"))?;
    let bits = *bytes
        .get(bits_offset)
        .ok_or_else(|| format_error("truncated WinZip JPEG SOF precision"))?;
    if (marker == 0xc0 && bits != 8) || (marker == 0xc1 && !matches!(bits, 8 | 12)) {
        return Err(Error::UnsupportedFeature {
            feature: format!("winzip-jpeg-{bits}-bit-sequential"),
        });
    }
    let height_offset = offset
        .checked_add(3)
        .ok_or_else(|| format_error("WinZip JPEG SOF height offset overflows"))?;
    let width_offset = offset
        .checked_add(5)
        .ok_or_else(|| format_error("WinZip JPEG SOF width offset overflows"))?;
    let count_offset = offset
        .checked_add(7)
        .ok_or_else(|| format_error("WinZip JPEG component-count offset overflows"))?;
    let height = usize::from(parse_u16_be(bytes, height_offset)?);
    let width = usize::from(parse_u16_be(bytes, width_offset)?);
    let count = usize::from(
        *bytes
            .get(count_offset)
            .ok_or_else(|| format_error("truncated WinZip JPEG component count"))?,
    );
    if width == 0 || height == 0 || !(1..=4).contains(&count) {
        return Err(format_error("WinZip JPEG frame geometry is invalid"));
    }
    let expected = 8_usize
        .checked_add(
            count
                .checked_mul(3)
                .ok_or_else(|| format_error("WinZip JPEG SOF component size overflows"))?,
        )
        .ok_or_else(|| format_error("WinZip JPEG SOF size overflows"))?;
    if size != expected {
        return Err(format_error("WinZip JPEG SOF segment has an invalid size"));
    }
    let mut max_horizontal = 1_usize;
    let mut max_vertical = 1_usize;
    let mut identifiers = [false; 256];
    for component_index in 0..count {
        let base = component_index
            .checked_mul(3)
            .and_then(|value| value.checked_add(8))
            .and_then(|value| offset.checked_add(value))
            .ok_or_else(|| format_error("WinZip JPEG component offset overflows"))?;
        let identifier = *bytes
            .get(base)
            .ok_or_else(|| format_error("truncated WinZip JPEG component"))?;
        let identifier_state = identifiers
            .get_mut(usize::from(identifier))
            .ok_or_else(|| format_error("WinZip JPEG component identifier is out of range"))?;
        if *identifier_state {
            return Err(format_error(
                "WinZip JPEG frame repeats a component identifier",
            ));
        }
        *identifier_state = true;
        let factors_offset = base
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG sampling-factor offset overflows"))?;
        let factors = *bytes
            .get(factors_offset)
            .ok_or_else(|| format_error("truncated WinZip JPEG sampling factors"))?;
        let horizontal_factor = usize::from(factors >> 4);
        let vertical_factor = usize::from(factors & 0x0f);
        let quant_offset = base
            .checked_add(2)
            .ok_or_else(|| format_error("WinZip JPEG quantization-selector offset overflows"))?;
        let quant_index = usize::from(
            *bytes
                .get(quant_offset)
                .ok_or_else(|| format_error("truncated WinZip JPEG quantization selector"))?,
        );
        if !(1..=4).contains(&horizontal_factor)
            || !(1..=4).contains(&vertical_factor)
            || quant_index >= 4
        {
            return Err(format_error("WinZip JPEG component parameters are invalid"));
        }
        *metadata
            .components
            .get_mut(component_index)
            .ok_or_else(|| format_error("WinZip JPEG component index is out of range"))? =
            Component {
                identifier,
                horizontal_factor,
                vertical_factor,
                quant_index,
            };
        max_horizontal = max_horizontal.max(horizontal_factor);
        max_vertical = max_vertical.max(vertical_factor);
    }
    if count == 1 {
        metadata.components[0].horizontal_factor = 1;
        metadata.components[0].vertical_factor = 1;
        max_horizontal = 1;
        max_vertical = 1;
    }
    let mcu_width = max_horizontal
        .checked_mul(8)
        .ok_or_else(|| format_error("WinZip JPEG MCU width overflows"))?;
    let mcu_height = max_vertical
        .checked_mul(8)
        .ok_or_else(|| format_error("WinZip JPEG MCU height overflows"))?;
    let horizontal_rounding = mcu_width
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG MCU width underflows"))?;
    let vertical_rounding = mcu_height
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG MCU height underflows"))?;
    metadata.horizontal_mcus = width
        .checked_add(horizontal_rounding)
        .ok_or_else(|| format_error("WinZip JPEG horizontal MCU count overflows"))?
        / mcu_width;
    metadata.vertical_mcus = height
        .checked_add(vertical_rounding)
        .ok_or_else(|| format_error("WinZip JPEG vertical MCU count overflows"))?
        / mcu_height;
    metadata.bits = bits;
    metadata.height = height;
    metadata.width = width;
    metadata.num_components = count;
    metadata.frame_seen = true;
    Ok(end)
}

fn parse_sos(metadata: &mut Metadata, bytes: &[u8], offset: usize) -> Result<usize> {
    if !metadata.frame_seen {
        return Err(format_error("WinZip JPEG scan precedes its frame header"));
    }
    let end = segment_end(bytes, offset)?;
    let size = end
        .checked_sub(offset)
        .ok_or_else(|| format_error("WinZip JPEG SOS size underflows"))?;
    let count_offset = offset
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG scan-count offset overflows"))?;
    let count = usize::from(
        *bytes
            .get(count_offset)
            .ok_or_else(|| format_error("truncated WinZip JPEG scan component count"))?,
    );
    if !(1..=metadata.num_components).contains(&count) {
        return Err(format_error("WinZip JPEG scan component count is invalid"));
    }
    let expected = 6_usize
        .checked_add(
            count
                .checked_mul(2)
                .ok_or_else(|| format_error("WinZip JPEG SOS component size overflows"))?,
        )
        .ok_or_else(|| format_error("WinZip JPEG SOS size overflows"))?;
    if size != expected {
        return Err(format_error("WinZip JPEG SOS segment has an invalid size"));
    }
    let mut selected = [false; 4];
    for scan_index in 0..count {
        let base = scan_index
            .checked_mul(2)
            .and_then(|value| value.checked_add(3))
            .and_then(|value| offset.checked_add(value))
            .ok_or_else(|| format_error("WinZip JPEG scan-component offset overflows"))?;
        let identifier = *bytes
            .get(base)
            .ok_or_else(|| format_error("truncated WinZip JPEG scan component"))?;
        let frame_components = metadata
            .components
            .get(..metadata.num_components)
            .ok_or_else(|| format_error("WinZip JPEG component range is out of bounds"))?;
        let component_index = frame_components
            .iter()
            .position(|component| component.identifier == identifier)
            .ok_or_else(|| format_error("WinZip JPEG scan references an unknown component"))?;
        let selection = selected
            .get_mut(component_index)
            .ok_or_else(|| format_error("WinZip JPEG component index is out of range"))?;
        if *selection {
            return Err(format_error("WinZip JPEG scan repeats a component"));
        }
        *selection = true;
        let selectors_offset = base
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG Huffman-selector offset overflows"))?;
        let selectors = *bytes
            .get(selectors_offset)
            .ok_or_else(|| format_error("truncated WinZip JPEG Huffman selectors"))?;
        let dc_table = usize::from(selectors >> 4);
        let ac_table = usize::from(selectors & 0x0f);
        let component = *metadata
            .components
            .get(component_index)
            .ok_or_else(|| format_error("WinZip JPEG component index is out of range"))?;
        let dc_present = metadata
            .huff_present
            .first()
            .and_then(|tables| tables.get(dc_table))
            .copied()
            == Some(true);
        let ac_present = metadata
            .huff_present
            .get(1)
            .and_then(|tables| tables.get(ac_table))
            .copied()
            == Some(true);
        let quant_present =
            metadata.quant_present.get(component.quant_index).copied() == Some(true);
        if dc_table >= 4 || ac_table >= 4 || !dc_present || !ac_present || !quant_present {
            return Err(format_error("WinZip JPEG scan references a missing table"));
        }
        *metadata
            .scan_components
            .get_mut(scan_index)
            .ok_or_else(|| format_error("WinZip JPEG scan index is out of range"))? =
            ScanComponent {
                component_index,
                dc_table,
                ac_table,
            };
    }
    let spectral = offset
        .checked_add(3)
        .and_then(|value| value.checked_add(count.checked_mul(2)?))
        .ok_or_else(|| format_error("WinZip JPEG spectral selector offset overflows"))?;
    let spectral_end = spectral
        .checked_add(3)
        .ok_or_else(|| format_error("WinZip JPEG spectral selector range overflows"))?;
    if bytes.get(spectral..spectral_end) != Some(&[0, 63, 0]) {
        return Err(Error::UnsupportedFeature {
            feature: String::from("winzip-jpeg-nonsequential-scan"),
        });
    }
    metadata.num_scan_components = count;
    Ok(end)
}

const EOB_OFFSET: usize = 0;
const ZERO_OFFSET: usize = EOB_OFFSET + 4 * 13 * 63;
const PIVOT_OFFSET: usize = ZERO_OFFSET + 4 * 62 * 3 * 6;
const AC_MAGNITUDE_OFFSET: usize = PIVOT_OFFSET + 4 * 63 * 5 * 7;
const AC_REMAINDER_OFFSET: usize = AC_MAGNITUDE_OFFSET + 4 * 3 * 9 * 9 * 9;
const AC_SIGN_OFFSET: usize = AC_REMAINDER_OFFSET + 4 * 3 * 7 * 13;
const DC_MAGNITUDE_OFFSET: usize = AC_SIGN_OFFSET + 4 * 27 * 3 * 2;
const DC_REMAINDER_OFFSET: usize = DC_MAGNITUDE_OFFSET + 4 * 13 * 10;
const DC_SIGN_OFFSET: usize = DC_REMAINDER_OFFSET + 4 * 13 * 14;

struct Models {
    bins: Vec<Bin>,
}

impl Models {
    fn required_bytes() -> Result<u64> {
        let bytes = MODEL_COUNT
            .checked_mul(size_of::<Bin>())
            .ok_or_else(|| format_error("WinZip JPEG model size overflows"))?;
        usize_to_u64(bytes, "WinZip JPEG model size is not representable as u64")
    }

    fn new(limits: Limits) -> Result<Self> {
        let bytes = Self::required_bytes()?;
        check_limit(
            bytes,
            limits.max_dictionary_bytes(),
            LimitKind::DictionaryBytes,
        )?;
        let mut bins = Vec::new();
        try_reserve(&mut bins, MODEL_COUNT)?;
        bins.resize(MODEL_COUNT, Bin::adaptive());
        Ok(Self { bins })
    }

    fn reset(&mut self) {
        self.bins.fill(Bin::adaptive());
    }

    fn decode(
        &mut self,
        index: usize,
        decoder: &mut ArithmeticDecoder<'_, '_>,
        control: &mut ParseControl<'_>,
    ) -> Result<u8> {
        let bin = self
            .bins
            .get_mut(index)
            .ok_or_else(|| format_error("WinZip JPEG probability model index is out of range"))?;
        decoder.decode_bit(bin, control)
    }
}

#[inline(always)]
fn model_index(offset: usize, coordinates: &[usize], dimensions: &[usize]) -> Result<usize> {
    if coordinates.len() != dimensions.len() {
        return Err(format_error(
            "WinZip JPEG probability model rank is invalid",
        ));
    }
    let mut index = 0_usize;
    for (coordinate, dimension) in coordinates.iter().zip(dimensions) {
        if coordinate >= dimension {
            return Err(format_error(
                "WinZip JPEG probability context is out of range",
            ));
        }
        index = index
            .checked_mul(*dimension)
            .and_then(|value| value.checked_add(*coordinate))
            .ok_or_else(|| format_error("WinZip JPEG probability model index overflows"))?;
    }
    offset
        .checked_add(index)
        .filter(|value| *value < MODEL_COUNT)
        .ok_or_else(|| format_error("WinZip JPEG probability model index is out of range"))
}

fn eob_index(component: usize, context: usize, node: usize) -> Result<usize> {
    model_index(EOB_OFFSET, &[component, context, node], &[4, 13, 63])
}

fn zero_index(component: usize, coefficient: usize, first: usize, second: usize) -> Result<usize> {
    model_index(
        ZERO_OFFSET,
        &[component, coefficient, first, second],
        &[4, 62, 3, 6],
    )
}

fn pivot_index(component: usize, coefficient: usize, first: usize, second: usize) -> Result<usize> {
    model_index(
        PIVOT_OFFSET,
        &[component, coefficient, first, second],
        &[4, 63, 5, 7],
    )
}

fn ac_magnitude_index(
    component: usize,
    kind: usize,
    first: usize,
    second: usize,
    context: usize,
) -> Result<usize> {
    model_index(
        AC_MAGNITUDE_OFFSET,
        &[component, kind, first, second, context],
        &[4, 3, 9, 9, 9],
    )
}

fn ac_remainder_index(component: usize, kind: usize, position: usize, bit: usize) -> Result<usize> {
    model_index(
        AC_REMAINDER_OFFSET,
        &[component, kind, position, bit],
        &[4, 3, 7, 13],
    )
}

fn ac_sign_index(component: usize, context: usize, magnitude: usize, sign: usize) -> Result<usize> {
    model_index(
        AC_SIGN_OFFSET,
        &[component, context, magnitude, sign],
        &[4, 27, 3, 2],
    )
}

fn dc_magnitude_index(component: usize, value_context: usize, context: usize) -> Result<usize> {
    model_index(
        DC_MAGNITUDE_OFFSET,
        &[component, value_context, context],
        &[4, 13, 10],
    )
}

fn dc_remainder_index(component: usize, value_context: usize, bit: usize) -> Result<usize> {
    model_index(
        DC_REMAINDER_OFFSET,
        &[component, value_context, bit],
        &[4, 13, 14],
    )
}

fn dc_sign_index(component: usize, north: usize, west: usize, predicted: usize) -> Result<usize> {
    model_index(
        DC_SIGN_OFFSET,
        &[component, north, west, predicted],
        &[4, 2, 2, 2],
    )
}

#[derive(Clone, Copy)]
struct Block {
    coefficients: [i16; 64],
    eob: u8,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            coefficients: [0; 64],
            eob: 0,
        }
    }
}

fn row_of(coefficient: usize) -> Result<usize> {
    ROW.get(coefficient)
        .copied()
        .ok_or_else(|| format_error("WinZip JPEG coefficient index is out of range"))
}

fn column_of(coefficient: usize) -> Result<usize> {
    COLUMN
        .get(coefficient)
        .copied()
        .ok_or_else(|| format_error("WinZip JPEG coefficient index is out of range"))
}

fn zigzag_at(row: usize, column: usize) -> Result<usize> {
    ZIGZAG
        .get(row)
        .and_then(|values| values.get(column))
        .copied()
        .ok_or_else(|| format_error("WinZip JPEG zigzag coordinate is out of range"))
}

fn left_of(coefficient: usize) -> Result<usize> {
    let column = column_of(coefficient)?;
    zigzag_at(
        row_of(coefficient)?,
        column
            .checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG left coefficient underflows"))?,
    )
}

fn up_of(coefficient: usize) -> Result<usize> {
    let row = row_of(coefficient)?;
    zigzag_at(
        row.checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG upper coefficient underflows"))?,
        column_of(coefficient)?,
    )
}

fn up_left_of(coefficient: usize) -> Result<usize> {
    let row = row_of(coefficient)?;
    let column = column_of(coefficient)?;
    zigzag_at(
        row.checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG upper-left row underflows"))?,
        column
            .checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG upper-left column underflows"))?,
    )
}

fn right_of(coefficient: usize) -> Result<usize> {
    zigzag_at(
        row_of(coefficient)?,
        column_of(coefficient)?
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG right coefficient overflows"))?,
    )
}

fn down_of(coefficient: usize) -> Result<usize> {
    zigzag_at(
        row_of(coefficient)?
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG lower coefficient overflows"))?,
        column_of(coefficient)?,
    )
}

fn coefficient(block: &Block, index: usize) -> Result<i64> {
    block
        .coefficients
        .get(index)
        .copied()
        .map(i64::from)
        .ok_or_else(|| format_error("WinZip JPEG coefficient index is out of range"))
}

fn absolute_coefficient(block: &Block, index: usize) -> Result<i64> {
    coefficient(block, index)?
        .checked_abs()
        .ok_or_else(|| format_error("WinZip JPEG coefficient magnitude overflows"))
}

fn coefficient_sum(coefficient_index: usize, block: &Block) -> Result<i64> {
    let row = row_of(coefficient_index)?;
    let column = column_of(coefficient_index)?;
    let mut sum = 0_i64;
    for index in 0..64_usize {
        if index != coefficient_index && row_of(index)? >= row && column_of(index)? >= column {
            sum = sum
                .checked_add(absolute_coefficient(block, index)?)
                .ok_or_else(|| format_error("WinZip JPEG coefficient sum overflows"))?;
        }
    }
    Ok(sum)
}

fn quant_value(quant: &[u16; 64], index: usize) -> Result<i64> {
    let value = i64::from(
        *quant
            .get(index)
            .ok_or_else(|| format_error("WinZip JPEG quantization index is out of range"))?,
    );
    if value == 0 {
        return Err(format_error(
            "WinZip JPEG quantization values must be nonzero",
        ));
    }
    Ok(value)
}

fn scale_neighbours(
    north: &Block,
    west: &Block,
    index: usize,
    target: usize,
    quant: &[u16; 64],
) -> Result<i64> {
    let magnitude = absolute_coefficient(north, index)?
        .checked_add(absolute_coefficient(west, index)?)
        .ok_or_else(|| format_error("WinZip JPEG neighbour scaling overflows"))?;
    let numerator = magnitude
        .checked_mul(quant_value(quant, index)?)
        .ok_or_else(|| format_error("WinZip JPEG neighbour scaling overflows"))?;
    Ok(numerator / quant_value(quant, target)?)
}

fn average(
    coefficient_index: usize,
    north: &Block,
    west: &Block,
    quant: &[u16; 64],
) -> Result<i64> {
    let direct = absolute_coefficient(north, coefficient_index)?
        .checked_add(absolute_coefficient(west, coefficient_index)?)
        .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
    if coefficient_index <= 2 {
        return direct
            .checked_add(1)
            .map(|value| value / 2)
            .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"));
    }
    let mut total = direct;
    let divisor = if row_of(coefficient_index)? == 0 {
        total = total
            .checked_add(scale_neighbours(
                north,
                west,
                left_of(coefficient_index)?,
                coefficient_index,
                quant,
            )?)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
        4
    } else if column_of(coefficient_index)? == 0 {
        total = total
            .checked_add(scale_neighbours(
                north,
                west,
                up_of(coefficient_index)?,
                coefficient_index,
                quant,
            )?)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
        4
    } else if coefficient_index == 4 {
        let upper = scale_neighbours(
            north,
            west,
            up_of(coefficient_index)?,
            coefficient_index,
            quant,
        )?;
        let left = scale_neighbours(
            north,
            west,
            left_of(coefficient_index)?,
            coefficient_index,
            quant,
        )?;
        total = total
            .checked_add(upper)
            .and_then(|value| value.checked_add(left))
            .and_then(|value| value.checked_add(3))
            .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
        6
    } else {
        for neighbour in [
            up_of(coefficient_index)?,
            left_of(coefficient_index)?,
            up_left_of(coefficient_index)?,
        ] {
            total = total
                .checked_add(scale_neighbours(
                    north,
                    west,
                    neighbour,
                    coefficient_index,
                    quant,
                )?)
                .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
        }
        total = total
            .checked_add(4)
            .ok_or_else(|| format_error("WinZip JPEG coefficient average overflows"))?;
        8
    };
    Ok(total / divisor)
}

fn boundary_difference(
    coefficient_index: usize,
    current: &Block,
    north: &Block,
    west: &Block,
    quant: &[u16; 64],
) -> Result<i64> {
    if row_of(coefficient_index)? == 0 {
        let down = down_of(coefficient_index)?;
        let neighbour_sum = coefficient(north, down)?
            .checked_add(coefficient(current, down)?)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))?;
        let adjustment = neighbour_sum
            .checked_mul(quant_value(quant, down)?)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))?
            / quant_value(quant, coefficient_index)?;
        coefficient(north, coefficient_index)?
            .checked_sub(adjustment)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))
    } else if column_of(coefficient_index)? == 0 {
        let right = right_of(coefficient_index)?;
        let neighbour_sum = coefficient(west, right)?
            .checked_add(coefficient(current, right)?)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))?;
        let adjustment = neighbour_sum
            .checked_mul(quant_value(quant, right)?)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))?
            / quant_value(quant, coefficient_index)?;
        coefficient(west, coefficient_index)?
            .checked_sub(adjustment)
            .ok_or_else(|| format_error("WinZip JPEG boundary prediction overflows"))
    } else {
        Ok(0)
    }
}

fn category(value: u64) -> Result<usize> {
    if value == 0 {
        Ok(0)
    } else {
        usize::try_from(u64::BITS - value.leading_zeros())
            .map_err(|_| format_error("WinZip JPEG category is not representable"))
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_ac_binarization(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    component: usize,
    kind: usize,
    first: usize,
    second: usize,
    position: usize,
    control: &mut ParseControl<'_>,
) -> Result<i32> {
    let mut ones = 0_usize;
    while ones < 14 {
        let context = ones.min(8);
        let bit = models.decode(
            ac_magnitude_index(component, kind, first, second, context)?,
            decoder,
            control,
        )?;
        if bit == 0 {
            break;
        }
        ones = ones
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG AC magnitude width overflows"))?;
    }
    decode_remainder(ones, 13, |bit| {
        models.decode(
            ac_remainder_index(component, kind, position, bit)?,
            decoder,
            control,
        )
    })
}

fn decode_dc_binarization(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    component: usize,
    value_context: usize,
    control: &mut ParseControl<'_>,
) -> Result<i32> {
    let mut ones = 0_usize;
    while ones < 15 {
        let context = ones.min(9);
        let bit = models.decode(
            dc_magnitude_index(component, value_context, context)?,
            decoder,
            control,
        )?;
        if bit == 0 {
            break;
        }
        ones = ones
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG DC magnitude width overflows"))?;
    }
    decode_remainder(ones, 14, |bit| {
        models.decode(
            dc_remainder_index(component, value_context, bit)?,
            decoder,
            control,
        )
    })
}

fn decode_remainder<F>(ones: usize, maximum_bit: usize, mut decode: F) -> Result<i32>
where
    F: FnMut(usize) -> Result<u8>,
{
    if ones == 0 {
        return Ok(0);
    }
    if ones == 1 {
        return Ok(1);
    }
    let bits = ones
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG binarization width underflows"))?;
    if bits > maximum_bit {
        return Err(format_error("WinZip JPEG binarization is too wide"));
    }
    let mut value = 1_u32
        .checked_shl(
            u32::try_from(bits)
                .map_err(|_| format_error("WinZip JPEG binarization width is not representable"))?,
        )
        .ok_or_else(|| format_error("WinZip JPEG binarization overflows"))?;
    for bit_index in (0..bits).rev() {
        let bit = u32::from(decode(bit_index)?);
        value |=
            bit.checked_shl(u32::try_from(bit_index).map_err(|_| {
                format_error("WinZip JPEG remainder position is not representable")
            })?)
            .ok_or_else(|| format_error("WinZip JPEG remainder overflows"))?;
    }
    i32::try_from(value).map_err(|_| format_error("WinZip JPEG magnitude is not representable"))
}

fn decode_fixed(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    fixed: &mut Bin,
    control: &mut ParseControl<'_>,
) -> Result<u8> {
    decoder.decode_bit(fixed, control)
}

#[allow(clippy::too_many_arguments)]
fn decode_ac_sign(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    fixed: &mut Bin,
    sign_contexts: &[usize; 64],
    component: usize,
    coefficient_index: usize,
    absolute_value: i32,
    current: &Block,
    north: &Block,
    west: &Block,
    quant: &[u16; 64],
    control: &mut ParseControl<'_>,
) -> Result<u8> {
    let predicted_sign = if row_of(coefficient_index)? == 0 || column_of(coefficient_index)? == 0 {
        let difference = boundary_difference(coefficient_index, current, north, west, quant)?;
        if difference == 0 {
            return decode_fixed(decoder, fixed, control);
        }
        usize::from(difference < 0)
    } else if coefficient_index == 4 {
        let sum = coefficient(north, coefficient_index)?
            .signum()
            .checked_add(coefficient(west, coefficient_index)?.signum())
            .ok_or_else(|| format_error("WinZip JPEG sign prediction overflows"))?;
        if sum == 0 {
            return decode_fixed(decoder, fixed, control);
        }
        usize::from(sum < 0)
    } else if row_of(coefficient_index)? == 1 {
        let value = coefficient(north, coefficient_index)?;
        if value == 0 {
            return decode_fixed(decoder, fixed, control);
        }
        usize::from(value < 0)
    } else if column_of(coefficient_index)? == 1 {
        let value = coefficient(west, coefficient_index)?;
        if value == 0 {
            return decode_fixed(decoder, fixed, control);
        }
        usize::from(value < 0)
    } else {
        return decode_fixed(decoder, fixed, control);
    };
    let context = *sign_contexts
        .get(coefficient_index)
        .ok_or_else(|| format_error("WinZip JPEG sign context is out of range"))?;
    let magnitude = category(
        u64::try_from(absolute_value)
            .map_err(|_| format_error("WinZip JPEG AC magnitude is negative"))?,
    )? / 2;
    let magnitude = magnitude.min(2);
    models.decode(
        ac_sign_index(component, context, magnitude, predicted_sign)?,
        decoder,
        control,
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_ac_component(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    fixed: &mut Bin,
    sign_contexts: &[usize; 64],
    component: usize,
    coefficient_index: usize,
    can_be_zero: bool,
    current: &Block,
    north: Option<&Block>,
    west: Option<&Block>,
    quant: &[u16; 64],
    control: &mut ParseControl<'_>,
) -> Result<i16> {
    let zero = Block::default();
    let north = match north {
        Some(value) => value,
        None => &zero,
    };
    let west = match west {
        Some(value) => value,
        None => &zero,
    };
    let row = row_of(coefficient_index)?;
    let column = column_of(coefficient_index)?;
    let coefficient_context = coefficient_index
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG AC coefficient context underflows"))?;
    let first_value = if row == 0 || column == 0 {
        boundary_difference(coefficient_index, current, north, west, quant)?
            .checked_abs()
            .ok_or_else(|| format_error("WinZip JPEG AC prediction magnitude overflows"))?
    } else {
        average(coefficient_index, north, west, quant)?
    };
    let second_value = coefficient_sum(coefficient_index, current)?;
    if can_be_zero {
        let first_context = category(
            u64::try_from(first_value)
                .map_err(|_| format_error("WinZip JPEG AC zero context is negative"))?,
        )?
        .min(2);
        let second_context = category(
            u64::try_from(second_value)
                .map_err(|_| format_error("WinZip JPEG AC zero context is negative"))?,
        )?
        .min(5);
        let nonzero = models.decode(
            zero_index(
                component,
                coefficient_context,
                first_context,
                second_context,
            )?,
            decoder,
            control,
        )?;
        if nonzero == 0 {
            return Ok(0);
        }
    }

    let first_context = category(
        u64::try_from(first_value)
            .map_err(|_| format_error("WinZip JPEG AC pivot context is negative"))?,
    )?
    .min(4);
    let second_context = category(
        u64::try_from(second_value)
            .map_err(|_| format_error("WinZip JPEG AC pivot context is negative"))?,
    )?
    .min(6);
    let pivot = models.decode(
        pivot_index(
            component,
            coefficient_context,
            first_context,
            second_context,
        )?,
        decoder,
        control,
    )?;
    let absolute_value = if pivot == 0 {
        1
    } else {
        let (kind, position) = if row == 0 {
            (
                0,
                column
                    .checked_sub(1)
                    .ok_or_else(|| format_error("WinZip JPEG AC column context underflows"))?,
            )
        } else if column == 0 {
            (
                1,
                row.checked_sub(1)
                    .ok_or_else(|| format_error("WinZip JPEG AC row context underflows"))?,
            )
        } else {
            let adjusted = coefficient_index
                .checked_sub(4)
                .ok_or_else(|| format_error("WinZip JPEG AC magnitude context underflows"))?;
            (
                2,
                category(
                    u64::try_from(adjusted)
                        .map_err(|_| format_error("WinZip JPEG AC context is not representable"))?,
                )?,
            )
        };
        let magnitude_first = category(
            u64::try_from(first_value)
                .map_err(|_| format_error("WinZip JPEG AC magnitude context is negative"))?,
        )?
        .min(8);
        let magnitude_second = category(
            u64::try_from(second_value)
                .map_err(|_| format_error("WinZip JPEG AC magnitude context is negative"))?,
        )?
        .min(8);
        decode_ac_binarization(
            decoder,
            models,
            component,
            kind,
            magnitude_first,
            magnitude_second,
            position,
            control,
        )?
        .checked_add(2)
        .ok_or_else(|| format_error("WinZip JPEG AC magnitude overflows"))?
    };
    let sign = decode_ac_sign(
        decoder,
        models,
        fixed,
        sign_contexts,
        component,
        coefficient_index,
        absolute_value,
        current,
        north,
        west,
        quant,
        control,
    )?;
    let value = if sign == 0 {
        absolute_value
    } else {
        absolute_value
            .checked_neg()
            .ok_or_else(|| format_error("WinZip JPEG AC coefficient overflows"))?
    };
    i16::try_from(value).map_err(|_| format_error("WinZip JPEG AC coefficient is out of range"))
}

fn rounded_prediction(value: i64) -> Result<i64> {
    let adjusted = if value < 0 {
        value.checked_sub(5000)
    } else {
        value.checked_add(5000)
    }
    .ok_or_else(|| format_error("WinZip JPEG DC rounding overflows"))?;
    Ok(adjusted / 10_000)
}

fn directional_prediction(
    neighbour: &Block,
    current: &Block,
    neighbour_coefficient: usize,
    quant: &[u16; 64],
) -> Result<i64> {
    let base = coefficient(neighbour, 0)?
        .checked_mul(10_000)
        .ok_or_else(|| format_error("WinZip JPEG DC prediction overflows"))?;
    let neighbour_sum = coefficient(neighbour, neighbour_coefficient)?
        .checked_add(coefficient(current, neighbour_coefficient)?)
        .ok_or_else(|| format_error("WinZip JPEG DC prediction overflows"))?;
    let adjustment = 11_038_i64
        .checked_mul(quant_value(quant, neighbour_coefficient)?)
        .and_then(|value| value.checked_mul(neighbour_sum))
        .ok_or_else(|| format_error("WinZip JPEG DC prediction overflows"))?
        / quant_value(quant, 0)?;
    rounded_prediction(
        base.checked_sub(adjustment)
            .ok_or_else(|| format_error("WinZip JPEG DC prediction overflows"))?,
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_dc_component(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    component: usize,
    current: &Block,
    north: Option<&Block>,
    west: Option<&Block>,
    quant: &[u16; 64],
    control: &mut ParseControl<'_>,
) -> Result<i16> {
    let predicted = match (north, west) {
        (None, None) => 0_i64,
        (None, Some(west)) => directional_prediction(west, current, 1, quant)?,
        (Some(north), None) => directional_prediction(north, current, 2, quant)?,
        (Some(north), Some(west)) => {
            let north_prediction = directional_prediction(north, current, 2, quant)?;
            let west_prediction = directional_prediction(west, current, 1, quant)?;
            let mut north_difference = 0_i64;
            let mut west_difference = 0_i64;
            for coordinate in 1..8_usize {
                let vertical = zigzag_at(coordinate, 0)?;
                let horizontal = zigzag_at(0, coordinate)?;
                north_difference = north_difference
                    .checked_add(
                        coefficient(north, vertical)?
                            .checked_sub(coefficient(current, vertical)?)
                            .and_then(i64::checked_abs)
                            .ok_or_else(|| format_error("WinZip JPEG DC refinement overflows"))?,
                    )
                    .ok_or_else(|| format_error("WinZip JPEG DC refinement overflows"))?;
                west_difference = west_difference
                    .checked_add(
                        coefficient(west, horizontal)?
                            .checked_sub(coefficient(current, horizontal)?)
                            .and_then(i64::checked_abs)
                            .ok_or_else(|| format_error("WinZip JPEG DC refinement overflows"))?,
                    )
                    .ok_or_else(|| format_error("WinZip JPEG DC refinement overflows"))?;
            }
            let (weighted, other, difference) = if north_difference > west_difference {
                let difference = north_difference
                    .checked_sub(west_difference)
                    .ok_or_else(|| format_error("WinZip JPEG DC refinement underflows"))?;
                (west_prediction, north_prediction, difference)
            } else {
                let difference = west_difference
                    .checked_sub(north_difference)
                    .ok_or_else(|| format_error("WinZip JPEG DC refinement underflows"))?;
                (north_prediction, west_prediction, difference)
            };
            let shift = u32::try_from(difference.min(31))
                .map_err(|_| format_error("WinZip JPEG DC weight is not representable"))?;
            let weight = 1_i64
                .checked_shl(shift)
                .ok_or_else(|| format_error("WinZip JPEG DC weight overflows"))?;
            let denominator = weight
                .checked_add(1)
                .ok_or_else(|| format_error("WinZip JPEG DC weight overflows"))?;
            weight
                .checked_mul(weighted)
                .and_then(|value| value.checked_add(other))
                .and_then(|value| value.checked_div(denominator))
                .ok_or_else(|| format_error("WinZip JPEG DC refinement overflows"))?
        }
    };
    let sum = coefficient_sum(0, current)?;
    let value_context = category(
        u64::try_from(sum)
            .map_err(|_| format_error("WinZip JPEG DC magnitude context is negative"))?,
    )?
    .min(12);
    let absolute_value = i64::from(decode_dc_binarization(
        decoder,
        models,
        component,
        value_context,
        control,
    )?);
    let value = if absolute_value == 0 {
        predicted
    } else {
        let zero = Block::default();
        let north_value = coefficient(
            match north {
                Some(value) => value,
                None => &zero,
            },
            0,
        )?;
        let west_value = coefficient(
            match west {
                Some(value) => value,
                None => &zero,
            },
            0,
        )?;
        let sign = models.decode(
            dc_sign_index(
                component,
                usize::from(north_value < predicted),
                usize::from(west_value < predicted),
                usize::from(predicted < 0),
            )?,
            decoder,
            control,
        )?;
        if sign == 0 {
            predicted.checked_add(absolute_value)
        } else {
            predicted.checked_sub(absolute_value)
        }
        .ok_or_else(|| format_error("WinZip JPEG DC coefficient overflows"))?
    };
    i16::try_from(value).map_err(|_| format_error("WinZip JPEG DC coefficient is out of range"))
}

#[allow(clippy::too_many_arguments)]
fn decode_block(
    decoder: &mut ArithmeticDecoder<'_, '_>,
    models: &mut Models,
    fixed: &mut Bin,
    sign_contexts: &[usize; 64],
    component: usize,
    north: Option<&Block>,
    west: Option<&Block>,
    quant: &[u16; 64],
    control: &mut ParseControl<'_>,
) -> Result<Block> {
    let average_value = match (north, west) {
        (None, None) => 0_i64,
        (None, Some(west)) => coefficient_sum(0, west)?,
        (Some(north), None) => coefficient_sum(0, north)?,
        (Some(north), Some(west)) => coefficient_sum(0, north)?
            .checked_add(coefficient_sum(0, west)?)
            .and_then(|value| value.checked_add(1))
            .map(|value| value / 2)
            .ok_or_else(|| format_error("WinZip JPEG EOB context overflows"))?,
    };
    let eob_context = category(
        u64::try_from(average_value)
            .map_err(|_| format_error("WinZip JPEG EOB context is negative"))?,
    )?
    .min(12);
    let mut bit_string = 1_usize;
    for _ in 0..6 {
        let node = bit_string
            .checked_sub(1)
            .ok_or_else(|| format_error("WinZip JPEG EOB node underflows"))?;
        let bit = usize::from(models.decode(
            eob_index(component, eob_context, node)?,
            decoder,
            control,
        )?);
        bit_string = bit_string
            .checked_mul(2)
            .and_then(|value| value.checked_add(bit))
            .ok_or_else(|| format_error("WinZip JPEG EOB value overflows"))?;
    }
    let eob = bit_string & 0x3f;
    let mut current = Block {
        coefficients: [0; 64],
        eob: u8::try_from(eob).map_err(|_| format_error("WinZip JPEG EOB is not representable"))?,
    };
    for coefficient_index in (1..=eob).rev() {
        let value = decode_ac_component(
            decoder,
            models,
            fixed,
            sign_contexts,
            component,
            coefficient_index,
            coefficient_index != eob,
            &current,
            north,
            west,
            quant,
            control,
        )?;
        *current
            .coefficients
            .get_mut(coefficient_index)
            .ok_or_else(|| format_error("WinZip JPEG AC coefficient index is out of range"))? =
            value;
    }
    current.coefficients[0] = decode_dc_component(
        decoder, models, component, &current, north, west, quant, control,
    )?;
    Ok(current)
}

struct ScanWriter<'output> {
    output: &'output mut Vec<u8>,
    expected: u64,
    maximum: u64,
    bit_string: u64,
    bit_length: u8,
    predicted: [i16; 4],
    mcu_counter: usize,
    restart_marker_index: u8,
}

impl<'output> ScanWriter<'output> {
    fn new(output: &'output mut Vec<u8>, expected: u64, maximum: u64) -> Self {
        Self {
            output,
            expected,
            maximum,
            bit_string: 0,
            bit_length: 0,
            predicted: [0; 4],
            mcu_counter: 0,
            restart_marker_index: 0,
        }
    }

    fn append_byte(&mut self, value: u8, control: &mut ParseControl<'_>) -> Result<()> {
        let new_size = usize_to_u64(
            self.output
                .len()
                .checked_add(1)
                .ok_or_else(|| format_error("WinZip JPEG output size overflows"))?,
            "WinZip JPEG output size is not representable as u64",
        )?;
        if new_size > self.expected {
            return Err(format_error(
                "WinZip JPEG output exceeds its ZIP declaration",
            ));
        }
        check_limit(new_size, self.maximum, LimitKind::TotalOutputBytes)?;
        control.checkpoint(1)?;
        self.output.push(value);
        Ok(())
    }

    fn emit_scan_byte(&mut self, value: u8, control: &mut ParseControl<'_>) -> Result<()> {
        self.append_byte(value, control)?;
        if value == 0xff {
            self.append_byte(0, control)?;
        }
        Ok(())
    }

    fn push_bits(&mut self, bits: u32, length: u8, control: &mut ParseControl<'_>) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        if length > 32 || self.bit_length > 7 {
            return Err(format_error("WinZip JPEG bit writer state is invalid"));
        }
        let mask = if length == 32 {
            u64::from(u32::MAX)
        } else {
            1_u64
                .checked_shl(u32::from(length))
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| format_error("WinZip JPEG bit mask overflows"))?
        };
        self.bit_string = self
            .bit_string
            .checked_shl(u32::from(length))
            .and_then(|value| value.checked_add(u64::from(bits) & mask))
            .ok_or_else(|| format_error("WinZip JPEG bit writer overflows"))?;
        self.bit_length = self
            .bit_length
            .checked_add(length)
            .ok_or_else(|| format_error("WinZip JPEG bit length overflows"))?;
        while self.bit_length >= 8 {
            let remaining = self
                .bit_length
                .checked_sub(8)
                .ok_or_else(|| format_error("WinZip JPEG bit length underflows"))?;
            let byte = u8::try_from((self.bit_string >> u32::from(remaining)) & 0xff)
                .map_err(|_| format_error("WinZip JPEG scan byte is not representable"))?;
            self.emit_scan_byte(byte, control)?;
            self.bit_length = remaining;
            self.bit_string &= if remaining == 0 {
                0
            } else {
                1_u64
                    .checked_shl(u32::from(remaining))
                    .and_then(|value| value.checked_sub(1))
                    .ok_or_else(|| format_error("WinZip JPEG residual bit mask overflows"))?
            };
        }
        Ok(())
    }

    fn push_huffman(
        &mut self,
        table: &[HuffCode; 256],
        symbol: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let code = table
            .get(symbol)
            .copied()
            .ok_or_else(|| format_error("WinZip JPEG Huffman symbol is out of range"))?;
        if code.length == 0 {
            return Err(format_error(
                "WinZip JPEG scan uses an absent Huffman symbol",
            ));
        }
        self.push_bits(u32::from(code.code), code.length, control)
    }

    fn push_encoded_value(
        &mut self,
        table: &[HuffCode; 256],
        value: i32,
        high_bits: usize,
        control: &mut ParseControl<'_>,
    ) -> Result<()> {
        let magnitude = i64::from(value)
            .checked_abs()
            .ok_or_else(|| format_error("WinZip JPEG encoded magnitude overflows"))?;
        let category =
            category(u64::try_from(magnitude).map_err(|_| {
                format_error("WinZip JPEG encoded magnitude is not representable")
            })?)?;
        if category > 15 || high_bits > 15 {
            return Err(format_error(
                "WinZip JPEG value is not Huffman-representable",
            ));
        }
        let category_u32 = u32::try_from(category)
            .map_err(|_| format_error("WinZip JPEG category is not representable"))?;
        let mask = if category_u32 == 0 {
            0_u32
        } else {
            1_u32
                .checked_shl(category_u32)
                .and_then(|item| item.checked_sub(1))
                .ok_or_else(|| format_error("WinZip JPEG encoded-value mask overflows"))?
        };
        let bits = if value >= 0 {
            u32::try_from(value)
                .map_err(|_| format_error("WinZip JPEG encoded value is invalid"))?
                & mask
        } else {
            mask.checked_sub(
                u32::try_from(magnitude)
                    .map_err(|_| format_error("WinZip JPEG negative value is not representable"))?,
            )
            .ok_or_else(|| format_error("WinZip JPEG negative value exceeds its category"))?
        };
        let symbol = high_bits
            .checked_mul(16)
            .and_then(|item| item.checked_add(category))
            .ok_or_else(|| format_error("WinZip JPEG Huffman symbol overflows"))?;
        self.push_huffman(table, symbol, control)?;
        self.push_bits(
            bits,
            u8::try_from(category)
                .map_err(|_| format_error("WinZip JPEG category is not representable"))?,
            control,
        )
    }

    fn pad_with_ones(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        if self.bit_length == 0 {
            return Ok(());
        }
        let padding = 8_u8
            .checked_sub(self.bit_length)
            .ok_or_else(|| format_error("WinZip JPEG padding length underflows"))?;
        let bits = 1_u32
            .checked_shl(u32::from(padding))
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| format_error("WinZip JPEG padding bits overflow"))?;
        self.push_bits(bits, padding, control)
    }

    fn restart(&mut self, control: &mut ParseControl<'_>) -> Result<()> {
        self.pad_with_ones(control)?;
        self.append_byte(0xff, control)?;
        self.append_byte(
            0xd0_u8
                .checked_add(self.restart_marker_index)
                .ok_or_else(|| format_error("WinZip JPEG restart marker overflows"))?,
            control,
        )?;
        self.restart_marker_index = self
            .restart_marker_index
            .checked_add(1)
            .ok_or_else(|| format_error("WinZip JPEG restart marker index overflows"))?
            & 7;
        self.mcu_counter = 0;
        self.predicted.fill(0);
        Ok(())
    }
}

fn append_metadata(
    output: &mut Vec<u8>,
    bytes: &[u8],
    expected: u64,
    maximum: u64,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let new_size = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| format_error("WinZip JPEG output size overflows"))?;
    let new_size_u64 = usize_to_u64(
        new_size,
        "WinZip JPEG output size is not representable as u64",
    )?;
    if new_size_u64 > expected {
        return Err(format_error(
            "WinZip JPEG metadata exceeds the ZIP output declaration",
        ));
    }
    check_limit(new_size_u64, maximum, LimitKind::TotalOutputBytes)?;
    try_reserve(output, bytes.len())?;
    for chunk in bytes.chunks(crate::parse_util::CONTROL_CHUNK_SIZE) {
        control.checkpoint(usize_to_u64(
            chunk.len(),
            "WinZip JPEG metadata chunk is not representable as u64",
        )?)?;
        output.extend_from_slice(chunk);
    }
    Ok(())
}

fn sign_contexts() -> Result<[usize; 64]> {
    let mut contexts = [0_usize; 64];
    let mut next = 0_usize;
    for (coefficient_index, context) in contexts.iter_mut().enumerate().skip(1) {
        let row = row_of(coefficient_index)?;
        let column = column_of(coefficient_index)?;
        if row == 0 || column == 0 || row == 1 || column == 1 {
            *context = next;
            next = next
                .checked_add(1)
                .ok_or_else(|| format_error("WinZip JPEG sign context count overflows"))?;
        }
    }
    if next != 27 {
        return Err(format_error(
            "WinZip JPEG sign context table is inconsistent",
        ));
    }
    Ok(contexts)
}

fn slice_height(metadata: &Metadata, slice_value: u8) -> Result<usize> {
    if metadata.horizontal_mcus == 0 || metadata.vertical_mcus == 0 {
        return Err(format_error("WinZip JPEG frame has no MCUs"));
    }
    if slice_value == 0 {
        return Ok(metadata.vertical_mcus);
    }
    let shift = u32::from(slice_value)
        .checked_add(6)
        .ok_or_else(|| format_error("WinZip JPEG slice shift overflows"))?;
    let power = 1_u64
        .checked_shl(shift)
        .ok_or_else(|| format_error("WinZip JPEG slice size overflows"))?;
    let horizontal = usize_to_u64(
        metadata.horizontal_mcus,
        "WinZip JPEG horizontal MCU count is not representable as u64",
    )?;
    let vertical = usize_to_u64(
        metadata.vertical_mcus,
        "WinZip JPEG vertical MCU count is not representable as u64",
    )?;
    let first_divisor = (power / horizontal).max(1);
    let first_rounding = first_divisor
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG slice divisor underflows"))?;
    let second_divisor = vertical
        .checked_add(first_rounding)
        .ok_or_else(|| format_error("WinZip JPEG slice divisor overflows"))?
        / first_divisor;
    let second_rounding = second_divisor
        .checked_sub(1)
        .ok_or_else(|| format_error("WinZip JPEG slice divisor underflows"))?;
    let height = vertical
        .checked_add(second_rounding)
        .ok_or_else(|| format_error("WinZip JPEG slice height overflows"))?
        / second_divisor;
    usize::try_from(height)
        .map_err(|_| format_error("WinZip JPEG slice height is not representable"))
}

fn allocate_blocks(
    metadata: &Metadata,
    slice_height: usize,
    model_bytes: u64,
    limits: Limits,
) -> Result<Vec<Vec<Block>>> {
    let mut counts = [0_usize; 4];
    let mut total_blocks = 0_usize;
    for scan_index in 0..metadata.num_scan_components {
        let scan = *metadata
            .scan_components
            .get(scan_index)
            .ok_or_else(|| format_error("WinZip JPEG scan component is missing"))?;
        let component = *metadata
            .components
            .get(scan.component_index)
            .ok_or_else(|| format_error("WinZip JPEG frame component is missing"))?;
        let count = metadata
            .horizontal_mcus
            .checked_mul(slice_height)
            .and_then(|value| value.checked_mul(component.horizontal_factor))
            .and_then(|value| value.checked_mul(component.vertical_factor))
            .ok_or_else(|| format_error("WinZip JPEG slice block count overflows"))?;
        if count == 0 {
            return Err(format_error("WinZip JPEG slice block count is zero"));
        }
        total_blocks = total_blocks
            .checked_add(count)
            .ok_or_else(|| format_error("WinZip JPEG aggregate block count overflows"))?;
        *counts
            .get_mut(scan_index)
            .ok_or_else(|| format_error("WinZip JPEG scan component index is out of range"))? =
            count;
    }
    let block_bytes = total_blocks
        .checked_mul(size_of::<Block>())
        .ok_or_else(|| format_error("WinZip JPEG slice buffer size overflows"))?;
    let aggregate = model_bytes
        .checked_add(usize_to_u64(
            block_bytes,
            "WinZip JPEG slice buffer size is not representable as u64",
        )?)
        .ok_or_else(|| format_error("WinZip JPEG decoder memory size overflows"))?;
    check_limit(
        aggregate,
        limits.max_dictionary_bytes(),
        LimitKind::DictionaryBytes,
    )?;
    let mut buffers = Vec::new();
    try_reserve(&mut buffers, metadata.num_scan_components)?;
    for count in counts.iter().copied().take(metadata.num_scan_components) {
        let mut blocks = Vec::new();
        try_reserve(&mut blocks, count)?;
        blocks.resize(count, Block::default());
        buffers.push(blocks);
    }
    Ok(buffers)
}

#[allow(clippy::too_many_arguments)]
fn decode_slice(
    input: &mut Input<'_>,
    metadata: &Metadata,
    blocks: &mut [Vec<Block>],
    models: &mut Models,
    fixed: &mut Bin,
    sign_contexts: &[usize; 64],
    slice_height: usize,
    current_height: usize,
    finished_rows: usize,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    for scan_index in 0..metadata.num_scan_components {
        let scan = *metadata
            .scan_components
            .get(scan_index)
            .ok_or_else(|| format_error("WinZip JPEG scan component is missing"))?;
        let component = *metadata
            .components
            .get(scan.component_index)
            .ok_or_else(|| format_error("WinZip JPEG frame component is missing"))?;
        let quant = metadata
            .quant_tables
            .get(component.quant_index)
            .ok_or_else(|| format_error("WinZip JPEG quantization table is missing"))?;
        let blocks_per_row = metadata
            .horizontal_mcus
            .checked_mul(component.horizontal_factor)
            .ok_or_else(|| format_error("WinZip JPEG block-row width overflows"))?;
        let rows = current_height
            .checked_mul(component.vertical_factor)
            .ok_or_else(|| format_error("WinZip JPEG component row count overflows"))?;
        let previous_row = slice_height
            .checked_mul(component.vertical_factor)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| format_error("WinZip JPEG previous slice row underflows"))?;
        let component_blocks = blocks
            .get_mut(scan_index)
            .ok_or_else(|| format_error("WinZip JPEG component buffer is missing"))?;
        let mut decoder = ArithmeticDecoder::new(input, control)?;
        for row in 0..rows {
            control.checkpoint(0)?;
            for column in 0..blocks_per_row {
                let index = row
                    .checked_mul(blocks_per_row)
                    .and_then(|value| value.checked_add(column))
                    .ok_or_else(|| format_error("WinZip JPEG block index overflows"))?;
                let north = if row > 0 {
                    let north_index = index
                        .checked_sub(blocks_per_row)
                        .ok_or_else(|| format_error("WinZip JPEG north block index underflows"))?;
                    component_blocks.get(north_index).copied()
                } else if finished_rows > 0 {
                    let north_index = previous_row
                        .checked_mul(blocks_per_row)
                        .and_then(|value| value.checked_add(column))
                        .ok_or_else(|| format_error("WinZip JPEG north block index overflows"))?;
                    component_blocks.get(north_index).copied()
                } else {
                    None
                };
                let west = if column > 0 {
                    let west_index = index
                        .checked_sub(1)
                        .ok_or_else(|| format_error("WinZip JPEG west block index underflows"))?;
                    component_blocks.get(west_index).copied()
                } else {
                    None
                };
                let block = decode_block(
                    &mut decoder,
                    models,
                    fixed,
                    sign_contexts,
                    scan_index,
                    north.as_ref(),
                    west.as_ref(),
                    quant,
                    control,
                )?;
                *component_blocks
                    .get_mut(index)
                    .ok_or_else(|| format_error("WinZip JPEG block index is out of range"))? =
                    block;
            }
        }
        decoder.flush(control)?;
    }
    Ok(())
}

fn encode_slice(
    writer: &mut ScanWriter<'_>,
    metadata: &Metadata,
    blocks: &[Vec<Block>],
    current_height: usize,
    is_last: bool,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    for mcu_row in 0..current_height {
        for mcu_column in 0..metadata.horizontal_mcus {
            if metadata.restart_interval != 0 && writer.mcu_counter == metadata.restart_interval {
                writer.restart(control)?;
            }
            for scan_index in 0..metadata.num_scan_components {
                let scan = *metadata
                    .scan_components
                    .get(scan_index)
                    .ok_or_else(|| format_error("WinZip JPEG scan component is missing"))?;
                let component = *metadata
                    .components
                    .get(scan.component_index)
                    .ok_or_else(|| format_error("WinZip JPEG frame component is missing"))?;
                let dc_table = metadata
                    .huff_codes
                    .first()
                    .and_then(|tables| tables.get(scan.dc_table))
                    .ok_or_else(|| format_error("WinZip JPEG DC Huffman table is missing"))?;
                let ac_table = metadata
                    .huff_codes
                    .get(1)
                    .and_then(|tables| tables.get(scan.ac_table))
                    .ok_or_else(|| format_error("WinZip JPEG AC Huffman table is missing"))?;
                let blocks_per_row = metadata
                    .horizontal_mcus
                    .checked_mul(component.horizontal_factor)
                    .ok_or_else(|| format_error("WinZip JPEG block-row width overflows"))?;
                for block_y in 0..component.vertical_factor {
                    for block_x in 0..component.horizontal_factor {
                        let x = mcu_column
                            .checked_mul(component.horizontal_factor)
                            .and_then(|value| value.checked_add(block_x))
                            .ok_or_else(|| format_error("WinZip JPEG block column overflows"))?;
                        let y = mcu_row
                            .checked_mul(component.vertical_factor)
                            .and_then(|value| value.checked_add(block_y))
                            .ok_or_else(|| format_error("WinZip JPEG block row overflows"))?;
                        let index = y
                            .checked_mul(blocks_per_row)
                            .and_then(|value| value.checked_add(x))
                            .ok_or_else(|| format_error("WinZip JPEG block index overflows"))?;
                        let block = blocks
                            .get(scan_index)
                            .and_then(|items| items.get(index))
                            .ok_or_else(|| format_error("WinZip JPEG block is missing"))?;
                        let dc = *block
                            .coefficients
                            .first()
                            .ok_or_else(|| format_error("WinZip JPEG DC coefficient is missing"))?;
                        let predicted = *writer
                            .predicted
                            .get(scan_index)
                            .ok_or_else(|| format_error("WinZip JPEG predictor is missing"))?;
                        let difference = i32::from(dc)
                            .checked_sub(i32::from(predicted))
                            .ok_or_else(|| format_error("WinZip JPEG DC difference overflows"))?;
                        writer.push_encoded_value(dc_table, difference, 0, control)?;
                        *writer
                            .predicted
                            .get_mut(scan_index)
                            .ok_or_else(|| format_error("WinZip JPEG predictor is missing"))? = dc;

                        let mut coefficient_index = 1_usize;
                        let eob = usize::from(block.eob);
                        while coefficient_index <= eob {
                            let first = coefficient_index;
                            let run_end = coefficient_index
                                .checked_add(15)
                                .ok_or_else(|| format_error("WinZip JPEG AC run overflows"))?;
                            while coefficient_index < 63
                                && coefficient_index < run_end
                                && block
                                    .coefficients
                                    .get(coefficient_index)
                                    .copied()
                                    .ok_or_else(|| {
                                        format_error("WinZip JPEG AC coefficient is missing")
                                    })?
                                    == 0
                            {
                                coefficient_index =
                                    coefficient_index.checked_add(1).ok_or_else(|| {
                                        format_error("WinZip JPEG AC coefficient index overflows")
                                    })?;
                            }
                            let zeroes = coefficient_index
                                .checked_sub(first)
                                .ok_or_else(|| format_error("WinZip JPEG AC run underflows"))?;
                            writer.push_encoded_value(
                                ac_table,
                                i32::from(*block.coefficients.get(coefficient_index).ok_or_else(
                                    || format_error("WinZip JPEG AC coefficient is missing"),
                                )?),
                                zeroes,
                                control,
                            )?;
                            coefficient_index =
                                coefficient_index.checked_add(1).ok_or_else(|| {
                                    format_error("WinZip JPEG AC coefficient index overflows")
                                })?;
                        }
                        if eob != 63 {
                            writer.push_huffman(ac_table, 0, control)?;
                        }
                    }
                }
            }
            writer.mcu_counter = writer
                .mcu_counter
                .checked_add(1)
                .ok_or_else(|| format_error("WinZip JPEG MCU counter overflows"))?;
        }
    }
    if is_last {
        writer.pad_with_ones(control)?;
    }
    Ok(())
}

fn read_bundle_sizes(input: &mut Input<'_>, control: &mut ParseControl<'_>) -> Result<(u64, u64)> {
    let short = input.read_slice(4, control)?;
    let [u0, u1, c0, c1] = <[u8; 4]>::try_from(short)
        .map_err(|_| format_error("truncated WinZip JPEG bundle header"))?;
    let uncompressed = u64::from(u16::from_le_bytes([u0, u1]));
    let compressed = u64::from(u16::from_le_bytes([c0, c1]));
    if uncompressed == 0xffff && compressed == 0xffff {
        let long = input.read_slice(8, control)?;
        let [u0, u1, u2, u3, c0, c1, c2, c3] = <[u8; 8]>::try_from(long)
            .map_err(|_| format_error("truncated WinZip JPEG extended bundle header"))?;
        let uncompressed = u64::from(u32::from_le_bytes([u0, u1, u2, u3]));
        let compressed = u64::from(u32::from_le_bytes([c0, c1, c2, c3]));
        Ok((uncompressed, compressed))
    } else {
        Ok((uncompressed, compressed))
    }
}

fn check_frame(counter: &mut u64, limits: Limits) -> Result<()> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| format_error("WinZip JPEG frame count overflows"))?;
    check_limit(
        *counter,
        limits.max_stream_frames(),
        LimitKind::StreamFrames,
    )
}

/// Decodes one complete ZIP method-96 payload and recreates its JPEG bytes.
pub(crate) fn decode_zip_jpeg(
    bytes: &[u8],
    expected: u64,
    maximum: u64,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(
        expected,
        limits.max_entry_output_bytes(),
        LimitKind::EntryOutputBytes,
    )?;
    check_limit(expected, maximum, LimitKind::TotalOutputBytes)?;
    let output_capacity = usize::try_from(expected)
        .map_err(|_| format_error("WinZip JPEG output size is not representable"))?;
    let mut output = Vec::new();
    try_reserve(&mut output, output_capacity)?;

    let mut input = Input::new(bytes);
    let properties = <[u8; 4]>::try_from(input.read_slice(4, control)?)
        .map_err(|_| format_error("truncated WinZip JPEG properties header"))?;
    let [header_size, version, method, flags] = properties;
    let header_size = usize::from(header_size);
    if header_size < 4 || version != 0x10 || method != 0x01 || flags & 0xe0 != 0 {
        return Err(format_error("invalid WinZip JPEG properties header"));
    }
    if header_size > 4 {
        let extension_size = header_size
            .checked_sub(4)
            .ok_or_else(|| format_error("WinZip JPEG properties size underflows"))?;
        let _ = input.read_slice(extension_size, control)?;
    }
    let slice_value = flags & 0x1f;
    let contexts = sign_contexts()?;
    let mut metadata = Metadata::default();
    let mut fixed = Bin::fixed();
    let mut first_bundle = true;
    let mut metadata_bytes = 0_u64;
    let mut frame_count = 0_u64;

    loop {
        check_frame(&mut frame_count, limits)?;
        let (uncompressed_size, compressed_size) = read_bundle_sizes(&mut input, control)?;
        if uncompressed_size == 0 || uncompressed_size > MAX_METADATA_SIZE {
            return Err(format_error("WinZip JPEG metadata bundle size is invalid"));
        }
        if compressed_size > MAX_METADATA_SIZE {
            return Err(format_error(
                "WinZip JPEG compressed bundle size is invalid",
            ));
        }
        metadata_bytes = metadata_bytes
            .checked_add(uncompressed_size)
            .ok_or_else(|| format_error("WinZip JPEG aggregate metadata size overflows"))?;
        check_limit(
            metadata_bytes,
            limits.max_header_bytes(),
            LimitKind::HeaderBytes,
        )?;
        let uncompressed_length = usize::try_from(uncompressed_size)
            .map_err(|_| format_error("WinZip JPEG metadata size is not representable"))?;
        let decoded_storage;
        let bundle = if compressed_size == 0 {
            input.read_slice(uncompressed_length, control)?
        } else {
            let compressed_length = usize::try_from(compressed_size)
                .map_err(|_| format_error("WinZip JPEG compressed size is not representable"))?;
            let compressed = input.read_slice(compressed_length, control)?;
            let rounded = uncompressed_size
                .checked_add(511)
                .ok_or_else(|| format_error("WinZip JPEG dictionary size overflows"))?
                & !511_u64;
            let dictionary = rounded.clamp(1024, 512 * 1024);
            check_limit(
                dictionary,
                limits.max_dictionary_bytes(),
                LimitKind::DictionaryBytes,
            )?;
            let dictionary_u32 = u32::try_from(dictionary)
                .map_err(|_| format_error("WinZip JPEG dictionary is not representable"))?;
            let mut lzma_properties = [0_u8; 5];
            lzma_properties[0] = 3 + 2 * 5 * 9;
            lzma_properties[1..].copy_from_slice(&dictionary_u32.to_le_bytes());
            decoded_storage = decode_lzma_exact(
                compressed,
                &lzma_properties,
                uncompressed_size,
                uncompressed_size,
                control,
            )?;
            decoded_storage.as_slice()
        };
        if bundle.len() != uncompressed_length {
            return Err(format_error(
                "WinZip JPEG metadata size differs from its declaration",
            ));
        }
        append_metadata(&mut output, bundle, expected, maximum, control)?;

        let parse_bytes = if first_bundle {
            let start = bundle
                .windows(2)
                .position(|window| window == [0xff, 0xd8])
                .ok_or_else(|| format_error("WinZip JPEG first bundle has no SOI marker"))?;
            first_bundle = false;
            bundle
                .get(start..)
                .ok_or_else(|| format_error("WinZip JPEG SOI offset is out of range"))?
        } else {
            bundle
        };
        match parse_metadata(&mut metadata, parse_bytes)? {
            MetadataResult::End => break,
            MetadataResult::Scan => {
                let height = slice_height(&metadata, slice_value)?;
                let model_bytes = Models::required_bytes()?;
                let mut blocks = allocate_blocks(&metadata, height, model_bytes, limits)?;
                let mut models = Models::new(limits)?;
                models.reset();
                let mut finished_rows = 0_usize;
                let mut writer = ScanWriter::new(&mut output, expected, maximum);
                while finished_rows < metadata.vertical_mcus {
                    check_frame(&mut frame_count, limits)?;
                    let remaining = metadata
                        .vertical_mcus
                        .checked_sub(finished_rows)
                        .ok_or_else(|| format_error("WinZip JPEG remaining rows underflow"))?;
                    let current_height = height.min(remaining);
                    decode_slice(
                        &mut input,
                        &metadata,
                        &mut blocks,
                        &mut models,
                        &mut fixed,
                        &contexts,
                        height,
                        current_height,
                        finished_rows,
                        control,
                    )?;
                    finished_rows = finished_rows
                        .checked_add(current_height)
                        .ok_or_else(|| format_error("WinZip JPEG finished row count overflows"))?;
                    encode_slice(
                        &mut writer,
                        &metadata,
                        &blocks,
                        current_height,
                        finished_rows == metadata.vertical_mcus,
                        control,
                    )?;
                }
            }
        }
    }
    if !input.is_finished() {
        return Err(format_error("WinZip JPEG stream has trailing input"));
    }
    let actual = usize_to_u64(
        output.len(),
        "WinZip JPEG output size is not representable as u64",
    )?;
    if actual != expected {
        return Err(format_error(
            "WinZip JPEG output size differs from its declaration",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, ErrorKind, WorkBudget};

    const SOURCE: &str =
        include_str!("../../tests/fixtures/method96/method96-project-authored.jpg.b64");
    const ARCHIVE: &str = include_str!("../../tests/fixtures/method96/winzip21-method96.zipx.b64");

    #[test]
    fn decodes_winzip_reference_stream_exactly() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let decoded = decode_zip_jpeg(
            payload,
            usize_to_u64(source.len(), "method 96 test size is not representable")?,
            usize_to_u64(source.len(), "method 96 test size is not representable")?,
            Limits::default(),
            &mut control,
        )?;
        if decoded != source {
            let first = decoded
                .iter()
                .zip(&source)
                .position(|(actual, expected)| actual != expected);
            let start = first.unwrap_or_default().saturating_sub(8);
            let end = start
                .saturating_add(32)
                .min(decoded.len())
                .min(source.len());
            return Err(Error::Format {
                detail: format!(
                    "method 96 output differs at {first:?}: actual={:02x?} expected={:02x?}",
                    decoded.get(start..end),
                    source.get(start..end)
                ),
            });
        }
        Ok(())
    }

    #[test]
    fn accepts_stored_metadata_and_extended_properties() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;
        let stored = stored_first_bundle(payload)?;
        assert_eq!(
            decode_reference(&stored, &source, Limits::default())?,
            source
        );

        let mut extended = Vec::new();
        try_reserve(&mut extended, payload.len() + 1)?;
        let flags = *payload
            .get(3)
            .ok_or_else(|| format_error("method 96 property flags are missing"))?;
        extended.extend_from_slice(&[5, 0x10, 1, flags, 0xa5]);
        extended.extend_from_slice(
            payload
                .get(4..)
                .ok_or_else(|| format_error("method 96 properties are truncated"))?,
        );
        assert_eq!(
            decode_reference(&extended, &source, Limits::default())?,
            source
        );

        let uncompressed_size = u32::from(u16::from_le_bytes([
            *stored
                .get(4)
                .ok_or_else(|| format_error("method 96 stored metadata size is missing"))?,
            *stored
                .get(5)
                .ok_or_else(|| format_error("method 96 stored metadata size is missing"))?,
        ]));
        let mut extended_bundle = Vec::new();
        let extended_capacity = stored
            .len()
            .checked_add(8)
            .ok_or_else(|| format_error("method 96 extended bundle size overflows"))?;
        try_reserve(&mut extended_bundle, extended_capacity)?;
        extended_bundle.extend_from_slice(
            stored
                .get(..4)
                .ok_or_else(|| format_error("method 96 properties are truncated"))?,
        );
        extended_bundle.extend_from_slice(&0xffff_u16.to_le_bytes());
        extended_bundle.extend_from_slice(&0xffff_u16.to_le_bytes());
        extended_bundle.extend_from_slice(&uncompressed_size.to_le_bytes());
        extended_bundle.extend_from_slice(&0_u32.to_le_bytes());
        extended_bundle.extend_from_slice(
            stored
                .get(8..)
                .ok_or_else(|| format_error("method 96 stored bundle is truncated"))?,
        );
        assert_eq!(
            decode_reference(&extended_bundle, &source, Limits::default())?,
            source
        );

        let mut twelve_bit_payload = stored;
        let payload_sof = find_frame_marker(&twelve_bit_payload, 8)?;
        *twelve_bit_payload
            .get_mut(payload_sof + 1)
            .ok_or_else(|| format_error("method 96 synthetic SOF marker is missing"))? = 0xc1;
        *twelve_bit_payload
            .get_mut(payload_sof + 4)
            .ok_or_else(|| format_error("method 96 synthetic precision is missing"))? = 12;
        let mut twelve_bit_source = source;
        let source_sof = find_frame_marker(&twelve_bit_source, 0)?;
        *twelve_bit_source
            .get_mut(source_sof + 1)
            .ok_or_else(|| format_error("method 96 source SOF marker is missing"))? = 0xc1;
        *twelve_bit_source
            .get_mut(source_sof + 4)
            .ok_or_else(|| format_error("method 96 source precision is missing"))? = 12;
        assert_eq!(
            decode_reference(&twelve_bit_payload, &twelve_bit_source, Limits::default(),)?,
            twelve_bit_source
        );
        Ok(())
    }

    #[test]
    fn rejects_sampled_truncation_corruption_and_trailing_input() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;

        let mut lengths = Vec::new();
        try_reserve(&mut lengths, 400)?;
        lengths.extend(0..256_usize.min(payload.len()));
        lengths.extend((256..payload.len()).step_by(64));
        let tail_start = payload.len().saturating_sub(128);
        lengths.extend(tail_start..payload.len());
        lengths.sort_unstable();
        lengths.dedup();
        for length in lengths {
            let prefix = payload
                .get(..length)
                .ok_or_else(|| format_error("method 96 prefix is out of range"))?;
            assert!(
                decode_reference(prefix, &source, Limits::default()).is_err(),
                "method 96 prefix {length} unexpectedly decoded"
            );
        }

        for offset in (0..payload.len()).step_by(127) {
            let mut corrupt = payload.to_vec();
            let byte = corrupt
                .get_mut(offset)
                .ok_or_else(|| format_error("method 96 mutation offset is out of range"))?;
            *byte ^= 0x40;
            if let Ok(decoded) = decode_reference(&corrupt, &source, Limits::default()) {
                assert_ne!(decoded, source, "mutation {offset} was invisible");
            }
        }

        let mut trailing = payload.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_reference(&trailing, &source, Limits::default())
                .as_ref()
                .err()
                .map(Error::kind),
            Some(ErrorKind::Format)
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_metadata_tables_and_scan_profiles() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;
        let stored = stored_first_bundle(payload)?;
        let metadata_start = 8_usize;

        let dqt = find_marker(&stored, metadata_start, 0xdb)?;
        let mut zero_quantizer = stored.clone();
        *zero_quantizer
            .get_mut(dqt + 5)
            .ok_or_else(|| format_error("method 96 DQT value is missing"))? = 0;
        assert!(decode_reference(&zero_quantizer, &source, Limits::default()).is_err());

        let mut malformed_dri = stored.clone();
        *malformed_dri
            .get_mut(dqt + 1)
            .ok_or_else(|| format_error("method 96 DQT marker is missing"))? = 0xdd;
        assert!(decode_reference(&malformed_dri, &source, Limits::default()).is_err());

        let dht = find_marker(&stored, metadata_start, 0xc4)?;
        let mut oversubscribed = stored.clone();
        *oversubscribed
            .get_mut(dht + 5)
            .ok_or_else(|| format_error("method 96 DHT count is missing"))? = 3;
        assert!(decode_reference(&oversubscribed, &source, Limits::default()).is_err());

        let mut repeated_huffman_symbol = stored.clone();
        let first_symbol = *repeated_huffman_symbol
            .get(dht + 21)
            .ok_or_else(|| format_error("method 96 first DHT symbol is missing"))?;
        *repeated_huffman_symbol
            .get_mut(dht + 22)
            .ok_or_else(|| format_error("method 96 second DHT symbol is missing"))? = first_symbol;
        assert!(decode_reference(&repeated_huffman_symbol, &source, Limits::default()).is_err());

        let sof = find_frame_marker(&stored, metadata_start)?;
        let mut repeated_component = stored.clone();
        let first_identifier = *repeated_component
            .get(sof + 10)
            .ok_or_else(|| format_error("method 96 first component is missing"))?;
        *repeated_component
            .get_mut(sof + 13)
            .ok_or_else(|| format_error("method 96 second component is missing"))? =
            first_identifier;
        assert!(decode_reference(&repeated_component, &source, Limits::default()).is_err());

        let mut progressive = stored.clone();
        *progressive
            .get_mut(sof + 1)
            .ok_or_else(|| format_error("method 96 SOF marker is missing"))? = 0xc2;
        assert_eq!(
            decode_reference(&progressive, &source, Limits::default())
                .as_ref()
                .err()
                .map(Error::kind),
            Some(ErrorKind::UnsupportedFeature)
        );

        let sos = find_marker(&stored, metadata_start, 0xda)?;
        let count = usize::from(
            *stored
                .get(sos + 4)
                .ok_or_else(|| format_error("method 96 SOS count is missing"))?,
        );
        let selector = sos
            .checked_add(5)
            .and_then(|value| value.checked_add(count.checked_mul(2)?))
            .ok_or_else(|| format_error("method 96 SOS selector offset overflows"))?;
        let mut spectral = stored.clone();
        *spectral
            .get_mut(selector)
            .ok_or_else(|| format_error("method 96 spectral selector is missing"))? = 1;
        assert_eq!(
            decode_reference(&spectral, &source, Limits::default())
                .as_ref()
                .err()
                .map(Error::kind),
            Some(ErrorKind::UnsupportedFeature)
        );

        let first_scan_component = *stored
            .get(sos + 5)
            .ok_or_else(|| format_error("method 96 first scan component is missing"))?;
        let mut repeated_scan_component = stored.clone();
        *repeated_scan_component
            .get_mut(sos + 7)
            .ok_or_else(|| format_error("method 96 second scan component is missing"))? =
            first_scan_component;
        assert!(decode_reference(&repeated_scan_component, &source, Limits::default()).is_err());

        let mut missing_tables = stored;
        *missing_tables
            .get_mut(sos + 6)
            .ok_or_else(|| format_error("method 96 Huffman selector is missing"))? = 0x33;
        assert!(decode_reference(&missing_tables, &source, Limits::default()).is_err());
        Ok(())
    }

    #[test]
    fn enforces_limits_work_and_cancellation() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;
        let source_size = usize_to_u64(
            source.len(),
            "method 96 source size is not representable as u64",
        )?;
        let limited_source_size = source_size
            .checked_sub(1)
            .ok_or_else(|| format_error("method 96 source size underflows"))?;
        let model_bytes = usize_to_u64(
            MODEL_COUNT
                .checked_mul(size_of::<Bin>())
                .ok_or_else(|| format_error("method 96 model size overflows"))?,
            "method 96 model size is not representable as u64",
        )?;
        let cases = [
            (
                Limits::builder()
                    .max_entry_output_bytes(limited_source_size)
                    .build(),
                LimitKind::EntryOutputBytes,
            ),
            (
                Limits::builder().max_header_bytes(292).build(),
                LimitKind::HeaderBytes,
            ),
            (
                Limits::builder().max_dictionary_bytes(0).build(),
                LimitKind::DictionaryBytes,
            ),
            (
                Limits::builder().max_dictionary_bytes(model_bytes).build(),
                LimitKind::DictionaryBytes,
            ),
            (
                Limits::builder().max_stream_frames(1).build(),
                LimitKind::StreamFrames,
            ),
        ];
        for (limits, expected_limit) in cases {
            let error = decode_reference(payload, &source, limits)
                .err()
                .ok_or_else(|| format_error("method 96 limit unexpectedly succeeded"))?;
            assert!(matches!(
                error,
                Error::LimitExceeded { limit, .. } if limit == expected_limit
            ));
        }

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::bounded(0);
        let mut control = ParseControl::new(&cancellation, &mut budget);
        assert!(matches!(
            decode_zip_jpeg(
                payload,
                source_size,
                source_size,
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
            decode_zip_jpeg(
                payload,
                source_size,
                source_size,
                Limits::default(),
                &mut control,
            ),
            Err(Error::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn rejects_lzma_bundle_bytes_outside_the_declared_stream() -> Result<()> {
        let source = decode_base64(SOURCE)?;
        let archive = decode_base64(ARCHIVE)?;
        let payload = reference_payload(&archive)?;
        let compressed_size = usize::from(u16::from_le_bytes([
            *payload
                .get(6)
                .ok_or_else(|| format_error("method 96 compressed size is missing"))?,
            *payload
                .get(7)
                .ok_or_else(|| format_error("method 96 compressed size is missing"))?,
        ]));
        let insertion = 8_usize
            .checked_add(compressed_size)
            .ok_or_else(|| format_error("method 96 LZMA range overflows"))?;
        let mut padded = payload.to_vec();
        padded.insert(insertion, 0);
        let increased = u16::try_from(
            compressed_size
                .checked_add(1)
                .ok_or_else(|| format_error("method 96 LZMA test size overflows"))?,
        )
        .map_err(|_| format_error("method 96 LZMA test size overflows"))?;
        padded
            .get_mut(6..8)
            .ok_or_else(|| format_error("method 96 bundle size is missing"))?
            .copy_from_slice(&increased.to_le_bytes());
        assert!(decode_reference(&padded, &source, Limits::default()).is_err());
        Ok(())
    }

    fn reference_payload(archive: &[u8]) -> Result<&[u8]> {
        archive
            .get(59..59 + 3_155)
            .ok_or_else(|| format_error("method 96 test payload is truncated"))
    }

    fn decode_reference(payload: &[u8], source: &[u8], limits: Limits) -> Result<Vec<u8>> {
        let expected = usize_to_u64(source.len(), "method 96 test size is not representable")?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        decode_zip_jpeg(payload, expected, expected, limits, &mut control)
    }

    fn stored_first_bundle(payload: &[u8]) -> Result<Vec<u8>> {
        let uncompressed = usize::from(u16::from_le_bytes([
            *payload
                .get(4)
                .ok_or_else(|| format_error("method 96 metadata size is missing"))?,
            *payload
                .get(5)
                .ok_or_else(|| format_error("method 96 metadata size is missing"))?,
        ]));
        let compressed = usize::from(u16::from_le_bytes([
            *payload
                .get(6)
                .ok_or_else(|| format_error("method 96 compressed size is missing"))?,
            *payload
                .get(7)
                .ok_or_else(|| format_error("method 96 compressed size is missing"))?,
        ]));
        let compressed_end = 8_usize
            .checked_add(compressed)
            .ok_or_else(|| format_error("method 96 compressed range overflows"))?;
        let compressed_bytes = payload
            .get(8..compressed_end)
            .ok_or_else(|| format_error("method 96 compressed metadata is truncated"))?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let properties = [93, 0, 4, 0, 0];
        let uncompressed_u64 = usize_to_u64(
            uncompressed,
            "method 96 metadata size is not representable as u64",
        )?;
        let metadata = decode_lzma_exact(
            compressed_bytes,
            &properties,
            uncompressed_u64,
            uncompressed_u64,
            &mut control,
        )?;
        let mut stored = Vec::new();
        let capacity = payload
            .len()
            .checked_sub(compressed)
            .and_then(|value| value.checked_add(uncompressed))
            .ok_or_else(|| format_error("method 96 stored fixture size overflows"))?;
        try_reserve(&mut stored, capacity)?;
        stored.extend_from_slice(
            payload
                .get(..4)
                .ok_or_else(|| format_error("method 96 properties are truncated"))?,
        );
        stored.extend_from_slice(
            &u16::try_from(uncompressed)
                .map_err(|_| format_error("method 96 metadata size exceeds u16"))?
                .to_le_bytes(),
        );
        stored.extend_from_slice(&0_u16.to_le_bytes());
        stored.extend_from_slice(&metadata);
        stored.extend_from_slice(
            payload
                .get(compressed_end..)
                .ok_or_else(|| format_error("method 96 arithmetic stream is missing"))?,
        );
        Ok(stored)
    }

    fn find_marker(bytes: &[u8], start: usize, marker: u8) -> Result<usize> {
        bytes
            .get(start..)
            .ok_or_else(|| format_error("method 96 marker search start is out of range"))?
            .windows(2)
            .position(|window| window == [0xff, marker])
            .and_then(|position| start.checked_add(position))
            .ok_or_else(|| format_error("method 96 marker is missing"))
    }

    fn find_frame_marker(bytes: &[u8], start: usize) -> Result<usize> {
        let candidates = [
            find_marker(bytes, start, 0xc0),
            find_marker(bytes, start, 0xc1),
        ];
        candidates
            .into_iter()
            .filter_map(Result::ok)
            .min()
            .ok_or_else(|| format_error("method 96 frame marker is missing"))
    }

    fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
        let compact: Vec<u8> = encoded
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if compact.len() % 4 != 0 {
            return Err(format_error("invalid method 96 test base64 length"));
        }
        let capacity = compact
            .len()
            .checked_div(4)
            .and_then(|value| value.checked_mul(3))
            .ok_or_else(|| format_error("method 96 test base64 size overflows"))?;
        let mut output = Vec::new();
        try_reserve(&mut output, capacity)?;
        for chunk in compact.chunks_exact(4) {
            let [first, second, third, fourth] = <[u8; 4]>::try_from(chunk)
                .map_err(|_| format_error("truncated method 96 test base64"))?;
            let first = base64_value(first)?;
            let second = base64_value(second)?;
            let third = base64_value(third)?;
            let fourth = base64_value(fourth)?;
            output.push((first << 2) | (second >> 4));
            if third < 64 {
                output.push((second << 4) | (third >> 2));
            }
            if fourth < 64 {
                output.push((third << 6) | fourth);
            }
        }
        Ok(output)
    }

    fn base64_value(value: u8) -> Result<u8> {
        match value {
            b'A'..=b'Z' => Ok(value - b'A'),
            b'a'..=b'z' => Ok(value - b'a' + 26),
            b'0'..=b'9' => Ok(value - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(64),
            _ => Err(format_error("invalid method 96 test base64")),
        }
    }
}
