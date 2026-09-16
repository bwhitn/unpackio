//! The 32-byte `wvpk` block header, a block iterator, and a whole-stream scan.

use crate::error::{Error, Scope};
use crate::format::{self, Flags, meta};
use crate::metadata::{SubBlocks, check_scope};

/// Header size on disk.
pub const HEADER_LEN: usize = 32;

fn bytes_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Truncated {
        need: usize::MAX,
        have: bytes.len(),
    })?;
    let slice = bytes.get(offset..end).ok_or(Error::Truncated {
        need: end,
        have: bytes.len(),
    })?;
    <[u8; N]>::try_from(slice).map_err(|_| Error::Truncated {
        need: end,
        have: bytes.len(),
    })
}

/// A parsed block header. Field names follow the reference struct.
#[derive(Clone, Copy, Debug)]
pub struct BlockHeader {
    /// Size of the block minus 8; on-disk block length is `ck_size + 8`.
    pub ck_size: u32,
    /// Stream version, `0x402..=0x410`.
    pub version: u16,
    /// First frame index of this block (40-bit).
    pub block_index: u64,
    /// Total frames in the file; `None` when unknown. Valid only on the block
    /// whose `block_index` is 0.
    pub total_samples: Option<u64>,
    /// Frames in this block; 0 marks a metadata-only block.
    pub block_samples: u32,
    pub flags: Flags,
    /// Running CRC of this block's decoded samples.
    pub crc: u32,
}

impl BlockHeader {
    /// Parse one header. Rejects bad magic, out-of-range versions, and
    /// implausible sizes; scope rejection (DSD, hybrid) happens here too so an
    /// out-of-scope file fails on its very first block.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                have: bytes.len(),
            });
        }
        let magic = bytes_at::<4>(bytes, 0)?;
        if magic != format::MAGIC {
            return Err(Error::BadMagic(magic));
        }
        let le32 = |offset: usize| bytes_at::<4>(bytes, offset).map(u32::from_le_bytes);
        let ck_size = le32(4)?;
        if ck_size
            .checked_add(8)
            .is_none_or(|size| size > format::MAX_BLOCK_SIZE)
            || ck_size < 24
        {
            return Err(Error::BadBlockSize(ck_size));
        }
        let version = u16::from_le_bytes(bytes_at::<2>(bytes, 8)?);
        if !(format::MIN_STREAM_VERS..=format::MAX_STREAM_VERS).contains(&version) {
            return Err(Error::UnsupportedVersion(version));
        }
        let block_index_u8 = bytes.get(10).copied().ok_or(Error::Truncated {
            need: HEADER_LEN,
            have: bytes.len(),
        })?;
        let total_samples_u8 = bytes.get(11).copied().ok_or(Error::Truncated {
            need: HEADER_LEN,
            have: bytes.len(),
        })?;
        let total_samples_low = le32(12)?;
        let block_index = (u64::from(block_index_u8) << 32) | u64::from(le32(16)?);
        let block_samples = le32(20)?;
        if block_samples > format::MAX_BLOCK_SAMPLES {
            return Err(Error::BadBlockSize(block_samples));
        }
        let flags = Flags(le32(24)?);
        if flags.is_dsd() {
            return Err(Error::OutOfScope(Scope::Dsd));
        }
        if flags.is_hybrid() {
            return Err(Error::OutOfScope(Scope::Hybrid));
        }
        // All-ones low word means unknown length.
        let total_samples = if total_samples_low == u32::MAX {
            None
        } else {
            Some(
                (u64::from(total_samples_u8) << 32)
                    .checked_sub(u64::from(total_samples_u8))
                    .and_then(|high| high.checked_add(u64::from(total_samples_low)))
                    .ok_or(Error::BadBlockSize(total_samples_low))?,
            )
        };
        Ok(Self {
            ck_size,
            version,
            block_index,
            total_samples,
            block_samples,
            flags,
            crc: le32(28)?,
        })
    }

    /// On-disk length of the whole block including the header.
    pub fn block_len(&self) -> Result<usize, Error> {
        usize::try_from(self.ck_size)
            .ok()
            .and_then(|size| size.checked_add(8))
            .ok_or(Error::BadBlockSize(self.ck_size))
    }
}

/// One block: its header plus a borrowed metadata region.
#[derive(Clone, Copy, Debug)]
pub struct Block<'a> {
    pub header: BlockHeader,
    pub metadata: &'a [u8],
}

impl<'a> Block<'a> {
    /// Iterate this block's metadata sub-blocks.
    pub fn sub_blocks(&self) -> SubBlocks<'a> {
        SubBlocks::new(self.metadata)
    }
}

/// Iterator over consecutive blocks in a byte stream. Strict: the stream must
/// begin at a block boundary and contain nothing but whole blocks (leading
/// tags or resynchronization are not handled at this milestone).
pub struct Blocks<'a> {
    rest: &'a [u8],
}

impl<'a> Blocks<'a> {
    pub fn new(stream: &'a [u8]) -> Self {
        Self { rest: stream }
    }
}

impl<'a> Iterator for Blocks<'a> {
    type Item = Result<Block<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let header = match BlockHeader::parse(self.rest) {
            Ok(h) => h,
            Err(e) => {
                self.rest = &[];
                return Some(Err(e));
            }
        };
        let len = match header.block_len() {
            Ok(len) => len,
            Err(error) => {
                self.rest = &[];
                return Some(Err(error));
            }
        };
        if self.rest.len() < len {
            let have = self.rest.len();
            self.rest = &[];
            return Some(Err(Error::Truncated { need: len, have }));
        }
        let Some(metadata) = self.rest.get(HEADER_LEN..len) else {
            self.rest = &[];
            return Some(Err(Error::Truncated {
                need: len,
                have: self.rest.len(),
            }));
        };
        let Some(rest) = self.rest.get(len..) else {
            self.rest = &[];
            return Some(Err(Error::Truncated {
                need: len,
                have: self.rest.len(),
            }));
        };
        self.rest = rest;
        Some(Ok(Block { header, metadata }))
    }
}

/// Stream-level facts, aggregated the way `wvunpack -ss` reports them.
/// This is the M0 conformance surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamInfo {
    pub version: u16,
    /// Stored bits per sample (bytes-per-sample times 8).
    pub bits_per_sample: u32,
    pub is_float: bool,
    /// Output channels, 1 or 2.
    pub channels: u32,
    pub sample_rate: u32,
    /// Total frames, when the first block declares them.
    pub total_samples: Option<u64>,
    pub lossless: bool,
    pub block_count: usize,
}

impl StreamInfo {
    /// Scan a whole stream: parse every block, walk every sub-block through
    /// the scope gate, and check block bookkeeping (contiguous frame indices,
    /// both initial and final flags set on each mono/stereo block, and a
    /// format that does not change after the first audio block).
    pub fn scan(stream: &[u8]) -> Result<Self, Error> {
        let mut info: Option<StreamInfo> = None;
        let mut expected_index: u64 = 0;
        let mut custom_rate: Option<u32> = None;

        for block in Blocks::new(stream) {
            let block = block?;
            let h = &block.header;
            for sub in block.sub_blocks() {
                let sub = sub?;
                check_scope(sub)?;
                if sub.id == meta::SAMPLE_RATE && sub.data.len() >= 3 {
                    let rate = sub
                        .data
                        .get(..3)
                        .and_then(|data| <[u8; 3]>::try_from(data).ok());
                    if let Some([low, middle, high]) = rate {
                        custom_rate = Some(
                            u32::from(low) | (u32::from(middle) << 8) | (u32::from(high) << 16),
                        );
                    }
                }
            }
            if h.block_samples == 0 {
                continue; // metadata-only block
            }
            if !(h.flags.initial_block() && h.flags.final_block()) {
                return Err(Error::OutOfScope(Scope::MultichannelSpanning));
            }
            if h.block_index != expected_index {
                return Err(Error::NonContiguousBlock {
                    expected: expected_index,
                    found: h.block_index,
                });
            }
            expected_index = expected_index
                .checked_add(u64::from(h.block_samples))
                .ok_or(Error::BadBlockSize(h.block_samples))?;

            let rate = h
                .flags
                .sample_rate()
                .or(custom_rate)
                .ok_or(Error::BadBlockSize(h.flags.sample_rate_index()))?;

            match &mut info {
                None => {
                    info = Some(StreamInfo {
                        version: h.version,
                        bits_per_sample: h.flags.bytes_per_sample() * 8,
                        is_float: h.flags.is_float(),
                        channels: h.flags.output_channels(),
                        sample_rate: rate,
                        total_samples: h.total_samples,
                        lossless: !h.flags.is_hybrid(),
                        block_count: 1,
                    });
                }
                Some(seen) => {
                    // The first audio block fixes the file's format.
                    let same = seen.bits_per_sample == h.flags.bytes_per_sample() * 8
                        && seen.is_float == h.flags.is_float()
                        && seen.sample_rate == rate
                        && seen.version == h.version;
                    if !same {
                        return Err(Error::FormatChanged);
                    }
                    seen.block_count += 1;
                }
            }
        }

        info.ok_or(Error::Truncated { need: 32, have: 0 })
    }
}
