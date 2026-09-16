//! WavPack v5 stream constants: magic, versions, header flags, metadata ids.
//!
//! Values follow the reference `include/wavpack.h` and the WavPack 5 file
//! format document (2020-04-12). See PROVENANCE.md.

/// Block magic, ASCII `wvpk`.
pub const MAGIC: [u8; 4] = *b"wvpk";

/// Lowest stream version this crate decodes.
pub const MIN_STREAM_VERS: u16 = 0x402;
/// Highest stream version this decoder understands.
pub const MAX_STREAM_VERS: u16 = 0x410;

/// A block is bounded to 1 MB in the reference resynchronizer.
pub const MAX_BLOCK_SIZE: u32 = 1 << 20;
/// A block holds at most this many frames.
pub const MAX_BLOCK_SAMPLES: u32 = 131072;

/// Standard sample-rate table indexed by header bits 23..=26. Index 15 means
/// the true rate rides in an [`meta::SAMPLE_RATE`] sub-block instead.
pub const SAMPLE_RATES: [u32; 15] = [
    6000, 8000, 9600, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000,
    192000,
];

/// The header `flags` word, with typed accessors instead of scattered masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags(pub u32);

impl Flags {
    pub const HYBRID: u32 = 1 << 3;
    pub const JOINT_STEREO: u32 = 1 << 4;
    pub const CROSS_DECORR: u32 = 1 << 5;
    pub const HYBRID_SHAPE: u32 = 1 << 6;
    pub const FLOAT_DATA: u32 = 1 << 7;
    pub const INT32_DATA: u32 = 1 << 8;
    pub const HYBRID_BITRATE: u32 = 1 << 9;
    pub const HYBRID_BALANCE: u32 = 1 << 10;
    pub const INITIAL_BLOCK: u32 = 1 << 11;
    pub const FINAL_BLOCK: u32 = 1 << 12;
    pub const HAS_CHECKSUM: u32 = 1 << 28;
    pub const NEW_SHAPING: u32 = 1 << 29;
    pub const FALSE_STEREO: u32 = 1 << 30;
    pub const DSD: u32 = 1 << 31;

    /// Any hybrid-family bit: the whole mode is out of scope together.
    pub const ANY_HYBRID: u32 = Self::HYBRID
        | Self::HYBRID_SHAPE
        | Self::HYBRID_BITRATE
        | Self::HYBRID_BALANCE
        | Self::NEW_SHAPING;

    /// Stored bytes per sample, 1..=4.
    pub fn bytes_per_sample(self) -> u32 {
        (self.0 & 0x3) + 1
    }

    /// True when the stored stream is one channel.
    pub fn mono_stored(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Output channel count implied by this block (1 or 2). `FALSE_STEREO`
    /// stores mono but plays stereo, and the reference reports 2 channels.
    pub fn output_channels(self) -> u32 {
        if self.0 & Self::FALSE_STEREO != 0 {
            2
        } else if self.mono_stored() {
            1
        } else {
            2
        }
    }

    pub fn is_float(self) -> bool {
        self.0 & Self::FLOAT_DATA != 0
    }

    pub fn is_hybrid(self) -> bool {
        self.0 & Self::ANY_HYBRID != 0
    }

    pub fn is_dsd(self) -> bool {
        self.0 & Self::DSD != 0
    }

    /// Left-shift applied after decode, bits 13..=17.
    pub fn output_shift(self) -> u32 {
        (self.0 >> 13) & 0x1f
    }

    /// Max magnitude of decoded data minus one, bits 18..=22.
    pub fn magnitude(self) -> u32 {
        (self.0 >> 18) & 0x1f
    }

    /// Sample-rate index, bits 23..=26. `0xF` = non-standard rate.
    pub fn sample_rate_index(self) -> u32 {
        (self.0 >> 23) & 0xf
    }

    /// The standard rate for this block, or `None` when index is `0xF`.
    pub fn sample_rate(self) -> Option<u32> {
        SAMPLE_RATES
            .get(usize::try_from(self.sample_rate_index()).ok()?)
            .copied()
    }

    pub fn initial_block(self) -> bool {
        self.0 & Self::INITIAL_BLOCK != 0
    }

    pub fn final_block(self) -> bool {
        self.0 & Self::FINAL_BLOCK != 0
    }
}

/// Metadata sub-block function ids (`id & ID_MASK`), and the framing bits that
/// share the id byte.
pub mod meta {
    /// Function id mask. Ids `0x21..=0x3f` carry [`OPTIONAL`] and may be
    /// skipped when unknown; ids `0x00..=0x1f` must be understood.
    pub const ID_MASK: u8 = 0x3f;
    /// Set on ids a decoder may skip when it does not know them.
    pub const OPTIONAL: u8 = 0x20;
    /// True byte length is one less than `words * 2`.
    pub const ODD_SIZE: u8 = 0x40;
    /// Size field is three bytes instead of one.
    pub const LARGE: u8 = 0x80;

    pub const DUMMY: u8 = 0x00;
    pub const ENCODER_INFO: u8 = 0x01;
    pub const DECORR_TERMS: u8 = 0x02;
    pub const DECORR_WEIGHTS: u8 = 0x03;
    pub const DECORR_SAMPLES: u8 = 0x04;
    pub const ENTROPY_VARS: u8 = 0x05;
    pub const HYBRID_PROFILE: u8 = 0x06;
    pub const SHAPING_WEIGHTS: u8 = 0x07;
    pub const FLOAT_INFO: u8 = 0x08;
    pub const INT32_INFO: u8 = 0x09;
    pub const WV_BITSTREAM: u8 = 0x0a;
    pub const WVC_BITSTREAM: u8 = 0x0b;
    pub const WVX_BITSTREAM: u8 = 0x0c;
    pub const CHANNEL_INFO: u8 = 0x0d;
    pub const DSD_BLOCK: u8 = 0x0e;

    pub const RIFF_HEADER: u8 = 0x21;
    pub const RIFF_TRAILER: u8 = 0x22;
    pub const ALT_HEADER: u8 = 0x23;
    pub const ALT_TRAILER: u8 = 0x24;
    pub const CONFIG_BLOCK: u8 = 0x25;
    pub const MD5_CHECKSUM: u8 = 0x26;
    pub const SAMPLE_RATE: u8 = 0x27;
    pub const ALT_EXTENSION: u8 = 0x28;
    pub const ALT_MD5_CHECKSUM: u8 = 0x29;
    pub const NEW_CONFIG_BLOCK: u8 = 0x2a;
    pub const CHANNEL_IDENTITIES: u8 = 0x2b;
    /// The wvx extension bitstream in its v5 "new" form: same payload as
    /// [`WVX_BITSTREAM`] but prefixed (inside the bitstream) with 5-bit
    /// width/shift fields. `ID_OPTIONAL_DATA | ID_WVX_BITSTREAM`.
    pub const WVX_NEW_BITSTREAM: u8 = 0x2c;
    pub const BLOCK_CHECKSUM: u8 = 0x2f;
}
