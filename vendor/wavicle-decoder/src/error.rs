//! Errors for parsing and scope rejection.

use core::fmt;

/// Why a byte stream could not be accepted.
///
/// `OutOfScope` is a deliberate rejection of valid WavPack content wavicle
/// does not implement (DSD, hybrid, multichannel, legacy); everything else is
/// malformed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the structure requires.
    Truncated { need: usize, have: usize },
    /// Block did not begin with `wvpk`.
    BadMagic([u8; 4]),
    /// Stream version outside the accepted `0x402..=0x410` range.
    UnsupportedVersion(u16),
    /// Valid WavPack, deliberately unimplemented.
    OutOfScope(Scope),
    /// A block's `ckSize` disagrees with the bytes available or is malformed.
    BadBlockSize(u32),
    /// A metadata sub-block overran its block or has an impossible size.
    BadSubBlock { id: u8 },
    /// A required (0x00..=0x1f) metadata id this crate does not know.
    UnknownRequiredId(u8),
    /// A later audio block changed the format the first block fixed.
    FormatChanged,
    /// In scope for the crate, but not implemented at this milestone.
    NotYetImplemented(&'static str),
    /// The block's decoded samples do not match its stored CRC. The reference
    /// silently mutes such a block; wavicle makes it a hard error so a
    /// corrupt block can never silently alter decoded content.
    CrcMismatch { stored: u32, computed: u32 },
    /// A decoded sample exceeded the header's stated magnitude bound.
    OverMagnitude,
    /// A required metadata sub-block is missing from an audio block.
    MissingSubBlock(&'static str),
    /// Audio blocks are not contiguous (unexpected first frame index).
    NonContiguousBlock { expected: u64, found: u64 },
    /// An input-sized decoder allocation could not be reserved.
    AllocationFailed { elements: usize },
}

/// The out-of-scope families, so rejection reads as policy, not failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Dsd,
    Hybrid,
    CorrectionFile,
    MoreThanTwoChannels,
    /// A mono/stereo frame split across blocks implies >2 source channels.
    MultichannelSpanning,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated: need {need} bytes, have {have}")
            }
            Self::BadMagic(m) => write!(f, "not a WavPack block (magic {m:02x?})"),
            Self::UnsupportedVersion(v) => {
                write!(f, "stream version {v:#06x} outside supported 0x402..=0x410")
            }
            Self::OutOfScope(s) => write!(f, "valid WavPack, out of wavicle's scope: {s}"),
            Self::BadBlockSize(n) => write!(f, "implausible block size {n}"),
            Self::BadSubBlock { id } => write!(f, "malformed metadata sub-block (id {id:#04x})"),
            Self::UnknownRequiredId(id) => {
                write!(f, "unknown required metadata id {id:#04x}")
            }
            Self::FormatChanged => {
                f.write_str("audio format changed after the first block fixed it")
            }
            Self::NotYetImplemented(what) => write!(f, "not yet implemented: {what}"),
            Self::CrcMismatch { stored, computed } => {
                write!(
                    f,
                    "block CRC mismatch: stored {stored:#010x}, computed {computed:#010x}"
                )
            }
            Self::OverMagnitude => f.write_str("decoded sample exceeds stated magnitude"),
            Self::MissingSubBlock(what) => write!(f, "audio block missing {what}"),
            Self::NonContiguousBlock { expected, found } => {
                write!(
                    f,
                    "non-contiguous block: expected frame {expected}, found {found}"
                )
            }
            Self::AllocationFailed { elements } => {
                write!(f, "could not reserve {elements} decoder elements")
            }
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dsd => "DSD audio",
            Self::Hybrid => "hybrid/lossy mode",
            Self::CorrectionFile => "correction-file (.wvc) content",
            Self::MoreThanTwoChannels => "more than two channels",
            Self::MultichannelSpanning => "multichannel block spanning",
        })
    }
}

impl std::error::Error for Error {}
