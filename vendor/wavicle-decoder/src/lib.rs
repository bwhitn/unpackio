//! Decoder-only WavPack core vendored for unpackio.
//!
//! A wavicle is Eddington's word for the quantum entity that is both wave and
//! particle. A lossless codec makes audio exactly that: a continuous wave to
//! the ear, discrete bits on disk, one identity in both observations.
//!
//! Scope: lossless mono/stereo decoding of WavPack streams — 16/24/32-bit
//! integer and bit-exact 32-bit float PCM. Pure Rust, no C, wasm-capable. Out
//! of scope: DSD, hybrid/lossy modes, correction files, more than two channels,
//! pre-4.0 legacy streams, and encoding.
//!
//! The exact upstream decoder source, local maintenance patches, provenance,
//! and oracle method are recorded in `PATCHES.md` and the parent project's
//! `PROVENANCE.md`. No encoder module or compression API is included.

#![forbid(unsafe_code)]

pub mod block;
pub mod error;
pub mod format;
pub mod metadata;

// Decoder bit I/O, median model, and sample tables.
#[cfg(feature = "decode")]
pub mod bitstream;
#[cfg(feature = "decode")]
pub mod entropy;

#[cfg(feature = "decode")]
pub mod decorr;

#[cfg(feature = "decode")]
pub mod float;

#[cfg(feature = "decode")]
pub mod decode;

pub use block::{Block, BlockHeader, Blocks, StreamInfo};
#[cfg(feature = "decode")]
pub use decode::{DecodedStream, decode_stream};
pub use error::{Error, Scope};
