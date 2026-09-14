//! Bounded decoder implementations and folder execution.

mod aes;
mod codecs;
mod deflate64;
mod filters;
mod lzma;
mod phase5_filters;
mod ppmd;
mod ppmd_i;
mod xz;

pub(crate) use aes::decode_aes;
pub(crate) use codecs::{
    ControlledInput, decode_brotli, decode_bzip2, decode_deflate, decode_lz4, decode_reader,
    decode_zstd,
};
pub(crate) use deflate64::decode_deflate64;
pub(crate) use filters::{decode_bcj2, decode_filter, decode_filter_in_place};
pub(crate) use lzma::{decode_lzma, decode_lzma2};
pub(crate) use ppmd::decode_ppmd;
pub(crate) use ppmd_i::decode_zip_ppmd;
#[cfg(test)]
pub(crate) use ppmd_i::encode_zip_ppmd_fixture_for_test;
pub(crate) use xz::{XzProfile, decode_xz};

/// 7z Copy method identifier.
pub(crate) const METHOD_COPY: &[u8] = &[0x00];
/// 7z Delta filter identifier.
pub(crate) const METHOD_DELTA: &[u8] = &[0x03];
/// 7z LZMA method identifier.
pub(crate) const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
/// 7z x86 BCJ filter identifier.
pub(crate) const METHOD_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
/// 7z x86 BCJ2 filter identifier.
pub(crate) const METHOD_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1b];
/// 7z PowerPC filter identifier.
pub(crate) const METHOD_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
/// 7z ARM filter identifier.
pub(crate) const METHOD_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
/// 7z SPARC filter identifier.
pub(crate) const METHOD_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
/// 7z ARM64 filter identifier.
pub(crate) const METHOD_ARM64: &[u8] = &[0x0a];
/// 7z LZMA2 method identifier.
pub(crate) const METHOD_LZMA2: &[u8] = &[0x21];
/// 7z PPMd method identifier.
pub(crate) const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
/// 7z Deflate method identifier.
pub(crate) const METHOD_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
/// 7z Deflate64 method identifier.
pub(crate) const METHOD_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
/// 7z BZip2 method identifier.
pub(crate) const METHOD_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
/// Private 7z Zstandard method identifier.
pub(crate) const METHOD_ZSTD: &[u8] = &[0x04, 0xf7, 0x11, 0x01];
/// Private 7z Brotli method identifier.
pub(crate) const METHOD_BROTLI: &[u8] = &[0x04, 0xf7, 0x11, 0x02];
/// Private 7z LZ4 method identifier.
pub(crate) const METHOD_LZ4: &[u8] = &[0x04, 0xf7, 0x11, 0x04];
/// 7z AES-256-CBC method identifier.
pub(crate) const METHOD_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
/// 7z IA-64 branch filter identifier.
pub(crate) const METHOD_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
/// 7z ARM Thumb branch filter identifier.
pub(crate) const METHOD_ARM_THUMB: &[u8] = &[0x03, 0x03, 0x07, 0x01];
/// 7z RISC-V branch filter identifier.
pub(crate) const METHOD_RISCV: &[u8] = &[0x0b];
/// 7z two-byte swap filter identifier.
pub(crate) const METHOD_SWAP2: &[u8] = &[0x02, 0x03, 0x02];
/// 7z four-byte swap filter identifier.
pub(crate) const METHOD_SWAP4: &[u8] = &[0x02, 0x03, 0x04];
