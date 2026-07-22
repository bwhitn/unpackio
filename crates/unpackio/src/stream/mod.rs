//! Standalone LZ4, Zstandard, and Unix `compress` stream sessions.
//!
//! These formats contain one logical output byte stream rather than named
//! archive members. Opening validates their bounded structural layout without
//! decoding. [`CompressedStream::extract_to`] sends bounded chunks only to a
//! caller-selected writer and returns success after every applicable frame
//! checksum has been verified.

use std::{
    cell::Cell,
    fmt,
    io::{self, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use crate::{
    CancellationToken, Error, LimitKind, Limits, Result, WorkBudget,
    parse_util::{CONTROL_CHUNK_SIZE, ParseControl, check_limit, usize_to_u64},
    volume::{PathVolumeProvider, read_single_volume},
};

mod cursor;
mod lz4;
mod unix_compress;
mod zstandard;

use lz4::Lz4Layout;
use unix_compress::UnixCompressLayout;
use zstandard::ZstandardLayout;

const LZ4_MAGIC: u32 = 0x184d_2204;
const LZ4_LEGACY_MAGIC: u32 = 0x184c_2102;
const SKIPPABLE_MAGIC_START: u32 = 0x184d_2a50;
const SKIPPABLE_MAGIC_END: u32 = 0x184d_2a5f;
const ZSTANDARD_MAGIC: u32 = 0xfd2f_b528;
const UNIX_COMPRESS_MAGIC: &[u8] = &[0x1f, 0x9d];

/// A supported standalone compression format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamFormat {
    /// LZ4 frame format, including legacy data frames.
    Lz4,
    /// Zstandard frame format.
    Zstandard,
    /// Unix `compress` `.Z` using variable-width LZW.
    UnixCompress,
}

impl StreamFormat {
    /// Returns the stable lowercase format name used in errors and FFI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lz4 => "lz4",
            Self::Zstandard => "zstandard",
            Self::UnixCompress => "unix-compress",
        }
    }
}

impl fmt::Display for StreamFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Validated aggregate metadata for LZ4 frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lz4StreamInfo {
    frame_count: u64,
    skippable_frame_count: u64,
    legacy_frame_count: u64,
    content_checksum_frame_count: u64,
    block_checksum_frame_count: u64,
    dictionary_frame_count: u64,
    maximum_block_bytes: u64,
}

impl Lz4StreamInfo {
    /// Returns the number of data frames.
    #[must_use]
    pub const fn frame_count(self) -> u64 {
        self.frame_count
    }

    /// Returns the number of bounded metadata frames skipped during decoding.
    #[must_use]
    pub const fn skippable_frame_count(self) -> u64 {
        self.skippable_frame_count
    }

    /// Returns the number of legacy LZ4 frames.
    #[must_use]
    pub const fn legacy_frame_count(self) -> u64 {
        self.legacy_frame_count
    }

    /// Returns the number of frames carrying a decoded-content checksum.
    #[must_use]
    pub const fn content_checksum_frame_count(self) -> u64 {
        self.content_checksum_frame_count
    }

    /// Returns the number of frames carrying per-block checksums.
    #[must_use]
    pub const fn block_checksum_frame_count(self) -> u64 {
        self.block_checksum_frame_count
    }

    /// Returns the number of frames declaring an external dictionary ID.
    #[must_use]
    pub const fn dictionary_frame_count(self) -> u64 {
        self.dictionary_frame_count
    }

    /// Returns the largest declared uncompressed block size.
    #[must_use]
    pub const fn maximum_block_bytes(self) -> u64 {
        self.maximum_block_bytes
    }
}

/// Validated aggregate metadata for Zstandard frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZstandardStreamInfo {
    frame_count: u64,
    skippable_frame_count: u64,
    content_checksum_frame_count: u64,
    dictionary_frame_count: u64,
    maximum_window_bytes: u64,
}

impl ZstandardStreamInfo {
    /// Returns the number of data frames.
    #[must_use]
    pub const fn frame_count(self) -> u64 {
        self.frame_count
    }

    /// Returns the number of bounded metadata frames skipped during decoding.
    #[must_use]
    pub const fn skippable_frame_count(self) -> u64 {
        self.skippable_frame_count
    }

    /// Returns the number of frames carrying a content checksum.
    #[must_use]
    pub const fn content_checksum_frame_count(self) -> u64 {
        self.content_checksum_frame_count
    }

    /// Returns the number of frames requiring a nonzero dictionary ID.
    #[must_use]
    pub const fn dictionary_frame_count(self) -> u64 {
        self.dictionary_frame_count
    }

    /// Returns the largest declared decoder window.
    #[must_use]
    pub const fn maximum_window_bytes(self) -> u64 {
        self.maximum_window_bytes
    }
}

/// Validated header metadata for a Unix `compress` stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixCompressStreamInfo {
    maximum_code_bits: u8,
    block_mode: bool,
    dictionary_bytes: u64,
}

impl UnixCompressStreamInfo {
    /// Returns the maximum encoded LZW code width.
    #[must_use]
    pub const fn maximum_code_bits(self) -> u8 {
        self.maximum_code_bits
    }

    /// Returns whether CLEAR-code block mode is enabled.
    #[must_use]
    pub const fn block_mode(self) -> bool {
        self.block_mode
    }

    /// Returns the decoder dictionary and expansion-stack bytes accounted
    /// before allocation.
    #[must_use]
    pub const fn dictionary_bytes(self) -> u64 {
        self.dictionary_bytes
    }
}

/// Format-specific standalone stream metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamInfoKind {
    /// LZ4 frame metadata.
    Lz4(Lz4StreamInfo),
    /// Zstandard frame metadata.
    Zstandard(ZstandardStreamInfo),
    /// Unix `compress` header metadata.
    UnixCompress(UnixCompressStreamInfo),
}

/// Validated metadata for one standalone compressed input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamInfo {
    format: StreamFormat,
    compressed_size: u64,
    uncompressed_size: Option<u64>,
    kind: StreamInfoKind,
}

impl StreamInfo {
    /// Returns the detected or caller-selected format.
    #[must_use]
    pub const fn format(self) -> StreamFormat {
        self.format
    }

    /// Returns the complete compressed input length.
    #[must_use]
    pub const fn compressed_size(self) -> u64 {
        self.compressed_size
    }

    /// Returns the aggregate decoded size only when every data frame declares
    /// one. Unix `compress` never declares it.
    #[must_use]
    pub const fn uncompressed_size(self) -> Option<u64> {
        self.uncompressed_size
    }

    /// Returns concrete format-specific metadata.
    #[must_use]
    pub const fn kind(self) -> StreamInfoKind {
        self.kind
    }
}

/// Verified extraction totals returned only after decoder finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamExtraction {
    output_bytes: u64,
    frames_decoded: u64,
    checksums_verified: u64,
}

impl StreamExtraction {
    /// Returns the bytes accepted by the caller-owned writer.
    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    /// Returns the number of decoded data frames.
    #[must_use]
    pub const fn frames_decoded(self) -> u64 {
        self.frames_decoded
    }

    /// Returns the number of data frames whose optional block/content checksum
    /// set was successfully verified. A frame with both block and content
    /// checksums contributes one; mandatory LZ4 descriptor checksums are
    /// validated while opening and are not counted here.
    #[must_use]
    pub const fn checksums_verified(self) -> u64 {
        self.checksums_verified
    }
}

enum StreamLayout {
    Lz4(Lz4Layout),
    Zstandard(ZstandardLayout),
    UnixCompress(UnixCompressLayout),
}

/// An owned, validated standalone compressed stream.
///
/// The input is retained so all validated frame ranges remain stable. No
/// filename is stored in these formats, and this type never derives or opens
/// an output path.
pub struct CompressedStream {
    bytes: Box<[u8]>,
    info: StreamInfo,
    layout: StreamLayout,
    limits: Limits,
}

impl CompressedStream {
    /// Detects and validates an in-memory LZ4, Zstandard, or Unix `compress`
    /// stream.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, limit, cancellation, or I/O error.
    /// A leading sequence containing only skippable frames is ambiguous and is
    /// rejected; use [`Self::open_bytes_as`] when an explicit format is known.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(bytes, None, limits, cancellation, budget)
    }

    /// Validates an in-memory stream as exactly the selected format.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the structure does not match `format` or a
    /// configured limit, work budget, or cancellation request is reached.
    pub fn open_bytes_as(
        bytes: Vec<u8>,
        format: StreamFormat,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(bytes, Some(format), limits, cancellation, budget)
    }

    /// Opens and auto-detects one bounded path-backed compressed stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for path reads or the same validation errors as
    /// [`Self::open_bytes`].
    pub fn open_path(
        path: &Path,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_path_inner(path, None, limits, cancellation, budget)
    }

    /// Opens one bounded path-backed stream as exactly `format`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for path reads or the same validation errors as
    /// [`Self::open_bytes_as`].
    pub fn open_path_as(
        path: &Path,
        format: StreamFormat,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_path_inner(path, Some(format), limits, cancellation, budget)
    }

    fn open_path_inner(
        path: &Path,
        format: Option<StreamFormat>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let expected_name = path.to_string_lossy();
        let mut provider = PathVolumeProvider::new(path.to_path_buf());
        let bytes = {
            let mut control = ParseControl::new(cancellation, budget);
            read_single_volume(&mut provider, &expected_name, limits, &mut control)?
        };
        Self::open_bytes_inner(bytes, format, limits, cancellation, budget)
    }

    fn open_bytes_inner(
        bytes: Vec<u8>,
        requested_format: Option<StreamFormat>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let compressed_size = usize_to_u64(
            bytes.len(),
            "compressed stream length is not representable as u64",
        )?;
        check_limit(
            compressed_size,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        {
            let mut control = ParseControl::new(cancellation, budget);
            control.consume_bytes(&bytes)?;
        }
        let format = match requested_format {
            Some(format) => format,
            None => detect_format(&bytes)?,
        };
        let (kind, uncompressed_size, layout) = match format {
            StreamFormat::Lz4 => {
                let (info, size, layout) = lz4::parse(&bytes, limits)?;
                (StreamInfoKind::Lz4(info), size, StreamLayout::Lz4(layout))
            }
            StreamFormat::Zstandard => {
                let (info, size, layout) = zstandard::parse(&bytes, limits)?;
                (
                    StreamInfoKind::Zstandard(info),
                    size,
                    StreamLayout::Zstandard(layout),
                )
            }
            StreamFormat::UnixCompress => {
                let (info, layout) = unix_compress::parse(&bytes, limits)?;
                (
                    StreamInfoKind::UnixCompress(info),
                    None,
                    StreamLayout::UnixCompress(layout),
                )
            }
        };
        if let Some(size) = uncompressed_size {
            check_limit(
                size,
                limits.max_entry_output_bytes(),
                LimitKind::EntryOutputBytes,
            )?;
            check_limit(
                size,
                limits.max_total_output_bytes(),
                LimitKind::TotalOutputBytes,
            )?;
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            info: StreamInfo {
                format,
                compressed_size,
                uncompressed_size,
                kind,
            },
            layout,
            limits,
        })
    }

    /// Returns validated metadata without decoding the content.
    #[must_use]
    pub const fn info(&self) -> StreamInfo {
        self.info
    }

    /// Returns the limits retained by this stream session.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns the owned compressed input bytes, excluding allocator metadata
    /// and the small validated frame table.
    #[must_use]
    pub const fn retained_input_bytes(&self) -> u64 {
        self.info.compressed_size
    }

    /// Decompresses into a caller-selected writer in bounded chunks.
    ///
    /// A writer can observe bytes before a trailing checksum is known. `Ok` is
    /// returned only after every applicable checksum and declared size has
    /// been verified. Callers needing atomic trusted output should stage it and
    /// commit only after this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, unsupported-feature, limit,
    /// cancellation, work-budget, or writer I/O error.
    pub fn extract_to<W: Write>(
        &self,
        writer: &mut W,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<StreamExtraction> {
        let mut control = ExtractionControl::new(writer, cancellation, budget, self.limits);
        match &self.layout {
            StreamLayout::Lz4(layout) => layout.extract(&self.bytes, &mut control)?,
            StreamLayout::Zstandard(layout) => layout.extract(&self.bytes, &mut control)?,
            StreamLayout::UnixCompress(layout) => layout.extract(&self.bytes, &mut control)?,
        }
        if self
            .info
            .uncompressed_size
            .is_some_and(|expected| expected != control.output_bytes)
        {
            return Err(stream_format_error(
                self.info.format.as_str(),
                "decoded size does not match the declared aggregate size",
            ));
        }
        Ok(control.finish())
    }

    /// Decompresses into a fallibly growing memory buffer.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::extract_to`], including an I/O error
    /// when the output allocation cannot be reserved.
    pub fn decompress(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Vec<u8>> {
        let mut writer = FallibleVec::new(self.info.uncompressed_size)?;
        self.extract_to(&mut writer, cancellation, budget)?;
        Ok(writer.bytes)
    }

    /// Fully decodes and verifies the stream while discarding its output.
    ///
    /// # Errors
    ///
    /// Returns the same validation, checksum, resource, or cancellation errors
    /// as [`Self::extract_to`].
    pub fn verify(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<StreamExtraction> {
        self.extract_to(&mut io::sink(), cancellation, budget)
    }
}

fn detect_format(bytes: &[u8]) -> Result<StreamFormat> {
    if bytes.get(..UNIX_COMPRESS_MAGIC.len()) == Some(UNIX_COMPRESS_MAGIC) {
        return Ok(StreamFormat::UnixCompress);
    }
    let mut position = 0_usize;
    loop {
        let magic_end = position
            .checked_add(4)
            .ok_or_else(|| stream_format_error("compressed", "magic range overflows"))?;
        let magic_bytes = bytes
            .get(position..magic_end)
            .ok_or_else(|| stream_format_error("compressed", "input has no supported magic"))?;
        let magic = u32::from_le_bytes(
            <[u8; 4]>::try_from(magic_bytes)
                .map_err(|_| stream_format_error("compressed", "magic is truncated"))?,
        );
        match magic {
            LZ4_MAGIC | LZ4_LEGACY_MAGIC => return Ok(StreamFormat::Lz4),
            ZSTANDARD_MAGIC => return Ok(StreamFormat::Zstandard),
            SKIPPABLE_MAGIC_START..=SKIPPABLE_MAGIC_END => {
                let size_start = magic_end;
                let size_end = size_start.checked_add(4).ok_or_else(|| {
                    stream_format_error("compressed", "skippable frame header overflows")
                })?;
                let size_bytes = bytes.get(size_start..size_end).ok_or_else(|| {
                    stream_format_error("compressed", "skippable frame header is truncated")
                })?;
                let size = u32::from_le_bytes(<[u8; 4]>::try_from(size_bytes).map_err(|_| {
                    stream_format_error("compressed", "skippable frame size is truncated")
                })?);
                let size = usize::try_from(size).map_err(|_| {
                    stream_format_error("compressed", "skippable frame size is not representable")
                })?;
                position = size_end.checked_add(size).ok_or_else(|| {
                    stream_format_error("compressed", "skippable frame range overflows")
                })?;
                if position > bytes.len() {
                    return Err(stream_format_error(
                        "compressed",
                        "skippable frame payload is truncated",
                    ));
                }
            }
            _ => {
                return Err(stream_format_error(
                    "compressed",
                    "input has no supported magic",
                ));
            }
        }
    }
}

pub(super) fn stream_format_error(format: &'static str, detail: &'static str) -> Error {
    Error::StreamFormat {
        format: String::from(format),
        detail: String::from(detail),
    }
}

pub(super) fn stream_checksum_error(format: &'static str, frame_index: u64) -> Error {
    Error::StreamChecksum {
        format: String::from(format),
        frame_index,
    }
}

pub(super) fn unsupported_stream_feature(format: &'static str, feature: &'static str) -> Error {
    Error::UnsupportedStreamFeature {
        format: String::from(format),
        feature: String::from(feature),
    }
}

pub(super) fn check_frame_count(count: u64, limits: Limits) -> Result<()> {
    check_limit(count, limits.max_stream_frames(), LimitKind::StreamFrames)
}

pub(super) fn push_layout<T>(values: &mut Vec<T>, value: T) -> Result<()> {
    values.try_reserve(1).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "compressed stream layout allocation failed",
        ))
    })?;
    values.push(value);
    Ok(())
}

struct ControlledInput<'input> {
    bytes: &'input [u8],
    position: usize,
    consumed: &'input Cell<usize>,
    cancellation: CancellationToken,
}

impl<'input> ControlledInput<'input> {
    fn new(
        bytes: &'input [u8],
        consumed: &'input Cell<usize>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            bytes,
            position: 0,
            consumed,
            cancellation,
        }
    }
}

impl Read for ControlledInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.cancellation.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "stream operation cancelled")
        })?;
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.bytes.get(self.position..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder input position is invalid",
            )
        })?;
        if remaining.is_empty() {
            return Ok(0);
        }
        let count = remaining.len().min(output.len()).min(CONTROL_CHUNK_SIZE);
        let source = remaining.get(..count).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "decoder input range is invalid")
        })?;
        let destination = output.get_mut(..count).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder output range is invalid",
            )
        })?;
        destination.copy_from_slice(source);
        self.position = self.position.checked_add(count).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder input position overflows",
            )
        })?;
        self.consumed.set(self.position);
        Ok(count)
    }
}

pub(super) struct ExtractionControl<'control, W: Write> {
    writer: &'control mut W,
    cancellation: &'control CancellationToken,
    budget: &'control mut WorkBudget,
    limits: Limits,
    output_bytes: u64,
    frames_decoded: u64,
    checksums_verified: u64,
}

impl<'control, W: Write> ExtractionControl<'control, W> {
    fn new(
        writer: &'control mut W,
        cancellation: &'control CancellationToken,
        budget: &'control mut WorkBudget,
        limits: Limits,
    ) -> Self {
        Self {
            writer,
            cancellation,
            budget,
            limits,
            output_bytes: 0,
            frames_decoded: 0,
            checksums_verified: 0,
        }
    }

    pub(super) fn checkpoint(&mut self, work: u64) -> Result<()> {
        self.cancellation.check()?;
        self.budget.charge(work)
    }

    pub(super) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(super) const fn limits(&self) -> Limits {
        self.limits
    }

    pub(super) fn write_output(&mut self, bytes: &[u8]) -> Result<()> {
        self.cancellation.check()?;
        let additional = usize_to_u64(
            bytes.len(),
            "stream output chunk length is not representable as u64",
        )?;
        let next = self
            .output_bytes
            .checked_add(additional)
            .ok_or_else(|| stream_format_error("compressed", "output size overflows"))?;
        check_limit(
            next,
            self.limits.max_entry_output_bytes(),
            LimitKind::EntryOutputBytes,
        )?;
        check_limit(
            next,
            self.limits.max_total_output_bytes(),
            LimitKind::TotalOutputBytes,
        )?;
        self.writer.write_all(bytes).map_err(Error::Io)?;
        self.output_bytes = next;
        Ok(())
    }

    pub(super) fn finish_frame(&mut self, checksum_verified: bool) -> Result<()> {
        self.frames_decoded = self
            .frames_decoded
            .checked_add(1)
            .ok_or_else(|| stream_format_error("compressed", "decoded frame count overflows"))?;
        if checksum_verified {
            self.checksums_verified = self.checksums_verified.checked_add(1).ok_or_else(|| {
                stream_format_error("compressed", "verified checksum count overflows")
            })?;
        }
        Ok(())
    }

    fn finish(self) -> StreamExtraction {
        StreamExtraction {
            output_bytes: self.output_bytes,
            frames_decoded: self.frames_decoded,
            checksums_verified: self.checksums_verified,
        }
    }
}

pub(super) fn pump_reader<R: Read, W: Write, IsChecksum>(
    reader: &mut R,
    consumed: &Cell<usize>,
    expected: Option<u64>,
    format: &'static str,
    frame_index: u64,
    control: &mut ExtractionControl<'_, W>,
    is_checksum_error: IsChecksum,
) -> Result<()>
where
    IsChecksum: Fn(&io::Error) -> bool,
{
    let start_output = control.output_bytes;
    let mut charged_input = 0_usize;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    loop {
        control.checkpoint(0)?;
        let result = catch_unwind(AssertUnwindSafe(|| reader.read(&mut buffer)));
        let read = match result {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                if control.cancellation.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                if is_checksum_error(&error) {
                    return Err(stream_checksum_error(format, frame_index));
                }
                return Err(stream_format_error(
                    format,
                    "decoder rejected or truncated frame",
                ));
            }
            Err(_) => {
                return Err(stream_format_error(format, "decoder panicked on its frame"));
            }
        };
        let input_position = consumed.get();
        let input_delta = input_position
            .checked_sub(charged_input)
            .ok_or_else(|| stream_format_error(format, "decoder input accounting underflows"))?;
        charged_input = input_position;
        let work = input_delta
            .checked_add(read)
            .and_then(|units| units.checked_add(1))
            .ok_or_else(|| stream_format_error(format, "decoder work accounting overflows"))?;
        control.checkpoint(usize_to_u64(
            work,
            "decoder work is not representable as u64",
        )?)?;
        if read == 0 {
            break;
        }
        let output = buffer.get(..read).ok_or_else(|| {
            stream_format_error(format, "decoder returned an invalid output length")
        })?;
        control.write_output(output)?;
        if let Some(expected) = expected {
            let frame_output = control
                .output_bytes
                .checked_sub(start_output)
                .ok_or_else(|| stream_format_error(format, "frame output accounting underflows"))?;
            if frame_output > expected {
                return Err(stream_format_error(
                    format,
                    "decoded frame exceeds its declared content size",
                ));
            }
        }
    }
    let actual = control
        .output_bytes
        .checked_sub(start_output)
        .ok_or_else(|| stream_format_error(format, "frame output accounting underflows"))?;
    if expected.is_some_and(|expected| expected != actual) {
        return Err(stream_format_error(
            format,
            "decoded frame size does not match its declaration",
        ));
    }
    if consumed.get() != charged_input {
        return Err(stream_format_error(
            format,
            "decoder input accounting is incomplete",
        ));
    }
    Ok(())
}

struct FallibleVec {
    bytes: Vec<u8>,
}

impl FallibleVec {
    fn new(expected: Option<u64>) -> Result<Self> {
        let capacity = expected.unwrap_or(0).min(1024 * 1024);
        let capacity = usize::try_from(capacity).map_err(|_| {
            stream_format_error("compressed", "output capacity is not representable")
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "stream output allocation failed",
            ))
        })?;
        Ok(Self { bytes })
    }
}

impl Write for FallibleVec {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.try_reserve(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "stream output allocation failed",
            )
        })?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
