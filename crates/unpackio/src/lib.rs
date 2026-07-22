#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
//! A security-focused, unpack-only archive and compressed-stream reader.
//!
//! The stable surface owns archive or standalone-stream input, exposes concrete
//! metadata, and sends decoded bytes only to caller-selected memory or output
//! sinks. It never creates, edits, or automatically extracts paths. See
//! [`Archive`] for 7z opening and listing, [`MemberReader`] for bounded member
//! reads with explicit checksum finalization, [`CompressedStream`] for LZ4,
//! Zstandard, and Unix `.Z`, [`ZipArchive`] for ZIP, [`RpmArchive`] for RPM,
//! [`CpioArchive`] for standalone CPIO, [`DebArchive`] for Debian packages,
//! [`ArjArchive`] for ARJ, and [`Limits`] for attacker-controlled resource
//! bounds.
//!
//! Low-level parser and coder-graph types are intentionally not part of this
//! API. The hidden `unstable-internals` feature exists only for this
//! repository's structural regression tests and fuzz harnesses and carries no
//! compatibility guarantee.
//!
//! # Opening and listing
//!
//! ```no_run
//! use std::path::Path;
//! use unpackio::{Archive, CancellationToken, Limits, WorkBudget};
//!
//! # fn main() -> unpackio::Result<()> {
//! let cancellation = CancellationToken::new();
//! let mut budget = WorkBudget::bounded(100_000_000);
//! let archive = Archive::open_path(
//!     Path::new("archive.7z"),
//!     Limits::default(),
//!     &cancellation,
//!     &mut budget,
//! )?;
//! for entry in archive.entries() {
//!     println!("{:?} {:?}", entry.kind(), entry.name_lossy());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! A raw name is metadata, not an extraction destination. Validate it with
//! [`validate_safe_utf16_path`] before applying a separately defined
//! filesystem policy. Even after the last [`MemberReader::read_chunk`] returns
//! zero, call [`MemberReader::finish`] before treating streamed bytes as
//! verified.
//!
//! # Standalone compressed streams
//!
//! ```no_run
//! use std::{io, path::Path};
//! use unpackio::{CancellationToken, CompressedStream, Limits, WorkBudget};
//!
//! # fn main() -> unpackio::Result<()> {
//! let cancellation = CancellationToken::new();
//! let mut open_budget = WorkBudget::bounded(100_000_000);
//! let stream = CompressedStream::open_path(
//!     Path::new("payload.zst"),
//!     Limits::default(),
//!     &cancellation,
//!     &mut open_budget,
//! )?;
//! println!("{} {:?}", stream.info().format(), stream.info().uncompressed_size());
//! let mut decode_budget = WorkBudget::bounded(100_000_000);
//! stream.extract_to(&mut io::sink(), &cancellation, &mut decode_budget)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Concrete non-7z containers
//!
//! ```no_run
//! use std::{io, path::Path};
//! use unpackio::{CancellationToken, Limits, RpmArchive, WorkBudget, ZipArchive};
//!
//! # fn main() -> unpackio::Result<()> {
//! let cancellation = CancellationToken::new();
//! let mut budget = WorkBudget::bounded(100_000_000);
//! let zip = ZipArchive::open_path(
//!     Path::new("archive.zip"),
//!     Limits::default(),
//!     &cancellation,
//!     &mut budget,
//! )?;
//! zip.extract_entry_to(0, &mut io::sink(), &cancellation, &mut budget)?;
//!
//! let rpm = RpmArchive::open_path(
//!     Path::new("package.rpm"),
//!     Limits::default(),
//!     &cancellation,
//!     &mut budget,
//! )?;
//! println!("{:?}", rpm.payload_compression());
//! # Ok(())
//! # }
//! ```

mod archive;
mod arj;
mod bounded;
mod cancel;
mod checksum;
mod coder_properties;
mod cpio;
mod deb;
mod decode;
mod error;
mod execute;
mod graph;
mod limits;
mod metadata;
mod model;
mod parse_util;
mod parser;
mod password;
mod path;
mod raw;
mod rpm;
mod stream;
mod validate;
mod volume;
mod zip;

pub use archive::{Archive, ArchiveResources, EntrySink, MemberReader};
pub use arj::{ArjArchive, ArjCompressionMethod, ArjEntry, ArjEntryKind, ArjEntrySink};
pub use cancel::{CancellationToken, WorkBudget};
pub use cpio::{CpioArchive, CpioEntry, CpioEntrySink, CpioFormat};
pub use deb::{
    DebArchive, DebCompression, DebEntry, DebEntryKind, DebEntrySink, DebMember, DebMemberKind,
    DebSection,
};
pub use error::{ChecksumScope, Error, ErrorKind, LimitKind};
pub use limits::{Limits, LimitsBuilder};
#[cfg(feature = "unstable-internals")]
#[doc(hidden)]
pub use model::{
    ArchiveHeader, ArchiveVersion, BindPair, Coder, ExternalProperty, FileStream, FilesInfo,
    Folder, HeaderEnvelope, NextHeaderKind, PackStream, ParsedArchive, ParsedNextHeader,
    PendingExternalFolderHeader, StoredProperty, StreamsInfo, Substream,
};
pub use model::{EntryKind, FileEntry};
#[cfg(feature = "unstable-internals")]
#[doc(hidden)]
pub use parser::{parse_archive, parse_archive_header};
pub use path::{UnsafePathReason, validate_safe_path, validate_safe_utf16_path};
pub use rpm::{
    RpmArchive, RpmEntry, RpmEntrySink, RpmHeader, RpmHeaderEntry, RpmLead, RpmPayloadCompression,
    RpmValue,
};
pub use stream::{
    CompressedStream, Lz4StreamInfo, StreamExtraction, StreamFormat, StreamInfo, StreamInfoKind,
    UnixCompressStreamInfo, ZstandardStreamInfo,
};
pub use volume::{MemoryVolumeProvider, PathVolumeProvider, Volume, VolumeProvider, VolumeRequest};
pub use zip::{
    ZipArchive, ZipCompressionMethod, ZipEncryption, ZipEntry, ZipEntrySink, ZipTimestamp,
};

/// The result type returned by the core library.
pub type Result<T> = std::result::Result<T, Error>;

/// A machine-readable statement of the current implementation boundary.
pub const IMPLEMENTATION_STATUS: &str = "multi-format-unpack-readers-pre-alpha";
