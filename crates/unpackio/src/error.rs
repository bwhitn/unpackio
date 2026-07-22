//! Typed failures exposed by archive-processing APIs.
//!
//! Match [`Error::kind`] when a payload-free, forward-compatible category is
//! sufficient. Direct matches on [`Error`] must retain a wildcard arm because
//! the enum is non-exhaustive. Integrity failures are never success: a writer
//! or callback may already have observed bytes when a later checksum fails, so
//! callers that need atomic trusted output should write to a temporary
//! destination and commit it only after the operation returns `Ok`.

use std::{fmt, io};

/// A stable, payload-free classification suitable for an eventual FFI layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input does not conform to its selected compressed format.
    Format,
    /// A required checksum did not match.
    Checksum,
    /// The archive uses an unknown or unavailable method identifier.
    UnsupportedMethod,
    /// The archive uses a valid feature that this implementation lacks.
    UnsupportedFeature,
    /// A configured resource limit was exceeded.
    LimitExceeded,
    /// A required archive volume could not be obtained.
    MissingVolume,
    /// Encrypted content was encountered without a password.
    PasswordRequired,
    /// Authentication is unavailable in 7z, so corruption and a wrong password
    /// cannot always be distinguished.
    WrongPasswordOrCorrupt,
    /// The caller cancelled the operation.
    Cancelled,
    /// An input or output operation failed.
    Io,
}

/// The checksum layer at which verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChecksumScope {
    /// The fixed start-header fields.
    StartHeader,
    /// The next-header byte range.
    NextHeader,
    /// A decoded encoded-header stream.
    EncodedHeader,
    /// One packed input stream before decoding.
    PackedStream,
    /// A decoded folder stream.
    Folder,
    /// A decoded additional/property stream.
    AdditionalStream,
    /// An individual archive member.
    Member,
    /// An RPM package metadata header.
    PackageHeader,
    /// An RPM compressed or decoded payload.
    PackagePayload,
}

impl fmt::Display for ChecksumScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::StartHeader => "start header",
            Self::NextHeader => "next header",
            Self::EncodedHeader => "encoded header",
            Self::PackedStream => "packed stream",
            Self::Folder => "folder",
            Self::AdditionalStream => "additional stream",
            Self::Member => "member",
            Self::PackageHeader => "package header",
            Self::PackagePayload => "package payload",
        };
        formatter.write_str(name)
    }
}

/// A configured limit that can reject attacker-controlled work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitKind {
    /// Bytes in a raw or decoded header.
    HeaderBytes,
    /// Files and directory entries.
    Files,
    /// Folder records.
    Folders,
    /// Coders in one folder.
    CodersPerFolder,
    /// Coders across the archive.
    TotalCoders,
    /// Input plus output stream ports in one folder.
    StreamsPerFolder,
    /// Input plus output stream ports across the parsed header.
    TotalStreams,
    /// Data and skippable frames in one compressed stream.
    StreamFrames,
    /// Substreams across the parsed header.
    Substreams,
    /// Length-delimited properties in one next header.
    HeaderProperties,
    /// Property bytes for one coder.
    CoderPropertyBytes,
    /// Encoded name bytes for one entry.
    NameBytesPerEntry,
    /// Encoded name bytes across the archive.
    TotalNameBytes,
    /// Decoder dictionary memory.
    DictionaryBytes,
    /// Decoded bytes for one entry.
    EntryOutputBytes,
    /// Decoded bytes across the operation.
    TotalOutputBytes,
    /// Archive volumes.
    Volumes,
    /// Bytes across all archive volumes.
    TotalInputBytes,
    /// AES key-derivation exponent.
    KdfPower,
    /// Nested parser or encoded-header recursion depth.
    RecursionDepth,
    /// Bytes searched for an SFX signature.
    SfxScanBytes,
    /// Abstract caller-configured work units.
    WorkUnits,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HeaderBytes => "header bytes",
            Self::Files => "files",
            Self::Folders => "folders",
            Self::CodersPerFolder => "coders per folder",
            Self::TotalCoders => "total coders",
            Self::StreamsPerFolder => "streams per folder",
            Self::TotalStreams => "total streams",
            Self::StreamFrames => "compressed stream frames",
            Self::Substreams => "substreams",
            Self::HeaderProperties => "header properties",
            Self::CoderPropertyBytes => "coder property bytes",
            Self::NameBytesPerEntry => "name bytes per entry",
            Self::TotalNameBytes => "total name bytes",
            Self::DictionaryBytes => "dictionary bytes",
            Self::EntryOutputBytes => "entry output bytes",
            Self::TotalOutputBytes => "total output bytes",
            Self::Volumes => "volumes",
            Self::TotalInputBytes => "total input bytes",
            Self::KdfPower => "KDF power",
            Self::RecursionDepth => "recursion depth",
            Self::SfxScanBytes => "SFX scan bytes",
            Self::WorkUnits => "work units",
        };
        formatter.write_str(name)
    }
}

/// A failure produced by opening, parsing, validating, or decoding compressed input.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The bytes violate a format invariant.
    Format {
        /// A bounded diagnostic that does not contain secret material.
        detail: String,
    },
    /// A standalone compressed stream violates a format invariant.
    StreamFormat {
        /// Stable lowercase format name.
        format: String,
        /// A bounded diagnostic that does not contain output data.
        detail: String,
    },
    /// A checksum did not match.
    Checksum {
        /// The layer whose checksum failed.
        scope: ChecksumScope,
        /// The member index when `scope` is [`ChecksumScope::Member`].
        member_index: Option<u64>,
    },
    /// A standalone compressed frame checksum did not match.
    StreamChecksum {
        /// Stable lowercase format name.
        format: String,
        /// Zero-based data-frame index.
        frame_index: u64,
    },
    /// No decoder is registered for a method identifier.
    UnsupportedMethod {
        /// The exact method identifier from the validated archive model.
        method_id: Box<[u8]>,
    },
    /// A recognized, valid feature has not been implemented.
    UnsupportedFeature {
        /// A stable feature name.
        feature: String,
    },
    /// A recognized standalone compressed-stream feature is unavailable.
    UnsupportedStreamFeature {
        /// Stable lowercase format name.
        format: String,
        /// Stable feature identifier.
        feature: String,
    },
    /// Attacker-controlled work exceeded a configured bound.
    LimitExceeded {
        /// The limit that rejected the operation.
        limit: LimitKind,
        /// The amount requested by the operation.
        requested: u64,
        /// The configured maximum.
        maximum: u64,
    },
    /// A volume provider could not supply the next required volume.
    MissingVolume {
        /// The exact expected volume name.
        expected: String,
    },
    /// A password is required before processing can continue.
    PasswordRequired,
    /// Either the password is wrong or encrypted bytes are corrupt.
    WrongPasswordOrCorrupt,
    /// The operation was cancelled at a work checkpoint.
    Cancelled,
    /// An I/O operation failed.
    Io(io::Error),
}

impl Error {
    /// Returns the payload-free category for this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Format { .. } | Self::StreamFormat { .. } => ErrorKind::Format,
            Self::Checksum { .. } | Self::StreamChecksum { .. } => ErrorKind::Checksum,
            Self::UnsupportedMethod { .. } => ErrorKind::UnsupportedMethod,
            Self::UnsupportedFeature { .. } | Self::UnsupportedStreamFeature { .. } => {
                ErrorKind::UnsupportedFeature
            }
            Self::LimitExceeded { .. } => ErrorKind::LimitExceeded,
            Self::MissingVolume { .. } => ErrorKind::MissingVolume,
            Self::PasswordRequired => ErrorKind::PasswordRequired,
            Self::WrongPasswordOrCorrupt => ErrorKind::WrongPasswordOrCorrupt,
            Self::Cancelled => ErrorKind::Cancelled,
            Self::Io(_) => ErrorKind::Io,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format { detail } => write!(formatter, "invalid archive format: {detail}"),
            Self::StreamFormat { format, detail } => {
                write!(formatter, "invalid {format} stream: {detail}")
            }
            Self::Checksum {
                scope,
                member_index: Some(index),
            } => write!(formatter, "{scope} checksum mismatch at member {index}"),
            Self::Checksum {
                scope,
                member_index: None,
            } => write!(formatter, "{scope} checksum mismatch"),
            Self::StreamChecksum {
                format,
                frame_index,
            } => write!(
                formatter,
                "{format} checksum mismatch at frame {frame_index}"
            ),
            Self::UnsupportedMethod { method_id } => {
                formatter.write_str("unsupported archive method 0x")?;
                for byte in method_id {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::UnsupportedFeature { feature } => {
                write!(formatter, "unsupported 7z feature: {feature}")
            }
            Self::UnsupportedStreamFeature { format, feature } => {
                write!(formatter, "unsupported {format} stream feature: {feature}")
            }
            Self::LimitExceeded {
                limit,
                requested,
                maximum,
            } => write!(
                formatter,
                "limit exceeded for {limit}: requested {requested}, maximum {maximum}"
            ),
            Self::MissingVolume { expected } => {
                write!(formatter, "missing archive volume: {expected}")
            }
            Self::PasswordRequired => formatter.write_str("archive password required"),
            Self::WrongPasswordOrCorrupt => {
                formatter.write_str("wrong password or corrupt encrypted data")
            }
            Self::Cancelled => formatter.write_str("archive operation cancelled"),
            Self::Io(error) => write!(formatter, "archive I/O error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, io};

    use super::{ChecksumScope, Error, ErrorKind, LimitKind};

    #[test]
    fn every_checksum_scope_has_a_stable_display_name() {
        for (scope, expected) in [
            (ChecksumScope::StartHeader, "start header"),
            (ChecksumScope::NextHeader, "next header"),
            (ChecksumScope::EncodedHeader, "encoded header"),
            (ChecksumScope::PackedStream, "packed stream"),
            (ChecksumScope::Folder, "folder"),
            (ChecksumScope::AdditionalStream, "additional stream"),
            (ChecksumScope::Member, "member"),
        ] {
            assert_eq!(scope.to_string(), expected);
        }
    }

    #[test]
    fn every_limit_has_a_stable_display_name() {
        for (limit, expected) in [
            (LimitKind::HeaderBytes, "header bytes"),
            (LimitKind::Files, "files"),
            (LimitKind::Folders, "folders"),
            (LimitKind::CodersPerFolder, "coders per folder"),
            (LimitKind::TotalCoders, "total coders"),
            (LimitKind::StreamsPerFolder, "streams per folder"),
            (LimitKind::TotalStreams, "total streams"),
            (LimitKind::StreamFrames, "compressed stream frames"),
            (LimitKind::Substreams, "substreams"),
            (LimitKind::HeaderProperties, "header properties"),
            (LimitKind::CoderPropertyBytes, "coder property bytes"),
            (LimitKind::NameBytesPerEntry, "name bytes per entry"),
            (LimitKind::TotalNameBytes, "total name bytes"),
            (LimitKind::DictionaryBytes, "dictionary bytes"),
            (LimitKind::EntryOutputBytes, "entry output bytes"),
            (LimitKind::TotalOutputBytes, "total output bytes"),
            (LimitKind::Volumes, "volumes"),
            (LimitKind::TotalInputBytes, "total input bytes"),
            (LimitKind::KdfPower, "KDF power"),
            (LimitKind::RecursionDepth, "recursion depth"),
            (LimitKind::SfxScanBytes, "SFX scan bytes"),
            (LimitKind::WorkUnits, "work units"),
        ] {
            assert_eq!(limit.to_string(), expected);
        }
    }

    #[test]
    fn kind_does_not_depend_on_payload() {
        let error = Error::MissingVolume {
            expected: String::from("archive.002"),
        };
        assert_eq!(error.kind(), ErrorKind::MissingVolume);
        assert_eq!(error.to_string(), "missing archive volume: archive.002");
    }

    #[test]
    fn method_identifier_is_rendered_without_indexing() {
        let error = Error::UnsupportedMethod {
            method_id: Box::from([0x21_u8, 0xff]),
        };
        assert_eq!(error.to_string(), "unsupported archive method 0x21ff");
    }

    #[test]
    fn every_error_variant_has_a_stable_kind_and_message() {
        let errors = [
            (
                Error::Format {
                    detail: String::from("bad record"),
                },
                ErrorKind::Format,
                "invalid archive format: bad record",
            ),
            (
                Error::StreamFormat {
                    format: String::from("lz4"),
                    detail: String::from("bad frame"),
                },
                ErrorKind::Format,
                "invalid lz4 stream: bad frame",
            ),
            (
                Error::Checksum {
                    scope: ChecksumScope::Folder,
                    member_index: None,
                },
                ErrorKind::Checksum,
                "folder checksum mismatch",
            ),
            (
                Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(7),
                },
                ErrorKind::Checksum,
                "member checksum mismatch at member 7",
            ),
            (
                Error::StreamChecksum {
                    format: String::from("zstandard"),
                    frame_index: 3,
                },
                ErrorKind::Checksum,
                "zstandard checksum mismatch at frame 3",
            ),
            (
                Error::UnsupportedMethod {
                    method_id: Box::from([0x21_u8]),
                },
                ErrorKind::UnsupportedMethod,
                "unsupported archive method 0x21",
            ),
            (
                Error::UnsupportedFeature {
                    feature: String::from("test feature"),
                },
                ErrorKind::UnsupportedFeature,
                "unsupported 7z feature: test feature",
            ),
            (
                Error::UnsupportedStreamFeature {
                    format: String::from("lz4"),
                    feature: String::from("external-dictionary"),
                },
                ErrorKind::UnsupportedFeature,
                "unsupported lz4 stream feature: external-dictionary",
            ),
            (
                Error::LimitExceeded {
                    limit: LimitKind::Files,
                    requested: 3,
                    maximum: 2,
                },
                ErrorKind::LimitExceeded,
                "limit exceeded for files: requested 3, maximum 2",
            ),
            (
                Error::MissingVolume {
                    expected: String::from("archive.7z.002"),
                },
                ErrorKind::MissingVolume,
                "missing archive volume: archive.7z.002",
            ),
            (
                Error::PasswordRequired,
                ErrorKind::PasswordRequired,
                "archive password required",
            ),
            (
                Error::WrongPasswordOrCorrupt,
                ErrorKind::WrongPasswordOrCorrupt,
                "wrong password or corrupt encrypted data",
            ),
            (
                Error::Cancelled,
                ErrorKind::Cancelled,
                "archive operation cancelled",
            ),
        ];

        for (error, kind, message) in errors {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            assert!(StdError::source(&error).is_none());
        }
    }

    #[test]
    fn io_conversion_preserves_kind_message_and_source() {
        let error = Error::from(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.to_string(), "archive I/O error: short read");
        assert!(StdError::source(&error).is_some());
    }
}
