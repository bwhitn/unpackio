//! Bounded, unpack-only RPM packages.

mod cpio;
pub(crate) mod decode;
mod header;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::{
    CancellationToken, ChecksumScope, Error, LimitKind, Limits, Result, WorkBudget,
    parse_util::{
        CONTROL_CHUNK_SIZE, ParseControl, check_limit, checked_range, try_reserve, usize_to_u64,
    },
};

const TAG_PAYLOAD_FORMAT: u32 = 1124;
const TAG_PAYLOAD_COMPRESSOR: u32 = 1125;
const SIGNATURE_TAG_SHA1: u32 = 269;
const SIGNATURE_TAG_SHA256: u32 = 273;
const SIGNATURE_TAG_SHA3_256: u32 = 279;
const TAG_PAYLOAD_SHA256: u32 = 5092;
const TAG_PAYLOAD_SHA256_ALGORITHM: u32 = 5093;
const TAG_PAYLOAD_SHA256_ALT: u32 = 5097;
const TAG_PAYLOAD_SHA512: u32 = 5121;
const TAG_PAYLOAD_SHA512_ALT: u32 = 5122;
const TAG_PAYLOAD_SHA3_256: u32 = 5123;
const TAG_PAYLOAD_SHA3_256_ALT: u32 = 5124;

/// The fixed metadata from an RPM lead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmLead {
    major: u8,
    minor: u8,
    package_type: u16,
    architecture: u16,
    name: Box<[u8]>,
    operating_system: u16,
    signature_type: u16,
    reserved: [u8; 16],
}

impl RpmLead {
    /// Returns the RPM format major version.
    #[must_use]
    pub const fn major(&self) -> u8 {
        self.major
    }

    /// Returns the RPM format minor version.
    #[must_use]
    pub const fn minor(&self) -> u8 {
        self.minor
    }

    /// Returns the raw package-type identifier.
    #[must_use]
    pub const fn package_type(&self) -> u16 {
        self.package_type
    }

    /// Returns the legacy architecture identifier from the lead.
    #[must_use]
    pub const fn architecture(&self) -> u16 {
        self.architecture
    }

    /// Returns the byte-preserving package name from the legacy lead.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the legacy operating-system identifier.
    #[must_use]
    pub const fn operating_system(&self) -> u16 {
        self.operating_system
    }

    /// Returns the legacy signature-type identifier.
    #[must_use]
    pub const fn signature_type(&self) -> u16 {
        self.signature_type
    }

    /// Returns the exact sixteen reserved bytes at the end of the legacy lead.
    ///
    /// These bytes are preserved as metadata and are not interpreted.
    #[must_use]
    pub const fn reserved(&self) -> &[u8; 16] {
        &self.reserved
    }
}

/// One typed value stored in an RPM header index.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RpmValue {
    /// The RPM NULL type.
    Null,
    /// Raw character bytes.
    Char(Box<[u8]>),
    /// Unsigned 8-bit integers.
    Int8(Box<[u8]>),
    /// Unsigned big-endian 16-bit integers.
    Int16(Box<[u16]>),
    /// Unsigned big-endian 32-bit integers.
    Int32(Box<[u32]>),
    /// Unsigned big-endian 64-bit integers.
    Int64(Box<[u64]>),
    /// One NUL-terminated byte string, excluding its terminator.
    String(Box<[u8]>),
    /// Opaque binary bytes.
    Binary(Box<[u8]>),
    /// A sequence of NUL-terminated byte strings.
    StringArray(Box<[Box<[u8]>]>),
    /// A sequence of localized NUL-terminated byte strings.
    I18nString(Box<[Box<[u8]>]>),
}

impl RpmValue {
    /// Returns the bytes for scalar byte-oriented values.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Char(value) | Self::Int8(value) | Self::String(value) | Self::Binary(value) => {
                Some(value)
            }
            _ => None,
        }
    }

    /// Returns the 32-bit integer array when this is an INT32 value.
    #[must_use]
    pub fn as_u32_slice(&self) -> Option<&[u32]> {
        match self {
            Self::Int32(value) => Some(value),
            _ => None,
        }
    }

    /// Returns string-array values without interpreting their encoding.
    #[must_use]
    pub fn as_string_array(&self) -> Option<&[Box<[u8]>]> {
        match self {
            Self::StringArray(value) | Self::I18nString(value) => Some(value),
            _ => None,
        }
    }
}

/// One RPM header index entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmHeaderEntry {
    tag: u32,
    value: RpmValue,
}

impl RpmHeaderEntry {
    /// Returns the numeric RPM tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        self.tag
    }

    /// Returns the parsed typed value.
    #[must_use]
    pub const fn value(&self) -> &RpmValue {
        &self.value
    }
}

/// A validated RPM signature or main header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpmHeader {
    entries: Box<[RpmHeaderEntry]>,
    raw_size: u64,
}

impl RpmHeader {
    /// Returns entries in their original index order, including duplicate tags.
    #[must_use]
    pub fn entries(&self) -> &[RpmHeaderEntry] {
        &self.entries
    }

    /// Returns the last value carrying `tag`, matching RPM's effective-value
    /// convention while still preserving every raw entry through [`Self::entries`].
    #[must_use]
    pub fn value(&self, tag: u32) -> Option<&RpmValue> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.tag == tag)
            .map(|entry| &entry.value)
    }

    /// Returns the complete encoded header byte length.
    #[must_use]
    pub const fn raw_size(&self) -> u64 {
        self.raw_size
    }
}

/// Compression declared for an RPM CPIO payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RpmPayloadCompression {
    /// An uncompressed CPIO payload.
    None,
    /// A gzip payload.
    Gzip,
    /// A bzip2 payload.
    Bzip2,
    /// An XZ payload.
    Xz,
    /// A legacy LZMA-alone payload.
    Lzma,
    /// A Zstandard payload.
    Zstandard,
    /// A declared compressor not recognized by this version.
    Unknown,
}

/// Owned metadata for one CPIO member in an RPM payload.
pub type RpmEntry = crate::CpioEntry;

/// A callback boundary for natural-order RPM payload extraction.
pub trait RpmEntrySink {
    /// Starts one member. Its raw name remains metadata and is never a path.
    fn begin_entry(&mut self, entry: &RpmEntry) -> Result<()>;

    /// Receives one bounded decoded member chunk.
    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> Result<()>;

    /// Reports success only after applicable member integrity checks.
    fn finish_entry(&mut self, entry_index: u64) -> Result<()>;
}

/// An owned, bounded RPM metadata and CPIO payload reader.
pub struct RpmArchive {
    lead: RpmLead,
    signature: RpmHeader,
    header: RpmHeader,
    payload: Box<[u8]>,
    entries: Box<[RpmEntry]>,
    compression: RpmPayloadCompression,
    limits: Limits,
}

impl RpmArchive {
    /// Opens in-memory RPM bytes and validates its headers and CPIO envelope.
    ///
    /// Payload members are retained in decoded memory after all applicable
    /// package-level integrity checks pass. No member name is interpreted as a
    /// filesystem path.
    ///
    /// # Errors
    ///
    /// Returns a typed format, checksum, unsupported-feature, limit,
    /// cancellation, work-budget, decompression, or allocation error.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        check_limit(
            usize_to_u64(bytes.len(), "RPM input size is not representable as u64")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        let mut control = ParseControl::new(cancellation, budget);
        let parsed = header::parse(&bytes, limits, &mut control)?;
        verify_header_digests(&bytes, &parsed, &mut control)?;
        validate_payload_digest_algorithm(&parsed.header)?;
        let compression = payload_compression(&parsed.header)?;
        let payload_format = header_scalar_bytes(&parsed.header, TAG_PAYLOAD_FORMAT)?;
        if let Some(format) = payload_format {
            if !format.eq_ignore_ascii_case(b"cpio") {
                return Err(Error::UnsupportedFeature {
                    feature: format!("rpm-payload-format-{}", escaped_identifier(format)),
                });
            }
        }
        for (tag, feature) in [
            (TAG_PAYLOAD_SHA512, "rpm-payload-sha512-verification"),
            (
                TAG_PAYLOAD_SHA512_ALT,
                "rpm-uncompressed-payload-sha512-verification",
            ),
            (TAG_PAYLOAD_SHA3_256, "rpm-payload-sha3-256-verification"),
            (
                TAG_PAYLOAD_SHA3_256_ALT,
                "rpm-uncompressed-payload-sha3-256-verification",
            ),
        ] {
            if parsed.header.value(tag).is_some() {
                return Err(Error::UnsupportedFeature {
                    feature: String::from(feature),
                });
            }
        }
        let input_size = usize_to_u64(bytes.len(), "RPM input size is not representable")?;
        let compressed_size = input_size
            .checked_sub(parsed.payload_start)
            .ok_or_else(|| rpm_format("payload start is past the input"))?;
        let compressed = checked_range(
            &bytes,
            parsed.payload_start,
            compressed_size,
            "RPM payload range overflows",
            "RPM payload is truncated",
        )?;
        verify_payload_digest(&parsed.header, TAG_PAYLOAD_SHA256, compressed, &mut control)?;
        let payload = decode::decode_payload(compressed, compression, limits, &mut control)?;
        verify_payload_digest(
            &parsed.header,
            TAG_PAYLOAD_SHA256_ALT,
            &payload,
            &mut control,
        )?;
        let entries = cpio::parse(&payload, limits, &mut control)?;
        Ok(Self {
            lead: parsed.lead,
            signature: parsed.signature,
            header: parsed.header,
            payload: payload.into_boxed_slice(),
            entries: entries.into_boxed_slice(),
            compression,
            limits,
        })
    }

    /// Opens an RPM path without deriving any extraction destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for input reads or any error documented by
    /// [`Self::open_bytes`].
    pub fn open_path(
        path: &Path,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let bytes = read_path(path, limits, cancellation, budget)?;
        Self::open_bytes(bytes, limits, cancellation, budget)
    }

    /// Returns the legacy RPM lead.
    #[must_use]
    pub const fn lead(&self) -> &RpmLead {
        &self.lead
    }

    /// Returns the signature header, including unverified OpenPGP blobs.
    #[must_use]
    pub const fn signature_header(&self) -> &RpmHeader {
        &self.signature
    }

    /// Returns the main package metadata header.
    #[must_use]
    pub const fn header(&self) -> &RpmHeader {
        &self.header
    }

    /// Returns the declared payload compression.
    #[must_use]
    pub const fn payload_compression(&self) -> RpmPayloadCompression {
        self.compression
    }

    /// Returns CPIO entries in exact payload order, including duplicates.
    #[must_use]
    pub fn entries(&self) -> &[RpmEntry] {
        &self.entries
    }

    /// Returns one entry by stable payload-order index.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&RpmEntry> {
        let index = usize::try_from(index).ok()?;
        self.entries.get(index)
    }

    /// Returns the limits retained for extraction operations.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns retained decoded payload bytes for resource accounting.
    #[must_use]
    pub fn retained_payload_bytes(&self) -> usize {
        self.payload.len()
    }

    /// Verifies and copies one member to a caller-selected writer.
    ///
    /// # Errors
    ///
    /// Returns a typed index, checksum, limit, cancellation, budget, or writer
    /// error. Integrity is checked before the first output write.
    pub fn extract_entry_to(
        &self,
        entry_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let entry = self.required_entry(entry_index)?;
        let mut control = ParseControl::new(cancellation, budget);
        let data = self.verified_data(entry, &mut control)?;
        for chunk in data.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "RPM output chunk length is not representable",
            )?)?;
            writer.write_all(chunk).map_err(Error::Io)?;
        }
        Ok(entry.size())
    }

    /// Extracts all members in payload order with shared output, work, and
    /// cancellation accounting.
    ///
    /// # Errors
    ///
    /// Returns the first member or sink error. `finish_entry` is called only
    /// after the current member's applicable checksum succeeds.
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn RpmEntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = total
                .checked_add(entry.size())
                .ok_or(Error::LimitExceeded {
                    limit: LimitKind::TotalOutputBytes,
                    requested: u64::MAX,
                    maximum: self.limits.max_total_output_bytes(),
                })?;
            check_limit(
                entry.size(),
                self.limits.max_entry_output_bytes(),
                LimitKind::EntryOutputBytes,
            )?;
            check_limit(
                total,
                self.limits.max_total_output_bytes(),
                LimitKind::TotalOutputBytes,
            )?;
            let data = self.verified_data(entry, &mut control)?;
            sink.begin_entry(entry)?;
            for chunk in data.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "RPM sink chunk length is not representable",
                )?)?;
                sink.write_entry(entry.index(), chunk)?;
            }
            sink.finish_entry(entry.index())?;
        }
        Ok(total)
    }

    /// Rechecks every applicable CPIO member checksum and discards the bytes.
    ///
    /// # Errors
    ///
    /// Returns the first checksum, range, cancellation, or budget error.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            total = total
                .checked_add(entry.size())
                .ok_or(Error::LimitExceeded {
                    limit: LimitKind::TotalOutputBytes,
                    requested: u64::MAX,
                    maximum: self.limits.max_total_output_bytes(),
                })?;
            check_limit(
                total,
                self.limits.max_total_output_bytes(),
                LimitKind::TotalOutputBytes,
            )?;
            self.verified_data(entry, &mut control)?;
        }
        Ok(())
    }

    fn required_entry(&self, index: u64) -> Result<&RpmEntry> {
        let index = usize::try_from(index).map_err(|_| rpm_format("entry index is too large"))?;
        self.entries
            .get(index)
            .ok_or_else(|| rpm_format("entry index is out of range"))
    }

    fn verified_data<'archive>(
        &'archive self,
        entry: &RpmEntry,
        control: &mut ParseControl<'_>,
    ) -> Result<&'archive [u8]> {
        let length = entry
            .data_end
            .checked_sub(entry.data_start)
            .ok_or_else(|| rpm_format("member data range underflows"))?;
        let data = checked_range(
            &self.payload,
            entry.data_start,
            length,
            "RPM member data range overflows",
            "RPM member data range is invalid",
        )?;
        if let Some(expected) = entry.checksum {
            if cpio::byte_sum(data, control)? != expected {
                return Err(Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(entry.index()),
                });
            }
        }
        Ok(data)
    }
}

fn payload_compression(header: &RpmHeader) -> Result<RpmPayloadCompression> {
    let Some(value) = header_scalar_bytes(header, TAG_PAYLOAD_COMPRESSOR)? else {
        // RPM v4's historical default, also used by rpmfile.
        return Ok(RpmPayloadCompression::Gzip);
    };
    if value.eq_ignore_ascii_case(b"gzip") || value.eq_ignore_ascii_case(b"gz") {
        Ok(RpmPayloadCompression::Gzip)
    } else if value.eq_ignore_ascii_case(b"bzip2") || value.eq_ignore_ascii_case(b"bzip") {
        Ok(RpmPayloadCompression::Bzip2)
    } else if value.eq_ignore_ascii_case(b"xz") {
        Ok(RpmPayloadCompression::Xz)
    } else if value.eq_ignore_ascii_case(b"lzma") {
        Ok(RpmPayloadCompression::Lzma)
    } else if value.eq_ignore_ascii_case(b"zstd") || value.eq_ignore_ascii_case(b"zstandard") {
        Ok(RpmPayloadCompression::Zstandard)
    } else if value.eq_ignore_ascii_case(b"none") || value.is_empty() {
        Ok(RpmPayloadCompression::None)
    } else {
        Err(Error::UnsupportedFeature {
            feature: format!("rpm-payload-compression-{}", escaped_identifier(value)),
        })
    }
}

fn header_scalar_bytes(header: &RpmHeader, tag: u32) -> Result<Option<&[u8]>> {
    match header.value(tag) {
        None => Ok(None),
        Some(RpmValue::String(value)) => Ok(Some(value)),
        Some(_) => Err(rpm_format("header scalar string tag has the wrong type")),
    }
}

fn verify_header_digests(
    bytes: &[u8],
    parsed: &header::ParsedHeaders,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    if parsed.signature.value(SIGNATURE_TAG_SHA3_256).is_some() {
        return Err(Error::UnsupportedFeature {
            feature: String::from("rpm-header-sha3-256-verification"),
        });
    }
    let main_size = parsed
        .payload_start
        .checked_sub(parsed.main_start)
        .ok_or_else(|| rpm_format("main-header range underflows"))?;
    let main = checked_range(
        bytes,
        parsed.main_start,
        main_size,
        "RPM main-header range overflows",
        "RPM main header is truncated",
    )?;
    if let Some(expected) = header_scalar_bytes(&parsed.signature, SIGNATURE_TAG_SHA256)? {
        verify_hex_digest(
            expected,
            &decode::sha256_hex(main, control)?,
            ChecksumScope::PackageHeader,
        )?;
    }
    if let Some(expected) = header_scalar_bytes(&parsed.signature, SIGNATURE_TAG_SHA1)? {
        verify_hex_digest(
            expected,
            &decode::sha1_hex(main, control)?,
            ChecksumScope::PackageHeader,
        )?;
    }
    Ok(())
}

fn validate_payload_digest_algorithm(header: &RpmHeader) -> Result<()> {
    let Some(value) = header.value(TAG_PAYLOAD_SHA256_ALGORITHM) else {
        return Ok(());
    };
    let values = match value {
        RpmValue::Int32(values) => values,
        _ => {
            return Err(rpm_format(
                "payload digest algorithm tag has the wrong type",
            ));
        }
    };
    if values.len() != 1 {
        return Err(rpm_format(
            "payload digest algorithm tag must contain one value",
        ));
    }
    let algorithm = values
        .first()
        .copied()
        .ok_or_else(|| rpm_format("payload digest algorithm is missing"))?;
    if algorithm == 8 {
        Ok(())
    } else {
        Err(Error::UnsupportedFeature {
            feature: format!("rpm-payload-digest-algorithm-{algorithm}"),
        })
    }
}

fn verify_payload_digest(
    header: &RpmHeader,
    tag: u32,
    bytes: &[u8],
    control: &mut ParseControl<'_>,
) -> Result<()> {
    let Some(value) = header.value(tag) else {
        return Ok(());
    };
    let values = match value {
        RpmValue::StringArray(values) => values,
        _ => return Err(rpm_format("payload digest tag has the wrong type")),
    };
    if values.len() != 1 {
        return Err(Error::UnsupportedFeature {
            feature: String::from("rpm-multiple-payload-digests"),
        });
    }
    let expected = values
        .first()
        .ok_or_else(|| rpm_format("payload digest array is empty"))?;
    verify_hex_digest(
        expected,
        &decode::sha256_hex(bytes, control)?,
        ChecksumScope::PackagePayload,
    )
}

fn verify_hex_digest(expected: &[u8], actual: &str, scope: ChecksumScope) -> Result<()> {
    if expected.len() != actual.len()
        || !expected.iter().all(u8::is_ascii_hexdigit)
        || !expected.eq_ignore_ascii_case(actual.as_bytes())
    {
        return Err(Error::Checksum {
            scope,
            member_index: None,
        });
    }
    Ok(())
}

fn escaped_identifier(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes.iter().copied().take(32) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            output.push(char::from(byte));
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        String::from("empty")
    } else {
        output
    }
}

fn read_path(
    path: &Path,
    limits: Limits,
    cancellation: &CancellationToken,
    budget: &mut WorkBudget,
) -> Result<Vec<u8>> {
    let metadata = path.metadata().map_err(Error::Io)?;
    check_limit(
        metadata.len(),
        limits.max_total_input_bytes(),
        LimitKind::TotalInputBytes,
    )?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| rpm_format("path size is not representable on this platform"))?;
    let mut bytes = Vec::new();
    try_reserve(&mut bytes, capacity)?;
    let mut file = File::open(path).map_err(Error::Io)?;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    loop {
        cancellation.check()?;
        let read = file.read(&mut buffer).map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| rpm_format("path read returned an invalid byte count"))?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "RPM input chunk length is not representable",
        )?)?;
        let requested = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| rpm_format("RPM path input size overflows"))?;
        check_limit(
            usize_to_u64(requested, "RPM path input size is not representable")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn rpm_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("RPM: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    use super::{RpmArchive, RpmEntrySink, RpmPayloadCompression};
    use crate::{
        CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget, checksum::Crc32,
    };

    struct HeaderValue {
        tag: u32,
        value_type: u32,
        count: u32,
        bytes: Vec<u8>,
    }

    fn append_be_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn u32_len(value: usize) -> Result<u32> {
        u32::try_from(value).map_err(|_| super::rpm_format("test length exceeds u32"))
    }

    fn string_value(tag: u32, value: &[u8]) -> HeaderValue {
        let mut bytes = value.to_vec();
        bytes.push(0);
        HeaderValue {
            tag,
            value_type: 6,
            count: 1,
            bytes,
        }
    }

    fn string_array_value(tag: u32, value: &[u8]) -> HeaderValue {
        let mut bytes = value.to_vec();
        bytes.push(0);
        HeaderValue {
            tag,
            value_type: 8,
            count: 1,
            bytes,
        }
    }

    fn int32_value(tag: u32, value: u32) -> HeaderValue {
        HeaderValue {
            tag,
            value_type: 4,
            count: 1,
            bytes: value.to_be_bytes().to_vec(),
        }
    }

    fn build_header(values: &[HeaderValue]) -> Result<Vec<u8>> {
        let mut store = Vec::new();
        let mut indices = Vec::new();
        for value in values {
            append_be_u32(&mut indices, value.tag);
            append_be_u32(&mut indices, value.value_type);
            append_be_u32(&mut indices, u32_len(store.len())?);
            append_be_u32(&mut indices, value.count);
            store.extend_from_slice(&value.bytes);
        }
        let mut output = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
        append_be_u32(&mut output, u32_len(values.len())?);
        append_be_u32(&mut output, u32_len(store.len())?);
        output.extend_from_slice(&indices);
        output.extend_from_slice(&store);
        Ok(output)
    }

    fn build_shared_string_header(count: u32, value: &[u8]) -> Result<Vec<u8>> {
        let mut store = value.to_vec();
        store.push(0);
        let mut indices = Vec::new();
        for ordinal in 0..count {
            append_be_u32(&mut indices, 2_000_u32.saturating_add(ordinal));
            append_be_u32(&mut indices, 6);
            append_be_u32(&mut indices, 0);
            append_be_u32(&mut indices, 1);
        }
        let mut output = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
        append_be_u32(&mut output, count);
        append_be_u32(&mut output, u32_len(store.len())?);
        output.extend_from_slice(&indices);
        output.extend_from_slice(&store);
        Ok(output)
    }

    fn build_lead() -> Vec<u8> {
        let mut lead = vec![0_u8; 96];
        if let Some(magic) = lead.get_mut(..4) {
            magic.copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        }
        if let Some(major) = lead.get_mut(4) {
            *major = 3;
        }
        if let Some(minor) = lead.get_mut(5) {
            *minor = 0;
        }
        if let Some(name) = lead.get_mut(10..17) {
            name.copy_from_slice(b"fixture");
        }
        if let Some(package_type) = lead.get_mut(6..8) {
            package_type.copy_from_slice(&0_u16.to_be_bytes());
        }
        if let Some(architecture) = lead.get_mut(8..10) {
            architecture.copy_from_slice(&1_u16.to_be_bytes());
        }
        if let Some(operating_system) = lead.get_mut(76..78) {
            operating_system.copy_from_slice(&1_u16.to_be_bytes());
        }
        if let Some(signature_type) = lead.get_mut(78..80) {
            signature_type.copy_from_slice(&5_u16.to_be_bytes());
        }
        if let Some(reserved) = lead.get_mut(80..96) {
            reserved.copy_from_slice(b"reserved-bytes!!");
        }
        lead
    }

    fn append_hex(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn append_cpio_record(
        output: &mut Vec<u8>,
        magic: &[u8; 6],
        name: &[u8],
        data: &[u8],
        mode: u32,
        checksum: u32,
    ) -> Result<()> {
        output.extend_from_slice(magic);
        append_hex(output, 1);
        append_hex(output, mode);
        append_hex(output, 1000);
        append_hex(output, 1000);
        append_hex(output, 1);
        append_hex(output, 1_700_000_000);
        append_hex(output, u32_len(data.len())?);
        append_hex(output, 0);
        append_hex(output, 0);
        append_hex(output, 0);
        append_hex(output, 0);
        let name_size = name
            .len()
            .checked_add(1)
            .ok_or_else(|| super::rpm_format("test CPIO name length overflows"))?;
        append_hex(output, u32_len(name_size)?);
        append_hex(output, checksum);
        output.extend_from_slice(name);
        output.push(0);
        while output.len() % 4 != 0 {
            output.push(0);
        }
        output.extend_from_slice(data);
        while output.len() % 4 != 0 {
            output.push(0);
        }
        Ok(())
    }

    fn byte_sum(bytes: &[u8]) -> u32 {
        bytes
            .iter()
            .copied()
            .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(byte)))
    }

    fn build_cpio() -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        append_cpio_record(
            &mut payload,
            b"070702",
            b"./same.txt",
            b"first",
            0o100_644,
            byte_sum(b"first"),
        )?;
        append_cpio_record(
            &mut payload,
            b"070701",
            b"./same.txt",
            b"second",
            0o100_600,
            0,
        )?;
        append_cpio_record(&mut payload, b"070701", b"./empty", b"", 0o100_644, 0)?;
        append_cpio_record(&mut payload, b"070701", b"TRAILER!!!", b"", 0, 0)?;
        Ok(payload)
    }

    fn hex_digest(hasher: impl Digest) -> String {
        let digest = hasher.finalize();
        let mut output = String::new();
        for byte in digest.iter() {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    fn sha1_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        hex_digest(hasher)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex_digest(hasher)
    }

    fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
        let compressed = miniz_oxide::deflate::compress_to_vec(bytes, 6);
        let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        output.extend_from_slice(&compressed);
        let mut checksum = Crc32::new();
        checksum.update(bytes)?;
        output.extend_from_slice(&checksum.finalize().to_le_bytes());
        output.extend_from_slice(&u32_len(bytes.len())?.to_le_bytes());
        Ok(output)
    }

    fn build_rpm(cpio: &[u8], gzip_payload: bool, digests: bool) -> Result<Vec<u8>> {
        let compressed = if gzip_payload {
            gzip(cpio)?
        } else {
            cpio.to_vec()
        };
        let compressor = if gzip_payload { b"gzip" } else { b"none" };
        build_rpm_from_payload(cpio, &compressed, compressor, digests)
    }

    fn build_rpm_from_payload(
        cpio: &[u8],
        compressed: &[u8],
        compressor: &[u8],
        digests: bool,
    ) -> Result<Vec<u8>> {
        let mut main_values = vec![
            string_value(1000, b"fixture"),
            string_value(1001, b"1.0"),
            string_value(1002, b"1"),
            string_value(1022, b"noarch"),
            string_value(super::TAG_PAYLOAD_FORMAT, b"cpio"),
            string_value(super::TAG_PAYLOAD_COMPRESSOR, compressor),
        ];
        if digests {
            main_values.insert(0, int32_value(super::TAG_PAYLOAD_SHA256_ALGORITHM, 8));
            main_values.push(string_array_value(
                super::TAG_PAYLOAD_SHA256,
                sha256_hex(compressed).as_bytes(),
            ));
            main_values.push(string_array_value(
                super::TAG_PAYLOAD_SHA256_ALT,
                sha256_hex(cpio).as_bytes(),
            ));
        }
        let main = build_header(&main_values)?;
        let signature = if digests {
            build_header(&[
                string_value(super::SIGNATURE_TAG_SHA1, sha1_hex(&main).as_bytes()),
                string_value(super::SIGNATURE_TAG_SHA256, sha256_hex(&main).as_bytes()),
            ])?
        } else {
            build_header(&[])?
        };
        let mut output = build_lead();
        output.extend_from_slice(&signature);
        while output.len() % 8 != 0 {
            output.push(0);
        }
        output.extend_from_slice(&main);
        output.extend_from_slice(compressed);
        Ok(output)
    }

    fn hex_nibble(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
            b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
            b'A'..=b'F' => Ok(byte.saturating_sub(b'A').saturating_add(10)),
            _ => Err(super::rpm_format("test fixture contains non-hex data")),
        }
    }

    fn decode_hex(encoded: &str) -> Result<Vec<u8>> {
        let mut chunks = encoded.as_bytes().chunks_exact(2);
        let capacity = encoded.len() / 2;
        let mut output = Vec::new();
        output.try_reserve_exact(capacity).map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "test fixture allocation failed",
            ))
        })?;
        for chunk in chunks.by_ref() {
            let high = chunk
                .first()
                .copied()
                .ok_or_else(|| super::rpm_format("test fixture high nibble is missing"))?;
            let low = chunk
                .get(1)
                .copied()
                .ok_or_else(|| super::rpm_format("test fixture low nibble is missing"))?;
            output.push(
                hex_nibble(high)?
                    .checked_mul(16)
                    .and_then(|value| value.checked_add(hex_nibble(low).ok()?))
                    .ok_or_else(|| super::rpm_format("test fixture byte overflows"))?,
            );
        }
        if !chunks.remainder().is_empty() {
            return Err(super::rpm_format("test fixture has an odd hex length"));
        }
        Ok(output)
    }

    fn open(bytes: Vec<u8>, limits: Limits) -> Result<RpmArchive> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        RpmArchive::open_bytes(bytes, limits, &cancellation, &mut budget)
    }

    fn extract(archive: &RpmArchive, index: u64) -> Result<Vec<u8>> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut output = Vec::new();
        archive.extract_entry_to(index, &mut output, &cancellation, &mut budget)?;
        Ok(output)
    }

    #[test]
    fn lists_metadata_duplicates_empty_and_extracts_exact_bytes() -> Result<()> {
        let cpio = build_cpio()?;
        let archive = open(build_rpm(&cpio, false, true)?, Limits::default())?;
        assert_eq!(archive.payload_compression(), RpmPayloadCompression::None);
        assert_eq!(archive.lead().name(), b"fixture");
        assert_eq!(archive.lead().reserved(), b"reserved-bytes!!");
        assert_eq!(archive.entries().len(), 3);
        assert_eq!(
            archive.entries().first().map(|entry| entry.raw_name()),
            Some(b"./same.txt".as_slice())
        );
        assert_eq!(
            archive.entries().get(1).map(|entry| entry.raw_name()),
            Some(b"./same.txt".as_slice())
        );
        assert_eq!(archive.entries().get(2).map(|entry| entry.size()), Some(0));
        assert_eq!(extract(&archive, 0)?, b"first");
        assert_eq!(extract(&archive, 1)?, b"second");
        assert_eq!(extract(&archive, 2)?, b"");
        Ok(())
    }

    #[test]
    fn decodes_gzip_and_verifies_header_and_payload_digests() -> Result<()> {
        let cpio = build_cpio()?;
        let rpm = build_rpm(&cpio, true, true)?;
        let archive = open(rpm.clone(), Limits::default())?;
        assert_eq!(archive.payload_compression(), RpmPayloadCompression::Gzip);
        assert_eq!(extract(&archive, 1)?, b"second");

        let mut corrupt = rpm;
        let payload_byte = corrupt
            .len()
            .checked_sub(9)
            .ok_or_else(|| super::rpm_format("test RPM is unexpectedly short"))?;
        let byte = corrupt
            .get_mut(payload_byte)
            .ok_or_else(|| super::rpm_format("test payload byte is missing"))?;
        *byte ^= 1;
        let error = open(corrupt, Limits::default()).err();
        assert_eq!(error.as_ref().map(Error::kind), Some(ErrorKind::Checksum));
        Ok(())
    }

    #[test]
    fn decodes_bzip2_xz_lzma_and_zstandard_payloads() -> Result<()> {
        // Generated from `build_cpio()` with the system bzip2 1.0.8,
        // XZ Utils 5.8.1, and Zstandard 1.5.7 command-line encoders. Those
        // programs are fixture-generation oracles only, not dependencies.
        const BZIP2: &str = "425a6839314159265359caf9ac0300005f5f807e202803ffc0222414003f23dc602000920954680d1a0869801a47a9e46a091288c9a68064c43468341a4df484f280c181b13189198e90145afb9b94a9211c161613224e2c844a42b6e83901ac2a542f04318685255a5d6ec6148726280ac11582404f908a10cec83daf75af9ce83b1652a6b46012b1016eb813b9a97249fb78afc3df07f177245385090caf9ac030";
        const XZ: &str = "fd377a585a000004e6d6b44604c078fc0321011c0000000000000000b3995e70e001fb00705d00180ddd04659c833c1c7b5e479d2b7a81196255caff0e3b5544fb8d69f25feccfd0830e5f1b818513882356542bea50a31fd89baf3d94b6bff5622d9e8e97488da23749ade6876679911b61676bc206ef655532f34a968d3c740010353917240e15ded86c9202e9a1b91b113f9fee590000b4d9341cc0837c0200019401fc0300007ebe34b6b1c467fb020000000004595a";
        const LZMA: &str = "5d00000004ffffffffffffffff00180ddd04659c833c1c7b5e479d2b7a81196255caff0e3b5544fb8d69f25feccfd0830e5f1b818513882356542bea50a31fd89baf3d94b6bff5622d9e8e97488da23749ade6876679911b61676bc206ef655532f34a968d3c740010353917240e15ded86c9202e9a1b91b113fc33e81ffffecdd30d7";
        const ZSTD: &str = "28b52ffd0468e5030062861418806d0ec8cb5ad850a14c6605070c4abab88952dd16e5381999996bad83308ae140febf8ad2d3cc40d1d2f0bf70d6eff770729a8c5464fd241060dcdaff5ff9bb36ee3d417f6ef7ff0f12e5ffd7b7eff7011120106f8b1d894494e3cfd7b07168641640a15cca63f35a890f26855922c0f2611368670dcf08fac945df";
        let cpio = build_cpio()?;
        for (encoded, compressor, expected) in [
            (BZIP2, b"bzip2".as_slice(), RpmPayloadCompression::Bzip2),
            (XZ, b"xz".as_slice(), RpmPayloadCompression::Xz),
            (LZMA, b"lzma".as_slice(), RpmPayloadCompression::Lzma),
            (ZSTD, b"zstd".as_slice(), RpmPayloadCompression::Zstandard),
        ] {
            let compressed = decode_hex(encoded)?;
            let archive = open(
                build_rpm_from_payload(&cpio, &compressed, compressor, true)?,
                Limits::default(),
            )?;
            assert_eq!(archive.payload_compression(), expected);
            assert_eq!(extract(&archive, 0)?, b"first");
        }
        Ok(())
    }

    #[test]
    fn rejects_crc_corruption_truncation_and_limits() -> Result<()> {
        let cpio = build_cpio()?;
        let mut corrupt = build_rpm(&cpio, false, false)?;
        let needle = b"first";
        let start = corrupt
            .windows(needle.len())
            .position(|window| window == needle)
            .ok_or_else(|| super::rpm_format("test member data is missing"))?;
        let byte = corrupt
            .get_mut(start)
            .ok_or_else(|| super::rpm_format("test member byte is missing"))?;
        *byte ^= 1;
        let error = open(corrupt, Limits::default()).err();
        assert_eq!(error.as_ref().map(Error::kind), Some(ErrorKind::Checksum));

        let mut truncated = build_rpm(&cpio, false, false)?;
        let _ = truncated.pop();
        let error = open(truncated, Limits::default()).err();
        assert_eq!(error.as_ref().map(Error::kind), Some(ErrorKind::Format));

        let limits = Limits::builder().max_files(2).build();
        let error = open(build_rpm(&cpio, false, false)?, limits).err();
        assert!(matches!(
            error,
            Some(Error::LimitExceeded {
                limit: LimitKind::Files,
                ..
            })
        ));

        let limits = Limits::builder().max_entry_output_bytes(5).build();
        let error = open(build_rpm(&cpio, false, false)?, limits).err();
        assert!(matches!(
            error,
            Some(Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_header_model_allocation_amplification() -> Result<()> {
        let signature = build_header(&[])?;
        let main = build_shared_string_header(100, &[b'a'; 100])?;
        assert!(main.len() < 4096);
        let mut rpm = build_lead();
        rpm.extend_from_slice(&signature);
        while rpm.len() % 8 != 0 {
            rpm.push(0);
        }
        rpm.extend_from_slice(&main);
        rpm.extend_from_slice(&build_cpio()?);
        let limits = Limits::builder().max_header_bytes(4096).build();
        let error = open(rpm, limits).err();
        assert!(matches!(
            error,
            Some(Error::LimitExceeded {
                limit: LimitKind::HeaderBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_unsupported_digest_algorithms_before_payload_decoding() -> Result<()> {
        let cpio = build_cpio()?;
        let main = build_header(&[
            int32_value(super::TAG_PAYLOAD_SHA256_ALGORITHM, 1),
            string_value(super::TAG_PAYLOAD_FORMAT, b"cpio"),
            string_value(super::TAG_PAYLOAD_COMPRESSOR, b"none"),
        ])?;
        let signature = build_header(&[])?;
        let mut rpm = build_lead();
        rpm.extend_from_slice(&signature);
        while rpm.len() % 8 != 0 {
            rpm.push(0);
        }
        rpm.extend_from_slice(&main);
        rpm.extend_from_slice(&cpio);
        assert!(matches!(
            open(rpm, Limits::default()),
            Err(Error::UnsupportedFeature { feature })
                if feature == "rpm-payload-digest-algorithm-1"
        ));

        let main = build_header(&[
            string_value(super::TAG_PAYLOAD_FORMAT, b"cpio"),
            string_value(super::TAG_PAYLOAD_COMPRESSOR, b"none"),
        ])?;
        let signature = build_header(&[string_value(
            super::SIGNATURE_TAG_SHA3_256,
            b"0000000000000000000000000000000000000000000000000000000000000000",
        )])?;
        let mut rpm = build_lead();
        rpm.extend_from_slice(&signature);
        while rpm.len() % 8 != 0 {
            rpm.push(0);
        }
        rpm.extend_from_slice(&main);
        rpm.extend_from_slice(&cpio);
        assert!(matches!(
            open(rpm, Limits::default()),
            Err(Error::UnsupportedFeature { feature })
                if feature == "rpm-header-sha3-256-verification"
        ));
        Ok(())
    }

    struct CountingSink {
        started: u64,
        finished: u64,
        bytes: u64,
    }

    impl RpmEntrySink for CountingSink {
        fn begin_entry(&mut self, _entry: &super::RpmEntry) -> Result<()> {
            self.started = self.started.saturating_add(1);
            Ok(())
        }

        fn write_entry(&mut self, _entry_index: u64, bytes: &[u8]) -> Result<()> {
            self.bytes = self
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    super::rpm_format("test sink chunk length is not representable")
                })?)
                .ok_or_else(|| super::rpm_format("test sink byte count overflows"))?;
            Ok(())
        }

        fn finish_entry(&mut self, _entry_index: u64) -> Result<()> {
            self.finished = self.finished.saturating_add(1);
            Ok(())
        }
    }

    #[test]
    fn batch_uses_shared_budget_and_observes_boundaries() -> Result<()> {
        let cpio = build_cpio()?;
        let archive = open(build_rpm(&cpio, false, false)?, Limits::default())?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut sink = CountingSink {
            started: 0,
            finished: 0,
            bytes: 0,
        };
        assert_eq!(
            archive.extract_entries_to(&mut sink, &cancellation, &mut budget)?,
            11
        );
        assert_eq!((sink.started, sink.finished, sink.bytes), (3, 3, 11));

        let mut budget = WorkBudget::bounded(0);
        let mut sink = CountingSink {
            started: 0,
            finished: 0,
            bytes: 0,
        };
        let error = archive
            .extract_entries_to(&mut sink, &cancellation, &mut budget)
            .err();
        assert!(matches!(
            error,
            Some(Error::LimitExceeded {
                limit: LimitKind::WorkUnits,
                ..
            })
        ));
        assert_eq!(sink.finished, 0);
        Ok(())
    }
}
