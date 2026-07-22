//! Bounded, unpack-only ZIP archives.

mod cp437;
mod crypto;
mod decode;
mod parse;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crypto::ZipPassword;

use crate::{
    CancellationToken, Error, LimitKind, Limits, Result, WorkBudget,
    parse_util::{CONTROL_CHUNK_SIZE, ParseControl, check_limit, try_reserve, usize_to_u64},
};

/// A ZIP compression method stored in an entry header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ZipCompressionMethod {
    /// No compression (method 0).
    Stored,
    /// Deflate (method 8).
    Deflate,
    /// Deflate64 (method 9).
    Deflate64,
    /// BZip2 (method 12).
    Bzip2,
    /// LZMA (method 14).
    Lzma,
    /// The deprecated ZIP Zstandard identifier (method 20).
    ZstandardDeprecated,
    /// Zstandard (method 93).
    Zstandard,
    /// XZ (method 95), currently listable but not decoded.
    Xz,
    /// PPMd (method 98), currently listable but not decoded.
    Ppmd,
    /// A recognized or unknown numeric method without a registered decoder.
    Unknown(u16),
}

impl ZipCompressionMethod {
    /// Returns the exact ZIP method identifier.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Stored => 0,
            Self::Deflate => 8,
            Self::Deflate64 => 9,
            Self::Bzip2 => 12,
            Self::Lzma => 14,
            Self::ZstandardDeprecated => 20,
            Self::Zstandard => 93,
            Self::Xz => 95,
            Self::Ppmd => 98,
            Self::Unknown(identifier) => identifier,
        }
    }

    const fn from_id(identifier: u16) -> Self {
        match identifier {
            0 => Self::Stored,
            8 => Self::Deflate,
            9 => Self::Deflate64,
            12 => Self::Bzip2,
            14 => Self::Lzma,
            20 => Self::ZstandardDeprecated,
            93 => Self::Zstandard,
            95 => Self::Xz,
            98 => Self::Ppmd,
            other => Self::Unknown(other),
        }
    }
}

/// Encryption applied to one ZIP entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ZipEncryption {
    /// The entry is not encrypted.
    None,
    /// Traditional PKWARE ZipCrypto.
    ZipCrypto,
    /// WinZip AES AE-1 or AE-2.
    WinZipAes {
        /// Vendor version 1 (AE-1) or 2 (AE-2).
        vendor_version: u16,
        /// AES key size in bits: 128, 192, or 256.
        key_bits: u16,
    },
    /// PKWARE Strong Encryption or central-directory encryption.
    Strong,
}

/// Calendar components represented by the ZIP DOS date/time fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipTimestamp {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl ZipTimestamp {
    /// Returns the calendar year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// Returns the month in `1..=12`.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// Returns the day in `1..=31`.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Returns the hour in `0..=23`.
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }

    /// Returns the minute in `0..=59`.
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }

    /// Returns the second in `0..=59`.
    #[must_use]
    pub const fn second(self) -> u8 {
        self.second
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WinZipAes {
    vendor_version: u16,
    key_bytes: usize,
}

/// Owned metadata for one ZIP entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZipEntry {
    index: u64,
    raw_name: Box<[u8]>,
    name: String,
    raw_comment: Box<[u8]>,
    extra: Box<[u8]>,
    compression: ZipCompressionMethod,
    encryption: ZipEncryption,
    compressed_size: u64,
    uncompressed_size: u64,
    crc32: Option<u32>,
    is_directory: bool,
    unix_mode: Option<u32>,
    modified: Option<ZipTimestamp>,
    modified_time_raw: u16,
    modified_date_raw: u16,
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    internal_attributes: u16,
    external_attributes: u32,
    local_header_offset: u64,
    data_start: u64,
    data_end: u64,
    zipcrypto_check_byte: u8,
    aes: Option<WinZipAes>,
}

impl ZipEntry {
    /// Returns the stable zero-based archive-order index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the exact central-directory name bytes.
    #[must_use]
    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    /// Returns the decoded UTF-8 or CP437 name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact central-directory comment bytes.
    #[must_use]
    pub fn raw_comment(&self) -> &[u8] {
        &self.raw_comment
    }

    /// Returns the exact central-directory extra-field bytes.
    #[must_use]
    pub fn extra_fields(&self) -> &[u8] {
        &self.extra
    }

    /// Returns the effective compression method, including the method inside
    /// a WinZip AES wrapper.
    #[must_use]
    pub const fn compression_method(&self) -> ZipCompressionMethod {
        self.compression
    }

    /// Returns the entry encryption mode.
    #[must_use]
    pub const fn encryption(&self) -> ZipEncryption {
        self.encryption
    }

    /// Returns the declared compressed size, including encryption overhead.
    #[must_use]
    pub const fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Returns the declared decoded size.
    #[must_use]
    pub const fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Returns the applicable CRC. AE-2 deliberately omits CRC trust and
    /// therefore returns `None`.
    #[must_use]
    pub const fn crc32(&self) -> Option<u32> {
        self.crc32
    }

    /// Returns whether the name denotes a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Returns the Unix mode when the creator platform supplies one.
    #[must_use]
    pub const fn unix_mode(&self) -> Option<u32> {
        self.unix_mode
    }

    /// Returns whether the Unix mode marks a symbolic link.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        match self.unix_mode {
            Some(mode) => mode & 0o170_000 == 0o120_000,
            None => false,
        }
    }

    /// Returns a validated DOS timestamp, or `None` when the stored fields are
    /// outside their representable calendar ranges.
    #[must_use]
    pub const fn modified(&self) -> Option<ZipTimestamp> {
        self.modified
    }

    /// Returns the exact packed DOS time field from the central directory.
    #[must_use]
    pub const fn modified_time_raw(&self) -> u16 {
        self.modified_time_raw
    }

    /// Returns the exact packed DOS date field from the central directory.
    #[must_use]
    pub const fn modified_date_raw(&self) -> u16 {
        self.modified_date_raw
    }

    /// Returns the raw `version made by` field.
    #[must_use]
    pub const fn version_made_by(&self) -> u16 {
        self.version_made_by
    }

    /// Returns the raw minimum-version field.
    #[must_use]
    pub const fn version_needed(&self) -> u16 {
        self.version_needed
    }

    /// Returns the general-purpose bit flags.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Returns the raw internal attributes.
    #[must_use]
    pub const fn internal_attributes(&self) -> u16 {
        self.internal_attributes
    }

    /// Returns the raw external attributes.
    #[must_use]
    pub const fn external_attributes(&self) -> u32 {
        self.external_attributes
    }

    /// Returns the validated local-header offset.
    #[must_use]
    pub const fn local_header_offset(&self) -> u64 {
        self.local_header_offset
    }
}

/// A callback boundary for natural-order ZIP extraction.
pub trait ZipEntrySink {
    /// Starts one entry. Names remain metadata and are not paths.
    fn begin_entry(&mut self, entry: &ZipEntry) -> Result<()>;

    /// Receives a bounded decoded chunk for the current entry.
    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> Result<()>;

    /// Reports completion only after authentication, size, and CRC checks.
    fn finish_entry(&mut self, entry_index: u64) -> Result<()>;
}

/// An owned, bounded ZIP archive reader.
pub struct ZipArchive {
    bytes: Box<[u8]>,
    entries: Box<[ZipEntry]>,
    comment: Box<[u8]>,
    limits: Limits,
    password: Option<ZipPassword>,
}

impl ZipArchive {
    /// Opens in-memory ZIP bytes without a password.
    ///
    /// # Errors
    ///
    /// Returns a typed format, limit, unsupported-feature, cancellation, work,
    /// or I/O error. Entry payloads are not decoded while listing.
    pub fn open_bytes(
        bytes: Vec<u8>,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(bytes, limits, None, cancellation, budget)
    }

    /// Opens in-memory ZIP bytes with a byte-preserving per-archive password.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`ZipArchive::open_bytes`]. A password
    /// is retained in zeroizing storage only for this archive instance.
    pub fn open_bytes_with_password(
        bytes: Vec<u8>,
        limits: Limits,
        password: &[u8],
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        Self::open_bytes_inner(
            bytes,
            limits,
            Some(ZipPassword::new(password)?),
            cancellation,
            budget,
        )
    }

    fn open_bytes_inner(
        bytes: Vec<u8>,
        limits: Limits,
        password: Option<ZipPassword>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        check_limit(
            usize_to_u64(bytes.len(), "ZIP input size is not representable as u64")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        let mut control = ParseControl::new(cancellation, budget);
        let parsed = parse::parse(&bytes, limits, &mut control)?;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            entries: parsed.entries.into_boxed_slice(),
            comment: parsed.comment,
            limits,
            password,
        })
    }

    /// Opens a ZIP path without deriving any extraction destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for path reads or any opening error documented by
    /// [`ZipArchive::open_bytes`].
    pub fn open_path(
        path: &Path,
        limits: Limits,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let bytes = read_path(path, limits, cancellation, budget)?;
        Self::open_bytes(bytes, limits, cancellation, budget)
    }

    /// Opens a ZIP path with a byte-preserving per-archive password.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`ZipArchive::open_path`] and
    /// [`ZipArchive::open_bytes_with_password`].
    pub fn open_path_with_password(
        path: &Path,
        limits: Limits,
        password: &[u8],
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<Self> {
        let bytes = read_path(path, limits, cancellation, budget)?;
        Self::open_bytes_with_password(bytes, limits, password, cancellation, budget)
    }

    /// Returns entries in central-directory order, including duplicates.
    #[must_use]
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Returns one entry by stable archive-order index.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&ZipEntry> {
        let index = usize::try_from(index).ok()?;
        self.entries.get(index)
    }

    /// Returns the limits retained for later extraction operations.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns the retained ZIP input byte count.
    #[must_use]
    pub fn retained_input_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the raw archive comment.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Returns retained password capacity, useful for resource accounting.
    #[must_use]
    pub fn retained_password_bytes(&self) -> usize {
        self.password
            .as_ref()
            .map_or(0, ZipPassword::retained_bytes)
    }

    /// Decodes and verifies one entry before copying it to the caller's writer.
    ///
    /// No member name is interpreted as a filesystem path. Output may have
    /// reached the writer if the writer itself later fails; archive integrity
    /// is checked before the first write.
    ///
    /// # Errors
    ///
    /// Returns typed index, method, feature, password, authentication, checksum,
    /// limit, cancellation, work, or writer errors.
    pub fn extract_entry_to(
        &self,
        entry_index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let entry = self.required_entry(entry_index)?;
        let mut control = ParseControl::new(cancellation, budget);
        let decoded = decode::decode_entry(
            &self.bytes,
            entry,
            self.password.as_ref(),
            self.limits,
            self.limits
                .max_entry_output_bytes()
                .min(self.limits.max_total_output_bytes()),
            &mut control,
        )?;
        for chunk in decoded.chunks(CONTROL_CHUNK_SIZE) {
            control.checkpoint(usize_to_u64(
                chunk.len(),
                "ZIP output chunk length is not representable as u64",
            )?)?;
            writer.write_all(chunk).map_err(Error::Io)?;
        }
        usize_to_u64(
            decoded.len(),
            "ZIP decoded output size is not representable as u64",
        )
    }

    /// Decodes all entries in central-directory order using one shared output
    /// limit, work budget, and cancellation token.
    ///
    /// # Errors
    ///
    /// Returns the first extraction or sink error. `finish_entry` is never
    /// called until that entry's integrity checks have succeeded.
    pub fn extract_entries_to(
        &self,
        sink: &mut dyn ZipEntrySink,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> Result<u64> {
        let mut control = ParseControl::new(cancellation, budget);
        let mut total = 0_u64;
        for entry in self.entries.iter() {
            let remaining = self
                .limits
                .max_total_output_bytes()
                .checked_sub(total)
                .ok_or(Error::LimitExceeded {
                    limit: LimitKind::TotalOutputBytes,
                    requested: total,
                    maximum: self.limits.max_total_output_bytes(),
                })?;
            let maximum = remaining.min(self.limits.max_entry_output_bytes());
            let decoded = decode::decode_entry(
                &self.bytes,
                entry,
                self.password.as_ref(),
                self.limits,
                maximum,
                &mut control,
            )?;
            let decoded_size = usize_to_u64(
                decoded.len(),
                "ZIP decoded output size is not representable as u64",
            )?;
            total = total
                .checked_add(decoded_size)
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
            sink.begin_entry(entry)?;
            for chunk in decoded.chunks(CONTROL_CHUNK_SIZE) {
                control.checkpoint(usize_to_u64(
                    chunk.len(),
                    "ZIP sink chunk length is not representable as u64",
                )?)?;
                sink.write_entry(entry.index, chunk)?;
            }
            sink.finish_entry(entry.index)?;
        }
        Ok(total)
    }

    /// Decodes every entry and discards its verified bytes.
    ///
    /// # Errors
    ///
    /// Returns the first extraction error and shares total output/work limits
    /// across the complete verification operation.
    pub fn verify(&self, cancellation: &CancellationToken, budget: &mut WorkBudget) -> Result<()> {
        struct VerifySink;
        impl ZipEntrySink for VerifySink {
            fn begin_entry(&mut self, _entry: &ZipEntry) -> Result<()> {
                Ok(())
            }

            fn write_entry(&mut self, _entry_index: u64, _bytes: &[u8]) -> Result<()> {
                Ok(())
            }

            fn finish_entry(&mut self, _entry_index: u64) -> Result<()> {
                Ok(())
            }
        }
        self.extract_entries_to(&mut VerifySink, cancellation, budget)?;
        Ok(())
    }

    fn required_entry(&self, index: u64) -> Result<&ZipEntry> {
        let index = usize::try_from(index).map_err(|_| zip_format("entry index is too large"))?;
        self.entries
            .get(index)
            .ok_or_else(|| zip_format("entry index is out of range"))
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
        .map_err(|_| zip_format("path size is not representable on this platform"))?;
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
            .ok_or_else(|| zip_format("path read returned an invalid byte count"))?;
        budget.charge(usize_to_u64(
            chunk.len(),
            "ZIP input chunk length is not representable as u64",
        )?)?;
        let requested = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| zip_format("ZIP path input size overflows"))?;
        check_limit(
            usize_to_u64(requested, "ZIP path input size is not representable as u64")?,
            limits.max_total_input_bytes(),
            LimitKind::TotalInputBytes,
        )?;
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn zip_format(detail: &'static str) -> Error {
    Error::Format {
        detail: format!("ZIP: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use aes::{
        Aes128, Aes192, Aes256,
        cipher::{KeyIvInit, StreamCipher},
    };
    use ctr::Ctr128LE;
    use hmac::{Hmac, KeyInit, Mac};
    use pbkdf2::pbkdf2_hmac;
    use sha1::Sha1;

    use super::{ZipArchive, ZipCompressionMethod, ZipEncryption};
    use crate::{
        CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget,
        checksum::Crc32, parse_util::try_reserve,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[derive(Clone)]
    struct FixtureEntry {
        name: Vec<u8>,
        decoded: Vec<u8>,
        payload: Vec<u8>,
        method: u16,
        version_needed: u16,
        flags: u16,
        extra: Vec<u8>,
        crc: u32,
        mode: u32,
    }

    struct BuiltZip {
        bytes: Vec<u8>,
        data_offsets: Vec<usize>,
    }

    fn checksum(bytes: &[u8]) -> Result<u32> {
        Crc32::checksum(bytes)
    }

    fn stored(name: &[u8], decoded: &[u8]) -> Result<FixtureEntry> {
        Ok(FixtureEntry {
            name: name.to_vec(),
            decoded: decoded.to_vec(),
            payload: decoded.to_vec(),
            method: 0,
            version_needed: 20,
            flags: 0,
            extra: Vec::new(),
            crc: checksum(decoded)?,
            mode: 0o100_644,
        })
    }

    fn deflated(name: &[u8], decoded: &[u8]) -> Result<FixtureEntry> {
        Ok(FixtureEntry {
            name: name.to_vec(),
            decoded: decoded.to_vec(),
            payload: miniz_oxide::deflate::compress_to_vec(decoded, 6),
            method: 8,
            version_needed: 20,
            flags: 0,
            extra: Vec::new(),
            crc: checksum(decoded)?,
            mode: 0o100_644,
        })
    }

    fn hex_nibble(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
            b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
            b'A'..=b'F' => Ok(byte.saturating_sub(b'A').saturating_add(10)),
            _ => Err(super::zip_format("test fixture contains non-hex data")),
        }
    }

    fn decode_hex(encoded: &str) -> Result<Vec<u8>> {
        let mut chunks = encoded.as_bytes().chunks_exact(2);
        let mut output = Vec::new();
        output.try_reserve_exact(encoded.len() / 2).map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "test fixture allocation failed",
            ))
        })?;
        for chunk in chunks.by_ref() {
            let high = chunk
                .first()
                .copied()
                .ok_or_else(|| super::zip_format("test fixture high nibble is missing"))?;
            let low = chunk
                .get(1)
                .copied()
                .ok_or_else(|| super::zip_format("test fixture low nibble is missing"))?;
            output.push(
                hex_nibble(high)?
                    .checked_mul(16)
                    .and_then(|value| value.checked_add(hex_nibble(low).ok()?))
                    .ok_or_else(|| super::zip_format("test fixture byte overflows"))?,
            );
        }
        if !chunks.remainder().is_empty() {
            return Err(super::zip_format("test fixture has an odd hex length"));
        }
        Ok(output)
    }

    fn encoded_fixture(
        name: &[u8],
        decoded: &[u8],
        encoded: &str,
        method: u16,
        version_needed: u16,
        flags: u16,
    ) -> Result<FixtureEntry> {
        Ok(FixtureEntry {
            name: name.to_vec(),
            decoded: decoded.to_vec(),
            payload: decode_hex(encoded)?,
            method,
            version_needed,
            flags,
            extra: Vec::new(),
            crc: checksum(decoded)?,
            mode: 0o100_644,
        })
    }

    fn append_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn append_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn append_u64(output: &mut Vec<u8>, value: u64) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn u16_len(value: usize) -> Result<u16> {
        u16::try_from(value).map_err(|_| super::zip_format("test length exceeds u16"))
    }

    fn u32_len(value: usize) -> Result<u32> {
        u32::try_from(value).map_err(|_| super::zip_format("test length exceeds u32"))
    }

    fn build_zip(prefix: &[u8], fixtures: &[FixtureEntry]) -> Result<BuiltZip> {
        let mut output = prefix.to_vec();
        let zip_start = output.len();
        let mut local_offsets = Vec::new();
        let mut data_offsets = Vec::new();
        try_reserve(&mut local_offsets, fixtures.len())?;
        try_reserve(&mut data_offsets, fixtures.len())?;
        for fixture in fixtures {
            let relative_offset = output
                .len()
                .checked_sub(zip_start)
                .ok_or_else(|| super::zip_format("test ZIP offset underflows"))?;
            local_offsets.push(u32_len(relative_offset)?);
            append_u32(&mut output, 0x0403_4b50);
            append_u16(&mut output, fixture.version_needed);
            append_u16(&mut output, fixture.flags);
            append_u16(&mut output, fixture.method);
            append_u16(&mut output, 0);
            append_u16(&mut output, 0x5021);
            append_u32(&mut output, fixture.crc);
            append_u32(&mut output, u32_len(fixture.payload.len())?);
            append_u32(&mut output, u32_len(fixture.decoded.len())?);
            append_u16(&mut output, u16_len(fixture.name.len())?);
            append_u16(&mut output, u16_len(fixture.extra.len())?);
            output.extend_from_slice(&fixture.name);
            output.extend_from_slice(&fixture.extra);
            data_offsets.push(output.len());
            output.extend_from_slice(&fixture.payload);
        }
        let directory_start = output.len();
        for (fixture, local_offset) in fixtures.iter().zip(local_offsets.iter().copied()) {
            append_u32(&mut output, 0x0201_4b50);
            append_u16(&mut output, (3_u16 << 8) | 63);
            append_u16(&mut output, fixture.version_needed);
            append_u16(&mut output, fixture.flags);
            append_u16(&mut output, fixture.method);
            append_u16(&mut output, 0);
            append_u16(&mut output, 0x5021);
            append_u32(&mut output, fixture.crc);
            append_u32(&mut output, u32_len(fixture.payload.len())?);
            append_u32(&mut output, u32_len(fixture.decoded.len())?);
            append_u16(&mut output, u16_len(fixture.name.len())?);
            append_u16(&mut output, u16_len(fixture.extra.len())?);
            append_u16(&mut output, 0);
            append_u16(&mut output, 0);
            append_u16(&mut output, 0);
            append_u32(&mut output, fixture.mode << 16);
            append_u32(&mut output, local_offset);
            output.extend_from_slice(&fixture.name);
            output.extend_from_slice(&fixture.extra);
        }
        let directory_size = output
            .len()
            .checked_sub(directory_start)
            .ok_or_else(|| super::zip_format("test directory size underflows"))?;
        let relative_directory = directory_start
            .checked_sub(zip_start)
            .ok_or_else(|| super::zip_format("test directory offset underflows"))?;
        append_u32(&mut output, 0x0605_4b50);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0);
        append_u16(&mut output, u16_len(fixtures.len())?);
        append_u16(&mut output, u16_len(fixtures.len())?);
        append_u32(&mut output, u32_len(directory_size)?);
        append_u32(&mut output, u32_len(relative_directory)?);
        append_u16(&mut output, 0);
        Ok(BuiltZip {
            bytes: output,
            data_offsets,
        })
    }

    fn build_zip64_sfx(prefix: &[u8], fixture: &FixtureEntry) -> Result<BuiltZip> {
        let mut output = prefix.to_vec();
        let image_start = output.len();
        let mut local_extra = Vec::new();
        append_u16(&mut local_extra, 1);
        append_u16(&mut local_extra, 16);
        append_u64(
            &mut local_extra,
            u64::try_from(fixture.decoded.len())
                .map_err(|_| super::zip_format("test decoded size exceeds u64"))?,
        );
        append_u64(
            &mut local_extra,
            u64::try_from(fixture.payload.len())
                .map_err(|_| super::zip_format("test payload size exceeds u64"))?,
        );
        append_u32(&mut output, 0x0403_4b50);
        append_u16(&mut output, 45);
        append_u16(&mut output, fixture.flags);
        append_u16(&mut output, fixture.method);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0x5021);
        append_u32(&mut output, fixture.crc);
        append_u32(&mut output, u32::MAX);
        append_u32(&mut output, u32::MAX);
        append_u16(&mut output, u16_len(fixture.name.len())?);
        append_u16(&mut output, u16_len(local_extra.len())?);
        output.extend_from_slice(&fixture.name);
        output.extend_from_slice(&local_extra);
        let data_offset = output.len();
        output.extend_from_slice(&fixture.payload);

        let directory_start = output.len();
        let mut central_extra = Vec::new();
        append_u16(&mut central_extra, 1);
        append_u16(&mut central_extra, 24);
        append_u64(
            &mut central_extra,
            u64::try_from(fixture.decoded.len())
                .map_err(|_| super::zip_format("test decoded size exceeds u64"))?,
        );
        append_u64(
            &mut central_extra,
            u64::try_from(fixture.payload.len())
                .map_err(|_| super::zip_format("test payload size exceeds u64"))?,
        );
        append_u64(&mut central_extra, 0);
        append_u32(&mut output, 0x0201_4b50);
        append_u16(&mut output, (3_u16 << 8) | 63);
        append_u16(&mut output, 45);
        append_u16(&mut output, fixture.flags);
        append_u16(&mut output, fixture.method);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0x5021);
        append_u32(&mut output, fixture.crc);
        append_u32(&mut output, u32::MAX);
        append_u32(&mut output, u32::MAX);
        append_u16(&mut output, u16_len(fixture.name.len())?);
        append_u16(&mut output, u16_len(central_extra.len())?);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0);
        append_u32(&mut output, fixture.mode << 16);
        append_u32(&mut output, u32::MAX);
        output.extend_from_slice(&fixture.name);
        output.extend_from_slice(&central_extra);

        let directory_size = output
            .len()
            .checked_sub(directory_start)
            .ok_or_else(|| super::zip_format("test ZIP64 directory size underflows"))?;
        let relative_directory = directory_start
            .checked_sub(image_start)
            .ok_or_else(|| super::zip_format("test ZIP64 directory offset underflows"))?;
        let zip64_eocd = output
            .len()
            .checked_sub(image_start)
            .ok_or_else(|| super::zip_format("test ZIP64 EOCD offset underflows"))?;
        append_u32(&mut output, 0x0606_4b50);
        append_u64(&mut output, 44);
        append_u16(&mut output, (3_u16 << 8) | 63);
        append_u16(&mut output, 45);
        append_u32(&mut output, 0);
        append_u32(&mut output, 0);
        append_u64(&mut output, 1);
        append_u64(&mut output, 1);
        append_u64(
            &mut output,
            u64::try_from(directory_size)
                .map_err(|_| super::zip_format("test ZIP64 directory size exceeds u64"))?,
        );
        append_u64(
            &mut output,
            u64::try_from(relative_directory)
                .map_err(|_| super::zip_format("test ZIP64 directory offset exceeds u64"))?,
        );
        append_u32(&mut output, 0x0706_4b50);
        append_u32(&mut output, 0);
        append_u64(
            &mut output,
            u64::try_from(zip64_eocd)
                .map_err(|_| super::zip_format("test ZIP64 EOCD offset exceeds u64"))?,
        );
        append_u32(&mut output, 1);
        append_u32(&mut output, 0x0605_4b50);
        append_u16(&mut output, 0);
        append_u16(&mut output, 0);
        append_u16(&mut output, u16::MAX);
        append_u16(&mut output, u16::MAX);
        append_u32(&mut output, u32::MAX);
        append_u32(&mut output, u32::MAX);
        append_u16(&mut output, 0);
        Ok(BuiltZip {
            bytes: output,
            data_offsets: vec![data_offset],
        })
    }

    fn open(bytes: Vec<u8>) -> Result<ZipArchive> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        ZipArchive::open_bytes(bytes, Limits::default(), &cancellation, &mut budget)
    }

    fn extract(archive: &ZipArchive, index: u64) -> Result<Vec<u8>> {
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut output = Vec::new();
        archive.extract_entry_to(index, &mut output, &cancellation, &mut budget)?;
        Ok(output)
    }

    #[test]
    fn lists_and_extracts_stored_deflate_duplicates_cp437_and_sfx() -> Result<()> {
        let mut directory = stored(b"empty/", b"")?;
        directory.mode = 0o040_755;
        let fixtures = [
            stored(b"same.txt", b"first")?,
            deflated(b"same.txt", b"second second second")?,
            stored(&[0x82, b'.', b't', b'x', b't'], b"cp437")?,
            directory,
        ];
        let built = build_zip(b"synthetic-sfx-prefix", &fixtures)?;
        let archive = open(built.bytes)?;
        assert_eq!(archive.entries().len(), 4);
        assert_eq!(
            archive.entries().first().map(|entry| entry.name()),
            Some("same.txt")
        );
        assert_eq!(
            archive.entries().get(1).map(|entry| entry.name()),
            Some("same.txt")
        );
        assert_eq!(
            archive.entries().get(2).map(|entry| entry.name()),
            Some("é.txt")
        );
        assert_eq!(
            archive
                .entries()
                .get(1)
                .map(|entry| entry.compression_method()),
            Some(ZipCompressionMethod::Deflate)
        );
        assert_eq!(extract(&archive, 0)?, b"first");
        assert_eq!(extract(&archive, 1)?, b"second second second");
        assert_eq!(extract(&archive, 2)?, b"cp437");
        assert_eq!(extract(&archive, 3)?, b"");
        assert_eq!(
            archive.entries().get(3).map(|entry| entry.is_directory()),
            Some(true)
        );
        Ok(())
    }

    #[test]
    fn zip64_sfx_offsets_are_resolved_from_the_embedded_image() -> Result<()> {
        let prefix = b"synthetic executable prefix";
        let built = build_zip64_sfx(prefix, &stored(b"zip64.txt", b"zip64 payload")?)?;
        let archive = open(built.bytes.clone())?;
        assert_eq!(extract(&archive, 0)?, b"zip64 payload");
        assert_eq!(
            archive
                .entries()
                .first()
                .map(|entry| entry.local_header_offset()),
            Some(
                u64::try_from(prefix.len()).map_err(|_| {
                    super::zip_format("test prefix length is not representable")
                })?
            )
        );

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let limits = Limits::builder()
            .sfx_scan_limit(
                u64::try_from(prefix.len().saturating_sub(1))
                    .map_err(|_| super::zip_format("test SFX limit is not representable"))?,
            )
            .build();
        let error = ZipArchive::open_bytes(built.bytes, limits, &cancellation, &mut budget).err();
        assert!(matches!(
            error,
            Some(Error::LimitExceeded {
                limit: LimitKind::SfxScanBytes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn extracts_all_declared_zip_compression_methods_and_rejects_corruption() -> Result<()> {
        // BZip2 and ZIP-LZMA were generated by Python 3.12's standard
        // `zipfile` encoder. Zstandard was generated by zstd 1.5.7. The
        // Deflate64 fixture is a specification-defined stored block. These
        // encoders are fixture-generation oracles only, not dependencies.
        const BZIP2: &str = "425a6839314159265359831f87ad00011fd180001040002e24c03020007040d03402aa4d3d06a7ea940b068160c8380d8380a06c10101016080e83a080fc5dc914e142420c7e1eb4";
        const LZMA: &str = "090405005d00008000003d1a4a62295e8036040de6f14ecc1e62c65d267cb16e6600f237ed1ffffd93e000";
        const ZSTD: &str =
            "28b52ffd0468cd0000907a697020636f646563207061796c6f61640a0100565435c3dc311b99";
        const DEFLATE64: &str = "010300fcff616263";
        let decoded = b"zip codec payload\n".repeat(32);
        let fixtures = [
            encoded_fixture(b"bzip2.bin", &decoded, BZIP2, 12, 46, 0)?,
            encoded_fixture(b"lzma.bin", &decoded, LZMA, 14, 63, 2)?,
            encoded_fixture(b"zstd.bin", &decoded, ZSTD, 93, 63, 0)?,
            encoded_fixture(b"deflate64.bin", b"abc", DEFLATE64, 9, 21, 0)?,
        ];
        for fixture in &fixtures {
            let built = build_zip(&[], std::slice::from_ref(fixture))?;
            let archive = open(built.bytes.clone())?;
            assert_eq!(extract(&archive, 0)?, fixture.decoded);
            assert_eq!(
                archive
                    .entries()
                    .first()
                    .map(|entry| entry.compression_method().id()),
                Some(fixture.method)
            );

            let mut corrupt = built.bytes;
            let data_start = built
                .data_offsets
                .first()
                .copied()
                .ok_or_else(|| super::zip_format("test data offset is missing"))?;
            let mutation = data_start
                .checked_add(fixture.payload.len() / 2)
                .ok_or_else(|| super::zip_format("test mutation offset overflows"))?;
            let byte = corrupt
                .get_mut(mutation)
                .ok_or_else(|| super::zip_format("test compressed byte is missing"))?;
            *byte ^= 1;
            let archive = open(corrupt)?;
            assert!(extract(&archive, 0).is_err());
        }
        Ok(())
    }

    struct TestZipCryptoKeys {
        key0: u32,
        key1: u32,
        key2: u32,
    }

    impl TestZipCryptoKeys {
        fn new(password: &[u8]) -> Self {
            let mut keys = Self {
                key0: 0x1234_5678,
                key1: 0x2345_6789,
                key2: 0x3456_7890,
            };
            for byte in password.iter().copied() {
                keys.update(byte);
            }
            keys
        }

        fn update(&mut self, byte: u8) {
            self.key0 = test_crc_byte(self.key0, byte);
            self.key1 = self
                .key1
                .wrapping_add(self.key0 & 0xff)
                .wrapping_mul(134_775_813)
                .wrapping_add(1);
            let [high, _, _, _] = self.key1.to_be_bytes();
            self.key2 = test_crc_byte(self.key2, high);
        }

        fn encrypt(&mut self, plaintext: u8) -> u8 {
            let temporary = self.key2 | 2;
            let [_, mask, _, _] = temporary.wrapping_mul(temporary ^ 1).to_le_bytes();
            self.update(plaintext);
            plaintext ^ mask
        }
    }

    fn test_crc_byte(mut value: u32, byte: u8) -> u32 {
        value ^= u32::from(byte);
        for _ in 0..8 {
            value = if value & 1 == 0 {
                value >> 1
            } else {
                (value >> 1) ^ 0xedb8_8320
            };
        }
        value
    }

    fn zipcrypto(name: &[u8], decoded: &[u8]) -> Result<FixtureEntry> {
        zipcrypto_fixture(stored(name, decoded)?)
    }

    fn zipcrypto_fixture(fixture: FixtureEntry) -> Result<FixtureEntry> {
        let crc = checksum(&fixture.decoded)?;
        let mut header = [0_u8; 12];
        let [check, _, _, _] = crc.to_be_bytes();
        if let Some(last) = header.last_mut() {
            *last = check;
        }
        let mut keys = TestZipCryptoKeys::new(PASSWORD);
        let mut payload = Vec::new();
        payload.extend(header.iter().copied().map(|byte| keys.encrypt(byte)));
        payload.extend(
            fixture
                .payload
                .iter()
                .copied()
                .map(|byte| keys.encrypt(byte)),
        );
        Ok(FixtureEntry {
            name: fixture.name,
            decoded: fixture.decoded,
            payload,
            method: fixture.method,
            version_needed: fixture.version_needed,
            flags: fixture.flags | 1,
            extra: fixture.extra,
            crc,
            mode: fixture.mode,
        })
    }

    #[test]
    fn traditional_encryption_requires_and_verifies_password() -> Result<()> {
        let built = build_zip(&[], &[zipcrypto(b"secret.txt", b"secret bytes")?])?;
        let archive = open(built.bytes.clone())?;
        assert_eq!(
            archive.entries().first().map(|entry| entry.encryption()),
            Some(ZipEncryption::ZipCrypto)
        );
        assert_eq!(
            extract(&archive, 0).as_ref().err().map(Error::kind),
            Some(ErrorKind::PasswordRequired)
        );

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let wrong = ZipArchive::open_bytes_with_password(
            built.bytes.clone(),
            Limits::default(),
            b"wrong",
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(
            extract(&wrong, 0).as_ref().err().map(Error::kind),
            Some(ErrorKind::WrongPasswordOrCorrupt)
        );

        let mut budget = WorkBudget::unlimited();
        let correct = ZipArchive::open_bytes_with_password(
            built.bytes,
            Limits::default(),
            PASSWORD,
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(extract(&correct, 0)?, b"secret bytes");

        let compressed = zipcrypto_fixture(deflated(
            b"compressed-secret.txt",
            b"compressed secret bytes compressed secret bytes",
        )?)?;
        let built = build_zip(&[], &[compressed])?;
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_bytes_with_password(
            built.bytes,
            Limits::default(),
            PASSWORD,
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(
            extract(&archive, 0)?,
            b"compressed secret bytes compressed secret bytes"
        );
        Ok(())
    }

    fn aes_extra(vendor_version: u16, strength: u8, method: u16) -> Vec<u8> {
        let mut extra = Vec::new();
        append_u16(&mut extra, 0x9901);
        append_u16(&mut extra, 7);
        append_u16(&mut extra, vendor_version);
        extra.extend_from_slice(b"AE");
        extra.push(strength);
        append_u16(&mut extra, method);
        extra
    }

    fn apply_test_ctr(key: &[u8], bytes: &mut [u8]) -> Result<()> {
        let mut counter = [0_u8; 16];
        if let Some(first) = counter.first_mut() {
            *first = 1;
        }
        match key.len() {
            16 => Ctr128LE::<Aes128>::new_from_slices(key, &counter)
                .map_err(|_| super::zip_format("test AES-128 key is invalid"))?
                .apply_keystream(bytes),
            24 => Ctr128LE::<Aes192>::new_from_slices(key, &counter)
                .map_err(|_| super::zip_format("test AES-192 key is invalid"))?
                .apply_keystream(bytes),
            32 => Ctr128LE::<Aes256>::new_from_slices(key, &counter)
                .map_err(|_| super::zip_format("test AES-256 key is invalid"))?
                .apply_keystream(bytes),
            _ => return Err(super::zip_format("test AES key size is invalid")),
        }
        Ok(())
    }

    fn winzip_aes(name: &[u8], decoded: &[u8], strength: u8) -> Result<FixtureEntry> {
        winzip_aes_fixture(stored(name, decoded)?, strength, 2)
    }

    fn winzip_aes_fixture(
        fixture: FixtureEntry,
        strength: u8,
        vendor_version: u16,
    ) -> Result<FixtureEntry> {
        let key_bytes = match strength {
            1 => 16_usize,
            2 => 24_usize,
            3 => 32_usize,
            _ => return Err(super::zip_format("test AES strength is invalid")),
        };
        let salt_bytes = key_bytes / 2;
        let salt = vec![strength; salt_bytes];
        let mut derived = vec![0_u8; key_bytes * 2 + 2];
        pbkdf2_hmac::<Sha1>(PASSWORD, &salt, 1_000, &mut derived);
        let encryption_key = derived
            .get(..key_bytes)
            .ok_or_else(|| super::zip_format("test AES encryption key is truncated"))?;
        let authentication_key = derived
            .get(key_bytes..key_bytes * 2)
            .ok_or_else(|| super::zip_format("test AES authentication key is truncated"))?;
        let verifier = derived
            .get(key_bytes * 2..)
            .ok_or_else(|| super::zip_format("test AES verifier is truncated"))?;
        let mut ciphertext = fixture.payload;
        apply_test_ctr(encryption_key, &mut ciphertext)?;
        let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(authentication_key)
            .map_err(|_| super::zip_format("test AES HMAC key is invalid"))?;
        mac.update(&ciphertext);
        let authentication = mac.finalize().into_bytes();
        let mut payload = salt;
        payload.extend_from_slice(verifier);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(
            authentication
                .get(..10)
                .ok_or_else(|| super::zip_format("test AES authentication is truncated"))?,
        );
        let crc = if vendor_version == 1 {
            checksum(&fixture.decoded)?
        } else {
            0
        };
        Ok(FixtureEntry {
            name: fixture.name,
            decoded: fixture.decoded,
            payload,
            method: 99,
            version_needed: 51,
            flags: fixture.flags | 1,
            extra: aes_extra(vendor_version, strength, fixture.method),
            crc,
            mode: fixture.mode,
        })
    }

    #[test]
    fn winzip_aes_128_192_and_256_authenticate_before_success() -> Result<()> {
        for strength in [1_u8, 2, 3] {
            let built = build_zip(
                &[],
                &[winzip_aes(b"aes.txt", b"authenticated payload", strength)?],
            )?;
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::unlimited();
            let archive = ZipArchive::open_bytes_with_password(
                built.bytes.clone(),
                Limits::default(),
                PASSWORD,
                &cancellation,
                &mut budget,
            )?;
            assert_eq!(extract(&archive, 0)?, b"authenticated payload");
            assert_eq!(
                archive.entries().first().and_then(|entry| entry.crc32()),
                None
            );

            let mut corrupt = built.bytes;
            let data_offset = built
                .data_offsets
                .first()
                .copied()
                .ok_or_else(|| super::zip_format("test data offset is missing"))?;
            let ciphertext_offset = data_offset
                .checked_add(usize::from(strength) * 4 + 2)
                .ok_or_else(|| super::zip_format("test ciphertext offset overflows"))?;
            let byte = corrupt
                .get_mut(ciphertext_offset)
                .ok_or_else(|| super::zip_format("test ciphertext byte is missing"))?;
            *byte ^= 1;
            let mut budget = WorkBudget::unlimited();
            let corrupt_archive = ZipArchive::open_bytes_with_password(
                corrupt,
                Limits::default(),
                PASSWORD,
                &cancellation,
                &mut budget,
            )?;
            assert_eq!(
                extract(&corrupt_archive, 0).as_ref().err().map(Error::kind),
                Some(ErrorKind::WrongPasswordOrCorrupt)
            );
        }

        let decoded = b"AE-1 compressed payload AE-1 compressed payload";
        let fixture = winzip_aes_fixture(deflated(b"ae1.bin", decoded)?, 3, 1)?;
        let built = build_zip(&[], &[fixture])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_bytes_with_password(
            built.bytes,
            Limits::default(),
            PASSWORD,
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(extract(&archive, 0)?, decoded);
        assert_eq!(
            archive.entries().first().and_then(|entry| entry.crc32()),
            Some(checksum(decoded)?)
        );
        Ok(())
    }

    #[test]
    fn empty_winzip_aes_member_still_requires_valid_authentication() -> Result<()> {
        let built = build_zip(&[], &[winzip_aes(b"empty.txt", b"", 3)?])?;
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let archive = ZipArchive::open_bytes_with_password(
            built.bytes.clone(),
            Limits::default(),
            PASSWORD,
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(extract(&archive, 0)?, b"");

        let mut corrupt = built.bytes;
        let data_offset = built
            .data_offsets
            .first()
            .copied()
            .ok_or_else(|| super::zip_format("test data offset is missing"))?;
        let authentication_offset = data_offset
            .checked_add(3_usize * 4 + 2)
            .ok_or_else(|| super::zip_format("test authentication offset overflows"))?;
        let byte = corrupt
            .get_mut(authentication_offset)
            .ok_or_else(|| super::zip_format("test authentication byte is missing"))?;
        *byte ^= 1;
        let mut budget = WorkBudget::unlimited();
        let corrupt_archive = ZipArchive::open_bytes_with_password(
            corrupt,
            Limits::default(),
            PASSWORD,
            &cancellation,
            &mut budget,
        )?;
        assert_eq!(
            extract(&corrupt_archive, 0).as_ref().err().map(Error::kind),
            Some(ErrorKind::WrongPasswordOrCorrupt)
        );
        Ok(())
    }

    #[test]
    fn corruption_truncation_and_limits_are_typed() -> Result<()> {
        let built = build_zip(&[], &[stored(b"file.txt", b"payload")?])?;
        let mut corrupt = built.bytes.clone();
        let data_offset = built
            .data_offsets
            .first()
            .copied()
            .ok_or_else(|| super::zip_format("test data offset is missing"))?;
        let byte = corrupt
            .get_mut(data_offset)
            .ok_or_else(|| super::zip_format("test data byte is missing"))?;
        *byte ^= 1;
        let archive = open(corrupt)?;
        assert_eq!(
            extract(&archive, 0).as_ref().err().map(Error::kind),
            Some(ErrorKind::Checksum)
        );

        for length in 0..built.bytes.len() {
            let prefix = built
                .bytes
                .get(..length)
                .ok_or_else(|| super::zip_format("test truncation range is invalid"))?
                .to_vec();
            assert!(
                open(prefix).is_err(),
                "truncation {length} unexpectedly opened"
            );
        }

        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let limited = Limits::builder().max_files(0).build();
        let error =
            ZipArchive::open_bytes(built.bytes.clone(), limited, &cancellation, &mut budget);
        assert!(matches!(
            error,
            Err(crate::Error::LimitExceeded {
                limit: LimitKind::Files,
                ..
            })
        ));

        let mut budget = WorkBudget::unlimited();
        let output_limited = Limits::builder().max_entry_output_bytes(3).build();
        let error = ZipArchive::open_bytes(built.bytes, output_limited, &cancellation, &mut budget);
        assert!(matches!(
            error,
            Err(crate::Error::LimitExceeded {
                limit: LimitKind::EntryOutputBytes,
                ..
            })
        ));
        Ok(())
    }
}
