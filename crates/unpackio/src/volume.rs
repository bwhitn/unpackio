//! Bounded abstract access to one or more sequential archive volumes.

use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::Arc,
};

use crate::{
    Error, LimitKind, Limits, Result,
    parse_util::{CONTROL_CHUNK_SIZE, ParseControl, check_limit, format_error, try_reserve},
};

/// A seekable archive volume with a discoverable byte length.
pub trait Volume: Read + Seek {
    /// Returns the volume length without changing its logical read position.
    fn len(&mut self) -> io::Result<u64>;

    /// Returns whether the volume contains no bytes.
    fn is_empty(&mut self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }
}

/// Identifies the exact volume requested by the archive layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeRequest {
    index: u64,
    expected_name: String,
}

impl VolumeRequest {
    /// Creates a zero-based request with an exact display name.
    #[must_use]
    pub fn new(index: u64, expected_name: impl Into<String>) -> Self {
        Self {
            index,
            expected_name: expected_name.into(),
        }
    }

    /// Returns the zero-based sequential volume index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the expected volume name for diagnostics or lookup.
    #[must_use]
    pub fn expected_name(&self) -> &str {
        &self.expected_name
    }
}

/// Supplies volume bytes without coupling parsing to paths or callbacks.
pub trait VolumeProvider {
    /// Opens the requested volume or returns [`Error::MissingVolume`].
    fn open_volume(&mut self, request: &VolumeRequest) -> Result<Box<dyn Volume>>;
}

struct MemoryVolume {
    cursor: Cursor<Arc<[u8]>>,
}

impl Read for MemoryVolume {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(bytes)
    }
}

impl Seek for MemoryVolume {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

impl Volume for MemoryVolume {
    fn len(&mut self) -> io::Result<u64> {
        u64::try_from(self.cursor.get_ref().len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "memory volume length is not representable as u64",
            )
        })
    }
}

/// An in-memory provider suitable for byte APIs and callback adapters.
#[derive(Clone, Debug, Default)]
pub struct MemoryVolumeProvider {
    volumes: Vec<Arc<[u8]>>,
}

impl MemoryVolumeProvider {
    /// Owns sequential volumes in `.001`, `.002`, ... order.
    #[must_use]
    pub fn new(volumes: Vec<Vec<u8>>) -> Self {
        Self {
            volumes: volumes
                .into_iter()
                .map(|bytes| Arc::<[u8]>::from(bytes.into_boxed_slice()))
                .collect(),
        }
    }

    /// Returns the number of available volumes.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }
}

impl VolumeProvider for MemoryVolumeProvider {
    fn open_volume(&mut self, request: &VolumeRequest) -> Result<Box<dyn Volume>> {
        let index = usize::try_from(request.index()).map_err(|_| Error::MissingVolume {
            expected: request.expected_name().to_owned(),
        })?;
        let bytes = self
            .volumes
            .get(index)
            .cloned()
            .ok_or_else(|| Error::MissingVolume {
                expected: request.expected_name().to_owned(),
            })?;
        Ok(Box::new(MemoryVolume {
            cursor: Cursor::new(bytes),
        }))
    }
}

struct FileVolume {
    file: File,
    length: u64,
}

impl Read for FileVolume {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for FileVolume {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl Volume for FileVolume {
    fn len(&mut self) -> io::Result<u64> {
        Ok(self.length)
    }
}

/// A path-backed provider that derives later parts from a `.001` path.
#[derive(Clone, Debug)]
pub struct PathVolumeProvider {
    first_path: PathBuf,
}

impl PathVolumeProvider {
    /// Creates a provider rooted at the exact first-volume path.
    #[must_use]
    pub const fn new(first_path: PathBuf) -> Self {
        Self { first_path }
    }

    /// Returns the configured first-volume path.
    #[must_use]
    pub fn first_path(&self) -> &std::path::Path {
        &self.first_path
    }

    fn path_for(&self, index: u64) -> Result<PathBuf> {
        if index == 0 {
            return Ok(self.first_path.clone());
        }
        if self.first_path.extension() != Some(std::ffi::OsStr::new("001")) {
            return Err(format_error(
                "sequential path volume provider requires a .001 first path",
            ));
        }
        let ordinal = index
            .checked_add(1)
            .ok_or_else(|| format_error("sequential volume ordinal overflows"))?;
        Ok(self.first_path.with_extension(format!("{ordinal:03}")))
    }
}

impl VolumeProvider for PathVolumeProvider {
    fn open_volume(&mut self, request: &VolumeRequest) -> Result<Box<dyn Volume>> {
        let path = self.path_for(request.index())?;
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::MissingVolume {
                    expected: request.expected_name().to_owned(),
                });
            }
            Err(error) => return Err(Error::Io(error)),
        };
        let length = file.metadata().map_err(Error::Io)?.len();
        Ok(Box::new(FileVolume { file, length }))
    }
}

pub(crate) enum VolumeTermination {
    Missing(Error),
    Limit { requested: u64, maximum: u64 },
}

pub(crate) struct VolumeBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) termination: VolumeTermination,
}

fn sequential_name(first_name: &str, index: u64) -> Result<String> {
    if index == 0 {
        return Ok(first_name.to_owned());
    }
    let prefix = first_name.strip_suffix(".001").ok_or_else(|| {
        format_error("sequential volume access requires a .001 first-volume name")
    })?;
    let ordinal = index
        .checked_add(1)
        .ok_or_else(|| format_error("sequential volume ordinal overflows"))?;
    Ok(format!("{prefix}.{ordinal:03}"))
}

fn append_volume(
    output: &mut Vec<u8>,
    volume: &mut dyn Volume,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<()> {
    control.checkpoint(0)?;
    let length = volume.len().map_err(Error::Io)?;
    let current = u64::try_from(output.len())
        .map_err(|_| format_error("assembled volume length is not representable as u64"))?;
    let requested = current
        .checked_add(length)
        .ok_or_else(|| format_error("total volume length overflows"))?;
    check_limit(
        requested,
        limits.max_total_input_bytes(),
        LimitKind::TotalInputBytes,
    )?;
    let length_usize = usize::try_from(length)
        .map_err(|_| format_error("volume length is not representable on this platform"))?;
    try_reserve(output, length_usize)?;
    volume.seek(SeekFrom::Start(0)).map_err(Error::Io)?;

    let mut remaining = length;
    let mut buffer = [0_u8; CONTROL_CHUNK_SIZE];
    while remaining != 0 {
        control.checkpoint(0)?;
        let maximum = remaining.min(
            u64::try_from(buffer.len())
                .map_err(|_| format_error("volume read buffer length is not representable"))?,
        );
        let maximum = usize::try_from(maximum)
            .map_err(|_| format_error("volume read size is not representable"))?;
        let target = buffer
            .get_mut(..maximum)
            .ok_or_else(|| format_error("volume read buffer range is invalid"))?;
        let read = volume.read(target).map_err(Error::Io)?;
        if read == 0 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "volume ended before its declared length",
            )));
        }
        let read_u64 = u64::try_from(read)
            .map_err(|_| format_error("volume read length is not representable as u64"))?;
        control.checkpoint(read_u64)?;
        remaining = remaining
            .checked_sub(read_u64)
            .ok_or_else(|| format_error("volume read exceeded the declared length"))?;
        output.extend_from_slice(
            target
                .get(..read)
                .ok_or_else(|| format_error("volume read result exceeds its buffer"))?,
        );
    }
    Ok(())
}

pub(crate) fn read_sequential_volumes(
    provider: &mut dyn VolumeProvider,
    first_name: &str,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<VolumeBytes> {
    let mut bytes = Vec::new();
    let mut index = 0_u64;
    loop {
        let requested_count = index
            .checked_add(1)
            .ok_or_else(|| format_error("volume count overflows"))?;
        if requested_count > limits.max_volumes() {
            if bytes.is_empty() {
                return Err(Error::LimitExceeded {
                    limit: LimitKind::Volumes,
                    requested: requested_count,
                    maximum: limits.max_volumes(),
                });
            }
            return Ok(VolumeBytes {
                bytes,
                termination: VolumeTermination::Limit {
                    requested: requested_count,
                    maximum: limits.max_volumes(),
                },
            });
        }
        control.checkpoint(0)?;
        let expected_name = sequential_name(first_name, index)?;
        let request = VolumeRequest::new(index, expected_name);
        let mut volume = match provider.open_volume(&request) {
            Ok(volume) => volume,
            Err(error @ Error::MissingVolume { .. }) => {
                return Ok(VolumeBytes {
                    bytes,
                    termination: VolumeTermination::Missing(error),
                });
            }
            Err(error) => return Err(error),
        };
        append_volume(&mut bytes, volume.as_mut(), limits, control)?;
        index = requested_count;
    }
}

pub(crate) fn read_single_volume(
    provider: &mut dyn VolumeProvider,
    expected_name: &str,
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<u8>> {
    check_limit(1, limits.max_volumes(), LimitKind::Volumes)?;
    let request = VolumeRequest::new(0, expected_name);
    let mut volume = provider.open_volume(&request)?;
    let mut bytes = Vec::new();
    append_volume(&mut bytes, volume.as_mut(), limits, control)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryVolumeProvider, VolumeProvider, VolumeRequest, read_sequential_volumes,
        read_single_volume,
    };
    use crate::{
        CancellationToken, Error, LimitKind, Limits, WorkBudget, parse_util::ParseControl,
    };

    #[test]
    fn request_preserves_expected_name() {
        let request = VolumeRequest::new(4, "sample.005");
        assert_eq!(request.index(), 4);
        assert_eq!(request.expected_name(), "sample.005");
    }

    #[test]
    fn memory_provider_reports_the_exact_missing_name() {
        let mut provider = MemoryVolumeProvider::new(vec![vec![1, 2, 3]]);
        let request = VolumeRequest::new(1, "sample.002");
        assert!(matches!(
            provider.open_volume(&request),
            Err(crate::Error::MissingVolume { expected }) if expected == "sample.002"
        ));
    }

    #[test]
    fn aggregate_input_limit_precedes_volume_copy() {
        let mut provider = MemoryVolumeProvider::new(vec![vec![1, 2, 3, 4]]);
        let cancellation = CancellationToken::new();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = read_single_volume(
            &mut provider,
            "sample.7z",
            Limits::builder().max_total_input_bytes(3).build(),
            &mut control,
        );
        assert!(matches!(
            result,
            Err(Error::LimitExceeded {
                limit: LimitKind::TotalInputBytes,
                requested: 4,
                maximum: 3,
            })
        ));
    }

    #[test]
    fn cancellation_precedes_provider_callback() {
        let mut provider = MemoryVolumeProvider::new(vec![vec![1]]);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut budget = WorkBudget::unlimited();
        let mut control = ParseControl::new(&cancellation, &mut budget);
        let result = read_sequential_volumes(
            &mut provider,
            "sample.7z.001",
            Limits::default(),
            &mut control,
        );
        assert!(matches!(result, Err(Error::Cancelled)));
    }
}
