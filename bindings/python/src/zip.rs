//! Python adapter for the concrete unpack-only ZIP reader.

use std::{io, path::PathBuf, sync::Arc};

use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use unpackio::{
    Error, Result as CoreResult, UnsafePathReason, ZipArchive as CoreZipArchive,
    ZipCompressionMethod, ZipEncryption, ZipEntry as CoreZipEntry, ZipEntrySink,
    validate_safe_path,
};
use zeroize::Zeroizing;

use crate::{
    archive::copy_input_for,
    callback::{PythonSink, SinkMode, callback_continues},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{PythonCallbackError, detached_core_for, guard},
};

fn compression_name(method: ZipCompressionMethod) -> &'static str {
    match method {
        ZipCompressionMethod::Stored => "stored",
        ZipCompressionMethod::Deflate => "deflate",
        ZipCompressionMethod::Deflate64 => "deflate64",
        ZipCompressionMethod::Bzip2 => "bzip2",
        ZipCompressionMethod::Lzma => "lzma",
        ZipCompressionMethod::ZstandardDeprecated => "zstandard_deprecated",
        ZipCompressionMethod::Zstandard => "zstandard",
        ZipCompressionMethod::Mp3 => "mp3",
        ZipCompressionMethod::Xz => "xz",
        ZipCompressionMethod::Jpeg => "jpeg",
        ZipCompressionMethod::WavPack => "wavpack",
        ZipCompressionMethod::Ppmd => "ppmd",
        ZipCompressionMethod::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

fn unsafe_path_reason_name(reason: UnsafePathReason) -> &'static str {
    match reason {
        UnsafePathReason::Empty => "empty",
        UnsafePathReason::Nul => "nul",
        UnsafePathReason::Absolute => "absolute",
        UnsafePathReason::Unc => "unc",
        UnsafePathReason::Drive => "drive",
        UnsafePathReason::Traversal => "traversal",
        _ => "unknown",
    }
}

/// One owned Python snapshot of ZIP metadata.
#[pyclass(
    name = "ZipEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyZipEntry {
    #[pyo3(get)]
    index: u64,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    raw_comment: Vec<u8>,
    extra_fields: Vec<u8>,
    #[pyo3(get)]
    compression_method: String,
    #[pyo3(get)]
    compression_method_id: u16,
    #[pyo3(get)]
    encryption: String,
    #[pyo3(get)]
    aes_vendor_version: Option<u16>,
    #[pyo3(get)]
    aes_key_bits: Option<u16>,
    #[pyo3(get)]
    compressed_size: u64,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    crc32: Option<u32>,
    #[pyo3(get)]
    is_directory: bool,
    #[pyo3(get)]
    is_symlink: bool,
    #[pyo3(get)]
    unix_mode: Option<u32>,
    #[pyo3(get)]
    modified: Option<(u16, u8, u8, u8, u8, u8)>,
    #[pyo3(get)]
    modified_time_raw: u16,
    #[pyo3(get)]
    modified_date_raw: u16,
    #[pyo3(get)]
    version_made_by: u16,
    #[pyo3(get)]
    version_needed: u16,
    #[pyo3(get)]
    flags: u16,
    #[pyo3(get)]
    internal_attributes: u16,
    #[pyo3(get)]
    external_attributes: u32,
    #[pyo3(get)]
    local_header_offset: u64,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyZipEntry {
    pub(crate) fn from_core(entry: &CoreZipEntry) -> Self {
        let (encryption, aes_vendor_version, aes_key_bits) = match entry.encryption() {
            ZipEncryption::None => (String::from("none"), None, None),
            ZipEncryption::ZipCrypto => (String::from("zipcrypto"), None, None),
            ZipEncryption::WinZipAes {
                vendor_version,
                key_bits,
            } => (
                String::from("winzip_aes"),
                Some(vendor_version),
                Some(key_bits),
            ),
            ZipEncryption::Strong => (String::from("strong"), None, None),
            _ => (String::from("unknown"), None, None),
        };
        let (is_safe_path, unsafe_path_reason) = match validate_safe_path(entry.name()) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
        };
        let modified = entry.modified().map(|value| {
            (
                value.year(),
                value.month(),
                value.day(),
                value.hour(),
                value.minute(),
                value.second(),
            )
        });
        Self {
            index: entry.index(),
            raw_name: entry.raw_name().to_vec(),
            name: entry.name().to_owned(),
            raw_comment: entry.raw_comment().to_vec(),
            extra_fields: entry.extra_fields().to_vec(),
            compression_method: compression_name(entry.compression_method()).to_owned(),
            compression_method_id: entry.compression_method().id(),
            encryption,
            aes_vendor_version,
            aes_key_bits,
            compressed_size: entry.compressed_size(),
            size: entry.uncompressed_size(),
            crc32: entry.crc32(),
            is_directory: entry.is_directory(),
            is_symlink: entry.is_symlink(),
            unix_mode: entry.unix_mode(),
            modified,
            modified_time_raw: entry.modified_time_raw(),
            modified_date_raw: entry.modified_date_raw(),
            version_made_by: entry.version_made_by(),
            version_needed: entry.version_needed(),
            flags: entry.flags(),
            internal_attributes: entry.internal_attributes(),
            external_attributes: entry.external_attributes(),
            local_header_offset: entry.local_header_offset(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyZipEntry {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    #[getter]
    fn raw_comment(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_comment).unbind()
    }

    #[getter]
    fn extra_fields(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.extra_fields).unbind()
    }

    fn __repr__(&self) -> String {
        format!(
            "ZipEntry(index={}, name={:?}, method={:?}, encryption={:?}, size={})",
            self.index, self.name, self.compression_method, self.encryption, self.size
        )
    }
}

fn copy_password(password: Option<&Bound<'_, PyBytes>>) -> PyResult<Option<Zeroizing<Vec<u8>>>> {
    let Some(password) = password else {
        return Ok(None);
    };
    let source = password.as_bytes();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| PyMemoryError::new_err("unable to allocate ZIP password copy"))?;
    bytes.extend_from_slice(source);
    Ok(Some(Zeroizing::new(bytes)))
}

/// Opens ZIP bytes without auto-detecting or creating filesystem paths.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, password=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_zip_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    password: Option<&Bound<'_, PyBytes>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyZipArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input_for(py, data, limits, "zip")?;
        let password = copy_password(password)?;
        detached_core_for(py, "zip", move || {
            let mut budget = work_budget(max_work_units);
            match password.as_ref() {
                Some(password) => CoreZipArchive::open_bytes_with_password(
                    bytes,
                    limits,
                    password,
                    &cancellation,
                    &mut budget,
                ),
                None => CoreZipArchive::open_bytes(bytes, limits, &cancellation, &mut budget),
            }
        })
        .map(PyZipArchive::new)
    })
}

/// Opens a ZIP path without choosing any extraction destination.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, password=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_zip_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    password: Option<&Bound<'_, PyBytes>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyZipArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let password = copy_password(password)?;
        detached_core_for(py, "zip", move || {
            let mut budget = work_budget(max_work_units);
            match password.as_ref() {
                Some(password) => CoreZipArchive::open_path_with_password(
                    &path,
                    limits,
                    password,
                    &cancellation,
                    &mut budget,
                ),
                None => CoreZipArchive::open_path(&path, limits, &cancellation, &mut budget),
            }
        })
        .map(PyZipArchive::new)
    })
}

/// An owned ZIP session with caller-directed extraction only.
#[pyclass(name = "ZipArchive", module = "unpackio._native", frozen)]
pub(crate) struct PyZipArchive {
    value: Arc<CoreZipArchive>,
}

impl PyZipArchive {
    fn new(value: CoreZipArchive) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    fn metadata(&self) -> PyResult<Vec<PyZipEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate ZIP metadata list"))?;
        output.extend(entries.iter().map(PyZipEntry::from_core));
        Ok(output)
    }
}

#[pymethods]
impl PyZipArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "ZipArchive(entries={}, retained_input_bytes={}, retained_password_bytes={})",
                self.value.entries().len(),
                self.value.retained_input_bytes(),
                self.value.retained_password_bytes()
            ))
        })
    }

    fn entries(&self) -> PyResult<Vec<PyZipEntry>> {
        guard(|| self.metadata())
    }

    fn entry(&self, index: u64) -> PyResult<Option<PyZipEntry>> {
        guard(|| Ok(self.value.entry(index).map(PyZipEntry::from_core)))
    }

    #[getter]
    fn comment(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        guard(|| Ok(PyBytes::new(py, self.value.comment()).unbind()))
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn retained_input_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_input_bytes()))
    }

    #[getter]
    fn retained_password_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_password_bytes()))
    }

    #[pyo3(signature = (*, cancellation=None, max_work_units=1_000_000_000))]
    fn verify(
        &self,
        py: Python<'_>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<()> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            detached_core_for(py, "zip", move || {
                let mut budget = work_budget(max_work_units);
                archive.verify(&cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (index, writer, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn extract_entry_to(
        &self,
        py: Python<'_>,
        index: u64,
        writer: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "zip", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(writer, SinkMode::Writer, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (index, callback, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn stream_entry(
        &self,
        py: Python<'_>,
        index: u64,
        callback: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "zip", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(callback, SinkMode::Callback, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (sink, *, cancellation=None, max_work_units=1_000_000_000))]
    fn extract_entries_to(
        &self,
        py: Python<'_>,
        sink: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "zip", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonZipEntrySink {
                    target: sink,
                    cancellation: sink_cancellation,
                };
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }
}

struct PythonZipEntrySink {
    target: Py<PyAny>,
    cancellation: unpackio::CancellationToken,
}

impl PythonZipEntrySink {
    fn finish_callback(&self, result: PyResult<bool>) -> CoreResult<()> {
        match result {
            Ok(true) => self.cancellation.check(),
            Ok(false) => {
                self.cancellation.cancel();
                Err(Error::Cancelled)
            }
            Err(error) => Err(Error::Io(io::Error::other(PythonCallbackError::new(error)))),
        }
    }
}

impl ZipEntrySink for PythonZipEntrySink {
    fn begin_entry(&mut self, core_entry: &CoreZipEntry) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let size = core_entry.uncompressed_size();
            let entry = Py::new(py, PyZipEntry::from_core(core_entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, size))?;
            callback_continues(
                &result,
                "ZIP entry sink begin_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }

    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let chunk = PyBytes::new_with(py, bytes.len(), |output| {
                output.copy_from_slice(bytes);
                Ok(())
            })?;
            let result = self
                .target
                .bind(py)
                .call_method1("write_entry", (entry_index, chunk))?;
            callback_continues(
                &result,
                "ZIP entry sink write_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }

    fn finish_entry(&mut self, entry_index: u64) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let result = self
                .target
                .bind(py)
                .call_method1("finish_entry", (entry_index,))?;
            callback_continues(
                &result,
                "ZIP entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}
