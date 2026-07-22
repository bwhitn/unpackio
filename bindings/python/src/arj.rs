//! Python adapter for unpack-only ARJ archives.

use std::{io, path::PathBuf, sync::Arc};

use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use unpackio::{
    ArjArchive as CoreArjArchive, ArjCompressionMethod, ArjEntry as CoreArjEntry, ArjEntryKind,
    ArjEntrySink, Error, Result as CoreResult, UnsafePathReason, validate_safe_path,
};

use crate::{
    archive::copy_input_for,
    callback::{PythonSink, SinkMode, callback_continues},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{PythonCallbackError, detached_core_for, guard},
};

fn method_name(value: ArjCompressionMethod) -> &'static str {
    match value {
        ArjCompressionMethod::Stored => "stored",
        ArjCompressionMethod::CompressedMost => "compressed_most",
        ArjCompressionMethod::Compressed => "compressed",
        ArjCompressionMethod::CompressedFaster => "compressed_faster",
        ArjCompressionMethod::CompressedFastest => "compressed_fastest",
        ArjCompressionMethod::NoDataNoCrc => "no_data_no_crc",
        ArjCompressionMethod::NoData => "no_data",
        ArjCompressionMethod::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

fn kind_name(value: ArjEntryKind) -> &'static str {
    match value {
        ArjEntryKind::Binary => "binary",
        ArjEntryKind::Text => "text",
        ArjEntryKind::Comment => "comment",
        ArjEntryKind::Directory => "directory",
        ArjEntryKind::VolumeLabel => "volume_label",
        ArjEntryKind::ChapterLabel => "chapter_label",
        ArjEntryKind::Unknown(_) => "unknown",
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

/// One owned Python snapshot of an ARJ member.
#[pyclass(
    name = "ArjEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyArjEntry {
    #[pyo3(get)]
    index: u64,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    raw_comment: Vec<u8>,
    #[pyo3(get)]
    archiver_version: u8,
    #[pyo3(get)]
    minimum_version: u8,
    #[pyo3(get)]
    host_os: u8,
    #[pyo3(get)]
    flags: u8,
    #[pyo3(get)]
    compression_method: String,
    #[pyo3(get)]
    compression_method_id: u8,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    modified_time_raw: u32,
    #[pyo3(get)]
    compressed_size: u64,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    crc32: Option<u32>,
    #[pyo3(get)]
    file_spec_position: u16,
    #[pyo3(get)]
    access_mode: u16,
    #[pyo3(get)]
    is_encrypted: bool,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyArjEntry {
    fn from_core(entry: &CoreArjEntry) -> Self {
        let name = entry.name_lossy();
        let (is_safe_path, unsafe_path_reason) = match validate_safe_path(&name) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
        };
        Self {
            index: entry.index(),
            raw_name: entry.raw_name().to_vec(),
            name,
            raw_comment: entry.raw_comment().to_vec(),
            archiver_version: entry.archiver_version(),
            minimum_version: entry.minimum_version(),
            host_os: entry.host_os(),
            flags: entry.flags(),
            compression_method: method_name(entry.compression_method()).to_owned(),
            compression_method_id: entry.compression_method().id(),
            kind: kind_name(entry.kind()).to_owned(),
            modified_time_raw: entry.modified_time_raw(),
            compressed_size: entry.compressed_size(),
            size: entry.size(),
            crc32: entry.crc32(),
            file_spec_position: entry.file_spec_position(),
            access_mode: entry.access_mode(),
            is_encrypted: entry.is_encrypted(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyArjEntry {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    #[getter]
    fn raw_comment(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_comment).unbind()
    }

    fn __repr__(&self) -> String {
        format!(
            "ArjEntry(index={}, name={:?}, method={:?}, size={})",
            self.index, self.name, self.compression_method, self.size
        )
    }
}

/// Opens ARJ bytes without creating filesystem paths.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_arj_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyArjArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input_for(py, data, limits, "arj")?;
        detached_core_for(py, "arj", move || {
            let mut budget = work_budget(max_work_units);
            CoreArjArchive::open_bytes(bytes, limits, &cancellation, &mut budget)
        })
        .map(PyArjArchive::new)
    })
}

/// Opens an ARJ path without choosing an extraction destination.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_arj_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyArjArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        detached_core_for(py, "arj", move || {
            let mut budget = work_budget(max_work_units);
            CoreArjArchive::open_path(&path, limits, &cancellation, &mut budget)
        })
        .map(PyArjArchive::new)
    })
}

/// An owned ARJ session with caller-directed extraction only.
#[pyclass(name = "ArjArchive", module = "unpackio._native", frozen)]
pub(crate) struct PyArjArchive {
    value: Arc<CoreArjArchive>,
}

impl PyArjArchive {
    fn new(value: CoreArjArchive) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    fn metadata(&self) -> PyResult<Vec<PyArjEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate ARJ metadata list"))?;
        output.extend(entries.iter().map(PyArjEntry::from_core));
        Ok(output)
    }
}

#[pymethods]
impl PyArjArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "ArjArchive(entries={}, sfx_offset={}, retained_input_bytes={})",
                self.value.entries().len(),
                self.value.sfx_offset(),
                self.value.retained_input_bytes()
            ))
        })
    }

    fn entries(&self) -> PyResult<Vec<PyArjEntry>> {
        guard(|| self.metadata())
    }

    fn entry(&self, index: u64) -> PyResult<Option<PyArjEntry>> {
        guard(|| Ok(self.value.entry(index).map(PyArjEntry::from_core)))
    }

    #[getter]
    fn raw_name(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        guard(|| Ok(PyBytes::new(py, self.value.raw_name()).unbind()))
    }

    #[getter]
    fn raw_comment(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        guard(|| Ok(PyBytes::new(py, self.value.raw_comment()).unbind()))
    }

    #[getter]
    fn sfx_offset(&self) -> PyResult<u64> {
        guard(|| Ok(self.value.sfx_offset()))
    }

    #[getter]
    fn archiver_version(&self) -> PyResult<u8> {
        guard(|| Ok(self.value.archiver_version()))
    }

    #[getter]
    fn minimum_version(&self) -> PyResult<u8> {
        guard(|| Ok(self.value.minimum_version()))
    }

    #[getter]
    fn host_os(&self) -> PyResult<u8> {
        guard(|| Ok(self.value.host_os()))
    }

    #[getter]
    fn flags(&self) -> PyResult<u8> {
        guard(|| Ok(self.value.flags()))
    }

    #[getter]
    fn creation_time_raw(&self) -> PyResult<u32> {
        guard(|| Ok(self.value.creation_time_raw()))
    }

    #[getter]
    fn modification_time_raw(&self) -> PyResult<u32> {
        guard(|| Ok(self.value.modification_time_raw()))
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn retained_input_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_input_bytes()))
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
            detached_core_for(py, "arj", move || {
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
            detached_core_for(py, "arj", move || {
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
            detached_core_for(py, "arj", move || {
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
            detached_core_for(py, "arj", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonArjEntrySink {
                    target: sink,
                    cancellation: sink_cancellation,
                };
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }
}

struct PythonArjEntrySink {
    target: Py<PyAny>,
    cancellation: unpackio::CancellationToken,
}

impl PythonArjEntrySink {
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

impl ArjEntrySink for PythonArjEntrySink {
    fn begin_entry(&mut self, core_entry: &CoreArjEntry) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let entry = Py::new(py, PyArjEntry::from_core(core_entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, core_entry.size()))?;
            callback_continues(
                &result,
                "ARJ entry sink begin_entry() must return None or bool",
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
                "ARJ entry sink write_entry() must return None or bool",
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
                "ARJ entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}
