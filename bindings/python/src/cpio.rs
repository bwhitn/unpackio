//! Python adapter for standalone CPIO archives.

use std::{io, path::PathBuf, sync::Arc};

use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use unpackio::{
    CpioArchive as CoreCpioArchive, CpioEntry as CoreCpioEntry, CpioEntrySink, CpioFormat, Error,
    Result as CoreResult, UnsafePathReason, validate_safe_path,
};

use crate::{
    archive::copy_input_for,
    callback::{PythonSink, SinkMode, callback_continues},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{PythonCallbackError, detached_core_for, guard, map_core_error_for},
};

fn format_name(format: CpioFormat) -> &'static str {
    match format {
        CpioFormat::Newc => "newc",
        CpioFormat::CrcNewc => "crc_newc",
        CpioFormat::Odc => "odc",
        CpioFormat::BinaryLittleEndian => "binary_little_endian",
        CpioFormat::BinaryBigEndian => "binary_big_endian",
        CpioFormat::Mixed => "mixed",
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

fn entry_kind(mode: u32) -> &'static str {
    match mode & 0o170_000 {
        0o040_000 => "directory",
        0o100_000 => "file",
        0o120_000 => "symlink",
        0o010_000 => "fifo",
        0o020_000 => "character_device",
        0o060_000 => "block_device",
        0o140_000 => "socket",
        _ => "unknown",
    }
}

/// One owned Python snapshot of a CPIO member.
#[pyclass(
    name = "CpioEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyCpioEntry {
    #[pyo3(get)]
    index: u64,
    #[pyo3(get)]
    format: String,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    inode: u32,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    permissions: u32,
    #[pyo3(get)]
    uid: u32,
    #[pyo3(get)]
    gid: u32,
    #[pyo3(get)]
    link_count: u32,
    #[pyo3(get)]
    modified_time: u64,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    device_major: u32,
    #[pyo3(get)]
    device_minor: u32,
    #[pyo3(get)]
    rdev_major: u32,
    #[pyo3(get)]
    rdev_minor: u32,
    #[pyo3(get)]
    checksum: Option<u32>,
    #[pyo3(get)]
    is_directory: bool,
    #[pyo3(get)]
    is_symlink: bool,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyCpioEntry {
    fn from_core(entry: &CoreCpioEntry) -> Self {
        let name = entry.name_lossy();
        let (is_safe_path, unsafe_path_reason) = match validate_safe_path(&name) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
        };
        Self {
            index: entry.index(),
            format: format_name(entry.format()).to_owned(),
            raw_name: entry.raw_name().to_vec(),
            name,
            kind: entry_kind(entry.mode()).to_owned(),
            inode: entry.inode(),
            mode: entry.mode(),
            permissions: entry.mode() & 0o7777,
            uid: entry.uid(),
            gid: entry.gid(),
            link_count: entry.link_count(),
            modified_time: entry.modified_time(),
            size: entry.size(),
            device_major: entry.device_major(),
            device_minor: entry.device_minor(),
            rdev_major: entry.rdev_major(),
            rdev_minor: entry.rdev_minor(),
            checksum: entry.checksum(),
            is_directory: entry.is_directory(),
            is_symlink: entry.is_symlink(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyCpioEntry {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    fn __repr__(&self) -> String {
        format!(
            "CpioEntry(index={}, name={:?}, kind={:?}, size={})",
            self.index, self.name, self.kind, self.size
        )
    }
}

/// Opens CPIO bytes without creating filesystem paths.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_cpio_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyCpioArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input_for(py, data, limits, "cpio")?;
        detached_core_for(py, "cpio", move || {
            let mut budget = work_budget(max_work_units);
            CoreCpioArchive::open_bytes(bytes, limits, &cancellation, &mut budget)
        })
        .map(PyCpioArchive::new)
    })
}

/// Opens a CPIO path without choosing an extraction destination.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_cpio_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyCpioArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        detached_core_for(py, "cpio", move || {
            let mut budget = work_budget(max_work_units);
            CoreCpioArchive::open_path(&path, limits, &cancellation, &mut budget)
        })
        .map(PyCpioArchive::new)
    })
}

/// An owned standalone CPIO session with caller-directed extraction only.
#[pyclass(name = "CpioArchive", module = "unpackio._native", frozen)]
pub(crate) struct PyCpioArchive {
    value: Arc<CoreCpioArchive>,
}

impl PyCpioArchive {
    fn new(value: CoreCpioArchive) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    fn metadata(&self) -> PyResult<Vec<PyCpioEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate CPIO metadata list"))?;
        output.extend(entries.iter().map(PyCpioEntry::from_core));
        Ok(output)
    }
}

#[pymethods]
impl PyCpioArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "CpioArchive(entries={}, format={:?}, retained_input_bytes={})",
                self.value.entries().len(),
                format_name(self.value.format()),
                self.value.retained_input_bytes()
            ))
        })
    }

    fn entries(&self) -> PyResult<Vec<PyCpioEntry>> {
        guard(|| self.metadata())
    }

    fn entry(&self, index: u64) -> PyResult<Option<PyCpioEntry>> {
        guard(|| Ok(self.value.entry(index).map(PyCpioEntry::from_core)))
    }

    #[getter]
    fn format(&self) -> PyResult<String> {
        guard(|| Ok(format_name(self.value.format()).to_owned()))
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn retained_input_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_input_bytes()))
    }

    fn symlink_target(&self, py: Python<'_>, index: u64) -> PyResult<Option<Py<PyBytes>>> {
        guard(|| {
            let target = self
                .value
                .symlink_target(index)
                .map_err(|error| map_core_error_for(py, error, "cpio"))?;
            Ok(target.map(|value| PyBytes::new(py, value).unbind()))
        })
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
            detached_core_for(py, "cpio", move || {
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
            detached_core_for(py, "cpio", move || {
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
            detached_core_for(py, "cpio", move || {
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
            detached_core_for(py, "cpio", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonCpioEntrySink {
                    target: sink,
                    cancellation: sink_cancellation,
                };
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }
}

struct PythonCpioEntrySink {
    target: Py<PyAny>,
    cancellation: unpackio::CancellationToken,
}

impl PythonCpioEntrySink {
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

impl CpioEntrySink for PythonCpioEntrySink {
    fn begin_entry(&mut self, core_entry: &CoreCpioEntry) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let entry = Py::new(py, PyCpioEntry::from_core(core_entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, core_entry.size()))?;
            callback_continues(
                &result,
                "CPIO entry sink begin_entry() must return None or bool",
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
                "CPIO entry sink write_entry() must return None or bool",
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
                "CPIO entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}
