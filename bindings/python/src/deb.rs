//! Python adapter for Debian binary packages.

use std::{io, path::PathBuf, sync::Arc};

use pyo3::{exceptions::PyMemoryError, prelude::*, types::PyBytes};
use unpackio::{
    DebArchive as CoreDebArchive, DebCompression, DebEntry as CoreDebEntry, DebEntryKind,
    DebEntrySink, DebMember as CoreDebMember, DebMemberKind, DebSection, Error,
    Result as CoreResult, UnsafePathReason, validate_safe_path,
};

use crate::{
    archive::copy_input_for,
    callback::{PythonSink, SinkMode, callback_continues},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{PythonCallbackError, detached_core_for, guard},
};

fn compression_name(value: Option<DebCompression>) -> Option<String> {
    value.map(|compression| {
        match compression {
            DebCompression::None => "none",
            DebCompression::Gzip => "gzip",
            DebCompression::Xz => "xz",
            DebCompression::Zstandard => "zstandard",
            DebCompression::Bzip2 => "bzip2",
            DebCompression::Lzma => "lzma",
            _ => "unknown",
        }
        .to_owned()
    })
}

fn member_kind_name(value: DebMemberKind) -> &'static str {
    match value {
        DebMemberKind::DebianBinary => "debian_binary",
        DebMemberKind::ControlArchive => "control_archive",
        DebMemberKind::DataArchive => "data_archive",
        DebMemberKind::Optional => "optional",
        _ => "unknown",
    }
}

fn entry_kind_name(value: DebEntryKind) -> &'static str {
    match value {
        DebEntryKind::Regular => "file",
        DebEntryKind::HardLink => "hardlink",
        DebEntryKind::SymbolicLink => "symlink",
        DebEntryKind::CharacterDevice => "character_device",
        DebEntryKind::BlockDevice => "block_device",
        DebEntryKind::Directory => "directory",
        DebEntryKind::Fifo => "fifo",
        DebEntryKind::Other(_) => "other",
        _ => "unknown",
    }
}

fn section_name(value: DebSection) -> &'static str {
    match value {
        DebSection::Control => "control",
        DebSection::Data => "data",
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

/// One owned Python snapshot of an outer Debian ar member.
#[pyclass(
    name = "DebMember",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyDebMember {
    #[pyo3(get)]
    index: u64,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    compression: Option<String>,
    #[pyo3(get)]
    modified_time: u64,
    #[pyo3(get)]
    uid: u32,
    #[pyo3(get)]
    gid: u32,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    size: u64,
}

impl PyDebMember {
    fn from_core(member: &CoreDebMember) -> Self {
        Self {
            index: member.index(),
            raw_name: member.raw_name().to_vec(),
            name: member.name_lossy(),
            kind: member_kind_name(member.kind()).to_owned(),
            compression: compression_name(member.compression()),
            modified_time: member.modified_time(),
            uid: member.uid(),
            gid: member.gid(),
            mode: member.mode(),
            size: member.size(),
        }
    }
}

#[pymethods]
impl PyDebMember {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    fn __repr__(&self) -> String {
        format!(
            "DebMember(index={}, name={:?}, kind={:?}, size={})",
            self.index, self.name, self.kind, self.size
        )
    }
}

/// One owned Python snapshot of a Debian control/data tar entry.
#[pyclass(
    name = "DebEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyDebEntry {
    #[pyo3(get)]
    index: u64,
    #[pyo3(get)]
    section: String,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    raw_link_name: Option<Vec<u8>>,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    permissions: u32,
    #[pyo3(get)]
    uid: u64,
    #[pyo3(get)]
    gid: u64,
    #[pyo3(get)]
    modified_time: Option<i64>,
    #[pyo3(get)]
    size: u64,
    user_name: Option<Vec<u8>>,
    group_name: Option<Vec<u8>>,
    #[pyo3(get)]
    device_major: Option<u32>,
    #[pyo3(get)]
    device_minor: Option<u32>,
    #[pyo3(get)]
    header_checksum: u32,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyDebEntry {
    fn from_core(entry: &CoreDebEntry) -> Self {
        let name = entry.name_lossy();
        let (is_safe_path, unsafe_path_reason) = match validate_safe_path(&name) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
        };
        Self {
            index: entry.index(),
            section: section_name(entry.section()).to_owned(),
            raw_name: entry.raw_name().to_vec(),
            name,
            raw_link_name: entry.raw_link_name().map(<[u8]>::to_vec),
            kind: entry_kind_name(entry.kind()).to_owned(),
            mode: entry.mode(),
            permissions: entry.mode() & 0o7777,
            uid: entry.uid(),
            gid: entry.gid(),
            modified_time: entry.modified_time(),
            size: entry.size(),
            user_name: entry.user_name().map(<[u8]>::to_vec),
            group_name: entry.group_name().map(<[u8]>::to_vec),
            device_major: entry.device_major(),
            device_minor: entry.device_minor(),
            header_checksum: entry.header_checksum(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyDebEntry {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    #[getter]
    fn raw_link_name(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.raw_link_name
            .as_deref()
            .map(|value| PyBytes::new(py, value).unbind())
    }

    #[getter]
    fn user_name(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.user_name
            .as_deref()
            .map(|value| PyBytes::new(py, value).unbind())
    }

    #[getter]
    fn group_name(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.group_name
            .as_deref()
            .map(|value| PyBytes::new(py, value).unbind())
    }

    fn __repr__(&self) -> String {
        format!(
            "DebEntry(index={}, section={:?}, name={:?}, kind={:?}, size={})",
            self.index, self.section, self.name, self.kind, self.size
        )
    }
}

/// Opens Debian package bytes without creating filesystem paths.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_deb_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyDebArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input_for(py, data, limits, "deb")?;
        detached_core_for(py, "deb", move || {
            let mut budget = work_budget(max_work_units);
            CoreDebArchive::open_bytes(bytes, limits, &cancellation, &mut budget)
        })
        .map(PyDebArchive::new)
    })
}

/// Opens a Debian package path without choosing an extraction destination.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_deb_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyDebArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        detached_core_for(py, "deb", move || {
            let mut budget = work_budget(max_work_units);
            CoreDebArchive::open_path(&path, limits, &cancellation, &mut budget)
        })
        .map(PyDebArchive::new)
    })
}

/// An owned Debian package session with caller-directed extraction only.
#[pyclass(name = "DebArchive", module = "unpackio._native", frozen)]
pub(crate) struct PyDebArchive {
    value: Arc<CoreDebArchive>,
}

impl PyDebArchive {
    fn new(value: CoreDebArchive) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    fn entry_metadata(&self) -> PyResult<Vec<PyDebEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate Debian entry metadata"))?;
        output.extend(entries.iter().map(PyDebEntry::from_core));
        Ok(output)
    }

    fn member_metadata(&self) -> PyResult<Vec<PyDebMember>> {
        let members = self.value.members();
        let mut output = Vec::new();
        output
            .try_reserve_exact(members.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate Debian member metadata"))?;
        output.extend(members.iter().map(PyDebMember::from_core));
        Ok(output)
    }
}

#[pymethods]
impl PyDebArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "DebArchive(members={}, entries={}, retained_data_bytes={})",
                self.value.members().len(),
                self.value.entries().len(),
                self.value.retained_data_bytes()
            ))
        })
    }

    fn members(&self) -> PyResult<Vec<PyDebMember>> {
        guard(|| self.member_metadata())
    }

    fn member(&self, index: u64) -> PyResult<Option<PyDebMember>> {
        guard(|| Ok(self.value.member(index).map(PyDebMember::from_core)))
    }

    fn entries(&self) -> PyResult<Vec<PyDebEntry>> {
        guard(|| self.entry_metadata())
    }

    fn entry(&self, index: u64) -> PyResult<Option<PyDebEntry>> {
        guard(|| Ok(self.value.entry(index).map(PyDebEntry::from_core)))
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
    fn retained_control_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_control_bytes()))
    }

    #[getter]
    fn retained_data_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_data_bytes()))
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
            detached_core_for(py, "deb", move || {
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
        extract_to(
            py,
            &self.value,
            index,
            writer,
            cancellation,
            max_work_units,
            false,
        )
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
        extract_to(
            py,
            &self.value,
            index,
            callback,
            cancellation,
            max_work_units,
            true,
        )
    }

    #[pyo3(signature = (index, writer, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn extract_member_to(
        &self,
        py: Python<'_>,
        index: u64,
        writer: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        extract_member_to(
            py,
            &self.value,
            index,
            writer,
            cancellation,
            max_work_units,
            false,
        )
    }

    #[pyo3(signature = (index, callback, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn stream_member(
        &self,
        py: Python<'_>,
        index: u64,
        callback: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        extract_member_to(
            py,
            &self.value,
            index,
            callback,
            cancellation,
            max_work_units,
            true,
        )
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
            detached_core_for(py, "deb", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonDebEntrySink {
                    target: sink,
                    cancellation: sink_cancellation,
                };
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }
}

fn extract_to(
    py: Python<'_>,
    archive: &Arc<CoreDebArchive>,
    index: u64,
    target: Py<PyAny>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
    callback: bool,
) -> PyResult<u64> {
    guard(|| {
        let archive = Arc::clone(archive);
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let sink_cancellation = cancellation.clone();
        detached_core_for(py, "deb", move || {
            let mut budget = work_budget(max_work_units);
            let mode = if callback {
                SinkMode::Callback
            } else {
                SinkMode::Writer
            };
            let mut sink = PythonSink::new(target, mode, sink_cancellation);
            archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
        })
    })
}

fn extract_member_to(
    py: Python<'_>,
    archive: &Arc<CoreDebArchive>,
    index: u64,
    target: Py<PyAny>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
    callback: bool,
) -> PyResult<u64> {
    guard(|| {
        let archive = Arc::clone(archive);
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let sink_cancellation = cancellation.clone();
        detached_core_for(py, "deb", move || {
            let mut budget = work_budget(max_work_units);
            let mode = if callback {
                SinkMode::Callback
            } else {
                SinkMode::Writer
            };
            let mut sink = PythonSink::new(target, mode, sink_cancellation);
            archive.extract_member_to(index, &mut sink, &cancellation, &mut budget)
        })
    })
}

struct PythonDebEntrySink {
    target: Py<PyAny>,
    cancellation: unpackio::CancellationToken,
}

impl PythonDebEntrySink {
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

impl DebEntrySink for PythonDebEntrySink {
    fn begin_entry(&mut self, core_entry: &CoreDebEntry) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let entry = Py::new(py, PyDebEntry::from_core(core_entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, core_entry.size()))?;
            callback_continues(
                &result,
                "Debian entry sink begin_entry() must return None or bool",
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
                "Debian entry sink write_entry() must return None or bool",
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
                "Debian entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}
