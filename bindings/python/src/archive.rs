//! Python archive session over the stable owned Rust API.

use std::{path::PathBuf, sync::Arc};

use pyo3::{
    exceptions::{PyMemoryError, PyOverflowError},
    prelude::*,
    types::PyBytes,
};
use unpackio::{Archive as CoreArchive, Error, LimitKind};
use zeroize::Zeroizing;

use crate::{
    callback::{PythonEntrySink, PythonSink, PythonVolumeProvider, SinkMode},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{detached_core, guard},
    metadata::{PyArchiveResources, PyEntry},
};

pub(crate) fn copy_input(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: unpackio::Limits,
) -> PyResult<Vec<u8>> {
    copy_input_for(py, data, limits, "7z")
}

pub(crate) fn copy_input_for(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: unpackio::Limits,
    archive_format: &'static str,
) -> PyResult<Vec<u8>> {
    let source = data.as_bytes();
    let requested = u64::try_from(source.len()).map_err(|_| {
        PyOverflowError::new_err("compressed input length is not representable as u64")
    })?;
    if requested > limits.max_total_input_bytes() {
        return Err(crate::errors::map_core_error_for(
            py,
            Error::LimitExceeded {
                limit: LimitKind::TotalInputBytes,
                requested,
                maximum: limits.max_total_input_bytes(),
            },
            archive_format,
        ));
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(source.len())
        .map_err(|_| PyMemoryError::new_err("unable to allocate compressed input copy"))?;
    owned.extend_from_slice(source);
    Ok(owned)
}

fn open_bytes_core(
    bytes: Vec<u8>,
    limits: unpackio::Limits,
    password: Option<Zeroizing<String>>,
    cancellation: unpackio::CancellationToken,
    max_work_units: u64,
) -> unpackio::Result<CoreArchive> {
    let mut budget = work_budget(max_work_units);
    match password.as_ref() {
        Some(password) => CoreArchive::open_bytes_with_password(
            bytes,
            limits,
            password.as_str(),
            &cancellation,
            &mut budget,
        ),
        None => CoreArchive::open_bytes(bytes, limits, &cancellation, &mut budget),
    }
}

/// Opens an archive from an owned Python `bytes` object.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, password=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    password: Option<String>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input(py, data, limits)?;
        let password = password.map(Zeroizing::new);
        detached_core(py, move || {
            open_bytes_core(bytes, limits, password, cancellation, max_work_units)
        })
        .map(PyArchive::new)
    })
}

/// Opens an archive path, including sequential `.001` sets.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, password=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    password: Option<String>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let password = password.map(Zeroizing::new);
        detached_core(py, move || {
            let mut budget = work_budget(max_work_units);
            match password.as_ref() {
                Some(password) => CoreArchive::open_path_with_password(
                    &path,
                    limits,
                    password.as_str(),
                    &cancellation,
                    &mut budget,
                ),
                None => CoreArchive::open_path(&path, limits, &cancellation, &mut budget),
            }
        })
        .map(PyArchive::new)
    })
}

/// Opens sequential volumes supplied by a Python callable or provider object.
#[pyfunction]
#[pyo3(signature = (provider, first_volume_name, *, limits=None, password=None,
    cancellation=None, max_work_units=1_000_000_000))]
pub(crate) fn open_volumes(
    py: Python<'_>,
    provider: Py<PyAny>,
    first_volume_name: String,
    limits: Option<PyRef<'_, PyLimits>>,
    password: Option<String>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let password = password.map(Zeroizing::new);
        detached_core(py, move || {
            let mut provider = PythonVolumeProvider::new(provider, limits.max_total_input_bytes());
            let mut budget = work_budget(max_work_units);
            match password.as_ref() {
                Some(password) => CoreArchive::open_volumes_with_password(
                    &mut provider,
                    &first_volume_name,
                    limits,
                    password.as_str(),
                    &cancellation,
                    &mut budget,
                ),
                None => CoreArchive::open_volumes(
                    &mut provider,
                    &first_volume_name,
                    limits,
                    &cancellation,
                    &mut budget,
                ),
            }
        })
        .map(PyArchive::new)
    })
}

/// An owned, parsed archive session.
#[pyclass(name = "Archive", module = "unpackio._native", frozen)]
pub(crate) struct PyArchive {
    value: Arc<CoreArchive>,
}

impl PyArchive {
    fn new(archive: CoreArchive) -> Self {
        Self {
            value: Arc::new(archive),
        }
    }

    fn metadata(&self) -> PyResult<Vec<PyEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate metadata list"))?;
        for (index, entry) in entries.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| {
                PyOverflowError::new_err("archive entry index is not representable as u64")
            })?;
            output.push(PyEntry::from_core(index, entry));
        }
        Ok(output)
    }
}

#[pymethods]
impl PyArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "Archive(entries={}, retained_bytes={})",
                self.value.entries().len(),
                self.value.resources().retained_bytes()
            ))
        })
    }

    /// Returns owned metadata snapshots in stable archive order.
    fn entries(&self) -> PyResult<Vec<PyEntry>> {
        guard(|| self.metadata())
    }

    /// Returns one metadata snapshot or `None` for an absent index.
    fn entry(&self, index: u64) -> PyResult<Option<PyEntry>> {
        guard(|| {
            Ok(self
                .value
                .entry(index)
                .map(|entry| PyEntry::from_core(index, entry)))
        })
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn resources(&self) -> PyResult<PyArchiveResources> {
        guard(|| Ok(self.value.resources().into()))
    }

    /// Decodes all streamed members and verifies every applicable CRC.
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
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                archive.verify(&cancellation, &mut budget)
            })
        })
    }

    /// Sends bounded chunks to `writer.write()` and returns the verified count.
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
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(writer, SinkMode::Writer, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }

    /// Extracts every file entry through a natural-order entry sink.
    ///
    /// The sink receives `begin_entry(entry, size)`, bounded
    /// `write_entry(index, chunk)` calls, and `finish_entry(index)`. Each
    /// callback must return `None`/`True` to continue or `False` to cancel.
    /// `finish_entry` is called only after the member and folder CRCs pass.
    #[pyo3(signature = (sink, *, cancellation=None,
        max_work_units=1_000_000_000))]
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
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonEntrySink::new(sink, sink_cancellation);
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }

    /// Sends bounded chunks to a callback and returns the verified byte count.
    ///
    /// The callback must return `None`/`True` to continue or `False` to cancel.
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
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(callback, SinkMode::Callback, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }
}
