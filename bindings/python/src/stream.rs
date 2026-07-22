//! Python adapter for standalone compressed streams.

use std::{path::PathBuf, sync::Arc};

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use unpackio::{
    CompressedStream as CoreCompressedStream, StreamFormat, StreamInfo as CoreStreamInfo,
    StreamInfoKind,
};

use crate::{
    archive::copy_input,
    callback::{PythonSink, SinkMode},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{detached_core, guard},
};

fn parse_format(format: Option<String>) -> PyResult<Option<StreamFormat>> {
    let parsed = match format.as_deref() {
        None => None,
        Some("lz4") => Some(StreamFormat::Lz4),
        Some("zstd" | "zstandard") => Some(StreamFormat::Zstandard),
        Some("z" | "compress" | "unix-compress") => Some(StreamFormat::UnixCompress),
        Some(value) => {
            return Err(PyValueError::new_err(format!(
                "unsupported compressed-stream format {value:?}; expected lz4, zstd, or unix-compress"
            )));
        }
    };
    Ok(parsed)
}

fn open_stream_bytes_core(
    bytes: Vec<u8>,
    format: Option<StreamFormat>,
    limits: unpackio::Limits,
    cancellation: unpackio::CancellationToken,
    max_work_units: u64,
) -> unpackio::Result<CoreCompressedStream> {
    let mut budget = work_budget(max_work_units);
    match format {
        Some(format) => {
            CoreCompressedStream::open_bytes_as(bytes, format, limits, &cancellation, &mut budget)
        }
        None => CoreCompressedStream::open_bytes(bytes, limits, &cancellation, &mut budget),
    }
}

/// Opens an LZ4, Zstandard, or Unix `compress` byte stream.
#[pyfunction]
#[pyo3(signature = (data, *, format=None, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_stream_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    format: Option<String>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyCompressedStream> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let format = parse_format(format)?;
        let bytes = copy_input(py, data, limits)?;
        detached_core(py, move || {
            open_stream_bytes_core(bytes, format, limits, cancellation, max_work_units)
        })
        .map(PyCompressedStream::new)
    })
}

/// Opens one LZ4, Zstandard, or Unix `compress` path.
#[pyfunction]
#[pyo3(signature = (path, *, format=None, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_stream_path(
    py: Python<'_>,
    path: PathBuf,
    format: Option<String>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyCompressedStream> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let format = parse_format(format)?;
        detached_core(py, move || {
            let mut budget = work_budget(max_work_units);
            match format {
                Some(format) => CoreCompressedStream::open_path_as(
                    &path,
                    format,
                    limits,
                    &cancellation,
                    &mut budget,
                ),
                None => CoreCompressedStream::open_path(&path, limits, &cancellation, &mut budget),
            }
        })
        .map(PyCompressedStream::new)
    })
}

/// Validated metadata for one standalone compressed input.
#[pyclass(
    name = "StreamInfo",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyStreamInfo {
    format: String,
    compressed_size: u64,
    uncompressed_size: Option<u64>,
    frame_count: Option<u64>,
    skippable_frame_count: Option<u64>,
    content_checksum_frame_count: Option<u64>,
    block_checksum_frame_count: Option<u64>,
    dictionary_frame_count: Option<u64>,
    legacy_frame_count: Option<u64>,
    maximum_block_bytes: Option<u64>,
    maximum_window_bytes: Option<u64>,
    maximum_code_bits: Option<u8>,
    block_mode: Option<bool>,
    decoder_dictionary_bytes: Option<u64>,
}

impl From<CoreStreamInfo> for PyStreamInfo {
    fn from(info: CoreStreamInfo) -> Self {
        let mut value = Self {
            format: String::from(info.format().as_str()),
            compressed_size: info.compressed_size(),
            uncompressed_size: info.uncompressed_size(),
            frame_count: None,
            skippable_frame_count: None,
            content_checksum_frame_count: None,
            block_checksum_frame_count: None,
            dictionary_frame_count: None,
            legacy_frame_count: None,
            maximum_block_bytes: None,
            maximum_window_bytes: None,
            maximum_code_bits: None,
            block_mode: None,
            decoder_dictionary_bytes: None,
        };
        match info.kind() {
            StreamInfoKind::Lz4(lz4) => {
                value.frame_count = Some(lz4.frame_count());
                value.skippable_frame_count = Some(lz4.skippable_frame_count());
                value.content_checksum_frame_count = Some(lz4.content_checksum_frame_count());
                value.block_checksum_frame_count = Some(lz4.block_checksum_frame_count());
                value.dictionary_frame_count = Some(lz4.dictionary_frame_count());
                value.legacy_frame_count = Some(lz4.legacy_frame_count());
                value.maximum_block_bytes = Some(lz4.maximum_block_bytes());
            }
            StreamInfoKind::Zstandard(zstandard) => {
                value.frame_count = Some(zstandard.frame_count());
                value.skippable_frame_count = Some(zstandard.skippable_frame_count());
                value.content_checksum_frame_count = Some(zstandard.content_checksum_frame_count());
                value.dictionary_frame_count = Some(zstandard.dictionary_frame_count());
                value.maximum_window_bytes = Some(zstandard.maximum_window_bytes());
            }
            StreamInfoKind::UnixCompress(compress) => {
                value.maximum_code_bits = Some(compress.maximum_code_bits());
                value.block_mode = Some(compress.block_mode());
                value.decoder_dictionary_bytes = Some(compress.dictionary_bytes());
            }
            _ => {}
        }
        value
    }
}

#[pymethods]
impl PyStreamInfo {
    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "StreamInfo(format={:?}, compressed_size={}, uncompressed_size={:?})",
                self.format, self.compressed_size, self.uncompressed_size
            ))
        })
    }

    #[getter]
    fn format(&self) -> PyResult<String> {
        guard(|| Ok(self.format.clone()))
    }

    #[getter]
    const fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    #[getter]
    const fn uncompressed_size(&self) -> Option<u64> {
        self.uncompressed_size
    }

    #[getter]
    const fn frame_count(&self) -> Option<u64> {
        self.frame_count
    }

    #[getter]
    const fn skippable_frame_count(&self) -> Option<u64> {
        self.skippable_frame_count
    }

    #[getter]
    const fn content_checksum_frame_count(&self) -> Option<u64> {
        self.content_checksum_frame_count
    }

    #[getter]
    const fn block_checksum_frame_count(&self) -> Option<u64> {
        self.block_checksum_frame_count
    }

    #[getter]
    const fn dictionary_frame_count(&self) -> Option<u64> {
        self.dictionary_frame_count
    }

    #[getter]
    const fn legacy_frame_count(&self) -> Option<u64> {
        self.legacy_frame_count
    }

    #[getter]
    const fn maximum_block_bytes(&self) -> Option<u64> {
        self.maximum_block_bytes
    }

    #[getter]
    const fn maximum_window_bytes(&self) -> Option<u64> {
        self.maximum_window_bytes
    }

    #[getter]
    const fn maximum_code_bits(&self) -> Option<u8> {
        self.maximum_code_bits
    }

    #[getter]
    const fn block_mode(&self) -> Option<bool> {
        self.block_mode
    }

    #[getter]
    const fn decoder_dictionary_bytes(&self) -> Option<u64> {
        self.decoder_dictionary_bytes
    }
}

/// An owned standalone compressed-stream session.
#[pyclass(name = "CompressedStream", module = "unpackio._native", frozen)]
pub(crate) struct PyCompressedStream {
    value: Arc<CoreCompressedStream>,
}

impl PyCompressedStream {
    fn new(stream: CoreCompressedStream) -> Self {
        Self {
            value: Arc::new(stream),
        }
    }
}

#[pymethods]
impl PyCompressedStream {
    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            let info = self.value.info();
            Ok(format!(
                "CompressedStream(format={:?}, compressed_size={})",
                info.format().as_str(),
                info.compressed_size()
            ))
        })
    }

    #[getter]
    fn info(&self) -> PyResult<PyStreamInfo> {
        guard(|| Ok(self.value.info().into()))
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn retained_input_bytes(&self) -> PyResult<u64> {
        guard(|| Ok(self.value.retained_input_bytes()))
    }

    /// Fully decodes and verifies every applicable frame checksum.
    #[pyo3(signature = (*, cancellation=None, max_work_units=1_000_000_000))]
    fn verify(
        &self,
        py: Python<'_>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<()> {
        guard(|| {
            let stream = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                stream
                    .verify(&cancellation, &mut budget)
                    .map(|_extraction| ())
            })
        })
    }

    /// Sends bounded decoded chunks to `writer.write()`.
    #[pyo3(signature = (writer, *, cancellation=None, max_work_units=1_000_000_000))]
    fn extract_to(
        &self,
        py: Python<'_>,
        writer: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let stream = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(writer, SinkMode::Writer, sink_cancellation);
                stream
                    .extract_to(&mut sink, &cancellation, &mut budget)
                    .map(|extraction| extraction.output_bytes())
            })
        })
    }

    /// Sends bounded decoded chunks to a callback.
    #[pyo3(signature = (callback, *, cancellation=None, max_work_units=1_000_000_000))]
    fn stream(
        &self,
        py: Python<'_>,
        callback: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let stream = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core(py, move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(callback, SinkMode::Callback, sink_cancellation);
                stream
                    .extract_to(&mut sink, &cancellation, &mut budget)
                    .map(|extraction| extraction.output_bytes())
            })
        })
    }
}
