//! Python-visible resource limits, work budgets, and cancellation.

use pyo3::prelude::*;
use unpackio::{CancellationToken as CoreCancellationToken, Limits as CoreLimits, WorkBudget};

/// Default deterministic work units for one Python operation.
pub(crate) const DEFAULT_WORK_UNITS: u64 = 1_000_000_000;

/// Immutable per-archive resource limits.
#[pyclass(
    name = "Limits",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone, Copy, Default)]
pub(crate) struct PyLimits {
    value: CoreLimits,
}

#[pymethods]
impl PyLimits {
    #[new]
    #[pyo3(signature = (*, max_header_bytes=None, max_files=None, max_folders=None,
        max_coders_per_folder=None, max_total_coders=None, max_streams_per_folder=None,
        max_total_streams=None, max_stream_frames=None, max_substreams=None, max_header_properties=None,
        max_coder_property_bytes=None, max_name_bytes_per_entry=None,
        max_total_name_bytes=None, max_dictionary_bytes=None, max_entry_output_bytes=None,
        max_total_output_bytes=None, max_volumes=None, max_total_input_bytes=None,
        max_kdf_power=None, max_recursion_depth=None, sfx_scan_limit=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        max_header_bytes: Option<u64>,
        max_files: Option<u64>,
        max_folders: Option<u64>,
        max_coders_per_folder: Option<u64>,
        max_total_coders: Option<u64>,
        max_streams_per_folder: Option<u64>,
        max_total_streams: Option<u64>,
        max_stream_frames: Option<u64>,
        max_substreams: Option<u64>,
        max_header_properties: Option<u64>,
        max_coder_property_bytes: Option<u64>,
        max_name_bytes_per_entry: Option<u64>,
        max_total_name_bytes: Option<u64>,
        max_dictionary_bytes: Option<u64>,
        max_entry_output_bytes: Option<u64>,
        max_total_output_bytes: Option<u64>,
        max_volumes: Option<u64>,
        max_total_input_bytes: Option<u64>,
        max_kdf_power: Option<u8>,
        max_recursion_depth: Option<u64>,
        sfx_scan_limit: Option<u64>,
    ) -> Self {
        let mut builder = CoreLimits::builder();
        if let Some(value) = max_header_bytes {
            builder = builder.max_header_bytes(value);
        }
        if let Some(value) = max_files {
            builder = builder.max_files(value);
        }
        if let Some(value) = max_folders {
            builder = builder.max_folders(value);
        }
        if let Some(value) = max_coders_per_folder {
            builder = builder.max_coders_per_folder(value);
        }
        if let Some(value) = max_total_coders {
            builder = builder.max_total_coders(value);
        }
        if let Some(value) = max_streams_per_folder {
            builder = builder.max_streams_per_folder(value);
        }
        if let Some(value) = max_total_streams {
            builder = builder.max_total_streams(value);
        }
        if let Some(value) = max_stream_frames {
            builder = builder.max_stream_frames(value);
        }
        if let Some(value) = max_substreams {
            builder = builder.max_substreams(value);
        }
        if let Some(value) = max_header_properties {
            builder = builder.max_header_properties(value);
        }
        if let Some(value) = max_coder_property_bytes {
            builder = builder.max_coder_property_bytes(value);
        }
        if let Some(value) = max_name_bytes_per_entry {
            builder = builder.max_name_bytes_per_entry(value);
        }
        if let Some(value) = max_total_name_bytes {
            builder = builder.max_total_name_bytes(value);
        }
        if let Some(value) = max_dictionary_bytes {
            builder = builder.max_dictionary_bytes(value);
        }
        if let Some(value) = max_entry_output_bytes {
            builder = builder.max_entry_output_bytes(value);
        }
        if let Some(value) = max_total_output_bytes {
            builder = builder.max_total_output_bytes(value);
        }
        if let Some(value) = max_volumes {
            builder = builder.max_volumes(value);
        }
        if let Some(value) = max_total_input_bytes {
            builder = builder.max_total_input_bytes(value);
        }
        if let Some(value) = max_kdf_power {
            builder = builder.max_kdf_power(value);
        }
        if let Some(value) = max_recursion_depth {
            builder = builder.max_recursion_depth(value);
        }
        if let Some(value) = sfx_scan_limit {
            builder = builder.sfx_scan_limit(value);
        }
        Self {
            value: builder.build(),
        }
    }

    #[getter]
    const fn max_header_bytes(&self) -> u64 {
        self.value.max_header_bytes()
    }

    #[getter]
    const fn max_files(&self) -> u64 {
        self.value.max_files()
    }

    #[getter]
    const fn max_folders(&self) -> u64 {
        self.value.max_folders()
    }

    #[getter]
    const fn max_coders_per_folder(&self) -> u64 {
        self.value.max_coders_per_folder()
    }

    #[getter]
    const fn max_total_coders(&self) -> u64 {
        self.value.max_total_coders()
    }

    #[getter]
    const fn max_streams_per_folder(&self) -> u64 {
        self.value.max_streams_per_folder()
    }

    #[getter]
    const fn max_total_streams(&self) -> u64 {
        self.value.max_total_streams()
    }

    #[getter]
    const fn max_stream_frames(&self) -> u64 {
        self.value.max_stream_frames()
    }

    #[getter]
    const fn max_substreams(&self) -> u64 {
        self.value.max_substreams()
    }

    #[getter]
    const fn max_header_properties(&self) -> u64 {
        self.value.max_header_properties()
    }

    #[getter]
    const fn max_coder_property_bytes(&self) -> u64 {
        self.value.max_coder_property_bytes()
    }

    #[getter]
    const fn max_name_bytes_per_entry(&self) -> u64 {
        self.value.max_name_bytes_per_entry()
    }

    #[getter]
    const fn max_total_name_bytes(&self) -> u64 {
        self.value.max_total_name_bytes()
    }

    #[getter]
    const fn max_dictionary_bytes(&self) -> u64 {
        self.value.max_dictionary_bytes()
    }

    #[getter]
    const fn max_entry_output_bytes(&self) -> u64 {
        self.value.max_entry_output_bytes()
    }

    #[getter]
    const fn max_total_output_bytes(&self) -> u64 {
        self.value.max_total_output_bytes()
    }

    #[getter]
    const fn max_volumes(&self) -> u64 {
        self.value.max_volumes()
    }

    #[getter]
    const fn max_total_input_bytes(&self) -> u64 {
        self.value.max_total_input_bytes()
    }

    #[getter]
    const fn max_kdf_power(&self) -> u8 {
        self.value.max_kdf_power()
    }

    #[getter]
    const fn max_recursion_depth(&self) -> u64 {
        self.value.max_recursion_depth()
    }

    #[getter]
    const fn sfx_scan_limit(&self) -> u64 {
        self.value.sfx_scan_limit()
    }

    fn __repr__(&self) -> String {
        format!(
            "Limits(max_header_bytes={}, max_files={}, max_dictionary_bytes={}, \
             max_entry_output_bytes={}, max_total_output_bytes={}, max_volumes={}, \
             max_total_input_bytes={}, max_kdf_power={})",
            self.value.max_header_bytes(),
            self.value.max_files(),
            self.value.max_dictionary_bytes(),
            self.value.max_entry_output_bytes(),
            self.value.max_total_output_bytes(),
            self.value.max_volumes(),
            self.value.max_total_input_bytes(),
            self.value.max_kdf_power(),
        )
    }
}

impl PyLimits {
    pub(crate) const fn from_core(value: CoreLimits) -> Self {
        Self { value }
    }

    pub(crate) const fn value(&self) -> CoreLimits {
        self.value
    }
}

/// A thread-safe, per-operation cancellation request.
#[pyclass(
    name = "CancellationToken",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone, Default)]
pub(crate) struct PyCancellationToken {
    value: CoreCancellationToken,
}

#[pymethods]
impl PyCancellationToken {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Repeated calls are harmless.
    fn cancel(&self) {
        self.value.cancel();
    }

    #[getter]
    fn is_cancelled(&self) -> bool {
        self.value.is_cancelled()
    }
}

impl PyCancellationToken {
    pub(crate) fn value(&self) -> CoreCancellationToken {
        self.value.clone()
    }
}

pub(crate) fn limits_or_default(limits: Option<&PyLimits>) -> CoreLimits {
    limits.map_or_else(CoreLimits::default, PyLimits::value)
}

pub(crate) fn cancellation_or_new(
    cancellation: Option<&PyCancellationToken>,
) -> CoreCancellationToken {
    cancellation.map_or_else(CoreCancellationToken::new, PyCancellationToken::value)
}

pub(crate) const fn work_budget(max_work_units: u64) -> WorkBudget {
    WorkBudget::bounded(max_work_units)
}
