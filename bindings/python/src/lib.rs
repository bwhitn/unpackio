#![forbid(unsafe_code)]
#![deny(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
//! Native implementation of the `unpackio` Python package.

use pyo3::prelude::*;

mod archive;
mod arj;
mod callback;
mod config;
mod cpio;
mod deb;
mod errors;
mod metadata;
mod rpm;
mod stream;
mod zip;

/// Native implementation module installed as `unpackio._native`.
#[pymodule]
#[pyo3(name = "_native")]
fn native_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::guard(|| {
        errors::add_exceptions(module)?;
        module.add_class::<archive::PyArchive>()?;
        module.add_class::<arj::PyArjArchive>()?;
        module.add_class::<arj::PyArjEntry>()?;
        module.add_class::<config::PyLimits>()?;
        module.add_class::<config::PyCancellationToken>()?;
        module.add_class::<cpio::PyCpioArchive>()?;
        module.add_class::<cpio::PyCpioEntry>()?;
        module.add_class::<deb::PyDebArchive>()?;
        module.add_class::<deb::PyDebEntry>()?;
        module.add_class::<deb::PyDebMember>()?;
        module.add_class::<metadata::PyEntry>()?;
        module.add_class::<metadata::PyArchiveResources>()?;
        module.add_class::<stream::PyCompressedStream>()?;
        module.add_class::<stream::PyStreamInfo>()?;
        module.add_class::<rpm::PyRpmArchive>()?;
        module.add_class::<rpm::PyRpmEntry>()?;
        module.add_class::<rpm::PyRpmHeader>()?;
        module.add_class::<rpm::PyRpmHeaderEntry>()?;
        module.add_class::<zip::PyZipArchive>()?;
        module.add_class::<zip::PyZipEntry>()?;
        module.add_function(wrap_pyfunction!(archive::open_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(archive::open_path, module)?)?;
        module.add_function(wrap_pyfunction!(archive::open_volumes, module)?)?;
        module.add_function(wrap_pyfunction!(arj::open_arj_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(arj::open_arj_path, module)?)?;
        module.add_function(wrap_pyfunction!(cpio::open_cpio_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(cpio::open_cpio_path, module)?)?;
        module.add_function(wrap_pyfunction!(deb::open_deb_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(deb::open_deb_path, module)?)?;
        module.add_function(wrap_pyfunction!(stream::open_stream_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(stream::open_stream_path, module)?)?;
        module.add_function(wrap_pyfunction!(rpm::open_rpm_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(rpm::open_rpm_path, module)?)?;
        module.add_function(wrap_pyfunction!(zip::open_zip_bytes, module)?)?;
        module.add_function(wrap_pyfunction!(zip::open_zip_path, module)?)?;
        module.add("DEFAULT_MAX_WORK_UNITS", config::DEFAULT_WORK_UNITS)?;
        module.add(
            "IMPLEMENTATION_STATUS",
            "multi-format-unpack-readers-pre-alpha",
        )?;
        Ok(())
    })
}
