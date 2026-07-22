//! Owned Python snapshots of validated archive metadata.

use pyo3::prelude::*;
use unpackio::{
    ArchiveResources as CoreArchiveResources, EntryKind, FileEntry, UnsafePathReason,
    validate_safe_utf16_path,
};

fn entry_kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::SymbolicLink => "symlink",
        EntryKind::AntiItem => "anti_item",
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

/// One archive-order metadata record.
#[pyclass(
    name = "Entry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyEntry {
    #[pyo3(get)]
    index: u64,
    #[pyo3(get)]
    raw_name: Option<Vec<u16>>,
    #[pyo3(get)]
    name: Option<String>,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    has_stream: bool,
    #[pyo3(get)]
    is_empty_file: bool,
    #[pyo3(get)]
    is_anti_item: bool,
    #[pyo3(get)]
    size: Option<u64>,
    #[pyo3(get)]
    crc32: Option<u32>,
    #[pyo3(get)]
    creation_time: Option<u64>,
    #[pyo3(get)]
    access_time: Option<u64>,
    #[pyo3(get)]
    modification_time: Option<u64>,
    #[pyo3(get)]
    windows_attributes: Option<u32>,
    #[pyo3(get)]
    start_position: Option<u64>,
    #[pyo3(get)]
    unix_mode: Option<u32>,
    #[pyo3(get)]
    is_symlink: bool,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyEntry {
    pub(crate) fn from_core(index: u64, entry: &FileEntry) -> Self {
        let raw_name = entry.raw_name().map(<[u16]>::to_vec);
        let path_classification = entry.raw_name().map(validate_safe_utf16_path);
        let (is_safe_path, unsafe_path_reason) = match path_classification {
            Some(Ok(())) => (true, None),
            Some(Err(reason)) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
            None => (false, Some(String::from("missing"))),
        };
        Self {
            index,
            raw_name,
            name: entry.name_lossy(),
            kind: entry_kind_name(entry.kind()).to_owned(),
            has_stream: entry.has_stream(),
            is_empty_file: entry.is_empty_file(),
            is_anti_item: entry.is_anti_item(),
            size: entry.size(),
            crc32: entry.crc32(),
            creation_time: entry.creation_time(),
            access_time: entry.access_time(),
            modification_time: entry.modification_time(),
            windows_attributes: entry.windows_attributes(),
            start_position: entry.start_position(),
            unix_mode: entry.unix_mode(),
            is_symlink: entry.is_symlink(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyEntry {
    fn __repr__(&self) -> String {
        format!(
            "Entry(index={}, name={:?}, kind={:?}, size={:?}, crc32={:?})",
            self.index, self.name, self.kind, self.size, self.crc32
        )
    }
}

/// Accounted memory retained by an open archive session.
#[pyclass(
    name = "ArchiveResources",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone, Copy)]
pub(crate) struct PyArchiveResources {
    #[pyo3(get)]
    input_bytes: u64,
    #[pyo3(get)]
    metadata_bytes: u64,
    #[pyo3(get)]
    password_bytes: u64,
    #[pyo3(get)]
    retained_bytes: u64,
}

impl From<CoreArchiveResources> for PyArchiveResources {
    fn from(resources: CoreArchiveResources) -> Self {
        Self {
            input_bytes: resources.input_bytes(),
            metadata_bytes: resources.metadata_bytes(),
            password_bytes: resources.password_bytes(),
            retained_bytes: resources.retained_bytes(),
        }
    }
}

#[pymethods]
impl PyArchiveResources {
    fn __repr__(&self) -> String {
        format!(
            "ArchiveResources(input_bytes={}, metadata_bytes={}, password_bytes={}, \
             retained_bytes={})",
            self.input_bytes, self.metadata_bytes, self.password_bytes, self.retained_bytes
        )
    }
}
