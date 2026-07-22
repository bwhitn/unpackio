//! Translation between stable core errors and Python exceptions.

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
};

use pyo3::{
    create_exception,
    exceptions::{PyBaseException, PyException},
    prelude::*,
    types::PyBytes,
};
use unpackio::{ChecksumScope, Error, LimitKind};

create_exception!(
    unpackio._native,
    UnpackioError,
    PyException,
    "Base unpackio exception."
);
create_exception!(
    unpackio._native,
    FormatError,
    UnpackioError,
    "Malformed compressed input."
);
create_exception!(
    unpackio._native,
    ChecksumError,
    UnpackioError,
    "A required compressed-input checksum did not match."
);
create_exception!(
    unpackio._native,
    UnsupportedMethodError,
    UnpackioError,
    "No decoder is available for a method identifier."
);
create_exception!(
    unpackio._native,
    UnsupportedFeatureError,
    UnpackioError,
    "A valid input feature is not implemented."
);
create_exception!(
    unpackio._native,
    LimitExceededError,
    UnpackioError,
    "A configured resource bound was exceeded."
);
create_exception!(
    unpackio._native,
    MissingVolumeError,
    UnpackioError,
    "A required sequential archive volume is absent."
);
create_exception!(
    unpackio._native,
    PasswordRequiredError,
    UnpackioError,
    "Encrypted archive content requires a password."
);
create_exception!(
    unpackio._native,
    WrongPasswordOrCorruptError,
    UnpackioError,
    "The password is wrong or encrypted archive bytes are corrupt."
);
create_exception!(
    unpackio._native,
    CancelledError,
    UnpackioError,
    "The archive operation was cancelled."
);
create_exception!(
    unpackio._native,
    ArchiveIoError,
    UnpackioError,
    "An archive input or output operation failed."
);
create_exception!(
    unpackio._native,
    InternalError,
    UnpackioError,
    "An unexpected native failure was contained at the FFI boundary."
);

/// An exception returned by a Python provider, writer, or callback while the
/// archive core is operating outside the interpreter.
#[derive(Debug)]
pub(crate) struct PythonCallbackError {
    error: PyErr,
}

impl PythonCallbackError {
    pub(crate) const fn new(error: PyErr) -> Self {
        Self { error }
    }

    fn clone_error(&self, py: Python<'_>) -> PyErr {
        self.error.clone_ref(py)
    }
}

impl fmt::Display for PythonCallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Python callback failed")
    }
}

impl std::error::Error for PythonCallbackError {}

fn checksum_scope_name(scope: ChecksumScope) -> &'static str {
    match scope {
        ChecksumScope::StartHeader => "start_header",
        ChecksumScope::NextHeader => "next_header",
        ChecksumScope::EncodedHeader => "encoded_header",
        ChecksumScope::PackedStream => "packed_stream",
        ChecksumScope::Folder => "folder",
        ChecksumScope::AdditionalStream => "additional_stream",
        ChecksumScope::Member => "member",
        ChecksumScope::PackageHeader => "package_header",
        ChecksumScope::PackagePayload => "package_payload",
        _ => "unknown",
    }
}

fn limit_name(limit: LimitKind) -> &'static str {
    match limit {
        LimitKind::HeaderBytes => "header_bytes",
        LimitKind::Files => "files",
        LimitKind::Folders => "folders",
        LimitKind::CodersPerFolder => "coders_per_folder",
        LimitKind::TotalCoders => "total_coders",
        LimitKind::StreamsPerFolder => "streams_per_folder",
        LimitKind::TotalStreams => "total_streams",
        LimitKind::StreamFrames => "stream_frames",
        LimitKind::Substreams => "substreams",
        LimitKind::HeaderProperties => "header_properties",
        LimitKind::CoderPropertyBytes => "coder_property_bytes",
        LimitKind::NameBytesPerEntry => "name_bytes_per_entry",
        LimitKind::TotalNameBytes => "total_name_bytes",
        LimitKind::DictionaryBytes => "dictionary_bytes",
        LimitKind::EntryOutputBytes => "entry_output_bytes",
        LimitKind::TotalOutputBytes => "total_output_bytes",
        LimitKind::Volumes => "volumes",
        LimitKind::TotalInputBytes => "total_input_bytes",
        LimitKind::KdfPower => "kdf_power",
        LimitKind::RecursionDepth => "recursion_depth",
        LimitKind::SfxScanBytes => "sfx_scan_bytes",
        LimitKind::WorkUnits => "work_units",
        _ => "unknown",
    }
}

fn structured_error(
    py: Python<'_>,
    error: PyErr,
    kind: &'static str,
    attributes: impl FnOnce(&Bound<'_, PyBaseException>) -> PyResult<()>,
) -> PyErr {
    let value = error.value(py);
    let result = value.setattr("kind", kind).and_then(|()| attributes(value));
    match result {
        Ok(()) => error,
        Err(attribute_error) => attribute_error,
    }
}

/// Converts a stable core error without erasing its machine-readable payload.
pub(crate) fn map_core_error(py: Python<'_>, error: Error) -> PyErr {
    map_core_error_for(py, error, "7z")
}

/// Converts a stable core error with the concrete caller-selected format.
pub(crate) fn map_core_error_for(
    py: Python<'_>,
    error: Error,
    archive_format: &'static str,
) -> PyErr {
    match error {
        Error::Format { detail } => {
            let message = format!("invalid {archive_format} format: {detail}");
            structured_error(py, FormatError::new_err(message), "format", |value| {
                value.setattr("detail", detail)?;
                value.setattr("format", archive_format)
            })
        }
        Error::StreamFormat { format, detail } => {
            let message = format!("invalid {format} stream: {detail}");
            structured_error(py, FormatError::new_err(message), "format", |value| {
                value.setattr("detail", detail)?;
                value.setattr("format", format)
            })
        }
        Error::Checksum {
            scope,
            member_index,
        } => {
            let message = match member_index {
                Some(index) => format!("{scope} checksum mismatch at member {index}"),
                None => format!("{scope} checksum mismatch"),
            };
            structured_error(py, ChecksumError::new_err(message), "checksum", |value| {
                value.setattr("scope", checksum_scope_name(scope))?;
                value.setattr("member_index", member_index)?;
                value.setattr("format", archive_format)?;
                value.setattr("frame_index", None::<u64>)
            })
        }
        Error::StreamChecksum {
            format,
            frame_index,
        } => {
            let message = format!("{format} checksum mismatch at frame {frame_index}");
            structured_error(py, ChecksumError::new_err(message), "checksum", |value| {
                value.setattr("scope", "stream_frame")?;
                value.setattr("member_index", None::<u64>)?;
                value.setattr("format", format)?;
                value.setattr("frame_index", frame_index)
            })
        }
        Error::UnsupportedMethod { method_id } => {
            let method_hex = method_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let message = format!("unsupported {archive_format} method 0x{method_hex}");
            structured_error(
                py,
                UnsupportedMethodError::new_err(message),
                "unsupported_method",
                |value| {
                    value.setattr("method_id", PyBytes::new(py, &method_id))?;
                    value.setattr("method_id_hex", method_hex)
                },
            )
        }
        Error::UnsupportedFeature { feature } => {
            let message = format!("unsupported {archive_format} feature: {feature}");
            structured_error(
                py,
                UnsupportedFeatureError::new_err(message),
                "unsupported_feature",
                |value| {
                    value.setattr("feature", feature)?;
                    value.setattr("format", archive_format)
                },
            )
        }
        Error::UnsupportedStreamFeature { format, feature } => {
            let message = format!("unsupported {format} stream feature: {feature}");
            structured_error(
                py,
                UnsupportedFeatureError::new_err(message),
                "unsupported_feature",
                |value| {
                    value.setattr("feature", feature)?;
                    value.setattr("format", format)
                },
            )
        }
        Error::LimitExceeded {
            limit,
            requested,
            maximum,
        } => structured_error(
            py,
            LimitExceededError::new_err(format!(
                "limit exceeded for {limit}: requested {requested}, maximum {maximum}"
            )),
            "limit_exceeded",
            |value| {
                value.setattr("limit", limit_name(limit))?;
                value.setattr("requested", requested)?;
                value.setattr("maximum", maximum)
            },
        ),
        Error::MissingVolume { expected } => {
            let message = format!("missing archive volume: {expected}");
            structured_error(
                py,
                MissingVolumeError::new_err(message),
                "missing_volume",
                |value| value.setattr("expected", expected),
            )
        }
        Error::PasswordRequired => structured_error(
            py,
            PasswordRequiredError::new_err("archive password required"),
            "password_required",
            |_| Ok(()),
        ),
        Error::WrongPasswordOrCorrupt => structured_error(
            py,
            WrongPasswordOrCorruptError::new_err("wrong password or corrupt encrypted data"),
            "wrong_password_or_corrupt",
            |_| Ok(()),
        ),
        Error::Cancelled => structured_error(
            py,
            CancelledError::new_err("archive operation cancelled"),
            "cancelled",
            |_| Ok(()),
        ),
        Error::Io(error) => {
            if let Some(callback) = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<PythonCallbackError>())
            {
                return callback.clone_error(py);
            }
            let raw_os_error = error.raw_os_error();
            let io_kind = format!("{:?}", error.kind());
            let message = error.to_string();
            structured_error(
                py,
                ArchiveIoError::new_err(format!("archive I/O error: {message}")),
                "io",
                |value| {
                    value.setattr("io_kind", io_kind)?;
                    value.setattr("raw_os_error", raw_os_error)?;
                    value.setattr("detail", message)
                },
            )
        }
        other => structured_error(
            py,
            UnpackioError::new_err(other.to_string()),
            "unknown",
            |_| Ok(()),
        ),
    }
}

pub(crate) fn callback_cancelled_error(py: Python<'_>) -> PyErr {
    structured_error(
        py,
        CancelledError::new_err("stream callback requested cancellation"),
        "cancelled",
        |_| Ok(()),
    )
}

fn contain_unwind<T>(operation: impl FnOnce() -> T) -> Result<T, ()> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| ())
}

fn internal_error(message: &'static str) -> PyErr {
    Python::attach(|py| {
        structured_error(py, InternalError::new_err(message), "internal", |_| Ok(()))
    })
}

/// Contains any unexpected unwind from a Python-visible native entry point.
pub(crate) fn guard<T>(operation: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    match contain_unwind(operation) {
        Ok(result) => result,
        Err(_) => Err(internal_error(
            "unexpected native failure contained at the unpackio FFI boundary",
        )),
    }
}

/// Runs Rust-only archive work while detached from the interpreter.
pub(crate) fn detached_core<T, F>(py: Python<'_>, operation: F) -> PyResult<T>
where
    T: Send,
    F: FnOnce() -> unpackio::Result<T> + Send,
{
    guard(
        || match py.detach(|| catch_unwind(AssertUnwindSafe(operation))) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(map_core_error(py, error)),
            Err(_) => Err(internal_error(
                "unexpected native failure contained during unpackio archive processing",
            )),
        },
    )
}

/// Runs Rust-only work detached from Python and preserves its selected format
/// in structured exceptions.
pub(crate) fn detached_core_for<T, F>(
    py: Python<'_>,
    archive_format: &'static str,
    operation: F,
) -> PyResult<T>
where
    T: Send,
    F: FnOnce() -> unpackio::Result<T> + Send,
{
    guard(
        || match py.detach(|| catch_unwind(AssertUnwindSafe(operation))) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(map_core_error_for(py, error, archive_format)),
            Err(_) => Err(internal_error(
                "unexpected native failure contained during unpackio archive processing",
            )),
        },
    )
}

pub(crate) fn add_exceptions(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("UnpackioError", module.py().get_type::<UnpackioError>())?;
    module.add("FormatError", module.py().get_type::<FormatError>())?;
    module.add("ChecksumError", module.py().get_type::<ChecksumError>())?;
    module.add(
        "UnsupportedMethodError",
        module.py().get_type::<UnsupportedMethodError>(),
    )?;
    module.add(
        "UnsupportedFeatureError",
        module.py().get_type::<UnsupportedFeatureError>(),
    )?;
    module.add(
        "LimitExceededError",
        module.py().get_type::<LimitExceededError>(),
    )?;
    module.add(
        "MissingVolumeError",
        module.py().get_type::<MissingVolumeError>(),
    )?;
    module.add(
        "PasswordRequiredError",
        module.py().get_type::<PasswordRequiredError>(),
    )?;
    module.add(
        "WrongPasswordOrCorruptError",
        module.py().get_type::<WrongPasswordOrCorruptError>(),
    )?;
    module.add("CancelledError", module.py().get_type::<CancelledError>())?;
    module.add("ArchiveIoError", module.py().get_type::<ArchiveIoError>())?;
    module.add("InternalError", module.py().get_type::<InternalError>())
}

#[cfg(test)]
mod tests {
    use std::io;

    use pyo3::{PyTypeInfo, exceptions::PyRuntimeError, prelude::*};
    use unpackio::{ChecksumScope, Error, LimitKind};

    use super::{
        ArchiveIoError, CancelledError, ChecksumError, FormatError, InternalError,
        LimitExceededError, MissingVolumeError, PasswordRequiredError, UnsupportedFeatureError,
        UnsupportedMethodError, WrongPasswordOrCorruptError, guard, map_core_error,
    };

    fn assert_mapping<T: PyTypeInfo>(
        py: Python<'_>,
        source: Error,
        expected_kind: &str,
    ) -> PyResult<()> {
        let mapped = map_core_error(py, source);
        if !mapped.is_instance_of::<T>(py) {
            return Err(PyRuntimeError::new_err(
                "core error mapped to the wrong Python exception type",
            ));
        }
        let actual_kind: String = mapped.value(py).getattr("kind")?.extract()?;
        if actual_kind != expected_kind {
            return Err(PyRuntimeError::new_err(
                "Python exception has the wrong structured kind",
            ));
        }
        Ok(())
    }

    #[test]
    fn ffi_guard_contains_an_unexpected_unwind() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            let result: PyResult<()> = guard(|| std::panic::resume_unwind(Box::new("test unwind")));
            let error = match result {
                Err(error) => error,
                Ok(()) => {
                    return Err(PyRuntimeError::new_err(
                        "the FFI guard did not contain an injected unwind",
                    ));
                }
            };
            if !error.is_instance_of::<InternalError>(py) {
                return Err(PyRuntimeError::new_err(
                    "an injected unwind did not become InternalError",
                ));
            }
            let kind: String = error.value(py).getattr("kind")?.extract()?;
            if kind != "internal" {
                return Err(PyRuntimeError::new_err(
                    "InternalError is missing its structured kind",
                ));
            }
            Ok(())
        })
    }

    #[test]
    fn every_stable_core_error_has_a_distinct_python_mapping() -> PyResult<()> {
        Python::initialize();
        Python::attach(|py| {
            assert_mapping::<FormatError>(
                py,
                Error::Format {
                    detail: String::from("test"),
                },
                "format",
            )?;
            assert_mapping::<FormatError>(
                py,
                Error::StreamFormat {
                    format: String::from("lz4"),
                    detail: String::from("test"),
                },
                "format",
            )?;
            assert_mapping::<ChecksumError>(
                py,
                Error::Checksum {
                    scope: ChecksumScope::Member,
                    member_index: Some(7),
                },
                "checksum",
            )?;
            assert_mapping::<ChecksumError>(
                py,
                Error::StreamChecksum {
                    format: String::from("zstandard"),
                    frame_index: 2,
                },
                "checksum",
            )?;
            assert_mapping::<UnsupportedMethodError>(
                py,
                Error::UnsupportedMethod {
                    method_id: vec![0xAA].into_boxed_slice(),
                },
                "unsupported_method",
            )?;
            assert_mapping::<UnsupportedFeatureError>(
                py,
                Error::UnsupportedFeature {
                    feature: String::from("test feature"),
                },
                "unsupported_feature",
            )?;
            assert_mapping::<UnsupportedFeatureError>(
                py,
                Error::UnsupportedStreamFeature {
                    format: String::from("lz4"),
                    feature: String::from("external-dictionary"),
                },
                "unsupported_feature",
            )?;
            assert_mapping::<LimitExceededError>(
                py,
                Error::LimitExceeded {
                    limit: LimitKind::WorkUnits,
                    requested: 2,
                    maximum: 1,
                },
                "limit_exceeded",
            )?;
            assert_mapping::<MissingVolumeError>(
                py,
                Error::MissingVolume {
                    expected: String::from("archive.002"),
                },
                "missing_volume",
            )?;
            assert_mapping::<PasswordRequiredError>(
                py,
                Error::PasswordRequired,
                "password_required",
            )?;
            assert_mapping::<WrongPasswordOrCorruptError>(
                py,
                Error::WrongPasswordOrCorrupt,
                "wrong_password_or_corrupt",
            )?;
            assert_mapping::<CancelledError>(py, Error::Cancelled, "cancelled")?;
            assert_mapping::<ArchiveIoError>(py, Error::Io(io::Error::other("test")), "io")
        })
    }
}
