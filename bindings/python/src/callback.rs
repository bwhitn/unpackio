//! Bounded adapters for Python writers, callbacks, and volume providers.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use pyo3::{
    exceptions::{PyMemoryError, PyTypeError, PyValueError},
    prelude::*,
    types::{PyBool, PyBytes},
};
use unpackio::{
    CancellationToken, EntrySink, Error, FileEntry, LimitKind, Result as CoreResult, Volume,
    VolumeProvider, VolumeRequest,
};

use crate::{
    errors::{PythonCallbackError, callback_cancelled_error},
    metadata::PyEntry,
};

pub(crate) fn callback_continues(
    result: &Bound<'_, PyAny>,
    return_type_error: &'static str,
) -> PyResult<bool> {
    if result.is_none() {
        return Ok(true);
    }
    if !result.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err(return_type_error));
    }
    result.extract::<bool>()
}

#[derive(Clone, Copy)]
pub(crate) enum SinkMode {
    Writer,
    Callback,
}

pub(crate) struct PythonSink {
    target: Py<PyAny>,
    mode: SinkMode,
    cancellation: CancellationToken,
}

impl PythonSink {
    pub(crate) const fn new(
        target: Py<PyAny>,
        mode: SinkMode,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            target,
            mode,
            cancellation,
        }
    }

    pub(crate) fn callback_error(error: PyErr) -> io::Error {
        io::Error::other(PythonCallbackError::new(error))
    }
}

impl Write for PythonSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Python::attach(|py| {
            let chunk = PyBytes::new_with(py, bytes.len(), |output| {
                output.copy_from_slice(bytes);
                Ok(())
            })?;
            let target = self.target.bind(py);
            let result = match self.mode {
                SinkMode::Writer => target.call_method1("write", (chunk,)),
                SinkMode::Callback => target.call1((chunk,)),
            }?;
            match self.mode {
                SinkMode::Writer => {
                    let count = result.extract::<usize>().map_err(|_| {
                        PyTypeError::new_err("writer.write() must return an integer byte count")
                    })?;
                    if count > bytes.len() {
                        return Err(PyValueError::new_err(
                            "writer.write() returned more bytes than it received",
                        ));
                    }
                    Ok(count)
                }
                SinkMode::Callback => {
                    if !callback_continues(&result, "stream callback must return None or bool")? {
                        self.cancellation.cancel();
                        return Err(callback_cancelled_error(py));
                    }
                    Ok(bytes.len())
                }
            }
        })
        .map_err(Self::callback_error)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct PythonEntrySink {
    target: Py<PyAny>,
    cancellation: CancellationToken,
}

impl PythonEntrySink {
    pub(crate) const fn new(target: Py<PyAny>, cancellation: CancellationToken) -> Self {
        Self {
            target,
            cancellation,
        }
    }

    fn finish_callback(&self, result: PyResult<bool>) -> CoreResult<()> {
        match result {
            Ok(true) => self.cancellation.check(),
            Ok(false) => {
                self.cancellation.cancel();
                Err(Error::Cancelled)
            }
            Err(error) => Err(Error::Io(PythonSink::callback_error(error))),
        }
    }
}

impl EntrySink for PythonEntrySink {
    fn begin_entry(&mut self, member_index: u64, entry: &FileEntry, size: u64) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let entry = Py::new(py, PyEntry::from_core(member_index, entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, size))?;
            callback_continues(&result, "entry sink begin_entry() must return None or bool")
        });
        self.finish_callback(result)
    }

    fn write_entry(&mut self, member_index: u64, bytes: &[u8]) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let chunk = PyBytes::new_with(py, bytes.len(), |output| {
                output.copy_from_slice(bytes);
                Ok(())
            })?;
            let result = self
                .target
                .bind(py)
                .call_method1("write_entry", (member_index, chunk))?;
            callback_continues(&result, "entry sink write_entry() must return None or bool")
        });
        self.finish_callback(result)
    }

    fn finish_entry(&mut self, member_index: u64) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let result = self
                .target
                .bind(py)
                .call_method1("finish_entry", (member_index,))?;
            callback_continues(
                &result,
                "entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}

struct OwnedVolume {
    cursor: Cursor<Vec<u8>>,
}

impl Read for OwnedVolume {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(bytes)
    }
}

impl Seek for OwnedVolume {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

impl Volume for OwnedVolume {
    fn len(&mut self) -> io::Result<u64> {
        u64::try_from(self.cursor.get_ref().len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Python volume length is not representable as u64",
            )
        })
    }
}

enum ProviderOutcome {
    Missing,
    Bytes(Vec<u8>),
    Limit { requested: u64, maximum: u64 },
}

pub(crate) struct PythonVolumeProvider {
    provider: Py<PyAny>,
    max_total_input_bytes: u64,
}

impl PythonVolumeProvider {
    pub(crate) const fn new(provider: Py<PyAny>, max_total_input_bytes: u64) -> Self {
        Self {
            provider,
            max_total_input_bytes,
        }
    }

    fn invoke(&self, request: &VolumeRequest) -> PyResult<ProviderOutcome> {
        Python::attach(|py| {
            let provider = self.provider.bind(py);
            let response = if provider.hasattr("open_volume")? {
                provider.call_method1("open_volume", (request.index(), request.expected_name()))?
            } else {
                provider.call1((request.index(), request.expected_name()))?
            };
            if response.is_none() {
                return Ok(ProviderOutcome::Missing);
            }
            let bytes = response
                .cast::<PyBytes>()
                .map_err(|_| PyTypeError::new_err("volume provider must return bytes or None"))?;
            let source = bytes.as_bytes();
            let requested = u64::try_from(source.len()).map_err(|_| {
                PyValueError::new_err("Python volume length is not representable as u64")
            })?;
            if requested > self.max_total_input_bytes {
                return Ok(ProviderOutcome::Limit {
                    requested,
                    maximum: self.max_total_input_bytes,
                });
            }
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(source.len())
                .map_err(|_| PyMemoryError::new_err("unable to allocate Python volume copy"))?;
            owned.extend_from_slice(source);
            Ok(ProviderOutcome::Bytes(owned))
        })
    }
}

impl VolumeProvider for PythonVolumeProvider {
    fn open_volume(&mut self, request: &VolumeRequest) -> CoreResult<Box<dyn Volume>> {
        match self.invoke(request) {
            Ok(ProviderOutcome::Missing) => Err(Error::MissingVolume {
                expected: request.expected_name().to_owned(),
            }),
            Ok(ProviderOutcome::Limit { requested, maximum }) => Err(Error::LimitExceeded {
                limit: LimitKind::TotalInputBytes,
                requested,
                maximum,
            }),
            Ok(ProviderOutcome::Bytes(bytes)) => Ok(Box::new(OwnedVolume {
                cursor: Cursor::new(bytes),
            })),
            Err(error) => Err(Error::Io(io::Error::other(PythonCallbackError::new(error)))),
        }
    }
}
