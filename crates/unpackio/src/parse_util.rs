//! Shared checked arithmetic, allocation, and operation-control helpers.

use std::io;

use crate::{CancellationToken, Error, LimitKind, Result, WorkBudget};

pub(crate) const CONTROL_CHUNK_SIZE: usize = 4096;

pub(crate) struct ParseControl<'control> {
    cancellation: &'control CancellationToken,
    budget: &'control mut WorkBudget,
}

impl<'control> ParseControl<'control> {
    pub(crate) const fn new(
        cancellation: &'control CancellationToken,
        budget: &'control mut WorkBudget,
    ) -> Self {
        Self {
            cancellation,
            budget,
        }
    }

    pub(crate) fn checkpoint(&mut self, units: u64) -> Result<()> {
        self.cancellation.check()?;
        self.budget.charge(units)
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn consume_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return self.checkpoint(0);
        }
        for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
            self.checkpoint(usize_to_u64(
                chunk.len(),
                "work chunk length is not representable as u64",
            )?)?;
        }
        Ok(())
    }
}

pub(crate) fn format_error(detail: &'static str) -> Error {
    Error::Format {
        detail: String::from(detail),
    }
}

pub(crate) fn usize_to_u64(value: usize, detail: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| format_error(detail))
}

pub(crate) fn u64_to_usize(value: u64, detail: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| format_error(detail))
}

pub(crate) fn checked_range<'data>(
    bytes: &'data [u8],
    start: u64,
    length: u64,
    overflow_detail: &'static str,
    truncated_detail: &'static str,
) -> Result<&'data [u8]> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| format_error(overflow_detail))?;
    let start = u64_to_usize(
        start,
        "byte range start is not representable on this platform",
    )?;
    let end = u64_to_usize(end, "byte range end is not representable on this platform")?;
    bytes
        .get(start..end)
        .ok_or_else(|| format_error(truncated_detail))
}

pub(crate) fn check_limit(value: u64, maximum: u64, limit: LimitKind) -> Result<()> {
    if value > maximum {
        Err(Error::LimitExceeded {
            limit,
            requested: value,
            maximum,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn try_reserve<T>(values: &mut Vec<T>, additional: usize) -> Result<()> {
    values.try_reserve_exact(additional).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "archive model allocation failed",
        ))
    })
}

pub(crate) fn copy_bytes(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<Box<[u8]>> {
    control.checkpoint(usize_to_u64(
        bytes.len(),
        "copied byte length is not representable as u64",
    )?)?;
    let mut copy = Vec::new();
    try_reserve(&mut copy, bytes.len())?;
    for chunk in bytes.chunks(CONTROL_CHUNK_SIZE) {
        control.checkpoint(0)?;
        copy.extend_from_slice(chunk);
    }
    Ok(copy.into_boxed_slice())
}
