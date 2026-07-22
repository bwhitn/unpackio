//! RPM bridge to the shared checked CPIO parser.

use super::RpmEntry;
use crate::{Limits, Result, parse_util::ParseControl};

pub(super) fn parse(
    payload: &[u8],
    limits: Limits,
    control: &mut ParseControl<'_>,
) -> Result<Vec<RpmEntry>> {
    crate::cpio::parse_entries(payload, limits, control).map(|(_, entries)| entries)
}

pub(super) fn byte_sum(bytes: &[u8], control: &mut ParseControl<'_>) -> Result<u32> {
    crate::cpio::byte_sum(bytes, control)
}
