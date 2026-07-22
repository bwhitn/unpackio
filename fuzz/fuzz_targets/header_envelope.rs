#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use unpackio::{CancellationToken, Limits, WorkBudget, parse_archive_header};

const MINIMAL_PLAIN_ENVELOPE: &[u8] = &[
    0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x08, 0xa8, 0x34, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x23, 0xc2, 0x58,
    0x01, 0x00,
];

fuzz_target!(|data: &[u8]| {
    let limits = Limits::builder()
        .max_header_bytes(1024 * 1024)
        .max_total_input_bytes(2 * 1024 * 1024)
        .sfx_scan_limit(64 * 1024)
        .build();
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(4 * 1024 * 1024);
    let _ = parse_archive_header(data, limits, &cancellation, &mut budget);

    let Some(sfx_length) = data.len().checked_add(MINIMAL_PLAIN_ENVELOPE.len()) else {
        return;
    };
    let mut sfx = Vec::new();
    if sfx.try_reserve_exact(sfx_length).is_err() {
        return;
    }
    sfx.extend_from_slice(data);
    sfx.extend_from_slice(MINIMAL_PLAIN_ENVELOPE);
    let mut sfx_budget = WorkBudget::bounded(4 * 1024 * 1024);
    let _ = parse_archive_header(&sfx, limits, &cancellation, &mut sfx_budget);
});
