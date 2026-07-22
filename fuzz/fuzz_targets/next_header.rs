#![no_main]
#![forbid(unsafe_code)]

mod support;

use libfuzzer_sys::fuzz_target;
use unpackio::{CancellationToken, Limits, WorkBudget, parse_archive};

fn parse(bytes: &[u8]) {
    let limits = Limits::builder()
        .max_header_bytes(1024 * 1024)
        .max_files(4096)
        .max_folders(4096)
        .max_total_coders(4096)
        .max_total_streams(8192)
        .max_substreams(4096)
        .max_header_properties(4096)
        .max_total_input_bytes(2 * 1024 * 1024)
        .build();
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let _ = parse_archive(bytes, limits, &cancellation, &mut budget);
}

fuzz_target!(|data: &[u8]| {
    if let Some(archive) = support::wrap_next_header(data) {
        parse(&archive);
    }

    let Some(capacity) = data.len().checked_add(2) else {
        return;
    };
    let mut plain = Vec::new();
    if plain.try_reserve_exact(capacity).is_err() {
        return;
    }
    plain.push(0x01);
    plain.extend_from_slice(data);
    plain.push(0x00);
    if let Some(archive) = support::wrap_next_header(&plain) {
        parse(&archive);
    }
});
