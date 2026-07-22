#![no_main]
#![forbid(unsafe_code)]

mod support;

use libfuzzer_sys::fuzz_target;
use unpackio::{CancellationToken, Limits, WorkBudget, parse_archive};

fn next_byte(input: &mut std::slice::Iter<'_, u8>) -> u8 {
    match input.next() {
        Some(value) => *value,
        None => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = data.iter();
    let Some(coder_count) = (next_byte(&mut input) % 4).checked_add(1) else {
        return;
    };
    let mut header = Vec::from([0x01, 0x04, 0x06, 0, 1, 0x09, 0, 0, 0x07, 0x0b, 1, 0]);
    header.push(coder_count);
    for _ in 0..coder_count {
        header.extend_from_slice(&[1, 0]);
    }
    let Some(bind_count) = coder_count.checked_sub(1) else {
        return;
    };
    for _ in 0..bind_count {
        header.push(next_byte(&mut input) % coder_count);
        header.push(next_byte(&mut input) % coder_count);
    }
    header.push(0x0c);
    header.extend(std::iter::repeat_n(0, usize::from(coder_count)));
    header.extend_from_slice(&[0, 0, 0]);

    let Some(archive) = support::wrap_next_header(&header) else {
        return;
    };
    let limits = Limits::builder()
        .max_header_bytes(4096)
        .max_files(32)
        .max_folders(32)
        .max_coders_per_folder(8)
        .max_total_coders(32)
        .max_streams_per_folder(32)
        .max_total_streams(64)
        .max_substreams(32)
        .max_total_input_bytes(8192)
        .build();
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(64 * 1024);
    let _ = parse_archive(&archive, limits, &cancellation, &mut budget);
});
