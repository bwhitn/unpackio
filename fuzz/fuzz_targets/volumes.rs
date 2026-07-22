#![no_main]
#![forbid(unsafe_code)]

mod support;

use libfuzzer_sys::fuzz_target;
use unpackio::{Archive, CancellationToken, Limits, MemoryVolumeProvider, Result, WorkBudget};

fn limits() -> Limits {
    Limits::builder()
        .max_header_bytes(64 * 1024)
        .max_files(32)
        .max_folders(16)
        .max_coders_per_folder(8)
        .max_total_coders(32)
        .max_streams_per_folder(32)
        .max_total_streams(64)
        .max_substreams(32)
        .max_header_properties(128)
        .max_coder_property_bytes(1024)
        .max_name_bytes_per_entry(4096)
        .max_total_name_bytes(16 * 1024)
        .max_dictionary_bytes(1024 * 1024)
        .max_entry_output_bytes(1024 * 1024)
        .max_total_output_bytes(2 * 1024 * 1024)
        .max_volumes(8)
        .max_total_input_bytes(2 * 1024 * 1024)
        .max_recursion_depth(8)
        .sfx_scan_limit(64 * 1024)
        .build()
}

fn split(bytes: &[u8], width: usize) -> Vec<Vec<u8>> {
    let width = width.max(1);
    bytes.chunks(width).take(9).map(<[u8]>::to_vec).collect()
}

fn exercise(parts: Vec<Vec<u8>>, limits: Limits) -> Result<()> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let mut provider = MemoryVolumeProvider::new(parts);
    let archive = Archive::open_volumes(
        &mut provider,
        "fuzz.7z.001",
        limits,
        &cancellation,
        &mut budget,
    )?;
    archive.verify(&cancellation, &mut budget)
}

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().map_or(1_usize, usize::from);
    let width = selector % 4096 + 1;
    let payload = match data.get(1..) {
        Some(payload) => payload,
        None => &[],
    };
    let _ = exercise(split(payload, width), limits());

    if let Some(archive) = support::wrap_copy_archive(payload) {
        let parts = split(&archive, width);
        let _ = exercise(parts.clone(), limits());
        if selector & 1 != 0 {
            let mut missing = parts;
            let _ = missing.pop();
            let _ = exercise(missing, limits());
        }
    }
});
