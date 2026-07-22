#![no_main]
#![forbid(unsafe_code)]

mod support;

use libfuzzer_sys::fuzz_target;
use unpackio::{Archive, CancellationToken, Limits, WorkBudget};

fn exercise(data: Vec<u8>, limits: Limits) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) = Archive::open_bytes(data, limits, &cancellation, &mut budget) {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_with_password(data: Vec<u8>, limits: Limits) {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    if let Ok(archive) =
        Archive::open_bytes_with_password(data, limits, "fuzz-password", &cancellation, &mut budget)
    {
        let _ = archive.verify(&cancellation, &mut budget);
    }
}

fn exercise_generated(
    seed: &support::GeneratedDecoderSeed,
    limits: Limits,
) -> unpackio::Result<()> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    let archive = match seed.password() {
        Some(password) => Archive::open_bytes_with_password(
            seed.archive().to_vec(),
            limits,
            password,
            &cancellation,
            &mut budget,
        )?,
        None => Archive::open_bytes(seed.archive().to_vec(), limits, &cancellation, &mut budget)?,
    };
    archive.verify(&cancellation, &mut budget)?;
    if let Some(expected) = seed.expected() {
        let actual = archive.extract_entry(0, &cancellation, &mut budget)?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let limits = Limits::builder()
        .max_header_bytes(64 * 1024)
        .max_files(32)
        .max_folders(16)
        .max_coders_per_folder(16)
        .max_total_coders(32)
        .max_streams_per_folder(64)
        .max_total_streams(128)
        .max_substreams(32)
        .max_header_properties(128)
        .max_coder_property_bytes(1024)
        .max_name_bytes_per_entry(4096)
        .max_total_name_bytes(16 * 1024)
        .max_dictionary_bytes(33 * 1024 * 1024)
        .max_entry_output_bytes(1024 * 1024)
        .max_total_output_bytes(2 * 1024 * 1024)
        .max_total_input_bytes(2 * 1024 * 1024)
        .max_kdf_power(8)
        .max_recursion_depth(8)
        .sfx_scan_limit(64 * 1024)
        .build();
    if let Some(seed) = support::generated_decoder_seed(data) {
        let generated = exercise_generated(&seed, limits);
        assert!(
            generated.is_ok(),
            "in-process generated decoder seed was rejected: {generated:?}"
        );
        let mutation_selector = data.get(1).copied().map_or(0, |value| value);
        if let Some(mutated) = seed.mutated(mutation_selector) {
            exercise(mutated.clone(), limits);
            exercise_with_password(mutated, limits);
        }
        if seed.password().is_some() {
            exercise(seed.archive().to_vec(), limits);
        }
    }
    exercise(data.to_vec(), limits);
    exercise_with_password(data.to_vec(), limits);
    if let Some(archive) = support::wrap_copy_archive(data) {
        exercise(archive, limits);
    }
    if let Some(archive) = support::wrap_unreferenced_additional_archive(data, b"member") {
        exercise(archive, limits);
    }

    let external_selector = data.first().copied().map_or(0, |value| value % 4);
    let arbitrary_folder = match data.get(1..) {
        Some(bytes) => bytes,
        None => &[],
    };
    let arbitrary_end = arbitrary_folder.len().min(256);
    let arbitrary_folder = match arbitrary_folder.get(..arbitrary_end) {
        Some(bytes) => bytes,
        None => &[],
    };
    let folder_definition: &[u8] = if external_selector == 0 {
        &[1, 1, 0]
    } else {
        arbitrary_folder
    };
    if let Some(archive) = support::wrap_external_folder_archive(data, folder_definition) {
        exercise(archive, limits);
    }

    let selector = data.first().copied().map_or(0, |value| value % 21);
    let delta_property = [selector];
    let ppmd_properties = [6, 0, 0x10, 0, 0];
    let aes_properties = [0, 0];
    let (method, properties): (&[u8], Option<&[u8]>) = match selector {
        0 => (&[0x21], Some(&[0])),
        1 => (&[0x03, 0x01, 0x01], Some(&[0x5d, 0x00, 0x10, 0x00, 0x00])),
        2 => (&[0x03], Some(&delta_property)),
        3 => (&[0x03, 0x03, 0x01, 0x03], None),
        4 => (&[0x03, 0x03, 0x02, 0x05], None),
        5 => (&[0x03, 0x03, 0x05, 0x01], None),
        6 => (&[0x0a], None),
        7 => (&[0x03, 0x03, 0x08, 0x05], None),
        8 => (&[0x04, 0x01, 0x08], None),
        9 => (&[0x04, 0x02, 0x02], None),
        10 => (&[0x03, 0x04, 0x01], Some(&ppmd_properties)),
        11 => (&[0x04, 0xf7, 0x11, 0x02], None),
        12 => (&[0x04, 0xf7, 0x11, 0x04], None),
        13 => (&[0x04, 0xf7, 0x11, 0x01], None),
        14 => (&[0x06, 0xf1, 0x07, 0x01], Some(&aes_properties)),
        15 => (&[0x04, 0x01, 0x09], None),
        16 => (&[0x03, 0x03, 0x04, 0x01], None),
        17 => (&[0x03, 0x03, 0x07, 0x01], None),
        18 => (&[0x0b], None),
        19 => (&[0x02, 0x03, 0x02], None),
        _ => (&[0x02, 0x03, 0x04], None),
    };
    let Ok(unpack_size) = u64::try_from(data.len()) else {
        return;
    };
    if let Some(archive) =
        support::wrap_one_coder_archive(data, method, properties, unpack_size, None)
    {
        exercise(archive.clone(), limits);
        exercise_with_password(archive, limits);
    }
    if matches!(selector, 0..=8 | 15..=20)
        && let Some(archive) =
            support::wrap_one_coder_archive(data, method, properties, u64::MAX, None)
    {
        exercise(archive, limits);
    }
});
