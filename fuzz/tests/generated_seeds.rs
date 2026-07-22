#![forbid(unsafe_code)]

#[path = "../fuzz_targets/support.rs"]
mod support;

use unpackio::{
    Archive, CancellationToken, Error, ErrorKind, LimitKind, Limits, Result, WorkBudget,
};

fn limits() -> Limits {
    Limits::builder()
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
        .build()
}

fn verify_seed_with_limits(seed: &support::GeneratedDecoderSeed, limits: Limits) -> Result<()> {
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
        assert_eq!(
            archive.extract_entry(0, &cancellation, &mut budget)?,
            expected
        );
    }
    Ok(())
}

fn verify_seed(seed: &support::GeneratedDecoderSeed) -> Result<()> {
    verify_seed_with_limits(seed, limits())
}

fn ppmd_seed() -> Result<support::GeneratedDecoderSeed> {
    support::generated_decoder_seed(&[19, 0])
        .ok_or_else(|| std::io::Error::other("generated PPMd decoder seed is missing").into())
}

fn verification_rejection(bytes: Vec<u8>, limits: Limits) -> Result<Error> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
    match Archive::open_bytes(bytes, limits, &cancellation, &mut budget) {
        Ok(archive) => archive
            .verify(&cancellation, &mut budget)
            .err()
            .ok_or_else(|| std::io::Error::other("mutated archive verified").into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn every_generated_profile_verifies_and_every_mutation_is_bounded() -> Result<()> {
    for profile in 0_u8..21 {
        let data = [profile, 0, b'a', b'b', b'c', 0xe8, 0x0f, 0x80];
        let Some(seed) = support::generated_decoder_seed(&data) else {
            return Err(std::io::Error::other("generated decoder seed is missing").into());
        };
        verify_seed(&seed)?;
        for mutation in 0_u8..8 {
            let Some(bytes) = seed.mutated(mutation) else {
                continue;
            };
            let cancellation = CancellationToken::new();
            let mut budget = WorkBudget::bounded(8 * 1024 * 1024);
            let opened = match seed.password() {
                Some(password) => Archive::open_bytes_with_password(
                    bytes,
                    limits(),
                    password,
                    &cancellation,
                    &mut budget,
                ),
                None => Archive::open_bytes(bytes, limits(), &cancellation, &mut budget),
            };
            if let Ok(archive) = opened {
                let _ = archive.verify(&cancellation, &mut budget);
            }
        }
    }
    Ok(())
}

#[test]
fn ppmd_profile_enforces_integrity_and_operation_boundaries() -> Result<()> {
    let seed = ppmd_seed()?;
    verify_seed(&seed)?;

    // PPMd's first range byte is a fixed initialization marker, so corrupt a
    // later arithmetic-coded byte rather than pretending that marker affects
    // the decoded member.
    let Some(corrupted) = seed.mutated(8) else {
        return Err(std::io::Error::other("generated PPMd corruption is missing").into());
    };
    let error = verification_rejection(corrupted, limits())?;
    assert!(matches!(
        error.kind(),
        ErrorKind::Format | ErrorKind::Checksum
    ));

    // Selector 35 chooses the property-byte mutation class while targeting
    // the order byte; changing only the model size can remain a valid stream.
    for selector in [2_u8, 35, 5, 6, 7] {
        let Some(mutated) = seed.mutated(selector) else {
            return Err(std::io::Error::other("generated PPMd mutation is missing").into());
        };
        let error = match verification_rejection(mutated, limits()) {
            Ok(error) => error,
            Err(_) => {
                return Err(std::io::Error::other(format!(
                    "generated PPMd mutation {selector} verified"
                ))
                .into());
            }
        };
        if selector == 6 {
            assert_eq!(error.kind(), ErrorKind::Checksum);
        }
    }

    let limited_dictionary = Limits::builder()
        .max_dictionary_bytes((64 * 1024) - 1)
        .build();
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        Archive::open_bytes(
            seed.archive().to_vec(),
            limited_dictionary,
            &cancellation,
            &mut budget,
        ),
        Err(Error::LimitExceeded {
            limit: LimitKind::DictionaryBytes,
            requested: 65_536,
            maximum: 65_535,
        })
    ));

    let limited_output = Limits::builder()
        .max_entry_output_bytes(49)
        .max_total_output_bytes(49)
        .build();
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let output_result = Archive::open_bytes(
        seed.archive().to_vec(),
        limited_output,
        &cancellation,
        &mut budget,
    );
    let output_error = match output_result {
        Ok(archive) => archive
            .verify(&cancellation, &mut budget)
            .err()
            .ok_or_else(|| std::io::Error::other("limited PPMd stream verified"))?,
        Err(error) => error,
    };
    assert!(matches!(
        output_error,
        Error::LimitExceeded {
            limit: LimitKind::TotalOutputBytes | LimitKind::EntryOutputBytes,
            requested: 50,
            maximum: 49,
        }
    ));

    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(
        seed.archive().to_vec(),
        limits(),
        &cancellation,
        &mut open_budget,
    )?;
    let mut exhausted = WorkBudget::bounded(0);
    assert!(matches!(
        archive.verify(&cancellation, &mut exhausted),
        Err(Error::LimitExceeded {
            limit: LimitKind::WorkUnits,
            ..
        })
    ));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut budget = WorkBudget::unlimited();
    assert!(matches!(
        archive.verify(&cancelled, &mut budget),
        Err(Error::Cancelled)
    ));
    Ok(())
}
