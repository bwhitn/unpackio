#![forbid(unsafe_code)]
//! Opt-in natural-order solid-folder verification benchmark.

use std::{error::Error as StdError, fs, hint::black_box, io, path::Path, time::Instant};

use unpackio::{Archive, CancellationToken, EntrySink, FileEntry, Limits, WorkBudget};

#[derive(Default)]
struct CountingSink {
    bytes: u64,
}

impl EntrySink for CountingSink {
    fn begin_entry(
        &mut self,
        _member_index: u64,
        _entry: &FileEntry,
        _size: u64,
    ) -> unpackio::Result<()> {
        Ok(())
    }

    fn write_entry(&mut self, _member_index: u64, bytes: &[u8]) -> unpackio::Result<()> {
        let count = u64::try_from(bytes.len()).map_err(|_| {
            unpackio::Error::Io(io::Error::other(
                "benchmark chunk length is not representable as u64",
            ))
        })?;
        self.bytes = self.bytes.checked_add(count).ok_or_else(|| {
            unpackio::Error::Io(io::Error::other("benchmark sink byte count overflowed"))
        })?;
        Ok(())
    }

    fn finish_entry(&mut self, _member_index: u64) -> unpackio::Result<()> {
        Ok(())
    }
}

fn output_bytes(archive: &Archive) -> Result<u64, Box<dyn StdError>> {
    let mut total = 0_u64;
    for entry in archive.entries() {
        if let Some(size) = entry.size() {
            total = total
                .checked_add(size)
                .ok_or("benchmark output byte count overflowed")?;
        }
    }
    Ok(total)
}

fn main() -> Result<(), Box<dyn StdError>> {
    let Some(root) = std::env::var_os("UNPACKIO_7Z_TESTDATA") else {
        println!("natural_order_solid: skipped; UNPACKIO_7Z_TESTDATA is not set");
        return Ok(());
    };
    let iterations = match std::env::var("UNPACKIO_BENCH_ITERATIONS") {
        Ok(value) => value.parse::<u64>()?,
        Err(std::env::VarError::NotPresent) => 50,
        Err(error) => return Err(error.into()),
    };
    if iterations == 0 {
        return Err(String::from("UNPACKIO_BENCH_ITERATIONS must be non-zero").into());
    }
    let path = Path::new(&root).join("lzma2.7z");
    let bytes = fs::read(&path)?;
    let cancellation = CancellationToken::new();
    let mut open_budget = WorkBudget::unlimited();
    let archive = Archive::open_bytes(bytes, Limits::default(), &cancellation, &mut open_budget)?;
    let decoded_per_iteration = output_bytes(&archive)?;

    let mut warmup_budget = WorkBudget::unlimited();
    let mut warmup_sink = CountingSink::default();
    let warmup_bytes =
        archive.extract_entries_to(&mut warmup_sink, &cancellation, &mut warmup_budget)?;
    if warmup_bytes != decoded_per_iteration || warmup_sink.bytes != decoded_per_iteration {
        return Err(String::from("benchmark warmup byte count mismatch").into());
    }
    let work_per_iteration = warmup_budget.consumed();
    let resources = archive.resources();
    let start = Instant::now();
    for _ in 0..iterations {
        let mut budget = WorkBudget::unlimited();
        let mut sink = CountingSink::default();
        let extracted =
            black_box(&archive).extract_entries_to(&mut sink, &cancellation, &mut budget)?;
        if extracted != decoded_per_iteration || sink.bytes != decoded_per_iteration {
            return Err(String::from("benchmark extraction byte count mismatch").into());
        }
        if budget.consumed() != work_per_iteration {
            return Err(String::from("benchmark work accounting is not deterministic").into());
        }
    }
    let elapsed = start.elapsed();
    let total_decoded = decoded_per_iteration
        .checked_mul(iterations)
        .ok_or("benchmark total decoded bytes overflowed")?;
    let elapsed_nanos = elapsed.as_nanos();
    let bytes_per_second = u128::from(total_decoded)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_div(elapsed_nanos))
        .ok_or("benchmark duration was zero or throughput overflowed")?;
    let bytes_per_mib = 1024_u128 * 1024;
    let throughput_mib = bytes_per_second / bytes_per_mib;
    let throughput_mib_milli = (bytes_per_second % bytes_per_mib)
        .checked_mul(1000)
        .and_then(|value| value.checked_div(bytes_per_mib))
        .ok_or("benchmark fractional throughput overflowed")?;
    println!(
        "natural_order_solid: archive={} entries={} iterations={} decoded_bytes_per_iteration={} work_units_per_iteration={} archive_input_bytes={} archive_metadata_bytes={} archive_retained_bytes={} elapsed_seconds={:.6} throughput_mib_s={throughput_mib}.{throughput_mib_milli:03}",
        path.display(),
        archive.entries().len(),
        iterations,
        decoded_per_iteration,
        work_per_iteration,
        resources.input_bytes(),
        resources.metadata_bytes(),
        resources.retained_bytes(),
        elapsed.as_secs_f64()
    );
    Ok(())
}
