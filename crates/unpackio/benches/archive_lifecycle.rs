#![forbid(unsafe_code)]
//! Opt-in release benchmark for complete archive and stream lifecycles.

use std::{
    error::Error as StdError,
    fs,
    hint::black_box,
    io::{self, Write},
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use unpackio::{
    Archive, ArjArchive, ArjEntry, ArjEntrySink, CancellationToken, CompressedStream, CpioArchive,
    CpioEntry, CpioEntrySink, DebArchive, DebEntry, DebEntrySink, EntrySink, Error, FileEntry,
    Limits, RpmArchive, RpmEntry, RpmEntrySink, WorkBudget, ZipArchive, ZipEntry, ZipEntrySink,
};

const DEFAULT_ITERATIONS: u64 = 10;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IterationMetrics {
    entries: u64,
    output_bytes: u64,
    writes: u64,
    owned_output_allocations: u64,
    work_units: u64,
    cancellation_latency_ns: u64,
}

impl IterationMetrics {
    fn checked_add(self, other: Self) -> Result<Self, Box<dyn StdError>> {
        Ok(Self {
            entries: self
                .entries
                .checked_add(other.entries)
                .ok_or("entry count overflow")?,
            output_bytes: self
                .output_bytes
                .checked_add(other.output_bytes)
                .ok_or("output byte count overflow")?,
            writes: self
                .writes
                .checked_add(other.writes)
                .ok_or("write count overflow")?,
            owned_output_allocations: self
                .owned_output_allocations
                .checked_add(other.owned_output_allocations)
                .ok_or("owned output allocation count overflow")?,
            work_units: self
                .work_units
                .checked_add(other.work_units)
                .ok_or("work unit count overflow")?,
            cancellation_latency_ns: self
                .cancellation_latency_ns
                .checked_add(other.cancellation_latency_ns)
                .ok_or("cancellation latency overflow")?,
        })
    }

    fn stable_eq(self, other: Self) -> bool {
        let variable_cancellation =
            self.cancellation_latency_ns != 0 || other.cancellation_latency_ns != 0;
        Self {
            work_units: if variable_cancellation {
                0
            } else {
                self.work_units
            },
            cancellation_latency_ns: 0,
            ..self
        } == Self {
            work_units: if variable_cancellation {
                0
            } else {
                other.work_units
            },
            cancellation_latency_ns: 0,
            ..other
        }
    }
}

fn cancellation_latency<T, F>(
    cancellation: &CancellationToken,
    operation: F,
) -> Result<u64, Box<dyn StdError>>
where
    F: FnOnce() -> unpackio::Result<T>,
{
    let trigger = cancellation.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let trigger_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1));
        let cancelled_at = Instant::now();
        trigger.cancel();
        sender.send(cancelled_at)
    });
    let outcome = operation();
    let returned_at = Instant::now();
    let cancelled_at = receiver.recv()?;
    trigger_thread
        .join()
        .map_err(|_| "cancellation trigger thread panicked")??;
    match outcome {
        Err(Error::Cancelled) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("in-flight cancellation operation completed successfully".into()),
    }
    let latency = returned_at
        .checked_duration_since(cancelled_at)
        .ok_or("operation returned before the cancellation trigger")?;
    Ok(u64::try_from(latency.as_nanos())?)
}

#[derive(Default)]
struct CountingWriter {
    bytes: u64,
    writes: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("write length is not representable as u64"))?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| io::Error::other("writer byte count overflow"))?;
        self.writes = self
            .writes
            .checked_add(1)
            .ok_or_else(|| io::Error::other("writer call count overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CountingEntrySink {
    entries: u64,
    bytes: u64,
    writes: u64,
}

impl CountingEntrySink {
    fn begin(&mut self) -> unpackio::Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("batch entry count overflow")))?;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> unpackio::Result<()> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| Error::Io(io::Error::other("batch write length exceeds u64")))?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| Error::Io(io::Error::other("batch byte count overflow")))?;
        self.writes = self
            .writes
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("batch write count overflow")))?;
        Ok(())
    }
}

impl EntrySink for CountingEntrySink {
    fn begin_entry(
        &mut self,
        _member_index: u64,
        _entry: &FileEntry,
        _size: u64,
    ) -> unpackio::Result<()> {
        self.begin()
    }

    fn write_entry(&mut self, _member_index: u64, bytes: &[u8]) -> unpackio::Result<()> {
        self.write(bytes)
    }

    fn finish_entry(&mut self, _member_index: u64) -> unpackio::Result<()> {
        Ok(())
    }
}

macro_rules! impl_entry_sink {
    ($trait_name:ident, $entry_type:ty) => {
        impl $trait_name for CountingEntrySink {
            fn begin_entry(&mut self, _entry: &$entry_type) -> unpackio::Result<()> {
                self.begin()
            }

            fn write_entry(&mut self, _entry_index: u64, bytes: &[u8]) -> unpackio::Result<()> {
                self.write(bytes)
            }

            fn finish_entry(&mut self, _entry_index: u64) -> unpackio::Result<()> {
                Ok(())
            }
        }
    };
}

impl_entry_sink!(ZipEntrySink, ZipEntry);
impl_entry_sink!(RpmEntrySink, RpmEntry);
impl_entry_sink!(CpioEntrySink, CpioEntry);
impl_entry_sink!(DebEntrySink, DebEntry);
impl_entry_sink!(ArjEntrySink, ArjEntry);

trait LifecycleArchive: Sized {
    fn open_bytes_for_bench(
        bytes: Vec<u8>,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self>;

    fn open_path_for_bench(
        path: &Path,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self>;

    fn entry_count_for_bench(&self) -> usize;

    fn extract_bytes_for_bench(
        &self,
        index: u64,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Vec<u8>>;

    fn extract_to_for_bench(
        &self,
        index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<u64>;

    fn extract_batch_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<CountingEntrySink>;

    fn verify_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<()>;
}

impl LifecycleArchive for Archive {
    fn open_bytes_for_bench(
        bytes: Vec<u8>,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self> {
        match password {
            Some(password) => Archive::open_bytes_with_password(
                bytes,
                Limits::default(),
                password,
                cancellation,
                budget,
            ),
            None => Archive::open_bytes(bytes, Limits::default(), cancellation, budget),
        }
    }

    fn open_path_for_bench(
        path: &Path,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self> {
        match password {
            Some(password) => Archive::open_path_with_password(
                path,
                Limits::default(),
                password,
                cancellation,
                budget,
            ),
            None => Archive::open_path(path, Limits::default(), cancellation, budget),
        }
    }

    fn entry_count_for_bench(&self) -> usize {
        self.entries().len()
    }

    fn extract_bytes_for_bench(
        &self,
        index: u64,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Vec<u8>> {
        self.extract_entry(index, cancellation, budget)
    }

    fn extract_to_for_bench(
        &self,
        index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<u64> {
        self.extract_entry_to(index, writer, cancellation, budget)
    }

    fn extract_batch_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<CountingEntrySink> {
        let mut sink = CountingEntrySink::default();
        self.extract_entries_to(&mut sink, cancellation, budget)?;
        Ok(sink)
    }

    fn verify_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<()> {
        self.verify(cancellation, budget)
    }
}

macro_rules! impl_lifecycle_archive {
    ($archive:ty) => {
        impl LifecycleArchive for $archive {
            fn open_bytes_for_bench(
                bytes: Vec<u8>,
                _password: Option<&str>,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<Self> {
                Self::open_bytes(bytes, Limits::default(), cancellation, budget)
            }

            fn open_path_for_bench(
                path: &Path,
                _password: Option<&str>,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<Self> {
                Self::open_path(path, Limits::default(), cancellation, budget)
            }

            fn entry_count_for_bench(&self) -> usize {
                self.entries().len()
            }

            fn extract_bytes_for_bench(
                &self,
                index: u64,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<Vec<u8>> {
                let mut output = Vec::new();
                self.extract_entry_to(index, &mut output, cancellation, budget)?;
                Ok(output)
            }

            fn extract_to_for_bench(
                &self,
                index: u64,
                writer: &mut dyn Write,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<u64> {
                self.extract_entry_to(index, writer, cancellation, budget)
            }

            fn extract_batch_for_bench(
                &self,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<CountingEntrySink> {
                let mut sink = CountingEntrySink::default();
                self.extract_entries_to(&mut sink, cancellation, budget)?;
                Ok(sink)
            }

            fn verify_for_bench(
                &self,
                cancellation: &CancellationToken,
                budget: &mut WorkBudget,
            ) -> unpackio::Result<()> {
                self.verify(cancellation, budget)
            }
        }
    };
}

impl_lifecycle_archive!(RpmArchive);
impl_lifecycle_archive!(CpioArchive);
impl_lifecycle_archive!(DebArchive);
impl_lifecycle_archive!(ArjArchive);

impl LifecycleArchive for ZipArchive {
    fn open_bytes_for_bench(
        bytes: Vec<u8>,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self> {
        match password {
            Some(password) => ZipArchive::open_bytes_with_password(
                bytes,
                Limits::default(),
                password.as_bytes(),
                cancellation,
                budget,
            ),
            None => ZipArchive::open_bytes(bytes, Limits::default(), cancellation, budget),
        }
    }

    fn open_path_for_bench(
        path: &Path,
        password: Option<&str>,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Self> {
        match password {
            Some(password) => ZipArchive::open_path_with_password(
                path,
                Limits::default(),
                password.as_bytes(),
                cancellation,
                budget,
            ),
            None => ZipArchive::open_path(path, Limits::default(), cancellation, budget),
        }
    }

    fn entry_count_for_bench(&self) -> usize {
        self.entries().len()
    }

    fn extract_bytes_for_bench(
        &self,
        index: u64,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<Vec<u8>> {
        let mut output = Vec::new();
        self.extract_entry_to(index, &mut output, cancellation, budget)?;
        Ok(output)
    }

    fn extract_to_for_bench(
        &self,
        index: u64,
        writer: &mut dyn Write,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<u64> {
        self.extract_entry_to(index, writer, cancellation, budget)
    }

    fn extract_batch_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<CountingEntrySink> {
        let mut sink = CountingEntrySink::default();
        self.extract_entries_to(&mut sink, cancellation, budget)?;
        Ok(sink)
    }

    fn verify_for_bench(
        &self,
        cancellation: &CancellationToken,
        budget: &mut WorkBudget,
    ) -> unpackio::Result<()> {
        self.verify(cancellation, budget)
    }
}

fn archive_iteration<A: LifecycleArchive>(
    path: &Path,
    bytes: &[u8],
    password: Option<&str>,
    operation: &str,
    opened: Option<&A>,
) -> Result<IterationMetrics, Box<dyn StdError>> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let mut metrics = IterationMetrics::default();
    match operation {
        "inventory" => {
            let archive =
                A::open_bytes_for_bench(bytes.to_vec(), password, &cancellation, &mut budget)?;
            metrics.entries = u64::try_from(black_box(archive.entry_count_for_bench()))?;
        }
        "path-inventory" => {
            let archive = A::open_path_for_bench(path, password, &cancellation, &mut budget)?;
            metrics.entries = u64::try_from(black_box(archive.entry_count_for_bench()))?;
        }
        "path-verify" => {
            let archive = A::open_path_for_bench(path, password, &cancellation, &mut budget)?;
            archive.verify_for_bench(&cancellation, &mut budget)?;
        }
        "bytes" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            let output = archive.extract_bytes_for_bench(0, &cancellation, &mut budget)?;
            metrics.output_bytes = u64::try_from(black_box(output.len()))?;
            metrics.owned_output_allocations = 1;
        }
        "writer" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            metrics.output_bytes =
                archive.extract_to_for_bench(0, &mut io::sink(), &cancellation, &mut budget)?;
        }
        "callback" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            let mut writer = CountingWriter::default();
            metrics.output_bytes =
                archive.extract_to_for_bench(0, &mut writer, &cancellation, &mut budget)?;
            if metrics.output_bytes != writer.bytes {
                return Err("callback byte count disagrees with extraction".into());
            }
            metrics.writes = writer.writes;
        }
        "batch" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            let sink = archive.extract_batch_for_bench(&cancellation, &mut budget)?;
            metrics.entries = sink.entries;
            metrics.output_bytes = sink.bytes;
            metrics.writes = sink.writes;
        }
        "verify" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            archive.verify_for_bench(&cancellation, &mut budget)?;
        }
        "cancelled" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            cancellation.cancel();
            match archive.verify_for_bench(&cancellation, &mut budget) {
                Err(Error::Cancelled) => {}
                Err(error) => return Err(error.into()),
                Ok(()) => return Err("pre-cancelled archive verification succeeded".into()),
            }
        }
        "cancel-latency" => {
            let archive = opened.ok_or("opened archive is unavailable")?;
            metrics.cancellation_latency_ns = cancellation_latency(&cancellation, || {
                archive.verify_for_bench(&cancellation, &mut budget)
            })?;
        }
        _ => return Err(format!("unknown archive operation {operation:?}").into()),
    }
    metrics.work_units = budget.consumed();
    Ok(metrics)
}

fn stream_iteration(
    path: &Path,
    bytes: &[u8],
    operation: &str,
    opened: Option<&CompressedStream>,
) -> Result<IterationMetrics, Box<dyn StdError>> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let mut metrics = IterationMetrics::default();
    match operation {
        "inventory" => {
            let stream = CompressedStream::open_bytes(
                bytes.to_vec(),
                Limits::default(),
                &cancellation,
                &mut budget,
            )?;
            black_box(stream.info());
        }
        "path-inventory" => {
            let stream =
                CompressedStream::open_path(path, Limits::default(), &cancellation, &mut budget)?;
            black_box(stream.info());
        }
        "bytes" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            let output = stream.decompress(&cancellation, &mut budget)?;
            metrics.output_bytes = u64::try_from(black_box(output.len()))?;
            metrics.owned_output_allocations = 1;
        }
        "writer" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            metrics.output_bytes = stream
                .extract_to(&mut io::sink(), &cancellation, &mut budget)?
                .output_bytes();
        }
        "callback" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            let mut writer = CountingWriter::default();
            metrics.output_bytes = stream
                .extract_to(&mut writer, &cancellation, &mut budget)?
                .output_bytes();
            if metrics.output_bytes != writer.bytes {
                return Err("callback byte count disagrees with stream extraction".into());
            }
            metrics.writes = writer.writes;
        }
        "verify" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            metrics.output_bytes = stream.verify(&cancellation, &mut budget)?.output_bytes();
        }
        "cancelled" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            cancellation.cancel();
            match stream.verify(&cancellation, &mut budget) {
                Err(Error::Cancelled) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("pre-cancelled stream verification succeeded".into()),
            }
        }
        "cancel-latency" => {
            let stream = opened.ok_or("opened stream is unavailable")?;
            metrics.cancellation_latency_ns =
                cancellation_latency(&cancellation, || stream.verify(&cancellation, &mut budget))?;
        }
        "batch" => return Err("batch is not a standalone-stream operation".into()),
        _ => return Err(format!("unknown stream operation {operation:?}").into()),
    }
    metrics.work_units = budget.consumed();
    Ok(metrics)
}

fn measure<F>(
    iterations: u64,
    mut iteration: F,
) -> Result<(Duration, IterationMetrics), Box<dyn StdError>>
where
    F: FnMut() -> Result<IterationMetrics, Box<dyn StdError>>,
{
    let warmup = iteration()?;
    let start = Instant::now();
    let mut totals = IterationMetrics::default();
    for _ in 0..iterations {
        let observed = iteration()?;
        if !observed.stable_eq(warmup) {
            return Err(format!(
                "benchmark metrics changed between iterations: {warmup:?} != {observed:?}"
            )
            .into());
        }
        totals = totals.checked_add(observed)?;
    }
    Ok((start.elapsed(), totals))
}

fn run_archive<A: LifecycleArchive>(
    path: &Path,
    bytes: &[u8],
    password: Option<&str>,
    operation: &str,
    iterations: u64,
) -> Result<(Duration, IterationMetrics), Box<dyn StdError>> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let opened = if matches!(operation, "inventory" | "path-inventory" | "path-verify") {
        None
    } else {
        Some(A::open_bytes_for_bench(
            bytes.to_vec(),
            password,
            &cancellation,
            &mut budget,
        )?)
    };
    measure(iterations, || {
        archive_iteration(path, bytes, password, operation, opened.as_ref())
    })
}

fn run_stream(
    path: &Path,
    bytes: &[u8],
    operation: &str,
    iterations: u64,
) -> Result<(Duration, IterationMetrics), Box<dyn StdError>> {
    let cancellation = CancellationToken::new();
    let mut budget = WorkBudget::unlimited();
    let opened = if matches!(operation, "inventory" | "path-inventory") {
        None
    } else {
        Some(CompressedStream::open_bytes(
            bytes.to_vec(),
            Limits::default(),
            &cancellation,
            &mut budget,
        )?)
    };
    measure(iterations, || {
        stream_iteration(path, bytes, operation, opened.as_ref())
    })
}

fn main() -> Result<(), Box<dyn StdError>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let kind = arguments
        .first()
        .ok_or("usage: archive_lifecycle KIND PATH OPERATION [ITERATIONS] [PASSWORD]")?;
    let path = Path::new(
        arguments
            .get(1)
            .ok_or("archive_lifecycle requires a fixture path")?,
    );
    let operation = arguments
        .get(2)
        .ok_or("archive_lifecycle requires an operation")?;
    let iterations = arguments
        .get(3)
        .map_or(Ok(DEFAULT_ITERATIONS), |value| value.parse::<u64>())?;
    if iterations == 0 {
        return Err("iterations must be nonzero".into());
    }
    let password = arguments.get(4).map(String::as_str);
    let bytes = fs::read(path)?;
    let input_bytes = u64::try_from(bytes.len())?;
    let (elapsed, metrics) = match kind.as_str() {
        "7z" => run_archive::<Archive>(path, &bytes, password, operation, iterations)?,
        "zip" => run_archive::<ZipArchive>(path, &bytes, password, operation, iterations)?,
        "rpm" => run_archive::<RpmArchive>(path, &bytes, password, operation, iterations)?,
        "cpio" => run_archive::<CpioArchive>(path, &bytes, password, operation, iterations)?,
        "deb" => run_archive::<DebArchive>(path, &bytes, password, operation, iterations)?,
        "arj" => run_archive::<ArjArchive>(path, &bytes, password, operation, iterations)?,
        "stream" => run_stream(path, &bytes, operation, iterations)?,
        _ => return Err(format!("unknown benchmark kind {kind:?}").into()),
    };
    let elapsed_ns = elapsed.as_nanos();
    let average_ns = elapsed_ns.checked_div(u128::from(iterations)).unwrap_or(0);
    let cancellation_latency_ns = metrics
        .cancellation_latency_ns
        .checked_div(iterations)
        .unwrap_or(0);
    println!(
        "{{\"kind\":{kind:?},\"fixture\":{:?},\"operation\":{operation:?},\"iterations\":{iterations},\"input_bytes\":{input_bytes},\"elapsed_ns\":{elapsed_ns},\"average_ns\":{average_ns},\"entries\":{},\"output_bytes\":{},\"writes\":{},\"owned_output_allocations\":{},\"work_units\":{},\"cancellation_latency_ns\":{cancellation_latency_ns}}}",
        path.display().to_string(),
        metrics.entries,
        metrics.output_bytes,
        metrics.writes,
        metrics.owned_output_allocations,
        metrics.work_units,
    );
    Ok(())
}
