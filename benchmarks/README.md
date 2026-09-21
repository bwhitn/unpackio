# Release lifecycle benchmarks

These opt-in tools measure the shipped read-only Rust and installed-wheel
Python APIs. They are development support only: generators may invoke external
archive tools, but no generator, writer, CLI, or subprocess fallback is linked
into `unpackio`.

## Fixture generation

Generate one fixture directory and retain it unchanged for both sides of a
comparison:

```text
python3 benchmarks/generate_fixtures.py /tmp/unpackio-perf \
  --bytes 4194304 --files 32
```

The generator requires `7zz`, `lz4`, `zstd`, and Unix `compress`. It writes a
manifest with every fixture's size and SHA-256 plus the resolved generator-tool
hashes. Payloads, names, timestamps, and unencrypted containers are
deterministic. The encrypted 7z generator deliberately uses 7-Zip's random
salt; comparisons therefore reuse the same generated directory and pin its
manifest rather than claiming a byte-identical encrypted regeneration.
Re-running the command against a manifested directory validates every fixture
and deterministic source split, then exits without changing a byte. A
nonempty directory without that manifest is rejected rather than overwritten.

The matrix contains solid and encrypted 7z, mixed standard ZIP methods, ZIP
Deflate64/Zstandard/XZ/JPEG/WavPack/PPMd, RPM, CPIO, Debian, ARJ, LZ4,
Zstandard, and Unix `.Z`. External tools are fixture generators only. The
advanced JPEG and WavPack inputs are derived from the already provenance-pinned
committed evidence.

## Native matrix

Use the primary toolchain explicitly if another Rust installation precedes
rustup on `PATH`:

```text
PATH="$(dirname "$(rustup which --toolchain 1.98.1 rustc)"):$PATH" \
  cargo build --release --locked \
  --bench archive_lifecycle
python3 benchmarks/run_release.py /tmp/unpackio-perf /tmp/native.json \
  --binary target/release/deps/archive_lifecycle-<hash> \
  --rustc "$(rustup which --toolchain 1.98.1 rustc)" \
  --phase after --samples 3
```

Each sample is a fresh process. The benchmark performs one correctness warmup,
requires deterministic entries/bytes/write/allocation/work counters, and then
times repeated operations. The outer runner records median in-process wall
time, process wall time, user/system CPU, peak RSS, block I/O, artifact size,
artifact hash, output bytes, callback writes, owned-output allocation events,
and work units. `cancel-latency` triggers cancellation from a second thread
during a long decode and measures from the trigger to the typed cancellation
return; `cancelled` separately measures the pre-cancel fast path.

`owned_output_allocations` counts API-visible owned output materializations; it
is not a claim to count every dependency allocator call. Output byte and write
counts expose the copy/callback boundary, while isolated-process peak RSS
captures native allocator and decoder state. On macOS, `ru_maxrss` is reported
in bytes. Cached inputs commonly make block-I/O counters zero; the path-open
timings are still retained.

## Installed-wheel Python matrix

Build, install, and benchmark a wheel in an isolated environment:

```text
python3 -m maturin build --release --locked \
  --manifest-path bindings/python/Cargo.toml --out /tmp/wheels
python3 -m venv /tmp/unpackio-bench-venv
/tmp/unpackio-bench-venv/bin/python -m pip install --no-deps --no-index \
  /tmp/wheels/unpackio-*.whl
python3 benchmarks/run_python_release.py /tmp/unpackio-perf /tmp/python.json \
  --python /tmp/unpackio-bench-venv/bin/python \
  --wheel /tmp/wheels/unpackio-*.whl \
  --rustc "$(rustup which --toolchain 1.98.1 rustc)" \
  --phase after --samples 3
```

This matrix exercises metadata projection, path and byte opening, writer,
callback, natural-order batch, verification, and cancellation through the
installed package. Chunk and byte counters quantify Python-boundary object and
callback pressure. Wheel and native-extension sizes and hashes are recorded in
the report.

## Interpretation

Benchmarks never relax limits, work accounting, cancellation checks, CRC/hash
verification, or integrity-before-success. A change is retained only when the
complete lifecycle matrix remains correct and the intended path improves or
removes objectively measured copies/callbacks. See `BENCHMARKS.md` for the
published comparison, host details, exact fixture-manifest hash, and decisions
that were evaluated but deliberately not adopted.
