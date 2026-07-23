# Test and platform matrix

The required local phase gates are:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check
```

The Python-only product gate also inspects `cargo metadata` and fails if a
workspace target has kind `bin` or `example`. Installed-wheel tests require an
empty entry-point set and no `Requires-Dist`, so a console script or Python
runtime dependency cannot be added unnoticed.

The Python workflow builds six optimized `cp39-abi3` wheels: manylinux 2.17
x86-64/aarch64, macOS x86-64/arm64, and Windows x86-64/ARM64. Each exact wheel
is installed on its native architecture and runs the complete binding suite on
CPython 3.12, 3.13, and 3.14. This is an 18-job runtime compatibility matrix,
not six rebuilds per Python version; ABI3 produces one wheel per platform.
The source distribution is separately rebuilt into a wheel before it is
eligible for release.

The manually dispatched `release-pypi` workflow calls both ordinary CI
workflows, assembles exactly those six tested wheels plus the sdist, validates
their tags, and records their SHA-256 hashes. Only after all jobs pass does its
`pypi` environment job become eligible for required-reviewer approval. See
`RELEASING.md`; publication is not an automatic CI gate and no PyPI credential
is stored in the repository.

The internal core contract also checks its default feature set and warning-free
documentation:

```text
cargo check -p unpackio --no-default-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo test --workspace --doc --all-features --locked
```

GitHub Actions runs all targets/features on Linux, macOS, and Windows and runs
Rust 1.85 separately as the MSRV. Tests use only caller-selected temporary
paths and make no automatic archive-name-based extraction decisions.

The ordinary core suite includes generated ZIP, RPM, CPIO, Debian, and ARJ
coverage. ZIP tests
exercise ordinary/ZIP64/SFX structure; Store, Deflate, Deflate64, BZip2,
ZIP-LZMA, and both Zstandard IDs; ZipCrypto; WinZip AES AE-1/AE-2 at every key
size; duplicate/empty/CP437 names; password, authentication, CRC, descriptor,
truncation, overlap, SFX, dictionary, output, work, and cancellation failures.
RPM tests exercise typed headers, shared-value allocation amplification,
uncompressed/gzip/BZip2/XZ/LZMA/Zstandard payloads, newc/CRC-newc metadata,
supported package digests, duplicates/empty members, truncation, corruption,
dictionary/output/work/cancellation limits, and batch boundaries.

Standalone CPIO tests cover newc, CRC-newc, odc, historical binary little-/
big-endian and mixed layouts, exact output and metadata, unsafe names, every
truncation, alignment/trailer/checksum failures, and count/name/input/output/
work/cancellation limits. Debian tests cover the required ar member order,
V7/ustar, GNU long names/links, bounded PAX records, every admitted control/data
compressor, exact outer/inner output, tar/ar corruption and truncation, and all
applicable resource controls. ARJ tests cover stored/SFX/no-data forms, real
method 1--4 archives, exact output SHA-256, main/local/extended and member CRCs,
encrypted/unknown/split boundaries, packed corruption/truncation, and SFX/
dictionary/output/work/cancellation limits.

The Python suite creates ZIPs with the standard library and complete RPM,
CPIO, Debian, and stored-ARJ inputs in memory. It checks format-specific
metadata, duplicate and empty entries, unsafe paths, one-entry and batch
callback boundaries, corruption, cancellation, limits, password-required
classification, and exception preservation through an installed ABI3 wheel.
Python test authors never write an archive member name to the filesystem.

A separate Windows oracle job downloads the official stock 7-Zip 26.02
x64 installer, verifies its release SHA-256 before execution, installs it only
under the ephemeral runner directory, and runs the ignored corpus-free core,
property-matrix, Phase 5, and `-sni`/`-sns` classification suites. The
2026-07-20 capability follow-up at `24cf688` passed its ordinary-authoring
control, Rust verification, ADS readback, and stage
assertions. Raw AES, `-sni`, and `-sns` each stopped before archive creation
with `System ERROR: Not implemented`; no semantic support is inferred. The
generated suites accept the same test-only executable override and require the
exact standalone or Windows 26.02 banner before authoring any fixture.
The expanded job at `d1eabdf` passed all four generated core/property tests and
both Phase 5 tests, and confirmed that the explicit Copy-to-AES author request
is also rejected before archive creation.

A separate Linux capability job downloads the official 26.02 x64 tarball,
requires SHA-256
`41aaba7b1235304ab5aa0624530c67ae829496cd29e875925271efdccc28c03e`,
extracts only `7zz`, and publishes the structured capability report. The
hard-link probe checks that Rust returns the expected bytes for both entries
and records whether stock extraction preserves same-inode identity. The first
reviewed run at `d1eabdf` passed both byte checks, while stock extraction
reported `same-file=false`; it therefore establishes readable entries but not
hard-link semantics. The symlink probe restored its relative target, and both
raw-AES authoring forms returned `E_NOTIMPL` without creating an archive.

## 32-bit

The Linux i686 job installs the target and multilib linker, then compiles the
whole workspace and runs the core library/integration tests:

```text
rustup target add i686-unknown-linux-gnu
cargo check --workspace --all-targets --all-features --locked \
  --target i686-unknown-linux-gnu
cargo test -p unpackio --lib --tests --all-features --locked \
  --target i686-unknown-linux-gnu
```

The Phase 2 suite includes a `target_pointer_width = "32"` regression that
raises count limits deliberately and confirms a file count that cannot fit
`usize` returns `Format` before allocation. The normal conversion, offset,
volume, metadata, and Phase 6 stable-API tests run in the same linked job.

## Miri

Miri applies to the safe in-tree parser/model/graph/decoder logic. The CI job
uses nightly and runs the library tests without the unstable inspection API:

```text
rustup toolchain install nightly --component miri
cargo +nightly miri setup
cargo +nightly miri test -p unpackio --lib --no-default-features
```

The core has `#![forbid(unsafe_code)]`; Miri remains useful for dependency-free
aliasing, bounds, and platform-model regressions. Oracle tests, filesystem
volume discovery, benchmarks, and libFuzzer are not Miri workloads and have
their own gates.

## Differential tests

`7zz` is a test oracle only. With the audited 7z testdata available:

```text
UNPACKIO_7Z_TESTDATA=/path/to/audited/testdata \
  cargo test -p unpackio --test reference_headers --all-features -- --ignored
UNPACKIO_7Z_TESTDATA=/path/to/audited/testdata \
  cargo test -p unpackio --test phase3_reference -- --ignored
UNPACKIO_7Z_TESTDATA=/path/to/audited/testdata \
cargo test -p unpackio --test phase4_reference -- --ignored
cargo test -p unpackio --test phase5_reference -- --ignored
cargo test -p unpackio --lib stock_7zz_ -- --ignored
```

No external corpus is required for the stock-method generated matrix. With
exact stock `7zz` 26.02 on `PATH` (or `UNPACKIO_7ZZ` set for the generated or
capability suites):

```text
cargo test -p unpackio --test generated_oracle --all-features --locked -- --ignored
cargo test -p unpackio --test phase5_reference --all-features --locked -- --ignored
cargo test -p unpackio --test phase4_reference \
  generated_symlink_metadata_and_target_match_oracle \
  --all-features --locked -- --ignored
cargo test -p unpackio --lib stock_7zz_ --all-features --locked -- --ignored
cargo test -p unpackio --test capability_probe \
  stock_7zz_2602_capability_probe_report \
  --all-features --locked -- --ignored --nocapture
```

The first command generates Copy, LZMA, LZMA2, Delta, BCJ, BCJ2, PPC, ARM,
ARM64, SPARC, Deflate, BZip2, PPMd, AES, and synthetic-prefix SFX cases in a
temporary directory. It compares bytes, SHA-256, size, CRC, method, and name,
checks transforming filter input, and rejects packed-data corruption. Its
exact-version property test additionally generates 24 archives spanning
decoder-visible dictionary/model/probability/distance/block properties,
Deflate levels, filter chains, encrypted variants, and solid layouts. Exact
coder bytes, method tokens, folder counts, metadata, bytes, SHA-256, CRCs, and
verification must agree; 7zz-normalized switches cannot silently count. Every
matrix archive also has corruption, strategic truncation, entry-output,
work-budget, cancellation, and applicable dictionary-limit checks. CRC-correct
plain-header mutations exercise shortened logical packed input and
oversized/empty coder properties; encrypted-header cases keep their negative
checks without claiming direct access to encrypted inner properties. The
second command supplies the six Phase 5 methods plus solid, encrypted, and
five-volume compositions. Generated archives are deleted and never become a
runtime dependency or committed corpus.

The ignored `stock_7zz_accepts_external_folder_stream` library test checks three
fully synthetic archives with `7zz` 26.02: one selects the only decoded
AdditionalStreamsInfo folder output, one selects output index 1 while reusing
output index 0 for an external Name, and one carries an unreferenced additional
Copy folder beside a normal main stream. Deterministic non-oracle tests then
assert exact Rust extraction and verification, additional-only handling,
packed/folder/substream checksum scopes, AES password states, shared
output/work/cancellation limits, and plain/encrypted three-part volume behavior.
No generated archive is retained.

The capability-probe command requires the exact 26.02 oracle and prints
machine-readable `UNPACKIO_7ZZ_PROBE` TSV records. It distinguishes authoring,
oracle reading, Rust reading, and platform applicability; the synthetic
platform-neutral results are an asserted version-specific baseline. Windows
CI additionally asserts a successful no-switch control and the reviewed
`-sni`/`-sns` stage classifications, checks ADS byte readback before
authoring, and publishes its bounded TSV diagnostics in the job summary. See
`CAPABILITY_PROBES.md` for fixture hashes, the reviewed Windows results, and
interpretation. The Linux job reports raw-AES main/filter authoring and link
semantics through the same bounded records. Its first reviewed result is
recorded in that document. Probe candidates are discovery evidence, not
positive compatibility fixtures. The executable override is consumed only by the
generated differential and capability integration-test harnesses; production
crates never inspect it or spawn the oracle.

No result is claimed for the literal `<CORPUS>` or `<MALFORMED_CORPUS>`
placeholders; the owner confirmed that no such external sets are available.
See `CORPUS.md` and `COMPATIBILITY.md` for the generated-evidence boundary.

Standalone stream differentials use native tools only to author temporary
test input; runtime code never invokes them. Supply one format at a time:

```text
UNPACKIO_STREAM_FORMAT=lz4 \
UNPACKIO_STREAM_FIXTURE=/tmp/expected.lz4 \
UNPACKIO_STREAM_EXPECTED=/tmp/expected.txt \
  cargo test -p unpackio --test stream_formats --locked \
    optional_external_stream_fixture_matches_exact_bytes

UNPACKIO_STREAM_FORMAT=zstandard \
UNPACKIO_STREAM_FIXTURE=/tmp/expected.zst \
UNPACKIO_STREAM_EXPECTED=/tmp/expected.txt \
  cargo test -p unpackio --test stream_formats --locked \
    optional_external_stream_fixture_matches_exact_bytes

UNPACKIO_UNIX_COMPRESS_FIXTURE=/tmp/expected.Z \
UNPACKIO_UNIX_COMPRESS_EXPECTED=/tmp/expected.txt \
  cargo test -p unpackio --test stream_formats --locked \
    optional_unix_compress_oracle_fixture_matches_exact_bytes
```

Normal tests independently generate valid standard/legacy LZ4 frames,
Zstandard frames, and Unix `.Z` code streams and require exact output,
checksum/corruption handling, truncation behavior, dictionary/window/frame/
output/work limits, and cancellation. `CORPUS.md` records the reviewed local
native-tool versions, hashes, commands, and non-retention boundary.

## Coverage

Coverage is measured for the Rust implementation core. Install
`cargo-llvm-cov` 0.8.7 or newer as a development tool, then run the ordinary
suite:

```text
cargo llvm-cov -p unpackio --all-features --locked
```

To merge the corpus-free oracle paths into the same report, start clean and
run the opt-in tests without deleting prior profiles:

```text
cargo llvm-cov clean --workspace
cargo llvm-cov --no-clean -p unpackio --all-features --locked
cargo llvm-cov --no-clean -p unpackio --test generated_oracle \
  --all-features --locked -- --ignored
cargo llvm-cov --no-clean -p unpackio --test phase5_reference \
  --all-features --locked -- --ignored
cargo llvm-cov --no-clean -p unpackio --test phase4_reference \
  --all-features --locked -- \
  generated_symlink_metadata_and_target_match_oracle --ignored
cargo llvm-cov --no-clean -p unpackio --lib --all-features --locked -- \
  stock_7zz_accepts_external_folder_stream --ignored
cargo llvm-cov --no-clean -p unpackio --test capability_probe \
  --all-features --locked -- \
  stock_7zz_2602_capability_probe_report --ignored
cargo llvm-cov report
```

Coverage percentages are diagnostic, not compatibility claims. Positive
oracle fixtures, corruption/limit regressions, and fuzz depth remain required
even when a line is executed.

On 2026-07-18, cargo-llvm-cov 0.8.7 measured 65.00% core line coverage for the
ordinary all-feature suite. Merging the corpus-free generated-method, Phase 5,
and symlink oracle tests raised core line coverage to 81.66% (78.21% regions).
The `-p unpackio` command measures only the implementation core. In particular,
positive generated PPMd raised its
decoder file from 7.99% to 70.79% lines, and the generated core/Phase 5 filter
matrices raised the two filter files to 81.29% and 80.51%. These values describe
this source revision and toolchain, not a permanent threshold.

On 2026-07-19, after staged external-folder resolution and sequential
unreferenced-additional verification were added, the ordinary all-feature suite
measured 67.15% core line coverage. Merging the generated-method, Phase 5,
symlink, stock additional-stream, and exact-version capability-probe paths
raised line coverage to 83.85% (80.45% regions) after the property matrix's
negative pass was added. In that merged report `archive.rs` reached 86.27%,
`metadata.rs` reached 88.62%, and `decode/ppmd.rs` reached 76.59% lines. The
capability candidates remain diagnostic and do not establish compatibility.
These results used cargo-llvm-cov 0.8.7 and rustc/Homebrew LLVM 22.1.8, target
only the implementation core, and remain diagnostic rather than a compatibility
threshold.

On 2026-07-21 the ordinary `unpackio` all-feature suite, including the generated
PPMd compatibility and strict Brotli completion regressions, measured 76.54%
core line coverage (73.20% regions). The new centralized
`coder_properties.rs` measured 88.41% line coverage. This used cargo-llvm-cov
0.8.7 with Homebrew LLVM 22.1.8, ignored oracle-only tests, and is diagnostic
rather than a release threshold.

The excluded fuzz package has a deterministic invariant test for its 21
in-process decoder/graph seed profiles and eight structured mutation classes:

```text
cargo test --manifest-path fuzz/Cargo.toml --locked
```

That test runs the core through the public API, but source percentages from the
nested package are not merged into the root cargo-llvm-cov figures above.
LibFuzzer counter/feature observations from the subsequent 100,000-execution
decoder campaign and 50,000-execution campaigns for the other targets are
recorded, with their sanitizer limitation, in `FUZZING.md`.

The twentieth and twenty-first profiles use a fixed stock-`7zz` 26.02 PPMd
order-6/64-KiB vector
whose exact command and hashes are recorded in `CORPUS.md`. A core unit test
checks its exact 50-byte output through canonical five-byte and zero-reserved
seven-byte property records, every strict packed prefix, and output/work
limits. The public fuzz integration regression additionally checks meaningful
packed corruption, bounded property mutations, folder CRC failure, dictionary
and output limits, zero work, and pre-cancellation. Run alone under
cargo-llvm-cov 0.8.7, that focused core unit executes 64.94% of
`decode/ppmd.rs` lines; this targeted-only diagnostic is not merged with or
compared as a percentage delta to the broader 83.85% report above.

## Fuzzing and benchmarks

Nightly cargo-fuzz commands, seed policy, triage, and current smoke evidence
are in `FUZZING.md`. The reproducible natural-order solid benchmark is:

```text
UNPACKIO_7Z_TESTDATA=/path/to/audited/testdata \
UNPACKIO_BENCH_ITERATIONS=50 \
  cargo bench -p unpackio --bench natural_order_solid
```

The benchmark verifies output before timing and reports deterministic work
units plus retained archive accounting. The 10,000-substream unit regression
is the non-timing proof that natural-order member/substream traversal is
linear; timing is not used as a correctness assertion.

## Python binding and wheels

The binding is intentionally excluded from the root workspace and has its own
lockfile and gates:

```text
cargo fmt --manifest-path bindings/python/Cargo.toml --all -- --check
PYO3_PYTHON=python cargo clippy \
  --manifest-path bindings/python/Cargo.toml \
  --all-targets --all-features --locked -- -D warnings
PYO3_PYTHON=python cargo test \
  --manifest-path bindings/python/Cargo.toml \
  --no-default-features --lib --locked
PYO3_PYTHON=python cargo check \
  --manifest-path bindings/python/Cargo.toml --all-features --locked
cargo deny --manifest-path bindings/python/Cargo.toml \
  --all-features --config bindings/python/deny.toml check
```

The no-default-features Rust tests link against the selected interpreter,
exercise the binding's unexpected-unwind containment helper, and assert a
distinct structured mapping for every stable core error. The all-features
target uses PyO3 extension-module linkage and is compile/Clippy
checked; an installed wheel is the correct executable test artifact for that
mode on platforms which deliberately leave CPython symbols for the loader.

Build and test the actual package, not an in-tree Python shim:

```text
python -m pip install 'maturin==1.13.3'
maturin build --manifest-path bindings/python/Cargo.toml \
  --release --locked --compatibility pypi --out bindings/python/dist
python -m pip install --force-reinstall bindings/python/dist/unpackio-*.whl
python -m unittest discover -s bindings/python/tests -v
maturin sdist --manifest-path bindings/python/Cargo.toml \
  --out bindings/python/dist
python -m pip wheel --no-deps bindings/python/dist/unpackio-*.tar.gz \
  --wheel-dir bindings/python/dist/from-sdist
```

The binding suite constructs a CRC-protected Copy archive independently and
tests distribution/native module names, raw UTF-16 metadata and unsafe paths,
writer/callback extraction, callback exception identity and cancellation,
provider/writer exception identity, same-archive callback reentrancy, CRC
failure, structured format/limit/work/cancellation errors, every limit override, per-archive
password accounting, path opening, Python volume
providers and exact missing-volume names, and interpreter detachment during an
8 MiB Rust-only verification. A 46,000-byte callback output also asserts that
delivery spans multiple chunks and no chunk exceeds 8 KiB; partial writer
counts are honored and an impossible count is rejected.

The batch fixture independently generates a three-entry solid Copy archive
with two streamed members, an empty member, and duplicate names. It asserts
natural begin/write/finish sequencing, exact output, bounded chunks, member CRC
failure before finish, exact exceptions from write and finish callbacks,
callback/token cancellation, output preflight, one shared work budget, and a
batch cost proving the solid folder is decoded at most once.

On 2026-07-18 the locally built `cp39-abi3` macOS wheel installed into a clean
CPython 3.12 virtual environment and all 10 binding tests passed. The sdist
also rebuilt into a wheel in an isolated PEP 517 build; that rebuilt wheel was
installed and passed the same suite. On 2026-07-20, PR #1 at `8c26a6e`
observed successful Python 3.9 wheel build/install/tests on Linux, macOS, and
Windows, plus the Rust 1.85 binding gate and sdist rebuild test. These are
packaging/FFI platform results; the independent Python fixture still adds
positive decoder evidence only for Copy.

On 2026-07-21 a locally built `cp39-abi3` macOS x86-64 wheel installed into a
clean CPython 3.12 virtual environment and all 15 binding tests passed. Its
metadata has no `Requires-Dist`, and its license payload includes
`LICENSES/BSD-3-Clause-netbsd-zopen.txt` for the Unix `.Z` adaptation. CI now
has explicit manylinux-compatible Linux x86-64 and aarch64 build jobs; the aarch64 artifact
is installed and tested on a native `ubuntu-24.04-arm` runner. Those new Linux
jobs remain configured evidence until their first hosted run completes.

The same 2026-07-21 local gate passed root and separately locked binding/fuzz
format checks, root strict all-target/all-feature Clippy, binding and fuzz
strict Clippy, 191 non-ignored root Rust tests plus two core doctests, two
binding Rust tests, 15 installed-wheel Python tests, the 21-profile fuzz
generator, a 10,000-run finite standalone-stream fuzz smoke, and cargo-deny
0.20.2 for all three dependency graphs. The host wheel is
`unpackio-0.1.0-cp39-abi3-macosx_10_12_x86_64.whl`; its metadata has no
`Requires-Dist`. Local Miri, Rust 1.85 execution, Linux wheel execution, and
instrumented nightly cargo-fuzz are unavailable on this Intel macOS
stable-only host and remain configured CI gates.

After the separate ZIP/RPM readers were added later on 2026-07-21, the full
locked root workspace suite and doctests again completed with no failures.
Strict root and binding Clippy, warning-denied rustdoc, root/binding/fuzz
format checks, the two no-default-feature binding Rust tests, the deterministic
fuzz-package tests, and all three cargo-deny graphs passed. A freshly built
`cp39-abi3` macOS x86-64 wheel installed into a clean CPython 3.12 environment
and all 17 installed-package tests passed. The generated sdist contains the
new core and adapter sources and rebuilt offline into an ABI3 wheel; the
installed wheel still declares no Python `Requires-Dist`. An explicit Rust
1.85.0 toolchain check passed for every root target/feature and for the
all-feature Python binding; it also caught and prompted removal of two newer
let-chain expressions before this result was recorded.

The later Python data-contract gate rebuilt and installed the same
`cp39-abi3` macOS x86-64 wheel into a clean CPython 3.12 environment; all 19
installed-package tests passed. The two added tests prove that the native ZIP
and RPM objects return their documented metadata, typed password/corruption
outcomes, ZipCrypto and AE-2 AES-256 extraction, symbolic/scalar RPM headers,
unknown tags, duplicate and empty members, and path-based exact extraction. A
separate core regression proves that an empty AE-2 member succeeds only with
an intact authentication tag. They use generated repository-owned
ZIP/ZipCrypto/WinZip-AES/RPM/CPIO bytes.

The ordinary core coverage pass used cargo-llvm-cov 0.8.7 and Homebrew LLVM
22.1.8. It measured 76.22% total core line coverage. The new ZIP files measured
73.39% (`zip/mod.rs`), 77.49% (`zip/parse.rs`), 84.25% (`zip/crypto.rs`), and
73.63% (`zip/decode.rs`); the new RPM files measured 72.60% (`rpm/mod.rs`),
67.03% (`rpm/header.rs`), 79.42% (`rpm/cpio.rs`), and 65.08%
(`rpm/decode.rs`). These percentages are diagnostic; the positive,
corruption, truncation, resource-limit, and exact-output assertions remain the
compatibility evidence.

The same installed wheel passed disposable compatibility-oracle checks whose
exact inputs and hashes are recorded in `PROVENANCE.md`. The generated matrix
covered 24 AES profiles across four compression methods, AE-1/AE-2, and
128-/192-/256-bit keys, each with nonempty and empty duplicate-name entries.
`unpackio` extracted exact bytes and verified every archive. A separately
generated gzip/newc package matched expected names, output bytes, and modes.
These were test-only checks in a disposable environment, not runtime
dependencies or committed corpus.

After standalone CPIO, Debian-package, and ARJ support was added on 2026-07-21,
the locked root workspace passed 221 non-ignored Rust tests plus three doctests;
21 external-oracle tests remained intentionally ignored. Root, binding, and
fuzz formatting and warning-denied Clippy passed, as did all three cargo-deny
advisory/license/source/ban graphs and both deterministic fuzz-package tests.
The `archive_formats` harness completed 1,000 finite seedless runs over all five
concrete non-7z archive readers without a failure; this host lacked cargo-fuzz,
nightly sanitizer hooks, and coverage instrumentation, so that run is only a
harness/no-panic smoke.

A fresh optimized `cp39-abi3` macOS x86-64 wheel installed without Python
runtime dependencies in a clean CPython environment and all 23 binding tests
passed. The final Python-only 964,108-byte wheel includes the ARJ
dependency/adaptation notice, has no `entry_points.txt` or `Requires-Dist`, and
installs no console script. The ordinary cargo-llvm-cov 0.7.0 pass with Homebrew LLVM measured
75.32% core line coverage after the executable target was removed. New-reader line
coverage was 70.31% for CPIO; 63.20% for Debian orchestration, 80.95% for its
ar parser, and 72.30% for its tar parser; and 66.94% for ARJ orchestration plus
86.22% for ARJ decoding. These percentages are diagnostic, not compatibility
claims. Miri, 32-bit execution, Rust 1.85, sanitizer-backed fuzzing, and hosted
Linux/macOS/Windows wheel runs remain configured CI gates rather than local
evidence on this stable Intel macOS host.
