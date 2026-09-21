# Test and platform matrix

Primary checks use the repository-pinned Rust 1.98.1 toolchain. Rust 1.85.0 is
run separately as the compatibility floor; passing on the primary compiler
does not replace the MSRV jobs. If a non-rustup `cargo` precedes rustup on
`PATH`, prepend the selected toolchain directory so Cargo also spawns the
matching compiler:

```text
PATH="$(dirname "$(rustup which --toolchain 1.98.1 rustc)"):$PATH" cargo ...
```

`rustup run 1.98.1 cargo` alone is insufficient on such a host because Cargo
resolves its child `rustc` from `PATH`.

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
ZIP-LZMA, both Zstandard IDs, XZ method 95, JPEG method 96, WavPack method 97,
and PPMd method 98; ZipCrypto;
WinZip AES AE-1/AE-2
at every key size; duplicate/empty/CP437 names; password, authentication, CRC,
descriptor, truncation, overlap, SFX, dictionary, output, work, and cancellation
failures. Method-95 cases cover all XZ 1.0.4 Checks and permitted prefilters,
multiple Blocks, Stream Padding, every strict payload prefix, CRC-correct
header/property/Index mutations, exact Index records, encryption composition,
and failure before writer or batch-sink finalization.
Method-97 cases cover 10 official-WavPack-generated profiles spanning every
supported storage width, integer/float, mono/stereo, three/four/
sixteen channels, a custom sample rate, wrapper trailers, and multiple blocks.
Every strict payload prefix, structural/bitstream/CRC corruption, malformed or
excessive metadata, size/version/profile disagreement, encryption composition,
all applicable limits, cancellation, unrelated-entry access, and atomic sink
failure are checked.
Method-98 cases cover every legal property restoration value, order/model
endpoints, end-marker/exact-input rules, a forced allocator-pressure pass for
Restart/Cutoff/Freeze, every strict packed prefix, corrupt properties/range
state/trailing data, declared size/CRC/version disagreement, encryption
composition, unrelated-entry selection, and failure before writer or batch
sink delivery.
The committed WinZip 21 method-94/96 reference test independently pins each
project-authored source, archive, and local-header payload SHA-256; source CRC;
and member name, method, sizes, flags, encryption, and version-needed metadata.
It requires byte-exact method-96 extraction/verification and typed unsupported
method-94 failure without output. Dedicated method-96 tests cover compressed
and stored metadata, extended properties, malformed Huffman/quantization/frame/
scan state, unsupported profiles, sampled strict truncation, corruption,
trailing input, exact LZMA declared-byte accounting, resource/work/cancellation
failure, encryption composition, and atomic delivery. No normal test invokes
an external tool. The separate checksum-pinned packMP3 and XFileUnpacker oracle
runs that established the expected outputs are recorded in `CORPUS.md` and
`PROVENANCE.md`.
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

The Python suite creates ZIPs with the standard library and project-authored
in-memory serializers, plus complete RPM, CPIO, Debian, and stored-ARJ inputs.
It checks format-specific
metadata, duplicate and empty entries, unsafe paths, one-entry and batch
callback boundaries, corruption, cancellation, limits, password-required
classification, XZ method-95, JPEG method-96, WavPack method-97, and PPMd
method-98 metadata/extraction/errors, registered method-94 typed unsupported
errors, and exception
preservation through an installed ABI3 wheel.
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
uses nightly and runs a bounded, explicitly named smoke set without the
unstable inspection API. This keeps the gate within its 30-minute budget while
covering integer parsing, cancellation, CRC state, filter state, graph
execution, header parsing, path policy, stream pumping, volume limits, and a
ZIP lifecycle:

```text
rustup toolchain install nightly --component miri
cargo +nightly miri setup
for test_name in <the bounded list in .github/workflows/ci.yml>; do
  cargo +nightly miri test --locked -p unpackio --lib \
    --no-default-features "$test_name" -- --exact
done
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
ARM64, SPARC, Deflate, BZip2, PPMd, AES, synthetic-prefix SFX, ZIP XZ
method-95, and ZIP PPMd method-98 cases in a temporary directory. It compares
bytes, SHA-256, size, CRC, method, name, and the ZIP version-needed field,
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

The separately pinned local-only WinZip/SharpCompress sample set is optional:

```text
UNPACKIO_WINZIP_TESTDATA=/path/to/pinned/SharpCompress/tests/TestArchives/Archives \
  cargo test -p unpackio --test winzip_reference --locked \
  external_pinned_zipx_archives_match_expected_outputs \
  -- --ignored --exact --nocapture
```

`CORPUS.md` records the exact acquisition revision, archive and output hashes,
method/version/encryption inventory, and redistribution decision. The test
refuses a changed archive before parsing and then extracts and verifies every
regular member. Four filenames/upstream tests attest WinZip 26/27 BZip2,
ZIP-LZMA, XZ, and Zstandard output. The supplemental PPMd sample has no recorded
producer, tool version, or command and is explicitly not counted as WinZip
method-98 evidence.

The normal, non-ignored `zip_recompression_reference` integration test covers
the separately committed WinZip 21 method-94/96 fixtures. Their controlled
source inputs, exact product/installer identities, complete GUI recipe, archive
and payload hashes, redistribution basis, and independent output-oracle results
are recorded in `CORPUS.md`. The test confirms that the current public surface
lists both real files accurately, reconstructs and verifies the method-96 JPEG
byte for byte, and returns `UnsupportedMethod` for method 94 before emitting
bytes.

The separate method-94 clean-room research corpus is verified without an
external executable by:

```text
ruby crates/unpackio/tests/fixtures/method94/verify.rb
ruby crates/unpackio/tests/fixtures/method94/analyze.rb
```

It checks exact manifest/file-set agreement and all 54 MP3/PMP base64 sizes,
SHA-256 values, signatures, oracle-acceptance records, and byte-exact
round-trip assertions. The generator was also run twice into fresh temporary
directories with the checksum-pinned LAME and packMP3 tools; recursive diffs of
the original 53 manifest records and all 106 original pair files were empty;
the added intensity-stereo pair was independently regenerated exactly. This
corpus is research evidence and intentionally does not make the normal
method-94 extraction test expect success. The analyzer independently parses
MPEG framing and verifies the
PMP signature, descriptor, byte-4 feature bitmap, global flags, reservoir
marker, and frame count for all 54 pairs. It explicitly leaves only the byte-11
entropy stream unresolved.

The same test binary contains three ignored harnesses for the fresh local-only
Windows WinZip evidence. They require the archive/original paths and recorded
recipe/product variables rather than accepting an unlabelled sample:

- `external_winzip_ppmd_oracle_matches_project_input` checks the pinned WinZip
  21.0.12288 PPMd archive using `UNPACKIO_WINZIP_PPMD_ARCHIVE`,
  `UNPACKIO_WINZIP_PPMD_ORIGINAL`, `UNPACKIO_WINZIP_PPMD_PRODUCT_VERSION`, and
  `UNPACKIO_WINZIP_PPMD_AUTHORING_RECIPE`.
- `external_winzip_wavpack_oracle_matches_original_wave` checks the pinned
  WinZip 21.0.12288 WavPack archive using the existing
  `UNPACKIO_WINZIP_WAVPACK_*`, `UNPACKIO_WINZIP_PRODUCT_VERSION`, and
  `UNPACKIO_WINZIP_AUTHORING_RECIPE` variables.
- `external_reproducible_winzip24_archives_match_project_input` checks all four
  WinZip 24.0.14033 replacements using
  `UNPACKIO_WINZIP_REPLACEMENT_TESTDATA`,
  `UNPACKIO_WINZIP_REPLACEMENT_ORIGINAL`,
  `UNPACKIO_WINZIP_REPLACEMENT_PRODUCT_VERSION`, and
  `UNPACKIO_WINZIP_REPLACEMENT_AUTHORING_RECIPE`.

Each harness pins the relevant archive/output hashes and metadata, performs
byte-exact production extraction, and completes full archive verification.
`CORPUS.md` records the successful 2026-09-16 invocations and exact values.

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

No result is claimed for the historical literal `<CORPUS>` or
`<MALFORMED_CORPUS>` placeholders; the owner confirmed that no general 7z sets
are available. The opt-in checksum-pinned ZIPX set above is narrower and stays
outside the repository. See `CORPUS.md` and `COMPATIBILITY.md` for each
generated/external evidence boundary.

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

The `archive_formats` target additionally creates valid ZIP method-95/XZ,
method-97/WavPack, and method-98/PPMd members on every input and drives
input-selected corruption and strict truncation through the same public
open/verify/extract path. Every iteration requires all fixed streams to extract
to their exact expected output before the hostile variants run.

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

The broader generated lifecycle matrix is documented in
`benchmarks/README.md`. It measures every concrete archive/stream family,
advanced ZIP decoders, encrypted 7z, byte/writer/callback/batch paths, and an
installed-wheel Python matrix in isolated release processes. Reports include
wall/CPU/RSS/I/O, output/callback/copy proxies, cancellation response, and
wheel/native size. The final before/after evidence is in `BENCHMARKS.md`.

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
python -m pip install 'maturin==1.15.0'
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

On 2026-09-14, the ZIP XZ method-95 review unit passed root/fuzz/binding format
checks, strict all-target/all-feature Clippy, 227 non-ignored root Rust tests
plus three doctests, two binding Rust tests, both deterministic fuzz-package
tests, and cargo-deny 0.20.2 for all three locked dependency graphs. The focused
ignored differential passed against stock `7zz` 26.02, and the stable-built
archive-format fuzzer completed 10,000 finite runs with the limitations in
`FUZZING.md`. An optimized `cp39-abi3` macOS x86-64 wheel built with pinned
maturin 1.13.3, installed into a clean CPython 3.12.10 environment, and passed
all 24 installed-package tests. Its SHA-256 is
`598440040aa065f23dd41a7245d441281454c0f9432cd046e0587ea1ca80dda3`, its
size is 943,934 bytes, and its installed metadata has neither `Requires-Dist`
nor entry points. The release benchmark target compiled, but the historical
7z benchmark run correctly skipped because `UNPACKIO_7Z_TESTDATA` was not set;
no ZIP throughput or peak-memory claim is made. Miri, Rust 1.85 execution, and
nightly ASan fuzzing are unavailable on this stable-only host and remain CI
gates.

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

### 2026-09-14 ZIP methods 95 and 98 completion gate

The final locked root workspace runs passed 238 non-ignored Rust tests and
three doctests in both development and optimized profiles; 25 environment- or
corpus-dependent tests remained intentionally ignored in each ordinary run.
Root formatting, warning-denied all-target/
all-feature Clippy, and warning-denied rustdoc passed. The separately locked
Python adapter passed formatting, warning-denied all-target/all-feature Clippy,
warning-denied rustdoc, its all-feature compile check, and both no-default-
feature Rust tests. The separately locked fuzz package passed formatting,
warning-denied all-target/all-feature Clippy, and both deterministic generator
tests. Cargo-deny 0.20.2 reported advisories, bans, licenses, and sources clean
for all three graphs.

The focused stock-`7zz` 26.02 method-95 and method-98 differentials both
passed. The checksum-pinned, local-only SharpCompress corpus test passed all
five archives: four WinZip-labelled BZip2, ZIP-LZMA, XZ, and Zstandard samples,
plus the explicitly unattributed PPMd sample. The release-only PPMd matrix
forced Restart, Cutoff, and Freeze restoration under allocator pressure and
passed exact decoding. The natural-order release benchmark target compiled
warning-free and then explicitly skipped because `UNPACKIO_7Z_TESTDATA` was not
set; no ZIP throughput or peak-memory result is inferred from that check.

An ordinary cargo-llvm-cov 0.7.0 run using Homebrew LLVM 22.1.8 measured
77.11% total core line coverage, 73.91% region coverage, and 44.74% function
coverage. New-file line coverage was 76.80% for `decode/ppmd_i.rs`, 83.48% for
`decode/xz.rs`, 80.72% for `zip/decode.rs`, and 83.64% for `zip/mod.rs`. These
numbers are diagnostic; the corruption, prefix, exact-output, restoration,
resource-limit, cancellation, encryption-wrapper, and integrity-before-sink
assertions are the compatibility evidence.

Pinned maturin 1.13.3 built
`unpackio-0.1.1-cp39-abi3-macosx_10_12_x86_64.whl` with an ABI3 Python 3.14
build interpreter. The 984,218-byte wheel has SHA-256
`f6fd5901f5b7f86af91926495e48fb9279bd1ae2707b41cbe6387cd64e9a8b20` and
passed all 26 tests after installation into a clean CPython 3.12.10 virtual
environment. Its metadata has no Python runtime dependency or entry point, and
its license
payload includes `MIT-SharpCompress.txt`. The 377,921-byte source distribution
has SHA-256
`b04feb6ec3fd2368fb2c551e24450c4902f65b1fd5fddb15bf9fdccfc4e467e7`;
an isolated PEP 517 rebuild produced a distinct 984,299-byte wheel with SHA-256
`0c2838343e3419f78ac47268c704381d724a21041afe8170dc1f22e22d8aa82f`,
and that wheel also passed all 26 installed-package tests in a second clean
environment. The source archive was inspected for both new decoder modules,
both notices, both SharpCompress license copies, and the binding lockfile.

The final stable-built `archive_formats` harness completed 10,000 seedless
executions in 99 seconds with no failure and 41 MiB reported RSS, while
requiring valid method-95 and method-98 extraction before hostile variants.
This host has neither cargo-fuzz nor rustup/nightly, and the runner reported no
sanitizer or coverage instrumentation; the run is therefore finite no-panic
evidence only. Miri is not installed. Rust 1.85, Miri, sanitizer-backed fuzzing,
32-bit execution, and hosted multi-platform wheel execution remain configured
CI gates rather than local evidence; the local gates used Homebrew rustc 1.97.0
and LLVM 22.1.8.

### 2026-09-14 version 0.2.0 dependency and packaging gate

Fresh `cargo update --dry-run --verbose` checks for the root, Python binding,
and fuzz manifests each selected zero additional Rust-1.85-compatible updates.
The only newer direct releases are deliberately held: `aes` 0.9.3 requires
Rust 1.89, `delharc` 0.7/0.8 require Rust 1.93/1.95, and `ruzstd` 0.8.2 uses
integer APIs absent from Rust 1.85 while 0.9 requires Rust 1.87. Exact selected
versions, features, checksums, source revisions, and licenses are recorded in
`DEPENDENCIES.md` and `PROVENANCE.md`. Cargo-deny 0.20.2 reported advisories,
bans, licenses, and sources clean for all three refreshed lockfiles.

The final development-profile root run passed 238 non-ignored Rust tests plus
three doctests; 25 external-corpus/environment tests remained intentionally
ignored. Root formatting, warning-denied all-target/all-feature Clippy, and
warning-denied rustdoc passed. The separate binding passed formatting,
warning-denied Clippy/rustdoc, its all-feature compile check, and both Rust
tests; the fuzz package passed formatting, warning-denied Clippy, and both
deterministic generator tests. The complete root suite and all-feature binding
check also passed in the official Rust 1.85.0 Docker image
(`sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52`).
The stock-`7zz` 26.02 XZ/PPMd differentials and generated method matrix, plus
the optimized PPMd restoration-pressure checks, remained clean. The release
benchmark target compiled. Miri is not installed locally; nightly Miri,
sanitizer fuzzing, 32-bit execution, and hosted platform wheels remain CI
gates.

Pinned maturin 1.15.0 built a clean direct
`unpackio-0.2.0-cp39-abi3-macosx_10_12_x86_64.whl` (997,723 bytes, SHA-256
`df6344c18d1087125c789fe1461e2bec82650a3efbf4140c438977eaf4912dd1`).
The corrected 378,041-byte sdist has SHA-256
`b908265de22cd710eaad4e76661193682eedf573e7be310860e449440bb71dd9`;
all 119 entries were inspected and none is a nested wheel or distribution
output; a second build with a populated local `dist-0.2.0` directory proved
the explicit exclusion rather than relying on a clean tree. An isolated PEP
517 rebuild produced a 997,877-byte wheel with SHA-256
`c2613a35a5b178ae751dbaab7dbfe25ff2f718a20aee214e51fcad0298d32612`.
The direct and rebuilt wheels each installed into a separate clean CPython
3.12.10 environment and passed all 26 binding tests. Both report version
0.2.0, no `Requires-Dist`, no entry point, and the complete license/notice
payload. Checksum-pinned actionlint 1.7.12 and Ruby's YAML parser accepted all
three updated workflows.

Finally, the refreshed stable `archive_formats` harness completed 10,000
seedless executions in 92 seconds with seed `2925986431`, no failure, and 49
MiB reported RSS. Its missing-sanitizer/missing-coverage warnings make this a
finite no-panic check only; the configured nightly ASan run remains required.

### 2026-09-15 ZIP WavPack method 97 completion gate

At that completion gate, the final locked root workspace passed formatting,
warning-denied
all-target/all-feature Clippy, warning-denied rustdoc, 244 non-ignored Rust
tests, and three doctests. Twenty-six environment- or corpus-dependent tests
remained intentionally ignored, including the then-deferred Windows WinZip
method-97 product oracle. That oracle was completed on 2026-09-16 as recorded
below. The separately locked Python binding passed
formatting, warning-denied Clippy/rustdoc, its all-feature compile check, and
both no-default-feature Rust tests. The fuzz package passed formatting,
warning-denied Clippy, and both deterministic generator tests. The local
decoder fork independently passed formatting, warning-denied Clippy, three
tests, and its doctests. Cargo-deny 0.20.2 reported advisories, bans, licenses,
and sources clean for the root, binding, fuzz, and local-decoder graphs.

The complete root suite and all-feature binding check also passed in the
official Rust 1.85.0 Docker image
(`sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52`).
The decoder fork passed warning-denied all-target/all-feature Clippy under the
same MSRV. The release-only PPMd restoration-pressure test remained clean. The
natural-order release benchmark target compiled and explicitly skipped because
`UNPACKIO_7Z_TESTDATA` was not set; no ZIP throughput or peak-memory result is
inferred. Miri is not installed locally, and nightly Miri, sanitizer-backed
fuzzing, 32-bit execution, and hosted multi-platform wheels remain CI gates.

All 10 deterministic method-97 payloads regenerated byte-for-byte with exact
official WavPack 4.80, and exact official WavPack 5.9 decoded each expected WAV
byte-for-byte. The Rust suite covers the admitted integer/float, one-to-16-
channel, custom-rate, wrapper/trailer, and multiblock profiles; every strict
prefix; structural, bitstream, and checksum corruption; unsupported profiles;
resource/work/cancellation failures; ZipCrypto and WinZip AES; atomic writer
and batch boundaries; and checked 8-bit PCM conversion. The final stable-built
`archive_formats` harness completed 10,000 executions from an empty corpus in
106 seconds with seed `970203`, no failure, and 39 MiB reported RSS. Its
missing-sanitizer/missing-coverage warnings make that a finite no-panic check,
not a substitute for nightly ASan fuzzing.

Pinned maturin 1.15.0 produced the definitive direct
`unpackio-0.2.0-cp39-abi3-macosx_10_12_x86_64.whl`: 1,024,211 bytes, SHA-256
`59ca11ac016bb8d0251ebdda7f6a4600b0d229db14f9a0971414ee31d90525c4`.
The 428,382-byte source distribution has SHA-256
`565d6735ea86fad12383ff8d4587ccce944679f00eae4156bc41de2e07eec0b6`;
its 162 entries include the decoder fork, patch record, adapter, and both new
license sets, with no nested target, wheel, bytecode, or distribution output.
An independent PEP 517 rebuild produced a 1,024,276-byte wheel with SHA-256
`062cfda2c0b47f5d34b8fe34853f3012bb4924859bf7b6168845dabd8e54b42c`.
The direct and rebuilt wheels each contain 20 identically named entries,
installed into separate clean CPython 3.12.10 environments, and passed all 27
binding tests. Both report version 0.2.0, no `Requires-Dist`, no entry point,
and the complete MIT/WavPack BSD license and notice payload.

At this gate, the Windows WinZip authoring/verification step was intentionally
deferred at the user's request. Its ignored harness required a recorded product
version, authoring recipe, original input, and archive/output SHA-256 values
before any product-parity claim could be added. That evidence was supplied and
the harness passed on 2026-09-16 as recorded above.

### 2026-09-15 ZIP methods 94 and 96 fixture gate

The provenance-complete WinZip 21 fixture addition passed
`cargo fmt --all -- --check`, warning-denied all-workspace/all-target/all-feature
Clippy, all-workspace/all-feature tests, and `cargo deny check`. The root suite
reported 245 non-ignored Rust tests and three doctests passing; the same 26
external-corpus/environment tests remained intentionally ignored. The new
`zip_recompression_reference` test also passed independently.

This phase adds fixed test data, a metadata/typed-error regression, and
documentation only. It does not add or alter a production decoder, dependency,
parser, unsafe boundary, resource policy, or fuzz-reachable runtime path, so no
new Miri, property, fuzz, differential-extraction, or benchmark campaign was
applicable. The earlier method-97 campaigns and gates remain recorded above.

### 2026-09-16 ZIP JPEG method 96 completion gate

The final method-96 implementation passed root formatting, warning-denied
all-workspace/all-target/all-feature Clippy, all-workspace/all-feature tests,
warning-denied rustdoc, and `cargo deny check`. The root suite reported 255
non-ignored Rust tests and three doctests passing; 26 external-corpus or
environment-dependent tests remained intentionally ignored. The separately
locked Python binding, fuzz package, and local WavPack decoder graph passed
their applicable formatting, warning-denied compile/lint/documentation, test,
and cargo-deny gates. The release-only PPMd allocator-pressure test passed, and
the natural-order release benchmark compiled and explicitly skipped because
`UNPACKIO_7Z_TESTDATA` was unset.

Method-96 tests cover the provenance-complete three-component, 8-bit,
one-by-one-sampled WinZip fixture; stored and LZMA-compressed metadata bundles;
short and extended bundle headers; sequential SOF0/SOF1 parsing at 8 and 12
bits; repeated frame-component and scan-component identifiers; progressive and
spectral-profile rejection; DQT, DHT, DRI, SOF, and SOS validation; absent,
zero, oversubscribed, and repeatedly defined tables; inner-LZMA and outer-payload
exact consumption; every fixture prefix; payload corruption; aggregate
dictionary, metadata, frame, output, work, and cancellation limits; ZipCrypto
and WinZip AES wrappers; and CRC-before-writer/batch delivery. Positive
interoperability is deliberately claimed only for the committed fixture's
layout; parser acceptance of other legal component and sampling layouts is not
presented as fixture-backed compatibility evidence.

The exact CI compile gate and complete root suite also passed in the official
Rust 1.85.0 Linux image. The all-target/all-feature compile gate and complete
library/integration suite passed for `i686-unknown-linux-gnu`, exercising the
same method-96 paths on a 32-bit target. Current-toolchain Clippy is clean;
optional Rust 1.85 Clippy still reports five pre-existing style lints outside
the method-96 files, while the CI's Rust 1.85 compile/test contract passes.
Miri and nightly sanitizer instrumentation are not installed locally, so their
configured CI jobs remain authoritative. A stable selector-throttled fuzz run
completed 10,000 seedless executions in 9 seconds with seed `960216`, no
failure, and 43 MiB reported RSS; its missing-instrumentation warning means it
is finite invariant/no-panic evidence, not sanitizer or coverage evidence.

Pinned maturin 1.15.0 produced the final direct
`unpackio-0.2.0-cp39-abi3-macosx_10_12_x86_64.whl`: 1,060,797 bytes, SHA-256
`5c2666997f067eea50f761c932e9b273425509588c21db49976fce5e7748d283`.
The 474,488-byte sdist has SHA-256
`7743b1c48ff0f8d2c34167367f3a76da1dac87eb9de8ef10c22aa1cf1163d13d`;
its 171 entries contain no nested target, wheel, distribution, bytecode, or
`__pycache__` output. An isolated PEP 517 rebuild produced a 1,060,884-byte
wheel with SHA-256
`1b637162655378028e77cf8074d19e50a26f8795f31152b447c31ea885eb2366`.
The direct and rebuilt wheels each contain the same 21 entry names, no Python
bytecode, no runtime dependency, and no console entry point. Each installed in
a separate clean CPython 3.12.10 environment and passed all 28 binding tests;
both report version 0.2.0 and include the complete root-equivalent license and
notice payload.

### 2026-09-16 ZIP MP3 method-94 research-corpus gate

The clean-room generator produced 53 accepted and unique MP3/PMP pairs. Every
case passed packMP3 v1.0g's internal verification and a second byte-exact
decode comparison. A complete second generation in a fresh temporary
directory had an empty recursive diff against the committed manifest and all
106 base64 files. The external-free verifier reported 53 unique MP3 streams,
53 unique PMP streams, 972,360 decoded MP3 bytes, and 679,268 PMP bytes.
`git diff --check` and the check for committed binary/oracle/temp-path leakage
were also clean.

The phase passed `cargo fmt --all -- --check`, warning-denied
all-workspace/all-target/all-feature Clippy, all-workspace/all-feature tests,
and `cargo deny check`; the targeted `zip_recompression_reference` test passed
separately. The root suite again reported 255 non-ignored Rust tests and three
doctests passing, with the same 26 external-corpus or environment-dependent
tests intentionally ignored. This phase adds original fixture tooling,
base64 research data, and documentation only. It changes no production parser,
decoder, dependency, unsafe boundary, limit, or fuzz-reachable path, so no new
Miri, sanitizer, property, fuzz, binding-wheel, or benchmark campaign applies.

### 2026-09-16 method-94 envelope and fresh WinZip evidence gate

The external-free method-94 verifier again accepted all 53 pairs, and the new
MIT analyzer passed Ruby syntax checking before independently parsing every
MP3 frame and verifying the PMP signature, descriptor, flags, reservoir marker,
and big-endian frame count. It observed 13 distinct unresolved values for
header byte 4 and deliberately made no claim about the entropy stream beginning
at byte 11.
A temporary-copy negative audit independently flipped the signature,
descriptor, flags, reservoir, and frame-count bytes; the analyzer rejected all
five mutations.

Three opt-in production harness runs passed against the fresh local-only
evidence: WinZip 21.0.12288 PPMd method 98, WinZip 21.0.12288 WavPack method
97, and all four WinZip 24.0.14033 BZip2, ZIP-LZMA, XZ, and Zstandard
replacement archives. The harnesses pin the executable/product identity in
the provenance record, archive and source hashes, member method and version,
compressed and uncompressed sizes, encryption state, CRC, decoded bytes, and
full-archive verification. Stock `7zz` 26.02 also completed integrity checks
for PPMd and all four formats it can decode; it identifies WavPack method 97
but does not implement that decoder.

The final tree passed `cargo fmt --all -- --check`, warning-denied
all-workspace/all-target/all-feature Clippy, all-workspace/all-feature tests,
warning-denied rustdoc, `cargo deny check`, and `git diff --check`. The ordinary
suite reported 255 non-ignored Rust tests and three doctests passing, with 28
environment- or corpus-dependent tests ignored; the three new evidence
harnesses were then run explicitly and passed. This follow-up changes test and
research tooling plus documentation, not a production parser, decoder,
dependency, unsafe boundary, resource policy, or fuzz-reachable path. No new
Miri, property, sanitizer-fuzz, binding-wheel, or benchmark campaign applies;
the production-decoder and stock-`7zz` checks above are the applicable
differential tests.

### 2026-09-16 method-94 feature-map follow-up gate

The clean-room generator now produces 54 accepted, unique MP3/PMP pairs. The
additional input is a project-authored five-frame, zero-main-data MPEG-1 Layer
III stream with intensity stereo enabled; the external packMP3 oracle accepted
it, verified its own round trip, and independently decoded it byte for byte.
A fresh complete generation matched the committed manifest and all 108 base64
files exactly. The external-free verifier reported 54 unique MP3 streams, 54
unique PMP streams, 974,445 decoded MP3 bytes, and 679,297 PMP bytes.

The expanded MIT analyzer parses standard Layer III side information and
mechanically verifies all eight byte-4 feature bits across 14 observed
combinations: padding, mid/side stereo, intensity stereo, switched blocks,
nonzero subblock gain, SCFSI scalefactor sharing, preflag, and scalefac-scale.
It accepted all 54 unmodified pairs, and eight independent negative runs each
flipped one byte-4 bit in the intensity fixture and were rejected. The entropy
stream at byte 11 remains outside the verified grammar, so method 94 continues
to return its typed unsupported-method error without output.

This follow-up passed Ruby warning/syntax checks, the targeted
`zip_recompression_reference` test, `cargo fmt --all -- --check`,
warning-denied all-workspace/all-target/all-feature Clippy, the complete
all-workspace/all-feature suite (255 non-ignored Rust tests and three doctests;
28 environment- or corpus-dependent tests ignored), warning-denied rustdoc,
`cargo deny check`, and `git diff --check`. It changes fixture/research tooling,
corpus data, and documentation only; no production parser, decoder, dependency,
unsafe boundary, resource policy, or fuzz-reachable path changed, so no new
Miri, property, sanitizer-fuzz, binding-wheel, or benchmark campaign applies.

### 2026-09-21 Rust 1.98.1 archive-lifecycle optimization gate

The completion tree passed the repository-pinned Rust 1.98.1 formatting,
warning-denied workspace/all-target/all-feature Clippy, complete
workspace/all-feature tests, no-default-feature check, warning-denied rustdoc,
and three doctests. Root, Python-binding, and fuzz-package cargo-deny checks all
passed advisories, bans, licenses, and sources. The separately locked Python
crate also passed formatting, warning-denied all-target/all-feature Clippy, its
two Rust tests, and its all-feature compile. Rust 1.85.0 passed the complete
core workspace test suite and both the core and binding all-target/all-feature
compile contracts. Rust 1.98.1 also compiled the complete workspace for
`i686-unknown-linux-gnu`; linked 32-bit execution remains the Linux CI job's
platform gate.

The release-only PPMd allocator-pressure test passed. Exact stock `7zz` 26.02
then passed the six generated core/property tests, both Phase 5 generated
tests, the generated symlink test, three library interoperability tests, and
the structured capability probe. Together those generated archives exercised
every stock-authorable supported 7z coder/filter, encrypted and solid layouts,
split volumes, corruption, truncation, resource limits, cancellation, and
expected typed unsupported capability results. No oracle executable or output
became a runtime dependency or committed fixture.

On `nightly-2026-09-01`, all 12 bounded Miri smoke tests passed, including the
LZMA2 EOS and new stream-pump batching/control-accounting regressions. An
exploratory full library Miri run produced no finding through the archive,
bounds, CPIO, and
earlier Debian tests but was stopped at a CPU-heavy Debian matrix rather than
misreported as a completed gate; CI and the recorded result use the explicit
bounded set. Cargo-fuzz 0.13.2 completed 10,000 AddressSanitizer and
coverage-guided executions for each of the eight targets with no crash,
sanitizer finding, timeout, or artifact. `FUZZING.md` records the per-target
coverage, feature, corpus, RSS, and duration observations. The fuzz package's
two deterministic profile/mutation tests passed separately.

Pinned maturin 1.15.0 produced the direct macOS x86-64 CPython 3.9 ABI3 wheel:
1,075,348 bytes, SHA-256
`d8de208abb97a59ffe4acbf2a541ca57b5e4e4c07cacc7ec76c339a080e252b1`.
It installed into an isolated CPython 3.12.10 environment and passed all 28
binding tests. The independently built 2,052,078-byte source distribution has
SHA-256
`940754358905c05dbd47b5515422c328894744b37beaa8e3d3897057cec2923f`;
its 284 entries contain no nested target, distribution, wheel, bytecode, or
`__pycache__` artifact. A no-build-isolation PEP 517 rebuild using the same
pinned maturin produced a separately hashed 1,075,626-byte wheel
(`40c60cab2b7d1bd3dc485384ae14ac0a4de913e17fb39168787dce59989938f7`).
That wheel contains 21 entries, no runtime dependency or console entry point,
and also passed all 28 tests after installation in a separate clean
environment.

The reproducible release benchmark gate generated 41 hash-pinned fixtures and
ran 111 native plus 89 installed-wheel operation rows, with five isolated
process samples per row. Every completed comparison retained exact decoded
bytes, work accounting, and allocation counts; only deliberately in-flight
cancellation work varies with its trigger schedule. The runners measured
wall/CPU time, peak RSS, block I/O, writes, cancellation latency, and
native/wheel size. The full
method matrix, report hashes, selected before/after values, profiler findings,
and deliberately rejected speculative changes are recorded in
`BENCHMARKS.md`. The generator was rerun safely against its existing output and
revalidated its manifest rather than silently replacing comparison inputs.
