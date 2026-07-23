# Implementation phase plan

This plan is ordered by security dependencies rather than method popularity.
Every phase is reviewable on its own, keeps all completed gates green, and
updates compatibility claims only when an identified corpus test passes.
Phases 1-7 are present on `main`; subsequent compatibility-hardening review
units are recorded below. Historical dates identify when each review unit and
its recorded local gates were performed.

## Source audit completed before implementation

The source revision, license, testdata inventory, and exact hashes used during
the initial audit are recorded in `PROVENANCE.md` and
`reference/7z-testdata.sha256`.

The initial corpus placeholders did not resolve to paths, and no separate 7z
corpus was available. No claim based on those placeholders is made. Audited
and generated evidence is recorded separately in `CORPUS.md`; binary fixtures
were not copied when their individual provenance was not established.

## Phase 1: foundation and policy

Status: implemented and audited on 2026-07-18. The audit
reran all baseline gates, added the required root `AGENTS.md`, and corrected the
resource model to include an explicit builder-configurable recursion-depth
limit. No existing Phase 1 layer was rewritten.

Deliverables:

- the project MIT license, separate upstream license texts, NOTICE, and exact provenance
  policy;
- workspace using edition 2024, MSRV 1.85, committed lockfile, a safe core,
  and no shipped executable crate;
- architecture, dependency ADR, threat model, security policy, corpus record,
  compatibility matrix, fuzzing plan, and benchmark record;
- cargo-deny license/source/ban/advisory configuration;
- typed error taxonomy, all default resource limits with builder overrides,
  cancellation/work-budget primitives, `VolumeProvider`, and safe path policy;
- CI definitions for formatting, Clippy, tests/docs, MSRV, 32-bit compilation,
  Linux/macOS/Windows, cargo-deny, Miri, and fuzz smoke tests.

Exit gate: format, Clippy with `-D warnings`, tests, documentation tests,
metadata, lockfile, license policy, and the active fuzz target pass. No archive
compatibility is claimed.

## Phase 2: bounded parser and validated model

Status: complete as of 2026-07-18.

Review units:

1. **Implemented:** bounded reader, 7z uint decoder, signature/start-header
   parsing, checked SFX scan, start/next-header CRCs, cancellation/work
   checkpoints, and a validated header-envelope type;
2. **Implemented:** borrowed raw PackInfo, UnpackInfo, SubStreamsInfo,
   FilesInfo, Header/EncodedHeader grammar, and exact bounded property readers;
3. **Implemented:** separate arbitrary coder-graph validation/topological
   schedule plus an owned validated model and exact file/substream mapping,
   using `Option` for absent CRC and unknown size;
4. **Implemented at the no-decode boundary:** additional streams and external
   property references, raw UTF-16 names, inline timestamps/attributes/
   StartPos, empty/anti records, and bounded unknown/archive/comment
   properties. External contents originally awaited decoding at this phase
   boundary; the 2026-07-19 post-phase follow-up now stages external folder
   definitions for bounded archive-layer resolution;
5. **Implemented:** generated malformed regressions, exact 100,000-entry
   boundary, malicious decoder declarations, nested truncations, mutation
   sweeps, and a 32-bit-only conversion regression plus CI compile target;
6. **Implemented where applicable:** raw/CRC-correct model and targeted graph
   fuzz targets plus the existing path target. Volume discovery remains a
   Phase 4 provider concern rather than bypassing the current byte-slice API.

Required regressions include FilesInfo-only initialization, invalid packed
indices, 100,000 empty entries, truncation, checked-offset overflow, malformed
counts/graphs, CRC-array mismatches, paths, and missing volumes. Decoder-sized
properties are validated structurally and bounded even though decompression is
not yet implemented.

Exit gate: arbitrary bytes never panic under fuzzing/Miri where applicable; no
allocation occurs before its relevant limit; every parsed property is exactly
consumed; all malformed regressions return the expected typed error. No
decompression claim is made.

Gate evidence on 2026-07-18: format, Clippy with `-D warnings`, all workspace
tests/features and documentation tests, both workspace/fuzz cargo-deny checks,
the 32-logical-archive source-audit model harness, external
`COMPRESS-492.7z` rejection, and four 10,000-run stable libFuzzer smoke targets
passed. The local Homebrew Rust installation is stable 1.97 and has neither
rustup, cargo-fuzz, Miri, nor the i686 standard library, so local MSRV, Miri,
instrumented cargo-fuzz, and 32-bit compilation could not run. Their CI jobs
remain configured; a 32-bit-only conversion regression is compiled by the
cross-target job. `BENCHMARKS.md` records why extraction benchmarking is not
applicable before a decoder exists.

## Phase 3: graph, CRC enforcement, and core methods

Status: complete for the declared Phase 3 scope as of
2026-07-18. Encryption-dependent chains remain an explicit Phase 4 gate and
are not claimed here.

Review units:

1. **Implemented:** linear decoder execution-plan integration using the Phase
   2 validated folder DAG and topological schedule, including four-input BCJ2
   and reverse-serialized chains;
2. **Implemented:** packed/folder/member bounded readers, explicit
   `MemberReader::finish`, caller-owned natural-order `EntrySink`, and all
   applicable packed/folder/member/encoded-header CRC layers;
3. **Implemented:** Copy plus corrupted packed, folder, and member regressions;
4. **Implemented:** LZMA and LZMA2 after exact BSD-3-Clause provenance
   admission, with malicious dictionary properties, declared-size/EOS rules,
   output-backed history, cancellation, and work limits;
5. **Implemented:** Delta, BCJ, BCJ2, PPC, ARM, ARM64, and SPARC filters with
   bounded tails/side streams and proportional loop checkpoints;
6. **Implemented:** one-decode-per-folder natural-order extraction, known and
   unknown per-entry preflight limits, linear 10,000-substream regressions,
   fuzz coverage, and a reproducible solid extraction benchmark.

Exit gate: byte/SHA-256, size, CRC, and metadata comparisons pass for identified
fixtures for every claimed method and chain, including encrypted-chain fixtures
only after AES exists. Extraction helpers cannot report success before member
CRC verification.

Gate evidence on 2026-07-18: workspace and fuzz formatting, strict workspace
Clippy, 54 core unit tests, 33 parser/model integration tests, documentation
tests/build, and both workspace/fuzz cargo-deny checks passed. The opt-in pinned
reference tests passed 32 stored-header models plus the missing-UnpackInfo
regression. The decoder differential passed `copy.7z`, `lzma.7z`, `lzma2.7z`,
`delta.7z`, `bcj.7z`, `bcj2.7z`, `ppc.7z`, `arm.7z`, `arm64.7z`, `sparc.7z`,
and `sfx.exe` against `7zz` 26.02 for ordered paths, sizes, optional CRCs,
exact bytes, and RustCrypto SHA-256. A final seedless 1,000-run stable-built
decoder fuzz smoke passed; `FUZZING.md` records its instrumentation limits and
the earlier 10,000-run seeded smoke. The release natural-order sink benchmark
decoded 36,054 bytes per iteration for 50 iterations at 48.742 MiB/s on the
documented host.

The local Homebrew Rust 1.97 installation still has no cargo-miri command or
i686 standard library, so local Miri and 32-bit checks could not execute; both
attempts failed solely for missing tooling/target. The configured CI jobs run
Miri, MSRV 1.85, i686 compilation, and Linux/macOS/Windows tests. Peak RSS was
not measured, and the current full-folder buffer is documented without a
constant-memory claim.

## Phase 4: codec expansion, crypto, SFX, metadata, and volumes

Status: implemented for the evidence-bounded capability rows in
`COMPATIBILITY.md` on 2026-07-18, with external folder definitions added as a
reviewed post-phase follow-up on 2026-07-19. Semantic decoded comments and a
filesystem collision/extraction policy remain explicit unsupported or
raw-metadata boundaries rather than inflated Phase 4 claims.

Review units:

1. **Implemented:** exact-version admission for `miniz_oxide`, `bzip2-rs`,
   `brotli-decompressor`, `lz4_flex`, `ruzstd`, RustCrypto AES/CBC/SHA-256, and
   `zeroize`, with complete transitive/license/unsafe/memory review;
2. **Implemented:** Deflate, BZip2, Brotli, checked LZ4-frame, and bounded
   Zstandard adapters with property/frame preflight, conservative working-memory
   charges, output/input/work/cancellation checks, dependency panic boundaries,
   and truncation regressions;
3. **Implemented:** safe in-tree PPMd7 variant-H adaptation from the exact MIT
   Go module, including checked address arithmetic, fallible heap access and
   allocation, output/work/cancellation bounds, exact source hashes, and notice;
4. **Implemented:** RustCrypto AES-256-CBC/SHA-256 with exact 7z property/KDF
   layout, direct and iterated KDF modes, pre-work `max_kdf_power`, per-round
   control checks, per-archive zeroizing password bytes, zeroized derived
   material, encrypted headers/data, and combined wrong-password/corrupt typing;
5. **Implemented:** AdditionalStreamsInfo decoding and exact external
   Name, creation/access/modification time, Windows attribute, and StartPos
   application; raw UTF-16, archive/comment properties, empty/anti/duplicate
   entries, Unix modes, symlink metadata, and safe-path separation are
   preserved. The follow-up stages externally stored main folder definitions,
   decodes every AdditionalStreamsInfo folder once, selects the indexed output,
   requires exact folder-record consumption, and revalidates the complete
   header. Explicit archive verification independently walks every additional
   folder, including unreferenced folders, drops each output before continuing,
   verifies every applicable CRC, and shares limits/password/control with main
   streams;
6. **Implemented:** bounded path and memory `VolumeProvider`s, sequential `.001`
   naming, checked aggregate input/count/capacity, cancellation/work between
   callbacks and reads, exact missing-volume diagnostics, split packed streams,
   and encrypted multi-volume data; and
7. **Implemented:** Phase 4 public-API differential/oracle tests, an encrypted
   BCJ→LZMA2→AES generated oracle, five-part encrypted/unencrypted memory tests,
   the real six-part path fixture, external metadata/CRC regressions, symlink
   oracle, external-folder stock-oracle and malformed/encrypted regressions,
   expanded decoder fuzzing, and an active volume fuzz target.

Exit gate: every supported row claimed in `COMPATIBILITY.md` has a named
differential test. Five-volume encrypted and unencrypted fixtures, SFX,
encrypted BCJ chains, and wrong/missing-password cases pass. Secrets have no
global cache and are cleared in drop tests where observable.

Gate evidence on 2026-07-18: workspace formatting, strict all-target/all-feature
Clippy, 80 core unit tests, 33 parser/model integration tests, all workspace and
documentation tests, rustdoc with warnings denied, and both workspace/fuzz
cargo-deny checks passed. All six fuzz binaries compile and pass strict Clippy;
the expanded decoder and new volume targets each completed a 1,000-run seedless
stable-built no-panic smoke. The opt-in corpus gates passed the 32 logical
stored-header models, missing-UnpackInfo rejection, all Phase 3 method
differentials, and all eight Phase 4 oracle tests. Phase 4 evidence includes
standard Deflate/BZip2/PPMd/AES byte/SHA/size/CRC/metadata comparisons, private
Brotli/LZ4/Zstd common-corpus comparisons, wrong/missing passwords, a generated
encrypted BCJ→LZMA2→AES differential, real six-part path input, deterministic
five-part encrypted and unencrypted memory input, exact missing/limit errors,
and generated symlink mode/target comparison.

The release natural-order solid benchmark decoded 36,054 bytes per iteration
for 50 iterations at 49.183 MiB/s on the documented host. Local Miri, MSRV
1.85, and i686 compilation could not run because this Homebrew Rust installation
has no `cargo-miri`, `rustup`, alternate toolchain, or i686 standard library;
the attempted i686 check failed only with missing `core`. CI retains dedicated
Miri, MSRV, i686, and Linux/macOS/Windows jobs. Stable-built fuzz smoke lacks
sanitizer/coverage instrumentation and is not presented as a coverage or
peak-memory result.

## Phase 5: remaining methods and complete differential corpus

1. **Implemented:** an in-tree bounded Deflate64 decoder for stored, fixed, and
   dynamic blocks, with its 64 KiB history charged before decoding and exact
   Apache Commons Compress revision, hashes, license, and notice recorded.
2. **Implemented:** checked IA64, ARM Thumb, RISC-V, Swap2, and Swap4 filters,
   based on pinned 0BSD XZ algorithm descriptions and without a new runtime
   dependency.
3. **Implemented:** a closed unknown-output admission policy. Bounded-input
   size-preserving methods and codecs with an explicit format terminator may
   run without a declared output size; other adapters return the typed
   `coder-unknown-unpacked-size` unsupported-feature error before decoding.
4. **Implemented:** `7zz`-authored production-path differentials for all six
   methods, including transforming inputs, bytes/SHA-256/size/CRC/metadata,
   packed-data corruption, Deflate64 solid/non-solid and encrypted data/header
   chains, and separately authored five-part encrypted and unencrypted
   archives through `PathVolumeProvider`.
5. Existing Phase 2-4 evidence remains the positive and malformed matrix for
   SFX, metadata, external streams, Unicode, symlinks, duplicates, graph and
   header corruption, passwords, and the audited 7z fixture set. No separate
   valid or malformed corpus path was available, so none was run or claimed as
   evidence.

Exit gate: all target rows are either supported with passing evidence or marked
unsupported with a typed-error test. No ambiguous “partial” claim remains.

Gate evidence on 2026-07-18: workspace formatting, strict all-target/all-feature
Clippy, 96 core unit tests, 34 parser/model integration tests, all workspace and
documentation tests, rustdoc with warnings denied, and both workspace/fuzz
cargo-deny checks passed. All six fuzz binaries compile and pass strict Clippy;
the expanded decoder target completed a freshly rebuilt 1,000-run seedless
stable-built no-panic smoke. The audited model tests, Phase 3 differential,
all eight Phase 4 oracle tests, and both Phase 5 oracle tests passed. The Phase
5 matrix covers all six methods, corruption, encrypted solid and non-solid
Deflate64, and separately authored five-part encrypted and unencrypted
archives. The release natural-order solid benchmark decoded 36,054 bytes per
iteration for 50 iterations at 44.139 MiB/s on the documented host.

Local Miri and i686 checks could not run: this Homebrew Rust installation has
no `cargo-miri`, `rustup`, or i686 standard library. The i686 attempt failed
only with missing `core`; dedicated CI jobs retain both gates plus the MSRV and
Linux/macOS/Windows matrix. The owner confirmed that the separate corpus sets
are unavailable, so only the accessible pinned and generated evidence is
claimed.

## Phase 6: stabilize the Rust API

Status: implemented as of 2026-07-18.

1. **Implemented:** froze concrete archive, entry metadata, error, limits,
   password-opening, volume, list, sink, path-policy, retained-resource, and
   explicit stream-finish behavior for the `0.1.x` line in `API.md` and
   `ERRORS.md`.
2. **Implemented:** removed raw envelope/parser/folder/coder mapping from the
   default surface. The documentation-hidden `unstable-internals` feature is
   enabled only by Phase 2 integration tests and fuzz targets.
3. **Implemented:** added a stable-surface integration fixture covering all
   three open forms, metadata, output, CRC failure, and resource reporting.
   The original executable Rust examples were subsequently removed when the
   shipped product boundary became Python-only in item 21 below.
4. **Implemented:** accounted retained archive bytes/model/password state and
   complete decoded-folder state held by `MemberReader`. Category-specific
   input/header/name/property/count/dictionary/output/KDF/work limits remain
   enforced by their owning layers.
5. **Implemented:** extended the 10,000-substream regression to natural-order
   sink extraction with an exact linear work budget. Each entry and substream
   is advanced once and each folder is decoded once; random member access
   remains explicitly documented as potentially re-decoding a solid folder.
6. **Implemented:** CI now checks the default curated surface, warning-free
   rustdoc, Linux/macOS/Windows tests, linked i686 tests including the
   32-bit conversion regression, MSRV, targeted Miri, cargo-deny, and all fuzz
   smoke targets. Reproduction commands are in `TESTING.md` and `FUZZING.md`.

Exit gate: API review confirms direct mappings for `open_path`, `open_bytes`,
`open_volumes`, list, `extract_entry_to`, and bounded streaming/callback output,
without exposing parser/graph generics.

Gate evidence on 2026-07-18: formatting, strict all-target/all-feature Clippy,
97 core unit tests, 34 parser/model integration regressions, three default
stable-API tests, all library/integration targets, documentation tests, and warning-denied
rustdoc passed. Both runtime and fuzz cargo-deny graphs reported advisories,
bans, licenses, and sources `ok`. The pinned structural suite, Phase 3 core
differential, all eight Phase 4 oracle tests, and both Phase 5 generated oracle
tests passed after the API change. All six fuzz binaries rebuilt with strict
Clippy and each completed a fresh 1,000-run seedless stable-built no-panic
smoke; nightly instrumented CI remains authoritative.

The Phase 6 release benchmark processed 10 solid entries and 36,054 bytes per
iteration with exactly 92,896 charged work units, 40.364 MiB/s in the
direct-process peak-memory sample, 1,359,872 bytes peak process RSS, and 8,184
bytes of accounted retained archive payload. The separate 10,000-substream
test exhausted exactly a `2n + 3` work budget for natural-order sink extraction
while finishing all entries, which is the deterministic non-timing regression
against an O(n²) rescan.

Local Miri and i686 execution remain unavailable because the Homebrew Rust
installation has no `cargo-miri`, `rustup`, alternate MSRV toolchain, or i686
standard library. The attempted i686 check failed only with missing `core` and
the attempted Miri command reported that no such Cargo command is installed.
CI retains Rust 1.85, Linux/macOS/Windows, targeted Miri, and now linked i686
test jobs. The literal `<CORPUS>` and `<MALFORMED_CORPUS>` sets were confirmed
unavailable and are not claimed as evidence.

## Phase 7: separate Python package

Status: implemented as of 2026-07-18 after the Phase 2-6
gates passed.

1. **Implemented:** created a workspace-excluded, separately locked
   `bindings/python` package using PyO3 0.29.0 and maturin 1.13.3. The PyPI
   distribution/import name is `unpackio`; the limited-API native module is
   `unpackio._native`; the core has no Python dependency.
2. **Implemented:** mapped the stable path, bytes, and sequential-volume open
   forms; archive-order metadata; limits, cancellation, work budgets, resource
   accounting, verification, writer extraction, and bounded callback streaming
   without duplicating parser/model/graph/decoder/crypto/path code.
3. **Implemented:** added distinct structured exceptions for every stable core
   error kind, exact propagation of Python provider/writer/callback exceptions,
   callback-triggered cancellation, and explicit unwind containment. The
   binding contains no handwritten unsafe code and release builds retain unwind
   semantics.
4. **Implemented:** Rust-only archive work detaches from Python. Owned handles
   are reattached only for a provider/writer/callback call; no borrowed Python
   reference crosses that region. Output uses bounded core chunks and provides
   no default complete-output return API. Native success remains after CRC
   finalization.
5. **Implemented:** exposed every archive limit, checked Python input/volume
   lengths before fallible Rust copies, retained per-operation tokens/budgets,
   preserved raw UTF-16 and optional metadata, and documented Python-owned
   password/provider/sink memory that Rust cannot erase or account.
6. **Implemented:** added `bindings/python/AGENTS.md`, PEP 561 stubs, exact
   license/notice payloads, a separate cargo-deny policy, installed-wheel tests,
   sdist rebuild testing, and Linux/macOS/Windows wheel CI plus an MSRV gate.
   ADR 0003 records the FFI and packaging decision. This phase changes only
   this repository.

Exit gate evidence on 2026-07-18: the binding passed formatting, strict
all-target/all-feature Clippy, all-feature compilation, its Rust unwind unit,
the exhaustive stable-error mapping unit, and its separate cargo-deny
advisory/ban/license/source policy. A release `cp39-abi3` macOS wheel installed
into a clean CPython 3.12 virtual environment;
all 10 public binding tests passed, including structured errors, CRC failure,
callbacks, volumes, limits, and interpreter detachment. The sdist rebuilt into
a wheel in an isolated PEP 517 environment; that installed wheel passed the
same suite. Both artifacts contained the package, type marker/stub,
licenses/notices, and generated SBOM. Root Rust gates remain green and the
workspace excludes the binding.

The GitHub workflow builds, installs, and tests produced wheels on Linux,
macOS, and Windows and checks Rust 1.85 separately. On 2026-07-20, PR #1 at
`8c26a6e` passed that three-platform wheel matrix, the binding quality and
MSRV gates, and the sdist rebuild test. The Python Copy fixture proves the FFI
boundary without broadening any codec row in `COMPATIBILITY.md`.

## Post-phase compatibility hardening

Status: active after the repository owner confirmed on 2026-07-18 that no
separate valid or malformed corpus is available.

1. Added a corpus-free generated `7zz` 26.02 oracle suite for the 13
   stock-authored core methods, header/data AES, and synthetic-prefix
   SFX. It verifies method selection, transforming filter input, ordered name,
   size, CRC, exact bytes, SHA-256, password typing, and packed corruption.
2. Fixed a parallel ignored-test collision in the encoded-header oracle by
   replacing clock-resolution filenames with a process-local atomic ordinal.
3. Added exhaustive public error kind/display/source regressions for every
   checksum scope, limit, and typed error variant.
4. Installed development-only cargo-fuzz 0.13.2 and cargo-llvm-cov 0.8.7 under
   a temporary tool root. All six fuzz targets passed 10,000 coverage-guided
   executions. The local sysroot lacked ASan, so nightly ASan CI remains the
   authoritative sanitizer gate.
5. Measured 65.00% core line coverage for ordinary all-feature tests and
   81.66% after merging the generated-method, Phase 5, and symlink oracle
   paths. Coverage measures the implementation core and remains diagnostic
   rather than a compatibility threshold.
6. Added staged external-folder resolution with folder-output `DataIndex`
   validation, exact reparse consumption, decoded-output reuse for external
   metadata, CRC/password/limit regressions, a generated fuzz wrapper, and
   black-box acceptance by stock `7zz` 26.02 for one- and two-folder forms.
7. Added sequential verification of unreferenced AdditionalStreamsInfo folders
   with exact packed/folder/substream checksum scopes, AES password states,
   cumulative additional-plus-main output/work/cancellation accounting,
   crossed three-part plain/encrypted memory volumes, a CRC-correct fuzz
   wrapper, and black-box acceptance by stock `7zz` 26.02. The refreshed
   ordinary core line report is 67.15%; merging the generated-method, Phase 5,
   symlink, stock additional-stream, and capability-probe paths reaches 83.85%
   lines (80.45% regions) after the matrix's negative pass. Capability candidates
   remain diagnostic rather than positive compatibility evidence.
8. Added an exact-version, corpus-free stock-`7zz` capability-probe suite with
   structured author/oracle/Rust outcomes and deterministic candidate hashes.
   The 26.02 macOS baseline covers comment candidates, alternative coders,
   unknown sizes, raw `AES256CBC` authoring, hard links, and symlinks; it finds
   no new confirmed decoder gap. The first Windows run rejected `-sni`
   security-descriptor and `-sns` alternate-stream authoring before producing
   an archive, so those semantics remain unproven rather than inferred.
9. Added a 24-archive exact-26.02 positive property matrix for LZMA/LZMA2
   dictionaries, LZMA probability properties, PPMd order/memory, Delta
   distances, BZip2 blocks, Deflate levels, filter chains, encrypted variants,
   and solid/non-solid multi-entry layouts. It rejects silent authoring
   normalization through exact coder-property, packed-header, method-token,
   graph, and folder-count assertions before comparing metadata, bytes,
   SHA-256, CRCs, and verification.
10. Extended all 24 property-matrix cases with packed corruption, three
    physical truncation boundaries, entry-output/work/cancellation limits, and
    applicable dictionary limits. Plain headers also get CRC-correct logical
    packed truncation plus oversized and empty coder-property declarations;
    BZip2 gets invalid block headers. Encrypted-header cases retain hostile
    outer-byte and operation-boundary coverage without claiming that their
    encrypted inner property bytes were directly mutated.
11. Added a corpus-free deterministic decoder generator with 21 complete,
    CRC-correct archive profiles and eight bounded structured mutation classes.
    Its standalone invariant test reaches production open, verification,
    extraction, graph, decoder, CRC, limit, work, and cancellation paths without
    retaining a binary fuzz corpus.
12. Added a fixed PPMd order-6/64-KiB packed vector produced by black-box stock
    `7zz` 26.02 from project-authored text. Exact provenance and hashes accompany
    core every-prefix/resource regressions and public corruption/CRC/limit/
    cancellation checks. A fresh 100,000-execution `decoding` campaign completed
    without a crash or timeout; its stable-sysroot no-ASan limitation remains
    explicit in `FUZZING.md`.
13. Added a checksum-pinned Windows stock-7-Zip 26.02 capability job. It accepts
    the official Windows banner through a test-only executable override and
    emits `-sni` security-descriptor and `-sns` alternate-stream classifications.
    The first output was reviewed on 2026-07-20: both authoring commands
    returned exit 2 with `System ERROR:`, so neither produced compatibility
    evidence.
14. The hardened follow-up at `24cf688` completed on 2026-07-20. The ordinary
    control was authored, oracle-tested/extracted, and Rust-verified; ADS
    creation passed byte-for-byte readback; and raw AES, `-sni`, and `-sns`
    each returned `System ERROR: Not implemented` before producing an archive.
    The full Rust workflow, including Miri, and the Python workflow passed.
    These results change no runtime feature boundary.
15. Promoted the corpus-free `generated_oracle` core/property matrix and both
    Phase 5 generated suites into the checksum-pinned Windows oracle job. Both
    harnesses accept the test-only executable override, recognize exact
    standalone and Windows 26.02 banners, generate fixtures in unique
    temporary directories, and delete them. Local exact-26.02 runs passed
    before the CI change. The first expanded Windows run at `d1eabdf` passed
    all four core/property tests and both Phase 5 tests.
16. Added a separately checksum-pinned Linux 26.02 capability job for link
    semantics. The hard-link probe now requires both Rust entry extractions to
    match the project-authored bytes and reports same-inode oracle extraction
    separately. Raw `AES256CBC` is attempted as both a main coder and a filter
    chain. The exact packaged manual establishes that `-sni` and `-sns` store
    only to WIM, so they are removed from the 7z compatibility backlog. The
    first Linux result at `d1eabdf` passed both Rust member-byte checks and
    symlink restoration, rejected both raw-AES authoring forms with
    `E_NOTIMPL`, and reported `same-file=false` for stock hard-link extraction.
    It therefore adds byte-level evidence without a hard-link semantic claim.
17. Added the Python batch adapter: strict PPMd admission for canonical
    five-byte properties and a zero-reserved seven-byte compatibility form;
    generated exact/malformed/resource tests;
    Python natural-order batch extraction with one shared budget/token and
    CRC-finalized entry boundaries; a complete-versus-unfinished Brotli
    regression; and explicit Linux x86-64/aarch64 ABI3 wheel jobs with native
    aarch64 smoke testing. No dependency or lockfile changed, and no external
    runtime fallback was added. Local gate evidence is recorded in
    `TESTING.md`: formatting, strict Clippy, full locked Rust tests, binding
    tests, installed ABI3 wheel tests, fuzz generator/smoke, ordinary coverage,
    and all three cargo-deny graphs passed. Hosted ARM64, Rust 1.85, Miri, and
    sanitizer evidence remain pending their configured CI runs.
18. Added explicitly separate unpack-only readers for standalone LZ4 frames,
    Zstandard frames, and Unix `compress` `.Z` streams without changing the
    7z `Archive` model or adding a command-line surface. The readers validate bounded frame/code layouts,
    enforce input/dictionary/frame/output/work/cancellation limits, verify all
    declared checksums, and write only to caller-selected sinks. Rust and
    Python APIs expose metadata and bounded extraction; generated hostile
    tests, a dedicated fuzz target, native-tool exact-output differentials,
    the NetBSD BSD-3-Clause adaptation notice, and an installed ABI3 wheel
    smoke test accompany the implementation. External LZ4/Zstandard
    dictionaries and Zstandard magicless frames remain typed unsupported.
19. Added separate unpack-only `ZipArchive` and `RpmArchive` models without
    changing the 7z `Archive` or adding a writer/filesystem API. ZIP covers
    ordinary/ZIP64/SFX structure, six compression families, ZipCrypto, and
    WinZip AES AE-1/AE-2; RPM covers typed headers, six payload compressor
    forms, newc/CRC-newc, and the documented supported digest boundaries.
    Rust/Python generated tests and a seedless deep-structure fuzz target cover
    positive extraction, corruption, truncation, path, allocation, output,
    work, cancellation, and callback behavior. The compatibility matrix records
    split/strong ZIP encryption, ZIP XZ/PPMd, non-newc RPM payloads, OpenPGP
    authentication, legacy/per-file RPM digests, and constant-memory RPM
    decoding as explicit remaining boundaries rather than parity claims.
20. Added separate unpack-only `CpioArchive`, `DebArchive`, and `ArjArchive`
    models without changing 7z `Archive` or adding a CLI. The shared CPIO parser now
    covers newc/CRC-newc, odc, and both historical binary byte orders; Debian
    covers its checked ar/tar envelope and all documented payload compressors;
    ARJ covers bounded SFX, checked headers, methods 0--4 and empty methods 8/9.
    Concrete Rust/Python APIs, generated hostile/resource cases, compressor and
    real ARJ method fixtures, seedless fuzz paths, provenance/license records,
    and installed ABI3 wheel tests accompany the implementation. Compression
    wrappers for raw CPIO, general ar/tar, package installation, Debian
    signatures, and encrypted/split/security ARJ remain explicit boundaries.
21. Removed the executable frontend, its workspace member, and the executable
    Rust examples. The supported consumer product is now only the `unpackio`
    Python package backed by the separately compiled safe-Rust core. CI rejects
    future Cargo `bin`/`example` targets, and installed-wheel tests reject
    entry points. No console script, command parser, or subprocess archive
    surface is packaged; tests continue to invoke `7zz` only through
    ignored/checksum-pinned oracle harnesses.

No binary oracle output or fuzzer working corpus is committed. Further
compatibility work should use these generated/fuzz/coverage paths and retain a
typed unsupported result wherever stock syntax is still unimplemented.

## Continuous review rules

Every pull request updates `COMPATIBILITY.md`, `SECURITY.md`, `THREAT_MODEL.md`,
`DEPENDENCIES.md`, `PROVENANCE.md`, `FUZZING.md`, and `BENCHMARKS.md` when its
claims or evidence change. A method cannot move to “supported” in the same
change that merely adds a decoder dependency: parser/graph integration,
corruption behavior, limits, and differential evidence are all required.
