# Fuzzing

## Active targets

`fuzz/fuzz_targets/path_validation.rs` feeds arbitrary UTF-8 (when valid) and
arbitrary little-endian UTF-16 units to both path validators. The target checks
the no-panic property and exercises traversal, root, drive, UNC, NUL, and
unpaired-surrogate handling. It has no filesystem side effects.

`fuzz/fuzz_targets/header_envelope.rs` feeds arbitrary bytes to the production
bounded envelope parser under reduced input/header/SFX limits and a finite work
budget. It also places a CRC-correct minimal plain envelope after an arbitrary
SFX prefix, exercising valid discovery and attacker-controlled false
candidates without bypassing production CRC checks.

`fuzz/fuzz_targets/next_header.rs` wraps arbitrary bytes in CRC-correct start
and next headers, then also forces them into a bounded plain Header body. It
invokes the production raw parser, exact property readers, graph validator, and
model conversion with reduced count/allocation limits and a finite work
budget. Recomputing both CRC layers ensures mutations reach nested validation.
The harness enables the documentation-hidden `unstable-internals` feature;
applications do not need and must not rely on that parser/model surface.

`fuzz/fuzz_targets/validated_graph.rs` constructs a complete small StreamsInfo
record and derives bind-pair domains from fuzz bytes. It keeps the surrounding
grammar and CRCs valid so cycles, duplicate inputs/outputs, roots, and
declaration-order variations reach the isolated production graph validator.

`fuzz/fuzz_targets/decoding.rs` invokes `Archive::open_bytes` and
`Archive::open_bytes_with_password`, then `Archive::verify`, with reduced
header/count/property/dictionary/input/output/KDF/recursion limits and a finite
work budget. Valid seeds reach encoded/encrypted-header resolution, arbitrary
graph execution, every Phase 3-5 decoder and filter, password/KDF handling, and
packed/folder/member CRC paths through the public API. Mutations retain the
no-panic, bounded-work contract even when an earlier CRC or parser layer rejects
them.

The same target also wraps every input into a CRC-correct one-member Copy
archive and into one selected single-input core coder archive. These generated
envelopes keep signature/start/next-header grammar and ranges valid, so
seedless CI runs reach production graph execution and Copy CRC finalization.
The target also builds a CRC-correct archive whose main folder definition is
stored in AdditionalStreamsInfo. One selector supplies a valid Copy folder and
the others supply up to 256 arbitrary bytes, so seedless runs reach both the
successful staged decode/reparse path and bounded malformed external-folder
parsing without weakening any checksum.
Every input is also wrapped as the packed bytes of an otherwise CRC-correct,
unreferenced AdditionalStreamsInfo Copy folder beside a valid main Copy member.
Calling `Archive::verify` on that envelope keeps the outer grammar and main
member valid while driving arbitrary additional-stream bytes through packed,
folder, and logical-substream verification under the public operation limits.
The selected one-coder wrappers directly exercise LZMA/LZMA2, all
single-input filters, Deflate, Deflate64, BZip2, PPMd, Brotli, LZ4, Zstandard,
and bounded AES/KDF error paths without disabling an integrity check in
production code. A second generated wrapper declares an unknown output size
for the closed allowlist of boundary- or EOS-terminated methods. BCJ2
four-input success coverage uses both an in-process seed and the corpus-free
generated `7zz` oracle; malformed graph/input coverage remains in the fuzz
target.

Every `decoding` input now also selects one of 21 complete, CRC-correct,
in-process archive profiles: Copy; the fixed raw-LZMA EOS vector; three LZMA2
dictionary properties; stored Deflate and Deflate64; fixed BZip2, Brotli, and
PPMd vectors (the PPMd payload is exercised with both canonical five-byte and
zero-reserved seven-byte properties); uncompressed LZ4 and Zstandard frames; direct-KDF AES; a
reverse-declaration Copy graph; four-input BCJ2; LZMA2-to-BCJ and
LZMA2-to-PPC chains; and Copy-to-Delta chains at distances 1, 4, and 256.
Input-derived payloads are capped at 64 bytes. The positive archive must open,
verify, and, when the expected transform is independently known, extract exact
bytes. A second path applies one of eight structured mutations: packed-data
corruption, physical truncation, CRC-correct property-length/property-byte/
bind-index/unpack-size changes, folder-CRC corruption, or a CRC-correct
packed-size decrement. This keeps every seedless run in deep parser/graph/
decoder states while retaining arbitrary malformed coverage. The fixed vectors
and test-only AES authoring provenance are recorded in `CORPUS.md` and
`PROVENANCE.md`.

`fuzz/fuzz_targets/volumes.rs` sends arbitrary part boundaries, missing terminal
parts, excessive part counts, and CRC-correct Copy archives through
`Archive::open_volumes` and `MemoryVolumeProvider`. Reduced volume/input/output
limits and finite work budgets exercise exact sequential discovery,
cross-boundary parsing/decoding, aggregate allocation checks, and missing/limit
termination through the public API.

`fuzz/fuzz_targets/stream_formats.rs` sends bounded arbitrary bytes through
auto-detection and explicit LZ4, Zstandard, and Unix `.Z` opens, then verifies
any accepted layout. Every input also creates valid raw-block LZ4 and
Zstandard frames whose exact output is asserted, plus a `.Z` header around
arbitrary code bytes. Reduced frame/input/dictionary/output/work limits keep
the structural scanners and decoder loops bounded while exercising checksum,
width-transition, frame-count, and cancellation checkpoints through the stable
`CompressedStream` API.

`fuzz/fuzz_targets/archive_formats.rs` sends bounded arbitrary bytes through
the public `ZipArchive`, `RpmArchive`, `CpioArchive`, `DebArchive`, and
`ArjArchive` open/verify paths with reduced input/header/count/name/dictionary/
output/work/SFX limits. Every input also becomes the payload of structurally
valid stored ZIP, uncompressed RPM/CRC-newc, standalone CRC-newc, uncompressed
Debian, and stored ARJ containers; exact extraction is asserted. These
seedless wrappers keep central/local ZIP records, ZIP/member CRCs, RPM headers,
CPIO alignment/checksums, ar/tar checksums, and ARJ header/member CRCs correct
so mutations reach format-specific semantic and output boundaries instead of
stopping at magic bytes.

The ZIP generator also embeds a complete XZ 1.0.4 method-95 Stream around
project-authored `abc` output. Every input drives the valid exact-output case,
one input-selected XZ-byte mutation under an otherwise CRC-correct ZIP
envelope, and one strict XZ-prefix truncation. This keeps Stream/Block/Index,
filter-property, padding, Check, decoded-size, and member-CRC rejection paths
reachable without invoking an external encoder or weakening production
checks.

It independently embeds the nine-byte stock-`7zz` 26.02 ZIP PPMd-I
method-98 vector for project-authored `abc`. Every input first drives exact
successful extraction, then an input-selected payload mutation and a strict
prefix. Those cases retain a structurally and CRC-correct ZIP envelope so the
fuzzer reaches property parsing, range normalization, model/context updates,
allocator/restoration checks, early/missing end markers, exact input
consumption, output-size reconciliation, and member CRC handling. The target
never invokes the oracle or the test-only encoder.

The same target embeds the exact WavPack 4.80 method-97 payload and expected
RIFF/WAVE bytes for the project-authored 8-bit mono profile. Every input first
requires exact extraction, then selects one WavPack byte mutation and one
strict prefix inside an otherwise valid, CRC-correct ZIP envelope. This keeps
block/header/metadata parsing, decoder panic containment, WavPack CRC, wrapper
reconstruction, output reconciliation, and ZIP CRC paths reachable without an
encoder, writer, or external command in the fuzz package.

The target also embeds the provenance-complete WinZip 21 method-96 payload and
project-authored JPEG. To control per-execution cost, one of every 64 selector
classes (including the empty initial input) requires exact successful
reconstruction, then derives an input-selected payload mutation and strict
prefix inside an otherwise valid ZIP envelope. This makes properties, metadata
bundle/LZMA handling, persistent JPEG tables, arithmetic contexts, slice
buffers, Huffman reconstruction, exact outer consumption, limits, and member
CRC paths reachable without invoking WinZip, XArchive, or an external decoder.

Normal tests complement fuzzing with exhaustive decoding of every one- and
two-byte 7z integer encoding, all truncations of the nine-byte form, all split
points of the standard CRC vector, all byte-prefix truncations of valid outer
and nested headers, CRC-correct mutation sweeps, valid graph chains of lengths
one through eight, the 100,000-entry boundary, every prefix of small LZMA and
LZMA2 EOS streams and a raw Deflate final-block stream, truncated LZMA range
initialization, truncated BCJ2 range input, corrupt Copy/member CRCs, every
prefix of a stored Deflate64 block, every prefix and exact/trailing variants of
an external-folder archive, invalid external output indices, external
packed/folder/substream CRCs, encrypted password states, and decoder
output/work/cancellation limits. Serialized unreferenced-additional regressions
also cover additional-only and additional-plus-main success, distinct packed,
folder, and substream corruption scopes, AES password states, cumulative
additional-plus-main output accounting, work exhaustion, cancellation, and
plain/encrypted packed data crossing three memory-volume boundaries.

Solid-output regressions additionally cover pre-decode limits for every known
substream, an unknown final member capped to one entry allowance, typed
pre-decode rejection of an unknown non-final member, and proportional work
charging across an x86 BCJ input with no branch opcodes.

The exact-version `7zz` capability probes are not fuzz seeds and make no
no-panic claim. Their deterministic synthetic comment, alternative-coder, and
unknown-size candidates exercise ordinary parser boundaries; only a probe that
becomes accepted compatibility evidence may be promoted to a seed after its
origin and expected result are recorded. Temporary oracle-authored link and
platform-metadata archives are deleted. The Windows no-switch control,
ADS-readback precondition, stage baseline, and bounded command diagnostics
classify the oracle environment; they do not enter a fuzz corpus or bypass the
production parser's normal limits and checksums.

The exact-version method/property matrix is also positive differential input,
not automatically a fuzz corpus. Its property combinations may be promoted to
the existing generated decoding wrappers only after the serialized case is
reduced, its origin and expected result remain reproducible, and mutation does
not require invoking `7zz` from a fuzz target. The matrix itself never runs in
libFuzzer. Continuous execution in the checksum-pinned oracle job does not add
its ephemeral archives to a fuzz corpus. Its deterministic CRC-correct
packed-size/property mutations remain integration regressions; a later
seed-generator change may reproduce their structures without retaining
oracle-authored archive bytes.

The targets use `libfuzzer-sys` 0.4.13. Its NCSA license term is recorded as an
exact, fuzz-only cargo-deny exception; it is not a runtime dependency or runtime
license exception.

Run a smoke test with a nightly toolchain and cargo-fuzz:

```text
cargo +nightly fuzz run path_validation -- -runs=10000
cargo +nightly fuzz run header_envelope -- -runs=10000
cargo +nightly fuzz run next_header -- -runs=10000
cargo +nightly fuzz run validated_graph -- -runs=10000
cargo +nightly fuzz run decoding -- -runs=10000
cargo +nightly fuzz run volumes -- -runs=10000
cargo +nightly fuzz run stream_formats -- -runs=10000
cargo +nightly fuzz run archive_formats -- -runs=10000
```

The fuzz package enables `unpackio/unstable-internals` because three structural
targets require deep parser/model visibility; other targets do not call those
exports and continue to enter through the stable archive API. To confirm
the standalone harness graph and license policy before running:

```text
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo test --manifest-path fuzz/Cargo.toml --locked
cargo deny --manifest-path fuzz/Cargo.toml check
```

The standalone integration test enumerates all 21 positive archive profiles and all
eight mutation classes. It is a deterministic generator invariant check, not a
replacement for libFuzzer mutation or oracle differential tests. The fuzz-smoke
CI job runs this invariant test before launching the eight targets.

Generated corpus and crash artifacts are ignored. Minimized, non-sensitive
regressions move into normal unit/integration tests with documented provenance.
No private or external archive corpus is required for a seedless smoke run:
the structural targets synthesize valid envelopes/graphs and `decoding`
constructs CRC-correct Copy and selected-method wrappers from every input.

## Planned targets

| Target | Phase | Primary properties |
| --- | ---: | --- |
| Header-envelope parser | 2 | Active: no panic; bounded scan/ranges; CRCs; cancellation/work limits |
| Nested raw header parser | 2 | Active: bounded reads/allocations; exact property consumption |
| CRC-correct header mutation | 2 | Active in `next_header`: semantic validation beyond CRC gates |
| Validated graph builder | 2/3 | Active: index uniqueness, roots, cycles, totals, deterministic schedule |
| Decoder dispatch and loops | 3+ | Active in `decoding`: public dispatch, encoded headers, output/dictionary/work bounds, cancellation, CRCs, no stalls |
| Volume discovery/logical reads | 2/4 | Active in `volumes`: exact sequential requests, count/byte limits, missing parts, cross-boundary ranges |
| Path validation | 1 | No panic and stable safety classification |
| Standalone compressed streams | Additive | Active: LZ4/Zstandard frame ranges and checksums; Unix `.Z` code/dictionary state; all shared limits |
| ZIP and RPM containers | Additive | Active: arbitrary public open/verify plus valid stored-ZIP and CRC-newc RPM wrappers with exact extraction and shared limits |

Fuzz targets invoke the same production validation and limits as public APIs;
they do not bypass CRC or invent sizes. Future method-specific targets may
increase state-machine depth beyond the shared public decoder target.

## Python FFI coverage

Phase 7 adds no parser, model, graph, decoder, crypto, volume-assembly, or path
implementation to fuzz independently. Arbitrary 7z archive bytes entering
`unpackio.open_bytes` reach the same production functions already exercised by
`header_envelope`, `next_header`, `validated_graph`, and `decoding`; Python
volumes reach the same `VolumeProvider` logic exercised by `volumes`.
Python ZIP/RPM bytes reach the same public core functions exercised by
`archive_formats`; their callback conversion boundary is covered by installed-
wheel tests.

The FFI-only state space is covered by deterministic installed-wheel tests for
invalid archive bytes, CRC failure, unsafe raw UTF-16 names, provider absence,
limits, cancellation, callback exception identity, callback `False`, writer
delivery, natural-order solid batch extraction, empty and duplicate entries,
batch CRC/exception/cancellation boundaries, shared work/output limits, and
concurrent Python progress during detached Rust work. The same installed-wheel
suite covers the native Python data contract: duplicate order, metadata
projection, correct and incorrect ZIP passwords, caller-owned seekable output,
typed corruption, symbolic/scalar RPM headers, and verified RPM extraction.
No independent binary parser is introduced; arbitrary bytes still enter the
existing ZIP/RPM core fuzz surface.
The native unwind helper has a Rust regression that injects an unwind and observes
containment. A future dedicated CPython fuzz harness must be added only if the
adapter gains independent conversion grammar or stateful callback scheduling;
it must not bypass the existing core fuzz targets.

## Seed and mutation strategy

- Seed the raw parser with generated minimal plain/encoded headers and admit
  any future external seed only after its provenance review.
- Maintain a mutator that recomputes start/next-header CRCs so changes reach
  nested validation.
- Seed graph fuzzing with small valid multi-input and non-declaration-order
  graphs, then mutate counts, bindings, and packed indices.
- Keep the embedded ZIP method-95 seed byte-for-byte tied to the generated
  vector recorded in `CORPUS.md`; mutate and truncate it only inside the
  in-process hostile wrapper.
- Keep the method-98 seed byte-for-byte tied to the separately generated PPMd-I
  vector in `CORPUS.md`; always run its exact positive case before the
  input-selected mutation and prefix so a decoder regression cannot hide
  behind permissive fuzz error handling.
- Keep the method-97 WavPack payload and expected WAV tied to the exact hashes
  in `CORPUS.md`; require its positive extraction before applying the selected
  payload mutation and strict prefix.
- Seed volume fuzzing with gaps, empty parts, short reads, exact-boundary reads,
  encrypted-block boundaries, and excessive totals.
- Never place confidential archives, real passwords, decrypted headers, or
  customer paths in a fuzz corpus.

## Triage

Every crash, timeout, excessive allocation, non-progress loop, Miri failure,
checksum bypass, or inconsistent error classification is retained and treated
as a security issue until explained. Fixes add a minimized deterministic test.
Fuzz duration, toolchain, target, corpus revision, and peak memory are recorded
when sustained campaigns begin in Phase 2.

## Current smoke evidence

On 2026-07-18, `header_envelope`, `next_header`, `validated_graph`, and
`path_validation` each completed 10,000 executions with no crash using the
locally available stable-built libFuzzer runner. Those runs lacked sanitizer
and coverage instrumentation, as their warnings reported, so they are only
harness/no-panic smoke checks and do not replace the nightly `cargo-fuzz` CI
job.

On the same date, `decoding` completed 10,000 stable-built executions with no
crash after loading copied seeds for all ten supported method fixtures. The
runner reported a 179,082-byte, ten-file seed set and 26 MiB RSS at
initialization. It also reported missing sanitizer hooks and no coverage
instrumentation, so this is only a public-API harness/seed no-panic smoke run,
not a coverage or memory benchmark. The temporary seed directory was separate
from and did not modify the pinned corpus.

After CRC-correct generated Copy and selected single-input coder wrappers were
added, the same target also completed a 1,000-execution seedless stable-built
smoke run. That run began from the empty corpus and reached the generated valid
envelopes without external fixtures. It had the same missing-sanitizer and
missing-coverage limitations; nightly `cargo fuzz` remains the authoritative
CI smoke gate.

After Phase 4 decoder/password selectors and the volume target were added,
`decoding` and `volumes` each completed another 1,000-execution seedless
stable-built smoke run on 2026-07-18 with no crash. Each run reported 26-27 MiB
RSS and the same missing sanitizer hooks/no coverage instrumentation; these are
harness no-panic checks, not coverage or peak-memory claims. All six fuzz
binaries also compiled from the separately locked fuzz package.

After the Phase 5 selectors, unknown-output wrappers, and remaining methods
were added, all six fuzz binaries rebuilt and passed strict Clippy. The
`decoding` binary completed another 1,000-execution seedless stable-built smoke
run on 2026-07-18 with no crash and 27 MiB reported RSS. The runner again
reported missing sanitizer hooks and no coverage instrumentation, so this is a
harness no-panic check rather than coverage or peak-memory evidence.

After the Phase 6 API visibility change, all six fuzz binaries rebuilt with
the package-level `unstable-internals` feature and passed strict Clippy. Each
fresh binary completed a 1,000-execution seedless stable-built smoke run on
2026-07-18 with no crash. The runners reported 25-27 MiB RSS and again warned
that sanitizer hooks and coverage instrumentation were unavailable, so these
are harness/no-panic checks only; the nightly cargo-fuzz CI jobs remain the
authoritative instrumented gate.

Phase 7 changes no fuzz target or archive-processing implementation. The six
core targets still compile and run under the root workflow, while the separate
binding workflow exercises FFI-specific behavior through installed wheels. No
new fuzz-coverage claim is made for PyO3 or CPython internals.

After the repository owner confirmed that no separate valid or malformed
corpus is available, all six targets completed a fresh 10,000-execution
coverage-guided run on 2026-07-18. The local Homebrew stable sysroot could not
link `rustc-stable_rt.asan`; the local command therefore used cargo-fuzz 0.13.2
with `RUSTC_BOOTSTRAP=1 --sanitizer none`. This is real sanitizer-coverage
feedback, but it is not an AddressSanitizer result and does not replace the
nightly ASan CI gate.

On 2026-07-19, after adding the CRC-correct external-folder wrapper,
`decoding` rebuilt and completed 1,000 additional executions with no crash.
The ignored local working corpus began with 301 generated entries; libFuzzer
finished at 1,817 coverage counters, 3,318 feature counters, 288 retained
entries, and 26 MiB reported RSS. This used the same Homebrew
`RUSTC_BOOTSTRAP=1 --sanitizer none` fallback and emitted the same missing
sanitizer-hook warnings, so it is a coverage-guided harness/no-panic smoke
result, not AddressSanitizer or peak-memory evidence.

After adding the CRC-correct unreferenced-additional wrapper on the same date,
`decoding` rebuilt and completed another 1,000 executions with no crash. It
loaded 325 working-corpus files, initialized with 1,857 coverage counters and
3,381 feature counters, and finished at 1,888 coverage counters, 3,488 feature
counters, 317 retained entries, and 27 MiB reported RSS. The run again used
`RUSTC_BOOTSTRAP=1 --sanitizer none` and emitted missing sanitizer-hook
warnings, so it is coverage-guided harness/no-panic evidence rather than an
AddressSanitizer or peak-memory result.

The last observations before the in-process decoder-seed generator were:

| Target | Coverage counters | Feature counters | Corpus entries | RSS |
| --- | ---: | ---: | ---: | ---: |
| `header_envelope` | 64 | 98 | 11 | 25 MiB |
| `next_header` | 400 | 596 | 97 | 25 MiB |
| `validated_graph` | 444 | 670 | 19 | 25 MiB |
| `decoding` | 1,888 | 3,488 | 317 | 27 MiB |
| `volumes` | 805 | 1,215 | 40 | 26 MiB |
| `path_validation` | 71 | 128 | 66 | 25 MiB |

No target crashed or timed out. The generated working corpora remain under the
ignored `fuzz/corpus/` path; they are disposable local fuzzer state, not
project compatibility fixtures. The reproducible authoritative command stays
the nightly cargo-fuzz form above, which enables AddressSanitizer by default.

On 2026-07-19, the new deterministic decoder profiles first passed their
standalone exhaustive test and then ran from fresh empty temporary corpora. The
`decoding` target completed 100,000 executions; each other target completed
50,000. No target crashed or timed out. The observations at process exit were:

| Target | Runs | Coverage counters | Feature counters | Retained entries | Corpus bytes | RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `header_envelope` | 50,000 | 64 | 98 | 12 | 404 | 25 MiB |
| `next_header` | 50,000 | 511 | 876 | 141 | 2,144 | 25 MiB |
| `validated_graph` | 50,000 | 445 | 671 | 15 | 55 | 25 MiB |
| `decoding` | 100,000 | 3,661 | 8,255 | 1,007 | 12,408 | 58 MiB |
| `volumes` | 50,000 | 763 | 1,196 | 48 | 1,853 | 26 MiB |
| `path_validation` | 50,000 | 74 | 165 | 78 | 2,401 | 25 MiB |

The `decoding` binary had previously ended at 1,888 counters and 3,488
features, but the harness itself also grew, so that delta is evidence of
substantially deeper feedback—not a source-line coverage percentage. The
fresh `volumes` corpus ended below the earlier retained-corpus observation; no
coverage improvement is claimed for that target.

These runs used cargo-fuzz 0.13.2 with sanitizer-coverage feedback and the
local fallback `RUSTC_BOOTSTRAP=1 --sanitizer none`, because the Homebrew stable
sysroot lacks the matching AddressSanitizer runtime. The reported RSS is a
runner observation, not a bounded-memory benchmark. The missing sanitizer
hooks mean these results are no-panic/coverage-guided evidence only; the
nightly AddressSanitizer job remains required. All temporary corpora were
created under `/private/tmp` and are not repository fixtures.

After adding the twentieth, fixed PPMd profile, a second fresh `decoding`-only
campaign completed 100,000 executions in 38 seconds without a crash or timeout.
It ended at 3,738 coverage counters, 8,663 feature counters, 1,192 retained
entries (approximately 18 KiB), and 63 MiB RSS. The preceding PPMd-free run
ended at 3,661 counters and 8,255 features, but the harness changed, so this is
feedback-depth evidence rather than a source-coverage delta. This run used the
same Homebrew-stable `RUSTC_BOOTSTRAP=1 --sanitizer none` fallback and therefore
does not replace the nightly AddressSanitizer gate.

On 2026-07-21, after adding the twenty-first zero-reserved seven-byte PPMd
profile, the deterministic 21-profile/eight-mutation test passed. A freshly
built stable `decoding` harness then completed 1,000 seedless executions with
no crash or timeout and 48 MiB reported RSS. It explicitly warned that
sanitizer hooks and coverage instrumentation were missing. Direct cargo-fuzz
could not start because this host has stable Rust only and rejects its nightly
`-Zsanitizer` option; Miri is likewise not installed. This result is therefore
only a harness/no-panic smoke, while nightly ASan fuzzing and Miri remain CI
gates.

Later on 2026-07-21, the new `stream_formats` harness completed 10,000 finite
seedless executions through auto-detection, all three explicit formats, and
the generated exact-output LZ4/Zstandard paths. Its first empty-seed run found
an invalid harness fixture: a zero-length LZ4 uncompressed block had been
emitted where the format requires the end marker. The generator was corrected
to omit that block, and the full rerun completed without a decoder failure.
This host again lacked nightly cargo-fuzz, sanitizer hooks, and coverage
instrumentation, so the result is a finite invariant/no-panic smoke rather
than ASan evidence; the configured nightly CI run remains authoritative.

After ZIP and RPM support was added on 2026-07-21, all fuzz binaries including
`archive_formats` compiled from the separately locked fuzz package and its two
deterministic integration tests passed. `archive_formats` exercises arbitrary
public open/verify paths and generated valid stored-ZIP and CRC-newc RPM
wrappers with exact extraction. This host still has no rustup nightly or
`cargo-fuzz`, so no local coverage-guided execution is claimed for the new
target; the configured nightly CI smoke remains the sanitizer-backed gate.

After standalone CPIO, Debian-package, and ARJ paths were added to the same
target, the separately locked fuzz package again passed strict compilation and
both deterministic generator tests. A fresh `archive_formats` binary completed
1,000 seedless executions while invoking arbitrary open/verify paths and valid
generated exact-output wrappers for ZIP, RPM, CPIO, Debian, and ARJ. It found
no failure, but emitted the expected missing-sanitizer/missing-instrumentation
warnings because this host has neither cargo-fuzz nor rustup/nightly. This is a
finite harness/no-panic smoke only; it does not replace the configured nightly
coverage-guided AddressSanitizer run.

On 2026-09-14, after adding the always-valid and hostile ZIP XZ method-95
wrappers, the separately locked fuzz package's two deterministic tests and
strict all-target Clippy passed. A fresh stable-built `archive_formats` binary
then completed 10,000 executions from an empty corpus in three seconds with no
failure and 28 MiB reported RSS. Every iteration first extracted the valid XZ
member to exact `abc`; nonempty inputs also selected one XZ mutation and one
strict prefix. The runner again reported missing sanitizer hooks and no
coverage instrumentation because this host has neither `cargo-fuzz` nor a
nightly toolchain. This is finite harness/no-panic evidence, not an ASan,
coverage, throughput, or peak-memory claim; the configured nightly gate remains
authoritative.

After adding the corresponding exact-output and hostile ZIP PPMd method-98
paths, the separately locked package again passed formatting, warning-denied
all-target/all-feature Clippy, and both deterministic generator tests. A final
stable-built `archive_formats` binary completed 10,000 seedless executions in
99 seconds with seed `167906171`, no failure, and 41 MiB reported RSS. Every
iteration verified exact XZ and PPMd extraction before selecting their hostile
mutation and strict-prefix paths. The runner explicitly reported missing
sanitizer hooks and missing coverage instrumentation on this Homebrew stable
toolchain. This is finite invariant/no-panic evidence only; it does not replace
the configured nightly AddressSanitizer and coverage-guided gates or establish
a memory-performance bound.

After the version 0.2.0 dependency refresh, the rebuilt stable
`archive_formats` harness completed another 10,000 seedless executions in 92
seconds with seed `2925986431`, no failure, and 49 MiB reported RSS. The same
valid-XZ/PPMd-first invariants and hostile mutation/prefix paths ran against the
updated dependency graph. The runner again reported no sanitizer or coverage
instrumentation, so this remains finite invariant/no-panic evidence; nightly
ASan coverage-guided fuzzing remains the authoritative CI gate.

After adding ZIP WavPack method 97 and hardening the decoder-only local fork,
the separately locked fuzz package passed formatting, warning-denied
all-target/all-feature Clippy, and both deterministic generator tests. A fresh
stable-built `archive_formats` binary then completed 10,000 executions from an
empty corpus in 106 seconds with seed `970203`, no failure, and 39 MiB reported
RSS. Every iteration required exact valid XZ, WavPack, and PPMd extraction;
nonempty inputs also selected the method-specific mutation and strict-prefix
paths. The runner reported missing sanitizer hooks and no coverage
instrumentation on this stable host, so this is finite invariant/no-panic
evidence only. The configured nightly AddressSanitizer coverage-guided run
remains authoritative.

After adding the ZIP JPEG method-96 decoder, the separately locked fuzz package
again passed formatting, warning-denied all-target/all-feature Clippy, and both
deterministic generator tests. The selector-throttled method-96 path requires
byte-exact extraction of the provenance-complete WinZip fixture, then exercises
a selected payload mutation and strict prefix without making the 3,155-byte
payload dominate every iteration. A fresh stable-built `archive_formats`
binary completed 10,000 seedless executions in 9 seconds with seed `960216`,
no failure, and 43 MiB reported RSS. The runner reported missing sanitizer
hooks and no coverage instrumentation on this stable host, so this remains a
finite invariant/no-panic check; the configured nightly AddressSanitizer
coverage-guided run remains authoritative.

## 2026-09-21 Rust 1.98.1 hot-path gate

The production changes are reachable through the existing `stream_formats`,
`archive_formats`, `decoding`, and `volumes` targets. The ordinary
property/prefix/corruption suites remain the primary exact assertions for `.Z`
code-window boundaries, 7z member/folder CRC finalization, and path/volume
reads. Benchmark fixtures were not promoted to trusted seeds merely because
they were performance inputs.

Cargo-fuzz 0.13.2 and `nightly-2026-09-01` completed 10,000 seedless,
coverage-guided AddressSanitizer executions for every target with no crash,
sanitizer finding, timeout, or retained crash artifact. After the measured
LZMA hot-loop tuning, the affected `decoding` and `archive_formats` binaries
were rebuilt and each completed another 10,000 executions; the table records
those final runs for those two targets:

| Target | Coverage counters | Feature counters | Retained corpus | RSS | Time |
| --- | ---: | ---: | ---: | ---: | ---: |
| `path_validation` | 123 | 260 | 81 / 1,178 bytes | 41 MiB | <1 s |
| `header_envelope` | 131 | 212 | 14 / 175 bytes | 42 MiB | <1 s |
| `next_header` | 581 | 892 | 98 / 632 bytes | 48 MiB | <1 s |
| `validated_graph` | 728 | 1,047 | 23 / 94 bytes | 63 MiB | <1 s |
| `decoding` | 6,586 | 13,871 | 557 / 3,179 bytes | 329 MiB | 16 s |
| `volumes` | 1,284 | 2,020 | 55 / 736 bytes | 98 MiB | 1 s |
| `stream_formats` | 875 | 1,257 | 72 / 730 bytes | 351 MiB | 2 s |
| `archive_formats` | 4,694 | 10,456 | 568 / 1,850 bytes | 347 MiB | 1,049 s |

These RSS values are fuzzer-process observations, not product memory bounds.
The separately locked fuzz package also passed its all-binary compile, both
deterministic generated-profile tests, and cargo-deny advisory, ban, license,
and source checks. Unlike the older stable-host observations above, this is the
configured nightly ASan smoke gate rather than a no-instrumentation fallback.
