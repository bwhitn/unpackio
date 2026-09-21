# Benchmark results

## 2026-09-21 Rust 1.98.1 archive-lifecycle matrix

The Rust 1.98.1 optimization pass compared the unchanged source revision
`e275e468c05004e2183c3cd5f043ab5f0b1e8a48` with the tree published by the
completion revision containing this section. Both sides used the same generated
fixture directory, Rust 1.98.1 (`48a229cea`, LLVM 22.1.8), release settings,
CPython 3.12.10, and macOS 26.5.2 x86-64 host (8-core 2.3 GHz Intel, 16 GiB).
The fixture manifest SHA-256 is
`e2e52fb27dbab2b7ef1ca2e3211e94af298e63c0edf0e6f88b609a5168ea5025`.

`benchmarks/generate_fixtures.py` creates the 41-file matrix: solid,
encrypted, split-volume, and every stock-7zz-authorable supported 7z coder or
filter; mixed and advanced ZIP; RPM, CPIO, Debian, and ARJ; and LZ4,
Zstandard, and Unix `.Z` streams. `benchmarks/run_release.py` recorded 111
native operation rows, and `benchmarks/run_python_release.py` recorded 89 rows
through an installed ABI3 wheel. Each published value is the median of five
fresh-process samples after a verified warmup. The reports include in-process
and process wall time, user/system CPU, peak RSS, block I/O, input/output bytes,
write callbacks, API-visible owned-output allocations, deterministic work
units where available, cancellation latency, and binary/wheel size and hashes.
The commands and interpretation rules are in `benchmarks/README.md`.

Selected installed-wheel medians show the intended lifecycle effects. Negative
percentages are faster. Tiny sub-millisecond rows and individual decoder rows
remain sensitive to process launch, run order, and thermal state; they are
retained in the complete reports and are not used to claim a universal decoder
speedup.

| Fixture and operation | Baseline | After | Change | Writes, baseline to after |
| --- | ---: | ---: | ---: | ---: |
| Solid 7z callback | 27.553 ms | 27.885 ms | +1.2% | 16 to 16 |
| Solid 7z batch | 37.037 ms | 36.679 ms | -1.0% | 1,024 to 512 |
| Mixed ZIP/ZIPX path inventory | 0.434 ms | 0.318 ms | -26.6% | 0 to 0 |
| RPM batch | 1.158 ms | 0.834 ms | -28.0% | 1,024 to 512 |
| CPIO writer | 0.042 ms | 0.036 ms | -15.8% | 32 to 16 |
| Debian batch | 0.852 ms | 0.555 ms | -34.9% | 1,025 to 513 |
| ARJ batch | 10.877 ms | 10.586 ms | -2.7% | 1,024 to 512 |
| LZ4 callback | 2.082 ms | 1.685 ms | -19.1% | 1,024 to 512 |
| Zstandard callback | 2.027 ms | 1.739 ms | -14.2% | 1,024 to 512 |
| Unix `.Z` writer | 169.848 ms | 37.069 ms | -78.2% | 218,606 to 512 |
| WinZip JPEG callback | 9.441 ms | 8.388 ms | -11.2% | 2 to 1 |
| Split 7z path verification | 36.713 ms | 36.138 ms | -1.6% | 0 to 0 |
| Encrypted 7z callback | 160.313 ms | 153.191 ms | -4.4% | 16 to 16 |

The deterministic counters are the stronger acceptance evidence. All completed
paired native rows produced identical decoded byte and work-unit totals; only
in-flight cancellation work varies with the trigger schedule. All API-visible
owned-output allocation counts stayed equal, and the affected 4 KiB delivery
paths halved their write counts while retaining 4 KiB work and cancellation
checkpoints. Unix `.Z` callback delivery fell from 218,606 writes to 512 per
Python operation. Installed-wheel peak RSS for the selected rows remained
within normal process-level variation; for example `.Z` writer RSS was
16,785,408 versus 17,010,688 bytes. Cached-input block I/O was zero in the
published rows. Triggered cancellation returned in approximately 1.4--1.6 ms,
including the benchmark's 1 ms trigger delay; pre-cancelled operations retained
their immediate typed-error path.

| Artifact | Baseline bytes | After bytes | Change |
| --- | ---: | ---: | ---: |
| Native benchmark harness | 1,967,312 | 1,987,776 | +1.04% |
| macOS x86-64 ABI3 wheel | 1,068,819 | 1,075,348 | +0.61% |
| Installed native extension | 2,250,184 | 2,262,464 | +0.55% |

The baseline and after wheel SHA-256 values are respectively
`3aa7973901eca953f768ca6dd95d0c9ac7000ff18f1975dcfd515f2ac4665bd5`
and `d8de208abb97a59ffe4acbf2a541ca57b5e4e4c07cacc7ec76c339a080e252b1`.
The complete native baseline/after report hashes are
`326c8641024b8bcc9dfcc53f951b568cc973a6266f9a70e800e2d5f230efccb1`
and `61ea467ef6d029fc214cff5634e6d15bfedae2081a2ea5bbdb2357d797804e17`;
the Python report hashes are
`02aabb7f87d149adbd1c3917f8dd1caac65267a3ba94d3950e02698db99bfd7c`
and `bf3b9e56937b43339471259c81bc93360326e0fbd5e3d1a03ba47036e29e711b`.

Symbolized release sampling covered container traversal, solid state, every
admitted decoder family, encryption/KDF, integrity work, volumes, delivery,
batching, and Python projection. It identified Unix `.Z` bit-at-a-time input
and per-byte delivery as the clearest project-owned hot path; that reader now
uses a checked little-endian byte window and an 8 KiB delivery buffer. Public
archive and stream delivery uses 8 KiB writes without weakening the independent
4 KiB control cadence. Whole-folder 7z extraction transfers ownership instead
of copying where the requested range permits, and partial ranges perform one
checked copy. The JPEG arithmetic-model index was made explicitly inline after
alternating samples confirmed the code-layout win. The exact-toolchain audit
also caught a ThinLTO layout regression in solid LZMA2: forcing the measured
probability/tree/literal/length helpers inline and precomputing invariant
literal masks reduced a repeatable approximately 20% paired slowdown to about
2% in seven alternating 100-iteration pairs; the complete five-process matrix
then measured solid callback and verification at -0.2% and -3.5% natively.
Profiles otherwise remained dominated by the admitted codec implementations
(PPMd, Deflate64, BZip2, LZ4, and Zstandard) or by SHA-256 KDF work, so no
speculative crypto, CRC, volume, or PyO3 rewrite was adopted.

Rust 1.98's byte-endian UTF-16 conversion helpers were evaluated but not used:
archive names are exact `[u16]` code units that may include unpaired surrogates,
and the existing conversion plus raw-unit preservation is the required format
and path-policy contract. `PROVENANCE.md` records that decision. No benchmark
result relaxed a size, work, cancellation, checksum, password, or path-policy
boundary.

## Historical results

Phase 7 retains the Phase 6 opt-in release-mode benchmark for natural-order
caller-owned sink extraction of the solid `lzma2.7z` reference fixture.
Extraction decodes its folder once, checks every member CRC before the sink
finalizes that member, and checks the folder CRC before delivery. Parsing/opening and one correctness
warmup occur outside the timed loop.

The statements below are retained as contemporaneous history. References to a
missing timing claim or a future lifecycle matrix were accurate for those
snapshots and are superseded by the 2026-09-21 matrix above.

| Date | Commit | Benchmark | Result | Peak memory | Notes |
| --- | --- | --- | --- | --- | --- |
| 2026-07-18 | Pre-commit Phase 1 snapshot | N/A | Not run | Not measured | Foundation only |
| 2026-07-18 | Pre-commit Phase 2.1 snapshot | Header envelope | Not benchmarked | No archive-derived buffer allocation | Correctness/fuzz review unit only |
| 2026-07-18 | Pre-commit Phase 2 snapshot | Parser/model amplification | 100,000 empty entries accepted; 100,001 rejected | Not measured | Pass/fail bounded-allocation regression; not a performance claim |
| 2026-07-18 | Pre-commit Phase 3 snapshot | Natural-order solid `Archive::extract_entries_to`, `lzma2.7z`, 50 timed iterations | 36,054 decoded bytes/iteration; 0.035271 s total; 48.742 MiB/s | Not measured | Counting sink correctness warmup passed; one solid folder decoded per iteration; no filesystem I/O in timed loop |
| 2026-07-18 | Pre-commit Phase 4 snapshot | Natural-order solid `Archive::extract_entries_to`, `lzma2.7z`, 50 timed iterations | 36,054 decoded bytes/iteration; 0.034955 s total; 49.183 MiB/s | Not measured | Same reproducibility workload after codec/crypto/volume integration; counting sink correctness warmup passed; one solid folder decoded per iteration |
| 2026-07-18 | Pre-commit Phase 5 snapshot | Natural-order solid `Archive::extract_entries_to`, `lzma2.7z`, 50 timed iterations | 36,054 decoded bytes/iteration; 0.038949 s total; 44.139 MiB/s | Not measured | Same reproducibility workload after remaining-method integration; counting sink correctness warmup passed; one solid folder decoded per iteration |
| 2026-07-18 | Pre-commit Phase 6 snapshot | Natural-order solid `Archive::extract_entries_to`, `lzma2.7z`, 50 timed iterations | 10 entries; 36,054 decoded bytes and 92,896 deterministic work units/iteration; 0.042591 s total; 40.364 MiB/s | 1,359,872-byte direct-process peak RSS; 8,184-byte retained archive payload account; one 36,054-byte folder output | Direct release binary under macOS `/usr/bin/time -l`; correctness warmup passed; every timed iteration matched byte and work counts |
| 2026-07-18 | Pre-commit Phase 7 snapshot | Python FFI | Not benchmarked | Not measured | Installed-wheel test verifies that another Python thread advances during 8 MiB Copy verification; this is a GIL-detachment correctness test, not a throughput or memory result |
| 2026-07-21 | Uncommitted Python batch snapshot | Python natural-order batch adapter | Not benchmarked | Caller-retained Python buffers not measured | Installed-wheel functional test proves one shared work budget and a batch work cost below two random-access solid-folder decodes; no new decoder path was added |
| 2026-07-21 | Uncommitted standalone-stream snapshot | LZ4, Zstandard, and Unix `.Z` extraction | Not benchmarked | Decoder dictionaries/windows are preflighted; process peak not measured | Exact native-tool differentials and bounded-memory tests are functional evidence only, not throughput measurements |
| 2026-07-21 | Uncommitted release-profile audit | macOS x86-64 CPython ABI3 wheel | ThinLTO/O3 retained; 719,812-byte wheel | 1,424,240-byte native extension before installation metadata | FatLTO/O3 saved 2.0% but regressed Unix `.Z`; FatLTO/Oz saved 19.2% but materially regressed every measured decoder |
| 2026-07-21 | Uncommitted CPIO/Debian/ARJ snapshot | Optimized macOS x86-64 `cp39-abi3` wheel packaging | 964,108-byte Python-only wheel; 23 installed-wheel tests passed | Process peak not measured | No console entry point or Python runtime dependency; includes ZIP/RPM, three new readers, ARJ decoder dependency, fixtures' required notices, and all existing formats; a size observation, not a throughput benchmark |
| 2026-09-14 | Superseded ZIP XZ method-95 snapshot | Optimized macOS x86-64 `cp39-abi3` wheel packaging | 943,934-byte wheel; 24 installed-wheel tests passed | Process peak not measured | This initial snapshot used the dependency's aggregate XZ reader; the final allocation audit replaced it with the in-tree fallibly allocating LZMA2 path and disabled that dependency feature. The unrelated 7z release benchmark compiled but skipped because `UNPACKIO_7Z_TESTDATA` was unset; no ZIP throughput claim |
| 2026-09-14 | Uncommitted ZIP XZ/PPMd method-95/98 completion snapshot | Optimized macOS x86-64 `cp39-abi3` wheel packaging | 984,218-byte wheel; 26 installed-wheel tests passed | Process peak not measured | The source distribution rebuilt into a separately hashed 984,299-byte wheel and passed the same installed suite. The natural-order 7z release benchmark compiled warning-free and again skipped without `UNPACKIO_7Z_TESTDATA`; the optimized PPMd restoration-pressure correctness matrix passed, but no ZIP timing or peak-memory claim is made |
| 2026-09-15 | Uncommitted ZIP WavPack method-97 completion snapshot | Optimized macOS x86-64 `cp39-abi3` wheel packaging | 1,024,211-byte direct wheel; 27 installed-wheel tests passed | Per-block working storage is preflighted; process peak not measured | Ten official-WavPack-generated exact-output profiles passed; the 428,382-byte sdist rebuilt to a separately hashed 1,024,276-byte wheel that passed the same suite. The natural-order benchmark compiled and explicitly skipped without `UNPACKIO_7Z_TESTDATA`; no WavPack throughput claim |
| 2026-09-16 | Uncommitted ZIP JPEG method-96 completion snapshot | Optimized macOS x86-64 `cp39-abi3` wheel packaging | 1,060,797-byte direct wheel; 28 installed-wheel tests passed | Probability models and slice buffers are aggregate-preflighted; process peak not measured | The 474,488-byte sdist rebuilt to a separately hashed 1,060,884-byte wheel that passed the same suite. The natural-order benchmark compiled and explicitly skipped without `UNPACKIO_7Z_TESTDATA`; no JPEG throughput claim |

The exact Git object for these historical measurements was not recorded. The
`Pre-commit` labels preserve that limitation; the rows must not be attributed
to merge commit `77c2176` or treated as fresh post-merge measurements.

Benchmark context:

- archive SHA-256:
  `15934a5ff1325d4608f9b9c63b1a6d110957566fbea4f9e12c60864b5b7a684f`;
- archive size: 6,110 bytes; output size: 36,054 bytes;
- command: `UNPACKIO_7Z_TESTDATA=<audited>/testdata
  UNPACKIO_BENCH_ITERATIONS=50 cargo bench -p unpackio --bench
  natural_order_solid`;
- Rust: 1.97.0 (`2d8144b78`), release profile, target
  `x86_64-apple-darwin`;
- host: Intel Core i9-9880H at 2.30 GHz, 16 GiB RAM;
- sampling: one untimed verified extraction warmup followed by one
  50-iteration wall-time sample; Phase 6 peak RSS used the already-built
  release benchmark binary directly under `/usr/bin/time -l`;
- limits: `Limits::default()` and an unlimited abstract work budget. Byte,
  dictionary, count, and recursion limits remain active.

The Phase 6 account reports 6,110 owned input bytes, 2,074 validated metadata
bytes, no password bytes, and 8,184 retained archive payload bytes. This solid
fixture has one 36,054-byte decoded folder output, which is retained only for
the current extraction iteration. The 1,359,872-byte RSS measurement is the
whole benchmark process and therefore includes executable/runtime/allocator
state that is deliberately outside archive payload accounting.

Complexity correctness does not depend on the timing sample. The unit
regression constructs 10,000 zero-size substreams and gives verification,
natural-order sink extraction, and last-member range discovery their exact
checked work allowance. Natural-order extraction consumes `2n + 3` work units,
finishes all `n` entries, advances one substream cursor, and decodes its folder
once; an accidental nested rescan exhausts the budget. Random access remains
documented separately because selecting members independently can re-decode a
solid folder.

This microbenchmark is a reproducibility baseline, not a statistically robust
performance claim. The current decoder retains a complete bounded folder
output, so this result does not claim constant-memory streaming.

The Phase 7 adapter, including Python `extract_entries_to`, calls the same
natural-order Rust operations and introduces no alternate parser or decoder.
The batch test measures minimum accepted work allowances only as a
deterministic complexity assertion: its allowance is greater than either
single member and less than the sum of two random-access extractions. It is not
a timing or throughput result. Writer/callback time, Python-owned buffers, and
objects retained by a caller are outside the core benchmark and resource
account. A future Python benchmark must separately report native decoder time,
callback overhead, chunk count, interpreter version, free-threaded/GIL mode,
and Python-owned peak memory. The functional detachment regression is not used
as performance evidence.

The standalone stream API likewise has no timing claim yet. Its tests prove
checked frame/code traversal, bounded output, and preflight of LZ4 working
memory, Zstandard windows, and the complete Unix `.Z` prefix/suffix/expansion
tables. The native LZ4, Zstandard, and `compress` comparisons record exact
bytes and hashes in `CORPUS.md`, but they are not benchmarks. A future result
must separately report compressed/output sizes, frame or code characteristics,
checksum mode, decoder window/dictionary accounting, peak RSS, and sink cost.

The ZIP, RPM, CPIO, Debian, and ARJ readers likewise have no throughput claim
yet. ZIP and ARJ own bounded compressed input and temporarily materialize one
verified entry before caller output. RPM owns one complete bounded decoded CPIO
payload for the archive lifetime, reported by `retained_payload_bytes`; repeated
entry access therefore does not repeat payload decompression. Standalone CPIO
retains its source, while Debian retains its source and both bounded decoded
tar images. Generated tests prove the limit and integrity boundaries but are
not benchmarks. Any future result must report container/method/encryption,
entry count, compressed and decoded bytes, retained archive state, temporary
decoder memory, work allowance, sink cost, and whether package/member integrity
was fully verified.

For ZIP XZ method 95, preflight walks the complete Stream/Block/Index layout
before decoding, then materializes and checks each bounded Block before joining
the verified member. The new tests establish exact output, work/cancellation,
dictionary/output limits, and sink-finalization behavior; the 10,000-run fuzz
smoke and 7zz differential are also correctness evidence, not performance
measurements. A future ZIP XZ benchmark must report Block count and sizes,
filter chain, Check type, LZMA2 dictionary, Stream Padding, ZIP encryption,
compressed/output bytes, work units, temporary Block/member allocation, and
sink cost.

ZIP JPEG method 96 likewise has no throughput claim. It temporarily retains
the reconstructed member, one fixed 28,328-bin probability model, and bounded
slice buffers; metadata LZMA state is not live with slice decoding. Tests prove
byte-exact WinZip reconstruction, aggregate dictionary/header/frame/output/work
limits, cancellation, table validation, two encryption wrappers, and
integrity-before-sink behavior. The external oracle and selector-throttled fuzz
path are correctness evidence only. A future benchmark must report JPEG
dimensions, precision, components/sampling, scan and slice topology, metadata
bundle compression, compressed/output bytes, model/slice/output allocations,
work units, encryption wrapper, sink cost, and peak RSS.

ZIP WavPack method 97 likewise has no throughput claim. Its adapter preparses
the complete stream, then calls the decoder one bounded block at a time while
temporarily retaining the verified ZIP member output. Tests establish exact
integer/float and one-to-sixteen-channel reconstruction, wrapper recovery,
working-memory/output/work/cancellation limits, two checksum layers, and
sink-finalization behavior; the official WavPack differential and fuzz smoke
are correctness evidence only. A future benchmark must report block and
channel topology, sample format/rate/count, wrapper bytes, compressed and
decoded sizes, decoder/output allocations, work units, encryption wrapper,
sink cost, and peak RSS.

ZIP PPMd method 98 likewise has no throughput claim. The release-only pressure
gate forces Restart, Cutoff, and Freeze restoration with an order-16, 1 MiB
model and requires deterministic exact output, while ordinary tests establish
work/cancellation, model/output limits, end-marker/input exactness, and
integrity-before-sink behavior. A future timing result must report order,
suballocator size, restoration mode and count, compressed/output bytes, model
and temporary member allocation, work units, encryption wrapper, sink cost,
sample distribution, and peak RSS. A small easily predicted PPMd input is not
a representative throughput benchmark, and a faster decoder may not omit the
end-marker, exact-consumption, size, or CRC gates.

## Release compilation profile audit

The 2026-07-21 wheel audit compared clean, stripped `cp39-abi3` builds on the
same x86-64 macOS host. All profiles retained one codegen unit, checked integer
overflow, and unwind semantics required by the Python panic boundary. The
benchmark repeatedly verified 16 MiB all-zero fixtures authored temporarily by
stock `7zz` 26.02, LZ4 1.10.0, Zstandard 1.5.7, and macOS `compress`; fixtures
and build targets remained outside the repository.

| Profile | Wheel bytes | LZMA2 | LZ4 | Zstandard | Unix `.Z` |
| --- | ---: | ---: | ---: | ---: | ---: |
| ThinLTO, `opt-level=3` | 719,812 | 134.83 MiB/s | 6,060.25 MiB/s | 3,281.28 MiB/s | 154.02 MiB/s |
| FatLTO, `opt-level=3` | 705,407 | 142.64 MiB/s | 6,011.08 MiB/s | 3,476.72 MiB/s | 132.91 MiB/s |
| FatLTO, `opt-level="z"` | 581,487 | 88.37 MiB/s | 2,634.88 MiB/s | 2,711.34 MiB/s | 91.98 MiB/s |

Each throughput is the median of three samples after a warmup. LZMA2 and Unix
`.Z` used eight verifications per sample, LZ4 used 100, and Zstandard used 50.
The highly compressible fixture makes this a compiler-profile comparison, not
a general decoder-performance claim. ThinLTO/O3 remains the release profile:
FatLTO's 2.0% wheel reduction does not justify its observed 13.7% Unix `.Z`
regression, while optimizing for size caused substantially broader slowdowns.
Cargo and maturin both strip release symbols; `panic="unwind"` and overflow
checks remain deliberate security requirements and are not size-tuning knobs.

## Continuing methodology

Future optimization work extends the statistically sampled lifecycle matrix
rather than replacing it with a single-codec microbenchmark. Each published
result records the source revision, Rust version, target triple, CPU, RAM,
fixture-manifest hash, method graph, compressed and output bytes, file count,
warmup/sample method, wall and CPU time, peak RSS, block I/O, delivery and
allocation counters, work units, cancellation latency, artifact sizes, and
configured limits.

Benchmark inputs include small-file-heavy and large-file solid archives,
non-solid controls, random versus natural order, encrypted and unencrypted
chains once AES exists, and five-volume inputs once admitted. Correct output and
CRC verification run before timing. A faster failure or skipped CRC is never a
valid result.

Bounded-memory tests are separate pass/fail gates and verify that declared
dictionary/property/output sizes are rejected before allocation. Benchmark
regressions do not justify weakening defaults.
