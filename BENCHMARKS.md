# Benchmark results

## Current result

Phase 7 retains the Phase 6 opt-in release-mode benchmark for natural-order
caller-owned sink extraction of the solid `lzma2.7z` reference fixture.
Extraction decodes its folder once, checks every member CRC before the sink
finalizes that member, and checks the folder CRC before delivery. Parsing/opening and one correctness
warmup occur outside the timed loop.

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

## Expanded future methodology

Future work adds statistically sampled natural-order solid extraction and peak
RSS benchmarks as the current full-folder-buffered callback/sink pipeline
evolves. Each published result records commit, Rust version, target triple,
CPU, RAM, archive hash, method graph, compressed and output bytes, file count,
warmup/sample method, wall throughput, peak RSS, and configured limits.

Benchmark inputs include small-file-heavy and large-file solid archives,
non-solid controls, random versus natural order, encrypted and unencrypted
chains once AES exists, and five-volume inputs once admitted. Correct output and
CRC verification run before timing. A faster failure or skipped CRC is never a
valid result.

Bounded-memory tests are separate pass/fail gates and verify that declared
dictionary/property/output sizes are rejected before allocation. Benchmark
regressions do not justify weakening defaults.
