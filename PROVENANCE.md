# Provenance

## Pinned behavioral reference

- Project: `github.com/bodgit/sevenzip`
- Commit: `dcfc72a0ee9f527c55521f44ffdf1c31b732e256`
- Tag at commit: `v1.6.5`
- Commit date: 2026-07-11
- Copyright: Copyright (c) 2020, Matt Dainty
- License: BSD-3-Clause, reproduced verbatim in
  `LICENSES/BSD-3-Clause-bodgit-sevenzip.txt`
- Inspection date: 2026-07-18

The exact commit was cloned to a temporary inspection directory and checked out
detached. The audit covered `reader.go`, `types.go`, `struct.go`, `register.go`,
all `internal/*` decoder wrappers/filters, Go tests, git history relevant to
panic and resource-limit fixes, `go.mod`, `LICENSE`, and `testdata`.
The unmodified checkout passed `go test ./...` with Go 1.26.5 on macOS.

Phase 1 Rust source is original work created for this repository from the
requirements and format-oriented design analysis. No Go parser, graph,
decoder, filter, or cryptographic source was copied, transliterated, or adapted
in Phase 1. The upstream notice is included now so future adaptations cannot be
merged without it.

Phase 2 was implemented after inspecting the pinned Go fixed header, variable
integer, header grammar, stream/file records, file mapping, and known decoder
property readers. The adaptation ledger below treats that influence
conservatively as BSD-3-Clause adapted work even though the Rust control flow,
error model, bounded readers, validation boundary, graph analysis, checked
conversions, limit checks, cancellation, work accounting, and public model are
independently designed. No Go decoder loop, filter, cryptographic primitive, or
password cache was copied or adapted during Phase 2.

Phase 3 adapts the pinned Go Delta and branch-filter implementations and the
pinned Go BCJ2 implementation into checked, safe Rust. LZMA and LZMA2 are
adapted from the independently maintained BSD-3-Clause Go module
`github.com/ulikunitz/xz` v0.5.15, which is the exact version pinned by the Go
reference. The module proxy origin record resolves that tag to commit
`7eee8a8a405163554a9accec7b9402ee21400769`, release time
2025-08-29T05:26:47Z, and module sum
`h1:9DNdB5s+SgV3bQ2ApL10xRc35ck0DuIX/isZvIk+ubY=`. Its BSD-3-Clause notice is
reproduced in `LICENSES/BSD-3-Clause-ulikunitz-xz.txt`.

Phase 4 adapts the 7z AES property layout and KDF serialization from the
pinned Go AES wrapper, while delegating AES-256, CBC, and SHA-256 primitives to
the identified RustCrypto crates. It adapts the pinned Go-specific 16-byte
Brotli framing test, but delegates Brotli, raw Deflate, BZip2, LZ4 frame, and
Zstandard frame algorithms to the exact permissively licensed Cargo crates in
`DEPENDENCIES.md`. The PPMd7 variant-H decoder is a safe, fallible adaptation
of `github.com/stangelandcl/ppmd` v0.1.1, tag commit
`e7008704a75379d49824363eca5d87e947b2d9fa`, licensed MIT. Its notice is
reproduced in `LICENSES/MIT-stangelandcl-ppmd.txt`. No PPMd source from 7-Zip,
p7zip, or an SDK was inspected.

Phase 5 adapts the Deflate64 block grammar, canonical Huffman behavior,
64 KiB history rules, and length/distance tables from Apache Commons Compress
`HuffmanDecoder.java` at commit
`9499ba8ed3c6dce1275ac3d0471afa414b23daff` (2026-07-17), Apache-2.0. The
Apache notice is preserved in `NOTICE`, and the repository's
`LICENSES/Apache-2.0.txt` supplies the license text. The Rust state machine, bounded bit
reader, stack tables, exact-input rule, allocation strategy, checked history,
and operation control were rewritten for this project.

Phase 6 public API curation, entry metadata accessors, retained-resource
accounting, examples, tests, CI policy, and documentation are original Rust
work licensed MIT. They import no algorithm and add no decoder.
The `unstable-internals` feature exposes the already recorded Phase 2 model
only to repository tests/fuzzers; it does not change the provenance or license
of that model.

Phase 7's Python adapter, exception mapping, callback/volume bridges, type
stubs, tests, packaging, and CI are original work licensed MIT.
They call only the stable Rust API and import no archive algorithm, decoder,
cryptographic construction, parser, graph, or path-policy source. The binding
was designed against the public PyO3 0.29 and maturin 1.13 documentation; no
PyO3 or maturin source was copied or adapted. The Python Copy-archive test
builder is an original deterministic boundary fixture and makes no new codec
compatibility claim.

The 2026-07-21 PPMd interoperability rule is original safe Rust based on the
task's externally supplied behavioral description of py7zr 1.1.3: retain the
canonical five-byte order/memory record, and accept a seven-byte record only
when its final two reserved bytes are zero. No py7zr source, decoder code, or
archive fixture was inspected, copied, translated, vendored, or added as a
dependency. `crates/unpackio/src/coder_properties.rs` centralizes that rule for
model validation and decoding; the PPMd algorithm remains solely the already
admitted `stangelandcl/ppmd` adaptation. Generated tests wrap the existing
stock-`7zz` packed PPMd vector with both property records and original hostile
variants.

The Python natural-order batch adapter, structural sink protocol, generated
solid Copy fixtures, type stubs, and wheel-matrix changes are original project
work licensed MIT. They delegate graph execution, folder reuse,
work/cancellation accounting, and CRC finalization to the existing stable core
API. No downstream application or py7zr code was inspected or incorporated.
The workflow design uses the public documentation for the already pinned
maturin action and GitHub-hosted ARM64 runner labels; neither is runtime code.

The incomplete Brotli negative vector is original test derivation: it removes
the terminal byte from the already recorded ten-byte complete `hello\n`
`brotli-decompressor` vector. This models the externally described
flush-without-finish behavior without copying a py7zr stream or implementation.
The complete vector retains its BSD-3-Clause OR MIT upstream provenance; the
one-byte truncation and regression assertions are MIT project
work.

The 2026-07-21 standalone LZ4 and Zstandard stream layer is original checked
Rust built from the official format documents pinned below and the public APIs
of the already admitted `lz4_flex` 0.14.0 and `ruzstd` 0.8.1 decoders. The
layout validators, frame table, limit accounting, checksum boundary, output
API, fuzz target, Python adapter, and tests are MIT. No LZ4 or
Zstandard implementation source was copied into this repository. LZ4 header
checksums use `twox-hash` 2.1.4; block/content decoding and checksums remain in
`lz4_flex`. Zstandard content-checksum calculation is enabled through
`ruzstd`'s `hash` feature and its existing `twox-hash` dependency.

The safe Rust Unix `compress` decoder adapts the `.Z` header, grouped
least-significant-bit-first code reader, variable-width transition,
CLEAR-reset, prefix/suffix dictionary, and special next-code expansion
semantics from NetBSD `usr.bin/compress/zopen.c` at commit
`bd9f26305380f03b3821f55381448a82827d6749`. The source is BSD-3-Clause,
Copyright (c) 1985, 1986, 1992, 1993 The Regents of the University of
California; its exact notice is reproduced in
`LICENSES/BSD-3-Clause-netbsd-zopen.txt`. Rust-owned storage, checked arithmetic,
fallible allocation, output/work/cancellation controls, typed errors, and FFI
integration are original MIT work. GPL `ncompress`, official
7-Zip, and p7zip source were not inspected or used.

The IA64, ARM Thumb, and RISC-V instruction layouts and bijective decoder
semantics were independently expressed in checked Rust after inspecting the
corresponding liblzma filter descriptions in XZ Utils commit
`f3b5688159c60495f48db3942a36509671dfce89` (2026-07-03). Those three files
are 0BSD. XZ is an algorithm reference only: it is not a dependency, no C code
is vendored or linked, and the new Rust source is licensed MIT.
Swap2 and Swap4 are original checked byte-group reversals based on the method
definition and black-box oracle behavior. No official 7-Zip or p7zip source
was obtained or inspected for any Phase 5 method.

No official 7-Zip or p7zip source was obtained, opened, or translated for this
work. The secondary module's `doc/LZMA2.md` describes format behavior by
comparison with the LZMA SDK; the Rust work used the identified BSD Go source
files and external behavior, not SDK source. The Rust implementation replaces
the source buffering, indexing, integer conversion, allocation, and error paths
with checked Rust operations, explicit output/dictionary limits, and operation
control.

The installed `7zz` 26.02 executable was used only to inspect/test corpus
behavior. No official 7-Zip or p7zip source was obtained or inspected.

The 2026-07-19 external-folder follow-up adapts only the serialized external
flag and `DataIndex` grammar from the pinned Go `types.go:readUnpackInfo` at
`dcfc72a0ee9f527c55521f44ffdf1c31b732e256`, under its BSD-3-Clause license.
That Go revision returns a TODO error for the feature, so the bounded staged
parse/decode/reparse architecture is original Rust work. Black-box tests with
the `7zz` 26.02 executable established that `DataIndex` addresses decoded
AdditionalStreamsInfo folder outputs rather than their logical substreams;
one- and two-folder synthetic archives were accepted. No oracle source code was
obtained, inspected, copied, or adapted.

The 2026-07-19 capability-probe suite is original integration-test and fixture
construction code. Its CRC-correct Copy candidates reuse the already recorded
7z container grammar; its classifications come only from executing the stock
`7zz` 26.02 binary and the public Rust API. No oracle source, SDK, SFX stub, or
binary fixture was inspected, copied, adapted, or retained. Deterministic
candidate hashes and the limits of each behavioral inference are recorded in
`CAPABILITY_PROBES.md`.

The Windows CI extension uses the official `ip7z/7zip` 26.02 release asset
`7z2602-x64.exe`, whose release metadata reports SHA-256
`6745fa76dc2ea031596d8678f6f6b99c3c1b435b4164a63485adbbc7b8d82ef0`.
The workflow verifies that digest before black-box execution and retains
neither the installer nor an authored archive. The test-only executable-name
override now selects the oracle for the capability, generated core/property,
and Phase 5 harnesses. Its Windows/standalone banner classification and command
selection are original Rust test code licensed MIT; no oracle
source was inspected or adapted.

The Linux capability job uses the official `ip7z/7zip` 26.02 release asset
`7z2602-linux-x64.tar.xz`, whose release metadata and locally verified digest
are SHA-256
`41aaba7b1235304ab5aa0624530c67ae829496cd29e875925271efdccc28c03e`.
CI extracts only `7zz`. During this audit, the packaged
`MANUAL/cmdline/switches/sni.htm` and `sns.htm` files were read as primary
behavioral documentation: both identify storage as WIM-only. No text, binary,
source, SDK, or implementation from that package is copied or shipped. The
new Linux workflow and Rust member-byte probe are original MIT
test code.

The first checksum-pinned Linux and expanded Windows executions of that code
completed at `d1eabdf` in GitHub Actions run `29787328152`. Linux reported
matching Rust bytes for both hard-link entries, `same-file=false` after stock
extraction, successful relative-symlink restoration, and no raw-AES archive
from either authoring form. Windows passed all four generated core/property
tests and both Phase 5 tests. These are black-box execution records; no
generated archive, oracle binary, manual text, or implementation material was
retained.

The 2026-07-20 Windows-probe follow-up is original Rust and workflow code
licensed MIT. It separates project-authored security and ADS
inputs, checks the project-authored ADS bytes through the host filesystem,
authors an ordinary control archive, bounds diagnostic context, asserts the
reviewed black-box stages, and publishes structured records. It imports no
algorithm or oracle code and retains no generated archive.

The 2026-07-19 generated property matrix is original integration-test code over
the existing public and test-only validated-model APIs. Method options are sent
to the installed stock `7zz` 26.02 executable and validated only through its
black-box listing/extraction behavior plus the already documented 7z coder
properties parsed by Rust. No oracle source, SDK code, binary archive, or new
algorithm implementation was inspected, copied, retained, or redistributed.

The 2026-07-19 in-process decoder seed generator and structured mutator are
original fuzz/test code over the already recorded 7z container, coder-property,
graph, CRC, and direct AES-KDF layouts. Minimal uncompressed LZMA2, Deflate,
Deflate64, LZ4-frame, and Zstandard-frame records were independently serialized
for bounded test payloads; they are not compression APIs and are not compiled
into the runtime crates. Test-only AES-CBC encryption is delegated to the same
RustCrypto `aes` 0.9.2 and `cbc` 0.2.1 crates used by the core dependency graph,
with a fixed public fuzz password. The raw LZMA vector retains its documented
XZ Utils 5.8.3 command provenance. The BZip2 vector was produced from the
synthetic text `hello\n` by `/usr/bin/bzip2` 1.0.8. The ten-byte Brotli vector
is the `hello\n` regression in the published `brotli-decompressor` 5.0.3
`src/reader.rs`, licensed BSD-3-Clause OR MIT. The 49-byte PPMd vector was
produced from project-authored text by a black-box stock `7zz` 26.02 command;
no 7-Zip or p7zip source was inspected. Exact commands and vector hashes are
recorded in `CORPUS.md`; no complete archive, external corpus item, oracle
source, or secret was copied into the fuzz package.

## Reference observations that affect the Rust design

These are behavioral audit facts, not inherited implementation choices:

- the Go parser does not route every declared property length through an exact
  bounded child reader;
- several CRC slices use `0` as both an absent value and a possible CRC;
- folder execution follows serialized coder order rather than a separately
  validated topological schedule;
- external folder/name/time/attribute properties, StartPos, archive properties,
  and additional streams return TODO errors; anti-items are not handled;
- SFX signature search is fixed at 1 MiB;
- path volumes are discovered sequentially from `.001` until a missing suffix;
- the AES code uses a process-global LRU whose key contains the plaintext
  password and whose value contains the derived key; and
- recent upstream history includes fixes for missing unpack info, empty-reader
  initialization, fuzz panics, 32-bit/OOM counts, AES KDF work, LZMA2 dictionary
  shifts, and PPMd 32-bit behavior.

The Phase 2 panic audit tied regressions to upstream history rather than only
to issue descriptions: `10d75506fa01719e9e0f074c4e7b3c3b96f4233d`
guards a nil FilesInfo during initialization (`empty2.7z`),
`db3ba775286aa4efce8fdd1c398bf2bd4dfba37d` handles missing UnpackInfo
(`COMPRESS-492.7z`), `740fcf91a86fb010fd60a11456743e911de893f5`
adds fuzz panic defenses, and `c9e301ea8886d9c6068d8662aed751dfd324acb1`
addresses 32-bit/OOM count conversion. A separate
generated regression covers the pinned `folderReader`/File.Open path where an
unvalidated packed-input index could reach an input slice. Rust rejects each
condition while constructing the model, before any open/decoder API exists.

The Rust architecture instead uses options, pre-decoding validation, a general
graph, builder limits, exact missing-volume errors, and per-archive zeroized
password state with no global plaintext or derived-key cache.

## Adaptation ledger

Every adaptation is recorded at symbol granularity. The upstream BSD-3-Clause
notice applies to the behavioral adaptations below; original Rust additions
are offered under MIT.

| Rust file and symbol | Upstream file and symbol/lines | Commit | Nature of adaptation | License |
| --- | --- | --- | --- | --- |
| `crates/unpackio/src/bounded.rs`: `BoundedReader::read_7z_uint` | `types.go`: `readUint64` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted 7z variable-integer field interpretation; rewritten as a bounded, fallible, allocation-free Rust reader | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/parser.rs`: `parse_raw_signature_header`, `parse_archive_header` | `struct.go`: `signatureHeader`, `startHeader`; `reader.go`: `findSignature`, `Reader.init` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted signature/start-header layout, relative next-header range, CRC layers, and SFX behavior; independently redesigned with typed errors, configurable bounds, candidate isolation, checked arithmetic, cancellation, and work accounting | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/raw.rs`: raw property, folder, PackInfo, UnpackInfo, SubStreamsInfo, StreamsInfo, FilesInfo, Header parsers | `types.go`: `readBool`, `readOptionalBool`, `readCRC`, `readSizes`, `readPackInfo`, `readCoder`, `readFolder`, `readUnpackInfo`, `readSubStreamsInfo`, `readStreamsInfo`, `readFilesInfo`, `readHeader` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted serialized field ordering and ID grammar, including the external-folder flag and `DataIndex`; rewritten as borrowed Rust syntax records with bounded reads, exact outer consumption, global count/property limits, checked totals, fallible allocation, cancellation, and typed unsupported features | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/validate.rs`: file/substream mapping and inherited CRC handling | `reader.go`: `Reader.init`; `struct.go`: `streamsInfo.FileFolderAndSize`; `types.go`: `readSubStreamsInfo` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted archive-order mapping and substream semantics; replaced unchecked/raw indexing and zero sentinels with exact cardinality validation and `Option` values | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/validate.rs` and `coder_properties.rs`: LZMA2, PPMd, and AES property resource validation | `internal/lzma2/reader.go:NewReader`, `internal/ppmd/reader.go:NewReader`, `internal/aes7z/reader.go:NewReader`; py7zr 1.1.3 seven-byte behavior supplied as an external requirement | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256`; no py7zr source revision inspected | Adapted canonical property layouts and LZMA2 dictionary/AES salt-IV-KDF calculations for structural and resource-limit validation before decoder construction; the strict zero-reserved seven-byte PPMd admission is original Rust | BSD-3-Clause upstream notice; new Rust changes MIT |
| `crates/unpackio/src/decode/filters.rs`: Delta, x86 BCJ, PPC, ARM, ARM64, SPARC | `internal/delta/reader.go`; `internal/bra/{bcj,ppc,arm,arm64,sparc}.go` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted decoder transforms into checked, in-place safe Rust with bounded property parsing and cancellation/work checkpoints | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/decode/filters.rs`: BCJ2 range and four-stream decoder | `internal/bcj2/reader.go` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted range/probability and side-stream semantics; replaced stream indexing and unchecked growth with checked cursors, exact side-stream consumption, fallible allocation, and output/work limits | BSD-3-Clause upstream notice; Rust changes MIT |
| `crates/unpackio/src/decode/lzma.rs`: range/probability trees, state machine, literal/length/distance decoding, dictionary history | `github.com/ulikunitz/xz/lzma`: `decoder.go`, `decoderdict.go`, `directcodec.go`, `distcodec.go`, `lengthcodec.go`, `literalcodec.go`, `operation.go`, `prob.go`, `properties.go`, `rangecodec.go`, `state.go`, `treecodecs.go` | `v0.5.15`, commit `7eee8a8a405163554a9accec7b9402ee21400769` | Adapted algorithm/state semantics into a one-shot safe Rust decoder with checked state access, exact declared-size/EOS behavior, fallible output allocation, dictionary-distance validation, and cancellation/work checks | Ulrich Kunitz BSD-3-Clause notice; Rust changes MIT |
| `crates/unpackio/src/decode/lzma.rs`: LZMA2 control/chunk state | `github.com/ulikunitz/xz/lzma`: `header2.go`, `reader2.go` | `v0.5.15`, commit `7eee8a8a405163554a9accec7b9402ee21400769` | Adapted chunk/reset/property state and sizes; rewritten around bounded slice cursors, exact EOS/trailing-byte rules, checked sizes, and operation control | Ulrich Kunitz BSD-3-Clause notice; Rust changes MIT |
| `crates/unpackio/src/decode/ppmd.rs`: PPMd7 model, range decoder, context/state heap, and suballocator | `github.com/stangelandcl/ppmd`: `reader.go` and `internal/h7z/*.go` listed and hashed below | `v0.1.1`, commit `e7008704a75379d49824363eca5d87e947b2d9fa` | Adapted variant-H model semantics into safe Rust; every modeled address, heap access, conversion, allocation, output append, and arithmetic boundary is fallible, dictionary memory is charged before allocation, and decode loops honor cancellation/work limits | Clayton Stangeland/Adam Hathcock MIT notice; Rust changes MIT |
| `crates/unpackio/src/decode/ppmd_i.rs`: ZIP PPMd-I revision-1 model, carryless range decoder, context/state heap, and suballocator | Dmitry Shkarin `ppmdi1.rar`; public-domain `Model.cpp`, `PPMd.h`, `SubAlloc.hpp`, and Dmitry Subbotin `Coder.hpp` separately published in OpenXRay; SharpCompress's managed I1 port by Michael Bone at the exact revisions and hashes below | Original archive SHA-256 `5a559300c26949fc5dd015983bfe680fd9a32c2b4afb85320dc9b38f90f8c5d6`; OpenXRay commit `bcefa731baf3add37c33348ec709ab391a9032a2`; SharpCompress commit `e04d51176c5d87668c4c8779825342230c33aa74` | Adapted canonical variant-I revision-1 semantics and used the managed port to cross-check packed layout and control flow; pointer layouts are modeled as validated offsets, allocations and arithmetic are fallible, list traversal is bounded, and decode loops enforce input/output/dictionary/work/cancellation limits | Original authors' public-domain dedication; SharpCompress MIT notice; new Rust changes MIT |
| `crates/unpackio/src/decode/aes.rs`: property parsing, password encoding, KDF input serialization, and block truncation | `internal/aes7z/reader.go:NewReader`; `internal/aes7z/key.go:calculateKey` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted the property and KDF byte layout; replaced the global Go cache with per-archive zeroized state and bounded/checkpointed KDF work; cryptographic primitives are supplied exclusively by RustCrypto | BSD-3-Clause upstream notice; Rust changes MIT; RustCrypto crates MIT OR Apache-2.0 |
| `crates/unpackio/src/decode/codecs.rs`: optional 7-Zip Brotli header removal | `internal/brotli/reader.go:headerFrame`, `NewReader` | `dcfc72a0ee9f527c55521f44ffdf1c31b732e256` | Adapted only the private 16-byte frame recognition; all Brotli bitstream decoding is delegated to `brotli-decompressor` | BSD-3-Clause upstream notice; Rust adapter changes MIT |
| `crates/unpackio/src/decode/deflate64.rs`: bit reader, Huffman tables, block decoder, history copy | Apache Commons Compress `src/main/java/org/apache/commons/compress/compressors/deflate64/HuffmanDecoder.java` | `9499ba8ed3c6dce1275ac3d0471afa414b23daff` | Adapted the Deflate64 grammar and numeric tables into a one-shot safe Rust decoder; all input/range/arithmetic/output operations are checked, the 64 KiB resource is preflighted, allocation is fallible, and loops honor cancellation/work limits | Apache-2.0 source and notice; Rust changes MIT |
| `crates/unpackio/src/decode/phase5_filters.rs`: `decode_ia64`, `decode_arm_thumb`, `decode_riscv` | XZ Utils `src/liblzma/simple/{ia64,armthumb,riscv}.c` algorithm descriptions | `f3b5688159c60495f48db3942a36509671dfce89` | Instruction layouts and reversible address transforms independently expressed with checked slice access/conversions, explicit 32-bit wrapping address domains, and cancellation/work checkpoints; no XZ runtime code or library is shipped | Reference files 0BSD; original Rust expression MIT |
| `crates/unpackio/src/stream/unix_compress.rs`: `CodeReader`, `decode_lzw`, dictionary/width/CLEAR state | NetBSD `usr.bin/compress/zopen.c`: read-side `getcode`/`zread` behavior | `bd9f26305380f03b3821f55381448a82827d6749` | Adapted Unix `.Z` grouped code packing and LZW state into safe Rust with checked table access, pre-allocation dictionary accounting, bounded output, and cancellation/work checkpoints | NetBSD/Berkeley BSD-3-Clause notice; Rust changes MIT |

## Container primitive origin ledger

| Component | Rust origin | Algorithm/reference | Applicable license | Evidence |
| --- | --- | --- | --- | --- |
| Bounded byte reader and exact child readers | Original `crates/unpackio/src/bounded.rs` except the variable-integer row above | Rust slice and integer semantics; no external implementation copied | MIT | Unit tests cover fixed widths, exact consumption, boundary encodings, and all long-integer truncations |
| Validated archive model | Original `crates/unpackio/src/model.rs` | Project architecture and pinned-reference record semantics, subject to adaptation rows above | MIT plus upstream notice for adapted semantics | Construction is crate-private and occurs only after range/count/property/graph/mapping validation; missing CRCs and unknown sizes are options |
| General folder graph validator and scheduler | Original `crates/unpackio/src/graph.rs` | Requirements-driven directed-port model; no upstream graph algorithm copied | MIT | Generated tests cover valid chains, invalid packed indices, duplicate domains, roots, and cycles; pinned corpus validates complex graphs |
| Raw UTF-16/property validators | Original safe Rust in `crates/unpackio/src/validate.rs`, with serialized property layouts covered by the adaptation rows | Pinned Go grammar and project resource/path requirements | MIT plus upstream notice for adapted layouts | Two-pass name limits precede allocation; exact child consumption; external indices checked; raw code units retained |
| CRC-32 | Original `crates/unpackio/src/checksum.rs` | CRC-32/ISO-HDLC reflected polynomial `0xEDB88320`; table generated at compile time, with no external table or implementation copied | MIT | Standard `123456789` vector (`0xCBF43926`), empty vector, incremental equivalence, and corrupt start/next-header tests |
| Folder executor and output APIs | Original `crates/unpackio/src/execute.rs` and `archive.rs`, using the validated model | Requirements-driven linear port/binding executor, CRC-finalizing session design, caller-owned natural-order sink, and ordered reconstruction of encoded-header substreams; no 7-Zip or p7zip implementation source was consulted | MIT | Reverse-stored Copy chain test, BCJ2 corpus graph, packed/folder/member CRC regressions, reader/sink finish regressions, linear solid traversal, known/unknown entry caps, output/work/cancellation limits, generated multi-substream header accepted by stock `7zz` 26.02, and separate negative multi-folder oracle evidence |
| Stock-7zz capability-probe harness | Original `crates/unpackio/tests/capability_probe.rs` over the already recorded serialized container grammar | Project evidence rules and black-box execution of exact stock `7zz` 26.02; no oracle implementation source consulted | MIT plus the upstream notice for already adapted serialized grammar | Exact-version structured author/read/Rust results for comment candidates, alternative coder candidate, unknown sizes, raw AES main/filter authoring, link member bytes and host semantics, and platform metadata switches; Windows control, ADS readback, bounded diagnostic context, and stage-drift checks; deterministic hashes in `CAPABILITY_PROBES.md` |
| Stock-7zz method/property matrix | Original additions to `crates/unpackio/tests/generated_oracle.rs` over the already recorded coder-property grammar | Project differential-evidence rules and black-box execution of exact stock `7zz` 26.02; no oracle implementation source consulted | MIT plus the upstream notice for already adapted serialized grammar | 24 ephemeral archives; exact LZMA/LZMA2/PPMd/Delta properties, BZip2 packed headers, Deflate level distinction, filter/AES graphs, solid folder shapes, metadata, bytes, SHA-256, CRC-finalized verification, packed corruption, physical/logical truncation, CRC-correct property mutations, and resource/work/cancellation limits |
| Stock-7zz PPMd positive vector | Original test integration in `crates/unpackio/src/decode/ppmd.rs` and `fuzz/fuzz_targets/support.rs`; 49 packed bytes produced from project-authored text | Black-box `7-Zip (z) 26.02 (x64)` invocation `7zz a -t7z -m0=PPMd:o6:mem64k -mhc=off -mhe=off -bd -bb0`; no 7-Zip or p7zip source inspected | Project-authored input and original Rust test code MIT; executable output retained only as a test vector | Exact command, properties, CRC, decoded/packed/archive SHA-256 values, and non-retention record in `CORPUS.md`; exact decode, every packed prefix, corruption, dictionary/output/work, and cancellation regressions |
| In-process decoder fuzz seeds and structured mutator | Original `fuzz/fuzz_targets/support.rs`, `decoding.rs`, and `fuzz/tests/generated_seeds.rs` over already recorded serialized grammar | Project hostile-input requirements; fixed vectors and test-only primitive origins recorded above; no new decoder implementation or runtime API | MIT plus the upstream notice for adapted 7z/AES serialization; embedded Brotli vector under BSD-3-Clause OR MIT; RustCrypto crates MIT OR Apache-2.0 | 21 verified positive profiles, eight bounded mutation classes, deterministic exhaustive generator test, and fresh coverage-guided campaigns without an external corpus |
| Additional-stream processor, verifier, and external metadata resolver | Original `crates/unpackio/src/metadata.rs` and `archive.rs` orchestration over Phase 2's adapted serialized property layouts | Requirements-driven sequential decoding of validated AdditionalStreamsInfo folders, verification of every logical substream, and exact bounded application to file records; no external decoder or container implementation copied | MIT plus upstream notice for adapted layouts | Synthetic production-API external Name tests; exact/trailing-byte rejection; referenced and unreferenced packed/folder/substream CRC checks; AES password states; shared output/work/cancellation limits; crossed three-part memory volumes; and limits for decoded header/name bytes |
| Staged external-folder resolver | Original staging and orchestration in `model.rs`, `validate.rs`, `parser.rs`, `metadata.rs`, and `archive.rs`, over the adapted `types.go:readUnpackInfo` flag/`DataIndex` grammar recorded above | Project hostile-input requirements plus black-box `7zz` 26.02 behavior; the pinned Go revision does not implement resolution | MIT plus the upstream BSD-3-Clause notice for adapted serialized grammar | Production extraction with one and two AdditionalStreamsInfo folder outputs; stock-oracle acceptance of both forms; external Name reuse; exact-consumption, prefix-truncation, index, pre-decode packed-range overlap, packed/folder/substream CRC, combined count/output-limit, and encrypted password-state regressions |
| Sequential volume assembly | Original `crates/unpackio/src/volume.rs` and archive integration | Project `VolumeProvider` requirements plus the pinned reference's observed `.001` naming behavior; no provider or concatenation code copied | MIT | Memory/path providers, total-byte and volume-count preflight, cancellation/work checks between reads, exact missing suffix, six-part fixture, five-part encrypted fixture, and cross-volume packed data |
| Standalone LZ4/Zstandard layout and output session | Original `crates/unpackio/src/stream/{mod,lz4,zstandard,cursor}.rs` | Official pinned LZ4/Zstandard frame documents listed below; decoder/checksum crates listed in `DEPENDENCIES.md`; no implementation source copied | MIT; specification repositories BSD-2-Clause/BSD-3-Clause; decoder crates MIT | Generated current/legacy/concatenated/skippable/checksum frames, exhaustive small truncations, dictionary/window/frame/output/work/cancellation limits, fuzz target, and native command-line-tool differentials |
| Standalone Python stream adapter | Original `bindings/python/src/stream.rs`, stubs, and tests | Adapter over the stable `CompressedStream` API; no parsing or decoder logic duplicated | MIT | Magic/explicit opens, concrete info, path no-side-effect, bounded writer/callback output, exception identity, cancellation, and limit tests |
| Safe path and symlink metadata policy | Original `crates/unpackio/src/path.rs` and `model.rs` accessors | Project security requirements and platform path syntax; no extraction code or external implementation copied | MIT | Traversal/absolute/drive/UNC/device/NUL tests over UTF-16 and a generated `7zz -snl` symlink metadata oracle |

## Adapted source hashes

The exact public-domain PPMd-I revision-1 mirror inputs inspected for ZIP
method 98 are:

| Source file | SHA-256 |
| --- | --- |
| `Model.cpp` | `40bc27f205addf3ad249c9db92aa644a9761886315d6e5dc6ca306d5dac211aa` |
| `PPMd.h` | `586f20649e3f9ff334d58ff5338af1ec5166f75f3e6ffc96723bb3f978148cfb` |
| `SubAlloc.hpp` | `445244bcac687744c47f5cec377c89bc23b4cd43a7a40b3261124e469c45928c` |
| `Coder.hpp` | `0180aeeb2382353ed52f8a02d7c770b87a938ef4efabdb7d641a0a4dfb827dbe` |

The secondary managed-port inputs used to cross-check that adaptation are
from SharpCompress commit `e04d51176c5d87668c4c8779825342230c33aa74`
(2026-08-07), licensed MIT with the notice reproduced in
`LICENSES/MIT-SharpCompress.txt`:

| Source file | SHA-256 |
| --- | --- |
| `I1/Allocator.cs` | `1e2a6f5c7b68bde3d84f9fca5f6dec48369d893ba935a59577f3376d072dd005` |
| `I1/Coder.cs` | `e0d00eff741d3e5234ed542b6861db2b38f23d90b7a26479a2895e9341c78607` |
| `I1/MemoryNode.cs` | `d987459e2d5648d8442a7f7173844d219b79a01427177807491f49b818ec558b` |
| `I1/Model.cs` | `8273f1cf70ae49208e4e4152adbdd976b9ebc28887e14f0abafcbf05f48f8408` |
| `I1/ModelRestorationMethod.cs` | `4559b00c8b4bcf18e59013f2f51bc59d0392e777dfb2dfcda976ba31e99a03ce` |
| `I1/Pointer.cs` | `a3c5df77bd1c9731f31bfbbe7b588417cd08cbe6e3011d0711900ca4ec1fdaf9` |
| `I1/PpmContext.cs` | `f2c09e0b30cf22cb344c61d864e2f4ae112fd742d02735b12e6639eb76e4afdd` |
| `I1/PpmState.cs` | `806224c50a285454e424b2b46dbbfd6fd357f85070378a0449cc30380ec8f9b4` |
| `I1/See2Context.cs` | `7a161b047184b70437617a673bf4dacdf9aff1515617c23706cd515fe8c65fc1` |

The following SHA-256 values identify the exact pinned Go decoder inputs:

| Source file | SHA-256 |
| --- | --- |
| `internal/delta/reader.go` | `3f0fe62a46579fbc8d45f440939125d1e46e6d201a6a3004be35e95cad14cf3e` |
| `internal/bra/bcj.go` | `fc6ea1a56baeaa29de9abd11500013e1df857757fbb4f5a49d28673c93f8d41d` |
| `internal/bra/ppc.go` | `227b1fae1d6c5ba37ec5ddc4342f674162dfb04fd1245a914d18dbb5b0287c04` |
| `internal/bra/arm.go` | `8a73bffde1c8bf99105f6693e590c39af94014e6d64c9098fbd6155e0447609b` |
| `internal/bra/arm64.go` | `aee89873098e048bf4ff17c130378d0f91aa6a28c5f83094387f37904c1e12e2` |
| `internal/bra/sparc.go` | `0ebc3a80c8ce57634ba7c6f8e986eba33437d5a9df45468a3525d4775f7d8c9e` |
| `internal/bcj2/reader.go` | `0dc02a7a5cfcb22b747f03d4e1532cbc0c7c3d4b2776ee440e3c8cd1dffaddd5` |
| `internal/aes7z/reader.go` | `ccc36f061373813aad398e1db46a99946655612695780d9c29f1ba2152e37504` |
| `internal/aes7z/key.go` | `4f19ee803bf2429d4f0bd4df8b35474b830ae0b71426dae48bd95102879cc1ba` |
| `internal/deflate/reader.go` | `22eb3d80df6a498e39ceaa2b4cf6b3c74f54660e190ccb5a29ea1ce1d999cbc9` |
| `internal/bzip2/reader.go` | `4c3cad40c8f7fb46d06c4bafe281566c470111a0593a83e9e1a0af4192d5a6f3` |
| `internal/ppmd/reader.go` | `fd06ae4e7458d098d70f2f093743a82b746f95cb19b88a6e25a0f8570bf7b470` |
| `internal/brotli/reader.go` | `f8d89add7d9e688b41da5407feb4e2337c056b4457751932bc09a11778157445` |
| `internal/lz4/reader.go` | `8b0d327abca63b9207fdb7d4e93d8da4cd1c14c96c878833e3bfbf7b13e1bdbd` |
| `internal/zstd/reader.go` | `d53d1ee68e436f1757a392ced8ab00567d22ed3199220dbba73a12051e7357d9` |

The following SHA-256 values identify the exact `github.com/ulikunitz/xz`
v0.5.15 inputs. Files not listed were not adaptation sources.

| Source file | SHA-256 |
| --- | --- |
| `lzma/decoder.go` | `e30675e3b507cdb039472642ac9edad3c2a828c0afb63585ac6505f7994f52fa` |
| `lzma/decoderdict.go` | `9a1c0c2156733f24c57360c66f539015a588f717431876b12b012fced5417731` |
| `lzma/directcodec.go` | `97683a60f191304d873aa494d113822778decf42020041c9635d7e43dd8b555d` |
| `lzma/distcodec.go` | `1ca5bd4ff5d99bf43da54c398f4541865fe67c3f8c1990350a4261d861665b47` |
| `lzma/header2.go` | `c3bec4bcedac321bf9122da6dd25cd04b82ed8f3df2b9e7fc784cca4e1973ffb` |
| `lzma/lengthcodec.go` | `26163259c8aed61b74fe067d9934b9ad4eecda04f8df5d12367f9a04a765d58d` |
| `lzma/literalcodec.go` | `c81ea22ca483202f400858b7a8eab7e31ff9de504b51aa86950fc33e75ee82eb` |
| `lzma/operation.go` | `f300f395380634187457934401837074764a578778c12ff0ebe1a3462c7dfff4` |
| `lzma/prob.go` | `9b1ef349dd937503aaafaf8d3045b779782ae611182b6473a55111dda6e336cb` |
| `lzma/properties.go` | `69ef672663f7a2481cbacd35a6337a83f97db8066aa3c9636dee0244e2aded3c` |
| `lzma/rangecodec.go` | `f49aef1737de15d327c3a242303e20da8ba8bb8f34759c55165ab927557efa6c` |
| `lzma/reader2.go` | `5fe5c6021efbac407b1bfb344334fd36b8cdd1bc0caea829e3fe76549fa418b3` |
| `lzma/state.go` | `2d896e3d0b6b8949d43e20bec6aa60444d44e3f7a7e1482b234281cd0547e825` |
| `lzma/treecodecs.go` | `b1db10d283f453789587808d1aae1ed3540572085c0551e35d5b46b70b861861` |
| `LICENSE` | `701cbcc144a7c865b072f27547e66ddbf17ac44a3bd21f71149ace02518f107c` |

The following SHA-256 values identify every source file used from
`github.com/stangelandcl/ppmd` v0.1.1. Other files in that module were not used
as adaptation sources.

| Source file | SHA-256 |
| --- | --- |
| `reader.go` | `2f7b1843eb7788844daefddb8b51667668331d8a1ab2decbe48f9af34231544d` |
| `internal/h7z/consts.go` | `2a9a56f7ec6fa05c2bc5810880ca2fc7c05fe987cb81dd94605031848f1a7d34` |
| `internal/h7z/decoder.go` | `f27d6364e4a06eb7f68eccb3deee7f41dc7af1a5e141e2dcef2aa9fee4d42bab` |
| `internal/h7z/freqdata.go` | `7e1541ddb6aba906c5241ea3b11c68abb68da36dd39b431ee5eda48dc6c10470` |
| `internal/h7z/heap.go` | `2be2e1c3e060214ae8caf93dc731f588a08d9f324248b9773e466cb660235d36` |
| `internal/h7z/modelppm.go` | `13e31cd65b35ec498c8ad3f4fd0a1ea3cef8138e45ddb2bdae8cf197fee3281f` |
| `internal/h7z/ppmcontext.go` | `c7b6ef1445d17ba315b295ce8fc5a8b10bce0ad8d4388409ed1def5d6cff9c9f` |
| `internal/h7z/rarmemblock.go` | `1c2cf7ce554104e1d14455bb64e362a54cb3aa834c9b1dcafa17a4b77d58af54` |
| `internal/h7z/rarnode.go` | `194c8e92c3c3f3f88dc913fa6e5f2e661a65f281fbcbfd3c141eeb91e5cdcb93` |
| `internal/h7z/see2context.go` | `52a63a3ed922c2e6edcc8fb810534b8f9695851de4cd198ffa5550ec6710ca80` |
| `internal/h7z/shift.go` | `c96bcc32c692f8df2fa4b5e52fbaf5d8bbc2efc899b0e9bcb23d9e82b2c0f29e` |
| `internal/h7z/state.go` | `4e3be4a2e7fe33aa175568fc9d2e2867d93bce2b6b7abcddfd62fc7b5a35ad9b` |
| `internal/h7z/stateref.go` | `5e1e5c7905a5778c38d4ff27c9ffcbbe3c77c21d263c4dabeefd4b7319654c4b` |
| `internal/h7z/suballocator.go` | `1e216241994434de5ee8cc52fdbad182ab8b052df7a3e153e691557550dd222a` |
| `LICENSE` | `9bdaf6c691adeb560c86a43c26b9dd4f8a52c8d9965229e356e545e5894c3ab1` |

The following SHA-256 values identify the exact Phase 5 algorithm references.
Only the listed Apache Java decoder was adapted. The listed XZ files were used
as 0BSD instruction-layout/behavior references; no other XZ file was an
implementation source or runtime input.

| Project/source file | Commit | SHA-256 | License |
| --- | --- | --- | --- |
| Apache Commons Compress `src/main/java/org/apache/commons/compress/compressors/deflate64/HuffmanDecoder.java` | `9499ba8ed3c6dce1275ac3d0471afa414b23daff` | `2877fd6245852b966e1b220b7e96282fadfed329dd0f241b0e1cf56f08421f0c` | Apache-2.0 |
| Apache Commons Compress `NOTICE.txt` | `9499ba8ed3c6dce1275ac3d0471afa414b23daff` | `5318998af3591f72e0e3e80667d32ba334c080399011a767f93e611d907036ca` | Notice retained in `NOTICE` |
| XZ Utils `src/liblzma/simple/ia64.c` | `f3b5688159c60495f48db3942a36509671dfce89` | `049579b1428b44e7170bf6e1aee6e8eee953dc61ab4f1f551fdc3026b30271d7` | 0BSD reference only |
| XZ Utils `src/liblzma/simple/armthumb.c` | `f3b5688159c60495f48db3942a36509671dfce89` | `a40d52404e38408d2c6cb7ababffc157c1faed09d9d1d09ece69792a607fce88` | 0BSD reference only |
| XZ Utils `src/liblzma/simple/riscv.c` | `f3b5688159c60495f48db3942a36509671dfce89` | `5962ff339c83114e3fe403162ee5e2f8ed6d81f198c20de6d60240c1d9a2fe97` | 0BSD reference only |
| LZ4 `doc/lz4_Frame_format.md` | `0774d05537f9762f838f7ab541b7765f1a729cb5` | `382fe98ea6770abc39070cfba1287fe299f4570ddfc75713a1a8aa5483e38b98` | Official format reference; repository BSD-2-Clause |
| LZ4 `lib/LICENSE` | `0774d05537f9762f838f7ab541b7765f1a729cb5` | `8b58c446121a109ccf32edc094bba3010a3d85e4ee3702950db55e4d3e87736c` | BSD-2-Clause reference license |
| Zstandard `doc/zstd_compression_format.md` | `5c7b7bad26808e6b40ac3b3d0075466e27738a9d` | `9ce5315c466d644fb41b54a7dcb707eb6e067bb5f36d79c0728a7ea2050cd8f7` | Official format reference; repository BSD-3-Clause |
| Zstandard `LICENSE` | `5c7b7bad26808e6b40ac3b3d0075466e27738a9d` | `7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8` | BSD-3-Clause reference license |
| NetBSD `usr.bin/compress/zopen.c` | `bd9f26305380f03b3821f55381448a82827d6749` | `2e1375092ef015bfbf423f88d656fb6b8c705e1a3ca267cf003c2ca630854c7f` | BSD-3-Clause adaptation source; notice reproduced in `LICENSES/BSD-3-Clause-netbsd-zopen.txt` |

## Decoder and filter origin ledger

“Implemented” here records source origin, not compatibility by itself. Tested
support claims and exact fixtures are maintained separately in
`COMPATIBILITY.md`.

| Method/component | Go reference location | Rust origin | Applicable Rust-code license | Status |
| --- | --- | --- | --- | --- |
| Copy | `register.go:newCopyReader` | Original `execute.rs` pass-through branch | MIT | Implemented and tested |
| Delta | `internal/delta/reader.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| LZMA | `internal/lzma/reader.go` plus Go xz dependency | Adapted `decode/lzma.rs` from xz v0.5.15 | Ulrich Kunitz BSD-3-Clause plus MIT changes | Implemented and tested |
| LZMA2 | `internal/lzma2/reader.go` plus Go xz dependency | Adapted `decode/lzma.rs` from xz v0.5.15 | Ulrich Kunitz BSD-3-Clause plus MIT changes | Implemented and tested |
| BCJ/x86 | `internal/bra/bcj.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| BCJ2 | `internal/bcj2/reader.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| PPC | `internal/bra/ppc.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| ARM | `internal/bra/arm.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| ARM64 | `internal/bra/arm64.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| SPARC | `internal/bra/sparc.go` | Adapted `decode/filters.rs` | BSD-3-Clause plus MIT changes | Implemented and tested |
| Deflate | `internal/deflate/reader.go` plus Go compress dependency | Original bounded adapter in `decode/codecs.rs` over `miniz_oxide` 0.9.1 from `https://github.com/Frommi/miniz_oxide` | Adapter MIT; dependency MIT OR Zlib OR Apache-2.0 | Implemented and tested with raw-stream corruption/output/dictionary/work controls and `deflate.7z` differential evidence |
| BZip2 | `internal/bzip2/reader.go` plus Go standard library | Original bounded adapter in `decode/codecs.rs` over `bzip2-rs` 0.1.2 from `https://github.com/paolobarbolini/bzip2-rs` | Adapter MIT; dependency MIT OR Apache-2.0 | Implemented and tested with header/memory/cancellation controls and `bzip2.7z` differential evidence |
| PPMd | `internal/ppmd/reader.go` plus Go PPMd dependency | Adapted `decode/ppmd.rs` from `github.com/stangelandcl/ppmd` v0.1.1 at commit `e7008704a75379d49824363eca5d87e947b2d9fa` | Upstream MIT notice; Rust changes MIT | Implemented and tested with property/memory/cancellation/truncation controls and `ppmd.7z` differential evidence |
| AES-256-CBC/SHA-256 KDF | `internal/aes7z/reader.go`, `key.go`, plus Go standard library | Adapted property/KDF serialization in `decode/aes.rs`; primitives from RustCrypto `aes` 0.9.2, `cbc` 0.2.1, `cipher` 0.5.2, and `sha2` 0.11.0 | BSD-3-Clause for adapted layout; Rust changes MIT; primitives MIT OR Apache-2.0 | Implemented and tested for encrypted headers/data, direct/iterated KDF, KDF/cancellation limits, missing/wrong passwords, and identified encrypted fixtures |
| Brotli | `internal/brotli/reader.go` plus Go Brotli dependency | Original bounded adapter over `brotli-decompressor` 6.0.0, with pinned-Go adaptation only for the private 16-byte 7-Zip prefix | Adapter MIT plus pinned BSD-3-Clause notice; dependency BSD-3-Clause OR MIT | Implemented and tested with private `brotli.7z` fixture and common-corpus byte/SHA baseline retained from the independently licensed 5.0.3 regression vector; stock `7zz` 26.02 cannot decode the private method ID |
| LZ4 | `internal/lz4/reader.go` plus Go LZ4 dependency | Original bounded checked-frame adapter over `lz4_flex` 0.14.0 from `https://github.com/pseitz/lz4_flex` | Adapter MIT; dependency MIT | Implemented and tested with private `lz4.7z` fixture and common-corpus byte/SHA baseline; stock `7zz` 26.02 cannot decode the private method ID |
| Zstd | `internal/zstd/reader.go` plus Go compress dependency | Original frame-window-preflighting adapter over `ruzstd` 0.8.1 from `https://github.com/KillingSpark/zstd-rs` | Adapter MIT; dependency MIT | Implemented and tested without dictionaries using private `zstd.7z` fixture and common-corpus byte/SHA baseline; 0.8.1 is pinned because later releases exceed Rust 1.85; stock `7zz` 26.02 cannot decode the private method ID |
| Standalone LZ4 frame | Outside the 7z reference surface | Original bounded layout/session adapter over `lz4_flex` 0.14.0 using the pinned official frame document | Adapter MIT; dependency MIT; document repository BSD-2-Clause | Standard/legacy/concatenated/skippable frames implemented; declared checksums enforced; external dictionaries typed unsupported |
| Standalone Zstandard frame | Outside the 7z reference surface | Original bounded layout/session adapter over `ruzstd` 0.8.1 using the pinned official format document | Adapter MIT; dependency MIT; document repository BSD-3-Clause | Standard concatenated/skippable frames implemented; content checksum and window enforced; external dictionaries typed unsupported |
| Unix `compress` `.Z` | Outside the 7z reference surface | Checked safe-Rust adaptation of pinned NetBSD `zopen.c` read behavior | NetBSD/Berkeley BSD-3-Clause plus MIT Rust changes | 9-16 bit block/non-block LZW implemented with width/CLEAR/dictionary/output/work/cancellation tests and native-tool differential evidence; format has no checksum |
| Deflate64 | Not in pinned Go reference | Checked in-tree `decode/deflate64.rs` adaptation from the pinned Apache Commons Compress file above | Apache-2.0 source; Rust changes MIT | Implemented and tested with stored/dynamic/long-distance streams, every-prefix truncation, corruption, output/dictionary/work controls, and generated `7zz` differential archives |
| IA64 | Not in pinned Go reference | Original checked Rust expression in `decode/phase5_filters.rs` using the pinned XZ algorithm description | Rust MIT; reference 0BSD | Implemented and tested with transforming instruction bundles, corruption, tail safety, and `7zz` differential evidence |
| ARM Thumb | Not in pinned Go reference | Original checked Rust expression in `decode/phase5_filters.rs` using the pinned XZ algorithm description | Rust MIT; reference 0BSD | Implemented and tested with transforming branch instructions, nonzero address behavior, corruption, and `7zz` differential evidence |
| RISC-V | Not in pinned Go reference | Original checked Rust expression in `decode/phase5_filters.rs` using the pinned XZ algorithm description | Rust MIT; reference 0BSD | Implemented and tested for JAL and AUIPC pairs with transforming fixture, nonzero address behavior, corruption, and `7zz` differential evidence |
| Swap2 | Not in pinned Go reference | Original checked group reversal in `decode/phase5_filters.rs` | MIT | Implemented and tested for full words, odd tails, corruption, and `7zz` differential evidence |
| Swap4 | Not in pinned Go reference | Original checked group reversal in `decode/phase5_filters.rs` | MIT | Implemented and tested for full words, tails, corruption, real five-volume encrypted/unencrypted archives, and `7zz` differential evidence |

## ZIP and RPM origin ledger

The ZIP and RPM extension is original safe Rust, licensed MIT,
except for behavior delegated to the exact permissively licensed dependencies
below. No source from 7-Zip, p7zip, Info-ZIP, libarchive, `pyzipper`, or
`rpmfile` was copied, translated, or vendored. Those Python packages were used
only to define a read-compatibility comparison and Python-facing expectations.

The ZIP XZ method-95 boundary was pinned on 2026-09-14 before implementation.
PKWARE APPNOTE 6.3.10 (FINAL, 2022-11-01), retrieved from the official PKWARE
distribution URL with SHA-256
`0b993022a7d320a0bf704e6980bea36fafd17a6066ab994db0a0c16278a50cd6`,
registers method 95 as XZ. WinZip's *Additional Compression Methods
Specification* 3.1 (2014-04-14), preserved in the Internet Archive snapshot
`20150121121519id_` and retrieved with SHA-256
`8f584a40114fb5ec9c440f7a7f6a5e4200def378d6b564e1a434410cb1328c6e`,
defines the payload as exactly one XZ 1.0.4 Stream with optional zero Stream
Padding, at most one predefined size-preserving filter before LZMA2, all four
defined XZ Check types, and zero or more Blocks. It requires the ZIP
version-needed value used for Deflate (2.0, while later values remain valid
when another ZIP feature requires them). The current WinZip knowledge-base
method table and unsupported-format article, reviewed 2025-01-09 and retrieved
2026-09-14, independently retain method 95 and version-needed 2.0.

The referenced public-domain *The .xz File Format* 1.0.4 (2009-08-27) was
retrieved from Tukaani with SHA-256
`fada567e0ebd8b910d2c3210d13e74f3fcc8475d64e29e35db0fc05e3c6820f5`.
It supplies the Stream, Block, Index, VLI, padding, filter-property, and Check
invariants independently expressed by the MIT wrapper. The method adapter
reuses the existing in-tree checked LZMA2, Delta, and BCJ decoders. The
original method-95 boundary review inspected the then-admitted Apache-2.0
`lzma-rust2` 0.16.4 crate and found both that its
LZMA2 dictionary is created with an infallible `vec!` allocation and that its streaming
`XzReader` compares the decoded Block count with the Index but does not compare
each Index record's Unpadded Size and Uncompressed Size. Consequently method
95 does not use that permissive aggregate boundary: the project wrapper
preflights every record, gives the fallibly allocating in-tree LZMA2 decoder
only that Block's derived Compressed Data range and property, requires exact
input and output consumption, applies the declared size-preserving filters,
and verifies the declared XZ Check before joining Block output. The later
0.20.1 dependency refresh retains only the safe-code `std`/LZMA-alone surface;
its optional XZ container remains disabled and does not change this boundary.
No encoder, writer API, FFI, external command, or runtime fallback is added.

The ZIP PPMd method-98 boundary was pinned on 2026-09-14 before
implementation. WinZip's live *Additional Compression Methods* specification
at `https://www.winzip.com/de/support/compression-methods/`, retrieved
2026-09-14, identifies the codec as PPMd variant I revision 1 and
defines the two-byte little-endian prefix as
`(order - 1) | ((memory_mib - 1) << 4) | (restoration << 12)`. It admits
orders 2 through 16, model memories 1 through 256 MiB, restoration values 0
(restart), 1 (cutoff), and 2 (freeze), and the Deflate-equivalent
version-needed value 2.0. PKWARE APPNOTE 6.3.10 registers method 98 and defers
the codec details to the vendor specification. The payload terminates with the
codec end marker; the ZIP header's independently bounded uncompressed size is
also required, and extraction succeeds only after both boundaries and the ZIP
CRC agree.

The safe in-tree PPMd-I model, carryless range decoder, context/state layout,
and suballocator are adapted from Dmitry Shkarin's original PPMII variant-I
revision-1 sources and Dmitry Subbotin's public-domain range coder. The
canonical author archive `ppmdi1.rar` was retrieved from
`https://compression.ru/ds/ppmdi1.rar` with SHA-256
`5a559300c26949fc5dd015983bfe680fd9a32c2b4afb85320dc9b38f90f8c5d6`.
Because the archive is a solid RAR revision unsupported by the available
inspection tools, exact separately published source files were inspected in
the OpenXRay mirror at commit
`bcefa731baf3add37c33348ec709ab391a9032a2`; their hashes are recorded above.
Only the canonical PPMII model, allocator, and carryless range-coder behavior
was adapted. OpenXRay-specific trained-model additions were excluded. The new
Rust expression replaces pointers, unions, casts, and unchecked arithmetic
with validated offsets, checked heap access, fallible allocation, explicit
limits, bounded list traversal, work accounting, and cancellation. It is
offered under MIT while preserving the authors' public-domain attribution.

`ppmd-rust` 1.4.0 and 1.5.0 were audited and rejected as runtime dependencies
or adaptation sources: their own provenance states that they port the PPMd
code from 7-Zip, their model uses extensive `unsafe` pointer arithmetic, and
their `CC0-1.0 OR MIT-0` expression is outside this repository's admitted
runtime license set. No code from those crates, 7-Zip, p7zip, an SDK, or
libarchive was copied, translated, linked, or vendored. Stock `7zz` is used
only as a black-box test oracle; libarchive was inspected only as a rejected
candidate/reference implementation.

### Deferred WinZip recompression research

The 2026-09-14 research pass pinned the registrations but did not admit another
decoder. PKWARE APPNOTE 6.3.10, with the exact hash above, assigns 94 to MP3,
96 to the WinZip JPEG variant, and 97 to WavPack. WinZip's live method table at
`https://kb.winzip.com/en/130539` independently records those identifiers and
the Deflate-equivalent version-needed value 2.0. The WinZip article
`https://kb.winzip.com/130580`, retrieved the same day, says MP3 compression
was introduced in WinZip 21 and is selected for MP3 input under the Best
compression setting, but neither that article nor APPNOTE publishes the method
94 payload grammar, framing, termination, or reconstruction rules. Registration
and product behavior therefore cannot support a decoder or positive fixture.

The official *WinZip JPEG Compression Specification*, version 1.0 (2008), was
retrieved from `https://www.winzip.com/static/wz/docs/wz-jpg-comp.pdf` with
SHA-256
`91eb8a1fe967b8ddf58d044a407a994fc3103d3c1b6e21649c051afa0096cd99`.
It defines method 96/version-needed 2.0, a minimum four-byte properties header
(format version `0x10`, method 1, and option/slice fields), bounded metadata
bundles with two- or four-byte sizes and a 16 MiB maximum, an inner LZMA 4.57
metadata stream, JPEG marker/scan and arithmetic-coded transform data, and
exact reconstruction for the specified 8-/12-bit sequential one- through
four-component JPEG profiles. This is a nested parser/decoder, not a normal
JPEG library call. XADMaster 1.10.8 at commit
`881e0ec25e249c9ad5bbc1b6782ae8dcdf48a6ed` was the only complete independent
decoder located, but it is LGPL-2.1 C/Objective-C with an unsafe native parser.
It was inspected only to establish candidate availability and was not copied,
translated, linked, or used as an oracle.

APPNOTE section 5.9 is the authoritative method-97 framing: WavPack output
begins immediately after the local-header data, the local and central method
fields are 97, version-needed follows Deflate, and every storage byte of each
sample—including nominally unused bits—must round-trip. The official *WavPack
5 Library Documentation*, dated 2024-02-15, was retrieved from
`https://www.wavpack.com/WavPack5LibraryDoc.pdf` with SHA-256
`8622c1b780788227d05602bda8fa8690f0ba425252c6d5ffee72e751329652ee`.
Its WinZip compatibility notes require the legacy lossless/very-high encoder
configuration, preserving RIFF headers and trailers as wrapper data, and a
reader callback plus `OPEN_WRAPPER` for exact recovery; zero audio samples are
not a valid WavPack stream. Official WavPack 5.9.0 at commit
`5803634a030e2a11dba602ba057b89cc34486c67` is BSD-licensed native C but would
require an unsafe FFI and delegate the hostile stream parser. `wavpack-rs` at
commit `009766e5d06a6072f3b95a268d73089abd2726ed` was rejected for the missing
license file at that revision, overflow-disabled and unchecked input paths,
unbounded unary decoding, incomplete PCM coverage, and inability to reconstruct
the exact original RIFF wrapper.

Libarchive 3.8.9 at commit
`27cbc7827172698143e440801fc0ba39ccb4f1f5` was also checked. Its BSD-licensed
C ZIP reader recognizes these numeric identifiers but implements neither the
WinZip JPEG nor WavPack payload decoder; its broad unsafe native parser is not
an admissible fallback. No safe, permissively licensed, bounded method-94,
method-96, or method-97 implementation and no provenance-complete deterministic
encoder/fixture set was found. The verified public names are therefore exposed
only as stable metadata enum values, while extraction returns the numeric typed
`UnsupportedMethod` error before codec allocation.

### Deferred ZIP structure and encryption research

APPNOTE 6.3.10 section 8 supplies the split/spanned design facts. Split ZIP is
the same segmentation model as removable-media spanning; ordinary split names
are `filename.z01` through `filename.z(n-1)` followed by `filename.zip`, while
DOS spanned disks use `PKBACK#xxx` labels. The first segment may carry
`0x08074b50`, and a single-segment abandoned split may carry `0x30304b50`.
Segment sizes may differ, the minimum conventional segment is 64 KiB, local and
central header records must not be split, the central directory may span only
between records, and member data may cross disks. The format's nearly 2^32
disk/size capacities are not implementation defaults. The future bounded
caller-provider model, ordering/range rules, work sharing, cancellation, and
failure classification are recorded in `THREAT_MODEL.md`; no parser or API has
been admitted.

APPNOTE sections 7.0 through 7.8 pin the Strong Encryption surface. Bits 0 and
6 identify it, bit 13 identifies an encrypted central directory and masked
local metadata, central extra field `0x0017` uses format 2, and each encrypted
file has a variable decryption header with format 3, IV, algorithm/key/flag
declarations, encrypted random data, optional certificate structures, and
encrypted validation data plus CRC. Registered algorithms include RC2, RC4,
DES, 3DES, AES, Blowfish, and Twofish; block algorithms use CBC, and the
password/session-key construction uses SHA-1-derived material. Central-directory
encryption requires the Archive Decryption Header, ZIP64 EOCD version 2,
version-needed 62, optional central compression, hashes, masked local fields,
and no random-access claim. The specification also carries an explicit
proprietary/patent warning. No complete admissible cryptographic/certificate
stack or redistributable positive/corrupt fixture set was found, so the review
defines a future resource/KDF/metadata boundary without changing the current
typed-unsupported behavior.

### Local-only WinZip interoperability corpus

Representative proprietary-tool output is not committed. A local sparse clone
of SharpCompress at exact commit
`e04d51176c5d87668c4c8779825342230c33aa74` (MIT notice copied verbatim to
`LICENSES/MIT-SharpCompress.txt`, SHA-256
`b7ca2b6174cee11afe41d78b48527e3d7659a4435c25019a4a5e072299a2f8ed`)
supplied four version-labelled WinZip ZIPX samples. `WinZip26_BZip2.zipx` and
`WinZip26_LZMA.zipx` entered that upstream corpus at commit
`224614312fa7992e98f4cab9136c2723892ca103`; `WinZip27_XZ.zipx` at
`b9d019561f8be6c7195bfeab482824284617f351`; and
`WinZip27_ZSTD.zipx` at `92df1ecd5f7579a88a1c5a7d30744a091de95b2a`.
The filenames and test names are upstream attestations of WinZip 26/27, but the
upstream commits do not record an automation/GUI creation command. That missing
producer command is preserved as a provenance limitation rather than invented.

The opt-in `winzip_reference` integration test pins each archive hash, entry
count, method, version-needed field, absence of encryption, member CRC/size,
and decoded SHA-256; it then performs extraction and full verification under
production limits. The same corpus contains `Zip.ppmd.zip`, present since
SharpCompress's initial commit and useful as an independent method-98 layout
and output vector, but neither its filename nor history identifies WinZip or a
producer version. It is therefore supplemental PPMd interoperability evidence,
not counted as a WinZip-produced archive. Exact hashes, inventory, reproduction
command, and the no-redistribution decision are in `CORPUS.md`.

| Component | Exact origin/revision | License | Use and adaptation status |
| --- | --- | --- | --- |
| ZIP records, ZIP64, descriptors, method IDs, flags, extras, and traditional encryption facts | PKWARE APPNOTE 6.3.10 (2022-11-01), official `APPNOTE.TXT`, retrieved 2026-07-21 | Specification; no source code imported | Independently expressed checked parser/model and legacy ZipCrypto state machine; MIT project code |
| ZIP XZ method 95 | WinZip *Additional Compression Methods Specification* 3.1 (2014-04-14), Internet Archive snapshot `20150121121519id_`, SHA-256 `8f584a40114fb5ec9c440f7a7f6a5e4200def378d6b564e1a434410cb1328c6e`; PKWARE APPNOTE 6.3.10, SHA-256 `0b993022a7d320a0bf704e6980bea36fafd17a6066ab994db0a0c16278a50cd6`; retrieved 2026-09-14 | Format specifications; no source code imported | Exact one-Stream XZ 1.0.4 profile, optional zero padding, Deflate-equivalent version-needed rule, per-Block/Index exactness, and ZIP member-integrity integration independently expressed in MIT Rust |
| ZIP PPMd method 98 framing | WinZip live *Additional Compression Methods* specification and PKWARE APPNOTE 6.3.10, retrieved 2026-09-14 | Format specifications; no source code imported | Exact two-byte property prefix, PPMd-I revision-1 selection, order/memory/restoration bounds, end-marker requirement, and Deflate-equivalent version-needed rule independently expressed in MIT Rust |
| ZIP PPMd-I revision-1 decoder | Dmitry Shkarin `ppmdi1.rar`, SHA-256 `5a559300c26949fc5dd015983bfe680fd9a32c2b4afb85320dc9b38f90f8c5d6`; separately published original-source mirror files at OpenXRay commit `bcefa731baf3add37c33348ec709ab391a9032a2`; SharpCompress I1 port by Michael Bone at commit `e04d51176c5d87668c4c8779825342230c33aa74`; hashes above | Original sources state public domain; SharpCompress MIT; new Rust code MIT | Safe, fallible adaptation of the original context model, allocator, restoration modes, and Dmitry Subbotin carryless range coder, with managed layout/control-flow cross-checking; no OpenXRay trained-model extension and no 7-Zip-derived implementation used |
| XZ 1.0.4 container and checks | Tukaani *The .xz File Format* 1.0.4 (2009-08-27), SHA-256 `fada567e0ebd8b910d2c3210d13e74f3fcc8475d64e29e35db0fc05e3c6820f5`, retrieved 2026-09-14 | Public-domain format specification | Structural reference for checked Stream/Block/Index parsing, predefined filters, CRC-32/CRC-64/SHA-256 checks, exact padding, and size reconciliation; no XZ source copied or linked |
| WinZip AES AE-1/AE-2 layout | WinZip AES Encryption Specification 1.04 (2009-01-30), official WinZip support document, retrieved 2026-07-21 | Specification; no source code imported | Independently expressed salt/verifier/layout/authentication adapter; AES/CTR/PBKDF2/HMAC/SHA-1 delegated to RustCrypto |
| CP437 name mapping | Unicode Consortium `Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT`, retrieved 2026-07-21 | Unicode data-file license | Byte-to-Unicode display table only; raw ZIP names remain authoritative metadata |
| `rawzip` | crates.io 0.5.1, checksum `75a2b2577f5fd7e26caabd4aa7bba1ef18653ff32204eea251c1136db1a549f3`, source commit `571e479673646848ec16b12213b7600d639971d8` | MIT | Safe ZIP locator/central iterator dependency; writer API unused; all security validation remains project code |
| WinZip AES primitives | RustCrypto `ctr` 0.10.1, `hmac` 0.13.0, `pbkdf2` 0.13.0, and `sha1` 0.11.0, exact crates.io checksums in `Cargo.lock`; existing `aes` 0.9.2 | MIT OR Apache-2.0 | Cryptographic primitives only; no primitive is reimplemented |
| ZIP Deflate64 | Existing in-tree Apache Commons Compress adaptation recorded above | Apache-2.0 plus MIT changes | Reused behind ZIP method 9 with the same bounds and operation controls |
| RPM envelope, tags, payload declarations, and digest ranges | RPM 6.0 format-v4/signature-digest manuals and official `include/rpm/rpmtag.h` at rpm commit `a8f0192aee1c08bd1454ed2ac6ebaf506004b55c`, inspected 2026-07-21 | RPM project GPL source tree was consulted only for public numeric tag definitions; no implementation code copied or linked | Original bounded lead/header/store parser and digest selection; factual constants do not import source-code licensing |
| SVR4 `newc`/CRC-`newc` CPIO records | Public SVR4 new ASCII record definition and RPM payload documentation, inspected 2026-07-21 | Format specification; no implementation source imported | Original exact-alignment/range/checksum parser; no libarchive or GNU cpio source inspected |
| XZ LZMA2 Blocks | Existing in-tree `decode/lzma.rs` adaptation from `github.com/ulikunitz/xz/lzma` v0.5.15 commit `7eee8a8a405163554a9accec7b9402ee21400769` | BSD-3-Clause plus MIT changes | Fallibly allocating, checked LZMA2 entropy decoder shared by 7z, ZIP, RPM, and Debian behind the original exact XZ Block/Index/check/resource wrapper |
| Legacy LZMA payloads | `lzma-rust2` crates.io 0.20.1, checksum `5e2a88783b84d2d67ef2791778a9e76bfb68b8017aaf6c9d7d5f2626a478b16c`, source commit `62042f7fe56e6a98e886c5f8f9e8a04d04183069` | Apache-2.0 | Safe-code legacy LZMA-alone entropy decoder for RPM and Debian; encoder/optimization and optional aggregate XZ container disabled |
| Other RPM payload codecs | Already admitted `miniz_oxide` 0.9.1, `bzip2-rs` 0.1.2, and `ruzstd` 0.8.1 | MIT/Zlib/Apache-2.0 combinations recorded in `DEPENDENCIES.md` | Existing bounded decoders reused; original RPM gzip envelope and payload dispatcher |
| Python test-oracle sources | `pyzipper` 0.4.0 tag commit `a814388f5a8a7b172ee2e2ca668fc33c7516e6bc`, PyPI sdist SHA-256 `a4b96afcac04c5589d5abdc6158dd362166374e3cc6810aa441e65f8a17cb9e3`; `rpmfile` 2.2.1 tag/attested commit `c71e53491bb3ae8581e32630089c174b99b2aba6`, PyPI sdist SHA-256 `8ffc44d15f8d2b6cad1ea885b09e1ca5f1744532c24710554f3fe4873506e9da`; inspected 2026-07-21 | MIT | Test-only read-path/API evidence. `pyzipper` admits Store/Deflate/BZip2/ZIP-LZMA plus WinZip AES; `rpmfile.RPMFile` admits `070701` payload records and gzip/BZip2/XZ/optional-Zstandard decompression. The RPM tag-name table was adapted as described below; no parser, decoder, crypto, or filesystem source was copied, and neither package is a build/runtime/test dependency |

Generated ZIP fixtures are original serializers in Rust/Python tests. The
original fixed BZip2/Zstandard vectors were created from project-authored bytes
by locally installed `bzip2` 1.0.8 and Zstandard 1.5.7 executables; the
method-95 XZ vectors use XZ Utils 5.8.3 as recorded in `CORPUS.md`. Only
compressed bytes are embedded. Python standard-library `zipfile` generated the
interoperability Deflate/BZip2/LZMA archives used by binding tests. WinZip
AES/ZipCrypto fixtures are produced by independent test-only encoders around
public passwords and project-authored text; no writer is included in runtime
code. The separate RPM XZ/LZMA vectors retain their recorded XZ Utils 5.8.1
origin.

Generated RPM fixtures are original typed-header and CPIO serializers used
only under `cfg(test)` or in binding tests. They wrap project-authored bytes and
exercise every admitted compressor and digest boundary. The production package
contains no RPM or CPIO writer API.

## Standalone CPIO, Debian package, and ARJ origin ledger

The standalone CPIO and Debian readers are original safe Rust, licensed MIT OR
Apache-2.0. Their parsers were independently expressed from the public format
documents below; no implementation source from GNU cpio, GNU tar, dpkg,
libarchive, 7-Zip, p7zip, or another archive library was copied, translated,
linked, or vendored. The production package contains no CPIO, ar, tar, Debian,
or ARJ writer.

| Component | Exact origin/revision | License | Use and adaptation status |
| --- | --- | --- | --- |
| CPIO new ASCII, CRC-new ASCII, old portable ASCII, and historical binary records | The Open Group Base Specifications Issue 7, 2018 edition, `cpio`/extended `cpio` format descriptions; public System V `newc`/CRC record definition; inspected 2026-07-21 | Format specifications; no implementation source imported | Original checked parser for `070701`, `070702`, `070707`, and little-/big-endian binary magic `070707`; exact alignment, bounds, trailer, and applicable CRC validation |
| Debian binary package envelope | Debian `deb(5)` binary package format and Debian Policy 4.7.2.0, binary packages appendix; inspected 2026-07-21 | Format documentation; no dpkg source imported | Original checked System V ar subset requiring `debian-binary`, `control.tar*`, and `data.tar*`; no package installation, maintainer-script execution, or signature claim |
| tar members inside Debian packages | POSIX.1-2017 `pax` extended tar interchange format plus documented GNU long-name/long-link records; inspected 2026-07-21 | Format specifications/documentation; no implementation source imported | Original V7/ustar parser with checksum, bounded PAX records, GNU long name/link handling, metadata preservation, and caller-selected sinks |
| Debian member compression | Existing admitted `miniz_oxide` 0.9.1, `bzip2-rs` 0.1.2, `lzma-rust2` 0.20.1, and `ruzstd` 0.8.1 | MIT/Zlib/Apache-2.0 combinations recorded in `DEPENDENCIES.md` | Existing bounded gzip, BZip2, XZ, legacy LZMA-alone, and Zstandard adapters reused; no new compressor or FFI dependency |
| ARJ headers, methods, flags, and SFX identification | `ARJ TECHNICAL INFORMATION`, September 2001, file `doc/arj.txt` in `unarj-rs` 0.2.1, SHA-256 `b6163452b2a6ed99b5bcf1e78535c5257244240467b87ad3218b0378cda9ab29`; inspected 2026-07-21 | Public format document; no embedded C excerpt copied | Original checked main/local/extended-header parser, bounded SFX scan, typed unsupported feature detection, range validation, and CRC enforcement |
| ARJ methods 1--3 payload decoder | `delharc` crates.io 0.6.2, checksum `3658b90877f637514897c3dcbd628e0d290bcc7fee551a398b3994ebdc62d51e`, source commit `737ab3fc9913dad0a4fb9965f0bcd95a013f5a28`, Rafal Michalski | MIT OR Apache-2.0 | Exact dependency's static LH6 decoder only; its archive parser and optional decoders are unused. The release also fixes header-parser overflow/preallocation defects even though that parser remains outside the invoked surface. Original wrapper preflights 68 KiB decoder state and output, accounts work/input, checks cancellation, catches dependency panics, and verifies ARJ CRC |
| ARJ method 4 payload decoder | `unarj-rs` crates.io 0.2.1 at commit `dbd80638eb4a200618c08de7b9e58b4d66a0d377`, Mike Krüger, `src/decode_fastest.rs` SHA-256 `555d36c89b5aa473953630520481800a9494f9e24d83d8fef97f36d1f97031e8` | The package metadata says MIT while the shipped `LICENSE` is Apache-2.0; this project conservatively treats the adaptation as Apache-2.0 | Checked safe-Rust adaptation of the variable-length literal/match grammar; rewritten around bounded bit reads, checked arithmetic/indexing, 8-KiB history preflight, work/cancellation checks, exact declared output, and typed errors |

The four committed ARJ method fixtures are base64 encodings of
`unarj-rs` 0.2.1's `tests/data/method{1,2,3,4}.arj`. They are retained under
the package's conservative Apache-2.0 treatment, and each contains the same
11,357-byte Apache-2.0 `LICENSE` payload as this repository's
`LICENSES/Apache-2.0.txt`. Exact archive and decoded hashes are in `CORPUS.md`.

The deterministic Debian compressor fixtures were generated locally on
2026-07-21 from a repository-authored tar member with bsdtar 3.5.3/libarchive
3.7.4, Apple gzip 479, bzip2 1.0.8, XZ Utils 5.8.3, and Zstandard 1.5.7.
Only compressed data is retained; none of those tools is a build or runtime
dependency. Exact hashes and generation scope are in `CORPUS.md`.

## Python adapter origin ledger

| Component | Exact origin/revision | License | Use and adaptation status |
| --- | --- | --- | --- |
| `bindings/python/src`, Python package/stubs/tests, workflow, and documentation | Original repository work, 2026-07-18 through 2026-07-21 | MIT | FFI adapter only; no upstream archive/stream algorithm or source adapted |
| Python ZIP/RPM data projections | Original repository work, 2026-07-21; output values checked with the test-oracle sources recorded above | MIT, except the adapted rpmfile tag-name table under its MIT notice | Native binding metadata and extraction only; no compatibility facade. `bindings/python/src/rpm.rs::main_tag_name` adapts rpmfile 2.2.1's complete factual tag/name mapping, selecting canonical spellings for its duplicate `5097`/`5101` typo aliases; exact upstream notice is in `LICENSES/MIT-rpmfile.txt`. No upstream parser, decoder, cryptography, writer, or filesystem extraction source was copied. Generated ZipCrypto and AE-2 AES-256 regressions reuse the repository's own specification-based test algorithms |
| PyO3 family | crates.io `pyo3`, `pyo3-ffi`, `pyo3-build-config`, `pyo3-macros`, and `pyo3-macros-backend` 0.29.2; `pyo3` checksum `4688ddedf473e32662b9b067670129a8afb8c18e351482c70d62ba4a88171e8b`, source commit `a70d17f898df41b3d1632ee987f624f5222d8d39`; remaining exact checksums in `bindings/python/Cargo.lock`; `https://github.com/PyO3/pyo3` | MIT OR Apache-2.0 | CPython ABI, owned handles, module/classes, exceptions, detach/attach, and limited-API build; dependency source not copied |
| Python host API | Python 3.9+ stable ABI as exposed by the caller's interpreter; `https://docs.python.org/3/c-api/stable.html` | Python Software Foundation License for CPython | External host platform only; no interpreter source or binary copied or bundled |
| maturin | PyPI/build-backend release 1.15.0, exactly pinned in `pyproject.toml`; `https://github.com/PyO3/maturin` | MIT OR Apache-2.0 | Development/build tool only; not a wheel runtime dependency and no source copied |
| GitHub checkout/setup actions | `actions/checkout` v7.0.1 at `3d3c42e5aac5ba805825da76410c181273ba90b1`; `actions/setup-python` v7.0.0 at `5fda3b95a4ea91299a34e894583c3862153e4b97` | MIT | CI-only, immutable pins; their Node 24 runtime is supplied by the selected GitHub-hosted runners |
| cargo-deny GitHub Action | `EmbarkStudios/cargo-deny-action` v2.1.1 at `3c6349835b2b7b196a839186cb8b78e02f7b5f25` | Apache-2.0 | CI-only policy runner for the three separately locked graphs; no runtime code and no source copied |
| maturin GitHub Action | `PyO3/maturin-action` v1.51.0 at commit `e83996d129638aa358a18fbd1dfb82f0b0fb5d3b` | MIT | CI-only pinned wheel builder; no runtime code and no source copied |
| GitHub artifact actions | `actions/upload-artifact` v7.0.1 at `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`; `actions/download-artifact` v8.0.1 at `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | MIT | CI-only pinned transfer of tested wheels/sdist into the manually approved publish job; no runtime code and no source copied |
| PyPI publishing action | `pypa/gh-action-pypi-publish` v1.14.2 at `dc37677b2e1c63e2034f94d8a5b11f265b73ba33` | BSD-3-Clause | CI-only Trusted Publishing client after protected-environment approval; no long-lived credential, runtime code, or copied source |
| `target-lexicon` | crates.io 0.13.5, checksum `adb6935a6f5c20170eeceb1a3835a49e12e19d792f6dd344ccc76a985ca5a6ca` | Apache-2.0 WITH LLVM-exception | PyO3 build-only target parsing; exact permissive cargo-deny exception, not linked into the wheel |
| Binding license payload | Root-equivalent `LICENSE`, `LICENSES/`, and `NOTICE` payload | Project MIT license plus separately labeled third-party/adapted-source terms | Included in wheel and sdist; preserves all adapted core provenance without relicensing it |

The binding's local `unpackio` dependency therefore inherits the complete parser,
model, decoder, filter, crypto, and corpus provenance recorded above. No
Python-facing file changes any decoder origin or expands a support claim.

## Corpus provenance

No binary corpus file is committed. The audited source tree's testdata hash
manifest is `reference/7z-testdata.sha256`; it permits exact reacquisition
for inspection but does not assert independent redistribution rights for every
fixture. See `CORPUS.md`.

The separate `<CORPUS>` and `<MALFORMED_CORPUS>` inputs in the request were
literal placeholders and the owner confirmed that no such sets are available.
The narrower local-only SharpCompress/WinZip ZIPX set is recorded above and in
`CORPUS.md`; it is fetched outside the tree, hash-checked before parsing, and
not redistributed. Any other future external corpus must have its paths,
hashes, origins, and licenses added here before it is copied, mutated, or used
for a compatibility claim.

Phase 5 oracle archives are created in unique temporary directories by
`crates/unpackio/tests/phase5_reference.rs` from deterministic synthetic bytes,
compared with the installed `7zz` 26.02 executable, and deleted. They are not
committed or redistributed. The matrix includes all six new methods, mutated
packed data, Deflate64 solid/non-solid and encrypted-header data, and separately
authored five-part encrypted and unencrypted Swap4 archives.

The same policy applies to `crates/unpackio/tests/generated_oracle.rs`. It creates
synthetic source bytes and temporary stock-method, AES, synthetic-prefix SFX,
ZIP XZ method-95, and ZIP PPMd method-98 archives with the selected exact
`7zz` 26.02, compares them through the
production Rust API, mutates packed data, and deletes the complete directory.
The checksum-pinned Windows job continuously executes it and the Phase 5
harness through the same black-box interface. The tests contain no 7-Zip
source or SFX stub and the generated archives are not redistributed. This test
evidence changes no decoder implementation origin in the ledgers above.

The nine-byte ZIP method-98 vector and deterministic project wrapper have the
exact command, properties, sizes, CRC, and hashes recorded in `CORPUS.md`.
Only the packed bytes are retained as source literals in Rust, Python, and the
archive-format fuzz target. The in-crate fixture encoder is compiled only under
`cfg(test)` and its order-2/1-MiB/Restart output must equal that independent
black-box vector exactly; it neither enters the library artifact nor creates a
public writer surface.

The embedded raw LZMA EOS regression is the deterministic output of XZ Utils
5.8.3 for the synthetic three-byte input `abc` using raw LZMA1 with a 4 KiB
dictionary, lc=3, lp=0, and pb=2. It is test data only; no XZ source was copied
for that vector, and it contains no third-party corpus content.
