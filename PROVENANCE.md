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
an admissible fallback. At the end of that 2026-09-14 pass, no safe,
permissively licensed, bounded method-94, method-96, or method-97
implementation and no provenance-complete deterministic encoder/fixture set
had been found, so all three registrations remained metadata-only.

The 2026-09-15 follow-up narrowed method 94 substantially without admitting
code. The packMP3 v1.0g repository was pinned at commit
`e61c11941552f4ffe6e219a847f441d9520d2e50`; its `LICENSE` SHA-256 is
`97628afebc60f026f5c2b25d7491c46a5c4ee61f693e7cfa07fbd2c03605979b` and
its `Readme.txt` SHA-256 is
`12dfcba7cb77a7050844171e484a812d9b9547d0b0eb1c2dd1830f4d05e5b67c`.
Both identify LGPL-3.0-or-later, which prohibits a dependency or adaptation;
the readme invites case-by-case requests for different terms but grants none
to this project. It was built and executed only as an external oracle. Command
`packMP3 -ver -v2 -np` transformed a project-authored MPEG-1 Layer III input
with SHA-256
`372d875979967b2d95b48c2ded842a2a6bbd295c50d2455f8ad9829d2826aa0e`
into a 216-byte PMP stream with SHA-256
`e348bb86122aaf35d1f4c136a0be6e025bf3ce2b5304aa1f17c962b5fff81de6`;
an independent oracle invocation reconstructed the original input byte for
byte.

The 2026-09-16 clean-room follow-up created a differential corpus rather than
reading or translating that implementation. The original MIT fixture script
`crates/unpackio/tests/fixtures/method94/generate.rb`, SHA-256
`d91eb0b2162112327f49651d66d8a9d8358b0d39f0267b4f6cb31645033d6209`,
generates deterministic integer-PCM RIFF/WAVE signals and invokes external
tools with argument arrays. It used the official LAME 4.0 source archive at
`https://downloads.sourceforge.net/project/lame/lame/4.0/lame-4.0.tar.gz`,
SHA-256 `3df5124d5ad3a98312ffd7ba6a9b36230e4f8a3e66d3ce0f425e336c32d216eb`,
under LGPL-2.0-or-later. The source was built only in temporary storage with
`--disable-decoder --disable-shared --enable-static`; the macOS frontend build
used `-include locale.h` without changing upstream source. The resulting local
`LAME 64bits version 4.0` encoder SHA-256 was
`14f9f7a8ff90807b1626800cd1b57a764bf1e7abaa70d5d87d275496add715ae`.
It is neither committed nor a package dependency.

The same pinned packMP3 v1.0g binary identified above converted each generated
MP3 as a black-box oracle and verified an internal encode/decode comparison. A
second independent oracle invocation decoded every PMP and was compared to the
source MP3 byte for byte. In addition to 53 LAME-generated inputs, the script
constructs one five-frame zero-main-data MPEG-1 Layer III stream directly from
the public frame and side-information grammar so intensity stereo is positively
exercised without importing codec code. The 54 accepted and unique pairs cover every MPEG-1
Layer III bitrate (32 through 320 kbit/s), 32/44.1/48 kHz, mono and stereo
modes, CRC-protected and unprotected frames, enabled and disabled reservoirs,
copyright/original/emphasis flags, ID3v1 and ID3v2 metadata, short/normal/long
streams, deterministic silence/impulse/tones/noise/transient/stereo signals,
intensity stereo, and CBR/ABR/VBR with and without LAME tags. Their decoded
totals are 974,445 MP3 bytes and 679,297 PMP bytes. A fresh second generation
left all original 53 records and 106 base64 files byte-identical and produced
the additional pair deterministically.

The corpus manifest at
`crates/unpackio/tests/fixtures/method94/research/manifest.json`, SHA-256
`7f4eb2efae2e17b9fe4b8b2476492a7aa6af2e911674de0bfe465ff1d440d85e`,
records every PCM profile, complete encoder argument list, source size/hash,
MP3 size/hash, PMP size/hash, oracle result, and tool identity. The independent
MIT verifier `crates/unpackio/tests/fixtures/method94/verify.rb`, SHA-256
`712ec88579631886202287f7308d2f0a196e2bfd3c694bedb333525031cb73b8`,
checks exact file-set agreement, base64 decoding, sizes, SHA-256 values,
MP3/PMP signatures, oracle acceptance, and round-trip assertions without
invoking an external tool. The corpus creates independently observable format
evidence; it is not itself a public grammar, does not admit LGPL expression,
and does not change method 94's typed-unsupported product boundary.

The 2026-09-16 public-document follow-up found no admissible payload grammar.
The upstream [packMP3 README](https://github.com/packjpg/packMP3/blob/master/Readme.txt)
documents invocation, incompatible PMP generations, and LGPL licensing, but
not field ordering, probability models, or termination. The University of
Regensburg catalog record for Matthias Stirner's
[*Weitere verlustfreie Kompression von MP3-Dateien*](https://epub.uni-regensburg.de/28161/)
marks the work unpublished and exposes no format text. Official WinZip method
documentation registers MP3 method 94 and product behavior but likewise does
not specify the PMP payload. No packMP3 source was read or adapted during this
search or analysis.

The original MIT clean-room analyzer
`crates/unpackio/tests/fixtures/method94/analyze.rb`, SHA-256
`276d81fa59db660dbcfb67d60b23196b541950424998911bf3fd683efe036522`,
parses the 54 MP3 inputs using standard MPEG-1 Layer III framing and side
information and compares
only observable PMP bytes. It proves the three-byte signature, the packed
sample-rate/channel-mode/fixed-bitrate descriptor, global CRC/original/
copyright/emphasis/ID3 flags, reservoir marker, and big-endian frame count. It
also mechanically proves header byte 4 as a feature-presence bitmap: padding,
mid/side stereo, intensity stereo, switched blocks, nonzero subblock gain,
SCFSI scalefactor sharing, preflag, and scalefac-scale in descending bit order.
The arithmetic/entropy stream begins at byte 11, but its symbol
alphabet, field sequence, models, state initialization, termination, and error
rules remain opaque. Consequently, implementing even the verified envelope
would not produce a decoder and would create no safe extraction claim; method
94 remains typed unsupported.

A checksum-pinned WinZip 21.0 installer with SHA-256
`9f05084542ebe3194b42fa4163fa30b8bceb4ac37b99ff15715112f56611d3b7`
was inspected as proprietary test-oracle evidence only. Its embedded
`WINZIP64.EXE`, SHA-256
`f0c9a57449a27c50146e15666c9dfa2f16e9b7cdf48d1ff2ac84220a974c24a1`,
contains the adjacent identifiers `packMP3`, `01/22/2016`, and
`Matthias Stirner`, matching packMP3 v1.0g, plus the C++ class names
`WzPackMP3` and `WzUnpackMP3`. This was strong evidence that WinZip 21 embeds
that codec, but did not by itself prove the ZIP payload boundary. Wrapping
the oracle PMP bytes in a minimal method-94 ZIP produced SHA-256
`703c4dc08435470eaab0f1a3b44ad5569050d189b994cc6b11f9d44e0fce1796`;
`7zz` recognizes the member as method 94 but cannot decode it. That synthetic
archive remains an uncommitted experiment; the later controlled WinZip fixture
below supersedes its fixture role. No proprietary or LGPL source was copied,
translated, or admitted.

For method 96, the earlier independent implementation author's published
[*WinZip JPEG Errata*](https://github.com/mietek/theunarchiver/wiki/WinZipJpegErrata)
records specification omissions and errors that prevent a complete decoder
without reverse engineering, including still-unresolved coding details. The
prohibited LGPL-2.1 XADMaster source identified above remains unusable.

A later search found a separate MIT implementation in XArchive, pinned at
commit `c17ca22a2ae75f1d6f97d0a56725655c49b97295`. Its repository `LICENSE`
SHA-256 is
`abdeb212f229d2b93a5c315763df4d7201c7d74f580ad9dc77d77dec7cbc6c69`.
The method-96 decoder first appears as 2,205 new lines across three files in
commit `0d071ffcd6b48ffcf39eefb434d431b6bb985a5a`, relative to parent
`b95039d5200ad4870d32c931d0d5d970441053fd`; the initial C++ file SHA-256 is
`a3e9f9e61f1ff24511dd72cc71405edb4368d27085e213a4d1d5dbf2f65d270e`.
Commit `8ee96bb93ab9c7e65451de979c4215b0eb36f4b9` then makes only a 15-line
addition/16-line deletion reformat. At the pinned revision, the C++, header,
and arithmetic-table file SHA-256 values are respectively
`5c6a7b7dfd34e519d90bed845f8a63a8213e86539ab5bba709d7f4f74040f6fe`,
`c4b8034c8e10b6a22768fe2a05da54862a34e1d6b2de1d0b92867a4817450dbe`,
and `7520d2355c70c04d8ebe8519b27a452af341d8756ea2f68d612e73acc2f9eff7`.
The source identifies the official 2008 specification and expired U.S. patent
4,791,403 as its basis and records five stream-verified specification
corrections. The three files and their introduction commit carry no XAD
attribution or license marker; this is positive declared-provenance evidence,
not proof beyond the published history.

The XFileUnpacker 0.1.0 Beta Ubuntu package was retained only as an external
binary oracle. Its SHA-256 is
`060fd956663da7177d03b1fb7d364e3de5f2597f9b9d5ad06182900d8c245cf6`.
In a read-only, network-disabled container with strict one-member and 1 MB
output limits, it decoded the known method-96 archive to a 57,105-byte JPEG
with SHA-256
`1bd83e1af9ff68f664eb01e66d02abba23e7edb0fd12adee6182af3e6f496c63`
and ZIP CRC-32 `D30F1F39`. That output matches an independent `unar` oracle byte
for byte. This validates the candidate on a real stream, but the source is not
admissible unchanged: it depends directly on C++/Qt and native LZMA, allocates
as much as 512 MiB per scan component rather than under an aggregate project
limit, does not reject zero or missing quantization tables before divisions,
does not require exact inner-LZMA or outer method-payload consumption, and has
no explicit bundle-count or total decode-work budget. A Rust adaptation must
replace all allocation and arithmetic with checked project primitives, validate
JPEG table presence and values before decode, apply aggregate input/output/
memory/work/cancellation limits, and require exact payload consumption.

The 2026-09-16 admission implements those requirements in safe Rust without
linking XArchive, Qt, native LZMA, or any external process. The exact adaptation
map is:

- XArchive probability constants, `WZJPEG_BIN`, `WZJPEG_BAC`, and
  `wzjpegBac*` functions map to `Bin`, `ArithmeticDecoder`, `q_smaller`,
  `q_bigger`, `log_x`, and `antilog_x` in
  `crates/unpackio/src/decode/winzip_jpeg.rs`;
- `WZJPEG_METADATA`, `wzjpegParseMetadata`, and its DHT/DQT/DRI/SOF/SOS
  branches map to `Metadata` and `parse_metadata` plus the marker-specific
  helpers, with added exact segment sizing, canonical Huffman validation,
  duplicate detection, table-presence checks, and nonzero quantizers;
- the zigzag facts and `wzjpegSum`/`Average`/`BDR`, binarization, AC/DC sign,
  magnitude, prediction, and block routines map to the checked coefficient and
  `decode_*` functions; all hostile arithmetic is widened and checked before
  narrowing to JPEG coefficient storage;
- the nine model arrays map to one fallibly allocated, bounds-indexed `Models`
  vector with the same 28,328-bin layout; `wzjpegDecodeSlice`, Huffman output,
  restart handling, and `wzjpegProcessStream` map to `decode_slice`,
  `ScanWriter`, `encode_slice`, and `decode_zip_jpeg`;
- `xwinzipjpegdecoder_tables.inc` maps value-for-value to
  `winzip_jpeg_tables.rs`. These finite-precision coder tables retain the
  upstream MIT attribution and exact notice in `LICENSES/MIT-xarchive.txt`.

The resulting admitted Rust files have SHA-256 values
`0f3953679e2338231a619adc8ec601b2fdd6b49b96e799c882c877aa94fa7229`
for `crates/unpackio/src/decode/winzip_jpeg.rs` and
`c2bb18173dbc54dec9813e1266aad35aa19eebd5d31ec7a2c39390b2be493c82`
for `crates/unpackio/src/decode/winzip_jpeg_tables.rs`. The copied MIT notice
has SHA-256
`abdeb212f229d2b93a5c315763df4d7201c7d74f580ad9dc77d77dec7cbc6c69`.
These hashes pin the reviewed adaptation state; any later source change
requires a new review and hash update.

The rewrite replaces per-component 512 MiB allocation with an aggregate
`max_dictionary_bytes` preflight for models and all active slice buffers,
charges aggregate bundle metadata and bundle/slice counts to
`max_header_bytes` and `max_stream_frames`, checks entry/total output before
growth, and charges cancellation/work throughout input, arithmetic, and output
loops. Compressed metadata uses the existing safe LZMA decoder with a dedicated
known-size exact-input mode. EOI must consume the complete outer method payload,
and the normal ZIP size/CRC gate precedes writer or batch delivery. All new
original safety/integration code is MIT; no XADMaster or 7-Zip/p7zip expression
was used.

The WinZip-labelled `zipdetails` sample at current repository commit
`7adb025fe52a22e80f82b3def18c070872f9cb20`, path
`t/files/0003-winzip/jpeg/winzip-jpeg.zipx`, has SHA-256
`59f4d04d0ba7a9b06830ae82599c125eef8d104e1fd7fb246bbc6530e1d7a3cf`
and was introduced by commit
`3fb43446f347688befadc102a5f102b99a815686`. Neither that commit nor the
corpus documentation identifies an exact WinZip version, authoring command,
original-input provenance, or redistribution terms, so the archive is not an
admissible committed positive fixture. The later controlled fixture below
supersedes that evidence gap; the admitted rewrite above closes the XArchive
safety requirements without admitting that sample.

A subsequent controlled WinZip run on 2026-09-15 completed the missing
positive-fixture and redistribution record for both methods. It used a clean,
network-isolated Windows 11 Enterprise evaluation VM and WinZip 21.0.12288
64-bit evaluation. The installer SHA-256 is
`9f05084542ebe3194b42fa4163fa30b8bceb4ac37b99ff15715112f56611d3b7`,
the extracted `WINZIP210-64.MSI` SHA-256 is
`ed8e850f6a2e97aebc44ebcff6c91232e4b6b06eab71fdea1bbeb75fc0db04a8`,
and the installed `WINZIP64.EXE` SHA-256 is
`f0c9a57449a27c50146e15666c9dfa2f16e9b7cdf48d1ff2ac84220a974c24a1`.
The executable reports product version 21.0 (12288), file version 31.0
64-bit, and a valid Authenticode signature from WinZip Computing LLC.

WinZip's official [default-compression documentation](https://kb.winzip.com/en/130351),
[ZIPX description](https://kb.winzip.com/en/130326), and
[General-options documentation](https://kb.winzip.com/en/130829) describe the
automatic Best-method selection and `.zipx` default. The recorded GUI recipe
enabled **Settings > WinZip Options > General > Create new Zip files using the
(.zipx) file type**, retained **Best method**, created a new archive, added
exactly one local source through **Create/Share > From PC or Cloud**, left
conversion/encryption/watermarking disabled, and saved as `.zipx`. Each final
archive was made in one uninterrupted run.

The method-94 archive has SHA-256
`4cb0f2e7d5fae6f13d708ad79cf4721064675a50f6582d936aa41573e308a841`.
Its sole unencrypted version-2.0 member is the 55,587-byte project-authored MP3
with CRC-32 `E6CDB0AC` and SHA-256
`372d875979967b2d95b48c2ded842a2a6bbd295c50d2455f8ad9829d2826aa0e`.
The 216-byte payload SHA-256 is
`e348bb86122aaf35d1f4c136a0be6e025bf3ce2b5304aa1f17c962b5fff81de6`:
it is byte-identical to the pinned packMP3 PMP oracle, and the locally built
packMP3 binary (SHA-256
`09a51dd32c8c9940409769c5f32219ce704941a9531fa26182363cca6a8cb429`)
decoded it back to the source byte for byte. This proves the WinZip payload
boundary without admitting the LGPL implementation.

The method-96 archive has SHA-256
`47454618f65cef060c2ba1d96b8b36d8028681ac693f9be3d57e791ec57c15e1`.
Its sole unencrypted version-2.0 member is the 7,823-byte project-authored JPEG
with CRC-32 `7422FE59` and SHA-256
`95ef01838a55308006fabf6d2e512123a37916067cce58dd5076c89da43e2244`.
The 3,155-byte payload SHA-256 is
`b8c58ce398a10deae01f74e0632971765f9d6a1df53148584bf91c44e52dc091`.
The checksum-pinned XFileUnpacker package decoded that archive to the source
byte for byte while isolated with a read-only filesystem, no network, dropped
capabilities, `no-new-privileges`, UID/GID 65534, one CPU, 512 MiB memory, 64
PIDs, read-only input, and a 1 MiB output-file cap.

Both source files contain only project-authored test patterns and are released
under the repository's MIT test-fixture terms. The exact originals and archives
are committed as base64 text; `CORPUS.md` records their complete sizes, hashes,
recipe, and oracle use. The proprietary WinZip artifacts, LGPL packMP3 source
and binary, and XFileUnpacker binary/container are not committed or linked and
cannot become runtime fallbacks. Method 94 still has no admissible
implementation source and remains typed unsupported. Method 96's fixture is
the authoritative positive regression for the admitted bounded checked
safe-Rust rewrite above; extraction and verification reproduce the committed
source byte for byte.

For method 97, the archived official WinZip compression-method page
([2009-04-14 snapshot](https://web.archive.org/web/20090414225734/http:/www.winzip.com/comp_info.htm))
adds that the embedded stream must be compatible with WavPack 4.32, but no
public method-97 archive with a complete producer/version/command/input record
was located during that research pass. The fresh WinZip 21 evidence created on
2026-09-16 and recorded below subsequently closed that product-oracle gap. The
official WavPack 4.80 encoder and 5.9 decoder additionally generate and
independently verify the byte stream that APPNOTE places directly in method 97.

The exact crates.io `wavicle` 0.1.0 release was admitted as the source of the
decoder-only local fork in `vendor/wavicle-decoder` after the follow-up audit.
The source crate checksum is
`1e312eaf22b4a7e5b7bf038edb3a7e4703c7b86dfabaea49d17af85e55eb76ab`,
its VCS commit is `4ac1134efe7a85a0b8c5921afc7c124160d179f2`, it has no normal dependency,
forbids unsafe code, and is available under `MIT OR Apache-2.0`; this project
selects MIT. Its published `PROVENANCE.md` maps the decoder to official
WavPack 5.9.0, although its stale `ATTRIBUTION.md` still says no port had
landed and omits the full BSD notice. The repository therefore carries both
exact notices and the independent file-level audit instead of relying on that
stale statement. The fork copies only decoder-reachable source and records all
changes in `vendor/wavicle-decoder/PATCHES.md`:

| `wavicle` 0.1.0 file | Upstream SHA-256 | Vendored SHA-256 | Declared WavPack 5.9.0 derivation / local change |
| --- | --- | --- | --- |
| `src/format.rs` | `d7c191d056b2e671aee2c2226c2e50fc9e5a514249c3806b99471d13d66f4515` | `923c3a16ed8e57272a11d18c2c2df029cf416bc9e5f3985d4515c903b5b935c3` | `include/wavpack.h`, `src/wavpack_local.h` constants; checked sample-rate lookup and decoder-only wording |
| `src/block.rs` | `5792a066d9429ba86e547367ef0a35016d632b41266a4230a5ffe5a09ad1bee5` | `269aea44472429d68bc78c477872fa9976c884238ceb0317bcf4b0377c209ded` | header and `read_next_header` bounds; checked field/range access and length arithmetic, plus corrected legacy 40-bit sample count |
| `src/metadata.rs` | `d10b3435a1b13985970f8244ce6783f7a0eebe0d78f329f9ce04ee15d18d4562` | `f76c1b14ff61cf852b5450dcb7f49bdeb249f33a6a781ca7a18613b4ea025a1f` | metadata framing; checked word-count arithmetic and slicing |
| `src/bitstream.rs` | `c4d3154d9822e9c25fb58a8efc8d8d7147eae929575b3eb865a121c2473ab490` | `53c98f298184b9b3df0c563d8a0e0e30cc9ea33b2928b9cdcfeb59555279d843` | bit-reader macros, `open_utils.c`, `read_words.c`; encoder bit writer removed and read widths/conversions checked |
| `src/entropy.rs` | `71cec5762c25893db45a93c9c82d9a2e27429acd8a459f6ffd04320c1575516d` | `e57e2b67ff108d28ad30809126e00d8442112e322ba20aa50035d91a31f70339` | `read_words.c`, `entropy_utils.c`, median macros; encoder removed, checked dynamic access, and explicit wrapping arithmetic |
| `src/decorr.rs` | `a0a70cb66f5680756730a27b6507d3355ea5a263c7ddf131bfb8c2cdf622c379` | `c239ef1626e1e2cc1fe2d0cabc822deab29f96af624d7490863d6e1a5819101a` | `decorr_utils.c`, `unpack.c`, weight macros; forward encoder passes removed, fallible pass allocation, and checked histories/terms |
| `src/float.rs` | `cda18ad5b38cbe96abc86c0e4c59582849a04f15c9ba0fc361393065c30d0b6a` | `b1b594c233db64211681f14c4f6396b1b2ed292f9b84fefe23900625802cfc0f` | `unpack_floats.c`, float/WVX helpers; encoder removed and signed/unsigned bit conversions made explicit |
| `src/decode.rs` | `2b2896bd956dadbc48513662e81a0e4136b8c9c5ca54aa3602270da93ba90f42` | `3a1caa6bb4f75428dd1e0d70f4f7b8b4ab56225417108939b25bdebab475ab2e` | lossless `unpack.c` driver, CRC, integer and float fixup; Rust 1.85 parity checks, fallible growth, checked slicing/indexing, and explicit bit-preserving conversions |
| `src/error.rs` | `3a87372c2ab1ef397667dee10af74261e53cbc93947853acbd01b2aae69b7638` | `ef1ddde7f9a27533cc38505c1b1d63c46c930bdb6c6137e0500b2086bb76e7b7` | original error model plus typed allocation failure |
| `src/lib.rs` | `8e42755a64e67dae1bbdb5da62b9c4fd9dcff2fbad365e72efb2d2ccfd12abcd` | `086ed33fc9cae593c6203465c8f67726c8d19ef6af68acae0a230956129e0b3e` | decoder-only documentation and exports; no encoder feature or API |

The dependency's `PROVENANCE.md` and stale `ATTRIBUTION.md` hashes are
`57ae47dc861355a99a3f38b5acb22f0b5b39085936da1253e5634acdd40d1332`
and `ebf42172d52780b7f023132e04964a62b9e2d9bb248f0ff60a49faf5803764f2`.
Its MIT text hashes to
`11b8ecad18b2b8e26bab1bdf2e17464d681a6a7ec8ca5bedd296e3d694eb298e`
and is reproduced in `LICENSES/MIT-wavicle.txt`. The local package is renamed
`unpackio-wavicle-decoder`, declares Rust 1.85, has no encoder module, and
adds no dependency. Its new manifest and patch documentation are MIT; copied
upstream source retains its original grant and derived-source notice. The
local `Cargo.toml` SHA-256 is
`7c2e2de71e2f6015b1ea7153fff9a5a46f0acd5888503d954b4a54987fd1bf0e`
and `PATCHES.md` is
`cfd8cb0c087d7b336932a638155c779f0ca6155098d78ae5132bd3ee08ed2950`.

The mapped official source is WavPack tag 5.9.0, commit
`5803634a030e2a11dba602ba057b89cc34486c67`, BSD-3-Clause. Audited file
SHA-256 values are: `include/wavpack.h`
`3c61d65511e258c5dc120a6daaee626d6a1051f3254ca9b67ac654a8f6212a97`;
`src/wavpack_local.h`
`51e187bb5ddb91723808a37c570e661b258e99947dd986481163a27d8f12fd01`;
`src/open_utils.c`
`d1d198ba6d0b6efd11745856dd8a988bf770bccf659ca6aaea557a110c6acaee`;
`src/unpack.c`
`bba495a5c33f432d8acd82a36a52d79d0d2ff7d05a1a5bc6e110ab7a92a9391c`;
`src/read_words.c`
`f35764aebeb8f0a304b453b4a86b4193093551f629f9c5cc8dcb4f444ff6cc1b`;
`src/entropy_utils.c`
`3d750a714829230d09a09701943c40ac10d8d3a8e4145fe9ca353205a18320d1`;
`src/decorr_utils.c`
`3dc93ee065ed9459dfc534614112dcf420c0aa59d222b743157128f4df166110`;
and `src/unpack_floats.c`
`d4b7c9664d43bc284909835cf38e0a70c3a518f7eb10dc4f92e78d559505b3d1`.
The exact upstream notice, SHA-256
`1703dd391c9b422910287add8483a27d9bead0b0b5ccd6d5017e995a7192b3e2`,
is reproduced in `LICENSES/BSD-3-Clause-wavpack.txt`.

`crates/unpackio/src/decode/wavpack.rs` is original MIT adapter code. It uses
the public APPNOTE/WavPack layout to preparse and bound every block and
metadata record, enforce the legacy lossless RIFF/WAVE profile and format
maxima, reconstruct wrapper bytes, interleave legacy multichannel blocks, and
integrate project limits, work, cancellation, panic containment, WavPack CRCs,
and ZIP size/CRC finalization. It calls the local decoder fork one already-bounded
audio block at a time. No encoder module or WavPack C code is linked or
translated into the adapter.

The deterministic committed inputs are project-authored by
`crates/unpackio/tests/fixtures/method97/generate.rb`. Exact official WavPack
4.80 at commit `8256af6b90958f190cf70dfeb7afaed13649776e` (BSD-3-Clause) generated
their legacy `-hh` streams, and exact official WavPack 5.9.0 at the commit
above independently decoded them byte-for-byte. Both executables are test
oracles only. `CORPUS.md` records every command, byte count, and hash.
Upstream `wavicle` commit `3b5938b21b0a52b9224573eef1ae32665dc5add5`
fixes its attribution but changes future source to MPL-2.0; it is not used,
and the local fork remains pinned to the exact permissive 0.1.0 source. The GPL
`symphonia-codec-wavpack`, unreleased `oxideav-wavpack`, native C WavPack,
and incomplete `wavpack-rs` remain rejected as runtime implementations for
the reasons in `DEPENDENCIES.md`. Method 94 remains metadata-only and typed
unsupported; method 96 is independently admitted as described above.

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

The 2026-09-15 history follow-up mapped the four labelled samples to
SharpCompress pull requests
[#661](https://github.com/adamhathcock/sharpcompress/pull/661),
[#722](https://github.com/adamhathcock/sharpcompress/pull/722), and
[#723](https://github.com/adamhathcock/sharpcompress/pull/723). Their commit,
pull-request, issue, and review text describes WinZip authorship but supplies no
exact GUI recipe or command, so the missing record cannot be recovered from
that public history.

Two more public PPMd archives were evaluated as local-only evidence. A
[Launchpad unzip report](https://bugs.launchpad.net/ubuntu/+source/unzip/+bug/393987)
from 2009-06-30 states that its attachment was made on Windows with WinZip, and
the `zipdetails` WinZip corpus contains
`t/files/0003-winzip/el-ppmd/winzip-el-ppmd.zip` at current commit
`7adb025fe52a22e80f82b3def18c070872f9cb20`. Both decode and pass integrity
checks, but neither source records the exact WinZip version and authoring
command. Their input redistribution provenance is also incomplete. They were
therefore not committed and did not by themselves satisfy the
reproducible WinZip-PPMd requirement; their byte-level evidence is recorded in
`CORPUS.md`.

That requirement and the four command-incomplete evidence roles were closed on
2026-09-16 with fresh archives from explicitly versioned official WinZip
installations in an offline Windows VM. WinZip 21.0 build 12288, identified by
the already pinned signed `WINZIP64.EXE` SHA-256
`f0c9a57449a27c50146e15666c9dfa2f16e9b7cdf48d1ff2ac84220a974c24a1`,
created one PPMd method-98 archive and one Best-Method-selected WavPack
method-97 archive from project-authored inputs. Their archive SHA-256 values
are respectively
`7ce980e5e69c83416ef0b010318212498203146128cb1f7ef3f3bf8a98fa8dbb`
and
`f4ac3979e467ab6da8204448e5c4c9023e7708c53e38b8f222978d803d0f16fd`.

WinZip's official legacy-download page supplied `winzip240.exe` over HTTPS.
The download had SHA-256
`d0ba9969dbf653e8be5e09e653eab3dc0cf9229992e805a7ccdea57ba4f8372d`
and a valid Corel Corporation Authenticode signature. Its embedded signed
64-bit MSI had SHA-256
`5cf5ebc086513f314165d97876c2727b9e0bf687eab4ce897202a443b54b3bd8`.
The installed signed executable reports product version `24.0 (14033)`, file
version `33.0 (64-bit)`, and SHA-256
`53c8ef7c606e2ff38ebd116216642e2d489fc424d52c058536985dc80f0e12ab`.
It created BZip2, ZIP-LZMA, XZ, and Zstandard ZIPX archives with SHA-256 values
`b9e29b673894538ac684f5969bf7a1b659261c6c7a4b6e44493a921bdd2a6a69`,
`99f5fde3b733db5f29c45b4ad93abca595c41c8896043006aca19d94a162133f`,
`730a78de0a36a82a2dbcd258a0ab1e65f385c6ba36f2f4c53ba9c7877fd27257`,
and
`49d159dd440832a05ba7e4ff3807b0c432d2c6af766547e525eb6a8f30c1401e`.

`CORPUS.md` records the exact input identities, GUI selections, member
inventories, hashes, and local-only decision. Stock `7zz` 26.02 independently
validated the PPMd and four replacement archives; it identifies but cannot
decode method 97. The production Rust decoder extracted every input exactly
and completed full verification through three ignored harnesses in
`winzip_reference`. No WinZip installer, executable, MSI, archive, or VM image
is committed, linked, invoked at runtime, or used as a fallback.

| Component | Exact origin/revision | License | Use and adaptation status |
| --- | --- | --- | --- |
| ZIP records, ZIP64, descriptors, method IDs, flags, extras, and traditional encryption facts | PKWARE APPNOTE 6.3.10 (2022-11-01), official `APPNOTE.TXT`, retrieved 2026-07-21 | Specification; no source code imported | Independently expressed checked parser/model and legacy ZipCrypto state machine; MIT project code |
| ZIP XZ method 95 | WinZip *Additional Compression Methods Specification* 3.1 (2014-04-14), Internet Archive snapshot `20150121121519id_`, SHA-256 `8f584a40114fb5ec9c440f7a7f6a5e4200def378d6b564e1a434410cb1328c6e`; PKWARE APPNOTE 6.3.10, SHA-256 `0b993022a7d320a0bf704e6980bea36fafd17a6066ab994db0a0c16278a50cd6`; retrieved 2026-09-14 | Format specifications; no source code imported | Exact one-Stream XZ 1.0.4 profile, optional zero padding, Deflate-equivalent version-needed rule, per-Block/Index exactness, and ZIP member-integrity integration independently expressed in MIT Rust |
| ZIP MP3/JPEG methods 94/96 fixture evidence | Project-authored source media and fresh WinZip 21.0.12288 one-member archives created 2026-09-15; exact source, payload, archive, installer, MSI, and executable hashes plus the GUI recipe are recorded above and in `CORPUS.md` | Source media and generated fixture selection under MIT project test-fixture terms; proprietary WinZip, LGPL packMP3, and XFileUnpacker are external oracles only | Committed metadata/payload/output vectors. Method 94 remains typed unsupported; method 96 is a byte-exact positive decoder regression. No oracle binary/source, runtime process, or fallback is admitted |
| ZIP MP3 method-94 clean-room differential corpus | Original deterministic integer-PCM generator, one directly constructed standards-based intensity-stereo input, and 54 MPEG-1 Layer III inputs created 2026-09-16; official LAME 4.0 source archive SHA-256 `3df5124d5ad3a98312ffd7ba6a9b36230e4f8a3e66d3ce0f425e336c32d216eb`; pinned packMP3 v1.0g oracle binary SHA-256 `09a51dd32c8c9940409769c5f32219ce704941a9531fa26182363cca6a8cb429`; complete per-case hashes and commands in the committed manifest | Generator, waveform selection, generated media, and independent envelope analyzer under MIT project test-fixture terms; LGPL LAME and packMP3 remain temporary external generator/oracle tools only | 54 unique MP3/PMP known-input pairs, 108 base64 files, byte-exact independent oracle round trips, repeat-generation identity, and mechanical proof of observable envelope bytes 0..10 including all byte-4 feature bits. The byte-11 entropy stream remains unresolved; no external source/binary/process is shipped and method 94 remains typed unsupported |
| ZIP JPEG method 96 decoder | XArchive commit `c17ca22a2ae75f1d6f97d0a56725655c49b97295`, introduced at `0d071ffcd6b48ffcf39eefb434d431b6bb985a5a`; exact upstream file hashes and symbol-to-Rust mapping recorded above | MIT; exact notice in `LICENSES/MIT-xarchive.txt`; new safety/integration code MIT | Safe in-tree adaptation with checked allocation/arithmetic, canonical/table validation, aggregate limits, work/cancellation, exact inner declared-byte and outer payload consumption, supported sequential-profile classification, and normal ZIP size/CRC/encryption integration; no C++/Qt/native dependency, writer, or fallback |
| ZIP WavPack method 97 framing and adapter | PKWARE APPNOTE 6.3.10 section 5.9; official *WavPack 5 Library Documentation* dated 2024-02-15, SHA-256 `8622c1b780788227d05602bda8fa8690f0ba425252c6d5ffee72e751329652ee`; archived official WinZip method page dated 2009-04-14; fresh WinZip 21.0.12288 archive SHA-256 `f4ac3979e467ab6da8204448e5c4c9023e7708c53e38b8f222978d803d0f16fd` | Format/product documentation; no implementation source imported; adapter and project input MIT; proprietary archive local-only | Original checked legacy lossless RIFF/WAVE stream parser, wrapper reconstruction, multichannel orchestration, limits/work/cancellation, and ZIP integrity integration. Fresh Windows WinZip output passes byte-exact production extraction and full verification |
| WavPack payload decoder | Local `unpackio-wavicle-decoder` fork of `wavicle` crates.io 0.1.0, source checksum `1e312eaf22b4a7e5b7bf038edb3a7e4703c7b86dfabaea49d17af85e55eb76ab`, commit `4ac1134efe7a85a0b8c5921afc7c124160d179f2`; upstream and vendored file hashes and its declared mapping to WavPack 5.9.0 commit `5803634a030e2a11dba602ba057b89cc34486c67` recorded above | Copied source MIT selected from MIT OR Apache-2.0; local patch code MIT; derived WavPack portions retain BSD-3-Clause notice | Decoder-only path dependency behind the method-97 checked adapter; patched for Rust 1.85, fallible allocation, checked hostile-input access/arithmetic, and exact legacy sample-count reconstruction; no encoder source/API, native FFI, archive parser, or command fallback. Exact MIT and WavPack BSD texts are shipped in `LICENSES/` |
| ZIP PPMd method 98 framing | WinZip live *Additional Compression Methods* specification and PKWARE APPNOTE 6.3.10, retrieved 2026-09-14 | Format specifications; no source code imported | Exact two-byte property prefix, PPMd-I revision-1 selection, order/memory/restoration bounds, end-marker requirement, and Deflate-equivalent version-needed rule independently expressed in MIT Rust |
| ZIP PPMd-I revision-1 decoder | Dmitry Shkarin `ppmdi1.rar`, SHA-256 `5a559300c26949fc5dd015983bfe680fd9a32c2b4afb85320dc9b38f90f8c5d6`; separately published original-source mirror files at OpenXRay commit `bcefa731baf3add37c33348ec709ab391a9032a2`; SharpCompress I1 port by Michael Bone at commit `e04d51176c5d87668c4c8779825342230c33aa74`; hashes above | Original sources state public domain; SharpCompress MIT; new Rust code MIT | Safe, fallible adaptation of the original context model, allocator, restoration modes, and Dmitry Subbotin carryless range coder, with managed layout/control-flow cross-checking; no OpenXRay trained-model extension and no 7-Zip-derived implementation used |
| Fresh WinZip ZIPX interoperability evidence | WinZip 21.0.12288 signed executable and WinZip 24.0.14033 official signed installer/MSI/executable, exact hashes above; six local-only archives over project-authored inputs with complete GUI recipes and hashes in `CORPUS.md` | Project-authored inputs and ignored Rust harness MIT; proprietary WinZip tools and generated archives remain uncommitted external test evidence | Method 97 and 98 product parity plus reproducible BZip2, ZIP-LZMA, XZ, and Zstandard replacements; stock-`7zz` inventory/integrity where supported and production byte-exact extraction/full verification for all six; no runtime dependency or fallback |
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
