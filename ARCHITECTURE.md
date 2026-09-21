# Architecture

Status: Phase 7 Python binding plus separate ZIP, RPM, CPIO, Debian, ARJ, and standalone stream readers,
2026-07-21. The
bounded byte parser, borrowed raw grammar, separate graph validator, semantic
model validator, owned metadata model, arbitrary-graph executor, core decoders,
crypto/password layer, sequential volume assembly, supported external metadata,
external-folder resolution, and CRC-finalizing member APIs are implemented
behind a curated public surface. A separately locked PyO3/maturin adapter
exposes that surface without moving parser or decoder logic across the FFI
boundary. The Python package is the consumer product; no CLI or console script
is shipped. Constant-memory
decoder pipelines remain future work.

## Design goals

The core treats every archive byte, declared count, offset, size, coder
property, filename, and volume response as untrusted. Parsing, semantic
validation, graph construction, decoding, volume access, and filesystem policy
are separate layers. The Python FFI wrapper does not reinterpret internal
parser state or copy complete decoded entries merely to cross the boundary.

The core is unpack-only. It will not expose compression, archive creation,
archive mutation, or implicit filesystem extraction. `Archive` remains the 7z
container; `ZipArchive`, `RpmArchive`, `CpioArchive`, `DebArchive`,
`ArjArchive`, and `CompressedStream` are separate validated models with no
lossy generic-archive normalization layer.

## Data flow and trust boundaries

```text
VolumeProvider
    -> bounded byte access / SFX and volume layout
    -> raw parser (syntax only, bounded sub-readers)
    -> semantic validator -> graph validator (DAG and resource plan)
    -> validated archive model (all cross-reference invariants)
    -> decoder executor (checksums, limits, cancellation)
    -> member reader / caller-provided sink

Raw UTF-16 path metadata -----------------> explicit safe-path validator

Owned bytes/path
    -> standalone magic or explicit format
    -> bounded LZ4/Zstandard frame table or Unix `.Z` header
    -> format decoder (limits, work, cancellation, declared checksums)
    -> caller-provided writer

Owned ZIP bytes/path + optional per-archive byte password
    -> bounded SFX/EOCD/ZIP64 location
    -> exact central/local/extras/descriptor validation
    -> concrete ZipEntry model
    -> authenticate/decrypt -> method decoder -> size/CRC verification
    -> caller-provided writer or entry sink

Owned RPM bytes/path
    -> bounded lead/signature/main-header parser
    -> typed index/store model + supported digest verification
    -> bounded payload decompressor
    -> exact newc/CRC-newc CPIO model
    -> caller-provided writer or entry sink

Owned standalone CPIO bytes/path
    -> exact checked layout dispatch (newc/CRC-newc/odc/binary)
    -> bounded names/ranges/alignment/trailer + applicable checksum
    -> concrete CpioEntry model -> caller-provided writer or entry sink

Owned Debian package bytes/path
    -> checked System V ar + Debian 2.0 member-order validation
    -> bounded control/data decompressor -> checked tar/pax/GNU model
    -> concrete DebMember/DebEntry model -> caller-provided writer or entry sink

Owned ARJ bytes/path
    -> bounded SFX scan -> checked main/local/extended headers and CRCs
    -> concrete ArjEntry model -> method decoder -> member CRC
    -> caller-provided writer or entry sink

Raw non-7z byte names ------------------> explicit safe-path validator
```

No layer may make a lower layer's unvalidated representation public.

ZIP uses `rawzip` only to locate and iterate the central structure; the
project parser independently validates every local/central range, ZIP64 extra,
descriptor, method/encryption declaration, overlap, and end-of-input boundary
before constructing `ZipEntry`. Decoder adapters receive only those validated
ranges. Traditional ZipCrypto and WinZip AES live in the ZIP crypto module and
cannot share password state with 7z.

ZIP XZ method 95 delegates only bounded LZMA2 Block data to the shared checked
XZ layer; ZIP WavPack method 97 reparses and bounds legacy lossless RIFF/WAVE
blocks before calling its safe-Rust decoder one block at a time; ZIP PPMd
method 98 has a distinct checked PPMd-I revision-1 model and does not reuse the
7z PPMd7 variant-H decoder. All three adapters receive the
validated entry's declared size and one shared operation control, enforce their
format-specific termination and exact-consumption rules, and return a complete
bounded buffer to the normal ZIP size/CRC and pre-delivery boundary. Method 96
adds a bounded metadata-bundle/LZMA layer, persistent validated JPEG tables,
slice-local arithmetic-coded DCT reconstruction, and exact Huffman scan
re-encoding before that same integrity boundary. Registered method 94 stops at
a typed dispatch error and has no decoder layer.

RPM header parsing produces ordered typed values without interpreting arbitrary
tag bytes as UTF-8. Package-level digest selection occurs before payload
decompression. The payload decoder returns one bounded CPIO image, and the
CPIO parser then validates names, alignment, file ranges, trailer placement,
and CRC-newc checksums. The retained decoded image makes entry reads cheap and
deterministic but is explicitly not a constant-memory RPM pipeline.

The standalone CPIO parser is also the RPM payload parser, so record alignment,
range, trailer, and checksum rules have one implementation. Debian owns its
`ar` and tar grammar privately rather than exposing a generic nested-archive
stack; both decoded tar images remain bounded retained state. ARJ uses a
project-owned checked header parser. Its method 1–3 payload adapter invokes
only the pinned `delharc` LH6 decoder behind dictionary/work/cancellation and
panic boundaries; no dependency header parser is used. Method 4 is an in-tree
checked bit/history decoder. These modules cannot share password or volume
state with 7z or ZIP.

## Layer responsibilities

### Byte and property parsing

The raw parser owns 7z variable-length integers, little-endian values, bitsets,
property tags, and bounded byte ranges. Every length-delimited property is
parsed through a child reader limited to exactly the declared length. A known
property must consume that reader exactly; an unknown but structurally valid
property is retained or skipped only according to the specification.

The parser performs checked offset arithmetic and fallible conversions before
allocation. It does not build decoder pipelines and does not decide whether a
raw path is safe.

The implemented Phase 2 byte layer uses a bounded slice reader, validates
total-input/header/SFX bounds, and checks cancellation and work budget while
scanning, checksumming, and reading records. `raw.rs` parses borrowed syntax
records and owns no validated claims. Fixed fields become a `HeaderEnvelope`
only after start/next-header CRC, version, identifier, and absolute-range
validation. Length-delimited file properties stay borrowed until `validate.rs`
parses each known property through an exact bounded reader or retains an
unknown payload according to its declared length.

### Validated archive model

Conversion from raw records to the validated model is the only place that may
resolve indices and counts. It must validate, before decoding:

- file, folder, coder, input-stream, output-stream, packed-stream, substream,
  and CRC-array counts;
- all bind-pair and packed-stream indices, with required uniqueness;
- checked totals and ranges for packed bytes, unpacked bytes, names, and
  external property streams;
- the exact mapping of non-empty files to substreams, independently of path
  validity;
- optional CRCs and optional unpack sizes without sentinel values; and
- external properties, additional streams, archive properties, StartPos,
  anti-items, and comments as their phases are implemented.

Raw UTF-16 code units remain attached to member metadata. A decoded display
name is additional metadata and cannot replace the raw code units.

The implemented model preserves inline names, times, attributes, StartPos,
empty/anti flags, archive/comment/unknown properties, and external property
definitions. `metadata.rs` provides the shared AdditionalStreamsInfo processor,
verifies packed/folder/substream CRCs, and applies external Name, FILETIME,
attribute, and StartPos values through exact bounded readers. Metadata
resolution retains the decoded folder outputs because `DataIndex` may select
any of them; archive verification instead consumes and drops one decoded folder
before starting the next. For external main-folder
definitions, the first parse validates AdditionalStreamsInfo and `DataIndex`,
then stages a bounded copy of the stored header. The archive layer decodes each
AdditionalStreamsInfo folder once, verifies its packed, folder, and substream
CRCs, selects the indexed folder output, reparses exactly the declared folder
count from that output, requires exact consumption, and revalidates the
complete header. `DataIndex` selects a decoded folder output, not an individual
logical substream. The same decoded outputs are reused for external file
properties. File-to-substream cardinality is exact and is resolved independently
of path safety.

### Stream graph

A folder becomes a graph of typed input and output ports. Graph construction
does not rely on coder declaration order. It validates every port index,
rejects duplicate bindings and duplicate packed inputs, detects cycles, and
requires the format-defined root structure. A topological execution schedule
is derived only after validation.

The implemented graph layer is isolated in `graph.rs`. It constructs port
ownership, validates bind and packed-input domains/uniqueness/partitioning,
requires one root output, rejects cycles, and returns an immutable
dependency-respecting coder order. `validate.rs` combines that result with
validated coder properties, optional output sizes, CRCs, and substreams; raw
indices never reach a decoder-facing model unchecked.

This representation must support arbitrary valid graphs, including multi-input
coders such as BCJ2. A method implementation receives only validated property
bytes, validated optional sizes, bounded inputs, an allocation account, and an
operation control object.

### Decoding and verification

Decoder constructors validate properties and account dictionary or working
memory before allocating it. Read loops check cancellation and work budget
between bounded input reads and decoder iterations. Output accounting is done
before bytes are returned to the caller.

Checksum layers are distinct: start header, next header, packed stream,
additional stream, decoded encoded header, folder stream, and member. `None`
means no checksum is present; CRC value zero is a real checksum value. A
convenience extraction call reports success only after member CRC verification.
A streaming member reader exposes `finish()` because `Drop` cannot return
verification failures.

An unknown unpacked size remains `None`. EOS-based decoding is permitted only
for methods whose 7z framing and codec semantics make the end unambiguous;
otherwise the operation returns `UnsupportedFeature` with a stable feature
name.

The executor materializes validated packed inputs, walks the immutable
topological coder order, moves each unique bound output to its destination
port, and requires the one validated root output. Copy, LZMA, LZMA2, Delta,
BCJ, BCJ2, PPC, ARM, ARM64, SPARC, Deflate, BZip2, PPMd, Brotli, LZ4,
Zstandard, Deflate64, IA64, ARM Thumb, RISC-V, Swap2, Swap4, and AES are
dispatched only after arity, property, memory, and output validation.
Deflate64's fixed 64 KiB window is included in validated folder resource
accounting before packed bytes are copied. Multi-input BCJ2 is supported; an otherwise valid
multi-output method has no registered decoder and returns a typed unsupported
feature rather than being reshaped into a chain.

Before packed input is copied, execution preflights every coder registration,
arity, and fixed property length. It constructs one checked output-to-input
binding table, so execution is linear in coder ports and bind pairs rather than
rescanning the graph at every node. Archive operations preflight all declared
substream sizes against the per-entry limit. A single unknown final substream
receives only the remaining per-entry allowance; an unknown non-final size is a
typed unsupported feature before decode begins.

Unknown coder output is admitted through an explicit method allowlist. Copy
and size-preserving filters derive their result size from bounded packed input;
BCJ2 terminates at its bounded main input; LZMA/LZMA2 require their codec EOS;
and raw Deflate/Deflate64 require their final block and enforce packed-input
consumption. PPMd and AES require declared sizes. The current generic reader
adapters for BZip2, Brotli, LZ4, and Zstandard are conservatively rejected for
unknown output because their internal buffering does not expose exact frame
consumption to this layer.

Current decoding is bounded but one-shot: one folder output is retained in a
`Vec` and a `MemberReader` exposes bounded slices of that buffer while tracking
the member CRC. LZMA uses this accounted output as history instead of allocating
a second declared-size dictionary. This honors configured memory/output limits
but is not a constant-memory decompression stream. `Archive::verify` first
decodes every AdditionalStreamsInfo folder, including unreferenced folders,
sequentially and verifies its packed, folder, and logical-substream CRCs. It
drops each additional folder before decoding the next, then decodes each main
solid folder once and verifies its substreams in natural order. Additional and
main folders share the same total-output allowance, configured dictionary and
KDF limits, per-archive password, work budget, and cancellation token.
`Archive::extract_entries_to` follows the same one-decode-per-folder path and
emits bounded chunks to a caller-owned `EntrySink`; it calls `finish_entry`
only after that member CRC succeeds, and only after the containing folder CRC
has already succeeded. Random member access may re-decode from the folder
start.

### Standalone compressed streams

`stream/mod.rs` owns the public `CompressedStream` session, common operation
control, output limits, bounded decoder input, and format detection.
`stream/cursor.rs` is the checked structural cursor.
`stream/lz4.rs`, `stream/zstandard.rs`, and `stream/unix_compress.rs` own their
format-specific validated layouts and decoding boundary. These modules do not
construct `Archive`, `FileEntry`, folders, graphs, paths, volumes, or password
state.

LZ4 and Zstandard scan the complete bounded input into a fallibly grown frame
table before extraction. Data plus skippable records count against
`max_stream_frames`; declared content/window/block sizes and all ranges are
checked before decoder construction. Exact data-frame slices prevent a decoder
from consuming a following frame. Declared header/block/content checksums are
not optionalized away. A dictionary ID is preserved in aggregate info but
requires a future explicit dictionary-provider contract, so extraction returns
typed unsupported.

Unix `.Z` has one header and no frame table. Its full prefix, suffix, and
expansion storage is calculated from the 9- through 16-bit header and checked
against the dictionary limit before fallible allocation. Width transitions,
CLEAR resets, code groups, prefix chains, input, output, work, and cancellation
are checked inside the decoder. The format has no output-size or checksum field
and the model keeps that absence explicit.

`extract_to` is the default output surface and never selects a path. The
convenience core-only `decompress` uses a fallibly growing bounded vector.
Python exposes only writer/callback output. No command-line frontend exists.

### Volumes

`VolumeProvider` decouples logical volume requests from paths, memory buffers,
and future callback adapters. The archive-owned assembly loop enforces
`max_volumes` and `max_total_input_bytes`, validates each reported length before
capacity reservation, performs fallible allocation, checkpoints before the
callback and between bounded reads, and returns `MissingVolume` with the exact
expected sequential name when the logical archive requires that part.

The archive layer, not a provider, owns `.001`, `.002`, ... sequence semantics.
`PathVolumeProvider` and `MemoryVolumeProvider` are current implementations.
The logical bytes are concatenated only within count/aggregate limits, so
encrypted blocks and packed streams crossing boundaries use the same parser and
decoder ranges as single-volume input. A terminal missing part is ignored only
after the complete logical archive range validates.

### Filesystem policy

The archive model preserves names and entry ordering even when a name is
unsafe. Path validation is an explicit, side-effect-free query and never
removes or reorders members. It rejects parent traversal, roots, drive prefixes,
UNC/device prefixes, and NULs using both slash conventions. There is no
automatic filesystem extraction in the initial API.

Any future extraction adapter must separately define collision, symlink,
hardlink, platform-name, and time/attribute policy and must use caller-provided
destinations.

### Password state

Passwords belong to one archive object and are stored as zeroizing UTF-16LE
bytes. AES properties and `max_kdf_power` are checked before hashing; KDF rounds
consume work budget and observe cancellation. Derived keys, IVs, and digest
buffers are zeroized. There is no process-global password or derived-key cache.
AES-256-CBC and SHA-256 use the exact RustCrypto crates admitted in
`DEPENDENCIES.md`, not handwritten primitives.

## Public API

Phase 6 freezes concrete, FFI-mappable metadata, option, resource, and error
types that map directly to:

- `open_path`
- `open_bytes`
- `open_volumes`
- list metadata
- `extract_entry_to`
- bounded streaming or callback extraction

Decoder internals, raw graph nodes, generic parser types, borrowed parser
buffers, and folder/substream indices are not stable public API. The hidden
`unstable-internals` feature exposes them only to repository structural tests
and fuzzers and is off by default. `Archive`, `FileEntry`, `ArchiveResources`,
`MemberReader`, `EntrySink`, limits/errors, path validators, and volume traits
form the supported root surface documented in `API.md`.

The additive standalone root surface consists of `CompressedStream`,
`StreamFormat`, concrete stream-info records, and verified extraction totals.
It avoids generic decoder or borrowed frame types so it remains FFI-mappable.

`ArchiveResources` accounts owned logical input, validated-model payload, and
zeroizing password storage. An active `MemberReader` separately reports the
complete folder output it retains. Dictionary/window allocations and decoder
output remain constrained by their configured limits; allocator metadata and
stack frames are not reported as archive payload.

## Python boundary

`bindings/python` is excluded from the Rust workspace and has its own lockfile,
deny policy, package metadata, tests, and binding-specific `AGENTS.md`. The
distribution is `unpackio`; maturin installs the ABI3 native extension as
`unpackio._native`. The core has no PyO3 or Python dependency, and no
executable target is shipped.

`open_path`, `open_bytes`, and `open_volumes` construct the same owned Rust
`Archive`. Python metadata objects are owned `FileEntry` snapshots, including
exact UTF-16 units and optional values. The binding exposes no raw parser,
validated wire-model, or coder-graph type and cannot derive a filesystem path.

`open_stream_path` and `open_stream_bytes` construct the separate core
`CompressedStream`, optionally from one of the stable string aliases documented
in `API.md`. Immutable `StreamInfo` exposes only concrete optional fields.
`CompressedStream.extract_to` and `.stream` reuse the bounded Python sink
adapter while Rust decoding stays detached; `.verify` discards output. No
whole-output Python return or inferred output filename is provided by the
native stream/archive classes.

Format-specific values are exposed directly by the native `ZipArchive`,
`ZipEntry`, `RpmArchive`, `RpmEntry`, and `RpmHeader` classes. Named RPM
headers are projections of retained typed values; the numeric/order-preserving
header remains canonical. There is no second Python parser, decoder,
cryptography implementation, or whole-member convenience API above these
classes.

Every archive-processing or caller-invoking Python operation has an explicit
unwind guard; trivial values and generated class-field access remain behind
PyO3's native trampoline. Parsing, KDF work,
decoding, volume assembly, and CRC verification execute inside
`Python::detach`; only provider, writer, and callback invocations reattach.
`extract_entry_to` adapts a Python `write(bytes)` method and `stream_entry`
adapts a callable to the core's CRC-finalizing single-entry path.
`extract_entries_to` adapts a structural begin/write/finish sink directly to
the core's natural-order `EntrySink`, using one work budget and cancellation
token for the complete batch. The core supplies bounded I/O chunks (currently
at most 8 KiB) while retaining 4 KiB cancellation/work checkpoints. Partial
writer counts are honored, impossible
counts are rejected, callback `False` cancels, and raised Python exceptions
are preserved. Batch `finish_entry` remains the per-member CRC trust boundary;
no callback name is used as a filesystem destination.

Python volume providers are callables or objects with
`open_volume(index, expected_name)` returning `bytes` or `None`. A returned
byte string is length-checked before its Rust copy; core volume count,
aggregate input, cancellation, and work accounting remain authoritative.
Python allocated the source object before Rust sees it, so caller-side Python
memory is outside archive resource accounting.

The binding stores no global operation state. Archives are immutable behind an
`Arc`; cancellation and work budgets are per operation; Rust password copies
are zeroized, then the core retains only its per-archive secret representation.
The original Python `str` remains Python-owned and cannot be cleared by Rust.

## Solid extraction

Natural-order solid extraction decodes each folder once, verifies the folder
before delivery, and verifies each substream/member before the corresponding
sink finalization. The current decoder still materializes the bounded folder
output before those callbacks. Random access may require re-decoding from a
folder start and will be explicit about that cost. Cache designs may not weaken
output limits, CRC verification, password isolation, or memory accounting.
The 10,000-substream deterministic work-budget regression proves a linear
entry/substream walk for verification and sink extraction, and the release
benchmark measures the same one-folder-per-iteration path.

## Unsafe code

The core crate forbids unsafe code. Admitted third-party crates remain behind
safe, bounded adapter APIs; their feature/unsafe audit is in `DEPENDENCIES.md`.
If a future in-repository decoder cannot be delivered
without unsafe code, it must live in a separate crate, have a written necessity
and invariant audit, expose a safe bounded interface, receive dedicated Miri or
sanitizer coverage as applicable, and be approved as a separate review. No such
exception exists in the current implementation.
