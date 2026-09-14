# Python API and Rust core contract

The supported consumer product is the Python `unpackio` package. It installs
no CLI or console script. The separately built Rust crate is the implementation
contract used by the PyO3 binding and repository tests; it is retained as a
concrete, FFI-friendly boundary rather than published as an executable.

Phase 6 freezes the supported Rust surface for the `0.1.x` line. Patch releases
will not remove or incompatibly change documented root exports, public method
signatures, error categories, metadata meanings, CRC success boundaries, or
default limit values. A breaking API change requires a `0.2` version and an
explicit migration note. Additive variants may appear only on types marked
`#[non_exhaustive]`.

The supported surface is:

- `Archive::open_path`, `Archive::open_bytes`, and `Archive::open_volumes`,
  including their per-session password forms;
- archive-order `FileEntry` metadata listing, with raw UTF-16 names and
  `Option` size/CRC values;
- `Archive::open_member` plus `MemberReader::read_chunk` and mandatory
  `MemberReader::finish`;
- `Archive::extract_entry_to`, verified in-memory extraction, verification,
  and natural-order `EntrySink` extraction;
- concrete error, limit, cancellation/work, path-policy, resource-accounting,
  and volume-provider types exported at the crate root.

The 2026-07-21 additive standalone-stream surface is deliberately not folded
into `Archive`:

- `CompressedStream::open_path`, `CompressedStream::open_bytes`, and their
  explicit-format `*_as` forms;
- concrete `StreamFormat`, `StreamInfo`, `StreamInfoKind`, and format-specific
  information records; and
- `CompressedStream::extract_to`, `decompress`, and `verify`, which return
  success only after decoder finalization and every declared frame checksum.

`CompressedStream` represents one unnamed byte stream. It has no member list,
raw path, archive metadata, password, or volume-provider API and never derives
an output path. Unknown decoded size remains `None`.

The 2026-07-21 non-7z extension is additive and uses concrete container
types rather than changing the 7z-specific `Archive` contract:

- `ZipArchive::open_path`, `open_bytes`, and their byte-password forms;
- archive-order `ZipEntry` metadata, raw byte names/comments/extra fields,
  ZIP64 sizes/offsets, methods, encryption, DOS time, Unix mode, and safe-path
  status;
- `ZipArchive::extract_entry_to`, `extract_entries_to`, and `verify`;
- `RpmArchive::open_path` and `open_bytes`;
- ordered typed `RpmHeader`/`RpmHeaderEntry` values and byte-preserving
  `RpmLead`/`RpmEntry` metadata; and
- `RpmArchive::extract_entry_to`, `extract_entries_to`, and `verify`.
- `CpioArchive::open_path`/`open_bytes`, archive-order `CpioEntry` metadata,
  `symlink_target`, extraction, batch extraction, and verification;
- `DebArchive::open_path`/`open_bytes`, outer `DebMember` and inner
  control-then-data `DebEntry` metadata, outer/inner extraction, batch
  extraction, and verification; and
- `ArjArchive::open_path`/`open_bytes`, archive/main-header metadata,
  archive-order `ArjEntry` metadata, extraction, batch extraction, and
  verification.

None of these containers offers a writer, editor, generic archive trait, automatic
filesystem extraction, or a whole-output return method. Duplicate names remain
separate index-addressed entries. ZIP passwords are byte strings because the
ZIP formats do not define a universal password-to-byte encoding. RPM has no
password API. `ZipArchive::retained_input_bytes` reports its retained source;
`RpmArchive::retained_payload_bytes` reports its currently retained decoded
CPIO payload. `CpioArchive` and `ArjArchive` report their retained source;
`DebArchive` separately reports the source, decoded control tar, and decoded
data tar. Temporary decoder state remains governed by `Limits`.

ZIP compression metadata names Store, Deflate, Deflate64, BZip2, ZIP-LZMA,
both Zstandard IDs, XZ (95), PPMd (98), and the registered-but-unsupported MP3
(94), JPEG (96), and WavPack (97) IDs. XZ and PPMd extraction use the same
writer/callback/batch API and typed limit/integrity errors as other supported
methods. A metadata name is not a decoder claim: attempting 94, 96, or 97
returns `UnsupportedMethod` with the original two-byte numeric identifier.

The `unstable-internals` feature is a repository test/fuzz hook. Its hidden raw
parser, validated wire model, folder graph, and envelope exports are not
covered by compatibility promises and must not be used by applications. It is
off by default and is not exposed through Python.

## Ownership and FFI shape

An `Archive` owns the logical input bytes, validated metadata, limits, and an
optional zeroizing password. Metadata values are concrete; entry indices are
`u64`; absence uses `Option`; and callbacks use object-safe traits. No public
decoder graph or borrowed parser buffer needs to cross a future FFI boundary.
`VolumeProvider` can be implemented by a future callback adapter without
changing parser ownership.

`ArchiveResources` reports accounted state retained by a session.
`MemberReader::retained_bytes` reports the complete decoded folder buffer held
by that reader, which can exceed its selected member size for a solid folder.
Temporary decoder dictionary/window state is constrained by
`max_dictionary_bytes`; packed input and decoded output are constrained by the
input/output limits documented in `THREAT_MODEL.md`.

A `CompressedStream` owns its complete compressed input and a small validated
frame table. `retained_input_bytes` reports the logical input bytes; decoder
windows and output exist only during an extraction operation and are bounded
by the retained `Limits`.

The CPIO, Debian, and ARJ models likewise own concrete metadata and immutable
validated byte ranges. Debian retains both decoded tar images for indexed
access. ARJ methods 1–3 allocate a preflighted fixed decoder window/table
budget only while decoding; method 4 uses bounded output as history. No public
type exposes a borrowed parser buffer or an input-derived destination path.

## Integrity and output

`extract_entry`, `extract_entry_to`, `verify`, and successful sink
finalization do not report success before applicable CRC verification.
Streaming reads can expose unauthenticated bytes, because 7z CRCs are trailing
integrity checks; `finish()` is mandatory. A caller requiring atomic trusted
output should write to a caller-managed temporary destination and publish it
only after success.

Raw names are never destinations. Applications must call the path validator
and separately define collision, link, platform-name, and race policy. The
core provides no automatic filesystem extraction.

Standalone LZ4/Zstandard checksums have the same delayed-trust rule: a writer
may observe bytes before a trailing checksum is available, and only a
successful operation verifies the frame's declared checksum set. Unix `.Z`
contains no checksum or decoded-size declaration, so successful EOF is a
decoder-completion result rather than an integrity guarantee.

ZIP one-entry extraction authenticates/decrypts and verifies the complete
entry before the first caller write. ZIP batch `finish_entry` follows the same
verified boundary. WinZip AES authentication is mandatory; AE-1 also checks
CRC, while AE-2 follows its authenticated-data convention. RPM opening verifies
every supported package-level digest before exposing a payload entry, and CPIO
CRC members are rechecked before output. OpenPGP blobs and unsupported RPM
digest algorithms are never presented as verified signatures.

CPIO CRC-newc sums are checked during open and again before output. Debian tar
header checksums are checked before the corresponding entry model exists;
the supported compression wrappers enforce their own available integrity
fields. ARJ main/local/extended header CRCs are checked while opening, and
member CRC is checked before one-entry output begins or a batch entry is
finished. ARJ encryption is not accepted as plaintext: extraction returns
`PasswordRequired` until an authenticated implementation exists.

## MSRV and platforms

The MSRV is Rust 1.85 with edition 2024. The supported CI targets are current
stable Rust on Linux, macOS, and Windows, plus an i686 Linux compile/test gate
for conversion behavior. MSRV or target support changes require a documented
versioned policy change.

## Python adapter

`bindings/python` is a separate PyO3/maturin distribution named `unpackio`;
its native extension is `unpackio._native`. It depends on the stable Rust
crate by path and does not duplicate parsing or decoding. The Rust workspace
explicitly excludes this package so the core retains no Python runtime or build
dependency. The resulting wheel is the only shipped consumer surface.

The Python surface maps the concrete Rust operations directly:

- `open_path(path, *, limits, password, cancellation, max_work_units)`;
- `open_bytes(data, *, limits, password, cancellation, max_work_units)`;
- `open_volumes(provider, first_volume_name, *, ...)`;
- `Archive.entries()`, `Archive.entry(index)`, `Archive.verify()`;
- `Archive.extract_entry_to(index, writer, *, ...)`;
- `Archive.extract_entries_to(sink, *, cancellation, max_work_units)`; and
- `Archive.stream_entry(index, callback, *, ...)`.

Standalone streams use separate FFI-safe names:

- `open_stream_bytes(data, *, format, limits, cancellation, max_work_units)`;
- `open_stream_path(path, *, format, limits, cancellation, max_work_units)`;
- immutable `CompressedStream.info`, `.limits`, and
  `.retained_input_bytes`; and
- `CompressedStream.extract_to(writer)`, `.stream(callback)`, and `.verify()`.

The optional format string accepts `lz4`, `zstd`/`zstandard`, and
`z`/`compress`/`unix-compress`; omission performs magic-based detection.
The native Python classes have no whole-output return method or automatic
filesystem output.

Concrete non-7z containers use parallel, format-specific Python names:

- `open_zip_bytes(data, *, limits, password, cancellation, max_work_units)`
  and `open_zip_path(path, *, ...)` return `ZipArchive`;
- `open_rpm_bytes(data, *, limits, cancellation, max_work_units)` and
  `open_rpm_path(path, *, ...)` return `RpmArchive`;
- each archive exposes ordered `entries()`, `entry(index)`, `verify()`,
  `extract_entry_to`, `extract_entries_to`, and `stream_entry`; and
- `RpmArchive.header` and `.signature_header` expose ordered numeric tags and
  typed values without guessing application-specific text encodings.
- `open_cpio_bytes`/`open_cpio_path` return `CpioArchive`;
- `open_deb_bytes`/`open_deb_path` return `DebArchive`, which distinguishes
  outer members from inner control/data entries; and
- `open_arj_bytes`/`open_arj_path` return `ArjArchive`.

The format-specific batch protocols mirror the 7z sink boundary but pass a
concrete entry (`ZipEntry`, `RpmEntry`, `CpioEntry`, `DebEntry`, or
`ArjEntry`). They preserve callback exceptions, share one work
budget/token for the operation, bound chunks, and call `finish_entry` only
after applicable integrity checks. `RpmHeader.as_named_dict()` provides a
complete symbolic/scalar header projection while preserving unknown tags
numerically. Applications use these unpackio-native objects directly.

`Entry` is an owned metadata snapshot. It preserves raw UTF-16 code units as
`list[int] | None`, lossy display text separately, every optional size/CRC/time/
attribute field as `None` when absent, archive order, kind, symlink metadata,
and the core safe-path result. A name is metadata only and is never used as a
destination. `ArchiveResources`, immutable `Limits`, and per-operation
`CancellationToken` expose the corresponding core policies without generic
Rust types crossing the FFI boundary.

Extraction has no default whole-output return API. `extract_entry_to` passes
bounded chunks to `writer.write`; `stream_entry` passes them to a callback
which returns `None`/`True` to continue or `False` to cancel. Both return the
verified byte count only after the core extraction helper completes applicable
folder/member CRC checks. Bytes observed before an exception are unverified and
are not rolled back. Writer and callback exceptions are preserved.

`extract_entries_to` is the Python batch API for natural-order extraction. Its
sink receives `begin_entry(entry, size)`, bounded
`write_entry(index, chunk)`, and `finish_entry(index)` calls. Methods return
`None`/`True` to continue or `False` to cancel. One core `WorkBudget` and one
`CancellationToken` cover the complete call, and the underlying Rust API
decodes each solid folder at most once. `finish_entry`, not delivery of the
last chunk, is the CRC-verified success boundary. Python callback exceptions
retain their identity, and token or callback cancellation remains
`CancelledError`. The sink chooses destinations by caller policy; the binding
never converts archive names into paths. Duplicate names therefore remain
distinct index-addressed entries. Empty files receive begin/finish with no
write; streamless directories and anti-items produce no sink event and remain
available through metadata listing.

A Python volume provider is either a callable or an object with
`open_volume(index, expected_name)`. It returns one `bytes` volume or `None`.
The binding checks a volume's size before its fallible Rust copy; the core then
enforces volume count, aggregate input, sequencing, cancellation, and work
limits. Python-owned provider buffers and sink-retained output are outside the
Rust retained-resource account.

Rust-only parsing, KDF, decoding, and verification run with Python detached;
the binding reattaches only for provider/writer/callback calls. Unexpected
unwinds are contained and translated to `InternalError`. The wheel uses the
CPython limited API for Python 3.9 and newer. CI builds explicit Linux,
macOS, and Windows x86-64/ARM64 ABI3 wheels, then installs each artifact and
runs the complete binding suite on Python 3.12, 3.13, and 3.14. The Rust
binding retains the repository MSRV of 1.85. The Python adapter remains
pre-alpha in `0.2.0`; compatibility claims remain exactly those in
`COMPATIBILITY.md`.
