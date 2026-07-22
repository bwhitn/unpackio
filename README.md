# unpackio

`unpackio` is a security-focused, unpack-only Python package backed by a Rust
core. It reads 7z, ZIP, RPM, Debian binary packages, standalone CPIO, and ARJ
containers, with a separate single-stream API for LZ4 frame files, Zstandard
frame files, and Unix `compress` `.Z` files. Each container has a concrete
model; non-7z formats are not forced through the 7z coder graph.

> **Current status: pre-alpha.** Support is limited to the evidence-backed
> slices in [COMPATIBILITY.md](COMPATIBILITY.md). The 7z core
> validates regular and bounded-SFX archives, executes arbitrary validated
> coder graphs, and supports the evidence-backed Copy/LZMA family, core
> filters, Deflate, Deflate64, BZip2, PPMd, Brotli, LZ4, Zstandard, IA64,
> ARM Thumb, RISC-V, Swap2, Swap4, and AES-256-CBC/SHA-256 slices in
> [COMPATIBILITY.md](COMPATIBILITY.md). It resolves supported encoded/encrypted
> headers, external folder definitions, and external metadata, and reads
> bounded sequential volumes. Member and archive APIs enforce applicable CRCs;
> streaming callers must explicitly call `finish()`. This is not a general
> “all 7z” compatibility claim. Each other container reader has its own
> concrete, unpack-only API.
> Standalone streams do not become synthetic archives: they have no invented
> member name, path, metadata, or CRC.

The intended scope is reading, listing, verifying, decrypting where the format
slice supports it, and decompressing archives plus reading and decompressing
the three documented standalone stream formats. Archive/stream creation and
modification and automatic filesystem extraction are outside the current
scope.

## Workspace

- `crates/unpackio`: safe Rust implementation core. It has
  `#![forbid(unsafe_code)]` and is not published as a command-line product.
- `bindings/python`: separately locked PyO3/maturin package distributed and
  imported as `unpackio`, with native module `unpackio._native`; this is the
  supported consumer API.
- `fuzz`: cargo-fuzz targets, kept outside the publishable workspace.

## 7z reader

The 7z implementation separates bounded byte parsing, the validated archive
model, coder-graph construction, decoding, volume access, and path policy. It
validates property lengths, stream topology, offsets, ranges, counts, and
applicable start-header, next-header, packed-stream, folder, substream, and
member CRCs before reporting success. Configurable input, header, count,
property, dictionary, output, volume, KDF, recursion, work, and cancellation
limits are enforced before allocation or expensive work.

Supported slices include encoded and encrypted headers, solid archives,
bounded SFX scanning, supported external metadata and folder definitions,
symlink metadata, and sequential volumes. Passwords are scoped to one archive
and zeroized on drop. Unsupported valid methods or features return structured
errors rather than silently degrading.

`Archive::extract_entries_to` processes entries in natural order, decodes each
solid folder at most once, and finalizes a caller-owned sink entry only after
its member CRC succeeds. Folder output is currently fully buffered under the
configured limits; it is not a constant-memory decompression pipeline. Raw
parser and coder-graph inspection remain hidden behind the off-by-default
`unstable-internals` test/fuzz feature. See [API.md](API.md) and
[ERRORS.md](ERRORS.md).

## Python binding

Python archive work runs with the interpreter detached. Writer, callback, and
natural-order batch extraction cross the native boundary in bounded chunks and
do not report success before Rust integrity finalization. Batch extraction
shares one operation budget and cancellation token. Python volume providers
receive exact indices and expected names, core errors become structured
exception subclasses, callback exceptions are preserved, and unexpected Rust
unwinds are contained at the FFI boundary.

The binding delegates parsing, decoding, cryptography, resource accounting,
path policy, and integrity checks to the Rust core. Archive names are never
automatic filesystem destinations, and no parser or decoder logic is
duplicated in Python.

The standalone `CompressedStream` surface is deliberately separate from
`Archive`. It validates concatenated/skippable LZ4 and Zstandard frames,
standard LZ4 legacy frames, and 9- through 16-bit Unix `.Z` LZW streams. It
enforces input/frame/dictionary/output/work/cancellation limits and verifies
every checksum the selected format carries. LZ4/Zstandard external
dictionaries are typed unsupported. Unix `.Z` has no embedded checksum or
decoded-size field, so successful decoding is not an authenticity guarantee.
The Python adapter exposes the same boundary as `open_stream_bytes` and
`open_stream_path`, with output delivered only to caller-owned writers or
callbacks. No CLI or console script is shipped.

The separate `ZipArchive` surface parses ordinary and ZIP64 central
directories, bounded SFX prefixes, raw names/comments/extra fields, duplicate
names, directories, Unix modes, and symlink metadata. Extraction supports
Store, Deflate, Deflate64, BZip2, ZIP-LZMA, and both registered Zstandard method
IDs. Traditional ZipCrypto and WinZip AES AE-1/AE-2 with 128-, 192-, or
256-bit keys are supported with per-archive zeroized byte passwords. Local and
central records, sizes, data descriptors, authentication codes, and applicable
entry CRCs must agree before success. Split/spanned ZIP, PKWARE Strong
Encryption, encrypted central directories, ZIP XZ, and ZIP PPMd remain typed
unsupported.

The separate `RpmArchive` surface validates the lead, signature header, main
header, typed index/store ranges, payload declaration, and the shared checked
CPIO layouts. It extracts uncompressed, gzip, BZip2, XZ, legacy LZMA, and
Zstandard payloads while preserving duplicate byte names, modes, ownership,
timestamps, device metadata, symlinks, hard-link metadata, directories, and
empty entries. Available SHA-1/SHA-256 header and SHA-256 payload digests plus
CPIO CRC records are verified. OpenPGP signatures are exposed as header data
but are not authenticated; legacy MD5, per-file digest tables, SHA-512/SHA-3
payload digests and SHA3-256-only header digests are not claimed. RPM currently
retains the bounded decoded CPIO payload in memory.

`CpioArchive` accepts SVR4 `newc`, CRC-`newc`, portable ASCII `odc`, and both
byte orders of the historical binary layout. It preserves raw names and all
numeric header fields, validates alignment/trailers and CRC-newc sums, and
never treats a member name as a destination. It accepts raw CPIO images only;
compression wrappers remain the responsibility of a containing format or a
separate stream reader.

`DebArchive` validates the System V `ar` envelope and Debian format `2.0`, then
decodes `control.tar` with no compression, gzip, XZ, or Zstandard and
`data.tar` with those choices plus BZip2 or legacy LZMA-alone. Inner V7/ustar,
GNU long-name/link, and POSIX pax metadata is parsed into byte-preserving tar
entries. Both decoded tar images are retained under the total-output limit.
There is no general-purpose `ar`/tar API and no package installation behavior.

`ArjArchive` validates bounded SFX prefixes, main/local/extended header CRCs,
member ranges, and member CRCs. It extracts stored method 0, compressed methods
1 through 4, and empty no-data methods 8 and 9. ARJ encryption, split or
multi-volume members, security envelopes, and host-specific text conversion
are explicit unsupported boundaries; names and link-like metadata are never
applied to the filesystem.

Rust callers use each concrete type's `open_bytes`/`open_path` methods. Python
callers use the corresponding `open_zip_*`, `open_rpm_*`, `open_cpio_*`,
`open_deb_*`, or `open_arj_*` functions. Canonical extraction is
index-addressed and caller-sink-only; no archive name becomes a filesystem
destination. Concrete entry types expose raw metadata, and extraction remains
explicit and caller-directed.

## Build

The workspace uses Rust edition 2024 and has a minimum supported Rust version
(MSRV) of **1.85**. `Cargo.lock` is committed.

```text
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check
```

The Python package retains a Python 3.9 ABI3 floor and publishes one optimized
wheel for each Linux, macOS, and Windows x86-64/ARM64 target. CI installs every
wheel and runs the binding suite on Python 3.12, 3.13, and 3.14 before a manual
PyPI approval can become available:

```text
maturin build --manifest-path bindings/python/Cargo.toml --release --locked
python -m unittest discover -s bindings/python/tests -v
cargo deny --manifest-path bindings/python/Cargo.toml \
  --all-features --config bindings/python/deny.toml check
```

See [bindings/python/README.md](bindings/python/README.md) for the output,
password, and callback trust boundaries.

`7zz` is permitted only in differential tests. It is never linked, invoked, or
required by the Rust core or Python package. There is no runtime fallback to
an external archive implementation. The distribution installs no console
script or executable; archive operations are available only through the
Python API:

```python
import io
import unpackio

archive = unpackio.open_path("archive.7z")
output = io.BytesIO()
archive.extract_entry_to(0, output)
```

Standalone Python callers use `open_stream_bytes` or `open_stream_path`; these
functions never infer an output filename from the input path.

## Project controls

- [ARCHITECTURE.md](ARCHITECTURE.md) defines trust boundaries and module
  ownership.
- [API.md](API.md) and [ERRORS.md](ERRORS.md) define the Python surface and its
  internal Rust/FFI and error contracts.
- [TESTING.md](TESTING.md) records platform, 32-bit, Miri, differential, fuzz,
  and benchmark commands.
- [RELEASING.md](RELEASING.md) defines the six-wheel ABI3 matrix, complete
  pre-publication gates, Trusted Publishing setup, and required manual PyPI
  approval.
- [`docs/adr`](docs/adr) records accepted trust-boundary, API, and Python-FFI
  decisions.
- [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) define
  security invariants.
- [DEPENDENCIES.md](DEPENDENCIES.md) and `deny.toml` define supply-chain rules.
- [PROVENANCE.md](PROVENANCE.md) records exact source origins and decoder
  provenance.
- [CORPUS.md](CORPUS.md) records what corpus material was actually inspected.
- [CAPABILITY_PROBES.md](CAPABILITY_PROBES.md) records corpus-free black-box
  stock-`7zz` feature probes and their interpretation limits.
- [AGENTS.md](AGENTS.md) records repository-wide implementation and review
  rules.

## Licensing

Original unpackio work is licensed solely under the **MIT License** in
`LICENSE`. Third-party and adapted-source terms are preserved separately in
`LICENSES/` and apply only to the material identified in `NOTICE` and
`PROVENANCE.md`.
