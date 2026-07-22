# unpackio for Python

`unpackio` is the Python distribution for the repository's security-focused,
unpack-only Rust 7z, ZIP, RPM, CPIO, Debian-package, and ARJ readers and its
separate LZ4/Zstandard/Unix `.Z` stream readers. The package imports as
`unpackio`; its implementation module is `unpackio._native`.

The binding delegates all parsing, graph validation, decoding, cryptography,
CRC verification, limits, and path classification to the stable Rust core. It
does not create archives and does not automatically extract archive names to
the filesystem.

ZIP and RPM use concrete APIs rather than pretending to be 7z archives:

```python
import io
import unpackio

zip_archive = unpackio.open_zip_path("input.zip", password=b"zip-password")
for entry in zip_archive.entries():
    print(entry.index, entry.name, entry.compression_method, entry.encryption)

rpm = unpackio.open_rpm_path("package.rpm")
print(rpm.payload_compression, rpm.header.value(1000))

output = io.BytesIO()
rpm.extract_entry_to(0, output)
```

Use `open_zip_bytes`/`open_zip_path` and
`open_rpm_bytes`/`open_rpm_path`. ZIP passwords are `bytes` and remain scoped
to one `ZipArchive`; RPM accepts no password. Both formats preserve raw names
as `bytes`, duplicate order, metadata, and safe-path classification. Neither
API writes a name to disk or returns all decoded payloads as one object.

## ALES data contract

ALES can consume the native, format-specific unpackio objects directly; no
API is named after another Python package:

```python
import io
import unpackio

archive = unpackio.open_zip_path("sample.zip", password=b"infected")
entry = archive.entries()[0]
verified = io.BytesIO()
archive.extract_entry_to(entry.index, verified)

package = unpackio.open_rpm_path("sample.rpm")
print(package.header.as_named_dict().get("name"))
payload = io.BytesIO()
package.extract_entry_to(package.entries()[0].index, payload)
```

`ZipEntry` exposes every value ALES records: decoded/raw names, comments,
extras, sizes, CRC, DOS timestamp, method, flags, creator/extractor versions,
attributes, local-header offset, encryption kind, and directory metadata.
Passwords are supplied when opening a `ZipArchive`; trying another password
creates another per-archive session. Even a zero-length encrypted member must
be extracted so its password verifier and authentication data are checked.

`RpmArchive.header` and `.signature_header` retain ordered typed tags.
`as_named_dict()` adds the complete symbolic projection needed by ALES,
preserves unknown tags under numeric keys, returns scalar integers for
single-value numeric tags, and selects the first locale for I18N values. RPM
opening validates the complete supported package, including applicable
digests, before member data is exposed.

These are unpackio APIs, not compatibility facades. They contain no writer,
`extractall`, automatic path use, or runtime fallback. Callers must apply their
own policy before using a metadata name as a path.

`ZipArchive.extract_entries_to` and `RpmArchive.extract_entries_to` use the
same three callbacks as the 7z batch protocol, with `ZipEntry` or `RpmEntry`
passed to `begin_entry`. One work budget and cancellation token cover the
complete call, chunks are bounded, callback exceptions retain their identity,
and `finish_entry` is the integrity-verified boundary. ZIP verifies
authentication/size/applicable CRC before finalization; RPM has already
verified supported package digests and rechecks applicable CRC-newc member
checksums. A caller should still stage output if callback failure must be
atomic.

RPM typed headers use numeric tags. `RpmHeader.entries()` retains order and
duplicates; `.value(tag)` returns the last effective value and `.as_dict()` is
a convenience projection. OpenPGP blobs are exposed but not authenticated.
The current RPM object retains the bounded decoded CPIO payload, reported by
`retained_payload_bytes`.

Standalone CPIO, Debian packages, and ARJ likewise use concrete APIs:

```python
import io
import unpackio

cpio = unpackio.open_cpio_path("payload.cpio")
deb = unpackio.open_deb_path("package.deb")
arj = unpackio.open_arj_path("archive.arj")

for entry in cpio.entries():
    print(entry.index, entry.format, entry.raw_name, entry.mode)
for entry in deb.entries():
    print(entry.index, entry.section, entry.raw_name, entry.kind)
for entry in arj.entries():
    print(entry.index, entry.compression_method, entry.raw_name, entry.crc32)

verified = io.BytesIO()
deb.extract_entry_to(0, verified)
```

Use the corresponding `open_cpio_bytes`, `open_deb_bytes`, or
`open_arj_bytes` function for owned byte input. `DebArchive.members()` lists
the outer ar members, while `entries()` lists the indexed control/data tar
entries; `extract_member_to` exposes an outer member to a caller-selected
writer. CPIO symlink targets are returned as raw bytes by `symlink_target`.
All three preserve raw names and safe-path classification without applying
paths, modes, ownership, devices, or links.

Their `extract_entries_to` methods use the same begin/write/finish protocol
with `CpioEntry`, `DebEntry`, or `ArjEntry`. A successful `finish_entry` is the
integrity boundary for every checksum the format provides: CRC-newc for CPIO,
the already validated tar header for Debian, and member CRC-32 for ARJ. Layouts
without a payload checksum do not gain one. Writer/sink exceptions and
cancellation retain their original Python identity, and chunks remain bounded.
For atomic publication, stage output until the operation succeeds.

The current Debian object retains both bounded decoded tar images. ARJ supports
single-volume methods 0--4 and empty no-data methods 8/9; encrypted entries
remain listable but extraction raises `PasswordRequired`, while split volumes
and security envelopes are typed unsupported. Standalone CPIO accepts raw
newc, CRC-newc, odc, and historical binary inputs but does not automatically
unwrap a compression stream.

Decoded output is delivered to a Python writer or bounded callback. A writer
or callback can observe bytes before a trailing archive CRC is checked, so the
operation's successful return is the integrity boundary. Use a temporary
destination when output must be published atomically.

Python retains ownership of any 7z password `str` or ZIP password `bytes`
passed by the caller and cannot erase that Python object. Every Rust-side
password copy is zeroized and kept only in the corresponding archive session.

Standalone inputs never become synthetic archives. Use `open_stream_bytes` or
`open_stream_path`, inspect `.info`, and select a writer or callback yourself:

```python
import io
import unpackio

stream = unpackio.open_stream_path("payload.zst")
print(stream.info.format, stream.info.uncompressed_size)

output = io.BytesIO()
decoded_bytes = stream.extract_to(output)
```

The optional `format=` value accepts `lz4`, `zstd`/`zstandard`, or
`z`/`compress`/`unix-compress`; omit it for magic detection. The binding never
removes an input suffix or opens a derived output path. `stream(callback)`
sends bounded chunks and preserves Python exceptions or `False` cancellation.
`verify()` decodes to a discard sink. There is intentionally no Python method
that returns the complete output as one object.

For LZ4 and Zstandard, successful return means every checksum declared by the
frames was finalized. A writer/callback may have observed earlier unverified
chunks, so atomic publication still requires caller-managed staging. Unix `.Z`
contains no checksum or declared decoded size; successful return means the LZW
decoder reached a valid EOF under the configured bounds, not that the bytes
are authenticated or protected against clean-boundary truncation.

```python
import unpackio

archive = unpackio.open_path("example.7z")
for entry in archive.entries():
    print(entry.index, entry.name, entry.size, entry.crc32)

with open("caller-selected-output.bin", "wb") as output:
    verified_bytes = archive.extract_entry_to(0, output)
```

`stream_entry(index, callback)` sends the same bounded chunks without first
forming a complete Python output object. Return `None` or `True` to continue,
or `False` to cancel.

`extract_entries_to(sink)` is the natural-order batch surface for solid
archives. It uses one core work budget and cancellation token for the entire
operation and decodes each solid folder at most once. The sink is structural;
archive names remain metadata and are never opened as filesystem paths:

```python
class Sink:
    def begin_entry(self, entry: unpackio.Entry, size: int) -> None:
        # Select a destination by entry.index and caller policy, not entry.name.
        ...

    def write_entry(self, index: int, chunk: bytes) -> None:
        # Chunks are bounded (currently at most 4 KiB).
        ...

    def finish_entry(self, index: int) -> None:
        # This callback is the CRC-verified success boundary for the entry.
        ...

verified_bytes = archive.extract_entries_to(Sink())
```

Each sink method returns `None` or `True` to continue, or `False` to cancel.
Python exceptions are re-raised unchanged. `begin_entry` and `write_entry` may
be observed before a later member CRC failure; only `finish_entry` means that
the core verified the applicable member and folder CRCs. A Python exception
raised by `finish_entry` still makes the overall operation fail. Duplicate
names remain separate index-addressed entries, and empty files receive
`begin_entry` followed by `finish_entry` without a write call. Streamless
directories and anti-items intentionally produce no sink event; callers that
need to materialize those records must use `archive.entries()` metadata and
their own validated policy.

`open_volumes` accepts a callable or an object with
`open_volume(index, expected_name)` returning `bytes` or `None`; all returned
parts remain subject to the core volume and aggregate-input limits.

Published releases use six optimized `cp39-abi3` wheels covering Linux,
macOS, and Windows on x86-64 and ARM64. Each exact wheel must pass this binding
suite on Python 3.12, 3.13, and 3.14 before the separately protected manual
PyPI publication step is available. The wheel adds no Python runtime
dependency or command-line entry point. See the repository `RELEASING.md` for
the release and Trusted Publisher procedure.

For a local development build:

```text
python -m pip install 'maturin==1.13.3'
maturin develop --manifest-path bindings/python/Cargo.toml
python -m unittest discover -s bindings/python/tests -v
```

See the repository `API.md`, `SECURITY.md`, `COMPATIBILITY.md`, and
`bindings/python/AGENTS.md` for the complete contracts and current support
evidence.
