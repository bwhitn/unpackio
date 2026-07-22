# ADR 0005: Separate unpack-only ZIP and RPM readers

- Status: accepted
- Date: 2026-07-21

## Context

Callers need ZIP and RPM inspection and extraction with at least the read-side
behavior of PyPI `pyzipper` and `rpmfile`. The existing `Archive` model is
specifically a 7z folder/coder graph. Treating ZIP entries or an RPM payload as
7z members would erase format-specific metadata and weaken validation.

The repository remains unpack-only. Compatibility with libraries that also
write archives does not authorize a writer, mutation API, automatic filesystem
extraction, runtime Python dependency, or external-tool fallback.

## Decision

Add independent `ZipArchive` and `RpmArchive` public types. Both own their
input, preserve raw member names and format metadata, and send decoded bytes
only to a caller-selected writer. Existing 7z `Archive` and standalone
`CompressedStream` behavior remain unchanged.

ZIP structure is read through exact-version `rawzip` 0.4.4. It is admitted as
an internal, safe-Rust, zero-dependency, MIT structural parser; no writer type
is re-exported. `unpackio` remains responsible for entry-count/name/input/output
limits, overlap and local-header validation, compression dispatch, passwords,
authentication, CRC completion, work accounting, and cancellation. The initial
compatibility target is Stored, Deflate, Deflate64, BZip2, LZMA, and Zstandard entries,
ZIP64, SFX prefixes, data descriptors, UTF-8 and CP437 names, traditional
ZipCrypto, and WinZip AES AE-1/AE-2 with 128-, 192-, and 256-bit keys. Split or
spanned ZIP archives and PKWARE certificate-based Strong Encryption remain
typed unsupported features until separate volume and trust/key contracts are
designed.

WinZip AES uses exact-version RustCrypto AES, CTR, PBKDF2-HMAC-SHA1, and HMAC
primitives. SHA-1 is present only because the interoperable WinZip AES format
requires PBKDF2-HMAC-SHA1 and HMAC-SHA1; it is not used as a standalone
collision-resistance claim. Authentication is checked before decoded output is
reported as successful. Password and derived-key bytes are per archive or per
operation and zeroized.

RPM parsing is implemented in-tree from the RPM file-format documentation. It
validates the lead, signature header, main header, index/store ranges, alignment,
and payload boundary before interpreting tags. It exposes header tags and a
bounded CPIO member model. Common RPM payload compressors are uncompressed,
gzip, bzip2, xz, legacy lzma, and Zstandard. CPIO `newc`, CRC-newc, and RPM's
`070701` newc and `070702` CRC-newc are parsed without deriving filesystem
paths; other `07070X` variants remain typed unsupported. Supported SHA-1/
SHA-256 header, SHA-256 payload, compressor, and CPIO checksums are verified.
Legacy MD5, per-file digests, SHA-512/SHA-3 payload digests, and OpenPGP
package-signature authentication, plus SHA3-256-only header digests, are
explicit boundaries rather than being
silently treated as verified.

All new readers reuse `Limits`, `WorkBudget`, `CancellationToken`, typed errors,
and safe-path validation. Declared sizes are checked before allocation, and a
successful high-level extraction means the applicable entry checksum or
authentication boundary has completed.

## Consequences

- The stable API has three concrete archive types instead of a lossy generic
  archive abstraction.
- Duplicate names and unsafe names remain metadata and retain their original
  ordering; they never select an output path automatically.
- Read compatibility can exceed the named Python libraries without exposing
  their write surfaces.
- Strong Encryption, split ZIP, and cryptographic RPM signature verification
  cannot be claimed until their explicit contracts and evidence are added.
- ZIP and RPM each require positive, corruption, truncation, limit, fuzz, and
  Python-adapter evidence before their compatibility rows become supported.
