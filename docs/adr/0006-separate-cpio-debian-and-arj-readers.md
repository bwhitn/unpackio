# ADR 0006: Separate unpack-only CPIO, Debian-package, and ARJ readers

Status: accepted 2026-07-21

## Context

Callers need metadata inspection and caller-directed extraction for raw CPIO,
Debian binary packages, and ARJ archives. Routing these formats through the 7z
`Archive` model would invent semantics, obscure their integrity boundaries, and
make the future FFI surface generic in ways that are difficult to stabilize.
Adding generic ar/tar APIs would also broaden the task beyond Debian packages.

All input is hostile. The readers must obey the existing count, name, input,
header, dictionary, output, work, cancellation, and SFX bounds; preserve raw
metadata; and never turn a stored name into a filesystem destination.

## Decision

- Add concrete `CpioArchive`, `DebArchive`, and `ArjArchive` types with owned
  byte/path opening, immutable indexed metadata, one-entry extraction, bounded
  callbacks, natural-order batch sinks, and verification.
- Keep them separate from the 7z `Archive`, ZIP, RPM, standalone stream,
  Python adapter, and future filesystem-policy layers. Add no CLI, writer,
  editor, compressor,
  installer, `extractall`, auto-detection, or automatic path use.
- Use the standalone checked CPIO parser for RPM payloads as well. It accepts
  SVR4 newc/CRC-newc, portable ASCII odc, and historical binary little-/
  big-endian records and verifies CRC-newc sums where present.
- Implement only the Debian 2.0 System V ar envelope and its two required tar
  sections. Parse V7/ustar, bounded POSIX pax, and GNU long-name/link records;
  reuse admitted gzip, BZip2, XZ/LZMA-alone, and Zstandard decoders. Do not
  expose a general ar or tar reader.
- Parse ARJ main/local/extended headers and bounded SFX prefixes in project
  safe Rust. Support stored/no-data methods directly, use exact `delharc`
  0.6.1's static LH6 decoder for methods 1--3 behind a documented memory/panic
  boundary, and retain the checked Apache-2.0 provenance of the in-tree method
  4 adaptation. Encryption, split/multi-volume data, security envelopes, and
  unknown methods remain typed unsupported.
- Verify every format-provided header/member checksum before reporting the
  corresponding success. A format without a payload checksum does not gain an
  invented one. Batch `finish_entry` remains the verified member boundary.
- Expose matching concrete Python classes/functions without duplicating parser
  or decoder logic. Python callback exceptions and cancellation remain
  unclassified, and output is delivered only to caller-selected sinks.

## Consequences

Debian packages retain the source plus both bounded decoded tar images, CPIO
retains its bounded source, and ARJ retains its bounded source and temporarily
materializes one verified decoded member. These resources are reported by the
public APIs and covered by configured limits, but none of the three readers has
a throughput claim yet.

The new ARJ dependency introduces a third-party unsafe-code boundary even
though the core crate retains `#![forbid(unsafe_code)]`. Its exact revision,
license, invoked path, fixed allocation charge, unchecked operation audit, and
panic containment are recorded in `DEPENDENCIES.md` and `PROVENANCE.md`.

Compatibility claims require generated positive/malformed/resource cases,
real-method fixtures where decoding is nontrivial, Python binding coverage,
and seedless fuzz entry points. Unsupported valid forms remain visible in
`COMPATIBILITY.md`; they are not silently accepted or delegated to a runtime
fallback.
