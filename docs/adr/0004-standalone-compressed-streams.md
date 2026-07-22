# ADR 0004: Separate standalone compressed-stream readers

- Status: accepted
- Date: 2026-07-21

## Context

The stable `Archive` API models named 7z members, coder graphs, folders,
volumes, and archive metadata. LZ4 frame files, Zstandard frame files, and Unix
`compress` `.Z` files instead represent one unnamed decoded byte stream.
Treating those inputs as synthetic archives would invent names, member CRCs,
or mappings and would blur the existing parser/model trust boundary.

The request expands the repository beyond the original 7z-only scope, but it
does not authorize writers, compression, automatic filesystem extraction, a
runtime command fallback, or ALES integration.

## Decision

Add a separate safe-Rust `CompressedStream` implementation in the core while
keeping `Archive` 7z-specific. The Python stream API owns its input, validates
a bounded frame/layout table at open time, exposes concrete `StreamInfo`, and
decodes only to a caller-selected writer. It never derives an output path.

The first admitted formats are:

- standard and legacy LZ4 frames, concatenated frames, and skippable frames;
- standard Zstandard frames, concatenated frames, and skippable frames; and
- Unix `compress` `.Z` streams with 9- through 16-bit variable-width LZW and
  optional CLEAR-code block mode.

LZ4 and Zstandard decoding continues to use the already admitted safe Rust
dependencies. Header, block, and content checksums are verified whenever the
format declares them. External-dictionary LZ4/Zstandard frames are listable
but return a typed `UnsupportedStreamFeature` during extraction because no
dictionary-provider contract is present.

The `.Z` state machine is a checked safe-Rust adaptation of the pinned
BSD-3-Clause NetBSD `zopen.c` implementation recorded in `PROVENANCE.md`. Its
complete dictionary/expansion memory is checked and charged before allocation.
The format has no checksum or declared decoded size, so successful EOF proves
only syntactic decoder completion. A truncation ending after a complete code
can be indistinguishable from a shorter valid stream; the API and security
documentation must not claim integrity that `.Z` does not carry.

`max_stream_frames` bounds data plus skippable frame amplification. Existing
input, dictionary, entry-output, total-output, work, and cancellation controls
apply to every standalone operation. Declared output and window sizes are
checked before decoder construction; unknown sizes remain `None` and are
bounded while decoding.

The Python adapter exposes distinct `open_stream_bytes`, `open_stream_path`,
`CompressedStream`, and `StreamInfo` names. Decoding remains detached from
Python and sends bounded chunks to a writer or callback. It has no default
whole-output-copy API and preserves callback exceptions and cancellation.

## Consequences

- Callers cannot accidentally pass a standalone stream to `Archive` and
  receive invented archive semantics.
- Applications choose all output destinations and atomic-publication policy.
- No CLI, executable frontend, or console script is added.
- LZ4/Zstandard frames requiring external dictionaries remain an explicit
  compatibility gap.
- Unix `.Z` output cannot be called checksum-verified; callers needing
  authenticity must supply an independent digest or authenticated envelope.
- Any additional standalone format requires its own bounded validator,
  provenance, dependency review, positive evidence, malformed tests, and an
  update to this compatibility boundary.
