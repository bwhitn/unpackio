# ADR 0002: Stable Rust API and retained-resource accounting

- Status: Accepted
- Date: 2026-07-18
- Decision owners: unpackio maintainers

## Context

Phases 2-5 temporarily exported parser envelopes, validated folders, coder
ports, and member-to-substream mappings so integration tests and fuzz harnesses
could inspect invariants. Freezing those types would couple applications and a
future Python layer to internal graph representation. The public extraction
surface also needs an explicit integrity boundary and an observable account of
state retained by solid member readers.

## Decision

1. Stabilize the concrete root exports listed in `API.md` for the `0.1.x`
   line. Keep opening explicit about limits, cancellation, and work budgets.
2. Expose archive-order `FileEntry` metadata but not folder/substream indices.
   Preserve raw UTF-16, optional CRC, optional size, timestamps, attributes,
   modes, StartPos, anti-items, and symlink classification.
3. Keep raw parser and graph inspection behind the off-by-default,
   documentation-hidden `unstable-internals` feature. Enable it only for
   structural integration tests and fuzz targets; it has no compatibility
   guarantee.
4. Keep `MemberReader::finish` as the streaming success boundary. Writers and
   sinks may observe bytes before a trailing CRC; only successful finalization
   establishes integrity.
5. Report retained archive input, validated metadata payload, zeroizing secret
   storage, and their checked total through `ArchiveResources`. Report the
   complete decoded folder allocation held by `MemberReader`, not merely the
   selected solid member slice.
6. Retain the existing category-specific enforcement: input/volume bytes,
   header/name/property/count allocations, dictionary/window memory, per-entry
   output, total output, KDF, recursion, work, and cancellation are checked by
   their owning layer before expensive work or attacker-sized allocation.
7. Natural-order verification and sink extraction advance one substream cursor
   and decode each folder at most once. Random member access may re-decode from
   a solid folder's start and is documented separately.

## Consequences

Applications and future bindings can list, select, stream, and extract without
knowing parser or coder types. Parser regressions and fuzzing retain deep model
visibility through an explicitly unstable build. Solid streaming is bounded
but remains full-folder buffered; reporting retained bytes makes that cost
observable without claiming constant-memory decoding.

Adding a new retained allocation category requires updating the account and
threat model. A future truly incremental decoder can change the reported
amount additively while preserving the `finish()` contract.

## Rejected alternatives

- Stabilizing `ArchiveHeader`, `Folder`, `Coder`, and `FileStream`: this would
  freeze internal graph layout and expose indices that callers do not need.
- Hiding limits behind convenience open functions: hostile-input policy must
  remain explicit and overrideable.
- Implementing `std::io::Read` as the only streaming contract: `Read` has no
  successful finalization hook for member/folder CRC errors.
- Treating bytes written before CRC as verified: trailing integrity checks make
  that claim false.
- Claiming constant-memory extraction: the current reader retains one bounded
  decoded folder.
