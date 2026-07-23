# ADR 0001: Trust boundaries, dependencies, and provenance

- Status: Accepted
- Date: 2026-07-18
- Decision owners: unpackio maintainers

## Context

7z is a graph-based container with attacker-controlled lengths, indices,
properties, decoder memory parameters, filenames, and volume boundaries. The
audited source material and black-box oracles provide useful behavioral
evidence without defining this project's architecture or safety requirements.
Decoder provenance is also a licensing and security boundary: prohibited
sources remain excluded, and permissive dependency metadata alone is
insufficient proof of origin.

## Decision

1. Use a safe Rust core with hard boundaries between syntax parsing, semantic
   validation, graph construction, decoding, volume access, and filesystem
   policy.
2. Make the raw parser unable to allocate or read beyond caller-provided
   `Limits`; parse each length-delimited property through an exact bounded
   child reader.
3. Validate coder graphs as an isolated part of semantic model conversion and
   expose decoder schedules only through the validated model. Schedule by graph
   topology, not serialized coder order.
4. Start with no third-party runtime dependencies. Admit one exact dependency
   version at a time through the checklist in `DEPENDENCIES.md`.
5. Allow runtime licenses only when the complete applicable expression can be
   satisfied by MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, or
   Unicode-3.0/Unicode-DFS-2016.
6. Reject unapproved registries and all git dependencies with cargo-deny.
   Commit lockfiles and deny wildcard requirements and duplicate versions by
   default.
7. Implement cryptographic primitives using approved RustCrypto crates. Keep
   secrets per archive and use zeroization; do not cache plaintext passwords or
   derived keys globally.
8. Do not inspect, copy, translate, link, vendor, or generate from official
   7-Zip or p7zip source. `7zz` may be executed only by differential tests.
9. Treat all BSD-3-Clause source material as provenance-controlled reference
   material. Record every adaptation at file/symbol granularity before merging
   it, and retain its notice.
10. Record every decoder/filter implementation independently, even when it is
    original, with its algorithm reference, code origin, and applicable
    license.

## Dependency admission record

An admission change must include the exact version, checksum through
`Cargo.lock`, enabled features, complete transitive graph, packaged license
files, repository origin, unsafe-code review, maintenance/advisory status,
memory behavior, cancellation behavior, and the decoder ledger update. A
crate's Cargo metadata is evidence, not the complete license review.

## Consequences

The initial implementation is slower to expand and may need original decoder
work where no suitable crate exists. In exchange, format validation is reusable
across decoders, dependency provenance is reviewable, Python callbacks remain
possible, and unsupported valid features produce typed errors instead of
partial extraction or panics.

The core will not expose a plugin API that bypasses memory accounting or graph
validation. A decoder extension mechanism can be considered only after the
public API is stabilized.

## Rejected alternatives

- Translating Go control flow mechanically: this preserves nil/sentinel and
  indexing hazards rather than using Rust invariants.
- Wrapping `7zz`, official 7-Zip, or p7zip: prohibited by runtime and provenance
  requirements.
- Using a single parser/model type: permits partially validated data to escape.
- Treating a zero CRC or size as absent: zero is a valid value.
- Automatically sanitizing names before stream mapping: changes archive
  semantics and can associate bytes with the wrong entry.
- A global AES key cache: retains secrets across unrelated archive lifetimes.
