# unpackio TODO

This file tracks open work. Completed implementation and audit history remains
in [PHASE_PLAN.md](PHASE_PLAN.md).

For this backlog, `ZIPX` means a structurally valid ZIP archive that uses one
or more advanced compression methods. It is not a separate container magic,
and neither the Rust core nor the Python binding should identify it from a
filename extension. Consumer-specific classification, child routing, lineage,
and malware rules remain outside unpackio.

All work below remains subject to the repository's hostile-input, licensing,
provenance, fixture, and validation requirements in [AGENTS.md](AGENTS.md).

## Current

- [x] Add bounded ZIP XZ method 95 extraction:
  - [x] Pin the exact method registration and payload framing from an
    authoritative ZIP/WinZip specification, including stream termination,
    padding or trailing-byte rules, integrity checks, and version-needed
    requirements. Record the document revision and retrieval evidence in
    `PROVENANCE.md` before implementation.
  - [x] Compare method 95 with the existing RPM XZ preflight and the admitted
    Apache-2.0 `lzma-rust2` backend. Reuse them only after proving that ZIP's
    framing, exact-consumption rules, and resource accounting are compatible;
    do not add a second ZIP parser or runtime command fallback.
  - [x] Preflight XZ block/filter dictionaries and declared output against
    `Limits` before decoder allocation, and charge all parsing, decoding, and
    checksum work to the caller's shared work budget and cancellation token.
  - [x] Integrate method 95 with the existing writer/callback extraction and
    integrity boundary. Keep it listable with `UnsupportedMethod` until every
    required gate passes.

- [x] Add bounded ZIP PPMd method 98 extraction:
  - [x] Pin the exact method-98 framing, PPMd variant/version, property layout,
    model order, memory size, restoration mode, and end-of-stream versus
    declared-size behavior from admissible sources.
  - [x] Determine whether the existing MIT PPMd7 variant-H core is compatible.
    Do not assume that 7z PPMd properties or framing apply to ZIP; record exact
    source, revision, license, and adaptation provenance for any new code.
  - [x] Reject invalid or excessive order/model declarations before allocation,
    require a bounded termination model, and account for range-decoder work and
    cancellation throughout extraction.
  - [x] Integrate method 98 with the existing writer/callback extraction and
    integrity boundary. Keep it listable with `UnsupportedMethod` until every
    required gate passes.

- [x] Complete the shared acceptance work for methods 95 and 98:

  Evidence for both methods is complete as of 2026-09-14.

  - [x] Create deterministic, project-authored positive fixtures from the
    published framing or an admitted encoder. Record exact bytes, hashes,
    generation steps, redistribution status, and any checksum-pinned,
    test-only black-box oracle in `CORPUS.md` and `PROVENANCE.md`.
  - [x] Add method-specific tests for every packed-stream prefix, malformed
    properties or headers, corrupt payloads and checks, unexpected trailing
    data, declared-size and CRC disagreement, dictionary/output/work limits,
    cancellation, and failure before sink finalization.
  - [x] Exercise unencrypted entries and, where the specifications permit,
    existing ZipCrypto and WinZip AES wrappers. Confirm that one unsupported or
    corrupt entry does not prevent callers from listing or selecting unrelated
    entries.
  - [x] Add Rust and installed-wheel Python coverage for metadata, byte-return,
    writer, callback, structured-error, batch-budget, and cancellation paths.
  - [x] Extend the ZIP fuzz generator/target with valid and hostile method-95
    and method-98 cases, then run the applicable format, Clippy, test,
    cargo-deny, fuzz, differential, and benchmark gates.
  - [x] Update `README.md`, `COMPATIBILITY.md`, `SECURITY.md`,
    `THREAT_MODEL.md`, `DEPENDENCIES.md`, `PROVENANCE.md`, `CORPUS.md`,
    `FUZZING.md`, `TESTING.md`, and `BENCHMARKS.md` wherever claims or evidence
    change. Do not claim support based only on admitting a decoder dependency.

## Deferred research

- [x] Research the remaining WinZip advanced recompression methods separately:
  - [x] Pin every authoritative registration and publicly available framing
    detail for MP3 method 94, JPEG method 96, and WavPack method 97. The audit
    found no public payload grammar for method 94; that evidence gap is now
    explicit rather than inferred from the method number.
  - [x] Identify safe, permissively licensed decoder candidates and exact
    revisions; model their memory, output, recursion, and CPU/work bounds before
    proposing a dependency or adaptation.
  - [ ] Establish deterministic positive fixtures and redistributable
    provenance for methods 94, 96, and 97. No admissible encoder/fixture set
    was found in the completed research pass; `PROVENANCE.md` records the
    searched primary specifications and rejected candidates. External tools
    may be checksum-pinned test oracles only and must never become runtime
    dependencies.
  - [x] Add stable enum/Python method names only after the registrations are
    verified. Until a complete method passes its gates, preserve its numeric ID
    and return a typed unsupported-method error on extraction.

- [x] Research the remaining ZIP structure and encryption boundaries as
  independent projects rather than prerequisites for methods 95 and 98:
  - [x] Define a bounded caller-supplied volume model for split/spanned ZIP,
    including disk ordering, missing/duplicate volumes, cross-volume ranges,
    maximum volume count, shared work, and cancellation.
  - [x] Pin the PKWARE Strong Encryption and encrypted-central-directory
    formats, cryptographic primitives, password/KDF limits, metadata exposure,
    and admissible implementation sources before considering support.
  - [x] Retain current listable/typed-unsupported behavior until parser,
    integrity, resource, provenance, and generated-fixture gates are complete.

- [ ] Validate representative benign WinZip-produced ZIPX archives for every
  implemented method without committing proprietary samples.
  - [x] Pin and locally verify WinZip-labelled BZip2, ZIP-LZMA, XZ, and
    Zstandard samples by archive hash, method/version/encryption inventory,
    entry metadata, exact output hashes, and full verification. Record their
    upstream revisions and local-only redistribution decision.
  - [ ] Acquire equivalent WinZip-produced PPMd method-98 evidence with a
    recorded WinZip tool version and authoring command. The available pinned
    `Zip.ppmd.zip` sample passes full extraction and integrity checks, but its
    producer and command are unrecorded and its filename does not establish
    WinZip provenance.
  - [ ] Recover exact authoring commands for the four WinZip-labelled upstream
    samples, or replace them with reproducible samples. Their hashes, upstream
    introduction commits, tool-version labels, complete inventories, outputs,
    and redistribution decision are recorded, but the upstream history does
    not contain the original GUI or command-line recipe.
