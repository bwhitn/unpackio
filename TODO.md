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

- [ ] Adopt Rust 1.98.1 and optimize measured archive/stream hot paths — **Source/performance work is complete;
  executed Rust CI failures and downstream release remain**:
  - [x] Capture release-mode baselines across generated 7z, ZIP/ZIPX, RPM, CPIO, Debian, ARJ, LZ4, Zstandard, and
    `.Z` fixtures for inventory, byte-return, writer, callback, batch, and Python paths. Record wall time, CPU, peak
    memory, allocations/copies, decompressed/written bytes, disk I/O, cancellation latency, and wheel/native size.
  - [x] Pin primary local, CI, release, and Python-binding builds to Rust 1.98.1 while retaining and testing
    `rust-version = "1.85"` as the MSRV unless compatibility is deliberately changed.
  - [x] Profile container/header traversal, coder graphs, solid state, every admitted decoder, encryption/KDF, CRC and
    hash work, volume reads, sink callbacks, batch accounting, and PyO3 projection. Evaluate current UTF-16 conversion
    APIs only where format semantics match, then implement measured buffer reuse, allocation, copy, batching, and I/O
    improvements without optimizing one method at the expense of the complete archive lifecycle.
  - [x] Preserve safe Rust, checked parsing, configured caller policy, cancellation, integrity-before-success,
    password zeroization, path policy, typed partial/unsupported behavior, raw metadata, and public Python contracts.
  - [ ] Close the full workspace, fuzz/Miri, ABI3 artifact, and downstream release gates:
    - [x] Record locally passing formatting/Clippy/tests, cargo-deny, MSRV, property/fuzz/differential/oracle,
      installed-package, and controlled benchmark evidence in `BENCHMARKS.md`, `TESTING.md`, and `FUZZING.md`.
    - [x] Push performance candidate `c24d20c4eff723bae162579abbb0096afaeab929` and complete the six-platform ABI3
      wheel build plus Python 3.12/3.13/3.14 installed-wheel smoke matrix in Actions run `35598351623`.
    - [x] Correct the failure exposed by Actions run `35598351665`: the quality and platform jobs now use the
      repository-required workspace test command without benchmark execution and separately build every benchmark
      target on Ubuntu, macOS, and Windows. The complete ordinary suite, doctests, and non-executing benchmark build
      pass locally with Rust 1.98.1.
    - [x] Make fuzz and Miri commands explicitly use a tested pinned nightly toolchain despite the repository's
      `rust-toolchain.toml` selecting stable 1.98.1. The failed fuzz job invoked stable and rejected `-Zsanitizer`; the
      failed Miri job asked stable 1.98.1 for an unavailable component. Every command now selects
      `nightly-2026-09-01` explicitly; the 12-test Miri matrix, two fuzz-package invariant tests, and all eight
      10,000-execution cargo-fuzz targets pass locally with cargo-fuzz 0.13.2.
    - [ ] Rerun the complete Rust workflow and require quality, all three platform jobs, Miri, fuzz smoke, MSRV,
      32-bit, cargo-deny, documentation, and applicable exact-oracle jobs to pass on one final commit. If a fix changes
      runtime source or dependencies, rerun the affected parity and controlled benchmark evidence. GitHub Actions
      capacity is currently exhausted: implement and validate the workflow corrections locally, but do not dispatch
      or rerun the hosted workflow until the owner confirms the allowance has reset.
    - [ ] Designate the first fully passing successor as the immutable completion revision, then update ALES's exact
      pin from `36ab720c973c941987b83b10f414ab00bfa5b6aa` and pass archive/stream adapters, routing, output/ObjectRules,
      image, SBOM/license, runtime-pruning, and authorized-corpus performance acceptance.

  Revision `c24d20c4eff723bae162579abbb0096afaeab929` is the measured performance candidate, not the final completion
  revision while the executed CI failures above remain. `BENCHMARKS.md`, `TESTING.md`, and `FUZZING.md` record the
  reproducible baseline, profiles, local gate results, and artifact/report hashes.

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

- [x] Add bounded ZIP WavPack method 97 extraction:
  - [x] Pin APPNOTE section 5.9, the WavPack WinZip compatibility profile,
    official WavPack 4.80/5.9 source revisions, and the exact permissively
    licensed decoder dependency and adapted-source notices.
  - [x] Commit deterministic project-authored RIFF/WAVE inputs and WavPack
    4.80 `-hh` payloads covering 8-/16-/24-/32-bit integer, 32-bit float,
    mono, stereo, odd/four/sixteen-channel, custom-rate, multi-block, and
    wrapper-trailer reconstruction. Verify every output against the official
    WavPack 5.9 decoder.
  - [x] Implement a checked method-97 adapter around the decoder-only local
    fork of `wavicle` 0.1.0. Omit its encoder, retain the Rust 1.85 MSRV, make
    reachable input-sized allocations fallible, replace input-derived
    unchecked access/arithmetic, and bound blocks, metadata, channels, terms,
    allocations, output, work, and cancellation; require exact block and ZIP
    consumption; verify WavPack and ZIP CRCs; and reject hybrid, DSD, RF64,
    alternate wrappers, mono optimization, v5-only metadata, and unsupported
    channel layouts.
  - [x] Cover Rust and installed-wheel Python metadata, exact output,
    writer/callback/batch behavior, ZipCrypto/AES composition, every payload
    prefix, corruption, typed unsupported profiles, limits, cancellation,
    atomic failure, unrelated-entry access, and valid/hostile fuzz paths.
  - [x] Update the compatibility, security, dependency, provenance, corpus,
    fuzzing, testing, benchmark, and binding documentation for the admitted
    profile, then record the independently completed Windows WinZip product
    oracle without broadening the admitted decoder profile.

## Deferred research

- [ ] Complete the remaining MP3 recompression method while retaining the
  completed JPEG method as an independent supported profile:
  - [x] Pin every authoritative registration and publicly available framing
    detail for MP3 method 94 and JPEG method 96. The audit found no public
    payload grammar for method 94; that evidence gap is explicit rather than
    inferred from the method number.
  - [x] Identify safe, permissively licensed decoder candidates and exact
    revisions; model their memory, output, recursion, and CPU/work bounds before
    proposing a dependency or adaptation. Method 96 uses the MIT-licensed
    adaptation reference XArchive commit
    `c17ca22a2ae75f1d6f97d0a56725655c49b97295`; its direct C++/Qt expression is
    not admissible runtime code, and the audit in `PROVENANCE.md` records the
    validation, missing checks, and admitted safe-Rust rewrite. Method 94's
    matching packMP3 v1.0g implementation remains LGPL-3.0-or-later and is an
    external oracle only.
  - [x] Establish deterministic positive fixtures and redistributable
    provenance for methods 94 and 96. Fresh one-member WinZip 21.0.12288
    archives over project-authored MP3 and JPEG test patterns are committed as
    hash-pinned base64 fixtures with the exact product identities and GUI recipe
    recorded in `CORPUS.md` and `PROVENANCE.md`. Pinned packMP3 and
    XFileUnpacker oracles independently reconstructed the originals byte for
    byte. Those external tools remain test oracles only and are neither
    committed nor runtime dependencies.
  - [x] Build a clean-room differential corpus for method 94 without reading or
    adapting the LGPL implementation. The deterministic fixture generator
    creates 54 unique project-authored MPEG-1 Layer III/PMP pairs spanning all
    MPEG-1 bitrates and sample rates, mono/stereo modes, CRC, reservoir and
    header flags, ID3 metadata, duration, signal classes, and CBR/ABR/VBR.
    Every pair passed packMP3 v1.0g's internal verification and a separate
    byte-exact decode, and an independent regeneration matched the committed
    manifest and 108 base64 files exactly. LAME and packMP3 remain uncommitted
    external fixture tools only.
  - [x] Implement method 96 behind the checked Rust core and Python binding.
    The decoder bounds input, output, fallible model/slice allocation,
    metadata, bundle/slice counts, work, and cancellation; requires validated
    JPEG tables and exact outer stream consumption; composes with ZipCrypto and
    WinZip AES; and passes byte-exact fixture, corruption, sampled truncation,
    stored/compressed metadata, malformed-table/profile, limit, cancellation,
    atomic writer/batch, fuzz, and installed-wheel coverage.
  - [x] Derive and mechanically verify the independently observable method-94
    PMP envelope against all 54 clean-room pairs. The MIT-only analyzer proves
    the `MS\x0a` signature; sample-rate/channel-mode/fixed-bitrate descriptor;
    byte-4 padding, mid/side, intensity, switched-block, subblock-gain, SCFSI,
    preflag, and scalefac-scale feature bits; CRC, original, copyright,
    emphasis, ID3v1, and ID3v2 flags; reservoir marker; and big-endian
    MPEG-frame count. The entropy stream beginning at byte 11 remains
    unresolved, so this evidence does not admit a decoder.
  - [ ] Implement method 94 only if it later clears its independent
    specification, provenance, dependency, and positive-fixture gates. It still
    lacks an admissible implementation source and public payload grammar; the
    new differential corpus is evidence from which such a grammar may be
    derived, not a decoder specification by itself. The method remains listable
    with its stable metadata and returns a typed unsupported-method error. Do
    not translate or link the LGPL packMP3 oracle.
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

- [x] Validate representative benign WinZip-produced ZIPX archives for every
  implemented method without committing proprietary samples.
  - [x] Pin and locally verify WinZip-labelled BZip2, ZIP-LZMA, XZ, and
    Zstandard samples by archive hash, method/version/encryption inventory,
    entry metadata, exact output hashes, and full verification. Record their
    upstream revisions and local-only redistribution decision.
  - [x] Generate and verify fresh WinZip-produced PPMd method-98 evidence with
    WinZip 21.0 build 12288 on Windows. The exact executable identity, pinned
    project-authored input, GUI recipe, archive/member hashes and inventory,
    stock-`7zz` integrity result, and byte-exact production decoder/full-verify
    result are recorded in `CORPUS.md` and `PROVENANCE.md`.
  - [x] Generate and verify a fresh WavPack method-97 archive with WinZip 21.0
    build 12288 on Windows. Best Method selected WavPack for the deterministic
    multiblock WAV; the versioned recipe, hashes, method metadata, and
    byte-exact ignored-harness result are recorded without committing the
    proprietary archive.
  - [x] Replace the four command-incomplete WinZip-labelled upstream evidence
    roles with reproducible WinZip 24.0 build 14033 BZip2, ZIP-LZMA, XZ, and
    Zstandard samples over one pinned project-authored input. Every archive has
    an exact GUI recipe, hash and inventory, passes stock-`7zz` integrity, and
    passes production extraction plus full verification. The historical
    samples remain documented as supplemental local-only evidence.
