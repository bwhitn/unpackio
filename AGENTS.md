# Repository rules

These rules apply to the entire repository.

## Scope and architecture

- This project is an unpack-only 7z, ZIP, RPM, CPIO, Debian-package, and ARJ
  archive reader with explicitly separated unpack-only readers for LZ4 frames,
  Zstandard frames, and Unix `compress` `.Z` streams. `Archive` remains
  7z-specific; every other container uses its own concrete archive type. Do not
  add an archive or stream writer, editor, mutation surface, or compression API.
- The shipped product is the Python `unpackio` package backed by the Rust core.
  Do not add or restore a CLI, console script, executable frontend, or
  subprocess-based archive interface.
- Keep byte parsing, validated archive models, coder-graph construction,
  decoders, volume access, filesystem path policy, the Rust core, and Python
  binding in separate layers.
- Do not modify or integrate with ALES unless a later task explicitly changes
  that scope.
- Preserve raw archive metadata. Never extract through a member path until an
  explicit filesystem policy has validated it.
- Unsupported valid features return a typed error. They must never panic,
  silently degrade, or fall back to another implementation.
- `7zz`, `rpmfile`, and `pyzipper` are permitted only as test oracles. They
  must never be runtime dependencies or fallbacks.

## Hostile-input and resource-safety rules

- Treat every archive byte and every volume response as hostile. Malformed
  input must return an error and must never cause a panic.
- The core crate must retain `#![forbid(unsafe_code)]`.
- Archive-processing paths must not use input-derived `unwrap`, `expect`,
  `panic!`, unchecked indexing, unchecked integer casts, unchecked offset or
  size arithmetic, or allocation before the applicable limit is validated.
- Use fallible integer conversion, checked arithmetic, bounded sub-readers,
  exact property consumption, and fallible allocation for attacker-controlled
  sizes.
- Enforce header, count, property, dictionary, output, volume, KDF, recursion,
  work-budget, and cancellation limits before allocation or expensive work.
- Verify every applicable start-header, next-header, encoded-header, folder,
  packed-stream, and member CRC. Extraction must not report success before the
  member CRC is verified.
- Represent a missing CRC and an unknown unpacked size with `Option`; never use
  a numeric sentinel.
- Invalid or unsafe paths must not change member ordering or file-to-stream
  mapping.
- Passwords and derived secrets are per archive, zeroized on drop, and never
  stored in a process-global cache. Use established cryptographic crates; do
  not implement AES or SHA manually.
- Do not weaken limits, validation, tests, lint rules, or error classification
  to make a test pass.

## Licensing, dependencies, and provenance

- License new original Rust code solely under MIT.
- Preserve the upstream Go project's BSD-3-Clause notice and exact provenance
  for every translated or adapted part.
- Runtime dependencies are restricted to MIT, Apache-2.0, BSD-2-Clause,
  BSD-3-Clause, ISC, Zlib, and Unicode-style licenses.
- Do not use GPL, LGPL, AGPL, MPL, SSPL, Commons Clause, noncommercial code,
  official 7-Zip source, or p7zip source.
- Every imported algorithm or adapted implementation requires a documented
  source, revision, license, and provenance record before it is integrated.
- Keep cargo-deny license, source, ban, and advisory enforcement current when
  dependencies change.

## Documentation and compatibility evidence

- Keep `COMPATIBILITY.md`, `SECURITY.md`, `THREAT_MODEL.md`,
  `DEPENDENCIES.md`, `PROVENANCE.md`, and `FUZZING.md` current with every
  material implementation change.
- Do not claim support for a method or feature without a positive fixture and
  appropriate corruption, truncation, and limit tests.
- Record corpus origin, revision, license or redistribution status, hashes,
  and expected oracle results before committing fixtures.

## Required review gates

Run targeted tests during development. Before completing a phase, run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

Run applicable Miri, property, fuzz-smoke, differential, and benchmark checks
as well. A phase is not complete while an applicable gate is failing or its
absence is undocumented.
