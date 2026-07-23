# Python binding rules

These rules apply to `bindings/python` in addition to the repository-wide
rules in the root `AGENTS.md`.

## Boundary and packaging

- This directory is a separate PyO3/maturin distribution named `unpackio`. Its
  native module is exactly `unpackio._native`.
- The binding is an adapter over the stable `unpackio` Rust API. Do not
  duplicate, fork, or reimplement parsing, validation, graph construction,
  decoding, cryptography, CRC handling, volume assembly, or path policy here.
- Keep the Rust core free of Python and PyO3 dependencies. Do not add a CLI,
  console script, or subprocess archive adapter. Do not modify code outside
  this repository.
- Treat Python as the caller-provided host platform; never bundle an
  interpreter. A new Python-level runtime dependency requires the same source,
  license, and provenance review as a Rust runtime dependency.
- Expose only unpacking, listing, verification, and caller-directed output.
  Never add archive creation, editing, compression, or automatic path-based
  extraction.

## FFI safety

- No Rust panic may cross the Python boundary. Guard every archive-processing
  or caller-invoking native operation with an explicit unwind boundary and
  translate an unexpected unwind into a stable internal exception without
  copying the panic payload into Python. Never place secrets in panic payloads
  or diagnostics. Generated field accessors and trivial
  value operations may rely on PyO3's own native trampoline; do not put archive
  parsing, decoding, or caller callbacks in those methods.
- Do not add handwritten `unsafe` code. If an unavoidable FFI operation later
  needs unsafe code, isolate it in a reviewed module, justify every invariant,
  add dedicated tests, and update the security and provenance documents first.
- Detach from the Python interpreter during parsing, KDF work, graph execution,
  decoding, CRC verification, and other Rust-only work. Never carry a borrowed
  Python reference across a detached section.
- Reattach only while invoking a Python volume provider, writer, or callback.
  Preserve callback exceptions exactly, stop the operation immediately, and
  ensure callback-triggered cancellation reaches the core token.
- Python-facing mutable state must remain safe under concurrent and
  free-threaded interpreters. Do not rely on the GIL as a Rust data lock.

## Data, integrity, and resources

- Use the core `Limits`, `CancellationToken`, `WorkBudget`, CRC finalization,
  and `VolumeProvider` contracts. Validate FFI-only chunk and conversion sizes
  before allocating or copying.
- Streaming and writer APIs are the default extraction surfaces. Do not make a
  complete decoded-output copy merely to cross the FFI boundary.
- A callback or writer may observe unverified chunks, but native success must
  not be returned until the core member/folder CRC finalization succeeds.
- Preserve exact raw UTF-16 units for 7z and exact raw name bytes for ZIP/RPM,
  alongside optional size/CRC metadata. Never turn an archive member name into
  a filesystem destination, and expose the core safe-path classification
  without altering member order or mapping.
- Python volume providers receive the exact zero-based index and expected
  volume name. Their results remain subject to volume-count, aggregate-input,
  work, and cancellation limits.
- Password state is per archive. Zeroize every temporary Rust password copy,
  never include passwords in exceptions or representations, and never cache a
  plaintext or derived secret globally. Python-owned strings cannot be erased
  by Rust and must be documented accordingly.

## Errors, dependencies, and tests

- Map every stable core error category to a distinct Python exception with
  machine-readable fields. Preserve `Option` values as `None` and never
  silently downgrade an unsupported feature.
- Binding runtime dependencies must satisfy the root license allowlist and the
  separate locked package must pass cargo-deny. Record exact versions,
  licenses, enabled features, unsafe/FFI boundaries, and origins.
- Keep Python type stubs synchronized with the native API.
- Tests must cover the public import path, metadata, structured errors,
  password handling, cancellation, GIL detachment, callback failure,
  CRC-finalized output, path classification, and Python volume providers.
- Wheel CI must build and install the produced wheel before running binding
  tests on Linux, macOS, and Windows. `7zz` remains an optional test oracle and
  is never invoked by the installed package.
