# ADR 0003: Python FFI and packaging boundary

- Status: Accepted
- Date: 2026-07-18
- Amended: 2026-07-21 (natural-order batch sink and Linux ARM64 wheels)
- Decision owners: unpackio maintainers

## Context

Phase 6 intentionally stabilized concrete owned Rust operations that can cross
an FFI boundary without exposing parser buffers, graph nodes, decoder generics,
or filesystem destinations. The Python package must preserve the same hostile-
input, resource, integrity, secret, and provenance contracts while allowing
Python callbacks and volume providers. CPython calls also introduce interpreter
locking, exception, reentrancy, allocation, and unwind boundaries that do not
belong in the core.

## Decision

1. Build `bindings/python` as a separately locked, root-workspace-excluded
   PyO3/maturin package. The distribution and import name is `unpackio`; the
   native limited-API module is `unpackio._native`; Python 3.9 is the minimum
   ABI.
2. Depend on the stable `unpackio` crate by path. Do not duplicate or
   reinterpret parsing, model validation, coder graphs, decoding,
   cryptography, checksums, volume sequencing, or path policy in the binding.
3. Expose only concrete owned archive sessions, metadata snapshots, limits,
   cancellation, work budgets, resource accounts, verification, and caller-
   directed output. Preserve raw UTF-16 and `Option` values as Python lists and
   `None`; never derive an extraction destination from a member name.
4. Detach Python during Rust-only opening, KDF, decoding, and verification.
   Carry only owned Python handles across that region and reattach for exactly
   one provider, writer, stream-callback, or batch-entry-sink invocation. Do
   not rely on the GIL as a Rust data lock.
5. Use bounded writer/callback chunks and provide no complete-output return API
   by default. A callback returns `None`/`True` to continue or `False` to
   cancel. Preserve provider/writer/callback exceptions exactly. Native success
   remains after the core CRC-finalizing helper returns.
   The batch surface directly adapts the stable natural-order `EntrySink` as
   `begin_entry(entry, size)`, `write_entry(index, chunk)`, and
   `finish_entry(index)`. One work budget and cancellation token span the
   complete call; folder reuse and CRC boundaries remain core behavior.
6. Let a Python volume provider return `bytes` or `None` for the exact
   `(index, expected_name)` request. Check the individual byte length before a
   fallible Rust copy; retain the core's aggregate volume/input/work/
   cancellation enforcement.
7. Map every stable core error kind to a distinct structured Python exception.
   Contain unexpected unwinds at custom native operations, retain
   `panic = "unwind"` in release artifacts, expose no panic payload through
   Python, and add no handwritten unsafe code. `InternalError` does not copy it into
   Python; the embedding process retains ownership of its global Rust panic
   hook. PyO3/`pyo3-ffi` own the isolated CPython unsafe
   boundary.
8. Move the Rust password temporary into zeroizing storage immediately and use
   only the core's per-archive secret path. Document that Rust cannot erase the
   caller's original Python `str`.
9. Give the binding its own cargo-deny policy, lockfile, type stub, license and
   notice payload, installed-wheel tests, sdist rebuild, MSRV check, and Linux
   x86-64/aarch64, macOS, and Windows wheel matrix. Linux aarch64 is installed
   and exercised on a native hosted ARM64 runner. Maturin and `7zz` are
   build/test tools only and never installed as runtime fallbacks; `py7zr` is
   not a runtime dependency or fallback either.

## Consequences

The core remains independent of CPython, while Python gets the same validated
model and decoder behavior without a second implementation. No CLI or console
script is shipped.
Rust-only work can run concurrently with Python, but callback/provider time and
Python-owned memory are controlled by the caller and are not charged as archive
state. The current core still buffers one bounded decoded folder; chunked FFI
delivery avoids an additional whole-entry Python copy but does not claim a
constant-memory decoder.

Because 7z integrity checks may trail output, Python sinks can observe bytes
before an error. Callers needing atomic trusted output must publish a temporary
destination only after native success. Reentrant calls operate on immutable
archives with separate cancellation/work state. During a batch,
`finish_entry` is the per-entry trust boundary; names are metadata and the sink
alone chooses destinations.

## Rejected alternatives

- Adding PyO3 to the core workspace: couples the security-critical core to a
  Python build/runtime boundary and broadens the dependency graph.
- Reimplementing container parsing in Python: creates divergent security,
  compatibility, and provenance behavior.
- Returning a complete `bytes` member by default: adds an avoidable whole-
  output Python allocation and obscures sink/CRC finalization semantics.
- Holding Python attached throughout decoding: prevents useful interpreter
  concurrency and encourages accidental borrowed-object use in decoder code.
- Converting callback exceptions to generic archive I/O errors: loses caller
  exception identity and structured control flow.
- Building with abort-on-panic: makes an unexpected native failure terminate
  the process instead of reaching the required FFI containment boundary.
