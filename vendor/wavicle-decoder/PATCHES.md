# unpackio decoder-only patch record

This directory starts from the exact `wavicle` 0.1.0 crates.io package
(checksum `1e312eaf22b4a7e5b7bf038edb3a7e4703c7b86dfabaea49d17af85e55eb76ab`),
corresponding to upstream commit
`4ac1134efe7a85a0b8c5921afc7c124160d179f2`. The unmodified per-file hashes
and the mapped WavPack 5.9.0 sources are recorded in the repository's
`PROVENANCE.md`.

The crates.io package's encoder module, encode-only sections in shared source,
tests, fixtures, and development-only dependency are deliberately omitted. No
encoder feature, module, bit writer, or compression API is present.

The maintained source changes are intentionally narrow:

- replace two `usize::is_multiple_of()` calls with equivalent remainder checks
  that compile on the repository's Rust 1.85 MSRV;
- make every input-sized allocation reachable through `decode_stream()` use
  `try_reserve_exact()` before growth and return `Error::AllocationFailed`;
- replace input-derived `expect`, unchecked indexing/slicing/casts, and
  debug-overflow-sensitive arithmetic in decoder paths with checked access,
  explicit bit-preserving conversions, or the format's intentional wrapping
  arithmetic; malformed state returns an existing typed decoder error;
- correct the legacy 40-bit total-sample reconstruction to match the official
  WavPack implementation;
- narrow the crate-level documentation and exports to the decoder-only build;
- add the local package manifest and this patch record.

New patch code and documentation are MIT. The copied upstream files retain
their MIT-or-Apache-2.0 grant, and the WavPack-derived portions retain the
BSD-3-Clause notice shipped at `LICENSES/BSD-3-Clause-wavpack.txt` in the
repository and Python distribution.
