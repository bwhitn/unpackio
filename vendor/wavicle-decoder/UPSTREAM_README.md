# wavicle

A pure-Rust WavPack v5 codec.

A *wavicle* is Eddington's word for the quantum entity that is both wave and
particle. A lossless codec makes audio exactly that: a continuous wave to the
ear, discrete bits on disk, one identity in both observations.

## Status

**Round-trip codec, verified against the reference.** Both directions are
lossless and bit-exact: decode and encode of 16/24/32-bit integer and 32-bit
float, mono and stereo, for inputs of any length (long data is split into
independent blocks). Float survives a BLAKE3 identity check over the decoded
bytes in both directions. Every milestone is gated bit-for-bit against the
reference `wvunpack`/`wavpack` CLI over a corpus; the decoder is additionally
fuzzed and never panics on hostile input. Decode is the default build; `encode`
is an additive feature.

The founding plan, milestone ladder, and conformance-oracle method live in
[design_docs/2026-07-15_wavpack_codec_plan.md](design_docs/2026-07-15_wavpack_codec_plan.md).

## Scope

- Lossless mono/stereo decode and encode of the WavPack v5 stream
  (versions 0x402..=0x410 read; 0x410 written).
- 16/24/32-bit integer and **bit-exact 32-bit float** PCM (including signed
  zero, denormals, and NaN payloads).
- Pure Rust, std-only, no C anywhere in the build graph; builds for wasm.
- Feature-split `decode` / `encode`.

Out of scope: DSD, hybrid/lossy modes and `.wvc` correction files, more than
two channels, pre-4.0 legacy streams. Out-of-scope streams are rejected with a
clear error, never silently mishandled.

## Relationship to WavPack

WavPack is David Bryant's audio compression format
([wavpack.com](https://www.wavpack.com), [dbry/WavPack](https://github.com/dbry/WavPack),
BSD-3-Clause). This crate is an independent Rust implementation of the WavPack
v5 bitstream, written for interoperability. It is not affiliated with or
endorsed by the WavPack project. Portions will be derived from the BSD-3-Clause
reference and ports; see [ATTRIBUTION.md](ATTRIBUTION.md) and
[PROVENANCE.md](PROVENANCE.md).

## License

Dual-licensed under Apache-2.0 or MIT, at your option.
