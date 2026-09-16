# Attribution

wavicle's own code is dual-licensed MIT OR Apache-2.0. Portions of it will be
derived from the following BSD-3-Clause sources, which permit that reuse with
attribution. This file carries the required notices; `PROVENANCE.md` records
which module derives from which source file.

No code has been ported yet (the crate is a name claim). When porting begins,
each derived file gets a header comment pointing here, and this file gains the
verbatim license text and copyright lines of every source actually used:

- **WavPack** (the C reference implementation) — Copyright David Bryant /
  Conifer Software. BSD-3-Clause.
  <https://github.com/dbry/WavPack>
- **Go-WavPack-encoder** and **Haxe-WavPack-Decoder** — Copyright Peter
  McQuillan; portions Conifer Software. BSD-3-Clause.
  <https://github.com/soiaf/Go-WavPack-encoder>,
  <https://github.com/soiaf/Haxe-WavPack-Decoder>
- **javasound-wavpack** — BSD-3-Clause; a fork of Peter McQuillan's Java
  "tiny" WavPack ports. <https://github.com/Tianscar/javasound-wavpack>

Per BSD-3-Clause clause 3, nothing in this crate claims endorsement by the
WavPack project, David Bryant, Conifer Software, or the port authors. The
crate name is deliberately not `wavpack*`.

Only the BSD-3-Clause sources above are consulted during development. GPL and
LGPL WavPack code (plugins, forks) is off-limits to keep the derivation clean.
