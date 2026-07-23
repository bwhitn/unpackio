# Compatibility

## Current implementation status

**Phase 7 adds a separate Python adapter but changes no codec compatibility
claim; decoding is implemented only for the rows explicitly marked supported
below.** The core locates regular and bounded
SFX signatures; verifies stored, encoded, and encrypted header layers;
validates arbitrary coder graphs; resolves supported external folder records
and metadata;
assembles bounded sequential volumes; and exposes CRC-finalizing member
extraction and archive verification through the Python package. No CLI,
console script, or executable frontend is shipped.

Passwords are owned and zeroized per archive. Path and memory
`VolumeProvider`s support sequential `.001` parts, including encrypted data and
packed streams crossing part boundaries. The current member reader still
streams a bounded member out of a fully decoded in-memory folder; it is not a
constant-memory decompression pipeline. Random access to a solid member
therefore re-decodes that folder, while `Archive::verify` and
`Archive::extract_entries_to` decode each folder once in natural order. A sink
entry is not finalized until its applicable CRC succeeds.

The supported public surface is listed in `API.md`. Raw parser, envelope, and
coder-graph exports are available only through the hidden
`unstable-internals` regression/fuzz feature and are not compatibility API.
The `unpackio` Python distribution delegates to that stable surface and adds no
method implementation or external runtime fallback. Its natural-order batch
sink uses the core's one-decode-per-folder path with one shared work budget and
cancellation token.

Only rows explicitly marked supported are compatibility claims. Fixture
coverage and differential evidence do not imply support beyond the stated
implementation boundary.

## ZIP archives

`ZipArchive` is a separate unpack-only model. It is not routed through the 7z
`Archive`, and no ZIP writer/editor API exists. Its reader supports the
structure, compression, encryption, integrity, and metadata boundaries listed
below.

| Area | Supported | Evidence | Explicit boundary |
| --- | --- | --- | --- |
| Structure | Ordinary ZIP, ZIP64 sizes/offsets/counts, bounded SFX prefixes, central/local headers, ZIP64 and signed/unsigned data descriptors, exact end record, raw archive comment | Generated Store/Deflate archives, empty and duplicate entries, CP437 names, SFX, ZIP64 SFX, descriptor and truncation/corruption cases | Split/spanned archives, central-directory encryption, and PKWARE Strong Encryption return `UnsupportedFeature` |
| Compression | Store (0), Deflate (8), Deflate64 (9), BZip2 (12), ZIP-LZMA (14), deprecated Zstandard (20), Zstandard (93) | Exact generated/fixed-vector extraction for every listed method; a 24-profile compatibility matrix; packed corruption, truncation, declared-size, output/work/cancellation tests | XZ (95), PPMd (98), and all unregistered method IDs are listable but extraction is typed unsupported |
| Encryption | Traditional ZipCrypto; WinZip AES AE-1/AE-2 with 128-, 192-, and 256-bit keys | Generated Store/Deflate ZipCrypto cases; all AES key sizes; AE-1 and AE-2; no/wrong password; authentication corruption including an empty AE-2 member; exact extraction/verification across method/version/key-size profiles | Passwords are caller-supplied bytes; no encoding is guessed. Strong encryption and encrypted central directories are unsupported |
| Integrity | Local/central agreement, exact ranges, AES authentication code, decoded size, applicable CRC-32 | Corruption before/inside/after payload, bad CRC/authenticator, bad password, descriptor mismatch, truncation | AE-2 follows the WinZip AES rule that authentication replaces a meaningful CRC field |
| Metadata | Raw and decoded names, raw comments/extras, duplicate order, DOS time, creator/version flags, attributes, Unix mode, directory/symlink classification, safe-path result | Generated duplicates, empty members, CP437/Unicode-path handling, modes, traversal/path-policy cases | Extended timestamp extras are preserved raw but not yet normalized into additional timestamp fields; no filesystem extraction |
| Python API | Native `ZipArchive`/`ZipEntry` expose the documented metadata and extraction values | Installed-wheel tests cover duplicate/empty entries, every recorded metadata field, no/wrong/correct ZipCrypto passwords, AE-2 AES-256 exact extraction, corruption, and caller-owned seekable output | There is no compatibility facade, writer/mutation API, automatic path use, or whole-member return method |

ZIP input, header, entry/name, decoded-output, dictionary, work, cancellation,
and SFX limits are checked before the relevant allocation or decoder work.
Each entry is decoded and verified before `extract_entry_to` writes its first
byte. Natural-order batch extraction shares total-output/work/cancellation
accounting and uses `finish_entry` as the trusted boundary.

## RPM packages

`RpmArchive` implements a native read/list/extract surface with strict
typed-header validation, CRC-newc, legacy LZMA and uncompressed payloads,
package digest checks, cancellation/work budgets, explicit resource limits,
duplicate preservation, and safe-path metadata. The API intentionally exposes
numeric RPM tags and byte-preserving typed values as its canonical surface.
Its symbolic projection returns names and scalar values without changing or
discarding that canonical metadata.

| Area | Supported | Evidence | Explicit boundary |
| --- | --- | --- | --- |
| Package envelope | RPM lead major 3/4, signature header, main header, all standard scalar/array/bin header value kinds, duplicate tag order, exact store ranges and alignment | Generated headers, shared-value amplification, truncation, offset/count/type/range/limit mutations | Header values remain bytes unless intrinsically numeric; no locale or policy interpretation is invented |
| Payload compression | Uncompressed, gzip, BZip2, XZ, legacy LZMA-alone, Zstandard | Exact extraction from generated/fixed vectors for each compressor; header/trailer/index/dictionary/truncation/output/work/cancellation tests | Unsupported compressors return a stable `UnsupportedFeature` |
| Payload archive | Shared checked CPIO parser: SVR4 `newc` (`070701`), CRC-`newc` (`070702`), portable ASCII `odc` (`070707`), and historical binary little-/big-endian records | Files, directories, symlinks, empty/duplicate names, every supported standalone layout, CRC members, trailer/padding/truncation/range cases, and exact name/data/mode checks over a generated gzip/newc package | The incompatible large-file `0707010` variant and unknown layouts are typed unsupported or malformed; no filesystem reconstruction |
| Metadata | Raw byte name, lossy display name, inode, mode/permissions, uid/gid, link count, mtime, size, device/rdev numbers, symlink/hard-link metadata, safe-path result | Generated mixed metadata and duplicate-order extraction | No automatic reconstruction of hard links, symlinks, owners, modes, or paths on a filesystem |
| Integrity | Signature-header SHA-1/SHA-256 digests of the main header; compressed and uncompressed payload SHA-256 tags (declared algorithm 8 when present); gzip CRC/ISIZE; XZ structural CRCs; Zstandard checksums; CRC-newc member sums | Positive digest package plus corruption of header, payload, compressor trailer, and member checksum; unsupported digest-algorithm regressions | OpenPGP blobs are exposed but not authenticated. Legacy package MD5, per-file digest tables, SHA3-256-only header digests, and SHA-512/SHA-3 payload digest tags are not verified; a package declaring the latter is typed unsupported rather than silently trusted |
| Python API | Native `RpmArchive`/`RpmEntry` plus `RpmHeader.as_named_dict()` expose the complete symbolic tag set, scalar values, unknown numeric tags, lead metadata, ordered members, and verified extraction | Installed-wheel tests exercise selected and non-selected named tags, string/I18N/integer/array values, unknown tags, lead reserved bytes, duplicate/empty members, path opening, and exact extraction | There is no filesystem extraction, private-header emulation, compatibility facade, or partial metadata from a corrupt/unsupported payload |

The complete decoded CPIO payload is currently retained in bounded memory, so
`retained_payload_bytes()` may approach `max_total_output_bytes`. This is not a
constant-memory RPM stream. Package-level supported digests are checked during
open, before any member can be emitted; applicable CPIO CRC is checked again
before a member write or `finish_entry`.

## CPIO, Debian packages, and ARJ

These are concrete unpack-only readers. They are not routed through the 7z
`Archive`, do not expose writer/editor APIs, and never choose filesystem paths.

| Format | Supported boundary | Positive and hostile evidence | Explicit limitation |
| --- | --- | --- | --- |
| Standalone CPIO | `newc`, CRC-`newc`, `odc`, binary little-endian, binary big-endian, and mixed input; exact headers, names, padding, trailer, numeric metadata, symlink bytes, and CRC-newc sums | Generated exact extraction for all five layouts; mixed duplicate/empty Python fixture; CRC corruption, truncation, nonzero padding/trailing data, count/name/input/output/work/cancellation limits; arbitrary and CRC-correct generated fuzz paths | Raw CPIO only; no automatic compression-wrapper detection, hard-link reconstruction, device creation, or path use; `0707010` is unsupported |
| Debian binary package (`.deb`) | Debian format `2.0` in a checked System V `ar`; optional underscore members; uncompressed/gzip/XZ/Zstandard control tar; uncompressed/gzip/XZ/Zstandard/BZip2/LZMA-alone data tar; V7/ustar, GNU long-name/link, and POSIX pax metadata | Exact generated outer/inner extraction, links and empty files; static vectors for every permitted compressor; positive GNU/pax records plus malformed pax, ar/tar checksum, ordering, truncation, count/name/header/input/output/work/cancellation tests; arbitrary/generated fuzz paths and installed-wheel tests | No general `ar`/tar API, BSD/GNU ar name table, package installation/scripts, signature verification, filesystem ownership/mode/link application, or automatic path use; both decoded tar images are retained under the total-output limit |
| ARJ | Bounded SFX scan; main/local/extended headers; methods 0–4 and zero-length methods 8/9; archive/member comments, raw names, host/version/flags/time/mode metadata; header and member CRC-32 | Synthetic stored/SFX/no-data fixtures; redistributable real-encoder method 1–4 fixtures with exact 11,357-byte SHA-256; packed corruption, truncation, header/member CRC, dictionary/output/work/cancellation/SFX/count tests; installed-wheel and arbitrary/generated fuzz paths | Single-volume, unencrypted data only. Encryption reports `PasswordRequired`; split/multi-volume, security envelopes, unknown methods, and host text conversion are typed unsupported. ARJ does not expose symlink or filesystem reconstruction |

`DebArchive` retains the original package plus both bounded decoded tar images.
`ArjArchive::extract_entry_to` decodes and CRC-verifies a complete member before
the first caller write; its batch sink calls `finish_entry` only after the same
verification. The method 1–3 adapter preflights 68 KiB for the dependency's
64-KiB ring and fixed Huffman tables; method 4 preflights its 8-KiB logical
history before output allocation or decoding.

## Standalone compressed streams

These readers are separate from the 7z `Archive` model and do not broaden any
7z container claim. They expose one unnamed output through the Python
`open_stream_*` functions; no command-line surface exists.

| Format | Supported boundary | Positive and hostile evidence | Known limitations |
| --- | --- | --- | --- |
| LZ4 frame (`.lz4`) | Standard version-1 frames, legacy frames, concatenated data frames, skippable frames, linked/independent blocks, optional content size, block checksums, and content checksums | Generated standard checked frames with exact output; generated legacy and concatenated/skippable stream; every prefix of a checked frame; payload/checksum corruption; frame/dictionary/output/work/cancellation limits; exact 1,000,000-byte differential against LZ4 CLI 1.10.0 | Frames declaring an external dictionary are listable but extraction returns typed `UnsupportedStreamFeature`; no magicless raw-block file API |
| Zstandard frame (`.zst`, `.zstd`) | Standard magic-bearing frames, concatenated data frames, skippable frames, raw/RLE/compressed blocks through `ruzstd`, optional content size, content checksum, and bounded windows | Generated raw checked and concatenated/skippable frames with exact output; every checked-frame prefix; checksum corruption; reserved/block/window/frame/output limits; exact 1,000,000-byte differential against Zstandard CLI 1.5.7 | Nonzero dictionary IDs are listable but extraction returns typed `UnsupportedStreamFeature`; magicless frames are not detected or accepted |
| Unix `compress` (`.Z`) | One 9- through 16-bit variable-width LZW stream, block and non-block modes, code-width transitions, dictionary saturation, and CLEAR resets | Fixed macOS 26.5.1 `/usr/bin/compress` exact fixture; generated width-transition/CLEAR and non-block streams; exact 1,000,000-byte and 2-MiB random native-tool differentials; reserved-width/dictionary/output/work/cancellation regressions | The format declares neither output size nor checksum. A truncation after a complete code may be indistinguishable from a shorter valid stream, so success is decoder completion, not an integrity guarantee |

All three retain unknown decoded size as `None`, enforce it during decoding,
and never infer an output filename. Python output uses bounded writer/callback
chunks and has no default whole-output return API.

## Methods and filters

In addition to the named external fixtures below, the corpus-free
`generated_oracle` test asks stock `7zz` 26.02 to author fresh Copy, LZMA,
LZMA2, Delta, BCJ, BCJ2, PPC, ARM, ARM64, SPARC, Deflate, BZip2, and PPMd
archives. Each method has exact bytes/SHA-256/size/CRC/name comparison and a
packed-data corruption rejection; transforming filter cases also prove that
the positive source was changed in the packed representation. This generated
evidence does not extend to the private Brotli/LZ4/Zstd identifiers that stock
`7zz` cannot author or decode.

An additional exact-26.02 property matrix generates 24 temporary archives. It
positively covers 64 KiB, 1 MiB, and 4 MiB LZMA/LZMA2 dictionaries; non-default
LZMA `lc`/`lp`/`pb`; PPMd orders 2 and 16 with 1 MiB and 4 MiB models; Delta
distances 1, 4, and 256; BZip2 100 KiB and 900 KiB blocks; distinct Deflate
levels 1 and 9; BCJ/PPC/Delta-to-LZMA2 chains; LZMA, LZMA2-chain, and PPMd data
encryption; encrypted headers; and four-entry solid/non-solid layouts including
an empty member. The harness asserts exact serialized coder properties or
stream headers, exact oracle method tokens, graph composition, folder counts,
metadata, bytes, SHA-256, CRC, and full verification. This is expanded positive
evidence. The same 24 cases now reject packed corruption, strategic physical
truncation, entry-output/work/cancellation limits, and applicable dictionary
limits. Plain headers additionally receive CRC-correct shortened packed-size
declarations plus oversized and empty coder-property declarations; BZip2 block
headers are invalidated separately. Encrypted-header inner properties are not
pretended to be directly mutable, but those cases retain corruption,
truncation, password, resource, work, and cancellation coverage.

The checksum-pinned Windows oracle job regenerates this core and property
matrix plus the Phase 5 matrix with the exact stock 26.02 executable. Its first
expanded run passed all four core/property tests and both Phase 5 tests at
commit `d1eabdf` in GitHub Actions run
[`29787328152`](https://github.com/bwhitn/unpackio/actions/runs/29787328152).
Its archives exist only in runner temporary directories. This turns the
existing opt-in evidence into a repeatable gate without broadening a codec or
metadata claim.

| Method/filter | Fixture coverage | Implementation status | Differential evidence |
| --- | --- | --- | --- |
| Copy | Registered; bundled fixture | Supported for validated graphs | `copy.7z`; corrupted-member, packed/folder/member CRC, output/work/cancellation regressions |
| Delta | Registered; bundled fixture | Supported, distances 1..256 | `delta.7z`; local property/cancellation tests |
| LZMA | Registered; bundled fixture | Supported for declared size and locally tested unknown-size EOS | `lzma.7z`; positive CRC-finalizing `Archive` extraction and raw EOS unit with every-prefix truncation, non-final/trailing range-state rejection, and malicious dictionary tests |
| LZMA2 | Registered; bundled fixture | Supported with reset/chunk/EOS validation, including locally tested unknown-size EOS | `lzma2.7z`; positive known/unknown-size uncompressed chunk, every-prefix truncation, output/cancellation tests |
| BCJ/x86 | Registered; bundled fixture | Supported | `bcj.7z`; exact bytes/SHA-256/member CRC |
| BCJ2 | Registered; bundled fixture | Supported for validated four-input graphs | `bcj2.7z`; positive/truncated range input and output-limit tests |
| PPC | Registered; bundled fixture | Supported | `ppc.7z`; tail-safety test |
| ARM | Registered; bundled fixture | Supported | `arm.7z`; exact bytes/SHA-256/member CRC |
| ARM64 | Registered; bundled fixture | Supported | `arm64.7z`; exact bytes/SHA-256/member CRC |
| SPARC | Registered; bundled fixture | Supported | `sparc.7z`; exact bytes/SHA-256/member CRC |
| Deflate | Registered; bundled fixture | Supported as raw Deflate with bounded 32 KiB working-memory charge and final-block unknown-size termination | `deflate.7z`; exact `7zz` bytes/SHA-256/size/CRC/metadata plus positive unknown-size and every-prefix truncation, output, dictionary, work, and cancellation tests |
| BZip2 | Registered; bundled fixture | Supported with block-size preflight and bounded adapter | `bzip2.7z`; exact `7zz` bytes/SHA-256/size/CRC/metadata plus malformed header, memory, and cancellation tests |
| PPMd | Registered; bundled fixture | Supported for PPMd7 variant H with declared output size; properties are exactly canonical five-byte order/memory or a seven-byte compatibility form with two zero reserved bytes | `ppmd.7z`; exact bytes/SHA-256/size/CRC/metadata plus generated exact extraction for both property forms, nonzero-reserved, wrong-length, declared-property truncation, malicious-memory, output/work, and cancellation tests. A fixed order-6/64-KiB packed vector supplies the decoded bytes |
| AES-256-CBC/SHA-256 | Registered; encrypted fixtures | Supported for declared-size AES-256-CBC streams and bounded direct/iterated 7z SHA-256 KDF | `aes7z.7z`, `t2.7z`-`t5.7z`, `7zcracker.7z`; generated header-encrypted and data-encrypted Copy exact `7zz` differentials with corruption and typed missing/wrong-password states; generated BCJ→LZMA2→AES encrypted-header differential; block truncation and KDF limit/work/cancellation tests |
| Brotli | Registered; bundled private-method fixture | Supported for complete streams, including the optional private 16-byte 7-Zip prefix; unfinished flush-only streams are malformed | `brotli.7z` verifies and matches the common `deflate.7z` corpus bytes/SHA-256/metadata; an independently recorded complete `hello\n` stream succeeds while its end-marker-truncated flush-only prefix returns `Format`; the standard oracle does not recognize this private method ID |
| LZ4 | Registered; bundled private-method fixture | Supported for checked LZ4 frames without external dictionaries | `lz4.7z` verifies and matches the common `deflate.7z` corpus bytes/SHA-256/metadata; stock `7zz` 26.02 rejects this private method ID |
| Zstd | Registered; bundled private-method fixture | Supported for frames whose declared window is within limits; dictionary frames are typed unsupported | `zstd.7z` verifies and matches the common `deflate.7z` corpus bytes/SHA-256/metadata; stock `7zz` 26.02 rejects this private method ID |
| Deflate64 | Not registered | Supported for stored, fixed, and dynamic blocks with a checked 64 KiB history charge and final-block EOS | Generated long-distance `deflate64.7z`; exact `7zz` bytes/SHA-256/size/CRC/metadata, direct dynamic-block regression, every stored-prefix truncation, trailing input, corruption, dictionary/output/work tests |
| IA64 | Not registered | Supported for empty or four-byte start properties; complete 16-byte bundles are transformed and tails are retained | Generated transforming IA64 bundle archive; exact `7zz` bytes/SHA-256/size/CRC/metadata and corruption evidence |
| ARM Thumb | Not registered | Supported for empty or four-byte start properties and complete aligned instructions | Generated transforming ARMT archive plus nonzero-start unit vector; exact `7zz` bytes/SHA-256/size/CRC/metadata and corruption evidence |
| RISC-V | Not registered | Supported for JAL and sequential AUIPC pairs with empty or four-byte start properties; the architectural low alignment bit is ignored | Generated transforming JAL/AUIPC archive plus nonzero-start unit vector; exact `7zz` bytes/SHA-256/size/CRC/metadata and corruption evidence |
| Swap2 | Not registered | Supported; complete two-byte groups are reversed and an odd tail is retained | Generated transforming Swap2 archive; exact `7zz` bytes/SHA-256/size/CRC/metadata, tail, property, and corruption tests |
| Swap4 | Not registered | Supported; complete four-byte groups are reversed and a short tail is retained | Generated transforming Swap4 archive; exact `7zz` differential, tail/property/corruption tests, and real five-part encrypted/unencrypted volume evidence |

## Container features and metadata

| Feature | Fixture coverage | Implementation status |
| --- | --- | --- |
| Plain/encoded headers | Both covered by tests | Supported when every encoded-header coder is one of the supported methods; stored, encoded-folder/substream, and parsed-header bounds/CRCs enforced. Multiple decoded substreams are consumed exactly and concatenated in stream order; a generated two-substream Copy header containing one named empty file is accepted by stock `7zz` 26.02. Rust also safely handles a generated multi-folder form, but stock `7zz` rejects that form, so it is not a 7zz-compatibility claim |
| Encrypted headers/data | Covered by password tests | Supported for graphs composed of supported methods; per-archive zeroized password state, KDF bound before hashing, and `PasswordRequired`/`WrongPasswordOrCorrupt` classification; positive external fixtures plus corpus-free generated header/data encryption, corruption, and exact oracle comparison |
| Solid archives | Natural-order and pooled access exercised | Supported for core methods; `lzma.7z`, `lzma2.7z`, `delta.7z`, and `bcj2.7z` provide positive solid evidence; verification and caller-owned sink extraction decode each folder once |
| Non-solid archives | Covered by fixtures | Supported for core methods; `copy.7z` provides positive non-solid evidence |
| SFX | Fixed 1 MiB scan; bundled `sfx.exe` | Bounded configurable discovery plus supported encoded-header/member decoding; external `sfx.exe` and a corpus-free synthetic `MZ` prefix over a generated Copy archive list, verify, and match oracle bytes/SHA-256 |
| Sequential `.001` volumes | Filesystem discovery; six bundled volumes | Supported through bounded object-safe `VolumeProvider`, `PathVolumeProvider`, and `MemoryVolumeProvider`; `multi.7z.001`-`.006` verifies through `Archive::open_path`, and a deterministic five-part unencrypted split verifies through memory |
| Encrypted multi-volume | No identified bundled five-volume evidence | Supported by both a deterministic five-part split of `aes7z.7z` and a separately `7zz`-authored five-part encrypted Swap4 archive; exact output/metadata match the oracle |
| Split entries | No separate claim from bundled volume archive | Supported through checked logical concatenation; the six-part fixture exercises packed data across part boundaries |
| Empty files/directories | Bundled fixtures | EmptyStream/EmptyFile records parsed and mapped; empty files can be opened as verified zero-byte members; directory extraction returns typed unsupported feature |
| UTF-16/Unicode names | UTF-16 decoding in parser | Exact UTF-16 code units, including unpaired surrogates, are preserved for inline and external names; lossy display conversion remains caller policy |
| Timestamps | Inline properties parsed | Inline and external raw Windows FILETIME creation/access/modification values are preserved |
| Windows/POSIX attributes and modes | Parsed/mapped | Inline and external raw Windows attributes are preserved; Unix-extension high bits expose a POSIX mode without applying it to a filesystem |
| Symlink metadata | Mode mapping exists; no bundled corpus assertion | Unix-extension mode identifies symlinks and member bytes preserve the target; a generated `7zz -snl` archive matches mode and target bytes |
| Hard links | `-snh` capability probe | Rust preserves both entries and returns the expected bytes for each on the macOS, Linux, and Windows probes. Stock extraction restored two ordinary files on macOS and Linux; Windows identity was unavailable. No automatic filesystem extraction or inode-preservation claim exists |
| Duplicate names | Duplicate-name fixtures | Preserved in archive order as distinct entries; there is no automatic extraction/collision policy |
| External folder/name/time/attribute streams | Explicit TODO errors | Supported for main-stream folder definitions and referenced Name/time/attribute/StartPos data. `DataIndex` selects a decoded AdditionalStreamsInfo folder output; folder definitions are staged, decoded, checksum-verified, reparsed for the exact declared folder count, consumed exactly, and fully revalidated. Synthetic one- and two-folder forms are accepted by stock `7zz` 26.02; encrypted, truncation, trailing-byte, index, CRC, coder-count, and output-limit regressions exercise the production API |
| Additional streams | Explicit TODO error | Parsed and decoded once per folder when referenced by external folder definitions or supported external file properties. `Archive::verify` sequentially decodes every folder, including unreferenced folders, and verifies packed, folder, and logical-substream CRCs while sharing limits and operation control with main streams. Unreferenced stream bytes are not exposed by the public API |
| StartPos | Explicit TODO error | Inline and external values preserved as `Option<u64>` |
| Anti-items | ID defined but not handled in FilesInfo | Parsed for streamless records |
| Archive properties | Explicit TODO error | Bounded raw properties retained |
| Comments | ID defined; no parser handling found | Bounded raw property retained without semantic text decoding. A synthetic file-comment candidate makes stock `7zz` 26.02 emit `Unsupported feature`; an archive-property candidate is ignored without a listed Comment field. Neither is positive semantic-comment evidence |
| Safe member paths | Hostile-path fixtures | Raw names and mapping are preserved independently; opt-in UTF-8/UTF-16 validators reject traversal, absolute, drive, UNC/device, and NUL paths; no automatic filesystem extraction exists |
| Unknown unpacked size/EOS | No compliant general model identified | Preserved as `None` and admitted by an explicit method allowlist: LZMA/LZMA2 require codec EOS, Deflate/Deflate64 require a final block, Copy/size-preserving filters derive the bounded input size, and BCJ2 ends at its bounded main stream. LZMA, LZMA2, Deflate, and Deflate64 have positive unknown-size units with truncation checks. PPMd, AES, BZip2, Brotli, LZ4, and Zstandard return typed `UnsupportedFeature` for unknown output; unknown packed size is also typed unsupported. Stock `7zz` 26.02 rejects the synthetic unknown-Copy-root candidate with `Data Error` and rejects unknown packed/non-final candidates with `Headers Error`; Rust's safe Copy extension is not credited as oracle parity |

## Stock 7zz capability-probe evidence

`crates/unpackio/tests/capability_probe.rs` emits structured, tab-separated
black-box outcomes for exact stock `7zz` 26.02. Its platform-neutral baseline
is asserted and its deterministic synthetic fixture hashes are recorded in
`CAPABILITY_PROBES.md`.

The reviewed runs do not identify a new confirmed decoder gap. The alternative
Copy-coder candidate is rejected as unsupported by both implementations;
unknown packed and non-final sizes are rejected by `7zz` and remain typed Rust
boundaries; and raw `AES256CBC` main-coder and Copy-chain authoring fail with
`E_NOTIMPL` on the observed macOS, Linux, and Windows hosts. A `-snl`
archive succeeds in both implementations. `-snh` produces an archive both can
verify and Rust returns the expected bytes for both entries, but stock
extraction on the observed macOS and Linux hosts does not recreate a hard-link
relationship. A checksum-pinned exact-26.02 Windows follow-up at
`24cf688` passed the ordinary-authoring control and Rust verification, and
confirmed ADS source creation by byte-for-byte readback. That oracle then
rejected raw AES, `-sni`, and `-sns` authoring with exit 2 and
`System ERROR: Not implemented`, so it produced no corresponding archive for
Rust to read. The official manual in the checksum-verified Linux 26.02 package
documents `-sni` and `-sns` storage as WIM-only, so those switches are not 7z
compatibility gaps. The separately pinned Linux run at `d1eabdf` confirmed
both Rust member byte streams but reported `same-file=false` after stock
extraction, so it adds no semantic hard-link claim. The expanded Windows job
in that run passed all four generated core/property tests and both Phase 5
tests.

Candidate acceptance, warning, or rejection is not itself a format-validity
claim. No capability row moves to supported without an accepted fixture,
semantic oracle evidence, corruption/limit coverage, and acceptable
provenance.

## Phase 2 structural evidence

- Unit tests cover plain and encoded identifiers, a regular archive with SFX
  scanning disabled, the exact SFX scan boundary, valid SFX after false
  candidates that fail checksums or candidate-local limits, every truncation
  of a minimal envelope, overflowed next-header offsets, unexpected
  identifiers, unsupported major versions, start/next CRC corruption, header
  and total-input limits, cancellation, and work-budget exhaustion.
- The opt-in source-audit harness passed the complete stored next-header
  parser and validated model for 32 logical archives: 31 single-file inputs
  (including `sfx.exe` and
  encrypted/encoded headers) plus the six joined `multi.7z.001`-`.006`
  volumes. At the Phase 2 boundary those cases proved only that stored stream
  descriptors validated; Phase 3/4 evidence below covers decoded headers.
- Generated tests cover two audited panic classes, exact 100,000-entry
  handling and rejection above it, every byte-prefix truncation, CRC-correct
  mutations, checked offset/count overflow, invalid and duplicate graph
  domains, cycles, deterministic topological schedules, file/substream
  cardinality, substream sizes/CRCs (including defined zero versus absence),
  external-property indices, overlapping
  packed ranges, bounded names/properties, unknown sizes, and malicious
  LZMA/LZMA2/PPMd/AES declarations.

## Phase 3 decoding evidence

- `crates/unpackio/tests/phase3_reference.rs` opens the real archives through the
  production parser/model/graph/session API. For `copy.7z`, `lzma.7z`,
  `lzma2.7z`, `delta.7z`, `bcj.7z`, `bcj2.7z`, `ppc.7z`, `arm.7z`,
  `arm64.7z`, `sparc.7z`, and `sfx.exe`, every streamed member matches `7zz`
  26.02 byte-for-byte and by RustCrypto SHA-256. Ordered member paths, sizes,
  and optional CRC values also match the oracle's `-slt` metadata. Declared
  size equals both outputs; `7zz` exits successfully after its integrity check,
  Rust `MemberReader::finish` verifies each declared member CRC, and a final
  natural-order archive verification succeeds.
- The test inputs are the exact external files identified by SHA-256 in
  `reference/7z-testdata.sha256`; they are not redistributed here. The command
  is `UNPACKIO_7Z_TESTDATA=<audited>/testdata cargo test -p unpackio --test
  phase3_reference -- --ignored`.
- Synthetic tests independently cover reverse-stored topological execution,
  unsupported method typing, a corrupted Copy member, packed/folder/member CRC
  scopes, corrupt Copy encoded-header CRC, cumulative nested encoded-header
  output limits, a stock-`7zz`-accepted two-substream encoded header, exact
  substream consumption, per-substream CRCs, every-prefix truncation, combined
  output preflight, solid two-member verification, charged linear traversal
  of 10,000 solid substreams, natural-order sink finalization before and after
  a corrupt member boundary, pre-decode per-entry limits across solid folders,
  unknown-final entry caps, typed rejection of unknown non-final sizes,
  total-output limits, work exhaustion, cancellation, LZMA/LZMA2 truncation,
  LZMA2 EOS and prefix truncation, BCJ2 range truncation, proportional x86 BCJ
  scan work, and filter tail handling.
- The positive method fixtures cover the exact method/property combinations in
  those files and the bounded generated property matrix described above. They
  still do not establish every possible property combination, encrypted chain,
  unknown-size stream, or architecture binary.

## Phase 4 decoding and archive-feature evidence

- `crates/unpackio/tests/phase4_reference.rs` verifies `deflate.7z`, `bzip2.7z`,
  `ppmd.7z`, `brotli.7z`, `lz4.7z`, and `zstd.7z`, plus encrypted
  `aes7z.7z`, `t2.7z`-`t5.7z`, and `7zcracker.7z`, through the production
  parser/model/graph/decoder API. Deflate, BZip2, PPMd, and the identified AES
  archives compare ordered names, sizes, optional CRCs, extracted bytes, and
  SHA-256 with `7zz` 26.02. The three private-method fixtures compare the same
  common corpus to the independently `7zz`-verified Deflate baseline because
  stock `7zz` rejects their private method IDs.
- An opt-in generated oracle creates an encrypted-header
  BCJ→LZMA2→AES archive from `sfx.exe` with `7zz`; production API metadata,
  extracted bytes/SHA-256, member CRC, and full verification match `7zz`.
- Missing-password, wrong encrypted-header password, and wrong encrypted-data
  password cases return their declared typed errors. Unit tests additionally
  bound KDF power before hash work, exercise direct and iterated KDF paths,
  reject non-block-aligned ciphertext, and checkpoint cancellation/work.
- The six real `multi.7z.001`-`.006` parts verify through the path provider.
  Memory-provider tests verify exact missing `.006` diagnostics, volume-count
  limits, aggregate input limits before copying, cancellation before provider
  callbacks, and deterministic five-part unencrypted `deflate.7z` and encrypted
  `aes7z.7z` splits.
- Production-API synthetic tests decode an external Name through
  AdditionalStreamsInfo and reject trailing bytes. Unit tests cover exact
  bounded external property application and applicable folder/substream CRCs.
  Separate fixtures stage main folder definitions in one of one or two decoded
  AdditionalStreamsInfo folder outputs, reuse another output for an external
  Name, and extract the member through the public API. Stock `7zz` 26.02 accepts
  both serialized forms. Regressions cover every archive prefix, exact external
  definition consumption, invalid output indices, packed/folder/substream CRC
  scopes, pre-decode main/additional packed-range overlap, combined coder/output
  limits, and encrypted missing/wrong/correct password paths.
  A separate accepted synthetic form contains an unreferenced
  AdditionalStreamsInfo Copy folder. `Archive::verify` covers that form both
  with and without main streams, exact packed/folder/substream checksum scopes,
  an AES folder's missing/wrong/correct password states, a cumulative
  additional-plus-main output limit, work exhaustion, cancellation, and plain
  and encrypted three-part memory volumes with packed bytes crossing a part
  boundary. Stock `7zz` 26.02 accepts the serialized form.
  A generated Unix `7zz -snl` archive matches symlink mode and stored target
  bytes. Path regressions cover traversal, absolute, drive, UNC/device, and NUL
  forms without changing archive entry mapping.

## Phase 5 decoding and corpus evidence

- `crates/unpackio/tests/phase5_reference.rs` asks `7zz` 26.02 to author temporary
  archives for Deflate64, IA64, ARM Thumb, RISC-V, Swap2, and Swap4. The
  source bytes deliberately trigger each transform; the Deflate64 vector
  includes a repeated region beyond the 32 KiB Deflate window. Every archive
  reaches the production parser/model/graph API and matches ordered metadata,
  exact output, RustCrypto SHA-256, size, and CRC with `7zz`.
- For each method, a byte in the middle of the declared packed region is
  corrupted and Rust verification must fail. Deflate64 unit tests also reject
  every prefix of a valid stored block, malformed LEN/NLEN, trailing packed
  input, output overruns, a 64 KiB dictionary-limit shortfall, and exhausted
  work. Filter tests cover short tails, exact properties, nonzero starts, and
  cancellation through their shared executor control.
- A generated two-member Deflate64 archive is checked in solid,
  encrypted-header/data form, and another in non-solid form. Separately
  generated unencrypted and encrypted Swap4 archives each consist of exactly
  five `7zz` volume files and verify through `PathVolumeProvider`; their bytes
  and metadata match the oracle.
- Unknown-output admission is centralized. Positive unit fixtures cover LZMA
  EOS, LZMA2 EOS, and Deflate/Deflate64 final blocks, including truncation and
  applicable trailing-input checks. Methods whose current adapter cannot
  establish the required end condition are rejected before packed-input
  decoding rather than guessing a size.
- Existing Phase 2-4 regressions remain the evidence for malformed headers and
  graphs, password errors, SFX, metadata, Unicode, symlinks, duplicates, path
  safety, and the audited fixture set. No separate valid or malformed corpus
  was available, so none is claimed as compatibility evidence.

## Phase 7 Python-binding evidence

- `bindings/python/tests/test_bindings.py` independently constructs a
  CRC-protected, one-member Copy archive and opens it through the installed
  `unpackio` wheel. It verifies archive-order metadata, exact raw UTF-16 name units,
  optional size/CRC values, path classification, writer and callback output,
  returned byte counts, multi-chunk output capped at 8 KiB per callback, and
  complete archive verification.
- A corrupted payload reaches the same core and raises structured
  `ChecksumError`; the native call never reports success. Format, total-input,
  work, cancellation, and exact missing-volume errors are also asserted with
  their machine-readable fields. Python provider/writer/callback exception
  identity, callback-triggered cancellation, and immutable same-archive
  callback reentrancy have direct regressions.
- Path opening and a two-part Python `VolumeProvider` exercise the three stable
  open forms. Every core limit is constructible from Python, password storage
  is accounted per archive, and an 8 MiB Copy verification confirms another
  Python thread advances while Rust-only work is detached.
- A generated three-entry solid Copy archive exercises the Python
  `extract_entries_to` adapter with two streamed members, an empty file, and
  duplicate names. Tests assert natural begin/write/finish boundaries, chunks
  no larger than the core's bound, exact bytes, one shared work budget, and a
  batch work cost below two random-access decodes. Separate regressions cover
  member-CRC failure before `finish_entry`, exact callback-exception identity,
  token and `False` cancellation, pre-begin output limits, and folder-level
  work exhaustion. Empty files receive explicit boundaries; streamless
  directories and anti-items remain metadata-only and do not produce batch
  sink events.
- Generated ZIP/ZipCrypto and RPM/CPIO packages exercise the documented native
  values from an installed wheel. The ZIP test covers every recorded
  metadata field, duplicate and empty entries, no/wrong/correct passwords,
  AE-2 AES-256 exact extraction, zero-length authentication, CRC corruption, and
  caller-owned seekable output. The RPM test covers reserved lead bytes,
  symbolic/scalar and unknown numeric tags, duplicate and empty members, exact
  output, and path construction. No member name is opened as an output path.
- On 2026-07-18 the locally built `cp39-abi3` macOS wheel installed into a
  clean CPython 3.12 virtual environment and all 10 binding tests passed. Its
  sdist independently rebuilt into a wheel, and that installed wheel passed the
  same suite. On 2026-07-20, PR #1 at `8c26a6e` passed the configured Python
  3.9 Linux/macOS/Windows wheel build/install/test jobs, binding quality gate,
  Rust 1.85 binding check, and sdist rebuild test. Those CI results establish
  the packaging/platform boundary, not additional codec evidence.
- On 2026-07-21 the Python data-contract change rebuilt a local macOS x86-64
  `cp39-abi3` wheel, installed it into a clean CPython 3.12 environment, and
  passed all 19 then-current installed-package tests, including the two
  format-specific migration tests above. The subsequent PyPI packaging audit
  rebuilt the sdist into an optimized 952,080-byte wheel, installed it in a
  new CPython 3.12 environment, and passed all 23 current binding tests. Wheel
  metadata had no `Requires-Dist` or entry point and included every required
  license/notice payload plus a generated CycloneDX SBOM.

The current workflow builds explicit manylinux 2.17, macOS, and Windows
`cp39-abi3` wheels for both x86-64 and ARM64. It installs each of those six
artifacts on its native architecture and runs the complete binding suite on
CPython 3.12, 3.13, and 3.14, for 18 smoke jobs. That expanded matrix is
configured but is not recorded as passing evidence until its first CI
execution succeeds; the release workflow cannot reach manual PyPI approval
unless every job passes.

The original Phase 7 7z binding fixture establishes FFI behavior for Copy only.
The later format-specific fixtures add Python evidence for standard-library
Deflate/BZip2/LZMA ZIP, stored ZipCrypto, and the generated uncompressed RPM
slice described above; they do not broaden any other method row. Other methods
retain their core evidence. The Python exception mapping is exhaustive over
the stable error kinds, but that alone is never treated as positive method
evidence.

## Evidence rule

Phase 6 adds no method row. `crates/unpackio/tests/phase6_api.rs` independently
constructs a CRC-protected Copy archive and exercises the default stable
surface through bytes, a temporary path, and two memory volumes. It compares
raw/display names, kind, optional size/CRC, explicit member streaming and
`finish`, `extract_entry_to`, missing indices, configured limits, archive and
folder retained-state accounting, per-session password storage, and corrupted
folder/member CRC failure. The 10,000-substream unit verifies natural-order
sink traversal with an exact linear work budget. These tests stabilize API
behavior; they do not broaden any codec claim above.

A Rust row becomes “supported” only after:

1. a named valid fixture reaches the API through the real parser/model/graph;
2. output bytes and SHA-256, size, CRC, and applicable metadata match an
   independent oracle;
3. corrupt/truncated/property-limit cases return the intended typed error;
4. solid/non-solid and relevant encrypted chains are tested; and
5. the decoder origin and exact dependency license are recorded.

`7zz` 26.02 could list/test standard bundled methods during the Phase 1 audit.
That local binary did not decode the bundled private method IDs for Brotli,
LZ4, or Zstd, so it cannot be the sole oracle for those fixtures without a
separately reviewed test plugin. This is an oracle limitation, not a Rust
compatibility result.
