# Corpus record

## Inputs actually available

The initial corpus placeholders contained no paths, and no separate 7z corpus
was available. The project therefore makes no claim based on those
placeholders.

On 2026-07-18 the repository owner confirmed that no separate valid or
malformed corpus is available. That absence is now an explicit test-design
constraint rather than a pending path request: ordinary development uses
deterministic in-tree constructors, on-demand `7zz` oracle generation,
CRC-correct semantic mutation, exhaustive truncation tests, and
coverage-guided fuzzing. No compatibility row is credited merely because a
fuzz target accepts arbitrary bytes.

An audited external 7z testdata set supplied the initial reference material:

- 38 top-level `testdata` files: 31 `.7z` files, six parts of
  `multi.7z.001` through `.006`, and one SFX executable;
- four fuzz artifacts under `testdata/fuzz/FuzzNewReaderWithPassword`;
- total files in the manifest: 42; and
- exact SHA-256 values in `reference/7z-testdata.sha256`.

These files were inspected in the temporary pinned checkout and were **not
copied** into this repository. A hash manifest establishes identity, not a
right to redistribute each binary fixture.

The source audit's own test suite passed on its recorded toolchain; this is
source-audit context, not unpackio evidence.

## ZIP and RPM evidence

No external ZIP or RPM corpus is committed. Unit, binding, and fuzz tests build
complete containers in process from project-authored names and payloads. The
serializers are test code, not runtime writer APIs. Every generated case is
extracted by index, so duplicates and unsafe names never become filesystem
destinations.

The original ZIP codec regression embeds four compressed byte strings. Python 3.12
standard-library `zipfile` generated the BZip2 and ZIP-LZMA streams from 576
bytes of repeated project text; Zstandard CLI 1.5.7 generated the Zstandard
frame; the Deflate64 value is a hand-assembled specification-defined stored
block for `abc`. Their exact identities are:

| ZIP method vector | Bytes | SHA-256 |
| --- | ---: | --- |
| BZip2 | 72 | `a264ecf45941bffee0cc5fef1631fe4c1b403519e3b5a358802e55dd69d4ae49` |
| ZIP-LZMA | 43 | `d3c547ae8c509cc284c1109c61eb2e2ef8aa397671990c5512ff829660d36239` |
| Zstandard | 38 | `767e1f10cafbeceee00b2aede9b738388ce144bcefa27380e1ca6eaa2c3282f1` |
| Deflate64 stored block | 8 | `a8bbdab8949681033eb6a11e4eeb3ee8095d3564f60b5b94adf12e55721effce` |

The common decoded ZIP text is 576 bytes with SHA-256
`62b5f624cbcacc0a55bff9e510af576ceb44a42a61a7e5c7b81ce40e91161eff`;
the Deflate64 result is exactly `abc`. Store/Deflate, ZIP64/SFX, descriptors,
CP437/Unicode names, duplicate/empty entries, ZipCrypto, and WinZip AES
fixtures are deterministic in-process project serializers. AES passwords,
salts, and payloads are public test data. Corruption and truncation are derived
in memory and never retained as redistributable files.

The method-95 regression adds deterministic XZ streams created on 2026-09-14
from that same 576-byte project text by XZ Utils 5.8.3/liblzma 5.8.3 and Perl
5.34.1. The baseline command was
`perl -e 'print "zip codec payload\n" x 32' | xz --format=xz --check=none
--stdout --lzma2=dict=64KiB`; the local default threaded encoder emitted the
optional Block Compressed Size and Uncompressed Size fields. Matrix vectors
added `--threads=1` and, between `--stdout` and `--lzma2=dict=64KiB`, the Check
and optional prefilter shown below. The nine-Block vector used
`--check=none --block-size=64`. Only compressed bytes are embedded; XZ Utils is
a test-only generator/oracle and is not invoked by the package.
The empty-Stream vector used
`printf '' | xz --format=xz --threads=1 --check=none
--lzma2=dict=64KiB --stdout` and contains zero Blocks.

| ZIP XZ method-95 vector | Bytes | SHA-256 |
| --- | ---: | --- |
| Empty Stream/NONE | 32 | `42552ae5ec08bdd8101b2057524a81cd8355474226603ac9829be426170ae731` |
| LZMA2/NONE with optional Block sizes | 88 | `35b398330dbc0c27e62a67ded1cfa6e4ce84dd5c8af04c7489ec5ad8d9d8eb34` |
| LZMA2/NONE without optional Block sizes | 84 | `748e6669738148cf00a4f0a7b78e2b412551e0ea60ab38109179c4e18eb369d3` |
| Delta/CRC32 | 92 | `93bc42516a1aaaf756a5ec058407fe6a7b6a8449a7816e6716d2066141a61c5d` |
| x86/CRC64 | 92 | `c20ff15d6f301b422b4e8ca9dff960a3cd30d8291e669cdd0d18b412b8473e4c` |
| PowerPC/SHA-256 | 116 | `2e36a2542304ae224568dd90763e942043cceb3effb789f2b3b7fe3f95e71759` |
| IA64/NONE | 84 | `614c6d077dabe923e87a2a31bb8e610ef2e7045dd1c36a162705f4662ac444ac` |
| ARM/NONE | 84 | `e989013d93ae1f18fdd89a1c9ef34c4adc1140e29bb3231183bcb22a30581998` |
| ARM Thumb/NONE | 84 | `81e3b07bad4ae36cd40d1940e87644fd82b3ba733a5091851edc984445a4344d` |
| SPARC/NONE | 84 | `87c241ee248e1d426cae8f7ffa654c313f098230738d17196c01ffa14245d894` |
| Nine Blocks/NONE | 480 | `464e2fec4209442e751cc0c8259c82df5e8267bb12baa803c24452fe3c12dffc` |

The fuzz target and Python binding test embed a smaller 52-byte LZMA2/NONE
stream for project-authored `abc`, generated with
`printf abc | xz --format=xz --threads=1 --check=none
--lzma2=dict=64KiB --stdout`. Its SHA-256 is
`4f1fee78a8bbb91dfc06cd8752d2be2647ae196972c83a5ebc2d0a7ada33f59f`;
its seven-byte Compressed Data requires one zero Block Padding byte, which is
also the basis of the CRC-correct padding-corruption regressions. All ZIP
wrappers, Index/property/header mutations, truncations, declared-size changes,
and encryption envelopes are project-authored in-memory test derivations under
the repository's MIT test-fixture terms.

The method-98 fixed vector was created on 2026-09-14 by the locally installed
black-box `7-Zip (z) 26.02 (x64)` with:

```text
printf abc | 7zz a -y -tzip '-m0=PPMd:o=2:mem=1m' method98.zip -siabc.bin
7zz t method98.zip
```

The resulting method-98 payload is the exact nine bytes
`01 00 61 03 6e 81 2d 4c 00`: two properties bytes for order 2, 1 MiB, Restart,
followed by the PPMd-I revision-1 range stream and end marker. Its SHA-256 is
`b619a182e5da04391b9daf32fb2452abd2d0838e9a5663237bff35dc831fcf86`.
The decoded bytes are project-authored `abc`, CRC-32 `352441C2`, SHA-256
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
The oracle emitted version-needed 6.3; the generated regression also exercises
the specification's minimum 2.0. The executable and full timestamp-bearing
oracle archive are not retained. A deterministic one-entry project serializer
around those bytes is 123 bytes with SHA-256
`2539bd7777b9d5fb4d91805001f4e652b11d1b3505889421a6f460941a409bf8`.
Only source literals and in-process serialization are committed.

Normal Rust tests also contain a `cfg(test)`-only PPMd-I encoder derived under
the exact provenance in `PROVENANCE.md`. It creates all legal order endpoints,
model sizes, and Restart/Cutoff/Freeze cases without exposing a writer in a
normal build. The fixed `abc` assertion ties it byte-for-byte to the independent
stock-`7zz` vector. A release-only pressure test forces all three memory
restoration algorithms in a 1 MiB model. Every strict packed prefix and the
property/range/trailing/size/CRC/version/limit/cancellation mutations are
derived in memory and are not retained as archive files.

### Local-only WinZip ZIPX interoperability set

No proprietary-tool sample is committed. On 2026-09-14 a sparse local clone of
SharpCompress at commit
`e04d51176c5d87668c4c8779825342230c33aa74` supplied four archives whose
upstream filenames and tests identify WinZip 26 or 27. Their source commits do
not record a WinZip command-line or GUI recipe, so the producer command cannot
be reproduced from the available provenance and is not invented here. The
archives also contain pre-existing executable/JPEG/text sample content whose
redistribution provenance is not complete; the deliberate decision is
local-test-only, never commit or package.

| Local sample | Upstream introduction | Archive SHA-256 | Entries | Method / version needed | Encryption |
| --- | --- | --- | ---: | --- | --- |
| `WinZip26_BZip2.zipx` | `224614312fa7992e98f4cab9136c2723892ca103` | `9348eec1f46601bd0d238a15373d60e8f0815f81da76d23c6671e7f54f3c98fe` | 5 | BZip2 (12) / 4.6 | none |
| `WinZip26_LZMA.zipx` | `224614312fa7992e98f4cab9136c2723892ca103` | `1ecd6aaf943f80f5fbd12225f24877f52676527ce8353946b94c5a579cd6fcf2` | 5 | ZIP-LZMA (14) / 6.3 | none |
| `WinZip27_XZ.zipx` | `b9d019561f8be6c7195bfeab482824284617f351` | `4a88881c8e5aa3c45d67991969023af3572c910602248061ce3b049080c6c069` | 3 | XZ (95) / 2.0 | none |
| `WinZip27_ZSTD.zipx` | `92df1ecd5f7579a88a1c5a7d30744a091de95b2a` | `d2bd5d90448b15a9c7450edbc7e5afae66d75482f5a48c74918c74898d8d75ea` | 3 | Zstandard (93) / 2.0 | none |

Every archive has the same three regular-file outputs (the two WinZip 26
archives additionally retain two directory entries):

| Output bytes | CRC-32 | SHA-256 |
| ---: | --- | --- |
| 45,056 | `CFB109C8` | `8557928804f57ecc340b3bb38b095a3607474ec8deb0076f316fcfe02b562106` |
| 40,372 | `088814E3` | `b251c7501fb0f55dd4a92feabe0a6f5733bc40a02679498155fae9b30138fc53` |
| 15,498 | `9BD160FA` | `4d581d93d369f6e1c9b295ff38d82dabd577f927dfaf0c35818c015c85e322d9` |

The same pinned corpus includes `Zip.ppmd.zip`, SHA-256
`957ad400590021536ba46ad494eaf60f2daa134c188c14b63175f9bfba9a4f5a`,
with six entries and the same three regular outputs encoded as PPMd method 98,
version-needed 6.3, without encryption. Its history reaches the SharpCompress
initial commit, but no producer/tool version or command is recorded and its
name does not attest WinZip. It is therefore an independent local method-98
sample, not evidence that the outstanding WinZip-PPMd provenance requirement
has been met.

The local corpus can be reacquired and checked with:

```text
git clone --filter=blob:none --no-checkout \
  https://github.com/adamhathcock/sharpcompress.git <local-sharpcompress>
git -C <local-sharpcompress> sparse-checkout init --cone
git -C <local-sharpcompress> sparse-checkout set tests/TestArchives/Archives
git -C <local-sharpcompress> checkout \
  e04d51176c5d87668c4c8779825342230c33aa74
UNPACKIO_WINZIP_TESTDATA=<local-sharpcompress>/tests/TestArchives/Archives \
  cargo test -p unpackio --test winzip_reference --locked -- --ignored --nocapture
```

The opt-in test checks every archive hash before parsing, then checks entry
count, method, version, no-encryption state, decoded size, CRC, output SHA-256,
and full archive verification. The samples remain outside the repository and
are never used by runtime code.

The RPM compressor regression wraps one deterministic generated CPIO payload
containing project-authored `first`, `second`, and empty members. Local `bzip2`
1.0.8, XZ Utils 5.8.1 (XZ and legacy LZMA-alone), and Zstandard 1.5.7 created
the following embedded payload byte strings:

| RPM payload vector | Bytes | SHA-256 |
| --- | ---: | --- |
| BZip2 | 162 | `6d05c1ee497435fb22d3c31e1448dd4c06fb68f891c3f0fd03b03520fba9a623` |
| XZ | 184 | `b7d8ecba56c0d38ef0807f7b48c1f6fc0fc003b31fee976faa44b0e8e848b4e9` |
| legacy LZMA | 131 | `6459a54004010c4eb69484c13b1affa8aedb2ce49d6c53a7d19433c8cd48f829` |
| Zstandard | 137 | `5ccf154e0a5121b6477fa89c7b0a0b893ca245b4f3beab2b7e904b08e9eb5194` |

RPM lead/header/digest/CPIO wrappers are generated in process and are original
test data licensed MIT. The compressor outputs contain only that
project-authored data and are retained under the same test-fixture terms. No
vendor RPM, package signature, third-party filename, or installed payload is
included.

On 2026-07-21, disposable direct-compatibility checks used the exact comparison
sdists recorded in `PROVENANCE.md`; no archive or third-party source was copied
into the repository. `pyzipper` 0.4.0 authored 24 temporary AES ZIPs spanning
Store, Deflate, BZip2, and ZIP-LZMA; AE-1 and AE-2; and 128-, 192-, and 256-bit
keys. Each contained a nonempty and empty duplicate-name entry. The installed
`unpackio` wheel listed both in order, extracted exact bytes, and verified every
archive. A separate original serializer produced one gzip/newc RPM containing
nonempty and empty members; `rpmfile` 2.2.1 and `unpackio` agreed exactly on
member names, output bytes, and permission modes, and `unpackio` verification
completed. All temporary inputs were deleted with their temporary directories.

## CPIO, Debian package, and ARJ evidence

Standalone CPIO tests generate every input in process. Positive cases cover
SVR4 new ASCII, CRC-new ASCII, old portable ASCII, and historical binary
little- and big-endian records, including empty entries, directories,
symlinks, mixed concatenated layouts, metadata, alignment, and exact output.
Derived cases exercise every truncation, bad trailer/name/range/alignment,
CRC failure, count/name/output/input/work/cancellation limit, and unsafe path
classification. These serializers are test-only original code and provide no
runtime writer API. RPM integration reuses this same parser and has a positive
CRC-newc wrapper fixture.

Debian tests build the ar envelope and uncompressed tar cases in process. The
five committed base64 vectors encode one deterministic 2,048-byte tar payload,
SHA-256
`9a08b2756245334024aa829157b77327db1bee5205a931c7b9d799a53b72bd26`,
containing only repository-authored fixture data. They were generated locally
on 2026-07-21 with bsdtar 3.5.3/libarchive 3.7.4 and the listed command-line
compressors:

| Debian tar vector | Bytes | SHA-256 |
| --- | ---: | --- |
| gzip (Apple gzip 479) | 157 | `2c6c3561816e07a6cb731ae68daf1001195ecc2909f70f153b6496c0a6f4e4e5` |
| BZip2 1.0.8 | 167 | `2f38ea8ba11be3b41de7aaffd82b8abc513b733aaa8d9e48ac6e672bf362b9e6` |
| XZ 5.8.3 | 208 | `f09d64a38dd315069ca79f392e7894c043f08a69ec052ba7a3911fbaffde5c32` |
| legacy LZMA-alone (XZ 5.8.3) | 154 | `80d49fee6a7deb7a621e9daac8ccdeb34dfbb6b5dd5e6866b17cde98d355212b` |
| Zstandard 1.5.7 | 148 | `2d97a6f858865abce11936f3c625266f32caa80daabe28e9f1eb762d06fb0a5d` |

The Debian suite also positively exercises V7/ustar metadata, GNU long
names/links, PAX overrides, control/data member ordering, and each admitted
compression suffix. Corruption, malformed PAX/GNU records, ar/tar truncation,
checksum failure, unsupported compression, counts, names, dictionary, output,
work, and cancellation are derived in tests.

The four committed ARJ archives are base64 encodings of the method fixtures in
`unarj-rs` 0.2.1 at commit
`dbd80638eb4a200618c08de7b9e58b4d66a0d377`. The package metadata declares
MIT but its bundled LICENSE is Apache-2.0, so the fixtures are conservatively
retained under Apache-2.0 and credited in `NOTICE`. Each decodes a single
`LICENSE` member of 11,357 bytes with SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`:

| ARJ method fixture | Archive bytes | Archive SHA-256 |
| --- | ---: | --- |
| method 1 | 4,085 | `a610180da1a37246e4471ce310f66e76cbf718ef44bee00bc341d459f7313d4d` |
| method 2 | 4,088 | `f5585d01f2534892aa488aebaed597e89db2778c57a61d7d6005570db249a6ee` |
| method 3 | 4,185 | `7186a2d7a0121a3b04c4f9a0bbfd9b2387edf5e3913ea1d67e6dae8eff5d6bb6` |
| method 4 | 4,553 | `3a1e1ebcf4cdc3dd01761dca3365a93feccf39f0039df13f996587b066b9da8a` |

All four extract exactly through the public API. Their packed-data corruption,
dictionary/output/work/cancellation failures are derived in memory. Generated
stored, no-data, SFX, encrypted-flag, unknown-method, header-CRC, member-CRC,
truncation, count/name/input/SFX-limit, and extended-header cases complement
those real-encoder fixtures. Local `7zz` 26.02 independently listed and
extracted the method-1 fixture to the same size and CRC; methods 2--4 are not
claimed as `7zz` differential evidence.

## Standalone compressed-stream evidence

No standalone external corpus is committed. Normal tests generate LZ4 and
Zstandard raw frames in process and embed one 26-byte Unix `.Z` fixture over
the project-authored bytes `hello unix compress\n`. macOS 26.5.1
`/usr/bin/compress` produced that fixture; the executable SHA-256 was
`bf8cb1cefedfbf86fbb38dd42278fcad8fe020f3b8989897f1a0b2187aabdda5`,
the compressed SHA-256 is
`b4bce679446fedb329fcb3cf671b7e1a99e838e834097f260ba65d2a1615ea1e`,
and the decoded SHA-256 is
`d4d893bf9ca2a6efb601cc7fcfb2d749ab74100af5894de8834043589c7acea4`.
The fixture is data from a black-box native tool, not imported source or an
implementation dependency.

On 2026-07-21 a disposable differential directory used this deterministic
1,000,000-byte input:

```text
awk 'BEGIN { for (i = 1; i <= 20000; i++) printf "line-%06d-abcdefghijklmnopqrstuvwxyz-0123456789\n", i }' > expected.txt
lz4 -f expected.txt expected.lz4
zstd -f --check expected.txt -o expected.zst
compress -c expected.txt > fixture.Z
```

The input SHA-256 was
`109c1ed93ca7acd9241d3df1ebc62eae5b027b2bc06073cd3fecbf5653a7c282`.
LZ4 CLI 1.10.0 (binary SHA-256
`f0f8e5dece2d110ffb6b474cb0a43fb781d718dc71edfd7bfe61f216668fb3d0`)
produced 103,195 bytes with SHA-256
`747ca19820fb6efee6efc8e988c2e4b2dd9d62a8e89bc375a3eb59e301a7a2e6`.
Zstandard CLI 1.5.7 (binary SHA-256
`f63aacd3210aaacaa9fb59c69a367ca9124aa179ddcbb1da241fdc96d8196268`)
produced 12,489 bytes with SHA-256
`9c47672b83388770a9cbb16dc0dce685073bc49b6b16ffdb4b5a122346ecf47d`.
`compress` produced 63,527 bytes with SHA-256
`f0225910762f6fdfd59a2530cebb294c53b2d0f31fdf067fa21f5d8329015773`.
All three decoded through the public API to exact input bytes.

A second disposable `/dev/urandom` input exercised Unix `.Z` dictionary
saturation and CLEAR behavior: 2,097,152 input bytes, SHA-256
`a2355c737628013dcce033445f2505fa0bd75a57b44635deec3217ba7e578951`,
became 2,823,532 compressed bytes, SHA-256
`6c41c989112977a6bad4f0fe76d54543c852963a0fa265cea7fc78a5054a8b9e`,
and decoded exactly. That nondeterministic input and every native-tool output
remain uncommitted disposable evidence. Deterministic generated tests cover
width transitions, block/non-block state, and CLEAR resets in CI.

## Current Rust structural evidence

The ignored integration harness in
`crates/unpackio/tests/reference_headers.rs` reads fixtures only from an explicit
`UNPACKIO_7Z_TESTDATA` directory, so no external binary is copied or implicitly
downloaded. On 2026-07-18 it passed the production stored-next-header parser
and validated model for 32 logical audited archives: 31 named single-file
fixtures and the six `multi.7z.001` through `.006` parts joined as one logical
byte sequence. The set includes the SFX executable and plain, encoded, and
encrypted header families.

This is evidence for stored syntax/model validation, not for decoding an
encoded header, password handling, volume-provider behavior, decoded metadata,
or any decoder. The same opt-in run confirms that external
`COMPRESS-492.7z` is rejected. Generated Rust regressions independently cover
that missing-UnpackInfo condition and both audited panic classes; the source
binary itself remains external and is not committed.

The exact local command was:

```text
UNPACKIO_7Z_TESTDATA=<AUDITED_7Z_TESTDATA>/testdata \
  cargo test -p unpackio --test reference_headers -- --ignored
```

## Current Rust decoding evidence

On 2026-07-18 the opt-in Phase 3 harness opened the exact external `copy.7z`,
`lzma.7z`, `lzma2.7z`, `delta.7z`, `bcj.7z`, `bcj2.7z`, `ppc.7z`, `arm.7z`,
`arm64.7z`, `sparc.7z`, and `sfx.exe` files identified by this repository's
hash manifest. Every streamed member was decoded through the production
archive/model/graph API, finalized with its Rust CRC, and compared against
`7zz` 26.02 output for exact bytes, declared size, and RustCrypto SHA-256.
Ordered path, size, and optional CRC metadata also matched `7zz l -slt`. The
external oracle exited successfully, including its own integrity check, and a
final Rust natural-order archive verification succeeded.

The exact command was:

```text
UNPACKIO_7Z_TESTDATA=<AUDITED_7Z_TESTDATA>/testdata \
  cargo test -p unpackio --test phase3_reference -- --ignored
```

The same ten method archives were copied to a temporary directory for a
10,000-execution stable-built `decoding` fuzz-harness smoke test and then
deleted. The pinned corpus itself was not changed. That Phase 3 run made no
claim for encrypted fixtures, multi-volume provider behavior, or unsupported
methods. The separate `<CORPUS>`/`<MALFORMED_CORPUS>` sets are confirmed
unavailable and are not used as evidence.

## Corpus-free generated differential evidence

`crates/unpackio/tests/generated_oracle.rs` removes the external-corpus dependency
for every method that stock `7zz` 26.02 can author in the initial core and
filter set. The ignored suite creates deterministic synthetic input
and temporary archives for Copy, LZMA, LZMA2, Delta, BCJ, BCJ2, PPC, ARM,
ARM64, SPARC, Deflate, BZip2, and PPMd. Filter fixtures contain matching branch
or delta patterns, and the test confirms that their packed representation was
actually transformed. For every archive it compares ordered raw name, size,
optional CRC, exact output bytes, and SHA-256 with `7zz`, verifies with Rust,
then mutates a packed byte and requires Rust verification to fail.

The same suite independently creates header-encrypted and data-encrypted Copy
archives. It checks the exact `PasswordRequired` and
`WrongPasswordOrCorrupt` states, compares correct-password output with the
oracle, and rejects corruption. A synthetic test-only `MZ` prefix is prepended
to a generated Copy archive to exercise bounded SFX discovery in both Rust and
`7zz`; no 7-Zip SFX source or stub is copied. All source files and archives are
deleted with their unique temporary directory.

The exact-version property-matrix test adds 24 positive archives for bounded
LZMA/LZMA2 dictionaries, LZMA probability properties, PPMd order/model memory,
Delta distances, BZip2 block sizes, Deflate levels, filter/compressor chains,
encrypted data and headers, and solid/non-solid four-entry layouts. It asserts
the decoder-visible coder property bytes or packed stream markers so an
accepted but normalized authoring switch cannot silently count as coverage.
Each archive is then subjected to packed corruption, fixed/next/final physical
truncation, output/work/cancellation limits, and applicable dictionary limits.
For plain headers, CRC-correct mutations shorten the declared first packed
stream and make a stored coder-property length oversized or empty; BZip2 also
gets an invalid block-size byte. The matrix retains no binary output and adds
no imported algorithm.

The complete generated suite was last run on 2026-07-19 with:

```text
cargo test -p unpackio --test generated_oracle --all-features --locked -- --ignored
```

All four tests passed with local `7zz` 26.02 on 2026-07-19. These cases are
reproducible test generation, not a committed binary corpus and not a runtime
dependency.

## In-process decoder fuzz seeds

The excluded fuzz package now constructs 21 complete small archives on every
run rather than retaining binary seed files. Profiles cover Copy, LZMA,
three LZMA2 dictionary properties, Deflate, Deflate64, BZip2, canonical and
zero-reserved seven-byte PPMd properties over the same packed stream, Brotli,
LZ4, Zstandard, AES, reverse-declaration Copy, BCJ2, two filter/compressor
chains, and three Delta distances. Input-derived plaintext is capped at 64
bytes. The standalone `fuzz/tests/generated_seeds.rs` test verifies every
profile and passes each of eight structured mutations through bounded public
operations.

Four embedded positive packed streams have fixed origin records:

| Stream | Origin | Packed SHA-256 | Decoded SHA-256 |
| --- | --- | --- | --- |
| raw LZMA `abc` | XZ Utils 5.8.3 command recorded below | `ccc82e613efa67d15c8121ef469a49b37dcb67f40f1334c16479bc60d8b13482` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| BZip2 `hello\n` | `/usr/bin/bzip2` 1.0.8 over synthetic input | `8f2cf133c7cb64e1407f2dc51fe6a966755130de4c257b04e26d1a9a9c92354b` | `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03` |
| Brotli `hello\n` | `brotli-decompressor` 5.0.3 `src/reader.rs` regression, BSD-3-Clause OR MIT | `f79a3ca17dcda113ab64c08a1c3bf146bce590ab016cb0b3bcc1409946015efe` | `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03` |
| PPMd order 6, 64 KiB model | Stock `7zz` 26.02 black-box command recorded below over project-authored text | `b0cfcc58d1e9615d16a77f477bef20d7759e9307f6605a19ed925d6729733854` | `350151a2946bf4981f4980e49cc308bfb129f1fe4a9e1f8471d46545090a88c9` |

The Brotli completion regression derives a nine-byte hostile prefix by
removing the final byte from the complete recorded vector. Its SHA-256 is
`80665dbf193bc0e2fe0b50eef9b973a40391d700e102fe72b02cceb11f1fcf4a`;
the expected result is `Format`, not decoded output. This derived negative is
not a py7zr fixture and makes no claim about copied py7zr bytes.

The PPMd source is the 50-byte project-authored UTF-8 string
`PPMd fuzz seed: alpha beta gamma delta 0123456789\n`. On 2026-07-19,
`7-Zip (z) 26.02 (x64)` authored the ephemeral archive with:

```text
7zz a -t7z -m0=PPMd:o6:mem64k -mhc=off -mhe=off -bd -bb0 \
  ppmd-o6-mem64k.7z seed.txt
```

`7zz t` succeeded. The serialized coder properties are
`06 00 00 01 00` (order 6 and little-endian 65,536-byte model memory), the
packed stream is 49 bytes, the decoded CRC-32 is `56B5ABF1`, and the ephemeral
complete archive SHA-256 was
`30d582cae58f45f206f4cad4fdbd5e112a7249e75c9781dc218ef8c5eac938b2`.
Only the packed test vector is embedded; the complete archive is not retained
in the repository. The executable was used only as a black-box test oracle,
and no 7-Zip or p7zip implementation source was inspected or incorporated.

The generated compatibility test also serializes
`06 00 00 01 00 00 00`, as externally documented for py7zr 1.1.3, around the
same packed bytes. This seven-byte archive is project-generated and not
oracle-authored or committed. The exact decoded bytes, dictionary/output/work/
cancellation bounds, nonzero reserved-byte rejection, wrong-length rejection,
and declared-property truncation are asserted in normal tests.

The remaining packed records are generated deterministically from each bounded
input using minimal stored/uncompressed frame grammar or RustCrypto AES-CBC.
The password is a fixed public fuzz string. No generated archive is committed,
so there is no static archive hash or redistribution artifact. These seeds are
deep no-panic/decoder evidence; they do not add a compatibility claim without
the separate oracle fixtures and corruption tests.

## Corpus-free capability probes

`crates/unpackio/tests/capability_probe.rs` constructs six deterministic,
CRC-correct Copy candidates for comments, an alternative coder declaration,
and unknown-size boundaries. It also asks exact stock `7zz` 26.02 to author
temporary raw-AES main/filter, hard-link, symlink, and platform metadata cases.
The test emits structured author/oracle/Rust outcomes and SHA-256 values, then
deletes its unique temporary directory. No resulting archive is committed or
treated as redistributable corpus material.

The observed candidate hashes, warnings, errors, and platform limitations are
recorded in `CAPABILITY_PROBES.md`. Synthetic rejection cannot prove that no
valid form exists, and acceptance without visible semantics cannot establish a
compatibility claim. The exact-version Windows follow-up at `24cf688` passed
an ordinary-authoring control and confirmed ADS source bytes by readback, then
observed `System ERROR: Not implemented` while raw AES, `-sni`, and `-sns`
were being authored. No corresponding archive existed for Rust to read, so the
run contributed no raw-AES, NT-security, or ADS corpus evidence. None of the
temporary control or host-authored outputs is retained as corpus material.
The checksum-pinned Linux job runs the same ephemeral constructors so
same-inode hard-link behavior can be observed on a capable host. Its first
reviewed run at `d1eabdf` verified both Rust member byte streams but stock
extraction reported `same-file=false`; no semantic hard-link corpus claim was
created. The same run's Windows job passed all four generated core/property
tests and both generated Phase 5 tests. The official 26.02 manual files used
to classify `-sni` and `-sns` as WIM-only are read from the verified release
archive and are neither copied nor made corpus inputs.

## Phase 4 external evidence

On 2026-07-18 the opt-in Phase 4 harness verified the exact external
`deflate.7z`, `bzip2.7z`, `ppmd.7z`, `brotli.7z`, `lz4.7z`, and `zstd.7z`
files plus password-protected `aes7z.7z`, `t2.7z`-`t5.7z`, and
`7zcracker.7z`. Deflate, BZip2, PPMd, `aes7z.7z`, `t2.7z`, and `t4.7z`
matched `7zz` 26.02 for ordered metadata, exact bytes, CRC, size, and SHA-256.
The private Brotli/LZ4/Zstd method IDs cannot be decoded by that stock oracle;
their fixtures instead matched the same independently oracle-verified Deflate
corpus bytes and metadata.

The real `multi.7z.001`-`.006` set verified through the path provider. The
harness also split the already identified Deflate and encrypted AES fixtures
deterministically into exactly five in-memory parts, without modifying or
committing either source fixture. An opt-in test used `7zz` to create a
temporary encrypted-header BCJ→LZMA2→AES archive from the pinned `sfx.exe`,
compared it to the oracle, and removed it. A separate generated Unix symlink
archive was likewise temporary. These generated cases are test-oracle outputs,
not redistributed corpus additions.

The command is:

```text
UNPACKIO_7Z_TESTDATA=<AUDITED_7Z_TESTDATA>/testdata \
  cargo test -p unpackio --test phase4_reference -- --ignored
```

## Phase 5 generated differential evidence

No Phase 5 binary fixture is committed. The ignored harness in
`crates/unpackio/tests/phase5_reference.rs` creates deterministic synthetic source
bytes and asks the selected exact `7zz` 26.02 executable to author archives
inside a unique temporary directory. The executable can be selected with the
test-only `UNPACKIO_7ZZ` override, including the checksum-pinned Windows CI
installation. The harness compares production Rust output,
SHA-256, size, CRC, ordered names, and metadata with the oracle and then
deletes the directory.

The generated positive matrix contains transforming inputs for Deflate64,
IA64, ARM Thumb, RISC-V, Swap2, and Swap4. The Deflate64 input contains a
65,536-byte deterministic prefix followed by distant repeated data and
long-match text. The architecture inputs contain synthetic IA64 bundles, ARM
Thumb branches, and RISC-V JAL/AUIPC pairs; packed bytes are checked to ensure
the oracle actually transformed each source. Each archive also receives a
separate mid-packed-region corruption that must fail Rust verification.

The composed matrix contains a two-member solid encrypted-header/data
Deflate64 archive, a two-member non-solid Deflate64 archive, and separately
authored unencrypted and encrypted Swap4 archives split by `7zz` into exactly
five `.001` through `.005` files. Both volume sets are read through the path
provider and compared with the oracle. These temporary oracle artifacts are
test outputs, not redistributable corpus additions. The separate user corpus
sets were confirmed unavailable.

The exact command run on 2026-07-18 was:

```text
cargo test -p unpackio --test phase5_reference -- --ignored
```

Both Phase 5 ignored tests passed with `7zz` 26.02. Existing Phase 2-4 tests
remain the corpus evidence for malformed grammar/graphs, SFX, metadata,
Unicode, symlinks, duplicate names, wrong passwords, and the audited fixtures.
A separate in-tree unit vector forces a dynamic Huffman block through
the Deflate64 decoder; the generated oracle fixture supplies the
Deflate64-specific long-distance and long-match evidence.

The checksum-pinned Windows oracle job now invokes both Phase 5 tests and all
four ignored `generated_oracle` tests. Every source and archive remains
ephemeral; CI does not create a retained or redistributable corpus.

## Encoded-header compatibility closure

On 2026-07-18 an ignored unit oracle generated three temporary Copy-encoded
headers entirely from documented 7z records and deleted each file after asking
stock `7zz` 26.02 to test it. The baseline has one folder and one substream.
The compatibility case partitions a valid decoded FilesInfo header across two
CRC-protected substreams and preserves one named empty file; both Rust and
`7zz` accept it. Rust regressions additionally corrupt each CRC, reject every
truncated prefix, and preflight the combined decoded size.

A two-folder form built from the same decoded bytes is accepted by the Rust
implementation's ordered, bounded reconstruction but rejected by stock `7zz`
26.02 with `Headers Error`. That result is retained as negative oracle evidence
and is not presented as stock-7zz compatibility. The command is:

```text
cargo test -p unpackio --lib stock_7zz_ -- --ignored
```

The 13-byte raw LZMA EOS unit in `decode/lzma.rs` is generated from the
synthetic bytes `abc` by XZ Utils 5.8.3 with
`xz --format=raw --stdout --lzma1=dict=4096,lc=3,lp=0,pb=2`. It is retained as
a deterministic positive unknown-size vector; every strict prefix and a byte
appended after EOS are negative termination cases. A validated-model
`Archive::extract_entry`
regression additionally requires that EOS and the member/folder/packed CRCs
all succeed before extraction is reported as successful. The vector contains
no third-party corpus content.

## Reference coverage observed

The Go tests identify fixtures for Copy, Delta, LZMA, LZMA2, BCJ, BCJ2, PPC,
ARM, ARM64, SPARC, Deflate, BZip2, PPMd, AES, Brotli, LZ4, and Zstd, plus plain,
encoded, and encrypted headers, empty streams/files, SFX, and six sequential
volumes. `lzma1900.7z` contains 633 listed entries and complex BCJ2/LZMA chains.

The Go fuzz target seeds `copy.7z` and asserts only that reader construction
does not panic. The four saved fuzz artifacts are malformed-input candidates,
not a complete malformed corpus.

## Local 7zz oracle inspection

`7zz` 26.02 successfully tested the standard-method, SFX, encrypted test
fixtures with known test passwords, and the six-volume archive. The locally
installed binary returned unsupported-method errors for the bundled private
method IDs `04F71101` (Zstd), `04F71102` (Brotli), and `04F71104` (LZ4).
`COMPRESS-492.7z` is a 39-byte malformed regression expected to fail. Archives
whose password was not documented were not treated as failed fixtures.

## Corpus admission requirements

Before using or committing the requested corpora, record for every file or
coherent source set:

- canonical path/source URL and acquisition date;
- SHA-256 and byte length;
- creator and redistribution license/permission;
- valid versus malformed classification and mutation history;
- passwords stored only in test configuration suitable for publication;
- expected `7zz` version/output and any oracle limitation; and
- the method, feature, metadata, volume, corruption, or regression claim it
  supports.

Malformed cases should be minimized without destroying the triggering
invariant. Valid cases must not be mutated in place; derived corruptions get new
hashes and provenance records.
