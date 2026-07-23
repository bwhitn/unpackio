# Dependency policy and ledger

## Current runtime graph

The workspace contains only the Rust implementation core; the separately
locked Python binding depends on it by path. There is no executable or CLI
crate. The core has the following exact direct runtime dependencies; default
features are disabled and `Cargo.lock` is committed.

| Crate | Version | License | Enabled features | Runtime role and origin |
| --- | --- | --- | --- | --- |
| `aes` | 0.9.1 | MIT OR Apache-2.0 | `zeroize` | RustCrypto AES-256 primitive; `https://github.com/RustCrypto/block-ciphers` |
| `cbc` | 0.2.1 | MIT OR Apache-2.0 | `zeroize` | RustCrypto CBC mode; `https://github.com/RustCrypto/block-modes` |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | `zeroize` | RustCrypto SHA-256 for the 7z KDF and differential hashes; `https://github.com/RustCrypto/hashes` |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | `alloc` | Per-archive password and derived-secret clearing; `https://github.com/RustCrypto/utils` |
| `miniz_oxide` | 0.8.9 | MIT OR Zlib OR Apache-2.0 | `with-alloc` | Raw Deflate decoder; `https://github.com/Frommi/miniz_oxide` |
| `bzip2-rs` | 0.1.2 | MIT OR Apache-2.0 | `rustc_1_37` | Safe Rust BZip2 decoder; `https://github.com/paolobarbolini/bzip2-rs` |
| `brotli-decompressor` | 5.0.3 | BSD-3-Clause OR MIT | `std` | Brotli decoder; `https://github.com/dropbox/rust-brotli-decompressor` |
| `lz4_flex` | 0.13.1 | MIT | `checked-decode`, `frame`, `safe-decode`, `safe-encode` | Safe checked LZ4-frame decoder for 7z coder payloads and standalone streams; `https://github.com/pseitz/lz4_flex` |
| `ruzstd` | 0.8.1 | MIT | `hash`, `std` | Zstandard frame decoder with content-checksum calculation for 7z coder payloads and standalone streams; `https://github.com/KillingSpark/zstd-rs`; 0.8.2 uses APIs unavailable on Rust 1.85 and 0.8.3 requires Rust 1.87, so both exceed this project's tested MSRV |
| `twox-hash` | 2.1.2 | MIT | `xxhash32` (plus `xxhash64` unified through `ruzstd/hash`) | LZ4 descriptor checksum validation and transitive LZ4/Zstandard frame checksum support; `https://github.com/shepmaster/twox-hash` |
| `rawzip` | 0.4.4 | MIT | none | Safe-Rust, zero-dependency ZIP/ZIP64 structural reader; writer types are neither used nor re-exported; `https://github.com/nickbabcock/rawzip` |
| `ctr` | 0.10.1 | MIT OR Apache-2.0 | `zeroize` | RustCrypto little-endian AES-CTR mode required by WinZip AES; `https://github.com/RustCrypto/block-modes` |
| `hmac` | 0.13.0 | MIT OR Apache-2.0 | `zeroize` | RustCrypto HMAC authentication for WinZip AES; `https://github.com/RustCrypto/MACs` |
| `pbkdf2` | 0.13.0 | MIT OR Apache-2.0 | `hmac` | RustCrypto PBKDF2 key derivation for WinZip AES; `https://github.com/RustCrypto/password-hashes` |
| `sha1` | 0.11.0 | MIT OR Apache-2.0 | `zeroize` | RustCrypto SHA-1 for the legacy WinZip AES PBKDF2/HMAC construction and verification of RPM's legacy SHA-1 header-digest field; never used as a modern signature primitive; `https://github.com/RustCrypto/hashes` |
| `lzma-rust2` | 0.16.4 | Apache-2.0 | `std`, `xz`; default `encoder`/`optimization` disabled | Safe configuration of the Apache-2.0 XZ-for-Java port for RPM XZ and legacy `.lzma` payload decoding; `https://github.com/hasenbanck/lzma-rust2` |
| `delharc` | 0.6.1 | MIT OR Apache-2.0 | no default features | Only the LH6/LH7 static-Huffman payload decoder used for ARJ methods 1–3; crates.io checksum `1c93ba2617f5094875af777b3e1e5d66e79d7c832e4ae2e25722c965a482e5a1`, source commit `969e19d90ddf0a8e93598ac5cf117dfd8d1c2b7d`; no dependency header parser or archive model is called; `https://github.com/royaltm/rust-delharc` |

The complete normal/build transitive graph at this revision is:

| Crates | Versions | License selection |
| --- | --- | --- |
| `cipher`, `crypto-common`, `inout` | 0.5.2, 0.2.2, 0.2.2 | MIT OR Apache-2.0 |
| `digest`, `block-buffer`, `hybrid-array` | 0.11.3, 0.12.1, 0.4.13 | MIT OR Apache-2.0 |
| `cpubits`, `cpufeatures`, `cfg-if`, `typenum` | 0.1.1, 0.3.0, 1.0.4, 1.20.1 | MIT OR Apache-2.0 |
| `alloc-no-stdlib`, `alloc-stdlib` | 2.0.4, 0.2.4 | BSD-3-Clause |
| `crc32fast`, `tinyvec` | 1.5.0, 1.12.0 | MIT OR Apache-2.0; Zlib OR Apache-2.0 OR MIT |
| `adler2` | 2.0.1 | MIT selected from 0BSD OR MIT OR Apache-2.0 |
| `const-oid`, `ctutils`, `cmov` | 0.10.2, 0.4.2, 0.5.4 | MIT OR Apache-2.0 |
| `autocfg`, `bitflags`, `chrono`, `memchr`, `num-traits` | 1.5.1, 2.13.1, 0.4.45, 2.8.3, 0.2.19 | Apache-2.0 OR MIT; MIT OR Apache-2.0; MIT OR Apache-2.0; MIT selected from Unlicense OR MIT; MIT OR Apache-2.0 |

No decoder dependency uses FFI or links a native library. The core crate still
enforces `#![forbid(unsafe_code)]`; third-party dependency internals are a
separate audited boundary and do not satisfy that core lint. The admission
audit found target-intrinsic/volatile or
buffer implementations in RustCrypto/`zeroize` and `ruzstd`. `lz4_flex` is
compiled with its checked, safe decoder features, and Brotli's optional unsafe
feature is disabled. Each dependency decoder is wrapped by bounded input and
output accounting, cancellation/work checkpoints, a panic boundary, and a
method-specific allocation preflight. BZip2 charges five times the advertised
block size, Brotli charges 32 MiB, linked LZ4 charges 24 MiB plus 64 KiB, raw
Deflate charges 32 KiB, and Zstandard charges its parsed frame-window size
before constructing the decoder. Standalone LZ4 conservatively charges three
maximum blocks plus 64 KiB history, standalone Zstandard charges the parsed
window, and Unix `.Z` charges complete prefix/suffix/expansion tables before
allocation. Dictionary-bearing LZ4 and Zstandard frames are listable but
rejected as typed unsupported during extraction.

The new standalone CPIO and Debian readers add no dependency. Debian package
payloads reuse the existing bounded Deflate, BZip2, XZ/LZMA-alone, and
Zstandard adapters. The ARJ reader adds exact `delharc` 0.6.1 only for methods
1--3's static LH6 payload decoding; its archive parser, dynamic LH1 decoder,
I/O adapters, and optional features are not used. The invoked static decoder
allocates a 64-KiB ring and two fixed Huffman tables containing 1,060
two-byte nodes, so the wrapper charges a rounded 68 KiB before construction,
then preallocates only the already output-limited member result. The reviewed
static-tree path contains one dependency-internal `get_unchecked` optimization
after its complete-tree builder has validated table construction. Calls are
also enclosed in a panic boundary, and malformed/corrupt/resource regressions
exercise the wrapper. ARJ method 4 is an in-tree checked decoder charging its
fixed 8-KiB logical history before work; methods 0, 8, and 9 need no decoder
dependency.

The ZIP layer uses `rawzip` only for safe structural location/iteration. The
project independently validates local/central agreement, ZIP64 fields,
descriptors, ranges, limits, and exact consumption before decoding. `rawzip`'s
writer modules are not imported or re-exported. WinZip AES uses only the listed
RustCrypto `aes`, `ctr`, `pbkdf2`, `hmac`, and `sha1` primitives; the format
adapter owns no primitive implementation. Traditional ZipCrypto is a small
in-tree compatibility construction because it is not cryptographically secure
and has no admitted runtime implementation dependency.

The RPM layer reuses already admitted BZip2, Deflate, and Zstandard decoders.
`lzma-rust2` adds bounded XZ and legacy LZMA-alone decoding in safe Rust; its
encoder/optimization defaults are disabled. The wrapper parses XZ headers,
indexes, blocks, and LZMA2 dictionary properties before decoder construction,
charges the declared dictionary, bounds output, and checkpoints controlled
input/output loops. RPM header, digest, and CPIO parsing add no dependency.

Phase 5 adds no runtime dependency. The in-tree Deflate64 decoder charges its
fixed 64 KiB history requirement during model validation and again at decoder
entry, uses only stack-bounded Huffman tables plus fallibly grown bounded
output, and checkpoints every input refill and output loop. Its Apache-2.0
algorithm source and notice are recorded in `PROVENANCE.md` and `NOTICE`.
IA64, ARM Thumb, RISC-V, Swap2, and Swap4 are in-tree size-preserving filters
with no dictionary allocation or external linkage. XZ Utils was consulted only
as the pinned 0BSD algorithm-description reference identified in provenance;
it is neither a Cargo dependency nor shipped code.

Phase 6 adds no runtime or development dependency. Public API curation,
retained-resource accounting, integration tests, platform tests, and documentation are
original workspace changes. The default core feature set remains empty; the
`unstable-internals` feature only changes visibility for repository tests and
fuzz harnesses and activates no dependency.

Phase 7 is isolated in the separately locked and workspace-excluded
`bindings/python` package. It adds no dependency to `unpackio` and no decoder
or cryptographic implementation. Its direct binding dependencies are:

| Crate | Version | License | Enabled features | Binding role and origin |
| --- | --- | --- | --- | --- |
| `pyo3` | 0.29.0 | MIT OR Apache-2.0 | `abi3-py39`, `macros`; `extension-module` only for wheels | CPython ABI/type/call adapter; `https://github.com/PyO3/pyo3` |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | `alloc` | Clears the binding's temporary Rust password owner before/while the core assumes ownership; already admitted above |
| `unpackio` | 0.1.1, local path | MIT plus recorded adapted-source notices | normal core features only | Sole parser/model/decoder/crypto implementation |

PyO3 resolves `pyo3-build-config`, `pyo3-ffi`, `pyo3-macros`, and
`pyo3-macros-backend` 0.29.0; `libc` 0.2.186; `once_cell` 1.21.4;
`portable-atomic` 1.14.0; `proc-macro2` 1.0.107; `quote` 1.0.47; `syn`
2.0.119; `heck` 0.5.0; and `unicode-ident` 1.0.24. These are MIT and/or
Apache-2.0. Build-only `target-lexicon` 0.13.5 is `Apache-2.0 WITH
LLVM-exception`; the LLVM exception
adds permission, is recorded as an exact-version build-only cargo-deny
exception, and is not linked into the wheel. The binding's independently
resolved core graph is captured in `bindings/python/Cargo.lock`; it remains
subject to the same decoder admissions and runtime allowlist. That independent
resolution selects the same exact `twox-hash` 2.1.2 (MIT) as the root
lockfile; no duplicate version occurs within either artifact graph.

PyO3 and `pyo3-ffi` contain the reviewed unsafe/FFI implementation needed to
call CPython. The binding crate itself has `unsafe_code = "forbid"`, and the
core remains `#![forbid(unsafe_code)]` and Python-unaware. The adapter uses
owned `Py<PyAny>` handles across detached regions, performs no borrowed-Python
access while detached, and reattaches for one provider/writer/callback call.
There is no native decoder dependency or second archive parser.

A Python 3.9-or-newer interpreter is the caller-provided host platform for the
extension, licensed by its distributor (CPython uses the PSF License). The
interpreter is not bundled, vendored, declared as a Python `Requires-Dist`, or
linked into the macOS wheel, and is outside the shipped Cargo dependency graph
and its runtime-license allowlist. This platform prerequisite does not permit a
PSF-licensed Rust/native library to be added to the wheel without a separate
policy decision.

Maturin 1.13.3 is pinned as the PEP 517 build backend and CI packaging tool; it
is not installed or imported by the wheel at runtime. The produced package has
no Python-level runtime dependency. Wheel and sdist license payloads include
the project MIT `LICENSE`, separate third-party/adapted-source texts under
`LICENSES/`, and `NOTICE`. The CI-only `PyO3/maturin-action` is pinned to commit
`86b9d133d34bc1b40018696f782949dac11bd380` (v1.49.4, MIT).

PyPI release automation adds no shipped dependency. The CI-only official
`pypa/gh-action-pypi-publish` action is pinned to commit
`cef221092ed1bacb1cc03d23a2d87d1d172e277b` (v1.14.0, BSD-3-Clause) and runs
only in the manually approved publish job. That job receives a short-lived
OIDC identity after all build/test/artifact gates; no PyPI password or API
token is committed or retained. Artifact transfer in the packaging and
release path pins `actions/upload-artifact` v4.6.2 at
`ea165f8d65b6e75b540449e92b4886f43607fa02` and
`actions/download-artifact` v4.3.0 at
`d3f86a106a0bac45b974a628896c90dbdf5c8093`; both use MIT. Those actions,
`actions/setup-python`, GitHub-hosted runners, and PyPI are
build/distribution infrastructure and are not imported, linked, or declared
by the installed wheel.

The 2026-07-21 Python interoperability changes add no Cargo or Python
dependency and do not alter any lockfile. PPMd property interoperability is an
in-tree parser rule over the already admitted decoder, and Python batch
extraction is an adapter over the existing stable core `EntrySink`. ZIP/RPM
data projections are exposed on the existing native classes, with no extra
Python adapter, decoder, crypto implementation, runtime fallback, or lockfile
entry. `py7zr`, `pyzipper`, `rpmfile`, and `7zz` are not
installed, imported, or executed by a built wheel. Wheel CI uses the same
pinned maturin action to cross-build manylinux-compatible x86-64 and aarch64
`cp39-abi3` artifacts; the aarch64 artifact is smoke-tested on GitHub's native
`ubuntu-24.04-arm` runner. GitHub-hosted runners and Actions are CI platforms,
not shipped dependencies.

On 2026-07-18, after the Phase 5 in-tree method additions,
cargo-deny 0.20.2 reported `advisories ok, bans ok, licenses ok, sources ok`
for both the runtime workspace and the separately locked fuzz package. The
final gate result is recorded in `PHASE_PLAN.md`.

The same cargo-deny 0.20.2 checks passed again after the Phase 6 feature/API
changes; the resolved dependency and license graphs did not change.

The separately configured Phase 7 binding graph also passed cargo-deny 0.20.2
for advisories, bans, licenses, and sources on 2026-07-18. Its exact
`target-lexicon` exception does not alter the root runtime allowlist.

`libfuzzer-sys` 0.4.13 and its transitive crates are confined to the excluded
`fuzz` package and are not linked into runtime artifacts. Its declared license
is `(MIT OR Apache-2.0) AND NCSA`; the required NCSA term has an exact-version,
fuzz-only exception in `fuzz/deny.exceptions.toml`. That exception is outside
the runtime workspace and does not expand the runtime license allowlist.
The fuzz package directly names `aes` 0.9.1 and `cbc` 0.2.1 only to author a
deterministic direct-KDF AES decoder seed with a public test password. Those
exact MIT OR Apache-2.0 packages were already present in the locked runtime
graph, so this adds no package or runtime dependency and no license exception.
After that direct-edge change, cargo-deny 0.20.2 again reported `advisories ok,
bans ok, licenses ok, sources ok` for both the runtime workspace and the
separately locked fuzz package on 2026-07-19.
After pinning `ruzstd` 0.8.1 to retain Rust 1.85 compatibility, cargo-deny
0.20.2 reported the same four successful checks for the runtime workspace,
fuzz package, and Python binding on 2026-07-19. No transitive dependency
changed; only the direct `ruzstd` version and checksum changed in each lockfile.
The same three cargo-deny 0.20.2 graphs reported `advisories ok, bans ok,
licenses ok, sources ok` on 2026-07-21 after the PPMd, batch-adapter, Brotli,
and wheel-matrix changes; no manifest or lockfile changed in that work.
The standalone-stream work later that day made the already resolved MIT
`twox-hash` 2.1.2 package a direct core dependency for LZ4 header checksums and
enabled `ruzstd`'s existing `hash` feature for Zstandard content checksums. It
added no package to the resolved runtime graph. Unix `.Z` is in-tree and adds
no dependency. After that change, cargo-deny 0.20.2 reported `advisories ok,
bans ok, licenses ok, sources ok` for the root runtime workspace, separately
locked fuzz package, and separately locked Python binding graph.
`cargo-deny`, cargo-fuzz, cargo-llvm-cov, Miri, Rust toolchains, GitHub Actions,
and `7zz` are development/test tools, not runtime dependencies. The local
coverage/fuzz audit used cargo-llvm-cov 0.8.7 and cargo-fuzz 0.13.2 installed
under a temporary tool root; neither changes a lockfile or shipped artifact.

## License allowlist

Every applicable runtime license must be satisfiable solely with:

- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- Zlib
- Unicode-3.0 or Unicode-DFS-2016

GPL, LGPL, AGPL, MPL, SSPL, Commons Clause, noncommercial terms, source-available
terms, and unknown/custom terms are rejected. Dual-license expressions are
accepted only when an allowed option actually applies. Combined `AND`
expressions must have every term allowed.

## Source and version policy

- crates.io is the only approved registry;
- git dependencies are denied;
- wildcard requirements are denied;
- duplicate crate versions are denied by default and require a documented,
  time-bounded exception if cargo-deny policy is later amended;
- exact resolved versions and checksums are committed in lockfiles;
- default features are disabled unless they are reviewed and needed; and
- runtime crates that vendor or derive from official 7-Zip or p7zip source are
  forbidden regardless of their declared crate license.

## Admission checklist

Before adding or updating a runtime crate, the change must record:

1. exact crate version, repository URL, maintainer/release status, and enabled
   features;
2. complete normal/build transitive graph from `cargo tree`;
3. Cargo SPDX expression and manual inspection of every packaged license and
   notice file;
4. upstream source provenance, including whether algorithm code was copied or
   generated from another project;
5. confirmation that official 7-Zip and p7zip source were not used;
6. unsafe blocks and FFI/native code, with isolation and audit plan;
7. maximum allocation/dictionary behavior and a way to account memory before
   allocation;
8. bounded-input, output-limit, cancellation, and malformed-property behavior;
9. current RustSec advisories, yanked status, and maintenance risk; and
10. the corresponding decoder row in `PROVENANCE.md`.

Passing cargo-deny is necessary but not sufficient: package metadata can omit
embedded or generated-code licensing facts.

## Capability admission status

| Capability | Required family or approach | Admission status |
| --- | --- | --- |
| CRC-32 | original safe Rust implementation in `checksum.rs` | Admitted; no dependency |
| AES-256 | RustCrypto `aes` family | `aes` 0.9.1 admitted with `zeroize` |
| CBC | RustCrypto `cbc`/`cipher` family | `cbc` 0.2.1 admitted with `zeroize` |
| SHA-256 | RustCrypto `sha2` family | `sha2` 0.11.0 admitted for the KDF and differential hashes |
| Secret storage | zeroizing per-archive owned bytes | `zeroize` 1.9.0 admitted; no global password/key cache |
| LZMA/LZMA2 | safe, limit-aware permissive implementation | In-tree safe Rust adaptation admitted; exact BSD-3-Clause provenance in `PROVENANCE.md` |
| Deflate | safe permissive implementation | `miniz_oxide` 0.8.9 admitted for Deflate |
| Deflate64 | safe permissive implementation | In-tree checked Rust adaptation of Apache Commons Compress's Apache-2.0 grammar/tables; no new dependency |
| IA64/ARM Thumb/RISC-V/Swap | safe size-preserving filters | In-tree checked Rust with pinned algorithm provenance; no new dependency |
| BZip2 | permissive implementation without native linkage | `bzip2-rs` 0.1.2 admitted behind a bounded adapter |
| PPMd | safe, explicitly memory-bounded permissive implementation | In-tree adaptation of `stangelandcl/ppmd` v0.1.1 admitted; exact MIT provenance in `PROVENANCE.md` |
| Brotli | safe permissive decoder | `brotli-decompressor` 5.0.3 admitted with unsafe feature disabled |
| LZ4 | safe permissive decoder | `lz4_flex` 0.13.1 admitted with checked/safe frame features |
| Zstd | safe permissive decoder | `ruzstd` 0.8.1 admitted with frame-window preflight and dictionaries rejected |
| Standalone Unix `.Z` | safe, limit-aware permissive implementation | In-tree safe Rust adaptation admitted; exact NetBSD BSD-3-Clause provenance and notice in `PROVENANCE.md` and `LICENSES/BSD-3-Clause-netbsd-zopen.txt` |
| Python FFI | isolated adapter over the stable core | PyO3 0.29.0 admitted in `bindings/python`; no Python dependency enters the core workspace |

## Development-only 7zz rule

`7zz` may be located and invoked by tests to generate or compare oracle output.
The runtime core and installed Python wheel must contain no command invocation
or fallback path to `7zz`. Official 7-Zip and p7zip source must not be
downloaded, vendored, read, or translated.

The capability-probe integration test adds no dependency. It uses
`std::process::Command`, the existing `sha2` dependency, and an installed
exact-version `7zz` test oracle. No oracle executable or generated archive is
packaged or committed.

The Windows CI oracle job obtains the official 26.02 x64 installer from the
`ip7z/7zip` GitHub release and checks the release-published SHA-256
`6745fa76dc2ea031596d8678f6f6b99c3c1b435b4164a63485adbbc7b8d82ef0`
before execution. It installs only inside the ephemeral runner and supplies
the resulting `7z.exe` through the test-only `UNPACKIO_7ZZ` override. This is the
explicitly permitted black-box oracle use, not a Cargo dependency, shipped
tool, source input, runtime fallback, or runtime-license exception. The
Windows control/ADS-readback checks and bounded diagnostic collector use only
`std::fs` and existing test code; publishing their TSV records through the
built-in GitHub job summary adds no action, package, or runtime dependency.
The generated core/property and Phase 5 harnesses use the same test-only
override and add no action, Cargo dependency, or lockfile change.

The Linux capability job uses the official 26.02 x64 tarball with release
SHA-256
`41aaba7b1235304ab5aa0624530c67ae829496cd29e875925271efdccc28c03e`.
It extracts only the `7zz` oracle into the ephemeral runner and adds no runtime
artifact, source input, Cargo dependency, or license exception. The bundled
manual is referenced only to classify WIM-only command switches; it is not
vendored or packaged.

The generated method/property matrix likewise adds no dependency or lockfile
change. It uses `std::process::Command`, the existing `sha2` test use, and the
installed exact-version oracle; all generated source and archive bytes remain
in a uniquely named temporary directory that is removed after the test.
