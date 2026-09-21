# Security policy

## Implementation status

This repository is pre-alpha. Phase 7 adds a Python adapter over the stable
Rust API but decodes only the methods explicitly supported in
`COMPATIBILITY.md`, resolves encoded and encrypted headers, supported external
folder definitions and metadata, and reads bounded
sequential volumes. Passwords and KDF output are per archive and zeroized. The
member reader holds one completely decoded folder in memory and reports that
retained allocation. A separate bounded `CompressedStream` surface accepts
LZ4, Zstandard, and Unix `.Z` inputs without inventing archive members. The
core also has separately validated `ZipArchive`, `RpmArchive`, `CpioArchive`,
`DebArchive`, and `ArjArchive` readers.
ZIP authenticates/decrypts entries only through its own per-archive password
state; RPM verifies its supported package digests before exposing payload
members and retains the decoded CPIO payload under configured limits. Do
not use this project as a security boundary or infer compatibility for an
untested method/property combination.

Once the repository has a hosting location, vulnerabilities should be reported
through its private security-advisory channel rather than a public issue. Until
then, disclose directly to the repository owner. Reports should include the
affected commit, smallest reproducer, observed resource use or error, platform,
and whether a password is involved. Do not include real passwords or sensitive
archive contents when a synthetic reproducer is possible.

## Non-negotiable invariants

- Malformed input returns a typed error and does not panic.
- The core crate forbids unsafe code.
- Compressed-input processing paths contain no `unwrap`, `expect`, `panic!`, unchecked
  input-derived indexing, unchecked narrowing, or unchecked offset arithmetic.
- A declared property is parsed in an exact bounded sub-reader.
- Allocation and expensive work follow their relevant limit checks.
- Raw parser records never escape as validated model records.
- All stream counts, indices, bindings, roots, cycles, totals, CRC arrays, and
  ranges are validated before decoder construction.
- Missing CRC and unknown unpacked size use `Option`; zero is not a sentinel.
- Archive output helpers verify member CRC before success; member streams
  require `finish()`. Standalone helpers verify every checksum declared by
  their frame format before success.
- ZIP output helpers require authentication, size, and applicable CRC success;
  RPM output requires supported package-digest and applicable CPIO-CRC success.
- Standalone CPIO requires exact records/trailer and applicable CRC-newc sums;
  Debian requires exact ar/tar ranges and tar header checksums; ARJ requires
  all header CRCs plus member CRC before successful output.
- Unsafe paths never change file-to-stream mapping.
- Password and key material is per archive, redacted, and zeroized; no global
  secret cache is permitted.
- Volume count and aggregate bytes are checked before allocation/copying;
  provider reads are checkpointed and a missing part names the exact expected
  suffix.
- Unsupported valid features return `UnsupportedFeature`; unknown methods
  return `UnsupportedMethod`.
- `7zz` cannot be a runtime fallback or dependency.

## Error taxonomy

The public categories are `Format`, `Checksum`, `UnsupportedMethod`,
`UnsupportedFeature`, `LimitExceeded`, `MissingVolume`, `PasswordRequired`,
`WrongPasswordOrCorrupt`, `Cancelled`, and `Io`. Diagnostics must not contain
password bytes, derived keys, decrypted header bytes, or unbounded attacker
strings.

`ERRORS.md` defines retry and partial-output semantics. In particular, bytes
observed before `MemberReader::finish`, `extract_entry_to` success, or
`EntrySink::finish_entry` are unverified and must not be committed as trusted
output.

Standalone format-specific payloads use `StreamFormat`, `StreamChecksum`, and
`UnsupportedStreamFeature` variants while retaining the stable `Format`,
`Checksum`, and `UnsupportedFeature` categories. They preserve the format and
zero-based frame index or feature name for FFI mapping.

## Unsafe-code exception process

No exception exists. A proposed exception must be isolated in a separate crate
and review, document why safe Rust is insufficient, enumerate every safety
invariant, minimize and annotate each unsafe block, add direct misuse and
sanitizer/Miri tests where applicable, and update the threat/dependency/
provenance records. The core crate remains `#![forbid(unsafe_code)]`.

## Checksum semantics

Start-header CRC protects the fixed next-header location fields. Next-header
CRC protects the stored next-header bytes. Encoded-header, additional-stream,
packed-stream, and folder CRCs protect their applicable decoded streams.
Member CRC protects exactly that member's output. A failure is scoped and never
converted to success because a caller stopped reading early.

AES-CBC does not authenticate ciphertext. A wrong password may therefore be
indistinguishable from corruption until structure or CRC verification; the
combined error is intentional.

The current implementation enforces start-header and stored-next-header CRCs
for regular and bounded-SFX inputs. During supported decoding it also verifies
packed-stream CRCs before decode, encoded-header folder/substream CRCs before
parsing decoded header bytes, and folder/member CRCs before a high-level helper
returns success. Encoded-header folders are accounted cumulatively before
decode, every declared substream must consume its folder output exactly, and
all substream CRCs succeed before the reconstructed header is parsed. CRC
errors retain distinct typed scopes. External folder definitions follow the
same packed/folder/substream verification before their bytes reach the parser;
the selected decoded folder output must contain exactly the declared folder
records. A `MemberReader`
caller can observe bytes before integrity is final and therefore must call
`finish()`; dropping it never implies success.

LZ4 descriptor checksums are validated while opening. LZ4 block/content and
Zstandard content checksums are finalized during extraction, and a standalone
call returns success only after all applicable frames finish. Frames without a
declared checksum cannot acquire an invented one. Unix `.Z` has no embedded
checksum or decoded-size declaration; valid EOF is therefore not evidence
against clean-boundary truncation or intentional substitution.

Standalone CPIO verifies CRC-newc sums while opening and before output; other
CPIO layouts carry no member checksum. Debian verifies every tar header before
publishing metadata and delegates gzip/XZ/Zstandard integrity checks to the
bounded shared wrapper decoders; uncompressed, BZip2, and LZMA-alone tar
members do not gain an invented package checksum. ARJ verifies main, local,
and extended header CRCs while opening. Methods 0–4 and method 9 require the
member CRC before a high-level extraction writes or a batch entry is
finalized; method 8 explicitly carries no CRC and is accepted only with zero
stored and output bytes.

ARJ encrypted entries remain listable metadata but extraction returns
`PasswordRequired`; there is no plaintext fallback. Split/multi-volume and
security-envelope flags are typed unsupported. The pinned `delharc` dependency
is used only for the static-LZH payload decoder, never for hostile headers. Its
64-KiB ring and fixed Huffman tables are conservatively charged as 68 KiB
before construction, calls are bounded by declared output and operation
checkpoints, and malformed-input panics are contained. Dependency-internal
unsafe code is recorded and audited in `DEPENDENCIES.md` and `PROVENANCE.md`;
the project core itself remains `#![forbid(unsafe_code)]`.

Python `extract_entry_to`, `stream_entry`, and batch `extract_entries_to` use
the same high-level finalizing paths. A Python writer or callback can observe
chunks before a trailing member CRC fails, but the native call does not return
success until member and folder checks finish. For a batch sink,
`finish_entry` is the per-entry trust boundary and is never called for a member
whose CRC failed. The binding never turns `Entry.raw_name` into a destination.

ZIP and RPM expose only the native writer/callback extraction operations.
They do not return a complete member automatically or derive an output path.
Applications that need a complete result may provide `io.BytesIO`, but its
memory is caller-owned and native per-entry/output/work controls remain
authoritative. A different ZIP password requires a separate archive session,
so secret state remains per archive. RPM opening validates the complete
supported package and does not bypass digest or payload validation for partial
metadata access. Zero decoded length is never treated as an authentication
shortcut: encrypted empty ZIP entries still verify their password and
authentication data.

`Archive::extract_entries_to` verifies the complete containing folder before
delivering any of its bytes, and calls the sink's `finish_entry` only after the
current member CRC succeeds. A sink can still observe bytes for a member whose
later member-CRC check fails, so only `finish_entry` is the success boundary.
No sink API derives a filesystem destination from raw archive metadata.

ZIP parsing requires its central and local records, ZIP64 values, descriptor,
payload range, and archive end to agree before an entry model exists. ZipCrypto
check bytes are only an early password signal; successful extraction still
requires exact decoding, size, and CRC. WinZip AES derives keys with bounded
PBKDF2-HMAC-SHA1, compares the password verifier, authenticates the complete
ciphertext, and only then decodes. AE-1 also verifies CRC; AE-2 follows the
format's authenticated-data rule. Password bytes and derived material are
zeroized and never shared with a 7z session.

ZIP XZ method 95 admits exactly one XZ 1.0.4 Stream followed only by optional
four-byte groups of zero Stream Padding. Stream Header, Block Header, Index,
and Stream Footer CRCs; every Index record and Block boundary; and each Block's
declared Check (NONE, CRC-32, CRC-64, or SHA-256) are validated before the
decoded member can succeed. The independent ZIP decoded-size and CRC boundary
still applies, including after ZipCrypto or WinZip AES processing.

ZIP JPEG method 96 validates its properties header and each bounded metadata
bundle before reconstructing bytes. LZMA metadata must produce the exact
declared bundle, aggregate metadata/bundle/slice/model/block memory is limited,
and every arithmetic input byte and output byte is work/cancellation charged.
Persistent JPEG quantization and canonical Huffman tables must be complete and
valid before a sequential scan; zero quantizers, repeated components/symbols,
oversubscribed codes, nonsequential profiles, coefficient overflow, truncated
segments, output-size disagreement, and trailing outer bytes fail closed. The
reconstructed JPEG is withheld until the independent ZIP CRC passes, including
after ZipCrypto or WinZip AES processing.

ZIP WavPack method 97 admits only legacy lossless RIFF/WAVE streams through
stream version `0x407`. The checked adapter requires bounded complete blocks,
contiguous sample/channel groups, consistent format and sample declarations,
at most 16 channels and 16 decorrelation terms, known sample count, exact
wrapper reconstruction, and exact packed/output consumption. It rejects
hybrid/lossy, DSD, RF64/non-RIFF, v5-only metadata, newer channel layouts, and
unknown sample counts. Each WavPack rolling CRC and the independent ZIP size
and CRC must pass, including after ZipCrypto or WinZip AES processing.

ZIP PPMd method 98 is a separate PPMd-I revision-1 boundary, not the 7z PPMd7
variant-H decoder. Its two-byte little-endian declaration must encode order 2
through 16, 1 through 256 MiB of model memory, and restoration mode restart,
cutoff, or freeze. The dictionary limit is checked before the fallible model
allocation. Decoding is bounded by the ZIP-declared output, but that size is
not accepted as a substitute for codec termination: an early or missing PPMd
end marker, output beyond the declared size, or any byte after the end marker
is malformed. The independent ZIP CRC still gates delivery, including through
ZipCrypto and WinZip AES.

RPM parsing validates both header index tables against their bounded stores
before constructing typed values. Supported main-header and payload digests are
checked while opening, before any CPIO member is available. CPIO CRC-newc sums
are rechecked before a member reaches a writer. OpenPGP signature blobs,
legacy MD5, and per-file digest tables are metadata only and are not reported
as authenticated; SHA3-256-only header digests and declared unsupported
SHA-512/SHA-3 payload digest modes fail closed with `UnsupportedFeature`.

## Python FFI boundary

The binding crate also forbids handwritten unsafe code. PyO3 and `pyo3-ffi`
own the CPython unsafe boundary; the core remains safe Rust and unaware of
Python. Native entry points contain unexpected unwinds and raise
`InternalError` without copying a panic payload into the Python exception.
Release builds explicitly
retain unwind semantics so this boundary remains effective.

Rust-only archive work detaches from the interpreter. Python is reattached only
for provider, writer, stream-callback, or batch-entry-sink calls, and no
borrowed Python reference crosses a detached region. Callback exceptions are
re-raised as the same Python exception object. A `False` callback requests
cancellation. One token and one work budget span a complete batch operation;
they are not reset between entries or folders. Tokens, work budgets, passwords,
and decoder state are never global.

Rust panic hooks are process-global and remain under the embedding
application's control; an unwind boundary cannot suppress an already-installed
hook without a racy global mutation. Archive code must therefore never place
secrets in panic payloads. An embedder that redirects process diagnostics must
configure its hook as part of its own hosting policy.

`open_bytes` checks `max_total_input_bytes` before allocating its owned Rust
copy and reserves fallibly. A Python volume provider's `bytes` length is
checked before its Rust copy and then passes through aggregate volume limits.
Memory already allocated by Python and memory retained by caller writers or
callbacks cannot be bounded or accounted by Rust; callers must bound their own
provider and sink behavior.

`open_stream_bytes` applies the same pre-copy input check. Standalone parsing
and decoding run detached; only bounded writer/callback delivery reattaches.
Callback exceptions and callback-requested cancellation retain the same
identity and classification as archive streaming.

Passwords passed as Python strings remain in Python-managed memory. Rust cannot
erase that caller object. Its Rust-owned buffer is moved immediately into
zeroizing storage, cleared after core construction, and the core retains only
its existing per-archive zeroizing representation.

## Limits and cancellation

Defaults are documented in `THREAT_MODEL.md` and implemented in `Limits`.
Builder overrides are explicit and per archive/session. A smaller entry limit
still applies inside a larger total limit. Dictionary memory is accounted
before allocation and does not include uncharged hidden caches. Parser and
encoded-header recursion is explicitly bounded. AES KDF power is checked before
hashing; each KDF round is charged. Cancellation and work-budget checks occur
between bounded volume/input reads and within long decoder/filter loops.
External-folder resolution validates its AdditionalStreamsInfo model and
folder-output `DataIndex` before decoding, charges all decoded outputs against
the cumulative output limit, reparses from the original header under the same
global count/property limits, and requires exact consumption of the selected
output. It may retain those bounded outputs because later `DataIndex` values can
refer to any folder. The bounded stored-header copy cannot exceed
`max_header_bytes`.
Supported LZMA decoding uses the output buffer itself as history. Third-party
codec adapters conservatively charge their working window/block memory before
decoder construction, bound output and input, and convert dependency panics to
typed format failures. `Archive::verify` processes every additional folder,
including unreferenced folders, before the main streams and drops each decoded
additional output before continuing. Additional and main folders share the
same total-output allowance, dictionary/KDF limits, per-archive password,
work budget, and cancellation token. Packed, folder, logical-substream, and
member CRCs retain distinct checksum scopes. Main-stream verification accounts
each folder once against total output, and natural-order `extract_entries_to`
does the same; one-member
random access bounds the complete containing folder. Every known solid
substream size is checked against the entry limit before folder decode. An
unknown final substream is decoded only where the codec supports EOS and with
an entry-sized remaining allowance; an unknown non-final substream is rejected
before decode. This is configured bounded memory, not constant-memory
streaming.

`CompressedStream` additionally checks `max_stream_frames` before growing its
layout table. It preflights declared aggregate output, LZ4 working blocks,
Zstandard windows, and the complete Unix `.Z` prefix/suffix/expansion storage
before decoder construction or allocation. Unknown output sizes are bounded
during every write. Input reads, frame boundaries, LZW codes, dictionary
walks, and decoder output loops share the caller's work budget and cancellation
token.

`ZipArchive` checks complete input and SFX/header bounds before structural
scanning, entry/name counts before metadata growth, declared decoded sizes
before extraction, and codec working memory before decoder construction. One
batch shares total output, work, and cancellation accounting. AES PBKDF2 uses
its fixed interoperable iteration count and charges the operation before work.
For method 95, the XZ Index is parsed before decoding; Block count, filter
count/properties, LZMA2 dictionary, total declared output, header bytes, and
coder totals are checked first. Parsing, LZMA2 output, reverse filters, and all
checks use the same work budget and cancellation token.
For method 97, the complete block/metadata layout, block and frame maxima,
channel topology, property totals, declared output, and worst-case per-block
working storage are checked before codec entry. One bounded block is decoded
at a time behind a panic boundary. Metadata scanning, per-sample decorrelation
work, reconstruction, and both checksum layers share the operation's work
budget and cancellation token; output capacity is reserved fallibly.
For method 98, property and coder counts, declared output, and model memory are
preflighted before model allocation. Range normalization, context traversal,
allocator maintenance/restoration, each decoded byte, and final end-marker
validation share the operation's work budget and cancellation token. Modeled
addresses are checked offsets into one fallibly allocated heap; input-derived
pointers, unchecked traversal, and a global model cache do not exist.

`RpmArchive` checks header index/store counts and modeled value allocation
before cloning values, then bounds compressed input, decoder dictionary/window,
decoded CPIO size, member count/names/sizes, work, and cancellation. It
currently retains the decoded CPIO image for the archive lifetime; that
retained allocation is observable through `retained_payload_bytes` and bounded
by the configured total-output limit.

`CpioArchive` bounds record count, individual and aggregate name bytes,
declared member and aggregate output, input, checksum work, and every aligned
range before metadata allocation. `DebArchive` accounts the outer members and
both inner tar streams under the count/name/header/input/output limits, and
retains the decoded control and data images only after bounded decompression.
`ArjArchive` bounds SFX scanning, header/extension totals, names, member
counts/sizes, decoder state, total output, work, and cancellation. Methods 1–3
preflight 68 KiB before constructing the dependency decoder; method 4
preflights its 8-KiB logical history and uses checked output indexing.

An open archive exposes checked `ArchiveResources` categories for its logical
input, validated metadata payload, per-archive secret buffer, and total. An
active `MemberReader` reports the complete decoded folder allocation that it
retains, including bytes outside the selected member in a solid folder.
Allocator bookkeeping and stack frames are not presented as archive payload;
input/header/name/property/count, dictionary/window, and output allocations
remain enforced by their separate configured limits. Natural-order sink
extraction retains at most one decoded folder and advances one substream cursor
rather than accumulating prior folders.

Deflate64 charges its fixed 64 KiB window during validated model construction,
before packed-input copying, and rechecks it at decoder entry. Its Huffman
alphabets are fixed-size stack values; attacker-sized output growth is checked
against the declared size and operation cap before fallible reservation. Every
bitstream refill and match-copy loop observes cancellation/work limits.

Unknown coder outputs use a closed allowlist. LZMA/LZMA2 and
Deflate/Deflate64 must reach their codec EOS/final block, and LZMA EOS also
requires a final range state with exact packed-input consumption; Copy and
size-preserving filters derive output from bounded input; BCJ2 ends with its
bounded main stream. PPMd and AES need declared sizes. BZip2, Brotli, LZ4, and
Zstandard are conservatively rejected for unknown output until their adapters
can prove exact framed-input consumption. No decoder invents a size.

7z PPMd coder properties are admitted only as the canonical five-byte
order/little-endian-memory record or as a seven-byte compatibility form whose
last two reserved bytes are both zero. All other lengths and nonzero reserved
bytes are malformed. The same parsed memory value is charged against the
dictionary limit before allocation for either form. Brotli remains strict
about stream completion: an unfinished flush-only stream is `Format`, even
when its already emitted prefix could produce the declared bytes.

## Password and volume boundaries

`Password` owns a zeroizing UTF-16LE buffer inside one `Archive`. Derived AES
keys, IVs, and digest buffers are zeroized and never cached globally. Error
messages do not echo passwords. Because AES-CBC is unauthenticated, encrypted
structural, size, or CRC failures are deliberately classified as
`WrongPasswordOrCorrupt` where the two causes cannot be separated.

`VolumeProvider` is an untrusted callback boundary. The archive layer checks
`max_volumes`, each reported length, the aggregate input limit, conversions,
and cancellation/work before reading or copying. Short reads are `Io`; a
provider-reported absent required part is `MissingVolume` with the expected
name. A terminal absent part is accepted only after the complete logical
archive bounds validate. The path provider performs no network discovery.

## Review gates

PyPI publication is isolated from building and testing. A manually dispatched
version-tag workflow reruns the complete core and Python gates, validates the
six-platform ABI3 wheel set and source distribution, and records SHA-256
digests before the publish job becomes eligible to run. The publish job uses a
GitHub `pypi` environment whose required reviewer is an external repository
setting; without that protection the repository does not meet its documented
release policy. Only this post-approval job receives `id-token: write`, and it
uses PyPI Trusted Publishing rather than a stored API token. It downloads the
already tested aggregate artifact, performs no checkout or build, and leaves
attestation generation enabled.

For version 0.2.0, every direct runtime crate is exact-pinned at the newest
Rust-1.85-compatible release admitted by the license/provenance policy, every
resolved graph passed cargo-deny, and the core and binding were tested with
Rust 1.85.0. CI actions are pinned to immutable commits. Maturin excludes
`dist*/**` from source distributions, and CI rejects any sdist containing a
nested wheel or build-output directory before attempting the isolated rebuild.

Security-sensitive changes must add a minimized regression and update all
affected compatibility, provenance, dependency, fuzzing, and benchmark claims.
Fuzz crashes are treated as security bugs until triaged. Corpus files need an
origin, hash, license/redistribution record, and expected oracle result before
commit.

No separate valid or malformed corpus is currently available. Security
regressions therefore use deterministic hostile constructors, CRC-correct
semantic mutation, exhaustive truncation/limit cases, and eight
coverage-guided targets: six 7z/path targets, the standalone-stream target,
and an archive-format target that also constructs structurally valid ZIP,
RPM, CPIO, Debian, and ARJ containers around arbitrary payloads. Its ZIP path
includes valid method-95 XZ, method-96 JPEG, method-97 WavPack, and method-98
PPMd streams plus structured corruption and truncation. The larger method-96
path is selector-throttled but includes the empty initial input, so every smoke
campaign reaches one exact positive decode and hostile mutation/prefix paths.
Temporary `7zz` output supplies positive
differential evidence only and is deleted after each opt-in test.

The original retained oracle-authored compressed payload is a 49-byte test-only 7z PPMd
stream over project-authored text; `CORPUS.md` records its exact 7zz 26.02
command, properties, CRC, and hashes. Production code does not invoke the
oracle. Unit and public-API regressions require exact output and reject every
strict packed prefix, meaningful corruption, low dictionary/output/work
budgets, and pre-cancellation before the vector is admitted as positive
evidence.

The compatibility extension wraps that same payload in generated archives
with canonical five-byte and zero-reserved seven-byte properties. It adds no
second PPMd implementation or external archive corpus. A separately generated
declared-property truncation and nonzero-reserved variants must fail before
decoding.

ZIP method 98 has its own nine-byte stock-`7zz` 26.02 vector over
project-authored `abc` and deterministic in-crate fixtures for every legal
property/restoration value. The latter encoder is compiled only for tests and
is not a public or production writer. Normal tests reject every strict payload
prefix, malformed property and range prefix, corruption, trailing data, early
or late end markers, size/CRC/version disagreement, insufficient dictionary,
output, coder/property or work limits, and cancellation before any writer or
batch sink is finalized. The external reference corpus is checksum-pinned,
opt-in, and never packaged; its supplemental PPMd sample is not attributed to
WinZip because the producer is unrecorded.

ZIP method 96 has a provenance-complete WinZip 21 vector over a
project-authored baseline JPEG, independently reconstructed byte-for-byte by a
pinned external oracle. Normal tests also exercise stored and LZMA-compressed
metadata, extended properties, malformed/missing/oversubscribed tables,
unsupported scan/frame profiles, sampled strict truncation, strategic
corruption, trailing input, low header/dictionary/frame/output/work limits,
cancellation, CRC-finalized atomic writer and batch delivery, and both ZIP
encryption schemes. The MIT reference source is not linked or executed.

ZIP method 97 has 10 deterministic WavPack 4.80 `-hh` payloads over
project-authored RIFF/WAVE inputs, independently decoded byte-for-byte by
official WavPack 5.9. They cover every supported storage width, integer and
float samples, mono/stereo, odd and maximum admitted channel
groups, a custom rate, multiple blocks, and wrapper trailers. Normal tests
reject every strict prefix, compressed-bit and internal-CRC corruption,
malformed metadata, excessive terms, unsupported versions/profiles, size and
resource disagreement, low work, and cancellation before any writer or batch
sink is finalized. A separate ignored harness is ready for a freshly authored,
versioned Windows WinZip archive; that deferred product oracle is not claimed
as completed evidence.

The exact-version capability probes are classification tests, not validation
shortcuts. Their observed `7zz` rejection of unknown packed and non-final sizes
does not weaken Rust's checked-range policy, and Rust's ability to derive a
bounded Copy output does not generalize EOS permission to another codec.
Synthesized comment or alternative-coder candidates remain hostile input unless
the normal parser, model, and decoder invariants accept them.

The Windows oracle job verifies the official 26.02 installer SHA-256 before
executing it and installs it only inside the ephemeral runner. Its executable
override is read only by ignored capability and generated-differential
integration tests; no production core, Python binding, wheel, or runtime path
can invoke the oracle. In the hardened follow-up at `24cf688`, the ordinary control
passed oracle and Rust verification, and ADS creation passed byte-for-byte
readback. Raw AES, `-sni`, and `-sns` then failed during authoring with
`System ERROR: Not implemented`, so none supplied feature
bytes to the Rust parser. The test keeps at most six sanitized diagnostic
marker/context lines and fails on a changed stage classification. Those test
diagnostics and assertions neither admit a runtime feature nor weaken any
hostile-input boundary.

The expanded Windows job at `d1eabdf` also rejected the explicit Copy-to-AES
authoring form and passed all four generated core/property tests plus both
Phase 5 tests. Those generated cases still enter the normal hostile-input
parser, checksum, resource, work, and cancellation paths.

The Linux capability job applies the same checksum-before-execution boundary
to the official 26.02 x64 tarball, extracts only the oracle executable, and
deletes every generated archive with its temporary directory. The hard-link
case now extracts both members through the production Rust API and requires
their bytes to match before reporting `rust-read=accepted`; same-inode identity
remains an oracle-host observation. The first reviewed job passed both member
checks but stock extraction reported `same-file=false`, so no filesystem-link
claim follows. The packaged 26.02 manual documents `-sni`
and `-sns` storage as WIM-only, so their Windows rejection does not justify
adding an unrelated 7z parser path.

The generated method/property matrix is positive differential evidence, not an
allocation or validation bypass. Requested dictionary/model sizes are asserted
from the validated coder properties and remain subject to the normal configured
limits before decoding. Its negative pass rejects packed corruption, strategic
physical truncation, low dictionary/output/work budgets, and cancellation for
every applicable generated form. CRC-correct plain-header mutations reach
logical packed truncation and oversized/empty coder-property validation without
disabling either header CRC. Its temporary archives are deleted.

The checksum-pinned CI invocation does not trust those archives: it runs the
same production limits, CRC checks, corruption cases, and exact temporary-tree
cleanup as the local opt-in harnesses.

## Rust 1.98.1 measured-I/O hardening

The 2026-09-21 optimization pass changes no trust boundary or configured
limit. Public writer/callback and path-read transfers may now be aggregated to
8 KiB, but `ParseControl::consume_bytes` still divides hostile-input and output
accounting into the existing 4 KiB cancellation/work checkpoints. Existing
Python regressions continue to enforce an 8 KiB maximum callback chunk.

Unix `.Z` output is accumulated in one fixed 8 KiB stack buffer instead of
issuing one writer call per decoded code. Dictionary sizes remain preflighted,
code windows use checked ranges and shifts, output limits are checked before
each delivered buffer, and work is charged for exactly the emitted byte count.
No input-derived allocation or unchecked access was introduced.

The high-level 7z byte-return path now verifies the member and folder CRCs
before moving a complete single-member folder buffer to the caller. A bounded
substream still receives one fallible exact-size copy after verification.
Writer extraction reads directly from the retained decoded folder in bounded
chunks while retaining the documented rule that a writer may observe bytes
before trailing CRC finalization. Failure never returns a trusted owned byte
result. The core remains `#![forbid(unsafe_code)]`; password storage,
zeroization, path policy, typed errors, and integrity ordering are unchanged.
