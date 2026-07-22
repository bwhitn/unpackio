# Stock 7zz capability probes

## Purpose and boundary

`crates/unpackio/tests/capability_probe.rs` is an opt-in, corpus-free black-box
suite for the exact stock `7zz` 26.02 executable. It separates four facts that
must not be conflated:

- whether `7zz` can author a candidate archive;
- whether `7zz` can read or test it;
- whether the Rust production API can open and verify it; and
- whether a platform-specific semantic effect was actually preserved.

The suite does not invoke `7zz` from the core or Python package, does not inspect or
adapt official 7-Zip source, and does not turn a synthesized candidate into a
positive compatibility fixture merely because a parser accepts it. Generated
files live in a uniquely named temporary directory and are removed after the
run.

## Running the probes

Place the exact stock `7zz` 26.02 executable on `PATH`, or set `UNPACKIO_7ZZ` to
the exact stock console executable. The override permits the official Windows
`7z.exe` name without changing the runtime package environment. Then run:

```text
cargo test -p unpackio --test capability_probe \
  stock_7zz_2602_capability_probe_report \
  --all-features --locked -- --ignored --nocapture
```

Each result is one tab-separated line prefixed with `UNPACKIO_7ZZ_PROBE`. The
columns are probe name, author status, oracle-read status, Rust-read status,
generated archive SHA-256 when one exists, and a bounded diagnostic. The
platform-neutral statuses are asserted as an exact 26.02 baseline so a changed
oracle result fails the ignored test instead of silently changing a claim.
Diagnostics retain at most six marker/context lines; in particular, the
non-empty line following a marker such as `System ERROR:` is no longer
discarded.

`accepted-with-warning` means the command exited successfully but emitted a
warning marker. It is not equivalent to semantic support.

The `windows-7zip-capability` GitHub Actions job downloads the official x64
26.02 installer release asset, requires SHA-256
`6745fa76dc2ea031596d8678f6f6b99c3c1b435b4164a63485adbbc7b8d82ef0`
before executing it, installs into the ephemeral runner directory, sets
`UNPACKIO_7ZZ` to that installation's `7z.exe`, and runs this ignored test with
output visible. The binary is a test oracle only; it is not cached, packaged,
or available to runtime code. The job copies the structured records into its
GitHub Actions summary. Windows control, `-sni`, and `-sns` author/read
classifications are asserted so an environmental or oracle change requires
review.

After publishing the capability summary, the same checksum-pinned job runs the
corpus-free generated core/property and Phase 5 differential suites. Those
suites use the test-only executable override, require the exact 26.02 banner,
and delete every generated archive. Successful results are compatibility
evidence, not part of the capability classification table below.

The `linux-7zip-capability` job independently downloads the official 26.02
Linux x64 archive, requires SHA-256
`41aaba7b1235304ab5aa0624530c67ae829496cd29e875925271efdccc28c03e`,
extracts only `7zz`, and publishes the same structured report. Its first run
was reviewed on 2026-07-20; the observed results are recorded below and do not
establish hard-link relationship preservation.

## Observed macOS 26.02 results

The following results were observed on 2026-07-19 and extended with the raw-AES
chain and Rust member-byte checks on 2026-07-20, using the x64 macOS build of
stock `7zz` 26.02:

| Probe | Fixture origin | 7zz result | Rust result | Interpretation |
| --- | --- | --- | --- | --- |
| File comment candidate | Original CRC-correct synthetic Copy archive | Test/list exit successfully with `Unsupported feature` warnings; no `Comment` field is listed | Opens and verifies; bounded raw property is retained | Not evidence that 7zz supports this comment serialization or that Rust semantically decodes comments |
| Archive comment candidate | Original CRC-correct synthetic Copy archive | Test/list succeed without warning, but no `Comment` field is listed | Opens and verifies; bounded raw archive property is retained | Appears ignored as an archive property; not semantic-comment evidence |
| Alternative Copy coder candidate | Original CRC-correct synthetic Copy archive | Rejected with `Unsupported feature` | Typed `UnsupportedFeature` | No demonstrated 26.02 parity gap; candidate validity beyond the black-box result is not claimed |
| Unknown Copy unpacked size | Original CRC-correct synthetic Copy archive | Rejected with `Data Error` | Opens and verifies by deriving Copy output from bounded input | Rust's safe extension is not credited as 7zz compatibility |
| Unknown packed size | Original CRC-correct synthetic Copy archive | Rejected with `Headers Error` | Typed `UnsupportedFeature` | Current Rust boundary agrees with the observed oracle rejection |
| Unknown non-final substream size | Original CRC-correct two-member Copy archive | Rejected with `Headers Error` | Typed `UnsupportedFeature` during verification | Current structured rejection remains appropriate |
| Raw `AES256CBC` author requests | `7zz a -m0=AES256CBC` and Copy→`AES256CBC` | Main-coder and filter-chain authoring both fail with `E_NOTIMPL` | Not run because no archive was produced | `7zz i` advertises the decoder ID, but read compatibility remains unproven without a permissibly sourced fixture |
| Hard-link switch | `7zz`-authored `-snh` archive over two host hard links | Author/test/extract succeed; extracted paths are distinct files on this host | Opens, verifies, and returns the expected bytes for both entries | Hard-link relationship preservation is not established by this host result |
| Symbolic-link switch | `7zz`-authored `-snl` archive | Author/test/extract succeed and restore the relative target | Opens and verifies both entries | Confirms the already documented symlink slice |
| NT security | Windows-only `-sni` probe | Not applicable on this host | Not run | The exact 26.02 manual says this switch stores metadata only in WIM, outside the 7z reader scope |
| NTFS alternate streams | Windows-only `-sns` probe | Not applicable on this host | Not run | The exact 26.02 manual says this switch stores streams only in WIM, outside the 7z reader scope |

The six deterministic synthesized archives had these SHA-256 values:

| Probe | SHA-256 |
| --- | --- |
| File comment candidate | `0613dd8ff540059ce5fb9cabc5ab876afa98fb9c1c6945a571a86ad4743ad6f4` |
| Archive comment candidate | `ffcce8a0d54efc09c6059309be3d7c6c89ae16ad6ea156ce7d247a4bb8b0f46d` |
| Alternative Copy coder candidate | `a1e1cbd05c69e982cb44fe620afbc5e7a6d27e8cd5f928a1d4c6ccd7d7e39423` |
| Unknown Copy unpacked size | `4bd9c052eb719182bc574ac88bf681f7eeefa05ef949f646d285f380ac34ef1d` |
| Unknown packed size | `5ee94cbc6de923ad71f97b3b9156df1019c0ac7551c65337ba0d7861704a353f` |
| Unknown non-final substream size | `2aa96e58bc47a5da7e42d26fc8986eea031deafacab695eec31abc2c1edf74d3` |

These hashes identify ephemeral test construction, not committed corpus files
or redistributed oracle material. `7zz`-authored link archives include host
metadata and therefore are not assigned stable hashes.

## Observed Linux 26.02 results

The first checksum-pinned Linux run completed from commit `d1eabdf` in GitHub
Actions run
[`29787328152`](https://github.com/bwhitn/unpackio/actions/runs/29787328152) on
Ubuntu 24.04. It reported the exact standalone `7-Zip (z) 26.02 (x64)` banner
and matched all six platform-neutral candidate baselines. The host-authored
results were:

| Probe | Author result | Oracle/Rust result | Interpretation |
| --- | --- | --- | --- |
| Raw `AES256CBC` main coder | Rejected, exit 2, `E_NOTIMPL` | Not run; no archive was produced | No raw-AES read evidence |
| Copy-to-`AES256CBC` chain | Rejected, exit 2, `E_NOTIMPL` | Not run; no archive was produced | The explicit filter form supplies no additional fixture |
| Hard link | Accepted | Oracle test/extract and Rust verification accepted; both Rust members matched the project-authored bytes, while oracle extraction reported `same-file=false` | Confirms two readable entries, not a preserved link relationship |
| Symbolic link | Accepted | Oracle extraction restored the relative target; Rust verified both entries | Confirms the existing symlink compatibility evidence |

The oracle listing exposed no hard-link field. As on macOS, the temporary
archive therefore supplies positive entry-byte evidence but no semantic
hard-link fixture. No host-authored archive or oracle binary was retained.

## Observed Windows 26.02 results

The first repository Windows run completed on 2026-07-19, but its diagnostic
collector omitted the line following `System ERROR:`. The hardened follow-up
completed on 2026-07-20 from commit `24cf688` in GitHub Actions run
[`29776673106`](https://github.com/bwhitn/unpackio/actions/runs/29776673106) on
Windows Server 2025. It used the checksum-pinned x64 installer, reported the
exact banner `7-Zip 26.02 (x64)`, passed the no-switch control and stage-drift
assertions, and matched the six platform-neutral candidate baselines above.
The reviewed Windows-specific and host-authored results were:

| Probe | Author result | Oracle/Rust result | Interpretation |
| --- | --- | --- | --- |
| Windows no-switch control | Accepted | Oracle test/extract and Rust verification accepted two separate entries | Confirms that ordinary authoring and both readers worked in the same environment |
| Raw `AES256CBC` main and Copy-chain forms | Rejected, exit 2, `System ERROR: Not implemented` | Not run; no archive was produced | No raw-AES read evidence from either authoring form |
| Hard link | Accepted | Oracle test/extract and Rust verification accepted; both Rust members matched the project-authored bytes, while same-file identity was unavailable to the test | No hard-link semantic-preservation claim |
| Symbolic link | Not applicable | Not run | The hosted process could not create the required unprivileged source link |
| NT security (`-sni`) | Rejected, exit 2, `System ERROR: Not implemented` | Not run; no archive was produced | Matches the shipped 26.02 manual's WIM-only authoring boundary; it is not a 7z compatibility gap |
| NTFS alternate streams (`-sns`) | Rejected, exit 2, `System ERROR: Not implemented` | Not run; no archive was produced | ADS readback succeeded, but the shipped manual documents WIM-only storage; it is not a 7z compatibility gap |

The follow-up demonstrates that the ordinary authoring path and Rust reader
were operational and that the ADS source existed with the expected bytes. The
exact Windows 26.02 oracle nevertheless rejected raw AES, `-sni`, and `-sns`
before producing an archive. The raw-AES result is evidence about that oracle
build and CI host, not proof that every valid serialization is absent and not
evidence of a Rust decoder gap. The official manual shipped in the
checksum-verified Linux 26.02 package explicitly limits `-sni` and `-sns`
storage to WIM, so those two switches are outside this 7z-only project.
Host-authored temporary archives contain host metadata and are not assigned
stable corpus hashes.

The expanded checksum-pinned Windows job at `d1eabdf`, in the same run linked
above, passed all four ignored `generated_oracle` core/property tests and both
ignored Phase 5 tests. It also confirmed the Copy-chain raw-AES rejection. The
generated archives were deleted and are not corpus files.

## Remaining probe work

A raw `AES256CBC` read probe, a positive alternative-coder archive, or a
semantic comment fixture may be added only when its bytes have an acceptable
documented origin and redistribution status. NT-security and ADS fixtures are
not sought for this project because the exact oracle manual documents their
storage as WIM-only.
Multi-output coder support likewise remains a conditional implementation item
until a valid stock-accepted method graph is available.

No probe result justifies weakening checked ranges, unknown-size policy, path
validation, CRC enforcement, or typed unsupported errors.
