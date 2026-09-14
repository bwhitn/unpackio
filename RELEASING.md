# Releasing the Python distribution

PyPI publication is intentionally manual and is never triggered by a push,
pull request, tag creation, or GitHub release. The `release-pypi` workflow must
be dispatched from an existing `v<version>` tag. It reruns the complete core
and Python workflows, validates and checksums the distribution set, and only
then enters the protected `pypi` GitHub environment. A required reviewer must
approve that environment deployment before the publish job can obtain an OIDC
token or contact PyPI.

The publish job has no repository checkout and performs no build. It downloads
the already tested aggregate artifact and uses PyPI Trusted Publishing. No
long-lived PyPI token is stored in GitHub. The publishing action is pinned to
an immutable release commit and produces PyPI publish attestations by default.

## Published artifacts

Every release contains one source distribution and six optimized `cp39-abi3`
wheels:

| Operating system | x86-64 | ARM64 |
| --- | --- | --- |
| Linux | manylinux 2.17 x86-64 | manylinux 2.17 aarch64 |
| macOS | Intel x86-64 | Apple Silicon arm64 |
| Windows | AMD/Intel x86-64 | Windows ARM64 |

The stable ABI floor remains CPython 3.9, so one wheel serves multiple CPython
versions for a given operating-system/architecture pair. Before a release can
reach the approval gate, every wheel is installed and the complete Python
binding suite passes under CPython 3.12, 3.13, and 3.14 on its native target.
The Linux aarch64 wheel is cross-built in a manylinux container and tested on
a native ARM64 runner. macOS Intel/Apple Silicon and Windows x86-64/ARM64 use
their corresponding native GitHub-hosted runners.

## One-time GitHub and PyPI setup

Repository files cannot create a protected GitHub environment. Before the
first release, an administrator must configure **Settings → Environments →
New environment** as follows:

1. Name the environment exactly `pypi`.
2. Add at least one required reviewer. A sole maintainer should leave
   “Prevent self-review” disabled so they can approve their own dispatched
   release.
3. Restrict deployment tags to `v*`.
4. Disable administrator bypass if the repository plan exposes that control.

For the first upload, configure a PyPI pending Trusted Publisher. Use these
exact identity fields:

| Field | Value |
| --- | --- |
| PyPI project | `unpackio` |
| GitHub owner | `bwhitn` |
| GitHub repository | `unpackio` |
| Workflow filename | `release.yml` |
| Environment | `pypi` |

A pending publisher creates the project on its first successful upload; it
does not reserve the name beforehand. If the PyPI project already exists,
configure the same values under that project's Publishing settings instead.
Do not configure a password or API-token secret for this workflow.

## Release procedure

1. Update all package versions and version assertions together. The Rust
   workspace, binding crate, Python project, and `unpackio.__version__` must
   agree.
2. Commit and push the reviewed release state. Ensure ordinary branch checks
   are green.
3. Create and push the matching immutable version tag, for example `v0.2.0`.
4. In GitHub Actions, choose **release-pypi**, select that tag in the “Use
   workflow from” selector, and dispatch the workflow. The equivalent command
   is `gh workflow run release.yml --ref v0.2.0`.
5. Wait for the complete core gates, cargo-deny, MSRV/32-bit/Miri/fuzz jobs,
   six wheel builds, 18 native wheel smoke jobs, sdist rebuild, artifact-set
   validation, and SHA-256 manifest generation to pass.
6. Review the distribution names and SHA-256 values in the workflow summary.
   Approve the waiting `pypi` environment deployment only when they are the
   intended release artifacts.
7. Confirm that PyPI shows the source distribution, all six wheels, and their
   Trusted Publisher attestations.

Any failed check prevents the approval job from becoming runnable. Rejecting
the environment deployment publishes nothing. PyPI files are immutable: if an
upload partially succeeds, do not rebuild or reuse that version; inspect the
published files and prepare a new version for any correction.

The relevant external setup references are the
[PyPI pending-publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/),
[PyPI Trusted Publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
and [GitHub environment protection documentation](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).
