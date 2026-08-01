# Reviewed Python dependency boundary

Finding `R25-C01` is closed for the supported Python targets by a split acquisition/install design.
Network acquisition is an explicit maintainer review activity. Routine development, CI, and release
installation are offline and consume only an already provisioned wheelhouse.

## Governed inputs

- `requirements/inputs/*.in` declare the six direct production/development choices. They are not
  installation inputs.
- `requirements/locks/python-artifacts.lock.json` is canonical JSON. It binds every transitive
  package to one exact wheel filename, size, official PyPI acquisition URL, SHA-256, SHA3-512,
  embedded version, and declared wheel-metadata license for each supported platform.
- The four `requirements/locks/*.lock` files are pip-compatible, fully transitive, exact-version,
  SHA-256-hashed production/development locks for CPython 3.14.4 on Windows x86-64 and Linux x86-64.
- `docs/SBOM.python.spdx.json` reconciles all 26 logical packages and their declared licenses. The
  artifact manifest remains the authority for per-platform wheel identities.
- `requirements.txt` and `requirements-dev.txt` deliberately install nothing, preventing old
  automation from silently returning to online resolution.

Linux requires glibc 2.28 or newer because the reviewed PQCrypto wheel advertises that floor. The
lock also accepts older-floor compatible wheels for CFFI and Pydantic Core; those exact filenames
and hashes are individually bound, not dynamically selected.

## Install contract

`python -m tools.locked_python_dependencies install` performs these gates in order:

1. canonical-manifest schema and duplicate-key checks;
2. exact CPython 3.14.4, non-free-threaded ABI, OS/architecture/glibc, and platform pip version;
3. dual SHA-256/SHA3-512 readback of the selected source lock;
4. exact profile-to-lock-to-artifact graph reconciliation;
5. exact wheelhouse set checks, rejecting missing, extra, renamed, symlinked, directory, and sdist
   entries;
6. one streaming size/SHA-256/SHA3-512 pass over every wheel plus embedded METADATA Name/Version
   validation;
7. a fresh-virtual-environment gate;
8. isolated pip execution with local wheels only, hash enforcement, binary-only inputs, dependency
   resolution disabled, caches disabled, and all `PIP_*` environment configuration removed;
9. `pip check`, an exact installed package/version readback, and creation of a new non-overwriting
   canonical install attestation containing interpreter, manifest, lock, artifact, command, and
   installed-graph identities.

The wrapper contains no download path and never opens a socket. Throughput is preserved by avoiding
the resolver and hashing each wheel in one streaming pass before installation.

## Rotation contract

A dependency, interpreter, pip, OS/architecture, glibc-floor, or wheel-filename change is a new
review, never an in-place relaxation. The maintainer must acquire wheels from the official project
release, reject sdists, independently read back the local bytes and wheel METADATA, regenerate all
affected platform/profile locks and the Python SBOM, and retain the acquisition output and old
source identities in a new run-owned evidence directory. The negative bypass suite and clean
offline installs on every supported platform must pass before the new manifest can replace this
one. Old wheelhouses and attestations are immutable evidence, not caches to reuse silently.
