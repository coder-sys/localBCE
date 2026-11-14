# RightRail: imported from

`rightrail/` is RightRail trunk commit `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`, imported into localBCE on
2026-11-14 as a snapshot (TRUNK_MIGRATION_PLAN.md step 0, variant B). This file lives outside `rightrail/` because
the trunk's documentation rule refuses hand-written Markdown that is not in its owners list
(rightrail/tests/test_doc_shape.py:14-21, 51-53).

- **Source.** The GitHub archive `rightrail-rightrail-main.zip`, 9,656,995 bytes, SHA-256
  `1afbc74dc3cf3f5a97c494a196f0c0e0a2d3938abdd16c76b8ce09d36ba0ab71`. Its archive comment is the commit id
  `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`. It holds 627 files under `rightrail-rightrail-main/`.
- **History: not available.** No git bundle or clone containing `fc89f9e5` was available, so the RightRail history is
  not reachable from this branch and nothing here can be offered upstream as a pull request. The owner was asked for
  a bundle (TRUNK_MIGRATION_PLAN.md decision 1).
- **Method.** On `codex/rightrail-trunk`, branched from `codex/rightrail-base-phases` (`dc586d87`): `git rm -r rightrail`,
  then every zip entry written to `rightrail/` byte for byte with its Unix executable bit (a one-off helper that
  checked the zip hash and archive comment first), then `git add`.
  All 627 files are tracked; none is ignored.
- **Joining the history later.** When a bundle with `fc89f9e5` arrives: `git merge -s ours --allow-unrelated-histories
  fc89f9e5`, then `git diff --stat 'fc89f9e5^{tree}' HEAD:rightrail`, which should list only the changes below. No
  file is rewritten.
- **Changed in localBCE since the import:**
  - `tests/test_privacy_artifact_scan.py:188` splits its PEM header literal (`"-----BEGIN " "PRIVATE KEY-----\n"`) so
    localBCE's secret scanner passes; the test's input is unchanged. This repeats `e292cedc` from the October import.

## Previous import (superseded)

From 2026-10-17 to this import, `rightrail/` was RightRail `rightrail-main` at
`af020b268094ae3fd6ef5e68fe575b7e5ac40a23` (2026-10-15, "TRAIN-11"), from `RightRail.bundle` (SHA-256
`3b61a4ab8bd007ba02aef61db643b72d07b20ab3a71fbbd5b216152634c1c5fa`), imported by localBCE `961434e1` with
`merge -s ours --allow-unrelated-histories` and `read-tree --prefix=rightrail/`. That history stays reachable. Its
record was `rightrail/IMPORTED_FROM.md`, removed by this import. The October-base implementations of G2
(`f16a61f4`), G4 (`90ffd3f9`) and the per-payment reason bound (`b5f806df`) remain on their branches as the record.

## Check

Without history: `python3 scripts/check_rightrail_zip_import.py PATH/TO/rightrail-rightrail-main.zip` checks the zip
hash and archive comment, then compares every file with `rightrail/`; only the file listed above may differ.
With history: `git diff --stat 'fc89f9e5^{tree}' HEAD:rightrail`.
