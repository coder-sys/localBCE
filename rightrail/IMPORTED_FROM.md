# Imported from

This tree is RightRail `rightrail-main` at `af020b268094ae3fd6ef5e68fe575b7e5ac40a23`
(2026-10-15, "TRAIN-11"), imported into localBCE under `rightrail/`.

- Source: `RightRail.bundle`, SHA-256
  `3b61a4ab8bd007ba02aef61db643b72d07b20ab3a71fbbd5b216152634c1c5fa`, which matches
  `cf0a2f03-MANIFEST.sha256`.
- Import commit: localBCE `961434e1d4dc0b745c2e8bffc0b32000e5619311` (2026-10-17). Method:
  `merge -s ours --allow-unrelated-histories`, then `read-tree --prefix=rightrail/`, so the
  RightRail history is reachable and no file was rewritten.
- Changed in localBCE since the import:
  - `e292cedc` (2026-10-17): `tests/test_privacy_artifact_scan.py` splits its PEM header
    literal so localBCE's secret scanner passes; the test's input is unchanged.
  - This file and its Markdown ceiling in `tests/test_bloat_budget.py` (2026-11-07).

To check: `git diff af020b2 HEAD -- . ':!IMPORTED_FROM.md'` from the localBCE root, with
paths under `rightrail/`, should show only the changes listed above.
