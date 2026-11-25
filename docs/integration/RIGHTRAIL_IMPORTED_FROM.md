# RightRail: imported from

`rightrail/` is RightRail trunk commit `e5d0f36bb1f7a17173cf1a1520095b1ad5b1eb15` (`rightrail-main`, 2026-11-22),
imported into localBCE on 2026-11-24 as a snapshot (TRUNK_MOVE_PLAN.md step M1). The RightRail maintainer named this
commit on 2026-11-23 (HANDOFF.md section 5, answer 1). This file lives outside `rightrail/` because the trunk's
documentation rule refuses hand-written Markdown that is not in its owners list.

- **Source.** A clone of the private repository `github.com/RightRail/rightrail`. The imported tree is
  `86fdbe4eb3906a8aa71717995a8cc0b0662166ac`, 769 files.
- **History: not imported.** The RightRail history is available from the private repository but is not in this
  repository: localBCE is public and RightRail is private, and the owner is holding every push of this import until that
  is settled (TRUNK_MOVE_PLAN.md, decision 1). Only the tree's files were brought in, through a parentless transfer
  commit that is not on any branch.
- **Method.** On `codex/rightrail-trunk-e5d0f36b`, branched from `codex/rightrail-trunk-step3` (`639c4a70`):
  `git rm -r rightrail`, then `git read-tree --prefix=rightrail/ -u 86fdbe4e`. No file is rewritten, so
  `git rev-parse HEAD:rightrail` at the import commit equals the tree hash above.
- **What the import removed.** localBCE's 14 commits of changes under `rightrail/` on the `fc89f9e5` base
  (`a0da49e8` to `bb50ba01`). The maintainer's answers supersede them; the owner approved dropping them from the tree
  on 2026-11-24 after a commit-by-commit review (TRUNK_MOVE_PLAN.md). They stay in git history on
  `codex/rightrail-trunk-step3`.
- **Changed in localBCE since the import:**
  - The maintainer's axiom-pin fix, taken from trunk merge commit `69dec25d` (its change to
    `lean/BlindLedger/Gate/AxiomCheck.lean` and `AXIOMS.txt`, 17 lines each): at `e5d0f36b` the Lean build fails on 17
    stale pins. Applied as its own commit after the import (`291534ee`). This is upstream's text, not a localBCE
    change.
  - `tests/test_privacy_artifact_scan.py:188` splits its PEM header literal (`"-----BEGIN " "PRIVATE KEY-----\n"`) so
    localBCE's secret scanner passes; the test's input is unchanged. **This is the only localBCE deviation from the
    imported tree.** It repeats the same change made after the 2026-10 and 2026-11-14 imports.

## Previous imports (superseded)

- 2026-11-14 to this import: trunk `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`, from the GitHub archive
  `rightrail-rightrail-main.zip` (SHA-256 `1afbc74dc3cf3f5a97c494a196f0c0e0a2d3938abdd16c76b8ce09d36ba0ab71`), with
  the same one local change (the split PEM header literal).
  `scripts/check_rightrail_zip_import.py` checks that import, not this one.
- 2026-10-17 to 2026-11-14: `rightrail-main` at `af020b268094ae3fd6ef5e68fe575b7e5ac40a23` (2026-10-15, "TRAIN-11"),
  from `RightRail.bundle` (SHA-256 `3b61a4ab8bd007ba02aef61db643b72d07b20ab3a71fbbd5b216152634c1c5fa`), imported by
  localBCE `961434e1`. That history stays reachable. The October-base implementations of G2 (`f16a61f4`), G4
  (`90ffd3f9`) and the per-payment reason bound (`b5f806df`) remain on their branches as the record.

## Check

`git rev-parse <import commit>:rightrail` must print `86fdbe4eb3906a8aa71717995a8cc0b0662166ac`. Against a clone of
the private repository: `git diff --stat 'e5d0f36b^{tree}' HEAD:rightrail` lists only the changes named above.
