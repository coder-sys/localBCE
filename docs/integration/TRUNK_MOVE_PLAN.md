# Moving localBCE onto RightRail trunk `e5d0f36b`: draft plan (2026-11-24)

## Status

- **Draft. Not approved, not committed.** Nothing in `rightrail/` or any other tracked file has been changed for it. This is job 6 of `HANDOFF.md` section 4.
- It replaces steps 0 to 3 of `TRUNK_MIGRATION_PLAN.md` (written for trunk `fc89f9e5`). Steps 4 to 7 of that plan keep their intent and are renumbered at the end of this page.
- It follows the maintainer's answers of 2026-11-23 (`HANDOFF.md` section 5). Each answer was checked against the tree at `e5d0f36b` on 2026-11-24 (next section).
- Every step is one reviewable commit and stops for the owner's "continue" (`GOVERNANCE.md`). Every commit passes the check set in `HANDOFF.md` section 7.

## The maintainer's answers, checked against `e5d0f36b`

| Answer | Checked how | Holds |
|---|---|---|
| 1. Base is `e5d0f36b`; `af4c7c52` is an ancestor; Lean 4.36 | `git merge-base --is-ancestor`; `lean/lean-toolchain` is `v4.36.0` | Yes. But the Lean 4.36 re-pin is incomplete: see "Trunk defects" |
| 2. Decision answer is version 4, u64 reason masks, 20-byte records | `conformance/FRAME_V1.md` section 8, change record 2026-11-22; `tests/test_gate_answer_v4.py` exists | Yes |
| 3. A reason's bit is its number; leaf-only codes at 62 and 63; 24 to 28 are the eligibility reasons | Same change record: names 24 to 28, refuses 29 to 61 for now | Yes |
| 4. Eligibility is rule set v2 reading the fact store (source 7, aid table, ELIG node, `elRead`); not runnable yet | `conformance/RULESET_V2.md` sections 1 to 5; `RuleSet/Spec.lean` `elRead` (line 155), `runnable` (line 2426) and its `#guard`s refusing `v2` | Yes |
| 5. Eligibility does not go into `coreFires` | `pack1_fires` and `coreFires` are in `RuleSet/Spec.lean` and pinned in `AxiomCheck.lean` | Consistent; nothing to check further |
| Smaller: `GATE_RULES_V1` keeps its name; links tail has a 4-byte reasons field (`tailsOf`); section 19 rows designed, not built | `conformance/GATE_RULES_V1.md` exists, no V2; `tailsOf` in `Engine3/HLinks.lean`; `ENGINE_V3.md` section 19 | Yes |

## Baseline of the unmodified trunk on this machine

Machine: x64 Windows 11, Intel Core Ultra 7 165U (12 cores), 31.5 GiB. Clone at `C:\work\rightrail`, detached at `e5d0f36b`, no tracked change. Raw logs: `C:\work\rr-baseline-logs`. The trunk's resource guard is not on this machine, so runs were unguarded but measured.

| Run | Result | Wall | Peak memory |
|---|---|---|---|
| `lake build` (default targets) | **Fails**: 515 of 516 steps; `BlindLedger.Gate.AxiomCheck` has 17 stale axiom pins | 11 min 48 s | about 7 GiB summed; largest process 2.8 GiB |
| The 21 executable targets | Pass | 97 s | 15.8 GiB committed |
| Side projects (`tools/obligations_format`, `tools/sha3_bench`, provider app Lean on v4.33.1) | Pass | 81 s | 3.5 GiB |
| `python -m pytest`, first run (Python 3.12.10, only default targets built) | 1,800 passed, 366 failed, 61 errors, 17 skipped, 5 xfailed | 1 h 44 min | 4.1 GiB |
| Rerun of the 37 affected files with every program built and `E3_SCRATCH` set | 541 passed, 10 failed, 5 skipped | 39 min | 1.0 GiB |

What the 10 remaining failures were, and what settled each:

| Tests | Cause | Settled by |
|---|---|---|
| 4 SQLite tests (`test_history_growth`, two in the cash-file files, the `test_right_rail_gate_payer` query plan) | The trunk expects SQLite 3.53.1; python.org's 3.12.10 ships 3.49.1 and 3.14.4 ships 3.50.4 | Swapping sqlite.org's 3.53.1 DLL into a private Python 3.14.4: all 112 tests in the four files pass |
| `test_right_rail_gate_decide::test_a_torn_qb_holds_that_shard_only` | Trunk defect: assumes payment id `pay-0001`, which depends on test order. Passes under `unittest`, fails under `pytest` (the README's command) | Candidate fix: read the id from the request |
| `test_right_rail_financial_canonical_json` (deep nesting) | Trunk defect: expects 1,000-deep JSON to be refused. CPython 3.12 and 3.14 read it; 3.12 refuses from 5,000 deep, 3.14 from 20,000. The kit pins CPython 3.11.15, the SBOM names 3.14.4 | Candidate fix: test at 100,000 deep, which both refuse |
| `test_engine3_facts_scale` (timing ratio at most 3.0) | This laptop. Unpinned, the engine drifts onto slow cores (ratios 3.8 to 5.0). Pinned to fast cores it passes about one run in three (1.6 to 3.7): frame times are two or three 15.6 ms clock ticks, and the processor throttles | **Not settled.** Needs a steadier machine or the maintainer's word on the bound |

Fixed setup, full suite (`C:\work\rightrail-fixes`: trunk plus the candidate patch, Python 3.14.4, SQLite 3.53.1, every program built): 1,946 passed, 5 skipped, 5 xfailed; 1 h 34 min; 4.0 GiB peak. The failures (174 counting subtests, 3 errors) are in four files only:

| File | Failing | Why |
|---|---|---|
| `test_right_rail_mirror_interaction_model`, `test_right_rail_scorecard` | 35 tests | Browser tests; no Node.js or Playwright here |
| `test_semantic_assurance_gate` | 7 tests | They require a clean git tree, and this copy holds the uncommitted candidate patch. On the clean trunk clone with the same Python and SQLite all 23 tests in the file pass |
| `test_engine3_facts_scale` | 1 test | The timing bound, as above |

Not run: 166 browser tests (they need Node.js, Playwright 1.62.1 and a browser path; each is a download needing approval), the `provider_app` Python suite, `pytest parked`.

## Trunk defects to send to the maintainer

Owner, 2026-11-24: send the fixes as one pull request against `RightRail/rightrail`; the timing test goes in as a note, not a fix. The two test fixes are commit `8c7a3a65` on the local branch `fix/test-order-and-json-depth` in `C:\work\rightrail-fixes`, also saved as `C:\work\rr-baseline-logs\trunk_test_fixes.patch` (outside this repository because it is RightRail code and this repository is public). Not pushed: the GitHub account on this machine has read access only and the repository does not allow forks.

`rightrail-main` on GitHub was at `95066ed4` on 2026-11-24, 82 commits past `e5d0f36b`. It includes commits marked WIP and untested, so the base stays `e5d0f36b` (answer 1).

1. **17 axiom pins were not regenerated for Lean 4.36. Already fixed upstream** at `95066ed4` (the same 17 theorems), so it is not in the pull request. At `e5d0f36b`, `RuleSet` theorems (`evalC_eq`, `evalC_le`, `dataFires_core` and 14 more) are pinned `[propext]` or `[propext, Quot.sound]`; under v4.36.0 they also depend on `Classical.choice`. `AxiomCheck.lean` and `AXIOMS.txt` both need the 17 lines; with them `lake build` passes 516 of 516 (checked). The import in M1 will carry this red unless the 17 lines are taken as a recorded local change or the base moves to a commit that has them.
2. **Order-dependent test** in `tests/test_right_rail_gate_decide.py` (above).
3. **Interpreter-dependent test** in `tests/test_right_rail_financial_canonical_json.py` (above). Underneath it is a question: which Python and which SQLite build do the maintainers run? No stock python.org build has SQLite 3.53.1.
4. **Timing test resolution** in `tests/test_engine3_facts_scale.py`: `GetProcessTimes` ticks are as large as the times measured.

## Environment the move needs

- elan with Lean v4.36.0 (trunk) and v4.33.1 (provider app). Run `lake` from inside each project folder.
- Build the default targets, then the 21 executable targets, then the three side projects. About 15 minutes and 16 GiB peak in all.
- Python 3.14.4 with `sqlite3.dll` 3.53.1, pytest from the hash-pinned `requirements-dev.txt`. Set `E3_SCRATCH` to a scratch folder.
- The signer at `rust\gate_mldsa87\target\release\rr_gate_mldsa87.exe`, SHA-256 `a1a6e9e4...6141` (checked). No standing signing seed is needed; tests make throwaway ones.

## Decisions needed before step M1

Owner's answers, 2026-11-24: (1) hold: M1 stays local and none of RightRail's current code is pushed until the owner confirms with the maintainer or makes the repository private; (3) yes, on a new branch, never force-pushed, after the owner's go-ahead on a commit-by-commit list; (4) yes, as a pull request whose text the owner sees first. No Node.js or Playwright download: the browser tests are listed as not run.

1. **Visibility.** `coder-sys/localBCE` is public and `RightRail/rightrail` is private. Step M1 would push 769 files of current RightRail code. `HANDOFF.md` section 1 says to check the outcome first. This blocks every push below.
2. **Snapshot or history.** The history is now available from the private repository. Importing it into a public repository is the same visibility question; the default below is a snapshot, as on 2026-11-14.
3. **Dropping the superseded work.** M1 replaces `rightrail/` wholesale, which removes localBCE's 14 commits of changes there from the tree (they stay in git history). `HANDOFF.md` section 3 says backing them out needs the owner's word.
4. **Sending the trunk fixes upstream**, and by whom.
5. **Who builds the engine's eligibility read** (not yet asked of the founder).

## Steps

**M1. Import `e5d0f36b` as `rightrail/`.** New branch from `codex/rightrail-trunk-step3`. `git rm -r rightrail`, write the trunk tree byte for byte, `git add`. Repeat the one known local change (split the PEM header literal in `rightrail/tests/test_privacy_artifact_scan.py`, still unsplit on trunk, so localBCE's secret scanner passes). Rewrite `RIGHTRAIL_IMPORTED_FROM.md`. Expected: `git diff 'e5d0f36b^{tree}' HEAD:rightrail` shows only that one line.

**M2. Baseline in place.** Build and run the trunk suite inside `rightrail/` and the localBCE check set. Expected reds: the 17 axiom pins and the three test defects, unless the maintainer has fixed them or the owner accepts the candidate patch as a recorded local change. The seven reds accepted on the old base should be gone, since their pins are trunk's again. Log only.

**M3. Re-port what the answers keep.** One commit each, each with a green build and regenerated axiom pins:
- The signer-free decision-check harness (`a0da49e8`), retargeted to answer version 4.
- The six reason-bound proofs (`379b487c` to `845e7b9c`). They were proved for a cap of 32; trunk's rule reasons run to 61, and trunk has none of `payLines`, `PayNumbering` or `assemble_pay_lt`. Re-prove on trunk's numbering code, or drop any the wider masks make unnecessary; decide per proof after reading trunk's `Flat/DecideRows.lean` and `Engine3` files.
- The unbuilt lemma section of `bb50ba01`: re-prove with the numbering proofs or drop.
- Not carried: `19e001c7`, `9330572b` (trunk has the reasons), `c7ad3c65`, `bbd0e947`, `013a686c`'s vector change, `36fb3603`.

The commit-by-commit review (2026-11-24, awaiting the owner's go-ahead) changes two points above. The signer-free harness is not needed on a machine that has the signer. The reason-bound proofs are not needed while trunk has 29 fixed reasons against a cap of 32 (`maxReasonCodes`), and they do not port as written: they classify the fixed `Rules.fires`, and on trunk new reasons come from rule sets.

**M4. Outside `rightrail/`.** Retarget `scripts/elig_snapshot.py` from feed snapshots to fact records (read trunk's `conformance/ELIG_EXTRACT_V1.md` and the fact-record design first) or park it. Regenerate `G_RULE_PARITY_REPORT`.

**M5. Design, then draft, the new work.** An eligibility pack for rule set v2 (aid-code table and rules for reasons 24 to 28), checked through `ruleset_admit`. A draft of the links-file reasons widening, as a protected change with an XI.2 record, not merged without the founder's approval.

**M6. Mark the superseded documents** (`TRUNK_STEP2_FRAME_DESIGN.md`, `TRUNK_STEP3_G2_DESIGN.md`, `TRUNK_STEP3_ELIG_PRODUCER_DESIGN.md`, `TRUNK_MOVE_ASSESSMENT*.md`, steps 0 to 3 of `TRUNK_MIGRATION_PLAN.md`) with a pointer here.

Then, from the old plan: share of cost (old step 4), the remaining rules (old 5 and 6) and the live wiring (old 7).

## Blocked on the RightRail side

- The engine does not carry the eligibility read, so no rule set v2 pack can run (`runnable` is false).
- The ELIG fact has status and aid code only: no benefit level (localBCE's G2 tests one) and no share of cost (G4).
- Section 19 sorted rows are not built; six-feed frames wait for them.
- The links-file widening needs the founder's approval before rule sets can emit reasons 24 to 28.
