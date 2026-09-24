# RightRail status

Updated: 2026-09-24. This is the one current status file for the single codebase
`rightrail-main`. Code is still being copied in from the older checkouts.

Standing rules: see CONSTITUTION.md (supreme; every change must comply).

Older detailed status files are archived word for word in `docs/history/`
(see `docs/README-HISTORY.md`). Raw run logs live in
`work/pq-wide-seed-native-20260913/build-filter-native/`.

## What RightRail is

RightRail gives a state Medicaid agency one operating record for a consequential
responsibility that crosses plans, providers and contractors, starting with one
recurring financial responsibility such as a state-directed hospital payment program.
It keeps the approved rule, evidence, open disagreements, the official's decision and
the next action connected until the work is done, while existing processors and
payment systems keep moving the money. It is five parts on one small foundation
(Control Pack, Blind Ledger, Mirror, Continuity State, Switch): Lean decides each
consequential step and the Python owner commits it.

## Standing claims

Pre-state build phase (the plan; CONSTITUTION VI.4): synthetic data,
`proofSuiteId=null`, `production_usable=false`, `activation=false`.

## What actually runs today and was verified

Only items with a recorded passing guarded test run. "Evidence" is the archived file
in `docs/history/` that holds the raw record.

1. **Lean-controlled financial correction** (the plan's Hospital H $3,000 shortfall).
   2026-09-24: 9 of 9 selected tests passed (run r7; r1-r6 failed and were fixed).
   The owner rejects the disallowed offset and authorizes the correction only through
   the Lean transition inside one database transaction; crashes before and after commit
   and exact retries were checked. Caveat: the Lean program was built on 2026-09-23
   from an OLDER version of the Lean source; the current source has never been compiled.
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
2. **Engine correction program self-checks (older source).** 2026-09-23: correction
   gates 32 of 32, existing 30 gates, 38-theorem checker. Evidence:
   `lean-engine-20260913-STATE.md`.
3. **Continuity admission (v6/v7) and correction follow-up through Mirror.**
   2026-09-24: 11 of 11 passed (run r6; r3-r5 failed and were fixed).
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
4. **Private snapshot indexes** (fast per-obligation reads, safe migration).
   2026-09-24: 6 of 6 passed; no tested query still scans a whole table.
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
5. **Queue claim path (Python).** 2026-09-24: 29 of 29 focused tests passed. The last
   broader Queue run (122 tests) still has 1 failure and 5 errors. Earlier Lean/Rust
   admission integration (2026-09-19): 4 of 4. Evidence: `lean-queue-20260913-STATE.md`.
6. **Security Lean proof target** (opportunity-accounting reducer). 2026-09-24: build
   succeeded on run r7 (r1-r6 failed): 18 theorems with no `sorry`, 39 examples,
   30 style warnings. Local compile only, not an independent kernel check.
   Evidence: `lean-security-20260913-STATE.md`.
7. **v5 financial owner, checker, Mirror, CLI, Continuity.** Narrowly accepted after
   focused runs of 63 and 5 tests (about 2026-09-20, by log dates).
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
8. **Provider App pre-submission checker core.** 2026-09-23: 13 of 13 Python tests and
   one Lean compile. Its later Lean comparison extension never built successfully.
   Evidence: `rightrail-provider-app-20260923-STATE.md`.

## What is written but has never run

- **Offline service kit** (assemble, verify, run, serve; lost-response retry; SHADOW
  restore). 0 runs; archive never assembled; needs an Engine build receipt.
- **Switch** shadow replay module and CLI: 10 tests written, 0 run.
- **Staff server additions** (read bundle, envelope, browser checks): 3 test files skipped.
- **Engine current Lean source** (fixed-point proof, release producer script): never
  compiled. Which exact source built the existing program could not be recovered.
- **Queue source-bound lifecycle mode**: still closed; the program is on its old pin.
- **State BLSDRQ01 clearance route**: run r2 (2026-09-24) was 45 passed, 1 failing (a
  retry-conflict test got the wrong error type). Later fixes are unrun; the production
  pin is still pending. Evidence: `lean-state-20260913-STATE.md`.
- **Provider Trust Graph** read model and local browser view: 12 tests written, 0 run.
- **Qualification bundle**: 17 tests written, 0 run; 8 evidence slots empty.
- **Security calculator cleanup**: its 64-test module not rerun.

## Known blockers

1. **Engine must rebuild the current source.** The build needs about 4.2 GB free RAM
   at start (4,190,433,321 bytes). The machine has 16 GB (15.3 GB usable) and usually
   only about 1-1.6 GB free with current apps open (1.0 GB when this was written). The
   last two Engine guard starts also failed with "Access denied" before measuring
   memory. Until this build happens, the service kit cannot be assembled and Queue's
   source-bound mode stays closed.
2. **One heavy run at a time.** All builds and tests share one guarded lane.

## Parked

Private zero-knowledge / post-quantum proof research (`PRIVATE_ZK` evidence mode). Per the
2026-09-24 plan this mode is conditional (only if a state must verify a hidden,
source-bound fact) and is not on the critical path. The native work in
`pq-wide-seed-native-20260913` is frozen as history. Retired research history lives in
bundles under `work/_retired-research-20260924`.

## Next 5 concrete steps

1. **Run the service kit end-to-end**: assemble, verify, run the scenario, serve the
   staff app on loopback. Needs the build receipt from step 2.
2. **Fresh Engine build of the current source** under the guard: free about 4.2 GB
   first (close apps or reboot), keep the build receipt, rerun the 9 correction tests
   on the new program.
3. **Make `rightrail-main` the only place code changes**; old checkouts become read-only.
4. **Hospital-payment full cycle demo** per the plan: 20 hospitals, $1M, Hospital H
   short $3,000, with incomplete files, disputed offsets, late records, partial
   corrections, repeat messages, crash recovery and restore, all visible in Mirror.
5. **Second, nonfinancial workflow via the Provider Trust Graph**: run its 12 written
   tests, then expose it read-only through an authenticated staff route.

## Change log

- 2026-09-24 — Private-ZK / Profile 11-12 track moved to `parked/private_zk/` (96 files); default `pytest` run excludes it (`pytest parked` runs it). Dead `tools/direct_mask_*` duplicates removed (newer copies live in `native/tools/`). New constitution tests: `tests/test_right_rail_financial_constitution_invariants.py` (written, not yet run).
- 2026-09-24 — Audit fixes (Art. III.1, III.5, V.2, VI.1, XI.10, XI.13): checker now enforces actor roles against a digest-bound roster (the check never fired before); database verification requires trusted authority (no default-digest shortcut, no `authority_*` aliases); owner constructor backdoor removed; 11 `assert` safety checks replaced by typed errors; staff server measures cash/state before and after instead of hard-coding them, resume checks real integrity fields, import-order and owner-id bugs fixed. 4 new tests. Not yet run (RAM below floor). Still open: population staging writes no history event (III.2; needs successor-tool and test changes), synthetic authority fallback on the continuity-package path (needs Switch/CLI/Mirror API change), two staff tests that open a LIVE owner on a TEST database.
