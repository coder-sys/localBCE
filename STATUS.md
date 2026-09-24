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
- 2026-09-24 — Audit fixes (Art. III.1, III.5, V.2, VI.1, XI.10, XI.13): checker now enforces actor roles against a digest-bound roster (the check never fired before); database verification requires trusted authority (no default-digest shortcut, no `authority_*` aliases); owner constructor backdoor removed; 11 `assert` safety checks replaced by typed errors; staff server measures cash/state before and after instead of hard-coding them, resume checks real integrity fields, import-order and owner-id bugs fixed. 4 new tests. Not yet run (RAM below floor).
- 2026-09-24 — Gate/packager cleanup (Art. IX.1-2, X.1, XI.2, XI.6): removed 23 files, about 8,600 lines, none imported by the live path (recoverable from git history). Gates removed, per XI.2: `ops_authority` (SHA3 pins over `ops/` Markdown; protected doc bytes, not a product invariant); `documentation_governance` (Markdown registry/link gate; paperwork); `project_acceptance` (acceptance across nine old per-team checkouts; obsolete in one trunk); `qualification_gate` v2 and v3 (evaluated `ops/launch_blockers.json` and evidence packets for activation; nothing live consults them, and the owner, service kit and staff server hard-code `production_usable=false` and `activation=false`); `test_security_freeze_spec` and `test_active_core_contract` (document wording, and guards against importing modules that do not exist here, which would fail anyway). Duplicate packagers `deployment_bundle`, `build_release_archive` and `release_manifest_gate` removed: the service kit is the one packager, with its own digest-bound manifest and engine build receipt. This withdraws the "Qualification bundle" item above (17 tests, 8 evidence slots): replaced by the service kit, not qualified. Dead `tests/conftest.py` removed (it set `BL_DEV` and `BL_ALLOW_LOCAL_TEST_ORACLE_KEYS`, which nothing reads). Kept: the privacy artifact scanner (Art. IV), the semantic assurance gate (independent Lean proof check, but still pinned to the old engine checkout commit and needs re-pinning to the trunk), the offline hash-locked dependency installer and its attack tests, and the native_v3 parser tests (the kernel binding imports that code). Engine test's absolute engine path is now repo-relative with an env override; the pinned 398E... `blind_financial.exe` was not found anywhere under `work/`, so that test fails until the binary is restored or the pin is changed openly. No claims gained; nothing was run.
- 2026-09-24 — Mirror cleanup (Art. IX.1-2, IX.4, X.3, XI.2, XI.6): `app/mirror` cut from 32 to 11 modules (about 25,100 lines removed incl. tests; recoverable from git history). Kept = import closure of `tools/provider_trust_graph_view.py` plus the NC FHIR source producer/verifier that feeds it (graph, export, read model, source admission, each producer with its `_independent` checker). Deleted, superseded by the live financial Mirror and with no importer outside themselves and their tests: Mirror v2 core/ingress/recovery, external corrective/governance/privacy-support approval, profile governance, qualification checker, operational owner, writer authority, restore publication, and 7 test files. Removed checks and why redundant (XI.2): their tests guarded v2 database/event-chain integrity, single-writer leases, restore/recovery sequencing and external-approval binding for a Mirror that nothing runs; the live financial Mirror has its own tests; no kept code calls them. The observation-based export path (`build_observation_export`) and its 3 tests (sanitized-observation/receipt rejection) went with it: its only caller was the deleted operational owner; the graph-based export and all its tests stay. The ingress-binding test in `test_mirror_state_source_contract.py` (admission output accepted by v6 ingress) was removed with ingress; all other source-admission tests stay. Unused, untested `build_support_evidence`/`verify_support_evidence` removed. NC Medicaid directory v1 pair parked in `parked/mirror_legacy/` (`pytest parked`). Read model and view now share one bounded selection loader. Only `py_compile` and an import check were run; tests not rerun (RAM below floor).
- 2026-09-24 — Docs cleanup (Art. IX.1, X.1, VI.4): living Markdown cut from 26 files / 249 KB to 14 files / 105 KB (58 KB of that is the target). Root `CURRENT_TASK.md`/`STATE.md` (2026-09-20 financial copies) archived verbatim in `docs/history/`; `provider_app/STATE.md`, `provider_app/AGENTS.md` deleted (already archived byte-identical). Roadmap, Lean kernel, Mirror, dependency-locking, rejected-architecture, provider backlog and five `ops/` docs deleted, their still-true content merged into `README.md`, `ARCHITECTURE.md` (rewritten as current truth) and the target; `NATIVE_V3_ARCHITECTURE.md`/`DATABASE_ZK_ARCHITECTURE.md` moved to `parked/private_zk/docs/`; six `native/tools/*/README.md` merged into `native/tools/README.md`. `docs/RIGHTRAIL_FULL_STACK_TARGET.md`, cited by the constitution but missing here, imported from the financial checkout with its status sentences removed. Nothing run.
- 2026-09-24 — Code still pointing at missing docs (not edited): `tools/right_rail_financial_service_kit.py` `STATE_FILES` lists `docs/FINANCIAL_SERVICE_KIT.md` and `docs/FINANCIAL_STAFF_WORKSPACE_ARCHITECTURE.md`, which were never in the trunk, so kit assembly cannot find them; `ops/launch_blockers.json` and `ops/verifier_artifact_pin.example.json` now have no consumer; `lean/engine/BlindLedger` and `lean/state/BlindLedger` carry divergent copies of the same modules (IX.1).
- 2026-09-24 — Closed the three open audit items (Art. III.2, V.2, V.4, XI.10). (A) `stage_population` now appends a `POPULATION_IMPORT_OPENED` event in the same transaction that creates the staged import row and manifest binding (payload: population id, SHA3 staging digest of the row's immutable columns under new domain `RR/FINANCIAL/POPULATION-STAGING/v1`, manifest fields); the checker and `tools/continuity_successor_v7.py` require it exactly once and first for every v7 population and reject it on v5/v6. Test expectations changed only where the new event appears (3 event-kind lists, one sequence 4->5). (B) No default authority anywhere: checker's continuity-package fallback and manifest-approver roster fallback removed (and the unused `ExpectedFinancialIdentity` default); `FinancialMirror.validate_continuity_package` now takes caller `trusted_authority` + `expected_scope` (new `validate_owner_continuity_package` for the Owner's own); Switch entry points and the CLI take trusted authority/scope, CLI via a required `--authority-file` (fails closed with `trusted_authority_missing`). The Switch previously always failed (`identity:scope-required`). (C) Two staff tests now open their second writer with the database's real TEST mode/owner id. 6 new tests. Nothing run (RAM below floor); only `py_compile`.
- 2026-09-24 — Parked native tools (Art. IX.4, X.2, X.3): 9 `native/tools/direct_mask_*` dirs plus the tools README (63 files, about 19,590 lines) moved by pure rename to `parked/private_zk/native/tools/`. `native/tools/direct_mask_fixture/` (10 files) stays: the protected guard refuses every mode, including live `Command`, without it (line 56). Its `Configure`/`Build`/`CTest` lanes serve only the parked fixture and now point at moved `tools\direct_mask_vole`/`direct_mask_pipeline`, so they fail closed; guard not edited.
- 2026-09-24 — Deleted with no reader (X.3, recoverable from git): `ops/launch_blockers.json`, `ops/verifier_artifact_pin.example.json`, `docs/security-freeze/BL-PQ512-v1/hardening.json` (rejected STARK-era layout, not the parked track). Kept `docs/SBOM.python.spdx.json`: current (6 dev packages) and reconciled against the locks by `tests/test_locked_python_dependencies.py`. `ARCHITECTURE.md` still cites `native/tools/README.md` (now under `parked/private_zk/native/tools/`).
- 2026-09-24 — Engine adapter collapse (Art. V.2, IX.2, IX.4, XI.5-XI.7): the correction request now passes owner → snapshot (DB verified once by the independent checker) → BLFCMD01 encode → one pinned contained launch → strict BLFCRES1 decode, with no layer re-checking the one before it. `right_rail_financial_engine.py` 1,849→1,592 lines, `right_rail_financial_semantic_adapter.py` 2,459→2,207: one release validator, one launch helper, no path pre-hash on the correction lane, no Python projection rule or digest re-verification duplicating the independent checker, dead snapshot round-trip API removed. Executable hashed once per call instead of three times: containment keeps the hash through the write-denying pinned handle and file-ID binding of the reopen; no cross-call mtime cache (mtime is settable, so it would weaken the pin). Wire formats, pins, digest domains and asserted codes unchanged; old/new encoder, decoder and snapshot builder compared byte-for-byte in-process (real E911 result vector plus 5,500 mutations, 0 differences); tests not run (RAM). State BLSDRQ01 clearance route, `governance_authority_v2`, `experiments/` and their tests parked in `parked/state_clearance/` (78 files, 14,288 Python lines, 30,623 lines with evidence data; nothing in the financial product imported them). Still open (V.2): `validate_correction_result_input` recomputes the correction's post-state projection in Python and the adapter recomputes `completion_at_ms`; both are pre-commit checks the owner relies on, and removing them needs the owner to run the independent checker before COMMIT.
