# RightRail status

Updated: 2026-09-29. Branch `cash-scale` = trunk `697bafd` (`connected-workflows` `618e81f`: correction-v2, G2,
G4, `deferral-pack`, `gate-rules-2`; docs `fc0fa3d`; Lean-live M0) + cash file 1a (`86ff3c9`) and 1b (trunk has neither). Git state, raw guard
logs and artifact provenance govern; a branch's pass does not verify another branch or their combination.
`CONSTITUTION.md` is supreme. Protected-change records (Art. XI.2) are in
`docs/CORE_REDESIGN.md`; how the code fits together is `ARCHITECTURE.md`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work,
official decisions and follow-through. Control Pack, Blind Ledger, Mirror,
Continuity and Switch share the financial owner; Provider App is separate.
The payment gate is one authority level within that product. Existing payment
systems move money. Synthetic, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`.

## Current verification (latest run per claim; raw logs are the record)

- **Full suite, 1b + lock speed-up + review fixes** (`cash1b-fix-full1-a1-L1`): `SUMMARY run=487 passed=475 failed=0 errors=0 skipped=12`, guard exit 0. Skips: two gate-rules vector tests (no `gate_rules.exe`), Windows symlink privilege, absent old engine artifact, no fresh evaluation-engine handoff, 7 external-gate semantic tests.
- **Lean-live M0** (`m0-full-r1` 463/475, 12 skipped): Lean decides the correction amount; the checker re-checks it before COMMIT. Its `lean/` edit also voids the engine pin until a guarded rebuild.
- **G2 dependency check** (`g2dep-r3-a1-L2`, 184/184): a correction follow-up reopens only when a derived dependency key moves (XI.2 record).
- **G4 support package v2** (XI.2 record): software version and Trust Graph profile are NONE (no bound source); Mirror refuses any other package shape.
- **Line pack (B+)**, documentation-only CMS-64.9 pack, built read-only from a fully verified store, quarters by owner-clock received time; a clock stepping back stops writes until it passes the last commit (XI.2 record). Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: proved sound, complete, fail-closed, monotone and arrival-order deterministic; stale reads give `STALE_*`/`*_UNVERIFIED` review (XI.2 record). 242/242 vectors, all 194 mutants killed (`gr2-mut-r3/r4a/r4b`, gate-rules-2 84c2016). Tests only, not the token path: signed checkpoints (gate-v1) and release path remain unbuilt. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Engine, proof and kit**: source-manifest reproduction and Lake build are in the XI.2 record; 30 evaluator, 18 decision-package, 42 correction KATs and 210 + 3,616 gate-rule cases (r69); 18 correction declarations passed trust-zero, axiom-closure and `leanchecker` checks (r70); 21 verifier tests (r73). Kit: 2,673-member archive run through the correction/retry/SHADOW scenario (r80); serve/restart (r84, r88); correction/cash restart (r85); clean checkout `e3fb69f` 24/24 (r89). 21 compile warnings and 30 fixed-vector native-axiom declarations remain; not an all-theorem axiom-hygiene claim. Later edits under `lean/` (gate rules) void the engine pin under AGENTS.md until a guarded rebuild. **Retained failures (unresolved, logs kept):** r75 native-path sort order, r78 CRLF parsing, r81-r83 smoke-harness issues; r85's outer run failed only in its count-print command.
- **Receiver cash file (1a `86ff3c9`, 1b)**: at most 500 rows a file, 6 per item; baseline B is the history-export manifest (XI.2 record), so a month is four files and a 6,000-payment quarter twelve. Quarter-end (twelfth 500-row file) writer lock alone, five runs (`cash1b-qeB1..5`): 3.32 to 3.75 s, median 3.43. Two speed-ups (one evidence read per payment; column-indexed checker rows) changed no rule, stored format or digest. The lock still grows about 0.36 s per earlier 500 payments (each payment re-binds its item's earlier evidence; design Phase 2). 1,000-row files stay out of reach. Fresh-owner apply 4.69 s (`cash1b-probe1`). The review's fixes are unreviewed; a `local_ref` version prefix is declined (XI.2 record).
- **Funding, clock, connectors, staff**: 24/24, 72/72, 30/30, 65/65 and 39/39 in earlier guarded runs (`cx-*`); browser runs cover the success path only, no exhaustive error-state crawl (`cx-browser-clock-r16-a1`: its confirmation wait timed out; the next read showed the restore complete). Switch (13) and Provider Trust Graph (12) run in the suite.
- Raw output: `native/guard/guarded-command-*.stdout.log`/`.stderr.log`; guard exits in `C:/Users/neers/rrb/logs/`. The runner's failing-subtest pass count is unreliable; raw unittest records govern. `git diff --check` passes; six historical CRLF whitespace warnings remain in `artifacts/engine-correction/vectors/run-vectors.cmd`.

## Connected behavior not in ARCHITECTURE.md

- Synthetic NC marker age uses a pinned logical-seconds-to-UTC mapping; contract v3/profile v5 reject old bindings, future instants and contradictory failures; date-only or absent markers stay UNKNOWN; FRESH means age at capture only.
- NC FHIR retries keep only the final attempt; invalid Retry-After is recorded with a matching empty delay slot; failure envelopes cannot enter graph admission; V2/V3 admission checks the observation window even with a source-contract digest.
- Only payments naming `pays_action_id` reduce a correction's unpaid amount; removing that link on a resend conflicts.

## Artifact boundary

- Pinned correction engine `1A7A1833...D3AF`, 6,279,168 bytes; exact pins and construction in `artifacts/engine-correction/PROVENANCE.md`; no new binary pin or retired entry was needed.
- The offline kit archive binds its assembly tree, including frozen connector and browser candidates; these checks do not qualify those tracks. Start floors are in `AGENTS.md`.

## Rules and unresolved work

- The NC capture path is synthetic file intake, no live transport. Financial file adapters (MCO reports, X12 820/835, MMIS extracts), shared provider/gate rules and payee-identity consumption remain unbuilt. Aggregate provider export has a read-model consistency consumer; keep it.
- Owner/Continuity v8 only; older stores fail without mutation, including stores written on trunk `6cccb84` or earlier (recreate the synthetic workspace). At most 10,000 events or rows per table.
- Complete the real-browser crawl of the declared interaction model; the Node model/scorecard is not one.
- Second synthetic state (G3) needs owner, checker and Lean changed together (`controlPackRulesWellFormed` pins H's labels), then a guarded rebuild; no partial change made. Conformance kit (G5): `conformance/`.
- A READY correction can go stale after later money events; cancel/reduce transitions and excess-request accounting remain to build. Reuse trusts the recorded input shortfall and ignores the paid list; no application calls it; a pin-transition event and stronger paid-list proofs are pending.
- The funding guard checks current projections only; full-store replay owns historical corruption.
- Whole-history checking was ~27 s at 10,000 rows (target 5 s). Lock contention may return `store_busy`. TEST restore through segmented history and a Lean seal codec remain unbuilt.
- OPEN RISK, cash-file open lock: a fresh CLI open verifies the whole store under the lock, 10.05 s at 6,000 payments (`cash1b-probe1`); journal mode is `delete`. Phase 2 / deployment-shape design: apply via the running owner, WAL with checkpoint-before-copy, incremental verify.
- OPEN RISK, concentrated history: 66 earlier payments per item lock a warm apply 7.11 s (`cash1b-probe1`), over 5 s; the test covers the spread shape only. Same design.
- Staff roles are UI-only; authentication, refusal logging and connection caps are absent. A replacement operator can restore and read but not take over work.
- Isolated TEST restore uses the system clock. The command log omits `pays_action_id`; the event chain carries it.
- No integrated payer gate; rule tests establish no durable token/release path. Gate failover TLC is a bounded model (3,516,192 states), not running failover; the deeper model, drill, CI and warm-worker throughput remain open.
- Historical unresolved runs, not current verification: Queue broad run 122 tests, 1 failure/5 errors; State clearance 45 pass/1 failure (under `parked/`); Security proof build, 30 style warnings. Qualification (17 tests, 8 empty evidence slots) and Security's 64-test cleanup need fresh evidence.

Next: connector/browser completion is paused at the founder's request; the browser crawl and final combined-source verification are outstanding. This candidate is a local commit, not a qualified release; no local check activates production.
