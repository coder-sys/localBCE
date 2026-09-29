# RightRail status

Updated: 2026-09-29. Trunk `bbd6b71` = `connected-workflows` (`618e81f`: correction-v2, G2,
G4, `deferral-pack`, `gate-rules-2`) + docs `fc0fa3d` + Lean-live M0, merged into branch `cash-scale` with cash file 1a (`86ff3c9`; trunk does not have it). Git state, raw guard
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

- **Full suite**: pending (fix round).
- **Lean-live M0** (`m0-full-r1` 463/475, 12 skipped): Lean decides the correction amount; the checker re-checks it before COMMIT. Its `lean/` edit also voids the engine pin until a guarded rebuild.
- **G2 dependency check** (`g2dep-r3-a1-L2`, 184/184): a correction follow-up reopens only when a derived dependency key moves (XI.2 record).
- **G4 support package v2** (XI.2 record): software version and Trust Graph profile are NONE (no bound source); Mirror refuses any other package shape.
- **Line pack (B+)**, documentation-only CMS-64.9 pack, built read-only from a fully verified store, quarters by owner-clock received time; a clock stepping back stops writes until it passes the last commit (XI.2 record). Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: proved sound, complete, fail-closed, monotone and arrival-order deterministic; stale reads give `STALE_*`/`*_UNVERIFIED` review (XI.2 record). 242/242 vectors, all 194 mutants killed (`gr2-mut-r3/r4a/r4b`, gate-rules-2 84c2016). Tests only, not the token path: signed checkpoints (gate-v1) and release path remain unbuilt. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Engine, proof and kit**: source-manifest reproduction and Lake build are in the XI.2 record; 30 evaluator, 18 decision-package, 42 correction KATs and 210 + 3,616 gate-rule cases (r69); 18 correction declarations passed trust-zero, axiom-closure and `leanchecker` checks (r70); 21 verifier tests (r73). Kit: 2,673-member archive assembled, verified, extracted and run through the correction/retry/SHADOW scenario (r80); serve/restart (r84, r88); packaged correction/cash restart (r85); clean checkout `e3fb69f` 24/24 (r89). 21 compile warnings and 30 fixed-vector native-axiom declarations remain; not an all-theorem axiom-hygiene claim. Later edits under `lean/` (gate rules) void the engine pin under AGENTS.md until a guarded rebuild. **Retained failures (unresolved, logs kept):** r75 native-path sort order, r78 CRLF parsing, r81-r83 smoke-harness issues; r85's outer run failed only in its count-print command.
- **Receiver cash file (1a, `86ff3c9`)**: at most 500 rows a file, 6 per item (`cash_file_row_cap`); a 1,000-row file locked the writer 4.95 s as the sixth file on 5,000 earlier payments (limit 4.5 s). At 500 (scratch harness `cash1a-m4`/`m5`): first file 1.1 s, eleventh 4.26 s concentrated, open verify 9.5 s at 5,500 events, store 139 MB; committed timing test 1.3 s spread, 1.2 s concentrated (`cash1a-t3`). The 8 MiB package cap (`MAX_PACKAGE_BYTES`) on the baseline also binds: rr-review found the third 500-row file on a 600-item store reaches it (not re-measured). Phase 1b (manifest baseline) is not started. Overlap (a repeat recorded as DUPLICATE) applies only when repeated rows carry new ids; a row that keeps stored ids must be the exact stored row or the whole file refuses. rr-review fixes (2026-09-29, record in `docs/CORE_REDESIGN.md`): pre-COMMIT now runs the checker's action and evidence-digest rules on the touched rows; a cash file's repeat of a reversed payment refuses (the owner's direct command still labels it DUPLICATE: open decision). Not re-reviewed. The earlier 20/20 (r63) and Acceptance/Mirror 117/117 (r65) predate `d5853b1` and are withdrawn.
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
- Staff roles are UI-only; authentication, refusal logging and connection caps are absent. A replacement operator can restore and read but not take over work.
- Isolated TEST restore uses the system clock. The command log omits `pays_action_id`; the event chain carries it.
- No integrated payer gate; rule tests establish no durable token/release path. Gate failover TLC is a bounded model (3,516,192 states), not running failover; the deeper model, drill, CI and warm-worker throughput remain open.
- Historical unresolved runs, not current verification: Queue broad run 122 tests, 1 failure/5 errors; State clearance 45 pass/1 failure (under `parked/`); Security proof build, 30 style warnings. Qualification (17 tests, 8 empty evidence slots) and Security's 64-test cleanup need fresh evidence.

Next: connector/browser completion is paused at the founder's request; the browser crawl and final combined-source verification are outstanding. This candidate is a local commit, not a qualified release; no local check activates production.
