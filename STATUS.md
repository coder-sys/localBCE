# RightRail status

Updated: 2026-09-29. Trunk has cash file 1a and 1b and PQ signing M1 (gate checkpoints signed with ML-DSA-87). Git state, raw guard
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

- **Full suite** (`lqw-full1`, quick wins `a4b422e`): 547 run, 537 passed, 0 failed, 10 skipped. Gates: `lqw-l6f`, `lqw-real6`, `lqw-cpin`.
- **Paid-sum merge** (`lean-paid-sum` + trunk `eb37f1c`; `lpsm-full1`): 551 run, 537 passed, 4 failed, 10 skipped; two failures fixed (evidence ceiling, stale `gate_rules` build, `lpsm-t2`); open: prose over its ceiling by 3,436 bytes and the cash-file timing test. `gate_verify` pin unchanged (`lpsm-gva2`, `lpsm-gvb2`).
- **Lean-live M0** (`m0-full-r1` 463/475, 12 skipped): Lean decides the correction amount, deriving the paid-so-far from linked payments (`lean-paid-sum`); the checker re-checks it before COMMIT.
- **G2 dependency check** (`g2dep-r3-a1-L2`, 184/184): a correction follow-up reopens only when a derived dependency key moves (XI.2 record).
- **G4 support package v2** (XI.2 record): software version and Trust Graph profile stay NONE.
- **Line pack (B+)** (documentation-only CMS-64.9 pack; XI.2 record): its tests run in the suite. Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Follow-through pack (M1)** (derived, documentation-only): full suite on merge with `8883de9`, `recm1-merge-full-a1-L3` `SUMMARY run=511 passed=497 failed=0 errors=0 skipped=14`; skips include ML-DSA vector tests (no exe).
- **Follow-through decision (M2)** (XI.2 record; `m2-full-a4-L2` 511/525, 14 skipped): an official's ASSIGN or CLOSE is one protected event, checked before COMMIT; a close commits with no document (only the pack flags `gap:closure-evidence-missing`, yet shows CLOSED); it stops only the uncollected share.
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: sound, complete, fail-closed, monotone, arrival-order deterministic (stale reads give `STALE_*`/`*_UNVERIFIED` review; XI.2 records). 274/274 vectors, 3,616 demo lines; all 204 mutants killed (`gate-r8-rmut*`). Tests only, not the token path. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Gate formats #1-#4, #12 (gate-v1)**: CHECKPOINT/v1, TOKEN/v1 and the payer's twelve-check `verifyToken` (Lean `BlindLedger.Gate`; XI.2 records): 256/256 golden vectors judged with real ML-DSA-87; 36 theorems on `propext`/`Quot.sound` only (`AXIOMS.txt`); 133/133 mutants killed in round 8; the 4 equivocation mutants rerun on M1, 4/4 (`pqm1-mut1-a15`; `gate_mutants` edits the live `Spec.lean`). Six LM1 statements proved. **UNBUILT** (target §4-§5): the checkpoint producer, the payer pin before send, the prior-digest check. **PQ signing M1:** every checkpoint signature is verified by the Lean `gate_verify` (`artifacts/gate-verify/`) and the signer is checked against NIST ACVP (115 vectors) and AWS-LC (4,944 cases): vector-verified, not proved.
- **Engine, proof and kit** (runs r67-r89: `artifacts/engine-correction/PROVENANCE.md`, raw guard logs): reproduced source manifest, six-target Lake build, KAT and gate-rule cases, trust-zero/axiom-closure/`leanchecker` on 18 correction declarations, 2,673-member kit, clean checkout 24/24. 21 compile warnings and 30 fixed-vector native-axiom declarations remain; not an all-theorem axiom-hygiene claim. **Retained failures (unresolved, logs kept):** r75 native-path sort order, r78 CRLF parsing, r81-r83 smoke-harness issues; r85's outer run failed only in its count-print command.
- **Receiver cash file**: at most 500 rows a file, 6 per item. Quarter-end (twelfth file) writer lock alone, five runs (`cash1b-qeB1..5`): 3.32 to 3.75 s, median 3.43; fresh-owner apply 4.69 s (`cash1b-probe1`). It grows 0.36 s per earlier 500 payments (Phase 2); 1,000-row files stay out of reach. The review's fixes are unreviewed.
- **Funding, clock, connectors, staff**: 24/24, 72/72, 30/30, 65/65 and 39/39 in earlier guarded runs (`cx-*`); browser runs cover the success path only, no exhaustive error-state crawl (`cx-browser-clock-r16-a1`: its confirmation wait timed out; the next read showed the restore complete). Switch (13) and Provider Trust Graph (12) run in the suite (`trunk-cv8-full-a1`, `ptg-full-a1`).
- **Slim, on trunk `2ec89a0`**: Rust engine, oracle, gate-check hooks, guard copy, proof/privacy instruments out of product: 43,772 to 36,869 lines. `slim1-full-6`: 529 run, 0 failed, 14 skipped.
- Raw output: the guard host's `native/guard/guarded-command-*.stdout.log`/`.stderr.log`; guard exits in `C:/Users/neers/rrb/logs/`. The runner's failing-subtest pass count is unreliable; raw unittest records govern. `git diff --check` passes except six historical CRLF warnings in `artifacts/engine-correction/vectors/run-vectors.cmd`.

## Connected behavior not in ARCHITECTURE.md

- NC FHIR retries keep only the final attempt; invalid Retry-After is recorded with a matching empty delay slot; failure envelopes cannot enter graph admission; V2/V3 admission checks the observation window even with a source-contract digest.
- A resend that drops a payment's `pays_action_id` link conflicts.

## Artifact boundary

- Pinned correction engine `1A5821FA...DBBE`, 6,298,112 bytes (Lean derives each correction request's paid-so-far from linked payments; BLFCMD03; replaces `1A7A1833...D3AF`, now in `RETIRED_PINS`); exact pins and construction in `artifacts/engine-correction/PROVENANCE.md`; two byte-identical producer builds `engine-release-lpsb-a2`/`-a3`.
- The offline kit archive binds its assembly tree, including frozen connector and browser candidates; these checks do not qualify those tracks. Start floors are in `AGENTS.md`.

## Rules and unresolved work

- The NC capture path is synthetic file intake, no live transport. Financial file adapters (MCO reports, X12 820/835, MMIS extracts), shared provider/gate rules and payee-identity consumption remain unbuilt. Aggregate provider export has a read-model consistency consumer; keep it.
- Owner/Continuity v8 only; older stores fail without mutation, including trunk `6cccb84` or earlier (recreate the workspace). At most 10,000 events or rows per table.
- Complete the real-browser crawl of the declared interaction model; the Node model/scorecard is not one.
- Second synthetic state (G3) needs owner, checker and Lean changed together (`controlPackRulesWellFormed` pins H's labels), then a guarded rebuild; no partial change made. Conformance kit (G5): `conformance/`.
- A READY correction can go stale after later money events; cancel/reduce transitions and excess-request accounting remain to build. Reuse trusts the recorded input shortfall and ignores the paid list; no application calls it; a pin-transition event and stronger paid-list proofs are pending.
- The funding guard checks current projections only; full-store replay owns historical corruption.
- Whole-history checking was ~27 s at 10,000 rows (target 5 s). Lock contention may return `store_busy`. TEST restore through segmented history and a Lean seal codec remain unbuilt.
- OPEN RISK, cash-file open lock: a fresh CLI open verifies the whole store under the lock, 10.05 s at 6,000 payments (`cash1b-probe1`); journal mode is `delete`. Phase 2 / deployment-shape design: apply via the running owner, WAL with checkpoint-before-copy, incremental verify.
- OPEN RISK, concentrated history: 66 earlier payments per item lock a warm apply 7.11 s (`cash1b-probe1`); the test covers the spread shape only. Same design.
- Staff roles are UI-only; authentication, refusal logging and connection caps are absent. A replacement operator can restore and read but not take over work.
- Isolated TEST restore uses the system clock. The command log omits `pays_action_id`; the event chain carries it.
- No integrated payer gate; rule tests establish no durable token/release path. Gate failover TLC is a bounded model (3,516,192 states), not running failover; the deeper model, drill, CI and warm-worker throughput remain open.
- Core size targets are unmet: owner ~3,000 vs 7,243 lines, checker ~1,800 vs 5,225, total ~9,300.
- Historical unresolved runs, not current verification: Queue broad run 122 tests, 1 failure/5 errors; State clearance 45 pass/1 failure (under `parked/`); Security proof build, 30 style warnings. Qualification (17 tests, 8 empty evidence slots) and Security's 64-test cleanup need fresh evidence.

Next: connector/browser completion is paused at the founder's request; the browser crawl and final combined-source verification are outstanding. This candidate is a local commit, not a qualified release; no local check activates production.
