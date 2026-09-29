# RightRail status

Updated: 2026-09-29. Branch `pq-m1` = trunk `7aff312` + PQ signing M1. Git state, raw guard
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

- **Full suite:** pending on the merged `pq-m1` tree. Touched modules `pqm1-t3` (gate formats, ACVP differential, bloat): 22 of 23; the prose budget failed and was then trimmed. Gate Lean build `pqm1-lean3`.
- **Lean-live M0** (`m0-full-r1` 463/475, 12 skipped): Lean decides the correction amount; the checker re-checks it before COMMIT.
- **G2 dependency check** (`g2dep-r3-a1-L2`, 184/184): a correction follow-up reopens only when a derived dependency key moves (XI.2 record).
- **G4 support package v2** (XI.2 record): software version and Trust Graph profile stay NONE.
- **Line pack (B+)** (documentation-only CMS-64.9 pack; XI.2 record): its tests run in the suite. Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Follow-through pack (M1)** (derived, documentation-only): its tests run in the suite.
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: sound, complete, fail-closed, monotone, arrival-order deterministic (stale reads give `STALE_*`/`*_UNVERIFIED` review; XI.2 records). 274/274 vectors, 3,616 demo lines; all 204 mutants killed (`gate-r8-rmut*`). Tests only, not the token path. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Gate formats #1-#4, #12 (gate-v1)**: CHECKPOINT/v1, TOKEN/v1 and the payer's twelve-check `verifyToken` (Lean `BlindLedger.Gate`); round 8 (XI.2 record): 252/252 golden vectors, judged with real ML-DSA-87 and KEY-CERT/v1; 36 theorems on `propext`/`Quot.sound` only (`AXIOMS.txt`); 133/133 spec mutants killed in round 8, not rerun on the KEY-CERT spec. The six LM1 statements are proved (no `sorry`): `Step.released_grows`, `Steps.coherent`, `Steps.at_most_once`, `installCert_equivocation`, rules `released_iff`, `one_payment_per_line`. **UNBUILT REQUIREMENTS** (target §4-§5): a checkpoint producer serialized per (tenant, shard), persisting before publishing, with a fork self-check; the payer pin written before send; the runtime verifier that priors hash to the anchored checkpoint `state_digest`. **PQ signing M1** (XI.2 record): KEY-CERT/v1 and every checkpoint signature are verified by the Lean `gate_verify` (`artifacts/gate-verify/`), checked against NIST ACVP (25 keyGen, 60 sigGen, 30 sigVer) and AWS-LC (4,936 mutated cases): vector-verified, not proved; payer product not built.
- **Engine, proof and kit** (runs r67-r89: `artifacts/engine-correction/PROVENANCE.md`, raw guard logs): reproduced source manifest, six-target Lake build, KAT and gate-rule cases, trust-zero/axiom-closure/`leanchecker` on 18 correction declarations, 2,673-member kit, clean checkout 24/24. 21 compile warnings and 30 fixed-vector native-axiom declarations remain; not an all-theorem axiom-hygiene claim. **Retained failures (unresolved, logs kept):** r75 native-path sort order, r78 CRLF parsing, r81-r83 smoke-harness issues; r85's outer run failed only in its count-print command.
- **Receiver cash file**: at most 500 rows a file, 6 per item. Quarter-end (twelfth file) writer lock alone, five runs (`cash1b-qeB1..5`): 3.32 to 3.75 s, median 3.43; fresh-owner apply 4.69 s (`cash1b-probe1`). It grows 0.36 s per earlier 500 payments (Phase 2); 1,000-row files stay out of reach. The review's fixes are unreviewed.
- **Funding, clock, connectors, staff**: 24/24, 72/72, 30/30, 65/65 and 39/39 in earlier guarded runs (`cx-*`); browser runs cover the success path only, no exhaustive error-state crawl (`cx-browser-clock-r16-a1`: its confirmation wait timed out; the next read showed the restore complete). Switch (13) and Provider Trust Graph (12) run in the suite (`trunk-cv8-full-a1`, `ptg-full-a1`).
- Raw output: `native/guard/guarded-command-*.stdout.log`/`.stderr.log`; guard exits in `C:/Users/neers/rrb/logs/`. The runner's failing-subtest pass count is unreliable; raw unittest records govern. `git diff --check` passes except six historical CRLF warnings in `run-vectors.cmd`.

## Connected behavior not in ARCHITECTURE.md

- Synthetic NC marker age, date-only markers and FRESH: the XI.2 capture-clock record in `docs/CORE_REDESIGN.md`.
- NC FHIR retries keep only the final attempt; invalid Retry-After is recorded with a matching empty delay slot; failure envelopes cannot enter graph admission; V2/V3 admission checks the observation window even with a source-contract digest.
- Only payments naming `pays_action_id` reduce a correction's unpaid amount; removing that link on a resend conflicts.

## Artifact boundary

- Pinned correction engine `1A7A1833...D3AF`, 6,279,168 bytes; exact pins and construction in `artifacts/engine-correction/PROVENANCE.md`; a guarded rebuild at `4efcb4b` (`engine-repin-r1-a1`) after the gate and M0 Lean edits reproduced it byte-for-byte; no new pin or retired entry.
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
- Historical unresolved runs, not current verification: Queue broad run 122 tests, 1 failure/5 errors; State clearance 45 pass/1 failure (under `parked/`); Security proof build, 30 style warnings. Qualification (17 tests, 8 empty evidence slots) and Security's 64-test cleanup need fresh evidence.

Next: connector/browser completion is paused at the founder's request; the browser crawl and final combined-source verification are outstanding. This candidate is a local commit, not a qualified release; no local check activates production.
