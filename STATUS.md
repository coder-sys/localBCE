# RightRail status

Updated: 2026-09-28. Current candidate: `codex/connected-workflows` at `618e81f`,
a clean tree apart from untracked guard scratch files. It is based on trunk
`6cccb84` and integrates `correction-v2`, G2 (dependency check), G4 (support
package v2), `deferral-pack` (B+ line pack) and `gate-rules-2`. Trunk has not
received this combination. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination.
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

- **Full suite:** `cwf-full-r1` on `618e81f`: run=475 passed=462 failed=1 (Markdown budget) skipped=12 (two gate-rules vector tests, symlink privilege, old accepted-engine artifact, no fresh engine handoff, 7 semantic-assurance tests that run only in the external gate). Gate-v1 round 8: `gate-r8-full-a1-L2` run=483 passed=473 failed=0 errors=0 skipped=10.
- **G2 dependency check** (`g2dep-r3-a1-L2`, 184/184): a correction follow-up reopens only when a derived dependency key moves (XI.2 record).
- **G4 support package v2** (XI.2 record): software version and Trust Graph profile are NONE (no bound source); Mirror refuses any other package shape.
- **Line pack (B+)**, documentation-only CMS-64.9 pack, built read-only from a fully verified store, quarters by owner-clock received time; a clock stepping back stops writes until it passes the last commit (XI.2 record). `bplus-fix5d` on `deferral-pack` 3656bf5: 221 run, 219 passed, 1 skipped, 1 failed (Markdown budget). Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: sound, complete, fail-closed, monotone, arrival-order deterministic; `allow_clear`, `later_allow_clear(_many)` and `allow_clear_store` proved over append-only sets checked against the checkpoint (stale reads give `STALE_*`/`*_UNVERIFIED` review; XI.2 records). 274/274 vectors, 3,616 demo lines; all 204 mutants killed (`gate-r8-rmut*`). Tests only, not the token path. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Gate formats #1-#4, #12 (gate-v1)**: CHECKPOINT/v1, TOKEN/v1 and the payer's twelve-check `verifyToken` (Lean `BlindLedger.Gate`); round 8 (XI.2 record): 232/232 golden vectors, 31 theorems on `propext`/`Quot.sound` only (`AXIOMS.txt`), 133/133 spec mutants killed. Stated, unproved (`sorry`): `Step.released_grows`, `Steps.coherent`, `Steps.at_most_once`, `installCert_equivocation`; rules `released_iff`, `one_payment_per_line`. **UNBUILT REQUIREMENTS** (target §4-§5): a checkpoint producer serialized per (tenant, shard), persisting before publishing, with a fork self-check; the payer pin written before send; KEY-CERT signing the shard count; the runtime verifier that priors hash to the anchored checkpoint `state_digest`. Offline payer verification is not claimed: ML-DSA-87 and the KEY-CERT chain are supplied inputs in Lean (`gate-r8-*` logs).
- **Engine, proof and kit** (XI.2 records; raw logs govern): the pinned engine was reproduced byte-identically from the 46-file source manifest `61a24519` (r77); six Lake targets built, 87 jobs (r68); 30 evaluator, 18 decision-package, 42 correction KATs and 210 + 3,616 gate-rule cases (r69); 18 correction declarations passed trust-zero, axiom-closure and `leanchecker` checks (r70); 21 verifier tests (r73). The 2,673-member kit assembled, verified, extracted and ran the correction/retry/SHADOW scenario (r80), serve/restart (r84, r88), packaged correction/cash restart (r85); clean checkout `e3fb69f` 24/24 (r89). The kit ran packaged source `707ba78`, not `86390ab`. 21 compile warnings and 30 fixed-vector native-axiom declarations remain; not an all-theorem axiom-hygiene claim. Later `lean/` edits (gate rules) void the engine pin under AGENTS.md until a guarded rebuild. **Retained failures (unresolved, logs kept):** r75 native-path sort order, r78 CRLF parsing, r81-r83 smoke-harness issues; r85's outer run failed only in its count-print command.
- **Receiver cash file**: 20/20 (r63); independent review found no source blocker; Acceptance/Mirror fixture equivalence 117/117 (r65).
- **Funding, clock, connectors, staff**: `cx-funding-r31-a1` 24/24; `cx-clock-contract-r32-a1` 72/72; `cx-clock-green-r15-a1` 30/30; `cx-connectors-final-r28-a1` 65/65; `cx-staff-r9-a1` 39/39; browser runs `cx-source-browser-r25-a1`, `cx-browser-r13-a1`, `cx-browser-clock-r16-a1`: success path only, no exhaustive error-state crawl. Switch (13) and Provider Trust Graph (12) run in the suite (`trunk-cv8-full-a1`, `ptg-full-a1`).
- Raw output: `native/guard/guarded-command-*.stdout.log`/`.stderr.log`; guard exits in `C:/Users/neers/rrb/logs/`. The runner's failing-subtest pass count is unreliable; raw unittest records govern. `git diff --check` passes; six historical CRLF whitespace warnings remain in `artifacts/engine-correction/vectors/run-vectors.cmd`.

## Connected behavior not in ARCHITECTURE.md

- Synthetic NC marker age uses a pinned logical-seconds-to-UTC mapping; contract v3/profile v5 reject old bindings, future instants and contradictory failures; date-only or absent markers stay UNKNOWN; FRESH means age at capture only.
- NC FHIR retries keep only the final attempt; invalid Retry-After is recorded with a matching empty delay slot; failure envelopes cannot enter graph admission; V2/V3 admission checks the observation window even with a source-contract digest.
- Only payments naming `pays_action_id` reduce a correction's unpaid amount; removing that link on a resend conflicts. The release producer pins CMD02/RES3 and independently derived RU02/RV02 vectors; the kit inventory includes `RETIRED_PINS`. Retired engines are verification-only; a missing or changed registry refuses verification.

## Artifact boundary

- Pinned correction engine `1A7A1833...D3AF`, 6,279,168 bytes; exact pins and construction in `artifacts/engine-correction/PROVENANCE.md`; no new binary pin or retired entry was needed.
- The offline kit archive binds its assembly tree, including frozen connector and browser candidates; these checks do not qualify those tracks. Lean builds need 4,029,372,048 free bytes to start, Python tests 2,200,000,000; both keep the 2,029,372,048-byte floor (guard v7; 955,630,224 lower while the owner's away file is valid).

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
