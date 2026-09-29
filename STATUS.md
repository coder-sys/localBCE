# RightRail status

Updated: 2026-09-28. Current candidate: `codex/connected-workflows`, based on
main `6cccb84`, integrating `correction-v2` (`70f87c7`) in local development
commit `595e611`, followed by funding/source-clock fixes in `2c61ae8` and
test-setup consolidation in `e026658`. Main has not received this combination.
Git state, raw guard logs and artifact provenance govern; a branch's pass does
not verify another branch or their combination. `CONSTITUTION.md` is supreme.
Connector/browser source and fixture consolidation remain uncommitted working
changes while the separate Lean build/kit increment is committed.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work,
official decisions and follow-through. Control Pack, Blind Ledger, Mirror,
Continuity and Switch share the financial owner; Provider App is separate.
The payment gate is one authority level within that product. Existing payment
systems move money. Synthetic, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`.

## Current verification (latest state; earlier superseded runs collapsed)

- **G2 dependency check** (`dep-check`): correction follow-up reopens only when a derived dependency key moves, named in `changed_dependencies` (XI.2 record in `docs/CORE_REDESIGN.md`). Acknowledgments, the correction's own requested payment and DUPLICATE confirmations do not reopen; new evidence does; an unexplained cancellation needs review. The checker refuses a forged DUPLICATE label (`duplicate-evidence:binding`). Guarded `g2dep-r3-a1-L2` (v6): run=184 passed=184, zero floor kills. On the merged line `int-g2-r2-a1-L1`: 176/177, the only failure the Markdown budget fixed by this merge.
- **G4 support package v2** (XI.2 record in `docs/CORE_REDESIGN.md`): `CORPORATE-SUPPORT/v2` carries rule version (the pack the correction was decided under), adapter versions, `work_ref_count` (0 or 1, no ids) and a vector reproduction (pinned engine only); software version and Trust Graph profile are NONE (no bound source). A failed Continuity restore is the second consumer: its package rides the raised error and the staff `restore-test` 409, with `error_class` from the closed `CONTINUITY_ERROR_CODES` or UNCLASSIFIED. Mirror refuses any other shape, extra keys included; tests run the privacy scan on the follow-up and restore packages and require only its unapproved-schema notice. Guarded run: see the commit message.
- **Line pack (B+)**, documentation-only CMS-64.9 pack: builds only from a store
  that verify_database has fully verified (read-only), with the package as its
  exact snapshot; quarters go by owner-clock received time, so a backdated
  payment or reversal leaves a closed quarter's rows unchanged, and reads
  only what was recorded before quarter end. The Owner reads its clock once
  per command and refuses a future decision time (Lean needs the same guard);
  a host clock stepping back stops every write (`event_commit_order`) until it
  passes the last commit time, never reordering history; the checker binds
  each evidence received time to its event's commit time and requires commit
  times in order, for the database and the package. Guarded bplus-fix5d on `deferral-pack` 3656bf5: 221 run, 219 passed, 1 skipped, 1 failed (Markdown budget, fixed on this line). Kill criterion 1 holds (19A 32,345 of 32,345, FULL).
- **Gate decision rules R1-R5 (Lean, `BlindLedger.Gate.Rules`)**: sound, complete, fail-closed, monotone, arrival-order deterministic; `allow_clear`, `allowed_decideAll`, `later_allow_clear(_many)` and `allow_clear_store` proved over append-only sets checked against the gate's checkpoint (stale reads give `STALE_*`/`*_UNVERIFIED` review, never a HOLD on unusable data). 242/242 vectors and 3,616 demo lines; the unittest fails if the runner is older than its sources. All 194 mutants killed (gate-rules-2 84c2016, gr2-mut-r3/r4a/r4b). Tests only, not the token path: signed checkpoints (gate-v1) and the release path remain unbuilt. Open Low: a CAP copy of a loose row gets no reason code; the unchained path is O(n*m).
- **Lean build/proof/kit**: r77 freshly reproduced the pinned engine from a
 canonical 46-file source manifest, both fixed vectors matched. r68 built all
 six Lake targets (87 jobs); r69 passed 30 evaluator, 18 decision-package, 42
 correction KATs and 210 + 3,616 gate-rule cases; r70 passed the formal
 gate's 18 selected correction declarations (fresh trust-zero checks,
 approved axiom closures, independent leanchecker, 42 KATs). Each guard/child
 exited zero with cleanup PASS. 21 compile
 warnings and 30 fixed-vector native-axiom declarations remain visible; not
 an all-theorem axiom-hygiene claim. All 21 verifier tests now pass (r73,
 after fixing two Windows cp1252 output errors from r72 via
 `PYTHONIOENCODING=utf-8:strict`; output encoding only, no gate/source
 change). r79 passed 24/24 kit, size and protected-invariant tests. r80
 assembled/verified/extracted the 2,673-member offline kit and its bundled
 correction/retry/SHADOW scenario. r84 passed kit serve and restart,
 retaining owner/epoch/sequence/history with an empty engine workspace.
 Retained failures (unresolved): r75 native-path sort order, r78 CRLF
 parsing, r81-r83 smoke-harness issues. r85 passed the packaged durable
 correction/cash restart test (1/1) and all six final size gates; its outer
 run failed only in the subsequent count-print command (unmatched
 parenthesis) — the failed outer result remains recorded. Current clean
 handoff: r88 freshly extracted the unchanged archive and passed both
 serve/restart cycles with stricter harness cleanup (superseding r86's
 stale bytecode refusal; corrected count-only r87 passed 78,975/80,000 code
 lines). Those kit runs packaged source committed as `707ba78`
 (then uncommitted), not `86390ab`; the engine module differs by an equal
 derived map (PROVENANCE). Clean checkout `e3fb69f` passed all 24
 kit/size/protected-invariant checks in r89 (19.393 s, zero
 failures/errors/skips, child/guard exit 0, cleanup PASS); its Lean tree is
 unchanged from the fresh build and formal proof evidence. Connector/browser
 work remains paused.
- **Receiver cash-file increment**: 20/20 new checks pass in guarded r63
 (isolated preview, independent pre/post replay, whole-file rollback, exact
 retries after reversal, concurrency, process crashes, CLI setup refusing
 mutation); independent money/storage review found no remaining source
 blocker. Grouped run: 75/77 passed, one total-size failure (since resolved:
 founder expanded the ceiling to 80,000, all six size gates pass in r79;
 2026-09-28 split into product 44,000 and tests+Lean 40,000 lines),
 one fresh-evaluation-engine skip (resolved in r74), no errors, cleanup
 PASS. Acceptance/Mirror fixture equivalence: 117/117 in r65, zero
 skips/errors, cleanup PASS.
- Fixture consolidation removed 148 lines without removing test methods or
 assertions (r66/r67 regression and fresh build passed; failed attempt r64
 preserved as log/stage). The real Edge bridge and response model
 corrections are written; exhaustive browser execution is pending.
 Process/Engine/Mirror test setup consolidation
 removed 131 further lines, retaining all 75 test methods, 440
 `self.assert` calls and the Mirror mock-call assertion; static review found
 no blocker.
- **Grouped regression aggregate** (ten groups, not one uninterrupted
 full-suite run): 420 unique tests, 409 passed, 11 skipped, zero
 failures/errors, no duplicate/missing/unknown IDs. Component runs: r40
 81 (79 passed/2 skipped); r42/r43 95/95 acceptance; r44 89 (88/1 skipped);
 r54 50 (42/8 skipped); r55/r56 17/17 owner batch; r57 48/48 storage,
 independent checker, protected invariants, Switch CLI; r58 24/24 staff;
 r59 16/16 interaction model/scorecard. Each guard/grouped command exited 0,
 cleanup PASS; all six size gates passed in r40; r41's 420-ID inventory
 matches the completed logs.
- The 11 skips: Windows symlink privilege (1, unverified), absent old
 accepted-engine artifact (1, unverified), unbuilt gate runner (1, covered
 by r69 vectors), no fresh evaluation-engine handoff (1, resolved r74), 7
 real semantic-assurance mutation checks needing a configured external
 candidate (resolved r72/r73; r69 separately ran all gate-rule vectors). The
 interaction-model crawl is not the constitution's exhaustive real-browser
 crawl.
- r33, r34, r37, r39, r45, r48: guard memory-floor or preflight-minimum
 stops, no full-suite verdict; contribute no tests to the aggregate above
 (e.g. r34: 226 passes before floor stop); superseded by the completed
 groups r40-r59. r35 completed a full run: 408/420 passed, 1 error, since
 fixed by explicit fixture-class dispatch; r36 reproduced the failure. r38
 (`cx-preconsolidation-r38-a1`) passed 8/8. `cx-funding-r31-a1` passed
 24/24. `cx-clock-contract-r32-a1` passed 72/72 (independent source review,
 no blocker). All 155 remaining tests after r45/r48 completed in r54-r59.
- Independent funding review found a nullable receipt-ID successor missed by
 the local join predicate (reproduced r36, fixed by testing `child.rowid`,
 confirmed passing r37).
- Prior focused runs, all passing with no unresolved findings: connector
 increment `cx-connectors-final-r28-a1` (65/65); real source-file browser
 run `cx-source-browser-r25-a1` (SINGLE/COMPARE, navigation, findings,
 empty discrepancies, right selection, no console warnings, min free memory
 2,961,432,576 B — first launch r24 failed on working-directory import,
 fixed by explicit repository setup); staff/package/budget
 `cx-staff-r9-a1` (39/39, includes the correction lost-response/SHADOW
 scenario and reuse baseline); clock fix `cx-clock-green-r15-a1` (30/30,
 62.396 s, fixes the chronology failure first caught by
 `cx-clock-red-r14-a1`); real-browser success-path runs `cx-browser-r13-a1`
 and `cx-browser-clock-r16-a1` (all five roles, seven backend controls,
 independent owner verification, restored decision-package equality true;
 second browser's confirmation wait timed out, next UI read showed the
 completed restore, final independent checks passed) — success path only,
 not an exhaustive error-state crawl. Earlier regression evidence (r18-r22,
 r27) reproduced now-fixed bugs (failing cases, missing source CLI, empty
 comparison silently serving SINGLE, import errors, a size-budget
 overshoot); all superseded by the passing runs above.
- Raw output: this worktree's `native/guard/guarded-command-*.stdout.log`
 and `.stderr.log`; guard/cleanup/exits in `C:/Users/neers/rrb/logs/`. The
 external runner's failing-subtest pass count is unreliable; raw unittest
 records govern. `git diff --check` passes; the merge retained six
 historical CRLF whitespace warnings in
 `artifacts/engine-correction/vectors/run-vectors.cmd` (bytes unchanged).

## Connected behavior

- Synthetic NC marker age uses a pinned logical-seconds-to-UTC mapping and
 independent calendar calculations. Contract v3/profile v5 reject old
 bindings, future instants and contradictory failures; date-only/absent
 markers remain UNKNOWN. FRESH describes age at capture only; graph
 freshness stays UNKNOWN.
- Every outer owner write verifies current funding leaf projections before
 work and before commit under the same lock; summaries check the same read
 snapshot. The bounded check covers current sources, not arbitrary
 historical tampering; full independent replay remains necessary for
 history and store integrity.
- NC FHIR retries retain only the final attempt's response/error and record
 invalid Retry-After with a matching empty delay slot. Failure envelopes
 verify as failures and cannot enter graph admission. V2/V3 admission checks
 the configured observation window even when a source-contract digest is
 present.
- The read-model CLI and loopback graph view can take a bounded source
 envelope with separately supplied expected capture context. The
 independent verifier compares all six fields before source admission;
 graph and aggregate-export verification still run before serving. Empty
 comparison inputs fail before a server opens. Source files and raw
 identities never enter the HTTP projection.
- The pinned Lean transition decides financial corrections atomically with
 the owner, no Python fallback: min(claim, shortfall not already requested
 by unpaid earlier corrections). Only payments naming `pays_action_id`
 reduce a request's unpaid amount; removing/changing that link on a resend
 conflicts.
- Staff cash commands name the correction they pay. HTTP and
 process-restart tests create the correction first, preserve the original
 retry body/revision, and check one committed payment. Acknowledgment still
 has zero cash effect.
- The demo clock advances to its explicit correction decision time before
 the command, so subsequent acknowledgment timestamps follow action
 creation, including after a lost response. Existing recorded history is
 not rewritten.
- The release producer pins CMD02/RES3 and independently derived RU02/RV02
 baseline vectors. The kit's exact inventory includes `RETIRED_PINS` and
 verifies its bytes against the independent checker's pin. All old
 provenance, inventory, guard and actual/expected comparisons remain
 required.
- HTTP framing is checked before dispatch: one length, one content type, no
 transfer encoding, exact body bytes, an 8,192-byte cap and five-second
 total deadline. Refusals use a bounded 100 ms/8,193-byte drain after
 sending; HEAD has no body. Clean delivery is best effort for peers
 exceeding those bounds.
- v8 Continuity exports chained bounded history and restores by replay to an
 isolated SHADOW/TEST owner. Mirror reads the same owner. Switch compares
 caller-supplied evaluators over verified SHADOW data; it is not live
 cutover.
- Switch and Provider Trust Graph already ran on trunk, contrary to old
 "0 run" entries: 13 Switch and 12 Trust Graph tests passed in the recorded
 trunk runs (`trunk-cv8-full-a1`, `ptg-full-a1`); the candidate full suite
 also passes these. Trust Graph remains read-only, without a gate consumer.

## Artifact and source boundary

- Pinned correction engine: `1A7A1833...D3AF`, 6,279,168 bytes; request
 `B658DCEE...D067`, result `83BB53D1...E0D6`; reuse request
 `9C203F6B...5B99`, expected result `973B0CA0...78E4F`. Exact pins and
 construction are in `artifacts/engine-correction/PROVENANCE.md`.
- The pin was reproduced byte-identically from the current combined Lean
 tree in r67/r77; provenance retains its earlier historical origin
 separately, no new binary pin or retired-engine entry was needed. r68/r69/
 r70 record the whole build, executable checks and independently checked
 correction proofs.
- Offline kit assemble/verify/extract/scenario passed r80; serve/restart
 passed r84. The archive binds the assembly working tree, including frozen
 connector and browser candidates; these checks do not qualify those other
 tracks. Lean builds need 4,029,372,048 free bytes to start; Python tests
 need 2,200,000,000. Both keep the 2,029,372,048-byte running floor (guard v7;
 1 GiB and both starts 955,630,224 lower while the owner's away file is valid).
- Retired engines are historical verification only, through the append-only,
 digest-pinned registry. A missing, malformed or changed registry refuses
 verification. Only the current engine may decide new corrections.

## Rules and unresolved work

- The NC capture path is synthetic file intake, no live transport. Financial
 file adapters (MCO reports, X12 820/835, MMIS extracts), shared
 provider/gate rules and payee-identity consumption remain unbuilt.
 Aggregate provider export already has a read-model consistency consumer;
 the A2 design's no-consumer premise is stale and not a reason to remove
 that check.
- Owner/Continuity v8 only; older stores fail without mutation. At most
 10,000 events or rows per table. One writer; history/projections/outbox
 commit together; exact retries do not write; changed meaning conflicts.
- Complete the real-browser crawl of the declared interaction model — the
 Node model/scorecard is not a browser crawl.
- Second synthetic state (plan G3) is not a Python-only edit: Lean's
 `controlPackRulesWellFormed` also pins H's test labels. Change
 owner/checker/Lean together, retain supported rule/version/role checks and
 digest/length bounds, rebuild, then exercise different amounts, recipients
 and timetable through correction, linked cash and Continuity. No partial
 policy change made.
- Support v2 (G4), shared provider/gate rules and payee-identity integration
 remain designed work (G2 landed above). New protected contracts require
 their XI.2 record.
- Conformance kit (G5): vectors, manifest and correction wire spec in
 `conformance/`.
- A READY correction can become stale after later money events; cancel/
 reduce transitions and excess-request accounting remain to build. Reuse
 still trusts recorded input shortfall and ignores the paid list; no
 application calls it. A new pin-transition event and stronger
 paid-list/amount proofs remain pending.
- The prior funding drift reproduction accepted 70 later writes; r31 now
 refuses all 70 after tampering, without a full history replay per write.
 The full-store replay still owns detection of historical corruption
 outside current projection links; the new local guard does not replace it.
- Whole-history checking was ~27 s at 10,000 rows, above the 5 s
 target. Lock contention may return `store_busy`; retries must keep the
 reviewed body. TEST restore through segmented history and a Lean seal
 codec remain unbuilt.
- Staff roles are UI-only; authentication, refusal logging and connection
 caps remain absent. A replacement operator can restore/read but not take
 over work.
- Isolated TEST restore creates an owner using the system clock;
 continuation there is not tied to the deterministic demo clock. Process
 resume is distinct: it advances the demo clock to the latest verified
 committed event.
- The financial command log omits `pays_action_id`; the event chain carries
 it.
- No integrated payer gate. Separate gate-format work still assumes
 admitted grants and authenticated checkpoint ancestry. Rule tests do not
 establish a durable token/release path. The gate-rules-2
 checkpoint-identity repair is not part of this candidate; preserve that
 branch's existing dirty work.
- Gate failover TLC is a bounded model (3,516,192 states), not running
 failover; the deeper model, operational drill, CI and warm-worker
 throughput remain open.
- Historical unresolved runs remain evidence, not current verification:
 Queue broad run 122 tests with 1 failure/5 errors; State clearance 45
 pass/1 failure before later unrun fixes; Security proof build succeeded
 with 30 style warnings. Qualification's 17 tests/8 empty evidence slots
 and Security's 64-test cleanup need fresh evidence. The State clearance
 route is under `parked/`.
- Private ZK is active in its separate prototype repository, evidence-only
 and never a core/gate prerequisite; old `parked/` sources remain
 reference.

Next: connector/browser completion remains paused at the founder's request;
the exhaustive browser crawl and final combined-source verification are
still outstanding. The receiver cash-file implementation is synthetic-only;
the distinct MCO/X12/MMIS formats listed above remain unsupported and refuse
completely. The founder requested local commits; this candidate is not a
qualified release. No production activation follows from any of these local
checks.
