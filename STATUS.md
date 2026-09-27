# RightRail status

Updated: 2026-09-26. Current candidate: `codex/connected-workflows`, based on
main `6cccb84`, integrating `correction-v2` (`70f87c7`) in local development
commit `595e611`, with the funding and source-clock fixes below in this local
development increment. Main has not received this combination. Git state,
raw guard logs and artifact provenance govern; a branch's pass does not verify
another branch or their combination. `CONSTITUTION.md` is supreme.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work,
official decisions and follow-through. Control Pack, Blind Ledger, Mirror,
Continuity and Switch share the financial owner; Provider App is separate.
The payment gate is one authority level within that product. Existing payment
systems move money. Synthetic, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`.

## Current verification

- Final repair and budget check, `cx-preconsolidation-r38-a1`: 8/8 passed,
  zero failures/errors/skips, guard exit 0, cleanup PASS. This reruns the NULL-ID
  successor rejection and borrowed crash helper, plus every unchanged size gate.
- Funding boundary, `cx-funding-r31-a1`: 24/24 passed, no failures, errors or
  skips, guard exit 0, cleanup PASS. Current-projection mutations refuse single
  writes, batches, retries and summaries; post-body drift rolls back. Acceptance
  test setup was subsequently consolidated; full regression remains required.
- Source clock/admission and consumers, `cx-clock-contract-r32-a1`: 72/72
  passed, no failures, errors or skips, guard exit 0, cleanup PASS, 2.991 s.
  Inclusive age bounds, malformed/future dates, six context fields, numeric-ID
  substitutions, failure precedence and body-discard evidence are checked.
  All size gates passed unchanged. Independent source review found no blocker.
- Combined r33 stopped on memory: 2,130,452,480 < 2,190,433,321 free bytes;
  cleanup PASS, outer exit 1. It recorded 140 completed passes, 2 skips (missing
  gate runner and Windows symlink privilege), and 1 interrupted test, with no
  final suite verdict. r34 subsequently recorded 226 passes, the same 2 skips and
  1 interrupted test before its own floor stop (2,159,529,984 free bytes), outer
  exit 1 and cleanup PASS. Neither verifies the full combination.
- Full r35 completed: 420 run, 408 passed, 0 failures, 1 error, 11 skips,
  guard exit 1, cleanup PASS. A protected invariant test borrows the acceptance
  process helper; its new child-helper lookup was missing from that borrowed
  class. Explicit fixture-class dispatch fixes the helper without changing the
  protected test; r36 confirms that invariant passes.
- Independent funding review found a nullable receipt-ID successor missed by
  the local join predicate. r36 reproduced the wrong refusal path: the later
  row-count diagnostic raised instead of the required projection-integrity
  error (1 pass, 1 failure, no skips; guard 1, cleanup PASS). The join now tests
  `child.rowid`, preserving schema and limits. Both repaired tests pass in r37.
- Combined r37 recorded 379 completed passes, 4 skips and 1 interrupted test
  (384 started) before the memory floor stopped it: 2,185,838,592 free bytes
  versus 2,190,433,321 required. Cleanup PASS; no final suite verdict or captured
  outer exit. No test failure/error was recorded. All funding, source, acceptance,
  protected invariant, staff and Switch tests reached their recorded outcomes;
  the interaction-model restore-position test was interrupted. The remaining
  36 tests were not started. This is not a completed full-suite pass.
- Connector increment, `cx-connectors-final-r28-a1`: 65/65 passed, no failures,
  errors or skips, guard exit 0, cleanup PASS. It covers source retries, admission,
  all six expected context fields, source-file view/comparison, malformed and
  oversized files, missing context, empty comparison paths, privacy and unchanged
  size limits. Existing mutation cases remain; repeated setup was consolidated.
- Real source-file browser run `cx-source-browser-r25-a1` verified SINGLE and
  COMPARE, record navigation, findings, empty discrepancies and right selection;
  no console warnings/errors, captures unchanged and exact retry projection equal.
  Guard exit 0, cleanup PASS, minimum free memory 2,961,432,576 bytes. Both servers
  stopped and the one test tab closed. A stale browser element was refreshed before
  retrying its click. This run preceded the empty-comparison-argument fix, which
  is covered in r28. The first harness launch (r24) failed to import `app` because
  the guard uses a different working directory; explicit repository setup fixed it.
- Regression evidence: r18 reproduced 7 failing cases across 3 tests; r21 showed
  the missing source CLI; r27 reproduced the empty-artifact comparison silently
  serving SINGLE. r19 had 42 passes and 3 incorrect-module import errors, resolved
  by the corrected 64/64 r20 run. r22 had 48 passes and one size-budget failure
  (78,074 > 78,019); setup deduplication and r28 pass preserve the original cap.
- Previous committed candidate, `cx-full-connectors-r29-a1`: 410 tests run, 399 passed, 0 failures,
  0 errors, 11 skipped, guard exit 0, cleanup PASS. Runtime 412.730 s;
  minimum free memory 2,569,719,808 bytes. This includes the attack modules and
  earlier connector/demo-clock fixes, not the new source-clock/funding fixes.
- All 11 skips: 1 missing `gate_rules.exe` build; 1 Windows symlink privilege
  refusal (WinError 1314); 1 absent `engine-snapshot-398e/blind_financial.exe`;
  1 unset fresh-engine handoff (`BLIND_FINANCIAL_EXE`/SHA256); 7 real semantic
  mutation checks requiring `BLIND_LEDGER_SEMANTIC_CANDIDATE` through the
  semantic assurance gate. These checks are not claimed verified.
- Focused staff/package/budget run `cx-staff-r9-a1`: 39/39 passed, no skips.
  The full run repeats the correction lost-response/SHADOW scenario: one commit,
  sequence 50 -> 51, exact retry writes nothing, independent integrity and
  read-only restore verified, replacement rejected. This is the source checkout,
  not an assembled offline kit. The reuse baseline also passed in the full run.
- Both passing runs print the intentional argparse refusal from
  `test_server_cli_rejects_partial_engine_configuration`; that test passes.
- Final clock fix, `cx-clock-green-r15-a1`: 30/30 staff and budget tests passed,
  no skips, 62.396 s, guard exit 0 and cleanup PASS. The added chronology check
  first failed under `cx-clock-red-r14-a1`: acknowledgment 1774828800075 preceded
  action creation 1774922400000. This is not a new full-suite result.
- Real browser `cx-browser-r13-a1` exercised all five roles and all seven backend
  controls along the H success path. Post-fix `cx-browser-clock-r16-a1` repeated
  correction, acknowledgment, cash, reporting and TEST restore: sequence 54,
  H cash 10,000,000 cents, shortfall 0, exactly one payment link to its correction;
  acknowledgment 1774922400002 follows creation 1774922400001. Independent owner
  verification passed; restored decision package equality was true. Both guard
  exits were 0 with cleanup PASS and no browser console warnings/errors. The
  second browser's confirmation wait timed out; the next direct UI read showed
  the completed restore, and the final independent checks passed. Both test tabs
  were closed. This verifies the success path, not an exhaustive error-state crawl.
- Raw output: this worktree's `native/guard/guarded-command-*.stdout.log` and
  `.stderr.log`; guard/cleanup/exits: `C:/Users/neers/rrb/logs/`.
  The external runner's failing-subtest pass count is unreliable; raw unittest
  records govern those earlier red runs. Passing counts above reconcile.
- Independent read-only review found no remaining blocker in the connection/HTTP
  fixes after the test reference repair. Unstaged `git diff --check` passes.
  The merge retained six historical CRLF whitespace warnings in
  `artifacts/engine-correction/vectors/run-vectors.cmd`; its bytes are unchanged.

## Connected behavior

- Synthetic NC marker age now uses a pinned logical-seconds-to-UTC mapping and
  independent calendar calculations. Contract v3/profile v5 reject old bindings,
  future instants and contradictory failures; date-only/absent markers remain
  UNKNOWN. FRESH describes age at capture only; graph freshness stays UNKNOWN.
- Every outer owner write verifies current funding leaf projections before work
  and before commit under the same lock; summaries check the same read snapshot.
  The bounded check covers current sources, not arbitrary historical tampering;
  full independent replay remains necessary for history and store integrity.
- NC FHIR retries now retain only the final attempt's response/error and record
  invalid Retry-After with a matching empty delay slot. Failure envelopes verify
  as failures and cannot enter graph admission. V2/V3 admission checks the
  configured observation window even when a source-contract digest is present.
- The read-model CLI and loopback graph view can take a bounded source envelope
  with separately supplied expected capture context. The independent verifier
  compares all six fields before source admission; graph and aggregate-export
  verification still run before serving. Empty comparison inputs fail before a
  server opens. Source files and raw identities never enter the HTTP projection.
- The pinned Lean transition decides financial corrections atomically with the
  owner, with no Python fallback: min(claim, shortfall not already requested by
  unpaid earlier corrections). Only payments naming `pays_action_id` reduce a
  request's unpaid amount. Removing or changing that link on a resend conflicts.
- Staff cash commands now name the correction they pay. HTTP and process-restart
  tests create the correction first, preserve the original retry body/revision,
  and check one committed payment. Acknowledgment still has zero cash effect.
- The demo clock advances to its explicit correction decision time before the
  command, so subsequent acknowledgment timestamps follow action creation,
  including after a lost response. Existing recorded history is not rewritten.
- The release producer now pins CMD02/RES3 and independently derived RU02/RV02
  baseline vectors. The kit's exact inventory includes `RETIRED_PINS`, and
  verifies its bytes against the independent checker's pin. All old provenance,
  inventory, guard and actual/expected comparisons remain required.
- HTTP framing is checked before dispatch: one length, one content type, no
  transfer encoding, exact body bytes, an 8,192-byte cap and five-second total
  deadline. Refusals use a bounded 100 ms/8,193-byte drain after sending; HEAD
  has no body. Clean delivery is best effort for peers exceeding those bounds.
- v8 Continuity exports chained bounded history and restores by replay to an
  isolated SHADOW/TEST owner. Mirror reads the same owner. Switch compares
  caller-supplied evaluators over verified SHADOW data; it is not live cutover.
- Switch and Provider Trust Graph already ran on trunk, contrary to the old
  "0 run" entries: 13 Switch and 12 Trust Graph tests passed in the recorded
  trunk runs (`trunk-cv8-full-a1`, `ptg-full-a1`). The candidate full suite
  also passes these tests. Trust Graph remains read-only, without a gate consumer.

## Artifact and source boundary

- Pinned correction engine: `1A7A1833...D3AF`, 6,279,168 bytes; request
  `B658DCEE...D067`, result `83BB53D1...E0D6`; reuse request `9C203F6B...5B99`,
  expected result `973B0CA0...78E4F`. Exact pins and construction are in
  `artifacts/engine-correction/PROVENANCE.md`.
- That executable was built twice byte-identically from the source named in its
  provenance, with 42/42 KATs. The combined candidate's Lean tree is newer.
  No claim that the existing binary was built from this combined tree is valid.
- Fresh build/repin and offline kit assemble/verify/extract/scenario/serve remain
  unrun. The Lean build needs 4,190,433,321 free bytes to start; Python tests need
  2,400,000,000. Both retain the 2,190,433,321-byte running floor. The founder
  directed work on other fixes while compiler memory is unavailable.
- Retired engines are historical verification only, through the append-only,
  digest-pinned registry. A missing, malformed or changed registry refuses
  verification. Only the current engine may decide new corrections.

## Rules and unresolved work

- The NC capture path is synthetic file intake, with no live transport. Financial
  file adapters (MCO reports, X12 820/835 and MMIS extracts), shared provider/gate
  rules and payee-identity consumption remain unbuilt. Aggregate provider export
  already has a read-model consistency consumer; the A2 design's no-consumer
  premise is stale and is not a reason to remove that check.
- Owner/Continuity v8 only; older stores fail without mutation. At most 10,000
  events or rows per table. One writer; history/projections/outbox commit
  together; exact retries do not write; changed meaning conflicts.
- Complete the real-browser crawl of the
  declared interaction model. The Node model/scorecard is not a browser crawl.
- Second synthetic state (plan G3) is not a Python-only edit: Lean's
  `controlPackRulesWellFormed` also pins H's test labels. Change owner/checker/
  Lean together, retain supported rule/version/role checks and digest/length
  bounds, rebuild, then exercise different amounts, recipients and timetable
  through correction, linked cash and Continuity. No partial policy change made.
- Dependency-aware follow-up (G2), support v2 (G4), conformance packaging (G5),
  shared provider/gate rules and payee-identity integration remain designed work.
  Acknowledgment currently reopens correction follow-up; dependencies do not yet
  identify which fact changed. New protected contracts require their XI.2 record.
- A READY correction can become stale after later money events; cancel/reduce
  transitions and excess-request accounting remain to build. Reuse still trusts
  recorded input shortfall and ignores the paid list; no application calls it.
  A new pin-transition event and stronger paid-list/amount proofs remain pending.
- The prior funding drift reproduction accepted 70 later writes; r31 now refuses
  all 70 after tampering, without a full history replay per write. The full-store
  replay still owns detection of historical corruption outside current projection
  links; the new local guard does not replace it.
- Whole-history checking was about 27 s at 10,000 rows, above the 5 s target.
  Lock contention may return `store_busy`; retries must keep the reviewed body.
  TEST restore through segmented history and a Lean seal codec remain unbuilt.
- Staff roles are UI-only; authentication, refusal logging and connection caps
  remain absent. A replacement operator can restore/read but not take over work.
- Isolated TEST restore creates an owner using the system clock; continuation
  there is not tied to the deterministic demo clock. Process resume is distinct:
  it advances the demo clock to the latest verified committed event.
- The financial command log omits `pays_action_id`; the event chain carries it.
- No integrated payer gate. Separate gate-format work still assumes admitted
  grants and authenticated checkpoint ancestry. Rule tests do not establish a
  durable token/release path. The gate-rules-2 checkpoint-identity repair is not
  part of this candidate; preserve that branch's existing dirty work.
- Gate failover TLC is a bounded model (3,516,192 states), not running failover;
  the deeper model, operational drill, CI and warm-worker throughput remain open.
- Historical unresolved runs remain evidence, not current verification: Queue
  broad run 122 tests with 1 failure/5 errors; State clearance 45 pass/1 failure
  before later unrun fixes; Security proof build succeeded with 30 style warnings.
  Qualification's 17 tests/8 empty evidence slots and Security's 64-test cleanup
  need fresh evidence. The State clearance route is under `parked/`.
- Private ZK is active in its separate prototype repository, evidence-only and
  never a core/gate prerequisite; old `parked/` sources remain reference.

Next: consolidate duplicated test setup first, as directed by the founder;
preserve every test, assertion and the 78,019-line cap (current tree: 78,018).
Commit the reviewed increments with their actual evidence, then complete the
combined regression and the independently reviewed financial input contract;
complete the real-browser error-state crawl; when memory permits, rebuild
and repin the final Lean tree, then assemble/verify/extract/run the offline kit.
The founder requested local commits; this candidate is not a qualified release.
No production activation follows from any of these local checks.
