# RightRail current state

Updated: 2026-09-20

## Current verified snapshot

Canonical checkout:

`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`

Branch: `rightrail-financial-workflow-20260913`.

Committed parent at the documentation handoff:
`06070168fd180a1173bb6426cbf7cbdbc33bc67a`, tree
`c52630fd511ebe3b1ca32b2390a289c3a07746a6`.

The State-owned working tree contains v5 source/test/CLI/measurement-harness
changes in these paths:

- `app/right_rail_financial_owner.py`
- `app/right_rail_financial_owner_independent.py`
- `app/right_rail_financial_mirror.py`
- `tests/rightrail_financial_expected_cases.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_independent.py`
- `tests/test_right_rail_financial_mirror.py`
- `tools/right_rail_financial_cli.py`
- `work/right_rail_financial_measurement_series.py`

The two untracked driver-supplied executables under `build-performance/` are
preserved and were not touched. This documentation batch is also intentionally
unstaged; no source, test, fixture, build, evidence, native, C, crypto, Lean,
Queue, Composition, operations, archive, or secret path was changed here.

## v5 implementation boundary

The working contracts are `RR/FINANCIAL/OWNER/v5` and
`RR/FINANCIAL/CONTINUITY/v5`. v2/v3/v4 stores and packages remain preserved
historical inputs and reject fail-closed without mutation.

The required owner boundary keeps the Python owner as the only transaction
writer for obligations, evaluations, cases, determinations, corrections,
balances, and action/outbox identity. Mirror queries and commands must use that
owner. The required Continuity boundary is a bounded versioned export/restore
surface: SHADOW must be query-only; TEST must be isolated and non-live;
dispatch and egress must remain disabled; restore must preserve a single live
writer.

The required v5 evaluation model retains plaintext rows and adds
`current_evaluation_receipt(item_id)`. The receipt contract is
`RR/FINANCIAL/EVALUATION-RECEIPT/v1`; it binds state/deployment/program/period/
currency scope, evaluation/obligation/revision, Control Pack id/version/digest,
sorted unique evidence id and record-digest bindings, trusted authority
id/epoch/digest, `evaluated_at_ms`, every result field, result digest, and
receipt digest. It carries references and digests only, never raw evidence or
signatures.

The required v5 determination contract has explicit evaluation id,
evaluation-result digest, and expected revision. It must bind the current and
historical evaluation, receipt, revision, projection, claim evidence coverage,
chronology, Control Pack, evidence, and authority before one atomic
determination/action/outbox transition. Exact same retries must be `DUPLICATE`;
changed identity/input/time must be conflict. There is no separate
verification-attempt, lease, receipt-consumption, or reservation table;
claimed adjustments and Queue reservations remain separate business/queue
state. The current batch is not accepted for this contract; see the review
disposition below.

## v5 review disposition — CORRECTED BOUNDED SLICE VERIFIED

The frozen v5 review found defects in the working owner/checker/Continuity
path. State applied the combined correction packet, then recompiled and ran the
affected owner, independent-checker, and Mirror suites through the existing
guard. The corrected bounded Python slice is verified for this synthetic,
state-local checkout; this is not production qualification or activation.

The corrected path now covers the prior findings:

1. Evaluation input and event bindings reconstruct historical projections and
   bind the stored evaluation to the authoritative event and current immutable
   records.
2. Trusted authority is fixed to the owner identity and checked against the
   stored metadata; future-dated evidence is rejected without clamping.
3. Stored action/determination retries are bound to the supplied obligation,
   and Continuity restore validates package metadata against its header before
   creation and cleans failed attempts.

The final guarded affected child evidence was:

```text
PROCESS_BOUNDARY precommit returncode=73 stdout='PHASE=BEFORE_REJECT\nPHASE=PRECOMMIT_AFTER_MUTATION\n' stderr=''
PROCESS_BOUNDARY postcommit returncode=74 stdout='PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n' stderr=''
Ran 58 tests in 22.223s
OK
```

Corrected owner SHA-256:
`2CDE008DBE45CEBD33D14F764CAF768A1E9AC5CE22A6AB03951B458A0AE7578A`.
Corrected independent-checker SHA-256:
`FE1CCDCA057FE36391FF9A9BCD9B4CD73ADAC9A934D3DB88D040E5F6BB1D5A55`.

The final Engine measurement child receipt at
`work/financial-measurements-v5-final-r3` reports `type=complete` and
`status=PASS` for sizes 5, 10, and 20 with three measured samples plus one
warmup, `all_reference_checks_passed=true`,
`all_source_bytes_unchanged=true`, and three verified TEST restores. Its
native, queue-wait, and outer-resource fields remain explicitly pending or
not applicable to this Python owner slice.

## Retained pre-correction focused evidence

The final Mirror/CLI caller packet ran through the existing guard:

```text
Ran 12 tests in 2.571s
OK
```

It reported no warnings or skips. This focused result is retained evidence,
not v5 acceptance because the completed review above found defects. Decisive
guard values were:

```text
PHYSICAL_PREFLIGHT free_bytes=3499163648 reserve_bytes=3221225472 reserve_floor_bytes=2576980378
CHILD_EXIT_STATUS exit=0
CLEANUP=PASS
MUTEX=RELEASED
```

The recorded main minimum free bytes were `3381149696` and peak private bytes
`81027072`. Final Mirror test SHA-256:
`35D56C3C16A8506D7F6F6BB48C8647F21BB282FABC43E608EACCBFBDF407521B`.

Retained preceding gates were acceptance `24 tests in 12.759s`, independent
`18 tests in 5.086s`, and expanded Mirror `10 tests in 2.050s`, all `OK`.
Two focused retry/conflict tests were included in the final caller packet.

The v5 measurement series retained 3 measured samples plus 1 warmup for each
size 5, 10, and 20, with 12 owner SQLite databases and 12 TEST restore
databases. The aggregate is the median of three per-sample medians. Actual
`_write()` wait/held medians were `2.019/7.188`, `1.815/6.052`, and
`1.708/6.597` ms; transaction totals were `36`, `54`, and `90`, with zero
acquisition failures. All 9 measured restores left source bytes unchanged.
This is a bounded observation, not an SLA; native metrics and queue wait/age
are not applicable. The retained measurement directory is
`work/financial-measurements-v5-r1`.

CASE10 covers abrupt owner-child exit before COMMIT and after COMMIT, restart,
independent verification, same-identity retry, and unchanged duplicate effects.
It is owner-local evidence and does not qualify Queue, Composition, native,
Lean, or a production boundary.

## Retained failures, warnings, and skips

Earlier failed attempts remain raw evidence and were not relabeled as passes:

- acceptance r1 had the BLOB/string `result_digest` check failure (`18` errors,
  `3` passed); r2 had evidence-binding/parser/clock/race failures; r3 had
  chronology and claim-order failures;
- Mirror r1 had a fixed-timestamp failure;
- compile-r3 passed but was wrong-scope because relative paths resolved under
  the guard build directory;
- corrected acceptance r4/r5, independent r1/r2, and Mirror r2/r3 are the
  retained successful corrections.

The exact raw logs, hashes, failed invocations, and older v2/v3/v4 receipts
remain in their existing guard/evidence workspaces and Git history. This file
does not duplicate those receipts. No new test/build/checker was run for this
documentation cleanup.

## Open gates and nonclaims

The prior security findings are addressed by the corrected source and the
affected re-verification above. Native verification-to-commit, native metrics,
Lean executable linkage/refinement, independent audit, authenticated sources,
custody, real PHI, live dispatch, payment movement, and production
qualification remain pending or separate. The active Lean direction does not
switch runtime authority away from the Python v5 owner.

Current claims remain:

`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`, synthetic, nonpayment, and non-PHI.

The fixed fixture is twenty hospitals and $1,000,000 total: H is $100,000 and
the other nineteen total $900,000. Expected cents and branch answers are
hand-derived. Preserve Queue schema 13/Profile 12, Composition schema 4, the
exact 100-reference protocol, source ownership/reservation, Queue/State/outbox
atomicity, the non-`CLEAR` economic guard, and all native/C/crypto/Lean
artifacts.
