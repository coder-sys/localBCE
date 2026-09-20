# RightRail current task

Updated: 2026-09-20

## Objective and working identity

This checkout is the canonical synthetic financial application:

`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`

Branch: `rightrail-financial-workflow-20260913`.

Committed parent at the current handoff:
`06070168fd180a1173bb6426cbf7cbdbc33bc67a`, tree
`c52630fd511ebe3b1ca32b2390a289c3a07746a6`.

The active implementation is working v5 Python owner/checker/Mirror/CLI/
Continuity code with its measurement harness. Source/test/harness work is
intentionally uncommitted and State-owned.
The two untracked `build-performance/` executables are preserved evidence and
must not be touched.

The maintained task is to keep this entry point aligned with actual source and
evidence while preserving the five-part responsibility: State Control Pack,
Blind Ledger, same-owner Mirror, bounded Continuity State, and deferred Switch.
This documentation cleanup does not authorize source, test, fixture, build,
native, C, crypto, Lean, Queue, Composition, operations, archive, or evidence
changes.

## Required v5 contract and review status

Owner and Continuity identities are `RR/FINANCIAL/OWNER/v5` and
`RR/FINANCIAL/CONTINUITY/v5`. v2/v3/v4 stores/packages remain preserved and
reject fail-closed without mutation.

The required owner boundary keeps the owner as sole writer for obligations,
evaluations, determinations, corrections, balances, and action/outbox identity.
The required v5 contract includes `current_evaluation_receipt(item_id)` and
the same receipt from `evaluate_obligation`. The receipt is
`RR/FINANCIAL/EVALUATION-RECEIPT/v1`; it binds scope, evaluation/obligation/
revision, Control Pack identity/digest, sorted evidence id/record-digest
bindings, trusted authority, timestamp, result fields, result digest, and
receipt digest. It contains references/digests only.

The required determination contract binds evaluation identity/digest and
expected revision to current and historical evaluation, receipt, projection,
evidence coverage/chronology, Control Pack, and authority before one atomic
determination/action/outbox transition. Exact same retries must be
`DUPLICATE`; changed identity or input must be conflict. State applied the
combined correction and completed affected re-verification; the corrected
bounded Python slice is verified as recorded in `STATE.md`. There is no
separate verification-attempt, lease, receipt-consumption, or Queue-reservation
boundary.

The required Continuity boundary is query-only SHADOW or isolated TEST/non-live;
dispatch and egress must remain disabled, and restore must create no second
live writer. Abrupt owner exits before COMMIT and after COMMIT are covered by
retained CASE10 evidence with restart, independent verification, same-identity
retry, and unchanged duplicate effects.

## Corrected final evidence

The final guarded affected source/test run compiled the corrected owner,
independent checker, Mirror, fixtures, CLI, and measurement harness, then ran
the three affected suites:

```text
Ran 58 tests in 22.223s
OK
```

The guard reported child exit `0`, minimum free bytes `3095826432`, peak
private bytes `54579200`, `CLEANUP=PASS`, and `MUTEX=RELEASED`. The corrected
owner and independent-checker hashes are recorded in `STATE.md`. The final
Engine measurement child receipt is `status=PASS` with all reference checks and
source-byte checks true across sizes 5, 10, and 20; this remains bounded local
evidence, not an SLA or production qualification.

## Retained focused evidence (pre-correction, not acceptance)

The final Mirror/CLI caller packet ran through the existing guard:

```text
Ran 12 tests in 2.571s
OK
```

No warnings or skips were reported. Guard decisive values were preflight free
bytes `3499163648`, reserve `3221225472`, reserve floor `2576980378`, minimum
free `3381149696`, peak private bytes `81027072`, child exits `7/0`,
`CLEANUP=PASS`, and `MUTEX=RELEASED`. Final Mirror test SHA-256:
`35D56C3C16A8506D7F6F6BB48C8647F21BB282FABC43E608EACCBFBDF407521B`.

Retained preceding focused gates were acceptance `24 tests in 12.759s`,
independent `18 tests in 5.086s`, and expanded Mirror `10 tests in 2.050s`,
all `OK`. Earlier failed attempts, warnings, and corrected reruns remain in
raw guard evidence and Git history; they are not silently converted into
current acceptance.

The v5 measurement series has three measured samples plus one warmup at each
of sizes 5, 10, and 20, with 12 owner databases and 12 TEST restore databases.
The aggregate is the median of three per-sample medians; actual write
wait/held medians are 2.019/7.188, 1.815/6.052, and 1.708/6.597 ms, with
transaction totals 36, 54, and 90 and zero acquisition failures. All nine
measured restores left source bytes unchanged. This is a bounded observation,
not an SLA; native metrics and queue wait/age are not applicable.

## Active next gates

1. Keep the corrected bounded slice aligned with its raw evidence while
   reconciling future Driver-wide, native, and formal gates. Do not infer
   production qualification or activation from this local result.
2. Continue the Lean extraction design for Engine with narrow versioned
   interfaces, a small trusted core, independent checks, and explicit state
   semantics. No runtime authority switch occurs until a pinned executable
   Lean artifact and refinement/linkage evidence exist.
3. Keep native verification-to-commit, native metrics, independent audit,
   custody, authenticated sources, real PHI, live dispatch, and payment
   movement as separate future gates.

## Protected boundary and claims

The fixed fixture is twenty hospitals and $1,000,000 total: H is $100,000 and
the other nineteen total $900,000. Expected values are hand-derived. Preserve
Queue schema 13/Profile 12, Composition schema 4, the exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity, the
non-`CLEAR` economic guard, and all native/C/crypto/Lean artifacts.

Current claims are synthetic, local, nonactivating, nonpayment, and non-PHI:
`proofSuiteId=null`, `production_usable=false`, `activation=false`,
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`. The Python v5 owner is not a deployed
formal authority, official processor, payment system, or independent audit.

State owns source, tests, fixtures, and generated evidence. Docs owns the
released Markdown only. Leave all changes from this documentation cleanup
unstaged for State integration. The complete pre-edit task/evidence narrative
remains recoverable from Git history and the immutable raw evidence paths.
