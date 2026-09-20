# RightRail financial workflow

This checkout contains a synthetic, state-local financial responsibility with
five explicit parts: State Control Pack, Blind Ledger owner, same-owner Mirror,
bounded Continuity State, and a deferred Switch. The official state/payment
processor remains the authority for funds movement. RightRail records
obligations, typed evidence, evaluations, determinations, authorized actions,
delivery, and descriptive cash/reporting facts; it does not move money or
authorize a live payment.

The owner is the sole writer. Mirror commands and queries that owner.
Continuity exports/restores a bounded versioned view into SHADOW or isolated
TEST/non-live state, with dispatch and egress disabled and no second live
writer. Evidence, official determination, action authorization,
acknowledgment, and cash/reporting completion are separate facts.

## Current working boundary

At this documentation release the branch is
`rightrail-financial-workflow-20260913` with committed parent
`06070168fd180a1173bb6426cbf7cbdbc33bc67a` / tree
`c52630fd511ebe3b1ca32b2390a289c3a07746a6`. The v5 source/test/CLI/
measurement-harness work is
intentionally uncommitted and State-owned; this cleanup does not change it.

The working contracts are `RR/FINANCIAL/OWNER/v5` and
`RR/FINANCIAL/CONTINUITY/v5`. v2/v3/v4 stores and packages remain preserved
historical inputs and reject fail-closed without mutation. The current Python
owner is the transaction authority. Lean extraction/design is the active
formal pivot, but no executable Lean linkage or runtime authority switch exists.

## Fixed synthetic responsibility

The fixture is twenty hospitals and $1,000,000 total: H is owed $100,000 and
the other nineteen total $900,000. Expected values are hand-derived. The
reviewer-fixed cents are H `10,000,000`, eighteen other items `4,700,000`
each, and one other item `5,400,000`.

The required v5 evaluation contract includes versioned plaintext evaluations
and `current_evaluation_receipt(item_id)`. Receipt contract
`RR/FINANCIAL/EVALUATION-RECEIPT/v1` binds scope, evaluation/obligation/
revision, Control Pack identity, sorted evidence id/record-digest bindings,
trusted authority, timestamp, result fields, result digest, and receipt digest;
it carries references/digests only. The required determination contract binds
explicit evaluation identity/digest and expected revision to current and
historical state before one atomic determination/action/outbox transition.
Exact retries must be `DUPLICATE`; changed identity or input must be conflict.
The frozen v5 review is complete; the current batch is `NOT ACCEPTED` pending
State's combined correction and affected re-verification. Detailed blockers are
in `STATE.md`.

## Entry points

| Boundary | Source |
| --- | --- |
| Owner and schema | `app/right_rail_financial_owner.py` |
| Independent reconstruction | `app/right_rail_financial_owner_independent.py` |
| Same-owner queries, commands, Continuity | `app/right_rail_financial_mirror.py` |
| Local caller surface | `tools/right_rail_financial_cli.py` |
| Expected fixture branches | `tests/rightrail_financial_expected_cases.py` |
| Focused acceptance/checker/Mirror tests | `tests/test_right_rail_financial_*.py` |

Read the current objective and blockers in [`CURRENT_TASK.md`](CURRENT_TASK.md),
then verified evidence in [`STATE.md`](STATE.md). The system boundary is in
[`ARCHITECTURE.md`](ARCHITECTURE.md); dependency order is in
[`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md); the design
contract is [`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md).

## Verified evidence

The final Mirror/CLI caller packet ran through the existing guard:

```text
Ran 12 tests in 2.571s
OK
```

It reported no warnings or skips. Guard evidence included
`PHYSICAL_PREFLIGHT free_bytes=3499163648 reserve_bytes=3221225472
reserve_floor_bytes=2576980378`, child exits `7/0`, minimum free bytes
`3381149696`, peak private bytes `81027072`, `CLEANUP=PASS`, and
`MUTEX=RELEASED`. The final Mirror test identity is
`35D56C3C16A8506D7F6F6BB48C8647F21BB282FABC43E608EACCBFBDF407521B`.

Retained preceding gates were acceptance `24 tests in 12.759s`, independent
`18 tests in 5.086s`, and expanded Mirror `10 tests in 2.050s`, all `OK`.
Earlier failed attempts and their corrections remain raw evidence; they are
not relabeled as passes.

## Limitations and claims

- The candidate is synthetic, local, nonactivating, nonpayment, and non-PHI:
  `proofSuiteId=null`, `production_usable=false`, and `activation=false`.
- Security review is complete. Its combined correction and affected
  re-verification, plus final measurement, are pending. Native metrics, native
  verification-to-commit, Lean replay/linkage, whole-system qualification,
  independent audit, real data/PHI, live dispatch, payment movement, and
  production qualification remain open.
- There is no separate verification-attempt, lease, receipt-consumption, or
  Queue-reservation boundary in the financial owner. Claimed-adjustment state
  and Queue reservations remain separate.
- The fixed Queue schema 13/Profile 12, Composition schema 4, exact 100-
  reference protocol, source ownership/reservation, atomicity, non-`CLEAR`
  guard, and native/C/crypto/Lean boundaries are separate protected seams.

## Product commitments

State owns rules, data, keys, histories, interfaces, tests, and continuity
export. RightRail remains replaceable without proprietary lock-in; vendor
compatibility is free/conformant rather than a share of denials, recoveries,
penalties, or savings. Provider App economics remain separate. Corporate
support receives zero PHI and no persistent linkable claim fingerprint.
