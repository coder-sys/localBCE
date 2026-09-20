# Agent instructions for RightRail financial workflow

Status: current child rules, updated 2026-09-20. The pre-edit body remains
immutable at `../instruction-history/financial-AGENTS-20260913.original.txt`;
the 2026-09-19 edit receipt is `../instruction-history/20260919-pre-edit.txt`.

## Scope, precedence, and read order

Work only in this checkout unless the Driver explicitly names another path:

`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-financial-workflow-20260913`

The latest explicit assignment governs first, followed by the Driver
`AGENTS.md`, this file, `CURRENT_TASK.md`, `STATE.md`, `README.md`,
`ARCHITECTURE.md`, the roadmap, and named technical authorities. After context
loss, recheck the actual path, Git root, branch, commit, tree, status, and any
expected hash before mutation. `CURRENT_TASK.md` owns the bounded objective;
`STATE.md` owns verified evidence and nonclaims; architecture and named docs
own their technical boundaries.

## Current working boundary

The checkout is branch `rightrail-financial-workflow-20260913`. Git HEAD,
tree, and status are authoritative for the current State integration; the
previous handoff parent was `06070168fd180a1173bb6426cbf7cbdbc33bc67a` /
tree `c52630fd511ebe3b1ca32b2390a289c3a07746a6`. The corrected v5 owner,
checker, Mirror, CLI, Continuity tests, and this maintained documentation
reconciliation are the explicit delivery. The current source/test edits are:

- `app/right_rail_financial_owner.py`
- `tests/test_right_rail_financial_acceptance.py`
- `tests/test_right_rail_financial_mirror.py`

The seven maintained child Markdown files are the documentation portion of the
same delivery. Preserve the two untracked driver-supplied executables under
`build-performance/`; never stage, rewrite, regenerate, or delete them.

The working Python owner, independent checker, Mirror, CLI, and Continuity
contract is v5: `RR/FINANCIAL/OWNER/v5` and
`RR/FINANCIAL/CONTINUITY/v5`. v2/v3/v4 stores and packages remain preserved
historical inputs and reject fail-closed without mutation. The current Python
owner remains the sole transaction authority; the active Lean pivot is a
design/extraction workstream, not a runtime authority switch.

## Product boundary and invariants

This is a synthetic, state-local financial-responsibility workflow with five
responsibilities: State Control Pack, Blind Ledger, same-owner Mirror, bounded
Continuity State, and deferred Switch. It records obligations, typed evidence,
evaluations, determinations, authorized actions, delivery, and descriptive
cash/reporting facts. It never moves money, authorizes a live payment, or
becomes an official processor.

The required owner boundary keeps the owner as the sole writer for obligations,
evaluations, cases,
determinations, corrections, balances, and action/outbox identity. Mirror
commands and queries that owner. Evidence, official determination, action,
acknowledgment, and cash/reporting completion are separate facts; an
acknowledgment is never cash receipt. The required Continuity boundary is
versioned, query-only SHADOW or isolated TEST/non-live; dispatch and egress
must remain disabled, with no second live writer.

The fixed fixture is twenty hospitals and $1,000,000 total: H is $100,000 and
the other nineteen total $900,000. Expected cents are hand-derived. Preserve
Queue schema 13/Profile 12, Composition schema 4, the exact 100-reference
protocol, source ownership/reservation, Queue/State/outbox atomicity, the
non-`CLEAR` guard, and all native/C/crypto/Lean boundaries.

Current claims are `proofSuiteId=null`, `production_usable=false`,
`activation=false`, `NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED`, synthetic,
nonpayment, and non-PHI. No Lean executable linkage, native verification-to-
commit, independent audit, real data/PHI, live dispatch, payment movement, or
whole-system qualification follows from this checkout.

## Versioned owner contract

The required v5 evaluation contract includes `current_evaluation_receipt(item_id)`
and the same receipt from `evaluate_obligation`. The receipt contract is
`RR/FINANCIAL/EVALUATION-RECEIPT/v1`; it binds scope, evaluation/obligation/
revision, Control Pack identity, sorted unique evidence id/record-digest
bindings, trusted authority identity, timestamp, all result fields, result
digest, and receipt digest. It carries references and digests only, never raw
evidence or signatures.

The required v5 determination contract binds explicit evaluation identity/
digest and expected revision to the current and historical evaluation, receipt,
projection, evidence coverage/chronology, Control Pack, and authority before
one atomic determination/action/outbox transition. Exact retries must be
`DUPLICATE`; changed identity or input must be conflict. The bounded Python v5
slice is implemented and locally re-verified for the current correction
packet; Driver disposition remains NOT ACCEPTED pending review of the source
and raw evidence. This does not qualify the wider Driver, native, Lean, or
production boundaries; see `STATE.md` for the evidence and remaining gates.
There is no separate verification-attempt, lease, receipt-consumption, or
Queue-reservation boundary; claimed-adjustment business state and Queue
reservations remain separate.

## Ownership and protected paths

State owns source, tests, fixtures, build outputs, logs, and generated evidence.
The following remain owner-gated unless an exact future assignment names the
path, checks, and evidence:

- `app/minimal_clearance_verification_queue.py`
- `app/minimal_clearance_verification_queue_independent.py`
- `app/minimal_clearance_composition.py`
- `app/minimal_clearance_composition_independent.py`
- `experiments/longfellow_v09_native_v3/`
- `app/mirror/`

## Resource and documentation policy

Use the existing guarded wrapper for any authorized execution:

`..\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v3.ps1`

Wrapper SHA-256:
`A9D3496E3789F16182D3F6946860BC7454F86AEC407FB9BFFE352D1F4FED7FE1`.
Preserve its cap, reserve, mutex, and backups. Documentation-only batches
launch no build, compiler, test, checker, native, or Lean process. The current
explicit State integration additionally names the three source/test paths
above; otherwise the seven maintained Markdown files are the only documentation
scope. Do not edit fixtures, generated executables, raw logs, proof artifacts,
native/C/crypto/Lean/Queue/Composition paths, operations policy, archives,
secrets, or another work root. Integrate only explicitly scoped paths in a
known-path commit and preserve the protected executables.

Before mutation, verify containment, ownership, expected identities, and Git
state. Never use reset, clean, destructive checkout, broad deletion, or
automatic staging. Preserve substantive warnings/failures in raw evidence or
Git history and report exact changed paths, hashes, link/diff checks, skips,
and remaining blockers. “Ran successfully” is not “verified.”
