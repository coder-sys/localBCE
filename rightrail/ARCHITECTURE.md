# RightRail architecture

How the code fits together today. The target is
`docs/RIGHTRAIL_FULL_STACK_TARGET.md`; run status is only in `STATUS.md`.

## Shape

```text
Control Pack + population manifest
        |
        v
FinancialOwner (app/right_rail_financial_owner.py) -- the only writer, one SQLite db
   |  evidence -> evaluation -> determination -> action/outbox, committed atomically
   |<-- correction transition decided by Lean (pinned executable, via app/right_rail_financial_engine.py)
   |
   +--> independent checker (app/right_rail_financial_owner_independent.py), read-only
   +--> Mirror (app/right_rail_financial_mirror.py): queries and commands back into the owner
   |        +--> staff server + browser UI (app/right_rail_financial_staff_server.py, app/staff_workspace/)
   |        +--> CLI (tools/right_rail_financial_cli.py)
   +--> Continuity export --> isolated SHADOW / TEST restore
   +--> Switch (app/right_rail_financial_switch.py): read-only replay and comparison
```

Dispatch and egress are disabled; nothing here moves money.

## Financial owner

`FinancialOwner` is the single writer for populations, obligations, typed
evidence, evaluations, cases, determinations, corrections, balances and
action/outbox identity. Every command carries identity, authority, expected
revision and canonical input. History, current projection and outbox row commit
in one transaction. An exact retry returns `DUPLICATE`; changed input is a
conflict. Crashes before and after commit are recovered by restart; the
committed result is found again by its command identity.

Store version is `RR/FINANCIAL/OWNER/v8` with its `RR/FINANCIAL/CONTINUITY/v8`
package; owner and checker accept v8 only and reject any other without
mutation (`unsupported_store_version`).

The evaluation receipt binds scope, Control Pack id/version/digest, sorted
evidence id/record-digest pairs, trusted authority, time, and result fields and
digests: references only, never raw evidence. A determination binds the
evaluation id, its result digest and the expected revision before the one atomic
determination/action/outbox transition. Missing, stale, malformed or
unauthorized input raises a typed error and changes nothing; the independent
checker enforces actor roles against a digest-bound roster.

Every outer write checks current funding projections against their immutable
receipts under the same SQLite lock, before executing and before committing;
independent full replay still checks the whole store.

## Lean decides, the owner commits

- **Correction transition** (`RR/FINANCIAL/CORRECTION-TRANSITION/v1`, wire spec
 `conformance/CORRECTION_TRANSITION_WIRE.md`).
 `FinancialOwner.reject_offset_and_authorize_correction` encodes a `BLFCMD03`
 request (payment links, from which Lean derives paid-so-far), runs the pinned
 Lean executable through the contained process runner
 (`app/minimal_clearance_verifier_process.py`), decodes the `BLFCRES3` result,
 computes every storage digest itself, checks the accepted delta against its
 own reconstructed post-transition snapshot, and commits it inside its
 existing transaction. A zero shortfall is rejected with no mutation; the
 action amount is the lesser of the claim and the still-unrequested unpaid
 balance (theorem `applyCorrectionTransition_action_amount_eq_linked`).
- **Evaluation:** `evaluate_live` (`app/right_rail_financial_engine.py`) sends
 `BLFIN02` to the pinned worker; its `BLFRES02` answer is bound to the three
 writes and re-checked before COMMIT.
- **Pinned executable:** the evaluator worker (`artifacts/engine-evaluator/`)
 decides both. If it fails, the command fails closed; there is no Python
 fallback. Only the current pin decides new work; retired engines are in
 `artifacts/engine-correction/RETIRED_PINS`.
- **Lean sources:** `lean/`, one Lake workspace (package `RightRail`, library
 `BlindLedger`: financial types, codec, evaluation, correction transition,
 decision package, gate rules, theorems; four executables).
 `lean/tools/semantic_assurance_gate.py` checks the correction transition's pinned
 theorem statements, proofs and axioms.

## Mirror, Continuity and Switch

**Mirror** reads the owner with bounded pagination and sends authorized
commands back to it. It has no tables of its own and cannot invent cash,
authority or clearance. From one current decision package it derives the
follow-up explanation, a state report and a recipient-safe support output; an
acknowledgment changes follow-up status, never cash.

**Continuity** exports the history as chained, bounded segments
(`RR/GATE/SEGMENT/v1`, docs/CORE_REDESIGN.md), which the checker verifies and
a fresh owner restores by replay; the older whole-state package (8 MiB)
remains. Restore runs in a private attempt directory and publishes atomically
without replacing anything. SHADOW opens read-only; TEST is isolated; neither
can dispatch, egress, become a live writer or replace an identity.

**Switch** takes only independently verified Continuity SHADOW bytes, gives
the same canonical input to a reference and a caller-supplied candidate
evaluator, and reports the differences. It has no write API, live routing or
cutover.

**Staff server** is loopback-only and serves `app/staff_workspace/`. The
**service kit** (`tools/right_rail_financial_service_kit.py`) is the one
packager: it assembles, verifies, extracts, runs the end-to-end scenario and
serves the workspace from a digest-bound offline archive. The release producer
is parked in `parked/release-producer/` (see its README); the kit bundles the
script byte for byte. Staff cash evidence names the correction request it pays;
acknowledgment alone never provides that credit.

## Mirror Provider Trust Graph

`app/mirror/` is the read-only Provider Trust Graph wedge: a synthetic North
Carolina FHIR source adapter with an independent verifier, source admission, the
trust graph and its read model, and `MIRROR_PROVIDER_EVIDENCE_EXPORT_V1` (an
allowlist-only aggregate export with a separately written verifier). It never
creates a financial determination, clearance or action. Raw source bytes,
identifiers, paths and error text never cross its boundary; failures use fixed
codes. `tools/provider_trust_graph_view.py` is a loopback browser view over it.

Source intake takes a bounded captured envelope and independently supplied
capture context; all six values (subject, credential, enrollment, locator,
observation and fetch time) must match the independent source check before
admission, so a mismatch opens no server. The served projection keeps freshness
and source truth unknown.

## Provider App

`provider_app/` is a separate product: an in-memory pre-submission checker for
fictional provider facts (`provider_app/README.md`).

## Path to the payment gate

The target ([`docs/RIGHTRAIL_FULL_STACK_TARGET.md`](docs/RIGHTRAIL_FULL_STACK_TARGET.md))
is an inline gate on every payment. There is no integrated payer gate. Toward it:

- Lean decides every evaluated money field, every payment and reversal, and
 `reject_offset_and_authorize_correction`; Python still decides population,
 publishing, evidence, offset authorization, acknowledgment, follow-through,
 reporting and funding.
- The correction codec (`BLFCMD03`/`BLFCRES3`) proves canonicity (P2)
 unconditionally, round-trip (P1) and trailing-byte rejection (P3) only for
 admissible values; nothing yet proves every value Lean emits is admissible.
- There is no batch decide API, independent witness, fenced standby or Bypass
 outcome. ML-DSA-87 checkpoints, Merkle tokens and shard routing exist only as
 the gate-v1 codec, Lean model and `gate_verify` (no product caller).
- The correction transition starts one Windows process per call, which
 disqualifies it for gate throughput; only evaluation has a long-lived worker.

## Rejected directions

- L2, rollup, sequencer, bridge or Ethereum settlement; Cairo, Starknet or
 Solidity settlement code. Official state payment rails move funds.
- Caller-selected plaintext evaluation or any private-proof-to-plaintext
 downgrade; the approved profile fixes the evidence mode.
- BL-PQ512, H4, K128 and K512 proof layouts and fixed-shape/AIR compatibility
 as a production authority.

Private zero-knowledge is an evidence-only prototype in its own repository
(Constitution IX.4).
