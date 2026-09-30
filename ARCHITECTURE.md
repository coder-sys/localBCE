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

Dispatch and egress are disabled; nothing here moves money, and an
acknowledgment never marks cash (the record kinds are separate: Constitution II).

## Financial owner

`FinancialOwner` is the single writer for populations, obligations, typed
evidence, evaluations, cases, determinations, corrections, balances and
action/outbox identity. Every command carries identity, authority, expected
revision and canonical input. History, current projection and outbox row commit
in one transaction. An exact retry returns `DUPLICATE`; changed input is a
conflict. Crashes before and after commit are recovered by restart; the
committed result is found again by its command identity.

The owner writes one store version, `RR/FINANCIAL/OWNER/v8` (population
manifest, program funding receipts, decision package v2, the exported
`commands` log and declared foreign keys), with its matching
`RR/FINANCIAL/CONTINUITY/v8` package (founder approval 2026-09-24). Owner and
independent checker accept v8 stores/packages only; every other version
is rejected without mutation, owner open with `unsupported_store_version`; a
converted v7 store (an `OPENING_BALANCE` event) fails `history:event-kind`.

The evaluation receipt binds scope, evaluation/obligation/revision, Control
Pack id/version/digest, sorted evidence id/record-digest pairs, trusted
authority id/epoch/digest, time, result fields and digests — references
only, never raw evidence. A determination binds the evaluation id, its
result digest and the expected revision against current and historical
state before the one atomic determination/action/outbox transition.

Missing, stale, malformed or unauthorized input raises a typed error and
changes nothing; the independent checker enforces actor roles against a
digest-bound roster.

Every outer write checks current funding projections against their immutable
receipts, indexed funding events, successor status and root coverage under the
same SQLite lock, before executing and before committing; the funding summary
checks within its read snapshot. It scans current funding sources twice per
batch and detects current-projection drift; independent full replay still
checks historical rows, digests and the whole store.

## Lean decides, the owner commits

- **Correction transition** (`RR/FINANCIAL/CORRECTION-TRANSITION/v1`).
 `FinancialOwner.reject_offset_and_authorize_correction` encodes a `BLFCMD03`
 request (payment links, from which Lean derives paid-so-far), runs the pinned Lean executable through the contained process runner
 (`app/minimal_clearance_verifier_process.py`), decodes the `BLFCRES3` result,
 computes every storage digest itself, checks the accepted delta against its
 own reconstructed post-transition snapshot, and commits it inside its
 existing transaction. A zero shortfall is rejected with no mutation; the
 action amount is exactly the lesser of the claim and the unpaid balance
 that earlier correction requests, less what linked payments paid on them,
 do not already ask for (theorem `applyCorrectionTransition_action_amount_eq_linked`). The release is an
 explicit immutable `FinancialCorrectionTransitionRelease`; without one, the
 command fails closed. There is no Python fallback decision.
- **Pinned executable:** `artifacts/engine-correction/`, built by the release
 producer from the exact source its `PROVENANCE.md` records (commit and
 file manifest); a later `lean/` change is not covered. Engines
 a re-pin retired are listed in its digest-pinned `RETIRED_PINS`: their
 committed follow-ups stay valid history, but only the current pin decides;
 a retired engine never decides after a newer one, and no correction, whatever
 engine decided it, requests more than was then requestable.
- **Evaluation:** Lean decides. `evaluate_live` (`app/right_rail_financial_engine.py`)
 sends `BLFIN02` to the pinned worker (`artifacts/engine-evaluator/`); its `BLFRES02`
 answer is bound to the three writes and re-checked before COMMIT. A bad worker
 refuses the write; no Python fallback.
- **Lean sources:** `lean/`, one Lake workspace (package `RightRail`, library
 `BlindLedger`: financial types, codec, evaluation, correction transition,
 decision package, gate rules, theorems; four executables).
 `lean/tools/semantic_assurance_gate.py` checks the correction transition's pinned
 theorem statements, proofs and axioms.

## Mirror, Continuity and Switch

**Mirror** reads the owner with bounded pagination and sends authorized
commands back to it. It has no tables of its own and cannot invent cash,
authority or clearance. From one current decision package it derives the
correction follow-up explanation, a state report and a recipient-safe
corporate-support output; a bounded follow-up drain is repeatable, and an
acknowledgment changes follow-up status without changing cash.

**Continuity** exports the history as chained, bounded segments
(`RR/GATE/SEGMENT/v1`, docs/CORE_REDESIGN.md), which the checker verifies and
a fresh owner restores by replay; the older whole-state package (8 MiB)
remains. Restore runs in a private attempt directory and publishes
atomically without replacing anything; a foreign destination and its
`-wal`/`-shm` sidecars stay intact and cleanup failures are reported.
SHADOW opens read-only; TEST is isolated; neither can dispatch, egress,
become a live writer or replace an identity.

**Switch** takes only independently verified Continuity SHADOW bytes, gives
the same canonical input to a reference and a candidate evaluator supplied
by the caller, and reports the differences. It has no write API, live
routing or cutover.

**Staff server** is loopback-only and serves `app/staff_workspace/`. The
**service kit** (`tools/right_rail_financial_service_kit.py`) is the one
packager: it assembles, verifies, extracts, runs the end-to-end scenario and
serves the workspace from a digest-bound offline archive. Its release
producer and inventory bind the current vectors, retired-pin registry and a
fresh guarded engine receipt. The kit checks canonical source paths and the
exact v4 guard records under LF or CRLF endings (raw log bytes stay
digest-bound); exercised archives are in provenance. Staff cash evidence names the correction request it
pays; acknowledgment alone never provides that credit. The synthetic staff
clock advances to the explicit decision time before issuing the correction, so
new demo acknowledgments follow their action, even after a lost response.

The HTTP adapter accepts exactly one length and content-type header, no
transfer encoding, and at most 8,192 bytes within a five-second total body
deadline. Refusals flush, then drain at most 8,193 unread bytes for 100 ms
before closing; HEAD sends no body, so a slow sender cannot hold a refusal open.

## Direct-state-owned clearance route (parked)

`parked/state_clearance/` (`parked/README.md`): only `CLEAR` or a valid
`EXCEPTION_APPROVED` may advance economic state; `HOLD`, `HUMAN_REVIEW` and
`BLOCK` cannot.

## Mirror Provider Trust Graph

`app/mirror/` is the read-only Provider Trust Graph wedge: a synthetic North
Carolina FHIR source adapter with an independent verifier, source admission, the
trust graph and its read model, and `MIRROR_PROVIDER_EVIDENCE_EXPORT_V1` (an
allowlist-only aggregate export with a separately written verifier). It never
creates a financial determination, clearance or action. Raw source bytes,
identifiers, paths and error text never cross its boundary; failures use fixed
codes. `tools/provider_trust_graph_view.py` is a loopback browser view over it.

Source intake takes a bounded captured envelope and independently supplied
capture context (subject, credential, enrollment, locator, observation and fetch
time); all six values must match the independent source check before admission.
Only the admitted graph reaches the read-model and export verification gates;
the served projection keeps freshness and source truth unknown. A failed capture
or context mismatch opens no server; retry recomputes the same projection. Both CLIs accept `--source-envelope` and
`--capture-context` (see `--help`) instead of `--artifact PATH`; the four
identities are opaque 128-character hex values from the capture configuration,
never parsed from the untrusted envelope. File intake for the fixed synthetic
profile only; no live fetch or financial-file adapter.

## Provider App

`provider_app/` is a separate product: an in-memory pre-submission checker for
fictional provider facts with `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, an
independent result checker and a Lean comparison path. See
`provider_app/README.md`.

## Path to the payment gate

The target end state
([`docs/RIGHTRAIL_FULL_STACK_TARGET.md`](docs/RIGHTRAIL_FULL_STACK_TARGET.md))
is Blind Ledger as an inline gate every FFS and managed-care payment passes
before money goes out, at full state scale. There is no integrated payer gate.
What exists today toward it:

- Lean decides every evaluated money field and one of 18 command types
 (`reject_offset_and_authorize_correction`); Python still decides
 population, Control Pack publishing, evidence, payment/reversal, offset
 authorization, acknowledgment, follow-through decisions, reporting and
 funding, and records what Lean decided.
- The live correction codec (`BLFCMD03`/`BLFCRES3`) proves canonicity (P2)
 unconditionally, round-trip (P1) and trailing-byte rejection (P3) only for
 admissible values; nothing yet proves every value Lean emits is admissible.
- There is no batch decide API, independent witness, fenced standby or Bypass
 outcome; ML-DSA-87 checkpoints, Merkle tokens and shard routing exist only as
 the gate-v1 codec, Lean model and `gate_verify` (no product caller).
- The correction transition still starts one Windows process per call, disqualifying
 for gate throughput; only evaluation has a long-lived worker; no pool benchmark exists.

Gate-v1's formats and Lean payer checks are not connected to signed grant
admission, durable payer state or the rules path.

## Rejected directions

- BL-PQ512, H4, K128 and K512 proof layouts, monolithic STARK-era launch
 blockers and version-3-composite assumptions.
- L2, rollup, sequencer, bridge or Ethereum settlement; Cairo, Starknet or
 Solidity settlement code. Official state payment rails move funds.
- Caller-selected plaintext evaluation or any private-proof-to-plaintext
 downgrade; the approved profile fixes the evidence mode.
- Fixed-shape/AIR compatibility as a production authority.

Private zero-knowledge is an active evidence-only prototype in its separate
repository (Constitution IX.4). The old native code under `parked/` remains
historical reference, not the current prototype or a core-product dependency.
