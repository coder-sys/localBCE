# RightRail architecture

How the code in this trunk fits together today. The target is
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

Evidence, evaluation, official determination, authorized action, dispatch,
receiver acknowledgment, cash and reporting are separate records. An
acknowledgment never marks cash. Dispatch and egress are disabled; nothing here
moves money.

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
(v2-v7, unknown) is rejected without mutation, owner open with
`unsupported_store_version`. The v7 conversion path was removed 2026-09-25
(decision C3; only synthetic data ever existed), so a v8 store converted from
v7 (contains an `OPENING_BALANCE` event) now fails `history:event-kind`.

The evaluation receipt binds scope, evaluation/obligation/revision, Control
Pack id/version/digest, sorted evidence id/record-digest pairs, trusted
authority id/epoch/digest, time, result fields and digests — references
only, never raw evidence. A determination binds the evaluation id, its
result digest and the expected revision against current and historical
state before the one atomic determination/action/outbox transition.

Missing, stale, malformed or unauthorized input raises a typed error and
changes nothing. The independent checker enforces actor roles against a
digest-bound roster.

Every outer write now checks current funding projections against their
immutable receipts, indexed funding events, successor status and root
coverage under the same SQLite lock, before executing and before
committing; the funding summary checks within its read snapshot. This
bounded check scans current funding sources, not the complete event
history, and runs twice per batch rather than per nested command — it
detects current-projection drift, while independent full replay still
checks historical rows, digests and the whole store. Felt effect: finance
staff cannot continue recording work or read a funding total once its
stored values have drifted from the recorded receipts. No new persistent
format or trust root.

## Lean decides, the owner commits

- **Correction transition** (`RR/FINANCIAL/CORRECTION-TRANSITION/v1`).
 `FinancialOwner.reject_offset_and_authorize_correction` encodes a `BLFCMD02`
 request, runs the pinned Lean executable through the contained process runner
 (`app/minimal_clearance_verifier_process.py`), decodes the `BLFCRES3` result,
 computes every storage digest itself, checks the accepted delta against its
 own reconstructed post-transition snapshot, and commits it inside its
 existing transaction. A zero shortfall is rejected with no mutation; the
 action amount is exactly the lesser of the claim and the unpaid balance
 that earlier correction requests, less what linked payments paid on them,
 do not already ask for (theorem `applyCorrectionTransition_action_amount_eq_b2`). The release is an
 explicit immutable `FinancialCorrectionTransitionRelease`; without one, the
 command fails closed. There is no Python fallback decision.
- **Pinned executable:** `artifacts/engine-correction/`, rebuilt twice
 byte-identically from the `lean/` commit its `PROVENANCE.md` names. Engines
 a re-pin retired are listed in its digest-pinned `RETIRED_PINS`: their
 committed follow-ups stay valid history, but only the current pin decides;
 a retired engine never decides after a newer one, and no correction, whatever
 engine decided it, requests more than was then requestable.
- **Evaluation comparison:** `BLFIN02`/`BLFRES02` in
 `app/right_rail_financial_engine.py` with
 `app/right_rail_financial_semantic_adapter.py` is a read-only comparison of
 the owner's evaluation against Lean. It never writes.
- **Lean sources:** `lean/`, one Lake workspace (package `RightRail`, library
 `BlindLedger`: financial types, codec, evaluation, correction transition,
 decision package, theorems, semantic kernel; executables `blind_financial`,
 `blind_financial_correction`, `blind_financial_axioms`,
 `blind_semantic_kernel`). `tools/semantic_assurance_gate.py` checks the
 correction transition's pinned theorem statements, proofs and axioms.

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
`-wal`/`-shm` sidecars are left intact and cleanup failures are reported.
SHADOW opens read-only; TEST is isolated; neither can dispatch, egress,
become a live writer or replace an identity.

**Switch** takes only independently verified Continuity SHADOW bytes, gives
the same canonical input to a reference and a candidate evaluator supplied
by the caller, and reports the differences. It has no write API, live
routing or cutover.

**Staff server** is loopback-only and serves `app/staff_workspace/`. The
**service kit** (`tools/right_rail_financial_service_kit.py`) is the one
packager: it assembles, verifies, extracts, runs the end-to-end scenario and
serves the workspace from a digest-bound offline archive. Its current
release producer and kit inventory bind the current vectors, retired-pin
registry and fresh guarded engine receipt. The kit checks canonical source
paths and the exact v4 guard records with either LF or Windows CRLF line
endings; raw log bytes remain digest-bound. Current exercised archives are
recorded in provenance. Staff cash evidence names the correction request it
pays; acknowledgment alone never provides that credit. The synthetic staff
clock advances to the explicit decision time before issuing the correction.
New demo acknowledgments therefore follow the action they acknowledge,
including after a lost response; existing history stays intact.

The HTTP adapter accepts exactly one length and content-type header, no
transfer encoding, and at most 8,192 bytes within a five-second total body
deadline before dispatch. Refusals flush their response, then drain at most
8,193 unread bytes for 100 ms before closing; HEAD sends no body — this
preserves ordinary Windows refusal responses without letting a slow sender
hold the refusal path open. Felt effect: staff get a defined refusal and
can retry from the current record; malformed or incomplete requests cannot
reach an owner command.

Second-state reuse still needs coordinated owner, checker and Lean changes:
`Types.lean:controlPackRulesWellFormed` also pins the Hospital H test
labels. The proposed Python-only policy-table edit would disagree with the
pinned engine. Keep approved rule/version/role checks, bounded local test
labels and digest binding together, then rebuild and test a distinct state
through correction and Continuity before claiming reuse. The staff server's
H labels are fixture data.

## Direct-state-owned clearance route (parked)

Parked in `parked/state_clearance/`: `app/direct_state_owned_clearance_v1.py`
evaluates one canonical `BLSDRQ01` request through the State kernel (`lean/`
StateKernel library, `rust/` process adapter; `app/semantic_kernel_binding.py`)
and commits through `app/transactional_database_boundary.py`. Only `CLEAR` or a
valid `EXCEPTION_APPROVED` may advance economic state; `HOLD`, `HUMAN_REVIEW`
and `BLOCK` cannot.

## Mirror Provider Trust Graph

`app/mirror/` is the read-only Provider Trust Graph wedge: a synthetic North
Carolina FHIR source adapter with an independent verifier, source admission, the
trust graph and its read model, and `MIRROR_PROVIDER_EVIDENCE_EXPORT_V1` (an
allowlist-only aggregate export with a separately written verifier). It never
creates a financial determination, clearance or action. Raw source bytes,
identifiers, paths and error text do not cross its boundary; failures use fixed
codes. `tools/provider_trust_graph_view.py` is a loopback browser view over it.

The source-intake connection takes a bounded captured envelope and independently
supplied capture context (subject, credential, enrollment, locator, observation
time and fetch time). All six values must match the independent source check
before admission. Only the admitted graph reaches the existing read-model and
export verification gates; the served projection keeps freshness and source
truth unknown. Failed capture or context mismatch opens no server. This path
has no writes, network fetch, cache or financial authority; retry recomputes the
same verified projection. Felt effect: the implementation lead can inspect a
capture directly during onboarding, removing the manual graph-file handoff and
its troubleshooting. Raw captures and identities remain outside HTTP responses.
Both CLIs accept `--source-envelope PATH --capture-context SUBJECT CREDENTIAL
ENROLLMENT LOCATOR OBSERVED FETCHED` instead of `--artifact PATH`, alongside the
existing `--request`, `--operation-ref` and `--now`. The four identities are
opaque 128-character hex values from the capture configuration. Comparison uses
the same options with the existing `compare-` (browser) or `left-`/`right-`
(read-model CLI) prefixes. Context must come from that configuration, not from
parsing the untrusted envelope. This is file intake for the fixed synthetic
profile; no authenticated live-fetch or financial-file adapter is implied.

## Provider App

`provider_app/` is a separate product: an in-memory pre-submission checker for
fictional provider facts with `PASS` / `MISSING` / `HUMAN_CHECK` outcomes, an
independent result checker and a Lean comparison path. See
`provider_app/README.md`.

## Rules that shape the code

- Lean semantics run in the deployed path or not at all; a Lean failure never
 falls back to a second implementation. Runtime/Lean disagreement fails closed.
- Money is integer cents; ordering, encodings and identities are canonical.
- Every input, package, query and process has an explicit bound.
- No PHI leaves the state boundary. Support uses approved fields and synthetic
 reproductions.
- Heavy runs go through `native/guard/` only.

## Path to the payment gate

The target end state
([`docs/RIGHTRAIL_FULL_STACK_TARGET.md`](docs/RIGHTRAIL_FULL_STACK_TARGET.md))
is Blind Ledger as an inline gate every FFS and managed-care payment passes
before money goes out, at full state scale. There is no integrated payer gate.
What exists today toward it:

- Lean decides one of 14 command types
 (`reject_offset_and_authorize_correction`); Python still decides
 population, evidence, payment/reversal, offset authorization,
 acknowledgment, reporting, funding and evaluation recording.
- The live correction codec (`BLFCMD02`/`BLFCRES3`) proves canonicity (P2)
 unconditionally, but round-trip (P1) and trailing-byte rejection (P3) only
 for admissible values; nothing yet proves every value Lean emits is
 admissible.
- There is no batch decide API, no ML-DSA-87 checkpoint signing, no
 Merkle-inclusion token, no independent witness, no member-key sharding, no
 fenced primary/standby, and no Bypass outcome.
- The subprocess-per-decision path
 (`app/minimal_clearance_verifier_process.py`, one Windows process per
 call, serialized to one core) is disqualifying for gate throughput; it
 needs replacing with a long-lived worker pool, not optimizing in place. No
 warm-worker throughput benchmark has been run.
- There is no CI, on-call rotation, or tested failover drill; `native/guard/`
 runs one heavy job at a time on one laptop.

See the target document for the authority ladder, gate points, batch
signing, fail policy and bypass, sharding, the proof boundary, evidence
modes, and post-quantum crypto choices, and for which of those are still
unresolved at their authority and recovery boundaries. The separate `gate-v1`
branch contains format, signature and Lean verification work; it has not been
connected here to signed grant admission, durable payer state or the rules path.

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
