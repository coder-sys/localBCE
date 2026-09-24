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
   +--> Continuity export --> isolated SHADOW / TEST restore; v7 receiver (tools/continuity_successor_v7.py)
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

The owner knows three store versions, `RR/FINANCIAL/OWNER/v5`, `v6` and `v7`
(new stores default to v7, which adds the population manifest and decision
package v2), each with its matching `RR/FINANCIAL/CONTINUITY/` package version.
Older (v2-v4) or unknown versions are rejected without mutation.

The evaluation receipt binds scope, evaluation/obligation/revision, Control
Pack id/version/digest, sorted evidence id/record-digest pairs, trusted
authority id/epoch/digest, time, result fields and digests. It carries
references only, never raw evidence. A determination binds the evaluation id,
its result digest and the expected revision against current and historical
state before the one atomic determination/action/outbox transition.

Missing, stale, malformed or unauthorized input raises a typed error and
changes nothing. The independent checker enforces actor roles against a
digest-bound roster.

## Lean decides, the owner commits

- **Correction transition** (`RR/FINANCIAL/CORRECTION-TRANSITION/v1`).
  `FinancialOwner.reject_offset_and_authorize_correction` encodes a `BLFCMD01`
  request, runs the pinned Lean executable through the contained process runner
  (`app/minimal_clearance_verifier_process.py`), decodes the `BLFCRES1` result,
  checks the accepted delta against its own reconstructed post-transition
  snapshot, and commits it inside its existing transaction. The release is an
  explicit immutable `FinancialCorrectionTransitionRelease`; without one, the
  command fails closed. There is no Python fallback decision.
- **Pinned executable:** `artifacts/engine-correction-e911/`. It was built from
  an older `lean/engine` source; see its `PROVENANCE.md`. The current
  `lean/engine` source must be rebuilt through the guard to replace it.
- **Evaluation comparison:** `BLFIN02`/`BLFRES02` in
  `app/right_rail_financial_engine.py` with
  `app/right_rail_financial_semantic_adapter.py` is a read-only comparison of
  the owner's evaluation against Lean. It never writes.
- **Lean sources:** `lean/engine/` (financial types, codec, evaluation,
  correction transition, decision package, theorems; executables
  `blind_financial`, `blind_financial_correction`, `blind_financial_axioms`)
  and `lean/state/` (the direct-state-owned clearance kernel).

## Mirror, Continuity and Switch

**Mirror** reads the owner with bounded pagination and sends authorized commands
back to it. It has no tables of its own and cannot invent cash, authority or
clearance. From one current decision package it derives the correction
follow-up explanation, a state report and a recipient-safe corporate-support
output; a bounded follow-up drain is repeatable, and an acknowledgment changes
follow-up status without changing cash.

**Continuity** exports a versioned, bounded package from the same owner. An
unexported admission table tracks exported row counts and canonical row bytes in
the same transaction, so the owner enforces the 10,000-row and 8 MiB limits
before commit; independent verification rebuilds that table from source rows.
Restore runs in a private attempt directory and publishes atomically without
replacing anything; a foreign destination and its `-wal`/`-shm` sidecars are
left intact and cleanup failures are reported. SHADOW opens read-only; TEST is
isolated; neither can dispatch, egress, become a live writer or replace an
identity. `tools/continuity_successor_v7.py` is an independent, integrity-only
receiver for v7 packages.

**Switch** takes only independently verified Continuity SHADOW bytes, gives the
same canonical input to a reference and a candidate evaluator supplied by the
caller, and reports the differences. It has no write API, live routing or
cutover.

**Staff server** is loopback-only and serves `app/staff_workspace/`. The
**service kit** (`tools/right_rail_financial_service_kit.py`) is the one
packager: it assembles, verifies, extracts, runs the end-to-end scenario and
serves the workspace from a digest-bound offline archive.

## Direct-state-owned clearance route

`app/direct_state_owned_clearance_v1.py` evaluates one canonical `BLSDRQ01`
request through the `lean/state` kernel (`app/semantic_kernel_binding.py`) and
commits through `app/transactional_database_boundary.py`. Only `CLEAR` or a valid
`EXCEPTION_APPROVED` may advance economic state; `HOLD`, `HUMAN_REVIEW` and
`BLOCK` cannot. `tools/semantic_assurance_gate.py` builds and checks the
separately pinned semantic kernel.

## Mirror Provider Trust Graph

`app/mirror/` is the read-only Provider Trust Graph wedge: a synthetic North
Carolina FHIR source adapter with an independent verifier, source admission, the
trust graph and its read model, and `MIRROR_PROVIDER_EVIDENCE_EXPORT_V1` (an
allowlist-only aggregate export with a separately written verifier). It never
creates a financial determination, clearance or action. Raw source bytes,
identifiers, paths and error text do not cross its boundary; failures use fixed
codes. `tools/provider_trust_graph_view.py` is a loopback browser view over it.

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

## Rejected directions

- BL-PQ512, H4, K128 and K512 proof layouts, monolithic STARK-era launch
  blockers and version-3-composite assumptions.
- L2, rollup, sequencer, bridge or Ethereum settlement; Cairo, Starknet or
  Solidity settlement code. Official state payment rails move funds.
- Caller-selected plaintext evaluation or any private-proof-to-plaintext
  downgrade; the approved profile fixes the evidence mode.
- Fixed-shape/AIR compatibility as a production authority.

The private zero-knowledge evidence mode and its native code are parked
(`parked/README.md`, `native/tools/README.md`).
