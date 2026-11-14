# RightRail architecture

A map of the code today, for engineers new to the repository, and the owner of
the product list. The target and the rollout are in
`docs/RIGHTRAIL_FULL_STACK_TARGET.md`; what runs is in `STATUS.md`.

## The six products

One evidence record is the product; these are the six ways it is used. Each
section below says what is built.

| Product | What it is |
|---|---|
| State Control Pack | The state-approved rules and population, signed by the state, and the bounded export and restore of the record (Continuity is part of it, not a product) |
| Blind Ledger | The operating record: the one writer of financial facts, with the independent checker and the formally verified gate core. Its end-state function is the inline payment gate on every payment |
| Mirror | The read-only workspace for finance staff, caseworkers and county offices (side by side; the decision stays the worker's; the view records what was shown) |
| Switch | Read-only replay of the record against a candidate system, before a replacement goes live |
| Provider App | A retail pre-submission checker sold to providers; nothing state-side depends on it |
| Provider Trust Graph | Read-only provider evidence from public sources; its own product, not part of Mirror |

The first paid jobs and the rollout order are owned by
`docs/RIGHTRAIL_FULL_STACK_TARGET.md` section 2; pricing by Constitution Article VIII.

## Shape

```text
Control Pack + population manifest
        |
        v
FinancialOwner (app/right_rail_financial_owner.py) -- the only writer; today one SQLite db per owner
   |  evidence -> evaluation -> determination -> action/outbox, committed atomically
   |<-- correction transition decided by Lean (pinned executable, via app/right_rail_financial_engine.py)
   |
   +--> independent checker (app/right_rail_financial_owner_independent.py), read-only
   +--> Mirror (app/right_rail_financial_mirror.py): queries and commands back into the owner
   |        +--> staff server + browser UI (app/right_rail_financial_staff_server.py, app/staff_workspace/)
   |        +--> CLI (tools/right_rail_financial_cli.py)
   +--> history export (Control Pack and Blind Ledger) --> isolated SHADOW / TEST restore
   +--> Switch (app/right_rail_financial_switch.py): read-only replay and comparison
```

Dispatch and egress are disabled; no money moves.

## Financial owner

`FinancialOwner` is the only writer for populations, obligations, typed
evidence, evaluations, cases, determinations, corrections, balances and
action/outbox identity. Every command carries identity, authority, expected
revision and canonical input. History, current projection and outbox row commit
in one transaction. An exact retry returns `DUPLICATE`; changed input is a
conflict. Restart recovers crashes before and after commit; the committed
result is found again by its command identity.

Store version is `RR/FINANCIAL/OWNER/v8` with its `RR/FINANCIAL/CONTINUITY/v8`
package; owner and checker accept v8 only and reject any other without
mutation (`unsupported_store_version`). One store for the gate and the ledger
is decided and in progress (`docs/STATE_EVIDENCE_ARCHITECTURE.md` section 12);
this section describes the store that runs today.

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
 decision package, gate rules, the history engine in `Gate/Engine3`, the frame codec in
 `Gate/Frame` and the store in `Gate/Flat`, theorems; 19 executables, of which three are pinned:
 the financial worker (`artifacts/engine-evaluator/`), `gate_verify` (`artifacts/gate-verify/`)
 and `gate_engine` (pin in `tools/tcb_report.txt`); the history engine `gate_hist3` is built
 and tested but not pinned, and the rest are test tools).
 `lean/tools/semantic_assurance_gate.py` checks the correction transition's pinned
 theorem statements, proofs and axioms.

## Mirror, the export and Switch

**Mirror** serves finance staff, caseworkers and county offices. It reads the owner with bounded pagination and sends authorized
commands back to it. The caseworker and county views are designed, not built
(`docs/STATE_EVIDENCE_ARCHITECTURE.md` roles). It has no tables of its own and cannot invent cash,
authority or clearance. From one current decision package it derives the
follow-up explanation, a state report and a recipient-safe support output; an
acknowledgment changes follow-up status, never cash.

**The export** (called Continuity in the code) exports the history as chained, bounded segments
(`RR/GATE/SEGMENT/v1`, `conformance/SEGMENT_V1.md`), which the checker verifies and
a fresh owner restores by replay; the older whole-state package (8 MiB)
remains. Restore runs in a private attempt directory and publishes atomically
without replacing anything. SHADOW opens read-only; TEST is isolated; neither
can dispatch, egress, become a live writer or replace an identity.

**Switch** takes only independently verified SHADOW bytes, gives
the same canonical input to a reference and a caller-supplied candidate
evaluator, and reports the differences. It has no write API, live routing or
cutover.

**Staff server** is loopback-only and serves `app/staff_workspace/`. The
**service kit** (`tools/right_rail_financial_service_kit.py`) is the one
packager: it assembles, verifies, extracts, runs the end-to-end scenario and
serves the workspace from a digest-bound offline archive. The release producer
is kept in `parked/release-producer/` until a release is planned (see its
README); the kit bundles the script byte for byte. Staff cash evidence names the correction request it pays;
acknowledgment alone never provides that credit.

## Provider Trust Graph

`app/mirror/` holds the read-only Provider Trust Graph, its own product: a synthetic North
Carolina FHIR source adapter with an independent verifier, source admission, the
trust graph and its read model, and the provider evidence export
(`app/mirror/provider_evidence_export_v1.py`, an allowlist-only aggregate export
with a separately written verifier). It never
creates a determination, clearance or action. Raw source bytes,
identifiers, paths and error text never cross its boundary; failures use fixed
codes. `tools/provider_trust_graph_view.py` is a loopback browser view over it.

Source intake takes a bounded captured envelope and independent capture context; all six values (subject, credential, enrollment, locator,
observation and fetch time) must match the independent source check before
admission, so a mismatch opens no server. The served projection keeps freshness and source truth unknown.

## Provider App

`provider_app/` is a retail in-memory pre-submission checker for fictional provider facts (`provider_app/README.md`). Nothing in `app/` depends on it.

## Financial core rules: history segments and the receiver cash file

Rules for two built parts of the payer app. Read before changing either. Protected-change records:
`git log --grep '^XI.2:'`. Store format: v8 only; v7 conversion and `OPENING_BALANCE` are retired. Open: more
transitions move to Lean.

Also protected, beyond the list in CONSTITUTION XI.2 (V.4: protected answers): `tests/rightrail_financial_expected_cases.py`,
Lean KAT/vector files, `artifacts/engine-correction/vectors/`, the correction engine pin, wire formats and digest
domains, theorem statements, and `tests/test_right_rail_financial_constitution_invariants.py`.

### History segments

Ceiling: 10,000 events, because Lean's `maxRows`/`maxRevision` (Types.lean) bound what the proof and checker accept.
The owner refuses the 10,001st event, revision or row of any table with `history_capacity` before commit. Raising it
is a Lean change. The 8 MiB package export stays, refused at export, not at write.

- Domain `RR/GATE/SEGMENT/v1` (one format for Continuity and the gate; the byte-level owner is `conformance/SEGMENT_V1.md`, which wins on any difference): SHA3-512 over `RR/GATE/SEGMENT/v1\0` and
  length-prefixed parts; `projection_root = D("rows", rows)`, `segment_digest = D("seal", seal)`,
  `manifest_digest = D("manifest", body)`; canonical JSON.
- Seal: `format`, `segment_index`, `first_sequence`, `last_sequence`, `event_count`, `previous_digest` (zero for
  segment 0), `event_head`, `projection_root`. A segment file adds its events, the sorted final images of the rows
  they touched, `segment_digest`, and a reserved `signature` (null, outside the digest).
- Bounds: seal after the write reaching 4,096 events or 4 MiB. A write carrying the open segment past 10,000 events
  or 16 MiB fails `history_segment_size`.
- Writes note touched rows in `history_pending`: O(this write) (IX.3). Older v8 stores are replayed on open and
  sealed as segment 0. The checker recomputes sealed segments' chain, counts and event heads; sealed rows are
  append-only.
- `export_history`: one fsynced file per segment; an existing file is compared, never rewritten.
  `restore_continuity(history=...)`: the checker verifies manifest, chains and seals; a fresh owner replays each
  segment and must reseal it byte-identically.
- Next: a Lean codec for the seal with a round-trip proof; then the signature.

### Receiver cash-file boundary (XI.2)

An operator previews one fictional receiver file against the reviewed ledger, then records its cash
evidence as one transaction: no repeated manual entry, exact retries, a refused row held alone. No money moves.

- Contract: `RR/FINANCIAL/RECEIVER-CASH-FILE/v1`, canonical ASCII JSON of at most 1 MiB, 1-500 ordered rows, at most
  6 per item (more: `cash_file_row_cap`). Root fields: `contract`, `source_class` (`SYNTHETIC_RECEIVER_CASH`),
  `scope`, `source`, `row_count`, `total_cents`, `rows`. Each row has exactly eight fields: `item_id`, `payment_id`,
  `common_origin_id`, `evidence_id`, `amount_cents`, `event_at_ms`, `pays_action_id` (null or an ID),
  `expected_revision`. The code (`app/right_rail_financial_cash_file.py`) holds the field grammar and number bounds.
- Refuse completely: duplicate JSON keys, missing or extra fields, noncanonical bytes, duplicate payment/evidence
  IDs or item/origin pairs, count/total disagreement. MCO reports, X12 820/835 and MMIS extracts are unsupported.
  Untrusted input never drops a row unreceipted or turns acknowledgment or reporting into cash.
  No caller-provided callback or success flag authorizes acceptance.
- Evidence: `record_payment_evidence` can return CONFLICT or an alias DUPLICATE after recording evidence, and
  `run_batch` rolls back exceptions, not those statuses. So the final check must follow history sealing and precede
  COMMIT.
- Binding: the caller supplies trusted scope, source context, source SHA-256, baseline SHA-256, owner ID/mode and
  authority. F is the exact file bytes; B is the exact `manifest.json` bytes that `export-history` wrote. Every derived command binds `local_ref = UPPER(SHA256(F)) || UPPER(SHA256(B))`. A retry never replaces B
  with a fresh export. The verifier does not import the producer. It accepts B only if canonical and it passes the
  export verifier's manifest checks (`_verify_manifest`).
- Under one BEGIN IMMEDIATE, the store must match B: same identity row and event head at B's sequence, and B's
  `segment_count` and `last_segment_digest` equal the live `history_segments` row sealed there. A row's `expected_revision` decides (Rows).
- After final sealing the checker verifies row and command order, each new event onto the chain, payment/evidence/
  action links, revisions, every table's before/after difference and per-item cash deltas, then runs its own rules on
  the touched obligations. Other cash, acknowledgments and reporting stay unchanged. A file with no NEW or OVERLAP
  row leaves durable state identical and makes zero SQL changes. Any mismatch rolls back the whole file. The receipt
  is published only after COMMIT.
- Preview (the default) runs the checked file on a private SQLite-backup copy (`<store>.cash-preview`, swept
  hourly), rolls it back and deletes it. Apply uses the same checked boundary. CLI apply opens only an existing,
  current store with the reviewed mode/ID (`mode=rw`); a missing or empty store is refused.
- Rows: NEW; RETRY (exact stored row); OVERLAP (a stored payment repeated under new IDs: DUPLICATE, one alias event,
  no cash; off its obligation's revision, unrun like ALIAS); ALIAS (a stored repeat: nothing written); or
  HELD (writes nothing): `unknown_item`, `already_recorded` (an ID reused with other facts), `conflict` (an origin
  with another amount, link or reversal), an owner refusal (a NEW row off its
  `expected_revision`: `obligation_revision_conflict`), or `depends_on_held`. Only an intake file
  (`app/right_rail_financial_intake.py`) holds rows; it ends with one `INTAKE_RECEIVED` event
  (`RR/FINANCIAL/INTAKE/v2`), written by `run_batch` in the same transaction, checker-verified; a raw file
  is received once. Any other file is atomic.
- Receipt `RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v4` (v1 to v3 stay valid): `contract`, `mode` (PREVIEW or APPLIED),
  `source_sha256`, `baseline_sha256`, `row_count`, `recorded_count`, `duplicate_count` (includes OVERLAP rows),
  `held_count`, `file_total_cents`, `recorded_cents`, `duplicate_cents`, `held_cents`, `cash_before_cents`,
  `cash_after_cents`, `cash_delta_cents`, `rows` (each `status`, `payment_id`, `reason`: a HELD row's hold cause, a
  DUPLICATE row's `exact_retry` or `alias_of_stored_payment`, else null), `proofSuiteId` (null),
  `production_usable` (false), `activation` (false). Amounts are the checker's sums. RETRY and ALIAS rows add zero cash, including payments reversed after their receipt; a new repeat
  of a reversed payment is DUPLICATE only if dated no later than the reversal, else `conflict`.
- Scope: local synthetic receiver cash evidence only; no live transport, source authentication, payment or activation claim.

#### Cash-file capacity

Target: the largest state's hospital-level program, about 600 hospitals with up to 3 lines a month (2,000 rows a
month, under Lean's `maxRows`). With the manifest baseline a month is four full files and a quarter twelve. All-provider refund flows need sharding or evaluations that bind evidence by digest (constant size) and are not claimed.

- One file is one `run_batch`: at most 500 rows, at most 6 per item (see the checker), bounded by the 5 s writer busy timeout. One evaluation per payment is kept.
- Before COMMIT the checker runs its own rules (never copies) on the touched rows. A structural test lists each
  whole-store rule not run before COMMIT, with its reason. Corruption that bypassed the owner is caught at the next
  open or by `verify-integrity`.

#### Cash-file refusals

Fixed classes only; no input or error text is printed (`ERROR:receiver_cash_file_refused:{code}`). `input`: the
CLI could not read an input. `format`: not the contract. `row_cap`: split the file. `binding`: hashes, scope,
owner/mode or baseline do not match this store. `stale`: the store moved while the file was planned; send it again.
`conflict`: this raw file was already received. `busy`: retry later. `failed`: checker or store refused; escalate.
A row's own fault is never a file refusal: the row is HELD.

### Lean paid sum

Lean derives paid-so-far from the payment rows and links a request carries; a request never carries paid totals, and
the checker re-checks the sum (see "Lean decides, the owner commits" above).

## Design rules beyond the Constitution

- **Boundaries.** The state owns rules, authority, policy transitions and official consequences, even when a verifier
  or proof supplies an evidence result. Every module states what it owns, receives and may mutate, and what evidence
  proves the boundary; no second ledger, speculative orchestration layer or duplicate receipt format compensates for
  an unresolved contract. Corruption, omission, duplication, replay, stale revision, wrong scope, cross-owner,
  cross-period and wrong-mode cases are visible in the record, never silent, and reach staff once per cause
  (Constitution XIV.4). A failed determination leaves durable bytes unchanged; a version-tag rejection test is not
  evidence of historical-schema compatibility. A receipt binds the exact scope, revision, rule identity, evidence
  references, authority, result fields and digest domains it claims; it is not source truth or payment confirmation.
  A pinned Lean artifact is linked to the runtime only after refinement, theorem, adapter, mutation, known-answer and
  resource evidence exists.
- **Bounded resources.** Set finite record, payload, package, memory and process limits. Measure the complete path with
  separately attributable ingestion, owner transaction, independent check, restore and recovery. A component benchmark
  is not a system SLA; missing targets remain unknown. A later commercial or routing need never silently expands
  current financial authority.

## Felt-value scorecard

`tests/instruments/right_rail_scorecard.py` runs one synthetic hospital journey through the real staff server, one
fresh page per role, into `docs/scorecard/hospital_h.json`; `tests/test_right_rail_scorecard.py` fails if any unit gets
worse (rewrite with `--write` after an improvement). Units: clicks and screens until the answer is visible; needed
facts missing from the page; rows shown as open; rows to add up by hand; HTTP requests; hours unresolved or past due
(synthetic clock); correction and reconciliation error in cents; a repeated payment message counted twice. The
"manual" baselines in the file are assumptions from the reference scenario, not measurements. The read model does not
carry payer, file and day, claim number, earlier decisions and their stored reason, signer name, hold categories or a
cure date. Open friction is listed in `STATUS.md`.

## Path to the payment gate

The target (`docs/RIGHTRAIL_FULL_STACK_TARGET.md`) is an inline gate on every payment. There is no integrated payer gate. Toward it:

- Lean decides every evaluated money field, every payment and reversal, and
 `reject_offset_and_authorize_correction` and offset authorization (`BLFOFA01`);
 Python still decides population, publishing, evidence, acknowledgment, follow-through,
 reporting and funding.
- The correction codec (`BLFCMD03`/`BLFCRES3`) proves one encoding per value (P2)
 unconditionally, round-trip (P1) and trailing-byte rejection (P3) only for
 admissible values; nothing yet proves every value Lean emits is admissible.
- Line identity is per shard and a producer refuses a store that went backwards: see `STATUS.md`.
- On synthetic data the gate has a rules-worker host (`app/right_rail_gate_decide.py`), a checkpoint producer, one
  ML-DSA-87 signer and a reference payer (`app/right_rail_gate_*.py`; Lean decides every release). It has no network
  service, independent witness or fenced standby. A bypass is admitted by the rules worker alone (`STATUS.md`).

## Rejected directions

- L2, rollup, sequencer, bridge or Ethereum settlement; Cairo, Starknet or
 Solidity settlement code. Official state payment rails move funds.
- Caller-selected plaintext evaluation or any private-proof-to-plaintext
 downgrade; the approved profile fixes the evidence mode.
- Earlier private-proof layouts (in git history), and fixed-shape or AIR compatibility, as a production authority.

Private zero-knowledge is an evidence-only prototype in its own repository
(Constitution IX.4).
