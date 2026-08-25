# Clearance database + conditional mandatory-ZK architecture

Status: authoritative transaction boundary; proof boundary is `NATIVE_V3_ARCHITECTURE.md`
Updated: 2026-08-25
Owner: this document defines the verifier-to-database, retry, recovery, migration, and
anti-rollback boundary. It does not select a backend or claim production persistence.

## Product rule

Blind Ledger controls a state-local clearance decision; it does not adjudicate the full claim or
move money. The official processor and payment system retain those functions.
No payment state transition occurs inside Blind Ledger; it owns clearance state only.

Exactly three pre-admission evidence modes exist, selected by the state-approved verifier-owned
control set before request admission. There is no runtime fallback or downgrade between them:

1. `DIRECT_STATE_OWNED` evaluates canonical non-PHI facts that the state owner already lawfully
   holds; no signature or ZK wrapper is required merely to re-prove the state's own facts.
2. `AUTHORITATIVE_ASSERTION` consumes an operation-scoped, minimally disclosed derived assertion
   from a government-delegated authoritative source. A qualified NIST-PQ signature establishes
   source authority, provenance, and scope, not independent truth or source honesty, and never
   selects `policyResult`, `effectiveDirective`, or a directive.
3. `PRIVATE_ZK` independently verifies a predicate over hidden source-bound data. The authoritative
   source binds a fresh operation-scoped proof-native hiding commitment; the proof opens that
   commitment and proves only the narrow assertion.

The smallest current standardized, nonactivating `AUTHORITATIVE_ASSERTION` candidate is
`sourceAuthProfileId=ML-DSA-44-PURE-HEDGED-V1`: FIPS 204 ML-DSA-44, pure rather than HashML-DSA,
hedged signing, and fixed context/domain `BL/SOURCE-AUTH/ASSERTION/v1`. Approved key-generation RBG
strength is at least 192 bits so the selected set retains its Category 2 claim. Its body is fixed-
length-delimited and canonical, never JSON, with no classical or algorithm fallback. It contains
only the exact state-issued 256-bit `operation_ref`, source authority/key/epoch, source profile/rule/
version, bounded delegated-assertion enum/value, and bounded validity interval. It never contains a
Blind directive, `policyResult`, `effectiveDirective`, exception, chronology, state transition,
payment amount, claimant/provider identity, raw-data digest, or stable fingerprint. This is a
nonactivating candidate requirement, not module validation, HSM/FIPS custody evidence, source truth,
or production qualification.

Blind verifies the canonical body/signature ephemerally and destroys/discards those bytes after verification;
only an opaque operation-scoped verification receipt/outcome plus qualified source-auth profile/
version/key epoch is durable. Blind does not claim OS or crash-dump zeroization. The authoritative
source owns lawful original retention. State recovery proves only that Blind recorded a valid
verification at the time; it cannot reverify the original source signature from Blind storage alone.
A source-assisted later re-verification is a separate reacquisition event, not guaranteed recovery.
State audit/checkpoint PQ signatures may authenticate opaque receipt history but do not recreate or
prove the original source signature. `proofSuiteId` remains `PRIVATE_ZK`-only and null.

When an undisclosed payment-relevant assertion crosses the clearance trust boundary and affects
automation, only `PRIVATE_ZK` can satisfy that hidden-evidence requirement; no clearance-state
transition occurs unless the qualified verifier accepts the narrow assertion and the resulting
state-owned update commits in one atomic database transaction. When the state clearance service
already lawfully holds all required evidence in plaintext, `DIRECT_STATE_OWNED` uses the approved
deterministic rule artifact and atomic state machine without adding a purposeless ZK wrapper.
`AUTHORITATIVE_ASSERTION` has its own qualified source-signature profile and does not wait on a
private-proof backend. A caller cannot select a weaker mode, and a failed mode cannot retry under a
different mode by changing a flag.

Ordinary Provider App preflight may check completeness and formatting locally and may emit a small
state-verifiable receipt. It does not create a Blind Ledger clearance receipt and cannot authorize
payment.

The first commercial provider-continuity wedge is likewise read-only, but it belongs externally to
Mirror's Provider Trust Graph. It emits evidence findings, source coverage, remediation/retest,
parity, and transition artifacts rather than an operative Blind Ledger directive. The five-directive
continuity module is an internal clearance-semantics harness, not that external API.

## Production-shaped patch-in contract

The local database, export/restore, and support seams are production-shaped candidates for a
state-owned persistence and custody adapter. Their invariant interface is the canonical artifact
grammar, derived logical chain identity, immutable event/receipt roots, exact retry and recovery,
state-owned export/restore, and zero-PHI support boundary. A production adapter substitutes durable
custody, deployment, key/authentication, and operational controls while preserving those identities,
ordering, transactions, and fail-closed behavior. Qualification reruns the same independent
artifact/database checks, mutation/replay/recovery tests, resource gates, and canonical KATs; a
semantic or state-interface rewrite is architecture review, not integration.

This seam can qualify for the read-only wedge independently of the private-payment backend; the private clearance path still requires the later Lean, ZK, and custody gates. Status is in `STATE.md`.

## Transaction boundary

### Queue/Proof Handoff V7 clean break

The active experimental queue boundary is V7. V6 databases, artifact readers, filesystem
snapshot/refetch paths, and proof-bound disposition receipts are unsupported and fail closed; no
migration, compatibility reader, fallback, wrapper, or dual path exists. Blind state creates a
fresh random 32-byte operation reference for each admission. Durable queue data contains only that
opaque reference, state-issued allowlisted assertion/profile/version, bounded validity window,
ordered batch position/root, optional approved-source registry root, chronology/status/retry data,
and qualification flags. Caller job IDs, artifact/source paths, patient/provider/case identity,
raw-data digests, acceptance bytes, and process-output hashes are not queue fields.

The V7 ownership chain is source-local prover -> optional aggregator -> independent verifier ->
state owner -> opaque-reference/directive outbox and ACK -> audit/recovery. Admission is two phase:
the state first issues an immutable allowlisted statement and fresh random 32-byte operation
reference in `AWAITING_HANDOFF`; for a batch it assigns positions and computes one domain-separated
ordered root from the exact issued references and canonical templates. Only after issuance may a
caller submit the single-use readable binary stream for that exact reference (or exact ordered
batch), transitioning it to `QUEUED`. The verifier receives that stream and the complete issued
statement, never an unrelated caller/reference argument. The verifier receives a
readable binary stream through one volatile single-use handoff. Each activated profile owns an
exact small envelope cap justified by its format; there is no universal input-admission allowance,
and a not-yet-selected private profile remains inactive. The complete process-tree peak requirement
is strictly below 5,000,000,000 bytes. No proof,
source, signature, commitment, or verifier output bytes are written to a proof workspace, DB,
receipt, event, log, export, backup, or error. Mutable staging is wiped where technically
possible; Python/OS/crash-dump zeroization is not claimed. A timeout, crash, lease expiry, restart,
transport failure, or ambiguity consumes the handoff and fails closed to
HELD with bounded `fresh_handoff_required`; retry requires a new state operation and fresh stream.

For the active V7 `PRIVATE_ZK` handoff, the verifier receipt is limited to `proofAccepted`, the
matching opaque reference, assertion and profile versions, bounded validity/order fields,
verifier/profile version, bounded outcome/error/resource codes, qualification flags, and the
nonactivating flags. It never supplies `policyResult` or `effectiveDirective`. `DIRECT_STATE_OWNED`
and `AUTHORITATIVE_ASSERTION` use their separate mode-specific state-evaluation or qualified
source-signature/assertion result; none is a disposition. The state owner separately controls
`PASS`, `MISSING`, `AMBIGUOUS`, or `FAIL` and resolves exactly `CLEAR`, `HOLD`, `HUMAN_REVIEW`,
`BLOCK`, or `EXCEPTION_APPROVED`; proof or signature acceptance alone can never create `CLEAR`. A
complete promotion batch is preflighted against one state snapshot and commits all composition
rows, events, state roots, and outbox rows in one transaction. A mixed APPLIED/HELD persisted image
is independently rejected.

This V7 boundary remains synthetic/experimental: `proofSuiteId=null`, `production_usable=false`,
activation=false, no backend is selected or qualified, and the co-equal zero-PHI, post-quantum,
recovery, 100 complete operations within 35 seconds p95, and below-5-GB gates remain open.

For a future qualified private batch, the service will:

1. receive a canonical native-v3 statement and fixed-profile proof envelope for the private-proof
   path;
2. select governed source-registry, automatic-control-set, governance, schema, program, and
   candidate-suite context;
3. verify the mandatory zero-knowledge proof with the native verifier, returning only the minimal
   allowlisted receipt;
4. let the state owner resolve its separate disposition control and preflight the complete ordered
   state chain against one snapshot;
5. open one serializable transaction only after preflight, rechecking state-before roots,
   governance roots, and anti-rollback epoch;
6. reject consumed nullifiers, stale roots, duplicates, conflicting retries, and partial batches;
7. pass only proof acceptance to the state owner; policy result, exception approval, effective
   directive, exact amount, and decision-path state remain state-owned rather than proof-supplied;
8. reserve the exact canonical state receipt and proposed transition for the later mandatory Lean
   gate; the current nonactivating boundary has no Lean result, and any future missing result,
   decoding error, theorem-version mismatch, or Rust/Lean disagreement rejects;
9. write state-after roots, the state-owned clearance commitment, and the audit event; economic
   clearance may advance only for `CLEAR` or a valid `EXCEPTION_APPROVED`;
10. commit the database transition exactly once, or roll it back; an uncertain response is resolved
    only by exact idempotent retry without proof reuse.

Verifier acceptance alone is never interpreted as `CLEAR` and never proves that funds moved. A
private-path database write without verifier acceptance is forbidden. The official state payment
system consumes an accepted clearance directive and later returns the actual outcome to Mirror.

## Current experimental application chain

The current nonactivating V7 implementation separates the source/prover, optional aggregation,
independent verifier, state-owned disposition, durable composition/outbox, and audit/recovery
owners. Queue promotion uses a one-use volatile handoff; it never refetches proof bytes. The
state owner, not the verifier, preserves `policyResult` separately from `effectiveDirective`, and
the opaque outbox cannot mutate payment, settlement, or official-system state.

This chain is not yet the production transaction described above. Its current native statement
does not carry the complete proposed/authorized amount contract, Lean is not linked, and the
official receiver is synthetic. The next breaking native revision must fail closed at the current
composition boundary; a separately reviewed composition version must then bind the new authorized
amount and canonical state identifiers rather than silently accepting the old grammar.

## Directive transition rules

| Effective directive | Required state-owned condition (with accepted selected-mode evidence where applicable) | Clearance/economic mutation |
| --- | --- | --- |
| `CLEAR` | Accepted proof where required, state `policyResult=PASS`, and no state exception is present. | Advance replay/audit state and exact authorized clearance state. |
| `HOLD` | Accepted proof where required and state `policyResult=MISSING`; a fixable requirement is missing. | Advance replay/audit state only. |
| `HUMAN_REVIEW` | Accepted proof where required and state `policyResult=AMBIGUOUS`; judgment, ambiguity, or additional evidence is required. | Advance replay/audit state only. |
| `BLOCK` | Accepted proof where required and state `policyResult=FAIL` without state exception; a selected prohibition holds. | Advance replay/audit state only. |
| `EXCEPTION_APPROVED` | Accepted proof where required, state `policyResult=FAIL`, and a registered state exception authorizes the scoped override. | Advance replay/audit state and only the clearance allowed by that authorization. |

In the table, “accepted proof where required” applies only to `PRIVATE_ZK`; the direct state-owned
evaluation or authoritative source-signature/assertion result is the corresponding non-dispositive
evidence input in the other two modes. The state-owned `policyResult` and exception control still
determine the directive in every mode.

The no-exception case uses a canonical domain-separated nonzero sentinel so every row has the same
shape. An emergency continuity action is a separate signed and expiring human override transaction,
not a parser fallback or a failed proof converted to `CLEAR`. Mirror records the underlying result,
override, final payment outcome, and any Blind Ledger failure.

The exact automatic control set is verifier-owned and binds rule order, priority/conflict handling,
directive mapping, scope, and effective interval. A prover cannot choose a favorable subset. Event,
observation, rule-effective, and decision times are distinct canonical values and remain stable
across retry. A negative fact cannot authorize `HOLD` or `BLOCK` merely because a record is absent
from an incomplete feed.

The executable chronology is strict: `rule_effective < event < observation < decision`. These four
times are bound identically across the request, decision, verifier receipt, and exact retry. The
transaction admits one decision (`decision_index=0`) and exactly two accesses indexed `[0,1]`
(`access_count=2`); every access carries the matching `decision_id`. Reads occur at observation time,
and the clearance-state write occurs at decision time. The independent parser is the current checker
for the READ/WRITE row roles; the producer compatibility object is not semantic authority.

## Formal semantic boundary

Lean 4 is the later mandatory executable authority for clearance meaning and the legal local
transition. It is not an active dependency of the current synthetic transaction boundary: the kernel
is not implemented, linked, or production-qualified. Before direct or private clearance authority,
the future kernel must cover bounded decoding, the five directives, result separation, control sets,
authoritative absence, chronology, exceptions, observation-only separation, replay, exact joins, and
allowed after-state.

For a future `PRIVATE_ZK` path, Rust proof acceptance must precede the Lean check. For a future
direct path, the Lean kernel must evaluate the canonical governed plaintext input directly. These
are distinct verifier-owned execution contexts; no caller may select, downgrade, or promote them.
Current Python/Rust KATs and local database tests are evidence for the patch-in contract, not Lean
or production clearance authority.

`LEAN_FORMAL_KERNEL.md` defines the required executable correspondence, theorem manifest, axiom
inventory, independent kernel check, and CI gates. Current status and nonactivation remain in
`STATE.md` and `CURRENT_TASK.md`.

## Current recovery and compatibility evidence

`app/production_boundary.py` and `app/transactional_database_boundary.py` remain the tested local
owners of the current compatibility seam. They must preserve one atomic clearance-state mutation,
exact receipt identities, idempotent retry, concurrency rejection, anti-rollback, backup/restore,
migration, append-only audit, and zero-PHI support behavior.

The focused evidence is `tests/test_bl_pq512_production_boundary.py`,
`tests/test_bl_pq512_transactional_database_boundary.py`,
`tests/test_bl_pq512_transactional_privacy_v2_migration.py`,
`tests/attacks/test_bl_pq512_transactional_privacy_v2_migration_attacks.py`,
the public-input, commitment, nullifier,
and custody tests named by the active-core map. These are synthetic compatibility regressions; they
do not select a proof backend or make historical package claims current.

The recovery contract is: reserve the exact expected and next anchors before commit, finalize after
commit, return an explicit indeterminate result on post-commit finalization failure, and resolve it
only by exact idempotent retry. Competing transitions, stale roots, older databases, partial writes,
and configuration drift fail closed. Backup/restore and restart must retain the same decision,
receipt, audit, and anti-rollback identities.

## What the selected proof must establish

No production proof is selected: the live verifier-selection sentinel is `proofSuiteId=null`,
`production_usable=false`, and `selection_status=UNSELECTED`. `DIRECT_STATE_OWNED` is a
verifier-owned synthetic continuity control-set identity, not a selected production evaluator.

The complete selected proof must eventually establish the hidden assertion and its authenticated
state-issued challenge under the future qualified contract. The verifier returns only proof
acceptance and a narrow opaque receipt; state-owned policy/disposition control, exception approval,
ordered state reads/writes, replay protection, value conservation, and the legal transition remain
state/Lean responsibilities. It may reveal no source identity or raw witness material.

Governed ingestion verifies source signatures over exact canonical bytes once, before registry
publication. Repeating public signature verification inside every proof is unnecessary when private
membership in that authenticated registry is proved. A prover-supplied registry root is forbidden.

Retired backend implementations and detailed migration narratives remain available through Git
history and retained source archives. No current release or readiness path selects them; the live
verifier-selection contract remains explicitly `UNSELECTED` until an independently reviewed backend
is selected.

It cannot establish that an authorized source told the truth, that the policy was wise or lawful, or that database operators preserved availability. Those are governance and operational trust boundaries.

## Cryptographic requirements

- `DIRECT_STATE_OWNED` uses state-owned canonical plaintext facts without a signature or ZK wrapper;
  `AUTHORITATIVE_ASSERTION` uses an operation-scoped minimally disclosed derived assertion with a
  qualified PQ signature; `PRIVATE_ZK` uses a source-bound hiding commitment and a proof of only the
  hidden assertion/predicate. No mode has runtime fallback or downgrade.
- The source commitment may remove exact raw-data SHA3-512 recomputation from a private proof only
  when the authoritative PQ signature binds that exact operation-scoped commitment and the proof
  opens it. Blind Ledger does not persist raw-data digests, deterministic claimant/provider hashes,
  source capture, proof, signature, path, stdout/stderr, credentials, or stable fingerprints;
  official source/state custody is an external audit dependency.
- Canonical fixed-profile native-v3 statements and privacy-safe observable behavior are required.
  SHA3-512 remains an authoritative external identifier; digest width alone is not proof-system
  security.
- A selected private backend must be versioned, deterministic, transparent, and derived from
  reviewed standards or constants without a secret or trusted setup. Ordinary public parameters are
  allowed. Any activation profile whose soundness or privacy depends on an unverified ceremony,
  toxic-waste destruction, or hidden parameter custody is rejected. The backend must be non-ECC,
  natively hiding, and independently verified.
- Every `PRIVATE_ZK` profile requires an exact zero-knowledge/privacy theorem for its actual adversary
  and transcript model. Interactive protocols require malicious-verifier privacy plus reset, abort,
  retry, and session composition. Noninteractive protocols require the exact NIZK or
  Fiat-Shamir/QROM privacy and soundness model instead; an inapplicable separate interactive
  malicious-verifier property is not required.
- Fiat-Shamir/QROM, grinding, separate cryptographic nullifiers, and recursion/aggregation are
  profile-conditional. If selected, each requires the exact profile theorem and full finite
  composition ledger, including bounded attempts, fan-in, retries, aborts, batching, recursion, and
  all bad events. A fresh state-issued 256-bit operation reference/challenge plus database uniqueness
  prevents cross-operation replay/binding failures but does not replace proof soundness.
- Every computational primitive used by an activated external-authority or private-proof profile
  must meet at least the NIST post-quantum Category 1 baseline for its attack model. NIST categories
  are broad comparison floors, not an exact proof-security claim, generic proof-soundness theorem, or
  `2^-128` forgery probability. Source, authorization, configuration, and audit signatures use a
  qualified PQ profile; classical-only failure never downgrades to plaintext or synthetic
  acceptance. Each suite declares its adversary work/query model, signature/oracle counts, key
  lifetime, reduction loss, and whether its selected NIST category preserves the intended 128-bit
  product claim under the finite profile/epoch bound; a stronger category is used when exact
  reduction or usage evidence requires it, without a global Category 3 mandate.
- Every qualified cryptographic profile/key epoch has a hard global ceiling of `2^32` cryptographic
  acceptance attempts across all operations, retries, batches, instances, and verifier sessions
  sharing that profile/epoch. Exceeding the ceiling or losing the trustworthy counter fails closed
  and requires rotation and requalification; this ceiling is assurance accounting, not throughput.
- The exact theorem ledger must prove the union of all statistical bad events over that full ceiling
  is at most `2^-128`, including proof soundness/knowledge, commitment binding where statistical,
  transcript/challenge collisions, enabled aggregation, operation-reference collisions, abort/
  retry/reset, and all union factors. Equal allocation across eight per-attempt classes requires at
  least 164 bits per event; use a 192-bit per-proof/statistical engineering target unless an exact
  tighter theorem ledger proves the complete bound. No unbounded deployment-lifetime `2^-128`
  probability is claimed.
- The private proof binds only the hidden source-bound assertion/predicate. The state-owned receipt
  and transaction bind policy, ruleset, `policyResult`, `effectiveDirective`, exception
  authorization, chronology, state-before, state-after, outbox, ACK, and clearance identities;
  proof or signature acceptance never equals `CLEAR`.
- One pinned executable Lean semantic/state-transition kernel is mandatory before automatic
  clearance policy/transition authority and must link fail-closed to the verifier and database;
  it is not a proof-backend or Mirror gate.
- Fail-closed parsing, resource limits, retries, recovery, migration, and anti-rollback are
  mandatory. Complete process-tree resident memory must remain strictly below 5,000,000,000
  decimal bytes, with no proving-attributable swap/pagefile growth.

## Qualification measurement boundary

The active complete-profile engineering floor is 100 complete operations within 35 seconds p95 on
the pinned laptop-class state-side verifier reference profile, with the complete resource and
negative-test boundary. Report source-prover, optional aggregator, independent verifier, state
transaction, and outbox/ACK stages separately; report external official-source and official-ACK
latency separately when applicable. A source-local prover or optional aggregator may declare exact
accelerator or hardware requirements, but its wall time and resources remain part of complete-profile
evidence. Component or cached results receive only component credit and cannot close the gate.
Throughput, memory, PQ strength, zero-PHI, ownership, recovery, and independent reconstruction are
co-equal gates.

## External-chain boundary

Ethereum is not a dependency. No L2, rollup, sequencer, bridge, Solidity settlement contract, or
public data-availability layer is active.

A committed later product phase may post one compact signed checkpoint or aggregate-proof commitment
directly to Ethereum L1. This is not a Phase 0-2 dependency, settlement role, L2, rollup, sequencer,
bridge, or payment rail. The posting cadence remains a governed deployment parameter and is not yet
fixed. The checkpoint binds the exact ordered accepted batch, control-set and software identities,
before/after state, prior checkpoint, exceptions, and interval. Full proofs and audit material remain
in state-controlled storage.

Posting a root proves public anchoring, not underlying correctness. Posting proof bytes does not
make Ethereum a verifier unless a separately qualified on-chain verifier checks the exact proof and
public inputs. Ethereum currently adds classical public timestamping and tamper evidence; it is not
the transparent post-quantum or non-ECC root of trust for Blind Ledger. The checkpoint must not
carry PHI, be the only durable copy, replace the operational database, authorize payment, or weaken
mandatory application verification.

## Phase boundary

- Phase 0: freeze native-v3 statement, typed five-directive receipt, source/exception-registry and
  state interfaces, threat model, and the declared laptop-class state-side reference/resource
  baseline.
- Phase 1: accept the smallest complete native-v3 clearance proof and independent negative-test
  boundary, including wrong-directive and exception-authorization attacks.
- Phase 2: qualify fixed-profile batching and the atomic database transition locally with adversarial
  tests and reproducible complete-process evidence.
- Later: production database/custody integration, independent audit, operator activation, and
  optional L1 checkpoint design after its persistence, cost, verifier, key, and PQ-claim boundaries
  are separately qualified.
