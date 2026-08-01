# BL-PQ512 foundation specification

Updated: 2026-07-18

Status: **review-ready synthetic-only foundation draft; not an implemented, qualified, audited, or
production-approved proof profile.**

Planning addendum: `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` makes every implementation and
qualification deliverable internally finishable. References below to external review mean the one
final audit/promotion gate; they do not require an outside party to select or implement the suite.
The current suite nevertheless remains `UNSELECTED`, `proofSuiteId=null`, and nonactivatable.

Current physical-topology addendum: the sealed application semantics feed the heterogeneous Wave 2
proof in `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The M31 semantic AIR and Fp16 Boolean
GKR SHA3 coprocessor share one committed bus and atomic verifier. This supersedes any reading below
that assumes all SHA3 internals remain in one generic Circle-STARK PCS.

This document is the review artifact for roadmap packages S02-S06 and the provisional S10
lifecycle draft. It supplements `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`; it does not supersede that
architecture, authorize real PHI, or authorize settlement. S03, S05, and S06 are complete as
application-specification packages. S02 remains open because the runtime/readiness configuration
still identifies the legacy `CAIRO_STARK_NATIVE` lane and requires a coordinated implementation,
configuration, mirror, and test migration—not a documentation-only rename. S04 and S10 remain
explicitly provisional.

The later R24 continuation through S12 is recorded in
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md` and
`docs/bl_pq512_suite_candidate_v1.json`. It supersedes this document only where it makes the S04
candidate byte layout, money boundary, and S10/S12 blocker ledger more exact. It deliberately
leaves `proofSuiteId` unset and activation forbidden.

The exact cross-lane money grammar, integer/range boundary, checked K256 aggregate rule, zero-value
private-denial behavior, and structural mismatch taxonomy are normative in sections 7 and 11 of
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md` and section 6 of
`docs/FIXED_SHAPE_CLAIM_AIR_DRAFT.md`. This foundation document does not define an alternate money
encoding.

The field, PCS, FRI, Fiat-Shamir, query, grinding, tree, transcript, and multi-target decisions
belong to S07-S09. This earlier foundation draft did not select them. The later
`docs/BL_PQ512_S09_INTERNAL_SOLUTION.md` now selects the degree-16 tower and authoritative
interactive public-coin construction direction, while keeping the PCS/FRI, full schedule, hiding,
proof format, module IDs, and `proofSuiteId` fail-closed.

## Normative language

`MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` are normative only for this draft's application
boundary and review discipline. They are not evidence that the cryptographic construction exists.

## S02: profile label and permitted claims

Status: **open pending synchronized canonical-operations wording.** The label and permitted claims
below are frozen in application documentation, but the repository is not yet globally coherent.

The selected target profile label is exactly `BL-PQ512-v1`.

The only permitted current claim is:

> `BL-PQ512-v1` is Blind Ledger's selected synthetic-only target architecture. It is not yet
> implemented, cryptographically qualified, independently audited, or approved for real PHI or
> production settlement.

The future release claim, and only after every applicable implementation, qualification,
independent-review, operational, and release gate passes, is:

> Privacy V2 12-field application ABI secured by `BL-PQ512-v1`.

Before those gates pass, documentation, logs, interfaces, dashboards, and demonstrations MUST NOT
say or imply that:

- the current S-two proof is zero knowledge;
- the current proof or application state meets strict 128-bit quantum security;
- a synthetic reference sidecar is a production proof envelope;
- the 12 legacy field values are the complete security context;
- a local simulator, mock verifier, or reference state machine is production infrastructure;
- the system is production ready, independently audited, or safe for real PHI.

`PQ512` means the target architecture uses authoritative 512-bit application bindings while aiming
for the separately reviewed security target. It does not mean 512-bit quantum security. No numeric
security budget is asserted by this foundation draft.

## S03: preserved external ABI

Status: **complete as an application-interface specification.** This does not qualify a proof
backend or freeze obsolete formulas and vectors.

The external application ABI MUST remain exactly this ordered list:

| Index | Name | Type |
| ---: | --- | --- |
| 0 | `protocolVersion` | `bytes32` |
| 1 | `settlementDomain` | `bytes32` |
| 2 | `batchNonce` | `bytes32` |
| 3 | `nullifierRootBefore` | `bytes32` |
| 4 | `nullifierRootAfter` | `bytes32` |
| 5 | `claimSourceRoot` | `bytes32` |
| 6 | `oracleFactsRoot` | `bytes32` |
| 7 | `policyRoot` | `bytes32` |
| 8 | `rulesetRoot` | `bytes32` |
| 9 | `opaqueBatchCommitment` | `bytes32` |
| 10 | `valueConservationCommitment` | `bytes32` |
| 11 | `settlementCommitment` | `bytes32` |

Preservation means preserving:

1. exactly 12 fields;
2. the indexes, order, names, and `bytes32` types above;
3. canonical Stark-field encoding at the existing external boundary;
4. the forbidden-public-output boundary;
5. exact-byte comparison, with no normalization, truncation, reordering, modulo repair, aliases,
   ignored values, or alternate encodings.

Preservation does **not** freeze obsolete formulas, denied-case values, padding values, or known-
answer vectors. Every real claim must eventually consume an attempt nullifier and every unused
fixed-capacity slot must eventually consume a cover nullifier. Consequently, old denied and padded
root values cannot be treated as immutable.

A semantic or formula change MUST be explicit in the profile/schema/epoch, MUST receive new known-
answer vectors, and MUST pass migration and mixed-profile rejection review. It MUST NOT be silently
presented as the previous proof relation.

The exact manifest-forbidden names remain:

- `approvedAmountCents`
- `paymentAmountCents`
- `claimCount`
- `approvedCount`
- `deniedCount`
- `encryptedPayload`

The prohibition is semantic, not spelling-based. Public outputs, proof metadata, settlement data,
events, logs, queues, and artifacts MUST NOT expose aliases or encodings of exact amounts, counts,
per-claim decisions or failure codes, member/patient identifiers, diagnoses, authorization data,
provider documents, or raw/encrypted medical-record payloads.

## S04: review-ready candidate authenticated proof envelope

Status: **exact local 744-byte format candidate; not an activated production encoding.** The suite
identifier remains unset, and proof dimensions/proof-body sections remain downstream of the final
AIR and reviewed proof-suite decisions. The exact offsets and parser rules are controlled by
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md` and the machine-readable candidate registry.

The proof envelope has two distinct parts:

1. a fixed-shape authenticated **metadata sidecar**; and
2. a separate opaque **proof body**.

`zkProof` is not a field inside the metadata sidecar. Implementations MUST NOT concatenate or parse
the two using an ambiguous or self-selected encoding. The final envelope parser MUST reject unknown
profiles, unknown suites, unknown schemas, missing fields, alternate encodings, incorrect lengths,
duplicate fields, and trailing data.

The semantic metadata inventory is below. Every listed identity/root is 64 nonzero bytes in the
candidate; all lifecycle integers are fixed-width big-endian.

| Semantic item | Requirement | Freeze status |
| --- | --- | --- |
| `profileId` | Full-width identity of exactly `BL-PQ512-v1` | Required; final digest waits for validated descriptor bytes |
| `proofSuiteId` | Complete field/PCS/FRI/transcript/hiding/proof-format identity | Required nonzero in ACTIVE state; deliberately `null` in the unqualified registry |
| `schemaId` | Complete formal statement and witness/public encoding | Required nonzero in ACTIVE state; final ID waits for S12/P06 closure |
| `verifierArtifactIdentity` | Exact verifier artifact and build provenance | Required; final ID waits for S11 and artifact build |
| `strongSettlementDomainId` | Full-width authority for the legacy settlement-domain alias | Required to avoid making field 1 the strict-PQ replay authority |
| `epoch` | Selects one immutable governed profile epoch | Nonzero `u64be` |
| `sequenceBefore` | Authenticated prior global sequence | `u64be`, less than `2^64-1` |
| `sequenceAfter` | The single permitted successor | Exactly `sequenceBefore+1` |
| `strongNullifierRootBefore` | Authoritative typed wide replay state before the transition, including slot nullifiers and master-salt-use tags | Required full 512-bit root |
| `strongNullifierRootAfter` | Authoritative typed wide replay state after 256 slot entries plus one salt-use entry | Required full 512-bit root and must differ |
| `strongGovernanceCommitment` | Binds the wide governed-root registry and legacy aliases | Required full 512-bit commitment |
| `strongPaymentStateRootBefore` | Composite benefit/obligation/private-ledger/operation state before | Required full 512-bit root |
| `strongPaymentStateRootAfter` | Composite payment state after every fixed slot operation | Required full 512-bit root and must differ |
| `strongBatchCommitment` | Authoritative binding over the 12 fields, sidecar prefix, private/value commitments, and hidden master salt | Required full 512-bit commitment |

The foundation T01 scaffold uses the literal placeholder `TBD-S12-P06-NOT-FROZEN` for `schemaId`.
It MUST NOT invent a combined statement identity before the S12 statement and P06 encoding artifact
exist. The current witness-only schema retains its separate, real identity
`BL-PQ512-WITNESS-SYNTHETIC-FOUNDATION-v0`.

The final transcript MUST authenticate, before deriving any challenge:

- all 12 canonical legacy values in their exact order;
- the complete metadata sidecar;
- the complete verifier artifact identity;
- the selected proof-suite and schema identities;
- every authoritative strong state value, including the resolved payment/asset state binding.

The final verifier MUST return typed authenticated strong outputs. State-management code MUST NOT
extract unchecked roots from proof bytes, reduce a strong value to one felt or one 256-bit digest,
or verify and then discard authoritative outputs. Exact transcript mechanics remain `TBD-S07/S09`.

The current synthetic reference encoder is evidence that strict parsing can be tested. It is not the
production encoding and MUST NOT be promoted by renaming its `REFERENCE` domains.

## S05: threat model update

Status: **complete as a repository/application threat-model specification.** The source-controlled
full model is `docs/BL_PQ512_THREAT_MODEL.md`; implementation and external-assurance gates remain
open.

### Assets and invariants

Protected assets include private claim and medical data, exact decisions and amounts, salts and
masking randomness, governed facts and policies, nullifier/payment state, profile/schema/verifier
identity, the exact 12-field ABI, source/dependency provenance, audit evidence, and availability
without witness-class leakage.

The system MUST fail closed on disagreement. Python, Rust, Cairo, RISC/reference models, the future
AIR, proof verifier, sidecar parser, and state owner must agree exactly on every applicable byte,
decision, amount, reason, root, commitment, and transition.

### Threat and control matrix

| Threat class | Representative attack | Required control or gate | Residual status |
| --- | --- | --- | --- |
| Malicious prover | Omits constraints, fabricates governed membership, reuses masks, or crafts malformed openings | Complete AIR review; independent verifier; full oracle-hiding inventory; tamper and malformed-proof tests | Open; Z01-Z12 and independent review required |
| Compromised proving worker | Reads witness plaintext, logs salts, retains masks, leaks through crashes or retries | Isolated no-co-tenant worker; minimum plaintext lifetime; zeroization; disabled swap/core dumps; artifact scan | Open operational and side-channel gate |
| Metadata inference | Learns decisions or batch occupancy from timing, roots, proof size, errors, retries, or cadence | Fixed shape and state-operation count; cover slots; uniform errors; measured fixed cadence | Open; T11-T13/O03-O05 required |
| Quantum attacker | Attacks long-lived roots, proof commitments, signatures, key wrapping, or harvested ciphertext later | Authoritative wide state and proof metadata; reviewed proof-system budget; PQ/hybrid custody migration | Open; S07-S09/P11-P12/O09 required |
| Parser disagreement | Uses alternate lengths, field order, normalization, trailing bytes, or cross-language ambiguity | One canonical encoder/parser; exact-byte differential vectors; reject extra/missing/unknown data | Open until P06/T01-T10 converge |
| Governance compromise | Registers fabricated roots, activates a wrong verifier, overwrites mappings, or abuses rollback | Immutable registry tuples; separated roles; authenticated activation; epoch/domain change; audit trail | External governance and independent-review gate |
| Build/dependency compromise | Substitutes compiler, dependency, vendored patch, verifier artifact, or stale source | Pinned reproducible inputs; SBOM; offline locked build; source/artifact readback hashes | S11 draft only; release remains blocked |
| High-capacity batching | Floods hundreds-of-claims queues, exploits padding cost, infers sparse/full batches, or causes witness-dependent cancellation | Reviewed capacity limits; bounded queues; identical slot work; admission control; first-four calibration; uniform cancellation | Capacity and operations remain open under A01/A05/O05 |
| Verifier/state-owner split | Verifier authenticates fewer values than state code consumes, or strong outputs are verified then discarded | Typed verified outputs; exact sidecar/statement reconstruction; one atomic compare-and-swap transition | Open until P07-P10 and malformed-output attacks pass |
| Oracle or KMS insider | Uses privileged source/custody access to sign fabricated facts, unwrap witnesses, or exfiltrate salts and masks | Separated roles; source manifests; HSM policy; threshold governance; immutable audit trail | External custody/governance gate |
| Relayer and resource abuse | Sends huge or malformed proofs, proof-selected parameters, duplicate work, or queue floods before cheap rejection | Out-of-band suite pin; length caps; parse-before-allocate; rate/admission control; bounded queues | Open until parser, verifier, and operations gates pass |
| Recovery ambiguity | Restores only one of legacy/wide state, replays a pre-recovery proof, or forks epochs | Full checkpoint rollback; epoch/domain advance; stale-proof rejection; readback verification | Open until S10/P08/O06 |
| Containing-rollup gap | Treats an incomplete rollup, bridge, finality, or availability path as a security boundary | Do not count it as mitigation; prove the complete verifier-to-state-to-rollup path later | Explicitly outside current claim-proof closure |

Zero knowledge does not protect a compromised proving host. Wide application hashes do not repair a
weak proof transcript. Fixed shape does not by itself hide submission cadence. Governance approval
does not replace cryptographic verification. These are separate boundaries and all must pass.

## S06: per-field security notions

Status: **complete as an application-field classification.** Numeric lifetime and theorem constants
remain S07 inputs rather than hidden assumptions in this table.

Every row requires exact equality and canonical encoding. “Strong authority” identifies the context
that must carry strict-PQ security; it does not claim that the context has been implemented.

| Field | Equality purpose | Replay purpose | Target-preimage reliance | Second-preimage reliance | Arbitrary-collision reliance | Hiding purpose | Strong authority |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocolVersion` | Select expected application version | Reject incompatible version reuse | None | None | None | None | Profile/schema state |
| `settlementDomain` | Match the configured settlement domain | Prevent cross-domain replay | None; it is a governed identifier | None; it is a governed identifier | None | None | Authenticated profile and state |
| `batchNonce` | Match the proven nonce | Unique consumption prevents replay | None; unpredictability is not its binding basis | None; uniqueness/state is authoritative | None | No confidentiality claim | Atomic nonce/sequence state |
| `nullifierRootBefore` | Match prior legacy root | Reject stale or competing legacy state | Legacy membership compatibility only; not strict-PQ quantified | Legacy tree binding compatibility only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public, not hiding | `strongNullifierRootBefore` |
| `nullifierRootAfter` | Match computed next legacy root | Advance one ordered transition | Legacy transition compatibility only; not strict-PQ quantified | Legacy transition binding only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public, not hiding | `strongNullifierRootAfter` |
| `claimSourceRoot` | Match governed legacy alias | Reject wrong epoch/registry selection | Legacy membership compatibility only; not strict-PQ quantified | Legacy record-binding compatibility only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public root may leak linkage | Registered wide claim-source root |
| `oracleFactsRoot` | Match governed legacy alias | Reject stale/wrong facts epoch | Legacy membership compatibility only; not strict-PQ quantified | Legacy fact-binding compatibility only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public root may leak linkage | Registered wide oracle-facts root |
| `policyRoot` | Match governed legacy alias | Reject stale/wrong policy epoch | Legacy membership compatibility only; not strict-PQ quantified | Legacy policy-binding compatibility only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public root may leak linkage | Registered wide policy root |
| `rulesetRoot` | Match governed legacy alias | Reject stale/wrong ruleset epoch | Legacy membership compatibility only; not strict-PQ quantified | Legacy ruleset-binding compatibility only; not strict-PQ quantified | MUST NOT be strict-PQ anchor | Public root may leak linkage | Registered wide ruleset root |
| `opaqueBatchCommitment` | Match the proven compatibility commitment | Helps identify changed/replayed legacy batches | Target-preimage binding intended; analysis open | Second-preimage binding intended; analysis open | MUST NOT be strict-PQ anchor | Intended hiding with fresh salt; proof open | `strongBatchCommitment` |
| `valueConservationCommitment` | Match the proven compatibility value commitment | Binds nonce within current formula | Target-preimage binding intended; low-entropy analysis open | Second-preimage binding intended; formula coverage open | MUST NOT be strict-PQ anchor | Intended amount hiding; proof open | Strong batch plus resolved payment-state binding |
| `settlementCommitment` | Match compatibility settlement identifier | Legacy deduplication identifier | Current formula is not a complete target-preimage binding | Current formula is not a complete second-preimage binding | MUST NOT be strict-PQ anchor | No independent hiding claim | `strongBatchCommitment`, sequence, and atomic state |

No one-felt field may be counted as the authoritative arbitrary-collision anchor for
`BL-PQ512-v1`. Fields 9-11 also MUST NOT be counted as independent security factors merely because
they are separately visible.

### S07 handoff ledger

| Field | Attacker influence | Lifetime/target treatment | Authoritative value | Failure consequence |
| --- | --- | --- | --- | --- |
| `protocolVersion` | Governance selects from a small set; submitter can request a value | Count every accepted profile/epoch; do not credit entropy | Authenticated profile/schema state | Downgrade or mixed-relation acceptance |
| `settlementDomain` | Governance/configuration controlled; submitter can replay across domains | Count every active domain and epoch | Full authenticated domain/profile state | Cross-domain replay |
| `batchNonce` | Submitter proposes; state owner decides uniqueness | Count every consumed nonce; uniqueness, not unpredictability, is the control | Atomic wide sequence/nonce state | Replay or competing transition |
| `nullifierRootBefore` | Prover chooses witness/path against governed prior state | Count every accepted prior root and proof | `strongNullifierRootBefore` | Stale-state or replay acceptance |
| `nullifierRootAfter` | Prover proposes the computed transition | Count every accepted next root and competing proof | `strongNullifierRootAfter` | Duplicate claim or state fork |
| `claimSourceRoot` | Governance registers; malicious source can choose records | Count all registered roots, records, epochs, and membership targets | Registered full-width claim-source root | Fabricated or substituted claim authority |
| `oracleFactsRoot` | Oracle/governance can choose facts; prover chooses paths | Count all sources, facts, roots, signatures, and epochs | Registered full-width oracle-facts root | Fabricated eligibility/authorization facts |
| `policyRoot` | Policy governance can choose records; prover chooses paths | Count all policies, rows, roots, and epochs | Registered full-width policy root | Wrong fee/prior-authorization result |
| `rulesetRoot` | Rules governance selects code/data identity | Count all rulesets, artifacts, roots, and epochs | Registered full-width ruleset root | Different adjudication relation |
| `opaqueBatchCommitment` | Prover controls batch and private salt subject to proof | Count all proofs, batches, salts, and attackable commitments | `strongBatchCommitment` | Batch substitution or privacy loss |
| `valueConservationCommitment` | Prover controls private values and salt subject to proof | Count all value targets, proofs, and low-entropy guesses | Strong batch plus resolved payment-state binding | Inflation, underpayment, or amount disclosure |
| `settlementCommitment` | Derived compatibility identifier; submitter can replay it | Count all receipts/epochs; do not treat fields 9-11 as independent factors | `strongBatchCommitment`, sequence, and atomic state | Deduplication or settlement confusion |

## S10: review-ready lifecycle candidate

Status: **exact local lifecycle candidate; no live-state operation authorized.** The full phase,
compare-and-swap, recovery, and fail-closed rules are controlled by the R24 pre-implementation
freeze. S10 remains open until selected identities, payment semantics, reference code, and attack
tests exist.

### Provisional authenticated state tuple

The atomic state must eventually contain at least:

```text
profileId
proofSuiteId                 // null in the unqualified candidate; nonzero only in ACTIVE state
schemaId
verifierArtifactIdentity
epoch
legacyProtocolVersionAlias  // exactly BE32(2) for this profile
legacySettlementDomainAlias // authenticated canonical felt paired with the strong domain
strongSettlementDomainId
globalSequence
legacyNullifierRoot
strongNullifierRoot
legacyGovernedRootAliases
strongGovernedRootRegistry
strongPaymentStateRoot
consumedBatchNonces
recordedStrongBatchCommitments
```

No element may be advanced or rolled back independently of the others.
The profile/governance record authenticates the protocol alias and the exact legacy/strong domain
pair; the strong domain is never derived from the legacy felt. The historical strong-nullifier root
also authenticates one context-free hidden master-salt-use key per batch, after the 256 ordered slot
keys, and is retained across migration and recovery.

### Lifecycle phases

1. **Genesis draft.** Freeze a reviewed source/tool/input manifest and one exact synthetic canonical-
   record snapshot. Derive legacy and strong structures independently from the same raw records.
   Genesis constants, tree encodings, and suite identities remain `TBD-S09`.
2. **Migration preparation.** Rebuild both paths reproducibly, produce same-record/same-operation
   equivalence evidence, test a migration proof when defined, drain the proof queue, and invalidate
   every pending proof tied to another checkpoint.
3. **Activation preflight.** Require reviewed S07-S12 decisions, verifier artifact readback, SBOM and
   reproducible-build evidence, cross-language vectors, attack gates, and an atomic rollback
   checkpoint. Any mismatch aborts before state mutation.
4. **Atomic activation.** In one transaction select the profile, suite, schema, verifier identity,
   epoch, domain, sequence, legacy state, strong state, governed registry, and resolved payment state.
   Partial activation is forbidden.
5. **Normal transition.** Accept only the one active profile/suite/schema/verifier/epoch and the exact
   current before-state. Competing proofs from one before-state cannot both commit.
6. **Upgrade.** A suite, schema, verifier, hash construction, or state-layout change requires a new
   profile or epoch, new vectors, new migration evidence, a queue drain, and another atomic activation.
7. **Pre-activation rollback.** Restore the complete reviewed pre-activation checkpoint and prove by
   readback that no new-profile state was accepted.
8. **Post-activation recovery.** Restore one complete consistent checkpoint only under the reviewed
   recovery process, then advance epoch and settlement domain so every proof pending before recovery
   is invalid. Root-only or code-only rollback is forbidden.

### Mixed-profile rejection

- Before activation, `BL-PQ512-v1` proofs MUST NOT advance legacy live state.
- At activation there is no interval in which old and new profiles can both update the same state.
- After activation, old, unknown, downgraded, or mixed profile/suite/schema/verifier combinations
  MUST be rejected before any mutation.
- A legacy alias matching while any strong value differs MUST fail closed.
- A strong value matching while any required legacy value differs MUST fail closed.
- Failed verification, parsing, persistence, or readback MUST leave every state element unchanged.

### S10 unresolved gates

- security budget and field/challenge assumptions: `TBD-S07`;
- M31 extension, FRI, query, blowup, and grinding decisions: `TBD-S08`;
- PCS/transcript/tree primitives, exact encodings, domain tags, suite ID, and multi-target treatment:
  `TBD-S09`;
- S12 consumes this lifecycle specification and must be present before activation; S12 is not a
  dependency for writing or closing S10 itself;
- strong payment/asset state type and transition: normative A11/P05 design inputs are required
  before S04/S10 closure, while their implementation packages remain downstream;
- production verifier/state implementation and durable atomicity: P07-P10;
- governance authorization and operational recovery ceremony: P12/O01/O06.

## Foundation acceptance boundary

This draft is review-ready only if:

- the external ABI still has exactly the 12 ordered fields above;
- no S07-S09 parameter has been selected or implied;
- metadata sidecar and proof body remain distinct;
- verifier artifact identity and unresolved strong payment-state binding are explicit;
- all required threat classes and all 12 field notions are present;
- S10 remains provisional and non-activatable;
- tests and documentation continue to say synthetic-only and non-production.

Passing those checks does not close S02-S06 or S10. Closure requires explicit review and roadmap
reconciliation; S10 additionally requires its stated dependencies.
