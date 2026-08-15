# Lean formal security kernel

Updated: 2026-08-14
Status: approved deferred target architecture and production-shaped semantic plug-in. Current
qualification status is authoritative in `STATE.md` and `CURRENT_TASK.md`; Lean work remains
phase-gated, is not a current implementation stage, and the kernel is not yet implemented or
linked to the deployed path; it is not production credit until those gates pass.

## Purpose

Blind Ledger will use Lean 4 for the smallest executable kernel that can authorize a clearance
semantic result or a clearance-state transition. Lean is not a side model and is not a claim that
the surrounding product, source data, database, cryptographic backend, or operations are formally
verified. The production design must either execute the proved Lean definitions or establish a
reviewed refinement proof from those definitions to the deployed implementation.

Until that link exists and the required theorem/build gates pass, the repository must not claim a
formally verified deployed kernel.

## Production-shaped patch-in contract

The Lean kernel is designed to replace the current semantic authority behind a fixed interface, not
to redesign the business contract. It must preserve the five directives, `policyResult`/
`effectiveDirective` separation, verifier-owned control-set and rule order, authoritative absence,
four-time chronology, exception identity, decision/access join, replay, and allowed after-state.
The production plug-in is the executable Lean artifact plus a narrow native adapter; it is qualified
against the existing canonical KATs, independent verification, mutation/replay/recovery, and
resource gates. A disagreement or an interface change fails closed and requires architecture review.
The read-only provider-continuity wedge may qualify its authenticated source and operational-store
adapters before this private-clearance kernel is linked.

## Ownership boundary

Lean owns the pure, deterministic meaning of:

- the five directives and the separation of `policyResult` from `effectiveDirective`;
- verifier-owned automatic-control-set selection, ordered rules, conflicts, scope, and effective
  intervals;
- authoritative completeness/nonmembership and the prohibition on inferring absence from an
  incomplete population;
- event, observation, rule-effective, and decision chronology;
- governed exception eligibility and the exact no-exception sentinel;
- read-only assessment versus operative clearance authority;
- canonical request, fact, receipt, and state-transition decoding for the authoritative semantic
  boundary;
- replay, retry, exact before-state, decision/access join, and allowed after-state;
- the rule that only `CLEAR` or a valid `EXCEPTION_APPROVED` may advance economic clearance state;
  and
- periodic checkpoint-chain construction as an audit commitment with no payment authority.

Rust continues to own the native cryptographic verifier, transcript reconstruction, proof-format
checks, bounded transport, storage integration, and operating-system boundary. The database owns
serialization, concurrency, durability, idempotency, recovery, and the committed operational
state. Adapters, Provider App, Mirror, the Switch, telemetry, and Ethereum submission stay outside
the Lean trusted kernel.

For the private path, Rust proof acceptance is necessary but not sufficient for mutation. The
exact proof-bound typed receipt and proposed transition must also be accepted by the Lean semantic
kernel before the database can commit. For the direct state-owned path, the Lean kernel evaluates
the exact canonical governed plaintext input. A caller cannot select either mode or promote an
observation-only evaluation into clearance authority.

## Planned module boundary

The initial implementation should be a small pinned project under `formal/lean/`:

```text
BlindLedger/Types.lean
BlindLedger/Codec.lean
BlindLedger/ControlSet.lean
BlindLedger/Evaluation.lean
BlindLedger/Exception.lean
BlindLedger/StateTransition.lean
BlindLedger/Checkpoint.lean
BlindLedger/Theorems.lean
BlindLedger/Executable.lean
```

The project pins one stable Lean toolchain and exact dependency lock. Avoid broad libraries and
metaprogramming in the trusted path. The build must retain the toolchain identity, source hashes,
theorem manifest, generated native artifact identity, and any admitted axioms.

## Required theorem gates

Names may be refined when the exact types freeze, but the properties may not be weakened:

1. `evaluation_deterministic`: identical governed input has one result.
2. `proof_acceptance_ne_clear`: proof/session acceptance alone cannot imply `CLEAR`.
3. `observe_only_no_operative_clearance`: the commercial read-only wedge cannot create an
   operative clearance decision or economic mutation.
4. `absence_requires_authoritative_completeness`: missing data from an incomplete feed cannot
   produce an automatic absence conclusion.
5. `policy_effective_separation`: the underlying result is preserved through exception handling.
6. `exception_requires_exact_authorization`: an exception is valid only for the exact role,
   subject, rule, amount or bound, reason, scope, interval, and underlying result.
7. `nonclear_no_economic_mutation`: `HOLD`, `HUMAN_REVIEW`, and `BLOCK` cannot advance economic
   clearance state.
8. `wrong_control_set_rejects`: a mismatched mode, rule order, conflict policy, scope, or interval
   cannot evaluate under another control set.
9. `chronology_strict`: the four times satisfy the frozen control-set relation.
10. `replay_preserves_state`: replay, conflicting retry, or wrong before-state cannot advance
    state.
11. `decision_access_join_unique`: every admitted access belongs to exactly one decision in the
    required order and no decision/access row is omitted or duplicated.
12. `decode_encode_roundtrip` and `canonical_encoding_injective`: authoritative bytes have one
    bounded interpretation and equivalent records cannot have competing encodings.
13. `checkpoint_chain_append_only`: each audit checkpoint binds the exact prior checkpoint and
    ordered batch without acquiring operational authority.

The theorem manifest must fail CI if a theorem disappears, its statement changes without an
explicit architecture review, or an unapproved axiom enters its dependency closure. Kernel checks,
including an independent environment check such as `lean4checker`, run from a clean pinned build.

## Executable correspondence

The preferred deployment is a Lean-compiled native library behind a narrow C-compatible boundary.
Rust passes the exact canonical bytes, receives either one typed result or a fail-closed error, and
does not reauthor the decision. A Rust parser may reject malformed transport earlier, but it cannot
replace the authoritative Lean decode/evaluation result. Any Rust/Lean disagreement rejects.

If measurements later show that one bounded parser or hash primitive cannot safely execute in the
Lean artifact, the exception requires a narrow external primitive specification, independent known
answer tests, an explicit trust assumption, and a proof that no semantic authority moved into an
unchecked convenience layer. Performance alone does not justify a separate unproved evaluator.

Lean-generated known-answer vectors and mutation fixtures must be consumed by the independent Rust
tests. Differential tests are required, but they do not substitute for executing the proved kernel
or proving implementation refinement.

## Proof-system correspondence

Lean proves the business relation and allowed state transition. It does not make an external ZK
backend sound by declaration. Before a private suite can receive production credit, the exact
native-v3 relation proved by the cryptographic system must map to the Lean relation under an
explicit, reviewed theorem boundary. Cryptographic assumptions, hash assumptions, external source
truth, signature security, and backend soundness remain named assumptions until separately closed.

The complete finite `<=2^-128` composition ledger should use machine-checked arithmetic and explicit
union terms where practical, but Lean must not turn an ideal-model or assumed cryptographic bound
into an unconditional theorem.

## Database and concurrency boundary

Lean specifies legal atomic transitions and proves their local invariants. It does not by itself
prove that a production database provides serializability, durability, crash recovery, or external
anti-rollback. Those properties require database evidence and may use an additional concurrency
model such as TLA+ while remaining consistent with the Lean transition relation.

## Nonclaims

Formal verification does not establish that a source told the truth, a policy is wise or lawful,
an authoritative feed is operationally complete, a cryptographic assumption holds, a database is
available, PHI controls are effective, funds moved, or Ethereum finalized a checkpoint. Each
boundary keeps its own evidence and claim.

Current nonactivation flags, source/payment boundary, and qualification status are authoritative in
`STATE.md`; this document retains the theorem and formal-verification gates for the plug-in.

## Implementation sequence

Do not begin this sequence in the current phase. The nonpayment commercial wedge and operational
foundations come first. Lean begins only after explicit phase authorization, but it remains a
mandatory gate before production clearance or payment authority.

1. Freeze the Lean types and theorem statements against the current Phase-0 and continuity V2
   vectors without changing their semantics.
2. Implement the pure evaluator and read-only/operative authority separation; reproduce every
   current positive and negative vector.
3. Implement bounded canonical decoding and prove round-trip/injectivity properties.
4. Implement the decision/access/state transition and required theorems.
5. Produce the native Lean artifact and a minimal Rust adapter that fails closed on any mismatch.
6. Add clean-build, theorem-manifest, axiom, independent-kernel-check, cross-language KAT,
   mutation, and resource gates.
7. Only then bind the private-proof receipt relation and production database candidate to the
   formal kernel.
