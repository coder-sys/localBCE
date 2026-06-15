# Batching Re-Architecture Plan

Status: planning artifact only. No implementation code in this run.

Goal: move the app layer from one proof per claim to one proof per batch, while preserving per-claim auditability, appeals, and 835 generation. This reduces on-chain verifier cost by amortizing one proof over many claims.

## 1. Current One-Claim Flow

Current flow, mapped to existing files:

- 837 ingestion: `app/ingestion.py`
- Shared context creation: `app/shared_context.py`
- Rules engine adapter: `app/rules_engine_adapter.py`
- Canonical Rust rules engine: `rules-engine-rust/src/lib.rs`
- Python fallback rules engine: `app/rules_engine_fallback.py`
- Demo prover and verifier: `app/stubs.py`
- Demo orchestrator: `app/orchestrator.py`
- JSON demo registry: `app/registry.py`
- Solidity claim registry: `contracts/src/ClaimsRegistry.sol`
- Groth16 verifier adapter: `contracts/src/ClaimVerifierAdapter.sol`
- Generated Groth16 verifier: `contracts/src/GeneratedClaimVerifier.sol`
- Payment trigger: `contracts/src/PaymentTrigger.sol`
- Payment bridge interface and stubs: `contracts/src/IBridge.sol`
- 835 generator: `app/generator_835.py`
- Appeal router: `app/appeal_router.py`
- Dashboard state and static page: `app/dashboard.py`, `dashboard/index.html`

Today, the Python demo path in `app/orchestrator.py` proves one claim at a time through `ZKProverStub`, verifies through `VerifierStub`, stores one claim in a JSON registry, optionally triggers one mock Circle payment, emits one 835, and routes one appeal.

The Solidity path in `contracts/src/ClaimsRegistry.sol` also records one claim at a time through:

```solidity
mapping(bytes32 => ClaimResult) public claims;

function recordClaim(
    bytes32 claimId,
    bool approved,
    string calldata denialReason,
    bytes32 contextHash,
    bytes calldata proof,
    bytes32[] calldata publicInputs
) external
```

That design is simple, but it forces one proof verification per claim.

## 2. Where Batching Slots Into The Existing Flow

Batching should slot in after shared-context creation and before proof generation.

Current single-claim path:

```text
parse_837 -> build_shared_context -> adjudicate -> prove one claim -> verify one proof -> record one claim -> trigger one payment -> generate one 835
```

Proposed batch path:

```text
parse many 837 claims
-> build many SharedContext objects
-> adjudicate each claim with Rust G1-G10
-> canonicalize each claim/result into leaves
-> build Merkle claim tree + result tree + payment tree + nullifier transition
-> prove the whole batch once
-> verify one batch proof
-> record batch roots on-chain
-> settle payments by batch/provider netting
-> keep per-claim 835 and appeal packets with Merkle inclusion paths
```

Future code-work likely lands in new files such as:

- `app/batching.py` for batch assembly, canonical leaf serialization, and Merkle tree building.
- `app/batch_orchestrator.py` or a new mode in `app/orchestrator.py` for batch execution.
- `rules-engine-rust/src/lib.rs` or a new Rust batch wrapper for applying the same G1-G10 logic across many claims.
- `contracts/src/BatchClaimsRegistry.sol` or a carefully versioned extension of `contracts/src/ClaimsRegistry.sol`.
- `contracts/src/BatchPaymentTrigger.sol` or a versioned extension of `contracts/src/PaymentTrigger.sol`.

## 3. Batch Leaves And Merkle Trees

Each claim should produce at least two canonical leaves.

Claim input leaf:

```text
claim_leaf = hash(
  claim_id_hash,
  normalized_context_hash,
  member_id_hash,
  provider_npi_hash,
  service_date,
  service_lines_hash,
  diagnosis_hash,
  charge_cents,
  prior_auth_hash,
  ruleset_version
)
```

Result leaf:

```text
result_leaf = hash(
  claim_id_hash,
  approved_bit,
  first_failed_gate_code,
  denial_reason_hash,
  carc_hash,
  rarc_hash,
  payable_amount_cents,
  nullifier,
  ruleset_version
)
```

Payment leaf:

```text
payment_leaf = hash(
  provider_payment_key_hash,
  batch_id,
  approved_claim_count,
  net_amount_cents,
  payment_rail,
  settlement_instruction_hash
)
```

Nullifier leaf:

```text
nullifier_leaf = hash(nullifier)
```

The batch builder should emit:

- `claimRoot`: Merkle root of claim input commitments.
- `resultRoot`: Merkle root of adjudication results.
- `paymentRoot`: Merkle root of provider/payment netting rows.
- `nullifierRootBefore`: prior spent-nullifier tree root.
- `nullifierRootAfter`: updated spent-nullifier tree root after this batch.
- `rulesetRoot`: commitment to the exact rules/RARC mapping/version used.

Canonical serialization must be frozen before audit. If two languages serialize the same claim differently, the proof and contract will disagree.

## 4. What The Single Batch Proof Proves

For a batch of `N` claims, the single proof should prove:

1. Every private normalized claim input was included in `claimRoot`.
2. The G1-G10 adjudication logic was applied to every claim.
3. The public result for each claim is correct:
   - decision bit
   - first failed gate
   - denial reason
   - CARC/RARC mapping
   - payable amount
4. Every result leaf is included in `resultRoot`.
5. Each claim nullifier was not already spent at `nullifierRootBefore`.
6. The nullifier tree transition from `nullifierRootBefore` to `nullifierRootAfter` is valid.
7. Duplicate claims inside the same batch are rejected.
8. Payment netting rows are derived from approved claim results and committed in `paymentRoot`.
9. The proof binds to `rulesetRoot`, so a prover cannot silently switch policy mappings.

Proof system choices:

- Groth16 batch circuit: lower EVM gas, but fixed batch sizes and trusted setup per circuit size.
- SP1/RISC Zero SNARK-wrapped zkVM: easier Rust reuse, cheaper EVM verification than native STARK, but the EVM anchor is pairing-based and not post-quantum.
- Native STARK/FRI verifier: best post-quantum story, but much higher gas and expert build/audit burden.
- Off-chain STARK verification with on-chain root/attestation: practical for a government environment, but weaker trustless on-chain verification.

## 5. On-Chain Changes

Current contract field in `contracts/src/ClaimsRegistry.sol`:

```solidity
mapping(bytes32 => ClaimResult) public claims;
```

Proposed batch-oriented fields:

```solidity
struct BatchResult {
    bool exists;
    bytes32 claimRoot;
    bytes32 resultRoot;
    bytes32 nullifierRootBefore;
    bytes32 nullifierRootAfter;
    bytes32 paymentRoot;
    bytes32 rulesetRoot;
    bytes32 verifierKeyId;
    uint256 claimCount;
    address submitter;
    uint256 timestamp;
}

mapping(bytes32 => BatchResult) public batches;
mapping(bytes32 => bool) public usedNullifierRoots;
```

Optional fields, depending on product and privacy decisions:

```solidity
mapping(bytes32 => bytes32) public claimToBatch;
mapping(bytes32 => bool) public knownResultLeaves;
```

Proposed function shape:

```solidity
function recordBatch(
    bytes32 batchId,
    bytes32 claimRoot,
    bytes32 resultRoot,
    bytes32 nullifierRootBefore,
    bytes32 nullifierRootAfter,
    bytes32 paymentRoot,
    bytes32 rulesetRoot,
    bytes32 verifierKeyId,
    uint256 claimCount,
    bytes calldata proof,
    bytes32[] calldata publicInputs
) external;
```

The existing `recordClaim` can remain temporarily for compatibility, but the batch architecture should treat `recordBatch` as the canonical settlement anchor.

Events should change from one `ClaimRecorded` event per claim to one batch event:

```solidity
event BatchRecorded(
    bytes32 indexed batchId,
    bytes32 claimRoot,
    bytes32 resultRoot,
    bytes32 nullifierRootAfter,
    bytes32 paymentRoot,
    uint256 claimCount,
    address indexed submitter
);
```

If on-chain per-claim discovery is required, add an optional indexed `ClaimIndexed` event. That leaks more metadata and costs more gas, so it needs a privacy/product decision.

## 6. Individual Claim Audit And Appeal

Per-claim auditability comes from Merkle inclusion, not from writing every claim result to contract storage.

For each claim, the batch system must retain:

- `batchId`
- `claimIndex`
- `claimLeaf`
- `resultLeaf`
- Merkle path from `claimLeaf` to `claimRoot`
- Merkle path from `resultLeaf` to `resultRoot`
- The normalized context used by the rules engine
- The adjudication result
- The 835 output

`app/appeal_router.py` should receive or produce appeal packets with:

```text
claim_id
batch_id
claim_index
denial_reason
first_failed_gate
carc
rarc
claim_leaf
result_leaf
claim_merkle_path
result_merkle_path
```

For an appeal, a reviewer can verify that the disputed claim was part of the recorded batch without needing every other claim in that batch.

If court/regulator workflows require on-chain proof of inclusion, add a read-only helper contract:

```solidity
function verifyClaimInBatch(
    bytes32 batchId,
    bytes32 resultLeaf,
    bytes32[] calldata merklePath,
    uint256 leafIndex
) external view returns (bool);
```

That helper does not prove the rule logic by itself. It only proves that a result was included in a batch whose proof was already accepted.

## 7. Payment Settlement Changes

Current contract in `contracts/src/PaymentTrigger.sol`:

```solidity
function triggerApprovedClaim(bytes32 claimId, address recipient, uint256 amount)
```

Current Python demo in `app/orchestrator.py`:

```python
CircleBridgeStub().trigger(result.claim_id, result.payable_amount, ctx.provider.npi)
```

Batch architecture should avoid one payment trigger per claim. It should settle net amounts per provider or payment account.

Proposed contract shape:

```solidity
function triggerBatchSettlement(
    bytes32 batchId,
    bytes32 paymentRoot,
    uint256 totalAmount,
    bytes32 settlementInstructionHash
) external returns (bytes32 settlementRef);
```

Alternative provider-claimable shape:

```solidity
function triggerProviderNetSettlement(
    bytes32 batchId,
    address recipient,
    uint256 amount,
    bytes32 paymentLeaf,
    bytes32[] calldata paymentMerklePath,
    uint256 paymentLeafIndex
) external returns (bytes32 settlementRef);
```

Required file changes in a future build:

- `contracts/src/PaymentTrigger.sol`: replace or add batch settlement methods.
- `contracts/src/IBridge.sol`: replace single-claim `triggerPayment` with batch/provider-net settlement methods.
- `app/orchestrator.py` or new `app/batch_orchestrator.py`: replace per-claim payment trigger with a batch netting step.
- `app/generator_835.py`: keep per-claim 835 generation, but include batch/control references if billing-domain review requires them.

Real Circle/FedNow movement remains external-partner work. Code can prepare settlement instructions, but access to payment rails is not solved by code alone.

## 8. What Breaks In The Current App Layer

Expected breakpoints:

- `tests/test_pipeline.py::PipelineTests::test_end_to_end_demo` expects one claim, one stub proof, one JSON registry entry, one payment stub, and one 835 path.
- `app/orchestrator.py` assumes a single `SharedContext` and single `AdjudicationResult`.
- `app/registry.py` stores individual claim records in JSON, not batch roots.
- `app/stubs.py::ZKProverStub` emits one fake proof per claim.
- `app/stubs.py::VerifierStub` verifies one fake proof shape.
- `contracts/test/ClaimsRegistry.t.sol::testRecordApprovedClaimStoresFields` assumes `recordClaim` and `claims(claimId)`.
- `contracts/test/ClaimsRegistry.t.sol::testRecordDeniedClaimStoresReason` assumes per-claim denial storage.
- `contracts/test/ClaimsRegistry.t.sol::testRejectsDuplicateClaim` assumes duplicate detection by `claimId` in a per-claim mapping.
- `contracts/test/ClaimsRegistry.t.sol::testRejectsInvalidProof` assumes the old verifier interface.
- `contracts/test/ClaimsRegistry.t.sol::testRealGroth16ProofRecordsClaim` assumes the current single-claim public input format.
- `contracts/test/ClaimsRegistry.t.sol::testRealGroth16ProofRejectsTamperedPublicInput` must be rewritten for batch public inputs.
- `contracts/test/ClaimsRegistry.t.sol::testPaymentTriggerOnApprovedClaim` assumes per-claim payment trigger.
- `contracts/test/ClaimsRegistry.t.sol::testPaymentTriggerRejectsZeroAmount` remains relevant, but should become a batch/provider-net amount check.
- `contracts/src/ClaimVerifierAdapter.sol` currently assumes four public inputs for the single-claim Groth16 verifier.
- `contracts/src/GeneratedClaimVerifier.sol` is generated for the current single-claim circuit and cannot verify a batch circuit.
- `zk/circuits/claim_adjudication_core.circom` is single-claim and would need a separate batch circuit rather than an in-place mutation.
- `zk-stark/src/lib.rs` is a single-claim STARK proof-of-concept and would need a batch trace/AIR.
- `zk-sp1/` currently has SP1 scaffolding, but previous local proving was blocked by resource limits. Batch SP1 proving would be heavier.

What should not break:

- The core G1-G10 rule semantics in `rules-engine-rust/src/lib.rs`.
- The Python/Rust agreement tests for individual claim decisions.
- The per-claim 835 generator API, if the batch layer feeds it individual `AdjudicationResult` objects.

## 9. Effort Estimate

Batch model and canonical serialization:

- Type: code-work plus audit prep.
- Prototype: 1-2 days.
- Hardened: about 1 week.
- Risk: cross-language serialization drift.

Merkle utilities and test vectors:

- Type: code-work.
- Prototype: 1-2 days.
- Hardened: 3-5 days.
- Risk: wrong leaf ordering or path convention breaks proofs and appeals.

Batch orchestrator:

- Type: code-work.
- Prototype: 1-3 days.
- Hardened: 1 week.
- Risk: one failed claim should not corrupt the whole batch without a clear rejection policy.

Rust batch rules wrapper:

- Type: code-work.
- Prototype: 2-4 days.
- Hardened: 1-2 weeks.
- Risk: first-failed-gate and CARC/RARC semantics must stay exactly aligned with existing tests.

Batch ZK circuit or zkVM program:

- Type: careful/audit-track.
- Groth16 fixed-size prototype: 1-2 weeks per useful batch size.
- STARK or zkVM prototype: 2-4 weeks depending on toolchain limits.
- Production: requires human cryptographic audit.
- Risk: underconstrained batch/nullifier logic silently breaks duplicate prevention.

Batch ClaimsRegistry contract:

- Type: code-work plus security audit.
- Prototype: 2-4 days.
- Hardened: 1-2 weeks plus audit.
- Risk: root replay, bad access control, accidental metadata leakage.

Batch payment trigger:

- Type: code-work for stubs; external-partner-work for real rails.
- Prototype with stubs: 2-5 days.
- Real Circle/FedNow: partnership/access timeline, likely weeks to months.
- Risk: payment reversals, settlement reconciliation, and authorization are business controls, not just Solidity.

835 batch references:

- Type: code-work plus billing-domain review.
- Prototype: 1-3 days.
- Hardened: domain review required.
- Risk: X12 semantics and payer requirements may not match the generic design.

Appeal and audit inclusion packets:

- Type: code-work plus legal/policy review.
- Prototype: 2-4 days.
- Hardened: 1-2 weeks plus review.
- Risk: exposing too much private claim data in audit packets.

Regulatory and RARC/CARC ratification:

- Type: careful/domain track.
- Timeline: human review dependent.
- Risk: technically consistent codes can still be wrong for Medi-Cal operations.

## 10. Human Decisions Needed Before Building

1. Batch size and latency: small batches reduce delay but save less gas; large batches save more gas but delay settlement.
2. Proof system: Groth16 batch, SNARK-wrapped zkVM, native STARK, or off-chain STARK verification with on-chain attestation.
3. Post-quantum posture: whether the on-chain trust anchor must be post-quantum now, or whether PQ proof generation plus non-PQ EVM wrap is acceptable temporarily.
4. Data privacy: whether `claimToBatch` or per-claim events are allowed on-chain.
5. Appeal UX: whether appeals verify inclusion off-chain, on-chain, or both.
6. Nullifier policy: whether nullifiers are per claim, per provider-claim-service tuple, or another canonical identity.
7. Payment rail: Circle, FedNow, both, or a manual treasury bridge during pilots.
8. Netting policy: net per provider, per payer, per program, per day, or per batch.
9. Failure policy: reject entire batch on one malformed claim, or quarantine bad claims before proof generation.
10. Access control: who can submit batches and who can trigger settlement.
11. RARC/CARC ratification: especially the G8 invalid-charge versus excessive-charge split.
12. Audit owner: which external cryptographic auditor and which Medi-Cal/domain reviewer sign off.

## 11. Recommended Build Order

1. Freeze canonical claim/result leaf formats and write language-independent test vectors.
2. Add Merkle utilities and batch assembly in the app layer, without touching contracts.
3. Keep the current per-claim rules tests green while adding batch-level tests.
4. Add a new batch registry contract alongside the current `ClaimsRegistry`, not as a replacement.
5. Add batch registry Forge tests for root storage, duplicate batch rejection, invalid proof rejection, and inclusion helper behavior.
6. Build an off-chain batch proof first and verify it locally.
7. Wire the batch proof to a standalone contract test.
8. Move payment to `paymentRoot` and provider-net settlement with stubs.
9. Add appeal packets with claim/result inclusion paths.
10. Only after tests, audit, and domain review should the old per-claim settlement path be retired.

## 12. Architecture Bottom Line

Batching is the right gas-reduction direction. It changes the chain from "verify every claim" to "verify one commitment to many correctly adjudicated claims." The cost shifts into batch construction, Merkle audit data, and a more complex proof statement.

This is not a one-line optimization. It changes `ClaimsRegistry`, `PaymentTrigger`, the prover public inputs, the test suite, and the operational model for appeals and settlement. The safest path is to build it beside the current one-claim flow, prove equivalence on test batches, then migrate.
