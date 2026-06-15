# Circuit / Crypto / Economic Audit Notes

Status: soundness-checked where locally executable, PENDING CRYPTOGRAPHIC AUDIT.

Scope: app-layer and `zk-sp1` glue only. The protected Groth16 `zk/` circuits and Winterfell `zk-stark/` artifacts were not modified.

## Local Tests Added Or Re-Run

- `tests/attacks/test_deep_original_attack_hunt.py`: the five local-now holes are now regression tests for the blocked behavior.
- `tests/attacks/test_harder_attack_surface_hunt.py`: new deeper-hunt tests for hash domain separation, claim-count public-input binding, mixed quarantine metadata exposure, ruleset-root semantics, and SP1 public-value scope.
- `tests/attacks/test_phase2_fixed_architecture_attacks.py`: updated duplicate-only batch expectation so the app recorder mirrors the contract's empty-batch rejection.
- `tests/attacks/test_open_ended_adversarial_hunt.py`: open-ended hunt for config-secret failure, policy-bundle omissions, amount weirdness, quarantine identity, and payment access-control footguns.
- `contracts/test/attacks/OpenEndedHunt.t.sol`: governance bricking proof for last-admin revoke.

## A. Circuit Logic / Constraint-Level Analysis

1. SP1 single-claim public values now include a batch-context commitment.
   - Local evidence: `public_values_bind_batch_ruleset_payment_context_and_reject_context_swap`.
   - Current SP1 public values bind `raw_claim_identity_commitment`, `batch_context_commitment`, `decision`, and `failure_code`.
   - The context commitment is the guest-side binding point for ruleset/payment/batch context.
   - Constraint-level enforcement still needs a real generated proof and audit.
   - Verdict: guest-side binding is implemented; constraint-level status is PENDING AUDIT - NOT LOCALLY PROVEN.

2. Raw 837 parsing is still outside the proof.
   - Local evidence: prior SP1 execute-mode tests proved normalized `ClaimInput`, not raw 837 parsing.
   - The raw claim identity commitment blocks simple proof-output reuse only if every consumer recomputes the same canonical commitment.
   - Verdict: needs an audited canonicalization spec before production trust.

3. Nullifier non-membership circuit was not re-run in this phase.
   - Local evidence in this run: anchor unchanged for `zk/circuits/nullifier_nonmembership.circom`.
   - Prior status remains: soundness-checked/static-tested, PENDING CRYPTOGRAPHIC AUDIT.
   - Verdict: do not treat static checks as a substitute for ZK audit. A conceptual non-membership bug can survive circomspect.

4. Full SP1 proof soundness was not locally executed in this phase.
   - Reason: this run was scoped to app-layer + SP1 glue and protected anchors; prior SP1 proof generation remained RAM/tooling constrained.
   - Verdict: core execution/equivalence is tested; real proof generation and wrapped EVM verification remain separate proof-track work.

## B. Crypto Protocol Findings

1. Hash record-type domain separation is present.
   - Local evidence: `test_crypto_record_type_domain_separation_blocks_same_field_collision`.
   - Same fields under `claim_leaf`, `result_leaf`, `payment_leaf`, `duplicate_leaf`, and `combined_batch_commitment` produce distinct digests.
   - Verdict: BLOCKED for this collision class.

2. Structured private hashing is now canonical.
   - Local evidence: `test_own_category_semantic_dict_hash_is_insertion_order_stable_blocked`.
   - The code now JSON-canonicalizes dict/list/tuple values before hashing.
   - Verdict: BLOCKED for insertion-order drift.

3. Claim and payment counts are now bound into verifier public inputs and the combined commitment.
   - Local evidence: `test_contract_public_inputs_bind_claim_count_blocked`, `testClaimCountMismatchAgainstPublicInputsRejected`.
   - Latest source-review evidence: `testPaymentIndexPastPaymentCountRejectsPadding` and `testCombinedCommitmentRejectsSwappedVerifierKeyId`.
   - The contract default public input length is now 11: index 9 must equal `bytes32(submission.claimCount)`, and index 10 must equal `bytes32(submission.paymentCount)`.
   - `computeCombinedBatchCommitment` now includes `verifierKeyId`, `claimCount`, and `paymentCount`.
   - Verdict: BLOCKED for the app/contract statement. Future batch circuits still need explicit padding/count constraints.

4. Ruleset approval is now content-addressed for the executable policy bundle.
   - Local evidence: `test_ruleset_record_is_content_addressed_blocked`.
   - Same label plus different policy content gives a different root and is rejected unless separately approved.
   - Current default bundle includes `rarc_mapping.tsv`, `rules-engine-rust/src/lib.rs`, `rules-engine-rust/src/main.rs`, `app/rules_engine_fallback.py`, and `app/rules_engine_adapter.py`.
   - Verdict: BLOCKED for approved executable policy files; signed human ratification records still belong in the governance process.

5. SP1 public values now bind a context commitment.
   - Local evidence: `test_sp1_public_values_bind_batch_context_commitment_blocked`.
   - Impact: consumers can reject a proof output checked against the wrong ruleset/payment/batch context.
   - Caveat: full cryptographic enforcement needs a real proof and an audited definition of the context commitment.
   - Verdict: guest-side BLOCKED; constraint-level PENDING AUDIT - NOT LOCALLY PROVEN.

## C. Economic / Game-Theory Findings

1. Raw NPI no longer leaves the per-claim payment rail.
   - Local evidence: `test_spec_vs_code_payment_stub_receives_provider_payment_alias_blocked`.
   - The per-claim bridge gets `provider_payment_key:<hmac-sha256>`, not `1999999987`.
   - Local evidence for keyed behavior: `test_provider_payment_alias_is_keyed_and_not_reproducible_without_key_blocked`.
   - Missing `BL_PROVIDER_ALIAS_KEY` now fails closed instead of falling back to a known local dev key.
   - Verdict: raw leakage, unkeyed dictionary attack, and missing-secret fallback are blocked; production secret management remains required.

2. Quarantine-only batches are no longer recorded.
   - Local evidence: `test_economic_quarantine_only_batch_is_not_recorded_blocked` and updated Phase 2 duplicate-only test.
   - Verdict: BLOCKED for empty/quarantine-only record spam.

3. Mixed valid + many invalid batches still expose operational exception counts.
   - Local evidence: `test_mixed_valid_batch_can_still_expose_large_quarantine_count_succeeded`.
   - Causal chain: one valid claim plus many invalid payloads records `claim_count=1` and `quarantine_count=N`.
   - Impact: on-chain or dashboard observers can infer exception volume and potentially stress/embarrass operations.
   - Recommended fix: decide whether quarantine counts belong off-chain, delayed, bucketed, or separately access-controlled.
   - Verdict: PARKED SIDE-CHANNEL, as requested.

4. Governance is still a high-trust control point.
   - Local evidence: contract tests already model accepting vs fail-closed checkers.
   - Causal chain: an admin can approve rulesets and verifier/checker contracts. If admin governance is compromised or careless, the proof layer can be bypassed by approving the wrong checker.
   - Recommended fix: multisig/timelock, verifier-key allowlist, emergency pause, independent auditor sign-off before enabling new verifiers.
   - Verdict: EXTERNAL GOVERNANCE/AUDIT TRACK.

## D. Invented Attack Patterns To Carry Forward

1. Semantic ruleset drift.
   - Same label, different main Rust policy bundle is now blocked by content-addressed roots.
   - The executable Rust and Python fallback/adapter policy paths are now included.
   - Remaining fix: add signed cofounder/domain ratification records to governance.

2. Provider alias dictionary attack.
   - Hashing NPI/name hides the literal string from casual logs, but public NPI spaces are searchable.
   - Fix with partner-issued provider payment tokens or deployment-secret keyed aliases.

3. Batch public-input mismatch by omission.
   - Any stored field not in the public inputs is policy metadata, not proof-bound truth.
   - Fix by creating a checklist: every on-chain stored field must be either public-input-bound, derived from a bound field, or explicitly labeled metadata.

4. Off-chain parser/proof split.
   - The proof sees normalized booleans and amounts. The parser decides how real 837 data becomes those booleans.
   - Fix by making parser canonicalization deterministic, signed, replay-resistant, and eventually either proven or separately attested.

5. Batch-size and padding ambiguity.
   - Roots alone do not explain how many leaves are real vs padded unless the circuit and public inputs bind count and padding rules.
   - Fix with claim-count binding plus explicit zero-leaf/padding constraints in the batch proof.

## E. Phase 1 Fixed Findings - 2026-06-14

1. Missing provider alias secret now fails closed.
   - Evidence: `test_provider_alias_missing_secret_fails_closed_blocked`.
   - Fix: `app/provider_alias.py` now raises when `BL_PROVIDER_ALIAS_KEY` is absent. Test code supplies an explicit test key through `tests/conftest.py`.

2. Content-addressed ruleset root now includes Python executable policy paths.
   - Evidence: `test_ruleset_content_root_includes_python_fallback_engine_blocked`.
   - Fix: `POLICY_ARTIFACTS` now includes `app/rules_engine_fallback.py` and `app/rules_engine_adapter.py` in addition to the Rust and RARC artifacts.

3. Batch ID now commits to quarantined payload records.
   - Evidence: `test_batch_id_includes_quarantined_payloads_blocked`.
   - Fix: batch ID derivation includes stable hashes of quarantined payload records.

4. Batch payment trigger now supports revokeRole and protects the final admin.
   - Evidence: `testPaymentTriggerGrantThenRevokeOperatorWorks` and `testPaymentTriggerRejectsRevokingLastAdmin`.
   - Fix: `BatchPaymentTrigger` now has `revokeRole`, emits `RoleRevoked`, and tracks `adminCount`.

5. Batch registry now protects the final admin.
   - Evidence: `testRegistryRejectsRevokingLastAdmin` and `testRegistryGrantSecondAdminThenRevokeWorks`.
   - Fix: `BatchClaimsRegistry` tracks `adminCount` and rejects revoking the last admin.

## F. Continued Open-Ended Hunt And Bounds Fixes - 2026-06-14

Skipped as prior-covered: duplicate replay/nullifier reuse, raw-NPI payment leakage, blank operator IDs, quarantine-only batch recording, dict insertion-order hashing, stale ruleset revocation after build, corrupt registry recovery, public output range checks, stale SP1 max-charge helper, malformed/empty proof stubs, missing provider secret fallback, omitted fallback artifacts, quarantine batch-ID collision, missing payment-role revoke, and last-admin bricking.

Bounds findings discovered in the open-ended hunt and fixed in the current bounds pass:

1. Result Merkle inclusion now rejects padding leaves past `claimCount`.
   - Evidence: `testPaddingZeroResultLeafPastClaimCountBlocked` and `test_python_merkle_verifier_rejects_padding_leaf_past_claim_count_blocked`.
   - Fix: `verifyClaimInBatch` / `checkClaimInBatch` reject `index >= claimCount`; Python `verify_inclusion` can enforce `leaf_count`.
   - Caveat: the ZK batch proof still needs external audit for equivalent count/padding constraints.

2. Merkle index high bits are now bounded.
   - Evidence: `testMerkleIndexHighBitsBlocked` and `test_python_merkle_verifier_rejects_high_index_bits_blocked`.
   - Fix: Solidity `_verifyRecord` rejects `index >= 2**MERKLE_DEPTH`; Python `verify_inclusion` rejects `index >= 2**len(siblings)`.

3. Contract now rejects `claimCount` above fixed Merkle capacity.
   - Evidence: `testClaimCountAboveMerkleCapacityBlocked`.
   - Fix: `submitBatch` rejects `claimCount > MERKLE_CAPACITY`.
   - Caveat: proof-side batch circuits still need audited count/capacity constraints.

4. Short public-input length governance misconfiguration is now rejected cleanly.
   - Evidence: `testShortPublicInputLengthMisconfigBlockedCleanly`.
   - Fix: checker config rejects lengths below the required statement shape; `_batchInputsMatch` also guards short input arrays before indexing.

5. Zero `max_claims` in app batch config is now rejected with a domain error.
   - Evidence: `test_zero_max_claims_config_rejected_with_domain_error_blocked`.
   - Fix: `submit_batches` validates `max_claims > 0`, `merkle_depth > 0`, and `max_claims <= 2**merkle_depth` before chunking.

Clean or blocked areas from this hunt:

1. App-side Merkle tree construction rejects over-capacity leaves.
   - Evidence: `test_python_merkle_tree_rejects_over_capacity_clean`.
   - Result: the builder refuses more leaves than `2**depth`; the weak area is verifier/index-bound validation, not tree construction.

2. CLM/SV1 amount mismatch is rejected before payment.
   - Evidence: `test_clm_sv1_amount_mismatch_rejected_before_payment_blocked` and `test_fresh_clm_sv1_amount_mismatch_rejected_before_835_blocked`.
   - Result: parser accepts syntactically valid EDI, but shared-context construction rejects `claim_total_mismatch`; no claim packet or payment is emitted.

3. Negative service-line amount under a positive claim total is rejected before payment.
   - Evidence: `test_negative_service_line_amount_rejected_before_payment_blocked`.
   - Result: shared-context construction rejects the CLM/service-line mismatch; no payment emitted.

4. Non-dict flags in the batch path remain quarantined rather than crashing.
   - Evidence: `test_batch_path_non_mapping_flags_are_quarantined_not_crashed_blocked`.
   - Result: batch returns `claim_count=0`, `quarantine_count=1`, reason `adjudication_failed`.

Convergence read:

The findings are getting less severe than the first attack runs. Earlier runs found real governance and manifest/secret hazards that could corrupt trust boundaries. This pass mostly found bound-check and configuration hardening problems around Merkle membership and batch metadata. Those are still worth fixing, especially before public audit/appeal workflows rely on inclusion proofs, but they are narrower than "wrong adjudication" or "money moves from a bad proof." The remaining highest-risk bucket is increasingly external-audit-only: ZK constraint soundness, proof wrapper trust, governance process, and production secret/ops controls.

## G. Cofounder/Claude Source-Review Follow-Up - 2026-06-15

These fixes were made in app-layer/contracts/zk-sp1 glue only. The protected Groth16 and Winterfell anchor artifacts were not modified.

Fixed in code and regression-tested:

1. Payment inclusion now has a real payment-count bound.
   - Fix: `BatchClaimsRegistry` stores `paymentCount`, public input index 10 binds it, and payment inclusion rejects `recordIndex >= paymentCount`.
   - Evidence: `testPaymentIndexPastPaymentCountRejectsPadding`; Forge full suite 55/55.

2. Combined batch commitment now binds the verifier identity and payment count.
   - Fix: `computeCombinedBatchCommitment` and app `combined_batch_commitment` include `verifierKeyId`, `claimCount`, and `paymentCount`.
   - Evidence: `testCombinedCommitmentRejectsSwappedVerifierKeyId`; Python full suite 131/131; Forge full suite 55/55.

3. Payment leaves now bind payout destination and approved-result set.
   - Fix: `payment_leaf` includes `recipient_commitment` and `approved_result_commitment`.
   - Evidence: `test_payment_leaf_binds_recipient_and_approved_result_set`.
   - Caveat: this commits to the app-side result set. A production batch proof must still prove `net_amount == sum(approved payable amounts)` inside the proof.

4. Result leaves now bind gate evidence, engine mode, and matching result identity.
   - Fix: `result_leaf` includes `gate_evidence_hash`, `policy_assertion_hash`, `engine_mode`, and rejects `result.claim_id != ctx.claim_id`.
   - Evidence: `test_result_leaf_binds_gate_evidence_and_engine_mode`, `test_engine_to_leaf_builder_gate_evidence_is_bound_to_result_leaf`, and `test_engine_to_leaf_builder_result_claim_id_mismatch_is_rejected`.

5. Claim leaves no longer treat operator flags as claim facts.
   - Fix: `claim_fact_hash` excludes `ctx.flags`; `policy_assertion_hash` is bound separately in the result leaf.
   - Evidence: locked vector update in `test_leaf_vectors_are_locked`.
   - Caveat: bound assertions are not the same as true assertions. Production still needs signed authoritative eligibility/provider/oracle attestations.

6. CLM/service-line total mismatch no longer survives to payment/835.
   - Fix: `build_shared_context` rejects `claim_total_mismatch`.
   - Evidence: `test_clm_total_must_match_service_line_sum`, `test_clm_sv1_amount_mismatch_rejected_before_payment_blocked`, and `test_fresh_clm_sv1_amount_mismatch_rejected_before_835_blocked`.

7. Duplicate identity survives pepper rotation.
   - Fix: `duplicate_identity_key` is a long-lived replay key independent of the rotating pepper nullifier; `BatchAuthority` tracks it across submissions.
   - Evidence: `test_duplicate_identity_survives_two_pepper_rotations`; older duplicate attack tests now fail closed on `duplicate_identity_key_already_recorded`.

Still audit/design-track, not honestly fixable as a quick code patch:

1. Authoritative oracle truth.
   - Current state: flags and policy assertions are bound, but the build does not verify them against signed CA-MMIS/provider/death-master/prior-auth sources.
   - Required next step: signed oracle attestations bound into claim/result/proof public values.

2. Payment-sum reconciliation inside the proof.
   - Current state: payment leaves commit to the approved result set, but the stub proof does not enforce netting math.
   - Required next step: production batch proof enforces `paymentRoot` is derived from approved result leaves and exact per-provider sums.

3. Multi-claim nullifier distinctness and insert-chain linkage.
   - Current state: app glue is hardened, but the protected circuit was not changed in this run.
   - Required next step: external ZK auditor reviews distinctness, root transition chaining, and padding/count constraints.

4. SP1 host/prover path on native Windows.
   - Current state: SP1 guest/lib tests pass locally, but full SP1 script/prover compilation is blocked by missing `protoc` and Unix-specific SP1 prover/JIT dependencies on Windows.
   - Required next step: run SP1 proving under WSL/Linux with protobuf compiler installed.

## H. Catastrophic Gap Closure Pass - 2026-06-15

Fixed or fail-closed in app/contracts/glue:

1. Live batch verification no longer pretends a stub proof is accepted.
   - App behavior: no valid real batch proof means `accepted_by_real_verifier == false`, settlement status `not_submitted_real_verifier_rejected`, and no payment bridge submission.
   - Contract behavior: `BatchStubVerifier` remains fail-closed. `BatchGroth16VerifierAdapter` calls the real generated Groth16 verifier for the known single-claim proof fixture and rejects garbage or batch-shaped public inputs.
   - Evidence: `testRealGroth16BatchAdapterRejectsGarbageAndBatchStatement`; Python full suite 135/135; Forge full suite 56/56.

2. Representative one-claim batch proof acceptance was removed.
   - App behavior: default batch mode records `multi_claim_batch_circuit_required` and `accepted=false`; it does not treat `batch_witnesses[0]` as proof for all approved claims.
   - Evidence: `test_default_batch_mode_requires_real_multi_claim_proof_for_many_approved_claims`.
   - Caveat: real multi-claim proof generation remains proof-track work against `zk/batch_multiclaim/`, PENDING CRYPTO AUDIT.

3. Provider payment netting is reconciled before payment leaf construction.
   - App behavior: proposed provider net amount must equal the exact sum of approved payable amounts; mismatch raises `payment_reconciliation_mismatch`.
   - Evidence: `test_payment_reconciliation_rejects_tampered_net_amount`.
   - Caveat: in-circuit payment-sum enforcement remains audit-track.

4. Oracle attestation interface was scaffolded.
   - App behavior: raw flags are marked `UNVERIFIED`; strict mode requires signed attestations for verified-fact paths.
   - Evidence: `test_signed_oracle_attestations_are_accepted_in_strict_mode`, `test_unsigned_or_forged_oracle_attestation_rejected_in_strict_mode`, and `test_raw_flags_are_marked_unverified_without_strict_mode`.
   - Caveat: real CA-MMIS/death-master/suspended-provider/prior-auth feeds and production signatures are external access/governance work.

5. Trusted setup is documented but not run.
   - Evidence: `zk/TRUSTED_SETUP_CEREMONY_PLAN.md`.
   - Caveat: all current Groth16 setup artifacts remain prototype-only until a real ceremony or transparent-STARK path is chosen.

## I. Consolidated Hardening Run - 2026-06-15

Status: soundness-checked where executable, PENDING CRYPTO AUDIT.

Implemented and tested:

1. Typed, length-prefixed canonical encoding for app-side commitments.
   - Delimiter and bool/int/string collisions now reject by construction.
   - Evidence: `test_typed_length_prefixed_encoding_blocks_demonstrated_collisions`.

2. Strict canonical boundary checks for app/witness input.
   - Member ids, fixed 10-digit NPI shape, service dates, procedure codes, cents, and amount bounds are enforced before commitment building.
   - Evidence: `test_noncanonical_member_id_rejected_before_nullifier_build`, `test_noncanonical_npi_and_procedure_rejected`, and `test_amount_bounds_reject_underflow_and_overwidth`.

3. Fail-closed secrets.
   - Duplicate pepper and oracle public key refuse unset production operation. Dev fallback requires explicit `BL_DEV=1`.
   - Evidence: `test_duplicate_pepper_missing_without_dev_fails_closed`.

4. Oracle scaffold moved from symmetric HMAC to Ed25519 public-key verification.
   - Claim binding, validity windows, and replay-cache hooks were added.
   - Evidence: `test_oracle_expired_forged_and_replayed_attestations_reject`.
   - Caveat: this remains an interface. Real feeds, HSM custody, threshold signing, and in-circuit verification are not built.

5. Batch registry replay and governance hardening.
   - Reused combined commitments, reused payment roots, payment roots without nullifier-root advance, arbitrary nullifier genesis bootstrap, test verifier registration outside explicit test mode, and single-claim Groth16 adapter registration as a batch checker now reject.
   - Evidence: `testReusingPaymentRootUnderFreshBatchRejected`, `testPaymentRequiresNullifierRootAdvance`, `testArbitraryNullifierBootstrapRejected`, `testStubVerifierRejectedWithoutExplicitTestFlag`, and `testSingleClaimAdapterCannotBeRegisteredAsBatchChecker`.

6. G8 split.
   - `invalid_charge` emits proposed `16/M79`; `excessive_charge` emits proposed `45` with blank RARC pending domain ratification.
   - Evidence: Rust/Python agreement tests and 835 denial tests.
   - Caveat: codes remain PENDING DOMAIN RATIFICATION.

Blocked, not faked:

1. Field-native Poseidon roots across Python and Solidity remain blocked.
   - Reason: no audited Solidity Poseidon implementation matching the local `pso-poseidon::new_circom` helper is vendored.
   - No SHA roots were mod-reduced, and no fake Poseidon replacement was introduced.

2. Poseidon parity with circomlib for arities 2, 4, and 11 remains an audit/build item.
   - Required before any claim that app, contract, Groth16, and STARK paths share the exact same field hash.

## J. Production-Lane Closure Pass - 2026-06-15

Status: app/contracts/spec hardened; production cryptographic enforcement remains
PENDING CRYPTO AUDIT.

Closed in code:

1. App payment root now matches the Solidity settlement leaf.
   - Previous risk: app-side payment tree committed to the internal payment record,
     while `BatchPaymentTrigger` verifies `sha256(abi.encodePacked(recipient,
     paymentRecord))`.
   - Fix: app payment tree now uses `payment_payee_record(recipient_address,
     payment_record)`, matching the Solidity leaf.
   - Evidence: `test_payment_root_uses_contract_payee_record_not_bare_payment_record`.

2. Production mode now fails closed until the production proof/oracle/settlement
   artifacts are explicitly configured.
   - Required artifacts now include the audited binding-circuit hash, verifier key
     hash, raw-837 derivation circuit, nullifier transition circuit, payment
     reconciliation circuit, native STARK verifier, accumulator root, effective
     ruleset timeline, fee schedule root, eligibility/provider/prior-auth oracle
     roots, in-circuit oracle key root, settlement-address-book root, data
     availability root, governance multisig, governance timelock, and verifier
     trust root.
   - Evidence: `test_production_mode_fails_closed_until_crypto_subsystems_exist`
     and `test_production_mode_passes_only_with_explicit_canonical_artifacts`.

3. Governance root updates now have executable multisig/timelock coverage.
   - Evidence: `testGovernanceMultisigRootUpdateRequiresThreshold` and
     `testGovernanceRootUpdateHonorsTimelock`.

Still not claimed as secure:

1. The real production binding circuit is still a spec plus gate, not a completed
   audited circuit.
2. The proof must enforce raw-claim derivation, oracle facts, fee schedules,
   accumulator transitions, nullifier transitions, payment sum reconciliation,
   and payment-recipient binding inside the proof.
3. Cairo/STARK proof generation and native on-chain STARK verification remain
   audit/build track work.
