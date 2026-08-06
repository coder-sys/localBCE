from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.wave4_adapters import (
    DualPqAuthenticator,
    ML_DSA_87,
    PqcryptoSoftwareSigner,
    SLH_DSA_SHAKE_256F,
)
from app.wave5_rollup import (
    AtomicRollupState,
    BasedOrderer,
    BridgeEscrow,
    DataAvailabilityStore,
    FinalityLevel,
    FinalityTracker,
    ForkAdapterController,
    InclusionList,
    L1Block,
    L2StateTransitionProver,
    LocalDeployment,
    OpaqueTransaction,
    PqGovernance,
    RecentRootAdapter,
    RecentRootReference,
    RollupClaimContext,
    RollupState,
    SettlementEngine,
    SyntheticReferenceClaimVerifier,
    Wave5RollupError,
    build_da_bundle,
    build_ethereum_compat_manifest,
    build_reference_claim_envelope,
    build_rollup_transition,
    make_synthetic_identity,
    run_wave5_conformance,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


@pytest.fixture(scope="module")
def governance() -> PqGovernance:
    ml = PqcryptoSoftwareSigner.generate(ML_DSA_87)
    sl = PqcryptoSoftwareSigner.generate(SLH_DSA_SHAKE_256F)
    authority = PqGovernance(DualPqAuthenticator((ml, sl)))
    yield authority
    ml.destroy()
    sl.destroy()


def _simple_transition():
    manifest = build_ethereum_compat_manifest()
    identity = make_synthetic_identity()
    initial = RollupState.genesis(manifest, identity)
    tx = OpaqueTransaction(_wide("sender"), 0, _wide("payload"), "ATTEMPT-TEST")
    orderer = BasedOrderer(manifest)
    orderer.submit(tx)
    inclusion = InclusionList(1, _wide("view"), (tx.tx_hash_512,), _wide("committee"))
    ordered = orderer.order(slot=1, inclusion_list=inclusion)
    da = build_da_bundle((tx.tx_hash_512, ordered.batch_commitment_512), mode="CELL_COMMITMENT", retention_until_slot=20)
    after_nullifier = _wide("nullifier-after")
    after_payment = _wide("payment-after")
    identity_values = (
        (2).to_bytes(32, "big"),
        (3).to_bytes(32, "big"),
        (4).to_bytes(32, "big"),
        (5).to_bytes(32, "big"),
        (6).to_bytes(32, "big"),
        (7).to_bytes(32, "big"),
        (8).to_bytes(32, "big"),
        (9).to_bytes(32, "big"),
        (10).to_bytes(32, "big"),
        (11).to_bytes(32, "big"),
        (12).to_bytes(32, "big"),
        (13).to_bytes(32, "big"),
    )
    sidecar = CandidateSidecarV1(
        identity.profile_id_512,
        identity.candidate_suite_id_512,
        identity.schema_id_512,
        identity.verifier_artifact_identity_512,
        identity.settlement_domain_id_512,
        identity.epoch,
        0,
        1,
        initial.nullifier_root_512,
        after_nullifier,
        manifest.manifest_digest_512,
        initial.payment_state_root_512,
        after_payment,
        _wide("batch-commitment"),
    )
    context = RollupClaimContext(
        manifest.baseline.fork_id_512,
        manifest.l1_chain_id,
        manifest.l2_chain_id,
        initial.digest_512,
        da.digest_512,
        identity.verifier_artifact_identity_512,
        identity.schema_id_512,
        identity.candidate_suite_id_512,
        identity.settlement_domain_id_512,
    )
    envelope = build_reference_claim_envelope(sidecar=sidecar, public_fields=identity_values, context=context)
    claim_receipt = SyntheticReferenceClaimVerifier().verify(envelope=envelope, context=context, identity=identity)
    transition = build_rollup_transition(
        before=initial,
        envelope=envelope,
        claim_receipt=claim_receipt,
        fork_id_512=manifest.baseline.fork_id_512,
        ordered_batch_commitment_512=ordered.batch_commitment_512,
        da_commitment_512=da.digest_512,
        bal_commitment_512=_wide("bal"),
        cbam_commitment_512=_wide("cbam"),
        attempt_id=tx.attempt_id,
        batch_nonce=0,
    )
    proof = L2StateTransitionProver(manifest).prove(transition)
    return manifest, identity, initial, transition, proof


def test_wave5_full_synthetic_claim_to_finalized_l1_and_rollback(governance: PqGovernance) -> None:
    receipt = run_wave5_conformance(governance)
    assert set(receipt.package_status) == {f"R{index:02d}" for index in range(1, 13)}
    assert all(status == "complete_internal_nonactivating" for status in receipt.package_status.values())
    assert receipt.rollback_ok is True
    assert receipt.network_access is False
    assert receipt.live_credentials is False
    assert receipt.production_usable is False
    assert receipt.activation_allowed is False
    assert receipt.proofSuiteId is None


def test_manifest_records_all_23_eips_and_rejects_unshipped_baseline() -> None:
    first = build_ethereum_compat_manifest()
    second = build_ethereum_compat_manifest()
    assert len(first.strawmap) == 23
    assert first.manifest_digest_512 == second.manifest_digest_512
    assert first.baseline.enabled_eips == ()
    assert len(first.optional_features_disabled) == 7
    with pytest.raises(Wave5RollupError, match="unshipped_eip"):
        replace(first, baseline=replace(first.baseline, enabled_eips=(8025,)))


def test_local_deployment_is_multi_node_and_networkless() -> None:
    manifest = build_ethereum_compat_manifest()
    deployment = LocalDeployment.build(manifest)
    assert len(deployment.nodes) == 5
    assert sum(node.role == "EL" for node in deployment.nodes) == 2
    assert sum(node.role == "CL" for node in deployment.nodes) == 2
    assert b"network_access" in deployment.canonical_bytes()
    assert b"true" not in deployment.canonical_bytes()


def test_claim_boundary_is_exactly_12_fields_and_tamper_rejects() -> None:
    _manifest, identity, _initial, _transition, _proof = _simple_transition()
    manifest = build_ethereum_compat_manifest()
    state = RollupState.genesis(manifest, identity)
    context = RollupClaimContext(
        manifest.baseline.fork_id_512,
        manifest.l1_chain_id,
        manifest.l2_chain_id,
        state.digest_512,
        _wide("da"),
        identity.verifier_artifact_identity_512,
        identity.schema_id_512,
        identity.candidate_suite_id_512,
        identity.settlement_domain_id_512,
    )
    sidecar = CandidateSidecarV1(
        identity.profile_id_512,
        identity.candidate_suite_id_512,
        identity.schema_id_512,
        identity.verifier_artifact_identity_512,
        identity.settlement_domain_id_512,
        1,
        0,
        1,
        state.nullifier_root_512,
        _wide("n-after"),
        manifest.manifest_digest_512,
        state.payment_state_root_512,
        _wide("p-after"),
        _wide("batch"),
    )
    envelope = build_reference_claim_envelope(
        sidecar=sidecar,
        public_fields=tuple(index.to_bytes(32, "big") for index in range(1, 13)),
        context=context,
    )
    verifier = SyntheticReferenceClaimVerifier()
    assert verifier.verify(envelope=envelope, context=context, identity=identity).proof_digest_512 == envelope.claim_proof_digest_512
    tampered = bytearray(envelope.proof_body)
    tampered[-1] ^= 1
    with pytest.raises(Wave5RollupError, match="proof_body"):
        verifier.verify(envelope=replace(envelope, proof_body=bytes(tampered)), context=context, identity=identity)


def test_based_ordering_rejects_withholding_nonce_conflicts_and_preconfirmation() -> None:
    manifest = build_ethereum_compat_manifest()
    orderer = BasedOrderer(manifest)
    tx = OpaqueTransaction(_wide("sender"), 0, _wide("payload"), "ATTEMPT-ORDER")
    orderer.submit(tx)
    inclusion = InclusionList(3, _wide("view"), (tx.tx_hash_512,), _wide("committee"))
    with pytest.raises(Wave5RollupError, match="inclusion_slot"):
        orderer.order(slot=2, inclusion_list=inclusion)
    conflicting = OpaqueTransaction(tx.sender_commitment_512, tx.nonce, _wide("other"), "ATTEMPT-CONFLICT")
    with pytest.raises(Wave5RollupError, match="nonce_conflict"):
        orderer.submit(conflicting)
    ordered = orderer.order(slot=3, inclusion_list=inclusion)
    with pytest.raises(Wave5RollupError, match="preconfirmation"):
        BasedOrderer.validate_payload(batch=ordered, inclusion_list=inclusion, execution_validated=False)


def test_da_partial_corrupt_and_expired_data_fail_closed() -> None:
    store = DataAvailabilityStore()
    bundle = build_da_bundle((_wide("cell-0"), _wide("cell-1")), mode="BLOB_COMMITMENT", retention_until_slot=3)
    digest = store.publish(bundle)
    with pytest.raises(Wave5RollupError, match="partial"):
        store.reconstruct(digest, bundle.cells[:1], current_slot=1)
    corrupted = replace(bundle.cells[1], commitment_512=_wide("corrupt"))
    with pytest.raises(Wave5RollupError, match="cell_mismatch"):
        store.reconstruct(digest, (bundle.cells[0], corrupted), current_slot=1)
    with pytest.raises(Wave5RollupError, match="retention"):
        store.reconstruct(digest, bundle.cells, current_slot=4)


def test_finality_never_equates_head_with_finalized() -> None:
    manifest, _identity, _initial, transition, proof = _simple_transition()
    deployment = LocalDeployment.build(manifest)
    tracker = FinalityTracker(manifest)
    tracker.observe(deployment.genesis)
    head = deployment.mine_block(
        slot=1,
        payload_digest_512=transition.ordered_batch_commitment_512,
        da_commitment_512=transition.da_commitment_512,
        state_root_512=proof.expected_l1_state_root_512,
    )
    tracker.observe(head)
    assert tracker.level(head.block_hash_512) is FinalityLevel.HEAD
    assert tracker.is_finalized(head.block_hash_512) is False


def test_atomic_state_requires_settlement_binding(governance: PqGovernance) -> None:
    manifest, identity, initial, transition, proof = _simple_transition()
    deployment = LocalDeployment.build(manifest)
    tracker = FinalityTracker(manifest)
    tracker.observe(deployment.genesis)
    block = deployment.mine_block(
        slot=1,
        payload_digest_512=transition.ordered_batch_commitment_512,
        da_commitment_512=transition.da_commitment_512,
        state_root_512=proof.expected_l1_state_root_512,
        finality=FinalityLevel.FINALIZED,
    )
    tracker.observe(block)
    approval = governance.approve(manifest.manifest_digest_512, proof.verifier_artifact_identity_512)
    settlement = SettlementEngine(manifest, tracker, governance).settle(
        proof=proof,
        transition=transition,
        block=block,
        approval=approval,
    )
    state = AtomicRollupState(initial)
    assert state.apply(transition=transition, proof=proof, settlement=settlement) == transition.after
    with pytest.raises(Wave5RollupError, match="replay"):
        state.apply(transition=transition, proof=proof, settlement=settlement)
    with pytest.raises(Wave5RollupError, match="stale"):
        AtomicRollupState(replace(initial, sequence=1)).apply(transition=transition, proof=proof, settlement=settlement)


def test_bridge_requires_finality_delay_and_replay_protection(governance: PqGovernance) -> None:
    manifest, _identity, _initial, transition, proof = _simple_transition()
    deployment = LocalDeployment.build(manifest)
    tracker = FinalityTracker(manifest)
    tracker.observe(deployment.genesis)
    block = deployment.mine_block(
        slot=1,
        payload_digest_512=transition.ordered_batch_commitment_512,
        da_commitment_512=transition.da_commitment_512,
        state_root_512=proof.expected_l1_state_root_512,
        finality=FinalityLevel.FINALIZED,
    )
    tracker.observe(block)
    approval = governance.approve(manifest.manifest_digest_512, proof.verifier_artifact_identity_512)
    settlement = SettlementEngine(manifest, tracker, governance).settle(proof=proof, transition=transition, block=block, approval=approval)
    bridge = BridgeEscrow(manifest=manifest, tracker=tracker, withdrawal_delay_slots=2)
    recipient = _wide("recipient")
    deposit = bridge.deposit(value_commitment_512=_wide("value"), recipient_commitment_512=recipient, block=block)
    request = bridge.request_withdrawal(deposit_id_512=deposit.deposit_id_512, settlement=settlement, recipient_commitment_512=recipient, current_slot=1)
    with pytest.raises(Wave5RollupError, match="delay"):
        bridge.finalize_withdrawal(request, block=block)


def test_optional_recent_root_adapter_is_disabled_by_default() -> None:
    reference = RecentRootReference(_wide("source"), _wide("root"), 1, 4, _wide("signed"))
    with pytest.raises(Wave5RollupError, match="optional_feature_disabled"):
        RecentRootAdapter().validate(reference, slot=2)


def test_fork_controller_requires_timelock_and_recovers_unknown_fork(governance: PqGovernance) -> None:
    manifest = build_ethereum_compat_manifest()
    identity = make_synthetic_identity()
    controller = ForkAdapterController(manifest, governance)
    approval = governance.approve(manifest.manifest_digest_512, identity.verifier_artifact_identity_512)
    controller.request_activation(manifest.future_shadow, approval, current_slot=2)
    with pytest.raises(Wave5RollupError, match="timelock"):
        controller.activate(current_slot=3, finality=FinalityLevel.FINALIZED)
    controller.activate(current_slot=4, finality=FinalityLevel.FINALIZED)
    controller.observe_fork(_wide("unknown-fork"))
    assert controller.paused is True
    controller.emergency_rollback(target=manifest.baseline, approval=approval, current_slot=5, finality=FinalityLevel.FINALIZED)
    assert controller.active == manifest.baseline
    assert controller.paused is False
