from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.batch.pq_suite_candidate import SIDECAR_LENGTH
from app.batch.pq_verifier_reference import (
    REFERENCE_STATUS as VERIFIER_REFERENCE_STATUS,
    VERIFICATION_KIND,
    reference_candidate_strong_batch_commitment,
)
from experiments.fixed_shape_claim_air.integrated_state_reference import (
    K256_OPERATION_COUNT,
    PAYMENT_TRANSITION_STATUS,
    REFERENCE_STATUS as STATE_REFERENCE_STATUS,
)
from tests.pq_integrated_reference_support import (
    FLAGS,
    MASTER_SALT,
    PRIVATE_BATCH_COMMITMENT,
    STRONG_VALUE_COMMITMENT,
    scenario,
    second_verified_transition,
    wide,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _synthetic_flags():
    with patch.dict("os.environ", FLAGS, clear=False):
        yield


def test_exact_statement_sidecar_typed_outputs_and_complete_tuple_cas() -> None:
    case = scenario()
    before = case.state.snapshot()

    assert len(case.receipt.public_outputs) == 12
    assert len(case.receipt.sidecar.encode()) == SIDECAR_LENGTH == 744
    assert case.receipt.sidecar == case.sidecar
    assert case.receipt.verification_kind == VERIFICATION_KIND
    assert case.receipt.reference_status == VERIFIER_REFERENCE_STATUS
    assert not hasattr(case.receipt, "raw_master_salt")
    assert not hasattr(case.receipt, "salt_use_tag_512")
    assert not hasattr(case.replay, "raw_master_salt")
    assert not hasattr(case.receipt, "canonical_private_batch_commitment")
    assert not hasattr(case.receipt, "hidden_strong_value_commitment")
    assert case.authority.validate_verified_outputs(
        case.receipt,
        expected_salt_use_tag_512=case.replay.salt_use_tag_512,
    ) == (
        case.public_outputs,
        case.sidecar,
    )

    after = case.state.commit_verified_transition(
        case.receipt,
        case.replay,
        case.payment,
        expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
    )

    assert after.reference_status == STATE_REFERENCE_STATUS
    assert after.sequence == 1
    assert after.legacy_nullifier_root == case.public_outputs[4]
    assert after.strong_nullifier_root == case.sidecar.strong_nullifier_root_after
    assert after.strong_payment_state_root == case.sidecar.strong_payment_state_root_after
    assert after.replay_key_count == 257
    assert after.consumed_nonce_count == 1
    assert after.recorded_batch_count == 1
    assert after.active_registry_commitment_sha3_512 == (
        case.receipt.active_registry_commitment_sha3_512
    )


def test_two_sequential_valid_batches_advance_one_complete_tuple_at_a_time() -> None:
    case = scenario()
    initial = case.state.snapshot()
    first = case.state.commit_verified_transition(
        case.receipt,
        case.replay,
        case.payment,
        expected_state_commitment_sha3_512=initial.state_commitment_sha3_512,
    )
    second_transition = second_verified_transition(case)
    second = case.state.commit_verified_transition(
        second_transition.receipt,
        second_transition.replay,
        second_transition.payment,
        expected_state_commitment_sha3_512=first.state_commitment_sha3_512,
    )

    assert (initial.sequence, first.sequence, second.sequence) == (0, 1, 2)
    assert (
        initial.replay_key_count,
        first.replay_key_count,
        second.replay_key_count,
    ) == (0, 257, 514)
    assert (
        initial.consumed_nonce_count,
        first.consumed_nonce_count,
        second.consumed_nonce_count,
    ) == (0, 1, 2)
    assert (
        initial.recorded_batch_count,
        first.recorded_batch_count,
        second.recorded_batch_count,
    ) == (0, 1, 2)
    assert second_transition.replay.existing_keys_512 == case.replay.merged_keys_512
    assert (
        second_transition.payment.before.sequence,
        second_transition.payment.after.sequence,
    ) == (1, 2)
    assert second.legacy_nullifier_root == second_transition.public_outputs[4]
    assert second.strong_nullifier_root == second_transition.sidecar.strong_nullifier_root_after
    assert second.strong_payment_state_root == (
        second_transition.sidecar.strong_payment_state_root_after
    )
    assert first.state_commitment_sha3_512 != second.state_commitment_sha3_512
    assert first.nonce_registry_root != second.nonce_registry_root
    assert first.batch_registry_root != second.batch_registry_root
    assert case.state.snapshot() == second


def test_candidate_strong_batch_inventory_binds_every_required_component() -> None:
    case = scenario()
    prefix = case.sidecar.encode()[:680]
    baseline = case.sidecar.strong_batch_commitment
    assert baseline == reference_candidate_strong_batch_commitment(
        prefix,
        case.public_outputs,
        canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
        hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
        raw_master_salt=MASTER_SALT,
    )

    changed_public = list(case.public_outputs)
    changed_public[9] = (499).to_bytes(32, "big")
    mutations = (
        reference_candidate_strong_batch_commitment(
            bytes([prefix[0] ^ 1]) + prefix[1:],
            case.public_outputs,
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=MASTER_SALT,
        ),
        reference_candidate_strong_batch_commitment(
            prefix,
            tuple(changed_public),
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=MASTER_SALT,
        ),
        reference_candidate_strong_batch_commitment(
            prefix,
            case.public_outputs,
            canonical_private_batch_commitment=wide("MUTATED-PRIVATE-BATCH"),
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=MASTER_SALT,
        ),
        reference_candidate_strong_batch_commitment(
            prefix,
            case.public_outputs,
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=wide("MUTATED-STRONG-VALUE"),
            raw_master_salt=MASTER_SALT,
        ),
        reference_candidate_strong_batch_commitment(
            prefix,
            case.public_outputs,
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=bytes([0xA6]) * 64,
        ),
    )
    assert all(value != baseline for value in mutations)
    assert len(set(mutations)) == len(mutations)


def test_replay_and_payment_transitions_are_exact_fixed_k256_shapes() -> None:
    case = scenario()
    assert len(case.replay.operations) == K256_OPERATION_COUNT + 1 == 257
    assert case.replay.operations[-1].position == 256
    assert case.replay.operations[-1].kind.value == "SALT_USE"
    assert case.replay.operations[-1].replay_key_512 == case.replay.merged_keys_512[
        case.replay.merged_keys_512.index(case.replay.operations[-1].replay_key_512)
    ]
    assert len(case.payment.economics) == K256_OPERATION_COUNT
    assert case.payment.reference_status == PAYMENT_TRANSITION_STATUS
    assert case.payment.before.sequence == 0
    assert case.payment.after.sequence == 1
    assert case.payment.before.operation_log_root_512 != case.payment.after.operation_log_root_512
    assert case.payment.roots.root_before_512 == case.sidecar.strong_payment_state_root_before
    assert case.payment.roots.root_after_512 == case.sidecar.strong_payment_state_root_after


def test_nonzero_synthetic_suite_id_cannot_activate_or_mutate_unqualified_registry() -> None:
    registry_path = ROOT / "docs" / "bl_pq512_suite_candidate_v1.json"
    before = registry_path.read_bytes()
    registry = json.loads(before)
    case = scenario()

    assert any(case.sidecar.proof_suite_id)
    assert "SYNTHETIC" in VERIFICATION_KIND
    assert "NOT_A_STARK_VERIFIER" in VERIFIER_REFERENCE_STATUS
    assert registry["status"] == "CANDIDATE_UNQUALIFIED"
    assert registry["activationAllowed"] is False
    assert registry["proofSuiteId"] is None
    assert not hasattr(case.authority, "register_production_verifier")
    assert not hasattr(case.authority, "activate")
    assert registry_path.read_bytes() == before


def test_payment_transition_is_honestly_limited_to_composite_and_operation_log() -> None:
    case = scenario()
    mutated_after = replace(
        case.payment.after,
        asset_registry_root_512=wide("SYNTHETIC-OPAQUE-ASSET-ROOT-CHANGE"),
    )
    assert mutated_after.asset_registry_root_512 != case.payment.after.asset_registry_root_512
    assert "NO_AUTHENTICATED_MAPS" in PAYMENT_TRANSITION_STATUS


def test_internal_transition_repr_omits_replay_keys_tags_and_payment_details() -> None:
    case = scenario()
    replay_repr = repr(case.replay)
    payment_repr = repr(case.payment)
    assert case.replay.salt_use_tag_512.hex() not in replay_repr
    assert case.replay.operations[0].replay_key_512.hex() not in replay_repr
    assert "operations=" not in replay_repr
    assert "economics=" not in payment_repr
    assert case.payment.roots.root_after_512.hex() not in payment_repr
