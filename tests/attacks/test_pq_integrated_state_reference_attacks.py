from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from threading import Barrier, Lock, Thread
from unittest.mock import patch

import pytest

from app.batch.pq_replay_state_reference import (
    build_provisional_strong_replay_transition,
)
from app.batch.pq_verifier_reference import (
    SyntheticActiveRegistryV1,
    SyntheticStrongVerificationRequestV1,
    canonical_public_outputs_v2,
)
from experiments.fixed_shape_claim_air.integrated_state_reference import (
    build_provisional_payment_transition,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError
from tests.pq_integrated_reference_support import (
    FLAGS,
    MASTER_SALT,
    PRIVATE_BATCH_COMMITMENT,
    STRONG_VALUE_COMMITMENT,
    authority,
    felt,
    replay_slot_operations,
    replay_transition,
    scenario,
    wide,
)
from app.batch.pq_replay_schedule_r25 import build_fixed_replay_schedule
from app.batch.pq_suite_candidate import candidate_salt_use_tag


@pytest.fixture(autouse=True)
def _synthetic_flags():
    with patch.dict("os.environ", FLAGS, clear=False):
        yield


def test_every_public_field_and_sidecar_byte_is_bound_by_synthetic_proof() -> None:
    case = scenario()
    proof = case.authority.build_synthetic_proof(
        public_outputs=case.public_outputs,
        encoded_sidecar=case.sidecar.encode(),
        canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
        hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
        raw_master_salt=MASTER_SALT,
    )
    for index in range(12):
        mutated = list(case.public_outputs)
        mutated[index] = felt(3 if index == 0 else 8000 + index)
        with pytest.raises(ValueError):
            request = SyntheticStrongVerificationRequestV1.create(
                public_outputs=tuple(mutated),
                encoded_sidecar=case.sidecar.encode(),
                proof_body=proof,
            )
            case.authority.verify(request)

    encoded = case.sidecar.encode()
    for malformed in (encoded[:-1], encoded + b"\x00"):
        with pytest.raises((TypeError, ValueError)):
            request = SyntheticStrongVerificationRequestV1.create(
                public_outputs=case.public_outputs,
                encoded_sidecar=malformed,
                proof_body=proof,
            )
            case.authority.verify(request)
    for position in range(len(encoded)):
        malformed = encoded[:position] + bytes([encoded[position] ^ 1]) + encoded[position + 1 :]
        with pytest.raises((TypeError, ValueError)):
            request = SyntheticStrongVerificationRequestV1.create(
                public_outputs=case.public_outputs,
                encoded_sidecar=malformed,
                proof_body=proof,
            )
            case.authority.verify(request)


def test_old_master_commitment_cannot_authorize_new_compatibility_field() -> None:
    case = scenario()
    changed = list(case.public_outputs)
    changed[9] = felt(999)
    with pytest.raises(
        ValueError,
        match="reference_candidate_strong_batch_commitment_mismatch",
    ):
        case.authority.build_synthetic_proof(
            public_outputs=tuple(changed),
            encoded_sidecar=case.sidecar.encode(),
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=MASTER_SALT,
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "profile_id",
        "proof_suite_id",
        "schema_id",
        "verifier_artifact_identity",
        "strong_settlement_domain_id",
    ),
)
def test_mixed_active_identity_is_rejected_before_proof_issuance(field_name: str) -> None:
    case = scenario()
    mixed = replace(case.sidecar, **{field_name: wide(f"MIXED-{field_name}")})
    with pytest.raises(ValueError, match=f"candidate_active_{field_name}_mismatch"):
        case.authority.build_synthetic_proof(
            public_outputs=case.public_outputs,
            encoded_sidecar=mixed.encode(),
            canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
            hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
            raw_master_salt=MASTER_SALT,
        )


def test_reused_master_salt_fails_in_same_provisional_replay_root() -> None:
    case = scenario()
    second_schedule = build_fixed_replay_schedule(
        replay_slot_operations(variant=1),
        salt_use_tag_512=candidate_salt_use_tag(MASTER_SALT),
    )
    with pytest.raises(ValueError, match="provisional_replay_key_already_present"):
        build_provisional_strong_replay_transition(
            case.replay.merged_keys_512,
            second_schedule,
            raw_master_salt=MASTER_SALT,
        )


def test_wrong_salt_use_tag_is_rejected_even_when_schedule_shape_is_valid() -> None:
    schedule = build_fixed_replay_schedule(
        replay_slot_operations(),
        salt_use_tag_512=wide("WRONG-SALT-USE-TAG"),
    )
    with pytest.raises(ValueError, match="provisional_replay_salt_use_tag_mismatch"):
        build_provisional_strong_replay_transition(
            (),
            schedule,
            raw_master_salt=MASTER_SALT,
        )


def test_direct_replay_transition_constructor_rechecks_master_salt() -> None:
    case = scenario()
    with pytest.raises(ValueError, match="provisional_replay_salt_use_tag_mismatch"):
        replace(case.replay, salt_use_tag_512=wide("FORGED-DIRECT-CONSTRUCTOR-SALT"))


def test_proof_and_replay_master_salts_must_match_atomically() -> None:
    case = scenario()
    before = case.state.snapshot()
    other_replay = replay_transition(salt=bytes([0xA6]) * 64)
    with pytest.raises(ValueError, match="synthetic_verified_outputs_salt_use_tag_mismatch"):
        case.state.commit_verified_transition(
            case.receipt,
            other_replay,
            case.payment,
            expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
        )
    assert case.state.snapshot() == before


def test_receipt_proof_digest_mutation_breaks_authority_capability() -> None:
    case = scenario()
    forged = replace(case.receipt, proof_digest_sha3_512=wide("FORGED-PROOF-DIGEST"))
    with pytest.raises(ValueError, match="synthetic_verified_outputs_authority_mismatch"):
        case.authority.validate_verified_outputs(
            forged,
            expected_salt_use_tag_512=case.replay.salt_use_tag_512,
        )


def test_active_registry_is_frozen_and_state_rejects_consistent_registry_drift() -> None:
    case = scenario()
    before = case.state.snapshot()
    registry = case.authority.registry
    original_active = registry.active
    original_commitment = registry.commitment_sha3_512
    forged_active = replace(
        original_active,
        proof_suite_id=wide("FORGED-SYNTHETIC-PROOF-SUITE"),
    )
    with pytest.raises(FrozenInstanceError):
        registry._active = forged_active  # type: ignore[misc]

    forged_registry = SyntheticActiveRegistryV1(forged_active)
    object.__setattr__(registry, "_active", forged_registry.active)
    object.__setattr__(registry, "_commitment", forged_registry.commitment_sha3_512)
    with pytest.raises(ValueError, match="synthetic_verifier_registry_drift"):
        case.state.snapshot()

    object.__setattr__(registry, "_active", original_active)
    object.__setattr__(registry, "_commitment", original_commitment)
    assert case.state.snapshot() == before


def test_direct_payment_transition_rejects_same_sequence_and_epoch_change() -> None:
    case = scenario()
    with pytest.raises(StructuralError, match="r25_payment_state_sequence_transition_invalid"):
        replace(case.payment, after=replace(case.payment.after, sequence=0))
    with pytest.raises(StructuralError, match="r25_payment_state_epoch_mismatch"):
        replace(case.payment, after=replace(case.payment.after, epoch=8))


def test_public_output_parser_consumes_at_most_thirteen_items() -> None:
    consumed = 0

    def oversized():
        nonlocal consumed
        for value in range(100_000):
            consumed += 1
            yield felt(value)

    with pytest.raises(ValueError, match="synthetic_verifier_public_output_count_mismatch"):
        canonical_public_outputs_v2(oversized())
    assert consumed == 13


def test_complete_state_rejects_replay_capacity_overflow_before_update() -> None:
    case = scenario()
    before = case.state.snapshot()
    with patch(
        "experiments.fixed_shape_claim_air.integrated_state_reference.MAX_SYNTHETIC_REPLAY_KEYS",
        256,
    ):
        with pytest.raises(ValueError, match="synthetic_complete_state_replay_key_capacity_exceeded"):
            case.state.commit_verified_transition(
                case.receipt,
                case.replay,
                case.payment,
                expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
            )
    assert case.state.snapshot() == before


def test_payment_omission_reorder_and_forged_log_root_fail_closed() -> None:
    case = scenario()
    with pytest.raises(StructuralError, match="integrated_payment_operation_count_mismatch"):
        build_provisional_payment_transition(
            case.payment.before,
            case.payment.after,
            case.payment.economics[:-1],
        )
    with pytest.raises(StructuralError, match="r25_payment_operation_order_invalid"):
        build_provisional_payment_transition(
            case.payment.before,
            case.payment.after,
            tuple(reversed(case.payment.economics)),
        )
    forged_after = replace(
        case.payment.after,
        operation_log_root_512=wide("FORGED-OPERATION-LOG-ROOT"),
    )
    with pytest.raises(StructuralError, match="integrated_payment_operation_log_mismatch"):
        build_provisional_payment_transition(
            case.payment.before,
            forged_after,
            case.payment.economics,
        )


def test_stale_cas_and_forged_receipt_leave_complete_state_unchanged() -> None:
    case = scenario()
    before = case.state.snapshot()
    case.state.commit_verified_transition(
        case.receipt,
        case.replay,
        case.payment,
        expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
    )
    committed = case.state.snapshot()
    with pytest.raises(ValueError, match="synthetic_complete_state_compare_and_swap_mismatch"):
        case.state.commit_verified_transition(
            case.receipt,
            case.replay,
            case.payment,
            expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
        )
    assert case.state.snapshot() == committed

    forged_public = list(case.receipt.public_outputs)
    forged_public[10] = felt(1000)
    forged_receipt = replace(case.receipt, public_outputs=tuple(forged_public))
    with pytest.raises(ValueError, match="synthetic_verified_outputs_authority_mismatch"):
        case.state.commit_verified_transition(
            forged_receipt,
            case.replay,
            case.payment,
            expected_state_commitment_sha3_512=committed.state_commitment_sha3_512,
        )
    assert case.state.snapshot() == committed


def test_two_threads_racing_the_same_cas_commit_exactly_once() -> None:
    case = scenario()
    before = case.state.snapshot()
    barrier = Barrier(3)
    result_lock = Lock()
    outcomes: list[tuple[str, object]] = []

    def commit(label: str) -> None:
        barrier.wait()
        try:
            result: object = case.state.commit_verified_transition(
                case.receipt,
                case.replay,
                case.payment,
                expected_state_commitment_sha3_512=before.state_commitment_sha3_512,
            )
        except Exception as exc:  # noqa: BLE001 - the exact fail-closed outcome is asserted.
            result = f"{type(exc).__name__}:{exc}"
        with result_lock:
            outcomes.append((label, result))

    threads = (
        Thread(target=commit, args=("first",)),
        Thread(target=commit, args=("second",)),
    )
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=10)

    assert not any(thread.is_alive() for thread in threads)
    committed = [value for _, value in outcomes if not isinstance(value, str)]
    rejected = [value for _, value in outcomes if isinstance(value, str)]
    assert len(committed) == 1
    assert rejected == [
        "ValueError:synthetic_complete_state_compare_and_swap_mismatch"
    ]
    final = case.state.snapshot()
    assert final == committed[0]
    assert final.sequence == 1
    assert final.replay_key_count == 257
    assert final.consumed_nonce_count == 1
    assert final.recorded_batch_count == 1


def test_cross_authority_receipt_is_not_a_transferable_capability() -> None:
    case = scenario()
    other = authority()
    with pytest.raises(ValueError, match="synthetic_verified_outputs_authority_mismatch"):
        other.validate_verified_outputs(
            case.receipt,
            expected_salt_use_tag_512=case.replay.salt_use_tag_512,
        )


def test_zero_nonce_and_production_environment_fail_closed() -> None:
    case = scenario()
    zero_nonce = list(case.public_outputs)
    zero_nonce[2] = bytes(32)
    with pytest.raises(ValueError, match="synthetic_verifier_batch_nonce_zero"):
        SyntheticStrongVerificationRequestV1.create(
            public_outputs=tuple(zero_nonce),
            encoded_sidecar=case.sidecar.encode(),
            proof_body=b"synthetic",
        )

    with patch.dict(
        "os.environ",
        {"BL_ENV": "production", "BL_DEV": "1"},
        clear=False,
    ):
        with pytest.raises(RuntimeError, match="synthetic_pq_verifier_reference_forbidden"):
            case.authority.validate_verified_outputs(
                case.receipt,
                expected_salt_use_tag_512=case.replay.salt_use_tag_512,
            )
        with pytest.raises(RuntimeError, match="synthetic_pq_integrated_state_reference_forbidden"):
            case.state.snapshot()


@pytest.mark.parametrize(
    ("name", "value"),
    (("BL_ENV", ""), ("BL_DEV", ""), ("BL_ALLOW_SYNTHETIC_PQ_VERIFIER_REFERENCE", "")),
)
def test_each_synthetic_verifier_enablement_flag_is_required(name: str, value: str) -> None:
    case = scenario()
    with patch.dict("os.environ", {name: value}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_verifier_reference_forbidden"):
            case.authority.validate_verified_outputs(
                case.receipt,
                expected_salt_use_tag_512=case.replay.salt_use_tag_512,
            )
