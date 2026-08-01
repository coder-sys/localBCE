from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from app.public_inputs import PUBLIC_INPUT_FIELDS_V2, build_native_stark_public_inputs_v2
from app.batch.pq_nullifier_derivation import (
    NullifierDerivationAuthorityV1,
    ReplayRegistryAuthorityBindingV1,
)
from experiments.fixed_shape_claim_air.authenticated_payment_reference import (
    AuthenticatedPaymentState,
)
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    BenefitScopeV1,
    build_payment_map_state,
)
from experiments.fixed_shape_claim_air.claim_truth_reference import (
    build_claim_truth_reference,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    StructuralError,
)
from experiments.fixed_shape_claim_air.stark252_projection_air import (
    compatibility_felt_from_sha3_512,
)
from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.wide_public_executable_air import (
    build_wide_public_executable_air_v2,
)
from experiments.fixed_shape_claim_air.wave1a_relation_reference import (
    PUBLIC_OUTPUT_NAMES,
    SlotNullifierInput,
    Wave1AContext,
    build_wave1a_reference_relation,
    verify_wave1a_reference_relation,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}

EXPECTED_PUBLIC_OUTPUTS = tuple(
    int(value, 16)
    for value in (
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0458fce3171522b6aad4a43b2de9a4cfd9c2691c04861cdaabea559e0f33177d",
        "079bf1afcf68f9e04ad148fd6b10eab7ccc36687b29035bf90d4a25fdf7088d3",
        "0029de9d96e9ebb88d8fe8d48e8cba0faba5be94b3a28354582f7978e2c9c62d",
        "0223ea52332e78e817cd86e9976043bbda84d8662944c8ea743292be45df3301",
        "0378478137e1e5be1f1537150d2f5dcdff5daf4b024b2ccaa0ee1c8d7b1576c7",
        "07a71712a803b3cc2f73436e97f839aceebd241cb1d2c7077c5192e951b8173e",
        "03f30fc5991c32f87a5a9ff8b29116ae5461c6729f24717f85f198738de4d72c",
        "0276df9d72ad7715132259e6a7ded263256ffec49e0a3fed2663daabceb2d8c3",
        "072a2fc74fc9677e9e937809640bce8ab91e1b76dacda5be8ff77d69878da442",
        "02c641b8958bbdbae62ea95295cc338cd249c206129459ca62eda7a090c51654",
        "0678dc3958e8aea835ac7e03422ae14d6ff5cf55b852f059a24dca8a03b36148",
    )
)
EXPECTED_STRONG_GOVERNANCE = bytes.fromhex(
    "23b49bae1c9e094b2e81d6039bb826c208fe91eff8ee098aa4fb13f348ed80b5"
    "735a096fd8373ede58c3f120ab52ffd76db3a05b8d6d47e63801918a0d91b997"
)
EXPECTED_STRONG_BATCH = bytes.fromhex(
    "d6f62b4fe0d470ed37b34bc86921f5b5daf32030be9aa30cf2a5fb696cfc7c3f"
    "f1af6df13b0f697c9e937809640bce8ab91e1b76dacda5be8ff77d69878da441"
)
EXPECTED_STRONG_VALUE = bytes.fromhex(
    "d7fcdb2f6becc18a6b13a23dacfc3d674429c71390c5882805b2027c33071c22"
    "af4b65ac97b03c8ce62ea95295cc338cd249c206129459ca62eda7a090c51653"
)
EXPECTED_STRONG_SETTLEMENT = bytes.fromhex(
    "2d6f9c33b7fd595f8546743fc03ffd382c78892c5c71c93d94982da5736df312"
    "2d4465dd986d7fc935ac7e03422ae14d6ff5cf55b852f059a24dca8a03b36147"
)


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


def _line() -> ServiceLine:
    return ServiceLine(
        original_line_index=0,
        line_id="LINE-A",
        procedure_code="T1019",
        charge_cents=100,
        units_cents=1,
        prior_authorization="",
        policy_present=True,
        allowed_cents=100,
        requires_prior_authorization=False,
        authorization_present=False,
    )


def _real(index: int, *, approved: bool) -> ClaimSlot:
    return ClaimSlot(
        slot_index=index,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=index + 1,
        claim_id=f"BL-SYNTH-CLAIM-{index + 1:04d}",
        member_id="SYNTH-MEMBER-001" if approved else "",
        provider_npi="1999999984",
        attempt_version=1,
        revision_kind=RevisionKind.ORIGINAL,
        parent_attempt_version=0,
        diagnoses=("F840",),
        service_lines=(_line(),),
        eligibility_active=True,
        provider_enrolled=True,
        provider_not_suspended=True,
        not_deceased=True,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=100,
        patient_responsibility_cents=20 if approved else 0,
        claimed_decision=1 if approved else 0,
        claimed_failure_code=0 if approved else 1,
        claimed_allowed_cents=100 if approved else 0,
        claimed_payment_cents=80 if approved else 0,
    )


def _cover(index: int) -> ClaimSlot:
    return ClaimSlot(
        slot_index=index,
        slot_kind=SlotKind.COVER,
        source_authority_id="",
        source_sequence=0,
        claim_id="",
        member_id="",
        provider_npi="",
        attempt_version=0,
        revision_kind=RevisionKind.COVER,
        parent_attempt_version=0,
        diagnoses=(),
        service_lines=(),
        eligibility_active=False,
        provider_enrolled=False,
        provider_not_suspended=False,
        not_deceased=False,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=0,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=0,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )


@pytest.fixture(scope="module")
def profile():
    return get_profile("K128_CALIBRATION")


@pytest.fixture(scope="module")
def slots(profile):
    return (
        _real(0, approved=True),
        _real(1, approved=False),
        *(_cover(index) for index in range(2, profile.claim_slots)),
    )


@pytest.fixture(scope="module")
def replay(profile):
    return tuple(
        SlotNullifierInput(
            index,
            (
                bytes(64)
                if index < 2
                else sha3_512(
                    b"BL-W1A-COVER-NONCE" + index.to_bytes(2, "big")
                ).digest()
            ),
        )
        for index in range(profile.claim_slots)
    )


@pytest.fixture(scope="module")
def context():
    strong_domain = sha3_512(
        b"BL-W1A-STRONG-SETTLEMENT-DOMAIN"
    ).digest()
    strong_nonce = sha3_512(b"BL-W1A-STRONG-BATCH-NONCE").digest()
    payment_before = AuthenticatedPaymentState(
        epoch=7,
        sequence=11,
        next_slot_index=0,
        payer_reserve_cents=1_000,
        provider_obligation_cents=30,
        total_paid_cents=40,
        patient_responsibility_cents=5,
        operation_log_root_sha3_512=sha3_512(b"BL-W1A-INITIAL-LOG").digest(),
    )
    nullifier_authority = NullifierDerivationAuthorityV1.from_secret(
        sha3_512(b"BL-W1A-NULLIFIER-AUTHORITY").digest(),
        sha3_512(b"BL-W1A-REGISTRY-LIFETIME-PEPPER").digest(),
    )
    return Wave1AContext(
        epoch=7,
        settlement_domain=compatibility_felt_from_sha3_512(strong_domain),
        batch_nonce=compatibility_felt_from_sha3_512(strong_nonce),
        raw_master_salt_512=sha3_512(b"BL-W1A-RAW-MASTER-SALT").digest(),
        strong_settlement_domain_id_512=strong_domain,
        strong_batch_nonce_512=strong_nonce,
        replay_registry_authority_binding=(
            ReplayRegistryAuthorityBindingV1.from_authority(nullifier_authority)
        ),
        nullifier_authority=nullifier_authority,
        payment_state_before=payment_before,
        payment_map_state_before=build_payment_map_state(
            epoch=7,
            sequence=11,
            strong_settlement_domain_id_512=strong_domain,
            benefit_scope=BenefitScopeV1(
                payer_authority_id="SYNTH-PAYER-001",
                plan_id="SYNTH-PLAN-001",
                benefit_period_start_day=20_000,
                benefit_period_end_day=20_365,
            ),
            payer_reserve_cents=1_000,
            operation_log_root_512=sha3_512(
                b"BL-W1A-INITIAL-PAYMENT-MAP-LOG"
            ).digest(),
        ),
    )


@pytest.fixture(scope="module")
def relation(profile, slots, replay, context):
    truth = build_claim_truth_reference(profile, slots)
    return build_wave1a_reference_relation(
        profile,
        slots,
        truth.governed_roots(),
        truth.authentication,
        replay,
        context,
    )


def test_k128_relation_composes_every_authenticated_lane(
    profile, relation
) -> None:
    assert verify_wave1a_reference_relation(profile, relation)
    assert len(relation.public_outputs) == 12
    assert relation.public_outputs == EXPECTED_PUBLIC_OUTPUTS
    assert relation.strong_governance_commitment_sha3_512 == EXPECTED_STRONG_GOVERNANCE
    assert relation.strong_batch_commitment_sha3_512 == EXPECTED_STRONG_BATCH
    assert relation.strong_value_conservation_commitment_sha3_512 == EXPECTED_STRONG_VALUE
    assert relation.strong_settlement_commitment_sha3_512 == EXPECTED_STRONG_SETTLEMENT
    assert len(PUBLIC_OUTPUT_NAMES) == 12
    assert relation.public_outputs[0] == 2
    assert relation.public_outputs[1:3] == (
        compatibility_felt_from_sha3_512(
            relation.context.strong_settlement_domain_id_512
        ),
        compatibility_felt_from_sha3_512(relation.context.strong_batch_nonce_512),
    )
    assert relation.public_outputs[5:9] == tuple(
        compatibility_felt_from_sha3_512(value)
        for value in relation.governed_roots.wide_roots
    )
    assert not hasattr(relation, "existing_legacy_nullifiers")
    assert len(relation.strong_transitions) == profile.claim_slots + 1
    assert all(
        left.root_after == right.root_before
        for left, right in zip(
            relation.strong_transitions,
            relation.strong_transitions[1:],
        )
    )
    assert relation.economics.total_plan_payable_cents == 80
    assert relation.economics.total_debits_cents == 80
    assert relation.economics.total_credits_cents == 80
    assert relation.nullifier_derivations_authenticated is True
    assert relation.cryptographic_paths_authenticated is True
    assert relation.physical_air_constrained is False
    assert relation.production_usable is False
    mapping = {
        item.batch_attr: relation.public_outputs[item.index]
        for item in PUBLIC_INPUT_FIELDS_V2
    }
    encoded = build_native_stark_public_inputs_v2(mapping)
    assert len(encoded) == 12
    assert all(len(value) == 64 for value in encoded)


def test_relation_rejects_replay_collision_and_governed_truth_forgery(
    profile, slots, replay, context, relation
) -> None:
    duplicate = replace(replay[3], private_cover_nonce_512=replay[2].private_cover_nonce_512)
    with pytest.raises(StructuralError, match="cover_nonce_duplicate"):
        build_wave1a_reference_relation(
            profile,
            slots,
            relation.governed_roots,
            relation.authentication,
            (*replay[:3], duplicate, *replay[4:]),
            context,
        )

    forged_slots = (
        replace(slots[0], claim_id="BL-SYNTH-CLAIM-9999"),
        *slots[1:],
    )
    with pytest.raises(ValueError, match="claimSourceRoot"):
        build_wave1a_reference_relation(
            profile,
            forged_slots,
            relation.governed_roots,
            relation.authentication,
            replay,
            context,
        )


def test_relation_recomputation_rejects_public_and_path_mutation(
    profile, relation
) -> None:
    changed_outputs = list(relation.public_outputs)
    changed_outputs[10] = (changed_outputs[10] + 1) % (2**251 + 17 * 2**192 + 1)
    with pytest.raises(StructuralError, match="recomputation_mismatch"):
        verify_wave1a_reference_relation(
            profile,
            replace(relation, public_outputs=tuple(changed_outputs)),
        )

    first = relation.strong_transitions[0]
    changed_path = list(first.predecessor_path)
    changed_path[0] = sha3_512(changed_path[0]).digest()
    changed_inner = replace(first.inner, predecessor_path=tuple(changed_path))
    changed_transition = replace(first, inner=changed_inner)
    with pytest.raises(StructuralError, match="recomputation_mismatch"):
        verify_wave1a_reference_relation(
            profile,
            replace(
                relation,
                strong_transitions=(
                    changed_transition,
                    *relation.strong_transitions[1:],
                ),
            ),
        )


def test_relation_rejects_legacy_replay_state_as_authority(
    profile, slots, replay, context, relation
) -> None:
    with pytest.raises(StructuralError, match="legacy_state_not_authoritative"):
        build_wave1a_reference_relation(
            profile,
            slots,
            relation.governed_roots,
            relation.authentication,
            replay,
            context,
            existing_legacy_nullifiers=(1,),
        )


def test_relation_public_outputs_match_executable_wide_projection_air(relation) -> None:
    wide_values = (
        relation.strong_transitions[0].root_before,
        relation.strong_transitions[-1].root_after,
        *relation.governed_roots.wide_roots,
        relation.strong_batch_commitment_sha3_512,
        relation.strong_value_conservation_commitment_sha3_512,
        relation.strong_settlement_commitment_sha3_512,
    )
    instance = build_wide_public_executable_air_v2(
        relation.public_outputs[0],
        relation.context.strong_settlement_domain_id_512,
        relation.context.strong_batch_nonce_512,
        wide_values,
    )
    assert instance.public_outputs == relation.public_outputs
    direct = evaluate_program(
        instance.program, instance.traces, instance.public_input_bytes
    )
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(),
        instance.traces,
        instance.public_input_bytes,
    )
    assert direct == serialized


def test_real_replay_keys_survive_decision_fact_and_batch_retry_changes(
    profile, slots, replay, context, relation
) -> None:
    denied_slots = (_real(0, approved=False), *slots[1:])
    denied_truth = build_claim_truth_reference(profile, denied_slots)
    denied = build_wave1a_reference_relation(
        profile,
        denied_slots,
        denied_truth.governed_roots(),
        denied_truth.authentication,
        replay,
        context,
    )
    assert denied.replay_derivations[0] == relation.replay_derivations[0]

    retried = build_wave1a_reference_relation(
        profile,
        slots,
        relation.governed_roots,
        relation.authentication,
        replay,
        replace(
            context,
            strong_batch_nonce_512=(changed_nonce := sha3_512(b"BL-W1A-RETRY-NONCE").digest()),
            batch_nonce=compatibility_felt_from_sha3_512(changed_nonce),
        ),
    )
    assert retried.replay_derivations[:2] == relation.replay_derivations[:2]
    assert all(
        changed != original
        for changed, original in zip(
            retried.replay_derivations[2:],
            relation.replay_derivations[2:],
            strict=True,
        )
    )


def test_registry_bound_authority_rejects_batch_level_pepper_rotation(context) -> None:
    rotated = NullifierDerivationAuthorityV1.from_secret(
        context.nullifier_authority.authority_id_512,
        sha3_512(b"BL-W1A-UNAUTHORIZED-ROTATED-PEPPER").digest(),
    )
    with pytest.raises(
        StructuralError,
        match="registry_pepper_rotation_requires_atomic_migration",
    ):
        replace(context, nullifier_authority=rotated)


def test_composed_reference_is_disabled_in_production(profile, slots, replay, context) -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            build_wave1a_reference_relation(
                profile,
                slots,
                build_claim_truth_reference(profile, slots).governed_roots(),
                build_claim_truth_reference(profile, slots).authentication,
                replay,
                context,
            )
