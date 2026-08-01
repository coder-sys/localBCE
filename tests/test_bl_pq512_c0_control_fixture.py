from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from experiments.bl_pq512_crypto_foundation.c0_control_fixture import (
    STATUS,
    _slots,
    build_all_c0_control_fixtures,
    build_c0_control_fixture,
)
from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_witness,
)
from experiments.fixed_shape_claim_air.ordered_map_reference import OrderedMapBuilder
from experiments.fixed_shape_claim_air import authenticated_payment_maps_reference as payment_maps
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    BenefitScopeV1,
    build_authenticated_payment_map_transition,
    build_payment_map_state,
)
from experiments.fixed_shape_claim_air.payment import derive_batch_economics
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}

EXPECTED = {
    "K128_CALIBRATION": (
        11217,
        "74c6812c830f9d53d556712b2c08700dae11fd95777a82b01f498743de6e738d2accc6319c7870425debc668b401a92a20e88bcc96c591c8bebb74dc3b496d83",
    ),
    "K512_CALIBRATION": (
        11231,
        "5d45ffed375d27d64762d6c03ec832e894e6d34fc057f78d8b6885f9441c9835fe0e9999f46807ac083c69c12e2481f8e457d09d825b19506b02fc6a44793d20",
    ),
}


@pytest.fixture(scope="module", autouse=True)
def _synthetic_environment():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        yield


@pytest.fixture(scope="module")
def fixtures():
    return build_all_c0_control_fixtures()


def test_c0_manifests_are_exact_and_cover_both_profiles(fixtures) -> None:
    assert [fixture.status for fixture in fixtures] == [STATUS, STATUS]
    assert [fixture.profile_id for fixture in fixtures] == [
        "K128_CALIBRATION",
        "K512_CALIBRATION",
    ]
    for fixture in fixtures:
        expected_length, expected_sha3 = EXPECTED[fixture.profile_id]
        assert fixture.fixture_manifest_length == expected_length
        assert fixture.fixture_manifest_sha3_512_hex == expected_sha3
        assert fixture.proof_suite_id is None
        assert fixture.activation_allowed is False
        assert fixture.public_input_names == tuple(PUBLIC_INPUT_FIELD_NAMES_V2)
        assert len(fixture.public_output_hex) == 12
        assert all(len(value) == 64 for value in fixture.public_output_hex)
        assert len(fixture.artifacts) == 8
        assert all(value.length > 0 for value in fixture.artifacts)
        assert all(len(value.sha3_512_hex) == 128 for value in fixture.artifacts)


def test_c0_state_shapes_roots_money_cases_and_h4_record_are_frozen(fixtures) -> None:
    for fixture in fixtures:
        k = fixture.claim_slots
        assert [(value.lane, value.operation_count, value.access_rows) for value in fixture.map_results] == [
            ("replay", k + 1, 2 * (k + 1)),
            ("benefit", k, 2 * k),
            ("obligation", k, 2 * k),
            ("ledger", 2 * k, 4 * k),
        ]
        assert fixture.state_root_before_hex != fixture.state_root_after_hex
        assert fixture.payment.payment_root_before_hex != fixture.payment.payment_root_after_hex
        assert fixture.payment.operation_log_before_hex != fixture.payment.operation_log_after_hex
        assert (
            fixture.payment.total_plan_payable_cents,
            fixture.payment.total_debits_cents,
            fixture.payment.total_credits_cents,
        ) == (80, 80, 80)
        assert fixture.payment.case_outcomes == (
            ("approved", "accepted", "0"),
            ("duplicate", "denied", "12"),
            ("conflict", "denied", "13"),
            ("denial", "denied", "1"),
            ("cover", "cover", "0"),
            ("correction", "rejected", "r25_revision_not_authorized"),
        )
        assert fixture.h4_resource_record.execution_manifest_sha3_512_hex == (
            "51c23310274ccf7c4d7f9abe4ae7eba43266b335bd377b21cbf92409729b91e2"
            "a40a39787a157baa080c9d0516c7815af404a4d58d9e76747f652f57cd017ed6"
        )
        assert fixture.h4_resource_record.production_usable is False


def test_c0_rebuild_is_byte_identical(fixtures) -> None:
    for fixture in fixtures:
        rebuilt = build_c0_control_fixture(PROFILES[fixture.profile_id])
        assert rebuilt.manifest_bytes == fixture.manifest_bytes
        assert rebuilt.fixture_manifest_sha3_512_hex == fixture.fixture_manifest_sha3_512_hex


def test_c0_negative_fixture_labels_are_present(fixtures) -> None:
    expected_names = {
        "stale_read",
        "omitted_write",
        "reordered_write",
        "duplicate_identity",
        "collision",
        "root_substitution",
        "conflicting_update",
    }
    for fixture in fixtures:
        assert {name for name, _ in fixture.negative_cases} == expected_names


def test_c0_stale_and_conflicting_updates_fail_closed() -> None:
    builder = OrderedMapBuilder(b"Z")
    key = sha3_512(b"BL/C0/NEGATIVE/KEY").digest()
    value = sha3_512(b"BL/C0/NEGATIVE/VALUE").digest()
    stale = builder.prove_upsert(key, value)
    builder.apply(stale)
    with pytest.raises(ValueError, match="ordered_map_apply_state_mismatch"):
        builder.apply(stale)

    current = builder.prove_upsert(key, sha3_512(b"BL/C0/NEGATIVE/UPDATE").digest())
    conflicting = builder.prove_upsert(key, sha3_512(b"BL/C0/NEGATIVE/CONFLICT").digest())
    builder.apply(current)
    with pytest.raises(ValueError, match="ordered_map_apply_root_before_mismatch"):
        builder.apply(conflicting)


def test_c0_omission_reordering_and_root_substitution_fail_closed() -> None:
    builder = OrderedMapBuilder(b"Y")
    before = builder.snapshot()
    transitions = []
    for index in range(2):
        witness = builder.prove_upsert(
            sha3_512(f"BL/C0/NEGATIVE/KEY/{index}".encode()).digest(),
            sha3_512(f"BL/C0/NEGATIVE/VALUE/{index}".encode()).digest(),
        )
        builder.apply(witness)
        transitions.append(witness)
    after = builder.snapshot()
    batch = build_ordered_map_batch_witness(before, after, tuple(transitions))
    with pytest.raises(ValueError, match="ordered_map_batch_endpoint_transition_mismatch"):
        build_ordered_map_batch_witness(before, after, (transitions[0],))
    with pytest.raises(ValueError, match="ordered_map_batch_endpoint_transition_mismatch"):
        build_ordered_map_batch_witness(before, after, tuple(reversed(transitions)))
    with pytest.raises(ValueError, match="ordered_map_batch_root_before_mismatch"):
        replace(batch, root_before=sha3_512(b"BL/C0/NEGATIVE/ROOT").digest())


def test_c0_control_is_disabled_outside_explicit_synthetic_environment() -> None:
    with mock.patch.dict(
        os.environ,
        {**FLAGS, "BL_ENV": "production"},
        clear=False,
    ):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            build_c0_control_fixture(PROFILES["K128_CALIBRATION"])



def test_c0_ledger_collision_fails_closed() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = _slots(profile)
    economics = derive_batch_economics(profile, slots)
    before = build_payment_map_state(
        epoch=7,
        sequence=11,
        strong_settlement_domain_id_512=sha3_512(b"BL/C0/SETTLEMENT-DOMAIN").digest(),
        benefit_scope=BenefitScopeV1("SYNTH-PAYER-001", "SYNTH-PLAN-001", 20_000, 20_365),
        payer_reserve_cents=10_000,
        operation_log_root_512=sha3_512(b"BL/C0/OPERATION-LOG-BEFORE").digest(),
    )
    collision_key = payment_maps.provider_payable_key("1999999984")
    with mock.patch.object(payment_maps, "_PAYER_RESERVE_KEY", collision_key):
        with pytest.raises(StructuralError, match="ledger_key_collision"):
            build_authenticated_payment_map_transition(profile, slots, economics, before)
