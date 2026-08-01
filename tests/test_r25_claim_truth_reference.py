from __future__ import annotations

from dataclasses import replace
import os
from unittest import mock

import pytest

from app.batch.pq_tree_reference import parse_canonical_record
from experiments.fixed_shape_claim_air.claim_truth_reference import (
    REFERENCE_STATUS,
    build_claim_truth_reference,
    require_claim_truth_authentication,
    require_governed_claim_truth,
)
from app.batch.pq_sparse_tree_reference import verify_sparse_dual_membership_proof
from app.batch.pq_tree_reference import verify_dual_tree_membership_proof
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import (
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
)


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}

EXPECTED_LEGACY_ROOTS = (
    int("05f1f759df03c7fb552c8c5959c698965d4f91791416b7a7623f8f3d286623d6", 16),
    int("071be68a1d3da446ac198af13f388c79d1ffee2ab38eb3991e4db57a07051b01", 16),
    int("06567d48f9a144ed3fc88362f1870b5e710a5c9076bd08437399ef200b98874d", 16),
    int("03b916299600c238dece9f67e3c5fc0a1a7066cfa88046a5785f45ee0873dded", 16),
)
EXPECTED_WIDE_ROOTS = tuple(
    bytes.fromhex(value)
    for value in (
        "5218deb0bcf5c4039a1ab014c4ce631094b4c147a407218ebef6054c62c84097b3cf13c6b4dea84f8ddfc4f49b92b1b3dbd61cb5ee7d440249204de5799a09aa",
        "a85a73bcaad95273795356bd4e410d96e2bd34e87e14b12e3ac377dd531bd9f95a9e833c7e6d05a1ac8a0cddc2160455f3109b170f48f5c2e1f7aa7019e76abd",
        "57d8e532b9726a0e33df3b1d8a6f5a9a00720b4002e4f5da52a62c73a07dc554eff676877b629c65e36984785f74b10329690c5a5ebb10ec52f64a47b756acc4",
        "807cc8bca09d560a5e2db39a555809d14320387a43376ffc79bb7acb038e754a9d7184478731fd6e132259e6a7ded263256ffec49e0a3fed2663daabceb2d8c2",
    )
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


def _approved() -> ClaimSlot:
    return ClaimSlot(
        slot_index=0,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=1,
        claim_id="BL-SYNTH-CLAIM-0001",
        member_id="SYNTH-MEMBER-001",
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
        patient_responsibility_cents=20,
        claimed_decision=1,
        claimed_failure_code=0,
        claimed_allowed_cents=100,
        claimed_payment_cents=80,
    )


def _cover(slot_index: int) -> ClaimSlot:
    return ClaimSlot(
        slot_index=slot_index,
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
    return (_approved(), *(_cover(index) for index in range(1, profile.claim_slots)))


@pytest.fixture(scope="module")
def baseline(profile, slots):
    return build_claim_truth_reference(profile, slots)


def test_k128_authenticated_truth_kat_has_exact_fixed_roots_and_dimensions(
    profile, slots, baseline
) -> None:
    assert baseline.status == REFERENCE_STATUS
    assert baseline.profile_id == "K128_CALIBRATION"
    assert len(baseline.slot_results) == 128
    assert [
        baseline.claim_source_tree.tree_height,
        baseline.oracle_tree.tree_height,
        baseline.policy_tree.tree_depth,
        baseline.ruleset_tree.tree_height,
    ] == [7, 13, 16, 0]
    assert [
        len(baseline.claim_source_tree.canonical_records),
        len(baseline.oracle_tree.canonical_records),
        len(baseline.policy_tree.keyed_records),
        len(baseline.ruleset_tree.canonical_records),
    ] == [128, 6_528, 128, 1]
    governed = baseline.governed_roots()
    assert governed.legacy_roots == EXPECTED_LEGACY_ROOTS
    assert governed.wide_roots == EXPECTED_WIDE_ROOTS
    assert require_governed_claim_truth(profile, slots, governed) == baseline


def test_real_and_cover_records_have_identical_private_payload_lengths(baseline) -> None:
    expected_record_type_counts = {
        "synthetic_claim_truth_source": 128,
        "synthetic_claim_truth_oracle_fact": 128,
        "synthetic_claim_truth_oracle_authorization": 6_400,
        "synthetic_claim_truth_policy": 128,
    }
    for records in (
        baseline.claim_source_tree.canonical_records,
        baseline.oracle_tree.canonical_records,
        tuple(record for _, record in baseline.policy_tree.keyed_records),
    ):
        lengths_by_type: dict[str, set[int]] = {}
        counts_by_type: dict[str, int] = {}
        for record in records:
            parsed = parse_canonical_record(record)
            lengths_by_type.setdefault(parsed.record_type, set()).add(
                len(
                    next(
                        field.payload
                        for field in parsed.fields
                        if field.name == "payload"
                    )
                )
            )
            counts_by_type[parsed.record_type] = (
                counts_by_type.get(parsed.record_type, 0) + 1
            )
        assert all(len(lengths) == 1 for lengths in lengths_by_type.values())
        assert counts_by_type == {
            record_type: expected_record_type_counts[record_type]
            for record_type in counts_by_type
        }


def test_every_slot_has_exact_dual_membership_and_governed_path_authentication(
    profile, slots, baseline
) -> None:
    authentication = baseline.authentication
    roots = baseline.governed_roots()
    assert len(authentication.slots) == profile.claim_slots
    assert tuple(value.slot_index for value in authentication.slots) == tuple(
        range(profile.claim_slots)
    )
    for index in (0, profile.claim_slots // 2, profile.claim_slots - 1):
        slot = authentication.slots[index]
        assert verify_dual_tree_membership_proof(
            slot.claim_source,
            expected_legacy_root_felt=roots.legacy_roots[0],
            expected_wide_root_sha3_512=roots.wide_roots[0],
        )
        assert verify_dual_tree_membership_proof(
            slot.oracle,
            expected_legacy_root_felt=roots.legacy_roots[1],
            expected_wide_root_sha3_512=roots.wide_roots[1],
        )
        assert len(slot.oracle_authorizations) == 50
        for authorization in (
            slot.oracle_authorizations[0],
            slot.oracle_authorizations[-1],
        ):
            assert verify_dual_tree_membership_proof(
                authorization,
                expected_legacy_root_felt=roots.legacy_roots[1],
                expected_wide_root_sha3_512=roots.wide_roots[1],
            )
        assert verify_sparse_dual_membership_proof(
            slot.policy,
            expected_legacy_root_felt=roots.legacy_roots[2],
            expected_wide_root_sha3_512=roots.wide_roots[2],
        )
    assert verify_dual_tree_membership_proof(
        authentication.ruleset,
        expected_legacy_root_felt=roots.legacy_roots[3],
        expected_wide_root_sha3_512=roots.wide_roots[3],
    )
    assert (
        require_claim_truth_authentication(
            profile,
            slots,
            roots,
            authentication,
        )
        == baseline
    )


def test_claim_truth_authentication_rejects_one_path_mutation(
    profile, slots, baseline
) -> None:
    authentication = baseline.authentication
    first = authentication.slots[0]
    source = first.claim_source
    changed_source = replace(
        source,
        wide_siblings_sha3_512=(
            bytes((source.wide_siblings_sha3_512[0][0] ^ 1,))
            + source.wide_siblings_sha3_512[0][1:],
            *source.wide_siblings_sha3_512[1:],
        ),
    )
    changed_first = replace(first, claim_source=changed_source)
    changed_authentication = replace(
        authentication,
        slots=(changed_first, *authentication.slots[1:]),
    )
    with pytest.raises(ValueError, match="authentication_mismatch:slot=0"):
        require_claim_truth_authentication(
            profile,
            slots,
            baseline.governed_roots(),
            changed_authentication,
        )


def test_claim_truth_authentication_rejects_authorization_path_mutation(
    profile, slots, baseline
) -> None:
    authentication = baseline.authentication
    first = authentication.slots[0]
    authorization = first.oracle_authorizations[0]
    changed_authorization = replace(
        authorization,
        wide_siblings_sha3_512=(
            bytes((authorization.wide_siblings_sha3_512[0][0] ^ 1,))
            + authorization.wide_siblings_sha3_512[0][1:],
            *authorization.wide_siblings_sha3_512[1:],
        ),
    )
    changed_first = replace(
        first,
        oracle_authorizations=(
            changed_authorization,
            *first.oracle_authorizations[1:],
        ),
    )
    changed_authentication = replace(
        authentication,
        slots=(changed_first, *authentication.slots[1:]),
    )
    with pytest.raises(ValueError, match="authentication_mismatch:slot=0"):
        require_claim_truth_authentication(
            profile,
            slots,
            baseline.governed_roots(),
            changed_authentication,
        )


def test_governed_root_binding_rejects_semantically_valid_oracle_forgery(
    profile, slots, baseline
) -> None:
    forged_first = replace(
        slots[0],
        eligibility_active=False,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=2,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )
    forged_slots = (forged_first, *slots[1:])
    forged = build_claim_truth_reference(profile, forged_slots)
    # A semantically valid denial also zeros authenticated patient
    # responsibility, so both the source/economic and oracle lanes move.
    assert forged.claim_source_tree.legacy_root_felt != baseline.claim_source_tree.legacy_root_felt
    assert forged.oracle_tree.wide_root_sha3_512 != baseline.oracle_tree.wide_root_sha3_512
    assert forged.policy_tree.wide_root_sha3_512 == baseline.policy_tree.wide_root_sha3_512
    with pytest.raises(ValueError, match="claimSourceRoot"):
        require_governed_claim_truth(
            profile, forged_slots, baseline.governed_roots()
        )


def test_governed_root_binding_rejects_source_and_policy_forgery(
    profile, slots, baseline
) -> None:
    source_slots = (
        replace(slots[0], claim_id="BL-SYNTH-CLAIM-9999"),
        *slots[1:],
    )
    source_forged = build_claim_truth_reference(profile, source_slots)
    assert source_forged.claim_source_tree.wide_root_sha3_512 != baseline.claim_source_tree.wide_root_sha3_512
    with pytest.raises(ValueError, match="claimSourceRoot"):
        require_governed_claim_truth(
            profile, source_slots, baseline.governed_roots()
        )

    changed_line = replace(slots[0].service_lines[0], allowed_cents=90)
    policy_slots = (
        replace(
            slots[0],
            service_lines=(changed_line,),
            claimed_allowed_cents=90,
            claimed_payment_cents=70,
        ),
        *slots[1:],
    )
    policy_forged = build_claim_truth_reference(profile, policy_slots)
    assert policy_forged.policy_tree.wide_root_sha3_512 != baseline.policy_tree.wide_root_sha3_512
    with pytest.raises(ValueError, match="policyRoot"):
        require_governed_claim_truth(
            profile, policy_slots, baseline.governed_roots()
        )


def test_claim_truth_reference_is_fail_closed_outside_synthetic_mode(
    profile, slots
) -> None:
    with mock.patch.dict(os.environ, {**FLAGS, "BL_ENV": "production"}, clear=False):
        with pytest.raises(RuntimeError, match="synthetic_pq_tree_reference_forbidden"):
            build_claim_truth_reference(profile, slots)
