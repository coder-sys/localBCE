from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512
import os
from unittest import mock

import pytest

from app.batch.pq_strong_nullifier_reference import DuplicateStrongNullifierError
from experiments.fixed_shape_claim_air.authenticated_payment_maps_reference import (
    BenefitScopeV1,
)
from experiments.fixed_shape_claim_air.claim_truth_reference import (
    build_claim_truth_reference,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.semantics import StructuralError
from experiments.fixed_shape_claim_air.wave1a_relation_reference import (
    build_wave1a_reference_relation,
    verify_wave1a_reference_relation,
)
from tests.test_wave1a_relation_reference import (
    FLAGS,
    _cover,
    _real,
    context as context_fixture,
    replay as replay_fixture,
)


@pytest.fixture(scope="module")
def material():
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        profile = get_profile("K128_CALIBRATION")
        slots = (
            _real(0, approved=True),
            _real(1, approved=False),
            *(_cover(index) for index in range(2, profile.claim_slots)),
        )
        replay = replay_fixture.__wrapped__(profile)
        context = context_fixture.__wrapped__()
        truth = build_claim_truth_reference(profile, slots)
        relation = build_wave1a_reference_relation(
            profile,
            slots,
            truth.governed_roots(),
            truth.authentication,
            replay,
            context,
        )
        yield profile, slots, replay, context, truth, relation


def test_security_flags_cannot_promote_host_reference_to_authenticated_air(
    material,
) -> None:
    _, _, _, _, _, relation = material
    for changes in (
        {"nullifier_derivations_authenticated": False},
        {"physical_air_constrained": True},
        {"production_usable": True},
    ):
        with pytest.raises(StructuralError, match="security_boundary_invalid"):
            replace(relation, **changes)


def test_strong_nullifier_substitution_moves_wide_binding_and_cannot_reuse_old_commitment(
    material,
) -> None:
    profile, _, _, _, _, relation = material
    changed_first = replace(
        relation.replay_derivations[0],
        strong_sha3_512=sha3_512(
            b"BL-W1A-ATTACK-SUBSTITUTED-STRONG-NULLIFIER"
        ).digest(),
    )
    with pytest.raises(StructuralError, match="recomputation_mismatch"):
        verify_wave1a_reference_relation(
            profile,
            replace(
                relation,
                replay_derivations=(
                    changed_first,
                    *relation.replay_derivations[1:],
                ),
            ),
        )


def test_benefit_scope_substitution_cannot_reuse_committed_relation(material) -> None:
    profile, _, _, _, _, relation = material
    substituted_scope = BenefitScopeV1(
        payer_authority_id="ATTACK-PAYER",
        plan_id="ATTACK-PLAN",
        benefit_period_start_day=20_000,
        benefit_period_end_day=20_365,
    )
    payment_maps = relation.payment_map_transition
    with pytest.raises(StructuralError, match="dummy_leaf_invalid"):
        replace(
            payment_maps,
            before=replace(payment_maps.before, benefit_scope=substituted_scope),
            after=replace(payment_maps.after, benefit_scope=substituted_scope),
        )


def test_master_salt_reuse_rejects_when_context_free_tag_already_exists(
    material,
) -> None:
    profile, slots, replay, context, truth, relation = material
    with pytest.raises(DuplicateStrongNullifierError, match="already present"):
        build_wave1a_reference_relation(
            profile,
            slots,
            truth.governed_roots(),
            truth.authentication,
            replay,
            context,
            existing_strong_nullifiers=(relation.salt_use_tag_sha3_512,),
        )
