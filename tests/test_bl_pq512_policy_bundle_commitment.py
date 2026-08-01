from __future__ import annotations

from dataclasses import replace

from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    POLICY_BUNDLE_BYTES,
    build_policy_commitments,
    policy_commitment_schedule,
)
from experiments.fixed_shape_claim_air.measurement import build_synthetic_measurement_slots
from experiments.fixed_shape_claim_air.profile import PROFILES


def test_k128_policy_execution_and_audit_commitment_kat() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    commitments = build_policy_commitments(profile, slots)
    assert len(commitments.bundles) == profile.claim_slots
    assert {len(bundle) for bundle in commitments.bundles} == {POLICY_BUNDLE_BYTES}
    assert commitments.execution_root.hex() == (
        "6fa58166ea8bdecca452c8ec5132ac06117c9123dd95b8ae1aa717d57bb6327c8"
        "9f5c4ae04186f0750f0db0491d90f2d1d4bb9748a852eb65dc3d65ec6dfa4f5"
    )
    assert commitments.audit_root.hex() == (
        "ea573235e6966209df99141e2d0267a2f81d1768f2fdd21dda889a8dd4e2625a"
        "b7846cf56f7c28e177b1595d281ce94d8ff8c083cfcda0c3a7d9fb1aa4f2fe9d"
    )
    schedule = policy_commitment_schedule(profile)
    assert schedule["proofSpongePermutations"] == 1_778
    assert schedule["proofKeccakRoundRows"] == 42_672
    assert schedule["auditAdditionalSpongePermutations"] == 256
    assert schedule["auditTreeInsideProof"] is False


def test_policy_change_moves_both_execution_and_audit_roots() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    original = build_policy_commitments(profile, slots)
    line = replace(slots[1].service_lines[0], allowed_cents=99)
    changed_slots = (
        slots[0],
        replace(
            slots[1],
            service_lines=(line,),
            claimed_allowed_cents=99,
            claimed_payment_cents=79,
        ),
        *slots[2:],
    )
    changed = build_policy_commitments(profile, changed_slots)
    assert changed.execution_root != original.execution_root
    assert changed.audit_root != original.audit_root
