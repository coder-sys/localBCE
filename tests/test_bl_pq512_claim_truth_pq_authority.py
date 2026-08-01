from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    build_claim_source_commitments,
)
from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ClaimTruthAuthorityRegistryV1,
    ClaimTruthRootsV1,
    decode_claim_truth_authority_envelope,
    encode_claim_truth_authority_envelope,
    sign_claim_truth_roots,
    verify_claim_truth_authority,
)
from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    build_oracle_commitments,
    oracle_bundle_from_slot,
)
from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    build_policy_commitments,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.ruleset_commitment import ruleset_root
from experiments.fixed_shape_claim_air.measurement import build_synthetic_measurement_slots
from experiments.fixed_shape_claim_air.profile import PROFILES


def test_dual_family_claim_truth_authority_accepts_exact_roots_and_fails_closed() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    source = build_claim_source_commitments(profile, slots)
    oracle = build_oracle_commitments(
        profile, tuple(oracle_bundle_from_slot(profile, slot) for slot in slots)
    )
    policy = build_policy_commitments(profile, slots)
    roots = ClaimTruthRootsV1(
        source.root,
        oracle.execution_root,
        oracle.audit_root,
        policy.execution_root,
        policy.audit_root,
        ruleset_root(profile),
    )
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    ml_public, ml_secret = ml.generate_keypair()
    slh_public, slh_secret = slh.generate_keypair()
    registry = ClaimTruthAuthorityRegistryV1(
        profile.profile_id,
        "BL-SYNTH-GOV-INTAKE-V1",
        7,
        sha3_512(b"snapshot-7").digest(),
        ml_public,
        slh_public,
    )
    envelope = sign_claim_truth_roots(
        registry,
        roots,
        ml_adapter=ml,
        ml_secret_key=ml_secret,
        slh_adapter=slh,
        slh_secret_key=slh_secret,
    )
    assert decode_claim_truth_authority_envelope(
        encode_claim_truth_authority_envelope(envelope)
    ) == envelope
    assert verify_claim_truth_authority(
        registry, envelope, ml_adapter=ml, slh_adapter=slh
    )
    wrong_roots = replace(
        roots,
        policy_execution_root=bytes((roots.policy_execution_root[0] ^ 1,))
        + roots.policy_execution_root[1:],
    )
    assert not verify_claim_truth_authority(
        registry,
        replace(envelope, roots=wrong_roots),
        ml_adapter=ml,
        slh_adapter=slh,
    )
    assert not verify_claim_truth_authority(
        replace(registry, epoch=8), envelope, ml_adapter=ml, slh_adapter=slh
    )
    bad_slh = bytes((envelope.slh_dsa_shake_256f_signature[0] ^ 1,)) + envelope.slh_dsa_shake_256f_signature[1:]
    assert not verify_claim_truth_authority(
        registry,
        replace(envelope, slh_dsa_shake_256f_signature=bad_slh),
        ml_adapter=ml,
        slh_adapter=slh,
    )
