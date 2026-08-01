from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from app.batch.pq_nullifier_derivation import (
    ATTEMPT_DOMAIN_CODE,
    COVER_DOMAIN_CODE,
    COVER_DOMAIN_CODE_V2,
    ENCODING_MAGIC,
    ENCODING_MAGIC_V2,
    AttemptReplayIdentityV1,
    CoverReplayContextV1,
    CoverReplayContextV2,
    NullifierDerivationAuthorityV1,
    ReplayRegistryAuthorityBindingV1,
    REVISION_KIND_CORRECTION,
    REVISION_KIND_ORIGINAL,
    derive_attempt_nullifiers_v1,
    derive_cover_nullifiers_v1,
    derive_cover_nullifiers_v2,
    encode_attempt_preimage_v1,
    encode_cover_preimage_v1,
    encode_cover_preimage_v2,
    pepper_commitment_sha3_512,
)


def _authority() -> NullifierDerivationAuthorityV1:
    return NullifierDerivationAuthorityV1.from_secret(
        sha3_512(b"BL-A12-AUTHORITY-ID").digest(),
        sha3_512(b"BL-A12-REGISTRY-LIFETIME-PEPPER").digest(),
    )


def _identity() -> AttemptReplayIdentityV1:
    return AttemptReplayIdentityV1(
        "BL-SYNTH-GOV-INTAKE-V1",
        "BL-SYNTH-CLAIM-0001",
        1,
        REVISION_KIND_ORIGINAL,
        0,
    )


def _cover_context() -> CoverReplayContextV1:
    return CoverReplayContextV1(
        "K128_CALIBRATION",
        sha3_512(b"BL-A12-STRONG-DOMAIN").digest(),
        7,
        9_001,
        127,
    )


def _cover_context_v2() -> CoverReplayContextV2:
    return CoverReplayContextV2(
        "K128_CALIBRATION",
        sha3_512(b"BL-A12-STRONG-DOMAIN").digest(),
        7,
        sha3_512(b"BL-A12-STRONG-BATCH-NONCE").digest(),
        127,
    )


def test_attempt_derivation_exact_kat_and_same_preimage_independence() -> None:
    derived = derive_attempt_nullifiers_v1(_identity(), _authority())
    encoded = encode_attempt_preimage_v1(_identity(), _authority())
    assert derived.canonical_preimage == encoded
    assert encoded[:8] == ENCODING_MAGIC
    assert int.from_bytes(encoded[10:12], "big") == ATTEMPT_DOMAIN_CODE
    assert int.from_bytes(encoded[12:16], "big") == len(encoded)
    assert len(encoded) == 136
    assert derived.strong_sha3_512 == sha3_512(encoded).digest()
    assert derived.legacy_felt == (
        2335562186963388424030922501396251997696454299118619761082162137812910618014
    )
    assert derived.strong_sha3_512.hex() == (
        "9687cdef3b4a978584378a72fbfbf9ee1de0ee197239a233b39b024cc930ba5e"
        "dca7bdf4509bb533f25aa0c6692f351e2cb7442fae5b4f68fe9e373368a7f95b"
    )
    assert pepper_commitment_sha3_512(_authority().pepper_512).hex() == (
        "82c917e3170c24bfc981ebb9f4f3376f90c6cff186b31fbb74ee30482051b142"
        "0d3cee70f1fbd13c941cfc135e72f8f5c43fd27025a08b9fd92b6ecc88b4cce1"
    )


def test_cover_derivation_exact_kat_and_separate_domain() -> None:
    nonce = sha3_512(b"BL-A12-COVER-NONCE").digest()
    derived = derive_cover_nullifiers_v1(_cover_context(), nonce)
    encoded = encode_cover_preimage_v1(_cover_context(), nonce)
    assert encoded[:8] == ENCODING_MAGIC
    assert int.from_bytes(encoded[10:12], "big") == COVER_DOMAIN_CODE
    assert int.from_bytes(encoded[12:16], "big") == len(encoded)
    assert len(encoded) == 206
    assert derived.canonical_preimage == encoded
    assert derived.strong_sha3_512 == sha3_512(encoded).digest()
    assert derived.canonical_preimage != encode_attempt_preimage_v1(_identity(), _authority())
    assert derived.legacy_felt == (
        2004135934551032400268341064277681677502251809018133360551466455354820697160
    )
    assert derived.strong_sha3_512.hex() == (
        "d616454ce2b8f2d712d740e160f0622497c11380dfbd7f6cefaccde89ea95d599"
        "66cdb4eed848c1f0e811d38dcc4a9e7b927d2c898c09018ed5cb7cf8f435d59"
    )


def test_cover_v2_uses_full_512_bit_batch_nonce_exact_kat() -> None:
    context = _cover_context_v2()
    nonce = sha3_512(b"BL-A12-COVER-NONCE").digest()
    encoded = encode_cover_preimage_v2(context, nonce)
    derived = derive_cover_nullifiers_v2(context, nonce)
    assert encoded[:8] == ENCODING_MAGIC_V2
    assert int.from_bytes(encoded[10:12], "big") == COVER_DOMAIN_CODE_V2
    assert int.from_bytes(encoded[12:16], "big") == len(encoded) == 238
    assert derived.canonical_preimage == encoded
    assert derived.legacy_felt == (
        1303882068298354117126764638511492033431691470871550730305404107384374080256
    )
    assert derived.strong_sha3_512.hex() == (
        "552249fee73b40d67d27f5e1a29aaa631381e30e4c3241bdb37502f0ab4d62bc"
        "f83f2f99dcb4b4ee8ea59e25c79e8ed9c682dadb5f3e2c675cc5e19a5b8ae34d"
    )


def test_real_attempt_key_uses_only_stable_governed_identity_and_pepper() -> None:
    base = derive_attempt_nullifiers_v1(_identity(), _authority())
    assert derive_attempt_nullifiers_v1(_identity(), _authority()) == base
    for changed in (
        replace(_identity(), source_authority_id="BL-SYNTH-GOV-INTAKE-V2"),
        replace(_identity(), source_claim_id="BL-SYNTH-CLAIM-0002"),
    ):
        observed = derive_attempt_nullifiers_v1(changed, _authority())
        assert observed.legacy_felt != base.legacy_felt
        assert observed.strong_sha3_512 != base.strong_sha3_512


def test_bl_pq512_v1_rejects_every_revision_before_derivation() -> None:
    correction = AttemptReplayIdentityV1(
        "BL-SYNTH-GOV-INTAKE-V1",
        "BL-SYNTH-CLAIM-0001",
        2,
        REVISION_KIND_CORRECTION,
        1,
    )
    with pytest.raises(ValueError, match="revision_not_authorized"):
        derive_attempt_nullifiers_v1(correction, _authority())


def test_cover_key_changes_for_every_uniqueness_context_and_nonce() -> None:
    context = _cover_context()
    nonce = sha3_512(b"BL-A12-COVER-NONCE").digest()
    base = derive_cover_nullifiers_v1(context, nonce)
    changes = (
        replace(context, profile_id="K256_DESIGN_POINT"),
        replace(
            context,
            strong_settlement_domain_id_512=sha3_512(b"BL-A12-OTHER-DOMAIN").digest(),
        ),
        replace(context, epoch=8),
        replace(context, batch_nonce_felt=9_002),
        replace(context, slot_index=126),
    )
    observed = [
        derive_cover_nullifiers_v1(changed, nonce)
        for changed in changes
    ]
    observed.append(
        derive_cover_nullifiers_v1(
            context,
            sha3_512(b"BL-A12-OTHER-COVER-NONCE").digest(),
        )
    )
    assert all(value.legacy_felt != base.legacy_felt for value in observed)
    assert all(value.strong_sha3_512 != base.strong_sha3_512 for value in observed)


def test_authority_rejects_wrong_commitment_and_zero_secret() -> None:
    authority = _authority()
    with pytest.raises(ValueError, match="pepper_commitment_mismatch"):
        replace(authority, pepper_commitment_512=bytes([1]) * 64)
    with pytest.raises(ValueError, match="replay_pepper_must_be_nonzero"):
        NullifierDerivationAuthorityV1.from_secret(authority.authority_id_512, bytes(64))


def test_registry_binding_rejects_authority_or_pepper_rotation() -> None:
    authority = _authority()
    binding = ReplayRegistryAuthorityBindingV1.from_authority(authority)
    binding.require_current_authority(authority)

    rotated_pepper = NullifierDerivationAuthorityV1.from_secret(
        authority.authority_id_512,
        sha3_512(b"BL-A12-ROTATED-PEPPER").digest(),
    )
    with pytest.raises(ValueError, match="pepper_rotation_requires_atomic_migration"):
        binding.require_current_authority(rotated_pepper)

    rotated_authority = NullifierDerivationAuthorityV1.from_secret(
        sha3_512(b"BL-A12-ROTATED-AUTHORITY").digest(),
        authority.pepper_512,
    )
    with pytest.raises(ValueError, match="authority_rotation_requires_atomic_migration"):
        binding.require_current_authority(rotated_authority)
