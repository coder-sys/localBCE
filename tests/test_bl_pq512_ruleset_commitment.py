from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.ruleset_commitment import (
    encode_ruleset,
    ruleset_root,
)
from experiments.fixed_shape_claim_air.profile import PROFILES


def test_ruleset_is_fixed_public_profile_commitment() -> None:
    expected = {
        "K128_CALIBRATION": 1_097,
        "K256_DESIGN_POINT": 1_097,
        "K512_CALIBRATION": 1_097,
    }
    for profile_id, profile in PROFILES.items():
        encoded = encode_ruleset(profile)
        assert len(encoded) == expected[profile_id]
        assert ruleset_root(profile) == __import__("hashlib").sha3_512(encoded).digest()
    assert len({ruleset_root(profile) for profile in PROFILES.values()}) == 3
