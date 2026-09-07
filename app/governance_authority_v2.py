"""Canonical application form of the authoritative master governance v2 tuple.

This module owns the governance preimage and commitment used by the database
boundary.  It retains every full-width input so the stored authority tuple and
its commitment remain the single canonical representation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

GOVERNANCE_DOMAIN: Final[bytes] = b"BL/PQ512/GOVERNANCE/v2"


PROFILE_CODES: Final[frozenset[int]] = frozenset({1, 2, 3})


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise ValueError(f"governance_authority_{label}_invalid")
    return value


@dataclass(frozen=True, slots=True)
class GovernanceAuthorityV2:
    """The exact immutable tuple hashed by ``GOVERNANCE/v2``."""

    profile_code: int
    epoch: int
    claim_truth_roots_512: tuple[bytes, bytes, bytes, bytes, bytes, bytes]
    claim_truth_authority_digest_512: bytes
    nullifier_authority_id_512: bytes
    pepper_commitment_512: bytes

    def __post_init__(self) -> None:
        if type(self.profile_code) is not int or self.profile_code not in PROFILE_CODES:
            raise ValueError("governance_authority_profile_code_invalid")
        if type(self.epoch) is not int or not 0 < self.epoch < 2**64:
            raise ValueError("governance_authority_epoch_invalid")
        if (
            type(self.claim_truth_roots_512) is not tuple
            or len(self.claim_truth_roots_512) != 6
        ):
            raise ValueError("governance_authority_truth_root_count_invalid")
        for index, root in enumerate(self.claim_truth_roots_512):
            _wide(f"truth_root_{index}", root)
        _wide(
            "claim_truth_authority_digest",
            self.claim_truth_authority_digest_512,
        )
        _wide("nullifier_authority_id", self.nullifier_authority_id_512)
        _wide("pepper_commitment", self.pepper_commitment_512)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                GOVERNANCE_DOMAIN,
                bytes((self.profile_code,)),
                self.epoch.to_bytes(8, "big"),
                *self.claim_truth_roots_512,
                self.claim_truth_authority_digest_512,
                self.nullifier_authority_id_512,
                self.pepper_commitment_512,
            )
        )

    @property
    def commitment_512(self) -> bytes:
        return sha3_512(self.canonical_bytes).digest()

__all__ = (
    "GovernanceAuthorityV2",
    "PROFILE_CODES",
)
