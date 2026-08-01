"""Canonical public ruleset bytes and SHA3-512 commitment."""

from __future__ import annotations

from hashlib import sha3_512
from typing import Final

from experiments.fixed_shape_claim_air.profile import (
    AUTHORIZATIONS_PER_CLAIM,
    DIAGNOSES_PER_CLAIM,
    POLICY_TREE_DEPTH,
    SERVICE_LINES_PER_CLAIM,
    CalibrationProfile,
)
from experiments.fixed_shape_claim_air.semantics import FAILURE_GATES


RULESET_MAGIC: Final[bytes] = b"BLPQRUL1"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


def _fixed_ascii(value: str, capacity: int) -> bytes:
    raw = value.encode("ascii")
    if not 1 <= len(raw) <= capacity:
        raise ValueError("ruleset_text_length_invalid")
    return bytes((len(raw),)) + raw.ljust(capacity, b"\x00")


def encode_ruleset(profile: CalibrationProfile) -> bytes:
    if not isinstance(profile, CalibrationProfile) or profile.profile_id not in _PROFILE_CODES:
        raise TypeError("ruleset_profile_invalid")
    out = bytearray(RULESET_MAGIC)
    out.append(_PROFILE_CODES[profile.profile_id])
    out.extend(profile.claim_slots.to_bytes(2, "big"))
    out.extend(
        (
            SERVICE_LINES_PER_CLAIM,
            DIAGNOSES_PER_CLAIM,
            AUTHORIZATIONS_PER_CLAIM,
            profile.claim_source_tree_depth,
            profile.oracle_tree_depth,
            POLICY_TREE_DEPTH,
            len(FAILURE_GATES),
        )
    )
    for gate in FAILURE_GATES:
        out.append(gate.code)
        out.extend(_fixed_ascii(gate.gate_id, 40))
        out.extend(_fixed_ascii(gate.reason, 40))
    return bytes(out)


def ruleset_root(profile: CalibrationProfile) -> bytes:
    return sha3_512(encode_ruleset(profile)).digest()


__all__ = ["RULESET_MAGIC", "encode_ruleset", "ruleset_root"]
