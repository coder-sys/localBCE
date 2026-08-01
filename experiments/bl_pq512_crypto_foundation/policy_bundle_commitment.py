"""Packed per-claim policy commitments with a separate audit tree.

The proof lane hashes one fixed bundle per claim and one ordered digest vector.
The audit lane reuses those leaf digests in a binary tree.  No policy field is
discarded by the throughput optimization.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.profile import SERVICE_LINES_PER_CLAIM, CalibrationProfile
from experiments.fixed_shape_claim_air.semantics import ClaimSlot, SlotKind, validate_batch


STATUS: Final[str] = "WAVE1B_PACKED_POLICY_EXECUTION_AND_AUDIT_COMMITMENTS_V2_NONACTIVATING"
RATE_BYTES: Final[int] = 72
DIGEST_BYTES: Final[int] = 64
BUNDLE_MAGIC: Final[bytes] = b"BLPQPOL2"
EXECUTION_ROOT_MAGIC: Final[bytes] = b"BLPQPXR2"
AUDIT_NODE_MAGIC: Final[bytes] = b"BLPQPAN2"
AUDIT_ROOT_MAGIC: Final[bytes] = b"BLPQPAR2"
LINE_BYTES: Final[int] = 18
LINE_BASE: Final[int] = 14
POLICY_BUNDLE_BYTES: Final[int] = LINE_BASE + SERVICE_LINES_PER_CLAIM * LINE_BYTES
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


def _profile_code(profile_id: str) -> int:
    try:
        return _PROFILE_CODES[profile_id]
    except (KeyError, TypeError) as exc:
        raise ValueError("policy_bundle_profile_unknown") from exc


def policy_bundle_from_slot(profile: CalibrationProfile, slot: ClaimSlot) -> bytes:
    if not isinstance(profile, CalibrationProfile) or not isinstance(slot, ClaimSlot):
        raise TypeError("policy_bundle_inputs_invalid")
    out = bytearray(BUNDLE_MAGIC)
    out.append(_profile_code(profile.profile_id))
    out.extend(slot.slot_index.to_bytes(4, "big"))
    real = slot.slot_kind is SlotKind.REAL
    out.append(int(real))
    for index in range(SERVICE_LINES_PER_CLAIM):
        live = index < len(slot.service_lines)
        line = slot.service_lines[index] if live else None
        out.append(int(live))
        out.append(int(line.policy_present) if line else 0)
        procedure = line.procedure_code.encode("ascii") if line else b""
        if len(procedure) > 10:
            raise ValueError("policy_bundle_procedure_too_long")
        out.append(len(procedure))
        out.extend(procedure.ljust(10, b"\x00"))
        out.extend((line.allowed_cents if line else 0).to_bytes(4, "big"))
        out.append(int(line.requires_prior_authorization) if line else 0)
    encoded = bytes(out)
    if len(encoded) != POLICY_BUNDLE_BYTES:
        raise AssertionError("policy_bundle_length_changed")
    return encoded


def _node_preimage(
    profile_id: str, child_height: int, position: int, left: bytes, right: bytes
) -> bytes:
    if len(left) != DIGEST_BYTES or len(right) != DIGEST_BYTES:
        raise ValueError("policy_audit_child_digest_invalid")
    return b"".join(
        (
            AUDIT_NODE_MAGIC,
            bytes((_profile_code(profile_id), child_height)),
            position.to_bytes(2, "big"),
            left,
            right,
        )
    )


def _audit_root_preimage(profile: CalibrationProfile, top: bytes) -> bytes:
    return b"".join(
        (
            AUDIT_ROOT_MAGIC,
            bytes((_profile_code(profile.profile_id), profile.claim_source_tree_depth)),
            profile.claim_slots.to_bytes(2, "big"),
            top,
        )
    )


def _execution_root_preimage(profile: CalibrationProfile, leaves: tuple[bytes, ...]) -> bytes:
    return b"".join(
        (
            EXECUTION_ROOT_MAGIC,
            bytes((_profile_code(profile.profile_id),)),
            profile.claim_slots.to_bytes(2, "big"),
            *leaves,
        )
    )


@dataclass(frozen=True, slots=True)
class PolicyCommitments:
    profile_id: str
    bundles: tuple[bytes, ...]
    leaf_digests: tuple[bytes, ...]
    execution_root: bytes
    audit_root: bytes
    audit_levels: tuple[tuple[bytes, ...], ...]


def build_policy_commitments(
    profile: CalibrationProfile, slots: Sequence[ClaimSlot]
) -> PolicyCommitments:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("policy_commitment_profile_required")
    materialized = tuple(slots)
    validate_batch(profile, materialized)
    bundles = tuple(policy_bundle_from_slot(profile, slot) for slot in materialized)
    leaves = tuple(sha3_512(bundle).digest() for bundle in bundles)
    execution_root = sha3_512(_execution_root_preimage(profile, leaves)).digest()
    levels: list[tuple[bytes, ...]] = [leaves]
    current = leaves
    for height in range(profile.claim_source_tree_depth):
        current = tuple(
            sha3_512(
                _node_preimage(
                    profile.profile_id,
                    height,
                    offset // 2,
                    current[offset],
                    current[offset + 1],
                )
            ).digest()
            for offset in range(0, len(current), 2)
        )
        levels.append(current)
    if len(current) != 1:
        raise AssertionError("policy_audit_tree_not_reduced")
    audit_root = sha3_512(_audit_root_preimage(profile, current[0])).digest()
    return PolicyCommitments(
        profile.profile_id,
        bundles,
        leaves,
        execution_root,
        audit_root,
        tuple(levels),
    )


def policy_commitment_schedule(profile: CalibrationProfile) -> dict[str, int | str | bool | None]:
    leaf_permutations = POLICY_BUNDLE_BYTES // RATE_BYTES + 1
    execution_bytes = 11 + DIGEST_BYTES * profile.claim_slots
    node_bytes = 140
    audit_root_bytes = 76
    proof_permutations = (
        profile.claim_slots * leaf_permutations
        + execution_bytes // RATE_BYTES
        + 1
    )
    audit_additional_permutations = (
        (profile.claim_slots - 1) * (node_bytes // RATE_BYTES + 1)
        + audit_root_bytes // RATE_BYTES
        + 1
    )
    return {
        "status": STATUS,
        "profileId": profile.profile_id,
        "bundleBytes": POLICY_BUNDLE_BYTES,
        "leafPermutations": leaf_permutations,
        "executionRootPreimageBytes": execution_bytes,
        "auditNodePreimageBytes": node_bytes,
        "auditRootPreimageBytes": audit_root_bytes,
        "proofSpongePermutations": proof_permutations,
        "proofKeccakRoundRows": proof_permutations * 24,
        "auditAdditionalSpongePermutations": audit_additional_permutations,
        "auditAdditionalKeccakRoundRows": audit_additional_permutations * 24,
        "auditTreeInsideProof": False,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


__all__ = (
    "BUNDLE_MAGIC",
    "LINE_BASE",
    "LINE_BYTES",
    "POLICY_BUNDLE_BYTES",
    "PolicyCommitments",
    "build_policy_commitments",
    "policy_bundle_from_slot",
    "policy_commitment_schedule",
)
