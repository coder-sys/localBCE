"""Compact exact call-order manifest for the segmented Wave 1A SHA3 engine.

Every component retains its independently executable physical SHA3 AIR.  This
manifest fixes their global order and offsets without materializing a second
multi-gigabyte copy of the same Keccak rows.  The Wave 1B streaming prover must
consume the segments in this order as one logical engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from .ordered_map_batch_reference import build_ordered_map_batch_schedule
from .profile import CalibrationProfile
from .semantics import StructuralError


DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/GLOBAL-SHA3-SCHEDULE/v1\x00"
COMPONENTS: Final[tuple[str, ...]] = (
    "claim_truth",
    "a12_nullifier",
    "salt_use",
    "replay_map",
    "payment",
    "master",
)
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


@dataclass(frozen=True, slots=True)
class GlobalSha3Segment:
    component: str
    tag: int
    call_offset: int
    call_count: int


@dataclass(frozen=True, slots=True)
class Wave1AGlobalSha3Schedule:
    profile_id: str
    segments: tuple[GlobalSha3Segment, ...]
    total_calls: int
    commitment_512: bytes


def _call_counts(k: int) -> tuple[int, ...]:
    if k not in {128, 256, 512}:
        raise StructuralError("wave1a_global_sha3_claim_slots_invalid")
    truth = 4 * k + 4
    a12 = k + 1
    salt = 1
    replay = build_ordered_map_batch_schedule(k + 1).sha3_call_rows
    payment_maps = (
        2 * build_ordered_map_batch_schedule(k).sha3_call_rows
        + build_ordered_map_batch_schedule(2 * k).sha3_call_rows
    )
    payment_application = 6 * k
    return truth, a12, salt, replay, payment_maps + payment_application, 4


def build_wave1a_global_sha3_schedule(
    profile: CalibrationProfile,
) -> Wave1AGlobalSha3Schedule:
    if not isinstance(profile, CalibrationProfile):
        raise StructuralError("wave1a_global_sha3_profile_invalid")
    try:
        profile_code = _PROFILE_CODES[profile.profile_id]
    except KeyError as exc:
        raise StructuralError("wave1a_global_sha3_profile_invalid") from exc
    counts = _call_counts(profile.claim_slots)
    offset = 0
    segments = []
    for tag, (component, count) in enumerate(
        zip(COMPONENTS, counts, strict=True), start=1
    ):
        segments.append(GlobalSha3Segment(component, tag, offset, count))
        offset += count
    preimage = bytearray(DOMAIN)
    preimage.extend(bytes((profile_code, len(segments))))
    for segment in segments:
        preimage.extend(bytes((segment.tag,)))
        preimage.extend(segment.call_offset.to_bytes(8, "big"))
        preimage.extend(segment.call_count.to_bytes(8, "big"))
    return Wave1AGlobalSha3Schedule(
        profile.profile_id,
        tuple(segments),
        offset,
        sha3_512(preimage).digest(),
    )


__all__ = (
    "GlobalSha3Segment",
    "Wave1AGlobalSha3Schedule",
    "build_wave1a_global_sha3_schedule",
)
