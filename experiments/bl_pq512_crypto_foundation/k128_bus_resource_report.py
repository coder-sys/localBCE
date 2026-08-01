"""Exact K128 SHA3 bus cost facts, deliberately separated from measurements.

This module derives only facts implied by the sealed Wave 1A schedule and the
C0 access census.  It has no process sampler, no timing claim, and no release
authority.  In particular, the large direct-SHA3 figures identify the retired
baseline that the generated-width backend must replace; they do not estimate
the resource use of that future backend.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Final

from experiments.bl_pq512_crypto_foundation.claim_batch_access_manifest import (
    build_c0_claim_batch_access_manifest,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    build_wave1a_global_sha3_capacity_schedule,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    build_wave1a_global_sha3_schedule,
)


SCHEMA_VERSION: Final[str] = "blind_ledger_pq512_k128_bus_resource_report_v1"
EVIDENCE_CLASS: Final[str] = "DERIVED_MODEL"
ARCHITECTURE_ID: Final[str] = "RETIRED_DIRECT_SHA3_STARK_V1"
PROFILE_ID: Final[str] = "K128_CALIBRATION"
SHA3_512_DIGEST_BYTES: Final[int] = 64
KECCAK_ROUNDS: Final[int] = 25
KECCAK_STATE_BYTES: Final[int] = 200
CHI_AND_GATES_PER_ROUND: Final[int] = 1_536


@dataclass(frozen=True, slots=True)
class K128BusSegment:
    component: str
    tag: int
    call_offset: int
    call_count: int


@dataclass(frozen=True, slots=True)
class K128BusResourceReport:
    schema_version: str
    evidence_class: str
    architecture_id: str
    profile_id: str
    schedule_commitment_512_hex: str
    capacity_commitment_512_hex: str
    cbam_commitment_512_hex: str
    segments: tuple[K128BusSegment, ...]
    sha3_calls: int
    sha3_permutations: int
    sha3_preimage_bytes: int
    sha3_digest_bytes: int
    sha3_message_plus_digest_bytes: int
    keccak_round_boundary_bytes: int
    chi_and_gate_count: int
    state_sha3_calls: int
    state_sha3_permutations: int
    state_preimage_bytes: int
    ordered_map_operations: int
    access_rows: int
    conflict_edges: int
    peak_rss_measured: bool
    scratch_measured: bool
    qualifies: bool
    activation_allowed: bool
    generated_maximum_padded_width: None
    unmeasured_or_unbounded: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """Return JSON-ready, explicitly nonqualifying evidence."""

        result = asdict(self)
        result["segments"] = [asdict(segment) for segment in self.segments]
        result["unmeasured_or_unbounded"] = list(self.unmeasured_or_unbounded)
        return result


def build_k128_bus_resource_report() -> K128BusResourceReport:
    """Derive the current direct-SHA3 baseline from its authoritative sources."""

    profile = PROFILES[PROFILE_ID]
    schedule = build_wave1a_global_sha3_schedule(profile)
    capacity = build_wave1a_global_sha3_capacity_schedule(profile)
    manifest = build_c0_claim_batch_access_manifest(profile)
    if schedule.total_calls != capacity.total_calls or schedule.total_calls != manifest.global_sha3_calls:
        raise ValueError("k128_bus_resource_schedule_count_mismatch")
    preimage_bytes = sum(run.capacity * run.count for run in capacity.runs)
    if preimage_bytes != manifest.global_preimage_bytes:
        raise ValueError("k128_bus_resource_preimage_mismatch")
    permutations = capacity.total_permutations
    return K128BusResourceReport(
        SCHEMA_VERSION,
        EVIDENCE_CLASS,
        ARCHITECTURE_ID,
        profile.profile_id,
        schedule.commitment_512.hex(),
        capacity.commitment_512.hex(),
        manifest.commitment_512.hex(),
        tuple(
            K128BusSegment(
                segment.component,
                segment.tag,
                segment.call_offset,
                segment.call_count,
            )
            for segment in schedule.segments
        ),
        schedule.total_calls,
        permutations,
        preimage_bytes,
        schedule.total_calls * SHA3_512_DIGEST_BYTES,
        preimage_bytes + schedule.total_calls * SHA3_512_DIGEST_BYTES,
        permutations * KECCAK_ROUNDS * KECCAK_STATE_BYTES,
        permutations * KECCAK_ROUNDS * CHI_AND_GATES_PER_ROUND,
        manifest.state_sha3_calls,
        manifest.state_sha3_permutations,
        manifest.state_preimage_bytes,
        manifest.ordered_map_operations,
        manifest.access_rows,
        manifest.conflict_edge_count,
        False,
        False,
        False,
        False,
        None,
        (
            "generated_backend_width",
            "generated_backend_commitment_layout",
            "generated_backend_peak_rss",
            "generated_backend_scratch",
            "allocator_overhead",
            "cross_term_cost",
            "promoted_tail_cost",
            "measured_latency",
            "measured_io",
        ),
    )


__all__ = (
    "ARCHITECTURE_ID",
    "EVIDENCE_CLASS",
    "K128BusResourceReport",
    "K128BusSegment",
    "SCHEMA_VERSION",
    "build_k128_bus_resource_report",
)
