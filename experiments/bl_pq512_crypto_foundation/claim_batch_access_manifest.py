"""Conservative C0 claim-batch access manifest and private access body.

The public manifest is derived only from a governed calibration profile and
fixed policy identifiers.  It intentionally contains no page positions,
keys, values, live-row selectors, decision counts, or other witness-shaped
data.  The separate private body has a profile-fixed row count and carries
only opaque 512-bit page tokens.

This module is a nonactivating census/reference boundary.  It does not select
a proof suite and does not claim that a salted SHA3 commitment implements the
future proof system's native hiding theorem.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
import hmac
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
)
from experiments.fixed_shape_claim_air.profile import CalibrationProfile, PROFILES
from experiments.fixed_shape_claim_air.wave1a_global_sha3_capacity_schedule import (
    Wave1AGlobalSha3CapacitySchedule,
    build_wave1a_global_sha3_capacity_schedule,
)
from experiments.fixed_shape_claim_air.wave1a_global_sha3_schedule import (
    COMPONENTS,
    build_wave1a_global_sha3_schedule,
)


STATUS: Final[str] = "C0_CBAM_REFERENCE_V1_NONACTIVATING"
PRIVATE_BODY_STATUS: Final[str] = (
    "C0_CBAM_PRIVATE_BODY_V1_NATIVE_HIDING_INPUT_ONLY"
)
JOB_BINDING_STATUS: Final[str] = "C0_CBAM_JOB_BINDING_V1_NONACTIVATING"
PUBLIC_MAGIC: Final[bytes] = b"BLPQCB01"
PRIVATE_MAGIC: Final[bytes] = b"BLPQCP01"
JOB_BINDING_MAGIC: Final[bytes] = b"BLPQCJ01"
ENCODING_VERSION: Final[int] = 1
MAX_PUBLIC_ENCODED_BYTES: Final[int] = 1 << 20
MAX_PRIVATE_ENCODED_BYTES: Final[int] = 1 << 20

BENCHMARK_POLICY_REFERENCE: Final[str] = "BL-R25-C0-BENCHMARK-POLICY-v1"
RESOURCE_POLICY_REFERENCE: Final[str] = "BL-R25-C0-RESOURCE-POLICY-v1"
PRIVATE_BODY_SCHEMA_REFERENCE: Final[str] = "BL-R25-C0-CBAM-PRIVATE-BODY-v1"
STATE_LAYOUT_REFERENCE: Final[str] = "BL-R25-DEPTH64-ORDERED-MAP-C0-v1"


def _reference_id(reference: str) -> bytes:
    return sha3_512(
        b"BL/PQ512/FIXED-POLICY-REFERENCE-ID/v1\x00" + reference.encode("ascii")
    ).digest()


BENCHMARK_POLICY_ID_512: Final[bytes] = _reference_id(BENCHMARK_POLICY_REFERENCE)
RESOURCE_POLICY_ID_512: Final[bytes] = _reference_id(RESOURCE_POLICY_REFERENCE)
PRIVATE_BODY_SCHEMA_ID_512: Final[bytes] = _reference_id(
    PRIVATE_BODY_SCHEMA_REFERENCE
)
STATE_LAYOUT_ID_512: Final[bytes] = _reference_id(STATE_LAYOUT_REFERENCE)

PUBLIC_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/C0/CLAIM-BATCH-ACCESS-MANIFEST/v1\x00"
)
PRIVATE_MASKED_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/C0/PRIVATE-ACCESS-BODY/MASKED-REFERENCE/v1\x00"
)
JOB_BINDING_COMMITMENT_DOMAIN: Final[bytes] = (
    b"BL/PQ512/C0/CLAIM-JOB-BINDING/v1\x00"
)

_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}
_COMPONENT_TAGS: Final[dict[str, int]] = {
    component: tag for tag, component in enumerate(COMPONENTS, start=1)
}
_LANE_SPECS: Final[tuple[tuple[str, int], ...]] = (
    ("replay", 1),
    ("benefit", 2),
    ("obligation", 3),
    ("ledger", 4),
    ("payment_application", 5),
)
_MAP_LANE_CODES: Final[tuple[int, ...]] = (1, 2, 3, 4)
_SERIAL_EDGE_REASON: Final[int] = 1

K128_STATE_SHA3_CALLS: Final[int] = 46_208
K128_STATE_SHA3_PERMUTATIONS: Final[int] = 96_900
K128_STATE_PREIMAGE_BYTES: Final[int] = 6_800_980
K128_ORDERED_MAP_OPERATIONS: Final[int] = 641
K128_ACCESS_ROWS: Final[int] = 1_282
K128_CONFLICT_EDGES: Final[int] = 764


def _bytes64(label: str, value: object, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        raise ValueError(f"c0_cbam_{label}_must_be_64_bytes")
    if nonzero and not any(value):
        raise ValueError(f"c0_cbam_{label}_must_be_nonzero")
    return value


def _uint(label: str, value: object, bits: int = 64) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"c0_cbam_{label}_invalid")
    return value


def _known_profile(profile_id: object) -> CalibrationProfile:
    if type(profile_id) is not str or profile_id not in PROFILES:
        raise ValueError("c0_cbam_profile_unknown")
    return PROFILES[profile_id]


@dataclass(frozen=True, slots=True)
class CbamHashRange:
    component: str
    tag: int
    call_offset: int
    call_count: int

    def __post_init__(self) -> None:
        if (
            type(self.component) is not str
            or self.component not in _COMPONENT_TAGS
            or type(self.tag) is not int
            or self.tag != _COMPONENT_TAGS[self.component]
        ):
            raise ValueError("c0_cbam_hash_range_component_invalid")
        _uint("hash_range_offset", self.call_offset)
        if _uint("hash_range_count", self.call_count) == 0:
            raise ValueError("c0_cbam_hash_range_count_zero")


@dataclass(frozen=True, slots=True)
class CbamStateLane:
    lane: str
    lane_code: int
    node_offset: int
    node_count: int
    ordered_map_operations: int
    access_rows: int
    sha3_calls: int
    sha3_permutations: int
    preimage_bytes: int
    conflict_edges: int

    def __post_init__(self) -> None:
        expected = dict(_LANE_SPECS)
        if (
            type(self.lane) is not str
            or self.lane not in expected
            or type(self.lane_code) is not int
            or self.lane_code != expected[self.lane]
        ):
            raise ValueError("c0_cbam_state_lane_identity_invalid")
        for label in (
            "node_offset",
            "node_count",
            "ordered_map_operations",
            "access_rows",
            "sha3_calls",
            "sha3_permutations",
            "preimage_bytes",
            "conflict_edges",
        ):
            _uint(f"state_lane_{label}", getattr(self, label))
        if self.node_count == 0 or self.sha3_calls == 0:
            raise ValueError("c0_cbam_state_lane_empty")
        if self.conflict_edges != self.node_count - 1:
            raise ValueError("c0_cbam_state_lane_edge_count_invalid")
        if self.lane_code in _MAP_LANE_CODES:
            if (
                self.ordered_map_operations != self.node_count
                or self.access_rows != 2 * self.ordered_map_operations
            ):
                raise ValueError("c0_cbam_map_lane_geometry_invalid")
        elif self.ordered_map_operations != 0 or self.access_rows != 0:
            raise ValueError("c0_cbam_application_lane_map_geometry_invalid")


@dataclass(frozen=True, slots=True, order=True)
class CbamConflictEdge:
    lane_code: int
    source_node: int
    destination_node: int
    reason_code: int = _SERIAL_EDGE_REASON

    def __post_init__(self) -> None:
        if type(self.lane_code) is not int or self.lane_code not in dict(
            (code, name) for name, code in _LANE_SPECS
        ):
            raise ValueError("c0_cbam_conflict_edge_lane_invalid")
        _uint("conflict_edge_source", self.source_node)
        _uint("conflict_edge_destination", self.destination_node)
        if (
            self.destination_node != self.source_node + 1
            or type(self.reason_code) is not int
            or self.reason_code != _SERIAL_EDGE_REASON
        ):
            raise ValueError("c0_cbam_conflict_edge_not_canonical_serial_edge")


def _capacity_stats(
    schedule: Wave1AGlobalSha3CapacitySchedule,
    component: str,
    labels: tuple[str, ...],
) -> tuple[int, int, int]:
    selected = tuple(
        run
        for run in schedule.runs
        if run.component == component and run.label in labels
    )
    if tuple(run.label for run in selected) != labels:
        raise ValueError("c0_cbam_authoritative_capacity_lane_mismatch")
    return (
        sum(run.count for run in selected),
        sum(run.permutations for run in selected),
        sum(run.capacity * run.count for run in selected),
    )


def _expected_lanes(profile: CalibrationProfile) -> tuple[CbamStateLane, ...]:
    k = profile.claim_slots
    capacities = build_wave1a_global_sha3_capacity_schedule(profile)
    definitions = (
        (
            "replay",
            1,
            k + 1,
            k + 1,
            "replay_map",
            ("replay_leaf", "replay_node", "replay_header"),
        ),
        (
            "benefit",
            2,
            k,
            k,
            "payment",
            ("benefit_leaf", "benefit_node", "benefit_header"),
        ),
        (
            "obligation",
            3,
            k,
            k,
            "payment",
            ("obligation_leaf", "obligation_node", "obligation_header"),
        ),
        (
            "ledger",
            4,
            2 * k,
            2 * k,
            "payment",
            ("ledger_leaf", "ledger_node", "ledger_header"),
        ),
        (
            "payment_application",
            5,
            k,
            0,
            "payment",
            ("key", "operation", "operation_log"),
        ),
    )
    lanes: list[CbamStateLane] = []
    node_offset = 0
    for lane, code, node_count, map_operations, component, labels in definitions:
        calls, permutations, preimage_bytes = _capacity_stats(
            capacities, component, labels
        )
        if map_operations:
            map_schedule = build_ordered_map_batch_schedule(map_operations)
            if (
                calls != map_schedule.sha3_call_rows
                or permutations != map_schedule.sha3_permutations
            ):
                raise ValueError("c0_cbam_authoritative_map_schedule_mismatch")
            access_rows = map_schedule.memory_rows
        else:
            access_rows = 0
        lanes.append(
            CbamStateLane(
                lane,
                code,
                node_offset,
                node_count,
                map_operations,
                access_rows,
                calls,
                permutations,
                preimage_bytes,
                node_count - 1,
            )
        )
        node_offset += node_count
    return tuple(lanes)


def _expected_edges(lanes: tuple[CbamStateLane, ...]) -> tuple[CbamConflictEdge, ...]:
    return tuple(
        CbamConflictEdge(lane.lane_code, source, source + 1)
        for lane in lanes
        for source in range(
            lane.node_offset, lane.node_offset + lane.node_count - 1
        )
    )


@dataclass(frozen=True, slots=True)
class ClaimBatchAccessManifest:
    """Profile-fixed public C0 envelope; never an activation artifact."""

    status: str
    profile_id: str
    benchmark_policy_id_512: bytes
    resource_policy_id_512: bytes
    state_layout_id_512: bytes
    private_body_schema_id_512: bytes
    global_sha3_schedule_commitment_512: bytes
    global_sha3_capacity_commitment_512: bytes
    hash_ranges: tuple[CbamHashRange, ...]
    state_lanes: tuple[CbamStateLane, ...]
    conflict_edges: tuple[CbamConflictEdge, ...]
    global_sha3_calls: int
    global_sha3_permutations: int
    global_preimage_bytes: int
    state_sha3_calls: int
    state_sha3_permutations: int
    state_preimage_bytes: int
    ordered_map_operations: int
    access_rows: int
    conflict_edge_count: int
    dag_node_count: int
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if self.status != STATUS:
            raise ValueError("c0_cbam_status_invalid")
        profile = _known_profile(self.profile_id)
        for label, value, expected in (
            (
                "benchmark_policy_id",
                self.benchmark_policy_id_512,
                BENCHMARK_POLICY_ID_512,
            ),
            ("resource_policy_id", self.resource_policy_id_512, RESOURCE_POLICY_ID_512),
            ("state_layout_id", self.state_layout_id_512, STATE_LAYOUT_ID_512),
            (
                "private_body_schema_id",
                self.private_body_schema_id_512,
                PRIVATE_BODY_SCHEMA_ID_512,
            ),
        ):
            if not hmac.compare_digest(_bytes64(label, value), expected):
                raise ValueError(f"c0_cbam_{label}_mismatch")
        schedule = build_wave1a_global_sha3_schedule(profile)
        capacities = build_wave1a_global_sha3_capacity_schedule(profile)
        if not hmac.compare_digest(
            _bytes64(
                "global_schedule_commitment",
                self.global_sha3_schedule_commitment_512,
            ),
            schedule.commitment_512,
        ):
            raise ValueError("c0_cbam_global_schedule_commitment_mismatch")
        if not hmac.compare_digest(
            _bytes64(
                "global_capacity_commitment",
                self.global_sha3_capacity_commitment_512,
            ),
            capacities.commitment_512,
        ):
            raise ValueError("c0_cbam_global_capacity_commitment_mismatch")
        expected_ranges = tuple(
            CbamHashRange(
                segment.component,
                segment.tag,
                segment.call_offset,
                segment.call_count,
            )
            for segment in schedule.segments
        )
        if type(self.hash_ranges) is not tuple or self.hash_ranges != expected_ranges:
            raise ValueError("c0_cbam_hash_ranges_not_authoritative")
        expected_lanes = _expected_lanes(profile)
        if type(self.state_lanes) is not tuple or self.state_lanes != expected_lanes:
            raise ValueError("c0_cbam_state_lanes_not_authoritative")
        expected_edges = _expected_edges(expected_lanes)
        if (
            type(self.conflict_edges) is not tuple
            or self.conflict_edges != expected_edges
        ):
            raise ValueError("c0_cbam_conflict_edges_not_canonical_reduction")
        global_bytes = sum(run.capacity * run.count for run in capacities.runs)
        expected_scalars = {
            "global_sha3_calls": schedule.total_calls,
            "global_sha3_permutations": capacities.total_permutations,
            "global_preimage_bytes": global_bytes,
            "state_sha3_calls": sum(lane.sha3_calls for lane in expected_lanes),
            "state_sha3_permutations": sum(
                lane.sha3_permutations for lane in expected_lanes
            ),
            "state_preimage_bytes": sum(lane.preimage_bytes for lane in expected_lanes),
            "ordered_map_operations": sum(
                lane.ordered_map_operations for lane in expected_lanes
            ),
            "access_rows": sum(lane.access_rows for lane in expected_lanes),
            "conflict_edge_count": len(expected_edges),
            "dag_node_count": sum(lane.node_count for lane in expected_lanes),
        }
        for label, expected in expected_scalars.items():
            observed = _uint(label, getattr(self, label))
            if observed != expected:
                raise ValueError(f"c0_cbam_{label}_mismatch")
        if capacities.total_calls != schedule.total_calls:
            raise ValueError("c0_cbam_global_schedule_capacity_count_mismatch")
        if self.proof_suite_id is not None:
            raise ValueError("c0_cbam_proof_suite_must_remain_none")
        if type(self.activation_allowed) is not bool or self.activation_allowed:
            raise ValueError("c0_cbam_activation_forbidden")
        if profile.profile_id == "K128_CALIBRATION":
            exact = (
                self.state_sha3_calls,
                self.state_sha3_permutations,
                self.state_preimage_bytes,
                self.ordered_map_operations,
                self.access_rows,
                self.conflict_edge_count,
            )
            if exact != (
                K128_STATE_SHA3_CALLS,
                K128_STATE_SHA3_PERMUTATIONS,
                K128_STATE_PREIMAGE_BYTES,
                K128_ORDERED_MAP_OPERATIONS,
                K128_ACCESS_ROWS,
                K128_CONFLICT_EDGES,
            ):
                raise ValueError("c0_cbam_k128_frozen_census_mismatch")
        if len(self.encoded) > MAX_PUBLIC_ENCODED_BYTES:
            raise ValueError("c0_cbam_public_encoding_bound_exceeded")

    @property
    def proofSuiteId(self) -> None:
        """Spelling used by the external architecture documents."""

        return self.proof_suite_id

    @property
    def encoded(self) -> bytes:
        profile_code = _PROFILE_CODES[self.profile_id]
        payload = bytearray((profile_code, 1, 0))  # C0-reference, inactive.
        payload.extend((0).to_bytes(1, "big"))  # None proof-suite sentinel.
        for value in (
            self.benchmark_policy_id_512,
            self.resource_policy_id_512,
            self.state_layout_id_512,
            self.private_body_schema_id_512,
            self.global_sha3_schedule_commitment_512,
            self.global_sha3_capacity_commitment_512,
        ):
            payload.extend(value)
        for value in (
            self.global_sha3_calls,
            self.global_sha3_permutations,
            self.global_preimage_bytes,
            self.state_sha3_calls,
            self.state_sha3_permutations,
            self.state_preimage_bytes,
            self.ordered_map_operations,
            self.access_rows,
            self.conflict_edge_count,
            self.dag_node_count,
        ):
            payload.extend(value.to_bytes(8, "big"))
        payload.extend(len(self.hash_ranges).to_bytes(2, "big"))
        for item in self.hash_ranges:
            payload.extend(bytes((item.tag,)))
            payload.extend(item.call_offset.to_bytes(8, "big"))
            payload.extend(item.call_count.to_bytes(8, "big"))
        payload.extend(len(self.state_lanes).to_bytes(2, "big"))
        for lane in self.state_lanes:
            payload.extend(bytes((lane.lane_code,)))
            for value in (
                lane.node_offset,
                lane.node_count,
                lane.ordered_map_operations,
                lane.access_rows,
                lane.sha3_calls,
                lane.sha3_permutations,
                lane.preimage_bytes,
                lane.conflict_edges,
            ):
                payload.extend(value.to_bytes(8, "big"))
        payload.extend(len(self.conflict_edges).to_bytes(4, "big"))
        for edge in self.conflict_edges:
            payload.extend(bytes((edge.lane_code, edge.reason_code)))
            payload.extend(edge.source_node.to_bytes(8, "big"))
            payload.extend(edge.destination_node.to_bytes(8, "big"))
        encoded = (
            PUBLIC_MAGIC
            + ENCODING_VERSION.to_bytes(2, "big")
            + len(payload).to_bytes(4, "big")
            + bytes(payload)
        )
        if len(encoded) > MAX_PUBLIC_ENCODED_BYTES:
            raise ValueError("c0_cbam_public_encoding_bound_exceeded")
        return encoded

    @property
    def commitment_512(self) -> bytes:
        return sha3_512(PUBLIC_COMMITMENT_DOMAIN + self.encoded).digest()


def build_c0_claim_batch_access_manifest(
    profile: CalibrationProfile,
) -> ClaimBatchAccessManifest:
    if (
        type(profile) is not CalibrationProfile
        or PROFILES.get(profile.profile_id) != profile
    ):
        raise ValueError("c0_cbam_profile_not_governed")
    schedule = build_wave1a_global_sha3_schedule(profile)
    capacities = build_wave1a_global_sha3_capacity_schedule(profile)
    ranges = tuple(
        CbamHashRange(
            segment.component,
            segment.tag,
            segment.call_offset,
            segment.call_count,
        )
        for segment in schedule.segments
    )
    lanes = _expected_lanes(profile)
    edges = _expected_edges(lanes)
    return ClaimBatchAccessManifest(
        STATUS,
        profile.profile_id,
        BENCHMARK_POLICY_ID_512,
        RESOURCE_POLICY_ID_512,
        STATE_LAYOUT_ID_512,
        PRIVATE_BODY_SCHEMA_ID_512,
        schedule.commitment_512,
        capacities.commitment_512,
        ranges,
        lanes,
        edges,
        schedule.total_calls,
        capacities.total_permutations,
        sum(run.capacity * run.count for run in capacities.runs),
        sum(lane.sha3_calls for lane in lanes),
        sum(lane.sha3_permutations for lane in lanes),
        sum(lane.preimage_bytes for lane in lanes),
        sum(lane.ordered_map_operations for lane in lanes),
        sum(lane.access_rows for lane in lanes),
        len(edges),
        sum(lane.node_count for lane in lanes),
    )


@dataclass(frozen=True, slots=True)
class CbamPrivateAccessRow:
    lane_code: int
    operation_index: int
    access_kind: int
    opaque_page_token_512: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.lane_code) is not int or self.lane_code not in _MAP_LANE_CODES:
            raise ValueError("c0_cbam_private_row_lane_invalid")
        _uint("private_row_operation_index", self.operation_index, 32)
        if type(self.access_kind) is not int or self.access_kind not in {0, 1}:
            raise ValueError("c0_cbam_private_row_access_kind_invalid")
        _bytes64(
            "private_row_opaque_page_token",
            self.opaque_page_token_512,
            nonzero=True,
        )


def _private_geometry(profile: CalibrationProfile) -> tuple[tuple[int, int, int], ...]:
    k = profile.claim_slots
    operation_counts = (k + 1, k, k, 2 * k)
    return tuple(
        (lane_code, operation_index, access_kind)
        for lane_code, operation_count in zip(
            _MAP_LANE_CODES, operation_counts, strict=True
        )
        for operation_index in range(operation_count)
        for access_kind in (0, 1)
    )


@dataclass(frozen=True, slots=True)
class CbamPrivateAccessBody:
    """Fixed-size private input; page identities remain opaque 512-bit tokens."""

    status: str
    profile_id: str
    rows: tuple[CbamPrivateAccessRow, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if self.status != PRIVATE_BODY_STATUS:
            raise ValueError("c0_cbam_private_body_status_invalid")
        profile = _known_profile(self.profile_id)
        expected = _private_geometry(profile)
        if type(self.rows) is not tuple or len(self.rows) != len(expected):
            raise ValueError("c0_cbam_private_body_row_count_invalid")
        if any(type(row) is not CbamPrivateAccessRow for row in self.rows):
            raise ValueError("c0_cbam_private_body_row_type_invalid")
        observed = tuple(
            (row.lane_code, row.operation_index, row.access_kind)
            for row in self.rows
        )
        if observed != expected:
            raise ValueError("c0_cbam_private_body_geometry_not_canonical")
        if len(self.encoded) > MAX_PRIVATE_ENCODED_BYTES:
            raise ValueError("c0_cbam_private_encoding_bound_exceeded")

    @property
    def encoded(self) -> bytes:
        payload = bytearray((_PROFILE_CODES[self.profile_id], 0))
        payload.extend(len(self.rows).to_bytes(4, "big"))
        for row in self.rows:
            payload.extend(bytes((row.lane_code, row.access_kind)))
            payload.extend(row.operation_index.to_bytes(4, "big"))
            payload.extend(row.opaque_page_token_512)
        encoded = (
            PRIVATE_MAGIC
            + ENCODING_VERSION.to_bytes(2, "big")
            + len(payload).to_bytes(4, "big")
            + bytes(payload)
        )
        if len(encoded) > MAX_PRIVATE_ENCODED_BYTES:
            raise ValueError("c0_cbam_private_encoding_bound_exceeded")
        return encoded

    def masked_reference_commitment_512(self, masking_seed_512: bytes) -> bytes:
        """Commit for tests/transcripts without claiming proof-native hiding."""

        seed = _bytes64("private_masking_seed", masking_seed_512, nonzero=True)
        return sha3_512(
            PRIVATE_MASKED_COMMITMENT_DOMAIN + seed + self.encoded
        ).digest()


def build_c0_private_access_body(
    profile: CalibrationProfile,
    opaque_page_tokens_512: Sequence[bytes],
) -> CbamPrivateAccessBody:
    if (
        type(profile) is not CalibrationProfile
        or PROFILES.get(profile.profile_id) != profile
    ):
        raise ValueError("c0_cbam_profile_not_governed")
    if type(opaque_page_tokens_512) not in {tuple, list}:
        raise ValueError("c0_cbam_private_tokens_sequence_invalid")
    geometry = _private_geometry(profile)
    if len(opaque_page_tokens_512) != len(geometry):
        raise ValueError("c0_cbam_private_token_count_invalid")
    tokens = tuple(opaque_page_tokens_512)
    if len(tokens) != len(geometry):
        raise ValueError("c0_cbam_private_token_count_changed")
    rows = tuple(
        CbamPrivateAccessRow(lane, operation, kind, token)
        for (lane, operation, kind), token in zip(geometry, tokens, strict=True)
    )
    return CbamPrivateAccessBody(PRIVATE_BODY_STATUS, profile.profile_id, rows)


@dataclass(frozen=True, slots=True)
class CbamClaimJobBinding:
    """Per-job C0 binding for a fixed census and opaque private access body.

    This is deliberately an input/transcript boundary, not a proof artifact.
    The future native-hiding proof must authenticate the same fields before this
    object can become activation-relevant.
    """

    status: str
    profile_id: str
    fixed_manifest_commitment_512: bytes
    masked_private_body_commitment_512: bytes
    batch_id_512: bytes
    sidecar_root_512: bytes
    state_root_512: bytes
    claim_attempt_id_512: bytes
    retry_id_512: bytes
    job_sequence_id_512: bytes
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        if self.status != JOB_BINDING_STATUS:
            raise ValueError("c0_cbam_job_binding_status_invalid")
        profile = _known_profile(self.profile_id)
        expected_manifest = build_c0_claim_batch_access_manifest(profile)
        if not hmac.compare_digest(
            _bytes64("job_fixed_manifest_commitment", self.fixed_manifest_commitment_512),
            expected_manifest.commitment_512,
        ):
            raise ValueError("c0_cbam_job_fixed_manifest_commitment_mismatch")
        for label, value in (
            ("job_masked_private_body_commitment", self.masked_private_body_commitment_512),
            ("job_batch_id", self.batch_id_512),
            ("job_sidecar_root", self.sidecar_root_512),
            ("job_state_root", self.state_root_512),
            ("job_claim_attempt_id", self.claim_attempt_id_512),
            ("job_retry_id", self.retry_id_512),
            ("job_sequence_id", self.job_sequence_id_512),
        ):
            _bytes64(label, value, nonzero=True)
        if self.proof_suite_id is not None:
            raise ValueError("c0_cbam_job_proof_suite_must_remain_none")
        if type(self.activation_allowed) is not bool or self.activation_allowed:
            raise ValueError("c0_cbam_job_activation_forbidden")
        if len(self.encoded) > MAX_PUBLIC_ENCODED_BYTES:
            raise ValueError("c0_cbam_job_encoding_bound_exceeded")

    @property
    def encoded(self) -> bytes:
        payload = bytearray((_PROFILE_CODES[self.profile_id], 1, 0, 0))
        for value in (
            self.fixed_manifest_commitment_512,
            self.masked_private_body_commitment_512,
            self.batch_id_512,
            self.sidecar_root_512,
            self.state_root_512,
            self.claim_attempt_id_512,
            self.retry_id_512,
            self.job_sequence_id_512,
        ):
            payload.extend(value)
        encoded = (
            JOB_BINDING_MAGIC
            + ENCODING_VERSION.to_bytes(2, "big")
            + len(payload).to_bytes(4, "big")
            + bytes(payload)
        )
        if len(encoded) > MAX_PUBLIC_ENCODED_BYTES:
            raise ValueError("c0_cbam_job_encoding_bound_exceeded")
        return encoded

    @property
    def commitment_512(self) -> bytes:
        return sha3_512(JOB_BINDING_COMMITMENT_DOMAIN + self.encoded).digest()

    def verify_private_body(
        self, body: CbamPrivateAccessBody, masking_seed_512: bytes
    ) -> None:
        if type(body) is not CbamPrivateAccessBody or body.profile_id != self.profile_id:
            raise ValueError("c0_cbam_job_private_body_profile_mismatch")
        if not hmac.compare_digest(
            self.masked_private_body_commitment_512,
            body.masked_reference_commitment_512(masking_seed_512),
        ):
            raise ValueError("c0_cbam_job_private_body_commitment_mismatch")


def build_c0_claim_job_binding(
    manifest: ClaimBatchAccessManifest,
    body: CbamPrivateAccessBody,
    masking_seed_512: bytes,
    *,
    batch_id_512: bytes,
    sidecar_root_512: bytes,
    state_root_512: bytes,
    claim_attempt_id_512: bytes,
    retry_id_512: bytes,
    job_sequence_id_512: bytes,
) -> CbamClaimJobBinding:
    """Bind all replay-relevant job identities without disclosing page tokens."""

    if type(manifest) is not ClaimBatchAccessManifest or type(body) is not CbamPrivateAccessBody:
        raise ValueError("c0_cbam_job_manifest_or_body_type_invalid")
    if manifest.profile_id != body.profile_id:
        raise ValueError("c0_cbam_job_manifest_body_profile_mismatch")
    result = CbamClaimJobBinding(
        JOB_BINDING_STATUS,
        manifest.profile_id,
        manifest.commitment_512,
        body.masked_reference_commitment_512(masking_seed_512),
        batch_id_512,
        sidecar_root_512,
        state_root_512,
        claim_attempt_id_512,
        retry_id_512,
        job_sequence_id_512,
    )
    result.verify_private_body(body, masking_seed_512)
    return result


@dataclass(slots=True)
class _CanonicalReader:
    data: bytes
    cursor: int = 0

    def take(self, label: str, count: int) -> bytes:
        stop = self.cursor + count
        if stop > len(self.data):
            raise ValueError(f"c0_cbam_decode_{label}_truncated")
        value = self.data[self.cursor : stop]
        self.cursor = stop
        return value

    def uint(self, label: str, count: int) -> int:
        return int.from_bytes(self.take(label, count), "big")

    def finish(self) -> None:
        if self.cursor != len(self.data):
            raise ValueError("c0_cbam_decode_trailing_bytes")


def _decode_payload(encoded: bytes, magic: bytes, label: str) -> _CanonicalReader:
    if type(encoded) is not bytes or len(encoded) > MAX_PUBLIC_ENCODED_BYTES:
        raise ValueError(f"c0_cbam_decode_{label}_type_or_bound_invalid")
    reader = _CanonicalReader(encoded)
    if reader.take("magic", len(magic)) != magic:
        raise ValueError(f"c0_cbam_decode_{label}_magic_invalid")
    if reader.uint("version", 2) != ENCODING_VERSION:
        raise ValueError(f"c0_cbam_decode_{label}_version_invalid")
    declared_length = reader.uint("payload_length", 4)
    if declared_length != len(encoded) - reader.cursor:
        raise ValueError(f"c0_cbam_decode_{label}_length_invalid")
    return _CanonicalReader(reader.take("payload", declared_length))


def _profile_from_code(code: int) -> str:
    for profile_id, profile_code in _PROFILE_CODES.items():
        if code == profile_code:
            return profile_id
    raise ValueError("c0_cbam_decode_profile_unknown")


def _component_from_tag(tag: int) -> str:
    for component, expected_tag in _COMPONENT_TAGS.items():
        if tag == expected_tag:
            return component
    raise ValueError("c0_cbam_decode_component_unknown")


def _lane_from_code(code: int) -> str:
    for lane, expected_code in _LANE_SPECS:
        if code == expected_code:
            return lane
    raise ValueError("c0_cbam_decode_lane_unknown")


def _decode_range(reader: _CanonicalReader) -> CbamHashRange:
    tag = reader.uint("public_range_tag", 1)
    return CbamHashRange(
        _component_from_tag(tag),
        tag,
        reader.uint("public_range_offset", 8),
        reader.uint("public_range_count", 8),
    )


def _decode_lane(reader: _CanonicalReader) -> CbamStateLane:
    code = reader.uint("public_lane_code", 1)
    return CbamStateLane(
        _lane_from_code(code),
        code,
        *(reader.uint("public_lane_scalar", 8) for _ in range(8)),
    )


def _decode_edge(reader: _CanonicalReader) -> CbamConflictEdge:
    lane_code = reader.uint("public_edge_lane", 1)
    reason_code = reader.uint("public_edge_reason", 1)
    return CbamConflictEdge(
        lane_code,
        reader.uint("public_edge_source", 8),
        reader.uint("public_edge_destination", 8),
        reason_code,
    )


def _decode_private_row(reader: _CanonicalReader) -> CbamPrivateAccessRow:
    lane_code = reader.uint("private_lane", 1)
    access_kind = reader.uint("private_access_kind", 1)
    operation_index = reader.uint("private_operation", 4)
    return CbamPrivateAccessRow(
        lane_code,
        operation_index,
        access_kind,
        reader.take("private_token", 64),
    )


def decode_c0_claim_batch_access_manifest(encoded: bytes) -> ClaimBatchAccessManifest:
    """Strictly reconstruct the profile-fixed public census from its bytes."""

    reader = _decode_payload(encoded, PUBLIC_MAGIC, "public")
    profile_id = _profile_from_code(reader.uint("public_profile", 1))
    if (reader.uint("public_status", 1), reader.uint("public_active", 1), reader.uint("public_suite", 1)) != (1, 0, 0):
        raise ValueError("c0_cbam_decode_public_flags_invalid")
    ids = tuple(reader.take("public_identifier", 64) for _ in range(6))
    scalars = tuple(reader.uint("public_scalar", 8) for _ in range(10))
    ranges = tuple(_decode_range(reader) for _ in range(reader.uint("public_range_total", 2)))
    lanes = tuple(_decode_lane(reader) for _ in range(reader.uint("public_lane_total", 2)))
    edges = tuple(_decode_edge(reader) for _ in range(reader.uint("public_edge_total", 4)))
    reader.finish()
    return ClaimBatchAccessManifest(
        STATUS, profile_id, *ids, ranges, lanes, edges, *scalars
    )


def decode_c0_private_access_body(encoded: bytes) -> CbamPrivateAccessBody:
    """Strictly reconstruct the fixed private row geometry from its bytes."""

    reader = _decode_payload(encoded, PRIVATE_MAGIC, "private")
    profile_id = _profile_from_code(reader.uint("private_profile", 1))
    if reader.uint("private_reserved", 1) != 0:
        raise ValueError("c0_cbam_decode_private_flags_invalid")
    row_total = reader.uint("private_row_total", 4)
    expected = _private_geometry(_known_profile(profile_id))
    if row_total != len(expected):
        raise ValueError("c0_cbam_decode_private_row_total_invalid")
    rows = tuple(_decode_private_row(reader) for _ in range(row_total))
    reader.finish()
    return CbamPrivateAccessBody(PRIVATE_BODY_STATUS, profile_id, rows)


def decode_c0_claim_job_binding(encoded: bytes) -> CbamClaimJobBinding:
    """Strictly reconstruct the non-activating per-job public binding."""

    reader = _decode_payload(encoded, JOB_BINDING_MAGIC, "job")
    profile_id = _profile_from_code(reader.uint("job_profile", 1))
    if (reader.uint("job_status", 1), reader.uint("job_active", 1), reader.uint("job_suite", 1)) != (1, 0, 0):
        raise ValueError("c0_cbam_decode_job_flags_invalid")
    values = tuple(reader.take("job_identifier", 64) for _ in range(8))
    reader.finish()
    return CbamClaimJobBinding(JOB_BINDING_STATUS, profile_id, *values)


__all__ = (
    "BENCHMARK_POLICY_ID_512",
    "BENCHMARK_POLICY_REFERENCE",
    "CbamConflictEdge",
    "CbamClaimJobBinding",
    "CbamHashRange",
    "CbamPrivateAccessBody",
    "CbamPrivateAccessRow",
    "CbamStateLane",
    "ClaimBatchAccessManifest",
    "K128_ACCESS_ROWS",
    "K128_CONFLICT_EDGES",
    "K128_ORDERED_MAP_OPERATIONS",
    "K128_STATE_PREIMAGE_BYTES",
    "K128_STATE_SHA3_CALLS",
    "K128_STATE_SHA3_PERMUTATIONS",
    "JOB_BINDING_STATUS",
    "PRIVATE_BODY_SCHEMA_ID_512",
    "PRIVATE_BODY_SCHEMA_REFERENCE",
    "RESOURCE_POLICY_ID_512",
    "RESOURCE_POLICY_REFERENCE",
    "STATE_LAYOUT_ID_512",
    "STATE_LAYOUT_REFERENCE",
    "STATUS",
    "build_c0_claim_batch_access_manifest",
    "build_c0_claim_job_binding",
    "build_c0_private_access_body",
    "decode_c0_claim_batch_access_manifest",
    "decode_c0_claim_job_binding",
    "decode_c0_private_access_body",
)
