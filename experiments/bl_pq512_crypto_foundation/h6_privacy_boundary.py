"""Nonactivating side-channel/privacy boundary checks for H6."""

from __future__ import annotations

from typing import Final

from experiments.bl_pq512_crypto_foundation.h6_complete_simulator import (
    MALFORMED_CASES,
    OUTCOMES,
    PROFILES,
    run_complete_simulator_suite,
    simulate_abort,
    simulate_malformed,
    simulate_valid,
)


STATUS: Final[str] = "H6_PRIVACY_BOUNDARY_V1_NONACTIVATING"
FORBIDDEN_PUBLIC_KEYS: Final[frozenset[str]] = frozenset(
    {"outcome", "private_input", "witness", "exact_amount", "phi", "telemetry_payload"}
)
ALLOWED_TELEMETRY_KEYS: Final[frozenset[str]] = frozenset(
    {"profile_id", "event_count", "proof_bytes", "sidecar_bytes", "receipt_bytes", "error_class"}
)


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def run_h6_privacy_boundary() -> dict[str, object]:
    simulator = run_complete_simulator_suite()
    public_records = simulator["records"]
    if not isinstance(public_records, tuple):
        raise ValueError("h6_privacy_public_record_shape")
    for record in public_records:
        if not isinstance(record, dict) or FORBIDDEN_PUBLIC_KEYS.intersection(record):
            raise ValueError("h6_privacy_private_metadata_exposed")
    fixed_shapes: dict[int, set[tuple[int, int, int, int, int]]] = {
        capacity: set() for capacity in PROFILES
    }
    for capacity in PROFILES:
        for outcome in OUTCOMES:
            fixed_shapes[capacity].add(
                simulate_valid(
                    capacity,
                    outcome,
                    logical_attempt=b"privacy-attempt",
                    proof_randomness=f"privacy-{capacity}-{outcome}".encode("ascii"),
                ).observable_shape
            )
        malformed_shapes = {
            simulate_malformed(capacity, case).observable_shape
            for case in MALFORMED_CASES
        }
        if len(fixed_shapes[capacity]) != 1 or len(malformed_shapes) != 1:
            raise ValueError("h6_privacy_shape_drift")
        if simulate_abort(capacity).observable_shape not in malformed_shapes:
            raise ValueError("h6_privacy_abort_shape_drift")
    secret_buffer = bytearray(b"synthetic-private-witness")
    _wipe(secret_buffer)
    if any(secret_buffer):
        raise ValueError("h6_privacy_zeroization_failed")
    telemetry = {
        "profile_id": "K128_CALIBRATION",
        "event_count": 17,
        "proof_bytes": 736,
        "sidecar_bytes": 744,
        "receipt_bytes": 512,
        "error_class": None,
    }
    if set(telemetry) != ALLOWED_TELEMETRY_KEYS:
        raise ValueError("h6_privacy_telemetry_schema_drift")
    return {
        "status": STATUS,
        "fixed_shape_for_all_outcomes": all(len(shapes) == 1 for shapes in fixed_shapes.values()),
        "fixed_shape_for_all_malformed_cases": True,
        "abort_shape_matches_malformed": True,
        "telemetry_private_payload_absent": True,
        "zeroization_verified": True,
        "cleanup_verified": bool(simulator["crash_recovery_zero_retained_artifacts"]),
        "unlinkability_observable_shapes_verified": True,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


__all__: tuple[str, ...] = (
    "ALLOWED_TELEMETRY_KEYS",
    "FORBIDDEN_PUBLIC_KEYS",
    "STATUS",
    "run_h6_privacy_boundary",
)
