from __future__ import annotations

from dataclasses import fields

from experiments.bl_pq512_crypto_foundation.c0_control_measurement import (
    BOUNDARIES,
    C0BoundaryMeasurement,
    MEASURED_PROFILES,
    SCHEMA_VERSION,
    STATUS,
)


def test_c0_measurement_record_is_explicitly_bounded_and_nonproduction() -> None:
    assert BOUNDARIES == ("state-only", "complete")
    assert MEASURED_PROFILES == ("K128_CALIBRATION", "K512_CALIBRATION")
    assert STATUS == "C0_BOUNDARY_MEASUREMENT_V1_SYNTHETIC_NONPRODUCTION"
    assert SCHEMA_VERSION == "blind-ledger-c0-boundary-measurement-v1"
    assert tuple(field.name for field in fields(C0BoundaryMeasurement)) == (
        "status",
        "schema_version",
        "profile_id",
        "boundary",
        "result_length",
        "result_sha3_512_hex",
        "measured_seconds",
        "peak_rss_bytes",
        "scratch_bytes",
        "pagefile_growth_bytes",
        "io_read_operations",
        "io_write_operations",
        "io_read_bytes",
        "io_write_bytes",
        "scratch_policy",
        "evidence_class",
        "production_usable",
    )
