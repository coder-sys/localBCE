"""Serial host-model measurements for K128/K256/K512; never proof timings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import gc
import json
from time import perf_counter
import tracemalloc
from typing import Final

from .payment import derive_batch_economics
from .payment_state import append_reference_operation_log
from .profile import CalibrationProfile, PROFILES
from .semantics import ClaimSlot, RevisionKind, ServiceLine, SlotKind
from .trace import build_logical_trace


MEASUREMENT_STATUS: Final[str] = (
    "SYNTHETIC_HOST_MODEL_ONLY_NO_PHYSICAL_AIR_NO_PROOF"
)
SHAPES: Final[tuple[str, ...]] = (
    "all_cover",
    "approval_plus_cover",
    "denial_plus_cover",
    "mixed_half_real",
    "full_capacity_real",
)


@dataclass(frozen=True, slots=True)
class ModelMeasurement:
    profile_id: str
    shape: str
    claim_slots: int
    phase_seconds: dict[str, float]
    phase_percent: dict[str, float]
    total_seconds: float
    python_tracemalloc_peak_bytes: int
    logical_dimensions: dict[str, int]
    physical_air_rows: None
    physical_air_columns: None
    proofs_generated: int
    proof_suite_id: None
    activation_allowed: bool
    status: str


def _line(index: int) -> ServiceLine:
    return ServiceLine(
        original_line_index=index,
        line_id=f"LINE-{index:04d}",
        procedure_code="T1019",
        charge_cents=100,
        units_cents=1,
        prior_authorization="",
        policy_present=True,
        allowed_cents=100,
        requires_prior_authorization=False,
        authorization_present=False,
    )


def _real(slot_index: int, *, denied: bool, full_inner: bool) -> ClaimSlot:
    lines = tuple(_line(index) for index in range(50 if full_inner else 1))
    diagnoses = (
        tuple(f"D{index:02d}" for index in range(16))
        if full_inner
        else ("F840",)
    )
    total = sum(line.charge_cents for line in lines)
    responsibility = 0 if denied else min(20, total)
    return ClaimSlot(
        slot_index=slot_index,
        slot_kind=SlotKind.REAL,
        source_authority_id="BL-SYNTH-GOV-INTAKE-V1",
        source_sequence=slot_index + 1,
        claim_id=f"BL-SYNTH-CLAIM-{slot_index + 1:04d}",
        member_id="" if denied else "SYNTH-MEMBER-001",
        provider_npi="1999999984",
        attempt_version=1,
        revision_kind=RevisionKind.ORIGINAL,
        parent_attempt_version=0,
        diagnoses=diagnoses,
        service_lines=lines,
        eligibility_active=True,
        provider_enrolled=True,
        provider_not_suspended=True,
        not_deceased=True,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=total,
        patient_responsibility_cents=responsibility,
        claimed_decision=0 if denied else 1,
        claimed_failure_code=1 if denied else 0,
        claimed_allowed_cents=0 if denied else total,
        claimed_payment_cents=0 if denied else total - responsibility,
    )


def _cover(slot_index: int) -> ClaimSlot:
    return ClaimSlot(
        slot_index=slot_index,
        slot_kind=SlotKind.COVER,
        source_authority_id="",
        source_sequence=0,
        claim_id="",
        member_id="",
        provider_npi="",
        attempt_version=0,
        revision_kind=RevisionKind.COVER,
        parent_attempt_version=0,
        diagnoses=(),
        service_lines=(),
        eligibility_active=False,
        provider_enrolled=False,
        provider_not_suspended=False,
        not_deceased=False,
        duplicate_claim=False,
        program_integrity_hold=False,
        total_charge_cents=0,
        patient_responsibility_cents=0,
        claimed_decision=0,
        claimed_failure_code=0,
        claimed_allowed_cents=0,
        claimed_payment_cents=0,
    )


def build_synthetic_measurement_slots(
    profile: CalibrationProfile,
    shape: str,
) -> tuple[ClaimSlot, ...]:
    if shape not in SHAPES:
        raise ValueError("r25_measurement_shape_unknown")
    k = profile.claim_slots
    if shape == "all_cover":
        return tuple(_cover(index) for index in range(k))
    if shape == "approval_plus_cover":
        return (_real(0, denied=False, full_inner=False),) + tuple(
            _cover(index) for index in range(1, k)
        )
    if shape == "denial_plus_cover":
        return (_real(0, denied=True, full_inner=False),) + tuple(
            _cover(index) for index in range(1, k)
        )
    if shape == "mixed_half_real":
        real_count = k // 2
        return tuple(
            _real(index, denied=index % 5 == 0, full_inner=False)
            for index in range(real_count)
        ) + tuple(_cover(index) for index in range(real_count, k))
    return tuple(
        _real(index, denied=False, full_inner=True) for index in range(k)
    )


def measure_model(profile: CalibrationProfile, shape: str) -> ModelMeasurement:
    gc.collect()
    tracemalloc.start()
    start = perf_counter()
    slots = build_synthetic_measurement_slots(profile, shape)
    after_fixture = perf_counter()
    trace = build_logical_trace(profile, slots)
    after_trace = perf_counter()
    economics = derive_batch_economics(profile, slots)
    after_economics = perf_counter()
    append_reference_operation_log(
        bytes([0xA5]) * 64,
        economics.slots,
        expected_count=profile.claim_slots,
    )
    after_operation_log = perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    phases = {
        "fixture_build": after_fixture - start,
        "logical_trace": after_trace - after_fixture,
        "payment_economics": after_economics - after_trace,
        "operation_log": after_operation_log - after_economics,
    }
    total = sum(phases.values())
    percentages = {
        name: (seconds / total * 100.0 if total else 0.0)
        for name, seconds in phases.items()
    }
    return ModelMeasurement(
        profile_id=profile.profile_id,
        shape=shape,
        claim_slots=profile.claim_slots,
        phase_seconds=phases,
        phase_percent=percentages,
        total_seconds=total,
        python_tracemalloc_peak_bytes=peak,
        logical_dimensions=dict(trace.logical_dimensions),
        physical_air_rows=trace.physical_air_rows,
        physical_air_columns=trace.physical_air_columns,
        proofs_generated=0,
        proof_suite_id=None,
        activation_allowed=False,
        status=MEASUREMENT_STATUS,
    )


def run_serial_measurements() -> tuple[ModelMeasurement, ...]:
    return tuple(
        measure_model(profile, shape)
        for profile in PROFILES.values()
        for shape in SHAPES
    )


def main() -> None:
    payload = [asdict(measurement) for measurement in run_serial_measurements()]
    print(json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
