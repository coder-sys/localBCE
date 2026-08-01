from __future__ import annotations

from functools import lru_cache
from dataclasses import replace
from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.claim_source_arrays_executable_air import (
    build_claim_source_arrays_executable_air,
)
from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


@lru_cache(maxsize=1)
def _instance():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    return build_claim_source_arrays_executable_air(profile, slots)


@lru_cache(maxsize=1)
def _ordered_instance():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    slots = (replace(slots[0], diagnoses=("A", "B")), *slots[1:])
    return build_claim_source_arrays_executable_air(profile, slots)


@lru_cache(maxsize=1)
def _two_line_instance():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    first = slots[0].service_lines[0]
    second = replace(
        first,
        original_line_index=1,
        line_id="LINE-0001",
        procedure_code="T1020",
    )
    slots = (
        replace(
            slots[0],
            service_lines=(first, second),
            total_charge_cents=200,
        ),
        *slots[1:],
    )
    return build_claim_source_arrays_executable_air(profile, slots)


def _mutate(instance, table: str, column: str, row: int, value: int):
    trace = instance.traces[table]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = value
    traces = dict(instance.traces)
    traces[table] = TraceTable(
        table, freeze_columns({name: tuple(values) for name, values in columns.items()})
    )
    return MappingProxyType(traces)


def test_k128_claim_source_array_kat() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert report.maximum_degree == 2
    assert report.identities_evaluated == 5_968_871
    assert report.lookup_messages_evaluated == 7_226_936
    assert report.program_commitment.hex() == (
        "c5a47bce19f2f6d857854b681ef54a3961019500a545d2d61530fb20eaf1c96c"
        "eb4ccbffe9ad027ab2878dddc63df3b512ba13f9a9b7219039de8af2d89337c9"
    )
    assert report.trace_commitment.hex() == (
        "d54006e3e82f319ada0a746dfbeacead76b403b369dcd98216515c89936143d0"
        "8d46702f048e5fa16c6e0e342f371cf32685557b2ca0f5d7ceea6a2b9ce4d595"
    )
    assert instance.diagnosis_canonicality_constrained is True
    assert instance.service_framing_constrained is True
    assert instance.original_line_index_uniqueness_constrained is True
    assert instance.service_sort_order_constrained is True
    assert instance.line_id_uniqueness_constrained is True
    assert instance.source_hashes_constrained is False
    assert instance.source_authority_constrained is False


def test_program_commitment_is_independent_of_source_array_witness() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    covers = build_claim_source_arrays_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "all_cover"),
    )
    assert _instance().program.commitment() == covers.program.commitment()


def test_diagnosis_order_comparator_and_character_mutations_fail() -> None:
    instance = _ordered_instance()
    original_borrow = instance.traces["claim_source_diagnosis"].columns["borrow_1"][0]
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "claim_source_diagnosis",
                "borrow_1",
                0,
                original_borrow ^ 1,
            ),
        )
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_diagnosis", "char_0", 0, ord("!")),
        )


def test_service_count_index_and_procedure_mutations_fail() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_service", "count_after", 0, 2),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_service", "original_line_index", 0, 49),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_service", "procedure_char_0", 0, ord("!")),
        )


def test_service_order_line_id_uniqueness_and_charge_sum_mutations_fail() -> None:
    instance = _two_line_instance()
    original_borrow = instance.traces["claim_source_service"].columns[
        "service_order_borrow_0"
    ][0]
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "claim_source_service",
                "service_order_borrow_0",
                0,
                original_borrow ^ 1,
            ),
        )
    original_line_id_byte = instance.traces["claim_source_sorted_line_id"].columns[
        "rank_byte_41"
    ][1]
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "claim_source_sorted_line_id",
                "rank_byte_41",
                1,
                original_line_id_byte ^ 1,
            ),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_service", "charge_sum_carry_3", 0, 1),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_service", "charge_sum_after_3", 0, 99),
        )
