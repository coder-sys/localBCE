from __future__ import annotations

from functools import lru_cache
from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.measurement import build_synthetic_measurement_slots
from experiments.fixed_shape_claim_air.policy_bundle_encoding_executable_air import (
    build_policy_bundle_encoding_executable_air,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


@lru_cache(maxsize=1)
def _instance():
    profile = PROFILES["K128_CALIBRATION"]
    return build_policy_bundle_encoding_executable_air(
        profile, build_synthetic_measurement_slots(profile, "mixed_half_real")
    )


def _mutate(instance, table: str, column: str, row: int, value: int):
    trace = instance.traces[table]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = value
    traces = dict(instance.traces)
    traces[table] = TraceTable(
        table, freeze_columns({name: tuple(values) for name, values in columns.items()})
    )
    return MappingProxyType(traces)


def test_k128_policy_bundle_encoding_air_kat() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert report.identities_evaluated == 449_920
    assert report.lookup_messages_evaluated == 465_664
    assert report.maximum_degree == 2
    assert report.program_commitment.hex() == (
        "cc6abb4307e314626a92c5b25092df3964418440d75dc4a36686c17c19d15d89"
        "83e302ce24e4b01a561d05afc132f117a268f4fd916b02f539177ef039454890"
    )
    assert report.trace_commitment.hex() == (
        "61de3e9e513e4a19f9fe1f78c934c2276cdb64a22bc34202658c5ec6cca01d8"
        "472790bd9d81d522bb3ac8c782726be50afd7877386f3e8cb72294ffa669246a6"
    )
    assert instance.policy_payload_constrained is True
    assert instance.policy_hashes_constrained is False


def test_policy_header_line_value_and_padding_mutations_fail() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed"):
        evaluate_program(
            instance.program,
            _mutate(instance, "policy_bundle_byte", "value", 0, ord("X")),
        )
    original = instance.traces["policy_line"].columns["allowed_byte_3"][0]
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "policy_line", "allowed_byte_3", 0, original ^ 1),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "policy_line", "procedure_char_9", 0, ord("A")),
        )


def test_policy_program_is_witness_shape_independent() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    covers = build_policy_bundle_encoding_executable_air(
        profile, build_synthetic_measurement_slots(profile, "all_cover")
    )
    assert _instance().program.commitment() == covers.program.commitment()
