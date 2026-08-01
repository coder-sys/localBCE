from __future__ import annotations

from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    TraceTable,
    evaluate_program,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.measurement import (
    build_synthetic_measurement_slots,
)
from experiments.fixed_shape_claim_air.oracle_bundle_encoding_executable_air import (
    build_oracle_bundle_encoding_executable_air,
)
from experiments.fixed_shape_claim_air.profile import PROFILES
from experiments.fixed_shape_claim_air.semantics import StructuralError


def _instance():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    return build_oracle_bundle_encoding_executable_air(profile, slots)


def _mutate(instance, table: str, column: str, row: int, value: int):
    trace = instance.traces[table]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = value
    traces = dict(instance.traces)
    traces[table] = TraceTable(
        table, freeze_columns({name: tuple(values) for name, values in columns.items()})
    )
    return MappingProxyType(traces)


def test_k128_oracle_flags_and_tokens_bind_exact_bundle() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert len(instance.bundles) == 128
    assert len(instance.traces["oracle_bundle_byte"].columns["value"]) == 128 * 2_133
    assert report.maximum_degree == 2
    assert report.identities_evaluated == 988_542
    assert report.lookup_messages_evaluated == 2_241_792
    assert report.program_commitment.hex() == (
        "6f9b6c0e4051acbc257f1e1762eba78506e59a6a393da48b7d752c86dc71d8e2"
        "280d4cbeb2b2dda0e44f8d5fe6ad29bd5b10734890aa8a070cea886a4a25aa02"
    )
    assert report.trace_commitment.hex() == (
        "f3f35441030f4be3f3d92869a57a5a80c6a5b4dea8e6ac6e9c30a122e46b138"
        "c979a5a4ca04899d4fc176090333eba54efba0e222e355c625f1ee332dbf6c5d0"
    )
    assert instance.token_ranks_constrained is True
    assert instance.fact_flags_constrained is True
    assert instance.authorization_flags_constrained is True
    assert instance.claim_semantics_links_constrained is False
    assert instance.hashes_constrained is False
    assert instance.signer_epoch_constrained is False


def test_program_commitment_is_independent_of_oracle_witness_shape() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    mixed = _instance()
    covers = build_oracle_bundle_encoding_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "all_cover"),
    )
    assert mixed.program.commitment() == covers.program.commitment()


def test_fact_and_authorization_mutations_fail() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_fact", "eligibility_active", 0, 0),
        )
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_authorization", "present", 0, 1),
        )


def test_token_and_flag_bundle_mutations_fail() -> None:
    instance = _instance()
    token_row = 33
    original = instance.traces["oracle_bundle_byte"].columns["value"][token_row]
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_bundle_byte", "value", token_row, original ^ 1),
        )
    flag_row = 14
    original = instance.traces["oracle_bundle_byte"].columns["value"][flag_row]
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_bundle_byte", "value", flag_row, original ^ 1),
        )


def test_fixed_bundle_header_relabeling_fails() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_bundle_byte", "value", 0, ord("X")),
        )


def test_four_byte_slot_link_and_unused_flag_bits_are_constrained() -> None:
    instance = _instance()
    slot_byte_row = 12
    original = instance.traces["oracle_bundle_byte"].columns["value"][slot_byte_row]
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "oracle_bundle_byte",
                "value",
                slot_byte_row,
                original ^ 1,
            ),
        )
    with pytest.raises(StructuralError, match="identity_failed"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "oracle_authorization_flag_byte",
                "bit_7",
                18,
                1,
            ),
        )


def test_token_presence_cannot_detach_from_authorization_flag() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "oracle_token__token_rank", "required", 0, 1),
        )
