from __future__ import annotations

from types import MappingProxyType

import pytest

from experiments.fixed_shape_claim_air.claim_source_encoding_executable_air import (
    build_claim_source_encoding_executable_air,
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


def _instance():
    profile = PROFILES["K128_CALIBRATION"]
    slots = build_synthetic_measurement_slots(profile, "mixed_half_real")
    return build_claim_source_encoding_executable_air(profile, slots)


def _mutate(instance, table: str, column: str, row: int, value: int):
    trace = instance.traces[table]
    columns = {name: list(values) for name, values in trace.columns.items()}
    columns[column][row] = value
    traces = dict(instance.traces)
    traces[table] = TraceTable(
        table, freeze_columns({name: tuple(values) for name, values in columns.items()})
    )
    return MappingProxyType(traces)


def test_k128_token_ranks_are_constrained_at_exact_bundle_offsets() -> None:
    instance = _instance()
    report = evaluate_program(instance.program, instance.traces)
    assert len(instance.bundles) == 128
    assert len(instance.traces["claim_source_bundle_byte"].columns["value"]) == (
        128 * 5_648
    )
    assert report.maximum_degree == 2
    assert report.identities_evaluated == 1_985_280
    assert report.lookup_messages_evaluated == 4_807_424
    assert report.program_commitment.hex() == (
        "a08939a2a8a56dabc0bacfc919d1fff5795636a783787d9c8e1c756418a345e3"
        "6661590c076dd003775199c523485a8906ba710ff6b2804a2acfe4eff0a6b232"
    )
    assert report.trace_commitment.hex() == (
        "872005f1904fa37590d8659dbcbd095030cf40e06a6c323670fa3d1f144d794e"
        "4d7be1e8d8cac736e7b7f94d42f6210bad6423b540fbf0af02bfe8e8e21d8d56"
    )
    assert instance.token_ranks_constrained is True
    assert instance.bundle_token_links_constrained is True
    assert instance.scalar_fields_constrained is True
    assert instance.bundle_other_fields_constrained is False
    assert instance.hashes_constrained is False
    assert instance.source_authority_constrained is False


def test_program_commitment_is_independent_of_claim_witness_shape() -> None:
    profile = PROFILES["K128_CALIBRATION"]
    mixed = _instance()
    covers = build_claim_source_encoding_executable_air(
        profile,
        build_synthetic_measurement_slots(profile, "all_cover"),
    )
    assert mixed.program.commitment() == covers.program.commitment()


def test_private_required_state_cannot_detach_from_real_slot() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "source_token__token_rank", "required", 0, 0),
        )


def test_token_rank_mutation_breaks_rank_or_bundle_link() -> None:
    instance = _instance()
    table = "source_token__token_rank"
    original = instance.traces[table].columns["rank_byte_41"][0]
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, table, "rank_byte_41", 0, original ^ 1),
        )


def test_bundle_token_byte_mutation_breaks_exact_offset_link() -> None:
    instance = _instance()
    row = 12
    original = instance.traces["claim_source_bundle_byte"].columns["value"][row]
    with pytest.raises(StructuralError, match="lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "claim_source_bundle_byte",
                "value",
                row,
                original ^ 1,
            ),
        )


def test_fixed_token_offset_relabeling_is_rejected() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="fixed_column_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_token_link", "bundle_offset", 0, 13),
        )


def test_fixed_header_and_cover_scalar_mutations_are_rejected() -> None:
    instance = _instance()
    with pytest.raises(StructuralError, match="identity_failed"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_bundle_byte", "value", 0, ord("X")),
        )
    cover_row = 127
    with pytest.raises(StructuralError, match="identity_failed|lookup_multiset_mismatch"):
        evaluate_program(
            instance.program,
            _mutate(instance, "claim_source_scalar", "sequence_byte_7", cover_row, 1),
        )


def test_npi_luhn_quotient_mutation_is_rejected() -> None:
    instance = _instance()
    original = instance.traces["claim_source_scalar"].columns[
        "npi_luhn_quotient"
    ][0]
    with pytest.raises(StructuralError, match="npi_luhn_check_digit"):
        evaluate_program(
            instance.program,
            _mutate(
                instance,
                "claim_source_scalar",
                "npi_luhn_quotient",
                0,
                original + 1,
            ),
        )
