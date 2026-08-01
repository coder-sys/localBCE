from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    boolean,
    cell,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
    namespace_air_program,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


def _fixture() -> tuple[AirProgram, dict[str, TraceTable]]:
    rows = 4
    source = TraceTable(
        "source",
        freeze_columns(
            {
                "live": (1, 1, 0, 0),
                "value": (0, 1, 2, 3),
                "acc": (0, 0, 1, 1),
            }
        ),
    )
    destination = TraceTable(
        "destination",
        freeze_columns({"live": (1, 1, 0, 0), "value": (0, 1, 2, 3)}),
    )
    source_table = AirTable(
        "source",
        ("live", "value", "acc"),
        rows,
        (
            Identity("live_boolean", boolean(cell("live")), 0, rows),
            Identity("acc_first", cell("acc"), 0, 1, "boundary"),
            Identity(
                "acc_transition",
                cell("acc", 1) - cell("acc") - cell("live") * cell("value"),
                0,
                rows - 1,
                "transition",
            ),
            Identity("acc_last", cell("acc") - 1, rows - 1, rows, "boundary"),
        ),
    )
    destination_table = AirTable(
        "destination",
        ("live", "value"),
        rows,
        (Identity("live_boolean", boolean(cell("live")), 0, rows),),
    )
    lookup = LookupArgument(
        "typed_values",
        (LookupSide("source", cell("live"), (cell("value"),), 0, rows),),
        (LookupSide("destination", cell("live"), (cell("value"),), 0, rows),),
    )
    return AirProgram("BL-WAVE1A-AIR-TEST-v1", (source_table, destination_table), (lookup,)), {
        "source": source,
        "destination": destination,
    }


def test_direct_and_serialized_evaluators_agree() -> None:
    program, traces = _fixture()
    direct = evaluate_program(program, traces)
    serialized = evaluate_serialized(program.canonical_bytes(), traces)
    assert direct == serialized
    assert direct.identities_evaluated == 13
    assert direct.lookup_messages_evaluated == 4
    assert direct.maximum_degree == 2


def test_constraint_degree_is_derived_from_expression_tree() -> None:
    program, _ = _fixture()
    assert program.maximum_degree == 2
    assert program.tables[0].identities[0].expression.degree == 2


def test_mutated_transition_is_rejected_by_both_evaluators() -> None:
    program, traces = _fixture()
    bad = dict(traces)
    bad["source"] = TraceTable(
        "source",
        freeze_columns({"live": (1, 1, 0, 0), "value": (0, 1, 2, 3), "acc": (0, 0, 0, 1)}),
    )
    with pytest.raises(StructuralError, match="air_identity_failed:source:acc_transition:1"):
        evaluate_program(program, bad)
    with pytest.raises(StructuralError, match="air_identity_failed:source:acc_transition:1"):
        evaluate_serialized(program.canonical_bytes(), bad)


def test_lookup_multiplicity_mutation_is_rejected() -> None:
    program, traces = _fixture()
    bad = dict(traces)
    bad["destination"] = TraceTable(
        "destination",
        freeze_columns({"live": (1, 1, 0, 0), "value": (0, 0, 2, 3)}),
    )
    with pytest.raises(StructuralError, match="air_lookup_multiset_mismatch:typed_values"):
        evaluate_program(program, bad)


def test_program_commitment_binds_constraint_expression() -> None:
    program, _ = _fixture()
    table = program.tables[0]
    altered_identity = replace(table.identities[-1], expression=cell("acc") - 2)
    altered_table = replace(table, identities=table.identities[:-1] + (altered_identity,))
    altered = replace(program, tables=(altered_table, program.tables[1]))
    assert program.commitment() != altered.commitment()


def test_ordered_public_input_cells_are_bound_by_both_evaluators() -> None:
    trace = TraceTable("public", freeze_columns({"value": (17, 23)}))
    program = AirProgram(
        "public-input-test",
        (AirTable("public", ("value",), 2, ()),),
        public_inputs=(
            PublicInputBinding("first", "public", "value", 0),
            PublicInputBinding("second", "public", "value", 1),
        ),
    )
    direct = evaluate_program(program, {"public": trace}, (17, 23))
    serialized = evaluate_serialized(
        program.canonical_bytes(), {"public": trace}, (17, 23)
    )
    assert direct == serialized


def test_air_namespace_preserves_semantics_in_both_evaluators() -> None:
    program, traces = _fixture()
    original = evaluate_program(program, traces)
    namespaced = namespace_air_program(program, traces, "benefit")

    direct = evaluate_program(namespaced.program, namespaced.traces)
    serialized = evaluate_serialized(
        namespaced.program.canonical_bytes(), namespaced.traces
    )

    assert direct == serialized
    assert direct.identities_evaluated == original.identities_evaluated
    assert direct.lookup_messages_evaluated == original.lookup_messages_evaluated
    assert direct.maximum_degree == original.maximum_degree
    assert direct.program_commitment != original.program_commitment
    assert direct.trace_commitment != original.trace_commitment
    assert namespaced.table_names == {
        "source": "benefit__source",
        "destination": "benefit__destination",
    }


@pytest.mark.parametrize("namespace", ("", "Benefit", "1benefit", "benefit-map", "a" * 33))
def test_air_namespace_rejects_noncanonical_names(namespace: str) -> None:
    program, traces = _fixture()
    with pytest.raises(StructuralError, match="air_namespace_invalid"):
        namespace_air_program(program, traces, namespace)


def test_air_namespace_rejects_mismatched_trace_set() -> None:
    program, traces = _fixture()
    incomplete = dict(traces)
    del incomplete["destination"]
    with pytest.raises(StructuralError, match="air_trace_table_set_mismatch"):
        namespace_air_program(program, incomplete, "benefit")
