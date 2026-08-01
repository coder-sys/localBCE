from __future__ import annotations

import json

import pytest

from experiments.fixed_shape_claim_air.executable_air import (
    M31,
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    boolean,
    cell,
    const,
    evaluate_program,
    evaluate_serialized,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


def test_nonboolean_selector_cannot_gate_a_constraint() -> None:
    trace = TraceTable("t", freeze_columns({"selector": (2,), "value": (0,)}))
    program = AirProgram(
        "selector-attack",
        (AirTable("t", ("selector", "value"), 1, (Identity("selector_boolean", boolean(cell("selector")), 0, 1),)),),
    )
    with pytest.raises(StructuralError, match="air_identity_failed:t:selector_boolean:0"):
        evaluate_program(program, {"t": trace})


def test_serialized_program_cannot_drop_a_table() -> None:
    trace = TraceTable("t", freeze_columns({"x": (0,)}))
    program = AirProgram("table-set-attack", (AirTable("t", ("x",), 1, (Identity("zero", cell("x"), 0, 1),)),))
    document = json.loads(program.canonical_bytes())
    document["tables"] = []
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(StructuralError, match="air_serialized_program_invalid"):
        evaluate_serialized(encoded, {"t": trace})


def test_next_row_reference_is_forbidden_in_local_identity() -> None:
    with pytest.raises(StructuralError, match="air_next_cell_outside_transition"):
        Identity("hidden_transition", cell("x", 1) - cell("x"), 0, 1, "local")


def test_serialized_degree_declaration_cannot_lie() -> None:
    trace = TraceTable("t", freeze_columns({"x": (0,)}))
    program = AirProgram(
        "degree-attack",
        (AirTable("t", ("x",), 1, (Identity("zero", cell("x"), 0, 1),)),),
    )
    document = json.loads(program.canonical_bytes())
    document["tables"][0]["identities"][0]["degree"] = 0
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(StructuralError, match="air_serialized_identity_invalid"):
        evaluate_serialized(encoded, {"t": trace})


def test_serialized_unknown_fields_are_not_ignored() -> None:
    trace = TraceTable("t", freeze_columns({"x": (0,)}))
    program = AirProgram(
        "unknown-field-attack",
        (AirTable("t", ("x",), 1, (Identity("zero", cell("x"), 0, 1),)),),
    )
    document = json.loads(program.canonical_bytes())
    document["tables"][0]["ignored_security_flag"] = True
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(StructuralError, match="air_serialized_table_invalid"):
        evaluate_serialized(encoded, {"t": trace})


def test_field_negative_lookup_weight_cannot_cancel_messages() -> None:
    source = TraceTable("source", freeze_columns({"value": (7,)}))
    destination = TraceTable(
        "destination", freeze_columns({"value": (7,), "weight": (M31 - 1,)})
    )
    lookup = LookupArgument(
        "negative-weight",
        (LookupSide("source", const(1), (cell("value"),), 0, 1),),
        (
            LookupSide(
                "destination",
                const(1),
                (cell("value"),),
                0,
                1,
                cell("weight"),
            ),
        ),
    )
    program = AirProgram(
        "negative-weight-attack",
        (
            AirTable("source", ("value",), 1, ()),
            AirTable("destination", ("value", "weight"), 1, ()),
        ),
        (lookup,),
    )
    with pytest.raises(StructuralError, match="air_lookup_weight_out_of_range"):
        evaluate_program(program, {"source": source, "destination": destination})
    with pytest.raises(StructuralError, match="air_lookup_weight_out_of_range"):
        evaluate_serialized(
            program.canonical_bytes(),
            {"source": source, "destination": destination},
        )


def test_duplicate_lookup_names_are_rejected() -> None:
    table = AirTable("t", ("x",), 1, ())
    lookup = LookupArgument(
        "duplicate", (LookupSide("t", const(1), (cell("x"),), 0, 1),),
        (LookupSide("t", const(1), (cell("x"),), 0, 1),),
    )
    with pytest.raises(StructuralError, match="air_program_duplicate_lookup"):
        AirProgram("duplicate-lookup-attack", (table,), (lookup, lookup))


def test_public_input_omission_reordering_and_mutation_fail_closed() -> None:
    trace = TraceTable("public", freeze_columns({"value": (17, 23)}))
    program = AirProgram(
        "public-input-attack",
        (AirTable("public", ("value",), 2, ()),),
        public_inputs=(
            PublicInputBinding("first", "public", "value", 0),
            PublicInputBinding("second", "public", "value", 1),
        ),
    )
    for supplied in (None, (23, 17), (17, 24), (17,)):
        with pytest.raises(StructuralError, match="air_public_input"):
            evaluate_program(program, {"public": trace}, supplied)
        with pytest.raises(StructuralError, match="air_public_input"):
            evaluate_serialized(program.canonical_bytes(), {"public": trace}, supplied)
