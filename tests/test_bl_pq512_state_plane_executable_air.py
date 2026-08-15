from __future__ import annotations

from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    boolean,
    cell,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.air_binary_ir import (
    encode_air_execution,
)
from experiments.fixed_shape_claim_air.executable_air import (
    evaluate_program,
    evaluate_serialized,
)
from experiments.fixed_shape_claim_air.state_plane_executable_air import (
    PROGRAM_ID,
    build_state_plane_air,
    compose_state_plane_air,
)
from tests.test_bl_pq512_state_plane import _proof


def _base_air_fixture() -> tuple[AirProgram, dict[str, TraceTable]]:
    """Small local base relation for the state-composition property."""

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
    return AirProgram(
        "BL-STATE-PLANE-BASE-TEST-v1",
        (source_table, destination_table),
        (lookup,),
    ), {"source": source, "destination": destination}


def test_state_plane_air_constrains_slots_sha3_roots_and_public_order() -> None:
    proof = _proof()
    instance = build_state_plane_air(proof)
    direct = evaluate_program(instance.program, instance.traces, instance.public_values)
    serialized = evaluate_serialized(
        instance.program.canonical_bytes(), instance.traces, instance.public_values
    )
    assert instance.program.program_id == PROGRAM_ID
    assert direct == serialized
    assert direct.identities_evaluated > proof.before.capacity
    assert direct.lookup_messages_evaluated >= len(instance.call_messages)
    assert instance.public_values == tuple(
        value
        for root in (proof.before.root_512, proof.after.root_512)
        for value in root
    )
    assert encode_air_execution(
        instance.program, instance.traces, instance.public_values
    )


def test_state_plane_air_composes_into_one_ordered_execution() -> None:
    base_program, base_traces = _base_air_fixture()
    program, traces, public_values = compose_state_plane_air(
        base_program, base_traces, (), _proof()
    )
    report = evaluate_program(program, traces, public_values)
    assert report.identities_evaluated > 0
    assert program.program_id.endswith("/WITH-STATE")
    assert any(
        binding.name.startswith("state_plane__state_root_")
        for binding in program.public_inputs
    )
