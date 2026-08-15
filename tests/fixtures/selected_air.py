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


def selected_air_fixture() -> tuple[AirProgram, dict[str, TraceTable]]:
    """Return the bounded relation needed by selected-parameter KATs.

    This is a test-local current-owner fixture, not the retired Wave1A test
    suite or a proof backend.  Its stable program identity preserves the
    selected-parameter commitment exercised by the remaining KATs.
    """

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
        "BL-WAVE1A-AIR-TEST-v1",
        (source_table, destination_table),
        (lookup,),
    ), {"source": source, "destination": destination}
