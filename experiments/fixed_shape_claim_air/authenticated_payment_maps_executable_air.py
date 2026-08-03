"""Executable composition of the three authenticated payment-map batches.

This layer proves that the benefit, obligation, and private-ledger endpoint
states are the outputs of their ordered-map AIRs.  It shares one physical byte
table across all lanes.  Payment-specific key/value derivations and SHA3 ports
remain explicit open boundaries and are never reported as constrained here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
    build_application_sha3_interface_program,
)
from .authenticated_payment_maps_reference import (
    AuthenticatedPaymentMapBatchTransition,
)
from .executable_air import (
    AirProgram,
    AirTable,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    freeze_columns,
    namespace_air_program,
)
from .ordered_map_batch_executable_air import (
    OrderedMapBatchAirInstance,
    build_ordered_map_batch_executable_air,
)
from .ordered_map_batch_reference import (
    OrderedMapBatchSchedule,
    OrderedMapHashCall,
    build_ordered_map_batch_schedule,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-AUTHENTICATED-PAYMENT-MAPS-AIR-v1"
COMPOSED_PROGRAM_ID: Final[str] = (
    "BL-WAVE1A-AUTHENTICATED-PAYMENT-MAPS-SHA3-AIR-v1"
)
_LANES: Final[tuple[str, ...]] = ("benefit", "obligation", "ledger")
_SHARED_BYTE_TABLE: Final[str] = "payment_maps_byte_shared"
_RANGE_LOOKUP: Final[str] = "ordered_map_byte_range"


@dataclass(frozen=True, slots=True)
class AuthenticatedPaymentMapsAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    transition: AuthenticatedPaymentMapBatchTransition
    schedules: Mapping[str, OrderedMapBatchSchedule]
    hash_calls: Mapping[str, tuple[OrderedMapHashCall, ...]]
    application_sha3: ApplicationSha3AirInstance | None = None
    call_index_offset: int = 0
    hashes_constrained: bool = False
    payment_semantics_constrained: bool = False
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        if self.payment_semantics_constrained:
            raise StructuralError("payment_maps_air_false_completion_claim")
        lookup_names = {lookup.name for lookup in self.program.lookups}
        if self.hashes_constrained and (
            self.program.program_id != COMPOSED_PROGRAM_ID
            or self.application_sha3 is None
            or not {
                "payment_maps_sha3_message_binding",
                "payment_maps_sha3_digest_binding",
            }.issubset(lookup_names)
        ):
            raise StructuralError("payment_maps_air_false_completion_claim")
        if self.sha3_interface_only and self.hashes_constrained:
            raise StructuralError("payment_maps_air_false_completion_claim")
        if self.hash_ports_constrained and (
            self.application_sha3 is None
            or not self.sha3_interface_only
            or not {
                "payment_maps_sha3_message_binding",
                "payment_maps_sha3_digest_binding",
            }.issubset(lookup_names)
        ):
            raise StructuralError("payment_maps_air_false_completion_claim")
        table_names = {table.name for table in self.program.tables}
        composed = self.hashes_constrained or self.hash_ports_constrained
        if (
            self.program.program_id
            != (COMPOSED_PROGRAM_ID if composed else PROGRAM_ID)
            or _SHARED_BYTE_TABLE not in table_names
            or any(f"{lane}__ordered_map_byte" in table_names for lane in _LANES)
        ):
            raise StructuralError("payment_maps_air_composition_invalid")


def _lane_state_table(
    lanes: Mapping[str, OrderedMapBatchAirInstance],
) -> tuple[AirTable, TraceTable, LookupArgument]:
    columns: dict[str, list[int]] = {
        "lane": [],
        "map_domain": [],
        "cursor_before": [],
        "cursor_after": [],
    }
    for prefix in ("inner_root_before", "inner_root_after", "root_before", "root_after"):
        for index in range(64):
            columns[f"{prefix}_{index}"] = []
    for lane_index, lane in enumerate(_LANES):
        trace = lanes[lane].traces["ordered_map_state"].columns
        columns["lane"].append(lane_index)
        for name in columns:
            if name != "lane":
                columns[name].append(trace[name][0])
    frozen = freeze_columns(columns)
    trace = TraceTable("payment_map_lane_state", frozen)
    table = AirTable(
        trace.name,
        tuple(trace.columns),
        len(_LANES),
        (),
        MappingProxyType(
            {
                "lane": tuple(range(len(_LANES))),
                "map_domain": tuple(columns["map_domain"]),
            }
        ),
    )
    values = (
        cell("lane"),
        cell("map_domain"),
        cell("cursor_before"),
        cell("cursor_after"),
        *(
            cell(f"{prefix}_{index}")
            for prefix in ("inner_root_before", "inner_root_after", "root_before", "root_after")
            for index in range(64)
        ),
    )
    sources = tuple(
        LookupSide(
            f"{lane}__ordered_map_state",
            const(1),
            (
                const(lane_index),
                cell("map_domain"),
                cell("cursor_before"),
                cell("cursor_after"),
                *(
                    cell(f"{prefix}_{index}")
                    for prefix in (
                        "inner_root_before",
                        "inner_root_after",
                        "root_before",
                        "root_after",
                    )
                    for index in range(64)
                ),
            ),
            0,
            1,
        )
        for lane_index, lane in enumerate(_LANES)
    )
    lookup = LookupArgument(
        "payment_map_lane_state_binding",
        sources,
        (LookupSide(trace.name, const(1), values, 0, len(_LANES)),),
    )
    return table, trace, lookup


def _shared_byte_table(
    lanes: Mapping[str, OrderedMapBatchAirInstance],
) -> tuple[AirTable, TraceTable]:
    multiplicity: Counter[int] = Counter()
    for lane in _LANES:
        columns = lanes[lane].traces["ordered_map_byte"].columns
        for value in range(256):
            multiplicity[value] += columns["multiplicity"][value]
    values = tuple(range(256))
    columns = freeze_columns(
        {
            "value": values,
            "multiplicity": tuple(multiplicity[value] for value in values),
        }
    )
    trace = TraceTable(_SHARED_BYTE_TABLE, columns)
    table = AirTable(
        trace.name,
        tuple(trace.columns),
        256,
        (),
        MappingProxyType(
            {
                "value": values,
            }
        ),
    )
    return table, trace


def build_authenticated_payment_maps_executable_air(
    transition: AuthenticatedPaymentMapBatchTransition,
    *,
    shard_index_bits: int = 24,
    compose_sha3: bool = False,
    interface_only: bool = False,
    call_index_offset: int = 0,
) -> AuthenticatedPaymentMapsAirInstance:
    if not isinstance(transition, AuthenticatedPaymentMapBatchTransition):
        raise StructuralError("payment_maps_air_transition_required")
    if type(compose_sha3) is not bool:
        raise StructuralError("payment_maps_air_compose_sha3_invalid")
    if type(interface_only) is not bool:
        raise StructuralError("payment_maps_air_interface_flag_invalid")
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("payment_maps_air_call_offset_invalid")
    witnesses = {
        "benefit": transition.benefit_batch_witness,
        "obligation": transition.obligation_batch_witness,
        "ledger": transition.ledger_batch_witness,
    }
    lanes: dict[str, OrderedMapBatchAirInstance] = {}
    schedules: dict[str, OrderedMapBatchSchedule] = {}
    for lane in _LANES:
        schedule = build_ordered_map_batch_schedule(
            len(witnesses[lane].operations),
            shard_index_bits=shard_index_bits,
        )
        schedules[lane] = schedule
        lanes[lane] = build_ordered_map_batch_executable_air(
            witnesses[lane], schedule
        )

    tables: list[AirTable] = []
    traces: dict[str, TraceTable] = {}
    lookups: list[LookupArgument] = []
    range_sources: list[LookupSide] = []
    for lane in _LANES:
        namespaced = namespace_air_program(
            lanes[lane].program, lanes[lane].traces, lane
        )
        byte_table = namespaced.table_names["ordered_map_byte"]
        tables.extend(table for table in namespaced.program.tables if table.name != byte_table)
        traces.update(
            (name, trace)
            for name, trace in namespaced.traces.items()
            if name != byte_table
        )
        for lookup in namespaced.program.lookups:
            if lookup.name == f"{lane}__{_RANGE_LOOKUP}":
                range_sources.extend(lookup.sources)
            else:
                lookups.append(lookup)

    shared_table, shared_trace = _shared_byte_table(lanes)
    tables.append(shared_table)
    traces[shared_trace.name] = shared_trace
    lookups.extend(
        (
            LookupArgument(
                "payment_maps_byte_range_shared",
                tuple(range_sources),
                (
                    LookupSide(
                        _SHARED_BYTE_TABLE,
                        const(1),
                        (cell("value"),),
                        0,
                        256,
                        cell("multiplicity"),
                    ),
                ),
            ),
        )
    )
    state_table, state_trace, state_lookup = _lane_state_table(lanes)
    tables.append(state_table)
    traces[state_trace.name] = state_trace
    lookups.append(state_lookup)

    hash_calls = MappingProxyType(
        {lane: lanes[lane].hash_calls for lane in _LANES}
    )
    if not compose_sha3:
        return AuthenticatedPaymentMapsAirInstance(
            AirProgram(PROGRAM_ID, tuple(tables), tuple(lookups)),
            MappingProxyType(traces),
            transition,
            MappingProxyType(schedules),
            hash_calls,
            call_index_offset=call_index_offset,
        )

    calls: list[Sha3Call] = []
    message_sources: list[LookupSide] = []
    digest_sources: list[LookupSide] = []
    call_offset = call_index_offset
    for lane in _LANES:
        schedule = schedules[lane]
        lane_calls = hash_calls[lane]
        calls.extend(
            Sha3Call(
                f"payment_map_{lane}_{call.ordinal}",
                call.message,
                len(call.message),
            )
            for call in lane_calls
        )
        family_ranges = (
            (0, schedule.leaf_hash_rows, 212),
            (
                schedule.leaf_hash_rows,
                schedule.leaf_hash_rows + schedule.node_hash_rows,
                141,
            ),
            (
                schedule.leaf_hash_rows + schedule.node_hash_rows,
                schedule.sha3_call_rows,
                84,
            ),
        )
        for row_start, row_stop, message_length in family_ranges:
            message_sources.extend(
                LookupSide(
                    f"{lane}__ordered_map_hash_port",
                    const(1),
                    (
                        cell("call_index") + call_offset,
                        const(position),
                        cell(f"message_{position}"),
                    ),
                    row_start,
                    row_stop,
                )
                for position in range(message_length)
            )
        digest_sources.append(
            LookupSide(
                f"{lane}__ordered_map_hash_port",
                const(1),
                (
                    cell("call_index") + call_offset,
                    *(cell(f"digest_{index}") for index in range(64)),
                ),
                0,
                schedule.sha3_call_rows,
            )
        )
        call_offset += schedule.sha3_call_rows
    sha3 = (
        build_application_sha3_interface_air(tuple(calls))
        if interface_only
        else build_application_sha3_executable_air(tuple(calls))
    )
    hash_lookups = (
        LookupArgument(
            "payment_maps_sha3_message_binding",
            tuple(message_sources),
            (
                LookupSide(
                    "sha3_message_batch",
                    cell("live"),
                    (cell("call_index"), cell("position"), cell("value")),
                    0,
                    sha3.traces["sha3_message_batch"].rows,
                ),
            ),
        ),
        LookupArgument(
            "payment_maps_sha3_digest_binding",
            tuple(digest_sources),
            (
                LookupSide(
                    "sha3_digest_batch",
                    const(1),
                    (
                        cell("call_index"),
                        *(cell(f"value_{index}") for index in range(64)),
                    ),
                    0,
                    sha3.traces["sha3_digest_batch"].rows,
                ),
            ),
        ),
    )
    return AuthenticatedPaymentMapsAirInstance(
        AirProgram(
            COMPOSED_PROGRAM_ID,
            (*tables, *sha3.program.tables),
            (*lookups, *sha3.program.lookups, *hash_lookups),
        ),
        MappingProxyType({**traces, **dict(sha3.traces)}),
        transition,
        MappingProxyType(schedules),
        hash_calls,
        sha3,
        call_index_offset,
        hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


def build_authenticated_payment_maps_sha3_interface_program(
    instance: AuthenticatedPaymentMapsAirInstance,
    *,
    call_index_offset: int,
) -> tuple[AirProgram, tuple[int, ...]]:
    """Attach verifier-only SHA ports to an uncomposed payment-map relation."""

    if (
        not isinstance(instance, AuthenticatedPaymentMapsAirInstance)
        or instance.application_sha3 is not None
        or instance.hashes_constrained
        or instance.hash_ports_constrained
        or type(call_index_offset) is not int
        or call_index_offset < 0
    ):
        raise StructuralError("payment_maps_interface_program_input_invalid")
    capacities = tuple(
        len(call.message)
        for lane in _LANES
        for call in instance.hash_calls[lane]
    )
    interface = build_application_sha3_interface_program(capacities)
    message_rows = interface.tables[0].rows
    digest_rows = interface.tables[1].rows
    calls: list[Sha3Call] = []
    message_sources: list[LookupSide] = []
    digest_sources: list[LookupSide] = []
    call_offset = call_index_offset
    for lane in _LANES:
        schedule = instance.schedules[lane]
        lane_calls = instance.hash_calls[lane]
        calls.extend(
            Sha3Call(
                f"payment_map_{lane}_{call.ordinal}",
                call.message,
                len(call.message),
            )
            for call in lane_calls
        )
        for row_start, row_stop, message_length in (
            (0, schedule.leaf_hash_rows, 212),
            (
                schedule.leaf_hash_rows,
                schedule.leaf_hash_rows + schedule.node_hash_rows,
                141,
            ),
            (
                schedule.leaf_hash_rows + schedule.node_hash_rows,
                schedule.sha3_call_rows,
                84,
            ),
        ):
            message_sources.extend(
                LookupSide(
                    f"{lane}__ordered_map_hash_port",
                    const(1),
                    (
                        cell("call_index") + call_offset,
                        const(position),
                        cell(f"message_{position}"),
                    ),
                    row_start,
                    row_stop,
                )
                for position in range(message_length)
            )
        digest_sources.append(
            LookupSide(
                f"{lane}__ordered_map_hash_port",
                const(1),
                (
                    cell("call_index") + call_offset,
                    *(cell(f"digest_{index}") for index in range(64)),
                ),
                0,
                schedule.sha3_call_rows,
            )
        )
        call_offset += schedule.sha3_call_rows
    if tuple(call.capacity for call in calls) != capacities:
        raise StructuralError("payment_maps_interface_program_schedule_mismatch")
    bindings = (
        LookupArgument(
            "payment_maps_sha3_message_binding",
            tuple(message_sources),
            (
                LookupSide(
                    "sha3_message_batch",
                    cell("live"),
                    (cell("call_index"), cell("position"), cell("value")),
                    0,
                    message_rows,
                ),
            ),
        ),
        LookupArgument(
            "payment_maps_sha3_digest_binding",
            tuple(digest_sources),
            (
                LookupSide(
                    "sha3_digest_batch",
                    const(1),
                    (
                        cell("call_index"),
                        *(cell(f"value_{index}") for index in range(64)),
                    ),
                    0,
                    digest_rows,
                ),
            ),
        ),
    )
    return (
        AirProgram(
            COMPOSED_PROGRAM_ID,
            (*instance.program.tables, *interface.tables),
            (*instance.program.lookups, *interface.lookups, *bindings),
        ),
        capacities,
    )


__all__ = [
    "AuthenticatedPaymentMapsAirInstance",
    "COMPOSED_PROGRAM_ID",
    "build_authenticated_payment_maps_executable_air",
    "build_authenticated_payment_maps_sha3_interface_program",
]
