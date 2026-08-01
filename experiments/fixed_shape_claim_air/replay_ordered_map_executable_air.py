"""Insert-only replay registry using the shared depth-64 ordered-map AIR.

This replaces the bespoke header-plus-open-inner-path split.  Replay now uses
the same reviewed full-key predecessor, allocator, multiproof, and hash-port
machinery as economic state, with an additional all-operations-must-insert
constraint.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Iterable, Mapping, Sequence

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
    build_application_sha3_interface_program,
)
from .executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    namespace_air_program,
)
from .ordered_map_batch_executable_air import (
    OrderedMapBatchAirInstance,
    build_ordered_map_batch_executable_air,
)
from .ordered_map_batch_reference import (
    build_ordered_map_batch_schedule,
    build_ordered_map_batch_witness,
)
from .ordered_map_reference import MAX_512, ZERO_512, OrderedMapBuilder
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-REPLAY-ORDERED-MAP-AIR-v1"
REPLAY_MAP_DOMAIN: Final[bytes] = b"R"
REPLAY_PRESENT_MARKER: Final[bytes] = sha3_512(
    b"BL/PQ512/WAVE1A/REPLAY-PRESENT/v1"
).digest()
_NAMESPACE: Final[str] = "replay_map"


@dataclass(frozen=True, slots=True)
class ReplayOrderedMapAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    ordered_map: OrderedMapBatchAirInstance
    nullifiers: tuple[bytes, ...]
    application_sha3: ApplicationSha3AirInstance | None = None
    call_index_offset: int = 0
    replay_paths_constrained: bool = True
    replay_insert_only_constrained: bool = True
    hashes_constrained: bool = False
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        if self.hashes_constrained and not {
            "sha3_message_batch",
            "sha3_digest_batch",
        }.issubset(self.traces):
            raise StructuralError("replay_ordered_map_false_hash_claim")
        if self.hashes_constrained and self.application_sha3 is None:
            raise StructuralError("replay_ordered_map_false_hash_claim")
        if self.hash_ports_constrained and (
            not self.sha3_interface_only
            or self.hashes_constrained
            or self.application_sha3 is None
            or not {
                "replay_ordered_map_sha3_message_binding",
                "replay_ordered_map_sha3_digest_binding",
            }.issubset(lookup.name for lookup in self.program.lookups)
        ):
            raise StructuralError("replay_ordered_map_false_hash_claim")


def _key(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or value in {ZERO_512, MAX_512}:
        raise StructuralError("replay_ordered_map_nullifier_invalid")
    return value


def build_replay_ordered_map_executable_air(
    existing_nullifiers: Iterable[bytes],
    new_nullifiers: Sequence[bytes],
    *,
    compose_sha3: bool = False,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> ReplayOrderedMapAirInstance:
    if type(compose_sha3) is not bool:
        raise StructuralError("replay_ordered_map_compose_sha3_invalid")
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("replay_ordered_map_call_offset_invalid")
    existing = tuple(_key(value) for value in existing_nullifiers)
    additions = tuple(_key(value) for value in new_nullifiers)
    if not additions:
        raise StructuralError("replay_ordered_map_additions_required")
    if len(set(existing)) != len(existing) or len(set((*existing, *additions))) != len(
        existing
    ) + len(additions):
        raise StructuralError("replay_ordered_map_duplicate_nullifier")

    builder = OrderedMapBuilder(
        REPLAY_MAP_DOMAIN,
        ((value, REPLAY_PRESENT_MARKER) for value in existing),
    )
    before = builder.snapshot()
    transitions = []
    for value in additions:
        transition = builder.prove_upsert(value, REPLAY_PRESENT_MARKER)
        if transition.mode != "insert":
            raise StructuralError("replay_ordered_map_update_forbidden")
        builder.apply(transition)
        transitions.append(transition)
    witness = build_ordered_map_batch_witness(before, builder.snapshot(), tuple(transitions))
    schedule = build_ordered_map_batch_schedule(len(additions))
    ordered_map = build_ordered_map_batch_executable_air(witness, schedule)
    namespaced = namespace_air_program(
        ordered_map.program,
        ordered_map.traces,
        _NAMESPACE,
    )
    operation_name = namespaced.table_names["ordered_map_operation"]
    tables: list[AirTable] = []
    for table in namespaced.program.tables:
        if table.name != operation_name:
            tables.append(table)
            continue
        tables.append(
            AirTable(
                table.name,
                table.columns,
                table.rows,
                (
                    *table.identities,
                    Identity("replay_insert_only", cell("is_insert") - 1, 0, table.rows),
                    *(
                        Identity(
                            f"replay_present_marker_{byte}",
                            cell(f"value_after_{byte}") - REPLAY_PRESENT_MARKER[byte],
                            0,
                            table.rows,
                        )
                        for byte in range(64)
                    ),
                ),
                table.fixed_columns,
            )
        )
    application_sha3 = None
    lookups = list(namespaced.program.lookups)
    traces = dict(namespaced.traces)
    if compose_sha3:
        calls = tuple(
            Sha3Call(
                f"replay_map_hash_{call.ordinal}",
                call.message,
                len(call.message),
            )
            for call in ordered_map.hash_calls
        )
        application_sha3 = (
            build_application_sha3_interface_air(calls)
            if interface_only
            else build_application_sha3_executable_air(calls)
        )
        hash_port = namespaced.table_names["ordered_map_hash_port"]
        message_sources: list[LookupSide] = []
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
                    hash_port,
                    const(1),
                    (
                        cell("call_index") + call_index_offset,
                        const(position),
                        cell(f"message_{position}"),
                    ),
                    row_start,
                    row_stop,
                )
                for position in range(message_length)
            )
        lookups.extend(
            (
                *application_sha3.program.lookups,
                LookupArgument(
                    "replay_ordered_map_sha3_message_binding",
                    tuple(message_sources),
                    (
                        LookupSide(
                            "sha3_message_batch",
                            cell("live"),
                            (cell("call_index"), cell("position"), cell("value")),
                            0,
                            application_sha3.traces["sha3_message_batch"].rows,
                        ),
                    ),
                ),
                LookupArgument(
                    "replay_ordered_map_sha3_digest_binding",
                    (
                        LookupSide(
                            hash_port,
                            const(1),
                            (
                                cell("call_index") + call_index_offset,
                                *(cell(f"digest_{index}") for index in range(64)),
                            ),
                            0,
                            schedule.sha3_call_rows,
                        ),
                    ),
                    (
                        LookupSide(
                            "sha3_digest_batch",
                            const(1),
                            (
                                cell("call_index"),
                                *(cell(f"value_{index}") for index in range(64)),
                            ),
                            0,
                            application_sha3.traces["sha3_digest_batch"].rows,
                        ),
                    ),
                ),
            )
        )
        tables.extend(application_sha3.program.tables)
        traces.update(application_sha3.traces)
    return ReplayOrderedMapAirInstance(
        AirProgram(PROGRAM_ID, tuple(tables), tuple(lookups)),
        MappingProxyType(traces),
        ordered_map,
        additions,
        application_sha3,
        call_index_offset,
        hashes_constrained=compose_sha3 and not interface_only,
        hash_ports_constrained=compose_sha3 and interface_only,
        sha3_interface_only=compose_sha3 and interface_only,
    )


def build_replay_ordered_map_sha3_interface_program(
    instance: ReplayOrderedMapAirInstance,
    *,
    call_index_offset: int,
) -> tuple[AirProgram, tuple[int, ...]]:
    """Attach verifier-only SHA ports without allocating the replay hash witness."""

    if (
        not isinstance(instance, ReplayOrderedMapAirInstance)
        or instance.application_sha3 is not None
        or instance.hashes_constrained
        or instance.hash_ports_constrained
        or type(call_index_offset) is not int
        or call_index_offset < 0
    ):
        raise StructuralError("replay_ordered_map_interface_program_input_invalid")
    capacities = tuple(len(call.message) for call in instance.ordered_map.hash_calls)
    interface = build_application_sha3_interface_program(capacities)
    schedule = instance.ordered_map.schedule
    hash_port = f"{_NAMESPACE}__ordered_map_hash_port"
    message_sources: list[LookupSide] = []
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
                hash_port,
                const(1),
                (
                    cell("call_index") + call_index_offset,
                    const(position),
                    cell(f"message_{position}"),
                ),
                row_start,
                row_stop,
            )
            for position in range(message_length)
        )
    bindings = (
        LookupArgument(
            "replay_ordered_map_sha3_message_binding",
            tuple(message_sources),
            (
                LookupSide(
                    "sha3_message_batch",
                    cell("live"),
                    (cell("call_index"), cell("position"), cell("value")),
                    0,
                    interface.tables[0].rows,
                ),
            ),
        ),
        LookupArgument(
            "replay_ordered_map_sha3_digest_binding",
            (
                LookupSide(
                    hash_port,
                    const(1),
                    (
                        cell("call_index") + call_index_offset,
                        *(cell(f"digest_{index}") for index in range(64)),
                    ),
                    0,
                    schedule.sha3_call_rows,
                ),
            ),
            (
                LookupSide(
                    "sha3_digest_batch",
                    const(1),
                    (
                        cell("call_index"),
                        *(cell(f"value_{index}") for index in range(64)),
                    ),
                    0,
                    interface.tables[1].rows,
                ),
            ),
        ),
    )
    return (
        AirProgram(
            PROGRAM_ID,
            (*instance.program.tables, *interface.tables),
            (*instance.program.lookups, *interface.lookups, *bindings),
        ),
        capacities,
    )


__all__ = [
    "ReplayOrderedMapAirInstance",
    "build_replay_ordered_map_executable_air",
    "build_replay_ordered_map_sha3_interface_program",
]
