"""Compact executable AIR for the private state-transition relation.

The full state-root AIR also contains the Boolean SHA3 traces.  H4 already
proves those exact root calls on the authenticated shared hash bus, so putting
the SHA3 traces into a second FRI proof would duplicate the dominant work and
break the laptop resource gate.  This fragment proves the remaining relation:
every old/new slot is the corresponding operation, empty slots carry no
private bytes, and the two public roots are the roots consumed by H4's state
hash calls.

The state-root hash relation and this compact transition relation are joined
by the versioned state-binding envelope and the H4 parent/transcript receipt.
The operation table is linked algebraically to fixed-capacity before/after
snapshot tables with typed multiset lookups.  The native verifier also
compares the decoded packed trace columns with the exact state operations in
that envelope; the AIR proof is never admitted on public-root equality alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.state_plane import (
    SHA3_512_LENGTH,
    StateEntry,
    StateSnapshot,
    StateTransitionProof,
    independently_verify_state_transition,
)
from experiments.fixed_shape_claim_air.executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-PQ512-STATE-RELATION-AIR-v2"
MAX_STATE_AIR_CAPACITY: Final[int] = 4_096
PACKED_CHUNK_BYTES: Final[int] = 3
PACKED_CHUNK_COUNT: Final[int] = (
    SHA3_512_LENGTH + PACKED_CHUNK_BYTES - 1
) // PACKED_CHUNK_BYTES


@dataclass(frozen=True, slots=True)
class StateRelationAirInstance:
    """One compact state relation and its private witness traces."""

    program: AirProgram
    traces: Mapping[str, TraceTable]
    proof: StateTransitionProof
    public_values: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.program, AirProgram):
            raise StructuralError("state_relation_air_program_invalid")
        if set(self.traces) != {table.name for table in self.program.tables}:
            raise StructuralError("state_relation_air_trace_set_invalid")
        if type(self.proof) is not StateTransitionProof:
            raise StructuralError("state_relation_air_proof_invalid")
        if type(self.public_values) is not tuple or any(
            type(value) is not int or not 0 <= value < (1 << 31) - 1
            for value in self.public_values
        ):
            raise StructuralError("state_relation_air_public_values_invalid")


def _column(phase: str, field: str, chunk: int | None = None) -> str:
    return f"{phase}_{field}" if chunk is None else f"{phase}_{field}_{chunk}"


def _pack(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + PACKED_CHUNK_BYTES], "big")


def _entry_columns(
    rows: tuple[tuple[int, StateEntry, StateEntry], ...],
) -> dict[str, tuple[int, ...]]:
    columns: dict[str, list[int]] = {"index": []}
    for phase in ("before", "after"):
        columns[_column(phase, "present")] = []
        for field in ("key", "value"):
            for chunk in range(PACKED_CHUNK_COUNT):
                columns[_column(phase, field, chunk)] = []
    for index, before, after in rows:
        columns["index"].append(index)
        for phase, entry in (("before", before), ("after", after)):
            columns[_column(phase, "present")].append(int(entry.present))
            for field, value in (("key", entry.key), ("value", entry.value)):
                for chunk in range(PACKED_CHUNK_COUNT):
                    columns[_column(phase, field, chunk)].append(
                        _pack(value, chunk * PACKED_CHUNK_BYTES)
                    )
    return {name: tuple(values) for name, values in columns.items()}


def _entry_identities(capacity: int, table_label: str) -> tuple[Identity, ...]:
    identities: list[Identity] = []
    for phase in ("before", "after"):
        present = cell(_column(phase, "present"))
        identities.append(
            Identity(
                f"{table_label}_{phase}_present_boolean",
                present * (present - 1),
                0,
                capacity,
            )
        )
        for field in ("key", "value"):
            for chunk in range(PACKED_CHUNK_COUNT):
                identities.append(
                    Identity(
                        f"{table_label}_{phase}_empty_{field}_{chunk}_zero",
                        (1 - present) * cell(_column(phase, field, chunk)),
                        0,
                        capacity,
                    )
                )
    return tuple(identities)


def _entry_table(
    name: str,
    rows: tuple[tuple[int, StateEntry, StateEntry], ...],
) -> tuple[AirTable, TraceTable]:
    capacity = len(rows)
    columns = _entry_columns(rows)
    trace = TraceTable(name, freeze_columns(columns))
    table = AirTable(
        name,
        tuple(trace.columns),
        capacity,
        _entry_identities(capacity, name),
        MappingProxyType({"index": tuple(range(capacity))}),
    )
    return table, trace


def _snapshot_table(
    name: str,
    snapshot: StateSnapshot,
) -> tuple[AirTable, TraceTable]:
    """Expose every fixed slot so operation rows cannot hide a state mismatch."""

    columns: dict[str, list[int]] = {"index": []}
    columns["present"] = []
    for field in ("key", "value"):
        for chunk in range(PACKED_CHUNK_COUNT):
            columns[f"{field}_{chunk}"] = []
    for index in range(snapshot.capacity):
        entry = snapshot._slot(index)
        columns["index"].append(index)
        columns["present"].append(int(entry.present))
        for field, value in (("key", entry.key), ("value", entry.value)):
            for chunk in range(PACKED_CHUNK_COUNT):
                columns[f"{field}_{chunk}"].append(
                    _pack(value, chunk * PACKED_CHUNK_BYTES)
                )
    frozen = freeze_columns(
        {name: tuple(values) for name, values in columns.items()}
    )
    trace = TraceTable(name, frozen)
    present = cell("present")
    identities: list[Identity] = [
        Identity(
            f"{name}_present_boolean",
            present * (present - 1),
            0,
            snapshot.capacity,
        )
    ]
    for field in ("key", "value"):
        for chunk in range(PACKED_CHUNK_COUNT):
            identities.append(
                Identity(
                    f"{name}_empty_{field}_{chunk}_zero",
                    (1 - present) * cell(f"{field}_{chunk}"),
                    0,
                    snapshot.capacity,
                )
            )
    table = AirTable(
        name,
        tuple(trace.columns),
        snapshot.capacity,
        tuple(identities),
        MappingProxyType({"index": tuple(range(snapshot.capacity))}),
    )
    return table, trace


def _relation_entry_values(phase: str) -> tuple[object, ...]:
    return (
        cell("index"),
        cell(_column(phase, "present")),
        *(
            cell(_column(phase, field, chunk))
            for field in ("key", "value")
            for chunk in range(PACKED_CHUNK_COUNT)
        ),
    )


def _snapshot_entry_values() -> tuple[object, ...]:
    return (
        cell("index"),
        cell("present"),
        *(
            cell(f"{field}_{chunk}")
            for field in ("key", "value")
            for chunk in range(PACKED_CHUNK_COUNT)
        ),
    )


def _operation_snapshot_lookup(
    phase: str,
    snapshot_name: str,
    capacity: int,
) -> LookupArgument:
    """Bind one operation phase to the exact fixed snapshot slot multiset."""

    return LookupArgument(
        f"state_relation_{phase}_snapshot",
        (
            LookupSide(
                "state_relation",
                const(1),
                _relation_entry_values(phase),
                0,
                capacity,
            ),
        ),
        (
            LookupSide(
                snapshot_name,
                const(1),
                _snapshot_entry_values(),
                0,
                capacity,
            ),
        ),
    )


def _root_call_lookup() -> LookupArgument:
    return LookupArgument(
        "state_root_call_order",
        (
            LookupSide(
                "state_roots",
                const(1),
                (cell("call_index"),),
                0,
                2,
            ),
        ),
        (
            LookupSide(
                "state_roots",
                const(1),
                (cell("call_index"),),
                0,
                2,
            ),
        ),
    )


def _roots_table(proof: StateTransitionProof) -> tuple[AirTable, TraceTable]:
    columns = {
        "call_index": (0, 1),
        **{
            f"root_{byte}": (
                proof.before.root_512[byte],
                proof.after.root_512[byte],
            )
            for byte in range(SHA3_512_LENGTH)
        },
    }
    trace = TraceTable("state_roots", freeze_columns(columns))
    table = AirTable(
        "state_roots",
        tuple(trace.columns),
        2,
        (),
        MappingProxyType({"call_index": (0, 1)}),
    )
    return table, trace


def build_state_relation_air(proof: StateTransitionProof) -> StateRelationAirInstance:
    """Build the non-hash portion of the state relation for proof composition."""

    if type(proof) is not StateTransitionProof:
        raise StructuralError("state_relation_air_proof_type_invalid")
    if proof.before.capacity > MAX_STATE_AIR_CAPACITY:
        raise StructuralError("state_relation_air_capacity_exceeds_h4_bound")
    independently_verify_state_transition(proof)
    capacity = proof.before.capacity
    operation_rows = tuple(
        (operation.index, operation.before, operation.after)
        for operation in proof.operations
    )
    relation_table, relation_trace = _entry_table(
        "state_relation", operation_rows
    )
    before_table, before_trace = _snapshot_table(
        "state_before_snapshot", proof.before
    )
    after_table, after_trace = _snapshot_table(
        "state_after_snapshot", proof.after
    )
    roots_table, roots_trace = _roots_table(proof)
    public_inputs = tuple(
        PublicInputBinding(
            f"state_relation_root_{phase}_{byte}",
            "state_roots",
            f"root_{byte}",
            phase,
        )
        for phase in range(2)
        for byte in range(SHA3_512_LENGTH)
    )
    program = AirProgram(
        PROGRAM_ID,
        (relation_table, before_table, after_table, roots_table),
        (
            _operation_snapshot_lookup(
                "before", "state_before_snapshot", capacity
            ),
            _operation_snapshot_lookup(
                "after", "state_after_snapshot", capacity
            ),
            _root_call_lookup(),
        ),
        public_inputs,
    )
    traces = MappingProxyType(
        {
            relation_trace.name: relation_trace,
            before_trace.name: before_trace,
            after_trace.name: after_trace,
            roots_trace.name: roots_trace,
        }
    )
    public_values = tuple(
        value
        for root in (proof.before.root_512, proof.after.root_512)
        for value in root
    )
    return StateRelationAirInstance(program, traces, proof, public_values)


__all__ = (
    "MAX_STATE_AIR_CAPACITY",
    "PACKED_CHUNK_BYTES",
    "PACKED_CHUNK_COUNT",
    "PROGRAM_ID",
    "StateRelationAirInstance",
    "build_state_relation_air",
)
