"""Executable AIR fragment for the fixed-shape state-root relation.

The fragment constrains every old/new slot, links the canonical snapshot bytes
to real SHA3-512 executable AIR, and exposes only the two wide state roots as
ordered public bytes.  It is deliberately a composable H4 prerequisite, not a
claim that the current native coordinator has already admitted the fragment.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.state_plane import (
    ENTRY_WIDTH,
    SHA3_512_LENGTH,
    StateEntry,
    StateSnapshot,
    StateTransitionProof,
    independently_verify_state_transition,
)

from .application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_executable_air,
)
from .air_composition import AirFragment, merge_air_fragments
from .executable_air import (
    AirProgram,
    AirTable,
    FixedColumnRuns,
    Identity,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    cell,
    const,
    freeze_columns,
    namespace_air_program,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-PQ512-STATE-ROOT-AIR-v1"
MAX_STATE_AIR_CAPACITY: Final[int] = 4_096
_ROOT_DOMAIN: Final[bytes] = b"BL/PQ512/STATE-PLANE/ROOT/v1\x00"


@dataclass(frozen=True, slots=True)
class StatePlaneAirInstance:
    """One fixed-shape state-root AIR instance and its private traces."""

    program: AirProgram
    traces: Mapping[str, TraceTable]
    proof: StateTransitionProof
    public_values: tuple[int, ...]
    call_messages: tuple[bytes, bytes]

    def __post_init__(self) -> None:
        if not isinstance(self.program, AirProgram):
            raise StructuralError("state_air_program_invalid")
        if set(self.traces) != {table.name for table in self.program.tables}:
            raise StructuralError("state_air_trace_set_invalid")
        if type(self.proof) is not StateTransitionProof:
            raise StructuralError("state_air_proof_invalid")
        if type(self.public_values) is not tuple or any(
            type(value) is not int or not 0 <= value < (1 << 31) - 1
            for value in self.public_values
        ):
            raise StructuralError("state_air_public_values_invalid")
        if type(self.call_messages) is not tuple or len(self.call_messages) != 2:
            raise StructuralError("state_air_call_messages_invalid")

    @property
    def public_root_values(self) -> tuple[int, ...]:
        return self.public_values


def _root_message(snapshot: StateSnapshot) -> bytes:
    encoded = snapshot.encoded
    return _ROOT_DOMAIN + len(encoded).to_bytes(4, "big") + encoded


def _entry(snapshot: StateSnapshot, index: int) -> StateEntry:
    for entry in snapshot.entries:
        if entry.index == index:
            return entry
    return StateEntry.empty(index)


def _slot_column(phase: str, field: str, byte: int | None = None) -> str:
    if byte is None:
        return f"{phase}_{field}"
    return f"{phase}_{field}_{byte}"


def _slot_trace_columns(proof: StateTransitionProof) -> dict[str, tuple[int, ...]]:
    columns: dict[str, list[int]] = {
        _slot_column(phase, field): []
        for phase in ("before", "after")
        for field in ("present",)
    }
    for phase in ("before", "after"):
        for field in ("key", "value"):
            for byte in range(SHA3_512_LENGTH):
                columns[_slot_column(phase, field, byte)] = []
    for index in range(proof.before.capacity):
        for phase, snapshot in (("before", proof.before), ("after", proof.after)):
            entry = _entry(snapshot, index)
            columns[_slot_column(phase, "present")].append(int(entry.present))
            for field, value in (("key", entry.key), ("value", entry.value)):
                for byte, item in enumerate(value):
                    columns[_slot_column(phase, field, byte)].append(item)
    return {name: tuple(values) for name, values in columns.items()}


def _slot_table_and_trace(proof: StateTransitionProof) -> tuple[AirTable, TraceTable]:
    columns = _slot_trace_columns(proof)
    identities: list[Identity] = []
    for phase in ("before", "after"):
        present = cell(_slot_column(phase, "present"))
        identities.append(
            Identity(
                f"{phase}_present_boolean",
                present * (present - 1),
                0,
                proof.before.capacity,
            )
        )
        for field in ("key", "value"):
            for byte in range(SHA3_512_LENGTH):
                identities.append(
                    Identity(
                        f"{phase}_empty_{field}_{byte}_zero",
                        (1 - present) * cell(_slot_column(phase, field, byte)),
                        0,
                        proof.before.capacity,
                    )
                )
    trace = TraceTable("state_slots", freeze_columns(columns))
    table = AirTable(
        "state_slots",
        tuple(trace.columns),
        proof.before.capacity,
        tuple(identities),
    )
    return table, trace


def _snapshot_header_length(snapshot: StateSnapshot) -> int:
    return len(snapshot.encoded) - snapshot.capacity * ENTRY_WIDTH


def _encoding_layout(
    proof: StateTransitionProof,
    messages: tuple[bytes, bytes],
) -> tuple[dict[str, tuple[int, ...]], tuple[tuple[int, int, int, int], ...]]:
    call_indices: list[int] = []
    positions: list[int] = []
    values: list[int] = []
    is_constant: list[int] = []
    constant_values: list[int] = []
    dynamic_slots: list[tuple[int, int, int, int]] = []
    snapshots = (proof.before, proof.after)
    for call_index, (snapshot, message) in enumerate(zip(snapshots, messages, strict=True)):
        snapshot_header = _snapshot_header_length(snapshot)
        message_prefix = len(_ROOT_DOMAIN) + 4
        for position, value in enumerate(message):
            call_indices.append(call_index)
            positions.append(position)
            values.append(value)
            snapshot_position = position - message_prefix
            slot_position = snapshot_position - snapshot_header
            if slot_position < 0 or slot_position >= snapshot.capacity * ENTRY_WIDTH:
                is_constant.append(1)
                constant_values.append(value)
                continue
            slot_index, entry_offset = divmod(slot_position, ENTRY_WIDTH)
            if entry_offset in range(1, 9):
                is_constant.append(1)
                constant_values.append(value)
                continue
            is_constant.append(0)
            constant_values.append(0)
            dynamic_slots.append((call_index, position, slot_index, entry_offset))
    return (
        {
            "call_index": tuple(call_indices),
            "position": tuple(positions),
            "value": tuple(values),
            "is_constant": tuple(is_constant),
            "constant_value": tuple(constant_values),
        },
        tuple(dynamic_slots),
    )


def _encoding_table_and_trace(
    proof: StateTransitionProof,
    messages: tuple[bytes, bytes],
) -> tuple[AirTable, TraceTable, tuple[tuple[int, int, int, int], ...]]:
    columns, dynamic_slots = _encoding_layout(proof, messages)
    rows = len(columns["value"])
    identities = (
        Identity(
            "constant_bytes_are_frozen",
            cell("is_constant") * (cell("value") - cell("constant_value")),
            0,
            rows,
        ),
    )
    trace = TraceTable("state_snapshot_encoding", freeze_columns(columns))
    table = AirTable(
        "state_snapshot_encoding",
        tuple(trace.columns),
        rows,
        identities,
        MappingProxyType(
            {
                "call_index": FixedColumnRuns(
                    ((0, len(messages[0])), (1, len(messages[1])))
                ),
                "position": tuple(
                    position
                    for message in messages
                    for position in range(len(message))
                ),
                "is_constant": columns["is_constant"],
                "constant_value": columns["constant_value"],
            }
        ),
    )
    return table, trace, dynamic_slots


def _root_table_and_trace(proof: StateTransitionProof) -> tuple[AirTable, TraceTable]:
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


def _dynamic_slot_lookup(
    proof: StateTransitionProof,
    dynamic_slots: tuple[tuple[int, int, int, int], ...],
) -> LookupArgument:
    sources: list[LookupSide] = []
    destinations: list[LookupSide] = []
    for call_index, position, slot_index, entry_offset in dynamic_slots:
        phase = "before" if call_index == 0 else "after"
        if entry_offset == 0:
            expression = cell(_slot_column(phase, "present"))
        elif entry_offset < 73:
            expression = cell(_slot_column(phase, "key", entry_offset - 9))
        else:
            expression = cell(_slot_column(phase, "value", entry_offset - 73))
        sources.append(
            LookupSide(
                "state_slots",
                const(1),
                (const(position), expression),
                slot_index,
                slot_index + 1,
            )
        )
        row = (
            len(_root_message(proof.before)) + position
            if call_index == 1
            else position
        )
        destinations.append(
            LookupSide(
                "state_snapshot_encoding",
                const(1),
                (cell("position"), cell("value")),
                row,
                row + 1,
            )
        )
    return LookupArgument(
        "state_slots_to_snapshot_encoding",
        tuple(sources),
        tuple(destinations),
    )


def _encoding_to_sha3_lookup(
    messages: tuple[bytes, bytes], sha3_message_rows: int
) -> LookupArgument:
    return LookupArgument(
        "state_snapshot_encoding_to_sha3",
        (
            LookupSide(
                "state_snapshot_encoding",
                const(1),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                sum(len(message) for message in messages),
            ),
        ),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                sha3_message_rows,
            ),
        ),
    )


def _root_digest_lookup(call_index: int) -> LookupArgument:
    return LookupArgument(
        f"state_root_digest_{call_index}",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                tuple(cell(f"value_{byte}") for byte in range(SHA3_512_LENGTH)),
                call_index,
                call_index + 1,
            ),
        ),
        (
            LookupSide(
                "state_roots",
                const(1),
                tuple(cell(f"root_{byte}") for byte in range(SHA3_512_LENGTH)),
                call_index,
                call_index + 1,
            ),
        ),
    )


def build_state_plane_air(proof: StateTransitionProof) -> StatePlaneAirInstance:
    """Build the state-slot/root AIR for one bounded transition witness."""

    if type(proof) is not StateTransitionProof:
        raise StructuralError("state_air_proof_type_invalid")
    if proof.before.capacity > MAX_STATE_AIR_CAPACITY:
        raise StructuralError("state_air_capacity_exceeds_h4_bound")
    independently_verify_state_transition(proof)
    messages = (_root_message(proof.before), _root_message(proof.after))
    sha3 = build_application_sha3_executable_air(
        tuple(
            Sha3Call(f"state_root_{index}", message, len(message))
            for index, message in enumerate(messages)
        )
    )
    slot_table, slot_trace = _slot_table_and_trace(proof)
    encoding_table, encoding_trace, dynamic_slots = _encoding_table_and_trace(
        proof, messages
    )
    root_table, root_trace = _root_table_and_trace(proof)
    public_inputs = tuple(
        PublicInputBinding(
            f"state_root_{phase}_{byte}",
            "state_roots",
            f"root_{byte}",
            phase,
        )
        for phase in range(2)
        for byte in range(SHA3_512_LENGTH)
    )
    program = AirProgram(
        PROGRAM_ID,
        (slot_table, encoding_table, root_table, *sha3.program.tables),
        (
            *sha3.program.lookups,
            _dynamic_slot_lookup(proof, dynamic_slots),
            _encoding_to_sha3_lookup(
                messages, sha3.traces["sha3_message_batch"].rows
            ),
            _root_digest_lookup(0),
            _root_digest_lookup(1),
        ),
        public_inputs,
    )
    traces = MappingProxyType(
        {
            slot_trace.name: slot_trace,
            encoding_trace.name: encoding_trace,
            root_trace.name: root_trace,
            **sha3.traces,
        }
    )
    public_values = tuple(
        value
        for root in (proof.before.root_512, proof.after.root_512)
        for value in root
    )
    return StatePlaneAirInstance(program, traces, proof, public_values, messages)


def compose_state_plane_air(
    base_program: AirProgram,
    base_traces: Mapping[str, TraceTable],
    base_public_values: tuple[int, ...],
    proof: StateTransitionProof,
) -> tuple[AirProgram, Mapping[str, TraceTable], tuple[int, ...]]:
    """Namespace and merge the state AIR into one executable AIR instance.

    The caller still owns the selected prover, public-coin transcript, and
    parent/receipt binding.  This helper only guarantees that the state
    constraints are present in the same encoded AIR execution as the caller's
    existing relation.
    """

    if not isinstance(base_program, AirProgram) or not isinstance(base_traces, Mapping):
        raise StructuralError("state_air_base_instance_invalid")
    if type(base_public_values) is not tuple or any(
        type(value) is not int or not 0 <= value < (1 << 31) - 1
        for value in base_public_values
    ):
        raise StructuralError("state_air_base_public_values_invalid")
    state = build_state_plane_air(proof)
    namespaced = namespace_air_program(state.program, state.traces, "state_plane")
    merged = merge_air_fragments(
        f"{base_program.program_id}/WITH-STATE",
        (
            AirFragment(base_program, base_traces),
            AirFragment(namespaced.program, namespaced.traces),
        ),
    )
    return (
        merged.program,
        merged.traces,
        (*base_public_values, *state.public_values),
    )


__all__ = (
    "MAX_STATE_AIR_CAPACITY",
    "PROGRAM_ID",
    "StatePlaneAirInstance",
    "build_state_plane_air",
    "compose_state_plane_air",
)
