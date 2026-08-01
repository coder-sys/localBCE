"""Executable AIR for deterministic depth-64 replay state headers.

This component constrains the authenticated ``nextAppendIndex`` successor,
binds it to the insertion index, hashes both state headers with exact SHA3-512,
and chains ordered transitions.  Inner predecessor/insertion path hashing is a
separate component so both can share the global SHA3 schedule in composition.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from .application_sha3_executable_air import (
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
)
from .authenticated_replay_state_reference import AuthenticatedReplayTransition
from .executable_air import (
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-REPLAY-HEADER-AIR-v1"
HEADER_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/REPLAY-STATE-HEADER/v1"
HEADER_BYTES: Final[int] = len(HEADER_DOMAIN) + 8 + 64


@dataclass(frozen=True, slots=True)
class ReplayHeaderAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    transitions: tuple[AuthenticatedReplayTransition, ...]


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _bytes(columns: dict[str, list[int]], prefix: str, value: bytes) -> None:
    for index, byte in enumerate(value):
        _append(columns, f"{prefix}_{index}", byte)


def _cursor_witness(before: int, after: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    before_bytes = before.to_bytes(8, "big")
    after_bytes = after.to_bytes(8, "big")
    carries = [0] * 8
    incoming = 1
    for index in range(7, -1, -1):
        total = before_bytes[index] + incoming
        carries[index] = total >> 8
        incoming = carries[index]
    if incoming:
        raise StructuralError("replay_header_cursor_overflow")
    return tuple(after_bytes), tuple(carries)


def build_replay_header_executable_air(
    transitions: Sequence[AuthenticatedReplayTransition],
    *,
    interface_only: bool = False,
) -> ReplayHeaderAirInstance:
    materialized = tuple(transitions)
    if not materialized or any(
        not isinstance(value, AuthenticatedReplayTransition) for value in materialized
    ):
        raise StructuralError("replay_header_transitions_required")

    header_columns: dict[str, list[int]] = {}
    calls: list[Sha3Call] = []
    byte_counts: Counter[int] = Counter()
    encoding_values: list[int] = []
    encoding_call: list[int] = []
    encoding_position: list[int] = []
    encoding_is_constant: list[int] = []
    encoding_constant: list[int] = []

    for index, transition in enumerate(materialized):
        if index and transition.root_before != materialized[index - 1].root_after:
            raise StructuralError("replay_header_root_chain_invalid")
        before = transition.next_append_index_before.to_bytes(8, "big")
        after, carries = _cursor_witness(
            transition.next_append_index_before,
            transition.next_append_index_after,
        )
        inserted = transition.inner.inserted_index.to_bytes(8, "big")
        _append(header_columns, "transition_index", index)
        for prefix, raw in (
            ("cursor_before", before),
            ("cursor_after", bytes(after)),
            ("inserted_index", inserted),
            ("inner_root_before", transition.inner.root_before),
            ("inner_root_after", transition.inner.root_after),
            ("root_before", transition.root_before),
            ("root_after", transition.root_after),
        ):
            _bytes(header_columns, prefix, raw)
            byte_counts.update(raw)
        for byte_index, carry in enumerate(carries):
            _append(header_columns, f"carry_{byte_index}", carry)

        for phase, cursor, inner_root, root in (
            ("before", before, transition.inner.root_before, transition.root_before),
            ("after", bytes(after), transition.inner.root_after, transition.root_after),
        ):
            message = HEADER_DOMAIN + cursor + inner_root
            call_index = len(calls)
            calls.append(Sha3Call(f"replay_{phase}_{index}", message, HEADER_BYTES))
            for position, value in enumerate(message):
                constant = position < len(HEADER_DOMAIN)
                encoding_call.append(call_index)
                encoding_position.append(position)
                encoding_values.append(value)
                encoding_is_constant.append(int(constant))
                encoding_constant.append(value if constant else 0)
            if len(root) != 64:
                raise AssertionError("replay_header_internal_root_width_invalid")

    rows = len(materialized)
    identities: list[Identity] = []
    for byte_index in range(8):
        identities.extend(
            (
                Identity(
                    f"carry_boolean_{byte_index}",
                    boolean(cell(f"carry_{byte_index}")),
                    0,
                    rows,
                ),
                Identity(
                    f"inserted_index_binding_{byte_index}",
                    cell(f"inserted_index_{byte_index}")
                    - cell(f"cursor_before_{byte_index}"),
                    0,
                    rows,
                ),
                Identity(
                    f"cursor_successor_{byte_index}",
                    cell(f"cursor_before_{byte_index}")
                    + (const(1) if byte_index == 7 else cell(f"carry_{byte_index + 1}"))
                    - cell(f"cursor_after_{byte_index}")
                    - 256 * cell(f"carry_{byte_index}"),
                    0,
                    rows,
                ),
            )
        )
    identities.append(Identity("cursor_no_overflow", cell("carry_0"), 0, rows))
    header_trace = TraceTable("replay_header", freeze_columns(header_columns))
    header_table = AirTable(
        "replay_header",
        tuple(header_trace.columns),
        rows,
        tuple(identities),
        MappingProxyType({"transition_index": tuple(range(rows))}),
    )

    encoding_trace = TraceTable(
        "replay_header_encoding",
        freeze_columns(
            {
                "call_index": encoding_call,
                "position": encoding_position,
                "value": encoding_values,
                "is_constant": encoding_is_constant,
                "constant_value": encoding_constant,
            }
        ),
    )
    encoding_table = AirTable(
        "replay_header_encoding",
        tuple(encoding_trace.columns),
        encoding_trace.rows,
        (
            Identity(
                "constant_binding",
                cell("is_constant") * (cell("value") - cell("constant_value")),
                0,
                encoding_trace.rows,
            ),
        ),
        MappingProxyType(
            {
                "call_index": tuple(encoding_call),
                "position": tuple(encoding_position),
                "is_constant": tuple(encoding_is_constant),
                "constant_value": tuple(encoding_constant),
            }
        ),
    )

    if type(interface_only) is not bool:
        raise StructuralError("replay_header_interface_flag_invalid")
    sha3 = (
        build_application_sha3_interface_air(tuple(calls))
        if interface_only
        else build_application_sha3_executable_air(tuple(calls))
    )
    lookups: list[LookupArgument] = [
        *sha3.program.lookups,
        LookupArgument(
            "replay_header_encoding_to_sha3",
            (
                LookupSide(
                    "replay_header_encoding",
                    const(1),
                    (cell("call_index"), cell("position"), cell("value")),
                    0,
                    encoding_trace.rows,
                ),
            ),
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
    ]
    domain_length = len(HEADER_DOMAIN)
    dynamic_sources: list[LookupSide] = []
    dynamic_destinations: list[LookupSide] = []
    for index in range(rows):
        header_row = index
        for phase, cursor_prefix, root_prefix in (
            ("before", "cursor_before", "inner_root_before"),
            ("after", "cursor_after", "inner_root_after"),
        ):
            call_id = f"replay_{phase}_{index}"
            call = sha3.call_rows[call_id]
            encoding_start = (2 * index + int(phase == "after")) * HEADER_BYTES
            for offset, column in (
                *(
                    (domain_length + byte, f"{cursor_prefix}_{byte}")
                    for byte in range(8)
                ),
                *(
                    (domain_length + 8 + byte, f"{root_prefix}_{byte}")
                    for byte in range(64)
                ),
            ):
                dynamic_sources.append(
                    LookupSide(
                        "replay_header",
                        const(1),
                        (const(2 * index + int(phase == "after")), const(offset), cell(column)),
                        header_row,
                        header_row + 1,
                    )
                )
                dynamic_destinations.append(
                    LookupSide(
                        "replay_header_encoding",
                        const(1),
                        (cell("call_index"), cell("position"), cell("value")),
                        encoding_start + offset,
                        encoding_start + offset + 1,
                    )
                )
            lookups.append(
                LookupArgument(
                        f"replay_header_digest_{phase}_{index}",
                        (
                            LookupSide(
                                "sha3_digest_batch",
                                const(1),
                                tuple(cell(f"value_{byte}") for byte in range(64)),
                                call.digest_row,
                                call.digest_row + 1,
                            ),
                        ),
                        (
                            LookupSide(
                                "replay_header",
                                const(1),
                                tuple(cell(f"root_{phase}_{byte}") for byte in range(64)),
                                header_row,
                                header_row + 1,
                            ),
                        ),
                )
            )
    lookups.append(
        LookupArgument(
            "replay_header_dynamic_encoding",
            tuple(dynamic_sources),
            tuple(dynamic_destinations),
        )
    )
    if rows > 1:
        lookups.append(
            LookupArgument(
                "replay_header_ordered_chain",
                (
                    LookupSide(
                        "replay_header",
                        const(1),
                        (
                            *(cell(f"cursor_after_{byte}") for byte in range(8)),
                            *(cell(f"root_after_{byte}") for byte in range(64)),
                        ),
                        0,
                        rows - 1,
                    ),
                ),
                (
                    LookupSide(
                        "replay_header",
                        const(1),
                        (
                            *(cell(f"cursor_before_{byte}") for byte in range(8)),
                            *(cell(f"root_before_{byte}") for byte in range(64)),
                        ),
                        1,
                        rows,
                    ),
                ),
            )
        )

    byte_values = tuple(range(256))
    byte_trace = TraceTable(
        "replay_header_byte",
        freeze_columns(
            {
                "value": byte_values,
                "multiplicity": tuple(byte_counts[value] for value in byte_values),
            }
        ),
    )
    byte_table = AirTable(
        "replay_header_byte",
        tuple(byte_trace.columns),
        256,
        (),
        MappingProxyType({"value": byte_values}),
    )
    byte_sources = tuple(
        LookupSide(
            "replay_header",
            const(1),
            (cell(f"{prefix}_{byte}"),),
            0,
            rows,
        )
        for prefix, width in (
            ("cursor_before", 8),
            ("cursor_after", 8),
            ("inserted_index", 8),
            ("inner_root_before", 64),
            ("inner_root_after", 64),
            ("root_before", 64),
            ("root_after", 64),
        )
        for byte in range(width)
    )
    lookups.append(
        LookupArgument(
            "replay_header_byte_range",
            byte_sources,
            (
                LookupSide(
                    "replay_header_byte",
                    const(1),
                    (cell("value"),),
                    0,
                    256,
                    cell("multiplicity"),
                ),
            ),
        )
    )
    return ReplayHeaderAirInstance(
        AirProgram(
            PROGRAM_ID,
            (*sha3.program.tables, header_table, encoding_table, byte_table),
            tuple(lookups),
        ),
        MappingProxyType(
            {
                **dict(sha3.traces),
                "replay_header": header_trace,
                "replay_header_encoding": encoding_trace,
                "replay_header_byte": byte_trace,
            }
        ),
        materialized,
    )


__all__ = ["ReplayHeaderAirInstance", "build_replay_header_executable_air"]
