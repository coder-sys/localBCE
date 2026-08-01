"""Bind every exact A12 wide nullifier to one insert-only replay operation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable, Mapping

from .a12_nullifier_executable_air import A12NullifierAirInstance
from .air_composition import (
    Sha3ComposedComponent,
    compose_sha3_air_components,
    compose_sha3_interface_components,
)
from .executable_air import AirProgram, LookupArgument, LookupSide, TraceTable, cell, const
from .replay_ordered_map_executable_air import (
    ReplayOrderedMapAirInstance,
    build_replay_ordered_map_executable_air,
)
from .semantics import StructuralError
from .salt_use_tag_executable_air import SaltUseTagAirInstance


PROGRAM_ID: Final[str] = "BL-WAVE1A-A12-REPLAY-COMPOSITION-AIR-v1"


@dataclass(frozen=True, slots=True)
class A12ReplayCompositionAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    a12: A12NullifierAirInstance
    replay: ReplayOrderedMapAirInstance
    salt_use: SaltUseTagAirInstance | None = None
    nullifier_derivations_authenticated: bool = True
    replay_paths_constrained: bool = True
    replay_hashes_constrained: bool = False
    salt_use_constrained: bool = False
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False


def build_a12_replay_composition_executable_air(
    a12: A12NullifierAirInstance,
    existing_nullifiers: Iterable[bytes],
    *,
    compose_sha3: bool = False,
    interface_only: bool = False,
    replay_call_index_offset: int | None = None,
    salt_use: SaltUseTagAirInstance | None = None,
) -> A12ReplayCompositionAirInstance:
    if not isinstance(a12, A12NullifierAirInstance):
        raise StructuralError("a12_replay_a12_instance_required")
    if compose_sha3 is not True:
        raise StructuralError("a12_replay_sha3_composition_required")
    if type(interface_only) is not bool:
        raise StructuralError("a12_replay_interface_flag_invalid")
    if salt_use is not None and not isinstance(salt_use, SaltUseTagAirInstance):
        raise StructuralError("a12_replay_salt_use_instance_invalid")
    a12_call_count = len(a12.sha3.digests)
    salt_call_count = 0 if salt_use is None else len(salt_use.sha3.digests)
    expected_replay_offset = a12_call_count + salt_call_count
    if (
        replay_call_index_offset is not None
        and replay_call_index_offset != expected_replay_offset
    ):
        raise StructuralError("a12_replay_call_offset_invalid")
    if salt_use is not None and salt_use.call_index_offset != a12_call_count:
        raise StructuralError("a12_replay_salt_call_offset_invalid")
    additions = (
        a12.strong_nullifiers
        if salt_use is None
        else (*a12.strong_nullifiers, salt_use.tag_512)
    )
    replay = build_replay_ordered_map_executable_air(
        existing_nullifiers,
        additions,
        compose_sha3=compose_sha3,
        interface_only=interface_only,
        call_index_offset=expected_replay_offset,
    )
    rows = len(a12.strong_nullifiers)
    link = LookupArgument(
        "a12_strong_nullifier_matches_replay_key",
        (
            LookupSide(
                "a12_output",
                const(1),
                (
                    cell("request_index"),
                    *(cell(f"strong_{index}") for index in range(64)),
                ),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "replay_map__ordered_map_operation",
                const(1),
                (
                    cell("operation_index"),
                    *(cell(f"key_{index}") for index in range(64)),
                ),
                0,
                rows,
            ),
        ),
    )
    salt_link = ()
    if salt_use is not None:
        salt_link = (
            LookupArgument(
                "a12_salt_use_tag_matches_replay_key",
                (
                    LookupSide(
                        "salt_use_tag_material",
                        const(1),
                        (
                            const(rows),
                            *(cell(f"tag_{index}") for index in range(64)),
                        ),
                        0,
                        1,
                    ),
                ),
                (
                    LookupSide(
                        "replay_map__ordered_map_operation",
                        const(1),
                        (
                            cell("operation_index"),
                            *(cell(f"key_{index}") for index in range(64)),
                        ),
                        rows,
                        rows + 1,
                    ),
                ),
            ),
        )
    components = [
        Sha3ComposedComponent(a12.program, a12.traces, a12.sha3, 0),
    ]
    if salt_use is not None:
        components.append(
            Sha3ComposedComponent(
                salt_use.program,
                salt_use.traces,
                salt_use.sha3,
                salt_use.call_index_offset,
            )
        )
    assert replay.application_sha3 is not None
    components.append(
        Sha3ComposedComponent(
            replay.program,
            replay.traces,
            replay.application_sha3,
            replay.call_index_offset,
        )
    )
    composer = (
        compose_sha3_interface_components
        if interface_only
        else compose_sha3_air_components
    )
    composed = composer(
        PROGRAM_ID,
        tuple(components),
        extra_lookups=(link, *salt_link),
    )
    return A12ReplayCompositionAirInstance(
        composed.program,
        composed.traces,
        a12,
        replay,
        salt_use,
        replay_hashes_constrained=compose_sha3 and not interface_only,
        salt_use_constrained=salt_use is not None and not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = ["A12ReplayCompositionAirInstance", "build_a12_replay_composition_executable_air"]
