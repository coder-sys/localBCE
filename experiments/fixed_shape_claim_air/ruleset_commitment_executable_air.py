"""Exact executable SHA3 commitment for the immutable profile ruleset."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from experiments.bl_pq512_crypto_foundation.ruleset_commitment import (
    encode_ruleset,
    ruleset_root,
)

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
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
)
from .profile import CalibrationProfile
from .semantics import StructuralError


PROGRAM_ID = "BL-WAVE1A-RULESET-COMMITMENT-SHA3-AIR-v1"


@dataclass(frozen=True, slots=True)
class RulesetCommitmentAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    root: bytes
    call_index_offset: int
    ruleset_hash_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False


def build_ruleset_commitment_executable_air(
    profile: CalibrationProfile,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> RulesetCommitmentAirInstance:
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("ruleset_commitment_call_offset_invalid")
    message = encode_ruleset(profile)
    root = ruleset_root(profile)
    calls = (Sha3Call("ruleset", message, len(message)),)
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    columns = freeze_columns(
        {
            "row": (0,),
            **{f"message_{index}": (value,) for index, value in enumerate(message)},
            **{f"root_{index}": (value,) for index, value in enumerate(root)},
        }
    )
    trace = TraceTable("ruleset_commitment", columns)
    table = AirTable(
        trace.name,
        tuple(columns),
        1,
        (),
        MappingProxyType(
            {
                "row": (0,),
                **{f"message_{index}": (value,) for index, value in enumerate(message)},
            }
        ),
    )
    messages = LookupArgument(
        "ruleset_commitment_sha3_message",
        tuple(
            LookupSide(
                table.name,
                const(1),
                (
                    const(call_index_offset),
                    const(index),
                    cell(f"message_{index}"),
                ),
                0,
                1,
            )
            for index in range(len(message))
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
    )
    digest = LookupArgument(
        "ruleset_commitment_sha3_digest",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (*(cell(f"value_{index}") for index in range(64)),),
                0,
                1,
            ),
        ),
        (
            LookupSide(
                table.name,
                const(1),
                (*(cell(f"root_{index}") for index in range(64)),),
                0,
                1,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (table, *sha3.program.tables),
        (*sha3.program.lookups, messages, digest),
    )
    return RulesetCommitmentAirInstance(
        program,
        MappingProxyType({trace.name: trace, **dict(sha3.traces)}),
        sha3,
        root,
        call_index_offset,
        ruleset_hash_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = (
    "RulesetCommitmentAirInstance",
    "build_ruleset_commitment_executable_air",
)
