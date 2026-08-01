"""Exact hidden master-salt use tag for replay insertion."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from app.batch.pq_suite_candidate import (
    SALT_USE_DOMAIN_CODE,
    SALT_USE_MAGIC,
    SALT_USE_VERSION,
    candidate_salt_use_tag,
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
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-SALT-USE-TAG-SHA3-AIR-v1"
_PREFIX: Final[bytes] = (
    SALT_USE_MAGIC
    + SALT_USE_VERSION.to_bytes(2, "big")
    + SALT_USE_DOMAIN_CODE.to_bytes(2, "big")
    + (64).to_bytes(2, "big")
)


@dataclass(frozen=True, slots=True)
class SaltUseTagAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    sha3: ApplicationSha3AirInstance
    tag_512: bytes
    call_index_offset: int
    tag_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False


def build_salt_use_tag_executable_air(
    raw_master_salt_512: bytes,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> SaltUseTagAirInstance:
    if (
        type(raw_master_salt_512) is not bytes
        or len(raw_master_salt_512) != 64
        or not any(raw_master_salt_512)
    ):
        raise StructuralError("salt_use_tag_master_salt_invalid")
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("salt_use_tag_call_offset_invalid")
    message = _PREFIX + raw_master_salt_512
    tag = candidate_salt_use_tag(raw_master_salt_512)
    calls = (Sha3Call("salt_use_tag", message, len(message)),)
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    columns = freeze_columns(
        {
            "row": (0,),
            **{f"message_{index}": (byte,) for index, byte in enumerate(message)},
            **{f"salt_{index}": (byte,) for index, byte in enumerate(raw_master_salt_512)},
            **{f"tag_{index}": (byte,) for index, byte in enumerate(tag)},
        }
    )
    identities = tuple(
        Identity(
            f"salt_message_{index}",
            cell(f"message_{len(_PREFIX) + index}") - cell(f"salt_{index}"),
            0,
            1,
        )
        for index in range(64)
    )
    trace = TraceTable("salt_use_tag_material", columns)
    table = AirTable(
        trace.name,
        tuple(columns),
        1,
        identities,
        MappingProxyType(
            {
                "row": (0,),
                **{
                    f"message_{index}": (byte,)
                    for index, byte in enumerate(_PREFIX)
                },
            }
        ),
    )
    message_lookup = LookupArgument(
        "salt_use_tag_sha3_message",
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
    digest_lookup = LookupArgument(
        "salt_use_tag_sha3_digest",
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
                (*(cell(f"tag_{index}") for index in range(64)),),
                0,
                1,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (table, *sha3.program.tables),
        (*sha3.program.lookups, message_lookup, digest_lookup),
    )
    return SaltUseTagAirInstance(
        program,
        MappingProxyType({trace.name: trace, **dict(sha3.traces)}),
        sha3,
        tag,
        call_index_offset,
        tag_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = (
    "SaltUseTagAirInstance",
    "build_salt_use_tag_executable_air",
)
