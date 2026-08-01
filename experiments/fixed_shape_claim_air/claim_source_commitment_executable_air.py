"""Exact SHA3 composition for the reversible claim-source commitment tree."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.claim_source_commitment import (
    ClaimSourceCommitments,
    _node_preimage,
    _root_preimage,
)

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
)
from .claim_source_arrays_executable_air import (
    ClaimSourceArraysAirInstance,
    build_claim_source_arrays_executable_air,
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
from .semantics import ClaimSlot, StructuralError


PROGRAM_ID = "BL-WAVE1A-CLAIM-SOURCE-COMMITMENT-SHA3-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimSourceCommitmentAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    source: ClaimSourceArraysAirInstance
    sha3: ApplicationSha3AirInstance
    call_index_offset: int
    source_hashes_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        tables = {table.name for table in self.program.tables}
        lookups = {lookup.name for lookup in self.program.lookups}
        if (not self.source_hashes_constrained and not self.hash_ports_constrained) or not {
            "claim_source_hash_edge_byte",
            "claim_source_hash_prefix_byte",
            "claim_source_hash_root",
        }.issubset(tables) or not {
            "claim_source_hash_leaf_messages",
            "claim_source_hash_edges_match_digests",
            "claim_source_hash_inner_messages",
            "claim_source_hash_root_digest",
        }.issubset(lookups):
            raise StructuralError("claim_source_hash_false_completion_claim")
        if self.sha3_interface_only != self.hash_ports_constrained or (
            self.sha3_interface_only and self.source_hashes_constrained
        ):
            raise StructuralError("claim_source_hash_false_completion_claim")


def _build(
    profile,
    source,
    *,
    bundles: tuple[bytes, ...],
    commitments: ClaimSourceCommitments,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> ClaimSourceCommitmentAirInstance:
    slots = profile.claim_slots
    if (
        len(bundles) != slots
        or len(commitments.leaf_digests) != slots
        or type(call_index_offset) is not int
        or call_index_offset < 0
    ):
        raise StructuralError("claim_source_hash_geometry_invalid")
    calls: list[Sha3Call] = [
        Sha3Call(f"claim_source_leaf_{index}", bundle, len(bundle))
        for index, bundle in enumerate(bundles)
    ]
    current = list(zip(commitments.leaf_digests, range(slots), strict=True))
    edge_rows: list[tuple[int, int, int, int, int]] = []
    prefix_rows: list[tuple[int, int, int]] = []
    ordinal = slots
    for height in range(profile.claim_source_tree_depth):
        next_level: list[tuple[bytes, int]] = []
        for position in range(0, len(current), 2):
            left, left_call = current[position]
            right, right_call = current[position + 1]
            message = _node_preimage(
                profile.profile_id,
                child_height=height,
                position=position // 2,
                left=left,
                right=right,
            )
            calls.append(Sha3Call(f"claim_source_node_{ordinal}", message, len(message)))
            for byte_index in range(64):
                edge_rows.append((call_index_offset + left_call, call_index_offset + ordinal, 12 + byte_index, byte_index, left[byte_index]))
                edge_rows.append((call_index_offset + right_call, call_index_offset + ordinal, 76 + byte_index, byte_index, right[byte_index]))
            prefix_rows.extend((call_index_offset + ordinal, index, value) for index, value in enumerate(message[:12]))
            next_level.append((commitments.levels[height + 1][position // 2], ordinal))
            ordinal += 1
        current = next_level
    if len(current) != 1:
        raise StructuralError("claim_source_hash_tree_not_reduced")
    top, top_call = current[0]
    root_message = _root_preimage(
        profile.profile_id,
        tree_height=profile.claim_source_tree_depth,
        claim_slots=slots,
        top=top,
    )
    root_call = ordinal
    calls.append(Sha3Call("claim_source_root", root_message, len(root_message)))
    prefix_rows.extend((call_index_offset + root_call, index, value) for index, value in enumerate(root_message[:12]))
    edge_rows.extend(
        (
            call_index_offset + top_call,
            call_index_offset + root_call,
            12 + byte_index,
            byte_index,
            top[byte_index],
        )
        for byte_index in range(64)
    )
    sha3 = (
        build_application_sha3_interface_air(tuple(calls))
        if interface_only
        else build_application_sha3_executable_air(tuple(calls))
    )

    edge_columns = freeze_columns(
        {
            "child_call": tuple(row[0] for row in edge_rows),
            "parent_call": tuple(row[1] for row in edge_rows),
            "message_position": tuple(row[2] for row in edge_rows),
            "byte_index": tuple(row[3] for row in edge_rows),
            "value": tuple(row[4] for row in edge_rows),
        }
    )
    edge_trace = TraceTable("claim_source_hash_edge_byte", edge_columns)
    edge_table = AirTable(
        edge_trace.name,
        tuple(edge_columns),
        edge_trace.rows,
        (),
        MappingProxyType(
            {
                name: edge_columns[name]
                for name in ("child_call", "parent_call", "message_position", "byte_index")
            }
        ),
    )
    prefix_columns = freeze_columns(
        {
            "call_index": tuple(row[0] for row in prefix_rows),
            "message_position": tuple(row[1] for row in prefix_rows),
            "value": tuple(row[2] for row in prefix_rows),
        }
    )
    prefix_trace = TraceTable("claim_source_hash_prefix_byte", prefix_columns)
    prefix_table = AirTable(
        prefix_trace.name,
        tuple(prefix_columns),
        prefix_trace.rows,
        (),
        MappingProxyType(prefix_columns),
    )
    root_columns = freeze_columns(
        {"row": (0,), **{f"value_{index}": (value,) for index, value in enumerate(commitments.root)}}
    )
    root_trace = TraceTable("claim_source_hash_root", root_columns)
    root_table = AirTable(root_trace.name, tuple(root_columns), 1, (), MappingProxyType({"row": (0,)}))

    leaf_stop = sha3.call_rows[f"claim_source_leaf_{slots - 1}"].message_stop
    leaf_messages = LookupArgument(
        "claim_source_hash_leaf_messages",
        (
            LookupSide(
                "claim_source_bundle_byte",
                const(1),
                (
                    cell("slot_index") + call_index_offset,
                    cell("byte_index"),
                    cell("value"),
                ),
                0,
                source.traces["claim_source_bundle_byte"].rows,
            ),
        ),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                leaf_stop,
            ),
        ),
    )
    edge_digests = LookupArgument(
        "claim_source_hash_edges_match_digests",
        (
            LookupSide(
                "sha3_digest_byte_batch",
                const(1),
                (cell("call_index"), cell("byte_index"), cell("value")),
                0,
                root_call * 64,
            ),
        ),
        (
            LookupSide(
                edge_table.name,
                const(1),
                (cell("child_call"), cell("byte_index"), cell("value")),
                0,
                edge_trace.rows,
            ),
        ),
    )
    inner_start = sha3.call_rows[f"claim_source_node_{slots}"].message_start
    inner_messages = LookupArgument(
        "claim_source_hash_inner_messages",
        (
            LookupSide(
                prefix_table.name,
                const(1),
                (cell("call_index"), cell("message_position"), cell("value")),
                0,
                prefix_trace.rows,
            ),
            LookupSide(
                edge_table.name,
                const(1),
                (cell("parent_call"), cell("message_position"), cell("value")),
                0,
                edge_trace.rows,
            ),
        ),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                inner_start,
                sha3.traces["sha3_message_batch"].rows,
            ),
        ),
    )
    root_digest = LookupArgument(
        "claim_source_hash_root_digest",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (*(cell(f"value_{index}") for index in range(64)),),
                root_call,
                root_call + 1,
            ),
        ),
        (
            LookupSide(
                root_table.name,
                const(1),
                (*(cell(f"value_{index}") for index in range(64)),),
                0,
                1,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (*source.program.tables, edge_table, prefix_table, root_table, *sha3.program.tables),
        (
            *source.program.lookups,
            *sha3.program.lookups,
            leaf_messages,
            edge_digests,
            inner_messages,
            root_digest,
        ),
    )
    return ClaimSourceCommitmentAirInstance(
        program,
        MappingProxyType(
            {
                **dict(source.traces),
                edge_trace.name: edge_trace,
                prefix_trace.name: prefix_trace,
                root_trace.name: root_trace,
                **dict(sha3.traces),
            }
        ),
        source,
        sha3,
        call_index_offset,
        source_hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


def build_claim_source_commitment_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> ClaimSourceCommitmentAirInstance:
    source = build_claim_source_arrays_executable_air(profile, slots)
    return _build(
        profile,
        source,
        bundles=source.source.bundles,
        commitments=source.source.commitments,
        call_index_offset=call_index_offset,
        interface_only=interface_only,
    )


__all__ = (
    "ClaimSourceCommitmentAirInstance",
    "build_claim_source_commitment_executable_air",
)
