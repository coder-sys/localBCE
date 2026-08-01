"""Exact proof-lane SHA3 composition for packed oracle and policy bundles.

Each proof lane hashes every reversible fixed-width bundle, then hashes the
ordered leaf-digest vector.  The separately signed audit root intentionally
stays outside the proof lane; it reuses the same leaves and is checked through
the dual-PQ authority envelope and independent audit proofs.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    EXECUTION_ROOT_MAGIC as ORACLE_EXECUTION_ROOT_MAGIC,
)
from experiments.bl_pq512_crypto_foundation.policy_bundle_commitment import (
    EXECUTION_ROOT_MAGIC as POLICY_EXECUTION_ROOT_MAGIC,
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
from .oracle_bundle_encoding_executable_air import (
    OracleBundleEncodingAirInstance,
    build_oracle_bundle_encoding_executable_air,
)
from .policy_bundle_encoding_executable_air import (
    PolicyBundleEncodingAirInstance,
    build_policy_bundle_encoding_executable_air,
)
from .profile import CalibrationProfile
from .semantics import ClaimSlot, StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-PACKED-EXECUTION-COMMITMENT-SHA3-AIR-v1"
_PROFILE_CODES: Final[dict[str, int]] = {
    "K128_CALIBRATION": 1,
    "K256_DESIGN_POINT": 2,
    "K512_CALIBRATION": 3,
}


@dataclass(frozen=True, slots=True)
class PackedExecutionCommitmentAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    kind: str
    encoding: OracleBundleEncodingAirInstance | PolicyBundleEncodingAirInstance
    sha3: ApplicationSha3AirInstance
    call_index_offset: int
    execution_hashes_constrained: bool = True
    audit_root_dual_pq_signed: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        table_names = {table.name for table in self.program.tables}
        lookup_names = {lookup.name for lookup in self.program.lookups}
        prefix = f"{self.kind}_execution"
        if (
            self.kind not in {"oracle", "policy"}
            or (not self.execution_hashes_constrained and not self.hash_ports_constrained)
            or not self.audit_root_dual_pq_signed
            or f"{prefix}_root" not in table_names
            or not {
                f"{prefix}_leaf_messages",
                f"{prefix}_root_message",
                f"{prefix}_root_digest",
            }.issubset(lookup_names)
        ):
            raise StructuralError("packed_execution_commitment_false_completion_claim")
        if self.sha3_interface_only != self.hash_ports_constrained or (
            self.sha3_interface_only and self.execution_hashes_constrained
        ):
            raise StructuralError("packed_execution_commitment_false_completion_claim")


def _build(
    profile: CalibrationProfile,
    kind: str,
    encoding: OracleBundleEncodingAirInstance | PolicyBundleEncodingAirInstance,
    *,
    bundle_table: str,
    bundles: tuple[bytes, ...],
    leaves: tuple[bytes, ...],
    execution_root: bytes,
    audit_root: bytes,
    magic: bytes,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> PackedExecutionCommitmentAirInstance:
    if (
        kind not in {"oracle", "policy"}
        or type(call_index_offset) is not int
        or call_index_offset < 0
    ):
        raise StructuralError("packed_execution_commitment_kind_invalid")
    rows = profile.claim_slots
    if len(bundles) != rows or len(leaves) != rows or len(magic) != 8:
        raise StructuralError("packed_execution_commitment_geometry_invalid")
    root_prefix = magic + bytes((_PROFILE_CODES[profile.profile_id],)) + rows.to_bytes(2, "big")
    root_message = root_prefix + b"".join(leaves)
    calls = tuple(
        Sha3Call(f"{kind}_leaf_{index}", bundle, len(bundle))
        for index, bundle in enumerate(bundles)
    ) + (Sha3Call(f"{kind}_execution_root", root_message, len(root_message)),)
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    root_columns = freeze_columns(
        {
            "row": (0,),
            **{f"prefix_{index}": (value,) for index, value in enumerate(root_prefix)},
            **{f"execution_{index}": (value,) for index, value in enumerate(execution_root)},
            **{f"audit_{index}": (value,) for index, value in enumerate(audit_root)},
        }
    )
    root_trace = TraceTable(f"{kind}_execution_root", root_columns)
    root_table = AirTable(
        root_trace.name,
        tuple(root_columns),
        1,
        (),
        MappingProxyType(
            {"row": (0,), **{f"prefix_{index}": (value,) for index, value in enumerate(root_prefix)}}
        ),
    )
    leaf_message_stop = sha3.call_rows[f"{kind}_leaf_{rows - 1}"].message_stop
    root_call = sha3.call_rows[f"{kind}_execution_root"]
    leaf_messages = LookupArgument(
        f"{kind}_execution_leaf_messages",
        (
            LookupSide(
                bundle_table,
                const(1),
                (
                    cell("slot_index") + call_index_offset,
                    cell("byte_index"),
                    cell("value"),
                ),
                0,
                encoding.traces[bundle_table].rows,
            ),
        ),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                0,
                leaf_message_stop,
            ),
        ),
    )
    root_sources = [
        LookupSide(
            root_table.name,
            const(1),
            (
                const(call_index_offset + rows),
                const(index),
                cell(f"prefix_{index}"),
            ),
            0,
            1,
        )
        for index in range(len(root_prefix))
    ]
    for byte_index in range(64):
        root_sources.append(
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (
                    const(call_index_offset + rows),
                    len(root_prefix)
                    + 64 * (cell("call_index") - call_index_offset)
                    + byte_index,
                    cell(f"value_{byte_index}"),
                ),
                0,
                rows,
            )
        )
    root_messages = LookupArgument(
        f"{kind}_execution_root_message",
        tuple(root_sources),
        (
            LookupSide(
                "sha3_message_batch",
                cell("live"),
                (cell("call_index"), cell("position"), cell("value")),
                root_call.message_start,
                root_call.message_stop,
            ),
        ),
    )
    root_digest = LookupArgument(
        f"{kind}_execution_root_digest",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (*(cell(f"value_{index}") for index in range(64)),),
                rows,
                rows + 1,
            ),
        ),
        (
            LookupSide(
                root_table.name,
                const(1),
                (*(cell(f"execution_{index}") for index in range(64)),),
                0,
                1,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID + f"/{kind}",
        (*encoding.program.tables, root_table, *sha3.program.tables),
        (
            *encoding.program.lookups,
            *sha3.program.lookups,
            leaf_messages,
            root_messages,
            root_digest,
        ),
    )
    return PackedExecutionCommitmentAirInstance(
        program,
        MappingProxyType(
            {**dict(encoding.traces), root_trace.name: root_trace, **dict(sha3.traces)}
        ),
        kind,
        encoding,
        sha3,
        call_index_offset,
        execution_hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


def build_oracle_execution_commitment_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> PackedExecutionCommitmentAirInstance:
    encoding = build_oracle_bundle_encoding_executable_air(profile, slots)
    commitments = encoding.commitments
    return _build(
        profile,
        "oracle",
        encoding,
        bundle_table="oracle_bundle_byte",
        bundles=encoding.bundles,
        leaves=commitments.leaf_digests,
        execution_root=commitments.execution_root,
        audit_root=commitments.audit_root,
        magic=ORACLE_EXECUTION_ROOT_MAGIC,
        call_index_offset=call_index_offset,
        interface_only=interface_only,
    )


def build_policy_execution_commitment_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> PackedExecutionCommitmentAirInstance:
    encoding = build_policy_bundle_encoding_executable_air(profile, slots)
    commitments = encoding.commitments
    return _build(
        profile,
        "policy",
        encoding,
        bundle_table="policy_bundle_byte",
        bundles=commitments.bundles,
        leaves=commitments.leaf_digests,
        execution_root=commitments.execution_root,
        audit_root=commitments.audit_root,
        magic=POLICY_EXECUTION_ROOT_MAGIC,
        call_index_offset=call_index_offset,
        interface_only=interface_only,
    )


__all__ = (
    "PackedExecutionCommitmentAirInstance",
    "build_oracle_execution_commitment_executable_air",
    "build_policy_execution_commitment_executable_air",
)
