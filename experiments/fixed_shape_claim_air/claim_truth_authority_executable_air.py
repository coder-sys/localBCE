"""Executable binding for a verifier-approved dual-PQ authority envelope.

ML-DSA-87 and SLH-DSA-SHAKE-256f verification remains in the narrow verifier
adapter.  The AIR hashes the exact signed authority message and exposes only
its 512-bit digest as public input, then makes all six signed roots available
for exact global-composition lookups.  This avoids a signature circuit in the
prover hot path without trusting an unbound host root.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ENVELOPE_MAGIC,
    ClaimTruthAuthorityEnvelopeV1,
    ClaimTruthAuthorityRegistryV1,
    SignatureAdapter,
    claim_truth_authority_message,
    verify_claim_truth_authority,
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
    PublicInputBinding,
    TraceTable,
    cell,
    const,
    freeze_columns,
)
from .semantics import StructuralError


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-TRUTH-DUAL-PQ-AUTHORITY-AIR-v1"
ROOT_NAMES: Final[tuple[str, ...]] = (
    "claim_source",
    "oracle_execution",
    "oracle_audit",
    "policy_execution",
    "policy_audit",
    "ruleset",
)


@dataclass(frozen=True, slots=True)
class ClaimTruthAuthorityAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    envelope: ClaimTruthAuthorityEnvelopeV1
    sha3: ApplicationSha3AirInstance
    public_input_bytes: tuple[int, ...]
    call_index_offset: int
    pq_authority_verified: bool = True
    authority_message_hash_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        tables = {table.name for table in self.program.tables}
        lookups = {lookup.name for lookup in self.program.lookups}
        if not self.pq_authority_verified or (
            not self.authority_message_hash_constrained
            and not self.hash_ports_constrained
        ):
            raise StructuralError("claim_truth_authority_air_false_completion_claim")
        if self.sha3_interface_only != self.hash_ports_constrained or (
            self.sha3_interface_only and self.authority_message_hash_constrained
        ):
            raise StructuralError("claim_truth_authority_air_false_completion_claim")
        if not {
            "claim_truth_authority_material",
            "sha3_message_batch",
            "sha3_digest_batch",
        }.issubset(tables) or not {
            "claim_truth_authority_sha3_message",
            "claim_truth_authority_sha3_digest",
        }.issubset(lookups):
            raise StructuralError("claim_truth_authority_air_false_completion_claim")


def build_claim_truth_authority_executable_air(
    registry: ClaimTruthAuthorityRegistryV1,
    envelope: ClaimTruthAuthorityEnvelopeV1,
    *,
    ml_adapter: SignatureAdapter,
    slh_adapter: SignatureAdapter,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> ClaimTruthAuthorityAirInstance:
    if type(call_index_offset) is not int or call_index_offset < 0:
        raise StructuralError("claim_truth_authority_call_offset_invalid")
    if not verify_claim_truth_authority(
        registry,
        envelope,
        ml_adapter=ml_adapter,
        slh_adapter=slh_adapter,
    ):
        raise StructuralError("claim_truth_authority_dual_pq_verification_failed")
    message = ENVELOPE_MAGIC + claim_truth_authority_message(
        profile_id=envelope.profile_id,
        authority_id=envelope.authority_id,
        epoch=envelope.epoch,
        snapshot_id=envelope.snapshot_id,
        roots=envelope.roots,
    )
    calls = (Sha3Call("claim_truth_authority", message, len(message)),)
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    roots = envelope.roots.ordered()
    columns: dict[str, tuple[int, ...]] = {
        "row": (0,),
        **{f"message_{index}": (value,) for index, value in enumerate(message)},
        **{
            f"root_{root_index}_{byte_index}": (value,)
            for root_index, root in enumerate(roots)
            for byte_index, value in enumerate(root)
        },
        **{
            f"digest_{index}": (value,)
            for index, value in enumerate(envelope.message_digest)
        },
    }
    root_offset = len(ENVELOPE_MAGIC) + 8 + 1 + 8 + 64 + 1 + 64
    identities = tuple(
        Identity(
            f"claim_truth_authority_root_{root_index}_{byte_index}",
            cell(f"root_{root_index}_{byte_index}")
            - cell(f"message_{root_offset + root_index * 64 + byte_index}"),
            0,
            1,
        )
        for root_index in range(len(roots))
        for byte_index in range(64)
    )
    material_trace = TraceTable(
        "claim_truth_authority_material", freeze_columns(columns)
    )
    material_table = AirTable(
        material_trace.name,
        tuple(material_trace.columns),
        1,
        identities,
        MappingProxyType({"row": (0,)}),
    )
    message_lookup = LookupArgument(
        "claim_truth_authority_sha3_message",
        tuple(
            LookupSide(
                material_table.name,
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
        "claim_truth_authority_sha3_digest",
        (
            LookupSide(
                "sha3_digest_batch",
                const(1),
                (cell("call_index"), *(cell(f"value_{index}") for index in range(64))),
                0,
                1,
            ),
        ),
        (
            LookupSide(
                material_table.name,
                const(1),
                (
                    const(call_index_offset),
                    *(cell(f"digest_{index}") for index in range(64)),
                ),
                0,
                1,
            ),
        ),
    )
    public_inputs = tuple(
        PublicInputBinding(
            f"claimTruthAuthorityDigest.byte{index:02d}",
            material_table.name,
            f"digest_{index}",
            0,
        )
        for index in range(64)
    )
    program = AirProgram(
        PROGRAM_ID,
        (material_table, *sha3.program.tables),
        (*sha3.program.lookups, message_lookup, digest_lookup),
        public_inputs,
    )
    return ClaimTruthAuthorityAirInstance(
        program,
        MappingProxyType(
            {material_trace.name: material_trace, **dict(sha3.traces)}
        ),
        envelope,
        sha3,
        tuple(envelope.message_digest),
        call_index_offset,
        authority_message_hash_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = (
    "ClaimTruthAuthorityAirInstance",
    "ROOT_NAMES",
    "build_claim_truth_authority_executable_air",
)
