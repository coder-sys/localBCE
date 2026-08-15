"""Exact composition of authoritative master commitments and Privacy V2 ABI."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.master_commitments_v2 import (
    MasterCommitmentInputsV2,
    PROTOCOL_VERSION,
)

from .air_composition import AirFragment, merge_air_fragments
from .executable_air import (
    AirProgram,
    LookupArgument,
    LookupSide,
    PublicInputBinding,
    TraceTable,
    cell,
    const,
)
from .master_commitments_executable_air import (
    MasterCommitmentsAirInstance,
    build_master_commitments_executable_air,
)
from .semantics import StructuralError
from .wide_public_executable_air import (
    WidePublicAirInstance,
    build_wide_public_executable_air_v2,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-MASTER-PUBLIC-COMPOSITION-AIR-v3"
V3_SIDECAR_BYTES: Final[int] = 744
V3_GOVERNANCE_OFFSET: Final[int] = 488
V3_GOVERNANCE_BYTES: Final[int] = 64
V3_PUBLIC_FIELD_COUNT: Final[int] = 12
V3_PUBLIC_FIELD_BYTES: Final[int] = 32
_GOVERNANCE_PUBLIC_PREFIX: Final[str] = "sidecar.strongGovernanceCommitment"


@dataclass(frozen=True, slots=True)
class MasterPublicAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    master: MasterCommitmentsAirInstance
    public: WidePublicAirInstance
    public_input_bytes: tuple[int, ...]
    master_public_links_constrained: bool = True
    governance_public_binding_constrained: bool = True

    def __post_init__(self) -> None:
        if (
            not self.master_public_links_constrained
            or not self.governance_public_binding_constrained
            or "master_public_wide_value_links"
            not in {lookup.name for lookup in self.program.lookups}
            or self.public_input_bytes
            != (
                *self.public.public_input_bytes,
                *self.master.commitments.governance_512,
            )
            or tuple(
                binding.name
                for binding in self.program.public_inputs[-V3_GOVERNANCE_BYTES:]
            )
            != tuple(
                f"{_GOVERNANCE_PUBLIC_PREFIX}.byte{index:02d}"
                for index in range(V3_GOVERNANCE_BYTES)
            )
        ):
            raise StructuralError("master_public_false_completion_claim")


def semantic_public_inputs_from_v3_sidecar(
    public_fields: tuple[bytes, ...],
    sidecar: bytes,
) -> tuple[int, ...]:
    """Return semantic public cells derived only from the v3 outer statement.

    The first 384 bytes are the frozen twelve-field application ABI.  The only
    added semantic public value is the existing 64-byte governance field at
    sidecar offsets 488..552.  The global v3 suite remains deliberately null.
    """

    if (
        type(public_fields) is not tuple
        or len(public_fields) != V3_PUBLIC_FIELD_COUNT
        or any(
            type(value) is not bytes or len(value) != V3_PUBLIC_FIELD_BYTES
            for value in public_fields
        )
    ):
        raise StructuralError("master_public_v3_public_fields_invalid")
    if (
        type(sidecar) is not bytes
        or len(sidecar) != V3_SIDECAR_BYTES
        or sidecar[:8] != b"BLPQSC01"
        or sidecar[8:10] != (1).to_bytes(2, "big")
        or sidecar[10:12] != bytes(2)
        or sidecar[12:16] != V3_SIDECAR_BYTES.to_bytes(4, "big")
        or not any(sidecar[16:80])
        or any(sidecar[80:144])
    ):
        raise StructuralError("master_public_v3_sidecar_header_invalid")
    for start in (144, 208, 272, 360, 424, 488, 552, 616, 680):
        if not any(sidecar[start : start + 64]):
            raise StructuralError("master_public_v3_sidecar_value_zero")
    sequence_before = int.from_bytes(sidecar[344:352], "big")
    if (
        int.from_bytes(sidecar[336:344], "big") == 0
        or sequence_before == 0xFFFFFFFFFFFFFFFF
        or int.from_bytes(sidecar[352:360], "big") != sequence_before + 1
        or sidecar[360:424] == sidecar[424:488]
        or sidecar[552:616] == sidecar[616:680]
    ):
        raise StructuralError("master_public_v3_sidecar_transition_invalid")
    return tuple(
        byte
        for field in public_fields
        for byte in field
    ) + tuple(
        sidecar[
            V3_GOVERNANCE_OFFSET : V3_GOVERNANCE_OFFSET + V3_GOVERNANCE_BYTES
        ]
    )


def _range_start(
    trace: TraceTable, column: str, value: int, expected_rows: int
) -> int:
    rows = tuple(index for index, observed in enumerate(trace.columns[column]) if observed == value)
    if len(rows) != expected_rows or rows != tuple(
        range(rows[0], rows[0] + expected_rows)
    ):
        raise StructuralError("master_public_material_field_geometry_invalid")
    return rows[0]


def build_master_public_composition(
    value: MasterCommitmentInputsV2,
    *,
    call_index_offset: int = 0,
    interface_only: bool = False,
) -> MasterPublicAirInstance:
    master = build_master_commitments_executable_air(
        value,
        call_index_offset=call_index_offset,
        interface_only=interface_only,
    )
    commitments = master.commitments
    selected_truth_roots = (
        value.claim_truth_roots_512[0],
        value.claim_truth_roots_512[1],
        value.claim_truth_roots_512[3],
        value.claim_truth_roots_512[5],
    )
    public = build_wide_public_executable_air_v2(
        PROTOCOL_VERSION,
        value.strong_settlement_domain_id_512,
        value.strong_batch_nonce_512,
        (
            value.replay_root_before_512,
            value.replay_root_after_512,
            *selected_truth_roots,
            commitments.batch_512,
            commitments.value_conservation_512,
            commitments.settlement_512,
        ),
    )
    material_trace = master.traces["master_commitment_material_byte"]
    output_trace = master.traces["master_commitment_output_byte"]
    projection_rows = {
        "settlement_domain": 0,
        "batch_nonce": 1,
        "replay_before": 2,
        "replay_after": 3,
        "claim_truth_root_0": 4,
        "claim_truth_root_1": 5,
        "claim_truth_root_3": 6,
        "claim_truth_root_5": 7,
    }
    sources: list[LookupSide] = []
    destinations: list[LookupSide] = []
    for field_name, projection_row in projection_rows.items():
        field_id = master.field_ids[field_name]
        for byte_index in range(64):
            material_row = _range_start(
                material_trace,
                "field_id",
                field_id,
                64,
            ) + byte_index
            sources.append(
                LookupSide(
                    material_trace.name,
                    const(1),
                    (const(projection_row), const(byte_index), cell("value")),
                    material_row,
                    material_row + 1,
                )
            )
            destinations.append(
                LookupSide(
                    "stark252_projection",
                    const(1),
                    (
                        cell("operation_index"),
                        const(byte_index),
                        cell(f"digest_{byte_index}"),
                    ),
                    projection_row,
                    projection_row + 1,
                )
            )
    for output_id, projection_row in ((1, 8), (2, 9), (3, 10)):
        output_start = _range_start(output_trace, "output_id", output_id, 64)
        for byte_index in range(64):
            sources.append(
                LookupSide(
                    output_trace.name,
                    const(1),
                    (const(projection_row), const(byte_index), cell("value")),
                    output_start + byte_index,
                    output_start + byte_index + 1,
                )
            )
            destinations.append(
                LookupSide(
                    "stark252_projection",
                    const(1),
                    (
                        cell("operation_index"),
                        const(byte_index),
                        cell(f"digest_{byte_index}"),
                    ),
                    projection_row,
                    projection_row + 1,
                )
            )
    links = LookupArgument(
        "master_public_wide_value_links",
        tuple(sources),
        tuple(destinations),
    )
    governance_start = _range_start(output_trace, "output_id", 0, 64)
    governance_public_bindings = tuple(
        PublicInputBinding(
            f"{_GOVERNANCE_PUBLIC_PREFIX}.byte{byte_index:02d}",
            output_trace.name,
            "value",
            governance_start + byte_index,
        )
        for byte_index in range(V3_GOVERNANCE_BYTES)
    )
    merged = merge_air_fragments(
        PROGRAM_ID,
        (
            AirFragment(master.program, master.traces),
            AirFragment(public.program, public.traces),
        ),
        extra_lookups=(links,),
        extra_public_inputs=governance_public_bindings,
    )
    return MasterPublicAirInstance(
        merged.program,
        MappingProxyType(dict(merged.traces)),
        master,
        public,
        (
            *public.public_input_bytes,
            *commitments.governance_512,
        ),
    )

__all__ = (
    "MasterPublicAirInstance",
    "build_master_public_composition",
    "semantic_public_inputs_from_v3_sidecar",
)
