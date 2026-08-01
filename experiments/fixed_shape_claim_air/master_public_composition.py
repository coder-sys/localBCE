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


PROGRAM_ID: Final[str] = "BL-WAVE1A-MASTER-PUBLIC-COMPOSITION-AIR-v2"


@dataclass(frozen=True, slots=True)
class MasterPublicAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    master: MasterCommitmentsAirInstance
    public: WidePublicAirInstance
    master_public_links_constrained: bool = True

    def __post_init__(self) -> None:
        if (
            not self.master_public_links_constrained
            or "master_public_wide_value_links"
            not in {lookup.name for lookup in self.program.lookups}
        ):
            raise StructuralError("master_public_false_completion_claim")


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
    merged = merge_air_fragments(
        PROGRAM_ID,
        (
            AirFragment(master.program, master.traces),
            AirFragment(public.program, public.traces),
        ),
        extra_lookups=(links,),
    )
    return MasterPublicAirInstance(
        merged.program,
        MappingProxyType(dict(merged.traces)),
        master,
        public,
    )

__all__ = (
    "MasterPublicAirInstance",
    "build_master_public_composition",
)
