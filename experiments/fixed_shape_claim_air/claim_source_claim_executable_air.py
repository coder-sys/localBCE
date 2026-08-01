"""Compose compact claim-source bytes with claim and oracle semantics.

The compact source bundle uses network-order integers while the original claim
tables use little-endian byte/limb views.  Every bridge below therefore states
the byte order explicitly instead of trusting the host objects used to build
both traces.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    TOKEN_ENCODED_BYTES,
)

from .claim_oracle_executable_air import (
    ClaimOracleAirInstance,
    build_claim_oracle_executable_air,
)
from .claim_source_arrays_executable_air import (
    ClaimSourceArraysAirInstance,
    build_claim_source_arrays_executable_air,
)
from .executable_air import AirProgram, LookupArgument, LookupSide, TraceTable, cell, const
from .profile import AUTHORIZATIONS_PER_CLAIM, SERVICE_LINES_PER_CLAIM, CalibrationProfile
from .policy_bundle_encoding_executable_air import (
    PolicyBundleEncodingAirInstance,
    build_policy_bundle_encoding_executable_air,
)
from .semantics import ClaimSlot


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-SOURCE-CLAIM-ORACLE-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimSourceClaimAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    source: ClaimSourceArraysAirInstance
    claim_oracle: ClaimOracleAirInstance
    policy: PolicyBundleEncodingAirInstance
    source_claim_semantics_constrained: bool = True
    source_oracle_authorization_token_constrained: bool = True
    policy_claim_semantics_constrained: bool = True
    source_hashes_constrained: bool = False
    source_authority_constrained: bool = False
    oracle_hashes_constrained: bool = False
    oracle_signer_epoch_constrained: bool = False


def build_claim_source_claim_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> ClaimSourceClaimAirInstance:
    materialized = tuple(slots)
    source = build_claim_source_arrays_executable_air(profile, materialized)
    claim_oracle = build_claim_oracle_executable_air(profile, materialized)
    policy = build_policy_bundle_encoding_executable_air(profile, materialized)
    slot_rows = profile.claim_slots
    service_rows = slot_rows * SERVICE_LINES_PER_CLAIM
    authorization_rows = slot_rows * AUTHORIZATIONS_PER_CLAIM

    slot_shape_link = LookupArgument(
        "claim_source_slot_shape_matches_claim_semantics",
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (
                    cell("slot_index"),
                    cell("npi_present"),
                    cell("diagnosis_count_byte_0"),
                    cell("service_count_byte_0"),
                ),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                (
                    cell("slot_index"),
                    cell("provider_present"),
                    cell("diagnoses_length"),
                    cell("lines_length"),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    # Real/cover is owned by claim_result.  Keep it as a separate two-column
    # bridge rather than smuggling a host-computed selector into claim_gate.
    real_link = LookupArgument(
        "claim_source_real_matches_claim_result",
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (cell("slot_index"), cell("real_byte_0")),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_result",
                const(1),
                (cell("slot_index"), cell("is_real")),
                0,
                slot_rows,
            ),
        ),
    )
    member_link = LookupArgument(
        "claim_source_member_presence_matches_claim_gate",
        (
            LookupSide(
                "claim_source_token_link",
                cell("is_member"),
                (cell("slot_index"), cell("nonzero")),
                0,
                slot_rows * 103,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                (cell("slot_index"), cell("member_present")),
                0,
                slot_rows,
            ),
        ),
    )
    total_link = LookupArgument(
        "claim_source_total_charge_matches_claim_gate",
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (
                    cell("slot_index"),
                    *(cell(f"total_charge_byte_{index}") for index in range(4)),
                ),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                (
                    cell("slot_index"),
                    cell("total_byte_3"),
                    cell("total_byte_2"),
                    cell("total_byte_1"),
                    cell("total_byte_0"),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    responsibility_link = LookupArgument(
        "claim_source_patient_responsibility_matches_claim_result",
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (
                    cell("slot_index"),
                    256 * cell("patient_responsibility_byte_2")
                    + cell("patient_responsibility_byte_3"),
                    256 * cell("patient_responsibility_byte_0")
                    + cell("patient_responsibility_byte_1"),
                ),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_result",
                const(1),
                (
                    cell("slot_index"),
                    cell("responsibility_limb_0"),
                    cell("responsibility_limb_1"),
                ),
                0,
                slot_rows,
            ),
        ),
    )
    service_link = LookupArgument(
        "claim_source_service_values_match_claim_semantics",
        (
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    *(cell(f"charge_byte_{index}") for index in range(4)),
                    *(cell(f"units_byte_{index}") for index in range(4)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    cell("charge_byte_3"),
                    cell("charge_byte_2"),
                    cell("charge_byte_1"),
                    cell("charge_byte_0"),
                    cell("units_byte_3"),
                    cell("units_byte_2"),
                    cell("units_byte_1"),
                    cell("units_byte_0"),
                ),
                0,
                service_rows,
            ),
        ),
    )
    authorization_token_link = LookupArgument(
        "claim_source_authorization_tokens_match_oracle_bundle",
        (
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    *(cell(f"authorization_rank_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "oracle_token_link",
                const(1),
                (
                    cell("slot_index"),
                    cell("token_index"),
                    *(cell(f"rank_byte_{index}") for index in range(TOKEN_ENCODED_BYTES)),
                ),
                0,
                authorization_rows,
            ),
        ),
    )
    policy_slot_link = LookupArgument(
        "claim_source_policy_slot_link",
        (
            LookupSide(
                "policy_slot",
                const(1),
                (cell("slot_index"), cell("real")),
                0,
                slot_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_scalar",
                const(1),
                (cell("slot_index"), cell("real_byte_0")),
                0,
                slot_rows,
            ),
        ),
    )
    policy_source_line_link = LookupArgument(
        "claim_source_policy_procedure_link",
        (
            LookupSide(
                "policy_line",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("enabled"),
                    cell("procedure_length"),
                    *(cell(f"procedure_char_{index}") for index in range(10)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_source_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    cell("procedure_length"),
                    *(cell(f"procedure_char_{index}") for index in range(10)),
                ),
                0,
                service_rows,
            ),
        ),
    )
    policy_claim_line_link = LookupArgument(
        "claim_policy_flags_match_claim_service",
        (
            LookupSide(
                "policy_line",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("enabled"),
                    cell("present"),
                    cell("requires_authorization"),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_service",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("live"),
                    cell("policy_present"),
                    cell("requires_authorization"),
                ),
                0,
                service_rows,
            ),
        ),
    )
    policy_fee_link = LookupArgument(
        "claim_policy_allowed_values_match_fee_arithmetic",
        (
            LookupSide(
                "policy_line",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("present"),
                    *(cell(f"allowed_byte_{index}") for index in range(4)),
                ),
                0,
                service_rows,
            ),
        ),
        (
            LookupSide(
                "claim_fee",
                const(1),
                (
                    cell("slot_index"),
                    cell("line_index"),
                    cell("policy_present"),
                    cell("allowed_byte_3"),
                    cell("allowed_byte_2"),
                    cell("allowed_byte_1"),
                    cell("allowed_byte_0"),
                ),
                0,
                service_rows,
            ),
        ),
    )

    program = AirProgram(
        PROGRAM_ID,
        (*source.program.tables, *claim_oracle.program.tables, *policy.program.tables),
        (
            *source.program.lookups,
            *claim_oracle.program.lookups,
            *policy.program.lookups,
            slot_shape_link,
            real_link,
            member_link,
            total_link,
            responsibility_link,
            service_link,
            authorization_token_link,
            policy_slot_link,
            policy_source_line_link,
            policy_claim_line_link,
            policy_fee_link,
        ),
    )
    return ClaimSourceClaimAirInstance(
        program,
        MappingProxyType(
            {**dict(source.traces), **dict(claim_oracle.traces), **dict(policy.traces)}
        ),
        source,
        claim_oracle,
        policy,
    )


__all__ = ["ClaimSourceClaimAirInstance", "build_claim_source_claim_executable_air"]
