"""Compose claim semantics with the exact packed-oracle encoding relation."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from experiments.bl_pq512_crypto_foundation.oracle_bundle_commitment import (
    FACT_NAMES,
)

from .claim_semantics_executable_air import (
    ClaimSemanticsAirInstance,
    build_claim_semantics_executable_air,
)
from .executable_air import (
    AirProgram,
    LookupArgument,
    LookupSide,
    TraceTable,
    cell,
    const,
)
from .oracle_bundle_encoding_executable_air import (
    OracleBundleEncodingAirInstance,
    build_oracle_bundle_encoding_executable_air,
)
from .profile import AUTHORIZATIONS_PER_CLAIM, CalibrationProfile
from .semantics import ClaimSlot


PROGRAM_ID: Final[str] = "BL-WAVE1A-CLAIM-ORACLE-COMPOSITION-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimOracleAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    claim: ClaimSemanticsAirInstance
    oracle: OracleBundleEncodingAirInstance
    oracle_claim_semantics_constrained: bool = True
    oracle_hashes_constrained: bool = False
    oracle_signer_epoch_constrained: bool = False


def build_claim_oracle_executable_air(
    profile: CalibrationProfile,
    slots: Sequence[ClaimSlot],
) -> ClaimOracleAirInstance:
    materialized = tuple(slots)
    claim = build_claim_semantics_executable_air(materialized)
    oracle = build_oracle_bundle_encoding_executable_air(profile, materialized)
    rows = profile.claim_slots
    authorization_rows = rows * AUTHORIZATIONS_PER_CLAIM

    fact_values = (
        cell("slot_index"),
        *(cell(name) for name in FACT_NAMES),
    )
    fact_link = LookupArgument(
        "claim_oracle_fact_link",
        (
            LookupSide(
                "oracle_fact",
                const(1),
                fact_values,
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "claim_gate",
                const(1),
                fact_values,
                0,
                rows,
            ),
        ),
    )
    real_link = LookupArgument(
        "claim_oracle_real_link",
        (
            LookupSide(
                "oracle_fact",
                const(1),
                (cell("slot_index"), cell("real")),
                0,
                rows,
            ),
        ),
        (
            LookupSide(
                "claim_result",
                const(1),
                (cell("slot_index"), cell("is_real")),
                0,
                rows,
            ),
        ),
    )
    authorization_link = LookupArgument(
        "claim_oracle_authorization_link",
        (
            LookupSide(
                "oracle_authorization",
                const(1),
                (
                    cell("slot_index"),
                    cell("authorization_index"),
                    cell("line_enabled"),
                    cell("required"),
                    cell("present"),
                ),
                0,
                authorization_rows,
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
                    cell("requires_authorization"),
                    cell("authorization_present"),
                ),
                0,
                authorization_rows,
            ),
        ),
    )
    program = AirProgram(
        PROGRAM_ID,
        (*claim.program.tables, *oracle.program.tables),
        (
            *claim.program.lookups,
            *oracle.program.lookups,
            fact_link,
            real_link,
            authorization_link,
        ),
    )
    return ClaimOracleAirInstance(
        program,
        MappingProxyType({**dict(claim.traces), **dict(oracle.traces)}),
        claim,
        oracle,
    )


__all__ = ["ClaimOracleAirInstance", "build_claim_oracle_executable_air"]
