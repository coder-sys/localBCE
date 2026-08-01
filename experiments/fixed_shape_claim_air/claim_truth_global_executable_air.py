"""One-engine global composition for source/oracle/policy/ruleset PQ authority."""

from __future__ import annotations

from dataclasses import dataclass

from .air_composition import (
    ComposedAirInstance,
    Sha3ComposedComponent,
    compose_sha3_air_components,
    compose_sha3_interface_components,
)
from .application_sha3_executable_air import INTERFACE_PROGRAM_ID
from .claim_source_commitment_executable_air import ClaimSourceCommitmentAirInstance
from .claim_truth_authority_executable_air import ClaimTruthAuthorityAirInstance
from .claim_truth_root_composition import build_claim_truth_root_lookup
from .packed_execution_commitment_executable_air import (
    PackedExecutionCommitmentAirInstance,
)
from .ruleset_commitment_executable_air import RulesetCommitmentAirInstance
from .semantics import StructuralError


PROGRAM_ID = "BL-WAVE1A-CLAIM-TRUTH-GLOBAL-AIR-v1"


@dataclass(frozen=True, slots=True)
class ClaimTruthGlobalAirInstance:
    composed: ComposedAirInstance
    source: ClaimSourceCommitmentAirInstance
    oracle: PackedExecutionCommitmentAirInstance
    policy: PackedExecutionCommitmentAirInstance
    ruleset: RulesetCommitmentAirInstance
    authority: ClaimTruthAuthorityAirInstance
    all_truth_roots_constrained: bool = True
    dual_pq_authority_constrained: bool = True
    one_sha3_engine: bool = True
    truth_root_ports_constrained: bool = False
    sha3_interface_only: bool = False


def build_claim_truth_global_executable_air(
    source: ClaimSourceCommitmentAirInstance,
    oracle: PackedExecutionCommitmentAirInstance,
    policy: PackedExecutionCommitmentAirInstance,
    ruleset: RulesetCommitmentAirInstance,
    authority: ClaimTruthAuthorityAirInstance,
) -> ClaimTruthGlobalAirInstance:
    if (
        not isinstance(source, ClaimSourceCommitmentAirInstance)
        or not isinstance(oracle, PackedExecutionCommitmentAirInstance)
        or oracle.kind != "oracle"
        or not isinstance(policy, PackedExecutionCommitmentAirInstance)
        or policy.kind != "policy"
        or not isinstance(ruleset, RulesetCommitmentAirInstance)
        or not isinstance(authority, ClaimTruthAuthorityAirInstance)
    ):
        raise StructuralError("claim_truth_global_components_invalid")
    ordered = (source, oracle, policy, ruleset, authority)
    components = tuple(
        Sha3ComposedComponent(
            value.program,
            value.traces,
            value.sha3,
            value.call_index_offset,
        )
        for value in ordered
    )
    interface_only = all(
        value.sha3.program.program_id == INTERFACE_PROGRAM_ID for value in ordered
    )
    if not interface_only and any(
        value.sha3.program.program_id == INTERFACE_PROGRAM_ID for value in ordered
    ):
        raise StructuralError("claim_truth_global_mixed_sha3_backends")
    composer = (
        compose_sha3_interface_components
        if interface_only
        else compose_sha3_air_components
    )
    composed = composer(
        PROGRAM_ID,
        components,
        extra_lookups=(build_claim_truth_root_lookup(),),
    )
    engine_table = "sha3_message_batch" if interface_only else "sha3_truth_shared"
    if tuple(table.name for table in composed.program.tables).count(engine_table) != 1:
        raise StructuralError("claim_truth_global_sha3_engine_not_unique")
    return ClaimTruthGlobalAirInstance(
        composed,
        source,
        oracle,
        policy,
        ruleset,
        authority,
        all_truth_roots_constrained=not interface_only,
        one_sha3_engine=not interface_only,
        truth_root_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = (
    "ClaimTruthGlobalAirInstance",
    "build_claim_truth_global_executable_air",
)
