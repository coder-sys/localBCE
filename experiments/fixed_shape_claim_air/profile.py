"""Synthetic-only provisional fixed-shape profiles for R25."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping


SERVICE_LINES_PER_CLAIM: Final[int] = 50
DIAGNOSES_PER_CLAIM: Final[int] = 16
FACTS_PER_CLAIM: Final[int] = 6
AUTHORIZATIONS_PER_CLAIM: Final[int] = 50
POLICY_TREE_DEPTH: Final[int] = 16
POLICY_REAL_ROW_CAPACITY: Final[int] = 65_533
LEGACY_NULLIFIER_TREE_DEPTH: Final[int] = 32
STRONG_NULLIFIER_TREE_DEPTH: Final[int] = 64


def _next_power_of_two(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("r25_dimension_must_be_positive_integer")
    return 1 << (value - 1).bit_length()


@dataclass(frozen=True, slots=True)
class CalibrationProfile:
    """One provisional measurement profile, never a governed production profile."""

    profile_id: str
    claim_slots: int
    claim_source_tree_depth: int
    oracle_tree_depth: int

    def __post_init__(self) -> None:
        expected_profiles = {
            "K128_CALIBRATION": (128, 7, 13),
            "K256_DESIGN_POINT": (256, 8, 14),
            "K512_CALIBRATION": (512, 9, 15),
        }
        if type(self.profile_id) is not str or self.profile_id not in expected_profiles:
            raise ValueError("r25_profile_id_unknown")
        observed = (
            self.claim_slots,
            self.claim_source_tree_depth,
            self.oracle_tree_depth,
        )
        if observed != expected_profiles[self.profile_id]:
            raise ValueError("r25_profile_dimensions_mismatch")

    def logical_dimensions(self) -> Mapping[str, int]:
        k = self.claim_slots
        service_rows = k * SERVICE_LINES_PER_CLAIM
        diagnosis_rows = k * DIAGNOSES_PER_CLAIM
        fact_rows = k * FACTS_PER_CLAIM
        authorization_rows = k * AUTHORIZATIONS_PER_CLAIM
        oracle_leaves = k * (1 + AUTHORIZATIONS_PER_CLAIM)
        return MappingProxyType(
            {
                "claim_slots": k,
                "service_line_rows": service_rows,
                "service_line_padded_rows": _next_power_of_two(service_rows),
                "diagnosis_rows": diagnosis_rows,
                "diagnosis_padded_rows": _next_power_of_two(diagnosis_rows),
                "fact_rows": fact_rows,
                "fact_padded_rows": _next_power_of_two(fact_rows),
                "authorization_rows": authorization_rows,
                "authorization_padded_rows": _next_power_of_two(
                    authorization_rows
                ),
                "policy_query_rows": service_rows,
                "policy_query_padded_rows": _next_power_of_two(service_rows),
                "claim_source_leaves": k,
                "oracle_leaves": oracle_leaves,
                "oracle_padded_leaves": _next_power_of_two(oracle_leaves),
                "legacy_nullifier_path_nodes": (
                    k * 2 * LEGACY_NULLIFIER_TREE_DEPTH
                ),
                "strong_nullifier_path_nodes": (
                    k * 2 * STRONG_NULLIFIER_TREE_DEPTH
                ),
                "legacy_nullifier_transitions": k,
                "strong_nullifier_transitions": k,
                "salt_use_transitions": 1,
                "strong_replay_transitions": k + 1,
                "benefit_state_path_operations": k,
                "obligation_state_path_operations": k,
                "private_asset_ledger_path_operations": k,
                "payment_state_transitions": k,
                "operation_log_appends": k,
                "policy_tree_depth": POLICY_TREE_DEPTH,
                "policy_real_row_capacity": POLICY_REAL_ROW_CAPACITY,
            }
        )


PROFILES: Final[Mapping[str, CalibrationProfile]] = MappingProxyType(
    {
        "K128_CALIBRATION": CalibrationProfile(
            "K128_CALIBRATION", 128, 7, 13
        ),
        "K256_DESIGN_POINT": CalibrationProfile(
            "K256_DESIGN_POINT", 256, 8, 14
        ),
        "K512_CALIBRATION": CalibrationProfile(
            "K512_CALIBRATION", 512, 9, 15
        ),
    }
)


def get_profile(profile_id: str) -> CalibrationProfile:
    if type(profile_id) is not str or profile_id not in PROFILES:
        raise ValueError("r25_profile_id_unknown")
    return PROFILES[profile_id]
