"""Exact oracle-layout comparison and constrained Wave 1B selection.

The comparison minimizes proof SHA3 permutations only after requiring all 50
authorization records, exact decode, fixed real/cover shape, a per-claim leaf
boundary, an independently verifiable audit path, and one attestation that
binds the execution and audit roots.  Layouts that win by deleting one of those
properties are reported but cannot be selected.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import json
from math import ceil, log2
from typing import Final, Sequence

from experiments.fixed_shape_claim_air.profile import PROFILES, CalibrationProfile

from .application_sha3_shared_schedule import (
    ORACLE_TREE,
    build_profile_shared_schedules,
)
from .oracle_bundle_commitment import (
    BUNDLE_BYTES,
    DIGEST_BYTES,
    RATE_BYTES,
    oracle_commitment_schedule,
)


STATUS: Final[str] = "WAVE1B_ORACLE_LAYOUT_CONSTRAINED_OPTIMUM_V1_NONACTIVATING"
CANONICAL_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1B/ORACLE-LAYOUT-OPTIMIZER/v1"
TOKEN_LANGUAGE_VALUES: Final[int] = 37**64
REQUIRED_AUTHORIZATION_FLAG_BITS: Final[int] = 3 * 50
REQUIRED_FACT_BITS: Final[int] = 7


@dataclass(frozen=True, slots=True)
class OracleLayoutCandidate:
    name: str
    proof_sponge_permutations: int
    independently_decodable_authorizations: int
    fixed_shape: bool
    per_claim_leaf_boundary: bool
    independent_audit_path: bool
    attestation_binds_execution_and_audit: bool
    selected: bool
    rejection_reason: str | None

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise ValueError("oracle_layout_name_invalid")
        if (
            type(self.proof_sponge_permutations) is not int
            or self.proof_sponge_permutations <= 0
        ):
            raise ValueError("oracle_layout_permutations_invalid")
        if self.independently_decodable_authorizations != 50:
            if self.selected:
                raise ValueError("oracle_layout_selected_without_authorizations")
        if self.selected and (
            not self.fixed_shape
            or not self.per_claim_leaf_boundary
            or not self.independent_audit_path
            or not self.attestation_binds_execution_and_audit
            or self.rejection_reason is not None
        ):
            raise ValueError("oracle_layout_selected_without_hard_requirements")


def _permutations(preimage_bytes: int) -> int:
    return preimage_bytes // RATE_BYTES + 1


def _legacy_oracle_schedule(profile: CalibrationProfile) -> int:
    return next(
        value.shared_sponge_permutations
        for value in build_profile_shared_schedules(profile)
        if value.tree_name == ORACLE_TREE
    )


def information_lower_bound_bytes() -> int:
    """Lower bound before domain/profile/slot framing.

    The exact token language has ``37**64`` values (empty plus every canonical
    token). Fifty independent tokens, 150 authorization bits, and seven
    real/fact bits must remain distinguishable.
    """

    states = (TOKEN_LANGUAGE_VALUES**50) * (1 << REQUIRED_AUTHORIZATION_FLAG_BITS)
    states *= 1 << REQUIRED_FACT_BITS
    return ceil(log2(states) / 8)


def compare_oracle_layouts(
    profile: CalibrationProfile,
) -> tuple[OracleLayoutCandidate, ...]:
    if not isinstance(profile, CalibrationProfile):
        raise TypeError("oracle_layout_profile_required")
    selected_schedule = oracle_commitment_schedule(profile)
    direct_manifest_bytes = 11 + profile.claim_slots * BUNDLE_BYTES
    compact_binary_tree = (
        profile.claim_slots * selected_schedule["leafPermutations"]
        + 2 * (profile.claim_slots - 1)
        + 2
    )
    return (
        OracleLayoutCandidate(
            "51-separate-record-dense-tree",
            _legacy_oracle_schedule(profile),
            50,
            True,
            False,
            True,
            False,
            False,
            "repeated record headers and 51 leaves per claim",
        ),
        OracleLayoutCandidate(
            "compact-direct-batch-manifest",
            _permutations(direct_manifest_bytes),
            50,
            True,
            False,
            False,
            False,
            False,
            "no per-claim leaf boundary or independent audit path",
        ),
        OracleLayoutCandidate(
            "compact-bundle-binary-proof-tree",
            compact_binary_tree,
            50,
            True,
            True,
            True,
            True,
            False,
            "more proof permutations than the parallel-leaf execution root",
        ),
        OracleLayoutCandidate(
            "compact-parallel-leaf-execution-plus-shared-leaf-audit",
            int(selected_schedule["proofSpongePermutations"]),
            50,
            True,
            True,
            True,
            True,
            True,
            None,
        ),
    )


def require_selected_layout_optimal(profile: CalibrationProfile) -> None:
    candidates = compare_oracle_layouts(profile)
    selected = tuple(value for value in candidates if value.selected)
    if len(selected) != 1:
        raise ValueError("oracle_layout_selected_count_invalid")
    admissible = tuple(
        value
        for value in candidates
        if value.independently_decodable_authorizations == 50
        and value.fixed_shape
        and value.per_claim_leaf_boundary
        and value.independent_audit_path
        and value.attestation_binds_execution_and_audit
    )
    if selected[0].proof_sponge_permutations != min(
        value.proof_sponge_permutations for value in admissible
    ):
        raise ValueError("oracle_layout_selected_not_constrained_minimum")
    lower_bound = information_lower_bound_bytes()
    if lower_bound > BUNDLE_BYTES:
        raise AssertionError("oracle_layout_information_bound_exceeds_encoding")
    if _permutations(lower_bound) != _permutations(BUNDLE_BYTES):
        raise ValueError("oracle_layout_leaf_not_block_optimal")


def oracle_layout_summary() -> dict[str, object]:
    profiles: list[dict[str, object]] = []
    for profile in PROFILES.values():
        require_selected_layout_optimal(profile)
        candidates = compare_oracle_layouts(profile)
        selected = next(value for value in candidates if value.selected)
        legacy = next(
            value
            for value in candidates
            if value.name == "51-separate-record-dense-tree"
        )
        profiles.append(
            {
                "profileId": profile.profile_id,
                "candidates": [
                    {
                        "name": value.name,
                        "proofSpongePermutations": value.proof_sponge_permutations,
                        "selected": value.selected,
                        "rejectionReason": value.rejection_reason,
                    }
                    for value in candidates
                ],
                "selectedProofSpongePermutations": (
                    selected.proof_sponge_permutations
                ),
                "supersededProofSpongePermutations": (
                    legacy.proof_sponge_permutations
                ),
                "permutationReduction": (
                    legacy.proof_sponge_permutations
                    - selected.proof_sponge_permutations
                ),
                "permutationSpeedup": (
                    legacy.proof_sponge_permutations
                    / selected.proof_sponge_permutations
                ),
            }
        )
    return {
        "status": STATUS,
        "informationLowerBoundBytesBeforeFraming": information_lower_bound_bytes(),
        "selectedBundleBytes": BUNDLE_BYTES,
        "selectedLeafPermutations": _permutations(BUNDLE_BYTES),
        "profiles": profiles,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def oracle_layout_canonical_sha3_512() -> str:
    encoded = json.dumps(
        oracle_layout_summary(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return sha3_512(CANONICAL_DOMAIN + encoded).hexdigest()


__all__: Sequence[str] = (
    "OracleLayoutCandidate",
    "STATUS",
    "compare_oracle_layouts",
    "information_lower_bound_bytes",
    "oracle_layout_canonical_sha3_512",
    "oracle_layout_summary",
    "require_selected_layout_optimal",
)
