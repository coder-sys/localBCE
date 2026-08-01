"""Exact root links from computed commitment lanes to the signed PQ envelope."""

from __future__ import annotations

from .executable_air import LookupArgument, LookupSide, cell, const


def build_claim_truth_root_lookup() -> LookupArgument:
    computed = (
        ("claim_source_hash_root", "value"),
        ("oracle_execution_root", "execution"),
        ("oracle_execution_root", "audit"),
        ("policy_execution_root", "execution"),
        ("policy_execution_root", "audit"),
        ("ruleset_commitment", "root"),
    )
    return LookupArgument(
        "claim_truth_computed_roots_match_dual_pq_authority",
        tuple(
            LookupSide(
                table,
                const(1),
                (
                    const(root_index),
                    *(cell(f"{prefix}_{byte_index}") for byte_index in range(64)),
                ),
                0,
                1,
            )
            for root_index, (table, prefix) in enumerate(computed)
        ),
        tuple(
            LookupSide(
                "claim_truth_authority_material",
                const(1),
                (
                    const(root_index),
                    *(cell(f"root_{root_index}_{byte_index}") for byte_index in range(64)),
                ),
                0,
                1,
            )
            for root_index in range(6)
        ),
    )


__all__ = ("build_claim_truth_root_lookup",)
