"""Fail-closed mapping of the Blind Ledger claim into Hint-MLWE relations.

This answers expressibility only. It does not assert an efficient compiler,
complete theorem composition, selected parameters, or K128/K512 qualification.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class RelationMapping:
    claim_component: str
    workspace_source: str
    hint_mlwe_mapping: str
    lowered_max_degree: int
    fixed_shape: bool


@dataclass(frozen=True, slots=True)
class ExpressibilityReport:
    answer: str
    framework_relation: str
    witness_mapping: str
    public_mapping: str
    components: tuple[RelationMapping, ...]
    outside_relation_obligations: tuple[str, ...]
    qualification_status: str
    failures: tuple[str, ...]


MAPPINGS = (
    RelationMapping(
        "fixed K slots, real/cover selection, and padding",
        "experiments/fixed_shape_claim_air/wave1a_global_executable_air.py",
        "Boolean selector a satisfies a(a-1)=0; fixed slot wiring is linear; "
        "conditional values use z=a*x+(1-a)*dummy with one product.",
        2,
        True,
    ),
    RelationMapping(
        "private claim facts, governed policy, and adjudication",
        "experiments/fixed_shape_claim_air/claim_semantics_executable_air.py",
        "Private fields and auxiliaries are committed in s1; equality is "
        "linear, AND is z=xy, and comparisons use Boolean limbs plus "
        "quadratic carry/borrow constraints.",
        2,
        True,
    ),
    RelationMapping(
        "payment arithmetic and value conservation",
        "experiments/fixed_shape_claim_air/fee_arithmetic_executable_air.py",
        "Amounts are 64-bit limbs with Boolean range constraints; additions "
        "and conservation are linear with constrained carries; products are "
        "lowered through one auxiliary per multiplication.",
        2,
        True,
    ),
    RelationMapping(
        "SHA3-512 nullifiers, governed roots, and master commitments",
        "experiments/fixed_shape_claim_air/application_sha3_executable_air.py",
        "Each bit satisfies b(b-1)=0; Keccak XOR/NOT/rotation wiring is "
        "linear after auxiliaries and every AND/chi term is quadratic. "
        "The 512-bit outputs are eight 64-bit limbs, not one field element.",
        2,
        True,
    ),
    RelationMapping(
        "fixed-width nullifier nonzero and intra-batch uniqueness",
        "experiments/fixed_shape_claim_air/a12_replay_composition_executable_air.py",
        "Limbwise equality is linear. For inequality, Boolean selectors pick "
        "one differing 64-bit limb d and an inverse witness enforces d*u=1.",
        2,
        True,
    ),
    RelationMapping(
        "authenticated replay-state reads, absence, and ordered writes",
        "experiments/fixed_shape_claim_air/replay_ordered_map_executable_air.py",
        "Committed before/after cells and the fixed access trace live in s1; "
        "read consistency, absence, key ordering, and write consistency lower "
        "to Boolean/range equations and quadratic products.",
        2,
        True,
    ),
    RelationMapping(
        "hidden state commitment before and after",
        "docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md",
        "The RF-ABDLOP commitment equation A1*s1+A2*s2=tA is linear. A "
        "complete fixed-capacity state and transition can be committed in s1 "
        "and constrained by F; a sublinear memory argument is an efficiency "
        "optimization, not an expressibility prerequisite.",
        2,
        True,
    ),
    RelationMapping(
        "authority-signed committed private columns",
        "experiments/fixed_shape_claim_air/claim_truth_authority_executable_air.py",
        "Bind the authority signature to a public column commitment. Either "
        "verify a PQ signature publicly on that commitment, or lower its "
        "finite polynomial/bit verification algorithm to quadratic equations "
        "with auxiliaries; opening equality remains linear.",
        2,
        True,
    ),
    RelationMapping(
        "ordered 12-field ABI and full-width PQ sidecar",
        "experiments/fixed_shape_claim_air/wide_public_executable_air.py",
        "Public fields, profile identifiers, epoch, sequence, and full-width "
        "commitments are constants in F; limbwise equality binds them to the "
        "committed witness and computed outputs.",
        1,
        True,
    ),
)

OUTSIDE_RELATION_OBLIGATIONS = (
    "The stateful verifier must compare the proved before commitment with its "
    "authoritative current commitment and atomically install the after "
    "commitment; a proof alone cannot choose the winning concurrent batch.",
    "Authenticated interactive SHA3-512 public-coin transport and anti-replay "
    "session binding are protocol obligations, not equations inside F.",
    "Reorganization, rollback, checkpoint recovery, data availability, and "
    "authority-key governance require the separately specified state machine "
    "and operational proofs.",
)


def evaluate_blind_ledger_claim_mapping(
    mappings: tuple[RelationMapping, ...] = MAPPINGS,
) -> ExpressibilityReport:
    failures: list[str] = []
    if not mappings:
        failures.append("relation_mapping_empty")
    for mapping in mappings:
        if mapping.lowered_max_degree > 2:
            failures.append(
                f"component_above_quadratic:{mapping.claim_component}"
            )
        if not mapping.fixed_shape:
            failures.append(
                f"component_not_fixed_shape:{mapping.claim_component}"
            )
        if not mapping.workspace_source:
            failures.append(
                f"component_source_missing:{mapping.claim_component}"
            )
        if not mapping.hint_mlwe_mapping:
            failures.append(
                f"component_mapping_missing:{mapping.claim_component}"
            )
    return ExpressibilityReport(
        answer="NO" if failures else "YES",
        framework_relation=(
            "The paper accepts a public set F={f_i} of linear and quadratic "
            "relations over psi(s1,m)."
        ),
        witness_mapping=(
            "s1 contains the fixed-shape private claim, auxiliary gate values, "
            "state openings, ordered access trace, and commitment openings; "
            "s2 is RF-ABDLOP hiding randomness."
        ),
        public_mapping=(
            "The exact 12-field ABI, full 512-bit sidecar, before/after state "
            "commitments, nullifiers, epoch/sequence, authority commitment, "
            "suite, schema, and parameter IDs are public constants in F."
        ),
        components=mappings,
        outside_relation_obligations=OUTSIDE_RELATION_OBLIGATIONS,
        qualification_status=(
            "EXPRESSIBLE_ONLY_NOT_IMPLEMENTED_OR_QUALIFIED"
        ),
        failures=tuple(failures),
    )


def main() -> int:
    report = evaluate_blind_ledger_claim_mapping()
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 0 if report.answer == "YES" else 1


if __name__ == "__main__":
    raise SystemExit(main())
