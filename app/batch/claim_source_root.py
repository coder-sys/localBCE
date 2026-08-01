from __future__ import annotations

from typing import Iterable, Sequence

from app.batch.attempt import GovernedClaimAttempt, legacy_attempt_record_commitment
from app.batch.merkle import PoseidonFieldMerkleTree
from app.batch.poseidon import domain_poseidon_hash
from app.batch.stark_encoding import canonical_cents, encode_claim, pack_felt_text
from app.canonical_order import canonical_diagnoses
from app.models import ServiceLine, SharedContext
from app.service_line_canonical import canonical_service_line_identities


CLAIM_SOURCE_SCHEMA = 2


def _hex(value: int) -> str:
    return f"{int(value):064x}"


def _optional_text(value: str | None) -> int:
    return 0 if not value else pack_felt_text(value)


def claim_source_service_lines_commitment(lines: Iterable[ServiceLine]) -> int:
    identities = canonical_service_line_identities(lines)
    acc = domain_poseidon_hash("claim_source", [len(identities)])
    for index, (procedure_code, charge_cents, units_cents, prior_authorization) in enumerate(identities):
        acc = domain_poseidon_hash(
            "claim_source",
            [
                len(identities),
                index,
                acc,
                pack_felt_text(procedure_code),
                int(charge_cents),
                int(units_cents),
                _optional_text(prior_authorization),
            ],
        )
    return acc


def claim_source_diagnosis_commitment(diagnoses: Iterable[str]) -> int:
    ordered = canonical_diagnoses(diagnoses)
    acc = domain_poseidon_hash("claim_source", [len(ordered)])
    for index, diagnosis in enumerate(ordered):
        acc = domain_poseidon_hash(
            "claim_source",
            [len(ordered), index, acc, pack_felt_text(diagnosis)],
        )
    return acc


def claim_source_leaf(
    ctx: SharedContext,
    *,
    attempt: GovernedClaimAttempt,
    attempt_nullifier: int,
    ruleset_root: int | str,
) -> int:
    attempt.validate_for_claim(ctx)
    encoded = encode_claim(ctx)
    return domain_poseidon_hash(
        "claim_source",
        [
            CLAIM_SOURCE_SCHEMA,
            encoded.claim_id,
            encoded.member_id,
            encoded.provider_npi,
            encoded.service_date,
            encoded.service_lines_commitment,
            encoded.diagnosis_commitment,
            len(ctx.diagnoses),
            canonical_cents(ctx.total_charge),
            int(attempt_nullifier),
            legacy_attempt_record_commitment(attempt, ctx),
            int(str(ruleset_root), 16) if isinstance(ruleset_root, str) else int(ruleset_root),
        ],
    )


def claim_source_tree(leaves: Sequence[int], depth: int) -> PoseidonFieldMerkleTree:
    ordered = sorted(int(leaf) for leaf in leaves)
    return PoseidonFieldMerkleTree(ordered, depth, "claim_source")


def claim_source_root_hex(leaves: Sequence[int], depth: int) -> str:
    return claim_source_tree(leaves, depth).root


def claim_source_leaf_hex(
    ctx: SharedContext,
    *,
    attempt: GovernedClaimAttempt,
    attempt_nullifier: int,
    ruleset_root: int | str,
) -> str:
    return _hex(
        claim_source_leaf(
            ctx,
            attempt=attempt,
            attempt_nullifier=attempt_nullifier,
            ruleset_root=ruleset_root,
        )
    )
