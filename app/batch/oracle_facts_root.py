from __future__ import annotations

from typing import Mapping, Sequence

from app.canonical_encoding import stable_private_hash
from app.batch.merkle import PoseidonFieldMerkleTree
from app.batch.poseidon import domain_poseidon_hash
from app.batch.stark_encoding import canonical_day_count, pack_felt_text
from app.batch.tar_required import is_tar_required
from app.models import SharedContext
from app.oracle_attestation import canonical_claim_source_commitment, canonical_tar_authorization_commitment
from app.service_line_canonical import canonical_service_line_identities


ORACLE_SIGNER_ROOT_SCHEMA = "oracle_signer_root_v1"
ORACLE_SIGNER_SET_DESCRIPTOR = "offchain_sphincs_sha2_128f_pqclean_attestation_set"


def canonical_oracle_signer_root() -> str:
    """Current descriptor commitment; key-set governance remains a separate release gate."""

    return stable_private_hash([ORACLE_SIGNER_ROOT_SCHEMA, [ORACLE_SIGNER_SET_DESCRIPTOR]])


def _text_words(value: str) -> tuple[int, ...]:
    raw = value.encode("utf-8")
    if not raw:
        return (0,)
    return tuple(int.from_bytes(raw[index : index + 16], "big") for index in range(0, len(raw), 16))


def oracle_text_commitment(value: str) -> int:
    words = _text_words(value)
    acc = domain_poseidon_hash("oracle", [len(value.encode("utf-8")), len(words)])
    for index, word in enumerate(words):
        acc = domain_poseidon_hash("oracle", [len(value.encode("utf-8")), len(words), index, acc, word])
    return acc


def oracle_fact_verification_commitment(fact_verification: Mapping[str, str]) -> int:
    ordered = tuple(sorted((str(key), str(value)) for key, value in fact_verification.items()))
    acc = domain_poseidon_hash("oracle", [len(ordered)])
    for index, (key, value) in enumerate(ordered):
        acc = domain_poseidon_hash(
            "oracle",
            [
                len(ordered),
                index,
                acc,
                oracle_text_commitment(key),
                oracle_text_commitment(value),
            ],
        )
    return acc


def oracle_evidence_commitment(evidence_root: str) -> int:
    clean = str(evidence_root).lower().removeprefix("0x")
    if len(clean) == 64:
        parsed = int(clean, 16)
        return domain_poseidon_hash("oracle", [parsed >> 128, parsed & (2**128 - 1)])
    return oracle_text_commitment(str(evidence_root))


def oracle_claim_fact_commitment(ctx: SharedContext) -> int:
    flags = ctx.flags
    return domain_poseidon_hash(
        "normalized_facts",
        [
            int(bool(flags.get("eligibility_active"))),
            int(bool(flags.get("provider_enrolled"))),
            int(bool(flags.get("provider_not_suspended"))),
            int(bool(flags.get("not_deceased"))),
            int(bool(flags.get("duplicate_claim"))),
            int(bool(flags.get("program_integrity_hold"))),
        ],
    )


def oracle_claim_facts_leaf(
    ctx: SharedContext,
    *,
    signer_root: int | str,
    claim_source_commitment: int | str,
    normalized_fact_commitment: int,
    evidence_root: str,
) -> int:
    flags = ctx.flags
    signer = oracle_evidence_commitment(signer_root) if isinstance(signer_root, str) else int(signer_root)
    claim_source = int(canonical_claim_source_commitment(claim_source_commitment), 16)
    return domain_poseidon_hash(
        "oracle",
        [
            0,
            pack_felt_text(ctx.claim_id),
            claim_source,
            signer,
            int(normalized_fact_commitment),
            oracle_fact_verification_commitment(ctx.fact_verification),
            oracle_evidence_commitment(evidence_root),
            int(bool(flags.get("eligibility_active"))),
            int(bool(flags.get("provider_enrolled"))),
            int(bool(flags.get("provider_not_suspended"))),
            int(bool(flags.get("not_deceased"))),
            int(bool(flags.get("duplicate_claim"))),
            int(bool(flags.get("program_integrity_hold"))),
        ],
    )


def prior_authorization_commitment(prior_authorization: str) -> int:
    return 0 if not prior_authorization else pack_felt_text(prior_authorization)


def signed_authorization_commitment(value: int | str | None) -> int:
    return int(canonical_tar_authorization_commitment(value), 16)


def oracle_line_authorization_leaf(
    *,
    claim_id: int,
    line_index: int,
    procedure_code: int,
    service_date_day: int,
    prior_authorization: str,
    authorization_present: bool,
    signed_tar_authorization_commitment: int | str | None,
    signer_root: int | str,
    fact_verification_commitment: int,
    evidence_root: int | str,
    valid_from_day: int,
    valid_until_day: int,
) -> int:
    signer = oracle_evidence_commitment(signer_root) if isinstance(signer_root, str) else int(signer_root)
    evidence = oracle_evidence_commitment(evidence_root) if isinstance(evidence_root, str) else int(evidence_root)
    return domain_poseidon_hash(
        "oracle",
        [
            1,
            int(claim_id),
            int(line_index),
            int(procedure_code),
            int(service_date_day),
            prior_authorization_commitment(prior_authorization),
            signed_authorization_commitment(signed_tar_authorization_commitment),
            int(bool(authorization_present)),
            signer,
            int(fact_verification_commitment),
            evidence,
            int(valid_from_day),
            int(valid_until_day),
        ],
    )


def canonical_oracle_claim_leaves(
    ctx: SharedContext,
    *,
    signer_root: int | str,
    claim_source_commitment: int | str,
    evidence_root: str,
    tar_required_codes: Sequence[str] | None = None,
) -> tuple[int, ...]:
    """Return the one canonical claim-plus-required-authorization oracle leaf set."""

    claim_leaf = oracle_claim_facts_leaf(
        ctx,
        signer_root=signer_root,
        claim_source_commitment=claim_source_commitment,
        normalized_fact_commitment=oracle_claim_fact_commitment(ctx),
        evidence_root=evidence_root,
    )
    signer_commitment = oracle_evidence_commitment(signer_root) if isinstance(signer_root, str) else int(signer_root)
    evidence_commitment = oracle_evidence_commitment(evidence_root)
    verification_commitment = oracle_fact_verification_commitment(ctx.fact_verification)
    claim_id = pack_felt_text(ctx.claim_id)
    service_date_day = canonical_day_count(ctx.service_date)
    tar_authorization_verified = ctx.fact_verification.get("tar_authorization") == "VERIFIED"
    leaves = [claim_leaf]
    for line_index, (procedure_code, _charge_cents, _units_cents, prior_authorization) in enumerate(
        canonical_service_line_identities(ctx.service_lines)
    ):
        if not is_tar_required(procedure_code, tar_required_codes):
            continue
        authorization_present = bool(prior_authorization) and tar_authorization_verified
        signed_authorization = prior_authorization_commitment(prior_authorization) if authorization_present else 0
        leaves.append(
            oracle_line_authorization_leaf(
                claim_id=claim_id,
                line_index=line_index,
                procedure_code=pack_felt_text(procedure_code),
                service_date_day=service_date_day,
                prior_authorization=prior_authorization,
                authorization_present=authorization_present,
                signed_tar_authorization_commitment=signed_authorization,
                signer_root=signer_commitment,
                fact_verification_commitment=verification_commitment,
                evidence_root=evidence_commitment,
                valid_from_day=service_date_day,
                valid_until_day=service_date_day,
            )
        )
    return tuple(leaves)


def oracle_facts_tree(leaves: Sequence[int], depth: int) -> PoseidonFieldMerkleTree:
    return PoseidonFieldMerkleTree(sorted(int(leaf) for leaf in leaves), depth, "oracle")


def oracle_facts_root_hex(leaves: Sequence[int], depth: int) -> str:
    return oracle_facts_tree(leaves, depth).root
