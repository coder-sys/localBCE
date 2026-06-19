from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from typing import Iterable, List

from app.canonical_encoding import canonical_record, digest_bytes, digest_hex, stable_private_hash
from app.batch.poseidon import FIELD_MODULUS, HELPER_CRATE, HELPER_CRATE_VERSION, domain_poseidon_hash
from app.models import AdjudicationResult, ServiceLine, SharedContext


LEAF_FORMAT_VERSION = "BL_BATCH_LEAF_V1"
DUPLICATE_CHECK_DOMAIN = "BL_DUPLICATE_CHECK_V1"
DUPLICATE_CHECK_PUBLIC_SALT = "BL_DUPLICATE_PUBLIC_SALT_V1"
DUPLICATE_CHECK_PEPPER_ENV = "BL_DUPLICATE_CHECK_PEPPER"
DUPLICATE_CHECK_DEV_PEPPER = "BL_LOCAL_DEV_PEPPER_NOT_FOR_PRODUCTION"
DEV_MODE_ENV = "BL_DEV"
ENVIRONMENT_ENV = "BL_ENV"
POSEIDON_STATUS = f"REAL POSEIDON via {HELPER_CRATE} {HELPER_CRATE_VERSION}; soundness-checked, PENDING CRYPTO AUDIT"
NULLIFIER_STATUS = "Full Poseidon field duplicate key is used as the circuit nullifier; PENDING CRYPTO AUDIT"


def _field_from_record(record_type: str, fields: Iterable[object]) -> int:
    return int.from_bytes(digest_bytes(record_type, fields), "big") % FIELD_MODULUS


def current_duplicate_pepper() -> str:
    pepper = os.environ.get(DUPLICATE_CHECK_PEPPER_ENV)
    if pepper:
        return pepper
    if os.environ.get(ENVIRONMENT_ENV, "").strip().lower() in {"prod", "production"}:
        raise RuntimeError(f"missing required duplicate pepper: {DUPLICATE_CHECK_PEPPER_ENV}")
    if os.environ.get(DEV_MODE_ENV) == "1":
        return DUPLICATE_CHECK_DEV_PEPPER
    raise RuntimeError(f"missing required duplicate pepper: {DUPLICATE_CHECK_PEPPER_ENV}")


def _duplicate_domain_field(pepper: str | None = None) -> int:
    pepper = pepper if pepper is not None else current_duplicate_pepper()
    return _field_from_record(
        "duplicate_domain_field",
        [DUPLICATE_CHECK_DOMAIN, DUPLICATE_CHECK_PUBLIC_SALT, pepper],
    )


def _duplicate_field(label: str, value: object, pepper: str | None = None) -> int:
    pepper = pepper if pepper is not None else current_duplicate_pepper()
    return _field_from_record(
        "duplicate_input_field",
        [DUPLICATE_CHECK_DOMAIN, DUPLICATE_CHECK_PUBLIC_SALT, pepper, label, value],
    )


def cents(amount: float) -> int:
    return int(round(float(amount) * 100))


def _service_codes(lines: List[ServiceLine]) -> List[str]:
    return [line.procedure_code for line in lines]


def _service_lines_hash(lines: List[ServiceLine]) -> str:
    return stable_private_hash(
        [
            {
                "line_id": line.line_id,
                "procedure_code": line.procedure_code,
                "charge_amount_cents": cents(line.charge_amount),
                "units": line.units,
                "prior_authorization": line.prior_authorization or "",
            }
            for line in lines
        ]
    )


def claim_fact_hash(ctx: SharedContext) -> str:
    """Hash claim facts separately from operator/oracle policy assertions."""
    return stable_private_hash(
        {
            "claim_id": ctx.claim_id,
            "transaction_set": ctx.transaction_set,
            "payer_id": ctx.payer_id,
            "member_id": ctx.member_id,
            "patient": {"name": ctx.patient.name, "id": ctx.patient.id},
            "provider": {"npi": ctx.provider.npi, "name": ctx.provider.name},
            "service_date": ctx.service_date,
            "diagnoses": ctx.diagnoses,
            "service_lines": [
                {
                    "line_id": line.line_id,
                    "procedure_code": line.procedure_code,
                    "charge_amount": cents(line.charge_amount),
                    "units": line.units,
                    "prior_authorization": line.prior_authorization or "",
                }
                for line in ctx.service_lines
            ],
            "total_charge": cents(ctx.total_charge),
        }
    )


def policy_assertion_hash(ctx: SharedContext) -> str:
    return stable_private_hash({"flags": ctx.flags, "fact_verification": ctx.fact_verification})


def gate_evidence_hash(result: AdjudicationResult) -> str:
    return stable_private_hash(
        [
            {"gate": gate.gate, "passed": gate.passed, "reason": gate.reason}
            for gate in result.gates
        ]
    )


def diagnosis_hash(ctx: SharedContext) -> str:
    return stable_private_hash(ctx.diagnoses)


def duplicate_identity_key(ctx: SharedContext, frequency_type: str = "original") -> str:
    """Long-lived local duplicate key that survives pepper rotation."""
    return stable_private_hash(
        [
            "duplicate_identity_v1",
            ctx.member_id,
            ctx.provider.npi,
            ctx.service_date,
            _service_codes(ctx.service_lines),
            cents(ctx.total_charge),
            frequency_type,
        ]
    )


def duplicate_check_key_int(ctx: SharedContext, frequency_type: str = "original", pepper: str | None = None) -> int:
    """Poseidon duplicate key over the domain-separated duplicate field set."""
    fields = [
        _duplicate_domain_field(pepper),
        _duplicate_field("member_id", ctx.member_id, pepper),
        _duplicate_field("provider_npi", ctx.provider.npi, pepper),
        _duplicate_field("service_date", ctx.service_date, pepper),
        _duplicate_field("service_codes", _service_codes(ctx.service_lines), pepper),
        cents(ctx.total_charge),
        _duplicate_field("frequency_type", frequency_type, pepper),
    ]
    return domain_poseidon_hash("nullifier", fields)


def duplicate_check_key(ctx: SharedContext, frequency_type: str = "original", pepper: str | None = None) -> str:
    return f"{duplicate_check_key_int(ctx, frequency_type, pepper):064x}"


def duplicate_check_nullifier(ctx: SharedContext, frequency_type: str = "original", pepper: str | None = None) -> int:
    return duplicate_check_key_int(ctx, frequency_type, pepper)


def batch_nullifier_commitment(nullifiers: Iterable[int]) -> str:
    acc = 0
    for nullifier in nullifiers:
        acc = domain_poseidon_hash("nullifier", [acc, int(nullifier)])
    return f"{acc:064x}"


def combined_batch_commitment(
    batch_id: str,
    claim_root: str,
    result_root: str,
    payment_root: str,
    nullifier_root_before: str,
    nullifier_root_after: str,
    batch_nullifier_record: str,
    ruleset_root: str,
    verifier_key_id: str,
    claim_count: int,
    payment_count: int,
    *,
    claim_source_root: str = "",
    oracle_facts_root: str = "",
    oracle_signer_root: str = "",
    fee_schedule_root: str = "",
    address_book_root: str = "",
    data_availability_root: str = "",
    denial_attestation_root: str = "",
    forced_inclusion_root: str = "",
    value_conservation_commitment: str = "",
) -> str:
    return digest_hex(
        "combined_batch_commitment",
        [
            batch_id,
            claim_root,
            result_root,
            payment_root,
            nullifier_root_before,
            nullifier_root_after,
            batch_nullifier_record,
            ruleset_root,
            claim_source_root,
            oracle_facts_root,
            oracle_signer_root,
            fee_schedule_root,
            address_book_root,
            data_availability_root,
            denial_attestation_root,
            forced_inclusion_root,
            value_conservation_commitment,
            verifier_key_id,
            int(claim_count),
            int(payment_count),
        ],
    )


def claim_leaf(ctx: SharedContext, duplicate_key: str, ruleset_version: str) -> str:
    fields = [
        stable_private_hash(ctx.claim_id),
        claim_fact_hash(ctx),
        stable_private_hash(ctx.member_id),
        stable_private_hash(ctx.provider.npi),
        ctx.service_date,
        _service_lines_hash(ctx.service_lines),
        diagnosis_hash(ctx),
        cents(ctx.total_charge),
        [line.prior_authorization or "" for line in ctx.service_lines],
        duplicate_key,
        ruleset_version,
    ]
    return digest_hex("claim_leaf", fields)


def result_leaf(
    ctx: SharedContext,
    result: AdjudicationResult,
    duplicate_key: str,
    ruleset_version: str,
    engine_mode: str,
) -> str:
    if result.claim_id != ctx.claim_id:
        raise ValueError("claim_id_mismatch_result_leaf")
    fields = [
        stable_private_hash(ctx.claim_id),
        1 if result.approved else 0,
        result.denial_reason,
        result.carc,
        result.rarc,
        cents(result.payable_amount),
        gate_evidence_hash(result),
        policy_assertion_hash(ctx),
        engine_mode,
        duplicate_key,
        ruleset_version,
    ]
    return digest_hex("result_leaf", fields)


def payment_leaf(
    batch_id: str,
    provider_payment_key_hash: str,
    recipient_commitment: str,
    approved_claim_count: int,
    net_amount_cents: int,
    reconciliation_commitment: str,
    payment_rail: str,
    settlement_instruction_hash: str,
    approved_result_commitment: str,
) -> str:
    return digest_hex(
        "payment_leaf",
        [
            batch_id,
            provider_payment_key_hash,
            recipient_commitment,
            approved_claim_count,
            net_amount_cents,
            reconciliation_commitment,
            payment_rail,
            settlement_instruction_hash,
            approved_result_commitment,
        ],
    )


def _address_bytes(address: str) -> bytes:
    clean = address[2:] if address.startswith("0x") else address
    if len(clean) != 40:
        raise ValueError("expected 20-byte EVM address")
    try:
        return bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("expected hex EVM address") from exc


def _bytes32(value: str) -> bytes:
    clean = value[2:] if value.startswith("0x") else value
    if len(clean) != 64:
        raise ValueError("expected 32-byte hex value")
    try:
        return bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("expected hex bytes32 value") from exc


def payment_payee_record(recipient_address: str, payment_record: str) -> str:
    """Match Solidity sha256(abi.encodePacked(address, bytes32))."""
    return hashlib.sha256(_address_bytes(recipient_address) + _bytes32(payment_record)).hexdigest()


def duplicate_leaf(duplicate_key: str) -> str:
    return digest_hex("duplicate_leaf", [duplicate_key])


@dataclass(frozen=True)
class ClaimLeafSet:
    claim_leaf: str
    result_leaf: str
    duplicate_leaf: str
    duplicate_check_key: str
    duplicate_nullifier: int
    poseidon_status: str = POSEIDON_STATUS


def build_claim_leaf_set(
    ctx: SharedContext,
    result: AdjudicationResult,
    ruleset_version: str,
    frequency_type: str,
    engine_mode: str = "engine_unbound",
    pepper: str | None = None,
) -> ClaimLeafSet:
    duplicate_key = duplicate_check_key(ctx, frequency_type, pepper)
    return ClaimLeafSet(
        claim_leaf=claim_leaf(ctx, duplicate_key, ruleset_version),
        result_leaf=result_leaf(ctx, result, duplicate_key, ruleset_version, engine_mode),
        duplicate_leaf=duplicate_leaf(duplicate_key),
        duplicate_check_key=duplicate_key,
        duplicate_nullifier=duplicate_check_nullifier(ctx, frequency_type, pepper),
    )
