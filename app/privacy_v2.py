"""Privacy V2 claim-proof input and exact public-output construction."""

from __future__ import annotations

from collections.abc import Mapping
import secrets
from typing import Any

from app.batch.poseidon import FIELD_MODULUS, domain_poseidon_hash
from app.batch.stark_binding import flatten_batch_claim_input_witness


PRIVACY_V2_PROTOCOL_VERSION = 2
PRIVACY_V2_PUBLIC_OUTPUT_NAMES = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)


def generate_privacy_v2_salts() -> tuple[int, int]:
    """Return distinct, nonzero Stark-field salts from the operating-system CSPRNG."""
    privacy_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    value_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    while value_salt == privacy_salt:
        value_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    return privacy_salt, value_salt


def _felt(name: str, value: object, *, nonzero: bool = False) -> int:
    integer = int(value)
    if integer < 0 or integer >= FIELD_MODULUS:
        raise ValueError(f"privacy_v2_{name}_not_field_element")
    if nonzero and integer == 0:
        raise ValueError(f"privacy_v2_{name}_must_be_nonzero")
    return integer


def build_privacy_v2_bundle(
    batch_bundle: Mapping[str, Any],
    *,
    settlement_domain: int,
    batch_nonce: int,
    private_data_commitment: int,
    privacy_salt: int,
    value_salt: int,
) -> dict[str, Any]:
    witness = batch_bundle["witness"]
    output = batch_bundle["expected_output"]
    domain = _felt("settlement_domain", settlement_domain, nonzero=True)
    nonce = _felt("batch_nonce", batch_nonce, nonzero=True)
    private_data = _felt("private_data_commitment", private_data_commitment, nonzero=True)
    privacy = _felt("privacy_salt", privacy_salt, nonzero=True)
    value = _felt("value_salt", value_salt, nonzero=True)
    total_allowed = int(output["total_allowed_cents"])
    total_payment = int(output["total_payment_cents"])
    if total_allowed != total_payment:
        raise ValueError("privacy_v2_value_conservation_mismatch")
    batch_commitment = _felt("batch_commitment", output["batch_commitment"])
    opaque_batch_commitment = domain_poseidon_hash(
        "private_batch_v2",
        [nonce, batch_commitment, private_data, privacy, domain],
    )
    value_conservation_commitment = domain_poseidon_hash(
        "value_conservation_v2",
        [total_allowed, total_payment, value, batch_commitment, nonce],
    )
    settlement_commitment = domain_poseidon_hash(
        "settlement_v2",
        [
            PRIVACY_V2_PROTOCOL_VERSION,
            domain,
            nonce,
            opaque_batch_commitment,
            value_conservation_commitment,
        ],
    )
    expected_output = {
        "protocol_version": PRIVACY_V2_PROTOCOL_VERSION,
        "settlement_domain": domain,
        "batch_nonce": nonce,
        "nullifier_root_before": _felt("nullifier_root_before", output["batch_root_before"]),
        "nullifier_root_after": _felt("nullifier_root_after", output["batch_root_after"]),
        "claim_source_root": _felt("claim_source_root", output["claim_source_root"]),
        "oracle_facts_root": _felt("oracle_facts_root", output["oracle_facts_root"]),
        "policy_root": _felt("policy_root", output["policy_root"]),
        "ruleset_root": _felt("ruleset_root", output["ruleset_root"]),
        "opaque_batch_commitment": opaque_batch_commitment,
        "value_conservation_commitment": value_conservation_commitment,
        "settlement_commitment": settlement_commitment,
    }
    serialized = [domain, nonce, private_data, privacy, value]
    serialized.extend(flatten_batch_claim_input_witness(witness))
    return {
        "entrypoint": "blind_ledger_cairo_adjudication::batch_main_v2",
        "witness": {
            "settlement_domain": domain,
            "batch_nonce": nonce,
            "private_data_commitment": private_data,
            "privacy_salt": privacy,
            "value_salt": value,
            "batch": witness,
        },
        "serialized_arguments": [str(item) for item in serialized],
        "serialized_arguments_hex_json": [hex(item) for item in serialized],
        "expected_output": expected_output,
    }
