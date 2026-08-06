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

_PRIVACY_V2_PUBLIC_OUTPUT_FIELDS = (
    ("protocolVersion", "protocol_version"),
    ("settlementDomain", "settlement_domain"),
    ("batchNonce", "batch_nonce"),
    ("nullifierRootBefore", "nullifier_root_before"),
    ("nullifierRootAfter", "nullifier_root_after"),
    ("claimSourceRoot", "claim_source_root"),
    ("oracleFactsRoot", "oracle_facts_root"),
    ("policyRoot", "policy_root"),
    ("rulesetRoot", "ruleset_root"),
    ("opaqueBatchCommitment", "opaque_batch_commitment"),
    ("valueConservationCommitment", "value_conservation_commitment"),
    ("settlementCommitment", "settlement_commitment"),
)
_PRIVACY_V2_PUBLIC_OUTPUT_KEYS = tuple(
    key for _, key in _PRIVACY_V2_PUBLIC_OUTPUT_FIELDS
)
_PRIVACY_V2_BUNDLE_KEYS = (
    "entrypoint",
    "witness",
    "serialized_arguments",
    "serialized_arguments_hex_json",
    "expected_output",
)


def generate_privacy_v2_salts() -> tuple[int, int]:
    """Return distinct, nonzero Stark-field salts from the operating-system CSPRNG."""
    privacy_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    value_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    while value_salt == privacy_salt:
        value_salt = secrets.randbelow(FIELD_MODULUS - 1) + 1
    return privacy_salt, value_salt


def _felt(name: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int:
        raise ValueError(f"privacy_v2_{name}_not_exact_integer")
    integer = value
    if integer < 0 or integer >= FIELD_MODULUS:
        raise ValueError(f"privacy_v2_{name}_not_field_element")
    if nonzero and integer == 0:
        raise ValueError(f"privacy_v2_{name}_must_be_nonzero")
    return integer


def privacy_v2_public_receipt(output: Mapping[str, Any]) -> dict[str, int]:
    """Return only the ordered public V2 receipt fields.

    The returned insertion order is the external 12-field order.  The helper
    rejects missing, extra, reordered, noncanonical, or private fields before
    constructing the receipt, so callers cannot accidentally publish a V1
    amount/count payload as a V2 public statement.
    """
    if not isinstance(output, Mapping):
        raise TypeError("privacy_v2_public_output_mapping_required")
    if tuple(output) != _PRIVACY_V2_PUBLIC_OUTPUT_KEYS:
        raise ValueError("privacy_v2_public_output_schema_mismatch")
    receipt = {
        public_name: _felt(public_name, output[private_key])
        for public_name, private_key in _PRIVACY_V2_PUBLIC_OUTPUT_FIELDS
    }
    if receipt["protocolVersion"] != PRIVACY_V2_PROTOCOL_VERSION:
        raise ValueError("privacy_v2_public_protocol_version_mismatch")
    if receipt["settlementDomain"] == 0:
        raise ValueError("privacy_v2_public_settlement_domain_zero")
    if receipt["batchNonce"] == 0:
        raise ValueError("privacy_v2_public_batch_nonce_zero")
    return receipt


def build_privacy_v2_bundle(
    batch_bundle: Mapping[str, Any],
    *,
    settlement_domain: int,
    batch_nonce: int,
    private_data_commitment: int,
    privacy_salt: int,
    value_salt: int,
) -> dict[str, Any]:
    if not isinstance(batch_bundle, Mapping):
        raise TypeError("privacy_v2_batch_bundle_mapping_required")
    witness = batch_bundle["witness"]
    output = batch_bundle["expected_output"]
    if not isinstance(output, Mapping):
        raise TypeError("privacy_v2_batch_output_mapping_required")
    domain = _felt("settlement_domain", settlement_domain, nonzero=True)
    nonce = _felt("batch_nonce", batch_nonce, nonzero=True)
    private_data = _felt("private_data_commitment", private_data_commitment, nonzero=True)
    privacy = _felt("privacy_salt", privacy_salt, nonzero=True)
    value = _felt("value_salt", value_salt, nonzero=True)
    if type(output["total_allowed_cents"]) is not int:
        raise ValueError("privacy_v2_total_allowed_not_exact_integer")
    if type(output["total_payment_cents"]) is not int:
        raise ValueError("privacy_v2_total_payment_not_exact_integer")
    total_allowed = output["total_allowed_cents"]
    total_payment = output["total_payment_cents"]
    if total_allowed < 0 or total_payment < 0:
        raise ValueError("privacy_v2_total_not_nonnegative")
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
    bundle = {
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
    privacy_v2_public_receipt(expected_output)
    return bundle


def verify_privacy_v2_bundle(
    batch_bundle: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    settlement_domain: int,
    batch_nonce: int,
    private_data_commitment: int,
    privacy_salt: int,
    value_salt: int,
) -> bool:
    """Recompute and verify a local V2 bundle without exposing private data.

    The verifier receives private witness context only at the local boundary;
    its public result is a boolean and the separate receipt helper exposes
    exactly the ordered twelve public fields.  Every serialized wrapper and
    private witness component is compared to a fresh recomputation, making a
    splice, stale salt, changed witness, or reordered public map fail closed.
    """
    if not isinstance(bundle, Mapping):
        raise TypeError("privacy_v2_bundle_mapping_required")
    if tuple(bundle) != _PRIVACY_V2_BUNDLE_KEYS:
        raise ValueError("privacy_v2_bundle_schema_mismatch")
    expected = build_privacy_v2_bundle(
        batch_bundle,
        settlement_domain=settlement_domain,
        batch_nonce=batch_nonce,
        private_data_commitment=private_data_commitment,
        privacy_salt=privacy_salt,
        value_salt=value_salt,
    )
    if bundle["entrypoint"] != expected["entrypoint"]:
        raise ValueError("privacy_v2_entrypoint_mismatch")
    if tuple(bundle["witness"]) != tuple(expected["witness"]):
        raise ValueError("privacy_v2_private_witness_mismatch")
    if bundle["witness"] != expected["witness"]:
        raise ValueError("privacy_v2_private_witness_value_mismatch")
    if list(bundle["serialized_arguments"]) != expected["serialized_arguments"]:
        raise ValueError("privacy_v2_serialized_arguments_mismatch")
    if list(bundle["serialized_arguments_hex_json"]) != expected[
        "serialized_arguments_hex_json"
    ]:
        raise ValueError("privacy_v2_serialized_hex_arguments_mismatch")
    if tuple(bundle["expected_output"]) != _PRIVACY_V2_PUBLIC_OUTPUT_KEYS:
        raise ValueError("privacy_v2_expected_output_schema_mismatch")
    if bundle["expected_output"] != expected["expected_output"]:
        raise ValueError("privacy_v2_expected_output_mismatch")
    privacy_v2_public_receipt(bundle["expected_output"])
    return True


__all__ = [
    "PRIVACY_V2_PROTOCOL_VERSION",
    "PRIVACY_V2_PUBLIC_OUTPUT_NAMES",
    "build_privacy_v2_bundle",
    "generate_privacy_v2_salts",
    "privacy_v2_public_receipt",
    "verify_privacy_v2_bundle",
]
