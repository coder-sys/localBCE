"""Strict whole-product KAT manifest for the local nonactivating boundary.

The manifest is deliberately commitment-only.  It freezes one canonical
schema across semantics, the ordered twelve-field public projection, the
744-byte sidecar, the bounded proof body, state transition, and atomic
receipt without publishing a witness, claim document, private amount, or
decryptable record.
"""

from __future__ import annotations

from hashlib import sha3_512
import json
from typing import Final

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2


SCHEMA: Final[str] = "blind-ledger-whole-product-kat-v1"
STATUS: Final[str] = "SYNTHETIC_NONACTIVATING_WHOLE_PRODUCT_KAT"
PROOF_GRAMMAR: Final[str] = "BLPQPF01"
SIDECAR_BYTES: Final[int] = 744
PROOF_BODY_BYTES: Final[int] = 696
EXPECTED_CASE_COUNT: Final[int] = 6
MAX_MANIFEST_BYTES: Final[int] = 128 * 1024
PROFILE_CAPACITIES: Final[dict[str, int]] = {"K128": 128, "K512": 512}
OUTCOMES: Final[frozenset[str]] = frozenset({"APPROVAL", "DENIAL", "COVER"})
_DOMAIN: Final[bytes] = b"BL/PQ512/WHOLE-PRODUCT-KAT/v1\x00"
_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {"activationAllowed", "cases", "fieldNames", "proofSuiteId", "schema", "status"}
)
_CASE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "caseId",
        "outcome",
        "profile",
        "publicFields",
        "semanticDigestSha3_512",
        "sidecar",
        "state",
        "proof",
        "receipt",
    }
)
_SIDECAR_KEYS: Final[frozenset[str]] = frozenset({"byteLength", "sha3_512"})
_STATE_KEYS: Final[frozenset[str]] = frozenset(
    {"beforeSha3_512", "afterSha3_512", "transitionSha3_512"}
)
_PROOF_KEYS: Final[frozenset[str]] = frozenset(
    {"bodyByteLength", "grammar", "sha3_512"}
)
_RECEIPT_KEYS: Final[frozenset[str]] = frozenset({"byteLength", "sha3_512"})


class WholeProductVectorError(ValueError):
    """Fail-closed error for the commitment-only whole-product corpus."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WholeProductVectorError("whole_product_vector_duplicate_key")
        result[key] = value
    return result


def canonical_manifest_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise WholeProductVectorError("whole_product_vector_not_canonicalizable") from exc


def _digest(label: str, *parts: str) -> str:
    digest = sha3_512(_DOMAIN + len(label).to_bytes(2, "big") + label.encode("ascii"))
    for part in parts:
        encoded = part.encode("ascii")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _hex_digest(label: str, value: object) -> None:
    if type(value) is not str or len(value) != 128:
        raise WholeProductVectorError(f"whole_product_vector_{label}_digest_invalid")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise WholeProductVectorError(f"whole_product_vector_{label}_digest_invalid") from exc
    if len(decoded) != 64 or not any(decoded):
        raise WholeProductVectorError(f"whole_product_vector_{label}_digest_invalid")


def _field(value: object, index: int) -> None:
    if type(value) is not str or len(value) != 64:
        raise WholeProductVectorError(f"whole_product_vector_field_{index}_invalid")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise WholeProductVectorError(f"whole_product_vector_field_{index}_invalid") from exc
    if len(decoded) != 32 or not any(decoded):
        raise WholeProductVectorError(f"whole_product_vector_field_{index}_invalid")


def expected_case(case_id: str, profile: str, outcome: str) -> dict[str, object]:
    """Derive the public commitment vector for one synthetic shape case."""

    fields = [
        _digest("public-field", case_id, profile, outcome, str(index))[:64]
        for index in range(len(PUBLIC_INPUT_FIELD_NAMES_V2))
    ]
    semantic = _digest("semantic", case_id, profile, outcome)
    sidecar_digest = _digest("sidecar", case_id, profile, outcome)
    state_before = _digest("state-before", case_id, profile, outcome)
    state_after = _digest("state-after", case_id, profile, outcome)
    transition = _digest("state-transition", state_before, state_after)
    proof_digest = _digest("proof-body", case_id, profile, outcome, PROOF_GRAMMAR)
    receipt_digest = _digest(
        "atomic-receipt",
        semantic,
        sidecar_digest,
        transition,
        proof_digest,
    )
    return {
        "caseId": case_id,
        "outcome": outcome,
        "profile": profile,
        "publicFields": fields,
        "semanticDigestSha3_512": semantic,
        "sidecar": {"byteLength": SIDECAR_BYTES, "sha3_512": sidecar_digest},
        "state": {
            "beforeSha3_512": state_before,
            "afterSha3_512": state_after,
            "transitionSha3_512": transition,
        },
        "proof": {
            "bodyByteLength": PROOF_BODY_BYTES,
            "grammar": PROOF_GRAMMAR,
            "sha3_512": proof_digest,
        },
        "receipt": {"byteLength": 64, "sha3_512": receipt_digest},
    }


def _check_exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise WholeProductVectorError(f"whole_product_vector_{label}_keys_invalid")
    return value


def parse_manifest(encoded: bytes) -> dict[str, object]:
    if type(encoded) is not bytes:
        raise TypeError("whole_product_vector_manifest_must_be_bytes")
    if not encoded or len(encoded) > MAX_MANIFEST_BYTES:
        raise WholeProductVectorError("whole_product_vector_manifest_size_invalid")
    try:
        value = json.loads(encoded, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WholeProductVectorError("whole_product_vector_json_invalid") from exc
    top = _check_exact_keys(value, _TOP_KEYS, "top")
    if canonical_manifest_bytes(top) != encoded:
        raise WholeProductVectorError("whole_product_vector_not_canonical")
    if (
        top["schema"] != SCHEMA
        or top["status"] != STATUS
        or top["proofSuiteId"] is not None
        or top["activationAllowed"] is not False
    ):
        raise WholeProductVectorError("whole_product_vector_identity_invalid")
    if top["fieldNames"] != list(PUBLIC_INPUT_FIELD_NAMES_V2):
        raise WholeProductVectorError("whole_product_vector_field_names_invalid")
    cases = top["cases"]
    if type(cases) is not list or len(cases) != EXPECTED_CASE_COUNT:
        raise WholeProductVectorError("whole_product_vector_case_count_invalid")
    seen: set[str] = set()
    for case in cases:
        record = _check_exact_keys(case, _CASE_KEYS, "case")
        case_id = record["caseId"]
        profile = record["profile"]
        outcome = record["outcome"]
        if (
            type(case_id) is not str
            or not case_id.startswith("KAT-")
            or case_id in seen
            or type(profile) is not str
            or profile not in PROFILE_CAPACITIES
            or type(outcome) is not str
            or outcome not in OUTCOMES
        ):
            raise WholeProductVectorError("whole_product_vector_case_identity_invalid")
        seen.add(case_id)
        fields = record["publicFields"]
        if type(fields) is not list or len(fields) != len(PUBLIC_INPUT_FIELD_NAMES_V2):
            raise WholeProductVectorError("whole_product_vector_public_field_count_invalid")
        for index, field in enumerate(fields):
            _field(field, index)
        _hex_digest("semantic", record["semanticDigestSha3_512"])
        sidecar = _check_exact_keys(record["sidecar"], _SIDECAR_KEYS, "sidecar")
        if sidecar["byteLength"] != SIDECAR_BYTES:
            raise WholeProductVectorError("whole_product_vector_sidecar_length_invalid")
        _hex_digest("sidecar", sidecar["sha3_512"])
        state = _check_exact_keys(record["state"], _STATE_KEYS, "state")
        for label in _STATE_KEYS:
            _hex_digest(f"state_{label}", state[label])
        proof = _check_exact_keys(record["proof"], _PROOF_KEYS, "proof")
        if proof["bodyByteLength"] != PROOF_BODY_BYTES or proof["grammar"] != PROOF_GRAMMAR:
            raise WholeProductVectorError("whole_product_vector_proof_identity_invalid")
        _hex_digest("proof", proof["sha3_512"])
        receipt = _check_exact_keys(record["receipt"], _RECEIPT_KEYS, "receipt")
        if receipt["byteLength"] != 64:
            raise WholeProductVectorError("whole_product_vector_receipt_length_invalid")
        _hex_digest("receipt", receipt["sha3_512"])
        if record != expected_case(case_id, profile, outcome):
            raise WholeProductVectorError("whole_product_vector_expected_value_mismatch")
    expected_ids = {
        f"KAT-{profile}-{outcome}"
        for profile in PROFILE_CAPACITIES
        for outcome in OUTCOMES
    }
    if seen != expected_ids:
        raise WholeProductVectorError("whole_product_vector_case_inventory_invalid")
    return top


def manifest_sha3_512(encoded: bytes) -> str:
    parse_manifest(encoded)
    return sha3_512(encoded).hexdigest()


__all__: tuple[str, ...] = (
    "EXPECTED_CASE_COUNT",
    "PROOF_BODY_BYTES",
    "PROOF_GRAMMAR",
    "PROFILE_CAPACITIES",
    "SCHEMA",
    "SIDECAR_BYTES",
    "STATUS",
    "WholeProductVectorError",
    "canonical_manifest_bytes",
    "expected_case",
    "manifest_sha3_512",
    "parse_manifest",
)
