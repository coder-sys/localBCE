"""Strict parser for the small synthetic R25 semantic-vector manifest."""

from __future__ import annotations

from hashlib import sha3_512
import json
from typing import Final


CORPUS_SCHEMA: Final[str] = "blind-ledger-bl-pq512-r25-vector-v1"
CORPUS_STATUS: Final[str] = "SYNTHETIC_NONACTIVATING_R25_REFERENCE"
PRIVACY_V2_ABI_SHA256: Final[str] = (
    "e65fb5866c400cee295dde80bd4996b01bb0f0077dcfa313e04b7b8d50d92bbd"
)
EXPECTED_CASE_COUNT: Final[int] = 20
EXPECTED_CORPUS_SHA3_512: Final[str] = (
    "f2b76eecb1a124a06370d2c75a4fbd6fa79c113952ed078e9cbebc12f10b6397"
    "aa6c1b7f7694f0e2e932be33f44157e87aa87a2655a9ae1c55253e677d385083"
)
MAX_CORPUS_BYTES: Final[int] = 64 * 1024
_TOP_KEYS: Final[frozenset[str]] = frozenset(
    {
        "activationAllowed",
        "abiSha256",
        "cases",
        "generation",
        "proofSuiteId",
        "schema",
        "status",
    }
)
_CASE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "allowedCents",
        "caseId",
        "decision",
        "failureCode",
        "kind",
        "mutation",
        "patientResponsibilityCents",
        "paymentCents",
    }
)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("r25_vector_duplicate_json_key")
        result[key] = value
    return result


def canonical_corpus_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def parse_r25_vector_corpus(encoded: bytes) -> dict[str, object]:
    if type(encoded) is not bytes:
        raise TypeError("r25_vector_corpus_must_be_bytes")
    if len(encoded) == 0 or len(encoded) > MAX_CORPUS_BYTES:
        raise ValueError("r25_vector_corpus_size_invalid")
    try:
        value = json.loads(encoded, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("r25_vector_corpus_json_invalid") from exc
    if type(value) is not dict or set(value) != _TOP_KEYS:
        raise ValueError("r25_vector_corpus_keys_invalid")
    if canonical_corpus_bytes(value) != encoded:
        raise ValueError("r25_vector_corpus_not_canonical_json")
    if value["schema"] != CORPUS_SCHEMA or value["status"] != CORPUS_STATUS:
        raise ValueError("r25_vector_corpus_identity_invalid")
    if value["abiSha256"] != PRIVACY_V2_ABI_SHA256:
        raise ValueError("r25_vector_corpus_abi_hash_mismatch")
    if value["proofSuiteId"] is not None or value["activationAllowed"] is not False:
        raise ValueError("r25_vector_corpus_activation_boundary_invalid")
    generation = value["generation"]
    if generation != {
        "failureSubsets": 8191,
        "k256Placements": 3840,
        "profiles": [128, 256, 512],
    }:
        raise ValueError("r25_vector_generation_inventory_invalid")
    cases = value["cases"]
    if type(cases) is not list or len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError("r25_vector_case_count_invalid")
    case_ids: list[str] = []
    for case in cases:
        if type(case) is not dict or set(case) != _CASE_KEYS:
            raise ValueError("r25_vector_case_keys_invalid")
        case_id = case["caseId"]
        if type(case_id) is not str or not case_id.startswith("R25-"):
            raise ValueError("r25_vector_case_id_invalid")
        case_ids.append(case_id)
        for label, maximum in (
            ("decision", 1),
            ("failureCode", 13),
            ("allowedCents", (1 << 32) - 1),
            ("patientResponsibilityCents", (1 << 32) - 1),
            ("paymentCents", (1 << 32) - 1),
        ):
            amount = case[label]
            if type(amount) is not int or amount < 0 or amount > maximum:
                raise ValueError(f"r25_vector_case_{label}_invalid")
        if case["decision"] == 1:
            if case["failureCode"] != 0 or case["allowedCents"] != (
                case["patientResponsibilityCents"] + case["paymentCents"]
            ):
                raise ValueError("r25_vector_approval_relation_invalid")
        elif case["allowedCents"] != 0 or case["paymentCents"] != 0:
            raise ValueError("r25_vector_nonapproval_economics_invalid")
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("r25_vector_case_id_duplicate")
    return value


def corpus_sha3_512(encoded: bytes) -> str:
    parse_r25_vector_corpus(encoded)
    observed = sha3_512(encoded).hexdigest()
    if observed != EXPECTED_CORPUS_SHA3_512:
        raise ValueError("r25_vector_corpus_digest_mismatch")
    return observed
