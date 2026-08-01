from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from experiments.fixed_shape_claim_air.vector_corpus import (
    EXPECTED_CASE_COUNT,
    EXPECTED_CORPUS_SHA3_512,
    corpus_sha3_512,
    parse_r25_vector_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "test_data" / "bl_pq512_r25_vectors_v1.json"
SCHEMA = ROOT / "schemas" / "bl_pq512_r25_vector_v1.schema.json"


def test_corpus_is_canonical_strict_nonactivating_and_abi_pinned() -> None:
    encoded = CORPUS.read_bytes()
    value = parse_r25_vector_corpus(encoded)
    assert len(value["cases"]) == EXPECTED_CASE_COUNT
    assert value["proofSuiteId"] is None
    assert value["activationAllowed"] is False
    assert corpus_sha3_512(encoded) == EXPECTED_CORPUS_SHA3_512
    schema = json.loads(SCHEMA.read_bytes())
    assert schema["properties"]["proofSuiteId"] == {"type": "null"}
    assert schema["properties"]["activationAllowed"] == {"const": False}


def test_parser_rejects_duplicate_keys_noncanonical_bytes_and_activation() -> None:
    encoded = CORPUS.read_bytes()
    with pytest.raises(ValueError, match="duplicate_json_key"):
        parse_r25_vector_corpus(
            encoded.replace(
                b'{"abiSha256":',
                b'{"abiSha256":"x","abiSha256":',
                1,
            )
        )
    with pytest.raises(ValueError, match="not_canonical_json"):
        parse_r25_vector_corpus(encoded.replace(b'"activationAllowed":false', b'"activationAllowed": false'))
    value = parse_r25_vector_corpus(encoded)
    value["activationAllowed"] = True
    mutated = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    with pytest.raises(ValueError, match="activation_boundary_invalid"):
        parse_r25_vector_corpus(mutated)


def test_every_named_case_has_unique_id_and_exact_economic_relation() -> None:
    cases = parse_r25_vector_corpus(CORPUS.read_bytes())["cases"]
    assert len({case["caseId"] for case in cases}) == EXPECTED_CASE_COUNT
    for case in cases:
        if case["decision"] == 1:
            assert case["allowedCents"] == (
                case["patientResponsibilityCents"] + case["paymentCents"]
            )
        else:
            assert case["allowedCents"] == case["paymentCents"] == 0
