from __future__ import annotations

import json

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_tree_reference import PUBLIC_OUTPUT_NAMES
from app.multipart_ascii import encode_multipart_ascii64
from experiments.fixed_shape_claim_air.witness_schema_reference import (
    FACT_IDS,
    UNVERIFIED_CRYPTOGRAPHIC_SURFACES,
    WitnessSchemaError,
    parse_structural_witness_json,
)


def _felt(value: int) -> str:
    return f"0x{value:064x}"


def _wide(value: int) -> str:
    return f"0x{value:0128x}"


def _multipart(value: str) -> dict[str, object]:
    return encode_multipart_ascii64(
        value, label="fixture", allow_empty=not value
    ).as_json()


def _policy(*, enabled: bool) -> dict[str, object]:
    return {
        "policy_present": enabled,
        "row_kind": 1 if enabled else 0,
        "procedure_code": "T1019" if enabled else "",
        "allowed_cents": 100 if enabled else 0,
        "requires_prior_authorization": False,
        "policy_leaf_index": 1 if enabled else 0,
        "next_procedure_code": "T1020" if enabled else "",
        "next_policy_leaf_index": 2 if enabled else 0,
        "legacy_path": [_felt(0)] * 16,
        "wide_path": [_wide(0)] * 16,
    }


def _line(index: int, *, enabled: bool) -> dict[str, object]:
    return {
        "enabled": enabled,
        "line_slot": index,
        "original_line_index": 0,
        "line_id": _multipart("LINE-A" if enabled else ""),
        "procedure_code": "T1019" if enabled else "",
        "charge_cents": 100 if enabled else 0,
        "units_cents": 1 if enabled else 0,
        "prior_authorization": _multipart(""),
        "policy_evidence": _policy(enabled=enabled),
    }


def _authorization(index: int) -> dict[str, object]:
    return {
        "authorization_slot": index,
        "required_by_policy": False,
        "authorization_present": False,
        "valid_from_day": 0,
        "valid_until_day": 0,
        "authorization_token": _multipart(""),
        "legacy_oracle_leaf": _felt(0),
        "wide_oracle_leaf": _wide(0),
    }


def _legacy_transition(index: int) -> dict[str, object]:
    return {
        "root_before": _felt(5_000 + index),
        "root_after": _felt(5_001 + index),
        "predecessor_value": _felt(index + 1),
        "successor_value": _felt(index + 2),
        "predecessor_index": index,
        "successor_index": index + 1,
        "inserted_index": index + 1_000,
        "predecessor_path": [_felt(0)] * 32,
        "insertion_path": [_felt(0)] * 32,
    }


def _strong_transition(index: int) -> dict[str, object]:
    return {
        "root_before": _wide(6_000 + index),
        "root_after": _wide(6_001 + index),
        "predecessor_value": _wide(index + 1),
        "successor_value": _wide(index + 2),
        "predecessor_index": index,
        "successor_index": index + 1,
        "inserted_index": index + 2_000,
        "predecessor_path": [_wide(0)] * 64,
        "insertion_path": [_wide(0)] * 64,
    }


def _slot(index: int, *, real: bool) -> dict[str, object]:
    fact_values = (True, True, True, True, False, False) if real else (False,) * 6
    return {
        "slot_index": index,
        "slot_kind": "REAL" if real else "COVER",
        "source_sequence": 1 if real else 0,
        "decision": 1 if real else 0,
        "failure_code": 0,
        "private_slot_salt_512": _wide(10_000 + index),
        "legacy_attempt_nullifier": _felt(20_000 + index),
        "strong_attempt_nullifier_512": _wide(30_000 + index),
        "claim_record_commitment_512": _wide(40_000 + index),
        "allowed_cents": 100 if real else 0,
        "payment_cents": 80 if real else 0,
        "claim_header": {
            "source_authority_id": _multipart("BL-SYNTH-GOV-INTAKE-V1" if real else ""),
            "claim_id": _multipart("BL-SYNTH-CLAIM-0001" if real else ""),
            "member_id": _multipart("SYNTH-MEMBER-001" if real else ""),
            "provider_npi": "1999999984" if real else "",
            "service_date_day": 20_000 if real else 0,
            "attempt_version": 1 if real else 0,
            "revision_kind": 1 if real else 0,
            "parent_attempt_version": 0,
            "diagnosis_count": 1 if real else 0,
            "service_line_count": 1 if real else 0,
            "total_charge_cents": 100 if real else 0,
            "legacy_claim_source_leaf": _felt(50_000 + index),
            "wide_claim_source_leaf": _wide(60_000 + index),
            "legacy_claim_facts_leaf": _felt(70_000 + index),
            "wide_claim_facts_leaf": _wide(80_000 + index),
        },
        "diagnoses": [
            {
                "enabled": real and position == 0,
                "diagnosis_slot": position,
                "diagnosis_code": "F840" if real and position == 0 else "",
            }
            for position in range(16)
        ],
        "claim_facts": [
            {
                "fact_slot": position,
                "fact_id": fact_id,
                "value": fact_values[position],
                "verified": True,
                "attestation_commitment_512": _wide(
                    90_000 + index * 10 + position
                ),
            }
            for position, fact_id in enumerate(FACT_IDS)
        ],
        "service_lines": [
            _line(position, enabled=real and position == 0)
            for position in range(50)
        ],
        "authorizations": [
            _authorization(position) for position in range(50)
        ],
        "legacy_nullifier_transition": _legacy_transition(index),
        "strong_nullifier_transition": _strong_transition(index),
    }


@pytest.fixture(scope="module")
def document() -> dict[str, object]:
    public = [
        {
            "index": index,
            "name": name,
            "felt": _felt(
                5_000
                if index == 3
                else 5_128
                if index == 4
                else index + 1
            ),
        }
        for index, name in enumerate(PUBLIC_OUTPUT_NAMES)
    ]
    return {
        "schema_id": "BL-PQ512-WITNESS-SYNTHETIC-FOUNDATION-v0",
        "status": "SYNTHETIC_ONLY_NOT_FOR_PRODUCTION",
        "synthetic_only": True,
        "production_frozen": False,
        "provisional_profile_digest_512": _wide(123),
        "capacity_profile": {
            "profile_id": "K128_CALIBRATION",
            "batch_claim_slots": 128,
            "service_lines_per_claim": 50,
            "diagnoses_per_claim": 16,
            "claim_facts_per_claim": 6,
            "authorizations_per_claim": 50,
            "claim_source_tree_depth": 7,
            "oracle_tree_depth": 13,
            "policy_tree_depth": 16,
            "policy_real_row_capacity": 65_533,
            "legacy_nullifier_tree_depth": 32,
            "strong_nullifier_tree_depth": 64,
        },
        "public_statement": public,
        "claim_slots": [
            _slot(index, real=index == 0) for index in range(128)
        ],
    }


@pytest.fixture(scope="module")
def raw(document) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


@pytest.fixture(scope="module")
def parsed(raw):
    return parse_structural_witness_json(raw)


def _replace_slot(
    document: dict[str, object], index: int, slot: dict[str, object]
) -> dict[str, object]:
    changed = dict(document)
    slots = list(document["claim_slots"])
    slots[index] = slot
    changed["claim_slots"] = slots
    return changed


def test_structural_decoder_executes_fixed_shape_and_money_relations(
    raw, parsed
) -> None:
    assert parsed.raw_json_bytes == len(raw)
    assert parsed.profile.profile_id == "K128_CALIBRATION"
    assert len(parsed.public_statement) == 12
    assert len(parsed.slots) == 128
    assert parsed.slots[0].slot_kind.value == "REAL"
    assert parsed.slots[0].patient_responsibility_cents == 20
    assert parsed.slots[-1].slot_kind.value == "COVER"
    assert parsed.synthetic_only is True
    assert parsed.production_frozen is False
    assert parsed.cryptographic_artifacts_authenticated is False
    assert parsed.unverified_cryptographic_surfaces == UNVERIFIED_CRYPTOGRAPHIC_SURFACES


def test_structural_decoder_rejects_duplicate_keys_and_noninteger_json_numbers() -> None:
    with pytest.raises(WitnessSchemaError, match="duplicate_key:schema_id"):
        parse_structural_witness_json(
            b'{"schema_id":"A","schema_id":"B"}'
        )
    with pytest.raises(WitnessSchemaError, match="non_integer_number"):
        parse_structural_witness_json(b'{"value":1.0}')


def test_schema_rejects_unknown_nested_fields(document) -> None:
    first = dict(document["claim_slots"][0])
    lines = list(first["service_lines"])
    enabled = dict(lines[0])
    enabled["unreviewed"] = True
    lines[0] = enabled
    first["service_lines"] = lines
    changed = _replace_slot(document, 0, first)
    with pytest.raises(WitnessSchemaError, match="extra_unreviewed"):
        parse_structural_witness_json(
            json.dumps(changed, separators=(",", ":")).encode("utf-8")
        )


def test_relational_decoder_rejects_count_and_nullifier_chain_mismatch(document) -> None:
    first = dict(document["claim_slots"][0])
    header = dict(first["claim_header"])
    header["diagnosis_count"] = 2
    first["claim_header"] = header
    changed = _replace_slot(document, 0, first)
    with pytest.raises(WitnessSchemaError, match="diagnosis_count_mismatch"):
        parse_structural_witness_json(
            json.dumps(changed, separators=(",", ":")).encode("utf-8")
        )

    second = dict(document["claim_slots"][1])
    transition = dict(second["legacy_nullifier_transition"])
    transition["root_before"] = _felt(9_999)
    second["legacy_nullifier_transition"] = transition
    changed = _replace_slot(document, 1, second)
    with pytest.raises(WitnessSchemaError, match="legacy_nullifier_chain_mismatch:1"):
        parse_structural_witness_json(
            json.dumps(changed, separators=(",", ":")).encode("utf-8")
        )


def test_semantic_decoder_rejects_felt_outside_stark_field(document) -> None:
    changed = dict(document)
    public = list(document["public_statement"])
    first = dict(public[0])
    first["felt"] = _felt(FIELD_MODULUS)
    public[0] = first
    changed["public_statement"] = public
    with pytest.raises(WitnessSchemaError, match="witness_felt_out_of_field"):
        parse_structural_witness_json(
            json.dumps(changed, separators=(",", ":")).encode("utf-8")
        )


def test_unverified_leaf_mutation_is_declared_not_misreported_as_authenticated(
    document, parsed
) -> None:
    first = dict(document["claim_slots"][0])
    header = dict(first["claim_header"])
    header["wide_claim_source_leaf"] = _wide(123_456)
    first["claim_header"] = header
    changed = _replace_slot(document, 0, first)
    changed_parsed = parse_structural_witness_json(
        json.dumps(changed, separators=(",", ":")).encode("utf-8")
    )
    assert changed_parsed.canonical_interchange_sha3_512 != parsed.canonical_interchange_sha3_512
    assert changed_parsed.cryptographic_artifacts_authenticated is False
    assert "claim_source_leaf_and_membership_path_recomputation" in changed_parsed.unverified_cryptographic_surfaces
