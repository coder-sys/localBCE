from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.multipart_ascii import (
    MultipartAscii64,
    decode_multipart_ascii64,
    encode_multipart_ascii64,
    parse_multipart_ascii64_json,
    require_unique_multipart_ascii64,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "bl_pq512_witness_v0.schema.json"
DOC_PATH = ROOT / "docs" / "FIXED_SHAPE_CLAIM_AIR_DRAFT.md"
POLICY_PATH = ROOT / "ops" / "policy_spec_v1.yaml"
ABI_PATH = ROOT / "ops" / "native_stark_public_inputs_v2.json"

EXPECTED_ABI = [
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
]

EXPECTED_GATES = [
    (1, "G1_MEMBER_ID_PRESENT", "member_id_missing"),
    (2, "G2_ELIGIBILITY_ACTIVE", "eligibility_inactive"),
    (3, "G2B_PATIENT_NOT_DECEASED", "patient_deceased"),
    (4, "G3_PROVIDER_NPI_PRESENT", "provider_npi_missing"),
    (5, "G4_PROVIDER_ENROLLED", "provider_not_enrolled"),
    (6, "G4B_PROVIDER_NOT_SUSPENDED", "provider_suspended"),
    (7, "G5_SERVICE_LINES_PRESENT", "service_line_missing"),
    (8, "G6_DIAGNOSIS_PRESENT", "diagnosis_missing"),
    (9, "G7_PRIOR_AUTH_WHEN_REQUIRED", "prior_authorization_required"),
    (10, "G8A_CHARGE_VALID", "invalid_charge"),
    (11, "G8B_FEE_SCHEDULE_PRESENT", "fee_schedule_missing"),
    (12, "G9_NOT_DUPLICATE", "duplicate_claim"),
    (13, "G10_NO_PROGRAM_INTEGRITY_HOLD", "program_integrity_hold"),
]


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _walk(value: object, path: str = "$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _require_exact_object_keys(schema_node: dict, instance: dict) -> None:
    required = set(schema_node["required"])
    properties = set(schema_node["properties"])
    missing = required - set(instance)
    extras = set(instance) - properties
    if missing:
        raise ValueError(f"missing:{','.join(sorted(missing))}")
    if extras:
        raise ValueError(f"extra:{','.join(sorted(extras))}")


def _prefix_item_identity(item: dict) -> tuple[int, str]:
    constraint = item["allOf"][1]["properties"]
    return constraint["index"]["const"], constraint["name"]["const"]


def test_schema_is_parseable_synthetic_v0_and_never_a_production_freeze() -> None:
    schema = _schema()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_id"]["const"] == (
        "BL-PQ512-WITNESS-SYNTHETIC-FOUNDATION-v0"
    )
    assert schema["properties"]["status"]["const"] == "SYNTHETIC_ONLY_NOT_FOR_PRODUCTION"
    assert schema["properties"]["synthetic_only"]["const"] is True
    assert schema["properties"]["production_frozen"]["const"] is False


def test_every_complete_object_schema_rejects_missing_and_extra_properties() -> None:
    schema = _schema()
    checked = 0
    for path, node in _walk(schema):
        if not isinstance(node, dict) or node.get("type") != "object" or "properties" not in node:
            continue
        checked += 1
        assert node.get("additionalProperties") is False, path
        assert node.get("required") == list(node["properties"]), path

    assert checked >= 12

    diagnosis = schema["$defs"]["diagnosis_slot"]
    valid_keys = {"enabled": True, "diagnosis_slot": 0, "diagnosis_code": "F840"}
    _require_exact_object_keys(diagnosis, valid_keys)

    missing = dict(valid_keys)
    missing.pop("diagnosis_code")
    with pytest.raises(ValueError, match="missing:diagnosis_code"):
        _require_exact_object_keys(diagnosis, missing)

    extra = {**valid_keys, "unreviewed": "forbidden"}
    with pytest.raises(ValueError, match="extra:unreviewed"):
        _require_exact_object_keys(diagnosis, extra)


def test_capacity_profiles_couple_k_to_independent_tree_depths() -> None:
    schema = _schema()
    capacity = schema["$defs"]["capacity_profile"]["properties"]

    assert capacity["service_lines_per_claim"]["const"] == 50
    assert capacity["diagnoses_per_claim"]["const"] == 16
    assert capacity["claim_facts_per_claim"]["const"] == 6
    assert capacity["authorizations_per_claim"]["const"] == 50
    assert capacity["policy_tree_depth"]["const"] == 16
    assert capacity["policy_real_row_capacity"]["const"] == 65_533
    assert capacity["legacy_nullifier_tree_depth"]["const"] == 32
    assert capacity["strong_nullifier_tree_depth"]["const"] == 64

    observed: dict[str, tuple[int, int, int]] = {}
    for branch in schema["allOf"]:
        profile = branch["if"]["properties"]["capacity_profile"]["properties"]["profile_id"]["const"]
        profile_then = branch["then"]["properties"]["capacity_profile"]["properties"]
        slots_then = branch["then"]["properties"]["claim_slots"]
        assert slots_then["minItems"] == slots_then["maxItems"]
        assert slots_then["minItems"] == profile_then["batch_claim_slots"]["const"]
        observed[profile] = (
            slots_then["minItems"],
            profile_then["claim_source_tree_depth"]["const"],
            profile_then["oracle_tree_depth"]["const"],
        )

    assert observed == {
        "K128_CALIBRATION": (128, 7, 13),
        "K256_DESIGN_POINT": (256, 8, 14),
        "K512_CALIBRATION": (512, 9, 15),
    }


def test_inner_tables_and_paths_are_fixed_width() -> None:
    defs = _schema()["$defs"]
    slot_properties = defs["claim_slot"]["properties"]

    for field, length in (("diagnoses", 16), ("service_lines", 50), ("authorizations", 50)):
        assert slot_properties[field]["minItems"] == length
        assert slot_properties[field]["maxItems"] == length

    assert defs["claim_facts"]["minItems"] == defs["claim_facts"]["maxItems"] == 6
    assert defs["legacy_policy_path"]["minItems"] == defs["legacy_policy_path"]["maxItems"] == 16
    assert defs["wide_policy_path"]["minItems"] == defs["wide_policy_path"]["maxItems"] == 16
    assert defs["legacy_nullifier_path"]["minItems"] == defs["legacy_nullifier_path"]["maxItems"] == 32
    assert defs["strong_nullifier_path"]["minItems"] == defs["strong_nullifier_path"]["maxItems"] == 64


def test_private_money_uses_the_shared_exact_u32_boundary() -> None:
    private_cents = _schema()["$defs"]["private_cents"]
    assert private_cents == {
        "type": "integer",
        "minimum": 0,
        "maximum": 4_294_967_295,
    }


def test_proof_bound_identifiers_use_exact_three_part_64_byte_encoding() -> None:
    defs = _schema()["$defs"]
    multipart = defs["multipart_ascii_64"]
    assert "bounded_token_31" not in defs
    assert multipart["properties"]["byte_length"]["maximum"] == 64
    assert multipart["properties"]["parts"]["minItems"] == 3
    assert multipart["properties"]["parts"]["maxItems"] == 3
    assert multipart["properties"]["parts"]["items"] is False

    header = defs["claim_header"]["properties"]
    for field in ("source_authority_id", "claim_id", "member_id"):
        assert header[field]["$ref"] == "#/$defs/multipart_ascii_64"
    line = defs["service_line_slot"]
    assert "line_id" in line["required"]
    assert line["properties"]["line_id"]["$ref"] == "#/$defs/multipart_ascii_64"
    assert line["properties"]["prior_authorization"]["$ref"] == "#/$defs/multipart_ascii_64"
    authorization = defs["authorization_slot"]["properties"]
    assert authorization["authorization_token"]["$ref"] == "#/$defs/multipart_ascii_64"


def test_multipart_identifier_codec_round_trips_boundaries_without_truncation() -> None:
    for length in (1, 30, 31, 60, 61, 64):
        value = "A" * length
        encoded = encode_multipart_ascii64(value, label="identifier")
        assert encoded.byte_length == length
        assert decode_multipart_ascii64(encoded, label="identifier") == value
        assert parse_multipart_ascii64_json(
            encoded.as_json(), label="identifier"
        ) == encoded

    empty = encode_multipart_ascii64("", label="padding", allow_empty=True)
    assert empty.as_json() == {
        "byte_length": 0,
        "parts": ["0x" + "0" * 64] * 3,
    }
    assert decode_multipart_ascii64(empty, label="padding", allow_empty=True) == ""

    with pytest.raises(ValueError, match="identifier_too_long"):
        encode_multipart_ascii64("A" * 65, label="identifier")
    with pytest.raises(ValueError, match="identifier_not_canonical_ascii_token"):
        encode_multipart_ascii64("lowercase", label="identifier")
    with pytest.raises(ValueError, match="identifier_not_canonical_ascii_token"):
        encode_multipart_ascii64("Aé", label="identifier")

    canonical = encode_multipart_ascii64("A", label="identifier")
    with pytest.raises(ValueError, match="identifier_part_0_padding_nonzero"):
        decode_multipart_ascii64(
            MultipartAscii64(canonical.byte_length, (canonical.parts[0] + 1, 0, 0)),
            label="identifier",
        )
    with pytest.raises(ValueError, match="identifier_part_0_length_noncanonical"):
        decode_multipart_ascii64(
            MultipartAscii64(2, canonical.parts),
            label="identifier",
        )


def test_distinct_line_ids_allow_identical_economics_but_repeated_ids_reject() -> None:
    first = encode_multipart_ascii64("LINE-1", label="line_id")
    second = encode_multipart_ascii64("LINE-2", label="line_id")
    require_unique_multipart_ascii64((first, second), label="service_line_id")
    with pytest.raises(ValueError, match="service_line_id_duplicate"):
        require_unique_multipart_ascii64((first, first), label="service_line_id")

    document = DOC_PATH.read_text(encoding="utf-8")
    assert "identical economic fields are preserved when and only when" in document
    assert "Repeated enabled line IDs are" in document
    assert "Disabled line slots" in document


def test_padding_and_cover_semantics_are_explicit_and_enabled_only() -> None:
    schema = _schema()
    defs = schema["$defs"]
    assert defs["fact_slot_base"]["properties"]["verified"] == {"const": True}
    assert "allOf" in defs["diagnosis_slot"]
    assert "allOf" in defs["service_line_slot"]
    assert "allOf" in defs["authorization_slot"]

    disabled_line = defs["service_line_slot"]["allOf"][0]["else"]["properties"]
    absent_policy = disabled_line["policy_evidence"]["properties"]
    assert absent_policy == {
        "policy_present": {"const": False},
        "row_kind": {"const": 0},
        "procedure_code": {"const": ""},
        "allowed_cents": {"const": 0},
        "requires_prior_authorization": {"const": False},
        "policy_leaf_index": {"const": 0},
        "next_procedure_code": {"const": ""},
        "next_policy_leaf_index": {"const": 0},
    }

    cover_branch = defs["claim_slot"]["allOf"][0]["then"]["properties"]
    assert cover_branch["source_sequence"]["const"] == 0
    assert cover_branch["claim_header"]["properties"]["diagnosis_count"]["const"] == 0
    assert cover_branch["diagnoses"]["items"]["properties"]["enabled"]["const"] is False
    assert cover_branch["service_lines"]["items"]["properties"]["enabled"]["const"] is False
    assert cover_branch["authorizations"]["items"]["properties"]["authorization_present"]["const"] is False

    document = DOC_PATH.read_text(encoding="utf-8")
    assert "The logical cover record is exact" in document
    assert "only enabled diagnoses and enabled lines participate" in document
    assert "Relational checks that JSON Schema cannot express" in document


def test_schema_preserves_exact_ordered_privacy_v2_abi() -> None:
    schema = _schema()
    prefix_items = schema["$defs"]["public_statement"]["prefixItems"]
    observed = [_prefix_item_identity(item) for item in prefix_items]
    manifest = json.loads(ABI_PATH.read_text(encoding="utf-8"))

    assert observed == list(enumerate(EXPECTED_ABI))
    assert [field["name"] for field in manifest["fields"]] == EXPECTED_ABI
    assert schema["$defs"]["public_statement"]["minItems"] == 12
    assert schema["$defs"]["public_statement"]["maxItems"] == 12
    assert schema["$defs"]["public_statement"]["items"] is False

    forbidden = set(manifest["forbidden_public_fields"])
    assert forbidden.isdisjoint(EXPECTED_ABI)


def test_gate_taxonomy_matches_governed_policy_artifact_exactly() -> None:
    schema = _schema()
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    schema_gates = [
        (entry["code"], entry["gate_id"], entry["reason"])
        for entry in schema["x-blind-ledger-failure-gates"]
    ]
    policy_gates = [
        (index, entry["id"], entry["failure_reason"])
        for index, entry in enumerate(policy["gates"], start=1)
    ]

    assert schema_gates == EXPECTED_GATES
    assert policy_gates == EXPECTED_GATES


def test_fact_slots_pin_the_six_claim_level_facts_in_order() -> None:
    facts = _schema()["$defs"]["claim_facts"]["prefixItems"]
    observed = []
    for item in facts:
        constraint = item["allOf"][1]["properties"]
        observed.append((constraint["fact_slot"]["const"], constraint["fact_id"]["const"]))

    assert observed == [
        (0, "eligibility_active"),
        (1, "provider_enrolled"),
        (2, "provider_not_suspended"),
        (3, "not_deceased"),
        (4, "duplicate_claim"),
        (5, "program_integrity_hold"),
    ]


def test_review_document_keeps_open_gates_and_no_fake_proof_parameters() -> None:
    document = DOC_PATH.read_text(encoding="utf-8")

    for marker in (
        "NOT A PRODUCTION FREEZE",
        "S07-S09",
        "K=256",
        "K=128",
        "K=512",
        "physical AIR row count",
        "FRI query count",
        "TBD",
        "This draft intentionally leaves `A01-A06` open.",
        "Synthetic data only",
    ):
        assert marker in document

    assert "FRI query count: 64" not in document
    assert "blow-up factor: 4" not in document
    assert "production-ready" not in document.lower()


def test_schema_has_no_free_form_patient_narrative_surface() -> None:
    rendered = json.dumps(_schema(), sort_keys=True)
    for forbidden in (
        "patient_name",
        "medical_narrative",
        "encryptedPayload",
        "approvedAmountCents",
        "paymentAmountCents",
        "claimCount",
        "approvedCount",
        "deniedCount",
    ):
        assert forbidden not in rendered
