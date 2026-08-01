"""Executable structural decoder for the synthetic fixed-shape witness schema.

The repository intentionally does not depend on a general JSON Schema package.
This module implements the small Draft 2020-12 keyword subset used by
``schemas/bl_pq512_witness_v0.schema.json`` and then applies the relational
checks JSON Schema cannot express.

The result is still not an authenticated proof witness: leaf/path/root
recomputation, proof-suite transcript encoding, AIR constraints, and the
authoritative payment transition remain open.  Those omissions are returned as
machine-readable declarations and are never silently treated as verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import json
from pathlib import Path
import re
from typing import Final, Mapping, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_tree_reference import PUBLIC_OUTPUT_NAMES
from app.multipart_ascii import (
    decode_multipart_ascii64,
    parse_multipart_ascii64_json,
)

from .profile import (
    AUTHORIZATIONS_PER_CLAIM,
    DIAGNOSES_PER_CLAIM,
    FACTS_PER_CLAIM,
    LEGACY_NULLIFIER_TREE_DEPTH,
    POLICY_REAL_ROW_CAPACITY,
    POLICY_TREE_DEPTH,
    SERVICE_LINES_PER_CLAIM,
    STRONG_NULLIFIER_TREE_DEPTH,
    CalibrationProfile,
    get_profile,
)
from .semantics import (
    ClaimSlot,
    RevisionKind,
    ServiceLine,
    SlotKind,
    validate_batch,
)


SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "bl_pq512_witness_v0.schema.json"
)
MAX_WITNESS_JSON_BYTES: Final[int] = 128 * 1024 * 1024
WITNESS_SCHEMA_ID: Final[str] = "BL-PQ512-WITNESS-SYNTHETIC-FOUNDATION-v0"
WITNESS_STATUS: Final[str] = "SYNTHETIC_ONLY_NOT_FOR_PRODUCTION"
FACT_IDS: Final[tuple[str, ...]] = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)
UNVERIFIED_CRYPTOGRAPHIC_SURFACES: Final[tuple[str, ...]] = (
    "claim_source_leaf_and_membership_path_recomputation",
    "oracle_fact_and_authorization_membership_path_recomputation",
    "policy_membership_and_nonmembership_path_recomputation",
    "legacy_and_strong_nullifier_derivation_and_path_recomputation",
    "claim_record_and_attestation_commitment_recomputation",
    "proof_transcript_and_native_witness_hiding",
    "authoritative_payment_state_transition",
)

_FELT_HEX: Final[re.Pattern[str]] = re.compile(r"0x[0-9a-f]{64}\Z")
_WIDE_HEX: Final[re.Pattern[str]] = re.compile(r"0x[0-9a-f]{128}\Z")


class WitnessSchemaError(ValueError):
    """Stable structural rejection from schema or relational validation."""


def _json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _schema_error(path: str, code: str) -> WitnessSchemaError:
    return WitnessSchemaError(f"witness_schema:{path}:{code}")


def _validate_schema_node(
    instance: object,
    node: Mapping[str, object],
    *,
    root: Mapping[str, object],
    path: str,
) -> None:
    reference = node.get("$ref")
    if reference is not None:
        if type(reference) is not str or not reference.startswith("#/$defs/"):
            raise _schema_error(path, "unsupported_reference")
        name = reference.removeprefix("#/$defs/")
        definitions = root.get("$defs")
        if not isinstance(definitions, Mapping) or name not in definitions:
            raise _schema_error(path, "missing_reference")
        target = definitions[name]
        if not isinstance(target, Mapping):
            raise _schema_error(path, "reference_not_schema")
        _validate_schema_node(instance, target, root=root, path=path)

    all_of = node.get("allOf")
    if all_of is not None:
        if not isinstance(all_of, list):
            raise _schema_error(path, "all_of_not_array")
        for index, child in enumerate(all_of):
            if not isinstance(child, Mapping):
                raise _schema_error(path, "all_of_child_not_schema")
            _validate_schema_node(
                instance,
                child,
                root=root,
                path=f"{path}.allOf[{index}]",
            )

    condition = node.get("if")
    if condition is not None:
        if not isinstance(condition, Mapping):
            raise _schema_error(path, "if_not_schema")
        try:
            _validate_schema_node(instance, condition, root=root, path=path)
            matched = True
        except WitnessSchemaError:
            matched = False
        branch = node.get("then") if matched else node.get("else")
        if branch is not None:
            if not isinstance(branch, Mapping):
                raise _schema_error(path, "conditional_branch_not_schema")
            _validate_schema_node(instance, branch, root=root, path=path)

    expected_type = node.get("type")
    if expected_type is not None:
        valid_type = {
            "object": type(instance) is dict,
            "array": type(instance) is list,
            "string": type(instance) is str,
            "integer": type(instance) is int,
            "boolean": type(instance) is bool,
        }.get(expected_type)
        if valid_type is None:
            raise _schema_error(path, "unsupported_type_keyword")
        if not valid_type:
            raise _schema_error(path, f"expected_{expected_type}")

    if "const" in node and not _json_equal(instance, node["const"]):
        raise _schema_error(path, "const_mismatch")
    if "enum" in node:
        choices = node["enum"]
        if not isinstance(choices, list) or not any(
            _json_equal(instance, choice) for choice in choices
        ):
            raise _schema_error(path, "enum_mismatch")

    if type(instance) is int:
        minimum = node.get("minimum")
        maximum = node.get("maximum")
        if minimum is not None and instance < minimum:
            raise _schema_error(path, "below_minimum")
        if maximum is not None and instance > maximum:
            raise _schema_error(path, "above_maximum")

    if type(instance) is str:
        minimum_length = node.get("minLength")
        maximum_length = node.get("maxLength")
        if minimum_length is not None and len(instance) < minimum_length:
            raise _schema_error(path, "below_min_length")
        if maximum_length is not None and len(instance) > maximum_length:
            raise _schema_error(path, "above_max_length")
        pattern = node.get("pattern")
        if pattern is not None:
            if type(pattern) is not str or re.search(pattern, instance) is None:
                raise _schema_error(path, "pattern_mismatch")

    if type(instance) is dict:
        required = node.get("required")
        properties = node.get("properties")
        if required is not None:
            if not isinstance(required, list) or any(
                type(value) is not str for value in required
            ):
                raise _schema_error(path, "required_invalid")
            missing = [value for value in required if value not in instance]
            if missing:
                raise _schema_error(path, f"missing_{missing[0]}")
        if properties is not None:
            if not isinstance(properties, Mapping):
                raise _schema_error(path, "properties_invalid")
            if node.get("additionalProperties") is False:
                extras = sorted(set(instance) - set(properties))
                if extras:
                    raise _schema_error(path, f"extra_{extras[0]}")
            for name, child in properties.items():
                if name not in instance:
                    continue
                if not isinstance(child, Mapping):
                    raise _schema_error(path, "property_schema_invalid")
                _validate_schema_node(
                    instance[name],
                    child,
                    root=root,
                    path=f"{path}.{name}",
                )

    if type(instance) is list:
        minimum_items = node.get("minItems")
        maximum_items = node.get("maxItems")
        if minimum_items is not None and len(instance) < minimum_items:
            raise _schema_error(path, "below_min_items")
        if maximum_items is not None and len(instance) > maximum_items:
            raise _schema_error(path, "above_max_items")
        prefix_items = node.get("prefixItems", [])
        if not isinstance(prefix_items, list):
            raise _schema_error(path, "prefix_items_invalid")
        for index, value in enumerate(instance):
            if index < len(prefix_items):
                child = prefix_items[index]
            else:
                child = node.get("items")
            if child is False:
                raise _schema_error(path, "additional_array_item")
            if child is None or child is True:
                continue
            if not isinstance(child, Mapping):
                raise _schema_error(path, "item_schema_invalid")
            _validate_schema_node(
                value,
                child,
                root=root,
                path=f"{path}[{index}]",
            )


def _strict_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes:
        raise TypeError("witness_json_must_be_bytes")
    if not raw or len(raw) > MAX_WITNESS_JSON_BYTES:
        raise WitnessSchemaError("witness_json_size_invalid")

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise WitnessSchemaError(f"witness_json_duplicate_key:{key}")
            result[key] = value
        return result

    def reject_float(value: str) -> object:
        raise WitnessSchemaError(f"witness_json_non_integer_number:{value}")

    def reject_constant(value: str) -> object:
        raise WitnessSchemaError(f"witness_json_nonfinite_number:{value}")

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise WitnessSchemaError("witness_json_not_utf8") from exc
    except json.JSONDecodeError as exc:
        raise WitnessSchemaError("witness_json_invalid_or_trailing") from exc
    if type(parsed) is not dict:
        raise WitnessSchemaError("witness_json_top_level_not_object")
    return parsed


def _schema() -> dict[str, object]:
    raw = SCHEMA_PATH.read_bytes()
    parsed = json.loads(raw.decode("utf-8"))
    if type(parsed) is not dict:
        raise RuntimeError("witness_schema_top_level_invalid")
    return parsed


def _walk_felts(value: object, path: str = "$") -> None:
    if type(value) is str and _FELT_HEX.fullmatch(value):
        if int(value[2:], 16) >= FIELD_MODULUS:
            raise WitnessSchemaError(f"witness_felt_out_of_field:{path}")
    elif type(value) is dict:
        for key, child in value.items():
            _walk_felts(child, f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _walk_felts(child, f"{path}[{index}]")


def _decode_identifier(
    value: object, *, label: str, allow_empty: bool
) -> str:
    encoded = parse_multipart_ascii64_json(
        value, label=label, allow_empty=allow_empty
    )
    return decode_multipart_ascii64(
        encoded, label=label, allow_empty=allow_empty
    )


def _zero_disabled_line(line: Mapping[str, object], *, slot_index: int) -> None:
    if line["line_slot"] != slot_index:
        raise WitnessSchemaError("witness_line_slot_position_mismatch")


def _revision(value: int) -> RevisionKind:
    mapping = {
        0: RevisionKind.COVER,
        1: RevisionKind.ORIGINAL,
        2: RevisionKind.CORRECTION,
        3: RevisionKind.REPLACEMENT,
        4: RevisionKind.VOID,
    }
    return mapping[value]


def _parse_slot(value: object, *, expected_index: int) -> ClaimSlot:
    if type(value) is not dict:
        raise WitnessSchemaError("witness_slot_not_object")
    slot = value
    if slot["slot_index"] != expected_index:
        raise WitnessSchemaError("witness_slot_index_position_mismatch")
    is_real = slot["slot_kind"] == "REAL"
    header = slot["claim_header"]
    if type(header) is not dict:
        raise WitnessSchemaError("witness_claim_header_not_object")
    source_authority_id = _decode_identifier(
        header["source_authority_id"],
        label=f"slot_{expected_index}_source_authority_id",
        allow_empty=not is_real,
    )
    claim_id = _decode_identifier(
        header["claim_id"],
        label=f"slot_{expected_index}_claim_id",
        allow_empty=not is_real,
    )
    member_id = _decode_identifier(
        header["member_id"],
        label=f"slot_{expected_index}_member_id",
        allow_empty=True,
    )

    diagnoses: list[str] = []
    seen_disabled_diagnosis = False
    raw_diagnoses = slot["diagnoses"]
    if type(raw_diagnoses) is not list:
        raise WitnessSchemaError("witness_diagnoses_not_array")
    for index, diagnosis in enumerate(raw_diagnoses):
        if type(diagnosis) is not dict:
            raise WitnessSchemaError("witness_diagnosis_not_object")
        if diagnosis["diagnosis_slot"] != index:
            raise WitnessSchemaError("witness_diagnosis_slot_position_mismatch")
        if diagnosis["enabled"]:
            if seen_disabled_diagnosis:
                raise WitnessSchemaError("witness_enabled_diagnosis_after_padding")
            diagnoses.append(diagnosis["diagnosis_code"])
        else:
            seen_disabled_diagnosis = True
    if header["diagnosis_count"] != len(diagnoses):
        raise WitnessSchemaError("witness_diagnosis_count_mismatch")

    facts = slot["claim_facts"]
    if type(facts) is not list:
        raise WitnessSchemaError("witness_claim_facts_not_array")
    fact_values: list[bool] = []
    for index, (fact, expected_id) in enumerate(
        zip(facts, FACT_IDS, strict=True)
    ):
        if type(fact) is not dict:
            raise WitnessSchemaError("witness_claim_fact_not_object")
        if fact["fact_slot"] != index or fact["fact_id"] != expected_id:
            raise WitnessSchemaError("witness_claim_fact_position_mismatch")
        fact_values.append(fact["value"])

    raw_lines = slot["service_lines"]
    raw_authorizations = slot["authorizations"]
    if type(raw_lines) is not list or type(raw_authorizations) is not list:
        raise WitnessSchemaError("witness_line_or_authorization_not_array")
    lines: list[ServiceLine] = []
    seen_disabled_line = False
    service_date = header["service_date_day"]
    for index, (line, authorization) in enumerate(
        zip(raw_lines, raw_authorizations, strict=True)
    ):
        if type(line) is not dict or type(authorization) is not dict:
            raise WitnessSchemaError("witness_line_or_authorization_not_object")
        _zero_disabled_line(line, slot_index=index)
        if authorization["authorization_slot"] != index:
            raise WitnessSchemaError("witness_authorization_slot_position_mismatch")
        enabled = line["enabled"]
        if not enabled:
            seen_disabled_line = True
            if (
                authorization["required_by_policy"]
                or authorization["authorization_present"]
            ):
                raise WitnessSchemaError(
                    "witness_disabled_line_authorization_not_canonical"
                )
            _decode_identifier(
                authorization["authorization_token"],
                label=f"slot_{expected_index}_authorization_{index}",
                allow_empty=True,
            )
            continue
        if seen_disabled_line:
            raise WitnessSchemaError("witness_enabled_line_after_padding")
        line_id = _decode_identifier(
            line["line_id"],
            label=f"slot_{expected_index}_line_{index}_id",
            allow_empty=False,
        )
        prior_authorization = _decode_identifier(
            line["prior_authorization"],
            label=f"slot_{expected_index}_line_{index}_prior_authorization",
            allow_empty=True,
        )
        policy = line["policy_evidence"]
        if type(policy) is not dict:
            raise WitnessSchemaError("witness_policy_evidence_not_object")
        if policy["policy_present"] and policy["procedure_code"] != line["procedure_code"]:
            raise WitnessSchemaError("witness_policy_procedure_mismatch")
        if authorization["required_by_policy"] != policy["requires_prior_authorization"]:
            raise WitnessSchemaError("witness_authorization_policy_requirement_mismatch")
        token = _decode_identifier(
            authorization["authorization_token"],
            label=f"slot_{expected_index}_authorization_{index}",
            allow_empty=not authorization["authorization_present"],
        )
        if authorization["authorization_present"]:
            if token != prior_authorization:
                raise WitnessSchemaError("witness_authorization_token_mismatch")
            if not (
                authorization["valid_from_day"]
                <= service_date
                <= authorization["valid_until_day"]
            ):
                raise WitnessSchemaError("witness_authorization_not_valid_on_service_day")
        lines.append(
            ServiceLine(
                original_line_index=line["original_line_index"],
                line_id=line_id,
                procedure_code=line["procedure_code"],
                charge_cents=line["charge_cents"],
                units_cents=line["units_cents"],
                prior_authorization=prior_authorization,
                policy_present=policy["policy_present"],
                allowed_cents=policy["allowed_cents"],
                requires_prior_authorization=policy[
                    "requires_prior_authorization"
                ],
                authorization_present=authorization[
                    "authorization_present"
                ],
            )
        )
    if header["service_line_count"] != len(lines):
        raise WitnessSchemaError("witness_service_line_count_mismatch")

    allowed = slot["allowed_cents"]
    payment = slot["payment_cents"]
    if slot["decision"] == 1:
        if payment > allowed:
            raise WitnessSchemaError("witness_payment_exceeds_allowed")
        patient_responsibility = allowed - payment
    else:
        patient_responsibility = 0

    return ClaimSlot(
        slot_index=expected_index,
        slot_kind=SlotKind.REAL if is_real else SlotKind.COVER,
        source_authority_id=source_authority_id,
        source_sequence=slot["source_sequence"],
        claim_id=claim_id,
        member_id=member_id,
        provider_npi=header["provider_npi"],
        attempt_version=header["attempt_version"],
        revision_kind=_revision(header["revision_kind"]),
        parent_attempt_version=header["parent_attempt_version"],
        diagnoses=tuple(diagnoses),
        service_lines=tuple(lines),
        eligibility_active=fact_values[0],
        provider_enrolled=fact_values[1],
        provider_not_suspended=fact_values[2],
        not_deceased=fact_values[3],
        duplicate_claim=fact_values[4],
        program_integrity_hold=fact_values[5],
        total_charge_cents=header["total_charge_cents"],
        patient_responsibility_cents=patient_responsibility,
        claimed_decision=slot["decision"],
        claimed_failure_code=slot["failure_code"],
        claimed_allowed_cents=allowed,
        claimed_payment_cents=payment,
    )


def _hex_bytes(label: str, value: object, *, width: int) -> bytes:
    pattern = _FELT_HEX if width == 32 else _WIDE_HEX
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise WitnessSchemaError(f"witness_{label}_hex_invalid")
    return bytes.fromhex(value[2:])


def _require_unique_nonzero(
    values: Sequence[bytes], *, label: str
) -> None:
    if any(not any(value) for value in values):
        raise WitnessSchemaError(f"witness_{label}_zero")
    if len(set(values)) != len(values):
        raise WitnessSchemaError(f"witness_{label}_duplicate")


def _validate_nullifier_sequences(
    instance: Mapping[str, object], slots: Sequence[Mapping[str, object]]
) -> None:
    public = instance["public_statement"]
    if type(public) is not list:
        raise WitnessSchemaError("witness_public_statement_not_array")
    expected_legacy_before = public[3]["felt"]
    inserted_legacy: list[int] = []
    inserted_strong: list[int] = []
    previous_strong_after: str | None = None
    for index, slot in enumerate(slots):
        legacy = slot["legacy_nullifier_transition"]
        strong = slot["strong_nullifier_transition"]
        if legacy["root_before"] != expected_legacy_before:
            raise WitnessSchemaError(
                f"witness_legacy_nullifier_chain_mismatch:{index}"
            )
        if legacy["root_after"] == legacy["root_before"]:
            raise WitnessSchemaError(
                f"witness_legacy_nullifier_noop:{index}"
            )
        expected_legacy_before = legacy["root_after"]
        if previous_strong_after is not None and strong["root_before"] != previous_strong_after:
            raise WitnessSchemaError(
                f"witness_strong_nullifier_chain_mismatch:{index}"
            )
        if strong["root_after"] == strong["root_before"]:
            raise WitnessSchemaError(
                f"witness_strong_nullifier_noop:{index}"
            )
        previous_strong_after = strong["root_after"]
        inserted_legacy.append(legacy["inserted_index"])
        inserted_strong.append(strong["inserted_index"])
    if expected_legacy_before != public[4]["felt"]:
        raise WitnessSchemaError("witness_legacy_nullifier_final_root_mismatch")
    if len(set(inserted_legacy)) != len(inserted_legacy):
        raise WitnessSchemaError("witness_legacy_inserted_index_duplicate")
    if len(set(inserted_strong)) != len(inserted_strong):
        raise WitnessSchemaError("witness_strong_inserted_index_duplicate")


@dataclass(frozen=True, slots=True)
class ParsedStructuralWitness:
    schema_id: str
    schema_sha3_512: bytes
    canonical_interchange_sha3_512: bytes
    raw_json_bytes: int
    profile: CalibrationProfile
    public_statement: tuple[bytes, ...]
    slots: tuple[ClaimSlot, ...]
    synthetic_only: bool
    production_frozen: bool
    cryptographic_artifacts_authenticated: bool
    unverified_cryptographic_surfaces: tuple[str, ...]


def parse_structural_witness_json(raw: bytes) -> ParsedStructuralWitness:
    """Validate schema plus noncryptographic relations; never authenticate paths."""

    instance = _strict_json(raw)
    schema = _schema()
    _validate_schema_node(instance, schema, root=schema, path="$")
    _walk_felts(instance)

    capacity = instance["capacity_profile"]
    if type(capacity) is not dict:
        raise WitnessSchemaError("witness_capacity_profile_not_object")
    profile = get_profile(capacity["profile_id"])
    exact_capacity = {
        "batch_claim_slots": profile.claim_slots,
        "service_lines_per_claim": SERVICE_LINES_PER_CLAIM,
        "diagnoses_per_claim": DIAGNOSES_PER_CLAIM,
        "claim_facts_per_claim": FACTS_PER_CLAIM,
        "authorizations_per_claim": AUTHORIZATIONS_PER_CLAIM,
        "claim_source_tree_depth": profile.claim_source_tree_depth,
        "oracle_tree_depth": profile.oracle_tree_depth,
        "policy_tree_depth": POLICY_TREE_DEPTH,
        "policy_real_row_capacity": POLICY_REAL_ROW_CAPACITY,
        "legacy_nullifier_tree_depth": LEGACY_NULLIFIER_TREE_DEPTH,
        "strong_nullifier_tree_depth": STRONG_NULLIFIER_TREE_DEPTH,
    }
    for name, expected in exact_capacity.items():
        if capacity[name] != expected:
            raise WitnessSchemaError(f"witness_capacity_mismatch:{name}")

    public = instance["public_statement"]
    if type(public) is not list:
        raise WitnessSchemaError("witness_public_statement_not_array")
    public_values: list[bytes] = []
    for index, (entry, expected_name) in enumerate(
        zip(public, PUBLIC_OUTPUT_NAMES, strict=True)
    ):
        if type(entry) is not dict:
            raise WitnessSchemaError("witness_public_field_not_object")
        if entry["index"] != index or entry["name"] != expected_name:
            raise WitnessSchemaError("witness_public_statement_order_mismatch")
        public_values.append(_hex_bytes("public_felt", entry["felt"], width=32))

    raw_slots = instance["claim_slots"]
    if type(raw_slots) is not list:
        raise WitnessSchemaError("witness_claim_slots_not_array")
    typed_slots = tuple(
        _parse_slot(value, expected_index=index)
        for index, value in enumerate(raw_slots)
    )
    validate_batch(profile, typed_slots)
    slot_mappings = tuple(raw_slots)
    _validate_nullifier_sequences(instance, slot_mappings)

    salts = tuple(
        _hex_bytes("private_slot_salt", slot["private_slot_salt_512"], width=64)
        for slot in slot_mappings
    )
    legacy_nullifiers = tuple(
        _hex_bytes("legacy_attempt_nullifier", slot["legacy_attempt_nullifier"], width=32)
        for slot in slot_mappings
    )
    strong_nullifiers = tuple(
        _hex_bytes("strong_attempt_nullifier", slot["strong_attempt_nullifier_512"], width=64)
        for slot in slot_mappings
    )
    _require_unique_nonzero(salts, label="private_slot_salt")
    _require_unique_nonzero(legacy_nullifiers, label="legacy_attempt_nullifier")
    _require_unique_nonzero(strong_nullifiers, label="strong_attempt_nullifier")

    canonical = json.dumps(
        instance,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    schema_raw = SCHEMA_PATH.read_bytes()
    return ParsedStructuralWitness(
        WITNESS_SCHEMA_ID,
        sha3_512(schema_raw).digest(),
        sha3_512(canonical).digest(),
        len(raw),
        profile,
        tuple(public_values),
        typed_slots,
        True,
        False,
        False,
        UNVERIFIED_CRYPTOGRAPHIC_SURFACES,
    )
