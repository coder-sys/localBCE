"""Independent verifier for the synthetic Contract Mirror V1 seam.

This module composes already-owned Denominator Ledger, source-reconciliation,
governance, and discrepancy-case verifiers.  It owns only the Contract Mirror
obligation/result binding; it does not re-parse FHIR, choose a source, or
authorize a payment, clearance, legal conclusion, or business truth.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.governance import provider_continuity_control_pack_v2_independent as governance
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import discrepancy_case_independent as case
from app.mirror import source_reconciliation_independent as reconciliation


ARTIFACT_KIND = "MIRROR_CONTRACT_MIRROR_V1"
SCHEMA = "mirror-contract-mirror-v1"
SCHEMA_VERSION = 1
STAGE_KIND = "CONTRACT_MIRROR"
DOMAIN = "BL/MIRROR/CONTRACT-MIRROR/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
HEX128 = re.compile(r"^[0-9a-f]{128}$")

CONTRACT_PROFILE_ID = "mirror.contract.synthetic-provider-directory.v1"
CONTRACT_PROFILE_VERSION = 1
OBLIGATION_ID = "mirror.obligation.provider-directory.active-return.v1"
OBLIGATION_VERSION = 1
RESPONSIBILITY_PROFILE_ID = "mirror.contract.responsibility.synthetic-v1"
EXCEPTION_CLASS_ID = "mirror.contract.exception.observation-only.synthetic-v1"
REMEDIATION_PROFILE_ID = case.CONTRACT_ID
RETEST_PROFILE_ID = case.RETEST_PROFILE_ID

STAGE_EVALUATED = "OBLIGATION_EVALUATED"
STAGE_RETESTED = "RETEST_EVALUATED"
STAGES = (STAGE_EVALUATED, STAGE_RETESTED)

RESULT_CONFORMING = "OBSERVED_CONFORMING"
RESULT_VARIANCE = "OBSERVED_VARIANCE"
RESULT_INDETERMINATE = "INDETERMINATE"
RESULT_PARTIAL = "PARTIAL_OBSERVATION"
RESULT_UNAVAILABLE = "UNAVAILABLE"
RESULT_STATUSES = (
    RESULT_CONFORMING,
    RESULT_VARIANCE,
    RESULT_INDETERMINATE,
    RESULT_PARTIAL,
    RESULT_UNAVAILABLE,
)

AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
FIXED_FLAGS = {
    "observation_only": True,
    "read_only": True,
    "business_truth_proven": False,
    "conformance_proven": False,
    "variance_proven": False,
    "absence_inferred": False,
    "nonmembership_inferred": False,
    "source_completeness": "UNKNOWN",
    "allow_nonmembership": False,
    "production_usable": False,
    "synthetic_only": True,
    "activation": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "proofSuiteId": None,
}

CASE_KEYS = {
    "schema",
    "schema_version",
    "contract_binding",
    "profile_binding",
    "governance_binding",
    "obligation",
    "denominator",
    "observation",
    "case_link",
    "evaluation",
    "exception_reference",
    "stage_kind",
    "prior_artifact_id",
    "prior_stage_id",
    "flags",
    "authority",
    "artifact_id",
    "current_stage_id",
    "transition_id",
}
CONTRACT_KEYS = {
    "contract_profile_id",
    "version",
    "stages",
    "obligation_id",
    "obligation_version",
    "responsibility_profile_id",
    "exception_class_id",
    "remediation_profile_id",
    "retest_profile_id",
    "result_statuses",
    "claims",
    "contract_digest",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
GOVERNANCE_KEYS = {
    "artifact_id",
    "stage_id",
    "transition_id",
    "profile_id",
    "profile_version",
    "profile_digest",
    "effective_start",
    "effective_end",
}
OBLIGATION_KEYS = {
    "obligation_id",
    "version",
    "responsible_boundary",
    "responsibility_profile_id",
    "subject",
    "scope",
    "effective_start",
    "effective_end",
    "population_definition_id",
    "population_definition_version",
    "denominator_contract_id",
    "denominator_profile_id",
    "denominator_profile_version",
    "required_observation",
    "permitted_exception",
    "remediation_rule",
    "governance_artifact_id",
}
DENOMINATOR_KEYS = {
    "artifact_id",
    "stage_id",
    "transition_id",
    "stage_kind",
    "profile_id",
    "profile_version",
    "population_root",
    "child_population_root",
    "input_record_count",
    "outcome_counts",
    "outcome_root",
    "coverage_status",
    "source_completeness",
    "allow_nonmembership",
}
OBSERVATION_KEYS = {
    "reconciliation_artifact_id",
    "reconciliation_stage_id",
    "reconciliation_transition_id",
    "source_observation_status",
    "linkage_status",
    "normalized_content_root",
    "comparison_content_root",
    "chronology_order",
    "chronology_prior_marker",
    "chronology_current_marker",
    "source_completeness",
    "allow_nonmembership",
}
CASE_LINK_KEYS = {"case_id", "artifact_id", "stage_id", "transition_id", "finding_id", "lifecycle_state"}
EVALUATION_KEYS = {
    "status",
    "basis",
    "expected_result",
    "observed_result",
    "dimensions",
    "conformance_claim",
    "variance_claim",
    "absence_inferred",
    "nonmembership_inferred",
    "business_truth_proven",
}
EXCEPTION_KEYS = {
    "status",
    "class_id",
    "governance_artifact_id",
    "effective_start",
    "effective_end",
    "changes_obligation",
    "payment_authority",
    "synthetic_only",
}

_PREVIOUS = {STAGE_RETESTED: {STAGE_EVALUATED}}
_HEX_FIELDS = {
    "artifact_id",
    "stage_id",
    "transition_id",
    "profile_digest",
    "population_root",
    "child_population_root",
    "outcome_root",
    "reconciliation_artifact_id",
    "reconciliation_stage_id",
    "reconciliation_transition_id",
    "normalized_content_root",
    "comparison_content_root",
    "case_id",
    "case_artifact_id",
    "case_stage_id",
    "case_transition_id",
    "finding_id",
    "governance_artifact_id",
}


class IndependentContractMirrorError(ValueError):
    """Stable fail-closed rejection from the Contract Mirror verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentContractMirrorError("contract:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentContractMirrorError("contract:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentContractMirrorError("contract:node-cap")
    if depth > 24:
        raise IndependentContractMirrorError("contract:depth-cap")
    if isinstance(value, float):
        raise IndependentContractMirrorError("contract:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentContractMirrorError("contract:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentContractMirrorError("contract:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentContractMirrorError("contract:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentContractMirrorError("contract:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentContractMirrorError("contract:constant")),
        )
    except IndependentContractMirrorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentContractMirrorError("contract:parse") from exc
    if not isinstance(value, dict):
        raise IndependentContractMirrorError("contract:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentContractMirrorError("contract:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentContractMirrorError(f"contract:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentContractMirrorError(f"contract:{label}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentContractMirrorError(f"contract:{label}") from exc
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentContractMirrorError(f"contract:{label}-keys")
    return value


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > denominator.MAX_COUNT:
        raise IndependentContractMirrorError(f"contract:{label}")
    return value


def _contract_binding() -> dict[str, object]:
    material = {
        "contract_profile_id": CONTRACT_PROFILE_ID,
        "version": CONTRACT_PROFILE_VERSION,
        "stages": list(STAGES),
        "obligation_id": OBLIGATION_ID,
        "obligation_version": OBLIGATION_VERSION,
        "responsibility_profile_id": RESPONSIBILITY_PROFILE_ID,
        "exception_class_id": EXCEPTION_CLASS_ID,
        "remediation_profile_id": REMEDIATION_PROFILE_ID,
        "retest_profile_id": RETEST_PROFILE_ID,
        "result_statuses": list(RESULT_STATUSES),
        "claims": {
            "evidence_only": True,
            "legal_conformance": False,
            "liability": False,
            "business_truth": False,
            "absence": False,
            "nonmembership": False,
            "payment": False,
        },
    }
    return {**material, "contract_digest": _digest("contract", material)}


def _profile_binding() -> dict[str, object]:
    material = {
        "profile_id": CONTRACT_PROFILE_ID,
        "version": CONTRACT_PROFILE_VERSION,
        "obligation_id": OBLIGATION_ID,
        "obligation_version": OBLIGATION_VERSION,
        "denominator_profile_id": denominator.PROFILE_ID,
        "denominator_profile_version": denominator.PROFILE_VERSION,
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
    }
    return {**material, "profile_digest": _digest("profile", material)}


def _governance_binding(raw: bytes, registry: Mapping[str, object], profile: Mapping[str, object], subject: Mapping[str, object]) -> dict[str, object]:
    try:
        value = governance._parse(raw)
        result = governance.verify_bytes(raw, registry)
        if value.get("schema") != governance.SCHEMA or result.get("current_stage_kind") != governance.STAGE_APPROVED:
            raise IndependentContractMirrorError("contract:governance-not-approved")
        descriptor = _expect(value.get("profile"), governance.PROFILE_KEYS, "governance-profile")
        if any(descriptor[key] != profile[key] for key in ("profile_id", "version", "profile_digest")):
            raise IndependentContractMirrorError("contract:governance-profile")
        if value.get("subject") != {"provider_graph_subject": subject["subject"], "scope": subject["scope"]}:
            raise IndependentContractMirrorError("contract:governance-subject")
    except IndependentContractMirrorError:
        raise
    except Exception as exc:
        raise IndependentContractMirrorError("contract:governance-reject") from exc
    return {
        "artifact_id": _hex(result["artifact_id"], "governance-artifact"),
        "stage_id": _hex(result["current_stage_id"], "governance-stage"),
        "transition_id": _hex(value["chain_root"], "governance-transition"),
        "profile_id": _text(result["profile_id"], "governance-profile-id"),
        "profile_version": result["profile_version"],
        "profile_digest": _hex(result["profile_digest"], "governance-profile-digest"),
        "effective_start": result["effective_start"],
        "effective_end": result["effective_end"],
    }


def _verify_denominator(raw: bytes, context: Mapping[str, object], registry: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    required = {"source_raw", "graph_raw", "governance_raw", "prior_denominator_raw"}
    if set(context) != required:
        raise IndependentContractMirrorError("contract:denominator-context")
    try:
        value = denominator._parse(raw)
        result = denominator.verify_artifact(
            raw,
            source_raw=context["source_raw"],
            graph_raw=context.get("graph_raw"),
            governance_raw=context["governance_raw"],
            registry=registry,
            prior_denominator_raw=context.get("prior_denominator_raw"),
        )
    except IndependentContractMirrorError:
        raise
    except Exception as exc:
        raise IndependentContractMirrorError("contract:denominator-reject") from exc
    return value, result


def _verify_case(raw: bytes, context: Mapping[str, object], registry: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    required = {"graph_raw", "reconciliation_raw", "reconciliation_context", "governance_raw"}
    if not required.issubset(context):
        raise IndependentContractMirrorError("contract:case-context")
    try:
        value = case._parse(raw)
        result = case.verify_artifact(
            raw,
            graph_raw=context["graph_raw"],
            reconciliation_raw=context["reconciliation_raw"],
            reconciliation_context=context["reconciliation_context"],
            governance_raw=context["governance_raw"],
            graph_profile_registry=registry,
            prior_case_raw=context.get("prior_case_raw"),
            retest_reconciliation_raw=context.get("retest_reconciliation_raw"),
            retest_context=context.get("retest_context"),
        )
    except IndependentContractMirrorError:
        raise
    except Exception as exc:
        raise IndependentContractMirrorError("contract:case-reject") from exc
    return value, result


def _observation(reconciliation_raw: bytes) -> tuple[dict[str, object], dict[str, object]]:
    try:
        value = reconciliation._parse(reconciliation_raw)
        result = value["result"]
        chronology = value["chronology"]
        content = value["source_content"]
        current = value["current_custody"]
        if not isinstance(result, dict) or not isinstance(chronology, dict) or not isinstance(content, dict) or not isinstance(current, dict):
            raise IndependentContractMirrorError("contract:observation-shape")
        return value, {
            "reconciliation_artifact_id": _hex(value["artifact_id"], "reconciliation-artifact"),
            "reconciliation_stage_id": _hex(value["current_stage_id"], "reconciliation-stage"),
            "reconciliation_transition_id": _hex(value["transition_id"], "reconciliation-transition"),
            "source_observation_status": _text(result["source_observation_status"], "source-observation-status"),
            "linkage_status": _text(value["linkage_transition"]["status"], "linkage-status"),
            "normalized_content_root": _hex(content["current_root"], "content-root"),
            "comparison_content_root": _hex(content["comparison_root"], "comparison-root", nullable=True),
            "chronology_order": _text(chronology["order"], "chronology-order"),
            "chronology_prior_marker": chronology["prior_marker"],
            "chronology_current_marker": chronology["current_marker"],
            "source_completeness": "UNKNOWN",
            "allow_nonmembership": False,
        }
    except IndependentContractMirrorError:
        raise
    except Exception as exc:
        raise IndependentContractMirrorError("contract:observation-reject") from exc


def _denominator_binding(value: Mapping[str, object], result: Mapping[str, object]) -> dict[str, object]:
    population = _expect(value["population"], denominator.POPULATION_KEYS, "denominator-population")
    narrowing = value.get("narrowing")
    narrowing_value = narrowing if isinstance(narrowing, dict) else None
    outcome_counts = narrowing_value["outcome_counts"] if narrowing_value is not None else None
    outcome_root = narrowing_value["outcome_root"] if narrowing_value is not None else None
    return {
        "artifact_id": _hex(result["artifact_id"], "denominator-artifact"),
        "stage_id": _hex(result["current_stage_id"], "denominator-stage"),
        "transition_id": _hex(result["transition_id"], "denominator-transition"),
        "stage_kind": _text(value["stage_kind"], "denominator-stage-kind"),
        "profile_id": _text(result["profile_id"], "denominator-profile-id"),
        "profile_version": result["profile_version"],
        "population_root": _hex(population["population_root"], "population-root"),
        "child_population_root": _hex(narrowing_value["child_population_root"], "child-population-root") if narrowing_value is not None else None,
        "input_record_count": _count(population["input_record_count"], "denominator-record-count"),
        "outcome_counts": dict(outcome_counts) if outcome_counts is not None else None,
        "outcome_root": _hex(outcome_root, "outcome-root", nullable=True),
        "coverage_status": _text(population["coverage_status"], "coverage-status"),
        "source_completeness": "UNKNOWN",
        "allow_nonmembership": False,
    }


def _obligation(*, governance_binding: Mapping[str, object], subject: Mapping[str, object], responsible_boundary: str) -> dict[str, object]:
    return {
        "obligation_id": OBLIGATION_ID,
        "version": OBLIGATION_VERSION,
        "responsible_boundary": responsible_boundary,
        "responsibility_profile_id": RESPONSIBILITY_PROFILE_ID,
        "subject": subject["subject"],
        "scope": subject["scope"],
        "effective_start": governance_binding["effective_start"],
        "effective_end": governance_binding["effective_end"],
        "population_definition_id": denominator.PROFILE_ID,
        "population_definition_version": denominator.PROFILE_VERSION,
        "denominator_contract_id": denominator.SCHEMA,
        "denominator_profile_id": denominator.PROFILE_ID,
        "denominator_profile_version": denominator.PROFILE_VERSION,
        "required_observation": {
            "profile_id": reconciliation.RECONCILIATION_CONTRACT_ID,
            "version": reconciliation.RECONCILIATION_CONTRACT_VERSION,
            "expected_result": "RETURNED_PROVIDER_DIRECTORY_OBSERVATION",
            "dimensions": ["source_observation_status", "normalized_content_root", "chronology_order"],
        },
        "permitted_exception": {
            "class_id": EXCEPTION_CLASS_ID,
            "governed_by_control_pack": True,
            "max_duration_seconds": 86_400,
            "may_change_obligation": False,
            "may_authorize_payment": False,
            "synthetic_only": True,
        },
        "remediation_rule": {
            "profile_id": REMEDIATION_PROFILE_ID,
            "retest_profile_id": RETEST_PROFILE_ID,
            "assertion_is_truth": False,
            "full_parity_required_for_resolution": True,
        },
        "governance_artifact_id": governance_binding["artifact_id"],
    }


def _exception_reference(governance_binding: Mapping[str, object]) -> dict[str, object]:
    return {
        "status": "NOT_APPLIED",
        "class_id": EXCEPTION_CLASS_ID,
        "governance_artifact_id": governance_binding["artifact_id"],
        "effective_start": None,
        "effective_end": None,
        "changes_obligation": False,
        "payment_authority": False,
        "synthetic_only": True,
    }


def _evaluation(denom: Mapping[str, object], observation: Mapping[str, object]) -> dict[str, object]:
    source_status = observation["source_observation_status"]
    coverage = denom["coverage_status"]
    if observation["source_completeness"] != "UNKNOWN" or observation["allow_nonmembership"] is not False:
        raise IndependentContractMirrorError("contract:source-claim")
    if coverage.endswith("UNKNOWN_DENOMINATOR") or denom["source_completeness"] != "UNKNOWN":
        status, basis = RESULT_INDETERMINATE, "DENOMINATOR_COMPLETENESS_UNKNOWN"
    elif source_status in {reconciliation.STATUS_SOURCE_FAILURE, reconciliation.STATUS_STALE_OR_GAPPED}:
        status, basis = RESULT_UNAVAILABLE, "SOURCE_OBSERVATION_UNAVAILABLE_OR_STALE"
    elif source_status in {reconciliation.STATUS_CONFLICTING, reconciliation.STATUS_NOT_OBSERVED_INCOMPLETE}:
        status, basis = RESULT_INDETERMINATE, "INCOMPLETE_OR_CONFLICTING_OBSERVATION"
    elif source_status == reconciliation.STATUS_OBSERVED_CHANGED:
        status, basis = RESULT_VARIANCE, "CHANGED_VERIFIED_SOURCE_CONTENT"
    elif source_status in {reconciliation.STATUS_OBSERVED_CONTINUED, reconciliation.STATUS_OBSERVED_NEW}:
        status, basis = RESULT_CONFORMING, "OBSERVED_RETURNED_CONTENT"
    else:
        status, basis = RESULT_PARTIAL, "BOUNDED_OBSERVATION"
    # The fixed synthetic source profile has unknown completeness, so the
    # completeness branch above deliberately prevents a conformance claim.
    if denom["source_completeness"] == "UNKNOWN":
        status = RESULT_INDETERMINATE
        basis = "DENOMINATOR_COMPLETENESS_UNKNOWN"
    return {
        "status": status,
        "basis": basis,
        "expected_result": "RETURNED_PROVIDER_DIRECTORY_OBSERVATION",
        "observed_result": source_status,
        "dimensions": ["denominator_population", "source_observation_status", "normalized_content_root", "chronology_order"],
        "conformance_claim": False,
        "variance_claim": False,
        "absence_inferred": False,
        "nonmembership_inferred": False,
        "business_truth_proven": False,
    }


def _case_link(case_value: Mapping[str, object], case_result: Mapping[str, object]) -> dict[str, object]:
    upstream = _expect(case_value["upstream"], case.UPSTREAM_KEYS, "case-upstream")
    finding = _expect(upstream["finding"], case.FINDING_KEYS, "case-finding")
    return {
        "case_id": _hex(case_result["case_id"], "case-id"),
        "artifact_id": _hex(case_result["artifact_id"], "case-artifact"),
        "stage_id": _hex(case_result["current_stage_id"], "case-stage"),
        "transition_id": _hex(case_result["transition_id"], "case-transition"),
        "finding_id": _hex(finding["finding_id"], "finding-id"),
        "lifecycle_state": _text(case_value["lifecycle_state"], "case-lifecycle"),
    }


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "stage_kind": value["stage_kind"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
            "denominator_artifact_id": value["denominator"]["artifact_id"],
            "reconciliation_artifact_id": value["observation"]["reconciliation_artifact_id"],
            "case_artifact_id": value["case_link"]["artifact_id"],
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "stage_kind": value["stage_kind"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    return artifact_id, stage_id, transition_id


def _validate_shape(value: Mapping[str, object]) -> None:
    if set(value) != CASE_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentContractMirrorError("contract:schema")
    if value.get("contract_binding") != _contract_binding() or value.get("profile_binding") != _profile_binding():
        raise IndependentContractMirrorError("contract:profile-binding")
    _text(value["stage_kind"], "stage")
    if value["stage_kind"] not in STAGES:
        raise IndependentContractMirrorError("contract:stage")
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        _hex(value[key], key)
    for key in ("prior_artifact_id", "prior_stage_id"):
        _hex(value[key], key, nullable=True)
    if (value["prior_artifact_id"] is None) != (value["prior_stage_id"] is None):
        raise IndependentContractMirrorError("contract:prior-pair")
    governance_binding = _expect(value["governance_binding"], GOVERNANCE_KEYS, "governance")
    for key in ("artifact_id", "stage_id", "transition_id", "profile_digest"):
        _hex(governance_binding[key], f"governance-{key}")
    for key in ("profile_id",):
        _text(governance_binding[key], f"governance-{key}")
    for key in ("profile_version", "effective_start", "effective_end"):
        if type(governance_binding[key]) is not int:
            raise IndependentContractMirrorError(f"contract:governance-{key}")
    obligation = _expect(value["obligation"], OBLIGATION_KEYS, "obligation")
    if obligation["obligation_id"] != OBLIGATION_ID or obligation["version"] != OBLIGATION_VERSION or obligation["responsibility_profile_id"] != RESPONSIBILITY_PROFILE_ID:
        raise IndependentContractMirrorError("contract:obligation")
    if obligation["effective_start"] != governance_binding["effective_start"] or obligation["effective_end"] != governance_binding["effective_end"] or obligation["governance_artifact_id"] != governance_binding["artifact_id"]:
        raise IndependentContractMirrorError("contract:obligation-governance")
    for key in ("subject", "scope", "responsible_boundary", "population_definition_id", "denominator_contract_id"):
        _text(obligation[key], f"obligation-{key}")
    for key in ("version", "effective_start", "effective_end", "population_definition_version", "denominator_profile_version"):
        if type(obligation[key]) is not int:
            raise IndependentContractMirrorError(f"contract:obligation-{key}")
    denom = _expect(value["denominator"], DENOMINATOR_KEYS, "denominator")
    for key in ("artifact_id", "stage_id", "transition_id", "population_root"):
        _hex(denom[key], f"denominator-{key}")
    for key in ("child_population_root", "outcome_root"):
        _hex(denom[key], f"denominator-{key}", nullable=True)
    for key in ("stage_kind", "profile_id", "coverage_status", "source_completeness"):
        _text(denom[key], f"denominator-{key}")
    for key in ("profile_version", "input_record_count"):
        _count(denom[key], f"denominator-{key}")
    if denom["allow_nonmembership"] is not False or denom["source_completeness"] != "UNKNOWN":
        raise IndependentContractMirrorError("contract:denominator-claims")
    if denom["stage_kind"] == denominator.STAGE_NARROWED:
        counts = _expect(denom["outcome_counts"], set(denominator.BUCKETS), "denominator-outcomes")
        for key in denominator.BUCKETS:
            _count(counts[key], f"denominator-outcome-{key}")
    elif denom["stage_kind"] == denominator.STAGE_BASELINE:
        if denom["child_population_root"] is not None or denom["outcome_root"] is not None or denom["outcome_counts"] is not None:
            raise IndependentContractMirrorError("contract:baseline-buckets")
    else:
        raise IndependentContractMirrorError("contract:denominator-stage")
    observation = _expect(value["observation"], OBSERVATION_KEYS, "observation")
    for key in ("reconciliation_artifact_id", "reconciliation_stage_id", "reconciliation_transition_id", "normalized_content_root"):
        _hex(observation[key], f"observation-{key}")
    _hex(observation["comparison_content_root"], "observation-comparison-root", nullable=True)
    for key in ("source_observation_status", "linkage_status", "chronology_order", "source_completeness"):
        _text(observation[key], f"observation-{key}")
    if observation["allow_nonmembership"] is not False or observation["source_completeness"] != "UNKNOWN":
        raise IndependentContractMirrorError("contract:observation-claims")
    case_link = _expect(value["case_link"], CASE_LINK_KEYS, "case-link")
    for key in ("case_id", "artifact_id", "stage_id", "transition_id", "finding_id"):
        _hex(case_link[key], f"case-link-{key}")
    _text(case_link["lifecycle_state"], "case-link-lifecycle")
    evaluation = _expect(value["evaluation"], EVALUATION_KEYS, "evaluation")
    if evaluation["status"] not in RESULT_STATUSES or evaluation["expected_result"] != "RETURNED_PROVIDER_DIRECTORY_OBSERVATION" or evaluation["observed_result"] != observation["source_observation_status"]:
        raise IndependentContractMirrorError("contract:evaluation")
    if evaluation["dimensions"] != ["denominator_population", "source_observation_status", "normalized_content_root", "chronology_order"]:
        raise IndependentContractMirrorError("contract:evaluation-dimensions")
    for key in ("conformance_claim", "variance_claim", "absence_inferred", "nonmembership_inferred", "business_truth_proven"):
        if evaluation[key] is not False:
            raise IndependentContractMirrorError("contract:evaluation-claim")
    exception = _expect(value["exception_reference"], EXCEPTION_KEYS, "exception")
    if exception["status"] != "NOT_APPLIED" or exception["class_id"] != EXCEPTION_CLASS_ID or exception["governance_artifact_id"] != governance_binding["artifact_id"] or exception["effective_start"] is not None or exception["effective_end"] is not None or exception["changes_obligation"] is not False or exception["payment_authority"] is not False or exception["synthetic_only"] is not True:
        raise IndependentContractMirrorError("contract:exception")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentContractMirrorError("contract:authority-flags")
    if value["stage_kind"] == STAGE_EVALUATED and (value["prior_artifact_id"] is not None or value["prior_stage_id"] is not None):
        raise IndependentContractMirrorError("contract:initial-prior")
    if value["stage_kind"] == STAGE_RETESTED and (value["prior_artifact_id"] is None or value["prior_stage_id"] is None):
        raise IndependentContractMirrorError("contract:retest-prior")


def _expected_body(
    stage: str,
    *,
    denominator_raw: bytes,
    denominator_context: Mapping[str, object],
    case_raw: bytes,
    case_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_contract_raw: bytes | None,
) -> dict[str, object]:
    denom_value, denom_result = _verify_denominator(denominator_raw, denominator_context, registry)
    case_value, case_result = _verify_case(case_raw, case_context, registry)
    upstream = _expect(case_value["upstream"], case.UPSTREAM_KEYS, "case-upstream")
    graph = _expect(upstream["graph"], case.GRAPH_KEYS, "case-graph")
    subject = {"subject": _text(case_value["subject"], "subject"), "scope": _text(case_value["scope"], "scope")}
    profile = {"profile_id": _text(graph["profile_id"], "graph-profile"), "version": graph["profile_version"], "profile_digest": _hex(graph["profile_digest"], "graph-profile-digest")}
    if type(profile["version"]) is not int:
        raise IndependentContractMirrorError("contract:graph-version")
    governance_raw = case_context["governance_raw"]
    governance_binding = _governance_binding(governance_raw, registry, profile, subject)
    if denom_value["governance_binding"]["artifact_id"] != governance_binding["artifact_id"]:
        raise IndependentContractMirrorError("contract:denominator-governance")
    if denom_value["source_binding"]["profile_digest"] != profile["profile_digest"]:
        raise IndependentContractMirrorError("contract:denominator-profile")
    observation_raw = case_context["reconciliation_raw"]
    if stage == STAGE_RETESTED:
        if prior_contract_raw is None:
            raise IndependentContractMirrorError("contract:prior-required")
        prior = _parse(prior_contract_raw)
        if prior.get("stage_kind") != STAGE_EVALUATED:
            raise IndependentContractMirrorError("contract:prior-stage")
        if prior.get("denominator", {}).get("artifact_id") != denom_result["artifact_id"]:
            raise IndependentContractMirrorError("contract:prior-denominator")
        if case_value["lifecycle_state"] not in {case.STAGE_PARITY, case.STAGE_PERSISTS}:
            raise IndependentContractMirrorError("contract:retest-case-stage")
        if case_value["retest"]["reconciliation_artifact_id"] is None:
            raise IndependentContractMirrorError("contract:retest-observation")
        observation_raw = case_context.get("retest_reconciliation_raw")
        if not isinstance(observation_raw, bytes):
            raise IndependentContractMirrorError("contract:retest-context")
    elif stage != STAGE_EVALUATED or prior_contract_raw is not None:
        raise IndependentContractMirrorError("contract:stage-input")
    if stage == STAGE_EVALUATED and case_value["lifecycle_state"] != case.STAGE_OPEN:
        raise IndependentContractMirrorError("contract:initial-case-stage")
    _, observation = _observation(observation_raw)
    if stage == STAGE_EVALUATED and observation["reconciliation_artifact_id"] != upstream["reconciliation"]["artifact_id"]:
        raise IndependentContractMirrorError("contract:case-observation")
    if stage == STAGE_EVALUATED and denom_value["source_binding"]["artifact_id"] != upstream["reconciliation"]["current_custody_artifact_id"]:
        raise IndependentContractMirrorError("contract:denominator-source")
    responsibility = case._responsibility(upstream["finding"]["kind"], observation["source_observation_status"])
    obligation = _obligation(governance_binding=governance_binding, subject=subject, responsible_boundary=responsibility["boundary"])
    body = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "contract_binding": _contract_binding(),
        "profile_binding": _profile_binding(),
        "governance_binding": governance_binding,
        "obligation": obligation,
        "denominator": _denominator_binding(denom_value, denom_result),
        "observation": observation,
        "case_link": _case_link(case_value, case_result),
        "evaluation": _evaluation(_denominator_binding(denom_value, denom_result), observation),
        "exception_reference": _exception_reference(governance_binding),
        "stage_kind": stage,
        "prior_artifact_id": prior_contract_raw and _parse(prior_contract_raw)["artifact_id"],
        "prior_stage_id": prior_contract_raw and _parse(prior_contract_raw)["current_stage_id"],
        "flags": dict(FIXED_FLAGS),
        "authority": dict(AUTHORITY_FLAGS),
    }
    return body


def build_artifact(
    stage: str,
    *,
    denominator_raw: bytes,
    denominator_context: Mapping[str, object],
    case_raw: bytes,
    case_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_contract_raw: bytes | None = None,
) -> bytes:
    if stage not in STAGES:
        raise IndependentContractMirrorError("contract:stage")
    body = _expected_body(
        stage,
        denominator_raw=denominator_raw,
        denominator_context=denominator_context,
        case_raw=case_raw,
        case_context=case_context,
        registry=registry,
        prior_contract_raw=prior_contract_raw,
    )
    artifact_id, stage_id, transition_id = _identity_values(body)
    value = {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}
    _validate_shape(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentContractMirrorError("contract:artifact-byte-cap")
    return raw


def verify_artifact(
    raw: bytes,
    *,
    denominator_raw: bytes,
    denominator_context: Mapping[str, object],
    case_raw: bytes,
    case_context: Mapping[str, object],
    registry: Mapping[str, object],
    prior_contract_raw: bytes | None = None,
) -> dict[str, object]:
    value = _parse(raw)
    _validate_shape(value)
    expected = _expected_body(
        value["stage_kind"],
        denominator_raw=denominator_raw,
        denominator_context=denominator_context,
        case_raw=case_raw,
        case_context=case_context,
        registry=registry,
        prior_contract_raw=prior_contract_raw,
    )
    body = dict(value)
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    if body != expected:
        raise IndependentContractMirrorError("contract:semantic-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentContractMirrorError("contract:identity")
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": _digest("payload", raw.hex()),
        "subject": value["obligation"]["subject"],
        "scope": value["obligation"]["scope"],
        "report_id": value["artifact_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": CONTRACT_PROFILE_ID,
        "profile_version": CONTRACT_PROFILE_VERSION,
        "contract_stage": value["stage_kind"],
        "denominator_artifact_id": value["denominator"]["artifact_id"],
        "denominator_population_root": value["denominator"]["population_root"],
        "case_artifact_id": value["case_link"]["artifact_id"],
        "case_id": value["case_link"]["case_id"],
        "reconciliation_artifact_id": value["observation"]["reconciliation_artifact_id"],
        "evaluation_status": value["evaluation"]["status"],
    }


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "CASE_KEYS", "CONTRACT_PROFILE_ID", "CONTRACT_PROFILE_VERSION",
    "FIXED_FLAGS", "IndependentContractMirrorError", "MAX_ARTIFACT_BYTES", "OBLIGATION_ID", "OBLIGATION_VERSION",
    "RESULT_CONFORMING", "RESULT_INDETERMINATE", "RESULT_PARTIAL", "RESULT_UNAVAILABLE", "RESULT_VARIANCE",
    "SCHEMA", "SCHEMA_VERSION", "STAGE_EVALUATED", "STAGE_KIND", "STAGE_RETESTED", "STAGES",
    "build_artifact", "verify_artifact", "_canonical", "_digest", "_parse", "_identity_values",
]
