"""Independent verifier for the bounded Mirror discrepancy-case lifecycle.

The case is an evidence and observation artifact, not a ticket, adjudication,
liability finding, payment instruction, or source-truth assertion.  This module
reconstructs every case transition from independently verified graph,
reconciliation, and governed-profile bytes.  It deliberately does not import
the composition service or the persistence store.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

from app.governance import provider_continuity_control_pack_v2_independent as governance
from app.mirror import provider_trust_graph_independent as graph
from app.mirror import source_reconciliation_independent as reconciliation


ARTIFACT_KIND = "MIRROR_DISCREPANCY_CASE_V1"
SCHEMA = "mirror-discrepancy-case-v1"
SCHEMA_VERSION = 1
STAGE_KIND = "DISCREPANCY_CASE"
DOMAIN = "BL/MIRROR/DISCREPANCY-CASE/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
HEX128 = re.compile(r"^[0-9a-f]{128}$")

CONTRACT_ID = "mirror.discrepancy-case.lifecycle.v1"
CONTRACT_VERSION = 1
RESPONSIBILITY_PROFILE_ID = "mirror.responsibility-boundary.synthetic-v1"
RETEST_PROFILE_ID = "mirror.retest-parity.synthetic-v1"

STAGE_OPEN = "OPEN_DISCREPANCY"
STAGE_RESPONSIBILITY = "RESPONSIBILITY_RECORDED"
STAGE_REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
STAGE_REMEDIATION_EVIDENCE = "REMEDIATION_EVIDENCE_ATTACHED"
STAGE_RETEST = "RETEST_EXECUTED"
STAGE_PARITY = "PARITY_OBSERVED"
STAGE_PERSISTS = "DISCREPANCY_PERSISTS"
STAGE_RESOLVED = "RESOLUTION_OBSERVED"
STAGE_SUPERSEDED = "SUPERSEDED_BY_NEW_EVIDENCE"
STAGES = (
    STAGE_OPEN,
    STAGE_RESPONSIBILITY,
    STAGE_REMEDIATION_PROPOSED,
    STAGE_REMEDIATION_EVIDENCE,
    STAGE_RETEST,
    STAGE_PARITY,
    STAGE_PERSISTS,
    STAGE_RESOLVED,
    STAGE_SUPERSEDED,
)
TERMINAL_STAGES = frozenset({STAGE_RESOLVED, STAGE_SUPERSEDED})

RESP_UNKNOWN = "UNKNOWN"
RESP_SHARED = "SHARED"
RESP_STATE_SOURCE = "STATE_SOURCE"
RESP_PLAN_OR_PROVIDER = "PLAN_OR_PROVIDER"
RESP_RIGHTRAIL_PROCESSING = "RIGHTRAIL_PROCESSING"
RESPONSIBILITIES = (
    RESP_UNKNOWN,
    RESP_SHARED,
    RESP_STATE_SOURCE,
    RESP_PLAN_OR_PROVIDER,
    RESP_RIGHTRAIL_PROCESSING,
)

PARITY_FULL = "FULL_BOUNDED_PARITY"
PARITY_PARTIAL = "PARTIAL_PARITY"
PARITY_MISMATCH = "MISMATCH"
PARITY_INDETERMINATE = "INDETERMINATE"
PARITY_STALE = "STALE"
PARITY_UNAVAILABLE = "UNAVAILABLE"
PARITY_STATUSES = (
    PARITY_FULL,
    PARITY_PARTIAL,
    PARITY_MISMATCH,
    PARITY_INDETERMINATE,
    PARITY_STALE,
    PARITY_UNAVAILABLE,
)

ACTION_RESPONSIBILITY = STAGE_RESPONSIBILITY
ACTION_REMEDIATION_PROPOSED = STAGE_REMEDIATION_PROPOSED
ACTION_REMEDIATION_EVIDENCE = STAGE_REMEDIATION_EVIDENCE
ACTION_RETEST = STAGE_RETEST
ACTION_PARITY = STAGE_PARITY
ACTION_PERSISTS = STAGE_PERSISTS
ACTION_RESOLVE = STAGE_RESOLVED
ACTION_SUPERSEDE = STAGE_SUPERSEDED
ACTIONS = frozenset({
    ACTION_RESPONSIBILITY,
    ACTION_REMEDIATION_PROPOSED,
    ACTION_REMEDIATION_EVIDENCE,
    ACTION_RETEST,
    ACTION_PARITY,
    ACTION_PERSISTS,
    ACTION_RESOLVE,
    ACTION_SUPERSEDE,
})

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
    "contract",
    "profile_binding",
    "governance_binding",
    "subject",
    "scope",
    "case_id",
    "upstream",
    "responsibility",
    "remediation",
    "retest",
    "resolution",
    "lifecycle_state",
    "transition",
    "flags",
    "authority",
    "artifact_id",
    "current_stage_id",
    "transition_id",
}
CONTRACT_KEYS = {
    "contract_id",
    "version",
    "stages",
    "responsibility_profile_id",
    "retest_profile_id",
    "parity_statuses",
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
GRAPH_KEYS = {
    "artifact_id",
    "report_id",
    "transition_id",
    "snapshot_id",
    "snapshot_root",
    "profile_id",
    "profile_version",
    "profile_digest",
    "governance_artifact_id",
    "governance_stage_id",
    "governance_transition_id",
}
FINDING_KEYS = {"finding_id", "kind", "observation_snapshot_id", "evidence_refs"}
RECON_KEYS = {
    "artifact_id",
    "stage_id",
    "transition_id",
    "result_status",
    "linkage_status",
    "current_custody_artifact_id",
    "current_custody_stage_id",
    "content_root",
    "comparison_root",
    "chronology_order",
    "chronology_prior_marker",
    "chronology_current_marker",
    "source_completeness",
    "allow_nonmembership",
    "graph_link_role",
}
UPSTREAM_KEYS = {"graph", "finding", "reconciliation"}
RESPONSIBILITY_KEYS = {
    "boundary",
    "basis",
    "mapping_profile_id",
    "liability_claim",
    "blame_claim",
    "synthetic_only",
}
REMEDIATION_KEYS = {
    "proposal",
    "assertion",
    "verified_result",
    "real_world_correction_proven",
}
RETEST_KEYS = {
    "status",
    "reconciliation_artifact_id",
    "source_observation_status",
    "parity",
}
PARITY_KEYS = {
    "status",
    "profile_id",
    "dimensions",
    "expected_finding_kind",
    "observed_source_status",
    "normalized_content_root",
    "chronology_order",
    "basis",
    "full_bounded_claim",
    "absence_inferred",
    "nonmembership_inferred",
    "business_truth_proven",
}
RESOLUTION_KEYS = {"state", "basis", "business_truth_proven"}
TRANSITION_KEYS = {"transition_kind", "prior_artifact_id", "prior_stage_id", "case_id", "basis"}

_PREVIOUS = {
    STAGE_RESPONSIBILITY: {STAGE_OPEN},
    STAGE_REMEDIATION_PROPOSED: {STAGE_RESPONSIBILITY},
    STAGE_REMEDIATION_EVIDENCE: {STAGE_REMEDIATION_PROPOSED},
    STAGE_RETEST: {STAGE_REMEDIATION_EVIDENCE},
    STAGE_PARITY: {STAGE_RETEST},
    STAGE_PERSISTS: {STAGE_RETEST},
    STAGE_RESOLVED: {STAGE_PARITY},
    STAGE_SUPERSEDED: set(STAGES) - {STAGE_RESOLVED, STAGE_SUPERSEDED},
}
_BASIS = {
    STAGE_OPEN: "GRAPH_FINDING_AND_RECONCILIATION",
    STAGE_RESPONSIBILITY: "VERIFIER_OWNED_RESPONSIBILITY_MAPPING",
    STAGE_REMEDIATION_PROPOSED: "BOUNDED_SYNTHETIC_REMEDIATION_REFERENCE",
    STAGE_REMEDIATION_EVIDENCE: "BOUNDED_SYNTHETIC_ACTOR_ASSERTION",
    STAGE_RETEST: "DETERMINISTIC_RETEST_AGAINST_STORED_RECONCILIATION",
    STAGE_PARITY: "RETEST_RESULT_PARITY_CLASSIFICATION",
    STAGE_PERSISTS: "RETEST_RESULT_REMAINS_DISCREPANT",
    STAGE_RESOLVED: "FULL_BOUNDED_PARITY_ONLY",
    STAGE_SUPERSEDED: "NEW_STORED_SOURCE_EVIDENCE",
}
_HEX_FIELDS = {
    "artifact_id",
    "stage_id",
    "transition_id",
    "profile_digest",
    "snapshot_id",
    "snapshot_root",
    "governance_artifact_id",
    "governance_stage_id",
    "governance_transition_id",
    "finding_id",
    "current_custody_artifact_id",
    "current_custody_stage_id",
    "content_root",
    "comparison_root",
}


class IndependentDiscrepancyCaseError(ValueError):
    """Stable fail-closed error from the case verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentDiscrepancyCaseError("case:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentDiscrepancyCaseError("case:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentDiscrepancyCaseError("case:node-cap")
    if depth > 24:
        raise IndependentDiscrepancyCaseError("case:depth-cap")
    if isinstance(value, float):
        raise IndependentDiscrepancyCaseError("case:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentDiscrepancyCaseError("case:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentDiscrepancyCaseError("case:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentDiscrepancyCaseError("case:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentDiscrepancyCaseError("case:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentDiscrepancyCaseError("case:constant")),
        )
    except IndependentDiscrepancyCaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentDiscrepancyCaseError("case:parse") from exc
    if not isinstance(value, dict):
        raise IndependentDiscrepancyCaseError("case:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentDiscrepancyCaseError("case:not-canonical")
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
        raise IndependentDiscrepancyCaseError(f"case:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentDiscrepancyCaseError(f"case:{label}")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise IndependentDiscrepancyCaseError(f"case:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentDiscrepancyCaseError(f"case:{label}") from exc
    return value


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentDiscrepancyCaseError(f"case:{label}-keys")
    return value


def _contract_binding() -> dict[str, object]:
    material = {
        "contract_id": CONTRACT_ID,
        "version": CONTRACT_VERSION,
        "stages": list(STAGES),
        "responsibility_profile_id": RESPONSIBILITY_PROFILE_ID,
        "retest_profile_id": RETEST_PROFILE_ID,
        "parity_statuses": list(PARITY_STATUSES),
        "claims": {
            "evidence_only": True,
            "liability": False,
            "real_world_correction": False,
            "absence": False,
            "nonmembership": False,
            "payment": False,
        },
    }
    return {**material, "contract_digest": _digest("contract", material)}


def _profile_binding(profile: Mapping[str, object]) -> dict[str, object]:
    descriptor = _expect_keys(profile, PROFILE_KEYS, "profile")
    _text(descriptor["profile_id"], "profile-id")
    if type(descriptor["version"]) is not int or descriptor["version"] < 1:
        raise IndependentDiscrepancyCaseError("case:profile-version")
    _hex(descriptor["profile_digest"], "profile-digest")
    return dict(descriptor)


def _verify_graph(raw: bytes, registry: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    try:
        value = graph._parse(raw)
        if value.get("schema") != graph.SCHEMA_V2:
            raise IndependentDiscrepancyCaseError("case:graph-v1-not-supported")
        result = graph.verify_bytes_v2(raw, registry)
        profile_binding = _profile_binding(value["profile"])
        subject = _expect_keys(value["subject"], {"provider_graph_subject", "scope"}, "graph-subject")
        snapshot = _expect_keys(value["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "graph-snapshot")
        _hex(result["report_id"], "graph-report")
        _hex(value["transition"]["transition_id"], "graph-transition")
        _hex(snapshot["snapshot_id"], "graph-snapshot-id")
        _hex(snapshot["snapshot_root"], "graph-snapshot-root")
    except IndependentDiscrepancyCaseError:
        raise
    except Exception as exc:
        raise IndependentDiscrepancyCaseError("case:graph-reject") from exc
    return value, result, {"profile": profile_binding, "subject": subject, "snapshot": snapshot}


def _verify_governance(raw: bytes, registry: Mapping[str, object], profile_binding: Mapping[str, object], subject: Mapping[str, object]) -> dict[str, object]:
    try:
        value = governance._parse(raw)
        result = governance.verify_bytes(raw, registry)
        if value.get("schema") != governance.SCHEMA or result.get("current_stage_kind") != governance.STAGE_APPROVED:
            raise IndependentDiscrepancyCaseError("case:governance-not-approved")
        descriptor = _expect_keys(value["profile"], governance.PROFILE_KEYS, "governance-profile")
        if any(descriptor[key] != profile_binding[key] for key in ("profile_id", "version", "profile_digest")):
            raise IndependentDiscrepancyCaseError("case:governance-profile")
        if value.get("subject") != dict(subject):
            raise IndependentDiscrepancyCaseError("case:governance-subject")
        _hex(result["artifact_id"], "governance-artifact")
        _hex(result["current_stage_id"], "governance-stage")
        _hex(value["chain_root"], "governance-transition")
        if type(result.get("effective_start")) is not int or type(result.get("effective_end")) is not int:
            raise IndependentDiscrepancyCaseError("case:governance-interval")
    except IndependentDiscrepancyCaseError:
        raise
    except Exception as exc:
        raise IndependentDiscrepancyCaseError("case:governance-reject") from exc
    return {
        "artifact_id": result["artifact_id"],
        "stage_id": result["current_stage_id"],
        "transition_id": value["chain_root"],
        "profile_id": result["profile_id"],
        "profile_version": result["profile_version"],
        "profile_digest": result["profile_digest"],
        "effective_start": result["effective_start"],
        "effective_end": result["effective_end"],
    }


def _graph_finding(value: Mapping[str, object], finding_id: str) -> dict[str, object]:
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise IndependentDiscrepancyCaseError("case:graph-findings")
    selected = None
    for candidate in findings:
        item = _expect_keys(candidate, graph.FINDING_KEYS, "graph-finding")
        if item.get("finding_id") == finding_id:
            if selected is not None:
                raise IndependentDiscrepancyCaseError("case:finding-duplicate")
            selected = item
    if selected is None:
        raise IndependentDiscrepancyCaseError("case:finding-missing")
    refs = selected.get("evidence_refs")
    if not isinstance(refs, list) or refs != sorted(refs) or len(set(refs)) != len(refs):
        raise IndependentDiscrepancyCaseError("case:finding-evidence")
    return {
        "finding_id": _hex(selected["finding_id"], "finding-id"),
        "kind": _text(selected["kind"], "finding-kind"),
        "observation_snapshot_id": _hex(selected["observation_snapshot_id"], "finding-snapshot"),
        "evidence_refs": [_text(item, "finding-ref") for item in refs],
    }


def _graph_link_role(recon_value: Mapping[str, object], graph_artifact_id: str) -> str:
    for role, key in (("CURRENT", "current_custody"), ("PREDECESSOR", "predecessor_custody")):
        summary = recon_value.get(key)
        if not isinstance(summary, dict):
            continue
        link = summary.get("graph_link")
        if isinstance(link, dict) and link.get("artifact_id") == graph_artifact_id:
            return role
    raise IndependentDiscrepancyCaseError("case:graph-reconciliation-binding")


def _verify_reconciliation(
    raw: bytes,
    context: Mapping[str, object],
    registry: Mapping[str, object],
    graph_artifact_id: str | None,
) -> tuple[dict[str, object], dict[str, object], str]:
    required = {"current_custody_raw", "prior_custody_raw", "current_graph_raw", "prior_graph_raw", "prior_reconciliation_raw", "qualified_baseline_custody_raw", "chronology_anchor_custody_raw"}
    if set(context) != required:
        raise IndependentDiscrepancyCaseError("case:reconciliation-context")
    try:
        value = reconciliation._parse(raw)
        result = reconciliation.verify_artifact(
            raw,
            current_custody_raw=context["current_custody_raw"],
            prior_custody_raw=context["prior_custody_raw"],
            current_graph_raw=context["current_graph_raw"],
            prior_graph_raw=context["prior_graph_raw"],
            prior_reconciliation_raw=context["prior_reconciliation_raw"],
            qualified_baseline_custody_raw=context["qualified_baseline_custody_raw"],
            chronology_anchor_custody_raw=context["chronology_anchor_custody_raw"],
            graph_profile_registry=registry,
        )
        role = _graph_link_role(value, graph_artifact_id) if graph_artifact_id is not None else "NONE"
        current = value["current_custody"]
        if not isinstance(current, dict):
            raise IndependentDiscrepancyCaseError("case:reconciliation-current")
        chronology = _expect_keys(value["chronology"], reconciliation.CHRONOLOGY_KEYS, "reconciliation-chronology")
        result_body = _expect_keys(value["result"], reconciliation.RESULT_KEYS, "reconciliation-result")
        source_content = _expect_keys(value["source_content"], reconciliation.SOURCE_CONTENT_KEYS, "reconciliation-content")
        _hex(result["artifact_id"], "reconciliation-artifact")
        _hex(result["current_stage_id"], "reconciliation-stage")
        _hex(result["transition_id"], "reconciliation-transition")
        _hex(current["artifact_id"], "reconciliation-custody-artifact")
        _hex(current["stage_id"], "reconciliation-custody-stage")
        _hex(source_content["current_root"], "reconciliation-content-root")
        _hex(source_content["comparison_root"], "reconciliation-comparison-root", nullable=True)
    except IndependentDiscrepancyCaseError:
        raise
    except Exception as exc:
        raise IndependentDiscrepancyCaseError("case:reconciliation-reject") from exc
    return value, result, role


def _upstream(
    graph_raw: bytes,
    reconciliation_raw: bytes,
    reconciliation_context: Mapping[str, object],
    governance_raw: bytes,
    registry: Mapping[str, object],
    finding_id: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    graph_value, graph_result, graph_meta = _verify_graph(graph_raw, registry)
    profile_binding = graph_meta["profile"]
    subject = graph_meta["subject"]
    governance_binding = _verify_governance(governance_raw, registry, profile_binding, subject)
    if governance_binding["profile_id"] != profile_binding["profile_id"] or governance_binding["profile_digest"] != profile_binding["profile_digest"]:
        raise IndependentDiscrepancyCaseError("case:governance-profile-binding")
    finding = _graph_finding(graph_value, finding_id)
    snapshot = graph_meta["snapshot"]
    if finding["observation_snapshot_id"] != snapshot["snapshot_id"]:
        raise IndependentDiscrepancyCaseError("case:finding-snapshot")
    if not governance_binding["effective_start"] <= snapshot["observation_time"] <= governance_binding["effective_end"]:
        raise IndependentDiscrepancyCaseError("case:governance-effective-interval")
    recon_value, recon_result, link_role = _verify_reconciliation(
        reconciliation_raw,
        reconciliation_context,
        registry,
        graph_result["report_id"],
    )
    if recon_result["profile_id"] != profile_binding["profile_id"] or recon_result["subject"] != subject["provider_graph_subject"] or recon_result["scope"] != subject["scope"]:
        raise IndependentDiscrepancyCaseError("case:reconciliation-profile-binding")
    current = recon_value["current_custody"]
    chronology = recon_value["chronology"]
    result_body = recon_value["result"]
    source_content = recon_value["source_content"]
    upstream = {
        "graph": {
            "artifact_id": graph_result["report_id"],
            "report_id": graph_result["report_id"],
            "transition_id": graph_value["transition"]["transition_id"],
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_root": snapshot["snapshot_root"],
            "profile_id": profile_binding["profile_id"],
            "profile_version": profile_binding["version"],
            "profile_digest": profile_binding["profile_digest"],
            "governance_artifact_id": governance_binding["artifact_id"],
            "governance_stage_id": governance_binding["stage_id"],
            "governance_transition_id": governance_binding["transition_id"],
        },
        "finding": finding,
        "reconciliation": {
            "artifact_id": recon_result["artifact_id"],
            "stage_id": recon_result["current_stage_id"],
            "transition_id": recon_result["transition_id"],
            "result_status": result_body["source_observation_status"],
            "linkage_status": recon_value["linkage_transition"]["status"],
            "current_custody_artifact_id": current["artifact_id"],
            "current_custody_stage_id": current["stage_id"],
            "content_root": source_content["current_root"],
            "comparison_root": source_content["comparison_root"],
            "chronology_order": chronology["order"],
            "chronology_prior_marker": chronology["prior_marker"],
            "chronology_current_marker": chronology["current_marker"],
            "source_completeness": "UNKNOWN",
            "allow_nonmembership": False,
            "graph_link_role": link_role,
        },
    }
    return upstream, profile_binding, governance_binding, {"subject": subject["provider_graph_subject"], "scope": subject["scope"]}


def _case_id(upstream: Mapping[str, object], profile_binding: Mapping[str, object], governance_binding: Mapping[str, object]) -> str:
    return _digest(
        "case-id",
        {
            "contract_id": CONTRACT_ID,
            "profile_binding": dict(profile_binding),
            "governance_artifact_id": governance_binding["artifact_id"],
            "graph_artifact_id": upstream["graph"]["artifact_id"],
            "finding_id": upstream["finding"]["finding_id"],
            "reconciliation_artifact_id": upstream["reconciliation"]["artifact_id"],
        },
    )


def _responsibility(finding_kind: str, source_status: str) -> dict[str, object]:
    if source_status == reconciliation.STATUS_SOURCE_FAILURE:
        boundary = RESP_RIGHTRAIL_PROCESSING
    elif finding_kind in {graph.FINDING_CONFLICT}:
        boundary = RESP_SHARED
    elif finding_kind in {graph.FINDING_INCOMPLETE, graph.FINDING_STALE}:
        boundary = RESP_STATE_SOURCE
    else:
        boundary = RESP_UNKNOWN
    return {
        "boundary": boundary,
        "basis": "EXPLICIT_SYNTHETIC_FINDING_AND_SOURCE_STATUS_MAPPING",
        "mapping_profile_id": RESPONSIBILITY_PROFILE_ID,
        "liability_claim": False,
        "blame_claim": False,
        "synthetic_only": True,
    }


def _empty_remediation() -> dict[str, object]:
    return {
        "proposal": None,
        "assertion": None,
        "verified_result": None,
        "real_world_correction_proven": False,
    }


def _remediation_reference(kind: str) -> dict[str, object]:
    if kind == "proposal":
        return {
            "reference_code": "SYNTHETIC_REMEDIATION_PROPOSAL_V1",
            "actor_class": "SYNTHETIC_BOUNDARY",
            "authority_class": "NONPRODUCTION",
            "claim_class": "PROPOSAL_ONLY",
        }
    if kind == "assertion":
        return {
            "reference_code": "SYNTHETIC_REMEDIATION_ASSERTION_V1",
            "actor_class": "SYNTHETIC_BOUNDARY",
            "authority_class": "NONPRODUCTION",
            "claim_class": "ACTOR_ASSERTION_ONLY",
        }
    raise IndependentDiscrepancyCaseError("case:remediation-kind")


def _parity(finding_kind: str, recon_value: Mapping[str, object], recon_result: Mapping[str, object]) -> dict[str, object]:
    result_body = recon_value["result"]
    source_status = result_body["source_observation_status"]
    if source_status == reconciliation.STATUS_OBSERVED_CONTINUED and finding_kind == graph.FINDING_CONTINUITY:
        status, basis = PARITY_FULL, "CONTINUITY_FINDING_AND_CONTINUED_CONTENT"
    elif source_status == reconciliation.STATUS_OBSERVED_CHANGED:
        status, basis = PARITY_MISMATCH, "CHANGED_VERIFIED_SOURCE_CONTENT"
    elif source_status == reconciliation.STATUS_STALE_OR_GAPPED:
        status, basis = PARITY_STALE, "STALE_OR_GAPPED_SOURCE_OBSERVATION"
    elif source_status == reconciliation.STATUS_SOURCE_FAILURE:
        status, basis = PARITY_UNAVAILABLE, "SOURCE_FAILURE"
    elif source_status in {reconciliation.STATUS_NOT_OBSERVED_INCOMPLETE, reconciliation.STATUS_CONFLICTING}:
        status, basis = PARITY_INDETERMINATE, "INCOMPLETE_OR_CONFLICTING_SOURCE"
    else:
        status, basis = PARITY_PARTIAL, "BOUNDED_OBSERVATION_NOT_FULL_PARITY"
    chronology = recon_value["chronology"]
    return {
        "status": status,
        "profile_id": RETEST_PROFILE_ID,
        "dimensions": ["finding_kind", "source_observation_status", "normalized_content_root", "chronology_order"],
        "expected_finding_kind": finding_kind,
        "observed_source_status": source_status,
        "normalized_content_root": recon_value["source_content"]["current_root"],
        "chronology_order": chronology["order"],
        "basis": basis,
        "full_bounded_claim": status == PARITY_FULL,
        "absence_inferred": False,
        "nonmembership_inferred": False,
        "business_truth_proven": False,
    }


def _empty_retest() -> dict[str, object]:
    return {
        "status": "NOT_REQUESTED",
        "reconciliation_artifact_id": None,
        "source_observation_status": None,
        "parity": None,
    }


def _empty_resolution() -> dict[str, object]:
    return {"state": "UNRESOLVED_OBSERVATION", "basis": "OPEN_DISCREPANCY", "business_truth_proven": False}


def _base_body(
    upstream: Mapping[str, object],
    profile_binding: Mapping[str, object],
    governance_binding: Mapping[str, object],
    subject: str,
    scope: str,
) -> dict[str, object]:
    case_id = _case_id(upstream, profile_binding, governance_binding)
    body: dict[str, object] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "contract": _contract_binding(),
        "profile_binding": dict(profile_binding),
        "governance_binding": dict(governance_binding),
        "subject": subject,
        "scope": scope,
        "case_id": case_id,
        "upstream": deepcopy(dict(upstream)),
        "responsibility": None,
        "remediation": _empty_remediation(),
        "retest": _empty_retest(),
        "resolution": _empty_resolution(),
        "lifecycle_state": STAGE_OPEN,
        "transition": {
            "transition_kind": STAGE_OPEN,
            "prior_artifact_id": None,
            "prior_stage_id": None,
            "case_id": case_id,
            "basis": _BASIS[STAGE_OPEN],
        },
        "flags": dict(FIXED_FLAGS),
        "authority": dict(AUTHORITY_FLAGS),
    }
    return body


def _validate_prior(value: Mapping[str, object]) -> None:
    _validate_shape(value)
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value.get("artifact_id"), value.get("current_stage_id"), value.get("transition_id")) != (artifact_id, stage_id, transition_id):
        raise IndependentDiscrepancyCaseError("case:prior-identity")


def _transition_body(
    prior: Mapping[str, object],
    action: str,
    *,
    retest_value: Mapping[str, object] | None = None,
    retest_result: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if action not in ACTIONS:
        raise IndependentDiscrepancyCaseError("case:action")
    previous = prior["lifecycle_state"]
    allowed = _PREVIOUS[action]
    if previous not in allowed:
        raise IndependentDiscrepancyCaseError("case:illegal-transition")
    body = deepcopy(dict(prior))
    if action == STAGE_RESPONSIBILITY:
        body["responsibility"] = _responsibility(
            body["upstream"]["finding"]["kind"],
            body["upstream"]["reconciliation"]["result_status"],
        )
    elif action == STAGE_REMEDIATION_PROPOSED:
        remediation = body["remediation"]
        remediation["proposal"] = _remediation_reference("proposal")
    elif action == STAGE_REMEDIATION_EVIDENCE:
        remediation = body["remediation"]
        if remediation["proposal"] is None:
            raise IndependentDiscrepancyCaseError("case:remediation-proposal-required")
        remediation["assertion"] = _remediation_reference("assertion")
    elif action == STAGE_RETEST:
        if retest_value is None or retest_result is None:
            raise IndependentDiscrepancyCaseError("case:retest-context-required")
        parity = _parity(body["upstream"]["finding"]["kind"], retest_value, retest_result)
        body["retest"] = {
            "status": "EXECUTED",
            "reconciliation_artifact_id": retest_result["artifact_id"],
            "source_observation_status": retest_value["result"]["source_observation_status"],
            "parity": parity,
        }
        body["remediation"]["verified_result"] = {
            "result_code": "DETERMINISTIC_RETEST_EXECUTED",
            "verifier_profile_id": RETEST_PROFILE_ID,
            "reconciliation_artifact_id": retest_result["artifact_id"],
            "business_truth_proven": False,
        }
    elif action == STAGE_PARITY:
        parity = body["retest"]["parity"]
        if body["retest"]["status"] != "EXECUTED" or not isinstance(parity, dict) or parity["status"] != PARITY_FULL:
            raise IndependentDiscrepancyCaseError("case:parity-not-full")
    elif action == STAGE_PERSISTS:
        parity = body["retest"]["parity"]
        if body["retest"]["status"] != "EXECUTED" or not isinstance(parity, dict) or parity["status"] == PARITY_FULL:
            raise IndependentDiscrepancyCaseError("case:discrepancy-not-persistent")
        body["resolution"] = {
            "state": "UNRESOLVED_OBSERVATION",
            "basis": parity["status"],
            "business_truth_proven": False,
        }
    elif action == STAGE_RESOLVED:
        parity = body["retest"]["parity"]
        if not isinstance(parity, dict) or parity["status"] != PARITY_FULL:
            raise IndependentDiscrepancyCaseError("case:resolution-requires-full-parity")
        body["resolution"] = {
            "state": "RESOLVED_OBSERVATION",
            "basis": "FULL_BOUNDED_PARITY",
            "business_truth_proven": False,
        }
    elif action == STAGE_SUPERSEDED:
        if retest_value is None or retest_result is None:
            raise IndependentDiscrepancyCaseError("case:supersession-context-required")
        previous_reconciliation = body["upstream"]["reconciliation"]["artifact_id"]
        if retest_result["artifact_id"] == previous_reconciliation:
            raise IndependentDiscrepancyCaseError("case:supersession-new-evidence-required")
        body["resolution"] = {
            "state": "SUPERSEDED_OBSERVATION",
            "basis": "NEW_STORED_RECONCILIATION_EVIDENCE",
            "business_truth_proven": False,
        }
        body["retest"] = {
            "status": "NOT_REQUESTED",
            "reconciliation_artifact_id": retest_result["artifact_id"],
            "source_observation_status": retest_value["result"]["source_observation_status"],
            "parity": None,
        }
    body["lifecycle_state"] = action
    body["transition"] = {
        "transition_kind": action,
        "prior_artifact_id": prior["artifact_id"],
        "prior_stage_id": prior["current_stage_id"],
        "case_id": prior["case_id"],
        "basis": _BASIS[action],
    }
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    return body


def _validate_shape(value: Mapping[str, object]) -> None:
    if set(value) != CASE_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentDiscrepancyCaseError("case:schema")
    if value.get("contract") != _contract_binding():
        raise IndependentDiscrepancyCaseError("case:contract")
    profile = _profile_binding(value.get("profile_binding"))
    _ = profile
    governance_binding = _expect_keys(value.get("governance_binding"), GOVERNANCE_KEYS, "governance-binding")
    for key in ("artifact_id", "stage_id", "transition_id", "profile_digest"):
        _hex(governance_binding[key], f"governance-{key}")
    for key in ("profile_id",):
        _text(governance_binding[key], f"governance-{key}")
    for key in ("profile_version", "effective_start", "effective_end"):
        if type(governance_binding[key]) is not int:
            raise IndependentDiscrepancyCaseError(f"case:governance-{key}")
    subject = _text(value.get("subject"), "subject")
    scope = _text(value.get("scope"), "scope")
    _hex(value.get("case_id"), "case-id")
    upstream = _expect_keys(value.get("upstream"), UPSTREAM_KEYS, "upstream")
    graph_value = _expect_keys(upstream["graph"], GRAPH_KEYS, "upstream-graph")
    for key in ("artifact_id", "report_id", "transition_id", "snapshot_id", "snapshot_root", "profile_digest", "governance_artifact_id", "governance_stage_id", "governance_transition_id"):
        _hex(graph_value[key], f"upstream-graph-{key}")
    for key in ("profile_id",):
        _text(graph_value[key], f"upstream-graph-{key}")
    if type(graph_value["profile_version"]) is not int:
        raise IndependentDiscrepancyCaseError("case:upstream-graph-version")
    finding = _expect_keys(upstream["finding"], FINDING_KEYS, "upstream-finding")
    _hex(finding["finding_id"], "upstream-finding-id")
    _text(finding["kind"], "upstream-finding-kind")
    refs = finding["evidence_refs"]
    if not isinstance(refs, list) or refs != sorted(refs) or len(set(refs)) != len(refs) or any(not isinstance(item, str) or not item for item in refs):
        raise IndependentDiscrepancyCaseError("case:upstream-finding-refs")
    recon = _expect_keys(upstream["reconciliation"], RECON_KEYS, "upstream-reconciliation")
    for key in ("artifact_id", "stage_id", "transition_id", "current_custody_artifact_id", "current_custody_stage_id", "content_root"):
        _hex(recon[key], f"upstream-reconciliation-{key}")
    _hex(recon["comparison_root"], "upstream-reconciliation-comparison-root", nullable=True)
    for key in ("result_status", "linkage_status", "chronology_order", "graph_link_role", "source_completeness"):
        _text(recon[key], f"upstream-reconciliation-{key}")
    if recon["allow_nonmembership"] is not False:
        raise IndependentDiscrepancyCaseError("case:upstream-nonmembership")
    responsibility = value["responsibility"]
    if responsibility is not None:
        item = _expect_keys(responsibility, RESPONSIBILITY_KEYS, "responsibility")
        if item["boundary"] not in RESPONSIBILITIES or item["basis"] != "EXPLICIT_SYNTHETIC_FINDING_AND_SOURCE_STATUS_MAPPING" or item["mapping_profile_id"] != RESPONSIBILITY_PROFILE_ID or item["liability_claim"] is not False or item["blame_claim"] is not False or item["synthetic_only"] is not True:
            raise IndependentDiscrepancyCaseError("case:responsibility-values")
    remediation = _expect_keys(value["remediation"], REMEDIATION_KEYS, "remediation")
    if remediation["proposal"] is not None:
        if remediation["proposal"] != _remediation_reference("proposal"):
            raise IndependentDiscrepancyCaseError("case:remediation-proposal")
    if remediation["assertion"] is not None:
        if remediation["assertion"] != _remediation_reference("assertion"):
            raise IndependentDiscrepancyCaseError("case:remediation-assertion")
    if remediation["real_world_correction_proven"] is not False:
        raise IndependentDiscrepancyCaseError("case:remediation-claim")
    if remediation["verified_result"] is not None and not isinstance(remediation["verified_result"], dict):
        raise IndependentDiscrepancyCaseError("case:remediation-result")
    retest = _expect_keys(value["retest"], RETEST_KEYS, "retest")
    if retest["status"] not in {"NOT_REQUESTED", "EXECUTED"}:
        raise IndependentDiscrepancyCaseError("case:retest-status")
    _hex(retest["reconciliation_artifact_id"], "case:retest-reconciliation", nullable=True)
    if retest["source_observation_status"] is not None:
        _text(retest["source_observation_status"], "case:retest-source-status")
    if retest["status"] == "NOT_REQUESTED" and retest["parity"] is not None:
        raise IndependentDiscrepancyCaseError("case:retest-empty")
    if retest["status"] == "EXECUTED":
        parity = _expect_keys(retest["parity"], PARITY_KEYS, "parity")
        if parity["status"] not in PARITY_STATUSES or parity["profile_id"] != RETEST_PROFILE_ID or parity["dimensions"] != ["finding_kind", "source_observation_status", "normalized_content_root", "chronology_order"]:
            raise IndependentDiscrepancyCaseError("case:parity-values")
        _hex(parity["normalized_content_root"], "case:parity-content")
        if parity["full_bounded_claim"] is not (parity["status"] == PARITY_FULL) or parity["absence_inferred"] is not False or parity["nonmembership_inferred"] is not False or parity["business_truth_proven"] is not False:
            raise IndependentDiscrepancyCaseError("case:parity-flags")
    resolution = _expect_keys(value["resolution"], RESOLUTION_KEYS, "resolution")
    if resolution["state"] not in {"UNRESOLVED_OBSERVATION", "RESOLVED_OBSERVATION", "SUPERSEDED_OBSERVATION"} or resolution["business_truth_proven"] is not False:
        raise IndependentDiscrepancyCaseError("case:resolution-values")
    lifecycle = value["lifecycle_state"]
    if lifecycle not in STAGES:
        raise IndependentDiscrepancyCaseError("case:lifecycle")
    transition = _expect_keys(value["transition"], TRANSITION_KEYS, "transition")
    if transition["transition_kind"] != lifecycle or transition["case_id"] != value["case_id"] or transition["basis"] != _BASIS[lifecycle]:
        raise IndependentDiscrepancyCaseError("case:transition-values")
    _hex(transition["prior_artifact_id"], "case:prior-artifact", nullable=True)
    _hex(transition["prior_stage_id"], "case:prior-stage", nullable=True)
    if (transition["prior_artifact_id"] is None) != (transition["prior_stage_id"] is None):
        raise IndependentDiscrepancyCaseError("case:prior-pair")
    if value["flags"] != FIXED_FLAGS or value["authority"] != AUTHORITY_FLAGS:
        raise IndependentDiscrepancyCaseError("case:authority-flags")
    _validate_lifecycle_semantics(value)


def _validate_lifecycle_semantics(value: Mapping[str, object]) -> None:
    """Reject a well-shaped byte sequence whose state does not match its stage."""

    lifecycle = value["lifecycle_state"]
    transition = value["transition"]
    prior_exists = transition["prior_artifact_id"] is not None
    if lifecycle == STAGE_OPEN:
        if prior_exists or value["responsibility"] is not None or value["remediation"] != _empty_remediation() or value["retest"] != _empty_retest() or value["resolution"] != _empty_resolution():
            raise IndependentDiscrepancyCaseError("case:open-state")
        return
    if not prior_exists:
        raise IndependentDiscrepancyCaseError("case:noninitial-prior")

    responsibility_required = lifecycle in {
        STAGE_RESPONSIBILITY,
        STAGE_REMEDIATION_PROPOSED,
        STAGE_REMEDIATION_EVIDENCE,
        STAGE_RETEST,
        STAGE_PARITY,
        STAGE_PERSISTS,
        STAGE_RESOLVED,
    }
    if responsibility_required and value["responsibility"] is None:
        raise IndependentDiscrepancyCaseError("case:responsibility-state")

    remediation = value["remediation"]
    if lifecycle in {STAGE_REMEDIATION_PROPOSED, STAGE_REMEDIATION_EVIDENCE, STAGE_RETEST, STAGE_PARITY, STAGE_PERSISTS, STAGE_RESOLVED} and remediation["proposal"] is None:
        raise IndependentDiscrepancyCaseError("case:proposal-state")
    if lifecycle in {STAGE_REMEDIATION_EVIDENCE, STAGE_RETEST, STAGE_PARITY, STAGE_PERSISTS, STAGE_RESOLVED} and remediation["assertion"] is None:
        raise IndependentDiscrepancyCaseError("case:assertion-state")
    if lifecycle in {STAGE_RETEST, STAGE_PARITY, STAGE_PERSISTS, STAGE_RESOLVED}:
        verified = remediation["verified_result"]
        expected_verified = {
            "result_code": "DETERMINISTIC_RETEST_EXECUTED",
            "verifier_profile_id": RETEST_PROFILE_ID,
            "reconciliation_artifact_id": value["retest"]["reconciliation_artifact_id"],
            "business_truth_proven": False,
        }
        if verified != expected_verified:
            raise IndependentDiscrepancyCaseError("case:verified-result-state")
    retest = value["retest"]
    if lifecycle in {STAGE_RETEST, STAGE_PARITY, STAGE_PERSISTS, STAGE_RESOLVED}:
        if retest["status"] != "EXECUTED" or retest["reconciliation_artifact_id"] is None or retest["source_observation_status"] is None:
            raise IndependentDiscrepancyCaseError("case:retest-state")
    if lifecycle in {STAGE_PARITY, STAGE_RESOLVED}:
        if not isinstance(retest["parity"], dict) or retest["parity"]["status"] != PARITY_FULL:
            raise IndependentDiscrepancyCaseError("case:full-parity-state")
    if lifecycle == STAGE_PERSISTS:
        if not isinstance(retest["parity"], dict) or retest["parity"]["status"] == PARITY_FULL:
            raise IndependentDiscrepancyCaseError("case:persistence-state")
        if value["resolution"] != {
            "state": "UNRESOLVED_OBSERVATION",
            "basis": retest["parity"]["status"],
            "business_truth_proven": False,
        }:
            raise IndependentDiscrepancyCaseError("case:persistence-resolution")
    elif lifecycle == STAGE_RESOLVED:
        if value["resolution"] != {
            "state": "RESOLVED_OBSERVATION",
            "basis": "FULL_BOUNDED_PARITY",
            "business_truth_proven": False,
        }:
            raise IndependentDiscrepancyCaseError("case:resolved-resolution")
    elif lifecycle == STAGE_SUPERSEDED:
        if retest["status"] != "NOT_REQUESTED" or retest["reconciliation_artifact_id"] is None or retest["source_observation_status"] is None or retest["parity"] is not None:
            raise IndependentDiscrepancyCaseError("case:superseded-retest-state")
        if value["resolution"] != {
            "state": "SUPERSEDED_OBSERVATION",
            "basis": "NEW_STORED_RECONCILIATION_EVIDENCE",
            "business_truth_proven": False,
        }:
            raise IndependentDiscrepancyCaseError("case:superseded-resolution")
    else:
        if value["resolution"] != _empty_resolution():
            raise IndependentDiscrepancyCaseError("case:active-resolution")


def _identity_values(value: Mapping[str, object]) -> tuple[str, str, str]:
    body = deepcopy(dict(value))
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    transition = value["transition"]
    retest = value["retest"]
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "case_id": value["case_id"],
            "lifecycle_state": value["lifecycle_state"],
            "prior_artifact_id": transition["prior_artifact_id"],
            "prior_stage_id": transition["prior_stage_id"],
            "retest_reconciliation_artifact_id": retest["reconciliation_artifact_id"],
            "resolution_state": value["resolution"]["state"],
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "transition_kind": value["lifecycle_state"],
            "prior_artifact_id": transition["prior_artifact_id"],
            "prior_stage_id": transition["prior_stage_id"],
            "case_id": value["case_id"],
        },
    )
    return artifact_id, stage_id, transition_id


def _expected_body(
    *,
    stage: str,
    graph_raw: bytes,
    reconciliation_raw: bytes,
    reconciliation_context: Mapping[str, object],
    governance_raw: bytes,
    registry: Mapping[str, object],
    finding_id: str | None,
    prior_case_raw: bytes | None,
    retest_reconciliation_raw: bytes | None,
    retest_context: Mapping[str, object] | None,
) -> dict[str, object]:
    if stage == STAGE_OPEN:
        if prior_case_raw is not None or finding_id is None:
            raise IndependentDiscrepancyCaseError("case:open-inputs")
        upstream, profile_binding, governance_binding, subject = _upstream(
            graph_raw, reconciliation_raw, reconciliation_context, governance_raw, registry, finding_id
        )
        return _base_body(upstream, profile_binding, governance_binding, subject["subject"], subject["scope"])
    if prior_case_raw is None:
        raise IndependentDiscrepancyCaseError("case:prior-required")
    prior = _parse(prior_case_raw)
    _validate_prior(prior)
    transition = _expect_keys(prior["transition"], TRANSITION_KEYS, "prior-transition")
    if transition["transition_kind"] not in _PREVIOUS.get(stage, set()):
        raise IndependentDiscrepancyCaseError("case:prior-stage")
    finding = prior["upstream"]["finding"]["finding_id"]
    upstream, profile_binding, governance_binding, subject = _upstream(
        graph_raw, reconciliation_raw, reconciliation_context, governance_raw, registry, finding
    )
    if dict(upstream) != dict(prior["upstream"]) or dict(profile_binding) != dict(prior["profile_binding"]) or dict(governance_binding) != dict(prior["governance_binding"]):
        raise IndependentDiscrepancyCaseError("case:prior-upstream-binding")
    if subject["subject"] != prior["subject"] or subject["scope"] != prior["scope"]:
        raise IndependentDiscrepancyCaseError("case:prior-subject-binding")
    retest_value = None
    retest_result = None
    if stage in {STAGE_RETEST, STAGE_SUPERSEDED}:
        if retest_reconciliation_raw is None or retest_context is None:
            raise IndependentDiscrepancyCaseError("case:transition-context")
        retest_value, retest_result, _role = _verify_reconciliation(
            retest_reconciliation_raw,
            retest_context,
            registry,
            None,
        )
        if retest_result["profile_id"] != prior["profile_binding"]["profile_id"] or retest_result["subject"] != prior["subject"] or retest_result["scope"] != prior["scope"]:
            raise IndependentDiscrepancyCaseError("case:retest-profile-binding")
    body = _transition_body(prior, stage, retest_value=retest_value, retest_result=retest_result)
    return body


def build_artifact(
    action: str,
    *,
    graph_raw: bytes,
    reconciliation_raw: bytes,
    reconciliation_context: Mapping[str, object],
    governance_raw: bytes,
    graph_profile_registry: Mapping[str, object],
    finding_id: str | None = None,
    prior_case_raw: bytes | None = None,
    retest_reconciliation_raw: bytes | None = None,
    retest_context: Mapping[str, object] | None = None,
) -> bytes:
    """Build one candidate from independently verified upstream bytes."""

    if action not in {STAGE_OPEN, *ACTIONS}:
        raise IndependentDiscrepancyCaseError("case:action")
    body = _expected_body(
        stage=action,
        graph_raw=graph_raw,
        reconciliation_raw=reconciliation_raw,
        reconciliation_context=reconciliation_context,
        governance_raw=governance_raw,
        registry=graph_profile_registry,
        finding_id=finding_id,
        prior_case_raw=prior_case_raw,
        retest_reconciliation_raw=retest_reconciliation_raw,
        retest_context=retest_context,
    )
    artifact_id, stage_id, transition_id = _identity_values(body)
    value = {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}
    _validate_shape(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentDiscrepancyCaseError("case:artifact-byte-cap")
    return raw


def verify_artifact(
    raw: bytes,
    *,
    graph_raw: bytes,
    reconciliation_raw: bytes,
    reconciliation_context: Mapping[str, object],
    governance_raw: bytes,
    graph_profile_registry: Mapping[str, object],
    prior_case_raw: bytes | None = None,
    retest_reconciliation_raw: bytes | None = None,
    retest_context: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Independently reconstruct and verify one case transition."""

    value = _parse(raw)
    _validate_shape(value)
    stage = value["lifecycle_state"]
    finding_id = value["upstream"]["finding"]["finding_id"] if stage == STAGE_OPEN else None
    expected = _expected_body(
        stage=stage,
        graph_raw=graph_raw,
        reconciliation_raw=reconciliation_raw,
        reconciliation_context=reconciliation_context,
        governance_raw=governance_raw,
        registry=graph_profile_registry,
        finding_id=finding_id,
        prior_case_raw=prior_case_raw,
        retest_reconciliation_raw=retest_reconciliation_raw,
        retest_context=retest_context,
    )
    body = dict(value)
    for key in ("artifact_id", "current_stage_id", "transition_id"):
        body.pop(key, None)
    if body != expected:
        raise IndependentDiscrepancyCaseError("case:semantic-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentDiscrepancyCaseError("case:identity")
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "subject": value["case_id"],
        "scope": value["scope"],
        "report_id": value["case_id"],
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": value["lifecycle_state"],
        "prior_artifact_id": value["transition"]["prior_artifact_id"],
        "prior_stage_id": value["transition"]["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": value["profile_binding"]["profile_id"],
        "profile_version": value["profile_binding"]["version"],
        "case_id": value["case_id"],
        "graph_artifact_id": value["upstream"]["graph"]["artifact_id"],
        "reconciliation_artifact_id": value["upstream"]["reconciliation"]["artifact_id"],
        "finding_id": value["upstream"]["finding"]["finding_id"],
        "result_status": value["upstream"]["reconciliation"]["result_status"],
        "retest_reconciliation_artifact_id": value["retest"]["reconciliation_artifact_id"],
        "responsibility_boundary": value["responsibility"]["boundary"] if value["responsibility"] is not None else None,
        "parity_status": value["retest"]["parity"]["status"] if isinstance(value["retest"]["parity"], dict) else None,
    }


__all__ = [
    "ACTIONS",
    "ARTIFACT_KIND",
    "AUTHORITY_FLAGS",
    "CONTRACT_ID",
    "CONTRACT_VERSION",
    "FIXED_FLAGS",
    "IndependentDiscrepancyCaseError",
    "MAX_ARTIFACT_BYTES",
    "PARITY_FULL",
    "PARITY_INDETERMINATE",
    "PARITY_MISMATCH",
    "PARITY_PARTIAL",
    "PARITY_STALE",
    "PARITY_UNAVAILABLE",
    "SCHEMA",
    "SCHEMA_VERSION",
    "STAGE_KIND",
    "STAGE_OPEN",
    "STAGE_PARITY",
    "STAGE_PERSISTS",
    "STAGE_REMEDIATION_EVIDENCE",
    "STAGE_REMEDIATION_PROPOSED",
    "STAGE_RESOLVED",
    "STAGE_RESPONSIBILITY",
    "STAGE_RETEST",
    "STAGE_SUPERSEDED",
    "STAGES",
    "TERMINAL_STAGES",
    "build_artifact",
    "verify_artifact",
    "_canonical",
    "_parse",
    "_identity_values",
]
