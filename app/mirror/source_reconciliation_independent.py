"""Independent verification for the synthetic Mirror temporal seam.

This module verifies a small state-side delta between already-custodied source
artifacts.  It does not infer enrollment, termination, nonmembership, payment,
clearance, or any other business truth.  The custody artifacts remain the
evidence authority; this module only derives and binds an evidence-proportional
observation status.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping

from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody_independent as custody


ARTIFACT_KIND = "NC_MEDICAID_SOURCE_RECONCILIATION_V2"
SCHEMA = "mirror-ncmedicaid-source-reconciliation-v2"
SCHEMA_VERSION = 2
STAGE_KIND = "SOURCE_RECONCILIATION"
DOMAIN = "BL/MIRROR/SOURCE-RECONCILIATION/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
MAX_GAP_SECONDS = 86_400
RECONCILIATION_CONTRACT_ID = "mirror.source-reconciliation.temporal.v2"
RECONCILIATION_CONTRACT_VERSION = 2
FETCHED_AT_FALLBACK_TRUSTED = False
HEX128 = re.compile(r"^[0-9a-f]{128}$")

STATUS_OBSERVED_NEW = "OBSERVED_NEW"
STATUS_OBSERVED_CONTINUED = "OBSERVED_CONTINUED"
STATUS_OBSERVED_CHANGED = "OBSERVED_CHANGED"
STATUS_NOT_OBSERVED_INCOMPLETE = "NOT_OBSERVED_IN_CURRENT_INCOMPLETE_SNAPSHOT"
STATUS_CONFLICTING = "CONFLICTING_OBSERVATION"
STATUS_STALE_OR_GAPPED = "STALE_OR_GAPPED_OBSERVATION"
STATUS_SOURCE_FAILURE = "SOURCE_FAILURE"
STATUSES = (
    STATUS_OBSERVED_NEW,
    STATUS_OBSERVED_CONTINUED,
    STATUS_OBSERVED_CHANGED,
    STATUS_NOT_OBSERVED_INCOMPLETE,
    STATUS_CONFLICTING,
    STATUS_STALE_OR_GAPPED,
    STATUS_SOURCE_FAILURE,
)
CHRONOLOGY = ("INITIAL", "ADVANCES", "EQUAL", "LATE", "GAP", "UNKNOWN")
LINKAGE_STATES = ("LINKED", "UNLINKED")
LINKAGE_TRANSITIONS = ("INITIAL", "UNCHANGED", "LINKED", "UNLINKED", "CHANGED")

AUTHORITY_FLAGS = dict(custody.AUTHORITY_FLAGS)
FIXED_FLAGS = {
    "observation_only": True,
    "read_only": True,
    "business_truth_proven": False,
    "production_source_authentication": False,
    "production_usable": False,
    "synthetic_only": True,
    "source_completeness": "UNKNOWN",
    "allow_nonmembership": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "proofSuiteId": None,
}

RECONCILIATION_KEYS = {
    "schema",
    "schema_version",
    "profile_binding",
    "reconciliation_contract",
    "subject",
    "scope",
    "prior_artifact_id",
    "prior_stage_id",
    "stage_kind",
    "predecessor_custody",
    "current_custody",
    "chronology",
    "result",
    "source_content",
    "linkage_transition",
    "anchors",
    "flags",
    "authority",
    "artifact_id",
    "current_stage_id",
    "transition_id",
}
SOURCE_CONTENT_KEYS = {"current_root", "comparison_root"}
LINKAGE_KEYS = {"status", "prior_state", "current_state"}
ANCHOR_KEYS = {"custody_artifact_id", "custody_stage_id", "content_root"}
CHRONOLOGY_ANCHOR_KEYS = {"custody_artifact_id", "custody_stage_id", "marker_kind", "marker_value"}
ANCHORS_KEYS = {"qualified_content_baseline", "chronology_anchor"}
CHRONOLOGY_KEYS = {
    "order", "marker_kind", "prior_marker", "current_marker", "gap_seconds",
    "prior_server_last_updated", "current_server_last_updated", "prior_fetched_at",
    "current_fetched_at", "fetched_at_fallback_trusted",
}


class IndependentSourceReconciliationError(ValueError):
    """Stable fail-closed rejection from the reconciliation boundary."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentSourceReconciliationError("reconciliation:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentSourceReconciliationError("reconciliation:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentSourceReconciliationError("reconciliation:node-cap")
    if depth > 24:
        raise IndependentSourceReconciliationError("reconciliation:depth-cap")
    if isinstance(value, float):
        raise IndependentSourceReconciliationError("reconciliation:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentSourceReconciliationError("reconciliation:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentSourceReconciliationError("reconciliation:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentSourceReconciliationError("reconciliation:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentSourceReconciliationError("reconciliation:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentSourceReconciliationError("reconciliation:constant")),
        )
    except IndependentSourceReconciliationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentSourceReconciliationError("reconciliation:parse") from exc
    if not isinstance(value, dict):
        raise IndependentSourceReconciliationError("reconciliation:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentSourceReconciliationError("reconciliation:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX128.fullmatch(value):
        raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentSourceReconciliationError(f"reconciliation:{label}") from exc
    return value


def _profile_binding() -> dict[str, object]:
    return custody._profile_binding()


def _contract_binding() -> dict[str, object]:
    material = {
        "contract_id": RECONCILIATION_CONTRACT_ID,
        "version": RECONCILIATION_CONTRACT_VERSION,
        "ordering": "SERVER_LAST_UPDATED_ONLY_WHEN_BOTH_MARKERS_EXIST",
        "max_gap_seconds": MAX_GAP_SECONDS,
        "statuses": list(STATUSES),
        "linkage_transitions": list(LINKAGE_TRANSITIONS),
        "fetched_at_fallback_trusted": FETCHED_AT_FALLBACK_TRUSTED,
        "absence_inference": False,
        "business_truth": False,
    }
    return {**material, "contract_digest": _digest("contract", material)}


def _link_summary(link: object) -> dict[str, object] | None:
    if link is None:
        return None
    if not isinstance(link, dict):
        raise IndependentSourceReconciliationError("reconciliation:graph-link")
    keys = {"artifact_id", "payload_hash", "graph_artifact_digest", "report_id", "admission_receipt_hex"}
    if set(link) != keys:
        raise IndependentSourceReconciliationError("reconciliation:graph-link")
    return {
        key: _text(link[key], f"graph-link-{key}") if key in {"artifact_id", "report_id"} else _hex(link[key], f"graph-link-{key}")
        for key in ("artifact_id", "payload_hash", "graph_artifact_digest", "report_id")
    }


def _content_root_from_custody(raw: bytes) -> str:
    """Derive one aggregate root from independently verified full resources."""

    try:
        value = custody._parse(raw)
        envelope = value["envelope"]
        if not isinstance(envelope, dict) or set(envelope) != {"encoding", "byte_length", "bytes_hex"}:
            raise IndependentSourceReconciliationError("reconciliation:content-envelope")
        envelope_raw = bytes.fromhex(str(envelope["bytes_hex"]))
        result = fhir.verify_bytes(envelope_raw, profile=profile.NC_MEDICAID_PROFILE)
        resources = result.get("resources")
    except IndependentSourceReconciliationError:
        raise
    except Exception as exc:
        raise IndependentSourceReconciliationError("reconciliation:content-verification") from exc
    if not isinstance(resources, list):
        raise IndependentSourceReconciliationError("reconciliation:content-resources")
    ordered: list[tuple[str, str, dict[str, object]]] = []
    seen: set[tuple[str, str]] = set()
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("resourceType"), str) or not isinstance(resource.get("id"), str):
            raise IndependentSourceReconciliationError("reconciliation:content-resource")
        key = (resource["resourceType"], resource["id"])
        if key in seen:
            raise IndependentSourceReconciliationError("reconciliation:content-duplicate")
        seen.add(key)
        ordered.append((key[0], key[1], resource))
    ordered.sort(key=lambda item: (item[0], item[1]))
    return _digest("source-content-root", {"resources": [item[2] for item in ordered]})


def _custody_view(
    raw: bytes | None,
    graph_raw: bytes | None,
    registry: Mapping[str, object],
    *,
    allow_unresolved_graph: bool = False,
) -> dict[str, object] | None:
    if raw is None:
        if graph_raw is not None:
            raise IndependentSourceReconciliationError("reconciliation:orphan-graph")
        return None
    try:
        value = custody._parse(raw)
        result = custody.verify_artifact(
            raw,
            graph_raw=graph_raw,
            graph_profile_registry=registry,
            allow_unresolved_graph=allow_unresolved_graph,
        )
    except Exception as exc:
        raise IndependentSourceReconciliationError("reconciliation:custody-reject") from exc
    if value.get("artifact_id") != result.get("artifact_id") or value.get("current_stage_id") != result.get("current_stage_id"):
        raise IndependentSourceReconciliationError("reconciliation:custody-identity")
    markers = value.get("server_markers")
    if not isinstance(markers, dict) or set(markers) != {"total", "last_updated"}:
        raise IndependentSourceReconciliationError("reconciliation:custody-markers")
    return {
        "artifact_id": result["artifact_id"],
        "stage_id": result["current_stage_id"],
        "prior_artifact_id": result["prior_artifact_id"],
        "prior_stage_id": result["prior_stage_id"],
        "subject": result["subject"],
        "scope": result["scope"],
        "profile_id": result["profile_id"],
        "profile_version": result["profile_version"],
        "envelope_digest": result["envelope_digest"],
        "snapshot_id": value["snapshot_id"],
        "snapshot_root": value["snapshot_root"],
        "observation_time": value["observation_time"],
        "fetched_at": value["fetched_at"],
        "source_status": value["source_status"],
        "failure_code": value["failure_code"],
        "freshness": value["freshness"],
        "page_complete": value["page_complete"],
        "server_last_updated": markers["last_updated"],
        "graph_link": _link_summary(value.get("graph_link")),
        "content_root": _content_root_from_custody(raw),
    }


def _validate_anchor(value: object, label: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != ANCHOR_KEYS:
        raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    _hex(value["custody_artifact_id"], f"{label}-artifact")
    _hex(value["custody_stage_id"], f"{label}-stage")
    _hex(value["content_root"], f"{label}-content")
    return value


def _validate_chronology_anchor(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != CHRONOLOGY_ANCHOR_KEYS:
        raise IndependentSourceReconciliationError("reconciliation:chronology-anchor")
    _hex(value["custody_artifact_id"], "chronology-anchor-artifact")
    _hex(value["custody_stage_id"], "chronology-anchor-stage")
    if value["marker_kind"] != "SERVER_LAST_UPDATED":
        raise IndependentSourceReconciliationError("reconciliation:chronology-anchor-kind")
    _time(value["marker_value"], "chronology-anchor-marker")
    return value


def _validate_anchors(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != ANCHORS_KEYS:
        raise IndependentSourceReconciliationError("reconciliation:anchors")
    return {
        "qualified_content_baseline": _validate_anchor(value["qualified_content_baseline"], "qualified-anchor"),
        "chronology_anchor": _validate_chronology_anchor(value["chronology_anchor"]),
    }


def _anchor_view(
    anchor: dict[str, object] | None,
    raw: bytes | None,
    registry: Mapping[str, object],
) -> dict[str, object] | None:
    if anchor is None:
        if raw is not None:
            raise IndependentSourceReconciliationError("reconciliation:unexpected-anchor-bytes")
        return None
    if raw is None:
        raise IndependentSourceReconciliationError("reconciliation:anchor-bytes-required")
    view = _custody_view(raw, None, registry, allow_unresolved_graph=True)
    if view is None or view["artifact_id"] != anchor["custody_artifact_id"] or view["stage_id"] != anchor["custody_stage_id"]:
        raise IndependentSourceReconciliationError("reconciliation:anchor-custody-binding")
    if "content_root" in anchor and view["content_root"] != anchor["content_root"]:
        raise IndependentSourceReconciliationError("reconciliation:anchor-content-binding")
    if "marker_value" in anchor and view["server_last_updated"] != anchor["marker_value"]:
        raise IndependentSourceReconciliationError("reconciliation:anchor-marker-binding")
    return view


def _content_anchor(view: dict[str, object]) -> dict[str, object]:
    return {
        "custody_artifact_id": view["artifact_id"],
        "custody_stage_id": view["stage_id"],
        "content_root": view["content_root"],
    }


def _chronology_anchor(view: dict[str, object]) -> dict[str, object] | None:
    marker = view["server_last_updated"]
    if marker is None:
        return None
    return {
        "custody_artifact_id": view["artifact_id"],
        "custody_stage_id": view["stage_id"],
        "marker_kind": "SERVER_LAST_UPDATED",
        "marker_value": marker,
    }


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise IndependentSourceReconciliationError(f"reconciliation:{label}") from exc


def _chronology(
    prior: dict[str, object] | None,
    current: dict[str, object],
    *,
    has_prior_transition: bool,
) -> dict[str, object]:
    prior_server = prior["server_last_updated"] if prior is not None else None
    current_server = current["server_last_updated"]
    order = "INITIAL" if not has_prior_transition else "UNKNOWN"
    marker_kind = "UNKNOWN"
    prior_marker: str | None = None
    current_marker: str | None = None
    gap_seconds: int | None = None
    if current_server is not None and not has_prior_transition:
        marker_kind = "SERVER_LAST_UPDATED"
        current_marker = current_server
    elif prior_server is not None and current_server is not None:
        prior_time = _time(prior_server, "prior-marker")
        current_time = _time(current_server, "current-marker")
        difference = int((current_time - prior_time).total_seconds())
        marker_kind = "SERVER_LAST_UPDATED"
        prior_marker = prior_server
        current_marker = current_server
        gap_seconds = difference if difference > 0 else None
        if difference < 0:
            order = "LATE"
        elif difference == 0:
            order = "EQUAL"
        elif difference > MAX_GAP_SECONDS:
            order = "GAP"
        else:
            order = "ADVANCES"
    return {
        "order": order,
        "marker_kind": marker_kind,
        "prior_marker": prior_marker,
        "current_marker": current_marker,
        "gap_seconds": gap_seconds,
        "prior_server_last_updated": prior_server,
        "current_server_last_updated": current_server,
        "prior_fetched_at": prior["fetched_at"] if prior is not None else None,
        "current_fetched_at": current["fetched_at"],
        "fetched_at_fallback_trusted": FETCHED_AT_FALLBACK_TRUSTED,
    }


def _qualified(value: dict[str, object]) -> bool:
    return value["source_status"] == "COMPLETE" and value["freshness"] in {"FRESH", "UNKNOWN"} and value["page_complete"] is True


def _result(
    baseline: dict[str, object] | None,
    current: dict[str, object],
    chronology: dict[str, object],
) -> dict[str, object]:
    order = chronology["order"]
    if current["source_status"] == "FAILED":
        status, basis = STATUS_SOURCE_FAILURE, "SOURCE_FAILURE"
    elif current["source_status"] == "STALE" or current["freshness"] == "STALE" or order in {"LATE", "GAP"}:
        status, basis = STATUS_STALE_OR_GAPPED, "SOURCE_MARKER_CHRONOLOGY"
    elif current["source_status"] == "PARTIAL":
        status, basis = STATUS_NOT_OBSERVED_INCOMPLETE, "CURRENT_INCOMPLETE_SNAPSHOT"
    elif baseline is not None and order == "EQUAL" and current["content_root"] != baseline["content_root"]:
        status, basis = STATUS_CONFLICTING, "EQUAL_SOURCE_MARKER"
    elif not _qualified(current):
        status, basis = STATUS_SOURCE_FAILURE, "UNQUALIFIED_SOURCE_STATUS"
    elif baseline is None:
        status, basis = STATUS_OBSERVED_NEW, "FIRST_QUALIFIED_OBSERVATION"
    elif current["content_root"] == baseline["content_root"]:
        status, basis = STATUS_OBSERVED_CONTINUED, "UNCHANGED_VERIFIED_SOURCE_CONTENT"
    else:
        status, basis = STATUS_OBSERVED_CHANGED, "VERIFIED_SOURCE_CONTENT_ROOT"
    if order == "UNKNOWN" and status in {STATUS_OBSERVED_CONTINUED, STATUS_OBSERVED_CHANGED}:
        basis = basis + ":CHRONOLOGY_UNKNOWN"
    return {
        "source_observation_status": status,
        "basis": basis,
        "source_status": current["source_status"],
        "freshness": current["freshness"],
        "absence_inferred": False,
        "nonmembership_inferred": False,
        "business_truth_proven": False,
        "read_only": True,
    }


def _linkage_transition(prior: dict[str, object] | None, current: dict[str, object]) -> dict[str, object]:
    prior_state = None if prior is None else ("LINKED" if prior["graph_link"] is not None else "UNLINKED")
    current_state = "LINKED" if current["graph_link"] is not None else "UNLINKED"
    if prior is None:
        status = "INITIAL"
    elif prior_state == current_state and prior["graph_link"] == current["graph_link"]:
        status = "UNCHANGED"
    elif current_state == "LINKED" and prior_state == "UNLINKED":
        status = "LINKED"
    elif current_state == "UNLINKED" and prior_state == "LINKED":
        status = "UNLINKED"
    else:
        status = "CHANGED"
    return {"status": status, "prior_state": prior_state, "current_state": current_state}


def _summary(value: dict[str, object] | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "artifact_id": value["artifact_id"],
        "stage_id": value["stage_id"],
        "envelope_digest": value["envelope_digest"],
        "snapshot_id": value["snapshot_id"],
        "snapshot_root": value["snapshot_root"],
        "observation_time": value["observation_time"],
        "fetched_at": value["fetched_at"],
        "source_status": value["source_status"],
        "failure_code": value["failure_code"],
        "freshness": value["freshness"],
        "page_complete": value["page_complete"],
        "server_last_updated": value["server_last_updated"],
        "graph_link": value["graph_link"],
    }


RESULT_KEYS = {
    "source_observation_status", "basis", "source_status", "freshness",
    "absence_inferred", "nonmembership_inferred", "business_truth_proven", "read_only",
}


def _validate_document_shape(value: dict[str, object]) -> None:
    if set(value) != RECONCILIATION_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentSourceReconciliationError("reconciliation:schema")
    if value.get("stage_kind") != STAGE_KIND:
        raise IndependentSourceReconciliationError("reconciliation:stage-kind")
    if value.get("profile_binding") != _profile_binding() or value.get("reconciliation_contract") != _contract_binding():
        raise IndependentSourceReconciliationError("reconciliation:contract")
    source_content = value.get("source_content")
    if not isinstance(source_content, dict) or set(source_content) != SOURCE_CONTENT_KEYS:
        raise IndependentSourceReconciliationError("reconciliation:source-content")
    _hex(source_content["current_root"], "source-content-current")
    if source_content["comparison_root"] is not None:
        _hex(source_content["comparison_root"], "source-content-comparison")
    linkage = value.get("linkage_transition")
    if not isinstance(linkage, dict) or set(linkage) != LINKAGE_KEYS or linkage["status"] not in LINKAGE_TRANSITIONS:
        raise IndependentSourceReconciliationError("reconciliation:linkage")
    if linkage["prior_state"] is not None and linkage["prior_state"] not in LINKAGE_STATES:
        raise IndependentSourceReconciliationError("reconciliation:linkage-prior")
    if linkage["current_state"] not in LINKAGE_STATES:
        raise IndependentSourceReconciliationError("reconciliation:linkage-current")
    chronology = value.get("chronology")
    if not isinstance(chronology, dict) or set(chronology) != CHRONOLOGY_KEYS or chronology["order"] not in CHRONOLOGY:
        raise IndependentSourceReconciliationError("reconciliation:chronology")
    if chronology["marker_kind"] not in {"SERVER_LAST_UPDATED", "UNKNOWN"}:
        raise IndependentSourceReconciliationError("reconciliation:chronology-kind")
    if chronology["marker_kind"] == "SERVER_LAST_UPDATED":
        if chronology["current_marker"] is None:
            raise IndependentSourceReconciliationError("reconciliation:chronology-current-marker")
        _time(chronology["current_marker"], "chronology-current-marker")
        if chronology["prior_marker"] is not None:
            _time(chronology["prior_marker"], "chronology-prior-marker")
    elif chronology["prior_marker"] is not None or chronology["current_marker"] is not None:
        raise IndependentSourceReconciliationError("reconciliation:chronology-unknown-marker")
    if chronology["fetched_at_fallback_trusted"] is not FETCHED_AT_FALLBACK_TRUSTED:
        raise IndependentSourceReconciliationError("reconciliation:fetched-at-fallback")
    result = value.get("result")
    if not isinstance(result, dict) or set(result) != RESULT_KEYS or result["source_observation_status"] not in STATUSES:
        raise IndependentSourceReconciliationError("reconciliation:result")
    if result["absence_inferred"] is not False or result["nonmembership_inferred"] is not False or result["business_truth_proven"] is not False or result["read_only"] is not True:
        raise IndependentSourceReconciliationError("reconciliation:result-flags")
    _validate_anchors(value.get("anchors"))


def _identity_values(value: dict[str, object]) -> tuple[str, str, str]:
    body = dict(value)
    body.pop("artifact_id", None)
    body.pop("current_stage_id", None)
    body.pop("transition_id", None)
    artifact_id = _digest("artifact-id", body)
    current = value.get("current_custody")
    if not isinstance(current, dict):
        raise IndependentSourceReconciliationError("reconciliation:current-custody")
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "current_custody_artifact_id": current["artifact_id"],
            "current_snapshot_root": current["snapshot_root"],
            "current_content_root": value["source_content"]["current_root"],
            "result_status": value["result"]["source_observation_status"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    predecessor = value.get("predecessor_custody")
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
            "predecessor_custody_artifact_id": predecessor["artifact_id"] if isinstance(predecessor, dict) else None,
            "current_custody_artifact_id": current["artifact_id"],
        },
    )
    return artifact_id, stage_id, transition_id


def _body(
    current_custody_raw: bytes,
    prior_custody_raw: bytes | None,
    *,
    current_graph_raw: bytes | None,
    prior_graph_raw: bytes | None,
    prior_artifact_id: str | None,
    prior_stage_id: str | None,
    prior_reconciliation_raw: bytes | None,
    qualified_baseline_custody_raw: bytes | None,
    chronology_anchor_custody_raw: bytes | None,
    graph_profile_registry: Mapping[str, object],
) -> dict[str, object]:
    current = _custody_view(current_custody_raw, current_graph_raw, graph_profile_registry)
    prior = _custody_view(prior_custody_raw, prior_graph_raw, graph_profile_registry)
    assert current is not None
    if (prior_artifact_id is None) != (prior_stage_id is None):
        raise IndependentSourceReconciliationError("reconciliation:prior-head-pair")
    if current["prior_artifact_id"] != (prior["artifact_id"] if prior is not None else None) or current["prior_stage_id"] != (prior["stage_id"] if prior is not None else None):
        raise IndependentSourceReconciliationError("reconciliation:custody-predecessor")
    if prior is not None and (current["subject"], current["scope"], current["profile_id"], current["profile_version"]) != (prior["subject"], prior["scope"], prior["profile_id"], prior["profile_version"]):
        raise IndependentSourceReconciliationError("reconciliation:profile-isolation")
    prior_value: dict[str, object] | None = None
    baseline: dict[str, object] | None = None
    chronology_anchor_view: dict[str, object] | None = None
    if prior_reconciliation_raw is None:
        if prior is not None or prior_artifact_id is not None or prior_stage_id is not None:
            raise IndependentSourceReconciliationError("reconciliation:prior-transition-required")
    else:
        if prior is None or prior_artifact_id is None or prior_stage_id is None:
            raise IndependentSourceReconciliationError("reconciliation:prior-head-pair")
        prior_value = _parse(prior_reconciliation_raw)
        _validate_document_shape(prior_value)
        if prior_value["artifact_id"] != prior_artifact_id or prior_value["current_stage_id"] != prior_stage_id:
            raise IndependentSourceReconciliationError("reconciliation:prior-binding")
        if prior_value["current_custody"] != _summary(prior):
            raise IndependentSourceReconciliationError("reconciliation:prior-custody-binding")
        if prior_value["source_content"]["current_root"] != prior["content_root"]:
            raise IndependentSourceReconciliationError("reconciliation:prior-content-binding")
        if _identity_values(prior_value) != (prior_value["artifact_id"], prior_value["current_stage_id"], prior_value["transition_id"]):
            raise IndependentSourceReconciliationError("reconciliation:prior-identity")
        prior_anchors = _validate_anchors(prior_value["anchors"])
        baseline = _anchor_view(prior_anchors["qualified_content_baseline"], qualified_baseline_custody_raw, graph_profile_registry)
        chronology_anchor_view = _anchor_view(prior_anchors["chronology_anchor"], chronology_anchor_custody_raw, graph_profile_registry)
    chronology = _chronology(chronology_anchor_view, current, has_prior_transition=prior_value is not None)
    result = _result(baseline, current, chronology)
    linkage = _linkage_transition(prior, current)
    prior_anchors = _validate_anchors(prior_value["anchors"] if prior_value is not None else {"qualified_content_baseline": None, "chronology_anchor": None})
    if result["source_observation_status"] in {STATUS_OBSERVED_NEW, STATUS_OBSERVED_CONTINUED, STATUS_OBSERVED_CHANGED} and _qualified(current) and chronology["order"] not in {"LATE", "GAP"}:
        qualified_anchor = _content_anchor(current)
    else:
        qualified_anchor = prior_anchors["qualified_content_baseline"]
    if current["server_last_updated"] is not None and chronology["order"] != "LATE":
        next_chronology_anchor = _chronology_anchor(current)
    else:
        next_chronology_anchor = prior_anchors["chronology_anchor"]
    if prior_value is None:
        if qualified_baseline_custody_raw is not None:
            if qualified_anchor is None:
                raise IndependentSourceReconciliationError("reconciliation:unexpected-baseline-bytes")
            _anchor_view(qualified_anchor, qualified_baseline_custody_raw, graph_profile_registry)
        if chronology_anchor_custody_raw is not None:
            if next_chronology_anchor is None:
                raise IndependentSourceReconciliationError("reconciliation:unexpected-chronology-bytes")
            _anchor_view(next_chronology_anchor, chronology_anchor_custody_raw, graph_profile_registry)
    body: dict[str, object] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "profile_binding": _profile_binding(),
        "reconciliation_contract": _contract_binding(),
        "subject": current["subject"],
        "scope": current["scope"],
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "stage_kind": STAGE_KIND,
        "predecessor_custody": _summary(prior),
        "current_custody": _summary(current),
        "chronology": chronology,
        "result": result,
        "source_content": {
            "current_root": current["content_root"],
            "comparison_root": baseline["content_root"] if baseline is not None else None,
        },
        "linkage_transition": linkage,
        "anchors": {
            "qualified_content_baseline": qualified_anchor,
            "chronology_anchor": next_chronology_anchor,
        },
        "flags": dict(FIXED_FLAGS),
        "authority": dict(AUTHORITY_FLAGS),
    }
    return body


def build_artifact(
    current_custody_raw: bytes,
    prior_custody_raw: bytes | None,
    *,
    current_graph_raw: bytes | None = None,
    prior_graph_raw: bytes | None = None,
    prior_artifact_id: str | None = None,
    prior_stage_id: str | None = None,
    prior_reconciliation_raw: bytes | None = None,
    qualified_baseline_custody_raw: bytes | None = None,
    chronology_anchor_custody_raw: bytes | None = None,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> bytes:
    """Build a candidate; durable admission independently rebuilds it."""

    registry = dict(graph_profile_registry or profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    body = _body(
        current_custody_raw,
        prior_custody_raw,
        current_graph_raw=current_graph_raw,
        prior_graph_raw=prior_graph_raw,
        prior_artifact_id=prior_artifact_id,
        prior_stage_id=prior_stage_id,
        prior_reconciliation_raw=prior_reconciliation_raw,
        qualified_baseline_custody_raw=qualified_baseline_custody_raw,
        chronology_anchor_custody_raw=chronology_anchor_custody_raw,
        graph_profile_registry=registry,
    )
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "current_custody_artifact_id": body["current_custody"]["artifact_id"],  # type: ignore[index]
            "current_snapshot_root": body["current_custody"]["snapshot_root"],  # type: ignore[index]
            "current_content_root": body["source_content"]["current_root"],  # type: ignore[index]
            "result_status": body["result"]["source_observation_status"],  # type: ignore[index]
            "prior_artifact_id": prior_artifact_id,
            "prior_stage_id": prior_stage_id,
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": prior_artifact_id,
            "prior_stage_id": prior_stage_id,
            "predecessor_custody_artifact_id": body["predecessor_custody"]["artifact_id"] if body["predecessor_custody"] is not None else None,  # type: ignore[index]
            "current_custody_artifact_id": body["current_custody"]["artifact_id"],  # type: ignore[index]
        },
    )
    value = {**body, "artifact_id": artifact_id, "current_stage_id": stage_id, "transition_id": transition_id}
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentSourceReconciliationError("reconciliation:artifact-byte-cap")
    return raw


def verify_artifact(
    raw: bytes,
    *,
    current_custody_raw: bytes,
    prior_custody_raw: bytes | None,
    current_graph_raw: bytes | None = None,
    prior_graph_raw: bytes | None = None,
    prior_reconciliation_raw: bytes | None = None,
    qualified_baseline_custody_raw: bytes | None = None,
    chronology_anchor_custody_raw: bytes | None = None,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Reconstruct custody content, anchors, chronology, and every identity."""

    value = _parse(raw)
    _validate_document_shape(value)
    registry = dict(graph_profile_registry or profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    expected_body = _body(
        current_custody_raw,
        prior_custody_raw,
        current_graph_raw=current_graph_raw,
        prior_graph_raw=prior_graph_raw,
        prior_artifact_id=value.get("prior_artifact_id"),
        prior_stage_id=value.get("prior_stage_id"),
        prior_reconciliation_raw=prior_reconciliation_raw,
        qualified_baseline_custody_raw=qualified_baseline_custody_raw,
        chronology_anchor_custody_raw=chronology_anchor_custody_raw,
        graph_profile_registry=registry,
    )
    for key, expected in expected_body.items():
        if value[key] != expected:
            raise IndependentSourceReconciliationError(f"reconciliation:{key}-binding")
    artifact_id, stage_id, transition_id = _identity_values(value)
    if (value["artifact_id"], value["current_stage_id"], value["transition_id"]) != (artifact_id, stage_id, transition_id):
        raise IndependentSourceReconciliationError("reconciliation:identity")
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")
    current = value["current_custody"]
    predecessor = value["predecessor_custody"]
    baseline = value["anchors"]["qualified_content_baseline"]
    chronology_anchor = value["anchors"]["chronology_anchor"]
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": custody.storage_payload_hash(raw),
        "subject": value["subject"],
        "scope": value["scope"],
        "report_id": None,
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": profile.NC_MEDICAID_GRAPH_PROFILE.profile_id,
        "profile_version": profile.NC_MEDICAID_GRAPH_PROFILE.version,
        "current_custody_artifact_id": current["artifact_id"],
        "current_custody_stage_id": current["stage_id"],
        "predecessor_custody_artifact_id": predecessor["artifact_id"] if isinstance(predecessor, dict) else None,
        "predecessor_custody_stage_id": predecessor["stage_id"] if isinstance(predecessor, dict) else None,
        "result_status": value["result"]["source_observation_status"],
        "current_snapshot_root": current["snapshot_root"],
        "current_content_root": value["source_content"]["current_root"],
        "current_source_status": current["source_status"],
        "qualified_baseline_custody_artifact_id": baseline["custody_artifact_id"] if baseline is not None else None,
        "qualified_baseline_custody_stage_id": baseline["custody_stage_id"] if baseline is not None else None,
        "chronology_anchor_custody_artifact_id": chronology_anchor["custody_artifact_id"] if chronology_anchor is not None else None,
        "chronology_anchor_custody_stage_id": chronology_anchor["custody_stage_id"] if chronology_anchor is not None else None,
    }


__all__ = [
    "ARTIFACT_KIND",
    "AUTHORITY_FLAGS",
    "FETCHED_AT_FALLBACK_TRUSTED",
    "FIXED_FLAGS",
    "LINKAGE_STATES",
    "LINKAGE_TRANSITIONS",
    "MAX_ARTIFACT_BYTES",
    "MAX_GAP_SECONDS",
    "RECONCILIATION_CONTRACT_ID",
    "RECONCILIATION_CONTRACT_VERSION",
    "RECONCILIATION_KEYS",
    "SCHEMA",
    "SCHEMA_VERSION",
    "STAGE_KIND",
    "STATUSES",
    "STATUS_CONFLICTING",
    "STATUS_NOT_OBSERVED_INCOMPLETE",
    "STATUS_OBSERVED_CHANGED",
    "STATUS_OBSERVED_CONTINUED",
    "STATUS_OBSERVED_NEW",
    "STATUS_SOURCE_FAILURE",
    "STATUS_STALE_OR_GAPPED",
    "IndependentSourceReconciliationError",
    "build_artifact",
    "verify_artifact",
]
