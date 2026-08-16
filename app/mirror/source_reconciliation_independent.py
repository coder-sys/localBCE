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

from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import source_evidence_custody_independent as custody


ARTIFACT_KIND = "NC_MEDICAID_SOURCE_RECONCILIATION_V1"
SCHEMA = "mirror-ncmedicaid-source-reconciliation-v1"
SCHEMA_VERSION = 1
STAGE_KIND = "SOURCE_RECONCILIATION"
DOMAIN = "BL/MIRROR/SOURCE-RECONCILIATION/"
MAX_ARTIFACT_BYTES = 262_144
MAX_STRING_BYTES = 8_192
MAX_GAP_SECONDS = 86_400
RECONCILIATION_CONTRACT_ID = "mirror.source-reconciliation.temporal.v1"
RECONCILIATION_CONTRACT_VERSION = 1
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
    "flags",
    "authority",
    "artifact_id",
    "current_stage_id",
    "transition_id",
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
        "ordering": "SERVER_LAST_UPDATED_THEN_FETCHED_AT",
        "max_gap_seconds": MAX_GAP_SECONDS,
        "statuses": list(STATUSES),
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


def _custody_view(raw: bytes | None, graph_raw: bytes | None, registry: Mapping[str, object]) -> dict[str, object] | None:
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
            allow_unresolved_graph=False,
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
    }


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise IndependentSourceReconciliationError(f"reconciliation:{label}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise IndependentSourceReconciliationError(f"reconciliation:{label}") from exc


def _chronology(prior: dict[str, object] | None, current: dict[str, object]) -> dict[str, object]:
    if prior is None:
        return {
            "order": "INITIAL",
            "marker_kind": "SERVER_LAST_UPDATED" if current["server_last_updated"] is not None else "FETCHED_AT",
            "prior_marker": None,
            "current_marker": current["server_last_updated"],
            "gap_seconds": None,
        }
    prior_marker = prior["server_last_updated"]
    current_marker = current["server_last_updated"]
    if prior_marker is not None and current_marker is not None:
        prior_time = _time(prior_marker, "prior-marker")
        current_time = _time(current_marker, "current-marker")
        difference = int((current_time - prior_time).total_seconds())
        marker_kind = "SERVER_LAST_UPDATED"
    else:
        prior_time = _time(prior["fetched_at"], "prior-fetched-at")
        current_time = _time(current["fetched_at"], "current-fetched-at")
        difference = int((current_time - prior_time).total_seconds())
        marker_kind = "FETCHED_AT"
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
        "gap_seconds": difference if difference > 0 else None,
    }


def _qualified(value: dict[str, object]) -> bool:
    return value["source_status"] == "COMPLETE" and value["freshness"] in {"FRESH", "UNKNOWN"} and value["page_complete"] is True


def _result(prior: dict[str, object] | None, current: dict[str, object], chronology: dict[str, object]) -> dict[str, object]:
    order = chronology["order"]
    if current["source_status"] == "FAILED":
        status, basis = STATUS_SOURCE_FAILURE, "SOURCE_FAILURE"
    elif current["source_status"] == "STALE" or current["freshness"] == "STALE" or order in {"LATE", "GAP"}:
        status, basis = STATUS_STALE_OR_GAPPED, "SOURCE_MARKER_CHRONOLOGY"
    elif current["source_status"] == "PARTIAL":
        status, basis = STATUS_NOT_OBSERVED_INCOMPLETE, "CURRENT_INCOMPLETE_SNAPSHOT"
    elif prior is not None and order == "EQUAL" and (
        current["snapshot_root"] != prior["snapshot_root"] or current["graph_link"] != prior["graph_link"]
    ):
        status, basis = STATUS_CONFLICTING, "EQUAL_SOURCE_MARKER"
    elif not _qualified(current):
        status, basis = STATUS_SOURCE_FAILURE, "UNQUALIFIED_SOURCE_STATUS"
    elif prior is None or not _qualified(prior):
        status, basis = STATUS_OBSERVED_NEW, "FIRST_QUALIFIED_OBSERVATION"
    elif current["snapshot_root"] == prior["snapshot_root"] and current["graph_link"] == prior["graph_link"]:
        status, basis = STATUS_OBSERVED_CONTINUED, "UNCHANGED_SNAPSHOT_AND_GRAPH"
    else:
        status, basis = STATUS_OBSERVED_CHANGED, "SNAPSHOT_ROOT"
    return {
        "status": status,
        "basis": basis,
        "source_status": current["source_status"],
        "freshness": current["freshness"],
        "absence_inferred": False,
        "nonmembership_inferred": False,
        "business_truth_proven": False,
        "read_only": True,
    }


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


def _body(
    current_custody_raw: bytes,
    prior_custody_raw: bytes | None,
    *,
    current_graph_raw: bytes | None,
    prior_graph_raw: bytes | None,
    prior_artifact_id: str | None,
    prior_stage_id: str | None,
    graph_profile_registry: Mapping[str, object],
) -> dict[str, object]:
    current = _custody_view(current_custody_raw, current_graph_raw, graph_profile_registry)
    prior = _custody_view(prior_custody_raw, prior_graph_raw, graph_profile_registry)
    assert current is not None
    if (prior_artifact_id is None) != (prior_stage_id is None):
        raise IndependentSourceReconciliationError("reconciliation:prior-head-pair")
    if current["prior_artifact_id"] != (prior["artifact_id"] if prior is not None else None) or current["prior_stage_id"] != (prior["stage_id"] if prior is not None else None):
        raise IndependentSourceReconciliationError("reconciliation:custody-predecessor")
    if prior is None and prior_artifact_id is not None:
        raise IndependentSourceReconciliationError("reconciliation:head-predecessor")
    if prior is not None and prior_artifact_id is None:
        raise IndependentSourceReconciliationError("reconciliation:head-predecessor")
    if prior is not None and (current["subject"], current["scope"], current["profile_id"], current["profile_version"]) != (prior["subject"], prior["scope"], prior["profile_id"], prior["profile_version"]):
        raise IndependentSourceReconciliationError("reconciliation:profile-isolation")
    chronology = _chronology(prior, current)
    result = _result(prior, current, chronology)
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
        graph_profile_registry=registry,
    )
    artifact_id = _digest("artifact-id", body)
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "current_custody_artifact_id": body["current_custody"]["artifact_id"],  # type: ignore[index]
            "current_snapshot_root": body["current_custody"]["snapshot_root"],  # type: ignore[index]
            "result_status": body["result"]["status"],  # type: ignore[index]
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
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Reconstruct custody views and verify every reconciliation identity."""

    value = _parse(raw)
    if set(value) != RECONCILIATION_KEYS or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION:
        raise IndependentSourceReconciliationError("reconciliation:schema")
    registry = dict(graph_profile_registry or profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    expected_body = _body(
        current_custody_raw,
        prior_custody_raw,
        current_graph_raw=current_graph_raw,
        prior_graph_raw=prior_graph_raw,
        prior_artifact_id=value.get("prior_artifact_id"),
        prior_stage_id=value.get("prior_stage_id"),
        graph_profile_registry=registry,
    )
    for key in ("profile_binding", "reconciliation_contract", "subject", "scope", "prior_artifact_id", "prior_stage_id", "stage_kind", "predecessor_custody", "current_custody", "chronology", "result", "flags", "authority"):
        if value[key] != expected_body[key]:
            raise IndependentSourceReconciliationError(f"reconciliation:{key}-binding")
    if value["stage_kind"] != STAGE_KIND or value["profile_binding"] != _profile_binding() or value["reconciliation_contract"] != _contract_binding():
        raise IndependentSourceReconciliationError("reconciliation:contract")
    if value["result"]["status"] not in STATUSES or value["chronology"]["order"] not in CHRONOLOGY:  # type: ignore[index]
        raise IndependentSourceReconciliationError("reconciliation:status")
    prior_id = value["prior_artifact_id"]
    prior_stage = value["prior_stage_id"]
    if prior_id is not None:
        _hex(prior_id, "prior-artifact-id")
        _hex(prior_stage, "prior-stage-id")
        if prior_reconciliation_raw is None:
            raise IndependentSourceReconciliationError("reconciliation:prior-bytes-required")
        prior_value = _parse(prior_reconciliation_raw)
        if prior_value.get("schema") != SCHEMA or prior_value.get("artifact_id") != prior_id or prior_value.get("current_stage_id") != prior_stage:
            raise IndependentSourceReconciliationError("reconciliation:prior-binding")
        if prior_value.get("profile_binding") != _profile_binding() or prior_value.get("reconciliation_contract") != _contract_binding() or prior_value.get("authority") != AUTHORITY_FLAGS or prior_value.get("flags") != FIXED_FLAGS:
            raise IndependentSourceReconciliationError("reconciliation:prior-contract")
        prior_custody = value["predecessor_custody"]
        if not isinstance(prior_custody, dict) or prior_value.get("current_custody") != prior_custody:
            raise IndependentSourceReconciliationError("reconciliation:prior-custody-binding")
        prior_body = dict(prior_value)
        prior_body.pop("artifact_id")
        prior_body.pop("current_stage_id")
        prior_body.pop("transition_id")
        prior_expected_id = _digest("artifact-id", prior_body)
        prior_current = prior_value.get("current_custody")
        if not isinstance(prior_current, dict):
            raise IndependentSourceReconciliationError("reconciliation:prior-current")
        prior_expected_stage = _digest(
            "stage-id",
            {
                "artifact_id": prior_expected_id,
                "current_custody_artifact_id": prior_current["artifact_id"],
                "current_snapshot_root": prior_current["snapshot_root"],
                "result_status": prior_value["result"]["status"],
                "prior_artifact_id": prior_value["prior_artifact_id"],
                "prior_stage_id": prior_value["prior_stage_id"],
            },
        )
        prior_predecessor = prior_value.get("predecessor_custody")
        prior_expected_transition = _digest(
            "transition-id",
            {
                "artifact_id": prior_expected_id,
                "current_stage_id": prior_expected_stage,
                "prior_artifact_id": prior_value["prior_artifact_id"],
                "prior_stage_id": prior_value["prior_stage_id"],
                "predecessor_custody_artifact_id": prior_predecessor["artifact_id"] if isinstance(prior_predecessor, dict) else None,
                "current_custody_artifact_id": prior_current["artifact_id"],
            },
        )
        if prior_value.get("artifact_id") != prior_expected_id or prior_value.get("current_stage_id") != prior_expected_stage or prior_value.get("transition_id") != prior_expected_transition:
            raise IndependentSourceReconciliationError("reconciliation:prior-identity")
    else:
        if prior_reconciliation_raw is not None:
            raise IndependentSourceReconciliationError("reconciliation:unexpected-prior")
    body = dict(value)
    body.pop("artifact_id")
    body.pop("current_stage_id")
    body.pop("transition_id")
    artifact_id = _digest("artifact-id", body)
    current = value["current_custody"]
    assert isinstance(current, dict)
    predecessor = value["predecessor_custody"]
    stage_id = _digest(
        "stage-id",
        {
            "artifact_id": artifact_id,
            "current_custody_artifact_id": current["artifact_id"],
            "current_snapshot_root": current["snapshot_root"],
            "result_status": value["result"]["status"],
            "prior_artifact_id": prior_id,
            "prior_stage_id": prior_stage,
        },
    )
    transition_id = _digest(
        "transition-id",
        {
            "artifact_id": artifact_id,
            "current_stage_id": stage_id,
            "prior_artifact_id": prior_id,
            "prior_stage_id": prior_stage,
            "predecessor_custody_artifact_id": predecessor["artifact_id"] if isinstance(predecessor, dict) else None,
            "current_custody_artifact_id": current["artifact_id"],
        },
    )
    if value["artifact_id"] != artifact_id or value["current_stage_id"] != stage_id or value["transition_id"] != transition_id:
        raise IndependentSourceReconciliationError("reconciliation:identity")
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")
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
        "result_status": value["result"]["status"],
        "current_snapshot_root": current["snapshot_root"],
        "current_source_status": current["source_status"],
    }


__all__ = [
    "ARTIFACT_KIND",
    "AUTHORITY_FLAGS",
    "FIXED_FLAGS",
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
