"""Independent verification for the state-owned NC Medicaid source-evidence artifact.

The custody artifact is deliberately narrower than a data lake.  It keeps one
canonical fixture envelope together with a verifier-derived summary and an
optional Provider Trust Graph link.  This module owns only the wire and binding
checks; it does not import the continuity-store producer, the FHIR transport, or
the graph producer.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph


ARTIFACT_KIND = "NC_MEDICAID_SOURCE_EVIDENCE_V1"
SCHEMA = "mirror-ncmedicaid-source-evidence-custody-v2"
SCHEMA_VERSION = 2
STAGE_KIND = "SOURCE_EVIDENCE_CUSTODIED"
DOMAIN = "BL/MIRROR/SOURCE-EVIDENCE-CUSTODY/"
ADMISSION_DOMAIN = "BL/MIRROR/SOURCE-ADMISSION/"
STORE_DOMAIN = "BL/MIRROR/CONTINUITY-STORE-V2/"
MAX_ARTIFACT_BYTES = 524_288
MAX_ENVELOPE_BYTES = 180_000
MAX_RECEIPT_BYTES = 32_768
MAX_STRING_BYTES = MAX_ENVELOPE_BYTES * 2 + 2_048
HEX128 = re.compile(r"^[0-9a-f]{128}$")

AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}

FIXED_FLAGS = {
    "observation_only": True,
    "production_source_authentication": False,
    "production_usable": False,
    "synthetic_only": True,
    "live_transport_authorized": False,
    "source_completeness": "UNKNOWN",
    "allow_nonmembership": False,
}

CUSTODY_POLICY = {
    "owner": "STATE_SIDE_MIRROR_CUSTODY",
    "retention": "STATE_CONTROLLED_FIXTURE_EVIDENCE_V1",
    "raw_payload": "RETAINED_IN_STATE_ARTIFACT",
    "export": "STATE_OWNED_FULL_RESTORE",
    "support": "COMPACT_ALLOWLIST_NO_RAW_PAYLOAD",
    "encryption_at_rest_qualified": False,
}

VERIFICATION_SCHEMA = "mirror-ncmedicaid-source-verification-receipt-v1"
VERIFICATION_KEYS = {
    "schema", "schema_version", "source_profile_id", "source_profile_version",
    "source_profile_digest", "graph_profile_id", "graph_profile_version",
    "graph_profile_digest", "envelope_id", "envelope_digest", "envelope_bytes",
    "snapshot_id", "snapshot_root", "observation_time", "fetched_at",
    "source_status", "failure_code", "freshness", "page_count", "resource_count",
    "resource_counts", "server_total", "server_last_updated", "source_completeness",
    "allow_nonmembership", "evidence_mode", "production_source_authentication",
    "synthetic_only", "production_usable",
}

ADMISSION_KEYS = {
    "schema", "profile_id", "profile_version", "profile_digest", "verifier_id",
    "verifier_epoch", "evidence_mode", "adapter_digest", "source_result_digest",
    "graph_input_digest", "graph_artifact_digest", "graph_report_id",
    "production_source_authentication", "receipt_id",
}

GRAPH_LINK_KEYS = {
    "artifact_id", "payload_hash", "graph_artifact_digest", "report_id",
    "admission_receipt_hex",
}

CUSTODY_KEYS = {
    "schema", "schema_version", "profile_binding", "subject", "scope",
    "prior_artifact_id", "prior_stage_id", "stage_kind", "source_status",
    "failure_code", "freshness", "observation_time", "fetched_at", "page_complete",
    "server_markers", "snapshot_id", "snapshot_root", "page_count", "resource_count",
    "source_completeness", "allow_nonmembership", "verification_receipt", "envelope",
    "envelope_digest", "graph_link", "flags", "authority", "custody_policy", "artifact_id", "current_stage_id",
    "transition_id",
}


class IndependentSourceCustodyError(ValueError):
    """Stable fail-closed rejection from the custody boundary."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentSourceCustodyError("custody:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentSourceCustodyError("custody:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentSourceCustodyError("custody:node-cap")
    if depth > 24:
        raise IndependentSourceCustodyError("custody:depth-cap")
    if isinstance(value, float):
        raise IndependentSourceCustodyError("custody:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentSourceCustodyError("custody:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentSourceCustodyError("custody:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentSourceCustodyError("custody:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentSourceCustodyError("custody:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentSourceCustodyError("custody:constant")),
        )
    except IndependentSourceCustodyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentSourceCustodyError("custody:parse") from exc
    if not isinstance(value, dict):
        raise IndependentSourceCustodyError("custody:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentSourceCustodyError("custody:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def admission_raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((ADMISSION_DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def admission_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((ADMISSION_DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def storage_payload_hash(raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((STORE_DOMAIN + "CANONICAL-PAYLOAD/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX128.fullmatch(value):
        raise IndependentSourceCustodyError(f"custody:{label}")
    return value


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentSourceCustodyError(f"custody:{label}")
    try:
        if len(value.encode("ascii")) > maximum:
            raise IndependentSourceCustodyError(f"custody:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentSourceCustodyError(f"custody:{label}") from exc
    return value


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentSourceCustodyError(f"custody:{label}-keys")
    return value


def _profile_binding() -> dict[str, object]:
    source = profile.NC_MEDICAID_PROFILE
    graph_profile = source.graph_profile
    return {
        **source.binding(),
        "graph_profile_id": graph_profile.profile_id,
        "graph_profile_version": graph_profile.version,
        "evidence_mode": graph_profile.evidence_mode.value,
        "source_completeness": source.completeness,
        "allow_nonmembership": source.allow_nonmembership,
        "live_transport_authorized": source.live_transport_authorized,
        "synthetic_only": source.synthetic_only,
        "production_usable": source.production_usable,
    }


def _flags() -> dict[str, object]:
    return dict(FIXED_FLAGS)


def _verification_receipt(raw: bytes, result: Mapping[str, object]) -> dict[str, object]:
    source = profile.NC_MEDICAID_PROFILE
    graph_profile = source.graph_profile
    counts = result.get("resource_counts")
    if not isinstance(counts, dict) or set(counts) != set(source.allowed_resource_types):
        raise IndependentSourceCustodyError("custody:resource-counts")
    receipt: dict[str, object] = {
        "schema": VERIFICATION_SCHEMA,
        "schema_version": 1,
        "source_profile_id": source.source_profile_id,
        "source_profile_version": source.version,
        "source_profile_digest": source.profile_digest,
        "graph_profile_id": graph_profile.profile_id,
        "graph_profile_version": graph_profile.version,
        "graph_profile_digest": graph_profile.profile_digest,
        "envelope_id": result["envelope_id"],
        "envelope_digest": _raw_digest("envelope", raw),
        "envelope_bytes": len(raw),
        "snapshot_id": result["snapshot_id"],
        "snapshot_root": result["snapshot_root"],
        "observation_time": result["observation_time"],
        "fetched_at": result["fetched_at"],
        "source_status": result["source_status"],
        "failure_code": result["failure_code"],
        "freshness": result["freshness"],
        "page_count": result["page_count"],
        "resource_count": result["resource_count"],
        "resource_counts": {key: counts[key] for key in sorted(counts)},
        "server_total": result["server_total"],
        "server_last_updated": result["server_last_updated"],
        "source_completeness": source.completeness,
        "allow_nonmembership": source.allow_nonmembership,
        "evidence_mode": graph_profile.evidence_mode.value,
        "production_source_authentication": False,
        "synthetic_only": True,
        "production_usable": False,
    }
    if set(receipt) != VERIFICATION_KEYS:
        raise IndependentSourceCustodyError("custody:verification-keys")
    return receipt


def _verify_verification_receipt(raw: bytes, result: Mapping[str, object], value: Mapping[str, object]) -> dict[str, object]:
    receipt = _expect(value.get("verification_receipt"), VERIFICATION_KEYS, "verification")
    expected = _verification_receipt(raw, result)
    if receipt != expected:
        raise IndependentSourceCustodyError("custody:verification-binding")
    return receipt


def _source_result_digest(result: Mapping[str, object], graph_input: bytes) -> str:
    graph_profile = profile.NC_MEDICAID_PROFILE.graph_profile
    return admission_digest(
        "source-result",
        {
            "profile_id": graph_profile.profile_id,
            "subject": graph_profile.subject,
            "scope": graph_profile.scope,
            "observation_time": result["observation_time"],
            "effective_start": graph_profile.effective_start,
            "effective_end": graph_profile.effective_end,
            "complete": False,
            "source_roles": list(graph_profile.source_roles),
            "evidence_mode": graph_profile.evidence_mode.value,
            "graph_input_digest": admission_raw_digest("graph-input", graph_input),
        },
    )


def _verify_admission_receipt(
    envelope: bytes,
    result: Mapping[str, object],
    graph_raw: bytes,
    graph_link: Mapping[str, object],
    graph_result: Mapping[str, object],
) -> None:
    raw_receipt_hex = graph_link.get("admission_receipt_hex")
    if not isinstance(raw_receipt_hex, str) or len(raw_receipt_hex) > MAX_RECEIPT_BYTES * 2 or len(raw_receipt_hex) % 2:
        raise IndependentSourceCustodyError("custody:admission-receipt")
    try:
        raw_receipt = bytes.fromhex(raw_receipt_hex)
    except ValueError as exc:
        raise IndependentSourceCustodyError("custody:admission-receipt") from exc
    if raw_receipt.hex() != raw_receipt_hex:
        raise IndependentSourceCustodyError("custody:admission-receipt")
    try:
        receipt = json.loads(
            raw_receipt.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentSourceCustodyError("custody:admission-constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentSourceCustodyError("custody:admission-receipt") from exc
    receipt = _expect(receipt, ADMISSION_KEYS, "admission-receipt")
    if _canonical(receipt) != raw_receipt:
        raise IndependentSourceCustodyError("custody:admission-canonical")
    source = profile.NC_MEDICAID_PROFILE
    graph_profile = source.graph_profile
    coverage = fhir.to_verified_source_coverage(result, profile=source)
    expected_body = {
        "schema": "mirror-source-admission-receipt-v2",
        "profile_id": graph_profile.profile_id,
        "profile_version": graph_profile.version,
        "profile_digest": graph_profile.profile_digest,
        "verifier_id": graph_profile.verifier_id,
        "verifier_epoch": graph_profile.verifier_epoch,
        "evidence_mode": graph_profile.evidence_mode.value,
        "adapter_digest": admission_raw_digest("adapter", envelope),
        "source_result_digest": _source_result_digest(result, coverage.graph_input),
        "graph_input_digest": admission_raw_digest("graph-input", coverage.graph_input),
        "graph_artifact_digest": admission_raw_digest("graph-artifact", graph_raw),
        "graph_report_id": graph_result["report_id"],
        "production_source_authentication": False,
    }
    expected = {"receipt_id": admission_digest("receipt-id", expected_body), **expected_body}
    if receipt != expected:
        raise IndependentSourceCustodyError("custody:admission-binding")
    if graph_link.get("graph_artifact_digest") != expected_body["graph_artifact_digest"] or graph_link.get("report_id") != graph_result["report_id"]:
        raise IndependentSourceCustodyError("custody:graph-link-binding")


def verify_artifact(
    raw: bytes,
    *,
    graph_raw: bytes | None = None,
    graph_profile_registry: Mapping[str, object] | None = None,
    allow_unresolved_graph: bool = False,
) -> dict[str, object]:
    """Verify a custody artifact and, when supplied, its graph bytes."""

    value = _parse(raw)
    if set(value) != CUSTODY_KEYS or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentSourceCustodyError("custody:schema")
    if value["profile_binding"] != _profile_binding():
        raise IndependentSourceCustodyError("custody:profile-binding")
    graph_profile = profile.NC_MEDICAID_PROFILE.graph_profile
    if value["subject"] != graph_profile.subject or value["scope"] != graph_profile.scope:
        raise IndependentSourceCustodyError("custody:subject-scope")
    if value["stage_kind"] != STAGE_KIND:
        raise IndependentSourceCustodyError("custody:stage-kind")
    for key in ("prior_artifact_id", "prior_stage_id"):
        if value[key] is not None:
            _text(value[key], key)
    source_status = value["source_status"]
    if source_status not in fhir.SOURCE_STATUSES:
        raise IndependentSourceCustodyError("custody:source-status")
    failure_code = value["failure_code"]
    if failure_code is not None and failure_code not in fhir.FAILURE_CODES:
        raise IndependentSourceCustodyError("custody:failure-code")
    if value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"}:
        raise IndependentSourceCustodyError("custody:freshness")
    if type(value["observation_time"]) is not int or value["observation_time"] != profile.NC_MEDICAID_PROFILE.observation_time:
        raise IndependentSourceCustodyError("custody:observation-time")
    if value["fetched_at"] != profile.NC_MEDICAID_PROFILE.fetched_at:
        raise IndependentSourceCustodyError("custody:fetched-at")
    if type(value["page_complete"]) is not bool or value["page_complete"] is not (source_status == "COMPLETE"):
        raise IndependentSourceCustodyError("custody:complete-flag")
    if value["source_completeness"] != "UNKNOWN" or value["allow_nonmembership"] is not False:
        raise IndependentSourceCustodyError("custody:claims")
    markers = value["server_markers"]
    if markers != {"total": value["verification_receipt"].get("server_total"), "last_updated": value["verification_receipt"].get("server_last_updated")}:
        raise IndependentSourceCustodyError("custody:markers")
    envelope = _expect(value["envelope"], {"encoding", "byte_length", "bytes_hex"}, "envelope")
    if envelope["encoding"] != "canonical-json-ascii-hex":
        raise IndependentSourceCustodyError("custody:envelope-encoding")
    if type(envelope["bytes_hex"]) is not str or len(envelope["bytes_hex"]) % 2 or len(envelope["bytes_hex"]) > MAX_ENVELOPE_BYTES * 2:
        raise IndependentSourceCustodyError("custody:envelope-bytes")
    try:
        envelope_raw = bytes.fromhex(envelope["bytes_hex"])
    except ValueError as exc:
        raise IndependentSourceCustodyError("custody:envelope-bytes") from exc
    if envelope_raw.hex() != envelope["bytes_hex"] or len(envelope_raw) != envelope["byte_length"] or len(envelope_raw) > MAX_ENVELOPE_BYTES:
        raise IndependentSourceCustodyError("custody:envelope-length")
    try:
        result = fhir.verify_bytes(envelope_raw, profile=profile.NC_MEDICAID_PROFILE)
    except Exception as exc:
        raise IndependentSourceCustodyError("custody:envelope-reject") from exc
    verification = _verify_verification_receipt(envelope_raw, result, value)
    if value["source_status"] != result["source_status"] or value["failure_code"] != result["failure_code"] or value["freshness"] != result["freshness"]:
        raise IndependentSourceCustodyError("custody:status-binding")
    if value["page_complete"] != result["page_complete"] or value["snapshot_id"] != result["snapshot_id"] or value["snapshot_root"] != result["snapshot_root"]:
        raise IndependentSourceCustodyError("custody:snapshot-binding")
    if value["page_count"] != result["page_count"] or value["resource_count"] != result["resource_count"]:
        raise IndependentSourceCustodyError("custody:count-binding")
    if value["envelope_digest"] != verification["envelope_digest"]:
        raise IndependentSourceCustodyError("custody:envelope-digest")
    _hex(value["envelope_digest"], "envelope-digest")
    if value["flags"] != _flags():
        raise IndependentSourceCustodyError("custody:authority-flags")
    if value["authority"] != AUTHORITY_FLAGS:
        raise IndependentSourceCustodyError("custody:authority")
    if value["custody_policy"] != CUSTODY_POLICY:
        raise IndependentSourceCustodyError("custody:policy")
    graph_link = value["graph_link"]
    if graph_link is not None:
        link = _expect(graph_link, GRAPH_LINK_KEYS, "graph-link")
        _text(link["artifact_id"], "graph-link-artifact-id")
        _hex(link["payload_hash"], "graph-link-payload-hash")
        _hex(link["graph_artifact_digest"], "graph-link-digest")
        _text(link["report_id"], "graph-link-report-id")
        if graph_raw is None and not allow_unresolved_graph:
            raise IndependentSourceCustodyError("custody:graph-bytes-required")
        if graph_raw is not None:
            if not isinstance(graph_profile_registry, Mapping) or graph_profile_registry.get(graph_profile.profile_id) is None:
                raise IndependentSourceCustodyError("custody:graph-registry")
            try:
                graph_result = graph.verify_bytes_v2(graph_raw, graph_profile_registry)
            except Exception as exc:
                raise IndependentSourceCustodyError("custody:graph-reject") from exc
            if (
                graph_result.get("profile_id") != graph_profile.profile_id
                or graph_result.get("profile_version") != graph_profile.version
                or graph_result.get("profile_digest") != graph_profile.profile_digest
            ):
                raise IndependentSourceCustodyError("custody:graph-profile")
            graph_value = json.loads(graph_raw.decode("ascii"))
            if not isinstance(graph_value, dict) or not isinstance(graph_value.get("report"), dict):
                raise IndependentSourceCustodyError("custody:graph-shape")
            if link["artifact_id"] != graph_result["report_id"] or link["report_id"] != graph_result["report_id"]:
                raise IndependentSourceCustodyError("custody:graph-id-binding")
            if link["payload_hash"] != storage_payload_hash(graph_raw):
                raise IndependentSourceCustodyError("custody:graph-payload-binding")
            _verify_admission_receipt(envelope_raw, result, graph_raw, link, graph_result)
    body = dict(value)
    body.pop("artifact_id")
    body.pop("current_stage_id")
    body.pop("transition_id")
    expected_artifact_id = _digest("artifact-id", body)
    expected_stage_id = _digest(
        "stage-id",
        {
            "artifact_id": expected_artifact_id,
            "envelope_digest": value["envelope_digest"],
            "source_status": value["source_status"],
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    expected_transition_id = _digest(
        "transition-id",
        {
            "artifact_id": expected_artifact_id,
            "current_stage_id": expected_stage_id,
            "prior_artifact_id": value["prior_artifact_id"],
            "prior_stage_id": value["prior_stage_id"],
        },
    )
    if value["artifact_id"] != expected_artifact_id or value["current_stage_id"] != expected_stage_id or value["transition_id"] != expected_transition_id:
        raise IndependentSourceCustodyError("custody:identity")
    _hex(value["artifact_id"], "artifact-id")
    _hex(value["current_stage_id"], "stage-id")
    _hex(value["transition_id"], "transition-id")
    return {
        "kind": ARTIFACT_KIND,
        "schema": SCHEMA,
        "artifact_id": value["artifact_id"],
        "payload": raw,
        "payload_hash": storage_payload_hash(raw),
        "subject": graph_profile.subject,
        "scope": graph_profile.scope,
        "report_id": graph_link["report_id"] if isinstance(graph_link, dict) else None,
        "current_stage_id": value["current_stage_id"],
        "transition_id": value["transition_id"],
        "stage_kind": STAGE_KIND,
        "prior_artifact_id": value["prior_artifact_id"],
        "prior_stage_id": value["prior_stage_id"],
        "authority_json": _canonical(AUTHORITY_FLAGS).decode("ascii"),
        "profile_id": graph_profile.profile_id,
        "profile_version": graph_profile.version,
        "source_profile_id": profile.NC_MEDICAID_PROFILE.source_profile_id,
        "source_profile_version": profile.NC_MEDICAID_PROFILE.version,
        "envelope_digest": value["envelope_digest"],
        "linked_graph_artifact_id": graph_link["artifact_id"] if isinstance(graph_link, dict) else None,
        "linked_graph_payload_hash": graph_link["payload_hash"] if isinstance(graph_link, dict) else None,
        "linked_graph_report_id": graph_link["report_id"] if isinstance(graph_link, dict) else None,
        "source_status": value["source_status"],
    }


def envelope_digest_from_artifact(raw: bytes) -> str:
    verified = verify_artifact(raw, allow_unresolved_graph=True)
    digest = verified.get("envelope_digest")
    return _hex(digest, "envelope-digest")


def has_graph_link(raw: bytes) -> bool:
    value = _parse(raw)
    if set(value) != CUSTODY_KEYS or value.get("schema") != SCHEMA:
        raise IndependentSourceCustodyError("custody:schema")
    return value.get("graph_link") is not None


__all__ = [
    "ARTIFACT_KIND", "AUTHORITY_FLAGS", "CUSTODY_POLICY", "IndependentSourceCustodyError", "SCHEMA",
    "SCHEMA_VERSION", "STAGE_KIND", "MAX_ARTIFACT_BYTES", "MAX_ENVELOPE_BYTES",
    "admission_digest", "admission_raw_digest", "build_verification_receipt",
    "envelope_digest_from_artifact", "has_graph_link", "storage_payload_hash",
    "verify_artifact",
]


build_verification_receipt = _verification_receipt
