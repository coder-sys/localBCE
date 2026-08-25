"""Producer-owned zero-PHI evidence export for the Blind governance wedge.

The request and response are intentionally smaller than a Provider Trust Graph.
Provider selection remains an in-memory Mirror access-control decision.  This
module validates the selected current primary graph with the existing
independent graph verifier, then constructs a fresh aggregate response from an
explicit allowlist.  It has no persistence, delivery, replay, logging, or
support side effect.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
import traceback
from typing import NoReturn

from app.mirror import nc_medicaid_fhir_profile as nc_profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.error_boundary import raise_redacted


class ProviderEvidenceExportError(ValueError):
    """Raised for one bounded, redacted contract failure."""


REQUEST_DOMAIN = "BL/MIRROR/PROVIDER_EVIDENCE_EXPORT/REQUEST"
RESPONSE_DOMAIN = "BL/MIRROR/PROVIDER_EVIDENCE_EXPORT/RESPONSE"
CONSUMER_DOMAIN = "BLIND/PROVIDER_GOVERNANCE_EVIDENCE"
EVIDENCE_PROFILE = "provider-continuity-aggregate"
EVIDENCE_PROFILE_VERSION = 1
GRAPH_SCHEMA = "mirror-provider-trust-graph-v2"
SYNTHETIC_SELECTION_AUTHORIZATION = "SYNTHETIC_PRIMARY_PROFILE_VERIFIED"
QUALIFICATION_STATUS = "SYNTHETIC_ONLY"
OUTCOME_KINDS = (
    "CONTINUITY_CONFIRMED",
    "CREDENTIAL_EXPIRED",
    "ENROLLMENT_TERMINATED",
    "EVIDENCE_INCOMPLETE",
    "AUTHORITATIVE_RECORD_ABSENT",
    "SOURCE_CONFLICT",
    "COVERAGE_STALE",
)
REQUEST_KEYS = {
    "domain",
    "version",
    "operation_ref",
    "consumer_domain",
    "evidence_profile",
    "evidence_profile_version",
    "not_before",
    "expires_at",
}
RESPONSE_KEYS = {
    "domain",
    "version",
    "operation_ref",
    "consumer_domain",
    "evidence_profile",
    "evidence_profile_version",
    "issued_at",
    "expires_at",
    "outcome",
    "source_count",
    "complete_source_count",
    "record_count",
    "finding_count",
    "discrepancy_count",
    "qualification_status",
    "synthetic_only",
    "production_usable",
    "activation",
    "clearance_authority",
    "payment_authority",
    "economic_mutation",
    "proofSuiteId",
}
MAX_REQUEST_BYTES = 4_096
MAX_RESPONSE_BYTES = 4_096
MAX_GRAPH_BYTES = 262_144
MAX_TIME = 10**12
MAX_WINDOW_SECONDS = 300
MAX_SOURCE_COUNT = 2
MAX_RECORD_COUNT = 16
MAX_FINDING_COUNT = 8
MAX_DISCREPANCY_COUNT = 8
_OPERATION_REF = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ProviderEvidenceSelectionV1:
    """In-memory Mirror selection; never serialized by this contract."""

    graph_artifact: bytes
    profile_registry: Mapping[str, object]
    authorization_evidence: str


def _fail(code: str) -> NoReturn:
    raise_redacted(ProviderEvidenceExportError, code)


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError):
        _fail("export:noncanonical")
    if len(raw) > MAX_RESPONSE_BYTES:
        _fail("export:byte-cap")
    return raw


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("export:duplicate-key")
        result[key] = value
    return result


def _parse(raw: bytes, *, maximum: int) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail("export:byte-cap")
    try:
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: _fail("export:constant"),
        )
    except ProviderEvidenceExportError:
        raise
    except (RecursionError, UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        _fail("export:parse")
    if not isinstance(value, dict) or _canonical(value) != raw:
        _fail("export:noncanonical")
    return value


def _expect_keys(value: object, expected: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(code)
    return value


def _text(value: object, expected: str, code: str) -> str:
    if type(value) is not str or value != expected:
        _fail(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _operation_ref(value: object, code: str = "export:operation-ref") -> str:
    if type(value) is not str or _OPERATION_REF.fullmatch(value) is None or set(value) == {"0"}:
        _fail(code)
    return value


def _validate_request(raw: bytes, *, now: int) -> dict[str, object]:
    if type(now) is not int or not 0 <= now <= MAX_TIME:
        _fail("export:clock")
    request = _parse(raw, maximum=MAX_REQUEST_BYTES)
    _expect_keys(request, REQUEST_KEYS, "export:request-keys")
    _text(request["domain"], REQUEST_DOMAIN, "export:request-domain")
    if type(request["version"]) is not int or request["version"] != 1:
        _fail("export:request-version")
    _operation_ref(request["operation_ref"])
    _text(request["consumer_domain"], CONSUMER_DOMAIN, "export:consumer-domain")
    _text(request["evidence_profile"], EVIDENCE_PROFILE, "export:evidence-profile")
    if type(request["evidence_profile_version"]) is not int or request["evidence_profile_version"] != EVIDENCE_PROFILE_VERSION:
        _fail("export:evidence-profile-version")
    not_before = _integer(request["not_before"], "export:not-before")
    expires_at = _integer(request["expires_at"], "export:expires-at")
    if expires_at <= not_before or expires_at - not_before > MAX_WINDOW_SECONDS:
        _fail("export:window")
    if not_before > now or expires_at <= now:
        _fail("export:time-window")
    return request


def _validate_selection_inner(selection: ProviderEvidenceSelectionV1) -> object:
    if not isinstance(selection, ProviderEvidenceSelectionV1):
        _fail("export:selection")
    if (
        type(selection.graph_artifact) is not bytes
        or not selection.graph_artifact
        or len(selection.graph_artifact) > MAX_GRAPH_BYTES
    ):
        _fail("export:graph-bytes")
    if selection.authorization_evidence != SYNTHETIC_SELECTION_AUTHORIZATION:
        _fail("export:authorization")
    registry = selection.profile_registry
    if not isinstance(registry, Mapping) or set(registry) != {nc_profile.SOURCE_PROFILE_ID}:
        _fail("export:profile-registry")
    profile = registry.get(nc_profile.SOURCE_PROFILE_ID)
    if not nc_profile.NC_MEDICAID_PROFILE.is_authorized_graph_profile(profile):
        _fail("export:profile-authority")
    try:
        verified = graph_independent.verify_artifact_v2(
            selection.graph_artifact,
            dict(registry),
        )
    except Exception:
        _fail("export:graph-reject")
    value = getattr(verified, "value", None)
    if not isinstance(value, dict):
        _fail("export:graph-result")
    if value.get("schema") != GRAPH_SCHEMA:
        _fail("export:graph-schema")
    profile_value = value.get("profile")
    if (
        not isinstance(profile_value, dict)
        or profile_value.get("profile_id") != profile.profile_id
        or profile_value.get("version") != profile.version
    ):
        _fail("export:graph-profile")
    if value.get("authority") != {
        "clearance_authority": False,
        "payment_authority": False,
        "economic_mutation": False,
        "production_usable": False,
        "synthetic_only": True,
    }:
        _fail("export:graph-authority")
    return value


def _validate_selection(selection: ProviderEvidenceSelectionV1) -> object:
    try:
        return _validate_selection_inner(selection)
    except ProviderEvidenceExportError:
        raise
    except Exception:
        _fail("export:selection")


def _derive_aggregate(value: Mapping[str, object]) -> dict[str, object]:
    sources = value.get("source_coverage")
    findings = value.get("findings")
    discrepancies = value.get("discrepancies")
    if (
        not isinstance(sources, list)
        or len(sources) != MAX_SOURCE_COUNT
        or not isinstance(findings, list)
        or not 1 <= len(findings) <= MAX_FINDING_COUNT
        or not isinstance(discrepancies, list)
        or len(discrepancies) > MAX_DISCREPANCY_COUNT
    ):
        _fail("export:aggregate-shape")
    complete_source_count = 0
    record_count = 0
    for source in sources:
        if not isinstance(source, Mapping):
            _fail("export:aggregate-source")
        if type(source.get("coverage_complete")) is not bool:
            _fail("export:aggregate-complete")
        if source["coverage_complete"]:
            complete_source_count += 1
        records = source.get("records")
        if not isinstance(records, list) or len(records) > MAX_RECORD_COUNT:
            _fail("export:aggregate-records")
        record_count += len(records)
    if record_count > MAX_RECORD_COUNT:
        _fail("export:aggregate-record-cap")
    if any(not isinstance(finding, Mapping) or finding.get("kind") not in OUTCOME_KINDS for finding in findings):
        _fail("export:aggregate-outcome")
    if len(findings) != 1:
        _fail("export:aggregate-outcome-count")
    return {
        "outcome": findings[0]["kind"],
        "source_count": len(sources),
        "complete_source_count": complete_source_count,
        "record_count": record_count,
        "finding_count": len(findings),
        "discrepancy_count": len(discrepancies),
    }


def _build_export_inner(request_raw: bytes, selection: ProviderEvidenceSelectionV1, *, now: int) -> bytes:
    """Validate one request and return one bounded, nonpersistent export."""

    request = _validate_request(request_raw, now=now)
    graph_value = _validate_selection(selection)
    aggregate = _derive_aggregate(graph_value)
    response: dict[str, object] = {
        "domain": RESPONSE_DOMAIN,
        "version": 1,
        "operation_ref": request["operation_ref"],
        "consumer_domain": CONSUMER_DOMAIN,
        "evidence_profile": EVIDENCE_PROFILE,
        "evidence_profile_version": EVIDENCE_PROFILE_VERSION,
        "issued_at": now,
        "expires_at": request["expires_at"],
        **aggregate,
        "qualification_status": QUALIFICATION_STATUS,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
        "clearance_authority": False,
        "payment_authority": False,
        "economic_mutation": False,
        "proofSuiteId": None,
    }
    if set(response) != RESPONSE_KEYS:
        _fail("export:response-keys")
    return _canonical(response)


def build_export(request_raw: bytes, selection: ProviderEvidenceSelectionV1, *, now: int) -> bytes:
    """Validate one request and return one bounded, nonpersistent export."""

    try:
        return _build_export_inner(request_raw, selection, now=now)
    except ProviderEvidenceExportError as error:
        request_raw = b""
        selection = None  # type: ignore[assignment]
        try:
            traceback.clear_frames(error.__traceback__)
        except Exception:
            pass
        raise
