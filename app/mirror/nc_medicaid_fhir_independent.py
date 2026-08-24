"""Independent verifier for the bounded V2 NC FHIR capture envelope."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.error_boundary import raise_redacted
from app.mirror.nc_medicaid_fhir_profile import (
    ALLOWED_MEDIA_TYPE, ALLOWED_RESOURCE_FIELDS, ALLOWED_RESOURCE_TYPES, CLAIM_FLAGS,
    DEFAULT_CAPTURE_CONTEXT, DynamicCaptureContext, NC_MEDICAID_PROFILE,
    NcMedicaidFhirSourceProfile, synthetic_resource_variants,
)
from app.mirror.source_admission import EvidenceMode, VerifiedSourceCoverage


class IndependentNcMedicaidFhirError(ValueError):
    """Fixed-code independent FHIR failure."""


ENVELOPE_SCHEMA = "mirror-ncmedicaid-fhir-observation-envelope-v2"
ENVELOPE_SCHEMA_VERSION = 2
ENVELOPE_KEYS = {
    "schema", "schema_version", "profile", "capture_context", "owner", "request", "observation_time", "fetched_at",
    "server_markers", "pages", "page_complete", "source_status", "failure_code", "source_completeness", "claims",
    "snapshot_root", "snapshot_id", "envelope_id",
}
PROFILE_KEYS = {"source_profile_id", "source_profile_version", "source_profile_digest", "graph_profile_version", "graph_profile_digest", "source_meaning", "transport_provenance", "record_authentication", "capability_statement_identity", "capability_statement_digest"}
CONTEXT_KEYS = {"subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observation_time", "fetched_at"}
OWNER_KEYS = {"owner", "system", "base_url", "host", "fhir_version"}
REQUEST_KEYS = {"method", "url", "query_parameters", "page_parameter", "request_identity"}
MARKER_KEYS = {"total", "last_updated"}
PAGE_KEYS = {"sequence", "request_url", "request_identity", "response_url", "status", "media_type", "byte_length", "body_digest", "body_hex", "attempt_statuses", "retry_after_seconds", "bundle", "resource_digests", "next_url", "failure_code", "transport_error", "page_id"}
BUNDLE_REQUIRED_KEYS = {"resourceType", "type", "id", "link", "entry"}
BUNDLE_OPTIONAL_KEYS = {"total", "meta"}
ENTRY_KEYS = {"fullUrl", "resource"}
RESOURCE_REQUIRED_KEYS = {
    "Practitioner": {"resourceType", "id", "identifier", "name", "active"},
    "PractitionerRole": {"resourceType", "id", "identifier", "active", "practitioner", "location", "code", "specialty", "network", "period", "endpoint"},
    "Location": {"resourceType", "id", "identifier", "name", "status", "address", "endpoint"},
}
TRANSPORT_ERROR_CODES = {"timeout", "transport"}
FAILURE_CODES = {"wrong-host", "redirect", "rate-limit", "server-error", "timeout", "retry-exhausted", "retry-after", "http-status", "media-type", "schema", "noncanonical", "partial-page", "query-drift", "total-drift", "marker-drift", "stale", "profile-downgrade", "capability-mismatch", "forbidden-resource", "forbidden-field", "reference", "identifier", "period", "address", "endpoint"}
SOURCE_STATUSES = {"COMPLETE", "PARTIAL", "FAILED", "STALE"}
_HEX = set("0123456789abcdef")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$")
_SYSTEM = re.compile(r"^(?:urn:[A-Za-z0-9:._-]+|https://[A-Za-z0-9._:/-]+)$")
_REFERENCE = re.compile(r"^(Practitioner|Location)/[A-Za-z0-9._-]{1,64}$")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentNcMedicaidFhirError, "json:noncanonical")


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IndependentNcMedicaidFhirError("json:duplicate-key")
        value[key] = item
    return value


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None, key: str | None = None, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > profile.transport_caps["max_nodes"]:
        raise IndependentNcMedicaidFhirError("json:node-cap")
    if depth > profile.transport_caps["max_depth"]:
        raise IndependentNcMedicaidFhirError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentNcMedicaidFhirError("json:float")
    if isinstance(value, str) and len(value.encode("utf-8")) > (profile.transport_caps["max_page_bytes"] * 2 if key == "body_hex" else profile.transport_caps["max_string_bytes"]):
        raise IndependentNcMedicaidFhirError("json:string-cap")
    if isinstance(value, dict):
        for name, item in value.items():
            if not isinstance(name, str):
                raise IndependentNcMedicaidFhirError("json:key-type")
            _walk(name, depth=depth + 1, count=count, profile=profile)
            _walk(item, depth=depth + 1, count=count, key=name, profile=profile)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count, profile=profile)


def _parse(raw: bytes, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > profile.transport_caps["complete_frame_bytes"]
        or len(raw) > profile.transport_caps["max_envelope_bytes"]
    ):
        raise IndependentNcMedicaidFhirError("json:byte-cap")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentNcMedicaidFhirError("json:constant")))
    except IndependentNcMedicaidFhirError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise_redacted(IndependentNcMedicaidFhirError, "json:parse")
    if not isinstance(value, dict):
        raise IndependentNcMedicaidFhirError("json:top-level")
    _walk(value, profile=profile)
    if _canonical(value) != raw:
        raise IndependentNcMedicaidFhirError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentNcMedicaidFhirError(label + ":keys")
    return value


def _text(value: object, label: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise IndependentNcMedicaidFhirError(label + ":text")
    return value


def _int(value: object, label: str, *, minimum: int = 0, maximum: int = 2_147_483_647) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentNcMedicaidFhirError(label + ":integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise IndependentNcMedicaidFhirError(label + ":boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise IndependentNcMedicaidFhirError(label + ":hex")
    return value


def _profile_binding(value: object, profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext) -> dict[str, object]:
    binding = _expect(value, PROFILE_KEYS, "profile")
    if binding != profile.binding(context):
        raise IndependentNcMedicaidFhirError("profile:binding")
    _text(binding["source_profile_id"], "profile:id"); _int(binding["source_profile_version"], "profile:version", minimum=1); _hex(binding["source_profile_digest"], "profile:digest"); _int(binding["graph_profile_version"], "profile:graph-version", minimum=3); _hex(binding["graph_profile_digest"], "profile:graph-digest"); _text(binding["capability_statement_identity"], "profile:capability-id")
    if binding["capability_statement_digest"] is not None:
        _hex(binding["capability_statement_digest"], "profile:capability-digest")
    return binding


def _context(value: object) -> DynamicCaptureContext:
    item = _expect(value, CONTEXT_KEYS, "capture-context")
    try:
        return DynamicCaptureContext(str(item["subject_id"]), str(item["credential_id"]), str(item["enrollment_id"]), str(item["subject_locator_digest"]), item["observation_time"], item["fetched_at"])  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise IndependentNcMedicaidFhirError("capture-context:binding") from None


def _query_parameters(profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext) -> list[list[str]]:
    return [[key, value.replace("{subject_locator_digest}", context.subject_locator_digest)] for key, value in profile.query_parameters]


def _validate_request(value: object, profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext) -> dict[str, object]:
    request = _expect(value, REQUEST_KEYS, "request")
    expected_url = profile.page_url(0, context)
    if request != {"method": "GET", "url": expected_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter, "request_identity": _digest("request", {"method": "GET", "url": expected_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter})}:
        raise IndependentNcMedicaidFhirError("request:profile")
    return request


def _validate_owner(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    owner = _expect(value, OWNER_KEYS, "owner")
    if owner != {"owner": profile.owner, "system": profile.system, "base_url": profile.base_url, "host": profile.host, "fhir_version": profile.fhir_version}:
        raise IndependentNcMedicaidFhirError("owner:binding")
    return owner


def _validate_date(value: object, label: str) -> str:
    text = _text(value, label, maximum=32)
    if _DATE.fullmatch(text) is None:
        raise IndependentNcMedicaidFhirError(label + ":format")
    return text


def _validate_identifier_list(value: object, label: str, profile: NcMedicaidFhirSourceProfile) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= profile.transport_caps["max_identifiers"]:
        raise IndependentNcMedicaidFhirError(label + ":count")
    for item in value:
        identifier = _expect(item, {"system", "value"}, label + ".item")
        system = _text(identifier["system"], label + ".system")
        if _SYSTEM.fullmatch(system) is None:
            raise IndependentNcMedicaidFhirError(label + ":system")
        _text(identifier["value"], label + ".value")


def _validate_resource(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("resourceType") not in profile.allowed_resource_types:
        raise IndependentNcMedicaidFhirError("resource:forbidden-resource")
    resource_type = str(value["resourceType"])
    allowed = set(dict(profile.allowed_resource_fields)[resource_type])
    if not set(value).issubset(allowed) or not RESOURCE_REQUIRED_KEYS[resource_type].issubset(value):
        raise IndependentNcMedicaidFhirError("resource:forbidden-field")
    resource = dict(value)
    resource_id = _text(resource["id"], "resource:id", maximum=64)
    if _RESOURCE_ID.fullmatch(resource_id) is None:
        raise IndependentNcMedicaidFhirError("resource:id")
    _validate_identifier_list(resource["identifier"], resource_type.lower() + ":identifier", profile)
    if resource_type == "Practitioner":
        _expect(resource["name"][0] if isinstance(resource["name"], list) and resource["name"] else None, {"use", "family", "given"}, "resource:name")
        _bool(resource["active"], "practitioner:active")
    elif resource_type == "PractitionerRole":
        _bool(resource["active"], "role:active")
        practitioner = resource["practitioner"].get("reference") if isinstance(resource["practitioner"], dict) else None
        locations = resource["location"]
        location = locations[0].get("reference") if isinstance(locations, list) and len(locations) == 1 and isinstance(locations[0], dict) else None
        if not isinstance(practitioner, str) or _REFERENCE.fullmatch(practitioner) is None or not isinstance(location, str) or _REFERENCE.fullmatch(location) is None:
            raise IndependentNcMedicaidFhirError("reference:shape")
        for key in ("code", "specialty"):
            if not isinstance(resource[key], list) or not resource[key]:
                raise IndependentNcMedicaidFhirError("resource:" + key)
        _expect(resource["period"], {"start", "end"}, "resource:period")
        start = _validate_date(resource["period"]["start"], "resource:period-start")
        end = _validate_date(resource["period"]["end"], "resource:period-end")
        if start > end:
            raise IndependentNcMedicaidFhirError("resource:period-order")
    else:
        _text(resource["name"], "location:name")
        if resource["status"] not in {"active", "inactive", "suspended"}:
            raise IndependentNcMedicaidFhirError("location:status")
        address = _expect(resource["address"], {"use", "line", "city", "state", "postalCode", "country"}, "resource:address")
        if address["use"] not in {"work", "home"} or not isinstance(address["line"], list) or not address["line"]:
            raise IndependentNcMedicaidFhirError("resource:address")
        for key in ("city", "state", "postalCode", "country"):
            _text(address[key], "resource:address-" + key)
        endpoint = resource["endpoint"]
        if not isinstance(endpoint, list):
            raise IndependentNcMedicaidFhirError("location:endpoint")
        for item in endpoint:
            if not isinstance(item, dict) or set(item) != {"reference"} or _REFERENCE.fullmatch(str(item["reference"])) is None:
                raise IndependentNcMedicaidFhirError("location:endpoint:unlinked")
    if _canonical(resource) not in synthetic_resource_variants(resource_type):
        raise IndependentNcMedicaidFhirError("resource:synthetic-binding")
    return resource


def _validate_bundle(bundle: object, profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str, context: DynamicCaptureContext) -> tuple[list[dict[str, object]], str | None, int | None, str | None]:
    if not isinstance(bundle, dict) or not set(bundle).issubset(BUNDLE_REQUIRED_KEYS | BUNDLE_OPTIONAL_KEYS) or not BUNDLE_REQUIRED_KEYS.issubset(bundle) or bundle["resourceType"] != "Bundle" or bundle["type"] != "searchset":
        raise IndependentNcMedicaidFhirError("bundle:keys")
    _text(bundle["id"], "bundle:id", maximum=64)
    links = bundle["link"]
    if not isinstance(links, list) or not 1 <= len(links) <= 2:
        raise IndependentNcMedicaidFhirError("bundle:links")
    relations: set[str] = set(); next_url: str | None = None
    for link_value in links:
        link = _expect(link_value, {"relation", "url"}, "bundle:link")
        relation = _text(link["relation"], "bundle:relation")
        if relation in relations or relation not in {"self", "next"}:
            raise IndependentNcMedicaidFhirError("bundle:link-relation")
        relations.add(relation); url = _text(link["url"], "bundle:url", maximum=1024)
        if relation == "self" and url != request_url:
            raise IndependentNcMedicaidFhirError("bundle:self-url")
        if relation == "next":
            next_url = url
    if "self" not in relations or (next_url is not None and next_url != profile.page_url(sequence + 1, context)):
        raise IndependentNcMedicaidFhirError("bundle:query-drift")
    total = bundle.get("total")
    if total is not None:
        _int(total, "bundle:total", maximum=profile.transport_caps["max_resources"])
    last_updated = None
    if bundle.get("meta") is not None:
        meta = _expect(bundle["meta"], {"lastUpdated"}, "bundle:meta")
        last_updated = _validate_date(meta["lastUpdated"], "bundle:last-updated")
    entries = bundle["entry"]
    if not isinstance(entries, list):
        raise IndependentNcMedicaidFhirError("bundle:entry-count")
    resources: list[dict[str, object]] = []
    for entry_value in entries:
        entry = _expect(entry_value, ENTRY_KEYS, "bundle:entry")
        resource = _validate_resource(entry["resource"], profile)
        full_url = _text(entry["fullUrl"], "bundle:full-url")
        if full_url != profile.base_url + "/" + str(resource["resourceType"]) + "/" + str(resource["id"]):
            raise IndependentNcMedicaidFhirError("bundle:full-url")
        resources.append(resource)
    return resources, next_url, total, last_updated


def _validate_page(value: object, profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str, context: DynamicCaptureContext) -> tuple[list[dict[str, object]], str | None, int | None, str | None]:
    page = _expect(value, PAGE_KEYS, "page")
    if page["sequence"] != sequence or page["request_url"] != request_url or page["request_identity"] != _digest("request", {"method": "GET", "url": request_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter}):
        raise IndependentNcMedicaidFhirError("page:request")
    _int(page["status"], "page:status", maximum=599); _hex(page["body_digest"], "page:body-digest"); _int(page["byte_length"], "page:byte-length", maximum=profile.transport_caps["max_page_bytes"])
    attempts = page["attempt_statuses"]
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= profile.transport_caps["max_retries"] + 1:
        raise IndependentNcMedicaidFhirError("page:attempts")
    for attempt_status in attempts:
        _int(attempt_status, "page:attempt-status", maximum=599)
    if attempts[-1] != page["status"]:
        raise IndependentNcMedicaidFhirError("page:attempt-final")
    retry_after = page["retry_after_seconds"]
    if not isinstance(retry_after, list) or len(retry_after) != len(attempts) or any(value is not None and (type(value) is not int or value < 0 or value > profile.transport_caps["max_retry_after_seconds"]) for value in retry_after):
        raise IndependentNcMedicaidFhirError("page:retry-after")
    failure = page["failure_code"]
    if failure is not None and (not isinstance(failure, str) or failure not in FAILURE_CODES):
        raise IndependentNcMedicaidFhirError("page:failure-code")
    transport_error = page["transport_error"]
    if transport_error is not None and transport_error not in TRANSPORT_ERROR_CODES:
        raise IndependentNcMedicaidFhirError("page:transport-error")
    if page["response_url"] is not None:
        _text(page["response_url"], "page:response-url", maximum=1024)
    if failure is None and page["response_url"] != request_url:
        raise IndependentNcMedicaidFhirError("page:response-url")
    if failure is None:
        if page["status"] != 200 or page["media_type"] != ALLOWED_MEDIA_TYPE or not isinstance(page["bundle"], dict) or page["body_hex"] is not None or transport_error is not None:
            raise IndependentNcMedicaidFhirError("page:success-binding")
        body = _canonical(page["bundle"])
        if len(body) != page["byte_length"] or _raw_digest("page-bytes", body) != page["body_digest"]:
            raise IndependentNcMedicaidFhirError("page:body-binding")
        resources, next_url, total, marker = _validate_bundle(page["bundle"], profile, sequence, request_url, context)
        if page["next_url"] != next_url or page["resource_digests"] != [_digest("resource", resource) for resource in resources]:
            raise IndependentNcMedicaidFhirError("page:resource-binding")
        return resources, next_url, total, marker
    if page["body_hex"] != "" or page["bundle"] is not None or page["resource_digests"] != [] or page["next_url"] is not None or page["byte_length"] != 0 or page["body_digest"] != _raw_digest("page-bytes", b""):
        raise IndependentNcMedicaidFhirError("page:failure-body")
    return [], None, None, None


def _validate_markers(value: object) -> dict[str, object]:
    return _expect(value, MARKER_KEYS, "markers")


def _freshness(marker: str | None) -> str:
    if marker is None:
        return "UNKNOWN"
    if not isinstance(marker, str) or _DATE.fullmatch(marker) is None:
        raise IndependentNcMedicaidFhirError("markers:last-updated")
    return "STALE" if marker.startswith(("1900", "197")) else "FRESH"


def _verified_resource_digests(resources: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, str]:
    if not isinstance(resources, list) or len(resources) != sum(count for _resource_type, count in profile.resource_cardinality):
        raise IndependentNcMedicaidFhirError("resource:graph-binding")
    result: dict[str, str] = {}
    for value in resources:
        resource = _validate_resource(value, profile)
        resource_type = str(resource["resourceType"])
        if resource_type in result:
            raise IndependentNcMedicaidFhirError("resource:graph-binding")
        result[resource_type] = _digest("resource", resource)
    if set(result) != set(profile.allowed_resource_types):
        raise IndependentNcMedicaidFhirError("resource:graph-binding")
    return result


def _graph_record_id(profile, role_index: int, context: DynamicCaptureContext, resource_digests: tuple[str, ...]) -> str:
    return _digest("graph-record", {"profile": profile.profile_digest, "role": role_index, "context": context.material(), "resource_digests": list(resource_digests)})


def _graph_source(graph_profile, role_index: int, observation_time: int, *, complete: bool, record_id: str) -> dict[str, object]:
    role = graph_profile.source_role_details[role_index]
    record = {
        "record_id": record_id, "record_kind": role.record_kind, "provider_id": graph_profile.subject,
        "credential_id": graph_profile.credential_id, "enrollment_id": graph_profile.enrollment_id,
        "subject_key": graph_profile.subject + "|" + graph_profile.credential_id + "|" + graph_profile.enrollment_id,
        "observed_at": observation_time, "issued_at": graph_profile.effective_start,
        "valid_from": graph_profile.effective_start, "valid_until": graph_profile.effective_end,
        "terminated_at": 0, "status": "ACTIVE",
    }
    source: dict[str, object] = {
        "source_id": role.source_id, "source_kind": role.source_kind, "coverage_scope": graph_profile.scope,
        "coverage_observation_time": observation_time, "coverage_effective_start": graph_profile.effective_start,
        "coverage_effective_end": graph_profile.effective_end, "coverage_complete": complete,
        "coverage_authority_id": role.authority_id, "nonmembership_keys": [], "records": [record],
        "provenance": {"provenance_id": role.provenance_id, "integrity_digest": "0" * 128},
    }
    view = graph_independent._profile_view(graph_profile)
    source["provenance"]["integrity_digest"] = graph_independent._integrity_digest(source, profile=view)  # type: ignore[index]
    return source


def _graph_input(profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext, resources: object) -> bytes:
    graph_profile = profile.graph_profile_for_context(context)
    resource_digests = _verified_resource_digests(resources, profile)
    value = {
        "schema": "mirror-provider-trust-graph-input-v2", "profile_id": graph_profile.profile_id,
        "profile_version": graph_profile.version, "profile_digest": graph_profile.profile_digest,
        "provider_graph_subject": graph_profile.subject, "scope": graph_profile.scope,
        "observation_time": context.observation_time,
        "sources": [
            _graph_source(
                graph_profile, 0, context.observation_time, complete=False,
                record_id=_graph_record_id(graph_profile, 0, context, (resource_digests["Practitioner"],)),
            ),
            _graph_source(
                graph_profile, 1, context.observation_time, complete=False,
                record_id=_graph_record_id(graph_profile, 1, context, (resource_digests["PractitionerRole"], resource_digests["Location"])),
            ),
        ],
        "prior_artifact": None, "remediation": None, "parity_cases": [],
    }
    return _canonical(value)


def verify_bytes(raw: bytes, *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> dict[str, object]:
    if not isinstance(profile, NcMedicaidFhirSourceProfile) or profile != NC_MEDICAID_PROFILE:
        raise IndependentNcMedicaidFhirError("profile:downgrade")
    value = _parse(raw, profile)
    if set(value) != ENVELOPE_KEYS or value["schema"] != ENVELOPE_SCHEMA or value["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise IndependentNcMedicaidFhirError("envelope:schema")
    context = _context(value["capture_context"])
    if value["observation_time"] != context.observation_time or value["fetched_at"] != context.fetched_at:
        raise IndependentNcMedicaidFhirError("snapshot:context-time")
    _profile_binding(value["profile"], profile, context); _validate_owner(value["owner"], profile); _validate_request(value["request"], profile, context)
    _int(value["observation_time"], "snapshot:observation-time", minimum=1); _int(value["fetched_at"], "snapshot:fetched-at", minimum=value["observation_time"])
    markers = _validate_markers(value["server_markers"])
    pages = value["pages"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= profile.transport_caps["max_pages"]:
        raise IndependentNcMedicaidFhirError("pages:count")
    source_status = value["source_status"]
    if source_status not in SOURCE_STATUSES:
        raise IndependentNcMedicaidFhirError("snapshot:status")
    failure_code = value["failure_code"]
    if failure_code is not None and failure_code not in FAILURE_CODES:
        raise IndependentNcMedicaidFhirError("snapshot:failure-code")
    if value["source_completeness"] != "UNKNOWN" or value["claims"] != CLAIM_FLAGS or value["page_complete"] is not (source_status == "COMPLETE"):
        raise IndependentNcMedicaidFhirError("snapshot:claims")
    resources: list[dict[str, object]] = []; totals: list[int | None] = []; marker_values: list[str | None] = []
    page_resource_types: set[str] = set()
    for index, page in enumerate(pages):
        if not isinstance(page, dict):
            raise IndependentNcMedicaidFhirError("page:request")
        if page.get("sequence") != index:
            raise IndependentNcMedicaidFhirError("page:request")
        bundle = page.get("bundle")
        entries = bundle.get("entry", []) if isinstance(bundle, dict) else []
        for entry in entries:
            resource = entry.get("resource") if isinstance(entry, dict) else None
            resource_type = resource.get("resourceType") if isinstance(resource, dict) else None
            if isinstance(resource_type, str):
                if resource_type in page_resource_types:
                    raise IndependentNcMedicaidFhirError("resource:duplicate")
                page_resource_types.add(resource_type)
    for sequence, page in enumerate(pages):
        request_url = profile.page_url(sequence, context)
        page_resources, next_url, total, marker = _validate_page(page, profile, sequence, request_url, context)
        resources.extend(page_resources); totals.append(total); marker_values.append(marker)
        if page.get("failure_code") is not None and sequence != len(pages) - 1:
            raise IndependentNcMedicaidFhirError("pages:after-failure")
        if next_url is None and sequence != len(pages) - 1:
            raise IndependentNcMedicaidFhirError("pages:omission")
        if next_url is not None and sequence == len(pages) - 1 and source_status == "COMPLETE":
            raise IndependentNcMedicaidFhirError("pages:partial")
    if pages[-1].get("failure_code") is not None and source_status == "COMPLETE":
        raise IndependentNcMedicaidFhirError("snapshot:failed-complete")
    total_values = {item for item in totals if item is not None}
    marker_values_unique = {item for item in marker_values if item is not None}
    if len(total_values) > 1 and failure_code != "total-drift":
        raise IndependentNcMedicaidFhirError("total-drift")
    if len(marker_values_unique) > 1 and failure_code != "marker-drift":
        raise IndependentNcMedicaidFhirError("marker-drift")
    expected_total = next(iter(total_values), None)
    expected_marker = next(iter(marker_values_unique), None)
    if markers != {"total": expected_total, "last_updated": expected_marker} and failure_code not in {"total-drift", "marker-drift"}:
        raise IndependentNcMedicaidFhirError("markers:binding")
    freshness = _freshness(expected_marker)
    if freshness == "STALE" and failure_code != "stale":
        raise IndependentNcMedicaidFhirError("snapshot:stale")
    complete = source_status == "COMPLETE" and failure_code is None
    counts = {resource_type: sum(1 for resource in resources if resource["resourceType"] == resource_type) for resource_type in profile.allowed_resource_types}
    if len(resources) > profile.transport_caps["max_resources"] or complete and counts != dict(profile.resource_cardinality):
        raise IndependentNcMedicaidFhirError("resource:cardinality")
    aggregate_ids = {str(item["resourceType"]): str(item["id"]) for item in resources}
    role = next((item for item in resources if item["resourceType"] == "PractitionerRole"), None)
    if role is not None:
        practitioner = role["practitioner"]["reference"] if isinstance(role.get("practitioner"), dict) else None
        location = role["location"][0]["reference"] if isinstance(role.get("location"), list) and role["location"] else None
        if (
            ("Practitioner" in aggregate_ids and practitioner != ("Practitioner/" + aggregate_ids["Practitioner"]))
            or ("Location" in aggregate_ids and location != ("Location/" + aggregate_ids["Location"]))
            or (complete and ("Practitioner" not in aggregate_ids or "Location" not in aggregate_ids))
        ):
            raise IndependentNcMedicaidFhirError("reference:binding")
    snapshot_root = _digest("snapshot-root", {"page_ids": [page["page_id"] for page in pages]})
    request_url = profile.page_url(0, context)
    expected_snapshot_id = _digest("snapshot-id", {"profile": profile.binding(context), "request_identity": _digest("request", {"method": "GET", "url": request_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter}), "capture_context": context.material(), "observation_time": context.observation_time, "fetched_at": context.fetched_at, "snapshot_root": snapshot_root, "source_status": source_status, "failure_code": failure_code, "server_markers": markers})
    if value["snapshot_root"] != snapshot_root or value["snapshot_id"] != expected_snapshot_id:
        raise IndependentNcMedicaidFhirError("snapshot:identity")
    _hex(value["snapshot_root"], "snapshot:root"); _hex(value["snapshot_id"], "snapshot:id")
    body_without_id = dict(value); body_without_id.pop("envelope_id")
    if value["envelope_id"] != _digest("envelope-id", body_without_id):
        raise IndependentNcMedicaidFhirError("envelope:identity")
    _hex(value["envelope_id"], "envelope:id")
    return {
        "accepted": True, "envelope_bytes": len(raw), "envelope_id": value["envelope_id"],
        "source_profile_id": profile.source_profile_id, "source_profile_version": profile.version,
        "source_profile_digest": profile.profile_digest, "source_contract_digest": profile.profile_digest,
        "graph_profile_digest": profile.graph_profile_for_context(context).profile_digest,
        "capture_context": context.material(), "observation_time": context.observation_time, "fetched_at": context.fetched_at,
        "source_status": source_status, "page_complete": value["page_complete"], "failure_code": failure_code,
        "freshness": freshness, "server_total": expected_total, "server_last_updated": expected_marker,
        "snapshot_root": snapshot_root, "page_count": len(pages), "resource_count": len(resources),
        "resource_counts": counts, "resources": resources, "snapshot_id": value["snapshot_id"],
        "page_digests": tuple(str(page["body_digest"]) for page in pages),
        "page_evidence": tuple({"page_index": int(page["sequence"]), "request_identity": page["request_identity"], "attempts": tuple({"transport_attempt": index, "status": status, "retry_after_seconds": page["retry_after_seconds"][index], "response_digest": page["body_digest"] if index == len(page["attempt_statuses"]) - 1 and page["failure_code"] is None else None, "response_url": page["response_url"] if index == len(page["attempt_statuses"]) - 1 else None, "redirect": page["failure_code"] == "redirect", "failure_code": page["failure_code"] if index == len(page["attempt_statuses"]) - 1 else None, "transport_error": page["transport_error"] if index == len(page["attempt_statuses"]) - 1 else None, "selected": index == len(page["attempt_statuses"]) - 1} for index, status in enumerate(page["attempt_statuses"]))} for page in pages),
        "transport_authenticated": False,
        "transport_evidence_classification": "SYNTHETIC_FIXTURE_UNAUTHENTICATED",
    }


def to_verified_source_coverage(result: Mapping[str, object], *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> VerifiedSourceCoverage:
    if result.get("accepted") is not True or result.get("source_status") != "COMPLETE" or result.get("page_complete") is not True:
        failure = result.get("failure_code")
        if not isinstance(failure, str) or failure not in FAILURE_CODES:
            raise_redacted(IndependentNcMedicaidFhirError, "source:invalid")
        raise_redacted(IndependentNcMedicaidFhirError, "source:" + failure)
    context = _context(result.get("capture_context"))
    graph_profile = profile.graph_profile_for_context(context)
    return VerifiedSourceCoverage(
        profile_id=graph_profile.profile_id, subject=graph_profile.subject, scope=graph_profile.scope,
        observation_time=context.observation_time, effective_start=graph_profile.effective_start,
        effective_end=graph_profile.effective_end, complete=False, source_roles=graph_profile.source_roles,
        evidence_mode=EvidenceMode.OBSERVATION_ONLY, graph_input=_graph_input(profile, context, result.get("resources")),
        credential_id=context.credential_id, enrollment_id=context.enrollment_id,
        subject_locator_digest=context.subject_locator_digest, source_contract_digest=profile.profile_digest,
        fetched_at=context.fetched_at, envelope_id=str(result["envelope_id"]), snapshot_id=str(result["snapshot_id"]),
        snapshot_root=str(result["snapshot_root"]), page_digests=tuple(result["page_digests"]), page_evidence=tuple(result["page_evidence"]),
        graph_profile=graph_profile,
    )


class NcMedicaidFhirVerifier:
    def __init__(self, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> None:
        if profile != NC_MEDICAID_PROFILE:
            raise IndependentNcMedicaidFhirError("profile:downgrade")
        self.profile = profile; self.identity = profile.graph_profile.verifier_id; self.epoch = profile.graph_profile.verifier_epoch

    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        return to_verified_source_coverage(verify_bytes(adapter_bytes, profile=self.profile), profile=self.profile)


SUPPORT_SCHEMA = "mirror-ncmedicaid-fhir-support-v2"
SUPPORT_KEYS = {"schema", "profile_id", "profile_version", "source_contract_digest", "observation_time", "fetched_at", "source_status", "failure_code", "freshness", "page_count", "resource_count", "server_total_known", "server_marker_known", "zero_phi_boundary", "support_safe", "synthetic_only", "no_external_transmission_performed"}


def build_support_evidence(raw: bytes, *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> bytes:
    result = verify_bytes(raw, profile=profile)
    return _canonical({"schema": SUPPORT_SCHEMA, "profile_id": profile.source_profile_id, "profile_version": profile.version, "source_contract_digest": profile.profile_digest, "observation_time": result["observation_time"], "fetched_at": result["fetched_at"], "source_status": result["source_status"], "failure_code": result["failure_code"], "freshness": result["freshness"], "page_count": result["page_count"], "resource_count": result["resource_count"], "server_total_known": result["server_total"] is not None, "server_marker_known": result["server_last_updated"] is not None, "zero_phi_boundary": True, "support_safe": True, "synthetic_only": True, "no_external_transmission_performed": True})


def verify_support_evidence(raw: bytes) -> dict[str, object]:
    value = _parse(raw, NC_MEDICAID_PROFILE)
    if set(value) != SUPPORT_KEYS or value["schema"] != SUPPORT_SCHEMA or value["profile_id"] != NC_MEDICAID_PROFILE.source_profile_id or value["profile_version"] != NC_MEDICAID_PROFILE.version or value["source_contract_digest"] != NC_MEDICAID_PROFILE.profile_digest:
        raise IndependentNcMedicaidFhirError("support:profile")
    if value["source_status"] not in SOURCE_STATUSES or value["failure_code"] is not None and value["failure_code"] not in FAILURE_CODES:
        raise IndependentNcMedicaidFhirError("support:status")
    if value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"} or value["zero_phi_boundary"] is not True or value["support_safe"] is not True or value["synthetic_only"] is not True or value["no_external_transmission_performed"] is not True:
        raise IndependentNcMedicaidFhirError("support:boundary")
    _int(value["page_count"], "support:pages", minimum=1, maximum=NC_MEDICAID_PROFILE.transport_caps["max_pages"]); _int(value["resource_count"], "support:resources", maximum=NC_MEDICAID_PROFILE.transport_caps["max_resources"])
    _int(value["observation_time"], "support:observation"); _int(value["fetched_at"], "support:fetched", minimum=value["observation_time"])
    return {"accepted": True, "support_bytes": len(raw), "source_status": value["source_status"], "failure_code": value["failure_code"]}


__all__ = ["ENVELOPE_SCHEMA", "ENVELOPE_SCHEMA_VERSION", "IndependentNcMedicaidFhirError", "NcMedicaidFhirVerifier", "build_support_evidence", "to_verified_source_coverage", "verify_bytes", "verify_support_evidence", "_canonical", "_digest", "_raw_digest"]
