"""Independent verifier for the synthetic NC Medicaid FHIR envelope.

This module does not import the envelope producer or transport.  It reconstructs
the fixed profile binding, page chain, bounded FHIR subset, resource references,
marker rules, identities, and the observation-only graph projection from bytes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping

from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.nc_medicaid_fhir_profile import (
    ALLOWED_MEDIA_TYPE,
    ALLOWED_RESOURCE_FIELDS,
    ALLOWED_RESOURCE_TYPES,
    CLAIM_FLAGS,
    NC_MEDICAID_PROFILE,
    NcMedicaidFhirSourceProfile,
)
from app.mirror.source_admission import EvidenceMode, VerifiedSourceCoverage


class IndependentNcMedicaidFhirError(ValueError):
    """Raised when an envelope fails the independent FHIR boundary."""


ENVELOPE_KEYS = {
    "schema", "schema_version", "profile", "owner", "request", "observation_time", "fetched_at",
    "server_markers", "pages", "page_complete", "source_status", "failure_code",
    "source_completeness", "claims", "snapshot_root", "snapshot_id", "envelope_id",
}
PROFILE_KEYS = {
    "source_profile_id", "source_profile_version", "source_profile_digest", "graph_profile_version",
    "graph_profile_digest", "source_meaning", "transport_provenance", "record_authentication",
    "capability_statement_identity", "capability_statement_digest",
}
OWNER_KEYS = {"owner", "system", "base_url", "host", "fhir_version"}
REQUEST_KEYS = {"method", "url", "query_parameters", "page_parameter", "request_identity"}
MARKER_KEYS = {"total", "last_updated"}
PAGE_KEYS = {
    "sequence", "request_url", "request_identity", "response_url", "status", "media_type", "byte_length",
    "body_digest", "body_hex", "attempt_statuses", "retry_after_seconds", "bundle", "resource_digests",
    "next_url", "failure_code", "transport_error", "page_id",
}
BUNDLE_REQUIRED_KEYS = {"resourceType", "type", "id", "link", "entry"}
BUNDLE_OPTIONAL_KEYS = {"total", "meta"}
ENTRY_KEYS = {"fullUrl", "resource"}
RESOURCE_REQUIRED_KEYS = {
    "Practitioner": {"resourceType", "id", "identifier", "name", "active"},
    "PractitionerRole": {"resourceType", "id", "identifier", "active", "practitioner", "location", "code", "specialty", "network", "period", "endpoint"},
    "Location": {"resourceType", "id", "identifier", "name", "status", "address", "endpoint"},
}
RESOURCE_IDS = {
    "Practitioner": "SYNTH_NC_PRACTITIONER_001",
    "PractitionerRole": "SYNTH_NC_PRACTITIONER_ROLE_001",
    "Location": "SYNTH_NC_LOCATION_001",
}
FAILURE_CODES = {
    "wrong-host", "redirect", "rate-limit", "server-error", "timeout", "retry-exhausted", "retry-after",
    "http-status", "media-type", "schema", "noncanonical", "partial-page", "query-drift", "total-drift",
    "marker-drift", "stale", "profile-downgrade", "capability-mismatch", "forbidden-resource",
    "forbidden-field", "reference", "identifier", "period", "address", "endpoint",
}
SOURCE_STATUSES = {"COMPLETE", "PARTIAL", "FAILED", "STALE"}
_HEX = set("0123456789abcdef")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$")
_SYSTEM = re.compile(r"^(?:urn:[A-Za-z0-9:._-]+|https://[A-Za-z0-9._:/-]+)$")
_REFERENCE = re.compile(r"^(Practitioner|Location)/[A-Za-z0-9._-]{1,64}$")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentNcMedicaidFhirError("json:noncanonical") from exc


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
    if isinstance(value, str):
        maximum = profile.transport_caps["max_page_bytes"] * 2 if key == "body_hex" else profile.transport_caps["max_string_bytes"]
        if len(value.encode("utf-8")) > maximum:
            raise IndependentNcMedicaidFhirError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentNcMedicaidFhirError("json:key-type")
            _walk(key, depth=depth + 1, count=count, profile=profile)
            _walk(item, depth=depth + 1, count=count, key=key, profile=profile)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count, profile=profile)


def _parse(raw: bytes, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > profile.transport_caps["max_envelope_bytes"]:
        raise IndependentNcMedicaidFhirError("json:byte-cap")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentNcMedicaidFhirError("json:constant")))
    except IndependentNcMedicaidFhirError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentNcMedicaidFhirError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentNcMedicaidFhirError("json:top-level")
    _walk(value, profile=profile)
    if _canonical(value) != raw:
        raise IndependentNcMedicaidFhirError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentNcMedicaidFhirError(f"{label}:keys")
    return value


def _subset(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not set(value).issubset(keys):
        raise IndependentNcMedicaidFhirError(f"{label}:forbidden-field")
    return value


def _text(value: object, label: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise IndependentNcMedicaidFhirError(f"{label}:text")
    return value


def _int(value: object, label: str, *, minimum: int = 0, maximum: int = 2_147_483_647) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentNcMedicaidFhirError(f"{label}:integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise IndependentNcMedicaidFhirError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(character not in _HEX for character in value):
        raise IndependentNcMedicaidFhirError(f"{label}:hex")
    return value


def _profile_binding(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    binding = _expect(value, PROFILE_KEYS, "profile")
    if binding != profile.binding():
        raise IndependentNcMedicaidFhirError("profile:binding")
    _text(binding["source_profile_id"], "profile:id")
    _int(binding["source_profile_version"], "profile:version", minimum=1)
    _hex(binding["source_profile_digest"], "profile:digest")
    _int(binding["graph_profile_version"], "profile:graph-version", minimum=2)
    _hex(binding["graph_profile_digest"], "profile:graph-digest")
    _text(binding["capability_statement_identity"], "profile:capability-id")
    if binding["capability_statement_digest"] is not None:
        _hex(binding["capability_statement_digest"], "profile:capability-digest")
    return binding


def _validate_request(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    request = _expect(value, REQUEST_KEYS, "request")
    if (
        request["method"] != "GET"
        or request["url"] != profile.request_url
        or request["query_parameters"] != [list(item) for item in profile.query_parameters]
        or request["page_parameter"] != profile.page_parameter
        or request["request_identity"] != _digest(
            "request",
            {"method": "GET", "url": profile.request_url, "query_parameters": [list(item) for item in profile.query_parameters], "page_parameter": profile.page_parameter},
        )
    ):
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
        raise IndependentNcMedicaidFhirError(f"{label}:format")
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IndependentNcMedicaidFhirError(f"{label}:format") from exc
    return text


def _validate_identifier_list(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= NC_MEDICAID_PROFILE.transport_caps["max_identifiers"]:
        raise IndependentNcMedicaidFhirError(f"{label}:count")
    result: list[dict[str, object]] = []
    for item in value:
        identifier = _expect(item, {"system", "value"}, label + ".item")
        system = _text(identifier["system"], label + ".system")
        if _SYSTEM.fullmatch(system) is None:
            raise IndependentNcMedicaidFhirError(f"{label}:system")
        _text(identifier["value"], label + ".value")
        result.append(identifier)
    return result


def _validate_name(value: object) -> None:
    if not isinstance(value, list) or len(value) != 1:
        raise IndependentNcMedicaidFhirError("resource:name")
    name = _expect(value[0], {"use", "family", "given"}, "resource:name")
    if name["use"] not in {"official", "usual"}:
        raise IndependentNcMedicaidFhirError("resource:name-use")
    _text(name["family"], "resource:name-family")
    if not isinstance(name["given"], list) or not 1 <= len(name["given"]) <= 2:
        raise IndependentNcMedicaidFhirError("resource:name-given")
    for given in name["given"]:
        _text(given, "resource:name-given")


def _validate_codeable(value: object, label: str) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 4:
        raise IndependentNcMedicaidFhirError(f"{label}:count")
    for item in value:
        concept = _expect(item, {"coding", "text"}, label)
        _text(concept["text"], label + ".text")
        coding = concept["coding"]
        if not isinstance(coding, list) or not 1 <= len(coding) <= 4:
            raise IndependentNcMedicaidFhirError(f"{label}:coding")
        for code in coding:
            coding_item = _expect(code, {"system", "code", "display"}, label + ".coding")
            _text(coding_item["system"], label + ".coding-system")
            _text(coding_item["code"], label + ".coding-code")
            _text(coding_item["display"], label + ".coding-display")


def _validate_reference(value: object, label: str, expected_type: str) -> str:
    reference = _expect(value, {"reference"}, label)
    result = _text(reference["reference"], label + ".reference")
    if result != expected_type + "/" + RESOURCE_IDS[expected_type] or _REFERENCE.fullmatch(result) is None:
        raise IndependentNcMedicaidFhirError(f"{label}:reference")
    return result


def _validate_reference_list(value: object, label: str) -> None:
    if not isinstance(value, list):
        raise IndependentNcMedicaidFhirError(f"{label}:list")
    if value:
        raise IndependentNcMedicaidFhirError(f"{label}:unlinked")


def _validate_period(value: object) -> None:
    period = _expect(value, {"start", "end"}, "resource:period")
    start = _validate_date(period["start"], "resource:period-start")
    end = _validate_date(period["end"], "resource:period-end")
    if start > end:
        raise IndependentNcMedicaidFhirError("resource:period-order")


def _validate_address(value: object) -> None:
    address = _expect(value, {"use", "line", "city", "state", "postalCode", "country"}, "resource:address")
    if address["use"] not in {"work", "home"}:
        raise IndependentNcMedicaidFhirError("resource:address-use")
    line = address["line"]
    if not isinstance(line, list) or not 1 <= len(line) <= 3:
        raise IndependentNcMedicaidFhirError("resource:address-line")
    for item in line:
        _text(item, "resource:address-line")
    for key in ("city", "state", "postalCode", "country"):
        _text(address[key], "resource:address-" + key)


def _validate_resource(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IndependentNcMedicaidFhirError("resource:shape")
    resource_type = value.get("resourceType")
    if resource_type not in profile.allowed_resource_types:
        raise IndependentNcMedicaidFhirError("resource:forbidden-resource")
    allowed = dict(profile.allowed_resource_fields)[str(resource_type)]
    resource = _subset(value, set(allowed), "resource")
    required = RESOURCE_REQUIRED_KEYS[str(resource_type)]
    if not required.issubset(resource):
        raise IndependentNcMedicaidFhirError("resource:missing-field")
    _text(resource["id"], "resource:id", maximum=64)
    if resource["id"] != RESOURCE_IDS[str(resource_type)]:
        raise IndependentNcMedicaidFhirError("resource:id")
    if resource_type == "Practitioner":
        _validate_identifier_list(resource["identifier"], "practitioner:identifier")
        _validate_name(resource["name"])
        _bool(resource["active"], "practitioner:active")
    elif resource_type == "PractitionerRole":
        _validate_identifier_list(resource["identifier"], "role:identifier")
        _bool(resource["active"], "role:active")
        _validate_reference(resource["practitioner"], "role:practitioner", "Practitioner")
        locations = resource["location"]
        if not isinstance(locations, list) or len(locations) != 1:
            raise IndependentNcMedicaidFhirError("role:location-count")
        _validate_reference(locations[0], "role:location", "Location")
        _validate_codeable(resource["code"], "role:code")
        _validate_codeable(resource["specialty"], "role:specialty")
        _validate_reference_list(resource["network"], "role:network")
        _validate_period(resource["period"])
        _validate_reference_list(resource["endpoint"], "role:endpoint")
    else:
        _validate_identifier_list(resource["identifier"], "location:identifier")
        _text(resource["name"], "location:name")
        if resource["status"] not in {"active", "inactive", "suspended"}:
            raise IndependentNcMedicaidFhirError("location:status")
        _validate_address(resource["address"])
        _validate_reference_list(resource["endpoint"], "location:endpoint")
    return resource


def _validate_bundle(bundle: object, profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str) -> tuple[list[dict[str, object]], str | None, int | None, str | None]:
    if not isinstance(bundle, dict) or not set(bundle).issubset(BUNDLE_REQUIRED_KEYS | BUNDLE_OPTIONAL_KEYS) or not BUNDLE_REQUIRED_KEYS.issubset(bundle):
        raise IndependentNcMedicaidFhirError("bundle:keys")
    if bundle["resourceType"] != "Bundle" or bundle["type"] != "searchset":
        raise IndependentNcMedicaidFhirError("bundle:type")
    _text(bundle["id"], "bundle:id", maximum=64)
    links = bundle["link"]
    if not isinstance(links, list) or not 1 <= len(links) <= 2:
        raise IndependentNcMedicaidFhirError("bundle:links")
    link_relations: set[str] = set()
    next_url: str | None = None
    for link_value in links:
        link = _expect(link_value, {"relation", "url"}, "bundle:link")
        relation = _text(link["relation"], "bundle:relation")
        if relation in link_relations or relation not in {"self", "next"}:
            raise IndependentNcMedicaidFhirError("bundle:link-relation")
        link_relations.add(relation)
        url = _text(link["url"], "bundle:url")
        if relation == "self" and url != request_url:
            raise IndependentNcMedicaidFhirError("bundle:self-url")
        if relation == "next":
            next_url = url
    if "self" not in link_relations:
        raise IndependentNcMedicaidFhirError("bundle:self-link")
    if next_url is not None and (sequence + 1 >= profile.transport_caps["max_pages"] or next_url != profile.page_url(sequence + 1)):
        raise IndependentNcMedicaidFhirError("bundle:query-drift")
    total = bundle.get("total")
    if total is not None:
        _int(total, "bundle:total", maximum=profile.transport_caps["max_resources"])
    meta = bundle.get("meta")
    last_updated = None
    if meta is not None:
        metadata = _expect(meta, {"lastUpdated"}, "bundle:meta")
        last_updated = _validate_date(metadata["lastUpdated"], "bundle:last-updated")
    entries = bundle["entry"]
    if not isinstance(entries, list):
        raise IndependentNcMedicaidFhirError("bundle:entry-count")
    resources: list[dict[str, object]] = []
    for entry_value in entries:
        entry = _expect(entry_value, ENTRY_KEYS, "bundle:entry")
        resource = _validate_resource(entry["resource"], profile)
        full_url = _text(entry["fullUrl"], "bundle:full-url")
        expected_full_url = profile.base_url + "/" + str(resource["resourceType"]) + "/" + str(resource["id"])
        if full_url != expected_full_url:
            raise IndependentNcMedicaidFhirError("bundle:full-url")
        resources.append(resource)
    return resources, next_url, total, last_updated


def _validate_page(value: object, profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str) -> tuple[list[dict[str, object]], str | None, int | None, str | None]:
    page = _expect(value, PAGE_KEYS, "page")
    if page["sequence"] != sequence or page["request_url"] != request_url or page["request_identity"] != _digest("request", {"method": "GET", "url": request_url, "query_parameters": [list(item) for item in profile.query_parameters], "page_parameter": profile.page_parameter}):
        raise IndependentNcMedicaidFhirError("page:request")
    _int(page["status"], "page:status", maximum=599)
    if page["media_type"] is not None:
        _text(page["media_type"], "page:media-type")
    _int(page["byte_length"], "page:byte-length", maximum=profile.transport_caps["max_page_bytes"])
    _hex(page["body_digest"], "page:body-digest")
    attempts = page["attempt_statuses"]
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= profile.transport_caps["max_retries"] + 1:
        raise IndependentNcMedicaidFhirError("page:attempts")
    for attempt_status in attempts:
        _int(attempt_status, "page:attempt-status", maximum=599)
    if attempts[-1] != page["status"]:
        raise IndependentNcMedicaidFhirError("page:attempt-final")
    retry_after = page["retry_after_seconds"]
    if not isinstance(retry_after, list) or len(retry_after) != len(attempts):
        raise IndependentNcMedicaidFhirError("page:retry-after")
    for seconds in retry_after:
        if seconds is not None:
            _int(seconds, "page:retry-after", maximum=profile.transport_caps["max_retry_after_seconds"])
    failure_code = page["failure_code"]
    if failure_code is not None and type(failure_code) is not str:
        raise IndependentNcMedicaidFhirError("page:failure-code")
    if failure_code is not None and failure_code not in FAILURE_CODES:
        raise IndependentNcMedicaidFhirError("page:failure-code")
    if page["transport_error"] is not None:
        _text(page["transport_error"], "page:transport-error")
    if page["response_url"] is not None:
        _text(page["response_url"], "page:response-url")
    if failure_code is None and page["response_url"] != request_url:
        raise IndependentNcMedicaidFhirError("page:response-url")
    if page["response_url"] is not None and page["response_url"] != request_url and failure_code != "wrong-host":
        raise IndependentNcMedicaidFhirError("page:response-url")
    bundle = page["bundle"]
    body_hex = page["body_hex"]
    if failure_code is None:
        if page["status"] != 200 or page["media_type"] != ALLOWED_MEDIA_TYPE or not isinstance(bundle, dict) or body_hex is not None:
            raise IndependentNcMedicaidFhirError("page:success-shape")
        resources, next_url, total, last_updated = _validate_bundle(bundle, profile, sequence, request_url)
        body = _canonical(bundle)
        if page["byte_length"] != len(body) or page["body_digest"] != _raw_digest("page-bytes", body):
            raise IndependentNcMedicaidFhirError("page:body-binding")
        digests = [_digest("resource", resource) for resource in resources]
        if page["resource_digests"] != digests:
            raise IndependentNcMedicaidFhirError("page:resource-binding")
    else:
        resources, next_url, total, last_updated = [], None, None, None
        if bundle is not None:
            raise IndependentNcMedicaidFhirError("page:failure-bundle")
        if type(body_hex) is not str or len(body_hex) > profile.transport_caps["max_page_bytes"] * 2 or any(character not in _HEX for character in body_hex):
            raise IndependentNcMedicaidFhirError("page:failure-body")
        try:
            body = bytes.fromhex(body_hex)
        except ValueError as exc:
            raise IndependentNcMedicaidFhirError("page:failure-body") from exc
        if len(body) != page["byte_length"] or page["body_digest"] != _raw_digest("page-bytes", body):
            raise IndependentNcMedicaidFhirError("page:failure-body-binding")
        if page["resource_digests"] != [] or page["next_url"] is not None:
            raise IndependentNcMedicaidFhirError("page:failure-fields")
    if page["next_url"] != next_url:
        raise IndependentNcMedicaidFhirError("page:next-binding")
    expected_page_id = _digest("page-id", {key: value for key, value in page.items() if key != "page_id"})
    if page["page_id"] != expected_page_id:
        raise IndependentNcMedicaidFhirError("page:id")
    _hex(page["page_id"], "page:id")
    return resources, next_url, total, last_updated


def _validate_resource_graph(resources: list[dict[str, object]], profile: NcMedicaidFhirSourceProfile, *, complete: bool) -> tuple[int, dict[str, int]]:
    seen: set[tuple[str, str]] = set()
    identifiers: dict[str, str] = {}
    for resource in resources:
        key = (str(resource["resourceType"]), str(resource["id"]))
        if key in seen:
            raise IndependentNcMedicaidFhirError("resource:duplicate")
        seen.add(key)
        for identifier in resource["identifier"]:  # type: ignore[union-attr]
            system = str(identifier["system"])
            value = str(identifier["value"])
            previous = identifiers.get(system)
            if previous == value:
                raise IndependentNcMedicaidFhirError("identifier:duplicate")
            if previous is not None and previous != value:
                raise IndependentNcMedicaidFhirError("identifier:conflict")
            identifiers[system] = value
    if len(resources) > profile.transport_caps["max_resources"]:
        raise IndependentNcMedicaidFhirError("resource:count")
    counts = {resource_type: sum(1 for resource in resources if resource["resourceType"] == resource_type) for resource_type in profile.allowed_resource_types}
    expected_counts = dict(profile.resource_cardinality)
    if complete and counts != expected_counts:
        raise IndependentNcMedicaidFhirError("resource:cardinality")
    practitioner = next((resource for resource in resources if resource["resourceType"] == "Practitioner"), None)
    role = next((resource for resource in resources if resource["resourceType"] == "PractitionerRole"), None)
    location = next((resource for resource in resources if resource["resourceType"] == "Location"), None)
    if role is not None:
        practitioner_reference = str(role["practitioner"]["reference"])  # type: ignore[index]
        location_reference = str(role["location"][0]["reference"])  # type: ignore[index]
        if practitioner is None or practitioner_reference != "Practitioner/" + str(practitioner["id"]):
            if complete:
                raise IndependentNcMedicaidFhirError("reference:practitioner")
        if location is None or location_reference != "Location/" + str(location["id"]):
            if complete:
                raise IndependentNcMedicaidFhirError("reference:location")
    if complete and (practitioner is None or role is None or location is None):
        raise IndependentNcMedicaidFhirError("reference:missing")
    return len(resources), counts


def _validate_markers(value: object, profile: NcMedicaidFhirSourceProfile) -> dict[str, object]:
    markers = _expect(value, MARKER_KEYS, "markers")
    if markers["total"] is not None:
        _int(markers["total"], "markers:total", maximum=profile.transport_caps["max_resources"])
    if markers["last_updated"] is not None:
        _validate_date(markers["last_updated"], "markers:last-updated")
    return markers


def _freshness(profile: NcMedicaidFhirSourceProfile, marker: str | None) -> str:
    if marker is None:
        return "UNKNOWN"
    try:
        fetched = datetime.fromisoformat(profile.fetched_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        updated = datetime.fromisoformat(marker.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise IndependentNcMedicaidFhirError("markers:last-updated") from exc
    age = (fetched - updated).days
    if age < 0 or age > profile.max_server_marker_age_days:
        return "STALE"
    return "FRESH"


def _graph_source(profile, role_index: int, observation_time: int, *, complete: bool, record_id: str) -> dict[str, object]:
    role = profile.source_role_details[role_index]
    record_kind = role.record_kind
    record = {
        "record_id": record_id,
        "record_kind": record_kind,
        "provider_id": profile.subject,
        "credential_id": profile.credential_id,
        "enrollment_id": profile.enrollment_id,
        "subject_key": profile.subject + "|" + profile.credential_id + "|" + profile.enrollment_id,
        "observed_at": observation_time,
        "issued_at": profile.effective_start,
        "valid_from": profile.effective_start,
        "valid_until": profile.effective_end,
        "terminated_at": 0,
        "status": "ACTIVE",
    }
    source: dict[str, object] = {
        "source_id": role.source_id,
        "source_kind": role.source_kind,
        "coverage_scope": profile.scope,
        "coverage_observation_time": observation_time,
        "coverage_effective_start": profile.effective_start,
        "coverage_effective_end": profile.effective_end,
        "coverage_complete": complete,
        "coverage_authority_id": role.authority_id,
        "nonmembership_keys": [],
        "records": [record],
        "provenance": {"provenance_id": role.provenance_id, "integrity_digest": "0" * 128},
    }
    view = graph_independent._profile_view(profile)
    source["provenance"]["integrity_digest"] = graph_independent._integrity_digest(source, profile=view)  # type: ignore[index]
    return source


def _graph_input(profile: NcMedicaidFhirSourceProfile, observation_time: int) -> bytes:
    graph_profile = profile.graph_profile
    value = {
        "schema": "mirror-provider-trust-graph-input-v2",
        "profile_id": graph_profile.profile_id,
        "profile_version": graph_profile.version,
        "profile_digest": graph_profile.profile_digest,
        "provider_graph_subject": graph_profile.subject,
        "scope": graph_profile.scope,
        "observation_time": observation_time,
        "sources": [
            _graph_source(graph_profile, 0, observation_time, complete=False, record_id="SYNTH_CREDENTIAL_RECORD_001"),
            _graph_source(graph_profile, 1, observation_time, complete=False, record_id="SYNTH_ENROLLMENT_RECORD_001"),
        ],
        "prior_artifact": None,
        "remediation": None,
        "parity_cases": [],
    }
    return _canonical(value)


def verify_bytes(raw: bytes, *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> dict[str, object]:
    """Independently verify one envelope, including explicit negative status evidence."""

    if not isinstance(profile, NcMedicaidFhirSourceProfile) or profile != NC_MEDICAID_PROFILE:
        raise IndependentNcMedicaidFhirError("profile:downgrade")
    value = _parse(raw, profile)
    if set(value) != ENVELOPE_KEYS or value["schema"] != "mirror-ncmedicaid-fhir-observation-envelope-v1" or value["schema_version"] != 1:
        raise IndependentNcMedicaidFhirError("envelope:schema")
    _profile_binding(value["profile"], profile)
    _validate_owner(value["owner"], profile)
    _validate_request(value["request"], profile)
    if value["observation_time"] != profile.observation_time or value["fetched_at"] != profile.fetched_at:
        raise IndependentNcMedicaidFhirError("snapshot:profile-time")
    observation_time = _int(value["observation_time"], "snapshot:observation-time", minimum=1)
    markers = _validate_markers(value["server_markers"], profile)
    pages = value["pages"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= profile.transport_caps["max_pages"]:
        raise IndependentNcMedicaidFhirError("pages:count")
    source_status = value["source_status"]
    if type(source_status) is not str or source_status not in SOURCE_STATUSES:
        raise IndependentNcMedicaidFhirError("snapshot:status")
    failure_code = value["failure_code"]
    if failure_code is not None and type(failure_code) is not str:
        raise IndependentNcMedicaidFhirError("snapshot:failure-code")
    if failure_code is not None and failure_code not in FAILURE_CODES:
        raise IndependentNcMedicaidFhirError("snapshot:failure-code")
    if value["source_completeness"] != "UNKNOWN" or value["claims"] != CLAIM_FLAGS:
        raise IndependentNcMedicaidFhirError("snapshot:claims")
    if value["page_complete"] is not (source_status == "COMPLETE"):
        raise IndependentNcMedicaidFhirError("snapshot:complete-flag")
    for expected_sequence, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("sequence") != expected_sequence:
            raise IndependentNcMedicaidFhirError("page:request")
    resources: list[dict[str, object]] = []
    totals: list[int | None] = []
    last_updated: list[str | None] = []
    for sequence, page in enumerate(pages):
        request_url = profile.page_url(sequence)
        page_resources, next_url, total, marker = _validate_page(page, profile, sequence, request_url)
        resources.extend(page_resources)
        totals.append(total)
        last_updated.append(marker)
        if page.get("failure_code") is not None and sequence != len(pages) - 1:
            raise IndependentNcMedicaidFhirError("pages:after-failure")
        if next_url is None and sequence != len(pages) - 1:
            raise IndependentNcMedicaidFhirError("pages:omission")
        if next_url is not None and sequence == len(pages) - 1 and source_status == "COMPLETE":
            raise IndependentNcMedicaidFhirError("pages:partial")
    if pages[-1].get("failure_code") is not None and source_status == "COMPLETE":
        raise IndependentNcMedicaidFhirError("snapshot:failed-complete")
    successful_totals = [total for page, total in zip(pages, totals) if page.get("failure_code") is None]
    successful_markers = [marker for page, marker in zip(pages, last_updated) if page.get("failure_code") is None]
    total_values = {value for value in successful_totals if value is not None}
    marker_values = {value for value in successful_markers if value is not None}
    total_present = sum(value is not None for value in successful_totals)
    marker_present = sum(value is not None for value in successful_markers)
    marker_drift = len(total_values) > 1 or (total_values and total_present != len(successful_totals)) or len(marker_values) > 1 or (marker_values and marker_present != len(successful_markers))
    if marker_drift and failure_code not in {"total-drift", "marker-drift"}:
        raise IndependentNcMedicaidFhirError("markers:drift")
    expected_total = next(iter(total_values)) if len(total_values) == 1 and total_present == len(successful_totals) else None
    expected_marker = next(iter(marker_values)) if len(marker_values) == 1 and marker_present == len(successful_markers) else None
    if markers != {"total": expected_total, "last_updated": expected_marker} and failure_code not in {"total-drift", "marker-drift"}:
        raise IndependentNcMedicaidFhirError("markers:binding")
    freshness = _freshness(profile, expected_marker)
    if freshness == "STALE" and failure_code != "stale":
        raise IndependentNcMedicaidFhirError("snapshot:stale")
    if freshness != "STALE" and failure_code == "stale":
        raise IndependentNcMedicaidFhirError("snapshot:stale-binding")
    complete = source_status == "COMPLETE" and failure_code is None
    resource_count, counts = _validate_resource_graph(resources, profile, complete=complete)
    snapshot_root = _digest("snapshot-root", {"page_ids": [page["page_id"] for page in pages]})
    if value["snapshot_root"] != snapshot_root or value["snapshot_id"] != _digest(
        "snapshot-id",
        {
            "profile": profile.binding(),
            "request_identity": _digest("request", {"method": "GET", "url": profile.request_url, "query_parameters": [list(item) for item in profile.query_parameters], "page_parameter": profile.page_parameter}),
            "observation_time": observation_time,
            "fetched_at": profile.fetched_at,
            "snapshot_root": snapshot_root,
            "source_status": source_status,
            "failure_code": failure_code,
            "server_markers": markers,
        },
    ):
        raise IndependentNcMedicaidFhirError("snapshot:identity")
    _hex(value["snapshot_root"], "snapshot:root")
    _hex(value["snapshot_id"], "snapshot:id")
    body_without_id = dict(value)
    body_without_id.pop("envelope_id")
    if value["envelope_id"] != _digest("envelope-id", body_without_id):
        raise IndependentNcMedicaidFhirError("envelope:identity")
    _hex(value["envelope_id"], "envelope:id")
    return {
        "accepted": True,
        "envelope_bytes": len(raw),
        "envelope_id": value["envelope_id"],
        "source_profile_id": profile.source_profile_id,
        "source_profile_version": profile.version,
        "source_profile_digest": profile.profile_digest,
        "graph_profile_digest": profile.graph_profile.profile_digest,
        "observation_time": observation_time,
        "fetched_at": profile.fetched_at,
        "source_status": source_status,
        "page_complete": value["page_complete"],
        "failure_code": failure_code,
        "freshness": freshness,
        "server_total": expected_total,
        "server_last_updated": expected_marker,
        "page_count": len(pages),
        "resource_count": resource_count,
        "resource_counts": counts,
        "resources": resources,
        "snapshot_id": value["snapshot_id"],
    }


def to_verified_source_coverage(result: Mapping[str, object], *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> VerifiedSourceCoverage:
    if result.get("accepted") is not True or result.get("source_status") != "COMPLETE" or result.get("page_complete") is not True:
        code = result.get("failure_code") or result.get("source_status") or "partial"
        raise IndependentNcMedicaidFhirError("source:" + str(code).lower())
    if result.get("freshness") not in {"FRESH", "UNKNOWN"}:
        raise IndependentNcMedicaidFhirError("source:stale")
    graph_profile = profile.graph_profile
    graph_input = _graph_input(profile, profile.observation_time)
    return VerifiedSourceCoverage(
        profile_id=graph_profile.profile_id,
        subject=graph_profile.subject,
        scope=graph_profile.scope,
        observation_time=profile.observation_time,
        effective_start=graph_profile.effective_start,
        effective_end=graph_profile.effective_end,
        complete=False,
        source_roles=graph_profile.source_roles,
        evidence_mode=EvidenceMode.OBSERVATION_ONLY,
        graph_input=graph_input,
    )


class NcMedicaidFhirVerifier:
    """Configured SourceVerifier implementation for synthetic fixture bytes."""

    def __init__(self, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> None:
        if profile != NC_MEDICAID_PROFILE:
            raise IndependentNcMedicaidFhirError("profile:downgrade")
        self.profile = profile
        self.identity = profile.graph_profile.verifier_id
        self.epoch = profile.graph_profile.verifier_epoch

    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        result = verify_bytes(adapter_bytes, profile=self.profile)
        return to_verified_source_coverage(result, profile=self.profile)


SUPPORT_SCHEMA = "mirror-ncmedicaid-fhir-support-v1"
SUPPORT_KEYS = {
    "schema", "profile_id", "profile_version", "fetched_at", "source_status", "failure_code", "freshness",
    "page_count", "resource_count", "server_total_known", "server_marker_known", "zero_phi_boundary",
    "support_safe", "synthetic_only", "no_external_transmission_performed",
}


def build_support_evidence(raw: bytes, *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE) -> bytes:
    result = verify_bytes(raw, profile=profile)
    value = {
        "schema": SUPPORT_SCHEMA,
        "profile_id": profile.source_profile_id,
        "profile_version": profile.version,
        "fetched_at": profile.fetched_at,
        "source_status": result["source_status"],
        "failure_code": result["failure_code"],
        "freshness": result["freshness"],
        "page_count": result["page_count"],
        "resource_count": result["resource_count"],
        "server_total_known": result["server_total"] is not None,
        "server_marker_known": result["server_last_updated"] is not None,
        "zero_phi_boundary": True,
        "support_safe": True,
        "synthetic_only": True,
        "no_external_transmission_performed": True,
    }
    return _canonical(value)


def verify_support_evidence(raw: bytes) -> dict[str, object]:
    value = _parse(raw, NC_MEDICAID_PROFILE)
    if set(value) != SUPPORT_KEYS or value["schema"] != SUPPORT_SCHEMA:
        raise IndependentNcMedicaidFhirError("support:keys")
    if value["profile_id"] != NC_MEDICAID_PROFILE.source_profile_id or value["profile_version"] != NC_MEDICAID_PROFILE.version or value["fetched_at"] != NC_MEDICAID_PROFILE.fetched_at:
        raise IndependentNcMedicaidFhirError("support:profile")
    if type(value["source_status"]) is not str or value["source_status"] not in SOURCE_STATUSES or value["failure_code"] is not None and (type(value["failure_code"]) is not str or value["failure_code"] not in FAILURE_CODES):
        raise IndependentNcMedicaidFhirError("support:status")
    if value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"}:
        raise IndependentNcMedicaidFhirError("support:freshness")
    _int(value["page_count"], "support:pages", minimum=1, maximum=NC_MEDICAID_PROFILE.transport_caps["max_pages"])
    _int(value["resource_count"], "support:resources", maximum=NC_MEDICAID_PROFILE.transport_caps["max_resources"])
    _bool(value["server_total_known"], "support:total")
    _bool(value["server_marker_known"], "support:marker")
    if value["zero_phi_boundary"] is not True or value["support_safe"] is not True or value["synthetic_only"] is not True or value["no_external_transmission_performed"] is not True:
        raise IndependentNcMedicaidFhirError("support:boundary")
    return {"accepted": True, "support_bytes": len(raw), "source_status": value["source_status"], "failure_code": value["failure_code"]}


__all__ = [
    "IndependentNcMedicaidFhirError",
    "NcMedicaidFhirVerifier",
    "build_support_evidence",
    "to_verified_source_coverage",
    "verify_bytes",
    "verify_support_evidence",
]
