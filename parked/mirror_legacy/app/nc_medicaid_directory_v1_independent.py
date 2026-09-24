"""Independent verifier for the bounded NC directory observation capture.

This module deliberately does not import the adapter or any producer
validation/aggregation helper.  It reparses the canonical transient capture,
reconstructs the FHIR request chain and resource joins, and returns only an
aggregate safe for the in-memory admission boundary.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit

from app.mirror.error_boundary import raise_redacted
from parked.mirror_legacy.app.nc_medicaid_directory_profile_v1 import (
    ALLOWED_MEDIA_TYPE,
    CONTINUATION_PARAMETER_NAMES,
    DirectoryOperationContext,
    FORBIDDEN_QUERY_PARAMETERS,
    NC_MEDICAID_DIRECTORY_PROFILE_V1,
    NcMedicaidDirectoryProfileV1,
)


CAPTURE_SCHEMA = "mirror-ncmedicaid-provider-directory-capture-v1"
CAPTURE_SCHEMA_VERSION = 1
OBSERVATION_SCHEMA = "mirror-ncmedicaid-provider-directory-observation-result-v1"
OBSERVATION_SCHEMA_VERSION = 1
RECEIPT_SCHEMA = "mirror-ncmedicaid-provider-directory-verification-receipt-v1"
RECEIPT_SCHEMA_VERSION = 1
OPERATION_BINDING_DOMAIN = b"BL/MIRROR/NC-MEDICAID/DIRECTORY/OPERATION/v1\0"
OBSERVATION_DIGEST_DOMAIN = b"BL/MIRROR/NC-MEDICAID/DIRECTORY/SANITIZED/v1\0"
VERIFIER_ID = "NC_MEDICAID_DIRECTORY_OBSERVATION_VERIFIER_V1"
VERIFIER_EPOCH = 1

FAILURE_CODES = frozenset(
    {
        "adapter-rejected",
        "active",
        "binding",
        "body-type",
        "bundle",
        "bundle-entry",
        "bundle-links",
        "bundle-type",
        "capture-cap",
        "capture-json",
        "capture-shape",
        "context",
        "duplicate-key",
        "duplicate-resource",
        "full-url",
        "http-status",
        "json-constant",
        "json-integer-cap",
        "json-parse",
        "json-shape",
        "json-string-cap",
        "json-walk-cap",
        "location-id",
        "location-mismatch",
        "media-type",
        "meta",
        "missing-operation",
        "modifier-field",
        "next-link",
        "operation",
        "operation-order",
        "page-cap",
        "period",
        "practitioner-mismatch",
        "practitioner-not-found",
        "profile",
        "reference",
        "reference-identity",
        "request-cap",
        "resource",
        "resource-cap",
        "resource-field",
        "resource-id",
        "resource-release",
        "resource-type",
        "response",
        "response-cap",
        "response-total-cap",
        "retry-after",
        "retry-exhausted",
        "rate-limit",
        "redirect",
        "sanitized",
        "search-next",
        "search-self",
        "search-mode",
        "search-total",
        "searchset",
        "timeout",
        "total-drift",
        "total-incomplete",
        "transport",
        "unexpected-operation",
        "unsupported-include",
        "url",
        "wrong-host",
        "server-error",
    }
)
TRANSPORT_FAILURES = frozenset(
    {
        "http-status",
        "media-type",
        "redirect",
        "rate-limit",
        "server-error",
        "timeout",
        "transport",
        "retry-exhausted",
        "retry-after",
        "resource-release",
        "response-cap",
        "response-total-cap",
        "request-cap",
        "page-cap",
        "resource-cap",
    }
)
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]{128}$")
_MAX_SIGNED_INT = 2**63 - 1
_DATE_PATTERN = re.compile(
    r"^(?:\d{4}(?:-\d{2}(?:-\d{2})?)?|\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))$"
)
_INSTANT_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_LOCATION_STATUS_VALUES = frozenset({"active", "suspended", "inactive"})


class DirectoryIndependentError(ValueError):
    """Stable public independent-verifier failure."""


class _Reject(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


@dataclass(frozen=True)
class VerifiedDirectoryAggregate:
    """Safe aggregate returned by the independent verifier."""

    profile_id: str
    profile_version: int
    source_contract_digest: str
    verifier_id: str
    verifier_epoch: int
    accepted: bool
    failure_code: str | None
    source_status: str
    traversal_status: str
    capture_age: str
    source_freshness: str
    dataset_completeness: str
    observation_time: int
    fetched_at: int
    practitioner_count: int
    role_count: int
    location_count: int
    search_page_count: int
    location_read_count: int
    request_count: int
    response_count: int
    retry_count: int
    ignored_field_count: int
    ignored_field_reasons: tuple[tuple[str, int], ...]

    @property
    def resource_count(self) -> int:
        return (
            self.practitioner_count
            + self.role_count
            + self.location_count
        )


@dataclass
class _ResourceRecord:
    resource_id: str
    full_url: str
    practitioner_id: str | None = None
    location_ids: tuple[str, ...] = ()


@dataclass
class _SegmentResult:
    resources: list[_ResourceRecord]
    next_index: int
    pages: int
    response_count: int
    retry_count: int
    ignored: Counter[str]
    complete: bool
    traversal_status: str
    failure_code: str | None
    total: int | None
    boundary: bool = False


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise _Reject("capture-json") from None


def _profile_material(profile: NcMedicaidDirectoryProfileV1) -> dict[str, object]:
    """Rebuild public profile material without calling the producer digest."""

    return {
        "schema": profile.source_contract_schema,
        "schema_version": profile.source_contract_version,
        "source_profile_id": profile.source_profile_id,
        "source_profile_version": profile.source_profile_version,
        "owner": profile.owner,
        "system": profile.system,
        "base_url": profile.base_url,
        "host": profile.host,
        "fhir_version": profile.fhir_version,
        "allowed_media_type": profile.allowed_media_type,
        "source_meaning": profile.source_meaning,
        "transport_provenance": profile.transport_provenance,
        "record_authentication": profile.record_authentication,
        "capability_statement_identity": profile.capability_statement_identity,
        "capability_statement_digest": profile.capability_statement_digest,
        "capability_statement_date": profile.capability_statement_date,
        "allowed_resource_types": list(profile.allowed_resource_types),
        "documented_interactions": {
            key: list(value) for key, value in profile.documented_interactions
        },
        "documented_search_parameters": {
            key: {name: kind for name, kind in value}
            for key, value in profile.documented_search_parameters
        },
        "selected_resource_fields": {
            key: list(value) for key, value in profile.selected_resource_fields
        },
        "continuation_parameter_names": list(
            profile.continuation_parameter_names
        ),
        "forbidden_query_parameters": list(profile.forbidden_query_parameters),
        "transport_caps": dict(profile.transport_caps),
        "flags": dict(profile.flags),
        "synthetic_only": profile.synthetic_only,
        "production_usable": profile.production_usable,
        "verifier_id": VERIFIER_ID,
        "verifier_epoch": VERIFIER_EPOCH,
    }


def _profile_digest(profile: NcMedicaidDirectoryProfileV1) -> str:
    digest = hashlib.sha3_512()
    digest.update(
        b"BL/MIRROR/NC-MEDICAID/DIRECTORY/source-contract/v1\0"
    )
    digest.update(_canonical(_profile_material(profile)))
    return digest.hexdigest()


def _digest(domain: bytes, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(domain)
    digest.update(raw)
    return digest.hexdigest()


def _operation_binding(operation_ref: str) -> str:
    return _digest(OPERATION_BINDING_DOMAIN, operation_ref.encode("ascii"))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _Reject("json-parse")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise _Reject("json-constant")


def _walk_bounded(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    depth: int = 0,
    count: list[int] | None = None,
) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > profile.transport_caps["max_total_nodes"]:
        raise _Reject("json-walk-cap")
    if depth > profile.transport_caps["max_depth"]:
        raise _Reject("json-walk-cap")
    if isinstance(value, float):
        raise _Reject("json-constant")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -(2**63) or value > 2**63 - 1:
            raise _Reject("json-integer-cap")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
            raise _Reject("json-string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _Reject("capture-shape")
            _walk_bounded(key, profile, depth=depth + 1, count=count)
            _walk_bounded(item, profile, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk_bounded(item, profile, depth=depth + 1, count=count)
    elif value is not None and not isinstance(value, (bool, int)):
        raise _Reject("capture-shape")


def _parse_capture(
    raw: object,
    profile: NcMedicaidDirectoryProfileV1,
) -> dict[str, object]:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > profile.transport_caps["max_capture_bytes"]
    ):
        raise _Reject("capture-cap")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _Reject:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _Reject("json-parse") from None
    if not isinstance(value, dict):
        raise _Reject("capture-shape")
    _walk_bounded(value, profile)
    try:
        canonical = _canonical(value)
    except _Reject:
        raise
    if canonical != raw:
        raise _Reject("capture-json")
    expected = {
        "schema",
        "schema_version",
        "profile",
        "operation",
        "operations",
        "capture_failure",
    }
    if set(value) != expected:
        raise _Reject("capture-shape")
    if value["schema"] != CAPTURE_SCHEMA or value["schema_version"] != CAPTURE_SCHEMA_VERSION:
        raise _Reject("capture-shape")
    if not isinstance(value["profile"], dict) or not isinstance(
        value["operation"], dict
    ):
        raise _Reject("capture-shape")
    if not isinstance(value["operations"], list):
        raise _Reject("capture-shape")
    if len(value["operations"]) > profile.transport_caps["max_requests"] + 1:
        raise _Reject("request-cap")
    if len(value["operations"]) == profile.transport_caps["max_requests"] + 1:
        terminal = value["operations"][-1]
        if not isinstance(terminal, dict) or terminal.get("failure_code") not in {
            "request-cap",
            "page-cap",
            "resource-cap",
        }:
            raise _Reject("request-cap")
    failure = value["capture_failure"]
    if failure is not None:
        if type(failure) is not str or failure not in FAILURE_CODES:
            raise _Reject("capture-shape")
        if value["operations"]:
            raise _Reject("capture-shape")
    profile_expected = {
        "source_profile_id": profile.source_profile_id,
        "source_profile_version": profile.source_profile_version,
        "source_contract_digest": _profile_digest(profile),
        "capability_statement_digest": profile.capability_statement_digest,
        "fhir_version": profile.fhir_version,
        "verifier_id": VERIFIER_ID,
        "verifier_epoch": VERIFIER_EPOCH,
    }
    if value["profile"] != profile_expected:
        raise _Reject("profile")
    return value


def _valid_id(value: object) -> bool:
    return type(value) is str and _ID_PATTERN.fullmatch(value) is not None


def _valid_location_id(value: object) -> bool:
    return _valid_id(value) and value != "." and value != ".."


def _valid_url_text(value: object, profile: NcMedicaidDirectoryProfileV1) -> bool:
    return (
        type(value) is str
        and len(value.encode("utf-8")) <= profile.transport_caps["max_url_bytes"]
    )


def _safe_query_url(
    url: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    required_filter: Mapping[str, str],
    continuation: bool,
) -> dict[str, str]:
    if not _valid_url_text(url, profile):
        raise _Reject("url")
    assert isinstance(url, str)
    if "\\" in url or "#" in url or "+" in url:
        raise _Reject("url")
    try:
        parts = urlsplit(url)
        port = parts.port
    except (ValueError, AttributeError):
        raise _Reject("url") from None
    if (
        parts.scheme != "https"
        or parts.hostname != profile.host
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or parts.path != "/fhir/" + resource_type
    ):
        raise _Reject("url")
    if any(token in parts.path.lower() for token in ("%2f", "%5c", "%2e", "%00")):
        raise _Reject("url")
    if re.search(r"%(?![0-9A-Fa-f]{2})", parts.query):
        raise _Reject("url")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except (TypeError, ValueError):
        raise _Reject("url") from None
    if not pairs or len(pairs) > 12:
        raise _Reject("url")
    query: dict[str, str] = {}
    for key, value in pairs:
        if (
            not key
            or key in query
            or len(value.encode("utf-8")) > profile.transport_caps["max_string_bytes"]
        ):
            raise _Reject("url")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in key + value):
            raise _Reject("url")
        query[key] = value
    for key in FORBIDDEN_QUERY_PARAMETERS:
        if key in query:
            raise _Reject("url")
    for key, value in required_filter.items():
        if query.get(key) != value:
            raise _Reject("search-self")
    allowed_extra = {"_count"}
    if continuation:
        allowed_extra.update(CONTINUATION_PARAMETER_NAMES)
    if any(
        key not in required_filter and key not in allowed_extra
        for key in query
    ):
        raise _Reject("url")
    if "_count" in query:
        if re.fullmatch(r"[1-9]\d{0,2}", query["_count"]) is None:
            raise _Reject("url")
        if int(query["_count"]) > profile.transport_caps["max_page_resources"]:
            raise _Reject("url")
    return query


def _safe_read_url(
    url: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    location_id: str,
) -> None:
    if not _valid_url_text(url, profile):
        raise _Reject("url")
    assert isinstance(url, str)
    if location_id == "." or location_id == "..":
        raise _Reject("location-id")
    if "\\" in url or "#" in url or "?" in url:
        raise _Reject("url")
    try:
        parts = urlsplit(url)
        port = parts.port
    except (ValueError, AttributeError):
        raise _Reject("url") from None
    if (
        parts.scheme != "https"
        or parts.hostname != profile.host
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or parts.query
        or parts.path != "/fhir/Location/" + location_id
    ):
        raise _Reject("url")
    if any(token in parts.path.lower() for token in ("%2f", "%5c", "%2e", "%00")):
        raise _Reject("url")


def _reference_id(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    ignored: Counter[str],
) -> str:
    if not isinstance(value, dict):
        raise _Reject("reference")
    if "identifier" in value:
        raise _Reject("reference-identity")
    reference = value.get("reference")
    if not isinstance(reference, str):
        raise _Reject("reference")
    if len(reference.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
        raise _Reject("reference")
    allowed = {"reference", "type", "display"}
    for key in value:
        if key in {"extension", "modifierExtension"}:
            raise _Reject("modifier-field")
        if key not in allowed:
            ignored["unselected-reference-field"] += 1
    if "type" in value and value["type"] != resource_type:
        raise _Reject("reference")
    if "display" in value and type(value["display"]) is not str:
        raise _Reject("reference")
    if reference.startswith("https://"):
        try:
            parts = urlsplit(reference)
            port = parts.port
        except (ValueError, AttributeError):
            raise _Reject("reference") from None
        if (
            parts.scheme != "https"
            or parts.hostname != profile.host
            or port not in (None, 443)
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or not parts.path.startswith("/fhir/")
        ):
            raise _Reject("reference")
        if any(
            token in parts.path.lower()
            for token in ("%2f", "%5c", "%2e", "%00")
        ):
            raise _Reject("reference")
        reference = parts.path.removeprefix("/fhir/")
    prefix = resource_type + "/"
    if not reference.startswith(prefix):
        raise _Reject("reference")
    identifier = reference[len(prefix):]
    if not _valid_id(identifier):
        raise _Reject("reference")
    if resource_type == "Location" and not _valid_location_id(identifier):
        raise _Reject("location-id")
    return identifier


def _full_url(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    resource_id: str,
) -> None:
    if resource_type == "Location" and not _valid_location_id(resource_id):
        raise _Reject("location-id")
    if not _valid_url_text(value, profile):
        raise _Reject("full-url")
    assert isinstance(value, str)
    try:
        parts = urlsplit(value)
        port = parts.port
    except (ValueError, AttributeError):
        raise _Reject("full-url") from None
    if (
        parts.scheme != "https"
        or parts.hostname != profile.host
        or port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path != "/fhir/" + resource_type + "/" + resource_id
    ):
        raise _Reject("full-url")
    if any(token in parts.path.lower() for token in ("%2f", "%5c", "%2e", "%00")):
        raise _Reject("full-url")


def _field_ignored(
    value: dict[str, object],
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    ignored: Counter[str],
) -> None:
    selected = dict(profile.selected_resource_fields)[resource_type]
    selected_set = set(selected)
    for key in value:
        if key in {
            "extension",
            "modifierExtension",
            "contained",
            "implicitRules",
        }:
            raise _Reject("modifier-field")
        if key not in selected_set:
            ignored["unselected-resource-field"] += 1


def _validate_meta(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    ignored: Counter[str],
) -> None:
    if not isinstance(value, dict):
        raise _Reject("meta")
    for key, item in value.items():
        if key in {"extension", "modifierExtension"}:
            raise _Reject("modifier-field")
        if key == "lastUpdated":
            if (
                type(item) is not str
                or _INSTANT_PATTERN.fullmatch(item) is None
            ):
                raise _Reject("meta")
        elif key == "versionId":
            if (
                type(item) is not str
                or len(item.encode("utf-8"))
                > profile.transport_caps["max_string_bytes"]
            ):
                raise _Reject("meta")
        else:
            ignored["unselected-meta-field"] += 1


def _validate_period(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
) -> None:
    if not isinstance(value, dict):
        raise _Reject("period")
    for key, item in value.items():
        if key not in {"start", "end"}:
            raise _Reject("period")
        if type(item) is not str or _DATE_PATTERN.fullmatch(item) is None:
            raise _Reject("period")
        if len(item.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
            raise _Reject("period")


def _validate_resource(
    resource: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    expected_type: str,
    requested_practitioner_id: str,
    ignored: Counter[str],
) -> _ResourceRecord:
    if not isinstance(resource, dict):
        raise _Reject("resource")
    _field_ignored(
        resource,
        profile,
        resource_type=expected_type,
        ignored=ignored,
    )
    if resource.get("resourceType") != expected_type:
        raise _Reject("resource-type")
    resource_id = resource.get("id")
    if not _valid_id(resource_id):
        raise _Reject("resource-id")
    assert isinstance(resource_id, str)
    if expected_type == "Location" and not _valid_location_id(resource_id):
        raise _Reject("location-id")
    if "active" in resource and type(resource["active"]) is not bool:
        raise _Reject("active")
    if "meta" in resource:
        _validate_meta(resource["meta"], profile, ignored=ignored)
    if expected_type == "PractitionerRole":
        if "practitioner" not in resource:
            raise _Reject("reference")
        practitioner_id = _reference_id(
            resource["practitioner"],
            profile,
            resource_type="Practitioner",
            ignored=ignored,
        )
        locations = resource.get("location", [])
        if not isinstance(locations, list):
            raise _Reject("reference")
        if len(locations) > profile.transport_caps["max_location_reads"]:
            raise _Reject("resource-cap")
        location_ids: list[str] = []
        for reference in locations:
            location_id = _reference_id(
                reference,
                profile,
                resource_type="Location",
                ignored=ignored,
            )
            if location_id in location_ids:
                raise _Reject("duplicate-resource")
            location_ids.append(location_id)
        if "period" in resource:
            _validate_period(resource["period"], profile)
        return _ResourceRecord(
            resource_id=resource_id,
            full_url="",
            practitioner_id=practitioner_id,
            location_ids=tuple(location_ids),
        )
    if expected_type == "Location" and "status" in resource:
        if (
            type(resource["status"]) is not str
            or resource["status"] not in _LOCATION_STATUS_VALUES
        ):
            raise _Reject("resource-field")
    return _ResourceRecord(resource_id=resource_id, full_url="")


def _verify_bundle(
    document: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    request_url: str,
    request_query: Mapping[str, str] | None = None,
    required_filter: Mapping[str, str],
    continuation: bool,
    seen_ids: set[str],
    requested_practitioner_id: str,
    ignored: Counter[str],
) -> tuple[
    list[_ResourceRecord],
    str | None,
    int | None,
    dict[str, str] | None,
]:
    if not isinstance(document, dict):
        raise _Reject("searchset")
    required = {"resourceType", "type", "link", "entry"}
    if not required.issubset(document):
        raise _Reject("bundle")
    for key in document:
        if key in {"modifierExtension", "contained", "implicitRules"}:
            raise _Reject("modifier-field")
        if key not in required and key not in {"id", "total", "meta"}:
            ignored["unselected-bundle-field"] += 1
    if document.get("resourceType") != "Bundle" or document.get("type") != "searchset":
        raise _Reject("bundle-type")
    links = document["link"]
    entries = document["entry"]
    if not isinstance(links, list) or not isinstance(entries, list):
        raise _Reject("bundle")
    if len(entries) > profile.transport_caps["max_page_resources"]:
        raise _Reject("resource-cap")
    self_url: str | None = None
    next_url: str | None = None
    for link in links:
        if not isinstance(link, dict):
            raise _Reject("bundle-links")
        if "relation" not in link or "url" not in link:
            raise _Reject("bundle-links")
        relation = link["relation"]
        url = link["url"]
        if type(relation) is not str:
            raise _Reject("bundle-links")
        for key in link:
            if key in {"extension", "modifierExtension"}:
                raise _Reject("modifier-field")
            if key not in {"relation", "url"}:
                ignored["unselected-link-field"] += 1
        if relation == "self":
            if self_url is not None or type(url) is not str:
                raise _Reject("search-self")
            self_url = url
        elif relation == "next":
            if next_url is not None or type(url) is not str:
                raise _Reject("search-next")
            next_url = url
        else:
            ignored["unselected-link"] += 1
    if self_url is None:
        raise _Reject("search-self")
    if request_query is None:
        request_query = _safe_query_url(
            request_url,
            profile,
            resource_type=resource_type,
            required_filter=required_filter,
            continuation=continuation,
        )
    else:
        request_query = dict(request_query)
    self_query = _safe_query_url(
        self_url,
        profile,
        resource_type=resource_type,
        required_filter=required_filter,
        continuation=continuation,
    )
    if self_query != request_query:
        raise _Reject("search-self")
    next_query: dict[str, str] | None = None
    if next_url is not None:
        next_query = _safe_query_url(
            next_url,
            profile,
            resource_type=resource_type,
            required_filter=required_filter,
            continuation=True,
        )
    total: int | None = None
    if "total" in document:
        raw_total = document["total"]
        if (
            type(raw_total) is not int
            or raw_total < 0
            or raw_total > profile.transport_caps["max_total_matches"]
        ):
            raise _Reject("search-total")
        total = raw_total
    records: list[_ResourceRecord] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise _Reject("bundle-entry")
        if "fullUrl" not in entry or "resource" not in entry:
            raise _Reject("bundle-entry")
        for key in entry:
            if key in {"extension", "modifierExtension"}:
                raise _Reject("modifier-field")
            if key not in {"fullUrl", "resource", "search"}:
                ignored["unselected-entry-field"] += 1
        if "search" in entry:
            search = entry["search"]
            if not isinstance(search, dict):
                raise _Reject("search-mode")
            mode = search.get("mode", "match")
            if mode == "include":
                raise _Reject("unsupported-include")
            if mode != "match":
                raise _Reject("search-mode")
            for key in search:
                if key in {"extension", "modifierExtension"}:
                    raise _Reject("modifier-field")
                if key != "mode":
                    ignored["unselected-search-field"] += 1
        record = _validate_resource(
            entry["resource"],
            profile,
            expected_type=resource_type,
            requested_practitioner_id=requested_practitioner_id,
            ignored=ignored,
        )
        _full_url(
            entry["fullUrl"],
            profile,
            resource_type=resource_type,
            resource_id=record.resource_id,
        )
        assert isinstance(entry["fullUrl"], str)
        if record.resource_id in seen_ids:
            raise _Reject("duplicate-resource")
        seen_ids.add(record.resource_id)
        record.full_url = entry["fullUrl"]
        records.append(record)
    if total is not None and len(records) > total:
        raise _Reject("total-drift")
    return records, next_url, total, next_query


def _validate_operation_shape(
    operation: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    index: int,
    kind: str,
    resource_type: str,
    request_url: str,
    request_filter: Mapping[str, str],
) -> tuple[dict[str, object] | None, str | None, int, int, int]:
    if not isinstance(operation, dict):
        raise _Reject("operation")
    expected_keys = {
        "sequence",
        "kind",
        "resource_type",
        "request_url",
        "filter",
        "attempt_statuses",
        "attempt_byte_lengths",
        "attempt_failure_codes",
        "retry_after_seconds",
        "response_status",
        "response_media_type",
        "response_url",
        "byte_length",
        "document",
        "next_url",
        "failure_code",
    }
    if set(operation) != expected_keys:
        raise _Reject("operation")
    if (
        operation["sequence"] != index
        or operation["kind"] != kind
        or operation["resource_type"] != resource_type
        or operation["request_url"] != request_url
        or operation["filter"] != dict(request_filter)
    ):
        raise _Reject("operation-order")
    if kind == "read":
        location_id = request_filter.get("id")
        if resource_type != "Location" or not _valid_location_id(location_id):
            raise _Reject("location-id")
        _safe_read_url(request_url, profile, location_id=location_id)
    attempts = operation["attempt_statuses"]
    sizes = operation["attempt_byte_lengths"]
    attempt_failures = operation["attempt_failure_codes"]
    retry_after = operation["retry_after_seconds"]
    failure = operation["failure_code"]
    if (
        not isinstance(attempts, list)
        or not isinstance(sizes, list)
        or not isinstance(attempt_failures, list)
        or not isinstance(retry_after, list)
        or len(attempts) != len(sizes)
        or len(attempts) != len(attempt_failures)
        or len(attempts) != len(retry_after)
        or len(attempts) > profile.transport_caps["max_retries"] + 1
    ):
        raise _Reject("operation")
    if len(attempts) == 0:
        if operation["failure_code"] not in {
            "request-cap",
            "page-cap",
            "resource-cap",
        }:
            raise _Reject("operation")
    for status in attempts:
        if type(status) is not int or not 0 <= status <= 599:
            raise _Reject("operation")
    for attempt_failure in attempt_failures:
        if attempt_failure is not None and (
            type(attempt_failure) is not str
            or attempt_failure not in FAILURE_CODES
        ):
            raise _Reject("operation")
    for size in sizes:
        maximum_size = profile.transport_caps["max_response_bytes"]
        if failure == "response-cap":
            maximum_size += 1
        if (
            type(size) is not int
            or size < 0
            or size > maximum_size
        ):
            raise _Reject("response-cap")
        if (
            size == profile.transport_caps["max_response_bytes"] + 1
            and failure != "response-cap"
        ):
            raise _Reject("response-cap")
    for value in retry_after:
        if value is not None and (
            type(value) is not int
            or value < 0
            or value > profile.transport_caps["max_retry_after_seconds"]
        ):
            raise _Reject("retry-after")
    if failure is not None and (
        type(failure) is not str or failure not in FAILURE_CODES
    ):
        raise _Reject("response")
    if attempts:
        last_attempt_failure = attempt_failures[-1]
        if failure is None and last_attempt_failure is not None:
            raise _Reject("response")
        retry_attempts = {
            "rate-limit",
            "server-error",
            "transport",
            "timeout",
        }
        if any(
            attempt_failure not in retry_attempts
            for attempt_failure in attempt_failures[:-1]
        ):
            raise _Reject("response")
        if failure == "retry-exhausted":
            if last_attempt_failure not in retry_attempts:
                raise _Reject("response")
        elif failure == "next-link":
            if last_attempt_failure is not None:
                raise _Reject("response")
        elif failure is not None and last_attempt_failure != failure:
            raise _Reject("response")
        for attempt_status, attempt_failure in zip(attempts, attempt_failures):
            if attempt_failure == "rate-limit" and attempt_status != 429:
                raise _Reject("response")
            if attempt_failure == "server-error" and not (
                500 <= attempt_status <= 599
            ):
                raise _Reject("response")
            if attempt_failure == "transport" and attempt_status != 0:
                raise _Reject("response")
            if attempt_failure is None and attempt_status != 200:
                raise _Reject("response")
        if failure is None:
            if any(
                attempt_failure is None for attempt_failure in attempt_failures[:-1]
            ):
                raise _Reject("response")
    response_status = operation["response_status"]
    if type(response_status) is not int or not 0 <= response_status <= 599:
        raise _Reject("response")
    if attempts and response_status != attempts[-1]:
        raise _Reject("response")
    if not attempts and response_status != 0:
        raise _Reject("response")
    media = operation["response_media_type"]
    if media is not None and (
        type(media) is not str
        or len(media.encode("utf-8")) > profile.transport_caps["max_string_bytes"]
    ):
        raise _Reject("response")
    response_url = operation["response_url"]
    if response_url is not None and not isinstance(response_url, str):
        raise _Reject("response")
    byte_length = operation["byte_length"]
    if (
        type(byte_length) is not int
        or byte_length < 0
        or byte_length > profile.transport_caps["max_response_bytes"]
    ):
        raise _Reject("response-cap")
    document = operation["document"]
    if document is not None and not isinstance(document, dict):
        raise _Reject("response")
    next_url = operation["next_url"]
    if next_url is not None and not _valid_url_text(next_url, profile):
        raise _Reject("url")
    if failure is None:
        if (
            len(attempts) == 0
            or response_status != 200
            or response_url != request_url
            or not isinstance(media, str)
            or not _media_type_allowed(media)
            or document is None
            or byte_length != sizes[-1]
        ):
            raise _Reject("response")
        if kind == "search":
            if next_url is not None:
                _safe_query_url(
                    next_url,
                    profile,
                    resource_type=resource_type,
                    required_filter=request_filter,
                    continuation=True,
                )
        else:
            if next_url is not None:
                raise _Reject("response")
    else:
        if failure == "next-link" and document is not None:
            pass
        elif document is not None:
            raise _Reject("response")
        if failure not in {"request-cap", "page-cap", "resource-cap"}:
            if len(attempts) == 0:
                raise _Reject("response")
    return (
        document,
        failure,
        1 if response_status != 0 else 0,
        max(0, len(attempts) - 1),
        sum(sizes),
    )


def _media_type_allowed(value: str) -> bool:
    pieces = [piece.strip() for piece in value.split(";")]
    if not pieces or pieces[0].lower() != ALLOWED_MEDIA_TYPE:
        return False
    parameters: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            return False
        key, parameter = piece.split("=", 1)
        key = key.strip().lower()
        parameter = parameter.strip()
        if not key or key in parameters:
            return False
        parameters[key] = parameter
    if "fhirversion" in parameters and parameters["fhirversion"] != "4.0":
        return False
    return all(key in {"fhirversion", "charset"} for key in parameters)


def _verify_search_segment(
    operations: list[object],
    profile: NcMedicaidDirectoryProfileV1,
    *,
    start: int,
    resource_type: str,
    initial_url: str,
    request_filter: Mapping[str, str],
    requested_practitioner_id: str,
    total_bytes_seen: int,
    total_pages_seen: int,
) -> tuple[_SegmentResult, int]:
    resources: list[_ResourceRecord] = []
    seen_ids: set[str] = set()
    ignored: Counter[str] = Counter()
    current_url = initial_url
    seen_urls: set[str] = set()
    current_query: dict[str, str] | None = None
    index = start
    pages = 0
    response_count = 0
    retry_count = 0
    known_total: int | None = None
    while True:
        boundary_failure: str | None = None
        if pages >= profile.transport_caps["max_search_pages"]:
            boundary_failure = "page-cap"
        elif (
            total_pages_seen + pages
            >= profile.transport_caps["max_search_pages_total"]
        ):
            boundary_failure = "page-cap"
        boundary_consumed = False
        if boundary_failure is not None:
            if index < len(operations):
                _, failure, responses, retries, operation_bytes = (
                    _validate_operation_shape(
                        operations[index],
                        profile,
                        index=index,
                        kind="search",
                        resource_type=resource_type,
                        request_url=current_url,
                        request_filter=request_filter,
                    )
                )
                if failure != boundary_failure:
                    raise _Reject("unexpected-operation")
                response_count += responses
                retry_count += retries
                total_bytes_seen += operation_bytes
                if total_bytes_seen > profile.transport_caps["max_total_response_bytes"]:
                    raise _Reject("response-total-cap")
                index += 1
                boundary_consumed = True
            result = _SegmentResult(
                resources,
                index,
                pages,
                response_count,
                retry_count,
                ignored,
                False,
                "PARTIAL",
                boundary_failure,
                known_total,
                boundary_consumed,
            )
            return result, total_bytes_seen
        if index >= len(operations):
            raise _Reject("missing-operation")
        if current_url in seen_urls:
            raise _Reject("next-link")
        seen_urls.add(current_url)
        document, failure, responses, retries, operation_bytes = _validate_operation_shape(
            operations[index],
            profile,
            index=index,
            kind="search",
            resource_type=resource_type,
            request_url=current_url,
            request_filter=request_filter,
        )
        total_bytes_seen += operation_bytes
        if total_bytes_seen > profile.transport_caps["max_total_response_bytes"]:
            raise _Reject("response-total-cap")
        response_count += responses
        retry_count += retries
        index += 1
        if failure is not None:
            status = "PARTIAL" if failure in TRANSPORT_FAILURES else "FAILED"
            result = _SegmentResult(
                resources,
                index,
                pages,
                response_count,
                retry_count,
                ignored,
                False,
                status,
                failure,
                known_total,
                failure in {"request-cap", "page-cap", "resource-cap"}
                and responses == 0
                and retries == 0
                and operation_bytes == 0,
            )
            return result, total_bytes_seen
        assert document is not None
        continuation = pages > 0
        try:
            page_resources, next_url, page_total, next_query = _verify_bundle(
                document,
                profile,
                resource_type=resource_type,
                request_url=current_url,
                request_query=current_query,
                required_filter=request_filter,
                continuation=continuation,
                seen_ids=seen_ids,
                requested_practitioner_id=requested_practitioner_id,
                ignored=ignored,
            )
        except _Reject as exc:
            if exc.code != "resource-cap":
                raise
            result = _SegmentResult(
                resources,
                index,
                pages,
                response_count,
                retry_count,
                ignored,
                False,
                "PARTIAL",
                "resource-cap",
                known_total,
            )
            return result, total_bytes_seen
        if page_total is not None:
            if known_total is not None and known_total != page_total:
                raise _Reject("total-drift")
            known_total = page_total
        resources.extend(page_resources)
        if len(resources) > profile.transport_caps["max_total_matches"]:
            raise _Reject("resource-cap")
        pages += 1
        if next_url is None:
            if known_total is not None and known_total != len(resources):
                raise _Reject("total-incomplete")
            result = _SegmentResult(
                resources,
                index,
                pages,
                response_count,
                retry_count,
                ignored,
                True,
                "COMPLETE",
                None,
                known_total,
            )
            return result, total_bytes_seen
        current_url = next_url
        current_query = next_query


def _base_aggregate(
    profile: NcMedicaidDirectoryProfileV1,
    *,
    observation_time: int,
    fetched_at: int,
    accepted: bool,
    failure_code: str | None,
    source_status: str,
    traversal_status: str,
    practitioner_count: int = 0,
    role_count: int = 0,
    location_count: int = 0,
    search_page_count: int = 0,
    location_read_count: int = 0,
    request_count: int = 0,
    response_count: int = 0,
    retry_count: int = 0,
    ignored: Counter[str] | None = None,
) -> VerifiedDirectoryAggregate:
    ignored = ignored or Counter()
    reasons = tuple(sorted((key, count) for key, count in ignored.items() if count))
    return VerifiedDirectoryAggregate(
        profile_id=profile.source_profile_id,
        profile_version=profile.source_profile_version,
        source_contract_digest=_profile_digest(profile),
        verifier_id=VERIFIER_ID,
        verifier_epoch=VERIFIER_EPOCH,
        accepted=accepted,
        failure_code=failure_code,
        source_status=source_status,
        traversal_status=traversal_status,
        capture_age="UNKNOWN",
        source_freshness="UNKNOWN",
        dataset_completeness="UNKNOWN",
        observation_time=observation_time,
        fetched_at=fetched_at,
        practitioner_count=practitioner_count,
        role_count=role_count,
        location_count=location_count,
        search_page_count=search_page_count,
        location_read_count=location_read_count,
        request_count=request_count,
        response_count=response_count,
        retry_count=retry_count,
        ignored_field_count=sum(count for _, count in reasons),
        ignored_field_reasons=reasons,
    )


def rejected_aggregate(
    profile: NcMedicaidDirectoryProfileV1 = NC_MEDICAID_DIRECTORY_PROFILE_V1,
    *,
    observation_time: int,
    fetched_at: int,
    failure_code: str,
) -> VerifiedDirectoryAggregate:
    if failure_code not in FAILURE_CODES:
        failure_code = "adapter-rejected"
    return _base_aggregate(
        profile,
        observation_time=observation_time,
        fetched_at=fetched_at,
        accepted=False,
        failure_code=failure_code,
        source_status="FAILED",
        traversal_status="FAILED",
    )


def _verify_capture(
    raw: bytes,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    context: DirectoryOperationContext,
    observation_time: int,
    fetched_at: int,
) -> VerifiedDirectoryAggregate:
    if not isinstance(context, DirectoryOperationContext):
        raise _Reject("context")
    capture = _parse_capture(raw, profile)
    operation = capture["operation"]
    assert isinstance(operation, dict)
    expected_operation_keys = {
        "operation_ref",
        "practitioner_id",
        "observation_time",
        "fetched_at",
        "operation_binding",
    }
    if set(operation) != expected_operation_keys:
        raise _Reject("context")
    if (
        operation["operation_ref"] != context.operation_ref
        or operation["practitioner_id"] != context.practitioner_id
        or operation["observation_time"] != observation_time
        or operation["fetched_at"] != fetched_at
        or operation["operation_binding"] != _operation_binding(context.operation_ref)
    ):
        raise _Reject("binding")
    if (
        type(observation_time) is not int
        or type(fetched_at) is not int
        or not 0 <= observation_time <= _MAX_SIGNED_INT
        or not observation_time <= fetched_at <= _MAX_SIGNED_INT
    ):
        raise _Reject("context")
    operations = capture["operations"]
    assert isinstance(operations, list)
    if capture["capture_failure"] is not None:
        return rejected_aggregate(
            profile,
            observation_time=observation_time,
            fetched_at=fetched_at,
            failure_code=str(capture["capture_failure"]),
        )
    if not operations:
        raise _Reject("missing-operation")
    if len(operations) > profile.transport_caps["max_requests"] + 1:
        raise _Reject("request-cap")
    practitioner_filter = {"_id": context.practitioner_id}
    practitioner_segment, total_bytes_seen = _verify_search_segment(
        operations,
        profile,
        start=0,
        resource_type="Practitioner",
        initial_url=profile.practitioner_search_url(context.practitioner_id),
        request_filter=practitioner_filter,
        requested_practitioner_id=context.practitioner_id,
        total_bytes_seen=0,
        total_pages_seen=0,
    )
    if practitioner_segment.next_index != len(operations) and (
        practitioner_segment.failure_code is not None
    ):
        raise _Reject("unexpected-operation")
    practitioner_count = len(practitioner_segment.resources)
    if practitioner_segment.failure_code is not None:
        return _base_aggregate(
            profile,
            observation_time=observation_time,
            fetched_at=fetched_at,
            accepted=False,
            failure_code=practitioner_segment.failure_code,
            source_status=practitioner_segment.traversal_status,
            traversal_status=practitioner_segment.traversal_status,
            practitioner_count=practitioner_count,
            search_page_count=practitioner_segment.pages,
            request_count=(
                practitioner_segment.next_index
                - (1 if practitioner_segment.boundary else 0)
            ),
            response_count=practitioner_segment.response_count,
            retry_count=practitioner_segment.retry_count,
            ignored=practitioner_segment.ignored,
        )
    if practitioner_count == 0:
        return _base_aggregate(
            profile,
            observation_time=observation_time,
            fetched_at=fetched_at,
            accepted=False,
            failure_code="practitioner-not-found",
            source_status="OBSERVED",
            traversal_status="COMPLETE",
            search_page_count=practitioner_segment.pages,
            request_count=practitioner_segment.next_index,
            response_count=practitioner_segment.response_count,
            retry_count=practitioner_segment.retry_count,
            ignored=practitioner_segment.ignored,
        )
    if practitioner_count != 1:
        raise _Reject("practitioner-mismatch")
    if practitioner_segment.resources[0].resource_id != context.practitioner_id:
        raise _Reject("practitioner-mismatch")

    role_filter = {"practitioner": "Practitioner/" + context.practitioner_id}
    role_segment, total_bytes_seen = _verify_search_segment(
        operations,
        profile,
        start=practitioner_segment.next_index,
        resource_type="PractitionerRole",
        initial_url=profile.practitioner_role_search_url(
            context.practitioner_id
        ),
        request_filter=role_filter,
        requested_practitioner_id=context.practitioner_id,
        total_bytes_seen=total_bytes_seen,
        total_pages_seen=practitioner_segment.pages,
    )
    ignored = practitioner_segment.ignored + role_segment.ignored
    if role_segment.failure_code is not None:
        if role_segment.next_index != len(operations):
            raise _Reject("unexpected-operation")
        return _base_aggregate(
            profile,
            observation_time=observation_time,
            fetched_at=fetched_at,
            accepted=False,
            failure_code=role_segment.failure_code,
            source_status=role_segment.traversal_status,
            traversal_status=role_segment.traversal_status,
            practitioner_count=practitioner_count,
            role_count=len(role_segment.resources),
            search_page_count=practitioner_segment.pages + role_segment.pages,
            request_count=role_segment.next_index
            - (1 if role_segment.boundary else 0),
            response_count=practitioner_segment.response_count
            + role_segment.response_count,
            retry_count=practitioner_segment.retry_count
            + role_segment.retry_count,
            ignored=ignored,
        )
    for role in role_segment.resources:
        if role.practitioner_id != context.practitioner_id:
            raise _Reject("practitioner-mismatch")
    location_ids: list[str] = []
    for role in role_segment.resources:
        for location_id in role.location_ids:
            if location_id not in location_ids:
                location_ids.append(location_id)
    if len(location_ids) > profile.transport_caps["max_location_reads"]:
        raise _Reject("resource-cap")

    index = role_segment.next_index
    location_records: list[_ResourceRecord] = []
    location_response_count = 0
    location_retry_count = 0
    location_ignored: Counter[str] = Counter()
    for location_id in location_ids:
        if index >= len(operations):
            raise _Reject("missing-operation")
        request_url = profile.location_read_url(location_id)
        document, failure, responses, retries, operation_bytes = _validate_operation_shape(
            operations[index],
            profile,
            index=index,
            kind="read",
            resource_type="Location",
            request_url=request_url,
            request_filter={"id": location_id},
        )
        total_bytes_seen += operation_bytes
        if total_bytes_seen > profile.transport_caps["max_total_response_bytes"]:
            raise _Reject("response-total-cap")
        location_response_count += responses
        location_retry_count += retries
        index += 1
        if failure is not None:
            if index != len(operations):
                raise _Reject("unexpected-operation")
            status = "PARTIAL" if failure in TRANSPORT_FAILURES else "FAILED"
            boundary = (
                failure in {"request-cap", "page-cap", "resource-cap"}
                and responses == 0
                and retries == 0
                and operation_bytes == 0
            )
            combined = ignored + location_ignored
            return _base_aggregate(
                profile,
                observation_time=observation_time,
                fetched_at=fetched_at,
                accepted=False,
                failure_code=failure,
                source_status=status,
                traversal_status=status,
                practitioner_count=practitioner_count,
                role_count=len(role_segment.resources),
                location_count=len(location_records),
                search_page_count=practitioner_segment.pages + role_segment.pages,
                location_read_count=(
                    index
                    - role_segment.next_index
                    - (1 if boundary else 0)
                ),
                request_count=index - (1 if boundary else 0),
                response_count=practitioner_segment.response_count
                + role_segment.response_count
                + location_response_count,
                retry_count=practitioner_segment.retry_count
                + role_segment.retry_count
                + location_retry_count,
                ignored=combined,
            )
        if not isinstance(document, dict):
            raise _Reject("location-mismatch")
        if document.get("resourceType") != "Location":
            raise _Reject("location-mismatch")
        record = _validate_resource(
            document,
            profile,
            expected_type="Location",
            requested_practitioner_id=context.practitioner_id,
            ignored=location_ignored,
        )
        if record.resource_id != location_id:
            raise _Reject("location-mismatch")
        location_records.append(record)
    if index != len(operations):
        raise _Reject("unexpected-operation")
    if (
        practitioner_count
        + len(role_segment.resources)
        + len(location_records)
        > profile.transport_caps["max_total_resources"]
    ):
        raise _Reject("resource-cap")
    ignored += location_ignored
    return _base_aggregate(
        profile,
        observation_time=observation_time,
        fetched_at=fetched_at,
        accepted=True,
        failure_code=None,
        source_status="OBSERVED",
        traversal_status="COMPLETE",
        practitioner_count=practitioner_count,
        role_count=len(role_segment.resources),
        location_count=len(location_records),
        search_page_count=practitioner_segment.pages + role_segment.pages,
        location_read_count=len(location_records),
        request_count=index,
        response_count=practitioner_segment.response_count
        + role_segment.response_count
        + location_response_count,
        retry_count=practitioner_segment.retry_count
        + role_segment.retry_count
        + location_retry_count,
        ignored=ignored,
    )


def verify_capture(
    raw: bytes,
    *,
    profile: NcMedicaidDirectoryProfileV1 = NC_MEDICAID_DIRECTORY_PROFILE_V1,
    context: DirectoryOperationContext,
    observation_time: int,
    fetched_at: int,
) -> VerifiedDirectoryAggregate:
    if not isinstance(profile, NcMedicaidDirectoryProfileV1):
        raise_redacted(DirectoryIndependentError, "profile")
    try:
        return _verify_capture(
            raw,
            profile,
            context=context,
            observation_time=observation_time,
            fetched_at=fetched_at,
        )
    except _Reject as exc:
        code = exc.code if exc.code in FAILURE_CODES else "capture-json"
        raise_redacted(DirectoryIndependentError, code)
    except Exception:
        raise_redacted(DirectoryIndependentError, "capture-json")


OBSERVATION_KEYS = {
    "schema",
    "schema_version",
    "profile_id",
    "profile_version",
    "source_contract_digest",
    "verifier_id",
    "verifier_epoch",
    "observation_time",
    "fetched_at",
    "accepted",
    "outcome",
    "source_status",
    "traversal_status",
    "capture_age",
    "source_freshness",
    "dataset_completeness",
    "failure_code",
    "practitioner_count",
    "role_count",
    "location_count",
    "search_page_count",
    "location_read_count",
    "request_count",
    "response_count",
    "retry_count",
    "ignored_field_count",
    "ignored_field_reasons",
    "flags",
}
RECEIPT_KEYS = {
    "schema",
    "schema_version",
    "profile_id",
    "profile_version",
    "source_contract_digest",
    "verifier_id",
    "verifier_epoch",
    "verification_status",
    "operation_binding",
    "observation_digest",
    "issued_at",
    "synthetic_only",
    "production_usable",
    "activation",
    "proofSuiteId",
}
SANITIZED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "source_truth_proven": False,
    "enrollment_status_proven": False,
    "license_status_proven": False,
    "credential_status_proven": False,
    "completeness": "UNKNOWN",
    "source_freshness": "UNKNOWN",
    "production_source_authentication": False,
    "proofSuiteId": None,
}


def _parse_sanitized(raw: object, expected: set[str], code: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise _Reject("sanitized")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _Reject:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _Reject("sanitized") from None
    if not isinstance(value, dict) or set(value) != expected:
        raise _Reject(code)
    if _canonical(value) != raw:
        raise _Reject("sanitized")
    return value


def verify_sanitized_pair(
    observation: bytes,
    receipt: bytes,
    *,
    profile: NcMedicaidDirectoryProfileV1 = NC_MEDICAID_DIRECTORY_PROFILE_V1,
) -> dict[str, object]:
    if not isinstance(profile, NcMedicaidDirectoryProfileV1):
        raise_redacted(DirectoryIndependentError, "profile")
    try:
        obs = _parse_sanitized(observation, OBSERVATION_KEYS, "sanitized")
        rec = _parse_sanitized(receipt, RECEIPT_KEYS, "sanitized")
        digest = _profile_digest(profile)
        if (
            obs["schema"] != OBSERVATION_SCHEMA
            or obs["schema_version"] != OBSERVATION_SCHEMA_VERSION
            or obs["profile_id"] != profile.source_profile_id
            or obs["profile_version"] != profile.source_profile_version
            or obs["source_contract_digest"] != digest
            or obs["verifier_id"] != VERIFIER_ID
            or obs["verifier_epoch"] != VERIFIER_EPOCH
            or obs["flags"] != SANITIZED_FLAGS
        ):
            raise _Reject("sanitized")
        if (
            type(obs["observation_time"]) is not int
            or type(obs["fetched_at"]) is not int
            or not 0 <= obs["observation_time"] <= _MAX_SIGNED_INT
            or not obs["observation_time"] <= obs["fetched_at"] <= _MAX_SIGNED_INT
        ):
            raise _Reject("sanitized")
        bounded_counts = {
            "practitioner_count": profile.transport_caps["max_total_matches"],
            "role_count": profile.transport_caps["max_total_matches"],
            "location_count": profile.transport_caps["max_location_reads"],
            "search_page_count": profile.transport_caps["max_search_pages_total"],
            "location_read_count": profile.transport_caps["max_location_reads"],
            "request_count": profile.transport_caps["max_requests"],
            "response_count": profile.transport_caps["max_requests"]
            * (profile.transport_caps["max_retries"] + 1),
            "retry_count": profile.transport_caps["max_requests"]
            * profile.transport_caps["max_retries"],
            "ignored_field_count": profile.transport_caps["max_total_nodes"],
        }
        for key, maximum in bounded_counts.items():
            value = obs[key]
            if type(value) is not int or not 0 <= value <= maximum:
                raise _Reject("sanitized")
        reasons = obs["ignored_field_reasons"]
        if not isinstance(reasons, dict):
            raise _Reject("sanitized")
        reason_total = 0
        for key, value in reasons.items():
            if (
                type(key) is not str
                or len(key.encode("utf-8")) > profile.transport_caps["max_string_bytes"]
                or type(value) is not int
                or not 0 <= value <= profile.transport_caps["max_total_nodes"]
            ):
                raise _Reject("sanitized")
            reason_total += value
        if reason_total != obs["ignored_field_count"]:
            raise _Reject("sanitized")
        if (
            rec["schema"] != RECEIPT_SCHEMA
            or rec["schema_version"] != RECEIPT_SCHEMA_VERSION
            or rec["profile_id"] != profile.source_profile_id
            or rec["profile_version"] != profile.source_profile_version
            or rec["source_contract_digest"] != digest
            or rec["verifier_id"] != VERIFIER_ID
            or rec["verifier_epoch"] != VERIFIER_EPOCH
            or rec["verification_status"] != "VERIFIED_AT_TIME"
            or type(rec["operation_binding"]) is not str
            or _HEX_PATTERN.fullmatch(rec["operation_binding"]) is None
            or rec["observation_digest"]
            != _digest(OBSERVATION_DIGEST_DOMAIN, observation)
            or rec["synthetic_only"] is not True
            or rec["production_usable"] is not False
            or rec["activation"] is not False
            or rec["proofSuiteId"] is not None
            or type(rec["issued_at"]) is not int
            or not 0 <= rec["issued_at"] <= _MAX_SIGNED_INT
            or rec["issued_at"] != obs["fetched_at"]
        ):
            raise _Reject("sanitized")
        if (
            obs["accepted"] is not True
            or obs["failure_code"] is not None
            or obs["outcome"] != "DIRECTORY_OBSERVED"
            or obs["source_status"] != "OBSERVED"
            or obs["traversal_status"] != "COMPLETE"
            or obs["capture_age"] != "UNKNOWN"
            or obs["source_freshness"] != "UNKNOWN"
            or obs["dataset_completeness"] != "UNKNOWN"
        ):
            raise _Reject("sanitized")
        return {
            "accepted": True,
            "profile_id": obs["profile_id"],
            "profile_version": obs["profile_version"],
            "verification_status": rec["verification_status"],
        }
    except _Reject as exc:
        code = exc.code if exc.code in FAILURE_CODES else "sanitized"
        raise_redacted(DirectoryIndependentError, code)
    except Exception:
        raise_redacted(DirectoryIndependentError, "sanitized")


__all__ = [
    "CAPTURE_SCHEMA",
    "CAPTURE_SCHEMA_VERSION",
    "DirectoryIndependentError",
    "FAILURE_CODES",
    "NC_MEDICAID_DIRECTORY_PROFILE_V1",
    "OBSERVATION_SCHEMA",
    "OBSERVATION_SCHEMA_VERSION",
    "RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA_VERSION",
    "VerifiedDirectoryAggregate",
    "rejected_aggregate",
    "verify_capture",
    "verify_sanitized_pair",
]
