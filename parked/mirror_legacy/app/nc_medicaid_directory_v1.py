"""Bounded synthetic-port adapter for NC Medicaid directory observations.

The adapter owns transport orchestration and transient capture construction.
It never creates a network client or durable state.  Raw response-shaped
capture bytes exist only between the local capture builder and the
independent verifier; the public return value is aggregate-only.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import time
from typing import Callable, Mapping, Protocol
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from app.mirror.error_boundary import raise_redacted
from parked.mirror_legacy.app.nc_medicaid_directory_profile_v1 import (
    ALLOWED_MEDIA_TYPE,
    CONTINUATION_PARAMETER_NAMES,
    FORBIDDEN_QUERY_PARAMETERS,
    NC_MEDICAID_DIRECTORY_PROFILE_V1,
    DirectoryOperationContext,
    NcMedicaidDirectoryProfileV1,
)
from parked.mirror_legacy.app import nc_medicaid_directory_v1_independent as independent


CAPTURE_SCHEMA = "mirror-ncmedicaid-provider-directory-capture-v1"
CAPTURE_SCHEMA_VERSION = 1
OBSERVATION_SCHEMA = "mirror-ncmedicaid-provider-directory-observation-result-v1"
OBSERVATION_SCHEMA_VERSION = 1
RECEIPT_SCHEMA = "mirror-ncmedicaid-provider-directory-verification-receipt-v1"
RECEIPT_SCHEMA_VERSION = 1
OPERATION_BINDING_DOMAIN = b"BL/MIRROR/NC-MEDICAID/DIRECTORY/OPERATION/v1\0"
OBSERVATION_DIGEST_DOMAIN = b"BL/MIRROR/NC-MEDICAID/DIRECTORY/SANITIZED/v1\0"
RETRYABLE_FAILURES = frozenset({"rate-limit", "server-error", "transport", "timeout"})
KNOWN_CAPTURE_FAILURES = frozenset(
    {
        "adapter-rejected",
        "body-type",
        "capture-cap",
        "duplicate-key",
        "json-constant",
        "json-integer-cap",
        "json-parse",
        "json-shape",
        "json-string-cap",
        "json-walk-cap",
        "media-type",
        "next-link",
        "page-cap",
        "profile",
        "request-cap",
        "resource-cap",
        "resource-release",
        "response-cap",
        "response-total-cap",
        "retry-after",
        "timeout",
        "transport",
        "wrong-host",
        "redirect",
        "http-status",
    }
)
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MAX_SIGNED_INT = 2**63 - 1
_DATE_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$"
)


class NcMedicaidDirectoryError(ValueError):
    """Public adapter error with a fixed code and no raw context."""


@dataclass(frozen=True)
class DirectoryTransportResponse:
    """Response value supplied by a synthetic transport port."""

    request_url: str
    status: int
    media_type: str | None
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()
    redirected_to: str | None = None

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None


class DirectoryTransport(Protocol):
    """Synchronous bounded transport seam; no implementation is provided."""

    def fetch(
        self,
        request_url: str,
        *,
        timeout_seconds: int,
        attempt: int,
    ) -> DirectoryTransportResponse:
        ...


@dataclass(frozen=True)
class DirectoryAdmission:
    """The only public adapter result."""

    accepted: bool
    observation: bytes
    verification_receipt: bytes | None
    telemetry: tuple[tuple[str, int | bool | str | None], ...]


class _CaptureFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


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
        raise _CaptureFailure("json-parse") from None


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
            raise _CaptureFailure("duplicate-key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise _CaptureFailure("json-constant")


def _walk_bounded(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    depth: int = 0,
    count: list[int] | None = None,
) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > profile.transport_caps["max_nodes"]:
        raise _CaptureFailure("json-walk-cap")
    if depth > profile.transport_caps["max_depth"]:
        raise _CaptureFailure("json-walk-cap")
    if isinstance(value, float):
        raise _CaptureFailure("json-constant")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -(2**63) or value > 2**63 - 1:
            raise _CaptureFailure("json-integer-cap")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
            raise _CaptureFailure("json-string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _CaptureFailure("json-shape")
            _walk_bounded(key, profile, depth=depth + 1, count=count)
            _walk_bounded(item, profile, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk_bounded(item, profile, depth=depth + 1, count=count)
    elif value is not None and not isinstance(value, (bool, int)):
        raise _CaptureFailure("json-shape")


def _parse_document(
    raw: object,
    profile: NcMedicaidDirectoryProfileV1,
) -> dict[str, object]:
    if type(raw) is not bytes:
        raise _CaptureFailure("body-type")
    if not raw or len(raw) > profile.transport_caps["max_response_bytes"]:
        raise _CaptureFailure("response-cap")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _CaptureFailure:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _CaptureFailure("json-parse") from None
    if not isinstance(value, dict):
        raise _CaptureFailure("json-shape")
    _walk_bounded(value, profile)
    return value


def _media_type_allowed(value: object) -> bool:
    if type(value) is not str:
        return False
    pieces = [piece.strip() for piece in value.split(";")]
    if not pieces or pieces[0].lower() != ALLOWED_MEDIA_TYPE:
        return False
    parameters: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            return False
        name, parameter = piece.split("=", 1)
        name = name.strip().lower()
        parameter = parameter.strip()
        if not name or name in parameters:
            return False
        parameters[name] = parameter
    if "fhirversion" in parameters and parameters["fhirversion"] != "4.0":
        return False
    return all(name in {"fhirversion", "charset"} for name in parameters)


def _header(response: object, name: str) -> object:
    try:
        method = getattr(response, "header")
    except Exception:
        method = None
    if callable(method):
        try:
            return method(name)
        except Exception:
            return None
    try:
        headers = getattr(response, "headers")
    except Exception:
        return None
    if not isinstance(headers, (tuple, list)):
        return None
    wanted = name.lower()
    for pair in headers:
        if isinstance(pair, (tuple, list)) and len(pair) == 2:
            key, value = pair
            if isinstance(key, str) and key.lower() == wanted:
                return value
    return None


def _retry_after(response: object, profile: NcMedicaidDirectoryProfileV1) -> int | None:
    raw = _header(response, "Retry-After")
    if raw is None:
        return None
    if type(raw) is not str or re.fullmatch(r"\d{1,3}", raw.strip()) is None:
        raise _CaptureFailure("retry-after")
    value = int(raw.strip())
    if value > profile.transport_caps["max_retry_after_seconds"]:
        raise _CaptureFailure("retry-after")
    return value


def _release_response(response: object) -> bool:
    try:
        closer = getattr(response, "close", None)
    except Exception:
        return False
    if closer is None:
        return True
    if not callable(closer):
        return False
    try:
        closer()
    except Exception:
        return False
    return True


def _safe_query(
    url: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
    required_filter: Mapping[str, str],
    continuation: bool,
) -> bool:
    if type(url) is not str:
        return False
    if len(url.encode("utf-8")) > profile.transport_caps["max_url_bytes"]:
        return False
    if "\\" in url or "#" in url:
        return False
    try:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or parts.hostname != profile.host
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or parts.path != "/fhir/" + resource_type
            or parts.port not in (None, 443)
            or "+" in parts.query
        ):
            return False
    except (ValueError, AttributeError):
        return False
    raw_path = parts.path.lower()
    if any(token in raw_path for token in ("%2f", "%5c", "%2e", "%00")):
        return False
    if re.search(r"%(?![0-9A-Fa-f]{2})", parts.query):
        return False
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except (TypeError, ValueError):
        return False
    if not pairs or len(pairs) > 12:
        return False
    query: dict[str, str] = {}
    for key, value in pairs:
        if key in query or not key or len(value.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
            return False
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in key + value):
            return False
        query[key] = value
    for key in FORBIDDEN_QUERY_PARAMETERS:
        if key in query:
            return False
    for key, value in required_filter.items():
        if query.get(key) != value:
            return False
    allowed_extra = {"_count"}
    if continuation:
        allowed_extra.update(CONTINUATION_PARAMETER_NAMES)
    if any(key not in required_filter and key not in allowed_extra for key in query):
        return False
    if "_count" in query:
        if re.fullmatch(r"[1-9]\d{0,2}", query["_count"]) is None:
            return False
        if int(query["_count"]) > profile.transport_caps["max_page_resources"]:
            return False
    return True


def _safe_read_url(
    url: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    location_id: str,
) -> bool:
    if type(url) is not str or len(url.encode("utf-8")) > profile.transport_caps["max_url_bytes"]:
        return False
    if location_id == "." or location_id == "..":
        return False
    if "\\" in url or "#" in url or "?" in url:
        return False
    try:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or parts.hostname != profile.host
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path != "/fhir/Location/" + location_id
            or parts.port not in (None, 443)
        ):
            return False
    except (ValueError, AttributeError):
        return False
    return not any(
        token in parts.path.lower() for token in ("%2f", "%5c", "%2e", "%00")
    )


def _reference_id(
    value: object,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    resource_type: str,
) -> str | None:
    if not isinstance(value, dict):
        return None
    reference = value.get("reference")
    if type(reference) is not str or len(reference.encode("utf-8")) > profile.transport_caps["max_string_bytes"]:
        return None
    if "identifier" in value:
        return None
    if "type" in value and value["type"] != resource_type:
        return None
    relative = resource_type + "/"
    if reference.startswith("https://"):
        try:
            parts = urlsplit(reference)
            if (
                parts.scheme != "https"
                or parts.hostname != profile.host
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or parts.path.startswith("/fhir/") is False
                or parts.port not in (None, 443)
            ):
                return None
            reference = parts.path.removeprefix("/fhir/")
        except (ValueError, AttributeError):
            return None
    if not reference.startswith(relative):
        return None
    identifier = reference[len(relative):]
    if _ID_PATTERN.fullmatch(identifier) is None:
        return None
    if resource_type == "Location" and (identifier == "." or identifier == ".."):
        return None
    return identifier


def _peek_next(document: dict[str, object]) -> str | None:
    links = document.get("link")
    if not isinstance(links, list):
        return None
    found: str | None = None
    for link in links:
        if not isinstance(link, dict):
            continue
        if link.get("relation") == "next":
            value = link.get("url")
            if type(value) is not str or found is not None:
                raise _CaptureFailure("next-link")
            found = value
    return found


def _empty_operation(
    sequence: int,
    *,
    kind: str,
    resource_type: str,
    request_url: str,
    request_filter: Mapping[str, str],
    failure_code: str,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "kind": kind,
        "resource_type": resource_type,
        "request_url": request_url,
        "filter": dict(request_filter),
        "attempt_statuses": [],
        "attempt_byte_lengths": [],
        "attempt_failure_codes": [],
        "retry_after_seconds": [],
        "response_status": 0,
        "response_media_type": None,
        "response_url": None,
        "byte_length": 0,
        "document": None,
        "next_url": None,
        "failure_code": failure_code,
    }


def _fetch_operation(
    transport: DirectoryTransport,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    sequence: int,
    kind: str,
    resource_type: str,
    request_url: str,
    request_filter: Mapping[str, str],
    total_response_bytes: int,
    monotonic_clock: Callable[[], float],
) -> tuple[dict[str, object], int]:
    attempts: list[int] = []
    attempt_byte_lengths: list[int] = []
    attempt_failure_codes: list[str | None] = []
    retry_after_values: list[int | None] = []
    response_status = 0
    response_media_type: str | None = None
    response_url: str | None = None
    byte_length = 0
    document: dict[str, object] | None = None
    failure_code: str | None = None

    for attempt in range(profile.transport_caps["max_retries"] + 1):
        response: object | None = None
        attempt_status = 0
        attempt_bytes = 0
        attempt_retry_after: int | None = None
        started = 0.0
        elapsed = 0.0
        try:
            started = monotonic_clock()
            response = transport.fetch(
                request_url,
                timeout_seconds=profile.transport_caps["timeout_seconds"],
                attempt=attempt,
            )
            elapsed = monotonic_clock() - started
            raw_status = getattr(response, "status")
            attempt_status = raw_status if type(raw_status) is int else 0
            raw_body = getattr(response, "body")
            attempt_bytes = len(raw_body) if type(raw_body) is bytes else 0
            attempt_retry_after = _retry_after(response, profile)
            if type(raw_body) is not bytes:
                failure_code = "body-type"
            elif len(raw_body) > profile.transport_caps["max_response_bytes"]:
                failure_code = "response-cap"
            elif elapsed > profile.transport_caps["timeout_seconds"]:
                failure_code = "timeout"
            elif attempt_status != 200:
                if attempt_status == 429:
                    failure_code = "rate-limit"
                elif 500 <= attempt_status <= 599:
                    failure_code = "server-error"
                else:
                    failure_code = "http-status"
            elif getattr(response, "redirected_to", None) is not None:
                failure_code = "redirect"
            elif getattr(response, "request_url", None) != request_url:
                failure_code = "wrong-host"
            elif not _media_type_allowed(getattr(response, "media_type", None)):
                failure_code = "media-type"
            elif not raw_body:
                failure_code = "response-cap"
            elif total_response_bytes + len(raw_body) > profile.transport_caps["max_total_response_bytes"]:
                failure_code = "response-total-cap"
            else:
                document = _parse_document(raw_body, profile)
                failure_code = None
        except _CaptureFailure as exc:
            failure_code = exc.code
        except TimeoutError:
            failure_code = "timeout"
        except Exception:
            failure_code = "transport"
        finally:
            if response is not None and not _release_response(response):
                failure_code = "resource-release"

        attempts.append(attempt_status)
        attempt_byte_lengths.append(
            min(attempt_bytes, profile.transport_caps["max_response_bytes"] + 1)
        )
        attempt_failure_codes.append(failure_code)
        retry_after_values.append(attempt_retry_after)
        total_response_bytes += attempt_bytes
        response_status = attempt_status
        if response is not None and failure_code is None:
            response_media_type = getattr(response, "media_type", None)
            response_url = request_url
            byte_length = attempt_bytes
        else:
            response_media_type = None
            response_url = None
            byte_length = 0
            document = None

        if failure_code in RETRYABLE_FAILURES and attempt < profile.transport_caps["max_retries"]:
            continue
        if failure_code in RETRYABLE_FAILURES:
            failure_code = "retry-exhausted"
        break

    next_url: str | None = None
    if failure_code is None and document is not None:
        try:
            next_url = _peek_next(document)
        except _CaptureFailure as exc:
            failure_code = exc.code
            document = None
            response_media_type = None
            response_url = None
            byte_length = 0

    return (
        {
            "sequence": sequence,
            "kind": kind,
            "resource_type": resource_type,
            "request_url": request_url,
            "filter": dict(request_filter),
            "attempt_statuses": attempts,
            "attempt_byte_lengths": attempt_byte_lengths,
            "attempt_failure_codes": attempt_failure_codes,
            "retry_after_seconds": retry_after_values,
            "response_status": response_status,
            "response_media_type": response_media_type,
            "response_url": response_url,
            "byte_length": byte_length,
            "document": document,
            "next_url": next_url,
            "failure_code": failure_code,
        },
        total_response_bytes,
    )


def _append_boundary_failure(
    operations: list[dict[str, object]],
    *,
    kind: str,
    resource_type: str,
    request_url: str,
    request_filter: Mapping[str, str],
    failure_code: str,
) -> None:
    operations.append(
        _empty_operation(
            len(operations),
            kind=kind,
            resource_type=resource_type,
            request_url=request_url,
            request_filter=request_filter,
            failure_code=failure_code,
        )
    )


def _capture_search(
    transport: DirectoryTransport,
    profile: NcMedicaidDirectoryProfileV1,
    *,
    operations: list[dict[str, object]],
    resource_type: str,
    initial_url: str,
    request_filter: Mapping[str, str],
    total_response_bytes: int,
    total_search_pages: int,
    monotonic_clock: Callable[[], float],
) -> tuple[int, int]:
    current_url = initial_url
    seen_urls: set[str] = set()
    pages = 0
    while True:
        if len(operations) >= profile.transport_caps["max_requests"]:
            _append_boundary_failure(
                operations,
                kind="search",
                resource_type=resource_type,
                request_url=current_url,
                request_filter=request_filter,
                failure_code="request-cap",
            )
            return total_response_bytes, total_search_pages
        if (
            pages >= profile.transport_caps["max_search_pages"]
            or total_search_pages >= profile.transport_caps["max_search_pages_total"]
        ):
            _append_boundary_failure(
                operations,
                kind="search",
                resource_type=resource_type,
                request_url=current_url,
                request_filter=request_filter,
                failure_code="page-cap",
            )
            return total_response_bytes, total_search_pages
        if current_url in seen_urls:
            _append_boundary_failure(
                operations,
                kind="search",
                resource_type=resource_type,
                request_url=current_url,
                request_filter=request_filter,
                failure_code="next-link",
            )
            return total_response_bytes, total_search_pages
        continuation = pages > 0
        if not _safe_query(
            current_url,
            profile,
            resource_type=resource_type,
            required_filter=request_filter,
            continuation=continuation,
        ):
            _append_boundary_failure(
                operations,
                kind="search",
                resource_type=resource_type,
                request_url=current_url,
                request_filter=request_filter,
                failure_code="next-link",
            )
            return total_response_bytes, total_search_pages
        seen_urls.add(current_url)
        operation, total_response_bytes = _fetch_operation(
            transport,
            profile,
            sequence=len(operations),
            kind="search",
            resource_type=resource_type,
            request_url=current_url,
            request_filter=request_filter,
            total_response_bytes=total_response_bytes,
            monotonic_clock=monotonic_clock,
        )
        operations.append(operation)
        pages += 1
        total_search_pages += 1
        if operation["failure_code"] is not None:
            return total_response_bytes, total_search_pages
        next_url = operation["next_url"]
        if next_url is None:
            return total_response_bytes, total_search_pages
        if not _safe_query(
            next_url,
            profile,
            resource_type=resource_type,
            required_filter=request_filter,
            continuation=True,
        ):
            operation["failure_code"] = "next-link"
            return total_response_bytes, total_search_pages
        current_url = next_url


def _practitioner_present(
    operations: list[dict[str, object]],
    practitioner_id: str,
) -> bool:
    found: list[str] = []
    for operation in operations:
        if operation.get("resource_type") != "Practitioner":
            continue
        document = operation.get("document")
        if not isinstance(document, dict):
            continue
        entries = document.get("entry")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            resource = entry.get("resource")
            if (
                isinstance(resource, dict)
                and resource.get("resourceType") == "Practitioner"
            ):
                resource_id = resource.get("id")
                if not isinstance(resource_id, str):
                    return False
                found.append(resource_id)
    return found == [practitioner_id]


def _location_ids_from_roles(
    operations: list[dict[str, object]],
    profile: NcMedicaidDirectoryProfileV1,
    *,
    practitioner_id: str,
) -> list[str] | None:
    location_ids: list[str] = []
    for operation in operations:
        if operation.get("resource_type") != "PractitionerRole":
            continue
        document = operation.get("document")
        if not isinstance(document, dict):
            continue
        entries = document.get("entry")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            resource = entry.get("resource")
            if not isinstance(resource, dict):
                continue
            if resource.get("resourceType") != "PractitionerRole":
                return None
            if (
                _reference_id(
                    resource.get("practitioner"),
                    profile,
                    resource_type="Practitioner",
                )
                != practitioner_id
            ):
                return None
            locations = resource.get("location")
            if locations is None:
                continue
            if not isinstance(locations, list):
                return None
            if len(locations) > profile.transport_caps["max_location_reads"]:
                return None
            seen_in_role: set[str] = set()
            for reference in locations:
                location_id = _reference_id(
                    reference,
                    profile,
                    resource_type="Location",
                )
                if location_id is None:
                    return None
                if location_id in seen_in_role:
                    return None
                seen_in_role.add(location_id)
                if location_id not in location_ids:
                    location_ids.append(location_id)
                    if len(location_ids) > profile.transport_caps["max_location_reads"]:
                        return location_ids
    return location_ids


def _entry_count(
    operations: list[dict[str, object]],
    resource_type: str,
) -> int:
    count = 0
    for operation in operations:
        if operation.get("resource_type") != resource_type:
            continue
        document = operation.get("document")
        if not isinstance(document, dict):
            continue
        entries = document.get("entry")
        if isinstance(entries, list):
            count += len(entries)
    return count


def _build_capture(
    transport: DirectoryTransport,
    profile: NcMedicaidDirectoryProfileV1,
    context: DirectoryOperationContext,
    *,
    observation_time: int,
    fetched_at: int,
    monotonic_clock: Callable[[], float],
) -> bytes:
    operations: list[dict[str, object]] = []
    total_response_bytes = 0
    total_search_pages = 0
    practitioner_filter = {"_id": context.practitioner_id}
    total_response_bytes, total_search_pages = _capture_search(
        transport,
        profile,
        operations=operations,
        resource_type="Practitioner",
        initial_url=profile.practitioner_search_url(context.practitioner_id),
        request_filter=practitioner_filter,
        total_response_bytes=total_response_bytes,
        total_search_pages=total_search_pages,
        monotonic_clock=monotonic_clock,
    )
    if (
        operations
        and operations[-1]["failure_code"] is None
        and _practitioner_present(operations, context.practitioner_id)
    ):
        role_filter = {"practitioner": "Practitioner/" + context.practitioner_id}
        total_response_bytes, total_search_pages = _capture_search(
            transport,
            profile,
            operations=operations,
            resource_type="PractitionerRole",
            initial_url=profile.practitioner_role_search_url(
                context.practitioner_id
            ),
            request_filter=role_filter,
            total_response_bytes=total_response_bytes,
            total_search_pages=total_search_pages,
            monotonic_clock=monotonic_clock,
        )
        if operations and operations[-1]["failure_code"] is None:
            location_ids = _location_ids_from_roles(
                operations,
                profile,
                practitioner_id=context.practitioner_id,
            )
            if location_ids is not None:
                if len(location_ids) > profile.transport_caps["max_location_reads"]:
                    _append_boundary_failure(
                        operations,
                        kind="read",
                        resource_type="Location",
                        request_url=profile.location_read_url(
                            location_ids[profile.transport_caps["max_location_reads"]]
                        ),
                        request_filter={
                            "id": location_ids[
                                profile.transport_caps["max_location_reads"]
                            ]
                        },
                        failure_code="resource-cap",
                    )
                elif (
                    1
                    + _entry_count(operations, "PractitionerRole")
                    + len(location_ids)
                    > profile.transport_caps["max_total_resources"]
                    and bool(location_ids)
                ):
                    _append_boundary_failure(
                        operations,
                        kind="read",
                        resource_type="Location",
                        request_url=profile.location_read_url(location_ids[0]),
                        request_filter={"id": location_ids[0]},
                        failure_code="resource-cap",
                    )
                else:
                    for location_id in location_ids:
                        if len(operations) >= profile.transport_caps["max_requests"]:
                            _append_boundary_failure(
                                operations,
                                kind="read",
                                resource_type="Location",
                                request_url=profile.location_read_url(location_id),
                                request_filter={"id": location_id},
                                failure_code="request-cap",
                            )
                            break
                        operation, total_response_bytes = _fetch_operation(
                            transport,
                            profile,
                            sequence=len(operations),
                            kind="read",
                            resource_type="Location",
                            request_url=profile.location_read_url(location_id),
                            request_filter={"id": location_id},
                            total_response_bytes=total_response_bytes,
                            monotonic_clock=monotonic_clock,
                        )
                        operations.append(operation)
                        if operation["failure_code"] is not None:
                            break

    capture: dict[str, object] = {
        "schema": CAPTURE_SCHEMA,
        "schema_version": CAPTURE_SCHEMA_VERSION,
        "profile": {
            "source_profile_id": profile.source_profile_id,
            "source_profile_version": profile.source_profile_version,
            "source_contract_digest": profile.profile_digest,
            "capability_statement_digest": profile.capability_statement_digest,
            "fhir_version": profile.fhir_version,
            "verifier_id": independent.VERIFIER_ID,
            "verifier_epoch": independent.VERIFIER_EPOCH,
        },
        "operation": {
            "operation_ref": context.operation_ref,
            "practitioner_id": context.practitioner_id,
            "observation_time": observation_time,
            "fetched_at": fetched_at,
            "operation_binding": _operation_binding(context.operation_ref),
        },
        "operations": operations,
        "capture_failure": None,
    }
    try:
        raw = _canonical(capture)
    except _CaptureFailure:
        raw = b""
    if not raw or len(raw) > profile.transport_caps["max_capture_bytes"]:
        capture = {
            "schema": CAPTURE_SCHEMA,
            "schema_version": CAPTURE_SCHEMA_VERSION,
            "profile": {
                "source_profile_id": profile.source_profile_id,
                "source_profile_version": profile.source_profile_version,
                "source_contract_digest": profile.profile_digest,
                "capability_statement_digest": profile.capability_statement_digest,
                "fhir_version": profile.fhir_version,
                "verifier_id": independent.VERIFIER_ID,
                "verifier_epoch": independent.VERIFIER_EPOCH,
            },
            "operation": {
                "operation_ref": context.operation_ref,
                "practitioner_id": context.practitioner_id,
                "observation_time": observation_time,
                "fetched_at": fetched_at,
                "operation_binding": _operation_binding(context.operation_ref),
            },
            "operations": [],
            "capture_failure": "capture-cap",
        }
        raw = _canonical(capture)
    return raw


def _safe_observation(
    checked: independent.VerifiedDirectoryAggregate,
    profile: NcMedicaidDirectoryProfileV1,
) -> bytes:
    value = {
        "schema": OBSERVATION_SCHEMA,
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "profile_id": profile.source_profile_id,
        "profile_version": profile.source_profile_version,
        "source_contract_digest": checked.source_contract_digest,
        "verifier_id": checked.verifier_id,
        "verifier_epoch": checked.verifier_epoch,
        "observation_time": checked.observation_time,
        "fetched_at": checked.fetched_at,
        "accepted": checked.accepted,
        "outcome": "DIRECTORY_OBSERVED" if checked.accepted else "REJECTED",
        "source_status": checked.source_status,
        "traversal_status": checked.traversal_status,
        "capture_age": checked.capture_age,
        "source_freshness": checked.source_freshness,
        "dataset_completeness": checked.dataset_completeness,
        "failure_code": checked.failure_code,
        "practitioner_count": checked.practitioner_count,
        "role_count": checked.role_count,
        "location_count": checked.location_count,
        "search_page_count": checked.search_page_count,
        "location_read_count": checked.location_read_count,
        "request_count": checked.request_count,
        "response_count": checked.response_count,
        "retry_count": checked.retry_count,
        "ignored_field_count": checked.ignored_field_count,
        "ignored_field_reasons": {
            key: count for key, count in checked.ignored_field_reasons
        },
        "flags": {
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
        },
    }
    return _canonical(value)


def _safe_receipt(
    observation: bytes,
    checked: independent.VerifiedDirectoryAggregate,
    context: DirectoryOperationContext,
) -> bytes:
    value = {
        "schema": RECEIPT_SCHEMA,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "profile_id": checked.profile_id,
        "profile_version": checked.profile_version,
        "source_contract_digest": checked.source_contract_digest,
        "verifier_id": checked.verifier_id,
        "verifier_epoch": checked.verifier_epoch,
        "verification_status": "VERIFIED_AT_TIME",
        "operation_binding": _operation_binding(context.operation_ref),
        "observation_digest": _digest(OBSERVATION_DIGEST_DOMAIN, observation),
        "issued_at": checked.fetched_at,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
        "proofSuiteId": None,
    }
    return _canonical(value)


def _fallback_aggregate(
    profile: NcMedicaidDirectoryProfileV1,
    *,
    observation_time: int,
    fetched_at: int,
    failure_code: str,
) -> independent.VerifiedDirectoryAggregate:
    return independent.rejected_aggregate(
        profile,
        observation_time=observation_time,
        fetched_at=fetched_at,
        failure_code=failure_code
    )


class NcMedicaidDirectoryAdapterV1:
    """Run one synthetic-port directory operation without persistence."""

    def __init__(
        self,
        transport: DirectoryTransport,
        *,
        profile: NcMedicaidDirectoryProfileV1 = NC_MEDICAID_DIRECTORY_PROFILE_V1,
        clock: Callable[[], int] | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(profile, NcMedicaidDirectoryProfileV1):
            raise_redacted(NcMedicaidDirectoryError, "profile")
        try:
            fetch = getattr(transport, "fetch", None)
        except Exception:
            raise_redacted(NcMedicaidDirectoryError, "transport")
        if not callable(fetch):
            raise_redacted(NcMedicaidDirectoryError, "transport")
        if clock is not None and not callable(clock):
            raise_redacted(NcMedicaidDirectoryError, "clock")
        if not callable(monotonic_clock):
            raise_redacted(NcMedicaidDirectoryError, "clock")
        self._transport = transport
        self._profile = profile
        self._clock = clock or (lambda: int(time.time()))
        self._monotonic_clock = monotonic_clock

    @property
    def profile(self) -> NcMedicaidDirectoryProfileV1:
        return self._profile

    def admit(self, context: DirectoryOperationContext) -> DirectoryAdmission:
        if not isinstance(context, DirectoryOperationContext):
            raise_redacted(NcMedicaidDirectoryError, "context")
        try:
            observation_time = self._clock()
            if (
                type(observation_time) is not int
                or not 0 <= observation_time <= _MAX_SIGNED_INT
            ):
                raise ValueError
            capture = _build_capture(
                self._transport,
                self._profile,
                context,
                observation_time=observation_time,
                fetched_at=observation_time,
                monotonic_clock=self._monotonic_clock,
            )
            fetched_at = self._clock()
            if (
                type(fetched_at) is not int
                or not observation_time <= fetched_at <= _MAX_SIGNED_INT
            ):
                raise ValueError
            # Rebind verifier-owned end time into the transient capture without
            # exposing the raw capture to the caller.
            value = json.loads(capture.decode("ascii"))
            value["operation"]["fetched_at"] = fetched_at
            capture = _canonical(value)
            checked = independent.verify_capture(
                capture,
                profile=self._profile,
                context=context,
                observation_time=observation_time,
                fetched_at=fetched_at,
            )
        except independent.DirectoryIndependentError as exc:
            code = str(exc)
            if code not in independent.FAILURE_CODES:
                code = "capture-rejected"
            checked = _fallback_aggregate(
                self._profile,
                observation_time=locals().get("observation_time", 0),
                fetched_at=locals().get("fetched_at", locals().get("observation_time", 0)),
                failure_code=code,
            )
            fetched_at = checked.fetched_at
        except Exception:
            observation_time = locals().get("observation_time", 0)
            fetched_at = locals().get("fetched_at", observation_time)
            if (
                type(observation_time) is not int
                or not 0 <= observation_time <= _MAX_SIGNED_INT
            ):
                observation_time = 0
            if (
                type(fetched_at) is not int
                or not observation_time <= fetched_at <= _MAX_SIGNED_INT
            ):
                fetched_at = observation_time
            checked = _fallback_aggregate(
                self._profile,
                observation_time=observation_time,
                fetched_at=fetched_at,
                failure_code="adapter-rejected",
            )
        finally:
            if "capture" in locals():
                del capture
            if "value" in locals():
                del value

        observation = _safe_observation(checked, self._profile)
        receipt = (
            _safe_receipt(observation, checked, context)
            if checked.accepted
            else None
        )
        if receipt is not None:
            try:
                independent.verify_sanitized_pair(
                    observation,
                    receipt,
                    profile=self._profile,
                )
            except Exception:
                raise_redacted(NcMedicaidDirectoryError, "output")
        telemetry = (
            ("request_count", checked.request_count),
            ("response_count", checked.response_count),
            ("search_page_count", checked.search_page_count),
            ("location_read_count", checked.location_read_count),
            ("resource_count", checked.resource_count),
            ("retry_count", checked.retry_count),
            ("ignored_field_count", checked.ignored_field_count),
            ("traversal_status", checked.traversal_status),
            ("source_freshness", checked.source_freshness),
            ("dataset_completeness", checked.dataset_completeness),
            ("failure_code", checked.failure_code),
        )
        return DirectoryAdmission(
            accepted=checked.accepted,
            observation=observation,
            verification_receipt=receipt,
            telemetry=telemetry,
        )


__all__ = [
    "ALLOWED_MEDIA_TYPE",
    "CAPTURE_SCHEMA",
    "CAPTURE_SCHEMA_VERSION",
    "DirectoryAdmission",
    "DirectoryTransport",
    "DirectoryTransportResponse",
    "NcMedicaidDirectoryAdapterV1",
    "NcMedicaidDirectoryError",
    "OBSERVATION_SCHEMA",
    "OBSERVATION_SCHEMA_VERSION",
    "RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA_VERSION",
]
