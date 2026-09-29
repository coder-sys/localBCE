"""Synthetic transport and V2 canonical envelope producer for NC FHIR."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
import hashlib
import json
from typing import Mapping, Protocol

from app.mirror.error_boundary import raise_redacted
from app.mirror.nc_medicaid_fhir_profile import (
    ALLOWED_MEDIA_TYPE, CLAIM_FLAGS, DEFAULT_CAPTURE_CONTEXT, DynamicCaptureContext,
    NC_MEDICAID_PROFILE, NcMedicaidFhirSourceProfile,
)


class NcMedicaidFhirError(ValueError):
    """Stable producer/fixture error boundary."""


class FhirTransportError(NcMedicaidFhirError):
    """A synthetic transport failure with a stable code."""


ENVELOPE_SCHEMA = "mirror-ncmedicaid-fhir-observation-envelope-v2"
ENVELOPE_SCHEMA_VERSION = 2
SOURCE_STATUSES = ("COMPLETE", "PARTIAL", "FAILED", "STALE")
FAILURE_CODES = {
    "wrong-host", "redirect", "rate-limit", "server-error", "timeout", "retry-exhausted",
    "retry-after", "http-status", "media-type", "schema", "noncanonical", "partial-page",
    "query-drift", "total-drift", "marker-drift", "stale", "profile-downgrade", "capability-mismatch",
    "forbidden-resource", "forbidden-field", "reference", "identifier", "period", "address", "endpoint",
}


@dataclass(frozen=True)
class FhirTransportResponse:
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


class FhirTransport(Protocol):
    def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> FhirTransportResponse:
        ...


class SyntheticFhirTransport:
    """Deterministic keyed fixture transport with no network dependency."""

    def __init__(self, responses: Mapping[tuple[str, int], FhirTransportResponse], failures: Mapping[tuple[str, int], str] | None = None) -> None:
        self._responses = dict(responses)
        self._failures = dict(failures or {})
        self.calls: list[tuple[str, int]] = []

    def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> FhirTransportResponse:
        del timeout_seconds
        self.calls.append((request_url, attempt))
        code = self._failures.get((request_url, attempt), self._failures.get((request_url, 0)))
        if code is not None:
            raise FhirTransportError(code)
        response = self._responses.get((request_url, attempt), self._responses.get((request_url, 0)))
        if response is None:
            raise FhirTransportError("timeout")
        return response


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(NcMedicaidFhirError, "json:noncanonical")


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise NcMedicaidFhirError("json:duplicate-key")
        value[key] = item
    return value


def _parse_fixture_body(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(NcMedicaidFhirError("json:constant")))
    except NcMedicaidFhirError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise_redacted(NcMedicaidFhirError, "json:parse")
    if not isinstance(value, dict):
        raise NcMedicaidFhirError("json:top-level")
    if canonical_json(value) != raw:
        raise NcMedicaidFhirError("json:noncanonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v2\0").encode("ascii"))
    digest.update(canonical_json(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/ENVELOPE/" + label + "/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _profile_required(profile: NcMedicaidFhirSourceProfile) -> None:
    if not isinstance(profile, NcMedicaidFhirSourceProfile) or profile != NC_MEDICAID_PROFILE:
        raise NcMedicaidFhirError("profile:downgrade")


def _query_parameters(profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext) -> list[list[str]]:
    return [[key, value.replace("{subject_locator_digest}", context.subject_locator_digest)] for key, value in profile.query_parameters]


def _request_identity(profile: NcMedicaidFhirSourceProfile, request_url: str, context: DynamicCaptureContext | None = None) -> str:
    context = context or DEFAULT_CAPTURE_CONTEXT
    return _digest("request", {"method": "GET", "url": request_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter})


def _response_failure(response: FhirTransportResponse | None, requested_url: str) -> str | None:
    if response is None:
        return None
    if response.redirected_to is not None:
        return "redirect"
    if response.request_url != requested_url:
        return "wrong-host"
    if response.status == 429:
        return "rate-limit"
    if response.status >= 500:
        return "server-error"
    if response.status != 200:
        return "http-status"
    if response.media_type != ALLOWED_MEDIA_TYPE:
        return "media-type"
    return None


def _retry_after(response: FhirTransportResponse) -> int | None:
    value = response.header("Retry-After")
    if value is None:
        return None
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise_redacted(NcMedicaidFhirError, "retry-after")
    if seconds < 0 or seconds > NC_MEDICAID_PROFILE.transport_caps["max_retry_after_seconds"]:
        raise NcMedicaidFhirError("retry-after")
    return seconds


def _failure_page(profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str, response: FhirTransportResponse | None, attempts: list[int], retry_after: list[int | None], failure_code: str, transport_error: str | None = None, context: DynamicCaptureContext | None = None) -> dict[str, object]:
    body_length = len(response.body) if response is not None and type(response.body) is bytes else 0
    if body_length > profile.transport_caps["max_page_bytes"]:
        failure_code = "schema"
    page: dict[str, object] = {
        "sequence": sequence, "request_url": request_url,
        "request_identity": _request_identity(profile, request_url, context),
        "response_url": response.request_url if response is not None and response.request_url == request_url else None,
        "status": response.status if response is not None else 0,
        "media_type": response.media_type if response is not None and response.media_type == ALLOWED_MEDIA_TYPE else None,
        "byte_length": 0, "body_digest": _raw_digest("page-bytes", b""), "body_hex": "",
        "attempt_statuses": attempts, "retry_after_seconds": retry_after, "bundle": None,
        "resource_digests": [], "next_url": None,
        "failure_code": failure_code if failure_code in FAILURE_CODES else "schema",
        "transport_error": transport_error,
    }
    page["page_id"] = _digest("page-id", {key: value for key, value in page.items() if key != "page_id"})
    return page


def _success_page(profile: NcMedicaidFhirSourceProfile, sequence: int, request_url: str, response: FhirTransportResponse, attempts: list[int], retry_after: list[int | None], context: DynamicCaptureContext | None = None) -> dict[str, object]:
    if len(response.body) > profile.transport_caps["max_page_bytes"]:
        return _failure_page(profile, sequence, request_url, response, attempts, retry_after, "schema", context=context)
    try:
        bundle = _parse_fixture_body(response.body)
    except NcMedicaidFhirError as exc:
        code = str(exc).split(":", 1)[-1]
        return _failure_page(profile, sequence, request_url, response, attempts, retry_after, "noncanonical" if code == "noncanonical" else "schema", context=context)
    links = bundle.get("link")
    next_url = next((link.get("url") for link in links if isinstance(link, dict) and link.get("relation") == "next"), None) if isinstance(links, list) else None
    entries = bundle.get("entry")
    resources = [entry.get("resource") for entry in entries if isinstance(entry, dict) and isinstance(entry.get("resource"), dict)] if isinstance(entries, list) else []
    page: dict[str, object] = {
        "sequence": sequence, "request_url": request_url, "request_identity": _request_identity(profile, request_url, context),
        "response_url": response.request_url, "status": response.status, "media_type": response.media_type,
        "byte_length": len(response.body), "body_digest": _raw_digest("page-bytes", response.body), "body_hex": None,
        "attempt_statuses": attempts, "retry_after_seconds": retry_after, "bundle": bundle,
        "resource_digests": [_digest("resource", resource) for resource in resources], "next_url": next_url,
        "failure_code": None, "transport_error": None,
    }
    page["page_id"] = _digest("page-id", {key: value for key, value in page.items() if key != "page_id"})
    return page


def _fetch_page(profile: NcMedicaidFhirSourceProfile, transport: FhirTransport, sequence: int, request_url: str, context: DynamicCaptureContext) -> dict[str, object]:
    attempts: list[int] = []
    retry_after_values: list[int | None] = []
    failure_code: str | None = None
    for attempt in range(profile.transport_caps["max_retries"] + 1):
        response: FhirTransportResponse | None = None
        transport_error: str | None = None
        try:
            response = transport.fetch(request_url, timeout_seconds=profile.transport_caps["timeout_seconds"], attempt=attempt)
            attempts.append(response.status)
            try:
                retry_after_values.append(_retry_after(response))
            except NcMedicaidFhirError:
                retry_after_values.append(None)
                return _failure_page(profile, sequence, request_url, response, attempts, retry_after_values, "retry-after", context=context)
            failure_code = _response_failure(response, request_url)
            if failure_code not in ("rate-limit", "server-error") or attempt >= profile.transport_caps["max_retries"]:
                break
        except FhirTransportError as exc:
            transport_error = "timeout" if exc.args == ("timeout",) else "transport"
            attempts.append(0); retry_after_values.append(None)
            if attempt >= profile.transport_caps["max_retries"]:
                failure_code = "timeout" if transport_error == "timeout" else "retry-exhausted"
                break
        except Exception:
            transport_error = "transport"
            attempts.append(0); retry_after_values.append(None)
            if attempt >= profile.transport_caps["max_retries"]:
                failure_code = "retry-exhausted"
                break
    if response is None:
        return _failure_page(profile, sequence, request_url, None, attempts, retry_after_values, failure_code or "timeout", transport_error, context)
    if failure_code is not None:
        if failure_code in ("rate-limit", "server-error") and len(attempts) > profile.transport_caps["max_retries"]:
            failure_code = "retry-exhausted"
        return _failure_page(profile, sequence, request_url, response, attempts, retry_after_values, failure_code, transport_error, context)
    return _success_page(profile, sequence, request_url, response, attempts, retry_after_values, context)


def _bundle_marker(bundle: object, key: str) -> object:
    if not isinstance(bundle, dict):
        return None
    if key == "total":
        return bundle.get("total")
    meta = bundle.get("meta")
    return meta.get("lastUpdated") if isinstance(meta, dict) else None


def _marker_age_seconds(marker: object, profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext) -> int | None:
    if marker is None:
        return None
    try:
        if type(marker) is not str:
            raise ValueError
        if len(marker) == 10 and date.fromisoformat(marker).isoformat() == marker:
            return None
        updated = datetime.fromisoformat(marker[:-1])
        if len(marker) != 20 or updated.isoformat(timespec="seconds") + "Z" != marker:
            raise ValueError
        clock = profile.capture_clock
        fetched = datetime.fromisoformat(str(clock["reference_utc"])[:-1]) + timedelta(seconds=(context.fetched_at - int(clock["reference_tick"])) * int(clock["seconds_per_tick"]))
    except (ValueError, OverflowError):
        raise_redacted(NcMedicaidFhirError, "markers:last-updated")
    age = fetched - updated
    if age < timedelta(0):
        raise NcMedicaidFhirError("markers:future")
    return age.days * 86_400 + age.seconds


def _discard_page_body(page: dict[str, object], failure_code: str) -> None:
    page.update(bundle=None, body_hex="", resource_digests=[], next_url=None, failure_code=failure_code, byte_length=0, body_digest=_raw_digest("page-bytes", b""))
    page["page_id"] = _digest("page-id", {key: value for key, value in page.items() if key != "page_id"})


def _envelope_body(profile: NcMedicaidFhirSourceProfile, context: DynamicCaptureContext, pages: list[dict[str, object]], *, source_status: str, failure_code: str | None, server_markers: dict[str, object]) -> dict[str, object]:
    snapshot_root = _digest("snapshot-root", {"page_ids": [page["page_id"] for page in pages]})
    request_url = profile.page_url(0, context)
    snapshot_id = _digest("snapshot-id", {"profile": profile.binding(context), "request_identity": _request_identity(profile, request_url, context), "capture_context": context.material(), "observation_time": context.observation_time, "fetched_at": context.fetched_at, "snapshot_root": snapshot_root, "source_status": source_status, "failure_code": failure_code, "server_markers": server_markers})
    return {
        "schema": ENVELOPE_SCHEMA, "schema_version": ENVELOPE_SCHEMA_VERSION,
        "profile": profile.binding(context),
        "capture_context": context.material(),
        "owner": {"owner": profile.owner, "system": profile.system, "base_url": profile.base_url, "host": profile.host, "fhir_version": profile.fhir_version},
        "request": {"method": "GET", "url": request_url, "query_parameters": _query_parameters(profile, context), "page_parameter": profile.page_parameter, "request_identity": _request_identity(profile, request_url, context)},
        "observation_time": context.observation_time, "fetched_at": context.fetched_at,
        "server_markers": server_markers, "pages": pages, "page_complete": source_status == "COMPLETE",
        "source_status": source_status, "failure_code": failure_code, "source_completeness": profile.completeness,
        "claims": dict(CLAIM_FLAGS), "snapshot_root": snapshot_root, "snapshot_id": snapshot_id,
    }


def build_fixture_envelope(transport: FhirTransport, *, profile: NcMedicaidFhirSourceProfile = NC_MEDICAID_PROFILE, context: DynamicCaptureContext | None = None) -> bytes:
    """Fetch only from the fixture port and emit one bounded V2 envelope."""
    _profile_required(profile)
    context = context or DEFAULT_CAPTURE_CONTEXT
    pages: list[dict[str, object]] = []
    request_url = profile.page_url(0, context)
    source_status = "COMPLETE"
    failure_code: str | None = None
    for sequence in range(profile.transport_caps["max_pages"]):
        page = _fetch_page(profile, transport, sequence, request_url, context)
        pages.append(page)
        if page["failure_code"] is not None:
            failure_code = str(page["failure_code"]); source_status = "FAILED" if sequence == 0 else "PARTIAL"; break
        next_url = page.get("next_url")
        if next_url is None:
            break
        if sequence + 1 >= profile.transport_caps["max_pages"]:
            _discard_page_body(page, "partial-page"); failure_code = "partial-page"; source_status = "PARTIAL"; break
        expected_next = profile.page_url(sequence + 1, context)
        if next_url != expected_next:
            _discard_page_body(page, "query-drift"); failure_code = "query-drift"; source_status = "PARTIAL"; break
        request_url = next_url
    else:
        source_status = "PARTIAL"; failure_code = "partial-page"
    if pages and pages[-1].get("next_url") is not None and source_status == "COMPLETE":
        source_status = "PARTIAL"; failure_code = "partial-page"
    totals = [_bundle_marker(page.get("bundle"), "total") for page in pages if page.get("failure_code") is None]
    markers = [_bundle_marker(page.get("bundle"), "last_updated") for page in pages if page.get("failure_code") is None]
    marker_ages = [_marker_age_seconds(marker, profile, context) for marker in markers]
    total_values = {value for value in totals if value is not None}; marker_values = {value for value in markers if value is not None}
    if len(total_values) > 1 or (total_values and sum(value is not None for value in totals) != len(totals)):
        failure_code = "total-drift"; source_status = "PARTIAL"
    if len(marker_values) > 1 or (marker_values and sum(value is not None for value in markers) != len(markers)):
        failure_code = "marker-drift"; source_status = "PARTIAL"
    server_markers = {"total": next(iter(total_values)) if len(total_values) == 1 and all(value is not None for value in totals) else None, "last_updated": next(iter(marker_values)) if len(marker_values) == 1 and all(value is not None for value in markers) else None}
    if failure_code is None and marker_ages and marker_ages[0] is not None and marker_ages[0] > profile.max_server_marker_age_days * 86_400:
        failure_code = "stale"
        source_status = "STALE"
    body = _envelope_body(profile, context, pages, source_status=source_status, failure_code=failure_code, server_markers=server_markers)
    body["envelope_id"] = _digest("envelope-id", body)
    raw = canonical_json(body)
    if len(raw) > profile.transport_caps["complete_frame_bytes"] or len(raw) > profile.transport_caps["max_envelope_bytes"]:
        raise NcMedicaidFhirError("envelope:byte-cap")
    return raw


def fixture_response(bundle: Mapping[str, object], request_url: str, *, status: int = 200, media_type: str | None = ALLOWED_MEDIA_TYPE, headers: tuple[tuple[str, str], ...] = ()) -> FhirTransportResponse:
    return FhirTransportResponse(request_url, status, media_type, canonical_json(dict(bundle)), headers)


__all__ = [
    "ENVELOPE_SCHEMA", "ENVELOPE_SCHEMA_VERSION", "FAILURE_CODES", "FhirTransport", "FhirTransportError",
    "FhirTransportResponse", "NcMedicaidFhirError", "SOURCE_STATUSES",
    "SyntheticFhirTransport", "build_fixture_envelope", "canonical_json", "fixture_response",
    "_digest", "_raw_digest", "_request_identity",
]
