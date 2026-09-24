"""Bounded synthetic-port tests for the NC Medicaid directory observation adapter."""

from __future__ import annotations

from dataclasses import dataclass
import json
import unittest

from app.mirror import nc_medicaid_directory_v1 as directory
from app.mirror import nc_medicaid_directory_v1_independent as independent
from app.mirror.nc_medicaid_directory_profile_v1 import (
    BASE_URL,
    DirectoryOperationContext,
    NC_MEDICAID_DIRECTORY_PROFILE_V1,
    NcMedicaidDirectoryProfileError,
)


PROFILE = NC_MEDICAID_DIRECTORY_PROFILE_V1
PRACTITIONER_ID = "practitioner-7"
ROLE_ID = "role-7"
LOCATION_ID = "location-7"
OPERATION_REF = "a" * 128
CONTEXT = DirectoryOperationContext(OPERATION_REF, PRACTITIONER_ID)


def _body(value: object) -> bytes:
    # Deliberately noncanonical server JSON: the adapter must derive its own
    # canonical transient capture rather than require server byte stability.
    return json.dumps(value, ensure_ascii=True, indent=2).encode("ascii")


def _bundle(
    request_url: str,
    resources: list[dict[str, object]],
    *,
    next_url: str | None = None,
    total: int | None = None,
) -> dict[str, object]:
    links: list[dict[str, str]] = [
        {"url": request_url, "relation": "self"},
    ]
    if next_url is not None:
        links.append({"url": next_url, "relation": "next"})
    entries = [
        {
            "resource": resource,
            "fullUrl": (
                BASE_URL
                + "/"
                + str(resource["resourceType"])
                + "/"
                + str(resource["id"])
            ),
            "search": {"mode": "match"},
        }
        for resource in resources
    ]
    value: dict[str, object] = {
        "type": "searchset",
        "resourceType": "Bundle",
        "link": links,
        "entry": entries,
    }
    if total is not None:
        value["total"] = total
    return value


def _resources(
    *,
    practitioner_id: str = PRACTITIONER_ID,
    role_id: str = ROLE_ID,
    location_ids: tuple[str, ...] = (LOCATION_ID,),
) -> tuple[dict[str, object], dict[str, object], dict[str, dict[str, object]]]:
    practitioner: dict[str, object] = {
        "resourceType": "Practitioner",
        "id": practitioner_id,
        "active": True,
        "meta": {
            "lastUpdated": "2026-09-12T12:00:00Z",
            "tag": [{"system": "https://secret.invalid", "code": "secret"}],
        },
        "identifier": [{"system": "https://secret.invalid", "value": "SECRET-NPI"}],
        "name": [{"family": "SECRET-PERSON", "given": ["secret@example.test"]}],
    }
    role: dict[str, object] = {
        "resourceType": "PractitionerRole",
        "id": role_id,
        "active": True,
        "practitioner": {
            "type": "Practitioner",
            "reference": "Practitioner/" + practitioner_id,
            "display": "SECRET-PERSON",
        },
        "location": [
            {
                "type": "Location",
                "reference": "Location/" + location_id,
                "display": "SECRET-SITE",
            }
            for location_id in location_ids
        ],
        "period": {"start": "2026-01-01", "end": "2026-12-31"},
        "role": [{"text": "SECRET-ROLE"}],
        "organization": {"reference": "Organization/secret"},
    }
    locations = {
        location_id: {
            "resourceType": "Location",
            "id": location_id,
            "status": "active",
            "meta": {"lastUpdated": "2026-09-12T12:00:00Z"},
            "name": "SECRET-SITE",
            "address": {"line": ["SECRET-ADDRESS"]},
        }
        for location_id in location_ids
    }
    return practitioner, role, locations


class FixtureTransport:
    """In-memory transport port with explicit per-request response sequences."""

    def __init__(self, responses: dict[str, object | list[object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, int, int]] = []

    def fetch(
        self,
        request_url: str,
        *,
        timeout_seconds: int,
        attempt: int,
    ) -> object:
        self.calls.append((request_url, timeout_seconds, attempt))
        if request_url not in self.responses:
            raise AssertionError("unexpected fixture request")
        value = self.responses[request_url]
        if isinstance(value, list):
            if not value:
                raise AssertionError("empty fixture response sequence")
            return value[min(attempt, len(value) - 1)]
        return value


@dataclass
class CloseableResponse:
    request_url: str
    status: int
    media_type: str | None
    body: bytes
    should_fail_close: bool = False
    closed: bool = False

    def close(self) -> None:
        self.closed = True
        if self.should_fail_close:
            raise RuntimeError("fixture-close-failure")


def _response(
    request_url: str,
    document: object | None,
    *,
    status: int = 200,
    media_type: str | None = "application/fhir+json; fhirVersion=4.0",
    headers: tuple[tuple[str, str], ...] = (),
    redirected_to: str | None = None,
    body: bytes | None = None,
) -> directory.DirectoryTransportResponse:
    return directory.DirectoryTransportResponse(
        request_url=request_url,
        status=status,
        media_type=media_type,
        body=_body(document) if body is None and document is not None else (body or b""),
        headers=headers,
        redirected_to=redirected_to,
    )


def _fixture_transport(
    *,
    practitioner_id: str = PRACTITIONER_ID,
    role_id: str = ROLE_ID,
    location_ids: tuple[str, ...] = (LOCATION_ID,),
    practitioner_next: str | None = None,
    practitioner_next_bundle: dict[str, object] | None = None,
    role_next: str | None = None,
    role_next_bundle: dict[str, object] | None = None,
    role_response: object | list[object] | None = None,
    location_responses: dict[str, object | list[object]] | None = None,
) -> FixtureTransport:
    practitioner, role, locations = _resources(
        practitioner_id=practitioner_id,
        role_id=role_id,
        location_ids=location_ids,
    )
    practitioner_url = PROFILE.practitioner_search_url(practitioner_id)
    role_url = PROFILE.practitioner_role_search_url(practitioner_id)
    responses: dict[str, object | list[object]] = {
        practitioner_url: _response(
            practitioner_url,
            _bundle(
                practitioner_url,
                [practitioner],
                next_url=practitioner_next,
                total=1,
            ),
        ),
        role_url: (
            role_response
            if role_response is not None
            else _response(
                role_url,
                _bundle(role_url, [role], next_url=role_next, total=1),
            )
        ),
    }
    if practitioner_next is not None:
        if practitioner_next_bundle is None:
            practitioner_next_bundle = _bundle(
                practitioner_next,
                [],
                total=1,
            )
        responses[practitioner_next] = _response(
            practitioner_next,
            practitioner_next_bundle,
        )
    if role_next is not None:
        if role_next_bundle is None:
            role_next_bundle = _bundle(role_next, [], total=1)
        responses[role_next] = _response(role_next, role_next_bundle)
    if location_responses is None:
        location_responses = {
            location_id: _response(
                PROFILE.location_read_url(location_id),
                locations[location_id],
            )
            for location_id in location_ids
        }
    for location_id, response in location_responses.items():
        responses[PROFILE.location_read_url(location_id)] = response
    return FixtureTransport(responses)


def _adapter(
    transport: FixtureTransport,
    *,
    clock_values: tuple[int, int] = (1_000, 1_005),
    monotonic_clock: object | None = None,
) -> directory.NcMedicaidDirectoryAdapterV1:
    clock_iter = iter(clock_values)
    return directory.NcMedicaidDirectoryAdapterV1(
        transport,
        clock=lambda: next(clock_iter),
        monotonic_clock=monotonic_clock or (lambda: 0.0),
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _capture(transport: FixtureTransport) -> bytes:
    return directory._build_capture(  # type: ignore[attr-defined]
        transport,
        PROFILE,
        CONTEXT,
        observation_time=1_000,
        fetched_at=1_005,
        monotonic_clock=lambda: 0.0,
    )


class NcMedicaidDirectoryV1Tests(unittest.TestCase):
    def test_positive_chain_is_aggregate_only_and_verified_at_time(self) -> None:
        transport = _fixture_transport()
        admission = _adapter(transport).admit(CONTEXT)

        self.assertTrue(admission.accepted)
        self.assertIsNotNone(admission.verification_receipt)
        observation = json.loads(admission.observation.decode("ascii"))
        receipt = json.loads(admission.verification_receipt.decode("ascii"))
        self.assertEqual("DIRECTORY_OBSERVED", observation["outcome"])
        self.assertEqual("OBSERVED", observation["source_status"])
        self.assertEqual("COMPLETE", observation["traversal_status"])
        self.assertEqual(
            {
                "practitioner_count": 1,
                "role_count": 1,
                "location_count": 1,
                "search_page_count": 2,
                "location_read_count": 1,
                "request_count": 3,
                "response_count": 3,
                "retry_count": 0,
            },
            {
                key: observation[key]
                for key in (
                    "practitioner_count",
                    "role_count",
                    "location_count",
                    "search_page_count",
                    "location_read_count",
                    "request_count",
                    "response_count",
                    "retry_count",
                )
            },
        )
        self.assertGreater(observation["ignored_field_count"], 0)
        self.assertEqual("VERIFIED_AT_TIME", receipt["verification_status"])
        self.assertEqual(dict(PROFILE.flags), observation["flags"])
        self.assertEqual(
            {request for request, _, _ in transport.calls},
            {
                PROFILE.practitioner_search_url(PRACTITIONER_ID),
                PROFILE.practitioner_role_search_url(PRACTITIONER_ID),
                PROFILE.location_read_url(LOCATION_ID),
            },
        )
        self.assertEqual([0, 0, 0], [attempt for _, _, attempt in transport.calls])
        self.assertEqual([5, 5, 5], [timeout for _, timeout, _ in transport.calls])
        self.assertEqual(
            {
                "accepted": True,
                "profile_id": PROFILE.source_profile_id,
                "profile_version": PROFILE.source_profile_version,
                "verification_status": "VERIFIED_AT_TIME",
            },
            independent.verify_sanitized_pair(
                admission.observation,
                admission.verification_receipt,
            ),
        )

    def test_public_boundary_has_no_raw_source_identity_or_transport_values(self) -> None:
        transport = _fixture_transport()
        admission = _adapter(transport).admit(CONTEXT)
        public = admission.observation + (admission.verification_receipt or b"")
        public_text = public.decode("ascii") + repr(admission.telemetry)
        for forbidden in (
            PRACTITIONER_ID,
            ROLE_ID,
            LOCATION_ID,
            OPERATION_REF,
            "SECRET-NPI",
            "SECRET-PERSON",
            "SECRET-SITE",
            "SECRET-ADDRESS",
            PROFILE.practitioner_search_url(PRACTITIONER_ID),
            PROFILE.practitioner_role_search_url(PRACTITIONER_ID),
            PROFILE.location_read_url(LOCATION_ID),
            BASE_URL,
        ):
            self.assertNotIn(forbidden, public_text)
        self.assertNotIn("mirror-ncmedicaid-provider-directory-capture", public_text)
        self.assertNotIn("document", public_text)

    def test_pagination_follows_returned_opaque_links_and_retries_exactly(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        role_url = PROFILE.practitioner_role_search_url(PRACTITIONER_ID)
        practitioner_next = practitioner_url + "&cursor=opaque-practitioner"
        role_next = role_url + "&cursor=opaque-role"
        practitioner, role, _ = _resources()
        transport = _fixture_transport(
            practitioner_next=practitioner_next,
            practitioner_next_bundle=_bundle(practitioner_next, [], total=1),
            role_next=role_next,
            role_next_bundle=_bundle(role_next, [], total=1),
            role_response=[
                _response(
                    role_url,
                    None,
                    status=429,
                    headers=(("Retry-After", "0"),),
                ),
                _response(
                    role_url,
                    _bundle(role_url, [role], next_url=role_next, total=1),
                ),
            ],
        )

        admission = _adapter(transport).admit(CONTEXT)
        self.assertTrue(admission.accepted)
        observation = json.loads(admission.observation.decode("ascii"))
        self.assertEqual(4, observation["search_page_count"])
        self.assertEqual(5, observation["request_count"])
        self.assertEqual(5, observation["response_count"])
        self.assertEqual(1, observation["retry_count"])
        self.assertEqual(
            [
                practitioner_url,
                practitioner_next,
                role_url,
                role_url,
                role_next,
                PROFILE.location_read_url(LOCATION_ID),
            ],
            [request for request, _, _ in transport.calls],
        )
        self.assertNotIn(
            practitioner_url + "&page=1",
            [request for request, _, _ in transport.calls],
        )

    def test_self_link_query_maps_bind_the_requested_page_but_allow_ordering(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        practitioner_next = practitioner_url + "&cursor=opaque-practitioner&_count=32"
        reordered_self = practitioner_url + "&_count=32&cursor=opaque-practitioner"
        transport = _fixture_transport(
            practitioner_next=practitioner_next,
            practitioner_next_bundle=_bundle(reordered_self, [], total=1),
        )

        admission = _adapter(transport).admit(CONTEXT)
        self.assertTrue(admission.accepted)

        cases = (
            ("initial-count", _fixture_transport()),
            (
                "continuation-cursor",
                _fixture_transport(
                    practitioner_next=practitioner_next,
                    practitioner_next_bundle=_bundle(
                        practitioner_next,
                        [],
                        total=1,
                    ),
                ),
            ),
        )
        for mutation, mutated_transport in cases:
            with self.subTest(mutation=mutation):
                value = json.loads(_capture(mutated_transport).decode("ascii"))
                if mutation == "initial-count":
                    value["operations"][0]["document"]["link"][0]["url"] = (
                        practitioner_url + "&_count=1"
                    )
                else:
                    value["operations"][1]["document"]["link"][0]["url"] = (
                        practitioner_url + "&cursor=different"
                    )
                with self.assertRaisesRegex(
                    independent.DirectoryIndependentError,
                    "search-self",
                ):
                    independent.verify_capture(
                        _canonical(value),
                        context=CONTEXT,
                        observation_time=1_000,
                        fetched_at=1_005,
                    )

    def test_constructor_requires_caller_transport_and_verifier_is_separate(self) -> None:
        with self.assertRaises(TypeError):
            directory.NcMedicaidDirectoryAdapterV1()  # type: ignore[call-arg]
        self.assertNotIn("NcMedicaidDirectoryAdapterV1", vars(independent))
        self.assertTrue(PROFILE.flags["synthetic_only"])
        self.assertFalse(PROFILE.flags["production_usable"])
        self.assertFalse(PROFILE.flags["activation"])
        self.assertIsNone(PROFILE.flags["proofSuiteId"])

    def test_mutated_capture_filters_references_urls_and_full_urls_fail_closed(self) -> None:
        mutation_cases = (
            ("self-filter", "search-self"),
            ("practitioner-reference", "practitioner-mismatch"),
            ("full-url", "full-url"),
            ("foreign-next", "url"),
            ("reference-identity", "reference-identity"),
        )
        for mutation, expected_code in mutation_cases:
            with self.subTest(mutation=mutation):
                value = json.loads(_capture(_fixture_transport()).decode("ascii"))
                practitioner_document = value["operations"][0]["document"]
                role_document = value["operations"][1]["document"]
                if mutation == "self-filter":
                    practitioner_document["link"][0]["url"] = (
                        PROFILE.base_url + "/Practitioner?_id=other"
                    )
                elif mutation == "practitioner-reference":
                    role_document["entry"][0]["resource"]["practitioner"][
                        "reference"
                    ] = "Practitioner/other"
                elif mutation == "full-url":
                    practitioner_document["entry"][0]["fullUrl"] = (
                        PROFILE.base_url + "/Practitioner/other"
                    )
                elif mutation == "foreign-next":
                    practitioner_document["link"].append(
                        {
                            "relation": "next",
                            "url": "https://foreign.invalid/fhir/Practitioner?_id="
                            + PRACTITIONER_ID,
                        }
                    )
                else:
                    role_document["entry"][0]["resource"]["practitioner"][
                        "identifier"
                    ] = {"value": "SECRET-IDENTITY"}
                with self.assertRaisesRegex(
                    independent.DirectoryIndependentError,
                    expected_code,
                ) as raised:
                    independent.verify_capture(
                        _canonical(value),
                        context=CONTEXT,
                        observation_time=1_000,
                        fetched_at=1_005,
                    )
                self.assertNotIn("SECRET-IDENTITY", str(raised.exception))
                self.assertNotIn("foreign.invalid", str(raised.exception))

    def test_mismatched_role_is_rejected_before_any_location_read(self) -> None:
        role_url = PROFILE.practitioner_role_search_url(PRACTITIONER_ID)
        _, role, _ = _resources()
        role["practitioner"]["reference"] = "Practitioner/other"
        transport = _fixture_transport()
        transport.responses[role_url] = _response(
            role_url,
            _bundle(role_url, [role], total=1),
        )

        admission = _adapter(transport).admit(CONTEXT)
        self.assertFalse(admission.accepted)
        self.assertEqual(
            "practitioner-mismatch",
            json.loads(admission.observation.decode("ascii"))["failure_code"],
        )
        self.assertEqual(
            [
                PROFILE.practitioner_search_url(PRACTITIONER_ID),
                role_url,
            ],
            [request for request, _, _ in transport.calls],
        )

    def test_location_status_is_optional_but_unknown_codes_are_rejected(self) -> None:
        _, _, locations = _resources()
        location_url = PROFILE.location_read_url(LOCATION_ID)

        optional_transport = _fixture_transport()
        optional_location = dict(locations[LOCATION_ID])
        optional_location.pop("status")
        optional_transport.responses[location_url] = _response(
            location_url,
            optional_location,
        )
        self.assertTrue(_adapter(optional_transport).admit(CONTEXT).accepted)

        invalid_transport = _fixture_transport()
        invalid_location = dict(locations[LOCATION_ID])
        invalid_location["status"] = "not-a-location-status"
        invalid_transport.responses[location_url] = _response(
            location_url,
            invalid_location,
        )
        admission = _adapter(invalid_transport).admit(CONTEXT)
        self.assertFalse(admission.accepted)
        self.assertEqual(
            "resource-field",
            json.loads(admission.observation.decode("ascii"))["failure_code"],
        )

    def test_location_dot_segments_are_rejected_but_dotted_ids_are_allowed(self) -> None:
        for location_id in (".", ".."):
            with self.subTest(location_id=location_id):
                with self.assertRaisesRegex(
                    NcMedicaidDirectoryProfileError,
                    "profile:location-id",
                ):
                    PROFILE.location_read_url(location_id)

        dotted_id = "location.7"
        dotted_transport = _fixture_transport(location_ids=(dotted_id,))
        dotted_admission = _adapter(dotted_transport).admit(CONTEXT)
        self.assertTrue(dotted_admission.accepted)
        self.assertIn(
            PROFILE.location_read_url(dotted_id),
            [request for request, _, _ in dotted_transport.calls],
        )

        role_url = PROFILE.practitioner_role_search_url(PRACTITIONER_ID)
        _, role, _ = _resources()
        role["location"][0]["reference"] = "Location/.."
        invalid_transport = _fixture_transport()
        invalid_transport.responses[role_url] = _response(
            role_url,
            _bundle(role_url, [role], total=1),
        )
        invalid_admission = _adapter(invalid_transport).admit(CONTEXT)
        self.assertFalse(invalid_admission.accepted)
        self.assertEqual(
            "location-id",
            json.loads(invalid_admission.observation.decode("ascii"))["failure_code"],
        )
        self.assertNotIn(
            PROFILE.location_read_url(LOCATION_ID),
            [request for request, _, _ in invalid_transport.calls],
        )

    def test_duplicate_json_and_unsupported_modifier_fail_without_raw_error_context(self) -> None:
        duplicate = (
            b'{"schema":"mirror-ncmedicaid-provider-directory-capture-v1",'
            b'"schema":"mirror-ncmedicaid-provider-directory-capture-v1"}'
        )
        with self.assertRaisesRegex(independent.DirectoryIndependentError, "json-parse") as raised:
            independent.verify_capture(
                duplicate,
                context=CONTEXT,
                observation_time=1_000,
                fetched_at=1_005,
            )
        self.assertNotIn("schema", str(raised.exception))

        value = json.loads(_capture(_fixture_transport()).decode("ascii"))
        value["operations"][0]["document"]["modifierExtension"] = []
        with self.assertRaisesRegex(independent.DirectoryIndependentError, "modifier-field"):
            independent.verify_capture(
                _canonical(value),
                context=CONTEXT,
                observation_time=1_000,
                fetched_at=1_005,
            )

    def test_duplicate_and_nonfinite_server_json_are_rejected_at_the_transport_boundary(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        duplicate_body = (
            b'{"resourceType":"Bundle","resourceType":"Bundle",'
            b'"type":"searchset","link":[],"entry":[]}'
        )
        duplicate_admission = _adapter(
            FixtureTransport(
                {
                    practitioner_url: _response(
                        practitioner_url,
                        None,
                        body=duplicate_body,
                    )
                }
            )
        ).admit(CONTEXT)
        self.assertFalse(duplicate_admission.accepted)
        self.assertEqual(
            "duplicate-key",
            json.loads(duplicate_admission.observation.decode("ascii"))["failure_code"],
        )

        nonfinite_admission = _adapter(
            FixtureTransport(
                {
                    practitioner_url: _response(
                        practitioner_url,
                        None,
                        body=b'{"resourceType":NaN}',
                    )
                }
            )
        ).admit(CONTEXT)
        self.assertFalse(nonfinite_admission.accepted)
        self.assertEqual(
            "json-constant",
            json.loads(nonfinite_admission.observation.decode("ascii"))["failure_code"],
        )

    def test_retry_capture_rejects_a_mutated_final_attempt_status(self) -> None:
        role_url = PROFILE.practitioner_role_search_url(PRACTITIONER_ID)
        _, role, _ = _resources()
        transport = _fixture_transport(
            role_response=[
                _response(
                    role_url,
                    None,
                    status=429,
                    headers=(("Retry-After", "0"),),
                ),
                _response(role_url, _bundle(role_url, [role], total=1)),
            ]
        )
        value = json.loads(_capture(transport).decode("ascii"))
        value["operations"][1]["attempt_statuses"][-1] = 500
        with self.assertRaisesRegex(independent.DirectoryIndependentError, "response"):
            independent.verify_capture(
                _canonical(value),
                context=CONTEXT,
                observation_time=1_000,
                fetched_at=1_005,
            )

    def test_media_type_and_redirect_failures_are_fixed_code_rejections(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        practitioner, _, _ = _resources()
        cases = (
            (
                _response(
                    practitioner_url,
                    _bundle(practitioner_url, [practitioner], total=1),
                    media_type="application/json",
                ),
                "media-type",
            ),
            (
                _response(
                    practitioner_url,
                    _bundle(practitioner_url, [practitioner], total=1),
                    redirected_to="https://foreign.invalid/fhir/Practitioner",
                ),
                "redirect",
            ),
        )
        for response, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                admission = _adapter(
                    FixtureTransport({practitioner_url: response})
                ).admit(CONTEXT)
                self.assertFalse(admission.accepted)
                self.assertEqual(
                    expected_code,
                    json.loads(admission.observation.decode("ascii"))["failure_code"],
                )

    def test_bounds_and_retry_exhaustion_are_partial_rejections(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        oversized = _response(
            practitioner_url,
            None,
            body=b"x" * (PROFILE.transport_caps["max_response_bytes"] + 1),
        )
        oversized_admission = _adapter(
            FixtureTransport({practitioner_url: oversized})
        ).admit(CONTEXT)
        self.assertFalse(oversized_admission.accepted)
        self.assertIsNone(oversized_admission.verification_receipt)
        oversized_observation = json.loads(
            oversized_admission.observation.decode("ascii")
        )
        self.assertEqual("response-cap", oversized_observation["failure_code"])
        self.assertEqual("PARTIAL", oversized_observation["traversal_status"])

        retries = [
            _response(
                practitioner_url,
                None,
                status=429,
                headers=(("Retry-After", "0"),),
            )
            for _ in range(PROFILE.transport_caps["max_retries"] + 1)
        ]
        retry_transport = FixtureTransport({practitioner_url: retries})
        retry_admission = _adapter(retry_transport).admit(CONTEXT)
        self.assertFalse(retry_admission.accepted)
        retry_observation = json.loads(retry_admission.observation.decode("ascii"))
        self.assertEqual("retry-exhausted", retry_observation["failure_code"])
        self.assertEqual(2, retry_observation["retry_count"])
        self.assertEqual(
            list(range(PROFILE.transport_caps["max_retries"] + 1)),
            [attempt for _, _, attempt in retry_transport.calls],
        )

    def test_reference_count_cap_is_checked_before_location_reads(self) -> None:
        location_ids = tuple(f"location-{index}" for index in range(33))
        transport = _fixture_transport(location_ids=location_ids)
        admission = _adapter(transport).admit(CONTEXT)
        self.assertFalse(admission.accepted)
        observation = json.loads(admission.observation.decode("ascii"))
        self.assertEqual("resource-cap", observation["failure_code"])
        self.assertEqual(2, observation["request_count"])
        self.assertEqual(
            [],
            [request for request, _, _ in transport.calls if "/Location/" in request],
        )

    def test_search_page_cap_is_reported_without_fetching_the_boundary_link(self) -> None:
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        next_urls = [
            practitioner_url + "&cursor=page-" + str(index)
            for index in range(1, 5)
        ]
        transport = _fixture_transport(
            practitioner_next=next_urls[0],
            practitioner_next_bundle=_bundle(
                next_urls[0],
                [],
                next_url=next_urls[1],
                total=1,
            ),
        )
        for index, request_url in enumerate(next_urls[1:], start=1):
            transport.responses[request_url] = _response(
                request_url,
                _bundle(
                    request_url,
                    [],
                    next_url=next_urls[index + 1] if index < len(next_urls) - 1 else None,
                    total=1,
                ),
            )

        admission = _adapter(transport).admit(CONTEXT)
        self.assertFalse(admission.accepted)
        observation = json.loads(admission.observation.decode("ascii"))
        self.assertEqual("page-cap", observation["failure_code"])
        self.assertEqual("PARTIAL", observation["traversal_status"])
        self.assertEqual(4, observation["search_page_count"])
        self.assertEqual(4, observation["request_count"])
        self.assertEqual(4, observation["response_count"])
        self.assertEqual(4, len(transport.calls))
        self.assertNotIn(next_urls[-1], [request for request, _, _ in transport.calls])

    def test_response_release_and_release_failure_are_bounded(self) -> None:
        practitioner, role, locations = _resources()
        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        role_url = PROFILE.practitioner_role_search_url(PRACTITIONER_ID)
        location_url = PROFILE.location_read_url(LOCATION_ID)
        closeables = [
            CloseableResponse(
                practitioner_url,
                200,
                "application/fhir+json",
                _body(_bundle(practitioner_url, [practitioner], total=1)),
            ),
            CloseableResponse(
                role_url,
                200,
                "application/fhir+json",
                _body(_bundle(role_url, [role], total=1)),
            ),
            CloseableResponse(
                location_url,
                200,
                "application/fhir+json",
                _body(locations[LOCATION_ID]),
            ),
        ]
        transport = FixtureTransport(
            {
                practitioner_url: closeables[0],
                role_url: closeables[1],
                location_url: closeables[2],
            }
        )
        self.assertTrue(_adapter(transport).admit(CONTEXT).accepted)
        self.assertTrue(all(response.closed for response in closeables))

        failing = CloseableResponse(
            practitioner_url,
            200,
            "application/fhir+json",
            _body(_bundle(practitioner_url, [practitioner], total=1)),
            should_fail_close=True,
        )
        failed_admission = _adapter(
            FixtureTransport({practitioner_url: failing})
        ).admit(CONTEXT)
        self.assertFalse(failed_admission.accepted)
        self.assertEqual(
            "resource-release",
            json.loads(failed_admission.observation.decode("ascii"))["failure_code"],
        )
        self.assertTrue(failing.closed)

    def test_synchronous_overrun_is_rejected_and_timeout_is_passed_to_transport(self) -> None:
        class OverrunClock:
            def __init__(self) -> None:
                self.value = 0.0

            def __call__(self) -> float:
                current = self.value
                self.value += 6.0
                return current

        practitioner_url = PROFILE.practitioner_search_url(PRACTITIONER_ID)
        transport = _fixture_transport()
        admission = _adapter(
            transport,
            monotonic_clock=OverrunClock(),
        ).admit(CONTEXT)
        self.assertFalse(admission.accepted)
        observation = json.loads(admission.observation.decode("ascii"))
        self.assertEqual("retry-exhausted", observation["failure_code"])
        self.assertEqual(
            [PROFILE.transport_caps["timeout_seconds"]] * 3,
            [timeout for _, timeout, _ in transport.calls],
        )
        self.assertEqual(
            [practitioner_url] * 3,
            [request for request, _, _ in transport.calls],
        )

    def test_sanitized_pair_mutation_is_rejected(self) -> None:
        admission = _adapter(_fixture_transport()).admit(CONTEXT)
        self.assertIsNotNone(admission.verification_receipt)
        receipt = json.loads(admission.verification_receipt.decode("ascii"))
        receipt["production_usable"] = True
        mutated = _canonical(receipt)
        with self.assertRaisesRegex(independent.DirectoryIndependentError, "sanitized"):
            independent.verify_sanitized_pair(
                admission.observation,
                mutated,
            )


if __name__ == "__main__":
    unittest.main()
