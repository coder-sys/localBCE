"""Fixture-qualified NC Medicaid FHIR source-boundary tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import traceback
import unittest
from unittest.mock import Mock

from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_independent as independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.source_admission import SourceAdmissionError, SourceAdmissionService


def _practitioner() -> dict[str, object]:
    return profile.synthetic_resource("Practitioner")


def _role() -> dict[str, object]:
    return profile.synthetic_resource("PractitionerRole")


def _location(variant: str = "baseline") -> dict[str, object]:
    return profile.synthetic_resource("Location", variant=variant)


def _bundle(page: int = 0, *, resources: list[dict[str, object]] | None = None, next_page: bool = False, total: int | None = 3, last_updated: str | None = profile.FIXTURE_LAST_UPDATED, location_variant: str = "baseline", context: profile.DynamicCaptureContext | None = None) -> dict[str, object]:
    if resources is None:
        resources = [_practitioner(), _role(), _location(location_variant)]
    request_url = profile.NC_MEDICAID_PROFILE.page_url(page, context)
    links: list[dict[str, str]] = [{"relation": "self", "url": request_url}]
    if next_page:
        links.append({"relation": "next", "url": profile.NC_MEDICAID_PROFILE.page_url(page + 1, context)})
    value: dict[str, object] = {
        "resourceType": "Bundle",
        "type": "searchset",
        "id": f"SYNTH_NC_BUNDLE_{page + 1:03d}",
        "link": links,
        "entry": [
            {
                "fullUrl": profile.BASE_URL + "/" + str(resource["resourceType"]) + "/" + str(resource["id"]),
                "resource": resource,
            }
            for resource in resources
        ],
    }
    if total is not None:
        value["total"] = total
    if last_updated is not None:
        value["meta"] = {"lastUpdated": last_updated}
    return value


def _transport(*bundles: dict[str, object], retries: dict[tuple[str, int], fhir.FhirTransportResponse] | None = None, context: profile.DynamicCaptureContext | None = None) -> fhir.SyntheticFhirTransport:
    responses: dict[tuple[str, int], fhir.FhirTransportResponse] = {}
    for index, bundle in enumerate(bundles):
        request_url = profile.NC_MEDICAID_PROFILE.page_url(index, context)
        responses[(request_url, 0)] = fhir.fixture_response(bundle, request_url)
    if retries:
        responses.update(retries)
    return fhir.SyntheticFhirTransport(responses)


def _envelope(*, two_pages: bool = False, total: int | None = 3, last_updated: str | None = profile.FIXTURE_LAST_UPDATED, location_variant: str = "baseline", context: profile.DynamicCaptureContext | None = None) -> bytes:
    groups = [[_practitioner(), _role()], [_location(location_variant)]] if two_pages else [[_practitioner(), _role(), _location(location_variant)]]
    bundles = [_bundle(index, resources=resources, next_page=index + 1 < len(groups), total=total, last_updated=last_updated, context=context) for index, resources in enumerate(groups)]
    return fhir.build_fixture_envelope(_transport(*bundles, context=context), context=context)


def _rebind(value: dict[str, object], *, expected_context: profile.DynamicCaptureContext | None = None) -> bytes:
    context_value = value["capture_context"]
    assert isinstance(context_value, dict)
    context = expected_context or profile.DynamicCaptureContext(
        context_value["subject_id"], context_value["credential_id"],
        context_value["enrollment_id"], context_value["subject_locator_digest"],
        context_value["observation_time"], context_value["fetched_at"],
    )
    for page in value["pages"]:
        if not isinstance(page, dict):
            continue
        if isinstance(page.get("bundle"), dict):
            body = fhir.canonical_json(page["bundle"])
            page["byte_length"] = len(body)
            page["body_digest"] = fhir._raw_digest("page-bytes", body)
            entries = page["bundle"].get("entry", [])
            resources = [entry["resource"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("resource"), dict)]
            page["resource_digests"] = [fhir._digest("resource", resource) for resource in resources]
            page["body_hex"] = None
        page["page_id"] = fhir._digest("page-id", {key: item for key, item in page.items() if key != "page_id"})
    snapshot_root = fhir._digest("snapshot-root", {"page_ids": [page["page_id"] for page in value["pages"]]})
    value["snapshot_root"] = snapshot_root
    value["snapshot_id"] = fhir._digest(
        "snapshot-id",
        {
            "profile": profile.NC_MEDICAID_PROFILE.binding(context),
            "request_identity": fhir._digest("request", {"method": "GET", "url": profile.NC_MEDICAID_PROFILE.page_url(0, context), "query_parameters": [[key, value.replace("{subject_locator_digest}", context.subject_locator_digest)] for key, value in profile.NC_MEDICAID_PROFILE.query_parameters], "page_parameter": profile.NC_MEDICAID_PROFILE.page_parameter}),
            "capture_context": context.material(),
            "observation_time": context.observation_time,
            "fetched_at": context.fetched_at,
            "snapshot_root": snapshot_root,
            "source_status": value["source_status"],
            "failure_code": value["failure_code"],
            "server_markers": value["server_markers"],
        },
    )
    body = dict(value)
    body.pop("envelope_id")
    value["envelope_id"] = fhir._digest("envelope-id", body)
    return fhir.canonical_json(value)


class NcMedicaidFhirSourceTests(unittest.TestCase):
    def assert_capture_failure(self, raw: bytes, code: str, *, status: str = "PARTIAL", freshness: str = "UNKNOWN") -> None:
        result = independent.verify_bytes(raw)
        self.assertEqual((status, code, freshness), (result["source_status"], result["failure_code"], result["freshness"]))
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:" + code):
            independent.NcMedicaidFhirVerifier().verify(raw)

    def test_fixed_profile_and_contract_digest_are_verifier_owned(self) -> None:
        self.assertEqual("ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v5", profile.SOURCE_PROFILE_ID)
        self.assertEqual("https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir", profile.BASE_URL)
        self.assertEqual("provider-directory-observation-associated-with-NCTracks-and-health-plan-contract-data", profile.NC_MEDICAID_PROFILE.source_meaning)
        self.assertEqual("official-hostname-over-tls-unverified", profile.NC_MEDICAID_PROFILE.transport_provenance)
        self.assertEqual("undocumented", profile.NC_MEDICAID_PROFILE.record_authentication)
        self.assertEqual(("Practitioner", "PractitionerRole", "Location"), profile.NC_MEDICAID_PROFILE.allowed_resource_types)
        self.assertFalse(profile.NC_MEDICAID_PROFILE.require_complete)
        self.assertFalse(profile.NC_MEDICAID_PROFILE.allow_nonmembership)
        self.assertFalse(profile.NC_MEDICAID_PROFILE.live_transport_authorized)
        self.assertTrue(profile.NC_MEDICAID_PROFILE.synthetic_only)
        self.assertEqual(profile.NC_MEDICAID_PROFILE.profile_digest, profile.NC_MEDICAID_GRAPH_PROFILE.source_contract_digest)
        self.assertEqual(profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest, graph_independent._profile_digest(profile.NC_MEDICAID_GRAPH_PROFILE))
        with self.assertRaises(profile.NcMedicaidFhirProfileError):
            profile.NcMedicaidFhirSourceProfile(capability_statement_identity="CALLER_OVERRIDE")
        self.assertEqual((3, 5, 5, 2, 3), (profile.SOURCE_CONTRACT_VERSION, profile.SOURCE_PROFILE_VERSION, profile.VERIFIER_EPOCH, fhir.ENVELOPE_SCHEMA_VERSION, profile.NC_MEDICAID_GRAPH_PROFILE.version))
        self.assertEqual({"kind": "SYNTHETIC_LOGICAL_SECONDS_V1", "reference_tick": 7010, "reference_utc": "2026-08-14T12:00:00Z", "seconds_per_tick": 1}, dict(profile.NC_MEDICAID_PROFILE.capture_clock))
        with self.assertRaises(TypeError):
            profile.NC_MEDICAID_PROFILE.capture_clock["reference_tick"] = 0
        altered = profile.NC_MEDICAID_PROFILE.material()
        altered["capture_clock"]["reference_tick"] = 0
        self.assertNotEqual(profile.NC_MEDICAID_PROFILE.profile_digest, profile._digest("source-contract", altered))

    def test_profile_owned_location_variant_allowlist_rejects_unregistered_change(self) -> None:
        baseline = profile.synthetic_resource("Location")
        changed = profile.synthetic_resource("Location", variant="changed")
        self.assertEqual("Synthetic NC Site", baseline["name"])
        self.assertEqual(profile.SYNTHETIC_CHANGED_LOCATION_NAME, changed["name"])
        self.assertNotEqual(baseline, changed)
        baseline["name"] = "caller-supplied location"
        self.assertEqual("Synthetic NC Site", profile.synthetic_resource("Location")["name"])
        with self.assertRaisesRegex(profile.NcMedicaidFhirProfileError, "profile:synthetic-resource"):
            profile.synthetic_resource("Location", variant="unregistered")

        changed_result = independent.verify_bytes(_envelope(location_variant="changed"))
        self.assertEqual("COMPLETE", changed_result["source_status"])
        changed_admission = SourceAdmissionService(profile.NC_MEDICAID_GRAPH_PROFILE, independent.NcMedicaidFhirVerifier()).admit(_envelope(location_variant="changed"))
        baseline_admission = SourceAdmissionService(profile.NC_MEDICAID_GRAPH_PROFILE, independent.NcMedicaidFhirVerifier()).admit(_envelope())
        baseline_graph = json.loads(baseline_admission.graph_input.decode("ascii"))
        changed_graph = json.loads(changed_admission.graph_input.decode("ascii"))
        self.assertNotEqual(
            baseline_graph["sources"][1]["records"][0]["record_id"],
            changed_graph["sources"][1]["records"][0]["record_id"],
        )

        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][2]["resource"]["name"] = "Unregistered Synthetic Location"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "resource:synthetic-binding"):
            independent.verify_bytes(_rebind(value))

    def test_legacy_profile_envelope_is_rejected_without_migration(self) -> None:
        for field, replacement in (
            ("source_profile_id", "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v2"),
            ("source_profile_version", 2),
            ("source_profile_id", "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v4"),
            ("source_profile_version", 4),
            ("source_profile_digest", "0" * 128),
        ):
            with self.subTest(field=field):
                value = json.loads(_envelope().decode("ascii"))
                value["profile"][field] = replacement
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "profile:binding"):
                    independent.verify_bytes(_rebind(value))

    def test_valid_fixture_is_deterministic_and_maps_to_observation_only_graph(self) -> None:
        first = _envelope()
        second = _envelope()
        self.assertEqual(first, second)
        result = independent.verify_bytes(first)
        self.assertEqual("COMPLETE", result["source_status"])
        self.assertEqual({"Practitioner": 1, "PractitionerRole": 1, "Location": 1}, result["resource_counts"])
        self.assertEqual("FRESH", result["freshness"])
        admission = SourceAdmissionService(profile.NC_MEDICAID_GRAPH_PROFILE, independent.NcMedicaidFhirVerifier()).admit(first)
        self.assertFalse(admission.production_source_authentication)
        self.assertEqual("observation_only", admission.receipt.decode("ascii").split('"evidence_mode":"', 1)[1].split('"', 1)[0])
        graph_result = graph_independent.verify_bytes_v2(admission.graph_artifact, dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY))
        self.assertTrue(graph_result["accepted"])
        self.assertEqual("EVIDENCE_INCOMPLETE", json.loads(admission.graph_artifact.decode("ascii"))["findings"][0]["kind"])

    def test_dynamic_capture_context_reaches_source_admission_without_profile_growth(self) -> None:
        context = profile.DynamicCaptureContext(
            "1" * 128, "2" * 128, "3" * 128, "4" * 128, 7_060, 7_070,
        )
        raw = _envelope(context=context)
        result = independent.verify_bytes(raw)
        admission = SourceAdmissionService(
            profile.NC_MEDICAID_PROFILE.graph_profile_for_context(context),
            independent.NcMedicaidFhirVerifier(expected_context=context),
        ).admit(raw)
        self.assertEqual(profile.NC_MEDICAID_PROFILE.profile_digest, result["source_contract_digest"])
        self.assertEqual(profile.NC_MEDICAID_PROFILE.profile_digest, admission.source_contract_digest)
        graph_input = json.loads(admission.graph_input.decode("ascii"))
        self.assertEqual(context.subject_id, graph_input["provider_graph_subject"])

    def test_marker_age_uses_inclusive_synthetic_seconds_and_unknown_precision(self) -> None:
        for marker, freshness in (
            ("2026-08-14T12:00:00Z", "FRESH"), ("2025-08-14T12:00:01Z", "FRESH"),
            ("2025-08-14T12:00:00Z", "FRESH"), ("2025-08-14T11:59:59Z", "STALE"),
            ("2000-01-01T00:00:00Z", "STALE"), ("2024-02-29T12:00:00Z", "STALE"),
            (None, "UNKNOWN"), ("2026-08-14", "UNKNOWN"), ("2024-02-29", "UNKNOWN"),
        ):
            with self.subTest(marker=marker):
                raw = _envelope(last_updated=marker)
                result = independent.verify_bytes(raw)
                expected = ("STALE", "stale") if freshness == "STALE" else ("COMPLETE", None)
                self.assertEqual((freshness, *expected), (result["freshness"], result["source_status"], result["failure_code"]))
                self.assertEqual(raw, _envelope(last_updated=marker))
                if freshness == "STALE":
                    with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:stale"):
                        independent.NcMedicaidFhirVerifier().verify(raw)
                else:
                    self.assertEqual(freshness, independent.NcMedicaidFhirVerifier().verify(raw).freshness)

    def test_future_invalid_calendar_and_non_utc_markers_fail_closed(self) -> None:
        for marker in (
            "2026-08-14T12:00:01Z", "9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z",
            "2025-02-29T00:00:00Z", "2026-04-31", "2026-13-01T00:00:00Z",
            "2026-08-14T24:00:00Z", "2026-08-14T12:60:00Z", "2026-08-14T12:00:60Z",
            "2026-08-14T12:00:00", "2026-08-14T12:00:00+00:00", "2026-08-14T12:00:00.0Z",
            "2026-08-14 12:00:00Z", True, 7010, [], {},
        ):
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(fhir.NcMedicaidFhirError, "markers:(last-updated|future)"):
                    _envelope(last_updated=marker)
                value = json.loads(_envelope())
                value["pages"][0]["bundle"]["meta"]["lastUpdated"] = marker
                value["server_markers"]["last_updated"] = marker
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "last-updated|markers:future"):
                    independent.verify_bytes(_rebind(value))

    def test_capture_clock_bounds_and_expected_context_prevent_time_substitution(self) -> None:
        base = profile.DEFAULT_CAPTURE_CONTEXT
        for field, replacement in (("subject_id", "1" * 128), ("credential_id", "2" * 128), ("enrollment_id", "3" * 128), ("subject_locator_digest", "4" * 128), ("observation_time", 7001), ("fetched_at", 7020)):
            with self.subTest(field=field):
                context = replace(base, **{field: replacement})
                raw = _envelope(context=context)
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:context-mismatch"):
                    independent.NcMedicaidFhirVerifier().verify(raw)
                admitted = SourceAdmissionService(profile.NC_MEDICAID_PROFILE.graph_profile_for_context(context), independent.NcMedicaidFhirVerifier(expected_context=context)).admit(raw)
                self.assertEqual(context.observation_time, json.loads(admitted.graph_input)["observation_time"])
        later = replace(base, fetched_at=base.fetched_at + 365 * 86_400 + 1)
        self.assertEqual("STALE", independent.verify_bytes(_envelope(context=later))["freshness"])
        self.assertEqual("STALE", independent.verify_bytes(_envelope(context=replace(base, fetched_at=2_147_483_647)))["freshness"])
        for fetched_at in (True, -1, base.observation_time - 1, 2_147_483_648, 10 ** 300):
            with self.subTest(fetched_at=fetched_at):
                with self.assertRaisesRegex(profile.NcMedicaidFhirProfileError, "profile:context-time"):
                    replace(base, fetched_at=fetched_at)
                value = json.loads(_envelope())
                value["capture_context"]["fetched_at"] = value["fetched_at"] = fetched_at
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "capture-context:binding"):
                    independent.verify_bytes(fhir.canonical_json(value))

    def test_contradictory_snapshot_status_and_failure_never_admit(self) -> None:
        baseline = json.loads(_envelope())
        for code in sorted(fhir.FAILURE_CODES):
            with self.subTest(code=code):
                value = deepcopy(baseline)
                value["failure_code"] = code
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:status-failure"):
                    independent.verify_bytes(_rebind(value))
        failed = json.loads(fhir.build_fixture_envelope(fhir.SyntheticFhirTransport({})))
        for status, code, complete in (("COMPLETE", "timeout", True), ("FAILED", "media-type", False)):
            failed.update(source_status=status, failure_code=code, page_complete=complete)
            with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:(status-failure|timeout)"):
                independent.verify_bytes(_rebind(failed))
        for status, code, complete in (("FAILED", None, False), ("PARTIAL", None, False), ("STALE", None, False), ("STALE", "stale", False), ("COMPLETE", None, False)):
            with self.subTest(status=status, code=code, complete=complete):
                value = deepcopy(baseline)
                value.update(source_status=status, failure_code=code, page_complete=complete)
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:(status-failure|claims)"):
                    independent.verify_bytes(_rebind(value))
        stale = json.loads(_envelope(last_updated="2000-01-01T00:00:00Z"))
        stale.update(source_status="COMPLETE", page_complete=True)
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:status-failure"):
            independent.NcMedicaidFhirVerifier().verify(_rebind(stale))
        result = independent.verify_bytes(_envelope())
        result["failure_code"] = "stale"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:stale"):
            independent.to_verified_source_coverage(result)

    def test_numeric_capture_id_coercion_cannot_match_trusted_string_ids(self) -> None:
        context = profile.DynamicCaptureContext("1" * 128, "2" * 128, "3" * 128, "4" * 128, 7000, 7010)
        verifier = independent.NcMedicaidFhirVerifier(expected_context=context)
        service = SourceAdmissionService(profile.NC_MEDICAID_PROFILE.graph_profile_for_context(context), verifier)
        for field in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest"):
            with self.subTest(field=field):
                value = json.loads(_envelope(context=context))
                value["capture_context"][field] = int(context.material()[field])
                forged = _rebind(value, expected_context=context)
                with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "capture-context:binding"):
                    verifier.verify(forged)
                with self.assertRaisesRegex(SourceAdmissionError, "verifier:reject"):
                    service.admit(forged)

    def test_partial_and_drift_failures_take_precedence_over_marker_age(self) -> None:
        for marker, second, code in ((profile.FIXTURE_LAST_UPDATED, None, "timeout"), ("2000-01-01T00:00:00Z", None, "timeout"), ("2000-01-01T00:00:00Z", _bundle(1, resources=[_location()], last_updated=None), "marker-drift"), ("2000-01-01T00:00:00Z", _bundle(1, resources=[_location()], total=2), "marker-drift")):
            with self.subTest(code=code, second=second):
                first = _bundle(resources=[_practitioner(), _role()], next_page=True, last_updated=marker)
                raw = fhir.build_fixture_envelope(_transport(first, *([] if second is None else [second])))
                self.assert_capture_failure(raw, code)

    def test_query_and_page_cap_failures_discard_body_and_remain_verifiable(self) -> None:
        drift = _bundle(next_page=True)
        drift["link"][1]["url"] = profile.REQUEST_URL + "&page=99"
        pages = [_bundle(index, resources=resources, next_page=index < 3) for index, resources in enumerate(([_practitioner()], [_role()], [_location()], []))]
        pages[-1]["link"].append({"relation": "next", "url": profile.REQUEST_URL + "&page=5"})
        for bundles, code in (((drift,), "query-drift"), (pages, "partial-page")):
            with self.subTest(code=code):
                raw = fhir.build_fixture_envelope(_transport(*bundles))
                self.assert_capture_failure(raw, code)
                page = json.loads(raw)["pages"][-1]
                self.assertEqual((0, fhir._raw_digest("page-bytes", b""), "", None, []), (page["byte_length"], page["body_digest"], page["body_hex"], page["bundle"], page["resource_digests"]))

    def test_two_page_chain_and_missing_total_are_explicitly_bounded(self) -> None:
        raw = _envelope(two_pages=True, total=None)
        result = independent.verify_bytes(raw)
        self.assertEqual(2, result["page_count"])
        self.assertIsNone(result["server_total"])
        self.assertEqual(3, result["resource_count"])

    def test_profile_owner_host_base_capability_and_fhir_bindings_reject(self) -> None:
        raw = _envelope()
        for path, replacement, code in (
            (("owner", "base_url"), "https://wrong.example/fhir", "owner:binding"),
            (("owner", "fhir_version"), "4.0.0", "owner:binding"),
            (("request", "url"), "https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir/Patient", "request:profile"),
            (("profile", "capability_statement_identity"), "CALLER_CAPABILITY", "profile:binding"),
            (("profile", "capability_statement_digest"), "0" * 128, "profile:binding"),
        ):
            value = json.loads(raw.decode("ascii"))
            value[path[0]][path[1]] = replacement
            with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, code):
                independent.verify_bytes(_rebind(value))

    def test_media_failures_are_explicit(self) -> None:
        request_url = profile.REQUEST_URL
        bad = fhir.SyntheticFhirTransport({(request_url, 0): fhir.fixture_response(_bundle(), request_url, media_type="application/json")})
        raw = fhir.build_fixture_envelope(bad)
        self.assert_capture_failure(raw, "media-type", status="FAILED")
        wrong_host = fhir.SyntheticFhirTransport({(request_url, 0): fhir.FhirTransportResponse("https://wrong.example/fhir", 200, fhir.ALLOWED_MEDIA_TYPE, fhir.canonical_json(_bundle()))})
        wrong_host_result = independent.verify_bytes(fhir.build_fixture_envelope(wrong_host))
        self.assertEqual("wrong-host", wrong_host_result["failure_code"])
        redirected = fhir.SyntheticFhirTransport({(request_url, 0): fhir.FhirTransportResponse(request_url, 200, fhir.ALLOWED_MEDIA_TYPE, fhir.canonical_json(_bundle()), redirected_to="https://wrong.example/fhir")})
        redirected_result = independent.verify_bytes(fhir.build_fixture_envelope(redirected))
        self.assertEqual("redirect", redirected_result["failure_code"])
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["response_url"] = "https://wrong.example/fhir/Practitioner"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "page:response-url"):
            independent.verify_bytes(_rebind(value))

    def test_fixture_profile_rejects_phi_shaped_resources_and_never_retains_failure_content(self) -> None:
        value = json.loads(_envelope().decode("ascii"))
        practitioner = value["pages"][0]["bundle"]["entry"][0]["resource"]
        practitioner["identifier"][0]["value"] = "REAL-PATIENT-123"
        practitioner["name"][0]["family"] = "Jane Patient SSN 123"
        practitioner["name"][0]["given"] = ["jane@example.com"]
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "resource:synthetic-binding"):
            independent.verify_bytes(_rebind(value))

        secret_body = b"Bearer SECRET patient=123 C:\\Users\\private"
        secret_url = "https://wrong.example/PRIVATE-PATIENT-123?token=SECRET"
        secret_media = "text/PRIVATE-PATIENT-123"
        request_url = profile.REQUEST_URL
        failed = fhir.build_fixture_envelope(
            fhir.SyntheticFhirTransport({
                (request_url, 0): fhir.FhirTransportResponse(secret_url, 500, secret_media, secret_body),
            })
        )
        self.assertNotIn(secret_body, failed)
        self.assertNotIn(secret_url.encode("ascii"), failed)
        self.assertNotIn(secret_media.encode("ascii"), failed)
        failed_page = json.loads(failed.decode("ascii"))["pages"][0]
        self.assertEqual(0, failed_page["byte_length"])
        self.assertIsNone(failed_page["response_url"])
        self.assertIsNone(failed_page["media_type"])
        self.assertEqual(fhir._raw_digest("page-bytes", b""), failed_page["body_digest"])
        self.assertNotEqual(fhir._raw_digest("page-bytes", secret_body), failed_page["body_digest"])
        self.assertEqual("FAILED", independent.verify_bytes(failed)["source_status"])
        failed_value = json.loads(failed.decode("ascii"))
        failed_value["pages"][0]["body_digest"] = fhir._raw_digest("page-bytes", secret_body)
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "page:failure-body"):
            independent.verify_bytes(_rebind(failed_value))

        class SecretErrorTransport:
            def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int):
                raise fhir.FhirTransportError("Bearer SECRET C:\\Users\\private")

        transport_failed = fhir.build_fixture_envelope(SecretErrorTransport())
        self.assertNotIn(b"Bearer SECRET", transport_failed)
        self.assertNotIn(b"Users", transport_failed)
        transport_page = json.loads(transport_failed.decode("ascii"))["pages"][0]
        self.assertEqual("transport", transport_page["transport_error"])
        independent.verify_bytes(transport_failed)

        tampered = json.loads(failed.decode("ascii"))
        tampered["pages"][0]["body_hex"] = "00"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "page:failure-body"):
            independent.verify_bytes(_rebind(tampered))

    def test_retry_after_and_exhaustion_are_distinguished(self) -> None:
        request_url = profile.REQUEST_URL
        throttled = fhir.fixture_response(_bundle(), request_url, status=429, headers=(("Retry-After", "2"),))
        success = fhir.fixture_response(_bundle(), request_url)
        transport = _transport(_bundle(), retries={(request_url, 0): throttled, (request_url, 1): success})
        raw = fhir.build_fixture_envelope(transport)
        page = json.loads(raw.decode("ascii"))["pages"][0]
        self.assertEqual([429, 200], page["attempt_statuses"])
        self.assertEqual("COMPLETE", independent.verify_bytes(raw)["source_status"])
        exhausted = fhir.SyntheticFhirTransport({(request_url, 0): throttled})
        failed = fhir.build_fixture_envelope(exhausted)
        self.assert_capture_failure(failed, "retry-exhausted", status="FAILED")

    def test_mixed_retries_preserve_verifiable_failure_evidence(self) -> None:
        throttled = fhir.fixture_response(_bundle(), profile.REQUEST_URL, status=429, headers=(("Retry-After", "2"),))
        malformed = fhir.fixture_response(_bundle(), profile.REQUEST_URL, status=429, headers=(("Retry-After", "invalid"),))
        timeout = fhir.FhirTransportError("timeout")
        transport_error = fhir.FhirTransportError("private-transport-detail")
        cases = (
            ((throttled, timeout, timeout), [429, 0, 0], [2, None, None], 0, "timeout", "timeout"),
            ((throttled, transport_error, transport_error), [429, 0, 0], [2, None, None], 0, "transport", "retry-exhausted"),
            ((timeout, throttled, throttled), [0, 429, 429], [None, 2, 2], 429, None, "retry-exhausted"),
            ((malformed,), [429], [None], 429, None, "retry-after"),
        )
        service = SourceAdmissionService(profile.NC_MEDICAID_PROFILE.graph_profile, independent.NcMedicaidFhirVerifier())
        for responses, statuses, delays, status, error, code in cases:
            with self.subTest(statuses=statuses, error=error, code=code):
                transport = Mock()
                transport.fetch.side_effect = responses
                raw = fhir.build_fixture_envelope(transport)
                page = json.loads(raw)["pages"][0]
                self.assertEqual((statuses, delays, status, error), (page["attempt_statuses"], page["retry_after_seconds"], page["status"], page["transport_error"]))
                self.assertEqual(len(responses), transport.fetch.call_count)
                result = independent.verify_bytes(raw)
                self.assertEqual(("FAILED", code), (result["source_status"], result["failure_code"]))
                self.assertEqual(error, result["page_evidence"][0]["attempts"][-1]["transport_error"])
                with self.assertRaisesRegex(SourceAdmissionError, "^verifier:reject$"):
                    service.admit(raw)

    def test_malformed_noncanonical_duplicate_nan_and_caps_fail_closed(self) -> None:
        raw = _envelope()
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:duplicate-key"):
            independent.verify_bytes(raw[:-1] + b',"schema":"forged"}')
        noncanonical = json.dumps(json.loads(raw.decode("ascii"))).encode("utf-8")
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:not-canonical"):
            independent.verify_bytes(noncanonical)
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:constant"):
            independent.verify_bytes(b"{\"x\":NaN}")
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:byte-cap"):
            independent.verify_bytes(b"x" * (profile.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"] + 1))
        value = json.loads(raw.decode("ascii"))
        value["pages"][0]["response_url"] = "x" * (profile.NC_MEDICAID_PROFILE.transport_caps["max_string_bytes"] + 1)
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:string-cap"):
            independent.verify_bytes(_rebind(value))
        nested: object = None
        for _ in range(profile.NC_MEDICAID_PROFILE.transport_caps["max_depth"] + 2):
            nested = [nested]
        value = json.loads(raw.decode("ascii"))
        value["claims"]["nested"] = nested
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:depth-cap"):
            independent.verify_bytes(fhir.canonical_json(value))
        value = json.loads(raw.decode("ascii"))
        value["claims"]["nodes"] = [0] * (profile.NC_MEDICAID_PROFILE.transport_caps["max_nodes"] + 1)
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "json:node-cap"):
            independent.verify_bytes(fhir.canonical_json(value))

    def test_forbidden_extra_missing_duplicate_and_bad_reference_resources_reject(self) -> None:
        mutations: list[tuple[str, object]] = []
        value = json.loads(_envelope().decode("ascii"))
        patient = {"resourceType": "Patient", "id": "SYNTH_NC_PATIENT_001"}
        value["pages"][0]["bundle"]["entry"].append({"fullUrl": profile.BASE_URL + "/Patient/SYNTH_NC_PATIENT_001", "resource": patient})
        mutations.append(("resource:forbidden-resource", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"].pop()
        mutations.append(("resource:cardinality", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"].append(deepcopy(value["pages"][0]["bundle"]["entry"][0]))
        mutations.append(("resource:duplicate", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][1]["resource"]["practitioner"] = {"reference": "Location/" + profile.SYNTHETIC_LOCATION_ID}
        mutations.append(("resource:synthetic-binding", value))
        for code, mutated in mutations:
            with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, code):
                independent.verify_bytes(_rebind(mutated))

    def test_bad_identifier_period_address_endpoint_and_forbidden_field_reject(self) -> None:
        mutations = (
            ("forbidden-field", 0, ("unexpected",), True),
            ("practitioner:identifier:system", 0, ("identifier", 0, "system"), "not a uri"),
            ("resource:period-order", 1, ("period",), {"start": "2026-12-31", "end": "2026-01-01"}),
            ("resource:period-start:calendar", 1, ("period", "start"), "2026-02-29"),
            ("resource:address-postalCode:text", 2, ("address", "postalCode"), {"raw": "27601"}),
            ("location:endpoint:unlinked", 2, ("endpoint",), [{"reference": "Endpoint/SYNTH_ENDPOINT_001"}]),
        )
        for code, resource, path, replacement in mutations:
            value = json.loads(_envelope())
            target = value["pages"][0]["bundle"]["entry"][resource]["resource"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(code=code), self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, code):
                independent.verify_bytes(_rebind(value))

    def test_page_omission_reorder_duplicate_cycle_query_drift_and_marker_drift_reject(self) -> None:
        raw = _envelope(two_pages=True)
        value = json.loads(raw.decode("ascii"))
        omitted = deepcopy(value)
        omitted["pages"] = omitted["pages"][:1]
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "pages:partial"):
            independent.verify_bytes(_rebind(omitted))
        reordered = deepcopy(value)
        reordered["pages"].reverse()
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "page:request"):
            independent.verify_bytes(_rebind(reordered))
        duplicate = deepcopy(value)
        duplicate["pages"].append(deepcopy(duplicate["pages"][1]))
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "page:request"):
            independent.verify_bytes(_rebind(duplicate))
        cyclic = deepcopy(value)
        cyclic["pages"][0]["bundle"]["link"][1]["url"] = profile.REQUEST_URL
        cyclic["pages"][0]["next_url"] = profile.REQUEST_URL
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "bundle:query-drift"):
            independent.verify_bytes(_rebind(cyclic))
        drift = deepcopy(value)
        drift["pages"][0]["bundle"]["link"][1]["url"] = profile.REQUEST_URL + "&page=99"
        drift["pages"][0]["next_url"] = profile.REQUEST_URL + "&page=99"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "bundle:query-drift"):
            independent.verify_bytes(_rebind(drift))
        marker = deepcopy(value)
        marker["pages"][1]["bundle"]["total"] = 2
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "total-drift"):
            independent.verify_bytes(_rebind(marker))
        updated = deepcopy(value)
        updated["pages"][1]["bundle"]["meta"]["lastUpdated"] = "2026-08-13T12:00:00Z"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "marker-drift"):
            independent.verify_bytes(_rebind(updated))

    def test_caller_claim_upgrades_and_producer_forgery_reject(self) -> None:
        raw = _envelope()
        for key, claim in (("completeness", "COMPLETE"), ("allow_nonmembership", True)):
            value = json.loads(raw.decode("ascii"))
            value["claims"][key] = claim
            with self.subTest(claim=key), self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:claims"):
                independent.verify_bytes(_rebind(value))
        value = json.loads(raw.decode("ascii"))
        value["accepted"] = True
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "envelope:schema"):
            independent.verify_bytes(_rebind(value))

    def test_stale_partial_and_failed_evidence_cannot_reach_graph(self) -> None:
        stale = _envelope(last_updated="1970-01-01T00:00:00Z")
        self.assert_capture_failure(stale, "stale", status="STALE", freshness="STALE")
        first = _bundle(0, resources=[_practitioner(), _role()], next_page=True)
        partial = fhir.build_fixture_envelope(_transport(first))
        partial_result = independent.verify_bytes(partial)
        self.assertIn(partial_result["source_status"], {"PARTIAL", "FAILED"})
        with self.assertRaises(independent.IndependentNcMedicaidFhirError):
            independent.NcMedicaidFhirVerifier().verify(partial)

    def test_public_errors_redact_input_and_custom_transport_canaries(self) -> None:
        canary = "PHI_CANARY Bearer SECRET C:\\Users\\private\\record"

        class ExplodingTransport:
            def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> fhir.FhirTransportResponse:
                del request_url, timeout_seconds, attempt
                raise RuntimeError(canary)

        raw = fhir.build_fixture_envelope(ExplodingTransport())
        self.assertNotIn(canary.encode("ascii"), raw)
        self.assert_capture_failure(raw, "retry-exhausted", status="FAILED")

        class StopSignal(BaseException):
            pass

        class StoppingTransport:
            def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> fhir.FhirTransportResponse:
                del request_url, timeout_seconds, attempt
                raise StopSignal(canary)

        with self.assertRaises(StopSignal):
            fhir.build_fixture_envelope(StoppingTransport())

        for field, value in (("source_status", canary), ("failure_code", canary)):
            result_value = {"accepted": False, "source_status": "PARTIAL", "page_complete": False, "failure_code": None}
            result_value[field] = value
            with self.assertRaises(independent.IndependentNcMedicaidFhirError) as caught:
                independent.to_verified_source_coverage(result_value)
            error = caught.exception
            rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            self.assertEqual(str(error), "source:invalid")
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertTrue(error.__suppress_context__)
            self.assertNotIn(canary, repr(error) + rendered)

        malformed = b'{"source":"' + canary.encode("ascii") + b'"'
        with self.assertRaises(independent.IndependentNcMedicaidFhirError) as caught:
            independent.verify_bytes(malformed)
        error = caught.exception
        rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self.assertEqual(str(error), "json:parse")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn(canary, repr(error) + rendered)

if __name__ == "__main__":
    unittest.main()
