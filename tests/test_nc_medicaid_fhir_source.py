"""Fixture-qualified NC Medicaid FHIR source-boundary tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import nc_medicaid_fhir as fhir
from app.mirror import nc_medicaid_fhir_independent as independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import support_boundary as support
from app.mirror.source_admission import SourceAdmissionService


def _practitioner() -> dict[str, object]:
    return {
        "resourceType": "Practitioner",
        "id": profile.SYNTHETIC_PRACTITIONER_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:provider", "value": "NCPROV-001"}],
        "name": [{"use": "official", "family": "Synthetic", "given": ["Provider"]}],
        "active": True,
    }


def _role() -> dict[str, object]:
    return {
        "resourceType": "PractitionerRole",
        "id": profile.SYNTHETIC_ROLE_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:role", "value": "NCROLE-001"}],
        "active": True,
        "practitioner": {"reference": "Practitioner/" + profile.SYNTHETIC_PRACTITIONER_ID},
        "location": [{"reference": "Location/" + profile.SYNTHETIC_LOCATION_ID}],
        "code": [{"coding": [{"system": "urn:synthetic:ncmedicaid:role", "code": "primary-care", "display": "Primary Care"}], "text": "Synthetic primary care"}],
        "specialty": [{"coding": [{"system": "urn:synthetic:ncmedicaid:specialty", "code": "family-medicine", "display": "Family Medicine"}], "text": "Synthetic family medicine"}],
        "network": [],
        "period": {"start": "2026-01-01", "end": "2026-12-31"},
        "endpoint": [],
    }


def _location() -> dict[str, object]:
    return {
        "resourceType": "Location",
        "id": profile.SYNTHETIC_LOCATION_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:location", "value": "NCLOC-001"}],
        "name": "Synthetic NC Site",
        "status": "active",
        "address": {"use": "work", "line": ["1 Synthetic Way"], "city": "Raleigh", "state": "NC", "postalCode": "27601", "country": "US"},
        "endpoint": [],
    }


def _bundle(page: int = 0, *, resources: list[dict[str, object]] | None = None, next_page: bool = False, total: int | None = 3, last_updated: str | None = profile.FIXTURE_LAST_UPDATED) -> dict[str, object]:
    if resources is None:
        resources = [_practitioner(), _role(), _location()]
    request_url = profile.NC_MEDICAID_PROFILE.page_url(page)
    links: list[dict[str, str]] = [{"relation": "self", "url": request_url}]
    if next_page:
        links.append({"relation": "next", "url": profile.NC_MEDICAID_PROFILE.page_url(page + 1)})
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


def _transport(*bundles: dict[str, object], retries: dict[tuple[str, int], fhir.FhirTransportResponse] | None = None) -> fhir.SyntheticFhirTransport:
    responses: dict[tuple[str, int], fhir.FhirTransportResponse] = {}
    for index, bundle in enumerate(bundles):
        request_url = profile.NC_MEDICAID_PROFILE.page_url(index)
        responses[(request_url, 0)] = fhir.fixture_response(bundle, request_url)
    if retries:
        responses.update(retries)
    return fhir.SyntheticFhirTransport(responses)


def _envelope(*, two_pages: bool = False, total: int | None = 3, last_updated: str | None = profile.FIXTURE_LAST_UPDATED) -> bytes:
    if not two_pages:
        return fhir.build_fixture_envelope(_transport(_bundle(total=total, last_updated=last_updated)))
    first = _bundle(0, resources=[_practitioner(), _role()], next_page=True, total=total, last_updated=last_updated)
    second = _bundle(1, resources=[_location()], total=total, last_updated=last_updated)
    return fhir.build_fixture_envelope(_transport(first, second))


def _rebind(value: dict[str, object]) -> bytes:
    for page in value["pages"]:
        if not isinstance(page, dict) or not isinstance(page.get("bundle"), dict):
            continue
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
            "profile": profile.NC_MEDICAID_PROFILE.binding(),
            "request_identity": fhir._digest("request", {"method": "GET", "url": profile.REQUEST_URL, "query_parameters": [list(item) for item in profile.NC_MEDICAID_PROFILE.query_parameters], "page_parameter": profile.NC_MEDICAID_PROFILE.page_parameter}),
            "observation_time": profile.NC_MEDICAID_PROFILE.observation_time,
            "fetched_at": profile.NC_MEDICAID_PROFILE.fetched_at,
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
    def test_fixed_profile_and_contract_digest_are_verifier_owned(self) -> None:
        self.assertEqual("ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v1", profile.SOURCE_PROFILE_ID)
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

    def test_live_transport_is_blocked_before_network_and_media_failures_are_explicit(self) -> None:
        with self.assertRaisesRegex(fhir.FhirTransportError, "live-transport-disabled"):
            fhir.LiveFhirTransport().fetch(profile.REQUEST_URL, timeout_seconds=5, attempt=0)
        request_url = profile.REQUEST_URL
        bad = fhir.SyntheticFhirTransport({(request_url, 0): fhir.fixture_response(_bundle(), request_url, media_type="application/json")})
        raw = fhir.build_fixture_envelope(bad)
        result = independent.verify_bytes(raw)
        self.assertEqual("FAILED", result["source_status"])
        self.assertEqual("media-type", result["failure_code"])
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:media-type"):
            independent.NcMedicaidFhirVerifier().verify(raw)
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
        failed_result = independent.verify_bytes(failed)
        self.assertEqual("FAILED", failed_result["source_status"])
        self.assertEqual("retry-exhausted", failed_result["failure_code"])

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
        mutations.append(("role:practitioner:reference", value))
        for code, mutated in mutations:
            with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, code):
                independent.verify_bytes(_rebind(mutated))

    def test_bad_identifier_period_address_endpoint_and_forbidden_field_reject(self) -> None:
        mutations = []
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][0]["resource"]["unexpected"] = True
        mutations.append(("forbidden-field", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][0]["resource"]["identifier"][0]["system"] = "not a uri"
        mutations.append(("practitioner:identifier:system", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][1]["resource"]["period"] = {"start": "2026-12-31", "end": "2026-01-01"}
        mutations.append(("resource:period-order", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][2]["resource"]["address"]["postalCode"] = {"raw": "27601"}
        mutations.append(("resource:address-postalCode:text", value))
        value = json.loads(_envelope().decode("ascii"))
        value["pages"][0]["bundle"]["entry"][2]["resource"]["endpoint"] = [{"reference": "Endpoint/SYNTH_ENDPOINT_001"}]
        mutations.append(("location:endpoint:unlinked", value))
        for code, mutated in mutations:
            with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, code):
                independent.verify_bytes(_rebind(mutated))

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
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "markers:drift"):
            independent.verify_bytes(_rebind(marker))
        updated = deepcopy(value)
        updated["pages"][1]["bundle"]["meta"]["lastUpdated"] = "2026-08-13T12:00:00Z"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "markers:drift"):
            independent.verify_bytes(_rebind(updated))

    def test_caller_claim_upgrades_and_producer_forgery_reject(self) -> None:
        raw = _envelope()
        value = json.loads(raw.decode("ascii"))
        value["claims"]["completeness"] = "COMPLETE"
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:claims"):
            independent.verify_bytes(_rebind(value))
        value = json.loads(raw.decode("ascii"))
        value["claims"]["allow_nonmembership"] = True
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "snapshot:claims"):
            independent.verify_bytes(_rebind(value))
        value = json.loads(raw.decode("ascii"))
        value["accepted"] = True
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "envelope:schema"):
            independent.verify_bytes(_rebind(value))

    def test_stale_partial_and_failed_evidence_cannot_reach_graph(self) -> None:
        stale = _envelope(last_updated="2020-01-01T00:00:00Z")
        stale_result = independent.verify_bytes(stale)
        self.assertEqual("STALE", stale_result["source_status"])
        self.assertEqual("stale", stale_result["failure_code"])
        with self.assertRaisesRegex(independent.IndependentNcMedicaidFhirError, "source:stale"):
            independent.NcMedicaidFhirVerifier().verify(stale)
        first = _bundle(0, resources=[_practitioner(), _role()], next_page=True)
        partial = fhir.build_fixture_envelope(_transport(first))
        partial_result = independent.verify_bytes(partial)
        self.assertIn(partial_result["source_status"], {"PARTIAL", "FAILED"})
        with self.assertRaises(independent.IndependentNcMedicaidFhirError):
            independent.NcMedicaidFhirVerifier().verify(partial)

    def test_observation_only_governance_store_export_restore_and_support(self) -> None:
        envelope = _envelope()
        admission = SourceAdmissionService(profile.NC_MEDICAID_GRAPH_PROFILE, independent.NcMedicaidFhirVerifier()).admit(envelope)
        graph_raw = admission.graph_artifact
        candidate, _ = governance.build_candidate(graph_raw, profile.NC_MEDICAID_GRAPH_PROFILE)
        tested, _ = governance.build_tested(candidate, profile.NC_MEDICAID_GRAPH_PROFILE)
        approval_record = governance.build_approval_record(tested, profile.NC_MEDICAID_GRAPH_PROFILE, approval_time=7_300)
        approved, _ = governance.build_approved(tested, approval_record, profile.NC_MEDICAID_GRAPH_PROFILE)
        registry = dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
        with tempfile.TemporaryDirectory(prefix="nc-medicaid-fhir-store-") as directory:
            root = Path(directory)
            database = root / "state.db"
            instance = store.ContinuityStore(database, graph_profile_registry=registry)
            before = instance._snapshot_rows()
            with self.assertRaisesRegex(store.StoreConflictError, "governance:not-approved"):
                instance.admit(store.ARTIFACT_GRAPH, graph_raw)
            self.assertEqual(before, instance._snapshot_rows())
            for artifact in (candidate, tested, approved):
                instance.admit(store.ARTIFACT_GOVERNANCE, artifact)
            first = instance.admit(store.ARTIFACT_GRAPH, graph_raw)
            self.assertEqual(first.raw, instance.admit(store.ARTIFACT_GRAPH, graph_raw).raw)
            withdrawal_authorization = governance.build_withdrawal_authorization(approved, profile.NC_MEDICAID_GRAPH_PROFILE, withdrawal_time=7_400)
            withdrawal, _ = governance.build_withdrawal(approved, withdrawal_authorization, profile.NC_MEDICAID_GRAPH_PROFILE)
            instance.admit(store.ARTIFACT_GOVERNANCE, withdrawal)
            self.assertEqual(first.raw, instance.admit(store.ARTIFACT_GRAPH, graph_raw).raw)
            exported = export.export_database(database, registry)
            restored = root / "restored.db"
            export.import_export(exported, restored, registry)
            self.assertEqual(exported, export.export_database(restored, registry))
            bundle = support.build_support_bundle(database, graph_profile_registry=registry)
            self.assertNotIn(profile.SYNTHETIC_SUBJECT, bundle.decode("ascii"))
            self.assertNotIn("NCPROV-001", bundle.decode("ascii"))
            self.assertTrue(support.verify_support_bytes(bundle)["accepted"])
        safe = independent.build_support_evidence(envelope)
        self.assertNotIn(profile.SYNTHETIC_PRACTITIONER_ID, safe.decode("ascii"))
        self.assertTrue(independent.verify_support_evidence(safe)["accepted"])


if __name__ == "__main__":
    unittest.main()
