"""Focused tests for the bounded synthetic PTG staff read model."""

from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_evidence_export_v1 as evidence_export
from app.mirror import provider_trust_graph as graph_producer
from app.mirror import provider_trust_graph_read_model_v1 as read_model
from app.mirror.source_admission import SourceAdmissionService
from tests.test_nc_medicaid_fhir_source import _envelope


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _request(operation_ref: str = "a" * 64) -> bytes:
    return _canonical(
        {
            "domain": evidence_export.REQUEST_DOMAIN,
            "version": 1,
            "operation_ref": operation_ref,
            "consumer_domain": evidence_export.CONSUMER_DOMAIN,
            "evidence_profile": evidence_export.EVIDENCE_PROFILE,
            "evidence_profile_version": evidence_export.EVIDENCE_PROFILE_VERSION,
            "not_before": 6_990,
            "expires_at": 7_050,
        }
    )


def _admission():
    return SourceAdmissionService(
        profile.NC_MEDICAID_GRAPH_PROFILE,
        fhir_independent.NcMedicaidFhirVerifier(),
    ).admit(_envelope())


def _read(artifact: bytes, *, profile_id: str | None = None, profile_version: int = 3) -> bytes:
    selected_profile_id = profile_id or profile.NC_MEDICAID_GRAPH_PROFILE.profile_id
    return read_model.build_read_model_v1(
        artifact,
        dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY),
        expected_profile_id=selected_profile_id,
        expected_profile_version=profile_version,
        export_request_raw=_request(),
        expected_operation_ref="a" * 64,
        now=7_000,
    )


def _selection(artifact: bytes, operation_ref: str = "a" * 64) -> read_model.ProviderTrustGraphReadSelectionV1:
    return read_model.ProviderTrustGraphReadSelectionV1(
        graph_artifact=artifact,
        profile_registry=dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY),
        expected_profile_id=profile.NC_MEDICAID_GRAPH_PROFILE.profile_id,
        expected_profile_version=profile.NC_MEDICAID_GRAPH_PROFILE.version,
        export_request_raw=_request(operation_ref),
        expected_operation_ref=operation_ref,
    )


def _stale_artifact(admission) -> bytes:
    value = json.loads(admission.graph_input.decode("ascii"))
    for source in value["sources"]:
        source["coverage_effective_start"] = value["observation_time"] + 1
        source["coverage_effective_end"] = 9_000
        source["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
            source,
            profile=profile.NC_MEDICAID_GRAPH_PROFILE,
        )
    artifact = graph_producer.build_report(
        graph_producer.canonical_input(value),
        profile=profile.NC_MEDICAID_GRAPH_PROFILE,
    )
    return artifact


def _walk(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class ProviderTrustGraphReadModelV1Tests(unittest.TestCase):
    def test_read_is_bounded_deterministic_transient_and_identifier_free(self) -> None:
        admission = _admission()
        original = admission.graph_artifact
        first = _read(original)
        second = _read(original)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), read_model.MAX_RESPONSE_BYTES)
        self.assertEqual(original, admission.graph_artifact)

        value = json.loads(first.decode("ascii"))
        self.assertEqual(read_model.SCHEMA, value["schema"])
        self.assertEqual("UNKNOWN", value["status"]["freshness"])
        self.assertEqual("UNKNOWN", value["status"]["completeness"])
        self.assertEqual("NOT_ESTABLISHED", value["status"]["source_truth"])
        self.assertEqual("CALLER_SUPPLIED_TRANSIENT", value["status"]["artifact_durability"])
        self.assertEqual("UPSTREAM_REQUIRED", value["status"]["caller_authorization"])
        self.assertIs(value["status"]["persisted"], False)
        self.assertEqual("FORBIDDEN", value["status"]["absence_inference"])
        self.assertEqual("CURRENT_VERIFIED_PROJECTION_ONLY", value["summary"]["count_semantics"])
        self.assertNotIn("outcome", value)
        self.assertNotIn("complete_source_count", repr(value))
        self.assertNotIn("operation_ref", repr(value))
        self.assertEqual((2, 2, 1, 0), (
            value["summary"]["source_count"],
            value["summary"]["record_count"],
            value["summary"]["finding_count"],
            value["summary"]["discrepancy_count"],
        ))
        self.assertEqual(
            ["FHIR_PRACTITIONER", "FHIR_PRACTITIONER_ROLE_LOCATION"],
            [source["source_role"] for source in value["observation"]["sources"]],
        )
        self.assertTrue(all(
            source["freshness"] == "UNKNOWN" and source["completeness"] == "UNKNOWN"
            for source in value["observation"]["sources"]
        ))
        self.assertEqual(
            "EVIDENCE_INCOMPLETE",
            value["observation"]["findings"][0]["graph_finding_kind"],
        )

        forbidden_keys = {
            "provider_id", "provider_graph_subject", "source_id", "record_id",
            "credential_id", "enrollment_id", "subject_key", "finding_id",
            "observation_snapshot_id", "snapshot_id", "snapshot_root",
            "source_root", "source_coverage_root", "findings_root",
            "discrepancies_root", "report_id", "profile_digest", "integrity_digest",
            "provenance_id", "coverage_authority_id", "nonmembership_keys",
            "evidence_refs", "operation_ref", "coverage_complete",
        }
        self.assertFalse(forbidden_keys.intersection(key for key, _ in _walk(value)))

        artifact = json.loads(original.decode("ascii"))
        sensitive_values = []
        sensitive_keys = {
            "provider_graph_subject", "source_id", "record_id", "provider_id",
            "credential_id", "enrollment_id", "subject_key", "finding_id",
            "observation_snapshot_id", "snapshot_id", "snapshot_root",
            "source_root", "report_id", "profile_digest", "integrity_digest",
            "provenance_id", "coverage_authority_id",
        }
        for key, child in _walk(artifact):
            if key in sensitive_keys and type(child) is str:
                sensitive_values.append(child)
        response_text = first.decode("ascii")
        self.assertTrue(sensitive_values)
        for sensitive_value in sensitive_values:
            self.assertNotIn(sensitive_value, response_text)

    def test_stale_coverage_is_visible_without_freshness_or_completeness_claim(self) -> None:
        admission = _admission()
        response = json.loads(_read(_stale_artifact(admission)).decode("ascii"))
        self.assertEqual("UNKNOWN", response["status"]["freshness"])
        self.assertEqual("UNKNOWN", response["status"]["completeness"])
        self.assertEqual("NOT_ESTABLISHED", response["status"]["source_truth"])
        self.assertIn(
            "COVERAGE_STALE",
            [finding["graph_finding_kind"] for finding in response["observation"]["findings"]],
        )

    def test_tampered_artifact_and_wrong_profile_reject_with_redacted_errors(self) -> None:
        admission = _admission()
        tampered = admission.graph_artifact.replace(b'"synthetic_only":true', b'"synthetic_only":false', 1)
        self.assertNotEqual(tampered, admission.graph_artifact)
        with self.assertRaisesRegex(read_model.ProviderTrustGraphReadModelV1Error, "read:v1:graph-reject"):
            _read(tampered)
        with self.assertRaisesRegex(read_model.ProviderTrustGraphReadModelV1Error, "read:v1:profile-registry"):
            _read(admission.graph_artifact, profile_id="UNREGISTERED_PROFILE")
        with self.assertRaisesRegex(read_model.ProviderTrustGraphReadModelV1Error, "read:v1:profile"):
            _read(admission.graph_artifact, profile_version=4)

    def test_page_and_detail_are_bounded_ephemeral_and_identifier_free(self) -> None:
        admission = _admission()
        selection = _selection(admission.graph_artifact)
        first_page = json.loads(
            read_model.build_read_model_page_v1(
                selection,
                collection="sources",
                offset=0,
                page_size=1,
                now=7_000,
            ).decode("ascii")
        )
        self.assertEqual("PAGE", first_page["view"])
        self.assertEqual(2, first_page["page"]["projected_item_count"])
        self.assertEqual(1, len(first_page["page"]["items"]))
        self.assertEqual(1, first_page["page"]["next_offset"])
        self.assertEqual("UNKNOWN", first_page["context"]["freshness"])
        self.assertEqual("UNKNOWN", first_page["context"]["completeness"])
        self.assertIs(first_page["persisted"], False)

        detail = json.loads(
            read_model.build_read_model_detail_v1(
                selection,
                collection="sources",
                index=0,
                now=7_000,
            ).decode("ascii")
        )
        self.assertEqual("DETAIL", detail["view"])
        self.assertIs(detail["detail"]["stable_identity"], False)
        self.assertIs(detail["persisted"], False)
        self.assertEqual("SYNTHETIC_PROFILE_BOUND", detail["detail"]["item"]["provenance_basis"])
        self.assertNotIn("source_id", json.dumps(detail))
        with self.assertRaisesRegex(read_model.ProviderTrustGraphReadModelV1Error, "read:v1:page-offset"):
            read_model.build_read_model_page_v1(
                selection,
                collection="sources",
                offset=3,
                page_size=1,
                now=7_000,
            )

    def test_compare_reverifies_both_observations_and_never_infers_absence(self) -> None:
        admission = _admission()
        left_ref = "a" * 64
        right_ref = "b" * 64
        response = json.loads(
            read_model.compare_read_models_v1(
                _selection(admission.graph_artifact, left_ref),
                _selection(_stale_artifact(admission), right_ref),
                now=7_000,
            ).decode("ascii")
        )
        comparison = response["comparison"]
        self.assertEqual("COMPARE", response["view"])
        self.assertEqual("UNKNOWN_NOT_ABSENT", comparison["missing_evidence_semantics"])
        self.assertEqual("FORBIDDEN", response["status"]["absence_inference"])
        self.assertIs(response["status"]["persisted"], False)
        self.assertTrue(comparison["source_changes"])
        self.assertTrue(comparison["finding_deltas"])
        self.assertEqual("SYNTHETIC_PROFILE_BOUND", comparison["left"]["provenance_basis"])
        self.assertNotIn("interpretation", comparison["left"])
        self.assertTrue(comparison["left"]["source_provenance"])
        self.assertEqual("UNKNOWN", comparison["left"]["freshness"])
        self.assertEqual("UNKNOWN", comparison["right"]["completeness"])
        self.assertNotIn("profile_digest", json.dumps(response))
        self.assertNotIn(left_ref, json.dumps(response))
        self.assertNotIn(right_ref, json.dumps(response))

        wrong_profile = _selection(admission.graph_artifact, right_ref)
        wrong_profile = read_model.ProviderTrustGraphReadSelectionV1(
            **{**wrong_profile.__dict__, "expected_profile_version": 4}
        )
        with self.assertRaisesRegex(read_model.ProviderTrustGraphReadModelV1Error, "read:v1:profile"):
            read_model.compare_read_models_v1(_selection(admission.graph_artifact, left_ref), wrong_profile, now=7_000)

    def test_local_cli_reads_bounded_inputs_and_emits_only_the_view(self) -> None:
        admission = _admission()
        request = _request()
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "artifact.json"
            request_path = Path(directory) / "request.json"
            right_request_path = Path(directory) / "right-request.json"
            artifact_path.write_bytes(admission.graph_artifact)
            request_path.write_bytes(request)
            right_request_path.write_bytes(_request("b" * 64))
            cases = (
                ("PAGE", ["page", "--artifact", str(artifact_path), "--request", str(request_path),
                          "--operation-ref", "a" * 64, "--collection", "sources", "--page-size", "1"]),
                ("COMPARE", ["compare", "--left-artifact", str(artifact_path), "--left-request", str(request_path),
                             "--left-operation-ref", "a" * 64, "--right-artifact", str(artifact_path),
                             "--right-request", str(right_request_path), "--right-operation-ref", "b" * 64]),
            )
            for expected_view, args in cases:
                with self.subTest(view=expected_view), redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                    status = read_model.main(args + ["--now", "7000"])
                self.assertEqual(0, status)
                self.assertEqual("", stderr.getvalue())
                value = json.loads(stdout.getvalue())
                self.assertEqual(expected_view, value["view"])
                if expected_view == "PAGE":
                    self.assertEqual(1, len(value["page"]["items"]))


if __name__ == "__main__":
    unittest.main()
