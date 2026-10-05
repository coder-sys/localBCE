from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import functools
import json
import traceback
import unittest
from unittest.mock import patch

from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import nc_medicaid_fhir_independent as nc_fhir
from app.mirror import nc_medicaid_fhir_profile as nc_profile
from app.mirror import source_admission
from app.mirror.source_admission import (
    SourceAdmissionError,
    SourceAdmissionService,
    SourceProfile,
    VerifiedSourceCoverage,
)


@functools.cache
def _fixture() -> tuple[bytes, SourceProfile, VerifiedSourceCoverage]:
    from tests.test_nc_medicaid_fhir_source import _envelope

    context = nc_profile.DynamicCaptureContext("1" * 128, "2" * 128, "3" * 128, "4" * 128, 7_060, 7_070)
    raw = _envelope(context=context)
    profile = nc_profile.NC_MEDICAID_PROFILE.graph_profile_for_context(context)
    return raw, profile, nc_fhir.NcMedicaidFhirVerifier(expected_context=context).verify(raw)


class FixedVerifier:
    """Returns one pre-verified nc result so admission is tested on its own."""

    def __init__(self, result: VerifiedSourceCoverage | None = None) -> None:
        _, profile, verified = _fixture()
        self.identity = profile.verifier_id
        self.epoch = profile.verifier_epoch
        self.result = verified if result is None else result
        self.calls = 0

    def verify(self, _raw: bytes) -> VerifiedSourceCoverage:
        self.calls += 1
        return self.result


def _service(verifier: object | None = None, profile: SourceProfile | None = None) -> SourceAdmissionService:
    return SourceAdmissionService(profile or _fixture()[1], verifier or FixedVerifier())  # type: ignore[arg-type]


class MirrorSourceAdmissionTests(unittest.TestCase):
    def test_configured_verifier_drives_admission_and_graph_is_independent(self) -> None:
        raw, profile, _ = _fixture()
        admission = _service().admit(raw)
        independent = graph_independent.verify_bytes_v2(admission.graph_artifact, {profile.profile_id: profile})
        receipt = json.loads(admission.receipt.decode("ascii"))
        artifact = graph.parse_canonical(admission.graph_artifact, artifact=True)

        self.assertTrue(independent["accepted"])
        self.assertEqual(admission.report_id, independent["report_id"])
        self.assertEqual(profile.profile_id, admission.profile_id)
        self.assertEqual(profile.verifier_id, admission.verifier_id)
        self.assertEqual(profile.verifier_epoch, admission.verifier_epoch)
        self.assertFalse(admission.production_source_authentication)
        self.assertFalse(receipt["production_source_authentication"])
        self.assertEqual(profile.evidence_mode, receipt["evidence_mode"])
        self.assertEqual(
            {"clearance_authority": False, "payment_authority": False, "economic_mutation": False},
            {key: artifact["authority"][key] for key in ("clearance_authority", "payment_authority", "economic_mutation")},
        )
        self.assertNotIn("directive", artifact)
        self.assertNotIn("payment", artifact)

    def test_removed_external_keyword_api_rejects_before_mutation(self) -> None:
        raw = _fixture()[0]
        verifier = FixedVerifier()
        service = _service(verifier)
        before = service.admit(raw)
        calls_before = verifier.calls
        for removed_kwargs in (
            {"external_evidence_raw": b"removed"},
            {"external_policy": {}},
        ):
            with self.subTest(removed_kwargs=tuple(removed_kwargs)):
                with self.assertRaises(TypeError):
                    service.admit(raw, **removed_kwargs)  # type: ignore[call-arg]
                self.assertEqual(calls_before, verifier.calls)
        after = service.admit(raw)
        self.assertEqual(before, after)
        self.assertEqual(calls_before + 1, verifier.calls)
        for field in (
            "external_artifact_id",
            "external_artifact_digest",
            "capture_id",
            "capture_context_digest",
        ):
            self.assertFalse(hasattr(before, field))

    def test_verifier_failure_and_malformed_output_fail_closed(self) -> None:
        raw, _, verified = _fixture()

        class FailingVerifier(FixedVerifier):
            def verify(self, _raw: bytes) -> VerifiedSourceCoverage:
                raise ValueError("fixture failure")

        with self.assertRaisesRegex(SourceAdmissionError, "verifier:reject"):
            _service(FailingVerifier()).admit(raw)
        with self.assertRaisesRegex(SourceAdmissionError, "graph:producer-reject"):
            _service(FixedVerifier(replace(verified, graph_input=b"not-canonical"))).admit(raw)

    def test_arbitrary_verifier_graph_and_parser_failures_have_no_public_context(self) -> None:
        canary = "PRIVATE-SOURCE-BOUNDARY-CANARY"
        raw, profile, verified = _fixture()
        valid_report = graph.build_report(verified.graph_input, profile=profile)
        stages = (
            (FixedVerifier, "verify", "verifier:reject"),
            (graph, "build_report", "graph:producer-reject"),
            (graph_independent, "verify_bytes_v2", "graph:independent-reject"),
            (graph, "parse_canonical", "graph:artifact-shape"),
        )
        for target, method, code in stages:
            with self.subTest(stage=code), ExitStack() as patches:
                if method == "parse_canonical":
                    patches.enter_context(patch.object(graph, "build_report", return_value=valid_report))
                patches.enter_context(patch.object(target, method, side_effect=RuntimeError(canary)))
                with self.assertRaisesRegex(SourceAdmissionError, code) as caught:
                    _service().admit(raw)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(canary, str(caught.exception))
                self.assertNotIn(canary, "".join(traceback.format_exception(caught.exception)))

    def test_verifier_configuration_failure_has_no_public_context(self) -> None:
        canary = "PRIVATE-SOURCE-VERIFIER-CANARY"
        raw, profile, _ = _fixture()

        class ExplodingConfiguration:
            @property
            def identity(self) -> str:
                raise RuntimeError(canary)

            @property
            def epoch(self) -> int:
                return profile.verifier_epoch

        with self.assertRaisesRegex(SourceAdmissionError, "composition:verifier") as caught:
            _service(ExplodingConfiguration()).admit(raw)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(canary, str(caught.exception))
        self.assertNotIn(canary, "".join(traceback.format_exception(caught.exception)))

    def test_result_profile_coverage_roles_and_mode_are_service_owned(self) -> None:
        raw, profile, verified = _fixture()
        strict = replace(profile, require_complete=True)
        mutations = (
            ("profile", {"profile_id": "OTHER_PROFILE"}, "result:profile-mismatch"),
            ("subject", {"subject": "OTHER_SUBJECT"}, "result:subject-or-scope-mismatch"),
            ("roles", {"source_roles": ("OTHER_ROLE", "OTHER_ROLE_2")}, "result:source-roles-mismatch"),
            ("partial", {"complete": False}, "result:partial-coverage"),
            ("malformed-complete", {"complete": 1}, "result:completeness"),
            ("mode", {"evidence_mode": "production"}, "result:evidence-mode-mismatch"),
        )
        for name, changes, expected in mutations:
            with self.subTest(name=name):
                result = replace(verified, graph_profile=strict, **{"complete": True, **changes})
                with self.assertRaisesRegex(SourceAdmissionError, expected):
                    _service(FixedVerifier(result), strict).admit(raw)

    def test_result_profile_is_required_and_owned_field_exact(self) -> None:
        raw, configured, verified = _fixture()
        cases = {
            "omitted": None,
            "profile-id": replace(configured, profile_id="OTHER_PROFILE", version=2),
            "credential": replace(configured, credential_id="f" * 128),
            "enrollment": replace(configured, enrollment_id="e" * 128),
            "source-role": replace(
                configured,
                source_role_details=(
                    replace(configured.source_role_details[0], authority_id="REBOUND"),
                    configured.source_role_details[1],
                ),
            ),
        }
        for name, graph_profile in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(SourceAdmissionError, "^result:profile-mismatch$") as caught:
                    _service(FixedVerifier(replace(verified, graph_profile=graph_profile))).admit(raw)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertTrue(caught.exception.__suppress_context__)
        _service().admit(raw)
        for shifted in (verified.observation_time - 1, verified.observation_time + 1, 999_999):
            with self.subTest(observation_time=shifted):
                with self.assertRaisesRegex(SourceAdmissionError, "^result:observation-mismatch$"):
                    _service(FixedVerifier(replace(verified, observation_time=shifted))).admit(raw)

    def test_graph_output_profile_and_coverage_rebinding_fail_closed(self) -> None:
        raw, _, verified = _fixture()
        value = json.loads(verified.graph_input)
        value["sources"][0]["coverage_effective_end"] = 6_999
        value["sources"][0]["provenance"]["integrity_digest"] = graph.source_integrity_digest(value["sources"][0])
        stale = replace(verified, graph_input=graph.canonical_input(value))
        with self.assertRaisesRegex(SourceAdmissionError, "graph:producer-reject|graph:stale-coverage"):
            _service(FixedVerifier(stale)).admit(raw)

    def test_exact_retry_is_deterministic_and_conflicting_retry_rejects(self) -> None:
        raw = _fixture()[0]
        service = _service()
        first = service.admit(raw)
        replay = service.admit(raw, expected_receipt=first.receipt)
        self.assertEqual(first.receipt, replay.receipt)
        self.assertEqual(first.graph_artifact, replay.graph_artifact)
        with self.assertRaisesRegex(SourceAdmissionError, "retry:conflict"):
            service.admit(raw, expected_receipt=first.receipt + b" ")

    def test_composition_mismatch_and_production_mode_are_rejected(self) -> None:
        profile = _fixture()[1]
        with self.assertRaisesRegex(SourceAdmissionError, "composition:verifier-mismatch"):
            _service(profile=replace(profile, verifier_id="OTHER_VERIFIER"))
        with self.assertRaisesRegex(ValueError, "profile:evidence-mode-not-qualified"):
            replace(profile, evidence_mode="production")
        with self.assertRaisesRegex(ValueError, "profile:source-roles"):
            replace(profile, source_roles=list(profile.source_roles))

    def test_retired_v1_grammars_are_refused(self) -> None:
        raw, profile, verified = _fixture()
        artifact = json.loads(_service().admit(raw).graph_artifact)
        del artifact["profile"]
        artifact["schema"] = "mirror-provider-trust-graph-v1"
        v1_artifact = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaisesRegex(graph_independent.IndependentProviderTrustGraphError, "^artifact:profile:schema$"):
            graph_independent.verify_bytes_v2(v1_artifact, {profile.profile_id: profile})
        self.assertFalse(hasattr(graph_independent, "verify_bytes"))
        value = json.loads(verified.graph_input)
        value["schema"] = "mirror-provider-trust-graph-input-v1"
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "^input:schema$"):
            graph.build_report(graph.canonical_input(value), profile=profile)
        with self.assertRaisesRegex(ValueError, "^profile:source-role-details$"):
            replace(profile, source_role_details=None)
        self.assertFalse(hasattr(source_admission, "RECEIPT_SCHEMA"))
        self.assertEqual("mirror-source-admission-receipt-v2", json.loads(_service().admit(raw).receipt)["schema"])


if __name__ == "__main__":
    unittest.main()
