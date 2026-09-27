from __future__ import annotations

from dataclasses import replace
from contextlib import ExitStack
import json
import traceback
import unittest
from unittest.mock import patch

from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import nc_medicaid_fhir_independent as nc_fhir
from app.mirror import nc_medicaid_fhir_profile as nc_profile
from app.mirror.source_admission import (
    EvidenceMode,
    SourceAdmissionError,
    SourceAdmissionService,
    SourceProfile,
    VerifiedSourceCoverage,
)


ADAPTER_SCHEMA = "mirror-test-source-adapter-v1"
PROFILE_ID = "SYNTHETIC_TEST_PROVIDER_PROFILE_V1"
VERIFIER_ID = "SYNTHETIC_TEST_SOURCE_VERIFIER_V1"
VERIFIER_EPOCH = 1
SUPPORTED_CASES = {"confirmed", "absent", "expired", "terminated", "conflict"}


class SyntheticTestVerificationError(ValueError):
    """Fixture-only verifier failure; no production source authentication."""


class SyntheticTestSourceVerifier:
    """Explicit test verifier backed by existing graph fixtures only."""

    identity = VERIFIER_ID
    epoch = VERIFIER_EPOCH

    @staticmethod
    def _parse(raw: bytes) -> dict[str, object]:
        if type(raw) is not bytes or not raw:
            raise SyntheticTestVerificationError("synthetic:bytes")
        try:
            value = json.loads(
                raw.decode("ascii"),
                object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SyntheticTestVerificationError("synthetic:parse") from exc
        if not isinstance(value, dict) or set(value) != {"schema", "case"}:
            raise SyntheticTestVerificationError("synthetic:schema")
        if value["schema"] != ADAPTER_SCHEMA or value["case"] not in SUPPORTED_CASES:
            raise SyntheticTestVerificationError("synthetic:unsupported-case")
        canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        if canonical != raw:
            raise SyntheticTestVerificationError("synthetic:noncanonical")
        return value

    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        value = self._parse(adapter_bytes)
        case = value["case"]
        assert isinstance(case, str)
        graph_input_value = graph.demo_input(case)
        graph_input = graph.canonical_input(graph_input_value)
        sources = graph_input_value["sources"]
        assert isinstance(sources, list)
        source_roles = tuple(source["source_id"] for source in sources)
        return VerifiedSourceCoverage(
            profile_id=PROFILE_ID,
            subject=graph.PROVIDER_GRAPH_SUBJECT,
            scope=graph.SCOPE,
            observation_time=7_000,
            effective_start=6_000,
            effective_end=9_000,
            complete=all(source["coverage_complete"] is True for source in sources),
            source_roles=source_roles,
            evidence_mode=EvidenceMode.SYNTHETIC_TEST_ONLY,
            graph_input=graph_input,
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SyntheticTestVerificationError("synthetic:duplicate-key")
        value[key] = item
    return value


def _adapter(case: str = "confirmed", **extra: object) -> bytes:
    value: dict[str, object] = {"schema": ADAPTER_SCHEMA, "case": case, **extra}
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _profile(**overrides: object) -> SourceProfile:
    values: dict[str, object] = {
        "profile_id": PROFILE_ID,
        "version": 1,
        "subject": graph.PROVIDER_GRAPH_SUBJECT,
        "scope": graph.SCOPE,
        "observation_time": 7_000,
        "effective_start": 6_000,
        "effective_end": 9_000,
        "source_roles": graph.SOURCE_IDS,
        "require_complete": True,
        "verifier_id": VERIFIER_ID,
        "verifier_epoch": VERIFIER_EPOCH,
        "evidence_mode": EvidenceMode.SYNTHETIC_TEST_ONLY,
    }
    values.update(overrides)
    return SourceProfile(**values)  # type: ignore[arg-type]


def _service(verifier: object | None = None, profile: SourceProfile | None = None) -> SourceAdmissionService:
    return SourceAdmissionService(profile or _profile(), verifier or SyntheticTestSourceVerifier())  # type: ignore[arg-type]


class MirrorSourceAdmissionTests(unittest.TestCase):
    def test_configured_verifier_drives_admission_and_graph_is_independent(self) -> None:
        service = _service()
        admission = service.admit(_adapter())
        independent = graph_independent.verify_bytes(admission.graph_artifact)
        receipt = json.loads(admission.receipt.decode("ascii"))
        artifact = graph.parse_canonical(admission.graph_artifact, artifact=True)

        self.assertTrue(independent["accepted"])
        self.assertEqual(admission.report_id, independent["report_id"])
        self.assertEqual(PROFILE_ID, admission.profile_id)
        self.assertEqual(VERIFIER_ID, admission.verifier_id)
        self.assertEqual(VERIFIER_EPOCH, admission.verifier_epoch)
        self.assertFalse(admission.production_source_authentication)
        telemetry = dict(admission.telemetry)
        self.assertEqual(5, len(admission.telemetry))
        self.assertEqual(len(admission.graph_artifact), telemetry["artifact_bytes"])
        self.assertFalse(telemetry["proof_performance_claim"])
        self.assertNotIn("SYNTH_", repr(admission.telemetry))
        self.assertFalse(receipt["production_source_authentication"])
        self.assertEqual("synthetic_test_only", receipt["evidence_mode"])
        self.assertEqual(
            {"clearance_authority": False, "payment_authority": False, "economic_mutation": False},
            {key: artifact["authority"][key] for key in ("clearance_authority", "payment_authority", "economic_mutation")},
        )
        self.assertNotIn("directive", artifact)
        self.assertNotIn("payment", artifact)

    def test_raw_verifier_authentication_profile_and_mode_fields_are_rejected(self) -> None:
        for extra in (
            {"verifier_id": VERIFIER_ID},
            {"verifier_epoch": VERIFIER_EPOCH},
            {"authenticated": True},
            {"evidence_mode": "synthetic_test_only"},
            {"source_roles": list(graph.SOURCE_IDS)},
            {"version": 1},
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(SourceAdmissionError, "verifier:reject"):
                    _service().admit(_adapter(**extra))

    def test_removed_external_keyword_api_rejects_before_mutation(self) -> None:
        class CountingVerifier(SyntheticTestSourceVerifier):
            def __init__(self) -> None:
                self.calls = 0

            def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
                self.calls += 1
                return super().verify(adapter_bytes)

        verifier = CountingVerifier()
        service = _service(verifier)
        raw = _adapter()
        before = service.admit(raw)
        before_bytes = (
            before.graph_input,
            before.graph_artifact,
            before.receipt,
            before.observation,
            before.verification_receipt,
        )
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
        after_bytes = (
            after.graph_input,
            after.graph_artifact,
            after.receipt,
            after.observation,
            after.verification_receipt,
        )
        self.assertEqual(before_bytes, after_bytes)
        self.assertEqual(calls_before + 1, verifier.calls)
        for field in (
            "external_artifact_id",
            "external_artifact_digest",
            "capture_id",
            "capture_context_digest",
        ):
            self.assertFalse(hasattr(before, field))

    def test_synthetic_verifier_failure_and_malformed_output_fail_closed(self) -> None:
        with self.assertRaisesRegex(SourceAdmissionError, "verifier:reject"):
            _service().admit(_adapter("fail"))

        class BadVerifier(SyntheticTestSourceVerifier):
            def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
                result = super().verify(adapter_bytes)
                return replace(result, graph_input=b"not-canonical")

        with self.assertRaisesRegex(SourceAdmissionError, "graph:producer-reject"):
            _service(BadVerifier()).admit(_adapter())

    def test_arbitrary_verifier_graph_and_parser_failures_have_no_public_context(self) -> None:
        canary = "PRIVATE-SOURCE-BOUNDARY-CANARY"
        graph_input = SyntheticTestSourceVerifier().verify(_adapter()).graph_input
        valid_report = graph.build_report(graph_input)
        stages = (
            (SyntheticTestSourceVerifier, "verify", "verifier:reject"),
            (graph, "build_report", "graph:producer-reject"),
            (graph_independent, "verify_bytes", "graph:independent-reject"),
            (graph, "parse_canonical", "graph:artifact-shape"),
        )
        for target, method, code in stages:
            with self.subTest(stage=code), ExitStack() as patches:
                if method == "parse_canonical":
                    patches.enter_context(patch.object(graph, "build_report", return_value=valid_report))
                patches.enter_context(patch.object(target, method, side_effect=RuntimeError(canary)))
                with self.assertRaisesRegex(SourceAdmissionError, code) as caught:
                    _service().admit(_adapter())
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(canary, str(caught.exception))
                self.assertNotIn(canary, "".join(traceback.format_exception(caught.exception)))

    def test_verifier_configuration_failure_has_no_public_context(self) -> None:
        canary = "PRIVATE-SOURCE-VERIFIER-CANARY"

        class ExplodingConfiguration:
            @property
            def identity(self) -> str:
                raise RuntimeError(canary)

            @property
            def epoch(self) -> int:
                return VERIFIER_EPOCH

        with self.assertRaisesRegex(SourceAdmissionError, "composition:verifier") as caught:
            _service(ExplodingConfiguration()).admit(_adapter())
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(canary, str(caught.exception))
        self.assertNotIn(canary, "".join(traceback.format_exception(caught.exception)))

    def test_result_profile_coverage_roles_and_mode_are_service_owned(self) -> None:
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
                class MutatingVerifier(SyntheticTestSourceVerifier):
                    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
                        return replace(super().verify(adapter_bytes), **changes)

                with self.assertRaisesRegex(SourceAdmissionError, expected):
                    _service(MutatingVerifier()).admit(_adapter())

    def test_supplied_graph_profile_must_equal_the_configured_profile(self) -> None:
        configured = _profile()

        class RebindingVerifier(SyntheticTestSourceVerifier):
            def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
                result = super().verify(adapter_bytes)
                rebound = replace(configured, profile_id="SYNTHETIC_PROFILE_B", version=2)
                return replace(result, graph_profile=rebound)

        with self.assertRaisesRegex(SourceAdmissionError, "^result:profile-mismatch$") as caught:
            SourceAdmissionService(configured, RebindingVerifier()).admit(_adapter())
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_v2_result_profile_is_required_and_owned_field_exact(self) -> None:
        from tests.test_nc_medicaid_fhir_source import _envelope

        context = nc_profile.DynamicCaptureContext(
            "1" * 128, "2" * 128, "3" * 128, "4" * 128, 7_060, 7_070,
        )
        raw = _envelope(context=context)
        configured = nc_profile.NC_MEDICAID_PROFILE.graph_profile_for_context(context)
        verified = nc_fhir.NcMedicaidFhirVerifier(expected_context=context).verify(raw)

        class RebindingVerifier:
            identity = configured.verifier_id
            epoch = configured.verifier_epoch

            def __init__(self, result: VerifiedSourceCoverage) -> None:
                self.result = result

            def verify(self, _raw: bytes) -> VerifiedSourceCoverage:
                return self.result

        cases = {
            "omitted": None,
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
                    SourceAdmissionService(configured, RebindingVerifier(replace(verified, graph_profile=graph_profile))).admit(raw)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertTrue(caught.exception.__suppress_context__)
        SourceAdmissionService(configured, RebindingVerifier(verified)).admit(raw)
        for observation_time in (context.observation_time - 1, context.observation_time + 1, 999_999):
            with self.subTest(observation_time=observation_time):
                result = replace(verified, observation_time=observation_time)
                with self.assertRaisesRegex(SourceAdmissionError, "^result:observation-mismatch$"):
                    SourceAdmissionService(configured, RebindingVerifier(result)).admit(raw)

    def test_graph_output_profile_and_coverage_rebinding_fail_closed(self) -> None:
        class StaleGraphVerifier(SyntheticTestSourceVerifier):
            def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
                result = super().verify(adapter_bytes)
                value = graph.demo_input("confirmed")
                value["sources"][0]["coverage_effective_end"] = 6_999
                return replace(result, graph_input=graph.canonical_input(value))

        with self.assertRaisesRegex(SourceAdmissionError, "graph:producer-reject|graph:stale-coverage"):
            _service(StaleGraphVerifier()).admit(_adapter())

    def test_exact_retry_is_deterministic_and_conflicting_retry_rejects(self) -> None:
        service = _service()
        first = service.admit(_adapter())
        replay = service.admit(_adapter(), expected_receipt=first.receipt)
        self.assertEqual(first.receipt, replay.receipt)
        self.assertEqual(first.graph_artifact, replay.graph_artifact)
        with self.assertRaisesRegex(SourceAdmissionError, "retry:conflict"):
            service.admit(_adapter("expired"), expected_receipt=first.receipt)

    def test_composition_mismatch_and_production_mode_are_rejected(self) -> None:
        with self.assertRaisesRegex(SourceAdmissionError, "composition:verifier-mismatch"):
            _service(profile=_profile(verifier_id="OTHER_VERIFIER"))
        with self.assertRaisesRegex(ValueError, "profile:evidence-mode-not-qualified"):
            _profile(evidence_mode="production")
        with self.assertRaisesRegex(ValueError, "profile:source-roles"):
            _profile(source_roles=list(graph.SOURCE_IDS))


if __name__ == "__main__":
    unittest.main()
