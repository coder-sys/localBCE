"""Focused adversarial gates for the zero-PHI Mirror evidence export."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import inspect
import io
import json
import secrets
import traceback
import unittest

from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_evidence_export_v1 as producer
from app.mirror import provider_evidence_export_v1_independent as independent
from app.mirror import provider_trust_graph as graph_producer
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.source_admission import SourceAdmissionService
from tests.test_nc_medicaid_fhir_source import _envelope


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _request(operation_ref: str, *, now: int = 7_000, not_before: int = 6_990, expires_at: int = 7_050) -> bytes:
    return _canonical(
        {
            "domain": producer.REQUEST_DOMAIN,
            "version": 1,
            "operation_ref": operation_ref,
            "consumer_domain": producer.CONSUMER_DOMAIN,
            "evidence_profile": producer.EVIDENCE_PROFILE,
            "evidence_profile_version": 1,
            "not_before": not_before,
            "expires_at": expires_at,
        }
    )


def _admission():
    admission = SourceAdmissionService(
        profile.NC_MEDICAID_GRAPH_PROFILE,
        fhir_independent.NcMedicaidFhirVerifier(),
    ).admit(_envelope())
    return admission


def _selection() -> producer.ProviderEvidenceSelectionV1:
    admission = _admission()
    return producer.ProviderEvidenceSelectionV1(
        graph_artifact=admission.graph_artifact,
        profile_registry=dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY),
        authorization_evidence=producer.SYNTHETIC_SELECTION_AUTHORIZATION,
    )


def _observation_selection() -> producer.ProviderEvidenceObservationSelectionV1:
    admission = _admission()
    return producer.ProviderEvidenceObservationSelectionV1(
        observation=admission.observation,
        verification_receipt=admission.verification_receipt,
        authorization_evidence=producer.SYNTHETIC_SELECTION_AUTHORIZATION,
    )


def _selection_for_graph_profile(admission, graph_profile) -> producer.ProviderEvidenceSelectionV1:
    value = json.loads(admission.graph_input.decode("ascii"))
    value["profile_id"] = graph_profile.profile_id
    value["profile_version"] = graph_profile.version
    value["profile_digest"] = graph_profile.profile_digest
    value["provider_graph_subject"] = graph_profile.subject
    value["observation_time"] = graph_profile.observation_start
    subject_key = f"{graph_profile.subject}|{graph_profile.credential_id}|{graph_profile.enrollment_id}"
    for source, role in zip(value["sources"], graph_profile.source_role_details):
        source["coverage_observation_time"] = graph_profile.observation_start
        source["coverage_effective_start"] = graph_profile.effective_start
        source["coverage_effective_end"] = graph_profile.effective_end
        source["coverage_authority_id"] = role.authority_id
        source["coverage_complete"] = source["coverage_complete"] or graph_profile.require_complete
        source["nonmembership_keys"] = [subject_key for _ in source["nonmembership_keys"]]
        source["provenance"]["provenance_id"] = role.provenance_id
        for record in source["records"]:
            record["provider_id"] = graph_profile.subject
            record["credential_id"] = graph_profile.credential_id
            record["enrollment_id"] = graph_profile.enrollment_id
            record["subject_key"] = subject_key
            record["observed_at"] = graph_profile.observation_start
        source["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
            source,
            profile=graph_profile,
        )
    graph_artifact, _telemetry = graph_producer.build_report(
        graph_producer.canonical_input(value),
        profile=graph_profile,
    )
    verified = graph_independent.verify_artifact_v2(
        graph_artifact,
        {graph_profile.profile_id: graph_profile},
    )
    if verified.summary.get("accepted") is not True:
        raise AssertionError("synthetic alternate graph was not independently valid")
    return producer.ProviderEvidenceSelectionV1(
        graph_artifact=graph_artifact,
        profile_registry={graph_profile.profile_id: graph_profile},
        authorization_evidence=producer.SYNTHETIC_SELECTION_AUTHORIZATION,
    )


class _RaisingRegistry(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError("SELECTION_SYNTHETIC_SENTINEL")

    def __iter__(self):
        raise RuntimeError("SELECTION_SYNTHETIC_SENTINEL")

    def __len__(self) -> int:
        return 1


def _conflict_selection() -> producer.ProviderEvidenceSelectionV1:
    admission = _admission()
    value = json.loads(admission.graph_input.decode("ascii"))
    for source in value["sources"]:
        source["coverage_complete"] = True
    extra = dict(value["sources"][0]["records"][0])
    extra["record_id"] = "f" * 128
    value["sources"][0]["records"].append(extra)
    value["sources"][0]["records"].sort(key=lambda record: record["record_id"])
    for source in value["sources"]:
        source["provenance"]["integrity_digest"] = graph_producer.source_integrity_digest(
            source,
            profile=profile.NC_MEDICAID_GRAPH_PROFILE,
        )
    graph_artifact, _telemetry = graph_producer.build_report(
        graph_producer.canonical_input(value),
        profile=profile.NC_MEDICAID_GRAPH_PROFILE,
    )
    return producer.ProviderEvidenceSelectionV1(
        graph_artifact=graph_artifact,
        profile_registry=dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY),
        authorization_evidence=producer.SYNTHETIC_SELECTION_AUTHORIZATION,
    )


class ProviderEvidenceExportV1Tests(unittest.TestCase):
    def test_valid_request_observation_export_and_independent_verification(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_observation_export(
            _request(operation_ref), _observation_selection(), now=7_000
        )
        verified = independent.verify_export(raw, expected_operation_ref=operation_ref, now=7_000)
        self.assertEqual("EVIDENCE_INCOMPLETE", verified.outcome)
        self.assertEqual((2, 0, 2, 1, 0), (
            verified.source_count,
            verified.complete_source_count,
            verified.record_count,
            verified.finding_count,
            verified.discrepancy_count,
        ))
        self.assertEqual(len(raw), len(producer._canonical(json.loads(raw.decode("ascii")))))

    def test_observation_selection_is_canonical_authorized_and_fail_closed(self) -> None:
        selection = _observation_selection()
        operation_ref = secrets.token_hex(32)
        observation = json.loads(selection.observation.decode("ascii"))
        observation["UNAUTHORIZED_SYNTHETIC_KEY"] = "Z" * 128
        altered = replace(selection, observation=_canonical(observation))
        with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:observation-reject"):
            producer.build_observation_export(_request(operation_ref), altered, now=7_000)
        with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:authorization"):
            producer.build_observation_export(
                _request(secrets.token_hex(32)),
                replace(selection, authorization_evidence=""),
                now=7_000,
            )
        with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:observation-reject"):
            producer.build_observation_export(
                _request(secrets.token_hex(32)),
                replace(selection, verification_receipt=b"{}"),
                now=7_000,
            )

    def test_observation_aggregate_fields_are_not_guessed(self) -> None:
        selection = _observation_selection()
        observation = json.loads(selection.observation.decode("ascii"))
        for key, value in (("record_count", None), ("source_count", 1), ("finding_count", 2)):
            with self.subTest(key=key):
                altered = dict(observation)
                if value is None:
                    del altered[key]
                else:
                    altered[key] = value
                with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:observation-reject"):
                    producer.build_observation_export(
                        _request(secrets.token_hex(32)),
                        replace(selection, observation=_canonical(altered)),
                        now=7_000,
                    )

    def test_valid_request_graph_export_and_independent_verification(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        verified = independent.verify_export(raw, expected_operation_ref=operation_ref, now=7_000)
        self.assertEqual(operation_ref, verified.operation_ref)
        self.assertEqual("EVIDENCE_INCOMPLETE", verified.outcome)
        self.assertEqual((2, 0, 2, 1, 0), (
            verified.source_count,
            verified.complete_source_count,
            verified.record_count,
            verified.finding_count,
            verified.discrepancy_count,
        ))
        self.assertTrue(verified.synthetic_only)
        self.assertFalse(verified.production_usable)
        self.assertFalse(verified.activation)
        self.assertIsNone(verified.proof_suite_id)

    def test_forbidden_source_sentinel_has_zero_sink_occurrences(self) -> None:
        sentinel = "Z" * 128
        selection = _selection()
        graph = json.loads(selection.graph_artifact.decode("ascii"))
        graph["UNAUTHORIZED_SYNTHETIC_KEY"] = sentinel
        mutated_graph = _canonical(graph)
        self.assertEqual(1, mutated_graph.count(sentinel.encode("ascii")))
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:graph-reject") as caught:
                producer.build_export(_request(secrets.token_hex(32)), replace(selection, graph_artifact=mutated_graph), now=7_000)
        self.assertNotIn(sentinel, str(stdout.getvalue()))
        self.assertNotIn(sentinel, str(stderr.getvalue()))
        for frame, _ in traceback.walk_tb(caught.exception.__traceback__):
            filename = frame.f_code.co_filename.replace("\\", "/")
            if "/app/mirror/" in filename:
                self.assertNotIn(sentinel, repr(frame.f_locals))
        sinks = {
            "response": b"",
            "error": str(caught.exception).encode("utf-8"),
            "logs": stdout.getvalue().encode("utf-8") + stderr.getvalue().encode("utf-8"),
            "support": b"",
            "database": b"",
            "recovery": b"",
            "exports": b"",
        }
        self.assertEqual({name: 0 for name in sinks}, {name: value.count(sentinel.encode("ascii")) for name, value in sinks.items()})

    def test_response_is_exact_allowlist_and_contains_no_forbidden_identity_material(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        value = json.loads(raw.decode("ascii"))
        self.assertEqual(producer.RESPONSE_KEYS, set(value))
        encoded = raw.decode("ascii")
        for forbidden in (
            "provider_graph_subject",
            "provider_id",
            "subject_key",
            "source_id",
            "record_id",
            "report_id",
            "snapshot_id",
            "root",
            "digest",
            "raw",
            "credential_id",
            "enrollment_id",
            "url",
            "path",
            "claimant",
            "patient",
            "phi",
            "error",
            "stdout",
            "stderr",
            "recovery",
            "checkpoint",
            "database",
            "signature",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("provider_evidence_export_v1", encoded)

    def test_request_unknown_missing_duplicate_noncanonical_caps_and_window_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        base = json.loads(_request(operation_ref).decode("ascii"))
        mutations: list[tuple[str, bytes]] = []
        unknown = dict(base)
        unknown["unknown"] = "Z"
        mutations.append(("unknown", _canonical(unknown)))
        missing = dict(base)
        del missing["evidence_profile"]
        mutations.append(("missing", _canonical(missing)))
        duplicate = b'{"consumer_domain":"BLIND/PROVIDER_GOVERNANCE_EVIDENCE","domain":"BL/MIRROR/PROVIDER_EVIDENCE_EXPORT/REQUEST","domain":"BL/MIRROR/PROVIDER_EVIDENCE_EXPORT/REQUEST","evidence_profile":"provider-continuity-aggregate","evidence_profile_version":1,"expires_at":7050,"not_before":6990,"operation_ref":"' + operation_ref.encode("ascii") + b'","version":1}'
        mutations.append(("duplicate", duplicate))
        mutations.append(("noncanonical", b" " + _request(operation_ref)))
        oversized = b"Z" * (producer.MAX_REQUEST_BYTES + 1)
        mutations.append(("oversized", oversized))
        future = _request(operation_ref, not_before=7_001)
        mutations.append(("future", future))
        expired = _request(operation_ref, expires_at=6_999)
        mutations.append(("expired", expired))
        expires_now = _request(operation_ref, expires_at=7_000)
        mutations.append(("expires-now", expires_now))
        overlong = _request(operation_ref, expires_at=7_400)
        mutations.append(("overlong", overlong))
        bad_ref = dict(base)
        bad_ref["operation_ref"] = "a" * 62
        mutations.append(("operation-ref", _canonical(bad_ref)))
        for label, raw in mutations:
            with self.subTest(label=label):
                with self.assertRaises(producer.ProviderEvidenceExportError):
                    producer.build_export(raw, _selection(), now=7_000)

    def test_wrong_response_profile_domain_enum_count_and_operation_binding_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        original = json.loads(raw.decode("ascii"))
        mutations = {
            "domain": ("domain", "wrong"),
            "version-bool": ("version", True),
            "profile": ("evidence_profile", "old"),
            "profile-version-bool": ("evidence_profile_version", True),
            "outcome": ("outcome", "CLEAR"),
            "count": ("source_count", 99),
            "one-source": ("source_count", 1),
            "ref": ("operation_ref", secrets.token_hex(32)),
        }
        for label, (key, value) in mutations.items():
            with self.subTest(label=label):
                mutated = dict(original)
                mutated[key] = value
                with self.assertRaises(independent.IndependentProviderEvidenceExportError):
                    independent.verify_export(
                        _canonical(mutated),
                        expected_operation_ref=operation_ref,
                        now=7_000,
                    )

    def test_real_graph_conflict_shape_is_accepted_and_unreachable_mutations_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _conflict_selection(), now=7_000)
        original = json.loads(raw.decode("ascii"))
        self.assertEqual(
            (2, 2, 3, 1, 1),
            (
                original["source_count"],
                original["complete_source_count"],
                original["record_count"],
                original["finding_count"],
                original["discrepancy_count"],
            ),
        )
        self.assertEqual("SOURCE_CONFLICT", original["outcome"])
        verified = independent.verify_export(raw, expected_operation_ref=operation_ref, now=7_000)
        self.assertEqual("SOURCE_CONFLICT", verified.outcome)
        for label, changes in (
            ("record-count", {"record_count": 2}),
            ("discrepancy-count", {"discrepancy_count": 0}),
            ("incomplete-source-count", {"complete_source_count": 1}),
        ):
            with self.subTest(label=label):
                mutated = dict(original)
                mutated.update(changes)
                with self.assertRaises(independent.IndependentProviderEvidenceExportError):
                    independent.verify_export(_canonical(mutated), expected_operation_ref=operation_ref, now=7_000)

    def test_unreachable_absence_relabel_from_real_producer_response_rejects(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        response = json.loads(raw.decode("ascii"))
        response.update({
            "source_count": 2,
            "complete_source_count": 2,
            "record_count": 0,
            "finding_count": 1,
            "discrepancy_count": 0,
            "outcome": "AUTHORITATIVE_RECORD_ABSENT",
        })
        self.assertEqual(
            (2, 2, 0, 1, 0),
            (
                response["source_count"],
                response["complete_source_count"],
                response["record_count"],
                response["finding_count"],
                response["discrepancy_count"],
            ),
        )
        with self.assertRaisesRegex(
            independent.IndependentProviderEvidenceExportError,
            "export:outcome-unreachable",
        ):
            independent.verify_export(
                _canonical(response),
                expected_operation_ref=operation_ref,
                now=7_000,
            )

    def test_factory_dynamic_profile_is_authorized_and_fixed_mutations_reject(self) -> None:
        admission = _admission()
        dynamic_context = replace(
            profile.DEFAULT_CAPTURE_CONTEXT,
            subject_id="a" * 128,
            credential_id="b" * 128,
            enrollment_id="c" * 128,
            subject_locator_digest="d" * 128,
            observation_time=7_001,
            fetched_at=7_011,
        )
        dynamic_profile = profile.NC_MEDICAID_PROFILE.graph_profile_for_context(dynamic_context)
        self.assertNotEqual(dynamic_profile, profile.NC_MEDICAID_GRAPH_PROFILE)
        self.assertTrue(profile.NC_MEDICAID_PROFILE.is_authorized_graph_profile(dynamic_profile))
        dynamic_selection = _selection_for_graph_profile(admission, dynamic_profile)
        dynamic_raw = producer.build_export(_request(secrets.token_hex(32)), dynamic_selection, now=7_001)
        self.assertEqual("EVIDENCE_INCOMPLETE", json.loads(dynamic_raw.decode("ascii"))["outcome"])

        base = profile.NC_MEDICAID_GRAPH_PROFILE
        altered_role = replace(
            base.source_role_details[0],
            authority_id="SYNTHETIC_ALTERED_AUTHORITY",
            provenance_id="SYNTHETIC_ALTERED_PROVENANCE",
        )
        mutations = (
            ("allow-nonmembership", replace(base, allow_nonmembership=True), ()),
            (
                "source-role-authority-provenance",
                replace(base, source_role_details=(altered_role, base.source_role_details[1])),
                ("SYNTHETIC_ALTERED_AUTHORITY", "SYNTHETIC_ALTERED_PROVENANCE"),
            ),
            ("verifier-id", replace(base, verifier_id="SYNTHETIC_ALTERED_VERIFIER"), ("SYNTHETIC_ALTERED_VERIFIER",)),
            ("verifier-epoch", replace(base, verifier_epoch=base.verifier_epoch + 1), ()),
            ("require-complete", replace(base, require_complete=True), ()),
        )
        for label, altered, sentinels in mutations:
            with self.subTest(label=label):
                selection = _selection_for_graph_profile(admission, altered)
                altered_repr = repr(altered)
                stdout = io.StringIO()
                stderr = io.StringIO()
                response = b""
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:profile-authority") as caught:
                        response = producer.build_export(_request(secrets.token_hex(32)), selection, now=7_000)
                self.assertEqual(b"", response)
                for sentinel in sentinels:
                    self.assertNotIn(sentinel, stdout.getvalue())
                    self.assertNotIn(sentinel, stderr.getvalue())
                    self.assertNotIn(sentinel, str(caught.exception))
                    self.assertNotIn(sentinel.encode("ascii"), response)
                self.assertNotIn(altered_repr, stdout.getvalue())
                self.assertNotIn(altered_repr, stderr.getvalue())
                self.assertNotIn(altered_repr, str(caught.exception))
                self.assertNotIn(altered_repr.encode("utf-8"), response)
                for frame, _ in traceback.walk_tb(caught.exception.__traceback__):
                    filename = frame.f_code.co_filename.replace("\\", "/")
                    if "/app/mirror/" in filename:
                        self.assertNotIn(altered_repr, repr(frame.f_locals))
                        for sentinel in sentinels:
                            self.assertNotIn(sentinel, repr(frame.f_locals))

    def test_expiry_and_replay_under_another_operation_reference_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        with self.assertRaisesRegex(independent.IndependentProviderEvidenceExportError, "export:operation-binding"):
            independent.verify_export(raw, expected_operation_ref=secrets.token_hex(32), now=7_000)
        with self.assertRaisesRegex(independent.IndependentProviderEvidenceExportError, "export:time-window"):
            independent.verify_export(raw, expected_operation_ref=operation_ref, now=7_051)

    def test_response_unknown_duplicate_and_reordered_bytes_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        value = json.loads(raw.decode("ascii"))
        unknown = dict(value)
        unknown["unknown"] = "Z"
        with self.assertRaises(independent.IndependentProviderEvidenceExportError):
            independent.verify_export(_canonical(unknown), expected_operation_ref=operation_ref, now=7_000)
        reordered = b"{" + b",".join(
            (
                ('"' + key + '":' + json.dumps(value[key], ensure_ascii=True, separators=(",", ":"))).encode("ascii")
                for key in reversed(list(value))
            )
        ) + b"}"
        with self.assertRaises(independent.IndependentProviderEvidenceExportError):
            independent.verify_export(reordered, expected_operation_ref=operation_ref, now=7_000)
        duplicate = raw[:-1] + b',"version":1}'
        with self.assertRaises(independent.IndependentProviderEvidenceExportError):
            independent.verify_export(duplicate, expected_operation_ref=operation_ref, now=7_000)

    def test_independent_rejects_unproducible_aggregate_relabel_and_count_mutations(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        original = json.loads(raw.decode("ascii"))
        mutations = {
            "finding-count": {"finding_count": 8},
            "discrepancy-count": {"discrepancy_count": 8},
            "outcome-relabel": {"outcome": "CONTINUITY_CONFIRMED"},
        }
        for label, changes in mutations.items():
            with self.subTest(label=label):
                mutated = dict(original)
                mutated.update(changes)
                with self.assertRaises(independent.IndependentProviderEvidenceExportError):
                    independent.verify_export(_canonical(mutated), expected_operation_ref=operation_ref, now=7_000)

    def test_nested_parse_and_selection_failures_are_redacted_and_bounded(self) -> None:
        sentinel = "NESTED_SYNTHETIC_SENTINEL"
        nested = b"[" * 1_600 + b'"' + sentinel.encode("ascii") + b'"' + b"]" * 1_600
        self.assertLessEqual(len(nested), producer.MAX_REQUEST_BYTES)
        selection = _selection()
        cases = (
            ("producer", lambda: producer.build_export(nested, selection, now=7_000), producer.ProviderEvidenceExportError),
            ("independent", lambda: independent.verify_export(nested, expected_operation_ref=secrets.token_hex(32), now=7_000), independent.IndependentProviderEvidenceExportError),
        )
        for label, call, error_type in cases:
            with self.subTest(label=label):
                with self.assertRaises(error_type) as caught:
                    call()
                self.assertRegex(str(caught.exception), r"^export:")
                for frame, _ in traceback.walk_tb(caught.exception.__traceback__):
                    filename = frame.f_code.co_filename.replace("\\", "/")
                    if "/app/mirror/" in filename:
                        self.assertNotIn(sentinel, repr(frame.f_locals))

        bad_selection = replace(selection, profile_registry=_RaisingRegistry())
        with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:selection") as caught:
            producer.build_export(_request(secrets.token_hex(32)), bad_selection, now=7_000)
        self.assertNotIn("SELECTION_SYNTHETIC_SENTINEL", str(caught.exception))
        for frame, _ in traceback.walk_tb(caught.exception.__traceback__):
            filename = frame.f_code.co_filename.replace("\\", "/")
            if "/app/mirror/" in filename:
                self.assertNotIn("SELECTION_SYNTHETIC_SENTINEL", repr(frame.f_locals))

    def test_old_graph_shaped_object_and_relabeling_are_rejected(self) -> None:
        selection = _selection()
        legacy = _canonical({
            "schema": "mirror-provider-trust-graph-v2",
            "profile": {"profile_id": profile.SOURCE_PROFILE_ID, "version": 3, "profile_digest": "0" * 128},
            "lifecycle": "APPROVED",
        })
        with self.assertRaises(producer.ProviderEvidenceExportError):
            producer.build_export(_request(secrets.token_hex(32)), replace(selection, graph_artifact=legacy), now=7_000)
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), selection, now=7_000)
        response = json.loads(raw.decode("ascii"))
        response["consumer_domain"] = "BLIND/CLAIMANT_CLEARANCE"
        with self.assertRaises(independent.IndependentProviderEvidenceExportError):
            independent.verify_export(_canonical(response), expected_operation_ref=operation_ref, now=7_000)

    def test_qualification_authority_and_synthetic_flips_reject(self) -> None:
        operation_ref = secrets.token_hex(32)
        raw = producer.build_export(_request(operation_ref), _selection(), now=7_000)
        original = json.loads(raw.decode("ascii"))
        for key, value in (
            ("qualification_status", "PRODUCTION"),
            ("synthetic_only", False),
            ("production_usable", True),
            ("activation", True),
            ("clearance_authority", True),
            ("payment_authority", True),
            ("economic_mutation", True),
            ("proofSuiteId", "classical"),
        ):
            with self.subTest(key=key):
                mutated = dict(original)
                mutated[key] = value
                with self.assertRaises(independent.IndependentProviderEvidenceExportError):
                    independent.verify_export(_canonical(mutated), expected_operation_ref=operation_ref, now=7_000)

    def test_no_shared_contract_implementation_or_classical_authentication(self) -> None:
        producer_source = inspect.getsource(producer)
        independent_source = inspect.getsource(independent)
        self.assertNotIn("provider_evidence_export_v1", independent_source)
        self.assertNotIn("provider_evidence_export_v1_independent", producer_source)
        for forbidden in ("ed25519", "ecdsa", "rsa", "signature", "import sqlite3", "import logging", "from logging", "print(", "open(", ".write("):
            self.assertNotIn(forbidden, producer_source.lower())
            self.assertNotIn(forbidden, independent_source.lower())

    def test_missing_selection_authorization_and_persistence_are_fail_closed(self) -> None:
        selection = _selection()
        with self.assertRaisesRegex(producer.ProviderEvidenceExportError, "export:authorization"):
            producer.build_export(
                _request(secrets.token_hex(32)),
                replace(selection, authorization_evidence=""),
                now=7_000,
            )
        producer_source = inspect.getsource(producer).lower()
        independent_source = inspect.getsource(independent).lower()
        for forbidden in ("sqlite", "import logging", "from logging", "print(", "open(", ".write(", "stdout", "stderr"):
            self.assertNotIn(forbidden, producer_source)
            self.assertNotIn(forbidden, independent_source)
