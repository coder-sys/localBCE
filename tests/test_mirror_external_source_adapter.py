"""Focused adversarial tests for the transport-neutral external-source seam."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import traceback
import unittest

from app.mirror import external_source_adapter as adapter
from app.mirror import external_source_adapter_independent as independent


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _hex(label: str) -> str:
    return hashlib.sha3_512(label.encode("ascii")).hexdigest()


def _policy(**changes: object) -> adapter.ExternalSourcePolicyV2:
    values: dict[str, object] = {
        "source_contract_digest": _hex("source-contract"),
        "capture_schema": "synthetic-capture-v2",
        "capture_schema_version": 2,
        "logical_endpoint_id": "SYNTHETIC_SOURCE_ENDPOINT_V1",
        "source_roles": ("DIRECTORY_OBSERVER", "STATE_SOURCE_BOUNDARY"),
        "verifier_id": "SYNTHETIC_EXTERNAL_CAPTURE_VERIFIER_V1",
        "verifier_epoch": 1,
        "authorization_artifact_digest": _hex("authorization-fixture"),
        "terms_artifact_digest": _hex("terms-fixture"),
        "effective_start": 1_000,
        "effective_end": 2_000,
        "expected_cadence_seconds": 600,
        "freshness_grace_seconds": 60,
        "max_capture_bytes": 4_096,
        "max_page_count": 4,
    }
    values.update(changes)
    return adapter.ExternalSourcePolicyV2(**values)


class _FixtureVerifier:
    def __init__(self, policy: adapter.ExternalSourcePolicyV2, **changes: object) -> None:
        self.verifier_id = policy.verifier_id
        self.verifier_epoch = policy.verifier_epoch
        self.policy = policy
        self.changes = changes

    def verify(self, capture_raw: bytes) -> adapter.VerifiedExternalCaptureV2:
        payload = hashlib.sha3_512(capture_raw).hexdigest()
        values: dict[str, object] = {
            "policy_digest": self.policy.digest,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "capture_id": independent.capture_id_for_payload(payload),
            "payload_sha3_512": payload,
            "observed_at": 1_200,
            "fetched_at": 1_210,
            "page_digests": (_hex("page-a"), _hex("page-b")),
            "page_count": 2,
            "server_identity_digest": independent._digest("server-identity", self.policy.logical_endpoint_id),
            "transport_receipt_digest": None,
            "transport_authenticated": False,
            "complete": True,
            "failure_code": "NONE",
            "zero_phi": True,
            "transport_evidence_classification": adapter.TRANSPORT_EVIDENCE_CLASSIFICATION,
            "subject_id": _hex("subject"),
            "credential_id": _hex("credential"),
            "enrollment_id": _hex("enrollment"),
            "subject_locator_digest": _hex("locator"),
        }
        values.update(self.changes)
        if "transport_receipt_digest" not in self.changes:
            values["transport_receipt_digest"] = independent._digest(
                "transport-receipt",
                {
                    "policy_digest": values["policy_digest"],
                    "verifier_id": values["verifier_id"],
                    "verifier_epoch": values["verifier_epoch"],
                    "payload_sha3_512": values["payload_sha3_512"],
                    "page_bindings": [[index, digest] for index, digest in enumerate(values["page_digests"])],
                    "server_identity_digest": values["server_identity_digest"],
                    "observed_at": values["observed_at"],
                    "fetched_at": values["fetched_at"],
                    "transport_authenticated": values["transport_authenticated"],
                    "complete": values["complete"],
                    "failure_code": values["failure_code"],
                    "transport_evidence_classification": values["transport_evidence_classification"],
                },
            )
        return adapter.VerifiedExternalCaptureV2(**values)


class ExternalSourceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self.raw = b"synthetic-capture-v1"
        self.verifier = _FixtureVerifier(self.policy)
        self.service = adapter.ExternalSourceAdapterService(self.policy, self.verifier)

    def _artifact(self, **changes: object) -> adapter.ExternalSourceArtifactV2:
        return adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, **changes)).admit(self.raw)

    def _value(self, raw: bytes | None = None) -> dict[str, object]:
        return json.loads((raw or self.service.admit(self.raw).raw).decode("ascii"))

    def _rebind(self, value: dict[str, object]) -> bytes:
        body = {key: item for key, item in value.items() if key != "artifact_id"}
        return _canonical({**body, "artifact_id": independent._digest("artifact-id", body)})

    def test_capture_context_identity_fields_are_required(self) -> None:
        for field in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "^external:"):
                    self._artifact(**{field: None})

    def test_policy_is_immutable_and_artifact_is_deterministic_without_raw_capture(self) -> None:
        first = self.service.admit(self.raw)
        second = self.service.admit(self.raw)
        self.assertEqual(first.raw, second.raw)
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertNotIn(self.raw, first.raw)
        self.assertEqual(first.status, "OBSERVATION_ADMITTED")
        with self.assertRaises(Exception):
            self.policy.profile_id = "changed"  # type: ignore[misc]
        self.assertEqual(tuple(self.policy.source_roles), ("DIRECTORY_OBSERVER", "STATE_SOURCE_BOUNDARY"))
        result = independent.verify_artifact(first.raw, policy=self.policy.material(), capture_raw=self.raw)
        self.assertEqual(result["artifact_id"], first.artifact_id)
        self.assertEqual(result["derived_status"], first.status)

    def test_all_derived_statuses_have_producer_independent_parity(self) -> None:
        cases = (
            ("admitted", {}, "OBSERVATION_ADMITTED"),
            ("authority", {"transport_authenticated": False, "failure_code": "AUTHORITY_UNQUALIFIED"}, "HOLD_AUTHORITY_UNQUALIFIED"),
            ("incomplete", {"complete": False}, "HOLD_INCOMPLETE"),
            ("stale", {"observed_at": 900, "fetched_at": 910}, "HOLD_STALE"),
            ("failure", {"failure_code": "SOURCE_FAILURE"}, "HOLD_SOURCE_FAILURE"),
        )
        for case_id, changes, expected in cases:
            with self.subTest(case_id=case_id):
                artifact = self._artifact(**changes)
                independent_result = independent.verify_artifact(artifact.raw, policy=self.policy.material(), capture_raw=self.raw)
                self.assertEqual(artifact.status, expected)
                self.assertEqual(independent_result["derived_status"], expected)
        self.assertEqual(len(cases), 5)

    def test_verifier_identity_epoch_policy_and_payload_bindings_are_owned_by_service(self) -> None:
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "verifier-config"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(_policy(verifier_epoch=2)))
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "payload-binding"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, payload_sha3_512=_hex("other"))).admit(self.raw)
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "verifier-binding"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, policy_digest=_hex("other"))).admit(self.raw)
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "capture-binding"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, capture_id=_hex("other"))).admit(self.raw)
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "server-binding"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, server_identity_digest=_hex("other-server"))).admit(self.raw)
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "transport-binding"):
            adapter.ExternalSourceAdapterService(self.policy, _FixtureVerifier(self.policy, transport_receipt_digest=_hex("other-transport"))).admit(self.raw)
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "capture-bytes"):
            self.service.admit(bytearray(self.raw))  # type: ignore[arg-type]

    def test_profile_drift_and_policy_digest_drift_fail_independently(self) -> None:
        artifact = self.service.admit(self.raw)
        drift = self.policy.material()
        drift["logical_endpoint_id"] = "SYNTHETIC_OTHER_ENDPOINT_V1"
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "policy-binding"):
            independent.verify_artifact(artifact.raw, policy=drift)
        value = self._value(artifact.raw)
        value["policy_digest"] = _hex("wrong-policy")
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "policy-binding"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())
        value = self._value(artifact.raw)
        value["capture"]["policy_digest"] = _hex("wrong-capture-policy")  # type: ignore[index]
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "capture-policy"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())

    def test_page_order_caps_and_time_failure_modes_fail_closed(self) -> None:
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(page_bindings=((1, _hex("page-a")), (0, _hex("page-b"))))
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(page_bindings=((0, _hex("page-a")), (2, _hex("page-b"))))
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(page_count=1)
        capped_policy = _policy(max_page_count=1)
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            adapter.ExternalSourceAdapterService(capped_policy, _FixtureVerifier(capped_policy)).admit(self.raw)
        self.assertEqual(self._artifact(observed_at=2_001, fetched_at=2_010).status, "HOLD_STALE")
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(observed_at=1_200, fetched_at=1_000)
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(failure_code="STALE")
        with self.assertRaises(adapter.ExternalSourceAdapterError):
            self._artifact(failure_code="AUTHORITY_UNQUALIFIED", transport_authenticated=True)

    def test_raw_capture_race_and_verifier_failures_do_not_emit_artifacts(self) -> None:
        class RaisingVerifier(_FixtureVerifier):
            def verify(self, capture_raw: bytes) -> adapter.VerifiedExternalCaptureV2:
                raise RuntimeError("fixture-failure")

        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "verifier-failure"):
            adapter.ExternalSourceAdapterService(self.policy, RaisingVerifier(self.policy)).admit(self.raw)

        class WrongBytesVerifier(_FixtureVerifier):
            def verify(self, capture_raw: bytes) -> adapter.VerifiedExternalCaptureV2:
                return _FixtureVerifier(self.policy).verify(b"different-snapshot")

        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "payload-binding"):
            adapter.ExternalSourceAdapterService(self.policy, WrongBytesVerifier(self.policy)).admit(self.raw)
        artifact = self.service.admit(self.raw)
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "payload-rebound"):
            independent.verify_artifact(artifact.raw, policy=self.policy.material(), capture_raw=b"altered-capture-v1xx")

    def test_public_errors_discard_verifier_and_parser_canaries(self) -> None:
        canary = "PHI_CANARY Bearer SECRET C:\\Users\\private\\record"

        class RaisingVerifier(_FixtureVerifier):
            def verify(self, capture_raw: bytes) -> adapter.VerifiedExternalCaptureV2:
                raise RuntimeError(canary)

        with self.assertRaises(adapter.ExternalSourceAdapterError) as caught:
            adapter.ExternalSourceAdapterService(self.policy, RaisingVerifier(self.policy)).admit(self.raw)
        error = caught.exception
        rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self.assertEqual(str(error), "external:verifier-failure")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn(canary, repr(error) + rendered)

        with self.assertRaises(independent.IndependentExternalSourceError) as caught:
            independent.verify_artifact(b'{"artifact_kind":"caf\xc3\xa9"}', policy=self.policy.material())
        error = caught.exception
        rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self.assertEqual(str(error), "external:parse")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn("caf", repr(error) + rendered)

    def test_independent_mutations_reject_unknown_fields_status_flags_and_rebound_ids(self) -> None:
        artifact = self.service.admit(self.raw)
        mutations: list[tuple[str, dict[str, object]]] = []
        value = self._value(artifact.raw)
        value["derived_status"] = "CONTROLLED_SHADOW_READY"
        mutations.append(("status-escalation", value))
        value = self._value(artifact.raw)
        value["flags"]["production_usable"] = True  # type: ignore[index]
        mutations.append(("production-flag", value))
        value = self._value(artifact.raw)
        value["capture"]["complete"] = False  # type: ignore[index]
        mutations.append(("complete-downgrade", value))
        value = self._value(artifact.raw)
        value["unexpected"] = "value"
        mutations.append(("unknown-key", value))
        value = self._value(artifact.raw)
        value["capture"]["page_bindings"] = list(reversed(value["capture"]["page_bindings"]))  # type: ignore[index]
        mutations.append(("page-reorder", value))
        for case_id, mutation in mutations:
            with self.subTest(case_id=case_id):
                with self.assertRaises(independent.IndependentExternalSourceError):
                    independent.verify_artifact(self._rebind(mutation), policy=self.policy.material())
        value = self._value(artifact.raw)
        value["capture"]["server_identity_digest"] = _hex("rebound-server")  # type: ignore[index]
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "server-binding"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())
        value = self._value(artifact.raw)
        value["capture"]["transport_receipt_digest"] = _hex("rebound-transport")  # type: ignore[index]
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "transport-binding"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())
        noncanonical = artifact.raw + b"\n"
        with self.assertRaises(independent.IndependentExternalSourceError):
            independent.verify_artifact(noncanonical, policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalSourceError):
            independent.verify_artifact(b'{"artifact_kind":"x","artifact_kind":"y"}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalSourceError):
            independent.verify_artifact(b'{"artifact_kind":"caf\xc3\xa9"}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalSourceError):
            independent.verify_artifact(b'{"artifact_kind":NaN}', policy=self.policy.material())
        self.assertEqual(len(mutations), 5)

    def test_forbidden_policy_material_and_output_injection_rejects(self) -> None:
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "external:endpoint"):
            _policy(logical_endpoint_id="http" + "://fixture.invalid")
        with self.assertRaisesRegex(adapter.ExternalSourceAdapterError, "source-role-forbidden"):
            _policy(source_roles=("bearer" + "token",))
        artifact = self.service.admit(self.raw)
        value = self._value(artifact.raw)
        value["url"] = "fixture"
        with self.assertRaises(independent.IndependentExternalSourceError):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())

    def test_exact_retry_and_same_capture_conflict_are_explicit(self) -> None:
        first = self.service.admit(self.raw)
        second = self.service.admit(self.raw)
        self.assertEqual(independent.verify_retry(first.raw, second.raw, policy=self.policy.material())["artifact_id"], first.artifact_id)
        changed = self.service.admit(b"synthetic-capture-v2")
        self.assertNotEqual(first.capture_id, changed.capture_id)
        value = self._value(changed.raw)
        value["capture"]["capture_id"] = first.capture_id  # type: ignore[index]
        rebound = self._rebind(value)
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "capture-id"):
            independent.verify_artifact(rebound, policy=self.policy.material())
        same_capture_different_metadata = self._artifact(observed_at=1_201)
        with self.assertRaisesRegex(independent.IndependentExternalSourceError, "capture-id-conflict"):
            independent.verify_retry(first.raw, same_capture_different_metadata.raw, policy=self.policy.material())

    def test_external_artifact_has_no_downstream_bridge_or_record_values(self) -> None:
        artifact = self.service.admit(self.raw)
        text = artifact.raw.decode("ascii")
        for marker in ("http", "token", "bearer", "password", "secret", "patient_id", "member_id", "claim_id"):
            self.assertNotIn(marker, text.lower())
        import importlib.util
        self.assertIsNone(importlib.util.find_spec("app.mirror.continuity_store"))
        self.assertEqual(independent.verify_artifact(artifact.raw, policy=self.policy.material())["external_authorization_qualified"], False)

    def test_independent_module_does_not_import_producer(self) -> None:
        source = Path("app/mirror/external_source_adapter_independent.py").read_text(encoding="utf-8")
        self.assertNotIn("from app.mirror import external_source_adapter", source)
        self.assertNotIn("import app.mirror.external_source_adapter", source)


if __name__ == "__main__":
    unittest.main()
