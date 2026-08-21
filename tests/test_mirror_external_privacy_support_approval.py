"""Focused adversarial tests for privacy/support assertion evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from app.mirror import external_privacy_support_approval as producer
from app.mirror import external_privacy_support_approval_independent as independent
from app.mirror import qualification_independent


def _hex(label: str) -> str:
    return hashlib.sha3_512(label.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _policy(**changes: object) -> producer.ExternalPrivacySupportPolicyV1:
    values: dict[str, object] = {
        "source_policy_digest": _hex("source-policy"),
        "quarantine_policy_digest": _hex("quarantine-policy"),
        "quarantine_artifact_id": _hex("quarantine-artifact"),
        "quarantine_head_artifact_id": _hex("quarantine-head-artifact"),
        "quarantine_head_root": _hex("quarantine-head-root"),
        "governance_observation_artifact_id": _hex("governance-artifact"),
        "governance_evidence_digest": _hex("governance-evidence"),
        "governance_decision": "GRANTED",
        "terms_digest": _hex("terms"),
        "retention_policy_digest": _hex("retention"),
        "verifier_id": "SYNTHETIC_STATE_PRIVACY_SUPPORT_VERIFIER_V1",
        "verifier_epoch": 4,
        "scope": producer.SCOPE,
        "effective_start": 1_000,
        "effective_end": 2_000,
        "max_evidence_bytes": 1_024,
        "privacy_authority_evidence_digest": _hex("privacy-authority"),
        "support_authority_evidence_digest": _hex("support-authority"),
        "revocation_head_digest": _hex("revocation-head"),
    }
    values.update(changes)
    return producer.ExternalPrivacySupportPolicyV1(**values)


def _pairs(keys: tuple[str, ...], state: bool) -> tuple[tuple[str, bool], ...]:
    return tuple((key, state) for key in keys)


class _FixtureVerifier:
    def __init__(self, policy: producer.ExternalPrivacySupportPolicyV1, **changes: object) -> None:
        self.policy = policy
        self.verifier_id = policy.verifier_id
        self.verifier_epoch = policy.verifier_epoch
        self.privacy_authority_evidence_digest = policy.privacy_authority_evidence_digest
        self.support_authority_evidence_digest = policy.support_authority_evidence_digest
        self.revocation_head_digest = policy.revocation_head_digest
        self.changes = changes

    def verify(self, evidence_raw: bytes) -> producer.VerifiedPrivacySupportAssertionV1:
        evidence_digest = hashlib.sha3_512(evidence_raw).hexdigest()
        values: dict[str, object] = {
            "policy_digest": self.policy.digest,
            "assertion_id": independent.assertion_id_for_evidence(evidence_digest, len(evidence_raw)),
            "evidence_sha3_512": evidence_digest,
            "evidence_byte_length": len(evidence_raw),
            "quarantine_policy_digest": self.policy.quarantine_policy_digest,
            "quarantine_artifact_id": self.policy.quarantine_artifact_id,
            "quarantine_head_artifact_id": self.policy.quarantine_head_artifact_id,
            "quarantine_head_root": self.policy.quarantine_head_root,
            "governance_observation_artifact_id": self.policy.governance_observation_artifact_id,
            "governance_evidence_digest": self.policy.governance_evidence_digest,
            "governance_decision": self.policy.governance_decision,
            "terms_digest": self.policy.terms_digest,
            "retention_policy_digest": self.policy.retention_policy_digest,
            "privacy_decision": "GRANTED",
            "support_decision": "GRANTED",
            "issued_at": 1_100,
            "valid_from": 1_150,
            "valid_until": 1_500,
            "observed_at": 1_200,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "privacy_authority_evidence_digest": self.privacy_authority_evidence_digest,
            "support_authority_evidence_digest": self.support_authority_evidence_digest,
            "revocation_head_digest": self.revocation_head_digest,
            "coverage": _pairs(producer.COVERAGE_KEYS, True),
            "support_controls": _pairs(producer.SUPPORT_CONTROL_KEYS, True),
            "zero_phi": True,
            "state_owned": True,
        }
        values.update(self.changes)
        return producer.VerifiedPrivacySupportAssertionV1(**values)


class PrivacySupportApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self.evidence = b"synthetic-privacy-support-assertion-v1"
        self.service = producer.ExternalPrivacySupportApprovalService(self.policy, _FixtureVerifier(self.policy))

    @staticmethod
    def _value(raw: bytes) -> dict[str, object]:
        return json.loads(raw.decode("ascii"))

    @staticmethod
    def _rebind(value: dict[str, object]) -> bytes:
        body = {key: item for key, item in value.items() if key != "artifact_id"}
        return _canonical({**body, "artifact_id": independent._digest("artifact-id", body)})

    def _artifact(self, **changes: object) -> producer.ExternalPrivacySupportApprovalArtifactV1:
        verifier = _FixtureVerifier(self.policy, **changes)
        return producer.ExternalPrivacySupportApprovalService(self.policy, verifier).observe(self.evidence)

    def test_decision_combinations_are_observed_and_independently_reconstructed(self) -> None:
        cases = (
            ("granted-granted", "GRANTED", "GRANTED", True, True),
            ("denied-denied", "DENIED", "DENIED", False, False),
            ("withdrawn-granted", "WITHDRAWN", "GRANTED", False, True),
            ("granted-withdrawn", "GRANTED", "WITHDRAWN", True, False),
        )
        for case_id, privacy_decision, support_decision, coverage, controls in cases:
            with self.subTest(case_id=case_id):
                artifact = self._artifact(
                    privacy_decision=privacy_decision,
                    support_decision=support_decision,
                    coverage=_pairs(producer.COVERAGE_KEYS, coverage),
                    support_controls=_pairs(producer.SUPPORT_CONTROL_KEYS, controls),
                )
                result = independent.verify_artifact(
                    artifact.raw,
                    policy=self.policy.material(),
                    evidence_raw=self.evidence,
                )
                self.assertEqual(result["privacy_decision"], privacy_decision)
                self.assertEqual(result["support_decision"], support_decision)
                self.assertEqual(result["derived_status"], producer.STATUS)
                self.assertFalse(result["external_authority_authenticated"])
                self.assertFalse(result["state_privacy_qualified"])
                self.assertFalse(result["state_support_qualified"])
                self.assertFalse(result["controlled_shadow_ready"])
                self.assertFalse(result["production_usable"])

    def test_policy_is_immutable_deterministic_and_raw_evidence_is_absent(self) -> None:
        first = self.service.observe(self.evidence)
        second = self.service.observe(self.evidence)
        self.assertEqual(first.raw, second.raw)
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertNotIn(self.evidence, first.raw)
        value = self._value(first.raw)
        self.assertEqual(value["derived_status"], producer.STATUS)
        for forbidden in ("APPROVED", "ACTIVE", "READY", "LIVE", "CLEAR", "QUALIFIED"):
            self.assertNotEqual(value["derived_status"], forbidden)
        self.assertEqual(set(value["assertion"]["coverage"]), set(producer.COVERAGE_KEYS))  # type: ignore[index]
        self.assertEqual(set(value["assertion"]["support_controls"]), set(producer.SUPPORT_CONTROL_KEYS))  # type: ignore[index]
        with self.assertRaises(Exception):
            self.policy.scope = "CALLER"  # type: ignore[misc]

    def test_verifier_configuration_exception_and_result_type_fail_closed(self) -> None:
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-config"):
            producer.ExternalPrivacySupportApprovalService(self.policy, _FixtureVerifier(_policy(verifier_epoch=5)))

        class RaisingVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedPrivacySupportAssertionV1:
                raise RuntimeError("fixture-only failure")

        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-failure"):
            producer.ExternalPrivacySupportApprovalService(self.policy, RaisingVerifier(self.policy)).observe(self.evidence)

        class WrongTypeVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedPrivacySupportAssertionV1:
                return {"not": "typed"}  # type: ignore[return-value]

        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-result-type"):
            producer.ExternalPrivacySupportApprovalService(self.policy, WrongTypeVerifier(self.policy)).observe(self.evidence)

    def test_upstream_authority_and_evidence_bindings_are_not_caller_selected(self) -> None:
        cases = (
            ("policy", {"policy_digest": _hex("other-policy")}, "policy-binding"),
            ("quarantine", {"quarantine_head_root": _hex("other-root")}, "upstream-binding"),
            ("governance", {"governance_observation_artifact_id": _hex("other-governance")}, "upstream-binding"),
            ("governance-evidence", {"governance_evidence_digest": _hex("other-evidence")}, "upstream-binding"),
            ("governance-decision", {"governance_decision": "DENIED"}, "upstream-binding"),
            ("terms", {"terms_digest": _hex("other-terms")}, "upstream-binding"),
            ("retention", {"retention_policy_digest": _hex("other-retention")}, "upstream-binding"),
            ("privacy-authority", {"privacy_authority_evidence_digest": _hex("other-privacy")}, "verifier-binding"),
            ("support-authority", {"support_authority_evidence_digest": _hex("other-support")}, "verifier-binding"),
            ("revocation", {"revocation_head_digest": _hex("other-revocation")}, "verifier-binding"),
            ("assertion", {"assertion_id": _hex("other-assertion")}, "assertion-binding"),
            ("evidence", {"evidence_sha3_512": _hex("other-payload")}, "evidence-binding"),
        )
        for case_id, changes, error in cases:
            with self.subTest(case_id=case_id):
                with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, error):
                    self._artifact(**changes)

    def test_granted_decisions_require_complete_coverage_and_controls(self) -> None:
        incomplete_coverage = list(_pairs(producer.COVERAGE_KEYS, True))
        incomplete_coverage[-1] = (incomplete_coverage[-1][0], False)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "coverage-incomplete"):
            self._artifact(coverage=tuple(incomplete_coverage))
        incomplete_controls = list(_pairs(producer.SUPPORT_CONTROL_KEYS, True))
        incomplete_controls[-1] = (incomplete_controls[-1][0], False)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "controls-incomplete"):
            self._artifact(support_controls=tuple(incomplete_controls))
        artifact = self.service.observe(self.evidence)
        value = self._value(artifact.raw)
        value["assertion"]["coverage"]["ai"] = False  # type: ignore[index]
        with self.assertRaisesRegex(independent.IndependentExternalPrivacySupportError, "coverage-incomplete"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())

    def test_raw_snapshot_caps_flags_and_policy_controls_fail_closed(self) -> None:
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-id"):
            _policy(verifier_id="https://fixture.invalid")
        small_policy = _policy(max_evidence_bytes=3)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "evidence-byte-cap"):
            producer.ExternalPrivacySupportApprovalService(small_policy, _FixtureVerifier(small_policy)).observe(self.evidence)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "evidence-bytes"):
            self.service.observe(bytearray(self.evidence))  # type: ignore[arg-type]

        class ChangedBytesVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedPrivacySupportAssertionV1:
                return _FixtureVerifier(self.policy).verify(b"different-snapshot-of-same-length!!")

        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "evidence-binding"):
            producer.ExternalPrivacySupportApprovalService(self.policy, ChangedBytesVerifier(self.policy)).observe(self.evidence)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "control-flags"):
            self._artifact(zero_phi=False)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "control-flags"):
            self._artifact(state_owned=False)

    def test_chronology_and_policy_window_are_strict(self) -> None:
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "policy-chronology"):
            self._artifact(issued_at=900, valid_from=1_150)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "policy-chronology"):
            self._artifact(valid_until=2_001)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-failure"):
            self._artifact(issued_at=1_300, valid_from=1_150)
        with self.assertRaisesRegex(producer.ExternalPrivacySupportApprovalError, "verifier-failure"):
            self._artifact(valid_from=1_600, observed_at=1_500)

    def test_independent_parser_rejects_mutations_unknowns_and_noncanonical_bytes(self) -> None:
        artifact = self.service.observe(self.evidence)
        mutations: list[tuple[str, dict[str, object]]] = []
        value = self._value(artifact.raw)
        value["derived_status"] = "CONTROLLED_SHADOW_READY"
        mutations.append(("status", value))
        value = self._value(artifact.raw)
        value["flags"]["state_privacy_qualified"] = True  # type: ignore[index]
        mutations.append(("privacy-flag", value))
        value = self._value(artifact.raw)
        value["flags"]["state_support_qualified"] = True  # type: ignore[index]
        mutations.append(("support-flag", value))
        value = self._value(artifact.raw)
        value["flags"]["payment_authority"] = True  # type: ignore[index]
        mutations.append(("payment-flag", value))
        value = self._value(artifact.raw)
        value["assertion"]["privacy_decision"] = "APPROVED"  # type: ignore[index]
        mutations.append(("decision", value))
        value = self._value(artifact.raw)
        value["assertion"]["coverage"]["new_field"] = True  # type: ignore[index]
        mutations.append(("coverage-key", value))
        value = self._value(artifact.raw)
        value["unknown"] = True
        mutations.append(("unknown", value))
        value = self._value(artifact.raw)
        del value["assertion"]["support_decision"]  # type: ignore[index]
        mutations.append(("missing", value))
        value = self._value(artifact.raw)
        value["assertion"]["coverage"]["ai"] = "true"  # type: ignore[index]
        mutations.append(("wrong-type", value))
        for flag in (
            "external_authority_authenticated", "state_privacy_qualified", "state_support_qualified",
            "controlled_shadow_ready", "production_usable", "activation", "payment_authority",
            "clearance_authority", "settlement_authority",
        ):
            value = self._value(artifact.raw)
            value["flags"][flag] = True  # type: ignore[index]
            mutations.append((f"flag-{flag}", value))
        for flag in ("read_only", "zero_phi", "state_owned"):
            value = self._value(artifact.raw)
            value["flags"][flag] = False  # type: ignore[index]
            mutations.append((f"flag-{flag}-downgrade", value))
        value = self._value(artifact.raw)
        value["flags"]["proofSuiteId"] = "fixture"  # type: ignore[index]
        mutations.append(("proof-suite", value))
        for case_id, mutation in mutations:
            with self.subTest(case_id=case_id):
                with self.assertRaises(independent.IndependentExternalPrivacySupportError):
                    independent.verify_artifact(self._rebind(mutation), policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalPrivacySupportError):
            independent.verify_artifact(artifact.raw + b"\n", policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalPrivacySupportError):
            independent.verify_artifact(b'{"artifact_kind":"x","artifact_kind":"y"}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalPrivacySupportError):
            independent.verify_artifact(b'{"artifact_kind":NaN}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalPrivacySupportError):
            independent.verify_artifact(b'{"artifact_kind":"caf\xc3\xa9"}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalPrivacySupportError):
            independent.verify_artifact(b"x" * (independent.MAX_ARTIFACT_BYTES + 1), policy=self.policy.material())
        self.assertEqual(len(mutations), 22)

    def test_independent_rejects_rebound_raw_and_policy_material(self) -> None:
        artifact = self.service.observe(self.evidence)
        with self.assertRaisesRegex(independent.IndependentExternalPrivacySupportError, "evidence-rebound"):
            independent.verify_artifact(artifact.raw, policy=self.policy.material(), evidence_raw=b"x" * len(self.evidence))
        drift = self.policy.material()
        drift["governance_observation_artifact_id"] = _hex("other-governance")
        with self.assertRaisesRegex(independent.IndependentExternalPrivacySupportError, "policy-binding"):
            independent.verify_artifact(artifact.raw, policy=drift)
        bad_policy = self.policy.material()
        bad_policy["unexpected"] = True
        with self.assertRaisesRegex(independent.IndependentExternalPrivacySupportError, "policy-keys"):
            independent.verify_artifact(artifact.raw, policy=bad_policy)

    def test_same_bytes_same_identity_and_decision_head_governance_changes_are_distinct(self) -> None:
        first = self.service.observe(self.evidence)
        self.assertEqual(first.raw, self.service.observe(self.evidence).raw)
        other_evidence = self.service.observe(b"another-privacy-support-assertion").artifact_id
        self.assertNotEqual(first.artifact_id, other_evidence)
        denied = self._artifact(
            privacy_decision="DENIED",
            support_decision="DENIED",
            coverage=_pairs(producer.COVERAGE_KEYS, False),
            support_controls=_pairs(producer.SUPPORT_CONTROL_KEYS, False),
        )
        self.assertNotEqual(first.artifact_id, denied.artifact_id)
        other_policy = _policy(quarantine_head_root=_hex("other-head"))
        other = producer.ExternalPrivacySupportApprovalService(other_policy, _FixtureVerifier(other_policy)).observe(self.evidence)
        self.assertNotEqual(first.artifact_id, other.artifact_id)
        governance_policy = _policy(governance_observation_artifact_id=_hex("other-governance"))
        governance = producer.ExternalPrivacySupportApprovalService(governance_policy, _FixtureVerifier(governance_policy)).observe(self.evidence)
        self.assertNotEqual(first.artifact_id, governance.artifact_id)

    def test_no_downstream_or_network_import_and_qualification_ledger_update(self) -> None:
        for path in (producer.__file__, independent.__file__):
            source = Path(path).read_text(encoding="utf-8").lower()
            for forbidden in (
                "from app.mirror import external_source_quarantine",
                "from app.mirror import external_governance_approval",
                "from app.mirror import continuity_store",
                "from app.mirror import provider_trust_graph",
                "from app.mirror import discrepancy",
                "import app.mirror.external_source_quarantine",
                "import urllib", "import requests", "import socket",
            ):
                self.assertNotIn(forbidden, source)
        gap = next(item for item in qualification_independent.GAP_LEDGER["software_gaps"] if item["gap_id"] == "EXTERNAL_PRIVACY_SUPPORT_ADAPTER")
        self.assertEqual(gap["status"], "SOFTWARE_CONTRACT_ONLY")
        self.assertIn("remain external", gap["claim"])
        self.assertEqual(
            next(item for item in qualification_independent.GAP_LEDGER["software_gaps"] if item["gap_id"] == "CONTROLLED_SHADOW_PILOT_RUNTIME")["status"],
            "UNIMPLEMENTED",
        )


if __name__ == "__main__":
    unittest.main()
