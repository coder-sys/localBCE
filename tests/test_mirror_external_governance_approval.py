"""Focused tests for the non-authorizing governance assertion contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from app.mirror import external_governance_approval as producer
from app.mirror import external_governance_approval_independent as independent
from app.mirror import qualification_independent


def _hex(label: str) -> str:
    return hashlib.sha3_512(label.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _policy(**changes: object) -> producer.ExternalGovernanceApprovalPolicyV1:
    values: dict[str, object] = {
        "source_policy_digest": _hex("source-policy"),
        "quarantine_policy_digest": _hex("quarantine-policy"),
        "quarantine_artifact_id": _hex("quarantine-artifact"),
        "quarantine_head_artifact_id": _hex("quarantine-head-artifact"),
        "quarantine_head_root": _hex("quarantine-head-root"),
        "verifier_id": "SYNTHETIC_STATE_GOVERNANCE_VERIFIER_V1",
        "verifier_epoch": 7,
        "scope": producer.SCOPE,
        "effective_start": 1_000,
        "effective_end": 2_000,
        "max_evidence_bytes": 1_024,
        "authority_evidence_digest": _hex("authority-evidence"),
        "revocation_head_digest": _hex("revocation-head"),
        "terms_digest": _hex("terms"),
        "retention_policy_digest": _hex("retention-policy"),
    }
    values.update(changes)
    return producer.ExternalGovernanceApprovalPolicyV1(**values)


class _FixtureVerifier:
    def __init__(self, policy: producer.ExternalGovernanceApprovalPolicyV1, **changes: object) -> None:
        self.policy = policy
        self.verifier_id = policy.verifier_id
        self.verifier_epoch = policy.verifier_epoch
        self.authority_evidence_digest = policy.authority_evidence_digest
        self.revocation_head_digest = policy.revocation_head_digest
        self.terms_digest = policy.terms_digest
        self.retention_policy_digest = policy.retention_policy_digest
        self.changes = changes

    def verify(self, evidence_raw: bytes) -> producer.VerifiedGovernanceAssertionV1:
        evidence_digest = hashlib.sha3_512(evidence_raw).hexdigest()
        values: dict[str, object] = {
            "policy_digest": self.policy.digest,
            "approval_id": independent.approval_id_for_evidence(evidence_digest, len(evidence_raw)),
            "evidence_sha3_512": evidence_digest,
            "evidence_byte_length": len(evidence_raw),
            "quarantine_policy_digest": self.policy.quarantine_policy_digest,
            "quarantine_artifact_id": self.policy.quarantine_artifact_id,
            "quarantine_head_artifact_id": self.policy.quarantine_head_artifact_id,
            "quarantine_head_root": self.policy.quarantine_head_root,
            "authority_evidence_digest": self.authority_evidence_digest,
            "revocation_head_digest": self.revocation_head_digest,
            "terms_digest": self.terms_digest,
            "retention_policy_digest": self.retention_policy_digest,
            "decision": "GRANTED",
            "issued_at": 1_100,
            "valid_from": 1_150,
            "valid_until": 1_500,
            "observed_at": 1_200,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "zero_phi": True,
            "state_owned": True,
        }
        values.update(self.changes)
        return producer.VerifiedGovernanceAssertionV1(**values)


class GovernanceApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = _policy()
        self.evidence = b"synthetic-governance-assertion-v1"
        self.verifier = _FixtureVerifier(self.policy)
        self.service = producer.ExternalGovernanceApprovalService(self.policy, self.verifier)

    @staticmethod
    def _value(raw: bytes) -> dict[str, object]:
        return json.loads(raw.decode("ascii"))

    @staticmethod
    def _rebind(value: dict[str, object]) -> bytes:
        body = {key: item for key, item in value.items() if key != "artifact_id"}
        return _canonical({**body, "artifact_id": independent._digest("artifact-id", body)})

    def _artifact(self, **changes: object) -> producer.ExternalGovernanceApprovalArtifactV1:
        return producer.ExternalGovernanceApprovalService(self.policy, _FixtureVerifier(self.policy, **changes)).observe(self.evidence)

    def test_all_three_decisions_are_observed_and_independently_reconstructed(self) -> None:
        for decision in producer.DECISIONS:
            with self.subTest(decision=decision):
                artifact = self._artifact(decision=decision)
                result = independent.verify_artifact(
                    artifact.raw,
                    policy=self.policy.material(),
                    evidence_raw=self.evidence,
                )
                self.assertEqual(result["decision"], decision)
                self.assertEqual(result["derived_status"], producer.STATUS)
                self.assertFalse(result["external_authority_authenticated"])
                self.assertFalse(result["state_approval_qualified"])
                self.assertFalse(result["controlled_shadow_ready"])
                self.assertFalse(result["production_usable"])
                self.assertFalse(result["activation"])

    def test_policy_is_immutable_artifact_is_deterministic_and_raw_evidence_is_absent(self) -> None:
        first = self.service.observe(self.evidence)
        second = self.service.observe(self.evidence)
        self.assertEqual(first.raw, second.raw)
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertNotIn(self.evidence, first.raw)
        value = self._value(first.raw)
        self.assertEqual(value["derived_status"], producer.STATUS)
        for forbidden in ("APPROVED", "ACTIVE", "READY", "LIVE", "CLEAR", "QUALIFIED"):
            self.assertNotEqual(value["derived_status"], forbidden)
        with self.assertRaises(Exception):
            self.policy.scope = "CALLER"  # type: ignore[misc]

    def test_verifier_configuration_exception_and_result_type_fail_closed(self) -> None:
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-config"):
            producer.ExternalGovernanceApprovalService(self.policy, _FixtureVerifier(_policy(verifier_epoch=8)))

        class RaisingVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedGovernanceAssertionV1:
                raise RuntimeError("fixture-only failure")

        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-failure"):
            producer.ExternalGovernanceApprovalService(self.policy, RaisingVerifier(self.policy)).observe(self.evidence)

        class WrongTypeVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedGovernanceAssertionV1:
                return {"not": "typed"}  # type: ignore[return-value]

        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-result-type"):
            producer.ExternalGovernanceApprovalService(self.policy, WrongTypeVerifier(self.policy)).observe(self.evidence)

    def test_policy_quarantine_authority_and_evidence_bindings_are_not_caller_selected(self) -> None:
        cases = (
            ("policy", {"policy_digest": _hex("other-policy")}, "policy-binding"),
            ("quarantine", {"quarantine_head_root": _hex("other-root")}, "quarantine-binding"),
            ("authority", {"authority_evidence_digest": _hex("other-authority")}, "verifier-binding"),
            ("revocation", {"revocation_head_digest": _hex("other-revocation")}, "verifier-binding"),
            ("terms", {"terms_digest": _hex("other-terms")}, "verifier-binding"),
            ("retention", {"retention_policy_digest": _hex("other-retention")}, "verifier-binding"),
            ("approval", {"approval_id": _hex("other-approval")}, "approval-binding"),
            ("payload", {"evidence_sha3_512": _hex("other-evidence")}, "evidence-binding"),
        )
        for case_id, changes, error in cases:
            with self.subTest(case_id=case_id):
                with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, error):
                    self._artifact(**changes)

    def test_raw_snapshot_caps_and_control_flags_fail_closed(self) -> None:
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-id"):
            _policy(verifier_id="https://fixture.invalid")
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "evidence-byte-cap"):
            producer.ExternalGovernanceApprovalService(
                _policy(max_evidence_bytes=3), _FixtureVerifier(_policy(max_evidence_bytes=3))
            ).observe(self.evidence)
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "evidence-bytes"):
            self.service.observe(bytearray(self.evidence))  # type: ignore[arg-type]

        class ChangedBytesVerifier(_FixtureVerifier):
            def verify(self, evidence_raw: bytes) -> producer.VerifiedGovernanceAssertionV1:
                return _FixtureVerifier(self.policy).verify(b"different-snapshot")

        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "evidence-binding"):
            producer.ExternalGovernanceApprovalService(self.policy, ChangedBytesVerifier(self.policy)).observe(self.evidence)

        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "control-flags"):
            self._artifact(zero_phi=False)

    def test_chronology_and_policy_window_are_strict(self) -> None:
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "policy-chronology"):
            self._artifact(issued_at=900, valid_from=1_150)
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "policy-chronology"):
            self._artifact(valid_until=2_001)
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-failure"):
            self._artifact(issued_at=1_300, valid_from=1_150)
        with self.assertRaisesRegex(producer.ExternalGovernanceApprovalError, "verifier-failure"):
            self._artifact(valid_from=1_600, observed_at=1_500)

    def test_independent_parser_rejects_mutation_rebinding_and_noncanonical_input(self) -> None:
        artifact = self.service.observe(self.evidence)
        mutations: list[tuple[str, dict[str, object]]] = []
        value = self._value(artifact.raw)
        value["derived_status"] = "CONTROLLED_SHADOW_READY"
        mutations.append(("status", value))
        value = self._value(artifact.raw)
        value["flags"]["production_usable"] = True  # type: ignore[index]
        mutations.append(("production", value))
        value = self._value(artifact.raw)
        value["assertion"]["decision"] = "APPROVED"  # type: ignore[index]
        mutations.append(("decision", value))
        value = self._value(artifact.raw)
        value["unknown"] = True
        mutations.append(("unknown", value))
        value = self._value(artifact.raw)
        value["policy"]["scope"] = "CALLER"  # type: ignore[index]
        mutations.append(("policy", value))
        for flag in (
            "external_authority_authenticated", "state_approval_qualified", "controlled_shadow_ready",
            "production_usable", "activation", "payment_authority", "clearance_authority",
            "settlement_authority",
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
                with self.assertRaises(independent.IndependentExternalGovernanceError):
                    independent.verify_artifact(self._rebind(mutation), policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalGovernanceError):
            independent.verify_artifact(artifact.raw + b"\n", policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalGovernanceError):
            independent.verify_artifact(b'{"artifact_kind":"x","artifact_kind":"y"}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalGovernanceError):
            independent.verify_artifact(b'{"artifact_kind":NaN}', policy=self.policy.material())
        with self.assertRaises(independent.IndependentExternalGovernanceError):
            independent.verify_artifact(b'{"artifact_kind":"caf\xc3\xa9"}', policy=self.policy.material())
        self.assertEqual(len(mutations), 17)
        with self.assertRaises(independent.IndependentExternalGovernanceError):
            independent.verify_artifact(b"x" * (independent.MAX_ARTIFACT_BYTES + 1), policy=self.policy.material())

    def test_independent_rejects_evidence_reference_rebinding_and_raw_mismatch(self) -> None:
        artifact = self.service.observe(self.evidence)
        value = self._value(artifact.raw)
        value["assertion"]["terms_digest"] = _hex("rebound-terms")  # type: ignore[index]
        with self.assertRaisesRegex(independent.IndependentExternalGovernanceError, "evidence-reference-binding"):
            independent.verify_artifact(self._rebind(value), policy=self.policy.material())
        with self.assertRaisesRegex(independent.IndependentExternalGovernanceError, "evidence-rebound"):
            independent.verify_artifact(artifact.raw, policy=self.policy.material(), evidence_raw=b"x" * len(self.evidence))
        drift = self.policy.material()
        drift["quarantine_head_root"] = _hex("other-head")
        with self.assertRaisesRegex(independent.IndependentExternalGovernanceError, "policy-binding"):
            independent.verify_artifact(artifact.raw, policy=drift)
        bad_policy = self.policy.material()
        bad_policy["unexpected"] = True
        with self.assertRaisesRegex(independent.IndependentExternalGovernanceError, "policy-keys"):
            independent.verify_artifact(artifact.raw, policy=bad_policy)

    def test_same_bytes_same_identity_and_distinct_decision_or_snapshot_are_distinct(self) -> None:
        first = self.service.observe(self.evidence)
        self.assertEqual(first.raw, self.service.observe(self.evidence).raw)
        different_evidence = self.service.observe(b"another-governance-assertion")
        self.assertNotEqual(first.artifact_id, different_evidence.artifact_id)
        different_decision = self._artifact(decision="DENIED")
        self.assertNotEqual(first.artifact_id, different_decision.artifact_id)
        other_policy = _policy(quarantine_head_root=_hex("other-head"))
        other = producer.ExternalGovernanceApprovalService(other_policy, _FixtureVerifier(other_policy)).observe(self.evidence)
        self.assertNotEqual(first.artifact_id, other.artifact_id)

    def test_no_downstream_mutation_import_and_qualification_ledger_update(self) -> None:
        for path in (producer.__file__, independent.__file__):
            source = Path(path).read_text(encoding="utf-8")
            for forbidden in (
                "from app.mirror import external_source_quarantine",
                "from app.mirror import continuity_store",
                "from app.mirror import provider_trust_graph",
                "from app.mirror import discrepancy",
                "import app.mirror.external_source_quarantine",
                "import app.mirror.continuity_store",
            ):
                self.assertNotIn(forbidden, source.lower())
        gap = next(item for item in qualification_independent.GAP_LEDGER["software_gaps"] if item["gap_id"] == "EXTERNAL_GOVERNANCE_APPROVAL_ADAPTER")
        self.assertEqual(gap["status"], "SOFTWARE_CONTRACT_ONLY")
        self.assertIn("remain external", gap["claim"])
        self.assertEqual(
            next(item for item in qualification_independent.GAP_LEDGER["software_gaps"] if item["gap_id"] == "CONTROLLED_SHADOW_PILOT_RUNTIME")["status"],
            "SOFTWARE_CONTRACT_ONLY",
        )


if __name__ == "__main__":
    unittest.main()
