"""Focused V2 governance-composition and profile-isolation tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from app.governance import provider_continuity_control_pack_v2 as governance
from app.governance import provider_continuity_control_pack_v2_independent as governance_independent
from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import support_boundary as support
from tests.test_mirror_provider_trust_graph_v2 import (
    _build,
    _canonical,
    _profile,
    _rebound_incomplete_artifact,
)


def _chain(profile) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    graph_raw, _ = _build(profile)
    candidate, _ = governance.build_candidate(graph_raw, profile)
    tested, _ = governance.build_tested(candidate, profile)
    approval = governance.build_approval_record(tested, profile, approval_time=7_300)
    approved, _ = governance.build_approved(tested, approval, profile)
    authorization = governance.build_withdrawal_authorization(approved, profile, withdrawal_time=7_400)
    withdrawal, _ = governance.build_withdrawal(approved, authorization, profile)
    return graph_raw, candidate, tested, approved, withdrawal


def _seed(store_instance: store.ContinuityStore, profile) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    chain = _chain(profile)
    for raw in chain[1:4]:
        store_instance.admit(store.ARTIFACT_GOVERNANCE, raw)
    return chain


class ProviderTrustGraphV2GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = (_profile(11), _profile(12))
        self.registry = {profile.profile_id: profile for profile in self.profiles}

    def test_approved_profile_is_required_and_exact_retry_is_state_stable(self) -> None:
        profile = self.profiles[0]
        graph_raw, candidate, tested, approved, _withdrawal = _chain(profile)
        with tempfile.TemporaryDirectory(prefix="mirror-v2-governance-required-") as directory:
            database = Path(directory) / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=self.registry)
            before = configured._snapshot_rows()
            with self.assertRaisesRegex(store.StoreConflictError, "governance:not-approved"):
                configured.admit(store.ARTIFACT_GRAPH, graph_raw)
            self.assertEqual(before, configured._snapshot_rows())
            for raw in (candidate, tested, approved):
                configured.admit(store.ARTIFACT_GOVERNANCE, raw)
            first = configured.admit(store.ARTIFACT_GRAPH, graph_raw)
            replay = configured.admit(store.ARTIFACT_GRAPH, graph_raw)
            self.assertEqual(first.raw, replay.raw)
            head = configured.provider_continuity_lifecycle_head(profile.subject, profile.scope, profile.profile_id)
            self.assertIsNotNone(head)
            assert head is not None
            self.assertEqual(profile.profile_id, head.profile_id)
            self.assertEqual(2, head.profile_version)

    def test_external_registry_and_profile_commitment_are_authoritative(self) -> None:
        profile = self.profiles[0]
        graph_raw, _candidate, _tested, approved, _withdrawal = _chain(profile)
        with self.assertRaisesRegex(governance_independent.IndependentControlPackV2Error, "profile:registry-miss"):
            governance_independent.verify_bytes(approved, {self.profiles[1].profile_id: self.profiles[1]})
        forged = json.loads(approved.decode("ascii"))
        forged["profile"]["profile_digest"] = "0" * 128
        forged["artifact_id"] = governance_independent._digest(
            "artifact-id", {key: value for key, value in forged.items() if key != "artifact_id"}
        )
        with self.assertRaisesRegex(governance_independent.IndependentControlPackV2Error, "profile:binding"):
            governance_independent.verify_bytes(_canonical(forged), self.registry)
        downgraded = json.loads(approved.decode("ascii"))
        downgraded["profile"]["version"] = 1
        downgraded["artifact_id"] = governance_independent._digest(
            "artifact-id", {key: value for key, value in downgraded.items() if key != "artifact_id"}
        )
        with self.assertRaisesRegex(governance_independent.IndependentControlPackV2Error, "profile:binding"):
            governance_independent.verify_bytes(_canonical(downgraded), self.registry)
        self.assertTrue(graph_independent.verify_bytes_v2(graph_raw, {profile.profile_id: profile})["accepted"])

    def test_profile_not_yet_effective_or_expired_observation_rejects(self) -> None:
        profile = self.profiles[0]
        for observation in (profile.effective_start - 1, profile.effective_end + 1):
            with self.assertRaisesRegex(graph.ProviderTrustGraphError, "input:observation-window"):
                _build(profile, observation=observation)

    def test_withdrawal_blocks_new_profile_admission_but_preserves_history_and_other_profile(self) -> None:
        profile_a, profile_b = self.profiles
        graph_a, *_ = _chain(profile_a)
        graph_b, candidate_b, tested_b, approved_b, withdrawal_b = _chain(profile_b)
        with tempfile.TemporaryDirectory(prefix="mirror-v2-governance-isolation-") as directory:
            database = Path(directory) / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=self.registry)
            _seed(configured, profile_a)
            _seed(configured, profile_b)
            configured.admit(store.ARTIFACT_GRAPH, graph_a)
            configured.admit(store.ARTIFACT_GRAPH, graph_b)
            configured.admit(store.ARTIFACT_GOVERNANCE, withdrawal_b)
            self.assertTrue(graph_independent.verify_bytes_v2(graph_b, self.registry)["accepted"])
            withdrawn_head = configured.provider_continuity_lifecycle_head(profile_b.subject, profile_b.scope, profile_b.profile_id)
            self.assertIsNotNone(withdrawn_head)
            assert withdrawn_head is not None
            self.assertFalse(withdrawn_head.active)
            self.assertEqual(2, withdrawn_head.profile_version)
            with self.assertRaisesRegex(store.StoreConflictError, "governance:withdrawn"):
                configured.admit(store.ARTIFACT_GRAPH, _build(profile_b, observation=8_000)[0])
            self.assertTrue(configured.admit(store.ARTIFACT_GRAPH, graph_b).raw)
            prior_a = json.loads(graph_a.decode("ascii"))
            remediation_a = {
                "action_artifact_id": "SYNTH_ACTION_001",
                "submitted_at": 7_500,
                "retest_result": "PASSED",
                "prior_finding_ids": [prior_a["findings"][0]["finding_id"]],
            }
            retest_a, _ = _build(profile_a, observation=8_000, prior=prior_a, remediation=remediation_a)
            configured.admit(store.ARTIFACT_GRAPH, retest_a)
            self.assertTrue(configured.provider_continuity_lifecycle_head(profile_a.subject, profile_a.scope, profile_a.profile_id).active)
            self.assertTrue(governance_independent.verify_bytes(withdrawal_b, self.registry)["accepted"])

    def test_required_completeness_is_still_enforced_at_governed_store_boundary(self) -> None:
        profile = _profile(13, require_complete=True)
        registry = {profile.profile_id: profile}
        valid, candidate, tested, approved, _withdrawal = _chain(profile)
        with tempfile.TemporaryDirectory(prefix="mirror-v2-governance-complete-") as directory:
            database = Path(directory) / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=registry)
            for raw in (candidate, tested, approved):
                configured.admit(store.ARTIFACT_GOVERNANCE, raw)
            configured.admit(store.ARTIFACT_GRAPH, valid)
            forged_incomplete = _rebound_incomplete_artifact(profile, valid)
            before = configured._snapshot_rows()
            with self.assertRaisesRegex(store.ArtifactAdmissionError, "artifact:independent-reject"):
                configured.admit(store.ARTIFACT_GRAPH, forged_incomplete)
            self.assertEqual(before, configured._snapshot_rows())

    def test_export_restore_and_support_retain_sanitized_profile_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-v2-governance-export-") as directory:
            root = Path(directory)
            database = root / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=self.registry)
            for profile in self.profiles:
                graph_raw, *_ = _seed(configured, profile)
                configured.admit(store.ARTIFACT_GRAPH, graph_raw)
            raw = export.export_database(database, self.registry)
            self.assertEqual(raw, export.export_database(database, self.registry))
            restored = root / "restored.db"
            export.import_export(raw, restored, self.registry)
            self.assertEqual(raw, export.export_database(restored, self.registry))
            self.assertEqual(
                store_independent.verify_database(database, self.registry),
                store_independent.verify_database(restored, self.registry),
            )
            bundle = support.build_support_bundle(database, graph_profile_registry=self.registry)
            value = json.loads(bundle.decode("ascii"))
            governed = value["profiles"]["governed_profiles"]
            self.assertEqual(
                [{"profile_id": profile.profile_id, "version": 2} for profile in self.profiles],
                governed,
            )
            for profile in self.profiles:
                self.assertNotIn(profile.subject, bundle.decode("ascii"))
            self.assertTrue(support.verify_support_bytes(bundle)["accepted"])

    def test_v2_stale_head_and_conflicting_retry_do_not_mutate_state(self) -> None:
        profile = self.profiles[0]
        with tempfile.TemporaryDirectory(prefix="mirror-v2-governance-retry-") as directory:
            database = Path(directory) / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=self.registry)
            initial, _candidate, _tested, _approved, _withdrawal = _chain(profile)
            _seed(configured, profile)
            configured.admit(store.ARTIFACT_GRAPH, initial)
            prior = json.loads(initial.decode("ascii"))
            remediation = {
                "action_artifact_id": "SYNTH_ACTION_001",
                "submitted_at": 7_500,
                "retest_result": "PASSED",
                "prior_finding_ids": [prior["findings"][0]["finding_id"]],
            }
            first, _ = _build(profile, observation=8_000, prior=prior, remediation=remediation)
            second, _ = _build(profile, observation=8_001, prior=prior, remediation=remediation)
            configured.admit(store.ARTIFACT_GRAPH, first)
            before = configured._snapshot_rows()
            with self.assertRaisesRegex(store.StoreConflictError, "head:stale-or-wrong-prior"):
                configured.admit(store.ARTIFACT_GRAPH, second)
            self.assertEqual(before, configured._snapshot_rows())


if __name__ == "__main__":
    unittest.main()
