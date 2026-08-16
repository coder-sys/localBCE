"""Focused synthetic V2 profile, registry, lifecycle, and mutation tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest

from app.mirror import continuity_export as export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as independent
from app.mirror import support_boundary as support
from app.mirror.source_admission import (
    EvidenceMode,
    MultiSubjectSourceAdmissionService,
    SourceAdmissionBinding,
    SourceAdmissionError,
    SourceProfile,
    SourceRole,
    VerifiedSourceCoverage,
)


ADAPTER_SCHEMA = "mirror-test-source-adapter-v2"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _profile(number: int, *, require_complete: bool = False) -> SourceProfile:
    suffix = f"{number:03d}"
    roles = (
        SourceRole(
            f"SYNTH_SOURCE_CREDENTIAL_{suffix}",
            "CREDENTIAL_REGISTRY",
            "CREDENTIAL",
            f"SYNTH_AUTHORITY_CREDENTIAL_{suffix}",
            f"SYNTH_PROVENANCE_CREDENTIAL_{suffix}",
        ),
        SourceRole(
            f"SYNTH_SOURCE_ENROLLMENT_{suffix}",
            "ENROLLMENT_REGISTRY",
            "ENROLLMENT",
            f"SYNTH_AUTHORITY_ENROLLMENT_{suffix}",
            f"SYNTH_PROVENANCE_ENROLLMENT_{suffix}",
        ),
    )
    return SourceProfile(
        profile_id=f"SYNTH_PROFILE_V2_{suffix}",
        version=2,
        subject=f"SYNTH_PROVIDER_{suffix}",
        scope=f"synthetic-scope-v2-{suffix}",
        observation_time=None,
        effective_start=6_000,
        effective_end=9_000,
        source_roles=tuple(role.source_id for role in roles),
        require_complete=require_complete,
        verifier_id=f"SYNTH_TEST_VERIFIER_V2_{suffix}",
        verifier_epoch=2,
        evidence_mode=EvidenceMode.SYNTHETIC_TEST_ONLY,
        source_role_details=roles,
        credential_id=f"SYNTH_CREDENTIAL_{suffix}",
        enrollment_id=f"SYNTH_ENROLLMENT_{suffix}",
        observation_start=6_000,
        observation_end=9_000,
    )


def _record(profile: SourceProfile, kind: str, observation: int, *, valid_until: int = 9_000, terminated_at: int = 0) -> dict[str, object]:
    prefix = "CREDENTIAL" if kind == "CREDENTIAL" else "ENROLLMENT"
    status = graph.STATUS_TERMINATED if terminated_at else (graph.STATUS_ACTIVE if observation < valid_until else graph.STATUS_EXPIRED)
    return {
        "record_id": f"SYNTH_{prefix}_RECORD_001",
        "record_kind": kind,
        "provider_id": profile.subject,
        "credential_id": profile.credential_id,
        "enrollment_id": profile.enrollment_id,
        "subject_key": f"{profile.subject}|{profile.credential_id}|{profile.enrollment_id}",
        "observed_at": observation,
        "issued_at": 6_000,
        "valid_from": 6_000,
        "valid_until": valid_until,
        "terminated_at": terminated_at,
        "status": status,
    }


def _input(
    profile: SourceProfile,
    *,
    observation: int = 7_000,
    case: str = "confirmed",
    prior: dict[str, object] | None = None,
    remediation: dict[str, object] | None = None,
    complete: bool = True,
    effective_end: int = 9_000,
) -> dict[str, object]:
    assert profile.source_role_details is not None
    credential = _record(profile, "CREDENTIAL", observation, valid_until=6_500 if case == "expired" else 9_000)
    enrollment = _record(profile, "ENROLLMENT", observation, terminated_at=6_500 if case == "terminated" else 0)
    records = {"CREDENTIAL": [credential], "ENROLLMENT": [enrollment]}
    if case == "absent":
        records = {"CREDENTIAL": [], "ENROLLMENT": []}
    if case == "conflict":
        records["CREDENTIAL"].append(_record(profile, "CREDENTIAL", observation, valid_until=9_000))
    subject_key = f"{profile.subject}|{profile.credential_id}|{profile.enrollment_id}"
    sources: list[dict[str, object]] = []
    for role in profile.source_role_details:
        nonmembership = [subject_key] if case == "absent" else []
        source: dict[str, object] = {
            "source_id": role.source_id,
            "source_kind": role.source_kind,
            "coverage_scope": profile.scope,
            "coverage_observation_time": observation,
            "coverage_effective_start": 6_000,
            "coverage_effective_end": effective_end,
            "coverage_complete": complete,
            "coverage_authority_id": role.authority_id,
            "nonmembership_keys": nonmembership,
            "records": records[role.record_kind],
            "provenance": {"provenance_id": role.provenance_id, "integrity_digest": "0" * 128},
        }
        source["provenance"]["integrity_digest"] = graph.source_integrity_digest(source, profile)  # type: ignore[index]
        sources.append(source)
    result: dict[str, object] = {
        "schema": graph.INPUT_SCHEMA_V2,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_digest": profile.profile_digest,
        "provider_graph_subject": profile.subject,
        "scope": profile.scope,
        "observation_time": observation,
        "sources": sources,
        "prior_artifact": prior,
        "remediation": remediation,
        "parity_cases": [],
    }
    return result


def _build(profile: SourceProfile, **kwargs: object) -> tuple[bytes, dict[str, object]]:
    return graph.build_report(graph.canonical_input(_input(profile, **kwargs)), profile=profile)


class SyntheticV2Verifier:
    """Fixture-only verifier; it makes no production authentication claim."""

    def __init__(self, profile: SourceProfile) -> None:
        self.profile = profile
        self.identity = profile.verifier_id
        self.epoch = profile.verifier_epoch

    def verify(self, adapter_bytes: bytes) -> VerifiedSourceCoverage:
        try:
            value = json.loads(adapter_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("synthetic:parse") from exc
        if not isinstance(value, dict) or set(value) != {"schema", "source_token", "case", "observation"}:
            raise ValueError("synthetic:schema")
        if value["schema"] != ADAPTER_SCHEMA or value["source_token"] != self.profile.subject:
            raise ValueError("synthetic:profile-token")
        if value["case"] not in {"confirmed", "expired", "incomplete"} or type(value["observation"]) is not int:
            raise ValueError("synthetic:evidence")
        if _canonical(value) != adapter_bytes:
            raise ValueError("synthetic:noncanonical")
        observation = value["observation"]
        graph_value = _input(self.profile, observation=observation, case=value["case"], complete=value["case"] != "incomplete")
        assert self.profile.source_role_details is not None
        return VerifiedSourceCoverage(
            profile_id=self.profile.profile_id,
            subject=self.profile.subject,
            scope=self.profile.scope,
            observation_time=observation,
            effective_start=self.profile.effective_start,
            effective_end=self.profile.effective_end,
            complete=value["case"] != "incomplete",
            source_roles=self.profile.source_roles,
            evidence_mode=EvidenceMode.SYNTHETIC_TEST_ONLY,
            graph_input=graph.canonical_input(graph_value),
        )


def _adapter(profile: SourceProfile, *, case: str = "confirmed", observation: int = 7_000, **extra: object) -> bytes:
    value: dict[str, object] = {
        "schema": ADAPTER_SCHEMA,
        "source_token": profile.subject,
        "case": case,
        "observation": observation,
        **extra,
    }
    return _canonical(value)


class ProviderTrustGraphV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = tuple(_profile(number) for number in (1, 2, 3))
        self.registry = {profile.profile_id: profile for profile in self.profiles}

    def test_three_subjects_are_isolated_and_independently_verified(self) -> None:
        artifacts = []
        for profile in self.profiles:
            initial, telemetry = _build(profile, observation=7_000, case="expired")
            prior = json.loads(initial.decode("ascii"))
            remediation = {
                "action_artifact_id": "SYNTH_ACTION_001",
                "submitted_at": 7_500,
                "retest_result": "PASSED",
                "prior_finding_ids": [prior["findings"][0]["finding_id"]],
            }
            retest, _ = _build(profile, observation=8_000, case="confirmed", prior=prior, remediation=remediation)
            for raw in (initial, retest):
                result = independent.verify_bytes_v2(raw, self.registry)
                self.assertTrue(result["accepted"])
                self.assertEqual(profile.profile_id, result["profile_id"])
                artifacts.append(raw)
            self.assertEqual(initial, _build(profile, observation=7_000, case="expired")[0])
            self.assertFalse(telemetry["proof_performance_claim"])
        self.assertEqual(6, len(set(artifacts)))
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "profile:registry-miss"):
            independent.verify_bytes_v2(artifacts[0], {self.profiles[1].profile_id: self.profiles[1]})
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "profile:registry-required"):
            independent.verify_bytes_v2(artifacts[0], {})
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            independent.verify_bytes(artifacts[0])

    def test_source_omission_reorder_duplicate_and_profile_mutations_fail(self) -> None:
        profile = self.profiles[0]
        raw, _ = _build(profile)
        value = json.loads(raw.decode("ascii"))
        assert isinstance(value, dict)
        for mutation in (
            lambda v: v["source_coverage"].pop(),
            lambda v: v["source_coverage"].reverse(),
            lambda v: v["source_coverage"].append(deepcopy(v["source_coverage"][0])),
        ):
            mutated = deepcopy(value)
            mutation(mutated)
            with self.assertRaises(independent.IndependentProviderTrustGraphError):
                independent.verify_bytes_v2(_canonical(mutated), self.registry)
        mutated = deepcopy(value)
        mutated["profile"]["profile_digest"] = "0" * 128
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            independent.verify_bytes_v2(_canonical(mutated), self.registry)

    def test_rebound_source_roots_still_fail_independent_semantics(self) -> None:
        profile = self.profiles[0]
        raw, _ = _build(profile, case="confirmed")
        value = json.loads(raw.decode("ascii"))
        assert isinstance(value, dict)
        view = graph._profile_view(profile)
        sources = value["source_coverage"]
        assert isinstance(sources, list)
        record = sources[0]["records"][0]
        record["valid_until"] = 6_500
        record["status"] = graph.STATUS_EXPIRED
        for source in sources:
            source["provenance"]["integrity_digest"] = graph.source_integrity_digest(source, profile)
            source_without_root = {key: item for key, item in source.items() if key != "source_root"}
            source["source_root"] = graph._source_root(source_without_root, profile=view)
        observation = value["observation_snapshot"]["observation_time"]
        snapshot_id, snapshot_root = graph._snapshot(
            [{key: item for key, item in source.items() if key != "source_root"} for source in sources],
            observation,
            profile=view,
        )
        value["observation_snapshot"] = {
            "snapshot_id": snapshot_id,
            "snapshot_root": snapshot_root,
            "observation_time": observation,
        }
        finding = value["findings"][0]
        finding["observation_snapshot_id"] = snapshot_id
        finding["finding_id"] = graph._digest(
            "finding-id",
            {key: finding[key] for key in ("kind", "subject_key", "observation_snapshot_id", "evidence_refs")},
            profile=view,
        )
        value["report"]["identity_material"]["snapshot_id"] = snapshot_id
        value["report"]["identity_material"]["snapshot_root"] = snapshot_root
        value["report"]["identity_material"]["source_coverage_root"] = graph._digest(
            "source-coverage-root", {"source_roots": [source["source_root"] for source in sources]}, profile=view
        )
        value["report"]["identity_material"]["findings_root"] = graph._findings_root(value["findings"], profile=view)
        value["report"]["report_id"] = graph._digest("report-id", value["report"]["identity_material"], profile=view)
        value["transition"]["current_report_id"] = value["report"]["report_id"]
        value["transition"]["current_snapshot_id"] = snapshot_id
        value["transition"]["current_snapshot_root"] = snapshot_root
        transition_core = {key: value["transition"][key] for key in graph.TRANSITION_KEYS if key != "transition_id"}
        value["transition"]["transition_id"] = graph._digest("transition-id", transition_core, profile=view)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "finding:semantic-mismatch"):
            independent.verify_bytes_v2(_canonical(value), self.registry)

    def test_lifecycle_snapshots_are_append_only_and_retest_is_bound(self) -> None:
        profile = self.profiles[0]
        initial, _ = _build(profile, observation=7_000, case="expired")
        prior = json.loads(initial.decode("ascii"))
        assert isinstance(prior, dict)
        remediation = {
            "action_artifact_id": "SYNTH_ACTION_001",
            "submitted_at": 7_500,
            "retest_result": "PASSED",
            "prior_finding_ids": [prior["findings"][0]["finding_id"]],
        }
        retest, _ = _build(profile, observation=8_000, case="confirmed", prior=prior, remediation=remediation)
        result = independent.verify_bytes_v2(retest, self.registry)
        self.assertEqual(graph.LIFECYCLE_REMEDIATED, result["lifecycle"])
        payload = json.loads(retest.decode("ascii"))
        self.assertEqual("RETEST", payload["transition"]["transition_kind"])
        self.assertEqual(prior["report"]["report_id"], payload["transition"]["prior_report_id"])
        self.assertEqual(retest, _build(profile, observation=8_000, case="confirmed", prior=prior, remediation=remediation)[0])
        bad = deepcopy(payload)
        bad["remediation"]["prior_artifact"]["profile"]["profile_id"] = self.profiles[1].profile_id
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            independent.verify_bytes_v2(_canonical(bad), self.registry)

    def test_configured_multi_subject_admission_never_uses_raw_authority_fields(self) -> None:
        service = MultiSubjectSourceAdmissionService(
            tuple(SourceAdmissionBinding(profile, SyntheticV2Verifier(profile)) for profile in self.profiles)
        )
        admission = service.admit(_adapter(self.profiles[1]))
        self.assertEqual(self.profiles[1].profile_id, admission.profile_id)
        self.assertFalse(admission.production_source_authentication)
        receipt = json.loads(admission.receipt.decode("ascii"))
        self.assertEqual("mirror-source-admission-receipt-v2", receipt["schema"])
        self.assertFalse(receipt["production_source_authentication"])
        replay = service.admit(_adapter(self.profiles[1]), expected_receipt=admission.receipt)
        self.assertEqual(admission.receipt, replay.receipt)
        with self.assertRaisesRegex(SourceAdmissionError, "retry:conflict"):
            service.admit(_adapter(self.profiles[1], case="expired"), expected_receipt=admission.receipt)
        with self.assertRaises(SourceAdmissionError):
            service.admit(_adapter(self.profiles[1], verifier_id="forged"))
        with self.assertRaises(SourceAdmissionError):
            service.admit(_adapter(self.profiles[1], authenticated=True))

    def test_stale_and_partial_snapshots_remain_explicit_read_only_findings(self) -> None:
        profile = self.profiles[0]
        stale, _ = _build(profile, effective_end=6_999)
        partial, _ = _build(profile, complete=False)
        self.assertEqual([graph.FINDING_STALE], independent.verify_bytes_v2(stale, self.registry)["finding_kinds"])
        self.assertEqual([graph.FINDING_INCOMPLETE], independent.verify_bytes_v2(partial, self.registry)["finding_kinds"])

    def test_profile_nonmembership_policy_is_not_caller_selected(self) -> None:
        profile = replace(self.profiles[0], allow_nonmembership=False)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "source:nonmembership-policy"):
            _build(profile, case="absent")

    def test_profile_downgrade_and_input_profile_override_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile:v2-version"):
            replace(self.profiles[0], version=1)
        value = _input(self.profiles[0])
        value["profile_version"] = 1
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "input:profile"):
            graph.build_report(graph.canonical_input(value), profile=self.profiles[0])

    def test_concurrent_store_retry_export_restore_and_support_are_profile_isolated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-v2-store-") as directory:
            root = Path(directory)
            database = root / "state.db"
            configured = store.ContinuityStore(database, graph_profile_registry=self.registry)
            artifacts = [_build(profile, case="expired")[0] for profile in self.profiles]

            def admit(raw: bytes):
                return configured.admit(store.ARTIFACT_GRAPH, raw)

            with ThreadPoolExecutor(max_workers=3) as executor:
                receipts = list(executor.map(admit, artifacts))
            self.assertEqual(3, len(receipts))
            replay = configured.admit(store.ARTIFACT_GRAPH, artifacts[0])
            self.assertEqual(receipts[0].raw, replay.raw)
            verified = store_independent.verify_database(database, self.registry)
            self.assertEqual(3, verified["artifact_count"])
            self.assertEqual(3, verified["event_count"])
            self.assertEqual(3, verified["head_count"])
            normalized = [store.verify_artifact(store.ARTIFACT_GRAPH, raw, graph_profile_registry=self.registry) for raw in artifacts]
            chain_ids = {store._chain_id(item.kind, item.subject, item.scope, item.profile_id) for item in normalized}
            self.assertEqual(3, len(chain_ids))

            prior = json.loads(artifacts[0].decode("ascii"))
            remediation = {
                "action_artifact_id": "SYNTH_ACTION_001",
                "submitted_at": 7_500,
                "retest_result": "PASSED",
                "prior_finding_ids": [prior["findings"][0]["finding_id"]],
            }
            retest, _ = _build(self.profiles[0], observation=8_000, case="confirmed", prior=prior, remediation=remediation)
            configured.admit(store.ARTIFACT_GRAPH, retest)
            verified_after = store_independent.verify_database(database, self.registry)
            self.assertEqual(4, verified_after["event_count"])
            self.assertEqual(3, verified_after["head_count"])
            heads = configured._snapshot_rows()["heads"]
            self.assertEqual(3, len(heads))
            head_artifacts = {row["artifact_id"] for row in heads}
            self.assertIn(json.loads(retest.decode("ascii"))["report"]["report_id"], head_artifacts)
            for initial in artifacts[1:]:
                self.assertIn(json.loads(initial.decode("ascii"))["report"]["report_id"], head_artifacts)

            exported = export.export_database(database, self.registry)
            self.assertEqual(exported, export.export_database(database, self.registry))
            self.assertTrue(export.verify_export_bytes(exported, self.registry)["accepted"])
            restored = root / "restored.db"
            export.import_export(exported, restored, self.registry)
            self.assertEqual(exported, export.export_database(restored, self.registry))
            self.assertEqual(verified_after, store_independent.verify_database(restored, self.registry))

            bundle = support.build_support_bundle(database, graph_profile_registry=self.registry)
            self.assertTrue(support.verify_support_bytes(bundle)["accepted"])
            text = bundle.decode("ascii")
            for profile in self.profiles:
                self.assertNotIn(profile.subject, text)
                self.assertNotIn(profile.profile_id, text)
            self.assertNotRegex(text, r"[0-9a-f]{128}")


if __name__ == "__main__":
    unittest.main()
