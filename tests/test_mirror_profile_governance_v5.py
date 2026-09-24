"""Focused synthetic Core V5 multi-profile governance composition tests."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest import mock

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import operational_owner as operational
from app.mirror import profile_governance_v1 as governance
from app.mirror import profile_governance_v1_independent as governance_independent
from app.mirror import provider_evidence_export_v1 as provider_export
from app.mirror import provider_trust_graph as graph
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from app.mirror import restore_publication
from app.mirror import source_admission
from app.mirror import writer_authority
from tests.test_nc_medicaid_fhir_source import _envelope
from tests.test_mirror_v2_consolidation import _Custody, _Storage


class _Clock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _OwnerPort:
    acquisition_identity = "synthetic-owner-v5-acquisition"

    def __init__(self, config: ingress.IngressConfigV2, observation: bytes, receipt: bytes) -> None:
        self.external_policy_digest = "4" * 128
        self.profile_digest = config.source_contract_digest
        self.observation = observation
        self.receipt = receipt
        self.calls: list[tuple[str, int, int]] = []

    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> operational.SanitizedObservationPayloadV1:
        self.calls.append((slot_id, scheduled_at, attempt))
        return operational.SanitizedObservationPayloadV1(self.observation, self.receipt)


class CoreV5ProfileGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=r"C:\Temp", prefix="mirror-v5-governance-")
        self.root = Path(self.temp.name)
        self.authority = writer_authority.WriterAuthority(self.root)
        self.clock = _Clock(7_002)
        self.ingress_path = self.root / "ingress.sqlite"
        self.ingress_config = ingress.IngressConfigV2(
            database_id="ingress-v6-governance-test",
            chain_id="ingress-v6-governance-chain",
            policy_digest="1" * 128,
            authorization_digest="2" * 128,
            terms_digest="3" * 128,
            effective_start=6_000,
            effective_end=9_000,
            cadence_seconds=1,
            max_slots=8,
        )
        self.ingress = ingress.IngressServiceV2(
            self.ingress_path,
            self.ingress_config,
            clock=self.clock,
            authority=self.authority,
        )
        self.profile_a = profile.NC_MEDICAID_GRAPH_PROFILE
        self.profile_b = replace(self.profile_a, profile_id="synthetic.public.profile.two")
        self.registry = {self.profile_a.profile_id: self.profile_a, self.profile_b.profile_id: self.profile_b}
        admission = source_admission.SourceAdmissionService(
            self.profile_a, fhir_independent.NcMedicaidFhirVerifier()
        ).admit(_envelope())
        self.observation = admission.observation
        self.verification_receipt = admission.verification_receipt
        self.graph_a = admission.graph_artifact
        graph_input = json.loads(admission.graph_input.decode("ascii"))
        graph_input["profile_id"] = self.profile_b.profile_id
        graph_input["profile_digest"] = self.profile_b.profile_digest
        self.graph_b, _telemetry = graph.build_report(
            graph.canonical_input(graph_input), profile=self.profile_b
        )
        self.ingress.ensure_slot(7_000)
        slot = self.ingress.eligible_slots(1)[0]
        lease_token = "governance-v5-lease-token-0123456789"
        self.ingress.claim_slot(slot.slot_id, lease_token=lease_token)
        admitted = self.ingress.admit_observation(
            self.observation,
            self.verification_receipt,
            scheduled_at=7_000,
            attempt=1,
            lease_token=lease_token,
        )
        self.ingress_artifact_id = admitted.artifact_id
        self.candidate_a, _ = governance.build_candidate(self.graph_a, self.profile_a)
        self.tested_a, _ = governance.build_tested(self.candidate_a, self.profile_a)
        approval_a = governance.build_approval_record(
            self.tested_a, self.profile_a, approval_time=7_001
        )
        self.approved_a, _ = governance.build_approved(
            self.tested_a, approval_a, self.profile_a
        )
        self.candidate_b, _ = governance.build_candidate(self.graph_b, self.profile_b)
        self.tested_b, _ = governance.build_tested(self.candidate_b, self.profile_b)
        approval_b = governance.build_approval_record(
            self.tested_b, self.profile_b, approval_time=7_001
        )
        self.approved_b, _ = governance.build_approved(
            self.tested_b, approval_b, self.profile_b
        )
        withdrawal_auth = governance.build_withdrawal_authorization(
            self.approved_b, self.profile_b, withdrawal_time=7_400
        )
        self.withdrawal_b, _ = governance.build_withdrawal(
            self.approved_b, withdrawal_auth, self.profile_b
        )

    def tearDown(self) -> None:
        self.authority.close()
        self.temp.cleanup()

    def _config(self, *, max_sessions: int = 8) -> core.CoreConfigV5:
        return core.CoreConfigV5(
            database_id="core-v5-governance-test",
            chain_id="core-v5-governance-chain",
            ingress_database_id="ingress-v6-governance-test",
            ingress_chain_id="ingress-v6-governance-chain",
            ingress_config_digest=self.ingress_config.digest,
            profile_registry_digest=governance.profile_registry_digest(self.registry),
            max_sessions=max_sessions,
            max_slots_per_session=4,
            cadence_seconds=1,
        )

    def _service(self, name: str = "core.sqlite", *, max_sessions: int = 8) -> core.CoreServiceV5:
        return core.CoreServiceV5(
            self.root / name,
            self._config(max_sessions=max_sessions),
            profile_registry=self.registry,
            ingress_path=self.ingress_path,
            clock=self.clock,
            authority=self.authority,
        )

    @staticmethod
    def _observation_variant(raw: bytes, receipt_raw: bytes, observation_time: int) -> tuple[bytes, bytes]:
        observation = json.loads(raw.decode("ascii"))
        receipt = json.loads(receipt_raw.decode("ascii"))
        observation["observation_time"] = observation_time
        receipt["issued_at"] = observation_time
        observation_bytes = ingress_independent._canonical(observation)
        receipt["observation_digest"] = ingress_independent._raw_digest(
            "sanitized-observation", observation_bytes
        )
        return observation_bytes, ingress_independent._canonical(receipt)

    def _ingest(self, service: core.CoreServiceV5, profile_id: str | None = None) -> core.CoreReceiptV5:
        return service.ingest_observation_from_ingress(
            self.ingress_path,
            self.ingress_artifact_id,
            profile_id=profile_id or self.profile_a.profile_id,
            profile_version=3,
        )

    def test_all_governance_lifecycle_artifacts_are_independent_and_identity_free(self) -> None:
        withdrawal_auth = governance.build_withdrawal_authorization(
            self.approved_a, self.profile_a, withdrawal_time=7_400
        )
        withdrawal_a, _ = governance.build_withdrawal(
            self.approved_a, withdrawal_auth, self.profile_a
        )
        values = (
            (self.candidate_a, governance.STAGE_CANDIDATE),
            (self.tested_a, governance.STAGE_TESTED),
            (self.approved_a, governance.STAGE_APPROVED),
            (withdrawal_a, governance.ACTION_WITHDRAWN),
        )
        for raw, expected in values:
            result = governance_independent.verify_bytes(raw, self.registry)
            self.assertEqual(expected, result["current_stage_kind"])
            text = raw.decode("ascii")
            for forbidden in (
                "provider_graph_subject", "credential_id", "enrollment_id",
                "subject_key", "source_coverage", "graph_artifact",
                "graph_snapshot", "raw_source",
            ):
                self.assertNotIn(forbidden, text)

    def test_two_profiles_have_isolated_heads_and_cross_profile_rejection(self) -> None:
        service = self._service()
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            service.admit_profile_artifact(raw)
        for raw in (self.candidate_b, self.tested_b, self.approved_b):
            service.admit_profile_artifact(raw)
        head_a = service.profile_head(self.profile_a.profile_id, 3)
        head_b = service.profile_head(self.profile_b.profile_id, 3)
        self.assertIsNotNone(head_a)
        self.assertIsNotNone(head_b)
        assert head_a is not None and head_b is not None
        self.assertNotEqual(head_a["head_ref"], head_b["head_ref"])
        with self.assertRaises(governance_independent.IndependentProfileGovernanceError):
            governance_independent.verify_bytes(self.approved_a, {self.profile_b.profile_id: self.profile_b})
        before = service.verify()
        forged = json.loads(self.candidate_b.decode("ascii"))
        forged["profile"] = governance.profile_descriptor(self.profile_a)
        forged_raw = governance.canonical_bytes(forged)
        with self.assertRaisesRegex(core.CoreConflictError, "governance"):
            service.admit_profile_artifact(forged_raw)
        self.assertEqual(
            service.admit_profile_artifact(self.candidate_b).raw,
            service.admit_profile_artifact(self.candidate_b).raw,
        )
        with self.assertRaisesRegex(core.CoreConflictError, "ingress-required"):
            service.ingest_observation(
                self.observation,
                self.verification_receipt,
                profile_digest=self.profile_b.profile_digest,
            )
        self.assertEqual(before, service.verify())

    def test_observation_session_retry_restart_expiry_and_slot_bound(self) -> None:
        service = self._service(max_sessions=1)
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            service.admit_profile_artifact(raw)
        observation_receipt = self._ingest(service)
        self.assertEqual(observation_receipt.raw, self._ingest(service).raw)
        opened = service.open_session(self.profile_a.profile_id, 3)
        self.assertEqual(opened.raw, service.open_session(self.profile_a.profile_id, 3).raw)
        self.assertEqual("RUNNING", service.start_session(opened.session_id).next_state)
        before_slot_rejection = service.verify()
        with self.assertRaisesRegex(core.CoreConflictError, "observation-input"):
            service.observe(opened.session_id, 4, "PARITY")
        self.assertEqual(before_slot_rejection, service.verify())
        self.assertEqual("RUNNING", service.observe(opened.session_id, 0, "PARITY").next_state)
        restarted = self._service(max_sessions=1)
        self.assertTrue(restarted.verify()["structural_valid"])
        self.assertEqual(
            service.observe(opened.session_id, 0, "PARITY").raw,
            restarted.observe(opened.session_id, 0, "PARITY").raw,
        )
        self.clock.value = 9_000
        paused = restarted.pause_if_stale(opened.session_id)
        self.assertEqual("PAUSED", paused.next_state)
        self.assertEqual("AUTHORITY_EXPIRED", json.loads(paused.raw)["material"]["reason"])
        self.assertTrue(restarted.verify()["structural_valid"])

    def test_withdrawal_pauses_a_live_session_and_rejection_is_byte_stable(self) -> None:
        service = self._service()
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            service.admit_profile_artifact(raw)
        self._ingest(service)
        opened = service.open_session(self.profile_a.profile_id, 3)
        service.start_session(opened.session_id)
        before = service.verify()
        forged = json.loads(self.candidate_a.decode("ascii"))
        forged["profile"]["profile_digest"] = "0" * 128
        with self.assertRaises(core.CoreConflictError):
            service.admit_profile_artifact(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.assertEqual(before, service.verify())
        withdrawal_auth = governance.build_withdrawal_authorization(self.approved_a, self.profile_a, withdrawal_time=7_500)
        withdrawal, _ = governance.build_withdrawal(self.approved_a, withdrawal_auth, self.profile_a)
        service.admit_profile_artifact(withdrawal)
        paused = service.pause_if_stale(opened.session_id)
        self.assertEqual("PAUSED", paused.next_state)
        self.assertEqual("AUTHORITY_WITHDRAWN", json.loads(paused.raw)["material"]["reason"])

    def test_fresh_head_requires_candidate_and_rejects_standalone_terminal_artifacts(self) -> None:
        service = self._service("fresh-head.sqlite")
        with self.assertRaisesRegex(core.CoreConflictError, "governance-stage"):
            service.admit_profile_artifact(self.approved_a)
        with self.assertRaisesRegex(core.CoreConflictError, "governance-stage"):
            service.admit_profile_artifact(self.withdrawal_b)
        self.assertEqual(
            {
                "artifact_count": 0,
                "event_count": 0,
                "profile_head_count": 0,
                "session_count": 0,
                "slot_count": 0,
            },
            {key: service.verify()[key] for key in ("artifact_count", "event_count", "profile_head_count", "session_count", "slot_count")},
        )

    def test_independent_image_verifier_rejects_tampering_without_mutating_current_store(self) -> None:
        service = self._service("image-verifier.sqlite")
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            service.admit_profile_artifact(raw)
        self._ingest(service)
        image = service.path.read_bytes()
        expected = service.verify()
        self.assertEqual(
            expected,
            core_independent.verify_bytes_v5(
                image,
                expected_database_id=self._config().database_id,
                expected_config_digest=self._config().digest,
                profile_registry=self.registry,
                ingress_bytes=self.ingress_path.read_bytes(),
            ),
        )
        tampered_path = self.root / "tampered-image.sqlite"
        tampered_path.write_bytes(image)
        connection = sqlite3.connect(tampered_path)
        try:
            connection.execute("UPDATE core_events_v5 SET receipt_digest=? WHERE sequence=1", ("0" * 128,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(core_independent.CoreVerificationError):
            core_independent.verify_bytes_v5(
                tampered_path.read_bytes(),
                expected_database_id=self._config().database_id,
                expected_config_digest=self._config().digest,
                profile_registry=self.registry,
            )
        self.assertEqual(image, service.path.read_bytes())

    def test_v5_rejects_wrong_registry_and_config_without_mutating_current_store(self) -> None:
        service = self._service("identity-rejection.sqlite")
        before = service.path.read_bytes()
        wrong_registry = {self.profile_a.profile_id: self.profile_a}
        with self.assertRaisesRegex(core_independent.CoreVerificationError, "core-v5:registry"):
            core_independent.verify_database_v5(
                service.path,
                expected_database_id=self._config().database_id,
                expected_config_digest=self._config().digest,
                profile_registry=wrong_registry,
            )
        self.assertEqual(before, service.path.read_bytes())

        wrong_config = replace(self._config(), ingress_config_digest="0" * 128)
        with self.assertRaises(core.CoreError):
            core.CoreServiceV5(
                service.path,
                wrong_config,
                profile_registry=self.registry,
                ingress_path=self.ingress_path,
                clock=self.clock,
                authority=self.authority,
            )
        self.assertEqual(before, service.path.read_bytes())

    def test_v4_file_is_rejected_before_mutation_and_v5_surfaces_are_sanitized(self) -> None:
        legacy = self.root / "legacy-v4.sqlite"
        v4_config = core.CoreConfigV2(
            database_id="legacy-v4-test", chain_id="legacy-v4-chain",
            ingress_database_id="ingress-v4-test", ingress_chain_id="ingress-v4-chain",
            runtime_profile_digest=self.profile_a.profile_digest,
            governance_policy_digest="2" * 128, privacy_policy_digest="3" * 128,
            ingress_config_digest="4" * 128, corrective_action_control_digest="5" * 128,
        )
        core.CoreServiceV2(legacy, v4_config, clock=self.clock, authority=self.authority)
        legacy_bytes = legacy.read_bytes()
        with self.assertRaises(core.CoreError):
            core.CoreServiceV5(legacy, self._config(), profile_registry=self.registry, clock=self.clock, authority=self.authority)
        self.assertEqual(legacy_bytes, legacy.read_bytes())

        service = self._service()
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            service.admit_profile_artifact(raw)
        self._ingest(service)
        logical = service.logical_export()
        support = json.dumps(service.support(), sort_keys=True, separators=(",", ":")).encode("ascii")
        for surface in (logical, support, service.path.read_bytes()):
            for forbidden in (b"CANARY-RAW-SOURCE", b"provider_graph_subject", b"credential_id", b"enrollment_id", b"subject_key", b"source_coverage", b"graph_artifact", b"graph_snapshot"):
                self.assertNotIn(forbidden, surface)
        self.assertEqual("mirror-core-logical-export-v5", json.loads(logical)["schema"])


class OperationalOwnerV5CompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=r"C:\Temp", prefix="mirror-v5-owner-")
        self.root = Path(self.temp.name)
        self.clock = _Clock(7_002)
        self.ingress_config = ingress.IngressConfigV2(
            database_id="owner-v5-ingress",
            chain_id="owner-v5-ingress-chain",
            policy_digest="1" * 128,
            authorization_digest="2" * 128,
            terms_digest="3" * 128,
            effective_start=6_000,
            effective_end=9_000,
            cadence_seconds=1,
            max_slots=8,
        )
        self.profile_a = profile.NC_MEDICAID_GRAPH_PROFILE
        self.profile_b = replace(self.profile_a, profile_id="synthetic.owner.profile.two")
        self.registry = {
            self.profile_a.profile_id: self.profile_a,
            self.profile_b.profile_id: self.profile_b,
        }
        admission = source_admission.SourceAdmissionService(
            self.profile_a, fhir_independent.NcMedicaidFhirVerifier()
        ).admit(_envelope())
        self.observation = admission.observation
        self.verification_receipt = admission.verification_receipt
        graph_input = json.loads(admission.graph_input.decode("ascii"))
        graph_input["profile_id"] = self.profile_b.profile_id
        graph_input["profile_digest"] = self.profile_b.profile_digest
        graph_b, _telemetry = graph.build_report(
            graph.canonical_input(graph_input), profile=self.profile_b
        )
        self.candidate_a, _ = governance.build_candidate(admission.graph_artifact, self.profile_a)
        self.tested_a, _ = governance.build_tested(self.candidate_a, self.profile_a)
        approval_a = governance.build_approval_record(self.tested_a, self.profile_a, approval_time=7_001)
        self.approved_a, _ = governance.build_approved(self.tested_a, approval_a, self.profile_a)
        self.candidate_b, _ = governance.build_candidate(graph_b, self.profile_b)
        self.tested_b, _ = governance.build_tested(self.candidate_b, self.profile_b)
        approval_b = governance.build_approval_record(self.tested_b, self.profile_b, approval_time=7_001)
        self.approved_b, _ = governance.build_approved(self.tested_b, approval_b, self.profile_b)
        self.custody = _Custody()
        self.storage = _Storage()
        registry_digest = governance.profile_registry_digest(self.registry)
        self.core_config = core.CoreConfigV5(
            database_id="owner-v5-core",
            chain_id="owner-v5-core-chain",
            ingress_database_id=self.ingress_config.database_id,
            ingress_chain_id=self.ingress_config.chain_id,
            ingress_config_digest=self.ingress_config.digest,
            profile_registry_digest=registry_digest,
            max_sessions=4,
            max_slots_per_session=4,
            cadence_seconds=1,
        )
        self.recovery_config = recovery.RecoveryConfigV5(
            database_id="owner-v5-recovery",
            chain_id="owner-v5-recovery-chain",
            profile_digest=self.ingress_config.source_contract_digest,
            custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id,
            ingress_database_id=self.ingress_config.database_id,
            core_database_id=self.core_config.database_id,
            ingress_config_digest=self.ingress_config.digest,
            core_config_digest=self.core_config.digest,
            profile_registry_digest=registry_digest,
        )
        self.port = _OwnerPort(self.ingress_config, self.observation, self.verification_receipt)
        self.operational_config = operational.OperationalConfigV5(
            self.port.acquisition_identity,
            self.port.external_policy_digest,
            self.ingress_config.source_contract_digest,
            self.profile_a.profile_id,
            self.profile_a.version,
            4,
        )
        self.owner: operational.MirrorOperationalOwnerV1 | None = None

    def tearDown(self) -> None:
        if self.owner is not None and not self.owner._closed:
            self.owner.close()
        self.temp.cleanup()

    def _owner(self) -> operational.MirrorOperationalOwnerV1:
        self.owner = operational.MirrorOperationalOwnerV5(
            self.root,
            self.ingress_config,
            self.core_config,
            self.recovery_config,
            self.port,
            self.custody,
            self.storage,
            clock=self.clock,
            operational_config=self.operational_config,
            profile_registry=self.registry,
        )
        return self.owner

    def _admit_a(self, owner: operational.MirrorOperationalOwnerV1) -> None:
        for raw in (self.candidate_a, self.tested_a, self.approved_a):
            owner.admit_profile_artifact(raw)

    def _request(self) -> bytes:
        return ingress_independent._canonical({
            "domain": provider_export.REQUEST_DOMAIN,
            "version": 1,
            "operation_ref": secrets.token_hex(32),
            "consumer_domain": provider_export.CONSUMER_DOMAIN,
            "evidence_profile": provider_export.EVIDENCE_PROFILE,
            "evidence_profile_version": provider_export.EVIDENCE_PROFILE_VERSION,
            "not_before": 6_990,
            "expires_at": 7_050,
        })

    @staticmethod
    def _copy_rehashed_v5_catalog(
        source: Path,
        target: Path,
        *,
        component: str | None = None,
        oversized_length: int | None = None,
        update_point: bool = True,
    ) -> None:
        if (component is None) == (oversized_length is None):
            raise AssertionError("one V5 corruption must be selected")
        if component is not None and component not in {"ingress", "core"}:
            raise AssertionError("unsupported V5 component")
        target.write_bytes(source.read_bytes())
        connection = sqlite3.connect(target)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT * FROM recovery_events ORDER BY sequence").fetchall()
            previous = recovery_independent.GENESIS_ROOT
            replacement: str | None = None
            for row in rows:
                value = recovery_independent._parse(bytes(row["event_raw"]), "test:recovery-v5-event")
                material = value["material"]
                if row["event_kind"] == "PREPARE":
                    material = dict(material)
                    if component is not None:
                        component_value = dict(material[component])
                        old_digest = str(component_value["config_digest"])
                        replacement = "f" * 128 if old_digest != "f" * 128 else "e" * 128
                        component_value["config_digest"] = replacement
                        material[component] = component_value
                    if oversized_length is not None:
                        material["bundle_length"] = oversized_length
                        value["payload_length"] = oversized_length
                    value["material"] = material
                elif oversized_length is not None and row["event_kind"] == "VERIFIED":
                    material = dict(material)
                    material["bundle_length"] = oversized_length
                    value["material"] = material

                value["before_root"] = previous
                value["material_digest"] = recovery_independent._v5_digest("material", value["material"])
                value["event_id"] = recovery_independent._v5_digest(
                    "event-id",
                    {
                        key: value[key]
                        for key in recovery_independent._EVENT_RAW_KEYS
                        if key not in {"event_id", "after_root"}
                    },
                )
                value["after_root"] = recovery_independent._v5_event_root(
                    int(value["sequence"]),
                    previous,
                    str(value["event_id"]),
                    str(value["event_kind"]),
                    str(value["point_id"]),
                    str(value["next_state"]),
                    str(value["material_digest"]),
                    str(value["stream_kind"]),
                    str(value["stream_id"]),
                )
                raw = recovery_independent._canonical(value)
                connection.execute(
                    "UPDATE recovery_events SET event_id=?,before_root=?,after_root=?,material_digest=?,payload_length=?,event_raw=?,receipt_digest=? WHERE sequence=?",
                    (
                        value["event_id"],
                        value["before_root"],
                        value["after_root"],
                        value["material_digest"],
                        value["payload_length"],
                        raw,
                        recovery_independent._v5_raw_digest("receipt", raw),
                        value["sequence"],
                    ),
                )
                previous = str(value["after_root"])

            if update_point:
                if component is not None:
                    if replacement is None:
                        raise AssertionError("missing component replacement")
                    column = {
                        "ingress": "ingress_config_digest",
                        "core": "core_config_digest",
                    }[component]
                    connection.execute(f"UPDATE recovery_points SET {column}=?", (replacement,))
                if oversized_length is not None:
                    connection.execute("UPDATE recovery_points SET bundle_length=?", (oversized_length,))
            connection.execute("UPDATE recovery_meta SET head_root=? WHERE meta_id=1", (previous,))
            connection.commit()
        finally:
            connection.close()

    def test_recovery_v5_binds_components_to_stored_config_and_cap(self) -> None:
        owner = self._owner()
        self._admit_a(owner)
        created = owner.run((7_000,), recovery_generation=1)
        self.assertEqual(1, created.counts["recovery_created"])
        valid_path = owner.recovery_path
        valid_point = recovery_independent.select_point_v5(
            valid_path,
            generation=1,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
            expected_profile_registry_digest=self.recovery_config.profile_registry_digest,
        )["point"]
        bundle_length = int(valid_point["bundle_length"])

        def metadata(path: Path) -> tuple[object, object, object]:
            connection = sqlite3.connect(path)
            try:
                return connection.execute(
                    "SELECT config_digest,config_material,profile_registry_material FROM recovery_meta WHERE meta_id=1"
                ).fetchone()
            finally:
                connection.close()

        valid_metadata = metadata(valid_path)

        def assert_rejected(
            path: Path,
            config: recovery.RecoveryConfigV5,
            expected_error: str,
            expected_metadata: tuple[object, object, object],
        ) -> None:
            self.assertEqual(config.digest, expected_metadata[0])
            self.assertEqual(expected_metadata, metadata(path))
            before = path.read_bytes()
            with self.assertRaisesRegex(recovery_independent.RecoveryVerificationError, expected_error):
                recovery_independent.verify_database_v5(
                    path,
                    expected_database_id=config.database_id,
                    expected_config_digest=config.digest,
                    expected_profile_registry_digest=config.profile_registry_digest,
                )
            self.assertEqual(before, path.read_bytes())
            with self.assertRaisesRegex(recovery_independent.RecoveryVerificationError, expected_error):
                recovery_independent.select_point_v5(
                    path,
                    generation=1,
                    expected_database_id=config.database_id,
                    expected_config_digest=config.digest,
                    expected_profile_registry_digest=config.profile_registry_digest,
                )
            self.assertEqual(before, path.read_bytes())

        for component in ("ingress", "core"):
            event_only = self.root / f"tampered-v5-{component}-event.sqlite"
            self._copy_rehashed_v5_catalog(
                valid_path,
                event_only,
                component=component,
                update_point=False,
            )
            assert_rejected(
                event_only,
                self.recovery_config,
                "recovery:v5-prepare-config",
                valid_metadata,
            )

            projection = self.root / f"tampered-v5-{component}-projection.sqlite"
            self._copy_rehashed_v5_catalog(
                valid_path,
                projection,
                component=component,
                update_point=True,
            )
            assert_rejected(
                projection,
                self.recovery_config,
                "recovery:v5-point-config",
                valid_metadata,
            )

        small_cap = max(bundle_length, 1_024)
        self.assertLess(small_cap, recovery_independent.MAX_BUNDLE_BYTES)
        self.assertLessEqual(bundle_length, small_cap)
        self.assertLessEqual(small_cap + 1, recovery_independent.MAX_BUNDLE_BYTES)
        small_config = replace(self.recovery_config, max_bundle_bytes=small_cap)
        small_path = self.root / "small-cap-recovery.sqlite"
        assert owner._authority is not None
        small_service = recovery.RecoveryServiceV5(
            small_path,
            small_config,
            self.custody,
            self.storage,
            profile_registry=self.registry,
            authority=owner._authority,
        )
        small_service.create_point(owner.ingress_path, owner.core_path, generation=1)
        small_summary = small_service.verify()
        self.assertEqual(small_cap, small_summary["config_material"]["max_bundle_bytes"])
        small_metadata = metadata(small_path)
        self.assertEqual(small_config.digest, small_metadata[0])

        event_only_oversize = self.root / "tampered-v5-cap-event.sqlite"
        self._copy_rehashed_v5_catalog(
            small_path,
            event_only_oversize,
            oversized_length=small_cap + 1,
            update_point=False,
        )
        assert_rejected(
            event_only_oversize,
            small_config,
            "recovery:v5-prepare-range",
            small_metadata,
        )

        projection_oversize = self.root / "tampered-v5-cap-projection.sqlite"
        self._copy_rehashed_v5_catalog(
            small_path,
            projection_oversize,
            oversized_length=small_cap + 1,
            update_point=True,
        )
        assert_rejected(
            projection_oversize,
            small_config,
            "recovery:v5-point-size",
            small_metadata,
        )

    def test_owner_v5_composes_profiles_retry_recovery_restore_export_and_privacy(self) -> None:
        owner = self._owner()
        self._admit_a(owner)
        for raw in (self.candidate_b, self.tested_b, self.approved_b):
            owner.admit_profile_artifact(raw)
        first = owner.run((7_000,))
        self.assertEqual(1, first.counts["admitted"])
        self.assertEqual(1, first.counts["core_ingested"])
        self.assertEqual((), owner._reconciliation_pending())
        self.assertIsNotNone(owner.core.profile_head(self.profile_a.profile_id, 3))
        self.assertIsNotNone(owner.core.profile_head(self.profile_b.profile_id, 3))
        exported = owner.export_provider_evidence(self._request())
        self.assertTrue(exported)
        recovery_result = owner.run(recovery_generation=1)
        self.assertEqual(1, recovery_result.counts["recovery_created"])
        retry = owner.run(recovery_generation=1)
        self.assertEqual(0, retry.counts["recovery_created"])
        recovery_summary = owner.recovery.verify()
        self.assertEqual("mirror-recovery-v5", recovery_summary["schema"])
        recovery_bytes = owner.recovery.path.read_bytes()
        self.assertNotIn(self.custody.custody_id.encode("ascii"), recovery_bytes)
        self.assertNotIn(self.storage.storage_id.encode("ascii"), recovery_bytes)
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(owner.recovery_path)
        point = recovery_independent.select_point_v5(
            owner.recovery_path,
            generation=1,
            expected_database_id=self.recovery_config.database_id,
            expected_config_digest=self.recovery_config.digest,
            expected_profile_registry_digest=self.recovery_config.profile_registry_digest,
        )["point"]
        restored_ingress = self.root / "restored-ingress.sqlite"
        restored_core = self.root / "restored-core.sqlite"
        def fault(point_name: str) -> None:
            if point_name == "after_core_link":
                raise RuntimeError("synthetic partial-publication fault")

        with self.assertRaises(recovery.RecoveryError):
            with mock.patch.object(restore_publication, "_FAULT_HOOK", fault):
                owner.recovery.restore_point(point["point_id"], restored_ingress, restored_core)
        self.assertFalse(restored_ingress.exists())
        self.assertTrue(restored_core.exists())
        self.assertEqual(
            "PUBLICATION_PENDING",
            recovery_independent.select_point_v5(
                owner.recovery_path,
                point_id=point["point_id"],
                expected_profile_registry_digest=self.recovery_config.profile_registry_digest,
            )["point"]["state"],
        )
        published = owner.recovery.restore_point(point["point_id"], restored_ingress, restored_core)
        self.assertEqual("PUBLISHED", published.state)
        bootstrap = owner.recovery.bootstrap(point["point_id"])
        parsed_bootstrap = recovery_independent.parse_bootstrap_v5(
            bootstrap,
            expected_profile_registry_digest=self.recovery_config.profile_registry_digest,
        )
        self.assertEqual(point["storage_id_digest"], parsed_bootstrap["storage_id_digest"])
        self.assertEqual(self.ingress_config.database_id, ingress_independent.verify_database(restored_ingress)["database_id"])
        self.assertEqual(self.core_config.database_id, core_independent.verify_database_v5(
            restored_core,
            expected_database_id=self.core_config.database_id,
            expected_config_digest=self.core_config.digest,
            profile_registry=self.registry,
            ingress_path=restored_ingress,
        )["database_id"])
        for surface in (owner.core.path.read_bytes(), owner.core.logical_export(), json.dumps(owner.core.support()).encode("ascii")):
            for forbidden in (b"provider_graph_subject", b"credential_id", b"enrollment_id", b"subject_key", b"source_coverage", b"graph_artifact", b"graph_snapshot"):
                self.assertNotIn(forbidden, surface)

    def test_recovery_v5_empty_cross_version_identity_and_sanitized_material(self) -> None:
        owner = self._owner()
        recovery_bytes = owner.recovery_path.read_bytes()
        empty = owner.recovery.verify()
        self.assertEqual(0, empty["point_count"])
        self.assertEqual(
            self.recovery_config.profile_registry_digest,
            empty["profile_registry_digest"],
        )
        self.assertEqual(
            empty,
            recovery_independent.verify_database_v5(
                owner.recovery_path,
                expected_database_id=self.recovery_config.database_id,
                expected_config_digest=self.recovery_config.digest,
                expected_profile_registry_digest=self.recovery_config.profile_registry_digest,
                expected_profile_registry_material=owner.recovery._profile_registry_material,
            ),
        )
        self.assertNotIn(self.custody.custody_id.encode("ascii"), recovery_bytes)
        self.assertNotIn(self.storage.storage_id.encode("ascii"), recovery_bytes)
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database(owner.recovery_path)
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(
                owner.recovery_path,
                expected_profile_registry_digest="0" * 128,
            )
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(
                owner.recovery_path,
                expected_config_digest="0" * 128,
            )
        self.assertEqual(recovery_bytes, owner.recovery_path.read_bytes())

        v3_path = self.root / "empty-v3-recovery.sqlite"
        v3_config = recovery.RecoveryConfigV2(
            database_id="owner-v3-empty-recovery",
            chain_id="owner-v3-empty-recovery-chain",
            profile_digest=self.ingress_config.source_contract_digest,
            custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id,
            ingress_database_id=self.ingress_config.database_id,
            core_database_id=self.core_config.database_id,
            ingress_config_digest=self.ingress_config.digest,
            core_config_digest=self.core_config.digest,
        )
        recovery.RecoveryServiceV2(
            v3_path,
            v3_config,
            self.custody,
            self.storage,
            authority=owner._authority,
        )
        self.assertEqual(0, recovery_independent.verify_database(v3_path)["point_count"])
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(v3_path)

        tampered_schema = self.root / "tampered-v5-schema.sqlite"
        tampered_schema.write_bytes(recovery_bytes)
        connection = sqlite3.connect(tampered_schema)
        try:
            connection.execute("UPDATE recovery_meta SET schema=?,schema_version=?", ("mirror-recovery-v3", 3))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(tampered_schema)

        tampered_config = self.root / "tampered-v5-config.sqlite"
        tampered_config.write_bytes(recovery_bytes)
        config_connection = sqlite3.connect(tampered_config)
        try:
            config_raw = config_connection.execute("SELECT config_material FROM recovery_meta").fetchone()[0]
            config = json.loads(bytes(config_raw).decode("ascii"))
            config["database_id"] = "wrong-v5-recovery-id"
            config_connection.execute(
                "UPDATE recovery_meta SET config_material=?",
                (recovery_independent._canonical(config),),
            )
            config_connection.commit()
        finally:
            config_connection.close()
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(tampered_config)

        tampered_registry = self.root / "tampered-v5-registry.sqlite"
        tampered_registry.write_bytes(recovery_bytes)
        registry_connection = sqlite3.connect(tampered_registry)
        try:
            registry_raw = registry_connection.execute("SELECT profile_registry_material FROM recovery_meta").fetchone()[0]
            registry = json.loads(bytes(registry_raw).decode("ascii"))
            registry["profiles"] = []
            registry_connection.execute(
                "UPDATE recovery_meta SET profile_registry_material=?",
                (recovery_independent._canonical(registry),),
            )
            registry_connection.commit()
        finally:
            registry_connection.close()
        with self.assertRaises(recovery_independent.RecoveryVerificationError):
            recovery_independent.verify_database_v5(tampered_registry)
        self.assertEqual(recovery_bytes, owner.recovery_path.read_bytes())

    def test_owner_v5_core_pending_retry_and_tamper_fail_closed(self) -> None:
        owner = self._owner()
        self._admit_a(owner)
        with mock.patch.object(owner.core, "ingest_observation_from_ingress", side_effect=core.CoreError("core-v5:database")):
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                owner.run((7_000,))
        self.assertEqual(1, len(owner._reconciliation_pending()))
        recovered = owner.run()
        self.assertEqual(1, recovered.counts["core_recovered"])
        self.assertEqual((), owner._reconciliation_pending())
        connection = sqlite3.connect(owner.core.path)
        try:
            connection.execute("UPDATE core_events_v5 SET receipt_digest=? WHERE sequence=1", ("0" * 128,))
            connection.commit()
        finally:
            connection.close()
        tampered = owner.core.path.read_bytes()
        with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
            owner.run()
        self.assertEqual(tampered, owner.core.path.read_bytes())

    def test_owner_v5_reopen_profile_filter_recovery_export_and_no_duplicate(self) -> None:
        owner_a = self._owner()
        self._admit_a(owner_a)
        intake = owner_a.run((7_000,))
        self.assertEqual(1, intake.counts["core_ingested"])
        owner_a.close()
        self.owner = None

        ingress_result = ingress_independent.verify_database(
            self.root / "ingress.sqlite",
            expected_database_id=self.ingress_config.database_id,
            expected_config_digest=self.ingress_config.digest,
            include_observation=True,
        )
        artifact_id = ingress_result["current_artifact_id"]
        self.assertIsInstance(artifact_id, str)
        self.operational_config = replace(
            self.operational_config,
            profile_id=self.profile_b.profile_id,
            profile_version=self.profile_b.version,
        )
        owner_b = self._owner()
        for raw in (self.candidate_b, self.tested_b, self.approved_b):
            owner_b.admit_profile_artifact(raw)
        assert isinstance(artifact_id, str)
        self.assertEqual((artifact_id,), owner_b._reconciliation_pending())
        source_calls_before_b = tuple(self.port.calls)
        recovery_result = owner_b.run(recovery_generation=1)
        self.assertEqual(1, recovery_result.counts["core_recovered"])
        self.assertEqual(0, recovery_result.counts["core_ingested"])
        self.assertEqual(source_calls_before_b, tuple(self.port.calls))
        self.assertEqual((), owner_b._reconciliation_pending())
        self.assertIsNotNone(owner_b.core.profile_head(self.profile_a.profile_id, 3))
        self.assertIsNotNone(owner_b.core.profile_head(self.profile_b.profile_id, 3))
        selected_b = owner_b._current_provider_observation_selection()
        self.assertEqual(self.observation, selected_b.observation)
        self.assertEqual(self.verification_receipt, selected_b.verification_receipt)
        self.assertEqual(1, recovery_result.counts["recovery_created"])
        self.assertTrue(owner_b.export_provider_evidence(self._request()))
        before_reopen = owner_b.recovery.verify()
        core_before_reopen = owner_b.core.verify()
        self.assertEqual(1, before_reopen["point_count"])
        owner_b.close()
        self.owner = None

        self.operational_config = replace(
            self.operational_config,
            profile_id=self.profile_a.profile_id,
            profile_version=self.profile_a.version,
        )
        owner_a_reopened = self._owner()
        reopened = owner_a_reopened.run(recovery_generation=1)
        self.assertEqual(0, reopened.counts["core_recovered"])
        self.assertEqual(0, reopened.counts["core_ingested"])
        self.assertEqual(0, reopened.counts["recovery_created"])
        after_reopen = owner_a_reopened.recovery.verify()
        self.assertEqual(core_before_reopen, owner_a_reopened.core.verify())
        self.assertEqual(before_reopen["point_count"], after_reopen["point_count"])
        self.assertEqual(before_reopen["event_count"], after_reopen["event_count"])
        self.assertEqual(before_reopen["head_root"], after_reopen["head_root"])
        self.assertEqual((), owner_a_reopened._reconciliation_pending())


if __name__ == "__main__":
    unittest.main()
