from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app.mirror import core_v2 as core
from app.mirror import core_v2_independent as core_independent
from app.mirror import external_source_adapter as external
from app.mirror import ingress_v2 as ingress
from app.mirror import ingress_v2_independent as ingress_independent
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir as fhir_runtime
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import operational_owner as operational
from app.mirror import recovery_v2 as recovery
from app.mirror import recovery_v2_independent as recovery_independent
from tests.test_mirror_v2_consolidation import _Custody, _Storage, _hex
from tests.test_nc_medicaid_fhir_source import _bundle, _envelope, _transport


class _Clock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _Port:
    acquisition_identity = "synthetic-acquisition-port"

    def __init__(self, config: ingress.IngressConfigV2, *, fail: bool = False) -> None:
        self.external_policy_digest = config.external_policy().digest
        self.profile_digest = config.source_contract_digest
        self.config = config
        self.fail = fail
        self.calls: list[tuple[str, int, int]] = []

    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> operational.AcquisitionPayloadV1:
        self.calls.append((slot_id, scheduled_at, attempt))
        if self.fail:
            raise RuntimeError("CANARY_ACQUISITION_EXCEPTION")
        envelope = _envelope()
        evidence = external.build_artifact_from_capture(
            self.config.external_policy(), envelope, fhir.verify_bytes(envelope)
        ).raw
        return operational.AcquisitionPayloadV1(envelope, evidence)


class _ScheduledPort(_Port):
    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> operational.AcquisitionPayloadV1:
        self.calls.append((slot_id, scheduled_at, attempt))
        context = profile.DynamicCaptureContext(
            profile.DEFAULT_CAPTURE_CONTEXT.subject_id,
            profile.DEFAULT_CAPTURE_CONTEXT.credential_id,
            profile.DEFAULT_CAPTURE_CONTEXT.enrollment_id,
            profile.DEFAULT_CAPTURE_CONTEXT.subject_locator_digest,
            scheduled_at,
            scheduled_at + 1,
        )
        envelope = fhir_runtime.build_fixture_envelope(
            _transport(_bundle(last_updated=profile.FIXTURE_LAST_UPDATED)), context=context
        )
        evidence = external.build_artifact_from_capture(
            self.config.external_policy(), envelope, fhir.verify_bytes(envelope)
        ).raw
        return operational.AcquisitionPayloadV1(envelope, evidence)


class _MalformedPort(_Port):
    def acquire(self, slot_id: str, scheduled_at: int, attempt: int) -> operational.AcquisitionPayloadV1:
        self.calls.append((slot_id, scheduled_at, attempt))
        canary = b"CANARY_RAW_CAPTURE_AND_EVIDENCE"
        return operational.AcquisitionPayloadV1(canary, canary)


class MirrorOperationalOwnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mirror-operational-owner-")
        self.root = Path(self.temp.name)
        self.time = profile.FIXTURE_OBSERVATION_TIME
        self.clock = _Clock(self.time)
        self.ingress_config = ingress.IngressConfigV2(
            database_id="operational-ingress",
            chain_id="operational-ingress-chain",
            policy_digest=_hex("operational-policy"),
            authorization_digest=_hex("operational-authorization"),
            terms_digest=_hex("operational-terms"),
            effective_start=self.time,
            effective_end=self.time + 3600,
            cadence_seconds=60,
            max_slots=16,
        )
        self.core_config = core.CoreConfigV2(
            database_id="operational-core",
            chain_id="operational-core-chain",
            ingress_database_id=self.ingress_config.database_id,
            ingress_chain_id=self.ingress_config.chain_id,
            runtime_profile_digest=self.ingress_config.source_contract_digest,
            governance_policy_digest=_hex("operational-governance"),
            privacy_policy_digest=_hex("operational-privacy"),
            ingress_config_digest=self.ingress_config.digest,
        )
        self.custody = _Custody()
        self.storage = _Storage()
        self.recovery_config = recovery.RecoveryConfigV2(
            database_id="operational-recovery",
            chain_id="operational-recovery-chain",
            profile_digest=_hex("operational-recovery-profile"),
            custody_id=self.custody.custody_id,
            storage_id=self.storage.storage_id,
            ingress_database_id=self.ingress_config.database_id,
            core_database_id=self.core_config.database_id,
            ingress_config_digest=self.ingress_config.digest,
            core_config_digest=self.core_config.digest,
        )

    def _owner(self, *, port: _Port | None = None, max_due: int = 4) -> tuple[operational.MirrorOperationalOwnerV1, _Port]:
        selected = port or _Port(self.ingress_config)
        config = operational.OperationalConfigV1(
            selected.acquisition_identity,
            self.ingress_config.external_policy().digest,
            self.ingress_config.source_contract_digest,
            max_due,
        )
        return operational.MirrorOperationalOwnerV1(
            self.root,
            self.ingress_config,
            self.core_config,
            self.recovery_config,
            selected,
            self.custody,
            self.storage,
            clock=self.clock,
            operational_config=config,
        ), selected

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_clean_initialization_exact_paths_counts_and_one_batch(self) -> None:
        owner, port = self._owner()
        try:
            self.assertEqual(
                {path.name for path in self.root.iterdir()},
                {"ingress.sqlite", "core.sqlite", "recovery.sqlite", "operational.lock"},
            )
            for path, expected in (
                (owner.ingress_path, 5),
                (owner.core_path, 6),
                (owner.recovery_path, 3),
            ):
                connection = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        expected,
                        connection.execute(
                            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                        ).fetchone()[0],
                    )
                finally:
                    connection.close()
            result = owner.run((self.time,))
            self.assertEqual("COMPLETE", result.status)
            self.assertEqual(1, result.counts["admitted"])
            self.assertEqual(1, result.counts["core_ingested"])
            self.assertFalse(result.recovery_created)
            for service_result in (owner.ingress.verify(), owner.core.verify(), owner.recovery.verify()):
                self.assertTrue(service_result["flags"]["read_only"])
                self.assertTrue(service_result["flags"]["synthetic_only"])
                self.assertFalse(service_result["flags"]["production_usable"])
                self.assertFalse(service_result["flags"]["activation"])
                self.assertIsNone(service_result["flags"]["proofSuiteId"])
            with self.assertRaises(TypeError):
                result.counts["admitted"] = 0  # type: ignore[index]
        finally:
            owner.close()

    def test_second_owner_and_replacements_fail_closed_with_fixed_codes(self) -> None:
        owner, port = self._owner()
        try:
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-lock$"):
                self._owner()[0]
            replacement = self.root / "ingress.replacement"
            shutil.copy2(owner.ingress_path, replacement)
            replacement.replace(owner.ingress_path)
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                owner.run()
        finally:
            owner.close()

    def test_constructor_rejects_root_and_config_identity_downgrades(self) -> None:
        with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-root$"):
            self._owner_for_root(Path("relative-operational-root"))
        bad_core = replace(self.core_config, ingress_chain_id="wrong-chain")
        with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-config$"):
            operational.MirrorOperationalOwnerV1(
                self.root,
                self.ingress_config,
                bad_core,
                self.recovery_config,
                _Port(self.ingress_config),
                self.custody,
                self.storage,
                clock=self.clock,
                operational_config=operational.OperationalConfigV1(
                    "synthetic-acquisition-port",
                    self.ingress_config.external_policy().digest,
                    self.ingress_config.source_contract_digest,
                ),
            )

    def test_max_due_bounds_port_calls_and_future_slots_are_not_acquired(self) -> None:
        owner, port = self._owner(max_due=1)
        try:
            result = owner.run((self.time, self.time + 60, self.time + 120))
            self.assertEqual(1, len(port.calls))
            self.assertEqual(1, result.counts["processed"])
            self.assertEqual(3, result.counts["scheduled"])
            self.assertEqual(0, result.counts["admission_rejected"])
        finally:
            owner.close()

    def test_acquisition_failure_is_fixed_count_and_does_not_leak_canary(self) -> None:
        owner, port = self._owner(port=_Port(self.ingress_config, fail=True))
        try:
            lease_canary = "LEASE_TOKEN_CANARY_" + "x" * 64
            with mock.patch.object(operational.secrets, "token_hex", return_value=lease_canary):
                result = owner.run((self.time,))
            self.assertEqual(1, result.counts["acquisition_rejected"])
            self.assertNotIn("CANARY_ACQUISITION_EXCEPTION", repr(result))
            self.assertNotIn(lease_canary, owner.ingress_path.read_bytes().decode("latin1"))
            snapshot = owner.ingress.verify()
            self.assertEqual(1, snapshot["slot_count"])
            self.assertEqual(0, snapshot["artifact_count"])
        finally:
            owner.close()

    def test_admission_failure_is_fixed_and_raw_canary_is_not_persisted(self) -> None:
        owner, _port = self._owner(port=_MalformedPort(self.ingress_config))
        try:
            result = owner.run((self.time,))
            self.assertEqual(1, result.counts["admission_rejected"])
            self.assertNotIn("CANARY_RAW_CAPTURE_AND_EVIDENCE", repr(result))
            self.assertNotIn(b"CANARY_RAW_CAPTURE_AND_EVIDENCE", owner.ingress_path.read_bytes())
            self.assertNotIn(b"CANARY_RAW_CAPTURE_AND_EVIDENCE", owner.ingress.logical_export())
            self.assertNotIn("CANARY_RAW_CAPTURE_AND_EVIDENCE", json.dumps(owner.ingress.support(), sort_keys=True))
            self.assertEqual({"LEASED": 1}, {key: value for key, value in owner.ingress.verify()["state_counts"].items() if value})
        finally:
            owner.close()

    def test_recovery_is_explicit_only_and_created_after_successful_state(self) -> None:
        owner, _port = self._owner()
        try:
            first = owner.run()
            self.assertFalse(first.recovery_created)
            with mock.patch.object(owner.core, "ingest_sources", wraps=owner.core.ingest_sources) as ingest, mock.patch.object(owner.recovery, "create_point", wraps=owner.recovery.create_point) as create_point:
                second = owner.run((self.time,), recovery_generation=1)
            self.assertTrue(second.recovery_created)
            self.assertEqual(1, second.counts["core_ingested"])
            self.assertEqual(1, ingest.call_count)
            self.assertEqual(1, create_point.call_count)
            self.assertEqual(1, owner.recovery.verify()["point_count"])
        finally:
            owner.close()

    def test_verifier_failure_is_fixed_and_has_no_exception_chain(self) -> None:
        owner, _port = self._owner()
        try:
            with mock.patch.object(
                ingress_independent,
                "verify_database",
                side_effect=RuntimeError("CANARY_VERIFIER_EXCEPTION"),
            ):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$") as context:
                    owner.run()
            self.assertIsNone(context.exception.__cause__)
            self.assertNotIn("CANARY_VERIFIER_EXCEPTION", str(context.exception))
        finally:
            owner.close()

    def test_restart_retry_is_idempotent_and_independently_reconstructed(self) -> None:
        owner, _port = self._owner()
        try:
            first = owner.run((self.time,))
            first_counts = (
                owner.ingress.verify()["artifact_count"],
                owner.core.verify()["artifact_count"],
                owner.ingress.verify()["sequence"],
                owner.core.verify()["sequence"],
            )
            ingress_export = owner.ingress.logical_export()
            core_export = owner.core.logical_export()
            recovery_export = owner.recovery.logical_export()
        finally:
            owner.close()
        owner, _port = self._owner()
        try:
            second = owner.run((self.time,))
            self.assertEqual(0, second.counts["admitted"])
            self.assertEqual(0, second.counts["core_ingested"])
            self.assertEqual(
                first_counts,
                (
                    owner.ingress.verify()["artifact_count"],
                    owner.core.verify()["artifact_count"],
                    owner.ingress.verify()["sequence"],
                    owner.core.verify()["sequence"],
                ),
            )
            self.assertEqual(ingress_export, owner.ingress.logical_export())
            self.assertEqual(core_export, owner.core.logical_export())
            self.assertEqual(recovery_export, owner.recovery.logical_export())
            self.assertEqual(
                self.ingress_config.database_id,
                ingress_independent.verify_database(owner.ingress_path)["database_id"],
            )
            self.assertTrue(
                core_independent.verify_database(
                    owner.core_path,
                    ingress_path=owner.ingress_path,
                )["ingress_bound"]
            )
            self.assertEqual(
                self.recovery_config.database_id,
                recovery_independent.verify_database(owner.recovery_path)["database_id"],
            )
        finally:
            owner.close()

    def test_core_failure_after_ingress_commit_is_recovered_without_acquisition(self) -> None:
        owner, first_port = self._owner()
        try:
            with mock.patch.object(owner.core, "ingest_sources", side_effect=RuntimeError("CANARY_CORE_FAILURE")):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$") as context:
                    owner.run((self.time,))
            self.assertIsNone(context.exception.__cause__)
            self.assertNotIn("CANARY_CORE_FAILURE", str(context.exception))
            self.assertEqual(1, len(first_port.calls))
            self.assertEqual(1, owner.ingress.verify()["artifact_count"])
            self.assertEqual(0, owner.core.verify()["artifact_count"])
        finally:
            owner.close()

        owner, restart_port = self._owner()
        try:
            with mock.patch.object(owner.core, "ingest_sources", wraps=owner.core.ingest_sources) as ingest:
                result = owner.run()
            self.assertEqual([], restart_port.calls)
            self.assertEqual(1, ingest.call_count)
            self.assertEqual(1, result.counts["core_recovered"])
            self.assertEqual(0, result.counts["core_ingested"])
            self.assertEqual(0, result.counts["core_pending"])
            self.assertEqual(3, owner.core.verify()["artifact_count"])
        finally:
            owner.close()

    def test_core_commit_then_raise_converges_without_duplicate_representation(self) -> None:
        owner, _port = self._owner()
        original = owner.core.ingest_sources

        def commit_then_raise(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            raise RuntimeError("CANARY_AFTER_CORE_COMMIT")

        try:
            with mock.patch.object(owner.core, "ingest_sources", side_effect=commit_then_raise):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                    owner.run((self.time,))
            self.assertEqual(3, owner.core.verify()["artifact_count"])
        finally:
            owner.close()

        owner, restart_port = self._owner()
        try:
            with mock.patch.object(owner.core, "ingest_sources", wraps=owner.core.ingest_sources) as ingest:
                result = owner.run()
            self.assertEqual([], restart_port.calls)
            self.assertEqual(0, ingest.call_count)
            self.assertEqual(0, result.counts["core_recovered"])
            self.assertEqual(0, result.counts["core_ingested"])
            self.assertEqual(0, result.counts["core_pending"])
            self.assertEqual(3, owner.core.verify()["artifact_count"])
        finally:
            owner.close()

    def test_recovery_backlog_is_bounded_and_prioritized_before_acquisition(self) -> None:
        owner, _port = self._owner(port=_ScheduledPort(self.ingress_config), max_due=4)
        try:
            self.clock.value = self.time + 120
            with mock.patch.object(owner.core, "ingest_sources", side_effect=RuntimeError("CANARY_CORE_BACKLOG")):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                    owner.run((self.time, self.time + 60, self.time + 120))
            self.assertEqual(3, owner.ingress.verify()["artifact_count"])
        finally:
            owner.close()

        owner, restart_port = self._owner(max_due=2)
        try:
            result = owner.run()
            self.assertEqual([], restart_port.calls)
            self.assertEqual(2, result.counts["core_recovered"])
            self.assertEqual(0, result.counts["core_ingested"])
            self.assertEqual(1, result.counts["core_pending"])
        finally:
            owner.close()

        owner, final_port = self._owner(max_due=2)
        try:
            result = owner.run()
            self.assertEqual([], final_port.calls)
            self.assertEqual(1, result.counts["core_recovered"])
            self.assertEqual(0, result.counts["core_pending"])
        finally:
            owner.close()

    def test_projection_drift_and_clock_rewind_fail_before_mutation(self) -> None:
        owner, port = self._owner()
        try:
            with mock.patch.object(owner.core, "_operational_represented_ingress_artifact_ids", return_value=("0" * 128, "0" * 128)):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                    owner.run((self.time,))
            self.assertEqual([], port.calls)
            self.assertEqual(0, owner.ingress.verify()["slot_count"])
        finally:
            owner.close()

        owner, port = self._owner()
        try:
            owner.run((self.time,))
            self.clock.value = self.time - 1
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                owner.run()
            self.assertEqual(1, len(port.calls))
        finally:
            owner.close()

    def test_entropy_and_payload_caps_are_fixed_and_sanitized(self) -> None:
        with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-acquisition$"):
            operational.AcquisitionPayloadV1(b"x" * (operational._MAX_ENVELOPE_BYTES + 1), b"x")

        owner, _port = self._owner()
        try:
            with mock.patch.object(operational.secrets, "token_hex", side_effect=RuntimeError("CANARY_ENTROPY")):
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$") as context:
                    owner.run((self.time,))
            self.assertIsNone(context.exception.__cause__)
            self.assertNotIn("CANARY_ENTROPY", str(context.exception))
            self.assertEqual({"DUE": 1}, {key: value for key, value in owner.ingress.verify()["state_counts"].items() if value})
        finally:
            owner.close()

    def test_store_replacement_is_fixed_without_sentinel_mutation(self) -> None:
        for name in ("ingress.sqlite", "core.sqlite", "recovery.sqlite"):
            owner, _port = self._owner()
            path = self.root / name
            original = path.read_bytes()
            sentinel = b"SENTINEL_STORE_REPLACEMENT"
            replacement = self.root / (name + ".replacement")
            replacement.write_bytes(sentinel)
            try:
                replacement.replace(path)
                with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                    owner.run()
                self.assertEqual(sentinel, path.read_bytes())
            finally:
                owner.close()
                path.unlink(missing_ok=True)
                path.write_bytes(original)

    def test_failed_port_leaves_lease_for_expiry_and_max_attempts_hold(self) -> None:
        owner, port = self._owner(port=_Port(self.ingress_config, fail=True))
        try:
            owner.run((self.time,))
            self.assertEqual({"LEASED": 1}, {key: value for key, value in owner.ingress.verify()["state_counts"].items() if value})
            for _index in range(self.ingress_config.max_attempts):
                self.clock.value += self.ingress_config.lease_seconds
                result = owner.run()
            self.assertEqual(1, result.counts["held"])
            self.assertEqual(self.ingress_config.max_attempts, len(port.calls))
        finally:
            owner.close()

    def test_expired_leases_are_processed_before_new_due_slots(self) -> None:
        port = _ScheduledPort(self.ingress_config)
        owner, _port = self._owner(port=port, max_due=2)
        try:
            created = owner.ingress.ensure_slot(self.time)
            expired_slot = json.loads(created.raw.decode("ascii"))["slot_id"]
            owner.ingress.claim_slot(expired_slot, lease_token="x" * 32)
            self.clock.value = self.time + self.ingress_config.lease_seconds
            scheduled = self.time + self.ingress_config.cadence_seconds
            result = owner.run((scheduled,))
            created_names = [call[0] for call in port.calls]
            self.assertEqual(2, len(created_names))
            self.assertEqual(expired_slot, created_names[0])
            self.assertEqual(2, result.counts["admitted"])
            self.assertEqual(0, result.counts["admission_rejected"])
        finally:
            owner.close()

    def test_multiple_admissions_use_one_core_batch_call(self) -> None:
        port = _ScheduledPort(self.ingress_config)
        owner, _port = self._owner(port=port, max_due=4)
        try:
            self.clock.value = self.time + 120
            with mock.patch.object(owner.core, "ingest_sources", wraps=owner.core.ingest_sources) as ingest:
                result = owner.run((self.time, self.time + 60))
            self.assertEqual(2, result.counts["admitted"])
            self.assertEqual(1, ingest.call_count)
            self.assertEqual(2, len(ingest.call_args.args[1]))
        finally:
            owner.close()

    def test_alias_hardlink_and_symlink_paths_fail_closed(self) -> None:
        owner, _port = self._owner()
        try:
            sidecar = self.root / "core.sqlite-wal"
            sidecar.write_bytes(b"sidecar")
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                owner.run()
        finally:
            owner.close()
            sidecar.unlink(missing_ok=True)

        owner, _port = self._owner()
        hardlink = self.root / "core-alias"
        try:
            os.link(owner.core_path, hardlink)
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-indeterminate$"):
                owner.run()
        finally:
            owner.close()
            if hardlink.exists():
                hardlink.unlink()

        ambiguous_root = self.root.parent / ".." / self.root.parent.name / self.root.name
        with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-root$"):
            self._owner_for_root(ambiguous_root)

        alias_root = self.root.parent / (self.root.name + "-alias")
        try:
            os.symlink(self.root, alias_root, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"directory symlink unavailable: {type(error).__name__}")
        try:
            with self.assertRaisesRegex(operational.OperationalOwnerError, "^mirror:operational-root$"):
                self._owner_for_root(alias_root)
        finally:
            alias_root.unlink(missing_ok=True)

    def _owner_for_root(self, root: Path, *, port: _Port | None = None, max_due: int = 4) -> tuple[operational.MirrorOperationalOwnerV1, _Port]:
        selected = port or _Port(self.ingress_config)
        config = operational.OperationalConfigV1(
            selected.acquisition_identity,
            self.ingress_config.external_policy().digest,
            self.ingress_config.source_contract_digest,
            max_due,
        )
        return operational.MirrorOperationalOwnerV1(
            root,
            self.ingress_config,
            self.core_config,
            self.recovery_config,
            selected,
            self.custody,
            self.storage,
            clock=self.clock,
            operational_config=config,
        ), selected


if __name__ == "__main__":
    unittest.main()
