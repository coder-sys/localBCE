"""Focused synthetic official-directive outbox tests.

All inputs are the existing zero-PHI queue/application fixtures.  The
receiver is an in-process deterministic fixture; no network or payment
interface is used.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
import unittest

from app.minimal_clearance_official_handoff import (
    OfficialHandoffConfigV1,
    OfficialHandoffIndeterminateError,
    OfficialHandoffLeaseError,
    OfficialHandoffStoreV1,
    build_directive_envelope,
)
from app.minimal_clearance_official_handoff_independent import (
    IndependentOfficialHandoffError,
    parse_envelope_bytes,
    read_applied_application,
    verify_database,
    verify_export_bytes,
)

from tests.test_minimal_clearance_queue_application import (
    QueueApplicationTests,
    _Acceptance,
    _StoreClock,
    _VERIFIER,
)


_RECEIVER_ID = b"R" * 32


class _Receiver:
    def __init__(self, *, malformed: bool = False) -> None:
        self.malformed = malformed
        self._lock = Lock()
        self.seen: dict[bytes, bytes] = {}
        self.side_effects = 0

    def identity_sha256(self) -> bytes:
        return _RECEIVER_ID

    def epoch(self) -> int:
        return 1

    def dispatch(self, envelope_bytes: bytes, idempotency_key: bytes) -> bytes:
        with self._lock:
            if self.malformed:
                return b"{}"
            if idempotency_key in self.seen:
                return self.seen[idempotency_key]
            envelope = parse_envelope_bytes(envelope_bytes)
            self.side_effects += 1
            accepted_ms = 20_000 + self.side_effects
            ack_id = hashlib.sha3_512(b"fixture-ack\x00" + idempotency_key).digest().hex().upper()
            raw = json.dumps(
                {
                    "schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE-OFFICIAL-HANDOFF/v1",
                    "receiver_identity": _RECEIVER_ID.hex().upper(),
                    "receiver_epoch": 1,
                    "idempotency_key": idempotency_key.hex().upper(),
                    "envelope_digest": hashlib.sha3_512(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v1\x00" + envelope_bytes).digest().hex().upper(),
                    "effective_directive": int(envelope["effective_directive"]),
                    "accepted_ms": accepted_ms,
                    "acknowledgment_id": ack_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            self.seen[idempotency_key] = raw
            return raw


class OfficialHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bl-official-handoff-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _prepared(self, count: int = 4):
        helper = QueueApplicationTests(methodName="test_verified_discovery_apply_and_duplicate_convergence")
        helper.setUp()
        self.addCleanup(helper.tearDown)
        # Re-root the existing fixture helper in this test's isolated directory
        # by using its own temporary root; no bytes leave the test boundary.
        queue_path, queue_config, acceptance = helper._queue(count=count)
        state, verifier = helper._state(acceptance)
        app = helper._application(queue_config, state)
        for index in range(count):
            app.discover(queue_path, f"job-{index}")
        works = [app.claim_next(f"application-worker-{index}") for index in range(count)]
        for work in works:
            self.assertIsNotNone(work)
            app.apply(work, queue_database=queue_path, state_store=state)  # type: ignore[arg-type]
        receiver = _Receiver()
        config = OfficialHandoffConfigV1(
            outbox_id="official-handoff-test", application_id=app.config.application_id,
            application_config_digest=app.config.digest, verifier_sha256=_VERIFIER,
            state_store_identity=state.state_store_identity(), receiver_identity=_RECEIVER_ID,
            receiver_epoch=1, capacity=16, lease_seconds=300,
        )
        outbox = OfficialHandoffStoreV1(path=helper.root / "outbox.sqlite3", config=config, clock=_StoreClock())
        return helper, queue_path, state, verifier, app, works, receiver, config, outbox

    def test_all_five_directives_and_digest_only_envelope(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        try:
            view = read_applied_application(
                helper.root / "application.sqlite3", helper.root / "clearance.sqlite3",
                expected_application_id=config.application_id,
                expected_application_config_digest=config.application_config_digest,
                expected_state_store_identity=config.state_store_identity,
                expected_verifier_sha256=config.verifier_sha256,
                job_id="job-0",
            )
            for directive in range(1, 6):
                receipt = dict(view.receipt, effective_directive=directive)
                variant = replace(view, receipt=receipt)
                raw = build_directive_envelope(variant, config)
                parsed = parse_envelope_bytes(raw)
                self.assertEqual(parsed["effective_directive"], directive)
                self.assertTrue(parsed["proof_session_accepted"])
                self.assertFalse(parsed["proof_acceptance_is_clear"])
                self.assertNotIn(bytes(view.acceptance.canonical_bytes()).hex().upper(), raw.decode("ascii"))
        finally:
            state.close()

    def test_reordered_concurrent_discovery_and_dispatch(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=4)
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                jobs = list(pool.map(lambda index: outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", f"job-{index}"), [3, 1, 0, 2]))
            self.assertEqual({job.job_id for job in jobs}, {f"job-{i}" for i in range(4)})
            claimed = [outbox.claim_next(f"handoff-worker-{i}") for i in range(4)]
            self.assertTrue(all(item is not None for item in claimed))
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda work: outbox.dispatch(work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver), claimed))  # type: ignore[arg-type]
            self.assertEqual([result.status for result in results], ["ACKNOWLEDGED"] * 4)
            self.assertEqual(receiver.side_effects, 4)
            self.assertEqual(outbox.snapshot()["status_counts"], {"ACKNOWLEDGED": 4, "DISCOVERED": 0, "HELD": 0, "LEASED": 0})
            outbox.verify_integrity()
        finally:
            state.close()

    def test_duplicate_discovery_and_send_before_record_deduplicate(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        failures = {"value": True}
        outbox = OfficialHandoffStoreV1(
            path=helper.root / "outbox.sqlite3", config=config, clock=_StoreClock(),
            before_fault=lambda name: (_ for _ in ()).throw(RuntimeError("send_before_record")) if name == "after_dispatch_before_outbox_commit" and failures["value"] else None,
        )
        try:
            first = outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            retry = outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            self.assertEqual(first.operation_id, retry.operation_id)
            work = outbox.claim_next("worker")
            self.assertIsNotNone(work)
            with self.assertRaisesRegex(RuntimeError, "send_before_record"):
                outbox.dispatch(work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            failures["value"] = False
            result = outbox.dispatch(work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            self.assertEqual(result.status, "ACKNOWLEDGED")
            self.assertEqual(receiver.side_effects, 1)
            self.assertEqual(outbox.support_summary()["duplicate_delivery_count"], 0)
        finally:
            state.close()

    def test_response_loss_restart_export_restore_and_application_state_immutability(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        fired = {"value": True}
        outbox = OfficialHandoffStoreV1(
            path=helper.root / "outbox.sqlite3", config=config, clock=_StoreClock(),
            after_commit_fault=lambda name: (_ for _ in ()).throw(RuntimeError("handoff_response_loss")) if name == "after_outbox_commit" and fired["value"] else None,
        )
        try:
            before_state = state.snapshot()
            outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            work = outbox.claim_next("worker")
            self.assertIsNotNone(work)
            with self.assertRaises(OfficialHandoffIndeterminateError):
                outbox.dispatch(work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            fired["value"] = False
            recovered = outbox.dispatch(work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            self.assertEqual(recovered.status, "ACKNOWLEDGED")
            self.assertEqual(receiver.side_effects, 1)
            self.assertEqual(state.snapshot(), before_state)
            exported = outbox.export_bytes()
            summary = verify_export_bytes(exported, expected_config=config.as_json())
            self.assertEqual(summary["status_counts"]["ACKNOWLEDGED"], 1)
            restored = outbox.restore_from_export(helper.root / "outbox-restore.sqlite3", exported)
            self.assertEqual(restored["status_counts"]["ACKNOWLEDGED"], 1)
            restarted = OfficialHandoffStoreV1(path=helper.root / "outbox.sqlite3", config=config, clock=_StoreClock())
            restarted.verify_integrity()
        finally:
            state.close()

    def test_wrong_receiver_ack_envelope_state_and_lease_fail_closed(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        try:
            outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            work = outbox.claim_next("worker")
            self.assertIsNotNone(work)
            with self.assertRaises(OfficialHandoffLeaseError):
                outbox.dispatch(replace(work, lease_token=b"X" * 24), application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            with self.assertRaises(OfficialHandoffLeaseError):
                outbox.dispatch(replace(work, attempt=2), application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            with self.assertRaises(OfficialHandoffLeaseError):
                outbox.dispatch(replace(work, envelope_bytes=b"{}"), application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            wrong_receiver = _Receiver()
            wrong_config = replace(config, receiver_identity=b"W" * 32)
            wrong_outbox = OfficialHandoffStoreV1(path=helper.root / "wrong.sqlite3", config=wrong_config, clock=_StoreClock())
            wrong_outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            wrong_work = wrong_outbox.claim_next("worker")
            self.assertIsNotNone(wrong_work)
            held = wrong_outbox.dispatch(wrong_work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=receiver)  # type: ignore[arg-type]
            self.assertEqual(held.status, "HELD")
            bad_outbox = OfficialHandoffStoreV1(path=helper.root / "bad.sqlite3", config=config, clock=_StoreClock())
            bad_outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            bad_work = bad_outbox.claim_next("worker")
            self.assertIsNotNone(bad_work)
            self.assertEqual(bad_outbox.dispatch(bad_work, application_database=helper.root / "application.sqlite3", state_database=helper.root / "clearance.sqlite3", receiver=_Receiver(malformed=True)).status, "HELD")  # type: ignore[arg-type]
        finally:
            state.close()

    def test_application_state_drift_and_expired_leases_fail_closed(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        try:
            outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            work = outbox.claim_next("worker")
            self.assertIsNotNone(work)
            before_state = state.snapshot()
            held_application = outbox.dispatch(
                work, application_database=helper.root / "missing-application.sqlite3",
                state_database=helper.root / "clearance.sqlite3", receiver=receiver,
            )  # type: ignore[arg-type]
            self.assertEqual(held_application.status, "HELD")
            self.assertEqual(state.snapshot(), before_state)

            expiry_clock = _StoreClock()
            expiry_config = replace(config, outbox_id="official-handoff-expiry", lease_seconds=1)
            expiry = OfficialHandoffStoreV1(path=helper.root / "expiry.sqlite3", config=expiry_config, clock=expiry_clock)
            expiry.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            old = expiry.claim_next("worker-0")
            self.assertIsNotNone(old)
            expiry_clock.advance(1001)
            fresh = expiry.claim_next("worker-1")
            self.assertIsNotNone(fresh)
            self.assertEqual(fresh.attempt, 2)  # type: ignore[union-attr]
            with self.assertRaises(OfficialHandoffLeaseError):
                expiry.dispatch(old, application_database=helper.root / "application.sqlite3", state_database=helper.root / "missing-state.sqlite3", receiver=receiver)  # type: ignore[arg-type]

            exhaustion_clock = _StoreClock()
            exhaustion_config = replace(config, outbox_id="official-handoff-exhaustion", lease_seconds=1)
            exhaustion = OfficialHandoffStoreV1(path=helper.root / "exhaustion.sqlite3", config=exhaustion_config, clock=exhaustion_clock)
            exhaustion.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            for expected_attempt in (1, 2, 3):
                claimed = exhaustion.claim_next("worker")
                self.assertIsNotNone(claimed)
                self.assertEqual(claimed.attempt, expected_attempt)  # type: ignore[union-attr]
                exhaustion_clock.advance(1001)
            self.assertIsNone(exhaustion.claim_next("worker"))
            self.assertEqual(exhaustion.snapshot()["status_counts"], {"ACKNOWLEDGED": 0, "DISCOVERED": 0, "HELD": 1, "LEASED": 0})
            exhaustion.verify_integrity()
        finally:
            state.close()

    def test_independent_export_and_metadata_tamper_fail_closed(self) -> None:
        helper, queue_path, state, verifier, app, works, receiver, config, outbox = self._prepared(count=1)
        try:
            outbox.discover(helper.root / "application.sqlite3", helper.root / "clearance.sqlite3", "job-0")
            exported = outbox.export_bytes()

            unknown = json.loads(exported.decode("ascii"))
            unknown["unknown"] = True
            with self.assertRaises(IndependentOfficialHandoffError):
                verify_export_bytes(json.dumps(unknown, sort_keys=True, separators=(",", ":")).encode("ascii"), expected_config=config.as_json())

            truncated = exported[:-1]
            with self.assertRaises(IndependentOfficialHandoffError):
                verify_export_bytes(truncated, expected_config=config.as_json())

            substituted = json.loads(exported.decode("ascii"))
            substituted["config"]["receiver_epoch"] = 2
            with self.assertRaises(IndependentOfficialHandoffError):
                verify_export_bytes(json.dumps(substituted, sort_keys=True, separators=(",", ":")).encode("ascii"), expected_config=config.as_json())

            event_tampered = json.loads(exported.decode("ascii"))
            event_tampered["transitions"][0]["event_bytes"] = "7B2270617468223A22736563726574227D"
            with self.assertRaises(IndependentOfficialHandoffError):
                verify_export_bytes(json.dumps(event_tampered, sort_keys=True, separators=(",", ":")).encode("ascii"), expected_config=config.as_json())

            with closing(sqlite3.connect(outbox.path)) as connection:
                connection.execute("UPDATE outbox_metadata SET config_digest=? WHERE id=1", (b"X" * 64,))
                connection.commit()
            with self.assertRaises(IndependentOfficialHandoffError):
                verify_database(outbox.path, expected_config=config.as_json())
        finally:
            state.close()


if __name__ == "__main__":
    unittest.main()
