"""Durable command identity, concurrent delivery, and bounded checkpoint lookup."""

from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer


REQUEST = gate.DecideRequest("tenant", "program", "SDP", "command", "payment", bytes(32),
                             "payee", 10, "2026-09", (), ())


class CommandIdentityTests(unittest.TestCase):
    def store(self, path):
        result = payer.PayerStore(path, links={}, grants=())
        self.addCleanup(result.close)
        return result

    @staticmethod
    def image(store):
        return {table: store._db.execute(f"SELECT * FROM {table}").fetchall() for table in payer._TABLES}

    def test_changed_request_conflicts_before_any_effect_sent_or_unsent(self):
        changes = (dict(payment_id="other"), dict(amount_cents=20), dict(payee_ref="other"), dict(period="2026-10"),
                   dict(evidence_refs=(bytes([1]) * 64,)))
        for sent in (False, True):
            for change in changes:
                with self.subTest(sent=sent, change=change), tempfile.TemporaryDirectory() as tmp:
                    store = self.store(Path(tmp) / "payer.db")
                    calls = []
                    def transmit(data):
                        calls.append(data)
                        if not sent:
                            raise OSError("transport failed")
                    if sent:
                        store.send(REQUEST, transmit)
                    else:
                        with self.assertRaisesRegex(OSError, "transport failed"):
                            store.send(REQUEST, transmit)
                    before = self.image(store)
                    with self.assertRaisesRegex(payer.GatePayerError, "^command_conflict$"):
                        store.send(replace(REQUEST, **change), calls.append)
                    self.assertEqual(self.image(store), before)
                    self.assertEqual(calls, [gate.encode_decide_request(REQUEST)])
                    store.close()

    def test_the_same_command_key_under_another_tenant_or_program_is_its_own_command(self):
        """Final review L5: a command key is scoped to its tenant and program, as the pins are, so another tenant's or
        program's reuse of it is stored and sent as its own command, never ``command_conflict``, and each is marked sent
        alone; a lost transmission of one is resent alone."""
        with tempfile.TemporaryDirectory() as tmp:
            store, sent = self.store(Path(tmp) / "payer.db"), []
            tenant, program = replace(REQUEST, tenant_id="other"), replace(REQUEST, program_id="other")
            store.send(REQUEST, sent.append)
            with self.assertRaisesRegex(OSError, "lost"):
                store.send(tenant, lambda _: (_ for _ in ()).throw(OSError("lost")))
            store.send(program, sent.append)
            store.resend(sent.append)
            self.assertEqual(sent, [gate.encode_decide_request(r) for r in (REQUEST, program, tenant)])
            self.assertEqual(store._db.execute("SELECT tenant, program, command_key, sent FROM commands ORDER BY rowid").fetchall(),
                             [("tenant", "program", "command", 1), ("other", "program", "command", 1), ("tenant", "other", "command", 1)])
            store.close()

    def test_a_command_row_without_its_tenant_or_program_is_refused_by_the_table(self):
        """Final review L4: an older writer cannot add a tenant-less command that no pinned payment could ever resend."""
        with tempfile.TemporaryDirectory() as tmp:
            store = self.store(Path(tmp) / "payer.db")
            for row in ((None, "program", "k"), ("tenant", None, "k"), ("tenant", "program", None)):
                with self.subTest(row=row), self.assertRaises(sqlite3.IntegrityError):
                    store._db.execute("INSERT INTO commands(tenant, program, command_key, request) VALUES(?,?,?,x'00')", row)
            store.close()

    def test_changed_member_key_under_reused_command_key_is_recorded_as_a_refusal(self):
        for sent in (False, True):
            with self.subTest(sent=sent), tempfile.TemporaryDirectory() as tmp:
                store = self.store(Path(tmp) / "payer.db")
                calls = []
                def transmit(data):
                    calls.append(data)
                    if not sent:
                        raise OSError("transport failed")
                if sent:
                    store.send(REQUEST, transmit)
                else:
                    with self.assertRaisesRegex(OSError, "transport failed"):
                        store.send(REQUEST, transmit)
                before = self.image(store)
                changed = replace(REQUEST, member_key=bytes([1]) * 32)
                with self.assertRaisesRegex(payer.GatePayerError, "^member_key_changed$"):
                    store.send(changed, calls.append)
                after = self.image(store)
                self.assertEqual([row[1:] for row in after["refusals"][len(before["refusals"]):]],
                                 [(REQUEST.tenant_id, REQUEST.program_id, REQUEST.payment_id, changed.member_key)])
                self.assertEqual({t: r for t, r in after.items() if t != "refusals"},
                                 {t: r for t, r in before.items() if t != "refusals"})
                self.assertEqual(calls, [gate.encode_decide_request(REQUEST)])
                store.close()

    def test_exact_retry_recovers_after_transport_failure_and_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payer.db"
            store = self.store(path)
            with self.assertRaises(OSError):
                store.send(REQUEST, lambda _: (_ for _ in ()).throw(OSError("lost")))
            store.close()
            store = self.store(path)
            sent = []
            store.resend(sent.append)
            store.send(REQUEST, sent.append)
            self.assertEqual(sent, [gate.encode_decide_request(REQUEST)])
            self.assertEqual(store._db.execute("SELECT request,sent FROM commands").fetchall(), [(sent[0], 1)])
            store.close()

    def test_interleaved_exact_deliveries_do_not_fail_the_sent_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payer.db"
            first, second = self.store(path), self.store(path)
            sent = []
            def deliver(data):
                sent.append(data)
                second.send(REQUEST, sent.append)
            first.send(REQUEST, deliver)
            self.assertEqual(sent, [gate.encode_decide_request(REQUEST)] * 2)
            self.assertEqual(first._db.execute("SELECT sent FROM commands").fetchall(), [(1,)])
            first.close()
            second.close()

    def test_competing_connection_cannot_replace_inflight_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payer.db"
            first, second = self.store(path), self.store(path)
            def deliver(_):
                with self.assertRaisesRegex(payer.GatePayerError, "command_conflict"):
                    second.send(replace(REQUEST, payment_id="other"), lambda _: self.fail("changed request sent"))
            first.send(REQUEST, deliver)
            self.assertEqual(first._db.execute("SELECT payment_id FROM pins").fetchall(), [(REQUEST.payment_id,)])
            self.assertEqual(first._db.execute("SELECT request,sent FROM commands").fetchall(),
                             [(gate.encode_decide_request(REQUEST), 1)])
            first.close()
            second.close()

    def test_newest_lookup_cost_does_not_grow_with_checkpoint_history(self):
        counts = []
        with tempfile.TemporaryDirectory() as tmp:
            store = self.store(Path(tmp) / "payer.db")
            for start, stop in ((0, 300), (300, 30000)):
                store._db.execute("BEGIN")
                store._db.executemany("INSERT INTO checkpoints VALUES(?,?,?,?,?,?,?,?,?)",
                    ((i.to_bytes(8, "big"), "tenant", i % 3, i // 100, 0, i, b"", b"", i) for i in range(start, stop)))
                store._db.execute("COMMIT")
                steps = [0]
                def tick():
                    steps[0] += 1
                    return 0
                store._db.set_progress_handler(tick, 1)
                try:
                    actual = store.newest_stored("tenant")
                finally:
                    store._db.set_progress_handler(None, 0)
                self.assertEqual(actual, {shard: (stop - 3 + shard).to_bytes(8, "big") for shard in range(3)})
                counts.append(steps[0])
            print(f"PAYER_NEWEST_LOOKUP rows=300,30000 sqlite_steps={counts}", flush=True)
            self.assertLessEqual(counts[1], counts[0] * 1.05)
            # The index is derived, not authority: rebuilding it leaves the answers unchanged.
            store._db.execute("DROP INDEX checkpoints_newest")
            store.close()
            store = self.store(Path(tmp) / "payer.db")
            self.assertEqual(store.newest_stored("tenant"), actual)
            store.close()


if __name__ == "__main__":
    unittest.main()
