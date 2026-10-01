"""Core R1a (rrb/archive/xi2-records-20261001.md "R1a"; red team rrb/reviews/core-r1-redteam.md H1, M1): one writer connection
holds a verified mark checked at every BEGIN. A commit it did not make means the store is verified again exactly as a
fresh open verifies it; a swapped file is store_replaced; any error discards the connection. R1c, R1d and R1b tests
are in commit 958947a (branch core-r1a) until their slices land.

Lock work is counted as SQLite VM steps (x100) run inside a transaction on connections made through
sqlite3.connect: deterministic, but blind to Python-side work, so the wall-time gates stay in the bench."""

from contextlib import closing, contextmanager
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as acceptance

FLAT = 1.25  # R1 gate: at most 25% more lock work after the unrelated history (docs/CORE_REDESIGN.md)
UNRELATED = ("item-01", "item-02", "item-03", "item-04")
CLAIM = "claim:obligation-item-h:offset-v1"
TAMPER = "UPDATE obligations SET received_cash_cents=received_cash_cents+1 WHERE item_id='item-06'"


def _pay(item, tag="x", amount=1):
    return {"item_id": item, "payment_id": f"{tag}-{item}-payment", "common_origin_id": f"{tag}-{item}-origin",
            "evidence_id": f"{tag}-{item}-evidence", "amount_cents": amount, "event_at_ms": expected.CASH_EVENT_MS}


def _foreign(path, sql, timeout=5.0):
    with closing(sqlite3.connect(str(path), timeout=timeout, isolation_level=None)) as other:
        other.executescript(sql)


def _grow(store, tag="", count=600):
    """Unrelated history on item-01..04 (M2): payments, conflicting repeats of a common origin, and reversals."""
    def payment(n, origin, amount):
        return ("record_payment_evidence", {"item_id": UNRELATED[origin % len(UNRELATED)], "payment_id": f"grow{tag}-payment-{n}",
                                            "common_origin_id": f"grow{tag}-origin-{origin}", "evidence_id": f"grow{tag}-evidence-{n}",
                                            "amount_cents": amount, "event_at_ms": expected.CASH_EVENT_MS})
    commands = []
    for n in range(count):
        if n % 10 == 8:
            commands.append(("reverse_payment", {"item_id": UNRELATED[(n - 8) % len(UNRELATED)], "payment_id": f"grow{tag}-payment-{n - 8}",
                                                 "evidence_id": f"grow{tag}-reversal-{n}"}))
        else:
            commands.append(payment(n, n - 7 if n % 10 == 9 else n, 2 if n % 10 == 9 else 1))
    for start in range(0, count, 300):
        store.run_batch(commands[start:start + 300])


class LockMeter:
    def __init__(self):
        self.steps = 0

    @contextmanager
    def watching(self):
        connect = sqlite3.connect  # the owner and adapter require plain sqlite3.Connection objects: no subclass

        def counted(*args, **kwargs):
            connection = connect(*args, **kwargs)
            connection.set_progress_handler(lambda: setattr(self, "steps", self.steps + connection.in_transaction), 100)
            return connection

        with patch.object(sqlite3, "connect", counted):
            yield self


class CoreR1aMarkTests(unittest.TestCase):
    def _fixture(self):
        fixture = acceptance.RightRailFinancialAcceptanceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)  # closes every owner _make_owner made, then the temp dir
        return fixture

    @contextmanager
    def _counting_verifies(self):
        calls, original = [], independent.verify_database_connection

        def counted(connection, **expectations):
            calls.append(1)
            return original(connection, **expectations)

        with patch.object(independent, "verify_database_connection", counted):
            yield calls

    def test_any_write_after_a_foreign_tamper_runs_the_full_verification_first(self):
        store = self._fixture()._build_base()
        _foreign(store.path, TAMPER)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^open_verification:"):
            store.record_payment_evidence(**_pay("item-05"))

    def test_a_tampered_store_is_refused_with_the_code_a_fresh_open_gives(self):
        for name, sql in {"meta": "UPDATE financial_meta SET owner_id='another-owner'", "obligation": TAMPER}.items():
            with self.subTest(name):
                fixture = self._fixture()
                store = fixture._build_base()
                _foreign(store.path, sql)
                with self.assertRaises(owner.FinancialError) as fresh:
                    fixture._make_owner(path=store.path, clock=store.clock)
                with self.assertRaises(owner.FinancialError) as write:
                    store.record_payment_evidence(**_pay("item-05"))
                self.assertEqual((type(write.exception), str(write.exception)), (type(fresh.exception), str(fresh.exception)))

    def test_an_export_after_a_foreign_tamper_is_refused(self):
        # A1 (M5): nothing leaves the state's boundary from history no full verification covers
        store = self._fixture()._build_base()
        _foreign(store.path, TAMPER)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^open_verification:"):
            store.export_continuity()

    def test_a_commit_by_a_second_owner_is_verified_before_the_next_write(self):
        fixture = self._fixture()
        store = fixture._build_base()
        second = fixture._make_owner(path=store.path, clock=store.clock)  # H2: until R2 a second process costs a full verify
        second.record_payment_evidence(**_pay("item-05"))
        with self._counting_verifies() as calls:
            self.assertIn("status", store.record_payment_evidence(**_pay("item-06")))
        self.assertGreaterEqual(len(calls), 1)

    def test_a_correction_after_a_foreign_tamper_is_refused_by_the_full_verification(self):
        fixture = self._fixture()
        store = fixture._build_base_for_correction()
        fixture._record_cash(store)
        fixture._record_claim(store)
        reopened = fixture._make_owner(path=store.path, clock=store.clock, correction_transition_release=store.correction_transition_release)
        _foreign(store.path, TAMPER)
        with self.assertRaises(owner.FinancialIntegrityError):  # its own snapshot check finds it first (decision 1)
            fixture._reject(reopened, CLAIM)

    def test_an_older_copy_restored_in_place_stays_refused(self):
        # M1: an older, internally consistent copy written over the live file is a rewind (III.6): every later
        # command and export is refused while the owner lives, not only the first (a restore has its own path)
        fixture = self._fixture()
        store = fixture._build_base()
        earlier = Path(tempfile.mkdtemp(dir=fixture.temp_dir.name)) / "earlier.sqlite"
        with closing(sqlite3.connect(str(store.path))) as live, closing(sqlite3.connect(str(earlier))) as copy:
            live.backup(copy)
        store.record_payment_evidence(**_pay("item-06"))
        with closing(sqlite3.connect(str(earlier))) as copy, closing(sqlite3.connect(str(store.path))) as live:
            copy.backup(live)  # same file, so only the history mark shows the rewind
        rewound = acceptance._image(store.path)
        for command in (lambda: store.record_payment_evidence(**_pay("item-05")),
                        lambda: store.record_payment_evidence(**_pay("item-04")), store.export_continuity):
            with self.assertRaisesRegex(owner.FinancialIntegrityError, "^store_replaced$"):
                command()
        self.assertEqual(acceptance._image(store.path), rewound)

    @unittest.skip("R1c: checker indexes")
    def test_first_write_after_open_lock_work_is_flat_in_history(self):
        fixture = self._fixture()
        store = fixture._build_base()
        measured = []
        for item in ("item-06", "item-05"):
            with LockMeter().watching() as meter:
                reopened = fixture._make_owner(path=store.path, clock=store.clock)
                meter.steps = 0  # the open itself is R1b
                reopened.record_payment_evidence(**_pay(item))
            measured.append(meter.steps)
            _grow(store, item)
        self.assertGreater(measured[0], 0, "no lock work was counted: connections must come from sqlite3.connect")
        self.assertLessEqual(measured[1], measured[0] * FLAT, f"lock work grew with unrelated history: {measured} (x100 VM steps)")

    def test_a_commit_after_the_verified_snapshot_is_never_inside_the_mark(self):
        # H1: the mark is read on the writer connection inside the verified transaction, so a commit that lands
        # after it (here: after the verify returns) moves data_version past the mark.
        fixture = self._fixture()
        store = fixture._build_base()
        wrote, original = [], independent.verify_database_connection

        def verify_then_tamper(connection, **expectations):
            result = original(connection, **expectations)
            if not wrote:
                try:
                    _foreign(store.path, TAMPER, timeout=0.5)
                    wrote.append(True)
                except sqlite3.OperationalError:
                    wrote.append(False)  # the verify held the lock (today, and R1 before R1b)
            return result

        with patch.object(independent, "verify_database_connection", verify_then_tamper):
            reopened = fixture._make_owner(path=store.path, clock=store.clock)
        if wrote == [True]:
            with self.assertRaisesRegex(owner.FinancialIntegrityError, "^open_verification:"):
                reopened.record_payment_evidence(**_pay("item-05"))
        else:
            self.assertEqual(wrote, [False])
            self.assertIn("status", reopened.record_payment_evidence(**_pay("item-05")))

    def test_a_failed_write_leaves_no_transaction_open_and_the_next_verifies_in_full(self):
        # M1: a persistent connection is discarded on any error, never left mid-transaction
        store = self._fixture()._build_base()
        store.record_payment_evidence(**_pay("item-06"))
        with self.assertRaises(owner.FinancialError):
            store.record_payment_evidence(**_pay("item-06", amount=2))  # same payment id, changed meaning
        _foreign(store.path, "BEGIN IMMEDIATE; ROLLBACK;", timeout=0.5)
        with self._counting_verifies() as calls:
            self.assertIn("status", store.record_payment_evidence(**_pay("item-05")))
        self.assertEqual(len(calls), 1)

    def test_close_is_idempotent_and_releases_the_store(self):
        fixture = self._fixture()
        base = fixture._build_base()
        base.close()
        path = base.path
        with fixture._make_owner(path=path, clock=base.clock) as store:
            store.record_payment_evidence(**_pay("item-06"))
        store.close()
        os.replace(path, Path(f"{path}.moved"))  # Windows refuses this while any handle is open


if __name__ == "__main__":
    unittest.main()
