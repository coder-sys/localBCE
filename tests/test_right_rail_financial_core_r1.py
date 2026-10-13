"""Core R1a (rrb/archive/xi2-records-20261001.md "R1a"; red team rrb/reviews/core-r1-redteam.md H1, M1): one writer connection
holds a verified mark checked at every BEGIN. A commit it did not make means the store is verified again exactly as a
fresh open verifies it; a swapped file is store_replaced; any error discards the connection. R1c: the correction's
own checks cover every input it reads. R1d and R1b tests are in commit 958947a (branch core-r1a) until they land.

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
from tests.rightrail_intake_rows import pay
from tests import test_right_rail_financial_acceptance as acceptance

FLAT = 1.25  # R1 gate: at most 25% more lock work after the unrelated history (docs/CORE_REDESIGN.md)
UNRELATED = ("item-01", "item-02", "item-03", "item-04")
CLAIM = "claim:obligation-item-h:offset-v1"
H_OBLIGATION = "(SELECT obligation_id FROM obligations WHERE item_id='item-h')"
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
            calls.append(Path(connection.execute("PRAGMA database_list").fetchone()[2]).resolve())  # the file verified: a cash plan's private copy is not the store
            return original(connection, **expectations)

        with patch.object(independent, "verify_database_connection", counted):
            yield calls

    def test_any_write_after_a_foreign_tamper_runs_the_full_verification_first(self):
        store = self._fixture()._build_base()
        _foreign(store.path, TAMPER)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^open_verification:"):
            pay(store, **_pay("item-05"))

    def test_a_tampered_store_is_refused_with_the_code_a_fresh_open_gives(self):
        for name, sql in {"meta": "UPDATE financial_meta SET owner_id='another-owner'", "obligation": TAMPER}.items():
            with self.subTest(name):
                fixture = self._fixture()
                store = fixture._build_base()
                _foreign(store.path, sql)
                with self.assertRaises(owner.FinancialError) as fresh:
                    fixture._make_owner(path=store.path, clock=store.clock)
                with self.assertRaises(owner.FinancialError) as write:
                    pay(store, **_pay("item-05"))
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
        pay(second, **_pay("item-05"))
        with self._counting_verifies() as calls:
            self.assertIn("status", pay(store, **_pay("item-06")))
        self.assertGreaterEqual(len(calls), 1)

    def test_a_correction_after_a_foreign_tamper_is_refused_by_the_full_verification(self):
        fixture = self._fixture()
        store = fixture._build_base_for_correction()
        fixture._record_cash(store)
        fixture._record_claim(store)
        reopened = fixture._make_owner(path=store.path, clock=store.clock)
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
        pay(store, **_pay("item-06"))
        with closing(sqlite3.connect(str(earlier))) as copy, closing(sqlite3.connect(str(store.path))) as live:
            copy.backup(live)  # same file, so only the history mark shows the rewind
        rewound = acceptance._image(store.path)
        for command in (lambda: pay(store, **_pay("item-05")),
                        lambda: pay(store, **_pay("item-04")), store.export_continuity):
            with self.assertRaisesRegex(owner.FinancialIntegrityError, "^store_replaced$"):
                command()
        self.assertEqual(acceptance._image(store.path), rewound)

    @unittest.skip("R1c: the pre-commit evidence read stays NOT INDEXED (an index-only read is weaker); lead kept the full read 2026-10-03, gap 48-101 vs 60 recorded in 3409453")
    def test_first_write_after_open_lock_work_is_flat_in_history(self):
        fixture = self._fixture()
        store = fixture._build_base()
        measured = []
        for item in ("item-06", "item-05"):
            with LockMeter().watching() as meter:
                reopened = fixture._make_owner(path=store.path, clock=store.clock)
                meter.steps = 0  # the open itself is R1b
                pay(reopened, **_pay(item))
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
                pay(reopened, **_pay("item-05"))
        else:
            self.assertEqual(wrote, [False])
            self.assertIn("status", pay(reopened, **_pay("item-05")))

    def test_a_failed_write_leaves_no_transaction_open_and_the_next_verifies_in_full(self):
        # M1: a persistent connection is discarded on any error, never left mid-transaction
        store = self._fixture()._build_base()
        pay(store, **_pay("item-06"))
        with self.assertRaises(owner.FinancialError):
            store.record_payment_evidence(**_pay("item-06", amount=2))  # a write the owner refuses inside its transaction (intake would hold it)
        _foreign(store.path, "BEGIN IMMEDIATE; ROLLBACK;", timeout=0.5)
        with self._counting_verifies() as calls:
            self.assertIn("status", pay(store, **_pay("item-05")))
        self.assertEqual((calls.count(Path(store.path).resolve()), len(calls)), (1, 2))  # the store once, the cash plan's private copy once, no other

    def test_a_raw_page_edit_while_the_owner_is_open_is_not_committed_on_top_of(self):
        # safety red team S1: a byte edit of a payments page moves no data_version and the writer's cached pages may
        # still be the old ones, so the correction's pre-COMMIT check could pass on state the file no longer holds
        fixture = self._fixture()
        store = fixture._build_base_for_correction()
        fixture._record_cash(store)
        claim = fixture._record_claim(store)
        _foreign(store.path, "PRAGMA wal_checkpoint(TRUNCATE)")  # the page is in the main file, not only the WAL
        key = b"origin:cash:h:v1" + expected.H_CASH_CENTS.to_bytes(4, "big")  # a payments row ends origin, amount
        image = Path(store.path).read_bytes()
        self.assertEqual(image.count(key), 1)
        with open(store.path, "r+b") as raw:
            raw.seek(image.index(key) + len(key) - 1)
            raw.write(bytes([image[image.index(key) + len(key) - 1] ^ 1]))  # one cent more cash than the history holds
        outcome = "committed"
        try:
            fixture._reject(store, claim)
        except owner.FinancialError as refusal:
            outcome = str(refusal)
        self.assertNotEqual(outcome, "committed")
        with self.assertRaises(owner.FinancialIntegrityError):
            fixture._make_owner(path=store.path, clock=store.clock)  # a fresh open sees the edit either way

    def test_a_clock_step_ahead_is_refused_unwritten_and_writes_resume_when_it_is_corrected(self):
        # safety red team M1: one commit at a stepped clock made event_commit_order refuse every later write store-wide
        store = self._fixture()._build_base()
        wall, mono = [store.clock.value + 1_000], [0]  # ms; a wall step moves only `wall`
        store.clock = owner._SystemClock()
        with patch.object(owner.time, "time_ns", lambda: wall[0] * 1_000_000), patch.object(owner.time, "monotonic_ns", lambda: mono[0] * 1_000_000):
            pay(store, **_pay("item-05"))
            wall[0] += 60_000
            mono[0] += 60_000
            pay(store, **_pay("item-06"))  # normal running
            wall[0] += owner._CLOCK_SKEW_MS - 1  # a small skew inside the bound
            pay(store, **_pay("item-04"))
            wall[0] += 3_600_000  # an hour's step ahead
            before = acceptance._image(store.path)
            with self.assertRaisesRegex(owner.FinancialIntegrityError, "^clock_jump_ahead$"):
                pay(store, **_pay("item-03"))
            self.assertEqual(acceptance._image(store.path), before)
            wall[0] -= 3_600_000  # the clock is corrected
            self.assertIn("status", pay(store, **_pay("item-03")))

    def test_a_forward_clock_step_that_stays_put_is_accepted_after_the_lockstep_window(self):
        store = self._fixture()._build_base()
        wall, mono = [store.clock.value + 1_000], [0]
        store.clock = owner._SystemClock()
        with patch.object(owner.time, "time_ns", lambda: wall[0] * 1_000_000), patch.object(owner.time, "monotonic_ns", lambda: mono[0] * 1_000_000):
            pay(store, **_pay("item-05"))
            wall[0] += 3_600_000  # a step ahead that is never corrected
            for _ in range(2):
                with self.assertRaisesRegex(owner.FinancialIntegrityError, "^clock_jump_ahead$"):
                    pay(store, **_pay("item-06"))
                wall[0] += owner._CLOCK_SKEW_MS // 2
                mono[0] += owner._CLOCK_SKEW_MS // 2  # time passes in step, still inside the window
            wall[0] += 1
            mono[0] += 1
            self.assertIn("status", pay(store, **_pay("item-06")))  # held for the whole window: the new baseline
            wall[0] += 60_000
            mono[0] += 60_000
            self.assertIn("status", pay(store, **_pay("item-04")))

    def test_close_is_idempotent_and_releases_the_store(self):
        fixture = self._fixture()
        base = fixture._build_base()
        base.close()
        path = base.path
        with fixture._make_owner(path=path, clock=base.clock) as store:
            pay(store, **_pay("item-06"))
        store.close()
        os.replace(path, Path(f"{path}.moved"))  # Windows refuses this while any handle is open


class CoreR1cInputTests(unittest.TestCase):
    """R1c: the correction's per-obligation check covers every input it reads (conflicts, outbox acknowledgments,
    command rows; index-filtered scans), so a stale whole-store result cannot let a tamper through."""

    _fixture = CoreR1aMarkTests._fixture

    def _correction_ready(self):
        fixture = self._fixture()
        store = fixture._build_base_for_correction()
        fixture._record_cash(store)
        fixture._record_claim(store)
        return fixture, store

    def test_every_decision_input_is_rechecked_when_the_whole_store_result_is_stale(self):
        # H3: a stand-in returns the pre-tamper whole-store result; the correction's own checks must still refuse.
        # Tables with no item-h row at this point get a forged row; immutable ones must be refused by the store.
        forged_determination = f"INSERT INTO determinations VALUES ('forged-determination',{H_OBLIGATION},NULL,'x','x','x',1,zeroblob(64),'x',0,'[]',0,0,0,zeroblob(64),'forged-evaluation',zeroblob(64));"
        forged_action = f"INSERT INTO actions VALUES ('forged-action',{H_OBLIGATION},'forged-determination','x','READY',0,'{{}}',zeroblob(64),zeroblob(64),0);"
        tampers = {
            "none": None,
            "financial_meta": "UPDATE financial_meta SET continuity_epoch=continuity_epoch+1",
            "obligations": "UPDATE obligations SET received_cash_cents=received_cash_cents+1 WHERE item_id='item-h'",
            "evaluations": "UPDATE evaluations SET received_cash_cents=received_cash_cents+1 WHERE evaluation_id=(SELECT current_evaluation_id FROM obligations WHERE item_id='item-h')",
            "population_items": "UPDATE population_items SET owed_cents=owed_cents+1 WHERE item_id='item-h'",
            "population_imports": "UPDATE population_imports SET expected_count=expected_count+1",
            "control_packs": "UPDATE control_packs SET effective_end_ms=effective_end_ms+1",
            "payments": "UPDATE payments SET amount_cents=amount_cents+1 WHERE payment_id='payment:h:cash'",
            "claimed_adjustments": f"UPDATE claimed_adjustments SET amount_cents=amount_cents+1 WHERE claim_id='{CLAIM}'",
            "cases": f"INSERT INTO cases VALUES ('forged-case',{H_OBLIGATION},'x','x','x',0,'[]','OPEN',0)",
            "determinations": forged_determination,
            "actions": forged_determination + forged_action,
            "action_outbox": forged_determination + forged_action + "INSERT INTO action_outbox VALUES ('forged-action','ACKNOWLEDGED',1,zeroblob(64),'forged-ack',0);",
            "financial_conflicts": f"INSERT INTO financial_conflicts VALUES ('forged-conflict',{H_OBLIGATION},'origin:cash:h:v1','payment:h:cash','{expected.H_CASH_EVIDENCE.evidence_id}',1,2,'x',0)",
            "financial_events": f"INSERT INTO financial_events VALUES ((SELECT MAX(event_sequence)+1 FROM financial_events),zeroblob(64),'OBLIGATION',{H_OBLIGATION},'x',0,0,'{{}}',zeroblob(64),zeroblob(64),zeroblob(64),0)",
            "commands": f"INSERT INTO commands VALUES ('OFFSET_DECISION:{expected.ACTION_CORRECTION_ID}','OFFSET_DECISION','{{}}',zeroblob(64),999999)",
        }
        immutable = {
            "evidence": ("UPDATE evidence SET amount_cents=amount_cents+1 WHERE evidence_id='evidence:cash-h:9700000'", "evidence_record_immutable"),
            "financial_identity": ("UPDATE financial_identity SET bound_owner_id='x'", "financial_identity_immutable"),
        }
        for table, (sql, refusal) in immutable.items():
            with self.subTest(table=table):
                _, store = self._correction_ready()
                with self.assertRaisesRegex(sqlite3.DatabaseError, refusal):
                    _foreign(store.path, sql)
        owner_first = {"evaluations": "evaluation_result_digest", "control_packs": "control_pack_digest"}
        for table, sql in tampers.items():
            with self.subTest(table=table):
                fixture, store = self._correction_ready()
                with closing(sqlite3.connect(str(store.path), isolation_level=None)) as connection:
                    connection.row_factory = sqlite3.Row
                    connection.execute("BEGIN")
                    verified = independent.verify_database_connection(connection, **store._checker_expectations())
                    connection.execute("COMMIT")
                    before = connection.total_changes
                    connection.executescript(sql or "")
                    self.assertEqual(connection.total_changes > before, sql is not None)
                stand_in = []
                with patch.object(independent, "verify_database_connection", lambda connection, **_: stand_in.append(1) or verified):
                    if sql is None:
                        self.assertEqual(fixture._reject(store, CLAIM)["status"], "CORRECTION_AUTHORIZED")
                        continue
                    with self.assertRaises(owner.FinancialError) as refused:
                        fixture._reject(store, CLAIM)
                if table in owner_first:  # the Owner's own read refuses before the whole-store check is asked
                    self.assertEqual(str(refused.exception), owner_first[table])
                else:
                    self.assertTrue(stand_in, "the refusal must come after the stale whole-store result was used")


if __name__ == "__main__":
    unittest.main()
