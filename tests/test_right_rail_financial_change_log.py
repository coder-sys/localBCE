"""The cash-file checker's change log (lean-live-m3-v1.md 12.5, XI.2 record D): a write inside the file transaction that the file does not name
is refused by CashFileCheck.finish itself, and the log refuses at least what the two whole-table snapshots refused. ChangeLogCompareTests are
rr-core's, copied unchanged from branch hist-inc."""

import subprocess
import re
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_cash_file as cash_tests

H = expected.H_ITEM_ID


class ChangeLogCompareTests(unittest.TestCase):
    """Record D: a write inside the file transaction that the file does not name is refused by CashFileCheck.finish itself."""

    def setUp(self):
        self.files = cash_tests.ReceiverCashFileTests("test_preview_apply_retry_restart_and_reversal")
        self.files.setUp()
        self.addCleanup(self.files.doCleanups)

    def _inject(self, before_finish):
        """Run ``before_finish(connection)`` after every command wrote and before the checker's finish; the store must be unchanged
        and the refusal must come from finish (not from the owner's own checks)."""
        real, refused = check.CashFileCheck.finish, []

        def finish(instance, connection, results):
            before_finish(connection)
            try:
                return real(instance, connection, results)
            except check.CashFileError:
                refused.append(True)
                raise
        with patch.object(check.CashFileCheck, "finish", finish):
            self.files._unchanged(lambda: self.files._apply(), "^cash_file_failed$")
        self.assertEqual(refused, [True])

    @staticmethod
    def _replace_sql(table, where, column=None, value=None):
        """REPLACE one row by itself (it gets a new rowid), with ``column`` set to the SQL ``value`` if given."""
        columns = check.ledger.TABLE_COLUMNS[table]
        values = ",".join(value if name == column else name for name in columns)
        return f"REPLACE INTO {table}({','.join(columns)}) SELECT {values} FROM {table} WHERE {where}"

    def test_writes_the_file_does_not_name_are_refused(self):  # green on trunk (the snapshot compare); must stay green
        other = f"(SELECT obligation_id FROM obligations WHERE item_id<>'{H}' ORDER BY rowid LIMIT 1)"
        for label, sql in (
            ("an untouched obligation's row", f"UPDATE obligations SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={other}"),
            ("an untouched obligation's case", f"UPDATE cases SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={other}"),
            ("an earlier evaluation row", "UPDATE evaluations SET evaluated_at_ms=evaluated_at_ms+1 WHERE rowid=(SELECT min(rowid) FROM evaluations)"),
            ("an evidence row replaced with other content (REPLACE skips the UPDATE trigger)",
             self._replace_sql("evidence", "rowid=(SELECT min(rowid) FROM evidence)", "received_at_ms", "received_at_ms+1")),
        ):
            with self.subTest(write=label):
                self._inject(lambda connection, sql=sql: connection.execute(sql))

    def test_an_identical_replace_that_moves_a_row_is_refused(self):  # RED: the snapshot compare is keyed by content, not rowid
        self._inject(lambda connection: connection.execute(self._replace_sql("evidence", "rowid=(SELECT min(rowid) FROM evidence)")))

    def test_finish_takes_no_whole_table_snapshot(self):  # RED: trunk reads every package table twice (937 ms at E=8,500)
        with patch.object(check, "_snapshot", side_effect=AssertionError("whole-table snapshot"), create=True):
            self.assertEqual(self.files._apply()["recorded_count"], 2)

    def _log_triggers(self, connection):
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_temp_master WHERE type='trigger' AND name LIKE 'rr_cfc_%'")]
        self.assertEqual(len(names), 3 * len(check.ledger.PACKAGE_TABLES), "one checker log trigger per package table and operation")
        return names

    def test_a_dropped_log_trigger_or_recursive_triggers_off_is_refused(self):  # RED: no rr_cfc_* triggers on trunk
        self._inject(lambda connection: connection.execute(f"DROP TRIGGER temp.{self._log_triggers(connection)[0]}"))
        self._inject(lambda connection: (self._log_triggers(connection), connection.execute("PRAGMA recursive_triggers=OFF")))

    def test_the_owner_never_bypasses_triggers(self):  # green on trunk; the change log's premise (R24)
        for path in sorted(Path(owner.__file__).parent.rglob("*.py")):
            with self.subTest(path=path.name):
                self.assertIsNone(re.search(r"blobopen|writable_schema|\bVACUUM\b", path.read_text(encoding="utf-8"), re.IGNORECASE))


class ChangeLogDifferentialTests(unittest.TestCase):
    """TEMPORARY (delete once the lead has merged and reviewed the change log): on a corpus of writes a file does not name, the change log
    refuses with the same verdict as the two whole-table snapshots it replaced, read from commit 731421a (the trunk the change started on)."""

    def setUp(self):
        self.files = cash_tests.ReceiverCashFileTests("test_preview_apply_retry_restart_and_reversal")
        self.files.setUp()
        self.addCleanup(self.files.doCleanups)
        source = subprocess.run(["git", "show", "731421a:app/right_rail_financial_cash_file_independent.py"], cwd=Path(owner.__file__).parents[1], capture_output=True, check=True).stdout
        self.snapshots = ModuleType("snapshot_checker")
        exec(compile(source, "snapshot_checker", "exec"), self.snapshots.__dict__)

    def _verdict(self, module, sql):
        """What apply does when ``sql`` runs after every command wrote and before the checker's finish."""
        real = module.CashFileCheck.finish

        def finish(instance, connection, results):
            for statement in sql:
                connection.execute(statement)
            return real(instance, connection, results)
        with patch.object(check, "CashFileCheck", module.CashFileCheck), patch.object(module.CashFileCheck, "finish", finish):
            try:
                self.files._apply(self.prepared)
            except Exception as error:
                return type(error).__name__, str(error)
        return None

    def test_the_change_log_refuses_every_write_the_snapshots_refused(self):
        self.prepared = self.files._prepare()
        other = f"(SELECT obligation_id FROM obligations WHERE item_id<>'{H}' ORDER BY rowid LIMIT 1)"
        first = lambda table: f"rowid=(SELECT min(rowid) FROM {table})"
        replace = ChangeLogCompareTests._replace_sql
        refused = {  # both refuse, with the same verdict
            "obligation": f"UPDATE obligations SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={other}",
            "case": f"UPDATE cases SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={other}",
            "evaluation": f"UPDATE evaluations SET evaluated_at_ms=evaluated_at_ms+1 WHERE {first('evaluations')}",
            "payment": f"UPDATE payments SET amount_cents=amount_cents+1 WHERE {first('payments')}",
            "meta": "UPDATE financial_meta SET updated_at_ms=updated_at_ms+1",
            "evidence replaced": replace("evidence", first("evidence"), "received_at_ms", "received_at_ms+1"),
            "payment replaced": replace("payments", first("payments"), "amount_cents", "amount_cents+1"),
            "evidence inserted": f"INSERT INTO evidence SELECT 'evidence:extra',{','.join(check.ledger.TABLE_COLUMNS['evidence'][1:])} FROM evidence WHERE {first('evidence')}",
        }
        for label, sql in refused.items():
            with self.subTest(write=label):
                old = self._verdict(self.snapshots, [sql])
                self.assertIsNotNone(old, "the whole-table snapshots refuse it")
                self.assertEqual(self._verdict(check, [sql]), old)
        with self.subTest(write="an identical replace that moves a row"):  # the snapshots compare content and accept it; with recursive_triggers ON the owner's delete guard refuses it first
            self.assertEqual(self._verdict(check, [replace("evidence", first("evidence"))]), ("IntegrityError", "history_row_delete"))
