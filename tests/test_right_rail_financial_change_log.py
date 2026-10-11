"""The cash-file checker's change log (lean-live-m3-v1.md 12.5, XI.2 record D): a write inside the file transaction that the file does not name
is refused by CashFileCheck.finish itself, however the log or the TEMP schema is tampered with."""

import re
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_cash_file as cash_tests

H = expected.H_ITEM_ID
OTHER = f"(SELECT obligation_id FROM main.obligations WHERE item_id<>'{H}' ORDER BY rowid LIMIT 1)"
WRITE = f"UPDATE main.obligations SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={OTHER}"  # only the log shows finish this row


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

    def _run(self, *statements):
        self._inject(lambda connection: [connection.execute(sql) for sql in statements])

    @staticmethod
    def _replace_sql(table, where, column=None, value=None):
        """REPLACE one row by itself (it gets a new rowid), with ``column`` set to the SQL ``value`` if given."""
        columns = check.ledger.TABLE_COLUMNS[table]
        values = ",".join(value if name == column else name for name in columns)
        return f"REPLACE INTO {table}({','.join(columns)}) SELECT {values} FROM {table} WHERE {where}"

    @classmethod
    def _past_the_owner(cls, table, where, column=None, value=None):
        """The REPLACE with the owner's own delete guard dropped first, so the refusal under test is finish's, not the owner's."""
        return (f'DROP TRIGGER temp."rr_track_{table}_DELETE"', cls._replace_sql(table, where, column, value))

    def test_writes_the_file_does_not_name_are_refused(self):  # green on trunk (the snapshot compare); must stay green
        for label, statements in (
            ("an untouched obligation's row", (WRITE,)),
            ("an untouched obligation's case", (f"UPDATE cases SET updated_at_ms=updated_at_ms+1 WHERE obligation_id={OTHER}",)),
            ("an earlier evaluation row", ("UPDATE evaluations SET evaluated_at_ms=evaluated_at_ms+1 WHERE rowid=(SELECT min(rowid) FROM evaluations)",)),
            ("an evidence row replaced with other content (REPLACE skips the UPDATE trigger)",
             self._past_the_owner("evidence", "rowid=(SELECT min(rowid) FROM evidence)", "received_at_ms", "received_at_ms+1")),
        ):
            with self.subTest(write=label):
                self._run(*statements)

    def test_an_identical_replace_that_moves_a_row_is_refused(self):  # RED: the snapshot compare is keyed by content, not rowid
        self._run(*self._past_the_owner("evidence", "rowid=(SELECT min(rowid) FROM evidence)"))

    def test_the_owner_refuses_a_replace_itself(self):  # with recursive_triggers ON the REPLACE's delete reaches the owner's guard
        def replace_then_bypass(connection):
            drop, replace = self._past_the_owner("evidence", "rowid=(SELECT min(rowid) FROM evidence)")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "^history_row_delete$"):
                connection.execute(replace)
            connection.execute(drop)
            connection.execute(replace)
        self._inject(replace_then_bypass)

    def test_finish_takes_no_whole_table_snapshot(self):  # every SELECT finish runs over a package table is filtered; COUNT(*) returns no row, control_packs is configuration the ledger reads whole
        real, statements = check.CashFileCheck.finish, []

        def finish(instance, connection, results):
            connection.set_trace_callback(statements.append)
            try:
                return real(instance, connection, results)
            finally:
                connection.set_trace_callback(None)
        with patch.object(check.CashFileCheck, "finish", finish):
            self.assertEqual(self.files._apply()["recorded_count"], 2)
        tables = check.ledger.PACKAGE_TABLES - {"control_packs"}
        scans = [sql for sql in statements if re.match(r"\s*SELECT\b(?!\s+COUNT\(\*\)\s+FROM)", sql) and not re.search(r"\bWHERE\b", sql)
                 and tables & set(re.findall(r"\b(?:FROM|JOIN)\s+(?:main\.)?(\w+)", sql))]
        self.assertIn("FROM main.obligations WHERE rowid=", "\n".join(statements))  # the trace saw finish's own reads
        self.assertEqual(scans, [])

    def _log_triggers(self, connection):
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_temp_master WHERE type='trigger' AND name LIKE 'rr_cfc_%'")]
        self.assertEqual(({name for (name,) in connection.execute("SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite~_%' ESCAPE '~'")}, len(names)), (logged := check.ledger.PACKAGE_TABLES | {"commands", "history_segments", "history_pending", "history_open", "history_row_counts"}, 3 * len(logged) + 3), "the store's tables are the package tables plus five named extras (an unexpected table fails); one log trigger per table and operation, three guarding the log")
        return names

    def test_a_dropped_log_trigger_or_an_unlogged_replace_delete_is_refused(self):  # recursive_triggers OFF: the REPLACE's delete is unlogged, the count refuses it
        self._inject(lambda connection: connection.execute(f"DROP TRIGGER temp.{self._log_triggers(connection)[0]}"))
        self._run("PRAGMA recursive_triggers=OFF", self._replace_sql("evidence", "rowid=(SELECT min(rowid) FROM evidence)"))

    def test_a_rewritten_log_is_refused(self):  # bypass (a): the log is append-only, whatever recursive_triggers is
        h = f"(SELECT min(rowid) FROM main.obligations WHERE item_id='{H}')"
        for label, statements in (
            ("deleted", ("DELETE FROM temp.rr_cfc_log WHERE tbl='obligations'",)),
            ("replaced", ("PRAGMA recursive_triggers=OFF", f"REPLACE INTO temp.rr_cfc_log SELECT id,tbl,op,{h},{h} FROM temp.rr_cfc_log WHERE tbl='obligations'", "PRAGMA recursive_triggers=ON")),
        ):
            with self.subTest(entry=label):
                self._run(WRITE, *statements)

    def test_a_log_trigger_dropped_and_recreated_is_refused(self):  # bypass (b): the TEMP schema cookie moves even when the SQL is identical
        def drop_write_recreate(connection):
            sql = connection.execute("SELECT sql FROM sqlite_temp_master WHERE name='rr_cfc_obligations_UPDATE'").fetchone()[0]
            for statement in ("DROP TRIGGER temp.rr_cfc_obligations_UPDATE", WRITE, sql.replace("CREATE TRIGGER", "CREATE TEMP TRIGGER", 1)):
                connection.execute(statement)
        self._inject(drop_write_recreate)

    def test_a_foreign_trigger_on_the_log_is_refused(self):  # bypass (c): any new TEMP object moves the cookie, whatever its name
        self._run("CREATE TEMP TRIGGER mute BEFORE INSERT ON rr_cfc_log BEGIN SELECT RAISE(IGNORE); END", WRITE)

    def test_a_temp_shadow_of_a_package_table_is_refused(self):  # bypass (d): finish reads main.<table>, and the new TEMP table moves the cookie
        columns = ",".join(check.ledger.TABLE_COLUMNS["obligations"])
        self._run("CREATE TEMP TABLE obligations AS SELECT * FROM main.obligations WHERE 0",
                  f"INSERT INTO temp.obligations(rowid,{columns}) SELECT rowid,{columns} FROM main.obligations", WRITE)

    def test_the_owner_never_bypasses_triggers(self):  # green on trunk; the change log's premises (R24), and the TEMP schema cookie finish compares is never reset
        for path in sorted(Path(owner.__file__).parent.rglob("*.py")):
            with self.subTest(path=path.name):
                self.assertIsNone(re.search(r"blobopen|writable_schema|\bVACUUM\b|PRAGMA\s+(\w+\.)?schema_version\s*=", path.read_text(encoding="utf-8"), re.IGNORECASE))
