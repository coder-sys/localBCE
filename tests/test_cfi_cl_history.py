"""C-L1 (design rrb/state/cfi-cl-design-20261009.md s5): index set 4 (two partial UNIQUE payload indexes and
obligations(item_id)) and the committed history_row_counts. C-L2 adds test_python_max_history_le_lean_max_history and
test_store_wide_sites_use_max_history with the Lean maxHistory split."""

from contextlib import closing
import re
import sqlite3
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_intake as intake
from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_canonical_json import encode
from tests import test_right_rail_financial_acceptance as fixtures
from tests import test_right_rail_financial_cash_file as cash_tests

H = cash_tests.expected.H_ITEM_ID
V4 = owner._PRIVATE_INDEX_SETS[4][len(owner._PRIVATE_INDEX_SETS[3]):]
RECEIVED, ALIAS, ITEM = (entry[0] for entry in V4)
ENTRY = {entry[0]: entry for entry in V4}
V3 = (*(f'DROP INDEX "{name}"' for name in ENTRY), "DROP TABLE history_row_counts", "PRAGMA user_version=3")
COUNTED = ("financial_events", *sorted(independent.PROJECTION_TABLES))


def _forge(connection, kind, aggregate_id, payload_json=None):
    """A raw copy of the first `kind` event under `aggregate_id`, its payload (so its key) kept unless given."""
    return connection.execute(
        "INSERT INTO financial_events SELECT (SELECT MAX(event_sequence)+1 FROM financial_events),randomblob(64),aggregate_type,?,kind,before_revision,after_revision,"
        "COALESCE(?,payload_json),payload_digest,previous_head,head,committed_at_ms FROM financial_events WHERE kind=? ORDER BY event_sequence LIMIT 1",
        (aggregate_id, payload_json, kind),
    )


class _Crash(Exception):
    pass


class _Writes:
    """The migration's connection, counting its schema and counter writes; the `crash_after`-th raises once it has run."""

    def __init__(self, connection, crash_after=None):
        self._connection, self._crash_after, self.writes = connection, crash_after, []

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def _run(self, method, sql, *arguments):
        result = getattr(self._connection, method)(sql, *arguments)
        if sql.startswith(("CREATE", "INSERT", "PRAGMA user_version=")):
            self.writes.append(sql)
            if len(self.writes) == self._crash_after:
                raise _Crash(sql)
        return result

    def execute(self, sql, *arguments):
        return self._run("execute", sql, *arguments)

    def executemany(self, sql, *arguments):
        return self._run("executemany", sql, *arguments)


class HistoryIndexTests(unittest.TestCase):
    def setUp(self):
        self.fx = cash_tests.ReceiverCashFileTests("test_preview_apply_retry_restart_and_reversal")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx._apply()  # file-payment-1 and -2 received under item H's obligation

    def _other(self):
        return self.fx._query("SELECT obligation_id FROM obligations WHERE item_id<>? LIMIT 1", H)[0][0]

    def _alias(self, misfiled=False):
        """Item H's evidence alias-evidence repeats file-origin-1: one PAYMENT_DUPLICATE_EVIDENCE, filed by the owner's own writer (under another obligation if `misfiled`)."""
        append, other = owner.FinancialOwner._append_event, self._other()

        def write(store, connection, **event):
            if misfiled and event["kind"] == "PAYMENT_DUPLICATE_EVIDENCE":
                revision = connection.execute("SELECT revision FROM obligations WHERE obligation_id=?", (other,)).fetchone()[0]
                event = {**event, "aggregate_id": other, "before_revision": revision, "after_revision": revision}
            return append(store, connection, **event)
        with patch.object(owner.FinancialOwner, "_append_event", write):
            self.fx.store.record_payment_evidence(item_id=H, payment_id="alias-payment", common_origin_id="file-origin-1", amount_cents=100, evidence_id="alias-evidence",
                                                  event_at_ms=cash_tests.expected.CASH_EVENT_MS, source_id="fictional-receiver", source_version="v1", local_ref="alias")
        self.assertEqual(len(self.fx._query("SELECT 1 FROM financial_events WHERE kind='PAYMENT_DUPLICATE_EVIDENCE'")), 1)

    def _file(self, rows, capture):
        fx = self.fx
        fx.baseline, fx.source = fx._manifest(), {**fx.source, "capture_id": capture}
        return fx._prepare({**fx.value, "source": fx.source, "row_count": len(rows), "total_cents": sum(row["amount_cents"] for row in rows), "rows": rows})

    def _copy(self, label, statements=(), approved=None):
        """A copy of the live store with `statements` run; if `approved` names a v4 index, its sqlite_master text is then set back to the approved one."""
        path = self.fx.fixture._copy(f"{label}.sqlite", self.fx.store)
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            for statement in statements:
                connection.execute(statement)
            if approved is not None:
                connection.execute("PRAGMA writable_schema=ON")
                connection.execute("UPDATE sqlite_master SET sql=? WHERE name=?", (owner._private_index_sql(*ENTRY[approved]), approved))
        return path

    def _open(self, path):
        return self.fx.fixture._make_owner(path=path, clock=self.fx.store.clock)

    def _owner_refuses(self, path, code):
        image = fixtures._image(path)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, f"^{re.escape(code)}$"):
            self._open(path)
        self.assertEqual(fixtures._image(path), image)

    def _both_refuse(self, label, statements, rule, approved=None):
        """A writing owner refuses the copy unchanged (schema_private_indexes) and the checker refuses it with `rule`. Under the approved text
        (`approved`) the schema checks pass, and the index's entries, not its text, give it away: both refuse with schema:index-integrity."""
        path = self._copy(label, statements, approved)
        rule = rule if approved is None else "schema:index-integrity"
        self._owner_refuses(path, "schema_private_indexes" if approved is None else f"open_verification:{rule}")
        self.fx.fixture._assert_checker_refuses(path, self.fx.store, f"^{re.escape(rule)}$")

    def _counter(self, path=None):
        path = self.fx.store.path if path is None else path
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            return dict(connection.execute("SELECT table_name,n FROM history_row_counts").fetchall()), {table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in COUNTED}

    def _second_insert_refused(self, kind, index):
        for version, statements in (("v4", ()), ("v3", V3)):
            with closing(sqlite3.connect(str(self._copy(f"{version}-{kind}", statements)), isolation_level=None)) as connection:
                if version == "v4":
                    with self.assertRaisesRegex(sqlite3.IntegrityError, f"^UNIQUE constraint failed: index '{index}'$"):
                        _forge(connection, kind, self._other())
                else:  # the same insert lands where the index is absent: the index alone refuses it
                    self.assertEqual(_forge(connection, kind, self._other()).rowcount, 1)

    def test_v4_received_payment_unique_refuses_second_insert(self):
        self._second_insert_refused("PAYMENT_RECEIVED", RECEIVED)

    def test_v4_alias_evidence_unique_refuses_second_insert(self):
        self._alias()
        self._second_insert_refused("PAYMENT_DUPLICATE_EVIDENCE", ALIAS)

    def test_v4_unique_conflict_rolls_back_whole_write_typed(self):
        """A planner bypass: the third payment's receipt carries the first's payment id. The whole write rolls back typed (not absorbed as a row fault);
        the store, its user_version and counter are unchanged, and the same file lands once the writer is sound."""
        fx = self.fx
        prepared = self._file([fx._row(1, 100, 0), fx._row(2, 200, 1), fx._row(3, 50, 2)], "c2")
        append, image, counter = owner.FinancialOwner._append_event, fixtures._image(fx.store.path), self._counter()

        def bypass(store, connection, **event):
            if event["kind"] == "PAYMENT_RECEIVED" and event["payload"]["payment_id"] == "file-payment-3":
                event = {**event, "payload": {**event["payload"], "payment_id": "file-payment-1"}}
            return append(store, connection, **event)
        with patch.object(owner.FinancialOwner, "_append_event", bypass), self.assertRaisesRegex(owner.FinancialIntegrityError, "^history_payload_unique$"):
            fx._apply(prepared)
        self.assertEqual((fixtures._image(fx.store.path), self._counter(), fx._query("PRAGMA user_version")), (image, counter, [(4,)]))
        self.assertEqual(fx._apply(prepared)["recorded_count"], 1)

    def test_keyed_begin_refuses_misfiled_alias_in_session(self):
        """E2 in-session: one alias filed under another obligation by this owner's own writer. The keyed begin reads the alias by its evidence id,
        finds it bound to another item's obligation and refuses with its own code; the begin's deferred re-verify (duplicate-evidence:binding)
        then holds the owner refused. Nothing is written."""
        fx = self.fx
        self._alias(misfiled=True)
        prepared = self._file([fx._row(2, 200, 1), {**fx._row(2, 100, 2), "payment_id": "alias-payment", "common_origin_id": "file-origin-1", "evidence_id": "alias-evidence"}], "c2")
        image = fixtures._image(fx.store.path)
        with self.assertRaisesRegex((check.CashFileError, owner.FinancialError), "^cash_file_failed$"):
            fx._apply(prepared)
        self.assertEqual(fixtures._image(fx.store.path), image)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^open_verification:duplicate-evidence:binding$"):
            fx.store.export_continuity()

    def test_v4_index_plan_uses_expression_index(self):
        """The keyed begin's two reads (and an item-keyed obligations read, C2's) as _find sends them: the planner searches the v4 index (design R5)."""
        self._alias()
        with closing(sqlite3.connect(self.fx.store.path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            for index, read in (
                (RECEIVED, lambda: check._keyed(connection, RECEIVED, ["file-payment-1"])),
                (ALIAS, lambda: check._keyed(connection, ALIAS, ["alias-evidence"])),
                (ITEM, lambda: check._find(connection, "obligations", ("item_id",), [(H,)])),
            ):
                with self.subTest(index):
                    sent = []
                    connection.set_trace_callback(sent.append)
                    self.assertTrue(read())
                    connection.set_trace_callback(None)
                    (sql,) = sent
                    plan = [row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + sql, ["x"] * sql.count("?"))]
                    self.assertTrue(any(f"USING INDEX {index} " in detail for detail in plan), plan)

    def test_v4_dropped_unique_index_refused_at_open(self):
        for name in (RECEIVED, ALIAS):
            with self.subTest(name):
                self._both_refuse(f"dropped-{name}", (f'DROP INDEX "{name}"',), "schema:private-indexes")

    def test_v4_index_made_nonunique_refused(self):
        self._alias()
        for name in (RECEIVED, ALIAS):
            with self.subTest(name):  # (SQLite reads UNIQUE from this text: under the approved text the same entries are a unique index)
                self._both_refuse(f"nonunique-{name}", (f'DROP INDEX "{name}"', owner._private_index_sql(*ENTRY[name][:3], False, ENTRY[name][4])), f"schema:private-index:{name}")

    def test_v4_index_partial_where_changed_refused(self):
        self._alias()
        for name in (RECEIVED, ALIAS):
            table, (key,), unique, where = ENTRY[name][1:]
            variants = {
                "term-dropped": (owner._private_index_sql(name, table, (key,), unique, where.replace(" AND aggregate_type='OBLIGATION'", "")), None),
                "literal-case": (owner._private_index_sql(name, table, (key,), unique, where.replace("'PAYMENT_", "'payment_")), None),  # matches no event: the index is empty
                "column-key": (owner._private_index_sql(name, table, ("payload_json",), unique, where), name),  # the approved text over a column key
            }
            if name == ALIAS:  # only aliases carry candidate_evidence_id, so a whole-table UNIQUE index builds: the approved text over a non-partial index
                variants["not-partial"] = (owner._private_index_sql(name, table, (key,), unique, None), name)
            for label, (sql, approved) in variants.items():
                with self.subTest(name, label=label):
                    self._both_refuse(f"where-{label}-{name}", (f'DROP INDEX "{name}"', sql), f"schema:private-index:{name}", approved)

    def test_v4_item_index_dropped_or_reshaped_refused(self):
        self._both_refuse("item-dropped", (f'DROP INDEX "{ITEM}"',), "schema:private-indexes")
        for label, keys, approved in (("sql", ("item_id", "obligation_id"), None), ("keys", ("period_id",), ITEM)):
            with self.subTest(label):
                self._both_refuse(f"item-{label}", (f'DROP INDEX "{ITEM}"', owner._private_index_sql(ITEM, "obligations", keys, False, None)), f"schema:private-index:{ITEM}", approved)

    def test_v4_counter_tamper_refused_by_verify_database(self):
        self.assertIn("payments", COUNTED)
        for label, statement, rule in (
            ("events-minus", "UPDATE history_row_counts SET n=n-1 WHERE table_name='financial_events'", "rows:counter:financial_events"),
            ("events-plus", "UPDATE history_row_counts SET n=n+1 WHERE table_name='financial_events'", "rows:counter:financial_events"),
            ("payments-plus", "UPDATE history_row_counts SET n=n+1 WHERE table_name='payments'", "rows:counter:payments"),
            ("payments-real", "UPDATE history_row_counts SET n=n+0.5 WHERE table_name='payments'", "rows:counter:payments"),
            ("missing", "DELETE FROM history_row_counts WHERE table_name='payments'", "rows:counter:set"),
            ("extra", "INSERT INTO history_row_counts VALUES ('bogus',0)", "rows:counter:set"),
        ):
            with self.subTest(label):
                self.fx.fixture._assert_checker_refuses(self._copy(f"counter-{label}", (statement,)), self.fx.store, f"^{re.escape(rule)}$")
        self._owner_refuses(self._copy("counter-open", ("UPDATE history_row_counts SET n=n+1 WHERE table_name='payments'",)), "open_verification:rows:counter:payments")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK constraint failed"):
            self._copy("counter-negative", ("UPDATE history_row_counts SET n=-1 WHERE table_name='payments'",))

    def test_v4_counter_events_crosscheck_at_open(self):
        """With the checker's recount off and COUNT(*) forbidden, the open's O(1) cross-check (events n == MAX(event_sequence), the exact row set) refuses."""
        with patch.object(independent, "_verify_row_counts", lambda connection: None), patch.object(owner, "_count_rows", side_effect=AssertionError("COUNT(*) at open")):
            for label, statement in (
                ("plus", "UPDATE history_row_counts SET n=n+1 WHERE table_name='financial_events'"),
                ("minus", "UPDATE history_row_counts SET n=n-1 WHERE table_name='financial_events'"),
                ("missing", "DELETE FROM history_row_counts WHERE table_name='payments'"),
            ):
                with self.subTest(label):
                    self._owner_refuses(self._copy(f"crosscheck-{label}", (statement,)), "history_row_counts")
            self._open(self._copy("crosscheck-honest")).close()

    def test_v4_counter_equals_count_after_each_write(self):
        fx = self.fx
        self.assertEqual(*self._counter())
        retry = self._file([fx._row(1, 100, 0), fx._row(2, 200, 1)], "c2")

        def held():  # an absorbed file's row at a stale revision: the owner refuses it, it rolls back to rr_row alone, the INTAKE lands
            raw, baseline = encode({**fx.value, "source": fx.source, "row_count": 1, "total_cents": 50, "rows": [fx._row(3, 50, 0)]}), fx._manifest()
            receipt = intake.ingest_cash_file(fx.store, raw, baseline, expected_source_sha256=cash_tests.sha(raw), expected_baseline_sha256=cash_tests.sha(baseline), expected_scope=fx.scope,
                                              expected_source=fx.source, expected_owner_id=fx.store.owner_id, expected_mode=fx.store.mode, trusted_authority=fx.fixture.authority)
            self.assertEqual([(row["status"], row["basis"]) for row in receipt["rows"]], [("HELD", "obligation_revision_conflict")])
        arguments = {"item_id": H, "common_origin_id": "batch-origin", "amount_cents": 10, "event_at_ms": cash_tests.expected.CASH_EVENT_MS}
        refused = [("record_payment_evidence", {**arguments, "payment_id": "batch-payment-1", "evidence_id": "batch-evidence-1"}),
                   ("record_payment_evidence", {**arguments, "payment_id": "batch-payment-2", "common_origin_id": "batch-origin-2", "evidence_id": "batch-evidence-2", "expected_revision": 99})]
        with patch.object(owner, "_CHECK_ROW_CACHE", True):
            for label, write, moves in (("retry", lambda: fx._apply(retry), False), ("alias", self._alias, True), ("held-row", held, True),
                                        ("refused-batch", lambda: self.assertRaises(owner.FinancialRevisionError, fx.store.run_batch, refused), False)):
                with self.subTest(label):
                    before = self._counter()
                    write()
                    self.assertEqual(self._counter() != before, moves)
                    self.assertEqual(*self._counter())
        self.assertEqual(fx._query("SELECT payment_id FROM payments WHERE payment_id LIKE 'batch-%' OR payment_id='file-payment-3'"), [])

    def test_migrate_v3_to_v4_idempotent_and_crash_rolls_back(self):
        install = owner._install_private_index_set
        for label in ("tables", "checker"):  # below 4 the counter table is a refusal
            path = self._copy(f"v3-counter-{label}", V3[:-2] + V3[-1:])
            if label == "tables":
                self._owner_refuses(path, "schema_tables")
            else:
                self.fx.fixture._assert_checker_refuses(path, self.fx.store, "^schema:tables$")
        spy = []
        with patch.object(owner, "_install_private_index_set", lambda connection: spy.append(_Writes(connection)) or install(spy[-1])):
            self._open(self._copy("v3-count", V3)).close()
        steps = len(spy[0].writes)
        self.assertEqual(steps, len(V4) + 3, spy[0].writes)  # each index, the table, its rows, user_version
        for crash_after in range(1, steps + 1):
            with self.subTest(crash_after=crash_after):
                path = self._copy(f"v3-crash-{crash_after}", V3)
                image = fixtures._image(path)
                with patch.object(owner, "_install_private_index_set", lambda connection: install(_Writes(connection, crash_after))), self.assertRaises(_Crash):
                    self._open(path)
                self.assertEqual(fixtures._image(path), image)
        path = self._copy("v3-crash-after", V3)
        image = fixtures._image(path)
        with patch.object(owner, "_install_history_append_only", side_effect=_Crash), self.assertRaises(_Crash):
            self._open(path)  # a crash later in the same open transaction
        self.assertEqual(fixtures._image(path), image)
        spy.clear()
        with patch.object(owner, "_install_private_index_set", lambda connection: spy.append(_Writes(connection)) or install(spy[-1])):
            for _ in range(2):
                self._open(path).close()
        self.assertEqual([len(writes.writes) for writes in spy], [steps, 0])
        counter, rows = self._counter(path)
        self.assertEqual((counter, set(counter)), (rows, set(COUNTED)))
        with closing(sqlite3.connect(str(path))) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)

    def test_migrate_v3_store_with_e1_refused_typed_unchanged(self):
        self._alias()
        for label, kind, payload in (("received", "PAYMENT_RECEIVED", None), ("alias", "PAYMENT_DUPLICATE_EVIDENCE", None), ("malformed", "PAYMENT_RECEIVED", "{")):
            with self.subTest(label):
                path = self._copy(f"v3-e1-{label}", V3)
                with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
                    self.assertEqual(_forge(connection, kind, self._other(), payload).rowcount, 1)
                self._owner_refuses(path, "history_payload_unique")

    def test_old_reader_refuses_v4_without_mutation(self):
        """A v3-era Owner and checker, as their index constants: both fail closed before any write. (The real v3-era Owner refuses earlier still, at its
        table check: it knows no history_row_counts.)"""
        path = self._copy("v4-old-reader")
        with patch.object(owner, "_PRIVATE_INDEX_SETS", {version: entries for version, entries in owner._PRIVATE_INDEX_SETS.items() if version < 4}), patch.object(owner, "_PRIVATE_INDEX_SET_VERSION", 3):
            self._owner_refuses(path, "schema_private_indexes")
        image = fixtures._image(path)
        with patch.object(independent, "PRIVATE_INDEX_DEFS", {version: defs for version, defs in independent.PRIVATE_INDEX_DEFS.items() if version < 4}):
            self.fx.fixture._assert_checker_refuses(path, self.fx.store, "^schema:private-index-version$")
        self.assertEqual(fixtures._image(path), image)

    def test_shadow_open_keeps_v3(self):
        fx = self.fx
        path = fx.fixture._path("shadow-v3.sqlite")
        owner.FinancialOwner.restore_continuity(package_bytes=fx.store.export_continuity(), recovered_path=path, trusted_authority=fx.fixture.authority, clock=fixtures._Clock())
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            for statement in V3:
                connection.execute(statement)
        image = fixtures._image(path)
        owner.FinancialOwner(path=path, config=fx.store.config, trusted_authority=fx.fixture.authority, clock=fixtures._Clock(), mode="SHADOW", owner_id=owner._SHADOW_OWNER_ID).close()
        self.assertEqual(fixtures._image(path), image)
        with closing(sqlite3.connect(str(path))) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)


if __name__ == "__main__":
    unittest.main()
