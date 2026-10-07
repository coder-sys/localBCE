"""CFI begin reads by key (cfi-history-design-20261007 s2, C1). The oracle is today's begin, kept here whole: it loads every table and walks every event."""

from contextlib import closing
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_cash_file_independent import _held, _matches, _fact, _recorded, _require, _table, ledger
from tests import test_right_rail_financial_cash_file as cash_tests

CORPUS = ("test_preview_apply_retry_restart_and_reversal", "test_mid_file_revision_and_action_refusals_refuse_a_file_that_is_not_absorbed_whole", "test_moved_baseline_keeps_retries_exact_and_a_row_at_its_revision_records",
          "test_planned_commit_equals_direct_for_an_overlapping_file_with_an_alias_row", "test_planned_commit_equals_direct_when_a_history_segment_seals_mid_file", "test_overlapping_file_records_new_rows_and_labels_repeats",
          "test_conflicting_reused_and_unknown_rows_are_held_with_their_class_and_a_prepared_row_at_its_revision_records", "test_repeat_of_a_reversed_payment_is_duplicate_only_if_it_predates_the_reversal",
          "test_linked_action_limit_and_ack_report_separation", "test_lost_response_recovers_without_new_cash", "test_a_plan_turns_only_refusals_into_a_refusal", "test_planned_commit_refuses_a_replayed_row_no_event_carries",
          "test_manifest_baseline_binds_digest_owner_and_the_live_chain")


def _old_begin_and_classify(self, connection):
    """begin and _classify as they were before C1: whole tables, one walk of every event."""
    _require(self._connection is None and not self._finished and isinstance(connection, sqlite3.Connection) and connection.in_transaction, "cash_file_failed")
    self._counts = check._counts(connection)
    stored = {table: _table(connection, table) for table in ("financial_identity", "financial_meta", "financial_events", "payments", "evidence", "actions", "obligations", "cases")}
    rows = {table: list(values.values()) for table, values in stored.items()}
    index = lambda table, key: {row[key]: row for row in rows[table]}
    identity, sequence, head, count, last = self._anchor
    ancestor = rows["financial_identity"][0]["genesis_head"] if sequence == 0 else index("financial_events", "event_sequence").get(sequence, {}).get("head")
    sealed = connection.execute("SELECT last_sequence,segment_digest FROM main.history_segments WHERE segment_index=?", (count - 1,)).fetchone()
    _require(rows["financial_identity"] == identity and ancestor == head and ((count, last) == (0, ledger.ZERO_DIGEST.hex().upper()) if sealed is None else (sealed[0], bytes(sealed[1]).hex().upper()) == (sequence, last)), "cash_file_binding")
    if self.intake is not None:
        _require(connection.execute("SELECT 1 FROM financial_events WHERE aggregate_type='INTAKE' AND aggregate_id=?", (self.intake["source_sha256"],)).fetchone() is None, "cash_file_conflict")
    received, aliases = {}, {}
    for event in rows["financial_events"]:
        if event["kind"] in ("PAYMENT_RECEIVED", "PAYMENT_DUPLICATE_EVIDENCE"):
            payload = json.loads(event["payload_json"])
            if event["kind"] == "PAYMENT_DUPLICATE_EVIDENCE":
                aliases[payload["candidate_evidence_id"]] = payload["existing_payment_id"]
                continue
            _require(payload["payment_id"] not in received, "cash_file_failed")
            received[payload["payment_id"]] = (event, payload)
    payments, evidence, actions = index("payments", "payment_id"), index("evidence", "evidence_id"), index("actions", "action_id")
    origins = {(row["obligation_id"], row["common_origin_id"]): row for row in rows["payments"]}
    obligations = {row["item_id"]: row["obligation_id"] for row in rows["obligations"] if row["period_id"] == self._context["expected_scope"]["period_id"]}
    turn = {row["obligation_id"]: row["revision"] for row in rows["obligations"]}
    self._items = obligations
    plan = []
    for _, argument in self.commands:
        if argument["item_id"] not in obligations:
            plan.append(("HELD", None, _held(argument, "unknown_item")))
            continue
        obligation = obligations[argument["item_id"]]
        existing = origins.get((obligation, argument["common_origin_id"]))
        stored_evidence = evidence.get(argument["evidence_id"])
        restated = {**argument, "local_ref": stored_evidence["local_ref"]} if stored_evidence is not None else argument
        if argument["payment_id"] in payments:
            same = stored_evidence is not None and _recorded(restated, payments[argument["payment_id"]], stored_evidence, *received.get(argument["payment_id"], (None, None)), actions)
            kind, answer = ("RETRY", argument["payment_id"]) if same else ("already_recorded", None)
        elif existing is None:
            kind, answer = ("NEW", argument["payment_id"]) if stored_evidence is None else ("already_recorded", None)
        elif not (existing["amount_cents"] == argument["amount_cents"] and argument["pays_action_id"] in (None, received[existing["payment_id"]][1].get("pays_action_id"))
                  and (stored_evidence is not None or existing["active"] == 1 or argument["event_at_ms"] <= evidence[existing["reversed_by_evidence_id"]]["event_at_ms"])):
            kind, answer = "conflict", None
        elif stored_evidence is None:
            kind, answer = "OVERLAP", existing["payment_id"]
        else:
            same = aliases.get(argument["evidence_id"]) == existing["payment_id"] and _matches(stored_evidence, _fact(restated))
            kind, answer = ("ALIAS", existing["payment_id"]) if same else ("already_recorded", None)
        if kind == "OVERLAP" and argument["expected_revision"] != turn[obligation]:
            kind = "ALIAS"
        turn[obligation] += kind == "NEW"
        skip = {"status": "DUPLICATE", "payment_id": answer, "reason": None} if kind in ("RETRY", "ALIAS") else None if answer else _held(argument, kind)
        plan.append(("HELD" if answer is None else kind, answer, skip))
    self._plan = tuple(plan)
    self._received, self._meta, self._obligations, self._cases = received, next(iter(stored["financial_meta"].items())), stored["obligations"], stored["cases"]
    self._payments, self._actions = payments, actions
    self._arm(connection)
    self._connection = connection
    return [skip for _, _, skip in self._plan]


def _dump(connection):
    """Every main table, ORDER BY 1, hashed: rows, and with them the meta head and the event chain."""
    names = [name for (name,) in connection.execute("SELECT name FROM main.sqlite_master WHERE type='table' ORDER BY name")]
    return {name: hashlib.sha256(repr([tuple(row) for row in connection.execute(f"SELECT * FROM main.{name} ORDER BY 1")]).encode()).hexdigest() for name in names}


def _recorded_call(log, call, phase):
    def wrapper(self, connection, *args):
        outcome = None
        try:
            outcome = call(self, connection, *args)
            return outcome
        except Exception as error:
            outcome = type(error).__name__ + ":" + str(error)
            raise
        finally:
            log.append((phase, repr(sorted(outcome) if isinstance(outcome, set) else outcome), getattr(self, "_plan", None), self.receipt, _dump(connection)))
    return wrapper


def _run(scenario, old):
    """Every begin and finish a scenario makes: what each answers and the tables it leaves, with today's begin (old) or the keyed one."""
    log = []
    begin = check._fixed_errors(_old_begin_and_classify) if old else check.CashFileCheck.begin
    with patch.object(check.CashFileCheck, "begin", _recorded_call(log, begin, "begin")), patch.object(check.CashFileCheck, "finish", _recorded_call(log, check.CashFileCheck.finish, "finish")):
        scenario()
    return log


class KeyedBeginTests(unittest.TestCase):
    def _fixture(self):
        fx = cash_tests.ReceiverCashFileTests("test_preview_apply_retry_restart_and_reversal")
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        return fx

    def _equal(self, scenario, kinds):
        before, after = _run(scenario, True), _run(scenario, False)
        self.assertEqual(len(before), len(after))
        for number, (old, new) in enumerate(zip(before, after)):
            self.assertEqual(old[:4], new[:4], number)
            self.assertEqual({name: value for name, value in old[4].items() if value != new[4][name]}.keys(), set(), (number, old[0]))
        seen = {kind for phase, _, plan, _, _ in after if phase == "begin" and plan for kind, _, _ in plan}
        self.assertLessEqual(kinds, seen)
        self.assertTrue(any(phase == "finish" and receipt for phase, _, _, receipt, _ in after))

    def test_fault_corpus_equals_the_whole_history_begin(self):
        def corpus():
            result = unittest.TestResult()
            unittest.TestSuite(cash_tests.ReceiverCashFileTests(name) for name in CORPUS).run(result)
            self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
        self._equal(corpus, {"NEW", "RETRY", "OVERLAP", "ALIAS", "HELD"})

    def test_seeded_files_equal_the_whole_history_begin(self):
        def seeded():
            fx = self._fixture()
            ids = fx._wide_store(12)

            def send(rows, capture):
                fx.baseline = fx._manifest()
                fx.source = {**fx.source, "capture_id": capture}
                try:
                    fx._apply(fx._prepare({**fx.value, "source": fx.source, "row_count": len(rows), "total_cents": sum(row["amount_cents"] for row in rows), "rows": rows}))
                except (check.CashFileError, owner.FinancialError):
                    pass  # a refused file is part of the log
            first = fx._file_of(ids[:3], 9, "s1")["rows"]
            send(first, "c1")
            send(first, "c1b")  # the same rows again: RETRY
            mixed = fx._file_of(ids[:3], 7, "s3")["rows"]
            mixed[0] = first[0]  # RETRY
            mixed[1] = {**mixed[1], "common_origin_id": "s1-origin-1"}  # a stored origin again: OVERLAP
            mixed[2] = {**mixed[2], "common_origin_id": "s1-origin-2", "amount_cents": 5}  # a stored origin with another amount: conflict
            mixed[3] = {**mixed[3], "item_id": "item-not-in-period"}
            mixed[4] = {**mixed[4], "evidence_id": "s1-evidence-5"}  # a stored evidence id: already_recorded
            send(mixed, "c2")
            send(fx._file_of(ids[3:6], 12, "s4")["rows"], "c3")
            send(fx._file_of(ids[:6], 8, "s5")["rows"], "c4")
        self._equal(seeded, {"NEW", "RETRY", "OVERLAP", "HELD"})

    def test_a_lookup_that_raises_a_database_error_refuses_and_writes_nothing(self):
        fx = self._fixture()
        prepared = fx._prepare()
        for failure in (sqlite3.DatabaseError("malformed"), sqlite3.OperationalError("locked")):
            with patch.object(check, "_find", side_effect=failure):
                fx._unchanged(lambda: fx._apply(prepared), "^cash_file_failed$")
        self.assertEqual(fx._apply(prepared)["recorded_count"], 2)  # the same file is still good

    def _raw_begin(self, fx, prepared, path, old):
        """What a begin makes of the store copy at `path` inside its own BEGIN IMMEDIATE: the plan's kinds, or its refusal."""
        instance = check.CashFileCheck(*prepared)
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                (check._fixed_errors(_old_begin_and_classify) if old else check.CashFileCheck.begin)(instance, connection)
                return [kind for kind, _, _ in instance._plan]
            except check.CashFileError as error:
                return str(error)
            finally:
                connection.execute("ROLLBACK")

    def _tampered_copy(self, fx, *statements):
        """A copy of the live store with raw SQL run on it; open verification must refuse it."""
        path = fx.store.path.with_name("tampered.sqlite")
        with closing(sqlite3.connect(fx.store.path.resolve().as_uri() + "?mode=ro", uri=True)) as live, closing(sqlite3.connect(path)) as target:
            live.backup(target)
            for statement in statements:
                target.execute(statement)
            target.commit()
        with self.assertRaises(independent.IndependentFinancialError):
            independent.verify_database(path, expected_scope=fx.scope, expected_authority=owner._checker_authority(fx.fixture.authority))
        return path

    def test_e1_duplicate_received_other_obligation_refused_at_open(self):
        """E1 (design s4): a PAYMENT_RECEIVED of file-payment-1 filed again under ANOTHER obligation. Today's walk over every event refuses a file naming the
        payment; the keyed begin reads the payment's own obligation and answers RETRY. Open verification (and the foreign-commit verify) refuses the store.
        C-L adds the payload-id uniqueness index that makes it impossible."""
        fx = self._fixture()
        prepared = fx._prepare()
        fx._apply(prepared)
        other = fx._query("SELECT obligation_id FROM obligations WHERE item_id<>? LIMIT 1", cash_tests.expected.H_ITEM_ID)[0][0]
        path = self._tampered_copy(fx, "INSERT INTO financial_events SELECT event_sequence+1000, randomblob(64), 'OBLIGATION', '" + other + "', kind, before_revision, after_revision, payload_json, payload_digest, previous_head, head, committed_at_ms FROM financial_events WHERE kind='PAYMENT_RECEIVED' LIMIT 1")
        self.assertEqual(self._raw_begin(fx, prepared, path, True), "cash_file_failed")
        self.assertEqual(self._raw_begin(fx, prepared, path, False), ["RETRY", "RETRY"])

    def test_e2_misfiled_alias_refused_at_open(self):
        """E2 (design s4): an alias confirmation filed under the wrong obligation. Today's walk finds it anywhere (ALIAS); the keyed begin looks under the
        item's own obligation and holds the row as already_recorded, writing nothing. Open verification refuses the store. C-L adds the payload-id uniqueness index."""
        fx = self._fixture()
        fx._apply()
        fx._file_b([fx._row(3, 50, 2), {**fx._row(4, 100, 3), "common_origin_id": "file-origin-1"}])
        prepared = fx._prepare()
        fx._apply(prepared)
        other = fx._query("SELECT obligation_id FROM obligations WHERE item_id<>? LIMIT 1", cash_tests.expected.H_ITEM_ID)[0][0]
        path = self._tampered_copy(fx, "DROP TRIGGER financial_event_update_immutable", "UPDATE financial_events SET aggregate_id='" + other + "' WHERE kind='PAYMENT_DUPLICATE_EVIDENCE'")
        self.assertEqual(self._raw_begin(fx, prepared, path, True), ["RETRY", "ALIAS"])
        self.assertEqual(self._raw_begin(fx, prepared, path, False), ["RETRY", "HELD"])


if __name__ == "__main__":
    unittest.main()
