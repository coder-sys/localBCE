"""CFI begin reads by key (cfi-history-design-20261007 s2, C1). The oracle is today's begin, kept here whole: it loads every table and walks every event.
CORPUS replays 17 of the 56 ReceiverCashFileTests under it; each of the other 39 is in EXCLUDED with its reason, and a test that is in neither fails the module."""

from contextlib import closing, contextmanager
import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_cash_file_independent import _held, _matches, _fact, _recorded, _require, _table, ledger
from tests import test_right_rail_financial_acceptance as fixtures
from tests import test_right_rail_financial_cash_file as cash_tests

CORPUS = ("test_preview_apply_retry_restart_and_reversal", "test_mid_file_revision_and_action_refusals_refuse_a_file_that_is_not_absorbed_whole", "test_moved_baseline_keeps_retries_exact_and_a_row_at_its_revision_records",
          "test_planned_commit_equals_direct_for_an_overlapping_file_with_an_alias_row", "test_planned_commit_equals_direct_when_a_history_segment_seals_mid_file", "test_overlapping_file_records_new_rows_and_labels_repeats",
          "test_conflicting_reused_and_unknown_rows_are_held_with_their_class_and_a_prepared_row_at_its_revision_records", "test_repeat_of_a_reversed_payment_is_duplicate_only_if_it_predates_the_reversal",
          "test_linked_action_limit_and_ack_report_separation", "test_lost_response_recovers_without_new_cash", "test_a_plan_turns_only_refusals_into_a_refusal", "test_planned_commit_refuses_a_replayed_row_no_event_carries",
          "test_manifest_baseline_binds_digest_owner_and_the_live_chain",
          "test_owner_bugs_the_checker_would_only_find_on_open_refuse_before_commit", "test_planned_commit_refuses_rows_unlike_the_plan_in_any_table", "test_final_verifier_failure_and_duplicate_sql_write_roll_back",
          "test_concurrent_identical_files_commit_cash_once")  # the fault tests of the last four lines are compared too (review LOW-4)
_NO_BEGIN = "refused before any begin runs (census cfx1: 0 begins), so there is nothing to compare"
_CHILD = "runs the CLI or a child process; its begin runs outside this module's patch"
_TIMING = "asserts wall time, not behaviour; the old begin alone differs run to run"
_STALE = "stale-plan, busy or preview mechanics; every begin classifies only NEW rows of a fresh store (census cfx1), a kind the corpus already compares"
_MIXED = "context binding and stale-plan mechanics; its begins classify only NEW and RETRY rows, kinds the corpus already compares"
_BIG = "2,000 rows or the row caps, all NEW; the 499-key chunk is compared by the 500-row resend below"
EXCLUDED = {
    **dict.fromkeys(("test_a_crash_between_plan_and_commit_leaves_the_store_unchanged", "test_cli_apply_commits_an_empty_plan_for_a_resent_file_and_one_overtaken_by_the_same_file", "test_cli_binds_custom_live_and_test_identities_and_never_shadow",
                     "test_cli_exports_the_manifest_a_file_is_prepared_against", "test_cli_preview_apply_privacy_and_source_preservation", "test_cli_refusal_never_migrates_or_creates_store", "test_process_crash_before_and_after_commit"), _CHILD),
    **dict.fromkeys(("test_an_owner_write_without_a_checker_verifies_every_evaluated_obligation", "test_bounds_types_counts_origins_and_unsupported_formats", "test_checked_context_and_commands_are_immutable_copies", "test_evaluation_bindings_cite_only_the_items_own_evidence",
                     "test_evaluation_takes_exactly_one_evidence_source", "test_every_field_is_required_and_unknowns_refuse", "test_every_whole_store_rule_runs_before_commit_or_is_excused", "test_history_export_replaces_only_an_earlier_manifest_of_this_history_and_not_through_a_leftover",
                     "test_independent_commands_bind_every_field_order_and_type", "test_noncanonical_duplicate_keys_and_file_cap_refuse", "test_preview_cleanup_failure_cannot_publish_success", "test_refusals_are_fixed_classes"), _NO_BEGIN),
    **dict.fromkeys(("test_a_repeated_production_apply_is_idempotent", "test_quarter_end_file_within_writer_timeout", "test_quarter_end_planned_commit_within_s1_bound"), _TIMING),
    "test_a_raw_sqlite_error_on_apply_is_cash_file_failed_and_writes_nothing": "the old begin against itself gives different results from run to run; it still runs in its own module",
    **dict.fromkeys(("test_row_caps_and_maximum_width_file", "test_two_thousand_rows_in_files_within_writer_timeout_and_size"), _BIG),
    **dict.fromkeys(("test_a_different_writer_between_plan_and_commit_is_planned_again", "test_a_plan_is_stale_when_a_deadline_fell_between_its_clock_and_the_commit", "test_a_planned_commit_failing_mid_copy_writes_nothing", "test_a_stale_plan_is_made_again_and_commits_what_a_fresh_apply_commits",
                     "test_a_stale_plan_is_refused_and_a_current_one_commits", "test_a_stale_refusal_keeps_the_writer_and_a_moved_store_is_verified_again", "test_planned_commit_runs_the_checker_on_the_live_rows_inside_the_lock", "test_planned_commit_writes_the_store_and_receipt_a_direct_apply_writes",
                     "test_preview_refuses_a_copy_with_a_dangling_key_and_lives_beside_the_store", "test_preview_runs_the_owners_own_check_as_apply_does", "test_three_stale_plans_are_cash_file_busy_and_write_nothing"), _STALE),
    **dict.fromkeys(("test_a_plan_with_nothing_to_write_or_after_a_seal_is_stale", "test_external_context_and_baseline_cannot_be_rebound", "test_production_apply_never_runs_a_file_on_the_live_store"), _MIXED),
}


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


@contextmanager
def _nonunique():
    """Index set 4 with its two payload indexes made plain, in the owner and both checkers: a store forged under it holds what the real set refuses."""
    with patch.dict(owner._PRIVATE_INDEX_SETS, {4: tuple((*entry[:3], entry[3] and entry[4] is None, entry[4]) for entry in owner._PRIVATE_INDEX_SETS[4])}), \
            patch.dict(independent.PRIVATE_INDEX_DEFS, {4: {name: (table, keys, unique and where is None, where) for name, (table, keys, unique, where) in independent.PRIVATE_INDEX_DEFS[4].items()}}):
        yield


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

    def _send(self, fx, rows, capture):
        fx.baseline = fx._manifest()
        fx.source = {**fx.source, "capture_id": capture}
        try:
            fx._apply(fx._prepare({**fx.value, "source": fx.source, "row_count": len(rows), "total_cents": sum(row["amount_cents"] for row in rows), "rows": rows}))
        except (check.CashFileError, owner.FinancialError):
            pass  # a refused file is part of the log

    def _equal(self, scenario, kinds):
        before, after = _run(scenario, True), _run(scenario, False)
        self.assertEqual(len(before), len(after))
        for number, (old, new) in enumerate(zip(before, after)):
            self.assertEqual(old[:4], new[:4], number)
            self.assertEqual({name: value for name, value in old[4].items() if value != new[4][name]}.keys(), set(), (number, old[0]))
        seen = {kind for phase, _, plan, _, _ in after if phase == "begin" and plan for kind, _, _ in plan}
        self.assertLessEqual(kinds, seen)
        self.assertTrue(any(phase == "finish" and receipt for phase, _, _, receipt, _ in after))
        return after

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

            send = lambda rows, capture: self._send(fx, rows, capture)
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

    def _copy(self, fx):
        """A copy of the live store taken as it is, for a begin of its own."""
        path = fx.store.path.with_name("copy.sqlite")
        with closing(sqlite3.connect(fx.store.path.resolve().as_uri() + "?mode=ro", uri=True)) as live, closing(sqlite3.connect(path)) as target:
            live.backup(target)
        return path

    def _refused(self, fx, prepared, rule):
        """The store is refused, with `rule`, at every open: the checker on a copy, a new owner, and the private copy under apply_cash_file and preview_cash_file (which wraps every refusal as cash_file_failed), none reaching a begin."""
        with self.assertRaises(independent.IndependentFinancialError) as raised:
            independent.verify_database(self._copy(fx), expected_scope=fx.scope, expected_authority=owner._checker_authority(fx.fixture.authority))
        self.assertEqual(str(raised.exception), rule)
        image = fixtures._image(fx.store.path)
        with patch.object(check.CashFileCheck, "begin", autospec=True) as begin:
            for route in (lambda: cash.apply_cash_file(fx.store, *prepared), lambda: fx.fixture._make_owner(path=fx.store.path, clock=fx.store.clock)):
                with self.assertRaises(owner.FinancialIntegrityError) as raised:
                    route()
                self.assertEqual(str(raised.exception), "open_verification:" + rule)
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
                cash.preview_cash_file(*prepared, path=fx.store.path, trusted_authority=fx.fixture.authority, clock=fx.store.clock)
        self.assertEqual(begin.call_count, 0)
        self.assertEqual(fixtures._image(fx.store.path), image)

    def _tamper_e1(self, fx, store):
        """`store` appends PAYMENT_RECEIVED of file-payment-1 again, under ANOTHER obligation, by the owner's own event writer: hash chain, schema and digests intact, only the commands-log rule broken."""
        other = fx._query("SELECT obligation_id FROM obligations WHERE item_id<>? LIMIT 1", cash_tests.expected.H_ITEM_ID)[0][0]
        payload = json.loads(fx._query("SELECT payload_json FROM financial_events WHERE kind='PAYMENT_RECEIVED' LIMIT 1")[0][0])
        payload = {key: value for key, value in payload.items() if key != "rows" and not key.startswith("evaluation")}
        revision = fx._query("SELECT revision FROM obligations WHERE obligation_id=?", other)[0][0]
        with patch.object(owner.FinancialOwner, "_record_command", lambda *arguments, **keywords: None), store._write() as connection:
            owner.FinancialOwner._append_event(store, connection, aggregate_type="OBLIGATION", aggregate_id=other, kind="PAYMENT_RECEIVED", before_revision=revision, after_revision=revision, payload=payload, committed_at_ms=store._now())

    def test_e1_duplicate_received_other_obligation_refused_at_open(self):
        """E1 (design s4): the tamper of _tamper_e1, which index set 4 refuses at the insert, so it is forged under _nonunique. There the store is refused at
        every open and both begins refuse it: the keyed one reads both receipts by the payment id. Under the real set the same store is refused for its index,
        and a v3 copy of it is refused, unchanged, by the open that would upgrade it."""
        with _nonunique():
            fx = self._fixture()
            fx._apply()
            self._tamper_e1(fx, fx.store)
            fx.baseline = fx._manifest()
            prepared = fx._prepare()  # the same file again
            self._refused(fx, prepared, "commands:duplicate")
            path = self._copy(fx)
            self.assertEqual(self._raw_begin(fx, prepared, path, True), "cash_file_failed")
            self.assertEqual(self._raw_begin(fx, prepared, path, False), "cash_file_failed")
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^schema_private_indexes$"):
            fx.fixture._make_owner(path=path, clock=fx.store.clock)
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            for entry in owner._PRIVATE_INDEX_SETS[4][len(owner._PRIVATE_INDEX_SETS[3]):]:
                connection.execute(f'DROP INDEX "{entry[0]}"')
            connection.execute("DROP TABLE history_row_counts")
            connection.execute("PRAGMA user_version=3")
        image = fixtures._image(path)
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "^history_payload_unique$"):
            fx.fixture._make_owner(path=path, clock=fx.store.clock)
        self.assertEqual(fixtures._image(path), image)

    def test_e1_run_batch_on_an_owner_open_before_the_tamper_is_refused_and_writes_nothing(self):
        """The deferred re-verify path: owner A is open, a second owner writes the E1 tamper and moves the data version. A's run_batch re-verifies, defers the failure, runs the
        begin, which reads both receipts by the payment id and refuses first, so its own code is kept (_begin). (Direct run_batch by the tampering owner itself, whose mark
        did not move, answers RETRY with no money written: the accepted owner-wide limit.) Forged under _nonunique, as the test above."""
        with _nonunique():
            fx = self._fixture()
            fx._apply()
            with fx.fixture._make_owner(path=fx.store.path, clock=fx.store.clock) as second:
                self._tamper_e1(fx, second)
                first, fx.store = fx.store, second
                fx.baseline = fx._manifest()
                fx.store = first
            prepared, image = fx._prepare(), fixtures._image(first.path)
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
                fx._apply(prepared)
            self.assertEqual(fixtures._image(first.path), image)

    def test_e2_misfiled_alias_refused_at_open(self):
        """E2 (design s4): an alias confirmation filed, by the owner's own event writer, under the wrong obligation: hash chain, schema and digests intact, only the
        duplicate-evidence rule broken. Today's walk finds it anywhere (ALIAS); the keyed begin looks under the item's own obligation and holds the row as
        already_recorded, writing nothing. The store is refused at every open. C-L adds the payload-id uniqueness index."""
        fx = self._fixture()
        fx._apply()
        other = fx._query("SELECT obligation_id FROM obligations WHERE item_id<>? LIMIT 1", cash_tests.expected.H_ITEM_ID)[0][0]
        append = owner.FinancialOwner._append_event

        def misfiled(self, connection, **event):
            if event["kind"] == "PAYMENT_DUPLICATE_EVIDENCE":
                revision = connection.execute("SELECT revision FROM obligations WHERE obligation_id=?", (other,)).fetchone()[0]
                event = {**event, "aggregate_id": other, "before_revision": revision, "after_revision": revision}
            return append(self, connection, **event)
        with patch.object(owner.FinancialOwner, "_append_event", misfiled):
            fx.store.record_payment_evidence(item_id=cash_tests.expected.H_ITEM_ID, payment_id="alias-payment", common_origin_id="file-origin-1", amount_cents=100, evidence_id="alias-evidence",
                                             event_at_ms=cash_tests.expected.CASH_EVENT_MS, source_id="fictional-receiver", source_version="v1", local_ref="alias")
        self.assertEqual(fx._query("SELECT DISTINCT aggregate_id FROM financial_events WHERE kind='PAYMENT_DUPLICATE_EVIDENCE'"), [(other,)])
        fx._file_b([fx._row(2, 200, 1), {**fx._row(2, 100, 2), "payment_id": "alias-payment", "common_origin_id": "file-origin-1", "evidence_id": "alias-evidence"}])
        prepared = fx._prepare()
        self._refused(fx, prepared, "duplicate-evidence:binding")
        path = self._copy(fx)
        self.assertEqual(self._raw_begin(fx, prepared, path, True), ["RETRY", "ALIAS"])
        self.assertEqual(self._raw_begin(fx, prepared, path, False), "cash_file_failed")  # v4: the alias is read by its evidence id and bound to that evidence's item

    def test_a_forged_receipt_store_refuses_the_begin(self):
        """Review LOW-1/LOW-2, on a copy edited under the immutability trigger and (for the first case) without the unique index, as a raw edit of a file would be. A second
        receipt of one payment is refused, never silently overwriting the first. json_extract keys a payload on its FIRST payment_id and json.loads keeps its LAST: a
        payload repeating its key with another requested payment's id, or an unrequested one, is refused."""
        fx = self._fixture()
        fx._apply()
        prepared = fx._prepare()
        events = fx._query("SELECT event_sequence, payload_json FROM financial_events WHERE kind='PAYMENT_RECEIVED' ORDER BY event_sequence")
        first, second = (json.loads(payload)["payment_id"] for _, payload in events[:2])
        for label, last in (("a second receipt of the payment", None), ("another requested payment", second), ("an unrequested payment", "not-in-the-file")):
            with self.subTest(label):
                path = self._copy(fx)
                self.assertIsInstance(self._raw_begin(fx, prepared, path, False), list)  # the untouched copy is a clean RETRY plan
                with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                    connection.execute("DROP TRIGGER financial_event_update_immutable")
                    if last is None:
                        entry = owner._PRIVATE_INDEX_SETS[4][len(owner._PRIVATE_INDEX_SETS[3])]
                        connection.execute(f'DROP INDEX "{entry[0]}"')
                        connection.execute(owner._private_index_sql(*entry[:3], False, entry[4]))  # the same index, made plain
                        row = connection.execute("SELECT * FROM financial_events WHERE event_sequence=?", (events[0][0],)).fetchone()
                        copied = connection.execute("INSERT INTO financial_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (row[0] + 1000, bytes(row[1][:63]) + bytes([row[1][63] ^ 1]), *row[2:])).rowcount
                    else:
                        forged = events[0][1][:-1] + ',"payment_id":' + json.dumps(last) + "}"
                        copied = connection.execute("UPDATE financial_events SET payload_json=? WHERE event_sequence=?", (forged, events[0][0])).rowcount
                self.assertEqual(copied, 1)
                self.assertEqual(self._raw_begin(fx, prepared, path, False), "cash_file_failed")

    def test_every_route_into_begin_runs_the_whole_store_check_first(self):
        """The keyed reads trust the store's indexes (LOW-1, accepted design) because the whole-store check, whose PRAGMA integrity_check sees every index entry, has run on the
        file before each begin: apply_cash_file (on its private copy, then on the live store its owner opened under the check), run_batch(cash_file_context=...) on an owner
        opened under it, preview_cash_file (on a private copy). Forged stores are refused before any begin: test_e1 and test_e2. A raw edit of a file after the owner
        opened it is the owner-wide accepted limit, not a begin's."""
        real_check, real_begin = independent._verify_connection, check.CashFileCheck.begin
        where = lambda connection: connection.execute("PRAGMA database_list").fetchone()[2]
        for route, files in (("apply_cash_file", 2), ("run_batch", 1), ("preview_cash_file", 1)):
            with self.subTest(route):
                fx = self._fixture()
                prepared, log = fx._prepare(), []

                def checked(connection, *arguments, **keywords):
                    result = real_check(connection, *arguments, **keywords)
                    log.append(("check", where(connection)))
                    return result

                def begun(instance, connection):
                    log.append(("begin", where(connection)))
                    return real_begin(instance, connection)
                with patch.object(independent, "_verify_connection", checked), patch.object(check.CashFileCheck, "begin", begun), fx.fixture._make_owner(path=fx.store.path, clock=fx.store.clock) as store:
                    if route == "apply_cash_file":
                        cash.apply_cash_file(store, *prepared)
                    elif route == "run_batch":
                        fx._apply(prepared, store=store)
                    else:
                        cash.preview_cash_file(*prepared, path=store.path, trusted_authority=fx.fixture.authority, clock=store.clock)
                begins = [(number, entry[1]) for number, entry in enumerate(log) if entry[0] == "begin"]
                self.assertEqual(len({file for _, file in begins}), files)
                for number, file in begins:
                    self.assertIn(("check", file), log[:number])

    def test_a_resend_across_the_key_chunk_with_retry_overlap_and_alias_rows_equals_the_whole_history_begin(self):
        """500 rows (the file cap): more than the 499 two-column keys of one chunk. File 1 is all NEW; file 2 resends 160 of them (RETRY), names 340 stored origins under new payment and evidence ids (OVERLAP); file 3 sends file 2 again (RETRY and ALIAS).
        Rows 330..499 are the 2nd key chunk's (499 keys to a chunk): row 499 is OVERLAP in file 2 and ALIAS in file 3, found only by the 2-column lookup."""
        widest, find = [], check._find

        def spy(connection, table, columns, keys, where="", index=""):
            keys = list(keys)
            widest.append((len(columns), len({key for key in keys if None not in key})))
            return find(connection, table, columns, keys, where, index)

        def resend():
            fx = self._fixture()
            ids = fx._wide_store(600)
            first = fx._file_of(ids, check.MAX_ROWS, "m1")["rows"]
            self._send(fx, first, "c1")
            fresh = fx._file_of(ids, check.MAX_ROWS, "m2")["rows"]
            second = first[:160] + [{**fresh[number], "common_origin_id": first[number]["common_origin_id"]} for number in range(160, 500)]
            self._send(fx, second, "c2")
            self._send(fx, second, "c3")
        with patch.object(check, "_find", spy):
            log = self._equal(resend, {"NEW", "RETRY", "OVERLAP", "ALIAS"})
        plans = [plan for phase, _, plan, _, _ in log if phase == "begin"]
        self.assertEqual([plan[499][0] for plan in plans], ["NEW", "OVERLAP", "ALIAS"])
        self.assertTrue(any(columns == 2 and count > 499 for columns, count in widest), widest)

    def test_a_database_error_in_the_live_begin_rolls_back_and_writes_nothing(self):
        """The private copy's begin passes; the begin at commit_cash_plan, inside the live BEGIN IMMEDIATE, meets the error (the test above fails the copy's begin)."""
        fx = self._fixture()
        prepared, find = fx._prepare(), check._find
        live = str(fx.store.path.resolve())
        raised = []

        def failing(connection, *arguments, **keywords):
            if connection.execute("PRAGMA database_list").fetchone()[2] == live:
                raised.append(1)
                raise sqlite3.DatabaseError("malformed")
            return find(connection, *arguments, **keywords)
        image, continuity = fixtures._image(fx.store.path), fx.store.export_continuity()
        with patch.object(check, "_find", failing):
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
                cash.apply_cash_file(fx.store, *prepared)
        self.assertEqual(raised, [1])
        self.assertEqual((fixtures._image(fx.store.path), fx.store.export_continuity()), (image, continuity))
        self.assertEqual(fx._query("SELECT payment_id FROM payments WHERE payment_id LIKE 'file-%'"), [])
        self.assertEqual(cash.apply_cash_file(fx.store, *prepared)["recorded_count"], 2)  # the lock was released and the same file is still good

    def test_every_cash_file_test_is_compared_or_excluded_with_a_reason(self):
        names = set(unittest.TestLoader().getTestCaseNames(cash_tests.ReceiverCashFileTests))
        self.assertEqual(set(CORPUS) | set(EXCLUDED), names)
        self.assertEqual(set(CORPUS) & set(EXCLUDED), set())
        self.assertEqual(len(CORPUS), len(set(CORPUS)))


if __name__ == "__main__":
    unittest.main()
