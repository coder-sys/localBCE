"""Receiver-file binding, atomicity, replay, preview and recovery attacks."""

from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
import ast
import copy
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_owner_independent import verify_database
from tests import test_right_rail_financial_acceptance as fixtures
from tests import rightrail_financial_expected_cases as expected
from tools import right_rail_financial_cli as cli


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class ReceiverCashFileTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RightRailFinancialAcceptanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture._build_base()
        self.package = self.store.export_continuity()
        self.scope = json.loads(self.package)["scope"]
        self.baseline = self._manifest()
        self.source = {"source_id": "fictional-receiver", "version": "v1",
                       "receiver_system_id": "receiver-1", "capture_id": "capture-1",
                       "captured_at_ms": expected.CASH_EVENT_MS}
        self.value = {"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1",
                      "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": self.scope,
                      "source": self.source, "row_count": 2, "total_cents": 300,
                      "rows": [self._row(1, 100, 0), self._row(2, 200, 1)]}

    def _manifest(self):
        """The history-export manifest a cash file is prepared against (Phase 1b B). Exporting seals: never call it inside _unchanged."""
        return self.store.export_history(Path(tempfile.mkdtemp(dir=self.fixture.temp_dir.name)) / "history")

    def _row(self, number, amount, revision, prefix="file"):
        return {"item_id": expected.H_ITEM_ID, "payment_id": f"{prefix}-payment-{number}",
                "common_origin_id": f"{prefix}-origin-{number}", "evidence_id": f"{prefix}-evidence-{number}",
                "amount_cents": amount, "event_at_ms": expected.CASH_EVENT_MS,
                "pays_action_id": None, "expected_revision": revision}

    def _prepare(self, value=None, baseline=None):
        raw = canonical(self.value if value is None else value)
        baseline = self.baseline if baseline is None else baseline
        return cash.prepare_cash_file(
            raw, baseline, expected_source_sha256=sha(raw), expected_baseline_sha256=sha(baseline),
            expected_scope=self.scope, expected_source=self.source, expected_owner_id=self.store.owner_id,
            expected_mode=self.store.mode, trusted_authority=self.fixture.authority,
        )

    def _apply(self, prepared=None, store=None):
        commands, context = self._prepare() if prepared is None else prepared
        return (self.store if store is None else store).run_batch(commands, cash_file_context=context)

    def _unchanged(self, callback, code=""):
        before = self.store.export_continuity()
        with self.assertRaisesRegex((check.CashFileError, owner.FinancialError), code):
            callback()
        self.assertEqual(self.store.export_continuity(), before)

    def _query(self, sql, *parameters):
        with closing(sqlite3.connect(self.store.path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            return connection.execute(sql, parameters).fetchall()

    def test_preview_apply_retry_restart_and_reversal(self):
        prepared = self._prepare()
        live = fixtures._image(self.store.path)
        preview = cash.preview_cash_file(*prepared, path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)
        self.assertEqual((preview["contract"], preview["mode"], preview["cash_delta_cents"]), ("RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v2", "PREVIEW", 300))
        self.assertEqual((self.store.export_continuity(), fixtures._image(self.store.path)), (self.package, live))  # the preview ran on a copy
        applied = self._apply(prepared)
        self.assertEqual((applied["recorded_count"], applied["duplicate_count"], applied["cash_delta_cents"]), (2, 0, 300))
        self.assertEqual(applied["cash_after_cents"] - applied["cash_before_cents"], 300)
        committed = self.store.export_continuity()
        restarted = self.fixture._make_owner(path=self.store.path, clock=self.store.clock)
        retry = self._apply(prepared, restarted)
        self.assertEqual((retry["recorded_count"], retry["duplicate_count"], retry["cash_delta_cents"]), (0, 2, 0))
        self.assertEqual(restarted.export_continuity(), committed)
        restarted.reverse_payment(item_id=expected.H_ITEM_ID, payment_id="file-payment-1", evidence_id="reversal-1")
        reversed_state = restarted.export_continuity()
        retry = self._apply(prepared, restarted)
        self.assertEqual((retry["file_total_cents"], retry["duplicate_cents"], retry["cash_delta_cents"]), (300, 300, 0))
        self.assertEqual(restarted.export_continuity(), reversed_state)
        verified = verify_database(restarted.path, expected_scope=self.scope,
                                   expected_authority=owner._checker_authority(self.fixture.authority))
        self.assertEqual(verified["totals"]["received_cash_cents"], 200)

    def test_every_field_is_required_and_unknowns_refuse(self):
        for section in (None, "scope", "source", "row"):
            target = self.value if section is None else self.value["rows"][0] if section == "row" else self.value[section]
            for field in [*target, "unknown"]:
                value = copy.deepcopy(self.value)
                changed = value if section is None else value["rows"][0] if section == "row" else value[section]
                if field == "unknown":
                    changed[field] = "private-marker"
                else:
                    del changed[field]
                with self.subTest(section=section, field=field), self.assertRaises(check.CashFileError):
                    self._prepare(value)

    def test_bounds_types_counts_origins_and_unsupported_formats(self):
        mutations = [("row_count", 0), ("row_count", 1001), ("row_count", True),
                     ("total_cents", 301), ("total_cents", 2**63), ("total_cents", 300.0),
                     ("source_class", "MCO_REPORT"), ("contract", "X12-835"), ("contract", "X12-820"),
                     ("contract", "MMIS"), ("rows", []), ("rows", {})]
        for field, replacement in mutations:
            value = {**self.value, field: replacement}
            with self.subTest(field=field, replacement=replacement), self.assertRaises(check.CashFileError):
                self._prepare(value)
        for field, values in {"amount_cents": (0, -1, 2**63, True, 1.5),
                              "expected_revision": (-1, 10000, True), "event_at_ms": (-1, 2**63, True),
                              "pays_action_id": (False, "", "a" * 129), "payment_id": ("", "a" * 129, "bad id")}.items():
            for replacement in values:
                value = copy.deepcopy(self.value)
                value["rows"][0][field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(check.CashFileError):
                    self._prepare(value)
        for field in ("payment_id", "evidence_id", "common_origin_id"):
            value = copy.deepcopy(self.value)
            value["rows"][1][field] = value["rows"][0][field]
            with self.subTest(duplicate=field), self.assertRaises(check.CashFileError):
                self._prepare(value)

    def test_noncanonical_duplicate_keys_and_file_cap_refuse(self):
        commands, context = self._prepare()
        raw = context["source_bytes"]
        for bad in (raw + b"\n", b'{"rows":[],"rows":[]}', b"[" * 2000, b" " * (cash.MAX_FILE_BYTES + 1)):
            altered = {**context, "source_bytes": bad, "expected_source_sha256": sha(bad)}
            with self.subTest(size=len(bad)), self.assertRaises(check.CashFileError):
                check.CashFileCheck(commands, altered)
            with self.assertRaises(check.CashFileError):
                cash._propose(bad, self.baseline)

    def test_independent_commands_bind_every_field_order_and_type(self):
        commands, context = self._prepare()
        bad_lists = [commands[:-1], commands[::-1], commands + commands[:1],
                     [("acknowledge_action", dict(commands[0][1])), commands[1]]]
        for field in commands[0][1]:
            row = dict(commands[0][1])
            row[field] = True if type(row[field]) is int else "changed"
            bad_lists.append([(commands[0][0], row), commands[1]])
        for bad in bad_lists:
            with self.subTest(commands=bad):
                self._unchanged(lambda: self.store.run_batch(bad, cash_file_context=context))

    def test_external_context_and_baseline_cannot_be_rebound(self):
        commands, context = self._prepare()
        for field in ("expected_source_sha256", "expected_baseline_sha256", "expected_owner_id", "expected_mode"):
            with self.subTest(field=field):
                self._unchanged(lambda: self.store.run_batch(commands, cash_file_context={**context, field: "changed"}))
        for section in ("expected_scope", "expected_source", "expected_authority"):
            for field in context[section]:
                changed = {**context[section], field: "changed"}
                with self.subTest(section=section, field=field):
                    self._unchanged(lambda: self.store.run_batch(commands, cash_file_context={**context, section: changed}))
        self._apply((commands, context))
        rebased = self._prepare(baseline=self._manifest())
        self._unchanged(lambda: self._apply(rebased))

    def test_stale_baseline_and_mixed_retry_roll_back(self):
        commands, context = self._prepare()
        self.store.record_payment_evidence(**commands[0][1])
        self._unchanged(lambda: self._apply((commands, context)))
        self._unchanged(lambda: self._apply(self._prepare()))

    def test_mid_file_revision_and_action_errors_roll_back(self):
        for changes in ({"expected_revision": 0}, {"pays_action_id": "missing-action"}):
            value = copy.deepcopy(self.value)
            value["rows"][1].update(changes)
            with self.subTest(changes=changes):
                self._unchanged(lambda: self._apply(self._prepare(value)))

    def _file_of(self, items, count, prefix="file"):
        revisions = dict(self._query("SELECT item_id,revision FROM obligations WHERE period_id=?", self.scope["period_id"]))
        rows = []
        for number in range(count):
            item = items[number % len(items)]
            rows.append({**self._row(number, 1, revisions[item], prefix), "item_id": item})
            revisions[item] += 1
        return {**self.value, "source": self.source, "rows": rows, "row_count": count, "total_cents": count}

    def _wide_store(self, count=600):
        """A new store with the largest state's `count` hospitals as obligations, at the cash event time."""
        store = self.fixture._make_owner()
        pack = self.fixture._pack(expected.CONTROL_PACK_V1)
        store.publish_control_pack(pack)
        ids = sorted([expected.H_ITEM_ID] + [f"item-{number:04d}" for number in range(1, count)])
        manifest = self.fixture._population_manifest(member_ids=tuple(ids))
        store.register_population_manifest(manifest)
        items = tuple(owner.PopulationItem(population_id=expected.POPULATION_ONE_ID, item_id=item, display_label=f"Synthetic {item}", owed_cents=expected.OTHER_ITEM_CENTS,
                                           due_at_ms=expected.H_DUE_AT_MS, currency="USD") for item in ids)
        store.stage_population(population_id=expected.POPULATION_ONE_ID, manifest_id=manifest.manifest_id, pack_id=pack.pack_id,
                               cutoff_ms=expected.CONTROL_PACK_V1.effective_start_ms, inclusion_rules=("included:synthetic",),
                               expected_count=len(items), items=items, chunk_size=500)
        store.validate_population(expected.POPULATION_ONE_ID)
        store.publish_population(expected.POPULATION_ONE_ID)
        self.fixture._advance_clock(store, expected.CASH_EVENT_MS)
        self.store = store
        self.baseline = self._manifest()
        return ids

    def _timed_apply(self, prepared):
        """Apply; return the receipt and the seconds the outer write held the lock (connect, BEGIN IMMEDIATE .. COMMIT)."""
        seconds, original = [], self.store._write
        @contextmanager
        def timed(**kwargs):
            outer = getattr(self.store._batch, "connection", None) is None
            start = time.perf_counter()
            try:
                with original(**kwargs) as connection:
                    yield connection
            finally:
                if outer:
                    seconds.append(time.perf_counter() - start)
        with patch.object(self.store, "_write", timed):
            receipt = self._apply(prepared)
        return receipt, seconds[0]

    def _grammar_file(self, count, per_item):
        """The widest legal file: 128-character ids, the largest integers, every row linked to an action."""
        wide = lambda kind, number: f"{kind}-{number:06d}".ljust(128, "x")
        rows = [{"item_id": wide("item", number // per_item), "payment_id": wide("payment", number), "common_origin_id": wide("origin", number),
                 "evidence_id": wide("evidence", number), "amount_cents": (2**63 - 1) // count, "event_at_ms": 2**63 - 1,
                 "pays_action_id": wide("action", number), "expected_revision": 9999} for number in range(count)]
        return {**self.value, "source": self.source, "rows": rows, "row_count": count, "total_cents": sum(row["amount_cents"] for row in rows)}

    def test_row_caps_and_maximum_width_file(self):
        self.source = {**self.source, "captured_at_ms": 2**63 - 1}
        widest = self._grammar_file(check.MAX_ROWS, check.MAX_ITEM_ROWS)
        self.assertLessEqual(len(canonical(widest)), cash.MAX_FILE_BYTES)  # size at the maximum: ~0.83 MB, under 1 MiB
        commands, context = self._prepare(widest)
        self.assertEqual(len(check.CashFileCheck(commands, context).commands), check.MAX_ROWS)
        for count, per_item in ((check.MAX_ROWS + 1, 1), (2 * check.MAX_ITEM_ROWS, check.MAX_ITEM_ROWS + 1)):
            value = self._grammar_file(count, per_item)
            raw = canonical(value)
            with self.subTest(rows=count, per_item=per_item):
                with self.assertRaisesRegex(check.CashFileError, "^cash_file_row_cap$"):
                    self._prepare(value)
                with self.assertRaisesRegex(check.CashFileError, "^cash_file_row_cap$"):
                    check.CashFileCheck(commands, {**context, "source_bytes": raw, "expected_source_sha256": sha(raw)})

    def test_two_thousand_rows_in_files_within_writer_timeout_and_size(self):
        # docs/CORE_REDESIGN.md "Cash-file capacity": the largest state's month (~1,800 lines, taken as 2,000) as full files,
        # spread then concentrated. The manifest baseline stays constant and a preview is a copy plus one open verify.
        ids = self._wide_store()
        shapes = (ids, ids[:-(-check.MAX_ROWS // check.MAX_ITEM_ROWS)])
        for number in range(-(-2_000 // check.MAX_ROWS)):
            with self.subTest(file=number):
                self.source = {**self.source, "capture_id": f"capture-{number}"}
                value = self._file_of(shapes[number % 2], check.MAX_ROWS, prefix=f"month-1-file-{number}")
                self.assertLess(len(canonical(value)), cash.MAX_FILE_BYTES)
                self.assertLess(len(self.baseline), 4096)  # the manifest stays ~1.9 KB whatever the history
                prepared = self._prepare(value)
                live, start = fixtures._image(self.store.path), time.perf_counter()
                preview = cash.preview_cash_file(*prepared, path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)
                previewed = time.perf_counter() - start
                self.assertLess(previewed, 15.0)
                self.assertEqual((preview["recorded_count"], fixtures._image(self.store.path)), (check.MAX_ROWS, live))
                receipt, seconds = self._timed_apply(prepared)
                print(f"CASH1B_MONTH file={number} rows={check.MAX_ROWS} preview_seconds={previewed:.2f} lock_seconds={seconds:.2f}", flush=True)
                self.assertEqual((receipt["recorded_count"], receipt["cash_delta_cents"]), (check.MAX_ROWS, check.MAX_ROWS))
                self.assertLess(seconds, 5.0)
                self.baseline = self._manifest()
        history = Path(tempfile.mkdtemp(dir=self.fixture.temp_dir.name))
        self.store.export_history(history)
        self.assertLess(sum(path.stat().st_size for path in history.iterdir()), 24 * 1024 * 1024)

    def test_evaluation_bindings_cite_only_the_items_own_evidence(self):
        # batch-frames-v1 D4: bindings come from the item's evidence read in the same transaction.
        self._wide_store(3)  # the smallest fixture with a second item, which then holds evidence of its own
        self.store.record_payment_evidence(**{**self._row(9, 5, 0, "other"), "item_id": "item-0001", "pays_action_id": None})
        self.baseline = self._manifest()
        other = self._query("SELECT evidence_id FROM evidence WHERE item_id<>? ORDER BY evidence_id LIMIT 1", expected.H_ITEM_ID)[0][0]
        real = engine.evaluate_live
        def citing_foreign(*args, **kwargs):
            decided = real(*args, **kwargs)
            return dataclasses.replace(decided, evidence_ids=tuple(sorted((*decided.evidence_ids, other))))
        with patch.object(engine, "evaluate_live", citing_foreign):
            self._unchanged(lambda: self.store.run_batch(cash._propose(canonical(self.value), self.baseline)), "evaluation_evidence_missing")

    def test_evaluation_takes_exactly_one_evidence_source(self):
        for given in ({}, {"evidence_ids": [], "evidence_bindings": []}):
            with self.subTest(given=sorted(given)), self.assertRaisesRegex(owner.FinancialIntegrityError, "evaluation_evidence_source"):
                self.store._insert_evaluation(None, result={}, pack=None, authority_epoch=0, authority_digest=b"", **given)

    def test_quarter_end_file_within_writer_timeout(self):
        # A quarter's last file on 5,500 earlier payments (6,000 in all), applied through an already-open owner: the lock of a warm apply,
        # not of a fresh CLI open (its verify adds seconds, docs/CORE_REDESIGN.md "Cash-file capacity") or of one 84-item history.
        # If it fails, MAX_ROWS drops again (docs/CORE_REDESIGN.md "Cash-file capacity").
        ids = self._wide_store()
        shapes = (ids, ids[:-(-check.MAX_ROWS // check.MAX_ITEM_ROWS)])
        for number in range(6_000 // check.MAX_ROWS - 1):
            self.store.run_batch(cash._propose(canonical(self._file_of(shapes[number % 2], check.MAX_ROWS, prefix=f"seed-{number}")), self.baseline))
        self.baseline = self._manifest()
        prepared, verified, real = self._prepare(self._file_of(shapes[1], check.MAX_ROWS, prefix="quarter-end")), [], independent._verify_evaluation_row
        with patch.object(independent, "_verify_evaluation_row", lambda *args, **kwargs: verified.append(args[2]["obligation_id"]) or real(*args, **kwargs)):
            receipt, seconds = self._timed_apply(prepared)
        print(f"CASH1B_QUARTER_END rows={check.MAX_ROWS} lock_seconds={seconds:.2f}", flush=True)
        self.assertEqual(receipt["recorded_count"], check.MAX_ROWS)
        self.assertEqual(len(verified), len(set(verified)), "each touched obligation is verified once per write, not by both the checker and the owner")
        self.assertEqual(len(verified), len(shapes[1]))
        self.assertLess(seconds, 5.0)

    def test_an_owner_write_without_a_checker_verifies_every_evaluated_obligation(self):
        verified, real = [], independent._verify_evaluation_row
        with patch.object(independent, "_verify_evaluation_row", lambda *args, **kwargs: verified.append(args[2]["obligation_id"]) or real(*args, **kwargs)):
            self.store.run_batch(cash._propose(canonical(self.value), self.baseline))
        self.assertEqual(verified, [self._query("SELECT obligation_id FROM obligations WHERE item_id=?", expected.H_ITEM_ID)[0][0]])

    def test_preview_runs_the_owners_own_check_as_apply_does(self):
        # An evaluated obligation outside what the checker verified is the owner's to verify, in a preview as in an apply.
        finish, prepared = check.CashFileCheck.finish, self._prepare()
        unverified = lambda instance, connection, results: finish(instance, connection, results) and set()
        def failing(instance, connection, label, *obligation_ids):
            if obligation_ids:
                raise owner.FinancialIntegrityError("injected")
        with patch.object(check.CashFileCheck, "finish", unverified), patch.object(owner.FinancialOwner, "_verify_before_commit", failing):
            self._unchanged(lambda: self._apply(prepared), "^injected$|evaluation_verification")
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
                cash.preview_cash_file(*prepared, path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)

    def test_manifest_baseline_binds_digest_owner_and_the_live_chain(self):
        manifest = json.loads(self.baseline)

        def sealed(**changes):  # the manifest with its digest recomputed, as a forger would
            body = {key: value for key, value in {**manifest, **changes}.items() if key != "manifest_digest"}
            return canonical({**body, "manifest_digest": independent._digest(independent.SEGMENT_DOMAIN, b"manifest", canonical(body)).hex().upper()})
        foreign = sealed(meta={**manifest["meta"], "owner_id": "other-owner"})
        for change in ({"meta": {**manifest["meta"], "sequence": None}}, {"meta": {**manifest["meta"], "history_head": None}}, {"identity": {**manifest["identity"], "schema_version": 0}}):
            with self.subTest(change=list(change)), self.assertRaisesRegex(check.CashFileError, "^cash_file_(binding|format)$"):
                self._prepare(baseline=sealed(**change))  # the export verifier's own meta and identity checks, reused
        for change in ({"segment_count": manifest["segment_count"] + 1}, {"last_segment_digest": "AB" * 32}):  # sealed lies: the live history_segments row is the anchor
            with self.subTest(change=list(change)):
                self._unchanged(lambda: self._apply(self._prepare(baseline=sealed(**change))), "^cash_file_binding$")
        forged = sealed(meta={**manifest["meta"], "history_head": {"hex": "AB" * 32}})  # this sequence, another head
        for code, baselines in {"cash_file_format": (self.baseline + b"\n", canonical({**manifest, "segment_count": 99}), self.package), "cash_file_binding": (foreign,)}.items():
            for raw in baselines:
                with self.subTest(code=code, size=len(raw)), self.assertRaisesRegex(check.CashFileError, f"^{code}$"):
                    self._prepare(baseline=raw)
        self._unchanged(lambda: self._apply(self._prepare(baseline=forged)), "^cash_file_binding$")

    def test_preview_refuses_a_copy_with_a_dangling_key_and_lives_beside_the_store(self):
        folders, finishing, connect, finish = [], [], sqlite3.connect, check.CashFileCheck.finish
        class Dangling(sqlite3.Connection):  # a copy whose deferred keys COMMIT would refuse: the pragma reports one while the file is being finished
            def execute(self, sql, *arguments):
                return super().execute("SELECT 'payments',1,'obligations',0" if finishing and sql == "PRAGMA foreign_key_check" else sql, *arguments)
        def finishing_finish(instance, connection, results):
            finishing.append(1)
            try:
                return finish(instance, connection, results)
            finally:
                finishing.clear()
        commands, context = self._prepare()
        with patch.object(sqlite3, "connect", lambda *a, **k: connect(*a, **k, factory=Dangling)), patch.object(check.CashFileCheck, "finish", finishing_finish),                 self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
            cash.preview_cash_file(commands, context, path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)
        folder = self.store.path.with_name(self.store.path.name + ".cash-preview")
        stale, fresh = folder / "stale", folder / "fresh"
        stale.mkdir(), fresh.mkdir()
        old = time.time() - 7200
        os.utime(stale, (old, old))
        real = tempfile.TemporaryDirectory
        with patch.object(cash.tempfile, "TemporaryDirectory", lambda **kwargs: folders.append(kwargs["dir"]) or real(**kwargs)):
            self.assertEqual(cash.preview_cash_file(commands, context, path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)["mode"], "PREVIEW")
        self.assertEqual((folders, sorted(path.name for path in folder.iterdir())), ([folder], ["fresh"]))  # swept the crashed copy, kept a recent one, left none of its own

    def test_history_export_replaces_only_an_earlier_manifest_of_this_history_and_not_through_a_leftover(self):
        directory = Path(self.fixture.temp_dir.name) / "export"
        directory.mkdir()
        for foreign in (b"{}", canonical({**json.loads(self.baseline), "identity": {**json.loads(self.baseline)["identity"], "id": "other"}})):  # not an earlier export of this history
            (directory / "manifest.json").write_bytes(foreign)
            with self.assertRaisesRegex(owner.FinancialError, "history_export_mismatch"):
                self.store.export_history(directory)
            self.assertEqual((directory / "manifest.json").read_bytes(), foreign)
        (directory / "manifest.json").unlink()
        (directory / "manifest.json.tmp").write_bytes(b"leftover")
        self.assertEqual(self.store.export_history(directory), self.baseline)
        self.assertEqual((directory / "manifest.json").read_bytes(), self.baseline)
        self.assertEqual(self.store.export_history(directory), self.baseline)  # the same manifest again is accepted

    def test_concurrent_identical_files_commit_cash_once(self):
        prepared = self._prepare()
        second = self.fixture._make_owner(path=self.store.path, clock=self.store.clock)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self._apply, prepared, store) for store in (self.store, second)]
            receipts = [future.result(timeout=30) for future in futures]
        self.assertEqual(sorted(receipt["cash_delta_cents"] for receipt in receipts), [0, 300])
        self.assertEqual(self.store.obligation_detail(expected.H_ITEM_ID)["received_cash_cents"], 300)

    def test_linked_action_limit_and_ack_report_separation(self):
        self.store = self.fixture._build_base_for_correction()
        self.fixture._prepare_acknowledged(self.store)
        self.package, self.baseline = self.store.export_continuity(), self._manifest()
        detail = self.store.obligation_detail(expected.H_ITEM_ID)
        rows = [self._row(1, expected.CORRECTION_PAYMENT_CENTS - 1, detail["revision"]),
                self._row(2, 2, detail["revision"] + 1)]
        for row in rows:
            row["pays_action_id"] = detail["actions"][0]["action_id"]
            row["event_at_ms"] = expected.P2_EVENT_MS
        self.source = {**self.source, "captured_at_ms": expected.P2_EVENT_MS}
        self.value.update(source=self.source, rows=rows, total_cents=expected.CORRECTION_PAYMENT_CENTS + 1)
        self.fixture._advance_clock(self.store, expected.P2_EVENT_MS)
        self._unchanged(lambda: self._apply())
        self.value["rows"][1]["amount_cents"] = 1
        self.value["total_cents"] = expected.CORRECTION_PAYMENT_CENTS
        self.assertEqual(self._apply()["cash_delta_cents"], expected.CORRECTION_PAYMENT_CENTS)
        before, after = json.loads(self.package)["tables"], json.loads(self.store.export_continuity())["tables"]
        for table in ("actions", "action_outbox", "determinations"):
            self.assertEqual(after[table], before[table], table)
        reports = lambda tables: [row for row in tables["evidence"] if row["kind"].startswith("REPORT")]
        self.assertEqual(reports(after), reports(before))
        self.assertEqual(self.store.obligation_detail(expected.H_ITEM_ID)["reporting_complete"], detail["reporting_complete"])

    def test_overlapping_file_records_new_rows_and_labels_repeats(self):
        self._apply()  # file A: file-payment-1 (100) and file-payment-2 (200) on H, revisions 0 -> 2
        self.baseline = self._manifest()
        self.source = {**self.source, "capture_id": "capture-2"}
        repeat = {**self._row(4, 100, 3), "common_origin_id": "file-origin-1"}  # file B names payment 1 again under its own ids
        self.value = {**self.value, "source": self.source, "total_cents": 150, "rows": [self._row(3, 50, 2), repeat]}
        prepared = self._prepare()
        receipt = self._apply(prepared)
        self.assertEqual((receipt["recorded_count"], receipt["duplicate_count"], receipt["cash_delta_cents"], receipt["duplicate_cents"]), (1, 1, 50, 100))
        aliases = self._query("SELECT before_revision,after_revision,payload_json FROM financial_events WHERE kind='PAYMENT_DUPLICATE_EVIDENCE'")
        self.assertEqual([(before, after, {key: value for key, value in json.loads(payload).items() if key != "rows"}) for before, after, payload in aliases],
                         [(3, 3, {"candidate_evidence_id": "file-evidence-4", "existing_payment_id": "file-payment-1", "common_origin_id": "file-origin-1"})])
        self.assertEqual(self._query("SELECT local_ref FROM evidence WHERE evidence_id='file-evidence-4'"), [(prepared[0][1][1]["local_ref"],)])
        verified = verify_database(self.store.path, expected_scope=self.scope, expected_authority=owner._checker_authority(self.fixture.authority))
        self.assertEqual(receipt["cash_after_cents"], verified["totals"]["received_cash_cents"])
        committed = self.store.export_continuity()
        retry = self._apply(prepared)  # RETRY + ALIAS: nothing written (III.3)
        self.assertEqual((retry["recorded_count"], retry["duplicate_count"], retry["cash_delta_cents"]), (0, 2, 0))
        self.assertEqual(self.store.export_continuity(), committed)
        self.store.record_payment_evidence(**self._row(5, 7, 3, "later"), source_id="fictional-receiver", source_version="v1", local_ref="later")
        later = self.store.export_continuity()
        retry = self._apply(prepared)  # stale baseline: repeats only, still exact
        self.assertEqual((retry["duplicate_count"], retry["cash_delta_cents"]), (2, 0))
        self.assertEqual(self.store.export_continuity(), later)

    def test_conflicting_reused_and_stale_rows_refuse_with_their_class(self):
        stale = self._prepare({**self.value, "row_count": 1, "total_cents": 7, "rows": [self._row(7, 7, 2)]})  # a new row reviewed before file A
        self._apply()
        self.baseline = self._manifest()
        origin_1 = {"common_origin_id": "file-origin-1"}
        cases = {"cash_file_conflict": ({**self._row(4, 101, 2), **origin_1}, {**self._row(4, 100, 2), **origin_1, "pays_action_id": "action-x"}),
                 "cash_file_already_recorded": ({**self._row(1, 100, 0), "common_origin_id": "file-origin-9"}, {**self._row(4, 100, 2), "evidence_id": "file-evidence-1"})}
        for code, rows in cases.items():
            for row in rows:
                value = {**self.value, "row_count": 1, "total_cents": row["amount_cents"], "rows": [row]}
                with self.subTest(code=code, row=row):
                    self._unchanged(lambda: self._apply(self._prepare(value)), f"^{code}$")
        self._unchanged(lambda: self._apply(stale), "^cash_file_stale$")

    def _file_b(self, rows, captured_at_ms=None):
        self.baseline = self._manifest()
        self.source = {**self.source, "capture_id": "capture-2", "captured_at_ms": captured_at_ms or self.source["captured_at_ms"]}
        self.value = {**self.value, "source": self.source, "row_count": len(rows), "total_cents": sum(row["amount_cents"] for row in rows), "rows": rows}

    def test_repeat_of_a_reversed_payment_is_duplicate_only_if_it_predates_the_reversal(self):
        reversed_at = expected.CASH_EVENT_MS + 1_000
        for label, at, duplicate in (("at the reversal", reversed_at, True), ("after the reversal", reversed_at + 4_000, False)):
            for path in ("cash file", "owner command"):
                with self.subTest(repeat=label, path=path):
                    self.setUp()
                    self._apply()
                    self.fixture._advance_clock(self.store, reversed_at + 10_000)
                    self.store.reverse_payment(item_id=expected.H_ITEM_ID, payment_id="file-payment-1", evidence_id="reversal-1", event_at_ms=reversed_at)
                    revision = self.store.obligation_detail(expected.H_ITEM_ID)["revision"]
                    row = {**self._row(4, 100, revision), "common_origin_id": "file-origin-1", "event_at_ms": at}  # file-payment-1's origin again, new ids
                    if path == "cash file":
                        self._file_b([row], at)
                        if duplicate:
                            receipt = self._apply()
                            self.assertEqual((receipt["recorded_count"], receipt["duplicate_count"], receipt["cash_delta_cents"]), (0, 1, 0))
                            verify_database(self.store.path, expected_scope=self.scope, expected_authority=owner._checker_authority(self.fixture.authority))
                        else:
                            self._unchanged(lambda: self._apply(), "^cash_file_conflict$")
                    else:
                        command = lambda: self.store.record_payment_evidence(**{key: value for key, value in row.items() if key != "pays_action_id"}, source_id="fictional-receiver", source_version="v1", local_ref="direct")
                        if duplicate:
                            self.assertEqual(command()["status"], "DUPLICATE")
                        else:
                            self._unchanged(command, "^payment_origin_reversed$")

    def _refused_by(self, rule, callback):  # finish's pre-COMMIT check refuses in its fixed class; the spy names the one checker rule
        seen, real = [], independent.verify_obligation_connection

        def spy(*args, **kwargs):
            try:
                return real(*args, **kwargs)
            except independent.IndependentFinancialError as error:
                seen.append(str(error))
                raise
        with patch.object(independent, "verify_obligation_connection", spy):
            self._unchanged(callback, "^cash_file_failed$")
        self.assertEqual(seen, [rule])

    def test_owner_bugs_the_checker_would_only_find_on_open_refuse_before_commit(self):
        store, reject_b = self.fixture._two_claim_corrections(300_000, 300_000, unpaid_cents=600_000)  # S4: two requests, 600,000 owed; the owner forgets earlier linked payments and pays request A twice (300,001 cents)
        self.store = store
        reject_b()
        self.baseline = self._manifest()
        revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
        rows = [{**self._row(1, 300_000, revision), "pays_action_id": expected.ACTION_CORRECTION_ID, "event_at_ms": expected.P2_EVENT_MS}]
        rows.append({**self._row(2, 1, revision + 1), "pays_action_id": expected.ACTION_CORRECTION_ID, "event_at_ms": expected.P2_EVENT_MS})
        self.source = {**self.source, "captured_at_ms": expected.P2_EVENT_MS}
        self.value.update(source=self.source, row_count=2, rows=rows, total_cents=300_001)
        self.fixture._advance_clock(store, expected.P2_EVENT_MS)
        with patch.object(owner, "_correction_paid", lambda connection, obligation_id: []):
            self._refused_by("payment:link", lambda: self._apply())
        self.setUp()  # S5: an OVERLAP alias is stored with a wrong content digest
        self._apply()
        self._file_b([self._row(3, 50, 2), {**self._row(4, 100, 3), "common_origin_id": "file-origin-1"}])
        original = owner.FinancialOwner._insert_evidence
        def wrong_digest(instance, connection, evidence):
            return original(instance, connection, dataclasses.replace(evidence, content_digest=b"" * 64) if evidence.evidence_id == "file-evidence-4" else evidence)
        with patch.object(owner.FinancialOwner, "_insert_evidence", wrong_digest):
            self._refused_by("evidence:content-digest", lambda: self._apply())

    def test_every_whole_store_rule_runs_before_commit_or_is_excused(self):
        """A rule only the open check runs turns a bad write into a store that will not open (lean-live M0 F1, cash 1a F1)."""
        functions = {node.name: node for node in ast.walk(ast.parse(Path(independent.__file__).read_text(encoding="utf-8"))) if isinstance(node, ast.FunctionDef)}
        names = lambda name: {node.id for node in ast.walk(functions[name]) if isinstance(node, ast.Name)}
        reached, todo = set(), ["verify_obligation_connection"]  # the entry both pre-COMMIT paths (cash finish, correction) call
        while todo:
            if (current := todo.pop()) not in reached and current in functions:
                reached.add(current)
                todo += names(current)
        untouched = "no cash-file or correction write changes these rows (finish proves it for the cash file)"
        written = "cash file: finish chains every new event and compares each written row to its command"
        current = "the touched current evaluation and projection are recomputed; finish proves the cash deltas"
        excused = {**dict.fromkeys(("_verify_packs", "_verify_population_manifest_rows", "_verify_populations", "_verify_population_history", "_verify_program_funding", "_verify_adjustments", "_verify_current_snapshot", "_verify_restore_source_binding"), untouched),
                   **dict.fromkeys(("_verify_events", "_verify_payments", "_verify_conflicts", "_verify_duplicate_evidence", "_verify_event_references", "_verify_commands", "_verify_replayed_rows", "_verify_history_tables"), written),
                   **dict.fromkeys(("_verify_obligations", "_verify_evaluations", "_verify_evaluation_history_events", "_verify_projections"), current)}
        unreached = {name for name in names("_verify_connection") if name.startswith("_verify_") and name not in reached}
        self.assertEqual(sorted(unreached - set(excused)), [], "a whole-store rule that neither runs before commit nor has a written reason")
        self.assertEqual(sorted(set(excused) - unreached), [], "an excused rule that is now reachable or gone: delete its line")

    def test_refusals_are_fixed_classes(self):
        for error, code in ((check.CashFileError("cash_file_stale"), "cash_file_stale"), (check.CashFileError("private-marker"), "cash_file_failed"),
                            (owner.FinancialBusyError("private-marker"), "cash_file_busy"), (owner.FinancialRevisionError("private-marker"), "cash_file_stale"),
                            (owner.FinancialConflictError("private-marker"), "cash_file_conflict"), (owner.FinancialIntegrityError("private-marker"), "cash_file_failed"),
                            (OSError("private-path"), "cash_file_failed")):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(cash.refusal(error), code)
        for module in (cash, check):
            with self.subTest(module=module.__name__):
                self.assertLessEqual(set(re.findall(r'"(cash_file_[a-z_]+)"', Path(module.__file__).read_text())), check.REFUSALS)

    def test_final_verifier_failure_and_duplicate_sql_write_roll_back(self):
        prepared = self._prepare()
        original = check.CashFileCheck.finish
        def fail_after_verification(instance, *args):
            original(instance, *args)
            raise check.CashFileError("injected_final_failure")
        with patch.object(check.CashFileCheck, "finish", fail_after_verification):
            self._unchanged(lambda: self._apply(prepared))
        self._apply(prepared)
        seal = self.store._seal_segment
        def write_without_effect(connection, **kwargs):
            seal(connection, **kwargs)
            connection.execute("UPDATE financial_meta SET sequence=sequence")
        with patch.object(self.store, "_seal_segment", write_without_effect):
            self._unchanged(lambda: self._apply(prepared))

    def test_lost_response_recovers_without_new_cash(self):
        prepared = self._prepare()
        original = self.store._write
        @contextmanager
        def lose_response(**kwargs):
            outer = getattr(self.store._batch, "connection", None) is None
            with original(**kwargs) as connection:
                yield connection
            if outer:
                raise ConnectionError("simulated lost response")
        with patch.object(self.store, "_write", lose_response), self.assertRaises(ConnectionError):
            self._apply(prepared)
        before = self.store.export_continuity()
        self.assertEqual(self._apply(prepared)["cash_delta_cents"], 0)
        self.assertEqual(self.store.export_continuity(), before)

    def test_preview_cleanup_failure_cannot_publish_success(self):
        with patch.object(cash.tempfile.TemporaryDirectory, "__exit__", side_effect=OSError("private-path")):
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_failed$"):
                cash.preview_cash_file(*self._prepare(), path=self.store.path, trusted_authority=self.fixture.authority, clock=self.store.clock)
        self.assertEqual(self.store.export_continuity(), self.package)

    def _cli_fixture(self):
        directory = Path(self.fixture.temp_dir.name)
        files = {"receiver.json": canonical(self.value), "baseline.json": self.baseline,
                 "authority.json": canonical(cli.authority_file_record(self.fixture.authority))}
        for name, data in files.items():
            (directory / name).write_bytes(data)
        args = ["--database", str(self.store.path), "--authority-file", str(directory / "authority.json")]
        for key, value in self.scope.items():
            args += ["--" + key.replace("_", "-"), value]
        args += ["receiver-cash-file", "--file", str(directory / "receiver.json"),
                 "--baseline", str(directory / "baseline.json"), "--source-sha256", sha(files["receiver.json"]),
                 "--baseline-sha256", sha(self.baseline), "--owner-id", self.store.owner_id, "--mode", self.store.mode,
                 "--source-context", *map(str, self.source.values())]
        return directory, files, args

    def test_cli_refusal_never_migrates_or_creates_store(self):
        directory, _, args = self._cli_fixture()
        changes = [tuple(f"DROP TABLE {name}" for name in ("history_segments", "history_pending", "history_open")),
                   tuple(f'DROP TRIGGER "{name}"' for name in owner._HISTORY_APPEND_ONLY_TRIGGERS),
                   tuple(f'DROP INDEX "{name}"' for name, _, _ in owner._PRIVATE_INDEX_SETS[2]) + ("PRAGMA user_version=0",),
                   (f'DROP INDEX "{owner._PRIVATE_INDEX_SETS[2][-1][0]}"', "PRAGMA user_version=1")]  # L2: a v1 index set is never written
        for index, statements in enumerate(changes):
            path = directory / f"old-{index}.sqlite"
            path.write_bytes(fixtures._image(self.store.path))
            with sqlite3.connect(path) as connection:
                for statement in statements:
                    connection.execute(statement)
            before = fixtures._image(path)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--database", str(path), *args[2:], "--apply"]), 2)
            self.assertEqual(fixtures._image(path), before)
        path = directory / "disappearing.sqlite"
        path.write_bytes(fixtures._image(self.store.path))
        connect = owner.FinancialOwner._connect
        def disappear(instance, **kwargs):
            instance.path.unlink()
            return connect(instance, **kwargs)
        with patch.object(owner.FinancialOwner, "_connect", disappear):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--database", str(path), *args[2:], "--apply"]), 2)
        self.assertFalse(path.exists())

    def test_cli_binds_custom_live_and_test_identities_and_never_shadow(self):
        custom = owner.FinancialOwner(path=self.fixture._path(), config=self.store.config,
                                      trusted_authority=self.fixture.authority, owner_id="custom-owner", clock=self.store.clock)
        with patch.object(self.fixture, "_make_owner", return_value=custom):
            self.fixture._build_base()
        restores = [owner.FinancialOwner.restore_continuity(
            package_bytes=self.package, recovered_path=self.fixture._path(), trusted_authority=self.fixture.authority,
            restore_mode=mode, clock=self.store.clock) for mode in ("TEST", "SHADOW")]
        for store in (custom, *restores):
            self.addCleanup(store.close)  # R1a: an owner holds the store open until closed
            self.store = store
            self.package = store.export_continuity()
            if store.mode == "SHADOW":  # never a cash-file target (Phase 1b): the CLI has no such mode and the checker refuses it
                self.baseline = self._manifest()
                with self.assertRaisesRegex(check.CashFileError, "^cash_file_binding$"):
                    self._prepare()
                _, _, args = self._cli_fixture()
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main(args)
                self.assertEqual(store.export_continuity(), self.package)
                continue
            self.baseline = self._manifest()
            _, _, args = self._cli_fixture()
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(args + ["--apply"])
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertEqual(json.loads(stdout.getvalue())["cash_delta_cents"], 300)

    def test_checked_context_and_commands_are_immutable_copies(self):
        commands, context = self._prepare()
        checked = check.CashFileCheck(commands, context)
        context["expected_source"]["capture_id"] = "changed-after-check"
        with self.assertRaises(TypeError):
            checked.commands[0][1]["amount_cents"] = 999
        self.assertEqual(checked.commands[0][1]["amount_cents"], 100)
        self.assertEqual(checked._context["expected_source"]["capture_id"], "capture-1")
        self._unchanged(lambda: self._apply((commands, context)))

    def test_process_crash_before_and_after_commit(self):
        directory, files, args = self._cli_fixture()
        script = '''
import os, sys
from contextlib import contextmanager
sys.path.insert(0, sys.argv[1])
from app.right_rail_financial_owner import FinancialOwner
from tools.right_rail_financial_cli import main
phase = sys.argv[2]
original = FinancialOwner._write
@contextmanager
def crashing(self, **kwargs):
    outer = getattr(self._batch, "connection", None) is None
    with original(self, **kwargs) as connection:
        yield connection
        if outer and phase == "before":
            os._exit(73)
    if outer and phase == "after":
        os._exit(74)
FinancialOwner._write = crashing
raise SystemExit(main(sys.argv[3:]))
'''
        for phase, code in (("before", 73), ("after", 74)):
            result = subprocess.run([sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[1]),
                                     phase, *args, "--apply"], capture_output=True, timeout=45)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (code, b"", b""))
            restarted = self.fixture._make_owner(path=self.store.path, clock=self.store.clock)
            if phase == "before":
                self.assertEqual(restarted.export_continuity(), self.package)
            else:
                self.assertEqual(self._apply(store=restarted)["cash_delta_cents"], 0)
        self.assertEqual({name: (directory / name).read_bytes() for name in files}, files)

    def test_cli_exports_the_manifest_a_file_is_prepared_against(self):
        directory, _, args = self._cli_fixture()
        output, stdout = directory / "history", io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main([*args[:args.index("receiver-cash-file")], "export-history", "--output", str(output),
                                       "--owner-id", self.store.owner_id, "--mode", self.store.mode]), 0)
        manifest = (output / "manifest.json").read_bytes()
        self.assertEqual((json.loads(stdout.getvalue())["manifest_sha256"], manifest), (sha(manifest), self.baseline))  # nothing was written since setUp
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(args + ["--apply"]), 0)

    def test_cli_preview_apply_privacy_and_source_preservation(self):
        directory, files, args = self._cli_fixture()
        for apply in (False, True):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                if apply:
                    code = cli.main(args + ["--apply"])
                else:
                    with patch.object(cli, "_owner", side_effect=AssertionError("incumbent opened")):
                        code = cli.main(args)
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertEqual(json.loads(stdout.getvalue())["cash_delta_cents"], 300)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cli.main(args + ["--file", str(directory / "private-marker")]), 2)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", "ERROR:receiver_cash_file_refused:cash_file_input\n"))
        self.assertEqual({name: (directory / name).read_bytes() for name in files}, files)


if __name__ == "__main__":
    unittest.main()
