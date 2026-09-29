"""Receiver-file binding, atomicity, replay, preview and recovery attacks."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
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
        self.baseline = self.store.export_continuity()
        self.scope = json.loads(self.baseline)["scope"]
        self.source = {"source_id": "fictional-receiver", "version": "v1",
                       "receiver_system_id": "receiver-1", "capture_id": "capture-1",
                       "captured_at_ms": expected.CASH_EVENT_MS}
        self.value = {"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1",
                      "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": self.scope,
                      "source": self.source, "row_count": 2, "total_cents": 300,
                      "rows": [self._row(1, 100, 0), self._row(2, 200, 1)]}

    def _row(self, number, amount, revision):
        return {"item_id": expected.H_ITEM_ID, "payment_id": f"file-payment-{number}",
                "common_origin_id": f"file-origin-{number}", "evidence_id": f"file-evidence-{number}",
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

    def _unchanged(self, callback):
        before = self.store.export_continuity()
        with self.assertRaises((check.CashFileError, owner.FinancialError)):
            callback()
        self.assertEqual(self.store.export_continuity(), before)

    def test_preview_apply_retry_restart_and_reversal(self):
        prepared = self._prepare()
        preview = cash.preview_cash_file(*prepared, trusted_authority=self.fixture.authority, clock=self.store.clock)
        self.assertEqual(preview["mode"], "PREVIEW")
        self.assertEqual(preview["cash_delta_cents"], 300)
        self.assertEqual(self.store.export_continuity(), self.baseline)
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
        self._unchanged(lambda: self._apply(self._prepare(baseline=self.store.export_continuity())))

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

    def test_thousand_rows_and_maximum_grammar_values(self):
        value = copy.deepcopy(self.value)
        value["rows"] = [self._row(i, 1, i) for i in range(1000)]
        value.update(row_count=1000, total_cents=1000)
        commands, context = self._prepare(value)
        self.assertEqual(len(check.CashFileCheck(commands, context).commands), 1000)
        value.update(row_count=1, total_cents=2**63 - 1)
        value["rows"] = [self._row(1, 2**63 - 1, 9999)]
        value["rows"][0]["payment_id"] = "a" * 128
        self.assertEqual(self._prepare(value)[0][0][1]["amount_cents"], 2**63 - 1)

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
        self.baseline = self.store.export_continuity()
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
        before, after = json.loads(self.baseline)["tables"], json.loads(self.store.export_continuity())["tables"]
        for table in ("actions", "action_outbox", "determinations"):
            self.assertEqual(after[table], before[table], table)
        reports = lambda tables: [row for row in tables["evidence"] if row["kind"].startswith("REPORT")]
        self.assertEqual(reports(after), reports(before))
        self.assertEqual(self.store.obligation_detail(expected.H_ITEM_ID)["reporting_complete"], detail["reporting_complete"])

    def test_alias_and_conflict_statuses_roll_back_whole_file(self):
        self.store.record_payment_evidence(**self._prepare()[0][0][1])
        baseline = self.store.export_continuity()
        for amount in (100, 101):
            value = copy.deepcopy(self.value)
            value["rows"] = [self._row(3, 200, 1), {**self._row(4, amount, 2), "common_origin_id": "file-origin-1"}]
            value["total_cents"] = 200 + amount
            with self.subTest(amount=amount):
                self._unchanged(lambda: self._apply(self._prepare(value, baseline)))

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
            with self.assertRaisesRegex(check.CashFileError, "^cash_file_preview_failed$"):
                cash.preview_cash_file(*self._prepare(), trusted_authority=self.fixture.authority, clock=self.store.clock)
        self.assertEqual(self.store.export_continuity(), self.baseline)

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
                   tuple(f'DROP INDEX "{name}"' for name, _, _ in owner._PRIVATE_INDEX_SETS[2]) + ("PRAGMA user_version=0",)]
        for index, statements in enumerate(changes):
            path = directory / f"old-{index}.sqlite"
            path.write_bytes(self.store.path.read_bytes())
            with sqlite3.connect(path) as connection:
                for statement in statements:
                    connection.execute(statement)
            before = path.read_bytes()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--database", str(path), *args[2:], "--apply"]), 2)
            self.assertEqual(path.read_bytes(), before)
        path = directory / "disappearing.sqlite"
        path.write_bytes(self.store.path.read_bytes())
        connect = owner.FinancialOwner._connect
        def disappear(instance, **kwargs):
            instance.path.unlink()
            return connect(instance, **kwargs)
        with patch.object(owner.FinancialOwner, "_connect", disappear):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--database", str(path), *args[2:], "--apply"]), 2)
        self.assertFalse(path.exists())

    def test_cli_binds_custom_live_test_and_shadow_identities(self):
        custom = owner.FinancialOwner(path=self.fixture._path(), config=self.store.config,
                                      trusted_authority=self.fixture.authority, owner_id="custom-owner", clock=self.store.clock)
        with patch.object(self.fixture, "_make_owner", return_value=custom):
            self.fixture._build_base()
        restores = [owner.FinancialOwner.restore_continuity(
            package_bytes=self.baseline, recovered_path=self.fixture._path(), trusted_authority=self.fixture.authority,
            restore_mode=mode, clock=self.store.clock) for mode in ("TEST", "SHADOW")]
        for store in (custom, *restores):
            self.store, self.baseline = store, store.export_continuity()
            _, _, args = self._cli_fixture()
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(args + ["--apply"])
            if store.mode == "SHADOW":
                self.assertEqual((code, stderr.getvalue()), (2, "ERROR:receiver_cash_file_refused\n"))
                self.assertEqual(store.export_continuity(), self.baseline)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(args), 0)
            else:
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
                self.assertEqual(restarted.export_continuity(), self.baseline)
            else:
                self.assertEqual(self._apply(store=restarted)["cash_delta_cents"], 0)
        self.assertEqual({name: (directory / name).read_bytes() for name in files}, files)

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
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", "ERROR:receiver_cash_file_refused\n"))
        self.assertEqual({name: (directory / name).read_bytes() for name in files}, files)


if __name__ == "__main__":
    unittest.main()
