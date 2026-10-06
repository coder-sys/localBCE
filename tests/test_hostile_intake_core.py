"""Hostile cash files through the absorb ladder, slice 1: every row applied, repaired or held; an untrusted container refused whole."""

import base64
from contextlib import closing
import json
import random
import sqlite3
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_intake as intake
from app.right_rail_financial_canonical_json import decode, encode
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_cash_file as cashtests

sha = cashtests.sha
KINDS = ("clean",) * 6 + ("digits", "digits", "locale", "date", "shape", "amount", "revision", "duplicate")


class HostileIntakeTests(unittest.TestCase):
    setUp = cashtests.ReceiverCashFileTests.setUp
    _manifest = cashtests.ReceiverCashFileTests._manifest
    _row = cashtests.ReceiverCashFileTests._row
    _query = cashtests.ReceiverCashFileTests._query

    def _ingest(self, raw, baseline=None, expected_sha=None):
        baseline = self.baseline if baseline is None else baseline
        return intake.ingest_cash_file(
            self.store, raw, baseline, expected_source_sha256=sha(raw) if expected_sha is None else expected_sha,
            expected_baseline_sha256=sha(baseline), expected_scope=self.scope, expected_source=self.source,
            expected_owner_id=self.store.owner_id, expected_mode=self.store.mode, trusted_authority=self.fixture.authority)

    def _file(self, rows, total):
        return {"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1", "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": self.scope,
                "source": self.source, "row_count": len(rows), "total_cents": total, "rows": rows}

    def _revisions(self):
        return dict(self._query("SELECT item_id,revision FROM obligations WHERE period_id=?", self.scope["period_id"]))

    def _payments(self, prefix):
        return {payment for (payment,) in self._query("SELECT payment_id FROM payments WHERE payment_id LIKE ?", prefix + "%")}

    def _intake_rows(self):
        path = intake.intake_folder(self.store) / "intake.sqlite"
        if not path.exists():
            return None
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            return [connection.execute(f"SELECT * FROM {table} ORDER BY 1,2,3").fetchall() for table in ("intake_receipts", "intake_holds")]

    def _hostile(self, seed):
        """A seeded file over some of the store's items: clean, repairable, holdable, duplicate and dependent rows, in one of three byte layouts."""
        rng = random.Random(seed)
        revisions = self._revisions()
        items = rng.sample(sorted(revisions), rng.randint(1, len(revisions)))
        rows, kinds, total, hostility = [], [], 0, rng.choice([0.03, 0.3, 1.0])
        for number in range(rng.randint(1, 80)):
            item, amount = rng.choice(items), rng.randint(1, 999)
            kind = rng.choice(KINDS) if rng.random() < hostility else "clean"
            row = {**self._row(number, amount, revisions[item], f"s{seed}"), "item_id": item}
            revisions[item] += 1  # a held row blocks every later row of its item, so only rows before it need the true revision
            total += amount
            if kind == "digits":
                row["amount_cents"] = str(amount).zfill(rng.randint(len(str(amount)), 12))
            elif kind == "locale":
                row["amount_cents"] = rng.choice([f"{amount},00", f"{amount}.00", f"1.{amount:03d},00", f"1,{amount:03d}.00"])
            elif kind == "date":
                row["event_at_ms"] = rng.choice(["01/02/2026", "02/01/2026", "2026-03-30"])
            elif kind == "shape":  # a row without its item cannot block the item's later rows; a gate refusal, slice 2
                del row[rng.choice(sorted(set(row) - {"item_id"}))]
            elif kind == "amount":
                row["amount_cents"] = rng.choice([0, -5, 1.5, None, True, "abc"])
            elif kind == "revision":
                row["expected_revision"] = rng.choice([-1, 10_000, "3"])
            elif kind == "duplicate" and rows:
                field = rng.choice(["payment_id", "evidence_id"])
                row[field] = rng.choice(rows).get(field, row[field])
            rows.append(row)
            kinds.append(kind)
        value = self._file(rows, total)
        layout = seed % 3
        if layout == 0:
            raw = encode(value)
        elif layout == 1:
            raw = json.dumps(value, indent=2).replace("\n", "\r\n").encode("ascii")  # pretty, unsorted, CRLF
        else:
            raw = intake.BOM + json.dumps(value).encode("ascii")
        return raw, rows, kinds

    def test_seeded_files_sort_every_row_and_move_only_clean_cash(self):
        seen = set()
        for seed in range(12):
            with self.subTest(seed=seed):
                self.baseline = self._manifest()
                raw, rows, kinds = self._hostile(seed)
                receipt = self._ingest(raw)
                held = {hold["row_index"]: hold for hold in receipt["holds"]}
                through = [i for i in range(len(rows)) if i not in held]
                seen |= {hold["reason"] for hold in held.values()} | {fact["rule_id"] for fact in receipt["repairs"]} | {key for key in ("applied", "repaired") if receipt[key]}
                self.assertEqual(receipt["received"], len(rows))
                self.assertEqual(receipt["applied"] + receipt["repaired"] + receipt["held"], receipt["received"])
                self.assertEqual(receipt["applied"] + receipt["repaired"], len(through))
                cents = sum(int(rows[i]["amount_cents"]) for i in through)
                self.assertEqual(receipt["unallocated_cents"], json.loads(raw.lstrip(intake.BOM))["total_cents"] - cents)
                gate = receipt["gate_receipt"]
                self.assertEqual((0, 0) if gate is None else (gate["recorded_count"], gate["cash_delta_cents"]), (len(through), cents))
                self.assertEqual(self._payments(f"s{seed}-"), {rows[i]["payment_id"] for i in through})  # a held row moves no money
                for i, kind in enumerate(kinds):
                    if kind == "locale":
                        self.assertEqual(held[i]["reason"], "amount_format")
                    if kind == "date":
                        self.assertEqual(held[i]["reason"], "date_format")
                    if kind in ("shape", "amount", "revision"):
                        self.assertIn(i, held)
                for i, hold in held.items():
                    if hold["depends_on"] is None:
                        self.assertEqual((hold["fault"], hold["fix"]), intake.FAULTS[hold["reason"]])
                    else:  # the fault of the row it waits on
                        self.assertEqual((hold["fault"], hold["fix"]), (intake.FAULTS[held[hold["depends_on"]]["reason"]][0], "release_row"))
                        self.assertLess(hold["depends_on"], i)
                        self.assertIn(hold["depends_on"], held)
                        self.assertEqual(rows[hold["depends_on"]]["item_id"], rows[i]["item_id"])
                for i in through:  # closure: nothing goes through behind a held row of its item
                    self.assertFalse(any(j < i and rows[j].get("item_id") == rows[i]["item_id"] for j in held))
                self._repairs_undo(raw, receipt)
                before = (self.store.export_continuity(), self._intake_rows())
                self.assertEqual(self._ingest(raw), receipt)  # the same bytes again: the first receipt, nothing written
                self.assertEqual((self.store.export_continuity(), self._intake_rows()), before)
                self.assertEqual((intake.intake_folder(self.store) / "raw" / sha(raw)).read_bytes(), raw)
        self.assertLessEqual({"applied", "repaired", "bom", "amount_format", "date_format", "shape", "amount", "revision", "duplicate", "depends_on_held", "item_cap"}, seen)  # the seeds reach every path

    def _repairs_undo(self, raw, receipt):
        """Every L1 fact puts its `before` back: the BOM in front of the bytes, the sender's own amount text into its row."""
        text = raw
        source_rows = None
        for fact in reversed(receipt["repairs"]):
            before, after = (base64.b64decode(fact[key]) for key in ("before_b64", "after_b64"))
            if fact["row_index"] is None:
                self.assertEqual((fact["rule_id"], fact["where"], after), ("bom", 0, b""))
                self.assertEqual(before + text[len(before):], raw)
            else:
                source_rows = source_rows or json.loads(raw.lstrip(intake.BOM))["rows"]
                self.assertEqual(fact["rule_id"], "amount_digits")
                self.assertEqual(decode(before, "ascii", None, None), source_rows[fact["row_index"]][fact["where"]])
                self.assertEqual(decode(after, "ascii", None, None), int(source_rows[fact["row_index"]][fact["where"]]))
                self.assertIsInstance(source_rows[fact["row_index"]][fact["where"]], str)

    def test_mixed_file_holds_exactly_what_it_cannot_take(self):
        revisions = self._revisions()
        h, one, two, three = expected.H_ITEM_ID, "item-01", "item-02", "item-03"

        def row(number, item, amount, **changes):
            made = {**self._row(number, amount, revisions[item], "mix"), "item_id": item, **changes}
            revisions[item] += 1
            return made
        rows = [row(0, h, 5), row(1, h, "007"), row(2, one, "1.000,00"), row(3, one, 4), row(4, two, 6, event_at_ms="01/02/2026"),
                row(5, three, 8, payment_id="mix-dup"), row(6, three, 9, payment_id="mix-dup")]
        rows += [row(number, h, 1) for number in range(7, 12)]
        receipt = self._ingest(encode(self._file(rows, 5 + 7 + 100_000 + 4 + 6 + 8 + 9 + 5)))
        self.assertEqual([(hold["row_index"], hold["reason"], hold["fault"], hold["fix"], hold["depends_on"]) for hold in receipt["holds"]], [
            (2, "amount_format", "sender", "sender_profile:amount_format", None), (3, "depends_on_held", "sender", "release_row", 2),
            (4, "date_format", "sender", "sender_profile:date_format", None), (5, "duplicate", "sender", "resend_row", None),
            (6, "duplicate", "sender", "resend_row", None), (11, "item_cap", "state", "next_file", None)])
        self.assertEqual([receipt[key] for key in ("received", "applied", "repaired", "held", "unallocated_cents")], [12, 5, 1, 6, 100_000 + 4 + 6 + 8 + 9 + 1])
        self.assertEqual(receipt["gate_receipt"]["cash_delta_cents"], 5 + 7 + 4 * 1)
        self.assertEqual(self._payments("mix-"), {"mix-payment-0", "mix-payment-1", "mix-payment-7", "mix-payment-8", "mix-payment-9", "mix-payment-10"})
        self.assertEqual(self._query("SELECT amount_cents FROM payments WHERE payment_id='mix-payment-1'"), [(7,)])
        stored = self._intake_rows()
        self.assertEqual([hold[2:] for hold in stored[1]], [(2, "mix-payment-2", "amount_format", "sender", "sender_profile:amount_format", None),
                                                            (3, "mix-payment-3", "depends_on_held", "sender", "release_row", 2),
                                                            (4, "mix-payment-4", "date_format", "sender", "sender_profile:date_format", None),
                                                            (5, "mix-dup", "duplicate", "sender", "resend_row", None),
                                                            (6, "mix-dup", "duplicate", "sender", "resend_row", None),
                                                            (11, "mix-payment-11", "item_cap", "state", "next_file", None)])
        self.assertEqual(stored[0][0][-1], receipt["receipt_digest"])
        self.assertEqual(receipt["receipt_digest"], sha(encode({key: value for key, value in receipt.items() if key != "receipt_digest"})))

    def test_all_rows_held_moves_nothing_and_is_receipted(self):
        rows = [{**self._row(0, 1, 0, "held"), "amount_cents": "1.000,00"}, {**self._row(1, 2, 1, "held"), "event_at_ms": "03/04/2026"}]
        before = self.store.export_continuity()
        receipt = self._ingest(encode(self._file(rows, 100_002)))
        self.assertEqual((receipt["held"], receipt["gate_receipt"], receipt["derived_sha256"], receipt["unallocated_cents"]), (2, None, None, 100_002))
        self.assertEqual(self.store.export_continuity(), before)

    def test_untrusted_container_is_refused_whole_keeping_only_its_bytes(self):
        good = self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID])], 100)
        cases = {
            "not json": (b"{\"rows\": [", "cash_file_format"),
            "not ascii": (encode(good).replace(b"receiver-1", "réceiver".encode("utf-8")), "cash_file_format"),
            "duplicate key": (b"{\"contract\":1," + encode(good)[1:], "cash_file_format"),
            "wrong contract": (encode({**good, "contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v2"}), "cash_file_format"),
            "row count": (encode({**good, "row_count": 2}), "cash_file_format"),
            "total": (encode({**good, "total_cents": 101}), "cash_file_format"),
            "total below held minimum": (encode({**good, "row_count": 2, "rows": good["rows"] + [{**self._row(2, 1, 0), "amount_cents": "1,00"}]}), "cash_file_format"),
            "too many rows": (encode({**good, "row_count": 501, "rows": good["rows"] * 501}), "cash_file_row_cap"),
            "scope": (encode({**good, "scope": {**self.scope, "period_id": "other-period"}}), "cash_file_binding"),
            "source": (encode({**good, "source": {**self.source, "capture_id": "capture-2"}}), "cash_file_binding"),
        }
        before = self.store.export_continuity()
        for name, (raw, code) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(check.CashFileError, code):
                self._ingest(raw)
            self.assertEqual((intake.intake_folder(self.store) / "raw" / sha(raw)).read_bytes(), raw)
        with self.assertRaisesRegex(check.CashFileError, "cash_file_binding"):
            self._ingest(encode(good), expected_sha="0" * 64)  # not the file its reviewer bound: not even kept
        self.assertFalse((intake.intake_folder(self.store) / "raw" / sha(encode(good))).exists())
        self.assertEqual(self.store.export_continuity(), before)
        self.assertEqual(self._intake_rows(), [[], []])
        self.assertEqual(self._ingest(encode(good))["applied"], 1)  # the good file after them all still goes through

    def test_crash_in_the_gate_leaves_nothing_and_the_resend_goes_through(self):
        raw = encode(self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID]), {**self._row(2, 50, 0), "amount_cents": "5.0"}], 150))
        before = self.store.export_continuity()
        with patch.object(check.CashFileCheck, "finish", side_effect=RuntimeError("crash")), self.assertRaisesRegex(RuntimeError, "crash"):
            self._ingest(raw)
        self.assertEqual((self.store.export_continuity(), self._intake_rows()), (before, [[], []]))
        self.assertEqual(self._ingest(raw)["gate_receipt"]["recorded_count"], 1)

    def test_crash_between_owner_and_intake_commits_converges_without_double_cash(self):
        raw = encode(self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID]), {**self._row(2, 50, 0), "event_at_ms": "1/2/26"}], 150))
        with patch.object(intake, "_stored", side_effect=[None, RuntimeError("crash")]), self.assertRaisesRegex(RuntimeError, "crash"):
            self._ingest(raw)
        self.assertEqual((self._payments("file-"), self._intake_rows()), ({"file-payment-1"}, [[], []]))  # the window this slice leaves open
        committed = self.store.export_continuity()
        receipt = self._ingest(raw)
        self.assertEqual((receipt["gate_receipt"]["recorded_count"], receipt["gate_receipt"]["duplicate_count"], receipt["gate_receipt"]["cash_delta_cents"]), (0, 1, 0))
        self.assertEqual((receipt["applied"], receipt["held"], receipt["unallocated_cents"]), (1, 1, 50))
        self.assertEqual(self.store.export_continuity(), committed)

    def test_intake_store_is_append_only(self):
        self._ingest(encode(self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID]), {**self._row(2, 5, 0), "amount_cents": "0,05"}], 105)))
        with closing(sqlite3.connect(intake.intake_folder(self.store) / "intake.sqlite")) as connection:
            for sql in ("UPDATE intake_receipts SET held=0", "DELETE FROM intake_receipts", "UPDATE intake_holds SET reason='x'", "DELETE FROM intake_holds"):
                with self.subTest(sql), self.assertRaisesRegex(sqlite3.DatabaseError, "intake_append_only"):
                    connection.execute(sql)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK"):
                connection.execute("INSERT INTO intake_receipts VALUES ('B','a','d','s',0,3,1,1,0,0,'{}','x')")


if __name__ == "__main__":
    unittest.main()
