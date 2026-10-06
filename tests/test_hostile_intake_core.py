"""Hostile cash files through the absorb ladder: every row admitted, repaired, resolved or held in the owner's one
transaction; an untrusted container refused whole; held cash unallocated until a later file releases it by evidence."""

import base64
import json
import random
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_intake as intake
from app.right_rail_financial_canonical_json import encode
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_cash_file as cashtests

sha = cashtests.sha
KINDS = ("clean",) * 6 + ("digits", "digits", "bare", "locale", "date", "shape", "amount", "revision", "duplicate")
BARE = b"@@"  # a quoted amount marked this way is written bare: a leading-zero number JSON cannot read


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

    def _verified(self):
        return cashtests.verify_database(self.store.path, expected_scope=self.scope, expected_authority=cashtests.owner._checker_authority(self.fixture.authority))

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
            elif kind == "bare":
                row["amount_cents"] = (BARE + str(amount).zfill(rng.randint(len(str(amount)) + 1, 12)).encode() + BARE).decode()
            elif kind == "locale":
                row["amount_cents"] = rng.choice([f"{amount},00", f"{amount}.00", f"1.{amount:03d},00", f"1,{amount:03d}.00"])
            elif kind == "date":
                row["event_at_ms"] = rng.choice(["01/02/2026", "02/01/2026", "2026-03-30"])
            elif kind == "shape":  # a row without its item cannot block the item's later rows
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
        return raw.replace(b'"' + BARE, b"").replace(BARE + b'"', b""), rows, kinds, total

    def test_seeded_files_sort_every_row_and_move_only_clean_cash(self):
        seen = set()
        for seed in range(12):
            with self.subTest(seed=seed):
                self.baseline = self._manifest()
                raw, rows, kinds, total = self._hostile(seed)
                receipt = self._ingest(raw)
                held = {row["row_index"]: row for row in receipt["rows"] if row["status"] == "HELD"}
                through = [i for i in range(len(rows)) if i not in held]
                seen |= {row["basis"] for row in held.values()} | {fact["rule_id"] for fact in receipt["repairs"]} | {row["status"] for row in receipt["rows"]}
                self.assertEqual([row["row_index"] for row in receipt["rows"]], list(range(len(rows))))
                self.assertEqual((receipt["received"], sum(receipt[status.lower()] for status in intake.OUTCOMES), receipt["resolved"]), (len(rows), len(rows), 0))
                cents = sum(int(str(rows[i]["amount_cents"]).strip("@")) for i in through)
                self.assertEqual((receipt["cash_delta_cents"], receipt["unallocated_cents"]), (cents, total - cents))
                self.assertEqual(self._payments(f"s{seed}-"), {rows[i]["payment_id"] for i in through})  # a held row moves no money
                for i, kind in enumerate(kinds):
                    if kind in ("locale", "date"):
                        self.assertEqual(held[i]["basis"], {"locale": "amount_format", "date": "date_format"}[kind])
                    if kind in ("shape", "amount", "revision"):
                        self.assertIn(i, held)
                    if kind in ("digits", "bare") and i not in held:
                        self.assertEqual((receipt["rows"][i]["status"], receipt["rows"][i]["basis"]), ("REPAIRED", ["amount_digits"]))
                for i, hold in held.items():
                    if hold["depends_on"] is None:
                        self.assertEqual((hold["fault"], hold["fix"]), intake.FAULTS.get(hold["basis"], intake._SENDER_RESEND))
                    else:  # the fault of the row it waits on
                        self.assertEqual((hold["fault"], hold["fix"]), (intake.FAULTS.get(held[hold["depends_on"]]["basis"], intake._SENDER_RESEND)[0], "release_row"))
                        self.assertLess(hold["depends_on"], i)
                        self.assertIn(hold["depends_on"], held)
                        self.assertEqual(rows[hold["depends_on"]]["item_id"], rows[i]["item_id"])
                for i in through:  # closure: nothing goes through behind a held row of its item
                    self.assertFalse(any(j < i and rows[j].get("item_id") == rows[i]["item_id"] for j in held))
                self._repairs_undo(raw, receipt)
                before = (self.store.export_continuity(), self.store.intake_records())
                self.assertEqual(self._ingest(raw), receipt)  # the same bytes again: the first receipt, nothing written
                self.assertEqual((self.store.export_continuity(), self.store.intake_records()), before)
                self.assertEqual((intake.intake_folder(self.store) / "raw" / sha(raw)).read_bytes(), raw)
        self.assertLessEqual({"ADMITTED", "REPAIRED", "bom", "number_text", "amount_format", "date_format", "shape", "amount", "revision", "duplicate", "depends_on_held", "item_cap"}, seen)  # the seeds reach every path
        self._verified()

    def _repairs_undo(self, raw, receipt):
        """Every L1 fact is exact both ways: byte facts, applied oldest first, make the bytes the rows were read from;
        undone newest first they give back the raw bytes. A row fact holds the sender's own amount text."""
        text = raw
        for fact in receipt["repairs"]:
            if fact["row_index"] is None:
                before, after, where = base64.b64decode(fact["before_b64"]), base64.b64decode(fact["after_b64"]), fact["where"]
                self.assertEqual((fact["rule_id"], text[where:where + len(before)]), ("bom" if before == intake.BOM else "number_text", before))
                text = text[:where] + after + text[where + len(before):]
        read = json.loads(text)["rows"]
        for fact in reversed(receipt["repairs"]):
            before, after = base64.b64decode(fact["before_b64"]), base64.b64decode(fact["after_b64"])
            if fact["row_index"] is None:
                text = text[:fact["where"]] + before + text[fact["where"] + len(after):]
            else:
                self.assertEqual(fact["rule_id"], "amount_digits")
                self.assertEqual(json.loads(before), read[fact["row_index"]][fact["where"]])
                self.assertEqual(json.loads(after), int(read[fact["row_index"]][fact["where"]]))
        self.assertEqual(text, raw)

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
        raw = encode(self._file(rows, 5 + 7 + 100_000 + 4 + 6 + 8 + 9 + 5))
        receipt = self._ingest(raw)
        self.assertEqual([(out["row_index"], out["status"], out["basis"], out["payment_id"], out["amount_cents"], out["fault"], out["fix"], out["depends_on"]) for out in receipt["rows"]], [
            (0, "ADMITTED", None, "mix-payment-0", 5, None, None, None), (1, "REPAIRED", ["amount_digits"], "mix-payment-1", 7, None, None, None),
            (2, "HELD", "amount_format", "mix-payment-2", 100_000, "sender", "sender_profile:amount_format", None),
            (3, "HELD", "depends_on_held", "mix-payment-3", 4, "sender", "release_row", 2),
            (4, "HELD", "date_format", "mix-payment-4", 6, "sender", "sender_profile:date_format", None),
            (5, "HELD", "duplicate", "mix-dup", 8, "sender", "resend_row", None), (6, "HELD", "duplicate", "mix-dup", 9, "sender", "resend_row", None),
            *[(i, "ADMITTED", None, f"mix-payment-{i}", 1, None, None, None) for i in range(7, 11)], (11, "HELD", "item_cap", "mix-payment-11", 1, "state", "next_file", None)])
        unallocated = 100_000 + 4 + 6 + 8 + 9 + 1
        self.assertEqual([receipt[key] for key in ("received", "admitted", "repaired", "resolved", "held", "cash_delta_cents", "unallocated_cents")], [12, 5, 1, 0, 6, 5 + 7 + 4, unallocated])
        self.assertEqual(self._payments("mix-"), {"mix-payment-0", "mix-payment-1", "mix-payment-7", "mix-payment-8", "mix-payment-9", "mix-payment-10"})
        self.assertEqual(self._query("SELECT amount_cents FROM payments WHERE payment_id='mix-payment-1'"), [(7,)])
        self.assertEqual(receipt["receipt_digest"], sha(encode({key: value for key, value in receipt.items() if key != "receipt_digest"})))
        cash_held = intake.held_cash(self.store)  # D3: held cents stay unallocated, never applied
        self.assertEqual((cash_held["unallocated_cents"], [(hold["row_index"], hold["reason"]) for hold in cash_held["holds"]], cash_held["released"]),
                         (unallocated, [(2, "amount_format"), (3, "depends_on_held"), (4, "date_format"), (5, "duplicate"), (6, "duplicate"), (11, "item_cap")], []))
        self.assertEqual(len(self.store.intake_records()), 1)
        self._verified()

    def test_row_faults_in_the_bytes_are_repaired_or_held_never_refused(self):
        revisions = self._revisions()
        rows = [self._row(0, 100, revisions[expected.H_ITEM_ID]), {**self._row(1, 10, revisions["item-01"]), "item_id": "item-01", "payment_id": "file-payment-NONASCII"},
                {**self._row(2, "@@00042@@", revisions["item-02"]), "item_id": "item-02"}, {**self._row(3, 30, revisions["item-03"]), "item_id": "item-03", "event_at_ms": "@@0" + str(expected.CASH_EVENT_MS) + "@@"},
                {**self._row(4, 20, 0), "item_id": "bad id"}]
        raw = encode(self._file(rows, 202)).replace(b"NONASCII", "payé".encode("utf-8")).replace(b'"@@', b"").replace(b'@@"', b"")
        receipt = self._ingest(raw)
        self.assertEqual([(out["status"], out["basis"], out["fault"], out["fix"]) for out in receipt["rows"]], [
            ("ADMITTED", None, None, None), ("HELD", "encoding", "sender", "sender_profile:encoding"), ("REPAIRED", ["amount_digits"], None, None),
            ("HELD", "date_format", "sender", "sender_profile:date_format"), ("HELD", "identifier", "sender", "resend_row")])
        self.assertEqual([fact["rule_id"] for fact in receipt["repairs"]], ["number_text", "number_text", "amount_digits"])
        self._repairs_undo(raw, receipt)
        self.assertEqual((receipt["cash_delta_cents"], receipt["unallocated_cents"], self._payments("file-")), (142, 60, {"file-payment-0", "file-payment-2"}))

    def test_all_rows_held_moves_nothing_and_is_receipted(self):
        rows = [{**self._row(0, 1, 0, "held"), "amount_cents": "1.000,00"}, {**self._row(1, 2, 1, "held"), "event_at_ms": "03/04/2026"}]
        payments = self._query("SELECT * FROM payments")
        receipt = self._ingest(encode(self._file(rows, 100_002)))
        self.assertEqual((receipt["held"], receipt["derived_sha256"], receipt["cash_delta_cents"], receipt["unallocated_cents"]), (2, None, 0, 100_002))
        self.assertEqual((self._query("SELECT * FROM payments"), len(self.store.intake_records())), (payments, 1))
        self._verified()

    def test_untrusted_container_is_refused_whole_keeping_only_its_bytes(self):
        good = self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID])], 100)
        cases = {
            "not json": (b"{\"rows\": [", "cash_file_format"),
            "not ascii": (encode(good).replace(b"receiver-1", "réceiver".encode("utf-8")), "cash_file_format"),
            "header leading zero": (encode(good).replace(b'"row_count":1', b'"row_count":01'), "cash_file_format"),
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
        self.assertEqual((self.store.export_continuity(), self.store.intake_records()), (before, []))
        self.assertEqual(self._ingest(encode(good))["admitted"], 1)  # the good file after them all still goes through

    def test_crash_in_the_gate_leaves_nothing_and_the_resend_goes_through(self):
        raw = encode(self._file([self._row(1, 100, self._revisions()[expected.H_ITEM_ID]), {**self._row(2, 50, 0), "amount_cents": "5.0"}], 150))
        before = self.store.export_continuity()
        with patch.object(check.CashFileCheck, "finish", side_effect=RuntimeError("crash")), self.assertRaisesRegex(RuntimeError, "crash"):
            self._ingest(raw)
        self.assertEqual((self.store.export_continuity(), self.store.intake_records()), (before, []))
        self.assertEqual(self._ingest(raw)["admitted"], 1)

    def test_a_crash_at_any_row_boundary_leaves_nothing_and_the_file_is_received_once(self):
        revision = self._revisions()[expected.H_ITEM_ID]
        rows = [self._row(1, 100, revision), {**self._row(2, 50, 0), "item_id": "item-01", "event_at_ms": "1/2/26"}, self._row(3, 30, revision + 1)]
        raw = encode(self._file(rows, 180))
        derived, facts = intake.absorb(raw, self.scope, self.source)
        facts = {"adapter": intake.ADAPTER, "ruleset_digest": intake.RULESET_DIGEST, "source_sha256": sha(raw), "derived_sha256": sha(derived), **facts}
        commands, context = cash.prepare_cash_file(
            derived, self.baseline, expected_source_sha256=sha(derived), expected_baseline_sha256=sha(self.baseline), expected_scope=self.scope,
            expected_source=self.source, expected_owner_id=self.store.owner_id, expected_mode=self.store.mode, trusted_authority=self.fixture.authority, intake=facts)
        before = self.store.export_continuity()
        for boundary in range(len(commands) + 1):  # before each row's write, then before the intake record that closes the file
            calls = []

            def crashing(real):
                def step(*arguments, **keywords):
                    calls.append(None)
                    if len(calls) > boundary:
                        raise RuntimeError("crash")
                    return real(*arguments, **keywords)
                return step
            with self.subTest(boundary=boundary), patch.object(self.store, "record_payment_evidence", crashing(self.store.record_payment_evidence)), \
                    patch.object(self.store, "record_intake", crashing(self.store.record_intake)), self.assertRaisesRegex(RuntimeError, "crash"):
                self.store.run_batch(commands, cash_file_context=context)
            self.assertEqual((len(calls), self.store.export_continuity(), self.store.intake_records(), self._payments("file-")), (boundary + 1, before, [], set()))
        receipt = self._ingest(raw)
        self.assertEqual([(out["status"], out["basis"]) for out in receipt["rows"]], [("ADMITTED", None), ("HELD", "date_format"), ("ADMITTED", None)])
        with self.assertRaisesRegex(check.CashFileError, "^cash_file_conflict$"):  # one raw file is received once, even through the gate
            self.store.run_batch(commands, cash_file_context=context)
        self.assertEqual(self._ingest(raw), receipt)

    def test_corrected_resend_releases_the_hold_by_evidence_and_history_keeps_the_original(self):
        revisions = self._revisions()
        clean = {**self._row(2, 50, revisions["item-01"]), "item_id": "item-01"}
        first = self._ingest(encode(self._file([self._row(1, 100, revisions[expected.H_ITEM_ID]), {**clean, "event_at_ms": "01/02/2026"}], 150)))
        self.assertEqual((first["admitted"], first["held"], first["unallocated_cents"]), (1, 1, 50))
        self.assertEqual(intake.held_cash(self.store), {"unallocated_cents": 50, "released": [], "holds": [
            {"source_sha256": first["source_sha256"], "row_index": 1, "payment_id": "file-payment-2", "amount_cents": 50, "reason": "date_format"}]})
        self.baseline = self._manifest()
        corrected = self._file([self._row(1, 100, revisions[expected.H_ITEM_ID]), clean], 150)
        resend = self._ingest(encode(corrected))  # the sender's whole file again, the held row fixed
        self.assertEqual([(out["status"], out["basis"]) for out in resend["rows"]], [("RESOLVED", "duplicate_of:file-payment-1"), ("ADMITTED", None)])
        self.assertEqual((resend["cash_delta_cents"], resend["unallocated_cents"]), (50, 0))
        released = intake.held_cash(self.store)
        self.assertEqual(released, {"unallocated_cents": 0, "holds": [], "released": [
            {"source_sha256": first["source_sha256"], "row_index": 1, "payment_id": "file-payment-2", "amount_cents": 50, "reason": "date_format",
             "released_by": resend["source_sha256"], "released_row": 1}]})
        again = self._ingest(json.dumps(corrected).encode("ascii"))  # the same rows in other bytes: each resolves to its payment, nothing new
        self.assertEqual(([out["status"] for out in again["rows"]], again["cash_delta_cents"], intake.held_cash(self.store)), (["RESOLVED", "RESOLVED"], 0, released))
        records = self.store.intake_records()
        self.assertEqual([intake._receipt(record) for record in records], [first, resend, again])  # the original hold stays in history
        self.assertEqual(self._payments("file-"), {"file-payment-1", "file-payment-2"})
        self._verified()


if __name__ == "__main__":
    unittest.main()
