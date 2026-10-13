"""Money and identity values are integers only (stack1-review F14), and JSON stays inside the Lean grammar (depth 32,
250,000 nodes, -(2^63) <= int < 2^63): anything else is a typed refusal at intake, and a stored row holding it is found,
row by row, for quarantine without refusing or rewriting the store."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner_independent as independent

REFUSED = {"1.5": "float", "1e3": "float", "-0.0": "float", "NaN": "constant", "Infinity": "constant", "-Infinity": "constant"}
TOP, BOTTOM = str((1 << 63) - 1), str(-(1 << 63))
# each Lean bound at its limit (admitted) and one past it (refused)
BOUNDS = {
    "depth": ("[" * 32 + "0" + "]" * 32, "[" * 33 + "0" + "]" * 33),
    "nodes": ("[" + ",".join(["0"] * 249_999) + "]", "[" + ",".join(["0"] * 250_000) + "]"),
    "int-top": (TOP, str(1 << 63)),
    "int-bottom": (BOTTOM, str(-(1 << 63) - 1)),
    "int-digits": (f'{{"a":{TOP}}}', f'{{"a":{"9" * 5000}}}'),
}


class FloatRefusalTests(unittest.TestCase):
    def test_every_float_is_a_typed_refusal_at_intake(self):
        for number, kind in REFUSED.items():
            for raw in (number, f'{{"amount_cents":{number}}}', f'{{"rows":[{{"amount_cents":1}},{{"amount_cents":{number}}}]}}'):
                with self.subTest(raw=raw):
                    with self.assertRaisesRegex(independent.IndependentFinancialError, f"^intake:{kind}$"):
                        independent._parse_json(raw, "intake")
                    with self.assertRaisesRegex(check.CashFileError, "^cash_file_format$"):
                        check._parsed(raw.encode("ascii"))

    def test_each_lean_bound_admits_its_limit_and_refuses_one_past_it(self):
        for bound, (limit, past) in BOUNDS.items():
            with self.subTest(bound=bound):
                self.assertEqual(independent._canonical(independent._parse_json(limit, "intake")), limit.encode("ascii"))
                with self.assertRaisesRegex(independent.IndependentFinancialError, "^intake:bounds$"):
                    independent._parse_json(past, "intake")
                with self.assertRaisesRegex(check.CashFileError, "^cash_file_format$"):
                    check._parsed(past.encode("ascii"))

    def test_an_integer_payload_is_unchanged_byte_for_byte(self):
        raw = '{"amount_cents":9223372036854775807,"rows":[{"amount_cents":-1,"id":"a-1"},{"amount_cents":0}],"z":null}'
        value = independent._parse_json(raw, "intake")
        self.assertEqual((independent._canonical(value), check._parsed(raw.encode("ascii"))), (raw.encode("ascii"), value))
        self.assertIs(type(value["amount_cents"]), int)

    def test_the_quarantine_scan_finds_each_row_past_the_grammar_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                for table, definition in {**independent._TABLE_DEFS, **independent._HISTORY_TABLE_DEFS}.items():
                    keys = ",".join(name for name, _, pk in sorted(definition, key=lambda column: column[2]) if pk)
                    db.execute(f"CREATE TABLE {table} ({','.join(f'{name} {kind}' for name, kind, _ in definition)}, PRIMARY KEY({keys}))")
                db.executemany("INSERT INTO commands VALUES (?,'K',?,x'00',?)", [
                    ("clean", '{"a":1}', 1), ("nested", '{"a":[{"b":1e3}]}', 2), ("real", "{}", 2.5),
                    ("nan", '{"a":NaN}', 3), ("broken", '{"a":', 4), ("whole", "3.0", 5), ("edge", f'{{"a":{BOTTOM}}}', 6),
                    ("deep", BOUNDS["depth"][1], 7), ("big", f'{{"a":{1 << 63}}}', 8)])
                db.execute("INSERT INTO history_pending VALUES ('evidence', 7, 0.5)")
                db.commit()
            before = path.read_bytes()
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                found = independent.json_quarantine_rows(db)
            self.assertEqual(path.read_bytes(), before)
        self.assertEqual(found, [
            {"table": "commands", "key": ("big",), "columns": {"request_json": "bounds"}},
            {"table": "commands", "key": ("deep",), "columns": {"request_json": "bounds"}},
            {"table": "commands", "key": ("nan",), "columns": {"request_json": "constant"}},
            {"table": "commands", "key": ("nested",), "columns": {"request_json": "float"}},
            {"table": "commands", "key": ("real",), "columns": {"event_sequence": "real"}},
            {"table": "commands", "key": ("whole",), "columns": {"request_json": "float"}},
            {"table": "history_pending", "key": ("evidence", 7), "columns": {"record_bytes": "real"}},
        ])


if __name__ == "__main__":
    unittest.main()
