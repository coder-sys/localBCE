"""The eligibility extract writer (scripts/build_elig_extract.py) against RightRail's own vectors.

- It reproduces RightRail's golden extract files (rightrail/tests/elig_vectors/*.elig) byte for byte from equivalent
  roster input.
- For every hostile file there that a roster can express, it refuses with the cause the reader names; the ones a
  roster cannot express (framing, filler, the trailer, the cover code, the registry) are listed by name.
- localBCE's synthetic roster becomes a file with pinned bytes.  A record that lacks a required field is refused;
  placeholders exist only in an explicit test mode and never for the status; the dropped benefit level is counted.
- RightRail's independent extract verifier accepts the writer's file (run in its own process; skipped with the reason
  named if that module cannot be imported).

Nothing here loads facts into a store or decides a line: no gate reads eligibility yet.
Design: docs/integration/ELIG_EXTRACT_AND_WIRING_DESIGN.md.  Synthetic, not legally verified, nonpayment.
"""

import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import build_elig_extract as bx  # noqa: E402

ROOT = bx.ROOT
VECTORS = ROOT / "rightrail" / "tests" / "elig_vectors"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "elig_extract" / "roster_v1.json"
FIXTURE_SHA3_512 = ("604ca54f2a746a9a7a7c70624fb20e0ec15853f95e1fc27f3e20012e0e6ae0dc"
                    "82fc150735fdaec5fd54751c5896085b5c936c284c970636365e6a3f918fbbc9")
# Hostile files whose fault is in the file's framing, filler, trailer, cover code or the registry entry: a roster has
# no way to say them, because the writer makes those parts itself.
NOT_EXPRESSIBLE = {
    "empty file", "no final line feed", "carriage returns", "row one byte short", "blank line", "row of 130 bytes",
    "first record a row", "no trailer", "header only", "unknown record type", "second header", "second trailer",
    "other layout", "space in trailer count", "unknown cover", "row filler", "header filler", "trailer filler",
    "count too high", "count too low", "no identity for kind 1", "identity code 3", "segment-only identity repeats",
}


def iso(raw: str) -> str:
    """Eight raw date characters as the roster writes a date, valid or not."""
    return f"{raw[:4]}-{raw[4:6]}-{raw[6:]}"


def lift(text: str) -> tuple[dict, object]:
    """(roster, fseq) saying what an extract file says, field by field, without checking any of it.  Text keeps
    everything but its padding; a file counter that is not digits stays text."""
    lines = text.split("\n")
    h, rows = lines[0], [x for x in lines[1:] if x[:1] == "D"]
    fseq = h[29:41]
    roster = {"synthetic": True, "sender": h[9:29].rstrip(" "), "scope": h[50:70].rstrip(" "), "as_of": iso(h[41:49]),
              "full_roster": h[49:50] == "F", "records": [
                  {"member_id": d[1:21].rstrip(" "), "segment": d[21:41].rstrip(" "), "status": d[41:42], "basis": d[42:43],
                   "program": d[43:63].rstrip(" "), "aid": d[63:73].rstrip(" "), "start": iso(d[73:81]),
                   "end": None if d[81:89] == "99991231" else iso(d[81:89]), "determined": iso(d[89:97]),
                   "notice": iso(d[97:105])} for d in rows]}
    return roster, int(fseq) if fseq.isascii() and fseq.isdigit() else fseq


def fixture() -> dict:
    return json.loads(FIXTURE.read_text("utf-8"))


class GoldenFiles(unittest.TestCase):
    def test_reproduces_rightrails_golden_files(self):
        for name in ("full.elig", "change.elig", "empty.elig"):
            data = (VECTORS / name).read_bytes()
            roster, fseq = lift(data.decode("ascii"))
            got, report = bx.build(roster, fseq)
            self.assertEqual(got, data, name)
            self.assertEqual(report["file_sha3_512"], hashlib.sha3_512(data).hexdigest(), name)
            self.assertEqual(report["placeholders_used"], dict.fromkeys(bx.PLACEHOLDERS, 0), name)
        self.assertEqual(lift((VECTORS / "change.elig").read_text("ascii"))[0]["full_roster"], False)

    def test_refuses_what_the_reader_refuses(self):
        hostile = json.loads((VECTORS / "hostile.json").read_text("utf-8"))
        names = {h["name"] for h in hostile}
        self.assertTrue(NOT_EXPRESSIBLE <= names, sorted(NOT_EXPRESSIBLE - names))
        expressed = [h for h in hostile if h["name"] not in NOT_EXPRESSIBLE]
        self.assertEqual(len(expressed), 17)
        for h in expressed:
            roster, fseq = lift(h["data"])
            with self.assertRaises(bx.ExtractRefused, msg=h["name"]) as cm:
                bx.build(roster, fseq)
            self.assertEqual(cm.exception.cause, h["cause"], h["name"])
        self.assertEqual({h["cause"] for h in expressed},
                         {"bad_text", "bad_number", "bad_date", "unknown_code", "span_backwards",
                          "determined_after_as_of", "duplicate_key"})


class Writer(unittest.TestCase):
    def refused(self, cause, where, roster=None, fseq=1, test_placeholders=False, **change):
        roster = dict(roster or fixture(), **change)
        with self.assertRaises(bx.ExtractRefused) as cm:
            bx.build(roster, fseq, test_placeholders)
        self.assertEqual((cm.exception.cause, cm.exception.where), (cause, where))
        return cm.exception

    def with_record(self, index, drop=(), **change):
        roster = fixture()
        rec = dict(roster["records"][index], **change)
        roster["records"][index] = {k: v for k, v in rec.items() if k not in drop}
        return roster

    def test_fixture_bytes_are_pinned(self):
        data, report = bx.build(fixture(), 1)
        self.assertEqual(hashlib.sha3_512(data).hexdigest(), FIXTURE_SHA3_512)
        self.assertEqual(bx.build(fixture(), 1)[0], data)
        lines = data.split(b"\n")
        self.assertEqual(lines[-1], b"")
        self.assertTrue(all(len(x) == 120 for x in lines[:-1]))
        self.assertEqual((lines[0][:9], lines[-2][:10]), (b"HRRELIG01", b"T000000010"))
        self.assertEqual(report["rows"], 10)
        self.assertIs(report["test_placeholders"], False)
        self.assertEqual(report["placeholders_used"], dict.fromkeys(bx.PLACEHOLDERS, 0))
        self.assertEqual(report["benefit_level_dropped"], 7)
        for flag in ("synthetic", "not_legally_verified", "nonpayment"):
            self.assertIs(report[flag], True)

    def test_fields_are_written_as_stated(self):
        rows = bx.build(fixture(), 1)[0].split(b"\n")
        first = rows[1]
        self.assertEqual(first[1:21].rstrip(), b"S00000001")
        self.assertEqual((first[21:41].rstrip(), first[41:43], first[43:63].rstrip(), first[63:73].rstrip()),
                         (b"SEG-0001", b"EG", b"SYN-PROGRAM", b"13"))
        self.assertEqual(first[73:105], b"20260101" b"99991231" b"20251215" b"20251216")  # no end is the open end
        self.assertEqual([r[41:43] for r in rows[8:11]], [b"NR", b"PG", b"RP"])
        self.assertEqual(rows[9][43:63].rstrip(), b"SYN-OTHER")  # a record's own program over the roster's

    def test_a_real_roster_must_supply_every_required_field(self):
        """Outside test mode nothing is filled in: a record that lacks a required field is refused."""
        self.assertEqual(bx.REQUIRED, ("member_id", "aid", "start", "segment", "status", "basis", "program",
                                       "determined", "notice"))
        for name in ("member_id", "aid", "start", "segment", "status", "basis", "determined", "notice"):
            self.refused("missing_field", "record 2", roster=self.with_record(1, drop=(name,)))
            self.refused("missing_field", "record 2", roster=self.with_record(1, **{name: None}))
        no_program = self.with_record(0)
        del no_program["program"]  # no roster program and none on the record
        self.refused("missing_field", "record 1", roster=no_program)
        self.assertEqual(len(bx.build(self.with_record(0, drop=("end",)), 1)[0]), 1452)  # end alone is optional

    def test_status_is_never_filled_in(self):
        """A missing status is refused in test mode too: it never defaults to eligible."""
        self.assertNotIn("status", bx.PLACEHOLDERS)
        self.assertNotIn("program", bx.PLACEHOLDERS)
        for mode in (False, True):
            self.refused("missing_field", "record 3", roster=self.with_record(2, drop=("status",)), test_placeholders=mode)
            self.refused("missing_field", "record 3", roster=self.with_record(2, status=None), test_placeholders=mode)
            self.refused("unknown_code", "record 3", roster=self.with_record(2, status=""), test_placeholders=mode)
            self.refused("missing_field", "record 3", roster=self.with_record(2, drop=("member_id",)), test_placeholders=mode)

    def test_placeholders_only_in_test_mode(self):
        roster = self.with_record(0, drop=("segment", "basis", "determined", "notice"))
        self.refused("missing_field", "record 1", roster=roster)
        data, report = bx.build(roster, 1, test_placeholders=True)
        row = data.split(b"\n")[1]
        self.assertEqual(row[21:41].rstrip(), b"13-20260101")  # the aid code, a dash, the start date
        self.assertEqual(row[41:43], b"EG")  # the status the record states; the placeholder basis
        self.assertEqual(row[89:105], b"20270314" b"20270314")  # both dates the as-of
        self.assertIs(report["test_placeholders"], True)
        self.assertEqual(report["placeholders_used"], {"segment": 1, "basis": 1, "determined": 1, "notice": 1})
        self.refused("bad_record", "header", test_placeholders="yes")

    def test_the_parked_array_form_is_not_accepted(self):
        for mode in (False, True):
            self.refused("bad_record", "record 1", roster=dict(fixture(), records=[["S1", "13", 1, "2026-01-01", None]]),
                         test_placeholders=mode)

    def test_benefit_level_never_reaches_the_file(self):
        with_level = fixture()
        without = copy.deepcopy(with_level)
        for r in without["records"]:
            r.pop("benefit_level", None)
        self.assertEqual(bx.build(with_level, 1)[0], bx.build(without, 1)[0])
        self.assertEqual(bx.build(without, 1)[1]["benefit_level_dropped"], 0)

    def test_cover_and_counter(self):
        change = bx.build(dict(fixture(), full_roster=False), 42)[0]
        self.assertEqual((change[29:41], change[49:50]), (b"000000000042", b"C"))
        for bad in (-1, 10 ** 12, "7", 1.0, True, None):
            self.refused("bad_number", "header", fseq=bad)
        self.refused("unknown_code", "header", full_roster="yes")

    def test_must_be_marked_synthetic(self):
        self.refused("not_synthetic", "header", synthetic=False)
        roster = fixture()
        del roster["synthetic"]
        self.refused("not_synthetic", "header", roster=roster)

    def test_refusals_name_the_reader_cause_and_the_position(self):
        self.refused("bad_text", "record 1", roster=self.with_record(0, member_id="S 1"))
        self.refused("bad_text", "record 1", roster=self.with_record(0, member_id=""))
        self.refused("bad_text", "record 2", roster=self.with_record(1, aid="\u00e9"))
        self.refused("bad_text", "record 2", roster=self.with_record(1, aid=13))
        self.refused("too_wide", "record 3", roster=self.with_record(2, member_id="S" * 21))
        self.refused("too_wide", "record 3", roster=self.with_record(2, aid="A" * 11))
        self.refused("bad_date", "record 1", roster=self.with_record(0, start="2026-02-30"))
        self.refused("bad_date", "record 1", roster=self.with_record(0, start="20260101"))
        self.refused("bad_date", "record 1", roster=self.with_record(0, start="0000-01-01"))
        self.refused("bad_date", "header", as_of="2027-13-01")
        self.refused("unknown_code", "record 8", roster=self.with_record(7, status="X"))
        self.refused("unknown_code", "record 8", roster=self.with_record(7, basis="g"))
        self.refused("span_backwards", "record 2", roster=self.with_record(1, start="2028-01-01"))
        self.refused("determined_after_as_of", "record 8", roster=self.with_record(7, determined="2027-03-15"))
        self.refused("bad_text", "header", sender="")
        self.refused("bad_text", "header", scope="A B")
        self.refused("bad_record", "record 1", roster=self.with_record(0, ssn="x"))
        self.refused("bad_record", "record 1", roster=dict(fixture(), records=["S1"]))
        self.refused("bad_record", "header", records="none")

    def test_duplicate_identity_is_refused_not_dropped(self):
        roster = fixture()
        roster["records"].append(roster["records"][0])  # the same member and segment twice, even as an exact copy
        self.refused("duplicate_key", "record 11", roster=roster)

    def test_a_notice_after_the_as_of_is_allowed(self):
        data = bx.build(fixture(), 1)[0].split(b"\n")[8]
        self.assertEqual(data[97:105], b"20270320")  # the fixture's as-of is 20270314

    def test_errors_carry_no_field_value(self):
        e = self.refused("bad_text", "record 1", roster=self.with_record(0, member_id="SECRET MEMBER"))
        self.assertNotIn("SECRET", str(e))
        e = self.refused("too_wide", "record 1", roster=self.with_record(0, member_id="SECRETMEMBER000000000"))
        self.assertNotIn("SECRET", str(e))


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bx.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_writes_the_file_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, report = Path(tmp) / "x.elig", Path(tmp) / "x.report.json"
            code, _, _ = self.run_cli("--roster", FIXTURE, "--fseq", 1, "--out", out, "--report", report)
            self.assertEqual(code, 0)
            self.assertEqual(hashlib.sha3_512(out.read_bytes()).hexdigest(), FIXTURE_SHA3_512)
            self.assertEqual(json.loads(report.read_text("utf-8"))["file_sha3_512"], FIXTURE_SHA3_512)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["x.elig", "x.report.json"])

    def test_a_refused_roster_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "roster.json"
            roster = fixture()
            roster["records"][3]["member_id"] = "SECRET MEMBER"
            bad.write_text(json.dumps(roster), "utf-8")
            code, out, err = self.run_cli("--roster", bad, "--fseq", 1, "--out", Path(tmp) / "x.elig")
            self.assertEqual((code, out, err), (1, "", "refused: bad_text at record 4\n"))
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["roster.json"])

    def test_refuses_to_write_under_rightrail_or_parked(self):
        for place in (ROOT / "rightrail" / "x.elig", ROOT / "parked" / "localbce" / "x.elig"):
            code, _, err = self.run_cli("--roster", FIXTURE, "--fseq", 1, "--out", place)
            self.assertEqual((code, err), (2, "refused: output path\n"))
            self.assertFalse(place.exists())
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_cli("--roster", FIXTURE, "--fseq", 1, "--out", Path(tmp) / "x", "--report", Path(tmp) / "x")
            self.assertEqual(code, 2)


# Run inside rightrail/ in its own process, with no bytecode written: RightRail's independent extract verifier reads
# the file given as an argument under the golden vectors' secret, registry entry and transport, and prints what it
# made of it.
VERIFY = r"""
import hashlib, json, sys, tempfile
try:
    from app import right_rail_fact_codec as codec, right_rail_fact_registry as reg
    from app.right_rail_reader_elig_independent import verify_elig
except Exception as e:
    print(json.dumps({"import_error": type(e).__name__ + ": " + str(e)})); sys.exit(0)
g = json.load(open("tests/elig_vectors/golden.json", encoding="utf-8"))
e = dict(g["entry"]); e.update(json.loads(sys.argv[2]))
e["kinds"] = reg.mask_of(e["ids"]); e["scope"], e["name"] = reg.ident(21, e["scope"]), reg.ident(31, e["name"])
data, rows = open(sys.argv[1], "rb").read(), []
with tempfile.TemporaryDirectory() as tmp:
    receipt = codec.decode_receipt(verify_elig(open(sys.argv[1], "rb"), g["secret"].encode(), e, rows.append, scratch=tmp, **g["transport"]))
facts = [codec.decode_fact(r) for r in rows]
print(json.dumps({"rows": len(facts), "receipt": {k: receipt[k] for k in ("cover", "asof", "fseq", "rows", "frows", "quar")},
                  "file_ok": receipt["file"] == hashlib.sha3_512(data).digest(),
                  "statuses": [f["value"]["status"] for f in facts], "kinds": sorted({f["kind"] for f in facts}),
                  "identities": len({bytes(f["sid"]) for f in facts}),
                  "raw_member_in_rows": any(b"S0000000" in bytes(r) for r in rows)}))
"""


class RightRailVerifier(unittest.TestCase):
    def test_rightrails_independent_verifier_accepts_the_file(self):
        data = bx.build(fixture(), 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "localbce.elig"
            path.write_bytes(data)
            done = subprocess.run([sys.executable, "-B", "-c", VERIFY, str(path), json.dumps({"scope": "LOCALBCE-SYN-STATE"})],
                                  cwd=str(ROOT / "rightrail"), capture_output=True, timeout=300,
                                  env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(done.returncode, 0, done.stderr.decode(errors="replace"))
        got = json.loads(done.stdout)
        if "import_error" in got:
            self.skipTest("RightRail's independent extract verifier cannot be imported here: " + got["import_error"])
        self.assertEqual(got["rows"], 10)
        self.assertEqual(got["receipt"], {"cover": 1, "asof": 20270314, "fseq": 1, "rows": 10, "frows": 10, "quar": 0})
        self.assertTrue(got["file_ok"])
        self.assertEqual(got["kinds"], [1])
        self.assertEqual(got["statuses"], [1, 1, 1, 1, 1, 1, 1, 2, 3, 4])
        self.assertEqual(got["identities"], 10)
        self.assertFalse(got["raw_member_in_rows"])  # the reader keys the member id; it never reaches a fact row


if __name__ == "__main__":
    unittest.main()
