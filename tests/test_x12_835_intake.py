"""Synthetic 835 intake: good files, every refusal code, control and balance faults, PLB carry-forward, caps, a hostile corpus,
and agreement of the independent re-derivation on every fixture. Fixtures are fictional: no real NPI, name or payer."""

import ast
import dataclasses
import json
import random
import re
import unittest
from pathlib import Path

from app.x12_835_independent import IndependentX12Error, rederive_835, verify_835
from app.x12_835_intake import Cas, Dtm, PlbAdjustment, Remittance, cents, parse_835
from app.x12_tokenizer import MAX_BYTES, X12Error, tokenize

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "1234567890"  # fictional NPI shape; the Luhn test below proves it cannot be a real one
CLAIMS = [
    "CLP*CLAIMA001*1*500.00*400.00*100.00*MC*PAYERCTL001*11*1", "CAS*PR*1*100.00", "DTM*232*20261001",
    "SVC*HC:99213*500.00*400.00**1", "CAS*PR*1*100.00", "DTM*472*20261001",
    "CLP*CLAIMB002*1*900.00*850.50*49.50*MC*PAYERCTL002*11*1", "CAS*PR*2*49.50*1",
]
PLB = f"PLB*{PROVIDER}*20261231*FB:CARRY0001*100.00*WO:WRITEOFF2*25.50"


def remit(total, *rest):
    return ["BPR*I*%s*C*ACH*CCP%s20261005" % (total, "*" * 11), "TRN*1*TRACE0001*1999999999", "DTM*405*20261003",
            "N1*PR*SYNTH STATE MEDICAID PROGRAM*PI*SYNTHPAYER01", f"N1*PE*EXAMPLE CLINIC OF NOWHERE*XX*{PROVIDER}", *rest]


def build(body, sets=1, groups=1, **o):
    icn = o.get("icn", "000000905")
    fields = ["00", " " * 10, "00", " " * 10, "ZZ", "SYNTHPAYER".ljust(15), "ZZ", "SYNTHPROVIDER".ljust(15), "261005", "1200",
              "^", "00501", icn, "0", o.get("usage", "T"), ":"]
    out = ["ISA*" + "*".join(fields)]
    for g in range(groups):
        gc = o.get("gc", str(g + 1))
        out.append("GS*HP*SYNTHPAYER01*SYNTHPROVIDER*20261005*1200*%s*X*%s" % (gc, o.get("ver", "005010X221A1")))
        for s in range(sets):
            sc = "%04d" % (s + 1)
            seg = ["ST*835*" + sc, *body]
            out += [*seg, "SE*%s*%s" % (o.get("se", len(seg) + 1), o.get("sc", sc))]
        out.append("GE*%s*%s" % (o.get("ge", sets), o.get("gec", gc)))
    out.append("IEA*%s*%s" % (o.get("iea", groups), o.get("ic", icn)))
    return ("~".join(out) + "~").encode("ascii")


GOOD = build(remit("1250.50", *CLAIMS))
WITH_PLB = build(remit("1125.00", *CLAIMS, PLB))
NEGATIVE_PLB = build(remit("1550.50", *CLAIMS, f"PLB*{PROVIDER}*20261231*FB:CARRY0001*-300.00"))
EMPTY = build(remit("0.00"))
EDGE = build(remit("0.01", "CLP*EDGE0001*1*999999999999.99*0.01*0.00*MC*PAYERCTL003", "SVC*HC:J0001*0.00*0.01"))
FIXTURES = {"good": GOOD, "plb": WITH_PLB, "negative-plb": NEGATIVE_PLB, "empty": EMPTY, "edge": EDGE,
            "separators": GOOD.decode().translate(str.maketrans("*^:~", "|!;$")).encode(),
            "two-plb-segments": build(remit("1100.00", *CLAIMS, PLB, f"PLB*{PROVIDER}*20261231*CS*25.00"))}


def edit(data, old, new):
    text = data.decode()
    assert text.count(old) == 1, old
    return text.replace(old, new).encode()


def code_of(error):
    assert error.__cause__ is None and error.__context__ is None and not error.args[1:]
    assert re.fullmatch(r"(x12|835):[a-z-]+", str(error))
    return str(error)


class Intake(unittest.TestCase):
    def both(self, data):
        """Run the intake and the independent re-derivation; they must agree. Returns (record, code)."""
        record = code = derived = other = None
        try:
            record = parse_835(data)
        except X12Error as error:
            code = code_of(error)
        try:
            derived = rederive_835(data)
        except IndependentX12Error as error:
            other = str(error)
        self.assertEqual(record is None, derived is None, (code, other))
        if record is not None:
            verify_835(data, record)
            self.assertEqual(json.loads(json.dumps(dataclasses.asdict(record))), derived)
        else:  # envelope-level refusals match exactly; past the tokenizer a multi-fault file may get different 835-stage codes
            try:
                tokenize(data)
            except X12Error as error:
                self.assertEqual((str(error), str(error)), (code, other))
        return record, code

    def refused(self, data, code):
        self.assertEqual(self.both(data), (None, code))
        self.assertEqual(self.derived_code(data), code)

    def derived_code(self, data):
        with self.assertRaises(IndependentX12Error) as caught:
            rederive_835(data)
        return str(caught.exception)

    def test_good_file_maps_to_cents(self):
        record, _ = self.both(GOOD)
        self.assertIsInstance(record, Remittance)
        self.assertEqual((record.interchange_control, record.group_control, record.set_control), ("000000905", "1", "0001"))
        self.assertEqual((record.total_cents, record.claims_paid_cents, record.plb_total_cents, record.forward_balance_cents),
                         (125050, 125050, 0, 0))
        self.assertEqual((record.effective_date, record.trace, record.dates), ("2026-10-05", "TRACE0001", (Dtm("405", "2026-10-03"),)))
        self.assertEqual((record.payer.name, record.payee.id), ("SYNTH STATE MEDICAID PROGRAM", PROVIDER))
        first, second = record.claims
        self.assertEqual((first.paid_cents, first.adjustments, first.dates), (40000, (Cas("PR", "1", 10000, ""),), (Dtm("232", "2026-10-01"),)))
        self.assertEqual((first.services[0].code, first.services[0].paid_cents, first.services[0].units), ("99213", 40000, "1"))
        self.assertEqual((second.paid_cents, second.adjustments[0].quantity, second.services), (85050, "1", ()))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.total_cents = 1

    def test_plb_carry_forward_is_kept_whole(self):
        record, _ = self.both(WITH_PLB)
        self.assertEqual(record.adjustments, (PlbAdjustment(PROVIDER, "2026-12-31", "FB", "CARRY0001", 10000),
                                              PlbAdjustment(PROVIDER, "2026-12-31", "WO", "WRITEOFF2", 2550)))
        self.assertEqual((record.total_cents, record.claims_paid_cents, record.plb_total_cents, record.forward_balance_cents),
                         (112500, 125050, 12550, 10000))
        record, _ = self.both(NEGATIVE_PLB)  # a negative adjustment raises the payment; the sign is kept as on the wire
        self.assertEqual((record.total_cents, record.plb_total_cents, record.forward_balance_cents), (155050, -30000, -30000))
        record, _ = self.both(FIXTURES["two-plb-segments"])
        self.assertEqual((len(record.adjustments), record.adjustments[2].reference, record.plb_total_cents), (3, "", 15050))

    def test_fixtures_agree_and_edges(self):
        for name, data in FIXTURES.items():
            with self.subTest(name):
                record, code = self.both(data)
                self.assertIsNotNone(record, code)
        self.assertEqual(self.both(FIXTURES["separators"])[0], parse_835(GOOD))
        record, _ = self.both(EDGE)
        self.assertEqual((record.claims[0].charge_cents, record.claims[0].paid_cents, record.claims[0].services[0].units),
                         (99999999999999, 1, ""))
        self.assertEqual(self.both(EMPTY)[0].claims, ())

    def test_cents_is_exact(self):
        for text, value in (("0", 0), ("0.1", 10), ("12.30", 1230), ("-5.5", -550), ("7", 700), ("0.05", 5), ("999999999999.99", 99999999999999)):
            self.assertEqual(cents(text), value)
        for text in ("1.234", "01", "-0", "-0.00", ".5", "5.", "1e3", "", "1,000", "+5", " 5", "1000000000000", "0x10", "NaN"):
            with self.assertRaises(X12Error, msg=text) as caught:
                cents(text)
            self.assertEqual(str(caught.exception), "835:amount")

    def test_totals_must_balance(self):
        for name, data in (("claims", edit(GOOD, "*1250.50*C*", "*1250.51*C*")), ("plb-ignored", edit(WITH_PLB, "*1125.00*C*", "*1250.50*C*")),
                           ("plb-doubled", build(remit("1125.00", *CLAIMS, PLB, PLB))),
                           ("claim", edit(GOOD, "*850.50*49.50*MC", "*850.51*49.50*MC")), ("empty", edit(EMPTY, "*0.00*C*", "*0.01*C*"))):
            with self.subTest(name):
                self.refused(data, "835:balance")

    def test_control_numbers_and_counts(self):
        for kwargs, code in (({"ic": "000000906"}, "x12:control"), ({"gec": "2"}, "x12:control"), ({"sc": "0002"}, "x12:control"),
                             ({"iea": 2}, "x12:count"), ({"ge": 2}, "x12:count"), ({"se": 3}, "x12:count"), ({"se": 99}, "x12:count"),
                             ({"icn": "0000009AB"}, "x12:isa"), ({"gc": "ABC", "gec": "ABC"}, "x12:control")):
            with self.subTest(kwargs):
                self.refused(build(remit("1250.50", *CLAIMS), **kwargs), code)

    def test_every_refusal_code(self):
        no_trn = [s for s in remit("0.00") if not s.startswith("TRN")]
        cases = {
            "x12:cap-bytes": GOOD + b"A" * MAX_BYTES, "x12:non-ascii": GOOD + "é".encode(), "x12:isa": b"ISA*00*" + b" " * 20,
            "x12:isa#prefix": b"XYZ" + GOOD[3:], "x12:separator": edit(GOOD, "*^*", "*:*"), "x12:separator#field": edit(GOOD, "SYNTHPAYER     ", "SYNTH~AYER     "),
            "x12:version": edit(GOOD, "*00501*", "*00401*"), "x12:truncated": GOOD[:-1], "x12:truncated#iea": GOOD[:GOOD.rindex(b"IEA")],
            "x12:trailing": GOOD + b"X", "x12:trailing#second-interchange": GOOD + GOOD,
            "x12:charset": edit(GOOD, "TRACE0001", "TRAC\x1fE0001"), "x12:segment": edit(GOOD, "~TRN*", "~trn*"),
            "x12:cap-elements": edit(GOOD, "DTM*405*20261003", "DTM*405*20261003" + "*" * 63),
            "x12:cap-element-length": edit(GOOD, "TRACE0001", "T" * 129), "x12:cap-repeats": edit(GOOD, "TRACE0001", "^".join("A" * 9)),
            "x12:cap-components": edit(GOOD, "TRACE0001", ":".join("A" * 17)),
            "x12:envelope": edit(GOOD, "~ST*835", "~ZZ*835"), "x12:shape": edit(GOOD, "TRACE0001", "TRACE0001^X"),
            "x12:shape#composite": edit(GOOD, "TRACE0001", "TRACE:0001"), "x12:extra": edit(GOOD, "1999999999", "1999999999*X"),
            "x12:extra#bpr": edit(GOOD, "CCP*", "CCP*BANK"),
            "835:production": build(remit("1250.50", *CLAIMS), usage="P"), "835:envelope": build(remit("1250.50", *CLAIMS), sets=2),
            "835:envelope#groups": build(remit("1250.50", *CLAIMS), groups=2), "835:envelope#type": edit(GOOD, "ST*835*", "ST*837*"),
            "835:version": build(remit("1250.50", *CLAIMS), ver="005010X222A1"), "835:version#purpose": edit(GOOD, "GS*HP*", "GS*HC*"),
            "835:segment": build(no_trn), "835:segment#extra": build(remit("1250.50", *CLAIMS, "REF*EV*X")),
            "835:segment#role": edit(GOOD, "N1*PE*", "N1*PR*"), "835:segment#order": build(remit("1125.00", PLB, *CLAIMS)),
            "835:segment#missing-payee": build(remit("0.00")[:-1]),
            "835:field": edit(GOOD, "TRACE0001", "TRACE@@@"), "835:field#trn01": edit(GOOD, "TRN*1*", "TRN*2*"),
            "835:field#svc": edit(GOOD, "HC:99213", "99213"), "835:field#cas": edit(GOOD, "CAS*PR*1*100.00~DTM*232", "CAS*PR~DTM*232"),
            "835:field#plb": edit(WITH_PLB, "FB:CARRY0001", "FBX:CARRY0001"), "835:field#blank": edit(GOOD, "CLAIMA001", ""),
            "835:amount": edit(GOOD, "*1250.50*C*", "*1250.505*C*"), "835:amount#negative-total": edit(GOOD, "*1250.50*C*", "*-1250.50*C*"),
            "835:amount#minus-zero": edit(GOOD, "*400.00*100.00*MC*", "*-0*100.00*MC*"), "835:amount#plb": edit(WITH_PLB, "*100.00*WO", "*1e2*WO"),
            "835:date": edit(GOOD, "*" * 11 + "20261005", "*" * 11 + "20261305"),
            "835:date#dtm": edit(GOOD, "DTM*405*20261003", "DTM*405*2026-10-03"), "835:date#leap": edit(GOOD, "DTM*232*20261001", "DTM*232*20270229"),
            "835:date#plb": edit(WITH_PLB, "*20261231*", "*20261232*"),
        }
        seen = set()
        for name, data in cases.items():
            with self.subTest(name):
                code = name.split("#")[0]
                seen.add(code)
                self.refused(data, code)
        self.assertEqual(len(seen), 23)
        for bad in ("text", None, bytearray(GOOD), [GOOD]):
            with self.assertRaises(X12Error) as caught:
                parse_835(bad)
            self.assertEqual(str(caught.exception), "x12:input")
            self.assertEqual(self.derived_code(bad), "x12:input")

    def test_error_text_never_carries_input(self):
        secret = "HUNTERSECRET"
        for data in (edit(GOOD, "SYNTH STATE MEDICAID PROGRAM", secret + "@"), edit(GOOD, "TRACE0001", secret + "^" * 9),
                     edit(GOOD, "CLAIMA001*1*500.00", "CLAIMA001*1*" + secret), edit(GOOD, "20261003", secret)):
            with self.assertRaises(X12Error) as caught:
                parse_835(data)
            error = caught.exception
            self.assertTrue(re.fullmatch(r"(x12|835):[a-z-]+", str(error)) and secret not in repr(error) + str(error.args))
            self.assertEqual((error.__cause__, error.__context__), (None, None))

    def test_caps_hold_at_the_boundary(self):
        def many(k):
            return build(remit("0.00", *["CLP*C%d*1*0.00*0.00*0.00*MC*P" % i for i in range(k)]))
        self.assertEqual(len(self.both(many(4990))[0].claims), 4990)  # 5,000 segments after the ISA, IEA included
        self.refused(many(4991), "x12:cap-segments")
        self.assertEqual(self.both(edit(GOOD, "TRACE0001", "T" * 60))[1], None)
        self.assertEqual(self.both(edit(GOOD, "TRACE0001", "T" * 61))[1], "835:field")
        self.assertEqual(len(tokenize(edit(GOOD, "DTM*405*20261003", "DTM*405*20261003" + "*" * 62)).groups), 1)
        self.assertEqual(len(tokenize(edit(GOOD, "TRACE0001", "T" * 128)).groups), 1)
        self.assertEqual(len(tokenize(edit(GOOD, "TRACE0001", "^".join("A" * 8))).groups), 1)
        self.assertEqual(len(tokenize(edit(GOOD, "TRACE0001", ":".join("A" * 16))).groups), 1)

    def test_hostile_corpus(self):
        head = GOOD[:GOOD.index(b"~") + 1]
        hostile = [
            ("x12:cap-bytes", head + b"~" * MAX_BYTES), ("x12:cap-segments", head + b"~" * 6000),
            ("x12:cap-elements", head + b"GS" + b"*" * 60000 + b"~IEA*0*000000905~"),
            ("x12:cap-element-length", edit(GOOD, "TRACE0001", "^" * 5000)), ("x12:cap-element-length", edit(GOOD, "TRACE0001", "A" * 500000)),
            ("x12:charset", edit(GOOD, "TRN*1", "TRN\r\n1")), ("x12:trailing", GOOD + b"\r\n"),
            ("x12:segment", edit(GOOD, "TRACE0001", "TRACE~0001")), ("x12:envelope", edit(GOOD, "~GS*", "~GS*X~GS*")),
        ]
        for want, data in hostile:
            with self.subTest(want):
                self.refused(data, want)
        self.refused(edit(GOOD, "TRACE0001", "TRACE*0001"), "x12:extra")  # an injected element separator becomes a refused extra field
        self.assertIsNotNone(self.both(edit(GOOD, "TRACE0001", "T" * 60))[0])

    def test_every_truncation_is_refused(self):
        for data in (GOOD, WITH_PLB):
            for n in range(len(data)):
                self.assertIsNone(self.both(data[:n])[0], n)

    def test_mutation_fuzz_agrees(self):
        rng, seen, accepted = random.Random(835), set(), 0
        alphabet = "*~^:ABZ09.-, \x00\n"
        for i in range(3000):
            data = bytearray(rng.choice((GOOD, WITH_PLB, NEGATIVE_PLB)))
            for _ in range(rng.randint(1, 3)):
                at, kind = rng.randrange(len(data)), rng.randrange(4)
                if kind == 0:
                    del data[at]
                elif kind == 1:
                    data.insert(at, ord(rng.choice(alphabet)))
                elif kind == 2:
                    data[at] = ord(rng.choice(alphabet))
                else:
                    data[at:at] = data[at:at + rng.randint(1, 40)]
            record, code = self.both(bytes(data))
            seen.add(code)
            accepted += record is not None
        self.assertGreaterEqual(len(seen), 8)
        self.assertTrue(0 < accepted < 3000)

    def test_verifier_catches_a_wrong_record(self):
        record = parse_835(WITH_PLB)
        verify_835(WITH_PLB, record)
        for wrong in (dataclasses.replace(record, forward_balance_cents=0), dataclasses.replace(record, adjustments=record.adjustments[:1]),
                      dataclasses.replace(record, claims=record.claims[::-1]), parse_835(GOOD), "record", None):
            with self.assertRaises(IndependentX12Error) as caught:
                verify_835(WITH_PLB, wrong)
            self.assertEqual(str(caught.exception), "835:disagree")

    def test_fixture_identifiers_are_fictional(self):
        def luhn_ok(digits):
            total = sum((d * 2 - 9 if d > 4 else d * 2) if i % 2 else d for i, d in enumerate(map(int, reversed(digits))))
            return total % 10 == 0
        found = set(re.findall(r"(?<![0-9])[0-9]{10}(?![0-9])", "".join(d.decode() for d in FIXTURES.values())))
        self.assertTrue(found and not any(luhn_ok("80840" + n) for n in found), found)
        self.assertTrue(luhn_ok("80840" + "1234567893"))  # the checker accepts a Luhn-valid NPI, so the fixtures' failure is real
        self.assertIn(b"*0*T*:", GOOD)  # ISA15 is T: synthetic only

    def test_modules_are_read_only_and_call_no_owner(self):
        allowed = {"app/x12_tokenizer.py": {"__future__", "dataclasses", "re", "string", "typing", "app.mirror.error_boundary"},
                   "app/x12_835_intake.py": {"__future__", "dataclasses", "datetime", "re", "app.mirror.error_boundary", "app.x12_tokenizer"},
                   "app/x12_835_independent.py": {"__future__", "dataclasses", "decimal", "json", "re", "datetime", "typing"}}
        for path, names in allowed.items():
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
            imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            self.assertLessEqual(imported, names, path)
            self.assertFalse({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} & {"open", "exec", "eval", "__import__"}, path)


if __name__ == "__main__":
    unittest.main()
