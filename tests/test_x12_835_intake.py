"""Synthetic 835 intake: good files, every refusal code, control and balance faults, PLB carry-forward, caps, a hostile corpus,
and agreement of the independent re-derivation on every fixture. Fixtures are fictional: no real NPI, name or payer."""

import ast
import dataclasses
import decimal
import hashlib
import json
import random
import re
import sys
import unittest
from pathlib import Path

from app.x12_835_independent import IndependentX12Error, origin_id as independent_origin_id, pool as independent_pool, rederive_835, verify_835
from app.x12_835_intake import Cas, Dtm, PlbAdjustment, Remittance, cents, origin_id, parse_835, pool
from app.x12_tokenizer import MAX_BYTES, X12Error, tokenize

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "1234567890"  # fictional NPI shape; the Luhn test below proves it cannot be a real one
CLAIMS = [
    "CLP*CLAIMA001*1*500.00*400.00*100.00*MC*PAYERCTL001*11*1", "CAS*PR*1*50.00", "DTM*232*20261001",
    "SVC*HC:99213*500.00*450.00**1", "CAS*PR*3*50.00", "DTM*472*20261001",
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
EDGE = build(remit("0.01", "CLP*EDGE0001*1*999999999999.99*0.01*0.00*MC*PAYERCTL003", "CAS*CO*45*999999999999.98",
                                "SVC*HC:J0001*999999999999.99*999999999999.99"))
BALANCED = build(remit("350.00", "CLP*MULTI001*1*300.00*200.00*0.00*MC*P1", "SVC*HC:A0001*100.00*100.00", "SVC*HC:A0002*200.00*100.00", "CAS*CO*45*100.00",
                       "CLP*MULTI002*1*100.00*150.00*0.00*MC*P2", "CAS*CO*45*-50.00"))
FIXTURES = {"good": GOOD, "plb": WITH_PLB, "negative-plb": NEGATIVE_PLB, "empty": EMPTY, "edge": EDGE,
            "separators": GOOD.decode().translate(str.maketrans("*^:~", "|!;$")).encode(),
            "balanced-multi": BALANCED, "two-plb-segments": build(remit("1100.00", *CLAIMS, PLB, f"PLB*{PROVIDER}*20261231*CS*25.00"))}


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
        self.assertEqual((record.interchange_sender, record.interchange_receiver, record.group_sender, record.group_receiver),
                         ("SYNTHPAYER", "SYNTHPROVIDER", "SYNTHPAYER01", "SYNTHPROVIDER"))
        self.assertEqual((record.total_cents, record.claims_paid_cents, record.plb_total_cents, record.forward_balance_cents),
                         (125050, 125050, 0, 0))
        self.assertEqual((record.effective_date, record.trace, record.dates), ("2026-10-05", "TRACE0001", (Dtm("405", "2026-10-03"),)))
        self.assertEqual((record.payer.name, record.payee.id), ("SYNTH STATE MEDICAID PROGRAM", PROVIDER))
        first, second = record.claims
        self.assertEqual((first.paid_cents, first.adjustments, first.dates), (40000, (Cas("PR", "1", 5000, ""),), (Dtm("232", "2026-10-01"),)))
        self.assertEqual((first.services[0].code, first.services[0].paid_cents, first.services[0].units), ("99213", 45000, "1"))
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
                           ("claim", edit(edit(GOOD, "*850.50*49.50*MC", "*850.51*49.50*MC"), "CAS*PR*2*49.50*1", "CAS*PR*2*49.49*1")), ("empty", edit(EMPTY, "*0.00*C*", "*0.01*C*"))):
            with self.subTest(name):
                self.refused(data, "835:balance")

    def test_a_bad_block_is_a_raw_row_and_the_rest_parses(self):  # one bad claim no longer sinks the whole remittance
        shifted = edit(edit(GOOD, "*500.00*400.00*100.00*MC", "*500.00*500.00*100.00*MC"), "*900.00*850.50*49.50", "*900.00*750.50*49.50")
        bal, fld, amt, date = "835:claim-balance", "835:field", "835:amount", "835:date"
        # name, data, the code each RAW row is flagged with, how many RAW rows, whether an unreadable amount holds every row, which list lost them
        for name, data, code, raw, unverified, lost in (
                ("shifted-between-claims", shifted, bal, 2, False, "claims"), ("svc03-over-claim", edit(GOOD, "*500.00*450.00**1", "*500.00*40000.00**1"), bal, 1, False, "claims"),
                ("svc-inflated-together", edit(GOOD, "*500.00*450.00**1", "*40050.00*40000.00**1"), bal, 1, False, "claims"),
                ("svc-short-of-claim", edit(GOOD, "*500.00*450.00**1", "*400.00*350.00**1"), bal, 1, False, "claims"),
                ("service-cas-zero", edit(GOOD, "CAS*PR*3*50.00", "CAS*PR*3*0.00"), bal, 1, False, "claims"),
                ("claim-cas-missing", edit(GOOD, "CAS*PR*2*49.50*1", "CAS*PR*2*0.00*1"), bal, 1, False, "claims"),
                ("sign", edit(GOOD, "CAS*PR*2*49.50*1", "CAS*PR*2*-49.50*1"), bal, 1, False, "claims"),
                ("service-cas-over", edit(GOOD, "CAS*PR*3*50.00", "CAS*PR*3*60.00"), bal, 1, False, "claims"),
                ("svc-shape", edit(GOOD, "HC:99213", "99213"), fld, 1, False, "claims"),
                ("cas-short", edit(GOOD, "CAS*PR*1*50.00~DTM*232", "CAS*PR~DTM*232"), fld, 1, False, "claims"),
                ("clp01-blank", edit(GOOD, "CLAIMA001", ""), fld, 1, False, "claims"),
                ("clp06-blank", edit(GOOD, "*100.00*MC*PAYERCTL001", "*100.00**PAYERCTL001"), fld, 1, False, "claims"),
                ("dtm-leap", edit(GOOD, "DTM*232*20261001", "DTM*232*20270229"), date, 1, False, "claims"),
                ("clp03-unreadable", edit(GOOD, "*500.00*400.00*100.00*MC", "*5e2*400.00*100.00*MC"), amt, 1, True, "claims"),
                ("clp04-minus-zero", edit(GOOD, "*400.00*100.00*MC*", "*-0*100.00*MC*"), amt, 1, True, "claims"),
                ("clp05-unreadable", edit(GOOD, "*400.00*100.00*MC", "*400.00*1e2*MC"), amt, 1, True, "claims"),
                ("clp04-three-decimals", edit(GOOD, "*500.00*400.00*100.00*MC", "*500.00*400.005*100.00*MC"), amt, 1, True, "claims"),
                ("plb01-blank", edit(WITH_PLB, "PLB*1234567890*", "PLB**"), fld, 2, False, "adjustments"),
                ("plb02-bad-date", edit(WITH_PLB, "*20261231*", "*20261232*"), date, 2, False, "adjustments"),
                ("plb-amount-unreadable", edit(WITH_PLB, "*100.00*WO", "*1e2*WO"), amt, 1, True, "adjustments")):
            with self.subTest(name):
                record, _ = self.both(data)
                self.assertIsNotNone(record)
                bad = [r for r in record.rows if r.key[0] == "RAW"]
                self.assertEqual(([r.flags for r in bad], record.balance_unverified), ([(code,)] * raw, unverified))
                self.assertEqual(None in [r.amount_cents for r in bad], unverified)
                self.assertEqual([record.claims_paid_cents, record.plb_total_cents, record.forward_balance_cents].count(None),
                                 3 if unverified else 0)  # a partial sum would look complete: totals exist only when every amount read
                self.assertTrue(all(r.amount_cents is not None for r in record.rows if r.key[0] != "RAW"))
                self.assertEqual(len(getattr(record, lost)) + raw, 2)
                self.assertEqual(len(record.rows), len(parse_835(WITH_PLB if lost == "adjustments" else GOOD).rows))  # no row folded away
        self.assertIn(b"*1250.50*C*", shifted)  # the shift keeps the file total, so the balance check passes and only the claim check sees it
        self.assertFalse(self.both(shifted)[0].balance_unverified)
        record, _ = self.both(BALANCED)  # two services, a negative adjustment, adjustments at both levels
        self.assertEqual((record.total_cents, [c.paid_cents for c in record.claims]), (35000, [20000, 15000]))

    def test_isa_and_gs_content_is_validated_and_carried(self):
        head = GOOD.decode()[4:105].split("*")

        def isa(**fields):
            parts = list(head)
            for key, value in fields.items():
                parts[int(key[1:]) - 1] = value
            return ("ISA*" + "*".join(parts)).encode() + GOOD[105:]
        for name, data in (("i01", isa(i01="99")), ("i01-blank-required", isa(i02="ABCDEFGHIJ")), ("i03", isa(i03="02")), ("i03-blank-required", isa(i04="ABCDEFGHIJ")),
                           ("i05", isa(i05="AA")), ("i05-blank", isa(i05="  ")), ("i06-blank", isa(i06=" " * 15)), ("i06-control", isa(i06="SYNTHPAYER    ")),
                           ("i06-leading", isa(i06=" SYNTHPAYER    ")), ("i07", isa(i07="99")), ("i08-blank", isa(i08=" " * 15)),
                           ("i09-month", isa(i09="261305")), ("i09-day", isa(i09="260230")), ("i09-digits", isa(i09="26100A")),
                           ("i10-hour", isa(i10="2460")), ("i10-minute", isa(i10="1260")), ("i10-digits", isa(i10="12AB")),
                           ("i02-control", isa(i01="03", i02="ABCDE\x01GHIJ"))):
            with self.subTest(name):
                self.refused(data, "x12:isa")
        for name, data in (("i01-03", isa(i01="03", i02="ABCDEFGHIJ")), ("i03-01", isa(i03="01", i04="ABCDEFGHIJ")), ("i05-01", isa(i05="01")),
                           ("i06-an", isa(i06="SYNTH@PAYER    ")), ("i08-an", isa(i08="(PROV)+ID=1;#?!")),
                           ("gs02-an", edit(GOOD, "SYNTHPAYER01*", "SYNTH@PAYER01*")), ("gs03-an", edit(GOOD, "*SYNTHPROVIDER*2", "*(SYN)+PROV@1*2")),
                           ("leap-day", isa(i09="240229")), ("gs-hhmmss", edit(GOOD, "*1200*1*X*", "*120059*1*X*")),
                           ("gs-15", edit(GOOD, "SYNTHPAYER01*", "SYNTHPAYER0123*")), ("gs-2", edit(GOOD, "SYNTHPAYER01*", "AB*"))):
            with self.subTest(name):
                self.assertIsNotNone(self.both(data)[0])
        for name, old, new in (("gs02-short", "SYNTHPAYER01*", "S*"), ("gs02-long", "SYNTHPAYER01*", "SYNTHPAYER01234567*"), ("gs02-empty", "HP*SYNTHPAYER01*", "HP**"),
                               ("gs02-padded", "SYNTHPAYER01*", "SYNTHPAYER01 *"),
                               ("gs03-short", "*SYNTHPROVIDER*2", "*S*2"),
                               ("gs04-month", "*20261005*1200*1*", "*20261305*1200*1*"), ("gs04-short", "*20261005*1200*1*", "*261005*1200*1*"),
                               ("gs04-year", "*20261005*1200*1*", "*18991005*1200*1*"), ("gs05-hour", "*1200*1*X*", "*2460*1*X*"), ("gs05-short", "*1200*1*X*", "*12*1*X*"),
                               ("gs05-minute", "*1200*1*X*", "*1260*1*X*"), ("gs07", "*1*X*0050", "*1*T*0050"), ("gs07-empty", "*1*X*0050", "*1**0050")):
            with self.subTest(name):
                self.refused(edit(GOOD, old, new), "x12:envelope")

    def test_id_charset_excludes_this_files_delimiters_only(self):
        record, _ = self.both(edit(GOOD, "SYNTHPAYER01*", "SYNTH@PAYER01*"))
        self.assertEqual(record.group_sender, "SYNTH@PAYER01")
        self.assertEqual(self.both(edit(GOOD, "SYNTHPAYER     ", "SYNTH@(+)PAYER "))[0].interchange_sender, "SYNTH@(+)PAYER")
        other = FIXTURES["separators"]  # element |, repeat !, component ;, terminator $: * and ^ are ordinary characters here
        self.assertEqual(self.both(edit(other, "SYNTHPAYER01|", "SYN*^PAYER01|"))[0].group_sender, "SYN*^PAYER01")
        for old, new, code in (("SYNTHPAYER01*", "SYNTHPAYER01*", "x12:charset"), ("SYNTHPAYER01*", "SYNTH:PAYER01*", "x12:shape"),
                               ("SYNTHPAYER01*", "SYNTH^PAYER01*", "x12:shape"), ("SYNTHPAYER     ", "SYNTH^PAYER    ", "x12:separator"),
                               ("SYNTHPAYER01*", "SYNTH*PAYER01*", "x12:extra")):
            with self.subTest(new):
                self.refused(edit(GOOD, old, new), code)
        for new, code in (("SYN|PAYER01|", "x12:extra"), ("SYN!PAYER01|", "x12:shape"), ("SYN;PAYER01|", "x12:shape")):
            with self.subTest(new):
                self.refused(edit(other, "SYNTHPAYER01|", new), code)

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
            "835:field": edit(GOOD, "TRACE0001", "TRACE@@@"), "835:field#debit": edit(GOOD, "*1250.50*C*", "*1250.50*D*"), "835:field#trn01": edit(GOOD, "TRN*1*", "TRN*2*"),
            # a fault inside one claim or adjustment is a RAW row, not a refusal: see test_a_bad_block_is_a_raw_row_and_the_rest_parses
            "835:amount#bpr02-unreadable": edit(GOOD, "*1250.50*C*", "*1250.505*C*"),  # nothing can balance, so the whole file refuses
            "835:amount#negative-total": edit(GOOD, "*1250.50*C*", "*-1250.50*C*"),
            "835:date": edit(GOOD, "*" * 11 + "20261005", "*" * 11 + "20261305"), "835:date#dtm": edit(GOOD, "DTM*405*20261003", "DTM*405*2026-10-03"),
        }
        seen = set()
        for name, data in cases.items():
            with self.subTest(name):
                code = name.split("#")[0]
                seen.add(code)
                self.refused(data, code)
        self.assertEqual((len(cases), len(seen)), (40, 23))
        for bad in ("text", None, bytearray(GOOD), [GOOD]):
            with self.assertRaises(X12Error) as caught:
                parse_835(bad)
            self.assertEqual(str(caught.exception), "x12:input")
            self.assertEqual(self.derived_code(bad), "x12:input")

    def test_error_text_never_carries_input(self):
        secret = "HUNTERSECRET"
        for data in (edit(GOOD, "SYNTH STATE MEDICAID PROGRAM", secret + "@"), edit(GOOD, "TRACE0001", secret + "^" * 9),
                     edit(GOOD, "*1250.50*C*", "*" + secret + "*C*"), edit(GOOD, "20261003", secret)):
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

    def test_unmodeled_envelope_elements_are_refused(self):
        for name, data, code in (("SE03", edit(GOOD, "*0001~GE*", "*0001*X~GE*"), "x12:extra"),
                                 ("GE03", edit(GOOD, "GE*1*1~", "GE*1*1*X~"), "x12:extra"),
                                 ("IEA03", edit(GOOD, "IEA*1*000000905~", "IEA*1*000000905*X~"), "x12:extra"),
                                 ("GS09", edit(GOOD, "*X*005010X221A1", "*X*005010X221A1*Z"), "x12:extra"),
                                 ("ST04", edit(GOOD, "ST*835*0001~", "ST*835*0001*005010X221A1*Z~"), "x12:extra"),
                                 ("ST03", edit(GOOD, "ST*835*0001~", "ST*835*0001*005010X222A1~"), "x12:version")):
            with self.subTest(name):
                self.refused(data, code)
        self.assertIsNotNone(self.both(edit(GOOD, "ST*835*0001~", "ST*835*0001*005010X221A1~"))[0])

    def test_years_are_bounded(self):
        for year, ok in (("0001", False), ("1899", False), ("1900", True), ("2199", True), ("2200", False), ("9999", False)):
            for old, new in (("DTM*405*20261003", f"DTM*405*{year}1003"), ("*" * 11 + "20261005", "*" * 11 + f"{year}1005")):
                with self.subTest(year=year, field=old[:3]):
                    data = edit(GOOD, old, new)
                    if ok:
                        self.assertIsNotNone(self.both(data)[0])
                    else:
                        self.refused(data, "835:date")

    def test_caps_are_counted_before_splitting(self):
        head = GOOD[:GOOD.index(b"~") + 1]
        def oversplit(data):
            seen = []
            def probe(frame, event, arg):
                if event == "c_call" and arg.__name__ == "split" and isinstance(arg.__self__, str):
                    seen.append(arg.__self__)
            sys.setprofile(probe)
            try:
                self.both(data)
            finally:
                sys.setprofile(None)
            return [s for s in seen if s.count("~") > 5000 or ("~" not in s and s.count("*") > 64)]
        self.assertEqual(oversplit(head + b"~" * 6000), [])
        self.assertEqual(oversplit(head + b"GS" + b"*" * 60000 + b"~IEA*0*000000905~"), [])

    def test_byte_cap_boundary(self):
        padded = GOOD + b" " * (MAX_BYTES - len(GOOD))
        self.refused(padded, "x12:trailing")  # exactly 1<<20 bytes passes the cap and fails for another reason
        self.refused(padded + b" ", "x12:cap-bytes")

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

    def test_verifier_demands_exact_types(self):
        record = parse_835(GOOD)
        claim = record.claims[0]
        verify_835(GOOD, record)

        class Text(str):
            pass

        def swap(**fields):
            return dataclasses.replace(record, **fields)

        def swap_claim(**fields):
            return swap(claims=(dataclasses.replace(claim, **fields), *record.claims[1:]))
        wrong = {"float-total": swap(total_cents=125050.0), "bool-for-int": swap(forward_balance_cents=False), "list-claims": swap(claims=list(record.claims)),
                 "dict-payer": swap(payer=dataclasses.asdict(record.payer)), "float-claim": swap_claim(charge_cents=50000.0),
                 "bool-claim": swap_claim(charge_cents=True), "list-adjustments": swap_claim(adjustments=list(claim.adjustments)),
                 "list-services": swap_claim(services=list(claim.services)), "dict-claim": swap(claims=(dataclasses.asdict(claim), *record.claims[1:])),
                 "float-line": swap_claim(services=(dataclasses.replace(claim.services[0], paid_cents=45000.0),)),
                 "str-subclass": swap(trace=Text("TRACE0001")), "bytes": swap(trace=b"TRACE0001"), "int-for-str": swap(trace=1),
                 "list-dates": swap(dates=list(record.dates)), "set-claims": swap(claims=set(record.claims))}
        for name, bad in wrong.items():
            with self.subTest(name):
                with self.assertRaises(IndependentX12Error) as caught:
                    verify_835(GOOD, bad)
                self.assertEqual(str(caught.exception), "835:disagree")

    def test_decimal_context_is_not_ambient(self):
        want = rederive_835(EDGE)
        with decimal.localcontext() as ambient:
            ambient.prec = 6
            self.assertEqual(rederive_835(EDGE), want)
            self.assertEqual(self.both(EDGE)[0].claims[0].charge_cents, 99999999999999)
            ambient.prec = 1
            self.assertEqual(rederive_835(GOOD)["total_cents"], 125050)

    def test_fixture_identifiers_are_fictional(self):
        def luhn_ok(digits):
            total = sum((d * 2 - 9 if d > 4 else d * 2) if i % 2 else d for i, d in enumerate(map(int, reversed(digits))))
            return total % 10 == 0
        found = set(re.findall(r"(?<![0-9])[0-9]{10}(?![0-9])", "".join(d.decode() for d in FIXTURES.values())))
        self.assertTrue(found and not any(luhn_ok("80840" + n) for n in found), found)
        self.assertTrue(luhn_ok("80840" + "1234567893"))  # the checker accepts a Luhn-valid NPI, so the fixtures' failure is real
        self.assertIn(b"*0*T*:", GOOD)  # ISA15 is T: synthetic only

    def test_modules_are_read_only_and_call_no_owner(self):
        allowed = {"app/x12_tokenizer.py": {"__future__", "dataclasses", "datetime", "re", "string", "typing", "app.mirror.error_boundary"},
                   "app/x12_835_intake.py": {"__future__", "dataclasses", "datetime", "hashlib", "re", "app.mirror.error_boundary", "app.x12_tokenizer"},
                   "app/x12_835_independent.py": {"__future__", "dataclasses", "decimal", "hashlib", "re", "datetime", "typing"}}
        for path, names in allowed.items():
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
            imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            self.assertLessEqual(imported, names, path)
            self.assertFalse({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} & {"open", "exec", "eval", "__import__"}, path)

    # ---- S3a fold keys (hold-release r4.2 sections 2 and 14: M21, M21z, M22) ----

    def rows(self, total, *segments, **o):
        record, code = self.both(build(remit(total, *segments), **o))
        self.assertIsNotNone(record, code)
        return record, {r.key: r for r in record.rows}

    def test_tag_comes_from_clp02_alone(self):
        record, rows = self.rows("60.00", "CLP*C1*1*100.00*100.00*0.00*MC*X1", "CLP*C2*22*-40.00*-40.00*0.00*MC*X2")
        self.assertEqual([(r.key, r.amount_cents, r.flags) for r in record.rows], [(("CLP", "X1"), 10000, ()), (("REV", "X2"), -4000, ())])
        self.assertEqual(rows[("CLP", "X1")].raw, "CLP\x1fC1\x1f1\x1f100.00\x1f100.00\x1f0.00\x1fMC\x1fX1\n")
        for status in ("2", "4", "19", "20", "23"):  # only 22 is a reversal
            self.assertEqual(self.rows("1.00", f"CLP*C*{status}*1.00*1.00*0.00*MC*K")[0].rows[0].key, ("CLP", "K"))

    def test_zero_and_sign_rows(self):  # M21z
        _, rows = self.rows("0.00", "CLP*D1*4*0.00*0.00*0.00*MC*DEN1")
        self.assertEqual((rows[("CLP", "DEN1")].amount_cents, rows[("CLP", "DEN1")].flags), (0, ()))
        record, _ = self.rows("30.00", "CLP*R1*22*30.00*30.00*0.00*MC*REVX")
        self.assertEqual((record.rows[0].key, record.rows[0].flags), (("REV", "REVX"), ("rev_sign",)))
        record, _ = self.rows("5.00", "CLP*P1*1*35.00*35.00*0.00*MC*PAYK", "CLP*P2*1*-30.00*-30.00*0.00*MC*NEGK")
        self.assertEqual([(r.key, r.flags) for r in record.rows], [(("CLP", "PAYK"), ()), (("CLP", "NEGK"), ("clp_sign",))])
        record, _ = self.rows("0.00", "CLP*Z1*1*50.00*50.00*0.00*MC*ZZ1", "CLP*Z2*1*-50.00*-50.00*0.00*MC*ZZ1")  # blocks that cancel: the net is 0, the negative block still shows
        self.assertEqual([(r.key, r.amount_cents, r.flags) for r in record.rows], [(("CLP", "ZZ1"), 0, ("clp_sign",))])

    def test_a_reissue_flipping_the_sign_keeps_its_key(self):  # M21z: S3 sees the same cell, not a second one
        other = "CLP*G*1*50.00*50.00*0.00*MC*G1"
        for tag, status, plus, minus in (("REV", "22", "100.00", "0.00"), ("CLP", "1", "100.00", "0.00")):
            a = self.rows(minus, f"CLP*F*{status}*-50.00*-50.00*0.00*MC*FLIP", other)[1][(tag, "FLIP")]
            b = self.rows(plus, f"CLP*F*{status}*50.00*50.00*0.00*MC*FLIP", other)[1][(tag, "FLIP")]
            self.assertEqual((a.amount_cents, b.amount_cents, a.raw == b.raw), (-5000, 5000, False), tag)
            self.assertEqual([a.flags, b.flags], [("clp_sign",) if tag == "CLP" else (), ("rev_sign",) if tag == "REV" else ()], tag)

    def test_blocks_with_one_key_fold_in_file_order(self):  # M21
        a, b = "CLP*A*1*100.00*100.00*0.00*MC*X", "CLP*B*1*50.00*50.00*0.00*MC*X"
        record, _ = self.rows("150.00", a, b)
        (row,) = record.rows
        self.assertEqual((row.key, row.amount_cents, row.raw.count("\n")), (("CLP", "X"), 15000, 2))
        self.assertNotEqual(self.rows("150.00", b, a)[0].rows[0].raw, row.raw)  # a reordered reissue differs, which S3 holds as CONFLICT
        self.assertEqual(self.rows("150.00", a, b)[0].rows, record.rows)
        only_b = self.rows("50.00", b)[0].rows[0]  # the review's T1/T2 case: [B] and [A, B] are one key with different raw
        self.assertEqual((only_b.key, only_b.raw == row.raw), (row.key, False))

    def test_plb_rows_fold_per_tuple(self):
        def plb(*tuples):
            return f"PLB*{PROVIDER}*20261231*" + "*".join(tuples)
        claim = "CLP*C1*1*200.00*200.00*0.00*MC*X"
        key = ("PLB", PROVIDER, "2026-12-31", "FB", "REFA")
        _, rows = self.rows("100.00", claim, plb("FB:REFA", "50.00"), plb("FB:REFA", "30.00", "WO", "20.00"))
        self.assertEqual((rows[key].amount_cents, rows[key[:3] + ("WO", "")].amount_cents), (-8000, -2000))
        self.assertEqual(self.rows("250.00", claim, plb("FB:REFA", "-50.00"))[1][key].amount_cents, 5000)  # a negative wire amount raises the payment
        zero = self.rows("200.00", claim, plb("FB:REFA", "10.00", "FB:REFA", "-10.00"))[1][key]
        self.assertEqual((zero.amount_cents, zero.flags), (0, ()))
        self.assertEqual(origin_id("S", key), hashlib.sha3_256("".join(f"{len(p)}:{p}" for p in ("RR/835/ORIGIN/v1", "S", *key)).encode()).hexdigest())

    def test_m22_example_rows(self):  # A 300, B 200, PLB +50 against an earlier cell, BPR02 450
        record, _ = self.rows("450.00", "CLP*A*1*300.00*300.00*0.00*MC*A1", "CLP*B*1*200.00*200.00*0.00*MC*B1", f"PLB*{PROVIDER}*20261231*FB:A1*50.00")
        self.assertEqual([(r.key, r.amount_cents) for r in record.rows],
                         [(("CLP", "A1"), 30000), (("CLP", "B1"), 20000), (("PLB", PROVIDER, "2026-12-31", "FB", "A1"), -5000)])

    def test_raw_keys(self):
        def raw_row(total, *segments):
            (row,) = [r for r in self.rows(total, *segments)[0].rows if r.key[0] == "RAW"]
            self.assertEqual(row.key, ("RAW", hashlib.sha3_256(f"13:RR/835/RAW/v1{len(row.raw)}:{row.raw}".encode()).hexdigest()))  # the domain tag, length-prefixed
            return row
        bad7 = raw_row("1.00", "CLP*C1*1*1.00*1.00*0.00*MC*BAD@7")  # CLP07 unreadable
        self.assertEqual((bad7.amount_cents, bad7.flags, self.rows("1.00", "CLP*C1*1*1.00*1.00*0.00*MC*BAD@7")[0].claims), (100, ("835:field",), ()))
        bad2 = raw_row("1.00", "CLP*C1*zz!*1.00*1.00*0.00*MC*OK7")  # CLP02 unreadable
        self.assertNotEqual(bad7.key, bad2.key)
        self.assertIn("CAS", raw_row("1.00", "CLP*C1*1*1.00*1.00*0.00*MC*", "CAS*PR*1*0.00").raw)  # a blank CLP07 keys RAW, with its children in the raw
        again = self.rows("1.00", "CLP*C1*1*1.00*1.00*0.00*MC*BAD@7", icn="000000906")[0].rows
        self.assertEqual(again, (bad7,))  # the key is the block, not the file around it
        moved = parse_835(build(remit("1.00", "CLP*C1*1*1.00*1.00*0.00*MC*BAD@7")).decode().translate(str.maketrans("*^:~", "|!;$")).encode())
        self.assertEqual(moved.rows, (bad7,))  # the same block under other delimiters keys the same
        self.assertEqual(origin_id("S", bad7.key), hashlib.sha3_256(f"16:RR/835/ORIGIN/v1" "1:S" "3:RAW" f"{len(bad7.key[1])}:{bad7.key[1]}".encode()).hexdigest())
        reason = raw_row("1.00", "CLP*C1*1*6.00*6.00*0.00*MC*K", f"PLB*{PROVIDER}*20261231*FBX:R*5.00")  # an unknown PLB reason
        self.assertEqual(reason.amount_cents, -500)
        self.assertEqual(raw_row("1.00", "CLP*C1*1*6.00*6.00*0.00*MC*K", f"PLB*{PROVIDER}*20261231*FB:A:B*5.00").amount_cents, -500)  # a composite reference

    def test_trailing_empties_are_not_content(self):  # F5: both encoders drop trailing empty elements, repeats and components
        keys = {self.rows("1.00", f"CLP*C1*1*1.00*1.00*0.00*MC*BAD@7{tail}")[0].rows[0].key for tail in ("", "*", "**", "^", ":", "^:*^")}
        self.assertEqual((len(keys), next(iter(keys))[0]), (1, "RAW"))

    def test_flags_are_per_block(self):  # F6: a REV +30.00 beside a REV -100.00 is still seen, in the folded row too
        record, rows = self.rows("30.00", "CLP*A*22*-100.00*-100.00*0.00*MC*R1", "CLP*B*22*30.00*30.00*0.00*MC*R1", "CLP*C*1*100.00*100.00*0.00*MC*P1")
        self.assertEqual((rows[("REV", "R1")].amount_cents, rows[("REV", "R1")].flags), (-7000, ("rev_sign",)))
        self.assertEqual(rows[("CLP", "P1")].flags, ())

    def test_pool_and_origin_follow_trn03_and_trn02(self):
        record, _ = self.both(GOOD)
        self.assertEqual(pool("S", record), ("S", "1999999999", "TRACE0001"))
        other = self.both(edit(GOOD, "1999999999", "1888888888"))[0]
        self.assertEqual((pool("S", other), other.trace == record.trace), (("S", "1888888888", "TRACE0001"), True))  # two payers, one TRN02: two pools
        self.assertNotEqual(pool("S", record), pool("T", record))
        self.assertEqual(origin_id("S", ("REV", "X1")), hashlib.sha3_256(b"16:RR/835/ORIGIN/v1" b"1:S" b"3:REV" b"2:X1").hexdigest())
        self.assertNotEqual(origin_id("S", ("CLP", "CLP/A")), origin_id("S/CLP", ("CLP", "A")))  # F4: the old "/"-joined id gave one id to both
        for name, data in FIXTURES.items():
            record = parse_835(data)
            for row in record.rows:
                self.assertEqual(independent_origin_id("S", list(row.key)), origin_id("S", row.key), name)
            self.assertEqual(independent_pool("S", rederive_835(data)), pool("S", record), name)


if __name__ == "__main__":
    unittest.main()
