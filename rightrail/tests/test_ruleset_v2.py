"""Signed rule set RULESET/v2 (conformance/RULESET_V2.md): eligibility read from the eligibility fact records (kind 1,
conformance/ELIG_EXTRACT_V1.md), with the eligibility source (7), its maximum age and the state's aid table in the signed
record.

- The twin codec app/right_rail_ruleset_codec.py against this file's own encoder, written from the spec alone: round
  trips, must-reject vectors with the refused part, every proper prefix refused, and the Lean model's golden digests.
- Version 1 is still read, unchanged: a version 1 record may name neither source 7, nor reasons 24 to 28, nor the
  eligibility node.
- The Lean decoder and interpreter (`ruleset_admit`: admission lines and EVAL questions) against this file's refusals and
  the reference evaluator conformance/ruleset_v2_ref.py, on the test pack's cases and on generated records and reads.
- The fixed eligibility guard: a PROGRAM_NOT_ELIGIBLE rule holds a line only on a present answer read within the
  maximum age, and any other hold reason whose rule's value depends on the eligibility read only on a read within the
  maximum age; on any other read the line goes to review (PROGRAM_NOT_ELIGIBLE_UNVERIFIED), whatever the rule says.  A
  hold rule true whatever the read holds the line on any read.  An as-of after the service date is within the age; one
  after the batch's own date is not.
- A rule naming a reason no fact field backs yet (24, 25) is well formed but refused at admission, by name (NOSOURCE),
  in the codec's check, the reference and Lean.
- The Lean eligibility read from facts (`elRead`, through belief) against the reference on a small fact corpus, and what
  the test pack decides on each read through the gate's own `dataFires`: the as-of is the oldest of the facts the answer
  cites, so a newer fact the answer does not rest on never freshens it.
- EVAL answers are the gate's `dataFires` in the empty context: no enrollment snapshot, so STALE_ENROLLMENT always fires
  and no hold rule that reads enrollment does.

Frozen before the codec, the reference and the Lean model exist (synthetic, non-PHI); the guard, the refusal, the read
and the EVAL path were each added, failing, before their implementation."""

import hashlib
import importlib
import random
import re
import unittest

from tests import _gate_authority as au
from tests import test_right_rail_gate_formats as fx
from tests import test_ruleset_admission as ra
from tests import test_ruleset_v1_codec as rs

TAG2 = b"RR/GATE/RULESET/v2\x00"
SIGTAG2 = b"RR/GATE/RULESET/v2/SIG\x00"
ELIG = 7
MAX_AIDS = 1024
MAX_COST = rs.MAX_COST
ELIG_BITS = (24, 25, 26, 27, 28)
FACT_BITS = (1, 7, 8, 9, 10, 12, 13, 14, 15, 18, 19, 20, 21)
MNE, MNE_UNV, STALE_ENR, PNE, PNE_UNV, STALE = 9, 10, 19, 26, 27, 28
u, ident, pat, with_ = rs.u, rs.ident, rs.pat, rs.with_


def module(test, name):
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as e:
        if e.name == name:
            test.fail(f"not built: {name} (RULESET_V2)")
        raise


def enc_expr(e):
    op = e[0]
    if op == "raw":
        return e[1]
    if op in ("and", "or"):
        return bytes([1 if op == "and" else 2, len(e[1])]) + b"".join(enc_expr(x) for x in e[1])
    if op == "not":
        return b"\x03" + enc_expr(e[1])
    if op == "elig":
        return bytes([0x22, e[1], e[2]])
    return rs.enc_expr(e)


def cost(e):
    op = e[0]
    if op in ("and", "or"):
        return 1 + sum(cost(x) for x in e[1])
    if op == "not":
        return 1 + cost(e[1])
    return 2 if op == "elig" else rs.cost(e)


def body(d):
    """A version 2 body: version 1's layout under its own tag, the aid table between the ages and the rules."""
    out = [TAG2, d["state"], ident(d["tenant"]), u(d["version"], 4), d["prev"], u(d["not_before"], 4),
           u(d["not_after"], 4), u(d["eff_from"], 4), u(d["eff_to"], 4), u(len(d["ends"]), 1)]
    out += [u(v, 4) + u(t, 4) for v, t in d["ends"]]
    out.append(u(len(d["cites"]), 1))
    out += [u(k, 1) + ident(r) + u(dt, 4) + doc for k, r, dt, doc in d["cites"]]
    out.append(u(len(d["ages"]), 1))
    out += [u(s, 1) + u(a, 2) for s, a in d["ages"]]
    out.append(u(len(d["aids"]), 2))
    out += [ident(c) + u(k, 1) for c, k in d["aids"]]
    out.append(u(len(d["rules"]), 1))
    out += [u(b, 1) + u(c, 1) + enc_expr(e) for b, c, e in d["rules"]]
    return b"".join(out)


def enc(d):
    return body(d) + rs.sigs(d)


# The test pack: a state's eligibility rules as data.  Aid codes A1 and A2 are on the program's
# list; R7 is a recognised code that is not.  Anything else, or a malformed code, is unrecognised.
AIDS = [("A1", 1), ("A2", 1), ("R7", 2)]
FRESH, PRESENT = ("fresh", ELIG), ("present", ELIG)
PACK2_CONDS = [
    # the segment's status is "not eligible" (an absent answer is never fresh: it goes to review)
    (MNE, ("and", [FRESH, ("date_ok",), ("elig", 2, 2)])),
    # a recognised aid code that is not on the program's list
    (PNE, ("and", [FRESH, ("date_ok",), ("elig", 3, 2)])),
    # no as-of at all, an answer that is unknown or in conflict, an unrecognised or malformed aid code, or a listed
    # not-eligible code read from facts too old to act on
    (PNE_UNV, ("or", [("not", PRESENT), ("elig", 1, 12), ("elig", 3, 3), ("and", [("not", FRESH), ("elig", 3, 2)])])),
    # the read's as-of (the oldest fact it cites) is older than the maximum age before the service date
    (STALE, ("and", [PRESENT, ("not", FRESH)])),
]
PACK2 = with_(rs.PACK1, format=2, ages=[(ELIG, 4)], aids=AIDS, rules=[(b, 0, e) for b, e in PACK2_CONDS])
# Every version 2 bound at its edge: five ages at their ceilings, 1024 aid codes of 20 bytes, version 1's other edges.
EDGE2 = with_(rs.EDGE, format=2, ages=[(1, 90), (2, 90), (3, 31), (4, 10), (ELIG, 10)],
              aids=[(f"C{i:019d}", 1 + i % 2) for i in range(MAX_AIDS)], rules=[(STALE, 31, rs.sized(MAX_COST))])


def rule(e, bit=PNE, cite=0):
    return with_(PACK2, rules=[(bit, cite, e)])


# (name, record dict or raw bytes, refused part).  A version 1 dict (no "format") is encoded by version 1's encoder.
REJECT = [
    ("v1_body_under_v2_tag", TAG2 + rs.enc(rs.PACK1)[len(rs.TAG):], "aids"),
    ("v2_tag_no_nul", TAG2[:-1] + b"\x01" + enc(PACK2)[len(TAG2):], "tag"),
    ("v3_tag", b"RR/GATE/RULESET/v3\x00" + enc(PACK2)[len(TAG2):], "tag"),
    ("v1_ages_src_7", with_(rs.PACK1, ages=[(ELIG, 4)]), "ages"),
    ("v1_present_7", with_(rs.PACK1, rules=[(7, 0, PRESENT)]), "expr"),
    ("v1_rule_bit_26", rs.rule(("date_ok",), bit=PNE), "rules"),
    ("v1_rule_bit_28", rs.rule(("date_ok",), bit=STALE), "rules"),
    ("v1_elig_node", rs.rule(("raw", b"\x22\x03\x02")), "expr"),
    ("ages_none", with_(PACK2, ages=[]), "ages"),
    ("ages_six", with_(PACK2, ages=[(1, 90), (2, 90), (3, 31), (4, 7), (ELIG, 4), (ELIG, 4)]), "ages"),
    ("ages_src_5", with_(PACK2, ages=[(5, 1)]), "ages"),
    ("ages_src_6", with_(PACK2, ages=[(6, 1)]), "ages"),
    ("ages_src_8", with_(PACK2, ages=[(8, 1)]), "ages"),
    ("age_elig_0", with_(PACK2, ages=[(ELIG, 0)]), "ages"),
    ("age_elig_11", with_(PACK2, ages=[(ELIG, 11)]), "ages"),
    ("ages_elig_first", with_(PACK2, ages=[(ELIG, 4), (4, 7)]), "ages"),
    ("ages_elig_twice", with_(PACK2, ages=[(ELIG, 4), (ELIG, 4)]), "ages"),
    ("aids_1025", with_(PACK2, aids=[(f"C{i:019d}", 1) for i in range(MAX_AIDS + 1)]), "aids"),
    ("aid_class_0", with_(PACK2, aids=[("A1", 0)]), "aids"),
    ("aid_class_3", with_(PACK2, aids=[("A1", 3)]), "aids"),
    ("aid_code_empty", with_(PACK2, aids=[("", 1)]), "aids"),
    ("aid_code_21", with_(PACK2, aids=[("A" * 21, 1)]), "aids"),
    ("aid_code_slash", with_(PACK2, aids=[("a/b", 1)]), "aids"),
    ("aid_code_lead_dash", with_(PACK2, aids=[("-a", 1)]), "aids"),
    ("aids_duplicate", with_(PACK2, aids=[("A1", 1), ("A1", 2)]), "aids"),
    ("aids_descending", with_(PACK2, aids=[("A2", 1), ("A1", 1)]), "aids"),
    ("aids_prefix_after", with_(PACK2, aids=[("A1", 1), ("A", 1)]), "aids"),
    ("rule_core_bit_0", rule(("date_ok",), bit=0), "rules"),
    ("rule_core_bit_11", rule(("date_ok",), bit=11), "rules"),
    ("rule_bit_29", rule(("date_ok",), bit=29), "rules"),
    ("elig_undeclared", with_(PACK2, ages=[(1, 90)], rules=[(PNE, 0, ("elig", 3, 2))]), "expr"),
    ("present_7_undeclared", with_(PACK2, ages=[(1, 90)], rules=[(PNE, 0, PRESENT)]), "expr"),
    ("elig_query_0", rule(("elig", 0, 1)), "expr"),
    ("elig_query_4", rule(("elig", 4, 1)), "expr"),
    ("elig_answer_0", rule(("elig", 1, 0)), "expr"),
    ("elig_answer_16", rule(("elig", 1, 16)), "expr"),
    ("elig_status_0", rule(("elig", 2, 0)), "expr"),
    ("elig_status_16", rule(("elig", 2, 16)), "expr"),
    ("elig_aid_0", rule(("elig", 3, 0)), "expr"),
    ("elig_aid_4", rule(("elig", 3, 4)), "expr"),
    ("hit_elig", rule(("hit", ELIG, 1, 2)), "expr"),
    ("overlap_elig", rule(("overlap", ELIG)), "expr"),
    ("elig_truncated", rule(("raw", b"\x22\x01")), "sigs"),
    ("cost_1025", with_(PACK2, ages=[(1, 90), (3, 31), (ELIG, 4)], rules=[(STALE, 0, rs.sized(MAX_COST + 1))]), "cost"),
]


def encode_case(d):
    return d if isinstance(d, bytes) else enc(d) if d.get("format") == 2 else rs.enc(d)


def lean_golden2():
    text = rs.LEAN_FILE.read_text("utf-8")
    if "def golden2 :" not in text:
        return None
    table = text.split("def golden2 :", 1)[1].split("\n\n", 1)[0]
    return {n: h for n, h in re.findall(r'\("([a-z0-9_]+)",\s*"([0-9a-f]{128})"\)', table)}


class OwnEncoder(unittest.TestCase):
    """This file's encoder against the spec's numbers (runs without the codec)."""

    def test_bounds(self):
        self.assertLessEqual(len(enc(EDGE2)), rs.MAX_RECORD)
        self.assertEqual(cost(EDGE2["rules"][0][2]), MAX_COST)
        self.assertEqual(sum(cost(e) for _, e in PACK2_CONDS), 26)
        self.assertEqual([b for b, _ in PACK2_CONDS], sorted(b for b, _ in PACK2_CONDS))

    def test_reject_names_unique(self):
        names = [n for n, _, _ in REJECT]
        self.assertEqual(len(names), len(set(names)))


class Codec(unittest.TestCase):
    def setUp(self):
        self.c = module(self, "app.right_rail_ruleset_codec")

    def refused(self, data, part, name):
        with self.assertRaises(self.c.RuleSetRefused, msg=name) as cm:
            self.c.decode(data)
        self.assertEqual(cm.exception.detail, part, name)

    def test_round_trips(self):
        for name, d in (("pack2", PACK2), ("edge2", EDGE2), ("no_aids", with_(PACK2, aids=[])),
                        ("no_elig_source", with_(PACK2, ages=[(1, 90)], rules=[(PNE, 0, ("hit", 1, 1, 1))])),
                        ("every_query", rule(("and", [("elig", 1, 15), ("elig", 2, 1), ("elig", 3, 3)]))),
                        ("unlisted_reasons", with_(PACK2, rules=[(b, 0, ("date_ok",)) for b in FACT_BITS + ELIG_BITS]))):
            x = enc(d)
            self.assertEqual(self.c.decode(x), d, name)
            self.assertEqual(self.c.encode(d), x, name)

    def test_version_1_unchanged(self):
        for d in (rs.PACK1, rs.EDGE):
            x = rs.enc(d)
            self.assertNotIn("format", self.c.decode(x))
            self.assertEqual(self.c.encode(d), x)
            self.assertEqual(self.c.message(x), hashlib.sha3_512(rs.SIGTAG + rs.body(d)).digest())

    def test_digest_and_message(self):
        for d in (PACK2, EDGE2):
            x = enc(d)
            self.assertEqual(self.c.digest(x), hashlib.sha3_512(body(d)).digest())
            self.assertEqual(self.c.message(x), hashlib.sha3_512(SIGTAG2 + body(d)).digest())

    def test_cost(self):
        for _, e in PACK2_CONDS:
            self.assertEqual(self.c.cost(e), cost(e))

    def test_must_reject(self):
        for name, d, part in REJECT:
            self.refused(encode_case(d), part, name)
            if not isinstance(d, bytes) and not any(r[2][0] == "raw" for r in d["rules"]):
                with self.assertRaises(self.c.RuleSetRefused, msg=name) as cm:
                    self.c.encode(d)
                self.assertEqual(cm.exception.detail, part, name)

    def test_aids_on_version_1_refused(self):
        with self.assertRaises(self.c.RuleSetRefused) as cm:
            self.c.encode(with_(rs.PACK1, aids=AIDS))
        self.assertEqual(cm.exception.detail, "aids")

    def test_every_proper_prefix_refused(self):
        for d in (PACK2, EDGE2):
            x = enc(d)
            cuts = set(range(len(body(d)) + 1)) if d is PACK2 else set(range(0, len(body(d)), 7))
            cuts |= set(range(0, len(x), 97)) | set(range(len(x) - 70, len(x)))
            for k in sorted(c for c in cuts if c < len(x)):
                with self.assertRaises(self.c.RuleSetRefused, msg=k):
                    self.c.decode(x[:k])

    def test_mutations_stay_canonical(self):
        x = enc(PACK2)
        for i in range(len(body(PACK2))):
            for flip in (0x01, 0x80):
                m = bytearray(x)
                m[i] ^= flip
                m = bytes(m)
                try:
                    d = self.c.decode(m)
                except self.c.RuleSetRefused:
                    continue
                self.assertNotEqual(d, PACK2, i)
                self.assertEqual(self.c.encode(d), m, i)


class LeanGolden(unittest.TestCase):
    def test_golden_digests_are_the_leans(self):
        golden = lean_golden2()
        if golden is None:
            self.fail(f"not built: `def golden2 :` in {rs.LEAN_FILE.name} (RULESET_V2 golden records)")
        self.assertEqual(golden, {n: hashlib.sha3_512(enc(d)).hexdigest() for n, d in (("pack2", PACK2), ("edge2", EDGE2))})


# ---- the eligibility read and the Lean interpreter ----

D0, A0 = 20270310, 20270308  # a service date and an as-of two days before it


def blk(code: bytes, n: int | None = None) -> bytes:
    """A 21-byte identifier block as a fact row stores the aid code: a length byte, the code, zeros."""
    out = bytes([len(code) if n is None else n]) + code
    return out[:21] + bytes(max(0, 21 - len(out)))


def read(ans=0, status=1, asof=A0, aids=(b"A1",)):
    return {"ans": ans, "status": status, "asof": asof, "aids": [a if len(a) == 21 else blk(a) for a in aids]}


def evals(cases):
    """The EVAL section of a `ruleset_admit` frame: (record index, service date, flow tag, read[, batch date]) per
    question; the batch date is the service date when not given."""
    out = u(len(cases), 2)
    for i, date, flow, r, *t in cases:
        out += u(i, 2) + u(date, 4) + u(t[0] if t else date, 4) + u(flow, 1) + u(r["ans"], 1) + u(r["status"], 1)
        out += u(r["asof"] or 0, 4)
        out += u(len(r["aids"]), 1) + b"".join(r["aids"])
    return out


def lean(records, cases=()):
    """The Lean answer lines: one per record (admission), then one per EVAL question."""
    p = ra.call(ra.frame([(4, x) for x in records]) + evals(cases))
    if p.returncode != 0:
        raise AssertionError(f"ruleset_admit exit {p.returncode}: {p.stderr.decode(errors='replace')}")
    return p.stdout.decode().splitlines()


def bits(mask):
    return {i for i in range(64) if mask >> i & 1}


def decided(test, mask, name):
    """The reasons an EVAL mask names besides STALE_ENROLLMENT, which the empty context (no enrollment snapshot) always
    fires."""
    got = bits(mask)
    test.assertIn(STALE_ENR, got, name)
    return got - {STALE_ENR}


def signed_v2(d, tag=SIGTAG2):
    b = body(d)
    msg = hashlib.sha3_512(tag + b).digest()
    sigs = sorted((au.key_id(n), fx.det_sign("authority-" + n, msg)) for n in ra.SIGNERS)
    return b + rs.sigs({"sigs": sigs})


# (name, service date, read, reasons fired): the test pack's answers (age 4 days; A1, A2 listed, R7 listed not eligible)
PACK2_CASES = [
    ("eligible", D0, read(), set()),
    ("listed_not_eligible", D0, read(aids=(b"R7",)), {PNE}),
    ("unlisted", D0, read(aids=(b"ZZ9",)), {PNE_UNV}),
    ("malformed_empty", D0, read(aids=(blk(b""),)), {PNE_UNV}),
    ("malformed_char", D0, read(aids=(blk(b"a/b"),)), {PNE_UNV}),
    ("listed_and_not", D0, read(aids=(b"A1", b"R7")), {PNE}),
    ("listed_and_unlisted", D0, read(aids=(b"A1", b"ZZ9")), {PNE_UNV}),
    ("not_eligible_and_unlisted", D0, read(aids=(b"R7", b"ZZ9")), {PNE, PNE_UNV}),
    ("no_as_of_absent", D0, read(ans=1, asof=None, aids=()), {PNE_UNV}),
    ("no_as_of_present", D0, read(asof=None), {PNE_UNV}),
    # an answer that is not present is never fresh: review, whatever its as-of
    ("absent_fresh", D0, read(ans=1, aids=()), {PNE_UNV, STALE}),
    ("absent_stale", D0, read(ans=1, asof=20270305, aids=()), {PNE_UNV, STALE}),
    ("status_not_eligible", D0, read(status=2), {MNE}),
    ("unknown", D0, read(ans=2, aids=()), {PNE_UNV, STALE}),
    ("conflict", D0, read(ans=3, aids=()), {PNE_UNV, STALE}),
    ("age_edge_fresh", 20270312, read(), set()),
    # a read too old to act on sends the line to review even when its aid code is listed eligible
    ("age_edge_stale", 20270313, read(), {PNE_UNV, STALE}),
    ("stale_not_eligible", 20270313, read(aids=(b"R7",)), {PNE_UNV, STALE}),
    ("month_edge_fresh", 20270304, read(asof=20270228), set()),
    ("month_edge_stale", 20270305, read(asof=20270228), {PNE_UNV, STALE}),
    ("leap_edge_fresh", 20280304, read(asof=20280229), set()),
    ("leap_edge_stale", 20280305, read(asof=20280229), {PNE_UNV, STALE}),
]


def gen_expr(rng, depth, srcs):
    leaves = [lambda: ("flow", rng.randint(1, 7)), lambda: ("date_ok",)]
    if ELIG in srcs:
        leaves += [lambda: PRESENT, lambda: FRESH, lambda: ("elig", 1, rng.randint(1, 15)),
                   lambda: ("elig", 2, rng.randint(1, 15)), lambda: ("elig", 3, rng.randint(1, 3))] * 2
    if 1 in srcs:
        leaves += [lambda: ("present", 1), lambda: ("fresh", 1), lambda: ("hit", 1, 1, 1)]
    if 4 in srcs:  # enrollment, so rules read enrollment and eligibility together
        leaves += [lambda: ("present", 4), lambda: ("fresh", 4), lambda: ("hit", 4, 1, rng.randint(2, 3)),
                   lambda: ("overlap", 4)]
    if depth <= 1 or rng.random() < 0.35:
        return rng.choice(leaves)()
    k = rng.random()
    if k < 0.2:
        return ("not", gen_expr(rng, depth - 1, srcs))
    return ("and" if k < 0.6 else "or", [gen_expr(rng, depth - 1, srcs) for _ in range(rng.randint(2, 4))])


POOL = [b"A1", b"A2", b"B", b"R7", b"X-1", b"Z9.z"]


def gen_record(rng):
    ages = sorted({(ELIG, rng.randint(1, 10))} | ({(1, 90)} if rng.random() < 0.3 else set())
                  | ({(4, rng.randint(1, 10))} if rng.random() < 0.5 else set()))
    srcs = {s for s, _ in ages}
    aids = sorted({(c.decode(), rng.randint(1, 2)) for c in rng.sample(POOL, rng.randint(0, len(POOL)))},
                  key=lambda a: a[0].encode())
    reasons = sorted(rng.sample(FACT_BITS + ELIG_BITS, rng.randint(1, 6)))
    return with_(PACK2, ages=ages, aids=aids, rules=[(b, 0, gen_expr(rng, 4, srcs)) for b in reasons])


def gen_read(rng):
    asof = None if rng.random() < 0.15 else 20270301 + rng.randint(0, 27)
    date = rng.choice([20270230, 20279999, 0]) if rng.random() < 0.05 else 20270301 + rng.randint(0, 30)
    today = rng.choice([20270230, 0]) if rng.random() < 0.03 else 20270301 + rng.randint(0, 30)
    aids = []
    for _ in range(rng.randint(0, 3)):
        k = rng.random()
        aids.append(blk(rng.choice(POOL + [b"ZZ9"])) if k < 0.8 else blk(b"") if k < 0.85 else
                    blk(b"a/b") if k < 0.9 else blk(b"Q" * 20, n=rng.choice([20, 25, 255])))
    return date, rng.randint(1, 3), read(ans=rng.randint(0, 3), status=rng.randint(0, 5), asof=asof, aids=aids), today


class LeanAgreement(unittest.TestCase):
    def setUp(self):
        self.ref = module(self, "conformance.ruleset_v2_ref")

    def test_signed_v2_record_is_admitted(self):
        d = with_(PACK2, state=au.STATE, tenant=fx.TENANT, not_before=ra.NB, not_after=ra.NA)
        digest = hashlib.sha3_512(body(d)).hexdigest()
        self.assertEqual(lean([signed_v2(d)]), [f"ADMIT 1 4 {digest}"])
        self.assertEqual(lean([signed_v2(d, tag=rs.SIGTAG)]), ["REFUSED UNSIGNED"])

    def test_lean_refuses_what_the_codec_refuses(self):
        names = [name for name, _, _ in REJECT]
        out = lean([encode_case(d) for _, d, _ in REJECT], [(i, D0, 2, read()) for i in range(len(REJECT))])
        self.assertEqual(len(out), 2 * len(REJECT))
        for k, name in enumerate(names):
            self.assertEqual(out[k], "REFUSED MALFORMED", name)
            self.assertEqual(out[len(REJECT) + k], f"EVAL {k} NONE", name)

    def test_the_test_pack_decides(self):
        cases = [(0, date, 2, r) for _, date, r, _ in PACK2_CASES]
        out = lean([enc(PACK2)], cases)[1:]
        for (name, date, r, want), line in zip(PACK2_CASES, out):
            self.assertEqual(decided(self, int(line.split()[2]), name), want, name)
            self.assertEqual(decided(self, self.ref.fired(PACK2, r, date, 2), name), want, name)

    def test_generated_records_and_reads_agree(self):
        rng = random.Random(20261122)
        recs = [gen_record(rng) for _ in range(40)]
        cases = [(i, *gen_read(rng)) for i in range(len(recs)) for _ in range(25)]
        out = lean([enc(d) for d in recs], cases)[len(recs):]
        self.assertEqual(len(out), len(cases))
        fired = set()
        for (i, date, flow, r, today), line in zip(cases, out):
            want = self.ref.fired(recs[i], r, date, flow, today)
            self.assertEqual(line, f"EVAL {i} {want}", (i, date, flow, r, today))
            fired |= bits(want)
        self.assertTrue(set(ELIG_BITS) & fired)
        self.assertIn(PNE_UNV, fired)
        self.assertTrue(any(4 in dict(d["ages"]) for d in recs))

    def test_version_1_records_evaluate_as_before(self):
        """A version 1 record reads no eligibility: its answers do not depend on the eligibility read."""
        cases = [(0, D0, f, r) for f in (1, 2, 3) for r in (read(), read(ans=1, asof=None, aids=()))]
        out = lean([rs.enc(rs.PACK1)], cases)[1:]
        self.assertEqual(len(out), len(cases))
        for k in range(0, len(out), 2):
            self.assertEqual(out[k], out[k + 1])
        for (_, date, f, r), line in zip(cases, out):
            self.assertEqual(line, f"EVAL 0 {self.ref.fired(rs.PACK1, r, date, f)}")


# ---- the fixed eligibility guard ----

# A rule set whose PROGRAM_NOT_ELIGIBLE rule asks nothing of the read.  Whatever a state signs, the gate holds a line
# for it only on a present answer read within the maximum age; on any other read the rule sends the line to review.
BARE_PNE = rule(("flow", 2))  # every line of flow 2, the flow the cases use
# (name, service date, read, reasons fired, batch date)
GUARD = [
    ("fresh_present", D0, read(), {PNE}, D0),
    ("stale", 20270313, read(), {PNE_UNV}, 20270313),
    ("no_as_of", D0, read(asof=None), {PNE_UNV}, D0),
    ("absent", D0, read(ans=1, aids=()), {PNE_UNV}, D0),
    ("unknown", D0, read(ans=2, aids=()), {PNE_UNV}, D0),
    ("conflict", D0, read(ans=3, aids=()), {PNE_UNV}, D0),
    ("bad_date", 20270230, read(), {PNE_UNV}, D0),
    # a later read about earlier coverage is within the age; a read dated after the batch itself is not
    ("as_of_after_service_date", D0, read(asof=20270312), {PNE}, 20270312),
    ("as_of_after_batch_date", D0, read(asof=20270312), {PNE_UNV}, 20270311),
    ("bad_batch_date", D0, read(), {PNE_UNV}, 20270230),
]

# Any hold reason, not only PROGRAM_NOT_ELIGIBLE: a hold rule whose value depends on the eligibility read holds only on
# a present answer read within the maximum age.  On any other read the line goes to review whenever the record has such
# a rule, whatever that rule's condition says (a rule cannot screen a stale read out).  Rules that do not read it, rules
# for another hold reason true whatever the read, and review rules, are untouched.
ABSENT_MNE = rule(("elig", 1, 2), bit=MNE)  # MEMBER_NOT_ENROLLED (a hold) when the answer is absent
GUARD_ANY = [
    ("hold_absent_no_as_of", ABSENT_MNE, D0, read(ans=1, asof=None, aids=()), {PNE_UNV}),
    ("hold_absent_stale", ABSENT_MNE, 20270313, read(ans=1, aids=()), {PNE_UNV}),
    ("hold_absent_fresh", ABSENT_MNE, D0, read(ans=1, aids=()), {PNE_UNV}),
    ("hold_status_stale", rule(("elig", 2, 2), bit=7), 20270313, read(status=2), {PNE_UNV}),
    ("hold_not_reading", rule(("flow", 2), bit=MNE), D0, read(ans=1, asof=None, aids=()), {MNE}),
    ("review_reading", rule(("elig", 1, 2), bit=MNE_UNV), D0, read(ans=1, asof=None, aids=()), {MNE_UNV}),
    ("review_and_hold", with_(PACK2, rules=[(MNE, 0, ("elig", 1, 2)), (PNE_UNV, 0, ("flow", 4))]), D0,
     read(ans=1, asof=None, aids=()), {PNE_UNV}),
    # the only eligibility rule asks for a fresh read itself, so it is false on this one (R7 read ten days before the
    # service date, maximum age 4): the line still goes to review, never allowed
    ("pne_screens_out_stale", rule(("and", [FRESH, ("elig", 3, 2)])), D0, read(asof=20270228, aids=(b"R7",)), {PNE_UNV}),
    ("hold_screens_out_stale", rule(("and", [FRESH, ("elig", 2, 2)]), bit=MNE), 20270313, read(status=2), {PNE_UNV}),
    # narrow: a rule whose other atoms rule the line out whatever the read (its condition false with every eligibility
    # atom unknown) leaves the line alone; one that could hold it under some read sends it to review
    ("other_flow_excluded", rule(("and", [("flow", 1), ("elig", 3, 2)])), D0, read(asof=20270228, aids=(b"R7",)), set()),
    ("bad_date_excluded", rule(("and", [("date_ok",), ("elig", 2, 2)]), bit=MNE), 20270230, read(status=2), set()),
    ("not_or_excluded", rule(("not", ("or", [("flow", 2), FRESH]))), D0, read(ans=2, aids=()), set()),
    ("not_elig_and_not_flow", rule(("and", [("not", ("elig", 3, 2)), ("not", ("flow", 2))])), D0,
     read(asof=None), set()),
    ("or_other_flow_or_elig", rule(("or", [("not", ("flow", 2)), ("elig", 3, 2)])), D0, read(asof=None), {PNE_UNV}),
    ("or_this_flow", rule(("or", [("flow", 2), ("not", ("elig", 1, 1))])), 20270313, read(), {PNE_UNV}),
    ("not_and_unknown", rule(("not", ("and", [("flow", 2), ("not", FRESH)])), bit=MNE), D0, read(ans=3, aids=()),
     {PNE_UNV}),
    # a hold rule already true without the read (this flow) holds the line on a stale read; one whose value is the
    # read's (another flow) sends it to review; not eligible for the program never holds on it, true or not (the Lean
    # model checks the same three with a fresh enrollment feed in place of the flow, `guardCond`)
    ("hold_true_whatever_the_read", rule(("or", [("flow", 2), ("and", [FRESH, ("elig", 2, 2)])]), bit=MNE), 20270313,
     read(status=2), {MNE}),
    ("hold_depends_on_the_read", rule(("or", [("flow", 1), ("and", [FRESH, ("elig", 2, 2)])]), bit=MNE), 20270313,
     read(status=2), {PNE_UNV}),
    ("pne_true_whatever_the_read", rule(("or", [("flow", 2), ("and", [FRESH, ("elig", 3, 2)])])), 20270313,
     read(aids=(b"R7",)), {PNE_UNV}),
]


class EligGuard(unittest.TestCase):
    def setUp(self):
        self.ref = module(self, "conformance.ruleset_v2_ref")

    def test_stale_missing_or_conflicting_reads_never_hold(self):
        both = with_(BARE_PNE, rules=[(PNE, 0, ("flow", 2)), (PNE_UNV, 0, ("flow", 4))])
        for d in (BARE_PNE, both):
            out = lean([enc(d)], [(0, date, 2, r, today) for _, date, r, _, today in GUARD])[1:]
            self.assertEqual(len(out), len(GUARD))
            for (name, date, r, want, today), line in zip(GUARD, out):
                self.assertEqual(decided(self, int(line.split()[2]), name), want, name)
                self.assertEqual(decided(self, self.ref.fired(d, r, date, 2, today), name), want, name)

    def test_every_hold_reading_eligibility_is_guarded(self):
        cases = [(k, date, 2, r) for k, (_, _, date, r, _) in enumerate(GUARD_ANY)]
        out = lean([enc(d) for _, d, _, _, _ in GUARD_ANY], cases)[len(GUARD_ANY):]
        self.assertEqual(len(out), len(GUARD_ANY))
        for (name, d, date, r, want), line in zip(GUARD_ANY, out):
            self.assertEqual(decided(self, int(line.split()[2]), name), want, name)
            self.assertEqual(decided(self, self.ref.fired(d, r, date, 2), name), want, name)


# ---- reasons with no data source yet ----

NO_SOURCE = (24, 25)  # BENEFIT_LEVEL_MISSING and its _UNVERIFIED: no kind-1 field carries a benefit level


class NoSource(unittest.TestCase):
    def setUp(self):
        self.c = module(self, "app.right_rail_ruleset_codec")
        self.ref = module(self, "conformance.ruleset_v2_ref")

    def test_benefit_level_rules_are_refused_at_admission(self):
        base = with_(PACK2, state=au.STATE, tenant=fx.TENANT, not_before=ra.NB, not_after=ra.NA)
        self.assertEqual(self.c.unbacked(base), [])
        self.assertTrue(self.ref.admissible(base))
        self.assertEqual(lean([signed_v2(base)])[0].split()[:2], ["ADMIT", "1"])
        for bit in NO_SOURCE:
            d = with_(base, rules=[(bit, 0, PRESENT)] + [r for r in base["rules"] if r[0] > bit])
            x = signed_v2(d)
            self.assertEqual(self.c.decode(x)["rules"], d["rules"], bit)  # well formed: the refusal is admission's
            self.assertEqual(self.c.unbacked(d), [bit])
            self.assertFalse(self.ref.admissible(d))
            # refused before the signatures are read: an unsigned record gets the same name
            self.assertEqual(lean([x, signed_v2(d, tag=rs.SIGTAG)]), ["REFUSED NOSOURCE"] * 2, bit)


# ---- the eligibility read from facts ----

# (name, service date, sources).  Each source is a full file of its own origin, read within its maximum age: (source,
# class, as-of, the member's rows as (status, aid code)), each row holding from 20260101 with no end.  The read asks for
# class 1; a class 2 source is weaker and never counts.
EL_CASES = [
    ("fresh", 20260303, [(1, 1, 20260301, [(1, b"A1")])]),
    ("stale", 20260303, [(1, 1, 20260210, [(1, b"A1")])]),
    ("stale_not_eligible", 20260303, [(1, 1, 20260210, [(1, b"R7")])]),
    ("no_as_of", 20260303, [(1, 1, 20260301, [])]),
    ("conflict", 20260303, [(1, 1, 20260301, [(1, b"A1")]), (2, 1, 20260302, [(2, b"R7")])]),
    ("agree", 20260303, [(1, 1, 20260301, [(1, b"A1")]), (2, 1, 20260302, [(1, b"R7")])]),
    ("unknown_code", 20260303, [(1, 1, 20260301, [(1, b"ZZ9")])]),
    # a newer fact the answer does not rest on (a weaker source's) does not freshen the stale one it does
    ("newer_weak_row", 20260303, [(1, 1, 20260210, [(1, b"R7")]), (2, 2, 20260302, [(1, b"A1")])]),
]
# What the test pack decides on each read (flow 2, the batch on the service date), besides STALE_ENROLLMENT.
EL_DECIDED = {"fresh": set(), "stale": {PNE_UNV, STALE}, "stale_not_eligible": {PNE_UNV, STALE}, "no_as_of": {PNE_UNV},
              "conflict": {PNE_UNV}, "agree": {PNE}, "unknown_code": {PNE_UNV}, "newer_weak_row": {PNE_UNV, STALE}}


def lean_el_golden():
    text = rs.LEAN_FILE.read_text("utf-8")
    if "def elGolden :" not in text:
        return None
    table = text.split("def elGolden :", 1)[1].split("\n\n", 1)[0]
    return dict(re.findall(r'\("([a-z_]+)",\s*"([^"]*)"\)', table))


def el_text(r):
    return f"{r['ans']} {r['status']} {r['asof'] or 0} {','.join(a.hex() for a in r['aids'])}"


class ElReadAgreement(unittest.TestCase):
    def test_reference_reads_and_decides(self):
        ref = module(self, "conformance.ruleset_v2_ref")
        got = {n: ref.el_read(srcs) for n, _, srcs in EL_CASES}
        self.assertEqual(el_text(got["fresh"]), f"0 1 20260301 {blk(b'A1').hex()}")
        self.assertEqual(el_text(got["no_as_of"]), "1 0 0 ")
        self.assertEqual(el_text(got["conflict"]), "3 0 0 ")  # an answer that cites no fact has no as-of
        self.assertEqual(el_text(got["agree"]), f"0 1 20260301 {blk(b'A1').hex()},{blk(b'R7').hex()}")  # the oldest
        self.assertEqual(el_text(got["newer_weak_row"]), f"0 1 20260210 {blk(b'R7').hex()}")
        for n, date, _ in EL_CASES:
            self.assertEqual(decided(self, ref.fired(PACK2, got[n], date, 2), n), EL_DECIDED[n], n)

    def test_lean_el_read_agrees_with_the_reference(self):
        """Lean's read of each case, and the reasons the gate's `dataFires` gives the test pack on it (`elGolden`)."""
        ref = module(self, "conformance.ruleset_v2_ref")
        golden = lean_el_golden()
        if golden is None:
            self.fail(f"not built: `def elGolden :` in {rs.LEAN_FILE.name} (elRead on the fact corpus)")
        want = {}
        for n, date, srcs in EL_CASES:
            r = ref.el_read(srcs)
            want[n] = f"{el_text(r)} {ref.fired(PACK2, r, date, 2)}"
        self.assertEqual(golden, want)


if __name__ == "__main__":
    unittest.main()
