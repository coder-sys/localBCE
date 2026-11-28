"""Signed rule set RULESET/v1 bytes (conformance/RULESET_V1.md): the Python twin codec app/right_rail_ruleset_codec.py
against this file's own encoder, written from the spec alone.  Round trips, must-reject vectors with the refused part,
every proper prefix refused, canonical bytes under mutation, and agreement with the Lean model's golden digests.

Frozen before the codec exists: every codec test fails "not built" until it does (synthetic, non-PHI)."""

import hashlib
import importlib
import re
import unittest
from pathlib import Path

LEAN_FILE = Path(__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "RuleSet" / "Spec.lean"
MODULE = "app.right_rail_ruleset_codec"
TAG = b"RR/GATE/RULESET/v1\x00"
SIGTAG = b"RR/GATE/RULESET/v1/SIG\x00"
MAX_RECORD = 131072
MAX_COST = 1024
SIG_LEN = 64 + 4627


def codec(test):
    try:
        return importlib.import_module(MODULE)
    except ModuleNotFoundError as e:
        if e.name == MODULE:
            test.fail(f"not built: {MODULE} (RULESET_V1 section 7)")
        raise


def pat(n, s):
    return bytes((s + i) & 255 for i in range(n))


def u(n, w):
    return n.to_bytes(w, "big")


def ident(s):
    b = s.encode()
    return u(len(b), 2) + b


def enc_expr(e):
    op = e[0]
    if op == "raw":
        return e[1]
    if op in ("and", "or"):
        return bytes([1 if op == "and" else 2, len(e[1])]) + b"".join(enc_expr(x) for x in e[1])
    if op == "not":
        return b"\x03" + enc_expr(e[1])
    if op == "flow":
        return bytes([0x10, e[1]])
    if op == "date_ok":
        return b"\x11"
    if op in ("present", "fresh", "overlap"):
        return bytes([{"present": 0x20, "fresh": 0x21, "overlap": 0x31}[op], e[1]])
    if op == "hit":
        return bytes([0x30, e[1], e[2], e[3]])
    raise ValueError(op)


def cost(e):
    op = e[0]
    if op in ("and", "or"):
        return 1 + sum(cost(x) for x in e[1])
    if op == "not":
        return 1 + cost(e[1])
    if op == "hit":
        return 2 if e[2] == 1 else 3
    return 2 if op == "overlap" else 1


def body(d):
    out = [TAG, d["state"], ident(d["tenant"]), u(d["version"], 4), d["prev"], u(d["not_before"], 4),
           u(d["not_after"], 4), u(d["eff_from"], 4), u(d["eff_to"], 4), u(len(d["ends"]), 1)]
    out += [u(v, 4) + u(t, 4) for v, t in d["ends"]]
    out.append(u(len(d["cites"]), 1))
    out += [u(k, 1) + ident(r) + u(dt, 4) + doc for k, r, dt, doc in d["cites"]]
    out.append(u(len(d["ages"]), 1))
    out += [u(s, 1) + u(a, 2) for s, a in d["ages"]]
    out.append(u(len(d["rules"]), 1))
    out += [u(b, 1) + u(c, 1) + enc_expr(e) for b, c, e in d["rules"]]
    return b"".join(out)


def sigs(d):
    return u(len(d["sigs"]), 1) + b"".join(k + s for k, s in d["sigs"])


def enc(d):
    return body(d) + sigs(d)


def with_(d, **kw):
    x = dict(d)
    x.update(kw)
    return x


def sized(c):
    """A condition of cost exactly c (c >= 1), at most 8 operands per node, reading deaths and exclusions."""
    if c == 1:
        return ("date_ok",)
    if c == 2:
        return ("hit", 1, 1, 1)
    if c == 3:
        return ("hit", 3, 2, 2)
    n = min(8, c - 1)
    parts = [(c - 1) // n + (1 if i < (c - 1) % n else 0) for i in range(n)]
    return ("and", [sized(p) for p in parts])


def nots(k):
    e = ("date_ok",)
    for _ in range(k):
        e = ("not", e)
    return e


def cert(s, x):
    return ("and", [("fresh", s), ("date_ok",), x])


def unv(s, x):
    return ("and", [("present", s), ("not", ("fresh", s)), ("date_ok",), x])


ENROLLED = ("or", [("and", [("flow", 3), ("hit", 4, 1, 2)]), ("and", [("flow", 4), ("hit", 4, 1, 3)])])
PACK1_CONDS = [
    (1, ("and", [("flow", 4), ("fresh", 4), ("date_ok",), ("overlap", 4)])),
    (7, cert(1, ("hit", 1, 1, 1))), (8, unv(1, ("hit", 1, 1, 1))),
    (9, cert(4, ("not", ENROLLED))), (10, unv(4, ("not", ENROLLED))),
    (12, cert(2, ("hit", 2, 2, 1))), (13, unv(2, ("hit", 2, 2, 1))),
    (14, cert(3, ("hit", 3, 2, 2))), (15, unv(3, ("hit", 3, 2, 2))),
    (18, ("not", ("fresh", 1))), (19, ("not", ("fresh", 4))), (20, ("not", ("fresh", 3))), (21, ("not", ("fresh", 2))),
]
CITE = (2, "TEST-CITE-1", 20260701, pat(64, 9))
PACK1 = {
    "state": pat(64, 0x40), "tenant": "TENANT-A", "version": 1, "prev": bytes(64),
    "not_before": 20261101, "not_after": 20261130, "eff_from": 20270101, "eff_to": 99991231,
    "ends": [], "cites": [CITE], "ages": [(1, 90), (2, 90), (3, 31), (4, 7)],
    "rules": [(b, 0, e) for b, e in PACK1_CONDS],
    "sigs": [(pat(64, 1), pat(4627, 1)), (pat(64, 2), pat(4627, 2))],
}
# Every bound at its edge: version 9 ending all eight earlier versions, a 31-day window, the widest range, a 128-byte
# tenant, 32 sources, every age at its ceiling, one rule of cost exactly 1024, sixteen signatures.
EDGE = {
    "state": pat(64, 0xC0), "tenant": "A" + "z9._:-" * 21 + "b", "version": 9, "prev": pat(64, 0x77),
    "not_before": 20261101, "not_after": 20261202, "eff_from": 10101, "eff_to": 99991231,
    "ends": [(1, 0)] + [(v, 20261200 + v) for v in range(2, 9)],
    "cites": [(1 + i % 7, f"REF-{i}", 20000101 + i % 28, pat(64, i + 1)) for i in range(32)],
    "ages": [(1, 90), (2, 90), (3, 31), (4, 10)],
    "rules": [(21, 31, sized(MAX_COST))],
    "sigs": [(pat(64, 15 * i), pat(4627, i)) for i in range(1, 17)],
}
V2 = with_(PACK1, version=2, prev=pat(64, 0x55))


def rule(e, bit=7, cite=0):
    return with_(PACK1, rules=[(bit, cite, e)])


# (name, record dict or raw bytes, refused part).  A dict case must also be refused by encode.
REJECT = [
    ("tag_v3", b"RR/GATE/RULESET/v3\x00" + enc(PACK1)[len(TAG):], "tag"),  # a version 1 body under the v2 tag: test_ruleset_v2
    ("tag_no_nul", TAG[:-1] + b"\x01" + enc(PACK1)[len(TAG):], "tag"),
    ("tenant_empty", with_(PACK1, tenant=""), "tenant"),
    ("tenant_lead_dash", with_(PACK1, tenant="-a"), "tenant"),
    ("tenant_space", with_(PACK1, tenant="a b"), "tenant"),
    ("tenant_129", with_(PACK1, tenant="A" * 129), "tenant"),
    ("version_0", with_(PACK1, version=0), "version"),
    ("prev_v1_nonzero", with_(PACK1, prev=pat(64, 1)), "prev"),
    ("prev_v2_zero", with_(V2, prev=bytes(64)), "prev"),
    ("window_invalid_date", with_(PACK1, not_before=20261131), "window"),
    ("window_reversed", with_(PACK1, not_before=20261130, not_after=20261101), "window"),
    ("window_32_days", with_(PACK1, not_after=20261203), "window"),
    ("effective_invalid", with_(PACK1, eff_from=20270229), "effective"),
    ("effective_reversed", with_(PACK1, eff_from=20270102, eff_to=20270101), "effective"),
    ("effective_zero_end", with_(PACK1, eff_to=0), "effective"),
    ("ends_nine", with_(PACK1, version=10, prev=pat(64, 3), ends=[(v, 0) for v in range(1, 10)]), "ends"),
    ("ends_version_0", with_(V2, ends=[(0, 0)]), "ends"),
    ("ends_own_version", with_(V2, ends=[(2, 0)]), "ends"),
    ("ends_v1_names_itself", with_(PACK1, ends=[(1, 0)]), "ends"),
    ("ends_duplicate", with_(V2, version=3, ends=[(1, 0), (1, 0)]), "ends"),
    ("ends_descending", with_(V2, version=3, ends=[(2, 0), (1, 0)]), "ends"),
    ("ends_bad_date", with_(V2, ends=[(1, 20261301)]), "ends"),
    ("ends_to_one", with_(V2, ends=[(1, 1)]), "ends"),
    ("cites_none", with_(PACK1, cites=[]), "cites"),
    ("cites_33", with_(PACK1, cites=[CITE] * 33), "cites"),
    ("cite_kind_0", with_(PACK1, cites=[(0,) + CITE[1:]]), "cites"),
    ("cite_kind_8", with_(PACK1, cites=[(8,) + CITE[1:]]), "cites"),
    ("cite_ref_empty", with_(PACK1, cites=[(2, "", 20260701, pat(64, 9))]), "cites"),
    ("cite_ref_bad", with_(PACK1, cites=[(2, "a/b", 20260701, pat(64, 9))]), "cites"),
    ("cite_date_invalid", with_(PACK1, cites=[(2, "R", 20260230, pat(64, 9))]), "cites"),
    ("cite_doc_zero", with_(PACK1, cites=[(2, "R", 20260701, bytes(64))]), "cites"),
    ("ages_none", with_(PACK1, ages=[]), "ages"),
    ("ages_five", with_(PACK1, ages=[(1, 90), (2, 90), (3, 31), (4, 7), (4, 7)]), "ages"),
    ("ages_src_0", with_(PACK1, ages=[(0, 1)]), "ages"),
    ("ages_src_5", with_(PACK1, ages=[(5, 1)]), "ages"),
    ("ages_duplicate", with_(PACK1, ages=[(1, 90), (1, 90)]), "ages"),
    ("ages_descending", with_(PACK1, ages=[(2, 90), (1, 90)]), "ages"),
    ("age_zero", with_(PACK1, ages=[(1, 0), (2, 90), (3, 31), (4, 7)]), "ages"),
    ("age_dmf_91", with_(PACK1, ages=[(1, 91), (2, 90), (3, 31), (4, 7)]), "ages"),
    ("age_pdeath_91", with_(PACK1, ages=[(1, 90), (2, 91), (3, 31), (4, 7)]), "ages"),
    ("age_excl_32", with_(PACK1, ages=[(1, 90), (2, 90), (3, 32), (4, 7)]), "ages"),
    ("age_span_11", with_(PACK1, ages=[(1, 90), (2, 90), (3, 31), (4, 11)]), "ages"),
    ("rules_none", with_(PACK1, rules=[]), "rules"),
    ("rules_65", with_(PACK1, rules=[(7, 0, ("date_ok",))] * 65), "rules"),
    ("rule_core_already_decided", rule(("date_ok",), bit=0), "rules"),
    ("rule_core_posting_cap", rule(("date_ok",), bit=11), "rules"),
    ("rule_core_date_invalid", rule(("date_ok",), bit=17), "rules"),
    ("rule_core_stale_released", rule(("date_ok",), bit=22), "rules"),
    ("rule_bit_24", rule(("date_ok",), bit=24), "rules"),
    ("rule_bit_255", rule(("date_ok",), bit=255), "rules"),
    ("rules_duplicate", with_(PACK1, rules=[(7, 0, ("date_ok",)), (7, 0, ("date_ok",))]), "rules"),
    ("rules_descending", with_(PACK1, rules=[(8, 0, ("date_ok",)), (7, 0, ("date_ok",))]), "rules"),
    ("rule_cite_out_of_range", rule(("date_ok",), cite=1), "rules"),
    ("expr_op_00", rule(("raw", b"\x00")), "expr"),
    ("expr_op_04", rule(("raw", b"\x04")), "expr"),
    ("expr_op_12", rule(("raw", b"\x12")), "expr"),
    ("expr_op_ff", rule(("raw", b"\xff")), "expr"),
    ("expr_and_1", rule(("and", [("date_ok",)])), "expr"),
    ("expr_or_9", rule(("or", [("date_ok",)] * 9)), "expr"),
    ("expr_flow_0", rule(("flow", 0)), "expr"),
    ("expr_flow_8", rule(("flow", 8)), "expr"),
    ("expr_src_0", rule(("present", 0)), "expr"),
    ("expr_src_5", rule(("fresh", 5)), "expr"),
    ("expr_src_undeclared", with_(PACK1, ages=[(1, 90)], rules=[(7, 0, ("present", 3))]), "expr"),
    ("expr_hit_dmf_party", rule(("hit", 1, 2, 1)), "expr"),
    ("expr_hit_excl_before", rule(("hit", 3, 2, 1)), "expr"),
    ("expr_hit_span_party", rule(("hit", 4, 2, 2)), "expr"),
    ("expr_hit_subject_3", rule(("hit", 4, 3, 2)), "expr"),
    ("expr_hit_test_0", rule(("hit", 4, 1, 0)), "expr"),
    ("expr_hit_test_4", rule(("hit", 4, 1, 4)), "expr"),
    ("expr_overlap_dmf", rule(("overlap", 1)), "expr"),
    ("expr_depth_9", rule(nots(8)), "expr"),
    ("cost_1025", rule(sized(MAX_COST + 1)), "cost"),
    ("cost_split_1025", with_(PACK1, rules=[(7, 0, sized(512)), (8, 0, sized(513))]), "cost"),
    ("sigs_none", with_(PACK1, sigs=[]), "sigs"),
    ("sigs_17", with_(PACK1, sigs=[(pat(64, 8 * i), pat(4627, i)) for i in range(1, 18)]), "sigs"),
    ("sigs_duplicate_key", with_(PACK1, sigs=[(pat(64, 1), pat(4627, 1)), (pat(64, 1), pat(4627, 2))]), "sigs"),
    ("sigs_descending", with_(PACK1, sigs=[(pat(64, 2), pat(4627, 2)), (pat(64, 1), pat(4627, 1))]), "sigs"),
    ("sigs_short", enc(PACK1)[:-1], "sigs"),
    ("sigs_trailing", enc(PACK1) + b"\x00", "sigs"),
    ("length", enc(PACK1) + bytes(MAX_RECORD + 1 - len(enc(PACK1))), "length"),
]


def lean_golden():
    text = LEAN_FILE.read_text("utf-8")
    if "def golden :" not in text:
        return None
    table = text.split("def golden :", 1)[1].split("\n\n", 1)[0]
    return {n: h for n, h in re.findall(r'\("([a-z0-9_]+)",\s*"([0-9a-f]{128})"\)', table)}


class OwnEncoder(unittest.TestCase):
    """This file's encoder against the spec's numbers (runs without the codec)."""

    def test_pack1_cost_and_sized(self):
        self.assertEqual(sum(cost(e) for _, e in PACK1_CONDS), 82)
        for c in (1, 2, 3, 4, 5, 64, 512, 513, MAX_COST, MAX_COST + 1):
            self.assertEqual(cost(sized(c)), c)
        self.assertEqual(cost(EDGE["rules"][0][2]), MAX_COST)

    def test_edge_fits_and_is_at_its_bounds(self):
        self.assertEqual(len(EDGE["tenant"].encode()), 128)
        self.assertLessEqual(len(enc(EDGE)), MAX_RECORD)
        self.assertEqual(len(enc(PACK1)) - len(body(PACK1)), 1 + 2 * SIG_LEN)

    def test_reject_names_unique(self):
        names = [n for n, _, _ in REJECT]
        self.assertEqual(len(names), len(set(names)))


class RuleSetCodec(unittest.TestCase):
    def setUp(self):
        self.c = codec(self)

    def refused(self, data, part, name):
        with self.assertRaises(self.c.RuleSetRefused, msg=name) as cm:
            self.c.decode(data)
        self.assertEqual(cm.exception.detail, part, name)

    def test_round_trips(self):
        for name, d in (("pack1", PACK1), ("edge", EDGE), ("v2", V2), ("depth_8", rule(nots(7))),
                        ("arity_8", rule(("or", [("date_ok",)] * 8))), ("flow_7", rule(("flow", 7)))):
            x = enc(d)
            self.assertEqual(self.c.decode(x), d, name)
            self.assertEqual(self.c.encode(d), x, name)

    def test_digest_and_message(self):
        for d in (PACK1, EDGE):
            x = enc(d)
            self.assertEqual(self.c.digest(x), hashlib.sha3_512(body(d)).digest())
            self.assertEqual(self.c.message(x), hashlib.sha3_512(SIGTAG + body(d)).digest())

    def test_cost(self):
        for _, e in PACK1_CONDS:
            self.assertEqual(self.c.cost(e), cost(e))
        self.assertEqual(self.c.cost(sized(MAX_COST)), MAX_COST)

    def test_must_reject(self):
        for name, d, part in REJECT:
            data = d if isinstance(d, bytes) else enc(d)
            self.refused(data, part, name)
            if not isinstance(d, bytes) and not any(r[2][0] == "raw" for r in d["rules"]):
                with self.assertRaises(self.c.RuleSetRefused, msg=name) as cm:
                    self.c.encode(d)
                self.assertEqual(cm.exception.detail, part, name)

    def test_every_proper_prefix_refused(self):
        for d in (PACK1, EDGE):
            x = enc(d)
            n = len(body(d)) + 2 * SIG_LEN
            cuts = set(range(min(n, len(x)))) if d is PACK1 else set(range(len(body(d)) + 1))
            cuts |= set(range(0, len(x), 97)) | set(range(len(x) - 70, len(x)))
            for k in sorted(c for c in cuts if c < len(x)):
                with self.assertRaises(self.c.RuleSetRefused, msg=k):
                    self.c.decode(x[:k])

    def test_mutations_stay_canonical(self):
        x = enc(PACK1)
        for i in range(len(body(PACK1))):
            for flip in (0x01, 0x80):
                m = bytearray(x)
                m[i] ^= flip
                m = bytes(m)
                try:
                    d = self.c.decode(m)
                except self.c.RuleSetRefused:
                    continue
                self.assertNotEqual(d, PACK1, i)
                self.assertEqual(self.c.encode(d), m, i)


class LeanGolden(unittest.TestCase):
    def test_golden_digests_are_the_leans(self):
        golden = lean_golden()
        if golden is None:
            self.fail(f"not built: `def golden :` in {LEAN_FILE.name} (RULESET_V1 golden records)")
        self.assertEqual(golden, {n: hashlib.sha3_512(enc(d)).hexdigest() for n, d in (("pack1", PACK1), ("edge", EDGE))})


if __name__ == "__main__":
    unittest.main()
