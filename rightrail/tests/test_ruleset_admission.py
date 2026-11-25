"""Admission of a signed rule set and the version series (conformance/RULESET_V1.md section 6, slice I2): the Lean
`ruleset_admit` frame, which decides, against records this file signs from fixed test-only seeds (`tests/_gate_authority.py`).
Every refusal the design lists, the accept cases, an exact re-send, and a two-version series selected at both known times.
Synthetic, non-PHI."""

import functools
import hashlib
import subprocess
import unittest

from tests import _gate_authority as au
from tests import test_flat_worker as fw
from tests import test_right_rail_gate_formats as fx
from tests import test_ruleset_v1_codec as rs

EXE = fw.BIN / "ruleset_admit.exe"
SIGNERS = ("p1", "p2")  # who signs a rule set: two POLICY keys of distinct employees (kPolicy = 2)
# POLICY keys added to the authority fixture's roster, approver and source keys: (role, employee, identity-provider subject)
POLICY_KEYS = {"p1": (au.POLICY, "hal", "sso-hal"), "p2": (au.POLICY, "ivy", "sso-ivy"),
               "p3": (au.POLICY, "hal", "sso-hal")}  # p3 is hal's second key
u = rs.u
NB, NA = 20270301, 20270331  # the signing window; the head's day (au.TODAY) is inside it
BASE = rs.with_(rs.PACK1, state=au.STATE, tenant=fx.TENANT, not_before=NB, not_after=NA)


def digest(d):
    return hashlib.sha3_512(rs.body(d)).digest()


def sign(d, signers=SIGNERS):
    body = rs.body(d)
    msg = hashlib.sha3_512(rs.SIGTAG + body).digest()
    sigs = sorted((au.key_id(n), fx.det_sign("authority-" + n, msg)) for n in set(signers))
    return body + rs.sigs({"sigs": sigs})


V1 = rs.with_(BASE, version=1, prev=bytes(64), eff_from=20270101, eff_to=99991231)
# version 2 cuts version 1 to the end of June and covers July on
V2 = rs.with_(BASE, version=2, prev=digest(V1), eff_from=20270701, eff_to=99991231, ends=[(1, 20270630)])


def key_set(extra=POLICY_KEYS, k_policy=2, revoked=None):
    """(pin, document) of a genesis key set holding the fixture's keys and `extra`, signed by its roster quorum."""
    body = au.keyset_body(revoked=revoked, extra=extra, k_policy=k_policy)
    return au.H(body), au.keyset_doc(body)


@functools.cache
def policy_set():
    return key_set()


def frame(records, asks=(), pin=None, ks=None):
    pin0, doc = ks or policy_set()
    out = (pin or pin0) + u(au.TODAY, 4) + u(len(doc), 4) + doc + u(0, 2) + u(len(fx.TENANT), 2) + fx.TENANT.encode()
    out += u(len(records), 2) + b"".join(u(kb, 4) + u(len(x), 4) + x for kb, x in records)
    return out + u(len(asks), 2) + b"".join(u(k, 4) + u(d, 4) for k, d in asks)


def call(data):
    if not EXE.exists():
        raise AssertionError(f"not built: {EXE}")
    return subprocess.run([str(EXE)], input=data, capture_output=True, timeout=900)


def raw(records, asks=(), pin=None, ks=None):
    p = call(frame(records, asks, pin, ks))
    return p.returncode, p.stdout.decode().splitlines()


class Admission(unittest.TestCase):
    def one(self, x, prior=()):
        """The answer line to `x` (batch 9) after `prior` admitted in batch 4."""
        code, out = raw([(4, p) for p in prior] + [(9, x)])
        self.assertEqual(code, 0)
        return out[-1]

    def test_accept_first_version(self):
        self.assertEqual(raw([(4, sign(V1))]), (0, [f"ADMIT 1 4 {digest(V1).hex()}"]))

    def test_exact_resend_answers_first_admission(self):
        code, out = raw([(4, sign(V1)), (7, sign(V1))])
        self.assertEqual(out, [f"ADMIT 1 4 {digest(V1).hex()}", "DUP 1 4"])

    def test_unsigned(self):
        for name, signers in (("one POLICY signer", ("p1",)), ("roster keys only", ("r1", "r2")),
                              ("two keys of one employee", ("p1", "p3")), ("approvers", ("a1", "a2")),
                              ("sources", ("s1", "s2")), ("roster key as second signer", ("p1", "r1"))):
            with self.subTest(name):
                self.assertEqual(self.one(sign(V1, signers)), "REFUSED UNSIGNED")

    def test_signer_key_not_live_on_head_day_is_unsigned(self):
        """A POLICY key counts only if it is live on the head's day (au.TODAY): unrevoked and inside its validity window."""
        for name, p2, revoked in (("expired", (au.POLICY, "ivy", "sso-ivy", 20270101, au.TODAY - 1), None),
                                  ("not yet valid", (au.POLICY, "ivy", "sso-ivy", au.TODAY + 1, 20271231), None),
                                  ("revoked", POLICY_KEYS["p2"], {"p2": 20270201})):
            with self.subTest(name):
                ks = key_set(POLICY_KEYS | {"p2": p2}, revoked=revoked)
                self.assertEqual(raw([(4, sign(V1))], ks=ks), (0, ["REFUSED UNSIGNED"]))
        edges = POLICY_KEYS | {"p2": (au.POLICY, "ivy", "sso-ivy", au.TODAY, au.TODAY)}  # live on that one day
        self.assertEqual(raw([(4, sign(V1))], ks=key_set(edges)), (0, [f"ADMIT 1 4 {digest(V1).hex()}"]))

    def test_signature_over_other_bytes_is_unsigned(self):
        other = rs.with_(V1, eff_from=20270102)
        self.assertEqual(self.one(rs.body(V1) + sign(other)[len(rs.body(other)):]), "REFUSED UNSIGNED")

    def test_malformed(self):
        self.assertEqual(self.one(b"not a rule set"), "REFUSED MALFORMED")
        self.assertEqual(self.one(sign(V1)[:-1]), "REFUSED MALFORMED")

    def test_cost_bound_exceeded(self):
        d = rs.with_(V1, rules=[(7, 0, rs.sized(rs.MAX_COST + 1))])
        self.assertEqual(self.one(sign(d)), "REFUSED MALFORMED")
        self.assertEqual(self.one(sign(rs.with_(V1, rules=[(7, 0, rs.sized(rs.MAX_COST))]))).split()[0], "ADMIT")

    def test_enrollment_age_bounds(self):
        """The state sets the enrollment age from 1 to 10 days; 0 or 11 is refused, and a rule set without one is admitted."""
        ages = [(1, 90), (2, 90), (3, 31)]
        for n, want in ((0, "REFUSED"), (1, "ADMIT"), (4, "ADMIT"), (10, "ADMIT"), (11, "REFUSED")):
            with self.subTest(n):
                answer = self.one(sign(rs.with_(V1, ages=ages + [(4, n)])))
                self.assertEqual(answer.split()[0] if want == "ADMIT" else answer, want if want == "ADMIT" else "REFUSED MALFORMED")
        no_span = rs.with_(V1, ages=ages, rules=[x for x in V1["rules"] if x[0] not in (1, 9, 10, 19)])
        self.assertEqual(self.one(sign(no_span)).split()[0], "ADMIT")

    def test_other_state_or_tenant(self):
        self.assertEqual(self.one(sign(rs.with_(V1, state=bytes(range(64))))), "REFUSED SCOPE")
        self.assertEqual(self.one(sign(rs.with_(V1, tenant="nc-other"))), "REFUSED SCOPE")

    def test_head_day_outside_signing_window(self):
        for nb, na in ((20270101, 20270131), (20270316, 20270331), (20270215, 20270314)):
            with self.subTest((nb, na)):
                self.assertEqual(self.one(sign(rs.with_(V1, not_before=nb, not_after=na))), "REFUSED EXPIRED")

    def test_chain(self):
        first = sign(V1)
        wrong = rs.pat(64, 1)
        self.assertEqual(self.one(sign(rs.with_(V1, version=2, prev=digest(V1)))), "REFUSED CHAIN")  # no version 1 yet
        self.assertEqual(self.one(sign(rs.with_(V2, prev=wrong)), (first,)), "REFUSED CHAIN")  # wrong prev
        self.assertEqual(self.one(sign(rs.with_(V1, eff_from=20280101)), (first,)), "REFUSED CHAIN")  # not after the last
        self.assertEqual(raw([(4, first), (3, sign(V2))])[1][1], "REFUSED CHAIN")  # an earlier batch than the last version

    def test_ends(self):
        first = sign(V1)
        for name, ends in (("does not shorten", [(1, 99991231)]),
                           ("before it starts", [(1, 20261231)])):
            with self.subTest(name):
                self.assertEqual(self.one(sign(rs.with_(V2, ends=ends)), (first,)), "REFUSED ENDS")
        v3 = rs.with_(V2, version=3, prev=digest(V2), eff_from=20280101, ends=[(1, 20270630)])  # already cut there
        out = raw([(4, first), (5, sign(V2)), (6, sign(v3))])[1]
        self.assertEqual(out[2], "REFUSED ENDS")
        w2 = rs.with_(V2, ends=[(1, 0)], eff_from=20270101)  # withdraws version 1
        v3 = rs.with_(V2, version=3, prev=digest(w2), ends=[(1, 0)])  # ends it again: no longer in force
        out = raw([(4, first), (5, sign(w2)), (6, sign(v3))])[1]
        self.assertEqual((out[1].split()[0], out[2]), ("ADMIT", "REFUSED ENDS"))

    def test_overlapping_ranges(self):
        first = sign(V1)
        self.assertEqual(self.one(sign(rs.with_(V2, ends=[])), (first,)), "REFUSED OVERLAP")
        self.assertEqual(self.one(sign(rs.with_(V2, eff_from=20270630)), (first,)), "REFUSED OVERLAP")

    def test_two_version_series_selected_at_both_known_times(self):
        asks = [(3, 20270801), (4, 20270601), (8, 20270801), (9, 20270801), (9, 20270601), (9, 20261231), (9, 20270630),
                (9, 20270701)]
        i1, i2 = digest(V1).hex(), digest(V2).hex()
        self.assertEqual(raw([(4, sign(V1)), (9, sign(V2))], asks), (0, [
            f"ADMIT 1 4 {i1}", f"ADMIT 2 9 {i2}",
            "NONE 3 20270801",  # before version 1 was admitted
            f"SELECT 4 20270601 1 {i1}",
            f"SELECT 8 20270801 1 {i1}",  # version 2 not yet known: version 1 still covers August
            f"SELECT 9 20270801 2 {i2}",  # known at 9: version 1 ends June 30
            f"SELECT 9 20270601 1 {i1}",  # a date before the cut keeps its version
            "NONE 9 20261231",  # no rule set covers it
            f"SELECT 9 20270630 1 {i1}", f"SELECT 9 20270701 2 {i2}"]))

    def test_withdrawn_version_covers_no_date(self):
        w2 = rs.with_(V2, ends=[(1, 0)], eff_from=20270101)
        out = raw([(4, sign(V1)), (9, sign(w2))], [(8, 20270601), (9, 20270601)])[1]
        self.assertEqual(out[2:], [f"SELECT 8 20270601 1 {digest(V1).hex()}", f"SELECT 9 20270601 2 {digest(w2).hex()}"])

    def test_refused_record_is_not_kept(self):
        code, out = raw([(4, sign(V1, ("p1",))), (5, sign(V1))], [(9, 20270601)])
        self.assertEqual(out, ["REFUSED UNSIGNED", f"ADMIT 1 5 {digest(V1).hex()}", f"SELECT 9 20270601 1 {digest(V1).hex()}"])

    def test_bad_key_set_admits_no_head(self):
        self.assertEqual(raw([(4, sign(V1))], pin=bytes(64)), (1, ["RULESET_ADMIT=NOHEAD"]))

    def test_key_set_refuses_policy_roles(self):
        """A key set that breaks the POLICY rules admits no head, so no rule set is admitted under it: POLICY keys whose
        employee and subject are not one to one, or a POLICY holder who, by employee or by subject, also holds an
        unrevoked key of another role (the fixture's r1, s1 and a2)."""
        cases = {"two employees under one subject": (au.POLICY, "jo", "sso-hal"),
                 "one employee under two subjects": (au.POLICY, "hal", "sso-hal-2")}
        for role, emp, idp in (("ROSTER", "ann", "ann"), ("SOURCE", "fay", "fay"), ("APPROVER", "di", "sso-di")):
            cases |= {f"POLICY and {role}: same employee and subject": (au.POLICY, emp, idp),
                      f"POLICY and {role}: same employee": (au.POLICY, emp, "sso-other"),
                      f"POLICY and {role}: same subject": (au.POLICY, "zed", idp)}
        for name, p4 in cases.items():
            with self.subTest(name):
                self.assertEqual(raw([(4, sign(V1))], ks=key_set(POLICY_KEYS | {"p4": p4})), (1, ["RULESET_ADMIT=NOHEAD"]))

    def test_revoked_other_role_keys_beside_policy(self):
        """Only unrevoked keys of other roles refuse: POLICY holders' revoked APPROVER (cy's a1 and a3), ROSTER and SOURCE
        keys leave the key set valid."""
        extra = POLICY_KEYS | {"p4": (au.POLICY, "cy", "sso-cy"), "r3": (au.ROSTER, "hal", "sso-hal"),
                               "s3": (au.SOURCE, "ivy", "sso-ivy")}
        ks = key_set(extra, revoked=dict.fromkeys(("a1", "a3", "r3", "s3"), 20270201))
        self.assertEqual(raw([(4, sign(V1, ("p1", "p4")))], ks=ks), (0, [f"ADMIT 1 4 {digest(V1).hex()}"]))

    def test_policy_threshold_range(self):
        nine = {f"q{i}": (au.POLICY, f"q{i}", f"sso-q{i}") for i in range(1, 10)}
        for k in (0, 1, 9):
            with self.subTest(k):
                self.assertEqual(raw([(4, sign(V1))], ks=key_set(POLICY_KEYS, k)), (1, ["RULESET_ADMIT=NOHEAD"]))
        self.assertEqual(raw([(4, sign(V1, tuple(nine)))], ks=key_set(nine, 9)), (1, ["RULESET_ADMIT=NOHEAD"]))
        ks = key_set(nine, 8)
        eight, seven = tuple(nine)[:8], tuple(nine)[:7]
        self.assertEqual(raw([(4, sign(V1, seven)), (5, sign(V1, eight))], ks=ks),
                         (0, ["REFUSED UNSIGNED", f"ADMIT 1 5 {digest(V1).hex()}"]))

    def test_malformed_frame(self):
        p = call(frame([(4, sign(V1))])[:-1])
        self.assertEqual((p.returncode, p.stdout, p.stderr.strip()), (2, b"", b"RULESET_ADMIT=FRAME"))


if __name__ == "__main__":
    unittest.main()
