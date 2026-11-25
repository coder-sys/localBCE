"""Class test: a resend of one payment, in every order of a change to its grant or a signed bypass, gets the canonical retry
answer (Constitution III.3) and is never stuck.

The payment is a claim held for review as a near duplicate of an earlier paid one.  A send is one of four inputs: a grant that
does not cover its program (``G0``), the covering grant (``G1``), the covering grant with the payment's own signed bypass
(``G1+own``), or with a bypass signed for another payment (``G1+other``).  Every sequence of one to three sends of the same
claim is run on a fresh pair.  For each send:
  - it gets an answer: one row for the payment, and no error;
  - the same inputs as an earlier send give that send's answer and signed tokens again (a retry);
  - the payment is paid at most once (a released payment's line keeps its finding; the token is what pays): all ALLOW tokens it was ever given are one token;
  - inputs not seen before are decided afresh, never answered with an old decision: a covering grant is never SCOPE, the
    payment's own bypass releases it once the gate has held it, and nothing else allows it."""

from __future__ import annotations

import itertools

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from tests import _class_cases as cc
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_right_rail_gate_formats as fx
from tests._class_harness import Harness, read_case

NEAR = 1 << decider.REASON_IDX["FFS_NEAR_DUPLICATE"]
G0 = au.grant([(fx.PROGRAM, 1 << 3, 3, 0)])  # transfer authority for SDP only: a claim is out of its scope
STATES = ("G0", "G1", "G1+own", "G1+other")


def pair(n: int):
    """Requests for a paid claim and a near duplicate of it (another billing provider, the first's rendering, the same member, day,
    procedure and charge), and the read set of the member's enrollment."""
    a, b = cc.Parts(n), cc.Parts(n + 1)
    b.sub837 = a.member
    b.claim = cc._put(b.claim, "CLM", f"NM1*82*1*ROE*RAY****XX*{a.npi}")
    ra, rb = read_case(a), read_case(b)
    return ra["sent"][0], rb["sent"][0], ra["feed"]


class ResendTests(Harness):
    def test_a_resend_in_every_order_of_grant_and_bypass_changes_keeps_the_retry_identity_and_is_never_stuck(self) -> None:
        sequences = [s for k in (1, 2, 3) for s in itertools.product(STATES, repeat=k)]
        with self.session() as run:
            for i, seq in enumerate(sequences):
                with self.subTest(sends=" -> ".join(seq)):
                    first, req, feed = pair(1000 + 3 * i)
                    pid = req.payment_id
                    inputs = {"G0": (G0, ()), "G1": (g.GRANT, ()),
                              "G1+own": (g.GRANT, (au.bypass(fx.PROGRAM, pid, au.digest(gate.encode_decide_request(req)), NEAR),)),
                              "G1+other": (g.GRANT, (au.bypass(fx.PROGRAM, first.payment_id, au.digest(gate.encode_decide_request(first)), NEAR),))}
                    paid = run([first], feed)
                    self.assertEqual([r[2] for r in paid[0]], ["ALLOW"], "the earlier claim is paid")
                    answered, tokens, held = {}, set(), False
                    for state in seq:
                        grant, bypasses = inputs[state]
                        rows, _, sealed = run([req], feed, grant, bypasses)  # an error here is a stuck resend: the subtest reports it
                        mine = [r for r in rows if r[0] == pid]
                        self.assertEqual(len(mine), 1, f"{state}: one answer for the payment, got {rows}")
                        outcome, why = mine[0][2], mine[0][3]
                        given = {t for _, toks, _ in sealed for t in toks if ffs.given([t]).get(pid, ("",))[0] == "ALLOW"}
                        if outcome == "ALLOW":
                            self.assertTrue(given, f"{state}: ALLOW with no signed ALLOW token")
                        if state in answered:  # a retry: the first answer for these inputs, byte for byte (the reasons are given from the tokens)
                            self.assertEqual((bool(given), sealed), answered[state], f"{state}: a resend of the same inputs got another answer")
                        else:
                            if not tokens:  # not paid yet: a new input is decided by itself
                                if state == "G0":
                                    self.assertEqual((outcome, why), ("HOLD", ("SCOPE",)), "G0 must hold for scope")
                                else:
                                    self.assertNotEqual(why, ("SCOPE",), f"{state}: a covering grant answered with the old scope hold")
                                    # a bypass releases a payment the gate already held: the first covering send only holds it
                                    self.assertEqual(bool(given), state == "G1+own" and held, f"{state}: got {outcome} {why}")
                            answered[state] = (bool(given), sealed)
                        held = held or state != "G0"
                        tokens |= given
                        self.assertLessEqual(len(tokens), 1, f"{state}: the payment was given a second ALLOW token")


if __name__ == "__main__":
    import unittest
    unittest.main()
