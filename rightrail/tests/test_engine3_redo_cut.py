"""A released key with two payments' rows, and a redone payment on it: the history summary must not cut that key to its first row.

The engine and the checker read a released key's first row only (conformance/ENGINE_V3.md, Flat/DecideCut.lean decideRows_cut)
unless a line of a redone payment is on the key.  Two payments' rows stand on one released key only through a signed bypass:
payment A is released and forty more payments make its core long (the summary then serves its keys); payment B has A's near key
(another payee) and is held for FFS_NEAR_DUPLICATE; B is sent again with a bypass and released, so the near key holds A's row,
then B's.  A is then redone: B's row is on A's near key, so A is no longer an ALLOW, and its reasons name that released row.  A
read cut to A's own row would miss it.  The old engine (every row read), the history engine and the checker must agree, and the
history engine's answer must be the one above.  Synthetic, nonpayment, non-PHI."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import engine3_compare as ec
from tests import test_flat_worker as fw
from tests import test_right_rail_gate_formats as fx

HIST, VERIFY = fw.BIN / "gate_hist3.exe", fw.BIN / "gate_verify3.exe"
NEAR = 1 << decider.REASON_IDX["FFS_NEAR_DUPLICATE"]


def payment(n: int, payee: str, rendering: str = "R7001", units: int = 1) -> bytes:
    """Payment `pay-n`: one FFS line of one member, day and procedure (one core)."""
    key, cents = g.member(fw.MEMBERS[0], 0), 12500 * units
    line = gate.encode_line("FFS_CLAIM", ec.lid(str(n)), key, payee, rendering, 20270301, "C99213", units, cents)
    return gate.encode_decide_request(gate.DecideRequest(fx.TENANT, fx.PROGRAM, "FFS_CLAIM", f"cmd-{n}", f"pay-{n}", key, payee, cents,
                                                         fx.PERIOD, (line,), ec.EVIDENCE))


# Forty payments of the core with a rendering provider, and a payee and units, of their own: all released, so the core (more than
# CoreSum.longMin rows) is summarised and its keys are read from the summary.
FILL = [payment(100 + i, f"P{7100 + i % 10}", f"R{7100 + i}", 1 + i // 10) for i in range(40)]


@unittest.skipUnless(os.name == "nt" and HIST.is_file() and VERIFY.is_file() and fw.ENGINE.is_file(),
                     f"REDO CUT NOT RUN: {HIST}, {VERIFY} or {fw.ENGINE} is missing; run `lake build gate_hist3 gate_verify3 gate_engine` in lean/")
class RedoCutTests(unittest.TestCase):
    def test_a_redone_payment_sees_every_row_of_its_released_key(self):
        a, b = payment(1, "P7001"), payment(2, "P7002")
        bypass = au.bypass(fx.PROGRAM, "pay-2", au.digest(b), NEAR)
        # (requests, bypasses, redone payments) of each batch
        batches = [([a], (), ()), (FILL, (), ()), ([b], (), ()), ([b], (bypass,), ()), ([a], (), (fw.pay_number(1),))]
        with tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH")) as tmp:
            dirs = [Path(tmp) / "old", Path(tmp) / "new"]
            engines = []
            for d, exe in zip(dirs, (fw.ENGINE, HIST)):
                d.mkdir()
                engines.append(fw.Engine(d, exe))
            heads, seen = [fw.GENESIS, fw.GENESIS], []
            try:
                for n, (reqs, byps, redo) in enumerate(batches, 1):
                    answers = []
                    for i, e in enumerate(engines):
                        data = decider.request_frame(g.HEAD, 0, n, g.ASOF, heads[i], g.PIN, fw.floors(heads[i]), g.KEYS, g.GRANT, ec.RELEASE, byps, reqs, redo)
                        why, recs, heads[i], _, _, leaves, adds = fw.read(data, e.send(data))
                        self.assertIsNone(why, f"batch {n}: engine {i} refused")
                        answers.append(({r.index: r for r in recs}, ec.semantic_leaves(leaves), sorted(adds)))
                    old, new = answers
                    self.assertEqual(ec.mismatch_indices(old[0], new[0]), [], f"batch {n}: decisions differ")
                    self.assertEqual((old[1], old[2]), (new[1], new[2]), f"batch {n}: leaves or adds differ")
                    seen.append([f"{r.outcome} {','.join(r.reasons) or '-'}" for r in new[0].values()] + [x.outcome for x in new[1]])
            finally:
                for e in engines:
                    e.close()
            # A is released; B is held as a near duplicate of A; B's bypass releases it; A redone is no longer an ALLOW
            near = "HUMAN_REVIEW FFS_NEAR_DUPLICATE"
            self.assertEqual(seen[0], ["ALLOW -", "ALLOW"])
            self.assertEqual(seen[1], ["ALLOW -"] * 40 + ["ALLOW"] * 40)
            self.assertEqual(seen[2], [near, "HUMAN_REVIEW"])
            self.assertEqual(seen[3], [near, "ALLOW"], "the bypass must release B (the line keeps its finding)")
            # B's held row is still unresolved (COLLIDES); FFS_NEAR_DUPLICATE is B's released row on A's near key
            self.assertEqual(seen[4], ["HUMAN_REVIEW COLLIDES_WITH_UNRESOLVED_NEAR,FFS_NEAR_DUPLICATE", "HUMAN_REVIEW"],
                             "A redone must see B's row on its near key")
            r = subprocess.run([str(VERIFY), str(dirs[1]), "0", "rows-offline", f"{dirs[1]}.verify", "0"], capture_output=True, text=True, timeout=600)
            self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-300:])
            self.assertIn("VERIFIED", r.stdout)


if __name__ == "__main__":
    unittest.main()
