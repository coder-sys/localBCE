"""The decision step's own check (lean/BlindLedger/Gate/Flat/DecideBench.lean, `decide_bench check`): a core over the posting cap
whose keys are each under it is held with POSTING_CAP by the reference rule and by the fixed-row decider, the per-key state does
not cap it, and then the two deciders agree on a run of batches of each corpus.  Synthetic, non-PHI."""
import re
import subprocess
import unittest

from tests import test_flat_worker as fw


class DecideBench(unittest.TestCase):
    def test_core_over_the_cap_and_decider_agreement(self):
        run = subprocess.run([str(fw.BIN / "decide_bench.exe"), "check", "125"], capture_output=True, text=True, timeout=1800)
        self.assertEqual(run.returncode, 0, run.stdout[-2000:] + run.stderr[-2000:])
        self.assertRegex(run.stdout, r"reference HOLD POSTING_CAP true, per key POSTING_CAP false, fixed-row decider equal true")
        self.assertRegex(run.stdout, r"check: \d+ batches, 0 mismatches")
        self.assertEqual(len(re.findall(r"mismatches 0;", run.stdout)), 4, run.stdout[-2000:])  # every corpus line reports none


if __name__ == "__main__":
    unittest.main()
