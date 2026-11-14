"""The model run's comparison of an answer with the spec's leaves (lean/BlindLedger/Gate/Engine3/Step.lean `leavesMatch`)
accepts the spec's leaf and refuses a wrong outcome, reason, authority or bypass, a wrong leaf count and bytes that are no
answer. Run by `leaf_check`. Synthetic."""
import subprocess
import unittest

from tests import test_flat_worker as fw


class LeafCheck(unittest.TestCase):
    def test_wrong_leaf_is_caught(self):
        run = subprocess.run([str(fw.BIN / "leaf_check.exe")], capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertRegex(run.stdout, r"8 checks, 0 failures")
        self.assertNotIn("FAIL", run.stdout)


if __name__ == "__main__":
    unittest.main()
