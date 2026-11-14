"""The checker's tagged rows file (lean/BlindLedger/Gate/Engine3/VStore.lean): the tag against its definition, a flipped byte,
a moved record, a wrong key, shard or set, a torn tail and the DPAPI key file, run by the `vstore_check` exe.  Synthetic, non-PHI."""
import subprocess
import tempfile
import unittest

from tests import test_flat_worker as fw


class VStore(unittest.TestCase):
    def test_tagged_rows_file(self):
        with tempfile.TemporaryDirectory() as d:
            run = subprocess.run([str(fw.BIN / "vstore_check.exe"), d.replace("\\", "/")], capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertRegex(run.stdout, r"\d+ checks, 0 failures")
        self.assertNotIn("FAIL", run.stdout)


if __name__ == "__main__":
    unittest.main()
