"""The checker's tagged rows file (lean/BlindLedger/Gate/Engine3/VStore.lean): the tag against its definition and against hashlib, a flipped byte,
a moved record, a wrong key, shard or set, a torn tail and the DPAPI key file, run by the `vstore_check` exe.  Synthetic, non-PHI."""
import hashlib
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
        # the tag of the test record (key 0..31, shard 3, set 1, place 5), computed here by another implementation
        rec = bytes((31 + j * 7) % 256 for j in range(256))
        want = hashlib.sha3_512(b"RR/GATE/VTAG2/v1\0" + bytes(range(32)) + (3).to_bytes(4, "little") + b"\x01" + (5).to_bytes(8, "little") + rec).hexdigest()
        self.assertIn(f"tag {want}", run.stdout)


if __name__ == "__main__":
    unittest.main()
