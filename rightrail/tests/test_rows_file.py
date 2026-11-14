"""The rows file (lean/BlindLedger/Gate/Engine3/RowsFile.lean): append and fetch of 2000 records, reopen, a torn tail, a cut to what
the log confirms (`open_cut`) and a read past the end, run by the `rows_test` exe.  Synthetic, non-PHI."""
import subprocess
import tempfile
import unittest

from tests import test_flat_worker as fw


class RowsFile(unittest.TestCase):
    def test_append_reopen_torn_tail_and_cut(self):
        with tempfile.TemporaryDirectory() as d:
            run = subprocess.run([str(fw.BIN / "rows_test.exe"), d.replace("\\", "/")], capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(run.stdout.strip(), "ROWS_OK")


if __name__ == "__main__":
    unittest.main()
