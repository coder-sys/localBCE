"""Test stores live under the scratch root, never the system Temp folder (the helper rule)."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import SCRATCH_ROOT


class ScratchRootTests(unittest.TestCase):
    def test_a_temp_dir_made_without_dir_lands_under_the_scratch_root(self) -> None:
        for make in (tempfile.mkdtemp, lambda: tempfile.TemporaryDirectory().name):
            made = Path(make()).resolve()
            self.addCleanup(shutil.rmtree, made, True)
            self.assertTrue(made.is_relative_to(SCRATCH_ROOT), made)

    def test_a_child_python_gets_the_same_root(self) -> None:
        done = subprocess.run([sys.executable, "-c", "import tempfile; print(tempfile.gettempdir())"], capture_output=True, text=True, timeout=60, env=os.environ.copy(), check=True)
        self.assertEqual(Path(done.stdout.strip()).resolve(), SCRATCH_ROOT)

    def probe(self, **env: str) -> list[str]:
        base = {k: v for k, v in os.environ.items() if k not in ("RR_TEST_SCRATCH", "TEMP", "TMP", "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH")}
        code = "import os, tempfile, tests; print(tests.SCRATCH_ROOT); print(tempfile.gettempdir()); print(os.environ['TEMP']); print(os.environ['TMP'])"
        done = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parent.parent, env={**base, **env}, capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_a_preset_root_still_gets_tempfile_and_temp_variables(self) -> None:
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as elsewhere:
            root = str(Path(root).resolve())
            self.assertEqual(self.probe(RR_TEST_SCRATCH=root, TEMP=elsewhere, TMP=elsewhere), [root] * 4)

    def test_a_missing_home_does_not_abort_the_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, *rest = self.probe(TEMP=temp, TMP=temp)
            self.assertEqual((root, rest), (str(Path(temp).resolve() / "rr-test-scratch"), [root] * 3))


if __name__ == "__main__":
    unittest.main()
