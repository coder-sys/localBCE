"""The log checker reads each command on its own records: a log cut inside a command, or missing one record of one, is
refused; a log cut between commands is a log of fewer commands and checks.

The log is the one of `test_obligations_checker_bytes` (every kind of command, then the run-end record). It is checked
with every whole-record prefix, and with each record but the last removed in turn, the digest of the run-end record
made right again so that it does not refuse the log first. A check weakened so that a command
may end short of its own records, or so that a lost record goes unnoticed, accepts one of these and this fails.
Synthetic, non-PHI, nonpayment.

The program is the pinned `obligations_shard` build (see `test_obligations_shard`)."""

from __future__ import annotations

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tests import test_obligations_shard as shard_tests
from tests.test_obligations_checker_bytes import COMMAND, RUN_END, one_of_each, seal
from tests.test_obligations_shard import RECORD, Scenario, run, shard


class CheckerRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        shard_tests.program()
        cls.folder = tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH"))
        cls.dir = Path(cls.folder.name)
        result, _, cls.log = shard(cls.dir / "log", one_of_each(Scenario()))
        assert result.returncode == 0, result.stdout + result.stderr
        cls.count = len(cls.log) // RECORD

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def check(self, name: str, data: bytes) -> tuple[int, str]:
        path = self.dir / name
        path.write_bytes(data)
        checked = run("check", str(path))
        path.unlink()
        return checked.returncode, checked.stdout

    def test_a_log_cut_inside_a_command_is_refused_and_one_cut_between_commands_checks(self) -> None:
        starts = [i for i in range(self.count) if self.log[i * RECORD] == COMMAND]
        self.assertEqual(len(starts), 8)

        def probe(k: int) -> tuple[int, int, str]:
            return (k, *self.check(f"prefix-{k}", self.log[:k * RECORD]))

        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(probe, range(1, self.count + 1)))
        for k, code, out in results:
            between = k == self.count or self.log[k * RECORD] in (COMMAND, RUN_END)
            with self.subTest(records=k):
                if between:
                    self.assertEqual(code, 0, out)
                    self.assertIn(f"commands={sum(1 for s in starts if s < k)} ", out)
                else:
                    self.assertEqual(code, 1, out)
                    self.assertIn("check failed", out)

    def test_a_log_missing_any_one_record_before_its_last_is_refused(self) -> None:
        def probe(i: int) -> tuple[int, int, str]:
            return (i, *self.check(f"dropped-{i}", seal(self.log[:i * RECORD] + self.log[(i + 1) * RECORD:])))

        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(probe, range(self.count - 1)))
        self.assertEqual([i for i, code, _ in results if code != 1], [])
        self.assertTrue(all("check failed" in out and "run-end" not in out for _, _, out in results))


if __name__ == "__main__":
    unittest.main()
