"""The log checker finds a changed byte in every record the engine writes for a command.

One obligation is taken through every kind of command the checker reads: a pack, an opening, a payment, an alias
(a payment of an origin already paid), a reversal, a payment of another origin, a payment that conflicts with that
origin, and an evaluation. The log is checked whole, then once for each byte of each kind's command record, its state
row, the first record of its evaluation reference, and the log's run-end record, with that one byte changed. Every
such log must be refused: the format has no byte the checker leaves free, but for the time of the log's first
command, which may be lower. The run-end record holds a digest of every record before it, which alone would refuse any
change; so after each change the digest is made right again, and only the checks on the records themselves can refuse
the log. A check weakened so that one field of one kind is no longer compared lets that field's bytes through, and this
fails. Synthetic, non-PHI, nonpayment.

The program is the pinned `obligations_shard` build (see `test_obligations_shard`)."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tests import test_obligations_shard as shard_tests
from tests.test_obligations_shard import RECORD, Scenario, frame, payment_frame, record, run, shard

# The command kinds, and the kind of the state row each is answered with, that this log holds.
EXPECTED = {(1, None), (2, 13), (5, 14), (5, 17), (6, 15), (5, 16), (12, 25)}
RUN_END, COMMAND, TEXT = 0x77, 0x74, 0xF5
AT = range(194, 202)  # a command record's time
DIGEST = slice(6, 70)  # a run-end record's digest


def seal(log: bytes) -> bytes:
    """`log`, a log of one run, with the place its run-end record names and the digest it holds made right."""
    end = len(log) - RECORD
    digest = hashlib.sha3_512(b"RR/OBLIG/RUN-END/v1" + bytes(5) + bytes(64) + log[:end]).digest()
    return log[:end + 1] + (end // RECORD).to_bytes(5, "little") + digest + log[end + DIGEST.stop:]


def one_of_each(scenario: Scenario) -> bytes:
    """The frames of every kind of command on the scenario's first obligation."""
    item, wire, now, at = scenario.item, scenario.wire, scenario.now, scenario.now + 10
    r = scenario.revisions[item] + 1
    reverse = {"kind": "reverse", "payment_id": f"{item}-p1", "evidence_id": f"{item}-r1", "common_origin_id": None, "event_at_ms": None}
    conflicting = record(item, "6", now, amount_cents=200, evidence_id=f"{item}-e6", local_ref="conflict-ref")
    return b"".join([
        shard_tests.pack_frame(now, wire),
        frame(2, now, wire),
        payment_frame(at, wire, record(item, "1", now), expected_revision=r),
        payment_frame(at, wire, record(item, "2", now), expected_revision=r + 1),
        payment_frame(at, wire, reverse, expected_revision=r + 1),
        payment_frame(at, wire, record(item, "8", now, common_origin_id=f"{item}-o8"), expected_revision=r + 2),
        payment_frame(at, wire, conflicting, expected_revision=r + 3),
        shard_tests.evaluate_frame(at, wire, f"{item}-eval-1"),
    ])


def targets(log: bytes) -> dict[str, int]:
    """For the first command of each (kind, state row kind): its record, its state row and the first record after the
    row; and the log's last record, its run-end record."""
    found: dict[tuple[int, int | None], int] = {}
    for i in range(len(log) // RECORD):
        if log[i * RECORD] == COMMAND:
            result = int.from_bytes(log[i * RECORD + 209:i * RECORD + 214], "little")
            row = None if result == 0 else log[(result - 1) * RECORD + 2]
            found.setdefault((log[i * RECORD + 1], row), i)
    assert set(found) == EXPECTED, set(found)
    out: dict[str, int] = {}
    for (kind, row), i in found.items():
        out[f"kind {kind} command record"] = i
        result = int.from_bytes(log[i * RECORD + 209:i * RECORD + 214], "little")
        if result:
            out[f"kind {kind} state row {row}"] = result - 1
            if log[result * RECORD] == TEXT:
                out[f"kind {kind} reference of row {row}"] = result
    out["run-end record"] = len(log) // RECORD - 1
    assert log[out["run-end record"] * RECORD] == RUN_END
    return out


class CheckerBytesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        shard_tests.program()
        cls.folder = tempfile.TemporaryDirectory(dir=os.environ.get("E3_SCRATCH"))
        cls.dir = Path(cls.folder.name)
        result, cls.answers, cls.log = shard(cls.dir / "log", one_of_each(Scenario()))
        cls.result = result

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def test_the_whole_log_checks(self) -> None:
        self.assertEqual(self.result.returncode, 0, self.result.stdout + self.result.stderr)
        self.assertEqual([a.split()[0] for a in self.answers], ["admitted"] * 8, self.answers)
        checked = run("check", str(self.dir / "log"))
        self.assertEqual(checked.returncode, 0, checked.stdout)
        self.assertIn("commands=8 ", checked.stdout)

    def test_a_changed_byte_in_any_command_record_state_row_reference_or_run_end_is_refused(self) -> None:
        places = targets(self.log)
        self.assertEqual(seal(self.log), self.log)
        first = places["kind 1 command record"]
        jobs = [(name, at, offset) for name, at in places.items() for offset in range(RECORD)
                if not (at == first and offset in AT)]

        def probe(job: tuple[str, int, int]) -> tuple[tuple[str, int, int], int, str]:
            name, at, offset = job
            changed = bytearray(self.log)
            changed[at * RECORD + offset] ^= 1
            path = self.dir / f"changed-{at}-{offset}"
            path.write_bytes(changed if name == "run-end record" else seal(bytes(changed)))
            checked = run("check", str(path))
            path.unlink()
            return job, checked.returncode, checked.stdout

        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(probe, jobs))
        accepted = [(name, offset) for (name, _, offset), code, _ in results if code != 1]
        self.assertEqual(accepted, [], "a changed byte the checker did not refuse")
        self.assertTrue(all("check failed" in out for _, code, out in results if code == 1))


if __name__ == "__main__":
    unittest.main()
