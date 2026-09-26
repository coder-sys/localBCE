"""run_batch: many commands share one durable commit, yet each stays atomic alone (Art. III)."""

import random
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import app.right_rail_financial_owner as owner_module
from app.right_rail_financial_owner import FinancialConflictError, FinancialIntegrityError, FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
from tests.test_right_rail_financial_acceptance import _Clock
from tools import load_synthetic as harness

_AUTHORITY = SyntheticTrustedAuthority()
_CRASH_CHILD = """
import itertools, os, sys
from tests.test_right_rail_financial_owner_batch import _commands, _open, _Owner
events = itertools.count(1)
_Owner.fail_on = lambda self, payload: os._exit(75) if next(events) == 3 else None  # two commands written, none committed
_open(sys.argv[1], _Owner).run_batch(_commands(12))
"""


class _Owner(FinancialOwner):
    """Refuses (or crashes) inside one command, after that command has already written rows."""

    def fail_on(self, payload):
        if payload.get("evidence_id") == "evidence:refused":
            raise FinancialIntegrityError("synthetic_refusal_after_writes")

    def _append_event(self, connection, **event):
        self.fail_on(event["payload"])
        return super()._append_event(connection, **event)


def _open(path, owner_type=FinancialOwner):
    config = FinancialOwnerConfig(**harness._SCOPE)
    return owner_type(path=Path(path), config=config, trusted_authority=_AUTHORITY, clock=_Clock(1_700_000_000_000))


def _commands(n):
    rng = random.Random(1)
    items = harness._build_cohort(random.Random(1), 4)
    return [harness._command(rng, items[i % 4], 1, i) for i in range(n)]


def _history(path):
    """Events, sealed segments and the open segment's tracking: all of history."""
    with closing(sqlite3.connect(path)) as connection:
        return [connection.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall() for table in ("financial_events", "history_segments", "history_pending", "history_open")]


def _rows(path):
    with closing(sqlite3.connect(path)) as connection:
        return owner_module._count_rows(connection)


def _support(evidence_id, origin="origin:batch"):
    return ("record_support_evidence", {"item_id": "item:000001", "evidence_id": evidence_id, "common_origin_id": origin, "received_at_ms": 1_700_000_000_000})  # a retry repeats its receipt time


class FinancialOwnerBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rr-owner-batch-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def _store(self, name, owner_type=FinancialOwner):
        owner = _open(self.directory / name, owner_type)
        harness._setup(owner, random.Random(1), 4, _AUTHORITY)
        return owner

    def test_batched_history_is_byte_identical_to_the_same_commands_run_singly(self) -> None:
        for seal_every in (4096, 5):  # 5: batches of 7 cross several seals, some mid-batch
            with self.subTest(seal_every=seal_every), mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", seal_every):
                single, batched = self._store(f"single-{seal_every}.sqlite"), self._store(f"batched-{seal_every}.sqlite")
                commands = _commands(40)
                single_results = [getattr(single, name)(**arguments) for name, arguments in commands]
                batched_results = [result for start in range(0, 40, 7) for result in batched.run_batch(commands[start:start + 7])]
                self.assertEqual(batched_results, single_results)
                self.assertEqual(_history(batched.path), _history(single.path))
                if seal_every == 5:
                    self.assertGreater(len(_history(batched.path)[1]), 8)  # the batches really crossed seals
                batched.verify_integrity()

    def test_a_refusal_mid_batch_rolls_back_the_whole_batch_and_its_seals(self) -> None:
        owner = self._store("isolation.sqlite", _Owner)
        history = _history(owner.path)
        with mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", 1), self.assertRaisesRegex(FinancialIntegrityError, "synthetic_refusal_after_writes") as refused:
            owner.run_batch([_support("evidence:kept-1"), _support("evidence:refused"), _support("evidence:kept-2")])  # kept-1 sealed a segment
        self.assertIn("batch_index=1", refused.exception.__notes__)
        self.assertEqual(_history(owner.path), history)
        with closing(sqlite3.connect(owner.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM evidence WHERE evidence_id IN ('evidence:kept-1','evidence:refused','evidence:kept-2')").fetchone()[0], 0)
        owner.verify_integrity()

    def test_cached_row_counts_stay_exact_through_batches_rollback_other_writers_and_reopen(self) -> None:
        self.assertTrue(owner_module._CHECK_ROW_CACHE)  # every commit below also recounts every table and compares
        owner, commands = self._store("counts.sqlite", _Owner), _commands(40)
        another = lambda: FinancialOwner(path=owner.path, config=owner.config, trusted_authority=_AUTHORITY, clock=owner.clock)  # same time line
        owner.run_batch(commands[:20])
        with self.assertRaisesRegex(FinancialIntegrityError, "synthetic_refusal_after_writes"):
            owner.run_batch([*commands[20:25], _support("evidence:refused")])  # its inserts roll back, uncounted
        another().run_batch(commands[20:30])  # another writer moves the history under this owner's cache
        for name, arguments in commands[30:]:
            getattr(owner, name)(**arguments)
        other, evaluate = another(), {"item_id": "item:000001"}
        for _ in range(3):  # two writers alternate: each cache must notice the other's commits
            other.evaluate_obligation(**evaluate)
            owner.evaluate_obligation(**evaluate)
        another().evaluate_obligation(**evaluate)  # a reopened owner counts afresh
        owner.evaluate_obligation(**evaluate)
        self.assertEqual(owner._row_cache[1], _rows(owner.path))
        owner.verify_integrity()

    def test_an_exact_retry_is_duplicate_and_a_changed_meaning_conflicts_as_alone(self) -> None:
        owner = self._store("retry.sqlite")
        self.assertEqual(owner.run_batch([_support("evidence:retry")])[0]["status"], "RECORDED")
        history = _history(owner.path)
        self.assertEqual(owner.run_batch([_support("evidence:retry")])[0]["status"], "DUPLICATE")
        changed = _support("evidence:retry", "origin:changed")
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            owner.run_batch([_support("evidence:retry"), changed])
        with self.assertRaisesRegex(FinancialConflictError, "evidence_identity_conflict"):
            owner.record_support_evidence(**changed[1])
        self.assertEqual(_history(owner.path), history)

    def test_a_crash_before_commit_leaves_no_part_of_the_batch(self) -> None:
        owner = self._store("crash.sqlite")
        history = _history(owner.path)
        root = Path(__file__).resolve().parents[1]
        child = subprocess.run([sys.executable, "-c", _CRASH_CHILD, str(owner.path)], cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(child.returncode, 75, child.stderr)
        reopened = _open(owner.path)  # opening rolls back the hot journal and replays history
        self.assertEqual(_history(owner.path), history)
        reopened.verify_integrity()


if __name__ == "__main__":
    unittest.main()
