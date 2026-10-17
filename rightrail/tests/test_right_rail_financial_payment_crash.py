"""M3 step 5: a crash of the engine worker or the owner process at each point around a Lean payment decision and its commit leaves
the store verifying, with no payment half-written or doubled, and a retry gives the answer a never-crashed run gives."""

import json
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app.right_rail_financial_owner_independent import verify_database
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as acceptance
from tests import test_right_rail_financial_semantic_adapter as adapter_tests
from tools import right_rail_financial_cli as cli

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = expected.H_CASH_EVIDENCE
_SCRIPT = '''
import os, sys
from contextlib import contextmanager
sys.path.insert(0, sys.argv[1])
from app import right_rail_financial_engine as engine
from app.right_rail_financial_mirror import FinancialMirror
from app.right_rail_financial_owner import FinancialOwner
from tools.right_rail_financial_cli import main
point, kind = sys.argv[2:4]
if kind == "reverse":
    FinancialMirror.record_payment_evidence = lambda self, item_id, payment_id, evidence_id, expected_revision, **_: self._command_result(
        self.owner.reverse_payment(item_id=item_id, payment_id=payment_id, evidence_id=evidence_id, expected_revision=expected_revision))
asked, real_decide, real_write = [False], engine.decide_payment_live, FinancialOwner._write
def decide(*args, **kwargs):
    asked[0] = True
    if point == "answer":
        os._exit(73)  # the owner dies before Lean's answer exists
    return real_decide(*args, **kwargs)
engine.decide_payment_live = decide
@contextmanager
def crashing(self, **kwargs):
    with real_write(self, **kwargs) as connection:
        yield connection
        if point == "commit" and asked[0]:
            os._exit(74)  # the answer is applied to the open transaction, COMMIT has not run
    if point == "receipt" and asked[0]:
        os._exit(75)  # COMMIT ran, the caller has no receipt
FinancialOwner._write = crashing
raise SystemExit(main(sys.argv[4:]))
'''
_TABLES = ("payments", "evidence", "financial_events", "financial_conflicts")


def _state(path: Path) -> dict:
    """What a restart finds: the payment rows, and how many evidence, event and conflict rows the store holds."""
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        rows = {name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in _TABLES}
        rows["payments_active"] = connection.execute("SELECT payment_id,amount_cents,active FROM payments ORDER BY payment_id").fetchall()
        rows["revision"] = connection.execute("SELECT revision FROM obligations WHERE item_id=?", (_EVIDENCE.item_id,)).fetchone()[0]
        return rows


class PaymentCrashTests(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        self.fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.directory = Path(self.fixture.temp_dir.name)
        self.store = self.fixture._build_base()

    def _command(self, kind: str) -> dict:
        if kind == "reverse":
            return {"payment_id": "payment:h:cash", "evidence_id": "crash-reversal"}
        return {"payment_id": "crash-payment", "common_origin_id": "crash-origin", "amount_cents": 100, "evidence_id": "crash-evidence",
                "event_at_ms": _EVIDENCE.event_at_ms, "source_id": "crash-source", "source_version": "v1"}

    def _run(self, store, kind: str, revision: int) -> dict:
        """One command on `store`, through the owner method the CLI reaches, at the revision the caller first read."""
        if kind == "reverse":
            return store.reverse_payment(item_id=_EVIDENCE.item_id, expected_revision=revision, **self._command(kind))
        return store.record_payment_evidence(item_id=_EVIDENCE.item_id, expected_revision=revision, **self._command(kind))

    def _prepare(self, kind: str) -> None:
        if kind == "reverse":
            acceptance._record_fixture_payment(self.store, _EVIDENCE, payment_id="payment:h:cash")

    def _verify(self, path: Path) -> None:
        verify_database(path, expected_scope=self.store._scope_value(), expected_authority=owner_module._checker_authority(self.fixture.authority))

    def _cli(self, path: Path, point: str, kind: str, revision: int) -> subprocess.CompletedProcess:
        authority = self.directory / "authority.json"
        authority.write_bytes(json.dumps(cli.authority_file_record(self.fixture.authority)).encode())
        command = self._command(kind)
        args = ["--database", str(path), "--authority-file", str(authority)]
        for key, value in self.store._scope_value().items():
            args += ["--" + key.replace("_", "-"), str(value)]
        args += ["record-payment-evidence", "--item-id", _EVIDENCE.item_id, "--payment-id", command["payment_id"], "--evidence-id", command["evidence_id"],
                 "--expected-revision", str(revision), "--common-origin-id", command.get("common_origin_id", "x"), "--amount-cents", str(command.get("amount_cents", 1)),
                 "--event-at-ms", str(command.get("event_at_ms", 1))]
        return subprocess.run([sys.executable, "-I", "-c", _SCRIPT, str(_ROOT), point, kind, *args], capture_output=True, timeout=120)

    def test_the_owner_dying_at_each_point_leaves_a_store_a_retry_completes_once(self) -> None:
        for kind in ("record", "reverse"):
            self._prepare(kind)
            image = acceptance._image(Path(self.store.path))
            revision = _state(Path(self.store.path))["revision"]
            twin = self.directory / f"twin-{kind}.sqlite"
            twin.write_bytes(image)
            clean = self._cli(twin, "none", kind, revision)
            self.assertEqual((clean.returncode, clean.stderr), (0, b""), kind)
            clean_answer, clean_state = json.loads(clean.stdout), _state(twin)
            for point, code in (("answer", 73), ("commit", 74), ("receipt", 75)):
                with self.subTest(kind=kind, point=point):
                    path = self.directory / f"{kind}-{point}.sqlite"
                    path.write_bytes(image)
                    before = _state(path)
                    crashed = self._cli(path, point, kind, revision)
                    self.assertEqual((crashed.returncode, crashed.stdout, crashed.stderr), (code, b"", b""))
                    self._verify(path)
                    self.assertEqual(_state(path), clean_state if point == "receipt" else before)  # COMMIT is the only thing that writes
                    retry = self._cli(path, "none", kind, revision)
                    self.assertEqual((retry.returncode, retry.stderr), (0, b""))
                    answer = json.loads(retry.stdout)
                    self.assertEqual(answer["status"], "DUPLICATE" if point == "receipt" else clean_answer["status"])
                    self.assertEqual({k: v for k, v in answer.items() if k not in ("status", "payment_id")}, {k: v for k, v in clean_answer.items() if k not in ("status", "payment_id")})
                    self.assertEqual(_state(path), clean_state)  # recorded once, never doubled
                    self._verify(path)

    def _kill_worker(self, when: str):
        """Patch the worker so its process is killed just before a frame is written, or just after the engine has read its answer and its memory.

        "after" kills inside commit_bytes once the real reading is taken, so the engine's recycle check never sees a dead process and the dead worker stays in place."""
        real_exchange, real_commit = process.ContainedWorker.exchange, process.ContainedWorker.commit_bytes

        def exchange(worker, *args, **kwargs):
            worker._kernel32.TerminateJobObject(worker._job, 1)
            return real_exchange(worker, *args, **kwargs)

        def commit_bytes(worker):
            reading = real_commit(worker)
            worker._kernel32.TerminateJobObject(worker._job, 1)
            return reading
        return patch.object(process.ContainedWorker, "exchange" if when == "before" else "commit_bytes", exchange if when == "before" else commit_bytes)

    def _fresh(self, kind: str, name: str):
        store = self.fixture._build_base(path=self.directory / name)
        if kind == "reverse":
            acceptance._record_fixture_payment(store, _EVIDENCE, payment_id="payment:h:cash")
        return store

    def test_the_worker_killed_before_its_answer_writes_nothing_and_a_retry_matches_a_clean_run(self) -> None:
        for kind in ("record", "reverse"):
            with self.subTest(kind=kind):
                clean = self._fresh(kind, f"clean-{kind}.sqlite")
                revision = _state(Path(clean.path))["revision"]
                clean_answer, store = self._run(clean, kind, revision), self._fresh(kind, f"killed-{kind}.sqlite")
                before = _state(Path(store.path))
                with self._kill_worker("before"), self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                    self._run(store, kind, revision)
                self.assertEqual(str(raised.exception), "lean_payment:evaluator_containment")
                self.assertEqual(_state(Path(store.path)), before)
                self._verify(Path(store.path))
                self.assertEqual(self._run(store, kind, revision), clean_answer)
                self.assertEqual(_state(Path(store.path)), _state(Path(clean.path)))
                self._verify(Path(store.path))

    def test_the_worker_killed_after_its_answer_still_commits_once_and_a_retry_is_the_same_payment(self) -> None:
        for kind in ("record", "reverse"):
            with self.subTest(kind=kind):
                engine._close_evaluator()  # a fresh worker and a zero request count: the recycle backstop cannot fire
                clean = self._fresh(kind, f"clean-{kind}.sqlite")
                revision = _state(Path(clean.path))["revision"]
                clean_answer, store = self._run(clean, kind, revision), self._fresh(kind, f"killed-{kind}.sqlite")
                with self._kill_worker("after"):
                    self.assertEqual(self._run(store, kind, revision), clean_answer)
                self.assertEqual(_state(Path(store.path)), _state(Path(clean.path)))
                with self.assertRaises(owner_module.FinancialIntegrityError) as raised:  # the next frame finds the dead worker: closed, nothing written
                    self._run(store, kind, revision)
                self.assertEqual(str(raised.exception), "lean_payment:evaluator_containment")
                retry = self._run(store, kind, revision)
                self.assertEqual((retry["status"], {k: v for k, v in retry.items() if k not in ("status", "payment_id")}),
                                 ("DUPLICATE", {k: v for k, v in clean_answer.items() if k not in ("status", "payment_id")}))
                self.assertEqual(_state(Path(store.path)), _state(Path(clean.path)))
                self._verify(Path(store.path))


if __name__ == "__main__":
    unittest.main()
