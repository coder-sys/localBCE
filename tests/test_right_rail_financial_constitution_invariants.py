"""Constitution-critical invariants for the RightRail financial correction slice.

Each test names the articles of ``CONSTITUTION.md`` it enforces:

* ``test_lean_containment_timeout_and_malformed_results_never_fall_back``
  V.2 (no silent fallback when Lean fails), III.5 (failure is closed, visible
  and loses no work), XI.10 (timed-out, malformed, partial or cleanup-failed
  state never creates authority), XI.5 (the Engine process is untrusted until
  its bytes are strictly decoded and bound).
* ``test_lean_rejected_results_map_to_typed_errors_without_mutation``
  V.1/V.2 (Lean decides; a Lean rejection is final and is never re-decided in
  Python), III.5, XI.13 (authority is never inferred from a process exit or a
  caller-chosen status).
* ``test_crash_after_correction_commit_before_followup_drains_once``
  III.2 (history, projection and action/outbox commit atomically), III.3
  (a lost response after commit recovers as an exact-retry DUPLICATE),
  XI.12 (restart and idempotency before optimization).
* ``test_unrelated_item_fact_preserves_valid_h_evaluation``
  III.3 (expected revision and evaluation identity are per responsibility,
  not global), IX.3 (ordinary work scales with the change, not with total
  history).
* ``test_relevant_late_h_payment_invalidates_prior_evaluation``
  III.3 (changed meaning is a conflict), III.5, XI.10 (stale state never
  creates authority).
* ``test_correction_requests_only_the_unpaid_balance``
  II and III.4 (a correction asks only for money actually short: zero
  shortfall is a Lean rejection with no write; otherwise min(claim, shortfall)).
* ``test_open_requests_stay_within_the_unpaid_balance``
  II and III.4 (R2: after every command the correction requests may together
  collect exactly min(what they leave unpaid, the unpaid balance), oldest
  first), V.4 (the expected amounts are derived here, not by the owner).

Every test also carries VI (honest claims): these are synthetic, non-PHI,
nonpayment fixtures; a local pass is "verified locally", never "qualified",
and the standing claims ``proofSuiteId=null``, ``production_usable=false``,
``activation=false`` are unchanged.

Pinned Engine artifact.  Every test here builds its owner through
``_build_base_for_correction``, and corrections run on the pinned evaluator
worker in ``artifacts/engine-evaluator`` (since M4 P1 the one-shot correction
exe is retired).  The ``_requires_pinned_correction_engine`` marker on each
test states whether the worker is actually executed or its answer stubbed.  A
missing or mismatched artifact is a hard failure, never a skip (VI.3).

The fixtures are reused unchanged from ``tests.test_right_rail_financial_acceptance``.
That test class is deliberately never bound to a name in this module so that
unittest and pytest do not collect and re-run the acceptance suite here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from typing import Any, TypeVar
import unittest
from unittest.mock import MagicMock, patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as financial_engine
from app.right_rail_financial_owner import (
    FinancialAuthorityError,
    FinancialConflictError,
    FinancialError,
    FinancialIntegrityError,
    FinancialOwner,
    FinancialRevisionError,
    SyntheticTrustedAuthority,
)
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as acceptance


_TestMethod = TypeVar("_TestMethod", bound=Callable[..., Any])


def _requires_pinned_correction_engine(usage: str) -> Callable[[_TestMethod], _TestMethod]:
    """Mark a test that needs the pinned evaluator worker.

    ``usage`` says whether the pinned worker is executed or only hashed.  The
    marker never skips: a missing artifact fails the test (VI.3).
    """

    def mark(test: _TestMethod) -> _TestMethod:
        test.requires_pinned_correction_engine = usage  # type: ignore[attr-defined]
        return test

    return mark


# Raw class attributes (staticmethod descriptors preserved) of the acceptance
# fixtures.  A mappingproxy is not a TestCase, so nothing extra is collected.
_ACCEPTANCE = vars(acceptance.RightRailFinancialAcceptanceTests)


class _AcceptanceFixtures:
    """The acceptance suite's owner fixtures, borrowed without modification."""

    _path = _ACCEPTANCE["_path"]
    _make_owner = _ACCEPTANCE["_make_owner"]
    _durable_counts = _ACCEPTANCE["_durable_counts"]
    _run_process_boundary = _ACCEPTANCE["_run_process_boundary"]
    _pack = _ACCEPTANCE["_pack"]
    _items = _ACCEPTANCE["_items"]
    _population_manifest = _ACCEPTANCE["_population_manifest"]
    _build_base = _ACCEPTANCE["_build_base"]
    _build_base_for_correction = _ACCEPTANCE["_build_base_for_correction"]
    _record_support = _ACCEPTANCE["_record_support"]
    _record_cash = _ACCEPTANCE["_record_cash"]
    _advance_clock = _ACCEPTANCE["_advance_clock"]
    _record_claim = _ACCEPTANCE["_record_claim"]
    _reject = _ACCEPTANCE["_reject"]
    _record_p2 = _ACCEPTANCE["_record_p2"]
    _assert_snapshot = _ACCEPTANCE["_assert_snapshot"]
    _assert_verified = _ACCEPTANCE["_assert_verified"]
    _assert_decision_package_verified = _ACCEPTANCE["_assert_decision_package_verified"]
    _two_claim_corrections = _ACCEPTANCE["_two_claim_corrections"]
    _pay_a = _ACCEPTANCE["_pay_a"]


# --- Independent BLFCRES3 encoder ------------------------------------------------
# Written from the wire layout in ``decode_correction_transition_result`` and
# deliberately independent of the adapter's private writer.  Every payload is
# checked against the real decoder before it is fed to the owner, so a wrong
# encoder fails loudly instead of passing for the wrong reason.

_ABSENT = b"\x00"
_CORRECTION_TRANSITION_TAG = 1  # OFFSET_REJECTED_CORRECTION_AUTHORIZED


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _u16(len(raw)) + raw


def _some_byte(value: int) -> bytes:
    return b"\x01" + bytes([value])


def _some_text(value: str) -> bytes:
    return b"\x01" + _text(value)


def _some_nat(value: int) -> bytes:
    return b"\x01" + value.to_bytes(8, "big")


def _result_header(status_tag: int, contract: str = financial_engine.CORRECTION_TRANSITION_OPERATION) -> bytes:
    return b"BLFCRES3" + _u16(3) + bytes([status_tag]) + _text(contract)


def _rejected_transition_result(reason_tag: int, requirement_tag: int) -> bytes:
    return b"".join(
        (
            _result_header(3),
            _some_byte(reason_tag),  # result reject reason
            bytes([3]),  # explanation code REJECTED
            _ABSENT,  # explanation transition
            _some_byte(reason_tag),  # explanation reject reason
            _some_byte(requirement_tag),  # explanation unresolved requirement
            _ABSENT,  # explanation claim id
            _ABSENT,  # explanation action id
            _ABSENT,  # explanation input evaluation id
            _ABSENT,  # explanation expected revision
            _ABSENT,  # explanation resulting revision
            _ABSENT,  # result action id
            _ABSENT,  # result determination id
            _ABSENT,  # mutation
        )
    )


def _duplicate_transition_result(*, action_id: str, claim_id: str, evaluation_id: str, expected_revision: int) -> bytes:
    return b"".join(
        (
            _result_header(2),
            _ABSENT,  # result reject reason
            bytes([2]),  # explanation code EXACT_RETRY
            _some_byte(_CORRECTION_TRANSITION_TAG),
            _ABSENT,  # explanation reject reason
            _ABSENT,  # explanation unresolved requirement
            _some_text(claim_id),
            _some_text(action_id),
            _some_text(evaluation_id),
            _some_nat(expected_revision),
            _ABSENT,  # explanation resulting revision
            _some_text(action_id),
            _some_text(f"determination:{action_id}"),
            _ABSENT,  # mutation
        )
    )


def _accepted_without_mutation(*, action_id: str, claim_id: str, evaluation_id: str, expected_revision: int) -> bytes:
    return b"".join(
        (
            _result_header(1),
            _ABSENT,  # result reject reason
            bytes([1]),  # explanation code CORRECTION_AUTHORIZED
            _some_byte(_CORRECTION_TRANSITION_TAG),
            _ABSENT,
            _ABSENT,
            _some_text(claim_id),
            _some_text(action_id),
            _some_text(evaluation_id),
            _some_nat(expected_revision),
            _some_nat(expected_revision + 1),
            _some_text(action_id),
            _some_text(f"determination:{action_id}"),
            _ABSENT,  # mutation missing: an ACCEPTED claim without its delta
        )
    )


# (reason, reason tag, requirement tag, owner error class, owner error code).
# Tags and the owner mapping are written out independently of the engine's
# private tables (V.4: expected answers are not derived from the code under test).
# Failure modes after which the engine recycles the live worker; a decodable-but-refused answer leaves it running.
_RECYCLED_FAILURES = frozenset({
    "containment_error", "worker_timeout", "worker_stderr", "worker_exchange_or_job_cap_kill", "worker_response_cap",
    "worker_frame_cap", "worker_unavailable", "timeout_raised", "unexpected_exception",
})
_LEAN_REJECTIONS: tuple[tuple[str, int, int, type[FinancialError], str], ...] = (
    ("SCOPE_MISMATCH", 4, 4, FinancialIntegrityError, "correction_scope_mismatch"),
    ("AUTHORITY_STALE", 5, 5, FinancialAuthorityError, "determination_authority_stale"),
    ("REVISION_CONFLICT", 8, 8, FinancialRevisionError, "obligation_revision_conflict"),
    ("EVALUATION_CONSUMED", 10, 10, FinancialConflictError, "evaluation_already_consumed"),
    ("CAPACITY", 17, 17, FinancialIntegrityError, "history_capacity"),
    ("NO_SHORTFALL", 20, 20, FinancialConflictError, "correction_no_shortfall"),
)


class RightRailFinancialConstitutionInvariantTests(_AcceptanceFixtures, unittest.TestCase):
    """Constitution-critical correction invariants (pinned Engine required)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-financial-constitution-")
        self.addCleanup(self.temp_dir.cleanup)
        self._path_counter = 0
        self.authority = SyntheticTrustedAuthority()

    # --- helpers ---------------------------------------------------------------

    def _durable_state(self, store: FinancialOwner) -> dict[str, object]:
        """Byte-level identity of everything durable the owner can have written.

        WAL (R0.5; XI.2 record in docs/CORE_REDESIGN.md): the database is the image a crash recovery reads, the
        main file plus every committed -wal frame, taken through a read-only connection that never checkpoints.
        The main file's bytes and the -wal/-shm names depend on which connection closed last, not on any commit."""

        with closing(sqlite3.connect(store.path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            database = connection.serialize()
        sidecars = sorted(
            path.name
            for path in store.path.parent.iterdir()
            if path.name.startswith(store.path.name) and path.name not in {store.path.name, f"{store.path.name}-wal", f"{store.path.name}-shm"}
        )
        return {
            "database_image_sha256": hashlib.sha256(database).hexdigest(),
            "database_image_size": len(database),
            "sidecars": sidecars,
            "continuity_sha256": hashlib.sha256(store.export_continuity()).hexdigest(),
            "counts": self._durable_counts(store.path),
            "summary": store.summary(),
        }

    @contextmanager
    def _commits(self, store: FinancialOwner, committed: bool) -> Iterator[None]:
        """A probe held open across the step: PRAGMA data_version moves iff another connection committed a page,
        even one a later commit restored, which the image above cannot see (III.3; XI.2 record)."""

        with closing(sqlite3.connect(store.path.resolve().as_uri() + "?mode=ro", uri=True)) as probe:
            version = probe.execute("PRAGMA data_version").fetchone()[0]
            yield
            self.assertEqual(probe.execute("PRAGMA data_version").fetchone()[0] != version, committed)

    def _correction_evidence(self, store: FinancialOwner) -> tuple[int, int]:
        detail = store.obligation_detail(expected.H_ITEM_ID)
        return len(detail["determinations"]), len(detail["actions"])

    @staticmethod
    def _worker(**exchange: object) -> MagicMock:
        """A stand-in for the live evaluator worker whose one exchange answers, or fails, as given."""

        return MagicMock(exchange=MagicMock(**exchange), commit_bytes=MagicMock(return_value=1))

    @contextmanager
    def _python_decision_paths_forbidden(self, store: FinancialOwner) -> Iterator[None]:
        """Fail if any non-Lean decision path runs (V.2: no silent fallback)."""

        with patch.object(
            store,
            "_recompute_obligation",
            side_effect=AssertionError("separate_evaluation_during_transition"),
        ) as recompute, patch.object(
            store,
            "_apply_accepted_correction_transition",
            side_effect=AssertionError("apply_without_lean_acceptance"),
        ) as apply_accepted:
            yield
        recompute.assert_not_called()
        apply_accepted.assert_not_called()

    def _prepare_h_claim(self) -> tuple[FinancialOwner, str, dict[str, Any]]:
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        return store, claim_id, receipt

    def _assert_engine_failure_is_closed(
        self,
        store: FinancialOwner,
        claim_id: str,
        receipt: dict[str, Any],
        *,
        worker: MagicMock | None = None,
        launch_error: Exception | None = None,
        closed: bool = False,
        error_type: type[FinancialError],
        error_code: str,
    ) -> None:
        before = self._durable_state(store)
        live = financial_engine._running_evaluator()  # the real worker the failure may recycle
        workspace = financial_engine._evaluator[1]
        with patch.object(financial_engine, "_running_evaluator", return_value=worker, side_effect=launch_error):
            with self._python_decision_paths_forbidden(store):
                with self.assertRaises(FinancialError) as raised:
                    self._reject(store, claim_id, receipt)
        # Typed, stable, and never the untyped base class.
        self.assertIs(type(raised.exception), error_type)
        self.assertEqual(str(raised.exception), error_code)
        # The owner really consulted the pinned Lean worker exactly once.
        if worker is not None:
            self.assertEqual(worker.exchange.call_count, 1)
            self.assertTrue(worker.exchange.call_args.args[0].startswith(b"BLFCMD03"))
        # A failure that may leave the worker out of step recycles it; either way no workspace outlives its worker (III.5).
        self.assertEqual(live.alive, not closed)
        self.assertEqual(workspace.exists(), not closed)
        self.assertEqual(financial_engine._evaluator == [], closed)
        # No partial change of any kind (III.5).
        self.assertEqual(self._durable_state(store), before)
        self.assertEqual(self._correction_evidence(store), (0, 0))
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID), receipt)

    # --- 1. Lean failure never falls back ---------------------------------------

    @_requires_pinned_correction_engine(
        "artifact identity is hashed for every failure mode; the binary is executed once, "
        "only for the final recovery retry"
    )
    def test_lean_containment_timeout_and_malformed_results_never_fall_back(self) -> None:
        store, claim_id, receipt = self._prepare_h_claim()
        revision = int(receipt["revision"])
        evaluation_id = str(receipt["evaluation_id"])
        action_id = expected.ACTION_CORRECTION_ID
        valid_rejection = _rejected_transition_result(4, 4)

        # Controls: the independent encodings decode (or fail) as intended.
        self.assertEqual(
            financial_engine.decode_correction_transition_result(valid_rejection)["reject_reason"],
            "SCOPE_MISMATCH",
        )
        malformed_payloads = {
            "garbage": b"garbage",
            "empty": b"",
            "truncated": valid_rejection[:-1],
            "trailing_byte": valid_rejection + b"\x00",
            "wrong_magic": b"BLFCRES1" + valid_rejection[8:],
            "unknown_status": b"BLFCRES3" + _u16(3) + b"\x09" + valid_rejection[11:],
            "wrong_contract": _result_header(3, "RR/FINANCIAL/CORRECTION-TRANSITION/v2") + valid_rejection[len(_result_header(3)):],
            "rejection_requirement_mismatch": _rejected_transition_result(8, 5),
            "accepted_without_mutation": _accepted_without_mutation(
                action_id=action_id,
                claim_id=claim_id,
                evaluation_id=evaluation_id,
                expected_revision=revision,
            ),
        }
        for name, payload in malformed_payloads.items():
            with self.subTest(control=name):
                with self.assertRaises(financial_engine.FinancialEngineError):
                    financial_engine.decode_correction_transition_result(payload)

        failure_modes: dict[str, MagicMock] = {
            "containment_error": self._worker(side_effect=process.VerifierProcessError("synthetic_containment_failure")),
            # The retired exe's timed-out, stderr, cap, cleanup and measurement modes, as the live worker reports them.
            "worker_timeout": self._worker(side_effect=process.VerifierProcessError("worker_timeout")),
            "worker_stderr": self._worker(side_effect=process.VerifierProcessError("worker_stderr")),
            "worker_exchange_or_job_cap_kill": self._worker(side_effect=process.VerifierProcessError("worker_exchange")),
            "worker_response_cap": self._worker(side_effect=process.VerifierProcessError("worker_response_cap")),
            "worker_frame_cap": self._worker(side_effect=process.VerifierProcessError("worker_frame_cap")),
            "worker_unavailable": self._worker(side_effect=process.VerifierProcessError("worker_unavailable")),
            "timeout_raised": self._worker(side_effect=TimeoutError("synthetic_timeout")),
            "unexpected_exception": self._worker(side_effect=OSError("synthetic_os_error")),
            "answer_not_bytes": self._worker(return_value="not bytes"),
            "decode_refused": self._worker(return_value=b"\x01"),
            "evaluation_rejected_tag": self._worker(return_value=b"\x02"),
            "encoding_failed": self._worker(return_value=b"\x03"),
            "unknown_answer_tag": self._worker(return_value=b"\x09"),
            "refusal_with_a_body": self._worker(return_value=b"\x01" + valid_rejection),
        }
        for name, payload in malformed_payloads.items():
            failure_modes[f"malformed_{name}"] = self._worker(return_value=b"\x00" + payload)

        for name, worker in failure_modes.items():
            with self.subTest(failure_mode=name):
                self._assert_engine_failure_is_closed(
                    store,
                    claim_id,
                    receipt,
                    worker=worker,
                    closed=name in _RECYCLED_FAILURES or name.startswith("malformed_"),
                    error_type=FinancialIntegrityError,
                    error_code="correction_transition_failed",
                )
        with self.subTest(failure_mode="launcher_os_error"):  # %TEMP% full or access denied while a worker is (re)launched
            self._assert_engine_failure_is_closed(
                store, claim_id, receipt, launch_error=OSError("synthetic_launch_failure"), closed=True,
                error_type=FinancialIntegrityError, error_code="correction_transition_failed",
            )

        # Lean reports DUPLICATE although the owner holds no action: never
        # treated as success.
        forged_duplicate = _duplicate_transition_result(
            action_id=action_id,
            claim_id=claim_id,
            evaluation_id=evaluation_id,
            expected_revision=revision,
        )
        self.assertEqual(
            financial_engine.decode_correction_transition_result(forged_duplicate)["status"],
            "DUPLICATE",
        )
        with self.subTest(failure_mode="duplicate_without_owner_action"):
            self._assert_engine_failure_is_closed(
                store,
                claim_id,
                receipt,
                worker=self._worker(return_value=b"\x00" + forged_duplicate),
                error_type=FinancialIntegrityError,
                error_code="correction_duplicate_without_action",
            )

        # Loses no work (III.5): the same command, unpatched, is still accepted
        # by the real pinned Engine exactly once.
        committed = self._reject(store, claim_id, receipt)
        self.assertEqual(committed["status"], "CORRECTION_AUTHORIZED")
        self.assertEqual(self._correction_evidence(store), (1, 1))
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        self._assert_verified(store)

    @_requires_pinned_correction_engine("the pinned worker is launched and killed")
    def test_a_dead_live_worker_fails_closed_and_is_replaced_by_a_clean_one(self) -> None:
        """The process-level modes on the real worker process: a gone worker is a typed failure with no change (it was the
        retired exe's cleanup/measurement/cap failures), and the next use is a fresh, accepted worker."""

        store, claim_id, receipt = self._prepare_h_claim()
        self.addCleanup(financial_engine._close_evaluator)
        dead = financial_engine._running_evaluator()
        dead_workspace = financial_engine._evaluator[1]
        dead.close()
        self.assertFalse(dead.alive)
        self._assert_engine_failure_is_closed(
            store, claim_id, receipt, worker=MagicMock(wraps=dead), closed=True,
            error_type=FinancialIntegrityError, error_code="correction_transition_failed",
        )
        self.assertFalse(dead_workspace.exists())  # the dead worker's workspace is reaped when it is replaced
        with patch.object(financial_engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 0):  # measured over the bound: recycled, closed
            committed = self._reject(store, claim_id, receipt)
        self.assertEqual(committed["status"], "CORRECTION_AUTHORIZED")
        self.assertEqual(financial_engine._evaluator, [])
        self.assertEqual(self._correction_evidence(store), (1, 1))

    @_requires_pinned_correction_engine("artifact identity is hashed; the binary is never executed")
    def test_lean_rejected_results_map_to_typed_errors_without_mutation(self) -> None:
        store, claim_id, receipt = self._prepare_h_claim()
        baseline = self._durable_state(store)
        for reason, reason_tag, requirement_tag, error_type, error_code in _LEAN_REJECTIONS:
            payload = _rejected_transition_result(reason_tag, requirement_tag)
            decoded = financial_engine.decode_correction_transition_result(payload)
            self.assertEqual(decoded["status"], "REJECTED")
            self.assertEqual(decoded["reject_reason"], reason)
            with self.subTest(reject_reason=reason):
                self._assert_engine_failure_is_closed(
                    store,
                    claim_id,
                    receipt,
                    worker=self._worker(return_value=b"\x00" + payload),
                    error_type=error_type,
                    error_code=error_code,
                )
        # Repeated Lean rejections accumulate nothing.
        self.assertEqual(self._durable_state(store), baseline)
        self._assert_snapshot(store, expected.H_CASH_AND_CLAIM)
        self._assert_verified(store)

    # --- 2. Crash after commit, before follow-up ----------------------------------

    @_requires_pinned_correction_engine("the binary is executed once, in the crashing child process")
    def test_crash_after_correction_commit_before_followup_drains_once(self) -> None:
        store, claim_id, receipt = self._prepare_h_claim()
        clock_value = max(store.clock.value + 1_000_000, expected.CORRECTION_AUTH_MS)  # type: ignore[attr-defined]  # not before the decision

        with tempfile.TemporaryDirectory() as child_temp:
            with patch.dict(os.environ, {"TMP": child_temp, "TEMP": child_temp}), self._commits(store, True):
                crashed = self._run_process_boundary(store=store, claim_id=claim_id, fault="process_postcommit", clock_value=clock_value)
            # os._exit ran no cleanup: the child's worker died with its job (so its workspace is removable) and wrote nothing there.
            (workspace,) = Path(child_temp).glob("rr-evaluator-*")
            self.assertEqual(list(workspace.iterdir()), [])
            for _ in range(50):
                shutil.rmtree(workspace, ignore_errors=True)
                if not workspace.exists():
                    break
                time.sleep(0.1)
            self.assertFalse(workspace.exists(), "the crashed child's worker is still running")
        # The child committed, then died before returning or draining anything.
        self.assertEqual(crashed.returncode, 74)
        self.assertEqual(crashed.stdout, "PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n")
        self.assertEqual(crashed.stderr, "")

        reopened = self._make_owner(path=store.path, clock=acceptance._Clock(clock_value + 1))
        # III.2: determination, action, outbox, projection and event are all present.
        counts = self._durable_counts(reopened.path)
        self.assertEqual(counts["determinations"], 1)
        self.assertEqual(counts["actions"], 1)
        self.assertEqual(counts["action_outbox"], 1)
        self._assert_snapshot(reopened, expected.H_REJECTED_CORRECTION)
        self._assert_verified(reopened)
        committed_state = self._durable_state(reopened)
        self.enterContext(self._commits(reopened, False))  # checked at cleanup: no drain or retry below commits
        first = reopened.drain_correction_followups(limit=10)
        self.assertEqual(first["count"], 1)
        self.assertFalse(first["has_more"])
        self.assertEqual(first["skipped"], {"count": 0, "reasons": {}})
        self.assertEqual(first["items"][0]["work_id"], expected.ACTION_CORRECTION_ID)
        self.assertEqual(first["items"][0]["followup_status"], "CURRENT")
        self.assertEqual(first["next_after_event_sequence"], first["items"][0]["source_event_sequence"])

        second = reopened.drain_correction_followups(
            after_event_sequence=first["next_after_event_sequence"],
            limit=10,
        )
        self.assertEqual(second["count"], 0)
        self.assertEqual(second["items"], [])
        self.assertFalse(second["has_more"])
        self.assertEqual(second["next_after_event_sequence"], first["next_after_event_sequence"])
        # Draining is a pure read: repeatable, and it writes nothing.
        self.assertEqual(reopened.drain_correction_followups(limit=10), first)
        self.assertEqual(self._durable_state(reopened), committed_state)

        # III.3: the exact retry of the lost-response command is a DUPLICATE,
        # decided from durable identity without re-running the Engine.
        engine_guard = MagicMock(side_effect=AssertionError("engine_invoked_for_exact_retry"))
        with patch.object(financial_engine, "_evaluate_wire", engine_guard):
            duplicate = self._reject(reopened, claim_id, receipt)
        engine_guard.assert_not_called()
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(duplicate["action_id"], expected.ACTION_CORRECTION_ID)
        self.assertEqual(self._durable_state(reopened), committed_state)
        self.assertEqual(self._correction_evidence(reopened), (1, 1))
        # The retry created no second follow-up item.
        self.assertEqual(reopened.drain_correction_followups(limit=10), first)
        self.assertEqual(
            reopened.drain_correction_followups(
                after_event_sequence=first["next_after_event_sequence"],
                limit=10,
            )["count"],
            0,
        )
        self._assert_verified(reopened)

    # --- 3. Unrelated change preserves a valid result -----------------------------

    @_requires_pinned_correction_engine("the binary is executed once for the accepted correction")
    def test_unrelated_item_fact_preserves_valid_h_evaluation(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        evaluated = store.evaluate_obligation(expected.H_ITEM_ID)
        receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
        self.assertEqual(evaluated["evaluation_receipt"], receipt)
        self.assertEqual(int(receipt["revision"]), int(evaluated["revision"]))

        other_item_id = expected.OTHER_ITEM_IDS[0]
        self.assertEqual(other_item_id, "item-01")
        other_before = store.current_evaluation_receipt(other_item_id)
        sequence_before = store.summary()["sequence"]
        store.record_support_evidence(
            item_id=other_item_id,
            evidence_id="evidence:support:item-01:unrelated-fact",
            common_origin_id="origin:support:item-01:unrelated-fact",
        )
        # The unrelated fact landed and moved global history...
        other_after = store.current_evaluation_receipt(other_item_id)
        self.assertEqual(int(other_after["revision"]), int(other_before["revision"]) + 1)
        self.assertGreater(store.summary()["sequence"], sequence_before)
        # ...but H's evaluation receipt and result digest are untouched.
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        self.assertEqual(store.obligation_detail(expected.H_ITEM_ID)["revision"], int(receipt["revision"]))

        committed = self._reject(store, claim_id, receipt)
        self.assertEqual(committed["status"], "CORRECTION_AUTHORIZED")
        self.assertEqual(committed["action_id"], expected.ACTION_CORRECTION_ID)
        self.assertEqual(committed["revision"], int(receipt["revision"]) + 1)
        detail = store.obligation_detail(expected.H_ITEM_ID)
        self.assertEqual(len(detail["determinations"]), 1)
        determination = detail["determinations"][0]
        self.assertEqual(determination["input_evaluation_id"], receipt["evaluation_id"])
        self.assertEqual(
            bytes(determination["input_evaluation_result_digest"]),
            bytes.fromhex(str(receipt["result_digest"])),
        )
        self.assertEqual(int(determination["expected_revision"]), int(receipt["revision"]))
        self.assertEqual(store.current_evaluation_receipt(other_item_id), other_after)
        self._assert_snapshot(store, expected.H_REJECTED_CORRECTION)
        self._assert_verified(store)

    # --- 4. Relevant new fact invalidates -----------------------------------------

    @_requires_pinned_correction_engine(
        "the release is configured so the rejection cannot come from a missing Engine; "
        "the binary is never executed"
    )
    def test_relevant_late_h_payment_invalidates_prior_evaluation(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        claim_id = self._record_claim(store)
        store.evaluate_obligation(expected.H_ITEM_ID)
        stale = store.current_evaluation_receipt(expected.H_ITEM_ID)

        self._record_p2(store)  # late H payment: a fact relevant to H
        current = store.current_evaluation_receipt(expected.H_ITEM_ID)
        self.assertEqual(int(current["revision"]), int(stale["revision"]) + 1)
        self.assertNotEqual(current["evaluation_id"], stale["evaluation_id"])
        self.assertNotEqual(current["result_digest"], stale["result_digest"])
        self.assertIn(expected.P2_EVIDENCE_ID, current["evidence_ids"])
        self.assertNotIn(expected.P2_EVIDENCE_ID, stale["evidence_ids"])

        attempts = (
            ("stale_revision_and_evaluation", int(stale["revision"]), stale["evaluation_id"], stale["result_digest"], "obligation_revision_conflict"),
            ("current_revision_stale_evaluation", int(current["revision"]), stale["evaluation_id"], stale["result_digest"], "evaluation_revision_conflict"),
            ("current_evaluation_stale_digest", int(current["revision"]), current["evaluation_id"], stale["result_digest"], "evaluation_reference_conflict"),
        )
        baseline = self._durable_state(store)
        for name, expected_revision, evaluation_id, result_digest, error_code in attempts:
            with self.subTest(attempt=name):
                engine_guard = MagicMock(side_effect=AssertionError("engine_invoked_for_stale_reference"))
                with patch.object(financial_engine, "_evaluate_wire", engine_guard):
                    with self._python_decision_paths_forbidden(store):
                        with self.assertRaises(FinancialError) as raised:
                            store.reject_offset_and_authorize_correction(
                                item_id=expected.H_ITEM_ID,
                                claim_id=claim_id,
                                expected_revision=expected_revision,
                                action_id=expected.ACTION_CORRECTION_ID,
                                decision_at_ms=expected.CORRECTION_AUTH_MS,
                                evaluation_id=evaluation_id,
                                evaluation_result_digest=result_digest,
                            )
                engine_guard.assert_not_called()
                self.assertIs(type(raised.exception), FinancialRevisionError)
                self.assertEqual(str(raised.exception), error_code)
                self.assertEqual(self._durable_state(store), baseline)
                self.assertEqual(self._correction_evidence(store), (0, 0))
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID), current)
        self._assert_verified(store)

    # --- 6. The correction requests only the unpaid balance (B2) -----------------

    @_requires_pinned_correction_engine("the binary is executed once per shortfall case")
    def test_correction_requests_only_the_unpaid_balance(self) -> None:
        cash = expected.H_CASH_EVIDENCE
        claim_cents = expected.UNAPPROVED_OFFSET_CENTS
        for cash_cents, shortfall_cents, requested_cents in (
            (expected.H_OWED_CENTS, 0, None),  # nothing short: no payment request
            (expected.H_OWED_CENTS - claim_cents // 3, claim_cents // 3, claim_cents // 3),  # partial
            (expected.H_OWED_CENTS - claim_cents, claim_cents, claim_cents),  # full
        ):
            with self.subTest(shortfall_cents=shortfall_cents):
                store = self._build_base_for_correction()
                store.record_payment_evidence(
                    item_id=cash.item_id, payment_id="payment:h:cash", common_origin_id=cash.common_origin_id,
                    amount_cents=cash_cents, evidence_id=cash.evidence_id, event_at_ms=cash.event_at_ms,
                    source_id=cash.source_id, source_version=cash.source_version, local_ref=cash.local_ref,
                )
                claim_id = self._record_claim(store)
                receipt = store.current_evaluation_receipt(expected.H_ITEM_ID)
                self.assertEqual(receipt["shortfall_cents"], shortfall_cents)
                if requested_cents is None:
                    before = self._durable_state(store)
                    with self.assertRaises(FinancialConflictError) as raised:
                        self._reject(store, claim_id, receipt)
                    self.assertEqual(str(raised.exception), "correction_no_shortfall")
                    self.assertEqual(self._durable_state(store), before)
                    self.assertEqual(self._correction_evidence(store), (0, 0))
                    continue
                self._reject(store, claim_id, receipt)
                with closing(sqlite3.connect(store.path)) as connection:
                    payload, determined = connection.execute(
                        "SELECT a.payload_json,d.amount_cents FROM actions a JOIN determinations d "
                        "ON d.determination_id=a.determination_id WHERE a.action_id=?",
                        (expected.ACTION_CORRECTION_ID,),
                    ).fetchone()
                self.assertEqual(json.loads(payload)["amount_cents"], requested_cents)
                self.assertEqual(determined, claim_cents)  # the rejected offset stays whole
                self._assert_verified(store)

    # --- 7. A payment answering a request never pays past the balance (core-theorems-v1 F1) ---

    @_requires_pinned_correction_engine("the binary is executed once")
    def test_linked_payment_never_pays_past_the_balance(self) -> None:
        store = self._build_base_for_correction()
        self._record_cash(store)
        self._reject(store, self._record_claim(store))
        cash = expected.H_CASH_EVIDENCE

        def pay(n: int, link: str | None = None) -> None:
            store.record_payment_evidence(
                item_id=cash.item_id, payment_id=f"payment:h:direct:{n}", common_origin_id=f"origin:cash:h:direct:{n}",
                amount_cents=expected.UNAPPROVED_OFFSET_CENTS, evidence_id=f"evidence:cash-h:direct:{n}",
                event_at_ms=expected.CORRECTION_AUTH_MS, source_id=cash.source_id, source_version=cash.source_version,
                local_ref=f"ref:cash:h:direct:{n}", pays_action_id=link,
            )

        pay(1)  # the payer settles the balance without naming the request
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID)["shortfall_cents"], 0)
        before = self._durable_state(store)
        with self.assertRaises(FinancialConflictError) as raised:
            pay(2, expected.ACTION_CORRECTION_ID)  # the open request must not collect it again
        self.assertEqual(str(raised.exception), "payment_exceeds_unpaid_balance")
        self.assertEqual(self._durable_state(store), before)

    # --- 8. Open correction requests stay within the unpaid balance (R2, core-theorems-v1 §4.4) ---

    @_requires_pinned_correction_engine("the binary is executed twice")
    def test_open_requests_stay_within_the_unpaid_balance(self) -> None:
        store, reject_b = self._two_claim_corrections(300_000, 300_000, unpaid_cents=600_000)

        def reverse(suffix: str) -> None:
            store.reverse_payment(item_id=expected.H_ITEM_ID, payment_id=f"payment:h:{suffix}", evidence_id=f"evidence:reversal-h:{suffix}")

        for step in (
            reject_b,  # 600,000 owed; A and B each request 300,000
            lambda: self._pay_a(store, 200_000, linked=False),  # 400,000 owed: B shrinks
            lambda: self._pay_a(store, 100_000, "p3", action=acceptance._ACTION_B),  # B collects what it has open
            lambda: reverse("p2"),  # 500,000 owed: B regrows
            lambda: self._pay_a(store, 500_000, "p4", linked=False),  # nothing owed: both close
            lambda: reverse("p4"),  # both reopen
        ):
            step()
            package = store.decision_package(expected.H_ITEM_ID)
            with closing(sqlite3.connect(store.path)) as connection:
                rows = connection.execute("SELECT action_id,json_extract(payload_json,'$.amount_cents') FROM actions WHERE kind='CORRECTION_PAYMENT_REQUEST' ORDER BY revision,action_id").fetchall()
                shortfall = connection.execute("SELECT shortfall_cents FROM obligations WHERE obligation_id=(SELECT obligation_id FROM actions LIMIT 1)").fetchone()[0]
                paid = dict(connection.execute(
                    "SELECT json_extract(e.payload_json,'$.pays_action_id'),SUM(p.amount_cents) FROM financial_events e "
                    "JOIN payments p ON p.payment_id=json_extract(e.payload_json,'$.payment_id') "
                    "WHERE e.kind='PAYMENT_RECEIVED' AND p.active=1 GROUP BY 1"
                ).fetchall())
            shown = {a["action_id"]: a.get("open_cents") for a in package["references"]["actions"]["items"]}  # only open_cents comes from the package
            unpaid = [amount - paid.get(action_id, 0) for action_id, amount in rows]  # amounts, order and balance come from the store rows
            opened = [shown.get(action_id) for action_id, _ in rows]
            self.assertTrue(all(isinstance(cents, int) and 0 <= cents <= left for cents, left in zip(opened, unpaid)), opened)
            self.assertEqual(sum(opened), min(sum(unpaid), shortfall))  # within the balance; no owed cent unrequested
            for index, cents in enumerate(opened):
                if cents:
                    self.assertEqual(opened[:index], unpaid[:index])  # older requests are served first
            self._assert_verified(store)
            self._assert_decision_package_verified(store, package)


if __name__ == "__main__":
    unittest.main()
