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

Every test also carries VI (honest claims): these are synthetic, non-PHI,
nonpayment fixtures; a local pass is "verified locally", never "qualified",
and the standing claims ``proofSuiteId=null``, ``production_usable=false``,
``activation=false`` are unchanged.

Pinned Engine artifact.  Every test here builds its owner through
``_build_base_for_correction``, which requires the pinned correction Engine in
``artifacts/engine-correction-e911`` (built from an older source; see its
``PROVENANCE.md``).  The ``_requires_pinned_correction_engine`` marker on each
test states whether the binary is actually executed or only its identity is
hashed.  A missing or mismatched artifact is a hard failure, never a skip
(VI.3).

The fixtures are reused unchanged from ``tests.test_right_rail_financial_acceptance``.
That test class is deliberately never bound to a name in this module so that
unittest and pytest do not collect and re-run the acceptance suite here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import tempfile
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
    """Mark a test that needs ``artifacts/engine-correction-e911``.

    ``usage`` says whether the pinned binary is executed or only hashed.  The
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

# --- Independent BLFCRES1 encoder ------------------------------------------------
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
    return b"BLFCRES1" + _u16(1) + bytes([status_tag]) + _text(contract)

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
_LEAN_REJECTIONS: tuple[tuple[str, int, int, type[FinancialError], str], ...] = (
    ("SCOPE_MISMATCH", 4, 4, FinancialIntegrityError, "correction_scope_mismatch"),
    ("AUTHORITY_STALE", 5, 5, FinancialAuthorityError, "determination_authority_stale"),
    ("REVISION_CONFLICT", 8, 8, FinancialRevisionError, "obligation_revision_conflict"),
    ("EVALUATION_CONSUMED", 10, 10, FinancialConflictError, "evaluation_already_consumed"),
    ("CAPACITY", 17, 17, FinancialIntegrityError, "history_capacity"),
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
        """Byte-level identity of everything durable the owner can have written."""

        database = store.path.read_bytes()
        sidecars = sorted(
            path.name
            for path in store.path.parent.iterdir()
            if path.name != store.path.name and path.name.startswith(store.path.name)
        )
        return {
            "database_sha256": hashlib.sha256(database).hexdigest(),
            "database_size": len(database),
            "sidecars": sidecars,
            "continuity_sha256": hashlib.sha256(store.export_continuity()).hexdigest(),
            "counts": self._durable_counts(store.path),
            "summary": store.summary(),
        }

    def _correction_evidence(self, store: FinancialOwner) -> tuple[int, int]:
        detail = store.obligation_detail(expected.H_ITEM_ID)
        return len(detail["determinations"]), len(detail["actions"])

    def _contained(self, store: FinancialOwner, stdout: bytes, **overrides: object) -> process.ContainedVerifierResult:
        """A containment result that passes every check unless overridden."""

        release = store.correction_transition_release
        assert isinstance(release, financial_engine.FinancialCorrectionTransitionRelease)
        values: dict[str, object] = {
            "exit_code": 0,
            "stdout": stdout,
            "stderr": b"",
            "peak_job_commit_bytes": 1,
            "cap_bytes": release.job_memory_cap_bytes,
            "cap_enforced": True,
            "active_process_limit": process.ACTIVE_PROCESS_LIMIT,
            "timed_out": False,
            "child_process_count": 1,
            "process_tree_complete": True,
            "measurement_complete": True,
            "cleanup_complete": True,
        }
        values.update(overrides)
        return process.ContainedVerifierResult(**values)  # type: ignore[arg-type]

    @contextmanager
    def _python_decision_paths_forbidden(self, store: FinancialOwner) -> Iterator[None]:
        """Fail if any non-Lean decision path runs (V.2: no silent fallback)."""

        with patch.object(
            store,
            "_recompute_obligation",
            side_effect=AssertionError("python_recompute_fallback"),
        ) as recompute, patch.object(
            store,
            "_apply_accepted_correction_transition",
            side_effect=AssertionError("apply_without_lean_acceptance"),
        ) as apply_accepted, patch.object(
            financial_engine,
            "evaluate_financial_snapshot",
            side_effect=AssertionError("evaluation_engine_fallback"),
        ) as evaluation_engine:
            yield
        recompute.assert_not_called()
        apply_accepted.assert_not_called()
        evaluation_engine.assert_not_called()

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
        containment: MagicMock,
        error_type: type[FinancialError],
        error_code: str,
    ) -> None:
        release = store.correction_transition_release
        assert isinstance(release, financial_engine.FinancialCorrectionTransitionRelease)
        before = self._durable_state(store)
        with patch.object(process, "run_contained_verifier_stream", containment):
            with self._python_decision_paths_forbidden(store):
                with self.assertRaises(FinancialError) as raised:
                    self._reject(store, claim_id, receipt)
        # Typed, stable, and never the untyped base class.
        self.assertIs(type(raised.exception), error_type)
        self.assertEqual(str(raised.exception), error_code)
        # The owner really consulted the pinned Lean transition exactly once.
        self.assertEqual(containment.call_count, 1)
        call = containment.call_args
        self.assertEqual(call.args[0], release.executable)
        self.assertEqual(call.args[1], financial_engine.CORRECTION_TRANSITION_ARGUMENTS)
        self.assertTrue(bytes(call.args[2]).startswith(b"BLFCMD01"))
        # No partial change of any kind (III.5).
        self.assertEqual(self._durable_state(store), before)
        self.assertEqual(self._correction_evidence(store), (0, 0))
        self.assertEqual(store.current_evaluation_receipt(expected.H_ITEM_ID), receipt)
        self.assertEqual(list(release.workspace.iterdir()), [])

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
            "wrong_magic": b"BLFCRES2" + valid_rejection[8:],
            "unknown_status": b"BLFCRES1" + _u16(1) + b"\x09" + valid_rejection[11:],
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
            "containment_error": MagicMock(
                side_effect=process.VerifierProcessError("synthetic_containment_failure"),
            ),
            "timeout_raised": MagicMock(side_effect=TimeoutError("synthetic_engine_timeout")),
            "unexpected_exception": MagicMock(side_effect=OSError("synthetic_engine_io_failure")),
            "timed_out_result": MagicMock(
                return_value=self._contained(store, b"", exit_code=1, timed_out=True),
            ),
            "nonzero_exit_with_valid_bytes": MagicMock(
                return_value=self._contained(store, valid_rejection, exit_code=2),
            ),
            "stderr_output": MagicMock(
                return_value=self._contained(store, valid_rejection, stderr=b"lean: panic"),
            ),
            "cap_not_enforced": MagicMock(
                return_value=self._contained(store, valid_rejection, cap_enforced=False),
            ),
            "cleanup_incomplete": MagicMock(
                return_value=self._contained(store, valid_rejection, cleanup_complete=False),
            ),
            "measurement_incomplete": MagicMock(
                return_value=self._contained(store, valid_rejection, measurement_complete=False),
            ),
            "not_a_contained_result": MagicMock(return_value=valid_rejection),
        }
        for name, payload in malformed_payloads.items():
            failure_modes[f"malformed_{name}"] = MagicMock(return_value=self._contained(store, payload))

        for name, containment in failure_modes.items():
            with self.subTest(failure_mode=name):
                self._assert_engine_failure_is_closed(
                    store,
                    claim_id,
                    receipt,
                    containment=containment,
                    error_type=FinancialIntegrityError,
                    error_code="correction_transition_failed",
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
                containment=MagicMock(return_value=self._contained(store, forged_duplicate)),
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
                    containment=MagicMock(return_value=self._contained(store, payload)),
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
        release = store.correction_transition_release
        assert isinstance(release, financial_engine.FinancialCorrectionTransitionRelease)
        clock_value = store.clock.value + 1_000_000  # type: ignore[attr-defined]

        crashed = self._run_process_boundary(
            store=store,
            claim_id=claim_id,
            fault="process_postcommit",
            clock_value=clock_value,
        )
        # The child committed, then died before returning or draining anything.
        self.assertEqual(crashed.returncode, 74)
        self.assertEqual(crashed.stdout, "PHASE=BEFORE_REJECT\nPHASE=POSTCOMMIT_AFTER_COMMIT\n")
        self.assertEqual(crashed.stderr, "")
        self.assertEqual(list(release.workspace.iterdir()), [])

        reopened = self._make_owner(
            path=store.path,
            clock=acceptance._Clock(clock_value + 1),
            correction_transition_release=release,
        )
        # III.2: determination, action, outbox, projection and event are all present.
        counts = self._durable_counts(reopened.path)
        self.assertEqual(counts["determinations"], 1)
        self.assertEqual(counts["actions"], 1)
        self.assertEqual(counts["action_outbox"], 1)
        self._assert_snapshot(reopened, expected.H_REJECTED_CORRECTION)
        self._assert_verified(reopened)
        committed_state = self._durable_state(reopened)

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
        with patch.object(process, "run_contained_verifier_stream", engine_guard):
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
                with patch.object(process, "run_contained_verifier_stream", engine_guard):
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

if __name__ == "__main__":
    unittest.main()
