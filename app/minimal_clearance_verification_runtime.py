"""Single-owner Queue V8 runtime.

The runtime exposes one state-issued 100-member batch and one volatile
handoff.  Counters are explicit: batch outcomes are counted in batches while
accepted operations are counted in operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from app.minimal_clearance_verification_queue import (
    IssuedVerificationBatch,
    OperationTemplate,
    QueueConfig,
    QueueResult,
    VerificationQueueError,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)


class VerificationRuntimeError(RuntimeError):
    pass


def _fixed(code: str) -> None:
    error = VerificationRuntimeError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


@dataclass(frozen=True, slots=True)
class RuntimeRunResult:
    outcome: str
    code: str | None
    accepted_operation_count: int
    verified_batch_count: int
    rejected_batch_count: int
    held_batch_count: int
    recovered_leases: int

    @property
    def processed(self) -> int:
        """Number of terminal batch outcomes, never an operation count."""
        if self.outcome == "INDETERMINATE":
            return 0
        return sum(int(value or 0) for value in (self.verified_batch_count, self.rejected_batch_count, self.held_batch_count))

    @property
    def verified(self) -> int:
        """Accepted operation count, retained for existing reporting callers."""
        return int(self.accepted_operation_count or 0)

    @property
    def accepted_count(self) -> int:
        """Compatibility-free explicit alias for accepted_operation_count."""
        return int(self.accepted_operation_count or 0)

    @property
    def rejected(self) -> int:
        return int(self.rejected_batch_count or 0)

    @property
    def held(self) -> int:
        return int(self.held_batch_count or 0)

    @property
    def indeterminate(self) -> bool:
        return self.outcome == "INDETERMINATE"


class MinimalClearanceVerificationRuntime:
    """One owner, one synchronous worker, one batch handoff."""

    def __init__(self, *, root: Path, verifier: object | None = None, config: QueueConfig | None = None) -> None:
        if not isinstance(root, Path) or not root.is_absolute() or not root.is_dir():
            _fixed("runtime_configuration")
        if verifier is None:
            _fixed("runtime_backend_unqualified")
        owner: _QueueRuntimeOwnership | None = None
        try:
            database = root / "queue.sqlite"
            if config is None:
                config = QueueConfig("minimal-clearance-queue-v8", 100)
            owner = _QueueRuntimeOwnership(lock_path=database.with_name(database.name + ".runtime-lock"), parent=root)
            store = _VerificationQueueStore(path=database, config=config, owner=owner)
        except VerificationQueueError as error:
            if owner is not None:
                owner.close()
            _fixed(str(error))
        except BaseException:
            if owner is not None:
                owner.close()
            _fixed("runtime_startup")
        self._closed = False
        self._root = root
        self._database_path = database
        self._database_owner = owner
        self._store = store
        self._verifier = verifier
        self._recovered_leases = self._store._startup_recovered_count

    def _assert_open(self) -> None:
        if self._closed:
            _fixed("runtime_closed")
        try:
            self._database_owner.assert_live()
        except BaseException:
            _fixed("runtime_owner")

    def run(self, *, max_batches: int = 1) -> RuntimeRunResult:
        self._assert_open()
        if type(max_batches) is not int or not 1 <= max_batches <= 256:
            _fixed("runtime_max_batches")
        accepted_operations = verified_batches = rejected_batches = held_batches = 0
        outcome_code: str | None = None
        for _ in range(max_batches):
            result = self._store._process_one_batch(verifier=self._verifier)
            held_batches += self._store._last_claim_held_count
            if result is None:
                if self._store._last_claim_error is not None and outcome_code is None:
                    outcome_code = self._store._last_claim_error
                break
            if result.error_code is not None and outcome_code is None:
                outcome_code = result.error_code
            if result.status == "VERIFIED":
                if result.accepted_count != 100:
                    _fixed("runtime_result")
                accepted_operations += result.accepted_count
                verified_batches += 1
            elif result.status == "REJECTED":
                rejected_batches += 1
            elif result.status == "HELD":
                held_batches += 1
            else:
                _fixed("runtime_result")
        if accepted_operations == verified_batches == rejected_batches == held_batches == 0:
            return RuntimeRunResult("EMPTY", outcome_code, 0, 0, 0, 0, self._recovered_leases)
        return RuntimeRunResult("PROCESSED", outcome_code, accepted_operations, verified_batches, rejected_batches, held_batches, self._recovered_leases)

    def issue_batch(self, *, template: OperationTemplate) -> IssuedVerificationBatch:
        self._assert_open()
        return self._store.issue_batch(template=template)

    def submit_batch_handoff(self, *, issued_batch: IssuedVerificationBatch, proof_stream: BinaryIO | VolatileProofHandoff, declared_length: int | None = None) -> IssuedVerificationBatch:
        self._assert_open()
        return self._store.submit_batch_handoff(issued_batch=issued_batch, proof_stream=proof_stream, declared_length=declared_length)

    def _verify_integrity(self) -> None:
        self._assert_open()
        self._store._verify_integrity()

    def _export_bytes(self) -> bytes:
        self._assert_open()
        return self._store._export_bytes()

    def _expected_config(self) -> dict[str, object]:
        self._assert_open()
        return self._store.config.as_json

    def support_summary(self) -> dict[str, Any]:
        self._assert_open()
        return self._store._support_summary()

    @property
    def _database_path(self) -> Path:
        return self.__database_path

    @_database_path.setter
    def _database_path(self, value: Path) -> None:
        self.__database_path = value

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._store._close()
        finally:
            self._database_owner.close()

    def __enter__(self) -> "MinimalClearanceVerificationRuntime":
        self._assert_open()
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()


__all__ = ("MinimalClearanceVerificationRuntime", "RuntimeRunResult", "VerificationRuntimeError")
