"""Single-owner Queue V8 runtime.

The runtime exposes only the state-issued 100-member batch issuance and its
one-shot volatile handoff. It has no per-operation or legacy V7 entry point.
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
    accepted_count: int | None
    rejected_count: int | None
    held_count: int | None
    recovered_leases: int

    @property
    def processed(self) -> int:
        return 0 if self.outcome == "INDETERMINATE" else sum(int(value or 0) for value in (self.accepted_count, self.rejected_count, self.held_count))

    @property
    def verified(self) -> int:
        return int(self.accepted_count or 0)

    @property
    def rejected(self) -> int:
        return int(self.rejected_count or 0)

    @property
    def held(self) -> int:
        return int(self.held_count or 0)

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
        try:
            database = root / "queue.sqlite"
            if config is None:
                config = QueueConfig("minimal-clearance-queue-v8", 100)
            owner = _QueueRuntimeOwnership(lock_path=database.with_name(database.name + ".runtime-lock"), parent=root)
            self._store = _VerificationQueueStore(path=database, config=config, owner=owner)
        except VerificationQueueError as error:
            _fixed(str(error))
        except BaseException:
            _fixed("runtime_startup")
        self._closed = False
        self._root = root
        self._database_path = database
        self._database_owner = owner
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
        accepted = rejected = held = 0
        for _ in range(max_batches):
            result = self._store._process_one_batch(verifier=self._verifier)
            if result is None:
                break
            if result.status == "VERIFIED":
                accepted += result.accepted_count
            elif result.status == "REJECTED":
                rejected += 1
            elif result.status == "HELD":
                held += 1
            else:
                _fixed("runtime_result")
        if accepted == rejected == held == 0:
            return RuntimeRunResult("EMPTY", None, None, None, None, self._recovered_leases)
        return RuntimeRunResult("PROCESSED", None, accepted, rejected, held, self._recovered_leases)

    def issue_batch(self, *, templates: tuple[OperationTemplate, ...]) -> IssuedVerificationBatch:
        self._assert_open()
        return self._store.issue_batch(templates=templates)

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
