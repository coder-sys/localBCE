"""Single-owner Queue V10 runtime.

The runtime exposes one state-issued 100-member batch and one volatile
handoff.  Counters are explicit: batch outcomes are counted in batches while
accepted operations are counted in operations.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Any, Mapping, Protocol

from app.minimal_clearance_source_auth_verifier_adapter import (
    MinimalClearanceSourceAuthVerifierAdapter,
    SourceAuthVerifierConfig,
)
from app.minimal_clearance_verification_queue import (
    IssuedVerificationBatch,
    OperationTemplate,
    QueueClock,
    QueueConfig,
    QueueResult,
    VerificationQueueError,
    VerificationOutcome,
    VolatileProofHandoff,
    _QueueRuntimeOwnership,
    _VerificationQueueStore,
)
from app.minimal_clearance_composition import (
    ClearanceCompositionStoreV2,
    CompositionBatchDeliveryResultV2,
    CompositionConfigV2,
    CompositionError,
    OfficialStateReceiverLookupPort,
    OfficialStateReceiverPort,
    StateDispositionControl,
    SyntheticAckEvidenceProfileV2,
)


class VerificationRuntimeError(RuntimeError):
    pass


def _fixed(code: str) -> None:
    error = VerificationRuntimeError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


_RUNTIME_DISPATCH_WORKER = "runtime-dispatch"
_RUNTIME_RECONCILIATION_WORKER = "runtime-reconciliation"
_RUNTIME_BATCH_LIMIT = 256


def _receiver_is_bound(config: CompositionConfigV2, receiver: object) -> bool:
    try:
        identity = receiver.identity_sha256()  # type: ignore[attr-defined]
        epoch = receiver.epoch()  # type: ignore[attr-defined]
    except Exception:
        return False
    return type(identity) is bytes and len(identity) == 32 and identity == config.receiver_identity and type(epoch) is int and epoch > 0 and epoch == config.receiver_epoch


def _lookup_is_bound(config: CompositionConfigV2, lookup: object) -> bool:
    try:
        profile = lookup.acknowledgment_profile()  # type: ignore[attr-defined]
        expected = config.acknowledgment_profile
        return (
            type(profile) is SyntheticAckEvidenceProfileV2
            and type(profile.verifier_identity) is bytes
            and len(profile.verifier_identity) == 32
            and profile.verifier_identity == expected.verifier_identity
            and type(profile.verifier_epoch) is int
            and profile.verifier_epoch > 0
            and profile.verifier_epoch == expected.verifier_epoch
            and type(profile.receiver_identity) is bytes
            and len(profile.receiver_identity) == 32
            and profile.receiver_identity == expected.receiver_identity
            and type(profile.receiver_epoch) is int
            and profile.receiver_epoch > 0
            and profile.receiver_epoch == expected.receiver_epoch
            and type(profile.mode) is str
            and profile.mode == expected.mode
            and profile.proof_suite_id is expected.proof_suite_id
            and type(profile.production_usable) is bool
            and profile.production_usable is expected.production_usable
            and type(profile.activation) is bool
            and profile.activation is expected.activation
        )
    except Exception:
        return False


class StateDispositionPort(Protocol):
    """State policy authority, called only after verifier acceptance."""

    def controls_for(self, *, batch_id: bytes, operation_refs: tuple[bytes, ...], verification_outcome: VerificationOutcome) -> Mapping[bytes, StateDispositionControl]: ...


@dataclass(frozen=True, slots=True)
class RuntimeOutboxResult:
    operation: str
    outcome: str
    batch_count: int
    attempted_operation_count: int
    acknowledged_operation_count: int
    unconfirmed_operation_count: int
    has_more: bool

    @property
    def processed(self) -> int:
        return self.batch_count


@dataclass(frozen=True, slots=True)
class RuntimeRunResult:
    outcome: str
    code: str | None
    accepted_operation_count: int
    verified_batch_count: int
    rejected_batch_count: int
    held_batch_count: int
    recovered_leases: int
    delivery: RuntimeOutboxResult | None = None
    reconciliation: RuntimeOutboxResult | None = None

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
    def rejected(self) -> int:
        return int(self.rejected_batch_count or 0)

    @property
    def held(self) -> int:
        return int(self.held_batch_count or 0)

    @property
    def indeterminate(self) -> bool:
        return self.outcome == "INDETERMINATE"

    @property
    def outbox_processed(self) -> int:
        return sum(result.batch_count for result in (self.delivery, self.reconciliation) if result is not None)


class MinimalClearanceVerificationRuntime:
    """One owner, one synchronous worker, one batch handoff."""

    @classmethod
    def from_source_auth(cls, *, root: Path, source_auth_config: SourceAuthVerifierConfig, state_disposition_port: StateDispositionPort | None = None, composition_config: CompositionConfigV2 | None = None, receiver: OfficialStateReceiverPort | None = None, lookup: OfficialStateReceiverLookupPort | None = None, clock: QueueClock | None = None) -> "MinimalClearanceVerificationRuntime":
        if type(source_auth_config) is not SourceAuthVerifierConfig:
            _fixed("runtime_configuration")
        verifier = MinimalClearanceSourceAuthVerifierAdapter(source_auth_config)
        kwargs: dict[str, object] = {"root": root, "verifier": verifier, "config": source_auth_config.queue_config, "state_disposition_port": state_disposition_port, "composition_config": composition_config}
        if receiver is not None:
            kwargs["receiver"] = receiver
        if lookup is not None:
            kwargs["lookup"] = lookup
        if clock is not None:
            kwargs["clock"] = clock
        return cls(**kwargs)  # type: ignore[arg-type]

    def __init__(self, *, root: Path, verifier: object | None = None, config: QueueConfig | None = None, state_disposition_port: StateDispositionPort | None = None, composition_config: CompositionConfigV2 | None = None, receiver: OfficialStateReceiverPort | None = None, lookup: OfficialStateReceiverLookupPort | None = None, clock: QueueClock | None = None) -> None:
        if not isinstance(root, Path) or not root.is_absolute() or not root.is_dir():
            _fixed("runtime_configuration")
        if verifier is None:
            _fixed("runtime_backend_unqualified")
        if clock is not None and not callable(getattr(clock, "now_ms", None)):
            _fixed("runtime_configuration")
        if receiver is not None and (not callable(getattr(receiver, "identity_sha256", None)) or not callable(getattr(receiver, "epoch", None)) or not callable(getattr(receiver, "dispatch", None))):
            _fixed("runtime_receiver_binding")
        if lookup is not None and (not callable(getattr(lookup, "acknowledgment_profile", None)) or not callable(getattr(lookup, "lookup_acknowledgment", None))):
            _fixed("runtime_acknowledgment_profile")
        owner: _QueueRuntimeOwnership | None = None
        store: _VerificationQueueStore | None = None
        composition_store: ClearanceCompositionStoreV2 | None = None

        def fail_startup(code: str) -> None:
            cleanup_failed = False
            for cleanup in (
                (composition_store.close if composition_store is not None else None),
                (store._close if store is not None else None),
                (owner._startup_cleanup if owner is not None else None),
            ):
                if cleanup is None:
                    continue
                try:
                    cleanup()
                except BaseException:
                    # Preserve fail-closed startup semantics when cleanup
                    # itself is indeterminate; the original startup code is
                    # not a proof that the resource boundary was released.
                    cleanup_failed = True
            _fixed("runtime_startup" if cleanup_failed else code)

        try:
            database = root / "state.sqlite"
            for legacy in (root / "queue.sqlite", root / "composition.sqlite"):
                if legacy.exists():
                    _fixed("legacy_database_unsupported")
            if config is None:
                config = QueueConfig("minimal-clearance-state-v10", 100)
            if composition_config is None:
                composition_config = CompositionConfigV2(config.queue_id, config.digest, capacity=max(100, config.capacity))
            if type(composition_config) is not CompositionConfigV2 or composition_config.queue_id != config.queue_id or composition_config.queue_config_digest != config.digest:
                _fixed("runtime_configuration")
            if receiver is not None and not _receiver_is_bound(composition_config, receiver):
                _fixed("runtime_receiver_binding")
            if lookup is not None and not _lookup_is_bound(composition_config, lookup):
                _fixed("runtime_acknowledgment_profile")
            owner = _QueueRuntimeOwnership(lock_path=database.with_name(database.name + ".runtime-lock"), parent=root)
            store = _VerificationQueueStore(path=database, config=config, owner=owner, clock=clock, composition_config=composition_config)
            composition_store = ClearanceCompositionStoreV2(path=database, config=composition_config, clock=store.clock)
        except VerificationRuntimeError as error:
            fail_startup(str(error))
        except VerificationQueueError as error:
            fail_startup(str(error))
        except CompositionError as error:
            fail_startup(str(error))
        except BaseException:
            fail_startup("runtime_startup")
        if store is None or composition_store is None or owner is None:
            _fixed("runtime_startup")
        self._closed = False
        self._operation_lock = threading.Lock()
        self._root = root
        self._database_path = database
        self._database_owner = owner
        self._store = store
        self._composition_store = composition_store
        self._verifier = verifier
        self._state_disposition_port = state_disposition_port
        self._composition_config = composition_config
        self._receiver = receiver
        self._lookup = lookup
        self._recovered_leases = self._store._startup_recovered_count

    def _assert_open(self) -> None:
        if self._closed:
            _fixed("runtime_closed")
        try:
            self._database_owner.assert_live()
        except BaseException:
            _fixed("runtime_owner")

    @contextmanager
    def _operation(self):
        if not self._operation_lock.acquire(blocking=False):
            _fixed("runtime_busy")
        try:
            self._assert_open()
            yield
        finally:
            self._operation_lock.release()

    @staticmethod
    def _validate_outbox_limit(value: int, code: str, *, allow_zero: bool = False) -> None:
        if type(value) is not int or value < (0 if allow_zero else 1) or value > _RUNTIME_BATCH_LIMIT:
            _fixed(code)

    def _require_receiver(self) -> OfficialStateReceiverPort:
        if self._receiver is None:
            _fixed("runtime_receiver_required")
        if not _receiver_is_bound(self._composition_config, self._receiver):
            _fixed("runtime_receiver_binding")
        return self._receiver

    def _require_lookup(self) -> OfficialStateReceiverLookupPort:
        if self._lookup is None:
            _fixed("runtime_acknowledgment_profile_required")
        if not _lookup_is_bound(self._composition_config, self._lookup):
            _fixed("runtime_acknowledgment_profile")
        return self._lookup

    @staticmethod
    def _outbox_result(operation: str, batches: list[CompositionBatchDeliveryResultV2]) -> RuntimeOutboxResult:
        attempted = sum(len(batch.results) for batch in batches)
        acknowledged = sum(item.status == "ACKNOWLEDGED" for batch in batches for item in batch.results)
        unconfirmed = sum(item.status == "DELIVERY_UNCONFIRMED" for batch in batches for item in batch.results)
        return RuntimeOutboxResult(operation, "PROCESSED" if batches else "EMPTY", len(batches), attempted, acknowledged, unconfirmed, bool(batches and batches[-1].has_more))

    def _dispatch_outbox_locked(self, *, max_batches: int) -> RuntimeOutboxResult:
        self._validate_outbox_limit(max_batches, "runtime_dispatch_max_batches")
        receiver = self._require_receiver()
        batches: list[CompositionBatchDeliveryResultV2] = []
        for _ in range(max_batches):
            try:
                batch = self._composition_store.dispatch_outbox_batch(_RUNTIME_DISPATCH_WORKER, receiver=receiver)
            except Exception as error:
                if str(error) == "receiver_binding":
                    _fixed("runtime_receiver_binding")
                _fixed("runtime_dispatch")
            if batch is None:
                break
            batches.append(batch)
            if not batch.has_more:
                break
        return self._outbox_result("DIRECT_DELIVERY", batches)

    def dispatch_outbox(self, *, max_batches: int = 1) -> RuntimeOutboxResult:
        """Dispatch ready state-owned directives through the configured receiver."""
        with self._operation():
            return self._dispatch_outbox_locked(max_batches=max_batches)

    def _reconcile_outbox_locked(self, *, max_batches: int) -> RuntimeOutboxResult:
        self._validate_outbox_limit(max_batches, "runtime_reconciliation_max_batches")
        lookup = self._require_lookup()
        batches: list[CompositionBatchDeliveryResultV2] = []
        for _ in range(max_batches):
            try:
                batch = self._composition_store.reconcile_outbox_batch(_RUNTIME_RECONCILIATION_WORKER, lookup=lookup)
            except Exception as error:
                if str(error) == "acknowledgment_profile":
                    _fixed("runtime_acknowledgment_profile")
                _fixed("runtime_reconciliation")
            if batch is None:
                break
            batches.append(batch)
            if not batch.has_more:
                break
        return self._outbox_result("RECONCILIATION", batches)

    def reconcile_outbox(self, *, max_batches: int = 1) -> RuntimeOutboxResult:
        """Reconcile delivery-ambiguous directives through the configured lookup."""
        with self._operation():
            return self._reconcile_outbox_locked(max_batches=max_batches)

    def run(self, *, max_batches: int = 1, dispatch_batches: int = 0, reconciliation_batches: int = 0) -> RuntimeRunResult:
        with self._operation():
            if type(max_batches) is not int or not 1 <= max_batches <= 256:
                _fixed("runtime_max_batches")
            self._validate_outbox_limit(dispatch_batches, "runtime_dispatch_max_batches", allow_zero=True)
            self._validate_outbox_limit(reconciliation_batches, "runtime_reconciliation_max_batches", allow_zero=True)
            if dispatch_batches:
                self._require_receiver()
            if reconciliation_batches:
                self._require_lookup()
            accepted_operations = verified_batches = rejected_batches = held_batches = 0
            outcome_code: str | None = None
            for _ in range(max_batches):
                result = self._store._process_one_batch(verifier=self._verifier, state_disposition_port=self._state_disposition_port)
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
            delivery = self._dispatch_outbox_locked(max_batches=dispatch_batches) if dispatch_batches else None
            reconciliation = self._reconcile_outbox_locked(max_batches=reconciliation_batches) if reconciliation_batches else None
            queue_processed = accepted_operations != 0 or verified_batches != 0 or rejected_batches != 0 or held_batches != 0
            outbox_processed = (delivery is not None and delivery.batch_count != 0) or (reconciliation is not None and reconciliation.batch_count != 0)
            if not queue_processed and not outbox_processed:
                return RuntimeRunResult("EMPTY", outcome_code, 0, 0, 0, 0, self._recovered_leases, delivery, reconciliation)
            return RuntimeRunResult("PROCESSED", outcome_code, accepted_operations, verified_batches, rejected_batches, held_batches, self._recovered_leases, delivery, reconciliation)

    def issue_batch(self, *, template: OperationTemplate) -> IssuedVerificationBatch:
        with self._operation():
            return self._store.issue_batch(template=template)

    def submit_batch_handoff(self, *, issued_batch: IssuedVerificationBatch, proof_stream: VolatileProofHandoff) -> IssuedVerificationBatch:
        with self._operation():
            return self._store.submit_batch_handoff(issued_batch=issued_batch, proof_stream=proof_stream)

    def _verify_integrity(self) -> None:
        with self._operation():
            self._store._verify_integrity()

    def _export_bytes(self) -> bytes:
        with self._operation():
            return self._store._export_bytes()

    def _expected_config(self) -> dict[str, object]:
        with self._operation():
            return self._store.config.as_json

    def support_summary(self) -> dict[str, Any]:
        with self._operation():
            summary = self._store._support_summary()
            composition = self._composition_store.snapshot()
            return {**summary, "outbox_counts": composition["outbox_counts"], "receiver_configured": self._receiver is not None, "reconciliation_configured": self._lookup is not None}

    def _close_queue_store(self) -> None:
        # Queue _close marks itself closed before closing handoffs. Wipe each
        # handoff first so a real buffer-export failure leaves cleanup retryable.
        for handoff in tuple(self._store._handoffs.values()):
            handoff.wipe()
        self._store._close()

    @property
    def _database_path(self) -> Path:
        return self.__database_path

    @_database_path.setter
    def _database_path(self, value: Path) -> None:
        self.__database_path = value

    def close(self) -> None:
        if not self._operation_lock.acquire(blocking=False):
            _fixed("runtime_busy")
        try:
            if self._closed:
                return
            self._composition_store.close()
            self._close_queue_store()
            try:
                self._database_owner.close()
            except VerificationQueueError as error:
                _fixed(str(error))
            except BaseException:
                _fixed("runtime_close")
            self._closed = True
        finally:
            self._operation_lock.release()

    def __enter__(self) -> "MinimalClearanceVerificationRuntime":
        self._assert_open()
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()


__all__ = ("MinimalClearanceVerificationRuntime", "RuntimeOutboxResult", "RuntimeRunResult", "StateDispositionPort", "VerificationRuntimeError")
