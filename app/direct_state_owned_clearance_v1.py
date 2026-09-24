"""Nonactivating Lean-controlled Direct-State-Owned atomic clearance seam."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable

from app.batch.poseidon import FIELD_MODULUS
from app.governance_authority_v2 import GovernanceAuthorityV2
from app.semantic_kernel_binding import (
    SemanticKernelBindingError,
    SemanticKernelResultMismatch,
    StateKernelPriorOperation,
    StateKernelRequest,
    StateKernelResult,
    assert_state_kernel_result_agrees,
    build_production_semantic_kernel_binding,
)
from app.transactional_database_boundary import (
    AntiRollbackReference,
    DirectStateOwnedDatabaseReceiptV1,
    DirectStateOwnedOperationV1,
    DirectStateOwnedCommitContextV1,
    SQLiteSettlementStoreV2,
)
from experiments.native_v3_plaintext_continuity.independent import (
    CONTROL_SET_ID,
    EVALUATOR_ID,
    IndependentBundleDetails,
    IndependentParseError,
    MODE_ID,
    RULE_ID,
    parse_bundle_details,
)
from experiments.native_v3_trust_boundary.profile import build_profile_bindings


class DirectStateOwnedClearanceError(ValueError):
    """Stable fail-closed errors at the direct composition boundary."""


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _wide(label: str) -> bytes:
    return _sha(b"BL/DIRECT-STATE-OWNED/IDENTITY/v1\x00", label.encode("ascii"))


def _field(label: str) -> bytes:
    value = int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1
    return value.to_bytes(32, "big")


DIRECT_EPOCH = 7
DIRECT_DATABASE_CONTEXT_ID = _wide("database-context-v1")
DIRECT_DATABASE_SCHEMA_ID = _wide("direct-state-owned-clearance-schema-v1")
DIRECT_DATABASE_PROGRAM_ID = _wide("verifier-owned-plaintext-continuity-program-v1")
DIRECT_DATABASE_DOMAIN = _field("direct-state-owned-database-domain-v1")
DIRECT_INITIAL_NULLIFIER_ROOT = _wide("direct-state-owned-nullifier-genesis-v1")
DIRECT_INITIAL_PAYMENT_ROOT = _wide("direct-state-owned-payment-genesis-v1")
DIRECT_INITIAL_CLEARANCE_ROOT = _wide("direct-state-owned-clearance-genesis-v1")
DIRECT_AUTHORITY_KEY = _wide("direct-state-owned-boundary-authority-v1")

DIRECT_GOVERNANCE_AUTHORITY = GovernanceAuthorityV2(
    profile_code=1,
    epoch=DIRECT_EPOCH,
    claim_truth_roots_512=tuple(
        _wide(f"direct-state-owned-truth-root-{index}") for index in range(6)
    ),
    claim_truth_authority_digest_512=_wide("direct-state-owned-truth-authority"),
    nullifier_authority_id_512=_wide("direct-state-owned-nullifier-authority"),
    pepper_commitment_512=_wide("direct-state-owned-pepper"),
)


@dataclass(frozen=True, slots=True)
class DirectClearanceReceiptV1:
    """Commitment-only result returned after one durable direct transition."""

    operation_digest: bytes
    bundle_id: bytes
    receipt_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    join_id: bytes
    sequence_before: int
    sequence_after: int
    nullifier_root_before: bytes
    nullifier_root_after: bytes
    clearance_root_before: bytes
    clearance_root_after: bytes
    clearance_count_before: int
    clearance_count_after: int
    payment_root_before: bytes
    payment_root_after: bytes
    settled_batch_count_before: int
    settled_batch_count_after: int
    state_binding: bytes
    audit_head: bytes
    policy_result: int
    effective_directive: int
    clearance_advanced: bool

    proof_suite_id: None = None
    proof_session_accepted: bool = False
    economic_mutation: bool = False

    def __post_init__(self) -> None:
        for label, value in (
            ("receipt_operation", self.operation_digest),
            ("receipt_bundle", self.bundle_id),
            ("receipt_id", self.receipt_id),
            ("receipt_request", self.request_id),
            ("receipt_attempt", self.attempt_id),
            ("receipt_decision", self.decision_id),
            ("receipt_join", self.join_id),
            ("receipt_nullifier_before", self.nullifier_root_before),
            ("receipt_nullifier_after", self.nullifier_root_after),
            ("receipt_clearance_before", self.clearance_root_before),
            ("receipt_clearance_after", self.clearance_root_after),
            ("receipt_payment_before", self.payment_root_before),
            ("receipt_payment_after", self.payment_root_after),
            ("receipt_state_binding", self.state_binding),
            ("receipt_audit_head", self.audit_head),
        ):
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise DirectStateOwnedClearanceError(f"{label}_invalid")
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise DirectStateOwnedClearanceError("receipt_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise DirectStateOwnedClearanceError("receipt_sequence_after_invalid")
        if type(self.clearance_count_before) is not int or self.clearance_count_before < 0:
            raise DirectStateOwnedClearanceError("receipt_clearance_count_before_invalid")
        if self.clearance_count_after != self.clearance_count_before + 1:
            raise DirectStateOwnedClearanceError("receipt_clearance_count_after_invalid")
        if type(self.settled_batch_count_before) is not int or self.settled_batch_count_before < 0:
            raise DirectStateOwnedClearanceError("receipt_settled_count_before_invalid")
        if self.settled_batch_count_after != self.settled_batch_count_before:
            raise DirectStateOwnedClearanceError("receipt_settled_count_changed")
        if self.payment_root_after != self.payment_root_before:
            raise DirectStateOwnedClearanceError("receipt_payment_root_changed")
        if self.policy_result not in (1, 2, 3, 4):
            raise DirectStateOwnedClearanceError("receipt_policy_result_invalid")
        if self.effective_directive not in (1, 2, 3, 4, 5):
            raise DirectStateOwnedClearanceError("receipt_directive_invalid")
        if self.policy_result != {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[self.effective_directive]:
            raise DirectStateOwnedClearanceError("receipt_policy_directive_mismatch")
        if type(self.clearance_advanced) is not bool:
            raise DirectStateOwnedClearanceError("receipt_clearance_flag_invalid")
        if self.clearance_advanced != (self.effective_directive in (1, 5)):
            raise DirectStateOwnedClearanceError("receipt_clearance_directive_mismatch")
        if self.proof_suite_id is not None or self.proof_session_accepted or self.economic_mutation:
            raise DirectStateOwnedClearanceError("receipt_forbidden_proof-or-economic-authority")


class DirectStateOwnedAtomicClearanceV1:
    """Verifier-owned direct continuity-to-database composition root."""

    def __init__(
        self,
        *,
        path: Path,
        anti_rollback: AntiRollbackReference | None = None,
        before_commit_hook: Callable[[], None] | None = None,
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError("direct_database_path_required")
        try:
            semantic_kernel = build_production_semantic_kernel_binding()
        except SemanticKernelBindingError as exc:
            raise DirectStateOwnedClearanceError(
                f"direct_semantic_kernel_unavailable:{exc}"
            ) from exc
        if not callable(getattr(semantic_kernel, "evaluate_state_request", None)):
            raise DirectStateOwnedClearanceError("direct_semantic_kernel_port_invalid")
        try:
            # Capture expected identities from the loaded pin, never from a result.
            pin = semantic_kernel.pin
            artifact_sha256 = pin.kernel_artifact_sha256
            source_binding_sha256 = pin.source_binding_sha256
        except (AttributeError, SemanticKernelBindingError, TypeError) as exc:
            raise DirectStateOwnedClearanceError(
                "direct_semantic_kernel_unavailable:semantic_kernel_trusted_pin"
            ) from exc
        if (
            type(artifact_sha256) is not bytes
            or len(artifact_sha256) != 32
            or not any(artifact_sha256)
            or type(source_binding_sha256) is not bytes
            or len(source_binding_sha256) != 32
            or not any(source_binding_sha256)
        ):
            raise DirectStateOwnedClearanceError(
                "direct_semantic_kernel_unavailable:semantic_kernel_trusted_pin"
            )
        self._semantic_kernel = semantic_kernel
        self._semantic_kernel_artifact_sha256 = artifact_sha256
        self._semantic_kernel_source_binding_sha256 = source_binding_sha256
        profile = build_profile_bindings()
        self._anti_rollback = anti_rollback
        self._profile_id = profile.profile_id
        self._phase0_receipt_binding = profile.frozen_receipt_binding
        self._store = SQLiteSettlementStoreV2(
            path=path,
            settlement_domain=DIRECT_DATABASE_DOMAIN,
            governance_authority=DIRECT_GOVERNANCE_AUTHORITY,
            initial_strong_nullifier_root=DIRECT_INITIAL_NULLIFIER_ROOT,
            initial_strong_payment_state_root=DIRECT_INITIAL_PAYMENT_ROOT,
            initial_direct_clearance_root=DIRECT_INITIAL_CLEARANCE_ROOT,
            epoch=DIRECT_EPOCH,
            profile_id=self._profile_id,
            suite_id=DIRECT_DATABASE_CONTEXT_ID,
            schema_id=DIRECT_DATABASE_SCHEMA_ID,
            verifier_artifact_identity=DIRECT_DATABASE_PROGRAM_ID,
            anti_rollback=anti_rollback,
            before_commit_hook=before_commit_hook,
        )
        self._store._bind_direct_authority(
            DIRECT_AUTHORITY_KEY,
            mode_id=MODE_ID,
            evaluator_id=EVALUATOR_ID,
            control_set_id=CONTROL_SET_ID,
            rule_id=RULE_ID,
            phase0_receipt_binding=profile.frozen_receipt_binding,
        )
        self._store.verify_integrity()

    @property
    def path(self) -> Path:
        return self._store.path

    @property
    def database(self) -> SQLiteSettlementStoreV2:
        """Expose the existing database port for bounded local qualification."""

        return self._store

    @staticmethod
    def _prior_operation(
        operation: DirectStateOwnedOperationV1 | None,
        operation_digest: bytes | None,
    ) -> StateKernelPriorOperation | None:
        if operation is None or operation_digest is None:
            if operation is not None or operation_digest is not None:
                raise DirectStateOwnedClearanceError("direct_retry_record_incomplete")
            return None
        return StateKernelPriorOperation(
            operation_digest=operation_digest,
            operation_version=0 if operation.clearance_advanced is None else 1,
            clearance_advanced=(
                operation.effective_directive in (1, 5)
                if operation.clearance_advanced is None
                else operation.clearance_advanced
            ),
            bundle_id=operation.bundle_id,
            receipt_id=operation.receipt_id,
            request_id=operation.request_id,
            attempt_id=operation.attempt_id,
            decision_id=operation.decision_id,
            join_id=operation.join_id,
            source_root=operation.source_root,
            profile_id=operation.profile_id,
            schema_id=operation.schema_id,
            program_id=operation.program_id,
            mode_id=operation.mode_id,
            evaluator_id=operation.evaluator_id,
            control_set_id=operation.control_set_id,
            rule_id=operation.rule_id,
            phase0_receipt_binding=operation.phase0_receipt_binding,
            exception_id=operation.exception_id,
            policy_result=operation.policy_result,
            effective_directive=operation.effective_directive,
            event_time=operation.event_time,
            observation_time=operation.observation_time,
            rule_effective_time=operation.rule_effective_time,
            decision_time=operation.decision_time,
            continuity_epoch=operation.continuity_epoch,
            continuity_sequence_before=operation.continuity_sequence_before,
            continuity_sequence_after=operation.continuity_sequence_after,
            continuity_before_state_id=operation.continuity_before_state_id,
            continuity_after_state_id=operation.continuity_after_state_id,
            continuity_before_audit_head=operation.continuity_before_audit_head,
            continuity_after_audit_head=operation.continuity_after_audit_head,
            continuity_before_root=operation.continuity_before_root,
            continuity_after_root=operation.continuity_after_root,
        )

    def _state_request(
        self,
        *,
        bundle: bytes,
        command_id: bytes,
        expected_revision: int,
        context: DirectStateOwnedCommitContextV1,
    ) -> StateKernelRequest:
        prior = self._prior_operation(
            context.prior_operation,
            context.prior_operation_digest,
        )
        direct = context.direct_state
        return StateKernelRequest(
            bundle=bundle,
            command_id=command_id,
            expected_revision=expected_revision,
            profile_id=self._profile_id,
            schema_id=DIRECT_DATABASE_SCHEMA_ID,
            program_id=DIRECT_DATABASE_PROGRAM_ID,
            mode_id=MODE_ID,
            evaluator_id=EVALUATOR_ID,
            control_set_id=CONTROL_SET_ID,
            rule_id=RULE_ID,
            phase0_receipt_binding=self._phase0_receipt_binding,
            governance_commitment=context.governance_commitment,
            continuity_epoch=direct.epoch,
            global_sequence=context.global_sequence,
            anti_rollback_epoch=context.anti_rollback_epoch,
            global_state_binding=context.global_state_binding,
            global_audit_head=context.global_audit_head,
            nullifier_root=context.nullifier_root,
            payment_root=context.payment_root,
            direct_sequence=direct.sequence,
            direct_count=context.direct_count,
            clearance_root=direct.clearance_root,
            direct_state_binding=direct.state_binding,
            database_state_binding=direct.database_state_binding,
            direct_payment_root=direct.payment_root,
            direct_settled_batch_count=direct.settled_batch_count,
            direct_audit_head=direct.audit_head,
            last_operation_digest=(
                b"\x00" * 64
                if direct.last_operation_digest is None
                else direct.last_operation_digest
            ),
            continuity_sequence=context.continuity_sequence,
            continuity_row_count=context.continuity_row_count,
            continuity_state_id=context.continuity_state_id,
            continuity_audit_head=context.continuity_audit_head,
            continuity_root=context.continuity_root,
            prior_operation=prior,
        )

    @staticmethod
    def _operation_from_result(result: StateKernelResult) -> DirectStateOwnedOperationV1:
        return DirectStateOwnedOperationV1(
            bundle_id=result.bundle_id,
            receipt_id=result.receipt_id,
            request_id=result.request_id,
            attempt_id=result.attempt_id,
            decision_id=result.decision_id,
            join_id=result.join_id,
            source_root=result.source_root,
            profile_id=result.profile_id,
            schema_id=result.schema_id,
            program_id=result.program_id,
            mode_id=result.mode_id,
            evaluator_id=result.evaluator_id,
            control_set_id=result.control_set_id,
            rule_id=result.rule_id,
            phase0_receipt_binding=result.phase0_receipt_binding,
            exception_id=result.exception_id,
            policy_result=result.policy,
            effective_directive=result.directive,
            event_time=result.event_time,
            observation_time=result.observation_time,
            rule_effective_time=result.rule_effective_time,
            decision_time=result.decision_time,
            continuity_epoch=result.continuity_epoch,
            continuity_sequence_before=result.sequence_before,
            continuity_sequence_after=result.sequence_after,
            continuity_before_state_id=result.before_state_id,
            continuity_after_state_id=result.after_state_id,
            continuity_before_audit_head=result.before_audit_head,
            continuity_after_audit_head=result.after_audit_head,
            continuity_before_root=result.before_continuity_root,
            continuity_after_root=result.after_continuity_root,
            clearance_advanced=result.economic_mutation,
        )

    def submit(
        self,
        bundle: bytes,
        *,
        expected_revision: int | None = None,
        command_id: bytes | None = None,
    ) -> DirectClearanceReceiptV1:
        """Evaluate and commit one versioned State request under SQLite's write lock."""

        if type(bundle) is not bytes:
            raise DirectStateOwnedClearanceError("direct_bundle_bytes_required")
        try:
            details = parse_bundle_details(bundle)
        except IndependentParseError as exc:
            raise DirectStateOwnedClearanceError(
                f"direct_independent_reject:{exc}"
            ) from exc
        if details.request["epoch"] != DIRECT_EPOCH:
            raise DirectStateOwnedClearanceError("direct_bundle_epoch_mismatch")
        if expected_revision is None:
            expected_revision = details.request["sequence_before"]
        if type(expected_revision) is not int or expected_revision < 0:
            raise DirectStateOwnedClearanceError("direct_expected_revision_invalid")
        if command_id is None:
            command_id = details.request["attempt_id"]
        if type(command_id) is not bytes or len(command_id) != 64 or not any(command_id):
            raise DirectStateOwnedClearanceError("direct_command_id_invalid")
        retry_lookup_ids = (
            ("bundle_id", details.bundle_id),
            ("attempt_id", command_id),
        )

        def prepare(context: DirectStateOwnedCommitContextV1) -> DirectStateOwnedOperationV1:
            if (
                context.prior_operation is not None
                and context.prior_operation.continuity_sequence_before != expected_revision
            ):
                raise SemanticKernelResultMismatch("state_kernel_retry_revision_conflict")
            request = self._state_request(
                bundle=bundle,
                command_id=command_id,
                expected_revision=expected_revision,
                context=context,
            )
            result = self._semantic_kernel.evaluate_state_request(request)
            if type(result) is not StateKernelResult:
                raise SemanticKernelBindingError("state_kernel_result_type")
            assert_state_kernel_result_agrees(
                result,
                request,
                artifact_sha256=self._semantic_kernel_artifact_sha256,
                source_binding_sha256=self._semantic_kernel_source_binding_sha256,
                details=details,
            )
            if result.disposition == "REPLAY":
                if context.prior_operation is None:
                    raise SemanticKernelResultMismatch("state_kernel_replay_without_record")
                return context.prior_operation
            return self._operation_from_result(result)

        try:
            committed, operation = self._store._commit_direct_state_owned(
                prepare,
                retry_lookup_ids=retry_lookup_ids,
            )
        except (SemanticKernelBindingError, SemanticKernelResultMismatch) as exc:
            raise DirectStateOwnedClearanceError(
                f"direct_semantic_kernel_reject:{exc}"
            ) from exc
        return self._receipt(operation, committed)

    @staticmethod
    def _receipt(
        operation: DirectStateOwnedOperationV1,
        committed: DirectStateOwnedDatabaseReceiptV1,
    ) -> DirectClearanceReceiptV1:
        return DirectClearanceReceiptV1(
            operation_digest=committed.operation_digest,
            bundle_id=committed.bundle_id,
            receipt_id=committed.receipt_id,
            request_id=operation.request_id,
            attempt_id=operation.attempt_id,
            decision_id=committed.decision_id,
            join_id=committed.join_id,
            sequence_before=committed.sequence_before,
            sequence_after=committed.sequence_after,
            nullifier_root_before=committed.nullifier_root_before,
            nullifier_root_after=committed.nullifier_root_after,
            clearance_root_before=committed.clearance_root_before,
            clearance_root_after=committed.clearance_root_after,
            clearance_count_before=committed.clearance_count_before,
            clearance_count_after=committed.clearance_count_after,
            payment_root_before=committed.payment_root_before,
            payment_root_after=committed.payment_root_after,
            settled_batch_count_before=committed.settled_batch_count_before,
            settled_batch_count_after=committed.settled_batch_count_after,
            state_binding=committed.state_binding,
            audit_head=committed.audit_head,
            policy_result=operation.policy_result,
            effective_directive=operation.effective_directive,
            clearance_advanced=committed.clearance_advanced,
        )

    def snapshot(self):
        return self._store.snapshot()

    def clearance_snapshot(self):
        return self._store.direct_clearance_snapshot()

    def identity_snapshot(self):
        return self._store.identity_snapshot()

    def verify_integrity(self) -> None:
        self._store.verify_integrity()

    def create_backup(self, destination: Path) -> None:
        self._store.create_backup(destination)

    def recover_from_backup(
        self,
        *,
        backup_path: Path,
        recovered_path: Path,
        anti_rollback: AntiRollbackReference | None = None,
    ) -> "DirectStateOwnedAtomicClearanceV1":
        recovered_store = self._store.recover_from_backup(
            backup_path=backup_path,
            recovered_path=recovered_path,
        )
        recovered_store.close()
        return DirectStateOwnedAtomicClearanceV1(
            path=recovered_path,
            anti_rollback=(self._anti_rollback if anti_rollback is None else anti_rollback),
        )

    def close(self) -> None:
        self._store.close()


__all__ = (
    "DIRECT_DATABASE_CONTEXT_ID",
    "DIRECT_DATABASE_DOMAIN",
    "DIRECT_DATABASE_PROGRAM_ID",
    "DIRECT_DATABASE_SCHEMA_ID",
    "DIRECT_EPOCH",
    "DIRECT_GOVERNANCE_AUTHORITY",
    "DIRECT_INITIAL_CLEARANCE_ROOT",
    "DIRECT_INITIAL_PAYMENT_ROOT",
    "DIRECT_INITIAL_NULLIFIER_ROOT",
    "DirectClearanceReceiptV1",
    "DirectStateOwnedAtomicClearanceV1",
    "DirectStateOwnedClearanceError",
)
