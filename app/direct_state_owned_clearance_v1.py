"""Nonactivating Direct-State-Owned Atomic Clearance V1 composition seam.

The service accepts only the canonical plaintext continuity bundle.  It first
uses the independent parser as the semantic acceptance boundary, then sends a
sealed commitment-only operation to the existing serializable SQLite state
boundary.  This is a local synthetic qualification seam: it is not a proof
backend, a payment rail, a production evaluator, or an activation path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable

from app.batch.poseidon import FIELD_MODULUS
from app.governance_authority_v2 import GovernanceAuthorityV2
from app.transactional_database_boundary import (
    AntiRollbackReference,
    DirectStateOwnedDatabaseReceiptV1,
    DirectStateOwnedOperationV1,
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
            ("receipt_state_binding", self.state_binding),
            ("receipt_audit_head", self.audit_head),
        ):
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise DirectStateOwnedClearanceError(f"{label}_invalid")
        if type(self.sequence_before) is not int or self.sequence_before < 0:
            raise DirectStateOwnedClearanceError("receipt_sequence_before_invalid")
        if self.sequence_after != self.sequence_before + 1:
            raise DirectStateOwnedClearanceError("receipt_sequence_after_invalid")
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
        profile = build_profile_bindings()
        self._anti_rollback = anti_rollback
        self._profile_id = profile.profile_id
        self._store = SQLiteSettlementStoreV2(
            path=path,
            settlement_domain=DIRECT_DATABASE_DOMAIN,
            governance_authority=DIRECT_GOVERNANCE_AUTHORITY,
            initial_strong_nullifier_root=DIRECT_INITIAL_NULLIFIER_ROOT,
            initial_strong_payment_state_root=DIRECT_INITIAL_CLEARANCE_ROOT,
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

    def _operation_from_details(
        self,
        details: IndependentBundleDetails,
    ) -> DirectStateOwnedOperationV1:
        decision = details.decision
        if (
            details.control_set_id != CONTROL_SET_ID
            or decision["mode_id"] != MODE_ID
            or decision["rule_id"] != RULE_ID
            or decision["control_set_id"] != CONTROL_SET_ID
            or decision["phase0_receipt_binding"] != details.phase0_receipt_binding
            or decision["state_before_id"] != details.before["id"]
            or decision["state_after_id"] != details.after["id"]
            or details.request["epoch"] != DIRECT_EPOCH
            or details.request["sequence_before"] != 0
        ):
            raise DirectStateOwnedClearanceError("direct_composition_binding_mismatch")
        return DirectStateOwnedOperationV1(
            bundle_id=details.bundle_id,
            receipt_id=details.receipt_id,
            request_id=details.request["id"],
            attempt_id=details.request["attempt_id"],
            decision_id=decision["decision_id"],
            join_id=details.join_id,
            source_root=details.facts["source_root"],
            profile_id=self._profile_id,
            schema_id=DIRECT_DATABASE_SCHEMA_ID,
            program_id=DIRECT_DATABASE_PROGRAM_ID,
            mode_id=decision["mode_id"],
            evaluator_id=EVALUATOR_ID,
            control_set_id=details.control_set_id,
            rule_id=decision["rule_id"],
            phase0_receipt_binding=details.phase0_receipt_binding,
            exception_id=decision["exception_id"],
            policy_result=details.policy_result,
            effective_directive=details.effective_directive,
            event_time=decision["event_time"],
            observation_time=decision["observation_time"],
            rule_effective_time=decision["rule_effective_time"],
            decision_time=decision["decision_time"],
            continuity_epoch=details.request["epoch"],
            continuity_sequence_before=details.request["sequence_before"],
            continuity_sequence_after=details.after["sequence"],
            continuity_before_state_id=details.before["id"],
            continuity_after_state_id=details.after["id"],
            continuity_before_audit_head=details.before["audit"],
            continuity_after_audit_head=details.after["audit"],
            continuity_before_root=details.before["root"],
            continuity_after_root=details.after["root"],
        )

    def submit(self, bundle: bytes) -> DirectClearanceReceiptV1:
        """Independently verify and atomically commit one canonical bundle."""

        if type(bundle) is not bytes:
            raise DirectStateOwnedClearanceError("direct_bundle_bytes_required")
        try:
            details = parse_bundle_details(bundle)
        except IndependentParseError as exc:
            raise DirectStateOwnedClearanceError(
                f"direct_independent_reject:{exc}"
            ) from exc
        operation = self._operation_from_details(details)
        sealed = self._store._seal_direct_state_owned(operation)
        committed = self._store._commit_direct_state_owned(sealed)
        return self._receipt(details, committed)

    @staticmethod
    def _receipt(
        details: IndependentBundleDetails,
        committed: DirectStateOwnedDatabaseReceiptV1,
    ) -> DirectClearanceReceiptV1:
        return DirectClearanceReceiptV1(
            operation_digest=committed.operation_digest,
            bundle_id=committed.bundle_id,
            receipt_id=committed.receipt_id,
            request_id=details.request["id"],
            attempt_id=details.request["attempt_id"],
            decision_id=committed.decision_id,
            join_id=committed.join_id,
            sequence_before=committed.sequence_before,
            sequence_after=committed.sequence_after,
            nullifier_root_before=committed.nullifier_root_before,
            nullifier_root_after=committed.nullifier_root_after,
            clearance_root_before=committed.clearance_root_before,
            clearance_root_after=committed.clearance_root_after,
            state_binding=committed.state_binding,
            audit_head=committed.audit_head,
            policy_result=details.policy_result,
            effective_directive=details.effective_directive,
            clearance_advanced=committed.clearance_advanced,
        )

    def snapshot(self):
        return self._store.snapshot()

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
    "DIRECT_INITIAL_NULLIFIER_ROOT",
    "DirectClearanceReceiptV1",
    "DirectStateOwnedAtomicClearanceV1",
    "DirectStateOwnedClearanceError",
)
