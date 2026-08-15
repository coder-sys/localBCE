from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha3_512
from pathlib import Path
import shutil
import sqlite3
from threading import Event, RLock

import pytest

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.production_boundary import (
    GovernanceAuthorityV2,
    NativeVerificationResult,
    ProductionBoundaryError,
    ProductionProofEnvelope,
    VerifiedSettlementOperationV2,
    _BATCH_NONCE_BINDING,
    _SETTLEMENT_DOMAIN_BINDING,
    _digest,
    build_v2_public_fields,
)
from app.transactional_database_boundary import (
    AntiRollbackAnchorSnapshot,
    InMemoryAntiRollbackReference,
    SQLiteSettlementStoreV2,
    TransactionalSettlementV2,
)
from experiments.bl_pq512_crypto_foundation.production_candidate import (
    PROOF_PACKAGE_COMMITMENT_DOMAIN,
    TRANSCRIPT_COMMITMENT_DOMAIN,
    NativeVerificationReceipt,
    statement_commitment,
)


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _field(label: str) -> bytes:
    return (int.from_bytes(_wide(label), "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


_SUITE = _wide("transactional-suite")
_SCHEMA = _wide("transactional-schema")
_VERIFIER = _wide("transactional-verifier")
_PROFILE = _wide("transactional-profile")
_DOMAIN = _field("transactional-domain")
_ROOTS = GovernanceAuthorityV2(
    profile_code=1,
    epoch=1,
    claim_truth_roots_512=tuple(
        _wide(f"transactional-truth-{index}") for index in range(6)
    ),
    claim_truth_authority_digest_512=_wide("transactional-truth-authority"),
    nullifier_authority_id_512=_wide("transactional-nullifier-authority"),
    pepper_commitment_512=_wide("transactional-pepper"),
)
_NULLIFIER_0 = _wide("transactional-nullifier-0")
_NULLIFIER_1 = _wide("transactional-nullifier-1")
_NULLIFIER_2 = _wide("transactional-nullifier-2")
_NULLIFIER_3 = _wide("transactional-nullifier-3")
_PAYMENT_0 = _wide("transactional-payment-0")
_PAYMENT_1 = _wide("transactional-payment-1")
_PAYMENT_2 = _wide("transactional-payment-2")
_PAYMENT_3 = _wide("transactional-payment-3")


def _envelope(
    *,
    nonce_label: str,
    sequence_before: int,
    nullifier_before: bytes,
    nullifier_after: bytes,
    payment_before: bytes,
    payment_after: bytes,
) -> tuple[ProductionProofEnvelope, bytes]:
    nonce = _field(nonce_label)
    sidecar = CandidateSidecarV1(
        profile_id=_PROFILE,
        proof_suite_id=_SUITE,
        schema_id=_SCHEMA,
        verifier_artifact_identity=_VERIFIER,
        strong_settlement_domain_id=_digest(_SETTLEMENT_DOMAIN_BINDING, _DOMAIN),
        epoch=1,
        sequence_before=sequence_before,
        sequence_after=sequence_before + 1,
        strong_nullifier_root_before=nullifier_before,
        strong_nullifier_root_after=nullifier_after,
        strong_governance_commitment=_ROOTS.commitment_512,
        strong_payment_state_root_before=payment_before,
        strong_payment_state_root_after=payment_after,
        strong_batch_commitment=_digest(_BATCH_NONCE_BINDING, nonce),
    ).encode()
    public_fields = build_v2_public_fields(
        settlement_domain=_DOMAIN,
        batch_nonce=nonce,
        sidecar=sidecar,
        governance_authority=_ROOTS,
        suite_id=_SUITE,
        schema_id=_SCHEMA,
        verifier_artifact_identity=_VERIFIER,
    )
    envelope = ProductionProofEnvelope(
        suite_id=_SUITE,
        schema_id=_SCHEMA,
        verifier_artifact_identity=_VERIFIER,
        public_outputs=b"".join(public_fields),
        sidecar=sidecar,
        proof_package=("synthetic-proof-" + nonce_label).encode("ascii"),
        transcript_evidence=("synthetic-transcript-" + nonce_label).encode("ascii"),
        evidence_commitment=_wide("transactional-evidence-" + nonce_label),
    )
    return envelope, nonce


class _ReceiptVerifier:
    def __init__(self) -> None:
        self._lock = RLock()
        self.calls = 0

    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        with self._lock:
            self.calls += 1
        encoded = envelope.encode()
        receipt = NativeVerificationReceipt(
            proof_suite_id=envelope.suite_id,
            schema_id=envelope.schema_id,
            verifier_artifact_identity=envelope.verifier_artifact_identity,
            envelope_commitment=sha3_512(encoded).digest(),
            statement_commitment=statement_commitment(envelope.public_outputs, envelope.sidecar),
            evidence_commitment=envelope.evidence_commitment,
            proof_package_commitment=sha3_512(
                PROOF_PACKAGE_COMMITMENT_DOMAIN + envelope.proof_package
            ).digest(),
            transcript_commitment=sha3_512(
                TRANSCRIPT_COMMITMENT_DOMAIN + envelope.transcript_evidence
            ).digest(),
        )
        return NativeVerificationResult(
            receipt=receipt,
            envelope_commitment=receipt.envelope_commitment,
            statement_commitment=receipt.statement_commitment,
        )


class _ForgedReceiptVerifier(_ReceiptVerifier):
    def verify(self, envelope: ProductionProofEnvelope) -> NativeVerificationResult:
        result = super().verify(envelope)
        return replace(result, envelope_commitment=_wide("forged-native-envelope-commitment"))


class _FinalizeGateAnchor:
    def __init__(self) -> None:
        self._delegate = InMemoryAntiRollbackReference()
        self.fail_finalize = False

    def snapshot(self) -> AntiRollbackAnchorSnapshot | None:
        return self._delegate.snapshot()

    def initialize(self, epoch: int, state_binding: bytes) -> None:
        self._delegate.initialize(epoch, state_binding)

    def prepare(
        self,
        *,
        expected_epoch: int,
        expected_state_binding: bytes,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        self._delegate.prepare(
            expected_epoch=expected_epoch,
            expected_state_binding=expected_state_binding,
            next_epoch=next_epoch,
            next_state_binding=next_state_binding,
            transition_commitment=transition_commitment,
        )

    def finalize(
        self,
        *,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        if self.fail_finalize:
            raise RuntimeError("injected_anchor_finalize_failure")
        self._delegate.finalize(
            next_epoch=next_epoch,
            next_state_binding=next_state_binding,
            transition_commitment=transition_commitment,
        )


class _DelayedFirstFinalizeAnchor(_FinalizeGateAnchor):
    def __init__(self) -> None:
        super().__init__()
        self.first_finalize_started = Event()
        self.release_first_finalize = Event()
        self._delay_lock = RLock()
        self._first_finalize_claimed = False

    def finalize(
        self,
        *,
        next_epoch: int,
        next_state_binding: bytes,
        transition_commitment: bytes,
    ) -> None:
        with self._delay_lock:
            should_delay = next_epoch == 1 and not self._first_finalize_claimed
            if should_delay:
                self._first_finalize_claimed = True
        if should_delay:
            self.first_finalize_started.set()
            if not self.release_first_finalize.wait(timeout=10.0):
                raise RuntimeError("delayed_anchor_finalize_timeout")
        super().finalize(
            next_epoch=next_epoch,
            next_state_binding=next_state_binding,
            transition_commitment=transition_commitment,
        )


def _store(
    path: Path,
    *,
    anti_rollback: InMemoryAntiRollbackReference | None = None,
    before_commit_hook: object | None = None,
) -> SQLiteSettlementStoreV2:
    return SQLiteSettlementStoreV2(
        path=path,
        settlement_domain=_DOMAIN,
        governance_authority=_ROOTS,
        initial_strong_nullifier_root=_NULLIFIER_0,
        initial_strong_payment_state_root=_PAYMENT_0,
        epoch=1,
        profile_id=_PROFILE,
        suite_id=_SUITE,
        schema_id=_SCHEMA,
        verifier_artifact_identity=_VERIFIER,
        anti_rollback=anti_rollback,
        before_commit_hook=before_commit_hook,  # type: ignore[arg-type]
    )


def _settlement(
    store: SQLiteSettlementStoreV2,
    verifier: _ReceiptVerifier,
    *submitters: bytes,
) -> TransactionalSettlementV2:
    return TransactionalSettlementV2(
        verifier=verifier,
        storage=store,
        settlement_domain=_DOMAIN,
        governance_authority=_ROOTS,
        authorized_submitters=list(submitters),
    )


def test_transaction_commits_roots_payment_sequence_and_audit_once(tmp_path: Path) -> None:
    path = tmp_path / "settlement.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="nonce-1",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    before = settlement.snapshot()
    receipt = settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    after = settlement.snapshot()
    settlement.verify_integrity()

    assert before.sequence == 0
    assert before.settled_batch_count == 0
    assert receipt.sequence_after == 1
    assert after.sequence == 1
    assert after.strong_nullifier_root == _NULLIFIER_1
    assert after.strong_payment_state_root == _PAYMENT_1
    assert after.state_binding == receipt.state_binding
    assert after.anti_rollback_epoch == 1
    assert verifier.calls == 1

    with sqlite3.connect(path) as connection:
        counts = tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("settlement_requests", "settled_nullifier_roots", "audit_events")
        )
        payload = bytes(connection.execute("SELECT payload FROM audit_events").fetchone()[0])
        with pytest.raises(sqlite3.IntegrityError, match="audit_events_append_only"):
            connection.execute("DELETE FROM audit_events")
    assert counts == (1, 1, 1)
    assert b"synthetic-proof" not in payload
    assert b"synthetic-transcript" not in payload
    assert submitter.hex().encode("ascii") not in payload
    assert b'"submitter_commitment"' in payload


def test_exact_retry_is_idempotent_and_conflicting_retry_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "retry.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter_a = _wide("transactional-submitter-a")
    submitter_b = _wide("transactional-submitter-b")
    settlement = _settlement(store, verifier, submitter_a, submitter_b)
    envelope, nonce = _envelope(
        nonce_label="retry-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    first = settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter_a)
    retry = settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter_a)
    with pytest.raises(ProductionBoundaryError, match="database_conflicting_retry"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter_b)

    assert retry == first
    assert settlement.snapshot().settled_batch_count == 1
    assert verifier.calls == 3


def test_stale_roots_duplicate_nonce_and_nullifier_root_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-replay-submitter")
    settlement = _settlement(store, verifier, submitter)
    first, nonce_1 = _envelope(
        nonce_label="replay-nonce-1",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    settlement.submit(envelope=first, batch_nonce=nonce_1, submitter=submitter)

    stale, stale_nonce = _envelope(
        nonce_label="stale-root-nonce",
        sequence_before=1,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )
    with pytest.raises(ProductionBoundaryError, match="database_nullifier_root_stale"):
        settlement.submit(envelope=stale, batch_nonce=stale_nonce, submitter=submitter)

    conflicting_nonce, same_nonce = _envelope(
        nonce_label="replay-nonce-1",
        sequence_before=1,
        nullifier_before=_NULLIFIER_1,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )
    with pytest.raises(ProductionBoundaryError, match="database_conflicting_retry"):
        settlement.submit(envelope=conflicting_nonce, batch_nonce=same_nonce, submitter=submitter)

    second, nonce_2 = _envelope(
        nonce_label="replay-nonce-2",
        sequence_before=1,
        nullifier_before=_NULLIFIER_1,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )
    settlement.submit(envelope=second, batch_nonce=nonce_2, submitter=submitter)
    root_rollback, nonce_3 = _envelope(
        nonce_label="replay-nonce-3",
        sequence_before=2,
        nullifier_before=_NULLIFIER_2,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_2,
        payment_after=_PAYMENT_3,
    )
    with pytest.raises(ProductionBoundaryError, match="database_nullifier_replay"):
        settlement.submit(envelope=root_rollback, batch_nonce=nonce_3, submitter=submitter)

    assert settlement.snapshot().settled_batch_count == 2
    settlement.verify_integrity()


def test_concurrent_competing_transitions_publish_exactly_one(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-concurrent-submitter")
    settlement = _settlement(store, verifier, submitter)
    candidate_a = _envelope(
        nonce_label="concurrent-a",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    candidate_b = _envelope(
        nonce_label="concurrent-b",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_2,
    )

    def submit(candidate: tuple[ProductionProofEnvelope, bytes]) -> str:
        try:
            settlement.submit(envelope=candidate[0], batch_nonce=candidate[1], submitter=submitter)
            return "committed"
        except ProductionBoundaryError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(submit, (candidate_a, candidate_b)))

    assert outcomes.count("committed") == 1
    assert outcomes.count("database_sequence_stale") == 1
    assert settlement.snapshot().settled_batch_count == 1
    settlement.verify_integrity()


def test_partial_failure_rolls_back_and_restart_recovers_idempotently(tmp_path: Path) -> None:
    path = tmp_path / "recovery.sqlite3"
    submitter = _wide("transactional-recovery-submitter")
    verifier = _ReceiptVerifier()
    envelope, nonce = _envelope(
        nonce_label="recovery-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    def fail_before_commit() -> None:
        raise RuntimeError("injected_failure_before_commit")

    failing_store = _store(path, before_commit_hook=fail_before_commit)
    failing = _settlement(failing_store, verifier, submitter)
    with pytest.raises(RuntimeError, match="injected_failure_before_commit"):
        failing.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert failing.snapshot().sequence == 0
    assert failing.snapshot().settled_batch_count == 0
    failing.verify_integrity()
    failing.close()

    recovered_store = _store(path)
    recovered = _settlement(recovered_store, verifier, submitter)
    receipt = recovered.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    recovered.close()

    restarted_store = _store(path)
    restarted = _settlement(restarted_store, verifier, submitter)
    retry = restarted.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert retry == receipt
    assert restarted.snapshot().settled_batch_count == 1
    restarted.verify_integrity()


def test_forged_post_verification_operation_cannot_advance_state(tmp_path: Path) -> None:
    path = tmp_path / "sealed-operation.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-seal-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="sealed-operation-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    operation = settlement._prepare(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    forged = replace(operation, envelope_commitment=_wide("forged-envelope-commitment"))

    assert not hasattr(VerifiedSettlementOperationV2, "_from_native_verified")
    assert not hasattr(store, "commit_verified")
    with pytest.raises(ProductionBoundaryError, match="database_operation_not_native_authorized"):
        store._commit_verified(forged)
    other_store = _store(tmp_path / "other-sealed-operation.sqlite3")
    _settlement(other_store, verifier, submitter)
    with pytest.raises(ProductionBoundaryError, match="database_operation_not_native_authorized"):
        other_store._commit_verified(operation)
    with pytest.raises(ProductionBoundaryError, match="database_native_authority_already_bound"):
        _settlement(store, verifier, submitter)
    assert store.snapshot().sequence == 0
    assert other_store.snapshot().sequence == 0
    store.verify_integrity()


def test_anchor_finalize_failure_is_durable_but_exact_retry_reconciles_once(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor-finalize-retry.sqlite3"
    anchor = _FinalizeGateAnchor()
    store = _store(path, anti_rollback=anchor)  # type: ignore[arg-type]
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-anchor-finalize-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="anchor-finalize-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    anchor.fail_finalize = True
    with pytest.raises(
        ProductionBoundaryError,
        match="database_transition_committed_anchor_pending",
    ):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT sequence, settled_batch_count FROM state"
        ).fetchone() == (1, 1)
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone() == (1,)
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 0
    assert observed.pending is not None and observed.pending.next_epoch == 1

    anchor.fail_finalize = False
    retry = settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert retry.sequence_after == 1
    assert settlement.snapshot().settled_batch_count == 1
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 1 and observed.pending is None
    settlement.verify_integrity()


def test_pending_anchor_refuses_tampered_committed_transition(tmp_path: Path) -> None:
    path = tmp_path / "anchor-pending-tamper.sqlite3"
    anchor = _FinalizeGateAnchor()
    store = _store(path, anti_rollback=anchor)  # type: ignore[arg-type]
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-anchor-tamper-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="anchor-tamper-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    anchor.fail_finalize = True
    with pytest.raises(
        ProductionBoundaryError,
        match="database_transition_committed_anchor_pending",
    ):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE settlement_requests SET operation_digest=?",
            (sqlite3.Binary(_wide("tampered-anchor-operation-digest")),),
        )
    anchor.fail_finalize = False
    with pytest.raises(
        ProductionBoundaryError,
        match="anti_rollback_pending_transition_mismatch",
    ):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 0 and observed.pending is not None
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT sequence, settled_batch_count FROM state"
        ).fetchone() == (1, 1)


def test_anchor_reservation_survives_precommit_failure_and_exact_replay(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor-precommit-replay.sqlite3"
    anchor = InMemoryAntiRollbackReference()
    submitter = _wide("transactional-anchor-precommit-submitter")
    verifier = _ReceiptVerifier()
    envelope, nonce = _envelope(
        nonce_label="anchor-precommit-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    def fail_before_commit() -> None:
        raise RuntimeError("injected_failure_after_anchor_reservation")

    failing_store = _store(
        path,
        anti_rollback=anchor,
        before_commit_hook=fail_before_commit,
    )
    failing = _settlement(failing_store, verifier, submitter)
    with pytest.raises(RuntimeError, match="injected_failure_after_anchor_reservation"):
        failing.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert failing.snapshot().sequence == 0
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 0 and observed.pending is not None

    competing, competing_nonce = _envelope(
        nonce_label="anchor-precommit-competing-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_2,
    )
    with pytest.raises(ProductionBoundaryError, match="anti_rollback_transition_conflict"):
        failing.submit(
            envelope=competing,
            batch_nonce=competing_nonce,
            submitter=submitter,
        )
    failing.close()

    recovered_store = _store(path, anti_rollback=anchor)
    recovered = _settlement(recovered_store, verifier, submitter)
    receipt = recovered.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert receipt.sequence_after == 1
    assert recovered.snapshot().settled_batch_count == 1
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 1 and observed.pending is None
    recovered.verify_integrity()


def test_delayed_finalize_remains_idempotent_after_later_transition(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchor-delayed-finalize.sqlite3"
    anchor = _DelayedFirstFinalizeAnchor()
    store = _store(path, anti_rollback=anchor)  # type: ignore[arg-type]
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-delayed-finalize-submitter")
    settlement = _settlement(store, verifier, submitter)
    first, nonce_1 = _envelope(
        nonce_label="delayed-finalize-nonce-1",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    second, nonce_2 = _envelope(
        nonce_label="delayed-finalize-nonce-2",
        sequence_before=1,
        nullifier_before=_NULLIFIER_1,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_result = executor.submit(
            settlement.submit,
            envelope=first,
            batch_nonce=nonce_1,
            submitter=submitter,
        )
        assert anchor.first_finalize_started.wait(timeout=10.0)
        try:
            second_receipt = settlement.submit(
                envelope=second,
                batch_nonce=nonce_2,
                submitter=submitter,
            )
        finally:
            anchor.release_first_finalize.set()
        first_receipt = first_result.result(timeout=10.0)

    assert first_receipt.sequence_after == 1
    assert second_receipt.sequence_after == 2
    assert settlement.snapshot().settled_batch_count == 2
    observed = anchor.snapshot()
    assert observed is not None and observed.epoch == 2 and observed.pending is None
    settlement.verify_integrity()


def test_forged_native_receipt_cannot_reach_database_transaction(tmp_path: Path) -> None:
    path = tmp_path / "forged-native-receipt.sqlite3"
    store = _store(path)
    verifier = _ForgedReceiptVerifier()
    submitter = _wide("transactional-forged-receipt-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="forged-native-receipt-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    with pytest.raises(ProductionBoundaryError, match="transactional_verifier_binding_mismatch"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    assert store.snapshot().sequence == 0
    store.verify_integrity()


def test_integrity_scan_rejects_durable_request_tampering(tmp_path: Path) -> None:
    path = tmp_path / "tampered-request.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-tamper-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="tampered-request-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE settlement_requests SET state_binding_after=?",
            (sqlite3.Binary(_wide("tampered-durable-state-binding")),),
        )
    with pytest.raises(ProductionBoundaryError, match="database_request_state_binding_invalid"):
        store.verify_integrity()


@pytest.mark.parametrize(
    ("column", "expected_error"),
    (
        ("operation_digest", "database_request_audit_binding_mismatch"),
        ("submitter", "database_request_state_binding_invalid"),
    ),
)
def test_integrity_scan_binds_operation_digest_and_submitter(
    tmp_path: Path,
    column: str,
    expected_error: str,
) -> None:
    path = tmp_path / f"tampered-{column}.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-provenance-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label=f"tampered-{column}-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)

    assert column in {"operation_digest", "submitter"}
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"UPDATE settlement_requests SET {column}=?",
            (sqlite3.Binary(_wide(f"tampered-{column}-value")),),
        )
    with pytest.raises(ProductionBoundaryError, match=expected_error):
        store.verify_integrity()


def test_write_transaction_rechecks_persisted_configuration(tmp_path: Path) -> None:
    path = tmp_path / "configuration-drift.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-configuration-submitter")
    settlement = _settlement(store, verifier, submitter)
    envelope, nonce = _envelope(
        nonce_label="configuration-drift-nonce",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE configuration SET verifier_artifact_identity=? WHERE id=1",
            (sqlite3.Binary(_wide("drifted-verifier-artifact")),),
        )
    with pytest.raises(ProductionBoundaryError, match="database_configuration_identity_mismatch"):
        settlement.submit(envelope=envelope, batch_nonce=nonce, submitter=submitter)
    with sqlite3.connect(path) as connection:
        state = connection.execute("SELECT sequence, settled_batch_count FROM state").fetchone()
    assert state == (0, 0)


def test_verified_backup_restores_replay_state_and_audit_chain(tmp_path: Path) -> None:
    path = tmp_path / "backup-source.sqlite3"
    backup_path = tmp_path / "backup.sqlite3"
    recovered_path = tmp_path / "backup-recovered.sqlite3"
    store = _store(path)
    verifier = _ReceiptVerifier()
    submitter = _wide("transactional-backup-submitter")
    settlement = _settlement(store, verifier, submitter)
    first, nonce_1 = _envelope(
        nonce_label="backup-nonce-1",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    original_receipt = settlement.submit(
        envelope=first,
        batch_nonce=nonce_1,
        submitter=submitter,
    )
    store.create_backup(backup_path)
    settlement.close()

    recovered_store = store.recover_from_backup(
        backup_path=backup_path,
        recovered_path=recovered_path,
    )
    recovered = _settlement(recovered_store, verifier, submitter)
    retry = recovered.submit(envelope=first, batch_nonce=nonce_1, submitter=submitter)
    assert retry == original_receipt
    assert recovered.snapshot().sequence == 1
    assert recovered.snapshot().settled_batch_count == 1

    second, nonce_2 = _envelope(
        nonce_label="backup-nonce-2",
        sequence_before=1,
        nullifier_before=_NULLIFIER_1,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )
    recovered.submit(envelope=second, batch_nonce=nonce_2, submitter=submitter)
    assert recovered.snapshot().sequence == 2
    recovered.verify_integrity()


def test_external_anchor_rejects_rolled_back_database_file(tmp_path: Path) -> None:
    path = tmp_path / "anti-rollback.sqlite3"
    old_path = tmp_path / "anti-rollback-old.sqlite3"
    anchor = InMemoryAntiRollbackReference()
    submitter = _wide("transactional-anchor-submitter")
    verifier = _ReceiptVerifier()
    store = _store(path, anti_rollback=anchor)
    settlement = _settlement(store, verifier, submitter)
    first, nonce_1 = _envelope(
        nonce_label="anchor-nonce-1",
        sequence_before=0,
        nullifier_before=_NULLIFIER_0,
        nullifier_after=_NULLIFIER_1,
        payment_before=_PAYMENT_0,
        payment_after=_PAYMENT_1,
    )
    settlement.submit(envelope=first, batch_nonce=nonce_1, submitter=submitter)
    settlement.close()
    shutil.copy2(path, old_path)

    store = _store(path, anti_rollback=anchor)
    settlement = _settlement(store, verifier, submitter)
    second, nonce_2 = _envelope(
        nonce_label="anchor-nonce-2",
        sequence_before=1,
        nullifier_before=_NULLIFIER_1,
        nullifier_after=_NULLIFIER_2,
        payment_before=_PAYMENT_1,
        payment_after=_PAYMENT_2,
    )
    settlement.submit(envelope=second, batch_nonce=nonce_2, submitter=submitter)
    settlement.close()

    shutil.copy2(old_path, path)
    for suffix in ("-wal", "-shm"):
        companion = Path(str(path) + suffix)
        if companion.exists():
            companion.unlink()
    with pytest.raises(ProductionBoundaryError, match="anti_rollback_state_older_than_anchor"):
        _store(path, anti_rollback=anchor)
