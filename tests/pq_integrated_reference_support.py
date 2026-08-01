from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha3_512

from app.batch.pq_replay_schedule_r25 import (
    ReplayOperation,
    ReplayOperationKind,
    build_fixed_replay_schedule,
)
from app.batch.pq_replay_state_reference import (
    ProvisionalStrongReplayTransitionV1,
    build_provisional_strong_replay_transition,
)
from app.batch.pq_suite_candidate import CandidateSidecarV1, candidate_salt_use_tag
from app.batch.pq_verifier_reference import (
    SyntheticActiveRegistryV1,
    SyntheticActiveSuiteTupleV1,
    SyntheticStrongVerificationRequestV1,
    SyntheticStrongVerifierAuthorityV1,
    SyntheticVerifiedStrongOutputsV1,
    sidecar_with_reference_candidate_strong_batch,
)
from experiments.fixed_shape_claim_air.integrated_state_reference import (
    ProvisionalPaymentTransitionV1,
    SyntheticCompleteTupleStateV1,
    build_provisional_payment_transition,
)
from experiments.fixed_shape_claim_air.payment import SlotEconomics
from experiments.fixed_shape_claim_air.payment_state import (
    PAYMENT_STATE_VERSION,
    StrongPaymentStateV1Reference,
    append_reference_operation_log,
)
from experiments.fixed_shape_claim_air.semantics import SlotKind


FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_VERIFIER_REFERENCE": "1",
    "BL_ALLOW_SYNTHETIC_PQ_STATE_REFERENCE": "1",
    "BL_ALLOW_SYNTHETIC_PQ_REPLAY_SCHEDULE_R25": "1",
    "BL_ALLOW_SYNTHETIC_PQ_REPLAY_STATE_REFERENCE": "1",
    "BL_ALLOW_SYNTHETIC_R25_PAYMENT_STATE_REFERENCE": "1",
    "BL_ALLOW_SYNTHETIC_PQ_INTEGRATED_STATE_REFERENCE": "1",
}

ARTIFACT_BYTES = b"SYNTHETIC-R26-VERIFIER-CAPABILITY-ARTIFACT"
MASTER_SALT = bytes([0xA5]) * 64
PRIVATE_BATCH_COMMITMENT = sha3_512(b"SYNTHETIC-R26-PRIVATE-BATCH").digest()
STRONG_VALUE_COMMITMENT = sha3_512(b"SYNTHETIC-R26-STRONG-VALUE").digest()
STRONG_GOVERNANCE_COMMITMENT = sha3_512(b"SYNTHETIC-R26-GOVERNANCE").digest()


def felt(value: int) -> bytes:
    return value.to_bytes(32, "big")


def wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def public_outputs(
    *,
    nonce: int = 9001,
    root_before: int = 101,
    root_after: int = 202,
) -> tuple[bytes, ...]:
    return tuple(
        felt(value)
        for value in (
            2,
            7001,
            nonce,
            root_before,
            root_after,
            301,
            302,
            303,
            304,
            401,
            402,
            403,
        )
    )


def active_tuple() -> SyntheticActiveSuiteTupleV1:
    return SyntheticActiveSuiteTupleV1(
        profile_id=wide("SYNTHETIC-R26-PROFILE"),
        proof_suite_id=wide("SYNTHETIC-R26-NONACTIVATING-PROOF-SUITE"),
        schema_id=wide("SYNTHETIC-R26-STATEMENT-SCHEMA"),
        verifier_artifact_identity=sha3_512(ARTIFACT_BYTES).digest(),
        strong_settlement_domain_id=wide("SYNTHETIC-R26-STRONG-DOMAIN"),
        epoch=7,
        legacy_protocol_version_alias=felt(2),
        legacy_settlement_domain_alias=felt(7001),
    )


def authority() -> SyntheticStrongVerifierAuthorityV1:
    return SyntheticStrongVerifierAuthorityV1(
        SyntheticActiveRegistryV1(active_tuple()),
        verifier_artifact_bytes=ARTIFACT_BYTES,
    )


def replay_slot_operations(*, variant: int = 0) -> tuple[ReplayOperation, ...]:
    operations: list[ReplayOperation] = []
    for position in range(256):
        key = sha3_512(
            b"SYNTHETIC-R26-REPLAY-SLOT"
            + variant.to_bytes(4, "big")
            + position.to_bytes(2, "big")
        ).digest()
        if position < 4:
            operations.append(
                ReplayOperation(
                    position,
                    ReplayOperationKind.ATTEMPT_NULLIFIER,
                    key,
                    attempt_version=1,
                    revision_kind="ORIGINAL",
                    parent_attempt_version=0,
                )
            )
        else:
            operations.append(
                ReplayOperation(
                    position,
                    ReplayOperationKind.COVER_NULLIFIER,
                    key,
                )
            )
    return tuple(operations)


def replay_transition(
    *,
    existing: tuple[bytes, ...] = (),
    salt: bytes = MASTER_SALT,
    variant: int = 0,
) -> ProvisionalStrongReplayTransitionV1:
    schedule = build_fixed_replay_schedule(
        replay_slot_operations(variant=variant),
        salt_use_tag_512=candidate_salt_use_tag(salt),
    )
    return build_provisional_strong_replay_transition(
        existing,
        schedule,
        raw_master_salt=salt,
    )


def economics() -> tuple[SlotEconomics, ...]:
    return tuple(
        SlotEconomics(
            slot_index=position,
            slot_kind=SlotKind.REAL if position < 4 else SlotKind.COVER,
            decision=0,
            gross_allowed_cents=0,
            patient_responsibility_cents=0,
            plan_payable_cents=0,
            payer_reserve_debit_cents=0,
            provider_payable_credit_cents=0,
        )
        for position in range(256)
    )


def payment_state(*, sequence: int = 0) -> StrongPaymentStateV1Reference:
    return StrongPaymentStateV1Reference(
        version=PAYMENT_STATE_VERSION,
        epoch=7,
        sequence=sequence,
        asset_registry_root_512=wide("SYNTHETIC-R26-ASSET-REGISTRY"),
        benefit_accumulator_root_512=wide("SYNTHETIC-R26-BENEFIT-ACCUMULATOR"),
        obligation_root_512=wide("SYNTHETIC-R26-OBLIGATION"),
        private_asset_ledger_root_512=wide("SYNTHETIC-R26-PRIVATE-ASSET-LEDGER"),
        operation_log_root_512=wide("SYNTHETIC-R26-OPERATION-LOG-GENESIS"),
    )


def payment_transition(
    before: StrongPaymentStateV1Reference,
) -> ProvisionalPaymentTransitionV1:
    operations = economics()
    next_log = append_reference_operation_log(
        before.operation_log_root_512,
        operations,
        expected_count=256,
    )
    after = replace(
        before,
        sequence=before.sequence + 1,
        operation_log_root_512=next_log,
    )
    return build_provisional_payment_transition(before, after, operations)


@dataclass(frozen=True)
class Scenario:
    authority: SyntheticStrongVerifierAuthorityV1
    state: SyntheticCompleteTupleStateV1
    replay: ProvisionalStrongReplayTransitionV1
    payment: ProvisionalPaymentTransitionV1
    public_outputs: tuple[bytes, ...]
    sidecar: CandidateSidecarV1
    receipt: SyntheticVerifiedStrongOutputsV1


@dataclass(frozen=True)
class VerifiedTransition:
    replay: ProvisionalStrongReplayTransitionV1
    payment: ProvisionalPaymentTransitionV1
    public_outputs: tuple[bytes, ...]
    sidecar: CandidateSidecarV1
    receipt: SyntheticVerifiedStrongOutputsV1


def scenario() -> Scenario:
    verifier = authority()
    replay = replay_transition()
    before_payment = payment_state()
    payment = payment_transition(before_payment)
    public = public_outputs()
    active = verifier.registry.active
    provisional_sidecar = CandidateSidecarV1(
        profile_id=active.profile_id,
        proof_suite_id=active.proof_suite_id,
        schema_id=active.schema_id,
        verifier_artifact_identity=active.verifier_artifact_identity,
        strong_settlement_domain_id=active.strong_settlement_domain_id,
        epoch=active.epoch,
        sequence_before=0,
        sequence_after=1,
        strong_nullifier_root_before=replay.root_before_512,
        strong_nullifier_root_after=replay.root_after_512,
        strong_governance_commitment=STRONG_GOVERNANCE_COMMITMENT,
        strong_payment_state_root_before=payment.roots.root_before_512,
        strong_payment_state_root_after=payment.roots.root_after_512,
        strong_batch_commitment=wide("SYNTHETIC-R26-PROVISIONAL-BATCH"),
    )
    sidecar = sidecar_with_reference_candidate_strong_batch(
        provisional_sidecar,
        public,
        canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
        hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
        raw_master_salt=MASTER_SALT,
    )
    proof = verifier.build_synthetic_proof(
        public_outputs=public,
        encoded_sidecar=sidecar.encode(),
        canonical_private_batch_commitment=PRIVATE_BATCH_COMMITMENT,
        hidden_strong_value_commitment=STRONG_VALUE_COMMITMENT,
        raw_master_salt=MASTER_SALT,
    )
    request = SyntheticStrongVerificationRequestV1.create(
        public_outputs=public,
        encoded_sidecar=sidecar.encode(),
        proof_body=proof,
    )
    receipt = verifier.verify(request)
    state = SyntheticCompleteTupleStateV1(
        authority=verifier,
        sequence=0,
        legacy_nullifier_root=public[3],
        legacy_governed_roots=public[5:9],
        replay_keys_512=(),
        strong_governance_commitment=STRONG_GOVERNANCE_COMMITMENT,
        payment_state=before_payment,
    )
    return Scenario(verifier, state, replay, payment, public, sidecar, receipt)


def second_verified_transition(case: Scenario) -> VerifiedTransition:
    """Build a distinct synthetic transition from case's committed sequence-one state."""

    salt = bytes([0xA6]) * 64
    replay = replay_transition(
        existing=case.replay.merged_keys_512,
        salt=salt,
        variant=1,
    )
    payment = payment_transition(case.payment.after)
    public = public_outputs(nonce=9002, root_before=202, root_after=303)
    active = case.authority.registry.active
    provisional_sidecar = CandidateSidecarV1(
        profile_id=active.profile_id,
        proof_suite_id=active.proof_suite_id,
        schema_id=active.schema_id,
        verifier_artifact_identity=active.verifier_artifact_identity,
        strong_settlement_domain_id=active.strong_settlement_domain_id,
        epoch=active.epoch,
        sequence_before=1,
        sequence_after=2,
        strong_nullifier_root_before=replay.root_before_512,
        strong_nullifier_root_after=replay.root_after_512,
        strong_governance_commitment=STRONG_GOVERNANCE_COMMITMENT,
        strong_payment_state_root_before=payment.roots.root_before_512,
        strong_payment_state_root_after=payment.roots.root_after_512,
        strong_batch_commitment=wide("SYNTHETIC-R26-SECOND-PROVISIONAL-BATCH"),
    )
    private_batch_commitment = wide("SYNTHETIC-R26-SECOND-PRIVATE-BATCH")
    strong_value_commitment = wide("SYNTHETIC-R26-SECOND-STRONG-VALUE")
    sidecar = sidecar_with_reference_candidate_strong_batch(
        provisional_sidecar,
        public,
        canonical_private_batch_commitment=private_batch_commitment,
        hidden_strong_value_commitment=strong_value_commitment,
        raw_master_salt=salt,
    )
    proof = case.authority.build_synthetic_proof(
        public_outputs=public,
        encoded_sidecar=sidecar.encode(),
        canonical_private_batch_commitment=private_batch_commitment,
        hidden_strong_value_commitment=strong_value_commitment,
        raw_master_salt=salt,
    )
    request = SyntheticStrongVerificationRequestV1.create(
        public_outputs=public,
        encoded_sidecar=sidecar.encode(),
        proof_body=proof,
    )
    return VerifiedTransition(
        replay=replay,
        payment=payment,
        public_outputs=public,
        sidecar=sidecar,
        receipt=case.authority.verify(request),
    )
