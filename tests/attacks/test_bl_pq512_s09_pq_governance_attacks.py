from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    PqSignatureAdapterError,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_governance import (
    MAX_ATTEMPTS_PER_STATEMENT,
    ChallengeAttemptGovernance,
    EpochContributorRegistry,
    StatementBinding,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    EnvelopeKind,
    OutputKind,
    PublicCoinSession,
    RoundDescriptor,
    RoundKind,
    SignedEnvelope,
)


PUBLIC_OUTPUTS = bytes(384)
SIDECAR = bytes(744)
CANDIDATE_DIGEST = sha3_512(b"ATTACK-CANDIDATE").digest()
DESCRIPTOR = RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1)
SCHEDULE_DIGEST = sha3_512(DESCRIPTOR.encode()).digest()
PROVER_MESSAGE = b"ATTACK-PROVER-MESSAGE"


def _statement() -> StatementBinding:
    return StatementBinding.from_statement(
        public_outputs=PUBLIC_OUTPUTS,
        sidecar=SIDECAR,
        candidate_descriptor_sha3_512=CANDIDATE_DIGEST,
        schedule_sha3_512=SCHEDULE_DIGEST,
    )


def _material(count_per_suite: int = 1):
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    entries = []
    for suite_label, adapter in ((b"ML", ml), (b"SLH", slh)):
        for index in range(count_per_suite):
            label = suite_label + bytes([index])
            public_key, secret_key = adapter.generate_keypair()
            contributor = Contributor(
                sha3_512(b"ATTACK-CONTRIBUTOR/" + label).digest(),
                sha3_512(b"ATTACK-KEY/" + label).digest(),
                adapter.suite_id,
                public_key,
            )
            entries.append((contributor, secret_key))
    entries.sort(key=lambda item: item[0].contributor_id)
    return adapters, tuple(item[0] for item in entries), {
        item[0].contributor_id: item[1] for item in entries
    }


def _signed_prefix(governance, ticket, secret_keys, missing_ids):
    contributors = governance.active_contributors
    session = PublicCoinSession(
        session_id=ticket.session_id,
        public_outputs=PUBLIC_OUTPUTS,
        sidecar=SIDECAR,
        candidate_descriptor_sha3_512=CANDIDATE_DIGEST,
        schedule=(DESCRIPTOR,),
        contributors=contributors,
        verifiers=governance.adapters,
        production_mode=True,
    )
    prior_root = session.transcript_root
    session.begin_round(DESCRIPTOR, PROVER_MESSAGE)
    random_by_id = {
        item.contributor_id: sha3_512(ticket.session_id + item.contributor_id).digest()
        for item in contributors
    }
    commitments = []
    for contributor in contributors:
        payload = session.commitment_for(
            contributor.contributor_id, random_by_id[contributor.contributor_id]
        )
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_COMMITMENT, contributor.contributor_id, payload
        )
        envelope = SignedEnvelope(
            contributor.contributor_id,
            payload,
            governance.adapters[contributor.suite_id].sign(
                secret_key=secret_keys[contributor.contributor_id], message=message
            ),
        )
        session.submit_commitment(envelope)
        commitments.append(envelope)
    reveals = []
    for contributor in contributors:
        if contributor.contributor_id in missing_ids:
            continue
        payload = random_by_id[contributor.contributor_id]
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_REVEAL, contributor.contributor_id, payload
        )
        envelope = SignedEnvelope(
            contributor.contributor_id,
            payload,
            governance.adapters[contributor.suite_id].sign(
                secret_key=secret_keys[contributor.contributor_id], message=message
            ),
        )
        session.submit_reveal(envelope)
        reveals.append(envelope)
    return prior_root, tuple(commitments), tuple(reveals)


def _record(governance, ticket, prior_root, commitments, reveals):
    return governance.record_missing_reveal_abort(
        ticket=ticket,
        round_index=0,
        descriptor=DESCRIPTOR,
        prior_transcript_root=prior_root,
        prover_message_sha3_512=sha3_512(PROVER_MESSAGE).digest(),
        commitments=commitments,
        reveals=reveals,
    )


def test_adapters_reject_wrong_types_lengths_mutation_and_runtime_exception(monkeypatch) -> None:
    ml = MlDsa87PqcryptoAdapter()
    public_key, secret_key = ml.generate_keypair()
    signature = ml.sign(secret_key=secret_key, message=b"MESSAGE")
    assert not ml.verify(public_key=public_key[:-1], message=b"MESSAGE", signature=signature)
    assert not ml.verify(public_key=public_key, message="MESSAGE", signature=signature)
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=signature[:-1])
    mutated = bytes([signature[0] ^ 1]) + signature[1:]
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=mutated)
    with pytest.raises(PqSignatureAdapterError, match="secret_key_size_invalid"):
        ml.sign(secret_key=secret_key[:-1], message=b"MESSAGE")
    monkeypatch.setattr(ml._module, "verify", lambda *_: (_ for _ in ()).throw(RuntimeError("boom")))
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=signature)


def test_registry_and_adapter_set_reject_downgrade_wrong_size_and_single_suite() -> None:
    adapters, contributors, _ = _material()
    ml = next(item for item in contributors if item.suite_id == ML_DSA_87_SUITE_ID)
    slh = next(item for item in contributors if item.suite_id == SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID)
    wrong_size = Contributor(ml.contributor_id, ml.key_id, ml.suite_id, ml.public_key[:-1])
    with pytest.raises(ValueError, match="public_key_size_invalid"):
        EpochContributorRegistry(sha3_512(b"EPOCH").digest(), tuple(sorted((wrong_size, slh), key=lambda x: x.contributor_id)))
    second_ml_pk, _ = adapters[ML_DSA_87_SUITE_ID].generate_keypair()
    second_ml = Contributor(
        sha3_512(b"SECOND-ML").digest(),
        sha3_512(b"SECOND-ML-KEY").digest(),
        ML_DSA_87_SUITE_ID,
        second_ml_pk,
    )
    with pytest.raises(ValueError, match="requires_both_exact_pq_suites"):
        EpochContributorRegistry(
            sha3_512(b"EPOCH").digest(), tuple(sorted((ml, second_ml), key=lambda x: x.contributor_id))
        )
    registry = EpochContributorRegistry(
        sha3_512(b"EPOCH").digest(), tuple(sorted((ml, slh), key=lambda x: x.contributor_id))
    )
    with pytest.raises(ValueError, match="exact_pqcrypto_adapter_required"):
        ChallengeAttemptGovernance(
            registry=registry,
            statement=_statement(),
            adapters={ML_DSA_87_SUITE_ID: object(), SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: adapters[SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID]},
        )


def test_early_abort_and_mutated_signed_evidence_fail_without_state_change() -> None:
    adapters, contributors, secret_keys = _material()
    registry = EpochContributorRegistry(sha3_512(b"ATTACK-EPOCH/EVIDENCE").digest(), contributors)
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=_statement(), adapters=adapters
    )
    ticket = governance.burn_attempt()
    missing = contributors[0].contributor_id
    prior_root, commitments, reveals = _signed_prefix(
        governance, ticket, secret_keys, {missing}
    )
    audit_before = governance.audit_root
    with pytest.raises(ValueError, match="all_ordered_commitments_required"):
        _record(governance, ticket, prior_root, commitments[:-1], reveals)
    assert governance.audit_root == audit_before
    assert governance.quarantined_contributor_ids == ()

    target = commitments[0]
    mutated_signature = bytes([target.signature[0] ^ 1]) + target.signature[1:]
    mutated = (SignedEnvelope(target.contributor_id, target.payload, mutated_signature),) + commitments[1:]
    with pytest.raises(ValueError, match="evidence_signature_invalid"):
        _record(governance, ticket, prior_root, mutated, reveals)
    assert governance.audit_root == audit_before
    assert governance.quarantined_contributor_ids == ()


def test_missing_suite_is_quarantined_no_reenrollment_and_retry_fails_closed() -> None:
    adapters, contributors, secret_keys = _material()
    registry = EpochContributorRegistry(sha3_512(b"ATTACK-EPOCH/QUARANTINE").digest(), contributors)
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=_statement(), adapters=adapters
    )
    ticket = governance.burn_attempt()
    missing = contributors[0]
    prior_root, commitments, reveals = _signed_prefix(
        governance, ticket, secret_keys, {missing.contributor_id}
    )
    _record(governance, ticket, prior_root, commitments, reveals)
    assert governance.quarantined_contributor_ids == (missing.contributor_id,)
    with pytest.raises(RuntimeError, match="reenrollment_forbidden"):
        governance.reenroll_contributor(missing)
    with pytest.raises(RuntimeError, match="requires_two_suite_diverse"):
        governance.burn_attempt()


def test_four_preburned_attempts_are_a_hard_cap() -> None:
    adapters, contributors, secret_keys = _material(count_per_suite=3)
    registry = EpochContributorRegistry(sha3_512(b"ATTACK-EPOCH/CAP").digest(), contributors)
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=_statement(), adapters=adapters
    )
    for ordinal in range(MAX_ATTEMPTS_PER_STATEMENT):
        ticket = governance.burn_attempt()
        assert ticket.ordinal == ordinal
        active = governance.active_contributors
        suite_counts = {
            suite: sum(item.suite_id == suite for item in active)
            for suite in (ML_DSA_87_SUITE_ID, SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID)
        }
        missing = next(item for item in active if suite_counts[item.suite_id] > 1)
        prior_root, commitments, reveals = _signed_prefix(
            governance, ticket, secret_keys, {missing.contributor_id}
        )
        _record(governance, ticket, prior_root, commitments, reveals)
    assert governance.burned_ordinals == (0, 1, 2, 3)
    with pytest.raises(RuntimeError, match="attempt_cap_exhausted"):
        governance.burn_attempt()
