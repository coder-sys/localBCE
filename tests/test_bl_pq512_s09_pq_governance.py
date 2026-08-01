from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    INTERNAL_REFERENCE_NOTICE,
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_governance import (
    SELECTIVE_ABORT_BUDGET_BITS,
    ChallengeAttemptGovernance,
    EpochContributorRegistry,
    StatementBinding,
    _public_coin_signature_message,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    COMMITMENT_DOMAIN,
    REVEAL_DOMAIN,
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
CANDIDATE_DIGEST = sha3_512(b"PQ-GOV-CANDIDATE").digest()
DESCRIPTOR = RoundDescriptor(RoundKind.COMPOSITION_COEFFICIENT, 0, OutputKind.FIELD16, 1)
SCHEDULE_DIGEST = sha3_512(DESCRIPTOR.encode()).digest()
PROVER_MESSAGE = b"FIXED-PROVER-MESSAGE"


@pytest.fixture(scope="module")
def cryptographic_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    entries = []
    for label, adapter in ((b"ML-A", ml), (b"ML-B", ml), (b"SLH-A", slh)):
        public_key, secret_key = adapter.generate_keypair()
        contributor = Contributor(
            sha3_512(b"CONTRIBUTOR/" + label).digest(),
            sha3_512(b"KEY/" + label).digest(),
            adapter.suite_id,
            public_key,
        )
        entries.append((contributor, secret_key))
    entries.sort(key=lambda item: item[0].contributor_id)
    return adapters, tuple(item[0] for item in entries), {
        item[0].contributor_id: item[1] for item in entries
    }


def _statement() -> StatementBinding:
    return StatementBinding.from_statement(
        public_outputs=PUBLIC_OUTPUTS,
        sidecar=SIDECAR,
        candidate_descriptor_sha3_512=CANDIDATE_DIGEST,
        schedule_sha3_512=SCHEDULE_DIGEST,
    )


def _session(ticket, contributors, adapters):
    return PublicCoinSession(
        session_id=ticket.session_id,
        public_outputs=PUBLIC_OUTPUTS,
        sidecar=SIDECAR,
        candidate_descriptor_sha3_512=CANDIDATE_DIGEST,
        schedule=(DESCRIPTOR,),
        contributors=contributors,
        verifiers=adapters,
        production_mode=True,
    )


def _signed_round_prefix(ticket, contributors, adapters, secret_keys, missing_ids):
    session = _session(ticket, contributors, adapters)
    prior_root = session.transcript_root
    session.begin_round(DESCRIPTOR, PROVER_MESSAGE)
    reveals_by_id = {
        item.contributor_id: sha3_512(b"REVEAL/" + ticket.session_id + item.contributor_id).digest()
        for item in contributors
    }
    commitments = []
    for contributor in contributors:
        payload = session.commitment_for(
            contributor.contributor_id, reveals_by_id[contributor.contributor_id]
        )
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_COMMITMENT, contributor.contributor_id, payload
        )
        signature = adapters[contributor.suite_id].sign(
            secret_key=secret_keys[contributor.contributor_id], message=message
        )
        envelope = SignedEnvelope(contributor.contributor_id, payload, signature)
        session.submit_commitment(envelope)
        commitments.append(envelope)
    reveals = []
    for contributor in contributors:
        if contributor.contributor_id in missing_ids:
            continue
        payload = reveals_by_id[contributor.contributor_id]
        message = session.signature_message(
            EnvelopeKind.RANDOMNESS_REVEAL, contributor.contributor_id, payload
        )
        signature = adapters[contributor.suite_id].sign(
            secret_key=secret_keys[contributor.contributor_id], message=message
        )
        envelope = SignedEnvelope(contributor.contributor_id, payload, signature)
        session.submit_reveal(envelope)
        reveals.append(envelope)
    return prior_root, tuple(commitments), tuple(reveals)


def test_exact_locked_adapters_sign_verify_and_expose_nonqualification(cryptographic_material) -> None:
    adapters, contributors, secret_keys = cryptographic_material
    expected = {
        ML_DSA_87_SUITE_ID: ("ML-DSA-87", 2592, 4896, 4627),
        SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: (
            "SPHINCS+-SHAKE-256f-simple",
            64,
            128,
            49856,
        ),
    }
    for contributor in contributors:
        adapter = adapters[contributor.suite_id]
        message = b"PQ-ADAPTER-KAT/" + contributor.contributor_id
        signature = adapter.sign(
            secret_key=secret_keys[contributor.contributor_id], message=message
        )
        assert (
            adapter.algorithm_name,
            adapter.public_key_size,
            adapter.secret_key_size,
            adapter.signature_size,
        ) == expected[adapter.suite_id]
        assert len(signature) == adapter.signature_size
        assert adapter.verify(
            public_key=contributor.public_key, message=message, signature=signature
        )
        assert adapter.synthetic_only is False
        assert adapter.internal_reference_only is True
        assert adapter.software_only is True
        assert adapter.hsm_backed is False
        assert adapter.fips_validation_evidence is False
        assert adapter.qualification_notice == INTERNAL_REFERENCE_NOTICE


def test_governance_signature_framing_has_exact_authoritative_parity(
    cryptographic_material,
) -> None:
    adapters, all_contributors, _ = cryptographic_material
    contributors = tuple(
        sorted(
            (
                next(item for item in all_contributors if item.suite_id == ML_DSA_87_SUITE_ID),
                next(
                    item
                    for item in all_contributors
                    if item.suite_id == SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
                ),
            ),
            key=lambda item: item.contributor_id,
        )
    )
    registry = EpochContributorRegistry(sha3_512(b"EPOCH/PARITY").digest(), contributors)
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=_statement(), adapters=adapters
    )
    ticket = governance.burn_attempt()
    session = _session(ticket, contributors, adapters)
    prior_root = session.transcript_root
    session.begin_round(DESCRIPTOR, PROVER_MESSAGE)
    contributor = contributors[0]
    reveal = sha3_512(b"PARITY-REVEAL").digest()
    commitment = session.commitment_for(contributor.contributor_id, reveal)
    prover_digest = sha3_512(PROVER_MESSAGE).digest()
    for kind, domain, payload in (
        (EnvelopeKind.RANDOMNESS_COMMITMENT, COMMITMENT_DOMAIN, commitment),
        (EnvelopeKind.RANDOMNESS_REVEAL, REVEAL_DOMAIN, reveal),
    ):
        assert _public_coin_signature_message(
            domain=domain,
            session_id=ticket.session_id,
            round_index=0,
            descriptor=DESCRIPTOR,
            prior_root=prior_root,
            prover_message_sha3_512=prover_digest,
            contributor=contributor,
            payload=payload,
        ) == session.signature_message(kind, contributor.contributor_id, payload)


def test_statement_bound_preburn_audit_and_success_are_append_only(
    cryptographic_material,
) -> None:
    adapters, all_contributors, _ = cryptographic_material
    contributors = tuple(
        sorted(
            (
                next(item for item in all_contributors if item.suite_id == ML_DSA_87_SUITE_ID),
                next(
                    item
                    for item in all_contributors
                    if item.suite_id == SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
                ),
            ),
            key=lambda item: item.contributor_id,
        )
    )
    registry = EpochContributorRegistry(sha3_512(b"EPOCH/SUCCESS").digest(), contributors)
    statement = _statement()
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=statement, adapters=adapters
    )
    initial_root = governance.audit_root
    ticket = governance.burn_attempt()
    assert SELECTIVE_ABORT_BUDGET_BITS == 2
    assert ticket.ordinal == 0
    assert ticket.statement_root == statement.statement_root
    assert governance.burned_ordinals == (0,)
    assert governance.audit_events[0].prior_root == initial_root
    assert governance.audit_events[0].resulting_root == ticket.burn_audit_root
    success_root = governance.record_success(
        ticket=ticket, final_transcript_root=sha3_512(b"FINAL-TRANSCRIPT").digest()
    )
    assert governance.audit_events[1].prior_root == ticket.burn_audit_root
    assert governance.audit_events[1].resulting_root == success_root == governance.audit_root
    with pytest.raises(RuntimeError, match="already_completed"):
        governance.burn_attempt()
    with pytest.raises(FrozenInstanceError):
        registry.epoch_id = bytes(64)


def test_missing_reveal_is_derived_quarantined_and_excluded_from_retry(
    cryptographic_material,
) -> None:
    adapters, contributors, secret_keys = cryptographic_material
    registry = EpochContributorRegistry(sha3_512(b"EPOCH/ABORT").digest(), contributors)
    governance = ChallengeAttemptGovernance(
        registry=registry, statement=_statement(), adapters=adapters
    )
    ticket = governance.burn_attempt()
    missing = next(item for item in contributors if item.suite_id == ML_DSA_87_SUITE_ID)
    prior_root, commitments, reveals = _signed_round_prefix(
        ticket,
        contributors,
        adapters,
        secret_keys,
        {missing.contributor_id},
    )
    evidence = governance.record_missing_reveal_abort(
        ticket=ticket,
        round_index=0,
        descriptor=DESCRIPTOR,
        prior_transcript_root=prior_root,
        prover_message_sha3_512=sha3_512(PROVER_MESSAGE).digest(),
        commitments=commitments,
        reveals=reveals,
    )
    assert evidence.missing_contributor_ids == (missing.contributor_id,)
    assert governance.quarantined_contributor_ids == (missing.contributor_id,)
    assert governance.audit_events[-1].kind == "MISSING_REVEAL_ABORT"
    assert governance.audit_events[-1].payload_sha3_512 == evidence.evidence_sha3_512
    retry = governance.burn_attempt()
    assert retry.ordinal == 1
    assert missing.contributor_id not in retry.contributor_ids
    assert len(retry.contributor_ids) == 2
