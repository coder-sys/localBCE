"""Bounded cross-session S09 retry and quarantine governance reference.

The epoch registry and statement are immutable.  Attempt ordinals 0..3 are
burned into an append-only SHA3-512 audit chain before a session identifier is
released.  Missing reveals are derived from exact PQ-signed transcript
envelopes, then quarantined atomically for the remainder of the epoch.

This module is internal/reference evidence.  It has no durable publication,
clock/deadline, HSM, or production orchestration integration.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from hashlib import sha3_512
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    expected_public_key_size,
    is_exact_supported_adapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    COMMITMENT_DOMAIN,
    PUBLIC_OUTPUTS_LENGTH,
    REVEAL_DOMAIN,
    SIDECAR_LENGTH,
    TRANSCRIPT_MAGIC,
    TRANSCRIPT_VERSION,
    Contributor,
    RoundDescriptor,
    SignedEnvelope,
    randomness_commitment,
)


MAX_ATTEMPTS_PER_STATEMENT: Final[int] = 4
SELECTIVE_ABORT_BUDGET_BITS: Final[int] = 2
MAX_PARALLEL_SIGNATURE_VERIFICATIONS: Final[int] = 32
APPROVED_SUITES: Final[frozenset[str]] = frozenset(
    (ML_DSA_87_SUITE_ID, SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID)
)

GOVERNANCE_MAGIC: Final[bytes] = b"BLPQGV01"
REGISTRY_DOMAIN: Final[bytes] = b"S09/EPOCH-REGISTRY"
STATEMENT_DOMAIN: Final[bytes] = b"S09/STATEMENT-BINDING"
AUDIT_INIT_DOMAIN: Final[bytes] = b"S09/AUDIT-INIT"
ATTEMPT_BURN_DOMAIN: Final[bytes] = b"S09/ATTEMPT-BURN"
ABORT_EVIDENCE_DOMAIN: Final[bytes] = b"S09/MISSING-REVEAL-ABORT"
SUCCESS_DOMAIN: Final[bytes] = b"S09/ATTEMPT-SUCCESS"
AUDIT_APPEND_DOMAIN: Final[bytes] = b"S09/AUDIT-APPEND"


def _exact_bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ValueError(f"public_coin_governance_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise ValueError(f"public_coin_governance_{label}_must_be_nonzero")
    return value


def _frame(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 0xFFFF:
        raise ValueError("public_coin_governance_domain_invalid")
    result = bytearray(GOVERNANCE_MAGIC)
    result.extend(len(domain).to_bytes(2, "big"))
    result.extend(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise ValueError("public_coin_governance_frame_part_invalid")
        result.extend(len(part).to_bytes(4, "big"))
        result.extend(part)
    return bytes(result)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha3_512(_frame(domain, *parts)).digest()


def _public_coin_signature_message(
    *,
    domain: int,
    session_id: bytes,
    round_index: int,
    descriptor: RoundDescriptor,
    prior_root: bytes,
    prover_message_sha3_512: bytes,
    contributor: Contributor,
    payload: bytes,
) -> bytes:
    framed = bytearray(TRANSCRIPT_MAGIC)
    framed.extend(TRANSCRIPT_VERSION.to_bytes(2, "big"))
    framed.extend(domain.to_bytes(2, "big"))
    for part in (
        session_id,
        round_index.to_bytes(4, "big"),
        descriptor.encode(),
        prior_root,
        prover_message_sha3_512,
        contributor.contributor_id,
        contributor.key_id,
        payload,
    ):
        framed.extend(len(part).to_bytes(4, "big"))
        framed.extend(part)
    return bytes(framed)


def _encoded_envelope(envelope: SignedEnvelope) -> bytes:
    return _frame(
        ABORT_EVIDENCE_DOMAIN,
        envelope.contributor_id,
        envelope.payload,
        envelope.signature,
    )


@dataclass(frozen=True, slots=True)
class EpochContributorRegistry:
    epoch_id: bytes
    contributors: tuple[Contributor, ...]
    registry_root: bytes = field(init=False)

    def __post_init__(self) -> None:
        _exact_bytes("epoch_id", self.epoch_id, 64, nonzero=True)
        if type(self.contributors) is not tuple or len(self.contributors) < 2:
            raise ValueError("public_coin_governance_registry_requires_two_contributors")
        if any(not isinstance(item, Contributor) for item in self.contributors):
            raise ValueError("public_coin_governance_registry_contributor_invalid")
        contributor_ids = tuple(item.contributor_id for item in self.contributors)
        if contributor_ids != tuple(sorted(contributor_ids)) or len(set(contributor_ids)) != len(
            contributor_ids
        ):
            raise ValueError("public_coin_governance_registry_ids_not_unique_sorted")
        key_ids = tuple(item.key_id for item in self.contributors)
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("public_coin_governance_registry_key_id_duplicate")
        keyed_public_keys = tuple((item.suite_id, item.public_key) for item in self.contributors)
        if len(set(keyed_public_keys)) != len(keyed_public_keys):
            raise ValueError("public_coin_governance_registry_public_key_duplicate")
        if {item.suite_id for item in self.contributors} != APPROVED_SUITES:
            raise ValueError("public_coin_governance_registry_requires_both_exact_pq_suites")
        for contributor in self.contributors:
            expected_length = expected_public_key_size(contributor.suite_id)
            if type(contributor.public_key) is not bytes or len(contributor.public_key) != expected_length:
                raise ValueError("public_coin_governance_registry_public_key_size_invalid")
        root = _digest(
            REGISTRY_DOMAIN,
            self.epoch_id,
            *(item.encode() for item in self.contributors),
        )
        object.__setattr__(self, "registry_root", root)


@dataclass(frozen=True, slots=True)
class StatementBinding:
    public_outputs_sha3_512: bytes
    sidecar_sha3_512: bytes
    candidate_descriptor_sha3_512: bytes
    schedule_sha3_512: bytes
    statement_root: bytes = field(init=False)

    def __post_init__(self) -> None:
        for label in (
            "public_outputs_sha3_512",
            "sidecar_sha3_512",
            "candidate_descriptor_sha3_512",
            "schedule_sha3_512",
        ):
            _exact_bytes(label, getattr(self, label), 64, nonzero=True)
        object.__setattr__(
            self,
            "statement_root",
            _digest(
                STATEMENT_DOMAIN,
                self.public_outputs_sha3_512,
                self.sidecar_sha3_512,
                self.candidate_descriptor_sha3_512,
                self.schedule_sha3_512,
            ),
        )

    @classmethod
    def from_statement(
        cls,
        *,
        public_outputs: bytes,
        sidecar: bytes,
        candidate_descriptor_sha3_512: bytes,
        schedule_sha3_512: bytes,
    ) -> StatementBinding:
        _exact_bytes("public_outputs", public_outputs, PUBLIC_OUTPUTS_LENGTH)
        _exact_bytes("sidecar", sidecar, SIDECAR_LENGTH)
        _exact_bytes(
            "candidate_descriptor_sha3_512",
            candidate_descriptor_sha3_512,
            64,
            nonzero=True,
        )
        _exact_bytes("schedule_sha3_512", schedule_sha3_512, 64, nonzero=True)
        return cls(
            sha3_512(public_outputs).digest(),
            sha3_512(sidecar).digest(),
            candidate_descriptor_sha3_512,
            schedule_sha3_512,
        )


@dataclass(frozen=True, slots=True)
class AttemptTicket:
    epoch_id: bytes
    registry_root: bytes
    statement_root: bytes
    ordinal: int
    session_id: bytes
    contributor_ids: tuple[bytes, ...]
    burn_audit_root: bytes


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    kind: str
    payload_sha3_512: bytes
    prior_root: bytes
    resulting_root: bytes


@dataclass(frozen=True, slots=True)
class LocallyHashChainedMissingRevealEvidence:
    """Local hash-chain record authenticated only by the included signed envelopes."""

    ordinal: int
    round_index: int
    missing_contributor_ids: tuple[bytes, ...]
    evidence_sha3_512: bytes
    prior_audit_root: bytes
    resulting_audit_root: bytes


class ChallengeAttemptGovernance:
    """One statement's finite attempt ledger inside one immutable epoch."""

    def __init__(
        self,
        *,
        registry: EpochContributorRegistry,
        statement: StatementBinding,
        adapters: Mapping[str, object],
    ) -> None:
        if not isinstance(registry, EpochContributorRegistry):
            raise TypeError("public_coin_governance_registry_required")
        if not isinstance(statement, StatementBinding):
            raise TypeError("public_coin_governance_statement_required")
        if type(adapters) is not dict:
            raise TypeError("public_coin_governance_adapter_map_must_be_dict")
        checked: dict[str, object] = {}
        for suite_id in APPROVED_SUITES:
            adapter = adapters.get(suite_id)
            if not is_exact_supported_adapter(adapter, suite_id):
                raise ValueError("public_coin_governance_exact_pqcrypto_adapter_required")
            checked[suite_id] = adapter
        if set(adapters) != APPROVED_SUITES:
            raise ValueError("public_coin_governance_adapter_set_not_exact")

        self.registry = registry
        self.statement = statement
        self.adapters = checked
        self._contributor_by_id = {item.contributor_id: item for item in registry.contributors}
        self._quarantined: set[bytes] = set()
        self._burned_ordinals: list[int] = []
        self._events: list[AuditEvent] = []
        self._open_ticket: AttemptTicket | None = None
        self._closed = False
        self._audit_root = _digest(
            AUDIT_INIT_DOMAIN,
            registry.epoch_id,
            registry.registry_root,
            statement.statement_root,
        )

    @property
    def audit_root(self) -> bytes:
        return self._audit_root

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def burned_ordinals(self) -> tuple[int, ...]:
        return tuple(self._burned_ordinals)

    @property
    def quarantined_contributor_ids(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._quarantined))

    @property
    def active_contributors(self) -> tuple[Contributor, ...]:
        return tuple(
            item for item in self.registry.contributors if item.contributor_id not in self._quarantined
        )

    def _append(self, *, kind: str, payload_sha3_512: bytes) -> bytes:
        _exact_bytes("audit_payload_sha3_512", payload_sha3_512, 64)
        sequence = len(self._events)
        prior = self._audit_root
        resulting = _digest(
            AUDIT_APPEND_DOMAIN,
            prior,
            sequence.to_bytes(4, "big"),
            kind.encode("ascii"),
            payload_sha3_512,
        )
        self._events.append(AuditEvent(sequence, kind, payload_sha3_512, prior, resulting))
        self._audit_root = resulting
        return resulting

    def burn_attempt(self) -> AttemptTicket:
        if self._closed:
            raise RuntimeError("public_coin_governance_statement_already_completed")
        if self._open_ticket is not None:
            raise RuntimeError("public_coin_governance_attempt_already_open")
        ordinal = len(self._burned_ordinals)
        if ordinal >= MAX_ATTEMPTS_PER_STATEMENT:
            raise RuntimeError("public_coin_governance_attempt_cap_exhausted")
        active = self.active_contributors
        if len(active) < 2 or {item.suite_id for item in active} != APPROVED_SUITES:
            raise RuntimeError("public_coin_governance_retry_requires_two_suite_diverse_services")
        contributor_ids = tuple(item.contributor_id for item in active)
        session_id = _digest(
            ATTEMPT_BURN_DOMAIN,
            self.registry.epoch_id,
            self.registry.registry_root,
            self.statement.statement_root,
            ordinal.to_bytes(1, "big"),
            *contributor_ids,
        )
        burn_payload = _digest(
            ATTEMPT_BURN_DOMAIN,
            self.statement.statement_root,
            ordinal.to_bytes(1, "big"),
            session_id,
            *contributor_ids,
        )
        burn_root = self._append(kind="ATTEMPT_BURNED", payload_sha3_512=burn_payload)
        self._burned_ordinals.append(ordinal)
        ticket = AttemptTicket(
            self.registry.epoch_id,
            self.registry.registry_root,
            self.statement.statement_root,
            ordinal,
            session_id,
            contributor_ids,
            burn_root,
        )
        self._open_ticket = ticket
        return ticket

    def _require_open_ticket(self, ticket: AttemptTicket) -> None:
        if not isinstance(ticket, AttemptTicket) or ticket != self._open_ticket:
            raise ValueError("public_coin_governance_ticket_not_current")

    def record_missing_reveal_abort(
        self,
        *,
        ticket: AttemptTicket,
        round_index: int,
        descriptor: RoundDescriptor,
        prior_transcript_root: bytes,
        prover_message_sha3_512: bytes,
        commitments: tuple[SignedEnvelope, ...],
        reveals: tuple[SignedEnvelope, ...],
    ) -> LocallyHashChainedMissingRevealEvidence:
        self._require_open_ticket(ticket)
        if type(round_index) is not int or round_index < 0 or round_index > 0xFFFFFFFF:
            raise ValueError("public_coin_governance_round_index_not_u32")
        if not isinstance(descriptor, RoundDescriptor):
            raise TypeError("public_coin_governance_round_descriptor_required")
        _exact_bytes("prior_transcript_root", prior_transcript_root, 64, nonzero=True)
        _exact_bytes("prover_message_sha3_512", prover_message_sha3_512, 64)
        if type(commitments) is not tuple or any(
            not isinstance(item, SignedEnvelope) for item in commitments
        ):
            raise TypeError("public_coin_governance_commitment_tuple_required")
        if type(reveals) is not tuple or any(not isinstance(item, SignedEnvelope) for item in reveals):
            raise TypeError("public_coin_governance_reveal_tuple_required")

        commitment_ids = tuple(item.contributor_id for item in commitments)
        if commitment_ids != ticket.contributor_ids:
            raise ValueError("public_coin_governance_all_ordered_commitments_required")
        reveal_ids = tuple(item.contributor_id for item in reveals)
        expected_reveal_order = tuple(item for item in ticket.contributor_ids if item in set(reveal_ids))
        if reveal_ids != expected_reveal_order or len(set(reveal_ids)) != len(reveal_ids):
            raise ValueError("public_coin_governance_reveals_not_unique_registry_order")
        missing = tuple(item for item in ticket.contributor_ids if item not in set(reveal_ids))
        if not missing:
            raise ValueError("public_coin_governance_abort_requires_missing_reveal")

        commitment_by_id = {item.contributor_id: item for item in commitments}
        verification_jobs: list[tuple[object, bytes, bytes, bytes]] = []
        for domain, envelopes in ((COMMITMENT_DOMAIN, commitments), (REVEAL_DOMAIN, reveals)):
            for envelope in envelopes:
                contributor = self._contributor_by_id[envelope.contributor_id]
                message = _public_coin_signature_message(
                    domain=domain,
                    session_id=ticket.session_id,
                    round_index=round_index,
                    descriptor=descriptor,
                    prior_root=prior_transcript_root,
                    prover_message_sha3_512=prover_message_sha3_512,
                    contributor=contributor,
                    payload=envelope.payload,
                )
                verification_jobs.append(
                    (
                        self.adapters[contributor.suite_id],
                        contributor.public_key,
                        message,
                        envelope.signature,
                    )
                )
                if domain == REVEAL_DOMAIN:
                    expected_commitment = randomness_commitment(
                        session_id=ticket.session_id,
                        round_index=round_index,
                        descriptor=descriptor,
                        prior_root=prior_transcript_root,
                        prover_message_sha3_512=prover_message_sha3_512,
                        contributor_id=contributor.contributor_id,
                        reveal=envelope.payload,
                    )
                    if commitment_by_id[contributor.contributor_id].payload != expected_commitment:
                        raise ValueError(
                            "public_coin_governance_abort_evidence_commitment_mismatch"
                        )

        def verify_job(job: tuple[object, bytes, bytes, bytes]) -> bool:
            adapter, public_key, message, signature = job
            return adapter.verify(
                public_key=public_key,
                message=message,
                signature=signature,
            ) is True

        worker_count = min(MAX_PARALLEL_SIGNATURE_VERIFICATIONS, len(verification_jobs))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            verification_results = tuple(executor.map(verify_job, verification_jobs))
        if not all(verification_results):
            raise ValueError("public_coin_governance_abort_evidence_signature_invalid")

        prior_audit_root = self._audit_root
        evidence_digest = _digest(
            ABORT_EVIDENCE_DOMAIN,
            ticket.epoch_id,
            ticket.registry_root,
            ticket.statement_root,
            ticket.ordinal.to_bytes(1, "big"),
            ticket.session_id,
            round_index.to_bytes(4, "big"),
            descriptor.encode(),
            prior_transcript_root,
            prover_message_sha3_512,
            prior_audit_root,
            *(_encoded_envelope(item) for item in commitments),
            *(_encoded_envelope(item) for item in reveals),
            *missing,
        )
        self._quarantined.update(missing)
        resulting_root = self._append(
            kind="MISSING_REVEAL_ABORT", payload_sha3_512=evidence_digest
        )
        self._open_ticket = None
        return LocallyHashChainedMissingRevealEvidence(
            ticket.ordinal,
            round_index,
            missing,
            evidence_digest,
            prior_audit_root,
            resulting_root,
        )

    def record_success(self, *, ticket: AttemptTicket, final_transcript_root: bytes) -> bytes:
        self._require_open_ticket(ticket)
        _exact_bytes("final_transcript_root", final_transcript_root, 64, nonzero=True)
        payload = _digest(
            SUCCESS_DOMAIN,
            ticket.statement_root,
            ticket.ordinal.to_bytes(1, "big"),
            ticket.session_id,
            final_transcript_root,
        )
        resulting = self._append(kind="ATTEMPT_SUCCEEDED", payload_sha3_512=payload)
        self._open_ticket = None
        self._closed = True
        return resulting

    def reenroll_contributor(self, contributor: Contributor) -> None:
        if not isinstance(contributor, Contributor):
            raise TypeError("public_coin_governance_contributor_required")
        raise RuntimeError("public_coin_governance_reenrollment_forbidden_within_epoch")
