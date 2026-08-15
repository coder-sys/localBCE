"""Verifier-owned selected public-coin session with durable attempt custody.

The store burns an attempt before the session identifier is released.  Only a
round that the exact production ``PublicCoinSession`` has finalized is written
to custody.  The complete transcript is independently replayed before the
terminal custody record commits.  Custody stores commitments and roots, never
the private proof transcript itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final, Mapping

from experiments.bl_pq512_crypto_foundation.durable_public_coin_custody import (
    CustodyContributor,
    CustodyError,
    DurablePublicCoinCustody,
    OpaqueCustodyReceipt,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    is_exact_supported_adapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import (
    Contributor,
    PublicCoinSession,
    RoundEvidence,
    SelectedTheoremRoundSchedule,
)
from experiments.bl_pq512_crypto_foundation.selected_public_coin import (
    SelectedChallengeBundle,
    SelectedPublicCoinTranscript,
    capture_selected_transcript,
    encode_selected_transcript_evidence,
    verify_selected_transcript,
)


STATUS: Final[str] = "Z09_DURABLE_SELECTED_PUBLIC_COIN_NONACTIVATING"
PRODUCTION_USABLE: Final[bool] = False
ACTIVATION_ALLOWED: Final[bool] = False
GLOBAL_PROOF_SUITE_ID: Final[None] = None

_STATEMENT_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/SELECTED-STATEMENT/v1\x00"
_ROUND_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/SELECTED-ROUND/v1\x00"
_FINAL_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/SELECTED-FINAL/v1\x00"
_WORKER_ABORT_DOMAIN: Final[bytes] = b"BL/PQ512/Z09/WORKER-ABORT/v1\x00"


def _digest(domain: bytes, *parts: bytes) -> bytes:
    out = bytearray(len(domain).to_bytes(2, "big"))
    out.extend(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise CustodyError("durable_selected_digest_part_invalid")
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return sha3_512(out).digest()


def _encode_signed_envelopes(envelopes: tuple[object, ...]) -> bytes:
    encoded = bytearray(len(envelopes).to_bytes(2, "big"))
    for envelope in envelopes:
        signature = envelope.signature
        encoded.extend(envelope.contributor_id)
        encoded.extend(envelope.payload)
        encoded.extend(len(signature).to_bytes(4, "big"))
        encoded.extend(signature)
    return bytes(encoded)


def _encode_round_evidence(evidence: RoundEvidence) -> bytes:
    if type(evidence) is not RoundEvidence:
        raise CustodyError("durable_selected_exact_round_evidence_required")
    message = evidence.prover_message
    return b"".join(
        (
            evidence.descriptor.encode(),
            len(message).to_bytes(4, "big"),
            message,
            _encode_signed_envelopes(evidence.commitments),
            _encode_signed_envelopes(evidence.reveals),
            evidence.resulting_root,
        )
    )


def selected_custody_statement_root(
    *,
    public_outputs: bytes,
    sidecar: bytes,
    schedule: SelectedTheoremRoundSchedule,
    contributors: tuple[Contributor, ...],
) -> bytes:
    if type(public_outputs) is not bytes or len(public_outputs) != 384:
        raise CustodyError("durable_selected_public_outputs_must_be_384_bytes")
    if type(sidecar) is not bytes or len(sidecar) != 744:
        raise CustodyError("durable_selected_sidecar_must_be_744_bytes")
    if type(schedule) is not SelectedTheoremRoundSchedule:
        raise CustodyError("durable_selected_schedule_required")
    if type(contributors) is not tuple or any(
        type(item) is not Contributor for item in contributors
    ):
        raise CustodyError("durable_selected_contributors_required")
    return _digest(
        _STATEMENT_DOMAIN,
        public_outputs,
        sidecar,
        schedule.proof_suite_id,
        schedule.parameter_commitment,
        schedule.program_binary_commitment,
        schedule.schedule_commitment,
        *(item.encode() for item in contributors),
    )


@dataclass(frozen=True, slots=True)
class CustodiedSelectedCompletion:
    transcript: SelectedPublicCoinTranscript
    challenge_bundle: SelectedChallengeBundle
    custody_receipt: OpaqueCustodyReceipt


class DurableSelectedPublicCoinSession:
    """One live production session bound to one durable custody attempt."""

    __slots__ = (
        "_adapters",
        "_closed",
        "_custody",
        "_next_record_sequence",
        "_pending_completion",
        "_receipt",
        "_session",
        "_transcript_root",
    )

    def __init__(
        self,
        *,
        custody: DurablePublicCoinCustody,
        public_outputs: bytes,
        sidecar: bytes,
        schedule: SelectedTheoremRoundSchedule,
        contributors: tuple[Contributor, ...],
        adapters: Mapping[str, object],
    ) -> None:
        if type(custody) is not DurablePublicCoinCustody:
            raise CustodyError("durable_selected_exact_custody_required")
        if type(adapters) is not dict:
            raise CustodyError("durable_selected_adapter_map_must_be_dict")
        suites = {item.suite_id for item in contributors}
        if set(adapters) != suites or any(
            not is_exact_supported_adapter(adapters[suite], suite) for suite in suites
        ):
            raise CustodyError("durable_selected_exact_locked_adapters_required")
        expected_configuration = tuple(
            CustodyContributor(item.contributor_id, item.suite_id)
            for item in contributors
        )
        if custody.contributor_configuration != expected_configuration:
            raise CustodyError("durable_selected_contributor_registry_mismatch")
        expected_statement = selected_custody_statement_root(
            public_outputs=public_outputs,
            sidecar=sidecar,
            schedule=schedule,
            contributors=contributors,
        )
        if custody.statement_root != expected_statement:
            raise CustodyError("durable_selected_statement_root_mismatch")
        release = custody.burn_attempt()
        self._custody = custody
        self._receipt = release.custody_receipt
        self._next_record_sequence = 0
        self._transcript_root: bytes | None = None
        self._adapters = dict(adapters)
        self._closed = False
        self._pending_completion: tuple[
            SelectedPublicCoinTranscript, SelectedChallengeBundle, bytes
        ] | None = None
        self._session = PublicCoinSession(
            session_id=release.session_id,
            public_outputs=public_outputs,
            sidecar=sidecar,
            candidate_descriptor_sha3_512=schedule.proof_suite_id,
            schedule=schedule.descriptors,
            contributors=contributors,
            verifiers=adapters,
            production_mode=True,
            theorem_schedule=schedule,
        )

    @property
    def session(self) -> PublicCoinSession:
        return self._session

    @property
    def custody_receipt(self) -> OpaqueCustodyReceipt:
        return self._receipt

    @property
    def closed(self) -> bool:
        return self._closed

    def record_latest_verified_round(self) -> OpaqueCustodyReceipt:
        if self._closed:
            raise CustodyError("durable_selected_session_closed")
        evidence = self._session.evidence
        if len(evidence) != self._next_record_sequence + 1:
            raise CustodyError("durable_selected_exactly_one_new_round_required")
        latest = evidence[-1]
        if latest.round_index != self._next_record_sequence:
            raise CustodyError("durable_selected_round_sequence_mismatch")
        if self._transcript_root is not None and latest.prior_root != self._transcript_root:
            raise CustodyError("durable_selected_prior_root_mismatch")
        commitment = _digest(_ROUND_DOMAIN, _encode_round_evidence(latest))
        self._receipt = self._custody.append_round(
            self._receipt,
            expected_record_sequence=self._next_record_sequence,
            round_index=latest.round_index,
            prior_transcript_root=latest.prior_root,
            resulting_transcript_root=latest.resulting_root,
            authenticated_record_sha3_512=commitment,
        )
        self._transcript_root = latest.resulting_root
        self._next_record_sequence += 1
        return self._receipt

    def prepare_completion(
        self,
    ) -> tuple[SelectedPublicCoinTranscript, SelectedChallengeBundle]:
        if self._closed:
            raise CustodyError("durable_selected_session_closed")
        if self._pending_completion is not None:
            return self._pending_completion[:2]
        if not self._session.complete or len(self._session.evidence) != self._next_record_sequence:
            raise CustodyError("durable_selected_unrecorded_or_incomplete_transcript")
        transcript = capture_selected_transcript(self._session)
        bundle = verify_selected_transcript(transcript, self._adapters)
        encoded = encode_selected_transcript_evidence(transcript)
        final_commitment = _digest(_FINAL_DOMAIN, encoded)
        self._pending_completion = (transcript, bundle, final_commitment)
        return transcript, bundle

    def commit_completion(self) -> CustodiedSelectedCompletion:
        if self._closed:
            raise CustodyError("durable_selected_session_closed")
        if self._pending_completion is None:
            raise CustodyError("durable_selected_completion_not_prepared")
        transcript, bundle, final_commitment = self._pending_completion
        self._receipt = self._custody.append_final(
            self._receipt,
            expected_record_sequence=self._next_record_sequence,
            final_transcript_root=transcript.final_transcript_root,
            authenticated_final_sha3_512=final_commitment,
        )
        self._closed = True
        return CustodiedSelectedCompletion(transcript, bundle, self._receipt)

    def complete(self) -> CustodiedSelectedCompletion:
        self.prepare_completion()
        return self.commit_completion()

    def abort_worker(self, *, round_index: int, failure_code: str) -> OpaqueCustodyReceipt:
        if self._closed:
            raise CustodyError("durable_selected_session_closed")
        if len(self._session.evidence) != self._next_record_sequence:
            raise CustodyError("durable_selected_verified_round_not_recorded")
        self._pending_completion = None
        if (
            type(round_index) is not int
            or round_index < 0
            or round_index > 0xFFFF_FFFF
            or type(failure_code) is not str
            or not 1 <= len(failure_code) <= 64
            or not failure_code.isascii()
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in failure_code)
        ):
            raise CustodyError("durable_selected_worker_failure_code_invalid")
        prior = self._transcript_root or bytes(64)
        commitment = _digest(
            _WORKER_ABORT_DOMAIN,
            self._session.session_id,
            self._next_record_sequence.to_bytes(4, "big"),
            round_index.to_bytes(4, "big"),
            failure_code.encode("ascii"),
            prior,
        )
        self._receipt = self._custody.append_worker_abort(
            self._receipt,
            expected_record_sequence=self._next_record_sequence,
            round_index=round_index,
            prior_transcript_root=prior,
            authenticated_abort_sha3_512=commitment,
        )
        self._closed = True
        return self._receipt


__all__ = (
    "ACTIVATION_ALLOWED",
    "CustodiedSelectedCompletion",
    "DurableSelectedPublicCoinSession",
    "GLOBAL_PROOF_SUITE_ID",
    "PRODUCTION_USABLE",
    "STATUS",
    "selected_custody_statement_root",
)
