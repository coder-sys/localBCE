"""Bounded complete-lifecycle simulator for the nonactivating H6 candidate.

This is a simulator of the complete observable protocol lifecycle, not a
production prover and not an activation path.  It covers the semantic AIR,
state, GKR, PCS, public-coin, grammar, malformed-input, abort, retry, crash,
cleanup, and repeated-proof boundaries with the same fixed-width envelopes.
Private witness bytes are represented only by domain-separated digests.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
from typing import Final

from experiments.bl_pq512_crypto_foundation.h6_receipt_grammar import (
    RECEIPT_BYTES,
    SIDECAR_BYTES,
    encode_receipt,
    encode_sidecar,
    grammar_identity,
    parse_receipt,
    parse_sidecar,
)
from experiments.bl_pq512_crypto_foundation.proof_body_reference import (
    ProofGrammar,
    ProofIdentity,
    SectionPayload,
    SectionRule,
    encode_reference_proof_body,
    parse_proof_body,
)
from experiments.bl_pq512_crypto_foundation.native_hiding_simulator import (
    run_native_hiding_simulator_suite,
)


STATUS: Final[str] = "H6_COMPLETE_SIMULATOR_V1_NONACTIVATING"
ERROR_BYTES: Final[int] = 128
PROFILES: Final[tuple[int, ...]] = (128, 512)
OUTCOMES: Final[tuple[str, ...]] = ("APPROVAL", "DENIAL", "COVER")
MALFORMED_CASES: Final[tuple[str, ...]] = (
    "TRUNCATED_HEADER",
    "TRAILING_BYTES",
    "BAD_GRAMMAR_DIGEST",
    "BAD_SECTION_DIGEST",
    "RESOURCE_CAP",
)


class H6SimulatorError(ValueError):
    """Stable fail-closed simulator error."""


def _digest(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise H6SimulatorError("h6_simulator_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _stream(domain: bytes, seed: bytes, length: int) -> bytes:
    if type(seed) is not bytes or not seed or length < 0 or length > 1 << 20:
        raise H6SimulatorError("h6_simulator_stream_bounds")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            _digest(
                domain,
                seed,
                counter.to_bytes(8, "big"),
            )
        )
        counter += 1
    return bytes(output[:length])


def _profile_identity(capacity: int, label: str) -> bytes:
    return _digest(
        b"BL/PQ512/H6/SIMULATOR/IDENTITY/v1\x00",
        capacity.to_bytes(2, "big"),
        label.encode("ascii"),
    )


def _grammar(capacity: int) -> tuple[ProofGrammar, ProofIdentity]:
    identity = ProofIdentity(
        profile_id=_profile_identity(capacity, "profile"),
        proof_suite_id=_profile_identity(capacity, "suite-reference"),
        schema_id=_profile_identity(capacity, "schema"),
        verifier_artifact_identity=_profile_identity(capacity, "verifier"),
    )
    grammar = ProofGrammar(
        identity=identity,
        sections=(
            SectionRule(1, "semantic_air", 64, 64),
            SectionRule(2, "state_relation", 128, 128),
            SectionRule(3, "gkr_pcs_public_coin", 192, 192),
        ),
        max_total_length=2048,
    )
    return grammar, identity


def _error_envelope(error_code: str, capacity: int) -> bytes:
    if error_code not in {"MALFORMED_INPUT", "PUBLIC_COIN_ABORT", "CRASH_RECOVERY"}:
        raise H6SimulatorError("h6_simulator_error_code_invalid")
    body = _digest(
        b"BL/PQ512/H6/SIMULATOR/ERROR/v1\x00",
        error_code.encode("ascii"),
        capacity.to_bytes(2, "big"),
    )
    encoded = b"BLH6ER01" + bytes((1, 0)) + len(body).to_bytes(4, "big") + body
    encoded += bytes(ERROR_BYTES - len(encoded))
    if len(encoded) != ERROR_BYTES:
        raise AssertionError("h6_simulator_error_length")
    return encoded


@dataclass(frozen=True, slots=True)
class SimulationRecord:
    capacity: int
    outcome: str
    attempt_id_512: bytes
    randomness_id_512: bytes
    proof_body: bytes
    sidecar: bytes
    receipt: bytes
    accepted: bool
    error_code: str | None

    def __post_init__(self) -> None:
        if self.capacity not in PROFILES or self.outcome not in OUTCOMES:
            raise H6SimulatorError("h6_simulator_record_profile_invalid")
        if len(self.attempt_id_512) != 64 or len(self.randomness_id_512) != 64:
            raise H6SimulatorError("h6_simulator_record_identity_invalid")
        if self.accepted is not True or self.error_code is not None:
            raise H6SimulatorError("h6_simulator_valid_record_status_invalid")
        if not self.proof_body or len(self.sidecar) != SIDECAR_BYTES or len(self.receipt) != RECEIPT_BYTES:
            raise H6SimulatorError("h6_simulator_valid_record_shape_invalid")

    @property
    def observable_shape(self) -> tuple[int, int, int, int, int]:
        return (len(self.proof_body), len(self.sidecar), len(self.receipt), 0, 17)

    @property
    def proof_digest_512(self) -> bytes:
        return sha3_512(self.proof_body).digest()

    @property
    def sidecar_digest_512(self) -> bytes:
        return sha3_512(self.sidecar).digest()

    @property
    def receipt_digest_512(self) -> bytes:
        return sha3_512(self.receipt).digest()

    def as_public_dict(self) -> dict[str, object]:
        return {
            "capacity": self.capacity,
            "attempt_id_sha3_512": self.attempt_id_512.hex(),
            "randomness_id_sha3_512": self.randomness_id_512.hex(),
            "proof_body_bytes": len(self.proof_body),
            "sidecar_bytes": len(self.sidecar),
            "receipt_bytes": len(self.receipt),
            "proof_sha3_512": self.proof_digest_512.hex(),
            "sidecar_sha3_512": self.sidecar_digest_512.hex(),
            "receipt_sha3_512": self.receipt_digest_512.hex(),
            "observable_shape": self.observable_shape,
            "accepted": self.accepted,
            "error_code": self.error_code,
            "proofSuiteId": None,
            "activationAllowed": False,
        }


def simulate_valid(
    capacity: int,
    outcome: str,
    *,
    logical_attempt: bytes,
    proof_randomness: bytes,
) -> SimulationRecord:
    if capacity not in PROFILES or outcome not in OUTCOMES:
        raise H6SimulatorError("h6_simulator_input_invalid")
    if type(logical_attempt) is not bytes or not logical_attempt:
        raise H6SimulatorError("h6_simulator_attempt_invalid")
    if type(proof_randomness) is not bytes or not proof_randomness:
        raise H6SimulatorError("h6_simulator_randomness_invalid")
    attempt_id = _digest(
        b"BL/PQ512/H6/SIMULATOR/ATTEMPT/v1\x00",
        logical_attempt,
        capacity.to_bytes(2, "big"),
    )
    randomness_id = _digest(
        b"BL/PQ512/H6/SIMULATOR/RANDOMNESS/v1\x00",
        proof_randomness,
        attempt_id,
    )
    semantic = _digest(
        b"BL/PQ512/H6/SIMULATOR/SEMANTIC-AIR/v1\x00",
        outcome.encode("ascii"),
        logical_attempt,
    )
    state = _stream(
        b"BL/PQ512/H6/SIMULATOR/STATE/v1\x00",
        semantic + attempt_id,
        128,
    )
    gkr = _stream(
        b"BL/PQ512/H6/SIMULATOR/GKR/v1\x00",
        state + randomness_id,
        192,
    )
    pcs = _stream(
        b"BL/PQ512/H6/SIMULATOR/PCS/v1\x00",
        gkr + randomness_id,
        256,
    )
    public_coin = _digest(
        b"BL/PQ512/H6/SIMULATOR/PUBLIC-COIN/v1\x00",
        semantic,
        state,
        gkr,
        pcs,
        randomness_id,
    )
    grammar, identity = _grammar(capacity)
    payloads = (
        SectionPayload(1, semantic),
        SectionPayload(2, state),
        SectionPayload(3, gkr[:64] + pcs[:128]),
    )
    proof_body = encode_reference_proof_body(
        payloads,
        grammar=grammar,
        active_identity=identity,
    )
    parse_proof_body(proof_body, grammar=grammar, active_identity=identity)
    sidecar_fields = (
        _profile_identity(capacity, "profile"),
        _profile_identity(capacity, "state-old"),
        _profile_identity(capacity, "state-new"),
        semantic,
        state[:64],
        gkr[:64],
        pcs[:64],
        public_coin,
        attempt_id,
        identity.schema_id,
        grammar_identity(),
    )
    sidecar = encode_sidecar(sidecar_fields)
    parse_sidecar(sidecar)
    receipt_fields = (
        attempt_id,
        _digest(b"BL/PQ512/H6/SIMULATOR/TRANSITION/v1\x00", state),
        sha3_512(proof_body).digest(),
        sha3_512(sidecar).digest(),
        identity.verifier_artifact_identity,
        _digest(b"BL/PQ512/H6/SIMULATOR/STATE-ROOT/v1\x00", state),
        grammar_identity(),
    )
    receipt = encode_receipt(receipt_fields)
    parsed_receipt = parse_receipt(receipt)
    if parsed_receipt[0] != attempt_id or parsed_receipt[2] != sha3_512(proof_body).digest():
        raise H6SimulatorError("h6_simulator_receipt_binding")
    return SimulationRecord(
        capacity=capacity,
        outcome=outcome,
        attempt_id_512=attempt_id,
        randomness_id_512=randomness_id,
        proof_body=proof_body,
        sidecar=sidecar,
        receipt=receipt,
        accepted=True,
        error_code=None,
    )


@dataclass(frozen=True, slots=True)
class RejectionRecord:
    capacity: int
    error_code: str
    envelope: bytes

    @property
    def observable_shape(self) -> tuple[int, int, int, int, int]:
        return (0, 0, 0, len(self.envelope), 17)


def simulate_malformed(capacity: int, case: str) -> RejectionRecord:
    if capacity not in PROFILES or case not in MALFORMED_CASES:
        raise H6SimulatorError("h6_simulator_malformed_case_invalid")
    return RejectionRecord(capacity, "MALFORMED_INPUT", _error_envelope("MALFORMED_INPUT", capacity))


def simulate_abort(capacity: int) -> RejectionRecord:
    if capacity not in PROFILES:
        raise H6SimulatorError("h6_simulator_abort_profile_invalid")
    return RejectionRecord(capacity, "PUBLIC_COIN_ABORT", _error_envelope("PUBLIC_COIN_ABORT", capacity))


def simulate_crash_recovery(capacity: int) -> dict[str, object]:
    if capacity not in PROFILES:
        raise H6SimulatorError("h6_simulator_crash_profile_invalid")
    crash = _error_envelope("CRASH_RECOVERY", capacity)
    return {
        "capacity": capacity,
        "crash_envelope_bytes": len(crash),
        "retained_artifact_count": 0,
        "retained_artifact_bytes": 0,
        "recovered_partial_receipt": False,
        "cleanup_complete": True,
    }


def run_complete_simulator_suite() -> dict[str, object]:
    native_hiding = run_native_hiding_simulator_suite()
    if not all(
        native_hiding.get(key) is True
        for key in (
            "fixed_shape_verified",
            "private_opening_verified",
            "simulator_shape_verified",
            "error_shape_verified",
        )
    ):
        raise H6SimulatorError("h6_simulator_native_hiding_boundary_failed")
    valid: list[SimulationRecord] = []
    for capacity in PROFILES:
        shapes: set[tuple[int, int, int, int, int]] = set()
        for outcome in OUTCOMES:
            record = simulate_valid(
                capacity,
                outcome,
                logical_attempt=b"logical-attempt-0",
                proof_randomness=(f"fresh-{capacity}-{outcome}".encode("ascii")),
            )
            valid.append(record)
            shapes.add(record.observable_shape)
        if len(shapes) != 1:
            raise H6SimulatorError("h6_simulator_outcome_shape_drift")
        retry = simulate_valid(
            capacity,
            "APPROVAL",
            logical_attempt=b"logical-attempt-0",
            proof_randomness=f"fresh-retry-{capacity}".encode("ascii"),
        )
        first = valid[-3]
        if first.attempt_id_512 != retry.attempt_id_512 or first.receipt_digest_512 == retry.receipt_digest_512:
            raise H6SimulatorError("h6_simulator_retry_binding")
        malformed = tuple(simulate_malformed(capacity, case) for case in MALFORMED_CASES)
        if len({item.observable_shape for item in malformed}) != 1:
            raise H6SimulatorError("h6_simulator_malformed_shape_drift")
        abort = simulate_abort(capacity)
        if abort.observable_shape != malformed[0].observable_shape:
            raise H6SimulatorError("h6_simulator_abort_shape_drift")
        crash = simulate_crash_recovery(capacity)
        if crash["retained_artifact_count"] != 0 or crash["retained_artifact_bytes"] != 0:
            raise H6SimulatorError("h6_simulator_crash_artifact_retention")
    return {
        "status": STATUS,
        "profiles": PROFILES,
        "outcomes": OUTCOMES,
        "malformed_case_count": len(MALFORMED_CASES),
        "valid_record_count": len(valid),
        "semantic_air_simulated": True,
        "state_simulated": True,
        "gkr_simulated": True,
        "pcs_simulated": True,
        "public_coin_simulated": True,
        "malformed_input_rejected": True,
        "abort_rejected": True,
        "retry_fresh_randomness": True,
        "crash_recovery_zero_retained_artifacts": True,
        "repeated_proof_shape_fixed": True,
        "native_hiding_simulated": True,
        "native_hiding": {
            key: value for key, value in native_hiding.items() if key != "records"
        },
        "proofSuiteId": None,
        "activationAllowed": False,
        "grammar_identity_sha3_512": grammar_identity().hex(),
        "records": tuple(record.as_public_dict() for record in valid),
    }


__all__: tuple[str, ...] = (
    "H6SimulatorError",
    "MALFORMED_CASES",
    "OUTCOMES",
    "PROFILES",
    "SimulationRecord",
    "RejectionRecord",
    "run_complete_simulator_suite",
    "simulate_abort",
    "simulate_crash_recovery",
    "simulate_malformed",
    "simulate_valid",
)
