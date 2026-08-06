"""Bounded native-hiding construction and simulator for local qualification.

This module is the executable bridge between the native-hiding worksheet and
the fixed-shape lifecycle simulator. It masks every private trace column with
a domain-separated M31 polynomial, commits to the private and masked views
with SHA3-512, and exposes only fixed-shape digest records. The private
opening is retained solely for a local reference verifier; no exact witness,
amount, or mask coefficient is returned by the public record.

The implementation is intentionally bounded and nonactivating. It proves the
mask algebra and parser/shape/zeroization boundary for the local fixture; it
does not claim that this small reference is the complete production PCS,
constant-time implementation, or an activated proof suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import os
import secrets
from typing import Final, Sequence

from experiments.bl_pq512_crypto_foundation.native_hiding_parameters import (
    HidingTableDimensions,
    build_native_hiding_interface_plan,
)


M31_MODULUS: Final[int] = (1 << 31) - 1
STATUS: Final[str] = "WAVE2_NATIVE_HIDING_REFERENCE_SIMULATOR_V1_NONACTIVATING"
MAGIC: Final[bytes] = b"BLNH01"
DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/NATIVE-HIDING-SIMULATOR/v1\x00"
MASK_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/NATIVE-HIDING-MASK/v1\x00"
TRANSCRIPT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/NATIVE-HIDING-TRANSCRIPT/v1\x00"
ERROR_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/NATIVE-HIDING-ERROR/v1\x00"
MAX_TRACE_ROWS: Final[int] = 4_096
MAX_COLUMNS: Final[int] = 32
ERROR_BYTES: Final[int] = 128
QUERY_COUNT: Final[int] = 4
PROFILE_SHAPES: Final[dict[int, tuple[int, int]]] = {
    128: (64, 4),
    512: (128, 8),
}


class NativeHidingError(ValueError):
    """Stable fail-closed local hiding error."""


def _exact_bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise NativeHidingError(f"native_hiding_{label}_length_invalid")
    if nonzero and not any(value):
        raise NativeHidingError(f"native_hiding_{label}_zero")
    return value


def _m31(label: str, value: object) -> int:
    if type(value) is not int or not 0 <= value < M31_MODULUS:
        raise NativeHidingError(f"native_hiding_{label}_not_canonical_m31")
    return value


def _ascii(label: str, value: object) -> bytes:
    if type(value) is not str or not value:
        raise NativeHidingError(f"native_hiding_{label}_invalid")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise NativeHidingError(f"native_hiding_{label}_not_ascii") from exc


def _hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise NativeHidingError("native_hiding_hash_part_invalid")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def _expand(seed: bytes, count: int, *, domain: bytes = MASK_DOMAIN) -> tuple[int, ...]:
    _exact_bytes("expansion_seed", seed, 64, nonzero=True)
    if type(count) is not int or not 1 <= count <= MAX_TRACE_ROWS:
        raise NativeHidingError("native_hiding_expansion_count_invalid")
    values: list[int] = []
    counter = 0
    while len(values) < count:
        block = _hash(domain, seed, counter.to_bytes(8, "big"))
        for offset in range(0, len(block), 4):
            values.append(int.from_bytes(block[offset : offset + 4], "big") % M31_MODULUS)
            if len(values) == count:
                break
        counter += 1
    return tuple(values)


def _evaluate(coefficients: Sequence[int], x: int) -> int:
    x = _m31("evaluation_point", x)
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + _m31("mask_coefficient", coefficient)) % M31_MODULUS
    return result


def _canonical_values(values: Sequence[int], label: str) -> bytes:
    if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray, str)):
        raise NativeHidingError(f"native_hiding_{label}_sequence_invalid")
    if not values or len(values) > MAX_TRACE_ROWS:
        raise NativeHidingError(f"native_hiding_{label}_count_invalid")
    return b"".join(_m31(label, value).to_bytes(4, "big") for value in values)


def _deterministic_seed(seed: object) -> bytes:
    """Allow deterministic masks only under an explicit test-only guard."""

    if (
        os.environ.get("BL_ENV") != "test"
        or os.environ.get("BL_DETERMINISTIC_TEST_ONLY") != "1"
    ):
        raise NativeHidingError("native_hiding_deterministic_seed_requires_test_guard")
    return _exact_bytes("deterministic_seed", seed, 64, nonzero=True)


class MaskSession:
    """Issue one-use mask seeds for a fixed session."""

    __slots__ = ("session_id", "_issued")

    def __init__(self, session_id: bytes) -> None:
        self.session_id = _exact_bytes("session_id", session_id, 64, nonzero=True)
        self._issued: set[bytes] = set()

    def issue(
        self,
        profile_id: str,
        column_index: int,
        *,
        deterministic_seed: bytes | None = None,
    ) -> bytes:
        profile = _ascii("profile_id", profile_id)
        if type(column_index) is not int or not 0 <= column_index < MAX_COLUMNS:
            raise NativeHidingError("native_hiding_column_index_invalid")
        seed = (
            _deterministic_seed(deterministic_seed)
            if deterministic_seed is not None
            else secrets.token_bytes(64)
        )
        issued = _hash(
            DOMAIN,
            self.session_id,
            profile,
            column_index.to_bytes(2, "big"),
            seed,
        )
        if issued in self._issued:
            raise NativeHidingError("native_hiding_mask_seed_reuse")
        self._issued.add(issued)
        return issued


@dataclass(frozen=True, slots=True)
class MaskedColumn:
    """A private local opening plus its public digest commitments."""

    profile_id: str
    column_index: int
    trace_rows: int
    mask_degree: int
    masked_values: tuple[int, ...]
    mask_coefficients: tuple[int, ...]
    private_trace_digest: bytes
    mask_commitment: bytes
    masked_trace_commitment: bytes

    def __post_init__(self) -> None:
        _ascii("profile_id", self.profile_id)
        if type(self.column_index) is not int or not 0 <= self.column_index < MAX_COLUMNS:
            raise NativeHidingError("native_hiding_column_index_invalid")
        if type(self.trace_rows) is not int or not 1 <= self.trace_rows <= MAX_TRACE_ROWS:
            raise NativeHidingError("native_hiding_trace_rows_invalid")
        if type(self.mask_degree) is not int or not 1 <= self.mask_degree < self.trace_rows:
            raise NativeHidingError("native_hiding_mask_degree_invalid")
        if type(self.masked_values) is not tuple or len(self.masked_values) != self.trace_rows:
            raise NativeHidingError("native_hiding_masked_trace_shape_invalid")
        if any(
            type(value) is not int or not 0 <= value < M31_MODULUS
            for value in self.masked_values
        ):
            raise NativeHidingError("native_hiding_masked_trace_value_invalid")
        if type(self.mask_coefficients) is not tuple or len(self.mask_coefficients) != self.mask_degree:
            raise NativeHidingError("native_hiding_mask_coefficient_shape_invalid")
        for value in self.mask_coefficients:
            _m31("mask_coefficient", value)
        for label, value in (
            ("private_trace_digest", self.private_trace_digest),
            ("mask_commitment", self.mask_commitment),
            ("masked_trace_commitment", self.masked_trace_commitment),
        ):
            _exact_bytes(label, value, 64, nonzero=True)

    @property
    def public_shape(self) -> tuple[int, int, int]:
        return (self.trace_rows, self.mask_degree, QUERY_COUNT)

    def as_public_dict(self) -> dict[str, object]:
        """Return only fixed-shape commitments and no private trace material."""

        return {
            "profile_id": self.profile_id,
            "column_index": self.column_index,
            "trace_rows": self.trace_rows,
            "mask_degree": self.mask_degree,
            "query_count": QUERY_COUNT,
            "private_trace_commitment_sha3_512": self.private_trace_digest.hex(),
            "mask_commitment_sha3_512": self.mask_commitment.hex(),
            "masked_trace_commitment_sha3_512": self.masked_trace_commitment.hex(),
        }

    def verify_private_opening(self, private_trace: Sequence[int]) -> None:
        encoded = _canonical_values(private_trace, "private_trace")
        if len(private_trace) != self.trace_rows:
            raise NativeHidingError("native_hiding_private_trace_shape_invalid")
        expected_private_digest = _hash(DOMAIN, self.profile_id.encode("ascii"), encoded)
        if expected_private_digest != self.private_trace_digest:
            raise NativeHidingError("native_hiding_private_trace_commitment_mismatch")
        expected_mask = tuple(
            _evaluate(self.mask_coefficients, row + 1) for row in range(self.trace_rows)
        )
        expected_masked = tuple(
            (_m31("private_trace", value) + mask) % M31_MODULUS
            for value, mask in zip(private_trace, expected_mask, strict=True)
        )
        if expected_masked != self.masked_values:
            raise NativeHidingError("native_hiding_masked_trace_mismatch")
        expected_mask_commitment = _hash(
            MASK_DOMAIN,
            self.profile_id.encode("ascii"),
            self.column_index.to_bytes(2, "big"),
            b"".join(value.to_bytes(4, "big") for value in self.mask_coefficients),
        )
        if expected_mask_commitment != self.mask_commitment:
            raise NativeHidingError("native_hiding_mask_commitment_mismatch")
        expected_masked_commitment = _hash(
            TRANSCRIPT_DOMAIN,
            self.profile_id.encode("ascii"),
            self.column_index.to_bytes(2, "big"),
            b"".join(value.to_bytes(4, "big") for value in self.masked_values),
        )
        if expected_masked_commitment != self.masked_trace_commitment:
            raise NativeHidingError("native_hiding_masked_trace_commitment_mismatch")


@dataclass(frozen=True, slots=True)
class HidingTranscript:
    profile_id: str
    session_id: bytes
    public_statement_digest: bytes
    columns: tuple[MaskedColumn, ...]
    transcript_digest: bytes
    simulated: bool
    proof_suite_id: None = None
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        _ascii("profile_id", self.profile_id)
        _exact_bytes("session_id", self.session_id, 64, nonzero=True)
        _exact_bytes("public_statement_digest", self.public_statement_digest, 64, nonzero=True)
        if type(self.columns) is not tuple or not 1 <= len(self.columns) <= MAX_COLUMNS:
            raise NativeHidingError("native_hiding_column_count_invalid")
        if tuple(item.column_index for item in self.columns) != tuple(range(len(self.columns))):
            raise NativeHidingError("native_hiding_column_order_invalid")
        if any(item.profile_id != self.profile_id for item in self.columns):
            raise NativeHidingError("native_hiding_column_profile_mismatch")
        _exact_bytes("transcript_digest", self.transcript_digest, 64, nonzero=True)
        if self.proof_suite_id is not None or self.activation_allowed:
            raise NativeHidingError("native_hiding_activation_boundary_violated")

    @property
    def observable_shape(self) -> tuple[int, int, int, int]:
        return (len(self.columns), self.columns[0].trace_rows, QUERY_COUNT, ERROR_BYTES)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": STATUS,
            "profile_id": self.profile_id,
            "session_id_sha3_512": self.session_id.hex(),
            "public_statement_sha3_512": self.public_statement_digest.hex(),
            "column_count": len(self.columns),
            "trace_rows": self.columns[0].trace_rows,
            "query_count": QUERY_COUNT,
            "error_envelope_bytes": ERROR_BYTES,
            "transcript_sha3_512": self.transcript_digest.hex(),
            "columns": tuple(item.as_public_dict() for item in self.columns),
            "observable_shape": self.observable_shape,
            "simulated": self.simulated,
            "proofSuiteId": None,
            "activationAllowed": False,
        }


def _profile_shape(profile: int) -> tuple[str, int, int, int]:
    if profile not in PROFILE_SHAPES:
        raise NativeHidingError("native_hiding_profile_invalid")
    rows, columns = PROFILE_SHAPES[profile]
    plan = build_native_hiding_interface_plan(
        profile_id=f"K{profile}_NATIVE_HIDING_FIXTURE",
        tables=tuple(
            HidingTableDimensions(
                f"fixture_{index:02d}",
                rows,
                1,
                index != 15,
            )
            for index in range(16)
        ),
        log_blowup=1,
        fri_query_count=1,
        reduced_air_degree=1,
    )
    return f"K{profile}_NATIVE_HIDING_FIXTURE", rows, columns, plan.trace_mask_degree_freedom


def build_hiding_transcript(
    profile: int,
    private_columns: Sequence[Sequence[int]],
    *,
    public_statement: bytes,
    session_id: bytes,
    mask_session: MaskSession,
    deterministic_seed: bytes | None = None,
) -> HidingTranscript:
    profile_id, trace_rows, expected_columns, mask_degree = _profile_shape(profile)
    _exact_bytes("public_statement", public_statement, 64, nonzero=True)
    _exact_bytes("session_id", session_id, 64, nonzero=True)
    if mask_session.session_id != session_id:
        raise NativeHidingError("native_hiding_session_mismatch")
    if not isinstance(private_columns, Sequence) or isinstance(
        private_columns, (bytes, bytearray, str)
    ):
        raise NativeHidingError("native_hiding_private_columns_invalid")
    if len(private_columns) != expected_columns:
        raise NativeHidingError("native_hiding_private_column_count_invalid")
    columns: list[MaskedColumn] = []
    for index, private_trace in enumerate(private_columns):
        encoded = _canonical_values(private_trace, "private_trace")
        if len(private_trace) != trace_rows:
            raise NativeHidingError("native_hiding_private_trace_shape_invalid")
        seed = mask_session.issue(
            profile_id,
            index,
            deterministic_seed=deterministic_seed,
        )
        coefficients = _expand(seed, mask_degree)
        masked = tuple(
            (_m31("private_trace", value) + _evaluate(coefficients, row + 1))
            % M31_MODULUS
            for row, value in enumerate(private_trace)
        )
        columns.append(
            MaskedColumn(
                profile_id,
                index,
                trace_rows,
                mask_degree,
                masked,
                coefficients,
                _hash(DOMAIN, profile_id.encode("ascii"), encoded),
                _hash(
                    MASK_DOMAIN,
                    profile_id.encode("ascii"),
                    index.to_bytes(2, "big"),
                    b"".join(value.to_bytes(4, "big") for value in coefficients),
                ),
                _hash(
                    TRANSCRIPT_DOMAIN,
                    profile_id.encode("ascii"),
                    index.to_bytes(2, "big"),
                    b"".join(value.to_bytes(4, "big") for value in masked),
                ),
            )
        )
    transcript_digest = _hash(
        TRANSCRIPT_DOMAIN,
        profile_id.encode("ascii"),
        session_id,
        _hash(DOMAIN, public_statement),
        b"".join(item.masked_trace_commitment for item in columns),
        QUERY_COUNT.to_bytes(2, "big"),
    )
    return HidingTranscript(
        profile_id,
        session_id,
        _hash(DOMAIN, public_statement),
        tuple(columns),
        transcript_digest,
        False,
    )


def simulate_hiding_transcript(
    profile: int,
    *,
    public_statement: bytes,
    session_id: bytes,
    deterministic_seed: bytes | None = None,
) -> HidingTranscript:
    profile_id, trace_rows, column_count, _ = _profile_shape(profile)
    seed = (
        _deterministic_seed(deterministic_seed)
        if deterministic_seed is not None
        else secrets.token_bytes(64)
    )
    columns = tuple(
        tuple(_expand(_hash(DOMAIN, seed, index.to_bytes(2, "big")), trace_rows))
        for index in range(column_count)
    )
    session = MaskSession(session_id)
    transcript = build_hiding_transcript(
        profile,
        columns,
        public_statement=public_statement,
        session_id=session_id,
        mask_session=session,
        deterministic_seed=(
            _hash(DOMAIN, seed, b"simulator-mask-seed")
            if deterministic_seed is not None
            else None
        ),
    )
    return HidingTranscript(
        transcript.profile_id,
        transcript.session_id,
        transcript.public_statement_digest,
        transcript.columns,
        transcript.transcript_digest,
        True,
    )


def verify_hiding_transcript(
    transcript: HidingTranscript,
    private_columns: Sequence[Sequence[int]],
) -> None:
    if type(transcript) is not HidingTranscript or transcript.simulated:
        raise NativeHidingError("native_hiding_reference_transcript_required")
    if len(private_columns) != len(transcript.columns):
        raise NativeHidingError("native_hiding_private_column_count_invalid")
    for column, private_trace in zip(transcript.columns, private_columns, strict=True):
        column.verify_private_opening(private_trace)
    expected = _hash(
        TRANSCRIPT_DOMAIN,
        transcript.profile_id.encode("ascii"),
        transcript.session_id,
        transcript.public_statement_digest,
        b"".join(item.masked_trace_commitment for item in transcript.columns),
        QUERY_COUNT.to_bytes(2, "big"),
    )
    if expected != transcript.transcript_digest:
        raise NativeHidingError("native_hiding_transcript_digest_mismatch")


def fixed_error_envelope(profile: int, error_code: str) -> bytes:
    if profile not in PROFILE_SHAPES or error_code not in {
        "MALFORMED_INPUT",
        "PUBLIC_COIN_ABORT",
        "CRASH_RECOVERY",
    }:
        raise NativeHidingError("native_hiding_error_invalid")
    body = _hash(ERROR_DOMAIN, f"K{profile}".encode("ascii"), error_code.encode("ascii"))
    envelope = MAGIC + bytes((1, 0)) + len(body).to_bytes(4, "big") + body
    if len(envelope) > ERROR_BYTES:
        raise AssertionError("native_hiding_error_envelope_overflow")
    return envelope + bytes(ERROR_BYTES - len(envelope))


def run_native_hiding_simulator_suite() -> dict[str, object]:
    records: list[dict[str, object]] = []
    for profile in PROFILE_SHAPES:
        _, rows, columns, _ = _profile_shape(profile)
        private_columns = tuple(
            tuple((column + row + 1) % M31_MODULUS for row in range(rows))
            for column in range(columns)
        )
        session_id = _hash(DOMAIN, f"session-{profile}".encode("ascii"))
        session = MaskSession(session_id)
        statement = _hash(DOMAIN, f"statement-{profile}".encode("ascii"))
        actual = build_hiding_transcript(
            profile,
            private_columns,
            public_statement=statement,
            session_id=session_id,
            mask_session=session,
        )
        verify_hiding_transcript(actual, private_columns)
        simulated = simulate_hiding_transcript(
            profile,
            public_statement=statement,
            session_id=_hash(DOMAIN, f"sim-session-{profile}".encode("ascii")),
        )
        if actual.observable_shape != simulated.observable_shape:
            raise NativeHidingError("native_hiding_simulator_shape_mismatch")
        errors = tuple(
            fixed_error_envelope(profile, code)
            for code in ("MALFORMED_INPUT", "PUBLIC_COIN_ABORT", "CRASH_RECOVERY")
        )
        if len(set(map(len, errors))) != 1 or len(errors[0]) != ERROR_BYTES:
            raise NativeHidingError("native_hiding_error_shape_mismatch")
        records.extend((actual.as_public_dict(), simulated.as_public_dict()))
    return {
        "status": STATUS,
        "profile_count": len(PROFILE_SHAPES),
        "record_count": len(records),
        "fixed_shape_verified": True,
        "private_opening_verified": True,
        "simulator_shape_verified": True,
        "error_shape_verified": True,
        "zeroization_required": True,
        "proofSuiteId": None,
        "activationAllowed": False,
        "records": tuple(records),
    }


def zeroize(buffer: bytearray) -> None:
    if type(buffer) is not bytearray:
        raise TypeError("native_hiding_zeroize_bytearray_required")
    for index in range(len(buffer)):
        buffer[index] = 0


__all__ = (
    "ERROR_BYTES",
    "HidingTranscript",
    "MAGIC",
    "M31_MODULUS",
    "MaskSession",
    "MaskedColumn",
    "NativeHidingError",
    "PROFILE_SHAPES",
    "STATUS",
    "build_hiding_transcript",
    "fixed_error_envelope",
    "run_native_hiding_simulator_suite",
    "simulate_hiding_transcript",
    "verify_hiding_transcript",
    "zeroize",
)
