"""Mode-specific AUTHORITATIVE_ASSERTION V1 verification.

This module owns only the volatile source-signature handoff and its narrow,
non-dispositive result.  State issuance, acceptance-unit reservation, state
disposition, and the outbox remain owned by the composition store.

The controlled reference profile is pure FIPS 204 ML-DSA-65.  The resolved
``pqcrypto`` API does not expose hedging or a context parameter, so the
complete domain-separated canonical message is signed directly.  Source-side
key generation/signing is intentionally not part of this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, BinaryIO, Final, NoReturn

class AuthoritativeAssertionError(RuntimeError):
    """Fixed public failure codes for the volatile assertion boundary."""


def _fail(code: str) -> NoReturn:
    error = AuthoritativeAssertionError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


MODE: Final[str] = "AUTHORITATIVE_ASSERTION"
SOURCE_AUTH_PROFILE_ID: Final[str] = "ML-DSA-65-PURE-V1"
SIGNATURE_PROFILE_VERSION: Final[str] = "FIPS204-ML-DSA-65-PURE-V1"
VERIFIER_PROFILE_VERSION: Final[str] = "BL-AUTH-ASSERTION-MLDSA65-VERIFIER-V1"
QUALIFICATION_FLAGS: Final[tuple[str, ...]] = ("authoritative_assertion_v1",)
MEMBER_COUNT: Final[int] = 100
RESERVATION_UNITS: Final[int] = 101
LIFETIME_ACCEPTANCE_CAP: Final[int] = 2**32
PUBLIC_KEY_SIZE: Final[int] = 1952
SECRET_KEY_SIZE: Final[int] = 4032
SIGNATURE_SIZE: Final[int] = 3309
MAX_VALIDITY_WINDOW_MS: Final[int] = 365 * 24 * 60 * 60 * 1000
RECEIPT_LIMIT_BYTES: Final[int] = 16 * 1024
_MAX_TOKEN: Final[int] = 128
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_BATCH_LEAF = b"BL/AUTHORITATIVE-ASSERTION/BATCH-LEAF/v1\x00"
_BATCH_ROOT = b"BL/AUTHORITATIVE-ASSERTION/BATCH-ROOT/v1\x00"
_MESSAGE = b"BL/AUTHORITATIVE-ASSERTION/SOURCE-SIGNATURE/v1\x00"
_RECEIPT = b"BL/AUTHORITATIVE-ASSERTION/RECEIPT/v1\x00"
_VERIFIER_TOKEN = object()
_DURABLE_TOKEN = object()
_RESERVATION_TOKEN = object()


def _token(value: object, code: str) -> str:
    if type(value) is not str or len(value) > _MAX_TOKEN or _TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _u64(value: int, code: str = "integer") -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        _fail(code)
    return value.to_bytes(8, "big")


def _root(value: object, code: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(code)
    return bytes(value)


def _ref(value: object, code: str = "operation_ref") -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail(code)
    return bytes(value)


def _field(tag: bytes, value: bytes) -> bytes:
    if type(tag) is not bytes or len(tag) != 1 or type(value) is not bytes or len(value) >= 2**32:
        _fail("canonical_field")
    return tag + len(value).to_bytes(4, "big") + value


def _text(value: str, code: str) -> bytes:
    return _token(value, code).encode("ascii")


def _optional_root(value: bytes | None, code: str) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + _field(b"R", _root(value, code))


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail("canonical_type")
        digest.update(part)
    return digest.digest()


@dataclass(frozen=True, slots=True)
class AuthoritativeAssertionTemplateV1:
    """Caller-provided allowlisted metadata; it has no state-issued values."""

    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    approved_source_registry_root: bytes | None = None

    def __post_init__(self) -> None:
        _token(self.assertion_identifier, "assertion_identifier")
        if type(self.assertion_version) is not int or not 1 <= self.assertion_version <= 2**31:
            _fail("assertion_version")
        _token(self.state_profile_version, "state_profile_version")
        if type(self.valid_from_ms) is not int or type(self.valid_until_ms) is not int or not 0 <= self.valid_from_ms < self.valid_until_ms or self.valid_until_ms - self.valid_from_ms > MAX_VALIDITY_WINDOW_MS:
            _fail("validity_window")
        if self.approved_source_registry_root is not None:
            _root(self.approved_source_registry_root, "source_registry_root")

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _field(b"I", _text(self.assertion_identifier, "assertion_identifier")),
                _field(b"V", _u64(self.assertion_version)),
                _field(b"P", _text(self.state_profile_version, "state_profile_version")),
                _field(b"F", _u64(self.valid_from_ms)),
                _field(b"T", _u64(self.valid_until_ms)),
                _field(b"G", _optional_root(self.approved_source_registry_root, "source_registry_root")),
            )
        )


@dataclass(frozen=True, slots=True)
class AuthoritativeIssuedOperationV1:
    """Immutable state-issued operation statement."""

    operation_ref: bytes
    template: AuthoritativeAssertionTemplateV1
    batch_position: int
    batch_root: bytes

    def __post_init__(self) -> None:
        _ref(self.operation_ref)
        if type(self.template) is not AuthoritativeAssertionTemplateV1:
            _fail("statement_template")
        if type(self.batch_position) is not int or not 0 <= self.batch_position < MEMBER_COUNT:
            _fail("batch_position")
        _root(self.batch_root, "batch_root")

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _field(b"N", _ref(self.operation_ref)),
                _field(b"O", _u64(self.batch_position)),
                _field(b"B", _root(self.batch_root, "batch_root")),
                _field(b"T", self.template.canonical_bytes),
            )
        )


def compute_batch_root(statements: tuple[AuthoritativeIssuedOperationV1, ...]) -> bytes:
    if type(statements) is not tuple or len(statements) != MEMBER_COUNT:
        _fail("authoritative_batch_cardinality")
    if tuple(statement.batch_position for statement in statements) != tuple(range(MEMBER_COUNT)):
        _fail("authoritative_batch_order")
    leaves = tuple(
        _sha(_BATCH_LEAF, _u64(statement.batch_position), _ref(statement.operation_ref), statement.template.canonical_bytes)
        for statement in statements
    )
    return _sha(_BATCH_ROOT, _u64(MEMBER_COUNT), b"".join(leaves))


@dataclass(frozen=True, slots=True)
class AuthoritativeBatchStatementV1:
    statements: tuple[AuthoritativeIssuedOperationV1, ...]
    batch_root: bytes
    source_key_epoch: int = 0

    def __post_init__(self) -> None:
        if type(self.statements) is not tuple or len(self.statements) != MEMBER_COUNT:
            _fail("authoritative_batch_cardinality")
        if type(self.source_key_epoch) is not int or self.source_key_epoch < 0:
            _fail("source_key_epoch")
        _root(self.batch_root, "batch_root")
        if any(statement.batch_root != self.batch_root for statement in self.statements) or compute_batch_root(self.statements) != self.batch_root:
            _fail("authoritative_batch_root")
        profiles = {statement.template.state_profile_version for statement in self.statements}
        if len(profiles) != 1:
            _fail("authoritative_profile_binding")

    @property
    def state_profile_version(self) -> str:
        return self.statements[0].template.state_profile_version

    @property
    def operation_refs(self) -> tuple[bytes, ...]:
        return tuple(statement.operation_ref for statement in self.statements)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _field(b"M", _text(MODE, "mode")),
                _field(b"C", _u64(MEMBER_COUNT)),
                _field(b"P", _text(self.state_profile_version, "state_profile_version")),
                _field(b"A", _text(SOURCE_AUTH_PROFILE_ID, "source_auth_profile")),
                _field(b"S", _text(SIGNATURE_PROFILE_VERSION, "signature_profile")),
                _field(b"E", _u64(self.source_key_epoch)),
                _field(b"Q", b"".join(_field(b"F", _text(flag, "qualification_flag")) for flag in QUALIFICATION_FLAGS)),
                _field(b"R", _root(self.batch_root, "batch_root")),
                b"".join(_field(b"I", statement.canonical_bytes) for statement in self.statements),
            )
        )


def signature_message(batch: AuthoritativeBatchStatementV1) -> bytes:
    if type(batch) is not AuthoritativeBatchStatementV1:
        _fail("authoritative_batch_shape")
    return _field(b"D", _MESSAGE) + _field(b"V", batch.canonical_bytes)


class AuthoritativeReservation:
    """Single-use state-owned proof-attempt reservation capability."""

    __slots__ = ("batch_root", "units", "_used", "_origin")

    def __init__(self, batch_root: bytes, units: int, *, _origin: object) -> None:
        self.batch_root = _root(batch_root, "reservation_batch_root")
        if type(units) is not int or units != RESERVATION_UNITS:
            _fail("reservation_units")
        if _origin is not _RESERVATION_TOKEN:
            _fail("reservation_origin")
        self.units = units
        self._used = False
        self._origin = _origin

    def consume(self, batch_root: bytes) -> None:
        if self._used or self._origin is not _RESERVATION_TOKEN or self.batch_root != _root(batch_root, "reservation_batch_root"):
            _fail("reservation_reuse")
        self._used = True


def _create_reservation(batch_root: bytes) -> AuthoritativeReservation:
    return AuthoritativeReservation(batch_root, RESERVATION_UNITS, _origin=_RESERVATION_TOKEN)


class VolatileSignatureHandoff:
    """Single-use exact-size signature stream; no filesystem staging."""

    __slots__ = ("_stream", "declared_length", "_used", "_closed", "_staging")

    def __init__(self, stream: BinaryIO, *, declared_length: int | None = None) -> None:
        if not hasattr(stream, "read") or not callable(stream.read):
            _fail("signature_handoff_stream")
        if declared_length is not None and (type(declared_length) is not int or declared_length != SIGNATURE_SIZE):
            close = getattr(stream, "close", None)
            if callable(close):
                close()
            _fail("signature_length")
        self._stream = stream
        self.declared_length = declared_length
        self._used = False
        self._closed = False
        self._staging = bytearray()

    @property
    def used(self) -> bool:
        return self._used

    @property
    def closed(self) -> bool:
        return self._closed

    def _open(self) -> None:
        if self._closed:
            _fail("signature_handoff_closed")
        if self._used:
            _fail("signature_handoff_reuse")
        self._used = True

    def read_exact(self) -> bytes:
        self._open()
        try:
            while len(self._staging) < SIGNATURE_SIZE:
                remaining = SIGNATURE_SIZE - len(self._staging)
                try:
                    value = self._stream.read(remaining)
                except BaseException:
                    _fail("signature_transport")
                if type(value) is not bytes:
                    _fail("signature_bytes")
                if not value:
                    _fail("signature_length")
                if len(value) > remaining:
                    self._staging.extend(value[:remaining])
                    _fail("signature_length")
                self._staging.extend(value)
        except AuthoritativeAssertionError:
            raise
        try:
            extra = self._stream.read(1)
        except BaseException:
            _fail("signature_transport")
        if type(extra) is not bytes or extra:
            _fail("signature_trailing_bytes")
        return bytes(self._staging)

    def wipe(self) -> None:
        for index in range(len(self._staging)):
            self._staging[index] = 0
        self._staging.clear()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            close = getattr(self._stream, "close", None)
            if callable(close):
                close()
        finally:
            self.wipe()

    def __enter__(self) -> "VolatileSignatureHandoff":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class AuthoritativeAssertionResultV1:
    assertion_accepted: bool
    batch_root: bytes
    member_count: int
    source_auth_profile_id: str
    signature_profile_version: str
    verifier_profile_version: str
    source_key_epoch: int
    outcome_code: str
    error_code: str | None = None
    resource_code: str | None = None
    qualification_flags: tuple[str, ...] = QUALIFICATION_FLAGS
    _origin: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._origin not in {_VERIFIER_TOKEN, _DURABLE_TOKEN}:
            _fail("assertion_result_origin")
        if type(self.assertion_accepted) is not bool:
            _fail("assertion_result_shape")
        _root(self.batch_root, "assertion_batch_root")
        if type(self.member_count) is not int or self.member_count != MEMBER_COUNT:
            _fail("assertion_result_cardinality")
        if self.source_auth_profile_id != SOURCE_AUTH_PROFILE_ID or self.signature_profile_version != SIGNATURE_PROFILE_VERSION or self.verifier_profile_version != VERIFIER_PROFILE_VERSION:
            _fail("assertion_result_profile")
        if type(self.source_key_epoch) is not int or self.source_key_epoch < 0:
            _fail("assertion_result_epoch")
        _token(self.outcome_code, "assertion_outcome")
        if self.error_code is not None:
            _token(self.error_code, "assertion_error")
        if self.resource_code is not None:
            _token(self.resource_code, "assertion_resource")
        if type(self.qualification_flags) is not tuple or self.qualification_flags != QUALIFICATION_FLAGS:
            _fail("assertion_result_flags")

    @property
    def as_json(self) -> dict[str, Any]:
        return {
            "schema": "BL/AUTHORITATIVE-ASSERTION/RECEIPT/v1",
            "evidence_mode": MODE,
            "assertion_accepted": self.assertion_accepted,
            "batch_root": self.batch_root.hex().upper(),
            "member_count": self.member_count,
            "source_auth_profile_id": self.source_auth_profile_id,
            "signature_profile_version": self.signature_profile_version,
            "verifier_profile_version": self.verifier_profile_version,
            "source_key_epoch": self.source_key_epoch,
            "outcome_code": self.outcome_code,
            "error_code": self.error_code,
            "resource_code": self.resource_code,
            "qualification_flags": list(self.qualification_flags),
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
        }

    @property
    def receipt_bytes(self) -> bytes:
        import json

        raw = json.dumps(self.as_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(raw) > RECEIPT_LIMIT_BYTES:
            _fail("assertion_receipt_bounds")
        return raw

    @property
    def receipt_digest(self) -> bytes:
        return _sha(_RECEIPT, self.receipt_bytes)

    @property
    def verifier_owned(self) -> bool:
        return self._origin is _VERIFIER_TOKEN


_RESULT_KEYS: Final[frozenset[str]] = frozenset({
    "schema", "evidence_mode", "assertion_accepted", "batch_root", "member_count",
    "source_auth_profile_id", "signature_profile_version", "verifier_profile_version",
    "source_key_epoch", "outcome_code", "error_code", "resource_code", "qualification_flags",
    "proof_suite_id", "production_usable", "activation",
})


def parse_result(value: object) -> AuthoritativeAssertionResultV1:
    if isinstance(value, AuthoritativeAssertionResultV1):
        return value
    if type(value) is not dict or set(value) != _RESULT_KEYS:
        _fail("assertion_result_unknown_field")
    if value["schema"] != "BL/AUTHORITATIVE-ASSERTION/RECEIPT/v1" or value["evidence_mode"] != MODE or value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("assertion_result_binding")
    if type(value["assertion_accepted"]) is not bool or type(value["member_count"]) is not int or type(value["source_key_epoch"]) is not int or type(value["qualification_flags"]) is not list:
        _fail("assertion_result_shape")
    try:
        batch_root = bytes.fromhex(value["batch_root"])
    except (TypeError, ValueError):
        _fail("assertion_batch_root")
    flags = tuple(value["qualification_flags"])
    return AuthoritativeAssertionResultV1(bool(value["assertion_accepted"]), batch_root, int(value["member_count"]), str(value["source_auth_profile_id"]), str(value["signature_profile_version"]), str(value["verifier_profile_version"]), int(value["source_key_epoch"]), str(value["outcome_code"]), None if value["error_code"] is None else str(value["error_code"]), None if value["resource_code"] is None else str(value["resource_code"]), flags, _origin=_DURABLE_TOKEN)


class AuthoritativeAssertionVerifierV1:
    """Verifier-owned public-key access control and volatile signature check."""

    def __init__(self, *, public_key: bytes, source_key_epoch: int = 0) -> None:
        if type(public_key) is not bytes or len(public_key) != PUBLIC_KEY_SIZE:
            _fail("source_public_key_size")
        if type(source_key_epoch) is not int or source_key_epoch < 0:
            _fail("source_key_epoch")
        self._public_key = bytes(public_key)
        self._source_key_epoch = source_key_epoch

    def verify(self, batch: AuthoritativeBatchStatementV1, signature_stream: BinaryIO | VolatileSignatureHandoff, *, reservation: AuthoritativeReservation, declared_length: int | None = None) -> AuthoritativeAssertionResultV1:
        if type(batch) is not AuthoritativeBatchStatementV1:
            _fail("authoritative_batch_shape")
        if type(reservation) is not AuthoritativeReservation:
            close = getattr(signature_stream, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException:
                    pass
            _fail("reservation_required")
        try:
            reservation.consume(batch.batch_root)
        except AuthoritativeAssertionError:
            close = getattr(signature_stream, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException:
                    pass
            raise
        handoff: VolatileSignatureHandoff | None = None
        try:
            try:
                handoff = signature_stream if isinstance(signature_stream, VolatileSignatureHandoff) else VolatileSignatureHandoff(signature_stream, declared_length=declared_length)
            except AuthoritativeAssertionError as error:
                return AuthoritativeAssertionResultV1(False, batch.batch_root, MEMBER_COUNT, SOURCE_AUTH_PROFILE_ID, SIGNATURE_PROFILE_VERSION, VERIFIER_PROFILE_VERSION, self._source_key_epoch, "MALFORMED", str(error), None, _origin=_VERIFIER_TOKEN)
            if batch.source_key_epoch != self._source_key_epoch:
                return AuthoritativeAssertionResultV1(False, batch.batch_root, MEMBER_COUNT, SOURCE_AUTH_PROFILE_ID, SIGNATURE_PROFILE_VERSION, VERIFIER_PROFILE_VERSION, batch.source_key_epoch, "KEY_EPOCH_MISMATCH", "source_key_epoch_mismatch", None, _origin=_VERIFIER_TOKEN)
            try:
                signature = handoff.read_exact()
            except AuthoritativeAssertionError as error:
                return AuthoritativeAssertionResultV1(False, batch.batch_root, MEMBER_COUNT, SOURCE_AUTH_PROFILE_ID, SIGNATURE_PROFILE_VERSION, VERIFIER_PROFILE_VERSION, self._source_key_epoch, "MALFORMED", str(error), None, _origin=_VERIFIER_TOKEN)
            try:
                from pqcrypto.sign import ml_dsa_65

                accepted = bool(ml_dsa_65.verify(self._public_key, signature_message(batch), signature))
            except BaseException:
                accepted = False
            return AuthoritativeAssertionResultV1(accepted, batch.batch_root, MEMBER_COUNT, SOURCE_AUTH_PROFILE_ID, SIGNATURE_PROFILE_VERSION, VERIFIER_PROFILE_VERSION, self._source_key_epoch, "ACCEPTED" if accepted else "SIGNATURE_INVALID", None if accepted else "signature_invalid", None, _origin=_VERIFIER_TOKEN)
        finally:
            if handoff is not None:
                handoff.close()


__all__ = (
    "AuthoritativeAssertionError", "AuthoritativeAssertionResultV1", "AuthoritativeAssertionTemplateV1",
    "AuthoritativeAssertionVerifierV1", "AuthoritativeBatchStatementV1", "AuthoritativeIssuedOperationV1", "AuthoritativeReservation",
    "LIFETIME_ACCEPTANCE_CAP", "MAX_VALIDITY_WINDOW_MS", "MEMBER_COUNT", "MODE", "PUBLIC_KEY_SIZE", "QUALIFICATION_FLAGS",
    "RECEIPT_LIMIT_BYTES", "RESERVATION_UNITS", "SECRET_KEY_SIZE", "SIGNATURE_PROFILE_VERSION",
    "SIGNATURE_SIZE", "SOURCE_AUTH_PROFILE_ID", "VERIFIER_PROFILE_VERSION", "VolatileSignatureHandoff",
    "compute_batch_root", "parse_result", "signature_message",
)
