"""Typed adapter for the byte-pinned Profile12 Queue lifecycle executable.

The caller owns the Queue runtime lock, SQLite transaction, clock sample,
handoff custody, SQL mutation, and commit. This module only reconstructs the
selected batch from the caller's active connection, invokes one bounded
sidecar process, and validates its typed result. For successful
``submitHandoff`` and ``claimNextBatch`` operations, the decoded Lean
after-state and event are the transition decision returned to the Queue caller;
this module does not create a Python host plan for either edge.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
import struct
from pathlib import Path
from typing import Any, Final, Literal, Mapping

from app.minimal_clearance_verification_queue_independent import (
    _SCHEMA as _QUEUE_EVENT_SCHEMA,
    IndependentQueueError,
    SCHEMA_VERSION as _QUEUE_SCHEMA_VERSION,
    lifecycle_snapshot_from_connection,
)
from app.minimal_clearance_verifier_process import (
    VerifierProcessError,
    run_contained_verifier_stream,
)

LifecycleOperation = Literal["submitHandoff", "claimNextBatch"]

INPUT_MAGIC = b"BLQLIN01"
OUTPUT_MAGIC = b"BLQLOU01"
WIRE_VERSION = 1
MAX_FRAME_BYTES = 16_384
MAX_RESPONSE_BYTES = 32_768
MAX_STRING_BYTES = 96
MAX_FLAGS_BYTES = 4_096
MAX_EVENT_BYTES = 2_048
# Mirrors the protected Queue's LEAN_ADMISSION_TIMEOUT_SECONDS authority.
MAX_ADMISSION_TIMEOUT_SECONDS = 3.0
NAT_MAX = (1 << 64) - 1

_LIFECYCLE_EXECUTABLE_PATH: Final[Path] = (
    Path(__file__).resolve().parents[1]
    / "semantic_kernel"
    / "rust"
    / "target"
    / "x86_64-pc-windows-gnu"
    / "release"
    / "lifecycle.exe"
)
_LIFECYCLE_EXECUTABLE_SIZE_BYTES: Final[int] = 6_571_008
_LIFECYCLE_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881"
)
# The fixed old pin remains available only through this explicit nonqualifying mode.
_LIFECYCLE_RUNTIME_MODE: Final[Literal["legacy-pinned-v2", "source-bound-v1"]] = "legacy-pinned-v2"
_LIFECYCLE_LEGACY_EXECUTABLE_SIZE_BYTES: Final[int] = 6_571_008
_LIFECYCLE_LEGACY_EXECUTABLE_SHA256: Final[bytes] = bytes.fromhex(
    "B28081DA085DC3E5170ED1CB34F13AA3C32F4B0614CF6D699025FA18FD1DD881"
)
# No reviewed executable currently matches the updated source/link manifest.
# Keep this unset until a separate replacement executable and its manifest are reviewed together.
_LIFECYCLE_SOURCE_MANIFEST_SHA256: Final[str | None] = None
_LIFECYCLE_PROVENANCE_MAX_BYTES: Final[int] = 256
_LIFECYCLE_PROVENANCE_PREFIX: Final[str] = "BL-LIFECYCLE-PROVENANCE/1"

_BATCH_CODES = {
    "awaiting": 0,
    "queued": 1,
    "leased": 2,
    "verified": 3,
    "rejected": 4,
    "held": 5,
}
_SOURCE_CODES = {
    "absent": 0,
    "authorized": 1,
    "started": 2,
    "completed": 3,
    "unknown": 4,
}
_VERIFIER_CODES = {"unreserved": 0, "started": 1, "completed": 2, "unknown": 3}
_TERMINAL_CODES = {"none": 0, "accepted": 1, "rejected": 2, "aborted": 3, "unknown": 4}
_ATTEMPT_CODES = {"reserved": 0, "accepted": 1, "rejected": 2, "held": 3}
_EVENT_KIND_CODES = {"batchIssued": 1, "handoffSubmitted": 2, "verificationStarted": 3}
_EVENT_STATUS_CODES = {"awaitingHandoff": 0, "queued": 1, "leased": 2, "held": 3}


class LifecycleAdapterError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class LifecycleCounter:
    used: int
    cap: int


@dataclass(frozen=True, slots=True)
class LifecycleAccounting:
    proof: LifecycleCounter
    source_a: LifecycleCounter
    source_s: LifecycleCounter
    source_m: LifecycleCounter
    source_u: LifecycleCounter
    verifier_v: LifecycleCounter


@dataclass(frozen=True, slots=True)
class LifecycleConfig:
    schema_version: int
    profile_epoch: int
    profile_token: str
    source_auth_profile: str
    composition_version: int
    source_key_epoch: int
    admission_timeout_ms: int
    lease_duration_ms: int
    queue_id: str
    config_digest: bytes


@dataclass(frozen=True, slots=True)
class LifecycleIdentity:
    batch_id: bytes
    batch_root: bytes
    session_ref: bytes
    public_coin: bytes
    proof_context: bytes
    identity_digest: bytes
    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    approved_source_registry_root: bytes | None
    qualification_flags: bytes
    member_count: int
    admission_seq: int


@dataclass(frozen=True, slots=True)
class LifecycleState:
    config: LifecycleConfig
    identity: LifecycleIdentity
    batch: str
    source: str
    verifier: str
    terminal: str
    valid_from_ms: int
    valid_until_ms: int
    next_eligible_ms: int
    updated_ms: int
    attempt: int
    attempt_id: int
    attempt_status: str
    verifier_v_upper: int
    global_live_lease_count: int
    live_lease_count: int
    lease_expires_ms: int
    claim_sequence: int
    transition_sequence: int
    reservation_before: int
    reservation_after: int
    proof_attempts_per_batch: int
    attempt_source_key_epoch: int
    handoff_attached: bool
    accounting: LifecycleAccounting


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    schema_version: int
    sequence: int
    kind: str
    batch_id: bytes
    status: str
    error_code: str | None
    attempt: int
    at_ms: int
    member_count: int
    receipt_id: bytes | None = None
    identity_digest: bytes | None = None
    reservation_before: int | None = None
    reservation_after: int | None = None


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    before: LifecycleState
    after: LifecycleState
    event: LifecycleEvent


def _fail(code: str) -> None:
    raise LifecycleAdapterError(code)


def _parse_lifecycle_provenance(stderr: bytes) -> tuple[str, int, bytes]:
    if type(stderr) is not bytes or not 0 < len(stderr) <= _LIFECYCLE_PROVENANCE_MAX_BYTES:
        _fail("lifecycle_provenance_protocol")
    try:
        line = stderr.decode("ascii")
    except UnicodeDecodeError:
        _fail("lifecycle_provenance_protocol")
    if not line.endswith("\n") or line.count("\n") != 1 or "\r" in line:
        _fail("lifecycle_provenance_protocol")
    fields = line[:-1].split(";")
    if len(fields) != 4 or fields[0] != _LIFECYCLE_PROVENANCE_PREFIX:
        _fail("lifecycle_provenance_protocol")
    expected_keys = ("manifest_sha256", "exe_size", "exe_sha256")
    values: list[str] = []
    for field, expected_key in zip(fields[1:], expected_keys, strict=True):
        key, separator, value = field.partition("=")
        if separator != "=" or key != expected_key or not value:
            _fail("lifecycle_provenance_protocol")
        values.append(value)
    manifest_sha256, executable_size_text, executable_sha256 = values
    if (
        len(manifest_sha256) != 64
        or any(character not in "0123456789abcdef" for character in manifest_sha256)
        or len(executable_sha256) != 64
        or any(character not in "0123456789abcdef" for character in executable_sha256)
    ):
        _fail("lifecycle_provenance_protocol")
    if (
        not executable_size_text.isascii()
        or not executable_size_text.isdecimal()
        or str(int(executable_size_text)) != executable_size_text
    ):
        _fail("lifecycle_provenance_protocol")
    executable_size = int(executable_size_text)
    if not 0 < executable_size <= NAT_MAX:
        _fail("lifecycle_provenance_protocol")
    return manifest_sha256, executable_size, bytes.fromhex(executable_sha256)


def _verify_lifecycle_provenance(stderr: bytes) -> None:
    manifest_sha256, executable_size, executable_sha256 = _parse_lifecycle_provenance(stderr)
    if (
        executable_size != _LIFECYCLE_EXECUTABLE_SIZE_BYTES
        or executable_sha256 != _LIFECYCLE_EXECUTABLE_SHA256
    ):
        _fail("lifecycle_provenance_executable")
    expected_manifest = _LIFECYCLE_SOURCE_MANIFEST_SHA256
    if expected_manifest is None:
        _fail("lifecycle_provenance_unreviewed")
    if (
        len(expected_manifest) != 64
        or any(character not in "0123456789abcdef" for character in expected_manifest)
        or manifest_sha256 != expected_manifest
    ):
        _fail("lifecycle_provenance_manifest")


def _verify_lifecycle_runtime_mode(stderr: bytes) -> None:
    if _LIFECYCLE_RUNTIME_MODE == "legacy-pinned-v2":
        if (
            _LIFECYCLE_SOURCE_MANIFEST_SHA256 is not None
            or _LIFECYCLE_EXECUTABLE_SIZE_BYTES != _LIFECYCLE_LEGACY_EXECUTABLE_SIZE_BYTES
            or _LIFECYCLE_EXECUTABLE_SHA256 != _LIFECYCLE_LEGACY_EXECUTABLE_SHA256
        ):
            _fail("lifecycle_legacy_mode_configuration")
        if type(stderr) is not bytes or stderr != b"":
            _fail("lifecycle_legacy_stderr")
        return
    if _LIFECYCLE_RUNTIME_MODE == "source-bound-v1":
        _verify_lifecycle_provenance(stderr)
        return
    _fail("lifecycle_provenance_mode")


def _nat(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= NAT_MAX:
        _fail(f"lifecycle_{name}")
    return value


def _blob(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        _fail(f"lifecycle_{name}")
    return value


def _ascii(value: object, name: str, *, allow_empty: bool = False) -> bytes:
    if type(value) is not str or (not allow_empty and not value):
        _fail(f"lifecycle_{name}")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _fail(f"lifecycle_{name}")
    if len(encoded) > MAX_STRING_BYTES:
        _fail(f"lifecycle_{name}")
    return encoded


def _pack_u64(value: object, name: str) -> bytes:
    return struct.pack("<Q", _nat(value, name))


def _pack_string(value: object, name: str, *, allow_empty: bool = False) -> bytes:
    encoded = _ascii(value, name, allow_empty=allow_empty)
    return bytes((len(encoded),)) + encoded


def _pack_option_fixed(value: bytes | None, length: int, name: str) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + _blob(value, length, name)


def _encode_counter(value: LifecycleCounter, name: str) -> bytes:
    return _pack_u64(value.used, f"{name}_used") + _pack_u64(value.cap, f"{name}_cap")


def _encode_state(state: LifecycleState) -> bytes:
    if type(state) is not LifecycleState:
        _fail("lifecycle_state_type")
    config = state.config
    identity = state.identity
    if type(config) is not LifecycleConfig or type(identity) is not LifecycleIdentity:
        _fail("lifecycle_state_shape")
    try:
        batch_code = _BATCH_CODES[state.batch]
        source_code = _SOURCE_CODES[state.source]
        verifier_code = _VERIFIER_CODES[state.verifier]
        terminal_code = _TERMINAL_CODES[state.terminal]
        attempt_code = _ATTEMPT_CODES[state.attempt_status]
    except (KeyError, TypeError):
        _fail("lifecycle_state_enum")
    if type(state.handoff_attached) is not bool:
        _fail("lifecycle_handoff_flag")
    flags = identity.qualification_flags
    if type(flags) is not bytes or not 0 < len(flags) <= MAX_FLAGS_BYTES:
        _fail("lifecycle_flags")

    result = bytearray()
    result.extend(_pack_u64(config.schema_version, "schema"))
    result.extend(_pack_u64(config.profile_epoch, "profile_epoch"))
    result.extend(_pack_string(config.profile_token, "profile_token"))
    result.extend(_pack_string(config.source_auth_profile, "source_auth_profile"))
    result.extend(_pack_u64(config.composition_version, "composition_version"))
    result.extend(_pack_u64(config.source_key_epoch, "source_key_epoch"))
    result.extend(_pack_u64(config.admission_timeout_ms, "admission_timeout"))
    result.extend(_pack_u64(config.lease_duration_ms, "lease_duration"))
    result.extend(_pack_string(config.queue_id, "queue_id"))
    result.extend(_blob(config.config_digest, 64, "config_digest"))

    result.extend(_blob(identity.batch_id, 32, "batch_id"))
    result.extend(_blob(identity.batch_root, 64, "batch_root"))
    result.extend(_blob(identity.session_ref, 64, "session_ref"))
    result.extend(_blob(identity.public_coin, 96, "public_coin"))
    result.extend(_blob(identity.proof_context, 64, "proof_context"))
    result.extend(_blob(identity.identity_digest, 64, "identity_digest"))
    result.extend(_pack_string(identity.assertion_identifier, "assertion_identifier"))
    result.extend(_pack_u64(identity.assertion_version, "assertion_version"))
    result.extend(_pack_string(identity.state_profile_version, "state_profile_version"))
    result.extend(_pack_option_fixed(identity.approved_source_registry_root, 64, "registry_root"))
    result.extend(struct.pack("<H", len(flags)))
    result.extend(flags)
    result.extend(_pack_u64(identity.member_count, "member_count"))
    result.extend(_pack_u64(identity.admission_seq, "admission_seq"))

    result.extend((batch_code, source_code, verifier_code, terminal_code))
    for name, value in (
        ("valid_from", state.valid_from_ms),
        ("valid_until", state.valid_until_ms),
        ("next_eligible", state.next_eligible_ms),
        ("updated", state.updated_ms),
        ("attempt", state.attempt),
        ("attempt_id", state.attempt_id),
    ):
        result.extend(_pack_u64(value, name))
    result.append(attempt_code)
    for name, value in (
        ("verifier_v_upper", state.verifier_v_upper),
        ("global_live_lease_count", state.global_live_lease_count),
        ("live_lease_count", state.live_lease_count),
        ("lease_expires", state.lease_expires_ms),
        ("claim_sequence", state.claim_sequence),
        ("transition_sequence", state.transition_sequence),
        ("reservation_before", state.reservation_before),
        ("reservation_after", state.reservation_after),
        ("proof_attempts_per_batch", state.proof_attempts_per_batch),
        ("attempt_source_key_epoch", state.attempt_source_key_epoch),
    ):
        result.extend(_pack_u64(value, name))
    result.append(1 if state.handoff_attached else 0)
    accounting = state.accounting
    if type(accounting) is not LifecycleAccounting:
        _fail("lifecycle_accounting")
    for name, counter in (
        ("proof", accounting.proof),
        ("source_a", accounting.source_a),
        ("source_s", accounting.source_s),
        ("source_m", accounting.source_m),
        ("source_u", accounting.source_u),
        ("verifier_v", accounting.verifier_v),
    ):
        if type(counter) is not LifecycleCounter:
            _fail("lifecycle_counter")
        result.extend(_encode_counter(counter, name))
    if len(result) + 18 > MAX_FRAME_BYTES:
        _fail("lifecycle_frame_bound")
    return bytes(result)


def _encode_request(operation: LifecycleOperation, now_ms: int, state: LifecycleState) -> bytes:
    if operation == "submitHandoff":
        op_code = 1
    elif operation == "claimNextBatch":
        op_code = 2
    else:
        _fail("lifecycle_operation")
    frame = INPUT_MAGIC + bytes((WIRE_VERSION, op_code)) + _pack_u64(now_ms, "now") + _encode_state(state)
    if len(frame) > MAX_FRAME_BYTES:
        _fail("lifecycle_frame_bound")
    return frame


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        if type(length) is not int or length < 0 or length > len(self.data) - self.offset:
            _fail("lifecycle_response_short")
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def ascii8(self, name: str, *, allow_empty: bool = False) -> str:
        length = self.u8()
        if length > MAX_STRING_BYTES:
            _fail(f"lifecycle_{name}")
        try:
            value = self.take(length).decode("ascii")
        except UnicodeDecodeError:
            _fail(f"lifecycle_{name}")
        if not allow_empty and not value:
            _fail(f"lifecycle_{name}")
        return value

    def option_fixed(self, length: int, name: str) -> bytes | None:
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.take(length)
        _fail(f"lifecycle_{name}_tag")

    def option_nat(self) -> int | None:
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.u64()
        _fail("lifecycle_option_nat_tag")

    def option_string(self) -> str | None:
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.ascii8("option_string", allow_empty=True)
        _fail("lifecycle_option_string_tag")

    def finish(self) -> None:
        if self.offset != len(self.data):
            _fail("lifecycle_response_trailing")


def _decode_counter(reader: _Reader) -> LifecycleCounter:
    return LifecycleCounter(reader.u64(), reader.u64())


def _decode_state(reader: _Reader) -> LifecycleState:
    config = LifecycleConfig(
        schema_version=reader.u64(),
        profile_epoch=reader.u64(),
        profile_token=reader.ascii8("profile_token"),
        source_auth_profile=reader.ascii8("source_auth_profile"),
        composition_version=reader.u64(),
        source_key_epoch=reader.u64(),
        admission_timeout_ms=reader.u64(),
        lease_duration_ms=reader.u64(),
        queue_id=reader.ascii8("queue_id"),
        config_digest=reader.take(64),
    )
    batch_id = reader.take(32)
    batch_root = reader.take(64)
    session_ref = reader.take(64)
    public_coin = reader.take(96)
    proof_context = reader.take(64)
    identity_digest = reader.take(64)
    assertion_identifier = reader.ascii8("assertion_identifier")
    assertion_version = reader.u64()
    state_profile_version = reader.ascii8("state_profile_version")
    approved_source_registry_root = reader.option_fixed(64, "registry_root")
    flags_length = reader.u16()
    if not 0 < flags_length <= MAX_FLAGS_BYTES:
        _fail("lifecycle_flags")
    qualification_flags = reader.take(flags_length)
    member_count = reader.u64()
    admission_seq = reader.u64()
    identity = LifecycleIdentity(
        batch_id=batch_id,
        batch_root=batch_root,
        session_ref=session_ref,
        public_coin=public_coin,
        proof_context=proof_context,
        identity_digest=identity_digest,
        assertion_identifier=assertion_identifier,
        assertion_version=assertion_version,
        state_profile_version=state_profile_version,
        approved_source_registry_root=approved_source_registry_root,
        qualification_flags=qualification_flags,
        member_count=member_count,
        admission_seq=admission_seq,
    )
    batch_code, source_code, verifier_code, terminal_code = reader.take(4)
    batch = next((name for name, code in _BATCH_CODES.items() if code == batch_code), None)
    source = next((name for name, code in _SOURCE_CODES.items() if code == source_code), None)
    verifier = next((name for name, code in _VERIFIER_CODES.items() if code == verifier_code), None)
    terminal = next((name for name, code in _TERMINAL_CODES.items() if code == terminal_code), None)
    if None in (batch, source, verifier, terminal):
        _fail("lifecycle_response_state_enum")
    times_and_attempt = [reader.u64() for _ in range(6)]
    attempt_status_code = reader.u8()
    attempt_status = next((name for name, code in _ATTEMPT_CODES.items() if code == attempt_status_code), None)
    if attempt_status is None:
        _fail("lifecycle_response_attempt_enum")
    rest = [reader.u64() for _ in range(10)]
    handoff_code = reader.u8()
    if handoff_code not in (0, 1):
        _fail("lifecycle_response_handoff")
    accounting = LifecycleAccounting(
        proof=_decode_counter(reader),
        source_a=_decode_counter(reader),
        source_s=_decode_counter(reader),
        source_m=_decode_counter(reader),
        source_u=_decode_counter(reader),
        verifier_v=_decode_counter(reader),
    )
    return LifecycleState(
        config=config,
        identity=identity,
        batch=batch,
        source=source,
        verifier=verifier,
        terminal=terminal,
        valid_from_ms=times_and_attempt[0],
        valid_until_ms=times_and_attempt[1],
        next_eligible_ms=times_and_attempt[2],
        updated_ms=times_and_attempt[3],
        attempt=times_and_attempt[4],
        attempt_id=times_and_attempt[5],
        attempt_status=attempt_status,
        verifier_v_upper=rest[0],
        global_live_lease_count=rest[1],
        live_lease_count=rest[2],
        lease_expires_ms=rest[3],
        claim_sequence=rest[4],
        transition_sequence=rest[5],
        reservation_before=rest[6],
        reservation_after=rest[7],
        proof_attempts_per_batch=rest[8],
        attempt_source_key_epoch=rest[9],
        handoff_attached=bool(handoff_code),
        accounting=accounting,
    )


def _decode_event(reader: _Reader) -> LifecycleEvent:
    schema_version = reader.u64()
    sequence = reader.u64()
    kind_code = reader.u8()
    kind = next((name for name, code in _EVENT_KIND_CODES.items() if code == kind_code), None)
    batch_id = reader.take(32)
    status_code = reader.u8()
    status = next((name for name, code in _EVENT_STATUS_CODES.items() if code == status_code), None)
    if kind is None or status is None:
        _fail("lifecycle_response_event_enum")
    error_code = reader.option_string()
    attempt = reader.u64()
    at_ms = reader.u64()
    member_count = reader.u64()
    receipt_id = reader.option_fixed(32, "receipt_id")
    identity_digest = reader.option_fixed(64, "identity_digest")
    reservation_before = reader.option_nat()
    reservation_after = reader.option_nat()
    return LifecycleEvent(
        schema_version=schema_version,
        sequence=sequence,
        kind=kind,
        batch_id=batch_id,
        status=status,
        error_code=error_code,
        attempt=attempt,
        at_ms=at_ms,
        member_count=member_count,
        receipt_id=receipt_id,
        identity_digest=identity_digest,
        reservation_before=reservation_before,
        reservation_after=reservation_after,
    )


def _queue_event_bytes(event: LifecycleEvent) -> bytes:
    kinds = {
        "batchIssued": "BATCH_ISSUED",
        "handoffSubmitted": "HANDOFF_SUBMITTED",
        "verificationStarted": "VERIFICATION_STARTED",
    }
    statuses = {
        "awaitingHandoff": "AWAITING_HANDOFF",
        "queued": "QUEUED",
        "leased": "LEASED",
        "held": "HELD",
    }
    if event.kind not in kinds or event.status not in statuses:
        _fail("lifecycle_event_enum")
    schema_version = _nat(event.schema_version, "event_schema")
    if schema_version != _QUEUE_SCHEMA_VERSION:
        _fail("lifecycle_event_schema")
    payload: dict[str, Any] = {
        "schema": _QUEUE_EVENT_SCHEMA,
        "sequence": _nat(event.sequence, "event_sequence"),
        "kind": kinds[event.kind],
        "batch_id": _blob(event.batch_id, 32, "event_batch_id").hex().upper(),
        "status": statuses[event.status],
        "error_code": event.error_code,
        "attempt": _nat(event.attempt, "event_attempt"),
        "at_ms": _nat(event.at_ms, "event_at_ms"),
        "member_count": _nat(event.member_count, "event_member_count"),
    }
    if event.receipt_id is not None:
        payload["receipt_id"] = _blob(event.receipt_id, 32, "event_receipt_id").hex().upper()
    if event.identity_digest is not None:
        payload["identity_digest"] = _blob(event.identity_digest, 64, "event_identity_digest").hex().upper()
    if event.reservation_before is not None:
        payload["reservation_before"] = _nat(event.reservation_before, "event_reservation_before")
    if event.reservation_after is not None:
        payload["reservation_after"] = _nat(event.reservation_after, "event_reservation_after")
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail("lifecycle_event_encoding")


def canonical_queue_event_bytes(event: LifecycleEvent) -> bytes:
    """Encode a typed lifecycle result event in the Queue's canonical JSON form."""

    if type(event) is not LifecycleEvent:
        _fail("lifecycle_event_type")
    return _queue_event_bytes(event)


def _validate_submit_result(
    before: LifecycleState,
    after: LifecycleState,
    event: LifecycleEvent,
    *,
    now_ms: int,
) -> None:
    """Check the result shape and preserved Queue fields without planning it."""

    if type(before) is not LifecycleState or type(after) is not LifecycleState:
        _fail("lifecycle_submit_state_type")
    if type(event) is not LifecycleEvent:
        _fail("lifecycle_submit_event_type")
    now_ms = _nat(now_ms, "now_ms")
    preserved_fields = (
        "config",
        "identity",
        "source",
        "verifier",
        "terminal",
        "valid_from_ms",
        "valid_until_ms",
        "attempt",
        "attempt_id",
        "attempt_status",
        "verifier_v_upper",
        "global_live_lease_count",
        "live_lease_count",
        "lease_expires_ms",
        "claim_sequence",
        "reservation_before",
        "reservation_after",
        "proof_attempts_per_batch",
        "attempt_source_key_epoch",
        "accounting",
    )
    if any(getattr(after, field) != getattr(before, field) for field in preserved_fields):
        _fail("lifecycle_submit_state_shape")
    if (
        after.batch != "queued"
        or after.next_eligible_ms != now_ms
        or after.updated_ms != now_ms
        or after.transition_sequence != before.transition_sequence + 1
        or after.handoff_attached is not True
    ):
        _fail("lifecycle_submit_state_shape")
    if (
        event.schema_version != before.config.schema_version
        or event.schema_version != _QUEUE_SCHEMA_VERSION
        or event.sequence != after.transition_sequence
        or event.kind != "handoffSubmitted"
        or event.batch_id != before.identity.batch_id
        or event.status != "queued"
        or event.error_code is not None
        or event.attempt != after.attempt
        or event.at_ms != after.updated_ms
        or event.member_count != before.identity.member_count
        or event.receipt_id is not None
        or event.identity_digest is not None
        or event.reservation_before is not None
        or event.reservation_after is not None
    ):
        _fail("lifecycle_submit_event_shape")
    _queue_event_bytes(event)


def _validate_claim_result(
    before: LifecycleState,
    after: LifecycleState,
    event: LifecycleEvent,
    *,
    now_ms: int,
) -> None:
    """Check the claim result shape and preserved fields without planning it."""

    if type(before) is not LifecycleState or type(after) is not LifecycleState:
        _fail("lifecycle_claim_state_type")
    if type(event) is not LifecycleEvent:
        _fail("lifecycle_claim_event_type")
    now_ms = _nat(now_ms, "now_ms")
    next_sequence = before.transition_sequence + 1
    lease_expires_ms = now_ms + before.config.lease_duration_ms
    if next_sequence > NAT_MAX or lease_expires_ms > NAT_MAX:
        _fail("lifecycle_claim_state_shape")
    preserved_fields = (
        "config",
        "identity",
        "source",
        "verifier",
        "terminal",
        "valid_from_ms",
        "valid_until_ms",
        "next_eligible_ms",
        "attempt_id",
        "attempt_status",
        "verifier_v_upper",
        "reservation_before",
        "reservation_after",
        "proof_attempts_per_batch",
        "attempt_source_key_epoch",
        "handoff_attached",
        "accounting",
    )
    if any(getattr(after, field) != getattr(before, field) for field in preserved_fields):
        _fail("lifecycle_claim_state_shape")
    if (
        after.batch != "leased"
        or after.updated_ms != now_ms
        or after.attempt != 1
        or after.global_live_lease_count != 1
        or after.live_lease_count != 1
        or after.lease_expires_ms != lease_expires_ms
        or after.claim_sequence != next_sequence
        or after.transition_sequence != next_sequence
    ):
        _fail("lifecycle_claim_state_shape")
    if (
        event.schema_version != before.config.schema_version
        or event.schema_version != _QUEUE_SCHEMA_VERSION
        or event.sequence != next_sequence
        or event.kind != "verificationStarted"
        or event.batch_id != before.identity.batch_id
        or event.status != "leased"
        or event.error_code is not None
        or event.attempt != 1
        or event.at_ms != now_ms
        or before.identity.member_count != 100
        or event.member_count != 100
        or event.receipt_id is not None
        or event.identity_digest is not None
        or event.reservation_before != before.reservation_before
        or event.reservation_after != before.reservation_after
    ):
        _fail("lifecycle_claim_event_shape")
    _queue_event_bytes(event)


def _decode_response(response: bytes, *, request: bytes) -> tuple[LifecycleState, LifecycleEvent]:
    if type(response) is not bytes or len(response) > MAX_RESPONSE_BYTES:
        _fail("lifecycle_response_bound")
    reader = _Reader(response)
    if reader.take(8) != OUTPUT_MAGIC or reader.u8() != WIRE_VERSION:
        _fail("lifecycle_response_magic")
    status = reader.u8()
    echo_length = reader.u16()
    echo = reader.take(echo_length)
    if status == 2:
        if echo_length != 0:
            _fail("lifecycle_malformed_echo")
        code = reader.u8()
        reader.finish()
        _fail("lifecycle_kernel_malformed" if code in (1, 2) else "lifecycle_response_error_code")
    if echo != request:
        _fail("lifecycle_input_binding")
    if status == 1:
        code = reader.u8()
        reader.finish()
        if code != 1:
            _fail("lifecycle_response_error_code")
        _fail("lifecycle_precondition_rejected")
    if status != 0:
        _fail("lifecycle_response_status")
    after = _decode_state(reader)
    event = _decode_event(reader)
    reader.finish()
    return after, event


def _terminal_from_result(result: tuple[Any, ...] | None) -> str:
    if result is None:
        return "none"
    if len(result) < 2 or type(result[1]) is not str:
        _fail("lifecycle_result_shape")
    mapping = {"VERIFIED": "accepted", "REJECTED": "rejected", "HELD": "aborted"}
    try:
        return mapping[result[1]]
    except KeyError:
        _fail("lifecycle_result_status")


def _state_from_snapshot(snapshot: Mapping[str, Any], *, handoff_attached: bool) -> LifecycleState:
    if type(handoff_attached) is not bool:
        _fail("lifecycle_handoff_flag")
    try:
        config_row = snapshot["config"]
        meta = snapshot["meta"]
        batch = snapshot["batch"]
        attempt = snapshot["attempt"]
        lease = snapshot["lease"]
        source = snapshot["source_admission"]
        composition_meta = snapshot["composition_meta"]
        members = snapshot["members"]
    except (KeyError, TypeError):
        _fail("lifecycle_snapshot_shape")
    if len(batch) != 19 or len(attempt) != 12 or (lease is not None and len(lease) != 7):
        _fail("lifecycle_snapshot_rows")
    if source is not None and len(source) != 18:
        _fail("lifecycle_source_row")
    if len(composition_meta) != 17:
        _fail("lifecycle_composition_meta")

    batch_statuses = {
        "AWAITING_HANDOFF": "awaiting",
        "QUEUED": "queued",
        "LEASED": "leased",
        "VERIFIED": "verified",
        "REJECTED": "rejected",
        "HELD": "held",
    }
    source_statuses = {
        "AUTHORIZED": "authorized",
        "STARTED": "started",
        "COMPLETED": "completed",
        "UNKNOWN": "unknown",
    }
    verifier_statuses = {
        "UNRESERVED": "unreserved",
        "STARTED": "started",
        "COMPLETED": "completed",
        "UNKNOWN": "unknown",
    }
    attempt_statuses = {
        "RESERVED": "reserved",
        "ACCEPTED": "accepted",
        "REJECTED": "rejected",
        "HELD": "held",
    }
    try:
        batch_phase = batch_statuses[batch[11]]
        source_phase = "absent" if source is None else source_statuses[source[17]]
        verifier_phase = verifier_statuses[attempt[10]]
        attempt_phase = attempt_statuses[attempt[6]]
    except (KeyError, TypeError):
        _fail("lifecycle_snapshot_enum")

    config = LifecycleConfig(
        schema_version=_nat(config_row["schema_version"], "schema"),
        profile_epoch=_nat(config_row["profile_epoch"], "profile_epoch"),
        profile_token=config_row["profile_version"],
        source_auth_profile=config_row["source_auth_profile"],
        composition_version=_nat(composition_meta[1], "composition_version"),
        source_key_epoch=_nat(config_row["source_key_epoch"], "source_key_epoch"),
        admission_timeout_ms=3_000,
        lease_duration_ms=60_000,
        queue_id=config_row["queue_id"],
        config_digest=_blob(snapshot["config_digest"], 64, "config_digest"),
    )
    identity = LifecycleIdentity(
        batch_id=_blob(batch[0], 32, "batch_id"),
        batch_root=_blob(batch[1], 64, "batch_root"),
        session_ref=_blob(batch[2], 64, "session_ref"),
        public_coin=_blob(batch[18], 96, "public_coin"),
        proof_context=_blob(snapshot["proof_context"], 64, "proof_context"),
        identity_digest=_blob(batch[10], 64, "identity_digest"),
        assertion_identifier=batch[3],
        assertion_version=_nat(batch[4], "assertion_version"),
        state_profile_version=batch[5],
        approved_source_registry_root=None if batch[8] is None else _blob(batch[8], 64, "registry_root"),
        qualification_flags=_blob_type(batch[9], "qualification_flags"),
        member_count=len(members),
        admission_seq=_nat(batch[12], "admission_seq"),
    )
    proof_cap = _nat(meta[18], "proof_cap")
    proof_used = _nat(meta[17], "proof_used")
    source_epoch = _blob(attempt[5], 8, "attempt_source_epoch")
    global_lease_count = _nat(meta[16], "global_lease_count")
    state = LifecycleState(
        config=config,
        identity=identity,
        batch=batch_phase,
        source=source_phase,
        verifier=verifier_phase,
        terminal=_terminal_from_result(snapshot["result"]),
        valid_from_ms=_nat(batch[6], "valid_from"),
        valid_until_ms=_nat(batch[7], "valid_until"),
        next_eligible_ms=_nat(batch[14], "next_eligible"),
        updated_ms=_nat(batch[16], "updated"),
        attempt=_nat(batch[13], "attempt"),
        attempt_id=_nat(attempt[0], "attempt_id"),
        attempt_status=attempt_phase,
        verifier_v_upper=_nat(attempt[11], "verifier_v_upper"),
        global_live_lease_count=global_lease_count,
        live_lease_count=0 if lease is None else 1,
        lease_expires_ms=0 if lease is None else _nat(lease[6], "lease_expires"),
        claim_sequence=0 if lease is None else _nat(lease[4], "claim_sequence"),
        transition_sequence=_nat(meta[13], "transition_sequence"),
        reservation_before=_nat(attempt[2], "reservation_before"),
        reservation_after=_nat(attempt[3], "reservation_after"),
        proof_attempts_per_batch=_nat(attempt[4], "proof_attempts_per_batch"),
        attempt_source_key_epoch=int.from_bytes(source_epoch, "big"),
        handoff_attached=handoff_attached,
        accounting=LifecycleAccounting(
            proof=LifecycleCounter(proof_used, proof_cap),
            source_a=LifecycleCounter(_nat(meta[20], "source_a_used"), proof_cap),
            source_s=LifecycleCounter(_nat(meta[21], "source_s_used"), proof_cap),
            source_m=LifecycleCounter(_nat(meta[22], "source_m_used"), proof_cap),
            source_u=LifecycleCounter(_nat(meta[23], "source_u_used"), proof_cap),
            verifier_v=LifecycleCounter(_nat(meta[24], "verifier_v_used"), proof_cap),
        ),
    )
    return state


def _blob_type(value: object, name: str) -> bytes:
    if type(value) is not bytes or not 0 < len(value) <= MAX_FLAGS_BYTES:
        _fail(f"lifecycle_{name}")
    return value


def reconstruct_lifecycle_state(
    connection: sqlite3.Connection,
    *,
    batch_id: bytes,
    handoff_attached: bool,
    expected_config: Mapping[str, Any] | None = None,
) -> LifecycleState:
    """Read a validated selected-batch state from the caller's active transaction."""

    if not isinstance(expected_config, Mapping):
        _fail("lifecycle_expected_config")
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        _fail("lifecycle_transaction_required")
    changes_before = connection.total_changes
    try:
        snapshot = lifecycle_snapshot_from_connection(
            connection,
            batch_id=batch_id,
            expected_config=expected_config,
        )
    except IndependentQueueError as error:
        _fail(f"lifecycle_snapshot:{error}")
    if not connection.in_transaction or connection.total_changes != changes_before:
        _fail("lifecycle_connection_mutated")
    return _state_from_snapshot(snapshot, handoff_attached=handoff_attached)


def _run_lifecycle_frame(
    frame: bytes,
    *,
    workspace: Path,
    timeout_seconds: float,
) -> bytes:
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME_BYTES:
        _fail("lifecycle_frame_bound")
    if (
        type(timeout_seconds) is not float
        or not 0 < timeout_seconds <= MAX_ADMISSION_TIMEOUT_SECONDS
    ):
        _fail("lifecycle_timeout")
    try:
        result = run_contained_verifier_stream(
            _LIFECYCLE_EXECUTABLE_PATH,
            (),
            frame,
            workspace=workspace,
            timeout_seconds=timeout_seconds,
            stdout_cap_bytes=MAX_RESPONSE_BYTES,
            stderr_cap_bytes=16_384,
            stdout_ascii=False,
            stderr_ascii=True,
            expected_input_bytes=len(frame),
            expected_executable_size_bytes=_LIFECYCLE_EXECUTABLE_SIZE_BYTES,
            expected_executable_sha256=_LIFECYCLE_EXECUTABLE_SHA256,
        )
    except VerifierProcessError as error:
        _fail(f"lifecycle_process:{error}")
    if result.exit_code != 0 or result.timed_out or not result.cap_enforced or result.active_process_limit != 1:
        _fail("lifecycle_process_result")
    _verify_lifecycle_runtime_mode(result.stderr)
    if type(result.stdout) is not bytes or len(result.stdout) > MAX_RESPONSE_BYTES:
        _fail("lifecycle_response_bound")
    return result.stdout


def evaluate_lifecycle_transition(
    connection: sqlite3.Connection,
    *,
    batch_id: bytes,
    operation: LifecycleOperation,
    now_ms: int,
    handoff_attached: bool,
    workspace: Path,
    expected_config: Mapping[str, Any] | None = None,
    timeout_seconds: float = MAX_ADMISSION_TIMEOUT_SECONDS,
) -> LifecycleTransition:
    """Evaluate one lifecycle transition without taking custody or changing SQLite.

    The caller must hold the existing Queue owner lock and use its intended
    transaction snapshot. The exact Queue-owned clock sample and volatile
    handoff observation are inputs. For both operations, the executable's
    decoded after-state and event are returned after structural, preservation,
    and wire checks; no Python success plan is derived. This function never
    opens/closes the connection or commits/rolls back.
    """

    if not isinstance(expected_config, Mapping):
        _fail("lifecycle_expected_config")
    if (
        type(timeout_seconds) is not float
        or not 0 < timeout_seconds <= MAX_ADMISSION_TIMEOUT_SECONDS
    ):
        _fail("lifecycle_timeout")
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        _fail("lifecycle_transaction_required")
    changes_before = connection.total_changes
    before = reconstruct_lifecycle_state(
        connection,
        batch_id=batch_id,
        handoff_attached=handoff_attached,
        expected_config=expected_config,
    )
    if not connection.in_transaction or connection.total_changes != changes_before:
        _fail("lifecycle_connection_mutated")
    if operation not in ("submitHandoff", "claimNextBatch"):
        _fail("lifecycle_operation")
    frame = _encode_request(operation, now_ms, before)
    response = _run_lifecycle_frame(
        frame,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
    )
    if not connection.in_transaction or connection.total_changes != changes_before:
        _fail("lifecycle_connection_mutated")
    after, event = _decode_response(response, request=frame)
    if operation == "submitHandoff":
        _validate_submit_result(before, after, event, now_ms=now_ms)
    else:
        _validate_claim_result(before, after, event, now_ms=now_ms)
    return LifecycleTransition(before=before, after=after, event=event)


__all__ = (
    "LifecycleAccounting",
    "LifecycleAdapterError",
    "LifecycleConfig",
    "LifecycleCounter",
    "LifecycleEvent",
    "LifecycleIdentity",
    "LifecycleOperation",
    "LifecycleState",
    "LifecycleTransition",
    "canonical_queue_event_bytes",
    "evaluate_lifecycle_transition",
    "reconstruct_lifecycle_state",
)
