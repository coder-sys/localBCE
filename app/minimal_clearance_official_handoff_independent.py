"""Independent reconstruction for the synthetic official-directive outbox.

This module deliberately does not import the producer outbox.  It parses the
canonical envelope/ack grammar, reconstructs the SQLite chain, and performs
the read-only application/state admission checks used by discovery and
dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Final, Mapping

from app.minimal_clearance_acceptance_independent import parse_acceptance_bytes
from app.minimal_clearance_queue_application_independent import (
    IndependentQueueApplicationError,
    verify_database_connection,
    verify_database as verify_application_database,
)


def _private_zk_identity(label: str) -> bytes:
    digest = hashlib.sha3_512(b"BL/NATIVE-V3/PRIVATE-ZK/IDENTITY/v1\x00")
    digest.update(label.encode("ascii"))
    return digest.digest()


PRIVATE_ZK_DATABASE_CONTEXT_ID = _private_zk_identity("database-context.v1")
PRIVATE_ZK_DATABASE_SCHEMA_ID = _private_zk_identity("database-schema.v1")
PRIVATE_ZK_DATABASE_PROGRAM_ID = _private_zk_identity("database-program.v1")
PRIVATE_ZK_MODE_ID = _private_zk_identity("mode.PRIVATE_ZK.v1")
PRIVATE_ZK_INITIAL_PAYMENT_ROOT = _private_zk_identity("payment-genesis.v1")
_ZERO_SUITE = bytes(64)
_PROFILE = b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v1\x00"


class IndependentOfficialHandoffError(RuntimeError):
    """Fail-closed independent reconstruction error."""


_SCHEMA: Final[str] = "BL/NATIVE-V3/MINIMAL-CLEARANCE-OFFICIAL-HANDOFF/v1"
_SCHEMA_VERSION: Final[int] = 1
_STATUS: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "ACKNOWLEDGED", "HELD", "DELIVERY_UNCONFIRMED"})
_MAX_ENVELOPE: Final[int] = 16 * 1024
_MAX_ACK: Final[int] = 4096
_MAX_EXPORT: Final[int] = 8 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_MATERIAL = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/MATERIAL/v1\x00"
_GENESIS = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/GENESIS/v1\x00"
_HEAD = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/HEAD/v1\x00"
_EVENT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-HANDOFF/EVENT/v1\x00"
_ENVELOPE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ENVELOPE/v1\x00"
_IDEMPOTENCY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-IDEMPOTENCY/v1\x00"
_OPERATION = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-OPERATION/v1\x00"
_ACK = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK/v1\x00"
_ACK_PROFILE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-PROFILE/v1\x00"
_ACK_RECEIPT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-ACK-RECEIPT/v1\x00"
_RESULT = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/OFFICIAL-DIRECTIVE-RESULT/v1\x00"
_STATE_IDENTITY = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/STATE-STORE-IDENTITY/v1\x00"
_CAP_BYTES: Final[int] = 5_000_000_000
_FIXED_ID_BYTES: Final[int] = 128
_ACK_EVIDENCE_MODE: Final[str] = "SYNTHETIC_ONLY"
_ACK_PROFILE_VERSION: Final[int] = 1
_RECONCILIATION_STATUS: Final[frozenset[str]] = frozenset({"DISCOVERED", "LEASED", "EXHAUSTED", "ACKNOWLEDGED"})


def _private_zk_profile_digest(statement: Any, verifier_sha256: bytes) -> bytes:
    return _sha(
        _PROFILE,
        PRIVATE_ZK_MODE_ID,
        PRIVATE_ZK_DATABASE_CONTEXT_ID,
        PRIVATE_ZK_DATABASE_SCHEMA_ID,
        PRIVATE_ZK_DATABASE_PROGRAM_ID,
        bytes(statement.get("execution_context")),
        bytes(statement.get("evaluator_id")),
        bytes(statement.get("schema_id")),
        bytes(statement.get("program_id")),
        bytes(statement.get("automatic_control_set")),
        bytes.fromhex("1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0"),
        verifier_sha256,
        _ZERO_SUITE,
        (7).to_bytes(8, "big"),
    )

_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset({
    "schema", "handoff_config_digest", "receiver_identity", "receiver_epoch", "application_id_digest", "application_config_digest", "application_job_id_digest",
    "application_operation_id", "application_result_digest", "state_store_identity", "state_receipt_digest",
    "request_id", "attempt_id", "decision_id", "receipt_id", "state_after_id", "state_binding_after",
    "audit_head_after", "policy_result", "effective_directive", "proof_session_accepted",
    "proof_acceptance_is_clear", "payment_root_unchanged", "settled_batch_count_unchanged", "verifier_epoch",
    "ack_evidence_profile_digest",
    "economic_mutation", "proof_suite_id",
})
_ACK_KEYS: Final[frozenset[str]] = frozenset({
    "schema", "receiver_identity", "receiver_epoch", "idempotency_key", "envelope_digest",
    "effective_directive", "accepted_ms", "acknowledgment_id",
})
_ACK_KEYS_WITH_POLICY: Final[frozenset[str]] = frozenset(set(_ACK_KEYS) | {"policy_result"})
_ACK_PROFILE_KEYS: Final[frozenset[str]] = frozenset({
    "schema_version", "mode", "verifier_identity", "verifier_epoch", "receiver_identity",
    "receiver_epoch", "proof_suite_id", "production_usable", "activation",
})
_ACK_RECEIPT_KEYS: Final[frozenset[str]] = frozenset({
    "schema_version", "mode", "profile_digest", "verifier_identity", "verifier_epoch",
    "receiver_identity", "receiver_epoch", "operation_id", "job_id_digest", "idempotency_key",
    "envelope_digest", "ack_digest", "acknowledgment_id", "policy_result", "effective_directive",
    "proof_suite_id", "production_usable", "activation",
})


def _fail(code: str) -> None:
    raise IndependentOfficialHandoffError(code)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail("binding_type")
        digest.update(part)
    return digest.digest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IndependentOfficialHandoffError("json") from exc


def _hex(value: bytes) -> str:
    return value.hex().upper()


def _blob(value: Any, size: int, label: str) -> bytes:
    if type(value) is not str:
        _fail(label)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentOfficialHandoffError(label) from exc
    if size is not None and len(raw) != size:
        _fail(label)
    return raw


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(label)
    return value


def _token(value: Any, label: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(label)
    return value


def _fixed_ascii(value: str, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentOfficialHandoffError(label + "_ascii") from exc
    if len(encoded) > _FIXED_ID_BYTES:
        _fail(label + "_width")
    return len(encoded).to_bytes(2, "big") + encoded + b"\x00" * (_FIXED_ID_BYTES - len(encoded))


def _operation_identity(config: Mapping[str, Any], job_id: str, envelope_digest_value: bytes, config_digest: bytes) -> bytes:
    return _sha(
        _OPERATION, config_digest, _fixed_ascii(config["application_id"], "application_id"),
        _fixed_ascii(job_id, "job_id"), envelope_digest_value,
    )


def _idempotency_key(config: Mapping[str, Any], job_id: str, envelope_digest_value: bytes, config_digest: bytes) -> bytes:
    return _sha(
        _IDEMPOTENCY, config_digest, _fixed_ascii(config["outbox_id"], "outbox_id"),
        _fixed_ascii(job_id, "job_id"), envelope_digest_value,
    )


def acknowledgment_profile_digest(
    *, verifier_identity: bytes, verifier_epoch: int, receiver_identity: bytes, receiver_epoch: int,
) -> bytes:
    """Return the verifier-owned, synthetic-only acknowledgment profile identity."""
    if type(verifier_identity) is not bytes or len(verifier_identity) != 32:
        _fail("profile_verifier_identity")
    if type(verifier_epoch) is not int or verifier_epoch < 1:
        _fail("profile_verifier_epoch")
    if type(receiver_identity) is not bytes or len(receiver_identity) != 32:
        _fail("profile_receiver_identity")
    if type(receiver_epoch) is not int or receiver_epoch < 1:
        _fail("profile_receiver_epoch")
    value = {
        "schema_version": _ACK_PROFILE_VERSION,
        "mode": _ACK_EVIDENCE_MODE,
        "verifier_identity": _hex(verifier_identity),
        "verifier_epoch": verifier_epoch,
        "receiver_identity": _hex(receiver_identity),
        "receiver_epoch": receiver_epoch,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
    }
    return _sha(_ACK_PROFILE, _json_bytes(value))


def acknowledgment_profile_bytes(
    *, verifier_identity: bytes, verifier_epoch: int, receiver_identity: bytes, receiver_epoch: int,
) -> bytes:
    """Return canonical profile bytes; callers cannot select another mode."""
    if type(verifier_identity) is not bytes or len(verifier_identity) != 32:
        _fail("profile_verifier_identity")
    if type(verifier_epoch) is not int or verifier_epoch < 1:
        _fail("profile_verifier_epoch")
    if type(receiver_identity) is not bytes or len(receiver_identity) != 32:
        _fail("profile_receiver_identity")
    if type(receiver_epoch) is not int or receiver_epoch < 1:
        _fail("profile_receiver_epoch")
    value = {
        "schema_version": _ACK_PROFILE_VERSION,
        "mode": _ACK_EVIDENCE_MODE,
        "verifier_identity": _hex(verifier_identity),
        "verifier_epoch": verifier_epoch,
        "receiver_identity": _hex(receiver_identity),
        "receiver_epoch": receiver_epoch,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
    }
    return _json_bytes(value)


def build_ack_qualification_receipt(
    *, profile_digest: bytes, verifier_identity: bytes, verifier_epoch: int,
    receiver_identity: bytes, receiver_epoch: int, operation_id: bytes, job_id: str,
    idempotency_key: bytes, envelope_digest_value: bytes, ack_digest: bytes,
    acknowledgment_id: str, policy_result: int, effective_directive: int,
) -> bytes:
    """Build the bounded, support-safe receipt retained for a qualified ack."""
    for raw, size, label in (
        (profile_digest, 64, "receipt_profile"), (verifier_identity, 32, "receipt_verifier"),
        (receiver_identity, 32, "receipt_receiver"), (operation_id, 64, "receipt_operation"),
        (idempotency_key, 64, "receipt_idempotency"), (envelope_digest_value, 64, "receipt_envelope"),
        (ack_digest, 64, "receipt_ack_digest"),
    ):
        _blob(_hex(raw), size, label)
    _integer(verifier_epoch, "receipt_verifier_epoch", 1)
    _integer(receiver_epoch, "receipt_receiver_epoch", 1)
    _integer(policy_result, "receipt_policy_result", 1)
    _integer(effective_directive, "receipt_directive", 1)
    if policy_result > 5 or effective_directive > 5 or not _TOKEN.fullmatch(acknowledgment_id):
        _fail("receipt_value")
    value = {
        "schema_version": _ACK_PROFILE_VERSION, "mode": _ACK_EVIDENCE_MODE,
        "profile_digest": _hex(profile_digest), "verifier_identity": _hex(verifier_identity),
        "verifier_epoch": verifier_epoch, "receiver_identity": _hex(receiver_identity),
        "receiver_epoch": receiver_epoch, "operation_id": _hex(operation_id),
        "job_id_digest": _hex(_sha(_ACK_RECEIPT, job_id.encode("ascii"))),
        "idempotency_key": _hex(idempotency_key), "envelope_digest": _hex(envelope_digest_value),
        "ack_digest": _hex(ack_digest), "acknowledgment_id": acknowledgment_id,
        "policy_result": policy_result, "effective_directive": effective_directive,
        "proof_suite_id": None, "production_usable": False, "activation": False,
    }
    return _json_bytes(value)


def parse_ack_qualification_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        _fail("receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("receipt_encoding") from exc
    if type(value) is not dict or set(value) != _ACK_RECEIPT_KEYS or raw != _json_bytes(value):
        _fail("receipt_canonical")
    if value["schema_version"] != _ACK_PROFILE_VERSION or value["mode"] != _ACK_EVIDENCE_MODE:
        _fail("receipt_profile")
    for name, size in (("profile_digest", 64), ("verifier_identity", 32), ("receiver_identity", 32),
                       ("operation_id", 64), ("job_id_digest", 64), ("idempotency_key", 64),
                       ("envelope_digest", 64), ("ack_digest", 64)):
        _blob(value[name], size, "receipt_" + name)
    _integer(value["verifier_epoch"], "receipt_verifier_epoch", 1)
    _integer(value["receiver_epoch"], "receipt_receiver_epoch", 1)
    _token(value["acknowledgment_id"], "receipt_ack_id")
    for name in ("policy_result", "effective_directive"):
        _integer(value[name], "receipt_" + name, 1)
        if value[name] > 5:
            _fail("receipt_directive")
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("receipt_nonactivation")
    return value


def parse_envelope_bytes(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ENVELOPE:
        _fail("envelope_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("envelope_encoding") from exc
    if type(value) is not dict or set(value) != _ENVELOPE_KEYS or raw != _json_bytes(value):
        _fail("envelope_canonical")
    if value["schema"] != _SCHEMA:
        _fail("envelope_schema")
    _blob(value["handoff_config_digest"], 64, "envelope_handoff_config")
    _blob(value["receiver_identity"], 32, "envelope_receiver")
    _integer(value["receiver_epoch"], "envelope_receiver_epoch", 1)
    _integer(value["verifier_epoch"], "envelope_verifier_epoch", 1)
    _blob(value["ack_evidence_profile_digest"], 64, "envelope_profile")
    for name in (
        "application_id_digest", "application_config_digest", "application_job_id_digest",
        "application_operation_id", "application_result_digest", "state_store_identity",
        "state_receipt_digest", "request_id", "attempt_id", "decision_id", "receipt_id",
        "state_after_id", "state_binding_after", "audit_head_after",
    ):
        _blob(value[name], 64, "envelope_" + name)
    for name in ("policy_result", "effective_directive"):
        _integer(value[name], "envelope_" + name, 1)
        if value[name] > 5:
            _fail("envelope_directive")
    if (
        value["proof_session_accepted"] is not True
        or value["proof_acceptance_is_clear"] is not False
        or value["payment_root_unchanged"] is not True
        or value["settled_batch_count_unchanged"] is not True
        or value["economic_mutation"] is not False
        or value["proof_suite_id"] is not None
    ):
        _fail("envelope_nonactivation_or_economic")
    return value


def parse_acknowledgment_bytes(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_ACK:
        _fail("ack_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("ack_encoding") from exc
    if type(value) is not dict or set(value) not in {_ACK_KEYS, _ACK_KEYS_WITH_POLICY} or raw != _json_bytes(value):
        _fail("ack_canonical")
    if value["schema"] != _SCHEMA:
        _fail("ack_schema")
    _blob(value["receiver_identity"], 32, "ack_receiver")
    _integer(value["receiver_epoch"], "ack_epoch", 1)
    _blob(value["idempotency_key"], 64, "ack_idempotency")
    _blob(value["envelope_digest"], 64, "ack_envelope")
    _integer(value["effective_directive"], "ack_directive", 1)
    if value["effective_directive"] > 5:
        _fail("ack_directive")
    if "policy_result" in value:
        _integer(value["policy_result"], "ack_policy_result", 1)
        if value["policy_result"] > 5:
            _fail("ack_policy_result")
    _integer(value["accepted_ms"], "ack_time")
    _blob(value["acknowledgment_id"], 64, "ack_id")
    return value


def envelope_digest(raw: bytes) -> bytes:
    parse_envelope_bytes(raw)
    return _sha(_ENVELOPE, raw)


def acknowledgment_digest(raw: bytes) -> bytes:
    parse_acknowledgment_bytes(raw)
    return _sha(_ACK, raw)


def validate_acknowledgment(
    raw: bytes, *, envelope_bytes: bytes, operation_id: bytes, job_id: str,
    config: Mapping[str, Any], expected_policy_result: int | None = None,
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Validate immediate and lookup acknowledgments through one path.

    The identity and epoch fields are observation bindings only.  This routine
    deliberately provides no cryptographic authentication or production claim.
    """
    try:
        ack = parse_acknowledgment_bytes(raw)
        envelope = parse_envelope_bytes(envelope_bytes)
    except IndependentOfficialHandoffError:
        raise
    if type(operation_id) is not bytes or len(operation_id) != 64:
        _fail("ack_operation")
    _token(job_id, "ack_job")
    env_digest = _sha(_ENVELOPE, envelope_bytes)
    ack_digest = _sha(_ACK, raw)
    profile_digest = _blob(config["ack_evidence_profile_digest"], 64, "config_profile")
    verifier = _blob(config["verifier_sha256"], 32, "config_verifier")
    receiver = _blob(config["receiver_identity"], 32, "config_receiver")
    config_bytes = _json_bytes({k: v for k, v in config.items() if not k.startswith("_")})
    config_digest = _sha(_MATERIAL, config_bytes)
    expected_idempotency = _idempotency_key(config, job_id, env_digest, config_digest)
    expected_operation = _operation_identity(config, job_id, env_digest, config_digest)
    supplied_idempotency = config.get("_expected_idempotency_key")
    if operation_id != expected_operation or (supplied_idempotency is not None and _blob(supplied_idempotency, 64, "expected_idempotency") != expected_idempotency):
        _fail("expected_idempotency_binding")
    if (
        bytes.fromhex(ack["receiver_identity"]) != receiver
        or int(ack["receiver_epoch"]) != int(config["receiver_epoch"])
        or bytes.fromhex(ack["idempotency_key"]) != expected_idempotency
        or bytes.fromhex(ack["envelope_digest"]) != env_digest
        or int(ack["effective_directive"]) != int(envelope["effective_directive"])
        or envelope["handoff_config_digest"].upper() != _hex(config_digest)
        or envelope["application_id_digest"].upper() != _hex(_sha(_ENVELOPE, str(config["application_id"]).encode("ascii")))
        or envelope["application_job_id_digest"].upper() != _hex(_sha(_ENVELOPE, job_id.encode("ascii")))
        or envelope["application_config_digest"].upper() != str(config["application_config_digest"]).upper()
        or envelope["state_store_identity"].upper() != str(config["state_store_identity"]).upper()
        or envelope["receiver_identity"].upper() != _hex(receiver)
        or int(envelope["receiver_epoch"]) != int(config["receiver_epoch"])
        or int(envelope["verifier_epoch"]) != int(config["verifier_epoch"])
        or envelope["ack_evidence_profile_digest"].upper() != _hex(profile_digest)
    ):
        _fail("ack_binding")
    if expected_policy_result is not None and int(envelope["policy_result"]) != expected_policy_result:
        _fail("ack_policy_binding")
    if "policy_result" in ack and int(ack["policy_result"]) != int(envelope["policy_result"]):
        _fail("ack_policy_binding")
    if profile_digest != acknowledgment_profile_digest(
        verifier_identity=verifier, verifier_epoch=int(config["verifier_epoch"]),
        receiver_identity=receiver, receiver_epoch=int(config["receiver_epoch"]),
    ):
        _fail("ack_profile_binding")
    receipt = build_ack_qualification_receipt(
        profile_digest=profile_digest, verifier_identity=verifier, verifier_epoch=int(config["verifier_epoch"]),
        receiver_identity=receiver, receiver_epoch=int(config["receiver_epoch"]), operation_id=operation_id,
        job_id=job_id, idempotency_key=bytes.fromhex(ack["idempotency_key"]), envelope_digest_value=env_digest,
        ack_digest=ack_digest, acknowledgment_id=str(ack["acknowledgment_id"]),
        policy_result=int(envelope["policy_result"]), effective_directive=int(ack["effective_directive"]),
    )
    return ack, env_digest, ack_digest, receipt


@dataclass(frozen=True, slots=True)
class AppliedApplicationViewV1:
    application_id: str
    application_config_digest: bytes
    state_store_identity: bytes
    job_id: str
    operation_id: bytes
    application_result_digest: bytes
    state_receipt_digest: bytes
    receipt: dict[str, Any]
    acceptance: Any


def _parse_state_receipt(raw: bytes, acceptance: Any) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 16 * 1024:
        _fail("state_receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("state_receipt_encoding") from exc
    names = {
        "operation_digest", "artifact_sha256", "artifact_digest", "statement_digest", "circuit_id", "bundle_id",
        "receipt_id", "join_id", "settlement_id", "request_id", "attempt_id", "decision_id", "sequence_before",
        "sequence_after", "state_before_id", "state_after_id", "clearance_root_before", "clearance_root_after",
        "clearance_count_before", "clearance_count_after", "payment_root_before", "payment_root_after",
        "settled_batch_count_before", "settled_batch_count_after", "state_binding_after", "audit_head_after",
        "policy_result", "effective_directive", "proof_session_accepted", "economic_mutation", "proof_suite_id",
    }
    if type(value) is not dict or set(value) != names or raw != _json_bytes(value):
        _fail("state_receipt_canonical")
    digest_names = names - {
        "sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after",
        "settled_batch_count_before", "settled_batch_count_after", "policy_result", "effective_directive",
        "proof_session_accepted", "economic_mutation", "proof_suite_id",
    }
    for name in digest_names:
        _blob(value[name], 32 if name in {"artifact_sha256", "circuit_id"} else 64, "state_receipt_" + name)
    for name in ("sequence_before", "sequence_after", "clearance_count_before", "clearance_count_after", "settled_batch_count_before", "settled_batch_count_after", "policy_result", "effective_directive"):
        _integer(value[name], "state_receipt_" + name)
    if (
        value["proof_session_accepted"] is not True or value["economic_mutation"] is not False
        or value["proof_suite_id"] is not None or not 1 <= value["effective_directive"] <= 5
        or value["artifact_sha256"].upper() != _hex(acceptance.artifact_sha256)
        or value["artifact_digest"].upper() != _hex(acceptance.artifact_digest)
        or value["circuit_id"].upper() != _hex(acceptance.circuit_id)
        or value["statement_digest"].upper() != _hex(acceptance.statement_digest)
        or value["receipt_id"].upper() != _hex(acceptance.statement.receipt_id)
        or value["join_id"].upper() != _hex(acceptance.statement.join_id)
        or value["request_id"].upper() != _hex(acceptance.statement.request_id)
        or value["attempt_id"].upper() != _hex(acceptance.statement.attempt_id)
        or value["decision_id"].upper() != _hex(acceptance.statement.decision_id)
        or value["policy_result"] != acceptance.policy_result
        or value["effective_directive"] != acceptance.effective_directive
        or value["payment_root_before"] != value["payment_root_after"]
        or value["settled_batch_count_before"] != value["settled_batch_count_after"]
    ):
        _fail("state_receipt_binding")
    return value


def _read_state_binding(path: Path, view: AppliedApplicationViewV1, expected_verifier_sha256: bytes) -> None:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("state_database_path")
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise IndependentOfficialHandoffError("state_database_open") from exc
    try:
        row = connection.execute("SELECT * FROM minimal_proof_clearance_state WHERE id=1").fetchone()
        if row is None or len(row) != 17 or int(row[1]) != 3:
            _fail("state_schema")
        if (
            bytes(row[2]) != view.acceptance.statement.statement_bytes
            or bytes(row[3]) != view.acceptance.circuit_id
            or bytes(row[16]) != expected_verifier_sha256
            or bytes(row[4]) != bytes.fromhex(view.receipt["state_after_id"])
            or int(row[6]) != int(view.receipt["sequence_after"])
            or bytes(row[13]) != bytes.fromhex(view.receipt["state_binding_after"])
            or bytes(row[14]) != bytes.fromhex(view.receipt["audit_head_after"])
            or bytes(row[15]) != bytes.fromhex(view.receipt["operation_digest"])
            or bytes(row[11]) != PRIVATE_ZK_INITIAL_PAYMENT_ROOT
            or int(row[12]) != 0
        ):
            _fail("state_binding")
        expected_identity = _sha(
            _STATE_IDENTITY, PRIVATE_ZK_DATABASE_CONTEXT_ID, PRIVATE_ZK_DATABASE_SCHEMA_ID,
            PRIVATE_ZK_DATABASE_PROGRAM_ID, PRIVATE_ZK_MODE_ID, view.acceptance.circuit_id,
            bytes(row[2]), expected_verifier_sha256,
            _private_zk_profile_digest(view.acceptance.statement, expected_verifier_sha256),
        )
        if expected_identity != view.state_store_identity:
            _fail("state_identity")
    except sqlite3.Error as exc:
        raise IndependentOfficialHandoffError("state_database_read") from exc
    finally:
        connection.close()


def read_applied_application(
    application_database: Path,
    state_database: Path,
    *,
    expected_application_id: str,
    expected_application_config_digest: bytes,
    expected_state_store_identity: bytes,
    expected_verifier_sha256: bytes,
    job_id: str,
) -> AppliedApplicationViewV1:
    """Read and independently bind one terminal APPLIED application job."""
    _token(expected_application_id, "application_id")
    _token(job_id, "job_id")
    if len(expected_application_config_digest) != 64 or len(expected_state_store_identity) != 64 or len(expected_verifier_sha256) != 32:
        _fail("application_expected_identity")
    if not application_database.is_file() or application_database.is_symlink():
        _fail("application_database_path")
    try:
        connection = sqlite3.connect(f"file:{application_database.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise IndependentOfficialHandoffError("application_database_open") from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        try:
            verify_database_connection(connection)
        except (IndependentQueueApplicationError, OSError) as exc:
            raise IndependentOfficialHandoffError("application_verification") from exc
        metadata = connection.execute("SELECT * FROM app_metadata WHERE id=1").fetchone()
        job = connection.execute("SELECT * FROM app_jobs WHERE job_id=?", (job_id,)).fetchone()
        result = connection.execute("SELECT * FROM app_results WHERE job_id=?", (job_id,)).fetchone()
        if metadata is None or len(metadata) != 11 or job is None or len(job) != 13 or result is None or len(result) != 7:
            _fail("application_job_missing")
        if (
            str(metadata[2]) != expected_application_id
            or bytes(metadata[4]) != expected_application_config_digest
            or bytes(metadata[8]) != expected_state_store_identity
            or str(job[6]) != "APPLIED" or str(result[1]) != "APPLIED"
            or bytes(result[4]) != bytes(job[1])
            or result[2] is None or result[3] is None
        ):
            _fail("application_binding")
        acceptance = parse_acceptance_bytes(bytes(job[4]))
        if acceptance.canonical_bytes() != bytes(job[4]):
            _fail("application_acceptance")
        receipt_raw = bytes(result[2])
        receipt = _parse_state_receipt(receipt_raw, acceptance)
        result_digest = _sha(_RESULT, job_id.encode("ascii"), bytes(job[1]), bytes(result[3]), b"APPLIED")
        if bytes(result[3]) != _sha(b"BL/NATIVE-V3/MINIMAL-CLEARANCE/APPLICATION/STATE-RECEIPT/v1\x00", receipt_raw):
            _fail("application_receipt_digest")
        view = AppliedApplicationViewV1(
            application_id=expected_application_id,
            application_config_digest=bytes(metadata[4]),
            state_store_identity=bytes(metadata[8]),
            job_id=job_id,
            operation_id=bytes(job[1]),
            application_result_digest=result_digest,
            state_receipt_digest=bytes(result[3]),
            receipt=receipt,
            acceptance=acceptance,
        )
        connection.execute("ROLLBACK")
    except (sqlite3.Error, ValueError) as exc:
        raise IndependentOfficialHandoffError("application_database_read") from exc
    finally:
        connection.close()
    _read_state_binding(state_database, view, expected_verifier_sha256)
    return view


def _parse_config(value: Any) -> tuple[dict[str, Any], bytes, bytes]:
    keys = {
        "schema_version", "outbox_id", "application_id", "application_config_digest", "verifier_sha256", "state_store_identity",
        "receiver_identity", "receiver_epoch", "capacity", "lease_seconds", "max_attempts", "busy_timeout_ms",
        "verifier_epoch", "ack_evidence_profile_digest", "proof_suite_id", "production_usable", "activation",
    }
    if type(value) is not dict or set(value) != keys or value["schema_version"] != _SCHEMA_VERSION:
        _fail("config_keys")
    outbox_id = _token(value["outbox_id"], "outbox_id")
    application_id = _token(value["application_id"], "application_id")
    app_digest = _blob(value["application_config_digest"], 64, "application_config_digest")
    verifier = _blob(value["verifier_sha256"], 32, "verifier_sha256")
    state_id = _blob(value["state_store_identity"], 64, "state_store_identity")
    receiver = _blob(value["receiver_identity"], 32, "receiver_identity")
    epoch = _integer(value["receiver_epoch"], "receiver_epoch", 1)
    verifier_epoch = _integer(value["verifier_epoch"], "verifier_epoch", 1)
    profile_digest = _blob(value["ack_evidence_profile_digest"], 64, "ack_evidence_profile_digest")
    capacity = _integer(value["capacity"], "capacity", 1)
    lease = _integer(value["lease_seconds"], "lease_seconds", 1)
    if not 1 <= capacity <= 10_000 or not 1 <= lease <= 3_600 or value["max_attempts"] != 3 or value["busy_timeout_ms"] != 5_000:
        _fail("config_bounds")
    if value["proof_suite_id"] is not None or value["production_usable"] is not False or value["activation"] is not False:
        _fail("config_nonactivation")
    expected_profile = acknowledgment_profile_digest(
        verifier_identity=verifier, verifier_epoch=verifier_epoch,
        receiver_identity=receiver, receiver_epoch=epoch,
    )
    if profile_digest != expected_profile:
        _fail("config_profile")
    canonical = _json_bytes(value)
    digest = _sha(_MATERIAL, canonical)
    parsed = dict(value, outbox_id=outbox_id, application_id=application_id, application_config_digest=app_digest, verifier_sha256=verifier, state_store_identity=state_id, receiver_identity=receiver, ack_evidence_profile_digest=profile_digest)
    return parsed, canonical, digest


def _parse_export(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_EXPORT:
        _fail("export_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("export_encoding") from exc
    top = {"schema", "config", "metadata", "jobs", "leases", "acks", "profiles", "receipts", "reconciliation", "transitions"}
    if type(value) is not dict or set(value) != top or value["schema"] != _SCHEMA or raw != _json_bytes(value):
        _fail("export_keys")
    config, _, config_digest = _parse_config(value["config"])
    profiles = value["profiles"]
    if type(profiles) is not list or len(profiles) != 1:
        _fail("profiles_shape")
    profile = profiles[0]
    if type(profile) is not dict or set(profile) != {"profile_digest", "profile_bytes"}:
        _fail("profile_keys")
    profile_digest = _blob(profile["profile_digest"], 64, "profile_digest")
    profile_bytes = _blob(profile["profile_bytes"], None, "profile_bytes")
    try:
        profile_value = json.loads(profile_bytes.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentOfficialHandoffError("profile_encoding") from exc
    if (
        profile_bytes != acknowledgment_profile_bytes(
            verifier_identity=config["verifier_sha256"], verifier_epoch=int(config["verifier_epoch"]),
            receiver_identity=config["receiver_identity"], receiver_epoch=int(config["receiver_epoch"]),
        )
        or profile_digest != acknowledgment_profile_digest(
            verifier_identity=config["verifier_sha256"], verifier_epoch=int(config["verifier_epoch"]),
            receiver_identity=config["receiver_identity"], receiver_epoch=int(config["receiver_epoch"]),
        )
        or type(profile_value) is not dict or set(profile_value) != _ACK_PROFILE_KEYS
        or profile_value != json.loads(acknowledgment_profile_bytes(
            verifier_identity=config["verifier_sha256"], verifier_epoch=int(config["verifier_epoch"]),
            receiver_identity=config["receiver_identity"], receiver_epoch=int(config["receiver_epoch"]),
        ).decode("ascii"))
    ):
        _fail("profile_binding")
    receipts = value["receipts"]
    if type(receipts) is not list:
        _fail("receipts_shape")
    receipt_map: dict[str, bytes] = {}
    for receipt in receipts:
        if type(receipt) is not dict or set(receipt) != {"job_id", "receipt_bytes"}:
            _fail("receipt_row_keys")
        jid = _token(receipt["job_id"], "receipt_job")
        if jid in receipt_map:
            _fail("receipt_duplicate")
        receipt_raw = _blob(receipt["receipt_bytes"], None, "receipt_bytes")
        parse_ack_qualification_receipt(receipt_raw)
        receipt_map[jid] = receipt_raw
    metadata = value["metadata"]
    if type(metadata) is not dict or set(metadata) != {"head_root", "next_sequence"}:
        _fail("metadata_keys")
    head = _blob(metadata["head_root"], 64, "metadata_head")
    next_sequence = _integer(metadata["next_sequence"], "metadata_sequence")
    jobs = value["jobs"]
    if type(jobs) is not list:
        _fail("jobs_shape")
    job_map: dict[str, dict[str, Any]] = {}
    previous_discovery_sequence = 0
    for index, job in enumerate(jobs, 1):
        keys = {"job_id", "operation_id", "envelope_digest", "envelope_bytes", "idempotency_key", "status", "discovery_sequence", "attempt", "next_eligible_ms", "created_ms", "updated_ms", "last_error_code"}
        if type(job) is not dict or set(job) != keys:
            _fail("job_keys")
        jid = _token(job["job_id"], "job_id")
        discovery_sequence = _integer(job["discovery_sequence"], "discovery_sequence", 1)
        if jid in job_map or discovery_sequence <= previous_discovery_sequence:
            _fail("job_order")
        previous_discovery_sequence = discovery_sequence
        operation = _blob(job["operation_id"], 64, "operation")
        envelope = _blob(job["envelope_bytes"], None, "envelope")
        env = parse_envelope_bytes(envelope)
        env_digest = _blob(job["envelope_digest"], 64, "envelope_digest")
        idem = _blob(job["idempotency_key"], 64, "idempotency")
        if (
            env_digest != _sha(_ENVELOPE, envelope)
            or env["handoff_config_digest"].upper() != _hex(config_digest)
            or env["application_id_digest"].upper() != _hex(_sha(_ENVELOPE, config["application_id"].encode("ascii")))
            or env["application_config_digest"].upper() != _hex(config["application_config_digest"])
            or env["application_job_id_digest"].upper() != _hex(_sha(_ENVELOPE, jid.encode("ascii")))
            or env["state_store_identity"].upper() != _hex(config["state_store_identity"])
            or env["receiver_identity"].upper() != _hex(config["receiver_identity"])
            or int(env["receiver_epoch"]) != int(config["receiver_epoch"])
            or int(env["verifier_epoch"]) != int(config["verifier_epoch"])
            or env["ack_evidence_profile_digest"].upper() != _hex(config["ack_evidence_profile_digest"])
            or idem != _idempotency_key(config, jid, env_digest, config_digest)
        ):
            _fail("job_digest")
        expected_operation = _operation_identity(config, jid, env_digest, config_digest)
        if operation != expected_operation or job["status"] not in _STATUS:
            _fail("job_binding")
        for name in ("attempt", "next_eligible_ms", "created_ms", "updated_ms"):
            _integer(job[name], "job_" + name)
        if job["attempt"] > 3:
            _fail("job_attempt")
        if job["last_error_code"] is not None:
            _token(job["last_error_code"], "job_error_code")
        job_map[jid] = dict(job, operation_id=operation, envelope_digest=env_digest, envelope_bytes=envelope, idempotency_key=idem, envelope=env)
    leases = value["leases"]
    if type(leases) is not list:
        _fail("leases_shape")
    lease_map: dict[str, dict[str, Any]] = {}
    for lease in leases:
        keys = {"job_id", "worker_id", "token", "attempt", "leased_ms", "expires_ms"}
        if type(lease) is not dict or set(lease) != keys:
            _fail("lease_keys")
        jid = _token(lease["job_id"], "lease_job")
        if jid in lease_map or jid not in job_map or job_map[jid]["status"] != "LEASED":
            _fail("lease_binding")
        _token(lease["worker_id"], "lease_worker")
        _blob(lease["token"], 24, "lease_token")
        attempt = _integer(lease["attempt"], "lease_attempt", 1)
        leased = _integer(lease["leased_ms"], "lease_time")
        if _integer(lease["expires_ms"], "lease_expiry") <= leased or attempt != job_map[jid]["attempt"]:
            _fail("lease_state")
        lease_map[jid] = dict(lease)
    acks = value["acks"]
    if type(acks) is not list:
        _fail("acks_shape")
    ack_map: dict[str, dict[str, Any]] = {}
    for ack in acks:
        keys = {"job_id", "ack_bytes", "ack_digest", "operation_id", "completed_ms"}
        keys = keys | {"ack_receipt", "profile_digest"}
        if type(ack) is not dict or set(ack) != keys:
            _fail("ack_row_keys")
        jid = _token(ack["job_id"], "ack_job")
        if jid in ack_map or jid not in job_map or job_map[jid]["status"] != "ACKNOWLEDGED":
            _fail("ack_binding")
        raw_ack = _blob(ack["ack_bytes"], None, "ack_bytes")
        parsed_ack = parse_acknowledgment_bytes(raw_ack)
        digest = _blob(ack["ack_digest"], 64, "ack_digest")
        operation = _blob(ack["operation_id"], 64, "ack_operation")
        if (
            digest != _sha(_ACK, raw_ack)
            or operation != job_map[jid]["operation_id"]
            or parsed_ack["receiver_identity"].upper() != _hex(config["receiver_identity"])
            or int(parsed_ack["receiver_epoch"]) != int(config["receiver_epoch"])
            or parsed_ack["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
            or parsed_ack["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
            or int(parsed_ack["effective_directive"]) != int(job_map[jid]["envelope"]["effective_directive"])
            or ("policy_result" in parsed_ack and int(parsed_ack["policy_result"]) != int(job_map[jid]["envelope"]["policy_result"]))
        ):
            _fail("ack_value_binding")
        if jid not in receipt_map:
            _fail("ack_receipt_missing")
        ack_receipt = _blob(ack["ack_receipt"], None, "ack_receipt")
        receipt_value = parse_ack_qualification_receipt(ack_receipt)
        ack_profile = _blob(ack["profile_digest"], 64, "ack_profile_digest")
        expected_profile = config["ack_evidence_profile_digest"]
        if (
            ack_receipt != receipt_map[jid] or ack_profile != expected_profile
            or receipt_value["profile_digest"].upper() != _hex(ack_profile)
            or receipt_value["operation_id"].upper() != _hex(operation)
            or receipt_value["job_id_digest"].upper() != _hex(_sha(_ACK_RECEIPT, jid.encode("ascii")))
            or receipt_value["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
            or receipt_value["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
            or receipt_value["ack_digest"].upper() != _hex(digest)
            or receipt_value["acknowledgment_id"] != parsed_ack["acknowledgment_id"]
            or int(receipt_value["policy_result"]) != int(job_map[jid]["envelope"]["policy_result"])
            or int(receipt_value["effective_directive"]) != int(parsed_ack["effective_directive"])
            or receipt_value["verifier_identity"].upper() != _hex(config["verifier_sha256"])
            or int(receipt_value["verifier_epoch"]) != int(config["verifier_epoch"])
            or receipt_value["receiver_identity"].upper() != _hex(config["receiver_identity"])
            or int(receipt_value["receiver_epoch"]) != int(config["receiver_epoch"])
        ):
            _fail("ack_receipt_binding")
        _integer(ack["completed_ms"], "ack_time")
        ack_map[jid] = dict(ack, ack_bytes=raw_ack, ack_value=parsed_ack, ack_receipt=ack_receipt, profile_digest=ack_profile)
    if any(jid not in ack_map for jid in receipt_map):
        _fail("receipt_orphan")
    for jid, job in job_map.items():
        if (job["status"] == "LEASED") != (jid in lease_map):
            _fail("lease_final")
        if (job["status"] == "ACKNOWLEDGED") != (jid in ack_map):
            _fail("ack_final")
    reconciliation = value["reconciliation"]
    if type(reconciliation) is not list:
        _fail("reconciliation_shape")
    reconciliation_map: dict[str, dict[str, Any]] = {}
    for row in reconciliation:
        keys = {
            "job_id", "operation_id", "envelope_digest", "idempotency_key", "status", "worker_id",
            "token", "attempt", "leased_ms", "expires_ms", "next_eligible_ms", "discovered_ms",
            "updated_ms", "last_error_code",
        }
        if type(row) is not dict or set(row) != keys:
            _fail("reconciliation_keys")
        jid = _token(row["job_id"], "reconciliation_job")
        if jid in reconciliation_map or jid not in job_map:
            _fail("reconciliation_job")
        operation = _blob(row["operation_id"], 64, "reconciliation_operation")
        env_digest = _blob(row["envelope_digest"], 64, "reconciliation_envelope")
        idem = _blob(row["idempotency_key"], 64, "reconciliation_idempotency")
        job = job_map[jid]
        if operation != job["operation_id"] or env_digest != job["envelope_digest"] or idem != job["idempotency_key"]:
            _fail("reconciliation_binding")
        status = row["status"]
        if status not in _RECONCILIATION_STATUS or job["status"] not in {"DELIVERY_UNCONFIRMED", "ACKNOWLEDGED"}:
            _fail("reconciliation_status")
        _integer(row["attempt"], "reconciliation_attempt")
        if row["attempt"] > 3:
            _fail("reconciliation_attempt")
        for name in ("next_eligible_ms", "discovered_ms", "updated_ms"):
            _integer(row[name], "reconciliation_" + name)
        if row["status"] == "LEASED":
            _token(row["worker_id"], "reconciliation_worker")
            _blob(row["token"], 24, "reconciliation_token")
            _integer(row["leased_ms"], "reconciliation_leased")
            if _integer(row["expires_ms"], "reconciliation_expiry") <= row["leased_ms"]:
                _fail("reconciliation_expiry")
        else:
            if row["worker_id"] is not None or row["token"] is not None or row["leased_ms"] is not None or row["expires_ms"] is not None:
                _fail("reconciliation_unleased")
        if row["last_error_code"] is not None:
            _token(row["last_error_code"], "reconciliation_error")
        if status == "ACKNOWLEDGED" and job["status"] != "ACKNOWLEDGED":
            _fail("reconciliation_ack_status")
        if status != "ACKNOWLEDGED" and job["status"] != "DELIVERY_UNCONFIRMED":
            _fail("reconciliation_terminal_status")
        reconciliation_map[jid] = dict(row)
    for jid, job in job_map.items():
        if job["status"] == "DELIVERY_UNCONFIRMED" and jid not in reconciliation_map:
            _fail("reconciliation_missing")
    transitions = value["transitions"]
    if type(transitions) is not list or next_sequence != len(transitions):
        _fail("transition_count")
    expected_head = _sha(_GENESIS, config["outbox_id"].encode("ascii"), config_digest)
    replay: dict[str, str] = {}
    replay_attempt: dict[str, int] = {}
    recon_replay: dict[str, str] = {}
    recon_attempt: dict[str, int] = {}
    for index, transition in enumerate(transitions, 1):
        keys = {"sequence", "transition_kind", "job_id", "before_root", "after_root", "event_bytes", "event_digest"}
        if type(transition) is not dict or set(transition) != keys or _integer(transition["sequence"], "transition_sequence", 1) != index:
            _fail("transition_keys")
        jid = _token(transition["job_id"], "transition_job")
        if jid not in job_map:
            _fail("transition_job")
        before = _blob(transition["before_root"], 64, "before_root")
        after = _blob(transition["after_root"], 64, "after_root")
        event = _blob(transition["event_bytes"], None, "event_bytes")
        digest = _blob(transition["event_digest"], 64, "event_digest")
        if before != expected_head or digest != _sha(_EVENT, str(transition["transition_kind"]).encode("ascii"), jid.encode("ascii"), event):
            _fail("transition_digest")
        try:
            ev = json.loads(event.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IndependentOfficialHandoffError("transition_event") from exc
        if type(ev) is not dict or event != _json_bytes(ev):
            _fail("transition_event_canonical")
        kind = transition["transition_kind"]
        if type(kind) is not str:
            _fail("transition_kind")
        status = ev.get("status")
        previous = replay.get(jid)
        if kind == "DISCOVER":
            if set(ev) != {"at_ms", "status", "discovery_sequence", "effective_directive", "policy_result"}:
                _fail("transition_discover_event")
            _integer(ev["at_ms"], "discover_time")
            if status != "DISCOVERED" or ev["discovery_sequence"] != job_map[jid]["discovery_sequence"]:
                _fail("transition_discover")
            for name in ("effective_directive", "policy_result"):
                _integer(ev[name], "discover_" + name, 1)
                if ev[name] > 5 or ev[name] != job_map[jid]["envelope"][name]:
                    _fail("transition_discover_binding")
            if previous is not None: _fail("transition_discover")
            replay[jid] = "DISCOVERED"
            replay_attempt[jid] = 0
        elif kind == "CLAIM":
            if set(ev) != {"at_ms", "status", "attempt", "worker_id", "expires_ms"}:
                _fail("transition_claim_event")
            at_ms = _integer(ev["at_ms"], "claim_time")
            attempt = _integer(ev["attempt"], "claim_attempt", 1)
            _token(ev["worker_id"], "claim_worker")
            if status != "LEASED" or attempt != replay_attempt.get(jid, 0) + 1 or _integer(ev["expires_ms"], "claim_expiry") <= at_ms:
                _fail("transition_claim")
            if previous != "DISCOVERED": _fail("transition_claim")
            replay[jid] = "LEASED"
            replay_attempt[jid] = attempt
        elif kind == "EXPIRED_REQUEUE":
            if set(ev) != {"at_ms", "status", "attempt", "error_code", "expired_ms"}:
                _fail("transition_requeue_event")
            _integer(ev["at_ms"], "requeue_time")
            _integer(ev["attempt"], "requeue_attempt", 1)
            _token(ev["error_code"], "requeue_error")
            if status != "DISCOVERED" or ev["attempt"] != replay_attempt.get(jid) or _integer(ev["expired_ms"], "requeue_expiry") > ev["at_ms"]:
                _fail("transition_requeue")
            if previous != "LEASED": _fail("transition_requeue")
            replay[jid] = "DISCOVERED"
        elif kind == "EXPIRED_DELIVERY_UNCONFIRMED":
            if set(ev) != {"at_ms", "status", "attempt", "error_code", "expired_ms"}:
                _fail("transition_delivery_unconfirmed_event")
            _integer(ev["at_ms"], "delivery_unconfirmed_time")
            _integer(ev["attempt"], "delivery_unconfirmed_attempt", 1)
            _token(ev["error_code"], "delivery_unconfirmed_error")
            if status != "DELIVERY_UNCONFIRMED" or ev["attempt"] != replay_attempt.get(jid) or _integer(ev["expired_ms"], "delivery_unconfirmed_expiry") > ev["at_ms"]:
                _fail("transition_delivery_unconfirmed")
            if previous != "LEASED": _fail("transition_delivery_unconfirmed")
            replay[jid] = "DELIVERY_UNCONFIRMED"
        elif kind == "DELIVERY_UNCONFIRMED":
            required = {
                "at_ms", "status", "attempt", "error_code", "operation_id", "envelope_digest",
                "idempotency_key", "policy_result", "effective_directive",
            }
            if set(ev) != required:
                _fail("transition_delivery_unconfirmed_event")
            _integer(ev["at_ms"], "delivery_unconfirmed_time")
            _integer(ev["attempt"], "delivery_unconfirmed_attempt", 1)
            _token(ev["error_code"], "delivery_unconfirmed_error")
            for name in ("operation_id", "envelope_digest", "idempotency_key"):
                _blob(ev[name], 64, "delivery_unconfirmed_" + name)
            for name in ("policy_result", "effective_directive"):
                _integer(ev[name], "delivery_unconfirmed_" + name, 1)
                if ev[name] > 5 or ev[name] != job_map[jid]["envelope"][name]:
                    _fail("delivery_unconfirmed_binding")
            if (
                previous != "LEASED" or status != "DELIVERY_UNCONFIRMED"
                or ev["attempt"] != replay_attempt.get(jid)
                or ev["operation_id"].upper() != _hex(job_map[jid]["operation_id"])
                or ev["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
                or ev["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
            ):
                _fail("transition_delivery_unconfirmed")
            replay[jid] = "DELIVERY_UNCONFIRMED"
        elif kind == "RECONCILIATION_DISCOVERED":
            required = {"at_ms", "status", "attempt", "operation_id", "envelope_digest", "idempotency_key"}
            if set(ev) != required:
                _fail("transition_reconciliation_discovered_event")
            _integer(ev["at_ms"], "reconciliation_discovered_time")
            _integer(ev["attempt"], "reconciliation_discovered_attempt")
            for name in ("operation_id", "envelope_digest", "idempotency_key"):
                _blob(ev[name], 64, "reconciliation_discovered_" + name)
            if (
                status != "DELIVERY_UNCONFIRMED" or replay.get(jid) != "DELIVERY_UNCONFIRMED"
                or recon_replay.get(jid) not in {None, "DISCOVERED"}
                or ev["operation_id"].upper() != _hex(job_map[jid]["operation_id"])
                or ev["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
                or ev["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
            ):
                _fail("transition_reconciliation_discovered")
            recon_replay[jid] = "DISCOVERED"
            recon_attempt.setdefault(jid, 0)
        elif kind == "RECONCILIATION_CLAIM":
            required = {"at_ms", "status", "attempt", "worker_id", "expires_ms"}
            if set(ev) != required:
                _fail("transition_reconciliation_claim_event")
            at_ms = _integer(ev["at_ms"], "reconciliation_claim_time")
            attempt = _integer(ev["attempt"], "reconciliation_claim_attempt", 1)
            _token(ev["worker_id"], "reconciliation_claim_worker")
            if status != "DELIVERY_UNCONFIRMED" or _integer(ev["expires_ms"], "reconciliation_claim_expiry") <= at_ms or recon_replay.get(jid) != "DISCOVERED":
                _fail("transition_reconciliation_claim")
            if attempt != recon_attempt.get(jid, 0) + 1:
                _fail("transition_reconciliation_claim_attempt")
            recon_attempt[jid] = attempt
            recon_replay[jid] = "LEASED"
        elif kind in {"RECONCILIATION_INDETERMINATE", "RECONCILIATION_EXPIRED_REQUEUE"}:
            required = {"at_ms", "status", "attempt", "error_code"}
            if set(ev) != required:
                _fail("transition_reconciliation_release_event")
            _integer(ev["at_ms"], "reconciliation_release_time")
            _integer(ev["attempt"], "reconciliation_release_attempt")
            _token(ev["error_code"], "reconciliation_release_error")
            if status != "DELIVERY_UNCONFIRMED" or recon_replay.get(jid) != "LEASED" or ev["attempt"] != recon_attempt.get(jid):
                _fail("transition_reconciliation_release")
            recon_replay[jid] = "DISCOVERED"
        elif kind == "RECONCILIATION_EXHAUSTED":
            required = {"at_ms", "status", "attempt", "error_code"}
            if set(ev) != required:
                _fail("transition_reconciliation_exhausted_event")
            _integer(ev["at_ms"], "reconciliation_exhausted_time")
            _integer(ev["attempt"], "reconciliation_exhausted_attempt")
            _token(ev["error_code"], "reconciliation_exhausted_error")
            if status != "DELIVERY_UNCONFIRMED" or recon_replay.get(jid) not in {"LEASED", "DISCOVERED"} or ev["attempt"] != recon_attempt.get(jid):
                _fail("transition_reconciliation_exhausted")
            recon_replay[jid] = "EXHAUSTED"
        elif kind == "ACKNOWLEDGED_BY_RECONCILIATION":
            required = {
                "at_ms", "status", "attempt", "receiver_identity", "receiver_epoch", "idempotency_key",
                "envelope_digest", "ack_digest", "acknowledgment_id", "effective_directive", "policy_result",
                "profile_digest", "verifier_identity", "verifier_epoch", "mode",
            }
            if set(ev) != required:
                _fail("transition_reconciliation_ack_event")
            _integer(ev["at_ms"], "reconciliation_ack_time")
            _integer(ev["attempt"], "reconciliation_ack_attempt", 1)
            for name, size in (("receiver_identity", 32), ("idempotency_key", 64), ("envelope_digest", 64), ("ack_digest", 64), ("profile_digest", 64), ("verifier_identity", 32)):
                _blob(ev[name], size, "reconciliation_ack_" + name)
            _integer(ev["receiver_epoch"], "reconciliation_ack_epoch", 1)
            _integer(ev["verifier_epoch"], "reconciliation_ack_verifier_epoch", 1)
            _token(ev["acknowledgment_id"], "reconciliation_ack_id")
            for name in ("effective_directive", "policy_result"):
                _integer(ev[name], "reconciliation_ack_" + name, 1)
                if ev[name] > 5:
                    _fail("reconciliation_ack_directive")
            if (
                status != "ACKNOWLEDGED" or replay.get(jid) != "DELIVERY_UNCONFIRMED" or jid not in ack_map
                or recon_replay.get(jid) != "LEASED" or ev["attempt"] != recon_attempt.get(jid)
                or ev["receiver_identity"].upper() != _hex(config["receiver_identity"])
                or ev["receiver_epoch"] != int(config["receiver_epoch"])
                or ev["verifier_identity"].upper() != _hex(config["verifier_sha256"])
                or ev["verifier_epoch"] != int(config["verifier_epoch"])
                or ev["profile_digest"].upper() != _hex(config["ack_evidence_profile_digest"])
                or ev["mode"] != _ACK_EVIDENCE_MODE
                or ev["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
                or ev["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
                or ev["ack_digest"].upper() != ack_map[jid]["ack_digest"].upper()
                or ev["acknowledgment_id"] != ack_map[jid]["ack_value"]["acknowledgment_id"]
                or ev["policy_result"] != job_map[jid]["envelope"]["policy_result"]
                or ev["effective_directive"] != job_map[jid]["envelope"]["effective_directive"]
            ):
                _fail("transition_reconciliation_ack_binding")
            replay[jid] = "ACKNOWLEDGED"
            recon_replay[jid] = "ACKNOWLEDGED"
        elif kind == "ACKNOWLEDGED":
            required = {"at_ms", "status", "attempt", "receiver_identity", "receiver_epoch", "idempotency_key", "envelope_digest", "ack_digest", "effective_directive", "acknowledgment_id", "policy_result", "profile_digest", "verifier_identity", "verifier_epoch", "mode"}
            if set(ev) != required:
                _fail("transition_ack_event")
            _integer(ev["at_ms"], "ack_time")
            _integer(ev["attempt"], "ack_attempt", 1)
            _blob(ev["receiver_identity"], 32, "ack_event_receiver")
            _integer(ev["receiver_epoch"], "ack_event_epoch", 1)
            _blob(ev["idempotency_key"], 64, "ack_event_idempotency")
            _blob(ev["envelope_digest"], 64, "ack_event_envelope")
            _blob(ev["ack_digest"], 64, "ack_event_digest")
            _integer(ev["effective_directive"], "ack_event_directive", 1)
            stored_ack = ack_map.get(jid, {}).get("ack_value")
            if not isinstance(stored_ack, dict):
                _fail("transition_ack")
            if (
                ev["effective_directive"] > 5
                or ev["effective_directive"] != job_map[jid]["envelope"]["effective_directive"]
                or ev["receiver_identity"].upper() != _hex(config["receiver_identity"])
                or ev["receiver_epoch"] != int(config["receiver_epoch"])
                or ev["idempotency_key"].upper() != _hex(job_map[jid]["idempotency_key"])
                or ev["envelope_digest"].upper() != _hex(job_map[jid]["envelope_digest"])
                or ev["receiver_identity"].upper() != stored_ack["receiver_identity"].upper()
                or ev["receiver_epoch"] != stored_ack["receiver_epoch"]
                or ev["idempotency_key"].upper() != stored_ack["idempotency_key"].upper()
                or ev["envelope_digest"].upper() != stored_ack["envelope_digest"].upper()
                or ev["effective_directive"] != stored_ack["effective_directive"]
            ):
                _fail("transition_ack_binding")
            _token(ev["acknowledgment_id"], "ack_event_id")
            _integer(ev["policy_result"], "ack_event_policy", 1)
            if ev["policy_result"] > 5 or ev["policy_result"] != job_map[jid]["envelope"]["policy_result"]:
                _fail("ack_event_policy_binding")
            _blob(ev["profile_digest"], 64, "ack_event_profile")
            _blob(ev["verifier_identity"], 32, "ack_event_verifier")
            _integer(ev["verifier_epoch"], "ack_event_verifier_epoch", 1)
            if (
                ev["acknowledgment_id"] != stored_ack["acknowledgment_id"]
                or ev["profile_digest"].upper() != _hex(config["ack_evidence_profile_digest"])
                or ev["verifier_identity"].upper() != _hex(config["verifier_sha256"])
                or ev["verifier_epoch"] != int(config["verifier_epoch"])
                or ev["mode"] != _ACK_EVIDENCE_MODE
            ):
                _fail("ack_event_profile_binding")
            if previous != "LEASED" or status != "ACKNOWLEDGED" or jid not in ack_map or ev["attempt"] != replay_attempt.get(jid) or ev["ack_digest"] != ack_map[jid]["ack_digest"]:
                _fail("transition_ack")
            replay[jid] = "ACKNOWLEDGED"
        elif kind == "HELD":
            if set(ev) != {"at_ms", "status", "attempt", "error_code"}:
                _fail("transition_held_event")
            _integer(ev["at_ms"], "held_time")
            _integer(ev["attempt"], "held_attempt", 1)
            _token(ev["error_code"], "held_error")
            if previous != "LEASED" or status != "HELD" or ev["attempt"] != replay_attempt.get(jid):
                _fail("transition_held")
            replay[jid] = "HELD"
        else:
            _fail("transition_kind")
        expected_head = _sha(_HEAD, expected_head, index.to_bytes(8, "big"), digest)
        if expected_head != after:
            _fail("transition_head")
    if expected_head != head or set(replay) != set(job_map) or any(replay[jid] != job["status"] for jid, job in job_map.items()):
        _fail("transition_final")
    for jid, row in reconciliation_map.items():
        if recon_replay.get(jid) != row["status"]:
            _fail("reconciliation_transition_final")
    counts = {status: sum(1 for job in jobs if job["status"] == status) for status in sorted(_STATUS)}
    if counts["DISCOVERED"] + counts["LEASED"] > int(config["capacity"]):
        _fail("capacity")
    if sum(1 for row in reconciliation if row["status"] in {"DISCOVERED", "LEASED"}) > int(config["capacity"]):
        _fail("reconciliation_capacity")
    return value, {
        "schema": _SCHEMA, "outbox_id": config["outbox_id"], "head_root": _hex(head),
        "status_counts": counts, "transition_count": len(transitions), "config_digest": _hex(config_digest),
        "acknowledged_count": counts["ACKNOWLEDGED"],
        "delivery_unconfirmed_count": counts["DELIVERY_UNCONFIRMED"],
        "reconciliation_counts": {status: sum(1 for row in reconciliation if row["status"] == status) for status in sorted(_RECONCILIATION_STATUS)},
        "profile_digest": _hex(profile_digest), "qualification_receipt_count": len(receipts),
    }


def verify_export_bytes(raw: bytes, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value, summary = _parse_export(raw)
    if expected_config is not None and _json_bytes(expected_config) != _json_bytes(value["config"]):
        _fail("expected_config_mismatch")
    return summary


def _schema(connection: sqlite3.Connection) -> None:
    expected = {"outbox_metadata", "outbox_jobs", "outbox_leases", "outbox_acks", "outbox_reconciliation", "outbox_transitions"}
    actual = {str(row[1]) for row in connection.execute("SELECT type,name FROM sqlite_master WHERE type='table'")}
    if actual != expected:
        _fail("database_objects")


def _db_export(connection: sqlite3.Connection) -> bytes:
    _schema(connection)
    meta = connection.execute("SELECT * FROM outbox_metadata WHERE id=1").fetchone()
    if meta is None or len(meta) != 12 or int(meta[0]) != 1 or int(meta[1]) != _SCHEMA_VERSION:
        _fail("metadata_missing")
    try:
        config_value = json.loads(bytes(meta[3]).decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise IndependentOfficialHandoffError("metadata_config") from exc
    config, config_bytes, config_digest = _parse_config(config_value)
    if (
        bytes(meta[3]) != config_bytes or bytes(meta[4]) != config_digest
        or str(meta[2]) != config["outbox_id"] or str(meta[5]) != config["application_id"]
        or bytes(meta[6]) != config["application_config_digest"]
        or bytes(meta[7]) != config["state_store_identity"]
        or bytes(meta[8]) != config["receiver_identity"]
        or int(meta[9]) != config["receiver_epoch"]
    ):
        _fail("metadata_config_binding")
    _blob(_hex(bytes(meta[10])), 64, "metadata_head")
    _integer(int(meta[11]), "metadata_sequence")
    for row in connection.execute("SELECT status FROM outbox_acks"):
        if row[0] != "ACKNOWLEDGED":
            _fail("ack_status")
    blob = lambda value: None if value is None else _hex(bytes(value))
    profile_bytes = acknowledgment_profile_bytes(
        verifier_identity=config["verifier_sha256"], verifier_epoch=int(config["verifier_epoch"]),
        receiver_identity=config["receiver_identity"], receiver_epoch=int(config["receiver_epoch"]),
    )
    profile_digest = acknowledgment_profile_digest(
        verifier_identity=config["verifier_sha256"], verifier_epoch=int(config["verifier_epoch"]),
        receiver_identity=config["receiver_identity"], receiver_epoch=int(config["receiver_epoch"]),
    )
    receipts = [
        {"job_id": str(row[0]), "receipt_bytes": blob(row[6])}
        for row in connection.execute("SELECT * FROM outbox_acks ORDER BY job_id")
    ]
    value = {
        "schema": _SCHEMA,
        "config": config_value,
        "metadata": {"head_root": blob(meta[10]), "next_sequence": int(meta[11])},
        "jobs": [
            {"job_id": str(row[0]), "operation_id": blob(row[1]), "envelope_digest": blob(row[2]), "envelope_bytes": blob(row[3]), "idempotency_key": blob(row[4]), "status": str(row[5]), "discovery_sequence": int(row[6]), "attempt": int(row[7]), "next_eligible_ms": int(row[8]), "created_ms": int(row[9]), "updated_ms": int(row[10]), "last_error_code": row[11]}
            for row in connection.execute("SELECT * FROM outbox_jobs ORDER BY discovery_sequence")
        ],
        "leases": [
            {"job_id": str(row[0]), "worker_id": str(row[1]), "token": blob(row[2]), "attempt": int(row[3]), "leased_ms": int(row[4]), "expires_ms": int(row[5])}
            for row in connection.execute("SELECT * FROM outbox_leases ORDER BY job_id")
        ],
        "acks": [
            {"job_id": str(row[0]), "ack_bytes": blob(row[2]), "ack_digest": blob(row[3]), "operation_id": blob(row[4]), "completed_ms": int(row[5]), "ack_receipt": blob(row[6]), "profile_digest": blob(row[7])}
            for row in connection.execute("SELECT * FROM outbox_acks ORDER BY job_id")
        ],
        "profiles": [{"profile_digest": _hex(profile_digest), "profile_bytes": _hex(profile_bytes)}],
        "receipts": receipts,
        "reconciliation": [
            {"job_id": str(row[0]), "operation_id": blob(row[1]), "envelope_digest": blob(row[2]), "idempotency_key": blob(row[3]), "status": str(row[4]), "worker_id": row[5], "token": blob(row[6]), "attempt": int(row[7]), "leased_ms": None if row[8] is None else int(row[8]), "expires_ms": None if row[9] is None else int(row[9]), "next_eligible_ms": int(row[10]), "discovered_ms": int(row[11]), "updated_ms": int(row[12]), "last_error_code": row[13]}
            for row in connection.execute("SELECT * FROM outbox_reconciliation ORDER BY job_id")
        ],
        "transitions": [
            {"sequence": int(row[0]), "transition_kind": str(row[1]), "job_id": str(row[2]), "before_root": blob(row[3]), "after_root": blob(row[4]), "event_bytes": blob(row[5]), "event_digest": blob(row[6])}
            for row in connection.execute("SELECT * FROM outbox_transitions ORDER BY sequence")
        ],
    }
    return _json_bytes(value)


def verify_database(path: Path, *, expected_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("database_path")
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        connection.execute("BEGIN")
        raw = _db_export(connection)
    except sqlite3.Error as exc:
        raise IndependentOfficialHandoffError("database_read") from exc
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass
    return verify_export_bytes(raw, expected_config=expected_config)


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE outbox_metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
          outbox_id TEXT NOT NULL, config_json BLOB NOT NULL, config_digest BLOB NOT NULL,
          application_id TEXT NOT NULL, application_config_digest BLOB NOT NULL, state_store_identity BLOB NOT NULL,
          receiver_identity BLOB NOT NULL, receiver_epoch INTEGER NOT NULL, head_root BLOB NOT NULL, next_sequence INTEGER NOT NULL);
        CREATE TABLE outbox_jobs (job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE, envelope_digest BLOB NOT NULL UNIQUE,
          envelope_bytes BLOB NOT NULL, idempotency_key BLOB NOT NULL UNIQUE, status TEXT NOT NULL, discovery_sequence INTEGER NOT NULL UNIQUE,
          attempt INTEGER NOT NULL, next_eligible_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_error_code TEXT);
        CREATE TABLE outbox_leases (job_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, token BLOB NOT NULL, attempt INTEGER NOT NULL, leased_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
          FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id));
        CREATE TABLE outbox_acks (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, ack_bytes BLOB NOT NULL, ack_digest BLOB NOT NULL,
          operation_id BLOB NOT NULL UNIQUE, completed_ms INTEGER NOT NULL, ack_receipt BLOB NOT NULL,
          profile_digest BLOB NOT NULL, FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id));
        CREATE TABLE outbox_reconciliation (job_id TEXT PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE,
          envelope_digest BLOB NOT NULL UNIQUE, idempotency_key BLOB NOT NULL UNIQUE, status TEXT NOT NULL,
          worker_id TEXT, token BLOB, attempt INTEGER NOT NULL, leased_ms INTEGER, expires_ms INTEGER,
          next_eligible_ms INTEGER NOT NULL, discovered_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
          last_error_code TEXT, FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id));
        CREATE TABLE outbox_transitions (sequence INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL, job_id TEXT NOT NULL,
          before_root BLOB NOT NULL, after_root BLOB NOT NULL, event_bytes BLOB NOT NULL, event_digest BLOB NOT NULL UNIQUE,
          FOREIGN KEY(job_id) REFERENCES outbox_jobs(job_id));
        """
    )


def restore_export_to_fresh_database(path: Path, raw: bytes) -> dict[str, Any]:
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        _fail("restore_target")
    value, summary = _parse_export(raw)
    connection = sqlite3.connect(path)
    try:
        _create_schema(connection)
        config = value["config"]
        config_bytes = _json_bytes(config)
        config_digest = _sha(_MATERIAL, config_bytes)
        meta = value["metadata"]
        connection.execute(
            "INSERT INTO outbox_metadata VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (1, _SCHEMA_VERSION, config["outbox_id"], config_bytes, config_digest, config["application_id"], _blob(config["application_config_digest"],64,"app_digest"), _blob(config["state_store_identity"],64,"state"), _blob(config["receiver_identity"],32,"receiver"), config["receiver_epoch"], _blob(meta["head_root"],64,"head"), meta["next_sequence"]),
        )
        for job in value["jobs"]:
            connection.execute("INSERT INTO outbox_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (job["job_id"], _blob(job["operation_id"],64,"op"), _blob(job["envelope_digest"],64,"env_digest"), _blob(job["envelope_bytes"],None,"env"), _blob(job["idempotency_key"],64,"idem"), job["status"], job["discovery_sequence"], job["attempt"], job["next_eligible_ms"], job["created_ms"], job["updated_ms"], job["last_error_code"]))
        for lease in value["leases"]:
            connection.execute("INSERT INTO outbox_leases VALUES (?,?,?,?,?,?)", (lease["job_id"], lease["worker_id"], _blob(lease["token"],24,"token"), lease["attempt"], lease["leased_ms"], lease["expires_ms"]))
        for ack in value["acks"]:
            connection.execute("INSERT INTO outbox_acks VALUES (?,?,?,?,?,?,?,?)", (ack["job_id"], "ACKNOWLEDGED", _blob(ack["ack_bytes"],None,"ack"), _blob(ack["ack_digest"],64,"ack_digest"), _blob(ack["operation_id"],64,"ack_op"), ack["completed_ms"], _blob(ack["ack_receipt"],None,"ack_receipt"), _blob(ack["profile_digest"],64,"profile_digest")))
        for row in value["reconciliation"]:
            connection.execute("INSERT INTO outbox_reconciliation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (row["job_id"], _blob(row["operation_id"],64,"reconciliation_operation"), _blob(row["envelope_digest"],64,"reconciliation_envelope"), _blob(row["idempotency_key"],64,"reconciliation_idempotency"), row["status"], row["worker_id"], None if row["token"] is None else _blob(row["token"],24,"reconciliation_token"), row["attempt"], row["leased_ms"], row["expires_ms"], row["next_eligible_ms"], row["discovered_ms"], row["updated_ms"], row["last_error_code"]))
        for transition in value["transitions"]:
            connection.execute("INSERT INTO outbox_transitions VALUES (?,?,?,?,?,?,?)", (transition["sequence"], transition["transition_kind"], transition["job_id"], _blob(transition["before_root"],64,"before"), _blob(transition["after_root"],64,"after"), _blob(transition["event_bytes"],None,"event"), _blob(transition["event_digest"],64,"event_digest")))
        connection.commit()
    finally:
        connection.close()
    verified = verify_database(path, expected_config=config)
    return verified if verified == summary else (_fail("restore_parity"))


__all__ = (
    "AppliedApplicationViewV1", "IndependentOfficialHandoffError", "acknowledgment_digest",
    "acknowledgment_profile_bytes", "acknowledgment_profile_digest", "build_ack_qualification_receipt",
    "envelope_digest", "parse_ack_qualification_receipt", "parse_acknowledgment_bytes", "parse_envelope_bytes",
    "read_applied_application", "validate_acknowledgment",
    "restore_export_to_fresh_database", "verify_database", "verify_export_bytes",
)
