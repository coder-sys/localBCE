"""Fail-closed transport and result binding for the exact Lean semantic kernel.

The native adapter is the only process boundary in this module.  It receives
the original continuity bundle bytes, and the existing Windows containment
runner owns process, memory, timeout, output, and cleanup limits.  This module
does not evaluate policy or reconstruct a bundle; it only decodes the pinned
adapter result and compares it with the independently reconstructed details.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Protocol

from app.minimal_clearance_resource_limits import ADMISSION_CAP_BYTES, ACTIVE_PROCESS_LIMIT
from app.minimal_clearance_verifier_process import (
    VerifierProcessError,
    run_contained_verifier_stream,
)
from parked.state_clearance.experiments.native_v3_plaintext_continuity.independent import (
    MAX_BUNDLE_BYTES,
    IndependentBundleDetails,
    REASON_CONTROL_INTERVAL,
    REASON_EXPIRED_OR_TERMINATED,
    REASON_INCOMPLETE_OR_AMBIGUOUS,
    REASON_MISSING_AUTHORITATIVE,
    REASON_STALE_RULE,
    REASON_VALID,
)


# The wire version remains /2; State distinguishes the completed contract by
# requiring the full exact result field set below, not by accepting the legacy
# 28-field /2 line.
SEMANTIC_ADAPTER_PROTOCOL = "BL-SEMANTIC-ADAPTER/2"
SEMANTIC_KERNEL_SCHEMA = "BLCBND02/v2"
SEMANTIC_KERNEL_RESULT = "PASS"
SEMANTIC_KERNEL_MAX_TIMEOUT_SECONDS = 30.0
SEMANTIC_KERNEL_PACKAGE_PROTOCOL = "BL-SEMANTIC-PACKAGE/1"
SEMANTIC_KERNEL_SOURCE_MANIFEST_PROTOCOL = "BL-SEMANTIC-SOURCE-MANIFEST/1"
SEMANTIC_KERNEL_BUILD_RECEIPT_PROTOCOL = "BL-SEMANTIC-BUILD-RECEIPT/1"
STATE_KERNEL_SCHEMA = "BLSDCLR01/v1"
STATE_ADAPTER_PROTOCOL = "BL-STATE-SEMANTIC-ADAPTER/1"
STATE_KERNEL_BUILD_ID = "BLSK-BLSDCLR01-STATE-V1"
STATE_KERNEL_REQUEST_MAGIC = b"BLSDRQ01"
STATE_KERNEL_REQUEST_VERSION = 1
MAX_STATE_KERNEL_REQUEST_BYTES = MAX_BUNDLE_BYTES + 3_110
_GIT_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_PACKAGE_FILE_BYTES = 256 * 1024 * 1024
_PACKAGE_HASH_CHUNK_BYTES = 1024 * 1024

POLICY_NAMES = {
    1: "PASS",
    2: "MISSING",
    3: "AMBIGUOUS",
    4: "FAIL",
}
DIRECTIVE_NAMES = {
    1: "CLEAR",
    2: "HOLD",
    3: "HUMAN_REVIEW",
    4: "BLOCK",
    5: "EXCEPTION_APPROVED",
}
REASON_NAMES = {
    "VALID_CONTINUITY",
    "AUTHORITATIVE_ABSENCE",
    "EXPIRED_OR_TERMINATED",
    "INCOMPLETE_OR_AMBIGUOUS",
    "STALE_RULE_INTERVAL",
    "CONTROL_INTERVAL",
}
REASON_IDS = {
    "VALID_CONTINUITY": REASON_VALID,
    "AUTHORITATIVE_ABSENCE": REASON_MISSING_AUTHORITATIVE,
    "EXPIRED_OR_TERMINATED": REASON_EXPIRED_OR_TERMINATED,
    "INCOMPLETE_OR_AMBIGUOUS": REASON_INCOMPLETE_OR_AMBIGUOUS,
    "STALE_RULE_INTERVAL": REASON_STALE_RULE,
    "CONTROL_INTERVAL": REASON_CONTROL_INTERVAL,
}
DIRECTIVE_POLICY = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}

_HEX_64_RE = re.compile(r"^[0-9a-f]{128}$")
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")


class SemanticKernelBindingError(RuntimeError):
    """The exact semantic-kernel boundary could not be established."""


class SemanticKernelResultMismatch(SemanticKernelBindingError):
    """The accepted native result does not equal independent reconstruction."""


class SemanticKernelPort(Protocol):
    """The narrow port consumed by the direct-state composition root."""

    def evaluate(self, bundle: bytes) -> "SemanticKernelResult":
        """Evaluate exactly ``bundle`` and return the checked result."""

    def evaluate_state_request(self, request: "StateKernelRequest") -> "StateKernelResult":
        """Evaluate one database-bound State request through the exact kernel."""


def _hex_value(value: str, *, field: str, size: int) -> bytes:
    pattern = _HEX_64_RE if size == 64 else _HEX_32_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SemanticKernelBindingError(f"semantic_kernel_field:{field}")
    return bytes.fromhex(value)


def _decimal_value(value: str, *, field: str) -> int:
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise SemanticKernelBindingError(f"semantic_kernel_field:{field}")
    return int(value, 10)


def _ascii_value(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or any(character in value for character in "\x00\r\n;=")
    ):
        raise SemanticKernelBindingError(f"semantic_kernel_field:{field}")
    return value


@dataclass(frozen=True, slots=True)
class SemanticKernelResult:
    """The complete semantic result surfaced by the pinned adapter.

    All identity values are decoded from exactly 64-byte lower-case hex
    fields.  The fields not used by the SQLite operation are still required so
    that a native result cannot silently omit a semantic binding.
    """

    protocol: str
    schema: str
    result: str
    kernel_build_id: str
    artifact_sha256: bytes
    source_binding_sha256: bytes
    bundle_id: bytes
    bundle_bytes: int
    policy: int
    directive: int
    reason: str
    reason_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    join_id: bytes
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    mode_id: bytes
    evaluator_id: bytes
    control_set_id: bytes
    rule_id: bytes
    phase0_receipt_binding: bytes
    source_root: bytes
    completeness_id: bytes
    exception_id: bytes
    before_state_id: bytes
    after_state_id: bytes
    receipt_id: bytes
    chronology_id: bytes
    replay_id: bytes
    decision_path_id: bytes
    before_audit_head: bytes
    before_continuity_root: bytes
    after_audit_head: bytes
    after_continuity_root: bytes
    audit_head_after: bytes
    continuity_root_after: bytes
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int
    continuity_epoch: int
    sequence_before: int
    sequence_after: int
    proof_suite_id: str
    proof_session_accepted: bool
    economic_mutation: bool
    replay_stateful: bool

    def __post_init__(self) -> None:
        if self.protocol != SEMANTIC_ADAPTER_PROTOCOL:
            raise SemanticKernelBindingError("semantic_kernel_protocol")
        if self.schema != SEMANTIC_KERNEL_SCHEMA or self.result != SEMANTIC_KERNEL_RESULT:
            raise SemanticKernelBindingError("semantic_kernel_result_header")
        _ascii_value(self.kernel_build_id, field="kernel_build_id")
        if type(self.artifact_sha256) is not bytes or len(self.artifact_sha256) != 32:
            raise SemanticKernelBindingError("semantic_kernel_artifact_hash")
        if type(self.source_binding_sha256) is not bytes or len(self.source_binding_sha256) != 32:
            raise SemanticKernelBindingError("semantic_kernel_source_hash")
        for field in (
            "bundle_id",
            "reason_id",
            "request_id",
            "attempt_id",
            "decision_id",
            "join_id",
            "profile_id",
            "schema_id",
            "program_id",
            "mode_id",
            "evaluator_id",
            "control_set_id",
            "rule_id",
            "phase0_receipt_binding",
            "source_root",
            "completeness_id",
            "exception_id",
            "before_state_id",
            "after_state_id",
            "receipt_id",
            "chronology_id",
            "replay_id",
            "decision_path_id",
            "before_audit_head",
            "before_continuity_root",
            "after_audit_head",
            "after_continuity_root",
            "audit_head_after",
            "continuity_root_after",
        ):
            value = getattr(self, field)
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise SemanticKernelBindingError(f"semantic_kernel_identity:{field}")
        if self.policy not in POLICY_NAMES or self.directive not in DIRECTIVE_NAMES:
            raise SemanticKernelBindingError("semantic_kernel_policy_directive")
        if DIRECTIVE_POLICY[self.directive] != self.policy:
            raise SemanticKernelBindingError("semantic_kernel_policy_directive")
        if self.reason not in REASON_NAMES:
            raise SemanticKernelBindingError("semantic_kernel_reason")
        if self.reason_id != REASON_IDS[self.reason]:
            raise SemanticKernelBindingError("semantic_kernel_reason_identity")
        if type(self.bundle_bytes) is not int or not 0 < self.bundle_bytes <= MAX_BUNDLE_BYTES:
            raise SemanticKernelBindingError("semantic_kernel_bundle_length")
        for field in (
            "event_time",
            "observation_time",
            "rule_effective_time",
            "decision_time",
            "continuity_epoch",
            "sequence_before",
            "sequence_after",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise SemanticKernelBindingError(f"semantic_kernel_number:{field}")
        if self.proof_suite_id != "NONE":
            raise SemanticKernelBindingError("semantic_kernel_proof_suite")
        if self.proof_session_accepted or self.economic_mutation or self.replay_stateful:
            raise SemanticKernelBindingError("semantic_kernel_authority_flags")


_RESULT_FIELDS = frozenset(
    {
        "schema",
        "result",
        "kernel_build_id",
        "artifact_sha256",
        "source_binding_sha256",
        "bundle_id",
        "bundle_bytes",
        "policy",
        "directive",
        "reason",
        "reason_id",
        "request_id",
        "attempt_id",
        "decision_id",
        "join_id",
        "profile_id",
        "schema_id",
        "program_id",
        "mode_id",
        "evaluator_id",
        "control_set_id",
        "rule_id",
        "phase0_receipt_binding",
        "source_root",
        "completeness_id",
        "exception_id",
        "before_state_id",
        "after_state_id",
        "receipt_id",
        "chronology_id",
        "replay_id",
        "decision_path_id",
        "before_audit_head",
        "before_continuity_root",
        "after_audit_head",
        "after_continuity_root",
        "audit_head_after",
        "continuity_root_after",
        "event_time",
        "observation_time",
        "rule_effective_time",
        "decision_time",
        "continuity_epoch",
        "sequence_before",
        "sequence_after",
        "proof_suite_id",
        "proof_session_accepted",
        "economic_mutation",
        "replay_stateful",
    }
)


def _parse_bool(value: str, *, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise SemanticKernelBindingError(f"semantic_kernel_field:{field}")


def parse_semantic_adapter_output(output: bytes) -> SemanticKernelResult:
    """Parse one exact, newline-terminated adapter result line."""

    if type(output) is not bytes or not output.endswith(b"\n") or output.count(b"\n") != 1:
        raise SemanticKernelBindingError("semantic_kernel_output_framing")
    if b"\r" in output:
        raise SemanticKernelBindingError("semantic_kernel_output_framing")
    try:
        line = output[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SemanticKernelBindingError("semantic_kernel_output_ascii") from exc
    fields = line.split(";")
    if not fields or fields[0] != SEMANTIC_ADAPTER_PROTOCOL:
        raise SemanticKernelBindingError("semantic_kernel_output_protocol")
    values: dict[str, str] = {}
    for token in fields[1:]:
        if token.count("=") != 1:
            raise SemanticKernelBindingError("semantic_kernel_output_field")
        key, value = token.split("=", 1)
        if not key or key in values or not value:
            raise SemanticKernelBindingError("semantic_kernel_output_field")
        _ascii_value(value, field=key)
        values[key] = value
    if frozenset(values) != _RESULT_FIELDS:
        raise SemanticKernelBindingError("semantic_kernel_output_field_set")

    ids = {
        field: _hex_value(values[field], field=field, size=64)
        for field in (
            "bundle_id",
            "reason_id",
            "request_id",
            "attempt_id",
            "decision_id",
            "join_id",
            "profile_id",
            "schema_id",
            "program_id",
            "mode_id",
            "evaluator_id",
            "control_set_id",
            "rule_id",
            "phase0_receipt_binding",
            "source_root",
            "completeness_id",
            "exception_id",
            "before_state_id",
            "after_state_id",
            "receipt_id",
            "chronology_id",
            "replay_id",
            "decision_path_id",
            "before_audit_head",
            "before_continuity_root",
            "after_audit_head",
            "after_continuity_root",
            "audit_head_after",
            "continuity_root_after",
        )
    }
    try:
        policy = {name: code for code, name in POLICY_NAMES.items()}[values["policy"]]
        directive = {name: code for code, name in DIRECTIVE_NAMES.items()}[values["directive"]]
    except KeyError as exc:
        raise SemanticKernelBindingError("semantic_kernel_policy_directive") from exc
    result = SemanticKernelResult(
        protocol=SEMANTIC_ADAPTER_PROTOCOL,
        schema=values["schema"],
        result=values["result"],
        kernel_build_id=values["kernel_build_id"],
        artifact_sha256=_hex_value(values["artifact_sha256"], field="artifact_sha256", size=32),
        source_binding_sha256=_hex_value(
            values["source_binding_sha256"], field="source_binding_sha256", size=32
        ),
        bundle_bytes=_decimal_value(values["bundle_bytes"], field="bundle_bytes"),
        policy=policy,
        directive=directive,
        reason=values["reason"],
        **ids,
        event_time=_decimal_value(values["event_time"], field="event_time"),
        observation_time=_decimal_value(values["observation_time"], field="observation_time"),
        rule_effective_time=_decimal_value(
            values["rule_effective_time"], field="rule_effective_time"
        ),
        decision_time=_decimal_value(values["decision_time"], field="decision_time"),
        continuity_epoch=_decimal_value(values["continuity_epoch"], field="continuity_epoch"),
        sequence_before=_decimal_value(values["sequence_before"], field="sequence_before"),
        sequence_after=_decimal_value(values["sequence_after"], field="sequence_after"),
        proof_suite_id=values["proof_suite_id"],
        proof_session_accepted=_parse_bool(
            values["proof_session_accepted"], field="proof_session_accepted"
        ),
        economic_mutation=_parse_bool(values["economic_mutation"], field="economic_mutation"),
        replay_stateful=_parse_bool(values["replay_stateful"], field="replay_stateful"),
    )
    if result.result != SEMANTIC_KERNEL_RESULT:
        raise SemanticKernelBindingError("semantic_kernel_result_rejected")
    return result


_STATE_REQUEST_ID_FIELDS = (
    "profile_id",
    "schema_id",
    "program_id",
    "mode_id",
    "evaluator_id",
    "control_set_id",
    "rule_id",
    "phase0_receipt_binding",
    "governance_commitment",
)
_STATE_REQUEST_ROOT_FIELDS = (
    "global_state_binding",
    "global_audit_head",
    "nullifier_root",
    "payment_root",
    "clearance_root",
    "direct_state_binding",
    "database_state_binding",
    "direct_payment_root",
    "direct_audit_head",
    "last_operation_digest",
    "continuity_state_id",
    "continuity_audit_head",
    "continuity_root",
)
_STATE_OPERATION_ID_FIELDS = (
    "bundle_id",
    "receipt_id",
    "request_id",
    "attempt_id",
    "decision_id",
    "join_id",
    "source_root",
    "profile_id",
    "schema_id",
    "program_id",
    "mode_id",
    "evaluator_id",
    "control_set_id",
    "rule_id",
    "phase0_receipt_binding",
    "exception_id",
    "continuity_before_state_id",
    "continuity_after_state_id",
    "continuity_before_audit_head",
    "continuity_after_audit_head",
    "continuity_before_root",
    "continuity_after_root",
)
_STATE_OPERATION_INT_FIELDS = (
    "policy_result",
    "effective_directive",
    "event_time",
    "observation_time",
    "rule_effective_time",
    "decision_time",
    "continuity_epoch",
    "continuity_sequence_before",
    "continuity_sequence_after",
)
_STATE_PRIOR_RECORD_BYTES = 1 + 1 + 64 + 16 * 64 + 9 * 8 + 6 * 64
_STATE_U64_MAX = (1 << 64) - 1
_STATE_U32_MAX = (1 << 32) - 1
_STATE_INPUT_DOMAIN = b"BL/DIRECT-STATE-OWNED/STATE-INPUT/v1\x00"
_STATE_CONTINUITY_CONTEXT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2\x00"
_STATE_CONTINUITY_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ID/v2\x00"
_STATE_CONTINUITY_AUDIT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2\x00"
_STATE_CONTINUITY_ROOT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/ROOT/v2\x00"


def _state_sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def _state_u64(value: int, *, field: str) -> bytes:
    if type(value) is not int or not 0 <= value <= _STATE_U64_MAX:
        raise SemanticKernelBindingError(f"state_kernel_number:{field}")
    return value.to_bytes(8, "big")


def _state_continuity_id(
    *,
    profile_id: bytes,
    mode_id: bytes,
    sequence: int,
    row_count: int,
    audit_head: bytes,
    continuity_root: bytes,
) -> bytes:
    if type(row_count) is not int or not 0 <= row_count <= _STATE_U32_MAX:
        raise SemanticKernelBindingError("state_kernel_number:continuity_row_count")
    context_id = _state_sha(_STATE_CONTINUITY_CONTEXT_DOMAIN, profile_id, mode_id)
    raw = b"".join(
        (
            b"BLCSTA02",
            (2).to_bytes(2, "big"),
            b"\x00\x00",
            context_id,
            _state_u64(sequence, field="continuity_sequence"),
            row_count.to_bytes(4, "big"),
            b"\x00" * 4,
            audit_head,
            continuity_root,
        )
    )
    return _state_sha(_STATE_CONTINUITY_ID_DOMAIN, raw)


@dataclass(frozen=True, slots=True)
class StateKernelPriorOperation:
    """Exact persisted operation supplied to Lean for retry classification."""

    operation_digest: bytes
    operation_version: int
    clearance_advanced: bool
    bundle_id: bytes
    receipt_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    join_id: bytes
    source_root: bytes
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    mode_id: bytes
    evaluator_id: bytes
    control_set_id: bytes
    rule_id: bytes
    phase0_receipt_binding: bytes
    exception_id: bytes
    policy_result: int
    effective_directive: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int
    continuity_epoch: int
    continuity_sequence_before: int
    continuity_sequence_after: int
    continuity_before_state_id: bytes
    continuity_after_state_id: bytes
    continuity_before_audit_head: bytes
    continuity_after_audit_head: bytes
    continuity_before_root: bytes
    continuity_after_root: bytes

    def __post_init__(self) -> None:
        for name in ("operation_digest", *_STATE_OPERATION_ID_FIELDS):
            value = getattr(self, name)
            if type(value) is not bytes or len(value) != 64 or not any(value):
                raise SemanticKernelBindingError(f"state_kernel_prior_identity:{name}")
        if type(self.operation_version) is not int or self.operation_version not in (0, 1):
            raise SemanticKernelBindingError("state_kernel_prior_version")
        if type(self.clearance_advanced) is not bool:
            raise SemanticKernelBindingError("state_kernel_prior_clearance_flag")
        if self.policy_result not in POLICY_NAMES or self.effective_directive not in DIRECTIVE_NAMES:
            raise SemanticKernelBindingError("state_kernel_prior_policy_directive")
        if DIRECTIVE_POLICY[self.effective_directive] != self.policy_result:
            raise SemanticKernelBindingError("state_kernel_prior_policy_directive")
        if self.clearance_advanced != (self.effective_directive in (1, 5)):
            raise SemanticKernelBindingError("state_kernel_prior_clearance_flag")
        for name in _STATE_OPERATION_INT_FIELDS:
            _state_u64(getattr(self, name), field=name)
        if not (
            self.rule_effective_time
            < self.event_time
            < self.observation_time
            < self.decision_time
        ):
            raise SemanticKernelBindingError("state_kernel_prior_chronology")
        if self.continuity_sequence_after != self.continuity_sequence_before + 1:
            raise SemanticKernelBindingError("state_kernel_prior_sequence")

    def operation_bytes(self) -> bytes:
        identities = b"".join(getattr(self, name) for name in _STATE_OPERATION_ID_FIELDS[:16])
        numbers = b"".join(
            _state_u64(getattr(self, name), field=name)
            for name in _STATE_OPERATION_INT_FIELDS
        )
        state_ids = b"".join(getattr(self, name) for name in _STATE_OPERATION_ID_FIELDS[16:])
        return identities + numbers + state_ids

    def encode(self) -> bytes:
        return bytes((self.operation_version, int(self.clearance_advanced))) + self.operation_digest + self.operation_bytes()

    @classmethod
    def decode(cls, raw: bytes) -> "StateKernelPriorOperation":
        if type(raw) is not bytes or len(raw) != _STATE_PRIOR_RECORD_BYTES:
            raise SemanticKernelBindingError("state_kernel_prior_record_length")
        version, advanced = raw[0], raw[1]
        if advanced not in (0, 1):
            raise SemanticKernelBindingError("state_kernel_prior_record_flag")
        offset = 2
        digest = raw[offset : offset + 64]
        offset += 64
        ids = {}
        for name in _STATE_OPERATION_ID_FIELDS[:16]:
            ids[name] = raw[offset : offset + 64]
            offset += 64
        numbers = {}
        for name in _STATE_OPERATION_INT_FIELDS:
            numbers[name] = int.from_bytes(raw[offset : offset + 8], "big")
            offset += 8
        for name in _STATE_OPERATION_ID_FIELDS[16:]:
            ids[name] = raw[offset : offset + 64]
            offset += 64
        value = cls(
            operation_digest=digest,
            operation_version=version,
            clearance_advanced=bool(advanced),
            **ids,
            **numbers,
        )
        if value.encode() != raw:
            raise SemanticKernelBindingError("state_kernel_prior_record_noncanonical")
        return value


@dataclass(frozen=True, slots=True)
class StateKernelRequest:
    """Canonical v1 request assembled from the live SQLite transaction."""

    bundle: bytes
    command_id: bytes
    expected_revision: int
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    mode_id: bytes
    evaluator_id: bytes
    control_set_id: bytes
    rule_id: bytes
    phase0_receipt_binding: bytes
    governance_commitment: bytes
    continuity_epoch: int
    global_sequence: int
    anti_rollback_epoch: int
    global_state_binding: bytes
    global_audit_head: bytes
    nullifier_root: bytes
    payment_root: bytes
    direct_sequence: int
    direct_count: int
    clearance_root: bytes
    direct_state_binding: bytes
    database_state_binding: bytes
    direct_payment_root: bytes
    direct_settled_batch_count: int
    direct_audit_head: bytes
    last_operation_digest: bytes
    continuity_sequence: int
    continuity_row_count: int
    continuity_state_id: bytes
    continuity_audit_head: bytes
    continuity_root: bytes
    prior_operation: StateKernelPriorOperation | None = None

    def __post_init__(self) -> None:
        if type(self.bundle) is not bytes or not 0 < len(self.bundle) <= MAX_BUNDLE_BYTES:
            raise SemanticKernelBindingError("state_kernel_bundle_size")
        for name in ("command_id", *_STATE_REQUEST_ID_FIELDS, *_STATE_REQUEST_ROOT_FIELDS):
            value = getattr(self, name)
            if type(value) is not bytes or len(value) != 64:
                raise SemanticKernelBindingError(f"state_kernel_identity:{name}")
            if name != "last_operation_digest" and not any(value):
                raise SemanticKernelBindingError(f"state_kernel_identity:{name}")
        for name in (
            "expected_revision",
            "continuity_epoch",
            "global_sequence",
            "anti_rollback_epoch",
            "direct_sequence",
            "direct_count",
            "direct_settled_batch_count",
            "continuity_sequence",
            "continuity_row_count",
        ):
            _state_u64(getattr(self, name), field=name)
        if self.continuity_row_count > _STATE_U32_MAX:
            raise SemanticKernelBindingError("state_kernel_number:continuity_row_count")
        if self.direct_count == 0:
            if any(self.last_operation_digest):
                raise SemanticKernelBindingError("state_kernel_genesis_last_operation")
        elif not any(self.last_operation_digest):
            raise SemanticKernelBindingError("state_kernel_current_last_operation")
        if not (
            self.global_sequence
            == self.direct_sequence
            == self.direct_count
            == self.continuity_sequence
            == self.continuity_row_count
        ):
            raise SemanticKernelBindingError("state_kernel_current_revision_mismatch")
        if self.continuity_epoch != 7:
            raise SemanticKernelBindingError("state_kernel_current_epoch")
        if (
            self.global_state_binding != self.database_state_binding
            or self.global_audit_head != self.direct_audit_head
            or self.payment_root != self.direct_payment_root
        ):
            raise SemanticKernelBindingError("state_kernel_current_state_binding")
        calculated_id = _state_continuity_id(
            profile_id=self.profile_id,
            mode_id=self.mode_id,
            sequence=self.continuity_sequence,
            row_count=self.continuity_row_count,
            audit_head=self.continuity_audit_head,
            continuity_root=self.continuity_root,
        )
        if calculated_id != self.continuity_state_id:
            raise SemanticKernelBindingError("state_kernel_current_continuity_id")
        if self.prior_operation is not None and type(self.prior_operation) is not StateKernelPriorOperation:
            raise SemanticKernelBindingError("state_kernel_prior_record_type")

    def encode(self) -> bytes:
        chunks = [
            STATE_KERNEL_REQUEST_MAGIC,
            STATE_KERNEL_REQUEST_VERSION.to_bytes(2, "big"),
            b"\x00\x00",
            len(self.bundle).to_bytes(4, "big"),
            self.bundle,
            self.command_id,
            _state_u64(self.expected_revision, field="expected_revision"),
        ]
        chunks.extend(getattr(self, name) for name in _STATE_REQUEST_ID_FIELDS)
        chunks.extend(
            _state_u64(getattr(self, name), field=name)
            for name in ("continuity_epoch", "global_sequence", "anti_rollback_epoch")
        )
        chunks.extend(getattr(self, name) for name in _STATE_REQUEST_ROOT_FIELDS[:4])
        chunks.extend(
            _state_u64(getattr(self, name), field=name)
            for name in ("direct_sequence", "direct_count", "direct_settled_batch_count")
        )
        chunks.extend(getattr(self, name) for name in _STATE_REQUEST_ROOT_FIELDS[4:10])
        chunks.extend(
            _state_u64(getattr(self, name), field=name)
            for name in ("continuity_sequence", "continuity_row_count")
        )
        chunks.extend(getattr(self, name) for name in _STATE_REQUEST_ROOT_FIELDS[10:])
        prior = b"" if self.prior_operation is None else self.prior_operation.encode()
        chunks.extend((len(prior).to_bytes(4, "big"), prior))
        encoded = b"".join(chunks)
        if len(encoded) > MAX_STATE_KERNEL_REQUEST_BYTES:
            raise SemanticKernelBindingError("state_kernel_request_size")
        return encoded

    @property
    def input_sha3_512(self) -> bytes:
        return _state_sha(_STATE_INPUT_DOMAIN, self.encode())


def parse_state_kernel_request(encoded: bytes) -> StateKernelRequest:
    """Parse one canonical BLSDRQ01/v1 request without accepting trailing bytes."""

    if type(encoded) is not bytes or not 16 <= len(encoded) <= MAX_STATE_KERNEL_REQUEST_BYTES:
        raise SemanticKernelBindingError("state_kernel_request_size")
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        if end > len(encoded):
            raise SemanticKernelBindingError("state_kernel_request_truncated")
        value = encoded[offset:end]
        offset = end
        return value

    if take(8) != STATE_KERNEL_REQUEST_MAGIC:
        raise SemanticKernelBindingError("state_kernel_request_magic")
    if int.from_bytes(take(2), "big") != STATE_KERNEL_REQUEST_VERSION or take(2) != b"\x00\x00":
        raise SemanticKernelBindingError("state_kernel_request_version")
    bundle_length = int.from_bytes(take(4), "big")
    if not 0 < bundle_length <= MAX_BUNDLE_BYTES:
        raise SemanticKernelBindingError("state_kernel_bundle_size")
    bundle = take(bundle_length)
    command_id = take(64)
    expected_revision = int.from_bytes(take(8), "big")
    ids = {name: take(64) for name in _STATE_REQUEST_ID_FIELDS}
    numbers = {
        name: int.from_bytes(take(8), "big")
        for name in ("continuity_epoch", "global_sequence", "anti_rollback_epoch")
    }
    roots = {name: take(64) for name in _STATE_REQUEST_ROOT_FIELDS[:4]}
    numbers.update(
        {
            name: int.from_bytes(take(8), "big")
            for name in ("direct_sequence", "direct_count", "direct_settled_batch_count")
        }
    )
    roots.update({name: take(64) for name in _STATE_REQUEST_ROOT_FIELDS[4:10]})
    numbers.update(
        {
            name: int.from_bytes(take(8), "big")
            for name in ("continuity_sequence", "continuity_row_count")
        }
    )
    roots.update({name: take(64) for name in _STATE_REQUEST_ROOT_FIELDS[10:]})
    prior_length = int.from_bytes(take(4), "big")
    if prior_length not in (0, _STATE_PRIOR_RECORD_BYTES):
        raise SemanticKernelBindingError("state_kernel_prior_record_length")
    prior = StateKernelPriorOperation.decode(take(prior_length)) if prior_length else None
    if offset != len(encoded):
        raise SemanticKernelBindingError("state_kernel_request_trailing_bytes")
    request = StateKernelRequest(
        bundle=bundle,
        command_id=command_id,
        expected_revision=expected_revision,
        prior_operation=prior,
        **ids,
        **numbers,
        **roots,
    )
    if request.encode() != encoded:
        raise SemanticKernelBindingError("state_kernel_request_noncanonical")
    return request


_STATE_RESULT_ID_FIELDS = (
    "input_sha3_512",
    "command_id",
    "bundle_id",
    "reason_id",
    "request_id",
    "attempt_id",
    "decision_id",
    "join_id",
    "profile_id",
    "schema_id",
    "program_id",
    "mode_id",
    "evaluator_id",
    "control_set_id",
    "rule_id",
    "phase0_receipt_binding",
    "source_root",
    "completeness_id",
    "exception_id",
    "before_state_id",
    "after_state_id",
    "receipt_id",
    "chronology_id",
    "replay_id",
    "decision_path_id",
    "before_audit_head",
    "before_continuity_root",
    "after_audit_head",
    "after_continuity_root",
    "audit_head_after",
    "continuity_root_after",
    "evidence_request_id",
    "evidence_decision_id",
    "evidence_join_id",
    "evidence_receipt_id",
    "evidence_decision_path_id",
    "prior_operation_digest",
)
_STATE_RESULT_FIELDS = frozenset(
    {
        "schema",
        "result",
        "kernel_build_id",
        "artifact_sha256",
        "source_binding_sha256",
        "input_sha3_512",
        "command_id",
        "expected_revision",
        "current_sequence",
        "bundle_id",
        "bundle_bytes",
        "policy",
        "directive",
        "reason",
        "reason_id",
        "request_id",
        "attempt_id",
        "decision_id",
        "join_id",
        "profile_id",
        "schema_id",
        "program_id",
        "mode_id",
        "evaluator_id",
        "control_set_id",
        "rule_id",
        "phase0_receipt_binding",
        "source_root",
        "completeness_id",
        "exception_id",
        "before_state_id",
        "after_state_id",
        "receipt_id",
        "chronology_id",
        "replay_id",
        "decision_path_id",
        "before_audit_head",
        "before_continuity_root",
        "after_audit_head",
        "after_continuity_root",
        "audit_head_after",
        "continuity_root_after",
        "evidence_request_id",
        "evidence_decision_id",
        "evidence_join_id",
        "evidence_receipt_id",
        "evidence_decision_path_id",
        "event_time",
        "observation_time",
        "rule_effective_time",
        "decision_time",
        "continuity_epoch",
        "sequence_before",
        "sequence_after",
        "proof_suite_id",
        "proof_session_accepted",
        "economic_mutation",
        "replay_stateful",
        "disposition",
        "prior_operation_digest",
    }
)


@dataclass(frozen=True, slots=True)
class StateKernelResult:
    """Strictly parsed result for the additive Lean-controlled State operation."""

    protocol: str
    schema: str
    result: str
    kernel_build_id: str
    artifact_sha256: bytes
    source_binding_sha256: bytes
    input_sha3_512: bytes
    command_id: bytes
    expected_revision: int
    current_sequence: int
    bundle_id: bytes
    bundle_bytes: int
    policy: int
    directive: int
    reason: str
    reason_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    join_id: bytes
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    mode_id: bytes
    evaluator_id: bytes
    control_set_id: bytes
    rule_id: bytes
    phase0_receipt_binding: bytes
    source_root: bytes
    completeness_id: bytes
    exception_id: bytes
    before_state_id: bytes
    after_state_id: bytes
    receipt_id: bytes
    chronology_id: bytes
    replay_id: bytes
    decision_path_id: bytes
    before_audit_head: bytes
    before_continuity_root: bytes
    after_audit_head: bytes
    after_continuity_root: bytes
    audit_head_after: bytes
    continuity_root_after: bytes
    evidence_request_id: bytes
    evidence_decision_id: bytes
    evidence_join_id: bytes
    evidence_receipt_id: bytes
    evidence_decision_path_id: bytes
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int
    continuity_epoch: int
    sequence_before: int
    sequence_after: int
    proof_suite_id: str
    proof_session_accepted: bool
    economic_mutation: bool
    replay_stateful: bool
    disposition: str
    prior_operation_digest: bytes

    def __post_init__(self) -> None:
        if self.protocol != STATE_ADAPTER_PROTOCOL:
            raise SemanticKernelBindingError("state_kernel_protocol")
        if self.schema != STATE_KERNEL_SCHEMA or self.result != SEMANTIC_KERNEL_RESULT:
            raise SemanticKernelBindingError("state_kernel_result_header")
        if self.kernel_build_id != STATE_KERNEL_BUILD_ID:
            raise SemanticKernelBindingError("state_kernel_build_id")
        for name in ("artifact_sha256", "source_binding_sha256"):
            value = getattr(self, name)
            if type(value) is not bytes or len(value) != 32 or not any(value):
                raise SemanticKernelBindingError(f"state_kernel_identity:{name}")
        for name in _STATE_RESULT_ID_FIELDS:
            value = getattr(self, name)
            if type(value) is not bytes or len(value) != 64:
                raise SemanticKernelBindingError(f"state_kernel_identity:{name}")
            if name != "prior_operation_digest" and not any(value):
                raise SemanticKernelBindingError(f"state_kernel_identity:{name}")
        if self.policy not in POLICY_NAMES or self.directive not in DIRECTIVE_NAMES:
            raise SemanticKernelBindingError("state_kernel_policy_directive")
        if DIRECTIVE_POLICY[self.directive] != self.policy:
            raise SemanticKernelBindingError("state_kernel_policy_directive")
        if self.reason not in REASON_NAMES:
            raise SemanticKernelBindingError("state_kernel_reason")
        if self.reason_id != REASON_IDS[self.reason]:
            raise SemanticKernelBindingError("state_kernel_reason_identity")
        if self.proof_suite_id != "NONE" or self.proof_session_accepted:
            raise SemanticKernelBindingError("state_kernel_proof_authority")
        if not self.replay_stateful:
            raise SemanticKernelBindingError("state_kernel_replay_authority")
        if self.economic_mutation != (self.directive in (1, 5)):
            raise SemanticKernelBindingError("state_kernel_economic_authority")
        if self.disposition not in {"ACCEPT", "REPLAY"}:
            raise SemanticKernelBindingError("state_kernel_disposition")
        for name in (
            "expected_revision",
            "current_sequence",
            "bundle_bytes",
            "event_time",
            "observation_time",
            "rule_effective_time",
            "decision_time",
            "continuity_epoch",
            "sequence_before",
            "sequence_after",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= _STATE_U64_MAX:
                raise SemanticKernelBindingError(f"state_kernel_number:{name}")
        if not 0 < self.bundle_bytes <= MAX_BUNDLE_BYTES:
            raise SemanticKernelBindingError("state_kernel_bundle_length")
        if not (
            self.rule_effective_time
            < self.event_time
            < self.observation_time
            < self.decision_time
        ):
            raise SemanticKernelBindingError("state_kernel_chronology")
        if self.sequence_after != self.sequence_before + 1:
            raise SemanticKernelBindingError("state_kernel_sequence")
        if self.disposition == "ACCEPT" and any(self.prior_operation_digest):
            raise SemanticKernelBindingError("state_kernel_prior_digest")
        if self.disposition == "REPLAY" and not any(self.prior_operation_digest):
            raise SemanticKernelBindingError("state_kernel_prior_digest")


def parse_state_kernel_adapter_output(output: bytes) -> StateKernelResult:
    """Parse one exact, newline-terminated v1 State adapter line."""

    if type(output) is not bytes or not output.endswith(b"\n") or output.count(b"\n") != 1 or b"\r" in output:
        raise SemanticKernelBindingError("state_kernel_output_framing")
    try:
        line = output[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SemanticKernelBindingError("state_kernel_output_ascii") from exc
    fields = line.split(";")
    if not fields or fields[0] != STATE_ADAPTER_PROTOCOL:
        raise SemanticKernelBindingError("state_kernel_output_protocol")
    values: dict[str, str] = {}
    for token in fields[1:]:
        if token.count("=") != 1:
            raise SemanticKernelBindingError("state_kernel_output_field")
        key, value = token.split("=", 1)
        if not key or key in values or not value:
            raise SemanticKernelBindingError("state_kernel_output_field")
        _ascii_value(value, field=key)
        values[key] = value
    if frozenset(values) != _STATE_RESULT_FIELDS:
        raise SemanticKernelBindingError("state_kernel_output_field_set")
    ids = {
        name: _hex_value(values[name], field=name, size=64)
        for name in _STATE_RESULT_ID_FIELDS
    }
    try:
        policy = {name: code for code, name in POLICY_NAMES.items()}[values["policy"]]
        directive = {name: code for code, name in DIRECTIVE_NAMES.items()}[values["directive"]]
    except KeyError as exc:
        raise SemanticKernelBindingError("state_kernel_policy_directive") from exc
    result = StateKernelResult(
        protocol=STATE_ADAPTER_PROTOCOL,
        schema=values["schema"],
        result=values["result"],
        kernel_build_id=values["kernel_build_id"],
        artifact_sha256=_hex_value(values["artifact_sha256"], field="artifact_sha256", size=32),
        source_binding_sha256=_hex_value(
            values["source_binding_sha256"], field="source_binding_sha256", size=32
        ),
        expected_revision=_decimal_value(values["expected_revision"], field="expected_revision"),
        current_sequence=_decimal_value(values["current_sequence"], field="current_sequence"),
        bundle_bytes=_decimal_value(values["bundle_bytes"], field="bundle_bytes"),
        policy=policy,
        directive=directive,
        reason=values["reason"],
        **ids,
        event_time=_decimal_value(values["event_time"], field="event_time"),
        observation_time=_decimal_value(values["observation_time"], field="observation_time"),
        rule_effective_time=_decimal_value(values["rule_effective_time"], field="rule_effective_time"),
        decision_time=_decimal_value(values["decision_time"], field="decision_time"),
        continuity_epoch=_decimal_value(values["continuity_epoch"], field="continuity_epoch"),
        sequence_before=_decimal_value(values["sequence_before"], field="sequence_before"),
        sequence_after=_decimal_value(values["sequence_after"], field="sequence_after"),
        proof_suite_id=values["proof_suite_id"],
        proof_session_accepted=_parse_bool(
            values["proof_session_accepted"], field="proof_session_accepted"
        ),
        economic_mutation=_parse_bool(values["economic_mutation"], field="economic_mutation"),
        replay_stateful=_parse_bool(values["replay_stateful"], field="replay_stateful"),
        disposition=values["disposition"],
    )
    return result


def assert_state_kernel_result_agrees(
    result: StateKernelResult,
    request: StateKernelRequest,
    *,
    artifact_sha256: bytes,
    source_binding_sha256: bytes,
    details: IndependentBundleDetails | None = None,
) -> None:
    """Bind the typed Lean result to canonical bytes without re-evaluating policy."""

    expected_bundle_id = _state_sha(
        b"BL/NATIVE-V3/CONTINUITY/BUNDLE/v2\x00",
        request.bundle,
    )
    expected_values = {
        "artifact_sha256": artifact_sha256,
        "source_binding_sha256": source_binding_sha256,
        "input_sha3_512": request.input_sha3_512,
        "command_id": request.command_id,
        "expected_revision": request.expected_revision,
        "current_sequence": request.global_sequence,
        "bundle_id": expected_bundle_id,
        "bundle_bytes": len(request.bundle),
        "profile_id": request.profile_id,
        "schema_id": request.schema_id,
        "program_id": request.program_id,
        "mode_id": request.mode_id,
        "evaluator_id": request.evaluator_id,
        "control_set_id": request.control_set_id,
        "rule_id": request.rule_id,
        "phase0_receipt_binding": request.phase0_receipt_binding,
        "continuity_epoch": request.continuity_epoch,
    }
    for name, expected in expected_values.items():
        if getattr(result, name) != expected:
            raise SemanticKernelResultMismatch(f"state_kernel_binding:{name}")
    if result.attempt_id != request.command_id:
        raise SemanticKernelResultMismatch("state_kernel_binding:attempt_id")
    if result.replay_stateful is not True:
        raise SemanticKernelResultMismatch("state_kernel_binding:replay_stateful")

    if details is not None:
        reason_name = {
            REASON_VALID: "VALID_CONTINUITY",
            REASON_MISSING_AUTHORITATIVE: "AUTHORITATIVE_ABSENCE",
            REASON_EXPIRED_OR_TERMINATED: "EXPIRED_OR_TERMINATED",
            REASON_INCOMPLETE_OR_AMBIGUOUS: "INCOMPLETE_OR_AMBIGUOUS",
            REASON_STALE_RULE: "STALE_RULE_INTERVAL",
            REASON_CONTROL_INTERVAL: "CONTROL_INTERVAL",
        }.get(details.reason_id)
        evidence_values = {
            "policy": details.policy_result,
            "directive": details.effective_directive,
            "reason": reason_name,
            "reason_id": details.reason_id,
            "attempt_id": details.request["attempt_id"],
            "mode_id": details.decision["mode_id"],
            "control_set_id": details.control_set_id,
            "rule_id": details.decision["rule_id"],
            "phase0_receipt_binding": details.phase0_receipt_binding,
            "evidence_request_id": details.request["id"],
            "evidence_decision_id": details.decision["decision_id"],
            "evidence_join_id": details.join_id,
            "evidence_receipt_id": details.receipt_id,
            "evidence_decision_path_id": details.decision["decision_path_id"],
            "source_root": details.facts["source_root"],
            "completeness_id": details.completeness["id"],
            "exception_id": details.decision["exception_id"],
            "event_time": details.request["event_time"],
            "observation_time": details.request["observation_time"],
            "rule_effective_time": details.request["rule_effective_time"],
            "decision_time": details.request["decision_time"],
        }
        for name, expected in evidence_values.items():
            if getattr(result, name) != expected:
                raise SemanticKernelResultMismatch(f"state_kernel_evidence_binding:{name}")

    prior = request.prior_operation
    if result.disposition == "ACCEPT":
        if prior is not None:
            raise SemanticKernelResultMismatch("state_kernel_accept_with_prior")
        if request.expected_revision != request.global_sequence:
            raise SemanticKernelResultMismatch("state_kernel_stale_revision")
        before_sequence = request.global_sequence
        before_row_count = request.direct_count
        before_state_id = request.continuity_state_id
        before_audit = request.continuity_audit_head
        before_root = request.continuity_root
        if any(result.prior_operation_digest):
            raise SemanticKernelResultMismatch("state_kernel_prior_digest")
    else:
        if prior is None:
            raise SemanticKernelResultMismatch("state_kernel_replay_without_prior")
        if result.prior_operation_digest != prior.operation_digest:
            raise SemanticKernelResultMismatch("state_kernel_prior_digest")
        if (
            request.expected_revision != prior.continuity_sequence_before
            or request.global_sequence < prior.continuity_sequence_after
        ):
            raise SemanticKernelResultMismatch("state_kernel_retry_revision")
        before_sequence = prior.continuity_sequence_before
        before_row_count = before_sequence
        before_state_id = prior.continuity_before_state_id
        before_audit = prior.continuity_before_audit_head
        before_root = prior.continuity_before_root
        for result_name, prior_name in (
            ("bundle_id", "bundle_id"),
            ("receipt_id", "receipt_id"),
            ("request_id", "request_id"),
            ("attempt_id", "attempt_id"),
            ("decision_id", "decision_id"),
            ("join_id", "join_id"),
            ("source_root", "source_root"),
            ("profile_id", "profile_id"),
            ("schema_id", "schema_id"),
            ("program_id", "program_id"),
            ("mode_id", "mode_id"),
            ("evaluator_id", "evaluator_id"),
            ("control_set_id", "control_set_id"),
            ("rule_id", "rule_id"),
            ("phase0_receipt_binding", "phase0_receipt_binding"),
            ("exception_id", "exception_id"),
            ("policy", "policy_result"),
            ("directive", "effective_directive"),
            ("event_time", "event_time"),
            ("observation_time", "observation_time"),
            ("rule_effective_time", "rule_effective_time"),
            ("decision_time", "decision_time"),
            ("continuity_epoch", "continuity_epoch"),
            ("sequence_before", "continuity_sequence_before"),
            ("sequence_after", "continuity_sequence_after"),
            ("before_state_id", "continuity_before_state_id"),
            ("after_state_id", "continuity_after_state_id"),
            ("before_audit_head", "continuity_before_audit_head"),
            ("after_audit_head", "continuity_after_audit_head"),
            ("before_continuity_root", "continuity_before_root"),
            ("after_continuity_root", "continuity_after_root"),
            ("economic_mutation", "clearance_advanced"),
        ):
            if getattr(result, result_name) != getattr(prior, prior_name):
                raise SemanticKernelResultMismatch(f"state_kernel_prior_binding:{result_name}")
        if result.attempt_id != request.command_id:
            raise SemanticKernelResultMismatch("state_kernel_prior_command")
        if prior.operation_version == 0 and request.expected_revision != 0:
            raise SemanticKernelResultMismatch("state_kernel_legacy_retry_revision")

    if result.sequence_before != before_sequence or result.sequence_after != before_sequence + 1:
        raise SemanticKernelResultMismatch("state_kernel_sequence")
    if (
        result.before_state_id != before_state_id
        or result.before_audit_head != before_audit
        or result.before_continuity_root != before_root
    ):
        raise SemanticKernelResultMismatch("state_kernel_before_state")

    if result.disposition == "REPLAY" and prior is not None and prior.operation_version == 0:
        legacy_ids = {
            "request_id": prior.request_id,
            "decision_id": prior.decision_id,
            "join_id": prior.join_id,
            "receipt_id": prior.receipt_id,
            "after_state_id": prior.continuity_after_state_id,
            "after_audit_head": prior.continuity_after_audit_head,
            "after_continuity_root": prior.continuity_after_root,
            "audit_head_after": prior.continuity_after_audit_head,
            "continuity_root_after": prior.continuity_after_root,
        }
        if details is not None:
            legacy_ids.update(
                {
                    "replay_id": details.decision["replay_id"],
                    "decision_path_id": details.decision["decision_path_id"],
                }
            )
        for name, expected in legacy_ids.items():
            if getattr(result, name) != expected:
                raise SemanticKernelResultMismatch(f"state_kernel_legacy_retry:{name}")
        return

    expected_request_id = _state_sha(
        b"BL/DIRECT-STATE-OWNED/STATE-REQUEST/v1\x00",
        request.command_id,
        expected_bundle_id,
        _state_u64(request.expected_revision, field="expected_revision"),
        before_state_id,
        request.governance_commitment,
        request.control_set_id,
        request.mode_id,
    )
    expected_decision_id = _state_sha(
        b"BL/DIRECT-STATE-OWNED/STATE-DECISION/v1\x00",
        expected_request_id,
        result.evidence_decision_id,
        before_state_id,
        result.source_root,
        bytes((result.policy, result.directive)),
        result.exception_id,
    )
    expected_audit = _state_sha(
        _STATE_CONTINUITY_AUDIT_DOMAIN,
        before_audit,
        expected_decision_id,
        bytes((result.directive,)),
    )
    expected_root = _state_sha(
        _STATE_CONTINUITY_ROOT_DOMAIN,
        before_root,
        result.source_root,
        expected_decision_id,
    )
    expected_after_state_id = _state_continuity_id(
        profile_id=request.profile_id,
        mode_id=request.mode_id,
        sequence=before_sequence + 1,
        row_count=before_row_count + 1,
        audit_head=expected_audit,
        continuity_root=expected_root,
    )
    expected_ids = {
        "request_id": expected_request_id,
        "decision_id": expected_decision_id,
        "join_id": _state_sha(
            b"BL/DIRECT-STATE-OWNED/STATE-JOIN/v1\x00",
            expected_decision_id,
            result.evidence_join_id,
        ),
        "receipt_id": _state_sha(
            b"BL/DIRECT-STATE-OWNED/STATE-RECEIPT/v1\x00",
            expected_decision_id,
            expected_after_state_id,
            result.evidence_receipt_id,
        ),
        "replay_id": _state_sha(
            b"BL/DIRECT-STATE-OWNED/STATE-REPLAY/v1\x00",
            expected_request_id,
            before_state_id,
            expected_bundle_id,
            request.control_set_id,
        ),
        "decision_path_id": _state_sha(
            b"BL/DIRECT-STATE-OWNED/STATE-DECISION-PATH/v1\x00",
            result.evidence_decision_path_id,
            expected_decision_id,
        ),
        "after_state_id": expected_after_state_id,
        "after_audit_head": expected_audit,
        "after_continuity_root": expected_root,
        "audit_head_after": expected_audit,
        "continuity_root_after": expected_root,
    }
    if result.disposition == "REPLAY" and prior is not None:
        prior_expected = {
            "request_id": prior.request_id,
            "decision_id": prior.decision_id,
            "join_id": prior.join_id,
            "receipt_id": prior.receipt_id,
            "after_state_id": prior.continuity_after_state_id,
            "after_audit_head": prior.continuity_after_audit_head,
            "after_continuity_root": prior.continuity_after_root,
            "audit_head_after": prior.continuity_after_audit_head,
            "continuity_root_after": prior.continuity_after_root,
        }
        if any(expected_ids[name] != value for name, value in prior_expected.items()):
            raise SemanticKernelResultMismatch("state_kernel_prior_transition_reconstruction")
    for name, expected in expected_ids.items():
        if getattr(result, name) != expected:
            raise SemanticKernelResultMismatch(f"state_kernel_result_binding:{name}")


def _parse_state_bool(value: str, *, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise SemanticKernelBindingError(f"state_kernel_field:{field}")


def _is_reparse_point(path: Path) -> bool:
    """Reject symlinks/junctions/reparse points before following a package path."""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = int(getattr(os.lstat(path), "st_file_attributes", 0))
    except OSError:
        return True
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _package_relative_path(raw: object, *, root: Path, field: str) -> Path:
    """Resolve one package-relative path without accepting traversal or aliases."""

    if type(raw) is not str or not raw or "\x00" in raw:
        raise SemanticKernelBindingError(f"semantic_kernel_package_path:{field}")
    relative = Path(raw)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise SemanticKernelBindingError(f"semantic_kernel_package_path:{field}")
    candidate = (root / relative).absolute()
    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise SemanticKernelBindingError(f"semantic_kernel_package_path:{field}") from exc
    if os.path.normcase(str(candidate)) != os.path.normcase(str(resolved_candidate)):
        raise SemanticKernelBindingError(f"semantic_kernel_package_path:{field}")
    current = candidate
    while current != root.parent:
        if _is_reparse_point(current):
            raise SemanticKernelBindingError(f"semantic_kernel_package_reparse:{field}")
        current = current.parent
    return candidate


def _package_file_identity(
    path: Path,
    *,
    size_bytes: int,
    sha256: bytes,
    field: str,
) -> None:
    """Read one package file with exact size/hash and regular-file identity checks."""

    if type(size_bytes) is not int or not 0 < size_bytes <= _MAX_PACKAGE_FILE_BYTES:
        raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
    if type(sha256) is not bytes or len(sha256) != 32 or not any(sha256):
        raise SemanticKernelBindingError(f"semantic_kernel_package_hash:{field}")
    if _is_reparse_point(path):
        raise SemanticKernelBindingError(f"semantic_kernel_package_reparse:{field}")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SemanticKernelBindingError(f"semantic_kernel_package_missing:{field}") from exc
    if not stat.S_ISREG(metadata.st_mode) or int(metadata.st_nlink) != 1:
        raise SemanticKernelBindingError(f"semantic_kernel_package_regular:{field}")
    if int(metadata.st_size) != size_bytes:
        raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(_PACKAGE_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > size_bytes:
                    raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
                digest.update(chunk)
    except SemanticKernelBindingError:
        raise
    except OSError as exc:
        raise SemanticKernelBindingError(f"semantic_kernel_package_read:{field}") from exc
    if total != size_bytes:
        raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
    if not hmac.compare_digest(digest.digest(), sha256):
        raise SemanticKernelBindingError(f"semantic_kernel_package_identity:{field}")


def _strict_json_object(path: Path, *, field: str) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_pairs,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SemanticKernelBindingError(f"semantic_kernel_package_json:{field}") from exc
    if type(payload) is not dict:
        raise SemanticKernelBindingError(f"semantic_kernel_package_json:{field}")
    return payload


def _package_hex(raw: object, *, field: str) -> bytes:
    if type(raw) is not str or _HEX_32_RE.fullmatch(raw) is None:
        raise SemanticKernelBindingError(f"semantic_kernel_package_field:{field}")
    return bytes.fromhex(raw)


@dataclass(frozen=True, slots=True)
class SemanticKernelPackageFile:
    path: Path
    size_bytes: int
    sha256: bytes
    role: str


@dataclass(frozen=True, slots=True)
class SemanticKernelPin:
    """Immutable identities required to launch the native adapter."""

    package_protocol: str
    package_root: Path
    adapter_executable: Path
    kernel_artifact: Path
    source_manifest: Path
    build_receipt: Path
    workspace: Path
    adapter_size_bytes: int
    adapter_sha256: bytes
    kernel_artifact_size_bytes: int
    kernel_artifact_sha256: bytes
    source_manifest_size_bytes: int
    source_manifest_sha256: bytes
    build_receipt_size_bytes: int
    build_receipt_sha256: bytes
    source_binding_sha256: bytes
    kernel_build_id: str
    handoff_commit: str
    handoff_tree: str
    package_files: tuple[SemanticKernelPackageFile, ...] = ()
    adapter_protocol: str = SEMANTIC_ADAPTER_PROTOCOL
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.package_protocol != SEMANTIC_KERNEL_PACKAGE_PROTOCOL:
            raise SemanticKernelBindingError("semantic_kernel_package_protocol")
        for field in (
            "package_root",
            "adapter_executable",
            "kernel_artifact",
            "source_manifest",
            "build_receipt",
        ):
            value = getattr(self, field)
            if not isinstance(value, Path) or not value.is_absolute():
                raise SemanticKernelBindingError(f"semantic_kernel_{field}_path")
        if not isinstance(self.workspace, Path) or not self.workspace.is_absolute():
            raise SemanticKernelBindingError("semantic_kernel_workspace_path")
        for field in (
            "adapter_size_bytes",
            "kernel_artifact_size_bytes",
            "source_manifest_size_bytes",
            "build_receipt_size_bytes",
        ):
            value = getattr(self, field)
            if type(value) is not int or not 0 < value <= _MAX_PACKAGE_FILE_BYTES:
                raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
        for field in (
            "adapter_sha256",
            "kernel_artifact_sha256",
            "source_manifest_sha256",
            "build_receipt_sha256",
            "source_binding_sha256",
        ):
            value = getattr(self, field)
            if type(value) is not bytes or len(value) != 32 or not any(value):
                raise SemanticKernelBindingError(f"semantic_kernel_pin:{field}")
        if not _GIT_ID_RE.fullmatch(self.handoff_commit) or not _GIT_ID_RE.fullmatch(
            self.handoff_tree
        ):
            raise SemanticKernelBindingError("semantic_kernel_handoff_identity")
        if type(self.package_files) is not tuple or not self.package_files:
            raise SemanticKernelBindingError("semantic_kernel_package_files")
        if self.adapter_protocol not in {SEMANTIC_ADAPTER_PROTOCOL, STATE_ADAPTER_PROTOCOL}:
            raise SemanticKernelBindingError("semantic_kernel_adapter_protocol")
        expected_build = (
            "BLSK-BLCBND02-EXACT-V2"
            if self.adapter_protocol == SEMANTIC_ADAPTER_PROTOCOL
            else STATE_KERNEL_BUILD_ID
        )
        if self.kernel_build_id != expected_build:
            raise SemanticKernelBindingError("semantic_kernel_protocol_build_mismatch")
        if (
            type(self.timeout_seconds) is not float
            or not 0.0 < self.timeout_seconds <= SEMANTIC_KERNEL_MAX_TIMEOUT_SECONDS
        ):
            raise SemanticKernelBindingError("semantic_kernel_timeout")
        _ascii_value(self.kernel_build_id, field="kernel_build_id")


def _package_relative_name(path: Path, *, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SemanticKernelBindingError("semantic_kernel_package_role_path") from exc


def _package_role(
    payload: object,
    *,
    field: str,
    package_root: Path,
) -> tuple[str, Path, int, bytes]:
    if type(payload) is not dict or set(payload) != {"path", "size_bytes", "sha256", "role"}:
        raise SemanticKernelBindingError(f"semantic_kernel_package_role:{field}")
    role = payload["role"]
    if type(role) is not str or not role or not role.isascii():
        raise SemanticKernelBindingError(f"semantic_kernel_package_role:{field}")
    path = _package_relative_path(payload["path"], root=package_root, field=field)
    size_bytes = payload["size_bytes"]
    sha256 = _package_hex(payload["sha256"], field=field)
    if type(size_bytes) is not int or not 0 < size_bytes <= _MAX_PACKAGE_FILE_BYTES:
        raise SemanticKernelBindingError(f"semantic_kernel_package_size:{field}")
    return role, path, size_bytes, sha256


class PinnedSemanticKernelBinding:
    """Run one exact bundle through the pinned adapter and containment runner."""

    def __init__(self, pin: SemanticKernelPin) -> None:
        self._pin = pin

    @property
    def pin(self) -> SemanticKernelPin:
        return self._pin

    def evaluate(self, bundle: bytes) -> SemanticKernelResult:
        if type(bundle) is not bytes:
            raise SemanticKernelBindingError("semantic_kernel_bundle_bytes")
        if not 0 < len(bundle) <= MAX_BUNDLE_BYTES:
            raise SemanticKernelBindingError("semantic_kernel_bundle_size")
        try:
            for package_file in self._pin.package_files:
                _package_file_identity(
                    package_file.path,
                    size_bytes=package_file.size_bytes,
                    sha256=package_file.sha256,
                    field=package_file.role,
                )
        except SemanticKernelBindingError:
            raise
        if not self._pin.adapter_executable.is_file() or self._pin.adapter_executable.is_symlink():
            raise SemanticKernelBindingError("semantic_kernel_adapter_unavailable")
        self._pin.workspace.mkdir(parents=True, exist_ok=True)
        if not self._pin.workspace.is_dir() or self._pin.workspace.is_symlink():
            raise SemanticKernelBindingError("semantic_kernel_workspace_unavailable")
        try:
            contained = run_contained_verifier_stream(
                self._pin.adapter_executable,
                (),
                bundle,
                workspace=self._pin.workspace,
                timeout_seconds=self._pin.timeout_seconds,
                expected_executable_size_bytes=self._pin.adapter_size_bytes,
                expected_executable_sha256=self._pin.adapter_sha256,
                expected_input_bytes=len(bundle),
            )
        except VerifierProcessError as exc:
            raise SemanticKernelBindingError(f"semantic_kernel_transport:{exc}") from exc
        if (
            contained.exit_code != 0
            or contained.stderr != b""
            or contained.timed_out
            or not contained.cap_enforced
            or contained.cap_bytes != ADMISSION_CAP_BYTES
            or contained.active_process_limit != ACTIVE_PROCESS_LIMIT
            or not contained.process_tree_complete
            or not contained.measurement_complete
            or not contained.cleanup_complete
        ):
            raise SemanticKernelBindingError(
                "semantic_kernel_containment:"
                f"exit={contained.exit_code};stderr={contained.stderr!r};stdout={contained.stdout!r};"
                f"timed_out={contained.timed_out};cap_enforced={contained.cap_enforced};"
                f"cap_bytes={contained.cap_bytes};active_process_limit={contained.active_process_limit};"
                f"process_tree_complete={contained.process_tree_complete};"
                f"measurement_complete={contained.measurement_complete};"
                f"cleanup_complete={contained.cleanup_complete}"
            )
        try:
            result = parse_semantic_adapter_output(contained.stdout)
        except SemanticKernelBindingError as exc:
            raise SemanticKernelBindingError(
                f"{exc}:stdout={contained.stdout!r};stderr={contained.stderr!r}"
            ) from exc
        if result.artifact_sha256 != self._pin.kernel_artifact_sha256:
            raise SemanticKernelBindingError(
                "semantic_kernel_artifact_identity:"
                f"actual={result.artifact_sha256.hex()};expected={self._pin.kernel_artifact_sha256.hex()}"
            )
        if result.source_binding_sha256 != self._pin.source_binding_sha256:
            raise SemanticKernelBindingError(
                "semantic_kernel_source_identity:"
                f"actual={result.source_binding_sha256.hex()};expected={self._pin.source_binding_sha256.hex()}"
            )
        if result.kernel_build_id != self._pin.kernel_build_id:
            raise SemanticKernelBindingError(
                "semantic_kernel_build_identity:"
                f"actual={result.kernel_build_id};expected={self._pin.kernel_build_id}"
            )
        if result.bundle_bytes != len(bundle):
            raise SemanticKernelBindingError("semantic_kernel_bundle_length")
        return result

    def evaluate_state_request(self, request: StateKernelRequest) -> StateKernelResult:
        if type(request) is not StateKernelRequest:
            raise SemanticKernelBindingError("state_kernel_request_type")
        if (
            self._pin.adapter_protocol != STATE_ADAPTER_PROTOCOL
            or self._pin.kernel_build_id != STATE_KERNEL_BUILD_ID
        ):
            raise SemanticKernelBindingError("state_kernel_release_not_pinned")
        encoded = request.encode()
        try:
            for package_file in self._pin.package_files:
                _package_file_identity(
                    package_file.path,
                    size_bytes=package_file.size_bytes,
                    sha256=package_file.sha256,
                    field=package_file.role,
                )
        except SemanticKernelBindingError:
            raise
        if not self._pin.adapter_executable.is_file() or self._pin.adapter_executable.is_symlink():
            raise SemanticKernelBindingError("semantic_kernel_adapter_unavailable")
        self._pin.workspace.mkdir(parents=True, exist_ok=True)
        if not self._pin.workspace.is_dir() or self._pin.workspace.is_symlink():
            raise SemanticKernelBindingError("semantic_kernel_workspace_unavailable")
        try:
            contained = run_contained_verifier_stream(
                self._pin.adapter_executable,
                (),
                encoded,
                workspace=self._pin.workspace,
                timeout_seconds=self._pin.timeout_seconds,
                expected_executable_size_bytes=self._pin.adapter_size_bytes,
                expected_executable_sha256=self._pin.adapter_sha256,
                expected_input_bytes=len(encoded),
            )
        except VerifierProcessError as exc:
            raise SemanticKernelBindingError(f"state_kernel_transport:{exc}") from exc
        if (
            contained.exit_code != 0
            or contained.stderr != b""
            or contained.timed_out
            or not contained.cap_enforced
            or contained.cap_bytes != ADMISSION_CAP_BYTES
            or contained.active_process_limit != ACTIVE_PROCESS_LIMIT
            or not contained.process_tree_complete
            or not contained.measurement_complete
            or not contained.cleanup_complete
        ):
            raise SemanticKernelBindingError(
                "state_kernel_containment:"
                f"exit={contained.exit_code};stderr={contained.stderr!r};stdout={contained.stdout!r};"
                f"timed_out={contained.timed_out};cap_enforced={contained.cap_enforced};"
                f"cap_bytes={contained.cap_bytes};active_process_limit={contained.active_process_limit};"
                f"process_tree_complete={contained.process_tree_complete};"
                f"measurement_complete={contained.measurement_complete};"
                f"cleanup_complete={contained.cleanup_complete}"
            )
        try:
            result = parse_state_kernel_adapter_output(contained.stdout)
        except SemanticKernelBindingError as exc:
            raise SemanticKernelBindingError(
                f"{exc}:stdout={contained.stdout!r};stderr={contained.stderr!r}"
            ) from exc
        if result.artifact_sha256 != self._pin.kernel_artifact_sha256:
            raise SemanticKernelBindingError("state_kernel_artifact_identity")
        if result.source_binding_sha256 != self._pin.source_binding_sha256:
            raise SemanticKernelBindingError("state_kernel_source_identity")
        if result.kernel_build_id != self._pin.kernel_build_id:
            raise SemanticKernelBindingError("state_kernel_build_identity")
        assert_state_kernel_result_agrees(
            result,
            request,
            artifact_sha256=self._pin.kernel_artifact_sha256,
            source_binding_sha256=self._pin.source_binding_sha256,
        )
        return result


def assert_semantic_result_agrees(
    result: SemanticKernelResult,
    bundle: bytes,
    details: IndependentBundleDetails,
    *,
    profile_id: bytes,
    schema_id: bytes,
    program_id: bytes,
    mode_id: bytes,
    evaluator_id: bytes,
    rule_id: bytes,
) -> None:
    """Require every surfaced native field to equal independent reconstruction."""

    expected: dict[str, Any] = {
        "bundle_id": details.bundle_id,
        "bundle_bytes": len(bundle),
        "policy": details.policy_result,
        "directive": details.effective_directive,
        "reason_id": details.reason_id,
        "request_id": details.request["id"],
        "attempt_id": details.request["attempt_id"],
        "decision_id": details.decision["decision_id"],
        "join_id": details.join_id,
        "profile_id": profile_id,
        "schema_id": schema_id,
        "program_id": program_id,
        "mode_id": mode_id,
        "evaluator_id": evaluator_id,
        "control_set_id": details.control_set_id,
        "rule_id": rule_id,
        "phase0_receipt_binding": details.phase0_receipt_binding,
        "source_root": details.facts["source_root"],
        "completeness_id": details.completeness["id"],
        "exception_id": details.decision["exception_id"],
        "before_state_id": details.before["id"],
        "after_state_id": details.after["id"],
        "receipt_id": details.receipt_id,
        "chronology_id": details.decision["chronology_id"],
        "replay_id": details.decision["replay_id"],
        "decision_path_id": details.decision["decision_path_id"],
        "before_audit_head": details.before["audit"],
        "before_continuity_root": details.before["root"],
        "after_audit_head": details.after["audit"],
        "after_continuity_root": details.after["root"],
        "audit_head_after": details.after["audit"],
        "continuity_root_after": details.after["root"],
        "event_time": details.request["event_time"],
        "observation_time": details.request["observation_time"],
        "rule_effective_time": details.request["rule_effective_time"],
        "decision_time": details.request["decision_time"],
        "continuity_epoch": details.request["epoch"],
        "sequence_before": details.request["sequence_before"],
        "sequence_after": details.after["sequence"],
    }
    for field, expected_value in expected.items():
        if getattr(result, field) != expected_value:
            raise SemanticKernelResultMismatch(f"semantic_kernel_mismatch:{field}")
    if result.reason not in REASON_NAMES:
        raise SemanticKernelResultMismatch("semantic_kernel_mismatch:reason")
    # The exact reason identity is the authoritative correspondence check;
    # no local reason-name-to-policy fallback is permitted here.
    if result.proof_suite_id != "NONE" or result.proof_session_accepted or result.economic_mutation or result.replay_stateful:
        raise SemanticKernelResultMismatch("semantic_kernel_mismatch:authority_flags")


def semantic_result_from_details(
    details: IndependentBundleDetails,
    *,
    profile_id: bytes,
    schema_id: bytes,
    program_id: bytes,
    mode_id: bytes,
    evaluator_id: bytes,
    rule_id: bytes,
) -> SemanticKernelResult:
    """Construct a result for isolated State-boundary tests only.

    Production code never calls this helper; it exists so DB retry/rollback
    tests can inject a typed port without becoming a second semantic evaluator.
    """

    reason = {
        REASON_VALID: "VALID_CONTINUITY",
        REASON_MISSING_AUTHORITATIVE: "AUTHORITATIVE_ABSENCE",
        REASON_EXPIRED_OR_TERMINATED: "EXPIRED_OR_TERMINATED",
        REASON_INCOMPLETE_OR_AMBIGUOUS: "INCOMPLETE_OR_AMBIGUOUS",
        REASON_STALE_RULE: "STALE_RULE_INTERVAL",
        REASON_CONTROL_INTERVAL: "CONTROL_INTERVAL",
    }.get(details.reason_id)
    if reason is None:
        raise SemanticKernelBindingError("semantic_kernel_reason")
    return SemanticKernelResult(
        protocol=SEMANTIC_ADAPTER_PROTOCOL,
        schema=SEMANTIC_KERNEL_SCHEMA,
        result=SEMANTIC_KERNEL_RESULT,
        kernel_build_id="TEST-SEMANTIC-KERNEL",
        artifact_sha256=b"\0" * 32,
        source_binding_sha256=b"\0" * 32,
        bundle_id=details.bundle_id,
        bundle_bytes=len(details.data),
        policy=details.policy_result,
        directive=details.effective_directive,
        reason=reason,
        reason_id=details.reason_id,
        request_id=details.request["id"],
        attempt_id=details.request["attempt_id"],
        decision_id=details.decision["decision_id"],
        join_id=details.join_id,
        profile_id=profile_id,
        schema_id=schema_id,
        program_id=program_id,
        mode_id=mode_id,
        evaluator_id=evaluator_id,
        control_set_id=details.control_set_id,
        rule_id=rule_id,
        phase0_receipt_binding=details.phase0_receipt_binding,
        source_root=details.facts["source_root"],
        completeness_id=details.completeness["id"],
        exception_id=details.decision["exception_id"],
        before_state_id=details.before["id"],
        after_state_id=details.after["id"],
        receipt_id=details.receipt_id,
        chronology_id=details.decision["chronology_id"],
        replay_id=details.decision["replay_id"],
        decision_path_id=details.decision["decision_path_id"],
        before_audit_head=details.before["audit"],
        before_continuity_root=details.before["root"],
        after_audit_head=details.after["audit"],
        after_continuity_root=details.after["root"],
        audit_head_after=details.after["audit"],
        continuity_root_after=details.after["root"],
        event_time=details.request["event_time"],
        observation_time=details.request["observation_time"],
        rule_effective_time=details.request["rule_effective_time"],
        decision_time=details.request["decision_time"],
        continuity_epoch=details.request["epoch"],
        sequence_before=details.request["sequence_before"],
        sequence_after=details.after["sequence"],
        proof_suite_id="NONE",
        proof_session_accepted=False,
        economic_mutation=False,
        replay_stateful=False,
    )


def load_production_pin() -> SemanticKernelPin:
    """Load and independently admit only a State-local immutable package."""

    repository_root = Path(__file__).resolve().parents[1]
    semantic_root = repository_root / "semantic_kernel"
    package_root = semantic_root / "pinned"
    pin_path = semantic_root / "adapter_pin.json"
    if _is_reparse_point(pin_path) or not pin_path.is_file():
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_missing")
    payload = _strict_json_object(pin_path, field="adapter_pin")
    required = {
        "package_protocol",
        "package_root",
        "adapter_executable",
        "kernel_artifact",
        "source_manifest",
        "build_receipt",
        "workspace",
        "adapter_size_bytes",
        "adapter_sha256",
        "kernel_artifact_size_bytes",
        "kernel_artifact_sha256",
        "source_manifest_size_bytes",
        "source_manifest_sha256",
        "build_receipt_size_bytes",
        "build_receipt_sha256",
        "source_binding_sha256",
        "kernel_build_id",
        "adapter_protocol",
        "handoff_commit",
        "handoff_tree",
        "timeout_seconds",
    }
    if set(payload) != required:
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_fields")
    if payload["package_protocol"] != SEMANTIC_KERNEL_PACKAGE_PROTOCOL:
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_protocol")
    try:
        declared_package_root = _package_relative_path(
            payload["package_root"],
            root=semantic_root,
            field="package_root",
        )
    except SemanticKernelBindingError:
        raise
    if os.path.normcase(str(declared_package_root)) != os.path.normcase(str(package_root)):
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_package_root")
    if not package_root.is_dir() or _is_reparse_point(package_root):
        raise SemanticKernelBindingError("semantic_kernel_package_missing")

    def package_path(name: str) -> Path:
        return _package_relative_path(payload[name], root=package_root, field=name)

    adapter_executable = package_path("adapter_executable")
    kernel_artifact = package_path("kernel_artifact")
    source_manifest = package_path("source_manifest")
    build_receipt = package_path("build_receipt")
    workspace = _package_relative_path(payload["workspace"], root=semantic_root, field="workspace")
    if os.path.normcase(str(workspace)) != os.path.normcase(str(semantic_root / "workspace")):
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_workspace")
    if not workspace.is_dir() or _is_reparse_point(workspace):
        raise SemanticKernelBindingError("semantic_kernel_workspace_unavailable")

    def size_value(name: str) -> int:
        raw = payload[name]
        if type(raw) is not int or not 0 < raw <= _MAX_PACKAGE_FILE_BYTES:
            raise SemanticKernelBindingError(f"semantic_kernel_artifact_pin:{name}")
        return raw

    def hash_value(name: str) -> bytes:
        return _package_hex(payload[name], field=name)

    adapter_size_bytes = size_value("adapter_size_bytes")
    adapter_sha256 = hash_value("adapter_sha256")
    kernel_artifact_size_bytes = size_value("kernel_artifact_size_bytes")
    kernel_artifact_sha256 = hash_value("kernel_artifact_sha256")
    source_manifest_size_bytes = size_value("source_manifest_size_bytes")
    source_manifest_sha256 = hash_value("source_manifest_sha256")
    build_receipt_size_bytes = size_value("build_receipt_size_bytes")
    build_receipt_sha256 = hash_value("build_receipt_sha256")
    source_binding_sha256 = hash_value("source_binding_sha256")
    _package_file_identity(
        source_manifest,
        size_bytes=source_manifest_size_bytes,
        sha256=source_manifest_sha256,
        field="source_manifest",
    )
    _package_file_identity(
        build_receipt,
        size_bytes=build_receipt_size_bytes,
        sha256=build_receipt_sha256,
        field="build_receipt",
    )
    source_payload = _strict_json_object(source_manifest, field="source_manifest")
    if set(source_payload) != {"protocol", "source_binding_sha256", "files"}:
        raise SemanticKernelBindingError("semantic_kernel_source_manifest_fields")
    if source_payload["protocol"] != SEMANTIC_KERNEL_SOURCE_MANIFEST_PROTOCOL:
        raise SemanticKernelBindingError("semantic_kernel_source_manifest_protocol")
    if _package_hex(source_payload["source_binding_sha256"], field="source_binding_sha256") != source_binding_sha256:
        raise SemanticKernelBindingError("semantic_kernel_source_manifest_binding")
    source_entries = source_payload["files"]
    if type(source_entries) is not list or not source_entries:
        raise SemanticKernelBindingError("semantic_kernel_source_manifest_files")

    build_payload = _strict_json_object(build_receipt, field="build_receipt")
    if set(build_payload) != {
        "protocol",
        "handoff_commit",
        "handoff_tree",
        "kernel_build_id",
        "adapter_protocol",
        "source_binding_sha256",
        "adapter_executable",
        "kernel_artifact",
    }:
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_fields")
    if build_payload["protocol"] != SEMANTIC_KERNEL_BUILD_RECEIPT_PROTOCOL:
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_protocol")
    for name in ("handoff_commit", "handoff_tree"):
        if type(build_payload[name]) is not str or _GIT_ID_RE.fullmatch(build_payload[name]) is None:
            raise SemanticKernelBindingError(f"semantic_kernel_build_receipt:{name}")
        if build_payload[name] != payload[name]:
            raise SemanticKernelBindingError(f"semantic_kernel_build_receipt:{name}")
    for name in ("kernel_build_id", "adapter_protocol"):
        if build_payload[name] != payload[name]:
            raise SemanticKernelBindingError(f"semantic_kernel_build_receipt:{name}")
    if _package_hex(build_payload["source_binding_sha256"], field="source_binding_sha256") != source_binding_sha256:
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_binding")
    adapter_role = _package_role(
        build_payload["adapter_executable"],
        field="adapter_executable",
        package_root=package_root,
    )
    kernel_role = _package_role(
        build_payload["kernel_artifact"],
        field="kernel_artifact",
        package_root=package_root,
    )
    if adapter_role[0] != "adapter-executable" or kernel_role[0] != "lean-kernel-static-library":
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_roles")
    if adapter_role[1:] != (adapter_executable, adapter_size_bytes, adapter_sha256):
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_adapter")
    if kernel_role[1:] != (kernel_artifact, kernel_artifact_size_bytes, kernel_artifact_sha256):
        raise SemanticKernelBindingError("semantic_kernel_build_receipt_kernel")

    package_files: list[SemanticKernelPackageFile] = [
        SemanticKernelPackageFile(
            path=adapter_executable,
            size_bytes=adapter_size_bytes,
            sha256=adapter_sha256,
            role="adapter_executable",
        ),
        SemanticKernelPackageFile(
            path=kernel_artifact,
            size_bytes=kernel_artifact_size_bytes,
            sha256=kernel_artifact_sha256,
            role="kernel_artifact",
        ),
        SemanticKernelPackageFile(
            path=source_manifest,
            size_bytes=source_manifest_size_bytes,
            sha256=source_manifest_sha256,
            role="source_manifest",
        ),
        SemanticKernelPackageFile(
            path=build_receipt,
            size_bytes=build_receipt_size_bytes,
            sha256=build_receipt_sha256,
            role="build_receipt",
        ),
    ]
    seen_paths = {_package_relative_name(item.path, root=package_root) for item in package_files}
    source_names: list[str] = []
    for index, item in enumerate(source_entries):
        if type(item) is not dict or set(item) != {"path", "size_bytes", "sha256"}:
            raise SemanticKernelBindingError(f"semantic_kernel_source_manifest_entry:{index}")
        path = _package_relative_path(item["path"], root=package_root, field=f"source:{index}")
        name = _package_relative_name(path, root=package_root)
        if name in seen_paths or name in source_names:
            raise SemanticKernelBindingError("semantic_kernel_source_manifest_duplicate")
        source_names.append(name)
        size_bytes = item["size_bytes"]
        sha256 = _package_hex(item["sha256"], field=f"source:{index}")
        if type(size_bytes) is not int or not 0 < size_bytes <= _MAX_PACKAGE_FILE_BYTES:
            raise SemanticKernelBindingError(f"semantic_kernel_source_manifest_size:{index}")
        package_files.append(
            SemanticKernelPackageFile(
                path=path,
                size_bytes=size_bytes,
                sha256=sha256,
                role=f"source:{name}",
            )
        )
    if source_names != sorted(source_names):
        raise SemanticKernelBindingError("semantic_kernel_source_manifest_order")

    expected_names = {_package_relative_name(item.path, root=package_root) for item in package_files}
    expected_directories: set[str] = set()
    for name in expected_names:
        parent = Path(name).parent
        while str(parent) not in ("", "."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_names: set[str] = set()
    actual_directories: set[str] = set()
    try:
        for candidate in package_root.rglob("*"):
            if _is_reparse_point(candidate):
                raise SemanticKernelBindingError("semantic_kernel_package_reparse:inventory")
            if candidate.is_file():
                actual_names.add(_package_relative_name(candidate, root=package_root))
            elif candidate.is_dir():
                actual_directories.add(_package_relative_name(candidate, root=package_root))
    except OSError as exc:
        raise SemanticKernelBindingError("semantic_kernel_package_inventory") from exc
    if actual_names != expected_names or actual_directories != expected_directories:
        raise SemanticKernelBindingError("semantic_kernel_package_inventory")
    for package_file in package_files:
        _package_file_identity(
            package_file.path,
            size_bytes=package_file.size_bytes,
            sha256=package_file.sha256,
            field=package_file.role,
        )
    try:
        return SemanticKernelPin(
            package_protocol=payload["package_protocol"],
            package_root=package_root,
            adapter_executable=adapter_executable,
            kernel_artifact=kernel_artifact,
            source_manifest=source_manifest,
            build_receipt=build_receipt,
            workspace=workspace,
            adapter_size_bytes=adapter_size_bytes,
            adapter_sha256=adapter_sha256,
            kernel_artifact_size_bytes=kernel_artifact_size_bytes,
            kernel_artifact_sha256=kernel_artifact_sha256,
            source_manifest_size_bytes=source_manifest_size_bytes,
            source_manifest_sha256=source_manifest_sha256,
            build_receipt_size_bytes=build_receipt_size_bytes,
            build_receipt_sha256=build_receipt_sha256,
            source_binding_sha256=source_binding_sha256,
            kernel_build_id=payload["kernel_build_id"],
            handoff_commit=payload["handoff_commit"],
            handoff_tree=payload["handoff_tree"],
            package_files=tuple(package_files),
            adapter_protocol=payload["adapter_protocol"],
            timeout_seconds=payload["timeout_seconds"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SemanticKernelBindingError("semantic_kernel_artifact_pin_invalid") from exc


def build_production_semantic_kernel_binding() -> PinnedSemanticKernelBinding:
    return PinnedSemanticKernelBinding(load_production_pin())


__all__ = (
    "DIRECTIVE_NAMES",
    "POLICY_NAMES",
    "PinnedSemanticKernelBinding",
    "SEMANTIC_ADAPTER_PROTOCOL",
    "SEMANTIC_KERNEL_PACKAGE_PROTOCOL",
    "SEMANTIC_KERNEL_SCHEMA",
    "SemanticKernelBindingError",
    "SemanticKernelPackageFile",
    "SemanticKernelPin",
    "SemanticKernelPort",
    "SemanticKernelResult",
    "SemanticKernelResultMismatch",
    "StateKernelPriorOperation",
    "StateKernelRequest",
    "StateKernelResult",
    "STATE_ADAPTER_PROTOCOL",
    "STATE_KERNEL_BUILD_ID",
    "STATE_KERNEL_REQUEST_MAGIC",
    "STATE_KERNEL_SCHEMA",
    "assert_semantic_result_agrees",
    "assert_state_kernel_result_agrees",
    "build_production_semantic_kernel_binding",
    "load_production_pin",
    "parse_semantic_adapter_output",
    "parse_state_kernel_adapter_output",
    "parse_state_kernel_request",
    "semantic_result_from_details",
)
