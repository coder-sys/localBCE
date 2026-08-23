"""Test-owned, one-shot qualification runner for the minimal clearance seam.

This module is evidence plumbing only.  The application verifier and state store
remain the authorities for verification, containment, and committed state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import Any

from app.minimal_clearance_proof_state import (
    MinimalClearanceReceiptV1,
    MinimalClearanceStateStoreV1,
    NativeMinimalClearanceVerifier,
)
from app.minimal_clearance_verifier_process import (
    ACTIVE_PROCESS_LIMIT,
    CAP_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
)


SCHEMA = "BL/MINIMAL-CLEARANCE/QUALIFICATION/v1"
SUCCESS_MARKER = "MINIMAL_CLEARANCE_VERIFIER_ACCEPT"
BUILD_PREFIX = "MINIMAL_CLEARANCE_BUILD phase="
MAX_RECORD_BYTES = 8_192
_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
_DIMENSIONS = ("inputs", "public_inputs", "layers", "terms")
_COMPLETE_TRACE = re.compile(
    r"^MINIMAL_CLEARANCE_BUILD phase=complete "
    r"inputs=(?P<inputs>[1-9][0-9]*) "
    r"public_inputs=(?P<public_inputs>[1-9][0-9]*) "
    r"layers=(?P<layers>[1-9][0-9]*) "
    r"terms=(?P<terms>[1-9][0-9]*)$"
)


class QualificationError(RuntimeError):
    """A missing or contradictory qualification authority."""


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise QualificationError(label)


def _read_only(path: Path) -> bool:
    attributes = getattr(path.stat(), "st_file_attributes", None)
    if type(attributes) is not int:
        raise QualificationError("artifact_readonly_unavailable")
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_READONLY", 1))


def _file_token(path: Path) -> tuple[int, int]:
    info = path.stat()
    return int(info.st_dev), int(info.st_ino)


def _read_artifact_once(
    path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> tuple[bytes, str, str, bool, tuple[int, int]]:
    _require(isinstance(path, Path) and path.is_file() and not path.is_symlink(), "artifact_not_regular")
    _require(type(expected_bytes) is int and expected_bytes > 0, "artifact_expected_length")
    _require(type(expected_sha256) is str and _HEX64.fullmatch(expected_sha256) is not None, "artifact_expected_sha256")
    raw = bytes(path.read_bytes())
    sha256 = hashlib.sha256(raw).hexdigest().upper()
    sha3_512 = hashlib.sha3_512(raw).hexdigest().upper()
    _require(len(raw) == expected_bytes, "artifact_length_mismatch")
    _require(sha256 == expected_sha256.upper(), "artifact_sha256_mismatch")
    readonly = _read_only(path)
    _require(readonly, "artifact_not_readonly")
    return raw, sha256, sha3_512, readonly, _file_token(path)


def _check_artifact_after(
    path: Path,
    *,
    expected_bytes: int,
    before_readonly: bool,
    before_token: tuple[int, int],
) -> bool:
    _require(path.is_file() and not path.is_symlink(), "artifact_changed_not_regular")
    info = path.stat()
    after_readonly = _read_only(path)
    _require(int(info.st_size) == expected_bytes, "artifact_size_changed")
    _require(after_readonly == before_readonly and after_readonly, "artifact_readonly_changed")
    _require(_file_token(path) == before_token, "artifact_file_replaced")
    return after_readonly


def _validate_acceptance_output(stdout: bytes, stderr: bytes) -> tuple[str, dict[str, int], str, int]:
    _require(type(stdout) is bytes and len(stdout) <= MAX_STDOUT_BYTES, "verifier_stdout_cap")
    _require(type(stderr) is bytes and len(stderr) <= MAX_STDERR_BYTES, "verifier_stderr_cap")
    try:
        text = stdout.decode("ascii", "strict")
        trace_text = stderr.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise QualificationError("verifier_output_not_ascii") from exc
    lines = text.splitlines()
    _require(len(lines) == 1, "verifier_stdout_unexpected")
    _require(lines[0].startswith(SUCCESS_MARKER + " "), "verifier_acceptance_marker")
    _require("/" not in lines[0] and "\\" not in lines[0], "verifier_stdout_path")
    dimension_match = re.match(
        r"^MINIMAL_CLEARANCE_VERIFIER_ACCEPT "
        r"inputs=(?P<inputs>[1-9][0-9]*) "
        r"public_inputs=(?P<public_inputs>[1-9][0-9]*) "
        r"layers=(?P<layers>[1-9][0-9]*) "
        r"terms=(?P<terms>[1-9][0-9]*)(?: .*)?$",
        lines[0],
    )
    _require(dimension_match is not None, "verifier_acceptance_dimensions")
    dimensions = {name: int(dimension_match.group(name)) for name in _DIMENSIONS}
    normalized_trace = trace_text.replace("\r\n", "\n")
    _require("\r" not in normalized_trace, "verifier_trace_line_endings")
    trace_lines = normalized_trace.splitlines()
    _require(len(trace_lines) == 8, "verifier_trace_line_count")
    _require(trace_lines[0] == BUILD_PREFIX + "public", "verifier_trace_public")
    _require(trace_lines[1] == BUILD_PREFIX + "private", "verifier_trace_private")
    _require(trace_lines[2] == BUILD_PREFIX + "assertions", "verifier_trace_assertions")
    _require(trace_lines[3] == BUILD_PREFIX + "mkcircuit", "verifier_trace_mkcircuit")
    complete_match = _COMPLETE_TRACE.fullmatch(trace_lines[4])
    _require(complete_match is not None, "verifier_trace_complete")
    trace_dimensions = {name: int(complete_match.group(name)) for name in _DIMENSIONS}
    _require(trace_dimensions == dimensions, "verifier_trace_dimensions")
    _require(
        trace_lines[5] == "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept remaining=0",
        "verifier_trace_proof_stage",
    )
    _require(
        trace_lines[6] == "MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received",
        "verifier_trace_commitment_stage",
    )
    _require(
        trace_lines[7] == "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept",
        "verifier_trace_verify_stage",
    )
    trace_digest = hashlib.sha3_512(stderr).hexdigest().upper()
    return SUCCESS_MARKER, dimensions, trace_digest, len(trace_lines)


def _validate_containment(result: Any) -> int:
    _require(result is not None, "verifier_containment_missing")
    cap_bytes = getattr(result, "cap_bytes", None)
    cap_enforced = getattr(result, "cap_enforced", None)
    active_limit = getattr(result, "active_process_limit", None)
    peak = getattr(result, "peak_job_commit_bytes", None)
    timed_out = getattr(result, "timed_out", None)
    exit_code = getattr(result, "exit_code", None)
    _require(type(cap_bytes) is int and cap_bytes == CAP_BYTES, "verifier_cap_unmeasured")
    _require(cap_enforced is True, "verifier_cap_not_enforced")
    _require(type(active_limit) is int and active_limit == ACTIVE_PROCESS_LIMIT, "verifier_process_limit")
    _require(type(peak) is int and peak >= 0 and peak <= CAP_BYTES, "verifier_peak_unmeasured_or_over_cap")
    _require(type(timed_out) is bool and not timed_out, "verifier_timed_out")
    _require(type(exit_code) is int and exit_code == 0, "verifier_exit_code")
    return peak


def _row_counts(path: Path) -> dict[str, int]:
    names = (
        "minimal_proof_clearance_requests",
        "minimal_proof_clearance_audit",
        "minimal_proof_clearance_transitions",
    )
    with sqlite3.connect(path) as connection:
        values = {name: int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]) for name in names}
    return values


def _receipt_values(receipt: Any) -> tuple[bytes, bytes, int, int, bool, bool, None]:
    if type(receipt) is not MinimalClearanceReceiptV1:
        raise QualificationError("receipt_type")
    artifact_sha256 = getattr(receipt, "artifact_sha256", None)
    artifact_digest = getattr(receipt, "artifact_digest", None)
    policy_result = getattr(receipt, "policy_result", None)
    directive = getattr(receipt, "effective_directive", None)
    proof_accepted = getattr(receipt, "proof_session_accepted", None)
    economic_mutation = getattr(receipt, "economic_mutation", None)
    proof_suite_id = getattr(receipt, "proof_suite_id", object())
    _require(type(artifact_sha256) is bytes and len(artifact_sha256) == 32, "receipt_sha256")
    _require(type(artifact_digest) is bytes and len(artifact_digest) == 64, "receipt_sha3_512")
    _require(type(policy_result) is int and type(directive) is int, "receipt_directive_fields")
    _require(proof_accepted is True, "receipt_not_accepted")
    _require(economic_mutation is False, "receipt_economic_mutation")
    _require(proof_suite_id is None, "receipt_proof_suite")
    return artifact_sha256, artifact_digest, policy_result, directive, proof_accepted, economic_mutation, proof_suite_id


def build_qualification_record(
    *,
    artifact_raw: bytes,
    artifact_sha256: str,
    artifact_sha3_512: str,
    artifact_readonly_before: bool,
    artifact_readonly_after: bool,
    artifact_file_identity_unchanged: bool,
    verifier_sha256: str,
    receipt: Any,
    containment: Any,
    stdout: bytes,
    stderr: bytes,
    state_before: Any,
    state_after: Any,
    counts_before: dict[str, int],
    counts_after: dict[str, int],
    schema_version: int,
    state_verifier_sha256: bytes,
    transition_kind: str,
    integrity_pass: bool,
    restart_pass: bool,
    recovery_pass: bool,
) -> dict[str, Any]:
    """Build the closed qualification record from already-owned evidence."""
    _require(type(artifact_raw) is bytes, "artifact_raw_type")
    _require(type(artifact_sha256) is str and _HEX64.fullmatch(artifact_sha256) is not None, "artifact_sha256")
    _require(type(artifact_sha3_512) is str and re.fullmatch(r"[0-9a-fA-F]{128}", artifact_sha3_512) is not None, "artifact_sha3_512")
    _require(type(artifact_readonly_before) is bool and artifact_readonly_before, "artifact_readonly_before")
    _require(type(artifact_readonly_after) is bool and artifact_readonly_after, "artifact_readonly_after")
    _require(artifact_file_identity_unchanged is True, "artifact_file_identity")
    _require(type(verifier_sha256) is str and _HEX64.fullmatch(verifier_sha256) is not None, "verifier_sha256")
    peak = _validate_containment(containment)
    marker, dimensions, trace_digest, trace_line_count = _validate_acceptance_output(stdout, stderr)
    receipt_sha256, receipt_sha3_512, policy_result, directive, accepted, economic, suite = _receipt_values(receipt)
    _require(receipt_sha256.hex().upper() == artifact_sha256.upper(), "receipt_artifact_sha256_mismatch")
    _require(receipt_sha3_512.hex().upper() == artifact_sha3_512.upper(), "receipt_artifact_sha3_512_mismatch")
    _require(type(schema_version) is int and schema_version == 3, "state_schema")
    _require(state_verifier_sha256 == bytes.fromhex(verifier_sha256), "state_verifier_identity")
    _require(transition_kind == "PRIVATE_ZK_CLEARANCE", "state_transition_kind")
    _require(counts_before == {name: 0 for name in counts_before}, "state_counts_before")
    _require(counts_after == {name: 1 for name in counts_after}, "state_counts_after")
    _require(integrity_pass is True and restart_pass is True and recovery_pass is True, "state_recovery")
    before_payment = getattr(state_before, "payment_root", None)
    after_payment = getattr(state_after, "payment_root", None)
    before_settled = getattr(state_before, "settled_batch_count", None)
    after_settled = getattr(state_after, "settled_batch_count", None)
    _require(type(before_payment) is bytes and before_payment == after_payment, "state_payment_root")
    _require(type(before_settled) is int and before_settled == after_settled, "state_settled_count")
    record = {
        "artifact_bytes": len(artifact_raw),
        "artifact_file_identity_unchanged": artifact_file_identity_unchanged,
        "artifact_readonly_after": artifact_readonly_after,
        "artifact_readonly_before": artifact_readonly_before,
        "artifact_sha256": artifact_sha256.upper(),
        "artifact_sha3_512": artifact_sha3_512.upper(),
        "containment": {
            "acceptance_marker": marker,
            "active_process_limit": ACTIVE_PROCESS_LIMIT,
            "cap_bytes": CAP_BYTES,
            "cap_enforced": True,
            "exit_code": 0,
            "peak_job_commit_bytes": peak,
            "peak_measured": True,
            "timed_out": False,
            "build_trace_line_count": trace_line_count,
            "build_trace_sha3_512": trace_digest,
            "build_dimensions": dimensions,
        },
        "effective_directive": directive,
        "economic_mutation": economic,
        "policy_result": policy_result,
        "proof_session_accepted": accepted,
        "proof_suite_id": suite,
        "receipt_artifact_sha256": receipt_sha256.hex().upper(),
        "receipt_artifact_sha3_512": receipt_sha3_512.hex().upper(),
        "schema": SCHEMA,
        "state": {
            "audit_rows": counts_after["minimal_proof_clearance_audit"],
            "integrity_pass": integrity_pass,
            "payment_root_unchanged": True,
            "recovery_pass": recovery_pass,
            "request_rows": counts_after["minimal_proof_clearance_requests"],
            "restart_pass": restart_pass,
            "schema_version": schema_version,
            "settled_batch_count_after": after_settled,
            "settled_batch_count_before": before_settled,
            "settled_batch_count_unchanged": True,
            "transition_kind": transition_kind,
            "transition_rows": counts_after["minimal_proof_clearance_transitions"],
            "verifier_identity_bound": True,
        },
        "verifier_identity_sha256": verifier_sha256.upper(),
    }
    return record


def canonical_record_bytes(record: dict[str, Any]) -> bytes:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    _require(len(encoded) <= MAX_RECORD_BYTES, "qualification_record_size")
    _require(b"\n" not in encoded and b"\r" not in encoded, "qualification_record_newline")
    return encoded


def run_qualification(
    *,
    artifact_path: Path,
    verifier_executable: Path,
    verifier_sha256: str,
    database_path: Path,
    backup_path: Path,
    recovered_path: Path,
    expected_artifact_bytes: int,
    expected_artifact_sha256: str,
    timeout_seconds: float = 30.0 * 60.0,
) -> dict[str, Any]:
    """Run exactly one submit and return a bounded, path-free record."""
    paths = (database_path, backup_path, recovered_path)
    _require(len(set(paths)) == 3, "qualification_path_alias")
    for path in paths:
        _require(isinstance(path, Path) and not path.exists() and path.parent.is_dir(), "qualification_path_not_fresh")
    raw, sha256, sha3_512, readonly_before, token = _read_artifact_once(
        artifact_path, expected_bytes=expected_artifact_bytes, expected_sha256=expected_artifact_sha256,
    )
    verifier = NativeMinimalClearanceVerifier(
        verifier_executable, executable_sha256=verifier_sha256, timeout_seconds=timeout_seconds,
    )
    store = MinimalClearanceStateStoreV1(path=database_path, verifier=verifier)
    recovered = None
    restarted = None
    try:
        state_before = store.snapshot()
        counts_before = _row_counts(database_path)
        receipt = store.submit(artifact_path)
        containment = verifier.last_containment_result
        _validate_containment(containment)
        if containment is None:
            raise QualificationError("verifier_containment_missing")
        stdout = containment.stdout
        stderr = containment.stderr
        _validate_acceptance_output(stdout, stderr)
        readonly_after = _check_artifact_after(
            artifact_path, expected_bytes=len(raw), before_readonly=readonly_before, before_token=token,
        )
        state_after = store.snapshot()
        counts_after = _row_counts(database_path)
        with sqlite3.connect(database_path) as connection:
            state_row = connection.execute(
                "SELECT schema_version, expected_verifier_sha256 FROM minimal_proof_clearance_state WHERE id=1"
            ).fetchone()
            transition_row = connection.execute(
                "SELECT transition_kind FROM minimal_proof_clearance_transitions"
            ).fetchone()
        _require(state_row is not None and transition_row is not None, "state_rows_missing")
        store.verify_integrity()
        store.create_backup(backup_path)
        recovered = store.recover_from_backup(backup_path=backup_path, recovered_path=recovered_path)
        recovered.verify_integrity()
        recovered_state = recovered.snapshot()
        recovered.close()
        recovered = None
        store.close()
        store = None  # type: ignore[assignment]
        restart_verifier = NativeMinimalClearanceVerifier(
            verifier_executable, executable_sha256=verifier_sha256, timeout_seconds=timeout_seconds,
        )
        restarted = MinimalClearanceStateStoreV1(path=database_path, verifier=restart_verifier)
        restarted.verify_integrity()
        restart_state = restarted.snapshot()
        restarted.close()
        restarted = None
        _require(recovered_state == state_after, "recovery_state_mismatch")
        _require(restart_state == state_after, "restart_state_mismatch")
        _require(int(state_row[0]) == 3, "state_schema")
        _require(bytes(state_row[1]) == bytes.fromhex(verifier_sha256), "state_verifier_identity")
        _require(transition_row[0] == "PRIVATE_ZK_CLEARANCE", "state_transition_kind")
        return build_qualification_record(
            artifact_raw=raw, artifact_sha256=sha256, artifact_sha3_512=sha3_512,
            artifact_readonly_before=readonly_before, artifact_readonly_after=readonly_after,
            artifact_file_identity_unchanged=True, verifier_sha256=verifier_sha256,
            receipt=receipt, containment=containment, stdout=stdout, stderr=stderr,
            state_before=state_before, state_after=state_after, counts_before=counts_before,
            counts_after=counts_after, schema_version=int(state_row[0]),
            state_verifier_sha256=bytes(state_row[1]), transition_kind=str(transition_row[0]),
            integrity_pass=True, restart_pass=True, recovery_pass=True,
        )
    finally:
        if restarted is not None:
            restarted.close()
        if recovered is not None:
            recovered.close()
        if store is not None:
            store.close()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--recovered", type=Path, required=True)
    parser.add_argument("--artifact-bytes", type=int, required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30.0 * 60.0)
    args = parser.parse_args(argv)
    try:
        record = run_qualification(
            artifact_path=args.artifact, verifier_executable=args.verifier,
            verifier_sha256=args.verifier_sha256, database_path=args.database,
            backup_path=args.backup, recovered_path=args.recovered,
            expected_artifact_bytes=args.artifact_bytes,
            expected_artifact_sha256=args.artifact_sha256,
            timeout_seconds=args.timeout_seconds,
        )
        sys.stdout.buffer.write(canonical_record_bytes(record) + b"\n")
        return 0
    except Exception as exc:
        message = str(exc)
        if "/" in message or "\\" in message:
            message = "qualification_failed"
        sys.stderr.write("qualification_failed:" + message + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
