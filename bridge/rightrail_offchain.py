#!/usr/bin/env python3
"""Append-only, off-chain RightRail ledger and reconciliation boundary.

This module deliberately has no proof, chain, payment-processor, or external
RightRail runtime dependency. The journal is the sole authoritative file. All
reports are deterministic read-only projections rebuilt from that journal.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterator


EVENT_SCHEMA = "localbce-rightrail-offchain-ledger-event-v1"
REMITTANCE_SCHEMA = "localbce-rightrail-remittance-event-v1"
REPORT_SCHEMA = "localbce-rightrail-reconciliation-report-v1"
GENESIS_HASH = "0" * 64
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CLAIM_HASH_RE = re.compile(r"0x[0-9a-f]{64}\Z")
EVENT_TYPES = frozenset({"ADJUDICATION_RECORDED", "REMITTANCE_RECORDED"})
REMITTANCE_KINDS = frozenset(
    {
        "PAYMENT",
        "REPAYMENT",
        "REVERSAL",
        "PARTIAL_RECOUPMENT",
        "PLB_ADJUSTMENT",
    }
)
EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "event_id",
        "event_type",
        "aggregate_id",
        "idempotency_key",
        "recorded_at",
        "payload",
        "payload_sha256",
        "previous_event_sha256",
        "event_sha256",
    }
)
ADJUDICATION_RESULT_FIELDS = frozenset(
    {"claim_id", "claim_hash", "status", "reason", "tx_submitted", "tx_hash"}
)
REMITTANCE_FIELDS = frozenset(
    {
        "schema_version",
        "remittance_id",
        "claim_hash",
        "event_kind",
        "delta_cents",
        "payer_trace_sha256",
        "source_artifact_sha256",
        "occurred_at",
        "synthetic_data",
    }
)


class LedgerError(ValueError):
    """Stable base error for malformed or conflicting ledger operations."""


class LedgerConflictError(LedgerError):
    """Raised when an idempotency key is reused with different content."""


class LedgerBusyError(LedgerError):
    """Raised when another writer owns the journal lock."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _require_exact_fields(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise LedgerError(f"{label} fields mismatch: missing={missing}, unknown={unknown}")


def _require_string(value: Any, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise LedgerError(f"{label} must be a non-empty string of at most {maximum} characters")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LedgerError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _require_claim_hash(value: Any) -> str:
    if not isinstance(value, str) or CLAIM_HASH_RE.fullmatch(value) is None:
        raise LedgerError("claim_hash must be 0x-prefixed lowercase 32-byte hex")
    return value


def _require_integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise LedgerError(f"{label} must be at least {minimum}")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_string(value, label, maximum=64)
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise LedgerError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LedgerError(f"{label} must include a timezone")
    return text


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_hash_input(event: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "event_sha256"}


def _event_id(event_type: str, idempotency_key: str, payload_sha256: str) -> str:
    digest = canonical_sha256(
        {
            "domain": "LOCALBCE/RIGHTRAIL/OFFCHAIN-EVENT-ID/v1",
            "event_type": event_type,
            "idempotency_key": idempotency_key,
            "payload_sha256": payload_sha256,
        }
    )
    return f"rrevt-{digest[:32]}"


def _validate_adjudication_payload(payload: dict[str, Any]) -> None:
    expected = frozenset(
        {
            "claim_id",
            "claim_hash",
            "decision",
            "reason",
            "owed_cents",
            "program",
            "jurisdiction",
            "source_result_sha256",
            "proof_execution",
            "settlement_backend",
            "tx_submitted",
            "tx_hash",
            "synthetic_data",
        }
    )
    _require_exact_fields(payload, expected, "adjudication payload")
    _require_string(payload["claim_id"], "claim_id", maximum=128)
    _require_claim_hash(payload["claim_hash"])
    if payload["decision"] not in {"APPROVED", "DENIED"}:
        raise LedgerError("decision must be APPROVED or DENIED")
    if payload["decision"] == "APPROVED" and payload["reason"] is not None:
        raise LedgerError("approved adjudication reason must be null")
    if payload["decision"] == "DENIED":
        _require_string(payload["reason"], "reason", maximum=256)
    owed_cents = _require_integer(payload["owed_cents"], "owed_cents", minimum=0)
    if payload["decision"] == "DENIED" and owed_cents != 0:
        raise LedgerError("denied adjudication must have owed_cents=0")
    _require_string(payload["program"], "program", maximum=128)
    _require_string(payload["jurisdiction"], "jurisdiction", maximum=64)
    _require_sha256(payload["source_result_sha256"], "source_result_sha256")
    if payload["proof_execution"] is not False:
        raise LedgerError("proof_execution must remain false")
    if payload["settlement_backend"] != "none":
        raise LedgerError("settlement_backend must remain none")
    if payload["tx_submitted"] is not False or payload["tx_hash"] is not None:
        raise LedgerError("off-chain adjudication cannot contain a submitted transaction")
    if payload["synthetic_data"] is not True:
        raise LedgerError("only synthetic adjudication data is accepted")


def validate_remittance(value: dict[str, Any]) -> dict[str, Any]:
    _require_exact_fields(value, REMITTANCE_FIELDS, "remittance event")
    if value["schema_version"] != REMITTANCE_SCHEMA:
        raise LedgerError("unexpected remittance schema_version")
    _require_string(value["remittance_id"], "remittance_id", maximum=128)
    _require_claim_hash(value["claim_hash"])
    if value["event_kind"] not in REMITTANCE_KINDS:
        raise LedgerError("unsupported remittance event_kind")
    _require_integer(value["delta_cents"], "delta_cents")
    if value["event_kind"] in {"PAYMENT", "REPAYMENT"} and value["delta_cents"] <= 0:
        raise LedgerError("payment and repayment deltas must be positive")
    if value["event_kind"] in {"REVERSAL", "PARTIAL_RECOUPMENT"} and value["delta_cents"] >= 0:
        raise LedgerError("reversal and recoupment deltas must be negative")
    _require_sha256(value["payer_trace_sha256"], "payer_trace_sha256")
    _require_sha256(value["source_artifact_sha256"], "source_artifact_sha256")
    _require_timestamp(value["occurred_at"], "occurred_at")
    if value["synthetic_data"] is not True:
        raise LedgerError("only synthetic remittance data is accepted")
    return value


def _validate_event(event: dict[str, Any], expected_sequence: int, previous_hash: str) -> None:
    _require_exact_fields(event, EVENT_FIELDS, "ledger event")
    if event["schema_version"] != EVENT_SCHEMA:
        raise LedgerError("unexpected ledger event schema_version")
    if _require_integer(event["sequence"], "sequence", minimum=1) != expected_sequence:
        raise LedgerError("ledger sequence is not contiguous")
    _require_string(event["event_id"], "event_id", maximum=64)
    if event["event_type"] not in EVENT_TYPES:
        raise LedgerError("unsupported ledger event_type")
    _require_claim_hash(event["aggregate_id"])
    _require_string(event["idempotency_key"], "idempotency_key", maximum=256)
    _require_timestamp(event["recorded_at"], "recorded_at")
    if not isinstance(event["payload"], dict):
        raise LedgerError("payload must be an object")
    payload_hash = _require_sha256(event["payload_sha256"], "payload_sha256")
    if payload_hash != canonical_sha256(event["payload"]):
        raise LedgerError("payload_sha256 mismatch")
    if event["previous_event_sha256"] != previous_hash:
        raise LedgerError("previous_event_sha256 mismatch")
    _require_sha256(event["event_sha256"], "event_sha256")
    if event["event_sha256"] != canonical_sha256(_event_hash_input(event)):
        raise LedgerError("event_sha256 mismatch")
    if event["event_id"] != _event_id(
        event["event_type"], event["idempotency_key"], payload_hash
    ):
        raise LedgerError("event_id mismatch")
    if event["event_type"] == "ADJUDICATION_RECORDED":
        _validate_adjudication_payload(event["payload"])
    else:
        validate_remittance(event["payload"])


def load_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LedgerError(f"could not read ledger: {error}") from error
    events: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    idempotency: dict[str, str] = {}
    event_ids: set[str] = set()
    for index, line in enumerate(lines, start=1):
        if not line:
            raise LedgerError("ledger cannot contain blank lines")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise LedgerError(f"ledger line {index} is not valid JSON") from error
        if not isinstance(event, dict):
            raise LedgerError(f"ledger line {index} must be an object")
        _validate_event(event, index, previous_hash)
        if event["event_id"] in event_ids:
            raise LedgerError("duplicate event_id in ledger")
        event_ids.add(event["event_id"])
        prior_payload = idempotency.get(event["idempotency_key"])
        if prior_payload is not None:
            raise LedgerError("duplicate idempotency_key persisted in ledger")
        idempotency[event["idempotency_key"]] = event["payload_sha256"]
        previous_hash = event["event_sha256"]
        events.append(event)
    return events


@contextmanager
def _writer_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise LedgerBusyError("ledger_writer_busy") from error
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as lock_file:
            lock_file.write(f"pid={os.getpid()}\n")
            lock_file.flush()
            os.fsync(lock_file.fileno())
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_lines(path: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            for event in events:
                output.write(canonical_json_bytes(event))
                output.write(b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def append_event(
    path: Path,
    *,
    event_type: str,
    aggregate_id: str,
    idempotency_key: str,
    payload: dict[str, Any],
    recorded_at: str,
) -> tuple[dict[str, Any], bool]:
    if event_type not in EVENT_TYPES:
        raise LedgerError("unsupported event_type")
    _require_claim_hash(aggregate_id)
    _require_string(idempotency_key, "idempotency_key", maximum=256)
    _require_timestamp(recorded_at, "recorded_at")
    if event_type == "ADJUDICATION_RECORDED":
        _validate_adjudication_payload(payload)
    else:
        validate_remittance(payload)
    payload_hash = canonical_sha256(payload)

    with _writer_lock(path):
        events = load_ledger(path)
        for existing in events:
            if existing["idempotency_key"] != idempotency_key:
                continue
            if existing["payload_sha256"] == payload_hash:
                return existing, False
            raise LedgerConflictError("idempotency_conflict")

        previous_hash = events[-1]["event_sha256"] if events else GENESIS_HASH
        event = {
            "schema_version": EVENT_SCHEMA,
            "sequence": len(events) + 1,
            "event_id": _event_id(event_type, idempotency_key, payload_hash),
            "event_type": event_type,
            "aggregate_id": aggregate_id,
            "idempotency_key": idempotency_key,
            "recorded_at": recorded_at,
            "payload": payload,
            "payload_sha256": payload_hash,
            "previous_event_sha256": previous_hash,
        }
        event["event_sha256"] = canonical_sha256(event)
        events.append(event)
        _atomic_write_lines(path, events)
        return event, True


def record_adjudication(
    ledger_path: Path,
    result_path: Path,
    *,
    owed_cents: int,
    program: str,
    jurisdiction: str,
    recorded_at: str,
) -> tuple[dict[str, Any], bool]:
    try:
        source_bytes = result_path.read_bytes()
        result = json.loads(source_bytes)
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"could not read adjudication result: {error}") from error
    if not isinstance(result, dict):
        raise LedgerError("adjudication result must be an object")
    _require_exact_fields(result, ADJUDICATION_RESULT_FIELDS, "adjudication result")
    decision = result["status"]
    if decision not in {"APPROVED", "DENIED"}:
        raise LedgerError("adjudication status must be APPROVED or DENIED")
    if result["tx_submitted"] is not False or result["tx_hash"] is not None:
        raise LedgerError("proof or chain-submitted adjudication cannot enter off-chain ledger")
    payload = {
        "claim_id": result["claim_id"],
        "claim_hash": result["claim_hash"],
        "decision": decision,
        "reason": result["reason"],
        "owed_cents": owed_cents if decision == "APPROVED" else 0,
        "program": program,
        "jurisdiction": jurisdiction,
        "source_result_sha256": sha256_bytes(source_bytes),
        "proof_execution": False,
        "settlement_backend": "none",
        "tx_submitted": False,
        "tx_hash": None,
        "synthetic_data": True,
    }
    return append_event(
        ledger_path,
        event_type="ADJUDICATION_RECORDED",
        aggregate_id=result["claim_hash"],
        idempotency_key=f"adjudication:{result['claim_hash']}",
        payload=payload,
        recorded_at=recorded_at,
    )


def record_remittance(
    ledger_path: Path, event_path: Path, *, recorded_at: str
) -> tuple[dict[str, Any], bool]:
    try:
        value = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"could not read remittance event: {error}") from error
    if not isinstance(value, dict):
        raise LedgerError("remittance event must be an object")
    validate_remittance(value)
    return append_event(
        ledger_path,
        event_type="REMITTANCE_RECORDED",
        aggregate_id=value["claim_hash"],
        idempotency_key=f"remittance:{value['remittance_id']}",
        payload=value,
        recorded_at=recorded_at,
    )


def build_reconciliation_report(
    events: list[dict[str, Any]], *, as_of: str | None = None
) -> dict[str, Any]:
    if as_of is None:
        as_of = events[-1]["recorded_at"] if events else "1970-01-01T00:00:00Z"
    _require_timestamp(as_of, "as_of")
    adjudications: dict[str, dict[str, Any]] = {}
    remittances: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        claim_hash = event["aggregate_id"]
        if event["event_type"] == "ADJUDICATION_RECORDED":
            adjudications[claim_hash] = event
        else:
            remittances.setdefault(claim_hash, []).append(event)

    claims: list[dict[str, Any]] = []
    for claim_hash in sorted(set(adjudications) | set(remittances)):
        adjudication = adjudications.get(claim_hash)
        claim_remittances = remittances.get(claim_hash, [])
        net_cents = sum(item["payload"]["delta_cents"] for item in claim_remittances)
        if adjudication is None:
            status = "HOLD_ORPHAN_REMITTANCE"
            decision = None
            owed_cents = None
            claim_id = None
        else:
            payload = adjudication["payload"]
            decision = payload["decision"]
            owed_cents = payload["owed_cents"]
            claim_id = payload["claim_id"]
            if decision == "DENIED":
                status = (
                    "RECONCILED_DENIED_NO_PAYMENT"
                    if net_cents == 0
                    else "HOLD_PAYMENT_FOR_DENIED_CLAIM"
                )
            elif net_cents == owed_cents:
                status = "RECONCILED"
            elif net_cents == 0:
                status = "AWAITING_REMITTANCE"
            elif net_cents < owed_cents:
                status = "HOLD_UNDERPAID"
            else:
                status = "HOLD_OVERPAID"
        claims.append(
            {
                "claim_hash": claim_hash,
                "claim_id": claim_id,
                "decision": decision,
                "owed_cents": owed_cents,
                "net_remittance_cents": net_cents,
                "status": status,
                "adjudication_event_id": (
                    adjudication["event_id"] if adjudication is not None else None
                ),
                "remittance_event_ids": sorted(
                    item["event_id"] for item in claim_remittances
                ),
            }
        )

    report = {
        "schema_version": REPORT_SCHEMA,
        "as_of": as_of,
        "runtime_activation": False,
        "proof_binding": False,
        "proof_execution": False,
        "settlement_backend": "none",
        "money_movement": False,
        "ledger_event_count": len(events),
        "ledger_head_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
        "claims": claims,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(json.dumps(value, indent=2, sort_keys=True).encode("ascii"))
            output.write(b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    adjudication = subparsers.add_parser("record-adjudication")
    adjudication.add_argument("--ledger", type=Path, required=True)
    adjudication.add_argument("--result", type=Path, required=True)
    adjudication.add_argument("--owed-cents", type=int, required=True)
    adjudication.add_argument("--program", required=True)
    adjudication.add_argument("--jurisdiction", required=True)
    adjudication.add_argument("--recorded-at", default=None)

    remittance = subparsers.add_parser("record-remittance")
    remittance.add_argument("--ledger", type=Path, required=True)
    remittance.add_argument("--event", type=Path, required=True)
    remittance.add_argument("--recorded-at", default=None)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--ledger", type=Path, required=True)

    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--ledger", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    reconcile.add_argument("--as-of", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "record-adjudication":
        event, appended = record_adjudication(
            args.ledger,
            args.result,
            owed_cents=args.owed_cents,
            program=args.program,
            jurisdiction=args.jurisdiction,
            recorded_at=args.recorded_at or utc_now(),
        )
        result = {"status": "ok", "appended": appended, "event": event}
    elif args.command == "record-remittance":
        event, appended = record_remittance(
            args.ledger,
            args.event,
            recorded_at=args.recorded_at or utc_now(),
        )
        result = {"status": "ok", "appended": appended, "event": event}
    elif args.command == "verify":
        events = load_ledger(args.ledger)
        result = {
            "status": "ok",
            "event_count": len(events),
            "ledger_head_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
        }
    else:
        events = load_ledger(args.ledger)
        report = build_reconciliation_report(events, as_of=args.as_of)
        write_json_atomic(args.output, report)
        result = {
            "status": "ok",
            "output": str(args.output),
            "report_sha256": report["report_sha256"],
            "claim_count": len(report["claims"]),
        }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        print(json.dumps({"status": "error", "error": str(error)}, sort_keys=True))
        raise SystemExit(1) from None
