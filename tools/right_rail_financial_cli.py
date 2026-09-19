"""Bounded local CLI for the synthetic RightRail financial Mirror.

The CLI opens one existing owner database and delegates all reads, commands,
continuity validation, and restore work to ``FinancialMirror``.  It has no
network, payment, corporate-egress, or direct-SQLite path.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorDispatchError,
    FinancialMirrorError,
    MAX_PACKAGE_BYTES,
)
from app.right_rail_financial_owner import (
    FinancialError,
    FinancialOwner,
    FinancialOwnerConfig,
    SyntheticTrustedAuthority,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True, help="existing FinancialOwner database")
    parser.add_argument("--state-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--period-id", required=True)
    parser.add_argument("--currency", default="USD")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("summary")

    obligations = subparsers.add_parser("list-obligations", aliases=("obligations",))
    obligations.add_argument("--status", choices=("OPEN", "ALL", "SATISFIED", "CASH_UNSATISFIED"), default="OPEN")
    obligations.add_argument("--limit", type=int, default=100)
    obligations.add_argument("--offset", type=int, default=0)

    detail = subparsers.add_parser("obligation-detail", aliases=("detail",))
    detail.add_argument("--item-id", required=True)
    detail.add_argument("--limit", type=int, default=100)

    history = subparsers.add_parser("history")
    history.add_argument("--limit", type=int, default=100)
    history.add_argument("--offset", type=int, default=0)

    action = subparsers.add_parser("action-payload", aliases=("action",))
    action.add_argument("--action-id", required=True)

    authorize = subparsers.add_parser("authorize-offset")
    _add_offset_arguments(authorize)

    reject = subparsers.add_parser("reject-offset-and-authorize-correction", aliases=("reject-offset",))
    _add_offset_arguments(reject)

    acknowledge = subparsers.add_parser("acknowledge-action", aliases=("acknowledge",))
    acknowledge.add_argument("--action-id", required=True)
    acknowledge.add_argument("--acknowledgment-ref", required=True)
    acknowledge.add_argument("--actor-id", default="synthetic-receiver")
    acknowledge.add_argument("--actor-role", default="RECEIVER")

    payment = subparsers.add_parser("record-payment-evidence", aliases=("record-payment",))
    payment.add_argument("--item-id", required=True)
    payment.add_argument("--payment-id", required=True)
    payment.add_argument("--common-origin-id", required=True)
    payment.add_argument("--amount-cents", type=int, required=True)
    payment.add_argument("--evidence-id", required=True)
    payment.add_argument("--event-at-ms", type=int, required=True)
    payment.add_argument("--source-id", default="synthetic-payment-source")
    payment.add_argument("--source-version", default="fixture-v1")
    payment.add_argument("--local-ref")
    payment.add_argument("--expected-revision", type=int)

    report = subparsers.add_parser("record-reporting-correction", aliases=("reporting-correction",))
    report.add_argument("--item-id", required=True)
    report.add_argument("--report-id", required=True)
    report.add_argument("--evidence-id")
    report.add_argument("--actor-id", default="synthetic-reporter")
    report.add_argument("--actor-role", default="REPORTING_EDITOR")
    report.add_argument("--expected-revision", type=int)
    report.add_argument("--event-at-ms", type=int)
    report.add_argument("--supersedes")

    subparsers.add_parser("verify-integrity")

    export = subparsers.add_parser("export-continuity")
    export.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate-continuity")
    validate.add_argument("--package", type=Path, required=True)

    restore = subparsers.add_parser("restore-continuity")
    restore.add_argument("--package", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)

    subparsers.add_parser("dispatch-outbox")
    return parser


def _add_offset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--item-id", required=True)
    parser.add_argument("--claim-id", required=True)
    parser.add_argument("--actor-id", default="synthetic-official")
    parser.add_argument("--actor-role", default="FINANCE_DECISION")
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--action-id")
    parser.add_argument("--decision-at-ms", type=int)


def _existing_database(path: Path) -> Path:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise FinancialMirrorError("database_missing")
    return path


def _owner(args: argparse.Namespace) -> FinancialOwner:
    database = _existing_database(args.database)
    config = FinancialOwnerConfig(
        state_id=args.state_id,
        deployment_id=args.deployment_id,
        program_id=args.program_id,
        period_id=args.period_id,
        currency=args.currency,
    )
    return FinancialOwner(path=database, config=config, trusted_authority=SyntheticTrustedAuthority())


def _read_package(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FinancialMirrorError("continuity_package_missing")
    with path.open("rb") as stream:
        package = stream.read(MAX_PACKAGE_BYTES + 1)
    if len(package) > MAX_PACKAGE_BYTES:
        raise FinancialMirrorError("continuity_package_size")
    return package


def _write_new(path: Path, value: bytes) -> None:
    if path.is_symlink() or not path.parent.is_dir():
        raise FinancialMirrorError("continuity_output_destination")
    try:
        with path.open("xb") as stream:
            stream.write(value)
    except FileExistsError:
        raise FinancialMirrorError("continuity_output_exists") from None


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _run(args: argparse.Namespace) -> Any:
    owner = _owner(args)
    mirror = FinancialMirror(owner)
    command = args.command

    if command == "summary":
        return mirror.summary()
    if command in {"list-obligations", "obligations"}:
        return mirror.list_obligations(status=args.status, limit=args.limit, offset=args.offset)
    if command in {"obligation-detail", "detail"}:
        return mirror.obligation_detail(args.item_id, limit=args.limit)
    if command == "history":
        return mirror.history(limit=args.limit, offset=args.offset)
    if command in {"action-payload", "action"}:
        return mirror.action_payload(args.action_id)
    if command == "authorize-offset":
        return mirror.authorize_offset(
            item_id=args.item_id,
            claim_id=args.claim_id,
            actor_id=args.actor_id,
            actor_role=args.actor_role,
            expected_revision=args.expected_revision,
            action_id=args.action_id,
            decision_at_ms=args.decision_at_ms,
        )
    if command in {"reject-offset-and-authorize-correction", "reject-offset"}:
        return mirror.reject_offset_and_authorize_correction(
            item_id=args.item_id,
            claim_id=args.claim_id,
            actor_id=args.actor_id,
            actor_role=args.actor_role,
            expected_revision=args.expected_revision,
            action_id=args.action_id,
            decision_at_ms=args.decision_at_ms,
        )
    if command in {"acknowledge-action", "acknowledge"}:
        return mirror.acknowledge_action(
            args.action_id,
            args.acknowledgment_ref,
            actor_id=args.actor_id,
            actor_role=args.actor_role,
        )
    if command in {"record-payment-evidence", "record-payment"}:
        return mirror.record_payment_evidence(
            item_id=args.item_id,
            payment_id=args.payment_id,
            common_origin_id=args.common_origin_id,
            amount_cents=args.amount_cents,
            evidence_id=args.evidence_id,
            event_at_ms=args.event_at_ms,
            source_id=args.source_id,
            source_version=args.source_version,
            local_ref=args.local_ref,
            expected_revision=args.expected_revision,
        )
    if command in {"record-reporting-correction", "reporting-correction"}:
        return mirror.record_reporting_correction(
            item_id=args.item_id,
            report_id=args.report_id,
            evidence_id=args.evidence_id,
            actor_id=args.actor_id,
            actor_role=args.actor_role,
            expected_revision=args.expected_revision,
            event_at_ms=args.event_at_ms,
            supersedes=args.supersedes,
        )
    if command == "verify-integrity":
        return mirror.verify_integrity()
    if command == "export-continuity":
        package = mirror.export_continuity()
        _write_new(args.output, package)
        return {"schema": "RR/FINANCIAL/MIRROR/v1", "status": "EXPORTED", "path": str(args.output), "package_bytes": len(package)}
    if command == "validate-continuity":
        return mirror.validate_continuity_package(_read_package(args.package))
    if command == "restore-continuity":
        shadow = mirror.restore_continuity(_read_package(args.package), args.destination)
        return {"status": "RESTORED_SHADOW", "destination": str(args.destination), "integrity": shadow.verify_integrity()}
    if command == "dispatch-outbox":
        mirror.dispatch_outbox()
        raise FinancialMirrorDispatchError("dispatch_disabled")
    raise FinancialMirrorError("unknown_command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _run(args)
    except FinancialMirrorDispatchError as error:
        print(f"ERROR:{error}", file=sys.stderr)
        return 3
    except (FinancialMirrorError, FinancialError, OSError, ValueError) as error:
        print(f"ERROR:{error}", file=sys.stderr)
        return 2
    if result is not None:
        print(_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
