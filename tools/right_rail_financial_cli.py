"""Bounded local CLI for the synthetic RightRail financial Mirror and Switch.

Owner commands open one existing database and delegate reads, commands,
Continuity validation, and restore work to ``FinancialMirror``. Switch
commands accept a verified SHADOW package and result records without opening
an Owner database. The CLI has no network, payment, or direct-SQLite path.
"""

from __future__ import annotations

import argparse
import hashlib
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
from app.right_rail_financial_switch import (
    COHORT_APPROVAL_CONTRACT,
    CandidateSpec,
    CohortApproval,
    DifferencePolicy,
    FinancialSwitchError,
    ReferenceSpec,
    decode_replay_input,
    prepare_shadow_replay_input,
    run_shadow_replay,
)
from app.right_rail_financial_owner import (
    FinancialError,
    FinancialOwner,
    FinancialOwnerConfig,
    SyntheticTrustedAuthority,
)


CLI_REFERENCE_SPEC_CONTRACT = "RR/SWITCH/CLI-REFERENCE-SPEC/v1"
CLI_CANDIDATE_SPEC_CONTRACT = "RR/SWITCH/CLI-CANDIDATE-SPEC/v1"
SWITCH_COMPARE_CLI_REPORT_CONTRACT = "RR/SWITCH/CLI-COMPARE-REPORT/v1"
SWITCH_COMPARE_INCOMPLETE_EXIT = 4
MAX_SWITCH_DOCUMENT_BYTES = 16 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, help="existing FinancialOwner database for Owner commands")
    parser.add_argument("--state-id")
    parser.add_argument("--deployment-id")
    parser.add_argument("--program-id")
    parser.add_argument("--period-id")
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

    receipt = subparsers.add_parser("current-evaluation-receipt", aliases=("evaluation-receipt", "evaluation"))
    receipt.add_argument("--item-id", required=True)

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

    switch_prepare = subparsers.add_parser("switch-prepare", help="write one canonical Switch replay input; runs no evaluator")
    _add_switch_files(switch_prepare, required=True)
    switch_prepare.add_argument("--output", type=Path, required=True, help="new replay-input file; existing paths are never replaced")

    switch_compare = subparsers.add_parser("switch-compare", help="compare supplied reference and candidate result records")
    switch_compare.add_argument("--package", type=Path, required=True)
    switch_compare.add_argument("--cohort-approval", type=Path)
    switch_compare.add_argument("--reference-spec", type=Path)
    switch_compare.add_argument("--candidate-spec", type=Path)
    switch_compare.add_argument("--report-output", type=Path, help="optional new canonical JSON report file")

    subparsers.add_parser("dispatch-outbox")
    return parser


def _add_switch_files(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--package", type=Path, required=True, help="exact Continuity SHADOW package bytes")
    parser.add_argument("--cohort-approval", type=Path, required=required)
    parser.add_argument("--reference-spec", type=Path, required=required)
    parser.add_argument("--candidate-spec", type=Path, required=required)


def _add_offset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--item-id", required=True)
    parser.add_argument("--claim-id", required=True)
    parser.add_argument("--actor-id", default="synthetic-official")
    parser.add_argument("--actor-role", default="FINANCE_DECISION")
    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument("--action-id")
    parser.add_argument("--decision-at-ms", type=int)
    parser.add_argument("--evaluation-id", required=True)
    parser.add_argument("--evaluation-result-digest", required=True)


def _existing_database(path: Path) -> Path:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise FinancialMirrorError("database_missing")
    return path


def _owner(args: argparse.Namespace) -> FinancialOwner:
    database = _existing_database(args.database)
    if any(
        type(value) is not str or not value
        for value in (args.state_id, args.deployment_id, args.program_id, args.period_id)
    ):
        raise FinancialMirrorError("financial_scope_missing")
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


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FinancialMirrorError("switch_json_duplicate_key")
        value[key] = item
    return value


def _reject_switch_json_constant(_value: str) -> object:
    raise FinancialMirrorError("switch_json_nonstandard_number")


def _read_switch_json(path: Path, label: str) -> dict[str, object]:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise FinancialMirrorError(f"{label}_missing")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SWITCH_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_SWITCH_DOCUMENT_BYTES:
        raise FinancialMirrorError(f"{label}_size")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_switch_json_constant,
        )
    except FinancialMirrorError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise FinancialMirrorError(f"{label}_json") from None
    if type(value) is not dict:
        raise FinancialMirrorError(f"{label}_object")
    return value


def _switch_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise FinancialMirrorError(f"{label}_fields")
    return value


def _read_cohort_approval(path: Path) -> CohortApproval:
    expected = {
        "contract", "approval_id", "cohort_id", "test_identity", "approved_by",
        "approval_ref", "source_class", "receiver_boundary_ref", "custody_ref",
        "permissions_ref", "pending_boundary_ref", "binding_sha256",
    }
    value = _switch_keys(_read_switch_json(path, "switch_approval"), expected, "switch_approval")
    if value.get("contract") != COHORT_APPROVAL_CONTRACT:
        raise FinancialMirrorError("switch_approval_contract")
    return CohortApproval(
        approval_id=value["approval_id"],
        cohort_id=value["cohort_id"],
        test_identity=value["test_identity"],
        approved_by=value["approved_by"],
        approval_ref=value["approval_ref"],
        source_class=value["source_class"],
        receiver_boundary_ref=value["receiver_boundary_ref"],
        custody_ref=value["custody_ref"],
        permissions_ref=value["permissions_ref"],
        pending_boundary_ref=value["pending_boundary_ref"],
        binding_sha256=value["binding_sha256"],
        contract=value["contract"],
    )


def _read_difference_policies(value: object, label: str) -> tuple[DifferencePolicy, ...]:
    if type(value) is not list or len(value) > 10000:
        raise FinancialMirrorError(f"{label}_shape")
    policies: list[DifferencePolicy] = []
    for record in value:
        record = _switch_keys(record, {"path", "classification", "rationale", "approval_ref"}, label)
        policies.append(DifferencePolicy(
            path=record["path"],
            classification=record["classification"],
            rationale=record["rationale"],
            approval_ref=record["approval_ref"],
        ))
    return tuple(policies)


def _read_reference_spec(path: Path) -> ReferenceSpec:
    required = {"contract", "identity", "expected_differences", "forbidden_differences"}
    allowed = required | {"result"}
    value = _read_switch_json(path, "switch_reference")
    if frozenset(value) not in {frozenset(required), frozenset(allowed)}:
        raise FinancialMirrorError("switch_reference_fields")
    if value.get("contract") != CLI_REFERENCE_SPEC_CONTRACT:
        raise FinancialMirrorError("switch_reference_contract")
    identity = _switch_keys(
        value.get("identity"),
        {"reference_id", "version", "authority_id", "reviewer_id", "source_ref", "source_sha256", "tool_version"},
        "switch_reference_identity",
    )
    answer = value.get("result")

    def supplied_answer(_replay_input: bytes, result: object = answer) -> object:
        return result

    return ReferenceSpec(
        reference_id=identity["reference_id"],
        version=identity["version"],
        authority_id=identity["authority_id"],
        reviewer_id=identity["reviewer_id"],
        source_ref=identity["source_ref"],
        source_sha256=identity["source_sha256"],
        tool_version=identity["tool_version"],
        evaluate=supplied_answer,
        expected_differences=_read_difference_policies(value["expected_differences"], "switch_expected_differences"),
        forbidden_differences=_read_difference_policies(value["forbidden_differences"], "switch_forbidden_differences"),
    )


def _read_candidate_spec(path: Path) -> CandidateSpec:
    required = {"contract", "identity"}
    allowed = required | {"result"}
    value = _read_switch_json(path, "switch_candidate")
    if frozenset(value) not in {frozenset(required), frozenset(allowed)}:
        raise FinancialMirrorError("switch_candidate_fields")
    if value.get("contract") != CLI_CANDIDATE_SPEC_CONTRACT:
        raise FinancialMirrorError("switch_candidate_contract")
    identity = _switch_keys(
        value.get("identity"),
        {"operator_id", "version", "tool_version", "release_sha256"},
        "switch_candidate_identity",
    )
    result = value.get("result")

    def supplied_result(_replay_input: bytes, output: object = result) -> object:
        return output

    return CandidateSpec(
        operator_id=identity["operator_id"],
        version=identity["version"],
        tool_version=identity["tool_version"],
        release_sha256=identity["release_sha256"],
        evaluate=supplied_result,
    )


def _try_switch_document(path: Path | None, loader: Any, label: str) -> tuple[Any, list[str]]:
    if path is None:
        return None, []
    try:
        return loader(path), []
    except (FinancialMirrorError, OSError) as error:
        return None, [f"{label}_invalid:{error}"]


def _verify_switch_package(package: bytes) -> None:
    verified = FinancialMirror.validate_continuity_package(package)
    if (
        verified.get("version") != 7
        or verified.get("mode") != "SHADOW"
        or verified.get("dispatch_enabled") is not False
        or verified.get("egress_enabled") is not False
    ):
        raise FinancialSwitchError("switch:continuity-v7-shadow-required")


def _switch_prepare(args: argparse.Namespace) -> dict[str, object]:
    package = _read_package(args.package)
    _verify_switch_package(package)
    approval = _read_cohort_approval(args.cohort_approval)
    reference = _read_reference_spec(args.reference_spec)
    candidate = _read_candidate_spec(args.candidate_spec)
    replay_input = prepare_shadow_replay_input(
        package,
        cohort_approval=approval,
        reference=reference,
        candidate=candidate,
    )
    decoded = decode_replay_input(replay_input)
    _write_new(args.output, replay_input)
    return {
        "contract": "RR/SWITCH/CLI-PREPARE-REPORT/v1",
        "status": "READY_FOR_EXTERNAL_COMPARISON",
        "replay_input_sha256": decoded.input_sha256,
        "replay_input_bytes": len(replay_input),
        "replay_input_path": str(args.output),
        "snapshot_sha256": hashlib.sha256(package).hexdigest().upper(),
        "candidate_authority": "NONE",
        "transfer_authorized": False,
        "source_class_verification": "CALLER_ASSERTED",
        "reference_independence": "CALLER_ASSERTED",
        "evaluators_run": False,
    }


def _switch_compare(args: argparse.Namespace) -> dict[str, object]:
    package = _read_package(args.package)
    _verify_switch_package(package)
    approval, approval_errors = _try_switch_document(args.cohort_approval, _read_cohort_approval, "cohort_approval")
    reference, reference_errors = _try_switch_document(args.reference_spec, _read_reference_spec, "reference_spec")
    candidate, candidate_errors = _try_switch_document(args.candidate_spec, _read_candidate_spec, "candidate_spec")
    report = run_shadow_replay(
        package,
        cohort_approval=approval,
        reference=reference,
        candidate=candidate,
    )
    report["evaluation_mode"] = "PRECOMPUTED_RESULT_FILES"
    resources = report["resources"]
    resources["reference_elapsed_ns"] = None
    resources["candidate_elapsed_ns"] = None
    resources["profile"] = "LOCAL_RESULT_COMPARISON_ONLY"
    isolation = report["isolation"]
    isolation["evaluator_input"] = "PRECOMPUTED_TYPED_RESULTS"
    isolation["evaluator_closure_isolation"] = "NOT_APPLICABLE_EXTERNAL_EVALUATORS_NOT_RUN"
    input_errors = approval_errors + reference_errors + candidate_errors
    if input_errors:
        report["status"] = "INCOMPLETE"
        report["comparison_status"] = "INCOMPLETE"
        report["reasons"] = list(report.get("reasons", [])) + input_errors
        report["unknowns"] = list(report.get("unknowns", [])) + [
            {"class": "UNKNOWN", "reason": reason} for reason in input_errors
        ]
    incomplete = report.get("status") == "INCOMPLETE"
    result = {
        "contract": SWITCH_COMPARE_CLI_REPORT_CONTRACT,
        "completion": "INCOMPLETE" if incomplete else "COMPLETED",
        "exit_code": SWITCH_COMPARE_INCOMPLETE_EXIT if incomplete else 0,
        "owner_state_writes": False,
        "comparison": report,
    }
    if args.report_output is not None:
        _write_new(args.report_output, _json(result).encode("ascii"))
    return result


def _switch_compare_error(error: BaseException) -> dict[str, object]:
    return {
        "contract": SWITCH_COMPARE_CLI_REPORT_CONTRACT,
        "completion": "ERROR",
        "exit_code": 2,
        "owner_state_writes": False,
        "comparison": None,
        "error": {"code": str(error)},
    }


def _run(args: argparse.Namespace) -> Any:
    if args.command == "switch-prepare":
        return _switch_prepare(args)
    if args.command == "switch-compare":
        return _switch_compare(args)
    owner = _owner(args)
    mirror = FinancialMirror(owner)
    command = args.command

    if command == "summary":
        return mirror.summary()
    if command in {"list-obligations", "obligations"}:
        return mirror.list_obligations(status=args.status, limit=args.limit, offset=args.offset)
    if command in {"obligation-detail", "detail"}:
        return mirror.obligation_detail(args.item_id, limit=args.limit)
    if command in {"current-evaluation-receipt", "evaluation-receipt", "evaluation"}:
        return mirror.current_evaluation_receipt(args.item_id)
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
            evaluation_id=args.evaluation_id,
            evaluation_result_digest=args.evaluation_result_digest,
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
            evaluation_id=args.evaluation_id,
            evaluation_result_digest=args.evaluation_result_digest,
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
    except (FinancialMirrorError, FinancialSwitchError, FinancialError, OSError, ValueError) as error:
        if args.command == "switch-compare":
            report = _switch_compare_error(error)
            print(_json(report))
            return int(report["exit_code"])
        print(f"ERROR:{error}", file=sys.stderr)
        return 2
    if args.command == "switch-compare":
        print(_json(result))
        return int(result["exit_code"])
    if result is not None:
        print(_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
