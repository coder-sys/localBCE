"""Bounded local CLI for the synthetic RightRail financial Mirror and Switch.

Owner commands open one existing database and delegate reads, commands,
Continuity validation, and restore work to ``FinancialMirror``. Switch
commands accept a verified SHADOW package and result records without opening
an Owner database. The CLI has no network, payment, or direct-SQLite path.
Every command takes its trusted authority (including the actor roster) from an
explicit ``--authority-file``; there is no built-in default authority.
Correction commands run only through the pinned Engine release named by
``--correction-transition-executable`` and ``--correction-transition-workspace``;
without both, the Owner fails closed with ``correction_transition_unavailable``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from app import right_rail_financial_engine as financial_engine
from app import right_rail_financial_cash_file as cash_file
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorDispatchError,
    FinancialMirrorError,
    MAX_PACKAGE_BYTES,
)
from app.right_rail_financial_followthrough import MAX_RULES_BYTES, PACK_CONTRACT, build_followthrough_pack
from app.right_rail_financial_line_pack import LINE_PACK_CONTRACT, MAX_LINE_MAP_BYTES, MAX_LINE_PACK_BYTES, build_line_pack
from app.right_rail_financial_switch import (
    COHORT_APPROVAL_CONTRACT,
    CURRENT_OWNER_SCHEMA_VERSION,
    CandidateSpec,
    CohortApproval,
    DifferencePolicy,
    FinancialSwitchError,
    ReferenceSpec,
    _decode_canonical_json,
    decode_replay_input,
    prepare_shadow_replay_input,
    run_shadow_replay,
)
from app.right_rail_financial_owner import (
    AuthorityActor,
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
    parser.add_argument(
        "--authority-file",
        type=Path,
        help="trusted authority JSON: authority_id, epoch, digest and actors roster (required)",
    )
    parser.add_argument(
        "--correction-transition-executable",
        type=Path,
        help="pinned correction Engine executable; without it correction commands fail closed",
    )
    parser.add_argument("--correction-transition-workspace", type=Path, help="empty Engine workspace directory")
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
    _add_actor_and_revision(acknowledge)

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
    payment.add_argument("--pays-action-id")
    payment.add_argument("--expected-revision", type=int, required=True)

    cash = subparsers.add_parser("receiver-cash-file")
    cash.add_argument("--file", type=Path, required=True)
    cash.add_argument("--baseline", type=Path, required=True)
    cash.add_argument("--source-sha256", required=True)
    cash.add_argument("--baseline-sha256", required=True)
    cash.add_argument("--source-context", nargs=5, required=True,
                      metavar=("SOURCE", "VERSION", "RECEIVER", "CAPTURE", "CAPTURED_AT_MS"))
    cash.add_argument("--owner-id", required=True)
    cash.add_argument("--mode", choices=("LIVE", "TEST"), required=True)
    cash.add_argument("--apply", action="store_true", help="record checked evidence; default is isolated preview")

    report = subparsers.add_parser("record-reporting-correction", aliases=("reporting-correction",))
    report.add_argument("--item-id", required=True)
    report.add_argument("--report-id", required=True)
    report.add_argument("--evidence-id")
    _add_actor_and_revision(report)
    report.add_argument("--event-at-ms", type=int)
    report.add_argument("--supersedes")

    subparsers.add_parser("verify-integrity")

    export = subparsers.add_parser("export-continuity")
    export.add_argument("--output", type=Path, required=True)

    segments = subparsers.add_parser("export-history", help="write sealed history segments and the manifest a cash file is prepared against")
    segments.add_argument("--output", type=Path, required=True)
    segments.add_argument("--owner-id", required=True)
    segments.add_argument("--mode", choices=("LIVE", "TEST"), required=True)

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

    line_pack = subparsers.add_parser("line-pack", help="write one documentation-only CMS-64.9 line pack from --database, verified read-only")
    line_pack.add_argument("--package", type=Path, required=True, help="that store's current Continuity package bytes")
    line_pack.add_argument("--line-map", type=Path, required=True, help="line map JSON listed by the approved Control Pack")
    line_pack.add_argument("--line", required=True)
    line_pack.add_argument("--quarter", required=True, help="federal fiscal quarter, e.g. FFY2025Q4")
    line_pack.add_argument("--reported-line-cents", type=int, required=True, help="the reported line amount: the coverage denominator")
    line_pack.add_argument("--generated-at-ms", type=int, required=True)
    line_pack.add_argument("--prior-pack", type=Path, help="the line pack this one supersedes")
    line_pack.add_argument("--output", type=Path, required=True, help="new line-pack file; existing paths are never replaced")

    followthrough = subparsers.add_parser("followthrough-pack", help="write the documentation-only follow-through pack from --database, verified read-only")
    followthrough.add_argument("--package", type=Path, required=True, help="that store's current Continuity package bytes")
    followthrough.add_argument("--rules", type=Path, required=True, help="rules JSON listed by the approved Control Pack")
    followthrough.add_argument("--generated-at-ms", type=int, required=True)
    followthrough.add_argument("--output", type=Path, required=True, help="new follow-through file; existing paths are never replaced")

    decision = subparsers.add_parser("record-followthrough-decision", help="record an official's ASSIGN or CLOSE decision on one recovery item")
    decision.add_argument("--item-id", required=True)
    decision.add_argument("--decision-id", required=True)
    decision.add_argument("--act", choices=("ASSIGN", "CLOSE"), required=True)
    decision.add_argument("--reason-code", help="CLOSE: a reason the rules list")
    decision.add_argument("--owner-id", help="ASSIGN: a typed party the rules name")
    decision.add_argument("--suggestion", type=Path, help="canonical JSON of the suggestion this decision answers, if any")
    _add_actor_and_revision(decision)

    subparsers.add_parser("dispatch-outbox")
    return parser


def _add_switch_files(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--package", type=Path, required=True, help="exact Continuity SHADOW package bytes")
    parser.add_argument("--cohort-approval", type=Path, required=required)
    parser.add_argument("--reference-spec", type=Path, required=required)
    parser.add_argument("--candidate-spec", type=Path, required=required)


def _add_actor_and_revision(parser: argparse.ArgumentParser) -> None:
    """Every mutating command names who acts and the revision they reviewed; no defaults."""
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--actor-role", required=True)
    parser.add_argument("--expected-revision", type=int, required=True)


def _add_offset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--item-id", required=True)
    parser.add_argument("--claim-id", required=True)
    _add_actor_and_revision(parser)
    parser.add_argument("--action-id")
    parser.add_argument("--decision-at-ms", type=int)
    parser.add_argument("--evaluation-id", required=True)
    parser.add_argument("--evaluation-result-digest", required=True)


def _existing_database(path: Path) -> Path:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise FinancialMirrorError("database_missing")
    return path


def _scope(args: argparse.Namespace) -> dict[str, str]:
    if any(
        type(value) is not str or not value
        for value in (args.state_id, args.deployment_id, args.program_id, args.period_id)
    ):
        raise FinancialMirrorError("financial_scope_missing")
    return {
        "state_id": args.state_id,
        "deployment_id": args.deployment_id,
        "program_id": args.program_id,
        "period_id": args.period_id,
        "currency": args.currency,
    }


def authority_file_record(authority: SyntheticTrustedAuthority) -> dict[str, object]:
    """The ``--authority-file`` JSON record for one trusted authority."""

    return {
        "authority_id": authority.authority_id,
        "epoch": authority.epoch,
        "digest": authority.digest.hex().upper(),
        "actors": [{"actor_id": actor.actor_id, "roles": list(actor.roles)} for actor in authority.actors],
    }


def _trusted_authority(args: argparse.Namespace) -> SyntheticTrustedAuthority:
    """Load the caller-supplied trusted authority; fail closed when it is absent."""

    if args.authority_file is None:
        raise FinancialMirrorError("trusted_authority_missing")
    value = _switch_keys(
        _read_switch_json(args.authority_file, "trusted_authority"),
        {"authority_id", "epoch", "digest", "actors"},
        "trusted_authority",
    )
    actors = value["actors"]
    if type(actors) is not list or not actors:
        raise FinancialMirrorError("trusted_authority_actors")
    roster: list[AuthorityActor] = []
    for actor in actors:
        actor = _switch_keys(actor, {"actor_id", "roles"}, "trusted_authority_actor")
        if type(actor["roles"]) is not list:
            raise FinancialMirrorError("trusted_authority_actor_roles")
        roster.append(AuthorityActor(actor["actor_id"], tuple(actor["roles"])))
    authority = SyntheticTrustedAuthority(
        authority_id=value["authority_id"],
        epoch=value["epoch"],
        actors=tuple(roster),
    )
    if authority_file_record(authority) != value:
        raise FinancialMirrorError("trusted_authority_digest")
    return authority


def _correction_release(args: argparse.Namespace) -> object | None:
    """The explicit correction release, or None (the Owner then fails closed)."""

    executable = args.correction_transition_executable
    workspace = args.correction_transition_workspace
    if executable is None and workspace is None:
        return None
    if executable is None or workspace is None:
        raise ValueError("correction_transition_paths")
    return financial_engine.load_correction_transition_release(executable, workspace)


def _owner(args: argparse.Namespace) -> FinancialOwner:
    database = _existing_database(args.database)
    config = FinancialOwnerConfig(**_scope(args))
    return FinancialOwner(
        path=database,
        config=config,
        trusted_authority=_trusted_authority(args),
        correction_transition_release=_correction_release(args),
        **({"mode": args.mode, "owner_id": args.owner_id, "existing_only": True}
           if args.command in ("receiver-cash-file", "export-history") else {}),
    )


def _read_package(path: Path, max_bytes: int = MAX_PACKAGE_BYTES, label: str = "continuity_package") -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FinancialMirrorError(f"{label}_missing")
    with path.open("rb") as stream:
        package = stream.read(max_bytes + 1)
    if len(package) > max_bytes:
        raise FinancialMirrorError(f"{label}_size")
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


def _verify_switch_package(package: bytes, authority: SyntheticTrustedAuthority, scope: dict[str, str]) -> None:
    verified = FinancialMirror.validate_continuity_package(
        package,
        trusted_authority=authority,
        expected_scope=scope,
    )
    if (
        verified.get("version") != CURRENT_OWNER_SCHEMA_VERSION
        or verified.get("mode") != "SHADOW"
        or verified.get("dispatch_enabled") is not False
        or verified.get("egress_enabled") is not False
    ):
        raise FinancialSwitchError("switch:continuity-shadow-required")


def _switch_prepare(args: argparse.Namespace) -> dict[str, object]:
    authority = _trusted_authority(args)
    scope = _scope(args)
    package = _read_package(args.package)
    _verify_switch_package(package, authority, scope)
    approval = _read_cohort_approval(args.cohort_approval)
    reference = _read_reference_spec(args.reference_spec)
    candidate = _read_candidate_spec(args.candidate_spec)
    replay_input = prepare_shadow_replay_input(
        package,
        trusted_authority=authority,
        expected_scope=scope,
        cohort_approval=approval,
        reference=reference,
        candidate=candidate,
    )
    decoded = decode_replay_input(replay_input, trusted_authority=authority, expected_scope=scope)
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
    authority = _trusted_authority(args)
    scope = _scope(args)
    package = _read_package(args.package)
    _verify_switch_package(package, authority, scope)
    approval, approval_errors = _try_switch_document(args.cohort_approval, _read_cohort_approval, "cohort_approval")
    reference, reference_errors = _try_switch_document(args.reference_spec, _read_reference_spec, "reference_spec")
    candidate, candidate_errors = _try_switch_document(args.candidate_spec, _read_candidate_spec, "candidate_spec")
    report = run_shadow_replay(
        package,
        trusted_authority=authority,
        expected_scope=scope,
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
    if args.command == "receiver-cash-file":
        authority = _trusted_authority(args)
        source = dict(zip(("source_id", "version", "receiver_system_id", "capture_id", "captured_at_ms"), args.source_context))
        source["captured_at_ms"] = int(source["captured_at_ms"])
        commands, context = cash_file.prepare_cash_file(
            _read_package(args.file, cash_file.MAX_FILE_BYTES), _read_package(args.baseline),
            expected_source_sha256=args.source_sha256, expected_baseline_sha256=args.baseline_sha256,
            expected_scope=_scope(args), expected_source=source, expected_owner_id=args.owner_id,
            expected_mode=args.mode, trusted_authority=authority,
        )
        if args.apply:
            return _owner(args).run_batch(commands, cash_file_context=context)
        return cash_file.preview_cash_file(commands, context, path=_existing_database(args.database), trusted_authority=authority)
    if args.command == "switch-prepare":
        return _switch_prepare(args)
    if args.command == "switch-compare":
        return _switch_compare(args)
    if args.command == "line-pack":
        pack = build_line_pack(
            args.database,
            _read_package(args.package),
            trusted_authority=_trusted_authority(args),
            expected_scope=_scope(args),
            line_map_bytes=_read_package(args.line_map, MAX_LINE_MAP_BYTES),
            line=args.line,
            quarter=args.quarter,
            reported_line_cents=args.reported_line_cents,
            generated_at_ms=args.generated_at_ms,
            prior_pack=None if args.prior_pack is None else _read_package(args.prior_pack, MAX_LINE_PACK_BYTES),
        )
        _write_new(args.output, pack)
        return {"contract": LINE_PACK_CONTRACT, "line_pack_sha256": hashlib.sha256(pack).hexdigest().upper(), "line_pack_path": str(args.output)}
    if args.command == "followthrough-pack":
        pack = build_followthrough_pack(
            args.database, _read_package(args.package), trusted_authority=_trusted_authority(args), expected_scope=_scope(args),
            rules_bytes=_read_package(args.rules, MAX_RULES_BYTES, "followthrough_rules"), generated_at_ms=args.generated_at_ms,
        )
        _write_new(args.output, pack)
        return {"contract": PACK_CONTRACT, "followthrough_pack_sha256": hashlib.sha256(pack).hexdigest().upper(), "followthrough_pack_path": str(args.output)}
    if args.command == "record-followthrough-decision":
        suggestion = None if args.suggestion is None else _decode_canonical_json(_read_package(args.suggestion, 4096, "followthrough_suggestion"), maximum=4096, label="followthrough_suggestion")
        return _owner(args).record_followthrough_decision(
            item_id=args.item_id, decision_id=args.decision_id, act=args.act, reason_code=args.reason_code, owner_id=args.owner_id, suggestion=suggestion,
            actor_id=args.actor_id, actor_role=args.actor_role, expected_revision=args.expected_revision,
        )
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
    if command in {"authorize-offset", "reject-offset-and-authorize-correction", "reject-offset"}:
        decide = mirror.authorize_offset if command == "authorize-offset" else mirror.reject_offset_and_authorize_correction
        return decide(
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
            expected_revision=args.expected_revision,
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
            pays_action_id=args.pays_action_id,
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
    if command == "export-history":
        manifest = owner.export_history(args.output)
        return {"schema": "RR/FINANCIAL/MIRROR/v1", "status": "EXPORTED", "path": str(args.output), "manifest_sha256": hashlib.sha256(manifest).hexdigest().upper()}
    if command == "validate-continuity":
        return mirror.validate_owner_continuity_package(_read_package(args.package))
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
    except (
        FinancialMirrorError,
        FinancialSwitchError,
        FinancialError,
        financial_engine.FinancialEngineError,
        OSError,
        ValueError,
    ) as error:
        if args.command == "receiver-cash-file":
            code = "cash_file_input" if isinstance(error, FinancialMirrorError) else cash_file.refusal(error)
            print(f"ERROR:receiver_cash_file_refused:{code}", file=sys.stderr)
            return 2
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
