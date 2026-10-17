"""Bounded local CLI for the synthetic RightRail financial Mirror and Switch.

Owner commands open one existing database and delegate reads, commands,
Continuity validation, and restore work to ``FinancialMirror``. Switch
commands accept a verified SHADOW package and result records without opening
an Owner database. The CLI has no network, payment, or direct-SQLite path.
Every command takes its trusted authority (including the actor roster) from an
explicit ``--authority-file``; there is no built-in default authority.
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
from app import right_rail_financial_intake as intake
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorError,
    MAX_PACKAGE_BYTES,
)
from app.right_rail_financial_custody import Custody
from app.right_rail_financial_canonical_json import encode
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


_KINDS = {"int": int, "path": Path}
_LIMIT = ("limit:int", {"default": 100})
_OFFSET = ("offset:int", {"default": 0})
# Every mutating command names who acts and the revision they reviewed; no defaults.
_ACTOR = ("actor-id!", "actor-role!", "expected-revision:int!")


def _flags(parser: argparse.ArgumentParser, *specs: str | tuple[str, dict[str, Any]]) -> None:
    """Add flags: ``name`` optional, ``name!`` required, ``name:int``/``name:path`` typed; a tuple adds argparse keywords."""
    for spec in specs:
        text, extra = (spec, {}) if isinstance(spec, str) else spec
        name, _, kind = text.partition(":")
        required = text.endswith("!")
        name, kind = name.rstrip("!"), kind.rstrip("!")
        parser.add_argument("--" + name, **({"required": True} if required else {}), **({"type": _KINDS[kind]} if kind else {}), **extra)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _flags(
        parser,
        ("database:path", {"help": "existing FinancialOwner database for Owner commands"}),
        "state-id", "deployment-id", "program-id", "period-id",
        ("currency", {"default": "USD"}),
        ("authority-file:path", {"help": "trusted authority JSON: authority_id, epoch, digest and actors roster (required)"}),
        ("custody-dir:path", {"help": "H2 custody log directory, outside the store's; with --custody-key, Owner commands check and extend it and packs are signed"}),
        ("custody-key", {"help": "ML-DSA-87 custody key file (a gate signer handle)"}),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, *flags: str | tuple[str, dict[str, Any]], **kwargs: str) -> None:
        _flags(commands.add_parser(name, **kwargs), *flags)

    switch_files = (
        ("package:path!", {"help": "exact Continuity SHADOW package bytes"}),
        "cohort-approval:path!", "reference-spec:path!", "candidate-spec:path!",
    )
    offset = ("item-id!", "claim-id!", *_ACTOR, "action-id", "decision-at-ms:int", "evaluation-id!", "evaluation-result-digest!")
    command("summary")
    command("list-obligations", ("status", {"choices": ("OPEN", "ALL", "SATISFIED", "CASH_UNSATISFIED"), "default": "OPEN"}), _LIMIT, _OFFSET)
    command("obligation-detail", "item-id!", _LIMIT)
    command("current-evaluation-receipt", "item-id!")
    command("history", _LIMIT, _OFFSET)
    command("action-payload", "action-id!")
    command("authorize-offset", *offset)
    command("reject-offset-and-authorize-correction", *offset)
    command("acknowledge-action", "action-id!", "acknowledgment-ref!", *_ACTOR)
    command(
        "record-payment-evidence", "item-id!", "payment-id!", "common-origin-id!", "amount-cents:int!", "evidence-id!",
        "event-at-ms:int!", ("source-id", {"default": "synthetic-payment-source"}), ("source-version", {"default": "fixture-v1"}),
        "local-ref", "pays-action-id", "expected-revision:int!",
    )
    command(
        "receiver-cash-file", "file:path!", "baseline:path!", "source-sha256!", "baseline-sha256!",
        ("source-context", {"nargs": 5, "required": True, "metavar": ("SOURCE", "VERSION", "RECEIVER", "CAPTURE", "CAPTURED_AT_MS")}),
        "owner-id!", ("mode", {"choices": ("LIVE", "TEST"), "required": True}),
        ("apply", {"action": "store_true", "help": "record checked evidence; default is isolated preview"}),
    )
    command("record-reporting-correction", "item-id!", "report-id!", "evidence-id", *_ACTOR, "event-at-ms:int", "supersedes")
    command("verify-integrity")
    command("export-continuity", "output:path!")
    command(
        "export-history", "output:path!", "owner-id!", ("mode", {"choices": ("LIVE", "TEST"), "required": True}),
        help="write sealed history segments and the manifest a cash file is prepared against",
    )
    command("validate-continuity", "package:path!")
    command("restore-continuity", "package:path!", "destination:path!")
    command(
        "switch-prepare", *switch_files, ("output:path!", {"help": "new replay-input file; existing paths are never replaced"}),
        help="write one canonical Switch replay input; runs no evaluator",
    )
    command(
        "switch-compare", "package:path!", "cohort-approval:path", "reference-spec:path", "candidate-spec:path",
        ("report-output:path", {"help": "optional new canonical JSON report file"}),
        help="compare supplied reference and candidate result records",
    )
    command(
        "line-pack",
        ("package:path!", {"help": "that store's current Continuity package bytes"}),
        ("line-map:path!", {"help": "line map JSON listed by the approved Control Pack"}),
        "line!", ("quarter!", {"help": "federal fiscal quarter, e.g. FFY2025Q4"}),
        ("reported-line-cents:int!", {"help": "the reported line amount: the coverage denominator"}),
        "generated-at-ms:int!", ("prior-pack:path", {"help": "the line pack this one supersedes"}),
        ("output:path!", {"help": "new line-pack file; existing paths are never replaced"}),
        help="write one documentation-only CMS-64.9 line pack from --database, verified read-only",
    )
    command(
        "followthrough-pack",
        ("package:path!", {"help": "that store's current Continuity package bytes"}),
        ("rules:path!", {"help": "rules JSON listed by the approved Control Pack"}),
        "generated-at-ms:int!",
        ("output:path!", {"help": "new follow-through file; existing paths are never replaced"}),
        help="write the documentation-only follow-through pack from --database, verified read-only",
    )
    command(
        "record-followthrough-decision", "item-id!", "decision-id!", ("act", {"choices": ("ASSIGN", "CLOSE"), "required": True}),
        ("reason-code", {"help": "CLOSE: a reason the rules list"}), ("owner-id", {"help": "ASSIGN: a typed party the rules name"}),
        ("suggestion:path", {"help": "canonical JSON of the suggestion this decision answers, if any"}), *_ACTOR,
        help="record an official's ASSIGN or CLOSE decision on one recovery item",
    )
    command(
        "custody-resolve", ("kind", {"choices": ("ADOPTED", "REWIND_ACCEPTED"), "required": True}), "actor-id!", "reason-ref!",
        ("expect-store-sequence:int!", {"help": "the store state the operator verified (verify-integrity)"}),
        ("expect-store-head!", {"help": "that state's history head, hex"}),
        help="an operator's signed custody act: ADOPTED where the log is lost, REWIND_ACCEPTED for a restored store",
    )
    return parser


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


def _owner(args: argparse.Namespace) -> FinancialOwner:
    database = _existing_database(args.database)
    config = FinancialOwnerConfig(**_scope(args))
    return FinancialOwner(
        path=database,
        config=config,
        trusted_authority=_trusted_authority(args),
        custody=None if args.command == "custody-resolve" else _custody(args),  # an operator act opens unchecked, then resolves
        **({"mode": args.mode, "owner_id": args.owner_id, "existing_only": True}
           if args.command in ("receiver-cash-file", "export-history") else {}),
    )


def _custody(args: argparse.Namespace) -> Custody | None:
    if (args.custody_dir is None) != (args.custody_key is None):
        raise FinancialMirrorError("custody_arguments")
    return None if args.custody_dir is None else Custody(args.custody_dir, args.custody_key)


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
    return encode(value).decode("ascii")


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
    return CohortApproval(**value)


def _read_difference_policies(value: object, label: str) -> tuple[DifferencePolicy, ...]:
    if type(value) is not list or len(value) > 10000:
        raise FinancialMirrorError(f"{label}_shape")
    return tuple(DifferencePolicy(**_switch_keys(record, {"path", "classification", "rationale", "approval_ref"}, label)) for record in value)


def _read_spec(path: Path, kind: str, contract: str, identity: set[str], policies: tuple[str, ...] = ()) -> dict[str, object]:
    """Read a reference or candidate spec file into spec fields; its stored ``result`` is the answer the evaluator returns."""
    required = {"contract", "identity", *policies}
    value = _read_switch_json(path, f"switch_{kind}")
    if frozenset(value) not in {frozenset(required), frozenset(required | {"result"})}:
        raise FinancialMirrorError(f"switch_{kind}_fields")
    if value.get("contract") != contract:
        raise FinancialMirrorError(f"switch_{kind}_contract")
    fixed = _switch_keys(value.get("identity"), identity, f"switch_{kind}_identity")
    answer = value.get("result")
    return {
        **fixed,
        "evaluate": lambda _replay_input: answer,
        **{name: _read_difference_policies(value[name], f"switch_{name}") for name in policies},
    }


def _read_reference_spec(path: Path) -> ReferenceSpec:
    identity = {"reference_id", "version", "authority_id", "reviewer_id", "source_ref", "source_sha256", "tool_version"}
    return ReferenceSpec(**_read_spec(path, "reference", CLI_REFERENCE_SPEC_CONTRACT, identity, ("expected_differences", "forbidden_differences")))


def _read_candidate_spec(path: Path) -> CandidateSpec:
    return CandidateSpec(**_read_spec(path, "candidate", CLI_CANDIDATE_SPEC_CONTRACT, {"operator_id", "version", "tool_version", "release_sha256"}))


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
        raw, baseline, expected = _read_package(args.file, cash_file.MAX_FILE_BYTES), _read_package(args.baseline), {"expected_source_sha256": args.source_sha256,  # R5: an upload goes through intake only; a row it cannot take is held, never paid
            "expected_baseline_sha256": args.baseline_sha256, "expected_scope": _scope(args), "expected_source": source, "expected_owner_id": args.owner_id, "expected_mode": args.mode, "trusted_authority": authority}
        if args.apply:
            with _owner(args) as owner:  # R1a: an owner holds the store open until closed, on success and on error
                return intake.ingest_cash_file(owner, raw, baseline, **expected)
        return intake.preview_intake(raw, baseline, path=_existing_database(args.database), **expected)
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
            generated_at_ms=args.generated_at_ms, custody=_custody(args),
            prior_pack=None if args.prior_pack is None else _read_package(args.prior_pack, MAX_LINE_PACK_BYTES),
        )
        _write_new(args.output, pack)
        return {"contract": LINE_PACK_CONTRACT, "line_pack_sha256": hashlib.sha256(pack).hexdigest().upper(), "line_pack_path": str(args.output)}
    if args.command == "followthrough-pack":
        pack = build_followthrough_pack(
            args.database, _read_package(args.package), trusted_authority=_trusted_authority(args), expected_scope=_scope(args),
            rules_bytes=_read_package(args.rules, MAX_RULES_BYTES, "followthrough_rules"), generated_at_ms=args.generated_at_ms, custody=_custody(args),
        )
        _write_new(args.output, pack)
        return {"contract": PACK_CONTRACT, "followthrough_pack_sha256": hashlib.sha256(pack).hexdigest().upper(), "followthrough_pack_path": str(args.output)}
    if args.command == "custody-resolve":
        custody = _custody(args)
        if custody is None:
            raise FinancialMirrorError("custody_arguments")
        with _owner(args) as owner:
            owner.resolve_custody(custody, args.kind, actor_id=args.actor_id, reason_ref=args.reason_ref,
                                  expect_sequence=args.expect_store_sequence, expect_head=bytes.fromhex(args.expect_store_head))
            return {"custody": args.kind, "sequence": args.expect_store_sequence}
    if args.command == "record-followthrough-decision":
        suggestion = None if args.suggestion is None else _decode_canonical_json(_read_package(args.suggestion, 4096, "followthrough_suggestion"), maximum=4096, label="followthrough_suggestion")
        with _owner(args) as owner:
            return owner.record_followthrough_decision(
                item_id=args.item_id, decision_id=args.decision_id, act=args.act, reason_code=args.reason_code, owner_id=args.owner_id, suggestion=suggestion,
                actor_id=args.actor_id, actor_role=args.actor_role, expected_revision=args.expected_revision,
            )
    with _owner(args) as owner:
        return _owner_command(args, owner)


_AUTHORIZE = ("", "item_id claim_id actor_id actor_role expected_revision action_id decision_at_ms evaluation_id evaluation_result_digest")
# Mirror calls that only forward arguments: command -> (positional attributes, keyword attributes); the method is the command with underscores.
_MIRROR_CALLS = {
    "summary": ("", ""),
    "list-obligations": ("", "status limit offset"),
    "obligation-detail": ("item_id", "limit"),
    "current-evaluation-receipt": ("item_id", ""),
    "history": ("", "limit offset"),
    "action-payload": ("action_id", ""),
    "authorize-offset": _AUTHORIZE,
    "reject-offset-and-authorize-correction": _AUTHORIZE,
    "acknowledge-action": ("action_id acknowledgment_ref", "actor_id actor_role expected_revision"),
    "record-payment-evidence": ("", "item_id payment_id common_origin_id amount_cents evidence_id event_at_ms source_id source_version local_ref pays_action_id expected_revision"),
    "record-reporting-correction": ("", "item_id report_id evidence_id actor_id actor_role expected_revision event_at_ms supersedes"),
    "verify-integrity": ("", ""),
}


def _owner_command(args: argparse.Namespace, owner: FinancialOwner) -> Any:
    mirror = FinancialMirror(owner)
    command = args.command
    if command in _MIRROR_CALLS:
        positional, keywords = (names.split() for names in _MIRROR_CALLS[command])
        return getattr(mirror, command.replace("-", "_"))(
            *(getattr(args, name) for name in positional), **{name: getattr(args, name) for name in keywords})
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
    raise FinancialMirrorError("unknown_command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _run(args)
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
