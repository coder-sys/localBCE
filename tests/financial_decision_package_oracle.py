"""Test oracle: rebuilds an owner decision package from durable rows and compares it.

Moved out of the product checker (slim-1b, T2): no product path runs it. Covers the behaviour
that the Owner's decision_package, served to staff through the Mirror, equals an independent
rebuild from the durable SQLite rows. Restore it as product with an auditor export.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import sqlite3

from app.right_rail_financial_owner_independent import (
    IndependentFinancialError,
    MAX_CENTS,
    MAX_PACKAGE_BYTES,
    MAX_PACKAGE_NODES,
    MAX_ROWS,
    _blob64,
    _canonical,
    _evaluation_bindings_json,
    _evaluation_receipt_body,
    _evidence_ids_json,
    _fail,
    _flag,
    _id,
    _integer,
    _open_readonly,
    _parse_json,
    _sum_cents,
    verify_database_connection,
)


DECISION_PACKAGE_CONTRACT = "RR/FINANCIAL/DECISION-PACKAGE/v3"
MAX_DECISION_PACKAGE_BYTES = MAX_PACKAGE_BYTES - 512
MAX_DECISION_PACKAGE_DEPTH = 32


def _snapshot_decision_package_input(value: object) -> dict[str, object]:
    """Bound and detach caller input before opening the owner database."""

    if type(value) is not dict:
        _fail("decision-package:object")
    encoded_bytes = 0
    nodes = 0
    active_containers: set[int] = set()

    def add_size(size: int) -> None:
        nonlocal encoded_bytes
        encoded_bytes += size
        if encoded_bytes > MAX_DECISION_PACKAGE_BYTES:
            _fail("decision-package:input-limit")

    def add_json_string(text: str) -> None:
        if type(text) is not str:
            _fail("decision-package:input")
        size = 2
        for character in text:
            point = ord(character)
            if point in {0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x22, 0x5C}:
                size += 2
            elif point < 0x20:
                size += 6
            elif point <= 0x7E:
                size += 1
            elif point <= 0xFFFF:
                size += 6
            else:
                size += 12
            if encoded_bytes + size > MAX_DECISION_PACKAGE_BYTES:
                _fail("decision-package:input-limit")
        add_size(size)

    def clone(current: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_PACKAGE_NODES or depth > MAX_DECISION_PACKAGE_DEPTH:
            _fail("decision-package:input-limit")
        if current is None:
            add_size(4)
            return None
        if type(current) is bool:
            add_size(4 if current else 5)
            return current
        if type(current) is int:
            if current < -(1 << 63) or current > MAX_CENTS:
                _fail("decision-package:input-limit")
            add_size(len(str(current)))
            return current
        if type(current) is float:
            if not math.isfinite(current):
                _fail("decision-package:input")
            try:
                encoded = json.dumps(
                    current,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("ascii")
            except (TypeError, ValueError, UnicodeError):
                _fail("decision-package:input")
            add_size(len(encoded))
            return current
        if type(current) is str:
            add_json_string(current)
            return current
        if type(current) not in {dict, list, tuple}:
            _fail("decision-package:input")
        identity = id(current)
        if identity in active_containers:
            _fail("decision-package:input-limit")
        active_containers.add(identity)
        try:
            if type(current) is dict:
                result: dict[str, object] = {}
                add_size(1)
                item_count = 0
                try:
                    for key, child in current.items():
                        if type(key) is not str:
                            _fail("decision-package:input")
                        if item_count:
                            add_size(1)
                        item_count += 1
                        add_json_string(key)
                        add_size(1)
                        result[key] = clone(child, depth + 1)
                except IndependentFinancialError:
                    raise
                except RuntimeError:
                    _fail("decision-package:input")
                add_size(1)
                return result
            result_items: list[object] = []
            add_size(1)
            item_count = 0
            try:
                for child in current:
                    if item_count:
                        add_size(1)
                    item_count += 1
                    result_items.append(clone(child, depth + 1))
            except IndependentFinancialError:
                raise
            except RuntimeError:
                _fail("decision-package:input")
            add_size(1)
            return tuple(result_items) if type(current) is tuple else result_items
        finally:
            active_containers.remove(identity)

    snapshot = clone(value, 0)
    assert type(snapshot) is dict
    return snapshot


def verify_decision_package(
    path: str | Path,
    item_id: str,
    package: object,
    *,
    expected_config: object | None = None,
    expected_scope: object | None = None,
    expected_authority: object | None = None,
    expected_mode: str | None = None,
    expected_owner_id: str | None = None,
) -> dict[str, object]:
    """Reconstruct and verify an owner decision package from durable rows.

    This checker does not import or call the financial owner. It first verifies
    the complete owner database, then rebuilds the package's receipt, pages,
    links, and conclusions from the same read-only SQLite snapshot.
    """

    _id(item_id, "decision-package:item")
    package = _snapshot_decision_package_input(package)
    connection = _open_readonly(path)
    try:
        try:
            connection.execute("BEGIN")
            verified = verify_database_connection(
                connection,
                expected_config=expected_config,
                expected_scope=expected_scope,
                expected_authority=expected_authority,
                expected_mode=expected_mode,
                expected_owner_id=expected_owner_id,
            )
            scope = dict(verified["scope"])
            obligations = connection.execute(
                "SELECT * FROM obligations WHERE item_id=? ORDER BY obligation_id",
                (item_id,),
            ).fetchall()
            if len(obligations) != 1:
                _fail("decision-package:obligation")
            obligation = obligations[0]
            obligation_id = str(obligation["obligation_id"])
            expected_obligation = {
                "obligation_id": obligation_id,
                "item_id": str(obligation["item_id"]),
                "population_id": str(obligation["population_id"]),
                "period_id": str(obligation["period_id"]),
                "currency": str(obligation["currency"]),
                "revision": int(obligation["revision"]),
                "owed_cents": int(obligation["owed_cents"]),
                "claimed_adjustment_cents": int(obligation["claimed_adjustment_cents"]),
                "lawful_adjustment_cents": int(obligation["lawful_adjustment_cents"]),
                "received_cash_cents": int(obligation["received_cash_cents"]),
                "shortfall_cents": int(obligation["shortfall_cents"]),
                "overage_cents": int(obligation["overage_cents"]),
                "cash_satisfied": bool(obligation["cash_satisfied"]),
                "amount_satisfied": bool(obligation["amount_satisfied"]),
                "timely": bool(obligation["timely"]),
                "reporting_complete": bool(obligation["reporting_complete"]),
                "verification_status": str(obligation["verification_status"]),
                "case_status": str(obligation["case_status"]),
                "delivery_status": str(obligation["delivery_status"]),
                "current_evaluation_id": None if obligation["current_evaluation_id"] is None else str(obligation["current_evaluation_id"]),
                "due_at_ms": int(obligation["due_at_ms"]),
            }
            population_id = _id(obligation["population_id"], "decision-package:population-id")
            population_row = connection.execute(
                """
                SELECT p.status,p.source_complete,p.expected_count,p.imported_count,p.validated_count,
                       b.manifest_id,b.manifest_version AS binding_version,
                       b.manifest_digest AS binding_digest,
                       m.manifest_version AS manifest_version,m.manifest_digest,
                       m.member_digest,m.member_count
                FROM population_imports p
                JOIN population_manifest_bindings b USING(population_id)
                JOIN population_manifests m USING(manifest_id)
                JOIN population_items i ON i.population_id=p.population_id
                WHERE p.population_id=? AND i.item_id=?
                """,
                (population_id, str(obligation["item_id"])),
            ).fetchone()
            if population_row is None:
                _fail("decision-package:population-binding")
            expected_count = _integer(population_row["expected_count"], "decision-package:population-expected", minimum=1, maximum=MAX_ROWS)
            imported_count = _integer(population_row["imported_count"], "decision-package:population-imported", maximum=MAX_ROWS)
            validated_count = _integer(population_row["validated_count"], "decision-package:population-validated", maximum=MAX_ROWS)
            if (
                population_row["status"] != "PUBLISHED"
                or _flag(population_row["source_complete"], "decision-package:population-source-complete") != 1
                or imported_count != expected_count
                or validated_count != expected_count
            ):
                _fail("decision-package:population-incomplete")
            manifest_id = _id(population_row["manifest_id"], "decision-package:manifest-id")
            manifest_version = _integer(population_row["manifest_version"], "decision-package:manifest-version", minimum=1, maximum=MAX_ROWS)
            if _integer(population_row["binding_version"], "decision-package:binding-version", minimum=1, maximum=MAX_ROWS) != manifest_version:
                _fail("decision-package:population-binding")
            manifest_digest = _blob64(population_row["manifest_digest"], "decision-package:manifest-digest")
            if _blob64(population_row["binding_digest"], "decision-package:binding-digest") != manifest_digest:
                _fail("decision-package:population-binding")
            member_digest = _blob64(population_row["member_digest"], "decision-package:member-digest")
            member_count = _integer(population_row["member_count"], "decision-package:member-count", minimum=1, maximum=MAX_ROWS)
            if member_count != expected_count:
                _fail("decision-package:population-binding")
            imported_members = tuple(
                _id(row["item_id"], "decision-package:population-member")
                for row in connection.execute(
                    "SELECT item_id FROM population_items WHERE population_id=? ORDER BY item_id",
                    (population_id,),
                )
            )
            manifest_members = tuple(
                _id(row["member_id"], "decision-package:manifest-member")
                for row in connection.execute(
                    "SELECT member_id FROM population_manifest_members WHERE manifest_id=? ORDER BY position",
                    (manifest_id,),
                )
            )
            if (
                imported_members != manifest_members
                or len(imported_members) != member_count
                or str(obligation["item_id"]) not in imported_members
            ):
                _fail("decision-package:population-membership")
            population_binding = {
                "population_id": population_id,
                "status": "PUBLISHED",
                "completeness": "EXACT",
                "source_complete": True,
                "manifest_id": manifest_id,
                "manifest_version": manifest_version,
                "manifest_digest": manifest_digest.hex().upper(),
                "member_id": str(obligation["item_id"]),
                "member_count": member_count,
                "member_digest": member_digest.hex().upper(),
            }
            if obligation["current_evaluation_id"] is None:
                _fail("decision-package:evaluation")
            evaluation = connection.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
                (obligation["current_evaluation_id"], obligation_id),
            ).fetchone()
            if evaluation is None:
                _fail("decision-package:evaluation")
            evidence_ids = _evidence_ids_json(evaluation["evidence_ids_json"], "decision-package:evidence")
            evidence_bindings = _evaluation_bindings_json(evaluation["evidence_bindings_json"], "decision-package:bindings")
            evaluation_scope = _parse_json(evaluation["scope_json"], "decision-package:scope")
            if not isinstance(evaluation_scope, dict):
                _fail("decision-package:scope")
            input_digest = _blob64(evaluation["input_snapshot_digest"], "decision-package:input-digest")
            pack_row = connection.execute(
                """
                SELECT cp.* FROM control_packs cp
                JOIN population_imports pi ON pi.pack_id=cp.pack_id
                WHERE pi.population_id=?
                """,
                (obligation["population_id"],),
            ).fetchone()
            if pack_row is None:
                _fail("decision-package:control-pack")
            authority_digest = _blob64(evaluation["authority_digest"], "decision-package:authority-digest")
            expected_receipt_body = _evaluation_receipt_body(
                row=evaluation,
                evidence_ids=evidence_ids,
                evidence_bindings=evidence_bindings,
                scope=evaluation_scope,
                control_pack_id=str(pack_row["pack_id"]),
                control_pack_version=int(pack_row["version"]),
                control_pack_digest=_blob64(pack_row["pack_digest"], "decision-package:pack-digest"),
                authority_epoch=int(evaluation["authority_epoch"]),
                authority_digest=authority_digest,
                input_snapshot_digest=input_digest,
            )
            expected_receipt = {
                **expected_receipt_body,
                "receipt_digest": _blob64(evaluation["receipt_digest"], "decision-package:receipt-digest").hex().upper(),
                "evaluation_result_digest": _blob64(evaluation["result_digest"], "decision-package:result-digest").hex().upper(),
            }

            references = package.get("references")
            if type(references) is not dict or type(references.get("evidence")) is not dict:
                _fail("decision-package:references")
            page_limit = references["evidence"].get("limit")
            page_offset = references["evidence"].get("offset")
            if type(page_limit) is not int or not 1 <= page_limit <= 200 or type(page_offset) is not int or not 0 <= page_offset <= MAX_ROWS:
                _fail("decision-package:page-bounds")

            def build_page(
                name: str,
                select_sql: str,
                count_sql: str,
                args: tuple[object, ...],
                project: object,
            ) -> dict[str, object]:
                total = int(connection.execute(count_sql, args).fetchone()[0])
                rows = connection.execute(select_sql + " LIMIT ? OFFSET ?", (*args, page_limit, page_offset)).fetchall()
                items = [project(row) for row in rows]  # type: ignore[operator]
                next_offset = page_offset + len(items) if page_offset + len(items) < total else None
                result = {
                    "offset": page_offset,
                    "limit": page_limit,
                    "count": len(items),
                    "total": total,
                    "next_offset": next_offset,
                    "items": items,
                }
                actual = references.get(name)
                if _canonical(actual, f"decision-package:{name}") != _canonical(result, f"decision-package:{name}:expected"):
                    _fail(f"decision-package:{name}")
                return result

            def project_evidence(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "evidence_id": str(row["evidence_id"]),
                    "item_id": str(row["item_id"]),
                    "kind": str(row["kind"]),
                    "common_origin_id": str(row["common_origin_id"]),
                    "source_id": str(row["source_id"]),
                    "source_version": str(row["source_version"]),
                    "local_ref": str(row["local_ref"]),
                    "applicable_at_ms": int(row["applicable_at_ms"]),
                    "event_at_ms": int(row["event_at_ms"]),
                    "received_at_ms": int(row["received_at_ms"]),
                    "amount_cents": None if row["amount_cents"] is None else int(row["amount_cents"]),
                    "reversal_of": None if row["reversal_of"] is None else str(row["reversal_of"]),
                    "supersedes": None if row["supersedes"] is None else str(row["supersedes"]),
                    "record_digest": _blob64(row["record_digest"], "decision-package:evidence-record").hex().upper(),
                    "obligation_id": obligation_id,
                }

            def project_case(row: sqlite3.Row) -> dict[str, object]:
                conditions = _parse_json(row["completion_conditions_json"], "decision-package:case-conditions")
                if not isinstance(conditions, dict):
                    _fail("decision-package:case-conditions")
                return {
                    "case_id": str(row["case_id"]),
                    "obligation_id": obligation_id,
                    "reason": str(row["reason"]),
                    "contractual_accountability": str(row["contractual_accountability"]),
                    "next_action_owner": str(row["next_action_owner"]),
                    "due_at_ms": int(row["due_at_ms"]),
                    "completion_conditions": {key: bool(conditions[key]) for key in sorted(conditions)},
                    "status": str(row["status"]),
                    "updated_at_ms": int(row["updated_at_ms"]),
                }

            def project_payment(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "payment_id": str(row["payment_id"]),
                    "obligation_id": obligation_id,
                    "evidence_id": str(row["evidence_id"]),
                    "common_origin_id": str(row["common_origin_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "event_at_ms": int(row["event_at_ms"]),
                    "active": bool(row["active"]),
                    "reversed_by_evidence_id": None if row["reversed_by_evidence_id"] is None else str(row["reversed_by_evidence_id"]),
                }

            def project_claim(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "claim_id": str(row["claim_id"]),
                    "obligation_id": obligation_id,
                    "evidence_id": str(row["evidence_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "owner_role": str(row["owner_role"]),
                    "deadline_ms": int(row["deadline_ms"]),
                    "status": str(row["status"]),
                    "created_at_ms": int(row["created_at_ms"]),
                    "updated_at_ms": int(row["updated_at_ms"]),
                }

            def project_determination(row: sqlite3.Row) -> dict[str, object]:
                supporting = _evaluation_bindings_json(row["supporting_evidence_json"], "decision-package:determination-evidence")
                return {
                    "determination_id": str(row["determination_id"]),
                    "obligation_id": obligation_id,
                    "claim_id": None if row["claim_id"] is None else str(row["claim_id"]),
                    "actor_id": str(row["actor_id"]),
                    "actor_role": str(row["actor_role"]),
                    "authority": {
                        "authority_id": str(row["authority_id"]),
                        "epoch": int(row["authority_epoch"]),
                        "digest": _blob64(row["authority_digest"], "decision-package:determination-authority").hex().upper(),
                    },
                    "decision": str(row["decision"]),
                    "amount_cents": int(row["amount_cents"]),
                    "supporting_evidence": supporting,
                    "expected_revision": int(row["expected_revision"]),
                    "resulting_revision": int(row["resulting_revision"]),
                    "decided_at_ms": int(row["decided_at_ms"]),
                    "determination_digest": _blob64(row["determination_digest"], "decision-package:determination-digest").hex().upper(),
                    "input_evaluation_id": str(row["input_evaluation_id"]),
                    "input_evaluation_result_digest": _blob64(row["input_evaluation_result_digest"], "decision-package:determination-evaluation").hex().upper(),
                }

            action_fields = (
                "action", "action_id", "obligation_id", "determination_id", "kind", "claim_id",
                "amount_cents", "currency", "revision", "input_evaluation_id",
                "input_evaluation_result_digest", "dispatch",
            )

            open_cents: dict[str, int] = {}  # R2, recomputed from the rows: oldest request keeps its unpaid part, the balance bounds the rest
            left = int(obligation["shortfall_cents"])
            for action_id, status, amount in connection.execute("SELECT action_id,status,json_extract(payload_json,'$.amount_cents') FROM actions WHERE obligation_id=? AND kind='CORRECTION_PAYMENT_REQUEST' ORDER BY revision,action_id", (obligation_id,)).fetchall():
                paid = connection.execute("SELECT COALESCE(SUM(p.amount_cents),0) FROM payments p JOIN financial_events e ON json_extract(e.payload_json,'$.payment_id')=p.payment_id WHERE p.active=1 AND e.kind='PAYMENT_RECEIVED' AND json_extract(e.payload_json,'$.pays_action_id')=?", (action_id,)).fetchone()[0]
                open_cents[action_id] = 0 if status == "CANCELLED" else min(max(amount - paid, 0), left)
                left -= open_cents[action_id]

            def project_action(row: sqlite3.Row) -> dict[str, object]:
                payload = _parse_json(row["payload_json"], "decision-package:action-payload")
                if not isinstance(payload, dict):
                    _fail("decision-package:action-payload")
                return {
                    "action_id": str(row["action_id"]),
                    "obligation_id": obligation_id,
                    "determination_id": str(row["determination_id"]),
                    "kind": str(row["kind"]),
                    "status": str(row["status"]),
                    "revision": int(row["revision"]),
                    "payload_digest": _blob64(row["payload_digest"], "decision-package:action-digest").hex().upper(),
                    "payload_fields": {key: payload[key] for key in action_fields if key in payload},
                    "open_cents": open_cents.get(str(row["action_id"])) if row["kind"] == "CORRECTION_PAYMENT_REQUEST" else None,
                    "created_at_ms": int(row["created_at_ms"]),
                    "acknowledgment": {
                        "status": str(row["outbox_status"]),
                        "reference": None if row["acknowledgment_ref"] is None else str(row["acknowledgment_ref"]),
                        "attempt": int(row["attempt"]),
                        "updated_at_ms": int(row["outbox_updated_at_ms"]),
                        "cash_effect_cents": 0,
                    },
                }

            def project_conflict(row: sqlite3.Row) -> dict[str, object]:
                return {
                    "conflict_id": str(row["conflict_id"]),
                    "obligation_id": obligation_id,
                    "common_origin_id": str(row["common_origin_id"]),
                    "existing_payment_id": None if row["existing_payment_id"] is None else str(row["existing_payment_id"]),
                    "candidate_evidence_id": str(row["candidate_evidence_id"]),
                    "existing_amount_cents": None if row["existing_amount_cents"] is None else int(row["existing_amount_cents"]),
                    "candidate_amount_cents": None if row["candidate_amount_cents"] is None else int(row["candidate_amount_cents"]),
                    "reason": str(row["reason"]),
                    "visible_at_ms": int(row["visible_at_ms"]),
                }

            case_page = build_page("cases", "SELECT * FROM cases WHERE obligation_id=? ORDER BY case_id", "SELECT COUNT(*) FROM cases WHERE obligation_id=?", (obligation_id,), project_case)
            evidence_select = "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? ORDER BY evidence_id"
            evidence_page = build_page("evidence", evidence_select, "SELECT COUNT(*) FROM evidence WHERE item_id=?", (item_id,), project_evidence)
            payment_page = build_page("payments", "SELECT * FROM payments WHERE obligation_id=? ORDER BY payment_id", "SELECT COUNT(*) FROM payments WHERE obligation_id=?", (obligation_id,), project_payment)
            claim_page = build_page("claims", "SELECT * FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id", "SELECT COUNT(*) FROM claimed_adjustments WHERE obligation_id=?", (obligation_id,), project_claim)
            determination_page = build_page("determinations", "SELECT * FROM determinations WHERE obligation_id=? ORDER BY determination_id", "SELECT COUNT(*) FROM determinations WHERE obligation_id=?", (obligation_id,), project_determination)
            action_base = "SELECT a.*,o.status AS outbox_status,o.attempt,o.acknowledgment_ref,o.updated_at_ms AS outbox_updated_at_ms FROM actions a JOIN action_outbox o ON o.action_id=a.action_id WHERE a.obligation_id=?"
            action_page = build_page("actions", action_base + " ORDER BY a.action_id", "SELECT COUNT(*) FROM actions WHERE obligation_id=?", (obligation_id,), project_action)
            conflict_page = build_page("conflicts", "SELECT * FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id", "SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,), project_conflict)
            report_select = "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? AND kind IN ('REPORT','REPORT_CORRECTION') ORDER BY evidence_id"
            reporting_page = build_page("reporting_evidence", report_select, "SELECT COUNT(*) FROM evidence WHERE item_id=? AND kind IN ('REPORT','REPORT_CORRECTION')", (item_id,), project_evidence)

            case_row = connection.execute("SELECT * FROM cases WHERE obligation_id=? ORDER BY case_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_case = None if case_row is None else project_case(case_row)
            action_row = connection.execute(action_base + " ORDER BY a.revision DESC,a.action_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_action = None if action_row is None else project_action(action_row)
            determination_row = connection.execute("SELECT * FROM determinations WHERE obligation_id=? ORDER BY resulting_revision DESC,determination_id DESC LIMIT 1", (obligation_id,)).fetchone()
            current_determination = None if determination_row is None else project_determination(determination_row)

            pack_scope = {"state_id": str(pack_row["state_id"]), "deployment_id": str(pack_row["deployment_id"]), "program_id": str(pack_row["program_id"]), "period_id": str(pack_row["period_id"])}
            source_refs = _parse_json(pack_row["source_refs_json"], "decision-package:pack-source-refs")
            authorized_roles = _parse_json(pack_row["authorized_roles_json"], "decision-package:pack-roles")
            if not isinstance(source_refs, dict) or set(source_refs) != {"values"} or not isinstance(authorized_roles, dict) or set(authorized_roles) != {"values"}:
                _fail("decision-package:control-pack")
            expected_pack = {
                "pack_id": str(pack_row["pack_id"]),
                "version": int(pack_row["version"]),
                "digest": _blob64(pack_row["pack_digest"], "decision-package:pack-digest").hex().upper(),
                "calculation_rule_id": str(pack_row["calculation_rule_id"]),
                "adjustment_rule_id": str(pack_row["adjustment_rule_id"]),
                "source_refs": list(source_refs["values"]),
                "authorized_roles": list(authorized_roles["values"]),
                "effective_start_ms": int(pack_row["effective_start_ms"]),
                "effective_end_ms": int(pack_row["effective_end_ms"]),
                "recorded_at_ms": int(pack_row["recorded_at_ms"]),
                "approved_at_ms": int(pack_row["approved_at_ms"]),
            }
            if pack_scope != {key: scope[key] for key in pack_scope}:
                _fail("decision-package:control-pack-scope")

            active_payment_count = int(connection.execute("SELECT COUNT(*) FROM payments WHERE obligation_id=? AND active=1", (obligation_id,)).fetchone()[0])
            authorized_claim_count = int(connection.execute("SELECT COUNT(*) FROM claimed_adjustments WHERE obligation_id=? AND status='AUTHORIZED'", (obligation_id,)).fetchone()[0])
            conflict_count = int(connection.execute("SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,)).fetchone()[0])
            report_count = int(reporting_page["total"])
            active_payment_cents = _sum_cents(
                [int(row[0]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1 ORDER BY payment_id", (obligation_id,))],
                "decision-package:cash-support",
            )
            adjustment_rows = connection.execute(
                "SELECT amount_cents,status FROM claimed_adjustments WHERE obligation_id=? AND status IN ('CLAIMED','AUTHORIZED') ORDER BY claim_id",
                (obligation_id,),
            ).fetchall()
            claimed_adjustment_cents = _sum_cents([int(row["amount_cents"]) for row in adjustment_rows], "decision-package:claimed-support")
            lawful_adjustment_cents = _sum_cents([int(row["amount_cents"]) for row in adjustment_rows if row["status"] == "AUTHORIZED"], "decision-package:lawful-support")
            active_payment_ids = [str(row["evidence_id"]) for row in payment_page["items"] if row["active"]]
            authorized_evidence_ids = [str(row["evidence_id"]) for row in claim_page["items"] if row["status"] == "AUTHORIZED"]
            reporting_evidence_ids = [str(row["evidence_id"]) for row in reporting_page["items"]]
            payment_references_complete = page_offset == 0 and payment_page["next_offset"] is None
            claim_references_complete = page_offset == 0 and claim_page["next_offset"] is None
            reporting_references_complete = page_offset == 0 and reporting_page["next_offset"] is None
            payment_support = (
                "SUPPORTED" if active_payment_count and active_payment_cents == int(obligation["received_cash_cents"])
                else "NO_LINKED_EVIDENCE" if not active_payment_count and int(obligation["received_cash_cents"]) == 0
                else "CONFLICTED"
            )
            adjustment_support = (
                "SUPPORTED"
                if (authorized_claim_count or adjustment_rows)
                and claimed_adjustment_cents == int(obligation["claimed_adjustment_cents"])
                and lawful_adjustment_cents == int(obligation["lawful_adjustment_cents"])
                else "NO_LINKED_EVIDENCE"
                if not adjustment_rows and int(obligation["claimed_adjustment_cents"]) == 0 and int(obligation["lawful_adjustment_cents"]) == 0
                else "CONFLICTED"
            )
            reporting_support = (
                "SUPPORTED" if bool(obligation["reporting_complete"]) and report_count
                else "UNKNOWN" if bool(obligation["reporting_complete"])
                else "CONFLICTED" if report_count
                else "NOT_SATISFIED"
            )
            if current_action is None:
                delivery_support = "UNKNOWN"
            elif current_action["status"] == "ACKNOWLEDGED" and current_action["acknowledgment"]["reference"] is not None:
                delivery_support = "SUPPORTED"
            else:
                delivery_support = "NOT_SATISFIED"
            amount_evidence_ids = sorted(set(active_payment_ids + authorized_evidence_ids))
            amount_satisfied = bool(obligation["amount_satisfied"])
            if payment_support == "CONFLICTED" or adjustment_support == "CONFLICTED":
                amount_support = "CONFLICTED"
            elif amount_satisfied and not active_payment_count and not authorized_claim_count:
                amount_support = "UNKNOWN"
            elif str(obligation["verification_status"]) == "CONFLICT_VISIBLE":
                amount_support = "CONFLICTED"
            else:
                amount_support = "SUPPORTED" if active_payment_count or authorized_claim_count else "NO_LINKED_EVIDENCE"
            requirements = {
                "amount_satisfied": "SUPPORTED" if amount_satisfied and amount_support == "SUPPORTED" else (
                    "NOT_SATISFIED" if not amount_satisfied and amount_support != "CONFLICTED"
                    else "CONFLICTED" if amount_support == "CONFLICTED" else "UNKNOWN"
                ),
                "delivery_acknowledged_or_not_required": "UNKNOWN" if current_action is None else "NOT_SATISFIED" if any(open_cents.get(a, 1) > 0 for (a,) in connection.execute("SELECT action_id FROM actions WHERE obligation_id=? AND status='READY'", (obligation_id,))) else "SUPPORTED",
                "reporting_complete": reporting_support,
            }
            missing_requirements = sorted(key for key, value in requirements.items() if value != "SUPPORTED")
            observed_case_status = None if current_case is None else current_case["status"]
            if observed_case_status != "RESOLVED":
                resolution_assessment = "NOT_RESOLVED"
            elif conflict_count or amount_support == "CONFLICTED" or reporting_support == "CONFLICTED":
                resolution_assessment = "CONFLICTED"
            elif any(value == "NOT_SATISFIED" for value in requirements.values()):
                resolution_assessment = "UNSUPPORTED"
            elif missing_requirements:
                resolution_assessment = "UNKNOWN"
            else:
                resolution_assessment = "SUPPORTED"

            expected_package = {
                "contract": DECISION_PACKAGE_CONTRACT,
                "scope": scope,
                "obligation": expected_obligation,
                "population_binding": population_binding,
                "evaluation_receipt": expected_receipt,
                "control_pack": expected_pack,
                "case": current_case,
                "current_determination": current_determination,
                "current_action": current_action,
                "cash": {
                    "recorded_received_cash_cents": int(obligation["received_cash_cents"]),
                    "cash_satisfied": bool(obligation["cash_satisfied"]),
                    "claimed_adjustment_cents": int(obligation["claimed_adjustment_cents"]),
                    "lawful_adjustment_cents": int(obligation["lawful_adjustment_cents"]),
                    "amount_satisfied": bool(obligation["amount_satisfied"]),
                    "shortfall_cents": int(obligation["shortfall_cents"]),
                    "overage_cents": int(obligation["overage_cents"]),
                    "active_payment_count": active_payment_count,
                    "authorized_adjustment_count": authorized_claim_count,
                },
                "reporting": {"complete": bool(obligation["reporting_complete"]), "evidence_count": report_count},
                "references": {
                    "cases": case_page,
                    "evidence": evidence_page,
                    "payments": payment_page,
                    "claims": claim_page,
                    "determinations": determination_page,
                    "actions": action_page,
                    "conflicts": conflict_page,
                    "reporting_evidence": reporting_page,
                },
                "conclusions": {
                    "cash_satisfaction": {
                        "result": "SATISFIED" if bool(obligation["cash_satisfied"]) else "NOT_SATISFIED",
                        "evidence_status": payment_support,
                        "recorded_received_cash_cents": int(obligation["received_cash_cents"]),
                        "required_cents": int(obligation["owed_cents"]),
                        "missing_cents": max(int(obligation["owed_cents"]) - int(obligation["received_cash_cents"]), 0),
                        "supporting_evidence_ids": active_payment_ids,
                        "supporting_references_complete": payment_references_complete,
                    },
                    "amount_satisfaction": {
                        "result": "SATISFIED" if amount_satisfied else "NOT_SATISFIED",
                        "evidence_status": amount_support,
                        "supporting_evidence_ids": amount_evidence_ids,
                        "supporting_references_complete": payment_references_complete and claim_references_complete,
                    },
                    "reporting_completion": {
                        "result": reporting_support,
                        "supporting_evidence_ids": reporting_evidence_ids,
                        "supporting_references_complete": reporting_references_complete,
                    },
                    "action_acknowledgment": {
                        "result": delivery_support,
                        "action_id": None if current_action is None else current_action["action_id"],
                        "reference": None if current_action is None else current_action["acknowledgment"]["reference"],
                        "cash_effect_cents": 0,
                    },
                    "case_resolution": {
                        "case_id": None if current_case is None else current_case["case_id"],
                        "obligation_id": obligation_id,
                        "observed_status": observed_case_status,
                        "assessment": resolution_assessment,
                        "required_conditions": requirements,
                        "missing_requirements": missing_requirements,
                        "supporting_evidence_ids": sorted(set(amount_evidence_ids + reporting_evidence_ids)),
                        "supporting_references_complete": payment_references_complete and claim_references_complete and reporting_references_complete,
                        "conflict_count": conflict_count,
                        "conflict_ids": [str(row["conflict_id"]) for row in conflict_page["items"]],
                    },
                },
            }
            if _canonical(package, "decision-package:actual") != _canonical(expected_package, "decision-package:expected"):
                _fail("decision-package:mismatch")
            connection.execute("COMMIT")
            return {
                "integrity": "VERIFIED",
                "obligation_id": obligation_id,
                "evaluation_id": str(evaluation["evaluation_id"]),
                "revision": int(evaluation["revision"]),
                "case_status": observed_case_status,
            }
        except IndependentFinancialError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError, OverflowError, UnicodeError) as error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            _fail("decision-package:malformed", error)
    finally:
        connection.close()
