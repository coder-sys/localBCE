"""Focused tamper tests for the independently written financial checker."""

from __future__ import annotations

import ast
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000

    def now_ms(self) -> int:
        self.value += 1
        return self.value


class IndependentFinancialCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-financial-independent-")
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Path(self.temp_dir.name) / "owner.sqlite"
        self.clock = _Clock()
        self.config = owner.FinancialOwnerConfig(
            state_id="state:test",
            deployment_id="deployment:test",
            program_id="program:test",
            period_id="period:test",
        )
        self.authority = owner.SyntheticTrustedAuthority()
        self.store = owner.FinancialOwner(
            path=self.db,
            config=self.config,
            trusted_authority=self.authority,
            clock=self.clock,
        )
        self._populate_owner()
        self.scope = {
            "state_id": self.config.state_id,
            "deployment_id": self.config.deployment_id,
            "program_id": self.config.program_id,
            "period_id": self.config.period_id,
            "currency": self.config.currency,
        }
        self.authority_binding = {
            "authority_id": self.authority.authority_id,
            "epoch": self.authority.epoch,
            "digest": self.authority.digest,
        }

    def _populate_owner(self) -> None:
        pack = owner.ControlPack(
            pack_id="pack:test",
            state_id=self.config.state_id,
            deployment_id=self.config.deployment_id,
            program_id=self.config.program_id,
            period_id=self.config.period_id,
            version=1,
            source_refs=("source:test",),
            effective_start_ms=1,
            effective_end_ms=20_000,
            recorded_at_ms=2,
            approved_at_ms=3,
            calculation_rule_id="calculation:per-recipient:v1",
            adjustment_rule_id="adjustment:offset:v1",
            authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
            expected_tests=(
                "program-total=100000000",
                "H-owed=10000000",
                "other-total=90000000",
                "timeliness-separate",
            ),
        )
        self.store.publish_control_pack(pack)
        item = owner.PopulationItem(
            population_id="population:test",
            item_id="item:H",
            display_label="Fixture H",
            owed_cents=10_000_000,
            due_at_ms=10_000,
        )
        self.store.stage_population(
            population_id="population:test",
            pack_id=pack.pack_id,
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            expected_count=1,
            items=(item,),
        )
        self.store.validate_population("population:test")
        self.store.publish_population("population:test")
        self.store.record_support_evidence(
            item_id="item:H",
            evidence_id="evidence:support:H",
            common_origin_id="support:H",
            applicable_at_ms=10,
            event_at_ms=10,
            received_at_ms=11,
        )
        self.store.record_payment_evidence(
            item_id="item:H",
            payment_id="payment:P1",
            common_origin_id="origin:P1",
            amount_cents=9_700_000,
            evidence_id="evidence:payment:P1",
            event_at_ms=20,
        )
        self.store.record_offset_claim(
            item_id="item:H",
            claim_id="claim:H",
            amount_cents=300_000,
            evidence_id="evidence:offset:H",
            deadline_ms=9_000,
        )
        self.store.authorize_offset(
            item_id="item:H",
            claim_id="claim:H",
            action_id="action:offset:claim:H",
            decision_at_ms=30,
        )
        self.store.acknowledge_action("action:offset:claim:H", "ack:H")
        self.store.record_reporting_evidence(
            item_id="item:H",
            report_id="report:H:original",
            evidence_id="evidence:report:H:original",
            event_at_ms=35,
        )
        self.store.record_reporting_correction(
            item_id="item:H",
            report_id="report:H:correction",
            evidence_id="evidence:report:H:correction",
            event_at_ms=40,
            supersedes="evidence:report:H:original",
        )
        self.store.record_reporting_correction(
            item_id="item:H",
            report_id="report:H:correction-2",
            evidence_id="evidence:report:H:correction-2",
            event_at_ms=45,
            supersedes="evidence:report:H:correction",
        )

    def _verify(self, path: Path | None = None, *, continuity_package: bytes | None = None) -> dict[str, object]:
        return independent.verify_database(
            path or self.db,
            expected_scope=self.scope,
            expected_authority=self.authority_binding,
            expected_mode="LIVE",
            expected_owner_id="financial-owner-v1",
            continuity_package=continuity_package,
        )

    def _copy_database(self, name: str) -> Path:
        target = Path(self.temp_dir.name) / name
        shutil.copy2(self.db, target)
        return target

    def _assert_rejected_without_repair(self, path: Path, mutate: object, code: str) -> None:
        assert callable(mutate)
        mutate(path)
        tampered_bytes = path.read_bytes()
        with self.assertRaisesRegex(independent.IndependentFinancialError, code):
            self._verify(path)
        self.assertEqual(path.read_bytes(), tampered_bytes)

    @staticmethod
    def _report_record_digest(row: sqlite3.Row, supersedes: str) -> bytes:
        return owner._digest(
            owner._EVIDENCE_DOMAIN,
            owner._canonical(
                {
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
                    "content_digest": bytes(row["content_digest"]).hex().upper(),
                    "amount_cents": row["amount_cents"],
                    "reversal_of": row["reversal_of"],
                    "supersedes": supersedes,
                }
            ),
        )

    @staticmethod
    def _rewrite_report_supersedes(path: Path, evidence_id: str, supersedes: str) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
            assert row is not None
            record_digest = IndependentFinancialCheckerTests._report_record_digest(row, supersedes)
            connection.execute("DROP TRIGGER evidence_record_immutable")
            connection.execute(
                "UPDATE evidence SET supersedes=?,record_digest=? WHERE evidence_id=?",
                (supersedes, record_digest, evidence_id),
            )
            connection.execute(independent._TRIGGER_DEFS["evidence_record_immutable"])

    def _add_published_history_population(self, population_id: str = "population:history") -> None:
        items = (
            owner.PopulationItem(
                population_id=population_id,
                item_id="item:history-1",
                display_label="History one",
                owed_cents=1,
                due_at_ms=10_001,
            ),
            owner.PopulationItem(
                population_id=population_id,
                item_id="item:history-2",
                display_label="History two",
                owed_cents=1,
                due_at_ms=10_002,
            ),
        )
        self.store.stage_population(
            population_id=population_id,
            pack_id="pack:test",
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            expected_count=2,
            items=items,
            chunk_size=1,
        )
        self.store.validate_population(population_id)
        self.store.publish_population(population_id)

    @staticmethod
    def _reorder_and_rehash_population_events(
        path: Path,
        population_id: str,
        left_kind: str,
        left_index: int,
        right_kind: str,
        right_index: int,
    ) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            rows = list(connection.execute("SELECT * FROM financial_events ORDER BY event_sequence"))
            left_candidates = [index for index, row in enumerate(rows) if row["aggregate_id"] == population_id and row["kind"] == left_kind]
            right_candidates = [index for index, row in enumerate(rows) if row["aggregate_id"] == population_id and row["kind"] == right_kind]
            left_position = left_candidates[left_index]
            right_position = right_candidates[right_index]
            rows[left_position], rows[right_position] = rows[right_position], rows[left_position]
            offset = 100_000
            connection.execute("UPDATE financial_events SET event_sequence=event_sequence+?", (offset,))
            meta = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
            assert meta is not None
            base_committed_at = min(int(row["committed_at_ms"]) for row in rows)
            scope = {
                "state_id": str(meta["state_id"]),
                "deployment_id": str(meta["deployment_id"]),
                "program_id": str(meta["program_id"]),
                "period_id": str(meta["period_id"]),
                "currency": str(meta["currency"]),
            }
            previous = independent._digest(
                independent.GENESIS_DOMAIN,
                independent._canonical(scope, "test:genesis-scope"),
                bytes(meta["trusted_authority_digest"]),
            )
            for sequence, row in enumerate(rows, start=1):
                committed_at = base_committed_at + sequence
                header = independent._event_header(
                    int(row["before_revision"]),
                    int(row["after_revision"]),
                    committed_at,
                    "test:event-header",
                )
                event_id = independent._digest(
                    independent.EVENT_DOMAIN,
                    sequence.to_bytes(8, "big"),
                    str(row["aggregate_type"]).encode("ascii"),
                    str(row["aggregate_id"]).encode("ascii"),
                    str(row["kind"]).encode("ascii"),
                    header,
                    bytes(row["payload_digest"]),
                )
                head = independent._digest(
                    independent.HEAD_DOMAIN,
                    previous,
                    event_id,
                    header,
                    bytes(row["payload_digest"]),
                )
                connection.execute(
                    "UPDATE financial_events SET event_sequence=?,event_id=?,previous_head=?,head=?,committed_at_ms=? WHERE event_sequence=?",
                    (sequence, event_id, previous, head, committed_at, int(row["event_sequence"]) + offset),
                )
                previous = head
            connection.execute("UPDATE financial_meta SET history_head=? WHERE id=1", (previous,))

    def test_valid_owner_fixture_reconstructs_projection_and_identity(self) -> None:
        result = self._verify()
        obligation = next(iter(result["obligations"].values()))
        self.assertEqual(result["schema"], "RR/FINANCIAL/OWNER/v3")
        self.assertEqual(result["mode"], "LIVE")
        self.assertEqual(result["totals"], {
            "owed_cents": 10_000_000,
            "received_cash_cents": 9_700_000,
            "lawful_adjustment_cents": 300_000,
            "shortfall_cents": 0,
        })
        self.assertEqual(obligation["received_cash_cents"], 9_700_000)
        self.assertEqual(obligation["lawful_adjustment_cents"], 300_000)
        self.assertEqual(obligation["shortfall_cents"], 0)
        self.assertEqual(obligation["amount_satisfied"], 1)
        self.assertEqual(obligation["cash_satisfied"], 0)
        self.assertEqual(obligation["case_status"], "RESOLVED")
        self.assertEqual(obligation["delivery_status"], "ACKNOWLEDGED")

    def test_checker_has_no_production_owner_import(self) -> None:
        checker_path = Path(independent.__file__).resolve()
        tree = ast.parse(checker_path.read_text(encoding="utf-8"))
        imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        ]
        imports.extend(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertNotIn("app.right_rail_financial_owner", imports)
        self.assertNotIn("right_rail_financial_owner", imports)

    def test_event_payload_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("event-payload-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE financial_events SET payload_json=? WHERE event_sequence=1",
                    ('{"tampered":true}',),
                )

        self._assert_rejected_without_repair(target, tamper, "history:payload-digest")

    def test_event_header_tamper_fails_owner_verification_without_repair(self) -> None:
        target = self._copy_database("event-header-tamper.sqlite")
        with closing(sqlite3.connect(target, isolation_level=None)) as connection:
            connection.execute(
                "UPDATE financial_events SET after_revision=after_revision+1 WHERE kind='POPULATION_SOURCE_COMPLETED'"
            )
        tampered_bytes = target.read_bytes()
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:event-id"):
            reopened = owner.FinancialOwner(
                path=target,
                config=self.config,
                trusted_authority=self.authority,
                clock=self.clock,
            )
            reopened.verify_integrity()
        self.assertEqual(target.read_bytes(), tampered_bytes)

    def test_rehashed_population_history_rejects_invalid_completion_lifecycle(self) -> None:
        population_id = "population:history"
        self._add_published_history_population(population_id)
        self._verify()

        before_stage = self._copy_database("population-stage-order-tamper.sqlite")
        self._reorder_and_rehash_population_events(
            before_stage,
            population_id,
            "POPULATION_STAGED",
            1,
            "POPULATION_SOURCE_COMPLETED",
            0,
        )
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:population-stage-order"):
            self._verify(before_stage)

        after_validation = self._copy_database("population-completion-order-tamper.sqlite")
        self._reorder_and_rehash_population_events(
            after_validation,
            population_id,
            "POPULATION_SOURCE_COMPLETED",
            0,
            "POPULATION_VALIDATED",
            0,
        )
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:population-completion-order"):
            self._verify(after_validation)

    def test_event_head_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("event-head-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE financial_events SET head=? WHERE event_sequence=(SELECT MAX(event_sequence) FROM financial_events)",
                    (b"\xff" * 64,),
                )

        self._assert_rejected_without_repair(target, tamper, "history:")

    def test_action_payload_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("action-payload-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                action_id = connection.execute("SELECT action_id FROM actions LIMIT 1").fetchone()[0]
                raw = connection.execute("SELECT payload_json FROM actions WHERE action_id=?", (action_id,)).fetchone()[0]
                payload = json.loads(raw)
                payload["tampered"] = True
                connection.execute("DROP TRIGGER action_payload_immutable")
                connection.execute(
                    "UPDATE actions SET payload_json=? WHERE action_id=?",
                    (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")), action_id),
                )
                connection.execute(
                    "CREATE TRIGGER action_payload_immutable BEFORE UPDATE OF action_id,obligation_id,determination_id,kind,revision,payload_json,payload_digest,idempotency_key,created_at_ms ON actions BEGIN SELECT RAISE(ABORT,'action_payload_immutable'); END"
                )

        self._assert_rejected_without_repair(target, tamper, "action:payload")

    def test_projection_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("projection-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE obligations SET received_cash_cents=received_cash_cents+1 WHERE obligation_id=?",
                    ("obligation:item:H:period:test",),
                )

        self._assert_rejected_without_repair(target, tamper, "projection:received_cash_cents")

    def test_evidence_record_digest_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("evidence-record-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute("DROP TRIGGER evidence_record_immutable")
                connection.execute(
                    "UPDATE evidence SET record_digest=? WHERE evidence_id=?",
                    (b"\x00" * 64, "evidence:support:H"),
                )
                connection.execute(
                    "CREATE TRIGGER evidence_record_immutable BEFORE UPDATE OF evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes ON evidence BEGIN SELECT RAISE(ABORT,'evidence_record_immutable'); END"
                )

        self._assert_rejected_without_repair(target, tamper, "evidence:record-digest")

    def test_reporting_supersedes_missing_target_fails_closed_without_repair(self) -> None:
        target = self._copy_database("reporting-lineage-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "DELETE FROM evidence WHERE evidence_id=?",
                    ("evidence:report:H:original",),
                )

        self._assert_rejected_without_repair(target, tamper, "evidence:report-supersedes-missing")

    def test_reporting_supersedes_fork_fails_closed_without_repair(self) -> None:
        target = self._copy_database("reporting-lineage-fork.sqlite")

        def tamper(path: Path) -> None:
            evidence = self.store._new_evidence(
                evidence_id="evidence:report:H:fork",
                item_id="item:H",
                kind="REPORT_CORRECTION",
                common_origin_id="report:H:fork",
                source_id="synthetic-report-source",
                source_version="fixture-v1",
                local_ref="report:report:H:fork",
                applicable_at_ms=42,
                event_at_ms=42,
                received_at_ms=1_000,
                supersedes="evidence:report:H:original",
            )
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        evidence.evidence_id,
                        evidence.item_id,
                        evidence.kind,
                        evidence.common_origin_id,
                        evidence.source_id,
                        evidence.source_version,
                        evidence.local_ref,
                        evidence.applicable_at_ms,
                        evidence.event_at_ms,
                        evidence.received_at_ms,
                        evidence.content_digest,
                        evidence.record_digest,
                        evidence.amount_cents,
                        evidence.reversal_of,
                        evidence.supersedes,
                    ),
                )

        self._assert_rejected_without_repair(target, tamper, "evidence:report-supersedes-fork")

    def test_reporting_supersedes_cycle_fails_closed_without_repair(self) -> None:
        target = self._copy_database("reporting-lineage-cycle.sqlite")

        def tamper(path: Path) -> None:
            self._rewrite_report_supersedes(
                path,
                "evidence:report:H:correction",
                "evidence:report:H:correction-2",
            )

        self._assert_rejected_without_repair(target, tamper, "evidence:report-supersedes-chronology")

    def test_population_completion_event_is_bound_to_source_flag(self) -> None:
        target = self._copy_database("population-completion-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE population_imports SET source_complete=0,status='STAGED',validated_count=0,validation_digest=NULL WHERE population_id=?",
                    ("population:test",),
                )

        self._assert_rejected_without_repair(target, tamper, "history:population-completion-binding")

    def test_common_origin_duplicate_and_conflict_are_visible_without_cash_rewrite(self) -> None:
        duplicate = self.store.record_payment_evidence(
            item_id="item:H",
            payment_id="payment:P2",
            common_origin_id="origin:P1",
            amount_cents=9_700_000,
            evidence_id="evidence:payment:P2",
            event_at_ms=21,
        )
        conflict = self.store.record_payment_evidence(
            item_id="item:H",
            payment_id="payment:P3",
            common_origin_id="origin:P1",
            amount_cents=9_600_000,
            evidence_id="evidence:payment:P3",
            event_at_ms=22,
        )
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(conflict["status"], "CONFLICT")
        self.store.evaluate_obligation("item:H")
        result = self._verify()
        obligation = next(iter(result["obligations"].values()))
        self.assertEqual(result["counts"]["conflicts"], 1)
        self.assertEqual(obligation["verification_status"], "CONFLICT_VISIBLE")
        self.assertEqual(obligation["received_cash_cents"], 9_700_000)

    def test_owner_continuity_package_digest_and_oversized_input_fail_closed(self) -> None:
        package = self.store.export_continuity()
        valid = self._verify(continuity_package=package)
        self.assertIsNotNone(valid["continuity"])

        tampered = json.loads(package.decode("ascii"))
        tampered["package_digest"] = "0" * 128
        tampered_bytes = json.dumps(tampered, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:package-digest"):
            self._verify(continuity_package=tampered_bytes)
        self.assertEqual(tampered_bytes, json.dumps(tampered, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"))

        oversized = b"x" * (independent.MAX_PACKAGE_BYTES + 1)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:byte-cap"):
            independent.verify_continuity_package(
                oversized,
                expected_scope=self.scope,
                expected_authority=self.authority_binding,
            )
