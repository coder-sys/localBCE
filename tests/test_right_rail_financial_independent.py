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

_HISTORY_TRIGGERS = ("financial_event_update_immutable", "financial_event_delete_immutable")


def _drop_history_triggers(connection: sqlite3.Connection) -> None:
    # Model an attacker with file access: the append-only triggers are
    # dropped for the tamper and restored, so only the history can reveal it.
    for name in _HISTORY_TRIGGERS:
        connection.execute(f"DROP TRIGGER {name}")


def _restore_history_triggers(connection: sqlite3.Connection) -> None:
    for name in _HISTORY_TRIGGERS:
        connection.execute(independent._TRIGGER_DEFS[name])


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
            "actors": [
                {"actor_id": actor.actor_id, "roles": list(actor.roles)}
                for actor in self.authority.actors
            ],
        }

    def _register_manifest(
        self,
        *,
        manifest_id: str,
        member_ids: tuple[str, ...],
        source_owner_id: str = "source-owner:test",
        source_version: str = "roster-test-v1",
    ) -> owner.PopulationManifest:
        manifest = owner.PopulationManifest(
            manifest_id=manifest_id,
            manifest_version=1,
            state_id=self.config.state_id,
            deployment_id=self.config.deployment_id,
            program_id=self.config.program_id,
            period_id=self.config.period_id,
            currency=self.config.currency,
            pack_id="pack:test",
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            source_owner_id=source_owner_id,
            authority_id=self.authority.authority_id,
            authority_epoch=self.authority.epoch,
            authority_digest=self.authority.digest,
            approved_by="synthetic-official",
            approval_ref=f"approval:{manifest_id}",
            source_id="source:population-roster",
            source_version=source_version,
            source_digest=bytes.fromhex("AB" * 64),
            member_ids=tuple(sorted(member_ids)),
        )
        self.store.register_population_manifest(manifest)
        return manifest

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
        manifest = self._register_manifest(
            manifest_id="population-manifest:test:v1",
            member_ids=(item.item_id,),
        )
        self.store.stage_population(
            population_id="population:test",
            manifest_id=manifest.manifest_id,
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
        receipt = self.store.current_evaluation_receipt("item:H")
        self.store.authorize_offset(
            item_id="item:H",
            claim_id="claim:H",
            action_id="action:offset:claim:H",
            decision_at_ms=2_000,
            expected_revision=receipt["revision"],
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
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

    def _verify(
        self,
        path: Path | None = None,
        *,
        mode: str = "LIVE",
        owner_id: str = "financial-owner-v1",
        current_snapshot_package: bytes | None = None,
        restore_source_package: bytes | None = None,
    ) -> dict[str, object]:
        return independent.verify_database(
            path or self.db,
            expected_scope=self.scope,
            expected_authority=self.authority_binding,
            expected_mode=mode,
            expected_owner_id=owner_id,
            current_snapshot_package=current_snapshot_package,
            restore_source_package=restore_source_package,
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
        manifest = self._register_manifest(
            manifest_id=f"population-manifest:{population_id}:v1",
            member_ids=tuple(item.item_id for item in items),
            source_owner_id=f"source-owner:{population_id}",
        )
        self.store.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id="pack:test",
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            expected_count=2,
            items=items,
            chunk_size=1,
        )
        self.store.validate_population(population_id)
        self.store.publish_population(population_id)

    def _make_partial_import(self, name: str = "partial-import.sqlite") -> Path:
        path = Path(self.temp_dir.name) / name
        partial = owner.FinancialOwner(
            path=path,
            config=self.config,
            trusted_authority=self.authority,
            clock=_Clock(),
        )
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
        partial.publish_control_pack(pack)
        population_id = "population:partial-history"
        items = tuple(
            owner.PopulationItem(
                population_id=population_id,
                item_id=f"item:partial-{index}",
                display_label=f"Partial item {index}",
                owed_cents=1,
                due_at_ms=10_000 + index,
            )
            for index in range(1, 5)
        )
        manifest = owner.PopulationManifest(
            manifest_id="population-manifest:partial-history:v1",
            manifest_version=1,
            state_id=self.config.state_id,
            deployment_id=self.config.deployment_id,
            program_id=self.config.program_id,
            period_id=self.config.period_id,
            currency=self.config.currency,
            pack_id=pack.pack_id,
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            source_owner_id="source-owner:partial-history",
            authority_id=self.authority.authority_id,
            authority_epoch=self.authority.epoch,
            authority_digest=self.authority.digest,
            approved_by="synthetic-official",
            approval_ref="approval:partial-history",
            source_id="source:population-roster",
            source_version="roster-partial-v1",
            source_digest=bytes.fromhex("CD" * 64),
            member_ids=tuple(sorted((*(item.item_id for item in items), "item:partial-5"))),
        )
        partial.register_population_manifest(manifest)
        result = partial.stage_population(
            population_id=population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=4,
            inclusion_rules=("INCLUDED",),
            expected_count=5,
            items=items,
            chunk_size=2,
        )
        self.assertEqual(result["imported_count"], 4)
        self.assertFalse(result["source_complete"])
        partial.close()
        return path

    @staticmethod
    def _rehash_partial_history(path: Path, variant: str) -> None:
        if variant not in {"removed", "reduced"}:
            raise ValueError(variant)
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            rows = [dict(row) for row in connection.execute("SELECT * FROM financial_events ORDER BY event_sequence")]
            stage_rows = [row for row in rows if row["aggregate_id"] == "population:partial-history" and row["kind"] == "POPULATION_STAGED"]
            assert len(stage_rows) == 2
            target = stage_rows[-1]
            removed_sequence: int | None = None
            if variant == "removed":
                removed_sequence = int(target["event_sequence"])
                rows = [row for row in rows if row["event_sequence"] != target["event_sequence"]]
            else:
                payload = json.loads(str(target["payload_json"]))
                payload["imported_count"] = 3
                payload["chunk_count"] = 1
                payload_bytes = independent._canonical(payload, "test:partial-payload")
                target["payload_json"] = payload_bytes.decode("ascii")
                target["payload_digest"] = independent._digest(independent.EVENT_DOMAIN, payload_bytes)
                target["after_revision"] = 3
            offset = 100_000
            _drop_history_triggers(connection)
            connection.execute("UPDATE financial_events SET event_sequence=event_sequence+?", (offset,))
            if removed_sequence is not None:
                connection.execute("DELETE FROM financial_events WHERE event_sequence=?", (removed_sequence + offset,))
            meta = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
            assert meta is not None
            identity = connection.execute("SELECT identity_digest FROM financial_identity WHERE id=1").fetchone()
            assert identity is not None
            base_committed_at = min(int(row["committed_at_ms"]) for row in rows)
            registered_at_by_manifest = {
                str(row["manifest_id"]): int(row["registered_at_ms"])
                for row in connection.execute(
                    "SELECT manifest_id,registered_at_ms FROM population_manifests"
                )
            }
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
                bytes(identity["identity_digest"]),
            )
            for sequence, row in enumerate(rows, start=1):
                committed_at = base_committed_at + sequence
                if row["aggregate_type"] == "POPULATION_MANIFEST":
                    committed_at = registered_at_by_manifest[str(row["aggregate_id"])]
                payload_bytes = str(row["payload_json"]).encode("ascii")
                payload_digest = independent._digest(independent.EVENT_DOMAIN, payload_bytes)
                row["payload_digest"] = payload_digest
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
                    payload_digest,
                )
                head = independent._digest(
                    independent.HEAD_DOMAIN,
                    previous,
                    event_id,
                    header,
                    payload_digest,
                )
                connection.execute(
                    "UPDATE financial_events SET event_sequence=?,before_revision=?,after_revision=?,event_id=?,previous_head=?,head=?,committed_at_ms=?,payload_json=?,payload_digest=? WHERE event_sequence=?",
                    (
                        sequence,
                        row["before_revision"],
                        row["after_revision"],
                        event_id,
                        previous,
                        head,
                        committed_at,
                        row["payload_json"],
                        payload_digest,
                        int(row["event_sequence"]) + offset,
                    ),
                )
                previous = head
            connection.execute("UPDATE financial_meta SET sequence=?,history_head=? WHERE id=1", (len(rows), previous))
            _restore_history_triggers(connection)

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
            _drop_history_triggers(connection)
            connection.execute("UPDATE financial_events SET event_sequence=event_sequence+?", (offset,))
            meta = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
            assert meta is not None
            identity = connection.execute("SELECT identity_digest FROM financial_identity WHERE id=1").fetchone()
            assert identity is not None
            base_committed_at = min(int(row["committed_at_ms"]) for row in rows)
            registered_at_by_manifest = {
                str(row["manifest_id"]): int(row["registered_at_ms"])
                for row in connection.execute(
                    "SELECT manifest_id,registered_at_ms FROM population_manifests"
                )
            }
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
                bytes(identity["identity_digest"]),
            )
            for sequence, row in enumerate(rows, start=1):
                committed_at = base_committed_at + sequence
                if row["aggregate_type"] == "POPULATION_MANIFEST":
                    committed_at = registered_at_by_manifest[str(row["aggregate_id"])]
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
            _restore_history_triggers(connection)

    def test_valid_owner_fixture_reconstructs_projection_and_identity(self) -> None:
        result = self._verify()
        obligation = next(iter(result["obligations"].values()))
        self.assertEqual(result["schema"], "RR/FINANCIAL/OWNER/v8")
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

    def test_determination_actor_without_roster_role_fails_closed_without_repair(self) -> None:
        for label, actor_id in (
            ("role-missing", "synthetic-reporter"),
            ("unknown-actor", "synthetic-unknown-actor"),
        ):
            with self.subTest(label=label):
                target = self._copy_database(f"determination-actor-{label}.sqlite")

                def tamper(path: Path, replacement: str = actor_id) -> None:
                    with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                        changed = connection.execute(
                            "UPDATE determinations SET actor_id=? WHERE actor_role='FINANCE_DECISION'",
                            (replacement,),
                        ).rowcount
                        self.assertEqual(changed, 1)

                self._assert_rejected_without_repair(target, tamper, "determination:actor-role")

    def test_database_verification_requires_digest_bound_authority_roster(self) -> None:
        without_roster = {key: value for key, value in self.authority_binding.items() if key != "actors"}
        widened_roster = dict(self.authority_binding)
        widened_roster["actors"] = [
            {"actor_id": actor["actor_id"], "roles": [*actor["roles"], "FINANCE_DECISION"]}
            if "FINANCE_DECISION" not in actor["roles"]
            else actor
            for actor in self.authority_binding["actors"]
        ]
        aliased_epoch = {
            ("authority_epoch" if key == "epoch" else key): value
            for key, value in self.authority_binding.items()
        }
        for label, authority, code in (
            ("absent", None, "identity:authority-required"),
            ("roster-missing", without_roster, "identity:authority-roster-required"),
            ("roster-not-bound", widened_roster, "identity:authority-roster-digest"),
            ("epoch-alias", aliased_epoch, "identity:missing-epoch"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(independent.IndependentFinancialError, code):
                    independent.verify_database(
                        self.db,
                        expected_scope=self.scope,
                        expected_authority=authority,
                        expected_mode="LIVE",
                        expected_owner_id="financial-owner-v1",
                    )
        self.assertEqual(self._verify()["mode"], "LIVE")

    def test_continuity_package_verification_requires_caller_authority_roster(self) -> None:
        package = self.store.export_continuity()
        without_roster = {key: value for key, value in self.authority_binding.items() if key != "actors"}
        for label, authority, code in (
            ("absent", None, "identity:authority-required"),
            ("roster-missing", without_roster, "identity:authority-roster-required"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(independent.IndependentFinancialError, code):
                    independent.verify_continuity_package(
                        package,
                        expected_scope=self.scope,
                        expected_authority=authority,
                    )
        verified = independent.verify_continuity_package(
            package,
            expected_scope=self.scope,
            expected_authority=self.authority_binding,
        )
        self.assertEqual(verified["authority"]["authority_id"], self.authority.authority_id)

    def test_event_payload_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("event-payload-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                _drop_history_triggers(connection)
                connection.execute(
                    "UPDATE financial_events SET payload_json=? WHERE event_sequence=1",
                    ('{"tampered":true}',),
                )
                _restore_history_triggers(connection)

        self._assert_rejected_without_repair(target, tamper, "history:payload-digest")

    def test_event_header_tamper_fails_owner_verification_without_repair(self) -> None:
        target = self._copy_database("event-header-tamper.sqlite")
        with closing(sqlite3.connect(target, isolation_level=None)) as connection:
            _drop_history_triggers(connection)
            connection.execute(
                "UPDATE financial_events SET after_revision=after_revision+1 WHERE kind='POPULATION_SOURCE_COMPLETED'"
            )
            _restore_history_triggers(connection)
        tampered_bytes = target.read_bytes()
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:event-id"):
            self._verify(target)
        # Owner open replays the history and refuses before any read or write.
        with self.assertRaisesRegex(owner.FinancialIntegrityError, r"\Aopen_verification:history:event-id\Z"):
            owner.FinancialOwner(
                path=target,
                config=self.config,
                trusted_authority=self.authority,
                clock=self.clock,
            )
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

    def test_rehashed_population_history_requires_staging_event_first(self) -> None:
        population_id = "population:history"
        self._add_published_history_population(population_id)
        reordered = self._copy_database("population-open-order-tamper.sqlite")
        self._reorder_and_rehash_population_events(
            reordered,
            population_id,
            "POPULATION_IMPORT_OPENED",
            0,
            "POPULATION_STAGED",
            0,
        )
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:population-open-order"):
            self._verify(reordered)

    def test_partial_population_history_binds_persisted_count_through_restart_and_restore(self) -> None:
        valid_path = self._make_partial_import()
        valid_result = self._verify(valid_path)
        self.assertEqual(valid_result["counts"]["populations"], 1)
        self.assertEqual(valid_result["sequence"], 5)

        reopened = owner.FinancialOwner(
            path=valid_path,
            config=self.config,
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        self.assertEqual(reopened.verify_integrity()["mode"], "LIVE")
        package = reopened.export_continuity()
        independent.verify_continuity_package(
            package,
            expected_scope=self.scope,
            expected_authority=self.authority_binding,
        )
        restored_path = Path(self.temp_dir.name) / "partial-valid-shadow.sqlite"
        restored = owner.FinancialOwner.restore_continuity(
            package_bytes=package,
            recovered_path=restored_path,
            trusted_authority=self.authority,
            clock=_Clock(),
        )
        self.assertEqual(restored.verify_integrity()["mode"], "SHADOW")
        restored.close()
        reopened.close()

        for variant in ("removed", "reduced"):
            target = Path(self.temp_dir.name) / f"partial-{variant}.sqlite"
            shutil.copy2(valid_path, target)
            self._rehash_partial_history(target, variant)
            try:
                self._verify(target)
            except independent.IndependentFinancialError as error:
                self.assertEqual(str(error), "history:population-imported-binding", f"variant={variant}")
            else:
                self.fail(f"variant={variant} was accepted")

            # Owner open replays the history against the projections and refuses
            # the tampered store without writing to it.
            tampered_bytes = target.read_bytes()
            with self.assertRaisesRegex(
                owner.FinancialIntegrityError,
                r"\Aopen_verification:history:population-imported-binding\Z",
                msg=f"variant={variant}",
            ):
                owner.FinancialOwner(
                    path=target,
                    config=self.config,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
            self.assertEqual(target.read_bytes(), tampered_bytes, f"variant={variant}")
            # The package path must reject such a store too. No Owner can open it,
            # so export through a handle that skipped open verification, as a
            # compromised writer would.
            tampered_owner = owner.FinancialOwner.__new__(owner.FinancialOwner)
            tampered_owner._initialize(
                path=target,
                config=self.config,
                trusted_authority=self.authority,
                clock=_Clock(),
                mode="LIVE",
                owner_id="financial-owner-v1",
                correction_transition_release=None,
                identity_contract=None,
            )
            tampered_package = tampered_owner.export_continuity()
            with self.assertRaisesRegex(independent.IndependentFinancialError, "history:population-imported-binding"):
                independent.verify_continuity_package(
                    tampered_package,
                    expected_scope=self.scope,
                    expected_authority=self.authority_binding,
                )
            rejected_restore = Path(self.temp_dir.name) / f"partial-{variant}-restore.sqlite"
            with self.assertRaisesRegex(owner.FinancialContinuityError, "continuity_restore_integrity"):
                owner.FinancialOwner.restore_continuity(
                    package_bytes=tampered_package,
                    recovered_path=rejected_restore,
                    trusted_authority=self.authority,
                    clock=_Clock(),
                )
            self.assertFalse(rejected_restore.exists())
            tampered_owner.close()

    def test_event_head_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("event-head-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                _drop_history_triggers(connection)
                connection.execute(
                    "UPDATE financial_events SET head=? WHERE event_sequence=(SELECT MAX(event_sequence) FROM financial_events)",
                    (b"\xff" * 64,),
                )
                _restore_history_triggers(connection)

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

    def test_evaluation_receipt_digest_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("evaluation-receipt-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE evaluations SET receipt_digest=? WHERE evaluation_id=(SELECT current_evaluation_id FROM obligations WHERE item_id=?)",
                    (b"\x00" * 64, "item:H"),
                )

        self._assert_rejected_without_repair(target, tamper, "evaluation:receipt-digest")

    def test_evaluation_authority_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("evaluation-authority-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "UPDATE evaluations SET authority_id=? WHERE evaluation_id=(SELECT current_evaluation_id FROM obligations WHERE item_id=?)",
                    ("stale-authority-v1", "item:H"),
                )

        self._assert_rejected_without_repair(target, tamper, "evaluation:authority")

    def test_historical_evaluation_input_tamper_fails_closed_without_repair(self) -> None:
        target = self._copy_database("evaluation-input-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                evaluation_id = connection.execute(
                    "SELECT evaluation_id FROM evaluations WHERE revision=(SELECT MAX(revision) FROM evaluations) LIMIT 1"
                ).fetchone()[0]
                raw = connection.execute(
                    "SELECT input_snapshot_json FROM evaluations WHERE evaluation_id=?",
                    (evaluation_id,),
                ).fetchone()[0]
                snapshot = json.loads(raw)
                snapshot["obligation"]["owed_cents"] += 1
                connection.execute(
                    "UPDATE evaluations SET input_snapshot_json=? WHERE evaluation_id=?",
                    (json.dumps(snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")), evaluation_id),
                )

        self._assert_rejected_without_repair(target, tamper, "evaluation:input-digest")

    def test_reporting_supersedes_missing_target_fails_closed_without_repair(self) -> None:
        target = self._copy_database("reporting-lineage-tamper.sqlite")

        def tamper(path: Path) -> None:
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "DELETE FROM evidence WHERE evidence_id=?",
                    ("evidence:report:H:original",),
                )

        # The declared foreign key (evidence.supersedes) refuses it before any per-table check.
        self._assert_rejected_without_repair(target, tamper, "foreign-keys:evidence")

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

    def test_private_index_inventory_rejects_unapproved_and_mismatched_indexes(self) -> None:
        corruptions = (
            (
                "unapproved-index",
                "CREATE INDEX unapproved_plan_index ON evidence(source_id)",
                "schema:private-indexes",
            ),
            (
                "mismatched-approved-name",
                "DROP INDEX rr_financial_v1_evidence_item_id; "
                "CREATE INDEX rr_financial_v1_evidence_item_id ON evidence(source_id)",
                "schema:private-index",
            ),
        )
        for label, statement, expected_error in corruptions:
            with self.subTest(label=label):
                target = Path(self.temp_dir.name) / f"{label}.sqlite"
                shutil.copyfile(self.db, target)
                with closing(sqlite3.connect(target, isolation_level=None)) as connection:
                    for sql in statement.split("; "):
                        connection.execute(sql)
                before = target.read_bytes()
                with self.assertRaisesRegex(independent.IndependentFinancialError, expected_error):
                    independent.verify_database(
                        target,
                        expected_config=self.config,
                        expected_authority=self.authority_binding,
                    )
                self.assertEqual(target.read_bytes(), before)

    def test_owner_continuity_package_digest_and_oversized_input_fail_closed(self) -> None:
        package = self.store.export_continuity()
        valid = self._verify(current_snapshot_package=package)
        self.assertIsNotNone(valid["continuity"])
        self.assertEqual(valid["continuity"]["role"], "current_snapshot")

        tampered = json.loads(package.decode("ascii"))
        tampered["package_digest"] = "0" * 128
        tampered_bytes = json.dumps(tampered, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:package-digest"):
            self._verify(current_snapshot_package=tampered_bytes)
        self.assertEqual(tampered_bytes, json.dumps(tampered, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"))

        oversized = b"x" * (independent.MAX_PACKAGE_BYTES + 1)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:byte-cap"):
            independent.verify_continuity_package(
                oversized,
                expected_scope=self.scope,
                expected_authority=self.authority_binding,
            )

    def test_package_roles_bind_content_and_restore_anchor(self) -> None:
        package = json.loads(self.store.export_continuity().decode("ascii"))
        package["tables"]["evidence"][0]["local_ref"] = "tampered:same-count-current"
        body = dict(package)
        del body["package_digest"]
        package["package_digest"] = independent.continuity_package_digest(body)
        altered_current = owner._canonical(package)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:current-snapshot-mismatch"):
            self._verify(current_snapshot_package=altered_current)

        source_package = self.store.export_continuity()
        restored_path = Path(self.temp_dir.name) / "role-test-restore.sqlite"
        restored = owner.FinancialOwner.restore_test_continuity(
            package_bytes=source_package,
            recovered_path=restored_path,
            trusted_authority=self.authority,
            clock=self.clock,
        )
        restored.close()
        altered_source = json.loads(source_package.decode("ascii"))
        altered_source["tables"]["evidence"][0]["local_ref"] = "tampered:same-count-source"
        source_body = dict(altered_source)
        del source_body["package_digest"]
        altered_source["package_digest"] = independent.continuity_package_digest(source_body)
        altered_source_bytes = owner._canonical(altered_source)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "continuity:restore-source-digest"):
            self._verify(
                restored_path,
                mode="TEST",
                owner_id=owner._TEST_OWNER_ID,
                restore_source_package=altered_source_bytes,
            )
