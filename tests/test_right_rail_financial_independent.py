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
from unittest.mock import patch

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


def _unverified_export(store: owner.FinancialOwner) -> bytes:
    """A compromised writer's package: R1a's export verifies the store first, so it is built here directly."""
    with closing(store._connect()) as connection:
        connection.execute("BEGIN")
        return store._continuity_package_bytes(connection)


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
        self.addCleanup(self.store.close)  # R1a: the owner's writer holds the file open until closed
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
        source_digest: bytes = bytes.fromhex("AB" * 64),
        approval_ref: str | None = None,
        store: owner.FinancialOwner | None = None,
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
            approval_ref=f"approval:{manifest_id}" if approval_ref is None else approval_ref,
            source_id="source:population-roster",
            source_version=source_version,
            source_digest=source_digest,
            member_ids=tuple(sorted(member_ids)),
        )
        (self.store if store is None else store).register_population_manifest(manifest)
        return manifest

    def _fixture_pack(self) -> owner.ControlPack:
        return owner.ControlPack(
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

    def _populate_owner(self) -> None:
        pack = self._fixture_pack()
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
        self.clock.value = 1_999  # recorded when decided: a later event never commits before this one
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
        self.store.close()  # R1a: the writer's commits reach the main file when it closes
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
        pack = self._fixture_pack()
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
        manifest = self._register_manifest(
            manifest_id="population-manifest:partial-history:v1",
            member_ids=tuple(item.item_id for item in items) + ("item:partial-5",),
            source_owner_id="source-owner:partial-history",
            source_version="roster-partial-v1",
            source_digest=bytes.fromhex("CD" * 64),
            approval_ref="approval:partial-history",
            store=partial,
        )
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
    def _history_rehash_context(
        connection: sqlite3.Connection, rows: list[sqlite3.Row] | list[dict[str, object]],
    ) -> tuple[int, dict[str, int], bytes]:
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
        return base_committed_at, registered_at_by_manifest, previous

    @staticmethod
    def _rehashed_event(
        row: sqlite3.Row | dict[str, object], sequence: int, committed_at: int,
        previous: bytes, payload_digest: bytes,
    ) -> tuple[bytes, bytes]:
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
        return event_id, head

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
            base_committed_at, registered_at_by_manifest, previous = (
                IndependentFinancialCheckerTests._history_rehash_context(connection, rows)
            )
            for sequence, row in enumerate(rows, start=1):
                committed_at = base_committed_at + sequence
                if row["aggregate_type"] == "POPULATION_MANIFEST":
                    committed_at = registered_at_by_manifest[str(row["aggregate_id"])]
                payload_bytes = str(row["payload_json"]).encode("ascii")
                payload_digest = independent._digest(independent.EVENT_DOMAIN, payload_bytes)
                row["payload_digest"] = payload_digest
                event_id, head = IndependentFinancialCheckerTests._rehashed_event(
                    row, sequence, committed_at, previous, payload_digest,
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
            times = [int(row["committed_at_ms"]) for row in rows]  # each position keeps its time: the clock stays in order
            left_candidates = [index for index, row in enumerate(rows) if row["aggregate_id"] == population_id and row["kind"] == left_kind]
            right_candidates = [index for index, row in enumerate(rows) if row["aggregate_id"] == population_id and row["kind"] == right_kind]
            left_position = left_candidates[left_index]
            right_position = right_candidates[right_index]
            rows[left_position], rows[right_position] = rows[right_position], rows[left_position]
            offset = 100_000
            _drop_history_triggers(connection)
            connection.execute("UPDATE financial_events SET event_sequence=event_sequence+?", (offset,))
            _base, _registered, previous = IndependentFinancialCheckerTests._history_rehash_context(connection, rows)
            for sequence, (row, committed_at) in enumerate(zip(rows, times), start=1):
                event_id, head = IndependentFinancialCheckerTests._rehashed_event(
                    row, sequence, committed_at, previous, bytes(row["payload_digest"]),
                )
                connection.execute(
                    "UPDATE financial_events SET event_sequence=?,event_id=?,previous_head=?,head=?,committed_at_ms=? WHERE event_sequence=?",
                    (sequence, event_id, previous, head, committed_at, int(row["event_sequence"]) + offset),
                )
                previous = head
            connection.execute("UPDATE financial_meta SET history_head=? WHERE id=1", (previous,))
            _restore_history_triggers(connection)

    @staticmethod
    def _edit_events_and_rehash(path: Path, edit: object) -> None:
        """Let ``edit(rows)`` change event dicts (payload_json, committed_at_ms), then rehash the whole chain."""
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            rows = [dict(row) for row in connection.execute("SELECT * FROM financial_events ORDER BY event_sequence")]
            edit(rows)
            _drop_history_triggers(connection)
            _base, _registered, previous = IndependentFinancialCheckerTests._history_rehash_context(connection, rows)
            for row in rows:
                payload_digest = independent._digest(independent.EVENT_DOMAIN, str(row["payload_json"]).encode("ascii"))
                event_id, head = IndependentFinancialCheckerTests._rehashed_event(
                    row, int(row["event_sequence"]), int(row["committed_at_ms"]), previous, payload_digest,
                )
                connection.execute(
                    "UPDATE financial_events SET event_id=?,previous_head=?,head=?,committed_at_ms=?,payload_json=?,payload_digest=? WHERE event_sequence=?",
                    (event_id, previous, head, row["committed_at_ms"], row["payload_json"], payload_digest, row["event_sequence"]),
                )
                previous = head
            connection.execute("UPDATE financial_meta SET history_head=? WHERE id=1", (previous,))
            _restore_history_triggers(connection)

    def test_rehashed_history_whose_commit_times_run_backward_fails_database_and_package(self) -> None:
        def last_event_before_its_predecessor(rows: list[dict[str, object]]) -> None:
            rows[-1]["committed_at_ms"] = int(rows[-2]["committed_at_ms"]) - 1

        target = self._copy_database("commit-order-tamper.sqlite")
        self._edit_events_and_rehash(target, last_event_before_its_predecessor)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:commit-order"):
            self._verify(target)
        # No Owner can open it; a compromised writer's export must fail the package path too.
        tampered_owner = owner.FinancialOwner.__new__(owner.FinancialOwner)
        tampered_owner._initialize(
            path=target, config=self.config, trusted_authority=self.authority, clock=_Clock(), mode="LIVE",
            owner_id="financial-owner-v1", identity_contract=None,
        )
        with self.assertRaisesRegex(independent.IndependentFinancialError, "history:commit-order"):
            independent.verify_continuity_package(
                _unverified_export(tampered_owner), expected_scope=self.scope, expected_authority=self.authority_binding,
            )

    def test_rehashed_evidence_received_before_its_event_committed_fails_replay(self) -> None:
        def skew_support_received(rows: list[dict[str, object]]) -> None:
            for row in rows:
                payload = json.loads(str(row["payload_json"]))
                for image in payload.get("rows", []):
                    if image.get("table") == "evidence" and image.get("row", {}).get("kind") == "SUPPORT":
                        image["row"]["received_at_ms"] = int(row["committed_at_ms"]) - 1
                        row["payload_json"] = independent._canonical(payload, "test:skew-payload").decode("ascii")
                        return
            self.fail("no SUPPORT evidence image in the fixture history")

        target = self._copy_database("evidence-received-at-tamper.sqlite")
        self._edit_events_and_rehash(target, skew_support_received)
        with self.assertRaisesRegex(independent.IndependentFinancialError, "replay:evidence-received-at"):
            self._verify(target)

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
                identity_contract=None,
            )
            tampered_package = _unverified_export(tampered_owner)
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
                target = self._copy_database(f"{label}.sqlite")
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
        restored = owner.FinancialOwner.restore_continuity(
            package_bytes=source_package,
            recovered_path=restored_path,
            trusted_authority=self.authority,
            clock=self.clock,
            restore_mode="TEST",
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

    def test_followthrough_pre_commit_check_matches_whole_database_rules(self) -> None:
        # The two modes must not drift: each forgery of the decided store raises the code verify_database raises
        # (the deleted command row gives the pre-COMMIT command code), and the untouched decision passes.
        from tests import test_right_rail_financial_followthrough as followthrough

        (Path(self.temp_dir.name) / "decided").mkdir()
        source = followthrough._decided_store(Path(self.temp_dir.name) / "decided")
        source.close()  # R1a: its commits reach the main file when it closes
        cases = (("untouched", lambda path: None, None), *((name, forge, code) for name, forge, _whole, code in followthrough.FORGERIES))
        for name, forge, code in cases:
            with self.subTest(name):
                copy = Path(self.temp_dir.name) / f"pre-commit-{name.replace(' ', '-')}.sqlite3"
                copy.write_bytes(source.path.read_bytes())
                forge(copy)
                with closing(sqlite3.connect(copy, isolation_level=None)) as connection:
                    connection.row_factory = sqlite3.Row
                    (obligation_id,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item-r2'").fetchone()
                    check = lambda: independent.verify_followthrough_connection(connection, obligation_id, followthrough.CLOSE, **source._checker_expectations())
                    if code is None:
                        self.assertEqual(check()["decision_id"], followthrough.CLOSE)
                    else:
                        with self.assertRaisesRegex(independent.IndependentFinancialError, f"^{code}$"):
                            check()

    def test_per_obligation_reads_ignore_other_obligations_but_the_caps_count_the_whole_table(self) -> None:
        # The pre-COMMIT reads (evidence, determinations, actions, outbox) are filtered in SQL to the touched obligation. Other
        # obligations' rows change nothing, up to the cap; one row past it fails closed even though none of them is read.
        zero = "zeroblob(64)"
        others = {  # table -> (column filtered on, this obligation's key, 'other' rows that would fail every check if the filter let one through)
            "evidence": ("item_id", "item:H", f"INSERT INTO evidence SELECT 'e'||i,'item:other','SUPPORT','o','s','v','r',1,1,1,{zero},{zero},NULL,NULL,NULL FROM n"),
            "determinations": ("obligation_id", None, f"INSERT INTO determinations SELECT 'd'||i,'obligation:other',NULL,'a','r','au',1,{zero},'OFFSET_AUTHORIZED',1,'[]',1,2,1,{zero},'e'||i,{zero} FROM n"),
            "actions": ("obligation_id", None, f"INSERT INTO actions SELECT 'a'||i,'obligation:other','d','K','READY',1,'{{}}',{zero},{zero},1 FROM n"),
            "action_outbox": ("action_id", "action:offset:claim:H", f"INSERT INTO action_outbox SELECT 'a'||i,'READY',0,{zero},NULL,1 FROM n"),
        }
        with closing(sqlite3.connect(self.db, isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            (obligation_id,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item:H'").fetchone()
            check = lambda: independent.verify_obligation_connection(connection, obligation_id, expected_config=self.config, expected_authority=self.authority)
            expected = check()
            for table, (column, key, insert) in others.items():
                key = key or obligation_id
                (held,) = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                for extra, code in ((independent.MAX_ROWS - held, None), (independent.MAX_ROWS - held + 1, f"^rows:cap:{table}$")):
                    with self.subTest(table=table, extra=extra):
                        connection.execute("BEGIN IMMEDIATE")
                        try:
                            connection.execute(f"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{extra}) {insert}")
                            if code is None:
                                mine = independent._bounded_rows(connection, table, column, [key])
                                self.assertTrue(mine)  # this obligation's own rows are read, in table order
                                self.assertEqual(mine, [row for row in independent._bounded_rows(connection, table) if row[column] == key])
                                self.assertEqual(check(), expected)
                            else:
                                with self.assertRaisesRegex(independent.IndependentFinancialError, code):
                                    check()
                        finally:
                            connection.execute("ROLLBACK")

    def test_pre_commit_reads_do_not_trust_an_index_that_hides_forged_rows(self) -> None:
        # File access can blank an index (writable_schema), insert a forged row it then omits, and restore the index SQL. Only a table scan sees it.
        from tests import test_right_rail_financial_followthrough as followthrough

        z = "zeroblob(64)"
        with closing(sqlite3.connect(self.db)) as connection:
            (obligation,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item:H'").fetchone()
        (Path(self.temp_dir.name) / "decided").mkdir()
        decided = followthrough._decided_store(Path(self.temp_dir.name) / "decided")
        decided.close()  # R1a: its commits reach the main file when it closes
        with closing(sqlite3.connect(decided.path)) as connection:
            (decided_obligation,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item-r2'").fetchone()

        def decided_copy(name: str) -> Path:
            return Path(shutil.copy2(decided.path, Path(self.temp_dir.name) / name))

        per_obligation = lambda connection: independent.verify_obligation_connection(connection, obligation, expected_config=self.config, expected_authority=self.authority)
        cases = (  # copy, table, its filter column and key, index, forged rows, the code an unhidden row gets, the pre-COMMIT check
            (self._copy_database, "evidence", "item_id", "item:H", "rr_financial_v1_evidence_item_id",(f"INSERT INTO evidence VALUES ('evidence:forged','item:H','SUPPORT','o','s','v','r',1,1,1,{z},{z},NULL,NULL,NULL)",), "evidence:content-digest", per_obligation),
            (self._copy_database, "determinations", "obligation_id", obligation, "rr_financial_v1_determinations_obligation_id",(f"INSERT INTO determinations VALUES ('determination:forged',:o,NULL,'a','x','au',1,{z},'OFFSET_AUTHORIZED',1,'[]',1,2,1,{z},'evaluation:forged',{z})",), "determination:role", per_obligation),
            (self._copy_database, "actions", "obligation_id", obligation, "rr_financial_v1_actions_obligation_id",(f"INSERT INTO actions VALUES ('action:forged',:o,'determination:forged','CORRECTION_PAYMENT_REQUEST','READY',1,'{{}}',{z},{z},1)", f"INSERT INTO action_outbox VALUES ('action:forged','READY',0,{z},NULL,1)"), "action:determination", per_obligation),
            (decided_copy, "financial_events", "kind", "FOLLOWTHROUGH_DECIDED", "rr_financial_v3_events_kind",  # R1c: a second copy of the decision
             (f"INSERT INTO financial_events SELECT event_sequence+1000,{z},aggregate_type,aggregate_id,kind,before_revision,after_revision,payload_json,payload_digest,previous_head,head,committed_at_ms FROM financial_events WHERE kind='FOLLOWTHROUGH_DECIDED'",),
             "followthrough:duplicate", lambda connection: independent.verify_followthrough_connection(connection, decided_obligation, followthrough.CLOSE, **decided._checker_expectations())),
        )

        def run(path: Path, *statements: str) -> None:  # one connection per step, so each reads the schema as the step before left it
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                for statement in statements:
                    connection.execute(statement, {"o": obligation})

        for copy_of, table, column, key, index, forged, code, check in cases:
            with self.subTest(table):
                copy = copy_of(f"hidden-{table}.sqlite")
                run(copy, "PRAGMA writable_schema=ON", f"UPDATE sqlite_master SET sql=sql||' WHERE 0' WHERE name='{index}'")
                run(copy, *forged)
                run(copy, "PRAGMA writable_schema=ON", f"UPDATE sqlite_master SET sql=replace(sql,' WHERE 0','') WHERE name='{index}'")
                with closing(sqlite3.connect(copy, isolation_level=None)) as connection:
                    connection.row_factory = sqlite3.Row
                    count = lambda hint: connection.execute(f"SELECT COUNT(*) FROM {table} {hint} WHERE {column}=?", (key,)).fetchone()[0]
                    self.assertEqual(count("NOT INDEXED"), count("") + 1)  # the index really hides it
                    with self.assertRaisesRegex(independent.IndependentFinancialError, f"^{code}$"):
                        check(connection)
                    if table == "financial_events":  # the Owner's command-source read, which must find exactly one, sees both too
                        self.assertEqual(len(connection.execute(owner._COMMAND_REQUEST_SQL["FOLLOWTHROUGH_DECISION"], (followthrough.CLOSE,)).fetchall()), 2)

    def test_pre_commit_never_selects_evaluation_snapshots(self) -> None:
        # The per-obligation check reads each evaluation's O(n)-byte input snapshot only for the current row, by its id: never for the whole history.
        with closing(sqlite3.connect(self._copy_database("snapshots.sqlite"))) as connection:
            connection.row_factory = sqlite3.Row
            (obligation,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item:H'").fetchone()
            statements: list[str] = []
            connection.set_trace_callback(statements.append)
            independent.verify_obligation_connection(connection, obligation, expected_config=self.config, expected_authority=self.authority)
        reads = [statement for statement in statements if "FROM evaluations" in statement]
        self.assertTrue(any("json_each" in statement for statement in reads), "the history read ran")
        for statement in reads:
            if "json_each" in statement:
                self.assertFalse(any(name in statement for name in ("*", "input_snapshot_json", "evidence_bindings_json", "receipt_digest")), statement)
            elif "input_snapshot_json" in statement or "*" in statement:
                self.assertIn("WHERE evaluation_id=", statement)

    def test_a_column_the_rules_need_is_never_dropped(self) -> None:
        # Forge each column of each of the item's evaluation rows in turn: the narrowed read must give the verdict the read of whole rows gave.
        with closing(sqlite3.connect(self._copy_database("columns.sqlite"), isolation_level=None)) as connection:
            connection.row_factory = sqlite3.Row
            (obligation,) = connection.execute("SELECT obligation_id FROM obligations WHERE item_id='item:H'").fetchone()
            rowids = [row[0] for row in connection.execute("SELECT rowid FROM evaluations WHERE obligation_id=?", (obligation,))]
            columns = [row["name"] for row in connection.execute("PRAGMA table_info(evaluations)")]

            def verdict() -> str:
                try:
                    independent.verify_obligation_connection(connection, obligation, expected_config=self.config, expected_authority=self.authority)
                except independent.IndependentFinancialError as error:
                    return str(error)
                return "ok"

            self.assertEqual(verdict(), "ok")
            verdicts = set()
            for rowid in rowids:
                for column in columns:
                    connection.execute("BEGIN")
                    try:
                        connection.execute(f"UPDATE evaluations SET {column}=CASE typeof({column}) WHEN 'integer' THEN {column}+1 WHEN 'blob' THEN x'00'||{column} WHEN 'null' THEN 1 ELSE {column}||'x' END WHERE rowid=?", (rowid,))
                        narrow = verdict()
                        with patch.object(independent, "_EVALUATION_COLUMNS", "rowid," + ",".join(columns)):
                            self.assertEqual(narrow, verdict(), (rowid, column))
                        verdicts.add(narrow)
                    except sqlite3.IntegrityError:
                        pass  # the schema itself refuses this forgery
                    finally:
                        connection.execute("ROLLBACK")
            self.assertGreater(len(verdicts), 2, verdicts)

    def test_a_conflict_id_must_be_the_owners_canonical_form(self) -> None:
        """A forged id that also rewrites its evaluation's snapshot passes every earlier check; only the id's form names the item, origin and evidence."""
        evidence = {"e": {"kind": "PAYMENT_CONFIRMATION", "common_origin_id": "o", "item_id": "i"}}
        for conflict_id, code in (("conflict:i:o:e", "conflict:existing-payment"), ("conflict:i:o:x", "conflict:id-form"), ("other", "conflict:id-form")):
            with self.subTest(conflict_id), closing(sqlite3.connect(":memory:")) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("CREATE TABLE financial_conflicts (conflict_id, obligation_id, common_origin_id, candidate_evidence_id, existing_payment_id)")
                connection.execute("CREATE TABLE financial_events (aggregate_type, kind, payload_json, committed_at_ms, event_sequence)")
                connection.execute("INSERT INTO financial_conflicts VALUES (?,'ob','o','e',NULL)", (conflict_id,))
                with self.assertRaisesRegex(independent.IndependentFinancialError, f"^{code}$"):
                    independent._verify_conflicts(connection, {}, evidence, {})
