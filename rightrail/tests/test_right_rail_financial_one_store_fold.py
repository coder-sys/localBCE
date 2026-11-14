"""Step 1a of the one-store design (section 5.4): the financial owner's own export, folded one event at a time.

Read-only check. For a frozen owner export, apply each event's own effects to a running copy of every table, and
require that (a) the copy equals the owner's sealed end-of-segment image of every table at each seal, and (b) after
each event the obligation equals the evaluation row that event names. A column that changes with no event, or a row no
event explains, makes the fold differ.

What is proved, and what is not. Computed by the fold, so a change to the image shows at the seal: the five captured
tables (from the event's rows), obligations, payments, action status, the manifest head, the funding projection, the
import's progress, and the columns an event's payload carries of a control pack, manifest, manifest member, population
item key, determination, funding receipt and evaluation. Copied from the sealed image and bound only by a digest the
event names: a population item's label, amount and due time (the population's validation digest is recomputed from the
stored items); a manifest's member ids (the member digest is recomputed). Copied from the sealed image and not bound at
all: a control pack's roles and rules; a manifest's scope, approval and source fields; a determination's actor,
authority, claim, decision and supporting evidence; an action's kind, payload and key; the decided columns, evidence
list and scope of an evaluation after the opening one (the obligation is compared to them, nothing compares them to
anything else); a payment's item and event time. Synthetic, non-PHI, nonpayment."""

from __future__ import annotations

import copy
import hashlib
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app.right_rail_financial_owner as owner_module
from app import right_rail_financial_intake as intake
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_canonical_json import encode
from app.right_rail_financial_owner import FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as acceptance
from tests.instruments.load_synthetic import _SCOPE, _setup

KEYS = {
    "control_packs": ("pack_id",), "population_imports": ("population_id",), "population_items": ("population_id", "item_id"),
    "obligations": ("obligation_id",), "evidence": ("evidence_id",), "payments": ("payment_id",),
    "claimed_adjustments": ("claim_id",), "cases": ("case_id",), "determinations": ("determination_id",),
    "actions": ("action_id",), "action_outbox": ("action_id",), "financial_conflicts": ("conflict_id",),
    "evaluations": ("evaluation_id",), "program_funding_receipts": ("receipt_id",),
    "program_funding_projection": ("source_record_ref",), "population_manifests": ("manifest_id",),
    "population_manifest_members": ("manifest_id", "position"),
    "population_manifest_heads": ("state_id", "deployment_id", "program_id", "period_id", "currency", "pack_id", "cutoff_ms", "source_owner_id"),
    "population_manifest_bindings": ("population_id",),
}
# What an evaluation decides, and the obligation carries with the same column names.
DECIDED = ("claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status", "case_status", "delivery_status")
HEAD_SCOPE = ("state_id", "deployment_id", "program_id", "period_id", "currency", "pack_id", "cutoff_ms", "source_owner_id")
HEX = lambda text: {"hex": text}
# The owner's 24 event kinds, by aggregate. A kind outside this table has no row in section 5.4 and stops the fold.
OBLIGATION_KINDS = frozenset(independent._EVENT_KINDS["OBLIGATION"])
ALL_KINDS = frozenset().union(*independent._EVENT_KINDS.values())


class FoldMismatch(AssertionError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FoldMismatch(message)


class Fold:
    """The running copy of every table, advanced by one event at a time."""

    def __init__(self) -> None:
        self.state: dict[str, dict[tuple, dict]] = {table: {} for table in KEYS}
        self.items_taken: set[tuple] = set()
        self.trail: list[tuple[int, str, dict]] = []  # (event sequence, obligation id, obligation after the event)
        self.last_sequence = 0

    def _key(self, table: str, row: dict) -> tuple:
        return tuple(row[column] for column in KEYS[table])

    def _put(self, table: str, row: dict) -> None:
        key = self._key(table, row)
        if self.state[table].get(key) != row:
            self.state[table][key] = row
            self.touched.add((table, key))

    def _patch(self, table: str, key: tuple, **columns: object) -> None:
        _need(key in self.state[table], f"{table}{key}: an event changes a row that no earlier event wrote")
        self._put(table, {**self.state[table][key], **columns})

    def _once(self, table: str, key: tuple, **derived: object) -> dict:
        """A row written once: the sealed image of the segment whose event names it, with the columns the event gives
        written over it, so a change to one of those columns shows at the seal."""
        if key in self.state[table]:
            return self.state[table][key]
        _need((table, key) in self.images, f"{table}{key}: an event names a row the segment does not hold")
        self._put(table, {**self.images[(table, key)], **derived})
        return self.state[table][key]

    def segment(self, segment: dict) -> None:
        self.images = {(record["table"], self._key(record["table"], record["row"])): record["row"] for record in segment["rows"]}
        self.touched: set[tuple] = set()
        first = segment["seal"]["first_sequence"]
        _need(first == self.last_sequence + 1, f"segment starts at {first}, not {self.last_sequence + 1}")
        for event in segment["events"]:
            _need(event["event_sequence"] == self.last_sequence + 1, "events are not consecutive")
            self.last_sequence = event["event_sequence"]
            self.event(event)
        _need(self.last_sequence == segment["seal"]["last_sequence"], "the seal's last sequence is not the last event")
        for table, key in sorted(self.touched | set(self.images), key=repr):  # every table, both ways
            _need((table, key) in self.touched, f"{table}{key}: the sealed image holds a row no event explains")
            _need((table, key) in self.images, f"{table}{key}: the fold changed a row the segment's end image does not hold")
            _need(self.state[table].get(key) == self.images[(table, key)], f"{table}{key}: the fold differs from the sealed image in {self._diff(table, key)}")

    def _diff(self, table: str, key: tuple) -> list[str]:
        folded, sealed = self.state[table].get(key) or {}, self.images[(table, key)]
        return [column for column in sealed if folded.get(column) != sealed[column]]

    def event(self, event: dict) -> None:
        payload = json.loads(event["payload_json"])
        t, kind, aggregate = event["committed_at_ms"], event["kind"], event["aggregate_id"]
        before, after = event["before_revision"], event["after_revision"]
        for record in payload.pop("rows", []):
            if "row" in record:
                key = self._key(record["table"], record["row"])
                _need(key not in self.state[record["table"]], f"{record['table']}{key}: captured twice as new")
                self._put(record["table"], record["row"])
            else:
                self._patch(record["table"], (record["key"],), **record["set"])
        if kind == "CONTROL_PACK_PUBLISHED":
            self._once("control_packs", (payload["pack_id"],), pack_id=payload["pack_id"], version=payload["version"], period_id=payload["period_id"], pack_digest=HEX(payload["digest"]))
        elif kind in {"POPULATION_MANIFEST_REGISTERED", "POPULATION_MANIFEST_SUPERSEDED"}:
            manifest = self._once("population_manifests", (aggregate,), manifest_id=aggregate, contract=payload["contract"], manifest_version=after, manifest_digest=HEX(payload["manifest_digest"]),
                                  member_digest=HEX(payload["member_digest"]), member_count=payload["member_count"], supersedes_manifest_id=payload["supersedes_manifest_id"],
                                  supersedes_digest=None if payload["supersedes_digest"] is None else HEX(payload["supersedes_digest"]), registered_at_ms=t)
            members = [self._once("population_manifest_members", (aggregate, position), manifest_id=aggregate, position=position)["member_id"] for position in range(manifest["member_count"])]
            stored = owner_module._digest(owner_module._POPULATION_MANIFEST_MEMBERS_DOMAIN, owner_module._canonical({"member_ids": members})).hex().upper()
            _need(stored == payload["member_digest"].upper(), f"{aggregate}: the member digest of the stored members differs from the event's")
            head_key = tuple(manifest[column] for column in HEAD_SCOPE)
            _need((kind == "POPULATION_MANIFEST_REGISTERED") == (head_key not in self.state["population_manifest_heads"]), "manifest kind and head disagree")
            if head_key in self.state["population_manifest_heads"]:
                self._patch("population_manifest_heads", head_key, manifest_id=aggregate, manifest_version=manifest["manifest_version"], manifest_digest=manifest["manifest_digest"], updated_at_ms=t)
            else:
                self._put("population_manifest_heads", {**dict(zip(HEAD_SCOPE, head_key)), "manifest_id": aggregate, "manifest_version": manifest["manifest_version"], "manifest_digest": manifest["manifest_digest"], "updated_at_ms": t})
        elif kind == "POPULATION_IMPORT_OPENED":
            self._once("population_manifest_bindings", (aggregate,), population_id=aggregate, manifest_id=payload["manifest_id"])
            manifest = self.state["population_manifests"][(payload["manifest_id"],)]
            fixed = self.images.get(("population_imports", (aggregate,)))
            _need(fixed is not None, "an opened population has no image in its segment")
            self._put("population_imports", {**fixed, "population_id": aggregate, "pack_id": manifest["pack_id"], "cutoff_ms": manifest["cutoff_ms"], "inclusion_rules_json": manifest["inclusion_rules_json"],
                                             "expected_count": manifest["member_count"], "source_complete": 0, "imported_count": 0, "validated_count": 0, "validation_digest": None, "status": "STAGED", "created_at_ms": t, "updated_at_ms": t})
        elif kind == "POPULATION_STAGED":
            fresh = sorted(key for table, key in self.images if table == "population_items" and key[0] == aggregate and key not in self.items_taken)
            _need(len(fresh) >= after - before, "a staged chunk has fewer items than it counts")
            manifest = self.state["population_manifests"][(self.state["population_manifest_bindings"][(aggregate,)]["manifest_id"],)]
            members = {row["member_id"] for key, row in self.state["population_manifest_members"].items() if key[0] == manifest["manifest_id"]}
            for key in fresh[: after - before]:
                self.items_taken.add(key)
                _need(key[1] in members, f"{key}: a staged item is not a member of the population's manifest")
                self._once("population_items", key, population_id=key[0], item_id=key[1], currency=manifest["currency"])
            self._patch("population_imports", (aggregate,), imported_count=after, updated_at_ms=t)
        elif kind == "POPULATION_SOURCE_COMPLETED":
            self._patch("population_imports", (aggregate,), source_complete=1, updated_at_ms=t)
        elif kind == "POPULATION_VALIDATED":
            rows = [(row["item_id"], row["display_label"], row["owed_cents"], row["due_at_ms"], row["currency"]) for key, row in sorted(self.state["population_items"].items()) if key[0] == aggregate]
            _need(len(rows) == payload["validated_count"] and owner_module._population_validation_digest(rows).hex().upper() == payload["validation_digest"].upper(), f"{aggregate}: the validation digest of the stored items differs from the event's")
            self._patch("population_imports", (aggregate,), imported_count=payload["validated_count"], validated_count=payload["validated_count"], validation_digest=HEX(payload["validation_digest"]), status="VALIDATED", updated_at_ms=t)
        elif kind == "POPULATION_PUBLISHED":
            self._patch("population_imports", (aggregate,), status="PUBLISHED", updated_at_ms=t)
            period = self.state["control_packs"][(payload["pack_id"],)]["period_id"]
            items = sorted(key for key in self.state["population_items"] if key[0] == aggregate)
            _need(len(items) == payload["item_count"] == after, "published item count differs from its event")
            for key in items:
                item = self.state["population_items"][key]
                obligation_id = FinancialOwner._obligation_id(item["item_id"], period)
                opening = {"claimed_adjustment_cents": 0, "lawful_adjustment_cents": 0, "received_cash_cents": 0, "shortfall_cents": item["owed_cents"], "overage_cents": 0,
                           "cash_satisfied": 0, "amount_satisfied": 0, "timely": 0, "reporting_complete": 0, "verification_status": "MISSING_EVIDENCE", "case_status": "OPEN", "delivery_status": "NONE"}
                self._put("obligations", {
                    "obligation_id": obligation_id, "population_id": aggregate, "item_id": item["item_id"], "period_id": period, "currency": item["currency"],
                    "owed_cents": item["owed_cents"], "due_at_ms": item["due_at_ms"], "rule_version": payload["pack_version"], "revision": 0, **opening,
                    "current_evaluation_id": f"evaluation:{obligation_id}:r0", "updated_at_ms": t})
                self._once("evaluations", (f"evaluation:{obligation_id}:r0",), evaluation_id=f"evaluation:{obligation_id}:r0", obligation_id=obligation_id, revision=0,
                           rule_version=payload["pack_version"], evaluated_at_ms=t, owed_cents=item["owed_cents"], **opening)
                self._agrees(obligation_id)
        elif kind in {"FUNDING_RECEIPT_RECORDED", "FUNDING_RECEIPT_SUPERSEDED"}:
            row = self.images.get(("program_funding_receipts", (aggregate,)))
            _need(row is not None, "a funding receipt has no image in its segment")  # the event holds every column of the row
            receipt = self._once("program_funding_receipts", (aggregate,), **{column: HEX(payload[column]) if column == "receipt_digest" else payload[column] for column in row})
            self._put("program_funding_projection", {"source_record_ref": receipt["source_record_ref"], "receipt_id": aggregate, "amount_cents": receipt["amount_cents"], "event_at_ms": receipt["event_at_ms"], "revision": after, "receipt_digest": receipt["receipt_digest"]})
        elif kind == "INTAKE_RECEIVED":  # a receipt only: the rows of its file are the payment events before it
            _need(event["aggregate_type"] == "INTAKE" and before == after == 0, "INTAKE_RECEIVED: an intake receipt moves no revision")
        elif kind in OBLIGATION_KINDS:
            self._obligation_event(event, payload)
        else:
            _need(False, f"{kind}: no row in section 5.4 (the list of owner events is closed)")

    def _obligation_event(self, event: dict, payload: dict) -> None:
        t, kind, ob, before, after = event["committed_at_ms"], event["kind"], event["aggregate_id"], event["before_revision"], event["after_revision"]
        if kind == "PAYMENT_RECEIVED":
            row = self.images.get(("payments", (payload["payment_id"],)))
            _need(row is not None, "a received payment has no image in its segment")
            _need((row["amount_cents"], row["common_origin_id"], row["evidence_id"], row["obligation_id"]) == (payload["amount_cents"], payload["common_origin_id"], payload["evidence_id"], ob), "payment differs from its event")
            self._put("payments", {**row, "active": 1, "reversed_by_evidence_id": None})
        elif kind == "PAYMENT_REVERSED":
            self._patch("payments", (payload["payment_id"],), active=0, reversed_by_evidence_id=payload["evidence_id"])
        elif kind in {"OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED"}:
            seen = self.state["evaluations"][(self.state["obligations"][(ob,)]["current_evaluation_id"],)]  # the evaluation the official decided on
            self._once("determinations", (payload["determination_id"],), obligation_id=ob, amount_cents=payload["amount_cents"], expected_revision=before, resulting_revision=after,
                       input_evaluation_id=seen["evaluation_id"], input_evaluation_result_digest=seen["result_digest"])
            action = self.images.get(("actions", (payload["action_id"],)))
            _need(action is not None, "an authorized action has no image in its segment")
            self._put("actions", {**action, "action_id": payload["action_id"], "obligation_id": ob, "determination_id": payload["determination_id"],
                                  "status": self.state["action_outbox"][(payload["action_id"],)]["status"]})
        elif kind == "ACTION_ACKNOWLEDGED":
            self._patch("actions", (payload["action_id"],), status=self.state["action_outbox"][(payload["action_id"],)]["status"])
        if "evaluation_id" not in payload:  # a repeat confirmation or a follow-through decision: no money moves
            _need(before == after, f"{kind}: no evaluation, so the revision must not move")
            self._agrees(ob)
        else:
            evaluation = self._once("evaluations", (payload["evaluation_id"],), evaluation_id=payload["evaluation_id"], obligation_id=ob, revision=after, input_snapshot_digest=HEX(payload["evaluation_input_digest"]),
                                    result_digest=HEX(payload["evaluation_result_digest"]), receipt_digest=HEX(payload["evaluation_receipt_digest"]))
            self._patch("obligations", (ob,), revision=after, current_evaluation_id=payload["evaluation_id"], updated_at_ms=t, **{column: evaluation[column] for column in DECIDED})
            self._agrees(ob)

    def _agrees(self, ob: str) -> None:
        """The state between two seals is exactly its evaluation row."""
        row = self.state["obligations"][(ob,)]
        evaluation = self.state["evaluations"][(row["current_evaluation_id"],)]
        mismatch = [column for column in ("owed_cents", *DECIDED) if row[column] != evaluation[column]] + (["revision"] if row["revision"] != evaluation["revision"] else [])
        _need(not mismatch, f"{ob} at revision {row['revision']}: differs from its evaluation row in {mismatch}")
        self.trail.append((self.last_sequence, ob, dict(row)))


def _load(directory: Path) -> list[dict]:
    manifest = json.loads((directory / "manifest.json").read_bytes())
    return [json.loads((directory / f"segment-{index:08d}.json").read_bytes()) for index in range(manifest["segment_count"])]


def fold_export(segments: list[dict]) -> Fold:
    fold = Fold()
    for segment in segments:
        fold.segment(segment)
    fold.kinds = {event["kind"] for segment in segments for event in segment["events"]}
    return fold


class OneStoreFoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = acceptance.RightRailFinancialAcceptanceTests("_build_base")  # its fixtures build the hospital scenario
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def _hospital(self, seal_events: int | None = None) -> list[dict]:
        if seal_events is not None:
            patcher = mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", seal_events)
            patcher.start()
            self.addCleanup(patcher.stop)
        store = self.case._build_base_for_correction()
        self.case._prepare_final(store)
        store.export_history(directory := self.case._path("history"))
        return _load(directory)

    def test_hospital_folds_to_the_sealed_images_in_one_segment(self) -> None:
        segments = self._hospital()
        self.assertEqual(len(segments), 1)
        fold = fold_export(segments)
        self.assertEqual(fold.last_sequence, 40)
        self.assertEqual(len(fold.state["obligations"]), 20)

    def test_hospital_folds_at_every_seal_when_sealed_often(self) -> None:
        segments = self._hospital(seal_events=8)
        self.assertGreaterEqual(len(segments), 5)
        self.assertEqual(fold_export(segments).last_sequence, 40)

    def test_several_events_for_one_obligation_inside_one_segment(self) -> None:
        authority = SyntheticTrustedAuthority()
        config = FinancialOwnerConfig(**_SCOPE)
        directory = Path(tempfile.mkdtemp(prefix="one-store-fold-", dir=self.case.temp_dir.name))
        owner = FinancialOwner(path=directory / "owner.sqlite3", config=config, trusted_authority=authority)
        self.addCleanup(owner.close)
        item = _setup(owner, random.Random(1), 2, authority)[0].item_id
        for index in range(3):
            owner.record_payment_evidence(item_id=item, payment_id=f"payment:{index}", common_origin_id=f"origin:{index}", amount_cents=100 + index, evidence_id=f"evidence:payment:{index}", event_at_ms=1_000 + index)
            owner.record_support_evidence(item_id=item, evidence_id=f"evidence:support:{index}", common_origin_id=f"origin:support:{index}")
            owner.evaluate_obligation(item)
        owner.export_history(history := directory / "history")
        segments = _load(history)
        self.assertEqual(len(segments), 1)
        fold = fold_export(segments)
        mine = [row for _sequence, ob, row in fold.trail if row["item_id"] == item and row["revision"] > 0]
        self.assertGreaterEqual(len({row["revision"] for row in mine}), 6)  # every step is its own state, not one end image
        self.assertTrue(any(row["received_cash_cents"] for row in mine))

    def test_a_column_that_changes_without_an_event_fails_the_fold(self) -> None:
        segments = self._hospital()
        fold_export(copy.deepcopy(segments))  # the untouched export folds
        exports = [segments, *self._journeys()]
        for exported in exports:
            fold_export(copy.deepcopy(exported))
        differs = "differs from the sealed image in.*"
        changes = (("obligations", "updated_at_ms"), ("obligations", "reporting_complete"), ("obligations", "revision"), ("cases", "updated_at_ms"), ("payments", "active"), ("actions", "status"),
                   ("action_outbox", "attempt"), ("claimed_adjustments", "status"), ("population_imports", "status"), ("population_manifest_heads", "updated_at_ms"), ("evaluations", "shortfall_cents"),
                   # columns the fold takes from an event's payload or computes from earlier rows
                   ("control_packs", "version"), ("control_packs", "pack_digest"), ("population_manifests", "member_count"), ("population_manifests", "manifest_digest"),
                   ("population_manifest_bindings", "manifest_id"), ("population_imports", "expected_count"), ("population_items", "currency"), ("determinations", "amount_cents"),
                   ("determinations", "input_evaluation_id"), ("program_funding_receipts", "amount_cents"), ("program_funding_receipts", "receipt_digest"), ("evaluations", "result_digest"))
        for table, column in changes:
            self._breaks(exports, table, column, differs + column)
        self._breaks(exports, "payments", "amount_cents", "payment differs")
        self._breaks(exports, "population_items", "owed_cents", "validation digest")  # copied from the image, bound by the population's validation digest
        self._breaks(exports, "population_items", "display_label", "validation digest")
        self._breaks(exports, "population_manifest_members", "member_id", "member digest")
        extra = copy.deepcopy(segments)
        payment = next(record for record in extra[0]["rows"] if record["table"] == "payments")
        extra[0]["rows"].append({"table": "payments", "row": {**payment["row"], "payment_id": "payment:no-event"}})
        with self.assertRaisesRegex(FoldMismatch, "no event explains"):
            fold_export(extra)

    def _breaks(self, exports: list[list[dict]], table: str, column: str, message: str) -> None:
        """Change one column of one sealed image, in the first export that holds the table, and require the fold to fail with the message."""
        with self.subTest(table=table, column=column):
            for exported in exports:
                broken = copy.deepcopy(exported)
                records = [record for segment in broken for record in segment["rows"] if record["table"] == table and (table != "evaluations" or record["row"]["revision"] == (0 if column == "shortfall_cents" else 1))]
                if records:
                    break
            else:
                self.fail(f"no export holds a {table} row to change")
            row = records[0]["row"]
            value = row[column]
            row[column] = {"hex": value["hex"][:-1] + ("0" if value["hex"][-1] != "1" else "2")} if isinstance(value, dict) else (value ^ 1) if isinstance(value, int) else str(value) + "x"
            with self.assertRaisesRegex(FoldMismatch, message):
                fold_export(broken)

    def test_an_unknown_event_kind_stops_the_fold_and_names_the_kind(self) -> None:
        fold = Fold()
        fold.images, fold.touched = {}, set()
        event = {"event_sequence": 1, "aggregate_type": "OBLIGATION", "aggregate_id": "x", "kind": "INVENTED_KIND", "before_revision": 0, "after_revision": 0, "committed_at_ms": 1, "payload_json": "{}"}
        with self.assertRaisesRegex(FoldMismatch, "INVENTED_KIND"):
            fold.event(event)

    def _journeys(self) -> list[list[dict]]:
        """Exports, sealed every few events, that between them write every event kind: the full journey, one that authorizes the offset, and one that supersedes a manifest."""
        patcher = mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", 5)
        patcher.start()
        self.addCleanup(patcher.stop)
        case = self.case
        store = case._build_base_for_correction()
        case._prepare_final(store)  # the journey: payments, conflict, reversal, claim, correction, acknowledgment, reports
        case._advance_clock(store, expected.P3_REPLACEMENT_EVIDENCE.event_at_ms + 1_000)
        first = case._funding_receipt()
        store.record_program_funding_receipt(first)
        store.record_program_funding_receipt(case._funding_receipt(receipt_id="funding-receipt:v2", amount_cents=first.amount_cents - 1, event_at_ms=first.event_at_ms + 1, supersedes_receipt_id=first.receipt_id))
        store.evaluate_obligation("item-01")
        store.record_followthrough_decision(item_id="item-02", decision_id="decision:assign", act="ASSIGN", owner_id="party:finance", actor_id="synthetic-official", actor_role="CASE_OWNER", expected_revision=store.obligation_detail("item-02")["revision"])
        self._absorb_cash_file(store)
        journey = _load(self._export(store))
        authorized, claim_id, _receipt = case._claimed_store()  # a second store, which authorizes the offset instead of rejecting it
        case._authorize(authorized, claim_id)
        offset = _load(self._export(authorized))
        early = case._make_owner()  # a manifest can be superseded only before its population is published
        early.publish_control_pack(case._pack(expected.CONTROL_PACK_V1))
        root = case._population_manifest()
        early.register_population_manifest(root)
        early.register_population_manifest(case._population_manifest(manifest_id="population-manifest:fixture-2026-01:v2", supersedes=root))
        return [journey, offset, _load(self._export(early))]

    def test_every_event_kind_the_owner_can_write_folds_at_every_seal(self) -> None:
        self.assertEqual(len(ALL_KINDS), 24)
        exports = self._journeys()
        folds = [fold_export(exported) for exported in exports]
        covered = frozenset().union(*(fold.kinds for fold in folds))
        self.assertEqual(covered, ALL_KINDS, sorted(ALL_KINDS - covered))
        self.assertGreaterEqual(len(exports[0]), 8)  # sealed every five events, so the journey crosses many seals
        self.assertTrue(all(len(exported) >= 2 for exported in exports[:2]))

    def _export(self, store: FinancialOwner) -> Path:
        store.export_history(directory := Path(tempfile.mkdtemp(dir=self.case.temp_dir.name)) / "history")
        return directory

    def _absorb_cash_file(self, store: FinancialOwner) -> None:
        """A receiver file with one clean row and one unreadable amount: the clean row pays, the other is held, one INTAKE receipt follows."""
        scope = json.loads(store.export_continuity())["scope"]
        source = {"source_id": "fictional-receiver", "version": "v1", "receiver_system_id": "receiver-1", "capture_id": "capture-1", "captured_at_ms": expected.CASH_EVENT_MS}
        row = lambda number, amount, revision, item: {"item_id": item, "payment_id": f"file-payment-{number}", "common_origin_id": f"file-origin-{number}", "evidence_id": f"file-evidence-{number}",
                                                       "amount_cents": amount, "event_at_ms": expected.CASH_EVENT_MS, "pays_action_id": None, "expected_revision": revision}
        rows = [row(0, 100, store.obligation_detail("item-03")["revision"], "item-03"), row(1, "1.000,00", store.obligation_detail("item-04")["revision"], "item-04")]
        raw = encode({"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1", "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": scope, "source": source, "row_count": 2, "total_cents": 100_100, "rows": rows})
        baseline = store.export_history(Path(tempfile.mkdtemp(dir=self.case.temp_dir.name)) / "baseline")
        sha = lambda data: hashlib.sha256(data).hexdigest().upper()
        receipt = intake.ingest_cash_file(store, raw, baseline, expected_source_sha256=sha(raw), expected_baseline_sha256=sha(baseline), expected_scope=scope, expected_source=source,
                                          expected_owner_id=store.owner_id, expected_mode=store.mode, trusted_authority=self.case.authority)
        self.assertEqual(receipt["held"], 1)


if __name__ == "__main__":
    unittest.main()
