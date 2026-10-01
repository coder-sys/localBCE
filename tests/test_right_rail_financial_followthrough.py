"""Proof obligations for the read-only follow-through pack (docs/CORE_REDESIGN.md "Follow-through pack").

The "R" store is built with public Owner commands only; every build verifies it read-only.
"""

from __future__ import annotations

from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_owner_independent as independent
from app.right_rail_financial_derived import NOT_HELD, DerivedError
from app.right_rail_financial_followthrough import MAX_RULES_BYTES, _add, _cms64_due, build_followthrough_pack
from app.right_rail_financial_owner import (
    ControlPack, FinancialAuthorityError, FinancialConflictError, FinancialInputError, FinancialIntegrityError, FinancialOwner,
    FinancialOwnerConfig, FinancialRevisionError, PopulationItem, PopulationManifest, SyntheticTrustedAuthority,
)
from tests import test_right_rail_financial_acceptance as acceptance
from tests.test_right_rail_financial_line_pack import _Clock
from tools import right_rail_financial_cli as financial_cli

RULES = (Path(__file__).resolve().parent / "fixtures" / "followthrough_rules_recovery_v1.json").read_bytes()
SCOPE = {"state_id": "state:synthetic-recovery", "deployment_id": "deployment:synthetic-recovery", "program_id": "program:synthetic-ffs-recovery", "period_id": "period:ffy2027q2"}
DAY = 86_400_000
NOTICE = 1_799_971_200_000  # 2027-01-15
PAID_R1 = 1_803_859_200_000  # 2027-03-01
CREDIT_R1 = 1_808_179_200_000  # 2027-04-20
RECOVERY_DUE = 1_805_155_200_000  # 2027-03-16
FEDERAL_ENDS = 1_831_507_200_000  # 2028-01-15
COLLECTED_DUE = 1_809_129_600_000  # 2027-05-01
FEDERAL_DUE = 1_840_752_000_000  # 2028-05-01
GENERATED = 1_843_430_400_000  # 2028-06-01
DAY_MS = lambda year, month, day: int(datetime(year, month, day, tzinfo=timezone.utc).timestamp()) * 1000
DIGEST_HEX = lambda blob: bytes(blob).hex().upper()


def _encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def _mutated(mutate, rules: bytes = RULES) -> bytes:
    value = json.loads(rules)
    mutate(value)
    return _encode(value)


def _ref(rules: bytes) -> str:
    return "followthrough-rules:sha256:" + hashlib.sha256(rules).hexdigest().upper()


def _build_r_store(directory: Path, rules_bytes: bytes, *, extra_refs: tuple[str, ...] = (), paid: tuple[int, int] = (PAID_R1, PAID_R1), credit: int | None = CREDIT_R1,
                   roles: tuple[str, ...] = ("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER", "CASE_OWNER")) -> FinancialOwner:
    authority = SyntheticTrustedAuthority()
    owner = FinancialOwner(path=directory / "recovery.sqlite3", config=FinancialOwnerConfig(**SCOPE), trusted_authority=authority, clock=_Clock())
    owner.publish_control_pack(ControlPack(
        pack_id="pack:recovery-v1", **SCOPE, version=1, source_refs=("synthetic:source:v1", _ref(rules_bytes), *extra_refs),
        effective_start_ms=1_000, effective_end_ms=4_000_000_000_000, recorded_at_ms=500, approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=roles,
        expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"),
    ))
    owed = {"item-r1": 1_000_000, "item-r2": 500_000, "item-r3": 300_000}
    items = tuple(PopulationItem(population_id="population:recovery-v1", item_id=item, display_label=f"synthetic-{item}", owed_cents=cents, due_at_ms=RECOVERY_DUE) for item, cents in owed.items())
    owner.register_population_manifest(PopulationManifest(
        manifest_id="manifest:recovery-v1", manifest_version=1, **SCOPE, pack_id="pack:recovery-v1", cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",), source_owner_id="rac-contractor-1", authority_id=authority.authority_id,
        authority_epoch=authority.epoch, authority_digest=authority.digest, approved_by="synthetic-official",
        approval_ref="ref:recovery-findings-v1", source_id="source:rac-findings-v1", source_version="v1",
        source_digest=hashlib.sha3_512(b"recovery-v1").digest(), member_ids=tuple(owed),
    ))
    owner.stage_population(population_id="population:recovery-v1", manifest_id="manifest:recovery-v1", pack_id="pack:recovery-v1", cutoff_ms=1_000, inclusion_rules=("included:synthetic",), expected_count=3, items=items, chunk_size=3)
    owner.validate_population("population:recovery-v1")
    owner.publish_population("population:recovery-v1")
    for name in ("r1", "r2"):
        _support(owner, name, f"evidence:notice:{name}", "state-demand-letters", NOTICE, NOTICE)
    owner.clock.value = paid[1]  # paid[0] is the collection date, paid[1] the day it was recorded
    owner.record_payment_evidence(item_id="item-r1", payment_id="payment:r1", common_origin_id="origin:r1", amount_cents=1_000_000, evidence_id="evidence:payment:r1", event_at_ms=paid[0], source_id="state-collections")
    if credit is not None:
        _support(owner, "r1", "evidence:credit:r1", "state-cms64", credit, credit, local_ref="cms64:FFY2027Q2:64.9C1:9C")
    return owner


def _support(owner: FinancialOwner, name: str, evidence_id: str, source_id: str, recorded_at_ms: int, event_at_ms: int, **more: object) -> None:
    owner.clock.value = recorded_at_ms
    owner.record_support_evidence(item_id=f"item-{name}", evidence_id=evidence_id, common_origin_id=evidence_id.replace("evidence:", "", 1), source_id=source_id, applicable_at_ms=event_at_ms, event_at_ms=event_at_ms, **more)


class FollowthroughTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="rr-followthrough-")
        cls.owner = _build_r_store(Path(cls.tmp.name), RULES)
        cls.db, cls.package = cls.owner.path, cls.owner.export_continuity()
        cls.trust = {"trusted_authority": cls.owner.trusted_authority, "expected_scope": {**SCOPE, "currency": "USD"}}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.owner.close()
        cls.tmp.cleanup()

    def _raw(self, at_ms: int = GENERATED, **changes: object) -> bytes:
        return build_followthrough_pack(**{"database": self.db, "package_bytes": self.package, "rules_bytes": RULES, "generated_at_ms": at_ms, **self.trust, **changes})

    def _items(self, *args: object, **changes: object) -> dict[str, dict]:
        return {item["item_id"]: item for item in json.loads(self._raw(*args, **changes))["items"]}

    def _sql(self, query: str, parameters: tuple = ()) -> list[tuple]:
        with closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as connection:
            return connection.execute(query, parameters).fetchall()

    def _one(self, query: str, *parameters: object) -> object:
        ((value,),) = self._sql(query, parameters)
        return value

    def _refused(self, code: str, **changes: object) -> None:
        with self.assertRaises(DerivedError) as caught:
            self._raw(**changes)
        self.assertEqual(str(caught.exception), code)

    def test_r1_chain_found_owned_satisfied_credited(self) -> None:
        item = self._items()["item-r1"]
        self.assertEqual(item["found"], {"source_owner_id": "rac-contractor-1", "source_id": "source:rac-findings-v1", "party": "CONTRACTOR", "kind": "SYSTEM", "manifest_id": "manifest:recovery-v1", "registered_at_ms": 1000, "approved_by": "synthetic-official", "approval_ref": "ref:recovery-findings-v1"})
        self.assertEqual(item["owner"], {"owner_id": "state-recovery-unit", "basis": "RULES_DEFAULT", "decision_id": None})
        self.assertEqual((item["status"], item["principal_cents"], item["open_cents"]), ("SATISFIED", 1_000_000, 0))
        digest = lambda evidence_id: DIGEST_HEX(self._one("SELECT record_digest FROM evidence WHERE evidence_id=?", evidence_id))
        satisfied = self._one("SELECT evaluation_id FROM evaluations WHERE obligation_id=? AND amount_satisfied=1 ORDER BY revision LIMIT 1", item["obligation_id"])
        citations = {clock["clock_id"]: clock["citation"] for clock in json.loads(RULES)["clocks"]}
        self.assertEqual(item["clocks"], [
            {"clock_id": "federal-share-credit", "citation": citations["federal-share-credit"],
             "anchor": {"source": "EVIDENCE:DISCOVERY_NOTICE", "at_ms": NOTICE, "recorded_at_ms": NOTICE, "evidence_id": "evidence:notice:r1", "evidence_record_digest": digest("evidence:notice:r1"), "event_sequence": None},
             "ends_ms": FEDERAL_ENDS, "due_ms": COLLECTED_DUE, "report": {"quarter": "FFY2027Q2", "form": "64.9C1", "line": None, "summary_line": "9C"},
             "satisfied": {"source": "EVIDENCE:FEDERAL_SHARE_CREDIT", "at_ms": CREDIT_R1, "evidence_id": "evidence:credit:r1", "evidence_record_digest": digest("evidence:credit:r1"), "evaluation_id": None},
             "stopped_by": None, "status": "MET"},
            {"clock_id": "recovery-action", "citation": citations["recovery-action"],
             "anchor": {"source": "EVIDENCE:DISCOVERY_NOTICE", "at_ms": NOTICE, "recorded_at_ms": NOTICE, "evidence_id": "evidence:notice:r1", "evidence_record_digest": digest("evidence:notice:r1"), "event_sequence": None},
             "ends_ms": RECOVERY_DUE, "due_ms": RECOVERY_DUE, "report": None,
             "satisfied": {"source": "SATISFIED", "at_ms": PAID_R1, "evidence_id": None, "evidence_record_digest": None, "evaluation_id": satisfied},
             "stopped_by": None, "status": "MET"},
        ])
        self.assertEqual((item["federal_share"], item["decisions"]), ({"period_id": "period:ffy2027q2", "basis_points": 5000, "cents": 500_000}, []))

    def test_r2_unrecovered_federal_share_still_due_and_missed(self) -> None:
        item = self._items()["item-r2"]
        federal, recovery = item["clocks"]
        self.assertEqual((item["status"], item["open_cents"], item["federal_share"]["cents"]), ("OPEN", 500_000, 250_000))
        self.assertEqual((federal["status"], federal["ends_ms"], federal["due_ms"], federal["satisfied"]), ("MISSED", FEDERAL_ENDS, FEDERAL_DUE, None))
        self.assertEqual(federal["report"], {"quarter": "FFY2028Q2", "form": "64.9O", "line": "1", "summary_line": "10C"})
        self.assertEqual(recovery["status"], "MISSED")
        early = self._items(1_840_665_600_000)["item-r2"]["clocks"]  # 2028-04-30
        self.assertEqual([clock["status"] for clock in early], ["RUNNING", "MISSED"])

    def test_r3_without_discovery_record_is_never_shown_as_safe(self) -> None:
        item = self._items()["item-r3"]
        self.assertEqual((item["status"], item["open_cents"], item["federal_share"]["cents"]), ("OPEN", 300_000, 150_000))
        for clock in item["clocks"]:
            self.assertEqual({key: clock[key] for key in ("anchor", "ends_ms", "report", "due_ms", "satisfied", "stopped_by")}, dict.fromkeys(("anchor", "ends_ms", "report", "due_ms", "satisfied", "stopped_by")))
            self.assertEqual(clock["status"], "NOT_ANCHORED")

    def test_anchor_is_the_earliest_listed_fact_and_backdating_is_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-ack-") as tmp, _build_r_store(Path(tmp), RULES) as owner:
            _support(owner, "r2", "evidence:ack:r2", "state-mailroom", 1_808_611_200_000, 1_799_539_200_000)  # recorded 2027-04-25, dated 2027-01-10
            raw = build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=RULES, generated_at_ms=GENERATED, **self.trust)
        federal, recovery = next(item["clocks"] for item in json.loads(raw)["items"] if item["item_id"] == "item-r2")
        self.assertEqual({key: federal["anchor"][key] for key in ("source", "at_ms", "recorded_at_ms", "evidence_id")}, {"source": "EVIDENCE:PROVIDER_ACKNOWLEDGMENT", "at_ms": 1_799_539_200_000, "recorded_at_ms": 1_808_611_200_000, "evidence_id": "evidence:ack:r2"})
        self.assertEqual((federal["ends_ms"], federal["report"]["quarter"], federal["report"]["form"], federal["due_ms"]), (1_831_075_200_000, "FFY2028Q2", "64.9O", FEDERAL_DUE))
        self.assertEqual((recovery["anchor"]["source"], recovery["anchor"]["at_ms"]), ("EVIDENCE:DISCOVERY_NOTICE", NOTICE))

    def test_rules_must_be_listed_by_exactly_one_approved_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-refs-") as tmp:
            for name, rules, extra, code in (
                ("unlisted", b"not the rules", (), "not-in-approved-control-pack"),
                ("twice", RULES, ("followthrough-rules:sha256:" + "0" * 64,), "ref-not-unique"),
            ):
                (Path(tmp) / name).mkdir()
                with self.subTest(name), _build_r_store(Path(tmp) / name, rules, extra_refs=extra) as owner:
                    package = owner.export_continuity()
                    with self.assertRaises(DerivedError) as caught:
                        build_followthrough_pack(owner.path, package, rules_bytes=RULES, generated_at_ms=GENERATED, **self.trust)
                    self.assertEqual(str(caught.exception), f"followthrough:followthrough-rules-{code}")
                    self.assertEqual(owner.export_continuity(), package)  # history unchanged
        for name, rules in (("one byte in a citation", RULES.replace(b"discovery;", b"Discovery;", 1)), ("pack_version 2", _mutated(lambda value: value.update(pack_version=2)))):
            with self.subTest(name):
                self._refused("followthrough:followthrough-rules-not-in-approved-control-pack", rules_bytes=rules)
        self.assertEqual(self.owner.export_continuity(), self.package)

    def test_rules_validation_refuses_malformed(self) -> None:
        clock = lambda value: value["clocks"][0]
        for name, mutate, code in (
            ("extra key", lambda v: v.update(extra=1), "rules-fields"),
            ("contract", lambda v: v.update(contract="RR/FOLLOWTHROUGH/RULES/v2"), "rules-contract"),
            ("state", lambda v: v.update(state_id="state:other"), "rules-state"),
            ("party order", lambda v: v["parties"].reverse(), "rules-party"),
            ("party type", lambda v: v["parties"][0].update(party="PROVIDER"), "rules-party"),
            ("party id", lambda v: v["parties"][0].update(party_id="bad id"), "switch:rules-party"),
            ("model owner", lambda v: v.update(default_owner_id="triage-model-1"), "rules-owner"),
            ("unknown owner", lambda v: v.update(default_owner_id="nobody"), "rules-owner"),
            ("event anchor", lambda v: clock(v).update(anchors=["EVENT:PAYMENT_RECEIVED"]), "rules-anchor"),
            ("undeclared purpose", lambda v: clock(v).update(anchors=["EVIDENCE:UNDECLARED"]), "rules-purpose-undeclared"),
            ("unit", lambda v: clock(v)["add"].update(unit="MONTH"), "rules-clock"),
            ("count", lambda v: clock(v)["add"].update(count=0), "rules-clock"),
            ("summary line", lambda v: clock(v)["report"]["collected"].update(summary_line="9c"), "rules-clock"),
            ("one party starts and satisfies", lambda v: v["parties"][3].update(purposes=["DISCOVERY_NOTICE", "FEDERAL_SHARE_CREDIT"]), "rules-party-both-ends"),
            ("stops", lambda v: v["closure_reasons"][0].update(stops=["no-such-clock"]), "rules-stops"),
            ("reason code", lambda v: v["closure_reasons"][0].update(reason_code="bankrupt"), "rules-reason"),
            ("basis points", lambda v: v["fmap_basis_points"][0].update(basis_points=10_001), "rules-fmap"),
        ):
            with self.subTest(name):
                self._refused(f"followthrough:{code}", rules_bytes=_mutated(mutate))
        self._refused("followthrough:followthrough-rules:canonical", rules_bytes=RULES.replace(b'"contract":', b'"contract": ', 1))

    def test_fmap_period_missing_is_a_declared_gap(self) -> None:
        rules = _mutated(lambda value: value.update(fmap_basis_points=[{"basis_points": 5000, "period_id": "period:ffy2027q3"}]))
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-fmap-") as tmp, _build_r_store(Path(tmp), rules) as owner:
            pack = json.loads(build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=rules, generated_at_ms=GENERATED, **self.trust))
        self.assertEqual([item["federal_share"] for item in pack["items"]], [None] * 3)
        self.assertIn("gap:fmap-period-missing:period:ffy2027q2", pack["unavailable"])

    def test_quarter_end_boundary_counts_the_last_millisecond(self) -> None:
        year = {"count": 1, "unit": "YEAR"}
        self.assertEqual(_add(1_806_537_600_000, year), 1_838_160_000_000)
        self.assertEqual(_cms64_due(1_838_160_000_000, None, 30), ("FFY2028Q2", 1_840_752_000_000, False))
        self.assertEqual(_cms64_due(1_838_160_000_001, None, 30), ("FFY2028Q3", 1_848_614_400_000, False))
        self.assertEqual(_cms64_due(1_838_160_000_000, 1_806_537_599_999, 30), ("FFY2027Q2", 1_809_129_600_000, True))
        self.assertEqual(_cms64_due(1_838_160_000_000, 1_838_160_000_000, 30), ("FFY2028Q2", 1_840_752_000_000, False))

    def test_leap_day_anchor_clamps_to_month_end(self) -> None:
        self.assertEqual(_add(1_835_395_200_000, {"count": 1, "unit": "YEAR"}), 1_866_931_200_000)  # 2028-02-29 to 2029-02-28
        self.assertEqual(_add(1_835_395_200_000, {"count": 4, "unit": "YEAR"}), 1_961_625_600_000)  # 2032-02-29
        self.assertEqual(_add(NOTICE, {"count": 60, "unit": "DAY"}), RECOVERY_DUE)

    def test_recovery_date_is_the_collection_date_not_the_recording_date(self) -> None:
        # (name, (collected, recorded), credit filed, generated, federal quarter/due/status, recovery-action collected-at/status)
        for name, paid, credit, generated, federal, action in (
            ("credit filed after the collection quarter's due date", (DAY_MS(2027, 3, 30), DAY_MS(2027, 4, 2)), DAY_MS(2027, 5, 15), GENERATED, ("FFY2027Q2", "64.9C1", COLLECTED_DUE, "MET_LATE"), (DAY_MS(2027, 3, 30), "MET_LATE")),
            ("collected, no credit, due date passed", (DAY_MS(2027, 3, 30), DAY_MS(2027, 4, 2)), None, DAY_MS(2027, 6, 1), ("FFY2027Q2", "64.9C1", COLLECTED_DUE, "MISSED"), (DAY_MS(2027, 3, 30), "MET_LATE")),
            ("collected before the year end, recorded after it", (DAY_MS(2028, 1, 10), DAY_MS(2028, 1, 20)), None, GENERATED, ("FFY2028Q2", "64.9C1", FEDERAL_DUE, "MISSED"), (DAY_MS(2028, 1, 10), "MET_LATE")),
            ("collected on time, recorded late", (DAY_MS(2027, 3, 10), DAY_MS(2027, 3, 20)), CREDIT_R1, GENERATED, ("FFY2027Q2", "64.9C1", COLLECTED_DUE, "MET"), (DAY_MS(2027, 3, 10), "MET")),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory(prefix="rr-followthrough-lag-") as tmp, _build_r_store(Path(tmp), RULES, paid=paid, credit=credit) as owner:
                item = next(i for i in json.loads(build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=RULES, generated_at_ms=generated, **self.trust))["items"] if i["item_id"] == "item-r1")
                credit_clock, action_clock = item["clocks"]
                self.assertEqual((credit_clock["report"]["quarter"], credit_clock["report"]["form"], credit_clock["due_ms"], credit_clock["status"]), federal)
                self.assertEqual((action_clock["satisfied"]["at_ms"], action_clock["status"]), action)

    def test_finder_not_typed_is_a_declared_gap(self) -> None:
        rules = _mutated(lambda value: value.update(parties=[party for party in value["parties"] if party["party_id"] != "rac-contractor-1"]))
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-finder-") as tmp, _build_r_store(Path(tmp), rules) as owner:
            pack = json.loads(build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=rules, generated_at_ms=GENERATED, **self.trust))
        self.assertEqual({(item["found"]["party"], item["found"]["kind"]) for item in pack["items"]}, {(None, None)})
        self.assertIn("gap:finder-not-typed:rac-contractor-1", pack["unavailable"])

    def test_a_clock_date_past_year_9999_is_refused_with_the_module_code(self) -> None:
        for unit in ("YEAR", "DAY"):
            with self.subTest(unit), self.assertRaisesRegex(DerivedError, "^clock-date-range$"):
                _add(DAY_MS(9999, 12, 1), {"count": 1 if unit == "YEAR" else 60, "unit": unit})
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-far-") as tmp, _build_r_store(Path(tmp), RULES) as owner:
            _support(owner, "r3", "evidence:notice:r3", "state-demand-letters", DAY_MS(9999, 12, 1), DAY_MS(9999, 12, 1))
            with self.assertRaisesRegex(DerivedError, "^followthrough:clock-date-range$"):
                build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=RULES, generated_at_ms=DAY_MS(9999, 12, 1), **self.trust)

    def test_pack_is_deterministic_and_documentation_only(self) -> None:
        raw = self._raw()
        self.assertEqual(self._raw(), raw)
        pack = json.loads(raw)
        self.assertEqual((pack["contract"], pack["documentation_only"], pack["claims"], pack["signer"], pack["comparison"]), ("RR/FOLLOWTHROUGH/PACK/v1", True, {"proofSuiteId": None, "production_usable": False, "activation": False}, None, None))
        self.assertEqual(pack["unavailable"], sorted(NOT_HELD))
        self._refused("followthrough:generated-before-package", at_ms=CREDIT_R1 - 1)
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-stale-") as tmp, _build_r_store(Path(tmp), RULES) as owner:
            early = owner.export_continuity()
            _support(owner, "r2", "evidence:ack:r2", "state-mailroom", 1_808_611_200_000, 1_799_539_200_000)
            with self.assertRaisesRegex(DerivedError, "^followthrough:"):  # a package older than the database is the checker's refusal
                build_followthrough_pack(owner.path, early, rules_bytes=RULES, generated_at_ms=GENERATED, **self.trust)

    def test_cli_writes_followthrough_pack_and_never_replaces(self) -> None:
        directory = Path(self.tmp.name)
        (directory / "authority.json").write_bytes(json.dumps(financial_cli.authority_file_record(self.trust["trusted_authority"])).encode("ascii"))
        (directory / "package.bin").write_bytes(self.package)
        (directory / "rules.json").write_bytes(RULES)
        output = directory / "followthrough.json"
        args = ["--database", str(self.db), "--authority-file", str(directory / "authority.json"), *[f"--{key.replace('_', '-')}={value}" for key, value in SCOPE.items()],
                "followthrough-pack", "--package", str(directory / "package.bin"), "--rules", str(directory / "rules.json"), "--generated-at-ms", str(GENERATED), "--output", str(output)]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(financial_cli.main(args), 0)
        self.assertEqual(output.read_bytes(), self._raw())
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(financial_cli.main(args), 2)  # the output file exists: never replaced
        self.assertEqual(output.read_bytes(), self._raw())
        for name, contents, code in (("absent.json", None, "followthrough_rules_missing"), ("big.json", b"x" * (MAX_RULES_BYTES + 1), "followthrough_rules_size")):
            if contents is not None:
                (directory / name).write_bytes(contents)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as refusal:
                self.assertEqual(financial_cli.main([*args[:-5], str(directory / name), *args[-4:]]), 2)
            self.assertEqual(refusal.getvalue(), f"ERROR:{code}\n")


EVIDENCE_AT = 1_811_635_200_000  # 2027-05-30
SUGGESTED_AT = 1_811_721_600_000  # 2027-05-31
CLOSE_AT = 1_811_808_000_000  # 2027-06-01
ASSIGN_AT = 1_811_894_400_000  # 2027-06-02
CLOSE = "decision:r2:close"
OFFICIAL = {"actor_id": "synthetic-official", "actor_role": "CASE_OWNER"}
SUGGESTION = {"source_id": "triage-model-1", "source_ref": "triage:r2:1", "source_sha256": hashlib.sha256(b"synthetic triage note r2").hexdigest().upper(),
              "suggested_at_ms": SUGGESTED_AT, "act": "CLOSE", "reason_code": "UNCOLLECTIBLE_OTHER", "owner_id": None}
TRUST = lambda store: {"trusted_authority": store.trusted_authority, "expected_scope": {**SCOPE, "currency": "USD"}}


def _legal(store: FinancialOwner, *tags: str, at_ms: int = EVIDENCE_AT) -> None:
    for tag in tags:
        _support(store, "r2", f"evidence:{tag}:r2", "state-legal-office", at_ms, at_ms)


def _decide(store: FinancialOwner, at_ms: int = CLOSE_AT, **changes: object) -> dict:
    """One decision as the official; the revision defaults to the item's current one."""
    call = {"item_id": "item-r2", "decision_id": CLOSE, "act": "CLOSE", "reason_code": "BANKRUPTCY", **OFFICIAL, **changes}
    call.setdefault("expected_revision", store.obligation_detail(call["item_id"])["revision"])
    store.clock.value = at_ms
    return store.record_followthrough_decision(**call)


def _decided_store(directory: Path, **changes: object) -> FinancialOwner:
    """The R store after the three legal-office records and the official's BANKRUPTCY close, with a model's suggestion beside it."""
    store = _build_r_store(directory, RULES, **changes)
    _legal(store, "petition", "creditor", "effort")
    _decide(store, suggestion=SUGGESTION)
    return store


def _pack(store: FinancialOwner, at_ms: int = GENERATED) -> dict:
    return json.loads(build_followthrough_pack(store.path, store.export_continuity(), rules_bytes=RULES, generated_at_ms=at_ms, **TRUST(store)))


def _history(store: FinancialOwner) -> tuple[int, bytes]:
    with closing(sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)) as connection:
        return connection.execute("SELECT count(*),(SELECT head FROM financial_events ORDER BY event_sequence DESC LIMIT 1) FROM financial_events").fetchone()


def _forge_payload(edit) -> object:
    def apply(path: Path) -> None:
        def only_the_decision(payload: dict) -> bool:
            if payload.get("decision_id") != CLOSE:
                return False
            edit(payload)
            return True
        assert acceptance.RightRailFinancialAcceptanceTests._rehash_history(path, only_the_decision) == 1
    return apply


def _forge_rows(*statements: str, rehash: bool = False) -> object:
    """As a writer with file access: drop the append-only triggers, change rows, restore them, and re-hash the chain if asked."""
    def apply(path: Path) -> None:
        with closing(sqlite3.connect(str(path), isolation_level=None)) as connection:
            triggers = connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'").fetchall()
            for name, _sql in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            for statement in statements:
                connection.execute(statement)
            for _name, sql in triggers:
                connection.execute(sql)
        if rehash:
            acceptance.RightRailFinancialAcceptanceTests._rehash_history(path, lambda payload: False)
    return apply


# (name, forgery of a copy of the decided store, the code verify_database raises, the code verify_followthrough_connection raises)
FORGERIES = (
    ("role", _forge_payload(lambda p: p.update(actor_role="REPORTING_EDITOR")), "followthrough:actor", "followthrough:actor"),
    ("revision", _forge_rows("UPDATE financial_events SET after_revision=after_revision+1 WHERE kind='FOLLOWTHROUGH_DECIDED'", rehash=True), "followthrough:revision", "followthrough:revision"),
    ("authority", _forge_payload(lambda p: p.update(authority_epoch=2)), "followthrough:authority", "followthrough:authority"),
    ("suggestion time", _forge_payload(lambda p: p["suggestion"].update(suggested_at_ms=CLOSE_AT + 1)), "followthrough:suggestion", "followthrough:suggestion"),
    ("extra key", _forge_payload(lambda p: p.update(rows=[])), "followthrough:payload", "followthrough:payload"),
    ("other item", _forge_payload(lambda p: p.update(item_id="item-r3")), "followthrough:payload", "followthrough:payload"),
    ("command row deleted", _forge_rows(f"DELETE FROM commands WHERE command_id='FOLLOWTHROUGH_DECISION:{CLOSE}'"), "commands:mismatch", "followthrough:command"),
)


class FollowthroughDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rr-followthrough-decision-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def _store(self, name: str = "store", **changes: object) -> FinancialOwner:
        (self.directory / name).mkdir()
        return self._closing(_decided_store(self.directory / name, **changes))

    def _closing(self, store: FinancialOwner) -> FinancialOwner:
        self.addCleanup(store.close)  # R1a: the owner's writer holds the file open until closed
        return store

    def _r2(self, store: FinancialOwner, at_ms: int = GENERATED) -> dict:
        return next(item for item in _pack(store, at_ms)["items"] if item["item_id"] == "item-r2")

    def _refused(self, store: FinancialOwner, error: type, code: str, **changes: object) -> None:
        before = _history(store)
        with self.assertRaisesRegex(error, f"^{code}$"):
            _decide(store, **changes)
        self.assertEqual(_history(store), before)

    def test_decision_records_suggestion_and_decision_side_by_side(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        _legal(store, "petition", "creditor", "effort")
        before = store.obligation_detail("item-r2")
        result = _decide(store, suggestion=SUGGESTION)
        after = store.obligation_detail("item-r2")
        self.assertEqual((result["status"], result["decision_id"]), ("RECORDED", CLOSE))
        for key in ("revision", "received_cash_cents", "shortfall_cents", "case_status"):
            self.assertEqual(after[key], before[key], key)
        item = self._r2(store)
        with closing(sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)) as connection:
            (sequence,) = connection.execute("SELECT event_sequence FROM financial_events WHERE kind='FOLLOWTHROUGH_DECIDED'").fetchone()
        self.assertEqual(item["status"], "CLOSED")
        self.assertEqual(item["decisions"], [{"decision_id": CLOSE, "act": "CLOSE", "reason_code": "BANKRUPTCY", "owner_id": None, "suggestion": SUGGESTION, "agrees_with_suggestion": False,
                                              "actor_id": "synthetic-official", "actor_role": "CASE_OWNER", "decided_at_ms": CLOSE_AT, "event_sequence": sequence}])
        federal, recovery = item["clocks"]
        self.assertEqual((federal["status"], federal["stopped_by"]), ("STOPPED", CLOSE))
        self.assertEqual(recovery["status"], "MISSED")  # the close came after its end

    def test_decision_retry_is_duplicate_and_changed_retry_conflicts(self) -> None:
        store = self._store()
        before = _history(store)
        self.assertEqual(_decide(store, suggestion=SUGGESTION)["status"], "DUPLICATE")
        self.assertEqual(_history(store), before)
        for changes in ({"reason_code": "UNCOLLECTIBLE_OTHER", "suggestion": SUGGESTION}, {"item_id": "item-r3", "suggestion": SUGGESTION}):
            with self.subTest(changes), self.assertRaisesRegex(FinancialConflictError, "^followthrough_decision_conflict$"):
                _decide(store, **changes)
        self.assertEqual(_history(store), before)

    def test_assign_after_close_reopens_and_names_the_owner(self) -> None:
        store = self._store()
        _decide(store, ASSIGN_AT, decision_id="decision:r2:assign", act="ASSIGN", reason_code=None, owner_id="state-recovery-unit")
        item = self._r2(store)
        self.assertEqual((item["status"], item["owner"]), ("OPEN", {"owner_id": "state-recovery-unit", "basis": "DECISION", "decision_id": "decision:r2:assign"}))
        self.assertEqual(item["clocks"][0]["status"], "MISSED")

    def test_decision_requires_roster_actor_and_allowed_role(self) -> None:
        store = self._store()
        other = {"decision_id": "decision:r2:other"}
        for actor, code in ((("synthetic-reporter", "REPORTING_EDITOR"), "followthrough_actor_role"), (("nobody", "CASE_OWNER"), "authority_actor_not_authorized")):
            with self.subTest(actor):
                self._refused(store, FinancialAuthorityError, code, **other, actor_id=actor[0], actor_role=actor[1])
        self._refused(store, FinancialInputError, "expected_revision_required", **other, expected_revision=None)
        self._refused(store, FinancialRevisionError, "obligation_revision_conflict", **other, expected_revision=store.obligation_detail("item-r2")["revision"] + 1)
        (self.directory / "narrow").mkdir()
        with self.assertRaisesRegex(FinancialIntegrityError, "^lean_evaluation:case_owner_role$"):  # Lean refuses a pack no case owner can act under
            _build_r_store(self.directory / "narrow", RULES, roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"))

    def test_decision_shape_refused(self) -> None:
        store = self._store()
        owner_id = "state-recovery-unit"
        for name, code, changes in (
            ("act", "followthrough_act", {"act": "REOPEN"}),
            ("close without reason", "followthrough_reason", {"reason_code": None}),
            ("close with owner", "followthrough_owner", {"owner_id": owner_id}),
            ("assign with reason", "followthrough_reason", {"act": "ASSIGN", "owner_id": owner_id}),
            ("assign without owner", "followthrough_owner", {"act": "ASSIGN", "reason_code": None}),
            ("extra suggestion key", "followthrough_suggestion", {"suggestion": {**SUGGESTION, "extra": 1}}),
            ("lower-case digest", "followthrough_suggestion", {"suggestion": {**SUGGESTION, "source_sha256": SUGGESTION["source_sha256"].lower()}}),
            ("suggestion after the clock", "followthrough_suggestion_time", {"suggestion": {**SUGGESTION, "suggested_at_ms": CLOSE_AT + 1}}),
            ("decision id", "decision_id", {"decision_id": "bad id"}),
        ):
            with self.subTest(name):
                self._refused(store, FinancialInputError, code, **{"decision_id": "decision:r2:other", **changes})

    def test_checker_binds_decision_events(self) -> None:
        store = self._store()
        store.close()  # R1a: its commits reach the main file when it closes
        for name, forge, code, _pre in FORGERIES:
            with self.subTest(name):
                forged = self.directory / f"forged-{name.replace(' ', '-')}.sqlite3"
                forged.write_bytes(store.path.read_bytes())
                forge(forged)
                with self.assertRaisesRegex(independent.IndependentFinancialError, f"^{code}$"):
                    independent.verify_database(forged, **store._checker_expectations())

    def test_restore_rebuilds_decision_commands(self) -> None:
        store = self._store()
        restored = self._closing(FinancialOwner.restore_continuity(package_bytes=store.export_continuity(), recovered_path=self.directory / "restored.sqlite3", trusted_authority=store.trusted_authority))
        query = "SELECT command_id,request_digest FROM commands WHERE command_id=?"
        with closing(sqlite3.connect(f"file:{store.path}?mode=ro", uri=True)) as original, closing(sqlite3.connect(f"file:{restored.path}?mode=ro", uri=True)) as copy:
            found = original.execute(query, (f"FOLLOWTHROUGH_DECISION:{CLOSE}",)).fetchall()
            self.assertEqual((len(found), copy.execute(query, (f"FOLLOWTHROUGH_DECISION:{CLOSE}",)).fetchall()), (1, found))
        restored.verify_integrity()

    def test_gaps_for_untyped_suggestion_unknown_reason_and_activity_after_close(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        untyped = {**SUGGESTION, "source_id": "unknown-model", "source_ref": "triage:r3:1", "reason_code": "NOT_IN_RULES"}
        _decide(store, item_id="item-r3", decision_id="decision:r3:close", reason_code="NOT_IN_RULES", suggestion=untyped)
        store.clock.value = ASSIGN_AT
        store.record_payment_evidence(item_id="item-r3", payment_id="payment:r3", common_origin_id="origin:r3", amount_cents=1_000, evidence_id="evidence:payment:r3", event_at_ms=ASSIGN_AT, source_id="state-collections")
        pack = _pack(store)
        for gap in ("gap:decision-not-in-rules:decision:r3:close", "gap:suggestion-source-not-typed:decision:r3:close", "gap:activity-after-close:item-r3"):
            self.assertIn(gap, pack["unavailable"])
        r3 = next(item for item in pack["items"] if item["item_id"] == "item-r3")
        self.assertNotIn("STOPPED", {clock["status"] for clock in r3["clocks"]})

    def test_close_needs_the_433_318_evidence(self) -> None:
        # Each purpose a reason requires is met by its own evidence row, received by the decision time. The state-legal-office
        # holds five purposes, so each reason here needs three legal-office rows (the notice row meets DISCOVERY_NOTICE).
        for reason, short, fixed in (("BANKRUPTCY", ("creditor", "effort"), "petition"), ("OUT_OF_BUSINESS", ("location", "effort"), "certification")):
            with self.subTest(reason):
                (self.directory / reason).mkdir()
                store = self._closing(_build_r_store(self.directory / reason, RULES))
                _legal(store, *short)
                _decide(store, decision_id="decision:short", reason_code=reason)
                self.assertEqual(self._r2(store)["clocks"][0]["status"], "MISSED")
                self.assertIn("gap:closure-evidence-missing:decision:short", _pack(store)["unavailable"])
                _legal(store, fixed, at_ms=CLOSE_AT + 1)
                _decide(store, CLOSE_AT + 2, decision_id="decision:met", reason_code=reason)
                self.assertEqual(self._r2(store)["clocks"][0]["status"], "STOPPED")
                unavailable = _pack(store)["unavailable"]
                self.assertIn("gap:closure-evidence-missing:decision:short", unavailable)  # never retroactive
                self.assertNotIn("gap:closure-evidence-missing:decision:met", unavailable)

    def test_one_document_cannot_meet_two_required_purposes(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        _legal(store, "petition-and-creditor", "effort")  # one legal-office document offered for both BANKRUPTCY_PETITION and CREDITOR_RECORD
        _decide(store)
        self.assertIn(f"gap:closure-evidence-missing:{CLOSE}", _pack(store)["unavailable"])
        self.assertEqual(self._r2(store)["clocks"][0]["status"], "MISSED")
        _legal(store, "creditor", at_ms=CLOSE_AT + 1)
        _decide(store, CLOSE_AT + 2, decision_id="decision:r2:close-2")
        self.assertEqual(self._r2(store)["clocks"][0]["status"], "STOPPED")

    def test_partial_recovery_then_close_keeps_the_collected_share_due(self) -> None:
        # 433.318(a)(1) excuses the state only to the extent it cannot recover: the collected part's federal share stays due.
        store = self._closing(_build_r_store(self.directory, RULES))
        store.clock.value = EVIDENCE_AT
        store.record_payment_evidence(item_id="item-r2", payment_id="payment:r2:partial", common_origin_id="origin:r2:partial", amount_cents=200_000,
                                      evidence_id="evidence:payment:r2:partial", event_at_ms=EVIDENCE_AT, source_id="state-collections")
        _legal(store, "petition", "creditor", "effort")
        _decide(store)
        item = self._r2(store)
        federal = item["clocks"][0]
        self.assertEqual((item["status"], item["open_cents"], federal["status"], federal["report"]), ("CLOSED", 300_000, "STOPPED", None))
        self.assertIn("gap:write-off-line-unknown:item-r2", _pack(store)["unavailable"])
        quarter, due, _ = _cms64_due(FEDERAL_ENDS, EVIDENCE_AT, 30)
        self.assertEqual(item["collected_share"], {
            "clock_id": "federal-share-credit", "collected_cents": 200_000, "basis_points": 5000, "cents": 100_000, "quarter": quarter, "due_ms": due,
            "report": {"quarter": quarter, "form": "64.9C1", "line": None, "summary_line": "9C"}, "status": "MISSED"})
        early = next(i for i in _pack(store, CLOSE_AT + DAY)["items"] if i["item_id"] == "item-r2")
        self.assertEqual(early["collected_share"]["status"], "DUE")
        (self.directory / "none").mkdir()
        self.assertIsNone(self._r2(self._closing(_decided_store(self.directory / "none")))["collected_share"])  # nothing collected: nothing due

    def test_evidence_recorded_after_a_close_never_covers_it(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        _legal(store, "creditor", "effort")
        _decide(store)
        _legal(store, "petition", at_ms=CLOSE_AT)  # the same millisecond as the decision, recorded after it
        unavailable = _pack(store)["unavailable"]
        self.assertEqual(self._r2(store)["clocks"][0]["status"], "MISSED")
        for gap in (f"gap:closure-evidence-missing:{CLOSE}", "gap:activity-after-close:item-r2"):
            self.assertIn(gap, unavailable)

    def test_one_document_recorded_three_times_meets_one_purpose(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        store.clock.value = EVIDENCE_AT
        for copy in "abc":
            store.record_support_evidence(item_id="item-r2", evidence_id=f"evidence:copy-{copy}:r2", common_origin_id="origin:legal-doc-1", source_id="state-legal-office",
                                          source_version="v1", local_ref="legal:doc-1", applicable_at_ms=EVIDENCE_AT, event_at_ms=EVIDENCE_AT)
        _decide(store)
        self.assertIn(f"gap:closure-evidence-missing:{CLOSE}", _pack(store)["unavailable"])
        self.assertEqual(self._r2(store)["clocks"][0]["status"], "MISSED")

    def test_an_aggregate_id_shared_across_types_still_opens(self) -> None:
        # A pack id equal to an obligation id: the whole-database walk keys by (type, id), as the pre-COMMIT query does.
        store = self._closing(_build_r_store(self.directory, RULES))
        store.clock.value = EVIDENCE_AT
        store.publish_control_pack(ControlPack(
            pack_id=store.obligation_detail("item-r3")["obligation_id"], **SCOPE, version=2, source_refs=("synthetic:source:v2",),
            effective_start_ms=4_000_000_000_000, effective_end_ms=4_100_000_000_000, recorded_at_ms=500, approved_at_ms=500,
            calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
            authorized_roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER", "CASE_OWNER"),
            expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate")))
        _decide(store, item_id="item-r3", decision_id="decision:r3:assign", act="ASSIGN", reason_code=None, owner_id="state-recovery-unit")
        independent.verify_database(store.path, **store._checker_expectations())
        self._closing(FinancialOwner(path=store.path, config=FinancialOwnerConfig(**SCOPE), trusted_authority=store.trusted_authority, clock=_Clock())).verify_integrity()

    def test_cli_records_followthrough_decision(self) -> None:
        store = self._closing(_build_r_store(self.directory, RULES))
        _legal(store, "petition", "creditor", "effort")
        (self.directory / "authority.json").write_bytes(json.dumps(financial_cli.authority_file_record(store.trusted_authority)).encode("ascii"))
        (self.directory / "suggestion.json").write_bytes(_encode(SUGGESTION))
        args = ["--database", str(store.path), "--authority-file", str(self.directory / "authority.json"), *[f"--{key.replace('_', '-')}={value}" for key, value in SCOPE.items()],
                "record-followthrough-decision", "--item-id", "item-r2", "--decision-id", CLOSE, "--act", "CLOSE", "--reason-code", "BANKRUPTCY", "--suggestion", str(self.directory / "suggestion.json"),
                "--actor-id", "synthetic-official", "--actor-role", "CASE_OWNER", "--expected-revision", str(store.obligation_detail("item-r2")["revision"])]
        with patch.object(owner_module._SystemClock, "now_ms", return_value=CLOSE_AT):
            for status in ("RECORDED", "DUPLICATE"):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(financial_cli.main(args), 0)
                self.assertEqual(json.loads(output.getvalue())["status"], status)

    def test_a_decision_the_checker_rejects_is_refused_before_commit(self) -> None:
        # The lean-live M0 F1 probe for this kind: an owner bug is refused before COMMIT, not found on the next open.
        store = self._closing(_build_r_store(self.directory, RULES))
        before = _history(store)
        with patch.object(owner_module, "_followthrough_shape", lambda *args, **kwargs: None):
            with self.assertRaisesRegex(FinancialIntegrityError, "^followthrough_verification:followthrough:payload"):
                _decide(store, item_id="item-r3", act="REOPEN", reason_code="X", owner_id=None)
        self.assertEqual(_history(store), before)
        self._closing(FinancialOwner(path=store.path, config=FinancialOwnerConfig(**SCOPE), trusted_authority=store.trusted_authority, clock=_Clock())).verify_integrity()


if __name__ == "__main__":
    unittest.main()
