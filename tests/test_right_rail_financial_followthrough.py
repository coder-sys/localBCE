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

from app.right_rail_financial_derived import NOT_HELD, DerivedError
from app.right_rail_financial_followthrough import MAX_RULES_BYTES, _add, _cms64_due, build_followthrough_pack
from app.right_rail_financial_owner import (
    ControlPack, FinancialOwner, FinancialOwnerConfig, PopulationItem, PopulationManifest, SyntheticTrustedAuthority,
)
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


def _build_r_store(directory: Path, rules_bytes: bytes, *, extra_refs: tuple[str, ...] = (), paid: tuple[int, int] = (PAID_R1, PAID_R1), credit: int | None = CREDIT_R1) -> FinancialOwner:
    authority = SyntheticTrustedAuthority()
    owner = FinancialOwner(path=directory / "recovery.sqlite3", config=FinancialOwnerConfig(**SCOPE), trusted_authority=authority, clock=_Clock())
    owner.publish_control_pack(ControlPack(
        pack_id="pack:recovery-v1", **SCOPE, version=1, source_refs=("synthetic:source:v1", _ref(rules_bytes), *extra_refs),
        effective_start_ms=1_000, effective_end_ms=4_000_000_000_000, recorded_at_ms=500, approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER", "CASE_OWNER"),
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
        cls.owner = None
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
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-ack-") as tmp:
            owner = _build_r_store(Path(tmp), RULES)
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
                with self.subTest(name):
                    (Path(tmp) / name).mkdir()
                    owner = _build_r_store(Path(tmp) / name, rules, extra_refs=extra)
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
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-fmap-") as tmp:
            owner = _build_r_store(Path(tmp), rules)
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
            with self.subTest(name), tempfile.TemporaryDirectory(prefix="rr-followthrough-lag-") as tmp:
                owner = _build_r_store(Path(tmp), RULES, paid=paid, credit=credit)
                item = next(i for i in json.loads(build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=RULES, generated_at_ms=generated, **self.trust))["items"] if i["item_id"] == "item-r1")
                credit_clock, action_clock = item["clocks"]
                self.assertEqual((credit_clock["report"]["quarter"], credit_clock["report"]["form"], credit_clock["due_ms"], credit_clock["status"]), federal)
                self.assertEqual((action_clock["satisfied"]["at_ms"], action_clock["status"]), action)

    def test_finder_not_typed_is_a_declared_gap(self) -> None:
        rules = _mutated(lambda value: value.update(parties=[party for party in value["parties"] if party["party_id"] != "rac-contractor-1"]))
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-finder-") as tmp:
            owner = _build_r_store(Path(tmp), rules)
            pack = json.loads(build_followthrough_pack(owner.path, owner.export_continuity(), rules_bytes=rules, generated_at_ms=GENERATED, **self.trust))
        self.assertEqual({(item["found"]["party"], item["found"]["kind"]) for item in pack["items"]}, {(None, None)})
        self.assertIn("gap:finder-not-typed:rac-contractor-1", pack["unavailable"])

    def test_a_clock_date_past_year_9999_is_refused_with_the_module_code(self) -> None:
        for unit in ("YEAR", "DAY"):
            with self.subTest(unit), self.assertRaisesRegex(DerivedError, "^clock-date-range$"):
                _add(DAY_MS(9999, 12, 1), {"count": 1 if unit == "YEAR" else 60, "unit": unit})
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-far-") as tmp:
            owner = _build_r_store(Path(tmp), RULES)
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
        with tempfile.TemporaryDirectory(prefix="rr-followthrough-stale-") as tmp:
            owner = _build_r_store(Path(tmp), RULES)
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


if __name__ == "__main__":
    unittest.main()
