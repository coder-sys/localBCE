"""Proof obligations for the read-only CMS-64.9 line pack (docs/CORE_REDESIGN.md "Line pack").

One synthetic store (public Owner commands only) and its Continuity package; every build verifies
the store read-only. The Ledger total each test compares against is recomputed here with read-only SQL.
"""

from __future__ import annotations

from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.right_rail_financial_line_pack import NOT_HELD, LinePackError, build_line_pack, quarter_window
from app.right_rail_financial_owner import (
    ControlPack, FinancialOwner, FinancialOwnerConfig, PopulationItem, PopulationManifest, SyntheticTrustedAuthority,
)
from app.right_rail_financial_owner_independent import continuity_package_digest
from tools import right_rail_financial_cli as financial_cli

LINE_MAP = Path(__file__).resolve().parent / "fixtures" / "cms64_line_map_synthetic_v1.json"
SCOPE = {"state_id": "state:synthetic-line-pack", "deployment_id": "deployment:synthetic-line-pack", "program_id": "program:synthetic-hcbs", "period_id": "period:ffy2025q4"}
Q3_START, Q4_START, Q4_END = 1_743_465_600_000, 1_751_328_000_000, 1_759_276_800_000  # 2025-04-01, 07-01, 10-01 UTC
DAY, AT = 86_400_000, 3_000_000_000_000  # AT: a pack time after every event
HCBS, PERSONAL_CARE = "synthetic-payment-source", "synthetic-personal-care-source"
V2_START, V3_START, V3_END = 4_000_000_000_000, 4_050_000_000_000, 4_102_444_800_000


def _encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def _ref(line_map: bytes) -> str:
    return "line-map:sha256:" + hashlib.sha256(line_map).hexdigest().upper()


def _control_pack(version: int, start: int, end: int, *refs: str) -> ControlPack:
    return ControlPack(
        pack_id=f"pack:line-pack-v{version}", **SCOPE, version=version, source_refs=("synthetic:source:v1", *refs),
        effective_start_ms=start, effective_end_ms=end, recorded_at_ms=500, approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"),
    )


def _build(directory: Path, authority: SyntheticTrustedAuthority, line_map: bytes) -> FinancialOwner:
    owner = FinancialOwner(path=directory / "line-pack.sqlite3", config=FinancialOwnerConfig(**SCOPE), trusted_authority=authority)
    owner.publish_control_pack(_control_pack(1, 1_000, V2_START, _ref(line_map)))
    items = tuple(PopulationItem(population_id="population:line-pack-v1", item_id=f"item:{i}", display_label=f"synthetic-{i}", owed_cents=owed, due_at_ms=Q4_END) for i, owed in enumerate((50_000, 70_000, 90_000)))
    owner.register_population_manifest(PopulationManifest(
        manifest_id="manifest:line-pack-v1", manifest_version=1, **SCOPE, pack_id="pack:line-pack-v1", cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",), source_owner_id="source-owner:line-pack", authority_id=authority.authority_id,
        authority_epoch=authority.epoch, authority_digest=authority.digest, approved_by="synthetic-official",
        approval_ref="ref:line-pack-v1", source_id="source:line-pack-v1", source_version="v1",
        source_digest=hashlib.sha3_512(b"line-pack-population-v1").digest(), member_ids=tuple(item.item_id for item in items),
    ))
    owner.stage_population(population_id="population:line-pack-v1", manifest_id="manifest:line-pack-v1", pack_id="pack:line-pack-v1", cutoff_ms=1_000, inclusion_rules=("included:synthetic",), expected_count=3, items=items, chunk_size=3)
    owner.validate_population("population:line-pack-v1")
    owner.publish_population("population:line-pack-v1")
    for n, (item, cents, at_ms, source) in enumerate((
        (0, 12_345, Q4_START + DAY * 14, HCBS),   # 19A, mid-quarter
        (1, 20_000, Q4_END - 1, HCBS),                    # 19A, last millisecond of the quarter
        (2, 30_000, Q4_START + DAY * 31, PERSONAL_CARE),  # 23A
        (0, 5_000, Q4_END, HCBS),                         # next quarter
        (1, 7_000, Q4_START - 1, HCBS),                   # prior quarter, reversed in Q4 below
        (2, 4_000, Q4_START + DAY, HCBS),          # 19A, reversed within Q4 below
    )):
        owner.record_payment_evidence(item_id=f"item:{item}", payment_id=f"payment:{n}", common_origin_id=f"origin:{n}", amount_cents=cents, evidence_id=f"evidence:payment:{n}", event_at_ms=at_ms, source_id=source)
    owner.reverse_payment(item_id="item:2", payment_id="payment:5", evidence_id="evidence:reversal:5", event_at_ms=Q4_START + DAY * 2)
    owner.reverse_payment(item_id="item:1", payment_id="payment:4", evidence_id="evidence:reversal:4", event_at_ms=Q4_START + DAY * 3)
    # The same origin again: an equal amount is a duplicate confirmation, a different amount a visible conflict.
    owner.record_payment_evidence(item_id="item:0", payment_id="payment:duplicate", common_origin_id="origin:0", amount_cents=12_345, evidence_id="evidence:duplicate:0", event_at_ms=Q4_START + DAY * 14, source_id=HCBS)
    owner.record_payment_evidence(item_id="item:2", payment_id="payment:conflict", common_origin_id="origin:2", amount_cents=31_000, evidence_id="evidence:conflict:2", event_at_ms=Q4_START + DAY * 31, source_id=PERSONAL_CARE)
    owner.publish_control_pack(_control_pack(2, V2_START, V3_START, _ref(line_map.replace(b'"pack_version":1', b'"pack_version":2'))))
    owner.publish_control_pack(_control_pack(3, V3_START, V3_END, _ref(line_map.replace(b'"pack_version":1', b'"pack_version":3')), "line-map:sha256:" + "0" * 64))
    return owner


class LinePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="rr-line-pack-")
        cls.db = Path(cls.tmp.name) / "line-pack.sqlite3"
        cls.authority = SyntheticTrustedAuthority()
        cls.line_map = LINE_MAP.read_bytes()
        cls.owner = _build(Path(cls.tmp.name), cls.authority, cls.line_map)
        cls.package = cls.owner.export_continuity()
        cls.trust = {"trusted_authority": cls.authority, "expected_scope": {**SCOPE, "currency": "USD"}}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.owner = None
        cls.tmp.cleanup()

    def _raw(self, line: str = "19A", reported: int = 32_345, at_ms: int = AT, **changes: object) -> bytes:
        return build_line_pack(**{"database": self.db, "package_bytes": self.package, "line_map_bytes": self.line_map, "line": line, "quarter": "FFY2025Q4", "reported_line_cents": reported, "generated_at_ms": at_ms, **self.trust, **changes})

    def _pack(self, *args: object, **changes: object) -> dict:
        raw = self._raw(*args, **changes)
        self.assertEqual(self._raw(*args, **changes), raw)  # deterministic on every build
        return json.loads(raw)

    def _sql(self, query: str, parameters: tuple = ()) -> list[tuple]:
        """Independent read-only SQL over the store (closed at once: sqlite3's ``with`` does not close)."""
        with closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as connection:
            return connection.execute(query, parameters).fetchall()

    def _ledger_cents(self, source: str, start: int, end: int) -> int:
        """Payments from ``source`` paid in [start, end) and still active at ``end``."""
        return self._sql(
            "SELECT COALESCE(SUM(p.amount_cents),0) FROM payments p JOIN evidence e ON e.evidence_id=p.evidence_id "
            "LEFT JOIN evidence r ON r.evidence_id=p.reversed_by_evidence_id "
            "WHERE (p.active=1 OR r.event_at_ms>=?) AND p.event_at_ms>=? AND p.event_at_ms<? AND e.source_id=?",
            (end, start, end, source),
        )[0][0]

    def _forged(self, table: str, key: str, value: str, **columns: object) -> bytes:
        """The package with one row edited and its public digest recomputed: grammar-valid, but not the store."""
        package = json.loads(self.package)
        next(row for row in package["tables"][table] if row[key] == value).update(columns)
        del package["package_digest"]
        return _encode({**package, "package_digest": continuity_package_digest(package)})

    def test_kill_criterion_1_synthetic_pack_reconciles_to_synthetic_line_to_the_cent(self) -> None:
        pack = self._pack()
        self.assertEqual((quarter_window("FFY2025Q3"), quarter_window("FFY2025Q4")), ((Q3_START, Q4_START), (Q4_START, Q4_END)))
        self.assertEqual((pack["total_cents"], pack["row_count"]), (32_345, 2))
        self.assertEqual(pack["coverage"], {"numerator_cents": 32_345, "denominator_cents": 32_345, "status": "FULL"})
        self.assertEqual([row["payment_id"] for row in pack["rows"]], ["payment:0", "payment:1"])
        self.assertEqual(pack["service_period_split"], [{"service_period_id": "period:ffy2025q4", "cents": 32_345, "row_count": 2}])

    def test_sum_equals_ledger_exact_cents(self) -> None:
        for line, source, quarter, start, end in (("19A", HCBS, "FFY2025Q3", Q3_START, Q4_START), ("19A", HCBS, "FFY2025Q4", Q4_START, Q4_END), ("23A", PERSONAL_CARE, "FFY2025Q4", Q4_START, Q4_END)):
            with self.subTest(line=line, quarter=quarter):
                pack = self._pack(line, reported=1, quarter=quarter)
                self.assertEqual(pack["total_cents"], self._ledger_cents(source, start, end))
                self.assertEqual(pack["total_cents"], sum(row["amount_cents"] for row in pack["rows"]))
        self.assertEqual(self._pack("23A", reported=30_000)["total_cents"], 30_000)

    def test_closed_quarter_keeps_a_later_reversal(self) -> None:
        q3 = self._pack(reported=7_000, quarter="FFY2025Q3")
        self.assertEqual((q3["total_cents"], q3["reversed_after_quarter"]), (7_000, [{"payment_id": "payment:4", "amount_cents": 7_000}]))
        q4 = self._pack()
        self.assertEqual(q4["prior_quarter_reversals"], [{"payment_id": "payment:4", "amount_cents": 7_000, "paid_quarter": "FFY2025Q3"}])
        self.assertEqual((q4["total_cents"], q4["reversed_after_quarter"]), (32_345, []))  # never netted into Q4
        self.assertIn("excluded:reversed-payment:payment:5", q4["unavailable"])  # reversed within its own quarter

    def test_rule_version_bound(self) -> None:
        pack = self._pack()
        ((pack_digest,),) = self._sql("SELECT pack_digest FROM control_packs WHERE pack_id='pack:line-pack-v1'")
        decided = {row[0]: (row[1], row[2].hex().upper()) for row in self._sql(
            "SELECT e.evaluation_id,e.rule_version,e.control_pack_digest FROM evaluations e JOIN obligations o ON o.current_evaluation_id=e.evaluation_id")}
        self.assertEqual(pack["versions"]["control_pack"], {"pack_id": "pack:line-pack-v1", "version": 1, "digest": pack_digest.hex().upper()})
        self.assertEqual(pack["versions"]["line_map_sha256"], hashlib.sha256(self.line_map).hexdigest().upper())
        for row in pack["rows"]:
            self.assertEqual(decided[row["evaluation_id"]], (row["rule_version"], pack_digest.hex().upper()))
        self.assertEqual(pack["versions"]["rule_versions"], sorted({row["rule_version"] for row in pack["rows"]}))
        self.assertFalse([item for item in pack["unavailable"] if item.startswith("gap:row-")])
        # A map no approved Control Pack lists (any byte changed, or another pack version) is refused.
        other_version = self.line_map.replace(b'"pack_version":1', b'"pack_version":4')
        for line_map in (other_version, self.line_map.replace(b"synthetic-payment-source", b"synthetic-other-source")):
            with self.subTest(line_map=line_map[:40]), self.assertRaisesRegex(LinePackError, "line-map-not-in-approved-control-pack"):
                self._raw(line_map_bytes=line_map)

    def test_line_map_ref_unique_and_window_covers_quarter(self) -> None:
        narrow = self._pack(line_map_bytes=self.line_map.replace(b'"pack_version":1', b'"pack_version":2'))
        self.assertIn("gap:line-map-window-does-not-cover-quarter", narrow["unavailable"])
        self.assertEqual(narrow["coverage"]["status"], "PARTIAL")
        self.assertNotIn("gap:line-map-window-does-not-cover-quarter", self._pack()["unavailable"])
        with self.assertRaisesRegex(LinePackError, "line-map-ref-not-unique"):  # pack v3 lists two line maps
            self._raw(line_map_bytes=self.line_map.replace(b'"pack_version":1', b'"pack_version":3'))

    def test_complete_or_declares_gap(self) -> None:
        exact = self._pack()  # payment:0's duplicate confirmation adds no row and no gap
        self.assertEqual(exact["unavailable"], sorted([*NOT_HELD, "excluded:reversed-payment:payment:5"]))
        self.assertEqual(self._sql("SELECT COUNT(*) FROM evidence WHERE evidence_id='evidence:duplicate:0'"), [(1,)])
        self.assertIsNotNone(exact["member_manifest_digest"])
        short = self._pack(reported=40_000)
        self.assertEqual(short["coverage"]["status"], "PARTIAL")
        self.assertIn("gap:reported-cents-not-in-this-package:7655", short["unavailable"])
        over = self._pack(reported=30_000)
        self.assertEqual(over["coverage"]["status"], "EXCEEDS_REPORTED")
        self.assertIn("gap:ledger-cents-above-reported:2345", over["unavailable"])
        next_quarter = self._pack(quarter="FFY2026Q1", reported=5_000)
        self.assertEqual(([row["payment_id"] for row in next_quarter["rows"]], next_quarter["coverage"]["status"]), (["payment:3"], "FULL"))
        conflicted = self._pack("23A", reported=30_000)  # cents match, but a differing amount is visible
        self.assertIn("gap:amount-conflict-visible:payment:2", conflicted["unavailable"])
        self.assertEqual((conflicted["row_count"], conflicted["coverage"]["status"]), (1, "PARTIAL"))

    def test_deterministic_same_store_same_bytes(self) -> None:
        self.assertEqual(self._raw(package_bytes=self.owner.export_continuity()), self._raw())

    def test_chronology_strict_for_a_superseding_pack(self) -> None:
        prior = self._raw()
        self.assertEqual(self._pack(at_ms=AT + 1, prior_pack=prior)["supersedes"], hashlib.sha256(prior).hexdigest().upper())
        self.assertIsNone(self._pack()["supersedes"])
        for at_ms in (AT, AT - 1):
            with self.subTest(at_ms=at_ms), self.assertRaisesRegex(LinePackError, "chronology-not-strict"):
                self._raw(at_ms=at_ms, prior_pack=prior)
        source = json.loads(prior)["source"]
        for edit, code in (
            ({"sequence": source["sequence"] + 1}, "chronology-not-strict"),
            ({"history_head": "0" * 128}, "chronology-not-strict"),  # same sequence, another head
            ({"program_id": "program:other"}, "prior-pack-identity"),
            ({"genesis_head": "0" * 128}, "prior-pack-identity"),
        ):
            with self.subTest(edit=sorted(edit)), self.assertRaisesRegex(LinePackError, code):
                self._raw(at_ms=AT + 1, prior_pack=_encode({**json.loads(prior), "source": {**source, **edit}}))
        with self.assertRaisesRegex(LinePackError, "prior-pack-identity"):
            self._raw(at_ms=AT + 1, prior_pack=self._raw("23A", reported=1))
        with self.assertRaisesRegex(LinePackError, "prior-pack:canonical"):
            self._raw(at_ms=AT + 1, prior_pack=prior + b" ")
        with self.assertRaisesRegex(LinePackError, "generated-before-package"):
            self._raw(at_ms=Q4_END)

    def test_never_asserts_allowability(self) -> None:
        raw = self._raw()
        pack = json.loads(raw)
        self.assertIs(pack["documentation_only"], True)
        self.assertEqual(pack["claims"], {"proofSuiteId": None, "production_usable": False, "activation": False})
        self.assertIsNone(pack["signer"])
        for word in (b"approv", b"allowab", b"valid", b"necessary", b"eligible", b"covered"):
            self.assertNotIn(word, raw.lower())
        self.assertEqual(set(pack), {
            "contract", "documentation_only", "claims", "line", "quarter", "window_ms", "payment_date_basis", "total_cents",
            "row_count", "rows", "reversed_after_quarter", "prior_quarter_reversals", "service_period_split",
            "member_manifest_digest", "provenance_root", "unavailable", "coverage", "versions", "source", "generated_at_ms",
            "supersedes", "signer",
        })
        expected_root = hashlib.sha256(_encode({"contract": "RR/LINE-PACK/PROVENANCE/v1", "evidence_record_digests": [row["evidence_record_digest"] for row in pack["rows"]]})).hexdigest().upper()
        self.assertEqual(pack["provenance_root"], expected_root)

    def test_only_a_verified_store_yields_a_pack(self) -> None:
        # Edited package rows with a recomputed (public, unkeyed) digest pass the package grammar but not the store.
        forged_map = self.line_map.replace(b'"payment_source_ids":["synthetic-payment-source"]', b'"payment_source_ids":["synthetic-payment-source","synthetic-personal-care-source"]')
        refs = json.dumps({"values": ["synthetic:source:v1", _ref(forged_map)]}, separators=(",", ":"), sort_keys=True)
        for package, line_map in (
            (self._forged("payments", "payment_id", "payment:0", amount_cents=22_345), self.line_map),
            (self._forged("control_packs", "pack_id", "pack:line-pack-v1", source_refs_json=refs), forged_map),
        ):
            with self.subTest(line_map=line_map == forged_map), self.assertRaisesRegex(LinePackError, "current-snapshot-mismatch"):
                self._raw(package_bytes=package, line_map_bytes=line_map)
        # A raw UPDATE on a copy of the store, with a package that matches it, fails the store's own checks.
        copy = Path(self.tmp.name) / "tampered.sqlite3"
        with closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as source, closing(sqlite3.connect(copy)) as target:
            source.backup(target)
            target.execute("UPDATE payments SET amount_cents=22345 WHERE payment_id='payment:0'")
            target.commit()
        with self.assertRaises(LinePackError) as refused:
            self._raw(database=copy, package_bytes=self._forged("payments", "payment_id", "payment:0", amount_cents=22_345))
        self.assertNotIn("current-snapshot-mismatch", str(refused.exception))

    def test_fails_closed(self) -> None:
        for changes, code in (
            ({"trusted_authority": SyntheticTrustedAuthority(authority_id="synthetic-authority-other")}, "meta:authority-binding"),
            ({"package_bytes": self.package[:-1]}, "continuity:package"),
            ({"package_bytes": None}, "continuity:byte-cap"),
            ({"database": None}, "database:path"),
            ({"quarter": "2025Q4"}, "quarter"),
            ({"reported_line_cents": 0}, "reported-line-cents"),
            ({"reported_line_cents": 1.0}, "reported-line-cents"),
            ({"line": "19D"}, "line-map-unknown-line"),
            ({"line_map_bytes": self.line_map + b"\n"}, "line-map:canonical"),
            ({"line_map_bytes": bytearray(self.line_map)}, "line-map:byte-cap"),
            ({"line_map_bytes": self.line_map.replace(b'["synthetic-payment-source"]', b'[["synthetic-payment-source"]]')}, "line-map-source"),
            ({"line_map_bytes": self.line_map.replace(b"PAYMENT_EVENT_AT", b"SERVICE_DATE_AT")}, "line-map-date-basis"),
        ):
            with self.subTest(code=code, changes=sorted(changes)), self.assertRaisesRegex(LinePackError, code):
                self._raw(**changes)

    def test_cli_writes_the_same_pack_and_never_replaces(self) -> None:
        directory = Path(self.tmp.name)
        (directory / "authority.json").write_bytes(json.dumps(financial_cli.authority_file_record(self.authority)).encode("ascii"))
        (directory / "package.bin").write_bytes(self.package)
        output = directory / "line-pack-19A.json"
        args = ["--authority-file", str(directory / "authority.json"), *[f"--{key.replace('_', '-')}={value}" for key, value in SCOPE.items()],
                "line-pack", "--package", str(directory / "package.bin"), "--line-map", str(LINE_MAP), "--line", "19A",
                "--quarter", "FFY2025Q4", "--reported-line-cents", "32345", "--generated-at-ms", str(AT), "--output", str(output)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(financial_cli.main(args), 2)  # no --database: refused, nothing written
        self.assertIn("line-pack:database:path", errors.getvalue())
        self.assertFalse(output.exists())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(financial_cli.main(["--database", str(self.db), *args]), 0)
        self.assertEqual(output.read_bytes(), self._raw())
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(financial_cli.main(["--database", str(self.db), *args]), 2)  # the output file exists: never replaced


if __name__ == "__main__":
    unittest.main()
