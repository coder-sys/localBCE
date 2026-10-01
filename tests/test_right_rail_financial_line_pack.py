"""Proof obligations for the read-only CMS-64.9 line pack (rrb/archive/xi2-records-20261001.md "Line pack").

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

from app import right_rail_gate_signer as signer
from app.right_rail_financial_custody import verify_pack
from app.right_rail_financial_line_pack import NOT_HELD, LinePackError, build_line_pack, quarter_window
from app.right_rail_financial_owner import (
    ControlPack, FinancialIntegrityError, FinancialOwner, FinancialOwnerConfig, PopulationItem, PopulationManifest, SyntheticTrustedAuthority,
)
from app.right_rail_financial_owner_independent import continuity_package_digest
from tests.test_right_rail_financial_custody import fixture_custody
from tools import right_rail_financial_cli as financial_cli

LINE_MAP = Path(__file__).resolve().parent / "fixtures" / "cms64_line_map_synthetic_v1.json"
SCOPE = {"state_id": "state:synthetic-line-pack", "deployment_id": "deployment:synthetic-line-pack", "program_id": "program:synthetic-hcbs", "period_id": "period:ffy2025q4"}
Q3_START, Q4_START, Q4_END = 1_743_465_600_000, 1_751_328_000_000, 1_759_276_800_000  # 2025-04-01, 07-01, 10-01 UTC
DAY, AT = 86_400_000, 3_000_000_000_000  # AT: a pack time after every event
HCBS, PERSONAL_CARE = "synthetic-payment-source", "synthetic-personal-care-source"
V2_START, V3_START, V3_END = 4_000_000_000_000, 4_050_000_000_000, 4_102_444_800_000


def _encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def _unsigned(raw: bytes) -> dict:
    return {key: value for key, value in json.loads(raw).items() if key != "signature"}


def _ref(line_map: bytes) -> str:
    return "line-map:sha256:" + hashlib.sha256(line_map).hexdigest().upper()


def _control_pack(version: int, start: int, end: int, *refs: str) -> ControlPack:
    return ControlPack(
        pack_id=f"pack:line-pack-v{version}", **SCOPE, version=version, source_refs=("synthetic:source:v1", *refs),
        effective_start_ms=start, effective_end_ms=end, recorded_at_ms=500, approved_at_ms=500,
        calculation_rule_id="calculation:per-recipient:v1", adjustment_rule_id="adjustment:offset:v1",
        authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
        expected_tests=("program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"),
    )


class _Clock:
    """The owner clock, set by the fixture: the time the Ledger records (learns) each fact."""
    value = 1_000

    def now_ms(self) -> int:
        return self.value


def _pay(owner: FinancialOwner, n: object, item: int, cents: int, at_ms: int, source: str = HCBS, recorded_at_ms: int | None = None) -> None:
    owner.clock.value = at_ms if recorded_at_ms is None else recorded_at_ms
    owner.record_payment_evidence(item_id=f"item:{item}", payment_id=f"payment:{n}", common_origin_id=f"origin:{n}", amount_cents=cents, evidence_id=f"evidence:payment:{n}", event_at_ms=at_ms, source_id=source)


def _reverse(owner: FinancialOwner, n: object, item: int, at_ms: int, recorded_at_ms: int | None = None) -> None:
    owner.clock.value = at_ms if recorded_at_ms is None else recorded_at_ms
    owner.reverse_payment(item_id=f"item:{item}", payment_id=f"payment:{n}", evidence_id=f"evidence:reversal:{n}", event_at_ms=at_ms)


def _population(owner: FinancialOwner, authority: SyntheticTrustedAuthority, name: str, owed: dict[str, int]) -> None:
    items = tuple(PopulationItem(population_id=f"population:line-pack-{name}", item_id=item, display_label=f"synthetic-{item}", owed_cents=cents, due_at_ms=Q4_END) for item, cents in owed.items())
    owner.register_population_manifest(PopulationManifest(
        manifest_id=f"manifest:line-pack-{name}", manifest_version=1, **SCOPE, pack_id="pack:line-pack-v1", cutoff_ms=1_000,
        inclusion_rules=("included:synthetic",), source_owner_id=f"source-owner:line-pack-{name}", authority_id=authority.authority_id,
        authority_epoch=authority.epoch, authority_digest=authority.digest, approved_by="synthetic-official",
        approval_ref=f"ref:line-pack-{name}", source_id=f"source:line-pack-{name}", source_version="v1",
        source_digest=hashlib.sha3_512(name.encode()).digest(), member_ids=tuple(owed),
    ))
    owner.stage_population(population_id=f"population:line-pack-{name}", manifest_id=f"manifest:line-pack-{name}", pack_id="pack:line-pack-v1", cutoff_ms=1_000, inclusion_rules=("included:synthetic",), expected_count=len(owed), items=items, chunk_size=3)
    owner.validate_population(f"population:line-pack-{name}")
    owner.publish_population(f"population:line-pack-{name}")


def _build(directory: Path, authority: SyntheticTrustedAuthority, line_map: bytes) -> FinancialOwner:
    owner = FinancialOwner(path=directory / "line-pack.sqlite3", config=FinancialOwnerConfig(**SCOPE), trusted_authority=authority, clock=_Clock())
    owner.publish_control_pack(_control_pack(1, 1_000, V2_START, _ref(line_map)))
    owner.publish_control_pack(_control_pack(2, V2_START, V3_START, _ref(line_map.replace(b'"pack_version":1', b'"pack_version":2'))))
    owner.publish_control_pack(_control_pack(3, V3_START, V3_END, _ref(line_map.replace(b'"pack_version":1', b'"pack_version":3')), "line-map:sha256:" + "0" * 64))
    _population(owner, authority, "v1", {"item:0": 50_000, "item:1": 70_000, "item:2": 90_000})
    # Each fact is recorded on its own date, in time order; the late-recording tests backdate on purpose.
    _pay(owner, 4, 1, 7_000, Q4_START - 1)  # prior quarter, reversed in Q4 below
    _pay(owner, 5, 2, 4_000, Q4_START + DAY)  # 19A, reversed within Q4 below
    _reverse(owner, 5, 2, Q4_START + DAY * 2)
    _reverse(owner, 4, 1, Q4_START + DAY * 3)
    _pay(owner, 0, 0, 12_345, Q4_START + DAY * 14)  # 19A, mid-quarter
    # The same origin again: an equal amount is a duplicate confirmation, a different amount a visible conflict.
    owner.record_payment_evidence(item_id="item:0", payment_id="payment:duplicate", common_origin_id="origin:0", amount_cents=12_345, evidence_id="evidence:duplicate:0", event_at_ms=Q4_START + DAY * 14, source_id=HCBS)
    _pay(owner, 2, 2, 30_000, Q4_START + DAY * 31, PERSONAL_CARE)  # 23A
    owner.record_payment_evidence(item_id="item:2", payment_id="payment:conflict", common_origin_id="origin:2", amount_cents=31_000, evidence_id="evidence:conflict:2", event_at_ms=Q4_START + DAY * 31, source_id=PERSONAL_CARE)
    _pay(owner, 1, 1, 20_000, Q4_END - 1)  # 19A, last millisecond of the quarter
    _pay(owner, 3, 0, 5_000, Q4_END)  # next quarter
    return owner


class LinePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="rr-line-pack-")
        cls.db = Path(cls.tmp.name) / "line-pack.sqlite3"
        cls.authority = SyntheticTrustedAuthority()
        cls.line_map = LINE_MAP.read_bytes()
        cls.owner = _build(Path(cls.tmp.name), cls.authority, cls.line_map)
        cls.custody = fixture_custody(cls.owner)
        cls.package = cls.owner.export_continuity()
        cls.trust = {"trusted_authority": cls.authority, "expected_scope": {**SCOPE, "currency": "USD"}}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.owner.close()
        cls.tmp.cleanup()

    def _raw(self, line: str = "19A", reported: int = 32_345, at_ms: int = AT, **changes: object) -> bytes:
        return build_line_pack(**{"database": self.db, "package_bytes": self.package, "line_map_bytes": self.line_map, "line": line, "quarter": "FFY2025Q4", "reported_line_cents": reported, "generated_at_ms": at_ms, **self.trust, "custody": self.custody, **changes})

    def _pack(self, *args: object, **changes: object) -> dict:
        raw = self._raw(*args, **changes)
        self.assertEqual(_unsigned(self._raw(*args, **changes)), _unsigned(raw))  # deterministic on every build but the hedged signature
        return json.loads(raw)

    def _sql(self, query: str, parameters: tuple = ()) -> list[tuple]:
        """Independent read-only SQL over the store (closed at once: sqlite3's ``with`` does not close)."""
        with closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as connection:
            return connection.execute(query, parameters).fetchall()

    def _ledger_cents(self, source: str, start: int, end: int) -> int:
        """Payments from ``source`` paid in [start, end), recorded before ``end`` and not reversed by a record before it."""
        return self._sql(
            "SELECT COALESCE(SUM(p.amount_cents),0) FROM payments p JOIN evidence e ON e.evidence_id=p.evidence_id "
            "LEFT JOIN evidence r ON r.evidence_id=p.reversed_by_evidence_id "
            "WHERE (p.active=1 OR r.received_at_ms>=?) AND p.event_at_ms>=? AND e.received_at_ms<? AND e.source_id=?",
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
        self.assertEqual(([row["payment_id"] for row in q3["rows"]], q3["prior_quarter_adjustments"]), (["payment:4"], []))
        q4 = self._pack()
        self.assertEqual(q4["prior_quarter_adjustments"], [{"kind": "REVERSAL", "payment_id": "payment:4", "amount_cents": 7_000, "paid_quarter": "FFY2025Q3"}])
        self.assertEqual(q4["total_cents"], 32_345)  # never netted into Q4
        self.assertIn("excluded:reversed-payment:payment:5", q4["unavailable"])  # reversed within its own quarter

    def test_rule_version_bound(self) -> None:
        pack = self._pack()
        ((pack_digest,),) = self._sql("SELECT pack_digest FROM control_packs WHERE pack_id='pack:line-pack-v1'")
        decided = {row[0]: (row[1], row[2].hex().upper()) for row in self._sql(  # each obligation's last evaluation before Q4 ends
            "SELECT e.evaluation_id,e.rule_version,e.control_pack_digest FROM evaluations e WHERE e.evaluated_at_ms<?1 AND NOT EXISTS "
            "(SELECT 1 FROM evaluations l WHERE l.obligation_id=e.obligation_id AND l.evaluated_at_ms<?1 AND l.revision>e.revision)", (Q4_END,))}
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
        self.assertEqual(_unsigned(self._raw(package_bytes=self.owner.export_continuity())), _unsigned(self._raw()))

    def test_chronology_strict_for_a_superseding_pack(self) -> None:
        prior = self._raw()
        self.assertEqual(self._pack(at_ms=AT + 1, prior_pack=prior)["supersedes"], hashlib.sha256(prior).hexdigest().upper())
        self.assertIsNone(self._pack()["supersedes"])
        for at_ms in (AT, AT - 1):
            with self.subTest(at_ms=at_ms), self.assertRaisesRegex(LinePackError, "chronology-not-strict"):
                self._raw(at_ms=at_ms, prior_pack=prior)
        source = json.loads(prior)["source"]
        ((earlier_head,),) = self._sql("SELECT head FROM financial_events WHERE event_sequence=?", (source["sequence"] - 1,))
        earlier = {**source, "sequence": source["sequence"] - 1, "history_head": earlier_head.hex().upper()}
        self.assertIsNotNone(self._pack(at_ms=AT + 1, prior_pack=_encode({**json.loads(prior), "source": earlier}))["supersedes"])
        v1 = {key: value for key, value in json.loads(prior).items() if key != "signature"} | {"contract": "RR/LINE-PACK/CMS-64.9/v1", "signer": None}
        self.assertIsNotNone(self._pack(at_ms=AT + 1, prior_pack=_encode(v1))["supersedes"])  # a signed v2 pack supersedes an unsigned v1 pack
        with self.assertRaisesRegex(LinePackError, "prior-pack-identity"):
            self._raw(at_ms=AT + 1, prior_pack=_encode({**v1, "contract": "RR/LINE-PACK/CMS-64.9/v0"}))
        for edit, code in (
            ({"sequence": source["sequence"] + 1}, "chronology-not-strict"),
            ({"history_head": "0" * 128}, "chronology-not-strict"),  # same sequence, another head
            ({"sequence": source["sequence"] - 1}, "chronology-not-strict"),  # an earlier sequence whose head is not in this history
            ({"sequence": source["sequence"] - 1, "history_head": None}, "chronology-not-strict"),
            ({"program_id": "program:other"}, "prior-pack-identity"),
            ({"genesis_head": "0" * 128}, "prior-pack-identity"),
        ):
            with self.subTest(edit=sorted(edit)), self.assertRaisesRegex(LinePackError, code):
                self._raw(at_ms=AT + 1, prior_pack=_encode({**json.loads(prior), "source": {**source, **edit}}))
        with self.assertRaisesRegex(LinePackError, "prior-pack-identity"):
            self._raw(at_ms=AT + 1, prior_pack=self._raw("23A", reported=1))
        with self.assertRaisesRegex(LinePackError, "prior-pack:canonical"):
            self._raw(at_ms=AT + 1, prior_pack=prior + b" ")
        with self.assertRaisesRegex(LinePackError, "generated-before-package"):  # the last fact was recorded at Q4_END
            self._raw(at_ms=Q4_END - 1)
        self._raw(at_ms=Q4_END)

    def test_never_asserts_allowability(self) -> None:
        raw = self._raw()
        pack = json.loads(raw)
        self.assertIs(pack["documentation_only"], True)
        self.assertEqual(pack["claims"], {"proofSuiteId": None, "production_usable": False, "activation": False})
        for word in (b"approv", b"allowab", b"valid", b"necessary", b"eligible", b"covered"):
            self.assertNotIn(word, raw.lower())
        self.assertEqual(set(pack), {
            "contract", "documentation_only", "claims", "line", "quarter", "window_ms", "payment_date_basis", "total_cents",
            "row_count", "rows", "prior_quarter_adjustments", "service_period_split",
            "member_manifest_digest", "provenance_root", "unavailable", "coverage", "versions", "source", "generated_at_ms",
            "supersedes", "signer", "signature",
        })
        public_key = signer.public_key(self.custody.key)  # H2: signed by the owner's custody key at the custody log's tail
        self.assertEqual((pack["contract"], verify_pack(raw, public_key)), ("RR/LINE-PACK/CMS-64.9/v2", _unsigned(raw)))
        tail = json.loads(self.custody.directory.joinpath(f"{pack['source']['owner_id']}.custody").read_bytes().splitlines()[-1])
        self.assertEqual((pack["signer"]["custody_n"], pack["signer"]["custody_digest"], tail["sequence"]), (tail["n"], tail["digest"], pack["source"]["sequence"]))
        for forged, key in ((raw.replace(b'"generated_at_ms":3000000000000', b'"generated_at_ms":3000000000001'), public_key), (raw, bytes(len(public_key)))):
            with self.assertRaisesRegex(FinancialIntegrityError, "^pack_signature$"):
                verify_pack(forged, key)
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
        store = ["--authority-file", str(directory / "authority.json"), *[f"--{key.replace('_', '-')}={value}" for key, value in SCOPE.items()]]
        custody = ["--custody-dir", str(self.custody.directory), "--custody-key", self.custody.key]
        args = [*custody, *store, "line-pack", "--package", str(directory / "package.bin"), "--line-map", str(LINE_MAP), "--line", "19A",
                "--quarter", "FFY2025Q4", "--reported-line-cents", "32345", "--generated-at-ms", str(AT), "--output", str(output)]
        for refused, code in ((args, "line-pack:database:path"), (["--database", str(self.db), *args[2:]], "custody_arguments"),
                              (["--database", str(self.db), *custody, *store, "custody-resolve", "--kind", "ADOPTED", "--actor-id", "operator:ana", "--reason-ref", "r",
                                "--expect-store-sequence", str(self.owner._high[0]), "--expect-store-head", self.owner._high[1].hex()], "custody_present")):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(financial_cli.main(refused), 2)  # no --database, a key without a log directory, a second adoption: refused
            self.assertIn(code, errors.getvalue())
        self.assertFalse(output.exists())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(financial_cli.main(["--database", str(self.db), *args]), 0)
        self.assertEqual(_unsigned(output.read_bytes()), _unsigned(self._raw()))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(financial_cli.main(["--database", str(self.db), *args]), 2)  # the output file exists: never replaced


class LateRecordingTests(unittest.TestCase):
    def test_a_fact_recorded_after_quarter_end_changes_only_the_quarter_that_records_it(self) -> None:
        authority, line_map = SyntheticTrustedAuthority(), LINE_MAP.read_bytes()
        with tempfile.TemporaryDirectory(prefix="rr-line-pack-late-") as tmp, _build(Path(tmp), authority, line_map) as owner:
            trust = {"trusted_authority": authority, "expected_scope": {**SCOPE, "currency": "USD"}, "custody": fixture_custody(owner)}

            def pack(package: bytes, quarter: str, at_ms: int = AT, **changes: object) -> bytes:
                return build_line_pack(database=Path(tmp) / "line-pack.sqlite3", package_bytes=package, line="19A",
                                       quarter=quarter, reported_line_cents=1, generated_at_ms=at_ms, **trust, **{"line_map_bytes": line_map, **changes})

            closed = pack(owner.export_continuity(), "FFY2025Q4")
            _reverse(owner, 0, 0, Q4_END - DAY, recorded_at_ms=Q4_END)  # dated in Q4, recorded Q1's first millisecond
            _pay(owner, "late", 1, 9_000, Q4_END - 1, recorded_at_ms=Q4_END + DAY)  # dated Q4's last millisecond, recorded in Q1
            owner.clock.value = Q4_END + DAY * 2  # then a differing amount for Q4's payment:1, a second roster and a new map, all in Q1
            owner.record_payment_evidence(item_id="item:1", payment_id="payment:1-conflict", common_origin_id="origin:1", amount_cents=21_000, evidence_id="evidence:conflict:1", event_at_ms=Q4_END - 1, source_id=HCBS)
            _population(owner, authority, "late", {"item:late": 1_000})
            late_map = line_map.replace(b'"pack_version":1', b'"pack_version":4')
            owner.publish_control_pack(_control_pack(4, V3_END, V3_END + DAY, _ref(late_map)))
            package = owner.export_continuity()
            rebuilt = pack(package, "FFY2025Q4", at_ms=AT + 1, prior_pack=closed)  # ancestry holds: the old head is in this history
            content = lambda raw: {k: v for k, v in json.loads(raw).items() if k not in {"source", "generated_at_ms", "supersedes", "signer", "signature"}}
            self.assertEqual(content(rebuilt), content(closed))
            self.assertEqual(json.loads(rebuilt)["supersedes"], hashlib.sha256(closed).hexdigest().upper())
            listed = {quarter: json.loads(pack(package, quarter)) for quarter in ("FFY2025Q3", "FFY2025Q4", "FFY2026Q1", "FFY2026Q2")}
            self.assertEqual({quarter: [(a["kind"], a["payment_id"]) for a in p["prior_quarter_adjustments"]] for quarter, p in listed.items()}, {
                "FFY2025Q3": [], "FFY2025Q4": [("REVERSAL", "payment:4")],
                "FFY2026Q1": [("REVERSAL", "payment:0"), ("CONFLICT", "payment:1"), ("PAYMENT", "payment:late")], "FFY2026Q2": [],
            })  # each late fact exactly once
            self.assertEqual(listed["FFY2026Q1"]["prior_quarter_adjustments"][1:], [
                {"kind": "CONFLICT", "payment_id": "payment:1", "amount_cents": 20_000, "paid_quarter": "FFY2025Q4"},
                {"kind": "PAYMENT", "payment_id": "payment:late", "amount_cents": 9_000, "paid_quarter": "FFY2025Q4"},
            ])
            self.assertIn("gap:member-manifest-not-complete-at-quarter-end", listed["FFY2026Q1"]["unavailable"])  # two by Q1's end
            with self.assertRaisesRegex(LinePackError, "line-map-not-in-approved-control-pack"):  # pack v4 was published after Q4 closed
                pack(package, "FFY2025Q4", line_map_bytes=late_map)
            self.assertEqual(json.loads(pack(package, "FFY2026Q1", line_map_bytes=late_map))["versions"]["control_pack"]["version"], 4)
            self.assertEqual(([row["payment_id"] for row in listed["FFY2026Q1"]["rows"]], listed["FFY2026Q1"]["total_cents"]), (["payment:3"], 5_000))  # never netted
            # Past year 3000 (where Windows' fromtimestamp raises OSError) the quarter is still computed; past 9998 it is refused.
            far_start = quarter_window("FFY3100Q2")[0]
            _pay(owner, "far", 1, 1_000, far_start - 1, recorded_at_ms=far_start)
            far = json.loads(pack(owner.export_continuity(), "FFY3100Q2", at_ms=far_start))
            self.assertEqual(far["prior_quarter_adjustments"], [{"kind": "PAYMENT", "payment_id": "payment:far", "amount_cents": 1_000, "paid_quarter": "FFY3100Q1"}])
            with self.assertRaisesRegex(LinePackError, "line-pack:quarter"):
                pack(package, "FFY9999Q1")


if __name__ == "__main__":
    unittest.main()
