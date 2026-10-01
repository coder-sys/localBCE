"""History segments (docs/CORE_REDESIGN.md "History segments"): bounded, chained, exported
incrementally, restored by replay and verified independently. Synthetic, non-PHI, nonpayment."""

from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import app.right_rail_financial_owner as owner_module
from app.right_rail_financial_owner import FinancialContinuityError, FinancialIntegrityError, FinancialOwner, FinancialOwnerConfig, SyntheticTrustedAuthority, _checker_authority
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_database, verify_history_export
from tests.test_right_rail_financial_acceptance import _image
from tools.load_synthetic import _SCOPE as SCOPE, _setup

AUTHORITY = SyntheticTrustedAuthority()
CONFIG = FinancialOwnerConfig(**SCOPE)
DOMAIN = b"RR/GATE/SEGMENT/v1\x00"


def _digest(*parts: bytes) -> bytes:
    """SHA3-512 over the domain and length-prefixed parts, written out independently of both modules."""
    digest = hashlib.sha3_512(DOMAIN)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big") + part)
    return digest.digest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


class HistorySegmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        patcher = mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", 8)  # several segments from a small store
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)
        self.owner = FinancialOwner(path=self.root / "owner.sqlite3", config=CONFIG, trusted_authority=AUTHORITY)
        self.addCleanup(self.owner.close)  # R1a: the owner's writer holds the file open until closed
        self.items = [item.item_id for item in _setup(self.owner, random.Random(1), 4, AUTHORITY)]
        self.commands = 0
        self._drive(30)

    def _drive(self, count: int) -> None:
        # Payments, support evidence and evaluations over four obligations: money rows inserted and updated across seals.
        for _ in range(count):
            index, item = self.commands, self.items[self.commands % 4]
            (
                lambda: self.owner.record_payment_evidence(item_id=item, payment_id=f"payment:{index}", common_origin_id=f"origin:{index}", amount_cents=100 + index, evidence_id=f"evidence:payment:{index}", event_at_ms=1_000 + index),
                lambda: self.owner.record_support_evidence(item_id=item, evidence_id=f"evidence:support:{index}", common_origin_id=f"origin:support:{index}"),
                lambda: self.owner.evaluate_obligation(item),
            )[index % 3]()
            self.commands += 1

    def _tracking(self) -> list[object]:
        with closing(sqlite3.connect(self.owner.path)) as connection:
            return [connection.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall() for table in ("history_segments", "history_pending", "history_open")]

    def _check(self, path: Path | None = None) -> None:
        verify_database(path or self.owner.path, expected_config=CONFIG, expected_authority=AUTHORITY)

    def _verify(self, directory: Path, **kwargs: object) -> dict[str, object]:
        return verify_history_export(directory, expected_authority=_checker_authority(AUTHORITY), **kwargs)

    def _export(self, name: str = "history") -> tuple[Path, dict[str, object]]:
        directory = self.root / name
        return directory, json.loads(self.owner.export_history(directory))

    def test_export_restore_by_replay_is_accepted_and_equal(self) -> None:
        directory, manifest = self._export()
        self.assertGreaterEqual(manifest["segment_count"], 4)
        tables = [{record["table"] for record in json.loads((directory / f"segment-{index:08d}.json").read_bytes())["rows"]} for index in range(manifest["segment_count"])]
        for table in ("obligations", "evidence", "payments", "evaluations"):  # replay crosses seals in every money table
            self.assertGreaterEqual(sum(table in written for written in tables), 2, table)
        checked = self._verify(directory)
        self.assertEqual((checked["segment_count"], checked["sequence"]), (manifest["segment_count"], manifest["meta"]["sequence"]))
        restored = FinancialOwner.restore_continuity(history=directory, recovered_path=self.root / "restored.sqlite3", trusted_authority=AUTHORITY)
        self.assertEqual(restored.verify_integrity()["sequence"], manifest["meta"]["sequence"])
        self._verify(directory, restored=restored.path)  # every restored row equals the segments' final image
        with closing(sqlite3.connect(self.owner.path)) as source, closing(sqlite3.connect(restored.path)) as target:
            for table in owner_module._PROJECTION_TABLES + ("financial_events",):
                query = f"SELECT * FROM {table} ORDER BY 1,2"
                self.assertEqual(source.execute(query).fetchall(), target.execute(query).fetchall(), table)
            reseal = "SELECT segment_index,segment_digest,rows_json FROM history_segments ORDER BY segment_index"
            self.assertEqual(source.execute(reseal).fetchall(), target.execute(reseal).fetchall())

    def test_segment_digests_match_an_independent_recompute(self) -> None:
        directory, manifest = self._export()
        previous = b"\x00" * 64
        for index in range(manifest["segment_count"]):
            segment = json.loads((directory / f"segment-{index:08d}.json").read_bytes())
            self.assertEqual(segment["seal"]["previous_digest"], previous.hex().upper())
            self.assertEqual(segment["seal"]["projection_root"], _digest(b"rows", _canonical(segment["rows"])).hex().upper())
            self.assertEqual(segment["seal"]["event_head"], segment["events"][-1]["head"]["hex"])
            self.assertLessEqual(segment["seal"]["event_count"], owner_module._MAX_SEGMENT_EVENTS)
            previous = _digest(b"seal", _canonical(segment["seal"]))
            self.assertEqual(segment["segment_digest"], previous.hex().upper())
            self.assertIsNone(segment["signature"])
        body = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        self.assertEqual(manifest["last_segment_digest"], previous.hex().upper())
        self.assertEqual(manifest["manifest_digest"], _digest(b"manifest", _canonical(body)).hex().upper())

    def test_export_is_incremental(self) -> None:
        directory, first = self._export()
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.glob("segment-*.json")}
        self._drive(12)
        _directory, second = self._export()
        self.assertGreater(second["segment_count"], first["segment_count"])
        for name, (data, mtime) in before.items():
            self.assertEqual(((directory / name).read_bytes(), (directory / name).stat().st_mtime_ns), (data, mtime), name)
        self._verify(directory)

    def test_one_flipped_byte_in_any_segment_is_rejected(self) -> None:
        directory, manifest = self._export()
        for name in ["manifest.json", *(f"segment-{index:08d}.json" for index in range(manifest["segment_count"]))]:
            original = (directory / name).read_bytes()
            for position in sorted({0, len(original) - 1, *range(1, len(original), max(1, len(original) // 40))}):
                tampered = bytearray(original)
                tampered[position] ^= 1
                (directory / name).write_bytes(bytes(tampered))
                with self.assertRaises(IndependentFinancialError, msg=f"{name}@{position}"):
                    self._verify(directory)
            (directory / name).write_bytes(original)
        self._verify(directory)

    def test_every_field_mutation_is_rejected(self) -> None:
        directory, manifest = self._export()
        path = directory / "segment-00000001.json"
        original = json.loads(path.read_bytes())
        mutations = {f"seal.{key}": (lambda segment, key=key: segment["seal"].__setitem__(key, 0 if isinstance(segment["seal"][key], str) else "0")) for key in original["seal"]}
        mutations.update({
            "seal.extra": lambda segment: segment["seal"].__setitem__("extra", 1),
            "segment_digest": lambda segment: segment.__setitem__("segment_digest", "0" * 128),
            "signature": lambda segment: segment.__setitem__("signature", "00"),
            "events.drop": lambda segment: segment["events"].pop(),
            "events.field": lambda segment: segment["events"][0].__setitem__("committed_at_ms", 1),
            "rows.drop": lambda segment: segment["rows"].pop(),
            "rows.duplicate": lambda segment: segment["rows"].append(segment["rows"][-1]),
            "rows.table": lambda segment: segment["rows"][0].__setitem__("table", "commands"),
            "rows.value": lambda segment: segment["rows"][0]["row"].__setitem__(next(iter(segment["rows"][0]["row"])), None),
        })
        for name, mutate in mutations.items():
            segment = json.loads(json.dumps(original))
            mutate(segment)
            path.write_bytes(_canonical(segment))
            with self.assertRaises(IndependentFinancialError, msg=name):
                self._verify(directory)
        path.write_bytes(_canonical(original))
        manifest_path = directory / "manifest.json"
        for key in manifest:
            changed = {**manifest, key: 0 if key != "segment_count" else manifest[key] - 1}
            manifest_path.write_bytes(_canonical(changed))
            with self.assertRaises(IndependentFinancialError, msg=f"manifest.{key}"):
                self._verify(directory)
        (directory / "segment-00000002.json").unlink()
        manifest_path.write_bytes(_canonical(manifest))
        with self.assertRaises(IndependentFinancialError, msg="missing segment"):
            self._verify(directory)

    def test_untrusted_authority_and_restore_mismatch_are_refused(self) -> None:
        directory, _manifest = self._export()
        with self.assertRaises(IndependentFinancialError):
            verify_history_export(directory, expected_authority={**_checker_authority(AUTHORITY), "epoch": 2})
        other = FinancialOwner.restore_continuity(package_bytes=self.owner.export_continuity(), recovered_path=self.root / "other.sqlite3", trusted_authority=AUTHORITY)
        with self.assertRaises(IndependentFinancialError):
            self._verify(directory, restored=other.path)  # restored from a different source
        with self.assertRaisesRegex(FinancialContinuityError, "continuity_source"):
            FinancialOwner.restore_continuity(package_bytes=b"{}", history=directory, recovered_path=self.root / "both.sqlite3", trusted_authority=AUTHORITY)

    def test_an_update_that_changes_nothing_is_not_tracked(self) -> None:
        # Two same-status evaluations of one obligation in one clock millisecond, sealed between: the second's case
        # UPDATE changes nothing, so no event carries it, and tracking it would leave a store that never reopens.
        now = self.owner.clock.now_ms()
        self.owner.clock = mock.Mock(now_ms=lambda: now)
        self.owner.evaluate_obligation(self.items[0])
        self._export()
        self.owner.evaluate_obligation(self.items[0])
        FinancialOwner(path=self.owner.path, config=CONFIG, trusted_authority=AUTHORITY, clock=self.owner.clock).close()
        self._check()

    def test_write_past_a_hard_bound_is_refused_and_rolled_back(self) -> None:
        # Every delta of the refused write rolls back, the open segment's tracking included.
        for bound, value in (("_MAX_SEGMENT_EVENTS", 20), ("_MAX_SEGMENT_BYTES", 40_000)):
            with self.subTest(bound=bound), mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", 10_000), mock.patch.object(owner_module, bound, value):
                with self.assertRaisesRegex(FinancialContinuityError, "^history_segment_size$"):
                    for _ in range(40):
                        before = (_image(self.owner.path), self._tracking())
                        self._drive(1)
                self.assertEqual((_image(self.owner.path), self._tracking()), before)
                self._check()

    def test_tracking_tables_are_checked_and_sealed_segments_are_append_only(self) -> None:
        with closing(sqlite3.connect(self.owner.path)) as connection, self.assertRaisesRegex(sqlite3.IntegrityError, "history_segment_immutable"):
            connection.execute("DELETE FROM history_segments")
        while "evidence" not in {row[0] for row in self._tracking()[1]}:  # the open segment wrote captured rows
            self._drive(1)
        self._check()
        with closing(sqlite3.connect(self.owner.path)) as connection:
            cursor = connection.execute("SELECT * FROM evidence WHERE rowid NOT IN (SELECT row_key FROM history_pending WHERE table_name='evidence') LIMIT 1")
            untouched = {column[0]: {"hex": value.hex().upper()} if type(value) is bytes else value for column, value in zip(cursor.description, cursor.fetchone())}
        size = len(_canonical({"table": "evidence", "row": untouched})) + 1
        pending_evidence = "(SELECT row_key FROM history_pending WHERE table_name='evidence' LIMIT 1)"
        tampers = {
            "UPDATE history_pending SET record_bytes=record_bytes+1 WHERE table_name='financial_events'; UPDATE history_open SET byte_count=byte_count+(SELECT COUNT(*) FROM history_pending WHERE table_name='financial_events')": "^history-pending:row$",
            f"INSERT INTO history_pending SELECT 'evidence',rowid,{size} FROM evidence WHERE evidence_id='{untouched['evidence_id']}'; UPDATE history_open SET byte_count=byte_count+{size}": "^history-open:counts$",
            f"UPDATE history_open SET byte_count=byte_count-(SELECT record_bytes FROM history_pending WHERE table_name='evidence' AND row_key={pending_evidence}); DELETE FROM history_pending WHERE table_name='evidence' AND row_key={pending_evidence}": "^history-open:counts$",
            "UPDATE history_open SET byte_count=byte_count+1": "^history-open:counts$",
            "DELETE FROM history_pending WHERE table_name='financial_events' AND row_key=(SELECT MAX(event_sequence) FROM financial_events)": "^history-open:counts$",
            "INSERT INTO history_pending VALUES ('evidence',1,1)": "^history-pending:row$",
            "UPDATE history_segments SET rows_json=rows_json||' ' WHERE segment_index=1": "^history-segments:1:seal$",
            "UPDATE history_segments SET previous_digest=zeroblob(64) WHERE segment_index=2": "^history-segments:2:seal$",
        }
        source = _image(self.owner.path)
        for statement, code in tampers.items():
            with self.subTest(statement=statement):
                tampered = self.root / "tampered.sqlite3"
                tampered.write_bytes(source)
                self._tamper(tampered, statement)
                with self.assertRaisesRegex(IndependentFinancialError, code):
                    self._check(tampered)
        # The Owner itself refuses, typed, to seal onto a tampered chain or with missing tracking.
        for statement, code in (("UPDATE history_segments SET rows_json=rows_json||' ' WHERE segment_index=(SELECT MAX(segment_index) FROM history_segments)", "^history_segment_chain$"), ("DELETE FROM history_open", "^history_segment_events$")):
            with self.subTest(statement=statement):
                self.owner.close()  # R1a: the bytes are swapped in while no connection holds the file
                self.owner.path.write_bytes(source)
                self._tamper(self.owner.path, statement)
                with self.assertRaisesRegex(FinancialIntegrityError, code):
                    self._drive(8)

    @staticmethod
    def _tamper(path: Path, statement: str) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            triggers = [row[0] for row in connection.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name='history_segments'")]
            for name in ("history_segment_update_immutable", "history_segment_delete_immutable"):
                connection.execute(f"DROP TRIGGER {name}")
            connection.executescript(statement)
            for sql in triggers:
                connection.execute(sql)

    def test_store_from_before_segments_seals_its_whole_history(self) -> None:
        with closing(sqlite3.connect(self.owner.path, isolation_level=None)) as connection:
            for table in ("history_segments", "history_pending", "history_open"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("CREATE TABLE right_rail_continuity_admission (table_name TEXT PRIMARY KEY, row_count INTEGER NOT NULL, row_bytes INTEGER NOT NULL)")
        tampered = self.root / "legacy-tampered.sqlite3"  # conversion replays first: an edit history does not explain is not sealed
        tampered.write_bytes(_image(self.owner.path))
        with closing(sqlite3.connect(tampered, isolation_level=None)) as connection:
            connection.execute("UPDATE program_funding_projection SET amount_cents=amount_cents+1")
        before = tampered.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification"):
            FinancialOwner(path=tampered, config=CONFIG, trusted_authority=AUTHORITY)
        self.assertEqual(tampered.read_bytes(), before)
        before = _image(self.owner.path)  # a history past the hard bound is refused inside the conversion
        with mock.patch.object(owner_module, "_MAX_SEGMENT_EVENTS", self.commands - 1), self.assertRaisesRegex(FinancialContinuityError, "^history_segment_size$"):
            FinancialOwner(path=self.owner.path, config=CONFIG, trusted_authority=AUTHORITY)
        self.assertEqual(_image(self.owner.path), before)
        reopened = FinancialOwner(path=self.owner.path, config=CONFIG, trusted_authority=AUTHORITY)
        self.addCleanup(reopened.close)
        self.assertEqual(self._tracking()[1:], [[], [(1, 0, 0)]])  # sealed in the conversion itself
        manifest = json.loads(reopened.export_history(self.root / "legacy"))
        self.assertEqual(manifest["segment_count"], 1)
        self._verify(self.root / "legacy")
        self._check()


if __name__ == "__main__":
    unittest.main()
