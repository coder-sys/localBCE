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
from app.right_rail_financial_owner_independent import IndependentFinancialError, verify_history_export
from tools.load_synthetic import _DEPLOYMENT_ID, _PERIOD_ID, _PROGRAM_ID, _STATE_ID, _setup

AUTHORITY = SyntheticTrustedAuthority()
CONFIG = FinancialOwnerConfig(state_id=_STATE_ID, deployment_id=_DEPLOYMENT_ID, program_id=_PROGRAM_ID, period_id=_PERIOD_ID)
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
        self.items, _ = _setup(self.owner, random.Random(7), 4, AUTHORITY)
        self.commands = 0
        self._drive(30)

    def _drive(self, count: int) -> None:
        for _ in range(count):
            index = self.commands
            item = self.items[index % len(self.items)]
            if index % 3 == 2:
                self.owner.evaluate_obligation(item.item_id)
            else:
                self.owner.record_payment_evidence(item_id=item.item_id, payment_id=f"payment:{index}", common_origin_id=f"origin:{index}", amount_cents=100 + index, evidence_id=f"evidence:{index}", event_at_ms=1_000 + index)
            self.commands += 1

    def _verify(self, directory: Path, **kwargs: object) -> dict[str, object]:
        return verify_history_export(directory, expected_authority=_checker_authority(AUTHORITY), **kwargs)

    def _export(self, name: str = "history") -> tuple[Path, dict[str, object]]:
        directory = self.root / name
        return directory, json.loads(self.owner.export_history(directory))

    def test_export_restore_by_replay_is_accepted_and_equal(self) -> None:
        directory, manifest = self._export()
        self.assertGreaterEqual(manifest["segment_count"], 4)
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

    def test_write_past_the_hard_bound_is_refused_and_rolled_back(self) -> None:
        with mock.patch.object(owner_module, "_SEAL_SEGMENT_EVENTS", 10_000), mock.patch.object(owner_module, "_MAX_SEGMENT_EVENTS", 20):
            with self.assertRaisesRegex(FinancialContinuityError, "history_segment_size"):
                for _ in range(40):
                    sequence = self.owner.verify_integrity()["sequence"]
                    self._drive(1)
            self.assertEqual(self.owner.verify_integrity()["sequence"], sequence)

    def test_store_from_before_segments_seals_its_whole_history(self) -> None:
        with closing(sqlite3.connect(self.owner.path, isolation_level=None)) as connection:
            for table in ("history_segments", "history_pending", "history_open"):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("CREATE TABLE right_rail_continuity_admission (table_name TEXT PRIMARY KEY, row_count INTEGER NOT NULL, row_bytes INTEGER NOT NULL)")
        tampered = self.root / "legacy-tampered.sqlite3"  # conversion replays first: an edit history does not explain is not sealed
        tampered.write_bytes(self.owner.path.read_bytes())
        with closing(sqlite3.connect(tampered, isolation_level=None)) as connection:
            connection.execute("UPDATE obligations SET owed_cents=owed_cents+1")
        before = tampered.read_bytes()
        with self.assertRaisesRegex(FinancialIntegrityError, "^open_verification"):
            FinancialOwner(path=tampered, config=CONFIG, trusted_authority=AUTHORITY)
        self.assertEqual(tampered.read_bytes(), before)
        reopened = FinancialOwner(path=self.owner.path, config=CONFIG, trusted_authority=AUTHORITY)
        manifest = json.loads(reopened.export_history(self.root / "legacy"))
        self.assertEqual(manifest["segment_count"], 1)
        self._verify(self.root / "legacy")


if __name__ == "__main__":
    unittest.main()
